#pragma once
#include "ir.h"
#include <vector>
#include <cstdint>
#include <algorithm>

// ====================================================================
// iralloc: target-independent register-allocation engine shared by all
// IRAsm backends (x86-64, wasm, ARM32/STM32, ARM64).
//
// The engine computes, per IR function:
//   - value intervals (first/last occurrence, int/float usage),
//   - block-level liveness (fixpoint over the CFG),
//   - segment split at call-like barriers; each segment is allocated
//     independently (volatile registers are freely reused between calls),
//   - a linear-scan assignment of virtual registers to physical registers
//     taken from target-defined pools (volatile + callee-saved GP and a
//     separate float-file pool), with crossing values preferring
//     callee-saved registers to survive barriers without spilling,
//   - per-instruction physical-register lookup (physOf / physNextOf).
//
// The targets only differ in the register pools / restrictions they pass
// in TargetDesc; the allocation policy itself is shared, so every backend
// gets exactly the same quality (and any improvement lands everywhere).
// ====================================================================

namespace iralloc {

// interval / usage data for one virtual register (frame slot)
struct VAlloc {
    bool floatUsed = false;      // used as a float value
    bool intUsed = false;        // used as an int/pointer value
    int first = -1;              // first occurrence (instr idx)
    int last = -1;               // last occurrence
    int lastUse = -1;            // last *use* (defs do not extend lifetime)
    bool firstIsUse = false;     // first occurrence is a use (live-in)
    bool crossesBarrier = false; // live across a call-like instruction
    bool forbidDiv = false;      // live before a div/mod -> no div-clobbered regs
    bool forbidAx = false;       // live before an instr needing a GP scratch
    bool forbidCx = false;       // live before a shift-by-reg -> no shift-count reg
    int phys = -1;               // allocated machine register, -1 = spill
};

// per-target register model
struct TargetDesc {
    const int* gpVol = nullptr;  // volatile GP pool (free between barriers)
    int nGpVol = 0;
    const int* gpCal = nullptr;  // callee-saved GP pool (survive barriers)
    int nGpCal = 0;
    const int* xmm = nullptr;    // float-file pool (separate space), -1 entries = none
    int nXmm = 0;

    // register ids used by the restriction machinery (x86 only)
    int divHi = -1;              // div quotient/scratch register (RAX)
    int divLo = -1;              // div remainder register (RDX)
    int shiftCount = -1;         // shift-by-register count register (RCX)
    int axScratch = -1;          // scratch for big immediates (RAX)

    bool restrictDiv = false;    // div/mod clobbers divHi/divLo
    bool restrictShift = false;  // shift-by-reg needs shiftCount
    bool restrictBigImm = false; // big immediates need axScratch

    // true: floats live in the separate xmm pool and int+float hybrids are
    // spilled; false: one register file for both (soft-float ARM32) and
    // hybrid values are allocated like plain ints.
    bool hybridSpill = true;
};

struct SegInfo {
    int st = 0, en = 0;                 // first/last position in active[]
    std::vector<VAlloc> alloc;          // per-value phys assignment for this segment
    std::vector<int> crossing;          // values live across this segment's trailing barrier
};

struct Block { int start = 0, end = 0; std::vector<int> succs; };

struct Info {
    int n = 0;                          // instruction count
    int maxSlot = 0;
    std::vector<VAlloc> alloc;          // whole-function type info
    std::vector<int> active;            // non-garbage instruction indices in order
    std::vector<SegInfo> segs;
    std::vector<int> preSegOfBarrier;   // barrier idx -> segment before it
    std::vector<int> nextSegOfBarrier;  // barrier idx -> segment after it
    std::vector<std::vector<int>> barrierCrossing;
    std::vector<int> segOfInstr;
    std::vector<int> calleeUsed;        // gpCal regs actually allocated somewhere
    const TargetDesc* td = nullptr;

    // physical register a virtual reg occupies at instruction idx
    int physOf(int v, int idx) const {
        if (v < 0 || v >= maxSlot) return -1;
        int s = (idx >= 0 && idx < (int)segOfInstr.size()) ? segOfInstr[idx] : -1;
        if (s < 0 && idx >= 0 && idx < (int)preSegOfBarrier.size())
            s = preSegOfBarrier[idx];   // barrier reads use pre-segment assignment
        if (s < 0) return -1;
        return segs[s].alloc[v].phys;
    }

    // physical register of a call/barrier result in the following segment
    int physNextOf(int v, int idx) const {
        if (v < 0 || v >= maxSlot) return -1;
        if (idx < 0 || idx >= (int)nextSegOfBarrier.size()) return -1;
        int s = nextSegOfBarrier[idx];
        if (s < 0) return -1;
        return segs[s].alloc[v].phys;
    }

    bool isVol(int p) const {
        for (int i = 0; i < td->nGpVol; i++) if (td->gpVol[i] == p) return true;
        return false;
    }
    bool isXmm(int p) const {
        for (int i = 0; i < td->nXmm; i++) if (td->xmm[i] == p) return true;
        return false;
    }
    // which pool does this value prefer / belong to?
    bool isFloatValue(int v) const { return alloc[v].floatUsed && !alloc[v].intUsed; }
};

using Bitset = std::vector<uint64_t>;

static inline void bsSet(Bitset& s, int v) { s[(unsigned)v >> 6] |= 1ULL << (v & 63); }
static inline void bsClear(Bitset& s, int v) { s[(unsigned)v >> 6] &= ~(1ULL << (v & 63)); }
static inline bool bsGet(const Bitset& s, int v) { return (s[(unsigned)v >> 6] >> (v & 63)) & 1; }

static bool isBarrier(IROp op) {
    return op == IROp::Call || op == IROp::ICall || op == IROp::PrintStr ||
           op == IROp::PrintInt || op == IROp::PrintFlt || op == IROp::Exit ||
           op == IROp::RawAsm;
}

static bool isTerminator(IROp op) {
    return op == IROp::Br || op == IROp::BrZ || op == IROp::BrNZ ||
           op == IROp::BrCC || op == IROp::Ret;
}

// record interval/type data for every Reg operand of an instruction
static void markInstr(const IRInstr& in, int idx, VAlloc* alloc) {
    auto def = [&](const IROperand& o, bool isF) {
        if (o.kind != IROperand::Reg) return;
        VAlloc& v = alloc[o.reg];
        if (v.first < 0) v.first = idx;
        v.last = idx;
        if (isF) v.floatUsed = true; else v.intUsed = true;
    };
    auto use = [&](const IROperand& o, bool isF) {
        if (o.kind != IROperand::Reg) return;
        VAlloc& v = alloc[o.reg];
        if (v.first < 0) { v.first = idx; v.firstIsUse = true; }
        v.last = idx;
        v.lastUse = idx;
        if (isF) v.floatUsed = true; else v.intUsed = true;
    };
    bool floatOp = false;
    switch (in.op) {
    case IROp::Const: case IROp::Str: case IROp::LeaGlobal: case IROp::LeaSlot:
        def(in.a, false); break;
    case IROp::FConst: def(in.a, true); break;
    case IROp::Mov: def(in.a, false); use(in.b, false); break;
    case IROp::Load: case IROp::Load32: def(in.a, false); break;
    case IROp::Store: case IROp::Store32: case IROp::FStore:
        use(in.b, in.op == IROp::FStore); break;
    case IROp::GLoad: case IROp::GLoad32: case IROp::FGLoad:
        def(in.a, in.op == IROp::FGLoad); break;
    case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
        use(in.b, in.op == IROp::FGStore); break;
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z: case IROp::PLoadW: case IROp::PLoadB:
        def(in.a, false); use(in.b, false); break;
    case IROp::PStore: case IROp::PStore32: case IROp::PStoreW: case IROp::PStoreB:
        use(in.a, false); use(in.b, false); break;
    case IROp::FPStore: use(in.a, false); use(in.b, true); break;
    case IROp::Arg: use(in.b, in.a.off != 0); break;
    case IROp::Call: case IROp::ICall: def(in.a, in.a.off != 0); break;
    case IROp::PrintInt: case IROp::Exit: use(in.a, false); break;
    case IROp::PrintFlt: use(in.a, true); break;
    case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Mul: case IROp::IDiv: case IROp::IMod: case IROp::UDiv: case IROp::UMod:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
        def(in.a, false); use(in.b, false); use(in.c, false); break;
    case IROp::Neg: case IROp::Not: def(in.a, false); use(in.b, false); break;
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
        def(in.a, true); use(in.b, true); use(in.c, true); break;
    case IROp::FMov: case IROp::FNeg: def(in.a, true); use(in.b, true); break;
    case IROp::I2F: def(in.a, true); use(in.b, false); break;
    case IROp::F2I: def(in.a, false); use(in.b, true); break;
    case IROp::FLoad: def(in.a, true); break;
    case IROp::Cmp:
        floatOp = in.a.off != 0;
        def(in.a, floatOp); use(in.b, floatOp); use(in.c, floatOp); break;
    case IROp::BrZ: case IROp::BrNZ: use(in.a, false); break;
    case IROp::BrCC:
        floatOp = in.a.off != 0;
        use(in.a, floatOp); use(in.b, floatOp); break;
    case IROp::Ret: use(in.a, in.a.off != 0); break;
    default: break;
    }
}

// backward liveness step for one instruction: before = (after - defs) + uses
static void applyDefUse(const IRInstr& in, Bitset& before) {
    switch (in.op) {
    case IROp::Mov: bsSet(before, in.b.reg); break;
    case IROp::Store: case IROp::Store32: case IROp::FStore:
    case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
        bsSet(before, in.b.reg); break;
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z: case IROp::PLoadW: case IROp::PLoadB:
        bsSet(before, in.b.reg); break;
    case IROp::PStore: case IROp::PStore32: case IROp::PStoreW: case IROp::PStoreB:
    case IROp::FPStore:
        bsSet(before, in.a.reg); bsSet(before, in.b.reg); break;
    case IROp::Arg: bsSet(before, in.b.reg); break;
    case IROp::PrintInt: case IROp::PrintFlt: case IROp::Exit:
        bsSet(before, in.a.reg); break;
    case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Mul: case IROp::IDiv: case IROp::IMod: case IROp::UDiv: case IROp::UMod:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
        bsSet(before, in.b.reg);
        if (in.c.kind == IROperand::Reg) bsSet(before, in.c.reg);
        break;
    case IROp::Neg: case IROp::Not: bsSet(before, in.b.reg); break;
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
        bsSet(before, in.b.reg);
        if (in.c.kind == IROperand::Reg) bsSet(before, in.c.reg);
        break;
    case IROp::FMov: case IROp::FNeg: case IROp::I2F: case IROp::F2I:
        bsSet(before, in.b.reg); break;
    case IROp::Cmp:
        bsSet(before, in.b.reg);
        if (in.c.kind == IROperand::Reg) bsSet(before, in.c.reg);
        break;
    case IROp::BrZ: case IROp::BrNZ: bsSet(before, in.a.reg); break;
    case IROp::BrCC:
        bsSet(before, in.a.reg);
        if (in.b.kind == IROperand::Reg) bsSet(before, in.b.reg);
        break;
    case IROp::Ret:
        if (in.a.kind == IROperand::Reg) bsSet(before, in.a.reg);
        break;
    default: break;
    }
    switch (in.op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::LeaGlobal: case IROp::LeaSlot:
    case IROp::Load: case IROp::Load32:
    case IROp::GLoad: case IROp::GLoad32: case IROp::FGLoad:
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z: case IROp::PLoadW: case IROp::PLoadB:
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::IDiv: case IROp::IMod: case IROp::UDiv: case IROp::UMod:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::Neg: case IROp::Not:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::FMov: case IROp::FNeg: case IROp::I2F: case IROp::F2I:
    case IROp::FLoad: case IROp::Cmp:
        if (in.a.kind == IROperand::Reg) bsClear(before, in.a.reg);
        break;
    case IROp::Call: case IROp::ICall:
        if (in.a.kind == IROperand::Reg) bsClear(before, in.a.reg);
        break;
    default: break;
    }
}

// full per-function analysis. Pure function: no emission, no target code.
static Info analyze(const IRFunction& fn, const TargetDesc& td) {
    Info ai;
    ai.td = &td;

    // compute max slot id used; runs (base+count) are reached through
    // pointers, so they never appear as operands and must be accounted for
    int maxSlot = 0;
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        auto upd = [&](const IROperand& o) {
            if (o.kind == IROperand::Reg && o.reg >= maxSlot) maxSlot = o.reg + 1;
            if (o.kind == IROperand::Slot && o.reg >= maxSlot) maxSlot = o.reg + 1;
        };
        upd(in.a); upd(in.b); upd(in.c);
    }
    for (auto& r : fn.runs) {
        int end = r.baseSlot + (r.count > 0 ? r.count : 1);
        if (end > maxSlot) maxSlot = end;
    }
    if (maxSlot < fn.nparams) maxSlot = fn.nparams;
    ai.maxSlot = maxSlot;

    int n = (int)fn.instrs.size();
    ai.n = n;
    std::vector<VAlloc> alloc((size_t)maxSlot);
    std::vector<Bitset> liveBefore((size_t)n, Bitset((size_t)((maxSlot + 63) >> 6), 0));

    // ---- interval data ----
    std::vector<int> pending;
    for (int i = 0; i < n; i++) {
        const IRInstr& in = fn.instrs[i];
        if (in.garbage) continue;
        markInstr(in, i, alloc.data());
        if (in.op == IROp::Arg) {
            pending.push_back(in.b.reg);
        } else if (in.op == IROp::Call || in.op == IROp::ICall) {
            int nargs = (int)in.c.imm;
            for (int k = 0; k < nargs && k < (int)pending.size(); k++)
                alloc[pending[k]].lastUse = i;   // args are consumed at the call
            pending.clear();
        }
    }

    // ---- CFG ----
    std::vector<int> starts;
    starts.push_back(0);
    for (int i = 0; i < n; i++) {
        if (fn.instrs[i].garbage) continue;
        if (fn.instrs[i].op == IROp::Label) starts.push_back(i);
        if (isTerminator(fn.instrs[i].op)) starts.push_back(i + 1);
    }
    std::vector<Block> blocks;
    std::vector<int> blockOfInstr((size_t)n, -1);
    std::unordered_map<int, int> labelBlock;
    for (size_t b = 0; b < starts.size(); b++) {
        int s = starts[b];
        int e = (b + 1 < starts.size()) ? starts[b + 1] - 1 : n - 1;
        if (e < s) continue;
        Block bl; bl.start = s; bl.end = e;
        blocks.push_back(bl);
        for (int i = s; i <= e; i++) blockOfInstr[i] = (int)blocks.size() - 1;
        if (fn.instrs[s].op == IROp::Label)
            labelBlock[fn.instrs[s].label] = (int)blocks.size() - 1;
    }
    for (auto& bl : blocks) {
        const IRInstr& last = fn.instrs[bl.end];
        auto target = [&](int lbl) -> int {
            auto it = labelBlock.find(lbl);
            return it != labelBlock.end() ? it->second : -1;
        };
        switch (last.op) {
        case IROp::Br:
            if (int t = target(last.b.label); t >= 0) bl.succs.push_back(t);
            break;
        case IROp::BrZ: case IROp::BrNZ: case IROp::BrCC:
            if (int t = target(last.b.label); t >= 0) bl.succs.push_back(t);
            if (bl.end + 1 < n && blockOfInstr[bl.end + 1] >= 0)
                bl.succs.push_back(blockOfInstr[bl.end + 1]);
            break;
        case IROp::Ret:
            break;
        default:
            if (bl.end + 1 < n && blockOfInstr[bl.end + 1] >= 0)
                bl.succs.push_back(blockOfInstr[bl.end + 1]);
            break;
        }
    }

    // ---- liveness (fixpoint over blocks) ----
    int nWords = (maxSlot + 63) >> 6;
    std::vector<Bitset> liveIn(blocks.size(), Bitset((size_t)nWords, 0));
    std::vector<Bitset> liveOut(blocks.size(), Bitset((size_t)nWords, 0));
    bool changed = true;
    for (int guard = 0; changed && guard < 1000; guard++) {
        changed = false;
        for (int b = (int)blocks.size() - 1; b >= 0; b--) {
            Block& bl = blocks[b];
            Bitset out((size_t)nWords, 0);
            for (int s : bl.succs)
                for (int w = 0; w < nWords; w++) out[w] |= liveIn[s][w];
            if (out != liveOut[b]) { liveOut[b] = out; changed = true; }
            Bitset in = out;
            for (int i = bl.end; i >= bl.start; i--) {
                Bitset before = in;
                if (!fn.instrs[i].garbage) applyDefUse(fn.instrs[i], before);
                liveBefore[i] = before;
                in = std::move(before);
            }
            if (in != liveIn[b]) { liveIn[b] = in; changed = true; }
        }
    }

    // ---- segment split: runs of instructions between barriers ----
    std::vector<int> active;
    for (int i = 0; i < n; i++) if (!fn.instrs[i].garbage) active.push_back(i);
    ai.active = active;

    std::vector<SegInfo>& segs = ai.segs;
    std::vector<int>& preSegOfBarrier = ai.preSegOfBarrier;
    std::vector<int>& nextSegOfBarrier = ai.nextSegOfBarrier;
    std::vector<std::vector<int>>& barrierCrossing = ai.barrierCrossing;
    preSegOfBarrier.assign((size_t)n, -1);
    nextSegOfBarrier.assign((size_t)n, -1);
    barrierCrossing.assign((size_t)n, {});

    auto buildSegment = [&](int st, int en, int trailingBarrier) {
        SegInfo sg;
        sg.st = st; sg.en = en;
        sg.alloc.assign((size_t)maxSlot, VAlloc());
        auto& A = sg.alloc;
        for (int p = st; p <= en; p++) {
            int idx = active[p];
            markInstr(fn.instrs[idx], idx, A.data());
        }
        // live-in values (params, call results, values crossing from before)
        // occupy a register from the segment head even if their first mention
        // inside the segment is later; otherwise their register could be
        // reused by a shorter-lived value and clobber the live-in value.
        {
            int segFirstIdx = active[st];
            for (int v = 0; v < maxSlot; v++)
                if (bsGet(liveBefore[segFirstIdx], v))
                    A[v].first = segFirstIdx;
        }
        if (trailingBarrier >= 0) {
            int b = trailingBarrier;
            for (int v = 0; v < maxSlot; v++) {
                bool liveB = bsGet(liveBefore[b], v);
                bool liveA = bsGet(liveBefore[b + 1], v);
                if (A[v].first >= 0) {
                    if (liveB) A[v].last = b;      // operand of the barrier: extend interval
                    if (liveB && liveA) sg.crossing.push_back(v);  // survives the call
                }
            }
        }
        // forbidden registers within this segment (div/scratch/shift-count)
        for (int p = st; p <= en; p++) {
            int idx = active[p];
            const IRInstr& in = fn.instrs[idx];
            IROp op = in.op;
            if (td.restrictDiv &&
                (op == IROp::IDiv || op == IROp::IMod || op == IROp::UDiv || op == IROp::UMod)) {
                for (int v = 0; v < maxSlot; v++)
                    if (bsGet(liveBefore[idx], v)) A[v].forbidDiv = true;
            }
            if (td.restrictBigImm) {
                bool needAx = false;
                switch (op) {
                case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z: case IROp::PLoadW: case IROp::PLoadB:
                case IROp::PStore: case IROp::PStore32: case IROp::PStoreW: case IROp::PStoreB:
                    needAx = true; break;
                case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor: case IROp::Mul:
                    if (in.c.kind == IROperand::Imm &&
                        !(in.c.imm >= INT32_MIN && in.c.imm <= INT32_MAX)) needAx = true;
                    break;
                case IROp::Cmp:
                    if (in.a.off == 0 && in.c.kind == IROperand::Imm &&
                        !(in.c.imm >= INT32_MIN && in.c.imm <= INT32_MAX)) needAx = true;
                    break;
                case IROp::BrCC:
                    if (in.a.off == 0 && in.b.kind == IROperand::Imm &&
                        !(in.b.imm >= INT32_MIN && in.b.imm <= INT32_MAX)) needAx = true;
                    break;
                default: break;
                }
                if (needAx) {
                    for (int v = 0; v < maxSlot; v++)
                        if (bsGet(liveBefore[idx], v)) A[v].forbidAx = true;
                }
            }
            if (td.restrictShift &&
                (op == IROp::Shl || op == IROp::Shr || op == IROp::Sar) &&
                in.c.kind == IROperand::Reg) {
                for (int v = 0; v < maxSlot; v++)
                    if (v != in.c.reg && bsGet(liveBefore[idx], v)) A[v].forbidCx = true;
            }
        }
        // linear scan for this segment (crossing values first so they get
        // callee-saved registers and avoid spilling at the barrier)
        std::vector<int> order;
        for (int v = 0; v < maxSlot; v++)
            if (A[v].first >= 0 && A[v].last >= 0) order.push_back(v);
        auto isCrossing = [&](int v) {
            return std::find(sg.crossing.begin(), sg.crossing.end(), v) != sg.crossing.end();
        };
        std::sort(order.begin(), order.end(), [&](int x, int y) {
            bool cx = isCrossing(x), cy = isCrossing(y);
            if (cx != cy) return cx;
            if (A[x].first != A[y].first) return A[x].first < A[y].first;
            return A[x].last < A[y].last;
        });
        int busyGp[256]; for (int& p : busyGp) p = -1;
        int busyF[256];  for (int& p : busyF)  p = -1;
        for (int v : order) {
            VAlloc& VA = A[v];
            for (int p = 0; p < 256; p++) {
                if (busyGp[p] >= 0 && A[busyGp[p]].last < VA.first) busyGp[p] = -1;
                if (busyF[p] >= 0  && A[busyF[p]].last  < VA.first) busyF[p] = -1;
            }
            bool crossing = isCrossing(v);
            bool isFloat = VA.floatUsed && !VA.intUsed;
            if (VA.floatUsed && VA.intUsed && td.hybridSpill) {
                VA.phys = -1;   // hybrid -> spill (separate float file)
                continue;
            }
            if (isFloat && td.nXmm > 0 && td.hybridSpill) {
                // float-file pool
                int pick = -1;
                for (int i = 0; i < td.nXmm; i++) {
                    int p = td.xmm[i];
                    if (p >= 0 && busyF[p] < 0) { pick = p; break; }
                }
                if (pick >= 0) { VA.phys = pick; busyF[pick] = v; }
                else VA.phys = -1;
                continue;
            }
            // GP pools: prefer callee-saved for crossing values
            std::vector<int> pool;
            if (crossing) {
                pool.assign(td.gpCal, td.gpCal + td.nGpCal);
                for (int i = 0; i < td.nGpVol; i++) pool.push_back(td.gpVol[i]);
            } else {
                pool.assign(td.gpVol, td.gpVol + td.nGpVol);
                for (int i = 0; i < td.nGpCal; i++) pool.push_back(td.gpCal[i]);
            }
            for (auto it = pool.begin(); it != pool.end(); ) {
                bool bad = (*it == td.divHi && (VA.forbidAx || VA.forbidDiv)) ||
                           (*it == td.divLo && VA.forbidDiv) ||
                           (*it == td.shiftCount && VA.forbidCx);
                if (bad) it = pool.erase(it); else ++it;
            }
            int pick = -1;
            for (int p : pool) if (busyGp[p] < 0) { pick = p; break; }
            if (pick >= 0) { VA.phys = pick; busyGp[pick] = v; }
            else VA.phys = -1;   // spilled for this segment
        }
        segs.push_back(std::move(sg));
    };

    int segStartPos = 0;
    for (int p = 0; p < (int)active.size(); p++) {
        int idx = active[p];
        if (isBarrier(fn.instrs[idx].op)) {
            int preSeg = (int)segs.size();
            buildSegment(segStartPos, p - 1, idx);
            preSegOfBarrier[idx] = preSeg;
            segStartPos = p + 1;
        }
    }
    if (segStartPos < (int)active.size())
        buildSegment(segStartPos, (int)active.size() - 1, -1);
    for (int p = 0; p < (int)active.size(); p++) {
        int idx = active[p];
        if (isBarrier(fn.instrs[idx].op)) {
            for (size_t s = 0; s < segs.size(); s++)
                if (segs[s].st == p + 1) { nextSegOfBarrier[idx] = (int)s; break; }
            if (preSegOfBarrier[idx] >= 0)
                barrierCrossing[idx] = segs[preSegOfBarrier[idx]].crossing;
        }
    }

    // per-instruction segment lookup (barriers map to their pre-segment)
    std::vector<int>& segOfInstr = ai.segOfInstr;
    segOfInstr.assign((size_t)n, -1);
    for (size_t s = 0; s < segs.size(); s++)
        for (int p = segs[s].st; p <= segs[s].en; p++)
            segOfInstr[active[p]] = (int)s;

    // ---- callee-saved registers actually used ----
    for (int p = 0; p < td.nGpCal; p++) {
        bool used = false;
        for (auto& sg : segs)
            for (auto& A : sg.alloc)
                if (A.phys == td.gpCal[p]) { used = true; break; }
        if (used) ai.calleeUsed.push_back(td.gpCal[p]);
    }

    ai.alloc = std::move(alloc);
    return ai;
}

} // namespace iralloc
