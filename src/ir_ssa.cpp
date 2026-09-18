#include "ir_ssa.h"
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <functional>

// ====================================================================
// Full SSA pass for the assembler-IR.
//
// The IR's "registers" are frame slots (IROperand::Reg), so every SSA
// version of a slot v collapses back to slot v at de-SSA time; the only
// copies that survive de-SSA are the ones that move a value between two
// *different* slots (a result of GVN forwarding / LICM hoisting). Memory
// operands (IROperand::Slot, used by Load/Store/LeaSlot) are addresses
// and are never versioned.
// ====================================================================

namespace {

const int kSsaBase = 1 << 26;      // SSA version ids live above this mark

// ------------------------------------------------------------------
// instruction behavior (mirrors irasm.cpp operand layout, validated
// against the actual backend emission)
// ------------------------------------------------------------------

// Does this instruction write a fresh value register into operand a?
static bool opIsRegDef(const IRInstr& in, int& dst) {
    dst = -1;
    if (in.a.kind != IROperand::Reg) return false;
    switch (in.op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::FMov:
    case IROp::LeaGlobal: case IROp::LeaSlot:
    case IROp::Load: case IROp::Load32: case IROp::FLoad:
    case IROp::GLoad: case IROp::GLoad32: case IROp::FGLoad:
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
    case IROp::PLoadW: case IROp::PLoadB:
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::Neg: case IROp::Not:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::FNeg: case IROp::I2F: case IROp::F2I:
    case IROp::Cmp:
    case IROp::Call: case IROp::ICall:
        dst = in.a.reg;
        return true;
    default:
        return false;
    }
}

// Calls forEachRead for every register operand that this instruction
// reads as a *value* (not a memory address). pos identifies the operand:
// 0 = a, 1 = b, 2 = c.
static void forEachRead(const IRInstr& in,
                        const std::function<void(IROperand&, int)>& fn) {
    auto r = [&](const IROperand& o, int pos) {
        if (o.kind == IROperand::Reg) fn(const_cast<IROperand&>(o), pos);
    };
    switch (in.op) {
    case IROp::Mov: case IROp::FMov:
    case IROp::Neg: case IROp::Not: case IROp::FNeg:
    case IROp::I2F: case IROp::F2I:
        r(in.b, 1);
        break;
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::Cmp:
        r(in.b, 1);
        r(in.c, 2);
        break;
    case IROp::Store: case IROp::Store32: case IROp::FStore:
    case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
        r(in.b, 1);
        break;
    case IROp::PStore: case IROp::PStore32: case IROp::PStoreW:
    case IROp::PStoreB: case IROp::FPStore:
        r(in.a, 0);
        r(in.b, 1);
        break;
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
    case IROp::PLoadW: case IROp::PLoadB:
        r(in.b, 1);
        break;
    case IROp::Arg:
        r(in.b, 1);
        break;
    case IROp::BrZ: case IROp::BrNZ:
    case IROp::PrintInt: case IROp::PrintFlt: case IROp::Exit:
        r(in.a, 0);
        break;
    case IROp::BrCC:
        r(in.a, 0);
        r(in.b, 1);
        break;
    case IROp::PrintStr: case IROp::Ret:
        if (in.a.kind == IROperand::Reg) r(in.a, 0);
        break;
    default:
        break;
    }
}

// Pure compute with no side effects: safe to delete when unused, safe to
// value-number, safe to fold.
static bool isPureSSA(IROp op) {
    switch (op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::FMov:
    case IROp::LeaGlobal: case IROp::LeaSlot:
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::Neg: case IROp::Not:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::FNeg: case IROp::I2F: case IROp::F2I:
    case IROp::Cmp:
        return true;
    default:
        return false;
    }
}

// Value-numbered in GVN: pure and no fault-placement concerns.
static bool isGvn(IROp op) {
    switch (op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::FMov:
    case IROp::LeaGlobal: case IROp::LeaSlot:
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::Neg: case IROp::Not:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::FNeg: case IROp::I2F: case IROp::F2I:
    case IROp::Cmp:
        return true;
    default:
        return false;
    }
}

// Hoistable by LICM: pure compute, cannot fault, no memory access.
static bool isHoistable(IROp op) {
    switch (op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::FMov:
    case IROp::LeaGlobal: case IROp::LeaSlot:
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::Neg: case IROp::Not:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul:
    case IROp::FNeg: case IROp::I2F: case IROp::F2I:
    case IROp::Cmp:
        return true;
    default:
        return false;
    }
}

// Integer constant folding (mirrors foldFunction semantics: shifts mask
// the count with 63 like the x86 backend, division by zero is not folded).
static bool foldIntOp(IROp op, const std::string& cond,
                      int64_t a, int64_t b, int64_t& out) {
    switch (op) {
    case IROp::Mov: out = a; return true;
    case IROp::Add: out = a + b; return true;
    case IROp::Sub: out = a - b; return true;
    case IROp::Mul: out = a * b; return true;
    case IROp::IDiv:
        if (b == 0) return false;
        if (a == INT64_MIN && b == -1) return false;   // overflow trap
        out = a / b; return true;
    case IROp::IMod:
        if (b == 0) return false;
        if (a == INT64_MIN && b == -1) return false;
        out = a % b; return true;
    case IROp::UDiv: if (b == 0) return false; out = (int64_t)((uint64_t)a / (uint64_t)b); return true;
    case IROp::UMod: if (b == 0) return false; out = (int64_t)((uint64_t)a % (uint64_t)b); return true;
    case IROp::And: out = a & b; return true;
    case IROp::Or:  out = a | b; return true;
    case IROp::Xor: out = a ^ b; return true;
    case IROp::Shl: out = (int64_t)((uint64_t)a << (b & 63)); return true;
    case IROp::Shr: out = (int64_t)((uint64_t)a >> (b & 63)); return true;
    case IROp::Sar: out = a >> (b & 63); return true;
    case IROp::Neg: out = -a; return true;
    case IROp::Not: out = ~a; return true;
    case IROp::Cmp:
        if (cond == "==") { out = (a == b) ? 1 : 0; return true; }
        if (cond == "!=") { out = (a != b) ? 1 : 0; return true; }
        if (cond == "<")  { out = (a <  b) ? 1 : 0; return true; }
        if (cond == "<=") { out = (a <= b) ? 1 : 0; return true; }
        if (cond == ">")  { out = (a >  b) ? 1 : 0; return true; }
        if (cond == ">=") { out = (a >= b) ? 1 : 0; return true; }
        if (cond == "u<")  { out = ((uint64_t)a <  (uint64_t)b) ? 1 : 0; return true; }
        if (cond == "u<=") { out = ((uint64_t)a <= (uint64_t)b) ? 1 : 0; return true; }
        if (cond == "u>")  { out = ((uint64_t)a >  (uint64_t)b) ? 1 : 0; return true; }
        if (cond == "u>=") { out = ((uint64_t)a >= (uint64_t)b) ? 1 : 0; return true; }
        return false;
    default:
        return false;
    }
}

// ------------------------------------------------------------------
// CFG
// ------------------------------------------------------------------

struct Phi {
    int slot = 0;               // original frame slot
    int reg = -1;               // SSA version of the slot
    std::vector<int> in;        // input version per predecessor (pred[] order)
    bool dead = false;
};

struct Block {
    int id = 0;
    int start = 0, end = 0;     // instruction range in a working copy
    int label = -1;             // block's Label id, or -1 for the entry block
    int term = -1;              // terminator instruction index, or -1
    int termType = 0;           // 0 = none/fall, 1 = Br, 2 = BrZ/BrNZ/BrCC, 3 = Ret/Exit
    std::vector<int> succ;
    std::vector<int> pred;
    int idom = -1;
    std::vector<int> kids;      // dominator tree
    int tin = 0, tout = 0;      // dom-tree DFS interval
    int post = 1;               // CFG postorder number
    bool reach = false;
    std::vector<Phi> phis;
    bool phiInserted = false;   // used by phi placement liveness filter
};

struct Use {
    int blk = -1;   // block containing the use
    int phi = -1;   // >= 0 : phi index inside blk; else code instruction
    int pred = -1;  // for phi uses: predecessor index in blk->pred
    int pos = 0;    // for instruction uses: operand position (0/1/2)
    int instr = 0;  // for instruction uses: instruction index
};

struct LoopInfo {
    int header = 0;
    int preheader = -1;
    std::vector<int> body;
    std::unordered_set<int> bset;
};

struct Pass {
    explicit Pass(IRFunction& fn) : fn_(fn) {}

    IRFunction& fn_;
    std::vector<IRInstr> code_;                 // working copy (no garbage)
    std::vector<Block> blk_;
    std::unordered_map<int, int> labelBlk_;     // label id -> block id
    int nextLabel_ = 0;                         // fresh label ids
    int maxSlot_ = 0;                           // highest slot used (+1)
    int nextTemp_ = 0;                          // fresh temp slots for cycle copies

    std::vector<int> slotVerCnt_;               // per original slot, next version id
    std::vector<int> verSlot_;                  // (ssa - base) -> original slot
    std::unordered_map<int, int> defBlk_;       // ssa reg -> defining block id
    std::unordered_map<int, int> constVal_;     // ssa reg -> known int constant

    std::vector<std::vector<Use>> uses_;        // (ssa - base) -> use sites
    std::vector<int> pendingPhiUses_;           // scratch

    std::vector<std::vector<IRInstr>> hoistIn_; // per block: LICM-injected instrs
    std::vector<std::vector<IRInstr>> endCopies_;  // per block: phi copies before terminator
    std::unordered_map<int, std::vector<IRInstr>> insertAfter_; // fallthrough split blocks
    std::vector<std::vector<IRInstr>> appendBlocks_;  // labelled/self-loop split blocks, emitted last

    bool changed_ = false;

    // ----- SSA ids -----
    int newSSA() {
        int id = kSsaBase + (int)verSlot_.size();
        verSlot_.push_back(-1);
        return id;
    }
    int ver(int slot) {
        if ((int)slotVerCnt_.size() <= slot) slotVerCnt_.resize(slot + 1, 0);
        int id = newSSA();
        verSlot_[id - kSsaBase] = slot;
        slotVerCnt_[slot]++;
        return id;
    }
    int origSlot(int ssa) const {
        if (ssa < kSsaBase) return ssa;
        return verSlot_[ssa - kSsaBase];
    }
    size_t uidx(int ssa) { return (size_t)(ssa - kSsaBase); }
    void ensureUses(int ssa) {
        size_t i = uidx(ssa);
        if (uses_.size() <= i) uses_.resize(i + 1);
    }

    // ----- helpers -----
    int newLabel() { return nextLabel_++; }
    int freshTemp() { return maxSlot_++; }

    void setPos(IRInstr& in, int pos, int reg) {
        if (pos == 0) in.a.reg = reg;
        else if (pos == 1) in.b.reg = reg;
        else in.c.reg = reg;
    }

    bool dom(int a, int b) const {
        if (a == b) return true;
        return blk_[a].tin <= blk_[b].tin && blk_[b].tout <= blk_[a].tout;
    }
};

// ------------------------------------------------------------------
// CFG construction
// ------------------------------------------------------------------
static void buildCFG(Pass& p) {
    // basic blocks: every Label (and position 0) starts a new block
    std::vector<int> starts;
    starts.push_back(0);
    for (int i = 1; i < (int)p.code_.size(); i++) {
        if (p.code_[i].op == IROp::Label) starts.push_back(i);
    }
    if (starts.empty()) return;
    starts.push_back((int)p.code_.size());   // sentinel

    p.blk_.clear();
    p.labelBlk_.clear();
    for (int b = 0; b + 1 < (int)starts.size(); b++) {
        Block bl;
        bl.id = (int)p.blk_.size();
        bl.start = starts[b];
        bl.end = starts[b + 1];
        for (int i = bl.start; i < bl.end; i++) {
            if (p.code_[i].op == IROp::Label) {
                bl.label = p.code_[i].a.label;
                p.labelBlk_[bl.label] = bl.id;
                break;
            }
        }
        p.blk_.push_back(bl);
        // scan valid labels for id allocation
    }
    // max label id (from Label ops and branch targets) for fresh allocation
    int maxLab = 0;
    for (auto& in : p.code_) {
        if (in.op == IROp::Label) maxLab = std::max(maxLab, in.a.label + 1);
        if (in.op == IROp::Br || in.op == IROp::BrZ || in.op == IROp::BrNZ)
            maxLab = std::max(maxLab, in.b.label + 1);
        if (in.op == IROp::BrCC) maxLab = std::max(maxLab, in.c.label + 1);
    }
    p.nextLabel_ = maxLab;

    auto targetBlk = [&](int lab) {
        auto it = p.labelBlk_.find(lab);
        return it == p.labelBlk_.end() ? -1 : it->second;
    };

    for (size_t b = 0; b < p.blk_.size(); b++) {
        Block& bl = p.blk_[b];
        // last non-empty instruction
        bl.term = -1;
        for (int i = bl.end - 1; i >= bl.start; i--) {
            if (p.code_[i].garbage) continue;
            bl.term = i;
            break;
        }
        if (bl.term < 0) {                       // empty block
            bl.termType = 0;
        } else {
            switch (p.code_[bl.term].op) {
            case IROp::Br:
                bl.termType = 1;
                break;
            case IROp::BrZ: case IROp::BrNZ: case IROp::BrCC:
                bl.termType = 2;
                break;
            case IROp::Ret: case IROp::Exit:
                bl.termType = 3;
                break;
            default:
                bl.termType = 0;
                break;
            }
        }
    }

    auto nextBlk = [&](size_t b) -> int {
        return (b + 1 < p.blk_.size()) ? (int)(b + 1) : -1;
    };

    for (size_t b = 0; b < p.blk_.size(); b++) {
        Block& bl = p.blk_[b];
        if (bl.termType == 3) continue;          // no successors
        int nb = nextBlk(b);
        if (bl.term < 0) {                       // empty block just falls through
            if (nb >= 0) bl.succ.push_back(nb);
            continue;
        }
        const IRInstr& t = p.code_[bl.term];
        switch (t.op) {
        case IROp::Br: {
            int tb = targetBlk(t.b.label);
            if (tb >= 0) bl.succ.push_back(tb);
            break;
        }
        case IROp::BrZ: case IROp::BrNZ: {
            if (nb >= 0) bl.succ.push_back(nb);
            int tb = targetBlk(t.b.label);
            if (tb >= 0) bl.succ.push_back(tb);
            break;
        }
        case IROp::BrCC: {
            if (nb >= 0) bl.succ.push_back(nb);
            int tb = targetBlk(t.c.label);
            if (tb >= 0) bl.succ.push_back(tb);
            break;
        }
        default:
            if (nb >= 0) bl.succ.push_back(nb);
            break;
        }
    }
    for (size_t b = 0; b < p.blk_.size(); b++)
        for (int s : p.blk_[b].succ) p.blk_[s].pred.push_back((int)b);
}

// ------------------------------------------------------------------
// reachability + postorder + dominators
// ------------------------------------------------------------------
static void reachAndPostorder(Pass& p) {
    int n = (int)p.blk_.size();
    std::vector<int> order;                        // reachable blocks, preorder
    std::vector<char> vis(n, 0);
    p.blk_[0].reach = true;
    vis[0] = 1;
    order.push_back(0);
    // iterative BFS/DFS for reachability
    for (size_t qi = 0; qi < order.size(); qi++) {
        int b = order[qi];
        for (int s : p.blk_[b].succ) {
            if (!vis[s]) { vis[s] = 1; order.push_back(s); }
        }
    }
    for (int i = 0; i < n; i++) p.blk_[i].reach = vis[i];

    // postorder via DFS (iterative)
    std::vector<int> it(n, 0);
    std::vector<int> dfStack;
    std::vector<char> seen(n, 0);
    int postNo = 0;
    dfStack.push_back(0);
    seen[0] = 1;
    while (!dfStack.empty()) {
        int b = dfStack.back();
        if (it[b] < (int)p.blk_[b].succ.size()) {
            int s = p.blk_[b].succ[it[b]++];
            if (p.blk_[s].reach && !seen[s]) { seen[s] = 1; dfStack.push_back(s); }
        } else {
            p.blk_[b].post = ++postNo;
            dfStack.pop_back();
        }
    }

    // iterative dominators (Cooper-Harvey-Kennedy style)
    p.blk_[0].idom = 0;
    for (int i = 1; i < n; i++) p.blk_[i].idom = -1;
    auto intersect = [&](int a, int b) {
        while (a != b) {
            while (p.blk_[a].post < p.blk_[b].post) a = p.blk_[a].idom;
            while (p.blk_[b].post < p.blk_[a].post) b = p.blk_[b].idom;
        }
        return a;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b : order) {
            if (b == 0) continue;
            int newIdom = -1;
            for (int pr : p.blk_[b].pred) {
                if (!p.blk_[pr].reach || p.blk_[pr].idom < 0) continue;
                // a block dominates itself in this iteration
                if (pr == b) continue;
                newIdom = (newIdom < 0) ? pr : intersect(pr, newIdom);
            }
            if (newIdom < 0) newIdom = 0;              // safety
            if (p.blk_[b].idom != newIdom) {
                p.blk_[b].idom = newIdom;
                changed = true;
            }
        }
        // self edges can never list the loop head as idom for itself
        for (int b = 0; b < n; b++)
            if (p.blk_[b].reach && p.blk_[b].idom < 0) p.blk_[b].idom = 0;
    }
    for (int i = 0; i < n; i++)
        if (p.blk_[i].reach && i != 0) p.blk_[p.blk_[i].idom].kids.push_back(i);

    // dom-tree interval (tin/tout) via iterative DFS on kids
    int tick = 0;
    std::vector<std::pair<int, int>> stk;
    stk.push_back({0, 0});
    p.blk_[0].tin = ++tick;
    while (!stk.empty()) {
        auto& top = stk.back();
        int b = top.first;
        if (top.second < (int)p.blk_[b].kids.size()) {
            int c = p.blk_[b].kids[top.second++];
            p.blk_[c].tin = ++tick;
            stk.push_back({c, 0});
        } else {
            p.blk_[b].tout = tick;
            stk.pop_back();
        }
    }
}

// ------------------------------------------------------------------
// dominance frontiers + phi placement + rename
// ------------------------------------------------------------------
static void placePhis(Pass& p) {
    int n = (int)p.blk_.size();
    if (n < 2) return;

    // dominance frontiers: for every join b with |preds| >= 2, every node on
    // the idom-chain from a pred up to (but excluding) idom(b) gets b in its
    // frontier.
    std::vector<std::vector<int>> df(n);
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach || (int)p.blk_[b].pred.size() < 2) continue;
        for (int pr : p.blk_[b].pred) {
            if (!p.blk_[pr].reach) continue;
            int runner = pr;
            while (runner != p.blk_[b].idom) {
                if (runner < 0) break;
                df[runner].push_back(b);
                runner = p.blk_[runner].idom;
            }
        }
    }

    // which slots are defined in >1 block -> need phis
    std::unordered_map<int, int> defBlocks;       // slot -> count of defining blocks
    std::unordered_map<int, bool> seenInBlk;
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach) continue;
        seenInBlk.clear();
        for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
            if (p.code_[i].garbage) continue;
            int dst;
            if (opIsRegDef(p.code_[i], dst) && dst >= 0) {
                if (!seenInBlk.count(dst)) {
                    seenInBlk[dst] = true;
                    defBlocks[dst]++;
                }
            }
        }
    }

    auto hasPhi = [&](int b, int slot) {
        for (auto& ph : p.blk_[b].phis)
            if (ph.slot == slot) return true;
        return false;
    };

    std::vector<int> work;
    std::unordered_set<int> inWork;
    for (auto& kv : defBlocks) {
        if (kv.second < 2) continue;
        int slot = kv.first;
        work.clear();
        inWork.clear();
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            seenInBlk.clear();
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                if (p.code_[i].garbage) continue;
                int dst;
                if (opIsRegDef(p.code_[i], dst) && dst == slot) {
                    if (!seenInBlk.count(dst)) { seenInBlk[dst] = true; work.push_back(b); inWork.insert(b); break; }
                }
            }
        }
        int guard = 0;
        while (!work.empty() && guard++ < 200000) {
            int b = work.back();
            work.pop_back();
            inWork.erase(b);
            for (int e : df[b]) {
                if (hasPhi(e, slot)) continue;
                Phi ph;
                ph.slot = slot;
                ph.in.assign(p.blk_[e].pred.size(), 0);
                p.blk_[e].phis.push_back(ph);
                if (!inWork.count(e)) {
                    inWork.insert(e);
                    work.push_back(e);
                }
            }
        }
    }
}

// table of slot -> version stacks for the rename
struct Rename {
    Pass& p;
    std::unordered_map<int, std::vector<int>> stacks;

    Rename(Pass& pp) : p(pp) {}
    int cur(int slot) {
        auto it = stacks.find(slot);
        if (it == stacks.end() || it->second.empty()) return slot;   // initial version = the slot
        return it->second.back();
    }
    void push(int slot, int v) { stacks[slot].push_back(v); }
    void pop(int slot) { auto& s = stacks[slot]; s.pop_back(); }
};

static void renameFunc(Pass& p) {
    Rename rn(p);
    int n = (int)p.blk_.size();

    // iterate dominator tree in preorder (iterative); each block records the
    // slots it pushed so the unwind at block exit pops exactly those.
    std::vector<std::pair<int, int>> stk;         // (block, kid index)
    std::vector<std::vector<int>> pushedByBlk(n);
    stk.push_back({0, 0});
    while (!stk.empty()) {
        auto& top = stk.back();
        int b = top.first;
        if (top.second == 0) {
            // ---- entering block b: process phis, instructions, successors ----
            pushedByBlk[b].clear();
            for (auto& ph : p.blk_[b].phis) {
                int v = p.ver(ph.slot);
                ph.reg = v;
                p.defBlk_[v] = b;
                rn.push(ph.slot, v);
                pushedByBlk[b].push_back(ph.slot);
            }
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                IRInstr& in = p.code_[i];
                if (in.garbage) continue;
                // reads first (uses the state *before* this instruction's def)
                forEachRead(in, [&](IROperand& o, int) {
                    o.reg = rn.cur(o.reg);
                });
                int dst;
                if (opIsRegDef(in, dst)) {
                    int v = p.ver(dst);
                    in.a.reg = v;
                    p.defBlk_[v] = b;
                    rn.push(dst, v);
                    pushedByBlk[b].push_back(dst);
                    if (in.op == IROp::Const) p.constVal_[v] = in.b.imm;
                }
            }
            // fill phi inputs (all matching pred indices) for each successor
            for (int s : p.blk_[b].succ) {
                for (int k = 0; k < (int)p.blk_[s].pred.size(); k++) {
                    if (p.blk_[s].pred[k] != b) continue;
                    for (auto& ph : p.blk_[s].phis)
                        ph.in[k] = rn.cur(ph.slot);
                }
            }
        }
        // descend to kid
        if (top.second < (int)p.blk_[b].kids.size()) {
            int c = p.blk_[b].kids[top.second++];
            stk.push_back({c, 0});
        } else {
            // pop the versions pushed at block entry
            for (int s : pushedByBlk[b]) rn.pop(s);
            stk.pop_back();
        }
    }
}

// ------------------------------------------------------------------
// def/use bookkeeping after renaming
// ------------------------------------------------------------------
static void rebuildUses(Pass& p) {
    p.uses_.clear();
    int n = (int)p.blk_.size();
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach) continue;
        for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
            IRInstr& in = p.code_[i];
            if (in.garbage) continue;
            forEachRead(in, [&](IROperand& o, int pos) {
                if (o.reg < kSsaBase) return;      // param reads keep raw slots
                p.ensureUses(o.reg);
                Use u; u.blk = b; u.phi = -1; u.pos = pos; u.instr = i;
                p.uses_[p.uidx(o.reg)].push_back(u);
            });
        }
        for (int pi = 0; pi < (int)p.blk_[b].phis.size(); pi++) {
            auto& ph = p.blk_[b].phis[pi];
            if (ph.dead) continue;
            for (int k = 0; k < (int)ph.in.size(); k++) {
                int v = ph.in[k];
                if (v < kSsaBase) continue;
                p.ensureUses(v);
                Use u; u.blk = b; u.phi = pi; u.pred = k;
                p.uses_[p.uidx(v)].push_back(u);
            }
        }
    }
}

// ------------------------------------------------------------------
// rewiring a value to another (GVN / copy-prop / phi folding)
// ------------------------------------------------------------------
static void rewire(Pass& p, int from, int to) {
    if (from < kSsaBase || to < kSsaBase || from == to) {
        if (from == to) return;
        // if one side is a raw slot... only reachable when phi merged a raw
        // param; treat as no-op for safety
        return;
    }
    p.ensureUses(from);
    p.ensureUses(to);
    auto& src = p.uses_[p.uidx(from)];
    auto& dst = p.uses_[p.uidx(to)];
    for (auto& u : src) {
        if (u.phi >= 0) {
            p.blk_[u.blk].phis[u.phi].in[u.pred] = to;
        } else {
            p.setPos(p.code_[u.instr], u.pos, to);
        }
        dst.push_back(u);
    }
    src.clear();
}

// ------------------------------------------------------------------
// SSA constant propagation + trivial-phi folding
// ------------------------------------------------------------------
static void ssaConstFold(Pass& p) {
    int n = (int)p.blk_.size();

    // trivial phi: every input is the same value v  -> rewire phi uses to v
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 64) {
        changed = false;
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            for (size_t pi = 0; pi < p.blk_[b].phis.size(); pi++) {
                auto& ph = p.blk_[b].phis[pi];
                if (ph.dead || ph.reg < kSsaBase) continue;
                int common = -1;
                bool ok = true;
                for (int v : ph.in) {
                    if (v < kSsaBase) continue;   // raw param
                    if (common < 0) common = v;
                    else if (common != v) { ok = false; break; }
                }
                if (ok && common >= kSsaBase) {
                    // also make sure common is not the phi itself
                    if (common == ph.reg) { ph.dead = true; changed = true; continue; }
                    p.ensureUses(ph.reg);
                    for (auto& u : p.uses_[p.uidx(ph.reg)]) {
                        if (u.phi >= 0) p.blk_[u.blk].phis[u.phi].in[u.pred] = common;
                        else p.setPos(p.code_[u.instr], u.pos, common);
                    }
                    // move uses into common
                    p.ensureUses(common);
                    auto& dst = p.uses_[p.uidx(common)];
                    auto& src = p.uses_[p.uidx(ph.reg)];
                    for (auto& u : src) dst.push_back(u);
                    src.clear();
                    ph.dead = true;
                    p.fn_.foldedInstrs++;
                    changed = true;
                    break;
                }
            }
        }
    }

    // fold pure instructions with constant inputs
    int guard2 = 0;
    bool changed2 = true;
    while (changed2 && guard2++ < 64) {
        changed2 = false;
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                IRInstr& in = p.code_[i];
                if (in.garbage) continue;
                if (!isPureSSA(in.op)) continue;
                if (in.op == IROp::Const) continue;    // already a constant
                int dst;
                if (!opIsRegDef(in, dst) || dst < kSsaBase) continue;

                auto constOfReg = [&](int r, int64_t& v) -> bool {
                    auto it = p.constVal_.find(r);
                    if (it != p.constVal_.end()) { v = it->second; return true; }
                    return false;
                };

                // Cmp/Mov/Neg/Not are unary-ish? they read b and maybe c.
                // Read the two sources generically through forEachRead.
                int64_t vals[2] = {0, 0};
                bool ok = true;
                int cnt = 0;
                forEachRead(in, [&](IROperand& o, int) {
                    if (cnt >= 2) { ok = false; return; }
                    if (o.kind == IROperand::Imm) { vals[cnt] = o.imm; cnt++; }
                    else if (o.kind == IROperand::Reg && o.reg >= kSsaBase) {
                        if (!constOfReg(o.reg, vals[cnt])) { ok = false; return; }
                        cnt++;
                    } else ok = false;
                });
                if (!ok || cnt == 0) continue;

                int64_t outv;
                if (!foldIntOp(in.op, in.cond, vals[0], cnt > 1 ? vals[1] : 0, outv)) continue;
                // float ops require double care -> skip (foldIntOp returns
                // false for them anyway)
                in.op = IROp::Const;
                in.b = IROperand::mkImm(outv);
                in.c = IROperand::none();
                p.constVal_[dst] = outv;
                p.fn_.foldedInstrs++;
                changed2 = true;
            }
        }
    }
}

// ------------------------------------------------------------------
// GVN (dominance-checked value numbering)
// ------------------------------------------------------------------
static void ssaGVN(Pass& p) {
    int n = (int)p.blk_.size();
    if (n < 2) return;

    struct GVNKey {
        std::string s;
        bool operator==(const GVNKey& o) const { return s == o.s; }
    };
    struct GVNKeyHash {
        size_t operator()(const GVNKey& k) const { return std::hash<std::string>()(k.s); }
    };
    std::unordered_map<GVNKey, int, GVNKeyHash> table;

    auto appendO = [&](std::string& s, const IROperand& o) {
        s.push_back((char)o.kind);
        if (o.kind == IROperand::Reg) {
            s.append((const char*)&o.reg, sizeof(int));
        } else if (o.kind == IROperand::Imm || o.kind == IROperand::FImm) {
            s.append((const char*)&o.imm, sizeof(int64_t));
        } else if (o.kind == IROperand::StrIdx) {
            s.append((const char*)&o.strIdx, sizeof(int));
        } else if (o.kind == IROperand::Slot) {
            s.append((const char*)&o.reg, sizeof(int));
        } else if (o.kind == IROperand::Global || o.kind == IROperand::Func ||
                   o.kind == IROperand::Import) {
            s.append(o.name);
            s.push_back('|');
            s.append(o.dll);
        } else if (o.kind == IROperand::Label) {
            s.append((const char*)&o.label, sizeof(int));
        }
        s.append((const char*)&o.off, sizeof(int));
    };

    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 16) {
        changed = false;
        table.clear();   // every def seen this iteration is live (garbage skipped)
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                IRInstr& in = p.code_[i];
                if (in.garbage) continue;
                if (!isGvn(in.op)) continue;
                int dst;
                if (!opIsRegDef(in, dst) || dst < kSsaBase) continue;

                // the key covers the operation's *inputs* only; the def
                // register must not be part of it or no two independent
                // computations would ever match.
                std::string key;
                key.append((const char*)&in.op, sizeof(int));
                key.append(in.cond);
                key.push_back('|');
                appendO(key, in.b);
                appendO(key, in.c);

                auto it = table.find(GVNKey{key});
                if (it != table.end()) {
                    int v = it->second;
                    if (v != dst && p.defBlk_.count(v) &&
                        p.dom(p.defBlk_[v], b)) {
                        // replace all uses of dst with v
                        p.ensureUses(dst);
                        p.ensureUses(v);
                        auto& dstU = p.uses_[p.uidx(dst)];
                        auto& vU = p.uses_[p.uidx(v)];
                        for (auto& u : dstU) {
                            if (u.phi >= 0) p.blk_[u.blk].phis[u.phi].in[u.pred] = v;
                            else p.setPos(p.code_[u.instr], u.pos, v);
                            vU.push_back(u);
                        }
                        dstU.clear();
                        in.garbage = true;
                        p.fn_.memOpts++;
                        changed = true;
                        continue;
                    }
                } else {
                    table.emplace(GVNKey{key}, dst);
                }
            }
        }
    }
}

// ------------------------------------------------------------------
// SSA dead code elimination
// ------------------------------------------------------------------
static void ssaDCE(Pass& p) {
    int n = (int)p.blk_.size();
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 256) {
        changed = false;
        std::unordered_map<int, int> cnt;                 // ssa -> use count
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                IRInstr& in = p.code_[i];
                if (in.garbage) continue;
                forEachRead(in, [&](const IROperand& o, int) {
                    if (o.reg >= kSsaBase) cnt[o.reg]++;
                });
            }
            for (auto& ph : p.blk_[b].phis) {
                if (ph.dead) continue;
                for (int v : ph.in) if (v >= kSsaBase) cnt[v]++;
            }
        }
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                IRInstr& in = p.code_[i];
                if (in.garbage || !isPureSSA(in.op)) continue;
                int dst;
                if (!opIsRegDef(in, dst)) continue;
                auto it = cnt.find(dst);
                if (it == cnt.end() || it->second == 0) {
                    in.garbage = true;
                    p.fn_.dceRemoved++;
                    changed = true;
                }
            }
            for (auto& ph : p.blk_[b].phis) {
                if (ph.dead) continue;
                auto it = cnt.find(ph.reg);
                if (it == cnt.end() || it->second == 0) {
                    ph.dead = true;
                    p.fn_.dceRemoved++;
                    changed = true;
                }
            }
        }
    }
}

// ------------------------------------------------------------------
// constant-condition branch folding
// ------------------------------------------------------------------

// Fold conditional terminators whose condition is a known constant. The
// losing edge is only removed when its target becomes unreachable (i.e.
// has no other *reachable* pred), so the phi/pred bookkeeping of every
// surviving join block stays intact and de-SSA remains consistent. The
// CFG edge lists are updated here; reach/dom are refreshed afterwards.
static bool ssaBranchFold(Pass& p) {
    int n = (int)p.blk_.size();

    auto knownConst = [&](const IROperand& o, int64_t& out) -> bool {
        if (o.kind == IROperand::Imm) { out = o.imm; return true; }
        if (o.kind == IROperand::Reg && o.reg >= kSsaBase) {
            auto it = p.constVal_.find(o.reg);
            if (it != p.constVal_.end()) { out = it->second; return true; }
        }
        return false;
    };

    // remove the edge from->to (from.succ & to.pred stay index-consistent
    // for every surviving block: `to` must be about to become unreachable).
    auto removeEdge = [&](int from, int to) {
        auto& fs = p.blk_[from].succ;
        fs.erase(std::remove(fs.begin(), fs.end(), to), fs.end());
        auto& tp = p.blk_[to].pred;
        tp.erase(std::remove(tp.begin(), tp.end(), from), tp.end());
    };

    auto lonePred = [&](int blk, int only) -> bool {
        for (int pr : p.blk_[blk].pred)
            if (pr != only && p.blk_[pr].reach) return false;
        return true;
    };

    bool any = false;
    for (int g = 0; g < 64; g++) {
        bool changed = false;
        for (int b = 0; b < n; b++) {
            if (!p.blk_[b].reach) continue;
            Block& bl = p.blk_[b];
            if (bl.term < 0 || bl.termType != 2) continue;
            IRInstr& t = p.code_[bl.term];
            if (t.garbage) continue;

            int64_t ca, cb;
            int64_t condTrue = 0;
            bool hasCond = false;
            bool taken = false;          // true = branch (label) is taken

            if (t.op == IROp::BrZ || t.op == IROp::BrNZ) {
                if (knownConst(t.a, ca)) { hasCond = true; condTrue = ca; }
            } else if (t.op == IROp::BrCC) {
                if (knownConst(t.a, ca) && knownConst(t.b, cb)) {
                    int64_t v;
                    if (foldIntOp(IROp::Cmp, t.cond, ca, cb, v)) {
                        hasCond = true; condTrue = (v != 0) ? 1 : 0;
                    }
                }
            }
            if (!hasCond) continue;

            if (t.op == IROp::BrZ)       taken = (condTrue == 0);
            else if (t.op == IROp::BrNZ) taken = (condTrue != 0);
            else /* BrCC */              taken = (condTrue != 0);

            int fb = (b + 1 < n) ? (b + 1) : -1;
            int tl = (t.op == IROp::BrCC) ? t.c.label : t.b.label;
            int tb = p.labelBlk_.count(tl) ? p.labelBlk_[tl] : -1;

            // any conditional whose branch target is its own fallthrough is
            // a no-op for both outcomes; never fold those.
            if (tb < 0 || tb == fb) continue;

            int losing;
            if (taken) {
                losing = fb;              // branch survives: drop the fallthrough
            } else {
                if (fb < 0) continue;     // no fallthrough: would fall off the function end
                losing = tb;              // fallthrough survives: drop the branch
            }
            if (!std::count(p.blk_[b].succ.begin(), p.blk_[b].succ.end(), losing)) continue;
            if (!lonePred(losing, b)) continue;

            // rewrite the terminator
            if (taken) {
                t.op = IROp::Br;
                t.a = IROperand::none();
                t.b = IROperand::lbl(tl);
                t.c = IROperand::none();
                bl.termType = 1;
            } else {
                t.garbage = true;
                bl.term = -1;
                bl.termType = 0;
            }

            removeEdge(b, losing);
            p.fn_.ssaBranches++;
            changed = true;
        }
        if (!changed) break;
        any = true;
    }
    if (any) reachAndPostorder(p);
    return any;
}

// ------------------------------------------------------------------
// block-local redundant pointer-load elimination (alias-conservative)
// ------------------------------------------------------------------

// CSEs pointer loads (peek family / GLoad) whose address operand is the
// *identical* SSA id and that are not separated by anything that could
// write to that memory. Only the 8-byte PLoad and GLoad families are
// value-numbered; different widths/addresses are never folded.

struct MemCSEKey { uint64_t tag; int64_t addr; int64_t off; bool operator==(const MemCSEKey& o) const {
    return tag == o.tag && addr == o.addr && off == o.off; } };
struct MemCSEHasher { size_t operator()(const MemCSEKey& k) const {
    return (size_t)k.tag * 0x9E3779B97F4A7C15ull ^ ((size_t)k.addr * 0x100000001B3ull) ^ (size_t)k.off; } };

static void ssaMemCSE(Pass& p) {
    int n = (int)p.blk_.size();
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach) continue;
        std::unordered_map<MemCSEKey, int, MemCSEHasher> last;
        for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
            IRInstr& in = p.code_[i];
            if (in.garbage) continue;
            switch (in.op) {
            case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
            case IROp::PLoadW: case IROp::PLoadB: {
                int dst;
                if (!opIsRegDef(in, dst) || dst < kSsaBase) break;
                MemCSEKey key;
                key.tag = (uint64_t)(int)in.op;
                key.addr = (in.b.kind == IROperand::Reg) ? in.b.reg : -1;
                key.off = in.b.off;
                auto it = last.find(key);
                if (it != last.end() && it->second != dst) {
                    rewire(p, dst, it->second);
                    in.garbage = true;
                    p.fn_.memOpts++;
                    break;
                }
                last[key] = dst;
                break;
            }
            case IROp::GLoad: case IROp::GLoad32: case IROp::FGLoad: {
                int dst;
                if (!opIsRegDef(in, dst) || dst < kSsaBase) break;
                MemCSEKey key;
                key.tag = (uint64_t)(int)in.op;
                key.addr = 0;
                key.off = in.b.off;
                if (in.b.kind == IROperand::Global) key.addr = (int64_t)std::hash<std::string>{}(in.b.name)
                                                          ^ (int64_t)((uint64_t)in.label << 1);
                auto it = last.find(key);
                if (it != last.end() && it->second != dst) {
                    rewire(p, dst, it->second);
                    in.garbage = true;
                    p.fn_.memOpts++;
                    break;
                }
                last[key] = dst;
                break;
            }
            case IROp::Store: case IROp::Store32: case IROp::FStore:
            case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
            case IROp::PStore: case IROp::PStore32: case IROp::PStoreW:
            case IROp::PStoreB: case IROp::FPStore:
            case IROp::Load: case IROp::Load32: case IROp::FLoad:
            case IROp::LeaSlot:
            case IROp::Call: case IROp::ICall:
            case IROp::PrintStr: case IROp::PrintInt: case IROp::PrintFlt:
                last.clear();
                break;
            default:
                break;
            }
        }
    }
}
// ------------------------------------------------------------------
// LICM: hoist invariant pure computations to loop preheaders
// ------------------------------------------------------------------
static void findLoops(Pass& p, std::vector<LoopInfo>& loops) {
    int n = (int)p.blk_.size();
    // back edges: s -> h where h dominates s
    std::unordered_map<int, std::vector<int>> backEdges;
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach || b == 0) continue;
        for (int s : p.blk_[b].succ) {
            if (s != b && p.dom(s, b)) backEdges[s].push_back(b);
        }
    }
    for (auto& kv : backEdges) {
        int h = kv.first;
        LoopInfo lp;
        lp.header = h;
        lp.bset.insert(h);
        std::vector<int> work = kv.second;
        while (!work.empty()) {
            int b = work.back();
            work.pop_back();
            if (b == h || lp.bset.count(b)) continue;
            lp.bset.insert(b);
            for (int pr : p.blk_[b].pred) {
                if (pr != h && !lp.bset.count(pr)) work.push_back(pr);
            }
        }
        lp.body.assign(lp.bset.begin(), lp.bset.end());
        int im = p.blk_[h].idom;
        if (im >= 0 && im != h && !lp.bset.count(im)) lp.preheader = im;
        loops.push_back(std::move(lp));
    }
    // innermost first (smaller bodies)
    std::sort(loops.begin(), loops.end(), [](const LoopInfo& a, const LoopInfo& b) {
        return a.body.size() < b.body.size();
    });
}

static void licm(Pass& p) {
    std::vector<LoopInfo> loops;
    findLoops(p, loops);
    int n = (int)p.blk_.size();
    p.hoistIn_.assign(n, {});
    if (n < 2) return;

    for (auto& lp : loops) {
        if (lp.preheader < 0) continue;

        // invariance of a value w.r.t. this loop:
        //   const, or defined outside the loop, or defined by a hoistable
        //   instruction whose sources are all invariant.
        std::unordered_map<int, bool> inv;
        bool more = true;
        int guard = 0;
        while (more && guard++ < 64) {
            more = false;
            for (int b : lp.body) {
                for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                    IRInstr& in = p.code_[i];
                    if (in.garbage) continue;
                    int dst;
                    if (!opIsRegDef(in, dst) || dst < kSsaBase) continue;
                    if (inv.count(dst)) continue;
                    if (lp.bset.count(p.defBlk_[dst]) == 0) { inv[dst] = true; continue; }
                    if (in.op == IROp::Const) { inv[dst] = true; continue; }
                    if (!isHoistable(in.op)) continue;
                    bool allOk = true;
                    forEachRead(in, [&](IROperand& o, int) {
                        if (o.reg < kSsaBase) return;         // raw param read
                        auto it = inv.find(o.reg);
                        if (it == inv.end() || !it->second) allOk = false;
                        else if (o.reg == dst) allOk = false; // cycle: skip
                    });
                    if (allOk) { inv[dst] = true; more = true; }
                }
            }
        }

        // hoist instructions whose defs are now invariant
        bool any = true;
        while (any) {
            any = false;
            for (int b : lp.body) {
                for (int i = p.blk_[b].start; i < p.blk_[b].end; i++) {
                    IRInstr& in = p.code_[i];
                    if (in.garbage) continue;
                    int dst;
                    if (!opIsRegDef(in, dst) || dst < kSsaBase) continue;
                    if (!lp.bset.count(p.defBlk_[dst])) continue;   // not defined here
                    if (!inv.count(dst) || !inv[dst]) continue;
                    if (!isHoistable(in.op)) continue;
                    // skip if it reads a value that is still moving (safety):
                    bool srcsOk = true;
                    forEachRead(in, [&](const IROperand& o, int) {
                        if (o.reg >= kSsaBase) {
                            auto it = inv.find(o.reg);
                            if (it == inv.end() || !it->second) srcsOk = false;
                        }
                    });
                    if (!srcsOk) continue;
                    // don't re-hoist something already injected
                    bool already = false;
                    for (auto& h : p.hoistIn_[lp.preheader])
                        if (!h.garbage && h.a.reg == dst) { already = true; break; }
                    if (already) continue;
                    p.hoistIn_[lp.preheader].push_back(in);
                    in.garbage = true;
                    p.fn_.memOpts++;
                    p.fn_.ssaHoisted++;
                    any = true;
                }
            }
        }
    }
}

// ------------------------------------------------------------------
// de-SSA: resolve phis into parallel copies on edges
// ------------------------------------------------------------------

static IRInstr mkMov(int dst, int src) {
    IRInstr in;
    in.op = IROp::Mov;
    in.a = IROperand::mkReg(dst);
    in.b = IROperand::mkReg(src);
    return in;
}

static IRInstr mkLabel(int lab) {
    IRInstr in;
    in.op = IROp::Label;
    in.a = IROperand::lbl(lab);
    return in;
}

static IRInstr mkBr(int lab) {
    IRInstr in;
    in.op = IROp::Br;
    in.b = IROperand::lbl(lab);
    return in;
}

// Retarget the labelled target `fromLabel` of pred's terminator to `toLabel`.
static void retargetTerm(Pass& p, int pred, int fromLabel, int toLabel) {
    IRInstr& term = p.code_[p.blk_[pred].term];
    if (term.op == IROp::Br || term.op == IROp::BrZ || term.op == IROp::BrNZ) {
        if (term.b.label == fromLabel) term.b.label = toLabel;
    } else if (term.op == IROp::BrCC) {
        if (term.c.label == fromLabel) term.c.label = toLabel;
    }
}

// place the copies for one edge; splits critical edges by inserting a
// dedicated block. Split blocks land either right after the pred in the
// stream (fall-through successor: reached by falling through) or in
// appendBlocks_ (labelled/self-loop successor: reached by a retargeted
// branch).
static void emitEdgeCopies(Pass& p, int pred, int succ) {
    // gather non-trivial copy tasks for live phis of the successor
    int pi = -1;
    for (int k = 0; k < (int)p.blk_[succ].pred.size(); k++)
        if (p.blk_[succ].pred[k] == pred) { pi = k; break; }
    if (pi < 0) return;

    struct Task { int dst; int src; };
    std::vector<Task> tasks;
    for (auto& ph : p.blk_[succ].phis) {
        if (ph.dead) continue;
        int d = p.origSlot(ph.reg);
        int s = p.origSlot(ph.in[pi]);
        if (d == s) continue;                    // already in place (same slot)
        tasks.push_back({d, s});
    }
    if (tasks.empty()) return;

    // resolve parallel copies (may need temps for cycles) -> linear Movs
    std::vector<IRInstr> copies;
    while (true) {
        bool anyRemoved = false;
        for (size_t k = 0; k < tasks.size();) {
            if (tasks[k].dst == tasks[k].src) { tasks.erase(tasks.begin() + k); anyRemoved = true; continue; }
            k++;
        }
        if (tasks.empty()) break;
        // find a task whose source is not some other task's destination
        int pick = -1;
        for (size_t k = 0; k < tasks.size(); k++) {
            bool srcIsOtherDst = false;
            for (size_t m = 0; m < tasks.size(); m++) {
                if (m == k) continue;
                if (tasks[m].dst == tasks[k].src) { srcIsOtherDst = true; break; }
            }
            if (!srcIsOtherDst) { pick = (int)k; break; }
        }
        if (pick < 0) {
            // cycle: break with a temp slot
            int t = p.freshTemp();
            copies.push_back(mkMov(t, tasks[0].src));
            tasks[0].src = t;
            continue;
        }
        copies.push_back(mkMov(tasks[pick].dst, tasks[pick].src));
        tasks.erase(tasks.begin() + pick);
    }
    if (copies.empty()) return;
    p.fn_.ssaCopies += (int)copies.size();

    int termType = p.blk_[pred].termType;
    Block& pb = p.blk_[pred];
    Block& sb = p.blk_[succ];

    if (succ == pred) {
        // self loop: the loop-carried phi value must be refreshed every
        // iteration, but NOT on the path that enters the loop for the first
        // time. A dedicated appended block carries the copies and feeds
        // back into the header; the header's jump to itself is retargeted
        // to that block, so only the looping path runs the copies.
        int lab = p.newLabel();
        std::vector<IRInstr> bl;
        bl.push_back(mkLabel(lab));
        for (auto& c : copies) bl.push_back(c);
        bl.push_back(mkBr(pb.label < 0 ? 0 : pb.label));
        p.appendBlocks_.push_back(std::move(bl));
        retargetTerm(p, pred, pb.label, lab);
        return;
    }

    if (termType == 2) {
        // conditional terminator: two successors -> critical edge; split.
        int cnt = 0, idx = -1;
        for (int k = 0; k < (int)pb.succ.size(); k++)
            if (pb.succ[k] == succ) { cnt++; if (idx < 0) idx = k; }
        if (cnt >= 2) {
            // both edges carry the same value (same pred index), so the
            // copies must run on every takeable edge: put them before the
            // terminator instead of on one of the two edges.
            for (auto& c : copies) p.endCopies_[pred].push_back(c);
            return;
        }
        bool viaFall = (idx == 0);      // succ[0] is always the fall-through
        int lab = p.newLabel();
        std::vector<IRInstr> bl;
        if (viaFall) {
            bl.push_back(mkLabel(lab));
            for (auto& c : copies) bl.push_back(c);
            bl.push_back(mkBr(sb.label));
            p.insertAfter_[pred] = std::move(bl);
        } else {
            // labelled successor: retarget the branch into an appended block
            bl.push_back(mkLabel(lab));
            for (auto& c : copies) bl.push_back(c);
            bl.push_back(mkBr(sb.label));
            p.appendBlocks_.push_back(std::move(bl));
            retargetTerm(p, pred, sb.label, lab);
        }
        return;
    }

    // single successor: copies before the terminator (no split needed)
    for (auto& c : copies) p.endCopies_[pred].push_back(c);
}

// ------------------------------------------------------------------
// rebuild the linear instruction list
// ------------------------------------------------------------------
static void setOperandSlots(Pass& p, IRInstr& in) {
    // convert SSA ids back to original slots
    if (in.a.kind == IROperand::Reg && in.a.reg >= kSsaBase) in.a.reg = p.origSlot(in.a.reg);
    if (in.b.kind == IROperand::Reg && in.b.reg >= kSsaBase) in.b.reg = p.origSlot(in.b.reg);
    if (in.c.kind == IROperand::Reg && in.c.reg >= kSsaBase) in.c.reg = p.origSlot(in.c.reg);
}

static void rebuild(Pass& p) {
    int n = (int)p.blk_.size();
    p.hoistIn_.resize(n);
    p.endCopies_.resize(n);

    std::vector<IRInstr> out;

    // emit each reachable block in original linear order; labels are
    // re-emitted explicitly and the block's own Label instruction is then
    // skipped by the body loop (avoids duplicating the marker).
    for (int b = 0; b < n; b++) {
        if (!p.blk_[b].reach) continue;
        Block& bl = p.blk_[b];
        if (bl.label >= 0) out.push_back(mkLabel(bl.label));
        // body instructions up to (but excluding) the terminator
        for (int i = bl.start; i < bl.end; i++) {
            if (i == bl.term) break;
            IRInstr& in = p.code_[i];
            if (in.garbage) continue;
            if (in.op == IROp::Label) continue;   // already printed above
            setOperandSlots(p, in);
            out.push_back(in);
        }
        // LICM-injected instructions
        if (b < (int)p.hoistIn_.size())
            for (auto& h : p.hoistIn_[b]) {
                if (h.garbage) continue;
                IRInstr c = h;
                setOperandSlots(p, c);
                out.push_back(c);
            }
        // phi edge copies
        if (b < (int)p.endCopies_.size())
            for (auto& c : p.endCopies_[b]) out.push_back(c);
        // terminator
        if (bl.term >= 0) {
            IRInstr& t = p.code_[bl.term];
            if (!t.garbage) {
                setOperandSlots(p, t);
                out.push_back(t);
            }
        }
        // fall-through split block immediately after this block
        auto it = p.insertAfter_.find(b);
        if (it != p.insertAfter_.end()) {
            for (auto& in : it->second) {
                IRInstr c = in;
                setOperandSlots(p, c);
                out.push_back(c);
            }
        }
    }
    // appended (labelled / self-loop) split blocks: reached only through a
    // retargeted branch, so their position is not flow-sensitive.
    for (auto& bl : p.appendBlocks_) {
        for (auto& in : bl) {
            IRInstr c = in;
            setOperandSlots(p, c);
            out.push_back(c);
        }
    }

    p.code_.swap(out);
    p.fn_.instrs.assign(out.begin(), out.end());
    p.fn_.maxSlot = std::max(p.fn_.maxSlot, p.maxSlot_);
}

} // namespace

// ====================================================================
// entry
// ====================================================================
bool IRSSA::optimize(IRFunction& fn) {
    Pass p(fn);

    // working copy: drop garbage, drop pre-EndFunc tail if any
    std::vector<bool> keep(fn.instrs.size(), true);
    for (size_t i = 0; i < fn.instrs.size(); i++)
        if (fn.instrs[i].garbage) keep[i] = false;

    int lastLive = (int)fn.instrs.size();
    for (int i = lastLive - 1; i >= 0; i--)
        if (fn.instrs[i].op == IROp::EndFunc && !fn.instrs[i].garbage) { lastLive = i + 1; break; }

    for (int i = 0; i < lastLive; i++)
        if (keep[i]) p.code_.push_back(fn.instrs[i]);

    if (p.code_.size() < 6) return false;

    // slot range (only *original* registers/memories; SSA ids are later)
    for (auto& in : p.code_) {
        if (in.a.kind == IROperand::Reg) p.maxSlot_ = std::max(p.maxSlot_, in.a.reg + 1);
        if (in.b.kind == IROperand::Reg) p.maxSlot_ = std::max(p.maxSlot_, in.b.reg + 1);
        if (in.c.kind == IROperand::Reg) p.maxSlot_ = std::max(p.maxSlot_, in.c.reg + 1);
        if (in.a.kind == IROperand::Slot) p.maxSlot_ = std::max(p.maxSlot_, in.a.reg + 1);
        if (in.b.kind == IROperand::Slot) p.maxSlot_ = std::max(p.maxSlot_, in.b.reg + 1);
        if (in.c.kind == IROperand::Slot) p.maxSlot_ = std::max(p.maxSlot_, in.c.reg + 1);
    }

    buildCFG(p);
    if (p.blk_.size() < 2) return false;

    reachAndPostorder(p);
    placePhis(p);
    renameFunc(p);            // may derive param reads -> raw slots stay raw
    rebuildUses(p);

    ssaConstFold(p);
    ssaGVN(p);
    ssaMemCSE(p);
    ssaDCE(p);
    licm(p);
    ssaDCE(p);
    ssaMemCSE(p);
    if (ssaBranchFold(p)) ssaDCE(p);   // fold const branches; clean dead conditions

    // de-SSA: copy-in phi arguments on their edges
    int n = (int)p.blk_.size();
    p.hoistIn_.resize(n);
    p.endCopies_.resize(n, {});
    std::set<std::pair<int, int>> doneEdges;
    for (int s = 0; s < n; s++) {
        if (!p.blk_[s].reach) continue;
        if (p.blk_[s].phis.empty()) continue;
        for (int pr : p.blk_[s].pred) {
            if (!p.blk_[pr].reach) continue;
            if (!doneEdges.insert({pr, s}).second) continue;   // parallel edges share one copy set
            emitEdgeCopies(p, pr, s);
        }
    }
    // raw slot conversions in the working copy
    for (auto& in : p.code_) setOperandSlots(p, in);
    // reset work-space fields before rebuild
    p.hoistIn_.resize(n);
    p.endCopies_.resize(n, {});
    rebuild(p);

    fn.maxSlot = std::max(fn.maxSlot, p.maxSlot_);
    return true;
}