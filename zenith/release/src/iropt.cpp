#include "iropt.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <functional>

// ====================================================================
// helper: operand inspection
// ====================================================================

// Returns true if the instruction defines a value into a.reg (Reg kind).
static bool definesReg(const IRInstr& in) {
    if (in.garbage) return false;
    if (in.a.kind != IROperand::Reg) return false;
    switch (in.op) {
    case IROp::Const: case IROp::FConst: case IROp::Str:
    case IROp::Mov: case IROp::FMov:
    case IROp::LeaGlobal: case IROp::LeaSlot:
    // case IROp::Load: case IROp::Load32: case IROp::FLoad:
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
        return true;
    default:
        return false;
    }
}

// The op is a "pure" computation: no memory writes, no control flow,
// no observable side effects. Safe to remove when its result is unused.
static bool isPureCompute(IROp op) {
    switch (op) {
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
        return true;
    default:
        return false;
    }
}

// Records the register (Reg kind) operands that are *read* by the instruction.
static void regInputs(const IRInstr& in, int& u1, int& u2) {
    u1 = u2 = -1;
    if (in.garbage) return;
    auto isReg = [](const IROperand& o) { return o.kind == IROperand::Reg; };
    switch (in.op) {
    case IROp::Store: case IROp::Store32: case IROp::FStore:
        if (isReg(in.b)) u1 = in.b.reg;
        break;
    case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
        if (isReg(in.b)) u1 = in.b.reg;
        break;
    case IROp::PStore: case IROp::PStore32: case IROp::PStoreW: case IROp::PStoreB:
    case IROp::FPStore:
        if (isReg(in.a)) u1 = in.a.reg;
        if (isReg(in.b)) u2 = in.b.reg;
        break;
    case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
    case IROp::PLoadW: case IROp::PLoadB:
        if (isReg(in.b)) u1 = in.b.reg;
        break;
    case IROp::Mov: case IROp::FMov: case IROp::Neg: case IROp::Not:
    case IROp::FNeg: case IROp::I2F: case IROp::F2I:
        if (isReg(in.b)) u1 = in.b.reg;
        break;
    case IROp::Add: case IROp::Sub: case IROp::Mul:
    case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
    case IROp::And: case IROp::Or: case IROp::Xor:
    case IROp::Shl: case IROp::Shr: case IROp::Sar:
    case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
    case IROp::Cmp:
        if (isReg(in.b)) u1 = in.b.reg;
        if (isReg(in.c)) u2 = in.c.reg;
        break;
    case IROp::Arg:
        if (isReg(in.b)) u1 = in.b.reg;
        break;
    case IROp::BrZ: case IROp::BrNZ: case IROp::PrintInt: case IROp::PrintFlt: case IROp::Exit:
        if (isReg(in.a)) u1 = in.a.reg;
        break;
    case IROp::BrCC:
        if (isReg(in.a)) u1 = in.a.reg;
        if (isReg(in.b)) u2 = in.b.reg;
        break;
    case IROp::PrintStr: case IROp::Ret:
        if (isReg(in.a)) u1 = in.a.reg;
        break;
    default:
        break;
    }
}

// ====================================================================
// Pass 1: dead function elimination
// ====================================================================
static void deadFunctionElimination(IRProgram& ir) {
    std::unordered_map<std::string, int> fnIndex;
    for (size_t i = 0; i < ir.functions.size(); i++)
        fnIndex[ir.functions[i].name] = (int)i;

    std::vector<bool> reachable(ir.functions.size(), false);
    std::unordered_set<std::string> visiting;
    std::function<void(const std::string&)> dfs = [&](const std::string& name) {
        if (visiting.count(name)) return;
        auto it = fnIndex.find(name);
        if (it == fnIndex.end()) return;
        int idx = it->second;
        if (reachable[idx]) return;
        reachable[idx] = true;
        IRFunction& fn = ir.functions[idx];
        if (fn.isExtern) return;
        visiting.insert(name);
        for (auto& in : fn.instrs) {
            if (in.op == IROp::Call && in.b.kind == IROperand::Func)
                dfs(in.b.name);
        }
        visiting.erase(name);
    };
    dfs(ir.entryFunc);

    for (size_t i = 0; i < ir.functions.size(); i++) {
        if (ir.functions[i].isExtern) continue;
        if (!reachable[i]) {
            ir.functions[i].garbage = true;
            ir.functions[i].instrs.clear();
            ir.confirmedGarbage++;
        }
    }
}

// ====================================================================
// Pass 2: block-local memory opts + copy propagation + jump threading
// ====================================================================
//
// IR operand layout for frame-slot memory ops (see IRAsm):
//   Load/Load32/FLoad: slot in b.reg, displacement in in.label
//   Store/Store32/FStore: slot in a.reg, displacement in in.label
//   LeaSlot: slot in b.reg, displacement in b.off
//
// Reg operands are single-assignment temporaries (written once), so a
// store's value register never changes and frame-slot memory is only
// mutated by Store*/FStore. Pointers can only reach frame slots through
// LeaSlot; if the function has no LeaSlot, PLoad/PStore cannot alias
// frame slots and are not barriers. Call/ICall do not touch frame slots.
static int computeMaxSlot(const IRFunction& fn);   // defined below

static void localOptFunction(IRFunction& fn) {
    bool hasLea = false;
    for (auto& in : fn.instrs)
        if (!in.garbage && in.op == IROp::LeaSlot) { hasLea = true; break; }

    struct Ent { int off; int size; int reg; int idx; bool isFloat; };   // idx: instr index
    std::unordered_map<int, std::vector<Ent>> st, ld;   // by frame slot id
    std::unordered_map<int, int> copyMap;               // temp reg -> temp reg

    auto overlaps = [](int aOff, int aSize, int bOff, int bSize) {
        return aOff < bOff + bSize && bOff < aOff + aSize;
    };
    auto clearAll = [&]() { st.clear(); ld.clear(); copyMap.clear(); };

    for (size_t i = 0; i < fn.instrs.size(); i++) {
        auto& in = fn.instrs[i];
        if (in.garbage) continue;

        // ---- copy propagation: replace uses of known Mov targets ----
        {
            auto maybe = [&](IROperand& o) {
                if (o.kind == IROperand::Reg) {
                    auto it = copyMap.find(o.reg);
                    if (it != copyMap.end()) { o.reg = it->second; fn.memOpts++; }
                }
            };
            switch (in.op) {
            case IROp::Store: case IROp::Store32: case IROp::FStore:
            case IROp::GStore: case IROp::GStore32: case IROp::FGStore:
                maybe(in.b);
                break;
            case IROp::PStore: case IROp::PStore32: case IROp::PStoreW:
            case IROp::PStoreB: case IROp::FPStore:
                maybe(in.a); maybe(in.b);
                break;
            case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
            case IROp::PLoadW: case IROp::PLoadB:
                maybe(in.b);
                break;
            case IROp::Mov: case IROp::FMov: case IROp::Neg: case IROp::Not:
            case IROp::FNeg: case IROp::I2F: case IROp::F2I:
                maybe(in.b);
                break;
            case IROp::Add: case IROp::Sub: case IROp::Mul:
            case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
            case IROp::And: case IROp::Or: case IROp::Xor:
            case IROp::Shl: case IROp::Shr: case IROp::Sar:
            case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
            case IROp::Cmp:
                maybe(in.b); maybe(in.c);
                break;
            case IROp::Arg: case IROp::BrZ: case IROp::BrNZ:
            case IROp::PrintInt: case IROp::PrintFlt: case IROp::Exit:
                maybe(in.a);
                break;
            case IROp::BrCC:
                maybe(in.a); maybe(in.b);
                break;
            case IROp::PrintStr: case IROp::Ret:
                maybe(in.a);
                break;
            default: break;
            }
        }

        switch (in.op) {
        case IROp::Label:
            clearAll();
            break;

        case IROp::Mov:
            // Mov t, x with x a single-assignment temp: t is an alias of x.
            if (in.b.kind == IROperand::Reg)
                copyMap[in.a.reg] = in.b.reg;
            break;

        case IROp::Store: case IROp::Store32: case IROp::FStore: {
            int s = in.a.reg, off = in.label;
            int size = (in.op == IROp::Store) ? 8 : 4;
            bool stIsFloat = (in.op == IROp::FStore);
            auto& v = st[s];
            // store-store dedup: exact same slot+offset+width+type, no read in between
            for (auto it = v.begin(); it != v.end();) {
                if (it->off == off && it->size == size && it->isFloat == stIsFloat) {
                    fn.instrs[it->idx].garbage = true;
                    fn.memOpts++;
                    it = v.erase(it);
                } else if (overlaps(it->off, it->size, off, size)) {
                    it = v.erase(it);   // superseded by this store
                } else {
                    it++;
                }
            }
            // A store overwrites its region: cached loads of any overlapping
            // region become stale and must be dropped, otherwise a later load
            // would reuse an outdated value (e.g. Store32 to slot+4 followed
            // by an 8-byte Load of slot+0 reads a mix of old and new bytes).
            auto& lv = ld[s];
            for (auto it = lv.begin(); it != lv.end();)
                if (overlaps(it->off, it->size, off, size)) it = lv.erase(it);
                else it++;
            v.push_back({ off, size, in.b.reg, (int)i, stIsFloat });
            break;
        }

        case IROp::Load: case IROp::Load32: case IROp::FLoad: {
            int s = in.b.reg, off = in.label;
            int size = (in.op == IROp::Load) ? 8 : 4;
            bool isFloat = (in.op == IROp::FLoad);
            bool replaced = false;
            auto& sv = st[s];
            auto& lv = ld[s];
            for (auto it = sv.begin(); it != sv.end();) {
                if (!overlaps(it->off, it->size, off, size)) { it++; continue; }
                // load-after-store: int8->int8 and float->float only; the
                // 32-bit int case is skipped (sign-extension semantics);
                // cross-type (Store32->FLoad or FStore->Load32) is rejected
                bool exact = (it->off == off && it->size == size);
                bool ok = (isFloat && exact && it->isFloat) || (!isFloat && exact && !it->isFloat && it->size == 8);
                if (ok) {
                    in.op = IROp::Mov;
                    in.b = IROperand::mkReg(it->reg);
                    in.c = IROperand::none();
                    fn.memOpts++;
                    replaced = true;
                    break;   // exact entry stays valid for later loads
                }
                it = sv.erase(it);   // this load reads the region -> invalidate
            }
            // repeated load: exact same slot+offset+width -> reuse the temp
            for (auto& e : lv) {
                if (e.off == off && e.size == size) {
                    in.op = IROp::Mov;
                    in.b = IROperand::mkReg(e.reg);
                    in.c = IROperand::none();
                    fn.memOpts++;
                    replaced = true;
                    break;
                }
            }
            for (auto it = lv.begin(); it != lv.end();)
                if (overlaps(it->off, it->size, off, size)) it = lv.erase(it);
                else it++;
            if (replaced)
                lv.push_back({ off, size, in.a.reg, (int)i });   // newest value wins
            break;
        }

        case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
        case IROp::PLoadW: case IROp::PLoadB:
            // unknown read: without any LeaSlot pointers cannot reach frame slots
            if (hasLea) clearAll();
            break;

        case IROp::PStore: case IROp::PStore32: case IROp::PStoreW:
        case IROp::PStoreB: case IROp::FPStore:
            if (hasLea) clearAll();
            break;

        default: break;
        }
    }

    // ---- jump threading: Br / BrZ / BrNZ / BrCC through trivial labels ----
    auto threadTarget = [&](int label) -> int {
        for (size_t i = 0; i < fn.instrs.size(); i++) {
            auto& in = fn.instrs[i];
            if (in.garbage) continue;
            if (in.op == IROp::Label && in.a.label == label) {
                for (size_t j = i + 1; j < fn.instrs.size(); j++) {
                    if (fn.instrs[j].garbage) continue;
                    if (fn.instrs[j].op == IROp::Br) return fn.instrs[j].b.label;
                    break;   // label is followed by real code -> not trivial
                }
                break;
            }
        }
        return -1;
    };
    for (int iter = 0; iter < 32; iter++) {
        bool changed = false;
        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::Br) {
                int t = threadTarget(in.b.label);
                if (t >= 0 && t != in.b.label) { in.b.label = t; fn.memOpts++; changed = true; }
            } else if (in.op == IROp::BrZ || in.op == IROp::BrNZ) {
                int t = threadTarget(in.b.label);
                if (t >= 0 && t != in.b.label) { in.b.label = t; fn.memOpts++; changed = true; }
            } else if (in.op == IROp::BrCC) {
                int t = threadTarget(in.c.label);
                if (t >= 0 && t != in.c.label) { in.c.label = t; fn.memOpts++; changed = true; }
            }
        }
        if (!changed) break;
    }
}

// ====================================================================
// Pass 3: constant propagation + folding + strength reduction
// ====================================================================

static bool evalCmp(const std::string& cond, int64_t a, int64_t b, bool isFloat) {
    (void)isFloat;  // float consts are not tracked by the int fold
    if (cond == "==") return a == b;
    if (cond == "!=") return a != b;
    if (cond == "<")  return a < b;
    if (cond == "<=") return a <= b;
    if (cond == ">")  return a > b;
    if (cond == ">=") return a >= b;
    if (cond == "u<")  return (uint64_t)a <  (uint64_t)b;
    if (cond == "u<=") return (uint64_t)a <= (uint64_t)b;
    if (cond == "u>")  return (uint64_t)a >  (uint64_t)b;
    if (cond == "u>=") return (uint64_t)a >= (uint64_t)b;
    return false;
}

// Negation of a compare condition: `!(a < b)` == `a >= b`. Works for both
// the signed and the unsigned forms.
static std::string invertCond(const std::string& cond) {
    if (cond == "==") return "!=";
    if (cond == "!=") return "==";
    if (cond == "<")  return ">=";
    if (cond == "<=") return ">";
    if (cond == ">")  return "<=";
    if (cond == ">=") return "<";
    if (cond == "u<")  return "u>=";
    if (cond == "u<=") return "u>";
    if (cond == "u>")  return "u<=";
    if (cond == "u>=") return "u<";
    return cond;
}

static bool constFoldIntOp(IROp op, const std::string& cond, int64_t a, int64_t b, int64_t& out) {
    switch (op) {
    case IROp::Add: out = a + b; return true;
    case IROp::Sub: out = a - b; return true;
    case IROp::Mul: out = a * b; return true;
    case IROp::IDiv: if (b == 0) return false; out = a / b; return true;
    case IROp::IMod: if (b == 0) return false; out = a % b; return true;
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
    case IROp::Cmp: out = evalCmp(cond, a, b, false) ? 1 : 0; return true;
    default: return false;
    }
}

static bool isPow2(int64_t v, int& shift) {
    if (v <= 0) return false;
    shift = 0;
    while ((v & 1) == 0) { v >>= 1; shift++; }
    return v == 1;
}

static void foldFunction(IRFunction& fn, bool speed) {
    // constVal: known constant value of Reg slots (unique per definition).
    std::unordered_map<int, int64_t> constVal;
    // Regs are single-assignment temps: defOp/defIdx remember which
    // instruction defined a register, so `Neg(Neg x)`, `(a<b)==0`, ... can
    // be folded by looking through the defining instruction.
    std::unordered_map<int, IROp> defOp;
    std::unordered_map<int, size_t> defIdx;
    // fresh temps for multi-instruction expansions (slots above current max)
    int nextTemp = computeMaxSlot(fn);

    auto constOf = [&](const IROperand& o, int64_t& v) -> bool {
        if (o.kind == IROperand::Imm) { v = o.imm; return true; }
        if (o.kind == IROperand::Reg) {
            auto it = constVal.find(o.reg);
            if (it != constVal.end()) { v = it->second; return true; }
        }
        return false;
    };
    // an insertion before `from` shifts every recorded definition index
    auto shiftDefIdx = [&](size_t from) {
        for (auto& kv : defIdx) if (kv.second >= from) kv.second++;
    };

    for (size_t i = 0; i < fn.instrs.size(); i++) {
        auto& in = fn.instrs[i];
        if (in.garbage) continue;
        if (in.a.kind == IROperand::Reg) { defOp[in.a.reg] = in.op; defIdx[in.a.reg] = i; }

        // Propagate / fold pure compute instructions.
        if (in.op == IROp::Const) {
            constVal[in.a.reg] = in.b.imm;
            continue;
        }

        // ---- strength reduction + folding ----
        if (in.op == IROp::Mov) {
            int64_t v;
            if (constOf(in.b, v)) {
                in.op = IROp::Const;
                in.b = IROperand::mkImm(v);
                in.c = IROperand::none();
                constVal[in.a.reg] = v;
                fn.foldedInstrs++;
                continue;
            }
            continue;
        }
        if (in.op == IROp::Neg || in.op == IROp::Not) {
            int64_t v;
            if (constOf(in.b, v)) {
                int64_t r = (in.op == IROp::Neg) ? -v : ~v;
                in.op = IROp::Const;
                in.b = IROperand::mkImm(r);
                constVal[in.a.reg] = r;
                fn.foldedInstrs++;
                continue;
            }
            // double negation: -(-x) -> x, ~(~x) -> x
            if (in.b.kind == IROperand::Reg) {
                auto dit = defOp.find(in.b.reg);
                if (dit != defOp.end() && dit->second == in.op) {
                    // the defining instruction may have been rewritten in
                    // place earlier in this pass, so re-verify its op
                    auto& inner = fn.instrs[defIdx[in.b.reg]];
                    if (inner.op == in.op) {
                        in.op = IROp::Mov;
                        in.b = inner.b;
                        in.c = IROperand::none();
                        constVal.erase(in.a.reg);   // value is not a constant
                        fn.foldedInstrs++;
                        continue;
                    }
                }
            }
            continue;
        }
        if (in.op == IROp::Cmp) {
            int64_t a, b;
            if (in.a.off == 0 && constOf(in.b, a) && constOf(in.c, b)) {
                int64_t r = evalCmp(in.cond, a, b, false) ? 1 : 0;
                in.op = IROp::Const;
                in.b = IROperand::mkImm(r);
                in.c = IROperand::none();
                in.cond.clear();
                constVal[in.a.reg] = r;
                fn.foldedInstrs++;
                continue;
            }
            // same-operand compare (ints only; floats can NaN)
            if (in.a.off == 0 && in.b.kind == IROperand::Reg &&
                in.c.kind == IROperand::Reg && in.b.reg == in.c.reg) {
                int64_t r = 0;
                if (in.cond == "==" || in.cond == "<=" || in.cond == ">=") r = 1;
                in.op = IROp::Const;
                in.b = IROperand::mkImm(r);
                in.c = IROperand::none();
                in.cond.clear();
                constVal[in.a.reg] = r;
                fn.foldedInstrs++;
                continue;
            }
            // (a < b) == 0 / == 1 / != 0 / != 1  ->  a single compare.
            // The inner compare is an int compare (result 0/1), so comparing
            // its result against 0/1 is exactly negation/identity; float
            // compares are never folded (NaN).
            if (in.a.off == 0 && (in.cond == "==" || in.cond == "!=")) {
                const IROperand* cmpOp = nullptr;
                int64_t cv = 0;
                if (in.b.kind == IROperand::Reg && in.c.kind == IROperand::Imm) { cmpOp = &in.b; cv = in.c.imm; }
                else if (in.c.kind == IROperand::Reg && in.b.kind == IROperand::Imm) { cmpOp = &in.c; cv = in.b.imm; }
                if (cmpOp && (cv == 0 || cv == 1)) {
                    auto dit = defOp.find(cmpOp->reg);
                    if (dit != defOp.end() && dit->second == IROp::Cmp) {
                        auto& inner = fn.instrs[defIdx[cmpOp->reg]];
                        if (inner.op == IROp::Cmp && inner.a.off == 0) {
                            bool negate = (cv == 0) == (in.cond == "==");
                            in.b = inner.b;
                            in.c = inner.c;
                            in.cond = negate ? invertCond(inner.cond) : inner.cond;
                            constVal.erase(in.a.reg);
                            fn.foldedInstrs++;
                            continue;
                        }
                    }
                }
            }
            continue;
        }

        // Binary int ops.
        bool isBin = false;
        switch (in.op) {
        case IROp::Add: case IROp::Sub: case IROp::Mul:
        case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
        case IROp::And: case IROp::Or: case IROp::Xor:
        case IROp::Shl: case IROp::Shr: case IROp::Sar:
            isBin = true;
            break;
        default: break;
        }
        if (!isBin) continue;

        // same-operand identities: x-x=0, x^x=0, x&x=x, x|x=x
        if (in.b.kind == IROperand::Reg && in.c.kind == IROperand::Reg &&
            in.b.reg == in.c.reg) {
            if (in.op == IROp::Sub || in.op == IROp::Xor) {
                in.op = IROp::Const;
                in.b = IROperand::mkImm(0);
                in.c = IROperand::none();
                constVal[in.a.reg] = 0;
                fn.foldedInstrs++;
                continue;
            }
            if (in.op == IROp::And || in.op == IROp::Or) {
                in.op = IROp::Mov;
                in.b = IROperand::mkReg(in.b.reg);
                in.c = IROperand::none();
                fn.strengthReduced++;
                continue;
            }
        }

        int64_t a, b;
        bool aConst = constOf(in.b, a);
        bool bConst = constOf(in.c, b);
        if (aConst && bConst) {
            int64_t r;
            if (constFoldIntOp(in.op, in.cond, a, b, r)) {
                in.op = IROp::Const;
                in.b = IROperand::mkImm(r);
                in.c = IROperand::none();
                constVal[in.a.reg] = r;
                fn.foldedInstrs++;
            }
            continue;
        }

        // strength reduction: one const operand
        int64_t k;
        bool kConst = bConst;
        const IROperand* other = &in.b;
        if (kConst) { k = b; }
        else if (aConst) { k = a; other = &in.c; }
        if (kConst) {
            switch (in.op) {
            case IROp::Mul:
                if (k == 0) { in.op = IROp::Const; in.b = IROperand::mkImm(0); in.c = IROperand::none(); constVal[in.a.reg] = 0; fn.foldedInstrs++; }
                else if (k == 1) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else if (k == -1) { in.op = IROp::Neg; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else { int sh; if (isPow2(k, sh)) { in.op = IROp::Shl; in.b = *other; in.c = IROperand::mkImm(sh); fn.strengthReduced++; } }
                // negative power of two: x * -8 -> -(x << 3)
                if (k != 0 && k != 1 && k != -1 && k != INT64_MIN && k < 0) {
                    int sh;
                    if (isPow2(-k, sh)) {
                        int t = nextTemp++;
                        IRInstr shl;
                        shl.op = IROp::Shl;
                        shl.a = IROperand::mkReg(t);
                        shl.b = *other;
                        shl.c = IROperand::mkImm(sh);
                        fn.instrs.insert(fn.instrs.begin() + (long)i, shl);
                        shiftDefIdx(i);
                        auto& cur = fn.instrs[i + 1];
                        cur.op = IROp::Neg;
                        cur.b = IROperand::mkReg(t);
                        cur.c = IROperand::none();
                        defOp[t] = IROp::Shl;
                        defIdx[t] = i;
                        fn.strengthReduced++;
                    }
                }
                break;
            case IROp::Add: case IROp::Sub: case IROp::Xor:
                if (k == 0) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else if (in.op == IROp::Xor && k == -1) { in.op = IROp::Not; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                break;
            case IROp::And:
                if (k == 0) { in.op = IROp::Const; in.b = IROperand::mkImm(0); in.c = IROperand::none(); constVal[in.a.reg] = 0; fn.foldedInstrs++; }
                else if (k == -1) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                break;
            case IROp::Or:
                if (k == 0) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else if (k == -1) { in.op = IROp::Const; in.b = IROperand::mkImm(-1); in.c = IROperand::none(); constVal[in.a.reg] = -1; fn.foldedInstrs++; }
                break;
            case IROp::Shl: case IROp::Shr: case IROp::Sar:
                if (k == 0) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                break;
            // Note: for IDiv/IMod the divisor is the const operand in c (b);
            // the dividend is never the one const here (both-const folded above).
            case IROp::UDiv:
                if (k == 1) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else { int sh; if (isPow2(k, sh)) { in.op = IROp::Shr; in.b = *other; in.c = IROperand::mkImm(sh); fn.strengthReduced++; } }
                break;
            case IROp::UMod:
                if (k == 1) { in.op = IROp::Const; in.b = IROperand::mkImm(0); in.c = IROperand::none(); constVal[in.a.reg] = 0; fn.foldedInstrs++; }
                else if (k > 0) { int sh; if (isPow2(k, sh)) { in.op = IROp::And; in.b = *other; in.c = IROperand::mkImm(k - 1); fn.strengthReduced++; } }
                break;
            case IROp::IDiv:
                if (k == 1) { in.op = IROp::Mov; in.b = *other; in.c = IROperand::none(); fn.strengthReduced++; }
                else if (speed) {
                    int sh;
                    if (isPow2(k, sh)) {
                        // t0 = x >> 63; t1 = t0 & (2^sh - 1); t2 = x + t1;
                        // a = t2 >> sh   (signed div by 2^sh, trunc-to-zero)
                        int64_t mask = (sh >= 63) ? INT64_MAX : ((1LL << sh) - 1);
                        int t0 = nextTemp++, t1 = nextTemp++, t2 = nextTemp++;
                        IRInstr a1, a2, a3;
                        a1.op = IROp::Sar; a1.a = IROperand::mkReg(t0); a1.b = in.b; a1.c = IROperand::mkImm(63);
                        a2.op = IROp::And; a2.a = IROperand::mkReg(t1); a2.b = IROperand::mkReg(t0); a2.c = IROperand::mkImm(mask);
                        a3.op = IROp::Add; a3.a = IROperand::mkReg(t2); a3.b = in.b; a3.c = IROperand::mkReg(t1);
                        in.op = IROp::Sar; in.b = IROperand::mkReg(t2); in.c = IROperand::mkImm(sh);
                        fn.instrs.insert(fn.instrs.begin() + i + 1, { a1, a2, a3 });
                        i += 3;
                        fn.strengthReduced++;
                    }
                }
                break;
            case IROp::IMod:
                if (k == 1) { in.op = IROp::Const; in.b = IROperand::mkImm(0); in.c = IROperand::none(); constVal[in.a.reg] = 0; fn.foldedInstrs++; }
                else if (speed) {
                    int sh;
                    if (isPow2(k, sh)) {
                        // div: t0 = x >> 63; t1 = t0 & mask; t2 = x + t1;
                        //      t3 = t2 >> sh; t4 = t3 << sh; a = x - t4
                        int64_t mask = (sh >= 63) ? INT64_MAX : ((1LL << sh) - 1);
                        int t0 = nextTemp++, t1 = nextTemp++, t2 = nextTemp++, t3 = nextTemp++, t4 = nextTemp++;
                        IRInstr a1, a2, a3, a4, a5;
                        a1.op = IROp::Sar; a1.a = IROperand::mkReg(t0); a1.b = in.b; a1.c = IROperand::mkImm(63);
                        a2.op = IROp::And; a2.a = IROperand::mkReg(t1); a2.b = IROperand::mkReg(t0); a2.c = IROperand::mkImm(mask);
                        a3.op = IROp::Add; a3.a = IROperand::mkReg(t2); a3.b = in.b; a3.c = IROperand::mkReg(t1);
                        a4.op = IROp::Sar; a4.a = IROperand::mkReg(t3); a4.b = IROperand::mkReg(t2); a4.c = IROperand::mkImm(sh);
                        a5.op = IROp::Shl; a5.a = IROperand::mkReg(t4); a5.b = IROperand::mkReg(t3); a5.c = IROperand::mkImm(sh);
                        in.op = IROp::Sub; in.a = IROperand::mkReg(in.a.reg); in.b = in.b; in.c = IROperand::mkReg(t4);
                        fn.instrs.insert(fn.instrs.begin() + i + 1, { a1, a2, a3, a4, a5 });
                        i += 5;
                        fn.strengthReduced++;
                    }
                }
                break;
            default: break;
            }
        }
    }
    if (nextTemp > fn.maxSlot) fn.maxSlot = nextTemp;
}

// ====================================================================
// Pass 4: dead code elimination (iterated to fixpoint)
// ====================================================================

// Collects which frame slots are read by Load ops, address-taken, etc.
struct MemInfo {
    std::vector<int> readCount;      // Load/Load32/FLoad reads per frame slot
    std::vector<bool> escaped;       // address-taken (LeaSlot) per frame slot
    std::unordered_map<std::string, int> globalRead; // GLoad* per global name
    std::unordered_map<std::string, bool> globalEscaped; // LeaGlobal
    bool hasPtrLoad = false;         // any PLoad* -> treat globals as potentially read
};

static MemInfo computeMemInfo(const IRFunction& fn, int maxSlot) {
    MemInfo mi;
    mi.readCount.assign(maxSlot, 0);
    mi.escaped.assign(maxSlot, false);
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        switch (in.op) {
        case IROp::Load: case IROp::Load32: case IROp::FLoad:
            if (in.b.kind == IROperand::Slot && in.b.reg >= 0 && in.b.reg < maxSlot)
                mi.readCount[in.b.reg]++;
            break;
        case IROp::LeaSlot:
            if (in.b.kind == IROperand::Slot && in.b.reg >= 0 && in.b.reg < maxSlot)
                mi.escaped[in.b.reg] = true;
            break;
        case IROp::PLoad: case IROp::PLoad32: case IROp::PLoad32Z:
        case IROp::PLoadW: case IROp::PLoadB:
            mi.hasPtrLoad = true;
            break;
        case IROp::GLoad: case IROp::GLoad32: case IROp::FGLoad:
            if (in.b.kind == IROperand::Global)
                mi.globalRead[in.b.name]++;
            break;
        case IROp::LeaGlobal:
            if (in.b.kind == IROperand::Global)
                mi.globalEscaped[in.b.name] = true;
            break;
        default: break;
        }
    }
    return mi;
}

static void dceFunction(IRFunction& fn) {
    int maxSlot = fn.maxSlot;
    MemInfo mi = computeMemInfo(fn, maxSlot);

    // slot inside a kept run? runs whose base slot is read/escaped stay alive.
    std::vector<bool> runAlive(fn.runs.size(), false);
    for (size_t r = 0; r < fn.runs.size(); r++) {
        int base = fn.runs[r].baseSlot;
        if (base < (int)mi.readCount.size() && mi.readCount[base] > 0) runAlive[r] = true;
        if (base < (int)mi.escaped.size() && mi.escaped[base]) runAlive[r] = true;
    }

    int iter = 0;
    bool changed = true;   // chains of dead pure instructions may need >8 sweeps
    while (changed) {
        changed = false;
        // recompute use counts over non-garbage instructions
        std::unordered_map<int, int> useCount;
        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            int u1, u2;
            regInputs(in, u1, u2);
            if (u1 >= 0) useCount[u1]++;
            if (u2 >= 0) useCount[u2]++;
        }

        for (auto& in : fn.instrs) {
            if (in.garbage) continue;

            // A def with zero uses that is pure -> dead.
            if (definesReg(in) && isPureCompute(in.op)) {
                auto it = useCount.find(in.a.reg);
                if (it == useCount.end() || it->second == 0) {
                    in.garbage = true;
                    fn.dceRemoved++;
                    changed = true;
                    continue;
                }
            }

            // Frame stores whose slot is never read (and not address-taken).
            if (in.op == IROp::Store || in.op == IROp::Store32 || in.op == IROp::FStore) {
                if (in.a.kind == IROperand::Slot && in.a.reg >= 0 && in.a.reg < maxSlot) {
                    int s = in.a.reg;
                    bool dead = false;
                    if (mi.escaped[s]) {
                        dead = false;
                    } else if (mi.readCount[s] == 0) {
                        dead = true;
                    } else {
                        // if s is inside a run, only the run base is loaded directly;
                        // member accesses all use the base slot id, so readCount[base]
                        // covers it. Store to a non-base member of an alive run:
                        dead = false;
                    }
                    if (dead) {
                        in.garbage = true;
                        fn.dceRemoved++;
                        changed = true;
                    }
                }
                continue;
            }

            // Global stores are observable side effects (other functions, PLoad,
            // external callers) so they are never dead based on local liveness.
            if (in.op == IROp::GStore || in.op == IROp::GStore32 || in.op == IROp::FGStore) {
                (void)mi;
            }
        }
        if (!changed) break;
        iter++;
        if (iter > 4096) break;   // safety cap: each sweep marks >=1 instr dead
    }
}

// ====================================================================
// Pass 5: dead branches
// ====================================================================
static void deadBranchElimination(IRFunction& fn) {
    std::unordered_map<int, int64_t> constVal;
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        if (in.op == IROp::Const && in.a.kind == IROperand::Reg) {
            constVal[in.a.reg] = in.b.imm;
            continue;
        }
        if (in.op == IROp::BrZ || in.op == IROp::BrNZ) {
            if (in.a.kind == IROperand::Reg) {
                auto it = constVal.find(in.a.reg);
                if (it != constVal.end()) {
                    bool zero = (it->second == 0);
                    if (in.op == IROp::BrZ && zero) { in.op = IROp::Br; in.a = IROperand::none(); fn.deadBranches++; }
                    else if (in.op == IROp::BrNZ && !zero) { in.op = IROp::Br; in.a = IROperand::none(); fn.deadBranches++; }
                    else if (in.op == IROp::BrZ && !zero) { in.garbage = true; fn.deadBranches++; }
                    else if (in.op == IROp::BrNZ && zero) { in.garbage = true; fn.deadBranches++; }
                    continue;
                }
            }
            continue;
        }
        if (in.op == IROp::BrCC) {
            auto ia = in.a.kind == IROperand::Reg ? constVal.find(in.a.reg) : constVal.end();
            auto ib = in.b.kind == IROperand::Reg ? constVal.find(in.b.reg) : constVal.end();
            bool aConst = (in.a.kind == IROperand::Imm) || (ia != constVal.end());
            bool bConst = (in.b.kind == IROperand::Imm) || (ib != constVal.end());
            if (aConst && bConst) {
                int64_t av = (in.a.kind == IROperand::Imm) ? in.a.imm : ia->second;
                int64_t bv = (in.b.kind == IROperand::Imm) ? in.b.imm : ib->second;
                bool taken = evalCmp(in.cond, av, bv, in.a.off != 0);
                if (taken) { in.op = IROp::Br; in.a = IROperand::none(); in.b = in.c; }
                else { in.garbage = true; }
                in.cond.clear();
                fn.deadBranches++;
            }
            continue;
        }
        // any pure op feeding a branch: propagate known result? keep simple
    }

    // Remove unconditional jumps to the very next label.
    for (size_t i = 0; i < fn.instrs.size(); i++) {
        auto& in = fn.instrs[i];
        if (in.garbage || in.op != IROp::Br) continue;
        int target = in.b.label;
        for (size_t j = i + 1; j < fn.instrs.size(); j++) {
            if (fn.instrs[j].garbage) continue;
            if (fn.instrs[j].op == IROp::Label && fn.instrs[j].a.label == target) {
                in.garbage = true;
                fn.deadBranches++;
            }
            break;
        }
    }

    // Conditional branches to the very next label are pure fallthroughs:
    // taking the branch or falling through reaches the same label.
    for (size_t i = 0; i < fn.instrs.size(); i++) {
        auto& in = fn.instrs[i];
        if (in.garbage) continue;
        int target = -1;
        if (in.op == IROp::BrZ || in.op == IROp::BrNZ) target = in.b.label;
        else if (in.op == IROp::BrCC) target = in.c.label;
        if (target < 0) continue;
        for (size_t j = i + 1; j < fn.instrs.size(); j++) {
            if (fn.instrs[j].garbage) continue;
            if (fn.instrs[j].op == IROp::Label && fn.instrs[j].a.label == target) {
                in.garbage = true;
                fn.deadBranches++;
            }
            break;
        }
    }
}

// ====================================================================
// Pass 6: slot compaction
// ====================================================================

// Highest slot id actually referenced by the function's live instructions.
// IRGen only tracks maxSlot for runs, so it is recomputed here from the
// operands (the IRAsm backend already does the same when sizing frames).
static int computeMaxSlot(const IRFunction& fn) {
    int maxSlot = 0;
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        auto upd = [&](const IROperand& o) {
            if ((o.kind == IROperand::Reg || o.kind == IROperand::Slot) && o.reg >= maxSlot)
                maxSlot = o.reg + 1;
        };
        upd(in.a); upd(in.b); upd(in.c);
    }
    if (maxSlot < fn.nparams) maxSlot = fn.nparams;
    return maxSlot;
}

static void compactSlots(IRFunction& fn) {
    int maxSlot = computeMaxSlot(fn);
    if (maxSlot == 0) return;

    std::vector<int> runIdx(maxSlot, -1);
    for (size_t r = 0; r < fn.runs.size(); r++) {
        int base = fn.runs[r].baseSlot;
        int count = std::max(1, fn.runs[r].count);
        for (int k = 0; k < count; k++) {
            if (base + k >= maxSlot) break;
            runIdx[base + k] = (int)r;
        }
    }

    // alive: referenced by any non-garbage instruction, or a parameter slot.
    std::vector<bool> alive(maxSlot, false);
    auto markAlive = [&](const IROperand& o) {
        if ((o.kind == IROperand::Reg || o.kind == IROperand::Slot) && o.reg >= 0 && o.reg < maxSlot)
            alive[o.reg] = true;
    };
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        markAlive(in.a); markAlive(in.b); markAlive(in.c);
    }
    for (int s = 0; s < maxSlot && s < fn.nparams; s++) alive[s] = true;

    // whole runs stay contiguous: if any member alive, keep all members
    std::vector<bool> runKept(fn.runs.size(), false);
    for (size_t r = 0; r < fn.runs.size(); r++) {
        int base = fn.runs[r].baseSlot;
        int count = std::max(1, fn.runs[r].count);
        for (int k = 0; k < count; k++) {
            if (base + k < maxSlot && alive[base + k]) { runKept[r] = true; break; }
        }
    }
    for (size_t r = 0; r < fn.runs.size(); r++) {
        if (!runKept[r]) continue;
        int base = fn.runs[r].baseSlot;
        int count = std::max(1, fn.runs[r].count);
        for (int k = 0; k < count && base + k < maxSlot; k++) alive[base + k] = true;
    }

    std::vector<int> remap(maxSlot, -1);
    int next = 0;
    for (int s = 0; s < maxSlot; s++) {
        if (alive[s]) remap[s] = next++;
    }
    if (next == maxSlot && std::all_of(remap.begin(), remap.end(), [&](int v){ return v >= 0; }))
        return; // nothing to compact

    auto remapOp = [&](IROperand& o) {
        if ((o.kind == IROperand::Reg || o.kind == IROperand::Slot) && o.reg >= 0 && o.reg < maxSlot)
            o.reg = remap[o.reg];
    };
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        remapOp(in.a); remapOp(in.b); remapOp(in.c);
    }

    // rebase runs
    for (auto& r : fn.runs) {
        if (runKept.size() == 0) break;
        int base = r.baseSlot;
        if (base < (int)remap.size() && remap[base] >= 0)
            r.baseSlot = remap[base];
    }
    fn.maxSlot = next;
}

// ====================================================================
// Pass 7: liveness-based slot reuse
// ====================================================================
//
// compactSlots removes slots that are never referenced. This pass goes
// further: frame slots whose live ranges do not overlap are merged, so
// maxSlot shrinks towards the peak live-slot concurrency instead of the
// total number of distinct temporaries/locals. No instruction is added,
// removed or reordered - only slot ids are renumbered - so neither the
// generated code's speed nor its size changes, only the stack frame.
//
// Slot model (from IRGen):
//   - Reg operands are single-assignment temporaries: written once, read
//     a few times. Live from their def to their last use.
//   - Slot operands are memory locals/params/arrays read by Load and
//     written by Store. Live from first write to last read.
//   - runs (structs/arrays) are contiguous ranges that stay whole.
//   - address-taken slots (LeaSlot) can be reached through pointers, so
//     they are pinned at their original id and never shared.
//   - parameters live at slots 0..nparams-1 (written by the prologue)
//     and stay pinned there.
//
// Loop soundness: a value defined before a loop header and used inside
// the loop must survive every back edge, so its live range is widened to
// the loop tail. A value defined inside the loop body is re-written each
// iteration and needs no widening. The IR is emitted in program order and
// loops are structured, so the loop body is the contiguous run of
// instructions [header, max back-edge tail].
static void reuseSlots(IRFunction& fn) {
    int maxSlot = computeMaxSlot(fn);
    if (maxSlot == 0) return;

    // ---- instruction positions (garbage skipped) ----
    std::vector<int> pos(fn.instrs.size(), -1);
    int n = 0;
    for (size_t i = 0; i < fn.instrs.size(); i++)
        if (!fn.instrs[i].garbage) pos[i] = n++;
    if (n == 0) return;

    // ---- run membership: every member slot maps to its run ----
    std::vector<int> slotRun(maxSlot, -1);
    for (size_t r = 0; r < fn.runs.size(); r++) {
        int base = fn.runs[r].baseSlot;
        int count = std::max(1, fn.runs[r].count);
        for (int k = 0; k < count && base + k < maxSlot; k++)
            slotRun[base + k] = (int)r;
    }

    // ---- address-taken slots (pinned, never shared) ----
    std::vector<bool> escaped(maxSlot, false);
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        if (in.op == IROp::LeaSlot && in.b.kind == IROperand::Slot &&
            in.b.reg >= 0 && in.b.reg < maxSlot)
            escaped[in.b.reg] = true;
    }

    // ---- per-slot live info ----
    struct SlotInfo {
        int def = -1;        // temp definition position
        int lastUse = -1;    // temp last read position
        int firstWrite = -1; // memory: first write position
        int lastRead = -1;   // memory: last read position
        bool isTemp = false;
    };
    std::vector<SlotInfo> info(maxSlot);
    // runLo/runHi: [lo,hi] envelope of every touch (read or write) of a run.
    // runLo is seeded with n (past-end sentinel), runHi with -1, so untouched
    // runs keep lo > hi and are skipped when building units.
    std::vector<int> runLo(fn.runs.size(), n);
    std::vector<int> runHi(fn.runs.size(), -1);

    auto markSlotRead = [&](int s, int p) {
        if (s < 0 || s >= maxSlot) return;
        if (slotRun[s] >= 0) {
            int r = slotRun[s];
            if (p < runLo[r]) runLo[r] = p;
            if (p > runHi[r]) runHi[r] = p;
        }
        if (p > info[s].lastRead) info[s].lastRead = p;
    };
    auto markSlotWrite = [&](int s, int p) {
        if (s < 0 || s >= maxSlot) return;
        if (slotRun[s] >= 0) {
            int r = slotRun[s];
            if (p < runLo[r]) runLo[r] = p;
            if (p > runHi[r]) runHi[r] = p;
        }
        if (info[s].firstWrite < 0 || p < info[s].firstWrite) info[s].firstWrite = p;
    };

    // defines a Reg result (definesReg omits Load/Load32/FLoad on purpose)
    auto definesTemp = [](const IRInstr& in) {
        if (in.a.kind != IROperand::Reg) return false;
        if (definesReg(in)) return true;
        switch (in.op) {
        case IROp::Load: case IROp::Load32: case IROp::FLoad: return true;
        default: return false;
        }
    };

    std::vector<int> pendingArgs;
    for (size_t i = 0; i < fn.instrs.size(); i++) {
        auto& in = fn.instrs[i];
        if (in.garbage) continue;
        int p = pos[i];

        if (definesTemp(in) && in.a.reg >= 0 && in.a.reg < maxSlot) {
            int s = in.a.reg;
            info[s].isTemp = true;
            if (p > info[s].def) info[s].def = p;
        }

        int u1, u2;
        regInputs(in, u1, u2);
        if (u1 >= 0 && u1 < maxSlot) { info[u1].isTemp = true; if (p > info[u1].lastUse) info[u1].lastUse = p; }
        if (u2 >= 0 && u2 < maxSlot) { info[u2].isTemp = true; if (p > info[u2].lastUse) info[u2].lastUse = p; }

        switch (in.op) {
        case IROp::Load: case IROp::Load32: case IROp::FLoad:
            if (in.b.kind == IROperand::Slot) markSlotRead(in.b.reg, p);
            break;
        case IROp::Store: case IROp::Store32: case IROp::FStore:
            if (in.a.kind == IROperand::Slot) markSlotWrite(in.a.reg, p);
            break;
        case IROp::LeaSlot:
            if (in.b.kind == IROperand::Slot) markSlotRead(in.b.reg, p);
            break;
        default: break;
        }

        if (in.op == IROp::Arg) {
            if (in.b.kind == IROperand::Reg && in.b.reg >= 0 && in.b.reg < maxSlot)
                pendingArgs.push_back(in.b.reg);
        } else if (in.op == IROp::Call || in.op == IROp::ICall) {
            // the call re-reads the arg slots from memory, so args stay
            // live until the call itself
            for (int s : pendingArgs)
                if (p > info[s].lastUse) info[s].lastUse = p;
            pendingArgs.clear();
        }
    }

    // ---- CFG liveness for memory slots and runs ----
    // Basic blocks: the entry block is [0, first label); every (non-garbage)
    // Label starts its own block; straight-line code between labels forms the
    // remaining blocks. Blocks are [start,end] inclusive in linear positions,
    // so a branch to a label targets that label's block. A value live through
    // a back edge automatically covers the whole loop body [header..tail],
    // which the interval envelope below turns into a conservative unit.
    struct BB { int start; int end; };
    std::vector<BB> bbs;
    std::unordered_map<int, int> labelBB;      // label id -> block index
    {
        std::vector<int> starts, startLabels;
        for (size_t i = 0; i < fn.instrs.size(); i++) {
            auto& in = fn.instrs[i];
            if (in.garbage) continue;
            if (in.op == IROp::Label && in.a.kind == IROperand::Label) {
                starts.push_back(pos[i]);
                startLabels.push_back(in.a.label);
            }
        }
        int prev = 0;
        for (size_t k = 0; k < starts.size(); k++) {
            int st = starts[k];
            if (st > prev) bbs.push_back({ prev, st - 1 });
            labelBB[startLabels[k]] = (int)bbs.size();
            bbs.push_back({ st, st });
            prev = st + 1;
        }
        if (prev <= n - 1) bbs.push_back({ prev, n - 1 });
    }

    // Liveness keys: runs use 0..unitsN-1, single memory slots use unitsN+s.
    int unitsN = (int)fn.runs.size();
    std::vector<std::vector<int>> succ(bbs.size());
    std::vector<std::unordered_set<int>> use(bbs.size()), def(bbs.size());
    std::vector<int> lastOp(bbs.size(), (int)IROp::Nop);
    {
        auto runKey = [&](int s) {
            return slotRun[s] >= 0 ? slotRun[s] : unitsN + s;
        };
        int cb = 0;
        for (size_t i = 0; i < fn.instrs.size(); i++) {
            auto& in = fn.instrs[i];
            if (in.garbage) continue;
            int p = pos[i];
            while (p > bbs[cb].end) cb++;
            lastOp[cb] = (int)in.op;
            switch (in.op) {
            case IROp::Load: case IROp::Load32: case IROp::FLoad:
            case IROp::LeaSlot:
                if (in.b.kind == IROperand::Slot && in.b.reg >= 0 && in.b.reg < maxSlot)
                    use[cb].insert(runKey(in.b.reg));
                break;
            case IROp::Store: case IROp::Store32: case IROp::FStore:
                if (in.a.kind == IROperand::Slot && in.a.reg >= 0 && in.a.reg < maxSlot)
                    def[cb].insert(runKey(in.a.reg));
                break;
            case IROp::Br: {
                auto it = labelBB.find(in.b.label);
                if (it != labelBB.end()) succ[cb].push_back(it->second);
                break;
            }
            case IROp::BrZ: case IROp::BrNZ: {
                auto it = labelBB.find(in.b.label);
                if (it != labelBB.end()) succ[cb].push_back(it->second);
                if (cb + 1 < (int)bbs.size()) succ[cb].push_back(cb + 1);
                break;
            }
            case IROp::BrCC: {
                auto it = labelBB.find(in.c.label);
                if (it != labelBB.end()) succ[cb].push_back(it->second);
                if (cb + 1 < (int)bbs.size()) succ[cb].push_back(cb + 1);
                break;
            }
            default: break;
            }
        }
        // straight-line fallthrough: blocks not ending in an unconditional
        // jump flow into the next block in linear order
        for (size_t b = 0; b < bbs.size(); b++)
            if (lastOp[b] != (int)IROp::Br && b + 1 < bbs.size())
                succ[b].push_back((int)b + 1);
    }

    // backward liveness fixpoint
    std::vector<std::unordered_set<int>> in(bbs.size()), out(bbs.size());
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b = (int)bbs.size() - 1; b >= 0; b--) {
            std::unordered_set<int> nin = use[b];
            for (int k : out[b])
                if (!def[b].count(k)) nin.insert(k);
            std::unordered_set<int> nout;
            for (int s : succ[b]) for (int k : in[s]) nout.insert(k);
            if (nin != in[b]) { in[b] = std::move(nin); changed = true; }
            if (nout != out[b]) { out[b] = std::move(nout); changed = true; }
        }
    }

    // interval envelopes: every block where a key is live (in∪out) or touched
    // (use∪def) widens its [lo,hi], seeded from the collection-pass bounds.
    for (size_t r = 0; r < fn.runs.size(); r++) {
        if (runLo[r] > runHi[r]) continue;    // run never touched
        int lo = runLo[r], hi = runHi[r];
        for (size_t b = 0; b < bbs.size(); b++) {
            if (in[b].count((int)r) || out[b].count((int)r) ||
                use[b].count((int)r) || def[b].count((int)r)) {
                lo = std::min(lo, bbs[b].start);
                hi = std::max(hi, bbs[b].end);
            }
        }
        runLo[r] = lo;
        runHi[r] = hi;
    }
    for (int s = 0; s < maxSlot; s++) {
        if (escaped[s]) continue;
        if (slotRun[s] >= 0) continue;        // handled above as a run
        if (info[s].isTemp) continue;         // temps keep dedicated slots
        if (info[s].firstWrite < 0 && info[s].lastRead < 0) continue;
        int key = unitsN + s;
        int lo = info[s].firstWrite >= 0 ? info[s].firstWrite : n;
        int hi = info[s].lastRead >= 0 ? info[s].lastRead : -1;
        for (size_t b = 0; b < bbs.size(); b++) {
            if (in[b].count(key) || out[b].count(key) ||
                use[b].count(key) || def[b].count(key)) {
                lo = std::min(lo, bbs[b].start);
                hi = std::max(hi, bbs[b].end);
            }
        }
        info[s].firstWrite = lo;
        info[s].lastRead = hi;
    }

    // ---- pinned slots: params, address-taken, and whole escaped runs ----
    std::vector<bool> pinned(maxSlot, false);
    for (int s = 0; s < maxSlot && s < fn.nparams; s++) pinned[s] = true;
    for (int s = 0; s < maxSlot; s++)
        if (escaped[s] && slotRun[s] >= 0) {
            int r = slotRun[s];
            int base = fn.runs[r].baseSlot;
            for (int k = 0; k < fn.runs[r].count && base + k < maxSlot; k++)
                pinned[base + k] = true;
        }
    for (int s = 0; s < maxSlot; s++)
        if (escaped[s]) pinned[s] = true;

    // ---- build units ----
    struct Unit {
        int slot = -1; int size = 1;
        int start = 0; int end = 0;
        int phys = -1; bool pinned = false;
    };
    std::vector<Unit> units;
    std::vector<int> remap(maxSlot, -1);
    for (int s = 0; s < maxSlot; s++)
        if (pinned[s]) { units.push_back({ s, 1, 0, 0, s, true }); remap[s] = s; }
    for (size_t r = 0; r < fn.runs.size(); r++) {
        int base = fn.runs[r].baseSlot;
        int count = std::max(1, fn.runs[r].count);
        if (base >= maxSlot || pinned[base]) continue;
        if (runLo[r] > runHi[r]) continue;   // run never touched
        int st = runLo[r];
        int en = runHi[r];
        if (en < st) en = st;
        units.push_back({ base, count, st, en, -1, false });
    }
    for (int s = 0; s < maxSlot; s++) {
        if (pinned[s] || slotRun[s] >= 0) continue;
        // Value temps keep dedicated slots (see allocation below); only
        // memory slots (locals written by Store, read by Load) may merge.
        if (info[s].isTemp) continue;
        if (info[s].firstWrite < 0 && info[s].lastRead < 0) continue;
        int st = info[s].firstWrite >= 0 ? info[s].firstWrite : 0;
        int en = info[s].lastRead >= 0 ? info[s].lastRead : st;
        if (en < st) en = st;
        units.push_back({ s, 1, st, en, -1, false });
    }

    // ---- allocate: first-fit with range expiry, run blocks stay whole ----
    std::vector<Unit> movable;
    for (auto& u : units)
        if (!u.pinned) movable.push_back(u);
    std::sort(movable.begin(), movable.end(), [](const Unit& a, const Unit& b) {
        if (a.start != b.start) return a.start < b.start;
        if (a.size != b.size) return a.size > b.size;
        return a.slot < b.slot;
    });

    std::vector<std::pair<int,int>> occ;   // occupied [lo, hi), sorted
    for (auto& u : units)
        if (u.pinned) occ.push_back({ u.phys, u.phys + u.size });
    std::sort(occ.begin(), occ.end());

    struct Active { int phys; int size; int end; };
    std::vector<Active> active;

    auto removeOcc = [&](int lo, int hi) {
        for (size_t k = 0; k < occ.size(); k++)
            if (occ[k].first == lo && occ[k].second == hi) { occ.erase(occ.begin() + k); return; }
    };
    auto expire = [&](int s) {
        for (size_t k = 0; k < active.size();) {
            if (active[k].end < s) {
                removeOcc(active[k].phys, active[k].phys + active[k].size);
                active.erase(active.begin() + k);
            } else k++;
        }
    };
    auto findGap = [&](int size) {
        int cand = 0;
        for (auto& r : occ) {
            if (r.first >= cand + size) break;
            cand = std::max(cand, r.second);
        }
        return cand;
    };

    int maxPhys = 0;
    for (auto& u : movable) {
        expire(u.start);
        int ph = findGap(u.size);
        u.phys = ph;
        remap[u.slot] = ph;
        occ.push_back({ ph, ph + u.size });
        std::sort(occ.begin(), occ.end());
        active.push_back({ ph, u.size, u.end });
        if (ph + u.size > maxPhys) maxPhys = ph + u.size;
    }
    for (auto& r : occ) maxPhys = std::max(maxPhys, r.second);

    // ---- value temps: dedicated slots, never merged ----
    // Each single-assignment temp gets its own frame slot above the memory
    // region. Merging them would fuse independent SSA values into one slot,
    // which the register-based backend cannot express. The linear-scan
    // allocator (step 4) replaces these slots with registers/spills.
    for (int s = 0; s < maxSlot; s++) {
        if (!info[s].isTemp) continue;
        if (remap[s] >= 0) continue;
        remap[s] = maxPhys++;
    }

    // ---- rewrite operands, rebase runs, update maxSlot ----
    auto remapOp = [&](IROperand& o) {
        if ((o.kind == IROperand::Reg || o.kind == IROperand::Slot) &&
            o.reg >= 0 && o.reg < maxSlot) {
            if (slotRun[o.reg] >= 0) {
                int r = slotRun[o.reg];
                int rb = fn.runs[r].baseSlot;
                if (remap[rb] >= 0) { o.reg = remap[rb] + (o.reg - rb); return; }
            }
            if (remap[o.reg] >= 0) o.reg = remap[o.reg];
        }
    };
    for (auto& in : fn.instrs) {
        if (in.garbage) continue;
        remapOp(in.a); remapOp(in.b); remapOp(in.c);
    }
    for (auto& r : fn.runs)
        if (r.baseSlot < (int)remap.size() && remap[r.baseSlot] >= 0)
            r.baseSlot = remap[r.baseSlot];
    fn.maxSlot = maxPhys;

    if (getenv("ZT_DEBUG_SLOTS")) {
        FILE* f = fopen("slots_dump.txt", "a");
        if (f) {
            fprintf(f, "== fn %s maxSlot %d -> maxPhys %d ==\n", fn.name.c_str(), maxSlot, maxPhys);
            for (size_t i = 0; i < fn.instrs.size(); i++) {
                auto& in = fn.instrs[i];
                fprintf(f, "  [%3d] op=%d %s a.reg=%d b.reg=%d b.imm=%lld c.reg=%d off=%d lab=%d\n",
                        i, (int)in.op, in.garbage ? "G" : " ",
                        in.a.reg, in.b.reg, (long long)in.b.imm, in.c.reg, in.label, in.b.label);
            }
            fprintf(f, "---- runs ----\n");
            for (size_t r = 0; r < fn.runs.size(); r++)
                fprintf(f, "run base=%d count=%d [%d,%d]\n", fn.runs[r].baseSlot, fn.runs[r].count,
                        runLo[r], runHi[r]);
            fprintf(f, "----\n");
            fclose(f);
        }
    }
}

// ====================================================================
// Pass 8: global removal
// ====================================================================
static void removeUnusedGlobals(IRProgram& ir) {
    std::unordered_map<std::string, bool> used;
    for (auto& g : ir.globals) used[g.name] = false;
    for (auto& fn : ir.functions) {
        if (fn.garbage) continue;
        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            // GStore/GStore32/FGStore carry the global in a, GLoad/FGLoad in b.
            if (in.a.kind == IROperand::Global) used[in.a.name] = true;
            if (in.b.kind == IROperand::Global) used[in.b.name] = true;
            if (in.c.kind == IROperand::Global) used[in.c.name] = true;
        }
    }
    auto it = std::remove_if(ir.globals.begin(), ir.globals.end(),
                             [&](const IRGlobal& g) { return !used[g.name]; });
    ir.removedGlobals = (int)std::distance(it, ir.globals.end());
    ir.globals.erase(it, ir.globals.end());
}

// ====================================================================
// Pass 9: string pool pruning
// ====================================================================
// The string pool is emitted into .rdata verbatim, so strings whose only
// references (Str / PrintStr) were removed by DCE would still cost file
// bytes and mapped RAM. Drop them and renumber the surviving indices.
static void pruneStrings(IRProgram& ir) {
    int n = (int)ir.strings.size();
    if (n == 0) return;

    std::vector<bool> keep(n, false);
    for (auto& fn : ir.functions) {
        if (fn.garbage) continue;
        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::Str && in.b.kind == IROperand::StrIdx &&
                in.b.strIdx >= 0 && in.b.strIdx < n)
                keep[in.b.strIdx] = true;
            if (in.op == IROp::PrintStr && in.a.kind == IROperand::StrIdx &&
                in.a.strIdx >= 0 && in.a.strIdx < n)
                keep[in.a.strIdx] = true;
        }
    }
    // string-initialized globals reference the pool by value
    for (auto& g : ir.globals) {
        if (!g.isString) continue;
        for (int i = 0; i < n; i++)
            if (ir.strings[i] == g.strValue) { keep[i] = true; break; }
    }

    std::vector<int> remap(n, -1);
    int next = 0;
    for (int i = 0; i < n; i++)
        if (keep[i]) remap[i] = next++;
    if (next == n) return;

    for (auto& fn : ir.functions) {
        if (fn.garbage) continue;
        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::Str && in.b.kind == IROperand::StrIdx &&
                in.b.strIdx >= 0 && in.b.strIdx < n)
                in.b.strIdx = remap[in.b.strIdx];
            if (in.op == IROp::PrintStr && in.a.kind == IROperand::StrIdx &&
                in.a.strIdx >= 0 && in.a.strIdx < n)
                in.a.strIdx = remap[in.a.strIdx];
        }
    }

    size_t saved = 0;
    for (int i = 0; i < n; i++)
        if (!keep[i]) saved += ir.strings[i].size() + 1;
    std::vector<std::string> newPool;
    newPool.reserve(next);
    for (int i = 0; i < n; i++)
        if (keep[i]) newPool.push_back(std::move(ir.strings[i]));
    ir.strings.swap(newPool);
    ir.fileSaved += (int)saved;
}

// ====================================================================
// entry
// ====================================================================
void IROpt::run(IRProgram& ir, bool speed) {
    for (auto& fn : ir.functions) {
        fn.beforeInstrs = (int)fn.instrs.size();
        fn.beforeRam = computeMaxSlot(fn) * 8;
    }
    ir.beforeTotalInstrs = (int)ir.functions.size();

    deadFunctionElimination(ir);

    for (auto& fn : ir.functions) {
        if (fn.garbage) continue;
        localOptFunction(fn);
        // fold -> DCE -> dead-branch -> fold ... forms cascading chains
        // (a folded compare frees a branch, the freed branch exposes a dead
        // store, the dead store makes a fold legal, ...), so run the passes
        // twice to reach the fixpoint on the common chains.
        for (int sweep = 0; sweep < 2; sweep++) {
            foldFunction(fn, speed);
            dceFunction(fn);
            deadBranchElimination(fn);
        }
        compactSlots(fn);
        reuseSlots(fn);
        fn.afterRam = fn.maxSlot * 8;
        fn.afterInstrs = (int)fn.instrs.size();
        ir.foldedInstrs += fn.foldedInstrs;
        ir.strengthReduced += fn.strengthReduced;
        ir.dceRemoved += fn.dceRemoved;
        ir.deadBranches += fn.deadBranches;
        ir.memOpts += fn.memOpts;
        ir.ramSaved += (fn.beforeRam - fn.afterRam);
    }

    removeUnusedGlobals(ir);
    pruneStrings(ir);

    ir.afterTotalInstrs = (int)ir.functions.size();
    for (auto& fn : ir.functions) {
        if (fn.garbage) continue;
        ir.afterTotalInstrs += (int)fn.instrs.size();
    }
    ir.beforeTotalInstrs = (int)ir.functions.size();
    for (auto& fn : ir.functions) ir.beforeTotalInstrs += (int)fn.instrs.size();
}
