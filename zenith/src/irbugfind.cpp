// ====================================================================
// irbugfind.cpp — static bug finder over the assembler-IR.
//
// Rules:
//   ZT-IR001  division / modulo by a zero constant
//   ZT-IR002  shift amount outside [0, 64)
//   ZT-IR003  constant add/sub/mul overflows int64, INT64_MIN negation,
//             INT64_MIN / -1 (idiv trap)
//   ZT-IR004  branch on a constant condition (BrZ/BrNZ/BrCC, self-cmp)
//   ZT-IR005  F2I of a constant that is NaN or outside int64
//   ZT-IR006  I2F of a constant that is not representable in float32
//   ZT-IR007  comparison decided by a known range (%K / &M results)
//   ZT-IR008  chained comparison (a Cmp/BrCC fed by another comparison)
//   ZT-IR009  self-comparison of a float (NaN semantics)
//   ZT-IR010  division/modulo of a value by itself (x / x, x % x)
//   ZT-IR011  loop whose counter step can never satisfy its guard
//
// Findings are printed as "Warning: IR <func>:<idx>: [ZT-IRxxx] ...".
// ====================================================================
#include "irbugfind.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

using i128 = __int128;

bool isRegLike(const IROperand& o);

// ------------------------------------------------------------ facts

struct IFacts {
    std::unordered_map<int, int64_t> ic;      // reg/slot id -> int const
    std::unordered_map<int, float> fc;        // reg/slot id -> float const
    std::unordered_map<std::string, int64_t> gc;  // global name -> int const
    // How the current value of an id was produced (see Origin). This is what
    // lets rule 004 match the AST rules: `while 1` (PLAIN literal) is exempt,
    // `if 1 > 1` / a computed constant is reported, and a Cmp of two plain
    // literals (IRGen's own switch dispatch: `selector == case`) is exempt.
    std::unordered_set<int> lit;      // plain literal origin (Const/...)
    std::unordered_set<int> cmpLit;   // Cmp of two plain literals
    // reg -> slot id it was loaded from (int Load, off==0 only). Lets
    // `x == x` be recognized as a self-comparison even though IRGen loads
    // the two sides into two different registers.
    std::unordered_map<int, int> via;
    // Registers holding a comparison result: what makes a Cmp/BrCC whose
    // *operand* is itself a comparison detectable (`0 <= i < 10`).
    std::unordered_set<int> cmpOut;
    // reg/slot -> range proven by `x % K` / `x & M` (and propagated through
    // moves, stores and loads). Enough to see that a compare can never hold.
    std::unordered_map<int, std::pair<int64_t, int64_t>> rng;

    bool operator==(const IFacts& o) const {
        return ic == o.ic && fc == o.fc && gc == o.gc && lit == o.lit &&
               cmpLit == o.cmpLit && via == o.via && cmpOut == o.cmpOut &&
               rng == o.rng;
    }
};

enum Origin { ORIGIN_COMPUTED = 0, ORIGIN_PLAIN = 1, ORIGIN_CMPLIT = 2 };

// meet = intersection of known facts (identity element: nothing known)
IFacts meet(const IFacts& a, const IFacts& b) {
    IFacts r;
    for (auto& kv : a.ic) {
        auto it = b.ic.find(kv.first);
        if (it != b.ic.end() && it->second == kv.second) {
            r.ic[kv.first] = kv.second;
            if (a.lit.count(kv.first) && b.lit.count(kv.first))
                r.lit.insert(kv.first);
            if (a.cmpLit.count(kv.first) && b.cmpLit.count(kv.first))
                r.cmpLit.insert(kv.first);
        }
    }
    for (auto& kv : a.fc) {
        auto it = b.fc.find(kv.first);
        if (it != b.fc.end() && it->second == kv.second) {
            r.fc[kv.first] = kv.second;
            if (a.lit.count(kv.first) && b.lit.count(kv.first))
                r.lit.insert(kv.first);
        }
    }
    for (auto& kv : a.gc) {
        auto it = b.gc.find(kv.first);
        if (it != b.gc.end() && it->second == kv.second) r.gc[kv.first] = kv.second;
    }
    for (auto& kv : a.via) {
        auto it = b.via.find(kv.first);
        if (it != b.via.end() && it->second == kv.second) r.via[kv.first] = kv.second;
    }
    for (auto& k : a.cmpOut)
        if (b.cmpOut.count(k)) r.cmpOut.insert(k);
    for (auto& kv : a.rng) {
        auto it = b.rng.find(kv.first);
        if (it != b.rng.end() && it->second == kv.second) r.rng[kv.first] = kv.second;
    }
    return r;
}

void setI(IFacts& F, int reg, int64_t v) {
    F.fc.erase(reg);
    F.ic[reg] = v;
    F.lit.erase(reg);
    F.cmpLit.erase(reg);
    F.via.erase(reg);   // a new value: no longer "loaded from slot X"
    F.cmpOut.erase(reg);
    F.rng.erase(reg);
}
void setILit(IFacts& F, int reg, int64_t v) {
    setI(F, reg, v);
    F.lit.insert(reg);
}
void setCmpLit(IFacts& F, int reg, int64_t v) {
    setI(F, reg, v);
    F.cmpLit.insert(reg);
}
void setF(IFacts& F, int reg, float v) {
    F.ic.erase(reg);
    F.fc[reg] = v;
    F.lit.erase(reg);
    F.cmpLit.erase(reg);
    F.via.erase(reg);
    F.cmpOut.erase(reg);
    F.rng.erase(reg);
}
void setFLit(IFacts& F, int reg, float v) {
    setF(F, reg, v);
    F.lit.insert(reg);
}
void killReg(IFacts& F, int reg) {
    F.ic.erase(reg);
    F.fc.erase(reg);
    F.lit.erase(reg);
    F.cmpLit.erase(reg);
    F.via.erase(reg);
    F.cmpOut.erase(reg);
    F.rng.erase(reg);
}
void killAll(IFacts& F) {
    F.ic.clear();
    F.fc.clear();
    F.gc.clear();
    F.lit.clear();
    F.cmpLit.clear();
    F.via.clear();
    F.cmpOut.clear();
    F.rng.clear();
}
// A write to slot `s` invalidates every register that was loaded from it.
void killViaSlot(IFacts& F, int s) {
    for (auto it = F.via.begin(); it != F.via.end();) {
        if (it->second == s) it = F.via.erase(it);
        else ++it;
    }
    F.rng.erase(s);
}

// Known range of an operand: a literal is a range of one, a register may
// carry one from `%K` / `&M` or hold a known constant.
bool rangeOf(const IROperand& o, const IFacts& F, int64_t& lo, int64_t& hi) {
    if (o.kind == IROperand::Imm) { lo = hi = o.imm; return true; }
    if (o.kind == IROperand::Reg || o.kind == IROperand::Slot) {
        auto it = F.ic.find(o.reg);
        if (it != F.ic.end()) { lo = hi = it->second; return true; }
        auto r = F.rng.find(o.reg);
        if (r != F.rng.end()) { lo = r->second.first; hi = r->second.second; return true; }
    }
    return false;
}

void setRange(IFacts& F, int reg, int64_t lo, int64_t hi) {
    if (lo > hi) return;
    F.ic.erase(reg);
    F.rng[reg] = {lo, hi};
}

// Two operands that denote the same runtime value: the same register, or two
// registers loaded from one slot with no write in between (IRGen loads both
// sides of `x / x` into different registers).
bool sameValue(const IROperand& a, const IROperand& b, const IFacts& F) {
    if (!isRegLike(a) || !isRegLike(b)) return false;
    if (a.reg == b.reg) return true;
    auto ia = F.via.find(a.reg);
    auto ib = F.via.find(b.reg);
    return ia != F.via.end() && ib != F.via.end() && ia->second == ib->second;
}

// IR007: a comparison whose two sides have known ranges is already decided —
// one arm of the branch is dead. Only the signed operators: an unsigned
// compare of ranges would need them split by sign first.
void reportRangeCmp(
    const IRInstr& in, const IFacts& F,
    const std::function<void(const char*, const std::string&)>& rep) {
    int64_t alo, ahi, blo, bhi;
    // `Cmp` puts its operands in b/c (a is the destination), a `BrCC` in a/b.
    const IROperand& lhs = (in.op == IROp::BrCC) ? in.a : in.b;
    const IROperand& rhs = (in.op == IROp::BrCC) ? in.b : in.c;
    if (!rangeOf(lhs, F, alo, ahi) || !rangeOf(rhs, F, blo, bhi)) return;
    bool t = false, f = false;
    const std::string& c = in.cond;
    if (c == "<")       { t = ahi <  blo; f = alo >= bhi; }
    else if (c == "<=") { t = ahi <= blo; f = alo >  bhi; }
    else if (c == ">")  { t = alo >  bhi; f = ahi <= blo; }
    else if (c == ">=") { t = alo >= bhi; f = ahi <  blo; }
    else if (c == "==") { f = ahi < blo || bhi < alo; }
    else if (c == "!=") { t = ahi < blo || bhi < alo; }
    else return;
    if (!t && !f) return;
    rep("IR007", std::string("comparison is always ") + (t ? "true" : "false") +
                     " (ranges [" + std::to_string(alo) + ", " +
                     std::to_string(ahi) + "] vs [" + std::to_string(blo) +
                     ", " + std::to_string(bhi) + "])");
}

// IR007's source facts, produced when exactly one operand of `%` / `&` is a
// known constant: `x % K` lands in [-(K-1), K-1], `x & M` in [0, M].
void setRangeFromOp(const IRInstr& in, IFacts& F, bool bx, bool by,
                    int64_t x, int64_t y) {
    if (!isRegLike(in.a) || bx == by) return;
    int64_t olo = 0, ohi = 0;
    bool ok = rangeOf(bx ? in.c : in.b, F, olo, ohi);
    if (in.op == IROp::IMod) {
        if (!by || y <= 0) return;   // the divisor has to be the constant
        int64_t m = y - 1;
        if (ok && olo >= 0) setRange(F, in.a.reg, 0, m);
        else setRange(F, in.a.reg, -(m), m);
    } else if (in.op == IROp::And) {
        int64_t M = bx ? x : y;
        if (M < 0) return;           // sign-extended mask: no upper bound
        int64_t hi = M;
        if (ok && ohi >= 0 && ohi < hi) hi = ohi;
        setRange(F, in.a.reg, 0, hi);
    }
}

Origin originOf(const IFacts& F, const IROperand& o) {
    if (o.kind == IROperand::Imm || o.kind == IROperand::FImm)
        return ORIGIN_PLAIN;
    if (o.kind == IROperand::Reg || o.kind == IROperand::Slot) {
        if (F.lit.count(o.reg)) return ORIGIN_PLAIN;
        if (F.cmpLit.count(o.reg)) return ORIGIN_CMPLIT;
    }
    return ORIGIN_COMPUTED;
}
// Plain literal? (Imm counts: it is literally a constant in the instruction)
bool isPlain(const IFacts& F, const IROperand& o) {
    return originOf(F, o) == ORIGIN_PLAIN;
}
// Keep the origin marker when a value is moved/stored/loaded.
void setLikeInt(IFacts& F, int reg, int64_t v, Origin o) {
    if (o == ORIGIN_PLAIN) setILit(F, reg, v);
    else if (o == ORIGIN_CMPLIT) setCmpLit(F, reg, v);
    else setI(F, reg, v);
}

float decodeF(const IROperand& o) {
    uint32_t u = (uint32_t)o.imm;
    float f;
    std::memcpy(&f, &u, sizeof(f));
    return f;
}

bool constInt(const IROperand& o, const IFacts& F, int64_t& v) {
    if (o.kind == IROperand::Imm) { v = o.imm; return true; }
    if (o.kind == IROperand::Reg || o.kind == IROperand::Slot) {
        auto it = F.ic.find(o.reg);
        if (it != F.ic.end()) { v = it->second; return true; }
    }
    return false;
}

bool constFloat(const IROperand& o, const IFacts& F, float& v) {
    if (o.kind == IROperand::FImm) { v = decodeF(o); return true; }
    if (o.kind == IROperand::Reg || o.kind == IROperand::Slot) {
        auto it = F.fc.find(o.reg);
        if (it != F.fc.end()) { v = it->second; return true; }
    }
    return false;
}

bool isRegLike(const IROperand& o) {
    return o.kind == IROperand::Reg || o.kind == IROperand::Slot;
}

int64_t wrapAdd(int64_t a, int64_t b) { return (int64_t)((uint64_t)a + (uint64_t)b); }
int64_t wrapSub(int64_t a, int64_t b) { return (int64_t)((uint64_t)a - (uint64_t)b); }
int64_t wrapMul(int64_t a, int64_t b) { return (int64_t)((uint64_t)a * (uint64_t)b); }
int64_t wrapNeg(int64_t a) { return (int64_t)(0u - (uint64_t)a); }
int64_t wrapShl(int64_t a, int k) { return (int64_t)((uint64_t)a << (k & 63)); }
int64_t wrapShr(int64_t a, int k) { return (int64_t)((uint64_t)a >> (k & 63)); }
int64_t wrapSar(int64_t a, int k) {
    if (k <= 0) return a;
    if (k > 63) k = 63;
    return a >> k;   // arithmetic shift (implementation-defined but gcc/clang do ASR)
}

bool cmpIntCond(const std::string& c, int64_t a, int64_t b) {
    if (c == "==") return a == b;
    if (c == "!=") return a != b;
    if (c == "<") return a < b;
    if (c == "<=") return a <= b;
    if (c == ">") return a > b;
    if (c == ">=") return a >= b;
    if (c == "u<") return (uint64_t)a < (uint64_t)b;
    if (c == "u<=") return (uint64_t)a <= (uint64_t)b;
    if (c == "u>") return (uint64_t)a > (uint64_t)b;
    if (c == "u>=") return (uint64_t)a >= (uint64_t)b;
    return false;
}

bool cmpFloatCond(const std::string& c, float a, float b) {
    if (c == "==") return a == b;
    if (c == "!=") return a != b;
    if (c == "<") return a < b;
    if (c == "<=") return a <= b;
    if (c == ">") return a > b;
    if (c == ">=") return a >= b;
    return false;
}

bool isTerminator(IROp op) {
    return op == IROp::Br || op == IROp::BrZ || op == IROp::BrNZ ||
           op == IROp::BrCC || op == IROp::Ret || op == IROp::Exit ||
           op == IROp::EndFunc;
}

int labelId(const IRInstr& in) {
    if (in.a.kind == IROperand::Label) return in.a.label;
    return in.label;
}

int branchTarget(const IRInstr& in) {
    if (in.op == IROp::BrCC) return in.c.label;
    return in.b.label;   // Br / BrZ / BrNZ
}

// ------------------------------------------------------------ checker

class IRChecker {
public:
    std::vector<std::string>* out_ = nullptr;
    int count_ = 0;
    std::unordered_set<std::string> seen_;

    void report(const std::string& fn, int idx, const char* code,
                const std::string& msg) {
        std::string key = std::string(code) + "|" + fn + "|" +
                          std::to_string(idx) + "|" + msg;
        if (!seen_.insert(key).second) return;
        out_->push_back("Warning: IR " + fn + ":" + std::to_string(idx) +
                        ": [ZT-" + code + "] " + msg);
        count_++;
    }
};

// ------------------------------------------------------------ analyzer

struct Block {
    int start = 0, end = 0;   // [start, end)
    std::vector<int> succ;
    std::vector<int> pred;
    IFacts out;
    bool reachable = false;
    bool computed = false;
};

class FuncAnalyzer {
public:
    const IRFunction& fn_;
    std::vector<std::string>* out_;
    IRChecker& chk_;
    const std::vector<IRInstr>& is_;
    std::vector<Block> blocks_;
    std::vector<int> blockOf_;          // instr index -> block index (-1 none)
    std::unordered_map<int, int> labelInstr_;  // label id -> instr index

    FuncAnalyzer(const IRFunction& f, std::vector<std::string>* out, IRChecker& c)
        : fn_(f), out_(out), chk_(c), is_(f.instrs) {}

    bool build() {
        if (is_.empty()) return false;
        for (size_t i = 0; i < is_.size(); i++) {
            if (is_[i].op == IROp::Label) labelInstr_[labelId(is_[i])] = (int)i;
        }
        // leaders
        std::vector<bool> leader(is_.size(), false);
        leader[0] = true;
        for (size_t i = 0; i < is_.size(); i++) {
            const IRInstr& in = is_[i];
            if (in.garbage) continue;
            if (isTerminator(in.op) && i + 1 < is_.size()) leader[i + 1] = true;
            if (in.op == IROp::Label) leader[i] = true;
            if (in.op == IROp::Br || in.op == IROp::BrZ ||
                in.op == IROp::BrNZ || in.op == IROp::BrCC) {
                int t = branchTarget(in);
                auto it = labelInstr_.find(t);
                if (it == labelInstr_.end()) return false;  // unresolved: bail out
                leader[it->second] = true;
            }
        }
        blockOf_.assign(is_.size(), -1);
        int cur = -1;
        for (size_t i = 0; i < is_.size(); i++) {
            if (leader[i]) {
                Block b;
                b.start = (int)i;
                blocks_.push_back(b);
                cur = (int)blocks_.size() - 1;
            }
            blockOf_[i] = cur;
        }
        for (auto& b : blocks_) b.end = b.start;  // placeholder
        // fill ends
        for (size_t k = 0; k < blocks_.size(); k++) {
            blocks_[k].end = (k + 1 < blocks_.size())
                                 ? blocks_[k + 1].start
                                 : (int)is_.size();
        }
        // successors
        for (size_t k = 0; k < blocks_.size(); k++) {
            Block& b = blocks_[k];
            const IRInstr& last = is_[b.end - 1];
            int fall = (k + 1 < blocks_.size()) ? (int)(k + 1) : -1;
            auto tgt = [&](const IRInstr& in) -> int {
                int t = branchTarget(in);
                auto it = labelInstr_.find(t);
                if (it == labelInstr_.end()) return -1;
                int bi = blockOf_[it->second];
                return bi;
            };
            switch (last.op) {
                case IROp::Br: {
                    int t = tgt(last);
                    if (t < 0) return false;
                    b.succ.push_back(t);
                    break;
                }
                case IROp::BrZ:
                case IROp::BrNZ:
                case IROp::BrCC: {
                    int t = tgt(last);
                    if (t < 0) return false;
                    b.succ.push_back(t);
                    if (fall >= 0) b.succ.push_back(fall);
                    break;
                }
                case IROp::Ret:
                case IROp::Exit:
                case IROp::EndFunc:
                    break;
                default:
                    if (fall >= 0) b.succ.push_back(fall);
                    break;
            }
            // dedup succ
            std::sort(b.succ.begin(), b.succ.end());
            b.succ.erase(std::unique(b.succ.begin(), b.succ.end()), b.succ.end());
        }
        // preds
        for (size_t k = 0; k < blocks_.size(); k++)
            for (int s : blocks_[k].succ)
                blocks_[s].pred.push_back((int)k);
        // reachability (BFS from block 0)
        std::vector<int> stack{0};
        blocks_[0].reachable = true;
        while (!stack.empty()) {
            int k = stack.back();
            stack.pop_back();
            for (int s : blocks_[k].succ) {
                if (!blocks_[s].reachable) {
                    blocks_[s].reachable = true;
                    stack.push_back(s);
                }
            }
        }
        return true;
    }

    IFacts inOf(int k) const {
        if (k == 0) return IFacts();   // function entry: nothing known
        const Block& b = blocks_[k];
        IFacts r;
        bool first = true;
        for (int p : b.pred) {
            if (!blocks_[p].reachable) continue;
            if (!blocks_[p].computed) continue;
            r = first ? blocks_[p].out : meet(r, blocks_[p].out);
            first = false;
        }
        return r;   // no computed pred -> empty (transient during fixpoint)
    }

    void simulate(const IFacts& in, IFacts& out, int k, bool check) {
        out = in;
        const Block& b = blocks_[k];
        for (int i = b.start; i < b.end; i++) {
            const IRInstr& inS = is_[i];
            if (inS.garbage) continue;
            step(inS, out, i, check);
        }
    }

    void clearIfReg(IFacts& F, const IROperand& o) {
        if (isRegLike(o)) killReg(F, o.reg);
    }

    void step(const IRInstr& in, IFacts& F, int idx, bool check) {
        const std::string& fn = fn_.name;
        auto rep = [&](const char* code, const std::string& msg) {
            if (check) chk_.report(fn, idx, code, msg);
        };

        switch (in.op) {
            case IROp::Nop:
            case IROp::Func:
            case IROp::EndFunc:
            case IROp::Label:
            case IROp::Arg:
            case IROp::PrintStr:
            case IROp::PrintInt:
            case IROp::PrintFlt:
            case IROp::Exit:
            case IROp::Ret:
            case IROp::Br:
                break;
            case IROp::BrZ:
            case IROp::BrNZ:
            case IROp::BrCC:
                if (check) checkBranches(in, F, idx);
                break;

            case IROp::Const:
                if (isRegLike(in.a)) setILit(F, in.a.reg, in.b.imm);
                break;
            case IROp::FConst:
                if (isRegLike(in.a)) setFLit(F, in.a.reg, decodeF(in.b));
                break;
            case IROp::Str:
                clearIfReg(F, in.a);
                break;
            case IROp::LeaGlobal:
            case IROp::LeaSlot:
                clearIfReg(F, in.a);
                break;

            case IROp::Mov: {
                if (!isRegLike(in.a)) break;
                int64_t v;
                float fv;
                if (constInt(in.b, F, v)) {
                    setLikeInt(F, in.a.reg, v, originOf(F, in.b));
                } else if (constFloat(in.b, F, fv)) {
                    if (isPlain(F, in.b)) setFLit(F, in.a.reg, fv);
                    else setF(F, in.a.reg, fv);
                } else killReg(F, in.a.reg);
                if (isRegLike(in.b)) {
                    auto iv = F.via.find(in.b.reg);
                    if (iv != F.via.end()) F.via[in.a.reg] = iv->second;
                    auto rr = F.rng.find(in.b.reg);
                    if (rr != F.rng.end() && !F.ic.count(in.a.reg))
                        F.rng[in.a.reg] = rr->second;
                    if (F.cmpOut.count(in.b.reg)) F.cmpOut.insert(in.a.reg);
                }
                break;
            }
            case IROp::FMov: {
                if (!isRegLike(in.a)) break;
                float fv;
                if (constFloat(in.b, F, fv)) {
                    if (isPlain(F, in.b)) setFLit(F, in.a.reg, fv);
                    else setF(F, in.a.reg, fv);
                } else killReg(F, in.a.reg);
                if (isRegLike(in.b)) {
                    auto iv = F.via.find(in.b.reg);
                    if (iv != F.via.end()) F.via[in.a.reg] = iv->second;
                }
                break;
            }

            case IROp::Load:
            case IROp::Load32: {
                if (!isRegLike(in.a)) break;
                // Memory displacement lives in in.label (<0 = 0). Anything
                // but a plain slot read: value unknown.
                if ((in.label >= 0 && in.label != 0)) {
                    killReg(F, in.a.reg);
                    break;
                }
                int64_t v;
                float fv;
                if (constInt(in.b, F, v)) {
                    if (in.op == IROp::Load32)
                        v = (int64_t)(int32_t)(uint32_t)(uint64_t)v;
                    setLikeInt(F, in.a.reg, v, originOf(F, in.b));
                } else if (constFloat(in.b, F, fv)) {
                    if (isPlain(F, in.b)) setFLit(F, in.a.reg, fv);
                    else setF(F, in.a.reg, fv);
                } else {
                    killReg(F, in.a.reg);
                }
                // remember where the value came from (for self-comparison)
                F.via.erase(in.a.reg);
                if (in.op == IROp::Load && isRegLike(in.b))
                    F.via[in.a.reg] = in.b.reg;
                // and the range the slot was last known to hold (IR007)
                if (!F.ic.count(in.a.reg) && isRegLike(in.b)) {
                    auto rr = F.rng.find(in.b.reg);
                    if (rr != F.rng.end()) F.rng[in.a.reg] = rr->second;
                }
                break;
            }
            // Store family: a = destination slot (displacement in in.label),
            // b = source register. (The ir.h comment there is stale.)
            case IROp::Store:
            case IROp::Store32: {
                if (in.label >= 0 && in.label != 0) { killAll(F); break; }
                if (!isRegLike(in.a)) break;
                killViaSlot(F, in.a.reg);
                int64_t v;
                if (constInt(in.b, F, v)) {
                    if (in.op == IROp::Store32)
                        v = (int64_t)(int32_t)(uint32_t)(uint64_t)v;
                    setLikeInt(F, in.a.reg, v, originOf(F, in.b));
                } else {
                    killReg(F, in.a.reg);
                    // the range survives the trip through memory (IR007)
                    if (isRegLike(in.b)) {
                        auto rr = F.rng.find(in.b.reg);
                        if (rr != F.rng.end()) F.rng[in.a.reg] = rr->second;
                    }
                }
                break;
            }
            case IROp::FStore: {
                if (in.label >= 0 && in.label != 0) { killAll(F); break; }
                if (!isRegLike(in.a)) break;
                killViaSlot(F, in.a.reg);
                float fv;
                if (constFloat(in.b, F, fv)) {
                    if (isPlain(F, in.b)) setFLit(F, in.a.reg, fv);
                    else setF(F, in.a.reg, fv);
                } else killReg(F, in.a.reg);
                break;
            }
            case IROp::FLoad: {
                if (!isRegLike(in.a)) break;
                if (in.label >= 0 && in.label != 0) {
                    killReg(F, in.a.reg);
                    break;
                }
                float fv;
                if (constFloat(in.b, F, fv)) {
                    if (isPlain(F, in.b)) setFLit(F, in.a.reg, fv);
                    else setF(F, in.a.reg, fv);
                } else killReg(F, in.a.reg);
                // `fa == fa` loads the same slot twice: remember it (IR009)
                F.via.erase(in.a.reg);
                if (isRegLike(in.b)) F.via[in.a.reg] = in.b.reg;
                break;
            }

            case IROp::GLoad:
            case IROp::GLoad32: {
                if (!isRegLike(in.a)) break;
                if (in.label >= 0 && in.label != 0) {
                    killReg(F, in.a.reg);   // field of a global: unknown
                    break;
                }
                auto it = F.gc.find(in.b.name);
                if (it != F.gc.end()) {
                    int64_t v = it->second;
                    if (in.op == IROp::GLoad32)
                        v = (int64_t)(int32_t)(uint32_t)(uint64_t)v;
                    setI(F, in.a.reg, v);
                } else {
                    killReg(F, in.a.reg);
                }
                break;
            }
            // GStore family: a = global name (displacement in in.label),
            // b = source register.
            case IROp::GStore:
            case IROp::GStore32: {
                if (in.label >= 0 && in.label != 0) break;  // field write
                int64_t v;
                if (constInt(in.b, F, v)) {
                    if (in.op == IROp::GStore32)
                        v = (int64_t)(int32_t)(uint32_t)(uint64_t)v;
                    F.gc[in.a.name] = v;
                } else {
                    F.gc.erase(in.a.name);
                }
                break;
            }
            case IROp::FGLoad: {
                if (isRegLike(in.a)) killReg(F, in.a.reg);
                break;
            }
            case IROp::FGStore:
                break;

            case IROp::PLoad:
            case IROp::PLoad32:
            case IROp::PLoad32Z:
            case IROp::PLoadW:
            case IROp::PLoadB:
                clearIfReg(F, in.a);
                break;
            case IROp::PStore:
            case IROp::PStore32:
            case IROp::PStoreW:
            case IROp::PStoreB:
            case IROp::FPStore:
                killAll(F);
                break;

            // ---- integer arithmetic ----
            case IROp::Add:
            case IROp::Sub:
            case IROp::Mul:
            case IROp::IDiv:
            case IROp::UDiv:
            case IROp::IMod:
            case IROp::UMod:
            case IROp::And:
            case IROp::Or:
            case IROp::Xor:
            case IROp::Shl:
            case IROp::Shr:
            case IROp::Sar: {
                if (!isRegLike(in.a)) break;
                int64_t x = 0, y = 0;
                bool bx = constInt(in.b, F, x), by = constInt(in.c, F, y);
                // checks
                if (check) {
                    checkIntBin(in, x, y, bx, by, rep);
                    // IR010: `x / x` (or `x % x`) from two loads of one slot
                    if (!bx && !by &&
                        (in.op == IROp::IDiv || in.op == IROp::IMod ||
                         in.op == IROp::UDiv || in.op == IROp::UMod) &&
                        sameValue(in.b, in.c, F))
                        rep("IR010", "division of a value by itself: 1 for a "
                                    "non-zero value and a division by zero at 0");
                }
                if (!bx || !by) {
                    killReg(F, in.a.reg);
                    if (check) setRangeFromOp(in, F, bx, by, x, y);
                    break;
                }
                int64_t r = 0;
                bool defined = true;
                switch (in.op) {
                    case IROp::Add: r = wrapAdd(x, y); break;
                    case IROp::Sub: r = wrapSub(x, y); break;
                    case IROp::Mul: r = wrapMul(x, y); break;
                    case IROp::IDiv:
                        if (y == 0 || (x == INT64_MIN && y == -1)) defined = false;
                        else r = x / y;
                        break;
                    case IROp::UDiv:
                        if (y == 0) defined = false;
                        else r = (int64_t)((uint64_t)x / (uint64_t)y);
                        break;
                    case IROp::IMod:
                        if (y == 0 || (x == INT64_MIN && y == -1)) defined = false;
                        else r = x % y;
                        break;
                    case IROp::UMod:
                        if (y == 0) defined = false;
                        else r = (int64_t)((uint64_t)x % (uint64_t)y);
                        break;
                    case IROp::And: r = x & y; break;
                    case IROp::Or: r = x | y; break;
                    case IROp::Xor: r = x ^ y; break;
                    case IROp::Shl: r = wrapShl(x, (int)y); break;
                    case IROp::Shr: r = wrapShr(x, (int)y); break;
                    case IROp::Sar: r = wrapSar(x, (int)y); break;
                    default: defined = false; break;
                }
                if (defined) setI(F, in.a.reg, r);
                else killReg(F, in.a.reg);
                break;
            }
            case IROp::Neg: {
                if (!isRegLike(in.a)) break;
                int64_t x;
                if (!constInt(in.b, F, x)) { killReg(F, in.a.reg); break; }
                if (check && x == INT64_MIN)
                    rep("IR003", "negating INT64_MIN overflows 64-bit int");
                setI(F, in.a.reg, wrapNeg(x));
                break;
            }
            case IROp::Not: {
                if (!isRegLike(in.a)) break;
                int64_t x;
                if (!constInt(in.b, F, x)) { killReg(F, in.a.reg); break; }
                setI(F, in.a.reg, ~x);
                break;
            }

            // ---- float arithmetic ----
            case IROp::FAdd:
            case IROp::FSub:
            case IROp::FMul:
            case IROp::FDiv: {
                if (!isRegLike(in.a)) break;
                float x, y;
                if (!constFloat(in.b, F, x) || !constFloat(in.c, F, y)) {
                    killReg(F, in.a.reg);
                    break;
                }
                float r = 0.0f;
                if (in.op == IROp::FAdd) r = x + y;
                else if (in.op == IROp::FSub) r = x - y;
                else if (in.op == IROp::FMul) r = x * y;
                else r = x / y;
                if (check && in.op == IROp::FDiv && y == 0.0f)
                    rep("IR001", "division by zero");
                setF(F, in.a.reg, r);
                break;
            }
            case IROp::FNeg: {
                if (!isRegLike(in.a)) break;
                float x;
                if (!constFloat(in.b, F, x)) { killReg(F, in.a.reg); break; }
                setF(F, in.a.reg, -x);
                break;
            }
            case IROp::I2F: {
                if (!isRegLike(in.a)) break;
                int64_t x;
                if (!constInt(in.b, F, x)) { killReg(F, in.a.reg); break; }
                float f = (float)x;
                if (check && (double)x != (double)f)
                    rep("IR006", "integer constant " + std::to_string(x) +
                                     " is not representable in float32");
                setF(F, in.a.reg, f);
                break;
            }
            case IROp::F2I: {
                if (!isRegLike(in.a)) break;
                float f;
                bool known = constFloat(in.b, F, f);
                if (check && known) {
                    if (std::isnan(f) || f < -9223372036854775808.0f ||
                        f >= 9223372036854775808.0f)
                        rep("IR005", "float-to-int conversion of a constant that "
                                    "is NaN or outside int64");
                }
                // never materialize: conversion of an out-of-range float is UB
                killReg(F, in.a.reg);
                break;
            }

            case IROp::Cmp: {
                if (!isRegLike(in.a)) break;
                if (check) {
                    // IR009: a float compared with itself. `!=` stays quiet:
                    // `f != f` is the canonical NaN test (as in BUG021).
                    if (in.a.off == 1 && in.cond != "!=" &&
                        sameValue(in.b, in.c, F))
                        rep("IR009", "self-comparison '" + in.cond +
                                         "' is false when the value is NaN");
                    // IR008: one side is itself a comparison result. The
                    // `x == 0` shape is how IRGen lowers `!x`, not a chain.
                    bool notShape = (in.cond == "==" &&
                                     in.c.kind == IROperand::Imm &&
                                     in.c.imm == 0);
                    if (!notShape &&
                        ((isRegLike(in.b) && F.cmpOut.count(in.b.reg)) ||
                         (isRegLike(in.c) && F.cmpOut.count(in.c.reg))))
                        rep("IR008", "chained comparison: '" + in.cond +
                                         "' compares a comparison result "
                                         "(0/1), not the original operands");
                }
                bool decided = false;
                if (in.a.off == 1) {          // float comparison
                    float x, y;
                    if (constFloat(in.b, F, x) && constFloat(in.c, F, y)) {
                        int64_t res = cmpFloatCond(in.cond, x, y) ? 1 : 0;
                        if (isPlain(F, in.b) && isPlain(F, in.c))
                            setCmpLit(F, in.a.reg, res);
                        else
                            setI(F, in.a.reg, res);
                        decided = true;
                    } else {
                        killReg(F, in.a.reg);
                    }
                } else {
                    int64_t x, y;
                    if (constInt(in.b, F, x) && constInt(in.c, F, y)) {
                        int64_t res = cmpIntCond(in.cond, x, y) ? 1 : 0;
                        // A Cmp of two plain literals is IRGen's own dispatch
                        // machinery (switch cases, logical-op operands):
                        // exempt from 004 so `switch <literal selector>` stays
                        // quiet.
                        if (isPlain(F, in.b) && isPlain(F, in.c))
                            setCmpLit(F, in.a.reg, res);
                        else
                            setI(F, in.a.reg, res);
                        decided = true;
                    } else {
                        killReg(F, in.a.reg);
                        // IR007: both sides known from ranges -> decided
                        if (check) reportRangeCmp(in, F, rep);
                    }
                }
                // the result of a comparison feeds the chained-compare check
                if (!decided && isRegLike(in.a)) F.cmpOut.insert(in.a.reg);
                break;
            }

            case IROp::Call:
            case IROp::ICall:
            case IROp::Syscall:
                killAll(F);   // the callee may write through any pointer
                break;

            case IROp::RawAsm:
                killAll(F);
                break;

            default:
                if (isRegLike(in.a)) killReg(F, in.a.reg);
                break;
        }
    }

    void checkIntBin(const IRInstr& in, int64_t x, int64_t y,
                     bool bx, bool by,
                     const std::function<void(const char*, const std::string&)>& rep) {
        if (in.op == IROp::IDiv || in.op == IROp::IMod ||
            in.op == IROp::UDiv || in.op == IROp::UMod) {
            if (by && y == 0) {
                rep("IR001", in.op == IROp::IDiv || in.op == IROp::UDiv
                                 ? "division by zero"
                                 : "modulo by zero");
                return;
            }
            if (in.op == IROp::IDiv && bx && by && x == INT64_MIN && y == -1)
                rep("IR003", "INT64_MIN / -1 overflows 64-bit int");
            return;
        }
        if (in.op == IROp::Shl || in.op == IROp::Shr || in.op == IROp::Sar) {
            if (by && (y < 0 || y > 63))
                rep("IR002", "shift amount " + std::to_string(y) +
                                 " is out of range [0, 64)");
            return;
        }
        if (in.op == IROp::Add || in.op == IROp::Sub || in.op == IROp::Mul) {
            if (!bx || !by) return;
            i128 t = 0;
            const char* what = "arithmetic";
            if (in.op == IROp::Add) { t = (i128)x + y; what = "addition"; }
            else if (in.op == IROp::Sub) { t = (i128)x - y; what = "subtraction"; }
            else { t = (i128)x * y; what = "multiplication"; }
            if (t < (i128)INT64_MIN || t > (i128)INT64_MAX)
                rep("IR003", std::string("constant ") + what +
                                 " overflows 64-bit int");
        }
    }

    void checkBranches(const IRInstr& in, const IFacts& F, int idx) {
        const std::string& fn = fn_.name;
        auto rep = [&](const char* code, const std::string& msg) {
            chk_.report(fn, idx, code, msg);
        };
        if (in.op == IROp::BrZ || in.op == IROp::BrNZ) {
            int64_t v;
            if (!constInt(in.a, F, v)) return;
            Origin o = originOf(F, in.a);
            if (o == ORIGIN_CMPLIT) return;       // IRGen's own dispatch (switch)
            if (o == ORIGIN_PLAIN && v != 0) return;  // `while 1`: plain literal
            bool taken = (in.op == IROp::BrZ) ? (v == 0) : (v != 0);
            rep("IR004", std::string("conditional branch on the constant ") +
                             std::to_string(v) +
                             (taken ? " (always taken)" : " (never taken)"));
            return;
        }
        if (in.op == IROp::BrCC) {
            if (in.a.off == 1) {
                // IR009: a float compared with itself in a branch. `!=` is
                // left alone: that is how NaN is tested.
                if (in.cond != "!=" && sameValue(in.a, in.b, F))
                    rep("IR009", "self-comparison '" + in.cond +
                                     "' in a branch is false when the value "
                                     "is NaN");
                return;   // float compare: NaN makes it unsafe otherwise
            }

            // IR008: an operand is itself a comparison result (0/1)
            if ((isRegLike(in.a) && F.cmpOut.count(in.a.reg)) ||
                (isRegLike(in.b) && F.cmpOut.count(in.b.reg))) {
                rep("IR008", "chained comparison: the branch '" + in.cond +
                                 "' compares a comparison result (0/1), not "
                                 "the original operands");
                return;
            }

            // Self-comparison: the same register on both sides (always equal),
            // or two loads from one slot with no write in between (via[]).
            if (isRegLike(in.a) && isRegLike(in.b) && in.a.reg == in.b.reg) {
                bool res = cmpIntCond(in.cond, 0, 0);
                rep("IR004", "self-comparison in a branch is always " +
                                 std::string(res ? "true" : "false"));
                return;
            }
            if (isRegLike(in.a) && isRegLike(in.b)) {
                auto va = F.via.find(in.a.reg);
                auto vb = F.via.find(in.b.reg);
                if (va != F.via.end() && vb != F.via.end() &&
                    va->second == vb->second) {
                    bool res = cmpIntCond(in.cond, 0, 0);
                    rep("IR004",
                        "self-comparison in a branch (both sides read the "
                        "same slot) is always " +
                            std::string(res ? "true" : "false"));
                    return;
                }
            }

            int64_t x, y;
            if (constInt(in.a, F, x) && constInt(in.b, F, y)) {
                // Report only when BOTH sides were computed. A plain literal
                // on either side covers IRGen's own machinery (for-loop step
                // sign check against Const 0) and source-level literals that
                // the AST pass already handles.
                if (originOf(F, in.a) == ORIGIN_PLAIN ||
                    originOf(F, in.b) == ORIGIN_PLAIN)
                    return;
                bool res = cmpIntCond(in.cond, x, y);
                rep("IR004", "branch on a constant comparison (" +
                                 std::to_string(x) + " " + in.cond + " " +
                                 std::to_string(y) + ") is always " +
                                 (res ? "true" : "false"));
            } else {
                // IR007: ranges (%K / &M results) already decide the branch,
                // so one of its arms is dead. Comparisons in branch position
                // arrive here as BrCC, not as a Cmp.
                reportRangeCmp(in, F, rep);
            }
        }
    }

    // ---------------- IR011: a loop whose step can never satisfy its guard --

    static bool clobbersAll(const IRInstr& in) {
        return in.op == IROp::Call || in.op == IROp::ICall ||
               in.op == IROp::Syscall || in.op == IROp::RawAsm;
    }

    // Does this instruction write register `reg`?
    static bool definesReg(const IRInstr& in, int reg) {
        if (in.garbage) return false;
        switch (in.op) {
            case IROp::Nop: case IROp::Func: case IROp::EndFunc:
            case IROp::Label: case IROp::Arg:
            case IROp::PrintStr: case IROp::PrintInt: case IROp::PrintFlt:
            case IROp::Exit: case IROp::Ret:
            case IROp::Br: case IROp::BrZ: case IROp::BrNZ: case IROp::BrCC:
            case IROp::Store: case IROp::Store32:
            case IROp::GStore: case IROp::GStore32:
            case IROp::PStore: case IROp::PStore32: case IROp::PStoreW:
            case IROp::PStoreB: case IROp::FPStore:
            case IROp::FStore: case IROp::FGStore:
                return false;
            default:
                return in.a.kind == IROperand::Reg && in.a.reg == reg;
        }
    }

    // Last definition of `reg` in [from, to), scanned backwards.
    // -1: none, -2: a call/asm that clobbers everything comes first.
    int lastDef(int from, int to, int reg) const {
        for (int i = to - 1; i >= from; i--) {
            const IRInstr& in = is_[i];
            if (in.garbage) continue;
            if (clobbersAll(in)) return -2;
            if (definesReg(in, reg)) return i;
        }
        return -1;
    }

    static std::string negCmp(const std::string& c) {
        if (c == "<") return ">";
        if (c == ">") return "<";
        if (c == "<=") return ">=";
        if (c == ">=") return "<=";
        return c;
    }

    void checkLoops() {
        for (size_t u = 0; u < blocks_.size(); u++) {
            if (!blocks_[u].reachable) continue;
            for (int v : blocks_[u].succ) {
                if (v < 0 || !blocks_[v].reachable) continue;
                if ((int)u < v) continue;   // forward edge: not a back edge
                checkLoop((int)u, v);
            }
        }
    }

    void checkLoop(int u, int v) {
        const Block& hb = blocks_[v];
        if (hb.end <= hb.start) return;
        const IRInstr& br = is_[hb.end - 1];
        if (br.op != IROp::BrCC) return;      // only a guard-shaped header
        if (hb.succ.size() != 2) return;
        int guardIdx = hb.end - 1;
        auto rep = [&](const std::string& msg) {
            chk_.report(fn_.name, guardIdx, "IR011", msg);
        };
        auto tit = labelInstr_.find(branchTarget(br));
        if (tit == labelInstr_.end()) return;
        int tBlock = blockOf_[tit->second];
        if (tBlock < 0 || !blocks_[tBlock].reachable) return;

        // ---- the natural loop over the back edge u -> v
        std::vector<char> inL(blocks_.size(), 0);
        std::vector<int> stack;
        inL[v] = 1;
        if (u != v) { inL[u] = 1; stack.push_back(u); }
        while (!stack.empty()) {
            int k = stack.back();
            stack.pop_back();
            for (int p : blocks_[k].pred) {
                if (inL[p]) continue;
                inL[p] = 1;
                stack.push_back(p);
            }
        }
        // one entry only: the header (a second one would break the step)
        for (size_t k = 0; k < blocks_.size(); k++) {
            if (inL[k]) continue;
            for (int s : blocks_[k].succ)
                if (inL[s] && s != v) return;
        }
        // the guard must be the only way out of the loop
        int nIn = 0;
        for (int s : hb.succ)
            if (inL[s]) nIn++;
        if (nIn != 1) return;
        bool contOnTrue = inL[tBlock] != 0;
        for (size_t k = 0; k < blocks_.size(); k++) {
            if (!inL[k]) continue;
            const IRInstr& last = is_[blocks_[k].end - 1];
            if (last.op == IROp::Ret || last.op == IROp::Exit ||
                last.op == IROp::EndFunc)
                return;
            if ((int)k != v)
                for (int s : blocks_[k].succ)
                    if (!inL[s]) return;   // an exit the guard does not gate
        }

        // ---- the counter: a guard operand loaded from a slot in v
        auto loadSlotOf = [&](const IROperand& o, int defIdx) -> int {
            if (defIdx < 0 || !isRegLike(o)) return -1;
            const IRInstr& in = is_[defIdx];
            if (in.op != IROp::Load || in.label > 0 || !isRegLike(in.b))
                return -1;
            if (in.a.reg != o.reg) return -1;
            return in.b.reg;
        };
        int defA = isRegLike(br.a) ? lastDef(hb.start, guardIdx, br.a.reg) : -1;
        int defB = isRegLike(br.b) ? lastDef(hb.start, guardIdx, br.b.reg) : -1;
        if (defA == -2 || defB == -2) return;
        int slotA = loadSlotOf(br.a, defA);
        int slotB = loadSlotOf(br.b, defB);
        int counterSlot = -1;
        IROperand bound = br.b;
        std::string cond = br.cond;
        if (slotA >= 0) {
            counterSlot = slotA;
            bound = br.b;
        } else if (slotB >= 0) {
            counterSlot = slotB;
            bound = br.a;
            cond = negCmp(cond);   // `n > i` read as `i < n`
        } else {
            return;
        }
        if (cond != "<" && cond != "<=" && cond != ">" && cond != ">=" &&
            cond != "!=")
            return;

        // ---- the bound: a literal, an invariant slot or a live-in register
        bool boundIsImm = false;
        int64_t boundImm = 0;
        int boundSlot = -1;
        bool boundRegLiveIn = false;
        if (bound.kind == IROperand::Imm) {
            boundIsImm = true;
            boundImm = bound.imm;
        } else if (isRegLike(bound)) {
            int bd = lastDef(hb.start, guardIdx, bound.reg);
            if (bd == -2) return;
            if (bd < 0) {
                boundRegLiveIn = true;
            } else {
                const IRInstr& in = is_[bd];
                if (in.op == IROp::Const && in.b.kind == IROperand::Imm) {
                    boundIsImm = true;
                    boundImm = in.b.imm;
                } else if (in.op == IROp::Load && isRegLike(in.b) &&
                           in.label <= 0) {
                    boundSlot = in.b.reg;
                } else {
                    return;   // recomputed each round: not invariant
                }
            }
        } else {
            return;
        }

        // ---- exactly one write to the counter, the bound never written
        int storeIdx = -1;
        bool boundWritten = false;
        for (size_t k = 0; k < blocks_.size(); k++) {
            if (!inL[k]) continue;
            for (int i = blocks_[k].start; i < blocks_[k].end; i++) {
                const IRInstr& in = is_[i];
                if (in.garbage) continue;
                if ((in.op == IROp::Store || in.op == IROp::Store32) &&
                    isRegLike(in.a)) {
                    if (in.a.reg == counterSlot) {
                        if (storeIdx >= 0) return;   // several writers
                        storeIdx = i;
                    } else if (boundSlot >= 0 && in.a.reg == boundSlot) {
                        boundWritten = true;
                    }
                }
                if (boundRegLiveIn && definesReg(in, bound.reg))
                    boundWritten = true;
            }
        }
        if (storeIdx < 0 || boundWritten) return;
        // the counter's address must never be taken: a pointer could write it
        for (size_t i = 0; i < is_.size(); i++) {
            const IRInstr& in = is_[i];
            if (in.garbage) continue;
            if (in.op == IROp::LeaSlot && isRegLike(in.b) &&
                in.b.reg == counterSlot)
                return;
        }

        // ---- the step: the single store writes `counter +/- K`
        const IRInstr& st = is_[storeIdx];
        if (!isRegLike(st.b)) return;
        int sb = blocks_[blockOf_[storeIdx]].start;
        int defIdx = lastDef(sb, storeIdx, st.b.reg);
        if (defIdx < 0) return;
        const IRInstr& def = is_[defIdx];
        if (def.op != IROp::Add && def.op != IROp::Sub) return;
        int64_t step = 0;
        if (def.c.kind == IROperand::Imm) {
            step = def.c.imm;
        } else if (isRegLike(def.c)) {
            int cd = lastDef(sb, defIdx, def.c.reg);
            if (cd < 0 || is_[cd].op != IROp::Const ||
                is_[cd].b.kind != IROperand::Imm)
                return;
            step = is_[cd].b.imm;
        } else {
            return;
        }
        if (!isRegLike(def.b)) return;
        int ld = lastDef(sb, defIdx, def.b.reg);
        if (ld < 0) return;
        const IRInstr& lin = is_[ld];
        if (lin.op != IROp::Load || lin.label > 0 || !isRegLike(lin.b) ||
            lin.b.reg != counterSlot)
            return;
        if (def.op == IROp::Sub) step = wrapNeg(step);

        // ---- values at loop entry (the guard runs on them first)
        auto entryConst = [&](int s, int64_t& out) -> bool {
            bool first = true;
            IFacts acc;
            for (int p : blocks_[v].pred) {
                if (p == v || inL[p]) continue;
                if (!blocks_[p].reachable || !blocks_[p].computed) continue;
                acc = first ? blocks_[p].out : meet(acc, blocks_[p].out);
                first = false;
            }
            if (first) return false;
            auto it = acc.ic.find(s);
            if (it == acc.ic.end()) return false;
            out = it->second;
            return true;
        };
        int64_t i0 = 0, lim = 0;
        bool haveI = entryConst(counterSlot, i0);
        bool haveL = boundIsImm ? ((lim = boundImm), true)
                                : (boundSlot >= 0 && entryConst(boundSlot, lim));
        auto loopWhile = [&](int64_t i, int64_t b) {
            bool c = cmpIntCond(cond, i, b);
            return contOnTrue ? c : !c;
        };
        // a loop that is never entered cannot run forever
        if (haveI && haveL && !loopWhile(i0, lim)) return;

        if (cond == "!=") {
            if (!haveI || !haveL) return;   // equality needs both ends known
            if (step == 0) {
                rep("the counter never changes (step 0), so it can never "
                    "equal " + std::to_string(lim) + ": the loop cannot finish");
                return;
            }
            bool towards = step > 0 ? (lim > i0) : (lim < i0);
            if (!towards) {
                rep("the counter starts at " + std::to_string(i0) +
                    " and steps by " + std::to_string(step) +
                    ", away from " + std::to_string(lim) +
                    ": it can never equal it");
                return;
            }
            i128 diff = (i128)lim - (i128)i0;
            i128 stp = step > 0 ? (i128)step : -(i128)step;
            if (diff % stp == 0) return;   // the bound is on the way
            rep("the counter starts at " + std::to_string(i0) +
                " and steps by " + std::to_string(step) +
                ", so it can never equal " + std::to_string(lim));
            return;
        }
        if (step == 0) {
            rep("the counter never changes (step 0), so the guard '" + cond +
                "' never turns: the loop cannot finish");
            return;
        }
        // does the loop condition stay true as the counter runs away?
        bool condAtPlus = (cond == ">" || cond == ">=");
        bool condAtMinus = (cond == "<" || cond == "<=");
        bool fPlus = contOnTrue ? condAtPlus : !condAtPlus;
        bool fMinus = contOnTrue ? condAtMinus : !condAtMinus;
        bool endless = (step > 0) ? fPlus : fMinus;
        if (!endless) return;
        std::string msg = "the guard '" + cond +
                          "' can never become false: the counter";
        if (haveI) msg += " starts at " + std::to_string(i0);
        msg += " and steps by " + std::to_string(step);
        if (haveL) msg += " (bound " + std::to_string(lim) + ")";
        msg += ", so the loop cannot finish";
        rep(msg);
    }

    void run() {
        if (fn_.garbage || fn_.isExtern) return;
        if (!build()) return;

        // fixpoint without checks (transient facts must not be reported)
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 10000) {
            changed = false;
            for (size_t k = 0; k < blocks_.size(); k++) {
                if (!blocks_[k].reachable) continue;
                IFacts in = inOf((int)k);
                IFacts out;
                simulate(in, out, (int)k, false);
                if (!blocks_[k].computed || !(out == blocks_[k].out)) {
                    blocks_[k].out = out;
                    blocks_[k].computed = true;
                    changed = true;
                }
            }
        }

        // final pass: converged facts, checks on
        for (size_t k = 0; k < blocks_.size(); k++) {
            if (!blocks_[k].reachable) continue;
            IFacts in = inOf((int)k);
            IFacts out;
            simulate(in, out, (int)k, true);
        }

        // structural pass over the converged CFG (IR011)
        checkLoops();
    }
};

}  // namespace

int runBugFindIR(const IRProgram& prog, std::vector<std::string>& warnings) {
    IRChecker chk;
    chk.out_ = &warnings;
    for (auto& fn : prog.functions) {
        FuncAnalyzer fa(fn, &warnings, chk);
        fa.run();
    }
    return chk.count_;
}
