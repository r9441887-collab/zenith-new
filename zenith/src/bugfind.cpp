// ====================================================================
// bugfind.cpp — static AST-level bug finder.
//
// Walks the parsed Program with an interval/constant domain and reports
// suspicious patterns as "Warning: <file>:<line>: [ZT-BUGxxx] ..." lines.
// Findings never change the exit code by themselves: main.cpp decides
// (--bugfind = strict, --no-bugfind / ZT_NO_BUGFIND = off).
//
// Rules:
//   ZT-BUG001  condition is always false
//   ZT-BUG002  condition is always true (plain literals are exempt)
//   ZT-BUG003  impossible conjunction (conflicting ranges on one name)
//   ZT-BUG004  self-comparison (x <op> x, int)
//   ZT-BUG005  equality that can never hold (x*K == C, x&M == C, x%M == C)
//   ZT-BUG006  division / modulo by a zero constant
//   ZT-BUG007  constant array index out of range
//   ZT-BUG008  array index range may leave [0, size)
//   ZT-BUG009  masked / modulo array index may leave [0, size)
//   ZT-BUG010  (x % 2) == 1 compared without a non-negative proof
//   ZT-BUG011  constant fold overflows int64 / shift amount out of range
//   ZT-BUG012  int compared with a non-integral float constant
//   ZT-BUG013  double vs float32 rounding changes a float comparison
//   ZT-BUG014  float domain error (sqrt<0, pow(<0,frac), fmod(_,0))
//   ZT-BUG015  for-loop with step 0 that never finishes
//   ZT-BUG016  comparison decided by the known ranges of both sides
//   ZT-BUG017  chained comparison (a < b < c evaluates as (a < b) < c)
//   ZT-BUG018  while-loop whose step never moves the counter to the bound
//   ZT-BUG019  while (i != limit) whose step can never reach the limit
//   ZT-BUG020  impossible conjunction of two contradictory comparisons
//   ZT-BUG021  self-comparison of a float (NaN semantics)
//   ZT-BUG022  division/modulo of an expression by itself (x / x, x % x)
// ====================================================================
#include "bugfind.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

using i128 = __int128;

// ---------------------------------------------------------------- utils

bool isCmpOp(const std::string& op) {
    return op == "==" || op == "!=" || op == "<" || op == "<=" ||
           op == ">" || op == ">=";
}

std::string fmtF(double d) {
    char b[64];
    snprintf(b, sizeof(b), "%g", d);
    return b;
}

// Negated comparison op (for narrowing the false branch).
std::string negOp(const std::string& op) {
    if (op == "==") return "!=";
    if (op == "!=") return "==";
    if (op == "<") return ">=";
    if (op == "<=") return ">";
    if (op == ">") return "<=";
    if (op == ">=") return "<";
    return op;
}

// Same relation with the operands swapped: a < b  <=>  b > a.
std::string swapOp(const std::string& op) {
    if (op == "<") return ">";
    if (op == "<=") return ">=";
    if (op == ">") return "<";
    if (op == ">=") return "<=";
    return op;
}

bool pureExpr(Expr* e) {
    if (!e) return false;
    if (dynamic_cast<NumberExpr*>(e) || dynamic_cast<FloatExpr*>(e) ||
        dynamic_cast<IdentExpr*>(e))
        return true;
    if (auto m = dynamic_cast<MemberExpr*>(e)) return pureExpr(m->object.get());
    if (auto u = dynamic_cast<UnaryExpr*>(e)) return pureExpr(u->operand.get());
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return pureExpr(b->left.get()) && pureExpr(b->right.get());
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e))
        return pureExpr(a->array.get()) && pureExpr(a->index.get());
    return false;
}

std::string es(Expr* e) {
    if (!e) return "?";
    if (auto n = dynamic_cast<NumberExpr*>(e)) return std::to_string(n->value);
    if (auto f = dynamic_cast<FloatExpr*>(e)) return fmtF(f->value);
    if (auto id = dynamic_cast<IdentExpr*>(e)) return id->name;
    if (auto m = dynamic_cast<MemberExpr*>(e))
        return es(m->object.get()) + "." + m->member;
    if (auto u = dynamic_cast<UnaryExpr*>(e))
        return "(" + u->op + es(u->operand.get()) + ")";
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return "(" + es(b->left.get()) + " " + b->op + " " +
               es(b->right.get()) + ")";
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e))
        return es(a->array.get()) + "[" + es(a->index.get()) + "]";
    if (auto c = dynamic_cast<CallExpr*>(e)) return c->name + "(...)";
    if (auto d = dynamic_cast<DerefExpr*>(e)) return "*(" + es(d->ptr.get()) + ")";
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) return "&" + a->name;
    if (dynamic_cast<StringExpr*>(e)) return "\"...\"";
    return "?";
}

bool clamp128(i128 x, int64_t& out) {
    if (x < (i128)INT64_MIN || x > (i128)INT64_MAX) return false;
    out = (int64_t)x;
    return true;
}

int64_t wrapAdd(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a + (uint64_t)b);
}
int64_t wrapSub(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a - (uint64_t)b);
}
int64_t wrapMul(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a * (uint64_t)b);
}
int64_t wrapShl(int64_t a, int k) {
    return (int64_t)((uint64_t)a << (k & 63));
}
int64_t wrapShr(int64_t a, int k) {
    return (int64_t)((uint64_t)a >> (k & 63));
}

// two-adic valuation of |k| (k != 0): how many times 2 divides k
int ctz64(int64_t k) {
    uint64_t u = (uint64_t)(k < 0 ? -(i128)k : k);
    if (u == 0) return 64;
    int n = 0;
    while ((u & 1) == 0) { u >>= 1; n++; }
    return n;
}

// ---------------------------------------------------------------- Ival

enum class ISt { Top, Rng, Bot };

struct Ival {
    ISt st = ISt::Top;  // Top = no information, Bot = contradiction (dead)
    int64_t lo = 0, hi = 0;

    static Ival top() { return Ival(); }
    static Ival bot() { Ival v; v.st = ISt::Bot; return v; }
    static Ival rng(int64_t a, int64_t b) {
        if (a > b) return bot();
        Ival v; v.st = ISt::Rng; v.lo = a; v.hi = b; return v;
    }
    static Ival cst(int64_t a) { return rng(a, a); }
    bool isTop() const { return st == ISt::Top; }
    bool isBot() const { return st == ISt::Bot; }
    bool isCst() const { return st == ISt::Rng && lo == hi; }
    int64_t v() const { return lo; }
};

// meet of information: Bot wins, Top is the identity
Ival iInt(Ival a, Ival b) {
    if (a.isBot() || b.isBot()) return Ival::bot();
    if (a.isTop()) return b;
    if (b.isTop()) return a;
    int64_t lo = std::max(a.lo, b.lo), hi = std::min(a.hi, b.hi);
    if (lo > hi) return Ival::bot();
    return Ival::rng(lo, hi);
}

// merge of alternative paths: Bot (dead path) is the identity
Ival iMer(Ival a, Ival b) {
    if (a.isBot()) return b;
    if (b.isBot()) return a;
    if (a.isTop() || b.isTop()) return Ival::top();
    return Ival::rng(std::min(a.lo, b.lo), std::max(a.hi, b.hi));
}

void iAdd(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isTop() || b.isTop()) { out = Ival::top(); return; }
    i128 v1 = (i128)a.lo + b.lo, v2 = (i128)a.lo + b.hi;
    i128 v3 = (i128)a.hi + b.lo, v4 = (i128)a.hi + b.hi;
    int64_t l, h;
    if (!clamp128(std::min(std::min(v1, v2), std::min(v3, v4)), l) ||
        !clamp128(std::max(std::max(v1, v2), std::max(v3, v4)), h)) {
        out = Ival::top(); return;
    }
    out = Ival::rng(l, h);
}

void iSub(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isTop() || b.isTop()) { out = Ival::top(); return; }
    i128 v1 = (i128)a.lo - b.hi, v2 = (i128)a.lo - b.lo;
    i128 v3 = (i128)a.hi - b.hi, v4 = (i128)a.hi - b.lo;
    int64_t l, h;
    if (!clamp128(std::min(std::min(v1, v2), std::min(v3, v4)), l) ||
        !clamp128(std::max(std::max(v1, v2), std::max(v3, v4)), h)) {
        out = Ival::top(); return;
    }
    out = Ival::rng(l, h);
}

void iMul(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isTop() || b.isTop()) { out = Ival::top(); return; }
    i128 p1 = (i128)a.lo * b.lo, p2 = (i128)a.lo * b.hi;
    i128 p3 = (i128)a.hi * b.lo, p4 = (i128)a.hi * b.hi;
    int64_t l, h;
    if (!clamp128(std::min(std::min(p1, p2), std::min(p3, p4)), l) ||
        !clamp128(std::max(std::max(p1, p2), std::max(p3, p4)), h)) {
        out = Ival::top(); return;
    }
    out = Ival::rng(l, h);
}

// integer division, truncating toward zero; divisor strictly one sign
void iDiv(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isTop() || b.isTop() || (b.lo <= 0 && b.hi >= 0)) {
        out = Ival::top(); return;
    }
    i128 q1 = (i128)a.lo / b.lo, q2 = (i128)a.lo / b.hi;
    i128 q3 = (i128)a.hi / b.lo, q4 = (i128)a.hi / b.hi;
    int64_t l, h;
    if (!clamp128(std::min(std::min(q1, q2), std::min(q3, q4)), l) ||
        !clamp128(std::max(std::max(q1, q2), std::max(q3, q4)), h)) {
        out = Ival::top(); return;
    }
    out = Ival::rng(l, h);
}

// remainder with the sign of the dividend (truncating division)
void iMod(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isTop() || b.isTop() || (b.lo <= 0 && b.hi >= 0)) {
        out = Ival::top(); return;
    }
    i128 m = (b.lo > 0) ? (i128)b.hi : -(i128)b.lo;   // max |divisor|
    if (m <= 0) { out = Ival::top(); return; }
    if (a.lo >= 0) {
        int64_t h;
        if (!clamp128(m - 1, h)) { out = Ival::top(); return; }
        out = Ival::rng(0, h);
    } else {
        int64_t l, h;
        if (!clamp128(-(m - 1), l) || !clamp128(m - 1, h)) {
            out = Ival::top(); return;
        }
        out = Ival::rng(l, h);
    }
}

void iAnd(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isCst() && b.isCst()) { out = Ival::cst(a.v() & b.v()); return; }
    const Ival* o = nullptr;
    int64_t m = 0;
    if (b.isCst()) { o = &a; m = b.v(); }
    else if (a.isCst()) { o = &b; m = a.v(); }
    if (!o) { out = Ival::top(); return; }
    if (m == -1) { out = *o; return; }
    if (m < 0) { out = Ival::top(); return; }
    if (o->isTop()) { out = Ival::rng(0, m); return; }
    int64_t hi = m;
    if (o->hi >= 0) hi = std::min(hi, o->hi);
    out = Ival::rng(0, std::max<int64_t>(0, hi));
}

void iOr(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isCst() && b.isCst()) { out = Ival::cst(a.v() | b.v()); return; }
    out = Ival::top();
}

void iXor(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (a.isCst() && b.isCst()) { out = Ival::cst(a.v() ^ b.v()); return; }
    out = Ival::top();
}

void iShl(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (!b.isCst() || b.v() < 0 || b.v() > 63 || a.isTop()) {
        out = Ival::top(); return;
    }
    int k = (int)b.v();
    if (a.isCst()) { out = Ival::cst(wrapShl(a.v(), k)); return; }
    i128 lo = (i128)a.lo << k, hi = (i128)a.hi << k;
    int64_t l, h;
    if (!clamp128(lo, l) || !clamp128(hi, h)) { out = Ival::top(); return; }
    out = Ival::rng(l, h);
}

// `>>` is a logical shift in every backend
void iShr(const Ival& a, const Ival& b, Ival& out) {
    if (a.isBot() || b.isBot()) { out = Ival::bot(); return; }
    if (!b.isCst() || b.v() < 0 || b.v() > 63 || a.isTop()) {
        out = Ival::top(); return;
    }
    int k = (int)b.v();
    if (a.isCst()) { out = Ival::cst(wrapShr(a.v(), k)); return; }
    if (a.lo >= 0) { out = Ival::rng(a.lo >> k, a.hi >> k); return; }
    out = Ival::top();
}

// ---------------------------------------------------------------- values

struct Val {
    Ival iv;                       // int knowledge (Top = unknown)
    bool hasFloat = false;         // value known as a float (fv valid)
    double fv = 0.0;
    bool typeKnown = false;        // static type is known
    bool isFloat = false;          // static type is float
    bool reported = false;         // a rule already fired for this value

    bool isIntConst() const { return iv.isCst() && !hasFloat; }
    int64_t ival() const { return iv.v(); }
};

Val valTop() { return Val(); }

Val valInt(int64_t v) {
    Val x;
    x.iv = Ival::cst(v);
    x.typeKnown = true;
    return x;
}

Val valFloat(double d) {
    Val x;
    x.hasFloat = true;
    x.fv = d;
    x.typeKnown = true;
    x.isFloat = true;
    return x;
}

Val mergeVal(const Val& a, const Val& b) {
    Val r;
    r.iv = iMer(a.iv, b.iv);
    r.typeKnown = a.typeKnown || b.typeKnown;
    if (a.typeKnown && b.typeKnown) r.isFloat = a.isFloat;
    else if (a.typeKnown) r.isFloat = a.isFloat;
    else if (b.typeKnown) r.isFloat = b.isFloat;
    if (a.hasFloat && b.hasFloat && a.fv == b.fv) {
        r.hasFloat = true;
        r.fv = a.fv;
    }
    r.reported = a.reported || b.reported;
    return r;
}

struct VarInfo {
    Val v;
    bool isConst = false;
    bool isGlobal = false;
    int arraySize = 0;
};

// float coercion: Zenith floats are 32-bit
Val toFloatVal(const Val& x) {
    if (x.hasFloat) {
        Val r = x;
        r.fv = (double)(float)x.fv;
        r.typeKnown = true;
        r.isFloat = true;
        r.iv = Ival::top();
        return r;
    }
    if (x.iv.isCst()) {
        Val r = valFloat((double)(float)x.iv.v());
        r.reported = x.reported;
        return r;
    }
    Val r;
    r.typeKnown = true;
    r.isFloat = true;
    r.reported = x.reported;
    return r;
}

// ---------------------------------------------------------------- analyzer

struct Ent {
    std::string name;
    bool had = false;
    VarInfo info;
};

struct ModInfo {
    std::unordered_set<std::string> names;
    bool nonLocal = false;
};

class Analyzer {
public:
    std::vector<std::string>* out_ = nullptr;
    std::string fileName_;
    BugLineFileFn fileForLine_;
    int count_ = 0;

    std::unordered_map<std::string, VarInfo> vars_;
    std::unordered_map<std::string, VarInfo> globalBase_;
    std::unordered_set<std::string> escaped_;
    std::vector<std::vector<Ent>> frames_;
    std::vector<std::pair<std::string, Ival>> pendingCons_;
    // Comparisons seen inside the current conjunction, as (left, op, right).
    // BUG003 only intersects ranges of one name, so it cannot see that
    // `a < b && b < a` contradicts itself; these pairs can.
    struct CmpPair {
        std::string a, op, b;
    };
    std::vector<CmpPair> pendingPairs_;
    int curLine_ = 0;
    bool unreachable_ = false;
    bool inGlobals_ = false;
    // A while-condition's variables can change between iterations: an
    // "always true" verdict from entry facts alone is then unstable, so
    // BUG002 is suppressed (an always-FALSE entry condition is stable: the
    // body never runs, so nothing can change).
    bool condVarsMutable_ = false;
    std::unordered_set<std::string> seen_;

    void run(const Program& prog) {
        count_ = 0;
        seen_.clear();
        vars_.clear();
        frames_.clear();
        escaped_.clear();
        inGlobals_ = true;
        for (auto& g : prog.globals) {
            curLine_ = g->line;
            walkStmt(g.get());
        }
        inGlobals_ = false;
        globalBase_ = vars_;
        // A global written by any function (or reached through &name) can
        // hold any of those written values at a later call, so its
        // initializer is not a stable fact for entry-state reasoning.
        {
            ModInfo all;
            for (auto& f : prog.functions) {
                if (f->isExtern) continue;
                collectModStmts(f->body.stmts, all);
            }
            for (auto& c : prog.classes)
                for (auto& m : c->methods)
                    if (!m.isAbstract) collectModStmts(m.body.stmts, all);
            for (auto& n : all.names) {
                auto it = globalBase_.find(n);
                if (it == globalBase_.end()) continue;
                VarInfo& vi = it->second;
                bool tk = vi.v.typeKnown;
                bool fl = vi.v.isFloat;
                vi.v = Val();
                if (tk) { vi.v.typeKnown = true; vi.v.isFloat = fl; }
            }
        }
        for (auto& f : prog.functions) {
            if (f->isExtern || f->body.stmts.empty()) continue;
            runBody(f->name, f->params, f->body.stmts);
        }
        for (auto& c : prog.classes) {
            for (auto& m : c->methods) {
                if (m.isAbstract || m.body.stmts.empty()) continue;
                runBody(c->name + "::" + m.name, m.params, m.body.stmts);
            }
        }
    }

    void runBody(const std::string& name, const std::vector<Param>& params,
                 const std::vector<std::unique_ptr<Stmt>>& stmts) {
        (void)name;
        vars_ = globalBase_;
        frames_.clear();
        pendingCons_.clear();
        pendingPairs_.clear();
        unreachable_ = false;
        pushFrame();
        for (auto& p : params) {
            VarInfo vi;
            if (p.type.kind == TypeKind::Float) {
                vi.v.typeKnown = true;
                vi.v.isFloat = true;
            } else if (p.type.kind == TypeKind::Int ||
                       p.type.kind == TypeKind::Bool) {
                vi.v.typeKnown = true;
                vi.v.isFloat = false;
            }
            setVar(p.name, vi);
        }
        for (auto& st : stmts) {
            if (unreachable_) break;
            walkStmt(st.get());
        }
        popFrame();
    }

    // ---- frames / variables ----
    void pushFrame() { frames_.emplace_back(); }

    void popFrame() {
        if (frames_.empty()) return;
        auto& fr = frames_.back();
        for (int i = (int)fr.size() - 1; i >= 0; i--) {
            Ent& e = fr[i];
            if (e.had) vars_[e.name] = e.info;
            else vars_.erase(e.name);
        }
        frames_.pop_back();
    }

    void setVar(const std::string& name, const VarInfo& info) {
        Ent e;
        e.name = name;
        auto it = vars_.find(name);
        if (it != vars_.end()) {
            e.had = true;
            e.info = it->second;
            it->second = info;
        } else {
            e.had = false;
            vars_[name] = info;
        }
        if (!frames_.empty()) frames_.back().push_back(std::move(e));
    }

    void setVal(const std::string& name, const Val& v) {
        auto it = vars_.find(name);
        if (it == vars_.end()) {
            VarInfo vi;
            vi.v = v;
            setVar(name, vi);
            return;
        }
        VarInfo vi = it->second;
        Val nv = v;
        if (vi.v.typeKnown && vi.v.isFloat) nv = toFloatVal(nv);
        else if (vi.v.typeKnown) {
            nv.typeKnown = true;
            nv.isFloat = false;
        }
        vi.v = nv;
        setVar(name, vi);
    }

    void killName(const std::string& name) {
        auto it = vars_.find(name);
        if (it == vars_.end()) return;
        VarInfo vi = it->second;
        bool tk = vi.v.typeKnown;
        bool fl = vi.v.isFloat;
        vi.v = Val();
        if (tk) { vi.v.typeKnown = true; vi.v.isFloat = fl; }
        setVar(name, vi);
    }

    void killNonLocals() {
        std::vector<std::string> keys;
        keys.reserve(vars_.size());
        for (auto& kv : vars_)
            if (kv.second.isGlobal || kv.second.arraySize > 0 ||
                escaped_.count(kv.first))
                keys.push_back(kv.first);
        for (auto& k : keys) killName(k);
    }

    void killAllValues() {
        std::vector<std::string> keys;
        keys.reserve(vars_.size());
        for (auto& kv : vars_) keys.push_back(kv.first);
        for (auto& k : keys) killName(k);
    }

    // ---- reporting ----
    void report(const char* code, int line, const std::string& msg) {
        std::string f = fileName_;
        if (fileForLine_ && line > 0) {
            std::string o = fileForLine_(line);
            if (!o.empty()) f = o;
        }
        if (f.empty()) f = "<input>";
        std::string key =
            std::string(code) + "|" + std::to_string(line) + "|" + msg;
        if (!seen_.insert(key).second) return;
        out_->push_back("Warning: " + f + ":" + std::to_string(line) +
                        ": [ZT-" + code + "] " + msg);
        count_++;
    }

    // ---- static constant folding (no side effects) ----
    bool staticConst(Expr* e, int64_t& out) {
        if (!e) return false;
        if (auto n = dynamic_cast<NumberExpr*>(e)) { out = n->value; return true; }
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            auto it = vars_.find(id->name);
            if (it != vars_.end() && it->second.v.isIntConst()) {
                out = it->second.v.ival();
                return true;
            }
            return false;
        }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) {
            int64_t v;
            if (!staticConst(u->operand.get(), v)) return false;
            if (u->op == "-") {
                if (v == INT64_MIN) return false;
                out = -v; return true;
            }
            if (u->op == "~") { out = ~v; return true; }
            if (u->op == "!") { out = (v == 0) ? 1 : 0; return true; }
            return false;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) {
            int64_t l, r;
            if (!staticConst(b->left.get(), l)) return false;
            if (!staticConst(b->right.get(), r)) return false;
            const std::string& op = b->op;
            if (op == "+") { out = wrapAdd(l, r); return true; }
            if (op == "-") { out = wrapSub(l, r); return true; }
            if (op == "*") { out = wrapMul(l, r); return true; }
            if (op == "&") { out = l & r; return true; }
            if (op == "|") { out = l | r; return true; }
            if (op == "^") { out = l ^ r; return true; }
            if (op == "<<") { if (r < 0 || r > 63) return false; out = wrapShl(l, (int)r); return true; }
            if (op == ">>") { if (r < 0 || r > 63) return false; out = wrapShr(l, (int)r); return true; }
            if (op == "/") { if (r == 0) return false; if (l == INT64_MIN && r == -1) return false; out = l / r; return true; }
            if (op == "%" || op == "//") { if (r == 0) return false; if (l == INT64_MIN && r == -1) return false; out = l % r; return true; }
            if (op == "==") { out = (l == r) ? 1 : 0; return true; }
            if (op == "!=") { out = (l != r) ? 1 : 0; return true; }
            if (op == "<") { out = (l < r) ? 1 : 0; return true; }
            if (op == "<=") { out = (l <= r) ? 1 : 0; return true; }
            if (op == ">") { out = (l > r) ? 1 : 0; return true; }
            if (op == ">=") { out = (l >= r) ? 1 : 0; return true; }
            if (op == "&&") { out = (l != 0 && r != 0) ? 1 : 0; return true; }
            if (op == "||") { out = (l != 0 || r != 0) ? 1 : 0; return true; }
            return false;
        }
        return false;
    }

    bool provablyNonNeg(Expr* e) {
        if (!e) return false;
        if (auto n = dynamic_cast<NumberExpr*>(e)) return n->value >= 0;
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            auto it = vars_.find(id->name);
            if (it == vars_.end()) return false;
            const Ival& iv = it->second.v.iv;
            return iv.st == ISt::Rng && iv.lo >= 0;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) {
            int64_t m;
            if (b->op == "&") {
                if (staticConst(b->right.get(), m) && m >= 0) return true;
                if (staticConst(b->left.get(), m) && m >= 0) return true;
                return false;
            }
            if (b->op == "+" || b->op == "*")
                return provablyNonNeg(b->left.get()) && provablyNonNeg(b->right.get());
            if (b->op == "<<") return provablyNonNeg(b->left.get());
            if (b->op == "%") {
                if (staticConst(b->right.get(), m) && m > 0)
                    return provablyNonNeg(b->left.get());
                return false;
            }
            return false;
        }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) return u->op == "!";
        return false;
    }

    // ---- expression walking ----
    Val walkExpr(Expr* e, int condMode) {
        if (!e) return valTop();
        if (auto n = dynamic_cast<NumberExpr*>(e)) return valInt(n->value);
        if (auto f = dynamic_cast<FloatExpr*>(e)) return valFloat(f->value);
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            if (id->name == "true") return valInt(1);
            if (id->name == "false") return valInt(0);
            auto it = vars_.find(id->name);
            if (it == vars_.end()) return valTop();
            return it->second.v;
        }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) {
            Val o = walkExpr(u->operand.get(), 0);
            return foldUnary(u, o);
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) return walkBinary(b, condMode);
        if (auto aa = dynamic_cast<ArrayAccessExpr*>(e)) {
            walkExpr(aa->array.get(), 0);
            Val idx = walkExpr(aa->index.get(), 0);
            checkIndex(aa->array.get(), aa->index.get(), idx);
            return valTop();
        }
        if (auto m = dynamic_cast<MemberExpr*>(e)) {
            walkExpr(m->object.get(), 0);
            return valTop();
        }
        if (auto d = dynamic_cast<DerefExpr*>(e)) {
            walkExpr(d->ptr.get(), 0);
            return valTop();
        }
        if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
            escaped_.insert(a->name);
            return valTop();
        }
        if (dynamic_cast<StringExpr*>(e)) return valTop();
        if (auto c = dynamic_cast<CallExpr*>(e)) return walkCall(c);
        return valTop();
    }

    Val walkCall(CallExpr* c) {
        std::vector<Val> av;
        if (c->receiver) walkExpr(c->receiver.get(), 0);
        for (auto& a : c->args) av.push_back(walkExpr(a.get(), 0));
        Val res = foldCall(c, av);
        killNonLocals();
        return res;
    }

    Val foldCall(CallExpr* c, const std::vector<Val>& av) {
        const std::string& n = c->name;

        // --- domain checks (ZT-BUG014) ---
        if (n == "sqrt" && av.size() == 1) {
            const Val& a = av[0];
            bool neg = (a.hasFloat && a.fv < 0) ||
                       (!a.hasFloat && a.iv.isCst() && a.iv.v() < 0);
            if (neg) report("BUG014", curLine_, "sqrt() of a negative value");
        } else if (n == "pow" && av.size() == 2) {
            const Val& b = av[0];
            const Val& ex = av[1];
            bool baseNeg = (b.hasFloat && b.fv < 0) ||
                           (!b.hasFloat && b.iv.isCst() && b.iv.v() < 0);
            bool fracExp = false;
            if (ex.hasFloat) fracExp = ex.fv != (double)(int64_t)ex.fv;
            if (baseNeg && fracExp)
                report("BUG014", curLine_,
                       "pow() of a negative base with a fractional exponent");
        } else if (n == "fmod" && av.size() == 2) {
            const Val& d = av[1];
            bool zero = (d.hasFloat && d.fv == 0.0) ||
                        (!d.hasFloat && d.iv.isCst() && d.iv.v() == 0);
            if (zero) report("BUG014", curLine_, "fmod() with a zero divisor");
        }

        // --- folds for float32-safe builtins ---
        if (n == "itof" && av.size() == 1 && av[0].iv.isCst() && !av[0].hasFloat)
            return valFloat((double)(float)av[0].iv.v());

        bool allConst = !av.empty();
        for (auto& v : av)
            if (!v.hasFloat && !v.iv.isCst()) allConst = false;
        if (!allConst || !av[0].hasFloat) return valTop();

        float x = (float)av[0].fv;
        if (n == "abs" && av.size() == 1) return valFloat((double)(x < 0 ? -x : x));
        if (n == "neg" && av.size() == 1) return valFloat((double)-x);
        if (n == "floor" && av.size() == 1) return valFloat((double)__builtin_floorf(x));
        if (n == "ceil" && av.size() == 1) return valFloat((double)__builtin_ceilf(x));
        if (n == "trunc" && av.size() == 1) return valFloat((double)__builtin_truncf(x));
        if ((n == "min" || n == "max") && av.size() == 2) {
            float y = (float)av[1].fv;
            return valFloat((double)(n == "min" ? (x < y ? x : y) : (x > y ? x : y)));
        }
        if (n == "fmod" && av.size() == 2) {
            float y = (float)av[1].fv;
            if (y == 0.0f) return valTop();
            return valFloat((double)__builtin_fmodf(x, y));
        }
        return valTop();
    }

    Val foldUnary(UnaryExpr* u, const Val& o) {
        const std::string& op = u->op;
        if (op == "-") {
            if (o.hasFloat) return valFloat((double)-(float)o.fv);
            if (o.iv.isCst()) {
                if (o.iv.v() == INT64_MIN) {
                    report("BUG011", curLine_,
                           "negating INT64_MIN overflows 64-bit int");
                    return valTop();
                }
                return valInt(-o.iv.v());
            }
            Val r;
            if (o.iv.st == ISt::Rng && o.iv.lo > INT64_MIN && o.iv.hi < INT64_MAX)
                r.iv = Ival::rng(-o.iv.hi, -o.iv.lo);
            r.typeKnown = o.typeKnown;
            r.isFloat = o.isFloat;
            return r;
        }
        if (op == "!") {
            if (o.hasFloat) return valInt((float)o.fv == 0.0f ? 1 : 0);
            if (o.iv.isCst()) return valInt(o.iv.v() == 0 ? 1 : 0);
            Val r;
            if (o.iv.st == ISt::Rng && !(o.iv.lo <= 0 && o.iv.hi >= 0))
                r.iv = Ival::cst(0);   // operand never 0 -> !x is 0
            r.typeKnown = true;
            return r;
        }
        if (op == "~") {
            if (!o.hasFloat && o.iv.isCst()) return valInt(~o.iv.v());
            Val r;
            r.typeKnown = o.typeKnown;
            r.isFloat = o.isFloat;
            return r;
        }
        return valTop();
    }

    Val walkBinary(BinaryExpr* b, int condMode) {
        const std::string& op = b->op;
        int childMode = 0;
        if (op == "&&" || op == "||")
            childMode = (condMode == 1 || condMode == 2) ? 2 : 0;
        // Whatever the operands of `||` record is an alternative, not a
        // conjunct: throw it away, or the enclosing `&&` would intersect
        // `x > 10 && (x == 3 || x == 12)` into a contradiction that the
        // expression does not have.
        size_t consAt = pendingCons_.size(), pairsAt = pendingPairs_.size();
        Val l = walkExpr(b->left.get(), childMode);
        Val r = walkExpr(b->right.get(), childMode);
        if (op == "||") {
            pendingCons_.resize(consAt);
            pendingPairs_.resize(pairsAt);
        }

        if (isCmpOp(op)) {
            Val res = foldCmp(op, l, r);
            if (checkCmpRules(b, op, l, r, res)) res.reported = true;
            if (condMode >= 1) recordConstraint(b, op, l, r);
            return res;
        }
        if (op == "&&" || op == "||") {
            Val res = foldLogic(op, l, r);
            if (op == "&&" && condMode >= 1 && !res.iv.isCst())
                checkConjunction(consAt, pairsAt);
            return res;
        }
        if (op == "%of") return foldPercent(l, r);
        if (op == "/" || op == "%" || op == "//") checkSelfDiv(b, l, r);
        return foldBin(op, l, r);
    }

    // ZT-BUG022: dividing an expression by itself is 1 (0 for the modulo) for
    // a non-zero value and a division by zero at 0.
    void checkSelfDiv(BinaryExpr* b, const Val& l, const Val& r) {
        if (l.hasFloat || r.hasFloat) return;
        if (l.iv.isCst() && r.iv.isCst()) return;   // folded silently elsewhere
        if (!pureExpr(b->left.get()) || !pureExpr(b->right.get())) return;
        std::string t = es(b->left.get());
        if (t.empty() || t == "?" || t != es(b->right.get())) return;
        const Ival& d = r.iv;   // the divisor side
        bool zeroPossible = !(d.st == ISt::Rng && !(d.lo <= 0 && d.hi >= 0));
        if (b->op == "/") {
            report("BUG022", curLine_,
                   "dividing '" + t + "' by itself is " +
                       (zeroPossible ? "1 for a non-zero value and a division "
                                       "by zero at 0"
                                     : "always 1"));
        } else {
            report("BUG022", curLine_,
                   "'" + t + " " + b->op + " " + t + "' is " +
                       (zeroPossible ? "0 for a non-zero value and a division "
                                       "by zero at 0"
                                     : "always 0"));
        }
    }

    Val foldCmp(const std::string& op, const Val& l, const Val& r) {
        Val res;
        res.typeKnown = true;
        auto cmpInt = [&](int64_t a, int64_t b) -> int64_t {
            if (op == "==") return a == b;
            if (op == "!=") return a != b;
            if (op == "<") return a < b;
            if (op == "<=") return a <= b;
            if (op == ">") return a > b;
            return a >= b;
        };
        auto cmpF = [&](float a, float b) -> int64_t {
            if (op == "==") return a == b;
            if (op == "!=") return a != b;
            if (op == "<") return a < b;
            if (op == "<=") return a <= b;
            if (op == ">") return a > b;
            return a >= b;
        };
        if (l.hasFloat || r.hasFloat) {
            float a, b;
            if (l.hasFloat && r.hasFloat) {
                a = (float)l.fv; b = (float)r.fv;
            } else if (l.hasFloat) {
                if (!r.iv.isCst()) return res;
                a = (float)l.fv; b = (float)r.iv.v();
            } else {
                if (!l.iv.isCst()) return res;
                a = (float)l.iv.v(); b = (float)r.fv;
            }
            res.iv = Ival::cst(cmpF(a, b));
            return res;
        }
        if (l.iv.isCst() && r.iv.isCst()) {
            res.iv = Ival::cst(cmpInt(l.iv.v(), r.iv.v()));
            return res;
        }
        return res;
    }

    Val foldLogic(const std::string& op, const Val& l, const Val& r) {
        Val res;
        res.typeKnown = true;
        if (l.iv.isCst() && r.iv.isCst()) {
            int a = l.iv.v() != 0, b = r.iv.v() != 0;
            res.iv = Ival::cst((op == "&&") ? (a && b) : (a || b));
            return res;
        }
        int a = l.iv.isCst() ? (l.iv.v() != 0 ? 1 : 0) : -1;
        int b = r.iv.isCst() ? (r.iv.v() != 0 ? 1 : 0) : -1;
        if (op == "&&") {
            if (a == 0) res.iv = Ival::cst(0);
            else if (a == 1 && b >= 0) res.iv = Ival::cst(b);
        } else {
            if (a == 1) res.iv = Ival::cst(1);
            else if (a == 0 && b >= 0) res.iv = Ival::cst(b);
        }
        return res;
    }

    Val foldPercent(const Val& l, const Val& r) {
        Val res;
        res.typeKnown = true;
        if (l.hasFloat || r.hasFloat) return res;
        if (l.iv.isCst() && r.iv.isCst()) {
            i128 p = (i128)l.iv.v() * (i128)r.iv.v();
            i128 q = p / 100;
            int64_t out;
            if (!clamp128(q, out)) {
                report("BUG011", curLine_,
                       "percent-of expression overflows 64-bit int");
                return valTop();
            }
            res.iv = Ival::cst(out);
            return res;
        }
        if (l.iv.isCst()) {
            Ival m;
            iMul(Ival::cst(l.iv.v()), r.iv, m);
            iDiv(m, Ival::cst(100), res.iv);
        } else if (r.iv.isCst()) {
            Ival m;
            iMul(l.iv, Ival::cst(r.iv.v()), m);
            iDiv(m, Ival::cst(100), res.iv);
        }
        return res;
    }

    Val foldBin(const std::string& op, const Val& l, const Val& r) {
        Val res;
        res.typeKnown = true;
        bool useFloat = l.hasFloat || r.hasFloat;

        // --- division family checks ---
        if (op == "/" || op == "%" || op == "//") {
            if (r.hasFloat) {
                if (op == "/" && r.fv == 0.0) {
                    report("BUG006", curLine_, "division by zero");
                    return valTop();
                }
            } else if (r.iv.isCst() && r.iv.v() == 0) {
                report("BUG006", curLine_,
                       op == "/" ? "division by zero" : "modulo by zero");
                return valTop();
            }
            if (!useFloat && l.iv.isCst() && r.iv.isCst() &&
                l.iv.v() == INT64_MIN && r.iv.v() == -1) {
                report("BUG011", curLine_,
                       "INT64_MIN / -1 overflows 64-bit int");
                return valTop();
            }
        }

        // --- shift amount check ---
        if ((op == "<<" || op == ">>") && r.iv.isCst() && !r.hasFloat) {
            int64_t k = r.iv.v();
            if (k < 0 || k > 63) {
                report("BUG011", curLine_,
                       "shift amount " + std::to_string(k) +
                       " is out of range [0, 64)");
                return valTop();
            }
        }

        // --- constant fold with overflow detection ---
        if (!useFloat && l.iv.isCst() && r.iv.isCst()) {
            int64_t a = l.iv.v(), b = r.iv.v();
            if (op == "+" || op == "-" || op == "*") {
                i128 t = 0;
                const char* what = "arithmetic";
                if (op == "+") { t = (i128)a + b; what = "addition"; }
                else if (op == "-") { t = (i128)a - b; what = "subtraction"; }
                else { t = (i128)a * b; what = "multiplication"; }
                int64_t o;
                if (!clamp128(t, o)) {
                    report("BUG011", curLine_,
                           std::string("constant ") + what +
                           " overflows 64-bit int");
                    return valTop();
                }
                res.iv = Ival::cst(o);
                return res;
            }
            if (op == "/") {
                if (b != 0) res.iv = Ival::cst(a / b);
                return res;
            }
            if (op == "%" || op == "//") {
                if (b != 0) res.iv = Ival::cst(a % b);
                return res;
            }
            if (op == "&") { res.iv = Ival::cst(a & b); return res; }
            if (op == "|") { res.iv = Ival::cst(a | b); return res; }
            if (op == "^") { res.iv = Ival::cst(a ^ b); return res; }
            if (op == "<<") { res.iv = Ival::cst(wrapShl(a, (int)b)); return res; }
            if (op == ">>") { res.iv = Ival::cst(wrapShr(a, (int)b)); return res; }
            return res;
        }

        // --- float32 fold ---
        if (useFloat) {
            if (op == "+" || op == "-" || op == "*" || op == "/") {
                float a, b;
                bool ok = true;
                if (l.hasFloat && r.hasFloat) {
                    a = (float)l.fv; b = (float)r.fv;
                } else if (l.hasFloat) {
                    if (!r.iv.isCst()) ok = false;
                    a = (float)l.fv; b = (float)r.iv.v();
                } else {
                    if (!l.iv.isCst()) ok = false;
                    a = (float)l.iv.v(); b = (float)r.fv;
                }
                if (ok) {
                    if (op == "/" && b == 0.0f) return res;
                    float c = 0.0f;
                    if (op == "+") c = a + b;
                    else if (op == "-") c = a - b;
                    else if (op == "*") c = a * b;
                    else c = a / b;
                    return valFloat((double)c);
                }
            }
            return res;
        }

        // --- interval arithmetic ---
        Ival o;
        if (op == "+") iAdd(l.iv, r.iv, o);
        else if (op == "-") iSub(l.iv, r.iv, o);
        else if (op == "*") iMul(l.iv, r.iv, o);
        else if (op == "/") iDiv(l.iv, r.iv, o);
        else if (op == "%" || op == "//") iMod(l.iv, r.iv, o);
        else if (op == "&") iAnd(l.iv, r.iv, o);
        else if (op == "|") iOr(l.iv, r.iv, o);
        else if (op == "^") iXor(l.iv, r.iv, o);
        else if (op == "<<") iShl(l.iv, r.iv, o);
        else if (op == ">>") iShr(l.iv, r.iv, o);
        else return res;
        res.iv = o;
        return res;
    }

    // ---------------- comparison rules ----------------
    bool checkCmpRules(BinaryExpr* b, const std::string& op,
                       const Val& l, const Val& r, Val& res) {
        bool reported = false;
        bool eq = op == "==", ne = op == "!=";
        Expr* L = b->left.get();
        Expr* R = b->right.get();

        // ZT-BUG012: int vs non-integral float constant
        if (eq || ne) {
            const Val* iv = nullptr;
            const Val* fv = nullptr;
            if (l.typeKnown && !l.isFloat && !l.hasFloat && !l.iv.isCst() &&
                r.typeKnown && r.isFloat && r.hasFloat) {
                iv = &l; fv = &r;
            } else if (r.typeKnown && !r.isFloat && !r.hasFloat && !r.iv.isCst() &&
                       l.typeKnown && l.isFloat && l.hasFloat) {
                iv = &r; fv = &l;
            }
            if (iv && fv && fv->fv != (double)(int64_t)fv->fv) {
                report("BUG012", curLine_,
                       std::string("comparing int with non-integral float constant ") +
                       fmtF(fv->fv) + (eq ? ": always false" : ": always true"));
                reported = true;
            }
        }

        // ZT-BUG013: double vs float32 rounding changes the result
        if ((eq || ne) && l.hasFloat && r.hasFloat) {
            bool plainL = dynamic_cast<FloatExpr*>(L) != nullptr;
            bool plainR = dynamic_cast<FloatExpr*>(R) != nullptr;
            if (!plainL || !plainR) {
                bool d = (l.fv == r.fv);
                bool f = ((float)l.fv == (float)r.fv);
                if (d != f) {
                    report("BUG013", curLine_,
                           "comparison result differs between double and float32 "
                           "evaluation (" + fmtF(l.fv) + (eq ? " == " : " != ") +
                           fmtF(r.fv) + ")");
                    reported = true;
                }
            }
        }

        if (!res.iv.isCst()) {
            // ZT-BUG004: self-comparison
            if (l.typeKnown && !l.isFloat && r.typeKnown && !r.isFloat &&
                pureExpr(L) && pureExpr(R) && es(L) == es(R) &&
                !es(L).empty() && es(L) != "?") {
                std::string what = (op == "!=" || op == "<" || op == ">")
                                       ? "always false" : "always true";
                report("BUG004", curLine_,
                       "self-comparison '" + es(L) + " " + op + " " + es(R) +
                       "' is " + what);
                reported = true;
            }

            // ZT-BUG005: equalities that can never hold
            if (eq || ne) reported = reported || checkImpossibleEq(b, op, L, R, l, r);

            // ZT-BUG010: (x % 2) == 1 without a non-negative proof
            if (eq || ne) reported = reported || checkOddMod(L, R, l, r);

            // ZT-BUG016: both sides have a known range, so one arm of the
            // branch is dead. Masks and modulos count here: foldBin tracks
            // `(x & 15)` as [0, 15] and `(x % 10)` as [-9, 9].
            if (!reported && !l.hasFloat && !r.hasFloat &&
                l.iv.st == ISt::Rng && r.iv.st == ISt::Rng &&
                !(l.iv.isCst() && r.iv.isCst())) {
                const Ival& A = l.iv;
                const Ival& B = r.iv;
                bool t = false, f = false;
                if (op == "<")       { t = A.hi <  B.lo; f = A.lo >= B.hi; }
                else if (op == "<=") { t = A.hi <= B.lo; f = A.lo >  B.hi; }
                else if (op == ">")  { t = A.lo >  B.hi; f = A.hi <= B.lo; }
                else if (op == ">=") { t = A.lo >= B.hi; f = A.hi <  B.lo; }
                else if (eq)         { f = A.hi < B.lo || B.hi < A.lo; }
                else if (ne)         { t = A.hi < B.lo || B.hi < A.lo; }
                // An always-true verdict on a while-condition is only stable
                // when the body cannot change what it reads (same gate as
                // BUG002); always-false means the body never runs at all.
                if (f || (t && !condVarsMutable_)) {
                    report("BUG016", curLine_,
                           "comparison '" + es(L) + " " + op + " " + es(R) +
                               "' is always " + (t ? "true" : "false") +
                               " (ranges [" + std::to_string(A.lo) + ", " +
                               std::to_string(A.hi) + "] vs [" +
                               std::to_string(B.lo) + ", " +
                               std::to_string(B.hi) + "])");
                    reported = true;
                }
            }

            // ZT-BUG017: a comparison used as an operand of another one.
            // `0 <= i < n` evaluates as `(0 <= i) < n`, i.e. 0/1 < n — the
            // right half of the intended range test never runs.
            if (!reported) {
                Expr* nested = nullptr;
                auto nl = dynamic_cast<BinaryExpr*>(L);
                auto nr = dynamic_cast<BinaryExpr*>(R);
                if (nl && isCmpOp(nl->op) && !nl->parenthesized) nested = L;
                else if (nr && isCmpOp(nr->op) && !nr->parenthesized)
                    nested = R;
                if (nested) {
                    report("BUG017", curLine_,
                           "chained comparison '" + es(L) + " " + op + " " +
                               es(R) + "': the nested comparison yields 0/1, "
                               "did you mean && ?");
                    reported = true;
                }
            }

            // ZT-BUG021: a float compared with itself. `a != a` is the
            // accepted NaN test and stays quiet; every other operator is a
            // mistake (or a NaN trap the author did not have in mind).
            if (!reported && op != "!=") {
                bool flt = l.hasFloat || r.hasFloat ||
                           (l.typeKnown && l.isFloat) ||
                           (r.typeKnown && r.isFloat);
                if (flt && pureExpr(L) && pureExpr(R) && es(L) == es(R) &&
                    !es(L).empty() && es(L) != "?") {
                    std::string why = (op == "<" || op == ">")
                                          ? "is always false"
                                          : "is false when " + es(L) +
                                                " is NaN";
                    report("BUG021", curLine_,
                           "self-comparison '" + es(L) + " " + op + " " +
                               es(R) + "' " + why);
                    reported = true;
                }
            }
        }
        return reported;
    }

    // one side: <expr> * K / & M / % M with a constant, other side constant C
    bool checkImpossibleEq(BinaryExpr* b, const std::string& op,
                           Expr* L, Expr* R, const Val& l, const Val& r) {
        (void)b;
        bool eq = op == "==";
        int64_t C = 0;
        Expr* inner = nullptr;
        if (l.isIntConst() && dynamic_cast<BinaryExpr*>(R)) {
            C = l.iv.v(); inner = R;
        } else if (r.isIntConst() && dynamic_cast<BinaryExpr*>(L)) {
            C = r.iv.v(); inner = L;
        } else {
            return false;
        }
        auto ib = dynamic_cast<BinaryExpr*>(inner);
        if (!ib) return false;

        auto fail = [&](const std::string& why) {
            report("BUG005", curLine_,
                   std::string(eq ? "equality can never hold: "
                                  : "inequality is always true: ") +
                   es(inner) + " " + op + " " + std::to_string(C) +
                   " (" + why + ")");
            return true;
        };

        if (ib->op == "*") {
            int64_t K;
            if (!staticConst(ib->left.get(), K) &&
                !staticConst(ib->right.get(), K))
                return false;
            if (K == 0) {
                if (C != 0) return fail("0 * x is always 0");
                return false;
            }
            int t = ctz64(K);
            if (t > 0 && t < 64) {
                uint64_t mask = (1ull << t) - 1;
                if (((uint64_t)C & mask) != 0)
                    return fail(std::to_string(C) + " is not a multiple of " +
                                std::to_string(K));
            }
            return false;
        }
        if (ib->op == "&") {
            int64_t M;
            if (!staticConst(ib->right.get(), M) &&
                !staticConst(ib->left.get(), M))
                return false;
            if (((uint64_t)C & ~(uint64_t)M) != 0)
                return fail("bits outside mask " + std::to_string(M) +
                            " can never be set");
            return false;
        }
        if (ib->op == "%" || ib->op == "//") {
            int64_t M;
            if (!staticConst(ib->right.get(), M) || M == 0) return false;
            i128 am = (M < 0) ? -(i128)M : (i128)M;
            i128 lo = -(am - 1), hi = am - 1;
            if ((i128)C < lo || (i128)C > hi)
                return fail("result of % " + std::to_string(M) +
                            " is within [" + std::to_string((int64_t)lo) +
                            ", " + std::to_string((int64_t)hi) + "]");
            return false;
        }
        return false;
    }

    bool isOddModExpr(Expr* e) {
        auto b = dynamic_cast<BinaryExpr*>(e);
        if (!b) return false;
        if (b->op != "%" && b->op != "//") return false;
        int64_t m;
        if (!staticConst(b->right.get(), m)) return false;
        return m == 2;
    }

    bool checkOddMod(Expr* L, Expr* R, const Val& l, const Val& r) {
        Expr* modSide = nullptr;
        if (isOddModExpr(L) && r.isIntConst() && r.iv.v() == 1) modSide = L;
        else if (isOddModExpr(R) && l.isIntConst() && l.iv.v() == 1) modSide = R;
        if (!modSide) return false;
        auto mb = dynamic_cast<BinaryExpr*>(modSide);
        if (!mb) return false;
        auto id = dynamic_cast<IdentExpr*>(mb->left.get());
        if (!id) return false;
        auto it = vars_.find(id->name);
        if (it == vars_.end()) return false;
        const Ival& iv = it->second.v.iv;
        if (iv.isCst()) return false;                  // constant folds elsewhere
        if (iv.st == ISt::Rng && iv.lo >= 0) return false;  // proven non-negative
        report("BUG010", curLine_,
               "'" + es(id) + " % 2' compared with 1 may be wrong for negative "
               "values (the remainder is -1 there)");
        return true;
    }

    // ---------------- constraint tracking for && ----------------
    Ival rangeForOp(const std::string& o, int64_t C) {
        if (o == "==") return Ival::cst(C);
        if (o == "<") {
            if (C == INT64_MIN) return Ival::bot();
            return Ival::rng(INT64_MIN, C - 1);
        }
        if (o == "<=") return Ival::rng(INT64_MIN, C);
        if (o == ">") {
            if (C == INT64_MAX) return Ival::bot();
            return Ival::rng(C + 1, INT64_MAX);
        }
        if (o == ">=") return Ival::rng(C, INT64_MAX);
        return Ival::top();   // != has no interval form
    }

    void recordConstraint(BinaryExpr* b, const std::string& op,
                          const Val& l, const Val& r) {
        // Both sides pure: remember the relation itself (BUG020), whatever
        // the operands look like — this is what catches `a < b && b < a`.
        if (pureExpr(b->left.get()) && pureExpr(b->right.get())) {
            std::string la = es(b->left.get()), ra = es(b->right.get());
            if (!la.empty() && la != "?" && !ra.empty() && ra != "?")
                pendingPairs_.push_back({la, op, ra});
        }

        Expr* varSide = nullptr;
        int64_t C = 0;
        bool flip = false;
        auto lid = dynamic_cast<IdentExpr*>(b->left.get());
        auto rid = dynamic_cast<IdentExpr*>(b->right.get());
        if (lid && r.isIntConst() && !r.hasFloat) {
            varSide = lid; C = r.iv.v();
        } else if (rid && l.isIntConst() && !l.hasFloat) {
            varSide = rid; C = l.iv.v(); flip = true;
        } else {
            return;
        }
        auto it = vars_.find(static_cast<IdentExpr*>(varSide)->name);
        if (it != vars_.end() && it->second.v.typeKnown && it->second.v.isFloat)
            return;   // float vars are not narrowed with int ranges
        const std::string& o = flip ? negOp(op) : op;
        Ival range = rangeForOp(o, C);
        if (range.isTop()) return;
        pendingCons_.push_back({es(varSide), range});
    }

    // Two relations on the same ordered pair of expressions that cannot both
    // hold. `!=` never contradicts an order relation (the domain has at least
    // two values), and the table stays valid for floats too: NaN simply makes
    // every comparison false, so the conjunction is still never true.
    static bool cmpPairUnsat(std::string x, std::string y) {
        if (x == "==") return y != "==";
        if (y == "==") return x != "==";
        if (x == "!=" || y == "!=") return false;
        bool xl = (x == "<" || x == "<="), yl = (y == "<" || y == "<=");
        bool xg = (x == ">" || x == ">="), yg = (y == ">" || y == ">=");
        return (xl && yg) || (xg && yl);
    }

    bool pairContradict(const CmpPair& p, const CmpPair& q) {
        std::string x = p.op, y;
        if (p.a == q.a && p.b == q.b) {
            y = q.op;
        } else if (p.a == q.b && p.b == q.a) {
            y = swapOp(q.op);   // q reads the pair the other way round
        } else {
            return false;
        }
        return cmpPairUnsat(x, y);
    }

    // Only the constraints added inside this `&&` node count: an operand of
    // an enclosing `||` is not part of the conjunction.
    void checkConjunction(size_t fromCons, size_t fromPairs) {
        std::unordered_map<std::string, Ival> acc;
        for (size_t i = fromCons; i < pendingCons_.size(); i++) {
            auto& p = pendingCons_[i];
            auto it = acc.find(p.first);
            if (it == acc.end()) acc[p.first] = p.second;
            else it->second = iInt(it->second, p.second);
        }
        for (auto& kv : acc) {
            if (kv.second.isBot())
                report("BUG003", curLine_,
                       "impossible conjunction: '" + kv.first +
                       "' cannot satisfy every comparison");
        }
        for (size_t i = fromPairs; i < pendingPairs_.size(); i++)
            for (size_t j = i + 1; j < pendingPairs_.size(); j++)
                if (pairContradict(pendingPairs_[i], pendingPairs_[j]))
                    report("BUG020", curLine_,
                           "impossible conjunction: '" +
                               pendingPairs_[i].a + " " + pendingPairs_[i].op +
                               " " + pendingPairs_[i].b + "' and '" +
                               pendingPairs_[j].a + " " + pendingPairs_[j].op +
                               " " + pendingPairs_[j].b +
                               "' can never both hold");
    }

    // ---------------- conditions ----------------
    Val checkCondition(Expr* cond) {
        pendingCons_.clear();
        pendingPairs_.clear();
        Val v = walkExpr(cond, 1);
        pendingCons_.clear();
        pendingPairs_.clear();
        if (v.iv.isCst() && !v.reported) {
            bool plain = dynamic_cast<NumberExpr*>(cond) != nullptr ||
                         dynamic_cast<FloatExpr*>(cond) != nullptr;
            if (v.iv.v() == 0)
                report("BUG001", curLine_, "condition is always false");
            else if (!plain && !condVarsMutable_)
                report("BUG002", curLine_, "condition is always true");
        }
        return v;
    }

    // returns false when the narrowed branch is unreachable
    bool narrow(Expr* cond, bool wantTrue) {
        if (!cond) return true;
        if (auto u = dynamic_cast<UnaryExpr*>(cond)) {
            if (u->op == "!") return narrow(u->operand.get(), !wantTrue);
            return true;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(cond)) {
            if (b->op == "&&") {
                if (wantTrue)
                    return narrow(b->left.get(), true) && narrow(b->right.get(), true);
                return true;
            }
            if (b->op == "||") {
                if (!wantTrue)
                    return narrow(b->left.get(), false) && narrow(b->right.get(), false);
                return true;
            }
            if (!isCmpOp(b->op)) return true;
            std::string op = wantTrue ? b->op : negOp(b->op);
            auto lid = dynamic_cast<IdentExpr*>(b->left.get());
            auto rid = dynamic_cast<IdentExpr*>(b->right.get());
            std::string name;
            int64_t C = 0;
            bool flip = false;
            if (lid && rhsIsIntConst(b->right.get(), C)) {
                name = lid->name;
            } else if (rid && rhsIsIntConst(b->left.get(), C)) {
                name = rid->name;
                flip = true;
            } else {
                return true;
            }
            if (flip) op = negOp(op);
            auto it = vars_.find(name);
            if (it == vars_.end()) return true;
            if (it->second.v.typeKnown && it->second.v.isFloat) return true;
            Ival range = rangeForOp(op, C);
            if (range.isTop()) return true;
            Ival nv = iInt(it->second.v.iv, range);
            if (nv.isBot()) return false;
            if (nv.isTop()) return true;
            Val v = it->second.v;
            v.iv = nv;
            setVal(name, v);
            return true;
        }
        return true;
    }

    bool rhsIsIntConst(Expr* e, int64_t& out) {
        if (auto n = dynamic_cast<NumberExpr*>(e)) { out = n->value; return true; }
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            auto it = vars_.find(id->name);
            if (it != vars_.end() && it->second.v.isIntConst()) {
                out = it->second.v.iv.v();
                return true;
            }
        }
        return false;
    }

    // ---------------- index checks ----------------
    void checkIndex(Expr* arrE, Expr* idxE, const Val& idx) {
        auto id = dynamic_cast<IdentExpr*>(arrE);
        if (!id) return;
        checkIndexByName(id->name, es(arrE), idxE, idx);
    }

    void checkIndexByName(const std::string& name, const std::string& arrText,
                          Expr* idxE, const Val& idx) {
        auto it = vars_.find(name);
        if (it == vars_.end()) return;
        int size = it->second.arraySize;
        if (size <= 0) return;

        if (auto ib = dynamic_cast<BinaryExpr*>(idxE)) {
            int64_t M;
            if (ib->op == "&" &&
                (staticConst(ib->right.get(), M) || staticConst(ib->left.get(), M))) {
                if (M >= (int64_t)size) {
                    report("BUG009", curLine_,
                           "array index '" + arrText + "' masked with " +
                           std::to_string(M) + " can reach " +
                           std::to_string(M) + ", outside [0, " +
                           std::to_string(size) + ")");
                    return;
                }
            } else if ((ib->op == "%" || ib->op == "//") &&
                       staticConst(ib->right.get(), M) && M != 0) {
                i128 am = (M < 0) ? -(i128)M : (i128)M;
                bool nonNeg = provablyNonNeg(ib->left.get());
                if (am > (i128)size || !nonNeg) {
                    report("BUG009", curLine_,
                           "array index '" + arrText + "' computed with '%" +
                           std::to_string(M) + "' may leave [0, " +
                           std::to_string(size) + ")");
                    return;
                }
            }
        }

        if (idx.iv.isCst()) {
            int64_t v = idx.iv.v();
            if (v < 0 || v >= (int64_t)size) {
                report("BUG007", curLine_,
                       "array index " + std::to_string(v) +
                       " is out of range [0, " + std::to_string(size) + ")");
            }
            return;
        }
        if (idx.iv.st == ISt::Rng) {
            if (idx.iv.lo < 0 || idx.iv.hi >= (int64_t)size) {
                report("BUG008", curLine_,
                       "array index may be out of range [0, " +
                       std::to_string(size) + ") (range [" +
                       std::to_string(idx.iv.lo) + ", " +
                       std::to_string(idx.iv.hi) + "])");
            }
        }
    }

    // ---------------- statements ----------------
    void walkBlock(const std::vector<std::unique_ptr<Stmt>>& stmts, bool frame) {
        if (frame) pushFrame();
        for (auto& st : stmts) {
            if (unreachable_) break;
            walkStmt(st.get());
        }
        if (frame) popFrame();
    }

    void walkStmt(Stmt* s) {
        if (!s || unreachable_) return;
        if (s->line > 0) curLine_ = s->line;

        if (auto vd = dynamic_cast<VarDecl*>(s)) {
            walkVarDecl(vd);
            return;
        }

        if (auto as = dynamic_cast<AssignStmt*>(s)) {
            walkAssign(as);
            return;
        }

        if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
            walkExpr(pa->ptr.get(), 0);
            walkExpr(pa->value.get(), 0);
            killNonLocals();
            return;
        }

        if (auto ex = dynamic_cast<ExprStmt*>(s)) {
            walkExpr(ex->expr.get(), 0);
            return;
        }

        if (auto rs = dynamic_cast<ReturnStmt*>(s)) {
            if (rs->value) walkExpr(rs->value.get(), 0);
            unreachable_ = true;
            return;
        }

        if (dynamic_cast<BreakStmt*>(s) || dynamic_cast<ContinueStmt*>(s)) {
            unreachable_ = true;
            return;
        }

        if (dynamic_cast<AsmStmt*>(s)) {
            killAllValues();
            return;
        }

        if (auto is = dynamic_cast<IfStmt*>(s)) { walkIf(is); return; }
        if (auto ws = dynamic_cast<WhileStmt*>(s)) { walkWhile(ws); return; }
        if (auto ls = dynamic_cast<LoopStmt*>(s)) { walkLoop(ls); return; }
        if (auto fs = dynamic_cast<ForStmt*>(s)) { walkFor(fs); return; }
        if (auto sw = dynamic_cast<SwitchStmt*>(s)) { walkSwitch(sw); return; }
    }

    void walkVarDecl(VarDecl* vd) {
        Val v;
        if (vd->init) v = walkExpr(vd->init.get(), 0);
        if (vd->type.kind == TypeKind::Float) v = toFloatVal(v);
        VarInfo vi;
        vi.isConst = vd->isConst;
        vi.isGlobal = inGlobals_;
        vi.arraySize = vd->arraySize;
        if (vd->arraySize > 0) {
            v = Val();
        } else {
            if (vd->isConst && !(v.hasFloat || v.iv.isCst())) v = Val();
            if (!v.typeKnown) {
                v.typeKnown = (vd->type.kind == TypeKind::Int ||
                               vd->type.kind == TypeKind::Bool ||
                               vd->type.kind == TypeKind::Float);
                v.isFloat = (vd->type.kind == TypeKind::Float);
            }
        }
        vi.v = v;
        setVar(vd->name, vi);
    }

    void walkAssign(AssignStmt* as) {
        Val v;
        if (as->value) v = walkExpr(as->value.get(), 0);
        if (as->indexExpr) {
            Val idx = walkExpr(as->indexExpr.get(), 0);
            checkIndexByName(as->name, as->name, as->indexExpr.get(), idx);
        }
        auto it = vars_.find(as->name);
        if (as->memberPath.empty() && !as->indexExpr) {
            VarInfo vi = (it != vars_.end()) ? it->second : VarInfo();
            if (vi.v.typeKnown && vi.v.isFloat) {
                v = toFloatVal(v);
            } else if (it != vars_.end() && it->second.v.typeKnown) {
                v.typeKnown = true;
                v.isFloat = false;
            } else if (it == vars_.end() && inGlobals_) {
                vi.isGlobal = true;
            }
            vi.v = v;
            setVar(as->name, vi);
        } else {
            killName(as->name);
        }
    }

    void walkIf(IfStmt* is) {
        Val cv = checkCondition(is->condition.get());
        bool constTrue = cv.iv.isCst() && cv.iv.v() != 0;
        bool constFalse = cv.iv.isCst() && cv.iv.v() == 0;

        auto pre = vars_;
        std::vector<std::string> baseKeys;
        baseKeys.reserve(pre.size());
        for (auto& kv : pre) baseKeys.push_back(kv.first);

        // then branch
        bool thenDead = constFalse;
        bool thenUnreach = true;
        std::unordered_map<std::string, VarInfo> thenState;
        pushFrame();
        if (!thenDead) {
            unreachable_ = false;
            if (narrow(is->condition.get(), true)) {
                walkBlock(is->thenBlock.stmts, false);
                thenUnreach = unreachable_;
            } else {
                thenDead = true;
            }
        }
        thenState = vars_;
        popFrame();

        // else branch
        bool hasElse = !is->elseBlock.stmts.empty();
        bool elseDead = constTrue;
        bool elseUnreach = true;
        std::unordered_map<std::string, VarInfo> elseState;
        pushFrame();
        if (hasElse && !elseDead) {
            unreachable_ = false;
            if (narrow(is->condition.get(), false)) {
                walkBlock(is->elseBlock.stmts, false);
                elseUnreach = unreachable_;
            } else {
                elseDead = true;
            }
        }
        elseState = vars_;
        popFrame();

        // join: only states that actually reach the code after the if
        std::unordered_map<std::string, Val> acc;
        if (!hasElse) {
            for (auto& k : baseKeys) acc[k] = pre.at(k).v;  // implicit else
        }
        auto contribute = [&](const std::unordered_map<std::string, VarInfo>& st) {
            for (auto& k : baseKeys) {
                auto it = st.find(k);
                Val v = (it != st.end()) ? it->second.v : pre.at(k).v;
                auto a = acc.find(k);
                if (a == acc.end()) acc[k] = v;
                else a->second = mergeVal(a->second, v);
            }
        };
        if (!thenDead && !thenUnreach) contribute(thenState);
        if (hasElse && !elseDead && !elseUnreach) contribute(elseState);
        for (auto& kv : acc) {
            auto it = vars_.find(kv.first);
            if (it != vars_.end()) it->second.v = kv.second;
        }

        bool thenGoes = thenDead || thenUnreach;
        if (hasElse) {
            bool elseGoes = elseDead || elseUnreach;
            unreachable_ = thenGoes && elseGoes;
        } else {
            unreachable_ = false;  // the implicit else always reaches here
        }
    }

    // Names a condition expression reads (used for the while-entry
    // mutability test: if the body rewrites any of them, the condition's
    // entry-facts verdict is not stable across iterations).
    void collectReadVars(Expr* e, std::unordered_set<std::string>& out) {
        if (!e) return;
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            out.insert(id->name);
            return;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) {
            collectReadVars(b->left.get(), out);
            collectReadVars(b->right.get(), out);
            return;
        }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) {
            collectReadVars(u->operand.get(), out);
            return;
        }
        if (auto aa = dynamic_cast<ArrayAccessExpr*>(e)) {
            collectReadVars(aa->array.get(), out);
            collectReadVars(aa->index.get(), out);
            return;
        }
        if (auto me = dynamic_cast<MemberExpr*>(e)) {
            collectReadVars(me->object.get(), out);
            return;
        }
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            if (c->receiver) collectReadVars(c->receiver.get(), out);
            for (auto& a : c->args) collectReadVars(a.get(), out);
            return;
        }
        if (auto d = dynamic_cast<DerefExpr*>(e)) {
            collectReadVars(d->ptr.get(), out);
            return;
        }
        if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
            out.insert(a->name);
            return;
        }
    }

    // ---------------- while-loop termination (ZT-BUG018 / ZT-BUG019) -----
    bool blockEscapes(const Block& b) {
        for (auto& sp : b.stmts)
            if (stmtEscapes(sp.get())) return true;
        return false;
    }

    // break/continue/return anywhere below: the loop may leave without the
    // condition ever turning false. A break that belongs to a nested loop
    // disqualifies us too — losing a report is fine, a false one is not.
    bool stmtEscapes(Stmt* s) {
        if (!s) return false;
        if (dynamic_cast<BreakStmt*>(s) || dynamic_cast<ContinueStmt*>(s) ||
            dynamic_cast<ReturnStmt*>(s))
            return true;
        if (auto is = dynamic_cast<IfStmt*>(s))
            return blockEscapes(is->thenBlock) || blockEscapes(is->elseBlock);
        if (auto ws = dynamic_cast<WhileStmt*>(s)) return blockEscapes(ws->body);
        if (auto ls = dynamic_cast<LoopStmt*>(s)) return blockEscapes(ls->body);
        if (auto fs = dynamic_cast<ForStmt*>(s)) return blockEscapes(fs->body);
        if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
            for (auto& sc : sw->cases)
                if (blockEscapes(sc.body)) return true;
        }
        return false;
    }

    // Every place `var` is written, at any depth (a shadowing declaration
    // counts too: it would mean the top-level write is not the one we found).
    void countWrites(const std::vector<std::unique_ptr<Stmt>>& stmts,
                     const std::string& var, int& n) {
        for (auto& sp : stmts) {
            Stmt* s = sp.get();
            if (!s) continue;
            if (auto as = dynamic_cast<AssignStmt*>(s)) {
                if (as->name == var) n++;
            } else if (auto vd = dynamic_cast<VarDecl*>(s)) {
                if (vd->name == var) n++;
            } else if (auto is = dynamic_cast<IfStmt*>(s)) {
                countWrites(is->thenBlock.stmts, var, n);
                countWrites(is->elseBlock.stmts, var, n);
            } else if (auto ws = dynamic_cast<WhileStmt*>(s)) {
                countWrites(ws->body.stmts, var, n);
            } else if (auto ls = dynamic_cast<LoopStmt*>(s)) {
                countWrites(ls->body.stmts, var, n);
            } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
                if (fs->varName == var) n++;
                countWrites(fs->body.stmts, var, n);
            } else if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
                for (auto& sc : sw->cases) countWrites(sc.body.stmts, var, n);
            }
        }
    }

    // The loop's only write to `var` is a top-level `var = var ± K`, with a K
    // the body never rewrites. Returns the delta per iteration.
    bool loopStep(const Block& body, const std::string& var, const ModInfo& mod,
                  int64_t& k) {
        int n = 0;
        countWrites(body.stmts, var, n);
        if (n != 1) return false;
        for (auto& sp : body.stmts) {
            auto as = dynamic_cast<AssignStmt*>(sp.get());
            if (!as || as->name != var) continue;
            if (!as->memberPath.empty() || as->indexExpr) return false;
            auto bin = dynamic_cast<BinaryExpr*>(as->value.get());
            if (!bin || (bin->op != "+" && bin->op != "-")) return false;
            Expr* rest = nullptr;
            if (auto id = dynamic_cast<IdentExpr*>(bin->left.get())) {
                if (id->name != var) return false;
                rest = bin->right.get();
            } else if (auto id = dynamic_cast<IdentExpr*>(bin->right.get())) {
                // `K - var` flips the direction every iteration: no fixed step
                if (id->name != var || bin->op != "+") return false;
                rest = bin->left.get();
            } else {
                return false;
            }
            int64_t C;
            if (!staticConst(rest, C)) return false;
            std::unordered_set<std::string> reads;
            collectReadVars(rest, reads);
            for (auto& nm : reads)
                if (mod.names.count(nm)) return false;
            k = (bin->op == "+") ? C : -C;
            return true;
        }
        return false;
    }

    bool varIntConst(const std::string& nm, int64_t& out) {
        auto it = vars_.find(nm);
        if (it == vars_.end()) return false;
        if (!it->second.v.isIntConst()) return false;
        out = it->second.v.iv.v();
        return true;
    }

    void checkLoopTermination(WhileStmt* ws, const ModInfo& mod, const Val& cv) {
        auto cb = dynamic_cast<BinaryExpr*>(ws->condition.get());
        if (!cb || !isCmpOp(cb->op)) return;

        std::string var;
        Expr* other = nullptr;
        bool flip = false;
        if (auto id = dynamic_cast<IdentExpr*>(cb->left.get())) {
            var = id->name;
            other = cb->right.get();
        } else if (auto id = dynamic_cast<IdentExpr*>(cb->right.get())) {
            var = id->name;
            other = cb->left.get();
            flip = true;
        } else {
            return;
        }
        std::string op = flip ? swapOp(cb->op) : cb->op;   // var op other

        // The bound has to stay put while the loop runs.
        if (!pureExpr(other)) return;
        std::unordered_set<std::string> reads;
        collectReadVars(other, reads);
        for (auto& r : reads)
            if (mod.names.count(r)) return;
        if (mod.nonLocal) {
            // A call in the body can rewrite anything the caller does not own.
            auto unstable = [&](const std::string& nm) {
                auto it = vars_.find(nm);
                if (it == vars_.end()) return false;
                return it->second.isGlobal || it->second.arraySize > 0 ||
                       escaped_.count(nm) > 0;
            };
            if (unstable(var)) return;
            for (auto& r : reads)
                if (unstable(r)) return;
        }

        if (blockEscapes(ws->body)) return;
        int64_t k;
        if (!loopStep(ws->body, var, mod, k)) return;
        if (cv.iv.isCst() && cv.iv.v() == 0) return;   // the body never runs

        std::string bound = es(other);
        if (op == "<" || op == "<=") {
            if (k > 0) return;
            report("BUG018", curLine_,
                   "while-loop never finishes: '" + var + " " + op + " " +
                       bound + "' with step " + std::to_string(k) +
                       (k == 0 ? " never changes the counter"
                               : " moves the counter away from the bound"));
        } else if (op == ">" || op == ">=") {
            if (k < 0) return;
            report("BUG018", curLine_,
                   "while-loop never finishes: '" + var + " " + op + " " +
                       bound + "' with step " + std::to_string(k) +
                       (k == 0 ? " never changes the counter"
                               : " moves the counter away from the bound"));
        } else if (op == "!=") {
            int64_t i0, lim;
            if (!varIntConst(var, i0)) return;
            if (!staticConst(other, lim)) return;
            if (i0 == lim) return;   // the condition is false right away
            bool dirOk = (k > 0) ? (lim > i0) : (lim < i0);
            bool hit = k != 0 && ((i128)lim - (i128)i0) % (i128)k == 0;
            if (k == 0 || !dirOk || !hit)
                report("BUG019", curLine_,
                       "while-loop never finishes: '" + var + " != " +
                           std::to_string(lim) + "' is never reached from " +
                           std::to_string(i0) + " with step " +
                           std::to_string(k));
        }
    }

    void walkWhile(WhileStmt* ws) {
        ModInfo mod = collectMod(ws->body);

        // Entry facts alone cannot prove "always true" when the body rewrites
        // what the condition reads — the next iteration sees new values. An
        // always-FALSE entry condition is stable (the body never runs), so
        // only BUG002 is gated, by condVarsMutable_.
        std::unordered_set<std::string> reads;
        collectReadVars(ws->condition.get(), reads);
        bool mutableCond = false;
        for (auto& r : reads) {
            if (mod.names.count(r)) { mutableCond = true; break; }
            if (mod.nonLocal) {
                auto it = vars_.find(r);
                if (it != vars_.end() &&
                    (it->second.isGlobal || it->second.arraySize > 0 ||
                     escaped_.count(r))) {
                    mutableCond = true;
                    break;
                }
            }
        }
        condVarsMutable_ = mutableCond;
        Val cv = checkCondition(ws->condition.get());
        condVarsMutable_ = false;
        checkLoopTermination(ws, mod, cv);

        auto pre = vars_;
        pushFrame();
        applyMod(mod);
        bool constFalse = cv.iv.isCst() && cv.iv.v() == 0;
        bool reach = !constFalse && narrow(ws->condition.get(), true);
        if (reach) {
            unreachable_ = false;
            walkBlock(ws->body.stmts, false);
        }
        popFrame();
        if (constFalse) {
            vars_ = pre;   // the body never ran: keep the entry state
        } else {
            applyMod(mod);
        }
        unreachable_ = false;
    }

    void walkLoop(LoopStmt* ls) {
        auto pre = vars_;
        ModInfo mod = collectMod(ls->body);
        pushFrame();
        applyMod(mod);
        unreachable_ = false;
        walkBlock(ls->body.stmts, false);
        popFrame();
        vars_ = pre;
        applyMod(mod);
        unreachable_ = false;
    }

    void walkFor(ForStmt* fs) {
        curLine_ = fs->line > 0 ? fs->line : curLine_;
        Val st, en, sp;
        if (fs->start) st = walkExpr(fs->start.get(), 0);
        if (fs->end) en = walkExpr(fs->end.get(), 0);
        if (fs->step) sp = walkExpr(fs->step.get(), 0);

        // No explicit step means step 1; only a non-constant step leaves the
        // loop variable's range unknown.
        bool stepConst = true;
        int64_t stepV = 1;
        if (fs->step) {
            stepConst = sp.iv.isCst() && !sp.hasFloat;
            if (stepConst) stepV = sp.iv.v();
        }
        bool startConst = st.iv.isCst() && !st.hasFloat;
        bool endConst = en.iv.isCst() && !en.hasFloat;

        auto pre = vars_;
        ModInfo mod = collectMod(fs->body);
        mod.names.insert(fs->varName);

        Ival range = Ival::top();
        bool zeroTrip = false;

        if (stepConst && stepV == 0) {
            zeroTrip = startConst && endConst && st.iv.v() >= en.iv.v();
            if (!zeroTrip)
                report("BUG015", curLine_,
                       "for-loop with step 0 never terminates");
            if (startConst && zeroTrip) range = Ival::cst(st.iv.v());
        } else if (startConst && endConst && stepConst) {
            int64_t a = st.iv.v(), b = en.iv.v();
            if (stepV > 0) {
                range = Ival::rng(a, (b == INT64_MIN) ? INT64_MIN : b - 1);
            } else {
                range = Ival::rng((b == INT64_MAX) ? INT64_MAX : b + 1, a);
            }
            zeroTrip = range.isBot();
        }

        pushFrame();
        applyMod(mod);
        VarInfo vi;
        vi.v.typeKnown = true;
        vi.v.isFloat = false;
        vi.v.iv = range;
        setVar(fs->varName, vi);

        unreachable_ = false;
        if (!zeroTrip) walkBlock(fs->body.stmts, false);

        popFrame();
        vars_ = pre;
        applyMod(mod);
        unreachable_ = false;
    }

    void walkSwitch(SwitchStmt* sw) {
        Val cv = walkExpr(sw->condition.get(), 0);

        auto pre = vars_;
        std::vector<std::string> baseKeys;
        baseKeys.reserve(pre.size());
        for (auto& kv : pre) baseKeys.push_back(kv.first);

        bool hasDefault = false;
        std::vector<std::unordered_map<std::string, VarInfo>> states;
        std::vector<bool> alive;

        for (auto& sc : sw->cases) {
            bool isDefault = !sc.condition;
            if (isDefault) hasDefault = true;
            Val cc;
            if (!isDefault) cc = walkExpr(sc.condition.get(), 0);
            bool skip = false;
            if (!isDefault && cv.iv.isCst() && cc.iv.isCst())
                skip = (cv.iv.v() != cc.iv.v());

            pushFrame();
            unreachable_ = false;
            if (!skip) {
                if (!isDefault && cc.iv.isCst() && sw->condition) {
                    auto id = dynamic_cast<IdentExpr*>(sw->condition.get());
                    if (id && !(it_isFloat(id->name))) {
                        auto it = vars_.find(id->name);
                        if (it != vars_.end()) {
                            Val v = it->second.v;
                            if (!(v.typeKnown && v.isFloat)) {
                                v.iv = Ival::cst(cc.iv.v());
                                setVal(id->name, v);
                            }
                        }
                    }
                }
                walkBlock(sc.body.stmts, false);
            }
            states.push_back(vars_);
            alive.push_back(!skip && !unreachable_);
            popFrame();
        }

        // every case ends with a branch to the end label: no fall-through
        std::unordered_map<std::string, Val> acc;
        if (!hasDefault) {
            for (auto& k : baseKeys) acc[k] = pre.at(k).v;  // no-match path
        }
        for (size_t i = 0; i < states.size(); i++) {
            if (!alive[i]) continue;
            for (auto& k : baseKeys) {
                auto it = states[i].find(k);
                Val v = (it != states[i].end()) ? it->second.v : pre.at(k).v;
                auto a = acc.find(k);
                if (a == acc.end()) acc[k] = v;
                else a->second = mergeVal(a->second, v);
            }
        }
        for (auto& kv : acc) {
            auto it = vars_.find(kv.first);
            if (it != vars_.end()) it->second.v = kv.second;
        }

        bool flows = !hasDefault;
        for (size_t i = 0; i < alive.size(); i++)
            if (alive[i]) flows = true;
        unreachable_ = !flows;
    }

    bool it_isFloat(const std::string& name) {
        auto it = vars_.find(name);
        if (it == vars_.end()) return false;
        return it->second.v.typeKnown && it->second.v.isFloat;
    }

    // ---------------- loop modification summary ----------------
    ModInfo collectMod(const Block& b) {
        ModInfo m;
        collectModStmts(b.stmts, m);
        return m;
    }

    void collectModStmts(const std::vector<std::unique_ptr<Stmt>>& stmts,
                         ModInfo& m) {
        for (auto& sp : stmts) collectModStmt(sp.get(), m);
    }

    void collectModStmt(Stmt* s, ModInfo& m) {
        if (!s) return;
        if (auto vd = dynamic_cast<VarDecl*>(s)) {
            m.names.insert(vd->name);
            if (vd->init) collectModExpr(vd->init.get(), m);
        } else if (auto as = dynamic_cast<AssignStmt*>(s)) {
            m.names.insert(as->name);
            if (as->value) collectModExpr(as->value.get(), m);
            if (as->indexExpr) collectModExpr(as->indexExpr.get(), m);
        } else if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
            collectModExpr(pa->ptr.get(), m);
            collectModExpr(pa->value.get(), m);
            m.nonLocal = true;
        } else if (auto ex = dynamic_cast<ExprStmt*>(s)) {
            collectModExpr(ex->expr.get(), m);
        } else if (auto rs = dynamic_cast<ReturnStmt*>(s)) {
            if (rs->value) collectModExpr(rs->value.get(), m);
        } else if (dynamic_cast<AsmStmt*>(s)) {
            m.nonLocal = true;
        } else if (auto is = dynamic_cast<IfStmt*>(s)) {
            collectModExpr(is->condition.get(), m);
            collectModStmts(is->thenBlock.stmts, m);
            collectModStmts(is->elseBlock.stmts, m);
        } else if (auto ws = dynamic_cast<WhileStmt*>(s)) {
            collectModExpr(ws->condition.get(), m);
            collectModStmts(ws->body.stmts, m);
        } else if (auto ls = dynamic_cast<LoopStmt*>(s)) {
            collectModStmts(ls->body.stmts, m);
        } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
            m.names.insert(fs->varName);
            if (fs->start) collectModExpr(fs->start.get(), m);
            if (fs->end) collectModExpr(fs->end.get(), m);
            if (fs->step) collectModExpr(fs->step.get(), m);
            collectModStmts(fs->body.stmts, m);
        } else if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
            collectModExpr(sw->condition.get(), m);
            for (auto& sc : sw->cases) {
                if (sc.condition) collectModExpr(sc.condition.get(), m);
                collectModStmts(sc.body.stmts, m);
            }
        }
    }

    void collectModExpr(Expr* e, ModInfo& m) {
        if (!e) return;
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            m.nonLocal = true;
            if (c->receiver) collectModExpr(c->receiver.get(), m);
            for (auto& a : c->args) collectModExpr(a.get(), m);
            return;
        }
        if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
            m.names.insert(a->name);
            m.nonLocal = true;
            return;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) {
            collectModExpr(b->left.get(), m);
            collectModExpr(b->right.get(), m);
            return;
        }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) {
            collectModExpr(u->operand.get(), m);
            return;
        }
        if (auto aa = dynamic_cast<ArrayAccessExpr*>(e)) {
            collectModExpr(aa->array.get(), m);
            collectModExpr(aa->index.get(), m);
            return;
        }
        if (auto me = dynamic_cast<MemberExpr*>(e)) {
            collectModExpr(me->object.get(), m);
            return;
        }
        if (auto d = dynamic_cast<DerefExpr*>(e)) {
            collectModExpr(d->ptr.get(), m);
            m.nonLocal = true;
            return;
        }
    }

    void applyMod(const ModInfo& m) {
        for (auto& n : m.names) killName(n);
        if (m.nonLocal) killNonLocals();
    }
};

}  // namespace

int runBugFind(const Program& prog, const std::string& fileName,
               std::vector<std::string>& warnings,
               const BugLineFileFn& fileForLine) {
    Analyzer a;
    a.out_ = &warnings;
    a.fileName_ = fileName;
    a.fileForLine_ = fileForLine;
    a.run(prog);
    return a.count_;
}
