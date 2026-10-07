#include "irgen.h"
#include <stdexcept>
#include <cstring>
#include <cmath>
#include <algorithm>

int IRGen::allocSlot() {
    // Unique slots: every definition gets its own slot id. This makes the
    // IR optimizations (use-count DCE, constant folding, slot removal) sound;
    // the optimizer reclaims unused slots afterwards.
    return poolNext_++;
}

void IRGen::freeSlot(int s) {
    (void)s;  // no-op: slots are reclaimed by the optimizer pass
}

void IRGen::recordRun(int base, int count) {
    if (curFn_) {
        IRFunction::IRRun r;
        r.baseSlot = base;
        r.count = count;
        curFn_->runs.push_back(r);
        if (base + count > curFn_->maxSlot) curFn_->maxSlot = base + count;
    }
}

int IRGen::newLabel() { return labelCounter_++; }

void IRGen::add(IROp op, IROperand a, IROperand b, IROperand c,
                const std::string& cond, int label) {
    IRInstr in;
    in.op = op;
    in.a = a; in.b = b; in.c = c;
    in.cond = cond;
    in.label = label;
    cur_->push_back(in);
}

int IRGen::ensureString(const std::string& s) {
    auto it = stringIndex_.find(s);
    if (it != stringIndex_.end()) return it->second;
    int idx = (int)ir_.strings.size();
    ir_.strings.push_back(s);
    stringIndex_[s] = idx;
    return idx;
}

void IRGen::computeStructLayouts() {
    structLayouts_.clear();
    for (auto& sd : ast_.structs) {
        StructLayout layout;
        layout.name = sd->name;
        layout.totalSize = 0;
        for (auto& f : sd->fields) {
            layout.fieldOffsets[f.name] = 0;
            layout.fieldTypes[f.name] = f.type;
        }
        structLayouts_[sd->name] = layout;
    }
    for (int pass = 0; pass < 8; pass++) {
        bool changed = false;
        for (auto& sd : ast_.structs) {
            auto it = structLayouts_.find(sd->name);
            if (it == structLayouts_.end()) continue;
            StructLayout& layout = it->second;
            int offset = 0;
            for (auto& f : sd->fields) {
                int fieldSize = 0;
                switch (f.type.kind) {
                    case TypeKind::Int:    fieldSize = 8; break;
                    case TypeKind::Float:  fieldSize = 4; break;
                    case TypeKind::Bool:   fieldSize = 4; break;
                    case TypeKind::Vec2:   fieldSize = 8; break;
                    case TypeKind::Vec3:   fieldSize = 12; break;
                    case TypeKind::Color:  fieldSize = 16; break;
                    case TypeKind::Struct: {
                        if (f.type.isPtr) { fieldSize = 8; break; }
                        auto nIt = structLayouts_.find(f.type.structName);
                        fieldSize = (nIt != structLayouts_.end()) ? nIt->second.totalSize : 8;
                        break;
                    }
                    default: fieldSize = 8; break;
                }
                if (fieldSize > 0 && offset % fieldSize != 0) offset += fieldSize - (offset % fieldSize);
                if (layout.fieldOffsets[f.name] != offset) { layout.fieldOffsets[f.name] = offset; changed = true; }
                offset += fieldSize;
            }
            if (layout.totalSize != offset) { layout.totalSize = offset; changed = true; }
        }
        if (!changed) break;
    }
}

bool IRGen::isGlobalVar(const std::string& name) const {
    return isGlobal_.count(name) != 0;
}

Type* IRGen::globalType(const std::string& name) {
    for (auto& g : ast_.globals) {
        if (g->name == name) return &g->type;
    }
    return nullptr;
}

Type* IRGen::varTypeOf(const std::string& name) {
    auto it = varTypes_.find(name);
    if (it != varTypes_.end()) return &it->second;
    return globalType(name);
}

int IRGen::typeBytes(TypeKind k) {
    switch (k) {
        case TypeKind::Float: return 4;
        case TypeKind::Bool: return 4;
        case TypeKind::Vec3: return 12;
        case TypeKind::Color: return 16;
        default: return 8;
    }
}

int IRGen::arrayElemBytes(const std::string& name) {
    if (Type* t = varTypeOf(name)) return typeBytes(t->kind);
    return 8;
}

int IRGen::scaleIdx(int idx, int elemBytes) {
    int s = allocSlot();
    if (elemBytes == 8) add(IROp::Shl, IROperand::mkReg(s), IROperand::mkReg(idx), IROperand::mkImm(3));
    else if (elemBytes == 4) add(IROp::Shl, IROperand::mkReg(s), IROperand::mkReg(idx), IROperand::mkImm(2));
    else if (elemBytes == 16) add(IROp::Shl, IROperand::mkReg(s), IROperand::mkReg(idx), IROperand::mkImm(4));
    else {
        int sz = allocSlot();
        add(IROp::Const, IROperand::mkReg(sz), IROperand::mkImm(elemBytes));
        add(IROp::Mul, IROperand::mkReg(s), IROperand::mkReg(idx), IROperand::mkReg(sz));
        freeSlot(sz);
    }
    return s;
}

bool IRGen::structFieldInfo(const std::string& structName, const std::string& field,
                            int& off, Type& ft) {
    auto it = structLayouts_.find(structName);
    if (it == structLayouts_.end()) return false;
    auto fit = it->second.fieldOffsets.find(field);
    if (fit == it->second.fieldOffsets.end()) return false;
    off = fit->second;
    auto tit = it->second.fieldTypes.find(field);
    if (tit != it->second.fieldTypes.end()) ft = tit->second;
    return true;
}

int IRGen::typeSize(const Type& t) {
    if (t.isPtr) return 8;               // every pointer is a qword
    switch (t.kind) {
        case TypeKind::Float: return 4;
        case TypeKind::Bool: return 4;
        case TypeKind::Vec3: return 12;
        case TypeKind::Color: return 16;
        case TypeKind::Struct: {
            auto it = structLayouts_.find(t.structName);
            if (it != structLayouts_.end() && it->second.totalSize > 0)
                return it->second.totalSize;
            return 8;
        }
        default: return 8;
    }
}

int IRGen::arraySizeOf(const std::string& name) {
    auto it = varArrays_.find(name);
    if (it != varArrays_.end()) return it->second;
    for (auto& g : ast_.globals)
        if (g->name == name) return g->arraySize;
    return 0;
}

// Static type of an expression. Pointer-ness (`isPtr`) is preserved: for a
// variable it is the declared type, for a dereference it is the pointee and
// for `&x` it is "pointer to x's type". Callers that must NOT treat a
// `ptr<float>` variable as a float value check `kind == Float && !isPtr`.
Type IRGen::exprType(Expr* e) {
    if (!e) return Type(TypeKind::Void);
    if (dynamic_cast<NumberExpr*>(e)) return Type(TypeKind::Int);
    if (dynamic_cast<FloatExpr*>(e)) return Type(TypeKind::Float);
    if (dynamic_cast<StringExpr*>(e)) return Type(TypeKind::String);
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (Type* t = varTypeOf(id->name)) return *t;
        return Type(TypeKind::Void);
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        if (u->op == "!") return Type(TypeKind::Bool);
        if (u->op == "~") return Type(TypeKind::Int);
        return exprType(u->operand.get());
    }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        const std::string& op = b->op;
        if (op == "==" || op == "!=" || op == "<" || op == "<=" ||
            op == ">" || op == ">=" || op == "&&" || op == "||")
            return Type(TypeKind::Bool);
        Type lt = exprType(b->left.get());
        Type rt = exprType(b->right.get());
        if (lt.kind == TypeKind::Float && !lt.isPtr) return lt;
        if (rt.kind == TypeKind::Float && !rt.isPtr) return rt;
        if ((op == "+" || op == "-") && lt.isPtr) return lt;   // p + n keeps p's type
        if (op == "+" && rt.isPtr) return rt;                  // n + p
        if (lt.kind != TypeKind::Void) return Type(lt.kind, lt.structName, false);
        if (rt.kind != TypeKind::Void) return Type(rt.kind, rt.structName, false);
        return Type(TypeKind::Int);
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        // flatten a.b.c into root + path; pointer fields are walked by kind
        // (the pointee structName stays in `kind`/`structName`), so the type
        // of `n1.next.val` resolves without loading anything.
        Expr* root = m;
        std::vector<MemberExpr*> path;
        while (auto mm = dynamic_cast<MemberExpr*>(root)) {
            path.push_back(mm);
            root = mm->object.get();
        }
        std::reverse(path.begin(), path.end());
        Type cur = exprType(root);
        if (cur.kind == TypeKind::Void) return cur;
        for (auto mm : path) {
            if (cur.kind == TypeKind::Vec2 || cur.kind == TypeKind::Vec3 ||
                cur.kind == TypeKind::Color) {
                cur = Type(TypeKind::Float);
            } else if (cur.kind == TypeKind::Struct) {
                Type ft;
                int off = 0;
                if (!structFieldInfo(cur.structName, mm->member, off, ft))
                    return Type(TypeKind::Void);
                cur = ft;
            } else {
                return Type(TypeKind::Void);
            }
        }
        return cur;
    }
    if (auto d = dynamic_cast<DerefExpr*>(e)) {
        Type t = exprType(d->ptr.get());
        if (t.isPtr) { t.isPtr = false; return t; }   // pointee type
        return Type(TypeKind::Void);
    }
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
        Type t;
        if (!a->target) t = varTypeOf(a->name) ? *varTypeOf(a->name) : Type(TypeKind::Void);
        else t = exprType(a->target.get());
        if (t.kind == TypeKind::Void) return t;
        t.isPtr = true;                                // &x -> ptr<x>
        return t;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        Type bt = exprType(arr->array.get());
        if (bt.kind == TypeKind::Void) return bt;
        bool arrayVar = false;
        if (auto id = dynamic_cast<IdentExpr*>(arr->array.get()))
            arrayVar = arraySizeOf(id->name) > 0;
        if (bt.isPtr && !arrayVar) { bt.isPtr = false; return bt; }  // p[i] -> pointee
        return bt;                                                    // arr[i] -> element type
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        for (auto& f : ast_.functions)
            if (f->name == c->name) return f->returnType;
        // Indirect call: the callee is a function pointer (variable or field).
        if (c->receiver) {
            if (auto mm = dynamic_cast<MemberExpr*>(c->receiver.get())) {
                Type rt = exprType(mm);
                if (rt.isFuncPtr() && rt.fn) return rt.fn->ret;
            }
        } else if (Type* t = varTypeOf(c->name)) {
            if (t->isFuncPtr() && t->fn) return t->fn->ret;
        }
        return Type(TypeKind::Void);
    }
    return Type(TypeKind::Void);
}

// A float VALUE: kind == Float and not a pointer. `ptr<float>` variables are
// addresses, not floats - routing them through emitFloatExpr would F2I them.
bool IRGen::exprIsFloat(Expr* e) {
    Type t = exprType(e);
    return t.kind == TypeKind::Float && !t.isPtr;
}

// Name of an AST node's type, for diagnostics. The IR backend reports what it
// cannot lower by name, so a missing case is a one-line fix instead of a
// bisect through a silent fallback to the classic backend.
static const char* exprKindName(Expr* e) {
    if (dynamic_cast<NumberExpr*>(e)) return "NumberExpr";
    if (dynamic_cast<FloatExpr*>(e)) return "FloatExpr";
    if (dynamic_cast<StringExpr*>(e)) return "StringExpr";
    if (dynamic_cast<IdentExpr*>(e)) return "IdentExpr";
    if (dynamic_cast<MemberExpr*>(e)) return "MemberExpr";
    if (dynamic_cast<BinaryExpr*>(e)) return "BinaryExpr";
    if (dynamic_cast<UnaryExpr*>(e)) return "UnaryExpr";
    if (dynamic_cast<DerefExpr*>(e)) return "DerefExpr";
    if (dynamic_cast<AddressOfExpr*>(e)) return "AddressOfExpr";
    if (dynamic_cast<ArrayAccessExpr*>(e)) return "ArrayAccessExpr";
    if (dynamic_cast<CallExpr*>(e)) return "CallExpr";
    return "unknown";
}

// A string is a pointer in the IR, so printing one goes through PrintStr with
// the pointer in a register. Getting this wrong prints the address of the
// text as a number, which is why it is worth asking the type instead of
// guessing from the expression shape. String concatenation is not a builtin
// here (see 07_вывод_в_консоль.txt), so a binary `+` is never a string.
bool IRGen::exprIsString(Expr* e) {
    if (dynamic_cast<StringExpr*>(e)) return true;
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        Type* t = varTypeOf(id->name);
        return t && t->kind == TypeKind::String;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        for (auto& f : ast_.functions)
            if (f->name == c->name) return f->returnType.kind == TypeKind::String;
        return false;
    }
    return false;
}

// ====================================================================
// Expression lowering
// ====================================================================

// ====================================================================
// 'app android' runtime lowering
//
// A phone has no PL011, no libc and no host FS abstraction, so every OS
// service is a raw Linux/AArch64 syscall. The backend emits one `__z_*`
// helper per service (see src/irasm_android.cpp) and this function maps
// the Zenith builtins onto them. Nothing here is shared with the other IR
// targets: the syscall numbers, the "0 means failure" convention and the
// Bionic-free libc calls are all Android's.
// ====================================================================

int IRGen::androidCallHelper(const char* helper, const std::vector<Expr*>& args) {
    std::vector<int> temps;
    temps.reserve(args.size());
    for (Expr* a : args) {
        if (a) { temps.push_back(emitIntExpr(a)); continue; }
        // an omitted optional argument (mmap's fd/offset) is a zero, not a hole:
        // the helper always wants a full argument list
        int z = allocSlot();
        add(IROp::Const, IROperand::mkReg(z), IROperand::mkImm(0));
        temps.push_back(z);
    }
    int res = allocSlot();
    for (size_t i = 0; i < temps.size(); i++) {
        add(IROp::Arg, IROperand::mkImm((int)i), IROperand::mkReg(temps[i]));
        freeSlot(temps[i]);
    }
    add(IROp::ICall, IROperand::mkReg(res), IROperand::imp(helper, ""),
        IROperand::mkImm((int)temps.size()));
    return res;
}

int IRGen::androidCallHelper1(const char* helper, Expr* a0) {
    return androidCallHelper(helper, {a0});
}
int IRGen::androidCallHelper2(const char* helper, Expr* a0, Expr* a1) {
    return androidCallHelper(helper, {a0, a1});
}
int IRGen::androidCallHelper3(const char* helper, Expr* a0, Expr* a1, Expr* a2) {
    return androidCallHelper(helper, {a0, a1, a2});
}
int IRGen::androidCallHelper4(const char* helper, Expr* a0, Expr* a1, Expr* a2, Expr* a3) {
    return androidCallHelper(helper, {a0, a1, a2, a3});
}

// micros()/millis() read CLOCK_MONOTONIC and divide. A constant divisor is a
// plain signed divide; the divisor is folded into the IR so nothing depends on
// the backend. `negative` is never used (monotonic time is unsigned-positive),
// it only exists to document that the result is not folded as a comparison.
int IRGen::androidScaledTime(int64_t divisor, bool negative) {
    (void)negative;
    int ns = androidCallHelper("__z_time_ns", {});
    int res = allocSlot();
    add(IROp::IDiv, IROperand::mkReg(res), IROperand::mkReg(ns), IROperand::mkImm(divisor));
    freeSlot(ns);
    return res;
}

void IRGen::androidPrint(Expr* arg, bool newline) {
    if (auto s = dynamic_cast<StringExpr*>(arg)) {
        IROperand a = IROperand::str(ensureString(s->value));
        a.off = newline ? 0 : 1;
        add(IROp::PrintStr, a);
        return;
    }
    if (exprIsString(arg)) {
        // A string-typed expression evaluates to its address, which is what
        // PrintStr wants in a register.
        int r = emitIntExpr(arg);
        IROperand a = IROperand::mkReg(r);
        a.off = newline ? 0 : 1;
        add(IROp::PrintStr, a);
        freeSlot(r);
        return;
    }
    bool isF = exprIsFloat(arg);
    int r = isF ? emitFloatExpr(arg) : emitIntExpr(arg);
    IROperand a = IROperand::mkReg(r);
    a.off = newline ? 0 : 1;
    add(isF ? IROp::PrintFlt : IROp::PrintInt, a);
    freeSlot(r);
}

int IRGen::androidCall(CallExpr* c) {
    const std::string& n = c->name;
    const size_t na = c->args.size();
    auto A = [&](size_t i) { return c->args[i].get(); };
    auto zero = [&]() -> int {
        int z = allocSlot();
        add(IROp::Const, IROperand::mkReg(z), IROperand::mkImm(0));
        return z;
    };

    // ---- output: print does not add a line break, println does ----
    if (n == "print" || n == "println" || n == "printLn") {
        if (na == 1) androidPrint(A(0), n != "print");
        return zero();
    }

    // ---- process lifetime: every one of these is exit_group(2) ----
    if (n == "exit" || n == "exit_process" || n == "sys_exit_group" || n == "halt") {
        int code = (na == 1) ? emitIntExpr(A(0)) : zero();
        int res = allocSlot();
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(code));
        add(IROp::ICall, IROperand::mkReg(res), IROperand::imp("__z_exit", ""),
            IROperand::mkImm(1));
        freeSlot(code);
        return res;
    }

    // ---- time ----
    if (n == "sleep" && na == 1) return androidCallHelper1("__z_sleep", A(0));
    if (n == "delay_us" && na == 1) return androidCallHelper1("__z_delay_us", A(0));
    if (n == "delay_ms" && na == 1) {
        // Android has no reason to spin: nanosleep(2) hands the core back to
        // the scheduler, which is what a phone wants. The classic backend
        // busy-waits here; going to sleep is both faster and kinder.
        int ms = emitIntExpr(A(0));
        int us = allocSlot();
        int k = allocSlot();
        add(IROp::Const, IROperand::mkReg(k), IROperand::mkImm(1000));
        add(IROp::Mul, IROperand::mkReg(us), IROperand::mkReg(ms), IROperand::mkReg(k));
        freeSlot(k);
        freeSlot(ms);
        int res = allocSlot();
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(us));
        add(IROp::ICall, IROperand::mkReg(res), IROperand::imp("__z_delay_us", ""),
            IROperand::mkImm(1));
        freeSlot(us);
        return res;
    }
    if (n == "rdtsc" && na == 0) return androidCallHelper("__z_time_ns", {});
    if (n == "micros" && na == 0) return androidScaledTime(1000, false);
    if (n == "millis" && na == 0) return androidScaledTime(1000000, false);

    // ---- heap: alloc/free are mmap(2)/munmap(2) with a size header ----
    if (n == "alloc" && na == 1) return androidCallHelper1("__z_alloc", A(0));
    if (n == "free" && na == 1) return androidCallHelper1("__z_free", A(0));

    // ---- strings ----
    if (n == "str_len" && na == 1) return androidCallHelper1("__z_str_len", A(0));

    // ---- memory primitives (byte-wise, memmove semantics) ----
    if (n == "mem_copy" && na == 3) return androidCallHelper3("__z_mem_copy", A(0), A(1), A(2));
    if (n == "mem_set" && na == 3) return androidCallHelper3("__z_mem_set", A(0), A(1), A(2));
    if (n == "mem_cmp" && na == 3) return androidCallHelper3("__z_mem_cmp", A(0), A(1), A(2));

    // ---- anonymous mappings ----
    //
    // Zenith's signature is mmap(len, prot, flags[, fd[, offset]]) — the size
    // first, because that is what a caller actually has. The kernel wants
    // mmap(addr, len, prot, flags, fd, off) with the address in front. So the
    // arguments are reshaped here rather than passed straight through: a zero
    // address (the kernel picks one) plus the five the kernel reads. The
    // result is the full six-argument list, which is also exactly what
    // Andropt's syscall inlining needs to replace the call with svc #0.
    if (n == "mmap" && na >= 3 && na <= 5) {
        int len  = emitIntExpr(A(0));
        int prot = emitIntExpr(A(1));
        int flg  = emitIntExpr(A(2));
        int fd   = (na > 3) ? emitIntExpr(A(3)) : zero();
        int off  = (na > 4) ? emitIntExpr(A(4)) : zero();
        int res  = allocSlot();
        int slots[6] = { zero(), len, prot, flg, fd, off };
        for (int k = 0; k < 6; k++) {
            add(IROp::Arg, IROperand::mkImm(k), IROperand::mkReg(slots[k]));
            freeSlot(slots[k]);
        }
        add(IROp::ICall, IROperand::mkReg(res), IROperand::imp("__z_mmap", ""),
            IROperand::mkImm(6));
        return res;
    }
    if (n == "munmap" && na == 2) return androidCallHelper2("__z_munmap", A(0), A(1));
    if (n == "madvise" && na == 3) return androidCallHelper3("__z_madvise", A(0), A(1), A(2));

    // ---- process / system information ----
    if (n == "getpid" && na == 0) return androidCallHelper("__z_getpid", {});
    if (n == "getuid" && na == 0) return androidCallHelper("__z_getuid", {});
    if (n == "geteuid" && na == 0) return androidCallHelper("__z_geteuid", {});
    if (n == "getgid" && na == 0) return androidCallHelper("__z_getgid", {});
    if (n == "sys_page_size" && na == 0) return androidCallHelper("__z_page_size", {});
    if (n == "sys_sched_yield" && na == 0) return androidCallHelper("__z_sched_yield", {});
    if (n == "sys_uname_field" && na == 3)
        return androidCallHelper3("__z_uname_field", A(0), A(1), A(2));

    // ---- argv / envp, read off the stack the kernel built ----
    if (n == "argc" && na == 0) return androidCallHelper("__z_argc", {});
    if (n == "arg_get" && na == 3) return androidCallHelper3("__z_arg_get", A(0), A(1), A(2));
    if (n == "env_get" && na == 3) return androidCallHelper3("__z_env_get", A(0), A(1), A(2));

    // ---- randomness and anonymous files ----
    if (n == "random_bytes" && na == 2) return androidCallHelper2("__z_random_bytes", A(0), A(1));
    if (n == "memfd_create" && na == 1) return androidCallHelper1("__z_memfd_create", A(0));

    // ---- descriptor-level file operations ----
    if (n == "file_open" && na == 2) return androidCallHelper2("__z_file_open", A(0), A(1));
    if ((n == "file_read" || n == "file_write") && na == 3)
        return androidCallHelper3(n == "file_read" ? "__z_file_read" : "__z_file_write",
                                  A(0), A(1), A(2));
    if ((n == "file_pread" || n == "file_pwrite") && na == 4)
        return androidCallHelper4(n == "file_pread" ? "__z_file_pread" : "__z_file_pwrite",
                                  A(0), A(1), A(2), A(3));
    if (n == "file_close" && na == 1) return androidCallHelper1("__z_file_close", A(0));
    if (n == "file_size" && na == 1) return androidCallHelper1("__z_file_size", A(0));
    if (n == "file_fstat_size" && na == 1) return androidCallHelper1("__z_file_fstat_size", A(0));
    if (n == "file_lseek" && na == 3) return androidCallHelper3("__z_file_lseek", A(0), A(1), A(2));
    if (n == "file_truncate" && na == 2) return androidCallHelper2("__z_file_truncate", A(0), A(1));
    if (n == "file_fsync" && na == 1) return androidCallHelper1("__z_file_fsync", A(0));

    // ---- path-level file operations ----
    if (n == "file_unlink" && na == 1) return androidCallHelper1("__z_file_unlink", A(0));
    if (n == "file_rename" && na == 2) return androidCallHelper2("__z_file_rename", A(0), A(1));
    if (n == "file_mkdir" && na == 2) return androidCallHelper2("__z_file_mkdir", A(0), A(1));

    return -1;   // not an Android builtin: let the generic path try
}

int IRGen::emitCall(CallExpr* c) {
    // 'app android': the syscall helpers shadow every OS-facing builtin.
    if (android_) {
        int r = androidCall(c);
        if (r >= 0) return r;
    }

    // ---- builtin: print / println ----
    if ((c->name == "print" || c->name == "println") && c->args.size() == 1) {
        bool nl = (c->name != "print");
        if (auto s = dynamic_cast<StringExpr*>(c->args[0].get())) {
            IROperand a = IROperand::str(ensureString(s->value));
            a.off = nl ? 0 : 1;
            add(IROp::PrintStr, a);
        } else if (exprIsString(c->args[0].get())) {
            int r = emitIntExpr(c->args[0].get());
            IROperand a = IROperand::mkReg(r);
            a.off = nl ? 0 : 1;
            add(IROp::PrintStr, a);
            freeSlot(r);
        } else if (exprIsFloat(c->args[0].get())) {
            int r = emitFloatExpr(c->args[0].get());
            IROperand a = IROperand::mkReg(r);
            a.off = nl ? 0 : 1;
            add(IROp::PrintFlt, a);
            freeSlot(r);
        } else {
            int r = emitIntExpr(c->args[0].get());
            IROperand a = IROperand::mkReg(r);
            a.off = nl ? 0 : 1;
            add(IROp::PrintInt, a);
            freeSlot(r);
        }
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    // ---- builtin: exit ----
    if (c->name == "exit" && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        add(IROp::Exit, IROperand::mkReg(r));
        freeSlot(r);
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    // ---- builtin: sleep ----
    if (c->name == "sleep" && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(r));
        add(IROp::ICall, IROperand::mkReg(res),
            IROperand::imp("Sleep", "kernel32.dll"), IROperand::mkImm(1));
        freeSlot(r);
        return res;
    }
    // ---- builtin: halt ----
    if (c->name == "halt" && c->args.empty()) {
        int res = allocSlot();
        add(IROp::Call, IROperand::mkReg(res), IROperand::func("__zt_halt"),
            IROperand::mkImm(0));
        return res;
    }
    // ---- builtin: rdtsc ----
    if (c->name == "rdtsc" && c->args.empty()) {
        int res = allocSlot();
        add(IROp::Call, IROperand::mkReg(res), IROperand::func("__zt_rdtsc"),
            IROperand::mkImm(0));
        return res;
    }
    // ---- builtin: alloc(size) ----
    if (c->name == "alloc" && c->args.size() == 1) {
        int sz = emitIntExpr(c->args[0].get());
        int heap = allocSlot();
        add(IROp::ICall, IROperand::mkReg(heap), IROperand::imp("GetProcessHeap", "kernel32.dll"),
            IROperand::mkImm(0));
        int zero = allocSlot();
        add(IROp::Const, IROperand::mkReg(zero), IROperand::mkImm(0));
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(heap));
        add(IROp::Arg, IROperand::mkImm(1), IROperand::mkReg(zero));
        add(IROp::Arg, IROperand::mkImm(2), IROperand::mkReg(sz));
        int res = allocSlot();
        add(IROp::ICall, IROperand::mkReg(res), IROperand::imp("HeapAlloc", "kernel32.dll"),
            IROperand::mkImm(3));
        return res;
    }
    // ---- builtin: free(ptr) ----
    if (c->name == "free" && c->args.size() == 1) {
        int p = emitIntExpr(c->args[0].get());
        int heap = allocSlot();
        add(IROp::ICall, IROperand::mkReg(heap), IROperand::imp("GetProcessHeap", "kernel32.dll"),
            IROperand::mkImm(0));
        int zero = allocSlot();
        add(IROp::Const, IROperand::mkReg(zero), IROperand::mkImm(0));
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(heap));
        add(IROp::Arg, IROperand::mkImm(1), IROperand::mkReg(zero));
        add(IROp::Arg, IROperand::mkImm(2), IROperand::mkReg(p));
        int dummy = allocSlot();
        add(IROp::ICall, IROperand::mkReg(dummy), IROperand::imp("HeapFree", "kernel32.dll"),
            IROperand::mkImm(3));
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    // ---- builtin: pause ----
    if (c->name == "pause" && c->args.empty()) {
        int msgIdx = ensureString("Press any key to continue . . .\r\n");
        int msgLen = (int)ir_.strings[msgIdx].size();
        int n11 = allocSlot();
        add(IROp::Const, IROperand::mkReg(n11), IROperand::mkImm(-11));
        int hOut = allocSlot();
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(n11));
        add(IROp::ICall, IROperand::mkReg(hOut), IROperand::imp("GetStdHandle", "kernel32.dll"),
            IROperand::mkImm(1));
        int strPtr = allocSlot();
        add(IROp::Str, IROperand::mkReg(strPtr), IROperand::str(msgIdx));
        int wlen = allocSlot();
        add(IROp::Const, IROperand::mkReg(wlen), IROperand::mkImm(msgLen));
        int z1 = allocSlot();
        add(IROp::Const, IROperand::mkReg(z1), IROperand::mkImm(0));
        int z2 = allocSlot();
        add(IROp::Const, IROperand::mkReg(z2), IROperand::mkImm(0));
        add(IROp::Arg, IROperand::mkImm(0), IROperand::mkReg(hOut));
        add(IROp::Arg, IROperand::mkImm(1), IROperand::mkReg(strPtr));
        add(IROp::Arg, IROperand::mkImm(2), IROperand::mkReg(wlen));
        add(IROp::Arg, IROperand::mkImm(3), IROperand::mkReg(z1));
        add(IROp::Arg, IROperand::mkImm(4), IROperand::mkReg(z2));
        int res = allocSlot();
        add(IROp::ICall, IROperand::mkReg(res), IROperand::imp("WriteFile", "kernel32.dll"),
            IROperand::mkImm(5));
        return res;
    }
    // ---- builtin: abs(x) = (x ^ (x>>63)) - (x>>63) ----
    if (c->name == "abs" && c->args.size() == 1) {
        int v = emitIntExpr(c->args[0].get());
        int sh = allocSlot();
        add(IROp::Sar, IROperand::mkReg(sh), IROperand::mkReg(v), IROperand::mkImm(63));
        int xr = allocSlot();
        add(IROp::Xor, IROperand::mkReg(xr), IROperand::mkReg(v), IROperand::mkReg(sh));
        int res = allocSlot();
        add(IROp::Sub, IROperand::mkReg(res), IROperand::mkReg(xr), IROperand::mkReg(sh));
        return res;
    }
    // ---- builtin: ftoi(x) / itof(x) ----
    if (c->name == "ftoi" && c->args.size() == 1) {
        int v = emitFloatExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::F2I, IROperand::mkReg(res), IROperand::mkReg(v));
        freeSlot(v);
        return res;
    }
    if (c->name == "itof" && c->args.size() == 1) {
        int v = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::I2F, IROperand::mkReg(res), IROperand::mkReg(v));
        freeSlot(v);
        return res;
    }
    // ---- builtin: min(a,b) = b + (a-b)*(a<b) ----
    if (c->name == "min" && c->args.size() == 2) {
        int a = emitIntExpr(c->args[0].get());
        int b = emitIntExpr(c->args[1].get());
        int lt = allocSlot();
        add(IROp::Cmp, IROperand::mkReg(lt), IROperand::mkReg(a), IROperand::mkReg(b), "<");
        int d = allocSlot();
        add(IROp::Sub, IROperand::mkReg(d), IROperand::mkReg(a), IROperand::mkReg(b));
        int p = allocSlot();
        add(IROp::Mul, IROperand::mkReg(p), IROperand::mkReg(d), IROperand::mkReg(lt));
        int res = allocSlot();
        add(IROp::Add, IROperand::mkReg(res), IROperand::mkReg(b), IROperand::mkReg(p));
        return res;
    }
    // ---- builtin: max(a,b) = a + (b-a)*(a<b) ----
    if (c->name == "max" && c->args.size() == 2) {
        int a = emitIntExpr(c->args[0].get());
        int b = emitIntExpr(c->args[1].get());
        int lt = allocSlot();
        add(IROp::Cmp, IROperand::mkReg(lt), IROperand::mkReg(a), IROperand::mkReg(b), "<");
        int d = allocSlot();
        add(IROp::Sub, IROperand::mkReg(d), IROperand::mkReg(b), IROperand::mkReg(a));
        int p = allocSlot();
        add(IROp::Mul, IROperand::mkReg(p), IROperand::mkReg(d), IROperand::mkReg(lt));
        int res = allocSlot();
        add(IROp::Add, IROperand::mkReg(res), IROperand::mkReg(a), IROperand::mkReg(p));
        return res;
    }
    // ---- builtin: clamp(x, lo, hi) = max(x,lo) then min(., hi) ----
    if (c->name == "clamp" && c->args.size() == 3) {
        int x = emitIntExpr(c->args[0].get());
        int lo = emitIntExpr(c->args[1].get());
        int hi = emitIntExpr(c->args[2].get());
        int lt1 = allocSlot();
        add(IROp::Cmp, IROperand::mkReg(lt1), IROperand::mkReg(x), IROperand::mkReg(lo), "<");
        int d1 = allocSlot();
        add(IROp::Sub, IROperand::mkReg(d1), IROperand::mkReg(lo), IROperand::mkReg(x));
        int p1 = allocSlot();
        add(IROp::Mul, IROperand::mkReg(p1), IROperand::mkReg(d1), IROperand::mkReg(lt1));
        int m = allocSlot();
        add(IROp::Add, IROperand::mkReg(m), IROperand::mkReg(x), IROperand::mkReg(p1));
        int lt2 = allocSlot();
        add(IROp::Cmp, IROperand::mkReg(lt2), IROperand::mkReg(m), IROperand::mkReg(hi), "<");
        int d2 = allocSlot();
        add(IROp::Sub, IROperand::mkReg(d2), IROperand::mkReg(m), IROperand::mkReg(hi));
        int p2 = allocSlot();
        add(IROp::Mul, IROperand::mkReg(p2), IROperand::mkReg(d2), IROperand::mkReg(lt2));
        int res = allocSlot();
        add(IROp::Add, IROperand::mkReg(res), IROperand::mkReg(hi), IROperand::mkReg(p2));
        return res;
    }
    // ---- memory peek/poke ----
    if (c->name == "peek8" && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::PLoadB, IROperand::mkReg(res), IROperand::mkReg(r));
        freeSlot(r);
        return res;
    }
    if (c->name == "peek16" && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::PLoadW, IROperand::mkReg(res), IROperand::mkReg(r));
        freeSlot(r);
        return res;
    }
    if (c->name == "peek32" && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::PLoad32Z, IROperand::mkReg(res), IROperand::mkReg(r));
        freeSlot(r);
        return res;
    }
    if ((c->name == "peek" || c->name == "peek64") && c->args.size() == 1) {
        int r = emitIntExpr(c->args[0].get());
        int res = allocSlot();
        add(IROp::PLoad, IROperand::mkReg(res), IROperand::mkReg(r));
        freeSlot(r);
        return res;
    }
    if (c->name == "poke8" && c->args.size() == 2) {
        int p = emitIntExpr(c->args[0].get());
        int v = emitIntExpr(c->args[1].get());
        add(IROp::PStoreB, IROperand::mkReg(p), IROperand::mkReg(v));
        freeSlot(p); freeSlot(v);
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    if (c->name == "poke16" && c->args.size() == 2) {
        int p = emitIntExpr(c->args[0].get());
        int v = emitIntExpr(c->args[1].get());
        add(IROp::PStoreW, IROperand::mkReg(p), IROperand::mkReg(v));
        freeSlot(p); freeSlot(v);
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    if (c->name == "poke32" && c->args.size() == 2) {
        int p = emitIntExpr(c->args[0].get());
        int v = emitIntExpr(c->args[1].get());
        add(IROp::PStore32, IROperand::mkReg(p), IROperand::mkReg(v));
        freeSlot(p); freeSlot(v);
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }
    if ((c->name == "poke" || c->name == "poke64") && c->args.size() == 2) {
        int p = emitIntExpr(c->args[0].get());
        int v = emitIntExpr(c->args[1].get());
        add(IROp::PStore, IROperand::mkReg(p), IROperand::mkReg(v));
        freeSlot(p); freeSlot(v);
        int res = allocSlot();
        add(IROp::Const, IROperand::mkReg(res), IROperand::mkImm(0));
        return res;
    }

    // ---- extern / import functions ----
    for (auto& f : ast_.functions) {
        if (f->isExtern && f->name == c->name) {
            bool fl = f->returnType.kind == TypeKind::Float;
            std::vector<int> temps(c->args.size());
            for (size_t i = 0; i < c->args.size(); i++) {
                temps[i] = exprIsFloat(c->args[i].get()) ? emitFloatExpr(c->args[i].get())
                                                         : emitIntExpr(c->args[i].get());
            }
            int res = allocSlot();
            for (size_t i = 0; i < c->args.size(); i++) {
                IROperand a = IROperand::mkImm((int)i);
                a.off = exprIsFloat(c->args[i].get()) ? 1 : 0;
                add(IROp::Arg, a, IROperand::mkReg(temps[i]));
                freeSlot(temps[i]);
            }
            IROperand resOp = IROperand::mkReg(res);
            resOp.off = fl ? 1 : 0;
            add(IROp::ICall, resOp, IROperand::imp(c->name, f->dllName),
                IROperand::mkImm((int)c->args.size()));
            if (fl) {
                // convert raw return bits to a float slot
                int fres = allocSlot();
                add(IROp::FMov, IROperand::mkReg(fres), resOp);
                freeSlot(res);
                return fres;
            }
            return res;
        }
    }

    // ---- virtual method dispatch ----
    if (c->isVirtual && !c->vtable.empty()) {
        bool fl = false;
        for (auto& f : ast_.functions) {
            if (f->name == c->name) { fl = f->returnType.kind == TypeKind::Float; break; }
        }
        std::vector<int> temps(c->args.size());
        for (size_t i = 0; i < c->args.size(); i++) {
            temps[i] = exprIsFloat(c->args[i].get()) ? emitFloatExpr(c->args[i].get())
                                                     : emitIntExpr(c->args[i].get());
        }
        // object address is arg 0; read the runtime class id from slot `__classid`
        int classId = allocSlot();
        add(IROp::PLoad, IROperand::mkReg(classId), IROperand::mkReg(temps[0]));
        int res = allocSlot();
        std::vector<int> caseLabels;
        for (size_t i = 0; i + 1 < c->vtable.size(); i++) {
            int L = newLabel();
            add(IROp::BrCC, IROperand::mkReg(classId), IROperand::mkImm(c->vtable[i].first),
                IROperand::lbl(L), "==");
            caseLabels.push_back(L);
        }
        auto emitBranchCall = [&](const std::string& impl) {
            for (size_t i = 0; i < temps.size(); i++) {
                IROperand a = IROperand::mkImm((int)i);
                a.off = exprIsFloat(c->args[i].get()) ? 1 : 0;
                add(IROp::Arg, a, IROperand::mkReg(temps[i]));
            }
            IROperand resOp = IROperand::mkReg(res);
            resOp.off = fl ? 1 : 0;
            add(IROp::Call, resOp, IROperand::func(impl),
                IROperand::mkImm((int)temps.size()));
        };
        emitBranchCall(c->vtable.back().second);   // default = static-type impl
        int done = newLabel();
        add(IROp::Br, IROperand::none(), IROperand::lbl(done));
        for (size_t i = 0; i + 1 < c->vtable.size(); i++) {
            add(IROp::Label, IROperand::lbl(caseLabels[i]));
            emitBranchCall(c->vtable[i].second);
            add(IROp::Br, IROperand::none(), IROperand::lbl(done));
        }
        add(IROp::Label, IROperand::lbl(done));
        for (auto& t : temps) freeSlot(t);
        freeSlot(classId);
        if (fl) {
            int fres = allocSlot();
            add(IROp::FMov, IROperand::mkReg(fres), IROperand::mkReg(res));
            freeSlot(res);
            return fres;
        }
        return res;
    }

    // ---- indirect call through a function pointer ----
    // Matches classic callCalleeKind: kind 1 = a function pointer variable
    // named like the callee, kind 2 = a function pointer field (receiver kept
    // after lowering; plain method calls have their receiver reset).
    {
        Type fpType;
        bool fp = false;
        if (c->receiver) {
            if (auto mm = dynamic_cast<MemberExpr*>(c->receiver.get())) {
                Type t = exprType(mm);
                if (t.isFuncPtr() && t.fn) { fp = true; fpType = t; }
            }
        } else if (Type* t = varTypeOf(c->name)) {
            if (t->isFuncPtr() && t->fn) { fp = true; fpType = *t; }
        }
        if (fp) {
            bool fl = fpType.fn->ret.kind == TypeKind::Float;
            int callee;
            if (c->receiver) {
                callee = emitExpr(c->receiver.get());
            } else {
                IdentExpr id;
                id.name = c->name;
                callee = emitExpr(&id);
            }
            std::vector<int> temps(c->args.size());
            for (size_t i = 0; i < c->args.size(); i++) {
                temps[i] = exprIsFloat(c->args[i].get()) ? emitFloatExpr(c->args[i].get())
                                                         : emitIntExpr(c->args[i].get());
            }
            int res = allocSlot();
            for (size_t i = 0; i < c->args.size(); i++) {
                IROperand a = IROperand::mkImm((int)i);
                a.off = exprIsFloat(c->args[i].get()) ? 1 : 0;
                add(IROp::Arg, a, IROperand::mkReg(temps[i]));
                freeSlot(temps[i]);
            }
            IROperand resOp = IROperand::mkReg(res);
            resOp.off = fl ? 1 : 0;
            add(IROp::ICall, resOp, IROperand::mkReg(callee),
                IROperand::mkImm((int)c->args.size()));
            freeSlot(callee);
            if (fl) {
                int fres = allocSlot();
                add(IROp::FMov, IROperand::mkReg(fres), IROperand::mkReg(res));
                freeSlot(res);
                return fres;
            }
            return res;
        }
    }

    // ---- user function call ----
    for (auto& f : ast_.functions) {
        if (!f->isExtern && f->name == c->name) {
            bool fl = f->returnType.kind == TypeKind::Float;
            std::vector<int> temps(c->args.size());
            for (size_t i = 0; i < c->args.size(); i++) {
                temps[i] = exprIsFloat(c->args[i].get()) ? emitFloatExpr(c->args[i].get())
                                                         : emitIntExpr(c->args[i].get());
            }
            int res = allocSlot();
            for (size_t i = 0; i < c->args.size(); i++) {
                IROperand a = IROperand::mkImm((int)i);
                a.off = exprIsFloat(c->args[i].get()) ? 1 : 0;
                add(IROp::Arg, a, IROperand::mkReg(temps[i]));
                freeSlot(temps[i]);
            }
            IROperand resOp = IROperand::mkReg(res);
            resOp.off = fl ? 1 : 0;
            add(IROp::Call, resOp, IROperand::func(c->name),
                IROperand::mkImm((int)c->args.size()));
            if (fl) {
                int fres = allocSlot();
                add(IROp::FMov, IROperand::mkReg(fres), IROperand::mkReg(res));
                freeSlot(res);
                return fres;
            }
            return res;
        }
    }

    throw std::runtime_error("IR mode: unsupported builtin/function '" + c->name + "'");
}

int IRGen::emitLogicalExpr(Expr* e, int trueLabel, int falseLabel) {
    // Lower boolean expression with short-circuit: jumps to trueLabel / falseLabel.
    // Returns -1 (no value slot) when control flow handles the result.
    auto bin = dynamic_cast<BinaryExpr*>(e);
    if (!bin || (bin->op != "&&" && bin->op != "||"))
        throw std::runtime_error("IR mode: internal logical expr error");
    if (bin->op == "&&") {
        // left false -> falseLabel; left true -> evaluate right
        int next = newLabel();
        emitBooleanValue(bin->left.get(), next, falseLabel);
        add(IROp::Label, IROperand::lbl(next));
        emitBooleanValue(bin->right.get(), trueLabel, falseLabel);
    } else {
        // left true -> trueLabel; left false -> evaluate right
        int next = newLabel();
        emitBooleanValue(bin->left.get(), trueLabel, next);
        add(IROp::Label, IROperand::lbl(next));
        emitBooleanValue(bin->right.get(), trueLabel, falseLabel);
    }
    return -1;
}

void IRGen::emitBooleanValue(Expr* e, int trueLabel, int falseLabel) {
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        if (bin->op == "&&" || bin->op == "||") {
            emitLogicalExpr(bin, trueLabel, falseLabel);
            return;
        }
    }
    int r = emitExpr(e);
    add(IROp::BrZ, IROperand::mkReg(r), IROperand::lbl(falseLabel));
    add(IROp::Br, IROperand::none(), IROperand::lbl(trueLabel));
    freeSlot(r);
}

int IRGen::emitIntExpr(Expr* e) {
    if (exprIsFloat(e)) {
        int r = emitExpr(e);
        int i = allocSlot();
        add(IROp::F2I, IROperand::mkReg(i), IROperand::mkReg(r));
        freeSlot(r);
        return i;
    }
    return emitExpr(e);
}

int IRGen::emitFloatExpr(Expr* e) {
    if (!exprIsFloat(e)) {
        int r = emitExpr(e);
        int f = allocSlot();
        add(IROp::I2F, IROperand::mkReg(f), IROperand::mkReg(r));
        freeSlot(r);
        return f;
    }
    return emitExpr(e);
}

int IRGen::emitExpr(Expr* e) {
    if (auto n = dynamic_cast<NumberExpr*>(e)) {
        int r = allocSlot();
        add(IROp::Const, IROperand::mkReg(r), IROperand::mkImm(n->value));
        return r;
    }
    if (auto fl = dynamic_cast<FloatExpr*>(e)) {
        int r = allocSlot();
        add(IROp::FConst, IROperand::mkReg(r), IROperand::fimmf((float)fl->value));
        return r;
    }
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        int r = allocSlot();
        add(IROp::Str, IROperand::mkReg(r), IROperand::str(ensureString(s->value)));
        return r;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (isGlobalVar(id->name)) {
            int r = allocSlot();
            add(IROp::GLoad, IROperand::mkReg(r), IROperand::glob(id->name));
            return r;
        }
        auto it = varSlots_.find(id->name);
        if (it == varSlots_.end())
            throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
        int r = allocSlot();
        add(IROp::Load, IROperand::mkReg(r), IROperand::slot(it->second));
        return r;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        bool isF = exprIsFloat(u->operand.get());
        int r = emitExpr(u->operand.get());
        int r2 = allocSlot();
        if (u->op == "-") {
            if (isF) add(IROp::FNeg, IROperand::mkReg(r2), IROperand::mkReg(r));
            else add(IROp::Neg, IROperand::mkReg(r2), IROperand::mkReg(r));
        } else if (u->op == "!") {
            add(IROp::Cmp, IROperand::mkReg(r2), IROperand::mkReg(r),
                IROperand::mkImm(0), "==", 0);
        } else if (u->op == "~") {
            add(IROp::Not, IROperand::mkReg(r2), IROperand::mkReg(r));
        } else {
            freeSlot(r); freeSlot(r2);
            throw std::runtime_error("IR mode: unsupported unary operator '" + u->op + "'");
        }
        freeSlot(r);
        return r2;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        std::string op = bin->op;
        if (op == "&&" || op == "||") {
            // materialize a 0/1 value. A single-assignment temp cannot be
            // written on two control-flow paths, so the result is stored to
            // a memory slot and loaded once at the join.
            int res = allocSlot();   // memory slot, written on both paths
            int z = allocSlot();
            add(IROp::Const, IROperand::mkReg(z), IROperand::mkImm(0));
            add(IROp::Store, IROperand::slot(res), IROperand::mkReg(z));
            freeSlot(z);
            int lTrue = newLabel(), lEnd = newLabel();
            emitBooleanValue(bin, lTrue, lEnd);
            add(IROp::Label, IROperand::lbl(lTrue));
            int o = allocSlot();
            add(IROp::Const, IROperand::mkReg(o), IROperand::mkImm(1));
            add(IROp::Store, IROperand::slot(res), IROperand::mkReg(o));
            freeSlot(o);
            add(IROp::Label, IROperand::lbl(lEnd));
            int out = allocSlot();
            add(IROp::Load, IROperand::mkReg(out), IROperand::slot(res));
            return out;
        }
        bool isF = exprIsFloat(bin->left.get()) || exprIsFloat(bin->right.get());
        if (op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=") {
            int rl = isF ? emitFloatExpr(bin->left.get()) : emitIntExpr(bin->left.get());
            int rr = isF ? emitFloatExpr(bin->right.get()) : emitIntExpr(bin->right.get());
            int r2 = allocSlot();
            IROperand resOp = IROperand::mkReg(r2);
            resOp.off = isF ? 1 : 0;
            add(IROp::Cmp, resOp, IROperand::mkReg(rl), IROperand::mkReg(rr), op, 0);
            freeSlot(rl); freeSlot(rr);
            return r2;
        }
        int rl = isF ? emitFloatExpr(bin->left.get()) : emitIntExpr(bin->left.get());
        int rr = isF ? emitFloatExpr(bin->right.get()) : emitIntExpr(bin->right.get());
        // Pointer arithmetic: `p + n` / `p - n` scale n by the pointee size
        // (stride), exactly like the classic backends' emitBinInt.
        if (!isF && (op == "+" || op == "-")) {
            Type lt = exprType(bin->left.get());
            Type rt = exprType(bin->right.get());
            if (lt.isPtr && !rt.isPtr) {
                Type pt = lt; pt.isPtr = false;
                int s = scaleIdx(rr, typeSize(pt));
                freeSlot(rr);
                rr = s;
            } else if (op == "+" && rt.isPtr && !lt.isPtr) {
                Type pt = rt; pt.isPtr = false;
                int s = scaleIdx(rl, typeSize(pt));
                freeSlot(rl);
                rl = s;
            }
        }
        int r2 = allocSlot();
        IROp iop;
        if (op == "+") iop = isF ? IROp::FAdd : IROp::Add;
        else if (op == "-") iop = isF ? IROp::FSub : IROp::Sub;
        else if (op == "*") iop = isF ? IROp::FMul : IROp::Mul;
        else if (op == "/") iop = isF ? IROp::FDiv : IROp::IDiv;
        else if (op == "%" || op == "//") iop = IROp::IMod;
        else if (op == "&") iop = IROp::And;
        else if (op == "|") iop = IROp::Or;
        else if (op == "^") iop = IROp::Xor;
        else if (op == "<<") iop = IROp::Shl;
        else if (op == ">>") iop = IROp::Shr;
        else {
            freeSlot(rl); freeSlot(rr); freeSlot(r2);
            throw std::runtime_error("IR mode: unsupported binary operator '" + op + "'");
        }
        add(iop, IROperand::mkReg(r2), IROperand::mkReg(rl), IROperand::mkReg(rr));
        freeSlot(rl); freeSlot(rr);
        return r2;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        return emitMemberLoad(m);
    }
    if (auto d = dynamic_cast<DerefExpr*>(e)) {
        int p = emitIntExpr(d->ptr.get());
        Type pt = exprType(d->ptr.get());
        pt.isPtr = false;                          // pointee type
        int r = allocSlot();
        // Width follows the pointee: floats/bools are 4-byte windows, pointers
        // and (non-Android) ints are full qwords. 'app android' keeps the
        // documented 4-byte `int` window for int pointees.
        if ((pt.kind == TypeKind::Float || pt.kind == TypeKind::Bool) && !pt.isPtr)
            add(IROp::PLoad32, IROperand::mkReg(r), IROperand::mkReg(p));
        else if (pt.kind == TypeKind::Int && android_)
            add(IROp::PLoad32, IROperand::mkReg(r), IROperand::mkReg(p));
        else
            add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(p));
        freeSlot(p);
        return r;
    }
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
        if (a->target) return emitAddrOf(a->target.get());
        if (isGlobalVar(a->name)) {
            int r = allocSlot();
            add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(a->name));
            return r;
        }
        auto it = varSlots_.find(a->name);
        if (it != varSlots_.end()) {
            int r = allocSlot();
            add(IROp::LeaSlot, IROperand::mkReg(r), IROperand::slot(it->second));
            return r;
        }
        // `&func` - a function address. Represented as LeaGlobal of the
        // function's symbol name; the backends resolve it to the code image
        // offset (irasm_android falls back to the function table when the
        // name is not a data global).
        for (auto& f : ast_.functions)
            if (f->name == a->name && !f->isExtern) {
                int r = allocSlot();
                add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(a->name));
                return r;
            }
        throw std::runtime_error("IR mode: unknown variable '" + a->name + "'");
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        return emitArrayAccess(arr, true);
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        return emitCall(c);
    }
    // Nothing above claimed the node, so the IR backend has no lowering for
    // it. Say which node it was: this throw makes main.cpp fall back to the
    // classic backend, and a bare "unsupported expression" made that silent
    // downgrade impossible to diagnose from the outside.
    throw std::runtime_error(std::string("IR mode: unsupported expression node '") +
                             exprKindName(e) + "'");
}

// Address of an lvalue. Handles the same shapes as the classic backends'
// emitAddr: variables, fields (with pointer hops: `n1.next.val` walks
// through the `next` pointer), array elements, dereferences and pointer
// arithmetic (`*(p + off)` lvalues).
int IRGen::emitAddrOf(Expr* e) {
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (isGlobalVar(id->name)) {
            int r = allocSlot();
            add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(id->name));
            return r;
        }
        auto it = varSlots_.find(id->name);
        if (it == varSlots_.end()) {
            for (auto& f : ast_.functions)
                if (f->name == id->name && !f->isExtern) {
                    int r = allocSlot();
                    add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(id->name));
                    return r;
                }
            throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
        }
        int r = allocSlot();
        add(IROp::LeaSlot, IROperand::mkReg(r), IROperand::slot(it->second));
        return r;
    }
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
        if (!a->target) {
            IdentExpr id;
            id.name = a->name;
            return emitAddrOf(static_cast<Expr*>(&id));
        }
        return emitAddrOf(a->target.get());
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        Expr* root = m;
        std::vector<MemberExpr*> path;
        while (auto mm = dynamic_cast<MemberExpr*>(root)) {
            path.push_back(mm);
            root = mm->object.get();
        }
        std::reverse(path.begin(), path.end());
        Type cur = exprType(root);
        if (cur.kind == TypeKind::Void)
            throw std::runtime_error("IR mode: unknown member base");
        int base;
        if (cur.isPtr) {
            base = emitExpr(root);      // object pointer value
            cur.isPtr = false;
        } else {
            base = emitAddrOf(root);    // object in place
        }
        int off = 0;
        auto addOff = [&](int b, int o) {
            if (o == 0) return b;
            int s = allocSlot();
            add(IROp::Const, IROperand::mkReg(s), IROperand::mkImm(o));
            int r = allocSlot();
            add(IROp::Add, IROperand::mkReg(r), IROperand::mkReg(b), IROperand::mkReg(s));
            freeSlot(b); freeSlot(s);
            return r;
        };
        for (size_t i = 0; i < path.size(); i++) {
            int foff = 0;
            Type ft;
            if (cur.kind == TypeKind::Struct) {
                if (!structFieldInfo(cur.structName, path[i]->member, foff, ft))
                    throw std::runtime_error("IR mode: unknown member '" + path[i]->member + "'");
            } else if (cur.kind == TypeKind::Vec2 || cur.kind == TypeKind::Vec3) {
                foff = (path[i]->member == "y") ? 4 : (path[i]->member == "z" ? 8 : 0);
                ft = Type(TypeKind::Float);
            } else if (cur.kind == TypeKind::Color) {
                static const char* cols[4] = {"r","g","b","a"};
                foff = 0;
                bool ok = false;
                for (int j = 0; j < 4; j++) if (cols[j] == path[i]->member) { foff = j * 4; ok = true; break; }
                if (!ok) throw std::runtime_error("IR mode: unknown member '" + path[i]->member + "'");
                ft = Type(TypeKind::Float);
            } else {
                throw std::runtime_error("IR mode: unsupported member base");
            }
            off += foff;
            cur = ft;
            // Intermediate pointer field: the bytes at base+off hold the next
            // object's address - hop through it and restart the offset.
            if (i + 1 < path.size() && cur.isPtr) {
                base = addOff(base, off);
                off = 0;
                int p = allocSlot();
                add(IROp::PLoad, IROperand::mkReg(p), IROperand::mkReg(base));
                freeSlot(base);
                base = p;
                cur.isPtr = false;
            }
        }
        return addOff(base, off);
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) return emitArrayAddr(arr);
    if (auto d = dynamic_cast<DerefExpr*>(e)) return emitIntExpr(d->ptr.get());
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        if (b->op == "+" || b->op == "-") return emitIntExpr(e);  // p + off
        throw std::runtime_error("IR mode: unsupported address expression 'BinaryExpr'");
    }
    throw std::runtime_error(std::string("IR mode: unsupported address expression '") +
                             exprKindName(e) + "'");
}

// &base[index]: base may be an array variable (address = lea of the slot) or
// a pointer variable/expression (address = pointer value), scaled by the
// element stride in both cases.
int IRGen::emitArrayAddr(ArrayAccessExpr* arr) {
    Type bt = exprType(arr->array.get());
    if (bt.kind == TypeKind::Void)
        throw std::runtime_error("IR mode: unknown array base");
    bool ptrBase = bt.isPtr;
    if (auto id = dynamic_cast<IdentExpr*>(arr->array.get())) {
        // An array variable is not a pointer base even when its element type
        // is one ([3]ptr<float>).
        if (arraySizeOf(id->name) > 0) ptrBase = false;
        int base;
        if (!ptrBase) {
            if (isGlobalVar(id->name)) {
                int r = allocSlot();
                add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(id->name));
                base = r;
            } else {
                auto it = varSlots_.find(id->name);
                if (it == varSlots_.end())
                    throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
                int r = allocSlot();
                add(IROp::LeaSlot, IROperand::mkReg(r), IROperand::slot(it->second));
                base = r;
            }
        } else {
            base = emitExpr(arr->array.get());   // load the pointer value
        }
        Type pt = bt;
        if (ptrBase) pt.isPtr = false;
        int stride = typeSize(pt);
        int idx = emitIntExpr(arr->index.get());
        int scaled = scaleIdx(idx, stride);
        freeSlot(idx);
        int addr = allocSlot();
        add(IROp::Add, IROperand::mkReg(addr), IROperand::mkReg(base), IROperand::mkReg(scaled));
        freeSlot(base); freeSlot(scaled);
        return addr;
    }
    // general base expression: must be pointer-valued (call result, deref,
    // pointer field, `&x`, `p + off`, ...)
    if (!ptrBase)
        throw std::runtime_error("IR mode: unsupported array base");
    int base = emitExpr(arr->array.get());
    Type pt = bt; pt.isPtr = false;
    int idx = emitIntExpr(arr->index.get());
    int scaled = scaleIdx(idx, typeSize(pt));
    freeSlot(idx);
    int addr = allocSlot();
    add(IROp::Add, IROperand::mkReg(addr), IROperand::mkReg(base), IROperand::mkReg(scaled));
    freeSlot(base); freeSlot(scaled);
    return addr;
}

// &name[index] for the AssignStmt index fast path (name is a local/global
// array or pointer variable).
int IRGen::emitElemAddr(const std::string& name, Expr* index) {
    if (!isGlobalVar(name) && varSlots_.count(name) == 0)
        throw std::runtime_error("IR mode: unknown variable '" + name + "'");
    Type bt;
    if (Type* t = varTypeOf(name)) bt = *t;
    else throw std::runtime_error("IR mode: unknown variable '" + name + "'");
    bool arrayVar = arraySizeOf(name) > 0;
    bool ptrBase = bt.isPtr && !arrayVar;
    int base;
    if (!ptrBase) {
        if (isGlobalVar(name)) {
            int r = allocSlot();
            add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(name));
            base = r;
        } else {
            int r = allocSlot();
            add(IROp::LeaSlot, IROperand::mkReg(r), IROperand::slot(varSlots_[name]));
            base = r;
        }
    } else {
        auto id = std::make_unique<IdentExpr>();
        id->name = name;
        base = emitExpr(id.get());   // load the pointer value
    }
    Type pt = bt;
    if (ptrBase) pt.isPtr = false;
    int idx = emitIntExpr(index);
    int scaled = scaleIdx(idx, typeSize(pt));
    freeSlot(idx);
    int addr = allocSlot();
    add(IROp::Add, IROperand::mkReg(addr), IROperand::mkReg(base), IROperand::mkReg(scaled));
    freeSlot(base); freeSlot(scaled);
    return addr;
}

int IRGen::emitMemberLoad(MemberExpr* m) {
    Type ft = exprType(m);
    if (ft.kind == TypeKind::Void)
        throw std::runtime_error("IR mode: unknown member '" + m->member + "'");
    int addr = emitAddrOf(m);
    int r = allocSlot();
    if ((ft.kind == TypeKind::Float || ft.kind == TypeKind::Bool) && !ft.isPtr)
        add(IROp::PLoad32, IROperand::mkReg(r), IROperand::mkReg(addr));
    else
        add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(addr));
    freeSlot(addr);
    return r;
}

int IRGen::emitArrayAccess(ArrayAccessExpr* arr, bool isLoad) {
    (void)isLoad;
    Type et = exprType(arr);
    int addr = emitArrayAddr(arr);
    int r = allocSlot();
    // Width follows the element type: floats/bools are 4-byte windows,
    // ints/pointers/struct-adjacent values are qwords.
    if ((et.kind == TypeKind::Float || et.kind == TypeKind::Bool) && !et.isPtr)
        add(IROp::PLoad32, IROperand::mkReg(r), IROperand::mkReg(addr));
    else
        add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(addr));
    freeSlot(addr);
    return r;
}

// ====================================================================
// Statement lowering
// ====================================================================

void IRGen::emitStmt(Stmt* s) {
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) {
        if (ret->value) {
            int r = exprIsFloat(ret->value.get()) ? emitFloatExpr(ret->value.get())
                                                  : emitIntExpr(ret->value.get());
            IROperand ro = IROperand::mkReg(r);
            ro.off = exprIsFloat(ret->value.get()) ? 1 : 0;
            add(IROp::Ret, ro);
            freeSlot(r);
        } else {
            add(IROp::Ret);
        }
        return;
    }
    if (auto vd = dynamic_cast<VarDecl*>(s)) {
        int nSlots = 1;
        if (vd->arraySize > 0) {
            nSlots = (vd->arraySize * typeSize(vd->type) + 7) / 8;
            if (nSlots < 1) nSlots = 1;
        } else if (vd->type.kind == TypeKind::Struct && !vd->type.isPtr) {
            auto it = structLayouts_.find(vd->type.structName);
            int sz = (it != structLayouts_.end()) ? it->second.totalSize : 8;
            nSlots = (sz + 7) / 8;
            if (nSlots < 1) nSlots = 1;
        }
        int base = allocSlot();
        for (int k = 1; k < nSlots; k++) allocSlot();   // contiguous slot ids
        recordRun(base, nSlots);
        varSlots_[vd->name] = base;
        varTypes_[vd->name] = vd->type;
        varArrays_[vd->name] = vd->arraySize;
        if (vd->init) {
            if (vd->type.kind == TypeKind::Float && !vd->type.isPtr) {
                int r = emitFloatExpr(vd->init.get());
                add(IROp::FStore, IROperand::slot(base), IROperand::mkReg(r));
                freeSlot(r);
            } else {
                int r = emitIntExpr(vd->init.get());
                add(IROp::Store, IROperand::slot(base), IROperand::mkReg(r));
                freeSlot(r);
            }
        } else if (vd->arraySize > 0) {
            // zero-init arrays
            int zero = allocSlot();
            add(IROp::Const, IROperand::mkReg(zero), IROperand::mkImm(0));
            for (int k = 0; k < nSlots; k++)
                add(IROp::Store, IROperand::slot(base + k), IROperand::mkReg(zero));
            freeSlot(zero);
        }
        // Fresh class-typed locals: stamp the runtime class id into the hidden
        // `__classid` slot (offset 0) so virtual dispatch works even for
        // objects that are never assigned through fields.
        if (vd->type.kind == TypeKind::Struct && !vd->type.isPtr && vd->arraySize == 0) {
            auto cidIt = ast_.classIDs.find(vd->type.structName);
            if (cidIt != ast_.classIDs.end()) {
                int cid = allocSlot();
                add(IROp::Const, IROperand::mkReg(cid), IROperand::mkImm(cidIt->second));
                add(IROp::Store, IROperand::slot(base), IROperand::mkReg(cid));
                freeSlot(cid);
            }
        }
        return;
    }
    if (auto ex = dynamic_cast<ExprStmt*>(s)) {
        int r = emitExpr(ex->expr.get());
        freeSlot(r);
        return;
    }
    if (auto as = dynamic_cast<AssignStmt*>(s)) {
        emitAssign(as);
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        int p = emitIntExpr(pa->ptr.get());
        Type et = exprType(pa->ptr.get());   // the pointer type of `&lvalue`
        et.isPtr = false;                    // ...so the pointee is the value type
        // Store width follows the pointee: floats/bools are 4-byte windows,
        // ints on Android keep the documented 4-byte `int` window, everything
        // else (pointers, structs by qword) is a full 8-byte store.
        if (et.kind == TypeKind::Float) {
            int v = emitFloatExpr(pa->value.get());
            add(IROp::FPStore, IROperand::mkReg(p), IROperand::mkReg(v));
            freeSlot(v);
        } else if (et.kind == TypeKind::Bool) {
            int v = emitIntExpr(pa->value.get());
            add(IROp::PStore32, IROperand::mkReg(p), IROperand::mkReg(v));
            freeSlot(v);
        } else if (et.kind == TypeKind::Int && android_) {
            int v = emitIntExpr(pa->value.get());
            add(IROp::PStore32, IROperand::mkReg(p), IROperand::mkReg(v));
            freeSlot(v);
        } else {
            int v = emitIntExpr(pa->value.get());
            add(IROp::PStore, IROperand::mkReg(p), IROperand::mkReg(v));
            freeSlot(v);
        }
        freeSlot(p);
        return;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        int thenL = newLabel(), elseL = newLabel(), endL = newLabel();
        emitBranchOnTrue(ifs->condition.get(), thenL, elseL);
        add(IROp::Label, IROperand::lbl(thenL));
        for (auto& st : ifs->thenBlock.stmts) emitStmt(st.get());
        add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        add(IROp::Label, IROperand::lbl(elseL));
        if (!ifs->elseBlock.stmts.empty()) {
            for (auto& st : ifs->elseBlock.stmts) emitStmt(st.get());
        }
        add(IROp::Label, IROperand::lbl(endL));
        return;
    }
    if (auto w = dynamic_cast<WhileStmt*>(s)) {
        int startL = newLabel(), bodyL = newLabel(), endL = newLabel();
        continueStack_.push_back(startL);
        breakStack_.push_back(endL);
        add(IROp::Label, IROperand::lbl(startL));
        emitBranchOnTrue(w->condition.get(), bodyL, endL);
        add(IROp::Label, IROperand::lbl(bodyL));
        for (auto& st : w->body.stmts) emitStmt(st.get());
        add(IROp::Br, IROperand::none(), IROperand::lbl(startL));
        add(IROp::Label, IROperand::lbl(endL));
        breakStack_.pop_back();
        continueStack_.pop_back();
        return;
    }
    if (auto l = dynamic_cast<LoopStmt*>(s)) {
        int startL = newLabel(), endL = newLabel();
        continueStack_.push_back(startL);
        breakStack_.push_back(endL);
        add(IROp::Label, IROperand::lbl(startL));
        for (auto& st : l->body.stmts) emitStmt(st.get());
        add(IROp::Br, IROperand::none(), IROperand::lbl(startL));
        add(IROp::Label, IROperand::lbl(endL));
        breakStack_.pop_back();
        continueStack_.pop_back();
        return;
    }
    if (auto f = dynamic_cast<ForStmt*>(s)) {
        // var = start
        int slot = allocSlot();
        recordRun(slot, 1);
        varSlots_[f->varName] = slot;
        varTypes_[f->varName] = {TypeKind::Int};
        varArrays_[f->varName] = 0;
        int startV = emitIntExpr(f->start.get());
        add(IROp::Store, IROperand::slot(slot), IROperand::mkReg(startV));
        freeSlot(startV);
        int constStep = 1;
        bool dynStep = false;
        if (f->step) {
            if (auto n = dynamic_cast<NumberExpr*>(f->step.get())) constStep = (int)n->value;
            else dynStep = true;
        }
        int stepSlot = -1;
        if (dynStep) {
            stepSlot = allocSlot();
            recordRun(stepSlot, 1);
            int sv = emitIntExpr(f->step.get());
            add(IROp::Store, IROperand::slot(stepSlot), IROperand::mkReg(sv));
            freeSlot(sv);
        }
        int startL = newLabel(), endL = newLabel(), contL = newLabel();
        continueStack_.push_back(contL);
        breakStack_.push_back(endL);
        add(IROp::Label, IROperand::lbl(startL));
        // condition: step > 0 ? (i < end) : (i > end)
        int endV = emitIntExpr(f->end.get());
        int iV = allocSlot();
        add(IROp::Load, IROperand::mkReg(iV), IROperand::slot(slot));
        int bodyL = newLabel();
        if (!dynStep) {
            if (constStep >= 0) add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), "<");
            else add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), ">");
            add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        } else {
            int stR = allocSlot();
            add(IROp::Load, IROperand::mkReg(stR), IROperand::slot(stepSlot));
            int zero = allocSlot();
            add(IROp::Const, IROperand::mkReg(zero), IROperand::mkImm(0));
            int posL = newLabel();
            add(IROp::BrCC, IROperand::mkReg(stR), IROperand::mkReg(zero), IROperand::lbl(posL), ">");
            freeSlot(zero);
            freeSlot(stR);
            add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), ">");
            add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
            add(IROp::Label, IROperand::lbl(posL));
            add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), "<");
            add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        }
        add(IROp::Label, IROperand::lbl(bodyL));
        for (auto& st : f->body.stmts) emitStmt(st.get());
        // continue jumps here to run the increment
        add(IROp::Label, IROperand::lbl(contL));
        // i += step  (fresh temp: single-assignment, no read-after-write)
        int cur = allocSlot();
        add(IROp::Load, IROperand::mkReg(cur), IROperand::slot(slot));
        int next = allocSlot();
        if (!dynStep) {
            if (constStep == 1) {
                add(IROp::Add, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(1));
            } else if (constStep == -1) {
                add(IROp::Sub, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(1));
            } else {
                add(IROp::Add, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(constStep));
            }
        } else {
            int stI = allocSlot();
            add(IROp::Load, IROperand::mkReg(stI), IROperand::slot(stepSlot));
            add(IROp::Add, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkReg(stI));
            freeSlot(stI);
        }
        add(IROp::Store, IROperand::slot(slot), IROperand::mkReg(next));
        freeSlot(cur);
        freeSlot(next);
        freeSlot(endV);
        freeSlot(iV);
        if (dynStep) freeSlot(stepSlot);
        add(IROp::Br, IROperand::none(), IROperand::lbl(startL));
        add(IROp::Label, IROperand::lbl(endL));
        breakStack_.pop_back();
        continueStack_.pop_back();
        return;
    }
    if (auto b = dynamic_cast<BreakStmt*>(s)) {
        if (breakStack_.empty()) throw std::runtime_error("IR mode: break outside loop");
        add(IROp::Br, IROperand::none(), IROperand::lbl(breakStack_.back()));
        return;
    }
    if (auto c = dynamic_cast<ContinueStmt*>(s)) {
        if (continueStack_.empty()) throw std::runtime_error("IR mode: continue outside loop");
        add(IROp::Br, IROperand::none(), IROperand::lbl(continueStack_.back()));
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        int cond = emitIntExpr(sw->condition.get());
        int endL = newLabel();
        std::vector<int> caseLabels(sw->cases.size());
        int defaultIdx = -1;
        for (size_t i = 0; i < sw->cases.size(); i++) {
            caseLabels[i] = newLabel();
            if (!sw->cases[i].condition) defaultIdx = (int)i;
        }
        for (size_t i = 0; i < sw->cases.size(); i++) {
            if (defaultIdx == (int)i) continue;
            int cv = emitIntExpr(sw->cases[i].condition.get());
            int eq = allocSlot();
            add(IROp::Cmp, IROperand::mkReg(eq), IROperand::mkReg(cond), IROperand::mkReg(cv), "==", 0);
            freeSlot(cv);
            add(IROp::BrNZ, IROperand::mkReg(eq), IROperand::lbl(caseLabels[i]));
            freeSlot(eq);
        }
        if (defaultIdx >= 0)
            add(IROp::Br, IROperand::none(), IROperand::lbl(caseLabels[defaultIdx]));
        add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        for (size_t i = 0; i < sw->cases.size(); i++) {
            add(IROp::Label, IROperand::lbl(caseLabels[i]));
            for (auto& st : sw->cases[i].body.stmts) emitStmt(st.get());
            add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        }
        add(IROp::Label, IROperand::lbl(endL));
        freeSlot(cond);
        return;
    }
    if (auto as = dynamic_cast<AsmStmt*>(s)) {
        IRAsmBlock blk;
        blk.wordSize = as->wordSize;
        for (auto& ins : as->instrs) {
            IRAsmBlock::Instr i;
            i.mnemonic = ins.mnemonic;
            i.op1 = ins.op1;
            i.op2 = ins.op2;
            i.op3 = ins.op3;
            blk.instrs.push_back(std::move(i));
        }
        int idx = (int)ir_.asmBlocks.size();
        ir_.asmBlocks.push_back(std::move(blk));
        add(IROp::RawAsm, IROperand::str(idx));
        return;
    }

    throw std::runtime_error("IR mode: unsupported statement");
}

void IRGen::emitAssign(AssignStmt* as) {
    // a[i] = v  (array or pointer element)
    if (as->indexExpr) {
        int addr = emitElemAddr(as->name, as->indexExpr.get());
        Type et;
        if (Type* t = varTypeOf(as->name)) et = *t;
        bool arrayVar = arraySizeOf(as->name) > 0;
        if (et.isPtr && !arrayVar) et.isPtr = false;   // p[i] -> pointee
        if (et.kind == TypeKind::Float && !et.isPtr) {
            int v = emitFloatExpr(as->value.get());
            add(IROp::FPStore, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        } else if (et.kind == TypeKind::Bool && !et.isPtr) {
            int v = emitIntExpr(as->value.get());
            add(IROp::PStore32, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        } else {
            int v = emitIntExpr(as->value.get());
            add(IROp::PStore, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        }
        freeSlot(addr);
        return;
    }

    // s.field = v  (member; walks pointer hops through emitAddrOf)
    if (!as->memberPath.empty()) {
        std::unique_ptr<Expr> chain;
        {
            auto root = std::make_unique<IdentExpr>();
            root->name = as->name;
            chain = std::move(root);
            for (auto& f : as->memberPath) {
                auto mm = std::make_unique<MemberExpr>();
                mm->object = std::move(chain);
                mm->member = f;
                chain = std::move(mm);
            }
        }
        Type ft = exprType(chain.get());
        if (ft.kind == TypeKind::Void)
            throw std::runtime_error("IR mode: unknown member target '" + as->name + "'");
        int addr = emitAddrOf(chain.get());
        if (ft.kind == TypeKind::Float && !ft.isPtr) {
            int v = emitFloatExpr(as->value.get());
            add(IROp::FPStore, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        } else if (ft.kind == TypeKind::Bool && !ft.isPtr) {
            int v = emitIntExpr(as->value.get());
            add(IROp::PStore32, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        } else {
            int v = emitIntExpr(as->value.get());
            add(IROp::PStore, IROperand::mkReg(addr), IROperand::mkReg(v));
            freeSlot(v);
        }
        freeSlot(addr);
        return;
    }

    // plain var = v
    if (isGlobalVar(as->name)) {
        if (auto t = varTypeOf(as->name)) {
            if (t->kind == TypeKind::Float && !t->isPtr) {
                int v = emitFloatExpr(as->value.get());
                add(IROp::FGStore, IROperand::glob(as->name), IROperand::mkReg(v));
                freeSlot(v);
                return;
            }
        }
        int v = emitIntExpr(as->value.get());
        add(IROp::GStore, IROperand::glob(as->name), IROperand::mkReg(v));
        freeSlot(v);
        return;
    }
    auto it = varSlots_.find(as->name);
    if (it == varSlots_.end())
        throw std::runtime_error("IR mode: unknown variable '" + as->name + "'");
    if (auto t = varTypeOf(as->name)) {
        if (t->kind == TypeKind::Float && !t->isPtr) {
            int v = emitFloatExpr(as->value.get());
            add(IROp::FStore, IROperand::slot(it->second), IROperand::mkReg(v));
            freeSlot(v);
            return;
        }
    }
    int v = emitIntExpr(as->value.get());
    add(IROp::Store, IROperand::slot(it->second), IROperand::mkReg(v));
    freeSlot(v);
}

void IRGen::emitBranchOnTrue(Expr* e, int trueLabel, int falseLabel) {
    // boolean expression as a control-flow condition
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        if (bin->op == "&&" || bin->op == "||") {
            emitLogicalExpr(bin, trueLabel, falseLabel);
            return;
        }
        std::string op = bin->op;
        if (op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=") {
            bool isF = exprIsFloat(bin->left.get()) || exprIsFloat(bin->right.get());
            int rl = isF ? emitFloatExpr(bin->left.get()) : emitIntExpr(bin->left.get());
            int rr = isF ? emitFloatExpr(bin->right.get()) : emitIntExpr(bin->right.get());
            // jump to trueLabel when condition holds
            IROperand aOp = IROperand::mkReg(rl);
            aOp.off = isF ? 1 : 0;
            add(IROp::BrCC, aOp, IROperand::mkReg(rr), IROperand::lbl(trueLabel), op, 0);
            freeSlot(rl); freeSlot(rr);
            add(IROp::Br, IROperand::none(), IROperand::lbl(falseLabel));
            return;
        }
    }
    int r = emitExpr(e);
    add(IROp::BrNZ, IROperand::mkReg(r), IROperand::lbl(trueLabel));
    freeSlot(r);
    add(IROp::Br, IROperand::none(), IROperand::lbl(falseLabel));
}

void IRGen::emitGlobalInit(const std::string& name, VarDecl* g) {
    (void)name; (void)g;  // handled via IRGlobal initializer data
}

void IRGen::generate() {
    computeStructLayouts();

    // ---- globals ----
    for (auto& g : ast_.globals) {
        IRGlobal ig;
        ig.name = g->name;
        isGlobal_[g->name] = true;
        if (g->type.kind == TypeKind::Float && !g->type.isPtr) {
            ig.isFloat = true;
            ig.size = 4;
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get()))
                ig.floatValue = (float)n->value;
            else if (auto f = dynamic_cast<FloatExpr*>(g->init.get()))
                ig.floatValue = (float)f->value;
            else ig.floatValue = 0.0f;
            ig.intValue = 0;
        } else if (g->type.kind == TypeKind::String) {
            ig.isString = true;
            if (auto s = dynamic_cast<StringExpr*>(g->init.get())) {
                ig.strValue = s->value;
                ensureString(s->value);
            } else ig.strValue.clear();
        } else if (g->type.kind == TypeKind::Bool) {
            ig.size = 4;
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get())) ig.intValue = n->value;
            else if (auto f = dynamic_cast<FloatExpr*>(g->init.get())) ig.intValue = (int64_t)f->value;
            else ig.intValue = 0;
        } else if (g->type.kind == TypeKind::Struct) {
            auto it = structLayouts_.find(g->type.structName);
            if (g->type.isPtr) {
                ig.size = 8;  // a pointer (e.g. `this`) occupies a single qword
            } else {
                ig.size = (it != structLayouts_.end()) ? it->second.totalSize : 8;
            }
            if (ig.size < 1) ig.size = 1;
            ig.isStruct = true;
            // Class-typed globals carry their runtime class id in the hidden
            // `__classid` slot (offset 0) so virtual dispatch works on them.
            ig.intValue = 0;
            if (!g->type.isPtr) {
                auto cidIt = ast_.classIDs.find(g->type.structName);
                if (cidIt != ast_.classIDs.end()) ig.intValue = cidIt->second;
            }
        } else {
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get())) ig.intValue = n->value;
            else ig.intValue = 0;
        }
        if (g->arraySize > 0) {
            int elem = 8;
            if ((g->type.kind == TypeKind::Float || g->type.kind == TypeKind::Bool) && !g->type.isPtr)
                elem = 4;
            else if (g->type.kind == TypeKind::Struct && !g->type.isPtr) {
                auto it = structLayouts_.find(g->type.structName);
                if (it != structLayouts_.end()) elem = it->second.totalSize;
            }
            ig.size = g->arraySize * elem;
        }
        // `var p: ptr<T> = &x`: the address only exists once the image is
        // loaded, so the entry function stores it before running user code.
        if (g->type.isPtr && g->arraySize == 0 &&
            dynamic_cast<AddressOfExpr*>(g->init.get()))
            runtimeGlobalInits_.push_back(g.get());
        ir_.globals.push_back(std::move(ig));
    }

    // ---- functions ----
    for (auto& f : ast_.functions) {
        IRFunction fn;
        fn.name = f->name;
        fn.nparams = (int)f->params.size();
        fn.isExtern = f->isExtern;
        fn.dllName = f->dllName;
        if (f->isExtern) {
            ir_.functions.push_back(std::move(fn));
            continue;
        }
        cur_ = &fn.instrs;
        curFn_ = &fn;
        nparams_ = fn.nparams;
        varSlots_.clear();
        varTypes_.clear();
        freeSlots_.clear();
        poolNext_ = nparams_;
        int p = 0;
        for (auto& prm : f->params) {
            varSlots_[prm.name] = p;
            varTypes_[prm.name] = prm.type;
            varArrays_[prm.name] = 0;
            p++;
        }
        add(IROp::Func, IROperand::func(f->name), IROperand::mkImm(fn.nparams));
        for (auto& stmt : f->body.stmts) emitStmt(stmt.get());
        bool returnsValue = f->returnType.kind != TypeKind::Void;
        bool returnsFloat = f->returnType.kind == TypeKind::Float;
        if (returnsValue) {
            int r = allocSlot();
            if (returnsFloat) {
                add(IROp::FConst, IROperand::mkReg(r), IROperand::fimmf(0.0f));
                IROperand ro = IROperand::mkReg(r);
                ro.off = 1;
                add(IROp::Ret, ro);
            } else {
                add(IROp::Const, IROperand::mkReg(r), IROperand::mkImm(0));
                add(IROp::Ret, IROperand::mkReg(r));
            }
            freeSlot(r);
        } else {
            add(IROp::Ret);
        }
        add(IROp::EndFunc, IROperand::func(f->name));
        ir_.functions.push_back(std::move(fn));
    }

    // ---- entry point ----
    bool hasMain = false;
    for (auto& f : ast_.functions) if (f->name == "main") { hasMain = true; break; }
    ir_.entryFunc = hasMain ? "main" : (ast_.functions.empty() ? "" : ast_.functions[0]->name);

    // ---- runtime global initializers (`var p: ptr<T> = &x`) ----
    // Prepended to the entry function: the static data image cannot hold
    // addresses that only become known when the image is laid out.
    if (!runtimeGlobalInits_.empty()) {
        IRFunction* ef = nullptr;
        for (auto& fn : ir_.functions)
            if (fn.name == ir_.entryFunc && !fn.isExtern) { ef = &fn; break; }
        if (!ef)
            throw std::runtime_error("IR mode: no entry function for global initializers");
        std::vector<IRInstr> pre;
        cur_ = &pre;
        curFn_ = ef;
        for (auto* g : runtimeGlobalInits_) {
            int v = emitIntExpr(g->init.get());
            add(IROp::GStore, IROperand::glob(g->name), IROperand::mkReg(v));
            freeSlot(v);
        }
        cur_ = nullptr;
        curFn_ = nullptr;
        ef->instrs.insert(ef->instrs.begin(),
                          std::make_move_iterator(pre.begin()),
                          std::make_move_iterator(pre.end()));
    }
}
