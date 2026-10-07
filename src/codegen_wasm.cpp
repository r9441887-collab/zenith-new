// codegen_wasm.cpp — WebAssembly backend for "app wasm"
// ====================================================================
// Produces a binary WebAssembly module (\0asm, MVP) from the AST.
//
// Value model:
//   - int/bool values      -> i64 on the wasm stack, 8 bytes in memory
//   - float values         -> f32 on the wasm stack, 4 bytes in memory
//   - addresses (string /
//     pointer / struct)    -> i32 on the wasm stack, stored as 8 bytes
//                             (i64) in memory so struct layouts match
//                             the x86-64 backend
// Memory layout:
//   [0 .. poolEnd)         string pool (NUL-terminated UTF-8)
//   [poolEnd .. dataEnd)   user globals (int/float/bool/string/ptr/struct/array)
//   [dataEnd .. heapEnd)   bump allocator (alloc())
//   [stackTop .. memEnd)   soft stack, grows DOWN (SP is wasm global #0)
//
// Soft-stack calling convention (every user function has the signature
// () -> i64/f32/i32/void):
//   - the caller reserves 8*n bytes (SP -= 8n), stores arg i at [SP + 8*i],
//     calls, then releases the slots (SP += 8n);
//   - the callee prologue allocates its own locals (SP -= locals), so the
//     locals live BELOW the argument slots; params are read at [SP + locals + 8*i];
//   - the epilogue deallocates the locals (SP += locals) before returning.
// The caller's frame and the callee's argument region never overlap.
//
// Environment imports (module "env"):
//   zt_print_str(i32)  print NUL-terminated string + newline
//   zt_print_int(i64)  print signed decimal + newline
//   zt_print_float(f32) print decimal + newline
//   zt_exit(i32)       terminate with exit code
//   zt_sleep(i64)      sleep milliseconds
//   zt_rdtsc() -> i64  high-resolution counter
//   zt_halt()          stop execution
// plus one import per `extern` function declared in the source.
//
// The module exports "_start" (the entry function, runs the program and
// returns the exit code) and "memory". With # [no_main] every user
// function is exported instead (library mode).

#include "codegen.h"
#include "ast.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cmath>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>

namespace {

// ---- wasm value types ----
constexpr uint8_t WT_I32 = 0x7F;
constexpr uint8_t WT_I64 = 0x7E;
constexpr uint8_t WT_F32 = 0x7D;

// ---- value kind produced by an expression ----
enum VK { VInt, VFloat, VAddr };

struct WasmSig {
    std::vector<uint8_t> params;   // wasm valtypes
    uint8_t result = 0;            // 0 = void, otherwise a valtype
    std::string key() const {
        std::string k;
        k.push_back((char)params.size());
        for (uint8_t p : params) k.push_back((char)p);
        k.push_back((char)result);
        return k;
    }
};

struct WasmImport {
    std::string module, name;
    int typeIdx = 0;
};

struct WasmFunc {
    std::string name;
    int typeIdx = 0;
    bool isExtern = false;
    std::vector<uint8_t> body;   // for user functions
};

struct WasmVar {
    int off = 0;         // address offset from $sp (locals/params) or absolute (globals)
    int globalAddr = 0;  // absolute address when isGlobal
    Type type;
    bool isGlobal = false;
    int arraySize = 0;
};

class WasmBackend {
public:
    WasmBackend(const std::unordered_map<std::string, StructLayout>& layouts, Program& p)
        : layouts_(layouts), prog(p) {}
    bool compile(const std::string& path);

private:
    const std::unordered_map<std::string, StructLayout>& layouts_;
    Program& prog;

    // ---- string pool ----
    std::vector<std::string> poolStrings_;
    std::vector<int> poolOffs_;      // per-string offset inside the pool
    int poolEnd_ = 0;
    std::unordered_map<std::string, int> poolIdxOf_;
    int ensureString(const std::string& s);
    void collectStringsStmt(Stmt* s);
    void collectStringsBlock(const std::vector<std::unique_ptr<Stmt>>& stmts);
    void collectStringsExpr(Expr* e);

    // ---- memory layout ----
    std::unordered_map<std::string, int> globalAddr_;
    int dataEnd_ = 0;
    int heapStart_ = 0;
    int stackTop_ = 0;
    int memPages_ = 0;
    struct DataSeg { int off; std::vector<uint8_t> bytes; };
    std::vector<DataSeg> dataSegs_;
    void addData(int off, const uint8_t* p, size_t n);

    // ---- types ----
    std::vector<WasmSig> typePool_;
    std::unordered_map<std::string, int> typeIdxOf_;
    int ensureType(const std::vector<uint8_t>& params, uint8_t result);
    uint8_t typeToValtype(const Type& t) const;
    std::vector<uint8_t> typeListOf(const std::vector<Param>& params) const;

    // ---- imports / functions ----
    std::vector<WasmImport> imports_;
    std::unordered_map<std::string, int> importIdxOf_;   // key "module::name"
    int importIndex(const std::string& module, const std::string& name,
                    const std::vector<uint8_t>& params, uint8_t result);
    std::vector<WasmFunc> funcs_;                        // user + internal
    std::unordered_map<std::string, int> funcIdxOf_;
    int newFuncIndex(const std::string& name, int typeIdx);
    int funcCallIndex(const std::string& name) const;    // full function space (imports first)

    // ---- current function state ----
    std::vector<uint8_t> code_;
    std::unordered_map<std::string, WasmVar> vars_;
    int frame_ = 0;                  // locals size of the current function (>= 8)
    int localsSize_ = 0;             // aligned locals size used in prologue/epilogue
    int nparams_ = 0;
    uint8_t funcRetType_ = 0;        // 0 = void
    int scratchOff_ = 0;             // scratch cells: first 16 bytes of the locals area
    int scratch2Off_ = 8;

    // ---- control flow ----
    std::vector<int> blockStack_;     // every structure (block/loop/if)
    std::vector<int> breakStack_;     // labels available to break
    std::vector<int> continueStack_;  // labels available to continue
    int nextLabel_ = 0;
    int newLabel() { return nextLabel_++; }
    int brDepth(int label);
    void pushBlock(int label) { blockStack_.push_back(label); }
    void popBlock() { blockStack_.pop_back(); }

    // ---- byte emission ----
    void b8(uint8_t v) { code_.push_back(v); }
    void b32(uint32_t v) { b8((uint8_t)v); b8((uint8_t)(v >> 8)); b8((uint8_t)(v >> 16)); b8((uint8_t)(v >> 24)); }
    void uleb(uint64_t v) { do { uint8_t c = v & 0x7F; v >>= 7; if (v) c |= 0x80; b8(c); } while (v); }
    void sleb(int64_t v);
    void wstr(const std::string& s);
    void i64c(int64_t v);
    void i32c(int32_t v);
    void f32c(float f);
    void emitMemArg() { uleb(0); uleb(0); }   // align=1, offset=0
    void extendToI64();                        // i32 -> i64 (extend_u)
    void wrapToI32();                          // i64 -> i32

    // ---- address helpers ----
    void emitGlobalAddr(const std::string& name);       // i32: address of a global
    void emitVarAddr(const WasmVar& v);                 // i32: address of a var/global
    void emitScratchAddr();                             // i32: address of the scratch cell
    void emitScratch2Addr();                            // i32: address of the 2nd scratch cell

    // ---- expression helpers ----
    VK exprKind(Expr* e);
    bool exprHasValue(Expr* e);
    uint8_t wasmTypeForKind(VK k) const;
    int elemBytesOf(const Type& t) const;
    int varBytes(const Type& t, int arraySize) const;
    void emitExpr(Expr* e);
    void emitCond(Expr* e);
    void emitMemberTail(int off, const Type& t);        // stack: base addr
    void emitMemberLoad(MemberExpr* m);
    void emitArrayLoad(ArrayAccessExpr* a);
    void emitArrayStore(ArrayAccessExpr* a, Expr* value);
    void emitCallExpr(CallExpr* c);
    void emitCallUser(const std::string& name, const std::vector<std::unique_ptr<Expr>>& args);
    void emitCopyValue(int size);                       // stack: [dst, src]

    // ---- statements ----
    void collectLocals(Stmt* s);
    void collectLocalsBlock(const std::vector<std::unique_ptr<Stmt>>& stmts);
    void emitStmt(Stmt* s);
    void emitAssign(AssignStmt* as);
    void emitReturn(ReturnStmt* r);

    // ---- layout / build ----
    void layoutGlobals();
    void emitUserFunction(FunctionDecl* f);
    void emitZtAlloc();
    void emitZtMemcpy();
    void buildModule(std::vector<uint8_t>& out);
};

// ====================================================================
// byte-level helpers
// ====================================================================

int WasmBackend::brDepth(int label) {
    // distance from the innermost open block to the block with `label`
    int depth = 0;
    for (int i = (int)blockStack_.size() - 1; i >= 0; i--) {
        if (blockStack_[i] == label) return depth;
        depth++;
    }
    throw std::runtime_error("wasm: label not found");
}

void WasmBackend::sleb(int64_t v) {
    bool more = true;
    while (more) {
        uint8_t c = (uint8_t)(v & 0x7F);
        v >>= 7;
        if ((v == 0 && !(c & 0x40)) || (v == -1 && (c & 0x40))) more = false;
        else c |= 0x80;
        b8(c);
    }
}

void WasmBackend::wstr(const std::string& s) {
    uleb(s.size());
    for (char c : s) b8((uint8_t)c);
}

void WasmBackend::i64c(int64_t v) { b8(0x42); sleb(v); }
void WasmBackend::i32c(int32_t v) { b8(0x41); sleb(v); }
void WasmBackend::f32c(float f) {
    b8(0x43);
    uint32_t u;
    std::memcpy(&u, &f, sizeof(u));
    b32(u);
}

void WasmBackend::extendToI64() { b8(0xAD); }   // i64.extend_i32_u
void WasmBackend::wrapToI32() { b8(0xA7); }     // i32.wrap_i64

// ====================================================================
// types / imports / function index reservation
// ====================================================================

int WasmBackend::ensureType(const std::vector<uint8_t>& params, uint8_t result) {
    WasmSig s;
    s.params = params;
    s.result = result;
    auto k = s.key();
    auto it = typeIdxOf_.find(k);
    if (it != typeIdxOf_.end()) return it->second;
    typePool_.push_back(s);
    int idx = (int)typePool_.size() - 1;
    typeIdxOf_[k] = idx;
    return idx;
}

uint8_t WasmBackend::typeToValtype(const Type& t) const {
    if (t.kind == TypeKind::Void) return 0;
    if (t.kind == TypeKind::Float) return WT_F32;
    if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) return WT_I32;
    return WT_I64;   // int, bool, vec2/3/color (addressed by pointer where needed)
}

std::vector<uint8_t> WasmBackend::typeListOf(const std::vector<Param>& params) const {
    std::vector<uint8_t> types;
    for (auto& p : params) types.push_back(typeToValtype(p.type));
    return types;
}

int WasmBackend::importIndex(const std::string& module, const std::string& name,
                             const std::vector<uint8_t>& params, uint8_t result) {
    std::string key = module + "::" + name;
    auto it = importIdxOf_.find(key);
    if (it != importIdxOf_.end()) return it->second;
    WasmImport imp;
    imp.module = module;
    imp.name = name;
    imp.typeIdx = ensureType(params, result);
    imports_.push_back(imp);
    int idx = (int)imports_.size() - 1;
    importIdxOf_[key] = idx;
    return idx;
}

int WasmBackend::newFuncIndex(const std::string& name, int typeIdx) {
    WasmFunc f;
    f.name = name;
    f.typeIdx = typeIdx;
    funcs_.push_back(f);
    int idx = (int)funcs_.size() - 1;
    funcIdxOf_[name] = idx;
    return idx;
}

int WasmBackend::funcCallIndex(const std::string& name) const {
    auto it = funcIdxOf_.find(name);
    if (it == funcIdxOf_.end())
        throw std::runtime_error("wasm: undefined function '" + name + "'");
    return (int)imports_.size() + it->second;
}

// ====================================================================
// string pool / memory layout
// ====================================================================

int WasmBackend::ensureString(const std::string& s) {
    auto it = poolIdxOf_.find(s);
    if (it != poolIdxOf_.end()) return it->second;
    int idx = (int)poolStrings_.size();
    poolStrings_.push_back(s);
    poolOffs_.push_back(poolEnd_);
    poolEnd_ += (int)s.size() + 1;
    poolIdxOf_[s] = idx;
    return idx;
}

void WasmBackend::addData(int off, const uint8_t* p, size_t n) {
    DataSeg seg;
    seg.off = off;
    seg.bytes.assign(p, p + n);
    dataSegs_.push_back(std::move(seg));
}

// Pre-scan the AST so the string pool is complete BEFORE globals are
// placed after it (otherwise pool growth would overlap the globals).
void WasmBackend::collectStringsExpr(Expr* e) {
    if (!e) return;
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        ensureString(s->value);
        return;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) { collectStringsExpr(u->operand.get()); return; }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        collectStringsExpr(b->left.get());
        collectStringsExpr(b->right.get());
        return;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) { collectStringsExpr(m->object.get()); return; }
    if (auto d = dynamic_cast<DerefExpr*>(e)) { collectStringsExpr(d->ptr.get()); return; }
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) {
        collectStringsExpr(a->array.get());
        collectStringsExpr(a->index.get());
        return;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        collectStringsExpr(c->receiver.get());
        for (auto& a : c->args) collectStringsExpr(a.get());
        return;
    }
}

void WasmBackend::collectStringsStmt(Stmt* s) {
    if (auto vd = dynamic_cast<VarDecl*>(s)) { collectStringsExpr(vd->init.get()); return; }
    if (auto r = dynamic_cast<ReturnStmt*>(s)) { collectStringsExpr(r->value.get()); return; }
    if (auto ex = dynamic_cast<ExprStmt*>(s)) { collectStringsExpr(ex->expr.get()); return; }
    if (auto as = dynamic_cast<AssignStmt*>(s)) {
        collectStringsExpr(as->indexExpr.get());
        collectStringsExpr(as->value.get());
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        collectStringsExpr(pa->ptr.get());
        collectStringsExpr(pa->value.get());
        return;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        collectStringsExpr(ifs->condition.get());
        collectStringsBlock(ifs->thenBlock.stmts);
        collectStringsBlock(ifs->elseBlock.stmts);
        return;
    }
    if (auto w = dynamic_cast<WhileStmt*>(s)) {
        collectStringsExpr(w->condition.get());
        collectStringsBlock(w->body.stmts);
        return;
    }
    if (auto l = dynamic_cast<LoopStmt*>(s)) {
        collectStringsBlock(l->body.stmts);
        return;
    }
    if (auto f = dynamic_cast<ForStmt*>(s)) {
        collectStringsExpr(f->start.get());
        collectStringsExpr(f->end.get());
        collectStringsExpr(f->step.get());
        collectStringsBlock(f->body.stmts);
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        collectStringsExpr(sw->condition.get());
        for (auto& c : sw->cases) {
            collectStringsExpr(c.condition.get());
            collectStringsBlock(c.body.stmts);
        }
        return;
    }
}

void WasmBackend::collectStringsBlock(const std::vector<std::unique_ptr<Stmt>>& stmts) {
    for (auto& s : stmts) collectStringsStmt(s.get());
}

int WasmBackend::elemBytesOf(const Type& t) const {
    switch (t.kind) {
        case TypeKind::Float:
        case TypeKind::Bool:   return 4;
        default:               return 8;
    }
}

int WasmBackend::varBytes(const Type& t, int arraySize) const {
    if (arraySize > 0) return arraySize * elemBytesOf(t);
    switch (t.kind) {
        case TypeKind::Float:
        case TypeKind::Bool:   return 4;
        case TypeKind::Struct: {
            auto it = layouts_.find(t.structName);
            int sz = (it != layouts_.end()) ? it->second.totalSize : 8;
            return sz > 0 ? sz : 8;
        }
        case TypeKind::Vec2:   return 8;
        case TypeKind::Vec3:   return 12;
        case TypeKind::Color:  return 16;
        default:               return 8;
    }
}

void WasmBackend::layoutGlobals() {
    int cur = poolEnd_;   // globals follow the string pool
    for (auto& g : prog.globals) {
        int size = varBytes(g->type, g->arraySize);
        size = (size + 7) & ~7;
        globalAddr_[g->name] = cur;
        // constant initializers are written straight into data segments
        if (g->type.kind == TypeKind::Float) {
            float f = 0.0f;
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get())) f = (float)n->value;
            else if (auto fl = dynamic_cast<FloatExpr*>(g->init.get())) f = (float)fl->value;
            uint32_t u;
            std::memcpy(&u, &f, sizeof(u));
            uint8_t bytes[4] = { (uint8_t)u, (uint8_t)(u >> 8), (uint8_t)(u >> 16), (uint8_t)(u >> 24) };
            addData(cur, bytes, 4);
        } else if (g->type.kind == TypeKind::String) {
            std::string val;
            if (auto s = dynamic_cast<StringExpr*>(g->init.get())) val = s->value;
            int strIdx = ensureString(val);
            uint64_t addr = (uint64_t)(uint32_t)poolOffs_[strIdx];
            uint8_t bytes[8];
            for (int k = 0; k < 8; k++) bytes[k] = (uint8_t)(addr >> (8 * k));
            addData(cur, bytes, 8);
        } else if (g->type.kind == TypeKind::Bool) {
            int64_t v = 0;
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get())) v = n->value;
            uint8_t bytes[8] = { (uint8_t)v, 0, 0, 0, 0, 0, 0, 0 };
            addData(cur, bytes, 8);
        } else if (g->type.kind == TypeKind::Struct && !g->type.isPtr) {
            auto cidIt = prog.classIDs.find(g->type.structName);
            if (cidIt != prog.classIDs.end()) {
                int64_t v = cidIt->second;
                uint8_t bytes[8];
                for (int k = 0; k < 8; k++) bytes[k] = (uint8_t)(v >> (8 * k));
                addData(cur, bytes, 8);
            }
        } else if (g->type.kind != TypeKind::Struct) {
            int64_t v = 0;
            if (auto n = dynamic_cast<NumberExpr*>(g->init.get())) v = n->value;
            if (v != 0) {
                uint8_t bytes[8];
                for (int k = 0; k < 8; k++) bytes[k] = (uint8_t)(v >> (8 * k));
                addData(cur, bytes, 8);
            }
        }
        cur += size;
    }
    dataEnd_ = cur;
}

// ====================================================================
// variable address helpers
// ====================================================================

void WasmBackend::emitGlobalAddr(const std::string& name) {
    auto it = globalAddr_.find(name);
    if (it == globalAddr_.end()) {
        std::cerr << "wasm: undefined global '" << name << "'" << std::endl;
        throw std::runtime_error("wasm: undefined global");
    }
    i32c((int32_t)it->second);
}

void WasmBackend::emitVarAddr(const WasmVar& v) {
    if (v.isGlobal) {
        i32c(v.globalAddr);
    } else {
        b8(0x23); uleb(2);           // global.get $fp (stable frame base)
        i32c(v.off);
        b8(0x6A);                    // i32.add
    }
}

void WasmBackend::emitScratchAddr() {
    b8(0x23); uleb(2);               // global.get $fp
    i32c(scratchOff_);
    b8(0x6A);                        // i32.add
}

void WasmBackend::emitScratch2Addr() {
    b8(0x23); uleb(2);               // global.get $fp
    i32c(scratch2Off_);
    b8(0x6A);                        // i32.add
}

// ====================================================================
// expression kind inference
// ====================================================================

VK WasmBackend::exprKind(Expr* e) {
    if (dynamic_cast<NumberExpr*>(e)) return VInt;
    if (dynamic_cast<FloatExpr*>(e)) return VFloat;
    if (dynamic_cast<StringExpr*>(e)) return VAddr;
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto it = vars_.find(id->name);
        if (it != vars_.end()) {
            const Type& t = it->second.type;
            if (t.kind == TypeKind::Float) return VFloat;
            if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) return VAddr;
            return VInt;
        }
        for (auto& g : prog.globals) {
            if (g->name == id->name) {
                const Type& t = g->type;
                if (t.kind == TypeKind::Float) return VFloat;
                if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) return VAddr;
                return VInt;
            }
        }
        throw std::runtime_error("wasm: unknown variable '" + id->name + "'");
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        if (u->op == "!") return VInt;
        return exprKind(u->operand.get());
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        if (bin->op == "&&" || bin->op == "||") return VInt;
        if (bin->op == "==" || bin->op == "!=" || bin->op == "<" || bin->op == "<=" ||
            bin->op == ">" || bin->op == ">=") return VInt;
        if (exprKind(bin->left.get()) == VFloat || exprKind(bin->right.get()) == VFloat)
            return VFloat;
        return VInt;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        std::vector<std::string> path;
        Expr* cur = m;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) { path.push_back(mm->member); cur = mm->object.get(); }
        std::reverse(path.begin(), path.end());
        Type t;
        bool have = false;
        if (auto id = dynamic_cast<IdentExpr*>(cur)) {
            auto it = vars_.find(id->name);
            if (it != vars_.end()) { t = it->second.type; have = true; }
            else for (auto& g : prog.globals) if (g->name == id->name) { t = g->type; have = true; break; }
        } else if (auto deref = dynamic_cast<DerefExpr*>(cur)) {
            if (auto id = dynamic_cast<IdentExpr*>(deref->ptr.get())) {
                auto it = vars_.find(id->name);
                if (it != vars_.end()) { t = it->second.type; have = true; }
                else for (auto& g : prog.globals) if (g->name == id->name) { t = g->type; have = true; break; }
            }
        }
        if (have) {
            for (auto& p : path) {
                if (t.kind == TypeKind::Struct) {
                    auto it = layouts_.find(t.structName);
                    if (it == layouts_.end()) break;
                    auto ft = it->second.fieldTypes.find(p);
                    if (ft == it->second.fieldTypes.end()) break;
                    t = ft->second;
                } else if (t.kind == TypeKind::Vec2 || t.kind == TypeKind::Vec3 || t.kind == TypeKind::Color) {
                    t = { TypeKind::Float };
                } else break;
            }
            if (t.kind == TypeKind::Float) return VFloat;
            if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) return VAddr;
        }
        return VInt;
    }
    if (auto d = dynamic_cast<DerefExpr*>(e)) {
        if (auto id = dynamic_cast<IdentExpr*>(d->ptr.get())) {
            auto it = vars_.find(id->name);
            if (it != vars_.end() && it->second.type.kind == TypeKind::Struct) return VAddr;
            for (auto& g : prog.globals)
                if (g->name == id->name && g->type.kind == TypeKind::Struct) return VAddr;
        }
        return VInt;
    }
    if (dynamic_cast<AddressOfExpr*>(e)) return VAddr;
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) {
        if (auto id = dynamic_cast<IdentExpr*>(a->array.get())) {
            for (auto& g : prog.globals)
                if (g->name == id->name) {
                    if (g->type.kind == TypeKind::Float) return VFloat;
                    if (g->type.kind == TypeKind::Struct && !g->type.isPtr) return VAddr;
                    return VInt;
                }
            auto it = vars_.find(id->name);
            if (it != vars_.end()) {
                if (it->second.type.kind == TypeKind::Float) return VFloat;
                if (it->second.type.kind == TypeKind::Struct && !it->second.type.isPtr) return VAddr;
                return VInt;
            }
        }
        return VInt;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        for (auto& f : prog.functions) {
            if (f->name == c->name) {
                if (f->returnType.kind == TypeKind::Float) return VFloat;
                if (f->returnType.kind == TypeKind::String ||
                    f->returnType.kind == TypeKind::Struct || f->returnType.isPtr) return VAddr;
                return VInt;
            }
        }
        return VInt;
    }
    return VInt;
}

bool WasmBackend::exprHasValue(Expr* e) {
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        if (c->name == "exit" || c->name == "halt") return false;
        if (c->name == "print" || c->name == "println" || c->name == "sleep") return false;
        for (auto& f : prog.functions)
            if (f->name == c->name) return f->returnType.kind != TypeKind::Void;
        return true;
    }
    return true;
}

uint8_t WasmBackend::wasmTypeForKind(VK k) const {
    switch (k) {
        case VFloat: return WT_F32;
        case VAddr:  return WT_I32;
        default:     return WT_I64;
    }
}

// ====================================================================
// expression emission
// ====================================================================

void WasmBackend::emitMemberTail(int off, const Type& t) {
    // stack: base address (i32); leaves the member value
    if (t.kind == TypeKind::Float) {
        i32c(off); b8(0x6A);
        b8(0x2A); emitMemArg();          // f32.load
        return;
    }
    if (t.kind == TypeKind::Bool) {
        i32c(off); b8(0x6A);
        b8(0x34); emitMemArg();          // i64.load32_s
        return;
    }
    if (t.kind == TypeKind::Struct && !t.isPtr) {
        i32c(off); b8(0x6A);             // address of the nested block (VAddr)
        return;
    }
    i32c(off); b8(0x6A);
    b8(0x29); emitMemArg();              // i64.load
    if (t.kind == TypeKind::String || t.isPtr) wrapToI32();
}

void WasmBackend::emitMemberLoad(MemberExpr* m) {
    std::vector<std::string> path;
    Expr* cur = m;
    while (auto mm = dynamic_cast<MemberExpr*>(cur)) { path.push_back(mm->member); cur = mm->object.get(); }
    std::reverse(path.begin(), path.end());

    int totalOff = 0;
    Type curT;
    bool advanced = false;

    auto advancePath = [&](Type t) {
        Type ct = t;
        int off = 0;
        bool ok = true;
        for (size_t i = 0; ok && i < path.size(); i++) {
            if (ct.kind == TypeKind::Struct) {
                auto it = layouts_.find(ct.structName);
                if (it == layouts_.end()) { ok = false; break; }
                auto fo = it->second.fieldOffsets.find(path[i]);
                auto ft = it->second.fieldTypes.find(path[i]);
                if (fo == it->second.fieldOffsets.end() || ft == it->second.fieldTypes.end()) { ok = false; break; }
                off = fo->second;
                ct = ft->second;
            } else if (ct.kind == TypeKind::Vec2 || ct.kind == TypeKind::Vec3) {
                off = (path[i] == "y") ? 4 : (path[i] == "z" ? 8 : 0);
                ct = { TypeKind::Float };
            } else if (ct.kind == TypeKind::Color) {
                static const char* cols[4] = { "r", "g", "b", "a" };
                off = 0;
                for (int j = 0; j < 4; j++) if (cols[j] == path[i]) { off = j * 4; break; }
                ct = { TypeKind::Float };
            } else { ok = false; break; }
            totalOff += off;
        }
        curT = ct;
        return ok;
    };

    if (auto id = dynamic_cast<IdentExpr*>(cur)) {
        WasmVar v;
        bool found = false;
        auto it = vars_.find(id->name);
        if (it != vars_.end()) { v = it->second; found = true; }
        else {
            for (auto& g : prog.globals)
                if (g->name == id->name) {
                    v.globalAddr = globalAddr_[g->name];
                    v.type = g->type;
                    v.isGlobal = true;
                    found = true;
                    break;
                }
        }
        if (!found) throw std::runtime_error("wasm: unknown struct base '" + id->name + "'");
        if (!advancePath(v.type)) throw std::runtime_error("wasm: unknown member");
        advanced = true;
        bool isPtrRoot = v.type.isPtr && v.type.kind == TypeKind::Struct;
        if (isPtrRoot) {
            // object pointer: load the pointer from the cell, then dereference
            emitVarAddr(v);
            b8(0x29); emitMemArg();      // i64.load (the pointer)
            wrapToI32();                 // base address
        } else {
            emitVarAddr(v);              // base = address of the struct block
        }
        emitMemberTail(totalOff, curT);
        return;
    }

    // base is a dereference: *p.a.b
    if (auto deref = dynamic_cast<DerefExpr*>(cur)) {
        emitExpr(deref->ptr.get());      // pointer value
        if (exprKind(deref->ptr.get()) == VInt) wrapToI32();
        Type rootType;
        if (auto id = dynamic_cast<IdentExpr*>(deref->ptr.get())) {
            auto it = vars_.find(id->name);
            if (it != vars_.end()) rootType = it->second.type;
            else for (auto& g : prog.globals) if (g->name == id->name) { rootType = g->type; break; }
        }
        if (rootType.kind == TypeKind::Struct ||
            rootType.kind == TypeKind::Vec2 || rootType.kind == TypeKind::Vec3 ||
            rootType.kind == TypeKind::Color) {
            if (!advancePath(rootType)) throw std::runtime_error("wasm: unknown member");
        }
        if (!advanced) curT = { TypeKind::Int };
        emitMemberTail(totalOff, curT);
        return;
    }

    throw std::runtime_error("wasm: unsupported member access");
}

void WasmBackend::emitArrayLoad(ArrayAccessExpr* a) {
    auto id = dynamic_cast<IdentExpr*>(a->array.get());
    if (!id) throw std::runtime_error("wasm: unsupported array base");
    WasmVar v;
    bool found = false;
    auto it = vars_.find(id->name);
    if (it != vars_.end()) { v = it->second; found = true; }
    else {
        for (auto& g : prog.globals)
            if (g->name == id->name) { v.globalAddr = globalAddr_[g->name]; v.type = g->type; v.isGlobal = true; found = true; break; }
    }
    if (!found) throw std::runtime_error("wasm: unknown array '" + id->name + "'");
    int elemBytes = elemBytesOf(v.type);
    // address = base + idx*elemBytes
    emitVarAddr(v);
    emitExpr(a->index.get());
    wrapToI32();
    i32c(elemBytes);
    b8(0x6C);   // i32.mul
    b8(0x6A);   // i32.add
    if (v.type.kind == TypeKind::Float) {
        b8(0x2A); emitMemArg();          // f32.load
        return;
    }
    if (v.type.kind == TypeKind::Bool) {
        b8(0x34); emitMemArg();          // i64.load32_s
        return;
    }
    if (v.type.kind == TypeKind::Struct && !v.type.isPtr) {
        return;                          // address of the element (VAddr)
    }
    b8(0x29); emitMemArg();              // i64.load
    if (v.type.kind == TypeKind::String || v.type.isPtr) wrapToI32();
}

void WasmBackend::emitArrayStore(ArrayAccessExpr* a, Expr* value) {
    auto id = dynamic_cast<IdentExpr*>(a->array.get());
    if (!id) throw std::runtime_error("wasm: unsupported array base");
    WasmVar v;
    bool found = false;
    auto it = vars_.find(id->name);
    if (it != vars_.end()) { v = it->second; found = true; }
    else {
        for (auto& g : prog.globals)
            if (g->name == id->name) { v.globalAddr = globalAddr_[g->name]; v.type = g->type; v.isGlobal = true; found = true; break; }
    }
    if (!found) throw std::runtime_error("wasm: unknown array '" + id->name + "'");
    int elemBytes = elemBytesOf(v.type);
    emitVarAddr(v);
    emitExpr(a->index.get());
    wrapToI32();
    i32c(elemBytes);
    b8(0x6C);
    b8(0x6A);                            // addr
    if (v.type.kind == TypeKind::Struct && !v.type.isPtr) {
        emitExpr(value);                 // struct value: copy the block
        emitCopyValue(varBytes(v.type, 0));
        return;
    }
    emitExpr(value);                     // value
    if (v.type.kind == TypeKind::Float) {
        if (exprKind(value) == VInt) b8(0xB4);   // int -> float
        b8(0x38); emitMemArg();          // f32.store
    } else if (v.type.kind == TypeKind::Bool) {
        b8(0x3E); emitMemArg();          // i64.store32
    } else if (v.type.kind == TypeKind::String || v.type.isPtr) {
        if (exprKind(value) == VAddr) extendToI64();
        else wrapToI32(), extendToI64();
        b8(0x37); emitMemArg();          // i64.store
    } else {
        b8(0x37); emitMemArg();          // i64.store
    }
}

void WasmBackend::emitCallUser(const std::string& name, const std::vector<std::unique_ptr<Expr>>& args) {
    int idx = funcCallIndex(name);
    int n = (int)args.size();
    // reserve argument slots on the soft stack
    b8(0x23); uleb(0);                   // global.get $sp
    i32c(n * 8);
    b8(0x6B);                            // i32.sub
    b8(0x24); uleb(0);                   // global.set $sp
    for (int i = 0; i < n; i++) {
        // address of slot: sp + 8*i (wasm stores expect [addr, value])
        b8(0x23); uleb(0);
        i32c(8 * i);
        b8(0x6A);
        emitExpr(args[i].get());
        VK k = exprKind(args[i].get());
        if (k == VFloat) {
            b8(0x38); emitMemArg();      // f32.store
        } else {
            if (k == VAddr) extendToI64();
            b8(0x37); emitMemArg();      // i64.store
        }
    }
    b8(0x10); uleb((uint64_t)idx);       // call
    // release the argument slots
    b8(0x23); uleb(0);
    i32c(n * 8);
    b8(0x6A);
    b8(0x24); uleb(0);
}

void WasmBackend::emitCopyValue(int size) {
    // stack: [dst, src]
    i32c(size);
    b8(0x10); uleb((uint64_t)funcCallIndex("__zt_memcpy"));
}

void WasmBackend::emitCallExpr(CallExpr* c) {
    // ---- builtins ----
    if (c->name == "print" || c->name == "println") {
        if (c->args.size() == 1) {
            VK k = exprKind(c->args[0].get());
            if (auto s = dynamic_cast<StringExpr*>(c->args[0].get())) {
                int idx = ensureString(s->value);
                i32c(poolOffs_[idx]);
                b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_print_str"]);
            } else if (k == VFloat) {
                emitExpr(c->args[0].get());
                b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_print_float"]);
            } else if (k == VAddr) {
                emitExpr(c->args[0].get());
                b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_print_str"]);
            } else {
                emitExpr(c->args[0].get());
                b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_print_int"]);
            }
        }
        return;
    }
    if (c->name == "exit" && c->args.size() == 1) {
        emitExpr(c->args[0].get());
        wrapToI32();
        b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_exit"]);
        b8(0x00);                       // unreachable
        i64c(0);
        return;
    }
    if (c->name == "sleep" && c->args.size() == 1) {
        emitExpr(c->args[0].get());
        b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_sleep"]);
        return;
    }
    if (c->name == "halt" && c->args.empty()) {
        b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_halt"]);
        b8(0x00);                       // unreachable
        i64c(0);
        return;
    }
    if (c->name == "rdtsc" && c->args.empty()) {
        b8(0x10); uleb((uint64_t)importIdxOf_["env::zt_rdtsc"]);
        return;
    }
    if (c->name == "alloc" && c->args.size() == 1) {
        emitExpr(c->args[0].get());
        wrapToI32();
        b8(0x10); uleb((uint64_t)funcCallIndex("__zt_alloc"));
        extendToI64();
        return;
    }
    if (c->name == "free" && c->args.size() == 1) {
        emitExpr(c->args[0].get());     // evaluate (may have side effects)
        b8(0x1A);                       // drop (bump allocator: no-op)
        i64c(0);
        return;
    }
    // ---- abs: inline arithmetic (int: (v^(v>>63))-(v>>63); float: v<0 ? -v : v)
    if (c->name == "abs" && c->args.size() == 1) {
        VK k = exprKind(c->args[0].get());
        if (k == VFloat) {
            emitScratchAddr();                       // addr (bottom)
            emitExpr(c->args[0].get());              // value (top)
            b8(0x38); emitMemArg();                  // [scr]=v
            emitScratchAddr(); b8(0x2A); emitMemArg();   // v
            f32c(0.0f);
            b8(0x5D);                    // f32.lt (v < 0)
            pushBlock(-1);
            b8(0x04); b8(0x7D);          // if (f32)
            emitScratchAddr(); b8(0x2A); emitMemArg();   //   v
            b8(0x8C);                    //   f32.neg
            b8(0x05);                    // else
            emitScratchAddr(); b8(0x2A); emitMemArg();   //   v
            b8(0x0B); popBlock();        // end
        } else {
            // [scr]=v
            emitScratchAddr(); emitExpr(c->args[0].get()); b8(0x37); emitMemArg();
            // s = v>>63; [scr2]=s
            emitScratch2Addr();                      // addr (bottom)
            emitScratchAddr(); b8(0x29); emitMemArg();   // addr, v
            i64c(63); b8(0x87);                          // addr, s
            b8(0x37); emitMemArg();                  // [scr2]=s
            // result = (v^s)-s
            emitScratchAddr(); b8(0x29); emitMemArg();   // v
            emitScratch2Addr(); b8(0x29); emitMemArg();  // v, s
            b8(0x85);                                    // v^s
            emitScratch2Addr(); b8(0x29); emitMemArg();  // v^s, s
            b8(0x7D);                                    // (v^s)-s
        }
        return;
    }
    // ---- min/max/clamp: inline comparisons via the scratch cell ----
    if ((c->name == "min" || c->name == "max") && c->args.size() == 2) {
        bool isF = (exprKind(c->args[0].get()) == VFloat || exprKind(c->args[1].get()) == VFloat);
        uint8_t storeOp = isF ? 0x38 : 0x37;
        uint8_t loadOp  = isF ? 0x2A : 0x29;
        // min: (b > a) ? a : b     max: (b < a) ? a : b
        uint8_t cmpOp   = isF ? (c->name == "max" ? 0x5D : 0x5E)
                              : (c->name == "max" ? 0x53 : 0x55);
        // keep both candidates in the scratch cells, compare, load back
        emitScratchAddr();                       // addr (bottom)
        emitExpr(c->args[0].get());              // a (top)
        b8(storeOp); emitMemArg();               // [scr]=a
        emitScratch2Addr();                      // addr (bottom)
        emitExpr(c->args[1].get());              // b (top)
        b8(storeOp); emitMemArg();               // [scr2]=b
        emitScratch2Addr(); b8(loadOp); emitMemArg();   // b
        emitScratchAddr();  b8(loadOp); emitMemArg();   // b, a
        b8(cmpOp);                               // cond
        pushBlock(-1);
        b8(0x04); b8(isF ? 0x7D : 0x7E);                  // if (cond) -> i64/f32
        emitScratchAddr();  b8(loadOp); emitMemArg();   //   a
        b8(0x05);                                // else
        emitScratch2Addr(); b8(loadOp); emitMemArg();   //   b
        b8(0x0B); popBlock();                    // end
        return;
    }
    if (c->name == "clamp" && c->args.size() == 3) {
        bool isF = (exprKind(c->args[0].get()) == VFloat ||
                    exprKind(c->args[1].get()) == VFloat ||
                    exprKind(c->args[2].get()) == VFloat);
        uint8_t storeOp = isF ? 0x38 : 0x37;
        uint8_t loadOp  = isF ? 0x2A : 0x29;
        uint8_t ltOp    = isF ? 0x5D : 0x53;   // f32.lt / i64.lt_s
        // stage 1: max(x, lo) -> [scr]
        emitScratchAddr();                       // addr (bottom)
        emitExpr(c->args[0].get());              // x (top)
        b8(storeOp); emitMemArg();               // [scr]=x
        emitScratch2Addr();                      // addr (bottom)
        emitExpr(c->args[1].get());              // lo (top)
        b8(storeOp); emitMemArg();               // [scr2]=lo
        emitScratch2Addr(); b8(loadOp); emitMemArg();   // lo
        emitScratchAddr();  b8(loadOp); emitMemArg();   // lo, x
        b8(ltOp);                                // cond
        pushBlock(-1);
        b8(0x04); b8(0x40);                      // if (lo<x): [scr] already = x
        b8(0x05);                                // else
        emitScratchAddr();                       // addr
        emitScratch2Addr(); b8(loadOp); emitMemArg();   // addr, lo
        b8(storeOp); emitMemArg();               // [scr]=lo
        b8(0x0B); popBlock();                    // end   -> [scr]=max
        // stage 2: min(max, hi) -> [scr]
        emitScratch2Addr();                      // addr (bottom)
        emitExpr(c->args[2].get());              // hi (top)
        b8(storeOp); emitMemArg();               // [scr2]=hi
        emitScratch2Addr(); b8(loadOp); emitMemArg();   // hi
        emitScratchAddr();  b8(loadOp); emitMemArg();   // hi, max
        b8(ltOp);                                // cond
        pushBlock(-1);
        b8(0x04); b8(0x40);                      // if (hi<max)
        emitScratchAddr();                       // addr
        emitScratch2Addr(); b8(loadOp); emitMemArg();   // addr, hi
        b8(storeOp); emitMemArg();               // [scr]=hi
        b8(0x0B); popBlock();                    // end   -> [scr]=min
        emitScratchAddr(); b8(loadOp); emitMemArg();   // result
        return;
    }
    // ---- memory peek/poke ----
    if (c->name == "peek8" && c->args.size() == 1) {
        emitExpr(c->args[0].get()); wrapToI32();
        b8(0x2F); emitMemArg();         // i64.load8_u
        return;
    }
    if (c->name == "peek16" && c->args.size() == 1) {
        emitExpr(c->args[0].get()); wrapToI32();
        b8(0x30); emitMemArg();         // i64.load16_u
        return;
    }
    if (c->name == "peek32" && c->args.size() == 1) {
        emitExpr(c->args[0].get()); wrapToI32();
        b8(0x35); emitMemArg();         // i64.load32_u
        return;
    }
    if ((c->name == "peek" || c->name == "peek64") && c->args.size() == 1) {
        emitExpr(c->args[0].get()); wrapToI32();
        b8(0x29); emitMemArg();         // i64.load
        return;
    }
    if (c->name == "poke8" && c->args.size() == 2) {
        emitExpr(c->args[0].get()); wrapToI32();
        emitExpr(c->args[1].get());
        b8(0x3A); emitMemArg();         // i64.store8
        i64c(0);
        return;
    }
    if (c->name == "poke16" && c->args.size() == 2) {
        emitExpr(c->args[0].get()); wrapToI32();
        emitExpr(c->args[1].get());
        b8(0x3B); emitMemArg();         // i64.store16
        i64c(0);
        return;
    }
    if (c->name == "poke32" && c->args.size() == 2) {
        emitExpr(c->args[0].get()); wrapToI32();
        emitExpr(c->args[1].get());
        b8(0x3E); emitMemArg();         // i64.store32
        i64c(0);
        return;
    }
    if ((c->name == "poke" || c->name == "poke64") && c->args.size() == 2) {
        emitExpr(c->args[0].get()); wrapToI32();
        emitExpr(c->args[1].get());
        b8(0x37); emitMemArg();         // i64.store
        i64c(0);
        return;
    }
    // ---- extern functions -> wasm imports ----
    for (auto& f : prog.functions) {
        if (f->isExtern && f->name == c->name) {
            int idx = importIdxOf_["env::" + c->name];
            for (auto& a : c->args) emitExpr(a.get());
            b8(0x10); uleb((uint64_t)idx);
            return;
        }
    }
    // ---- user function ----
    for (auto& f : prog.functions) {
        if (!f->isExtern && f->name == c->name) {
            emitCallUser(c->name, c->args);
            return;
        }
    }
    throw std::runtime_error("wasm: unsupported builtin/function '" + c->name + "'");
}

void WasmBackend::emitExpr(Expr* e) {
    if (auto n = dynamic_cast<NumberExpr*>(e)) {
        i64c(n->value);
        return;
    }
    if (auto fl = dynamic_cast<FloatExpr*>(e)) {
        f32c((float)fl->value);
        return;
    }
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        int idx = ensureString(s->value);
        i32c(poolOffs_[idx]);
        return;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto it = vars_.find(id->name);
        if (it != vars_.end()) {
            emitVarAddr(it->second);
            const Type& t = it->second.type;
            if (t.kind == TypeKind::Float) { b8(0x2A); emitMemArg(); return; }
            if (t.kind == TypeKind::Bool)  { b8(0x34); emitMemArg(); return; }  // i64.load32_s
            if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) {
                if (t.kind == TypeKind::Struct && !t.isPtr) return;   // address of the block
                b8(0x29); emitMemArg();
                wrapToI32();
                return;
            }
            b8(0x29); emitMemArg();        // i64.load
            return;
        }
        for (auto& g : prog.globals)
            if (g->name == id->name) {
                emitGlobalAddr(id->name);
                const Type& t = g->type;
                if (t.kind == TypeKind::Float) { b8(0x2A); emitMemArg(); return; }
                if (t.kind == TypeKind::Bool)  { b8(0x34); emitMemArg(); return; }
                if (t.kind == TypeKind::String || t.kind == TypeKind::Struct || t.isPtr) {
                    if (t.kind == TypeKind::Struct && !t.isPtr) return;   // address of the block
                    b8(0x29); emitMemArg();
                    wrapToI32();
                    return;
                }
                b8(0x29); emitMemArg();
                return;
            }
        throw std::runtime_error("wasm: unknown variable '" + id->name + "'");
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        VK k = exprKind(u->operand.get());
        if (u->op == "-") {
            emitExpr(u->operand.get());
            if (k == VFloat) b8(0x8C);         // f32.neg
            else b8(0x8B);                     // i64.neg
            return;
        }
        if (u->op == "!") {
            emitCond(u->operand.get());
            extendToI64();
            return;
        }
        if (u->op == "~") {
            emitExpr(u->operand.get());
            i64c(-1);
            b8(0x85);                          // i64.xor
            return;
        }
        throw std::runtime_error("wasm: unsupported unary operator '" + u->op + "'");
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        const std::string& op = bin->op;
        if (op == "&&" || op == "||") {
            if (op == "&&") {
                emitCond(bin->left.get());
                pushBlock(-1);
                b8(0x04); b8(0x40);            // if
                emitCond(bin->right.get());
                b8(0x05);                      // else
                b8(0x41); sleb(0);             // i32.const 0
                b8(0x0B);                      // end
                popBlock();
            } else {
                emitCond(bin->left.get());
                pushBlock(-1);
                b8(0x04); b8(0x40);            // if
                b8(0x41); sleb(1);             // i32.const 1
                b8(0x05);                      // else
                emitCond(bin->right.get());
                b8(0x0B);                      // end
                popBlock();
            }
            extendToI64();
            return;
        }
        bool isCmp = (op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=");
        VK lk = exprKind(bin->left.get());
        VK rk = exprKind(bin->right.get());
        bool isF = (lk == VFloat || rk == VFloat);
        emitExpr(bin->left.get());
        if (isCmp && lk == VAddr) extendToI64();
        if (isF && lk == VInt) { b8(0xB4); }   // f32.convert_i64_s
        emitExpr(bin->right.get());
        if (isCmp && rk == VAddr) extendToI64();
        if (isF && rk == VInt) { b8(0xB4); }
        if (isF) {
            if (op == "+") { b8(0x92); return; }
            if (op == "-") { b8(0x93); return; }
            if (op == "*") { b8(0x94); return; }
            if (op == "/") { b8(0x95); return; }
            if (isCmp) {
                uint8_t c = 0;
                if (op == "==") c = 0x5B; else if (op == "!=") c = 0x5C;
                else if (op == "<") c = 0x5D; else if (op == ">") c = 0x5E;
                else if (op == "<=") c = 0x5F; else c = 0x60;
                b8(c);
                extendToI64();
                return;
            }
            throw std::runtime_error("wasm: unsupported float operator '" + op + "'");
        }
        if (isCmp) {
            uint8_t c = 0;
            if (op == "==") c = 0x51; else if (op == "!=") c = 0x52;
            else if (op == "<") c = 0x53; else if (op == ">") c = 0x55;
            else if (op == "<=") c = 0x57; else c = 0x59;
            b8(c);
            extendToI64();
            return;
        }
        if (op == "+") { b8(0x7C); return; }
        if (op == "-") { b8(0x7D); return; }
        if (op == "*") { b8(0x7E); return; }
        if (op == "/") { b8(0x7F); return; }   // i64.div_s
        if (op == "%" || op == "//") { b8(0x81); return; }   // i64.rem_s
        if (op == "&") { b8(0x83); return; }
        if (op == "|") { b8(0x84); return; }
        if (op == "^") { b8(0x85); return; }
        if (op == "<<") { b8(0x86); return; }  // i64.shl
        if (op == ">>") { b8(0x88); return; }  // i64.shr_u (matches the x86 backend)
        throw std::runtime_error("wasm: unsupported binary operator '" + op + "'");
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        emitMemberLoad(m);
        return;
    }
    if (auto d = dynamic_cast<DerefExpr*>(e)) {
        emitExpr(d->ptr.get());
        if (exprKind(d->ptr.get()) == VInt) wrapToI32();
        b8(0x29); emitMemArg();                // i64.load
        return;
    }
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
        auto it = vars_.find(a->name);
        if (it != vars_.end()) {
            emitVarAddr(it->second);
            return;
        }
        for (auto& g : prog.globals)
            if (g->name == a->name) { emitGlobalAddr(a->name); return; }
        throw std::runtime_error("wasm: unknown variable '" + a->name + "'");
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        emitArrayLoad(arr);
        return;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        emitCallExpr(c);
        return;
    }
    throw std::runtime_error("wasm: unsupported expression");
}

void WasmBackend::emitCond(Expr* e) {
    VK k = exprKind(e);
    emitExpr(e);
    if (k == VFloat) {
        f32c(0.0f);
        b8(0x5C);                            // f32.ne
    } else if (k == VAddr) {
        i32c(0);
        b8(0x47);                            // i32.ne
    } else {
        i64c(0);
        b8(0x52);                            // i64.ne
    }
}

// ====================================================================
// statements
// ====================================================================

void WasmBackend::collectLocalsBlock(const std::vector<std::unique_ptr<Stmt>>& stmts) {
    for (auto& s : stmts) collectLocals(s.get());
}

void WasmBackend::collectLocals(Stmt* s) {
    if (auto vd = dynamic_cast<VarDecl*>(s)) {
        int size = varBytes(vd->type, vd->arraySize);
        size = (size + 7) & ~7;
        WasmVar v;
        v.off = frame_;
        v.type = vd->type;
        v.arraySize = vd->arraySize;
        vars_[vd->name] = v;
        frame_ += size;
        return;
    }
    if (auto f = dynamic_cast<ForStmt*>(s)) {
        // the loop counter is an implicit int local
        WasmVar v;
        v.off = frame_;
        v.type = { TypeKind::Int };
        v.arraySize = 0;
        vars_[f->varName] = v;
        frame_ += 8;
        collectLocalsBlock(f->body.stmts);
        return;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        collectLocalsBlock(ifs->thenBlock.stmts);
        collectLocalsBlock(ifs->elseBlock.stmts);
        return;
    }
    if (auto w = dynamic_cast<WhileStmt*>(s)) {
        collectLocalsBlock(w->body.stmts);
        return;
    }
    if (auto l = dynamic_cast<LoopStmt*>(s)) {
        collectLocalsBlock(l->body.stmts);
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        for (auto& c : sw->cases) collectLocalsBlock(c.body.stmts);
        return;
    }
}

void WasmBackend::emitAssign(AssignStmt* as) {
    // a[i] = v
    if (as->indexExpr) {
        WasmVar v;
        bool found = false;
        auto it = vars_.find(as->name);
        if (it != vars_.end()) { v = it->second; found = true; }
        else {
            for (auto& g : prog.globals)
                if (g->name == as->name) { v.globalAddr = globalAddr_[g->name]; v.type = g->type; v.isGlobal = true; found = true; break; }
        }
        if (!found) throw std::runtime_error("wasm: unknown variable '" + as->name + "'");
        int elemBytes = elemBytesOf(v.type);
        emitVarAddr(v);
        emitExpr(as->indexExpr.get());
        wrapToI32();
        i32c(elemBytes);
        b8(0x6C);
        b8(0x6A);
        if (v.type.kind == TypeKind::Struct && !v.type.isPtr) {
            emitExpr(as->value.get());
            emitCopyValue(varBytes(v.type, 0));
            return;
        }
        emitExpr(as->value.get());
        if (v.type.kind == TypeKind::Float) {
            if (exprKind(as->value.get()) == VInt) b8(0xB4);   // int -> float
            b8(0x38); emitMemArg();        // f32.store
        } else if (v.type.kind == TypeKind::Bool) {
            b8(0x3E); emitMemArg();        // i64.store32
        } else {
            if (exprKind(as->value.get()) == VAddr) extendToI64();
            b8(0x37); emitMemArg();        // i64.store
        }
        return;
    }

    // s.field = v
    if (!as->memberPath.empty()) {
        WasmVar v;
        bool found = false;
        auto it = vars_.find(as->name);
        if (it != vars_.end()) { v = it->second; found = true; }
        else {
            for (auto& g : prog.globals)
                if (g->name == as->name) { v.globalAddr = globalAddr_[g->name]; v.type = g->type; v.isGlobal = true; found = true; break; }
        }
        if (!found) throw std::runtime_error("wasm: unknown member target '" + as->name + "'");
        bool isPtrRoot = v.type.isPtr && v.type.kind == TypeKind::Struct;
        int totalOff = 0;
        Type curT = v.type;
        for (auto& p : as->memberPath) {
            bool ok = false;
            if (curT.kind == TypeKind::Struct) {
                auto lit = layouts_.find(curT.structName);
                if (lit != layouts_.end()) {
                    auto fo = lit->second.fieldOffsets.find(p);
                    auto ft = lit->second.fieldTypes.find(p);
                    if (fo != lit->second.fieldOffsets.end() && ft != lit->second.fieldTypes.end()) {
                        totalOff += fo->second;
                        curT = ft->second;
                        ok = true;
                    }
                }
            } else if (curT.kind == TypeKind::Vec2 || curT.kind == TypeKind::Vec3) {
                totalOff += (p == "y") ? 4 : (p == "z" ? 8 : 0);
                curT = { TypeKind::Float };
                ok = true;
            } else if (curT.kind == TypeKind::Color) {
                static const char* cols[4] = { "r", "g", "b", "a" };
                for (int j = 0; j < 4; j++) if (cols[j] == p) { totalOff += j * 4; break; }
                curT = { TypeKind::Float };
                ok = true;
            }
            if (!ok) throw std::runtime_error("wasm: unknown member '" + p + "' of '" + as->name + "'");
        }
        // base address
        if (isPtrRoot) {
            emitVarAddr(v);
            b8(0x29); emitMemArg();        // i64.load (the pointer)
            wrapToI32();
        } else {
            emitVarAddr(v);
        }
        i32c(totalOff);
        b8(0x6A);
        if (curT.kind == TypeKind::Struct && !curT.isPtr) {
            emitExpr(as->value.get());
            emitCopyValue(varBytes(curT, 0));
            return;
        }
        emitExpr(as->value.get());
        if (curT.kind == TypeKind::Float) {
            if (exprKind(as->value.get()) == VInt) b8(0xB4);   // int -> float
            b8(0x38); emitMemArg();        // f32.store
        } else if (curT.kind == TypeKind::Bool) {
            b8(0x3E); emitMemArg();        // i64.store32
        } else {
            if (exprKind(as->value.get()) == VAddr) extendToI64();
            b8(0x37); emitMemArg();        // i64.store
        }
        return;
    }

    // plain var = v
    auto it = vars_.find(as->name);
    if (it != vars_.end()) {
        emitVarAddr(it->second);
        const Type& t = it->second.type;
        if (t.kind == TypeKind::Float) {
            emitExpr(as->value.get());
            if (exprKind(as->value.get()) == VInt) b8(0xB4);   // int -> float
            b8(0x38); emitMemArg();
        } else if (t.kind == TypeKind::Bool) {
            emitExpr(as->value.get());
            b8(0x3E); emitMemArg();        // i64.store32
        } else if (t.kind == TypeKind::Struct && !t.isPtr) {
            emitExpr(as->value.get());
            emitCopyValue(varBytes(t, 0));
        } else if (t.kind == TypeKind::String || t.isPtr) {
            emitExpr(as->value.get());
            if (exprKind(as->value.get()) == VAddr) extendToI64();
            else wrapToI32(), extendToI64();
            b8(0x37); emitMemArg();
        } else {
            emitExpr(as->value.get());
            b8(0x37); emitMemArg();        // i64.store
        }
        return;
    }
    for (auto& g : prog.globals)
        if (g->name == as->name) {
            emitGlobalAddr(as->name);
            const Type& t = g->type;
            if (t.kind == TypeKind::Float) {
                emitExpr(as->value.get());
                if (exprKind(as->value.get()) == VInt) b8(0xB4);
                b8(0x38); emitMemArg();
            } else if (t.kind == TypeKind::Bool) {
                emitExpr(as->value.get());
                b8(0x3E); emitMemArg();
            } else if (t.kind == TypeKind::Struct && !t.isPtr) {
                emitExpr(as->value.get());
                emitCopyValue(varBytes(t, 0));
            } else if (t.kind == TypeKind::String || t.isPtr) {
                emitExpr(as->value.get());
                if (exprKind(as->value.get()) == VAddr) extendToI64();
                else wrapToI32(), extendToI64();
                b8(0x37); emitMemArg();
            } else {
                emitExpr(as->value.get());
                b8(0x37); emitMemArg();
            }
            return;
        }
    throw std::runtime_error("wasm: unknown variable '" + as->name + "'");
}

void WasmBackend::emitReturn(ReturnStmt* r) {
    if (r->value) {
        VK k = exprKind(r->value.get());
        emitExpr(r->value.get());
        if (funcRetType_ == WT_F32 && k == VInt) b8(0xB4);        // int -> float
        if (funcRetType_ == WT_I32 && k == VInt) wrapToI32();     // int -> addr
        if (funcRetType_ == WT_I64 && k == VAddr) extendToI64();  // addr -> int
        if (funcRetType_ == WT_I64 && k == VFloat) b8(0xA9);      // float -> int (trunc)
    } else if (funcRetType_) {
        if (funcRetType_ == WT_F32) f32c(0.0f);
        else if (funcRetType_ == WT_I32) i32c(0);
        else i64c(0);
    }
    // restore the locals area (epilogue): reload $fp, then free the frame
    b8(0x23); uleb(2);                 // global.get $fp
    i32c(16);
    b8(0x6A);                          // saved-fp slot address
    b8(0x28); emitMemArg();            // i32.load (old $fp)
    b8(0x24); uleb(2);                 // global.set $fp
    b8(0x23); uleb(0);                 // global.get $sp
    i32c(localsSize_);
    b8(0x6A);                          // i32.add
    b8(0x24); uleb(0);                 // global.set $sp
    b8(0x0F);                          // return
}

void WasmBackend::emitStmt(Stmt* s) {
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) { emitReturn(ret); return; }
    if (auto vd = dynamic_cast<VarDecl*>(s)) {
        if (vd->init) {
            auto it = vars_.find(vd->name);
            if (it == vars_.end()) throw std::runtime_error("wasm: internal var decl");
            WasmVar v = it->second;
            if (v.type.kind == TypeKind::Float) {
                emitVarAddr(v);
                emitExpr(vd->init.get());
                if (exprKind(vd->init.get()) == VInt) b8(0xB4);
                b8(0x38); emitMemArg();
            } else if (v.type.kind == TypeKind::Bool) {
                emitVarAddr(v);
                emitExpr(vd->init.get());
                b8(0x3E); emitMemArg();
            } else if (v.type.kind == TypeKind::Struct && !v.type.isPtr) {
                emitVarAddr(v);
                emitExpr(vd->init.get());
                emitCopyValue(varBytes(v.type, 0));
            } else if (v.type.kind == TypeKind::String || v.type.isPtr) {
                emitVarAddr(v);
                emitExpr(vd->init.get());
                if (exprKind(vd->init.get()) == VAddr) extendToI64();
                else wrapToI32(), extendToI64();
                b8(0x37); emitMemArg();
            } else {
                emitVarAddr(v);
                emitExpr(vd->init.get());
                b8(0x37); emitMemArg();
            }
        } else if (vd->type.kind == TypeKind::Struct && !vd->type.isPtr && vd->arraySize == 0) {
            // stamp the runtime class id for class-typed locals
            auto cidIt = prog.classIDs.find(vd->type.structName);
            if (cidIt != prog.classIDs.end()) {
                auto it = vars_.find(vd->name);
                emitVarAddr(it->second);
                i64c(cidIt->second);
                b8(0x37); emitMemArg();
            }
        }
        return;
    }
    if (auto ex = dynamic_cast<ExprStmt*>(s)) {
        emitExpr(ex->expr.get());
        if (exprHasValue(ex->expr.get())) b8(0x1A);   // drop
        return;
    }
    if (auto as = dynamic_cast<AssignStmt*>(s)) { emitAssign(as); return; }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        emitExpr(pa->ptr.get());
        if (exprKind(pa->ptr.get()) == VInt) wrapToI32();
        emitExpr(pa->value.get());
        b8(0x37); emitMemArg();          // i64.store (ptr is treated as int pointer)
        return;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        emitCond(ifs->condition.get());
        pushBlock(-1);
        b8(0x04); b8(0x40);              // if
        for (auto& st : ifs->thenBlock.stmts) emitStmt(st.get());
        if (!ifs->elseBlock.stmts.empty()) {
            b8(0x05);                    // else
            for (auto& st : ifs->elseBlock.stmts) emitStmt(st.get());
        }
        b8(0x0B);                        // end
        popBlock();
        return;
    }
    if (auto w = dynamic_cast<WhileStmt*>(s)) {
        int exitL = newLabel();
        int topL = newLabel();
        b8(0x02); b8(0x40); pushBlock(exitL);   // block $exit
        b8(0x03); b8(0x40); pushBlock(topL);    // loop $top
        emitCond(w->condition.get());
        b8(0x45);                                    // i32.eqz (exit when false)
        b8(0x0D); uleb((uint64_t)brDepth(exitL));    // br_if $exit
        breakStack_.push_back(exitL);
        continueStack_.push_back(topL);
        for (auto& st : w->body.stmts) emitStmt(st.get());
        breakStack_.pop_back();
        continueStack_.pop_back();
        b8(0x0C); uleb((uint64_t)brDepth(topL));    // br $top
        b8(0x0B); popBlock();                       // end loop
        b8(0x0B); popBlock();                       // end block
        return;
    }
    if (auto l = dynamic_cast<LoopStmt*>(s)) {
        int exitL = newLabel();
        int topL = newLabel();
        b8(0x02); b8(0x40); pushBlock(exitL);
        b8(0x03); b8(0x40); pushBlock(topL);
        breakStack_.push_back(exitL);
        continueStack_.push_back(topL);
        for (auto& st : l->body.stmts) emitStmt(st.get());
        breakStack_.pop_back();
        continueStack_.pop_back();
        b8(0x0C); uleb((uint64_t)brDepth(topL));
        b8(0x0B); popBlock();
        b8(0x0B); popBlock();
        return;
    }
    if (auto f = dynamic_cast<ForStmt*>(s)) {
        auto it = vars_.find(f->varName);
        if (it == vars_.end()) throw std::runtime_error("wasm: internal for var");
        WasmVar v = it->second;
        // i = start
        emitVarAddr(v);
        emitExpr(f->start.get());
        b8(0x37); emitMemArg();
        int exitL = newLabel();
        int topL = newLabel();
        int contL = newLabel();
        b8(0x02); b8(0x40); pushBlock(exitL);   // block $exit
        b8(0x03); b8(0x40); pushBlock(topL);    // loop $top
        // condition: step >= 0 ? (i < end) : (i > end). The step (and end) may
        // be arbitrary expressions, evaluated fresh each iteration.
        emitVarAddr(v);
        b8(0x29); emitMemArg();                 // i64.load i
        emitVarAddr(v);
        b8(0x29); emitMemArg();                 // i64.load i (second copy)
        emitExpr(f->end.get());
        emitExpr(f->end.get());
        b8(0x53);                               // i64.lt_s : i < end
        b8(0x55);                               // i64.gt_s : i > end
        if (f->step) emitExpr(f->step.get());
        else i64c(1);
        i64c(0);
        b8(0x59);                               // i64.ge_s : step >= 0
        b8(0xA7);                               // i32.wrap (select cond)
        b8(0x1B);                               // select lt/gt result
        b8(0x45);                               // i32.eqz (exit when done)
        b8(0x0D); uleb((uint64_t)brDepth(exitL));   // br_if $exit
        breakStack_.push_back(exitL);
        continueStack_.push_back(contL);
        b8(0x02); b8(0x40); pushBlock(contL);   // block $cont (wraps the body)
        for (auto& st : f->body.stmts) emitStmt(st.get());
        b8(0x0B); popBlock();                   // end $cont
        breakStack_.pop_back();
        continueStack_.pop_back();
        // continue lands here: increment, then loop
        emitVarAddr(v);
        emitVarAddr(v);
        b8(0x29); emitMemArg();                 // load i
        if (f->step) emitExpr(f->step.get());
        else i64c(1);
        b8(0x7C);                               // i64.add
        b8(0x37); emitMemArg();                 // store
        b8(0x0C); uleb((uint64_t)brDepth(topL));    // br $top
        b8(0x0B); popBlock();                   // end loop
        b8(0x0B); popBlock();                   // end block
        return;
    }
    if (auto b = dynamic_cast<BreakStmt*>(s)) {
        if (breakStack_.empty()) throw std::runtime_error("wasm: break outside loop");
        b8(0x0C); uleb((uint64_t)brDepth(breakStack_.back()));
        return;
    }
    if (auto c = dynamic_cast<ContinueStmt*>(s)) {
        if (continueStack_.empty()) throw std::runtime_error("wasm: continue outside loop");
        b8(0x0C); uleb((uint64_t)brDepth(continueStack_.back()));
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        int exitL = newLabel();
        // evaluate the condition once into the scratch cell
        emitScratchAddr();                       // addr (bottom)
        emitExpr(sw->condition.get());           // cond (top)
        b8(0x37); emitMemArg();                 // [scr] = cond
        b8(0x02); b8(0x40); pushBlock(exitL);
        breakStack_.push_back(exitL);
        int defaultIdx = -1;
        for (size_t i = 0; i < sw->cases.size(); i++)
            if (!sw->cases[i].condition) defaultIdx = (int)i;
        for (size_t i = 0; i < sw->cases.size(); i++) {
            if ((int)i == defaultIdx) continue;
            // if (cond == caseVal) { body; br $exit }
            emitScratchAddr();
            b8(0x29); emitMemArg();             // load cond
            emitExpr(sw->cases[i].condition.get());
            b8(0x51);                           // i64.eq
            pushBlock(-1);
            b8(0x04); b8(0x40);                 // if
            for (auto& st : sw->cases[i].body.stmts) emitStmt(st.get());
            b8(0x0C); uleb((uint64_t)brDepth(exitL));
            b8(0x0B);                           // end if
            popBlock();
        }
        if (defaultIdx >= 0) {
            for (auto& st : sw->cases[defaultIdx].body.stmts) emitStmt(st.get());
        }
        b8(0x0B); popBlock();                   // end block
        breakStack_.pop_back();
        return;
    }
    throw std::runtime_error("wasm: unsupported statement");
}

// ====================================================================
// function emission
// ====================================================================

void WasmBackend::emitUserFunction(FunctionDecl* f) {
    code_.clear();
    vars_.clear();
    frame_ = 24;                    // scratch cells (0, 8) + saved $fp slot (16) + padding
    scratchOff_ = 0;
    nparams_ = (int)f->params.size();
    for (auto& stmt : f->body.stmts) collectLocals(stmt.get());
    localsSize_ = (frame_ + 7) & ~7;
    // parameters live in the caller's argument slots: [SP + localsSize + 8*i]
    for (int i = 0; i < nparams_; i++) {
        WasmVar v;
        v.off = localsSize_ + 8 * i;
        v.type = f->params[i].type;
        vars_[f->params[i].name] = v;
    }

    if (f->returnType.kind == TypeKind::Void) funcRetType_ = 0;
    else if (f->returnType.kind == TypeKind::Float) funcRetType_ = WT_F32;
    else if (f->returnType.kind == TypeKind::String ||
             f->returnType.kind == TypeKind::Struct || f->returnType.isPtr) funcRetType_ = WT_I32;
    else funcRetType_ = WT_I64;

    b8(0x00);                      // no wasm locals declared (vars live on the soft stack)

    // prologue: allocate the locals area (below the argument slots)
    b8(0x23); uleb(0);             // global.get $sp
    i32c(localsSize_);
    b8(0x6B);                      // i32.sub
    b8(0x24); uleb(0);             // global.set $sp
    // save the caller's $fp at [fp + 16] before rebasing
    b8(0x23); uleb(0);             // global.get $sp
    i32c(16);
    b8(0x6A);                      // slot address
    b8(0x23); uleb(2);             // old $fp (still intact)
    b8(0x36); emitMemArg();        // i32.store
    b8(0x23); uleb(0);             // global.get $sp
    b8(0x24); uleb(2);             // global.set $fp   (stable frame base)

    for (auto& stmt : f->body.stmts) emitStmt(stmt.get());

    // implicit return (functions with a result must always return a value)
    if (funcRetType_) {
        if (funcRetType_ == WT_F32) f32c(0.0f);
        else if (funcRetType_ == WT_I32) i32c(0);
        else i64c(0);
    }
    // epilogue: reload $fp, then deallocate the locals area
    b8(0x23); uleb(2);
    i32c(16);
    b8(0x6A);
    b8(0x28); emitMemArg();          // i32.load (old $fp)
    b8(0x24); uleb(2);               // global.set $fp
    b8(0x23); uleb(0);
    i32c(localsSize_);
    b8(0x6A);
    b8(0x24); uleb(0);
    b8(0x0F);                      // return
    b8(0x0B);                      // end of body

    funcs_[funcIdxOf_[f->name]].body = code_;
}

void WasmBackend::emitZtAlloc() {
    // (i32 size) -> i32; locals: 2 x i32
    // result = cur; heap_end = cur + (size + 7) & ~7
    code_.clear();
    b8(0x02); b8(0x01); b8(WT_I32); b8(0x01); b8(WT_I32);   // 2 x i32 locals
    b8(0x20); uleb(0);                // local.get 0 (size)
    b8(0x41); sleb(7);
    b8(0x6A);                         // size + 7
    b8(0x41); sleb(-8);
    b8(0x71);                         // & -8
    b8(0x23); uleb(1);                // global.get $heap_end
    b8(0x22); uleb(1);                // local.tee 1 (cur)
    b8(0x6A);                         // cur + size8
    b8(0x24); uleb(1);                // global.set $heap_end
    b8(0x20); uleb(1);                // local.get 1 (cur = result)
    b8(0x0B);                         // end
    funcs_[funcIdxOf_["__zt_alloc"]].body = code_;
}

void WasmBackend::emitZtMemcpy() {
    // (i32 dst, i32 src, i32 size) -> void; locals: 4 x i32
    // byte-wise forward copy loop
    code_.clear();
    b8(0x04); b8(0x01); b8(WT_I32); b8(0x01); b8(WT_I32);
    b8(0x01); b8(WT_I32); b8(0x01); b8(WT_I32);             // 4 x i32 locals
    b8(0x02); b8(0x40);               // block $done
    b8(0x03); b8(0x40);               // loop $top
    b8(0x20); uleb(3);                //   local.get 3 (i)
    b8(0x20); uleb(2);                //   local.get 2 (size)
    b8(0x4F);                         //   i32.ge_u
    b8(0x0D); uleb(1);                //   br_if 1 ($done)
    b8(0x20); uleb(0);                //   local.get 0 (dst)
    b8(0x20); uleb(3);                //   local.get 3
    b8(0x6A);                         //   dst + i
    b8(0x20); uleb(1);                //   local.get 1 (src)
    b8(0x20); uleb(3);                //   local.get 3
    b8(0x6A);                         //   src + i
    b8(0x2D); emitMemArg();           //   i32.load8_u
    b8(0x3A); emitMemArg();           //   i32.store8
    b8(0x20); uleb(3);                //   local.get 3
    b8(0x41); sleb(1);
    b8(0x6A);                         //   i + 1
    b8(0x21); uleb(3);                //   local.set 3
    b8(0x0C); uleb(0);                //   br 0 ($top)
    b8(0x0B);                         // end loop
    b8(0x0B);                         // end block
    b8(0x0B);                         // end body
    funcs_[funcIdxOf_["__zt_memcpy"]].body = code_;
}

// ====================================================================
// module assembly
// ====================================================================

void WasmBackend::buildModule(std::vector<uint8_t>& out) {
    auto section = [&](uint8_t id, const std::vector<uint8_t>& payload) {
        out.push_back(id);
        uint64_t size = payload.size();
        do { uint8_t c = size & 0x7F; size >>= 7; if (size) c |= 0x80; out.push_back(c); } while (size);
        out.insert(out.end(), payload.begin(), payload.end());
    };
    std::vector<uint8_t> sec;

    // ---- type section ----
    sec.clear();
    sec.push_back((uint8_t)typePool_.size());
    for (auto& t : typePool_) {
        sec.push_back(0x60);                    // functype
        sec.push_back((uint8_t)t.params.size());
        for (uint8_t p : t.params) sec.push_back(p);
        if (t.result) { sec.push_back(1); sec.push_back(t.result); }
        else sec.push_back(0);
    }
    section(1, sec);

    // ---- import section ----
    sec.clear();
    sec.push_back((uint8_t)imports_.size());
    for (auto& imp : imports_) {
        sec.push_back((uint8_t)imp.module.size());
        sec.insert(sec.end(), imp.module.begin(), imp.module.end());
        sec.push_back((uint8_t)imp.name.size());
        sec.insert(sec.end(), imp.name.begin(), imp.name.end());
        sec.push_back(0x00);                    // func
        uint64_t ti = imp.typeIdx;
        do { uint8_t c = ti & 0x7F; ti >>= 7; if (ti) c |= 0x80; sec.push_back(c); } while (ti);
    }
    section(2, sec);

    // ---- function section ----
    sec.clear();
    sec.push_back((uint8_t)funcs_.size());
    for (auto& f : funcs_) {
        uint64_t ti = f.typeIdx;
        do { uint8_t c = ti & 0x7F; ti >>= 7; if (ti) c |= 0x80; sec.push_back(c); } while (ti);
    }
    section(3, sec);

    // ---- memory section ----
    sec.clear();
    sec.push_back(1);                    // count
    sec.push_back(0x00);                 // limits: min only
    uint64_t pages = memPages_;
    do { uint8_t c = pages & 0x7F; pages >>= 7; if (pages) c |= 0x80; sec.push_back(c); } while (pages);
    section(5, sec);

    // ---- global section: $sp (0), $heap_end (1), $fp (2) ----
    sec.clear();
    sec.push_back(3);                    // count
    auto globalInit = [&](int64_t value) {
        sec.push_back(WT_I32); sec.push_back(0x01);   // i32, mut
        sec.push_back(0x41);                           // i32.const
        int64_t v = value;
        bool more = true;
        while (more) {
            uint8_t c = (uint8_t)(v & 0x7F);
            v >>= 7;
            if ((v == 0 && !(c & 0x40)) || (v == -1 && (c & 0x40))) more = false;
            else c |= 0x80;
            sec.push_back(c);
        }
        sec.push_back(0x0B);                           // end
    };
    globalInit(stackTop_);
    globalInit(heapStart_);
    globalInit(0);                           // $fp (set by every function prologue)
    section(6, sec);

    // ---- export section ----
    sec.clear();
    std::vector<std::pair<std::string, int>> exportFuncs;
    if (!prog.isLibrary) {
        // entry: "main" or the first function
        std::string entry = "main";
        bool hasMain = false;
        for (auto& f : prog.functions)
            if (!f->isExtern && f->name == "main") { hasMain = true; break; }
        if (!hasMain && !prog.functions.empty()) entry = prog.functions[0]->name;
        if (!prog.functions.empty()) exportFuncs.push_back({"_start", funcCallIndex(entry)});
    } else {
        for (auto& f : prog.functions)
            if (!f->isExtern) exportFuncs.push_back({f->name, funcCallIndex(f->name)});
    }
    int exports = (int)exportFuncs.size() + 1;   // + memory
    sec.push_back((uint8_t)exports);
    auto exportEntry = [&](const std::string& name, uint8_t kind, uint64_t idx) {
        sec.push_back((uint8_t)name.size());
        sec.insert(sec.end(), name.begin(), name.end());
        sec.push_back(kind);
        do { uint8_t c = idx & 0x7F; idx >>= 7; if (idx) c |= 0x80; sec.push_back(c); } while (idx);
    };
    for (auto& e : exportFuncs) exportEntry(e.first, 0x00, (uint64_t)e.second);
    exportEntry("memory", 0x02, 0);
    section(7, sec);

    // ---- code section ----
    sec.clear();
    sec.push_back((uint8_t)funcs_.size());
    for (auto& f : funcs_) {
        uint64_t sz = f.body.size();
        do { uint8_t c = sz & 0x7F; sz >>= 7; if (sz) c |= 0x80; sec.push_back(c); } while (sz);
        sec.insert(sec.end(), f.body.begin(), f.body.end());
    }
    section(10, sec);

    // ---- data section ----
    sec.clear();
    int segCount = (poolEnd_ > 0 ? 1 : 0) + (int)dataSegs_.size();
    sec.push_back((uint8_t)segCount);
    if (poolEnd_ > 0) {
        sec.push_back(0x00);               // memidx 0
        sec.push_back(0x41); sec.push_back(0x00); sec.push_back(0x0B);   // i32.const 0, end
        uint64_t sz = (uint64_t)poolEnd_;
        do { uint8_t c = sz & 0x7F; sz >>= 7; if (sz) c |= 0x80; sec.push_back(c); } while (sz);
        for (auto& s : poolStrings_) {
            sec.insert(sec.end(), s.begin(), s.end());
            sec.push_back(0);
        }
    }
    for (auto& seg : dataSegs_) {
        sec.push_back(0x00);               // memidx 0
        sec.push_back(0x41);
        int64_t off = seg.off;
        bool more = true;
        while (more) {
            uint8_t c = (uint8_t)(off & 0x7F);
            off >>= 7;
            if ((off == 0 && !(c & 0x40)) || (off == -1 && (c & 0x40))) more = false;
            else c |= 0x80;
            sec.push_back(c);
        }
        sec.push_back(0x0B);
        uint64_t sz = seg.bytes.size();
        do { uint8_t c = sz & 0x7F; sz >>= 7; if (sz) c |= 0x80; sec.push_back(c); } while (sz);
        sec.insert(sec.end(), seg.bytes.begin(), seg.bytes.end());
    }
    section(11, sec);
}

// ====================================================================
// top-level entry
// ====================================================================

bool WasmBackend::compile(const std::string& path) {
    // 1. pre-scan string literals so the pool is complete before the
    //    globals area is placed right after it
    for (auto& g : prog.globals) collectStringsExpr(g->init.get());
    for (auto& f : prog.functions)
        if (!f->isExtern) collectStringsBlock(f->body.stmts);

    // 2. layout the globals
    layoutGlobals();
    heapStart_ = dataEnd_;

    // 3. size the memory: data + a 2 MB soft stack, minimum 64 pages
    int64_t needPages = (int64_t)((dataEnd_ + (2 << 20) + 65535) / 65536);
    if (needPages < 64) needPages = 64;
    if (needPages > 65535) {
        std::cerr << "wasm: program data exceeds the wasm memory limit" << std::endl;
        return false;
    }
    memPages_ = (int)needPages;
    stackTop_ = memPages_ * 65536 - 8;
    if (stackTop_ < dataEnd_ + 16) {
        std::cerr << "wasm: stack overlaps program data" << std::endl;
        return false;
    }

    // 4. environment imports + extern functions
    importIndex("env", "zt_print_str", { WT_I32 }, 0);
    importIndex("env", "zt_print_int", { WT_I64 }, 0);
    importIndex("env", "zt_print_float", { WT_F32 }, 0);
    importIndex("env", "zt_exit", { WT_I32 }, 0);
    importIndex("env", "zt_sleep", { WT_I64 }, 0);
    importIndex("env", "zt_rdtsc", {}, WT_I64);
    importIndex("env", "zt_halt", {}, 0);
    for (auto& f : prog.functions) {
        if (f->isExtern) {
            std::vector<uint8_t> params;
            for (auto& p : f->params) params.push_back(typeToValtype(p.type));
            importIndex("env", f->name, params, typeToValtype(f->returnType));
        }
    }

    // 5. reserve function indices: user functions, then the internals
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        // user functions take no wasm params: arguments travel via the
        // soft-stack slots (the callee reads them at [fp + localsSize + 8*i])
        newFuncIndex(f->name, ensureType({}, typeToValtype(f->returnType)));
    }
    newFuncIndex("__zt_alloc", ensureType({ WT_I32 }, WT_I32));
    newFuncIndex("__zt_memcpy", ensureType({ WT_I32, WT_I32, WT_I32 }, 0));

    // 6. emit the function bodies
    for (auto& f : prog.functions)
        if (!f->isExtern) emitUserFunction(f.get());
    emitZtAlloc();
    emitZtMemcpy();

    // 7. build and write the module
    std::vector<uint8_t> out;
    out.push_back(0x00); out.push_back(0x61); out.push_back(0x73); out.push_back(0x6D);  // \0asm
    out.push_back(0x01); out.push_back(0x00); out.push_back(0x00); out.push_back(0x00);  // version 1
    buildModule(out);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        std::cerr << "wasm: cannot write '" << path << "'" << std::endl;
        exit(1);
    }
    ofs.write((const char*)out.data(), (std::streamsize)out.size());
    if (!ofs.good()) {
        std::cerr << "wasm: cannot write '" << path << "'" << std::endl;
        exit(1);
    }
    return true;
}

} // namespace

bool Codegen::compileWasm(const std::string& outputPath) {
    computeStructLayouts();
    WasmBackend backend(structLayouts, prog);
    return backend.compile(outputPath);
}
