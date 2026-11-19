// parseembed — the compiler's own parser, linked in as code, and the loader
// that turns its ZAST blob back into a C++ Program.
//
// selfhost/parseobj.z (parser.z + lower.z + ast.z + lexer.z) is compiled to a
// relocatable ELF object with the compiler's own --obj flag and linked into
// zenith instead of tools/lexobj.o (see the PARSEROBJ rules in Makefile.linux:
// the two objects carry the same lex*/zenith_obj_init symbols, so one replaces
// the other outright — they can never be linked together).
//
// parseZ() drives it in-process: zenith_obj_init once, parseRun on the source
// bytes, then loadZast on the serialized tree. No fork, no temp files.
//
// In-source lexer/parser errors are reported by the selfhost front end itself
// on stderr in the exact "Error at line ..." format src/parser.cpp used, so the
// text the user sees is unchanged; only the "Parser error: ..." tail comes
// from here, out of parseErrMsg().
#include "parseembed.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

extern "C" {
void zenith_obj_init();            // z global initializers; run once, first
long long parseRun(long long src, long long len);
long long parseErrMsg();
long long parseErrMsgLen();
long long parseErrLine();
long long parseOutPtr();
long long parseOutLen();
void parseRelease();
}

// _printk is the only external symbol a --obj image may reach for output
// (print() in z code compiled that way). It stays in src/lexembed.cpp, which
// this binary still links for bugfind_test / tools/pardump; parseobj.o only
// ever *references* it, never defines it.

namespace {

// ---- ZAST layout (selfhost/ast.z: azBuild) ----
//
//   [0..255]                 header, 64 x u32 (H_* indices below)
//   [256 .. +nodeCount*72)   nodes: nodeCount x 18 x u32 = [tag, line, f0..f15]
//   strtab                   H_STRBYTES bytes: u32 len + bytes (strId = offset)
//   side                     H_SIDEWORDS x u32: lists, blocks, params, ...
//   sigs                     H_SIGBYTES bytes: u32 nparams, nparams*6 words, 6 words ret
//
// node id 0 is NIL and node ids start at 1, so slot 0 of the node array is
// padding (tag 0). strId 0 / sigId 0 are NIL too (azReset reserves offset 0).
constexpr size_t HDR_BYTES = 64 * 4;
constexpr size_t NODE_BYTES = 18 * 4;
constexpr size_t TYPEW = 6;

enum : uint32_t {
    H_NODECOUNT = 2, H_STRBYTES = 3, H_SIDEWORDS = 4, H_SIGBYTES = 5,
    H_FUNCS = 6, H_GLOBALS = 8, H_IMPORTS = 10, H_STRUCTS = 12,
    H_CLASSES = 14, H_IFACES = 16, H_CLASSIDS = 18,
    H_APPTYPE = 20, H_APPCATEGORY = 21, H_RENDERTYPE = 22, H_KERNELMODE = 23,
    H_ARCH = 24, H_FLAGS = 25, H_ASMWORD = 26, H_SYSCLK = 27, H_SYSTICK = 28,
    H_SRAMKB = 29, H_ARM64CLOCKLO = 30, H_ARM64CLOCKHI = 31, H_ANDROIDAPI = 32,
    H_ANDROIDMIN = 33, H_MODDESC = 34, H_MODAUTHOR = 35, H_MODVERSION = 36,
    H_MCU = 37, H_LEDPIN = 38, H_ARM64CHIP = 39, H_ANDROIDLABEL = 40
};

enum : uint32_t {
    N_NUMBER = 1, N_FLOAT = 2, N_IDENT = 3, N_MEMBER = 4, N_BINARY = 5,
    N_DEREF = 6, N_ADDROF = 7, N_UNARY = 8, N_ARRAYACC = 9, N_CALL = 10,
    N_STRING = 11, N_VARDECL = 12, N_RETURN = 13, N_EXPRSTMT = 14,
    N_ASSIGN = 15, N_PTRASSIGN = 16, N_IF = 17, N_WHILE = 18, N_LOOP = 19,
    N_SWITCH = 20, N_BREAK = 21, N_CONTINUE = 22, N_ASM = 23, N_FOR = 24,
    N_FUNC = 101, N_STRUCT = 102, N_CLASS = 103, N_INTERFACE = 104
};

constexpr uint32_t FLAG_KODRIVER = 1;
constexpr uint32_t FLAG_KMEXPLICIT = 2;
constexpr uint32_t FLAG_BOOTSERVICES = 4;
constexpr uint32_t FLAG_REAL16 = 8;
constexpr uint32_t FLAG_LEDACTIVELOW = 16;

inline uint32_t rd32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

struct Reader {
    const uint8_t* blob = nullptr;
    size_t blobLen = 0;
    const uint8_t* hdr = nullptr;
    const uint8_t* nodes = nullptr;
    const uint8_t* strtab = nullptr;
    const uint8_t* side = nullptr;
    const uint8_t* sig = nullptr;
    uint32_t nodeCount = 0, strBytes = 0, sideWords = 0, sigBytes = 0;
    bool bad = false;
    // interface names, filled before classes are walked: fixInterfaceType only
    // rewrites a Struct type whose name is one of these.
    std::set<std::string> ifaceNames;

    bool init(const uint8_t* p, size_t n) {
        if (!p || n < HDR_BYTES) return false;
        blob = p;
        blobLen = n;
        hdr = p;
        nodeCount = rd32(p + H_NODECOUNT * 4);
        strBytes = rd32(p + H_STRBYTES * 4);
        sideWords = rd32(p + H_SIDEWORDS * 4);
        sigBytes = rd32(p + H_SIGBYTES * 4);

        // Every section must lie inside the blob; a truncated or corrupted
        // image must not be walked, it is reported as a load failure.
        uint64_t off = HDR_BYTES;
        uint64_t nodesEnd = off + (uint64_t)nodeCount * NODE_BYTES;
        uint64_t strEnd = nodesEnd + strBytes;
        uint64_t sideEnd = strEnd + (uint64_t)sideWords * 4;
        uint64_t sigEnd = sideEnd + sigBytes;
        if (sigEnd > n) return false;

        nodes = p + off;
        strtab = p + nodesEnd;
        side = p + strEnd;
        sig = p + sideEnd;
        return true;
    }

    uint32_t h(uint32_t idx) const { return rd32(hdr + idx * 4); }

    std::string str(uint32_t id) {
        if (id == 0) return std::string();
        if (bad || id + 4 > strBytes) { bad = true; return std::string(); }
        uint32_t len = rd32(strtab + id);
        if ((uint64_t)id + 4 + len > strBytes) { bad = true; return std::string(); }
        return std::string((const char*)strtab + id + 4, len);
    }

    uint32_t word(uint32_t w) {
        if (bad || w >= sideWords) { bad = true; return 0; }
        return rd32(side + (size_t)w * 4);
    }

    const uint8_t* node(uint32_t id) {
        if (bad || id >= nodeCount) { bad = true; return nullptr; }
        return nodes + (size_t)id * NODE_BYTES;
    }

    uint32_t tag(uint32_t id) {
        const uint8_t* np = node(id);
        return np ? rd32(np) : 0;
    }

    uint32_t line(uint32_t id) {
        const uint8_t* np = node(id);
        return np ? rd32(np + 4) : 0;
    }

    uint32_t fld(uint32_t id, uint32_t f) {
        const uint8_t* np = node(id);
        if (!np) return 0;
        return rd32(np + 8 + f * 4);
    }

    std::shared_ptr<FuncPtrSig> sigOf(uint32_t id) {
        if (id == 0) return nullptr;
        if (bad || id + 4 > sigBytes) { bad = true; return nullptr; }
        uint32_t n = rd32(sig + id);
        uint64_t need = 4 + (uint64_t)(n + 1) * TYPEW * 4;
        if ((uint64_t)id + need > sigBytes) { bad = true; return nullptr; }
        auto s = std::make_shared<FuncPtrSig>();
        const uint8_t* q = sig + id + 4;
        s->params.reserve(n);
        for (uint32_t i = 0; i < n; i++) s->params.push_back(type(q + i * TYPEW * 4));
        s->ret = type(q + (size_t)n * TYPEW * 4);
        return s;
    }

    // [kind, strId, isPtr, addrSpace, arraySize, fnSigId]
    Type type(const uint8_t* q) {
        Type t;
        t.kind = (TypeKind)rd32(q + 0);
        t.structName = str(rd32(q + 4));
        t.isPtr = rd32(q + 8) != 0;
        t.addrSpace = rd32(q + 12) ? AddressSpace::Physical : AddressSpace::Virtual;
        t.arraySize = (int)rd32(q + 16);
        uint32_t s = rd32(q + 20);
        if (s) t.fn = sigOf(s);
        return t;
    }

    // type living in node fields f..f+5
    Type nodeType(uint32_t id, uint32_t f) {
        const uint8_t* np = node(id);
        if (!np) return Type();
        return type(np + 8 + f * 4);
    }

    // side list of node ids -> Block
    Block block(uint32_t start, uint32_t len) {
        Block b;
        if (len == 0) return b;
        b.stmts.reserve(len);
        for (uint32_t i = 0; i < len; i++) {
            auto s = stmt(word(start + i));
            if (s) b.stmts.push_back(std::move(s));
        }
        return b;
    }

    std::vector<std::string> strList(uint32_t start, uint32_t len) {
        std::vector<std::string> v;
        v.reserve(len);
        for (uint32_t i = 0; i < len; i++) v.push_back(str(word(start + i)));
        return v;
    }

    std::unique_ptr<Expr> expr(uint32_t id);
    std::unique_ptr<Stmt> stmt(uint32_t id);
    std::unique_ptr<FunctionDecl> func(uint32_t id);
    std::unique_ptr<StructDecl> strct(uint32_t id);
    std::unique_ptr<ClassDecl> cls(uint32_t id);
    std::unique_ptr<InterfaceDecl> iface(uint32_t id);
    std::unique_ptr<VarDecl> global(uint32_t id);
    void program(Program& prog);
};

std::unique_ptr<Expr> Reader::expr(uint32_t id) {
    if (id == 0) return nullptr;
    uint32_t t = tag(id);
    switch (t) {
        case N_NUMBER: {
            auto n = std::make_unique<NumberExpr>();
            uint32_t lo = fld(id, 0), hi = fld(id, 1);
            n->value = (int64_t)(((uint64_t)hi << 32) | (uint64_t)lo);
            return n;
        }
        case N_FLOAT: {
            auto f = std::make_unique<FloatExpr>();
            std::string text = str(fld(id, 0));
            double v = text.empty() ? 0.0 : std::strtod(text.c_str(), nullptr);
            f->value = fld(id, 1) ? -v : v;
            return f;
        }
        case N_IDENT: {
            auto e = std::make_unique<IdentExpr>();
            e->name = str(fld(id, 0));
            return e;
        }
        case N_MEMBER: {
            auto m = std::make_unique<MemberExpr>();
            m->object = expr(fld(id, 0));
            m->member = str(fld(id, 1));
            return m;
        }
        case N_BINARY: {
            auto b = std::make_unique<BinaryExpr>();
            b->left = expr(fld(id, 0));
            b->right = expr(fld(id, 1));
            b->op = str(fld(id, 2));
            b->parenthesized = fld(id, 3) != 0;
            return b;
        }
        case N_DEREF: {
            auto d = std::make_unique<DerefExpr>();
            d->ptr = expr(fld(id, 0));
            return d;
        }
        case N_ADDROF: {
            auto a = std::make_unique<AddressOfExpr>();
            a->name = str(fld(id, 0));
            a->target = expr(fld(id, 1));
            return a;
        }
        case N_UNARY: {
            auto u = std::make_unique<UnaryExpr>();
            u->op = str(fld(id, 0));
            u->operand = expr(fld(id, 1));
            return u;
        }
        case N_ARRAYACC: {
            auto a = std::make_unique<ArrayAccessExpr>();
            a->array = expr(fld(id, 0));
            a->index = expr(fld(id, 1));
            return a;
        }
        case N_CALL: {
            auto c = std::make_unique<CallExpr>();
            c->name = str(fld(id, 0));
            c->receiver = expr(fld(id, 1));
            uint32_t as = fld(id, 2), al = fld(id, 3);
            c->args.reserve(al);
            for (uint32_t i = 0; i < al; i++) c->args.push_back(expr(word(as + i)));
            c->isVirtual = fld(id, 4) != 0;
            // vtable = pairs (classID, mangled impl name); pair order may differ
            // from the C++ front end's — dispatch only reads them as a set.
            uint32_t vs = fld(id, 5), vl = fld(id, 6);
            c->vtable.reserve(vl / 2);
            for (uint32_t i = 0; i + 1 < vl; i += 2) {
                int cid = (int)word(vs + i);
                c->vtable.push_back({cid, str(word(vs + i + 1))});
            }
            return c;
        }
        case N_STRING: {
            auto s = std::make_unique<StringExpr>();
            s->value = str(fld(id, 0));
            return s;
        }
        default:
            bad = true;
            return nullptr;
    }
}

std::unique_ptr<Stmt> Reader::stmt(uint32_t id) {
    if (id == 0) return nullptr;
    uint32_t t = tag(id);
    uint32_t ln = line(id);
    switch (t) {
        case N_VARDECL: {
            auto v = std::make_unique<VarDecl>();
            v->line = (int)ln;
            v->name = str(fld(id, 0));
            v->type = nodeType(id, 1);
            v->init = expr(fld(id, 7));
            // VarDecl::arraySize is the decl's own `[N]`; the element type's
            // arraySize stays as the parser left it (src/parser.cpp never sets
            // Type::arraySize either — same rule on both sides).
            v->arraySize = (int)fld(id, 8);
            v->isConst = fld(id, 9) != 0;
            return v;
        }
        case N_RETURN: {
            auto r = std::make_unique<ReturnStmt>();
            r->line = (int)ln;
            r->value = expr(fld(id, 0));
            return r;
        }
        case N_EXPRSTMT: {
            auto x = std::make_unique<ExprStmt>();
            x->line = (int)ln;
            x->expr = expr(fld(id, 0));
            return x;
        }
        case N_ASSIGN: {
            auto a = std::make_unique<AssignStmt>();
            a->line = (int)ln;
            a->name = str(fld(id, 0));
            a->memberPath = strList(fld(id, 1), fld(id, 2));
            a->indexExpr = expr(fld(id, 3));
            a->value = expr(fld(id, 4));
            return a;
        }
        case N_PTRASSIGN: {
            auto p = std::make_unique<PtrAssignStmt>();
            p->line = (int)ln;
            p->ptr = expr(fld(id, 0));
            p->value = expr(fld(id, 1));
            return p;
        }
        case N_IF: {
            auto i = std::make_unique<IfStmt>();
            i->line = (int)ln;
            i->condition = expr(fld(id, 0));
            i->thenBlock = block(fld(id, 1), fld(id, 2));
            i->elseBlock = block(fld(id, 3), fld(id, 4));
            return i;
        }
        case N_WHILE: {
            auto w = std::make_unique<WhileStmt>();
            w->line = (int)ln;
            w->condition = expr(fld(id, 0));
            w->body = block(fld(id, 1), fld(id, 2));
            return w;
        }
        case N_LOOP: {
            // loop carries the body at f0/f1 (no condition slot), unlike
            // while/if which start their block pair at f1.
            auto l = std::make_unique<LoopStmt>();
            l->line = (int)ln;
            l->body = block(fld(id, 0), fld(id, 1));
            return l;
        }
        case N_SWITCH: {
            auto s = std::make_unique<SwitchStmt>();
            s->line = (int)ln;
            s->condition = expr(fld(id, 0));
            uint32_t cs = fld(id, 1), cl = fld(id, 2);
            for (uint32_t i = 0; i + 2 < cl; i += 3) {
                SwitchCase c;
                c.condition = expr(word(cs + i));   // 0 = default
                c.body = block(word(cs + i + 1), word(cs + i + 2));
                s->cases.push_back(std::move(c));
            }
            return s;
        }
        case N_BREAK: {
            auto b = std::make_unique<BreakStmt>();
            b->line = (int)ln;
            return b;
        }
        case N_CONTINUE: {
            auto c = std::make_unique<ContinueStmt>();
            c->line = (int)ln;
            return c;
        }
        case N_ASM: {
            auto a = std::make_unique<AsmStmt>();
            a->line = (int)ln;
            a->wordSize = (int32_t)fld(id, 0);
            uint32_t is = fld(id, 1), il = fld(id, 2);
            for (uint32_t i = 0; i + 3 < il; i += 4) {
                AsmInstr in;
                in.mnemonic = str(word(is + i));
                in.op1 = str(word(is + i + 1));
                in.op2 = str(word(is + i + 2));
                in.op3 = str(word(is + i + 3));
                a->instrs.push_back(std::move(in));
            }
            return a;
        }
        case N_FOR: {
            auto f = std::make_unique<ForStmt>();
            f->line = (int)ln;
            f->varName = str(fld(id, 0));
            f->start = expr(fld(id, 1));
            f->end = expr(fld(id, 2));
            f->step = expr(fld(id, 3));
            f->body = block(fld(id, 4), fld(id, 5));
            return f;
        }
        default:
            bad = true;
            return nullptr;
    }
}

std::unique_ptr<FunctionDecl> Reader::func(uint32_t id) {
    auto f = std::make_unique<FunctionDecl>();
    if (tag(id) != N_FUNC) { bad = true; return f; }
    f->line = (int)line(id);
    f->name = str(fld(id, 0));
    uint32_t ps = fld(id, 1), pl = fld(id, 2);
    f->params.reserve(pl / 7);
    for (uint32_t i = 0; i + 7 <= pl; i += 7) {
        Param p;
        p.name = str(word(ps + i));
        p.type = type(side + (size_t)(ps + i + 1) * 4);
        f->params.push_back(std::move(p));
    }
    f->returnType = nodeType(id, 3);
    f->body = block(fld(id, 9), fld(id, 10));
    f->isExtern = fld(id, 11) != 0;
    f->dllName = str(fld(id, 12));
    return f;
}

std::unique_ptr<StructDecl> Reader::strct(uint32_t id) {
    auto s = std::make_unique<StructDecl>();
    if (tag(id) != N_STRUCT) { bad = true; return s; }
    s->line = (int)line(id);
    s->name = str(fld(id, 0));
    uint32_t fs = fld(id, 1), fl = fld(id, 2);
    for (uint32_t i = 0; i + 7 <= fl; i += 7) {
        StructField f;
        f.name = str(word(fs + i));
        f.type = type(side + (size_t)(fs + i + 1) * 4);
        s->fields.push_back(std::move(f));
    }
    return s;
}

std::unique_ptr<ClassDecl> Reader::cls(uint32_t id) {
    auto c = std::make_unique<ClassDecl>();
    if (tag(id) != N_CLASS) { bad = true; return c; }
    c->line = (int)line(id);
    c->name = str(fld(id, 0));
    c->base = str(fld(id, 1));
    c->interfaces = strList(fld(id, 2), fld(id, 3));
    uint32_t fs = fld(id, 4), fl = fld(id, 5);
    for (uint32_t i = 0; i + 7 <= fl; i += 7) {
        StructField f;
        f.name = str(word(fs + i));
        f.type = type(side + (size_t)(fs + i + 1) * 4);
        c->fields.push_back(std::move(f));
    }
    // 12-word method records: [name, paramsStart, paramsLen, ret x 6,
    //                          bodyStart, bodyLen, isAbstract]
    uint32_t ms = fld(id, 6), ml = fld(id, 7);
    for (uint32_t i = 0; i + 12 <= ml; i += 12) {
        ClassMethod m;
        m.name = str(word(ms + i));
        m.isAbstract = word(ms + i + 11) != 0;
        uint32_t ps = word(ms + i + 1), pl = word(ms + i + 2);
        for (uint32_t j = 0; j + 7 <= pl; j += 7) {
            Param p;
            p.name = str(word(ps + j));
            p.type = type(side + (size_t)(ps + j + 1) * 4);
            // src/parser.cpp walks `for (auto& p : m.params)` and applies
            // fixInterfaceType through that reference, so a non-abstract
            // method's own parameter types are rewritten in place — and only
            // there: the abstract branch is skipped before the loop runs, and
            // the return type is fixed on the *copy* handed to the generated
            // function, never on m.returnType.
            if (!m.isAbstract && p.type.kind == TypeKind::Struct && !p.type.isPtr &&
                ifaceNames.count(p.type.structName))
                p.type.isPtr = true;
            m.params.push_back(std::move(p));
        }
        m.returnType = type(side + (size_t)(ms + i + 3) * 4);
        // The body is left behind on purpose: lower moved it into the
        // generated `Class::method` function, so the ClassMethod keeps an
        // empty Block, exactly as `fn->body = std::move(m.body)` leaves it.
        c->methods.push_back(std::move(m));
    }
    c->isAbstract = fld(id, 8) != 0;
    return c;
}

std::unique_ptr<InterfaceDecl> Reader::iface(uint32_t id) {
    auto d = std::make_unique<InterfaceDecl>();
    if (tag(id) != N_INTERFACE) { bad = true; return d; }
    d->line = (int)line(id);
    d->name = str(fld(id, 0));
    uint32_t ms = fld(id, 1), ml = fld(id, 2);
    for (uint32_t i = 0; i + 12 <= ml; i += 12) {
        ClassMethod m;
        m.name = str(word(ms + i));
        m.isAbstract = word(ms + i + 11) != 0;
        uint32_t ps = word(ms + i + 1), pl = word(ms + i + 2);
        for (uint32_t j = 0; j + 7 <= pl; j += 7) {
            Param p;
            p.name = str(word(ps + j));
            p.type = type(side + (size_t)(ps + j + 1) * 4);
            m.params.push_back(std::move(p));
        }
        m.returnType = type(side + (size_t)(ms + i + 3) * 4);
        d->methods.push_back(std::move(m));
    }
    return d;
}

std::unique_ptr<VarDecl> Reader::global(uint32_t id) {
    auto v = std::make_unique<VarDecl>();
    if (tag(id) != N_VARDECL) { bad = true; return v; }
    v->line = (int)line(id);
    v->name = str(fld(id, 0));
    v->type = nodeType(id, 1);
    v->init = expr(fld(id, 7));
    v->arraySize = (int)fld(id, 8);
    v->isConst = fld(id, 9) != 0;
    return v;
}

void Reader::program(Program& prog) {
    // ---- header ----
    prog.appType = (AppType)h(H_APPTYPE);
    prog.appCategory = (AppCategory)h(H_APPCATEGORY);
    prog.renderType = (RenderType)h(H_RENDERTYPE);
    prog.kernelMode = (KernelMode)h(H_KERNELMODE);
    prog.arch = (Arch)h(H_ARCH);
    uint32_t flags = h(H_FLAGS);
    prog.koDriver = (flags & FLAG_KODRIVER) != 0;
    prog.kernelModeExplicit = (flags & FLAG_KMEXPLICIT) != 0;
    prog.bootServicesManual = (flags & FLAG_BOOTSERVICES) != 0;
    prog.real16 = (flags & FLAG_REAL16) != 0;
    prog.ledActiveLow = (flags & FLAG_LEDACTIVELOW) != 0;
    prog.asmWordSize = (int32_t)h(H_ASMWORD);
    prog.sysclkHz = h(H_SYSCLK);
    prog.systickHz = h(H_SYSTICK);
    prog.sramKb = h(H_SRAMKB);
    prog.arm64ClockHz = ((uint64_t)h(H_ARM64CLOCKHI) << 32) | (uint64_t)h(H_ARM64CLOCKLO);
    prog.androidApiLevel = h(H_ANDROIDAPI);
    prog.androidMinSdk = h(H_ANDROIDMIN);
    prog.moduleDescription = str(h(H_MODDESC));
    prog.moduleAuthor = str(h(H_MODAUTHOR));
    prog.moduleVersion = str(h(H_MODVERSION));
    prog.mcu = str(h(H_MCU));
    prog.ledPin = str(h(H_LEDPIN));
    prog.arm64Chip = str(h(H_ARM64CHIP));
    prog.androidLabel = str(h(H_ANDROIDLABEL));
    // isLibrary / objOutput are not part of the blob: main.cpp keeps setting
    // them from [no_main] / --obj exactly as it always has.

    // ---- imports: side pairs [dll, module] ----
    {
        uint32_t s = h(H_IMPORTS), l = h(H_IMPORTS + 1);
        for (uint32_t i = 0; i + 1 < l; i += 2) {
            ImportDecl im;
            im.dllName = str(word(s + i));
            im.module = str(word(s + i + 1));
            prog.imports.push_back(std::move(im));
        }
    }

    // ---- classIDs: side pairs [name, cid] ----
    {
        uint32_t s = h(H_CLASSIDS), l = h(H_CLASSIDS + 1);
        for (uint32_t i = 0; i + 1 < l; i += 2)
            prog.classIDs[str(word(s + i))] = (int)word(s + i + 1);
    }

    // ---- globals ----
    {
        uint32_t s = h(H_GLOBALS), l = h(H_GLOBALS + 1);
        for (uint32_t i = 0; i < l; i++) prog.globals.push_back(global(word(s + i)));
    }

    // ---- structs (user structs first, then the class->struct lowering) ----
    {
        uint32_t s = h(H_STRUCTS), l = h(H_STRUCTS + 1);
        for (uint32_t i = 0; i < l; i++) prog.structs.push_back(strct(word(s + i)));
    }

    // ---- interfaces first: the class walk needs their names for
    // fixInterfaceType on non-abstract method parameters ----
    {
        uint32_t s = h(H_IFACES), l = h(H_IFACES + 1);
        for (uint32_t i = 0; i < l; i++) prog.interfaces.push_back(iface(word(s + i)));
    }
    for (auto& d : prog.interfaces) ifaceNames.insert(d->name);

    // ---- classes ----
    {
        uint32_t s = h(H_CLASSES), l = h(H_CLASSES + 1);
        for (uint32_t i = 0; i < l; i++) prog.classes.push_back(cls(word(s + i)));
    }

    // ---- functions, including the Class::method ones lower added ----
    {
        uint32_t s = h(H_FUNCS), l = h(H_FUNCS + 1);
        for (uint32_t i = 0; i < l; i++) prog.functions.push_back(func(word(s + i)));
    }

    if (bad) return;
}

} // namespace

bool loadZast(const uint8_t* blob, size_t len, Program& prog) {
    Reader r;
    if (!r.init(blob, len)) return false;
    prog = Program();
    r.program(prog);
    return !r.bad;
}

int parseZ(const std::string& src, Program& prog, std::string& msg, long long& errLine) {
    // One-time z runtime bring-up: a --obj image has no _start, so globals
    // whose initializers need code are set here, exactly once, before the
    // first entry into z code.
    static const bool inited = []() { zenith_obj_init(); return true; }();
    (void)inited;

    long long rc = parseRun((long long)(intptr_t)src.data(), (long long)src.size());

    // Capture the error text before anything else: it lives in a z global the
    // next run will overwrite. On success the buffer is not touched at all
    // (it may even never have been allocated), so only rc != 0 reads it.
    if (rc != 0) {
        const char* p = (const char*)(intptr_t)parseErrMsg();
        long long n = parseErrMsgLen();
        if (p && n > 0) msg.assign(p, (size_t)n);
        else msg.clear();
    } else {
        msg.clear();
    }
    errLine = parseErrLine();

    if (rc == 0) {
        const uint8_t* p = (const uint8_t*)(intptr_t)parseOutPtr();
        size_t n = (size_t)parseOutLen();
        if (!loadZast(p, n, prog)) {
            msg = "ZAST loader: malformed blob";
            rc = 3;
        }
    }

    parseRelease();
    return (int)rc;
}
