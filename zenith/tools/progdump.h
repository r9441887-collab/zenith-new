// progdump — deterministic textual dump of a C++ Program.
//
// The same dump is produced by two binaries:
//   tools/pardump  — the golden side: lexSource + Parser (the C++ front end);
//   tools/pardiff  — the new side:   parseZ (selfhost parser linked in as
//                                    parseobj.o) and then diffed against it.
// Anything the two front ends must agree on has to appear here, and nothing
// that is allowed to differ may. Deliberately excluded:
//   * CallExpr::vtable pair order — the accepted divergence (dispatch only
//     needs the set of (cid, mangled) pairs, the C++ and selfhost walkers
//     emit them in different orders);
//   * isLibrary / objOutput — never part of the parse, main.cpp sets them;
//   * the "missing abstract method" message choice when several are missing
//     — that is stderr-only and never reaches the Program.
#pragma once
#include "../src/ast.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace progdump {

inline std::string esc(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\t': o += "\\t"; break;
            case '\r': o += "\\r"; break;
            case '"':  o += "\\\""; break;
            default:
                if ((unsigned char)c < 32 || (unsigned char)c == 127) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\x%02x", (unsigned char)c);
                    o += b;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

inline std::string ind(int n) { return std::string((size_t)(n < 0 ? 0 : n), ' '); }

inline const char* kindName(TypeKind k) {
    switch (k) {
        case TypeKind::Int:     return "int";
        case TypeKind::Float:   return "float";
        case TypeKind::Bool:    return "bool";
        case TypeKind::Void:    return "void";
        case TypeKind::String:  return "string";
        case TypeKind::Vec2:    return "vec2";
        case TypeKind::Vec3:    return "vec3";
        case TypeKind::Color:   return "color";
        case TypeKind::Entity:  return "entity";
        case TypeKind::Struct:  return "struct";
        case TypeKind::FuncPtr: return "funcptr";
    }
    return "?";
}

inline std::string ty(const Type& t) {
    std::string s;
    if (t.isPtr) s += "*";
    s += kindName(t.kind);
    if (t.kind == TypeKind::Struct) { s += ":"; s += t.structName; }
    if (t.arraySize != 0) { s += "["; s += std::to_string((long long)t.arraySize); s += "]"; }
    if (t.addrSpace == AddressSpace::Physical) s += "@phys";
    if (t.fn) {
        s += "<(";
        for (size_t i = 0; i < t.fn->params.size(); i++) {
            if (i) s += ",";
            s += ty(t.fn->params[i]);
        }
        s += ")->";
        s += ty(t.fn->ret);
        s += ")>";
    }
    return s;
}

inline std::string flt(double v) {
    char b[40];
    std::snprintf(b, sizeof b, "%.17g", v);
    return b;
}

inline std::string i64(int64_t v) {
    return std::to_string((long long)v);
}

// ---- expressions (single line) ----

inline std::string ex(const Expr* e);

inline std::string exArgs(const std::vector<std::unique_ptr<Expr>>& args) {
    std::string s = "[";
    for (size_t i = 0; i < args.size(); i++) {
        if (i) s += ",";
        s += ex(args[i].get());
    }
    s += "]";
    return s;
}

inline std::string ex(const Expr* e) {
    if (!e) return "-";
    if (auto* n = dynamic_cast<const NumberExpr*>(e)) return "(num " + i64(n->value) + ")";
    if (auto* f = dynamic_cast<const FloatExpr*>(e))  return "(flt " + flt(f->value) + ")";
    if (auto* i = dynamic_cast<const IdentExpr*>(e))  return "(id " + i->name + ")";
    if (auto* s = dynamic_cast<const StringExpr*>(e)) return "(str \"" + esc(s->value) + "\")";
    if (auto* m = dynamic_cast<const MemberExpr*>(e))
        return "(mem " + ex(m->object.get()) + " " + m->member + ")";
    if (auto* b = dynamic_cast<const BinaryExpr*>(e))
        return "(bin " + b->op + " " + ex(b->left.get()) + " " + ex(b->right.get()) +
               " p=" + (b->parenthesized ? "1" : "0") + ")";
    if (auto* u = dynamic_cast<const UnaryExpr*>(e))
        return "(un " + u->op + " " + ex(u->operand.get()) + ")";
    if (auto* d = dynamic_cast<const DerefExpr*>(e))
        return "(deref " + ex(d->ptr.get()) + ")";
    if (auto* a = dynamic_cast<const AddressOfExpr*>(e))
        return "(adrf " + (a->name.empty() ? std::string("-") : a->name) + " " +
               ex(a->target.get()) + ")";
    if (auto* aa = dynamic_cast<const ArrayAccessExpr*>(e))
        return "(arr " + ex(aa->array.get()) + " " + ex(aa->index.get()) + ")";
    if (auto* c = dynamic_cast<const CallExpr*>(e))
        return "(call " + c->name + " rec=" + ex(c->receiver.get()) +
               " args=" + exArgs(c->args) + " virt=" + (c->isVirtual ? "1" : "0") + ")";
    return "(?)";
}

// ---- statements / blocks (multi line) ----

inline void st(const Stmt* s, int depth, std::string& out);

inline void block(const Block& b, int depth, std::string& out) {
    for (auto& s : b.stmts) st(s.get(), depth, out);
}

inline void st(const Stmt* s, int depth, std::string& out) {
    std::string p = ind(depth);
    if (!s) { out += p + "null\n"; return; }
    if (auto* v = dynamic_cast<const VarDecl*>(s)) {
        out += p + "var " + v->name + ": " + ty(v->type);
        if (v->init) out += " = " + ex(v->init.get());
        out += " array=" + std::to_string((long long)v->arraySize) +
               " const=" + (v->isConst ? "1" : "0") +
               " @" + std::to_string(v->line) + "\n";
        return;
    }
    if (auto* r = dynamic_cast<const ReturnStmt*>(s)) {
        out += p + "return " + ex(r->value.get()) + " @" + std::to_string(r->line) + "\n";
        return;
    }
    if (auto* x = dynamic_cast<const ExprStmt*>(s)) {
        out += p + "expr " + ex(x->expr.get()) + " @" + std::to_string(x->line) + "\n";
        return;
    }
    if (auto* a = dynamic_cast<const AssignStmt*>(s)) {
        out += p + "assign " + a->name;
        for (auto& m : a->memberPath) out += "." + m;
        if (a->indexExpr) out += "[" + ex(a->indexExpr.get()) + "]";
        out += " = " + ex(a->value.get()) + " @" + std::to_string(a->line) + "\n";
        return;
    }
    if (auto* q = dynamic_cast<const PtrAssignStmt*>(s)) {
        out += p + "passign " + ex(q->ptr.get()) + " = " + ex(q->value.get()) +
               " @" + std::to_string(q->line) + "\n";
        return;
    }
    if (auto* i = dynamic_cast<const IfStmt*>(s)) {
        out += p + "if " + ex(i->condition.get()) + " @" + std::to_string(i->line) + "\n";
        block(i->thenBlock, depth + 1, out);
        if (!i->elseBlock.stmts.empty()) {
            out += p + "else\n";
            block(i->elseBlock, depth + 1, out);
        }
        out += p + "end\n";
        return;
    }
    if (auto* w = dynamic_cast<const WhileStmt*>(s)) {
        out += p + "while " + ex(w->condition.get()) + " @" + std::to_string(w->line) + "\n";
        block(w->body, depth + 1, out);
        out += p + "end\n";
        return;
    }
    if (auto* l = dynamic_cast<const LoopStmt*>(s)) {
        out += p + "loop @" + std::to_string(l->line) + "\n";
        block(l->body, depth + 1, out);
        out += p + "end\n";
        return;
    }
    if (auto* sw = dynamic_cast<const SwitchStmt*>(s)) {
        out += p + "switch " + ex(sw->condition.get()) + " @" + std::to_string(sw->line) + "\n";
        for (auto& c : sw->cases) {
            out += p + "  case " + ex(c.condition.get()) + "\n";
            block(c.body, depth + 2, out);
        }
        out += p + "end\n";
        return;
    }
    if (dynamic_cast<const BreakStmt*>(s)) {
        out += p + "break @" + std::to_string(s->line) + "\n";
        return;
    }
    if (dynamic_cast<const ContinueStmt*>(s)) {
        out += p + "continue @" + std::to_string(s->line) + "\n";
        return;
    }
    if (auto* am = dynamic_cast<const AsmStmt*>(s)) {
        out += p + "asm word=" + std::to_string((long long)am->wordSize) +
               " @" + std::to_string(am->line) + "\n";
        for (auto& in : am->instrs) {
            out += p + "  " + in.mnemonic;
            if (!in.op1.empty()) out += " " + in.op1;
            if (!in.op2.empty()) out += " " + in.op2;
            if (!in.op3.empty()) out += " " + in.op3;
            out += "\n";
        }
        out += p + "end\n";
        return;
    }
    if (auto* f = dynamic_cast<const ForStmt*>(s)) {
        out += p + "for " + f->varName + " " + ex(f->start.get()) + " " + ex(f->end.get()) +
               " " + ex(f->step.get()) + " @" + std::to_string(f->line) + "\n";
        block(f->body, depth + 1, out);
        out += p + "end\n";
        return;
    }
    out += p + "unknown-stmt\n";
}

// ---- top-level ----

inline std::string params(const std::vector<Param>& ps) {
    std::string s = "[";
    for (size_t i = 0; i < ps.size(); i++) {
        if (i) s += ",";
        s += ps[i].name + ":" + ty(ps[i].type);
    }
    s += "]";
    return s;
}

inline void dump(const Program& prog, std::string& o) {
    o += "program appType=" + std::to_string((int)prog.appType) +
         " appCategory=" + std::to_string((int)prog.appCategory) +
         " renderType=" + std::to_string((int)prog.renderType) +
         " kernelMode=" + std::to_string((int)prog.kernelMode) +
         " arch=" + std::to_string((int)prog.arch) +
         " koDriver=" + (prog.koDriver ? "1" : "0") +
         " kernelModeExplicit=" + (prog.kernelModeExplicit ? "1" : "0") +
         " bootServicesManual=" + (prog.bootServicesManual ? "1" : "0") +
         " real16=" + (prog.real16 ? "1" : "0") +
         " ledActiveLow=" + (prog.ledActiveLow ? "1" : "0") + "\n";
    o += "meta asmWord=" + std::to_string((long long)prog.asmWordSize) +
         " sysclk=" + std::to_string((unsigned long long)prog.sysclkHz) +
         " systick=" + std::to_string((unsigned long long)prog.systickHz) +
         " sramKb=" + std::to_string((unsigned long long)prog.sramKb) +
         " arm64Clock=" + std::to_string((unsigned long long)prog.arm64ClockHz) +
         " androidApi=" + std::to_string((unsigned long long)prog.androidApiLevel) +
         " androidMin=" + std::to_string((unsigned long long)prog.androidMinSdk) + "\n";
    o += "str modDesc=\"" + esc(prog.moduleDescription) + "\" modAuthor=\"" +
         esc(prog.moduleAuthor) + "\" modVersion=\"" + esc(prog.moduleVersion) +
         "\" mcu=\"" + esc(prog.mcu) + "\" ledPin=\"" + esc(prog.ledPin) +
         "\" arm64Chip=\"" + esc(prog.arm64Chip) + "\" androidLabel=\"" +
         esc(prog.androidLabel) + "\"\n";

    for (auto& im : prog.imports)
        o += "import \"" + esc(im.dllName) + "\" \"" + esc(im.module) + "\"\n";

    {
        std::vector<std::pair<std::string, int>> ids(prog.classIDs.begin(), prog.classIDs.end());
        std::sort(ids.begin(), ids.end());
        for (auto& kv : ids)
            o += "classID \"" + esc(kv.first) + "\" " + std::to_string(kv.second) + "\n";
    }

    for (auto& g : prog.globals) {
        o += "global " + g->name + ": " + ty(g->type);
        if (g->init) o += " = " + ex(g->init.get());
        o += " array=" + std::to_string((long long)g->arraySize) +
             " const=" + (g->isConst ? "1" : "0") +
             " @" + std::to_string(g->line) + "\n";
    }

    for (auto& s : prog.structs) {
        o += "struct " + s->name + "\n";
        for (auto& f : s->fields) o += "  field " + f.name + ": " + ty(f.type) + "\n";
        o += "end\n";
    }

    for (auto& c : prog.classes) {
        o += "class " + c->name + " base=\"" + esc(c->base) + "\" abstract=" +
             (c->isAbstract ? "1" : "0") + " ifaces=[";
        for (size_t i = 0; i < c->interfaces.size(); i++) {
            if (i) o += ",";
            o += c->interfaces[i];
        }
        o += "]\n";
        for (auto& f : c->fields) o += "  field " + f.name + ": " + ty(f.type) + "\n";
        for (auto& m : c->methods) {
            o += "  method " + m.name + " abs=" + (m.isAbstract ? "1" : "0") +
                 " ret=" + ty(m.returnType) + " params=" + params(m.params) + "\n";
            if (!m.isAbstract) block(m.body, 2, o);
            o += "  end\n";
        }
        o += "end\n";
    }

    for (auto& it : prog.interfaces) {
        o += "interface " + it->name + "\n";
        for (auto& m : it->methods)
            o += "  method " + m.name + " abs=" + (m.isAbstract ? "1" : "0") +
                 " ret=" + ty(m.returnType) + " params=" + params(m.params) + "\n";
        o += "end\n";
    }

    for (auto& f : prog.functions) {
        o += "func " + f->name + " @" + std::to_string(f->line) +
             " extern=" + (f->isExtern ? "1" : "0") +
             " dll=\"" + esc(f->dllName) + "\"" +
             " ret=" + ty(f->returnType) +
             " params=" + params(f->params) + "\n";
        if (!f->isExtern) block(f->body, 1, o);
        o += "end\n";
    }
}

} // namespace progdump
