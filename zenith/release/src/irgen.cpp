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
                        auto nIt = structLayouts_.find(f.type.structName);
                        fieldSize = (nIt != structLayouts_.end()) ? nIt->second.totalSize : 8;
                        break;
                    }
                    default: fieldSize = 8; break;
                }
                if (offset % fieldSize != 0) offset += fieldSize - (offset % fieldSize);
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

bool IRGen::exprIsFloat(Expr* e) {
    if (dynamic_cast<FloatExpr*>(e)) return true;
    if (dynamic_cast<NumberExpr*>(e)) return false;
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        Type* t = varTypeOf(id->name);
        return t && t->kind == TypeKind::Float;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) return exprIsFloat(u->operand.get());
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return exprIsFloat(b->left.get()) || exprIsFloat(b->right.get());
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        // struct/vec member
        if (auto id = dynamic_cast<IdentExpr*>(m->object.get())) {
            Type* t = varTypeOf(id->name);
            if (t && (t->kind == TypeKind::Struct || t->kind == TypeKind::Vec2 ||
                      t->kind == TypeKind::Vec3 || t->kind == TypeKind::Color)) {
                std::string sn = t->kind == TypeKind::Struct ? t->structName : "";
                if (t->kind == TypeKind::Vec2) { return m->member == "x" || m->member == "y"; }
                if (t->kind == TypeKind::Vec3) { return m->member == "x" || m->member == "y" || m->member == "z"; }
                if (t->kind == TypeKind::Color) return true;
                int off = 0; Type ft;
                if (structFieldInfo(sn, m->member, off, ft)) return ft.kind == TypeKind::Float;
            }
        }
        return false;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        for (auto& f : ast_.functions) {
            if (f->name == c->name && !f->isExtern) return f->returnType.kind == TypeKind::Float;
        }
        return false;
    }
    if (dynamic_cast<StringExpr*>(e)) return false;
    if (dynamic_cast<DerefExpr*>(e)) return false;
    return false;
}

// ====================================================================
// Expression lowering
// ====================================================================

int IRGen::emitCall(CallExpr* c) {
    // ---- builtin: print / println ----
    if ((c->name == "print" || c->name == "println") && c->args.size() == 1) {
        bool isStr = false;
        if (auto id = dynamic_cast<IdentExpr*>(c->args[0].get()))
            if (auto t = globalType(id->name)) isStr = t->kind == TypeKind::String;
        if (auto s = dynamic_cast<StringExpr*>(c->args[0].get())) {
            add(IROp::PrintStr, IROperand::str(ensureString(s->value)));
        } else if (isStr) {
            int r = emitIntExpr(c->args[0].get());
            add(IROp::PrintStr, IROperand::mkReg(r));
            freeSlot(r);
        } else if (exprIsFloat(c->args[0].get())) {
            int r = emitFloatExpr(c->args[0].get());
            add(IROp::PrintFlt, IROperand::mkReg(r));
            freeSlot(r);
        } else {
            int r = emitIntExpr(c->args[0].get());
            add(IROp::PrintInt, IROperand::mkReg(r));
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
        int r = allocSlot();
        add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(p));
        freeSlot(p);
        return r;
    }
    if (auto a = dynamic_cast<AddressOfExpr*>(e)) {
        if (isGlobalVar(a->name)) {
            int r = allocSlot();
            add(IROp::LeaGlobal, IROperand::mkReg(r), IROperand::glob(a->name));
            return r;
        }
        auto it = varSlots_.find(a->name);
        if (it == varSlots_.end())
            throw std::runtime_error("IR mode: unknown variable '" + a->name + "'");
        int r = allocSlot();
        add(IROp::LeaSlot, IROperand::mkReg(r), IROperand::slot(it->second));
        return r;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        return emitArrayAccess(arr, true);
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        return emitCall(c);
    }
    throw std::runtime_error("IR mode: unsupported expression");
}

int IRGen::emitMemberLoad(MemberExpr* m) {
    // flatten a.b.c into base expression + member path
    std::vector<std::string> path;
    Expr* cur = m;
    while (auto mm = dynamic_cast<MemberExpr*>(cur)) {
        path.push_back(mm->member);
        cur = mm->object.get();
    }
    std::reverse(path.begin(), path.end());
    if (auto id = dynamic_cast<IdentExpr*>(cur)) {
        Type* t = varTypeOf(id->name);
        if (!t) throw std::runtime_error("IR mode: unknown struct base '" + id->name + "'");
        bool isPtrRoot = t->isPtr && t->kind == TypeKind::Struct;
        int totalOff = 0;
        Type curT = *t;
        int off = 0;
        for (size_t i = 0; i < path.size(); i++) {
            bool ok = false;
            if (curT.kind == TypeKind::Struct) {
                ok = structFieldInfo(curT.structName, path[i], off, curT);
            } else if (curT.kind == TypeKind::Vec2 || curT.kind == TypeKind::Vec3) {
                off = (path[i] == "y") ? 4 : (path[i] == "z" ? 8 : 0);
                curT = {TypeKind::Float};
                ok = true;
            } else if (curT.kind == TypeKind::Color) {
                static const char* cols[4] = {"r","g","b","a"};
                off = 0;
                ok = false;
                for (int j = 0; j < 4; j++) { if (cols[j] == path[i]) { off = j * 4; ok = true; break; } }
                if (ok) curT = {TypeKind::Float};
            }
            if (!ok) throw std::runtime_error("IR mode: unknown member '" + path[i] + "'");
            totalOff += off;
        }
        Type ft = curT;
        int r = allocSlot();
        if (isPtrRoot) {
            // object pointer (e.g. `this`): load the pointer, then dereference
            int p = allocSlot();
            if (isGlobalVar(id->name)) {
                add(IROp::GLoad, IROperand::mkReg(p), IROperand::glob(id->name));
            } else {
                auto pIt = varSlots_.find(id->name);
                if (pIt == varSlots_.end())
                    throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
                add(IROp::Load, IROperand::mkReg(p), IROperand::slot(pIt->second));
            }
            IROperand base = IROperand::mkReg(p);
            base.off = totalOff;
            if (ft.kind == TypeKind::Float || ft.kind == TypeKind::Bool) {
                add(IROp::PLoad32, IROperand::mkReg(r), base);
            } else {
                add(IROp::PLoad, IROperand::mkReg(r), base);
            }
            freeSlot(p);
            return r;
        }
        if (isGlobalVar(id->name)) {
            if (ft.kind == TypeKind::Float) {
                add(IROp::FGLoad, IROperand::mkReg(r), IROperand::glob(id->name), IROperand::none(), "", totalOff);
            } else if (ft.kind == TypeKind::Bool) {
                add(IROp::GLoad32, IROperand::mkReg(r), IROperand::glob(id->name), IROperand::none(), "", totalOff);
            } else {
                add(IROp::GLoad, IROperand::mkReg(r), IROperand::glob(id->name), IROperand::none(), "", totalOff);
            }
            return r;
        }
        auto it = varSlots_.find(id->name);
        if (it == varSlots_.end())
            throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
        if (ft.kind == TypeKind::Float) {
            add(IROp::FLoad, IROperand::mkReg(r), IROperand::slot(it->second), IROperand::none(), "", totalOff);
        } else if (ft.kind == TypeKind::Bool) {
            add(IROp::Load32, IROperand::mkReg(r), IROperand::slot(it->second), IROperand::none(), "", totalOff);
        } else {
            add(IROp::Load, IROperand::mkReg(r), IROperand::slot(it->second), IROperand::none(), "", totalOff);
        }
        return r;
    }
    if (auto deref = dynamic_cast<DerefExpr*>(cur)) {
        int p = emitIntExpr(deref->ptr.get());
        int totalOff = 0;
        Type ft;
        if (auto id = dynamic_cast<IdentExpr*>(deref->ptr.get())) {
            Type* t = varTypeOf(id->name);
            if (t && t->isPtr && t->kind == TypeKind::Struct) {
                Type curT = *t;
                int off = 0;
                bool ok = true;
                for (size_t i = 0; ok && i < path.size(); i++) {
                    if (curT.kind == TypeKind::Struct) {
                        ok = structFieldInfo(curT.structName, path[i], off, curT);
                    } else {
                        ok = false;
                    }
                    totalOff += off;
                }
                ft = curT;
            }
        }
        int r = allocSlot();
        IROperand base = IROperand::mkReg(p);
        base.off = totalOff;
        if (ft.kind == TypeKind::Float) add(IROp::PLoad32, IROperand::mkReg(r), base);
        else add(IROp::PLoad, IROperand::mkReg(r), base);
        freeSlot(p);
        return r;
    }
    throw std::runtime_error("IR mode: unsupported member access");
}

int IRGen::emitArrayAccess(ArrayAccessExpr* arr, bool isLoad) {
    // base must be a local/global array var
    auto id = dynamic_cast<IdentExpr*>(arr->array.get());
    if (!id) throw std::runtime_error("IR mode: unsupported array base");
    bool g = isGlobalVar(id->name);
    int elemBytes = arrayElemBytes(id->name);
    int idx = emitIntExpr(arr->index.get());
    int baseAddr = allocSlot();
    if (g) {
        add(IROp::LeaGlobal, IROperand::mkReg(baseAddr), IROperand::glob(id->name));
    } else {
        auto it = varSlots_.find(id->name);
        if (it == varSlots_.end())
            throw std::runtime_error("IR mode: unknown variable '" + id->name + "'");
        add(IROp::LeaSlot, IROperand::mkReg(baseAddr), IROperand::slot(it->second));
    }
    int scaled = scaleIdx(idx, elemBytes);
    freeSlot(idx);
    int addr = allocSlot();
    add(IROp::Add, IROperand::mkReg(addr), IROperand::mkReg(baseAddr), IROperand::mkReg(scaled));
    freeSlot(baseAddr); freeSlot(scaled);
    int r = allocSlot();
    if (elemBytes == 8) add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(addr));
    else if (elemBytes == 4) add(IROp::PLoad32Z, IROperand::mkReg(r), IROperand::mkReg(addr));
    else add(IROp::PLoad, IROperand::mkReg(r), IROperand::mkReg(addr));
    freeSlot(addr);
    (void)isLoad;
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
            nSlots = (vd->arraySize * typeBytes(vd->type.kind) + 7) / 8;
        } else if (vd->type.kind == TypeKind::Struct) {
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
        if (vd->init) {
            if (vd->type.kind == TypeKind::Float) {
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
        int v = emitIntExpr(pa->value.get());
        add(IROp::PStore, IROperand::mkReg(p), IROperand::mkReg(v));
        freeSlot(p); freeSlot(v);
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
        int startV = emitIntExpr(f->start.get());
        add(IROp::Store, IROperand::slot(slot), IROperand::mkReg(startV));
        freeSlot(startV);
        int step = 1;
        if (f->step) {
            if (auto n = dynamic_cast<NumberExpr*>(f->step.get())) step = (int)n->value;
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
        if (step >= 0) add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), "<");
        else add(IROp::BrCC, IROperand::mkReg(iV), IROperand::mkReg(endV), IROperand::lbl(bodyL), ">");
        add(IROp::Br, IROperand::none(), IROperand::lbl(endL));
        add(IROp::Label, IROperand::lbl(bodyL));
        for (auto& st : f->body.stmts) emitStmt(st.get());
        // continue jumps here to run the increment
        add(IROp::Label, IROperand::lbl(contL));
        // i += step  (fresh temp: single-assignment, no read-after-write)
        int cur = allocSlot();
        add(IROp::Load, IROperand::mkReg(cur), IROperand::slot(slot));
        int next = allocSlot();
        if (step == 1) {
            add(IROp::Add, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(1));
        } else if (step == -1) {
            add(IROp::Sub, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(1));
        } else {
            add(IROp::Add, IROperand::mkReg(next), IROperand::mkReg(cur), IROperand::mkImm(step));
        }
        add(IROp::Store, IROperand::slot(slot), IROperand::mkReg(next));
        freeSlot(cur);
        freeSlot(next);
        freeSlot(endV);
        freeSlot(iV);
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
    throw std::runtime_error("IR mode: unsupported statement");
}

void IRGen::emitAssign(AssignStmt* as) {
    // a[i] = v  (array element)
    if (as->indexExpr) {
        auto id = dynamic_cast<IdentExpr*>(as->indexExpr.get());
        (void)id;
        // indexExpr is the *index*; name is the array var
        // build: addr = &name + index*elem; store value
        if (!isGlobalVar(as->name) && varSlots_.count(as->name) == 0)
            throw std::runtime_error("IR mode: unknown variable '" + as->name + "'");
        int elemBytes = arrayElemBytes(as->name);
        int idx = emitIntExpr(as->indexExpr.get());
        int baseAddr = allocSlot();
        if (isGlobalVar(as->name))
            add(IROp::LeaGlobal, IROperand::mkReg(baseAddr), IROperand::glob(as->name));
        else
            add(IROp::LeaSlot, IROperand::mkReg(baseAddr), IROperand::slot(varSlots_[as->name]));
        int scaled = scaleIdx(idx, elemBytes);
        freeSlot(idx);
        int addr = allocSlot();
        add(IROp::Add, IROperand::mkReg(addr), IROperand::mkReg(baseAddr), IROperand::mkReg(scaled));
        freeSlot(baseAddr); freeSlot(scaled);
        int v = emitIntExpr(as->value.get());
        if (elemBytes == 8) add(IROp::PStore, IROperand::mkReg(addr), IROperand::mkReg(v));
        else if (elemBytes == 4) add(IROp::PStore32, IROperand::mkReg(addr), IROperand::mkReg(v));
        else add(IROp::PStore, IROperand::mkReg(addr), IROperand::mkReg(v));
        freeSlot(addr); freeSlot(v);
        return;
    }

    // s.field = v  (member)
    if (!as->memberPath.empty()) {
        bool g = isGlobalVar(as->name);
        Type* t = varTypeOf(as->name);
        if (!t) throw std::runtime_error("IR mode: unknown member target '" + as->name + "'");
        bool isPtrRoot = t->isPtr && t->kind == TypeKind::Struct;
        int totalOff = 0;
        Type curT = *t;
        int off = 0;
        for (size_t i = 0; i < as->memberPath.size(); i++) {
            bool ok = false;
            if (curT.kind == TypeKind::Struct) {
                ok = structFieldInfo(curT.structName, as->memberPath[i], off, curT);
            } else if (curT.kind == TypeKind::Vec2 || curT.kind == TypeKind::Vec3) {
                off = (as->memberPath[i] == "y") ? 4 : (as->memberPath[i] == "z" ? 8 : 0);
                curT = {TypeKind::Float};
                ok = true;
            } else if (curT.kind == TypeKind::Color) {
                static const char* cols[4] = {"r","g","b","a"};
                off = 0;
                ok = false;
                for (int j = 0; j < 4; j++) { if (cols[j] == as->memberPath[i]) { off = j * 4; ok = true; break; } }
                if (ok) curT = {TypeKind::Float};
            }
            if (!ok) throw std::runtime_error("IR mode: unknown member '" + as->memberPath[i] + "' of '" + as->name + "'");
            totalOff += off;
        }
        Type ft = curT;
        if (isPtrRoot) {
            // object pointer (e.g. `this`): store through the pointer
            int p = allocSlot();
            if (isGlobalVar(as->name)) {
                add(IROp::GLoad, IROperand::mkReg(p), IROperand::glob(as->name));
            } else {
                auto pIt = varSlots_.find(as->name);
                if (pIt == varSlots_.end())
                    throw std::runtime_error("IR mode: unknown variable '" + as->name + "'");
                add(IROp::Load, IROperand::mkReg(p), IROperand::slot(pIt->second));
            }
            IROperand base = IROperand::mkReg(p);
            base.off = totalOff;
            if (ft.kind == TypeKind::Float) {
                int v = emitFloatExpr(as->value.get());
                add(IROp::FPStore, base, IROperand::mkReg(v));
                freeSlot(v);
            } else if (ft.kind == TypeKind::Bool) {
                int v = emitIntExpr(as->value.get());
                add(IROp::PStore32, base, IROperand::mkReg(v));
                freeSlot(v);
            } else {
                int v = emitIntExpr(as->value.get());
                add(IROp::PStore, base, IROperand::mkReg(v));
                freeSlot(v);
            }
            freeSlot(p);
            return;
        }
        if (ft.kind == TypeKind::Float) {
            int v = emitFloatExpr(as->value.get());
            if (g) add(IROp::FGStore, IROperand::glob(as->name), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            else add(IROp::FStore, IROperand::slot(varSlots_[as->name]), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            freeSlot(v);
        } else if (ft.kind == TypeKind::Bool) {
            int v = emitIntExpr(as->value.get());
            if (g) add(IROp::GStore32, IROperand::glob(as->name), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            else add(IROp::Store32, IROperand::slot(varSlots_[as->name]), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            freeSlot(v);
        } else {
            int v = emitIntExpr(as->value.get());
            if (g) add(IROp::GStore, IROperand::glob(as->name), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            else add(IROp::Store, IROperand::slot(varSlots_[as->name]), IROperand::mkReg(v), IROperand::none(), "", totalOff);
            freeSlot(v);
        }
        return;
    }

    // plain var = v
    if (isGlobalVar(as->name)) {
        if (auto t = varTypeOf(as->name)) {
            if (t->kind == TypeKind::Float) {
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
        if (t->kind == TypeKind::Float) {
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
        if (g->type.kind == TypeKind::Float) {
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
            if (g->type.kind == TypeKind::Float || g->type.kind == TypeKind::Bool) elem = 4;
            else if (g->type.kind == TypeKind::Struct && !g->type.isPtr) {
                auto it = structLayouts_.find(g->type.structName);
                if (it != structLayouts_.end()) elem = it->second.totalSize;
            }
            ig.size = g->arraySize * elem;
        }
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
}
