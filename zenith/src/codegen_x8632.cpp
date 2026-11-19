// codegen_x8632.cpp — true 32-bit x86 (cdecl) backend for BIOS / bare+dependent apps.
// =============================================================================
// The main emitFunction/emitExpr/emitStmt pipeline is Win64/SysV x86-64 (REX,
// 8-byte slots, RIP-relative globals, rcx/rdx/r8/r9 args). When prog.arch ==
// X86_32 (BIOS apps are forced X86_32 in main.cpp) that emitter would still
// produce 64-bit machine code, which cannot run on a 32-bit protected-mode
// kernel. This backend emits genuine 32-bit code:
//
//   * cdecl calling convention: args pushed right-to-left, result in eax.
//   * stack frame: push ebp / mov ebp,esp / sub esp,frame / leave-ret.
//   * params at [ebp+8+4*i], locals at negative [ebp+disp] (4-byte slots).
//   * globals reached via absolute disp32 (image is loaded at a fixed base).
//   * strings reached via mov eax, imm32 (absolute address), patched by the
//     same writeBiosFlatImage string-fixup logic.
//   * calls/jumps are plain rel32 (mode-agnostic; shared fixup vectors).
//   * bios_*/inb/outb/vga_* builtins are emitted inline, REX-less.
//
// Only per-function lowering is independent; string collection, import-data /
// globals allocation, flat image writer and entry point are shared.

#include "codegen.h"
#include "ast.h"
#include <iostream>
#include <cstring>
#include <fstream>

using namespace std;

// ========================================================= Registers
// eax=0 ecx=1 edx=2 ebx=3 rsp=4 rbp=5 esi=6 edi=7 (allocation pool {0,1,2,3,6,7}).
// The backend is accumulator-style (result always returned in eax), so allocReg
// is only used transiently by some helpers; regsUsed is kept tidy.

void Codegen::emitX8632MovRegImm(int r, int32_t v) {
    static const uint8_t movImm[8] = {0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};
    emit8(movImm[r & 7]);
    emit32((uint32_t)v);
}

// mov reg, [ebp+off]  (32-bit)
void Codegen::x32LoadBPImpl(int r, int off) {
    if (off >= -128 && off <= 127) {
        emit8(0x8B); emit8((uint8_t)(0x45 | ((r & 7) << 3))); emit8((uint8_t)(int8_t)off);
    } else {
        emit8(0x8B); emit8((uint8_t)(0x85 | ((r & 7) << 3))); emit32((uint32_t)(int32_t)off);
    }
}

// mov [ebp+off], eax  (32-bit)
void Codegen::x32StoreBPEaxImpl(int off) {
    if (off >= -128 && off <= 127) { emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)off); }
    else                           { emit8(0x89); emit8(0x85); emit32((uint32_t)(int32_t)off); }
}

// mov [ebp+off], reg  (32-bit)
void Codegen::x32StoreBPImpl(int r, int off) {
    if (off >= -128 && off <= 127) {
        emit8(0x89); emit8((uint8_t)(0x45 | ((r & 7) << 3))); emit8((uint8_t)(int8_t)off);
    } else {
        emit8(0x89); emit8((uint8_t)(0x85 | ((r & 7) << 3))); emit32((uint32_t)(int32_t)off);
    }
}

// lea eax, [ebp+off]
void Codegen::x32LeaEaxBPImpl(int off) {
    if (off >= -128 && off <= 127) { emit8(0x8D); emit8(0x45); emit8((uint8_t)(int8_t)off); }
    else                           { emit8(0x8D); emit8(0x85); emit32((uint32_t)(int32_t)off); }
}

// mov eax, [disp32]  (32-bit absolute, for a global in the flat image)
void Codegen::x32LoadGlobalEaxImpl(uint32_t rva) {
    emit8(0x8B); emit8(0x05);
    size_t fp = code.size();
    globalFixups.push_back({fp, rva});
    emit32(0);
}

// mov [disp32], eax  (32-bit absolute, for a global in the flat image)
void Codegen::x32StoreGlobalEaxImpl(uint32_t rva) {
    emit8(0x89); emit8(0x05);
    size_t fp = code.size();
    globalFixups.push_back({fp, rva});
    emit32(0);
}

// eax *= stride (element size for `p + k`, `p[k]`, ...).
void Codegen::x32ScaleEax(int stride) {
    if (stride == 1) return;
    // shl — the old lea shortcuts were encoded as [eax + eax*scale] (a base
    // was included), so stride 2/4/8 multiplied by 3/5/9 and `arr[5] = ...`
    // overran the array into the return address.
    if (stride == 2) { emit8(0xC1); emit8(0xE0); emit8(0x01); return; }   // shl eax,1
    if (stride == 4) { emit8(0xC1); emit8(0xE0); emit8(0x02); return; }   // shl eax,2
    if (stride == 8) { emit8(0xC1); emit8(0xE0); emit8(0x03); return; }   // shl eax,3
    emit8(0x69); emit8(0xC0); emit32((uint32_t)stride);                   // imul eax,eax,imm32
}

// eax += the field offset at every path hop; intermediate POINTER fields are
// loaded between hops so `n1.next.val` walks [[n1+nextOff]+valOff].
void Codegen::x32WalkMemberPath(const std::string& rootStruct,
                                const std::vector<std::string>& path) {
    std::string curStruct = rootStruct;
    for (size_t i = 0; i < path.size(); i++) {
        auto sl = structLayouts.find(curStruct);
        if (sl == structLayouts.end())
            throw std::runtime_error("x8632: unknown struct '" + curStruct + "'");
        auto fo = sl->second.fieldOffsets.find(path[i]);
        auto ft = sl->second.fieldTypes.find(path[i]);
        if (fo == sl->second.fieldOffsets.end() || ft == sl->second.fieldTypes.end())
            throw std::runtime_error("x8632: unknown field '" + path[i] + "' in '" + curStruct + "'");
        int off = fo->second;
        if (off != 0) {
            if (off >= -128 && off <= 127) { emit8(0x83); emit8(0xC0); emit8((uint8_t)(int8_t)off); }
            else                           { emit8(0x05); emit32((uint32_t)(int32_t)off); }
        }
        if (i + 1 < path.size() && ft->second.isPtr) {
            emit8(0x8B); emit8(0x00);              // mov eax,[eax]  (hop through the pointer)
        }
        curStruct = ft->second.structName;
    }
}

// Address of an lvalue into eax: `&x`, `&a[i]`, `&o.f`, `&(*p)`, `&func`.
int Codegen::emitX8632Addr(Expr* e) {
    if (!e) { emitX8632MovRegImm(0, 0); return 0; }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto vi = getVarInfo(id->name);
        if (!vi) {
            bool isFunc = funcOffsets.count(id->name) > 0;
            if (!isFunc)
                for (auto& f : prog.functions)
                    if (f->name == id->name && !f->isExtern) { isFunc = true; break; }
            if (isFunc) {
                emit8(0xB8);
                size_t fp = code.size();
                funcRefFixups.push_back({fp, id->name});
                emit32(0);
                return 0;
            }
            throw std::runtime_error("undefined variable '" + id->name + "'");
        }
        if (vi->isGlobal) {
            emit8(0xB8);
            size_t fp = code.size();
            globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
            emit32(0);
        } else {
            x32LeaEaxBPImpl(vi->offset);
        }
        return 0;
    }
    if (auto ao = dynamic_cast<AddressOfExpr*>(e)) {
        if (ao->target) return emitX8632Addr(ao->target.get());
        IdentExpr id;
        id.name = ao->name;
        return emitX8632Addr(&id);
    }
    if (auto d = dynamic_cast<DerefExpr*>(e)) {
        return emitX8632Expr(d->ptr.get());       // the pointer value IS the address
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        std::vector<std::string> path;
        Expr* cur = m;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) {
            path.insert(path.begin(), mm->member);
            cur = mm->object.get();
        }
        Type rootT = exprType(cur);
        if (rootT.kind != TypeKind::Struct || rootT.structName.empty())
            throw std::runtime_error("x8632: member access on a non-struct expression");
        if (rootT.isPtr) emitX8632Expr(cur);      // pointer value = object address
        else             emitX8632Addr(cur);      // object address
        x32WalkMemberPath(rootT.structName, path);
        return 0;
    }
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) {
        Type elemT = exprType(e);
        Type baseT = exprType(a->array.get());
        if (baseT.isPtr) emitX8632Expr(a->array.get());   // pointer value
        else             emitX8632Addr(a->array.get());   // array/object address
        emit8(0x50);                                     // push base
        emitX8632Expr(a->index.get());                   // eax = index
        x32ScaleEax(arrayElemStride(elemT));
        emit8(0x59);                                     // pop ecx (base)
        emit8(0x01); emit8(0xC8);                        // add eax, ecx
        return 0;
    }
    // Anything else: its value is the address (same fallback as x64).
    return emitX8632Expr(e);
}

// Address of `name` / `name[index]` / `name.p1.p2...` into eax. `name` may be
// an array/struct slot (address = slot) or a pointer variable (address = its
// value, so `p[i] = v` stores through p).
void Codegen::emitX8632LValue(const std::string& name, Expr* index,
                              const std::vector<std::string>& memberPath) {
    auto vi = getVarInfo(name);
    if (!vi) throw std::runtime_error("undefined variable '" + name + "'");
    Type vt = vi->type;
    if (vt.isPtr && vi->arraySize == 0) {
        if (vi->isGlobal) x32LoadGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
        else              x32LoadBPImpl(0, vi->offset);
    } else {
        if (vi->isGlobal) {
            emit8(0xB8);
            size_t fp = code.size();
            globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
            emit32(0);
        } else {
            x32LeaEaxBPImpl(vi->offset);
        }
    }
    if (index) {
        Type et = vt;
        et.isPtr = false;
        emit8(0x50);                        // push base
        emitX8632Expr(index);               // eax = index
        x32ScaleEax(arrayElemStride(et));
        emit8(0x59);                        // pop ecx (base)
        emit8(0x01); emit8(0xC8);           // add eax, ecx
    }
    if (!memberPath.empty()) {
        Type mt = vt;
        mt.isPtr = false;
        if (mt.kind != TypeKind::Struct || mt.structName.empty())
            throw std::runtime_error("x8632: member assignment on non-struct '" + name + "'");
        x32WalkMemberPath(mt.structName, memberPath);
    }
}

// ============================================================== Frame vars
// 32-bit variant of allocateBlockVars: locals use 4-byte slots (ints, pointers,
// bools), 4-byte floats, arrays scale by element size, structs use their layout.
void Codegen::x8632AllocateBlockVars(const Block& block) {
    for (auto& stmt : block.stmts) {
        if (auto varDecl = dynamic_cast<VarDecl*>(stmt.get())) {
            int fieldSize = 4;
            if (varDecl->arraySize > 0) {
                fieldSize = arrayElemStride(varDecl->type) * varDecl->arraySize;
            } else if (varDecl->type.kind == TypeKind::Struct && !varDecl->type.isPtr) {
                auto it = structLayouts.find(varDecl->type.structName);
                if (it != structLayouts.end()) {
                    fieldSize = it->second.totalSize;
                    if (fieldSize % 4 != 0) fieldSize += 4 - (fieldSize % 4);
                }
            } else if (varDecl->type.kind == TypeKind::Vec2) {
                fieldSize = 8;
            } else if (varDecl->type.kind == TypeKind::Vec3) {
                fieldSize = 12;
            } else if (varDecl->type.kind == TypeKind::Color) {
                fieldSize = 16;
            } else {
                fieldSize = 4;
            }
            locals += fieldSize;
            VarInfo vi;
            vi.offset = -(locals);
            vi.type = varDecl->type;
            vi.isConst = varDecl->isConst;
            vi.arraySize = varDecl->arraySize;
            varInfos[varDecl->name] = vi;
        } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt.get())) {
            if (varInfos.find(forStmt->varName) == varInfos.end()) {
                locals += 4;
                VarInfo vi;
                vi.offset = -(locals);
                vi.type = {TypeKind::Int};
                varInfos[forStmt->varName] = vi;
            }
            x8632AllocateBlockVars(forStmt->body);
        } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
            x8632AllocateBlockVars(ifStmt->thenBlock);
            x8632AllocateBlockVars(ifStmt->elseBlock);
        } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt.get())) {
            x8632AllocateBlockVars(whileStmt->body);
        } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt.get())) {
            x8632AllocateBlockVars(loopStmt->body);
        } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt.get())) {
            for (auto& sc : switchStmt->cases)
                x8632AllocateBlockVars(sc.body);
        }
    }
}

// ================================================================ Jumps
void Codegen::emitX8632Jmp(int label)       { emitJmp(label); }
void Codegen::emitX8632Jcc(const std::string& cond, int label) { emitJcc(cond, label); }

// ============================================================== Function
void Codegen::emitX8632Function(FunctionDecl* func) {
    funcOffsets[func->name] = code.size();
    varInfos.clear();
    locals = 0;
    curFuncRetType = func->returnType;

    populateGlobalVarInfos();

    // Params: cdecl pushes them right-to-left; param i is at [ebp+8+4*i].
    for (size_t i = 0; i < func->params.size(); i++) {
        VarInfo vi;
        vi.offset = 8 + (int)i * 4;
        vi.type = func->params[i].type;
        varInfos[func->params[i].name] = vi;
    }

    x8632AllocateBlockVars(func->body);

    int frame = (locals + 15) & ~15;
    funcEndLabel = newLabel();
    regsUsed = 0;
    xmmRegsUsed = 0;

    emit8(0x55);                       // push ebp
    emit8(0x89); emit8(0xE5);          // mov ebp, esp
    if (frame > 0) {
        if (frame <= 127) { emit8(0x83); emit8(0xEC); emit8((uint8_t)frame); }
        else              { emit8(0x81); emit8(0xEC); emit32((uint32_t)frame); }
    }

    for (auto& stmt : func->body.stmts) emitX8632Stmt(stmt.get());

    emitLabel(funcEndLabel);
    emit8(0xC9);                       // leave
    emit8(0xC3);                       // ret
}

// ============================================================== Float ops
// Floats travel as raw f32 bits in eax (the FloatExpr model). Both operands
// are materialized as f32 bits in two stack slots, then loaded as
// st0 = left, st1 = right for the x87 op:
//   arith: op -> st1, fstp dword [esp] writes the result into the right slot,
//          pop eax takes the bits, add esp,4 drops the left slot;
//   cmp:   fucomip st(1) sets EFLAGS for left ? right (only CF/ZF/PF are
//          defined, so only setcc forms that read CF/ZF are legal — never
//          setl/setg, which read SF/OF), fstp st0 pops the leftover right
//          operand, and the add esp,8 cleanup must come after setcc because
//          add clobbers the flags.
void Codegen::emitX8632FloatBinary(BinaryExpr* bin) {
    const std::string& op = bin->op;
    bool isCmp   = op == "<" || op == ">" || op == "<=" || op == ">=" ||
                   op == "==" || op == "!=";
    bool isArith = op == "+" || op == "-" || op == "*" || op == "/";
    if (!isCmp && !isArith)
        throw std::runtime_error("x8632: unsupported float operator '" + op + "'");

    auto toFloatBits = [&](Expr* e, bool isFloat) {
        emitX8632Expr(e);
        if (!isFloat) x32EmitItof();       // int -> f32 bits
    };

    toFloatBits(bin->left.get(),  isFloatExpr(bin->left.get()));
    emit8(0x50);                                   // push left
    toFloatBits(bin->right.get(), isFloatExpr(bin->right.get()));
    emit8(0x50);                                   // push right
    // [esp] = right bits, [esp+4] = left bits
    emit8(0xD9); emit8(0x04); emit8(0x24);         // fld dword [esp]        st0=right
    emit8(0xD9); emit8(0x44); emit8(0x24); emit8(0x04); // fld dword [esp+4]  st0=left, st1=right

    if (isCmp) {
        emit8(0xDF); emit8(0xE9);                 // fucomip st(1): flags = left ? right
        emit8(0xDD); emit8(0xD8);                 // fstp st0 (drop right)
        uint8_t setcc =
            op == "<"  ? 0x92 :   // setb
            op == ">"  ? 0x97 :   // seta
            op == "<=" ? 0x96 :   // setbe
            op == ">=" ? 0x93 :   // setae
            op == "==" ? 0x94 :   // sete
                        0x95;     // setne
        emit8(0x0F); emit8(setcc); emit8(0xC0);   // setcc al
        emit8(0x0F); emit8(0xB6); emit8(0xC0);    // movzx eax, al
        emit8(0x83); emit8(0xC4); emit8(0x08);    // add esp, 8
    } else {
        // st0 = left, st1 = right. FADDP/FMULP are symmetric, but the plain
        // FSUBP/FDIVP forms compute st1 = st1 OP st0 = right OP left, so
        // subtraction and division use the reversed forms
        // (st1 = st0 OP st1 = left OP right): FSUBRP = DE E1, FDIVRP = DE F1.
        if      (op == "+") { emit8(0xDE); emit8(0xC1); }   // faddp st1
        else if (op == "*") { emit8(0xDE); emit8(0xC9); }   // fmulp st1
        else if (op == "-") { emit8(0xDE); emit8(0xE1); }   // fsubrp st1: left-right
        else                { emit8(0xDE); emit8(0xF1); }   // fdivrp st1: left/right
        emit8(0xD9); emit8(0x1C); emit8(0x24);    // fstp dword [esp] (result bits)
        emit8(0x58);                              // pop eax
        emit8(0x83); emit8(0xC4); emit8(0x04);    // add esp, 4 (drop left slot)
    }
}

// ==================================================== Implicit conversions
// eax: int -> raw f32 bits.
void Codegen::x32EmitItof() {
    emit8(0x50);                       // push eax
    emit8(0xDB); emit8(0x04); emit8(0x24);   // fild dword [esp]
    emit8(0xD9); emit8(0x1C); emit8(0x24);   // fstp dword [esp]
    emit8(0x58);                       // pop eax
}

// eax: raw f32 bits -> int, truncated toward zero (RC=11 in the control word
// for the store only, original CW restored). Same sequence as the ftoi()
// builtin, but without touching ecx: after the push the frame is
// [esp]=bits, then sub esp,12 lays cw/modcw/result over it, so one
// `add esp,16` drops the lot.
void Codegen::x32EmitFtoi() {
    emit8(0x50);                              // push bits
    emit8(0x81); emit8(0xEC); emit32(12);     // sub esp, 12 (cw save + scratch)
    emit8(0xD9); emit8(0x3C); emit8(0x24);    // fnstcw [esp]
    emit8(0x0F); emit8(0xB7); emit8(0x0C); emit8(0x24);  // movzx ecx, word [esp]
    emit8(0x81); emit8(0xC9); emit32(0x0C00); // or ecx, 0x0C00 (RC=11: round toward zero)
    emit8(0x66); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x04);  // mov [esp+4], cx
    emit8(0xD9); emit8(0x6C); emit8(0x24); emit8(0x04);  // fldcw [esp+4]
    emit8(0xD9); emit8(0x44); emit8(0x24); emit8(0x0C);  // fld dword [esp+12]
    emit8(0xDB); emit8(0x5C); emit8(0x24); emit8(0x08);  // fistp dword [esp+8]
    emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08);  // mov eax, [esp+8]
    emit8(0xD9); emit8(0x2C); emit8(0x24);    // fldcw [esp]  (restore)
    emit8(0x81); emit8(0xC4); emit32(16);     // add esp, 16 (result block + bits)
}

// Evaluate `e` for a slot of type `t`. t == nullptr means the consumer has no
// type (e.g. a call through a function pointer with no signature) and the
// value is passed through untouched — the pre-existing behaviour.
void Codegen::emitX8632ValueAs(Expr* e, const Type* t) {
    // No type, or a void/unknown one: pass the value through untouched —
    // the behaviour before implicit conversions existed.
    if (!t || t->kind == TypeKind::Void) { emitX8632Expr(e); return; }
    bool gotFloat  = isFloatExpr(e);
    bool wantFloat = t->kind == TypeKind::Float && !t->isPtr;
    emitX8632Expr(e);
    if (wantFloat) { if (!gotFloat) x32EmitItof(); }
    else           { if (gotFloat)  x32EmitFtoi(); }
}

// Conditions are integer truth tests. `if (f)` has to truncate the float,
// not test its raw bit pattern — every bit pattern except +0.0f is non-zero,
// so an unconverted float condition would almost always be true.
static const Type kTruthType{TypeKind::Int};

// ============================================================= Expression
int Codegen::emitX8632Expr(Expr* expr) {
    // Accumulator-style: value delivered in eax, returns 0.
    if (auto num = dynamic_cast<NumberExpr*>(expr)) {
        emitX8632MovRegImm(0, (int32_t)num->value);
        return 0;
    }
    if (auto fl = dynamic_cast<FloatExpr*>(expr)) {
        float f = (float)fl->value;
        uint32_t bits;
        std::memcpy(&bits, &f, 4);
        emitX8632MovRegImm(0, (int32_t)bits);   // floats travel as raw f32 bits
        return 0;
    }
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        auto vi = getVarInfo(id->name);
        if (!vi) {
            bool isFunc = funcOffsets.count(id->name) > 0;
            if (!isFunc)
                for (auto& f : prog.functions)
                    if (f->name == id->name && !f->isExtern) { isFunc = true; break; }
            if (isFunc) {
                emit8(0xB8);
                size_t fp = code.size();
                funcRefFixups.push_back({fp, id->name});
                emit32(0);
                return 0;
            }
            // Same failure mode as the 64-bit backend: report and abort the
            // build. Printing and returning 0 leaves a fixup-less hole in the
            // image while the compiler still exits with status 0.
            throw std::runtime_error("undefined variable '" + id->name + "'");
        }
        if (vi->isGlobal) {
            x32LoadGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
        } else {
            x32LoadBPImpl(0, vi->offset);
        }
        return 0;
    }
    if (auto str = dynamic_cast<StringExpr*>(expr)) {
        int idx = -1;
        for (size_t i = 0; i < stringPool.size(); i++)
            if (stringPool[i] == str->value) { idx = (int)i; break; }
        if (idx < 0) { idx = (int)stringPool.size(); stringPool.push_back(str->value); }
        emit8(0xB8);
        size_t fp = code.size();
        strFixups.push_back({fp, idx});
        emit32(0);
        return 0;
    }
    if (auto un = dynamic_cast<UnaryExpr*>(expr)) {
        emitX8632Expr(un->operand.get());
        if (un->op == "-") {
            if (isFloatExpr(un->operand.get())) {
                // fchs on the bit pattern held in eax
                emit8(0x50);                        // push eax
                emit8(0xD9); emit8(0x04); emit8(0x24);   // fld dword [esp]
                emit8(0xD9); emit8(0xE0);               // fchs
                emit8(0xD9); emit8(0x1C); emit8(0x24);   // fstp dword [esp]
                emit8(0x58);                        // pop eax
            } else {
                emit8(0xF7); emit8(0xD8);           // neg eax
            }
        }
        else if (un->op == "~") { emit8(0xF7); emit8(0xD0); }              // not eax
        else if (un->op == "!") {
            emit8(0x85); emit8(0xC0);                  // test eax,eax
            emit8(0x0F); emit8(0x94); emit8(0xC0);     // sete al
            emit8(0x0F); emit8(0xB6); emit8(0xC0);     // movzx eax,al
        }
        return 0;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        // Float arithmetic/comparisons lower through x87 (Phase C).
        if (isFloatExpr(bin->left.get()) || isFloatExpr(bin->right.get())) {
            emitX8632FloatBinary(bin);
            return 0;
        }
        emitX8632Expr(bin->left.get());        // left -> eax
        emit8(0x50);                           // push eax (left)
        // Typed pointer arithmetic: `p + k` / `p - k` scales k by the
        // pointee size (only when k is not itself a pointer, so `p - q`
        // stays a raw difference of addresses).
        Type lt = exprType(bin->left.get());
        Type rt = exprType(bin->right.get());
        bool ptrScale = lt.isPtr && !rt.isPtr &&
                        (bin->op == "+" || bin->op == "-");
        int ptrStride = 1;
        if (ptrScale) {
            Type et = lt;
            et.isPtr = false;
            ptrStride = arrayElemStride(et);
        }
        emitX8632Expr(bin->right.get());       // right -> eax
        if (ptrScale) x32ScaleEax(ptrStride);
        emit8(0x5B);                           // pop ebx (left)
        const std::string& op = bin->op;
        if (op == "+")      { emit8(0x01); emit8(0xD8); }              // eax = left+right
        else if (op == "-") {
            // left in ebx, right in eax -> left-right:
            // mov ecx,ebx (left); sub ecx,eax (left-right); mov eax,ecx
            // `mov ecx,ebx` is 89 D9 — 89 CB would be `mov ebx,ecx`, which
            // throws the left operand away and subtracts from garbage.
            emit8(0x89); emit8(0xD9);
            emit8(0x29); emit8(0xC1);
            emit8(0x89); emit8(0xC8);
        }
        else if (op == "*") { emit8(0x0F); emit8(0xAF); emit8(0xC3); } // imul eax,ebx
        else if (op == "/") { emit8(0x89); emit8(0xC1); emit8(0x89); emit8(0xD8); emit8(0x99); emit8(0xF7); emit8(0xF9); }
                               // mov ecx,eax (right); mov eax,ebx (left); cdq; idiv ecx
        else if (op == "%") { emit8(0x89); emit8(0xC1); emit8(0x89); emit8(0xD8); emit8(0x99); emit8(0xF7); emit8(0xF9); emit8(0x89); emit8(0xD0); }
        else if (op == "&") { emit8(0x21); emit8(0xD8); }
        else if (op == "|") { emit8(0x09); emit8(0xD8); }
        else if (op == "^") { emit8(0x31); emit8(0xD8); }
        else if (op == "<<") { emit8(0x89); emit8(0xC1); emit8(0x89); emit8(0xD8); emit8(0xD3); emit8(0xE0); }
                               // mov ecx,eax (count=right); mov eax,ebx (value=left); shl eax,cl
        else if (op == ">>") { emit8(0x89); emit8(0xC1); emit8(0x89); emit8(0xD8); emit8(0xD3); emit8(0xF8); }
        else if (op == "==") { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x94); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == "!=") { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x95); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        // Relational ops compare LEFT (ebx) against RIGHT (eax), so the cmp
        // must be `cmp ebx,eax` (39 C3). The old `cmp eax,ebx` (39 D8) set
        // flags for right-left while setl/setg read them as left-right,
        // inverting `i < 4` into `i > 4` and skipping the loop entirely.
        // ==/!= keep 39 D8: they are symmetric.
        else if (op == "<")  { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9C); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == ">")  { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9F); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == "<=") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9E); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == ">=") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9D); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == "&&" || op == "||") {
            // eax && ebx : (eax!=0)&(ebx!=0)
            emit8(0x85); emit8(0xC0); emit8(0x0F); emit8(0x95); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0);
            emit8(0x85); emit8(0xDB); emit8(0x0F); emit8(0x95); emit8(0xC3); emit8(0x0F); emit8(0xB6); emit8(0xDB);
            if (op == "&&") emit8(0x21); else emit8(0x09);
            emit8(0xD8);
        }
        else {
            throw std::runtime_error("x8632: unsupported operator '" + op + "'");
        }
        return 0;
    }
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        emitX8632Call(call);
        return 0;
    }
    if (auto deref = dynamic_cast<DerefExpr*>(expr)) {
        emitX8632Expr(deref->ptr.get());
        emit8(0x8B); emit8(0x00);       // mov eax, [eax]
        return 0;
    }
    if (auto addr = dynamic_cast<AddressOfExpr*>(expr)) {
        return emitX8632Addr(expr);
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        emitX8632Addr(arr);
        emit8(0x8B); emit8(0x00);       // mov eax, [eax]
        return 0;
    }
    if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        emitX8632Addr(memb);
        emit8(0x8B); emit8(0x00);       // mov eax, [eax]
        return 0;
    }
    throw std::runtime_error("x8632: unsupported expression");
}

// ============================================================= Statement
void Codegen::emitX8632Stmt(Stmt* stmt) {
    if (auto asmStmt = dynamic_cast<AsmStmt*>(stmt)) {
        int32_t ws = asmStmt->wordSize;
        if (ws == 0) ws = wordSize;
        for (auto& instr : asmStmt->instrs) emitAsmInstr(instr, ws);
        return;
    }
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        if (ret->value) emitX8632ValueAs(ret->value.get(), &curFuncRetType);
        emitX8632Jmp(funcEndLabel);
        return;
    }
    if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        if (varDecl->init) {
            emitX8632ValueAs(varDecl->init.get(), &varDecl->type);   // eax
            auto vi = getVarInfo(varDecl->name);
            if (vi && !vi->isGlobal) {
                x32StoreBPEaxImpl(vi->offset);
            } else if (vi && vi->isGlobal) {
                x32StoreGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
            } else {
                auto it = globalOffsets.find(varDecl->name);
                if (it != globalOffsets.end()) {
                    x32StoreGlobalEaxImpl(globalsRVA + (uint32_t)it->second);
                }
            }
        }
        return;
    }
    if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        if (!assign->indexExpr && assign->memberPath.empty()) {
            auto vi = getVarInfo(assign->name);
            emitX8632ValueAs(assign->value.get(),
                             vi ? &vi->type : nullptr);     // value in eax
            if (vi && !vi->isGlobal) { x32StoreBPEaxImpl(vi->offset); return; }
            if (vi && vi->isGlobal) {
                x32StoreGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
                return;
            }
            auto it = globalOffsets.find(assign->name);
            if (it != globalOffsets.end()) {
                x32StoreGlobalEaxImpl(globalsRVA + (uint32_t)it->second);
                return;
            }
            throw std::runtime_error("undefined variable '" + assign->name + "'");
        }
        // arr[idx] = value  /  o.f = value  (through a pointer root too:
        // p[i] stores through p's value, po.x through po's value)
        const Type* slotT = nullptr;
        Type slotType;
        if (auto vi = getVarInfo(assign->name)) {
            Type vt = vi->type;
            bool ok = true;
            if (!assign->memberPath.empty()) {
                // Mirror emitX8632LValue: the walk starts at the declared
                // type with its top-level pointer qualifier removed.
                Type mt = vt; mt.isPtr = false;
                std::string cur = mt.structName;
                if (mt.kind != TypeKind::Struct || cur.empty()) ok = false;
                for (auto& m : assign->memberPath) {
                    auto sl = structLayouts.find(cur);
                    if (sl == structLayouts.end()) { ok = false; break; }
                    auto ft = sl->second.fieldTypes.find(m);
                    if (ft == sl->second.fieldTypes.end()) { ok = false; break; }
                    slotType = ft->second;
                    cur = ft->second.structName;
                }
            } else {
                slotType = vt;
                slotType.isPtr = false;
            }
            if (ok) slotT = &slotType;
        }
        emitX8632ValueAs(assign->value.get(), slotT);        // value in eax
        emit8(0x50);                                       // push value
        emitX8632LValue(assign->name, assign->indexExpr.get(), assign->memberPath);
        emit8(0x5A);                                       // pop edx (value)
        emit8(0x89); emit8(0x10);                          // mov [eax], edx
        return;
    }
    if (auto ptrAssign = dynamic_cast<PtrAssignStmt*>(stmt)) {
        Type pt = exprType(ptrAssign->ptr.get());
        pt.isPtr = false;                                // the slot is a T
        emitX8632ValueAs(ptrAssign->value.get(), &pt);   // eax = value
        emit8(0x50);                                // push value
        emitX8632Expr(ptrAssign->ptr.get());        // eax = ptr
        emit8(0x5A);                                // pop edx
        emit8(0x89); emit8(0x10);                   // mov [eax], edx
        return;
    }
    if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        emitX8632Expr(exprStmt->expr.get());
        return;
    }
    if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        emitX8632ValueAs(ifStmt->condition.get(), &kTruthType);
        emit8(0x85); emit8(0xC0);                   // test eax,eax
        int elseL = newLabel();
        int endL = newLabel();
        emitX8632Jcc("==", elseL);
        for (auto& s : ifStmt->thenBlock.stmts) emitX8632Stmt(s.get());
        emitX8632Jmp(endL);
        emitLabel(elseL);
        for (auto& s : ifStmt->elseBlock.stmts) emitX8632Stmt(s.get());
        emitLabel(endL);
        return;
    }
    if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        int top = newLabel();
        int end = newLabel();
        emitLabel(top);
        emitX8632ValueAs(whileStmt->condition.get(), &kTruthType);
        emit8(0x85); emit8(0xC0);
        emitX8632Jcc("==", end);
        breakLabelStack.push_back(end);
        continueLabelStack.push_back(top);
        for (auto& s : whileStmt->body.stmts) emitX8632Stmt(s.get());
        breakLabelStack.pop_back();
        continueLabelStack.pop_back();
        emitX8632Jmp(top);
        emitLabel(end);
        return;
    }
    if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        int top = newLabel();
        int end = newLabel();
        emitLabel(top);
        breakLabelStack.push_back(end);
        continueLabelStack.push_back(top);
        for (auto& s : loopStmt->body.stmts) emitX8632Stmt(s.get());
        breakLabelStack.pop_back();
        continueLabelStack.pop_back();
        emitX8632Jmp(top);
        emitLabel(end);
        return;
    }
    if (auto breakStmt = dynamic_cast<BreakStmt*>(stmt)) {
        (void)breakStmt;
        if (!breakLabelStack.empty()) emitX8632Jmp(breakLabelStack.back());
        else emitX8632Jmp(funcEndLabel);
        return;
    }
    if (auto contStmt = dynamic_cast<ContinueStmt*>(stmt)) {
        (void)contStmt;
        if (!continueLabelStack.empty()) emitX8632Jmp(continueLabelStack.back());
        else emitX8632Jmp(funcEndLabel);
        return;
    }
    if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        if (forStmt->start) emitX8632Expr(forStmt->start.get());
        int top = newLabel();
        int end = newLabel();
        emitLabel(top);
        if (forStmt->end) {
            emitX8632ValueAs(forStmt->end.get(), &kTruthType);
            emit8(0x85); emit8(0xC0);
            emitX8632Jcc("==", end);
        }
        breakLabelStack.push_back(end);
        continueLabelStack.push_back(top);
        for (auto& s : forStmt->body.stmts) emitX8632Stmt(s.get());
        breakLabelStack.pop_back();
        continueLabelStack.pop_back();
        // var += step (default 1)
        emitX8632Expr(forStmt->step.get());
        emit8(0x50);                                   // push step
        auto vi = getVarInfo(forStmt->varName);
        if (vi) {
            if (vi->isGlobal) x32LoadGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
            else              x32LoadBPImpl(0, vi->offset);
            emit8(0x5B);                               // pop ebx
            emit8(0x01); emit8(0xD8);                  // add eax,ebx
            if (vi->isGlobal) x32StoreGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
            else              x32StoreBPEaxImpl(vi->offset);
        }
        emitX8632Jmp(top);
        emitLabel(end);
        return;
    }
    if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        emitX8632Expr(switchStmt->condition.get());    // eax = selector
        int endL = newLabel();
        int defaultL = endL;
        for (auto& sc : switchStmt->cases) {
            if (sc.condition) {
                emit8(0x50);                           // push selector (kept for each case)
                emitX8632Expr(sc.condition.get());     // eax = case value
                emit8(0x5B);                           // pop ebx (selector)
                emit8(0x39); emit8(0xC3);              // cmp ebx (sel), eax (case)
                int nextL = newLabel();
                emit8(0x0F); emit8(0x85);              // jne nextL
                size_t jpos = code.size();
                jmpFixups.push_back({jpos, nextL});
                emit32(0);
                for (auto& s : sc.body.stmts) emitX8632Stmt(s.get());
                emitX8632Jmp(endL);
                emitLabel(nextL);
            } else {
                defaultL = newLabel();
                emitLabel(defaultL);
                for (auto& s : sc.body.stmts) emitX8632Stmt(s.get());
                emitX8632Jmp(endL);
            }
        }
        emitLabel(endL);
        return;
    }
    throw std::runtime_error("x8632: unsupported statement");
}

// =================================================================== Call
void Codegen::emitX8632Call(CallExpr* call) {
    // Builtins are emitted inline (no rel32 call target exists for them).
    if (emitX8632Builtin(call)) return;

    // Indirect call through a function pointer: kind 1 goes through the
    // named variable, kind 2 through the receiver member expression
    // (`h.cb(41)`). cdecl: arguments are already pushed RTL, then the target
    // goes into eax and we `call eax`.
    std::string fpVar;
    int calleeKind = callCalleeKind(call, fpVar);
    if (calleeKind != 0) {
        for (int i = (int)call->args.size() - 1; i >= 0; i--) {
            Type pt;
            bool have = false;
            if (calleeKind == 1) {
                if (auto vi = getVarInfo(fpVar))
                    if (vi->type.isFuncPtr() && vi->type.fn &&
                        (size_t)i < vi->type.fn->params.size()) {
                        pt = vi->type.fn->params[i]; have = true;
                    }
            } else {
                Type rt = exprType(call->receiver.get());
                if (rt.isFuncPtr() && rt.fn && (size_t)i < rt.fn->params.size()) {
                    pt = rt.fn->params[i]; have = true;
                }
            }
            emitX8632ValueAs(call->args[i].get(), have ? &pt : nullptr);
            emit8(0x50);                        // push eax
        }
        if (calleeKind == 1) {
            auto vi = getVarInfo(fpVar);
            if (!vi) throw std::runtime_error("undefined variable '" + fpVar + "'");
            if (vi->isGlobal) x32LoadGlobalEaxImpl(globalsRVA + (uint32_t)vi->offset);
            else              x32LoadBPImpl(0, vi->offset);
        } else {
            emitX8632Expr(call->receiver.get());   // callee address -> eax
        }
        emit8(0xFF); emit8(0xD0);              // call eax
        if (!call->args.empty()) {
            int nb = (int)call->args.size() * 4;
            if (nb <= 127) { emit8(0x83); emit8(0xC4); emit8((uint8_t)nb); }
            else           { emit8(0x81); emit8(0xC4); emit32((uint32_t)nb); }
        }
        return;
    }

    // Standalone function definition? (funcOffsets lookup fails for builtins.)
    bool isUser = funcOffsets.count(call->name) > 0;
    if (!isUser) {
        for (auto& f : prog.functions)
            if (f->name == call->name && !f->isExtern) { isUser = true; break; }
    }
    if (!isUser) {
        throw std::runtime_error("call to undefined function: '" + call->name + "'");
    }

    const FunctionDecl* callee = nullptr;
    for (auto& f : prog.functions)
        if (f->name == call->name && !f->isExtern) { callee = f.get(); break; }

    for (int i = (int)call->args.size() - 1; i >= 0; i--) {
        const Type* pt = (callee && (size_t)i < callee->params.size())
                           ? &callee->params[i].type : nullptr;
        emitX8632ValueAs(call->args[i].get(), pt);
        emit8(0x50);                        // push eax
    }
    emit8(0xE8);
    size_t fp = code.size();
    callFixups.push_back({fp, call->name});
    emit32(0);
    if (!call->args.empty()) {
        int nb = (int)call->args.size() * 4;
        if (nb <= 127) { emit8(0x83); emit8(0xC4); emit8((uint8_t)nb); }
        else           { emit8(0x81); emit8(0xC4); emit32((uint32_t)nb); }
    }
}

// ====================================================== Inline BIOS builtins
// 32-bit REX-less implementations of the tiny BIOS freestanding builtins.
// Returns true if the call was handled (builtin emitted inline), false if it is
// a user-defined function that must be lowered as a regular cdecl call.
bool Codegen::emitX8632Builtin(CallExpr* call) {
    const std::string& n = call->name;
    auto handled_ = [&]() -> bool { return true; };

    if (n == "hlt") { emit8(0xF4); return true; }
    if (n == "cli") { emit8(0xFA); return true; }
    if (n == "sti") { emit8(0xFB); return true; }
    if (n == "halt") {
        emit8(0xF4);
        int l = newLabel();
        emitLabel(l);
        emit8(0xEB); emit8(0xFE);          // jmp $-2
        return true;
    }
    if (n == "int") {
        NumberExpr* num = dynamic_cast<NumberExpr*>(call->args[0].get());
        if (!num) return true;
        emit8(0xCD); emit8((uint8_t)(num->value & 0xFF));
        return true;
    }
    // ---- port I/O ----
    if (n == "inb") {
        emitX8632Expr(call->args[0].get());        // port -> eax
        emit8(0x89); emit8(0xC2);                  // mov edx, eax
        emit8(0xEC);                               // in al, dx
        emit8(0x0F); emit8(0xB6); emit8(0xC0);     // movzx eax, al
        return true;
    }
    if (n == "inw") {
        emitX8632Expr(call->args[0].get());
        emit8(0x89); emit8(0xC2);
        emit8(0x66); emit8(0xED);                  // in ax, dx
        emit8(0x0F); emit8(0xB7); emit8(0xC0);     // movzx eax, ax
        return true;
    }
    if (n == "ind") {
        emitX8632Expr(call->args[0].get());
        emit8(0x89); emit8(0xC2);
        emit8(0xED);                               // in eax, dx
        return true;
    }
    if (n == "outb") {
        emitX8632Expr(call->args[0].get()); emit8(0x50);            // port
        emitX8632Expr(call->args[1].get()); emit8(0x50);            // val
        emit8(0x58);                             // pop eax (val)
        emit8(0x5A);                             // pop edx (port)
        emit8(0xEE);                             // out dx, al
        return true;
    }
    if (n == "outw") {
        emitX8632Expr(call->args[0].get()); emit8(0x50);
        emitX8632Expr(call->args[1].get()); emit8(0x50);
        emit8(0x58); emit8(0x5A);
        emit8(0x66); emit8(0xEF);                  // out dx, ax
        return true;
    }
    if (n == "outd") {
        emitX8632Expr(call->args[0].get()); emit8(0x50);
        emitX8632Expr(call->args[1].get()); emit8(0x50);
        emit8(0x58); emit8(0x5A);
        emit8(0xEF);                               // out dx, eax
        return true;
    }
    // ---- raw memory ----
    if (n == "peek32") {
        emitX8632Expr(call->args[0].get());
        emit8(0x8B); emit8(0x00);                  // mov eax,[eax]
        return true;
    }
    if (n == "peek16") {
        emitX8632Expr(call->args[0].get());
        emit8(0x0F); emit8(0xB7); emit8(0x00);     // movzx eax, word [eax]
        return true;
    }
    if (n == "peek8") {
        emitX8632Expr(call->args[0].get());
        emit8(0x0F); emit8(0xB6); emit8(0x00);     // movzx eax, byte [eax]
        return true;
    }
    if (n == "poke32") {
        emitX8632Expr(call->args[1].get());        // value
        emit8(0x50);
        emitX8632Expr(call->args[0].get());        // addr
        emit8(0x5A);                               // pop edx
        emit8(0x89); emit8(0x10);                  // mov [eax], edx
        return true;
    }
    if (n == "poke16") {
        emitX8632Expr(call->args[1].get()); emit8(0x50);
        emitX8632Expr(call->args[0].get());
        emit8(0x5A);
        emit8(0x66); emit8(0x89); emit8(0x10);     // mov [eax], dx
        return true;
    }
    if (n == "poke8") {
        emitX8632Expr(call->args[1].get()); emit8(0x50);
        emitX8632Expr(call->args[0].get());
        emit8(0x5A);
        emit8(0x88); emit8(0x10);                  // mov [eax], dl
        return true;
    }
    // ---- descriptor tables ----
    if (n == "lidt") {
        emitX8632Expr(call->args[0].get());
        emit8(0x0F); emit8(0x01); emit8(0x18);     // lidt [eax]
        return true;
    }
    if (n == "lgdt") {
        emitX8632Expr(call->args[0].get());
        emit8(0x0F); emit8(0x01); emit8(0x10);     // lgdt [eax]
        return true;
    }
    // ---- VGA text mode ----
    if (n == "vga_clear") {
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi,0xB8000
        emit8(0x66); emit8(0xB8); emit8(0x20); emit8(0x07);               // mov ax,0x0720
        emit8(0xB9); emit8(0xD0); emit8(0x07); emit8(0x00); emit8(0x00);  // mov ecx,2000
        emit8(0x66); emit8(0xF3); emit8(0xAB);                           // rep stosw
        emit8(0xC7); emit8(0x04); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);  // mov dword[0x7E00],0
        return true;
    }
    if (n == "vga_putc") {
        // Same teletype the `print` builtin uses: it understands CR/LF and
        // scrolls, and it starts the program on a clean screen. A raw cell
        // store (the old body) turned 13/10 into visible glyphs and walked
        // straight past the last cell.
        x32ProgramPrints = true;
        emitX8632Expr(call->args[0].get()); emit8(0x50);   // char
        emitX8632Expr(call->args[1].get()); emit8(0x50);   // attr
        emit8(0x5B);                             // pop ebx (attr)
        emit8(0x58);                             // pop eax (char)
        emit8(0x8A); emit8(0xE3);                // mov ah, bl
        x32TeleNeeded = true;
        emit8(0xE8);
        x32TeleCallFixups.push_back(code.size());
        emit32(0);
        return true;
    }
    if (n == "vga_print") {
        // Byte loop over the NUL-terminated string, one teletype call per
        // character, so embedded newlines wrap like `print` does.
        x32ProgramPrints = true;
        emitX8632Expr(call->args[0].get());      // str -> eax
        emit8(0x89); emit8(0xC6);                // mov esi, eax
        int loop = newLabel();
        int done = newLabel();
        emitLabel(loop);
        emit8(0x0F); emit8(0xB6); emit8(0x06);   // movzx eax, byte [esi]
        emit8(0x85); emit8(0xC0);                // test eax, eax
        emitX8632Jcc("==", done);
        emit8(0x46);                             // inc esi
        x32TeleNeeded = true;
        emit8(0xB4); emit8(0x07);                // mov ah, 7
        emit8(0xE8);
        x32TeleCallFixups.push_back(code.size());
        emit32(0);
        emitX8632Jmp(loop);
        emitLabel(done);
        emit8(0xA1); emit32(0x7E00);             // mov eax, [0x7E00] (cursor)
        return true;
    }
    // ---- firmware framebuffer (info block at 0x8000) ----
    if (n == "fb_clear") {
        emitX8632Expr(call->args[0].get());      // color -> eax
        emit8(0x50);
        emit8(0x8B); emit8(0x3C); emit8(0x25); emit8(0x00); emit8(0x80); emit8(0x00); emit8(0x00);  // mov edi,[0x8000]
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x0C); emit8(0x80); emit8(0x00); emit8(0x00);  // mov ecx,[0x800C]
        emit8(0x0F); emit8(0xAF); emit8(0x0C); emit8(0x25); emit8(0x10); emit8(0x80); emit8(0x00); emit8(0x00);  // imul ecx,[0x8010]
        emit8(0x58);                             // pop eax (color)
        emit8(0xF3); emit8(0xAB);                // rep stosd
        return true;
    }
    if (n == "fb_pixel") {
        emitX8632Expr(call->args[0].get()); emit8(0x50);   // x
        emitX8632Expr(call->args[1].get()); emit8(0x50);   // y
        emitX8632Expr(call->args[2].get()); emit8(0x50);   // color
        emit8(0x58);                             // pop eax (color)
        emit8(0x5A);                             // pop edx (y)
        emit8(0x5B);                             // pop ebx (x)
        emit8(0x8B); emit8(0x3C); emit8(0x25); emit8(0x00); emit8(0x80); emit8(0x00); emit8(0x00);  // mov edi,[0x8000]
        emit8(0x8B); emit8(0x34); emit8(0x25); emit8(0x08); emit8(0x80); emit8(0x00); emit8(0x00);  // mov esi,[0x8008] pitch
        emit8(0x0F); emit8(0xAF); emit8(0xF2);  // imul esi, edx
        emit8(0x01); emit8(0xF7);               // add edi, esi
        emit8(0x8D); emit8(0x3C); emit8(0x9F);  // lea edi,[edi+ebx*4]
        emit8(0x89); emit8(0x07);               // mov [edi], eax
        return true;
    }
    auto fbFieldLoad = [&](const std::string& name, uint32_t addr) -> bool {
        if (n != name || call->args.size() != 0) return false;
        emit8(0x8B); emit8(0x04); emit8(0x25); emit32(addr);   // mov eax,[addr]
        return true;
    };
    if (fbFieldLoad("fb_width", 0x800C)) return true;
    if (fbFieldLoad("fb_height", 0x8010)) return true;
    if (fbFieldLoad("fb_pitch", 0x8008)) return true;
    if (fbFieldLoad("fb_bpp", 0x8014)) return true;
    if (fbFieldLoad("fb_addr", 0x8000)) return true;
    // ---- keyboard ----
    if (n == "bios_check_key") {
        emit8(0xB4); emit8(0x01); emit8(0xCD); emit8(0x16);   // int 16h, ah=1
        emit8(0x0F); emit8(0x95); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0);
        return true;
    }
    if (n == "bios_get_char") {
        emit8(0xB4); emit8(0x00); emit8(0xCD); emit8(0x16);   // int 16h, ah=0
        emit8(0x0F); emit8(0xB6); emit8(0xC0);                // movzx eax, al
        return true;
    }
    if (n == "bios_set_cursor") {
        emitX8632Expr(call->args[0].get()); emit8(0x50);   // x
        emitX8632Expr(call->args[1].get()); emit8(0x50);   // y
        emit8(0x5B); emit8(0x58);               // pop ebx (y) ; pop eax (x)
        emit8(0xB7); emit8(0x00);               // mov bh,0
        emit8(0x88); emit8(0xC2);               // mov dl,al (x)
        emit8(0x88); emit8(0xDE);               // mov dh,bl (y)
        emit8(0xB4); emit8(0x02); emit8(0xCD); emit8(0x10);
        return true;
    }
    if (n == "bios_scroll") {
        emitX8632Expr(call->args[0].get());     // lines -> eax
        emit8(0xB4); emit8(0x06);               // mov ah,6
        emit8(0xB7); emit8(0x07);               // mov bh,7
        emit8(0xB5); emit8(0x00); emit8(0xB1); emit8(0x00);   // ch=0 cl=0
        emit8(0xB6); emit8(24);                // dh=24
        emit8(0xB2); emit8(79);                // dl=79
        emit8(0xCD); emit8(0x10);               // int 10h
        return true;
    }
    if (n == "bios_video_mode") {
        emitX8632Expr(call->args[0].get());
        emit8(0xB4); emit8(0x00); emit8(0xCD); emit8(0x10);
        return true;
    }
    if (n == "bios_video_int") {
        emitX8632Expr(call->args[0].get());
        emit8(0x8A); emit8(0xE0); emit8(0xCD); emit8(0x10);
        return true;
    }

    // ---- float <-> int (x87) ----
    if (n == "ftoi" && call->args.size() == 1) {
        emitX8632Expr(call->args[0].get());       // eax = float bits
        x32EmitFtoi();                            // eax = int
        return true;
    }
    if (n == "itof" && call->args.size() == 1) {
        emitX8632Expr(call->args[0].get());       // eax = int
        x32EmitItof();                            // eax = float bits
        return true;
    }

    // ---- print / println: value, then a newline (same as the console std) ----
    if (n == "print" || n == "println" || n == "printLn") {
        if (call->args.size() != 1) return false;
        // A print anywhere in the program makes emitX8632Entry wipe the
        // screen once before main runs (see x32ProgramPrints). Emitting the
        // clear right here instead would place it inside a loop whenever the
        // first print sits in one, so each iteration would erase the lines
        // printed before it.
        //
        // No `int 10h` here: the 32-bit boot stub switches to protected mode
        // and leaves the real-mode IVT as the IDT, so any `int` instruction
        // #GPs (and then triple-faults). The VGA text buffer is plain memory,
        // so the clear and the teletype helper below do it by hand.
        x32ProgramPrints = true;
        Expr* a = call->args[0].get();
        // Teletype one character: AH = attribute, AL = char (helper appended
        // by emitX8632Entry, reached through a patched rel32).
        auto tele = [&]() {
            x32TeleNeeded = true;
            emit8(0xB4); emit8(0x07);              // mov ah, 7 (default attr)
            emit8(0xE8);
            x32TeleCallFixups.push_back(code.size());
            emit32(0);
        };
        bool isStr = dynamic_cast<StringExpr*>(a) != nullptr;
        if (!isStr) {
            if (auto id = dynamic_cast<IdentExpr*>(a)) {
                VarInfo* svi = getVarInfo(id->name);
                if (svi && svi->type.kind == TypeKind::String && !svi->type.isPtr) isStr = true;
            }
        }
        if (isStr) {
            emitX8632Expr(a);                       // string pointer
            emit8(0x89); emit8(0xC6);               // mov esi, eax
            int loop = newLabel(), isChar = newLabel(), done = newLabel();
            emitLabel(loop);
            emit8(0x0F); emit8(0xB6); emit8(0x06);  // movzx eax, byte [esi]
            emit8(0x85); emit8(0xC0);               // test eax, eax
            emitX8632Jcc("==", done);
            emit8(0x46);                            // inc esi
            emit8(0x3C); emit8(0x0A);               // cmp al, 10 (LF)
            emitX8632Jcc("!=", isChar);
            emit8(0xB0); emit8(0x0D); tele();       // newline: CR first...
            emit8(0xB0); emit8(0x0A); tele();       // ...then LF
            emitX8632Jmp(loop);
            emitLabel(isChar);
            tele();
            emitX8632Jmp(loop);
            emitLabel(done);
        } else if (isFloatExpr(a)) {
            // Same format as the x64 console path: optional '-', integer
            // digits, '.', then up to 6 fraction digits, stopping early when
            // the fraction hits an exact zero (2.5 -> "2.5", 0.0 -> "0.0").
            //
            // 16-byte frame: [esp] value/frac bits, [esp+4] scratch (trunc
            // CW / int part / digit / 10.0f), [esp+8] saved CW,
            // [esp+12] digit counter. The teletype helper keeps all
            // registers (pushad/popad) but clobbers flags, so every flag
            // read sits directly after its producer.
            emit8(0x83); emit8(0xEC); emit8(0x10);          // sub esp, 16
            emitX8632Expr(a);                               // eax = f32 bits
            emit8(0x89); emit8(0x04); emit8(0x24);          // mov [esp], eax
            emit8(0xA9); emit32(0x80000000);                // test eax, sign bit
            int posF = newLabel();
            emitX8632Jcc("==", posF);
            emit8(0xB0); emit8(0x2D); tele();               // '-'
            emit8(0x81); emit8(0x24); emit8(0x24);
            emit32(0x7FFFFFFF);                             // and [esp], 0x7FFFFFFF
            emitLabel(posF);
            // Round toward zero for the fistp conversions (fnstcw/or/fldcw,
            // same as the ftoi builtin); the original CW is restored below.
            emit8(0xD9); emit8(0x7C); emit8(0x24); emit8(0x08);      // fnstcw [esp+8]
            emit8(0x66); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08); // mov ax,[esp+8]
            emit8(0x66); emit8(0x0D); emit8(0x00); emit8(0x0C);      // or ax, 0x0C00 (RC=11: chop)
            emit8(0x66); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x04); // mov [esp+4], ax
            emit8(0xD9); emit8(0x6C); emit8(0x24); emit8(0x04);      // fldcw [esp+4]
            emit8(0xD9); emit8(0x04); emit8(0x24);                   // fld [esp]
            emit8(0xDB); emit8(0x5C); emit8(0x24); emit8(0x04);      // fistp dword [esp+4]
            // ---- integer digits (same div loop as the int path) ----
            emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x04);      // mov eax, [esp+4]
            emit8(0x85); emit8(0xC0);                                // test eax, eax
            int fzero = newLabel();
            emitX8632Jcc("==", fzero);
            emit8(0x68); emit32(0x01000000);               // push marker
            emit8(0xB9); emit32(10);                       // mov ecx, 10
            int fdloop = newLabel();
            emitLabel(fdloop);
            emit8(0x31); emit8(0xD2);                      // xor edx, edx
            emit8(0xF7); emit8(0xF1);                      // div ecx
            emit8(0x80); emit8(0xC2); emit8(0x30);         // add dl, '0'
            emit8(0x52);                                   // push digit
            emit8(0x85); emit8(0xC0);
            emitX8632Jcc("!=", fdloop);
            int ftdone = newLabel();
            emitX8632Jmp(ftdone);
            emitLabel(fzero);
            emit8(0x68); emit32(0x01000000);               // push marker
            emit8(0x68); emit32(0x30);                     // push '0'
            emitLabel(ftdone);
            int ftloop = newLabel(), ftend = newLabel();
            emitLabel(ftloop);
            emit8(0x58);                                   // pop eax
            emit8(0x3D); emit32(0x01000000);               // cmp eax, marker
            emitX8632Jcc("==", ftend);
            tele();
            emitX8632Jmp(ftloop);
            emitLabel(ftend);
            // ---- '.' ----
            emit8(0xB0); emit8(0x2E); tele();
            // ---- frac = value - (float)intPart ----
            emit8(0xD9); emit8(0x04); emit8(0x24);              // fld [esp]      st0=value
            emit8(0xDB); emit8(0x44); emit8(0x24); emit8(0x04);  // fild [esp+4]   st0=int, st1=value
            emit8(0xDE); emit8(0xE9);                           // fsubp st1: value-int
            emit8(0xD9); emit8(0x1C); emit8(0x24);              // fstp [esp]     frac
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x0C);
            emit32(6);                                          // [esp+12] = 6
            int floopL = newLabel(), fendL = newLabel();
            emitLabel(floopL);
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x04);
            emit32(0x41200000);                                 // [esp+4] = 10.0f
            emit8(0xD9); emit8(0x04); emit8(0x24);              // fld [esp]
            emit8(0xD8); emit8(0x4C); emit8(0x24); emit8(0x04);  // fmul [esp+4]
            emit8(0xD9); emit8(0x1C); emit8(0x24);              // fstp [esp]     frac *= 10
            emit8(0xD9); emit8(0x04); emit8(0x24);              // fld [esp]
            emit8(0xDB); emit8(0x5C); emit8(0x24); emit8(0x04);  // fistp [esp+4]  digit (trunc)
            emit8(0xD9); emit8(0x04); emit8(0x24);              // fld [esp]      st0=frac
            emit8(0xDB); emit8(0x44); emit8(0x24); emit8(0x04);  // fild [esp+4]   st0=dig, st1=frac
            emit8(0xDE); emit8(0xE9);                           // fsubp st1: frac-dig
            emit8(0xD9); emit8(0x1C); emit8(0x24);              // fstp [esp]     frac
            emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x04);  // mov eax, [esp+4]
            emit8(0x04); emit8(0x30);                           // add al, '0'
            tele();                                             // one fraction digit
            emit8(0x83); emit8(0x3C); emit8(0x24); emit8(0x00);  // cmp dword [esp], 0
            emitX8632Jcc("==", fendL);                          // exact -> done
            emit8(0x83); emit8(0x6C); emit8(0x24); emit8(0x0C);
            emit8(0x01);                                        // sub [esp+12], 1
            emitX8632Jcc("!=", floopL);
            emitLabel(fendL);
            emit8(0xD9); emit8(0x6C); emit8(0x24); emit8(0x08);  // fldcw [esp+8] (restore)
            emit8(0x83); emit8(0xC4); emit8(0x10);              // add esp, 16
        } else {
            emitX8632Expr(a);                       // eax = value
            emit8(0x85); emit8(0xC0);               // test eax, eax
            int pos = newLabel();
            emitX8632Jcc(">=", pos);
            emit8(0x50);                            // push value
            emit8(0xB0); emit8(0x2D); tele();       // al = '-'
            emit8(0x58);                            // pop value
            emit8(0xF7); emit8(0xD8);               // neg eax
            emitLabel(pos);
            int zero = newLabel(), emitDig = newLabel();
            emit8(0x85); emit8(0xC0);
            emitX8632Jcc("==", zero);
            emit8(0x68); emit32(0x01000000);        // push marker
            emit8(0xB9); emit32(10);                // mov ecx, 10
            int dloop = newLabel();
            emitLabel(dloop);
            emit8(0x31); emit8(0xD2);               // xor edx, edx
            emit8(0xF7); emit8(0xF1);               // div ecx
            emit8(0x80); emit8(0xC2); emit8(0x30);  // add dl, '0'
            emit8(0x52);                            // push digit
            emit8(0x85); emit8(0xC0);
            emitX8632Jcc("!=", dloop);
            emitX8632Jmp(emitDig);
            emitLabel(zero);
            emit8(0x68); emit32(0x01000000);        // push marker (terminator)
            emit8(0x68); emit32(0x30);              // push '0'
            emitLabel(emitDig);
            int tloop = newLabel(), tend = newLabel();
            emitLabel(tloop);
            emit8(0x58);                            // pop eax
            emit8(0x3D); emit32(0x01000000);        // cmp eax, marker
            emitX8632Jcc("==", tend);
            tele();                                 // al = digit
            emitX8632Jmp(tloop);
            emitLabel(tend);
        }
        // Trailing newline: CR then LF (print appends '\n' on every target).
        emit8(0xB0); emit8(0x0D); tele();
        emit8(0xB0); emit8(0x0A); tele();
        return true;
    }

    return false;  // not a builtin — caller resolves as a user function call
}

// ================================================================== Entry
void Codegen::emitX8632Entry() {
    entryPointCodeOffset = code.size();
    emit8(0xFA);                               // cli
    emit8(0xBC); emit32(0x90000);              // mov esp, 0x90000
    // One screen clear before main if the program prints at all (flag set
    // while emitting the print call sites): runs exactly once, wherever the
    // first print sits in the source — in a loop it would wipe the lines
    // printed by the previous iteration.
    if (x32ProgramPrints) {
        emit8(0xBF); emit32(0xB8000);          // mov edi, 0xB8000
        emit8(0xB9); emit32(2000);             // mov ecx, 2000
        emit8(0x66); emit8(0xB8); emit8(0x20); emit8(0x07);  // mov ax,0720h
        emit8(0x66); emit8(0xF3); emit8(0xAB); // rep stosw
        emit8(0xC7); emit8(0x04); emit8(0x25); // mov dword [0x7E00], 0
        emit32(0x7E00); emit32(0);             //   (teletype cursor)
    }
    std::string entryName = "main";
    if (funcOffsets.count("main") == 0 && !prog.functions.empty())
        entryName = prog.functions[0]->name;
    emit8(0xE8);
    size_t fp = code.size();
    callFixups.push_back({fp, entryName});
    emit32(0);
    int l = newLabel();
    emitLabel(l);
    emit8(0xF4);                               // hlt
    emit8(0xEB); emit8(0xFD);                  // jmp back onto the hlt (-3)
    if (x32TeleNeeded) emitX8632TeleHelper();
}

// Software teletype: AL = character, AH = attribute, screen state at [0x7E00]
// (cell index, 0..1999 for the 80x25 text screen). Plain stores into 0xB8000,
// CR = column 0, LF = next row, scrolling when the index passes the 25th row.
void Codegen::emitX8632TeleHelper() {
    if (x32TeleEmitted) return;
    x32TeleEmitted = true;
    size_t telePos = code.size();
    for (size_t cp : x32TeleCallFixups) {
        int32_t disp = (int32_t)((int64_t)telePos - (int64_t)(cp + 4));
        code[cp]     = (uint8_t)(disp & 0xFF);
        code[cp + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[cp + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[cp + 3] = (uint8_t)((disp >> 24) & 0xFF);
    }

    int crL = newLabel(), lfL = newLabel(), scrollL = newLabel(), doneL = newLabel();

    emit8(0x60);                               // pushad
    emit8(0x8B); emit8(0x0C); emit8(0x25); emit32(0x7E00);  // mov ecx,[0x7E00]
    emit8(0x3C); emit8(0x0D);                  // cmp al, 13 (CR)
    emitX8632Jcc("==", crL);
    emit8(0x3C); emit8(0x0A);                  // cmp al, 10 (LF)
    emitX8632Jcc("==", lfL);
    emit8(0x89); emit8(0xCA);                  // mov edx, ecx
    emit8(0xD1); emit8(0xE2);                  // shl edx, 1
    emit8(0x81); emit8(0xC2); emit32(0xB8000); // add edx, 0xB8000
    emit8(0x66); emit8(0x89); emit8(0x02);     // mov [edx], ax (AH = caller's attr)
    emit8(0x41);                               // inc ecx
    emit8(0x89); emit8(0x0C); emit8(0x25); emit32(0x7E00);  // mov [0x7E00],ecx
    emit8(0x81); emit8(0xF9); emit32(2000);    // cmp ecx, 2000 (80x25 cells)
    emitX8632Jcc(">=", scrollL);
    emitX8632Jmp(doneL);

    // CR: back to the start of the current row.
    emitLabel(crL);
    emit8(0x89); emit8(0xC8);                  // mov eax, ecx
    emit8(0x31); emit8(0xD2);                  // xor edx, edx
    emit8(0xBB); emit32(80);                   // mov ebx, 80
    emit8(0xF7); emit8(0xF3);                  // div ebx
    emit8(0x31); emit8(0xD2);                  // xor edx, edx
    emit8(0xB9); emit32(80);                   // mov ecx, 80
    emit8(0xF7); emit8(0xE1);                  // mul ecx
    emit8(0xA3); emit32(0x7E00);               // mov [0x7E00], eax
    emitX8632Jmp(doneL);

    // LF: one row down.
    emitLabel(lfL);
    emit8(0x89); emit8(0xC8);                  // mov eax, ecx
    emit8(0x31); emit8(0xD2);                  // xor edx, edx
    emit8(0xBB); emit32(80);                   // mov ebx, 80
    emit8(0xF7); emit8(0xF3);                  // div ebx
    emit8(0x40);                               // inc eax
    emit8(0xB9); emit32(80);                   // mov ecx, 80
    emit8(0xF7); emit8(0xE1);                  // mul ecx
    emit8(0xA3); emit32(0x7E00);               // mov [0x7E00], eax
    emit8(0x3D); emit32(2000);                 // cmp eax, 2000 (80x25 cells)
    emitX8632Jcc("<", doneL);

    // Scroll: rows 1..24 -> 0..23, blank the last row, offset -= 80.
    emitLabel(scrollL);
    emit8(0xBE); emit32(0xB8000 + 160);        // mov esi, 0xB800A0
    emit8(0xBF); emit32(0xB8000);              // mov edi, 0xB8000
    emit8(0xB9); emit32(1920);                 // mov ecx, 1920
    emit8(0x66); emit8(0xF3); emit8(0xA5);     // rep movsw
    emit8(0xBF); emit32(0xB8000 + 3840);       // mov edi, 0xB80F00
    emit8(0xB9); emit32(80);                   // mov ecx, 80
    emit8(0x66); emit8(0xB8); emit8(0x20); emit8(0x07);  // mov ax, 0720h
    emit8(0x66); emit8(0xF3); emit8(0xAB);     // rep stosw
    emit8(0x83); emit8(0x2C); emit8(0x25); emit32(0x7E00); emit8(80);  // sub [0x7E00],80
    emitX8632Jmp(doneL);

    emitLabel(doneL);
    emit8(0x61);                               // popad
    emit8(0xC3);                               // ret
}

// ================================================================== Image
void Codegen::writeX8632Image(const std::string& path) {
    // Identical flat layout to writeBiosFlatImage (code + strings + data +
    // globals + heap + 10-byte trailer); it also patches string/global/heap
    // fixups with absolute 0x100000-based addresses, which is exactly the
    // 32-bit absolute addressing this backend emits.
    writeBiosFlatImage(path);
}