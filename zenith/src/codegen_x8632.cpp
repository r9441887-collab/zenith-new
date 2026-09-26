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

// ============================================================== Frame vars
// 32-bit variant of allocateBlockVars: locals use 4-byte slots (ints, pointers,
// bools), 4-byte floats, arrays scale by element size, structs use their layout.
void Codegen::x8632AllocateBlockVars(const Block& block) {
    for (auto& stmt : block.stmts) {
        if (auto varDecl = dynamic_cast<VarDecl*>(stmt.get())) {
            int fieldSize = 4;
            if (varDecl->arraySize > 0) {
                int elemSize = (varDecl->type.kind == TypeKind::Float) ? 4 : 4;
                fieldSize = elemSize * varDecl->arraySize;
            } else if (varDecl->type.kind == TypeKind::Struct && !varDecl->type.isPtr) {
                auto it = structLayouts.find(varDecl->type.structName);
                if (it != structLayouts.end()) {
                    fieldSize = it->second.totalSize;
                    if (fieldSize % 4 != 0) fieldSize += 4 - (fieldSize % 4);
                }
            } else if (varDecl->type.kind == TypeKind::Float ||
                       varDecl->type.kind == TypeKind::Bool) {
                fieldSize = 4;
            } else {
                fieldSize = 4;
            }
            locals += fieldSize;
            VarInfo vi;
            vi.offset = -(locals);
            vi.type = varDecl->type;
            vi.isConst = varDecl->isConst;
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

// ============================================================= Expression
int Codegen::emitX8632Expr(Expr* expr) {
    // Accumulator-style: value delivered in eax, returns 0.
    if (auto num = dynamic_cast<NumberExpr*>(expr)) {
        emitX8632MovRegImm(0, (int32_t)num->value);
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
            std::cerr << "Error: undefined variable '" << id->name << "'\n";
            emitX8632MovRegImm(0, 0);
            return 0;
        }
        if (vi->isGlobal) {
            emit8(0x8B); emit8(0x05);            // mov eax, [disp32]
            size_t fp = code.size();
            globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
            emit32(0);
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
        if (un->op == "-")      { emit8(0xF7); emit8(0xD8); }              // neg eax
        else if (un->op == "~") { emit8(0xF7); emit8(0xD0); }              // not eax
        else if (un->op == "!") {
            emit8(0x85); emit8(0xC0);                  // test eax,eax
            emit8(0x0F); emit8(0x94); emit8(0xC0);     // sete al
            emit8(0x0F); emit8(0xB6); emit8(0xC0);     // movzx eax,al
        }
        return 0;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        emitX8632Expr(bin->left.get());        // left -> eax
        emit8(0x50);                           // push eax (left)
        emitX8632Expr(bin->right.get());       // right -> eax
        emit8(0x5B);                           // pop ebx (left)
        const std::string& op = bin->op;
        if (op == "+")      { emit8(0x01); emit8(0xD8); }              // eax = left+right
        else if (op == "-") {
            // left in ebx, right in eax -> left-right:
            // mov ecx,ebx (left); sub ecx,eax (left-right); mov eax,ecx
            emit8(0x89); emit8(0xCB);
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
        else if (op == "<")  { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x9C); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == ">")  { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x9F); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == "<=") { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x9E); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
        else if (op == ">=") { emit8(0x39); emit8(0xD8); emit8(0x0F); emit8(0x9D); emit8(0xC0); emit8(0x0F); emit8(0xB6); emit8(0xC0); }
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
        auto vi = getVarInfo(addr->name);
        if (vi && !vi->isGlobal) {
            x32LeaEaxBPImpl(vi->offset);
        } else if (vi && vi->isGlobal) {
            emit8(0xB8);
            size_t fp = code.size();
            globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
            emit32(0);
        } else {
            emitX8632MovRegImm(0, 0);
        }
        return 0;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        auto objId = dynamic_cast<IdentExpr*>(arr->array.get());
        if (objId) {
            auto vi = getVarInfo(objId->name);
            if (vi) {
                int elemSize = 4;
                emitX8632Expr(arr->index.get());      // idx -> eax
                emit8(0x50);                          // push idx
                if (vi->isGlobal) {
                    emit8(0x8D); emit8(0x05);         // lea eax,[disp32]
                    size_t fp = code.size();
                    globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
                    emit32(0);
                } else {
                    x32LeaEaxBPImpl(vi->offset);
                }
                emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x04);   // mov ecx,[esp+4]
                emit8(0x8D); emit8(0x04); emit8(0x88);                // lea eax,[eax+ecx*4]
                emit8(0x83); emit8(0xC4); emit8(0x04);
                emit8(0x8B); emit8(0x00);                             // mov eax,[eax]
                return 0;
            }
        }
        return 0;
    }
    if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        std::vector<std::string> path;
        Expr* cur = memb;
        std::string baseName;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) { path.insert(path.begin(), mm->member); cur = mm->object.get(); }
        if (auto objId = dynamic_cast<IdentExpr*>(cur)) baseName = objId->name;
        if (!baseName.empty()) {
            auto vi = getVarInfo(baseName);
            if (vi) {
                std::string curStruct = vi->type.structName;
                int totalOff = 0; bool found = true; Type fieldType;
                for (size_t i = 0; found && i < path.size(); i++) {
                    auto slIt = structLayouts.find(curStruct);
                    if (slIt == structLayouts.end()) { found = false; break; }
                    auto& layout = slIt->second;
                    auto fIt = layout.fieldOffsets.find(path[i]);
                    auto fTypeIt = layout.fieldTypes.find(path[i]);
                    if (fIt == layout.fieldOffsets.end() || fTypeIt == layout.fieldTypes.end()) { found = false; break; }
                    totalOff += fIt->second;
                    fieldType = fTypeIt->second;
                    curStruct = fieldType.structName;
                }
                if (found) {
                    bool isPtrRoot = vi->type.isPtr && vi->type.kind == TypeKind::Struct;
                    if (isPtrRoot) {
                        if (vi->isGlobal) { emit8(0x8B); emit8(0x05); size_t fp=code.size(); globalFixups.push_back({fp, globalsRVA+(uint32_t)vi->offset}); emit32(0); }
                        else x32LoadBPImpl(0, vi->offset);
                        emit8(0x8B); emit8(0x40); emit8((uint8_t)(int8_t)totalOff);  // mov eax,[eax+off]
                    } else {
                        if (vi->isGlobal) {
                            emit8(0x8B); emit8(0x05);
                            size_t fp = code.size();
                            globalFixups.push_back({fp, globalsRVA + (uint32_t)(vi->offset + totalOff)});
                            emit32(0);
                        } else {
                            x32LoadBPImpl(0, vi->offset + totalOff);
                        }
                    }
                    return 0;
                }
            }
        }
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
        if (ret->value) emitX8632Expr(ret->value.get());
        emitX8632Jmp(funcEndLabel);
        return;
    }
    if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        if (varDecl->init) {
            emitX8632Expr(varDecl->init.get());       // eax
            auto vi = getVarInfo(varDecl->name);
            if (vi) x32StoreBPEaxImpl(vi->offset);
            else {
                auto it = globalOffsets.find(varDecl->name);
                if (it != globalOffsets.end()) {
                    emit8(0x89); emit8(0x05);
                    size_t fp = code.size();
                    globalFixups.push_back({fp, globalsRVA + (uint32_t)it->second});
                    emit32(0);
                }
            }
        }
        return;
    }
    if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        emitX8632Expr(assign->value.get());            // value in eax
        if (!assign->indexExpr && assign->memberPath.empty()) {
            auto vi = getVarInfo(assign->name);
            if (vi) { x32StoreBPEaxImpl(vi->offset); return; }
            auto it = globalOffsets.find(assign->name);
            if (it != globalOffsets.end()) {
                emit8(0x89); emit8(0x05);
                size_t fp = code.size();
                globalFixups.push_back({fp, globalsRVA + (uint32_t)it->second});
                emit32(0);
                return;
            }
            std::cerr << "Error: undefined variable '" << assign->name << "'\n";
            return;
        }
        // arr[idx] = value
        if (assign->indexExpr) {
            emit8(0x50);                                // push value (eax)
            emitX8632Expr(assign->indexExpr.get());     // index -> eax
            emit8(0x50);                                // push index
            auto vi = getVarInfo(assign->name);
            if (vi) {
                if (vi->isGlobal) {
                    emit8(0x8D); emit8(0x05);
                    size_t fp = code.size();
                    globalFixups.push_back({fp, globalsRVA + (uint32_t)vi->offset});
                    emit32(0);
                } else {
                    x32LeaEaxBPImpl(vi->offset);
                }
                emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x04);   // mov ecx,[esp+4] (idx)
                emit8(0x8D); emit8(0x04); emit8(0x88);                // lea eax,[eax+ecx*4]
                emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x08);   // mov ecx,[esp+8] (value)
                emit8(0x89); emit8(0x08);                             // mov [eax], ecx
                emit8(0x83); emit8(0xC4); emit8(0x08);
            }
        }
        return;
    }
    if (auto ptrAssign = dynamic_cast<PtrAssignStmt*>(stmt)) {
        emitX8632Expr(ptrAssign->value.get());      // eax = value
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
        emitX8632Expr(ifStmt->condition.get());
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
        emitX8632Expr(whileStmt->condition.get());
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
            emitX8632Expr(forStmt->end.get());
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
            x32LoadBPImpl(0, vi->offset);
            emit8(0x5B);                               // pop ebx
            emit8(0x01); emit8(0xD8);                  // add eax,ebx
            x32StoreBPEaxImpl(vi->offset);
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

    // Standalone function definition? (funcOffsets lookup fails for builtins.)
    bool isUser = funcOffsets.count(call->name) > 0;
    if (!isUser) {
        for (auto& f : prog.functions)
            if (f->name == call->name && !f->isExtern) { isUser = true; break; }
    }
    if (!isUser) {
        std::cerr << "Error: undefined function '" << call->name << "'\n";
        return;
    }

    for (int i = (int)call->args.size() - 1; i >= 0; i--) {
        emitX8632Expr(call->args[i].get());
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
        emitX8632Expr(call->args[0].get()); emit8(0x50);   // char
        emitX8632Expr(call->args[1].get()); emit8(0x50);   // attr
        emit8(0x5B);                             // pop ebx (attr)
        emit8(0x58);                             // pop eax (char)
        emit8(0x8A); emit8(0xE3);                // mov ah, bl
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi,0xB8000
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov ecx,[0x7E00]
        emit8(0x01); emit8(0xC9);                // add ecx,ecx
        emit8(0x01); emit8(0xCF);                // add edi,ecx
        emit8(0x66); emit8(0x89); emit8(0x07);   // mov [edi], ax
        emit8(0xFF); emit8(0x04); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // inc dword[0x7E00]
        return true;
    }
    if (n == "vga_print") {
        emitX8632Expr(call->args[0].get());      // str -> eax
        emit8(0x89); emit8(0xC6);                // mov esi, eax
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi,0xB8000
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov ecx,[0x7E00]
        emit8(0x01); emit8(0xC9); emit8(0x01); emit8(0xCF);
        int loop = newLabel();
        int done = newLabel();
        emitLabel(loop);
        emit8(0x0F); emit8(0xB6); emit8(0x06);   // movzx eax, byte [esi]
        emit8(0x85); emit8(0xC0);
        emitX8632Jcc("==", done);
        emit8(0xB4); emit8(0x07);                // mov ah, 7
        emit8(0x66); emit8(0x89); emit8(0x07);   // mov [edi], ax
        emit8(0x46);                             // inc esi
        emit8(0x83); emit8(0xC7); emit8(0x02);   // add edi, 2
        emitX8632Jmp(loop);
        emitLabel(done);
        emit8(0x89); emit8(0xF8);                // mov eax, edi
        emit8(0x2D); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // sub eax, 0xB8000
        emit8(0xD1); emit8(0xE8);                // shr eax, 1
        emit8(0xA3); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov [0x7E00], eax
        emit8(0x31); emit8(0xC0);                // xor eax, eax
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

    return false;  // not a builtin — caller resolves as a user function call
}

// ================================================================== Entry
void Codegen::emitX8632Entry() {
    entryPointCodeOffset = code.size();
    emit8(0xFA);                               // cli
    emit8(0xBC); emit32(0x90000);              // mov esp, 0x90000
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
    emit8(0xEB); emit8(0xFC);                  // jmp $-2
}

// ================================================================== Image
void Codegen::writeX8632Image(const std::string& path) {
    // Identical flat layout to writeBiosFlatImage (code + strings + data +
    // globals + heap + 10-byte trailer); it also patches string/global/heap
    // fixups with absolute 0x100000-based addresses, which is exactly the
    // 32-bit absolute addressing this backend emits.
    writeBiosFlatImage(path);
}