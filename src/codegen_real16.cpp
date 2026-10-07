// codegen_real16.cpp — pure 16-bit real-mode backend (asm16 / asm_word_size: 16)
// =============================================================================
// Produces a flat 16-bit real-mode image that can be booted directly by the
// BIOS (or entered from a UEFI trampoline). Execution begins in 16-bit mode:
//   - BIOS:  the BIOS already runs in 16-bit real mode, so no mode switch is
//            needed; the image is a plain boot block (ORG 0x7C00).
//   - UEFI:  a separate trampoline switches to 16-bit real mode and far-jumps
//            into this image (see documentation/14_ассемблер.txt).
// Everything here is emitted with 16-bit operand/address sizes: no REX, 16-bit
// registers (ax/bx/cx/dx/sp/bp/si/di) and 16-bit addressing modes.
//
// All values live in the accumulator chain ax/cx/dx (regs 0/1/2) and memory is
// addressed via [bp+disp] for locals/params and absolute addresses for the
// boot block. Global variables are stored after the code, addressed directly.

#include "codegen.h"
#include "ast.h"
#include <iostream>
#include <fstream>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

// Windows wide/narrow path conversion (duplicated from codegen_pe.cpp so this
// translation unit stays self-contained).
static std::filesystem::path safeNarrowToPath(const std::string& s) {
#ifdef _WIN32
    int wlen = MultiByteToWideChar(0 /*CP_ACP*/, 0, s.c_str(), -1, nullptr, 0);
    if (wlen > 0) {
        std::wstring ws(static_cast<size_t>(wlen), L'\0');
        if (MultiByteToWideChar(0, 0, s.c_str(), -1, ws.data(), wlen) == 0) {
            return std::filesystem::path(s);
        }
        ws.resize(static_cast<size_t>(wlen - 1));
        return std::filesystem::path(ws);
    }
    return std::filesystem::path(s);
#else
    return s;
#endif
}

// 16-bit register encoding for the ModRM "reg" field (0=ax,1=cx,2=dx,3=bx,
// 4=sp,5=bp,6=si,7=di). We only ever allocate ax/cx/dx/bx (0..3).
void Codegen::emitReal16Jmp(int label) {
    emit8(0xE9); emit16(0);
    real16JmpFixups.push_back({code.size() - 2, label});
}

void Codegen::emitReal16Jcc(const std::string& cond, int label) {
    int cc = 0x84;
    if (cond == "==" || cond == "=") cc = 0x84;       // jz / je
    else if (cond == "!=" || cond == "!") cc = 0x85;  // jnz / jne
    else if (cond == "<") cc = 0x8C;                  // jl  (signed, like the x86-64 backend)
    else if (cond == "<=") cc = 0x8E;                 // jle
    else if (cond == ">") cc = 0x8F;                  // jg
    else if (cond == ">=") cc = 0x8D;                 // jge
    emit8(0x0F); emit8((uint8_t)(0x80 | cc)); emit16(0);
    real16JmpFixups.push_back({code.size() - 2, label});
}

void Codegen::emitReal16Entry() {
    // 16-bit real-mode entry point. The BIOS (or the UEFI trampoline) jumps
    // here with cs:ip pointing at the first byte. Real mode: no stack yet.
    // We set up a flat-ish stack below the image and call main().
    entryPointCodeOffset = code.size();
    emit8(0xFA);           // cli
    emit8(0xBC); emit16(0x9C00);  // mov sp, 0x9C00 (below the 0x9FC00 IVT end)
    // call main (or the first defined function)
    std::string entryName = "main";
    if (funcOffsets.count("main") == 0 && !prog.functions.empty())
        entryName = prog.functions[0]->name;
    emit8(0xE8); emit16(0);
    real16CallFixups.push_back({code.size() - 2, entryName});
    // halt loop
    emit8(0xF4);           // hlt
    emit8(0xEB); emit8(0xFD);  // jmp back onto the hlt (-3), not the byte before it
}

// ModRM helper for 16-bit addressing. reg = ModRM.reg field (dest/src code),
// memRM = rm field for [bp+disp8] -> mod=1 rm=101(bp).
static void emitModrm16(vector<uint8_t>& c, int mod, int reg, int rm) {
    c.push_back((uint8_t)(((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)));
}

void Codegen::emitReal16Function(FunctionDecl* func) {
    funcOffsets[func->name] = code.size();
    varInfos.clear();
    locals = 0;

    // Params: on the stack after the 2-byte return address: [bp+4], [bp+6], ...
    for (size_t i = 0; i < func->params.size(); i++) {
        VarInfo vi;
        vi.offset = 4 + (int)i * 2;
        vi.type = func->params[i].type;
        varInfos[func->params[i].name] = vi;
        locals += 2;
    }

    // Locals: negative offsets from bp.
    for (auto& stmt : func->body.stmts) {
        if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) {
            locals += 2;
            VarInfo vi;
            vi.offset = -locals;
            vi.type = vd->type;
            varInfos[vd->name] = vi;
        }
    }

    // frame: locals rounded up to 2
    int frame = (locals + 1) & ~1;
    funcEndLabel = newLabel();
    real16JmpFixups.clear();
    real16LoopStack.clear();

    // prologue: push bp; mov bp,sp; sub sp,frame
    emit8(0x55);                  // push bp
    emit8(0x89); emit8(0xE5);     // mov bp, sp
    if (frame > 0) {
        if (frame <= 127) {
            emit8(0x83); emit8(0xEC); emit8((uint8_t)frame);  // sub sp, imm8
        } else {
            emit8(0x81); emit8(0xEC); emit16((uint16_t)frame);  // sub sp, imm16
        }
    }

    for (auto& stmt : func->body.stmts) emitReal16Stmt(stmt.get());

    emitLabel(funcEndLabel);
    // epilogue: mov sp,bp; pop bp; ret
    emit8(0x89); emit8(0xEC);     // mov sp, bp
    emit8(0x5D);                  // pop bp
    emit8(0xC3);                  // ret

    // Resolve jumps that target labels emitted inside this function.
    for (auto& jf : real16JmpFixups) {
        int targetPos = 0;
        if (jf.second >= 0 && jf.second < (int)labelPositions.size())
            targetPos = labelPositions[jf.second];
        int64_t rel = targetPos - (int64_t)(jf.first + 2);
        code[jf.first]     = (uint8_t)(rel & 0xFF);
        code[jf.first + 1] = (uint8_t)((rel >> 8) & 0xFF);
    }
}

int Codegen::emitReal16Expr(Expr* expr) {
    if (auto num = dynamic_cast<NumberExpr*>(expr)) {
        emit8((uint8_t)(0xB8));            // mov ax, imm16
        emit16((uint16_t)(num->value & 0xFFFF));
        return 0;
    }
    if (auto ident = dynamic_cast<IdentExpr*>(expr)) {
        auto vi = getVarInfo(ident->name);
        if (!vi) {
            for (auto& g : prog.globals) {
                if (g->name == ident->name) {
                    emit8(0xA1); emit16(0);  // mov ax, [imm16] (patched in writeReal16Image)
                    real16GlobalFixups.push_back({(int)code.size() - 2, ident->name});
                    return 0;
                }
            }
            fprintf(stderr, "Error: undefined variable '%s'\n", ident->name.c_str());
            throw std::runtime_error("asm16: undefined variable '" + ident->name + "'");
        }
        emit8(0x8B); emit8(0x46); emit8((uint8_t)(int8_t)vi->offset);  // mov ax,[bp+off]
        return 0;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        int l = emitReal16Expr(bin->left.get());
        emit8(0x50);                       // push ax (left)
        int r = emitReal16Expr(bin->right.get());
        (void)r;
        emit8(0x5B);                       // pop bx (left -> bx)
        const std::string& op = bin->op;
        if (op == "+") { emit8(0x01); emit8(0xD8); }              // add ax,bx
        else if (op == "-") { emit8(0x29); emit8(0xC3); emit8(0x89); emit8(0xD8); }  // sub bx,ax; mov ax,bx (left - right)
        else if (op == "*") { emit8(0xF7); emit8(0xE3); }         // mul bx -> dx:ax
        else if (op == "&") { emit8(0x21); emit8(0xD8); }         // and ax,bx
        else if (op == "|") { emit8(0x09); emit8(0xD8); }         // or ax,bx
        else if (op == "^") { emit8(0x31); emit8(0xD8); }         // xor ax,bx
        else if (op == "==") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x94); emit8(0xC0); emit8(0x98); } // cmp bx,ax; sete al; cbw
        else if (op == "!=") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x95); emit8(0xC0); emit8(0x98); } // setne
        else if (op == "<")  { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9C); emit8(0xC0); emit8(0x98); } // setl
        else if (op == ">")  { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9F); emit8(0xC0); emit8(0x98); } // setg
        else if (op == "<=") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9E); emit8(0xC0); emit8(0x98); } // setle
        else if (op == ">=") { emit8(0x39); emit8(0xC3); emit8(0x0F); emit8(0x9D); emit8(0xC0); emit8(0x98); } // setge
        else {
            // BUG FIX: previously this merely printed a warning and emitted NO
            // opcode, silently producing wrong code. Throw so the compiler
            // reports the error instead of emitting a corrupt boot image.
            throw std::runtime_error("asm16: unsupported operator '" + op + "'");
        }
        return 0;
    }
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        return emitReal16Call(call);
    }
    throw std::runtime_error("asm16: unsupported expression (result not implemented)");
}

int Codegen::emitReal16Call(CallExpr* call) {
    // Real-mode calling convention (all in 16-bit words):
    //   push args right-to-left; call rel16; add sp, N*2; result in ax.
    // Only handles up to a few args; recursion via nested pushes handled by caller.
    for (int i = (int)call->args.size() - 1; i >= 0; i--) {
        int r = emitReal16Expr(call->args[i].get());
        (void)r;
        emit8(0x50);            // push ax
    }
    emit8(0xE8); emit16(0);
    real16CallFixups.push_back({code.size() - 2, call->name});
    if (!call->args.empty()) {
        int nbytes = (int)call->args.size() * 2;
        if (nbytes <= 127) {
            emit8(0x83); emit8(0xC4); emit8((uint8_t)nbytes);  // add sp, imm8
        } else {
            emit8(0x81); emit8(0xC4); emit16((uint16_t)nbytes);  // add sp, imm16
        }
    }
    return 0;
}

void Codegen::emitReal16Stmt(Stmt* stmt) {
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        if (ret->value) {
            int r = emitReal16Expr(ret->value.get());
            (void)r;  // result already in ax
        }
        emitReal16Jmp(funcEndLabel);
        return;
    }
    if (auto asmStmt = dynamic_cast<AsmStmt*>(stmt)) {
        for (auto& instr : asmStmt->instrs) emitAsm16Instr(instr);
        return;
    }
    if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        if (varDecl->init) {
            int r = emitReal16Expr(varDecl->init.get());
            (void)r;
            auto vi = getVarInfo(varDecl->name);
            if (vi) { emit8(0x89); emit8(0x46); emit8((uint8_t)(int8_t)vi->offset); }  // mov [bp+off],ax
        }
        return;
    }
    if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        if (!assign->indexExpr && assign->memberPath.empty()) {
            int r = emitReal16Expr(assign->value.get());
            (void)r;
            auto vi = getVarInfo(assign->name);
            if (vi) { emit8(0x89); emit8(0x46); emit8((uint8_t)(int8_t)vi->offset); }
            else {
                for (auto& g : prog.globals) {
                    if (g->name == assign->name) {
                        emit8(0xA3); emit16(0);  // mov [imm16], ax (patched in writeReal16Image)
                        real16GlobalFixups.push_back({(int)code.size() - 2, assign->name});
                        return;
                    }
                }
                fprintf(stderr, "Error: undefined variable '%s'\n", assign->name.c_str()); exit(1);
            }
        } else {
            fprintf(stderr, "Warning: asm16: array/member assignment skipped\n");
        }
        return;
    }
    if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        int r = emitReal16Expr(exprStmt->expr.get());
        (void)r;
        return;
    }
    if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        int elseLabel = newLabel();
        int endLabel = newLabel();
        int c = emitReal16Expr(ifStmt->condition.get());
        (void)c;
        emit8(0x3D); emit16(0);       // cmp ax, 0
        // invert: if (ax==0) jump else
        emit8(0x0F); emit8(0x84); emit16(0);
        real16JmpFixups.push_back({code.size() - 2, elseLabel});
        for (auto& s : ifStmt->thenBlock.stmts) emitReal16Stmt(s.get());
        emitReal16Jmp(endLabel);
        emitLabel(elseLabel);
        for (auto& s : ifStmt->elseBlock.stmts) emitReal16Stmt(s.get());
        emitLabel(endLabel);
        return;
    }
    if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        int top = newLabel();
        int end = newLabel();
        emitLabel(top);
        int c = emitReal16Expr(whileStmt->condition.get());
        (void)c;
        emit8(0x3D); emit16(0);       // cmp ax, 0
        emit8(0x0F); emit8(0x84); emit16(0);
        real16JmpFixups.push_back({code.size() - 2, end});
        real16LoopStack.push_back({top, end});
        for (auto& s : whileStmt->body.stmts) emitReal16Stmt(s.get());
        real16LoopStack.pop_back();
        emitReal16Jmp(top);
        emitLabel(end);
        return;
    }
    if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        int top = newLabel();
        int end = newLabel();
        emitLabel(top);
        real16LoopStack.push_back({top, end});
        for (auto& s : loopStmt->body.stmts) emitReal16Stmt(s.get());
        real16LoopStack.pop_back();
        emitReal16Jmp(top);
        emitLabel(end);
        return;
    }
    if (auto breakStmt = dynamic_cast<BreakStmt*>(stmt)) {
        (void)breakStmt;
        if (!real16LoopStack.empty()) emitReal16Jmp(real16LoopStack.back().second);
        else emitReal16Jmp(funcEndLabel);
        return;
    }
    if (auto contStmt = dynamic_cast<ContinueStmt*>(stmt)) {
        (void)contStmt;
        if (!real16LoopStack.empty()) emitReal16Jmp(real16LoopStack.back().first);
        else emitReal16Jmp(funcEndLabel);
        return;
    }
    throw std::runtime_error("asm16: unsupported statement");
}

// ============== Real16 Flat Image Builder ==============
// Layout (loaded at 0x7C00 by the BIOS / far-jumped by the UEFI trampoline):
//   [code]  [user globals]  [strings]  [heap-free head]  [rand seed]  ["Zenith"]
// RIP-relative fixups are not used in 16-bit mode; instead everything is
// referenced with absolute 16-bit addresses. Call/jmp sites are PC-relative
// and base-independent; absolute references to globals are computed from the
// flat load origin ORG 0x7C00 with DS = 0 (physical 0:0x7C00+offset), so the
// image works both as a real boot block and as a raw flat segment load.
void Codegen::writeReal16Image(const std::string& path) {
    // Build the string pool into a flat blob placed right after the code.
    stringOffsets.clear();
    vector<uint8_t> flatStrings;
    for (auto& s : stringPool) {
        stringOffsets.push_back((uint32_t)flatStrings.size());
        for (char ch : s) flatStrings.push_back((uint8_t)ch);
        flatStrings.push_back(0);
    }

    // User globals: one word each, referenced by absolute ORG 0x7C00 address.
    vector<uint8_t> flatGlobals;
    int globalDataBase = 0x7C00 + (int)(code.size() + flatStrings.size());
    for (auto& g : prog.globals) {
        globalOffsets[g->name] = globalDataBase + (int)flatGlobals.size();
        flatGlobals.push_back(0); flatGlobals.push_back(0);
    }

    // Resolve global-variable fixups (mov ax,[abs] / mov [abs],ax).
    for (auto& gf : real16GlobalFixups) {
        auto it = globalOffsets.find(gf.second);
        if (it == globalOffsets.end()) continue;
        uint16_t addr = (uint16_t)(it->second & 0xFFFF);
        code[gf.first]     = (uint8_t)(addr & 0xFF);
        code[gf.first + 1] = (uint8_t)(addr >> 8);
    }

    // Resolve calls: rel16 = target - (pos+2).
    for (auto& cf : real16CallFixups) {
        auto it = funcOffsets.find(cf.target);
        if (it == funcOffsets.end()) continue;
        int64_t rel = (int64_t)it->second - (int64_t)(cf.codePos + 2);
        code[cf.codePos]     = (uint8_t)(rel & 0xFF);
        code[cf.codePos + 1] = (uint8_t)((rel >> 8) & 0xFF);
    }

    // Emit a global-variable initialization prologue: store 0 into each global
    // only if the program has globals (simple version: skip, data is zero-filled).

    // Write the flat image + trailer.
    std::ofstream f(safeNarrowToPath(path), ios::binary);
    if (!f) { cerr << "Error: cannot open '" << path << "' for writing" << endl; exit(1); }
    f.write((const char*)code.data(), code.size());
    f.write((const char*)flatStrings.data(), flatStrings.size());
    f.write((const char*)flatGlobals.data(), flatGlobals.size());
    uint32_t entryOfs = (uint32_t)entryPointCodeOffset;
    f.write((const char*)&entryOfs, 4);
    f.write((const char*)kZenithMagic, 6);
    f.close();
    cout << "Compiled real16: " << path << " (" << code.size() << " B code, "
         << (code.size() + flatStrings.size() + flatGlobals.size() + 10) << " B total, entry +0x"
         << hex << entryOfs << dec << ")\n";
}
