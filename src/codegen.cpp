#include "codegen.h"
#include <cctype>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <filesystem>

// GP register pool allocatable by allocReg(). Registers:
//   0=rax, 1=rcx, 2=rdx, 3=rbx, 4=rsp, 5=rbp, 6=rsi, 7=rdi (x86 encoding).
// rsp(4)/rbp(5) are excluded; rsi/rdi are volatile on Win64 so the frame
// does not need to save/restore them. The call ABI uses rcx/rdx/r8/r9
// exclusively, so rsi/rdi never collide with argument passing.
static const int kAllocPool[] = { 0, 1, 2, 3, 6, 7 };
static const int kNumAllocRegs = (int)(sizeof(kAllocPool) / sizeof(kAllocPool[0]));

// Forward-declare Windows API to avoid windows.h conflicts with custom PE structs
#ifdef _WIN32
#ifndef CP_ACP
#define CP_ACP 0
#endif
extern "C" {
    __declspec(dllimport) int __stdcall MultiByteToWideChar(unsigned int cp, unsigned long flags, const char* str, int len, wchar_t* wstr, int wlen);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned int cp, unsigned long flags, const wchar_t* wstr, int wlen, char* str, int len, const char* def, int* used);
    __declspec(dllimport) int __stdcall GetModuleFileNameW(void* hMod, wchar_t* path, unsigned long size);
    __declspec(dllimport) void* __stdcall GetModuleHandleW(const wchar_t* name);
    __declspec(dllimport) unsigned int __stdcall GetSystemDirectoryW(wchar_t* path, unsigned int size);
}

static std::filesystem::path safeNarrowToPath(const std::string& s) {
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
}
#else
static std::filesystem::path safeNarrowToPath(const std::string& s) {
    return std::filesystem::path(s);
}
#endif

// Convert a wide output path to a narrow UTF-8/ACP string for the OS file APIs.
static std::string wideToNarrow(const std::wstring& ws) {
#ifdef _WIN32
    if (ws.empty()) return "";
    int n = WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, NULL, 0, NULL, NULL);
    if (n <= 0) return "";
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, &s[0], n, NULL, NULL);
    s.resize(static_cast<size_t>(n - 1));
    return s;
#else
    std::string out;
    for (wchar_t c : ws) {
        if (c <= 0x7F) out += (char)c;
        else out += '?';
    }
    return out;
#endif
}

// =========================================================================
// Inline-asm width validation (per target). Every backend (x86, real16,
// AArch64, Thumb-2) resolves plain 'asm {}' (wordSize == 0) to the target's
// natural register width. Explicit asm16/asm32 make sense only where a
// compatible encoding exists; out-of-range widths are a compile error here.
// =========================================================================
static void validateAsmWidths(Program& prog) {
    std::string target;
    std::string allowed;
    bool real16 = prog.real16;
    if (real16) {
        target = "real-mode 16-bit boot image (asm_word_size: 16)";
        allowed = "only 'asm16' or plain 'asm' (native 16-bit)";
    } else {
        switch (prog.appType) {
            case AppType::ARM64:
                target = "app arm64 (AArch64)";
                allowed = "'asm'/'asm32' (native 32/64-bit), but not 'asm16'";
                break;
            case AppType::STM32:
                target = "app stm32 (Thumb-2)";
                allowed = "'asm'/'asm32' (native 32-bit), but not 'asm16'";
                break;
            case AppType::WASM:
                target = "app wasm";
                allowed = "none";
                break;
            default:
                target = (prog.arch == Arch::X86_32) ? "x86-32 target"
                                                     : "x86-64 target";
                allowed = (prog.arch == Arch::X86_32)
                              ? "'asm'/'asm32' (native 32-bit), but not 'asm16'"
                              : "'asm' (native 64-bit) and 'asm32', but not 'asm16'";
        }
    }
    auto reject = [&](const AsmStmt& as) {
        std::string which;
        switch (as.wordSize) {
            case 16: which = "asm16"; break;
            case 32: which = "asm32"; break;
            default: which = "asm"; break;
        }
        throw std::runtime_error(which + " blocks are not supported for " + target +
                                 ": use " + allowed);
    };
    std::function<void(const Block&)> walk = [&](const Block& b) {
        for (auto& stmt : b.stmts) {
            if (auto as = dynamic_cast<AsmStmt*>(stmt.get())) {
                int32_t ws = as->wordSize;
                bool ok;
                if (real16) ok = (ws == 0 || ws == 16);
                else if (prog.appType == AppType::ARM64) ok = (ws == 0 || ws == 32 || ws == 64);
                else if (prog.appType == AppType::STM32) ok = (ws == 0 || ws == 32);
                else ok = (ws == 0 || ws == 32 || ws == 64);
                if (!ok) reject(*as);
            } else if (auto i = dynamic_cast<IfStmt*>(stmt.get())) {
                walk(i->thenBlock);
                walk(i->elseBlock);
            } else if (auto w = dynamic_cast<WhileStmt*>(stmt.get())) {
                walk(w->body);
            } else if (auto l = dynamic_cast<LoopStmt*>(stmt.get())) {
                walk(l->body);
            } else if (auto f = dynamic_cast<ForStmt*>(stmt.get())) {
                walk(f->body);
            } else if (auto s = dynamic_cast<SwitchStmt*>(stmt.get())) {
                for (auto& c : s->cases) walk(c.body);
            }
        }
    };
    for (auto& fn : prog.functions) walk(fn->body);
}

void Codegen::setCompilerDir(const std::string& dir) {
    compilerDir = safeNarrowToPath(dir);
}

Codegen::Codegen(Program& prog) : prog(prog) {
    wordSize = (prog.arch == Arch::X86_32) ? 32 : 64;
}

void Codegen::emit8(uint8_t b) { code.push_back(b); }

void Codegen::emit16(uint16_t v) {
    code.push_back(v & 0xFF);
    code.push_back((v >> 8) & 0xFF);
}

void Codegen::emit32(uint32_t v) {
    code.push_back(v & 0xFF);
    code.push_back((v >> 8) & 0xFF);
    code.push_back((v >> 16) & 0xFF);
    code.push_back((v >> 24) & 0xFF);
}

void Codegen::emit64(uint64_t v) {
    emit32((uint32_t)(v & 0xFFFFFFFF));
    emit32((uint32_t)((v >> 32) & 0xFFFFFFFF));
}

int Codegen::allocReg() {
    for (int i = 0; i < kNumAllocRegs; i++) {
        int r = kAllocPool[i];
        if (!(regsUsed & (1 << r))) {
            regsUsed |= (1 << r);
            return r;
        }
    }
    // No registers available — fail loudly instead of returning -1 which
    // leads to silent corrupt code generation (emitMovReg(-1,0) = garbage).
    throw std::runtime_error("register allocation failed: expression too deep (all 6 GP registers in use)");
}

void Codegen::freeReg(int r) {
    if (r >= 0) regsUsed &= ~(1 << r);
}

int Codegen::allocXmmReg() {
    for (int i = 0; i < 8; i++) {
        if (!(xmmRegsUsed & (1 << i))) {
            xmmRegsUsed |= (1 << i);
            return i;
        }
    }
    throw std::runtime_error("XMM register allocation failed: too many concurrent float expressions");
}

void Codegen::freeXmmReg(int r) {
    if (r >= 0) xmmRegsUsed &= ~(1 << r);
}

void Codegen::emitMovReg(int dst, int src) {
    if (dst == src) return;
    if (wordSize == 32) {
        // 32-bit mode: use 32-bit registers (eax, ecx, edx, ebx) without REX
        emit8(0x8B); emit8((uint8_t)(0xC0 + dst * 8 + src));  // mov dst, src
    } else {
        // 64-bit mode: use 64-bit registers with REX.W
        emit8(0x48); emit8(0x8B); emit8((uint8_t)(0xC0 + dst * 8 + src));  // mov dst, src
    }
}

void Codegen::emitMovRegImm(int r, int64_t val) {
    if (wordSize == 32) {
        // 32-bit mode: only 32-bit immediates
        uint32_t v = (uint32_t)val;
        if (r == 0) { emit8(0xB8); emit32(v); }
        else if (r == 1) { emit8(0xB9); emit32(v); }
        else if (r == 2) { emit8(0xBA); emit32(v); }
        else if (r == 3) { emit8(0xBB); emit32(v); }
        else if (r == 4) { emit8(0xBC); emit32(v); }
        else if (r == 5) { emit8(0xBD); emit32(v); }
        else if (r == 6) { emit8(0xBE); emit32(v); }
        else if (r == 7) { emit8(0xBF); emit32(v); }
    } else {
        // 64-bit mode: zero-extended imm32 or full 64-bit movabs
        if (val >= 0 && val <= 0x7FFFFFFF) {
            if (r == 0) { emit8(0xB8); emit32((uint32_t)val); }
            else if (r == 1) { emit8(0xB9); emit32((uint32_t)val); }
            else if (r == 2) { emit8(0xBA); emit32((uint32_t)val); }
            else if (r == 3) { emit8(0xBB); emit32((uint32_t)val); }
            else if (r == 4) { emit8(0xBC); emit32((uint32_t)val); }
            else if (r == 5) { emit8(0xBD); emit32((uint32_t)val); }
            else if (r == 6) { emit8(0xBE); emit32((uint32_t)val); }
            else if (r == 7) { emit8(0xBF); emit32((uint32_t)val); }
        } else {
            uint8_t rex = 0x48 | (r >> 3);
            emit8(rex); emit8(0xB8 + (r & 7));
            emit32((uint32_t)(val & 0xFFFFFFFF));
            emit32((uint32_t)((val >> 32) & 0xFFFFFFFF));
        }
    }
}

void Codegen::emitLoadRegFromBP(int r, int offset) {
    // mod=01 (disp8) or mod=10 (disp32) with rm=rbp(5): 0x45|(r<<3) / 0x85|(r<<3)
    if (offset >= -128 && offset <= 127) {
        emit8(0x8B); emit8((uint8_t)(0x45 | (r << 3))); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x8B); emit8((uint8_t)(0x85 | (r << 3))); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreToBP(int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x89); emit8(0x85); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreRegToBP(int r, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x89); emit8((uint8_t)(0x45 | (r << 3))); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x89); emit8((uint8_t)(0x85 | (r << 3))); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreToBP64(int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x48); emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLoadRegFromBP64(int r, int offset) {
    uint8_t rex = 0x48;
    if (offset >= -128 && offset <= 127) {
        emit8(rex); emit8(0x8B); emit8((uint8_t)(0x45 | (r << 3))); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(rex); emit8(0x8B); emit8((uint8_t)(0x85 | (r << 3))); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreRegToBP64(int r, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x48); emit8(0x89); emit8((uint8_t)(0x45 | (r << 3))); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x48); emit8(0x89); emit8((uint8_t)(0x85 | (r << 3))); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitAdd(int dst, int src) {
    if (wordSize == 32) {
        // 32-bit mode: use 32-bit registers without REX.W
        if (dst == 0 && src == 1) { emit8(0x03); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x03); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x03); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x03); emit8(0xC8); }
        else if (dst == 2 && src == 0) { emit8(0x03); emit8(0xD0); }
        else if (dst == 3 && src == 0) { emit8(0x03); emit8(0xD8); }
        else if (dst == 1 && src == 2) { emit8(0x01); emit8(0xD1); }
        else if (dst == 2 && src == 1) { emit8(0x01); emit8(0xCA); }
        else if (dst == 1 && src == 3) { emit8(0x01); emit8(0xD9); }
        else if (dst == 2 && src == 3) { emit8(0x01); emit8(0xDA); }
        else if (dst == 3 && src == 1) { emit8(0x01); emit8(0xCB); }
        else if (dst == 3 && src == 2) { emit8(0x01); emit8(0xD3); }
        else if (dst == 3 && src == 3) { emit8(0x01); emit8(0xDB); }
        else { emit8(0x01); emit8(0xC0 + dst + src * 8); }
    } else {
        // 64-bit mode: use 64-bit registers with REX.W
        if (dst == 0 && src == 1) { emit8(0x48); emit8(0x03); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x48); emit8(0x03); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x48); emit8(0x03); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x48); emit8(0x03); emit8(0xC8); }
        else if (dst == 2 && src == 0) { emit8(0x48); emit8(0x03); emit8(0xD0); }
        else if (dst == 3 && src == 0) { emit8(0x48); emit8(0x03); emit8(0xD8); }
        else if (dst == 1 && src == 2) { emit8(0x48); emit8(0x01); emit8(0xD1); }
        else if (dst == 2 && src == 1) { emit8(0x48); emit8(0x01); emit8(0xCA); }
        else if (dst == 1 && src == 3) { emit8(0x48); emit8(0x01); emit8(0xD9); }
        else if (dst == 2 && src == 3) { emit8(0x48); emit8(0x01); emit8(0xDA); }
        else if (dst == 3 && src == 1) { emit8(0x48); emit8(0x01); emit8(0xCB); }
        else if (dst == 3 && src == 2) { emit8(0x48); emit8(0x01); emit8(0xD3); }
        else if (dst == 3 && src == 3) { emit8(0x48); emit8(0x01); emit8(0xDB); }
        else { emit8(0x48); emit8(0x01); emit8(0xC0 + dst + src * 8); }
    }
}

void Codegen::emitSub(int dst, int src) {
    if (wordSize == 32) {
        // 32-bit mode
        if (dst == 0 && src == 1) { emit8(0x2B); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x2B); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x2B); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x2B); emit8(0xC8); }
        else if (dst == 1 && src == 3) { emit8(0x2B); emit8(0xCB); }
        else if (dst == 2 && src == 0) { emit8(0x2B); emit8(0xD0); }
        else if (dst == 2 && src == 3) { emit8(0x2B); emit8(0xD3); }
        else if (dst == 3 && src == 0) { emit8(0x2B); emit8(0xD8); }
        else if (dst == 3 && src == 1) { emit8(0x2B); emit8(0xD9); }
        else if (dst == 3 && src == 2) { emit8(0x2B); emit8(0xDA); }
        else if (dst == 3 && src == 3) { emit8(0x2B); emit8(0xDB); }
        else { emit8(0x2B); emit8(0xC0 + dst * 8 + src); }
    } else {
        // 64-bit mode
        if (dst == 0 && src == 1) { emit8(0x48); emit8(0x2B); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x48); emit8(0x2B); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x48); emit8(0x2B); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x48); emit8(0x2B); emit8(0xC8); }
        else if (dst == 1 && src == 3) { emit8(0x48); emit8(0x2B); emit8(0xCB); }
        else if (dst == 2 && src == 0) { emit8(0x48); emit8(0x2B); emit8(0xD0); }
        else if (dst == 2 && src == 3) { emit8(0x48); emit8(0x2B); emit8(0xD3); }
        else if (dst == 3 && src == 0) { emit8(0x48); emit8(0x2B); emit8(0xD8); }
        else if (dst == 3 && src == 1) { emit8(0x48); emit8(0x2B); emit8(0xD9); }
        else if (dst == 3 && src == 2) { emit8(0x48); emit8(0x2B); emit8(0xDA); }
        else if (dst == 3 && src == 3) { emit8(0x48); emit8(0x2B); emit8(0xDB); }
        else { emit8(0x48); emit8(0x2B); emit8(0xC0 + dst * 8 + src); }
    }
}

void Codegen::emitImul(int dst, int src) {
    if (wordSize == 32) {
        // 32-bit mode
        if (dst == 0 && src == 1) { emit8(0x0F); emit8(0xAF); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x0F); emit8(0xAF); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x0F); emit8(0xAF); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x0F); emit8(0xAF); emit8(0xC8); }
        else if (dst == 1 && src == 3) { emit8(0x0F); emit8(0xAF); emit8(0xCB); }
        else if (dst == 2 && src == 0) { emit8(0x0F); emit8(0xAF); emit8(0xD0); }
        else if (dst == 2 && src == 3) { emit8(0x0F); emit8(0xAF); emit8(0xD3); }
        else if (dst == 3 && src == 0) { emit8(0x0F); emit8(0xAF); emit8(0xD8); }
        else if (dst == 3 && src == 1) { emit8(0x0F); emit8(0xAF); emit8(0xD9); }
        else if (dst == 3 && src == 2) { emit8(0x0F); emit8(0xAF); emit8(0xDA); }
        else if (dst == 3 && src == 3) { emit8(0x0F); emit8(0xAF); emit8(0xDB); }
        else { emit8(0x0F); emit8(0xAF); emit8(0xC0 + dst * 8 + src); }
    } else {
        // 64-bit mode
        if (dst == 0 && src == 1) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); }
        else if (dst == 0 && src == 2) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC2); }
        else if (dst == 0 && src == 3) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC3); }
        else if (dst == 1 && src == 0) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC8); }
        else if (dst == 1 && src == 3) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xCB); }
        else if (dst == 2 && src == 0) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD0); }
        else if (dst == 2 && src == 3) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD3); }
        else if (dst == 3 && src == 0) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD8); }
        else if (dst == 3 && src == 1) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD9); }
        else if (dst == 3 && src == 2) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xDA); }
        else if (dst == 3 && src == 3) { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xDB); }
        else { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC0 + dst * 8 + src); }
    }
}

int Codegen::emitUnaryExpr(UnaryExpr* u) {
    if (u->op == "~") {
        int r = emitExpr(u->operand.get());
        // NOT instruction: F7 /2 (REX.W only needed for 64-bit)
        if (wordSize == 64) emit8(0x48);
        emit8(0xF7); emit8(0xD0 + r); 
        std::cout << "GEN: NOT r" << r << std::endl;
        return r;
    }
    if (u->op == "!") {
        int r = emitExpr(u->operand.get());
        // test reg, reg (sets ZF if zero) — both ModRM fields carry the register
        if (wordSize == 64) emit8(0x48);
        emit8(0x85); emit8((uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7)));
        // setz reg8 (set to 1 if zero flag)
        if (r >= 4) emit8(0x40);
        emit8(0x0F); emit8(0x94); emit8((uint8_t)(0xC0 | (r & 7)));
        // movzx r32, r8 — always needed to clear the upper bits left by SETcc.
        // In x64, movzx r32,r8 zeroes the top 32 bits too, so no REX.W here.
        if (r >= 4) emit8(0x40);
        emit8(0x0F); emit8(0xB6); emit8((uint8_t)(0xC0 | (r << 3) | (r & 7)));
        return r;
    }
    if (u->op == "-") {
        int r = emitExpr(u->operand.get());
        if (wordSize == 64) emit8(0x48);
        emit8(0xF7); emit8(0xD8 | (r & 7)); // neg reg
        return r;
    }
    return -1;
}

void Codegen::emitAnd(int dst, int src) {
    if (wordSize == 32) {
        emit8(0x23); emit8((uint8_t)(0xC0 + dst * 8 + src));
    } else {
        emit8(0x48); emit8(0x23); emit8((uint8_t)(0xC0 + dst * 8 + src));
    }
    std::cout << "GEN: AND r" << dst << ", r" << src << std::endl;
}

void Codegen::emitOr(int dst, int src) {
    if (wordSize == 32) {
        emit8(0x0B); emit8((uint8_t)(0xC0 + dst * 8 + src));
    } else {
        emit8(0x48); emit8(0x0B); emit8((uint8_t)(0xC0 + dst * 8 + src));
    }
    std::cout << "GEN: OR r" << dst << ", r" << src << std::endl;
}

void Codegen::emitXor(int dst, int src) {
    if (wordSize == 32) {
        emit8(0x33); emit8((uint8_t)(0xC0 + dst * 8 + src));
    } else {
        emit8(0x48); emit8(0x33); emit8((uint8_t)(0xC0 + dst * 8 + src));
    }
    std::cout << "GEN: XOR r" << dst << ", r" << src << std::endl;
}

// ============== SSE Float Instructions ==============

void Codegen::emitMovssXmm(int xmmDst, int xmmSrc) {
    // movss xmmDst, xmmSrc: F3 0F 10 /r (dst = dst reg, src = r/m)
    // We encode: movss xmmDst, xmmSrc (register to register)
    uint8_t modrm = 0xC0 | (xmmDst << 3) | xmmSrc;
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(modrm);
    } else {
        uint8_t rexByte = 0x40;
        if (xmmDst >= 8) rexByte |= 0x04;
        if (xmmSrc >= 8) rexByte |= 0x01;
        emit8(0xF3); emit8(rexByte); emit8(0x0F); emit8(0x10);
        emit8(0xC0 | ((xmmDst & 0x07) << 3) | (xmmSrc & 0x07));
    }
}

void Codegen::emitMovssXmmFromMem(int xmmDst, int gpReg, int offset) {
    uint8_t rex = 0x40;
    if (xmmDst >= 8) rex |= 0x04;
    uint8_t modrm;
    if (gpReg == 4) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10);
        if (offset == 0) {
            emit8(0x04 | (xmmDst << 3)); emit8(0x24);
        } else if (offset >= -128 && offset <= 127) {
            emit8(0x44 | (xmmDst << 3)); emit8(0x24); emit8((uint8_t)(int8_t)offset);
        } else {
            emit8(0x84 | (xmmDst << 3)); emit8(0x24); emit32((uint32_t)(int32_t)offset);
        }
        return;
    }
    if (gpReg == 5) {
        if (offset == 0) {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10);
            emit8(0x45 | (xmmDst << 3)); emit8(0x00);
        } else if (offset >= -128 && offset <= 127) {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10);
            emit8(0x45 | (xmmDst << 3)); emit8((uint8_t)(int8_t)offset);
        } else {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10);
            emit8(0x85 | (xmmDst << 3)); emit32((uint32_t)(int32_t)offset);
        }
        return;
    }
    uint8_t regEnc = gpReg;
    modrm = (xmmDst << 3) | regEnc;
    if (offset == 0 && gpReg != 5) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10); emit8(modrm);
    } else if (offset >= -128 && offset <= 127) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10); emit8(modrm | 0x40); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x10); emit8(modrm | 0x80); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitMovssXmmToMem(int xmmDst, int gpReg, int offset) {
    uint8_t rex = 0x40;
    if (xmmDst >= 8) rex |= 0x04;
    uint8_t modrm;
    if (gpReg == 4) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11);
        if (offset == 0) {
            emit8(0x04 | (xmmDst << 3)); emit8(0x24);
        } else if (offset >= -128 && offset <= 127) {
            emit8(0x44 | (xmmDst << 3)); emit8(0x24); emit8((uint8_t)(int8_t)offset);
        } else {
            emit8(0x84 | (xmmDst << 3)); emit8(0x24); emit32((uint32_t)(int32_t)offset);
        }
        return;
    }
    if (gpReg == 5) {
        if (offset == 0) {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11);
            emit8(0x45 | (xmmDst << 3)); emit8(0x00);
        } else if (offset >= -128 && offset <= 127) {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11);
            emit8(0x45 | (xmmDst << 3)); emit8((uint8_t)(int8_t)offset);
        } else {
            emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11);
            emit8(0x85 | (xmmDst << 3)); emit32((uint32_t)(int32_t)offset);
        }
        return;
    }
    uint8_t regEnc = gpReg;
    modrm = (xmmDst << 3) | regEnc;
    if (offset == 0 && gpReg != 5) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11); emit8(modrm);
    } else if (offset >= -128 && offset <= 127) {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11); emit8(modrm | 0x40); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); if (rex != 0x40) emit8(rex); emit8(0x0F); emit8(0x11); emit8(modrm | 0x80); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitAddss(int xmmDst, int xmmSrc) {
    // addss xmmDst, xmmSrc: F3 0F 58 /r
    uint8_t modrm = 0xC0 | (xmmDst << 3) | xmmSrc;
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x58); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x58); emit8(0xC0 | (xmmDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitSubss(int xmmDst, int xmmSrc) {
    uint8_t modrm = 0xC0 | (xmmDst << 3) | xmmSrc;
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x5C); emit8(0xC0 | (xmmDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitMulss(int xmmDst, int xmmSrc) {
    uint8_t modrm = 0xC0 | (xmmDst << 3) | xmmSrc;
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x59); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x59); emit8(0xC0 | (xmmDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitDivss(int xmmDst, int xmmSrc) {
    uint8_t modrm = 0xC0 | (xmmDst << 3) | xmmSrc;
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x5E); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x5E); emit8(0xC0 | (xmmDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitUcomiss(int xmmA, int xmmB) {
    // ucomiss xmmA, xmmB: 0F 2E /r
    uint8_t modrm = 0xC0 | (xmmA << 3) | xmmB;
    if (xmmA < 8 && xmmB < 8) {
        emit8(0x0F); emit8(0x2E); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmA >= 8) rex |= 0x04;
        if (xmmB >= 8) rex |= 0x01;
        emit8(rex); emit8(0x0F); emit8(0x2E); emit8(0xC0 | (xmmA & 0x7) << 3 | (xmmB & 0x7));
    }
}

void Codegen::emitCvtsi2ss(int xmmDst, int gpSrc) {
    // cvtsi2ss xmmDst, r64: F3 REX.W 0F 2A /r (64-bit)
    uint8_t modrm = 0xC0 | (xmmDst << 3) | gpSrc;
    if (xmmDst < 8 && gpSrc < 8) {
        emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(modrm);
    } else {
        uint8_t rex = 0x48;
        if (xmmDst >= 8) rex |= 0x04;
        if (gpSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x2A); emit8(0xC0 | (xmmDst & 0x7) << 3 | (gpSrc & 0x7));
    }
}

void Codegen::emitMovdGpFromXmm(int gpDst, int xmmSrc) {
    // movd r32, xmm: 66 0F 7E /r (copy the LOW 32 float bits to gp and
    // zero-extend). REX.W must NOT be set: with REX.W this becomes
    // movq (64-bit), which would copy garbage from the upper 32 XMM bits.
    uint8_t regField = gpDst & 0x7;
    uint8_t xmmField = xmmSrc & 0x7;
    uint8_t modrm = 0xC0 | (regField << 3) | xmmField;
    uint8_t rex = 0x40;
    if (gpDst >= 8) rex |= 0x04;  // REX.R
    if (xmmSrc >= 8) rex |= 0x01; // REX.B
    if (rex != 0x40) emit8(rex);
    emit8(0x66); emit8(0x0F); emit8(0x7E); emit8(modrm);
}

void Codegen::emitCvtss2si(int gpDst, int xmmSrc) {
    // cvtss2si r64, xmmSrc: F3 REX.W 0F 2D /r (64-bit)
    uint8_t modrm = 0xC0 | (gpDst << 3) | xmmSrc;
    if (gpDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2D); emit8(modrm);
    } else {
        uint8_t rex = 0x48;
        if (gpDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x2D); emit8(0xC0 | (gpDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitCvttss2si(int gpDst, int xmmSrc) {
    // cvttss2si r64, xmmSrc: F3 REX.W 0F 2C /r (truncate toward zero)
    uint8_t modrm = 0xC0 | (gpDst << 3) | xmmSrc;
    if (gpDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(modrm);
    } else {
        uint8_t rex = 0x48;
        if (gpDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x2C); emit8(0xC0 | (gpDst & 0x7) << 3 | (xmmSrc & 0x7));
    }
}

void Codegen::emitMovdXmmFromGp(int xmmDst, int gpSrc) {
    // movd xmm, r32: 66 0F 6E /r (raw bits gp -> xmm)
    uint8_t modrm = 0xC0 | (xmmDst << 3) | gpSrc;
    if (xmmDst < 8 && gpSrc < 8) {
        emit8(0x66); emit8(0x0F); emit8(0x6E); emit8(modrm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (gpSrc >= 8) rex |= 0x01;
        emit8(0x66); emit8(rex); emit8(0x0F); emit8(0x6E);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (gpSrc & 0x7));
    }
}

void Codegen::emitSqrtss(int xmmDst, int xmmSrc) {
    // sqrtss xmmDst, xmmSrc: F3 0F 51 /r
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x51);
        emit8(0xC0 | (xmmDst << 3) | xmmSrc);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x51);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
    }
}

void Codegen::emitAndps(int xmmDst, int xmmSrc) {
    // andps xmmDst, xmmSrc: 0F 54 /r
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0x0F); emit8(0x54); emit8(0xC0 | (xmmDst << 3) | xmmSrc);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(rex); emit8(0x0F); emit8(0x54);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
    }
}

void Codegen::emitMinss(int xmmDst, int xmmSrc) {
    // minss xmmDst, xmmSrc: F3 0F 5D /r
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x5D); emit8(0xC0 | (xmmDst << 3) | xmmSrc);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x5D);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
    }
}

void Codegen::emitMaxss(int xmmDst, int xmmSrc) {
    // maxss xmmDst, xmmSrc: F3 0F 5F /r
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0xF3); emit8(0x0F); emit8(0x5F); emit8(0xC0 | (xmmDst << 3) | xmmSrc);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0xF3); emit8(rex); emit8(0x0F); emit8(0x5F);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
    }
}

void Codegen::emitXorps(int xmmDst, int xmmSrc) {
    // xorps xmmDst, xmmSrc: 0F 57 /r (used to flip the sign bit)
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0x0F); emit8(0x57); emit8(0xC0 | (xmmDst << 3) | xmmSrc);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(rex); emit8(0x0F); emit8(0x57);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
    }
}

void Codegen::emitRoundss(int xmmDst, int xmmSrc, uint8_t imm) {
    // roundss xmmDst, xmmSrc, imm8: 66 0F 3A 0A /r ib
    // imm bit0: 1 = round (floor if imm==1), 2 = ceil, 3 = trunc, 0 = nearest
    if (xmmDst < 8 && xmmSrc < 8) {
        emit8(0x66); emit8(0x0F); emit8(0x3A); emit8(0x0A);
        emit8(0xC0 | (xmmDst << 3) | xmmSrc);
        emit8(imm);
    } else {
        uint8_t rex = 0x40;
        if (xmmDst >= 8) rex |= 0x04;
        if (xmmSrc >= 8) rex |= 0x01;
        emit8(0x66); emit8(rex); emit8(0x0F); emit8(0x3A); emit8(0x0A);
        emit8(0xC0 | ((xmmDst & 0x7) << 3) | (xmmSrc & 0x7));
        emit8(imm);
    }
}

static bool exprContainsCall(Expr* e);

int Codegen::emitFloatMathCall(CallExpr* call) {
    // Entirely float math intrinsics. Returns an XMM register index holding the
    // float result, or -1 if `call` is not a recognized math builtin.
    // All constraints here are pure float; the caller is responsible for
    // routing only float-typed uses here.
    const std::string& name = call->name;

    // ---- unary helpers (sqrt/abs/floor/ceil on one XMM in place) ----
    auto unaryInPlace = [&](const char* op) -> int {
        static const char* kUnary[] = {"sqrt", "abs", "floor", "ceil", "trunc", "neg"};
        bool known = false;
        for (auto k : kUnary) if (strcmp(k, op) == 0) { known = true; break; }
        if (!known) return -1;
        if (call->args.size() != 1) return -1;
        int a = emitFloatExpr(call->args[0].get());
        if (a < 0) a = 0;
        std::string o = op;
        if (o == "sqrt")      emitSqrtss(a, a);
        else if (o == "floor") emitRoundss(a, a, 1);
        else if (o == "ceil")  emitRoundss(a, a, 2);
        else if (o == "trunc") emitRoundss(a, a, 3);
        else if (o == "neg") {
            int m = allocXmmReg(); if (m < 0) m = 0;
            emitMovssXmmImm(m, -0.0f);
            emitXorps(a, m);
            freeXmmReg(m);
        }
        else if (o == "abs") {
            // clear the sign bit: value & 0x7FFFFFFF
            int saved = regsUsed;
            regsUsed = 0;
            int m = allocReg();
            emitMovRegImm(m, 0x7FFFFFFF);
            int mm = allocXmmReg(); if (mm < 0) mm = 0;
            emitMovdXmmFromGp(mm, m);
            freeReg(m);
            regsUsed = (uint8_t)saved;
            emitAndps(a, mm);
            freeXmmReg(mm);
        }
        return a;
    };
    int r = unaryInPlace(name.c_str());
    if (r >= 0) return r;

    // itof(n): int -> float. The argument is integer-typed, so it must go
    // through the general emitExpr (int path), not the float path.
    if (name == "itof" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int g = emitExpr(call->args[0].get());
        if (g < 0) g = 0;
        int f = allocXmmReg();
        if (f < 0) f = 0;
        emitCvtsi2ss(f, g);
        freeReg(g);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        return f;
    }

    // ---- binary helpers (sin/cos/tan use x87 for accuracy) ----
    if (name == "sin" || name == "cos" || name == "tan") {
        if (call->args.size() != 1) return -1;
        int a = emitFloatExpr(call->args[0].get());
        if (a < 0) a = 0;
        // push arg to scratch, operate on x87, pull result back
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x10);          // sub rsp, 16
        emitMovssXmmToMem(a, 4, 0);                                   // [rsp] = a
        emit8(0xD9); emit8(0x04); emit8(0x24);                        // fld dword [rsp]
        if (name == "sin")      { emit8(0xD9); emit8(0xFE); }         // fsin
        else if (name == "cos") { emit8(0xD9); emit8(0xFF); }         // fcos
        else {
            emit8(0xD9); emit8(0xF2);                                  // fptan
            emit8(0xDD); emit8(0xD8);                                  // fstp st0 (discard 1.0)
        }
        emit8(0xD9); emit8(0x1C); emit8(0x24);                        // fstp dword [rsp]
        emitMovssXmmFromMem(a, 4, 0);                                 // a = result
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x10);           // add rsp, 16
        return a;
    }
    if (name == "atan2") {
        if (call->args.size() != 2) return -1;
        int ay;
        bool aySpilled = false;
        if (exprContainsCall(call->args[1].get())) {
            ay = emitFloatExpr(call->args[0].get());  // y
            if (ay < 0) ay = 0;
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);
            emitMovssXmmToMem(ay, 4, 0);
            freeXmmReg(ay);
            aySpilled = true;
        } else {
            ay = emitFloatExpr(call->args[0].get());  // y
        }
        int ax = emitFloatExpr(call->args[1].get());  // x
        if (aySpilled) {
            int ly = allocXmmReg(); if (ly < 0) ly = 0;
            emitMovssXmmFromMem(ly, 4, 0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);
            ay = ly;
        }
        if (ay < 0) ay = 0; if (ax < 0) ax = 0;
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x10);
        emitMovssXmmToMem(ay, 4, 0); emit8(0xD9); emit8(0x04); emit8(0x24);  // fld y
        emitMovssXmmToMem(ax, 4, 0); emit8(0xD9); emit8(0x04); emit8(0x24);  // fld x -> st0=x, st1=y
        emit8(0xD9); emit8(0xF3);                                           // fpatan -> atan(y/x)
        emit8(0xD9); emit8(0x1C); emit8(0x24);                              // fstp dword [rsp]
        int res = allocXmmReg(); if (res < 0) res = 0;
        emitMovssXmmFromMem(res, 4, 0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x10);
        freeXmmReg(ay); freeXmmReg(ax);
        return res;
    }
    if (name == "min" || name == "max") {
        if (call->args.size() != 2) return -1;
        int a;
        bool aSpilled = false;
        if (exprContainsCall(call->args[1].get())) {
            a = emitFloatExpr(call->args[0].get());
            if (a < 0) a = 0;
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);
            emitMovssXmmToMem(a, 4, 0);
            freeXmmReg(a);
            aSpilled = true;
        } else {
            a = emitFloatExpr(call->args[0].get());
        }
        int b = emitFloatExpr(call->args[1].get());
        if (aSpilled) {
            int lx = allocXmmReg(); if (lx < 0) lx = 0;
            emitMovssXmmFromMem(lx, 4, 0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);
            a = lx;
        }
        if (a < 0) a = 0; if (b < 0) b = 0;
        if (name == "min") emitMinss(a, b); else emitMaxss(a, b);
        freeXmmReg(b);
        return a;
    }
    if (name == "fmod") {
        if (call->args.size() != 2) return -1;
        int a;
        bool aSpilled = false;
        if (exprContainsCall(call->args[1].get())) {
            a = emitFloatExpr(call->args[0].get());
            if (a < 0) a = 0;
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);
            emitMovssXmmToMem(a, 4, 0);
            freeXmmReg(a);
            aSpilled = true;
        } else {
            a = emitFloatExpr(call->args[0].get());
        }
        int b = emitFloatExpr(call->args[1].get());
        if (aSpilled) {
            int lx = allocXmmReg(); if (lx < 0) lx = 0;
            emitMovssXmmFromMem(lx, 4, 0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);
            a = lx;
        }
        if (a < 0) a = 0; if (b < 0) b = 0;
        // t = trunc(a/b); result = a - t*b
        int t = allocXmmReg();
        if (t < 0) t = a;
        emitMovssXmm(t, a);
        emitDivss(t, b);       // t = a/b
        emitRoundss(t, t, 3);  // t = trunc(a/b)
        emitMulss(t, b);       // t = trunc(a/b)*b
        emitSubss(a, t);       // a = a - t
        if (t != a) freeXmmReg(t);
        freeXmmReg(b);
        return a;
    }
    if (name == "pow") {
        // x^y = exp2(y*log2(x)) via x87: fyl2x + f2xm1 + fscale
        if (call->args.size() != 2) return -1;
        int ax;
        bool axSpilled = false;
        if (exprContainsCall(call->args[1].get())) {
            ax = emitFloatExpr(call->args[0].get());  // base x
            if (ax < 0) ax = 0;
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);
            emitMovssXmmToMem(ax, 4, 0);
            freeXmmReg(ax);
            axSpilled = true;
        } else {
            ax = emitFloatExpr(call->args[0].get());  // base x
        }
        int ay = emitFloatExpr(call->args[1].get());  // exponent y
        if (axSpilled) {
            int lx = allocXmmReg(); if (lx < 0) lx = 0;
            emitMovssXmmFromMem(lx, 4, 0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);
            ax = lx;
        }
        if (ax < 0) ax = 0; if (ay < 0) ay = 0;
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x10);
        // st0 = y, st1 = x
        emitMovssXmmToMem(ay, 4, 0); emit8(0xD9); emit8(0x04); emit8(0x24);  // fld y
        emitMovssXmmToMem(ax, 4, 0); emit8(0xD9); emit8(0x04); emit8(0x24);  // fld x -> st0=x, st1=y
        emit8(0xD9); emit8(0xF1);                                           // fyl2x -> st0 = y*log2(x) = t
        // st0 = t; want 2^t = 2^frac * 2^n
        emit8(0xD9); emit8(0xC0);                                           // fld st0 (dup t)
        emit8(0xD9); emit8(0xFC);                                           // frndint -> st0 = n, st1 = t
        emit8(0xDC); emit8(0xE9);                                           // fsub st1,st0 -> st1 = t-n = frac
        emit8(0xD9); emit8(0xC9);                                           // fxch -> st0 = frac, st1 = n
        emit8(0xD9); emit8(0xF0);                                           // f2xm1 -> st0 = 2^frac - 1
        emit8(0xD9); emit8(0xE8);                                           // fld1
        emit8(0xDE); emit8(0xC1);                                           // faddp st1, st0 -> st0 = 2^frac
        emit8(0xD9); emit8(0xFD);                                           // fscale -> st0 = 2^frac * 2^n = 2^t
        emit8(0xDD); emit8(0xD9);                                           // fstp st1 (pop n) -> st0 = 2^t
        emit8(0xD9); emit8(0x1C); emit8(0x24);                              // fstp dword [rsp]
        int res = allocXmmReg(); if (res < 0) res = 0;
        emitMovssXmmFromMem(res, 4, 0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x10);                 // add rsp, 16
        freeXmmReg(ax); freeXmmReg(ay);
        return res;
    }
    return -1;
}

void Codegen::emitMovssXmmImm(int xmmDst, float val) {
    // Load float immediate into XMM via memory
    // We'll push the constant into .rdata and use movss from there
    // For simplicity, use cvtsi2ss if val is a whole number, or push constant to stack
    // Better: put float constant in .rdata and reference via RIP-relative
    // But for code simplicity, convert int to float for now
    int intVal = (int)val;
    if ((float)intVal == val && intVal >= 0) {
        // Load integer into eax, then convert to float
        // (positive only: negative values would be zero-extended by
        //  emitMovRegImm and then misread by the 64-bit cvtsi2ss)
        int saved = regsUsed;
        regsUsed = 0;
        int r = allocReg();
        emitMovRegImm(r, (uint32_t)intVal);
        emitCvtsi2ss(xmmDst, r);
        freeReg(r);
        regsUsed = (uint8_t)saved;
    } else {
        // Push constant value to stack, then movss from stack
        int32_t intBits;
        memcpy(&intBits, &val, sizeof(int32_t));
        // sub rsp, 4
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x04);
        // mov dword [rsp], intBits
        emit8(0xC7); emit8(0x04); emit8(0x24); emit32((uint32_t)intBits);
        // movss xmmDst, [rsp]
        emitMovssXmmFromMem(xmmDst, 4, 0);
        // add rsp, 4
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x04);
    }
}

// ============== Labels ==============

int Codegen::newLabel() { return nextLabel++; }

void Codegen::emitLabel(int label) {
    size_t pos = code.size();
    if (pos >= labelPositions.size()) labelPositions.resize(pos + 1, -1);
    if ((size_t)label >= labelPositions.size()) labelPositions.resize(label + 1, -1);
    labelPositions[label] = (int)pos;
}

void Codegen::emitJmp(int label) {
    emit8(0xE9);
    jmpFixups.push_back({code.size(), label});
    emit32(0);
}

void Codegen::emitJcc(const std::string& cond, int label) {
    uint8_t jccOp;
    if (cond == "==") jccOp = 0x84;
    else if (cond == "!=") jccOp = 0x85;
    else if (cond == "<")  jccOp = 0x8C;
    else if (cond == ">")  jccOp = 0x8F;
    else if (cond == "<=") jccOp = 0x8E;
    else if (cond == ">=") jccOp = 0x8D;
    else jccOp = 0x84;

    emit8(0x0F); emit8(jccOp);
    jmpFixups.push_back({code.size(), label});
    emit32(0);
}

VarInfo* Codegen::getVarInfo(const std::string& name) {
    auto it = varInfos.find(name);
    if (it != varInfos.end()) return &it->second;
    return nullptr;
}

bool Codegen::isFloatExpr(Expr* expr) {
    if (dynamic_cast<FloatExpr*>(expr)) return true;
    if (dynamic_cast<NumberExpr*>(expr)) return false;
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        auto vi = getVarInfo(id->name);
        return vi && vi->type.kind == TypeKind::Float;
    }
    if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        std::vector<std::string> path;
        Expr* cur = memb;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) {
            path.insert(path.begin(), mm->member);
            cur = mm->object.get();
        }
        if (auto objId = dynamic_cast<IdentExpr*>(cur)) {
            auto vi = getVarInfo(objId->name);
            if (vi && vi->type.kind == TypeKind::Struct) {
                std::string curStruct = vi->type.structName;
                bool ok = true;
                Type fieldType;
                for (size_t i = 0; ok && i < path.size(); i++) {
                    auto slIt = structLayouts.find(curStruct);
                    if (slIt == structLayouts.end()) { ok = false; break; }
                    auto& layout = slIt->second;
                    auto fTypeIt = layout.fieldTypes.find(path[i]);
                    if (fTypeIt == layout.fieldTypes.end()) { ok = false; break; }
                    fieldType = fTypeIt->second;
                    curStruct = fieldType.structName;
                }
                return ok && fieldType.kind == TypeKind::Float;
            }
        }
        return false;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        // Comparisons yield a bool (int), never a float, even when the operands
        // are floats. Otherwise float callers (print, VarDecl init, ...) would
        // treat the GPR comparison result as an XMM register index.
        if (bin->op == "==" || bin->op == "!=" || bin->op == "<" ||
            bin->op == ">"  || bin->op == "<=" || bin->op == ">=") return false;
        return isFloatExpr(bin->left.get()) || isFloatExpr(bin->right.get());
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        if (auto objId = dynamic_cast<IdentExpr*>(arr->array.get())) {
            auto vi = getVarInfo(objId->name);
            return vi && vi->type.kind == TypeKind::Float;
        }
        return false;
    }
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        // A call to a float math intrinsic.
        static const char* kMathFloat[] = {"sqrt","abs","floor","ceil","trunc","neg",
                                           "sin","cos","tan","atan2","min","max","fmod","pow",
                                           "itof"};
        for (auto k : kMathFloat) if (call->name == k) return true;
        // A call to a user function that returns float.
        if (getenv("ZT_CALLDEBUG")) {
            for (auto& fn : prog.functions) {
                if (fn->name == call->name) {
                    fprintf(stderr, "  isFloatExpr(call %s) retKind=%d\n", call->name.c_str(), (int)fn->returnType.kind);
                    return fn->returnType.kind == TypeKind::Float;
                }
            }
            fprintf(stderr, "  isFloatExpr(call %s) not found\n", call->name.c_str());
        }
        for (auto& fn : prog.functions) {
            if (fn->name == call->name) return fn->returnType.kind == TypeKind::Float;
        }
        return false;
    }
    return false;
}

// ===== Large struct (>8 bytes) value handling =====
// Layout size of a type in bytes (pointer = 8). Returns 0 for non-aggregates.
int Codegen::structTypeSize(const Type& t) {
    if (t.isPtr) return 8;
    switch (t.kind) {
        case TypeKind::Vec2:  return 8;
        case TypeKind::Vec3:  return 12;
        case TypeKind::Color: return 16;
        case TypeKind::Struct: {
            if (t.structName.empty()) return 0;
            auto it = structLayouts.find(t.structName);
            if (it != structLayouts.end()) return it->second.totalSize;
            return 0;
        }
        default: return 0;
    }
}

// Returns ceil(totalSize/8) (>=2) when `e` is a non-pointer struct-typed value
// bigger than 8 bytes; 0 otherwise. Recognizes IdentExpr, CallExpr (user
// function return) and MemberExpr (final field type, unfolded through the
// struct layouts).
int Codegen::structValueQwords(Expr* e) {
    if (!e) return 0;
    Type t;
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto vi = getVarInfo(id->name);
        if (!vi) return 0;
        t = vi->type;
    } else if (auto call = dynamic_cast<CallExpr*>(e)) {
        for (auto& fn : prog.functions) {
            if (fn->name == call->name) { t = fn->returnType; break; }
        }
        if (t.kind == TypeKind::Void) return 0;
    } else if (auto m = dynamic_cast<MemberExpr*>(e)) {
        std::vector<std::string> path;
        Expr* cur = m;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) { path.insert(path.begin(), mm->member); cur = mm->object.get(); }
        auto objId = dynamic_cast<IdentExpr*>(cur);
        if (!objId) return 0;
        auto vi = getVarInfo(objId->name);
        if (!vi) return 0;
        if (!(vi->type.kind == TypeKind::Struct || vi->type.kind == TypeKind::Vec2 ||
              vi->type.kind == TypeKind::Vec3 || vi->type.kind == TypeKind::Color)) return 0;
        std::string curStruct = vi->type.structName;
        Type fieldType = vi->type;
        for (size_t i = 0; i < path.size(); i++) {
            auto slIt = structLayouts.find(curStruct);
            if (slIt == structLayouts.end()) return 0;
            auto& layout = slIt->second;
            auto fTypeIt = layout.fieldTypes.find(path[i]);
            if (fTypeIt == layout.fieldTypes.end()) return 0;
            fieldType = fTypeIt->second;
            curStruct = fieldType.structName;
        }
        t = fieldType;
    } else {
        return 0;
    }
    if (t.isPtr) return 0;
    int size = structTypeSize(t);
    if (size <= 8) return 0;
    return (size + 7) / 8;
}

// Emits the address of an Ident/Member struct *value* into r10.
// - local var: lea r10, [rbp+off]   - global var: lea r10, [rip+off]
// - pointer root: load the stored pointer, then add member offsets.
void Codegen::emitStructAddrR10(Expr* e) {
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto vi = getVarInfo(id->name);
        if (!vi) { emitMovRegImm(0, 0); return; }
        if (vi->isGlobal) emitGlobalLeaR10(vi->offset);
        else emitLeaR10FromBP(vi->offset);
        return;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        std::vector<std::string> path;
        Expr* cur = m;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) { path.insert(path.begin(), mm->member); cur = mm->object.get(); }
        if (auto objId = dynamic_cast<IdentExpr*>(cur)) {
            auto vi = getVarInfo(objId->name);
            if (vi) {
                bool isPtrRoot = vi->type.isPtr && vi->type.kind == TypeKind::Struct;
                if (vi->isGlobal) { if (isPtrRoot) emitGlobalLoadR10(vi->offset); else emitGlobalLeaR10(vi->offset); }
                else { if (isPtrRoot) emitLoadR10FromBP64(vi->offset); else emitLeaR10FromBP(vi->offset); }
                std::string curStruct = vi->type.structName;
                int totalOff = 0;
                bool found = true;
                for (size_t i = 0; found && i < path.size(); i++) {
                    auto slIt = structLayouts.find(curStruct);
                    if (slIt == structLayouts.end()) { found = false; break; }
                    auto& layout = slIt->second;
                    auto fIt = layout.fieldOffsets.find(path[i]);
                    if (fIt == layout.fieldOffsets.end()) { found = false; break; }
                    totalOff += fIt->second;
                    auto fTypeIt = layout.fieldTypes.find(path[i]);
                    if (fTypeIt == layout.fieldTypes.end()) { found = false; break; }
                    curStruct = fTypeIt->second.structName;
                }
                if (found && totalOff != 0) {
                    emit8(0x49); emit8(0x81); emit8(0xC2);          // add r10, imm32
                    emit32((uint32_t)(int32_t)totalOff);
                }
                return;
            }
        }
    }
    // Only reachable for invalid programs; structValueQwords gates all callers.
}

// Produces the big struct value of `e` in rax:rdx:r10 (k qwords).
// For a call, the callee already left its return value there. For memory
// (ident/member), load qwords from the computed address.
void Codegen::emitStructRegs(Expr* e, int k) {
    if (auto call = dynamic_cast<CallExpr*>(e)) {
        (void)emitExpr(call);
        return;
    }
    emitStructAddrR10(e);
    emit8(0x49); emit8(0x8B); emit8(0x02);                            // mov rax, [r10]
    emit8(0x49); emit8(0x8B); emit8(0x52); emit8(8);                  // mov rdx, [r10+8]
    if (k >= 3) { emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(16); }  // mov r10, [r10+16]
}

void Codegen::emitFloatStoreToBP(int xmm, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x0F); emit8(0x11);
        emit8(0x45 | (xmm << 3));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x0F); emit8(0x11);
        emit8(0x85 | (xmm << 3));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitFloatLoadFromBP(int xmm, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x0F); emit8(0x10);
        emit8(0x45 | (xmm << 3));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x0F); emit8(0x10);
        emit8(0x85 | (xmm << 3));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLeaRegFromBP(int r, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x48); emit8(0x8D); emit8((uint8_t)(0x45 | (r << 3))); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x48); emit8(0x8D); emit8((uint8_t)(0x85 | (r << 3))); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLeaR10FromBP(int offset) {
    emit8(0x4C); emit8(0x8D);
    if (offset >= -128 && offset <= 127) {
        emit8(0x55); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x95); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLoadFromAddr(int gpDst, int addrReg, int offset) {
    if (offset == 0) {
        if (addrReg == 5) {
            emit8(0x48); emit8(0x8B); emit8((uint8_t)(0x45 | (gpDst << 3))); emit8(0x00);
        } else {
            emit8(0x48); emit8(0x8B); emit8((uint8_t)((gpDst << 3) | addrReg));
        }
    } else if (offset >= -128 && offset <= 127) {
        uint8_t modrm = 0x40 | ((gpDst & 7) << 3) | (addrReg & 7);
        if (addrReg == 5) { modrm = 0x45 | ((gpDst & 7) << 3); }
        else if (addrReg == 4) { emit8(0x48); emit8(0x8B); emit8(modrm); emit8(0x24); emit8((uint8_t)(int8_t)offset); return; }
        emit8(0x48); emit8(0x8B); emit8(modrm); emit8((uint8_t)(int8_t)offset);
    } else {
        uint8_t modrm = 0x80 | ((gpDst & 7) << 3) | (addrReg & 7);
        if (addrReg == 5) { modrm = 0x85 | ((gpDst & 7) << 3); }
        else if (addrReg == 4) { emit8(0x48); emit8(0x8B); emit8(modrm); emit8(0x24); emit32((uint32_t)(int32_t)offset); return; }
        emit8(0x48); emit8(0x8B); emit8(modrm); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreToAddr(int gpSrc, int addrReg, int offset) {
    if (offset == 0) {
        if (addrReg == 5) {
            emit8(0x48); emit8(0x89); emit8((uint8_t)(0x45 | (gpSrc << 3))); emit8(0x00);
        } else {
            emit8(0x48); emit8(0x89); emit8((uint8_t)((gpSrc << 3) | addrReg));
        }
    } else if (offset >= -128 && offset <= 127) {
        uint8_t modrm = 0x40 | ((gpSrc & 7) << 3) | (addrReg & 7);
        if (addrReg == 5) { modrm = 0x45 | ((gpSrc & 7) << 3); }
        else if (addrReg == 4) { emit8(0x48); emit8(0x89); emit8(modrm); emit8(0x24); emit8((uint8_t)(int8_t)offset); return; }
        emit8(0x48); emit8(0x89); emit8(modrm); emit8((uint8_t)(int8_t)offset);
    } else {
        uint8_t modrm = 0x80 | ((gpSrc & 7) << 3) | (addrReg & 7);
        if (addrReg == 5) { modrm = 0x85 | ((gpSrc & 7) << 3); }
        else if (addrReg == 4) { emit8(0x48); emit8(0x89); emit8(modrm); emit8(0x24); emit32((uint32_t)(int32_t)offset); return; }
        emit8(0x48); emit8(0x89); emit8(modrm); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLoad32FromAddr(int gpDst, int addrReg, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x8B); emit8((uint8_t)(0x40 | ((gpDst & 7) << 3) | (addrReg & 7)));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x8B); emit8((uint8_t)(0x80 | ((gpDst & 7) << 3) | (addrReg & 7)));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStore32ToAddr(int gpSrc, int addrReg, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x89); emit8((uint8_t)(0x40 | ((gpSrc & 7) << 3) | (addrReg & 7)));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x89); emit8((uint8_t)(0x80 | ((gpSrc & 7) << 3) | (addrReg & 7)));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitFloatLoadFromAddr(int xmmDst, int addrReg, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x0F); emit8(0x10);
        emit8((uint8_t)(0x40 | ((xmmDst & 7) << 3) | (addrReg & 7)));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x0F); emit8(0x10);
        emit8((uint8_t)(0x80 | ((xmmDst & 7) << 3) | (addrReg & 7)));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitFloatStoreToAddr(int xmmDst, int addrReg, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x0F); emit8(0x11);
        emit8((uint8_t)(0x40 | ((xmmDst & 7) << 3) | (addrReg & 7)));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x0F); emit8(0x11);
        emit8((uint8_t)(0x80 | ((xmmDst & 7) << 3) | (addrReg & 7)));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLoadR10FromBP64(int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x4C); emit8(0x8B); emit8(0x55); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x4C); emit8(0x8B); emit8(0x95); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitGlobalLoadR10(int offset) {
    emit8(0x4C); emit8(0x8B); emit8(0x15);  // mov r10, [rip+disp32]
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitLoadFromAddrR10(int gpDst, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x49); emit8(0x8B); emit8((uint8_t)(0x40 | ((gpDst & 7) << 3) | 0x02));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x49); emit8(0x8B); emit8((uint8_t)(0x80 | ((gpDst & 7) << 3) | 0x02));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitLoad32FromAddrR10(int gpDst, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x41); emit8(0x8B); emit8((uint8_t)(0x40 | ((gpDst & 7) << 3) | 0x02));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x41); emit8(0x8B); emit8((uint8_t)(0x80 | ((gpDst & 7) << 3) | 0x02));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStoreToAddrR10(int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x49); emit8(0x89); emit8(0x42); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x49); emit8(0x89); emit8(0x82); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitStore32ToAddrR10(int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0x41); emit8(0x89); emit8(0x42); emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0x41); emit8(0x89); emit8(0x82); emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitFloatLoadFromAddrR10(int xmmDst, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x10);
        emit8((uint8_t)(0x40 | ((xmmDst & 7) << 3) | 0x02));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x10);
        emit8((uint8_t)(0x80 | ((xmmDst & 7) << 3) | 0x02));
        emit32((uint32_t)(int32_t)offset);
    }
}

void Codegen::emitFloatStoreToR10(int xmmDst, int offset) {
    if (offset >= -128 && offset <= 127) {
        emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x11);
        emit8((uint8_t)(0x40 | ((xmmDst & 7) << 3) | 0x02));
        emit8((uint8_t)(int8_t)offset);
    } else {
        emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x11);
        emit8((uint8_t)(0x80 | ((xmmDst & 7) << 3) | 0x02));
        emit32((uint32_t)(int32_t)offset);
    }
}

// ============== User Global Variables (RIP-relative, .data) ==============
// Each access emits an instruction with a disp32 placeholder and records a
// GlobalFixup; fixupSectionRVAs/bufPE later patch the displacement using the
// final globals RVA (like heapFixups).

void Codegen::emitGlobalLoadReg(int r, int offset) {
    uint8_t modrm = 0x05 | ((r & 7) << 3);  // mod=00, reg=r, rm=101 (RIP+disp32)
    emit8(0x48); emit8(0x8B); emit8(modrm);
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalLoadReg32(int r, int offset) {
    uint8_t modrm = 0x05 | ((r & 7) << 3);
    emit8(0x8B); emit8(modrm);
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalStoreReg64(int offset) {
    emit8(0x48); emit8(0x89); emit8(0x05);
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalStoreReg32(int offset) {
    emit8(0x89); emit8(0x05);
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalLeaReg(int r, int offset) {
    uint8_t modrm = 0x05 | ((r & 7) << 3);
    emit8(0x48); emit8(0x8D); emit8(modrm);
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalLeaR10(int offset) {
    emit8(0x4C); emit8(0x8D); emit8(0x15);  // lea r10, [rip+disp32]
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalFloatLoad(int xmm, int offset) {
    emit8(0xF3); emit8(0x0F); emit8(0x10);
    emit8(0x05 | ((xmm & 7) << 3));
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::emitGlobalFloatStore(int xmm, int offset) {
    emit8(0xF3); emit8(0x0F); emit8(0x11);
    emit8(0x05 | ((xmm & 7) << 3));
    globalFixups.push_back({code.size(), globalsRVA + (uint32_t)offset});
    emit32(0);
}

void Codegen::populateGlobalVarInfos() {
    for (auto& g : prog.globals) {
        auto it = globalOffsets.find(g->name);
        if (it != globalOffsets.end()) {
            VarInfo vi;
            vi.offset = it->second;
            vi.type = g->type;
            vi.isGlobal = true;
            vi.isConst = g->isConst;
            varInfos[g->name] = vi;
        }
    }
}

void Codegen::emitGlobalInit() {
    bool hasInit = false;
    bool hasClassGlobal = false;
    for (auto& g : prog.globals) {
        if (g->init) { hasInit = true; continue; }
        if (g->type.kind == TypeKind::Struct && !g->type.isPtr &&
            prog.classIDs.count(g->type.structName)) {
            hasClassGlobal = true;
        }
    }
    if (!hasInit && !hasClassGlobal) return;

    // Minimal stack frame so spill-based builtins (alloc, arena*, pool*, slot*)
    // that save registers to [rbp - spillBase] work during initialization.
    emit8(0x55);                       // push rbp
    emit8(0x48); emit8(0x89); emit8(0xE5);  // mov rbp, rsp
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 0x20

    int savedLocals = locals;
    int savedSpillBase = spillBase;
    locals = 0;
    spillBase = 8;

    populateGlobalVarInfos();

    for (auto& g : prog.globals) {
        if (!g->init) continue;
        int off = globalOffsets[g->name];
        if (g->type.kind == TypeKind::Float) {
            int x = emitFloatExpr(g->init.get());
            emitGlobalFloatStore(x, off);
            freeXmmReg(x);
        } else {
            int r = emitExpr(g->init.get());
            if (r != 0) { emitMovReg(0, r); freeReg(r); }
            emitGlobalStoreReg64(off);
            freeReg(0);
        }
        regsUsed = 0;
        xmmRegsUsed = 0;
    }

    // Class-typed globals without an initializer: stamp the runtime class id
    // into the hidden `__classid` slot so virtual dispatch works on them.
    for (auto& g : prog.globals) {
        if (g->init || g->type.kind != TypeKind::Struct || g->type.isPtr) continue;
        auto cidIt = prog.classIDs.find(g->type.structName);
        if (cidIt == prog.classIDs.end()) continue;
        emitMovRegImm(0, cidIt->second);
        emitGlobalStoreReg64(globalOffsets[g->name]);
        freeReg(0);
        regsUsed = 0;
        xmmRegsUsed = 0;
    }

    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 0x20
    emit8(0x5D);                       // pop rbp
    locals = savedLocals;
    spillBase = savedSpillBase;
}

void Codegen::emitLoadQwordDisp8(int dstReg, int baseReg, int disp) {
    // ModRM: mod=01 (disp8), reg=dstReg, rm=baseReg
    emit8(0x48); emit8(0x8B);
    emit8((uint8_t)(0x40 | (dstReg << 3) | baseReg));
    emit8((uint8_t)disp);
}

void Codegen::emitStoreQwordDisp8(int srcReg, int baseReg, int disp) {
    // ModRM: mod=01 (disp8), reg=srcReg, rm=baseReg
    emit8(0x48); emit8(0x89);
    emit8((uint8_t)(0x40 | (srcReg << 3) | baseReg));
    emit8((uint8_t)disp);
}

void Codegen::emitIncQwordDisp8(int baseReg, int disp) {
    emit8(0x48); emit8(0xFF);
    emit8((uint8_t)(0x40 | baseReg));  // mod=01, /0, rm=baseReg
    emit8((uint8_t)disp);
}

void Codegen::emitMovQwordDisp8Imm32(int baseReg, int disp, int32_t imm) {
    // MOV r/m64, imm32 (sign-extended): REX.W + C7 /0
    emit8(0x48); emit8(0xC7);
    emit8((uint8_t)(0x40 | baseReg));  // mod=01, /0, rm=baseReg
    emit8((uint8_t)disp);
    emit32((uint32_t)imm);
}

void Codegen::spillRegs() {
    if (regsUsed == 0) return;
    for (int i = 0; i < kNumAllocRegs; i++) {
        int r = kAllocPool[i];
        if (regsUsed & (1 << r)) {
            emitStoreRegToBP64(r, -(spillBase + i * 8));
        }
    }
}

void Codegen::reloadRegs() {
    if (regsUsed == 0) return;
    for (int i = 0; i < kNumAllocRegs; i++) {
        int r = kAllocPool[i];
        if (regsUsed & (1 << r)) {
            emitLoadRegFromBP64(r, -(spillBase + i * 8));
        }
    }
}

int Codegen::emitFloatExpr(Expr* expr) {
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        int mx = emitFloatMathCall(call);
        if (mx >= 0) return mx;
    }
    if (auto f = dynamic_cast<FloatExpr*>(expr)) {
        int x = allocXmmReg();
        if (x < 0) x = 0;
        emitMovssXmmImm(x, (float)f->value);
        return x;
    }
    if (auto n = dynamic_cast<NumberExpr*>(expr)) {
        int x = allocXmmReg();
        if (x < 0) x = 0;
        int saved = regsUsed;
        if (saved & 1) emit8(0x50);   // keep a live RAX across the scratch load
        regsUsed = 1;
        int r = allocReg();
        emitMovRegImm(r, n->value);
        emitCvtsi2ss(x, r);
        freeReg(r);
        regsUsed = (uint8_t)saved;
        if (saved & 1) emit8(0x58);   // restore RAX
        return x;
    }
    auto emitMovssXmmFromBP = [this](int xmmDst, int offset) {
        if (offset >= -128 && offset <= 127) {
            emit8(0xF3); emit8(0x0F); emit8(0x10);
            emit8(0x45 | (xmmDst << 3));
            emit8((uint8_t)(int8_t)offset);
        } else {
            emit8(0xF3); emit8(0x0F); emit8(0x10);
            emit8(0x85 | (xmmDst << 3));
            emit32((uint32_t)(int32_t)offset);
        }
    };
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        auto vi = getVarInfo(id->name);
        if (vi) {
            int x = allocXmmReg();
            if (x < 0) x = 0;
            if (vi->isGlobal) emitGlobalFloatLoad(x, vi->offset);
            else emitMovssXmmFromBP(x, vi->offset);
            return x;
        }
        int x = allocXmmReg();
        if (x < 0) x = 0;
        emitMovssXmmImm(x, 0.0f);
        return x;
    }
    if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        std::vector<std::string> path;
        Expr* cur = memb;
        std::string baseName;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) {
            path.insert(path.begin(), mm->member);
            cur = mm->object.get();
        }
        if (auto objId = dynamic_cast<IdentExpr*>(cur)) baseName = objId->name;
        if (!baseName.empty()) {
            auto vi = getVarInfo(baseName);
            if (vi) {
                std::string curStruct = vi->type.structName;
                bool isPtrRoot = vi->type.isPtr && vi->type.kind == TypeKind::Struct;
                int totalOff = 0;
                bool found = true;
                Type fieldType;
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
                if (found && (fieldType.kind == TypeKind::Float || fieldType.kind == TypeKind::Bool)) {
                    if (getenv("ZT_CALLDEBUG"))
                        fprintf(stderr, "  ffloat: base=%s field=%s totalOff=%d viOff=%d isGlobal=%d kind=%d\n",
                                baseName.c_str(), path.empty()?"":path.back().c_str(), totalOff, vi->offset, (int)vi->isGlobal, (int)vi->type.kind);
                    int x = allocXmmReg(); if (x < 0) x = 0;
                    if (isPtrRoot) {
                        int addr = allocReg();
                        if (vi->isGlobal) emitGlobalLoadReg(addr, vi->offset);
                        else emitLoadRegFromBP64(addr, vi->offset);
                        emitFloatLoadFromAddr(x, addr, totalOff);
                        freeReg(addr);
                        return x;
                    }
                    if (vi->isGlobal) emitGlobalFloatLoad(x, vi->offset + totalOff);
                    else emitMovssXmmFromBP(x, vi->offset + totalOff);
                    return x;
                }
            }
        }
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        if (auto objId = dynamic_cast<IdentExpr*>(arr->array.get())) {
            auto vi = getVarInfo(objId->name);
            if (vi && vi->type.kind == TypeKind::Float) {
                int x = allocXmmReg(); if (x < 0) x = 0;
                int idxReg = emitExpr(arr->index.get());
                if (idxReg != 0) { emitMovReg(0, idxReg); freeReg(idxReg); idxReg = 0; }
                if (vi->isGlobal) emitGlobalLeaR10(vi->offset);
                else emitLeaR10FromBP(vi->offset);
                emit8(0x48); emit8(0x69); emit8(0xC0); emit32(4);
                emit8(0x49); emit8(0x01); emit8(0xC2);
                freeReg(0);
                emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x10);
                emit8((uint8_t)(0x02 | ((x & 7) << 3)));
                return x;
            }
        }
    }
    if (auto u = dynamic_cast<UnaryExpr*>(expr)) {
        if (u->op == "-") {
            int x = emitFloatExpr(u->operand.get());
            if (x < 0) x = 0;
            int saved = regsUsed;
            if (saved & 1) emit8(0x50);   // keep a live RAX across the scratch load
            regsUsed = 1;
            int r = allocReg();
            emitMovRegImm(r, 0);
            int y = allocXmmReg();
            if (y < 0) y = 0;
            emitCvtsi2ss(y, r);
            freeReg(r);
            regsUsed = (uint8_t)saved;
            if (saved & 1) emit8(0x58);   // restore RAX
            emitSubss(y, x);              // y = 0.0f - x
            freeXmmReg(x);
            return y;
        }
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        return emitBinaryExpr(bin, true);
    }
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        // A user function returning a float leaves its result in xmm0 (Win64).
        // Emit the call (which handles args/push/restore), then treat xmm0 as
        // the live float result. Finder: builtins returning floats are handled
        // inside emitExpr/CallExpr codegen; any non-float call here just yields
        // the (garbage) xmm0, but only float-typed init/assign routes here.
        int r = emitExpr(call);
        freeReg(r);
        // xmm0 holds the float return value (Win64). It is NOT marked busy by the
        // call, so mark it busy and copy it into a freshly allocated register
        // (necessarily != xmm0). Without this, when the call is one operand of a
        // binary op or a 2-arg builtin (min/max/fmod/pow...), a second call
        // operand would also land in xmm0 and clobber this value.
        xmmRegsUsed |= (uint8_t)(1 << 0);   // xmm0 busy: holds the return value
        int x = allocXmmReg(); if (x < 0) x = 0;
        if (x != 0) emitMovssXmm(x, 0);     // copy xmm0 -> x
        xmmRegsUsed &= (uint8_t)~(1 << 0);  // xmm0 free again
        return x;
    }
    int x = allocXmmReg(); if (x < 0) x = 0;
    emitMovssXmmImm(x, 0.0f);
    return x;
}

static bool exprContainsCall(Expr* e) {
    if (!e) return false;
    if (dynamic_cast<CallExpr*>(e)) return true;
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return exprContainsCall(b->left.get()) || exprContainsCall(b->right.get());
    if (auto u = dynamic_cast<UnaryExpr*>(e))
        return exprContainsCall(u->operand.get());
    if (auto m = dynamic_cast<MemberExpr*>(e))
        return exprContainsCall(m->object.get());
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e))
        return exprContainsCall(a->array.get()) || exprContainsCall(a->index.get());
    if (auto d = dynamic_cast<DerefExpr*>(e))
        return exprContainsCall(d->ptr.get());
    return false;
}

static bool exprHasArrayAccess(Expr* e) {
    if (!e) return false;
    if (dynamic_cast<ArrayAccessExpr*>(e)) return true;
    if (dynamic_cast<CallExpr*>(e)) return false; // keep-alive already guards r10 around calls
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return exprHasArrayAccess(b->left.get()) || exprHasArrayAccess(b->right.get());
    if (auto u = dynamic_cast<UnaryExpr*>(e))
        return exprHasArrayAccess(u->operand.get());
    if (auto m = dynamic_cast<MemberExpr*>(e))
        return exprHasArrayAccess(m->object.get());
    if (auto d = dynamic_cast<DerefExpr*>(e))
        return exprHasArrayAccess(d->ptr.get());
    return false;
}

int Codegen::emitExprKeepAlive(Expr* expr, int& keepReg) {
    // Evaluate `expr` while keeping the value held in `keepReg` live across any
    // calls inside it. Calls clobber all caller-saved registers, so spill keepReg
    // to the stack first (push + sub rsp,8 keeps 16-byte alignment) and pop it
    // back into a fresh register afterwards.
    if (!exprContainsCall(expr)) return emitExpr(expr);
    emit8(0x50 + keepReg);          // push keepReg
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // sub rsp, 8
    int result = emitExpr(expr);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08); // add rsp, 8
    int restored = allocReg();
    if (restored < 0) restored = (result == 0) ? 1 : 0;
    emit8(0x58 + restored);         // pop restored
    freeReg(keepReg);
    regsUsed |= (1 << restored);
    keepReg = restored;
    return result;
}

int Codegen::emitExprKeepAliveR10(Expr* expr) {
    // Like emitExprKeepAlive, but for the untracked r10 base register used by
    // indexed assignments: save/restore r10 directly around the evaluation.
    if (!exprContainsCall(expr)) return emitExpr(expr);
    emit8(0x41); emit8(0x52);          // push r10
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // sub rsp, 8
    int result = emitExpr(expr);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08); // add rsp, 8
    emit8(0x41); emit8(0x5A);          // pop r10
    return result;
}

int Codegen::emitFloatExprKeepAliveR10(Expr* expr) {
    if (!exprContainsCall(expr)) return emitFloatExpr(expr);
    emit8(0x41); emit8(0x52);          // push r10
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // sub rsp, 8
    int x = emitFloatExpr(expr);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08); // add rsp, 8
    emit8(0x41); emit8(0x5A);          // pop r10
    return x;
}

int Codegen::emitBinaryExpr(BinaryExpr* bin, bool isFloat) {
    // Comparisons where at least one operand is float MUST be evaluated with
    // real float semantics. The integer path below would compare raw bit
    // patterns as signed ints (wrong for negative floats/NaN) and, worse,
    // evaluate a float-returning call into a GPR slot whose real value lands
    // in xmm0, so the compare sees garbage. This routing is reached both from
    // emitExpr (isFloat=false, e.g. inside && / || / print) and emitFloatExpr.
    if (bin->op == "==" || bin->op == "!=" || bin->op == "<" ||
        bin->op == ">"  || bin->op == "<=" || bin->op == ">=") {
        bool lf = isFloatExpr(bin->left.get());
        bool rf = isFloatExpr(bin->right.get());
        if (lf || rf) {
            auto toFloatXmm = [&](Expr* e, bool isF) -> int {
                if (isF) return emitFloatExpr(e);
                int g = emitExpr(e);
                int x = allocXmmReg(); if (x < 0) x = 0;
                emitCvtsi2ss(x, g);
                freeReg(g);
                return x;
            };
            int leftXmm;
            bool leftSpilled = false;
            if (exprContainsCall(bin->right.get())) {
                leftXmm = toFloatXmm(bin->left.get(), lf);
                if (leftXmm < 0) leftXmm = 0;
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);   // sub rsp, 8
                emitMovssXmmToMem(leftXmm, 4, 0);                     // [rsp] = left
                freeXmmReg(leftXmm);
                leftSpilled = true;
            } else {
                leftXmm = toFloatXmm(bin->left.get(), lf);
            }
            int rightXmm = toFloatXmm(bin->right.get(), rf);
            if (leftSpilled) {
                int lx = allocXmmReg(); if (lx < 0) lx = 0;
                emitMovssXmmFromMem(lx, 4, 0);                        // lx = [rsp]
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);   // add rsp, 8
                leftXmm = lx;
            }
            emitUcomiss(leftXmm, rightXmm);
            freeXmmReg(leftXmm);
            freeXmmReg(rightXmm);
            int r = allocReg();
            if (r < 0) r = 0;
            uint8_t setOp;
            if (bin->op == "==") setOp = 0x94;      // setE
            else if (bin->op == "!=") setOp = 0x95; // setNE
            else if (bin->op == "<") setOp = 0x92;  // setB
            else if (bin->op == ">") setOp = 0x97;  // setA
            else if (bin->op == "<=") setOp = 0x96; // setBE
            else setOp = 0x93;                        // setAE (>=)
            if (r >= 4) emit8(0x40);                 // REX prefix
            emit8(0x0F); emit8(setOp); emit8((uint8_t)(0xC0 | (r & 7)));
            if (r >= 4) emit8(0x40);                 // REX before movzx
            emit8(0x0F); emit8(0xB6); emit8((uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7)));
            return r;
        }
    }
    // Short-circuit && and ||
    if (bin->op == "%of") {
        if (isFloat || isFloatExpr(bin->right.get())) {
            fprintf(stderr, "Error: percent base must be an integer expression\n");
            exit(1);
        }
        // result = (percent * base) / 100
        int leftReg = emitExpr(bin->left.get());
        int tempReg = allocReg();
        if (tempReg < 0) tempReg = 0;
        emitMovReg(tempReg, leftReg);
        freeReg(leftReg);
        int rightReg = emitExprKeepAlive(bin->right.get(), tempReg);
        emitImul(rightReg, tempReg);      // rightReg = percent * base
        freeReg(tempReg);
        bool saveRcx = (regsUsed & 2) != 0 && rightReg != 1;
        bool saveRdx = (regsUsed & 4) != 0 && rightReg != 2;
        if (saveRcx) emit8(0x51);         // push rcx (preserve live outer value)
        if (saveRdx) emit8(0x52);         // push rdx (preserve live outer value)
        emitMovReg(0, rightReg);          // rax = product
        if (wordSize == 32) { emit8(0x99); } else { emit8(0x48); emit8(0x99); }  // cdq / cqo
        emitMovRegImm(1, 100);            // rcx = 100
        if (wordSize == 32) { emit8(0xF7); } else { emit8(0x48); emit8(0xF7); } emit8(0xF9);  // idiv rcx
        if (saveRdx) emit8(0x5A);         // pop rdx (restore outer value)
        if (saveRcx) emit8(0x59);         // pop rcx (restore outer value)
        freeReg(rightReg);
        regsUsed |= 1;                    // RAX holds the result
        return 0;
    }
    if (bin->op == "&&") {
        int leftReg = emitExpr(bin->left.get());
        emit8(0x48); emit8(0x85); emit8((uint8_t)(0xC0 | ((leftReg & 7) << 3) | (leftReg & 7)));
        int falseLabel = newLabel();
        emit8(0x0F); emit8(0x84);
        jmpFixups.push_back({code.size(), falseLabel}); emit32(0);
        freeReg(leftReg);
        int rightReg = emitExpr(bin->right.get());
        emit8(0x48); emit8(0x85); emit8((uint8_t)(0xC0 | ((rightReg & 7) << 3) | (rightReg & 7)));
        freeReg(rightReg);
        int trueLabel = newLabel();
        emit8(0x0F); emit8(0x85);
        jmpFixups.push_back({code.size(), trueLabel}); emit32(0);
        int resultReg = allocReg(); if (resultReg < 0) resultReg = 0;
        int endLabel = newLabel();
        emitLabel(falseLabel);
        emitMovRegImm(resultReg, 0);
        emitJmp(endLabel);
        emitLabel(trueLabel);
        emitMovRegImm(resultReg, 1);
        emitLabel(endLabel);
        return resultReg;
    }
    if (bin->op == "||") {
        int leftReg = emitExpr(bin->left.get());
        emit8(0x48); emit8(0x85); emit8((uint8_t)(0xC0 | ((leftReg & 7) << 3) | (leftReg & 7)));
        int trueLabel = newLabel();
        emit8(0x0F); emit8(0x85);
        jmpFixups.push_back({code.size(), trueLabel}); emit32(0);
        freeReg(leftReg);
        int rightReg = emitExpr(bin->right.get());
        emit8(0x48); emit8(0x85); emit8((uint8_t)(0xC0 | ((rightReg & 7) << 3) | (rightReg & 7)));
        freeReg(rightReg);
        int falseLabel = newLabel();
        emit8(0x0F); emit8(0x84);
        jmpFixups.push_back({code.size(), falseLabel}); emit32(0);
        int resultReg = allocReg(); if (resultReg < 0) resultReg = 0;
        int endLabel = newLabel();
        emitLabel(trueLabel);
        emitMovRegImm(resultReg, 1);
        emitJmp(endLabel);
        emitLabel(falseLabel);
        emitMovRegImm(resultReg, 0);
        emitLabel(endLabel);
        return resultReg;
    }

    if (!isFloat) {
        int leftReg = emitExpr(bin->left.get());
        int tempReg = allocReg();
        if (tempReg < 0 &&
            (bin->op == "+" || bin->op == "-" || bin->op == "*" ||
             bin->op == "&" || bin->op == "|" || bin->op == "^")) {
            // All GPRs are busy. Spill the left operand to the stack and
            // combine it into the right register with a memory-operand form
            // of the instruction; popping into a guessed register could
            // clobber values that are still live (e.g. an enclosing
            // expression's intermediate result).
            emit8(0x50 + leftReg);                 // push left
            int rightReg = emitExpr(bin->right.get());
            if (bin->op == "+") {
                if (wordSize == 64) emit8(0x48);
                emit8(0x03);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // add right, [rsp]
            } else if (bin->op == "-") {
                // memory form subtracts the wrong way; negate right first
                if (wordSize == 64) emit8(0x48);
                emit8(0xF7);
                emit8((uint8_t)(0xD8 | (rightReg & 7)));  // neg right
                if (wordSize == 64) emit8(0x48);
                emit8(0x03);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // add right, [rsp]
            } else if (bin->op == "*") {
                if (wordSize == 64) emit8(0x48);
                emit8(0x0F); emit8(0xAF);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // imul right, [rsp]
            } else if (bin->op == "&") {
                if (wordSize == 64) emit8(0x48);
                emit8(0x23);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // and right, [rsp]
            } else if (bin->op == "|") {
                if (wordSize == 64) emit8(0x48);
                emit8(0x0B);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // or right, [rsp]
            } else {                               // "^"
                if (wordSize == 64) emit8(0x48);
                emit8(0x33);
                emit8((uint8_t)(0x04 | ((rightReg & 7) << 3)));
                emit8(0x24);                       // xor right, [rsp]
            }
            if (wordSize == 64) emit8(0x48);
            emit8(0x83); emit8(0xC4); emit8(0x08); // add rsp, 8
            freeReg(leftReg);
            return rightReg;                       // remains allocated
        }
        if (tempReg < 0) {
            emit8(0x50 + leftReg);
            int rightReg = emitExpr(bin->right.get());
            int popReg = allocReg();
            if (popReg < 0) {
                popReg = (rightReg == 0) ? 1 : 0;
            }
            emit8(0x58 + popReg);
            if (bin->op == "+") {
                emitAdd(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "-") {
                emitSub(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "*") {
                emitImul(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "/") {
                // idiv rax by rcx: rax = left, rcx = right, rdx = 0
                bool saveRdx = (regsUsed & 4) != 0 && rightReg != 2 && popReg != 2;
                if (saveRdx) emit8(0x52);  // push rdx (save outer value)
                if (rightReg == 0 && popReg == 1) {
                    // left in rcx, right in rax → swap via xchg
                    emit8(0x48); emit8(0x87); emit8(0xC1); // xchg rax, rcx
                } else {
                    emitMovReg(0, popReg);            // rax = left (before pop may clobber rcx)
                    emit8(0x50 + rightReg); emit8(0x59);   // push rightReg; pop rcx
                }
                if (wordSize == 32) emit8(0x99); else emit8(0x48); emit8(0x99);  // cdq / cqo
                if (wordSize == 32) emit8(0xF7); else emit8(0x48); emit8(0xF7); emit8(0xF9);  // idiv rcx
                if (saveRdx) emit8(0x5A);  // pop rdx (restore outer value)
                freeReg(popReg);
                freeReg(rightReg);
                regsUsed |= 1; // only RAX live
                return 0;
            } else if (bin->op == "%" || bin->op == "//") {
                // idiv rax by rcx: rax = left, rcx = right, rdx = remainder
                bool saveRdx = (regsUsed & 4) != 0 && rightReg != 2 && popReg != 2;
                if (saveRdx) emit8(0x52);  // push rdx (save outer value)
                if (rightReg == 0 && popReg == 1) {
                    emit8(0x48); emit8(0x87); emit8(0xC1); // xchg rax, rcx
                } else {
                    emitMovReg(0, popReg);            // rax = left (before pop may clobber rcx)
                    emit8(0x50 + rightReg); emit8(0x59);   // push rightReg; pop rcx
                }
                if (wordSize == 32) { emit8(0x99); } else { emit8(0x48); emit8(0x99); }  // cdq / cqo
                if (wordSize == 32) { emit8(0xF7); } else { emit8(0x48); emit8(0xF7); } emit8(0xF9);  // idiv rcx
                if (wordSize == 32) { emit8(0x89); } else { emit8(0x48); emit8(0x89); } emit8(0xD0);  // mov rax, rdx (remainder)
                if (saveRdx) emit8(0x5A);  // pop rdx (restore outer value)
                freeReg(popReg);
                freeReg(rightReg);
                regsUsed |= 1; // only RAX live
                return 0;
            } else if (bin->op == "&") {
                emitAnd(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "|") {
                emitOr(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "^") {
                emitXor(popReg, rightReg);
                freeReg(rightReg);
                return popReg;
            } else if (bin->op == "<<" || bin->op == ">>") {
                // value in popReg, count in rightReg; count must be in CL.
                // In this path all GPRs are busy, so rcx may hold a live
                // value that must survive the shift.
                bool valueInRcx = (popReg == 1 && rightReg != 1);
                if (valueInRcx) {
                    // The value physically stays in rcx and is preserved by
                    // the push/pop around the shift; only renumber the slot
                    // for the final freeReg bookkeeping. The value->rax move
                    // must read from rcx before CL is loaded.
                    popReg = (rightReg == 0) ? 2 : 0;
                }
                bool saveRcx = rightReg != 1;
                if (saveRcx) emit8(0x51);            // push rcx (save live value)
                if (rightReg != 1) {
                    emit8(0x50 + rightReg);          // push count
                    if (valueInRcx) emitMovReg(0, 1);   // value -> rax (from rcx)
                    else emitMovReg(0, popReg);         // value -> rax
                    emit8(0x59);                     // pop rcx (count -> cl)
                } else {
                    emitMovReg(0, popReg);           // value -> rax
                }
                if (bin->op == "<<") {
                    if (wordSize == 32) emit8(0xD3);
                    else { emit8(0x48); emit8(0xD3); }
                    emit8(0xE0);
                } else {
                    if (wordSize == 32) emit8(0xD3);
                    else { emit8(0x48); emit8(0xD3); }
                    emit8(0xE8);
                }
                if (saveRcx) emit8(0x59);            // pop rcx (restore live value)
                freeReg(popReg);
                freeReg(rightReg);
                regsUsed |= 1;
                return 0;
            } else if (bin->op == "==" || bin->op == "!=" ||
                       bin->op == "<"  || bin->op == ">"  ||
                       bin->op == "<=" || bin->op == ">=") {
                emit8(0x48); emit8(0x39); emit8(0xC0 + popReg + rightReg * 8);
                emitMovRegImm(rightReg, 0);
                int endLabel = newLabel();
                if (bin->op == "==") { emit8(0x0F); emit8(0x85); }
                else if (bin->op == "!=") { emit8(0x0F); emit8(0x84); }
                else if (bin->op == "<") { emit8(0x0F); emit8(0x8D); }
                else if (bin->op == ">") { emit8(0x0F); emit8(0x8E); }
                else if (bin->op == "<=") { emit8(0x0F); emit8(0x8F); }
                else if (bin->op == ">=") { emit8(0x0F); emit8(0x8C); }
                jmpFixups.push_back({code.size(), endLabel});
                emit32(0);
                emitMovRegImm(rightReg, 1);
                emitLabel(endLabel);
                freeReg(popReg);
                return rightReg;
            } else {
                freeReg(popReg);
                freeReg(rightReg);
                return rightReg;
            }
        }
        emitMovReg(tempReg, leftReg);
        freeReg(leftReg);
        // A call inside the right operand would clobber tempReg, so keep it alive
        // on the stack across the evaluation.
        int rightReg = emitExprKeepAlive(bin->right.get(), tempReg);

        if (bin->op == "+") {
            emitAdd(rightReg, tempReg);
            freeReg(tempReg);
            return rightReg;
        } else if (bin->op == "-") {
            emitSub(tempReg, rightReg);
            emitMovReg(rightReg, tempReg);
            freeReg(tempReg);
            return rightReg;
        } else if (bin->op == "*") {
            emitImul(rightReg, tempReg);
            freeReg(tempReg);
            return rightReg;
        } else if (bin->op == "/") {
            // idiv needs divisor in rcx; cqo clobbers rdx. Live outer values in
            // rcx/rdx are pushed before the sequence and restored after it.
            bool saveRcx = (regsUsed & 2) != 0 && rightReg != 1;
            bool saveRdx = (regsUsed & 4) != 0 && rightReg != 2 && tempReg != 2;
            if (saveRcx) emit8(0x51);  // push rcx (save outer value)
            if (saveRdx) emit8(0x52);  // push rdx (save outer value)
            emit8(0x50 + rightReg);    // push divisor (any register)
            emitMovReg(0, tempReg);
            if (wordSize == 32) { emit8(0x99); } else { emit8(0x48); emit8(0x99); }  // cdq / cqo
            emit8(0x59);  // pop rcx
            if (wordSize == 32) { emit8(0xF7); } else { emit8(0x48); emit8(0xF7); } emit8(0xF9);  // idiv rcx
            if (saveRdx) emit8(0x5A);  // pop rdx (restore outer value)
            if (saveRcx) emit8(0x59);  // pop rcx (restore outer value)
            freeReg(rightReg);
            freeReg(tempReg);
            regsUsed |= 1;  // RAX holds the division result
            return 0;
        } else if (bin->op == "%" || bin->op == "//") {
            bool saveRcx = (regsUsed & 2) != 0 && rightReg != 1;
            bool saveRdx = (regsUsed & 4) != 0 && rightReg != 2 && tempReg != 2;
            if (saveRcx) emit8(0x51);  // push rcx (save outer value)
            if (saveRdx) emit8(0x52);  // push rdx (save outer value)
            emit8(0x50 + rightReg);    // push divisor (any register)
            emitMovReg(0, tempReg);
            if (wordSize == 32) { emit8(0x99); } else { emit8(0x48); emit8(0x99); }  // cdq / cqo
            emit8(0x59);  // pop rcx
            if (wordSize == 32) { emit8(0xF7); } else { emit8(0x48); emit8(0xF7); } emit8(0xF9);  // idiv rcx
            if (wordSize == 32) { emit8(0x89); } else { emit8(0x48); emit8(0x89); } emit8(0xD0);  // mov eax, edx (remainder)
            if (saveRdx) emit8(0x5A);  // pop rdx (restore outer value)
            if (saveRcx) emit8(0x59);  // pop rcx (restore outer value)
            freeReg(rightReg);
            freeReg(tempReg);
            regsUsed |= 1;  // RAX holds the modulo result
            return 0;
        } else if (bin->op == "&") {
            emitAnd(tempReg, rightReg);
            freeReg(rightReg);
            return tempReg;
        } else if (bin->op == "|") {
            emitOr(tempReg, rightReg);
            freeReg(rightReg);
            return tempReg;
        } else if (bin->op == "^") {
            emitXor(tempReg, rightReg);
            freeReg(rightReg);
            return tempReg;
        } else if (bin->op == "<<" || bin->op == ">>") {
            // value in tempReg, count in rightReg; count must be in CL.
            bool saveRcx = (regsUsed & 2) != 0 && rightReg != 1;
            if (tempReg == 1 && rightReg != 1) {
                // value occupies rcx; move it out before the count is loaded into CL
                int spare = -1;
                for (int i = 0; i < kNumAllocRegs; i++) {
                    int r = kAllocPool[i];
                    if (r != 1 && r != rightReg && !(regsUsed & (1 << r))) { spare = r; break; }
                }
                if (spare < 0) { emit8(0x50); spare = (rightReg == 0) ? 2 : 0; emit8(0x58 + spare); }
                emitMovReg(spare, 1);
                freeReg(1);
                tempReg = spare;
            }
            if (saveRcx) emit8(0x51);  // push rcx (save outer value)
            if (rightReg != 1) {
                emit8(0x50 + rightReg);              // push count
                emit8(0x59);                         // pop rcx (count -> cl)
            }
            // Shift IN PLACE in tempReg: any register may be the destination,
            // so avoid forcing the value through RAX, which often holds a live
            // intermediate of an enclosing expression.
            if (bin->op == "<<") {
                if (wordSize == 32) emit8(0xD3);
                else { emit8(0x48); emit8(0xD3); }
                emit8((uint8_t)(0xE0 | (tempReg & 7)));
            } else {
                if (wordSize == 32) emit8(0xD3);
                else { emit8(0x48); emit8(0xD3); }
                emit8((uint8_t)(0xE8 | (tempReg & 7)));
            }
            if (saveRcx) emit8(0x59);  // pop rcx (restore outer value)
            freeReg(rightReg);
            return tempReg;
        } else if (bin->op == "==" || bin->op == "!=" ||
                   bin->op == "<"  || bin->op == ">"  ||
                   bin->op == "<=" || bin->op == ">=") {
            emit8(0x48); emit8(0x39); emit8(0xC0 + tempReg + rightReg * 8);
            emitMovRegImm(rightReg, 0);
            int endLabel = newLabel();
            if (bin->op == "==") { emit8(0x0F); emit8(0x85); }
            else if (bin->op == "!=") { emit8(0x0F); emit8(0x84); }
            else if (bin->op == "<") { emit8(0x0F); emit8(0x8D); }
            else if (bin->op == ">") { emit8(0x0F); emit8(0x8E); }
            else if (bin->op == "<=") { emit8(0x0F); emit8(0x8F); }
            else if (bin->op == ">=") { emit8(0x0F); emit8(0x8C); }
            jmpFixups.push_back({code.size(), endLabel});
            emit32(0);
            emitMovRegImm(rightReg, 1);
            emitLabel(endLabel);
            freeReg(tempReg);
            return rightReg;
        } else {
            freeReg(tempReg);
            return rightReg;
        }
    } else {
        // If the right operand contains a call, evaluating it can clobber the
        // register holding the left operand (calls reset xmmRegsUsed), so spill
        // the left result to the stack and reload it afterwards.
        int leftXmm;
        bool leftSpilled = false;
        if (exprContainsCall(bin->right.get())) {
            leftXmm = emitFloatExpr(bin->left.get());
            if (leftXmm < 0) leftXmm = 0;
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);   // sub rsp, 8
            emitMovssXmmToMem(leftXmm, 4, 0);                     // [rsp] = left
            freeXmmReg(leftXmm);
            leftSpilled = true;
        } else {
            leftXmm = emitFloatExpr(bin->left.get());
        }
        int rightXmm = emitFloatExpr(bin->right.get());
        if (leftSpilled) {
            int lx = allocXmmReg(); if (lx < 0) lx = 0;
            emitMovssXmmFromMem(lx, 4, 0);                        // lx = [rsp]
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);   // add rsp, 8
            leftXmm = lx;
        }

        int resultXmm = rightXmm;
        if (bin->op == "+") {
            emitAddss(leftXmm, rightXmm);
            resultXmm = leftXmm;
            freeXmmReg(rightXmm);
        } else if (bin->op == "-") {
            int tempXmm = allocXmmReg();
            if (tempXmm < 0) {
                tempXmm = leftXmm;
                emitSubss(tempXmm, rightXmm);
                freeXmmReg(rightXmm);
            } else {
                emitMovssXmm(tempXmm, leftXmm);
                emitSubss(tempXmm, rightXmm);
                freeXmmReg(leftXmm);
                freeXmmReg(rightXmm);
            }
            resultXmm = tempXmm;
        } else if (bin->op == "*") {
            emitMulss(leftXmm, rightXmm);
            resultXmm = leftXmm;
            freeXmmReg(rightXmm);
        } else if (bin->op == "/") {
            int tempXmm = allocXmmReg();
            if (tempXmm < 0) {
                tempXmm = leftXmm;
                emitDivss(tempXmm, rightXmm);
                freeXmmReg(rightXmm);
            } else {
                emitMovssXmm(tempXmm, leftXmm);
                emitDivss(tempXmm, rightXmm);
                freeXmmReg(leftXmm);
                freeXmmReg(rightXmm);
            }
            resultXmm = tempXmm;
        } else if (bin->op == "==" || bin->op == "!=" ||
                   bin->op == "<"  || bin->op == ">"  ||
                   bin->op == "<=" || bin->op == ">=") {
            emitUcomiss(leftXmm, rightXmm);
            freeXmmReg(leftXmm);
            freeXmmReg(rightXmm);
            int r = allocReg();
            if (r < 0) r = 0;
            // SETcc (0F 9x) operates on a byte register; the low-byte forms of
            // rsi/rdi (sil/dil) and registers 8+ require the REX prefix, which
            // must be emitted BEFORE the instruction bytes. r is always in
            // {0,1,2,3,6,7} here, so REX is only needed for r >= 4 (6/7).
            {   uint8_t setOp;
                if (bin->op == "==") setOp = 0x94;      // setE
                else if (bin->op == "!=") setOp = 0x95; // setNE
                else if (bin->op == "<") setOp = 0x92;  // setB (CF)
                else if (bin->op == ">") setOp = 0x97;  // setA
                else if (bin->op == "<=") setOp = 0x96; // setBE
                else setOp = 0x93;                        // setAE (>=)
                if (r >= 4) emit8(0x40);                 // REX prefix (sil/dil/8+)
                emit8(0x0F); emit8(setOp); emit8((uint8_t)(0xC0 | (r & 7)));
                if (r >= 4) emit8(0x40);                 // REX prefix before movzx
                emit8(0x0F); emit8(0xB6); emit8((uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7)));
            }
            return r;
        }
        // Float arithmetic (+, -, *, /): the result stays in an XMM register
        // (resultXmm). It must be returned as-is so callers, which expect an
        // XMM index (emitFloatStoreToBP etc.), write the correct register.
        // The previous code wrongly converted to int (emitCvtss2si) and
        // returned a GPR index, so float math was only correct when the GPR
        // and XMM indices coincidentally matched.
        return resultXmm;
    }
}

int Codegen::emitExpr(Expr* expr) {
    if (auto u = dynamic_cast<UnaryExpr*>(expr)) return emitUnaryExpr(u);
    if (auto num = dynamic_cast<NumberExpr*>(expr)) {
        int r = allocReg();
        // allocReg now spills and retries
        emitMovRegImm(r, num->value);
        return r;
    }
    if (auto flt = dynamic_cast<FloatExpr*>(expr)) {
        int r = allocReg();
        // allocReg now spills and retries
        float fval = (float)flt->value;
        uint32_t bits;
        memcpy(&bits, &fval, sizeof(bits));
        emitMovRegImm(r, bits);
        return r;
    }
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        auto vi = getVarInfo(id->name);
        if (vi) {
            int r = allocReg();
            if (vi->isGlobal) {
                if (vi->type.kind == TypeKind::Float || vi->type.kind == TypeKind::Bool) {
                    emitGlobalLoadReg32(r, vi->offset);
                } else {
                    emitGlobalLoadReg(r, vi->offset);
                }
                return r;
            }
            if (vi->type.kind == TypeKind::Float || vi->type.kind == TypeKind::Bool) {
                emitLoadRegFromBP(r, vi->offset);
            } else {
                emitLoadRegFromBP64(r, vi->offset);
            }
            return r;
        }
        // Check if it's a known function — emit function reference (pointer)
        bool isFunc = funcOffsets.count(id->name) > 0;
        if (!isFunc) {
            for (auto& f : prog.functions) {
                if (f->name == id->name && !f->isExtern) { isFunc = true; break; }
            }
        }
        if (isFunc) {
            emit8(0x48); emit8(0x8D); emit8(0x05);
            size_t fixupPos = code.size();
            emit32(0);
            funcRefFixups.push_back({fixupPos, id->name});
            // Value is already in rax (LEA result)
            return 0;
        }
        std::cerr << "Error: undefined variable '" << id->name << "'\n";
        int r = allocReg();
        emitMovRegImm(r, 0);
        return r;
    }
    if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        // flatten a.b.c into base variable name + member path
        std::vector<std::string> path;
        Expr* cur = memb;
        std::string baseName;
        while (auto mm = dynamic_cast<MemberExpr*>(cur)) {
            path.insert(path.begin(), mm->member);
            cur = mm->object.get();
        }
        if (auto objId = dynamic_cast<IdentExpr*>(cur)) baseName = objId->name;
        if (!baseName.empty()) {
            auto vi = getVarInfo(baseName);
            if (vi) {
                std::string curStruct = vi->type.structName;
                bool isPtrRoot = vi->type.isPtr && vi->type.kind == TypeKind::Struct;
                int totalOff = 0;
                bool found = true;
                Type fieldType;
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
                    bool isFloatField = fieldType.kind == TypeKind::Float;
                    bool isBoolField = fieldType.kind == TypeKind::Bool;
                    if (getenv("ZT_CALLDEBUG"))
                        fprintf(stderr, "  member: base=%s field=%s isFloat=%d totalOff=%d viOff=%d isGlobal=%d kind=%d isPtr=%d struct=%s\n",
                                baseName.c_str(), path.empty()?"":path.back().c_str(), (int)isFloatField, totalOff, vi->offset,
                                (int)vi->isGlobal, (int)vi->type.kind, (int)vi->type.isPtr, curStruct.c_str());
                    if (isPtrRoot) {
                        int addr = allocReg();
                        if (vi->isGlobal) emitGlobalLoadReg(addr, vi->offset);
                        else emitLoadRegFromBP64(addr, vi->offset);
                        int r = allocReg();
                        if (isFloatField || isBoolField) emitLoad32FromAddr(r, addr, totalOff);
                        else emitLoadFromAddr(r, addr, totalOff);
                        freeReg(addr);
                        return r;
                    }
                    int r = allocReg();
                    if (isFloatField || isBoolField) {
                        if (vi->isGlobal) emitGlobalLoadReg32(r, vi->offset + totalOff);
                        else emitLoadRegFromBP(r, vi->offset + totalOff);
                    } else {
                        if (vi->isGlobal) emitGlobalLoadReg(r, vi->offset + totalOff);
                        else emitLoadRegFromBP64(r, vi->offset + totalOff);
                    }
                    return r;
                }
            }
        }
        int r = allocReg();
        emitMovRegImm(r, 0);
        return r;
    }
    if (auto str = dynamic_cast<StringExpr*>(expr)) {
        int idx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == str->value) { idx = (int)i; break; }
        }
        if (idx < 0) {
            idx = (int)stringPool.size();
            stringPool.push_back(str->value);
        }
        int r = allocReg();
        if (prog.koDriver) {
            // Kernel-module mode: reference strings with `mov r64, sign-ext-imm32`
            // + R_X86_64_32S (gcc -mcmodel=kernel style). Module addresses sit in
            // the high half of the 32-bit range, so the sign-extended immediate
            // reproduces the final address after the loader patches S+A.
            emit8(0x48); emit8(0xC7); emit8((uint8_t)(0xC0 | r));
            size_t fixupPos = code.size();
            emit32(0);
            koStrFixups.push_back({fixupPos, idx});
        } else {
            emit8(0x48); emit8(0x8D);
            emit8((uint8_t)(0x05 | (r << 3)));
            size_t fixupPos = code.size();
            emit32(0);
            strFixups.push_back({fixupPos, idx});
        }
        return r;
    }
if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        auto objId = dynamic_cast<IdentExpr*>(arr->array.get());
        if (objId) {
            auto vi = getVarInfo(objId->name);
            if (vi) {
                int elementSize = (vi->type.kind == TypeKind::Float) ? 4 : 8;
                // Bug A fix: the load path uses RAX as scratch (idx multiply,
                // mov rax,[r10]) which can destroy a live RAX holding an outer
                // expression's value (e.g. (mem[a]&255)*256+(mem[b]&255)).
                // Preserve RAX on the stack when it is live and restore it
                // before returning the loaded value in a different register.
                bool raxLive = (regsUsed & 1) != 0;
                if (raxLive) {
                    emit8(0x50);                                  // push rax
                    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // sub rsp, 8
                }
                int idxReg = emitExpr(arr->index.get());
                if (idxReg != 0) { emitMovReg(0, idxReg); freeReg(idxReg); idxReg = 0; }
                if (vi->isGlobal) emitGlobalLeaR10(vi->offset);
                else emitLeaR10FromBP(vi->offset);
                emit8(0x48); emit8(0x69); emit8(0xC0); emit32(elementSize);
                emit8(0x49); emit8(0x01); emit8(0xC2);
                int r;
                if (vi->type.kind == TypeKind::Float) {
                    freeReg(0);
                    int x = allocXmmReg();
                    if (x < 0) x = 0;
                    emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x10);
                    emit8((uint8_t)(0x02 | ((x & 7) << 3)));
                    r = allocReg();
                    emitCvtss2si(r, x);
                    freeXmmReg(x);
                } else {
                    emit8(0x49); emit8(0x8B); emit8(0x02);
                    freeReg(0);
                    r = allocReg();
                    if (r != 0) { emitMovReg(r, 0); freeReg(0); }
                }
                if (raxLive) {
                    // RAX holds the loaded value (r == 0); move it to a spare
                    // register and restore the outer RAX value.
                    if (r == 0) {
                        int spare = allocReg();
                        if (spare < 0) {
                            for (int i = 0; i < kNumAllocRegs; i++) {
                                int pr = kAllocPool[i];
                                if (pr != 0 && !(regsUsed & (1 << pr))) { spare = pr; regsUsed |= (1 << pr); break; }
                            }
                            if (spare < 0) spare = 1;
                        }
                        emitMovReg(spare, 0);
                        freeReg(0);
                        r = spare;
                    }
                    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08); // add rsp, 8
                    emit8(0x58);                                        // pop rax
                    regsUsed |= 1;                                      // RAX live again (outer value)
                    regsUsed |= (1 << r);                               // r holds the loaded value
                }
                return r >= 0 ? r : 0;
            }
        }
        int r = allocReg();
        emitMovRegImm(r, 0);
        return r;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        return emitBinaryExpr(bin, false);
    }
    if (auto addrOf = dynamic_cast<AddressOfExpr*>(expr)) {
        auto vi = getVarInfo(addrOf->name);
        int r = allocReg();
        if (!vi) {
            // &function — address of a Zenith function (e.g. for IDT gates,
            // callbacks). Same rip-relative LEA + fixup as a bare function ref.
            bool isFunc = funcOffsets.count(addrOf->name) > 0;
            if (!isFunc) {
                for (auto& f : prog.functions) {
                    if (f->name == addrOf->name && !f->isExtern) { isFunc = true; break; }
                }
            }
            if (isFunc) {
                freeReg(r);
                emit8(0x48); emit8(0x8D); emit8(0x05);
                size_t fixupPos = code.size();
                emit32(0);
                funcRefFixups.push_back({fixupPos, addrOf->name});
                return 0;                       // result in rax
            }
            emitMovRegImm(r, 0); return r;
        }
        if (vi->isGlobal) emitGlobalLeaReg(r, vi->offset);
        else emitLeaRegFromBP(r, vi->offset);
        return r;
    }
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name == "ftoi" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int fx = emitFloatExpr(call->args[0].get());
            if (fx < 0) fx = 0;
            int rOut = allocReg();
            if (rOut < 0) rOut = 0;
            emitCvttss2si(rOut, fx);
            freeXmmReg(fx);
            // The result register must be marked busy for the caller, and must
            // not be reloaded from the spill slots (which would clobber it).
            regsUsed = (uint8_t)(saved & ~(1 << rOut));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << rOut));
            return rOut >= 0 ? rOut : 0;
        }
        if (call->name == "alloc" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sizeReg = emitExpr(call->args[0].get());
            if (sizeReg != 1) { emitMovReg(1, sizeReg); freeReg(sizeReg); sizeReg = 1; }
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(15);  // add rcx, 15
            emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0); // and rcx, -16
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);  // add rcx, 16
            emit8(0x48); emit8(0x89); emit8(0xCB);  // mov rbx, rcx (save totalSize)
            emit8(0x48); emit8(0x8D); emit8(0x05);
            heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);
            int bumpLabel = newLabel();
            int failLabel = newLabel();
            int doneLabel = newLabel();
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x48); emit8(0x85); emit8(0xD2);  // test rdx, rdx
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), bumpLabel}); emit32(0);
            emit8(0x48); emit8(0x8B); emit8(0x4A); emit8(8);  // mov rcx, [rdx+8]
            emit8(0x48); emit8(0x39); emit8(0xD9);  // cmp rcx, rbx
            emit8(0x0F); emit8(0x82);
            jmpFixups.push_back({code.size(), bumpLabel}); emit32(0);
            emit8(0x48); emit8(0x8B); emit8(0x0A);  // mov rcx, [rdx]
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x31); emit8(0xC9);  // xor ecx, ecx
            emit8(0x48); emit8(0x89); emit8(0x0A);  // mov [rdx], rcx
            emit8(0x48); emit8(0x8D); emit8(0x42); emit8(0x10);  // lea rax, [rdx+16]
            emitJmp(doneLabel);
            emitLabel(bumpLabel);
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0xD1);  // mov rcx, rdx
            emit8(0x48); emit8(0x01); emit8(0xD9);  // add rcx, rbx
            emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
            emit8(0x0F); emit8(0x87);
            jmpFixups.push_back({code.size(), failLabel}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x5C); emit8(0x10); emit8(8);  // mov [rax+rdx+8], rbx
            emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [rax+rdx+16]
            emitJmp(doneLabel);
            emitLabel(failLabel);
            emit8(0x48); emit8(0x31); emit8(0xC0);  // xor eax, eax
            emitLabel(doneLabel);
            freeReg(1); freeReg(2); freeReg(3);
            int r = allocReg(); if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }
        if (call->name == "free" && call->args.size() == 1) {
            int r = emitExpr(call->args[0].get());
            if (r != 1) { emitMovReg(1, r); freeReg(r); }
            regsUsed = 0;
            emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0);  // lea rax, [rcx-16]
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x10);  // mov [rax], rdx
            emit8(0x48); emit8(0x89); emit8(0x05);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emitMovRegImm(0, 0);
            return 0;
        }

        // ============== Arena Allocator Builtins ==============
        // Arena header: [capacity:8][used:8], data at handle+16

        auto emitHeapAlloc = [this](int sizeReg) {
            if (sizeReg != 1) { emitMovReg(1, sizeReg); freeReg(sizeReg); }
            // rcx = size
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(15);  // add rcx, 15
            emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0); // and rcx, -16
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);  // add rcx, 16 (header)
            emit8(0x48); emit8(0x8D); emit8(0x05);
            heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);  // rax = heapArea
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);  // rdx = offset
            emit8(0x49); emit8(0x89); emit8(0xC0); // r8 = rax (save heapArea)
            emit8(0x48); emit8(0x03); emit8(0xCA); // rcx = totalSize + offset = newOffset
            emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
            int fl = newLabel();
            emit8(0x0F); emit8(0x87); jmpFixups.push_back({code.size(), fl}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x48); emit8(0x29); emit8(0xD1); // sub rcx, rdx (totalSize = newOffset - oldOffset)
            emit8(0x49); emit8(0x89); emit8(0x4C); emit8(0x10); emit8(8); // mov [r8+rdx+8], rcx
            emit8(0x49); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [r8+rdx+16]
            int dl = newLabel(); emitJmp(dl);
            emitLabel(fl); emit8(0x48); emit8(0x31); emit8(0xC0); // xor rax, rax (fail=0)
            emitLabel(dl);
            freeReg(1); freeReg(2);
        };

        // arenaCreate(capacity) -> handle
        // Header: [capacity:8][used:8], data at handle+16
        if (call->name == "arenaCreate" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int capReg = emitExpr(call->args[0].get());
            // Save capacity in reg 3 (rbx) — safe across emitHeapAlloc
            if (capReg != 3) { emitMovReg(3, capReg); freeReg(capReg); }
            // rcx = capacity + 16 (total allocation size)
            emitMovReg(1, 3);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            emitHeapAlloc(1);  // rax = block pointer (or 0 on fail)
            // [rax+0] = capacity (from rbx)
            emitStoreQwordDisp8(3, 0, 0);
            // [rax+8] = 0 (used = 0)
            emitMovQwordDisp8Imm32(0, 8, 0);
            // rax = handle (return value)
            freeReg(3);
            int r = allocReg();
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // arenaAlloc(arena, size) -> ptr
        // Header: [capacity:8][used:8], data at handle+16
        if (call->name == "arenaAlloc" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int aReg = emitExpr(call->args[0].get());
            int sReg = emitExpr(call->args[1].get());
            // Handle must be in rbx(3), size spilled to rcx(1); never live in rax
            if (aReg == 0) {
                if (sReg == 3) { emitMovReg(2, 3); sReg = 2; }
                emitMovReg(3, 0); aReg = 3;
            } else if (sReg == 3) {
                int tmp = (aReg == 1) ? 2 : 1;
                emitMovReg(tmp, 3); sReg = tmp;
                emitMovReg(3, aReg); freeReg(aReg); aReg = 3;
            } else if (sReg == 0) {
                int tmp = (aReg == 2) ? 1 : 2;
                emitMovReg(tmp, 0); sReg = tmp;
                if (aReg != 3) { emitMovReg(3, aReg); freeReg(aReg); }
                aReg = 3;
            } else {
                if (aReg != 3) { emitMovReg(3, aReg); freeReg(aReg); }
                aReg = 3;
            }
            // Force size into rcx(1) so rdx(2) is free for capacity
            if (sReg == 2) { emitMovReg(1, 2); sReg = 1; }

            int failLabel = newLabel();
            int doneLabel = newLabel();

            // Bounds check: rax = used[+8], rdx = capacity[+0]
            emitLoadQwordDisp8(2, 3, 0);   // rdx = [rbx+0] = capacity
            emitLoadQwordDisp8(0, 3, 8);   // rax = [rbx+8] = used
            emitAdd(0, sReg);              // rax = used + size (newUsed)
            // Guard 1: carry from (used + size) means overflow -> fail
            emit8(0x0F); emit8(0x82);      // jc rel32
            jmpFixups.push_back({code.size(), failLabel});
            emit32(0);
            // Guard 2: newUsed > capacity -> fail
            emit8(0x48); emit8(0x39); emit8(0xD0);  // cmp rax, rdx
            emit8(0x0F); emit8(0x87);      // ja rel32
            jmpFixups.push_back({code.size(), failLabel});
            emit32(0);

// Success: [rbx+8] = newUsed, then rax = oldUsed + rbx + 16
            emitStoreQwordDisp8(0, 3, 8);              // [rbx+8] = newUsed
            emitSub(0, sReg);                          // rax -= size -> oldUsed
            emitAdd(0, 3);                             // rax = oldUsed + handle
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(16); // rax += 16 (data offset)
            emitJmp(doneLabel);

            emitLabel(failLabel);
            emitMovRegImm(0, 0);   // return NULL
            emitLabel(doneLabel);

            freeReg(3); freeReg(1);
            regsUsed = 0;
            int r = allocReg();
            if (r < 0) r = 0;
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            // r now holds the result. Restore caller regs, but never reload r.
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r;
        }

        // arenaReset(arena) -> void
        if (call->name == "arenaReset" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int a = emitExpr(call->args[0].get());
            emitMovQwordDisp8Imm32(a, 8, 0);
            freeReg(a);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // arenaDestroy(arena) -> void (free the arena block back to heap)
        if (call->name == "arenaDestroy" && call->args.size() == 1) {
            int r = emitExpr(call->args[0].get());
            if (r != 1) { emitMovReg(1, r); freeReg(r); }
            regsUsed = 0;
            emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0); // lea rax, [rcx-16]
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx
            emit8(0x48); emit8(0x89); emit8(0x05);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emitMovRegImm(0, 0);
            return 0;
        }

        // ============== Pool Allocator Builtins ==============
        // Pool header: [blockSize:8][count:8][nextIdx:8], data at handle+24
        // Monotonic next-index allocator: O(1) alloc, reset to free all

        // poolCreate(blockSize, count) -> handle
        // Header: [blockSize:8][count:8][nextIdx:8], data at handle+24
        if (call->name == "poolCreate" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int bs = emitExpr(call->args[0].get());
            int cnt = emitExpr(call->args[1].get());
            // Save capacity in reg 3 (rbx) and count on stack
            if (bs != 3) { emitMovReg(3, bs); freeReg(bs); }
            if (cnt != 0) { emitMovReg(0, cnt); freeReg(cnt); }
            emit8(0x50); // push rax (count)
            emit8(0x58); // pop rcx (count in rcx)
            // rax = blockSize * count + 24
            emitMovReg(0, 3);
            emitImul(0, 1);  // rax *= rcx (count)
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(24);
            // Push count again for header store after alloc
            emit8(0x51); // push rcx (count)
            emitHeapAlloc(0);  // rax = block pointer
            // Store header fields
            emitStoreQwordDisp8(3, 0, 0);  // [rax+0] = blockSize (rbx)
            emit8(0x59); // pop rcx (count)
            emitStoreQwordDisp8(1, 0, 8);  // [rax+8] = count (rcx)
            emitMovQwordDisp8Imm32(0, 16, 0); // [rax+16] = 0 (nextIdx)
            freeReg(3);
            int r = allocReg();
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // poolAlloc(pool) -> ptr
        if (call->name == "poolAlloc" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int pReg = emitExpr(call->args[0].get());
            // Fix: move handle to rbx to avoid clobbering
            if (pReg != 3) { emitMovReg(3, pReg); freeReg(pReg); }
            regsUsed |= (1 << 3);
            // Load nextIdx into rax
            emitLoadQwordDisp8(0, 3, 16);
            regsUsed |= (1 << 0); // rax holds nextIdx
            // Load count into free reg
            int cReg = allocReg();
            emitLoadQwordDisp8(cReg, 3, 8);
            // cmp rax, cReg (nextIdx vs count)
            emit8(0x48); emit8(0x39); emit8((uint8_t)(0xC0 + (cReg << 3))); // cmp rax, cReg
            freeReg(cReg);
            // jae overflow (return 0)
            int overflow = newLabel();
            emit8(0x0F); emit8(0x83); // jae
            jmpFixups.push_back({code.size(), overflow}); emit32(0);
            // ptr = rbx + 24 + nextIdx * blockSize
            int bsReg = allocReg();
            emitLoadQwordDisp8(bsReg, 3, 0); // bsReg = blockSize
            emit8(0x48); emit8(0x0F); emit8(0xAF); emit8((uint8_t)(0xC0 + bsReg)); // imul rax, bsReg
            freeReg(bsReg);
            emitAdd(0, 3); // rax += rbx (base)
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(24); // rax += 24
            // rax = ptr
            int ptrR = allocReg();
            if (ptrR != 0) { emitMovReg(ptrR, 0); freeReg(0); }
            // nextIdx++: load, inc, store
            emitLoadQwordDisp8(0, 3, 16);
            emit8(0x48); emit8(0xFF); emit8(0xC0); // inc rax
            emitStoreQwordDisp8(0, 3, 16);
            freeReg(3);
            // Jump over overflow handler
            int done = newLabel();
            emitJmp(done);
            emitLabel(overflow);
            // Return 0
            emitMovRegImm(ptrR >= 0 ? ptrR : 0, 0);
            emitLabel(done);
            regsUsed = (uint8_t)(saved & ~(1 << ptrR));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << ptrR));
            int r = allocReg();
            if (ptrR >= 0 && r != ptrR) { emitMovReg(r, ptrR); freeReg(ptrR); }
            return r >= 0 ? r : 0;
        }

        // poolFree(pool, ptr) -> void (no-op, use poolReset to free all)
        if (call->name == "poolFree" && call->args.size() == 2) {
            int r1 = emitExpr(call->args[0].get());
            int r2 = emitExpr(call->args[1].get());
            freeReg(r1); freeReg(r2);
            regsUsed = 1;
            emitMovRegImm(0, 0);
            return 0;
        }

        // poolReset(pool) -> void (reset nextIdx to 0, freeing all blocks)
        if (call->name == "poolReset" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int p = emitExpr(call->args[0].get());
            emitMovQwordDisp8Imm32(p, 16, 0);
            freeReg(p);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // poolDestroy(pool) -> void (no-op)
        if (call->name == "poolDestroy" && call->args.size() == 1) {
            int r = emitExpr(call->args[0].get());
            freeReg(r);
            regsUsed = 1;
            emitMovRegImm(0, 0);
            return 0;
        }

        // ============== Slot Allocator Builtins ==============
        // Header: [maxCount:8][dataSize:8][freeHead:8][aliveCount:8] at handle+0
        // Slots at handle+32, stride = 16 + dataSize
        // Each slot: [generation:8][nextFree:8][data:dataSize]
        // Handle = (generation << 32) | slotIndex
        // rbx(3) = slot handle throughout

        // Helper: compute slotAddr = rbx + 32 + idx*stride into dstReg
        // idxReg has the index. Uses rax, rcx as temps. stride stored in memory.
        // After: dstReg = slotAddr, idxReg destroyed, rax/rcx trashed

        // slotCreate(maxCount, dataSize) -> slot
        if (call->name == "slotCreate" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int mcReg = emitExpr(call->args[0].get());
            int dsReg = emitExpr(call->args[1].get());
            // rbx = maxCount
            if (mcReg != 3) { emitMovReg(3, mcReg); freeReg(mcReg); }
            // rcx = dataSize
            if (dsReg != 1) { emitMovReg(1, dsReg); freeReg(dsReg); }
            // Save dataSize on stack, compute total size in rcx
            emit8(0x51); // push rcx (dataSize)
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16); // stride = dataSize+16
            emitImul(1, 3); // rcx *= maxCount
            // +32 slot header, align to 16, +16 block header
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(32 + 15); // add rcx, 47
            emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0);    // and rcx, -16
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);      // add rcx, 16 (block header)
            // rcx = totalSize
            emit8(0x48); emit8(0x8D); emit8(0x05);
            heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x49); emit8(0x89); emit8(0xC0); // mov r8, rax (save heapArea)
            emit8(0x48); emit8(0x03); emit8(0xCA); // rcx = totalSize + offset = newOffset
            emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
            int scFail = newLabel();
            emit8(0x0F); emit8(0x87);
            jmpFixups.push_back({code.size(), scFail}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x48); emit8(0x29); emit8(0xD1); // sub rcx, rdx (totalSize)
            emit8(0x49); emit8(0x89); emit8(0x4C); emit8(0x10); emit8(8); // mov [r8+rdx+8], totalSize
            emit8(0x49); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [r8+rdx+16]
            int scDone = newLabel();
            emitJmp(scDone);
            emitLabel(scFail);
            emit8(0x48); emit8(0x31); emit8(0xC0);
            emitLabel(scDone);
            // rax = block, stack has [dataSize]
            emit8(0x59); // pop rcx (dataSize)
            emitStoreQwordDisp8(3, 0, 0); // [rax+0] = maxCount
            emitStoreQwordDisp8(1, 0, 8); // [rax+8] = dataSize
            emitMovQwordDisp8Imm32(0, 16, -1); // freeHead = -1
            emitMovQwordDisp8Imm32(0, 24, 0);  // aliveCount = 0
            freeReg(3);
            int r = allocReg();
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // slotSpawn(slot) -> handle
        if (call->name == "slotSpawn" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            regsUsed |= (1 << 3);

            int fullLabel = newLabel();
            int doneLabel = newLabel();
            int freeListLabel = newLabel();

            // rax = freeHead
            emitLoadQwordDisp8(0, 3, 16);
            // cmp rax, -1
            emit8(0x48); emit8(0x83); emit8(0xF8); emit8((uint8_t)(int8_t)-1);
            // jne freeListLabel
            emitJcc("!=", freeListLabel);

            // === SEQUENTIAL PATH (freeHead == -1) ===
            emitLoadQwordDisp8(1, 3, 0);  // rcx = maxCount
            emitLoadQwordDisp8(2, 3, 24); // rdx = aliveCount = idx
            // cmp rdx, rcx; jae full
            emit8(0x48); emit8(0x39); emit8(0xCA); // cmp rdx, rcx
            emitJcc(">=", fullLabel);

            emit8(0x52); // push rdx (save idx)
            // stride = [rbx+8] + 16
            emitLoadQwordDisp8(0, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(16);
            // slotAddr = rbx + idx*stride + 32
            emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD0); // imul rdx, rax
            emitAdd(2, 3);
            emit8(0x48); emit8(0x83); emit8(0xC2); emit8(32);
            // Load gen, bump
            emitLoadQwordDisp8(0, 2, 0); // rax = gen
            emitIncQwordDisp8(2, 0);     // gen++
            // Pack: (gen << 32) | idx
            emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x20); // shl rax, 32
            emit8(0x59); // pop rcx (idx)
            emitAdd(0, 1); // rax += idx
            emitIncQwordDisp8(3, 24); // aliveCount++
            emitJmp(doneLabel);

            // === FREE LIST PATH ===
            emitLabel(freeListLabel);
            // rax = freeHead = idx
            emit8(0x50); // push rax (save idx)
            // stride = [rbx+8] + 16
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // slotAddr = rbx + idx*stride + 32
            emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); // imul rax, rcx
            emitAdd(0, 3);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            // Update free list
            emitLoadQwordDisp8(1, 0, 8); // rcx = nextFree
            emitStoreQwordDisp8(1, 3, 16); // [rbx+16] = nextFree
            // Load gen (no bump)
            emitLoadQwordDisp8(2, 0, 0); // rdx = gen
            // Pack: (gen << 32) | idx
            emit8(0x48); emit8(0xC1); emit8(0xE2); emit8(0x20); // shl rdx, 32
            emit8(0x59); // pop rcx (idx)
            emitMovReg(0, 2); // rax = gen<<32
            emitAdd(0, 1);    // rax += idx
            emitIncQwordDisp8(3, 24); // aliveCount++
            emitJmp(doneLabel);

            // === FULL ===
            emitLabel(fullLabel);
            emit8(0x48); emit8(0x31); emit8(0xC0); // xor rax, rax

            emitLabel(doneLabel);
            freeReg(3);
            int r = allocReg();
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // slotKill(slot, handle) -> void
        if (call->name == "slotKill" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            int hReg = emitExpr(call->args[1].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
            // Extract idx: mov eax, eax
            emit8(0x89); emit8(0xC0);
            emitMovReg(2, 0); // rdx = idx
            // stride = [rbx+8] + 16
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // slotAddr = rbx + idx*stride + 32
            emitImul(0, 1); // rax *= rcx
            emitAdd(0, 3);  // rax += rbx
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            // Bump generation: inc [rax+0]
            emitIncQwordDisp8(0, 0);
            // Push to free list: [rax+8] = oldFreeHead; [rbx+16] = idx
            emitLoadQwordDisp8(1, 3, 16); // rcx = oldFreeHead
            emitStoreQwordDisp8(1, 0, 8); // [rax+8] = oldFreeHead
            emitStoreQwordDisp8(2, 3, 16); // [rbx+16] = idx
            // Dec aliveCount: dec [rbx+24]
            emit8(0x48); emit8(0xFF); emit8(0x4B); emit8(0x18);
            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // slotGetI64(slot, handle, byteOffset) -> int
        if (call->name == "slotGetI64" && call->args.size() == 3) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            int hReg = emitExpr(call->args[1].get());
            int bReg = emitExpr(call->args[2].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
            emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
            if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
            // stride
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // slotAddr+byteOffset
            emitImul(0, 1);
            emitAdd(0, 3);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            emitAdd(0, 2); // + byteOffset
            // Load value
            emitLoadQwordDisp8(1, 0, 0); // rcx = value
            freeReg(3);
            int r = allocReg();
            if (r != 1) { emitMovReg(r, 1); freeReg(1); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // slotSetI64(slot, handle, byteOffset, value) -> void
        if (call->name == "slotSetI64" && call->args.size() == 4) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            int hReg = emitExpr(call->args[1].get());
            int bReg = emitExpr(call->args[2].get());
            int vReg = emitExpr(call->args[3].get());
            // save value BEFORE clobbering rbx with slot handle
            emit8(0x50 + vReg); // push value
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
            emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
            if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
            // stride
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // addr
            emitImul(0, 1);
            emitAdd(0, 3);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            emitAdd(0, 2);
            // Store
            emit8(0x59); // pop rcx (value)
            emitStoreQwordDisp8(1, 0, 0); // [rax] = value
            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // slotGetF32(slot, handle, byteOffset) -> i64 (float bits)
        if (call->name == "slotGetF32" && call->args.size() == 3) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            int hReg = emitExpr(call->args[1].get());
            int bReg = emitExpr(call->args[2].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
            emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
            if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
            // stride
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // addr
            emitImul(0, 1);
            emitAdd(0, 3);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            emitAdd(0, 2);
            // Load float bits: movss xmm0, [rax+0] then movd rcx, xmm0
            int x = allocXmmReg();
            emitMovssXmmFromMem(x, 0, 0);
            emitMovdGpFromXmm(1, x); // rcx = float bits as int
            freeXmmReg(x);
            freeReg(3);
            int r = allocReg();
            if (r != 1) { emitMovReg(r, 1); freeReg(1); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // slotSetF32(slot, handle, byteOffset, value) -> void
        if (call->name == "slotSetF32" && call->args.size() == 4) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            int hReg = emitExpr(call->args[1].get());
            int bReg = emitExpr(call->args[2].get());
            int vReg = emitExpr(call->args[3].get());
            // Convert value to float and park it on the stack BEFORE clobbering
            // rbx with the slot handle (the value may live in rbx itself).
            int x = allocXmmReg();
            emitCvtsi2ss(x, vReg); // xmm = (float)value
            // sub rsp, 4 for float storage
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x04);
            emitMovssXmmToMem(x, 4, 0); // movss [rsp], xmm
            freeXmmReg(x);
            freeReg(vReg);
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
            emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
            if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
            // stride
            emitLoadQwordDisp8(1, 3, 8);
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
            // addr
            emitImul(0, 1);
            emitAdd(0, 3);
            emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
            emitAdd(0, 2);
            // Load float from stack into xmm, store to addr
            int x2 = allocXmmReg();
            emitMovssXmmFromMem(x2, 4, 0); // xmm from [rsp]
            emitMovssXmmToMem(x2, 0, 0);   // movss [rax], xmm
            freeXmmReg(x2);
            // add rsp, 4
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x04);
            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // slotCount(slot) -> int
        if (call->name == "slotCount" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            emitLoadQwordDisp8(0, 3, 24); // rax = aliveCount
            freeReg(3);
            int r = allocReg();
            if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // slotReset(slot) -> void
        if (call->name == "slotReset" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sReg = emitExpr(call->args[0].get());
            if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
            emitMovQwordDisp8Imm32(3, 16, -1); // freeHead = -1
            emitMovQwordDisp8Imm32(3, 24, 0);  // aliveCount = 0
            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // slotDestroy(slot) -> void (free the slot block back to heap)
        if (call->name == "slotDestroy" && call->args.size() == 1) {
            int r = emitExpr(call->args[0].get());
            if (r != 1) { emitMovReg(1, r); freeReg(r); }
            regsUsed = 0;
            emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0); // lea rax, [rcx-16]
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx
            emit8(0x48); emit8(0x89); emit8(0x05);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emitMovRegImm(0, 0);
            return 0;
        }

        // sleep(seconds) -> void
        if (call->name == "sleep" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            if (isFloatExpr(call->args[0].get())) {
                // Float argument: seconds -> ms in FLOAT domain (arg * 1000.0f),
                // then convert to int. Fixes sleep(0.016) = Sleep(16) (was Sleep(0)).
                int x = emitFloatExpr(call->args[0].get());
                int t = allocXmmReg();
                if (t >= 0) {
                    emitMovssXmmImm(t, 1000.0f);
                    emitMulss(x, t);
                    freeXmmReg(t);
                }
                int r = allocReg();
                if (r < 0) r = 0;
                emitCvtss2si(r, x);
                freeXmmReg(x);
                freeReg(0);
                // r = ms; move to rax
                if (r != 0) { emitMovReg(0, r); freeReg(r); }
                if (t < 0) {
                    // no free XMM: fall back to ms = (int)seconds * 1000
                    emit8(0x48); emit8(0x69); emit8(0xC0); emit32(1000); // imul rax, rax, 1000
                }
            } else {
                int sReg = emitExpr(call->args[0].get());
                if (sReg != 0) { emitMovReg(0, sReg); freeReg(sReg); }
                // rax = seconds; ms = rax * 1000
                emit8(0x48); emit8(0x69); emit8(0xC0); emit32(1000); // imul rax, rax, 1000
            }
            // sub rsp, 0x20; mov ecx, eax; call Sleep; add rsp, 0x20
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // sub rsp, 32
            emit8(0x89); emit8(0xC1); // mov ecx, eax
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "Sleep", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 32
            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        // pause() -> void: print message and wait for Enter
        if (call->name == "pause" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;

            // Find or add "Press any key to continue . . .\r\n"
            std::string pauseMsg = "Press any key to continue . . .\r\n";
            int pauseIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == pauseMsg) { pauseIdx = (int)i; break; }
            }
            if (pauseIdx < 0) {
                pauseIdx = (int)stringPool.size();
                stringPool.push_back(pauseMsg);
            }

            // --- Get stdout handle ---
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // sub rsp, 32
            emit8(0xB9); emit32((uint32_t)-11); // mov ecx, -11 (STD_OUTPUT_HANDLE)
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 32
            emit8(0x50); // push rax (save stdout)

            // --- WriteFile(stdout, msg, len, NULL, NULL) ---
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28); // sub rsp, 40
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40); // mov rcx, [rsp+40] = stdout
            emit8(0x48); emit8(0x8D); emit8(0x15); // lea rdx, [rip+msg]
            strFixups.push_back({code.size(), pauseIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32((uint32_t)pauseMsg.size()); // mov r8d, len
            emit8(0x45); emit8(0x31); emit8(0xC9); // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // mov qword [rsp+32], 0
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28); // add rsp, 40

            // --- Get stdin handle ---
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28); // sub rsp, 40
            emit8(0xB9); emit32((uint32_t)-10); // mov ecx, -10 (STD_INPUT_HANDLE)
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28); // add rsp, 40
            // rax = stdin

            // --- ReadFile(stdin, buf, 1, &read, NULL) ---
            // [rsp+0..31] shadow, [rsp+32] overlapped, [rsp+40] buf, [rsp+48] bytesRead
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38); // sub rsp, 56
            emit8(0x48); emit8(0x89); emit8(0xC1); // mov rcx, rax (stdin)
            emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x28); // lea rdx, [rsp+40] buf
            emit8(0x41); emit8(0xB8); emit32(1); // mov r8d, 1
            emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x30); // lea r9, [rsp+48] bytesRead
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // mov qword [rsp+32], 0
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "ReadFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38); // add rsp, 56

            emit8(0x58); // pop rax (balance stdout push)

            freeReg(3);
            regsUsed = (uint8_t)saved;
            reloadRegs();
            emitMovRegImm(0, 0);
            return 0;
        }

        if (call->name == "print" && call->args.size() == 1 && !isLinux) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;

            int newlineIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == "\r\n") { newlineIdx = (int)i; break; }
            }
            if (newlineIdx < 0) {
                newlineIdx = (int)stringPool.size();
                stringPool.push_back("\r\n");
            }

            // --- Step 1: GetStdHandle(STD_OUTPUT_HANDLE = -11) ---
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 32
            emit8(0xB9); emit32((uint32_t)-11);                   // mov ecx, -11
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32
            emit8(0x50);  // push rax  (save handle on stack)

            if (auto strExpr = dynamic_cast<StringExpr*>(call->args[0].get())) {
                int strIdx = -1;
                for (size_t i = 0; i < stringPool.size(); i++) {
                    if (stringPool[i] == strExpr->value) { strIdx = (int)i; break; }
                }
                if (strIdx < 0) {
                    strIdx = (int)stringPool.size();
                    stringPool.push_back(strExpr->value);
                }
                int len = (int)strExpr->value.size();

                // --- WriteFile(handle, str, len, NULL, NULL) ---
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40]
                emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+disp32]
                strFixups.push_back({code.size(), strIdx});
                emit32(0);
                emit8(0x41); emit8(0xB8); emit32(len);  // mov r8d, len
                emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40

                // WriteFile(handle, "\r\n", 2, NULL, NULL)
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40]
                emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+disp32]
                strFixups.push_back({code.size(), newlineIdx});
                emit32(0);
                emit8(0x41); emit8(0xB8); emit32(2);  // mov r8d, 2
                emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

                emit8(0x58);  // pop rax (balance push)

            } else if (isFloatExpr(call->args[0].get())) {
                // --- Float case: decimal string on stack, then WriteFile ---
                int fv = emitFloatExpr(call->args[0].get());
                if (fv < 0) fv = 0;
                if (fv != 0) { emitMovssXmm(0, fv); freeXmmReg(fv); }
                xmmRegsUsed = 1;   // xmm0 = value

                // Reserve 96-byte buffer. The saved handle (pushed earlier) is now
                // at [rsp+0x60].
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x60);  // sub rsp, 96

                // ---- sign detection (absolute value to xmm0 if negative) ----
                int negTrue = newLabel();
                int negDone = newLabel();
                emit8(0x66); emit8(0x0F); emit8(0x7E); emit8(0xC0);   // movd eax, xmm0
                emit8(0xA9); emit32(0x80000000);                       // test eax, 0x80000000
                emitJcc("==", negDone);                                // not negative
                emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x10); emit8(0x01); // byte[rsp+16]=1 (negative flag; 16 is clear of int store at 8..15)
                {   int saved = regsUsed; regsUsed = 0;
                    int m = allocReg(); emitMovRegImm(m, 0x80000000);
                    int mx = allocXmmReg(); if (mx < 0) mx = 0;
                    emitMovdXmmFromGp(mx, m); freeReg(m); regsUsed = (uint8_t)saved;
                    emitXorps(0, mx); freeXmmReg(mx);
                }
                emitJmp(negTrue);
                emitLabel(negDone);
                emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x10); emit8(0x00); // byte[rsp+16]=0
                emitLabel(negTrue);
                // xmm0 = |value|; byte[rsp+16] = negative flag

                // ---- integer part: rax = trunc(|value|) ----
                emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xC0); // cvttss2si rax, xmm0 (truncate)
                emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x08); // [rsp+8]=int

                // ---- convert integer digits into buffer (r10=dst end, r8d=count) ----
                int izero = newLabel();
                emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax, rax
                emitJcc("!=", izero);
                emit8(0x49); emit8(0x89); emit8(0xE2);               // r10 = rsp
                emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1E);  // r10 += 30 (headroom below for '-')
                emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x30);  // byte[r10]='0'
                emit8(0x41); emit8(0xB8); emit8(0x01); emit8(0x00); emit8(0x00); emit8(0x00); // r8d=1
                int iafter = newLabel();
                emitJmp(iafter);
                emitLabel(izero);
                emit8(0x49); emit8(0x89); emit8(0xE2);               // r10 = rsp
                emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1E);  // r10 += 30 (integer digits land near middle, leaving room for fraction)
                emit8(0x45); emit8(0x31); emit8(0xC0);               // r8d = 0
                emit8(0xB9); emit8(0x0A); emit8(0x00); emit8(0x00); emit8(0x00); // ecx=10
                int iloop = newLabel();
                emitLabel(iloop);
                emit8(0x48); emit8(0x31); emit8(0xD2);               // edx=0
                emit8(0x48); emit8(0xF7); emit8(0xF1);               // div rcx
                emit8(0x80); emit8(0xC2); emit8(0x30);               // dl += '0'
                emit8(0x49); emit8(0xFF); emit8(0xCA);               // r10--
                emit8(0x41); emit8(0x88); emit8(0x12);               // [r10]=dl
                emit8(0x41); emit8(0xFF); emit8(0xC0);               // r8d++
                emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax
                emitJcc("!=", iloop);
                emitLabel(iafter);

                // ---- fraction: frac = |value| - (float)int ----
                emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08); // rax=[rsp+8]
                emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xC8); // cvtsi2ss xmm1, rax
                emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC1);             // subss xmm0, xmm1 (frac)
                int noFrac = newLabel();
                emitMovssXmmImm(1, 0.0f);                                       // xmm1 = 0.0
                emit8(0x0F); emit8(0x2E); emit8(0xC1);                          // ucomiss xmm0, xmm1
                emitJcc("==", noFrac);
                // write '.'
                emit8(0x4B); emit8(0x8D); emit8(0x04); emit8(0x02); // lea rax, [r10+r8] (dst)
                emit8(0xC6); emit8(0x00); emit8(0x2E);              // byte[rax]='.'
                emit8(0x41); emit8(0xFF); emit8(0xC0);              // r8d++
                emitMovssXmmImm(2, 10.0f);                          // xmm2 = 10.0
                // decimal digit loop, up to 4 digits
                emit8(0x41); emit8(0xBE); emit8(0x04); emit8(0x00); emit8(0x00); emit8(0x00); // r14d=4 (max)
                int fTop = newLabel();
                int fDone = newLabel();
                emitLabel(fTop);
                emit8(0x4B); emit8(0x8D); emit8(0x04); emit8(0x02);             // lea rax,[r10+r8]
                emit8(0xF3); emit8(0x0F); emit8(0x59); emit8(0xC2);             // mulss xmm0,xmm2 (*10)
                emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xD0); // cvttss2si rdx, xmm0 (digit, truncate)
                emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xDA); // cvtsi2ss xmm3, rdx
                emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC3);             // subss xmm0,xmm3
                emit8(0x80); emit8(0xC2); emit8(0x30);                         // dl += '0'
                emit8(0x88); emit8(0x10);                                       // byte[rax]=dl
                emit8(0x41); emit8(0xFF); emit8(0xC0);                         // r8d++
                emit8(0x41); emit8(0xFF); emit8(0xCE);                         // r14d--
                emit8(0x45); emit8(0x85); emit8(0xF6);                         // test r14d
                emitJcc("==", fDone);
                emit8(0x0F); emit8(0x2E); emit8(0xC1);                         // ucomiss xmm0, xmm1
                emitJcc("!=", fTop);
                emitLabel(fDone);
                emitLabel(noFrac);

                // ---- prepend '-' if negative ----
                int noNeg = newLabel();
                emit8(0x80); emit8(0x7C); emit8(0x24); emit8(0x10); emit8(0x00); // cmp byte[rsp+16],0
                emitJcc("==", noNeg);
                emit8(0x49); emit8(0xFF); emit8(0xCA);               // r10--
                emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x2D);  // byte[r10]='-'
                emit8(0x41); emit8(0xFF); emit8(0xC0);               // r8d++
                emitLabel(noNeg);

                // ---- WriteFile(handle, r10, r8d, NULL, NULL) ----
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(136); // rcx=[rsp+136] (handle)
                emit8(0x4C); emit8(0x89); emit8(0xD2);               // rdx = r10
                emit8(0x45); emit8(0x31); emit8(0xC9);               // r9d=0
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

                // ---- WriteFile(handle, "\r\n", 2, NULL, NULL) ----
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(136); // rcx=[rsp+136] (handle)
                emit8(0x48); emit8(0x8D); emit8(0x15);
                strFixups.push_back({code.size(), newlineIdx});
                emit32(0);
                emit8(0x41); emit8(0xB8); emit32(2);
                emit8(0x45); emit8(0x31); emit8(0xC9);
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x60);  // add rsp, 96 (buffer)
                emit8(0x58);  // pop rax (balance push)

            } else {
                // --- Int or JSON-record case ---
                int exprReg = emitExpr(call->args[0].get());
                if (exprReg != 0) { emitMovReg(0, exprReg); freeReg(exprReg); }
                else freeReg(0);

                // If the value points at a 'ZJSN' record (http_json result),
                // print the JSON pretty-printed (indented, like a JSON
                // viewer on a website). Records exist only when http_json is
                // used and always live in the fixed NET_JSON buffer, so the
                // check is an exact address-range test against that buffer —
                // no size heuristic (a large int like 84904 must never be
                // treated as a pointer).
                int notJson = newLabel();
                int jsonDone = newLabel();
                if (httpGetUsed) {
                    emit8(0x49); emit8(0x89); emit8(0xC3);  // mov r11, rax
                    emit8(0x4C); emit8(0x8D); emit8(0x15);  // lea r10, [rip+disp32]
                    netFixups.push_back({code.size(), NET_JSON}); emit32(0);  // r10 = record base
                    emit8(0x4D); emit8(0x29); emit8(0xD3);  // sub r11, r10
                    emit8(0x41); emit8(0x81); emit8(0xFB); emit32(NET_JSON_RECORD_SIZE);  // cmp r11d, recordSize
                    emit8(0x0F); emit8(0x83);  // jae notJson (outside the record)
                    jmpFixups.push_back({code.size(), notJson}); emit32(0);
                    emit8(0x4C); emit8(0x8B); emit8(0x50); emit8(0x08);  // mov r10, [rax+8]
                    emit8(0x41); emit8(0x81); emit8(0xFA); emit32(0x4E534A5A);  // cmp r10d, 'ZJSN'
                    emit8(0x0F); emit8(0x85);  // jne notJson
                    jmpFixups.push_back({code.size(), notJson}); emit32(0);
                } else {
                    emitJmp(notJson);
                }

                // ---- pretty-print the JSON record ----
                auto findOrAddStr = [&](const std::string& s) -> int {
                    for (size_t i = 0; i < stringPool.size(); i++)
                        if (stringPool[i] == s) return (int)i;
                    stringPool.push_back(s);
                    return (int)stringPool.size() - 1;
                };
                int obIdx = findOrAddStr("{");
                int cbIdx = findOrAddStr("}");
                int obrIdx = findOrAddStr("[");
                int cbrIdx = findOrAddStr("]");
                int commaIdx = findOrAddStr(",");
                int colonIdx = findOrAddStr(": ");
                int indentIdx = findOrAddStr("  ");

                // WriteFile(handle=r15, "str", len, NULL, NULL)
                auto emitWriteStr = [&](int strIdx, int len) {
                    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);  // sub rsp, 48 (16-aligned call)
                    emit8(0x4C); emit8(0x89); emit8(0xF9);  // mov rcx, r15
                    emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+disp32]
                    strFixups.push_back({code.size(), strIdx});
                    emit32(0);
                    emit8(0x41); emit8(0xB8); emit32((uint32_t)len);  // mov r8d, len
                    emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
                    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                    emit8(0xFF); emit8(0x15);
                    importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                    emit32(0);
                    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 48
                };
                // WriteFile(handle=r15, rdi, rsi-rdi, NULL, NULL)
                auto emitWriteRange = [&]() {
                    emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi
                    emit8(0x48); emit8(0x29); emit8(0xF9);  // sub rcx, rdi (len)
                    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);  // sub rsp, 48 (16-aligned call)
                    emit8(0x49); emit8(0x89); emit8(0xC8);  // mov r8, rcx
                    emit8(0x4C); emit8(0x89); emit8(0xF9);  // mov rcx, r15
                    emit8(0x48); emit8(0x89); emit8(0xFA);  // mov rdx, rdi
                    emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
                    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                    emit8(0xFF); emit8(0x15);
                    importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                    emit32(0);
                    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 48
                };
                // write 2 spaces per indent level (level in r14)
                auto emitIndent = [&]() {
                    int indLoop = newLabel();
                    int indDone = newLabel();
                    emit8(0x4C); emit8(0x89); emit8(0xF3);  // mov rbx, r14 (indent counter)
                    emitLabel(indLoop);
                    emit8(0x48); emit8(0x85); emit8(0xDB);  // test rbx, rbx
                    emit8(0x0F); emit8(0x84);  // jz indDone
                    jmpFixups.push_back({code.size(), indDone}); emit32(0);
                    emitWriteStr(indentIdx, 2);
                    emit8(0x48); emit8(0xFF); emit8(0xCB);  // dec rbx
                    emitJmp(indLoop);
                    emitLabel(indDone);
                };

                // setup: r15=handle, rsi=json text, r13=end, r14=indent
                emit8(0x4C); emit8(0x8B); emit8(0x3C); emit8(0x24);  // mov r15, [rsp]
                emit8(0x56);  // push rsi
                emit8(0x57);  // push rdi
                emit8(0x41); emit8(0x55);  // push r13
                emit8(0x41); emit8(0x56);  // push r14
                emit8(0x41); emit8(0x57);  // push r15
                emit8(0x48); emit8(0x8D); emit8(0x70); emit8(0x0C);  // lea rsi, [rax+12]
                emit8(0x44); emit8(0x8B); emit8(0x68); emit8(0x04);  // mov r13d, [rax+4]
                emit8(0x49); emit8(0x01); emit8(0xF5);  // add r13, rsi
                emit8(0x45); emit8(0x31); emit8(0xF6);  // xor r14d, r14d

                int jsonLoop = newLabel();
                int restoreStack = newLabel();
                int lblOpenBrace = newLabel();
                int lblOpenBracket = newLabel();
                int lblCloseBrace = newLabel();
                int lblCloseBracket = newLabel();
                int lblComma = newLabel();
                int lblColon = newLabel();
                int lblString = newLabel();
                int lblNumber = newLabel();

                emitLabel(jsonLoop);
                emit8(0x4C); emit8(0x39); emit8(0xEE);  // cmp rsi, r13
                emit8(0x0F); emit8(0x83);  // jae restoreStack (restore regs, then jsonDone)
                jmpFixups.push_back({code.size(), restoreStack}); emit32(0);
                emit8(0x48); emit8(0x0F); emit8(0xB6); emit8(0x06);  // movzx rax, byte [rsi]
                emit8(0x3C); emit8('{');
                emit8(0x0F); emit8(0x84);  // je lblOpenBrace
                jmpFixups.push_back({code.size(), lblOpenBrace}); emit32(0);
                emit8(0x3C); emit8('[');
                emit8(0x0F); emit8(0x84);  // je lblOpenBracket
                jmpFixups.push_back({code.size(), lblOpenBracket}); emit32(0);
                emit8(0x3C); emit8('}');
                emit8(0x0F); emit8(0x84);  // je lblCloseBrace
                jmpFixups.push_back({code.size(), lblCloseBrace}); emit32(0);
                emit8(0x3C); emit8(']');
                emit8(0x0F); emit8(0x84);  // je lblCloseBracket
                jmpFixups.push_back({code.size(), lblCloseBracket}); emit32(0);
                emit8(0x3C); emit8(',');
                emit8(0x0F); emit8(0x84);  // je lblComma
                jmpFixups.push_back({code.size(), lblComma}); emit32(0);
                emit8(0x3C); emit8(':');
                emit8(0x0F); emit8(0x84);  // je lblColon
                jmpFixups.push_back({code.size(), lblColon}); emit32(0);
                emit8(0x3C); emit8('"');
                emit8(0x0F); emit8(0x84);  // je lblString
                jmpFixups.push_back({code.size(), lblString}); emit32(0);
                emitJmp(lblNumber);

                emitLabel(lblOpenBrace);
                emitWriteStr(obIdx, 1);
                emitWriteStr(newlineIdx, 2);
                emitIndent();
                emit8(0x41); emit8(0xFF); emit8(0xC6);  // inc r14d
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                emitLabel(lblOpenBracket);
                emitWriteStr(obrIdx, 1);
                emitWriteStr(newlineIdx, 2);
                emitIndent();
                emit8(0x41); emit8(0xFF); emit8(0xC6);  // inc r14d
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                emitLabel(lblCloseBrace);
                emitWriteStr(newlineIdx, 2);
                emit8(0x41); emit8(0xFF); emit8(0xCE);  // dec r14d
                emitIndent();
                emitWriteStr(cbIdx, 1);
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                emitLabel(lblCloseBracket);
                emitWriteStr(newlineIdx, 2);
                emit8(0x41); emit8(0xFF); emit8(0xCE);  // dec r14d
                emitIndent();
                emitWriteStr(cbrIdx, 1);
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                emitLabel(lblComma);
                emitWriteStr(commaIdx, 1);
                emitWriteStr(newlineIdx, 2);
                emitIndent();
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                emitLabel(lblColon);
                emitWriteStr(colonIdx, 2);
                emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                emitJmp(jsonLoop);

                // string token: copy [start .. closing quote] verbatim
                emitLabel(lblString);
                {
                    int strScan = newLabel();
                    int strEnd = newLabel();
                    int strEsc = newLabel();
                    emit8(0x48); emit8(0x89); emit8(0xF7);  // mov rdi, rsi
                    emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                    emitLabel(strScan);
                    emit8(0x4C); emit8(0x39); emit8(0xEE);  // cmp rsi, r13
                    emit8(0x0F); emit8(0x83);  // jae strEnd
                    jmpFixups.push_back({code.size(), strEnd}); emit32(0);
                    emit8(0x48); emit8(0x0F); emit8(0xB6); emit8(0x06);  // movzx rax, [rsi]
                    emit8(0x3C); emit8('\\');
                    emit8(0x0F); emit8(0x84);  // je strEsc
                    jmpFixups.push_back({code.size(), strEsc}); emit32(0);
                    emit8(0x3C); emit8('"');
                    emit8(0x0F); emit8(0x84);  // je strEnd
                    jmpFixups.push_back({code.size(), strEnd}); emit32(0);
                    emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                    emitJmp(strScan);
                    emitLabel(strEsc);
                    emit8(0x48); emit8(0x83); emit8(0xC6); emit8(0x02);  // add rsi, 2
                    emitJmp(strScan);
                    emitLabel(strEnd);
                    emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi (past closing quote)
                    emitWriteRange();
                    emitJmp(jsonLoop);
                }

                // number token: copy until , } ] { [
                emitLabel(lblNumber);
                {
                    int numScan = newLabel();
                    int numEnd = newLabel();
                    emit8(0x48); emit8(0x89); emit8(0xF7);  // mov rdi, rsi
                    emitLabel(numScan);
                    emit8(0x4C); emit8(0x39); emit8(0xEE);  // cmp rsi, r13
                    emit8(0x0F); emit8(0x83);  // jae numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x48); emit8(0x0F); emit8(0xB6); emit8(0x06);  // movzx rax, [rsi]
                    emit8(0x3C); emit8(',');
                    emit8(0x0F); emit8(0x84);  // je numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x3C); emit8('}');
                    emit8(0x0F); emit8(0x84);  // je numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x3C); emit8(']');
                    emit8(0x0F); emit8(0x84);  // je numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x3C); emit8('{');
                    emit8(0x0F); emit8(0x84);  // je numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x3C); emit8('[');
                    emit8(0x0F); emit8(0x84);  // je numEnd
                    jmpFixups.push_back({code.size(), numEnd}); emit32(0);
                    emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
                    emitJmp(numScan);
                    emitLabel(numEnd);
                    emitWriteRange();
                    emitJmp(jsonLoop);
                }

                // newline + restore + balance handle push
                emitLabel(restoreStack);
                emitWriteStr(newlineIdx, 2);
                emit8(0x41); emit8(0x5F);  // pop r15
                emit8(0x41); emit8(0x5E);  // pop r14
                emit8(0x41); emit8(0x5D);  // pop r13
                emit8(0x5F);  // pop rdi
                emit8(0x5E);  // pop rsi
                emit8(0x58);  // pop rax (balance handle push)
                emitJmp(jsonDone);

                emitLabel(notJson);
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 32 (buffer)

                // Check for negative number
                int isNegLabel = newLabel();
                int notNegLabel = newLabel();
                if (wordSize == 64) emit8(0x48);
                emit8(0x85); emit8(0xC0);  // test rax, rax
                emit8(0x0F); emit8(0x88);  // js isNegLabel (jump if sign flag set)
                jmpFixups.push_back({code.size(), isNegLabel});
                emit32(0);
                emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x0A); emit8(0x00);  // mov byte [rsp+10], 0 (positive flag)
                emitJmp(notNegLabel);
                emitLabel(isNegLabel);
                emit8(0x48); emit8(0xF7); emit8(0xD8);  // neg rax
                emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x0A); emit8(0x01);  // mov byte [rsp+10], 1 (negative flag)
                emitLabel(notNegLabel);

                int notZero = newLabel();
                if (wordSize == 64) emit8(0x48);
                emit8(0x85); emit8(0xC0);  // test rax, rax
                emit8(0x0F); emit8(0x85);
                jmpFixups.push_back({code.size(), notZero});
                emit32(0);
                emit8(0xC6); emit8(0x04); emit8(0x24); emit8(0x30);  // mov byte [rsp], '0'
                emit8(0x41); emit8(0xB8); emit8(0x01); emit8(0x00); emit8(0x00); emit8(0x00);  // mov r8d, 1
                emit8(0x49); emit8(0x89); emit8(0xE2);  // mov r10, rsp
                int afterZero = newLabel();
                emitJmp(afterZero);
                emitLabel(notZero);

                emit8(0x49); emit8(0x89); emit8(0xE2);  // mov r10, rsp
                emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1F);  // add r10, 31
                emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d
                emit8(0xB9); emit8(0x0A); emit8(0x00); emit8(0x00); emit8(0x00);  // mov ecx, 10

                int convLoop = newLabel();
                emitLabel(convLoop);
                emit8(0x48); emit8(0x31); emit8(0xD2);  // xor edx, edx
                emit8(0x48); emit8(0xF7); emit8(0xF1);  // div rcx
                emit8(0x80); emit8(0xC2); emit8(0x30);  // add dl, '0'
                emit8(0x49); emit8(0xFF); emit8(0xCA);  // dec r10
                emit8(0x41); emit8(0x88); emit8(0x12);  // mov [r10], dl
                emit8(0x41); emit8(0xFF); emit8(0xC0);  // inc r8d
                emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
                emit8(0x0F); emit8(0x85);
                jmpFixups.push_back({code.size(), convLoop});
                emit32(0);

                // If was negative, prepend '-' before the digits
                int notNegPrint = newLabel();
                emit8(0x80); emit8(0x7C); emit8(0x24); emit8(0x0A); emit8(0x01);  // cmp byte [rsp+10], 1
                emit8(0x75);  // jne notNegPrint
                int jnePos2 = (int)code.size();
                emit8(0x00);  // placeholder
                emit8(0x49); emit8(0xFF); emit8(0xCA);  // dec r10
                emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x2D);  // mov byte [r10], '-'
                emit8(0x41); emit8(0xFF); emit8(0xC0);  // inc r8d
                emitLabel(notNegPrint);
                code[jnePos2] = (uint8_t)((int)code.size() - jnePos2 - 1);

                emitLabel(afterZero);

                // WriteFile(handle, r10, r8d, NULL, NULL)
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);  // sub rsp, 48 (16-aligned call)
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(80);
                emit8(0x4C); emit8(0x89); emit8(0xD2);  // mov rdx, r10
                emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 48

                // WriteFile(handle, "\r\n", 2, NULL, NULL)
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);  // sub rsp, 48 (16-aligned call)
                emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(80);
                emit8(0x48); emit8(0x8D); emit8(0x15);
                strFixups.push_back({code.size(), newlineIdx});
                emit32(0);
                emit8(0x41); emit8(0xB8); emit32(2);
                emit8(0x45); emit8(0x31); emit8(0xC9);
                emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
                emit32(0);
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 48

                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32 (buffer)
                emit8(0x58);  // pop rax (balance push)
                emitLabel(jsonDone);
            }

            regsUsed = (uint8_t)saved;
            reloadRegs();
            return 0;
        }

        // ============== Create:File Builtin ==============
        // Create:File("name", "content"[, "path"]) — создаёт файл с указанным
        // содержимым. Необязательный третий аргумент — путь к файлу (по умолчанию
        // "." — текущий каталог). Содержимое ограничено 100 символами (без учёта
        // пробелов).
        if (call->name == "Create:File" && (call->args.size() == 2 || call->args.size() == 3)) {
            auto nameExpr = dynamic_cast<StringExpr*>(call->args[0].get());
            auto contentExpr = dynamic_cast<StringExpr*>(call->args[1].get());
            auto pathExpr = call->args.size() == 3
                                ? dynamic_cast<StringExpr*>(call->args[2].get()) : nullptr;
            if (!nameExpr || !contentExpr || (call->args.size() == 3 && !pathExpr)) {
                std::cerr << "Error: Create:File requires string literals: "
                          << "Create:File(\"name\", \"content\"[, \"path\"])\n";
                throw std::runtime_error("Create:File bad arguments");
            }
            int nonspace = 0;
            for (char ch : contentExpr->value) {
                if (ch != ' ') nonspace++;
            }
            if (nonspace > 100) {
                std::cerr << "Error: Create:File content is limited to 100 characters "
                          << "(not counting spaces)\n";
                throw std::runtime_error("Create:File content too long");
            }

            std::string fullPath = nameExpr->value;
            if (pathExpr && !pathExpr->value.empty()) {
                std::string dir = pathExpr->value;
                while (!dir.empty() && (dir.back() == '\\' || dir.back() == '/')) dir.pop_back();
                if (!dir.empty() && dir != ".") fullPath = dir + "\\" + fullPath;
            }

            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;

            auto findOrAddStr = [&](const std::string& s) -> int {
                for (size_t i = 0; i < stringPool.size(); i++) {
                    if (stringPool[i] == s) return (int)i;
                }
                stringPool.push_back(s);
                return (int)stringPool.size() - 1;
            };
            int nameIdx = findOrAddStr(fullPath);
            int contentIdx = findOrAddStr(contentExpr->value);
            int len = (int)contentExpr->value.size();

            // 1) CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
            // 7 params: 3 stack args at [rsp+0x20..0x37]; 0x40 keeps rsp 16-aligned at the call
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40);  // sub rsp, 64
            emit8(0x48); emit8(0x8D); emit8(0x0D);  // lea rcx, [rip+name]
            strFixups.push_back({code.size(), nameIdx});
            emit32(0);
            emit8(0xBA); emit32(0x40000000);        // mov edx, GENERIC_WRITE
            emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d (share mode 0)
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d (security NULL)
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);    // [rsp+0x20] CREATE_ALWAYS
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80); // [rsp+0x28] FILE_ATTRIBUTE_NORMAL
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);    // [rsp+0x30] NULL template
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x40);  // add rsp, 64
            emit8(0x50);  // push rax (save handle on stack)

            // 2) WriteFile(handle, content, len, NULL, NULL)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40] (handle)
            emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+content]
            strFixups.push_back({code.size(), contentIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32(len);  // mov r8d, len
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);  // [rsp+0x20] NULL
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40

            // 3) CloseHandle(handle)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40] (handle)
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40

            emit8(0x58);  // pop rax (balance push)

            regsUsed = (uint8_t)saved;
            reloadRegs();
            return 0;
        }

        // ============== Shared Memory Builtins ==============
        // peek(addr) — reads a 64-bit value from the given address
        if (call->name == "peek" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x48); emit8(0x8B); emit8(0x00); // mov rax, [rax]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // poke(addr, val) — writes val (64-bit) to the given address
        if (call->name == "poke" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (val)
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (addr)
            emit8(0x41); emit8(0x58);  // pop r8 (addr)
            emit8(0x41); emit8(0x59);  // pop r9 (val)
            emit8(0x4D); emit8(0x89); emit8(0x08); // mov [r8], r9
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }

        // ============== Byte-width Memory Access Builtins ==============
        // peek8(addr) — reads an 8-bit value (zero-extended)
        if (call->name == "peek8" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x0F); emit8(0xB6); emit8(0x00); // movzx eax, byte ptr [rax]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // peek16(addr) — reads a 16-bit value (zero-extended)
        if (call->name == "peek16" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x0F); emit8(0xB7); emit8(0x00); // movzx eax, word ptr [rax]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // peek32(addr) — reads a 32-bit value (zero-extended)
        if (call->name == "peek32" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x8B); emit8(0x00); // mov eax, [rax]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // poke8(addr, val) — writes val (low 8 bits) to the given address
        if (call->name == "poke8" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (val)
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x5A);  // pop rdx (val)
            emit8(0x88); emit8(0x10); // mov [rax], dl
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // poke16(addr, val) — writes val (low 16 bits) to the given address
        if (call->name == "poke16" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (val)
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x5A);  // pop rdx (val)
            emit8(0x66); emit8(0x89); emit8(0x10); // mov [rax], dx
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }
        // poke32(addr, val) — writes val (low 32 bits) to the given address
        if (call->name == "poke32" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (val)
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x5A);  // pop rdx (val)
            emit8(0x89); emit8(0x10); // mov [rax], edx
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            return 0;
        }

        // ============== Network Builtins (WinINet, Windows-only) ==============
        // http_get(url) -> int. Sends an HTTP GET request to the given URL and
        // returns a pointer to the response record, or 0 on failure:
        //   [+0] status   : int (HTTP status code, e.g. 200)
        //   [+4] bodyLen  : int (bytes of body written to the buffer)
        //   [+8] body     : raw body bytes (up to NET_BUFFER_SIZE)
        // http_last_error() -> int. Returns the last WinINet / GetLastError code.
        if (call->name == "http_get" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            httpGetUsed = true;

            // rcx = URL (string literal address)
            int urlReg = emitExpr(call->args[0].get());
            if (urlReg != 1) { emitMovReg(1, urlReg); freeReg(urlReg); }
            else freeReg(1);

            auto emitImportCall = [&](const char* func, const char* dll) {
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), func, dll});
                emit32(0);
            };

            // Save callee-saved registers we use (allocator only ever touches rax/rcx/rdx/rbx).
            emit8(0x57);  // push rdi
            emit8(0x56);  // push rsi
            emit8(0x41); emit8(0x54);  // push r12
            emit8(0x48); emit8(0x89); emit8(0xCE);  // mov rsi, rcx (URL)

            int openFailed = newLabel();
            int openUrlFailed = newLabel();
            int readFailed = newLabel();
            int readDone = newLabel();
            int readLoop = newLabel();
            int done = newLabel();

            // InternetOpenA("Zenith", 0, NULL, NULL, 0) -> hInternet
            int agentIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == "Zenith") { agentIdx = (int)i; break; }
            }
            if (agentIdx < 0) {
                agentIdx = (int)stringPool.size();
                stringPool.push_back("Zenith");
            }
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x8D); emit8(0x0D);  // lea rcx, [rip+disp32]
            strFixups.push_back({code.size(), agentIdx});
            emit32(0);
            emit8(0x31); emit8(0xD2);  // xor edx, edx (INTERNET_OPEN_TYPE_PRECONFIG)
            emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("InternetOpenA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), openFailed}); emit32(0);  // jz openFailed
            emit8(0x48); emit8(0x89); emit8(0xC7);  // mov rdi, rax (hInternet)

            // Request uncompressed bodies: wine/wininet adds
            // "Accept-Encoding: gzip" by default, and gzip responses make
            // http_json (title/meta parsing) see binary data. Asking for
            // "identity" makes servers return the plain HTML.
            const char* aeHeader = "Accept-Encoding: identity";
            int aeIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == aeHeader) { aeIdx = (int)i; break; }
            }
            if (aeIdx < 0) {
                aeIdx = (int)stringPool.size();
                stringPool.push_back(aeHeader);
            }
            // InternetOpenUrlA(hInternet, url, "Accept-Encoding: identity", 25, RELOG|NO_CACHE_WRITE, 0)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x48);  // sub rsp, 72 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi
            emit8(0x48); emit8(0x89); emit8(0xF2);  // mov rdx, rsi
            emit8(0x4C); emit8(0x8D); emit8(0x05);  // lea r8, [rip+disp32]
            strFixups.push_back({code.size(), aeIdx});
            emit32(0);
            emit8(0x41); emit8(0xB9); emit32((uint32_t)strlen(aeHeader));  // mov r9d, header len
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0x84000000);
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
            emitImportCall("InternetOpenUrlA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x48);  // add rsp, 72
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), openUrlFailed}); emit32(0);  // jz openUrlFailed
            emit8(0x48); emit8(0x89); emit8(0xC6);  // mov rsi, rax (hUrl)

            // HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE=19, &status, &statusLen, NULL)
            emit8(0x4C); emit8(0x8D); emit8(0x05);  // lea r8, [rip+disp32]
            netFixups.push_back({code.size(), NET_STATUS}); emit32(0);
            emit8(0x41); emit8(0xC7); emit8(0x00); emit32(0);  // mov dword [r8], 0
            emit8(0x4C); emit8(0x8D); emit8(0x0D);  // lea r9, [rip+disp32]
            netFixups.push_back({code.size(), NET_STATUS_LEN}); emit32(0);
            emit8(0x41); emit8(0xC7); emit8(0x01); emit32(4);  // mov dword [r9], 4
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0xBA); emit32(0x20000013);  // mov edx, HTTP_QUERY_STATUS_CODE | FLAG_NUMBER
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("HttpQueryInfoA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56

            // Record header: buffer[0..3] = status code
            emit8(0x48); emit8(0x8B); emit8(0x05);
            netFixups.push_back({code.size(), NET_STATUS}); emit32(0);  // rax = status
            emit8(0x4C); emit8(0x8D); emit8(0x15);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // r10 = buffer
            emit8(0x41); emit8(0x89); emit8(0x02);  // mov dword [r10], eax

            // Read loop: total (r12) = 0; while (total < BUFSIZE-8) { read 4096; }
            emit8(0x45); emit8(0x31); emit8(0xE4);  // xor r12d, r12d
            emitLabel(readLoop);
            emit8(0x49); emit8(0x81); emit8(0xFC); emit32(NET_BUFFER_SIZE - 8);  // cmp r12, BUFSIZE-8
            emit8(0x0F); emit8(0x83);
            jmpFixups.push_back({code.size(), readDone}); emit32(0);  // jae readDone
            emit8(0x4C); emit8(0x8D); emit8(0x15);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // r10 = buffer
            emit8(0x4B); emit8(0x8D); emit8(0x54); emit8(0x22); emit8(0x08);  // lea rdx, [r10+r12+8]
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x41); emit8(0xB8); emit32(4096);  // mov r8d, 4096
            emit8(0xB8); emit32(NET_BUFFER_SIZE - 8);  // mov eax, max body size
            emit8(0x44); emit8(0x29); emit8(0xE0);  // sub eax, r12d (bytes left)
            emit8(0x45); emit8(0x39); emit8(0xC0);  // cmp r8d, eax
            emit8(0x44); emit8(0x0F); emit8(0x4F); emit8(0xC0);  // cmovg r8d, eax
            emit8(0x4C); emit8(0x8D); emit8(0x0D);
            netFixups.push_back({code.size(), NET_BYTES_READ}); emit32(0);  // r9 = &bytesRead
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("InternetReadFile", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56
            emit8(0x85); emit8(0xC0);  // test eax, eax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), readFailed}); emit32(0);  // jz readFailed
            emit8(0x48); emit8(0x8B); emit8(0x05);
            netFixups.push_back({code.size(), NET_BYTES_READ}); emit32(0);  // rax = bytesRead
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), readDone}); emit32(0);  // jz readDone
            emit8(0x4C); emit8(0x01); emit8(0xE0);  // add rax, r12
            emit8(0x49); emit8(0x89); emit8(0xC4);  // mov r12, rax
            emitJmp(readLoop);

            emitLabel(readDone);
            emit8(0x4C); emit8(0x89); emit8(0x25);
            netFixups.push_back({code.size(), NET_LEN}); emit32(0);  // store total len (slot)
            emit8(0x4C); emit8(0x8D); emit8(0x15);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // r10 = buffer
            emit8(0x45); emit8(0x89); emit8(0x64); emit8(0x22); emit8(0x04);  // mov [r10+4], r12d
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x8D); emit8(0x05);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // rax = buffer
            emitJmp(done);

            emitLabel(openUrlFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x31); emit8(0xC0);  // xor eax, eax
            emitJmp(done);

            emitLabel(readFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x31); emit8(0xC0);  // xor eax, eax
            emitJmp(done);

            emitLabel(openFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x31); emit8(0xC0);  // xor eax, eax

            emitLabel(done);
            emit8(0x41); emit8(0x5C);  // pop r12
            emit8(0x5E);  // pop rsi
            emit8(0x5F);  // pop rdi

            freeReg(1); freeReg(2); freeReg(3);
            int r = allocReg(); if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }
        if (call->name == "http_last_error" && call->args.empty()) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            httpGetUsed = true;
            emit8(0x48); emit8(0x8B); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // mov rax, [netErr]
            freeReg(1); freeReg(2); freeReg(3);
            int r = allocReg(); if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // ============== http_json(url) ==============
        // Like http_get, but also queries the raw response headers and runs
        // the emitted helper (httpjson_rt.cpp) that fills a 'ZJSN' record:
        //   [+0] status : int (HTTP status code)
        //   [+4] jsonLen: int (bytes of JSON text at [+12])
        //   [+8] magic  : 'ZJSN' (print() detects this and pretty-prints)
        //   [+12] json  : {"status":..,"title":"..","meta":[..],"headers":{..}}
        //   [+12+jsonMax] headLen / [+16+jsonMax] head (raw <head> contents)
        // Returns a pointer to the record, or 0 on failure.
        if (call->name == "http_json" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            httpGetUsed = true;

            // rcx = URL (string literal address)
            int urlReg = emitExpr(call->args[0].get());
            if (urlReg != 1) { emitMovReg(1, urlReg); freeReg(urlReg); }
            else freeReg(1);

            auto emitImportCall = [&](const char* func, const char* dll) {
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), func, dll});
                emit32(0);
            };

            emit8(0x57);  // push rdi
            emit8(0x56);  // push rsi
            emit8(0x41); emit8(0x54);  // push r12
            emit8(0x48); emit8(0x89); emit8(0xCE);  // mov rsi, rcx (URL)

            int openFailed = newLabel();
            int openUrlFailed = newLabel();
            int readFailed = newLabel();
            int readDone = newLabel();
            int readLoop = newLabel();
            int done = newLabel();

            // InternetOpenA("Zenith", 0, NULL, NULL, 0) -> hInternet
            int agentIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == "Zenith") { agentIdx = (int)i; break; }
            }
            if (agentIdx < 0) {
                agentIdx = (int)stringPool.size();
                stringPool.push_back("Zenith");
            }
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x8D); emit8(0x0D);  // lea rcx, [rip+disp32]
            strFixups.push_back({code.size(), agentIdx});
            emit32(0);
            emit8(0x31); emit8(0xD2);  // xor edx, edx (INTERNET_OPEN_TYPE_PRECONFIG)
            emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("InternetOpenA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), openFailed}); emit32(0);  // jz openFailed
            emit8(0x48); emit8(0x89); emit8(0xC7);  // mov rdi, rax (hInternet)

            // Request uncompressed bodies: wine/wininet adds
            // "Accept-Encoding: gzip" by default, and gzip responses make
            // http_json (title/meta parsing) see binary data. Asking for
            // "identity" makes servers return the plain HTML.
            const char* aeHeader = "Accept-Encoding: identity";
            int aeIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == aeHeader) { aeIdx = (int)i; break; }
            }
            if (aeIdx < 0) {
                aeIdx = (int)stringPool.size();
                stringPool.push_back(aeHeader);
            }
            // InternetOpenUrlA(hInternet, url, "Accept-Encoding: identity", 25, RELOG|NO_CACHE_WRITE, 0)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x48);  // sub rsp, 72 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi
            emit8(0x48); emit8(0x89); emit8(0xF2);  // mov rdx, rsi
            emit8(0x4C); emit8(0x8D); emit8(0x05);  // lea r8, [rip+disp32]
            strFixups.push_back({code.size(), aeIdx});
            emit32(0);
            emit8(0x41); emit8(0xB9); emit32((uint32_t)strlen(aeHeader));  // mov r9d, header len
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0x84000000);
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
            emitImportCall("InternetOpenUrlA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x48);  // add rsp, 72
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), openUrlFailed}); emit32(0);  // jz openUrlFailed
            emit8(0x48); emit8(0x89); emit8(0xC6);  // mov rsi, rax (hUrl)

            // HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE=19, &status, &statusLen, NULL)
            emit8(0x4C); emit8(0x8D); emit8(0x05);  // lea r8, [rip+disp32]
            netFixups.push_back({code.size(), NET_STATUS}); emit32(0);
            emit8(0x41); emit8(0xC7); emit8(0x00); emit32(0);  // mov dword [r8], 0
            emit8(0x4C); emit8(0x8D); emit8(0x0D);  // lea r9, [rip+disp32]
            netFixups.push_back({code.size(), NET_STATUS_LEN}); emit32(0);
            emit8(0x41); emit8(0xC7); emit8(0x01); emit32(4);  // mov dword [r9], 4
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0xBA); emit32(0x20000013);  // mov edx, HTTP_QUERY_STATUS_CODE | FLAG_NUMBER
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("HttpQueryInfoA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56

            // HttpQueryInfoA(hUrl, HTTP_QUERY_RAW_HEADERS_CRLF=22, &hdr, &hdrLen, NULL)
            emit8(0x4C); emit8(0x8D); emit8(0x05);  // lea r8, [rip+disp32]
            netFixups.push_back({code.size(), NET_HDR}); emit32(0);
            emit8(0x4C); emit8(0x8D); emit8(0x0D);  // lea r9, [rip+disp32]
            netFixups.push_back({code.size(), NET_HDR_LEN}); emit32(0);
            emit8(0x41); emit8(0xC7); emit8(0x01); emit32(NET_HDR_SIZE);  // mov dword [r9], NET_HDR_SIZE
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0xBA); emit32(22);  // mov edx, HTTP_QUERY_RAW_HEADERS_CRLF
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("HttpQueryInfoA", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56

            // Read loop: total (r12) = 0; while (total < BUFSIZE-8) { read 4096; }
            emit8(0x45); emit8(0x31); emit8(0xE4);  // xor r12d, r12d
            emitLabel(readLoop);
            emit8(0x49); emit8(0x81); emit8(0xFC); emit32(NET_BUFFER_SIZE - 8);  // cmp r12, BUFSIZE-8
            emit8(0x0F); emit8(0x83);
            jmpFixups.push_back({code.size(), readDone}); emit32(0);  // jae readDone
            emit8(0x4C); emit8(0x8D); emit8(0x15);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // r10 = buffer
            emit8(0x4B); emit8(0x8D); emit8(0x54); emit8(0x22); emit8(0x08);  // lea rdx, [r10+r12+8]
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 56 (16-aligned call)
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x41); emit8(0xB8); emit32(4096);  // mov r8d, 4096
            emit8(0xB8); emit32(NET_BUFFER_SIZE - 8);  // mov eax, max body size
            emit8(0x44); emit8(0x29); emit8(0xE0);  // sub eax, r12d (bytes left)
            emit8(0x45); emit8(0x39); emit8(0xC0);  // cmp r8d, eax
            emit8(0x44); emit8(0x0F); emit8(0x4F); emit8(0xC0);  // cmovg r8d, eax
            emit8(0x4C); emit8(0x8D); emit8(0x0D);
            netFixups.push_back({code.size(), NET_BYTES_READ}); emit32(0);  // r9 = &bytesRead
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emitImportCall("InternetReadFile", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 56
            emit8(0x85); emit8(0xC0);  // test eax, eax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), readFailed}); emit32(0);  // jz readFailed
            emit8(0x48); emit8(0x8B); emit8(0x05);
            netFixups.push_back({code.size(), NET_BYTES_READ}); emit32(0);  // rax = bytesRead
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), readDone}); emit32(0);  // jz readDone
            emit8(0x4C); emit8(0x01); emit8(0xE0);  // add rax, r12
            emit8(0x49); emit8(0x89); emit8(0xC4);  // mov r12, rax
            emitJmp(readLoop);

            emitLabel(readDone);
            emit8(0x4C); emit8(0x89); emit8(0x25);
            netFixups.push_back({code.size(), NET_LEN}); emit32(0);  // store total len (slot)

            // Close handles now, while rsi (hUrl) and rdi (hInternet) are still intact.
            // Their return value clobbers rax, so this must happen before the helper result.
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40

            // Call the helper: rcx=status, rdx=bodyLen, rsi=body, r8=headers, rdi=record
            emit8(0x48); emit8(0x8B); emit8(0x0D);
            netFixups.push_back({code.size(), NET_STATUS}); emit32(0);  // rcx = status
            emit8(0x48); emit8(0x8B); emit8(0x15);
            netFixups.push_back({code.size(), NET_LEN}); emit32(0);  // rdx = bodyLen
            emit8(0x48); emit8(0x8D); emit8(0x35);
            netFixups.push_back({code.size(), NET_BUF}); emit32(0);  // rsi = body
            emit8(0x4C); emit8(0x8D); emit8(0x05);
            netFixups.push_back({code.size(), NET_HDR}); emit32(0);  // r8 = raw headers
            emit8(0x48); emit8(0x8D); emit8(0x3D);
            netFixups.push_back({code.size(), NET_JSON}); emit32(0);  // rdi = record

            // Emit the position-independent helper once. The helper body must
            // never be fallen into from the first call site — jump over it and
            // call it, exactly like every later call site does.
            if (!httpJsonHelperEmitted) {
                httpJsonHelperEmitted = true;
                httpJsonHelperLabel = newLabel();
                int afterHelper = newLabel();
                emitJmp(afterHelper);  // skip the helper body
                emitLabel(httpJsonHelperLabel);
                std::vector<uint8_t> helper = buildHttpJsonHelper(NET_JSON_MAX, NET_HEAD_MAX);
                for (uint8_t b : helper) emit8(b);
                emitLabel(afterHelper);
            }
            emit8(0xE8);  // call helper
            jmpFixups.push_back({code.size(), httpJsonHelperLabel});
            emit32(0);
            emit8(0x48);  // mov rax, rdi (helper restores rdi; be explicit anyway)
            emit8(0x89); emit8(0xF8);
            emitJmp(done);

            emitLabel(openUrlFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x31); emit8(0xC0);  // xor eax, eax
            emitJmp(done);

            emitLabel(readFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x48); emit8(0x89); emit8(0xF1);  // mov rcx, rsi (hUrl)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0xF9);  // mov rcx, rdi (hInternet)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("InternetCloseHandle", "wininet.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x31); emit8(0xC0);  // xor eax, eax
            emitJmp(done);

            emitLabel(openFailed);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40 (16-aligned call)
            emitImportCall("GetLastError", "kernel32.dll");
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40
            emit8(0x48); emit8(0x89); emit8(0x05);
            netFixups.push_back({code.size(), NET_ERR}); emit32(0);  // store error
            emit8(0x31); emit8(0xC0);  // xor eax, eax

            emitLabel(done);
            emit8(0x41); emit8(0x5C);  // pop r12
            emit8(0x5E);  // pop rsi
            emit8(0x5F);  // pop rdi

            freeReg(1); freeReg(2); freeReg(3);
            int r = allocReg(); if (r != 0) { emitMovReg(r, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r));
            return r >= 0 ? r : 0;
        }

        // ============== Linux built-in functions (app linux) ==============
        // Linux target uses the SysV ABI and raw syscalls / dlopen'd libs for
        // all OS access (print via write(1,...), memory via mmap/munmap, files
        // via open/read/write, GUI via X11, graphics via Vulkan 1.3, socket I/O
        // via raw socket syscalls, sound via /dev/snd or dlopen'd libasound).
        if (prog.appType == AppType::Linux) {
            // Kernel-module mode ('app console/linux driver'): print() -> _printk.
            // Tried first so driver builtins win over the userspace Linux ones.
            if (prog.koDriver) {
                int kdResult;
                if (tryKOCall(call, kdResult)) return kdResult;
            }
            int liResult;
            if (tryLinuxCall(call, liResult)) return liResult;
            int lgResult;
            if (tryLinuxGUICall(call, lgResult)) return lgResult;
            int lvResult;
            if (tryLinuxVulkanCall(call, lvResult)) return lvResult;
            int lnResult;
            if (tryLinuxNetCall(call, lnResult)) return lnResult;
            int lwResult;
            if (tryLinuxWLCall(call, lwResult)) return lwResult;
        }

        // ============== GUI Built-in Functions ==============
        if (prog.appType == AppType::GUI) {
            int guiResult;
            if (tryGUICall(call, guiResult)) return guiResult;
            // Zenith Studio / runtime tool builtins (codegen_builtins.cpp):
            // Win32-backed helpers (glyphAt, mouseX/Y, fileLoad/Save, mem*, ...).
            // Only meaningful on Windows PE executables.
            int builtinResult;
            if (builtinAllowed(call->name) && tryBuiltinCall(call, builtinResult)) return builtinResult;
        }

        // ============== DX11 Shader Built-in Functions ==============
        if (prog.renderType == RenderType::DX11) {
            int dxResult;
            if (tryDX11Call(call, dxResult)) return dxResult;
        }

        // ============== Shared builtins (EFI/Bare): efi_print, efi_exit, halt, inb/outb ==============
        // Tried BEFORE tryEFICall so the argument-evaluating implementations win over the
        // duplicate (and previously unreachable) ones in the EFI-specific handler.
        // vga_clear/vga_putc/vga_print are handled by the cursor-aware versions in
        // tryEFICall (EFI/Bare) and tryBIOSCall (BIOS).
        if (prog.appType == AppType::EFI || prog.appType == AppType::Bare) {
            int builtinResult;
            if (builtinAllowed(call->name) && tryBuiltinCall(call, builtinResult)) return builtinResult;
        }

        // ============== EFI / Bare-metal Built-in Functions ==============
        if (prog.appType == AppType::EFI || prog.appType == AppType::Bare) {
            int efiResult;
            if (builtinAllowed(call->name) && tryEFICall(call, efiResult)) return efiResult;
        }

        // ============== BIOS Built-in Functions ==============
        // BIOS and bare are equivalent in the user's terms: a bare kernel that
        // runs on top of firmware (kernel_mode: dependent) may use bios_* too.
        if (prog.appType == AppType::BIOS ||
            (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent)) {
            int biosResult;
            if (builtinAllowed(call->name) && tryBIOSCall(call, biosResult)) return biosResult;
        }

        // ============== Winsock TCP/UDP builtins (net_* socket API) ==============
        // TCP/UDP servers and clients for Windows PE executables (console + GUI).
        if (prog.appType == AppType::Console || prog.appType == AppType::GUI) {
            int netResult;
            if (tryNetCall(call, netResult)) return netResult;
        }

        // ============== Sound builtins (sound_* PCM synthesis + waveOut) ==============
        // 8/16/24-bit sample generation and real playback for Windows PE apps.
        if (prog.appType == AppType::Console || prog.appType == AppType::GUI) {
            int soundResult;
            if (trySoundCall(call, soundResult)) return soundResult;
        }

        // ============== TLS builtins (tls_* over the embedded crypto blob) ==============
        // Real TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256) on bare sockets for Windows PE apps.
        if (prog.appType == AppType::Console || prog.appType == AppType::GUI ||
            prog.appType == AppType::Linux) {
            int tlsResult;
            if (tryTlsCall(call, tlsResult)) return tlsResult;
        }

        // ============== JS builtins (js_* over the embedded JS engine blob) ==============
        // Embedded freestanding JS interpreter (tools/jsrt.c as src/js_blob.h).
        if ((prog.appType == AppType::Console || prog.appType == AppType::GUI ||
             prog.appType == AppType::Linux) && !prog.koDriver) {
            int jsResult;
            if (tryJsCall(call, jsResult)) return jsResult;
        }

        regsUsed = 0;
        xmmRegsUsed = 0;

        // Arguments are placed into 8-byte "slots". A struct passed by value
        // occupies ceil(totalSize/8) consecutive slots (its memory is copied
        // verbatim, qword by qword), so the caller and callee agree on layout.
        auto structArgInfo = [&](Expr* e, bool& isStruct, bool& isGlobal,
                                 int& offset, int& slots) -> bool {
            isStruct = false; isGlobal = false; slots = 1;
            if (auto id = dynamic_cast<IdentExpr*>(e)) {
                auto sv = getVarInfo(id->name);
                if (sv && sv->type.kind == TypeKind::Struct) {
                    auto slIt = structLayouts.find(sv->type.structName);
                    if (slIt != structLayouts.end()) {
                        isStruct = true;
                        isGlobal = sv->isGlobal;
                        offset = sv->offset;
                        if (sv->type.isPtr) {
                            slots = 1;  // a pointer (e.g. `this`) occupies a single slot
                        } else {
                            slots = (int)((slIt->second.totalSize + 7) / 8);
                            if (slots < 1) slots = 1;
                        }
                    }
                }
            }
            return isStruct;
        };

        int totalSlots = 0;
        for (size_t i = 0; i < call->args.size(); i++) {
            int span = 1;
            if (!isFloatExpr(call->args[i].get())) {
                bool isS, isG; int so; int ss;
                if (structArgInfo(call->args[i].get(), isS, isG, so, ss)) span = ss;
                else {
                    int bigK = structValueQwords(call->args[i].get());
                    if (bigK >= 2) span = bigK;
                }
            }
            totalSlots += span;
        }
        int stackSlots = totalSlots > 4 ? totalSlots - 4 : 0;
        int stackAlloc;
        if (sysvAbi) {
            stackSlots = totalSlots > 6 ? totalSlots - 6 : 0;
            stackAlloc = stackSlots * 8;
        } else {
            stackAlloc = 0x20 + stackSlots * 8;
        }
        stackAlloc = (stackAlloc + 15) & ~15;
        if (stackAlloc <= 127) {
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8((uint8_t)stackAlloc);
        } else {
            emit8(0x48); emit8(0x81); emit8(0xEC); emit32((uint32_t)stackAlloc);
        }

        int argIndex = 0;
        uint8_t placedGP = 0;   // bit s = slot s (<4) holds a staged int arg in GP reg s
        uint8_t placedXmm = 0;  // bit s = slot s (<4) holds a staged float arg in XMM reg s

        // If a later argument contains a call, that call clobbers all caller-saved
        // registers (rcx/rdx/r8/r9/xmm0-3), so already-staged register args must be
        // spilled to the stack across its evaluation. A final pad keeps rsp 16-byte
        // aligned at the nested call site.
        // Bytes currently pushed onto rsp by spillPlacedArgs (pending restore).
        // The caller's stack-arg slots are positioned relative to the FINAL rsp
        // at the call, so while spilled args are on the stack the writes must be
        // offset by the spill depth. Paired spill/restore adds/subtracts so nested
        // risky args accumulate the depth correctly.
        int spillBytes = 0;
        auto spillPlacedArgs = [&](uint8_t gp, uint8_t xmm) {
            int nRegs = sysvAbi ? 6 : 4;
            int nPushed = 0;
            for (int s = 0; s < nRegs; s++) {
                if (!(gp & (1 << s))) continue;
                if (sysvAbi) {
                    if (s == 0) { emit8(0x57); }                        // push rdi
                    else if (s == 1) { emit8(0x56); }                   // push rsi
                    else if (s == 2) { emit8(0x52); }                   // push rdx
                    else if (s == 3) { emit8(0x51); }                   // push rcx
                    else if (s == 4) { emit8(0x41); emit8(0x50); }      // push r8
                    else { emit8(0x41); emit8(0x51); }                  // push r9
                } else {
                    if (s == 0) emit8(0x51);                             // push rcx
                    else if (s == 1) emit8(0x52);                        // push rdx
                    else if (s == 2) { emit8(0x41); emit8(0x50); }       // push r8
                    else { emit8(0x41); emit8(0x51); }                   // push r9
                }
                nPushed++;
            }
            for (int s = 0; s < 4; s++) {
                if (xmm & (1 << s)) {
                    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // sub rsp, 8
                    emit8(0xF3); emit8(0x0F); emit8(0x11);
                    emit8((uint8_t)(0x04 | (s << 3))); emit8(0x24);     // movss [rsp], xmms
                    nPushed++;
                }
            }
            if (nPushed & 1) {
                emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08); // pad
                nPushed++;
            }
            spillBytes += nPushed * 8;
        };
        auto restorePlacedArgs = [&](uint8_t gp, uint8_t xmm) {
            int nRegs = sysvAbi ? 6 : 4;
            int nPushed = 0;
            for (int s = 0; s < nRegs; s++) {
                if (gp & (1 << s)) nPushed++;
            }
            for (int s = 0; s < 4; s++) {
                if (xmm & (1 << s)) nPushed++;
            }
            if (nPushed & 1) {
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08); // remove pad
                nPushed++;
            }
            spillBytes -= nPushed * 8;
            for (int s = 3; s >= 0; s--) {
                if (xmm & (1 << s)) {
                    emit8(0xF3); emit8(0x0F); emit8(0x10);
                    emit8((uint8_t)(0x04 | (s << 3))); emit8(0x24);     // movss xmms, [rsp]
                    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);
                }
            }
            for (int s = nRegs - 1; s >= 0; s--) {
                if (!(gp & (1 << s))) continue;
                if (sysvAbi) {
                    if (s == 0) emit8(0x5F);                             // pop rdi
                    else if (s == 1) emit8(0x5E);                        // pop rsi
                    else if (s == 2) emit8(0x5A);                        // pop rdx
                    else if (s == 3) emit8(0x59);                        // pop rcx
                    else if (s == 4) { emit8(0x41); emit8(0x58); }       // pop r8
                    else { emit8(0x41); emit8(0x59); }                   // pop r9
                } else {
                    if (s == 0) emit8(0x59);                             // pop rcx
                    else if (s == 1) emit8(0x5A);                        // pop rdx
                    else if (s == 2) { emit8(0x41); emit8(0x58); }       // pop r8
                    else { emit8(0x41); emit8(0x59); }                   // pop r9
                }
            }
            // gp is a *slot* bitmask (bit s = register-argument slot s).
            for (int s = 0; s < nRegs; s++) {
                if (!(gp & (1 << s))) continue;
                if (sysvAbi) {
                    // slots 0..5 -> rdi(7), rsi(6), rdx(2), rcx(1), r8, r9
                    if (s == 0) regsUsed |= (1 << 7);
                    else if (s == 1) regsUsed |= (1 << 6);
                    else if (s == 2) regsUsed |= (1 << 2);
                    else if (s == 3) regsUsed |= (1 << 1);
                } else {
                    if (s == 0) regsUsed |= (1 << 1);   // slot0 -> rcx
                    else if (s == 1) regsUsed |= (1 << 2);   // slot1 -> rdx
                }
            }
            if (xmm) xmmRegsUsed |= xmm;
        };
        // Place a 64-bit value (already in valueReg) into argument slot `slot`.
        auto placeQwordIntoSlot = [&](int slot, int valueReg) {
            if (getenv("ZT_CALLDEBUG")) {
                fprintf(stderr, "    placeQ slot=%d valueReg=%d regsUsed_prev=%02x\n", slot, valueReg, (unsigned)regsUsed);
            }
            if (sysvAbi) {
                // SysV ABI: integer/pointer args -> rdi,rsi,rdx,rcx,r8,r9 (slots 0..5),
                // then stack (slots 6+). kAllocPool indexes: 0=rax,1=rcx,2=rdx,3=rbx,
                // 6=rsi,7=rdi. r8/r9 are outside the alloc pool.
                if (slot == 0) {          // -> rdi (alloc pool 7)
                    if (valueReg != 7) { emitMovReg(7, valueReg); freeReg(valueReg); }
                    regsUsed |= (1 << 7);
                    placedGP |= (1 << 0);
                } else if (slot == 1) {   // -> rsi (alloc pool 6)
                    if (valueReg != 6) { emitMovReg(6, valueReg); freeReg(valueReg); }
                    regsUsed |= (1 << 6);
                    placedGP |= (1 << 1);
                } else if (slot == 2) {   // -> rdx (alloc pool 2)
                    if (valueReg != 2) { emitMovReg(2, valueReg); freeReg(valueReg); }
                    regsUsed |= (1 << 2);
                    placedGP |= (1 << 2);
                } else if (slot == 3) {   // -> rcx (alloc pool 1)
                    if (valueReg != 1) { emitMovReg(1, valueReg); freeReg(valueReg); }
                    regsUsed |= (1 << 1);
                    placedGP |= (1 << 3);
                } else if (slot == 4) {   // -> r8
                    if (valueReg == 0)      { emit8(0x49); emit8(0x89); emit8(0xC0); }
                    else if (valueReg == 1) { emit8(0x49); emit8(0x89); emit8(0xC8); }
                    else if (valueReg == 2) { emit8(0x49); emit8(0x89); emit8(0xD0); }
                    else if (valueReg == 3) { emit8(0x49); emit8(0x89); emit8(0xD8); }
                    else if (valueReg == 6) { emit8(0x49); emit8(0x89); emit8(0xF0); }
                    else if (valueReg == 7) { emit8(0x49); emit8(0x89); emit8(0xF8); }
                    else { emitMovReg(0, valueReg); emit8(0x49); emit8(0x89); emit8(0xC0); }
                    freeReg(valueReg);
                    placedGP |= (1 << 4);
                } else if (slot == 5) {   // -> r9
                    if (valueReg == 0)      { emit8(0x49); emit8(0x89); emit8(0xC1); }
                    else if (valueReg == 1) { emit8(0x49); emit8(0x89); emit8(0xC9); }
                    else if (valueReg == 2) { emit8(0x49); emit8(0x89); emit8(0xD1); }
                    else if (valueReg == 3) { emit8(0x49); emit8(0x89); emit8(0xD9); }
                    else if (valueReg == 6) { emit8(0x49); emit8(0x89); emit8(0xF1); }
                    else if (valueReg == 7) { emit8(0x49); emit8(0x89); emit8(0xF9); }
                    else { emitMovReg(0, valueReg); emit8(0x49); emit8(0x89); emit8(0xC1); }
                    freeReg(valueReg);
                    placedGP |= (1 << 5);
                } else {
                    // SysV: stack args start at [rsp] right after the return address.
                    // The call-site frame reserves spillBytes; we stage push-down
                    // args starting at offset 0 (SysV has no 32-byte shadow).
                    int stackOff = (slot - 6) * 8 + spillBytes;
                    if (valueReg != 0) { emitMovReg(0, valueReg); freeReg(valueReg); }
                    if (stackOff < 128) {
                        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8((uint8_t)stackOff);
                    } else {
                        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32((uint32_t)stackOff);
                    }
                }
                return;
            }
            if (slot == 0) {
                if (valueReg != 1) { emitMovReg(1, valueReg); freeReg(valueReg); }
                regsUsed |= (1 << 1);
                placedGP |= (1 << 0);
            } else if (slot == 1) {
                if (valueReg != 2) { emitMovReg(2, valueReg); freeReg(valueReg); }
                regsUsed |= (1 << 2);
                placedGP |= (1 << 1);
            } else if (slot == 2) {
                if (valueReg == 0) {
                    emit8(0x49); emit8(0x89); emit8(0xC0);  // MOV R8, RAX
                } else if (valueReg == 1) {
                    emit8(0x49); emit8(0x89); emit8(0xC8);  // MOV R8, RCX
                } else if (valueReg == 2) {
                    emit8(0x49); emit8(0x89); emit8(0xD0);  // MOV R8, RDX
                } else if (valueReg == 3) {
                    emit8(0x49); emit8(0x89); emit8(0xD8);  // MOV R8, RBX
                } else {
                    emitMovReg(0, valueReg);
                    emit8(0x49); emit8(0x89); emit8(0xC0);  // MOV R8, RAX
                }
                freeReg(valueReg);
                placedGP |= (1 << 2);
            } else if (slot == 3) {
                if (valueReg == 0) {
                    emit8(0x49); emit8(0x89); emit8(0xC1);  // MOV R9, RAX
                } else if (valueReg == 1) {
                    emit8(0x49); emit8(0x89); emit8(0xC9);  // MOV R9, RCX
                } else if (valueReg == 2) {
                    emit8(0x49); emit8(0x89); emit8(0xD1);  // MOV R9, RDX
                } else if (valueReg == 3) {
                    emit8(0x49); emit8(0x89); emit8(0xD9);  // MOV R9, RBX
                } else {
                    emitMovReg(0, valueReg);
                    emit8(0x49); emit8(0x89); emit8(0xC1);  // MOV R9, RAX
                }
                freeReg(valueReg);
                placedGP |= (1 << 3);
            } else {
                int stackOff = 0x20 + (slot - 4) * 8 + spillBytes;
                if (valueReg != 0) { emitMovReg(0, valueReg); freeReg(valueReg); }
                if (stackOff < 128) {
                    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8((uint8_t)stackOff);
                } else {
                    emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32((uint32_t)stackOff);
                }
            }
        };

        // ================= Virtual method dispatch =================
        // The receiver object's hidden `__classid` slot (offset 0) selects the
        // implementation at runtime. The stack frame for the call (stackAlloc)
        // was already reserved above, alongside the normal user-call path.
        // Arguments are staged once (Win64 ABI); every dispatch target is a
        // direct call with those args already in RCX/RDX/R8/R9 or on the stack.
        // Only RAX/RBX are used for the compare chain, so the staged arguments
        // survive it.
        if (call->isVirtual && !call->vtable.empty()) {
            int objReg = emitExpr(call->args[0].get());
            if (objReg != 3) emitMovReg(3, objReg);   // object address -> rbx (callee-saved)
            freeReg(objReg);
            regsUsed |= (1 << 3);

            int argIndex = 1;
            for (size_t i = 1; i < call->args.size(); i++) {
                bool isFloatArg = isFloatExpr(call->args[i].get());
                bool riskyArg = exprContainsCall(call->args[i].get());
                bool isS = false, sGlobal = false;
                int sOffset = 0, sSlots = 1;
                if (!isFloatArg) structArgInfo(call->args[i].get(), isS, sGlobal, sOffset, sSlots);
                int span = isS ? sSlots : 1;
                if (span == 1 && !isFloatArg) {
                    int bigK = structValueQwords(call->args[i].get());
                    if (bigK >= 2) span = bigK;
                }

                uint8_t savedGP = placedGP;
                uint8_t savedXmm = placedXmm;
                if (riskyArg && (savedGP | savedXmm)) spillPlacedArgs(savedGP, savedXmm);

                if (isS) {
                    for (int k = 0; k < sSlots; k++) {
                        int r = allocReg();
                        if (sGlobal) emitGlobalLoadReg(r, sOffset + k * 8);
                        else emitLoadRegFromBP64(r, sOffset + k * 8);
                        placeQwordIntoSlot(argIndex + k, r);
                    }
                } else if (isFloatArg) {
                    int maxFp = sysvAbi ? 8 : 4;
                    if (argIndex < maxFp) {
                        int xmmIdx = argIndex;
                        int x = emitFloatExpr(call->args[i].get());
                        if (x != xmmIdx) { emitMovssXmm(xmmIdx, x); freeXmmReg(x); }
                        placedXmm |= (uint8_t)(1 << xmmIdx);
                        xmmRegsUsed |= (uint8_t)(1 << xmmIdx);
                    } else {
                        int stackOff = (sysvAbi ? (argIndex - 8) : (argIndex - 4)) * 8 + spillBytes;
                        int x = emitFloatExpr(call->args[i].get());
                        if (stackOff < 128) {
                            emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x44); emit8(0x24); emit8((uint8_t)stackOff);
                        } else {
                            emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x84); emit8(0x24); emit32((uint32_t)stackOff);
                        }
                        freeXmmReg(x);
                    }
                } else {
                    int bigK = structValueQwords(call->args[i].get());
                    if (bigK >= 2) {
                        if (dynamic_cast<CallExpr*>(call->args[i].get())) {
                            // Callee leaves the big struct value in rax:rdx:r10;
                            // place straight into slots (avoid [rsp+0..] scratch that
                            // would clobber the spill-pushed register args).
                            (void)emitExpr(call->args[i].get());
                            placeQwordIntoSlot(argIndex + 0, 0);
                            placeQwordIntoSlot(argIndex + 1, 2);
                            if (bigK >= 3) placeQwordIntoSlot(argIndex + 2, 10);
                        } else {
                            emitStructAddrR10(call->args[i].get());
                            for (int j = 0; j < bigK; j++) {
                                emitLoadFromAddrR10(0, j * 8);
                                placeQwordIntoSlot(argIndex + j, 0);
                            }
                        }
                    } else {
                        int argReg = emitExpr(call->args[i].get());
                        placeQwordIntoSlot(argIndex, argReg);
                    }
                }

                if (riskyArg && (savedGP | savedXmm)) restorePlacedArgs(savedGP, savedXmm);
                argIndex += span;
            }
            // self slot last (receiver address is kept in rbx, untouched by staging)
            placeQwordIntoSlot(0, 3);
            if (sysvAbi) { regsUsed |= (1 << 7); }   // rdi holds `this`
            else         { regsUsed |= (1 << 1); }   // rcx holds `this`

            // dispatch: read __classid = [rcx+0] (Win64) / [rdi+0] (SysV)
            if (sysvAbi)      { emit8(0x48); emit8(0x8B); emit8(0x07); }   // mov rax,[rdi]
            else              { emit8(0x48); emit8(0x8B); emit8(0x01); }  // mov rax,[rcx]
            int doneLabel = newLabel();
            std::vector<int> caseLabels;
            for (size_t i = 0; i + 1 < call->vtable.size(); i++) {
                int caseLabel = newLabel();
                emit8(0x48); emit8(0x3D);            // cmp rax, imm32 (sign-extended)
                emit32((uint32_t)call->vtable[i].first);
                emitJcc("==", caseLabel);
                caseLabels.push_back(caseLabel);
            }
            emit8(0xE8);                              // default = last (static-type) impl
            callFixups.push_back({code.size(), call->vtable.back().second});
            emit32(0);
            emitJmp(doneLabel);
            for (size_t i = 0; i + 1 < call->vtable.size(); i++) {
                emitLabel(caseLabels[i]);
                emit8(0xE8);
                callFixups.push_back({code.size(), call->vtable[i].second});
                emit32(0);
                emitJmp(doneLabel);
            }
            emitLabel(doneLabel);

            if (stackAlloc <= 127) {
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8((uint8_t)stackAlloc);
            } else {
                emit8(0x48); emit8(0x81); emit8(0xC4); emit32((uint32_t)stackAlloc);
            }
            regsUsed = 1;
            xmmRegsUsed = 0;
            return 0;
        }

        for (size_t i = 0; i < call->args.size(); i++) {
            bool isFloatArg = isFloatExpr(call->args[i].get());
            bool riskyArg = exprContainsCall(call->args[i].get());
            bool isS = false, sGlobal = false;
            int sOffset = 0, sSlots = 1;
            if (!isFloatArg) structArgInfo(call->args[i].get(), isS, sGlobal, sOffset, sSlots);
            int span = isS ? sSlots : 1;
            if (span == 1 && !isFloatArg) {
                int bigK = structValueQwords(call->args[i].get());
                if (bigK >= 2) span = bigK;
            }

            // Snapshot the staged args BEFORE evaluation; restore must use the same
            // set, since the current arg's own slots are placed after the spill.
            uint8_t savedGP = placedGP;
            uint8_t savedXmm = placedXmm;
            if (riskyArg && (savedGP | savedXmm)) spillPlacedArgs(savedGP, savedXmm);

            if (getenv("ZT_CALLDEBUG")) {
                std::string an;
                if (auto c = dynamic_cast<CallExpr*>(call->args[i].get())) an = "call:" + c->name;
                else if (auto id = dynamic_cast<IdentExpr*>(call->args[i].get())) an = "id:" + id->name;
                else if (auto f = dynamic_cast<FloatExpr*>(call->args[i].get())) an = "float";
                else if (auto n = dynamic_cast<NumberExpr*>(call->args[i].get())) an = "num";
                else an = "?";
                fprintf(stderr, "  [fn:%s] arg %zu %s float=%d risky=%d isS=%d sOff=%d sSlots=%d placedGP=%02x placedXmm=%02x regsUsed=%02x argIndex=%d\n",
                        call->name.c_str(), i, an.c_str(), (int)isFloatArg, (int)riskyArg, (int)isS, sOffset, sSlots,
                        (unsigned)placedGP, (unsigned)placedXmm, (unsigned)regsUsed, argIndex);
            }
            if (isS) {
                for (int k = 0; k < sSlots; k++) {
                    int r = allocReg();
                    if (sGlobal) emitGlobalLoadReg(r, sOffset + k * 8);
                    else emitLoadRegFromBP64(r, sOffset + k * 8);
                    placeQwordIntoSlot(argIndex + k, r);
                }
            } else if (isFloatArg) {
                int maxFp = sysvAbi ? 8 : 4;
                if (argIndex < maxFp) {
                    int xmmIdx = argIndex;
                    int x = emitFloatExpr(call->args[i].get());
                    if (x != xmmIdx) {
                        emitMovssXmm(xmmIdx, x);
                        freeXmmReg(x);
                    }
                    placedXmm |= (uint8_t)(1 << xmmIdx);
                    xmmRegsUsed |= (uint8_t)(1 << xmmIdx);
                } else {
                    int stackOff = (sysvAbi ? (argIndex - 8) : (argIndex - 4)) * 8 + spillBytes;
                    int x = emitFloatExpr(call->args[i].get());
                    if (stackOff < 128) {
                        emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x44); emit8(0x24); emit8((uint8_t)stackOff);
                    } else {
                        emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x84); emit8(0x24); emit32((uint32_t)stackOff);
                    }
                    freeXmmReg(x);
                }
            } else {
                int bigK = structValueQwords(call->args[i].get());
                if (bigK >= 2) {
                    if (dynamic_cast<CallExpr*>(call->args[i].get())) {
                        // Callee leaves the big struct value in rax:rdx:r10.
                        // Place each qword straight into its slot; do NOT round-trip
                        // through [rsp+0..0x17], which would clobber register args
                        // that spillPlacedArgs() pushed onto the same stack slots.
                        (void)emitExpr(call->args[i].get());
                        placeQwordIntoSlot(argIndex + 0, 0);
                        placeQwordIntoSlot(argIndex + 1, 2);
                        if (bigK >= 3) placeQwordIntoSlot(argIndex + 2, 10);
                    } else {
                        emitStructAddrR10(call->args[i].get());
                        for (int j = 0; j < bigK; j++) {
                            emitLoadFromAddrR10(0, j * 8);
                            placeQwordIntoSlot(argIndex + j, 0);
                        }
                    }
                } else {
                    int argReg = emitExpr(call->args[i].get());
                    placeQwordIntoSlot(argIndex, argReg);
                }
            }

            if (riskyArg && (savedGP | savedXmm)) restorePlacedArgs(savedGP, savedXmm);
            argIndex += span;
        }

        bool isImportCall = false;
        std::string importDll;
        // Check if the function is extern (from DLL import or auto-imported from embedded DLL)
        for (auto& func : prog.functions) {
            if (func->isExtern && func->name == call->name) {
                isImportCall = true;
                importDll = func->dllName;
                break;
            }
        }
        // Also check externFuncMap for auto-imported functions not in prog.functions
        if (!isImportCall) {
            auto eit = externFuncMap.find(call->name);
            if (eit != externFuncMap.end()) {
                isImportCall = true;
                importDll = eit->second.first;
            }
        }

        if (isImportCall) {
            if (sysvAbi) {
                emit8(0xFF); emit8(0x15);
                std::string soname = importDll.empty() ? "libc.so.6" : importDll;
                elfImportFixups.push_back({code.size(), call->name, soname});
                emit32(0);
            } else {
                emit8(0xFF); emit8(0x15);
                importCallFixups.push_back({code.size(), call->name, importDll});
                emit32(0);
            }
        } else {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, call->name});
        }

        if (stackAlloc <= 127) {
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8((uint8_t)stackAlloc);
        } else {
            emit8(0x48); emit8(0x81); emit8(0xC4); emit32((uint32_t)stackAlloc);
        }

        // All volatile regs clobbered by call; only RAX holds the return value
        regsUsed = 1;
        xmmRegsUsed = 0;
        return 0;
    }
    if (auto deref = dynamic_cast<DerefExpr*>(expr)) {
        int r = emitExpr(deref->ptr.get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x48); emit8(0x8B); emit8(0x00); // mov rax, [rax]
        regsUsed = 1;
        return 0;
    }

    int r = allocReg();
    emitMovRegImm(r, 0);
    return r;
}

void Codegen::emitStmt(Stmt* stmt, const Type* stmtType) {
    (void)stmtType;
    if (emitDebugInfo && stmt && stmt->line > 0) {
        if (dbgLines.empty() || dbgLines.back().offset != code.size() ||
            dbgLines.back().line != stmt->line) {
            dbgLines.push_back({code.size(), stmt->line});
        }
    }
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        if (ret->value) {
            // Large structs (>8 bytes) are returned in rax:rdx:r10 (k<=3 qwords).
            int bigK = structValueQwords(ret->value.get());
            if (bigK >= 2) {
                emitStructRegs(ret->value.get(), bigK);
                regsUsed = 0;
            } else if (curFuncRetType.kind == TypeKind::Float ||
                isFloatExpr(ret->value.get())) {
                // Win64 returns floats in xmm0; emit the float expression and
                // ensure the result lands in xmm0 before jumping to the epilogue.
                int x = emitFloatExpr(ret->value.get());
                if (x != 0) { emitMovssXmm(0, x); freeXmmReg(x); }
                xmmRegsUsed |= (uint8_t)(1 << 0);
            } else {
                int r = emitExpr(ret->value.get());
                if (r != 0) emitMovReg(0, r);
                regsUsed = 0;
            }
        }
        if (funcEndLabel >= 0) emitJmp(funcEndLabel);
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        int r = emitExpr(exprStmt->expr.get());
        freeReg(r);
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        if (varDecl->init) {
            if (varDecl->type.kind == TypeKind::Float) {
                int x = emitFloatExpr(varDecl->init.get());
                emitFloatStoreToBP(x, varInfos[varDecl->name].offset);
                freeXmmReg(x);
            } else {
                int bigK = structValueQwords(varDecl->init.get());
                if (bigK >= 2) {
                    // Locals live on the stack frame, so a big-struct init is a
                    // multi-qword copy of rax:rdx:r10 into [rbp+off .. off+3*8].
                    emitStructRegs(varDecl->init.get(), bigK);
                    int off = varInfos[varDecl->name].offset;
                    // rdx -> [rbp+off+8]
                    if (off + 8 >= -128 && off + 8 <= 127) {
                        emit8(0x48); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)(off + 8));
                    } else {
                        emit8(0x48); emit8(0x89); emit8(0x95); emit32((uint32_t)(int32_t)(off + 8));
                    }
                    // r10 -> [rbp+off+16] (only when it holds a real 3rd qword)
                    if (bigK >= 3) {
                        if (off + 16 >= -128 && off + 16 <= 127) {
                            emit8(0x4C); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)(off + 16));
                        } else {
                            emit8(0x4C); emit8(0x89); emit8(0x95); emit32((uint32_t)(int32_t)(off + 16));
                        }
                    }
                    // rax -> [rbp+off]
                    emitStoreToBP64(off);
                    regsUsed = 0;
                } else {
                    int r = emitExpr(varDecl->init.get());
                    if (r != 0) { emitMovReg(0, r); freeReg(r); }
                    if (varDecl->type.kind == TypeKind::Bool) {
                        emitStoreToBP(varInfos[varDecl->name].offset);
                    } else {
                        emitStoreToBP64(varInfos[varDecl->name].offset);
                    }
                    freeReg(0);
                }
            }
        }
        // Fresh class-typed locals get their runtime class id written into the
        // hidden `__classid` slot at offset 0, so virtual dispatch works even
        // for objects that are never initialized by field assignments.
        if (varDecl->type.kind == TypeKind::Struct && !varDecl->type.isPtr && varDecl->arraySize == 0) {
            auto cidIt = prog.classIDs.find(varDecl->type.structName);
            if (cidIt != prog.classIDs.end()) {
                emitMovRegImm(0, cidIt->second);
                emitStoreToBP64(varInfos[varDecl->name].offset);
                freeReg(0);
            }
        }
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        auto constVi = getVarInfo(assign->name);
        if (constVi && constVi->isConst) {
            fprintf(stderr, "Error: cannot assign to const variable '%s'\n", assign->name.c_str());
            exit(1);
        }
        if (assign->indexExpr) {
            auto vi = getVarInfo(assign->name);
            if (vi) {
                int elementSize = 4;
                if (vi->type.kind == TypeKind::Float) elementSize = 4;
                else elementSize = 8;
                if (vi->isGlobal) emitGlobalLeaR10(vi->offset);
                else emitLeaR10FromBP(vi->offset);
                int idxReg = emitExprKeepAliveR10(assign->indexExpr.get());
                if (idxReg != 0) { emitMovReg(0, idxReg); freeReg(idxReg); idxReg = 0; }
                emit8(0x48); emit8(0x69); emit8(0xC0); emit32(elementSize);
                emit8(0x49); emit8(0x01); emit8(0xC2);
                freeReg(0);
                if (vi->type.kind == TypeKind::Float) {
                    // A nested array load in the value expression would clobber
                    // r10 (it is used as scratch base by every array access),
                    // so preserve the computed base+index across evaluation.
                    bool guardR10 = exprHasArrayAccess(assign->value.get());
                    if (guardR10) {
                        emit8(0x41); emit8(0x52);                                  // push r10
                        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);        // sub rsp, 8
                    }
                    int x = emitFloatExprKeepAliveR10(assign->value.get());
                    if (guardR10) {
                        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);        // add rsp, 8
                        emit8(0x41); emit8(0x5A);                                  // pop r10
                    }
                    emit8(0xF3); emit8(0x41); emit8(0x0F); emit8(0x11);
                    emit8((uint8_t)(0x02 | ((x & 7) << 3)));
                    freeXmmReg(x);
                } else {
                    bool guardR10 = exprHasArrayAccess(assign->value.get());
                    if (guardR10) {
                        emit8(0x41); emit8(0x52);                                  // push r10
                        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);        // sub rsp, 8
                    }
                    int r = emitExprKeepAliveR10(assign->value.get());
                    if (r != 0) emitMovReg(0, r);
                    if (guardR10) {
                        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);        // add rsp, 8
                        emit8(0x41); emit8(0x5A);                                  // pop r10
                    }
                    emit8(0x49); emit8(0x89); emit8(0x02);
                    freeReg(r);
                }
            }
        } else if (!assign->memberPath.empty()) {
            auto vi = getVarInfo(assign->name);
            if (vi) {
                std::string curStruct = vi->type.structName;
                bool isPtrRoot = vi->type.isPtr && vi->type.kind == TypeKind::Struct;
                int totalOff = 0;
                bool found = true;
                Type fieldType;
                for (size_t i = 0; found && i < assign->memberPath.size(); i++) {
                    auto slIt = structLayouts.find(curStruct);
                    if (slIt == structLayouts.end()) { found = false; break; }
                    auto& layout = slIt->second;
                    auto fIt = layout.fieldOffsets.find(assign->memberPath[i]);
                    auto fTypeIt = layout.fieldTypes.find(assign->memberPath[i]);
                    if (fIt == layout.fieldOffsets.end() || fTypeIt == layout.fieldTypes.end()) { found = false; break; }
                    totalOff += fIt->second;
                    fieldType = fTypeIt->second;
                    curStruct = fieldType.structName;
                }
                if (found) {
                    if (vi->isGlobal) {
                        if (isPtrRoot) emitGlobalLoadR10(vi->offset);
                        else emitGlobalLeaR10(vi->offset);
                    } else {
                        if (isPtrRoot) emitLoadR10FromBP64(vi->offset);
                        else emitLeaR10FromBP(vi->offset);
                    }
                    bool isFloatField = fieldType.kind == TypeKind::Float;
                    bool isBigField = !fieldType.isPtr && structTypeSize(fieldType) > 8;
                    if (isBigField) {
                        // Assigning a >8B struct VALUE to a >8B struct field.
                        // RHS evaluation may clobber r10 (it is our dst base), so
                        // spill the RHS qwords to [rsp+0..0x18] scratch, then
                        // recompute the dst address in r10 and copy down.
                        int bigK = structValueQwords(assign->value.get());
                        if (bigK < 2) bigK = 2;
                        emitStructRegs(assign->value.get(), bigK);
                        emit8(0x48); emit8(0x89); emit8(0x04); emit8(0x24);                  // mov [rsp], rax
                        emit8(0x48); emit8(0x89); emit8(0x54); emit8(0x24); emit8(8);        // mov [rsp+8], rdx
                        if (bigK >= 3) emit8(0x4C); emit8(0x89); emit8(0x54); emit8(0x24); emit8(16); // mov [rsp+16], r10
                        if (vi->isGlobal) {
                            if (isPtrRoot) emitGlobalLoadR10(vi->offset);
                            else emitGlobalLeaR10(vi->offset);
                        } else {
                            if (isPtrRoot) emitLoadR10FromBP64(vi->offset);
                            else emitLeaR10FromBP(vi->offset);
                        }
                        if (totalOff != 0) {
                            emit8(0x49); emit8(0x81); emit8(0xC2); emit32((uint32_t)(int32_t)totalOff); // add r10, imm32
                        }
                        for (int j = 0; j < bigK; j++) {
                            emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8((uint8_t)(j * 8)); // mov rax, [rsp+j*8]
                            emitStoreToAddrR10(j * 8);
                        }
                        regsUsed = 0;
                    } else {
                        bool guardR10 = exprHasArrayAccess(assign->value.get());
                        if (guardR10) {
                            emit8(0x41); emit8(0x52);                                  // push r10
                            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);        // sub rsp, 8
                        }
                        if (isFloatField) {
                            int x = emitFloatExprKeepAliveR10(assign->value.get());
                            if (guardR10) {
                                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);    // add rsp, 8
                                emit8(0x41); emit8(0x5A);                              // pop r10
                            }
                            emitFloatStoreToR10(x, totalOff);
                            freeXmmReg(x);
                        } else {
                            int r = emitExprKeepAliveR10(assign->value.get());
                            if (r != 0) emitMovReg(0, r);
                            if (guardR10) {
                                emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);    // add rsp, 8
                                emit8(0x41); emit8(0x5A);                              // pop r10
                            }
                            emitStoreToAddrR10(totalOff);
                            freeReg(r);
                        }
                        if (guardR10) {
                            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);        // add rsp, 8
                            emit8(0x41); emit8(0x5A);                                  // pop r10
                        }
                        freeReg(0);
                    }
                }
            }
        } else {
            auto vi = getVarInfo(assign->name);
            if (vi && vi->type.kind == TypeKind::Float) {
                int x = emitFloatExpr(assign->value.get());
                if (vi->isGlobal) emitGlobalFloatStore(x, vi->offset);
                else emitFloatStoreToBP(x, vi->offset);
                freeXmmReg(x);
            } else if (vi) {
                int bigK = structValueQwords(assign->value.get());
                if (bigK >= 2) {
                    emitStructRegs(assign->value.get(), bigK);
                    if (vi->isGlobal) {
                        emit8(0x48); emit8(0x89); emit8(0x15);  // mov [rip+off+8], rdx
                        globalFixups.push_back({code.size(), globalsRVA + (uint32_t)(vi->offset + 8)});
                        emit32(0);
                        if (bigK >= 3) {
                            emit8(0x4C); emit8(0x89); emit8(0x15);  // mov [rip+off+16], r10
                            globalFixups.push_back({code.size(), globalsRVA + (uint32_t)(vi->offset + 16)});
                            emit32(0);
                        }
                        emitGlobalStoreReg64(vi->offset);
                    } else {
                        int off = vi->offset;
                        if (off + 8 >= -128 && off + 8 <= 127) {
                            emit8(0x48); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)(off + 8));
                        } else {
                            emit8(0x48); emit8(0x89); emit8(0x95); emit32((uint32_t)(int32_t)(off + 8));
                        }
                        if (bigK >= 3) {
                            if (off + 16 >= -128 && off + 16 <= 127) {
                                emit8(0x4C); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)(off + 16));
                            } else {
                                emit8(0x4C); emit8(0x89); emit8(0x95); emit32((uint32_t)(int32_t)(off + 16));
                            }
                        }
                        emitStoreToBP64(off);
                    }
                    regsUsed = 0;
                } else {
                    int r = emitExpr(assign->value.get());
                    if (r != 0) { emitMovReg(0, r); freeReg(r); }
                    if (vi->type.kind == TypeKind::Bool) {
                        if (vi->isGlobal) emitGlobalStoreReg32(vi->offset);
                        else emitStoreToBP(vi->offset);
                    } else {
                        if (vi->isGlobal) emitGlobalStoreReg64(vi->offset);
                        else emitStoreToBP64(vi->offset);
                    }
                    freeReg(0);
                }
            } else {
                fprintf(stderr, "Error: undefined variable '%s'\n", assign->name.c_str());
                exit(1);
            }
        }
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        int elseLabel = newLabel();
        int endLabel = newLabel();
        int condReg;
        if (auto bin = dynamic_cast<BinaryExpr*>(ifStmt->condition.get())) {
            if (isFloatExpr(bin)) {
                condReg = emitBinaryExpr(bin, true);
            } else {
                condReg = emitExpr(ifStmt->condition.get());
            }
        } else {
            condReg = emitExpr(ifStmt->condition.get());
        }
        if (wordSize == 64) emit8(0x48);
        emit8(0x85); emit8((uint8_t)(0xC0 | ((condReg & 7) << 3) | (condReg & 7)));
        freeReg(condReg);
        emit8(0x0F); emit8(0x84);
        jmpFixups.push_back({code.size(), elseLabel});
        emit32(0);
        for (auto& s : ifStmt->thenBlock.stmts) emitStmt(s.get());
        emitJmp(endLabel);
        emitLabel(elseLabel);
        for (auto& s : ifStmt->elseBlock.stmts) emitStmt(s.get());
        emitLabel(endLabel);
    } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        int loopLabel = newLabel();
        int endLabel = newLabel();
        emitLabel(loopLabel);
        int condReg;
        if (auto bin = dynamic_cast<BinaryExpr*>(whileStmt->condition.get())) {
            if (isFloatExpr(bin)) {
                condReg = emitBinaryExpr(bin, true);
            } else {
                condReg = emitExpr(whileStmt->condition.get());
            }
        } else {
            condReg = emitExpr(whileStmt->condition.get());
        }
        if (wordSize == 64) emit8(0x48);
        emit8(0x85); emit8((uint8_t)(0xC0 | ((condReg & 7) << 3) | (condReg & 7)));
        freeReg(condReg);
        emit8(0x0F); emit8(0x84);
        jmpFixups.push_back({code.size(), endLabel});
        emit32(0);
        breakLabelStack.push_back(endLabel);
        continueLabelStack.push_back(loopLabel);
        for (auto& s : whileStmt->body.stmts) emitStmt(s.get());
        continueLabelStack.pop_back();
        breakLabelStack.pop_back();
        emitJmp(loopLabel);
        emitLabel(endLabel);
    } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        int loopLabel = newLabel();
        int endLabel = newLabel();
        emitLabel(loopLabel);
        breakLabelStack.push_back(endLabel);
        continueLabelStack.push_back(loopLabel);
        for (auto& s : loopStmt->body.stmts) emitStmt(s.get());
        continueLabelStack.pop_back();
        breakLabelStack.pop_back();
        emitJmp(loopLabel);
        emitLabel(endLabel);
    } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        int endLabel = newLabel();
        breakLabelStack.push_back(endLabel);
        int condReg = emitExpr(switchStmt->condition.get());
        if (condReg != 0) { emitMovReg(0, condReg); freeReg(condReg); condReg = 0; }
        regsUsed |= 1;   // rax holds the switch value
        int defaultLabel = newLabel();
        bool hasDefault = false;
        std::vector<int> caseLabels;
        for (size_t i = 0; i < switchStmt->cases.size(); i++) {
            if (switchStmt->cases[i].condition) caseLabels.push_back(newLabel());
            else hasDefault = true;
        }
        size_t cIdx = 0;
        for (size_t i = 0; i < switchStmt->cases.size(); i++) {
            auto& sc = switchStmt->cases[i];
            if (sc.condition) {
                int v = emitExpr(sc.condition.get());
                emit8(0x48); emit8(0x39); emit8((uint8_t)(0xC0 + (v & 7) * 8 + 0));
                freeReg(v);
                emitJcc("==", caseLabels[cIdx]);
                cIdx++;
            } else {
                emitJmp(defaultLabel);
            }
        }
        emitJmp(endLabel);
        cIdx = 0;
        for (size_t i = 0; i < switchStmt->cases.size(); i++) {
            auto& sc = switchStmt->cases[i];
            if (sc.condition) {
                emitLabel(caseLabels[cIdx]);
                cIdx++;
            } else {
                emitLabel(defaultLabel);
            }
            for (auto& s : sc.body.stmts) emitStmt(s.get());
            emitJmp(endLabel);
        }
        if (!hasDefault) emitLabel(defaultLabel);
        emitLabel(endLabel);
        breakLabelStack.pop_back();
        freeReg(condReg);
    } else if (dynamic_cast<BreakStmt*>(stmt)) {
        if (!breakLabelStack.empty()) emitJmp(breakLabelStack.back());
    } else if (dynamic_cast<ContinueStmt*>(stmt)) {
        if (!continueLabelStack.empty()) emitJmp(continueLabelStack.back());
    } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        int loopLabel = newLabel();
        int continueLabel = newLabel();
        int endLabel = newLabel();

        int startReg = emitExpr(forStmt->start.get());
        if (startReg != 0) { emitMovReg(0, startReg); freeReg(startReg); }
        emitStoreToBP64(varInfos[forStmt->varName].offset);
        freeReg(0);

        // Determine if step is negative at compile time for correct comparison
        bool countdown = false;
        if (forStmt->step) {
            if (auto numExpr = dynamic_cast<NumberExpr*>(forStmt->step.get())) {
                if (numExpr->value < 0) countdown = true;
            }
        }

        emitLabel(loopLabel);

        int varReg = allocReg(); if (varReg < 0) varReg = 0;
        emitLoadRegFromBP64(varReg, varInfos[forStmt->varName].offset);
        int endReg = emitExprKeepAlive(forStmt->end.get(), varReg);
        emit8(0x48); emit8(0x39); emit8((uint8_t)(0xC0 + endReg * 8 + varReg));
        freeReg(endReg);
        if (countdown) {
            emit8(0x0F); emit8(0x8E); // jle endLabel (countdown: exit when var <= end)
        } else {
            emit8(0x0F); emit8(0x8D); // jge endLabel (countup: exit when var >= end)
        }
        jmpFixups.push_back({code.size(), endLabel});
        emit32(0);
        freeReg(varReg);

        breakLabelStack.push_back(endLabel);
        continueLabelStack.push_back(continueLabel);
        for (auto& s : forStmt->body.stmts) emitStmt(s.get());
        continueLabelStack.pop_back();
        breakLabelStack.pop_back();
        emitLabel(continueLabel);

        int curReg = allocReg(); if (curReg < 0) curReg = 0;
        emitLoadRegFromBP64(curReg, varInfos[forStmt->varName].offset);
        if (forStmt->step) {
            int stepReg = emitExprKeepAlive(forStmt->step.get(), curReg);
            emitAdd(curReg, stepReg);
            freeReg(stepReg);
        } else {
            emit8(0x48); emit8(0xFF); emit8(0xC0 + curReg); // inc reg
        }
        if (curReg != 0) { emitMovReg(0, curReg); freeReg(curReg); }
        emitStoreToBP64(varInfos[forStmt->varName].offset);
        freeReg(0);

        emitJmp(loopLabel);
        emitLabel(endLabel);
    } else if (auto ptrAssign = dynamic_cast<PtrAssignStmt*>(stmt)) {
        spillRegs();
        regsUsed = 0;
        int v = emitExpr(ptrAssign->value.get());
        if (v != 0) { emitMovReg(0, v); freeReg(v); } else freeReg(0);
        emit8(0x50); // push rax (value)
        int p = emitExpr(ptrAssign->ptr.get());
        if (p != 0) { emitMovReg(0, p); freeReg(p); } else freeReg(0);
        emit8(0x5A); // pop rdx
        emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx
        regsUsed = 0;
    } else if (auto asmStmt = dynamic_cast<AsmStmt*>(stmt)) {
        int32_t ws = asmStmt->wordSize;
        if (ws == 0) ws = wordSize;  // 'asm' (native) -> target's natural operand width
        for (auto& instr : asmStmt->instrs) emitAsmInstr(instr, ws);
    }
}

int Codegen::asmRegIndex(const std::string& name) const {
    std::string n = name;
    for (auto& c : n) c = (char)tolower((unsigned char)c);
    static const char* names64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char* names32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char* names16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char* names8[16] = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    for (int i = 0; i < 16; i++) { if (n == names64[i]) return i; }
    for (int i = 0; i < 16; i++) { if (n == names32[i]) return i; }
    for (int i = 0; i < 16; i++) { if (n == names16[i]) return i; }
    for (int i = 0; i < 16; i++) { if (n == names8[i]) return i; }
    return -1;
}

void Codegen::emitAsmInstr(const AsmInstr& instr, int32_t wordSize) {
    // 16-bit real-mode (asm16) instructions are encoded completely differently
    // (no REX, default operand size 16, 16-bit addressing modes) — see the
    // dedicated encoder below.
    if (wordSize == 16) { emitAsm16Instr(instr); return; }

    const bool w64 = (wordSize == 64);
    struct AsmOp { int type = 0; int reg = 0; int base = 0; int64_t disp = 0; };
    auto trimStr = [](std::string& s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    };
    auto parseNum = [&](const std::string& s) -> int64_t {
        std::string t = s;
        trimStr(t);
        bool neg = false;
        if (!t.empty() && t[0] == '-') { neg = true; t.erase(t.begin()); }
        int64_t val = 0;
        try {
            if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
                val = std::stoll(t.substr(2), nullptr, 16);
            else
                val = std::stoll(t, nullptr, 10);
        } catch (...) { val = 0; }
        return neg ? -val : val;
    };
    auto parseOp = [&](const std::string& raw) -> AsmOp {
        std::string s = raw;
        trimStr(s);
        AsmOp op;
        if (s.empty()) return op;
        if (s[0] == '[') {
            op.type = 3;
            std::string inner = s;
            if (inner.size() >= 2 && inner.back() == ']') inner = inner.substr(1, inner.size() - 2);
            size_t plus = inner.find('+');
            size_t minus = inner.find('-');
            std::string baseStr, dispStr;
            if (plus != std::string::npos) { baseStr = inner.substr(0, plus); dispStr = inner.substr(plus + 1); }
            else if (minus != std::string::npos) { baseStr = inner.substr(0, minus); dispStr = inner.substr(minus); }
            else { baseStr = inner; }
            trimStr(baseStr); trimStr(dispStr);
            op.base = asmRegIndex(baseStr);
            if (op.base < 0) {
                // No base register: the operand is an absolute address like
                // [0x7000] (or [0x7000+4]). Keep base=-1 so the encoder emits
                // a direct (absolute) memory reference instead of [rax+...].
                op.base = -1;
                op.disp = parseNum(baseStr) + (dispStr.empty() ? 0 : parseNum(dispStr));
            } else if (!dispStr.empty()) {
                op.disp = parseNum(dispStr);
            }
            return op;
        }
        int ri = asmRegIndex(s);
        if (ri >= 0) { op.type = 1; op.reg = ri; return op; }
        if (s.size() >= 3 && (s[0] == 'c' || s[0] == 'C') && (s[1] == 'r' || s[1] == 'R')) {
            try { op.type = 4; op.reg = std::stoi(s.substr(2)); return op; } catch (...) {}
        }
        op.type = 2;
        op.disp = parseNum(s);
        return op;
    };

    AsmOp o1 = parseOp(instr.op1);
    AsmOp o2 = parseOp(instr.op2);
    std::string m = instr.mnemonic;
    for (auto& c : m) c = (char)tolower((unsigned char)c);

    auto rex = [&](bool w, bool r, bool x, bool b) {
        // In 32-bit mode only set the REX bits when actually needed for r8-r15;
        // REX.W stays off (w64 false). A bare 0x40+0 prefix is harmless for
        // r8..r15 access, but for ordinary 32-bit registers we want NO REX.
        if (!w64 && !r && !x && !b) return;
        emit8((uint8_t)(0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0)));
    };
    auto modrm = [&](int mod, int reg, int rm) {
        emit8((uint8_t)(((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)));
    };
    auto unsupported = [&](const char* what) {
        fprintf(stderr, "Warning: asm: unsupported instruction '%s', skipped\n", what);
    };

    if (m == "mov") {
        if (o1.type == 1 && o2.type == 1) {
            rex(w64, o2.reg >= 8, false, o1.reg >= 8);
            emit8(0x89); modrm(3, o2.reg, o1.reg);
            return;
        }
        if (o1.type == 1 && o2.type == 2) {
            rex(w64, false, false, o1.reg >= 8);
            emit8((uint8_t)(0xB8 + (o1.reg & 7)));
            if (w64) emit64((uint64_t)o2.disp);
            else     emit32((uint32_t)o2.disp);
            return;
        }
        if (o1.type == 1 && o2.type == 3) {
            if (o2.base < 0) {
                // Absolute address (no base register): [disp32].
                // SIB with no base (mod=0, rm=4, SIB=0x25) works in both 32- and
                // 64-bit modes; the mod=0 rm=5 form would be RIP-relative in
                // long mode, which is wrong for asm32 inside a 64-bit app.
                rex(w64, o1.reg >= 8, false, false);
                emit8(0x8B); modrm(0, o1.reg, 4); emit8(0x25); emit32((uint32_t)o2.disp);
                return;
            }
            rex(w64, o1.reg >= 8, false, o2.base >= 8);
            emit8(0x8B); modrm(2, o1.reg, o2.base);
            emit32((uint32_t)o2.disp);
            return;
        }
        if (o1.type == 3 && o2.type == 1) {
            if (o1.base < 0) {
                // Absolute address (no base register): [disp32].
                // See comment above — SIB form is valid in both modes.
                rex(w64, o2.reg >= 8, false, false);
                emit8(0x89); modrm(0, o2.reg, 4); emit8(0x25); emit32((uint32_t)o1.disp);
                return;
            }
            rex(w64, o2.reg >= 8, false, o1.base >= 8);
            emit8(0x89); modrm(2, o2.reg, o1.base);
            emit32((uint32_t)o1.disp);
            return;
        }
        if (o1.type == 1 && o2.type == 4) {
            rex(true, o2.reg >= 8, false, o1.reg >= 8);
            emit8(0x0F); emit8(0x20); modrm(3, o2.reg, o1.reg);
            return;
        }
        if (o1.type == 4 && o2.type == 1) {
            rex(true, o1.reg >= 8, false, o2.reg >= 8);
            emit8(0x0F); emit8(0x22); modrm(3, o1.reg, o2.reg);
            return;
        }
        unsupported("mov");
        return;
    }

    int arithOp = -1;
    if (m == "add") arithOp = 0;
    else if (m == "or") arithOp = 1;
    else if (m == "and") arithOp = 4;
    else if (m == "sub") arithOp = 5;
    else if (m == "xor") arithOp = 6;
    if (arithOp >= 0) {
        static const uint8_t arithOpcodes[8] = {0x01, 0x09, 0x00, 0x00, 0x21, 0x29, 0x31, 0x00};
        if (o1.type == 1 && o2.type == 1) {
            rex(w64, o2.reg >= 8, false, o1.reg >= 8);
            emit8(arithOpcodes[arithOp]); modrm(3, o2.reg, o1.reg);
            return;
        }
        if (o1.type == 1 && o2.type == 2) {
            rex(w64, false, false, o1.reg >= 8);
            emit8(0x81); modrm(3, arithOp, o1.reg);
            emit32((uint32_t)o2.disp);
            return;
        }
        unsupported(m.c_str());
        return;
    }

    if (m == "test") {
        if (o1.type == 1 && o2.type == 1) {
            rex(w64, o2.reg >= 8, false, o1.reg >= 8);
            emit8(0x85); modrm(3, o2.reg, o1.reg);
            return;
        }
        if (o1.type == 1 && o2.type == 2) {
            rex(w64, false, false, o1.reg >= 8);
            emit8(0xF7); modrm(3, 0, o1.reg);
            emit32((uint32_t)o2.disp);
            return;
        }
        unsupported("test");
        return;
    }

    if (m == "not" || m == "neg" || m == "inc" || m == "dec") {
        bool group3 = (m == "not" || m == "neg");
        int d = (m == "not") ? 2 : (m == "neg") ? 3 : (m == "inc") ? 0 : 1;
        if (o1.type == 1) {
            rex(w64, false, false, o1.reg >= 8);
            emit8(group3 ? 0xF7 : 0xFF); modrm(3, d, o1.reg);
            return;
        }
        unsupported(m.c_str());
        return;
    }

    if (m == "shl" || m == "shr") {
        int d = (m == "shl") ? 4 : 5;
        if (o1.type == 1 && o2.type == 1 && o2.reg == 1) {
            rex(w64, false, false, o1.reg >= 8);
            emit8(0xD3); modrm(3, d, o1.reg);
            return;
        }
        if (o1.type == 1 && o2.type == 2) {
            rex(w64, false, false, o1.reg >= 8);
            emit8(0xC1); modrm(3, d, o1.reg);
            emit8((uint8_t)o2.disp);
            return;
        }
        unsupported(m.c_str());
        return;
    }

    if (m == "push" || m == "pop") {
        if (o1.type == 1) {
            if (o1.reg >= 8) emit8(0x41);
            emit8((uint8_t)((m == "push" ? 0x50 : 0x58) + (o1.reg & 7)));
            return;
        }
        if (m == "push" && o1.type == 2) {
            emit8(0x68);
            emit32((uint32_t)o1.disp);
            return;
        }
        unsupported(m.c_str());
        return;
    }

    if (m == "jmp") {
        int64_t rel = o1.disp - (int64_t)(code.size() + 5);
        emit8(0xE9);
        emit32((uint32_t)rel);
        return;
    }
    static const struct { const char* name; int cc; } jccTable[] = {
        {"je",0x84},{"jz",0x84},{"jne",0x85},{"jnz",0x85},{"jb",0x82},{"jbe",0x86},{"ja",0x87},{"jae",0x83},
        {"jl",0x8C},{"jle",0x8E},{"jg",0x8F},{"jge",0x8D},{"js",0x88},{"jns",0x89}
    };
    for (auto& j : jccTable) {
        if (m == j.name) {
            int64_t rel = o1.disp - (int64_t)(code.size() + 6);
            emit8(0x0F);
            emit8((uint8_t)(0x80 | j.cc));
            emit32((uint32_t)rel);
            return;
        }
    }

    if (m == "cli") { emit8(0xFA); return; }
    if (m == "sti") { emit8(0xFB); return; }
    if (m == "pause") { emit8(0xF3); emit8(0x90); return; }
    if (m == "hlt") { emit8(0xF4); return; }
    if (m == "nop") { emit8(0x90); return; }
    if (m == "ret") { emit8(0xC3); return; }
    if (m == "leave") { emit8(0xC9); return; }
    if (m == "iret" || m == "iretq") { emit8(0xCF); return; }
    if (m == "syscall") { emit8(0x0F); emit8(0x05); return; }
    if (m == "cpuid") { emit8(0x0F); emit8(0xA2); return; }
    if (m == "wrmsr") { emit8(0x0F); emit8(0x30); return; }
    if (m == "rdmsr") { emit8(0x0F); emit8(0x32); return; }
    if (m == "cqo" || m == "cqd") { emit8(0x48); emit8(0x99); return; }

    // ---- timing / memory-ordering / privileged extras (useful in drivers) ----
    if (m == "rdtsc")         { emit8(0x0F); emit8(0x31); return; }
    if (m == "rdtscp")        { emit8(0x0F); emit8(0x01); emit8(0xF9); return; }
    if (m == "lfence")        { emit8(0x0F); emit8(0xAE); emit8(0xE8); return; }
    if (m == "mfence")        { emit8(0x0F); emit8(0xAE); emit8(0xF0); return; }
    if (m == "sfence")        { emit8(0x0F); emit8(0xAE); emit8(0xF8); return; }
    if (m == "clts")          { emit8(0x0F); emit8(0x06); return; }
    if (m == "swapgs")        { emit8(0x0F); emit8(0x01); emit8(0xF8); return; }
    if (m == "clc") { emit8(0xF8); return; }
    if (m == "stc") { emit8(0xF9); return; }
    if (m == "cmc") { emit8(0xF5); return; }
    if (m == "cld") { emit8(0xFC); return; }
    if (m == "std") { emit8(0xFD); return; }
    if (m == "lock") { emit8(0xF0); return; }   // prefix; follows as its own line

    // xchg r64,r64 / xchg [mem], r64  (classic lock-free atomic swap; pair with
    // a preceding 'lock' line for fully-atomic integer exchange).
    if (m == "xchg") {
        if (o1.type == 1 && o2.type == 1) {
            rex(w64, o2.reg >= 8, false, o1.reg >= 8);
            emit8(0x87); modrm(3, o2.reg, o1.reg);
            return;
        }
        if (o1.type == 3 && o2.type == 1) {
            // xchg [base+disp], reg  (or absolute [disp32])
            if (o1.base < 0) {
                rex(w64, o2.reg >= 8, false, false);
                emit8(0x87); modrm(0, o2.reg, 4); emit8(0x25); emit32((uint32_t)o1.disp);
                return;
            }
            rex(w64, o2.reg >= 8, false, o1.base >= 8);
            emit8(0x87); modrm(2, o2.reg, o1.base);
            emit32((uint32_t)o1.disp);
            return;
        }
        unsupported("xchg");
        return;
    }

    if (m == "int") {
        if (o1.type == 2) { emit8(0xCD); emit8((uint8_t)o1.disp); return; }
        unsupported("int");
        return;
    }
    if (m == "in") {
        if (o1.type == 1 && o1.reg == 0 && o2.type == 2) {
            if (w64) { emit8(0x48); emit8(0xE5); emit8((uint8_t)o2.disp); }
            else     { emit8(0xE5); emit8((uint8_t)o2.disp); }
            return;
        }
        unsupported("in");
        return;
    }
    if (m == "out") {
        if (o1.type == 2 && o2.type == 1 && o2.reg == 0) {
            if (w64) { emit8(0x48); emit8(0xE7); emit8((uint8_t)o1.disp); }
            else     { emit8(0xE7); emit8((uint8_t)o1.disp); }
            return;
        }
        unsupported("out");
        return;
    }
    if (m == "lgdt" || m == "lidt") {
        int d = (m == "lgdt") ? 2 : 3;
        if (o1.type == 3) {
            rex(false, false, false, o1.base >= 8);
            emit8(0x0F); emit8(0x01); modrm(2, d, o1.base);
            emit32((uint32_t)o1.disp);
            return;
        }
        unsupported(m.c_str());
        return;
    }

    unsupported(m.c_str());
}

void Codegen::emitAsm16Instr(const AsmInstr& instr) {
    // =====================================================================
    // 16-bit real-mode encoder (asm16 { }).
    // Default operand size = 16, 16-bit addressing modes (BX/BP/SI/DI),
    // real-mode segment registers and BIOS-oriented instructions.
    // =====================================================================
    auto trimStr = [](std::string& s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    };
    auto toLower = [](std::string s) {
        for (auto& c : s) c = (char)tolower((unsigned char)c);
        return s;
    };
    auto parseNum = [](const std::string& s) -> int64_t {
        std::string t = s;
        while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(t.begin());
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
        bool neg = false;
        if (!t.empty() && t[0] == '-') { neg = true; t.erase(t.begin()); }
        int64_t v = 0;
        try {
            if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
                v = std::stoll(t.substr(2), nullptr, 16);
            else
                v = std::stoll(t, nullptr, 10);
        } catch (...) { v = 0; }
        return neg ? -v : v;
    };
    auto isReg16 = [](const std::string& n) -> int {
        static const char* r16[8] = {"ax","cx","dx","bx","sp","bp","si","di"};
        for (int i = 0; i < 8; i++) if (n == r16[i]) return i;
        return -1;
    };
    auto isReg8 = [](const std::string& n) -> int {
        static const char* r8[8] = {"al","cl","dl","bl","ah","ch","dh","bh"};
        for (int i = 0; i < 8; i++) if (n == r8[i]) return i;
        return -1;
    };
    auto isReg32 = [](const std::string& n) -> int {
        static const char* r32[8] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
        for (int i = 0; i < 8; i++) if (n == r32[i]) return i;
        return -1;
    };
    auto isSeg = [](const std::string& n) -> int {
        static const char* seg[6] = {"es","cs","ss","ds","fs","gs"};
        for (int i = 0; i < 6; i++) if (n == seg[i]) return i;
        return -1;
    };
    auto isCr = [](const std::string& n) -> int {
        if (n.size() >= 3 && (n[0] == 'c' || n[0] == 'C') && (n[1] == 'r' || n[1] == 'R')) {
            try { return std::stoi(n.substr(2)); } catch (...) { return -1; }
        }
        return -1;
    };

    struct Mem16 { bool ok = false; int rm = 0; int mod = 0; int64_t disp = 0; int seg = -1; };
    auto parseMem = [&](const std::string& raw, Mem16& m) -> bool {
        std::string s = raw;
        trimStr(s);
        if (s.size() < 2 || s.front() != '[' || s.back() != ']') return false;
        s = s.substr(1, s.size() - 2);
        // Optional segment override "es:di" / "es:[di]"
        size_t colon = s.find(':');
        if (colon != std::string::npos) {
            std::string segName = toLower(s.substr(0, colon));
            trimStr(segName);
            int seg = isSeg(segName);
            if (seg < 0) return false;
            m.seg = seg;
            s = s.substr(colon + 1);
            trimStr(s);
        }
        bool bx = false, bp = false, si = false, di = false;
        int64_t disp = 0; bool hasDisp = false;
        int64_t sign = 1;
        std::string cur;
        auto flush = [&]() {
            trimStr(cur);
            if (cur.empty()) return;
            std::string t = toLower(cur);
            if (t == "bx") bx = true;
            else if (t == "bp") bp = true;
            else if (t == "si") si = true;
            else if (t == "di") di = true;
            else { disp += sign * parseNum(cur); hasDisp = true; }
            cur.clear();
        };
        for (char c : s) {
            if (c == '+') { flush(); sign = 1; }
            else if (c == '-') { flush(); sign = -1; }
            else cur += c;
        }
        flush();
        int nreg = (bx?1:0)+(bp?1:0)+(si?1:0)+(di?1:0);
        if (nreg > 2) return false;
        if (nreg == 2 && !((bx&&si)||(bx&&di)||(bp&&si)||(bp&&di))) return false;
        if (bx && si) m.rm = 0;
        else if (bx && di) m.rm = 1;
        else if (bp && si) m.rm = 2;
        else if (bp && di) m.rm = 3;
        else if (si) m.rm = 4;
        else if (di) m.rm = 5;
        else if (bp) m.rm = 6;
        else if (bx) m.rm = 7;
        else m.rm = 6;                       // mod=00 rm=110 -> absolute disp16
        if (nreg == 0) { m.mod = 0; m.disp = disp; }
        else if (disp == 0 && !(nreg == 1 && bp)) { m.mod = 0; m.disp = 0; }
        else if (disp >= -128 && disp <= 127)   { m.mod = 1; m.disp = disp; }
        else                                    { m.mod = 2; m.disp = disp; }
        m.ok = true;
        return true;
    };
    auto emitModrm = [&](int mod, int reg, int rm) {
        emit8((uint8_t)(((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)));
    };
    auto emitMemDisp = [&](const Mem16& m) {
        if (m.mod == 1) emit8((uint8_t)(int8_t)m.disp);
        else if (m.mod == 2) emit16((uint16_t)m.disp);
    };
    auto emitSeg = [&](const Mem16& m) {
        // Segment-override prefixes (only for the 6 real-mode segments)
        static const uint8_t segPrefix[6] = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65};
        if (m.seg >= 0 && m.seg < 6) emit8(segPrefix[m.seg]);
    };
    auto unsupported = [&](const char* what) {
        fprintf(stderr, "Warning: asm16: unsupported instruction '%s', skipped\n", what);
    };

    struct Op { int kind = 0; int reg = 0; int64_t imm = 0; Mem16 mem; };
    // kind: 0 empty, 1 = r16, 2 = r8, 3 = r32, 4 = seg, 5 = cr, 6 = imm, 7 = mem
    auto parseOp = [&](const std::string& raw, Op& op) -> bool {
        std::string s = raw;
        trimStr(s);
        if (s.empty()) { op.kind = 0; return true; }
        if (s[0] == '[') {
            op.kind = 7;
            if (!parseMem(s, op.mem)) return false;
            return true;
        }
        std::string l = toLower(s);
        int r16 = isReg16(l);
        if (r16 >= 0) { op.kind = 1; op.reg = r16; return true; }
        int r8 = isReg8(l);
        if (r8 >= 0) { op.kind = 2; op.reg = r8; return true; }
        int r32 = isReg32(l);
        if (r32 >= 0) { op.kind = 3; op.reg = r32; return true; }
        int seg = isSeg(l);
        if (seg >= 0) { op.kind = 4; op.reg = seg; return true; }
        int cr = isCr(l);
        if (cr >= 0) { op.kind = 5; op.reg = cr; return true; }
        op.kind = 6;
        op.imm = parseNum(s);
        return true;
    };

    std::string m = toLower(instr.mnemonic);
    Op a, b;
    parseOp(instr.op1, a);
    parseOp(instr.op2, b);

    if (m == "mov") {
        if (a.kind == 1 && b.kind == 1) { emit8(0x89); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 2 && b.kind == 2) { emit8(0x88); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 1 && b.kind == 6) { emit8((uint8_t)(0xB8 + a.reg)); emit16((uint16_t)b.imm); return; }
        if (a.kind == 2 && b.kind == 6) { emit8((uint8_t)(0xB0 + a.reg)); emit8((uint8_t)b.imm); return; }
        if (a.kind == 1 && b.kind == 7) { emitSeg(b.mem); emit8(0x8B); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 1) { emitSeg(a.mem); emit8(0x89); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 2 && b.kind == 7) { emitSeg(b.mem); emit8(0x8A); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 2) { emitSeg(a.mem); emit8(0x88); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 7 && b.kind == 6) { emitSeg(a.mem); emit8(0xC7); emitModrm(a.mem.mod, 0, a.mem.rm); emitMemDisp(a.mem); emit16((uint16_t)b.imm); return; }
        if (a.kind == 4 && b.kind == 1) { emit8(0x8E); emitModrm(3, a.reg, b.reg); return; }
        if (a.kind == 1 && b.kind == 4) { emit8(0x8C); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 4 && b.kind == 7) { emitSeg(b.mem); emit8(0x8E); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 4) { emitSeg(a.mem); emit8(0x8C); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 3 && b.kind == 5) { emit8(0x0F); emit8(0x20); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 5 && b.kind == 3) { emit8(0x0F); emit8(0x22); emitModrm(3, a.reg, b.reg); return; }
        unsupported("mov");
        return;
    }

    static const struct { const char* name; uint8_t m16r16; uint8_t m8r8; uint8_t r16m16; uint8_t r8m8; int ext; } ar16[] = {
        {"add",0x01,0x00,0x03,0x02,0}, {"or",0x09,0x08,0x0B,0x0A,1},
        {"adc",0x11,0x10,0x13,0x12,2}, {"sbb",0x19,0x18,0x1B,0x1A,3},
        {"and",0x21,0x20,0x23,0x22,4}, {"sub",0x29,0x28,0x2B,0x2A,5},
        {"xor",0x31,0x30,0x33,0x32,6}, {"cmp",0x39,0x38,0x3B,0x3A,7}
    };
    for (auto& ap : ar16) {
        if (m != ap.name) continue;
        if (a.kind == 1 && b.kind == 1) { emit8(ap.m16r16); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 2 && b.kind == 2) { emit8(ap.m8r8); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 1 && b.kind == 7) { emitSeg(b.mem); emit8(ap.r16m16); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 2 && b.kind == 7) { emitSeg(b.mem); emit8(ap.r8m8); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 1) { emitSeg(a.mem); emit8(ap.m16r16); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 7 && b.kind == 2) { emitSeg(a.mem); emit8(ap.m8r8); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 1 && b.kind == 6) {
            if (b.imm >= -128 && b.imm <= 127) { emit8(0x83); emitModrm(3, ap.ext, a.reg); emit8((uint8_t)b.imm); }
            else { emit8(0x81); emitModrm(3, ap.ext, a.reg); emit16((uint16_t)b.imm); }
            return;
        }
        if (a.kind == 2 && b.kind == 6) { emit8(0x80); emitModrm(3, ap.ext, a.reg); emit8((uint8_t)b.imm); return; }
        if (a.kind == 7 && b.kind == 6) {
            if (b.imm >= -128 && b.imm <= 127) { emitSeg(a.mem); emit8(0x83); emitModrm(a.mem.mod, ap.ext, a.mem.rm); emitMemDisp(a.mem); emit8((uint8_t)b.imm); }
            else { emitSeg(a.mem); emit8(0x81); emitModrm(a.mem.mod, ap.ext, a.mem.rm); emitMemDisp(a.mem); emit16((uint16_t)b.imm); }
            return;
        }
        unsupported(ap.name);
        return;
    }

    if (m == "test") {
        if (a.kind == 1 && b.kind == 1) { emit8(0x85); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 2 && b.kind == 2) { emit8(0x84); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 1 && b.kind == 7) { emit8(0x85); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 1) { emit8(0x85); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 1 && b.kind == 6) { emit8(0xF7); emitModrm(3, 0, a.reg); emit16((uint16_t)b.imm); return; }
        if (a.kind == 2 && b.kind == 6) { emit8(0xF6); emitModrm(3, 0, a.reg); emit8((uint8_t)b.imm); return; }
        if (a.kind == 7 && b.kind == 6) { emitSeg(a.mem); emit8(0xF7); emitModrm(a.mem.mod, 0, a.mem.rm); emitMemDisp(a.mem); emit16((uint16_t)b.imm); return; }
        unsupported("test");
        return;
    }

    if (m=="not"||m=="neg"||m=="inc"||m=="dec"||m=="mul"||m=="imul"||m=="div"||m=="idiv") {
        int ext = 0;
        if (m=="inc") ext = 0; else if (m=="dec") ext = 1; else if (m=="not") ext = 2;
        else if (m=="neg") ext = 3; else if (m=="mul") ext = 4; else if (m=="imul") ext = 5;
        else if (m=="div") ext = 6; else ext = 7;
        if (a.kind == 1) { emit8((m=="inc"||m=="dec")?0xFF:0xF7); emitModrm(3, ext, a.reg); return; }
        if (a.kind == 2) { emit8(0xF6); emitModrm(3, ext, a.reg); return; }
        if (a.kind == 7) {
            emitSeg(a.mem);
            if (m=="inc"||m=="dec") { emit8(0xFF); emitModrm(a.mem.mod, ext, a.mem.rm); emitMemDisp(a.mem); }
            else { emit8(0xF7); emitModrm(a.mem.mod, ext, a.mem.rm); emitMemDisp(a.mem); }
            return;
        }
        unsupported(m.c_str());
        return;
    }

    static const struct { const char* name; int ext; } shTable[] = {
        {"rol",0},{"ror",1},{"rcl",2},{"rcr",3},{"shl",4},{"sal",4},{"shr",5},{"sar",7}
    };
    for (auto& sh : shTable) {
        if (m != sh.name) continue;
        if (b.kind == 1 && b.reg == 1) {                    // count in cl
            if (a.kind == 1) { emit8(0xD3); emitModrm(3, sh.ext, a.reg); return; }
            if (a.kind == 2) { emit8(0xD2); emitModrm(3, sh.ext, a.reg); return; }
            if (a.kind == 7) { emitSeg(a.mem); emit8(0xD3); emitModrm(a.mem.mod, sh.ext, a.mem.rm); emitMemDisp(a.mem); return; }
        }
        if (b.kind == 6) {
            if (b.imm == 1) {
                if (a.kind == 1) { emit8(0xD1); emitModrm(3, sh.ext, a.reg); return; }
                if (a.kind == 2) { emit8(0xD0); emitModrm(3, sh.ext, a.reg); return; }
                if (a.kind == 7) { emitSeg(a.mem); emit8(0xD1); emitModrm(a.mem.mod, sh.ext, a.mem.rm); emitMemDisp(a.mem); return; }
            } else {
                if (a.kind == 1) { emit8(0xC1); emitModrm(3, sh.ext, a.reg); emit8((uint8_t)b.imm); return; }
                if (a.kind == 2) { emit8(0xC0); emitModrm(3, sh.ext, a.reg); emit8((uint8_t)b.imm); return; }
                if (a.kind == 7) { emitSeg(a.mem); emit8(0xC1); emitModrm(a.mem.mod, sh.ext, a.mem.rm); emitMemDisp(a.mem); emit8((uint8_t)b.imm); return; }
            }
        }
        unsupported(sh.name);
        return;
    }

    if (m == "lea") {
        if (a.kind == 1 && b.kind == 7) { emit8(0x8D); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        unsupported("lea");
        return;
    }
    if (m == "xchg") {
        if (a.kind == 1 && b.kind == 1) { emit8(0x87); emitModrm(3, b.reg, a.reg); return; }
        if (a.kind == 1 && b.kind == 7) { emitSeg(b.mem); emit8(0x87); emitModrm(b.mem.mod, a.reg, b.mem.rm); emitMemDisp(b.mem); return; }
        if (a.kind == 7 && b.kind == 1) { emitSeg(a.mem); emit8(0x87); emitModrm(a.mem.mod, b.reg, a.mem.rm); emitMemDisp(a.mem); return; }
        if (a.kind == 2 && b.kind == 2) { emit8(0x86); emitModrm(3, b.reg, a.reg); return; }
        unsupported("xchg");
        return;
    }

    if (m == "push" || m == "pop") {
        if (a.kind == 1) { emit8((uint8_t)((m=="push"?0x50:0x58)+a.reg)); return; }
        if (a.kind == 4) {
            static const uint8_t pushSeg[6] = {0x06,0x0E,0x16,0x1E,0x00,0x00};
            static const uint8_t popSeg[6]  = {0x07,0x00,0x17,0x1F,0x00,0x00};
            if (m == "push") {
                if (pushSeg[a.reg]) { emit8(pushSeg[a.reg]); return; }
                if (a.reg >= 4) { emit8(0x0F); emit8((uint8_t)(0xA0 + (a.reg - 4) * 8)); return; }
            } else {
                if (popSeg[a.reg]) { emit8(popSeg[a.reg]); return; }
                if (a.reg >= 4) { emit8(0x0F); emit8((uint8_t)(0xA1 + (a.reg - 4) * 8)); return; }
            }
            unsupported(m.c_str());
            return;
        }
        if (m == "push" && a.kind == 6) {
            if (a.imm >= -128 && a.imm <= 127) { emit8(0x6A); emit8((uint8_t)a.imm); }
            else { emit8(0x68); emit16((uint16_t)a.imm); }
            return;
        }
        unsupported(m.c_str());
        return;
    }

    if (m == "call") {
        // near call rel16 (E8), far call seg:off (9A), or call r/m16 (FF /2)
        if (a.kind == 6) {
            int64_t rel = a.imm - (int64_t)(code.size() + 3);
            emit8(0xE8); emit16((uint16_t)rel);
            return;
        }
        if (a.kind == 1) { emit8(0xFF); emitModrm(3, 2, a.reg); return; }
        if (a.kind == 7) { emitSeg(a.mem); emit8(0xFF); emitModrm(a.mem.mod, 2, a.mem.rm); emitMemDisp(a.mem); return; }
        unsupported("call");
        return;
    }

    if (m == "jmp") {
        int64_t rel = a.imm - (int64_t)(code.size() + 2);
        if (rel >= -128 && rel <= 127) { emit8(0xEB); emit8((uint8_t)rel); }
        else {
            rel = a.imm - (int64_t)(code.size() + 3);
            emit8(0xE9); emit16((uint16_t)rel);
        }
        return;
    }
    static const struct { const char* name; int cc; } jcc16[] = {
        {"jo",0x0},{"jno",0x1},{"jb",0x2},{"jc",0x2},{"jnae",0x2},{"jae",0x3},{"jnc",0x3},{"jnb",0x3},
        {"je",0x4},{"jz",0x4},{"jne",0x5},{"jnz",0x5},{"jbe",0x6},{"jna",0x6},{"ja",0x7},{"jnbe",0x7},
        {"js",0x8},{"jns",0x9},{"jp",0xA},{"jpe",0xA},{"jnp",0xB},{"jpo",0xB},{"jl",0xC},{"jnge",0xC},
        {"jge",0xD},{"jnl",0xD},{"jle",0xE},{"jng",0xE},{"jg",0xF},{"jnle",0xF}
    };
    for (auto& j : jcc16) {
        if (m != j.name) continue;
        int64_t rel = a.imm - (int64_t)(code.size() + 2);
        if (rel >= -128 && rel <= 127) { emit8((uint8_t)(0x70 + j.cc)); emit8((uint8_t)rel); }
        else {
            rel = a.imm - (int64_t)(code.size() + 4);
            emit8(0x0F); emit8((uint8_t)(0x80 + j.cc)); emit16((uint16_t)rel);
        }
        return;
    }
    if (m == "jcxz" || m == "jecxz") {
        int64_t rel = a.imm - (int64_t)(code.size() + 2);
        emit8((uint8_t)(m == "jecxz" ? 0x67 : 0xE3)); emit8((uint8_t)rel);
        return;
    }

    if (m == "int") {
        if (a.kind == 6) { emit8(0xCD); emit8((uint8_t)a.imm); return; }
        unsupported("int");
        return;
    }
    if (m == "in") {
        if (a.kind == 2 && a.reg == 0 && b.kind == 6) { emit8(0xE4); emit8((uint8_t)b.imm); return; }
        if (a.kind == 1 && a.reg == 0 && b.kind == 6) { emit8(0xE5); emit8((uint8_t)b.imm); return; }
        if (a.kind == 2 && a.reg == 0 && b.kind == 1 && b.reg == 2) { emit8(0xEC); return; }
        if (a.kind == 1 && a.reg == 0 && b.kind == 1 && b.reg == 2) { emit8(0xED); return; }
        unsupported("in");
        return;
    }
    if (m == "out") {
        if (a.kind == 6 && b.kind == 2 && b.reg == 0) { emit8(0xE6); emit8((uint8_t)a.imm); return; }
        if (a.kind == 6 && b.kind == 1 && b.reg == 0) { emit8(0xE7); emit8((uint8_t)a.imm); return; }
        if (a.kind == 1 && a.reg == 2 && b.kind == 2 && b.reg == 0) { emit8(0xEE); return; }
        if (a.kind == 1 && a.reg == 2 && b.kind == 1 && b.reg == 0) { emit8(0xEF); return; }
        unsupported("out");
        return;
    }
    if (m == "lgdt" || m == "lidt") {
        int d = (m == "lgdt") ? 2 : 3;
        if (a.kind == 7) { emit8(0x0F); emit8(0x01); emitModrm(a.mem.mod, d, a.mem.rm); emitMemDisp(a.mem); return; }
        unsupported(m.c_str());
        return;
    }
    if (m == "sgdt" || m == "sidt") {
        int d = (m == "sgdt") ? 0 : 1;
        if (a.kind == 7) { emit8(0x0F); emit8(0x01); emitModrm(a.mem.mod, d, a.mem.rm); emitMemDisp(a.mem); return; }
        unsupported(m.c_str());
        return;
    }
    if (m == "lmsw") {
        if (a.kind == 1) { emit8(0x0F); emit8(0x01); emitModrm(3, 6, a.reg); return; }
        if (a.kind == 7) { emitSeg(a.mem); emit8(0x0F); emit8(0x01); emitModrm(a.mem.mod, 6, a.mem.rm); emitMemDisp(a.mem); return; }
        unsupported("lmsw");
        return;
    }
    if (m == "smsw") {
        if (a.kind == 1) { emit8(0x0F); emit8(0x01); emitModrm(3, 4, a.reg); return; }
        unsupported("smsw");
        return;
    }

    if (m == "cli") { emit8(0xFA); return; }
    if (m == "sti") { emit8(0xFB); return; }
    if (m == "clc") { emit8(0xF8); return; }
    if (m == "stc") { emit8(0xF9); return; }
    if (m == "cmc") { emit8(0xF5); return; }
    if (m == "hlt") { emit8(0xF4); return; }
    if (m == "nop") { emit8(0x90); return; }
    if (m == "ret") { emit8(0xC3); return; }
    if (m == "retf" || m == "retn") { emit8(m == "retf" ? 0xCB : 0xC3); return; }
    if (m == "leave") { emit8(0xC9); return; }
    if (m == "iret" || m == "iretw") { emit8(0xCF); return; }
    if (m == "int3") { emit8(0xCC); return; }
    if (m == "cld") { emit8(0xFC); return; }
    if (m == "std") { emit8(0xFD); return; }
    if (m == "cbw") { emit8(0x98); return; }
    if (m == "cwd") { emit8(0x99); return; }
    if (m == "lahf") { emit8(0x9F); return; }
    if (m == "sahf") { emit8(0x9E); return; }
    if (m == "wait" || m == "fwait") { emit8(0x9B); return; }
    if (m == "movsb") { emit8(0xA4); return; }
    if (m == "movsw") { emit8(0xA5); return; }
    if (m == "cmpsb") { emit8(0xA6); return; }
    if (m == "cmpsw") { emit8(0xA7); return; }
    if (m == "stosb") { emit8(0xAA); return; }
    if (m == "stosw") { emit8(0xAB); return; }
    if (m == "lodsb") { emit8(0xAC); return; }
    if (m == "lodsw") { emit8(0xAD); return; }
    if (m == "scasb") { emit8(0xAE); return; }
    if (m == "scasw") { emit8(0xAF); return; }

    unsupported(m.c_str());
}

bool Codegen::builtinAllowed(const std::string& name) {
    // Firmware-service functions exist only when the kernel runs on top of a
    // firmware that provides them (kernel_mode: dependent). In independent
    // mode the kernel owns the hardware itself, so calling them would crash
    // (e.g. 'int 0x16' / UEFI ConIn are simply not reachable from the bare
    // long-mode kernel). Reject early with a routing suggestion instead of a
    // cryptic runtime failure.
    if (prog.kernelMode == KernelMode::Independent) {
        const bool firmware = (name.rfind("efi_", 0) == 0 || name.rfind("bios_", 0) == 0);
        // Opt-in escape hatch: with 'boot_services: manual' the kernel takes
        // over the boot-services lifetime itself, so efi_gslot() is allowed
        // strictly BEFORE its own ExitBootServices call. Everything else
        // (and this builtin without the directive) stays blocked.
        if (firmware && !(name == "efi_gslot" && prog.bootServicesManual)) {
            std::cerr << "Error: '" << name << "' requires kernel_mode: dependent "
                      << "(the kernel runs on top of BIOS/UEFI).\n"
                      << "  In kernel_mode: independent the kernel owns the hardware itself;\n"
                      << "  use the direct-hardware builtins instead:\n"
                      << "    - keyboard: kb_hit() / kb_get()   (PS/2 controller)\n"
                      << "    - display:  vga_print()/vga_putc() or gop_*/fb_* (framebuffer)\n"
                      << "    - other:    inb()/outb(), peek()/poke(), asm { ... }\n"
                      << "  Or write 'kernel_mode: dependent' to get the firmware services back.\n";
            throw std::runtime_error("kernel_mode independent blocks firmware service");
        }
    }
    return true;
}

void Codegen::computeStructLayouts() {
    structLayouts.clear();
    // Tentative layouts (offsets resolved iteratively so that struct-typed
    // fields can use the final totalSize of nested structs/classes).
    for (auto& sd : prog.structs) {
        StructLayout layout;
        layout.name = sd->name;
        layout.totalSize = 0;
        for (auto& f : sd->fields) {
            layout.fieldOffsets[f.name] = 0;
            layout.fieldTypes[f.name] = f.type;
        }
        structLayouts[sd->name] = layout;
    }
    for (int pass = 0; pass < 8; pass++) {
        bool changed = false;
        for (auto& sd : prog.structs) {
            auto it = structLayouts.find(sd->name);
            if (it == structLayouts.end()) continue;
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
                        auto nIt = structLayouts.find(f.type.structName);
                        fieldSize = (nIt != structLayouts.end()) ? nIt->second.totalSize : 8;
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

void Codegen::allocateBlockVars(const Block& block) {
    for (auto& stmt : block.stmts) {
        if (auto varDecl = dynamic_cast<VarDecl*>(stmt.get())) {
            int fieldSize = 8;
            if (varDecl->arraySize > 0) {
                int elemSize = 8;
                if (varDecl->type.kind == TypeKind::Float) elemSize = 4;
                fieldSize = elemSize * varDecl->arraySize;
            } else if (varDecl->type.kind == TypeKind::Struct) {
                auto it = structLayouts.find(varDecl->type.structName);
                if (it != structLayouts.end()) {
                    fieldSize = it->second.totalSize;
                    if (fieldSize % 8 != 0) fieldSize += 8 - (fieldSize % 8);
                }
            } else if (varDecl->type.kind == TypeKind::Bool) {
                fieldSize = 4;
            } else if (varDecl->type.kind == TypeKind::Float) {
                fieldSize = 4;
            } else if (varDecl->type.kind == TypeKind::Vec2) {
                fieldSize = 8;
            } else if (varDecl->type.kind == TypeKind::Vec3) {
                fieldSize = 12;
                if (fieldSize % 8 != 0) fieldSize += 8 - (fieldSize % 8);
            } else if (varDecl->type.kind == TypeKind::Color) {
                fieldSize = 16;
            }
            locals += fieldSize;
            VarInfo vi;
            vi.offset = -(locals);
            vi.type = varDecl->type;
            vi.isConst = varDecl->isConst;
            varInfos[varDecl->name] = vi;
        } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt.get())) {
            if (varInfos.find(forStmt->varName) == varInfos.end()) {
                locals += 8;
                VarInfo vi;
                vi.offset = -(locals);
                vi.type = {TypeKind::Int};
                varInfos[forStmt->varName] = vi;
            }
            allocateBlockVars(forStmt->body);
        } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
            allocateBlockVars(ifStmt->thenBlock);
            allocateBlockVars(ifStmt->elseBlock);
        } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt.get())) {
            allocateBlockVars(whileStmt->body);
        } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt.get())) {
            allocateBlockVars(loopStmt->body);
        } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt.get())) {
            for (auto& sc : switchStmt->cases) {
                allocateBlockVars(sc.body);
            }
        }
    }
}

void Codegen::emitFunction(FunctionDecl* func) {
    funcOffsets[func->name] = code.size();
    varInfos.clear();
    locals = 0;
    curFuncRetType = func->returnType;

    if (emitDebugInfo) {
        dbgSubprograms.push_back({func->name, code.size(), 0, func->line});
        if (func->line > 0)
            dbgLines.push_back({code.size(), func->line});
    }

    populateGlobalVarInfos();

    int paramSlot = 0;
    for (size_t i = 0; i < func->params.size(); i++) {
        int off = (int)(24 + paramSlot * 8);
        VarInfo vi;
        vi.offset = off;
        vi.type = func->params[i].type;
        varInfos[func->params[i].name] = vi;
        int slots = 1;
        if (func->params[i].type.kind == TypeKind::Struct) {
            if (func->params[i].type.isPtr) {
                slots = 1;  // a pointer (e.g. `this`) occupies a single slot
            } else {
                auto it = structLayouts.find(func->params[i].type.structName);
                if (it != structLayouts.end()) {
                    slots = (int)((it->second.totalSize + 7) / 8);
                    if (slots < 1) slots = 1;
                }
            }
        }
        paramSlot += slots;
    }

    allocateBlockVars(func->body);

    spillBase = locals + 8; // spill area starts after local vars (48 bytes for 6 regs)
    locals += 48;           // reserve spill area

    frameSize = ((locals + 15) & ~15) + 8;
    regsUsed = 0;
    xmmRegsUsed = 0;
    funcEndLabel = newLabel();

    emit8(0x55);  // push rbp
    emit8(0x53);  // push rbx (callee-saved)
    emit8(0x48); emit8(0x89); emit8(0xE5);  // mov rbp, rsp
    if (frameSize > 0) {
        if (frameSize <= 127) {
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8((uint8_t)frameSize);
        } else {
            emit8(0x48); emit8(0x81); emit8(0xEC); emit32((uint32_t)frameSize);
        }
    }

    paramSlot = 0;
    for (size_t i = 0; i < func->params.size(); i++) {
        int slots = 1;
        if (func->params[i].type.kind == TypeKind::Struct) {
            if (func->params[i].type.isPtr) {
                slots = 1;  // a pointer (e.g. `this`) occupies a single slot
            } else {
                auto it = structLayouts.find(func->params[i].type.structName);
                if (it != structLayouts.end()) {
                    slots = (int)((it->second.totalSize + 7) / 8);
                    if (slots < 1) slots = 1;
                }
            }
        }
        for (int k = 0; k < slots; k++) {
            int slot = paramSlot + k;
            int maxReg = sysvAbi ? 6 : 4;
            if (slot >= maxReg) break;  // stack bytes are copied below (SysV) / in place (Win64)
            int off = (int)(24 + slot * 8);
            if (func->params[i].type.kind == TypeKind::Float) {
                // Float params arrive in XMM0-3 (Win64) / XMM0-7 (SysV), not GP regs.
                emitFloatStoreToBP(slot, off);
            } else if (sysvAbi) {
                if (slot == 0)       { emit8(0x48); emit8(0x89); emit8(0x7D); emit8((uint8_t)(int8_t)off); } // rdi
                else if (slot == 1)  { emit8(0x48); emit8(0x89); emit8(0x75); emit8((uint8_t)(int8_t)off); } // rsi
                else if (slot == 2)  { emit8(0x48); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)off); } // rdx
                else if (slot == 3)  { emit8(0x48); emit8(0x89); emit8(0x4D); emit8((uint8_t)(int8_t)off); } // rcx
                else if (slot == 4)  { emit8(0x4C); emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)off); } // r8
                else                 { emit8(0x4C); emit8(0x89); emit8(0x4D); emit8((uint8_t)(int8_t)off); } // r9
            } else if (slot == 0) {
                emit8(0x48); emit8(0x89); emit8(0x4D); emit8((uint8_t)(int8_t)off);
            } else if (slot == 1) {
                emit8(0x48); emit8(0x89); emit8(0x55); emit8((uint8_t)(int8_t)off);
            } else if (slot == 2) {
                emit8(0x4C); emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)off);
            } else if (slot == 3) {
                emit8(0x4C); emit8(0x89); emit8(0x4D); emit8((uint8_t)(int8_t)off);
            }
        }
        // SysV: stack args (slots >= 6) have no shadow; copy from their real
        // location [rbp+24+(slot-6)*8] into the standardized param slot
        // [rbp+24+slot*8] so the body reads them uniformly via varInfo offsets.
        if (sysvAbi) {
            for (int k = 0; k < slots; k++) {
                int slot = paramSlot + k;
                int off = (int)(24 + slot * 8);
                if (slot < 6) continue;
                int srcOff = 24 + (slot - 6) * 8;
                if (func->params[i].type.kind == TypeKind::Float) {
                    // float on stack (slot>=8 first float overflow) — copy via xmm
                    emit8(0xF3); emit8(0x0F); emit8(0x10);
                    emit8(0x45); emit8((uint8_t)(int8_t)srcOff);   // movss xmm0,[rbp+srcOff]
                    emit8(0xF3); emit8(0x0F); emit8(0x11);
                    emit8(0x45); emit8((uint8_t)(int8_t)off);      // movss [rbp+off],xmm0
                } else {
                    emit8(0x48); emit8(0x8B); emit8(0x45); emit8((uint8_t)(int8_t)srcOff); // mov rax,[rbp+srcOff]
                    emit8(0x48); emit8(0x89); emit8(0x45); emit8((uint8_t)(int8_t)off);    // mov [rbp+off],rax
                }
            }
        }
        paramSlot += slots;
    }

    for (auto& stmt : func->body.stmts) {
        emitStmt(stmt.get());
    }

    if (const char* zt = getenv("ZT_DUMP")) {
        if (std::string(zt) == func->name) {
            FILE* f = fopen("code_dump.bin", "wb");
            if (f) {
                fwrite(code.data() + funcOffsets[func->name],
                       code.size() - funcOffsets[func->name], 1, f);
                fclose(f);
            }
            fprintf(stderr, "ZT_DUMP: wrote %zu bytes for %s\n",
                    code.size() - funcOffsets[func->name], func->name.c_str());
        }
    }

    emitLabel(funcEndLabel);

    if (frameSize > 0) {
        if (frameSize <= 127) {
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8((uint8_t)frameSize);
        } else {
            emit8(0x48); emit8(0x81); emit8(0xC4); emit32((uint32_t)frameSize);
        }
    }
    emit8(0x5B);  // pop rbx (callee-saved)
    emit8(0x5D);  // pop rbp
    emit8(0xC3);

    if (emitDebugInfo && !dbgSubprograms.empty())
        dbgSubprograms.back().end = code.size();
}

// =====================================================================
// Early-boot diagnostics for EFI kernels.
//
// Serial COM1 (0x3F8, 115200 8N1): works even when the video pipeline
// is dead, so a null-modem capture on real hardware shows exactly how
// far the boot chain got ("[Z1]" entry .. "[Z4]" GOP cached).
//
// ConOut OutputString: prints through the firmware console, so on a
// machine where our GOP path dies the user still SEES why instead of
// a black screen.
// =====================================================================

void Codegen::emitEfiSerialInit() {
    // 16550 init: IER=0, DLAB divisor=1 (115200), 8N1, FIFO on, MCR out2|rts|dtr
    struct { uint16_t port; uint8_t val; } seq[] = {
        {0x3F9, 0x00}, // IER
        {0x3FB, 0x80}, // LCR: DLAB on
        {0x3F8, 0x01}, // divisor low (115200 baud)
        {0x3F9, 0x00}, // divisor high
        {0x3FB, 0x03}, // LCR: 8N1, DLAB off
        {0x3FA, 0xC7}, // FCR: enable+clear FIFOs
        {0x3FC, 0x0B}, // MCR: DTR|RTS|OUT2
        {0x3F9, 0x00}, // IER again after DLAB off
    };
    for (auto& s : seq) {
        emit8(0xBA); emit32(s.port);   // mov edx, port
        emit8(0xB0); emit8(s.val);     // mov al, val
        emit8(0xEE);                   // out dx, al
    }
}

void Codegen::emitEfiSerialChar(uint8_t c) {
    emit8(0xBA); emit32(0x3FD);        // mov edx, LSR
    emit8(0xEC);                       // wait: in al,dx
    emit8(0xA8); emit8(0x20);          // test al, 0x20 (THR empty)
    emit8(0x74); emit8((uint8_t)-5);   // jz wait (back over in/test/jz)
    emit8(0xBA); emit32(0x3F8);        // mov edx, THR
    emit8(0xB0); emit8(c);             // mov al, c
    emit8(0xEE);                       // out dx, al
}

void Codegen::emitEfiSerialStr(const char* s) {
    for (; *s; ++s) emitEfiSerialChar((uint8_t)*s);
}

// TEMP DEBUG: print EAX as 8 hex digits over COM1 (clobbers eax,ecx,edx,r11d)
// The value is mirrored into r11d and rotated THERE: rotating/and-ing eax in
// place destroys the remaining digits ("and al,0xF" clears bits that later
// rotations shift into view), so the dump printed garbage after digit #2.
void Codegen::emitEfiSerialHexEax() {
    emit8(0x41); emit8(0x89); emit8(0xC3);              // mov r11d, eax (copy)
    emit8(0xB9); emit32(8);                             // mov ecx, 8
    int loopLbl = newLabel();
    int digLbl = newLabel();
    emitLabel(loopLbl);
    emit8(0x41); emit8(0xC1); emit8(0xC3); emit8(0x04); // rol r11d, 4
    emit8(0x44); emit8(0x89); emit8(0xD8);              // mov eax, r11d (REX.R only: 0x45 would make it r8d)
    emit8(0x24); emit8(0x0F);                           // and al, 0x0F
    emit8(0x3C); emit8(0x0A);                           // cmp al, 10
    emitJcc("<", digLbl);
    emit8(0x04); emit8('A' - '0' - 10);                 // add al, 7
    emitLabel(digLbl);
    emit8(0x04); emit8('0');                            // add al, '0'
    emit8(0x41); emit8(0x88); emit8(0xC2);              // mov r10b, al (save digit)
    emit8(0xBA); emit32(0x3FD);                         // mov edx, LSR
    emit8(0xEC);                                        // in al,dx
    emit8(0xA8); emit8(0x20);                           // test al, 0x20
    emit8(0x74); emit8((uint8_t)-5);                    // jz back over in/test/jz
    emit8(0xBA); emit32(0x3F8);                         // mov edx, THR
    emit8(0x44); emit8(0x88); emit8(0xD0);              // mov al, r10b
    emit8(0xEE);                                        // out dx, al
    emit8(0xFF); emit8(0xC9);                           // dec ecx
    emitJcc("!=", loopLbl);                             // jne loopLbl
}

void Codegen::emitEfiConOut(const char* ascii) {
    // rcx = ConOut = [[SystemTable]+0x40]; rdx = UTF-16 blob (appended later)
    emit8(0x48); emit8(0x8B); emit8(0x05);
    heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
    emit32(0);                                        // rax = SystemTable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x40); // rax = [rax+0x40] = ConOut
    emit8(0x48); emit8(0x89); emit8(0xC1);              // rcx = This
    emit8(0x48); emit8(0x8D); emit8(0x15);              // lea rdx, [rip + disp32]
    efiStrFixups.push_back({code.size(), ascii});
    emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // shadow space
    emit8(0xFF); emit8(0x50); emit8(0x08);              // call [rax+8] OutputString
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
}

void Codegen::emitEfiPanicTail() {
    // Give the operator ~5 seconds to read the panic line, then reset via
    // RuntimeServices->ResetSystem(EfiResetWarm) so the box lands back in
    // the boot manager instead of hanging black. Falls into cli/hlt if the
    // firmware reset returns.
    auto loadSvc = [&](uint32_t stOff) {
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);                          // rax = SystemTable
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8((uint8_t)(int8_t)stOff); // rax = services
    };
    // Stall(5_000_000) — BootServices+0xF8
    loadSvc(0x60);
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0xB9); emit32(5000000);           // mov ecx, usecs
    emit8(0x31); emit8(0xD2);               // xor edx,edx
    emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d,r8d
    emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d,r9d
    emit8(0xFF); emit8(0x90); emit32(0x000000F8);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
    // ResetSystem(EfiResetWarm=1, 0, 0, NULL) — RuntimeServices+0x68
    loadSvc(0x58);
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0xB9); emit32(1);                 // mov ecx, EfiResetWarm
    emit8(0x31); emit8(0xD2);
    emit8(0x45); emit8(0x31); emit8(0xC0);
    emit8(0x45); emit8(0x31); emit8(0xC9);
    emit8(0xFF); emit8(0x90); emit32(0x00000068);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
    // Belt and braces: never fall back into dead memory.
    emit8(0xFA);                            // cli
    int haltLbl = newLabel();
    emitLabel(haltLbl);
    emit8(0xF4);                            // hlt
    emitJmp(haltLbl);
}

void Codegen::emitEntryPoint() {
    entryPointCodeOffset = code.size();

    if (prog.appType == AppType::Bare) {
        entryPointCodeOffset = code.size();
        
        // ================================================================
        // Firmware handoff verification for kernel_mode: independent
        // ================================================================
        if (prog.kernelMode == KernelMode::Independent) {
            // TODO: Re-enable after debugging boot stub
            // Currently disabled to allow boot to work
        }
        
        bool hm = funcOffsets.count("main") > 0;
        if (hm) { emit8(0xE8); size_t fp=code.size(); emit32(0); callFixups.push_back({fp,"main"}); }
        else if (!prog.functions.empty()) { emit8(0xE8); size_t fp=code.size(); emit32(0); callFixups.push_back({fp,prog.functions[0]->name}); }
        int l = newLabel(); emitLabel(l); emit8(0xF4); emit8(0xEB); emit8(0xFC);
        return;
    }

    if (prog.appType == AppType::BIOS) {
        entryPointCodeOffset = code.size();

        // 32-bit BIOS entry: call main(), then halt forever. No OS/EFI to return to.
        bool hm = funcOffsets.count("main") > 0;
        if (hm) { emit8(0xE8); size_t fp=code.size(); emit32(0); callFixups.push_back({fp,"main"}); }
        else if (!prog.functions.empty()) { emit8(0xE8); size_t fp=code.size(); emit32(0); callFixups.push_back({fp,prog.functions[0]->name}); }
        int l = newLabel(); emitLabel(l); emit8(0xF4); emit8(0xEB); emit8(0xFC);
        return;
    }

    if (prog.appType == AppType::EFI) {
        // EFI entry point: EfiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
        // rcx = ImageHandle, rdx = SystemTable
        //
        // Boot chain hardened for real hardware:
        //   1. Save callee-saved regs we clobber (odd push count => rsp 16-aligned).
        //   2. COM1 init + stage markers (debuggable over null-modem even when
        //      the video path is dead).
        //   3. Progress printed through firmware ConOut — the operator SEES a
        //      reason on screen instead of an unexplained black screen.
        //   4. LocateProtocol(GOP) + FULL mode scan (QueryMode every index),
        //      picking the highest-resolution mode with PixelFormat <= 1.
        //   5. Framebuffer cached into win32Globals+24..48, guarded against 0.
        //   6. Fatal failure => ConOut message -> ~5s stall -> ResetSystem(warm)
        //      so the box lands back in the boot manager instead of hanging.
        emit8(0x53);                    // push rbx
        emit8(0x41); emit8(0x54);       // push r12
        emit8(0x41); emit8(0x55);       // push r13
        emit8(0x41); emit8(0x56);       // push r14
        emit8(0x41); emit8(0x57);       // push r15

        // Store ImageHandle -> win32Globals, SystemTable -> win32Globals+8
        // so the efi_*/gop_*/fb_* builtins can find them.
        emit8(0x48); emit8(0x89); emit8(0x0D);  // mov [rip+disp], rcx
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x15);  // mov [rip+disp], rdx
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);

        emitEfiSerialStr("{S0");                            // TEMP: rsp at entry
        emit8(0x48); emit8(0x89); emit8(0xE0);              // mov rax, rsp
        emitEfiSerialHexEax();
        emitEfiSerialStr(" R");
        emit8(0x48); emit8(0x8B); emit8(0x00);              // mov rax, [rsp] (ret addr)
        emitEfiSerialHexEax();
        emitEfiSerialHexEax();                              // high dword of ret
        emitEfiSerialStr(" I");
        emit8(0x48); emit8(0x8D); emit8(0x05);
        emit32(0);                                          // lea rax, [rip+0]
        emitEfiSerialHexEax();                              // low dword of rip
        emitEfiSerialStr("}");

        // ================================================================
        // Disarm the firmware watchdog timer: BS->SetWatchdogTimer(0,0,0,NULL)
        // (BootServices = [ST+0x60], SetWatchdogTimer = [BS+0x100]).
        // The firmware arms a 5-minute watchdog when the image starts; QEMU
        // smoke tests finish long before it fires, but on real hardware any
        // interactive app (key wait, game loop) gets hard-reset mid-session.
        // Must be unconditional, not just for kernel_mode independent.
        // ================================================================
        {
            emit8(0x48); emit8(0x8B); emit8(0x05);
            heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
            emit32(0);                                        // rax = SystemTable
            emit8(0x48); emit8(0x85); emit8(0xC0);            // test rax, rax
            int wdDone = newLabel();
            emitJcc("==", wdDone);
            emit8(0x4C); emit8(0x8B); emit8(0x50); emit8(0x60); // r10 = BootServices
            emit8(0x4D); emit8(0x85); emit8(0xD2);            // test r10, r10
            int wdDone2 = newLabel();
            emitJcc("==", wdDone2);
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // shadow space
            emit8(0x4C); emit8(0x89); emit8(0xD1);            // rcx = This (BS)
            emit8(0x31); emit8(0xD2);                         // edx = timeout 0
            emit8(0x45); emit8(0x31); emit8(0xC0);            // r8d = code 0
            emit8(0x45); emit8(0x31); emit8(0xC9);            // r9d = data NULL
            emit8(0x41); emit8(0xFF); emit8(0x92);            // call [r10+0x100]
            emit8(0x00); emit8(0x01); emit8(0x00); emit8(0x00);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
            emitLabel(wdDone2);
            emitLabel(wdDone);
        }

        emitEfiSerialStr("{S1");                            // TEMP: rsp after watchdog
        emit8(0x48); emit8(0x89); emit8(0xE0);
        emitEfiSerialHexEax();
        emitEfiSerialStr("}");

        // ---- early diagnostics: COM1 up + "[Z1]" entered the stub ----
        emitEfiSerialInit();
        emitEfiSerialStr("[Z1]");
        emitEfiConOut("ZenithOS: booting\r\n");

        emitEfiSerialStr("{S2");                            // TEMP: rsp after ConOut
        emit8(0x48); emit8(0x89); emit8(0xE0);
        emitEfiSerialHexEax();
        emitEfiSerialStr("}");

        int panicLbl     = newLabel();
        int gopFailLoc   = newLabel();
        int gopFailMode  = newLabel();
        int gopFailFb    = newLabel();

        // ================================================================
        // BootServices = [SystemTable + 0x60]; LocateProtocol = [BS + 0x140]
        // (the EFI_SIGNAL_EVENT slot sits between WaitForEvent and CloseEvent,
        // pushing LocateProtocol past 0x138 — verified against EDK2 UefiSpec.h).
        // GUID {9042A9DE-23DC-4A38-96FB-7ADED080516A}
        // ================================================================
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);                                          // rax = SystemTable
        emit8(0x4C); emit8(0x8B); emit8(0x50); emit8(0x60); // r10 = BootServices
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // shadow space
        size_t gopGuidLeaPos = code.size();
        emit8(0x48); emit8(0x8D); emit8(0x0D); emit32(0);   // rcx = &GOP_GUID
        emit8(0x33); emit8(0xD2);                           // rdx = NULL
        emit8(0x4C); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 16});
        emit32(0);                                          // r8 = &win32Globals+16
        emit8(0x41); emit8(0xFF); emit8(0x92);              // call [r10+0x140]
        emit8(0x40); emit8(0x01); emit8(0x00); emit8(0x00);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 0x20

        // LocateProtocol failed -> diagnose + panic-reset (never continue silently)
        emit8(0x85); emit8(0xC0);              // test eax, eax
        emitJcc("!=", gopFailLoc);
        emitEfiSerialStr("[Z2]");
        emitEfiSerialStr("{g}");                            // TEMP: got GOP ptr
        emit8(0x48); emit8(0x8B); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 16});
        emit32(0);                                          // rbx = GOP
        // mov r12,[rbx+0x18]: reg=r12 needs REX.R (0x4C); 0x49 would decode
        // as mov rsp,[r11+0x18] and destroy the stack.
        emit8(0x4C); emit8(0x8B); emit8(0x63); emit8(0x18); // r12 = [rbx+0x18]
        emitEfiSerialStr("{m}");                            // TEMP: Mode ptr
        emit8(0x45); emit8(0x8B); emit8(0x2C); emit8(0x24); // r13d = [r12] MaxMode
        emitEfiSerialStr("{M}");                            // TEMP: MaxMode read
        emitEfiSerialStr("{R");                             // TEMP: dump rsp
        emit8(0x48); emit8(0x89); emit8(0xE0);              // mov rax, rsp
        emitEfiSerialHexEax();
        emitEfiSerialStr("}");
        emit8(0x41); emit8(0x81); emit8(0xFD); emit32(256); // cmp r13d, 256 (clamp; 0xFB would be r11d)
        {
            int maxOk = newLabel();
            emitJcc("<=", maxOk);
            emit8(0x41); emit8(0xBD); emit32(256);          // mov r13d, 256
            emitLabel(maxOk);
        }
        emit8(0x45); emit8(0x8B); emit8(0x74); emit8(0x24); emit8(0x04); // r14d = [r12+4] cur idx (0x64 would be r12d)
        emit8(0x45); emit8(0x31); emit8(0xFF);              // r15d = 0 (no candidate yet)
        // Loop frame 0x60: BOTTOM 0x20 stays empty as the ABI shadow/home area
        // (a callee writes its register-home slots at [rsp_at_call .. +0x20]),
        // live slots sit above it: [rsp+0x30]=i, [+0x38]=SizeOfInfo, [+0x40]=Info.
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x60); // loop frame
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);   // i = 0

        int scanLoop = newLabel();
        int scanNext = newLabel();
        int scanFree = newLabel();
        int scanDone = newLabel();
        emitLabel(scanLoop);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x30); // eax = i
        emit8(0x44); emit8(0x39); emit8(0xE8);              // cmp eax, r13d
        emitJcc(">=", scanDone);
        // QueryMode(This=rbx, ModeNumber=i, &SizeOfInfo, &Info)
        emit8(0x48); emit8(0x89); emit8(0xD9);              // rcx = rbx
        emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x30); // edx = i
        emit8(0x4C); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38); // r8 = &sz
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x40); // r9 = &info
        emit8(0xFF); emit8(0x13);                           // call [rbx] QueryMode
        emit8(0x85); emit8(0xC0);                           // test eax, eax
        emitJcc("!=", scanNext);                            // failed -> nothing to free
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x40); // rax = Info
        emit8(0x8B); emit8(0x48); emit8(0x0C);              // ecx = PixelFormat
        emit8(0x83); emit8(0xF9); emit8(0x01);              // cmp ecx, 1
        emitJcc(">", scanFree);                             // BltOnly/unusable -> free
        emit8(0x44); emit8(0x8B); emit8(0x40); emit8(0x04); // r8d = HorizontalResolution
        emit8(0x44); emit8(0x8B); emit8(0x48); emit8(0x08); // r9d = VerticalResolution
        emit8(0x45); emit8(0x0F); emit8(0xAF); emit8(0xC1);// imul r8d, r9d (score)
        emit8(0x45); emit8(0x39); emit8(0xF8);              // cmp r8d, r15d (score vs best; 0x43 has REX.R=0 -> edi!)
        emitJcc("<=", scanFree);                            // not better -> keep old
        emit8(0x45); emit8(0x8B); emit8(0xF8);              // r15d = r8d (8B: dest=REG field! 0xC7 was r8d=r15d)
        emit8(0x44); emit8(0x8B); emit8(0x74); emit8(0x24); emit8(0x30); // r14d = i
        emitLabel(scanFree);
        // FreePool(Info) — BS->FreePool = [BS + 0x48]
        emit8(0x4C); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x40); // r10 = Info
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);                                          // rax = SystemTable
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x60); // rax = BootServices
        emit8(0x4C); emit8(0x89); emit8(0xD1);              // rcx = Info (REX.R: 0x48 would pass rdx=mode# !)
        emit8(0xFF); emit8(0x50); emit8(0x48);              // call [rax+0x48]
        emitLabel(scanNext);
        emit8(0xFF); emit8(0x44); emit8(0x24); emit8(0x30); // inc dword [rsp+0x30]
        emitJmp(scanLoop);
        emitLabel(scanDone);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x60); // drop loop frame

        emit8(0x45); emit8(0x85); emit8(0xFF);              // test r15d, r15d
        emitJcc("==", gopFailMode);                         // nothing usable found

        // SetMode(best): [GOP + 0x08]
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
        emit8(0x44); emit8(0x89); emit8(0xF2);              // edx = r14d (0xE2 would be r12d)
        emit8(0x48); emit8(0x89); emit8(0xD9);              // rcx = rbx
        emit8(0xFF); emit8(0x53); emit8(0x08);              // call [rbx+0x08]
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", gopFailMode);
        // Refresh Mode/Info and re-validate the pixel format.
        emit8(0x4C); emit8(0x8B); emit8(0x63); emit8(0x18); // r12 = [rbx+0x18] (REX.R!)
        emit8(0x49); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08); // rax = [r12+8]
        emit8(0x8B); emit8(0x48); emit8(0x0C);              // ecx = PixelFormat
        emit8(0x83); emit8(0xF9); emit8(0x01);
        emitJcc(">", gopFailMode);
        emitEfiSerialStr("[Z3]");

        // ================================================================
        // Cache framebuffer info into win32Globals+24..48
        // (layout mirrors what the gop_*/fb_* builtins read):
        //   Mode->Info         = [r12 + 0x08]           (rax)
        //   FrameBufferBase    = [r12 + 0x18]           -> +24
        //   PixelsPerScanLine  = [Info + 0x20] (*4)     -> +32
        //   HorizResolution    = [Info + 0x04]          -> +36
        //   VertResolution     = [Info + 0x08]          -> +40
        //   PixelFormat        = [Info + 0x0C]          -> +48
        //   BPP                = (PixelFormat<2)?32:0   -> +44
        // ================================================================
        // rax = Mode->Info
        emit8(0x49); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08);
        // rcx = Mode->FrameBufferBase = [r12 + 0x18]
        emit8(0x49); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x18);
        emit8(0x48); emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 24});
        emit32(0);
        // win32Globals+32 = Pitch in bytes = PixelsPerScanLine * 4
        // (some GOP drivers leave PixelsPerScanLine = 0 -> fall back to width)
        emit8(0x8B); emit8(0x48); emit8(0x20);              // ecx = PixelsPerScanLine
        int pitchUseWidth = newLabel();
        emit8(0x85); emit8(0xC9);                           // test ecx, ecx
        emitJcc("!=", pitchUseWidth);
        emit8(0x8B); emit8(0x48); emit8(0x04);              // ecx = HorizontalResolution
        emitLabel(pitchUseWidth);
        emit8(0xC1); emit8(0xE1); emit8(0x02);              // shl ecx, 2
        emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 32});
        emit32(0);
        // win32Globals+36 = Info->HorizontalResolution
        emit8(0x8B); emit8(0x48); emit8(0x04);
        emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 36});
        emit32(0);
        // win32Globals+40 = Info->VerticalResolution
        emit8(0x8B); emit8(0x48); emit8(0x08);
        emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 40});
        emit32(0);
        // win32Globals+48 = Info->PixelFormat
        emit8(0x8B); emit8(0x48); emit8(0x0C);
        emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 48});
        emit32(0);
        // win32Globals+44 = BPP = (PixelFormat < 2) ? 32 : 0
        emit8(0x33); emit8(0xD2);              // xor edx, edx
        emit8(0x83); emit8(0xF9); emit8(0x02); // cmp ecx, 2
        emit8(0x0F); emit8(0x9C); emit8(0xC2); // setl dl
        emit8(0xC1); emit8(0xE2); emit8(0x05); // shl edx, 5
        emit8(0x89); emit8(0x15);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 44});
        emit32(0);

        // Guard: a zero framebuffer base would turn the kernel's first clear
        // into writes to physical address 0 => silent triple fault => black
        // screen forever. Panic loudly instead.
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 24});
        emit32(0);
        emit8(0x48); emit8(0x85); emit8(0xC0);              // test rax, rax
        emitJcc("==", gopFailFb);

        emitEfiSerialStr("[Z4]");                           // GOP fully cached

        // Happy path: jump over the failure handlers below (they fall into
        // the panic tail, which never returns).
        int bootOk = newLabel();
        emitJmp(bootOk);

        // ---- failure paths: say WHY, then reset the machine ----
        emitLabel(gopFailLoc);
        emitEfiSerialStr("[Z1e] locate-failed\r\n");
        emitEfiConOut("ZenithOS KERNEL PANIC: GOP locate failed\r\n");
        emitJmp(panicLbl);
        emitLabel(gopFailMode);
        emitEfiSerialStr("[Z3e] no-linear-mode\r\n");
        emitEfiConOut("ZenithOS KERNEL PANIC: no linear framebuffer mode\r\n");
        emitJmp(panicLbl);
        emitLabel(gopFailFb);
        emitEfiSerialStr("[ZFb] fb-base-zero\r\n");
        emitEfiConOut("ZenithOS KERNEL PANIC: framebuffer unavailable\r\n");
        emitLabel(panicLbl);
        emitEfiPanicTail();                    // stall -> ResetSystem(warm) -> hlt

        // ================================================================
        // Happy path continues here (jumped over the failure handlers).
        //
        // For independent kernels the stub hands control to the firmware's
        // successor — us — right here via GetMemoryMap/ExitBootServices,
        // UNLESS the source opted out with 'boot_services: manual'. In that
        // case the program itself performs EBS later (after its own pre-EBS
        // work) through the uefi_call()/efi_gslot() builtins.
        // ================================================================
        emitLabel(bootOk);

        if (prog.kernelMode == KernelMode::Independent && !prog.bootServicesManual) {
            // ============================================================
            // Independent kernel: the launched .efi IS the kernel, so the
            // firmware must not linger in memory as a passive supervisor.
            // Hand over its duties right now: GetMemoryMap -> ExitBootServices.
            //
            // After a successful ExitBootServices the kernel owns all memory,
            // timers and interrupts; no boot-services call may follow (only
            // port I/O like the COM1 diagnostics). Framebuffer info cached
            // above stays valid — the linear framebuffer pages remain mapped
            // and are ours once boot services are dead.
            //
            // Spec-mandated dance: GetMemoryMap may return
            // EFI_BUFFER_TOO_SMALL (double the buffer, retry) and
            // ExitBootServices may return EFI_INVALID_PARAMETER exactly ONCE
            // per new memory map (any boot-services call in between invalidates
            // the key), so on that status we rebuild the map and retry.
            //
            // Stack frame 0x50:
            //   [rsp+0x00..0x1F] ABI shadow/home area
            //   [rsp+0x20] MapKey          (also arg5 slot is +0x28)
            //   [rsp+0x28] DescriptorVersion (u32, 5th GetMemoryMap argument)
            //   [rsp+0x30] DescriptorSize
            //   [rsp+0x38] MemoryMapSize (current request)
            // ============================================================
            int ebsRetry  = newLabel();
            int ebsGotMap = newLabel();
            int ebsDone   = newLabel();
            int ebsFail   = newLabel();

            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x50); // frame
            // requested map size: 64 KiB static scratch (see .bss mm buffer)
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24);
            emit8(0x38); emit32(0x10000);

            emitLabel(ebsRetry);
            emit8(0xC7); emit8(0x44); emit8(0x24);              // version = 0
            emit8(0x28); emit32(0);
            emit8(0x48); emit8(0x8D); emit8(0x4C); emit8(0x24);
            emit8(0x38);                                        // rcx = &Size
            emit8(0x48); emit8(0x8D); emit8(0x15);              // rdx = buffer
            heapFixups.push_back({code.size(), 0xFFFFFA00});    // mm-buf sentinel
            emit32(0);
            emit8(0x4C); emit8(0x8D); emit8(0x44); emit8(0x24);
            emit8(0x20);                                        // r8 = &MapKey
            emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24);
            emit8(0x30);                                        // r9 = &DescSize
            emit8(0x48); emit8(0x8B); emit8(0x05);              // rax = SystemTable
            heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
            emit32(0);
            emit8(0x4C); emit8(0x8B); emit8(0x50); emit8(0x60); // r10 = BootServices
            emit8(0x41); emit8(0xFF); emit8(0x52); emit8(0x38); // call [r10+0x38]
            emit8(0x85); emit8(0xC0);                           // test eax, eax
            emitJcc("==", ebsGotMap);
            emit8(0x83); emit8(0xF8); emit8(0x05);              // BUFFER_TOO_SMALL?
            emitJcc("!=", ebsFail);
            emit8(0x48); emit8(0xD1); emit8(0x64); emit8(0x24);
            emit8(0x38);                                        // Size *= 2
            emitJmp(ebsRetry);

            emitLabel(ebsGotMap);
            emit8(0x48); emit8(0x8B); emit8(0x0D);              // rcx = ImageHandle
            heapFixups.push_back({code.size(), win32GlobalsRVA});
            emit32(0);
            emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = MapKey
            emit8(0x48); emit8(0x8B); emit8(0x05);              // rax = SystemTable
            heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
            emit32(0);
            emit8(0x4C); emit8(0x8B); emit8(0x50); emit8(0x60); // r10 = BootServices
            emit8(0x41); emit8(0xFF); emit8(0x92);              // call [r10+0xE8]
            emit32(0x000000E8);                                 //  ExitBootServices
            emit8(0x85); emit8(0xC0);
            emitJcc("==", ebsDone);
            emit8(0x83); emit8(0xF8); emit8(0x02);              // INVALID_PARAMETER
            emitJcc("==", ebsRetry);                            // stale key -> retry

            emitLabel(ebsFail);
            emitEfiSerialStr("[ZEb] exit-bs-failed\r\n");
            emitEfiConOut("ZenithOS WARNING: ExitBootServices failed; firmware stays resident\r\n");
            emitLabel(ebsDone);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x50); // drop frame
        }

        // GOP GUID blob lives in the code stream after this entry point's `ret`.
        // Patch the lea displacement now that we know the final layout position.
        {
            static const uint8_t efiGopGuid[16] = {
                0xDE, 0xA9, 0x42, 0x90, 0xDC, 0x23, 0x38, 0x4A,
                0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A
            };
            gopGuidBlob.assign(efiGopGuid, efiGopGuid + 16);
        }

        emitGlobalInit();

        bool hasMain = funcOffsets.count("main") > 0;
        if (hasMain) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, "main"});
        } else if (!prog.functions.empty()) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, prog.functions[0]->name});
        }

        // Return path depends on kernel mode:
        //  - dependent: restore callee-saved regs and return EFI_SUCCESS into
        //    the still-alive firmware (we never touched boot services).
        //  - independent: boot services are already dead at this point
        //    (either stub-performed above or program-performed via
        //    'boot_services: manual'). Falling back into the firmware runs
        //    its exit path on freed boot-services memory -> #GP. The kernel
        //    owns the machine now: mask interrupts and hlt forever.
        if (prog.kernelMode == KernelMode::Independent) {
            emit8(0xFA);               // cli
            emit8(0xF4);               // hlt
            emit8(0xEB); emit8(0xFE);  // jmp $-2  (halt loop)
        } else {
            emit8(0x33); emit8(0xC0);  // xor eax, eax
            emit8(0x41); emit8(0x5F);  // pop r15
            emit8(0x41); emit8(0x5E);  // pop r14
            emit8(0x41); emit8(0x5D);  // pop r13
            emit8(0x41); emit8(0x5C);  // pop r12
            emit8(0x5B);               // pop rbx
            emit8(0xC3);               // ret
        }

        // Append the GOP GUID blob right after the entry point and fix the
        // lea displacement emitted above (text section never moves, so the
        // RIP-relative offset is stable).
        if (!gopGuidBlob.empty()) {
            size_t blobPos = code.size();
            int32_t disp = (int32_t)(blobPos - (gopGuidLeaPos + 7));
            code[gopGuidLeaPos + 3] = (uint8_t)(disp & 0xFF);
            code[gopGuidLeaPos + 4] = (uint8_t)((disp >> 8) & 0xFF);
            code[gopGuidLeaPos + 5] = (uint8_t)((disp >> 16) & 0xFF);
            code[gopGuidLeaPos + 6] = (uint8_t)((disp >> 24) & 0xFF);
            code.insert(code.end(), gopGuidBlob.begin(), gopGuidBlob.end());
        }

        // Append the ConOut UTF-16 string blobs and patch their leas.
        // (efiStrFixups records positions AFTER the 3 opcode bytes.)
        for (auto& sf : efiStrFixups) {
            size_t blobPos = code.size();
            int32_t disp = (int32_t)(blobPos - (int64_t)(sf.codePos + 4));
            code[sf.codePos + 0] = (uint8_t)(disp & 0xFF);
            code[sf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[sf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[sf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
            for (const char* p = sf.text.c_str(); *p; ++p) {
                code.push_back((uint8_t)*p);
                code.push_back(0);
            }
            code.push_back(0); code.push_back(0);  // L'\0'
        }
        efiStrFixups.clear();
        return;
    }

    if (!embeddedDLLs.empty()) {
        // Extra stack space for loader (CreateFileA has 7 params, needs stack space)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x58); // sub rsp, 0x58
        emitEmbeddedLoader();
    } else {
        // sub rsp, 0x28: 32 bytes shadow space + 8 alignment padding
        // (entry rsp has 8 mod 16 from OS call; sub 0x28 → rsp 0 mod 16 for calling main)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
    }

    emitGlobalInit();

    bool hasMain = funcOffsets.count("main") > 0;

    if (prog.appType == AppType::GUI) {
        // Call main first
        if (hasMain) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, "main"});
        } else if (!prog.functions.empty()) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, prog.functions[0]->name});
        }

        // Save exit code, register VEH handler just before ExitProcess
        // VEH catches D3D11/DXGI cleanup exceptions during DLL_PROCESS_DETACH
        emit8(0x89); emit8(0xC3);  // mov ebx, eax (save exit code, callee-saved)
        emit8(0xB9); emit32(1);    // mov ecx, 1 (First = add as first handler)
        emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip + handler]
        size_t leaDispPos = code.size();
        emit32(0);  // placeholder
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "AddVectoredExceptionHandler", "kernel32.dll"});
        emit32(0);

        // ExitProcess(exitCode)
        emit8(0x89); emit8(0xD9);  // mov ecx, ebx (restore exit code)
        emit8(0xFF); emit8(0x15);
        entryExitProcessFixup = code.size();
        emit32(0);

        // --- VEH Handler ---
        size_t handlerStart = code.size();
        int32_t handlerDisp = (int32_t)(handlerStart - (leaDispPos + 4));
        code[leaDispPos]     = (uint8_t)(handlerDisp & 0xFF);
        code[leaDispPos + 1] = (uint8_t)((handlerDisp >> 8) & 0xFF);
        code[leaDispPos + 2] = (uint8_t)((handlerDisp >> 16) & 0xFF);
        code[leaDispPos + 3] = (uint8_t)((handlerDisp >> 24) & 0xFF);

        // Suppress ALL exceptions during DLL cleanup (process is exiting anyway)
        emit8(0xB8); emit32(0xFFFFFFFF);  // mov eax, -1 (EXCEPTION_CONTINUE_EXECUTION)
        emit8(0xC3);                       // ret

    } else {
        if (hasMain) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, "main"});
        } else if (!prog.functions.empty()) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            callFixups.push_back({fixupPos, prog.functions[0]->name});
        } else {
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 0x28
            emit8(0x33); emit8(0xC9);  // xor ecx, ecx
        }

        emit8(0x8B); emit8(0xC8);  // mov ecx, eax (exit code)
        emit8(0xFF); emit8(0x15);
        entryExitProcessFixup = code.size();
        emit32(0);
    }
}

void Codegen::generate(const std::string& outputPath) {
    generateWide(safeNarrowToPath(outputPath).wstring());
}


void Codegen::generateWide(const std::wstring& outputPath) {
    outputDir = std::filesystem::path(outputPath).parent_path();

    // Enforce per-target inline-asm width rules before any backend runs.
    validateAsmWidths(prog);

    // Linux target (app linux): select the SysV ABI and the ELF backend.
    // Everything downstream (register staging, parameter loading, extern
    // calls, entry point, final output) branches on isLinux/sysvAbi so
    // 'app linux' never produces a Windows PE binary.
    if (prog.appType == AppType::Linux) {
        isLinux = true;
        sysvAbi = true;
    }

    // ================================================================
    // STM32 (app stm32): flat Cortex-M Thumb-2 firmware image.
    // This backend is fully self-contained (see codegen_stm32.cpp) and
    // does not share any of the x86 RVA/section infrastructure below.
    // ================================================================
    if (prog.appType == AppType::STM32) {
        std::string narrowOut = wideToNarrow(outputPath);
        compileStm32(narrowOut);
        return;
    }

    if (prog.appType == AppType::ARM64) {
        std::string narrowOut = wideToNarrow(outputPath);
        compileArm64(narrowOut);
        return;
    }

    // ================================================================
    // WASM (app wasm): WebAssembly binary module. Self-contained backend
    // (see codegen_wasm.cpp); uses none of the x86 infrastructure below.
    // ================================================================
    if (prog.appType == AppType::WASM) {
        std::string narrowOut = wideToNarrow(outputPath);
        compileWasm(narrowOut);
        return;
    }

    computeStructLayouts();
    collectStrings();
    computeSectionRVAs();

    // ================================================================
    // Pure 16-bit real-mode boot image (asm_word_size: 16).
    // Emitted entirely in 16-bit real-mode encoding — no PE, no RVA table.
    // The BIOS already runs in 16-bit mode; a UEFI trampoline switches down
    // and far-jumps here. See codegen_real16.cpp.
    // ================================================================
    if (prog.real16) {
        emitReal16Entry();
        for (auto& func : prog.functions) {
            if (!func->isExtern) emitReal16Function(func.get());
        }
        {
            std::string narrowOut = wideToNarrow(outputPath);
            writeReal16Image(narrowOut);
        }
        return;
    }

    // buildImportData builds .rdata/.data layouts (string pool, win32 globals, heap state).
    // It is required for ALL app types — EFI and Bare also reference the string pool and
    // win32 globals (efi_print/vga_print), which previously stayed at RVA 0 (garbage).
    // Detect network builtin usage first so wininet imports / net state / buffer are allocated.
    detectNetworkUsage();
    detectNetSockUsage();
    detectSoundUsage();
    detectTlsUsage();
    detectJsUsage();
    detectVkUsage();
    detectWLUsage();
    buildImportData();

    if (prog.appType == AppType::GUI) {
        emitWndProc();
    }

    for (auto& func : prog.functions) {
        if (!func->isExtern) {
            emitFunction(func.get());
        }
    }

    if (libOutput) {
        emitDllEntryPoint();
        for (auto& func : prog.functions) {
            if (!func->isExtern) {
                ExportEntry ee;
                ee.name = func->name;
                ee.funcRVA = textRVA + (uint32_t)funcOffsets[func->name];
                exportEntries.push_back(ee);
            }
        }
    } else if (isLinux && prog.koDriver) {
        // Kernel-module mode: append init_module/cleanup_module wrappers (the
        // module loader, not a _start stub, invokes them).
        emitKOEntry();
    } else if (isLinux) {
        // Linux entry point + startup relocator (resolves OS imports via
        // dlopen/dlsym into the GOT, then calls user main / first function).
        emitLinuxEntryPoint();
        emitStartupRelocator();
    } else {
        emitEntryPoint();
    }

    // Append the TLS crypto blob to the end of .text (Windows PE apps only).
    // Must run before resolveFixups/resolveJmpFixups so `call rel32` sites into
    // the blob (tls_* builtins, and the JS engine's TLS host callbacks) resolve
    // against the final code layout.
    if ((tlsUsed || jsUsed) && !libOutput) {
        emitTlsBlob();
    }

    // Append the JS interpreter blob (code + zeroed 4 MiB arena) to the end of
    // .text. Also must precede resolveJmpFixups. .text is made RWX by jsUsed.
    if (jsUsed && !libOutput) {
        emitJsBlob();
    }

    fixupSectionRVAs();

    // Kernel-module mode: skip all the RVA/absolute-resolution machinery. The
    // driver object is emitted as a relocatable ELF64 (ET_REL) and finished by
    // buildKO() (modpost + gcc + ld -r) with kernel-headers tooling.
    if (prog.koDriver) {
        std::string narrowOut = wideToNarrow(outputPath);
        buildKO(narrowOut);
        return;
    }

    resolveFixups();
    resolveJmpFixups();

    // buildImportData() built the string pool (stringOffsets) BEFORE function
    // codegen, but some builtins (http_json's pretty-print) add strings to
    // stringPool during codegen. Append those late strings to .rdata and extend
    // stringOffsets so the strFixups patching in buildPE resolves correctly.
    if (stringPool.size() > stringOffsets.size()) {
        uint32_t poolStart = stringRVA - rdataRVA;
        for (size_t i = stringOffsets.size(); i < stringPool.size(); i++) {
            stringOffsets.push_back((uint32_t)rdata.size() - poolStart);
            for (char c : stringPool[i]) rdata.push_back((uint8_t)c);
            rdata.push_back(0);
        }
        while (rdata.size() % 16 != 0) rdata.push_back(0);
    }

    // Build export directory AFTER fixupSectionRVAs so RVAs are final
    if (libOutput) {
        buildExportDir();

        // Re-check section overlap after export dir may have grown .rdata
        uint32_t newRdataEnd = rdataRVA + (((uint32_t)rdata.size() + 0xFFF) & ~0xFFF);
        if (dataRVA < newRdataEnd) {
            dataRVA = newRdataEnd;
        }
    }

    // Convert wide output path back to narrow for buildPE
    {
        std::string narrowOut = wideToNarrow(outputPath);
        bool builtContainer = false;
        uint64_t imageBase = 0;
        if (prog.appType == AppType::BIOS) {
            writeBiosFlatImage(narrowOut);
        } else if (prog.appType == AppType::Bare || flatOutput) {
            writeBareFlatImage(narrowOut);
        } else if (prog.appType == AppType::Linux) {
            // Native Linux ELF64 (never a PE). Requires the SysV ABI and a
            // Linux-specific entry point / relocator emitted before this point.
            buildELF(narrowOut);
            builtContainer = true;
            imageBase = 0x400000;   // LOAD_BASE from codegen_elf.cpp
        } else {
            buildPE(narrowOut);
            builtContainer = true;
            if (prog.appType == AppType::EFI) {
                imageBase = 0x10000000;                       // EDK2-convention base
            } else {
                imageBase = (wordSize == 32) ? 0x400000u : 0x140000000ull;
            }
        }
        // DWARF debug sidecar: separate file, the compiled binary (which may be
        // a fixed-size firmware/boot image) stays byte-for-byte unchanged.
        if (builtContainer && emitDebugInfo) writeDebugInfo(imageBase, narrowOut);
    }
}
