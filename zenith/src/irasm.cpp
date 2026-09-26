#include "irasm.h"
#include "iralloc.h"
#include "x86emit.h"
#include <vector>
#include <unordered_map>
#include <string>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>

using namespace x86e;

// ====================================================================
// IRAsm implementation
// ====================================================================

struct AsmCtx {
    IRProgram& ir;
    std::vector<uint8_t> code;
    std::vector<uint8_t> rdata;
    std::vector<uint8_t> data;

    // ---- fixups ----
    struct Fix {
        enum Kind { Rip, IAT, Call, Jmp, DataStr64 } kind;
        size_t pos = 0;            // in .text for rel32 kinds, in .data for DataStr64
        int strIdx = -1;
        std::string name;
        int label = -1;
        int64_t off = 0;
    };
    std::vector<Fix> fixes;
    std::vector<size_t> labelPos;       // label id -> .text offset
    std::unordered_map<std::string, size_t> funcOff;
    std::unordered_map<std::string, size_t> globalOff;
    std::unordered_map<std::string, size_t> iatOff;
    std::unordered_map<int, size_t> strOff;
    std::unordered_map<std::string, int> globalStrIdx;   // string global -> pool idx
    size_t newlineOff = 0;
    size_t writtenOff = 0;
    size_t numBufOff = 0;
    size_t fconstTenOff = 0;
    size_t fnegSignOff = 0;

    // ---- imports (dll, func) ----
    std::vector<std::pair<std::string, std::string>> imports;

    // ---- layout ----
    static constexpr uint32_t kTextRVA = 0x1000;
    static constexpr uint64_t kImageBase = 0x140000000ULL;
    uint32_t rdataRVA = 0;
    uint32_t dataRVA = 0;
    uint32_t entryOff = 0;
    uint32_t importDirRVA = 0;
    uint32_t importDirSize = 0;

    // internal label ids for runtime helpers (far away from IR label ids)
    int nextLocalLabel = 1 << 20;
    std::unordered_map<std::string, size_t> localLabelOff;

    AsmCtx(IRProgram& p) : ir(p) {}

    void ensureLabel(int id) {
        if ((int)labelPos.size() <= id) labelPos.resize(id + 1, (size_t)-1);
    }
    int newLocalLabel() { return nextLocalLabel++; }

    int slotDisp(int slot, int off = 0, int callK = 0) {
        if (off < 0) off = 0;   // -1 means "no offset" (irgen default label)
        return 32 + callK + slot * 8 + off;
    }

    void addRipFix(size_t pos, const std::string& name, int str = -1, int64_t off = 0) {
        Fix f; f.kind = Fix::Rip; f.pos = pos; f.name = name; f.strIdx = str; f.off = off;
        fixes.push_back(f);
    }
    void addIatFix(size_t pos, const std::string& name) {
        Fix f; f.kind = Fix::IAT; f.pos = pos; f.name = name;
        fixes.push_back(f);
    }
    void addCallFix(size_t pos, const std::string& name) {
        Fix f; f.kind = Fix::Call; f.pos = pos; f.name = name;
        fixes.push_back(f);
    }
    void addJmpFix(size_t pos, int label) {
        Fix f; f.kind = Fix::Jmp; f.pos = pos; f.label = label;
        fixes.push_back(f);
    }
    void addDataStrFix(size_t pos, int strIdx) {
        Fix f; f.kind = Fix::DataStr64; f.pos = pos; f.strIdx = strIdx;
        fixes.push_back(f);
    }

    // dedup imports by function name
    int importSlot(const std::string& dll, const std::string& func) {
        for (size_t i = 0; i < imports.size(); i++)
            if (imports[i].second == func) return (int)i;
        imports.push_back({ dll, func });
        return (int)imports.size() - 1;
    }
};

// ====================================================================
// runtime helpers (kernel32 via IAT)
// ====================================================================
// infer system DLL for imports declared without an explicit 'from "..."' clause
static std::string mapFuncToDll(const std::string& fn) {
    if (fn == "ExitProcess" || fn == "GetStdHandle" || fn == "WriteFile" ||
        fn == "ReadFile" || fn == "HeapAlloc" || fn == "HeapFree" ||
        fn == "GetProcessHeap" || fn == "GetModuleHandleA" ||
        fn == "Sleep") return "kernel32.dll";
    if (fn.find("CreateWindowEx") == 0 || fn.find("DefWindowProc") == 0 ||
        fn.find("RegisterClass") == 0 || fn.find("DestroyWindow") == 0 ||
        fn.find("GetDC") == 0 || fn.find("PeekMessageA") == 0 ||
        fn.find("TranslateMessage") == 0 || fn.find("DispatchMessageA") == 0 ||
        fn.find("GetAsyncKeyState") == 0 || fn.find("PostQuitMessage") == 0 ||
        fn.find("LoadCursorA") == 0) return "user32.dll";
    if (fn.find("CreateDIBSection") == 0 || fn.find("BitBlt") == 0 ||
        fn.find("SelectObject") == 0 || fn.find("DeleteObject") == 0 ||
        fn.find("CreateCompatibleDC") == 0) return "gdi32.dll";
    return "kernel32.dll";
}

static void emitRuntimeHelpers(AsmCtx& ctx) {
    Em e(ctx.code);
    ctx.importSlot("kernel32.dll", "GetStdHandle");
    ctx.importSlot("kernel32.dll", "WriteFile");

    // ---- zt_write_out(rcx = ptr, rdx = len): WriteFile to stdout ----
    ctx.funcOff["__zt_write_out"] = ctx.code.size();
    e.push_r(R_RBX);
    e.push_r(R_RSI);
    e.push_r(R_R12);
    e.push_r(R_R13);
    e.push_r(R_R14);
    e.push_r(R_R15);
    e.mov_r64_reg(R_RBX, R_RCX);                 // rbx = ptr
    e.mov_r64_reg(R_RSI, R_RDX);                 // rsi = len
    e.mov_r32_imm(R_RCX, (uint32_t)-11);         // ecx = STD_OUTPUT_HANDLE
    e.sub_rsp_imm(40);                           // align + shadow
    e.call_rip(0); ctx.addIatFix(ctx.code.size() - 4, "GetStdHandle");
    e.add_rsp_imm(40);
    e.mov_r64_reg(R_RCX, R_RAX);                 // h = GetStdHandle(...)
    e.mov_r64_reg(R_RDX, R_RBX);                 // ptr
    e.mov_r64_reg(R_R8, R_RSI);                  // len
    e.lea_r64_rip(R_R9, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_written");
    e.sub_rsp_imm(40);
    e.mov_mem_imm64(4, 32, 0);                   // [rsp+32] = 0 (lpOverlapped)
    e.call_rip(0); ctx.addIatFix(ctx.code.size() - 4, "WriteFile");
    e.add_rsp_imm(40);
    e.pop_r(R_R15);
    e.pop_r(R_R14);
    e.pop_r(R_R13);
    e.pop_r(R_R12);
    e.pop_r(R_RSI);
    e.pop_r(R_RBX);
    e.ret();

    // ---- zt_print_string(rcx = ptr): print NUL-terminated string + CRLF ----
    ctx.funcOff["__zt_print_string"] = ctx.code.size();
    e.push_r(R_RBX);
    e.push_r(R_RSI);
    e.push_r(R_RDI);
    e.push_r(R_R12);
    e.push_r(R_R13);
    e.push_r(R_R14);
    e.push_r(R_R15);
    e.mov_r64_reg(R_RSI, R_RCX);                 // rsi = ptr
    e.xor_reg32(R_RDI);                          // rdi = 0
    int loopLbl = ctx.newLocalLabel();
    int doneLbl = ctx.newLocalLabel();
    ctx.localLabelOff["__slen_loop"] = ctx.code.size();
    ctx.ensureLabel(loopLbl);
    ctx.labelPos[loopLbl] = ctx.code.size();
    e.cmp_byte_sib0(R_RDI, R_RSI);               // cmp byte [rsi+rdi], 0
    e.jcc_rel(0x84, 0); ctx.addJmpFix(ctx.code.size() - 4, doneLbl);   // jz done
    e.inc_reg32(R_RDI);
    e.jmp_rel(0); ctx.addJmpFix(ctx.code.size() - 4, loopLbl);
    ctx.ensureLabel(doneLbl);
    ctx.labelPos[doneLbl] = ctx.code.size();
    e.mov_r64_reg(R_RCX, R_RSI);
    e.mov_r64_reg(R_RDX, R_RDI);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.lea_r64_rip(R_RCX, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_newline");
    e.mov_r32_imm(R_RDX, 2);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.pop_r(R_R15);
    e.pop_r(R_R14);
    e.pop_r(R_R13);
    e.pop_r(R_R12);
    e.pop_r(R_RDI);
    e.pop_r(R_RSI);
    e.pop_r(R_RBX);
    e.ret();
    (void)ctx.localLabelOff["__slen_loop"];

    // ---- zt_print_int(rcx = value): print decimal int + CRLF ----
    ctx.funcOff["__zt_print_int"] = ctx.code.size();
    e.push_r(R_RBX);
    e.push_r(R_RSI);
    e.push_r(R_RDI);
    e.push_r(R_R12);
    e.push_r(R_R13);
    e.push_r(R_R14);
    e.push_r(R_R15);
    e.mov_r64_reg(R_RSI, R_RCX);                 // rsi = value
    e.lea_r64_rip(R_RDI, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_num_buf", -1, 31);
    e.mov_byte_reg_imm(R_RDI, 0);                // buf[31] = 0
    e.mov_r64_reg(R_RAX, R_RSI);
    e.mov_r64_imm32(R_RBX, 10);
    e.test_r64_reg(R_RAX, R_RAX);
    int digLbl = ctx.newLocalLabel();
    int nosignLbl = ctx.newLocalLabel();
    e.jcc_rel(0x89, 0); ctx.addJmpFix(ctx.code.size() - 4, digLbl);   // jns digits
    e.f7_reg(3, R_RAX);                          // neg rax
    ctx.ensureLabel(digLbl);
    ctx.labelPos[digLbl] = ctx.code.size();
    e.xor_reg32(R_RDX);
    e.f7_reg(6, R_RBX);                          // div rbx -> rax = quot, rdx = rem
    e.add_byte_imm(R_RDX, (uint8_t)'0');
    e.dec_reg64(R_RDI);
    e.b(0x88); e.modrm(0, R_RDX, R_RDI);          // mov byte [rdi], dl
    e.test_r64_reg(R_RAX, R_RAX);
    e.jcc_rel(0x85, 0); ctx.addJmpFix(ctx.code.size() - 4, digLbl);   // jnz digits
    e.mov_r64_reg(R_RAX, R_RSI);
    e.test_r64_reg(R_RAX, R_RAX);
    e.jcc_rel(0x89, 0); ctx.addJmpFix(ctx.code.size() - 4, nosignLbl); // jns nosign
    e.dec_reg64(R_RDI);
    e.mov_byte_reg_imm(R_RDI, (uint8_t)'-');
    ctx.ensureLabel(nosignLbl);
    ctx.labelPos[nosignLbl] = ctx.code.size();
    e.lea_r64_rip(R_RAX, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_num_buf", -1, 31);
    e.sub_r64_reg(R_RAX, R_RDI);                 // len = end - ptr
    e.mov_r64_reg(R_RCX, R_RDI);
    e.mov_r64_reg(R_RDX, R_RAX);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.lea_r64_rip(R_RCX, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_newline");
    e.mov_r32_imm(R_RDX, 2);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.pop_r(R_R15);
    e.pop_r(R_R14);
    e.pop_r(R_R13);
    e.pop_r(R_R12);
    e.pop_r(R_RDI);
    e.pop_r(R_RSI);
    e.pop_r(R_RBX);
    e.ret();

    // ---- zt_print_digits(rcx = value): print unsigned decimal, no newline ----
    ctx.funcOff["__zt_print_digits"] = ctx.code.size();
    e.push_r(R_RBX);
    e.push_r(R_RSI);
    e.push_r(R_RDI);
    e.push_r(R_R12);
    e.push_r(R_R13);
    e.push_r(R_R14);
    e.push_r(R_R15);
    e.mov_r64_reg(R_RSI, R_RCX);                 // rsi = value
    e.lea_r64_rip(R_RDI, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_num_buf", -1, 31);
    e.mov_r64_reg(R_RAX, R_RSI);
    e.mov_r64_imm32(R_RBX, 10);
    int udigLbl = ctx.newLocalLabel();
    ctx.ensureLabel(udigLbl);
    ctx.labelPos[udigLbl] = ctx.code.size();
    e.xor_reg32(R_RDX);
    e.f7_reg(6, R_RBX);                          // div rbx -> rax=quot, rdx=rem
    e.add_byte_imm(R_RDX, (uint8_t)'0');
    e.dec_reg64(R_RDI);
    e.b(0x88); e.modrm(0, R_RDX, R_RDI);          // mov byte [rdi], dl
    e.test_r64_reg(R_RAX, R_RAX);
    e.jcc_rel(0x85, 0); ctx.addJmpFix(ctx.code.size() - 4, udigLbl);  // jnz digits
    e.lea_r64_rip(R_RAX, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_num_buf", -1, 31);
    e.sub_r64_reg(R_RAX, R_RDI);                 // len = end - ptr
    e.mov_r64_reg(R_RCX, R_RDI);
    e.mov_r64_reg(R_RDX, R_RAX);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.pop_r(R_R15);
    e.pop_r(R_R14);
    e.pop_r(R_R13);
    e.pop_r(R_R12);
    e.pop_r(R_RDI);
    e.pop_r(R_RSI);
    e.pop_r(R_RBX);
    e.ret();

    // ---- zt_print_float(rcx = float bits): print decimal + CRLF ----
    ctx.funcOff["__zt_print_float"] = ctx.code.size();
    e.push_r(R_RBX);
    e.push_r(R_RSI);
    e.push_r(R_RDI);
    e.push_r(R_R12);
    e.push_r(R_R13);
    e.push_r(R_R14);
    e.push_r(R_R15);
    e.sub_rsp_imm(48);                           // staging + shadow space ([rsp+32] = persistent float)
    e.mov_r32_reg(R_RBX, R_RCX);                 // rbx = float bits (zero-extended)
    e.mov_r64_reg(R_RAX, R_RBX);
    e.shift_imm_reg(5, R_RAX, 31);               // shr rax, 31 -> sign bit
    int negLbl = ctx.newLocalLabel();
    int fracLbl = ctx.newLocalLabel();
    int fracDoneLbl = ctx.newLocalLabel();
    e.test_r64_reg(R_RAX, R_RAX);
    e.jcc_rel(0x84, 0); ctx.addJmpFix(ctx.code.size() - 4, negLbl);   // jz skip '-'
    e.mov_byte_reg_imm(4, (uint8_t)'-');         // [rsp] = '-'
    e.lea_r64_mem(R_RCX, 4, 0);
    e.mov_r32_imm(R_RDX, 1);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    ctx.ensureLabel(negLbl);
    ctx.labelPos[negLbl] = ctx.code.size();
    e.and_r32_imm(R_RBX, 0x7FFFFFFF);            // ebx = positive bits
    e.mov_mem_r32(4, 4, R_RBX);                  // [rsp+4] = positive bits
    e.movss_xmm_mem(0, 4, 4);                    // xmm0 = value
    e.movss_mem_xmm(4, 32, 0);                   // [rsp+32] = value (survives calls)
    e.cvttss2si(R_RAX, 4, 4);                    // rax = (int64)value
    e.mov_r64_reg(R_RSI, R_RAX);                 // rsi = intpart
    e.mov_r64_reg(R_RCX, R_RAX);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_print_digits");
    e.mov_byte_reg_imm(4, (uint8_t)'.');         // [rsp] = '.'
    e.lea_r64_mem(R_RCX, 4, 0);
    e.mov_r32_imm(R_RDX, 1);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.movss_xmm_mem(0, 4, 32);                   // xmm0 = value (reload)
    e.mov_mem_r64(4, 8, R_RSI);                  // [rsp+8] = intpart
    e.cvtsi2ss(1, 4, 8);                         // xmm1 = (float)intpart
    e.subss(0, 1);                               // xmm0 = frac
    e.movss_mem_xmm(4, 32, 0);                   // [rsp+32] = frac
    e.mov_r32_imm(R_RDI, 0);                     // digit count
    ctx.ensureLabel(fracLbl);
    ctx.labelPos[fracLbl] = ctx.code.size();
    e.movss_xmm_mem(0, 4, 32);                   // xmm0 = frac (reload)
    e.movss_xmm_rip(1, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_fconst_ten");
    e.mulss(0, 1);                               // frac *= 10
    e.movss_mem_xmm(4, 4, 0);
    e.cvttss2si(R_RAX, 4, 4);                    // rax = digit
    e.mov_mem_r64(4, 8, R_RAX);
    e.cvtsi2ss(1, 4, 8);
    e.subss(0, 1);                               // frac -= digit
    e.movss_mem_xmm(4, 32, 0);                   // [rsp+32] = new frac
    e.add_byte_imm(R_RAX, (uint8_t)'0');         // al = '0'+digit
    e.mov_mem_r8(4, 0);                          // [rsp] = al
    e.lea_r64_mem(R_RCX, 4, 0);
    e.mov_r32_imm(R_RDX, 1);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.inc_reg32(R_RDI);
    e.mov_r32_mem(R_RAX, 4, 32);                 // rax = frac bits
    e.test_r64_reg(R_RAX, R_RAX);
    e.jcc_rel(0x84, 0); ctx.addJmpFix(ctx.code.size() - 4, fracDoneLbl);  // jz done
    e.cmp_r64_imm32(R_RDI, 6);
    e.jcc_rel(0x8C, 0); ctx.addJmpFix(ctx.code.size() - 4, fracLbl);      // jl loop
    ctx.ensureLabel(fracDoneLbl);
    ctx.labelPos[fracDoneLbl] = ctx.code.size();
    e.lea_r64_rip(R_RCX, 0); ctx.addRipFix(ctx.code.size() - 4, "__zt_newline");
    e.mov_r32_imm(R_RDX, 2);
    e.call_rel(0); ctx.addCallFix(ctx.code.size() - 4, "__zt_write_out");
    e.add_rsp_imm(48);
    e.pop_r(R_R15);
    e.pop_r(R_R14);
    e.pop_r(R_R13);
    e.pop_r(R_R12);
    e.pop_r(R_RDI);
    e.pop_r(R_RSI);
    e.pop_r(R_RBX);
    e.ret();

    // ---- zt_rdtsc(): return rdtsc as an unsigned 64-bit value ----
    ctx.funcOff["__zt_rdtsc"] = ctx.code.size();
    e.b(0x0F); e.b(0x31);                    // rdtsc (edx:eax)
    e.shift_imm_reg(4, R_RDX, 32);           // shl rdx, 32
    e.alu_reg(0x0B, R_RAX, R_RDX);           // or rax, rdx
    e.ret();

    // ---- zt_halt(): OS-hosted exit via ExitProcess, with cli;hlt;spin kept
    // as belt-and-braces should the call ever return (mirrors the classic
    // backend's belt-and-braces guard). No privileged instructions on PE. ----
    ctx.funcOff["__zt_halt"] = ctx.code.size();
    ctx.importSlot("kernel32.dll", "ExitProcess");
    e.xor_reg32(R_RCX);                          // exit code 0
    e.sub_rsp_imm(40);                           // shadow space
    e.call_rip(0); ctx.addIatFix(ctx.code.size() - 4, "ExitProcess");
    e.add_rsp_imm(40);
    e.b(0xFA);                               // cli
    e.b(0xF4);                               // hlt
    e.b(0xEB); e.b(0xFE);                    // jmp $  (rel8 = -2)
}

// ====================================================================
// function emission
// ====================================================================

namespace {

struct CondCc {
    uint8_t jcc;      // 0F 8x
    uint8_t setcc;    // 0F 9x
};

// ====================================================================
// inline-asm encoder (x86-64)
//
// Emits the parsed `asm { ... }` instructions verbatim into the emitter
// `e`, using NATIVE x86-64 register numbers (rax=0 ... r15=15). This is
// the IR-backend counterpart of Codegen::emitAsmInstr; the parsed forms
// are intentionally limited to what the asm parser produces.
// ====================================================================
static void encodeAsmX64(Em& e, const IRAsmBlock& blk) {
    const bool w64 = (blk.wordSize != 32);   // asm32 => 32-bit operands (no REX.W)

    struct Op { int type = 0; int reg = 0; int base = 0; int64_t disp = 0; };
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
    auto isRegName = [&](const std::string& s) -> int {
        static const char* n64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
        static const char* n32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
        for (int i = 0; i < 16; i++) if (s == n64[i] || s == n32[i]) return i;
        return -1;
    };
    auto parseOp = [&](const std::string& raw) -> Op {
        std::string s = raw; trimStr(s);
        Op op;
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
            op.base = isRegName(baseStr);
            if (op.base < 0) { op.base = -1; op.disp = parseNum(baseStr) + (dispStr.empty() ? 0 : parseNum(dispStr)); }
            else if (!dispStr.empty()) op.disp = parseNum(dispStr);
            return op;
        }
        int ri = isRegName(s);
        if (ri >= 0) { op.type = 1; op.reg = ri; return op; }
        op.type = 2;
        op.disp = parseNum(s);
        return op;
    };

    auto rex = [&](bool w, bool r, bool x, bool b) {
        if (!w64 && !r && !x && !b) return;
        e.b((uint8_t)(0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0)));
    };
    auto modrm = [&](int mod, int reg, int rm) {
        e.b((uint8_t)(((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)));
    };
    auto sib = [&](int scale, int idx, int base) {
        e.b((uint8_t)((scale << 6) | ((idx & 7) << 3) | (base & 7)));
    };
    auto rmMem = [&](int reg, int base, int64_t off) {
        if (base < 0) {
            // absolute [disp32] via SIB no-base
            modrm(0, reg, 4); sib(0, 4, 5); e.d((uint32_t)off);
            return;
        }
        if (off == 0 && (base & 7) != 5) { modrm(0, reg, base); return; }
        if (off >= -128 && off <= 127)   { modrm(1, reg, base); e.b((uint8_t)(int8_t)off); return; }
        modrm(2, reg, base); e.d((uint32_t)off);
    };
    auto unsupported = [&](const char* what) {
        fprintf(stderr, "Warning: IR asm: unsupported instruction '%s', skipped\n", what);
    };

    for (auto& instr : blk.instrs) {
        std::string m = instr.mnemonic;
        for (auto& c : m) c = (char)tolower((unsigned char)c);
        Op o1 = parseOp(instr.op1);
        Op o2 = parseOp(instr.op2);
        // ignore instr.op3 for now (no 3-operand asm forms emitted by the parser)

        if (m == "mov") {
            if (o1.type == 1 && o2.type == 1) { rex(w64, o2.reg >= 8, false, o1.reg >= 8); e.b(0x89); modrm(3, o2.reg, o1.reg); continue; }
            if (o1.type == 1 && o2.type == 2) {
                rex(w64, false, false, o1.reg >= 8);
                if (w64) {
                    if (o2.disp >= INT32_MIN && o2.disp <= INT32_MAX) {
                        // mov r64, imm32 (sign-extended): C7 /0
                        e.b((uint8_t)(0xC7)); modrm(3, 0, o1.reg); e.d((uint32_t)o2.disp);
                    } else {
                        // movabs r64, imm64: 48 B8 imm64
                        e.b((uint8_t)(0xB8 + (o1.reg & 7))); e.q((uint64_t)o2.disp);
                    }
                } else {
                    e.b((uint8_t)(0xB8 + (o1.reg & 7))); e.d((uint32_t)o2.disp);
                }
                continue;
            }
            if (o1.type == 1 && o2.type == 3) {
                rex(w64, o1.reg >= 8, false, o2.base >= 8);
                e.b(0x8B); rmMem(o1.reg, o2.base, o2.disp);
                continue;
            }
            if (o1.type == 3 && o2.type == 1) {
                rex(w64, o2.reg >= 8, false, o1.base >= 8);
                e.b(0x89); rmMem(o2.reg, o1.base, o1.disp);
                continue;
            }
            unsupported("mov");
            continue;
        }

        int arithOp = -1;
        if (m == "add") arithOp = 0;
        else if (m == "or") arithOp = 1;
        else if (m == "and") arithOp = 4;
        else if (m == "sub") arithOp = 5;
        else if (m == "xor") arithOp = 6;
        if (arithOp >= 0) {
            static const uint8_t arith[8] = {0x01, 0x09, 0x00, 0x00, 0x21, 0x29, 0x31, 0x00};
            if (o1.type == 1 && o2.type == 1) {
                rex(w64, o2.reg >= 8, false, o1.reg >= 8);
                e.b(arith[arithOp]); modrm(3, o2.reg, o1.reg);
                continue;
            }
            // op reg, imm  (imm8 fast path)
            if (o1.type == 1 && o2.type == 2) {
                if (o2.disp >= -128 && o2.disp <= 127) {
                    rex(w64, false, false, o1.reg >= 8);
                    e.b(0x83); modrm(3, arithOp, o1.reg); e.b((uint8_t)(int8_t)o2.disp);
                } else {
                    rex(w64, false, false, o1.reg >= 8);
                    e.b(0x81); modrm(3, arithOp, o1.reg); e.d((uint32_t)o2.disp);
                }
                continue;
            }
            unsupported(m.c_str());
            continue;
        }

        if (m == "cmp") {
            if (o1.type == 1 && o2.type == 1) { rex(w64, o2.reg >= 8, false, o1.reg >= 8); e.b(0x39); modrm(3, o2.reg, o1.reg); continue; }
            if (o1.type == 1 && o2.type == 2) {
                if (o2.disp >= -128 && o2.disp <= 127) {
                    rex(w64, false, false, o1.reg >= 8);
                    e.b(0x83); modrm(3, 7, o1.reg); e.b((uint8_t)(int8_t)o2.disp);
                } else {
                    rex(w64, false, false, o1.reg >= 8);
                    e.b(0x81); modrm(3, 7, o1.reg); e.d((uint32_t)o2.disp);
                }
                continue;
            }
            unsupported("cmp");
            continue;
        }

        if (m == "test") {
            if (o1.type == 1 && o2.type == 1) { rex(w64, o2.reg >= 8, false, o1.reg >= 8); e.b(0x85); modrm(3, o2.reg, o1.reg); continue; }
            if (o1.type == 1 && o2.type == 2) { rex(w64, false, false, o1.reg >= 8); e.b(0xF7); modrm(3, 0, o1.reg); e.d((uint32_t)o2.disp); continue; }
            unsupported("test");
            continue;
        }

        if (m == "not" || m == "neg" || m == "inc" || m == "dec") {
            int d = (m == "not") ? 2 : (m == "neg") ? 3 : (m == "inc") ? 0 : 1;
            bool group3 = (m == "not" || m == "neg");
            if (o1.type == 1) {
                rex(w64, false, false, o1.reg >= 8);
                e.b(group3 ? 0xF7 : 0xFF); modrm(3, d, o1.reg);
                continue;
            }
            unsupported(m.c_str());
            continue;
        }

        if (m == "shl" || m == "shr") {
            int d = (m == "shl") ? 4 : 5;
            if (o1.type == 1 && o2.type == 1 && o2.reg == 1) {   // shl reg, cl
                rex(w64, false, false, o1.reg >= 8);
                e.b(0xD3); modrm(3, d, o1.reg);
                continue;
            }
            if (o1.type == 1 && o2.type == 2) {
                rex(w64, false, false, o1.reg >= 8);
                e.b(0xC1); modrm(3, d, o1.reg); e.b((uint8_t)o2.disp);
                continue;
            }
            unsupported(m.c_str());
            continue;
        }

        if (m == "push" || m == "pop") {
            if (o1.type == 1) {
                if (o1.reg >= 8) e.b(0x41);
                e.b((uint8_t)((m == "push" ? 0x50 : 0x58) + (o1.reg & 7)));
                continue;
            }
            if (m == "push" && o1.type == 2) { e.b(0x68); e.d((uint32_t)o1.disp); continue; }
            unsupported(m.c_str());
            continue;
        }

        // simple no-operand instructions
        if (m == "cli") { e.b(0xFA); continue; }
        if (m == "sti") { e.b(0xFB); continue; }
        if (m == "hlt") { e.b(0xF4); continue; }
        if (m == "nop") { e.b(0x90); continue; }
        if (m == "ret") { e.b(0xC3); continue; }
        if (m == "leave") { e.b(0xC9); continue; }
        if (m == "syscall") { e.b(0x0F); e.b(0x05); continue; }
        if (m == "cpuid") { e.b(0x0F); e.b(0xA2); continue; }
        if (m == "wrmsr") { e.b(0x0F); e.b(0x30); continue; }
        if (m == "rdmsr") { e.b(0x0F); e.b(0x32); continue; }
        if (m == "cqo" || m == "cqd") { e.b(0x48); e.b(0x99); continue; }
        if (m == "rdtsc") { e.b(0x0F); e.b(0x31); continue; }
        if (m == "clc") { e.b(0xF8); continue; }
        if (m == "stc") { e.b(0xF9); continue; }
        if (m == "cmc") { e.b(0xF5); continue; }
        if (m == "cld") { e.b(0xFC); continue; }
        if (m == "std") { e.b(0xFD); continue; }
        if (m == "lock") { e.b(0xF0); continue; }

        if (m == "jmp") {
            // jmp imm32 relative (+5 for the E9 disp32)
            e.b(0xE9); e.d((uint32_t)((int64_t)o1.disp - 5));
            continue;
        }
        static const struct { const char* name; int cc; } jccTable[] = {
            {"je",0x84},{"jz",0x84},{"jne",0x85},{"jnz",0x85},{"jb",0x82},{"jbe",0x86},{"ja",0x87},{"jae",0x83},
            {"jl",0x8C},{"jle",0x8E},{"jg",0x8F},{"jge",0x8D},{"js",0x88},{"jns",0x89}
        };
        bool didJcc = false;
        for (auto& j : jccTable) {
            if (m == j.name) {
                e.b(0x0F); e.b((uint8_t)j.cc); e.d((uint32_t)((int64_t)o1.disp - 6));
                didJcc = true;
                break;
            }
        }
        if (didJcc) continue;

        if (m == "int") { if (o1.type == 2) { e.b(0xCD); e.b((uint8_t)o1.disp); } else unsupported("int"); continue; }

        unsupported(m.c_str());
    }
}

// signed 64-bit compare condition codes
static CondCc ccFor(const std::string& op) {
    if (op == "==")  return { 0x84, 0x94 };
    if (op == "!=")  return { 0x85, 0x95 };
    if (op == "<")   return { 0x8C, 0x9C };
    if (op == "<=")  return { 0x8E, 0x9E };
    if (op == ">")   return { 0x8F, 0x9F };
    if (op == ">=")  return { 0x8D, 0x9D };
    if (op == "u<")  return { 0x82, 0x92 };
    if (op == "u<=") return { 0x86, 0x96 };
    if (op == "u>")  return { 0x87, 0x97 };
    if (op == "u>=") return { 0x83, 0x93 };
    return { 0x84, 0x94 };
}

// float compare uses the CF-based (unsigned) condition codes from ucomiss
static uint8_t ccFloatFor(const std::string& op) {
    if (op == "==")  return 0x94;   // setz
    if (op == "!=")  return 0x95;   // setnz
    if (op == "<")   return 0x92;   // setb
    if (op == "<=")  return 0x96;   // setbe
    if (op == ">")   return 0x97;   // seta
    if (op == ">=")  return 0x93;   // setae
    return 0x94;
}

} // namespace

// float compare: setcc in r11b, then clear/set if unordered (PF)
static void emitFloatCompareResultR11(Em& e, const std::string& op) {
    e.setcc_reg(ccFloatFor(op), R_R11);
    e.movzx_r64_reg8(R_R11, R_R11);
    if (op == "!=") {
        // unordered -> true: jnp +6; mov r11d,1
        e.b(0x7B); e.b(0x06);
        e.mov_r32_imm(R_R11, 1);
    } else {
        // unordered -> false: jnp +3; xor r11d,r11d
        e.b(0x7B); e.b(0x03);
        e.xor_reg32(R_R11);
    }
}

// ====================================================================
// per-function analysis + linear-scan register allocation
// ====================================================================

namespace {

// GP pools. r11 is never allocated (GP scratch); xmm0 is never allocated
// (float scratch). User functions and the __zt helpers preserve
// rbx/r12-r15, so intervals that cross a call are confined to those.
const int kGpVol[] = { R_RAX, R_RCX, R_RDX, R_RSI, R_RDI, R_R8, R_R9, R_R10 };
const int kGpCal[] = { R_RBX, R_R12, R_R13, R_R14, R_R15 };
const int kXmmPool[] = { 1, 2, 3, 4, 5, 6, 7 };

// x86-64 target description for the shared allocation engine.
const iralloc::TargetDesc kX86Desc = {
    kGpVol, 8, kGpCal, 5, kXmmPool, 7,
    R_RAX, R_RDX, R_RCX, R_RAX,
    true, true, true,
    true,
};

} // namespace

static void emitFunction(AsmCtx& ctx, IRFunction& fn) {
    if (fn.garbage || fn.isExtern) return;

    // ---- shared allocation engine (liveness, segments, pools) ----
    auto ai = iralloc::analyze(fn, kX86Desc);
    int maxSlot = ai.maxSlot;
    int n = ai.n;
    auto& alloc = ai.alloc;
    auto& segs = ai.segs;
    auto& preSegOfBarrier = ai.preSegOfBarrier;
    auto& nextSegOfBarrier = ai.nextSegOfBarrier;
    auto& barrierCrossing = ai.barrierCrossing;
    std::vector<int>& calleeUsed = ai.calleeUsed;

    auto physOf = [&](int v, int idx) -> int { return ai.physOf(v, idx); };
    auto physNextOf = [&](int v, int idx) -> int { return ai.physNextOf(v, idx); };
    auto isVolGp = [&](int p) { return ai.isVol(p); };
    int S = maxSlot * 8;
    int F = align16(32 + S + (int)calleeUsed.size() * 8) + 8;  // body rsp 16-aligned
    if (getenv("ZT_TRACE_ALLOC")) {
        fprintf(stderr, "=== fn %s maxSlot=%d S=%d F=%d\n", fn.name.c_str(), maxSlot, S, F);
        for (int i = 0; i < n; i++) {
            const IRInstr& in = fn.instrs[i];
            if (in.garbage) continue;
            fprintf(stderr, "  %d op=%d s=%d", i, (int)in.op, ai.segOfInstr[i]);
            for (int a = 0; a < 3; a++) {
                const IROperand* o = a == 0 ? &in.a : a == 1 ? &in.b : &in.c;
                if (o->kind == IROperand::Reg)
                    fprintf(stderr, " v%d=reg%d", a, o->reg);
            }
            if (iralloc::isBarrier(in.op))
                fprintf(stderr, " [preS=%d nextS=%d cross:", preSegOfBarrier[i], nextSegOfBarrier[i]);
            if (iralloc::isBarrier(in.op)) {
                for (int v : barrierCrossing[i])
                    fprintf(stderr, " v%d(p%d->p%d)", v,
                            preSegOfBarrier[i] >= 0 ? segs[preSegOfBarrier[i]].alloc[v].phys : -1,
                            nextSegOfBarrier[i] >= 0 ? segs[nextSegOfBarrier[i]].alloc[v].phys : -1);
                fprintf(stderr, "]");
            }
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "=== end %s\n", fn.name.c_str());
    }

    ctx.funcOff[fn.name] = ctx.code.size();
    Em e(ctx.code);

    // spill live-across values that cannot survive the call, before it executes
    auto emitBarrierSpill = [&](int b) {
        int preS = preSegOfBarrier[b], nextS = nextSegOfBarrier[b];
        for (int v : barrierCrossing[b]) {
            int prevPhys = (preS >= 0) ? segs[preS].alloc[v].phys : -1;
            int nextPhys = (nextS >= 0) ? segs[nextS].alloc[v].phys : -1;
            if (prevPhys < 0) continue;
            bool xmm = alloc[v].floatUsed && !alloc[v].intUsed;
            bool needStore = xmm || isVolGp(prevPhys) || nextPhys != prevPhys;
            if (!needStore) continue;   // callee-saved and same register: survives for free
            if (xmm) e.movss_mem_xmm(4, ctx.slotDisp(v), prevPhys);
            else e.mov_stack_r64(ctx.slotDisp(v), prevPhys);
        }
    };

    // reload values that were spilled at the barrier into their new registers
    auto emitBarrierReload = [&](int b) {
        int preS = preSegOfBarrier[b], nextS = nextSegOfBarrier[b];
        for (int v : barrierCrossing[b]) {
            int prevPhys = (preS >= 0) ? segs[preS].alloc[v].phys : -1;
            int nextPhys = (nextS >= 0) ? segs[nextS].alloc[v].phys : -1;
            if (nextPhys < 0) continue;
            bool xmm = alloc[v].floatUsed && !alloc[v].intUsed;
            bool wasStored = (prevPhys < 0) || xmm || isVolGp(prevPhys) || nextPhys != prevPhys;
            if (!wasStored) continue;   // stayed in the same callee-saved register
            if (xmm) e.movss_xmm_mem(nextPhys, 4, ctx.slotDisp(v));
            else e.mov_r64_stack(nextPhys, ctx.slotDisp(v));
        }
    };

    // prologue
    e.sub_rsp_imm((uint32_t)F);
    for (int i = 0; i < fn.nparams; i++) {
        e.mov_r64_mem(R_R11, 4, F + 8 + i * 8);       // param i
        e.mov_mem_r64(4, 32 + i * 8, R_R11);          // -> slot i
    }
    for (size_t k = 0; k < calleeUsed.size(); k++)
        e.mov_mem_r64(4, 32 + S + (int)k * 8, calleeUsed[k]);

    auto emitEpilogue = [&]() {
        for (int k = (int)calleeUsed.size() - 1; k >= 0; k--)
            e.mov_r64_mem(calleeUsed[k], 4, 32 + S + k * 8);
        e.add_rsp_imm((uint32_t)F);
        e.ret();
    };

    // load a Reg|Imm operand into GP register dst
    auto loadGp = [&](int dst, const IROperand& op, int idx) {
        if (op.kind == IROperand::Reg) {
            int p = physOf(op.reg, idx);
            if (p >= 0) { if (p != dst) e.mov_r64_reg(dst, p); }
            else e.mov_r64_stack(dst, ctx.slotDisp(op.reg));
        } else if (op.kind == IROperand::Imm) {
            if (op.imm >= INT32_MIN && op.imm <= INT32_MAX)
                e.mov_r64_imm32(dst, (int32_t)op.imm);
            else
                e.mov_r64_imm64(dst, (uint64_t)op.imm);
        } else {
            throw std::runtime_error("IR asm: bad operand in GP load");
        }
    };

    struct PendingArg { int vreg; bool isFloat; };
    std::vector<PendingArg> pendingArgs;

    auto emitCallResult = [&](const IROperand& a, int idx) {
        if (a.kind != IROperand::Reg) return;
        int p = physNextOf(a.reg, idx);
        if (a.off) {
            if (p >= 0) { if (p != 0) e.movss_reg(p, 0); }
            else e.movss_mem_xmm(4, ctx.slotDisp(a.reg), 0);
        } else {
            if (p >= 0) { if (p != R_RAX) e.mov_r64_reg(p, R_RAX); }
            else e.mov_stack_r64(ctx.slotDisp(a.reg), R_RAX);
        }
    };

    for (int i = 0; i < n; i++) {
        IRInstr& in = fn.instrs[i];
        if (in.garbage) continue;
        switch (in.op) {
        case IROp::Nop:
        case IROp::Func:
        case IROp::EndFunc:
            break;
        case IROp::Label:
            ctx.ensureLabel(in.a.label);
            ctx.labelPos[in.a.label] = ctx.code.size();
            break;

        case IROp::Const: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) {
                if (in.b.imm >= INT32_MIN && in.b.imm <= INT32_MAX)
                    e.mov_r64_imm32(p, (int32_t)in.b.imm);
                else
                    e.mov_r64_imm64(p, (uint64_t)in.b.imm);
            } else {
                e.mov_mem_imm64(4, ctx.slotDisp(in.a.reg), in.b.imm);
            }
            break;
        }
        case IROp::FConst: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) {
                e.mov_r64_imm32(R_R11, (int32_t)in.b.imm);
                e.movd_xmm_r64(p, R_R11);
            } else {
                e.mov_mem_imm64(4, ctx.slotDisp(in.a.reg), in.b.imm);
            }
            break;
        }
        case IROp::Str: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) {
                e.lea_r64_rip(p, 0);
                ctx.addRipFix(ctx.code.size() - 4, "", in.b.strIdx);
            } else {
                e.lea_r64_rip(R_R11, 0);
                ctx.addRipFix(ctx.code.size() - 4, "", in.b.strIdx);
                e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }
        case IROp::LeaGlobal: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) {
                e.lea_r64_rip(p, 0);
                ctx.addRipFix(ctx.code.size() - 4, in.b.name);
            } else {
                e.lea_r64_rip(R_R11, 0);
                ctx.addRipFix(ctx.code.size() - 4, in.b.name);
                e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }
        case IROp::LeaSlot: {
            int p = physOf(in.a.reg, i);
            if (p >= 0)
                e.lea_r64_mem(p, 4, ctx.slotDisp(in.b.reg, in.b.off));
            else {
                e.lea_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg, in.b.off));
                e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }
        case IROp::Mov: {
            int pa = physOf(in.a.reg, i);
            int pb = physOf(in.b.reg, i);
            if (pa >= 0) {
                if (pb >= 0) { if (pb != pa) e.mov_r64_reg(pa, pb); }
                else e.mov_r64_stack(pa, ctx.slotDisp(in.b.reg));
            } else {
                if (pb >= 0) e.mov_stack_r64(ctx.slotDisp(in.a.reg), pb);
                else {
                    e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg));
                    e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
                }
            }
            break;
        }
        case IROp::Load:
        case IROp::Load32: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) {
                if (in.op == IROp::Load32)
                    e.movsxd_r64_mem(p, 4, ctx.slotDisp(in.b.reg, in.label));
                else
                    e.mov_r64_mem(p, 4, ctx.slotDisp(in.b.reg, in.label));
            } else {
                if (in.op == IROp::Load32)
                    e.movsxd_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg, in.label));
                else
                    e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg, in.label));
                e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }
        case IROp::Store:
        case IROp::Store32:
        case IROp::FStore: {
            int v = in.b.reg;
            int p = physOf(in.b.reg, i);
            int disp = ctx.slotDisp(in.a.reg, in.label);
            if (in.op == IROp::FStore) {
                if (p >= 0) e.movss_mem_xmm(4, disp, p);
                else { e.movss_xmm_mem(0, 4, ctx.slotDisp(v)); e.movss_mem_xmm(4, disp, 0); }
            } else if (in.op == IROp::Store32) {
                if (p >= 0) e.mov_mem_r32(4, disp, p);
                else { e.mov_r32_mem(R_R11, 4, ctx.slotDisp(v)); e.mov_mem_r32(4, disp, R_R11); }
            } else {
                if (p >= 0) e.mov_mem_r64(4, disp, p);
                else { e.mov_r64_mem(R_R11, 4, ctx.slotDisp(v)); e.mov_mem_r64(4, disp, R_R11); }
            }
            break;
        }
        case IROp::GLoad:
        case IROp::GLoad32:
        case IROp::FGLoad: {
            int p = physOf(in.a.reg, i);
            int64_t off = in.label < 0 ? 0 : in.label;
            if (in.op == IROp::FGLoad) {
                if (p >= 0) {
                    e.movss_xmm_rip(p, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                } else {
                    e.movss_xmm_rip(0, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                    e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
                }
            } else if (in.op == IROp::GLoad32) {
                if (p >= 0) {
                    e.movsxd_rip(p, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                } else {
                    e.movsxd_rip(R_R11, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                    e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
                }
            } else {
                if (p >= 0) {
                    e.mov_r64_rip(p, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                } else {
                    e.mov_r64_rip(R_R11, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.b.name, -1, off);
                    e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
                }
            }
            break;
        }
        case IROp::GStore:
        case IROp::GStore32:
        case IROp::FGStore: {
            int v = in.b.reg;
            int p = physOf(in.b.reg, i);
            int64_t off = in.label < 0 ? 0 : in.label;
            if (in.op == IROp::FGStore) {
                if (p >= 0) {
                    e.movss_rip_xmm(0, p);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                } else {
                    e.movss_xmm_mem(0, 4, ctx.slotDisp(v));
                    e.movss_rip_xmm(0, 0);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                }
            } else if (in.op == IROp::GStore32) {
                if (p >= 0) {
                    e.mov_rip_r32(0, p);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                } else {
                    e.mov_r32_mem(R_R11, 4, ctx.slotDisp(v));
                    e.mov_rip_r32(0, R_R11);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                }
            } else {
                if (p >= 0) {
                    e.mov_rip_r64(0, p);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                } else {
                    e.mov_r64_mem(R_R11, 4, ctx.slotDisp(v));
                    e.mov_rip_r64(0, R_R11);
                    ctx.addRipFix(ctx.code.size() - 4, in.a.name, -1, off);
                }
            }
            break;
        }
        case IROp::PLoad:
        case IROp::PLoad32:
        case IROp::PLoad32Z:
        case IROp::PLoadW:
        case IROp::PLoadB: {
            if (alloc[in.a.reg].floatUsed && !alloc[in.a.reg].intUsed) {
                // float bits through a pointer (movd loads the raw 32 bits)
                int pa = physOf(in.a.reg, i);
                int baseReg;
                int pb = physOf(in.b.reg, i);
                if (pb >= 0) baseReg = pb;
                else { e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg)); baseReg = R_R11; }
                if (pa >= 0) e.movd_xmm_mem(pa, baseReg, in.b.off);
                else {
                    e.movd_xmm_mem(0, baseReg, in.b.off);
                    e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
                }
            } else {
                int resReg = physOf(in.a.reg, i);
                bool store = false;
                if (resReg < 0) { resReg = R_RAX; store = true; }
                int baseReg;
                int pb = physOf(in.b.reg, i);
                if (pb >= 0) baseReg = pb;
                else { e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg)); baseReg = R_R11; }
                switch (in.op) {
                case IROp::PLoad: e.mov_r64_mem(resReg, baseReg, in.b.off); break;
                case IROp::PLoad32: e.movsxd_r64_mem(resReg, baseReg, in.b.off); break;
                case IROp::PLoad32Z: e.mov_r32_mem(resReg, baseReg, in.b.off); break;
                case IROp::PLoadW: e.movzx_r64_mem16(resReg, baseReg, in.b.off); break;
                case IROp::PLoadB: e.movzx_r64_mem8(resReg, baseReg, in.b.off); break;
                default: break;
                }
                if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_RAX);
            }
            break;
        }
        case IROp::PStore:
        case IROp::PStore32:
        case IROp::PStoreW:
        case IROp::PStoreB: {
            int baseReg;
            int pa = physOf(in.a.reg, i);
            if (pa >= 0) baseReg = pa;
            else { e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.a.reg)); baseReg = R_R11; }
            int valReg;
            int pb = physOf(in.b.reg, i);
            if (pb >= 0) valReg = pb;
            else {
                if (baseReg == R_R11) {
                    e.mov_r64_mem(R_RAX, 4, ctx.slotDisp(in.b.reg));
                    valReg = R_RAX;
                } else {
                    e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.b.reg));
                    valReg = R_R11;
                }
            }
            switch (in.op) {
            case IROp::PStore: e.mov_mem_r64(baseReg, in.a.off, valReg); break;
            case IROp::PStore32: e.mov_mem_r32(baseReg, in.a.off, valReg); break;
            case IROp::PStoreW: e.mov_mem_r16(baseReg, in.a.off, valReg); break;
            case IROp::PStoreB: e.mov_mem_r8_reg(baseReg, in.a.off, valReg); break;
            default: break;
            }
            break;
        }
        case IROp::FPStore: {
            int baseReg;
            int pa = physOf(in.a.reg, i);
            if (pa >= 0) baseReg = pa;
            else { e.mov_r64_mem(R_R11, 4, ctx.slotDisp(in.a.reg)); baseReg = R_R11; }
            int pb = physOf(in.b.reg, i);
            if (pb >= 0) e.movss_mem_xmm(baseReg, in.a.off, pb);
            else {
                e.movss_xmm_mem(0, 4, ctx.slotDisp(in.b.reg));
                e.movss_mem_xmm(baseReg, in.a.off, 0);
            }
            break;
        }
        case IROp::Arg:
            pendingArgs.push_back({ in.b.reg, in.a.off != 0 });
            break;
        case IROp::Call: {
            emitBarrierSpill(i);
            int nargs = (int)in.c.imm;
            int K = align16(nargs * 8);
            if (K) e.sub_rsp_imm((uint32_t)K);
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++) {
                PendingArg& pa = pendingArgs[k];
                int p = physOf(pa.vreg, i);
                if (pa.isFloat) {
                    if (p >= 0) e.movd_r64_xmm(R_R11, p);
                    else e.mov_r64_mem(R_R11, 4, ctx.slotDisp(pa.vreg, 0, K));
                    e.mov_stack_r64(k * 8, R_R11);
                } else {
                    if (p >= 0) e.mov_stack_r64(k * 8, p);
                    else {
                        e.mov_r64_mem(R_R11, 4, ctx.slotDisp(pa.vreg, 0, K));
                        e.mov_stack_r64(k * 8, R_R11);
                    }
                }
            }
            e.call_rel(0);
            ctx.addCallFix(ctx.code.size() - 4, in.b.name);
            if (K) e.add_rsp_imm((uint32_t)K);
            emitCallResult(in.a, i);
            emitBarrierReload(i);
            pendingArgs.clear();
            break;
        }
        case IROp::ICall: {
            emitBarrierSpill(i);
            int nargs = (int)in.c.imm;
            int stackN = nargs > 4 ? nargs - 4 : 0;
            int K = stackN > 0 ? align16(32 + stackN * 8) : 0;
            if (K) e.sub_rsp_imm((uint32_t)K);
            static const int gregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++) {
                PendingArg& pa = pendingArgs[k];
                int p = physOf(pa.vreg, i);
                if (k < 4) {
                    // stage through the shadow space to avoid cross moves
                    if (pa.isFloat) {
                        if (p == k) continue;
                        if (p >= 0) e.movss_mem_xmm(4, K + k * 8, p);
                        else {
                            e.movss_xmm_mem(0, 4, ctx.slotDisp(pa.vreg, 0, K));
                            e.movss_mem_xmm(4, K + k * 8, 0);
                        }
                    } else {
                        if (p == gregs[k]) continue;
                        if (p >= 0) e.mov_stack_r64(K + k * 8, p);
                        else {
                            e.mov_r64_mem(R_R11, 4, ctx.slotDisp(pa.vreg, 0, K));
                            e.mov_stack_r64(K + k * 8, R_R11);
                        }
                    }
                } else {
                    int disp = 32 + (k - 4) * 8;
                    if (pa.isFloat) {
                        if (p >= 0) e.movss_mem_xmm(4, disp, p);
                        else {
                            e.movss_xmm_mem(0, 4, ctx.slotDisp(pa.vreg, 0, K));
                            e.movss_mem_xmm(4, disp, 0);
                        }
                    } else {
                        if (p >= 0) e.mov_stack_r64(disp, p);
                        else {
                            e.mov_r64_mem(R_R11, 4, ctx.slotDisp(pa.vreg, 0, K));
                            e.mov_stack_r64(disp, R_R11);
                        }
                    }
                }
            }
            for (int k = 0; k < nargs && k < 4; k++) {
                PendingArg& pa = pendingArgs[k];
                int p = physOf(pa.vreg, i);
                if (pa.isFloat) {
                    if (p == k) continue;
                    e.movss_xmm_mem(k, 4, K + k * 8);
                } else {
                    if (p == gregs[k]) continue;
                    e.mov_r64_stack(gregs[k], K + k * 8);
                }
            }
            std::string dll = in.b.dll.empty() ? mapFuncToDll(in.b.name) : in.b.dll;
            ctx.importSlot(dll, in.b.name);
            e.call_rip(0);
            ctx.addIatFix(ctx.code.size() - 4, in.b.name);
            if (K) e.add_rsp_imm((uint32_t)K);
            emitCallResult(in.a, i);
            emitBarrierReload(i);
            pendingArgs.clear();
            break;
        }
        case IROp::PrintStr: {
            emitBarrierSpill(i);
            if (in.a.strIdx >= 0) {
                e.lea_r64_rip(R_RCX, 0);
                ctx.addRipFix(ctx.code.size() - 4, "", in.a.strIdx);
            } else {
                // String in a register (e.g. a string variable): pass the
                // pointer value in RCX instead of an (empty) RIP fixup.
                int p = physOf(in.a.reg, i);
                if (p >= 0) { if (p != R_RCX) e.mov_r64_reg(R_RCX, p); }
                else e.mov_r64_stack(R_RCX, ctx.slotDisp(in.a.reg));
            }
            e.call_rel(0);
            ctx.addCallFix(ctx.code.size() - 4, "__zt_print_string");
            emitBarrierReload(i);
            break;
        }
        case IROp::PrintInt: {
            emitBarrierSpill(i);
            int p = physOf(in.a.reg, i);
            if (p >= 0) { if (p != R_RCX) e.mov_r64_reg(R_RCX, p); }
            else e.mov_r64_stack(R_RCX, ctx.slotDisp(in.a.reg));
            e.call_rel(0);
            ctx.addCallFix(ctx.code.size() - 4, "__zt_print_int");
            emitBarrierReload(i);
            break;
        }
        case IROp::PrintFlt: {
            emitBarrierSpill(i);
            int p = physOf(in.a.reg, i);
            if (p >= 0) e.movd_r64_xmm(R_RCX, p);
            else e.mov_r64_stack(R_RCX, ctx.slotDisp(in.a.reg));
            e.call_rel(0);
            ctx.addCallFix(ctx.code.size() - 4, "__zt_print_float");
            emitBarrierReload(i);
            break;
        }
        case IROp::Exit: {
            emitBarrierSpill(i);
            int p = physOf(in.a.reg, i);
            if (p >= 0) { if (p != R_RCX) e.mov_r64_reg(R_RCX, p); }
            else e.mov_r64_stack(R_RCX, ctx.slotDisp(in.a.reg));
            ctx.importSlot("kernel32.dll", "ExitProcess");
            e.call_rip(0);
            ctx.addIatFix(ctx.code.size() - 4, "ExitProcess");
            break;
        }

        case IROp::RawAsm: {
            emitBarrierSpill(i);
            if (in.a.strIdx < 0 || in.a.strIdx >= (int)ctx.ir.asmBlocks.size())
                throw std::runtime_error("IR asm: bad inline asm block index");
            encodeAsmX64(e, ctx.ir.asmBlocks[in.a.strIdx]);
            emitBarrierReload(i);
            break;
        }

        // ---- integer arithmetic, three-address: a = b op c ----
        case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor: {
            int opc = (in.op == IROp::Add) ? 0x03 :
                      (in.op == IROp::Sub) ? 0x2B :
                      (in.op == IROp::And) ? 0x23 :
                      (in.op == IROp::Or)  ? 0x0B : 0x33;
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = R_R11; store = true; }
            loadGp(acc, in.b, i);
            if (in.c.kind == IROperand::Imm) {
                int64_t v = in.c.imm;
                if (v >= INT32_MIN && v <= INT32_MAX) {
                    int ext = (in.op == IROp::Add) ? 0 : (in.op == IROp::Sub) ? 5 :
                              (in.op == IROp::And) ? 4 : (in.op == IROp::Or) ? 1 : 6;
                    e.alu_imm_reg(ext, acc, (int32_t)v);
                } else {
                    int scratch = (acc == R_R11) ? R_RAX : R_R11;
                    e.mov_r64_imm64(scratch, (uint64_t)v);
                    e.alu_reg(opc, acc, scratch);
                }
            } else if (in.c.kind == IROperand::Reg) {
                int pc = physOf(in.c.reg, i);
                if (pc >= 0) e.alu_reg(opc, acc, pc);
                else e.alu_mem(opc, acc, 4, ctx.slotDisp(in.c.reg));
            } else {
                throw std::runtime_error("IR asm: bad operand in ALU op");
            }
            if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            break;
        }
        case IROp::Shl:
        case IROp::Shr:
        case IROp::Sar: {
            int ext = (in.op == IROp::Shl) ? 4 : (in.op == IROp::Shr) ? 5 : 7;
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0 || acc == R_RCX) { acc = R_R11; store = true; }
            loadGp(acc, in.b, i);
            if (in.c.kind == IROperand::Imm) {
                e.shift_imm_reg(ext, acc, (uint8_t)in.c.imm);
            } else if (in.c.kind == IROperand::Reg) {
                int pc = physOf(in.c.reg, i);
                if (pc == R_RCX) e.shift_cl_reg(ext, acc);
                else {
                    if (pc >= 0) e.mov_r64_reg(R_RCX, pc);
                    else e.mov_r64_stack(R_RCX, ctx.slotDisp(in.c.reg));
                    e.shift_cl_reg(ext, acc);
                }
            } else {
                throw std::runtime_error("IR asm: bad operand in shift");
            }
            if (store) {
                if (physOf(in.a.reg, i) >= 0)
                    e.mov_r64_reg(physOf(in.a.reg, i), R_R11);
                else
                    e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }
        case IROp::Mul: {
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = R_R11; store = true; }
            loadGp(acc, in.b, i);
            if (in.c.kind == IROperand::Imm) {
                int64_t v = in.c.imm;
                if (v >= INT32_MIN && v <= INT32_MAX)
                    e.imul_r64_imm(acc, (int32_t)v);
                else {
                    int scratch = (acc == R_R11) ? R_RAX : R_R11;
                    e.mov_r64_imm64(scratch, (uint64_t)v);
                    e.imul_r64_reg(acc, scratch);
                }
            } else if (in.c.kind == IROperand::Reg) {
                int pc = physOf(in.c.reg, i);
                if (pc >= 0) e.imul_r64_reg(acc, pc);
                else e.imul_r64(acc, 4, ctx.slotDisp(in.c.reg));
            } else {
                throw std::runtime_error("IR asm: bad operand in mul");
            }
            if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            break;
        }
        case IROp::IDiv:
        case IROp::IMod:
        case IROp::UDiv:
        case IROp::UMod: {
            bool isDiv = (in.op == IROp::IDiv || in.op == IROp::UDiv);
            bool isSigned = (in.op == IROp::IDiv || in.op == IROp::IMod);
            loadGp(R_RAX, in.b, i);
            if (isSigned) e.cqo();
            else e.xor_reg32(R_RDX);
            if (in.c.kind == IROperand::Imm) {
                if (in.c.imm >= INT32_MIN && in.c.imm <= INT32_MAX)
                    e.mov_r64_imm32(R_R11, (int32_t)in.c.imm);
                else
                    e.mov_r64_imm64(R_R11, (uint64_t)in.c.imm);
                e.f7_reg(isSigned ? 7 : 6, R_R11);
            } else if (in.c.kind == IROperand::Reg) {
                int pc = physOf(in.c.reg, i);
                if (pc >= 0) e.f7_reg(isSigned ? 7 : 6, pc);
                else {
                    e.mov_r64_stack(R_R11, ctx.slotDisp(in.c.reg));
                    e.f7_reg(isSigned ? 7 : 6, R_R11);
                }
            } else {
                throw std::runtime_error("IR asm: bad operand in div");
            }
            int resReg = isDiv ? R_RAX : R_RDX;
            int pa = physOf(in.a.reg, i);
            if (pa >= 0) { if (pa != resReg) e.mov_r64_reg(pa, resReg); }
            else e.mov_stack_r64(ctx.slotDisp(in.a.reg), resReg);
            break;
        }
        case IROp::Neg:
        case IROp::Not: {
            int ext = (in.op == IROp::Neg) ? 3 : 2;
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = R_R11; store = true; }
            loadGp(acc, in.b, i);
            e.f7_reg(ext, acc);
            if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            break;
        }

        // ---- float arithmetic, three-address: a = b op c ----
        case IROp::FAdd:
        case IROp::FSub:
        case IROp::FMul:
        case IROp::FDiv: {
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = 0; store = true; }
            int pb = physOf(in.b.reg, i);
            if (pb >= 0) { if (pb != acc) e.movss_reg(acc, pb); }
            else e.movss_xmm_mem(acc, 4, ctx.slotDisp(in.b.reg));
            if (in.c.kind == IROperand::Reg) {
                int pc = physOf(in.c.reg, i);
                if (in.op == IROp::FAdd) {
                    if (pc >= 0) e.addss(acc, pc); else e.addss_mem(acc, 4, ctx.slotDisp(in.c.reg));
                } else if (in.op == IROp::FSub) {
                    if (pc >= 0) e.subss(acc, pc); else e.subss_mem(acc, 4, ctx.slotDisp(in.c.reg));
                } else if (in.op == IROp::FMul) {
                    if (pc >= 0) e.mulss(acc, pc); else e.mulss_mem(acc, 4, ctx.slotDisp(in.c.reg));
                } else {
                    if (pc >= 0) e.divss(acc, pc); else e.divss_mem(acc, 4, ctx.slotDisp(in.c.reg));
                }
            } else {
                throw std::runtime_error("IR asm: bad operand in float op");
            }
            if (store) e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
            break;
        }
        case IROp::FMov: {
            int pa = physOf(in.a.reg, i);
            int pb = physOf(in.b.reg, i);
            if (pa >= 0) {
                if (pb >= 0) { if (pb != pa) e.movss_reg(pa, pb); }
                else e.movss_xmm_mem(pa, 4, ctx.slotDisp(in.b.reg));
            } else {
                if (pb >= 0) e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), pb);
                else {
                    e.movss_xmm_mem(0, 4, ctx.slotDisp(in.b.reg));
                    e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
                }
            }
            break;
        }
        case IROp::FNeg: {
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = 0; store = true; }
            int pb = physOf(in.b.reg, i);
            if (pb >= 0) { if (pb != acc) e.movss_reg(acc, pb); }
            else e.movss_xmm_mem(acc, 4, ctx.slotDisp(in.b.reg));
            e.pxor_rip(acc, 0);
            ctx.addRipFix(ctx.code.size() - 4, "__zt_fneg");
            if (store) e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
            break;
        }
        case IROp::I2F: {
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = 0; store = true; }
            if (in.b.kind == IROperand::Reg) {
                int pb = physOf(in.b.reg, i);
                if (pb >= 0) e.cvtsi2ss_reg(acc, pb);
                else e.cvtsi2ss(acc, 4, ctx.slotDisp(in.b.reg));
            } else if (in.b.kind == IROperand::Imm) {
                if (in.b.imm >= INT32_MIN && in.b.imm <= INT32_MAX)
                    e.mov_r64_imm32(R_R11, (int32_t)in.b.imm);
                else
                    e.mov_r64_imm64(R_R11, (uint64_t)in.b.imm);
                e.cvtsi2ss_reg(acc, R_R11);
            } else {
                throw std::runtime_error("IR asm: bad operand in I2F");
            }
            if (store) e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
            break;
        }
        case IROp::F2I: {
            int acc = physOf(in.a.reg, i);
            bool store = false;
            if (acc < 0) { acc = R_R11; store = true; }
            int pb = physOf(in.b.reg, i);
            if (pb >= 0) e.cvttss2si_reg(acc, pb);
            else e.cvttss2si(acc, 4, ctx.slotDisp(in.b.reg));
            if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            break;
        }
        case IROp::FLoad: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) e.movss_xmm_mem(p, 4, ctx.slotDisp(in.b.reg, in.label));
            else {
                e.movss_xmm_mem(0, 4, ctx.slotDisp(in.b.reg, in.label));
                e.movss_mem_xmm(4, ctx.slotDisp(in.a.reg), 0);
            }
            break;
        }

        case IROp::Cmp: {
            if (in.a.off != 0) {
                int pb = physOf(in.b.reg, i);
                if (pb >= 0) {
                    int pc = physOf(in.c.reg, i);
                    if (pc >= 0) e.ucomiss(pb, pc);
                    else e.ucomiss_mem(pb, 4, ctx.slotDisp(in.c.reg));
                } else {
                    e.movss_xmm_mem(0, 4, ctx.slotDisp(in.b.reg));
                    int pc = physOf(in.c.reg, i);
                    if (pc >= 0) e.ucomiss(0, pc);
                    else e.ucomiss_mem(0, 4, ctx.slotDisp(in.c.reg));
                }
                emitFloatCompareResultR11(e, in.cond);
                int pa = physOf(in.a.reg, i);
                if (pa >= 0) { if (pa != R_R11) e.mov_r64_reg(pa, R_R11); }
                else e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            } else {
                int acc = physOf(in.a.reg, i);
                bool store = false;
                if (acc < 0) { acc = R_R11; store = true; }
                loadGp(acc, in.b, i);
                if (in.c.kind == IROperand::Imm) {
                    if (in.c.imm >= INT32_MIN && in.c.imm <= INT32_MAX)
                        e.cmp_r64_imm32(acc, (int32_t)in.c.imm);
                    else {
                        int scratch = (acc == R_R11) ? R_RAX : R_R11;
                        e.mov_r64_imm64(scratch, (uint64_t)in.c.imm);
                        e.alu_reg(0x3B, acc, scratch);
                    }
                } else if (in.c.kind == IROperand::Reg) {
                    int pc = physOf(in.c.reg, i);
                    if (pc >= 0) e.cmp_r64_reg(acc, pc);
                    else e.cmp_r64_mem(acc, 4, ctx.slotDisp(in.c.reg));
                } else {
                    throw std::runtime_error("IR asm: bad operand in cmp");
                }
                e.setcc_reg(ccFor(in.cond).setcc, acc);
                e.movzx_r64_reg8(acc, acc);
                if (store) e.mov_stack_r64(ctx.slotDisp(in.a.reg), R_R11);
            }
            break;
        }

        case IROp::Br:
            e.jmp_rel(0);
            ctx.addJmpFix(ctx.code.size() - 4, in.b.label);
            break;
        case IROp::BrZ:
        case IROp::BrNZ: {
            int p = physOf(in.a.reg, i);
            if (p >= 0) e.test_r64_reg(p, p);
            else {
                e.mov_r64_stack(R_R11, ctx.slotDisp(in.a.reg));
                e.test_r64_reg(R_R11, R_R11);
            }
            e.jcc_rel(in.op == IROp::BrZ ? 0x84 : 0x85, 0);
            ctx.addJmpFix(ctx.code.size() - 4, in.b.label);
            break;
        }
        case IROp::BrCC: {
            if (in.a.off != 0) {
                int pa = physOf(in.a.reg, i);
                if (pa >= 0) {
                    int pb = physOf(in.b.reg, i);
                    if (pb >= 0) e.ucomiss(pa, pb);
                    else e.ucomiss_mem(pa, 4, ctx.slotDisp(in.b.reg));
                } else {
                    e.movss_xmm_mem(0, 4, ctx.slotDisp(in.a.reg));
                    int pb = physOf(in.b.reg, i);
                    if (pb >= 0) e.ucomiss(0, pb);
                    else e.ucomiss_mem(0, 4, ctx.slotDisp(in.b.reg));
                }
                emitFloatCompareResultR11(e, in.cond);
                e.test_r64_reg(R_R11, R_R11);
                e.jcc_rel(0x85, 0);                 // jnz
                ctx.addJmpFix(ctx.code.size() - 4, in.c.label);
            } else {
                int acc;
                int p = physOf(in.a.reg, i);
                if (p >= 0) acc = p;
                else {
                    e.mov_r64_stack(R_R11, ctx.slotDisp(in.a.reg));
                    acc = R_R11;
                }
                if (in.b.kind == IROperand::Imm) {
                    if (in.b.imm >= INT32_MIN && in.b.imm <= INT32_MAX)
                        e.cmp_r64_imm32(acc, (int32_t)in.b.imm);
                    else {
                        int scratch = (acc == R_R11) ? R_RAX : R_R11;
                        e.mov_r64_imm64(scratch, (uint64_t)in.b.imm);
                        e.alu_reg(0x3B, acc, scratch);
                    }
                } else if (in.b.kind == IROperand::Reg) {
                    int pb = physOf(in.b.reg, i);
                    if (pb >= 0) e.cmp_r64_reg(acc, pb);
                    else e.cmp_r64_mem(acc, 4, ctx.slotDisp(in.b.reg));
                } else {
                    throw std::runtime_error("IR asm: bad operand in BrCC");
                }
                e.jcc_rel(ccFor(in.cond).jcc, 0);
                ctx.addJmpFix(ctx.code.size() - 4, in.c.label);
            }
            break;
        }

        case IROp::Ret:
            if (in.a.kind == IROperand::Reg) {
                if (in.a.off) {
                    int p = physOf(in.a.reg, i);
                    if (p >= 0) { if (p != 0) e.movss_reg(0, p); }
                    else e.movss_xmm_mem(0, 4, ctx.slotDisp(in.a.reg));
                } else {
                    int p = physOf(in.a.reg, i);
                    if (p >= 0) { if (p != R_RAX) e.mov_r64_reg(R_RAX, p); }
                    else e.mov_r64_stack(R_RAX, ctx.slotDisp(in.a.reg));
                }
            }
            emitEpilogue();
            break;

        default:
            throw std::runtime_error("IR asm: unhandled op");
        }
    }
}

// ====================================================================
// section building
// ====================================================================

static void buildStringPool(AsmCtx& ctx) {
    // IR string pool first
    for (size_t i = 0; i < ctx.ir.strings.size(); i++) {
        ctx.strOff[(int)i] = ctx.rdata.size();
        for (char ch : ctx.ir.strings[i]) ctx.rdata.push_back((uint8_t)ch);
        ctx.rdata.push_back(0);
    }
    // string-initialized globals (may be referenced by StrIdx)
    int poolNext = (int)ctx.ir.strings.size();
    for (auto& g : ctx.ir.globals) {
        if (!g.used || !g.isString) continue;
        int idx = -1;
        for (size_t i = 0; i < ctx.ir.strings.size(); i++)
            if (ctx.ir.strings[i] == g.strValue) { idx = (int)i; break; }
        if (idx < 0) {
            idx = poolNext++;
            ctx.ir.strings.push_back(g.strValue);
            ctx.strOff[idx] = ctx.rdata.size();
            for (char ch : g.strValue) ctx.rdata.push_back((uint8_t)ch);
            ctx.rdata.push_back(0);
        }
        ctx.globalStrIdx[g.name] = idx;
    }
    // newline
    ctx.newlineOff = ctx.rdata.size();
    const char* nl = "\r\n";
    ctx.rdata.push_back((uint8_t)nl[0]);
    ctx.rdata.push_back((uint8_t)nl[1]);
    ctx.rdata.push_back(0);
}

static void buildImportTables(AsmCtx& ctx) {
    // group imports by DLL preserving first-use order
    struct DllImports { std::string dll; std::vector<std::string> funcs; };
    std::vector<DllImports> dlls;
    for (auto& imp : ctx.imports) {
        DllImports* target = nullptr;
        for (auto& d : dlls) if (d.dll == imp.first) { target = &d; break; }
        if (!target) { dlls.push_back({ imp.first, {} }); target = &dlls.back(); }
        target->funcs.push_back(imp.second);
    }
    if (dlls.empty()) return;

    auto alignTo = [&](size_t a) {
        while (ctx.rdata.size() % a != 0) ctx.rdata.push_back(0);
    };

    alignTo(8);

    // hint/name entries
    std::unordered_map<std::string, size_t> hintOff;
    for (auto& d : dlls) {
        for (auto& fn : d.funcs) {
            hintOff[fn] = ctx.rdata.size();
            ctx.rdata.push_back(0); ctx.rdata.push_back(0);   // hint
            for (char ch : fn) ctx.rdata.push_back((uint8_t)ch);
            ctx.rdata.push_back(0);
            if (ctx.rdata.size() % 2 != 0) ctx.rdata.push_back(0);
        }
    }

    // DLL name strings
    std::unordered_map<std::string, size_t> nameOff;
    for (auto& d : dlls) {
        nameOff[d.dll] = ctx.rdata.size();
        for (char ch : d.dll) ctx.rdata.push_back((uint8_t)ch);
        ctx.rdata.push_back(0);
    }

    alignTo(8);

    // ILT (OriginalFirstThunk) + IAT (FirstThunk), one 8-byte slot per function
    std::unordered_map<std::string, size_t> iltOff;
    std::unordered_map<std::string, size_t> iatStartOff;
    for (auto& d : dlls) {
        iltOff[d.dll] = ctx.rdata.size();
        for (auto& fn : d.funcs) {
            uint64_t hv = (uint64_t)(ctx.rdataRVA + (uint32_t)hintOff[fn]);
            ctx.rdata.push_back((uint8_t)hv); ctx.rdata.push_back((uint8_t)(hv >> 8));
            ctx.rdata.push_back((uint8_t)(hv >> 16)); ctx.rdata.push_back((uint8_t)(hv >> 24));
            ctx.rdata.push_back((uint8_t)(hv >> 32)); ctx.rdata.push_back((uint8_t)(hv >> 40));
            ctx.rdata.push_back((uint8_t)(hv >> 48)); ctx.rdata.push_back((uint8_t)(hv >> 56));
        }
        for (int k = 0; k < 8; k++) ctx.rdata.push_back(0);   // terminator

        iatStartOff[d.dll] = ctx.rdata.size();
        for (auto& fn : d.funcs) {
            ctx.iatOff[fn] = ctx.rdata.size();
            uint64_t hv = (uint64_t)(ctx.rdataRVA + (uint32_t)hintOff[fn]);
            ctx.rdata.push_back((uint8_t)hv); ctx.rdata.push_back((uint8_t)(hv >> 8));
            ctx.rdata.push_back((uint8_t)(hv >> 16)); ctx.rdata.push_back((uint8_t)(hv >> 24));
            ctx.rdata.push_back((uint8_t)(hv >> 32)); ctx.rdata.push_back((uint8_t)(hv >> 40));
            ctx.rdata.push_back((uint8_t)(hv >> 48)); ctx.rdata.push_back((uint8_t)(hv >> 56));
        }
        for (int k = 0; k < 8; k++) ctx.rdata.push_back(0);   // terminator
    }

    alignTo(8);

    // import descriptors
    ctx.importDirRVA = ctx.rdataRVA + (uint32_t)ctx.rdata.size();
    auto writeDW = [&](uint32_t v) {
        ctx.rdata.push_back((uint8_t)v); ctx.rdata.push_back((uint8_t)(v >> 8));
        ctx.rdata.push_back((uint8_t)(v >> 16)); ctx.rdata.push_back((uint8_t)(v >> 24));
    };
    for (auto& d : dlls) {
        writeDW(ctx.rdataRVA + (uint32_t)iltOff[d.dll]);   // OriginalFirstThunk
        writeDW(0);                                        // TimeDateStamp
        writeDW(0);                                        // ForwarderChain
        writeDW(ctx.rdataRVA + (uint32_t)nameOff[d.dll]);  // Name
        writeDW(ctx.rdataRVA + (uint32_t)iatStartOff[d.dll]); // FirstThunk
    }
    for (int k = 0; k < 20; k++) ctx.rdata.push_back(0);   // null descriptor
    ctx.importDirSize = (uint32_t)(dlls.size() + 1) * 20;
}

static void buildData(AsmCtx& ctx) {
    for (auto& g : ctx.ir.globals) {
        if (!g.used) continue;
        ctx.globalOff[g.name] = ctx.data.size();
        int sz = std::max(g.size, 8);
        if (g.isString) {
            int idx = ctx.globalStrIdx[g.name];
            ctx.addDataStrFix(ctx.data.size(), idx);
            for (int k = 0; k < 8; k++) ctx.data.push_back(0);
        } else if (g.isFloat) {
            float f = (float)g.floatValue;
            uint32_t u;
            std::memcpy(&u, &f, sizeof(u));
            ctx.data.push_back((uint8_t)u); ctx.data.push_back((uint8_t)(u >> 8));
            ctx.data.push_back((uint8_t)(u >> 16)); ctx.data.push_back((uint8_t)(u >> 24));
            for (int k = 4; k < sz; k++) ctx.data.push_back(0);
        } else {
            uint64_t v = (uint64_t)g.intValue;
            for (int k = 0; k < 8; k++) ctx.data.push_back((uint8_t)(v >> (8 * k)));
            for (int k = 8; k < sz; k++) ctx.data.push_back(0);
        }
        while (ctx.data.size() % 8 != 0) ctx.data.push_back(0);
    }
    // runtime buffers
    ctx.writtenOff = ctx.data.size();
    for (int k = 0; k < 8; k++) ctx.data.push_back(0);
    ctx.numBufOff = ctx.data.size();
    for (int k = 0; k < 32; k++) ctx.data.push_back(0);
    // float constant 10.0f used by the float printer
    ctx.fconstTenOff = ctx.data.size();
    float ten = 10.0f;
    uint32_t tu;
    std::memcpy(&tu, &ten, sizeof(tu));
    ctx.data.push_back((uint8_t)tu); ctx.data.push_back((uint8_t)(tu >> 8));
    ctx.data.push_back((uint8_t)(tu >> 16)); ctx.data.push_back((uint8_t)(tu >> 24));
    for (int k = 0; k < 4; k++) ctx.data.push_back(0);
    // float sign mask (0x80000000) used by FNeg
    ctx.fnegSignOff = ctx.data.size();
    ctx.data.push_back(0x00); ctx.data.push_back(0x00);
    ctx.data.push_back(0x00); ctx.data.push_back(0x80);
    for (int k = 0; k < 4; k++) ctx.data.push_back(0);
}

// ====================================================================
// fixup resolution
// ====================================================================

static void patchRel32(std::vector<uint8_t>& code, size_t pos, uint64_t target) {
    int64_t rel = (int64_t)target - (int64_t)(pos + 4);
    code[pos]     = (uint8_t)(rel & 0xFF);
    code[pos + 1] = (uint8_t)((rel >> 8) & 0xFF);
    code[pos + 2] = (uint8_t)((rel >> 16) & 0xFF);
    code[pos + 3] = (uint8_t)((rel >> 24) & 0xFF);
}

static void writeU64(std::vector<uint8_t>& buf, size_t pos, uint64_t v) {
    for (int k = 0; k < 8; k++) buf[pos + k] = (uint8_t)(v >> (8 * k));
}

static void resolveFixups(AsmCtx& ctx) {
    for (auto& f : ctx.fixes) {
        uint64_t target = 0;
        bool isData = false;
        switch (f.kind) {
        case AsmCtx::Fix::Call:
            if (!ctx.funcOff.count(f.name))
                throw std::runtime_error("IR asm: undefined function '" + f.name + "'");
            target = ctx.funcOff[f.name];
            break;
        case AsmCtx::Fix::Jmp:
            if ((int)ctx.labelPos.size() <= f.label || ctx.labelPos[f.label] == (size_t)-1)
                throw std::runtime_error("IR asm: undefined label");
            target = ctx.labelPos[f.label];
            break;
        case AsmCtx::Fix::IAT:
            if (!ctx.iatOff.count(f.name))
                throw std::runtime_error("IR asm: undefined import '" + f.name + "'");
            // rel32 from a .text instruction: (VA_iat) - (VA_instr + 4),
            // VA_i = ImageBase + RVA_i, so ImageBase cancels out.
            target = (uint64_t)ctx.rdataRVA + (uint64_t)ctx.iatOff[f.name] - AsmCtx::kTextRVA;
            break;
        case AsmCtx::Fix::Rip:
            if (f.strIdx >= 0)
                target = (uint64_t)ctx.rdataRVA + (uint64_t)ctx.strOff[f.strIdx] + (uint64_t)f.off - AsmCtx::kTextRVA;
            else if (f.name == "__zt_newline")
                target = (uint64_t)ctx.rdataRVA + (uint64_t)ctx.newlineOff + (uint64_t)f.off - AsmCtx::kTextRVA;
            else if (f.name == "__zt_num_buf")
                target = (uint64_t)ctx.dataRVA + (uint64_t)ctx.numBufOff + (uint64_t)f.off - AsmCtx::kTextRVA;
            else if (f.name == "__zt_fconst_ten")
                target = (uint64_t)ctx.dataRVA + (uint64_t)ctx.fconstTenOff + (uint64_t)f.off - AsmCtx::kTextRVA;
            else if (f.name == "__zt_fneg")
                target = (uint64_t)ctx.dataRVA + (uint64_t)ctx.fnegSignOff + (uint64_t)f.off - AsmCtx::kTextRVA;
            else if (f.name == "__zt_written")
                target = (uint64_t)ctx.dataRVA + (uint64_t)ctx.writtenOff + (uint64_t)f.off - AsmCtx::kTextRVA;
            else
                target = (uint64_t)ctx.dataRVA + (uint64_t)ctx.globalOff[f.name] + (uint64_t)f.off - AsmCtx::kTextRVA;
            break;
        case AsmCtx::Fix::DataStr64:
            target = (uint64_t)AsmCtx::kImageBase + (uint64_t)ctx.rdataRVA + (uint64_t)ctx.strOff[f.strIdx];
            isData = true;
            break;
        }
        if (isData) writeU64(ctx.data, f.pos, target);
        else patchRel32(ctx.code, f.pos, target);
    }
}

// ====================================================================
// PE writer
// ====================================================================

#pragma pack(push, 1)
struct PEDosHeader {
    uint16_t e_magic = 0x5A4D;
    uint16_t e_cblp = 0x90;
    uint16_t e_cp = 3;
    uint16_t e_crlc = 0;
    uint16_t e_cparhdr = 4;
    uint16_t e_minalloc = 0;
    uint16_t e_maxalloc = 0xFFFF;
    uint16_t e_ss = 0;
    uint16_t e_sp = 0xB8;
    uint16_t e_csum = 0;
    uint16_t e_ip = 0;
    uint16_t e_cs = 0;
    uint16_t e_lfarlc = 0x40;
    uint16_t e_ovno = 0;
    uint16_t e_res[4] = {0};
    uint16_t e_oemid = 0;
    uint16_t e_oeminfo = 0;
    uint16_t e_res2[10] = {0};
    uint32_t e_lfanew = 0x80;
};
struct PECoffHeader {
    uint16_t Machine = 0x8664;
    uint16_t NumberOfSections = 3;
    uint32_t TimeDateStamp = 0;
    uint32_t PointerToSymbolTable = 0;
    uint32_t NumberOfSymbols = 0;
    uint16_t SizeOfOptionalHeader = 240;
    uint16_t Characteristics = 0x0022;
};
struct PEDataDirectory {
    uint32_t VirtualAddress = 0;
    uint32_t Size = 0;
};
struct PEOptionalHeader64 {
    uint16_t Magic = 0x020B;
    uint8_t MajorLinkerVersion = 0;
    uint8_t MinorLinkerVersion = 0;
    uint32_t SizeOfCode = 0;
    uint32_t SizeOfInitializedData = 0;
    uint32_t SizeOfUninitializedData = 0;
    uint32_t AddressOfEntryPoint = 0;
    uint32_t BaseOfCode = 0x1000;
    uint64_t ImageBase = 0x140000000;
    uint32_t SectionAlignment = 0x1000;
    uint32_t FileAlignment = 0x200;
    uint16_t MajorOperatingSystemVersion = 6;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion = 0;
    uint16_t MinorImageVersion = 0;
    uint16_t MajorSubsystemVersion = 6;
    uint16_t MinorSubsystemVersion = 0;
    uint32_t Win32VersionValue = 0;
    uint32_t SizeOfImage = 0x4000;
    uint32_t SizeOfHeaders = 0x200;
    uint32_t CheckSum = 0;
    uint16_t Subsystem = 3;                 // CONSOLE
    uint16_t DllCharacteristics = 0x0160;
    uint64_t SizeOfStackReserve = 0x100000;
    uint64_t SizeOfStackCommit = 0x1000;
    uint64_t SizeOfHeapReserve = 0x100000;
    uint64_t SizeOfHeapCommit = 0x1000;
    uint32_t LoaderFlags = 0;
    uint32_t NumberOfRvaAndSizes = 16;
    PEDataDirectory DataDirectory[16];
};
struct PESectionHeader {
    char Name[8] = {0};
    uint32_t VirtualSize = 0;
    uint32_t VirtualAddress = 0;
    uint32_t SizeOfRawData = 0;
    uint32_t PointerToRawData = 0;
    uint32_t PointerToRelocations = 0;
    uint32_t PointerToLinenumbers = 0;
    uint16_t NumberOfRelocations = 0;
    uint16_t NumberOfLinenumbers = 0;
    uint32_t Characteristics = 0;
};
#pragma pack(pop)

static void writePEFile(const std::string& outputPath, AsmCtx& ctx) {
    uint32_t textSize = (uint32_t)ctx.code.size();
    uint32_t rdataSize = (uint32_t)ctx.rdata.size();
    uint32_t dataSize = (uint32_t)ctx.data.size();

    uint32_t textRaw = alignUp32(textSize, 0x200);
    uint32_t rdataRaw = alignUp32(rdataSize, 0x200);
    uint32_t dataRaw = alignUp32(dataSize, 0x200);
    uint32_t textVirt = alignUp32(textSize, 0x1000);
    uint32_t rdataVirt = alignUp32(rdataSize, 0x1000);
    uint32_t dataVirt = alignUp32(dataSize, 0x1000);

    ctx.rdataRVA = alignUp32(AsmCtx::kTextRVA + textVirt, 0x1000);
    ctx.dataRVA = alignUp32(ctx.rdataRVA + rdataVirt, 0x1000);

    PEDosHeader dos;
    PECoffHeader coff;
    PEOptionalHeader64 opt;
    opt.SizeOfCode = textRaw;
    opt.SizeOfInitializedData = rdataRaw + dataRaw;
    opt.AddressOfEntryPoint = AsmCtx::kTextRVA + ctx.entryOff;
    opt.SizeOfImage = alignUp32(ctx.dataRVA + dataVirt, 0x1000);
    opt.DataDirectory[1].VirtualAddress = ctx.importDirRVA;
    opt.DataDirectory[1].Size = ctx.importDirSize;

    uint32_t headerRaw = 0x200;   // 64-byte DOS + stub + PE/COFF + opt + 3 sections
    uint32_t textRawOfs = headerRaw;
    uint32_t rdataRawOfs = textRawOfs + textRaw;
    uint32_t dataRawOfs = rdataRawOfs + rdataRaw;
    opt.SizeOfHeaders = headerRaw;

    PESectionHeader textSec, rdataSec, dataSec;
    memcpy(textSec.Name, ".text", 6);
    textSec.VirtualSize = textSize;
    textSec.VirtualAddress = AsmCtx::kTextRVA;
    textSec.SizeOfRawData = textRaw;
    textSec.PointerToRawData = textRawOfs;
    textSec.Characteristics = 0x60000020;
    memcpy(rdataSec.Name, ".rdata", 7);
    rdataSec.VirtualSize = rdataSize;
    rdataSec.VirtualAddress = ctx.rdataRVA;
    rdataSec.SizeOfRawData = rdataRaw;
    rdataSec.PointerToRawData = rdataRawOfs;
    rdataSec.Characteristics = 0x40000040;
    memcpy(dataSec.Name, ".data", 6);
    dataSec.VirtualSize = dataSize;
    dataSec.VirtualAddress = ctx.dataRVA;
    dataSec.SizeOfRawData = dataRaw;
    dataSec.PointerToRawData = dataRawOfs;
    dataSec.Characteristics = 0xC0000040;

    std::ofstream f(outputPath, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
        throw std::runtime_error("IR asm: cannot open output file");

    auto pad = [&](size_t to) {
        size_t cur = (size_t)f.tellp();
        static const char z = 0;
        while (cur < to) { f.write(&z, 1); cur++; }
    };

    f.write((const char*)&dos, sizeof(dos));
    const char* stub = "This program cannot be run in DOS mode.\r\n";
    f.write(stub, (std::streamsize)strlen(stub) + 1);
    pad(0x80);
    uint32_t peSig = 0x00004550;
    f.write((const char*)&peSig, 4);
    f.write((const char*)&coff, sizeof(coff));
    f.write((const char*)&opt, sizeof(opt));
    f.write((const char*)&textSec, sizeof(textSec));
    f.write((const char*)&rdataSec, sizeof(rdataSec));
    f.write((const char*)&dataSec, sizeof(dataSec));
    pad(headerRaw);

    f.write((const char*)ctx.code.data(), (std::streamsize)textSize);
    pad(textRawOfs + textRaw);
    f.write((const char*)ctx.rdata.data(), (std::streamsize)rdataSize);
    pad(rdataRawOfs + rdataRaw);
    f.write((const char*)ctx.data.data(), (std::streamsize)dataSize);
    pad(dataRawOfs + dataRaw);
    f.close();
}

// ====================================================================
// IRAsm API
// ====================================================================

IRAsm::IRAsm(IRProgram& ir) : ir_(ir) {}

bool IRAsm::compile(const std::string& outputPath) {
    AsmCtx ctx(ir_);

    try {
        emitRuntimeHelpers(ctx);

        for (auto& fn : ir_.functions)
            emitFunction(ctx, fn);

        if (!ctx.funcOff.count(ir_.entryFunc)) {
            std::cerr << "IR asm: entry function '" << ir_.entryFunc << "' not found" << std::endl;
            return false;
        }

        // entry stub: sub rsp,40; call entry; mov ecx,eax; call ExitProcess
        Em e(ctx.code);
        ctx.entryOff = (uint32_t)ctx.code.size();
        e.sub_rsp_imm(40);
        e.call_rel(0);
        ctx.addCallFix(ctx.code.size() - 4, ir_.entryFunc);
        e.b(0x89); e.b(0xC1);                       // mov ecx, eax
        ctx.importSlot("kernel32.dll", "ExitProcess");
        e.call_rip(0);
        ctx.addIatFix(ctx.code.size() - 4, "ExitProcess");

        // layout
        uint32_t textSize = (uint32_t)ctx.code.size();
        uint32_t textVirt = alignUp32(textSize, 0x1000);
        ctx.rdataRVA = alignUp32(AsmCtx::kTextRVA + textVirt, 0x1000);

        buildStringPool(ctx);
        buildImportTables(ctx);

        uint32_t rdataSize = (uint32_t)ctx.rdata.size();
        uint32_t rdataVirt = alignUp32(rdataSize, 0x1000);
        ctx.dataRVA = alignUp32(ctx.rdataRVA + rdataVirt, 0x1000);

        buildData(ctx);
        resolveFixups(ctx);

        writePEFile(outputPath, ctx);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "IR asm: " << e.what() << std::endl;
        return false;
    }
}
