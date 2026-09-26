#pragma once
#include <vector>
#include <cstdint>
#include <cstring>

// ====================================================================
// tiny x86-64 encoder (shared by irasm.cpp and httpjson_rt.cpp)
// ====================================================================
namespace x86e {

// machine register indices
enum : int { R_RAX = 0, R_RCX = 1, R_RDX = 2, R_RBX = 3, R_RSP = 4,
             R_RBP = 5, R_RSI = 6, R_RDI = 7, R_R8 = 8, R_R9 = 9,
             R_R10 = 10, R_R11 = 11, R_R12 = 12, R_R13 = 13, R_R14 = 14, R_R15 = 15 };

// dedicated XMM scratch registers (never allocated to temps, so no
// callee-save/restore is needed for them)
const int XMM_SCR0 = 6;
const int XMM_SCR1 = 7;

static inline uint32_t alignUp32(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }
static inline int align16(int v) { return (v + 15) & ~15; }

struct Em {
    std::vector<uint8_t>& c;
    explicit Em(std::vector<uint8_t>& code) : c(code) {}

    void b(uint8_t x) { c.push_back(x); }
    void w(uint16_t x) { b((uint8_t)x); b((uint8_t)(x >> 8)); }
    void d(uint32_t x) { b((uint8_t)x); b((uint8_t)(x >> 8)); b((uint8_t)(x >> 16)); b((uint8_t)(x >> 24)); }
    void q(uint64_t x) { d((uint32_t)x); d((uint32_t)(x >> 32)); }

    // REX prefix. reg/rm are full register indices (0-15), or -1 when the
    // 3-bit field is implicit (e.g. rm is a SIB-encoded memory operand).
    void rex(uint8_t w, int reg, int rm) {
        uint8_t v = 0x40;
        if (w) v |= 0x08;
        if (reg >= 8) v |= 0x04;
        if (rm >= 8) v |= 0x01;
        if (v != 0x40) c.push_back(v);
    }
    void modrm(uint8_t mod, int reg, int rm) {
        c.push_back((uint8_t)((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
    }
    void sib(uint8_t scale, int index, int base) {
        c.push_back((uint8_t)((scale << 6) | ((index & 7) << 3) | (base & 7)));
    }

    // modrm for register/memory operand [base + off]. base is full register index.
    void rmMem(int reg, int base, int off) {
        int mod;
        if (off == 0 && (base & 7) != 5) mod = 0;
        else if (off >= -128 && off <= 127) mod = 1;
        else mod = 2;
        if ((base & 7) == 4) {          // rsp/r12 need SIB
            modrm((uint8_t)mod, reg, 4);
            sib(0, 4, base);
        } else {
            modrm((uint8_t)mod, reg, base);
        }
        if (mod == 1) b((uint8_t)(int8_t)off);
        else if (mod == 2) d((uint32_t)off);
    }
    void rmStack(int reg, int off) { rmMem(reg, 4, off); }  // [rsp + off]
    void rmRip(int reg, int32_t disp) {                     // [rip + disp32]
        modrm(0, reg, 5);
        d((uint32_t)disp);
    }

    // REX with separate X (index) and B (base) bits — needed for SIB addressing.
    void rex3(uint8_t w, int reg, int x, int b) {
        uint8_t v = 0x40;
        if (w) v |= 0x08;
        if (reg >= 8) v |= 0x04;
        if (x >= 8) v |= 0x02;
        if (b >= 8) v |= 0x01;
        if (v != 0x40) c.push_back(v);
    }

    // [base + index*1 + disp8] — SIB-encoded two-register addressing.
    // Always uses mod=1 + disp8 (even disp8=0) because mod=0 with a base of
    // rbp/r13 is not encodable (it means "no base").
    void rmIdx(int reg, int base, int index, int8_t disp) {
        modrm(1, reg, 4);
        sib(0, index, base);
        b((uint8_t)disp);
    }

    // ---- stack / general ----
    void push_r(uint8_t r) { if (r >= 8) b(0x41); b((uint8_t)(0x50 + (r & 7))); }
    void pop_r(uint8_t r) { if (r >= 8) b(0x41); b((uint8_t)(0x58 + (r & 7))); }
    void sub_rsp_imm(uint32_t v) { b(0x48); b(0x81); b(0xEC); d(v); }
    void add_rsp_imm(uint32_t v) { b(0x48); b(0x81); b(0xC4); d(v); }

    // ---- moves ----
    void mov_r64_mem(int dst, int base, int off) {   // mov dst, [base+off]
        rex(1, dst, base); b(0x8B); rmMem(dst, base, off);
    }
    void mov_r64_stack(int dst, int off) { mov_r64_mem(dst, 4, off); }
    void mov_mem_r64(int base, int off, int src) {   // mov [base+off], src
        rex(1, src, base); b(0x89); rmMem(src, base, off);
    }
    void mov_stack_r64(int off, int src) { mov_mem_r64(4, off, src); }
    void mov_r32_mem(int dst, int base, int off) {   // mov dst(32), [base+off]
        rex(0, dst, base); b(0x8B); rmMem(dst, base, off);
    }
    void mov_mem_r32(int base, int off, int src) {
        rex(0, src, base); b(0x89); rmMem(src, base, off);
    }
    void mov_mem_r16(int base, int off, int src) {
        b(0x66); rex(0, src, base); b(0x89); rmMem(src, base, off);
    }
    void mov_mem_r8(int base, int off) {             // mov byte [base+off], al
        b(0x88); rmMem(0, base, off);
    }
    void mov_mem_r8_reg(int base, int off, int src) {  // mov byte [base+off], src8
        rex(0, src, base); b(0x88); rmMem(src, base, off);
    }
    void mov_mem_imm16(int base, int off, uint16_t v) {  // mov word [base+off], imm16
        b(0x66); rex(0, -1, base); b(0xC7); rmMem(0, base, off); w(v);
    }
    void mov_r32_imm(int dst, uint32_t v) {          // mov dst, imm32
        rex(0, -1, dst); b((uint8_t)(0xB8 + (dst & 7))); d(v);
    }
    void mov_r64_imm32(int dst, int32_t v) {         // mov dst, sign-extended imm32
        rex(1, -1, dst); b(0xC7); modrm(3, 0, dst); d((uint32_t)v);
    }
    void mov_r64_imm64(int dst, uint64_t v) {        // movabs dst, imm64
        rex(1, -1, dst); b((uint8_t)(0xB8 + (dst & 7))); q(v);
    }
    void mov_r64_reg(int dst, int src) {             // mov dst, src
        rex(1, dst, src); b(0x8B); modrm(3, dst, src);
    }
    void mov_r32_reg(int dst, int src) {
        rex(0, dst, src); b(0x8B); modrm(3, dst, src);
    }
    void mov_mem_imm32(int base, int off, uint32_t v) {  // mov dword [base+off], imm32
        rex(0, -1, base); b(0xC7); rmMem(0, base, off); d(v);
    }
    void mov_mem_imm64(int base, int off, int64_t v) {   // mov qword [base+off], imm64
        if (v >= INT32_MIN && v <= INT32_MAX) {
            rex(1, -1, base); b(0xC7); rmMem(0, base, off); d((uint32_t)v);
        } else {
            mov_r64_imm64(0, (uint64_t)v);
            mov_mem_r64(base, off, 0);
        }
    }
    void movsxd_r64_mem(int dst, int base, int off) {
        rex(1, dst, base); b(0x63); rmMem(dst, base, off);
    }
    void movzx_r64_mem16(int dst, int base, int off) {
        rex(1, dst, base); b(0x0F); b(0xB7); rmMem(dst, base, off);
    }
    void movzx_r64_mem8(int dst, int base, int off) {
        rex(1, dst, base); b(0x0F); b(0xB6); rmMem(dst, base, off);
    }
    void movzx_r64_mem8_idx(int dst, int base, int index, int8_t disp) {
        rex3(1, dst, index, base); b(0x0F); b(0xB6); rmIdx(dst, base, index, disp);
    }
    void mov_byte_mem_imm(int base, int off, uint8_t v) {  // mov byte [base+off], imm8
        b(0xC6); rmMem(0, base, off); b(v);
    }

    // ---- effective addresses / rip ----
    void lea_r64_mem(int dst, int base, int off) {
        rex(1, dst, base); b(0x8D); rmMem(dst, base, off);
    }
    void lea_r64_rip(int dst, int32_t disp) {
        rex(1, dst, -1); b(0x8D); rmRip(dst, disp);
    }
    void mov_r64_rip(int dst, int32_t disp) {        // mov dst, [rip+disp]
        rex(1, dst, -1); b(0x8B); rmRip(dst, disp);
    }
    void mov_r32_rip(int dst, int32_t disp) {
        rex(0, dst, -1); b(0x8B); rmRip(dst, disp);
    }
    void movsxd_rip(int dst, int32_t disp) {
        rex(1, dst, -1); b(0x63); rmRip(dst, disp);
    }
    void mov_rip_r64(int32_t disp, int src) {        // mov [rip+disp], src
        rex(1, src, -1); b(0x89); rmRip(src, disp);
    }
    void mov_rip_r32(int32_t disp, int src) {
        rex(0, src, -1); b(0x89); rmRip(src, disp);
    }

    // ---- control flow ----
    void call_rip(int32_t disp) { b(0xFF); rmRip(2, disp); }   // call qword [rip+disp]
    void call_rel(int32_t disp) { b(0xE8); d((uint32_t)disp); }
    void jmp_rel(int32_t disp) { b(0xE9); d((uint32_t)disp); }
    void jcc_rel(uint8_t cc, int32_t disp) { b(0x0F); b(cc); d((uint32_t)disp); }
    void ret() { b(0xC3); }
    void cqo() { b(0x48); b(0x99); }
    void rep_movsb() { b(0xF3); b(0xA4); }

    // ---- ALU (registers full indices; memory via base/off) ----
    void alu_mem(int opCode, int dst, int base, int off) {  // op dst, [base+off]
        rex(1, dst, base); b((uint8_t)opCode); rmMem(dst, base, off);
    }
    void alu_reg(int opCode, int dst, int src) {            // op dst, src (reg)
        rex(1, dst, src); b((uint8_t)opCode); modrm(3, dst, src);
    }
    void alu_imm_reg(int opExt, int reg, int32_t v) {       // op reg, imm
        if (v >= -128 && v <= 127) {
            rex(1, -1, reg); b(0x83); modrm(3, opExt, reg); b((uint8_t)(int8_t)v);
        } else {
            rex(1, -1, reg); b(0x81); modrm(3, opExt, reg); d((uint32_t)v);
        }
    }
    void imul_r64(int dst, int base, int off) {             // imul dst, [base+off]
        rex(1, dst, base); b(0x0F); b(0xAF); rmMem(dst, base, off);
    }
    void imul_r64_reg(int dst, int src) {                   // imul dst, src
        rex(1, dst, src); b(0x0F); b(0xAF); modrm(3, dst, src);
    }
    void imul_r64_imm(int dst, int32_t v) {                 // imul dst, dst, imm32
        rex(1, -1, dst); b(0x69); modrm(3, dst, dst); d((uint32_t)v);
    }
    void f7_mem(int opExt, int base, int off) {             // idiv/div/neg/not r/m64
        rex(1, -1, base); b(0xF7); rmMem(opExt, base, off);
    }
    void f7_reg(int opExt, int rm) {
        rex(1, -1, rm); b(0xF7); modrm(3, opExt, rm);
    }
    void shift_cl_reg(int opExt, int reg) {                 // shl/shr/sar reg, cl
        rex(1, -1, reg); b(0xD3); modrm(3, opExt, reg);
    }
    void shift_imm_reg(int opExt, int reg, uint8_t sh) {
        rex(1, -1, reg); b(0xC1); modrm(3, opExt, reg); b(sh);
    }
    void cmp_r64_mem(int dst, int base, int off) {          // cmp dst, [base+off]
        rex(1, dst, base); b(0x3B); rmMem(dst, base, off);
    }
    void cmp_r64_reg(int dst, int src) {                    // cmp dst, src
        rex(1, dst, src); b(0x3B); modrm(3, dst, src);
    }
    void cmp_r64_imm32(int dst, int32_t v) {
        if (v >= -128 && v <= 127) { rex(1, -1, dst); b(0x83); modrm(3, 7, dst); b((uint8_t)(int8_t)v); }
        else { rex(1, -1, dst); b(0x81); modrm(3, 7, dst); d((uint32_t)v); }
    }
    void cmp_byte_mem_imm(int base, int off, uint8_t v) {   // cmp byte [base+off], imm8
        b(0x80); rmMem(7, base, off); b(v);
    }
    void cmp_byte_reg_imm(int reg, uint8_t v) {             // cmp reg8, imm8
        b(0x80); modrm(3, 7, reg); b(v);
    }
    void cmp_byte_mem_idx_imm(int base, int index, int8_t disp, uint8_t v) {
        rex3(0, -1, index, base); b(0x80); rmIdx(7, base, index, disp); b(v);
    }
    void test_r64_reg(int x, int y) {
        rex(1, x, y); b(0x85); modrm(3, x, y);
    }
    void test_byte_reg_imm(int reg, uint8_t v) {            // test reg8, imm8
        b(0xF6); modrm(3, 0, reg); b(v);
    }
    void setcc(uint8_t cc) { b(0x0F); b(cc); modrm(3, 0, 0); }  // setcc al
    void setcc_reg(uint8_t cc, int reg8) {                      // setcc r/m8 (full index)
        rex(0, -1, reg8); b(0x0F); b(cc); modrm(3, 0, reg8);
    }
    void movzx_rax_al() { b(0x0F); b(0xB6); b(0xC0); }
    void movzx_r64_reg8(int dst, int src8) {                    // movzx r64, r/m8 (full indices)
        rex(1, dst, src8); b(0x0F); b(0xB6); modrm(3, dst, src8);
    }
    void movd_r64_xmm(int gp, int xmm) {                        // movd r64, xmm (raw bits)
        b(0x66); rex(1, gp, xmm); b(0x0F); b(0x7E); modrm(3, xmm, gp);
    }
    void movd_xmm_r64(int xmm, int gp) {                        // movd xmm, r64 (raw bits)
        b(0x66); rex(1, xmm, gp); b(0x0F); b(0x6E); modrm(3, xmm, gp);
    }
    void movd_xmm_mem(int xmm, int base, int off) {         // movd xmm, [base+off] (raw bits)
        b(0x66); rex(1, xmm, base); b(0x0F); b(0x6E); rmMem(xmm, base, off);
    }
    void xor_reg32(int dst) { rex(0, dst, dst); b(0x31); modrm(3, dst, dst); }
    void xor_r64_reg(int dst, int src) { rex(1, dst, src); b(0x31); modrm(3, dst, src); }
    void or_byte_reg_imm(int reg, uint8_t v) {              // or reg8, imm8
        b(0x80); modrm(3, 1, reg); b(v);
    }
    void and_byte_reg_imm(int reg, uint8_t v) {
        b(0x80); modrm(3, 4, reg); b(v);
    }
    void inc_reg32(int reg) { rex(0, -1, reg); b(0xFF); modrm(3, 0, reg); }
    void inc_r64(int reg) { rex(1, -1, reg); b(0xFF); modrm(3, 0, reg); }
    void dec_reg64(int reg) { rex(1, -1, reg); b(0xFF); modrm(3, 1, reg); }
    void sub_r64_reg(int dst, int src) {                    // sub dst, src
        rex(1, dst, src); b(0x2B); modrm(3, dst, src);
    }
    void add_r64_reg(int dst, int src) {                    // add dst, src
        rex(1, dst, src); b(0x03); modrm(3, dst, src);
    }
    void add_byte_imm(int reg, uint8_t v) { b(0x80); modrm(3, 0, reg); b(v); }
    void and_r32_imm(int reg, uint32_t v) { rex(0, -1, reg); b(0x81); modrm(3, 4, reg); d(v); }
    void or_r32_imm(int reg, uint32_t v) { rex(0, -1, reg); b(0x81); modrm(3, 1, reg); d(v); }
    void mov_byte_reg_imm(int reg, uint8_t v) { b(0xC6); rmMem(0, reg, 0); b(v); }
    void cmp_byte_sib0(int index, int base) {               // cmp byte [base+index], 0
        b(0x80); modrm(0, 7, 4); sib(0, index, base); b(0);
    }

    // ---- SSE ----
    void movss_xmm_mem(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x10); rmMem(x, base, off); }
    void movss_mem_xmm(int base, int off, int x) { b(0xF3); rex(1, x, base); b(0x0F); b(0x11); rmMem(x, base, off); }
    void movsd_xmm_mem(int x, int base, int off) { b(0xF2); rex(1, x, base); b(0x0F); b(0x10); rmMem(x, base, off); }
    void movsd_mem_xmm(int base, int off, int x) { b(0xF2); rex(1, x, base); b(0x0F); b(0x11); rmMem(x, base, off); }
    void movss_xmm_rip(int x, int32_t disp) { b(0xF3); rex(1, x, -1); b(0x0F); b(0x10); rmRip(x, disp); }
    void movss_rip_xmm(int32_t disp, int x) { b(0xF3); rex(1, x, -1); b(0x0F); b(0x11); rmRip(x, disp); }
    void movsd_xmm_rip(int x, int32_t disp) { b(0xF2); rex(1, x, -1); b(0x0F); b(0x10); rmRip(x, disp); }
    void movsd_rip_xmm(int32_t disp, int x) { b(0xF2); rex(1, x, -1); b(0x0F); b(0x11); rmRip(x, disp); }
    void movss_reg(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x10); modrm(3, x, y); }
    void movsd_reg(int x, int y) { b(0xF2); rex(1, x, y); b(0x0F); b(0x10); modrm(3, x, y); }
    void addss(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x58); modrm(3, x, y); }
    void subss(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x5C); modrm(3, x, y); }
    void mulss(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x59); modrm(3, x, y); }
    void divss(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x5E); modrm(3, x, y); }
    void ucomiss(int x, int y) { rex(1, x, y); b(0x0F); b(0x2E); modrm(3, x, y); }
    void ucomiss_mem(int x, int base, int off) { rex(1, x, base); b(0x0F); b(0x2E); rmMem(x, base, off); }
    void addss_mem(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x58); rmMem(x, base, off); }
    void subss_mem(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x5C); rmMem(x, base, off); }
    void mulss_mem(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x59); rmMem(x, base, off); }
    void divss_mem(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x5E); rmMem(x, base, off); }
    void pxor_mem(int x, int base, int off) { b(0x66); rex(1, x, base); b(0x0F); b(0xEF); rmMem(x, base, off); }
    void pxor_rip(int x, int32_t disp) { b(0x66); rex(1, x, -1); b(0x0F); b(0xEF); rmRip(x, disp); }
    void ucomisd(int x, int y) { b(0x66); rex(1, x, y); b(0x0F); b(0x2E); modrm(3, x, y); }
    void roundss(int x, int y, uint8_t imm) { b(0x66); rex(1, x, y); b(0x0F); b(0x3A); b(0x0A); modrm(3, x, y); b(imm); }
    void roundsd(int x, int y, uint8_t imm) { b(0x66); rex(1, x, y); b(0x0F); b(0x3A); b(0x0B); modrm(3, x, y); b(imm); }
    void cvtsi2ss(int x, int base, int off) { b(0xF3); rex(1, x, base); b(0x0F); b(0x2A); rmMem(x, base, off); }
    void cvtsi2ss_reg(int x, int y) { b(0xF3); rex(1, x, y); b(0x0F); b(0x2A); modrm(3, x, y); }
    void cvttss2si(int dst, int base, int off) { b(0xF3); rex(1, dst, base); b(0x0F); b(0x2C); rmMem(dst, base, off); }
    void cvttss2si_reg(int dst, int y) { b(0xF3); rex(1, dst, y); b(0x0F); b(0x2C); modrm(3, dst, y); }
    void cvttsd2si_reg(int dst, int y) { b(0xF2); rex(1, dst, y); b(0x0F); b(0x2C); modrm(3, dst, y); }
    void pshufb(int x, int y) { b(0x66); rex(1, x, y); b(0x0F); b(0x38); b(0x00); modrm(3, x, y); }
    void pand(int x, int y) { b(0x66); rex(1, x, y); b(0x0F); b(0xDB); modrm(3, x, y); }
};

} // namespace x86e