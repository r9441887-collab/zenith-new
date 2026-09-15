// codegen_arm64.cpp — AArch64 backend for "app arm64"
// =========================================================================
// Produces a flat, position-independent AArch64 firmware image for QEMU:
//
//   qemu-system-aarch64 -machine virt -cpu cortex-a53 -kernel fw.bin -nographic
//   (or: -bios fw.bin)
//
// Image layout:
//   [startup] [runtime helpers] [user functions] [data]
//
// Data section: globals (first, offsets are known before codegen) then the
// string pool. X19 always points at the start of the data section, so globals
// are addressed as X19 + known-offset and strings as X19 + patched-offset
// (the offset is only known after layout, so string addresses are emitted as
// a 3-instruction MOVZ/MOVK/MOVK slot that is patched once offsets are known).
//
// Calling convention (internal, AAPCS64-ish):
//   - Integer/pointer args in x0..x7 (up to 8); results in x0.
//   - x19 = data base (constant). x29/x30 = frame pointer / link register.
//   - SP is 16-byte aligned at all call boundaries.
//   - Locals live in the callee frame at [SP + off].
//   - print() writes to the PL011 UART (0x09000000) on the virt machine.
//
// All integer values are 32-bit signed; loads use LDRSW so values are
// sign-extended into 64-bit registers (correct signed div/mod).
// =========================================================================
#include "codegen.h"
#include "ast.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <functional>
#include <cmath>

using namespace std;

// =========================================================================
// AArch64 instruction encoders (32-bit little-endian words)
// =========================================================================
namespace {

enum : int {
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29,
    X30, XSP = 31, XZR = 31
};

constexpr uint32_t PL011_BASE = 0x09000000u;
constexpr uint32_t PL011_FR   = 0x18u;   // flag register
constexpr uint32_t PL011_DR   = 0x00u;   // data register
constexpr uint32_t PL011_IBRD = 0x24u;   // integer baud rate divisor
constexpr uint32_t PL011_FBRD = 0x28u;   // fractional baud rate divisor
constexpr uint32_t PL011_LCRH = 0x2Cu;   // line control (8N1 = 0x70)
constexpr uint32_t PL011_CR   = 0x30u;   // control (UARTEN|TXE|RXE = 0x301)

// MOVZ Xd, #imm16 LSL #(hw*16)
inline uint32_t movz(int rd, uint16_t imm16, int hw) {
    return 0xD2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOVK Xd, #imm16 LSL #(hw*16)
inline uint32_t movk(int rd, uint16_t imm16, int hw) {
    return 0xF2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOVN Xd, #imm16 LSL #(hw*16)
inline uint32_t movn(int rd, uint16_t imm16, int hw) {
    return 0x92800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOV Xd, Xn  (ORR Xd, XZR, Xn)
inline uint32_t mov_reg(int rd, int rn) {
    return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}
// ADD Xd, Xn, #imm (LSL #shift, shift 0 or 12)
inline uint32_t add_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0x91000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUB Xd, Xn, #imm
inline uint32_t sub_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0xD1000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUBS Xd, Xn, #imm
inline uint32_t subs_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0xF1000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// CMP Xn, #imm  (SUBS XZR, Xn, #imm)
inline uint32_t cmp_imm(int rn, uint16_t imm12) {
    return subs_imm(XZR, rn, imm12);
}
// ADD Xd, Xn, Xm
inline uint32_t add_reg(int rd, int rn, int rm) {
    return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUB Xd, Xn, Xm
inline uint32_t sub_reg(int rd, int rn, int rm) {
    return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUBS Xd, Xn, Xm
inline uint32_t subs_reg(int rd, int rn, int rm) {
    return 0xEB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// CMP Xn, Xm
inline uint32_t cmp_reg(int rn, int rm) {
    return subs_reg(XZR, rn, rm);
}
// AND Xd, Xn, Xm
inline uint32_t and_reg(int rd, int rn, int rm) {
    return 0x8A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// ORR Xd, Xn, Xm
inline uint32_t orr_reg(int rd, int rn, int rm) {
    return 0xAA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// EOR Xd, Xn, Xm
inline uint32_t eor_reg(int rd, int rn, int rm) {
    return 0xCA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MVN Xd, Xm  (ORR Xd, XZR, NOT Xm)
inline uint32_t mvn(int rd, int rm) {
    return 0xAA0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
// NEG Xd, Xm  (SUB Xd, XZR, Xm)
inline uint32_t neg_reg(int rd, int rm) {
    return 0xCB0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
// LSL Xd, Xn, Xm
inline uint32_t lsl_reg(int rd, int rn, int rm) {
    return 0x9AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LSR Xd, Xn, Xm
inline uint32_t lsr_reg(int rd, int rn, int rm) {
    return 0x9AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// ASR Xd, Xn, Xm
inline uint32_t asr_reg(int rd, int rn, int rm) {
    return 0x9AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LSR Wd, Wn, #imm  (UBFM Wd, Wn, imm, 31)
inline uint32_t lsr_w_imm(int rd, int rn, uint8_t imm) {
    return 0x53000000u | ((uint32_t)(imm & 31) << 16) | (31u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MUL Xd, Xn, Xm
inline uint32_t mul_reg(int rd, int rn, int rm) {
    return 0x9B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SDIV Xd, Xn, Xm
inline uint32_t sdiv_reg(int rd, int rn, int rm) {
    return 0x9AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MSUB Xd, Wn, Wm, Xa  (Xd = Xa - Wn*Wm)
inline uint32_t msub_reg(int rd, int rn, int rm, int ra) {
    return 0x9B008000u | ((uint32_t)rm << 16) | ((uint32_t)ra << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LDR Xt, [Xn, #imm*8]  (unsigned offset, imm12 = offset/8)
inline uint32_t ldr_x(int rt, int rn, uint16_t imm12) {
    return 0xF9400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STR Xt, [Xn, #imm*8]
inline uint32_t str_x(int rt, int rn, uint16_t imm12) {
    return 0xF9000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDR Wt, [Xn, #imm*4]
inline uint32_t ldr_w(int rt, int rn, uint16_t imm12) {
    return 0xB9400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STR Wt, [Xn, #imm*4]
inline uint32_t str_w(int rt, int rn, uint16_t imm12) {
    return 0xB9000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRSW Xt, [Xn, #imm*4]  (32-bit signed load, sign-extended to 64)
inline uint32_t ldrsw(int rt, int rn, uint16_t imm12) {
    return 0xB9800000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRB Wt, [Xn, #imm]
inline uint32_t ldrb_w(int rt, int rn, uint16_t imm12) {
    return 0x39400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STRB Wt, [Xn, #imm]
inline uint32_t strb_w(int rt, int rn, uint16_t imm12) {
    return 0x39000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRSB Xt, [Xn, #imm]  (signed byte load)
inline uint32_t ldrsb_x(int rt, int rn, uint16_t imm12) {
    return 0x39800000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// B label (imm26, offset from this instruction, /4)
inline uint32_t b_imm_raw(uint32_t imm26) {
    return 0x14000000u | (imm26 & 0x03FFFFFFu);
}
// BL label
inline uint32_t bl_imm(uint32_t imm26) {
    return 0x94000000u | (imm26 & 0x03FFFFFFu);
}
// B.cond label (imm19, /4)
inline uint32_t b_cond(uint32_t cond, uint32_t imm19) {
    return 0x54000000u | ((cond & 15)) | ((imm19 & 0x7FFFFu) << 5);
}
// CBZ Xt, label
inline uint32_t cbz(int rt, uint32_t imm19) {
    return 0xB4000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt;
}
// CBNZ Xt, label
inline uint32_t cbnz(int rt, uint32_t imm19) {
    return 0xB5000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt;
}
// TBNZ Wt, #bit, label  (test bit and branch if non-zero)
inline uint32_t tbnz_w(int rt, uint32_t bit, uint32_t imm14) {
    return 0x37000000u | ((bit & 31u) << 19) | ((imm14 & 0x3FFFu) << 5) | (uint32_t)rt;
}
// CSET Xd, cond  (= CSINC Xd, XZR, XZR, inv(cond))
inline uint32_t cset(int rd, uint32_t cond) {
    return 0x9A9F03E0u | (((cond ^ 1) & 15) << 12) | (uint32_t)rd;
}
// BLR Xn
inline uint32_t blr(int rn) {
    return 0xD63F0000u | ((uint32_t)rn << 5);
}
// BR Xn
inline uint32_t br(int rn) {
    return 0xD61F0000u | ((uint32_t)rn << 5);
}
// RET (X30)
inline uint32_t ret_instr() {
    return 0xD65F03C0u;
}
// NOP
inline uint32_t nop_instr() {
    return 0xD503201Fu;
}
// ADR Xd, label (imm21*4, relative)
inline uint32_t adr(int rd, int32_t imm21) {
    uint32_t immhi = (uint32_t)(imm21 >> 2) & 0x7FFFFu;
    uint32_t immlo = (uint32_t)imm21 & 1u;
    return 0x10000000u | (immlo << 29) | (immhi << 5) | (uint32_t)rd;
}
// ADRP Xd, label (imm21 in pages of 4096)
inline uint32_t adrp(int rd, int32_t imm21) {
    uint32_t immhi = (uint32_t)(imm21 >> 2) & 0x7FFFFu;
    uint32_t immlo = (uint32_t)imm21 & 1u;
    return 0x90000000u | (immlo << 29) | (immhi << 5) | (uint32_t)rd;
}

// ---- inline-asm support: 32-bit (W) ALU variants ----
inline uint32_t mov_w_reg(int rd, int rn) {  // MOV Wd, Wm (ORR Wd, WZR, Wm)
    return 0x2A0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}
inline uint32_t add_w_reg(int rd, int rn, int rm) {
    return 0x0B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sub_w_reg(int rd, int rn, int rm) {
    return 0x4B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t cmp_w_reg(int rn, int rm) {  // CMP Wn, Wm (SUBS WZR, Wn, Wm)
    return 0x6B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5);
}
inline uint32_t and_w_reg(int rd, int rn, int rm) {
    return 0x0A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t orr_w_reg(int rd, int rn, int rm) {
    return 0x2A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t eor_w_reg(int rd, int rn, int rm) {
    return 0x4A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t neg_w_reg(int rd, int rm) {  // NEG Wd, Wm (SUB Wd, WZR, Wm)
    return 0x4B0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mvn_x(int rd, int rm) {  // MVN Xd, Xm (ORN Xd, XZR, Xm)
    return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mvn_w(int rd, int rm) {  // MVN Wd, Wm (ORN Wd, WZR, Wm)
    return 0x2A2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mul_w_reg(int rd, int rn, int rm) {
    return 0x1B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sdiv_w_reg(int rd, int rn, int rm) {
    return 0x1AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t udiv_x(int rd, int rn, int rm) {
    return 0x9AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t udiv_w(int rd, int rn, int rm) {
    return 0x1AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// 32-bit register shifts
inline uint32_t lsl_w_reg(int rd, int rn, int rm) {
    return 0x1AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t lsr_w_reg(int rd, int rn, int rm) {
    return 0x1AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_w_reg(int rd, int rn, int rm) {
    return 0x1AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t add_w_imm(int rd, int rn, uint16_t imm12) {
    return 0x11000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sub_w_imm(int rd, int rn, uint16_t imm12) {
    return 0x51000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t cmp_w_imm(int rn, uint16_t imm12) {
    return 0x71000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5);
}
// 64-bit register-offset loads/stores: LDR Xt,[Xn,Xm]
inline uint32_t ldr_x_reg(int rt, int rn, int rm) {
    return 0xF8600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t str_x_reg(int rt, int rn, int rm) {
    return 0xF8000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t ldr_w_reg(int rt, int rn, int rm) {
    return 0xB8600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t str_w_reg(int rt, int rn, int rm) {
    return 0xB8000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t ldrb_w_reg(int rt, int rn, int rm) {
    return 0x38600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t strb_w_reg(int rt, int rn, int rm) {
    return 0x38000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// 64-bit immediate shifts: UBFM/SBFM, sh 0..63
inline uint32_t lsl_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0xD3400000u | ((uint32_t)((64 - sh) & 63) << 16) | ((uint32_t)(63 - sh) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t lsr_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0xD3400000u | ((uint32_t)sh << 16) | (63u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0x93400000u | ((uint32_t)sh << 16) | (63u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// 32-bit immediate shifts (LSR W imm already exists as lsr_w_imm)
inline uint32_t lsl_w_imm(int rd, int rn, uint8_t sh) {
    sh &= 31;
    return 0x53000000u | ((uint32_t)((32 - sh) & 31) << 16) | ((uint32_t)(31 - sh) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_w_imm(int rd, int rn, uint8_t sh) {
    sh &= 31;
    return 0x13000000u | ((uint32_t)sh << 16) | (31u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// RET Xn
inline uint32_t ret_reg(int rn) {
    return 0xD65F0000u | ((uint32_t)rn << 5);
}
// system hints
inline uint32_t yield_instr()  { return 0xD503203Fu; }
inline uint32_t wfe_instr()    { return 0xD503205Fu; }
inline uint32_t wfi_instr()    { return 0xD503207Fu; }
inline uint32_t sev_instr()    { return 0xD503209Fu; }
inline uint32_t svc_imm(uint16_t imm16) { return 0xD4000001u | ((uint32_t)imm16 << 5); }
inline uint32_t hlt_imm(uint16_t imm16) { return 0xD4400000u | ((uint32_t)imm16 << 5); }
inline uint32_t brk_imm(uint16_t imm16) { return 0xD4200000u | ((uint32_t)imm16 << 5); }

} // namespace

// =========================================================================
// AArch64 backend state machine (per compileArm64() call)
// =========================================================================
namespace {

void u32pat(vector<uint8_t>& buf, int pos, uint32_t v) {
    if (pos < 0 || pos + 3 >= (int)buf.size()) return;
    buf[(size_t)pos]     = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)((v >> 8) & 0xFF);
    buf[(size_t)pos + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[(size_t)pos + 3] = (uint8_t)((v >> 24) & 0xFF);
}

// ARM condition codes (AArch64, flags from CMP left,right).
static int ccForOp(const string& op) {
    if (op == "==") return 0;   // EQ
    if (op == "!=") return 1;   // NE
    if (op == "<")  return 11;  // LT
    if (op == "<=") return 13;  // LE
    if (op == ">")  return 12;  // GT
    if (op == ">=") return 10;  // GE
    return -1;
}

static int invCc(int cc) {
    switch (cc) {
        case 0:  return 1;
        case 1:  return 0;
        case 10: return 11;
        case 11: return 10;
        case 12: return 13;
        case 13: return 12;
        default: return cc;
    }
}

static bool getIntConst(Expr* e, int64_t& v) {
    if (auto n = dynamic_cast<NumberExpr*>(e)) { v = n->value; return true; }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        int64_t cv;
        if (u->op == "-" && getIntConst(u->operand.get(), cv)) { v = -cv; return true; }
        return false;
    }
    return false;
}

enum class BrKind { B, Cond, Cbz, Cbnz, Tbnz };

struct BrRef {
    int pos = 0;
    int label = -1;
    BrKind kind = BrKind::B;
    int cc = 0;   // for Cond; also holds the bit for Tbnz
    int rt = 0;   // for Cbz/Cbnz
};

struct A64 {
    Program& prog;
    explicit A64(Program& p) : prog(p) {}

    // ---- per-compile state ----
    vector<uint8_t> code;
    vector<BrRef> branches;
    vector<int> labelPositions;
    int nextLabel = 0;
    int newLabel() { return nextLabel++; }
    void emitLabel(int label) {
        if (label >= (int)labelPositions.size()) labelPositions.resize(label + 1, -1);
        labelPositions[label] = (int)code.size();
    }

    // BL fixups (resolved after full layout)
    struct CallFix { int pos; string target; };
    vector<CallFix> callFixups;

    // strings (dedup)
    vector<string> strings;
    int stringIdx(const string& s) {
        for (int i = 0; i < (int)strings.size(); i++)
            if (strings[i] == s) return i;
        strings.push_back(s);
        return (int)strings.size() - 1;
    }

    // globals: offsets from the start of the data section (known before codegen)
    struct GInfo { int off; int size; Type type; };
    unordered_map<string, GInfo> globals;
    vector<string> globalOrder;

    // struct layouts (32-bit model: every field is 4 bytes)
    unordered_map<string, pair<int, unordered_map<string, pair<int, Type>>>> structs;
    int structSize(const string& name) {
        auto it = structs.find(name);
        return it == structs.end() ? 4 : it->second.first;
    }
    int typeSize(const Type& t, int arraySize = 0) {
        if (arraySize > 0) return arraySize * 4;
        switch (t.kind) {
            case TypeKind::Struct: return structSize(t.structName);
            case TypeKind::String: return 8;
            default: return 4;
        }
    }
    int elementSize(const Type& t) { return typeSize(t); }

    // ---- frame info ----
    struct VarInfo32 { int off; Type type; bool isParam; bool used; int size; };
    unordered_map<string, VarInfo32> vars;
    int frameSize = 0;      // whole frame (locals + saved LR), 16-aligned
    int tempBytes = 0;      // bytes of live temp values pushed above the frame
    int retLabel = -1;
    int swCur = 0;
    int swTempOff = 0;
    bool hasCalls = false;

    unordered_map<string, size_t> funcOffsets;
    vector<string> funcOrder;
    string entryName;

    // startup data-base fixups: positions of the ADRP / ADD that compute X19
    int startupAdrpPos = -1;
    int startupAddPos = -1;

    // ---- Raspberry Pi peripheral bases (selected in compile() from chip:) --
    uint32_t periphBase   = 0x3F000000u;   // BCM2835/2837 (Pi1-Pi3)
    uint32_t gpioBase     = 0x3F200000u;
    uint32_t uartBase     = 0x3F201000u;   // PL011
    uint32_t sysTimerBase = 0x3F003000u;   // 1 MHz microsecond counter (CLO @ +0x04)
    int ledGpio = 47;                      // Pi3 activity LED (Pi4 = 16)

    // ---- assembly primitives ----
    void u32(uint32_t v) {
        code.push_back((uint8_t)(v & 0xFF));
        code.push_back((uint8_t)((v >> 8) & 0xFF));
        code.push_back((uint8_t)((v >> 16) & 0xFF));
        code.push_back((uint8_t)((v >> 24) & 0xFF));
    }

    // Load 64-bit constant into rt.
    void loadConst(int rt, uint64_t v) {
        uint16_t lo = (uint16_t)(v & 0xFFFF);
        uint16_t hi = (uint16_t)((v >> 16) & 0xFFFF);
        uint16_t h3 = (uint16_t)((v >> 32) & 0xFFFF);
        uint16_t h4 = (uint16_t)((v >> 48) & 0xFFFF);
        if (h4 == 0 && h3 == 0 && hi == 0) {
            u32(movz(rt, lo, 0));
        } else if (h4 == 0 && h3 == 0) {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
        } else if (h4 == 0) {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
            u32(movk(rt, h3, 2));
        } else {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
            u32(movk(rt, h3, 2));
            u32(movk(rt, h4, 3));
        }
    }

    void mov(int rd, int rn) { u32(mov_reg(rd, rn)); }
    void addImm(int rd, int rn, uint16_t imm12) { u32(add_imm(rd, rn, imm12)); }
    void subImm(int rd, int rn, uint16_t imm12) { u32(sub_imm(rd, rn, imm12)); }
    void cmpImm(int rn, uint16_t imm12) { u32(cmp_imm(rn, imm12)); }
    void addReg(int rd, int rn, int rm) { u32(add_reg(rd, rn, rm)); }
    void subReg(int rd, int rn, int rm) { u32(sub_reg(rd, rn, rm)); }
    void cmpReg(int rn, int rm) { u32(cmp_reg(rn, rm)); }
    void andReg(int rd, int rn, int rm) { u32(and_reg(rd, rn, rm)); }
    void orrReg(int rd, int rn, int rm) { u32(orr_reg(rd, rn, rm)); }
    void eorReg(int rd, int rn, int rm) { u32(eor_reg(rd, rn, rm)); }
    void negReg(int rd, int rm) { u32(neg_reg(rd, rm)); }
    void lslR(int rd, int rn, int rm) { u32(lsl_reg(rd, rn, rm)); }
    void lsrR(int rd, int rn, int rm) { u32(lsr_reg(rd, rn, rm)); }
    void asrR(int rd, int rn, int rm) { u32(asr_reg(rd, rn, rm)); }
    void mulR(int rd, int rn, int rm) { u32(mul_reg(rd, rn, rm)); }
    void sdivR(int rd, int rn, int rm) { u32(sdiv_reg(rd, rn, rm)); }
    void msubR(int rd, int rn, int rm, int ra) { u32(msub_reg(rd, rn, rm, ra)); }
    void ldrX(int rt, int rn, uint32_t off) { u32(ldr_x(rt, rn, (uint16_t)(off / 8))); }
    void strX(int rt, int rn, uint32_t off) { u32(str_x(rt, rn, (uint16_t)(off / 8))); }
    void ldrW(int rt, int rn, uint32_t off) { u32(ldr_w(rt, rn, (uint16_t)(off / 4))); }
    void strW(int rt, int rn, uint32_t off) { u32(str_w(rt, rn, (uint16_t)(off / 4))); }
    void ldrswW(int rt, int rn, uint32_t off) { u32(ldrsw(rt, rn, (uint16_t)(off / 4))); }
    void ldrbW(int rt, int rn, uint32_t off) { u32(ldrb_w(rt, rn, (uint16_t)off)); }
    void strbW(int rt, int rn, uint32_t off) { u32(strb_w(rt, rn, (uint16_t)off)); }
    void ldrsbX(int rt, int rn, uint32_t off) { u32(ldrsb_x(rt, rn, (uint16_t)off)); }
    void csetR(int rd, int cc) { u32(cset(rd, (uint32_t)cc)); }

    // branch emitters (fixups resolved per function)
    void b_cc(int cc, int label) {
        int p = (int)code.size();
        u32(b_cond((uint32_t)cc, 0));
        branches.push_back({p, label, BrKind::Cond, cc, 0});
    }
    void b_imm(int label) {
        int p = (int)code.size();
        u32(b_imm_raw(0));
        branches.push_back({p, label, BrKind::B, -1, 0});
    }
    void cbzR(int rt, int label) {
        int p = (int)code.size();
        u32(cbz(rt, 0));
        branches.push_back({p, label, BrKind::Cbz, -1, rt});
    }
    void cbnzR(int rt, int label) {
        int p = (int)code.size();
        u32(cbnz(rt, 0));
        branches.push_back({p, label, BrKind::Cbnz, -1, rt});
    }
    void tbnzR(int rt, int bit, int label) {
        int p = (int)code.size();
        u32(tbnz_w(rt, (uint32_t)bit, 0));
        branches.push_back({p, label, BrKind::Tbnz, bit, rt});
    }

    void bl_fixup(const string& target) {
        int p = (int)code.size();
        u32(bl_imm(0));
        callFixups.push_back({p, target});
    }

    void ret() { u32(ret_instr()); }
    void nop() { u32(nop_instr()); }

    // SUB SP, SP, #bytes (imm12 max 4095, chunked)
    void subSp(int bytes) {
        while (bytes > 0) {
            int s = std::min(bytes, 4095);
            u32(sub_imm(XSP, XSP, (uint16_t)s));
            bytes -= s;
        }
    }
    void addSp(int bytes) {
        while (bytes > 0) {
            int s = std::min(bytes, 4095);
            u32(add_imm(XSP, XSP, (uint16_t)s));
            bytes -= s;
        }
    }

    // ---- stack value spill/restore (used by binary expression evaluation) ----
    void pushX0() { subSp(8); strX(X0, XSP, 0); tempBytes += 8; }
    void popX1()  { ldrX(X1, XSP, 0); addSp(8); tempBytes -= 8; }

    // X0 = X0 + v
    void addImmX0(int64_t v) {
        if (v == 0) return;
        if (v > 0 && v <= 4095) { addImm(X0, X0, (uint16_t)v); return; }
        if (v < 0 && v >= -4095) { subImm(X0, X0, (uint16_t)(-v)); return; }
        loadConst(X1, (uint64_t)v);
        addReg(X0, X0, X1);
    }

    // rd = SP + off  (any positive offset)
    void addSpAddr(int rd, int off) {
        int rem = off;
        bool first = true;
        while (rem > 0 || first) {
            int s = std::min(rem > 0 ? rem : 0, 4095);
            if (first) { u32(add_imm(rd, XSP, (uint16_t)s)); first = false; }
            else u32(add_imm(rd, rd, (uint16_t)s));
            rem -= s;
            if (rem <= 0) break;
        }
    }

    // load/store 32-bit value at [SP + off + tempBytes]
    void loadFromOff(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 3) == 0 && o / 4 <= 4095) { ldrswW(rt, XSP, (uint32_t)o); return; }
        addSpAddr(X1, o);
        ldrswW(rt, X1, 0);
    }
    void storeToOff(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 3) == 0 && o / 4 <= 4095) { strW(rt, XSP, (uint32_t)o); return; }
        int scratch = (rt == X0) ? X1 : X0;
        addSpAddr(scratch, o);
        strW(rt, scratch, 0);
    }
    void loadFromOff64(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 7) == 0 && o / 8 <= 4095) { ldrX(rt, XSP, (uint32_t)o); return; }
        addSpAddr(X1, o);
        ldrX(rt, X1, 0);
    }
    void storeToOff64(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 7) == 0 && o / 8 <= 4095) { strX(rt, XSP, (uint32_t)o); return; }
        int scratch = (rt == X0) ? X1 : X0;
        addSpAddr(scratch, o);
        strX(rt, scratch, 0);
    }

    VarInfo32* var(const string& n) { auto it = vars.find(n); return it == vars.end() ? nullptr : &it->second; }
    GInfo* global(const string& n) { auto it = globals.find(n); return it == globals.end() ? nullptr : &it->second; }

    Type varType(const string& n) {
        auto v = var(n);
        if (v) return v->type;
        auto g = global(n);
        if (g) return g->type;
        return Type(TypeKind::Int);
    }

    // ---- global access (offset from data start, known before codegen) ----
    void loadGlobal(int rt, int off) {
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095) { ldrswW(rt, X19, (uint32_t)off); return; }
        loadConst(X1, (uint64_t)off);
        addReg(X1, X19, X1);
        ldrswW(rt, X1, 0);
    }
    void storeGlobal(int rt, int off) {
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095) { strW(rt, X19, (uint32_t)off); return; }
        int scratch = (rt == X0) ? X1 : X0;
        loadConst(scratch, (uint64_t)off);
        addReg(scratch, X19, scratch);
        strW(rt, scratch, 0);
    }
    void loadStrAddrKnown(int rt, int off) {
        if (off >= 0 && off <= 4095) { u32(add_imm(rt, X19, (uint16_t)off)); return; }
        loadConst(X1, (uint64_t)off);
        addReg(rt, X19, X1);
    }

    // ---- string address with post-layout patch ----
    struct StrFix { int pos; int slot; };
    vector<StrFix> strFixups;
    // Emit: X1 = <patched str offset>; rt = X19 + X1  (5 fixed-size instructions)
    void emitStrAddr(int rt, int slot) {
        int pos = (int)code.size();
        u32(movz(X1, 0, 0));
        u32(movk(X1, 0, 1));
        u32(movk(X1, 0, 2));
        strFixups.push_back({pos, slot});
        addReg(rt, X19, X1);
    }
    void patchStrSlots(vector<uint8_t>& img, size_t baseOff, size_t dataStart,
                       const vector<StrFix>& fixes, const vector<uint32_t>& strOfs) {
        for (auto& fx : fixes) {
            uint32_t v = strOfs[(size_t)fx.slot] - (uint32_t)dataStart;
            uint16_t lo = (uint16_t)(v & 0xFFFF);
            uint16_t hi = (uint16_t)((v >> 16) & 0xFFFF);
            size_t pos = baseOff + (size_t)fx.pos;
            u32pat(img, (int)pos, movz(X1, lo, 0));
            u32pat(img, (int)pos + 4, movk(X1, hi, 1));
        }
    }

    // emitLoadVar / emitStoreVar
    void emitLoadVar(int rt, const string& n) {
        auto v = var(n);
        if (v) {
            if (v->size == 8) loadFromOff64(rt, v->off);
            else loadFromOff(rt, v->off);
            return;
        }
        auto g = global(n);
        if (g) { loadGlobal(rt, g->off); return; }
        cerr << "arm64: undefined variable '" << n << "'\n";
        loadConst(rt, 0);
    }
    void emitStoreVar(const string& n, int reg) {
        auto v = var(n);
        if (v) {
            if (v->size == 8) storeToOff64(reg, v->off);
            else storeToOff(reg, v->off);
            return;
        }
        auto g = global(n);
        if (g) { storeGlobal(reg, g->off); return; }
        cerr << "arm64: undefined variable '" << n << "'\n";
    }

    // ---- type helpers ----
    Type typeOf(Expr* e) {
        if (auto id = dynamic_cast<IdentExpr*>(e)) return varType(id->name);
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) return typeOf(a->array.get());
        if (auto m = dynamic_cast<MemberExpr*>(e)) {
            Type ot = typeOf(m->object.get());
            if (ot.kind == TypeKind::Struct) {
                auto it = structs.find(ot.structName);
                if (it != structs.end()) {
                    auto f = it->second.second.find(m->member);
                    if (f != it->second.second.end()) return f->second.second;
                }
            }
            return Type(TypeKind::Int);
        }
        if (auto c = dynamic_cast<CallExpr*>(e))
            for (auto& f : prog.functions)
                if (f->name == c->name && !f->isExtern) return f->returnType;
        return Type(TypeKind::Int);
    }
    int fieldOffsetOf(const Type& t, const string& member) {
        if (t.kind == TypeKind::Struct) {
            auto it = structs.find(t.structName);
            if (it != structs.end()) {
                auto f = it->second.second.find(member);
                if (f != it->second.second.end()) return f->second.first;
            }
        }
        cerr << "arm64: unknown field '" << member << "'\n";
        return 0;
    }
    int fieldOffset(Expr* obj, const string& member) { return fieldOffsetOf(typeOf(obj), member); }
    Type fieldTypeOf(const Type& t, const string& m) {
        if (t.kind == TypeKind::Struct) {
            auto it = structs.find(t.structName);
            if (it != structs.end()) {
                auto f = it->second.second.find(m);
                if (f != it->second.second.end()) return f->second.second;
            }
        }
        return Type(TypeKind::Int);
    }
    bool isFloatExpr(Expr* e) {
        if (dynamic_cast<FloatExpr*>(e)) return true;
        if (dynamic_cast<NumberExpr*>(e)) return false;
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            auto v = var(id->name);  if (v) return v->type.kind == TypeKind::Float;
            auto g = global(id->name); if (g) return g->type.kind == TypeKind::Float;
            return false;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) return isFloatExpr(b->left.get()) || isFloatExpr(b->right.get());
        if (auto u = dynamic_cast<UnaryExpr*>(e)) return isFloatExpr(u->operand.get());
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) return isFloatExpr(a->array.get());
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            for (auto& f : prog.functions)
                if (f->name == c->name && !f->isExtern) return f->returnType.kind == TypeKind::Float;
        }
        return false;
    }

    // ---- address computation (result in X0) ----
    void emitAddr(Expr* path) {
        if (auto id = dynamic_cast<IdentExpr*>(path)) {
            if (auto v = var(id->name)) { addSpAddr(X0, v->off + tempBytes); return; }
            auto g = global(id->name);
            if (g) { loadStrAddrKnown(X0, g->off); return; }
            cerr << "arm64: undefined variable '" << id->name << "'\n";
            loadConst(X0, 0);
            return;
        }
        if (auto aof = dynamic_cast<AddressOfExpr*>(path)) {
            if (auto v = var(aof->name)) { addSpAddr(X0, v->off + tempBytes); return; }
            auto g = global(aof->name);
            if (g) { loadStrAddrKnown(X0, g->off); return; }
            cerr << "arm64: undefined variable '" << aof->name << "'\n";
            loadConst(X0, 0);
            return;
        }
        if (auto mem = dynamic_cast<MemberExpr*>(path)) {
            emitAddr(mem->object.get());
            addImmX0(fieldOffset(mem->object.get(), mem->member));
            return;
        }
        if (auto arr = dynamic_cast<ArrayAccessExpr*>(path)) {
            int elem = elementSize(typeOf(arr->array.get()));
            emitAddr(arr->array.get());
            int64_t ci;
            if (getIntConst(arr->index.get(), ci)) {
                addImmX0(ci * elem);
            } else {
                pushX0();
                emitExpr(arr->index.get());
                if (elem == 4) { loadConst(X1, 2); lslR(X0, X0, X1); }
                else if (elem == 8) { loadConst(X1, 3); lslR(X0, X0, X1); }
                else if (elem > 1) { loadConst(X1, (uint64_t)elem); mulR(X0, X0, X1); }
                popX1();
                addReg(X0, X1, X0);
            }
            return;
        }
        if (auto d = dynamic_cast<DerefExpr*>(path)) {
            emitExpr(d->ptr.get());
            return;
        }
        cerr << "arm64: unhandled address expression\n";
        loadConst(X0, 0);
    }

    void emitAddrBase(const string& name) {
        if (auto v = var(name)) { addSpAddr(X0, v->off + tempBytes); return; }
        auto g = global(name);
        if (g) { loadStrAddrKnown(X0, g->off); return; }
        cerr << "arm64: undefined variable '" << name << "'\n";
        loadConst(X0, 0);
    }

    // ---- expression / statement dispatch ----
    int emitExpr(Expr* e);
    int emitBinInt(BinaryExpr* bin);
    int emitCall(CallExpr* c);
    bool tryBuiltin(CallExpr* c);
    void emitStmt(Stmt* s, int* brk, int* con, int* end);
    void emitAsmInstr(const AsmInstr& instr);
    void emitBlock(const Block& b, int* brk, int* con, int* end);
    int emitCondJump(Expr* c, int label, bool wantTrue);
    void emitSwitch(SwitchStmt* sw);
    void emitReturn(Expr* v, int retLabel);
    void allocVarSlots(FunctionDecl* f);
    void resetFn();
    void emitRuntime(const string& name);
    void emitStartup();
    void emitGlobalInit();
    void resolveBranches(const string& fn) {
        for (auto& b : branches) {
            int target = labelPositions[b.label];
            int pc = b.pos;
            switch (b.kind) {
                case BrKind::Cond: {
                    int imm19 = (target - pc) / 4;
                    if (imm19 < -262144 || imm19 > 262143) {
                        cerr << "arm64: B.cond out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, b_cond((uint32_t)b.cc, (uint32_t)(imm19 & 0x7FFFF)));
                    break;
                }
                case BrKind::Cbz:
                case BrKind::Cbnz: {
                    int imm19 = (target - pc) / 4;
                    if (imm19 < -262144 || imm19 > 262143) {
                        cerr << "arm64: CBZ/CBNZ out of range in '" << fn << "'\n";
                        continue;
                    }
                    uint32_t imm = (uint32_t)(imm19 & 0x7FFFF);
                    if (b.kind == BrKind::Cbz) u32pat(code, b.pos, cbz(b.rt, imm));
                    else u32pat(code, b.pos, cbnz(b.rt, imm));
                    break;
                }
                case BrKind::Tbnz: {
                    int imm14 = (target - pc) / 4;
                    if (imm14 < -8192 || imm14 > 8191) {
                        cerr << "arm64: TBNZ out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, tbnz_w(b.rt, (uint32_t)b.cc, (uint32_t)(imm14 & 0x3FFF)));
                    break;
                }
                case BrKind::B:
                default: {
                    int imm26 = (target - pc) / 4;
                    if (imm26 < -33554432 || imm26 > 33554431) {
                        cerr << "arm64: B out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, b_imm_raw((uint32_t)(imm26 & 0x3FFFFFF)));
                    break;
                }
            }
        }
    }

    // ---- per-function images ----
    struct FnImg {
        string name;
        vector<uint8_t> bytes;
        vector<CallFix> bls;
        vector<StrFix> strFixes;
    };
    vector<FnImg> userImgs;
    vector<FnImg> runtimeImgs;

    bool compile(const string& outputPath);
};

// =========================================================================
// Statements
// =========================================================================
void A64::emitStmt(Stmt* s, int* brk, int* con, int* end) {
    if (auto v = dynamic_cast<VarDecl*>(s)) {
        auto vi = var(v->name);
        if (vi && v->init) {
            emitExpr(v->init.get());
            if (vi->size == 8) storeToOff64(X0, vi->off);
            else storeToOff(X0, vi->off);
        }
        return;
    }
    if (auto a = dynamic_cast<AssignStmt*>(s)) {
        if (a->memberPath.empty() && !a->indexExpr) {
            emitExpr(a->value.get());
            emitStoreVar(a->name, X0);
            return;
        }
        if (!a->indexExpr) {
            if (auto v = var(a->name)) {
                int total = v->off;
                Type t = v->type;
                for (auto& m : a->memberPath) { total += fieldOffsetOf(t, m); t = fieldTypeOf(t, m); }
                if (total >= 0 && total / 4 <= 4095) {
                    emitExpr(a->value.get());
                    storeToOff(X0, total);
                    return;
                }
            }
        }
        emitAddrBase(a->name);
        if (a->indexExpr) {
            int elem = elementSize(varType(a->name));
            pushX0();
            emitExpr(a->indexExpr.get());
            if (elem == 4) { loadConst(X1, 2); lslR(X0, X0, X1); }
            else if (elem == 8) { loadConst(X1, 3); lslR(X0, X0, X1); }
            else if (elem > 1) { loadConst(X1, (uint64_t)elem); mulR(X0, X0, X1); }
            popX1();
            addReg(X0, X1, X0);
        }
        int total = 0;
        Type t = varType(a->name);
        for (auto& m : a->memberPath) { total += fieldOffsetOf(t, m); t = fieldTypeOf(t, m); }
        addImmX0(total);
        pushX0();
        emitExpr(a->value.get());
        mov(X1, X0);
        popX1();
        strW(X1, X0, 0);
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        emitAddr(pa->ptr.get());
        pushX0();
        emitExpr(pa->value.get());
        mov(X1, X0);
        popX1();
        strW(X1, X0, 0);
        return;
    }
    if (auto es = dynamic_cast<ExprStmt*>(s)) { emitExpr(es->expr.get()); return; }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        int trueL = newLabel();
        int endL = newLabel();
        emitCondJump(ifs->condition.get(), trueL, true);
        emitBlock(ifs->elseBlock, brk, con, end);
        b_imm(endL);
        emitLabel(trueL);
        emitBlock(ifs->thenBlock, brk, con, end);
        emitLabel(endL);
        return;
    }
    if (auto ws = dynamic_cast<WhileStmt*>(s)) {
        int startL = newLabel();
        int doneL = newLabel();
        emitLabel(startL);
        emitCondJump(ws->condition.get(), doneL, false);
        emitBlock(ws->body, &doneL, &startL, end);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto ls = dynamic_cast<LoopStmt*>(s)) {
        int startL = newLabel();
        int doneL = newLabel();
        emitLabel(startL);
        emitBlock(ls->body, &doneL, &startL, end);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto fs = dynamic_cast<ForStmt*>(s)) {
        int startL = newLabel();
        int stepL = newLabel();
        int doneL = newLabel();
        emitExpr(fs->start.get());
        emitStoreVar(fs->varName, X0);
        emitLabel(startL);
        emitLoadVar(X0, fs->varName);
        pushX0();
        emitExpr(fs->end.get());
        popX1();                    // X1 = counter, X0 = end
        cmpReg(X1, X0);
        int64_t sv = 1;
        bool sConst = fs->step ? getIntConst(fs->step.get(), sv) : false;
        int cc = (sConst && sv < 0) ? 13 : 10;  // LE for decreasing, GE otherwise
        b_cc(cc, doneL);
        emitBlock(fs->body, &doneL, &stepL, end);
        emitLabel(stepL);
        emitLoadVar(X0, fs->varName);
        pushX0();
        if (fs->step) emitExpr(fs->step.get());
        else loadConst(X0, 1);
        popX1();
        addReg(X0, X1, X0);
        emitStoreVar(fs->varName, X0);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) { emitSwitch(sw); return; }
    if (dynamic_cast<BreakStmt*>(s)) { if (brk) b_imm(*brk); return; }
    if (dynamic_cast<ContinueStmt*>(s)) { if (con) b_imm(*con); return; }
    if (auto r = dynamic_cast<ReturnStmt*>(s)) { emitReturn(r->value.get(), retLabel); return; }
    if (auto as = dynamic_cast<AsmStmt*>(s)) {
        for (auto& instr : as->instrs) emitAsmInstr(instr);
        return;
    }
}

void A64::emitBlock(const Block& b, int* brk, int* con, int* end) {
    for (auto& s : b.stmts) emitStmt(s.get(), brk, con, end);
}

// =========================================================================
// AArch64 inline assembler (asm {} / asm32 {} / asm16 {} blocks).
//
// Registers: x0-x30, w0-w30, sp, wsp, xzr/zr, wzr. 'asm' blocks are 64-bit
// register width everywhere; a register spelled 'w' selects a 32-bit
// (zero/sign-extending) operation. Memory operands use [base, offset] or
// [base, regoffset]; offsets are unscaled byte displacements, multiple of the
// access size for ldr/str. Branches take a signed byte displacement relative
// to the start of the branch instruction (b/bl = +-128 MB, b.cond/cbz/cbnz =
// +-1 MB); condition-suffixed mnemonics (beq/bne/...) are used instead of
// 'b.eq'.
// =========================================================================
void A64::emitAsmInstr(const AsmInstr& instr) {
    const string mn = instr.mnemonic;

    auto trim = [](string s) {
        while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        return s;
    };
    auto parseReg = [&](const string& raw, int& reg, bool& is64) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        if (s == "sp")  { reg = 31; is64 = true;  return true; }
        if (s == "wsp") { reg = 31; is64 = false; return true; }
        if (s == "xzr" || s == "zr") { reg = 31; is64 = true;  return true; }
        if (s == "wzr") { reg = 31; is64 = false; return true; }
        if ((s[0] == 'x' || s[0] == 'w') && s.size() > 1) {
            int v = 0;
            size_t i = 1;
            while (i < s.size() && isdigit((unsigned char)s[i])) { v = v * 10 + (s[i] - '0'); i++; }
            if (i == s.size() && v <= 30) { reg = v; is64 = (s[0] == 'x'); return true; }
        }
        return false;
    };
    auto parseImm = [&](const string& raw, int64_t& v) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        if (s[0] == '#') s.erase(s.begin());
        if (s.empty()) return false;
        bool neg = false;
        if (s[0] == '-') { neg = true; s.erase(s.begin()); }
        if (s.empty()) return false;
        try {
            size_t idx = 0;
            int64_t val;
            if (s.size() >= 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
                val = (int64_t)std::stoull(s.substr(2), &idx, 16);
                if (idx != s.size() - 2) return false;
            } else {
                val = (int64_t)std::stoull(s, &idx, 10);
                if (idx != s.size()) return false;
            }
            v = neg ? -val : val;
            return true;
        } catch (...) { return false; }
    };
    auto parseDisp = [&](const string& raw, int& disp) -> bool {
        int64_t v;
        if (!parseImm(raw, v)) return false;
        disp = (int)v;
        return true;
    };
    auto condCode = [](const string& s) -> int {
        if (s == "eq") return 0;  if (s == "ne") return 1;
        if (s == "hs" || s == "cs") return 2;  if (s == "lo" || s == "cc") return 3;
        if (s == "mi") return 4;  if (s == "pl") return 5;
        if (s == "vs") return 6;  if (s == "vc") return 7;
        if (s == "hi") return 8;  if (s == "ls") return 9;
        if (s == "ge") return 10; if (s == "lt") return 11;
        if (s == "gt") return 12; if (s == "le") return 13;
        if (s == "al") return 14;
        return -1;
    };
    auto unsupported = [&](const string& what) {
        cerr << "arm64: warning: unsupported asm '" << what << "', skipped\n";
    };
    auto badOperand = [&](const string& why) {
        cerr << "arm64: warning: asm '" << mn << "': " << why << ", skipped\n";
    };

    // ---- register moves & immediate loads ----
    if (mn == "mov" || mn == "movz" || mn == "movk") {
        int rd, rn; bool d64, n64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int64_t imm;
        if (parseImm(instr.op2, imm)) {
            uint64_t v = d64 ? (uint64_t)imm : (uint64_t)(int32_t)(int64_t)imm;
            if (mn == "mov") { loadConst(rd, v); return; }
            int hw = (instr.op3.empty() || instr.op3 == "0") ? 0 : 1;
            uint16_t lo = (uint16_t)(v & 0xFFFF);
            if (mn == "movz") u32(movz(rd, lo, hw));
            else u32(movk(rd, lo, hw));
            return;
        }
        if (parseReg(instr.op2, rn, n64)) {
            if (d64 != n64) { badOperand("mixed x/w registers in mov"); return; }
            u32(d64 ? mov_reg(rd, rn) : mov_w_reg(rd, rn));
            return;
        }
        badOperand("expected register or immediate operand");
        return;
    }

    // ---- two- or three-operand ALU: add/sub/and/orr/eor/mul/sdiv/udiv ----
    auto aluBinary = [&](uint32_t (*xEnc)(int, int, int), uint32_t (*wEnc)(int, int, int),
                         uint32_t xImmBase, uint32_t wImmBase) -> bool {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return false; }
        int rn = rd; bool n64 = d64;
        if (!instr.op2.empty()) {
            if (!parseReg(instr.op2, rn, n64)) { badOperand("bad source register"); return false; }
            if (d64 != n64) { badOperand("mixed x/w registers"); return false; }
        }
        if (instr.op3.empty()) {
            // 2-operand form: rd = rd op rn
            u32(d64 ? xEnc(rd, rd, rn) : wEnc(rd, rd, rn));
            return true;
        }
        int64_t imm;
        if (parseImm(instr.op3, imm)) {
            if (xImmBase == 0) { badOperand("immediate not supported for this operation"); return false; }
            if (d64) {
                if (imm >= 0 && imm <= 4095) { u32(xImmBase | ((uint32_t)imm << 10) | ((uint32_t)rn << 5) | (uint32_t)rd); return true; }
                if (imm < 0 && imm >= -4095) { // ADD --> SUB
                    if (mn == "add") { u32(sub_imm(rd, rn, (uint16_t)(-imm))); return true; }
                    if (mn == "sub") { u32(add_imm(rd, rn, (uint16_t)(-imm))); return true; }
                }
            } else {
                if (imm >= 0 && imm <= 4095) { u32(wImmBase | ((uint32_t)imm << 10) | ((uint32_t)rn << 5) | (uint32_t)rd); return true; }
                if (imm < 0 && imm >= -4095) {
                    if (mn == "add") { u32(sub_w_imm(rd, rn, (uint16_t)(-imm))); return true; }
                    if (mn == "sub") { u32(add_w_imm(rd, rn, (uint16_t)(-imm))); return true; }
                }
            }
            badOperand("immediate out of encoded range (0..4095)");
            return false;
        }
        int rm; bool m64;
        if (!parseReg(instr.op3, rm, m64)) { badOperand("bad third operand"); return false; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return false; }
        u32(d64 ? xEnc(rd, rn, rm) : wEnc(rd, rn, rm));
        return true;
    };

    if (mn == "add") { aluBinary(add_reg, add_w_reg, 0x91000000u, 0x11000000u); return; }
    if (mn == "sub") { aluBinary(sub_reg, sub_w_reg, 0xD1000000u, 0x51000000u); return; }
    if (mn == "and") { aluBinary(and_reg, and_w_reg, 0, 0); return; }   // imm not supported for and
    if (mn == "orr") { aluBinary(orr_reg, orr_w_reg, 0, 0); return; }
    if (mn == "eor") { aluBinary(eor_reg, eor_w_reg, 0, 0); return; }

    if (mn == "mul") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad first source register"); return; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return; }
        int rm = rn; bool m64 = n64;
        if (!instr.op3.empty() && !parseReg(instr.op3, rm, m64)) { badOperand("bad second source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        u32(d64 ? mul_reg(rd, rn, rm) : mul_w_reg(rd, rn, rm));
        return;
    }
    if (mn == "sdiv" || mn == "udiv") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad first source register"); return; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return; }
        int rm = rn; bool m64 = n64;
        if (!instr.op3.empty() && !parseReg(instr.op3, rm, m64)) { badOperand("bad second source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        if (mn == "sdiv") u32(d64 ? sdiv_reg(rd, rn, rm) : sdiv_w_reg(rd, rn, rm));
        else              u32(d64 ? udiv_x(rd, rn, rm)    : udiv_w(rd, rn, rm));
        return;
    }

    // ---- unary ALU: neg/mvn ----
    if (mn == "neg" || mn == "mvn") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rm; bool m64;
        if (!parseReg(instr.op2, rm, m64)) { badOperand("bad source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        if (mn == "neg") u32(d64 ? neg_reg(rd, rm) : neg_w_reg(rd, rm));
        else             u32(d64 ? mvn_x(rd, rm)   : mvn_w(rd, rm));
        return;
    }

    // ---- compare ----
    if (mn == "cmp") {
        int rn; bool n64;
        if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; }
        int64_t imm;
        if (parseImm(instr.op2, imm)) {
            if (imm >= 0 && imm <= 4095) { u32(n64 ? cmp_imm(rn, (uint16_t)imm) : cmp_w_imm(rn, (uint16_t)imm)); return; }
            if (imm < 0 && imm >= -4095) { // cmp rn, -v == adds rn, v
                u32(n64 ? add_imm(rn, rn, (uint16_t)(-imm)) : add_w_imm(rn, rn, (uint16_t)(-imm)));
                return;
            }
            badOperand("cmp immediate out of range (-4095..4095)");
            return;
        }
        int rm; bool m64;
        if (!parseReg(instr.op2, rm, m64)) { badOperand("bad comparator register"); return; }
        if (n64 != m64) { badOperand("mixed x/w registers"); return; }
        u32(n64 ? cmp_reg(rn, rm) : cmp_w_reg(rn, rm));
        return;
    }

    // ---- shifts: lsl/lsr/asr rd, rn, sh  (reg-reg or immediate) ----
    auto shift = [&]() -> bool {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return false; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad source register"); return false; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return false; }
        int64_t imm;
        if (parseImm(instr.op3, imm)) {
            if (d64) {
                if (imm < 0 || imm > 63) { badOperand("shift count must be 0..63"); return false; }
                if (mn == "lsl") u32(lsl_x_imm(rd, rn, (uint8_t)imm));
                else if (mn == "lsr") u32(lsr_x_imm(rd, rn, (uint8_t)imm));
                else u32(asr_x_imm(rd, rn, (uint8_t)imm));
                return true;
            } else {
                if (imm < 0 || imm > 31) { badOperand("shift count must be 0..31"); return false; }
                if (mn == "lsl") u32(lsl_w_imm(rd, rn, (uint8_t)imm));
                else if (mn == "lsr") u32(lsr_w_imm(rd, rn, (uint8_t)imm));
                else u32(asr_w_imm(rd, rn, (uint8_t)imm));
                return true;
            }
        }
        int rm; bool m64;
        if (instr.op3.empty() || !parseReg(instr.op3, rm, m64)) {
            if (instr.op3.empty()) rm = rn, m64 = n64;
            else { badOperand("bad shift operand"); return false; }
        }
        if (d64 != m64) { badOperand("mixed x/w registers"); return false; }
        if (mn == "lsl") u32(d64 ? lsl_reg(rd, rn, rm) : lsl_w_reg(rd, rn, rm));
        else if (mn == "lsr") u32(d64 ? lsr_reg(rd, rn, rm) : lsr_w_reg(rd, rn, rm));
        else u32(d64 ? asr_reg(rd, rn, rm) : asr_w_reg(rd, rn, rm));
        return true;
    };
    if (mn == "lsl" || mn == "lsr" || mn == "asr") { shift(); return; }

    // ---- memory: ldr/str/ldrb/strb/ldrsb/ldrsw ----
    auto memoryOp = [&](bool load, bool byte, bool signExtend) -> bool {
        int rt; bool t64;
        if (!parseReg(instr.op1, rt, t64)) { badOperand("bad register"); return false; }
        if (byte && t64) { badOperand("byte loads/stores require a 'w' register"); return false; }
        if (signExtend && !t64) { badOperand("ldrsb/ldrsw require an 'x' register"); return false; }
        string m = trim(instr.op2);
        if (m.size() < 2 || m.front() != '[' || m.back() != ']') { badOperand("expected [base, offset]"); return false; }
        m = m.substr(1, m.size() - 2);
        size_t comma = m.find(',');
        string baseStr = comma == string::npos ? m : m.substr(0, comma);
        string offStr = comma == string::npos ? "" : m.substr(comma + 1);
        int rn; bool n64;
        if (!parseReg(baseStr, rn, n64)) { badOperand("bad base register"); return false; }
        int rm = -1; bool m64 = true;
        int64_t off = 0;
        bool hasRegOff = false;
        if (!trim(offStr).empty()) {
            if (parseReg(offStr, rm, m64)) { hasRegOff = true; }
            else if (!parseImm(offStr, off)) { badOperand("bad offset"); return false; }
        }
        uint32_t scale = byte ? 1u : (t64 ? 8u : 4u);
        if (hasRegOff) {
            if (byte) u32(load ? ldrb_w_reg(rt, rn, rm) : strb_w_reg(rt, rn, rm));
            else if (t64) u32(load ? ldr_x_reg(rt, rn, rm) : str_x_reg(rt, rn, rm));
            else u32(load ? ldr_w_reg(rt, rn, rm) : str_w_reg(rt, rn, rm));
            return true;
        }
        if (off < 0) { badOperand("negative immediate offsets are not supported"); return false; }
        if (byte) {
            if (off > 4095) { badOperand("byte offset out of range (0..4095)"); return false; }
            u32(signExtend ? ldrsb_x(rt, rn, (uint16_t)off)
                           : (load ? ldrb_w(rt, rn, (uint16_t)off) : strb_w(rt, rn, (uint16_t)off)));
            return true;
        }
        if (off % scale != 0) { badOperand("offset must be a multiple of the access size"); return false; }
        if (off / scale > 4095) { badOperand("offset out of range for this access size"); return false; }
        if (signExtend) {
            u32(ldrsw(rt, rn, (uint16_t)(off / 4)));
        } else if (t64) {
            u32(load ? ldr_x(rt, rn, (uint16_t)(off / 8)) : str_x(rt, rn, (uint16_t)(off / 8)));
        } else {
            u32(load ? ldr_w(rt, rn, (uint16_t)(off / 4)) : str_w(rt, rn, (uint16_t)(off / 4)));
        }
        return true;
    };
    if (mn == "ldr" || mn == "str") { memoryOp(mn == "ldr", false, false); return; }
    if (mn == "ldrb" || mn == "strb") { memoryOp(mn == "ldrb", true, false); return; }
    if (mn == "ldrsb") { memoryOp(true, true, true); return; }
    if (mn == "ldrsw") { memoryOp(true, false, true); return; }

    // ---- relative branches (signed byte displacement from the instruction) ----
    auto branchDisp = [&](const string& raw, int& disp) -> bool {
        if (!parseDisp(raw, disp)) { badOperand("bad branch displacement"); return false; }
        if (disp % 4 != 0) { badOperand("branch displacement must be a multiple of 4"); return false; }
        return true;
    };
    if (mn == "b" || mn == "bl") {
        int disp;
        if (!branchDisp(instr.op1, disp)) return;
        int32_t imm26 = disp / 4;
        if (imm26 < (int32_t)0xFE000000 || imm26 > 0x01FFFFFF) { badOperand("branch out of range (+-128 MB)"); return; }
        u32(mn == "b" ? b_imm_raw((uint32_t)(imm26 & 0x03FFFFFF)) : bl_imm((uint32_t)(imm26 & 0x03FFFFFF)));
        return;
    }
    if (mn.size() == 3 && mn[0] == 'b') {
        int cc = condCode(mn.substr(1));
        if (cc < 0) { unsupported(mn); return; }
        int disp;
        if (!branchDisp(instr.op1, disp)) return;
        int32_t imm19 = disp / 4;
        if (imm19 < -262144 || imm19 > 262143) { badOperand("b.cond out of range (+-1 MB)"); return; }
        u32(b_cond((uint32_t)cc, (uint32_t)(imm19 & 0x7FFFF)));
        return;
    }
    if (mn == "cbz" || mn == "cbnz") {
        int rt; bool t64;
        if (!parseReg(instr.op1, rt, t64)) { badOperand("bad register"); return; }
        int disp;
        if (!branchDisp(instr.op2, disp)) return;
        int32_t imm19 = disp / 4;
        if (imm19 < -262144 || imm19 > 262143) { badOperand("cbz/cbnz out of range (+-1 MB)"); return; }
        u32(mn == "cbz" ? cbz(rt, (uint32_t)(imm19 & 0x7FFFF)) : cbnz(rt, (uint32_t)(imm19 & 0x7FFFF)));
        return;
    }

    // ---- indirect branches / calls ----
    if (mn == "br" || mn == "blr") {
        int rn; bool n64;
        if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; }
        u32(mn == "br" ? br(rn) : blr(rn));
        return;
    }
    if (mn == "ret") {
        if (instr.op1.empty()) { ret(); }
        else { int rn; bool n64; if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; } u32(ret_reg(rn)); }
        return;
    }

    // ---- condition set ----
    if (mn == "cset") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int cc = condCode(trim(instr.op2));
        if (cc < 0) { badOperand("bad condition flag"); return; }
        u32(cset(rd, (uint32_t)cc));
        return;
    }

    // ---- hints / specials ----
    if (mn == "nop")   { nop(); return; }
    if (mn == "wfi")   { u32(wfi_instr()); return; }
    if (mn == "wfe")   { u32(wfe_instr()); return; }
    if (mn == "sev")   { u32(sev_instr()); return; }
    if (mn == "yield") { u32(yield_instr()); return; }
    if (mn == "svc" || mn == "hlt" || mn == "brk") {
        int64_t imm;
        uint16_t v = 0;
        if (!instr.op1.empty() && parseImm(instr.op1, imm)) v = (uint16_t)(imm & 0xFFFF);
        if (mn == "svc") u32(svc_imm(v));
        else if (mn == "hlt") u32(hlt_imm(v));
        else u32(brk_imm(v));
        return;
    }

    unsupported(mn);
}

void A64::emitSwitch(SwitchStmt* sw) {
    int endL = newLabel();
    int defL = -1;
    int slot = swTempOff + 4 * (swCur++);
    emitExpr(sw->condition.get());
    storeToOff(X0, slot);
    vector<int> caseLabels;
    for (auto& cs : sw->cases) {
        if (cs.condition) {
            int L = newLabel();
            caseLabels.push_back(L);
            int64_t cv; bool cconst = getIntConst(cs.condition.get(), cv);
            if (cconst) loadConst(X0, (uint64_t)(int64_t)(int32_t)cv);
            else emitExpr(cs.condition.get());
            loadFromOff(X1, slot);
            cmpReg(X1, X0);
            b_cc(0, L);
        } else {
            defL = newLabel();
        }
    }
    if (defL < 0) defL = endL;
    b_imm(defL);
    int ci = 0;
    for (auto& cs : sw->cases) {
        if (cs.condition) {
            emitLabel(caseLabels[ci++]);
            emitBlock(cs.body, &endL, nullptr, &endL);
            b_imm(endL);
        }
    }
    if (defL != endL) {
        emitLabel(defL);
        for (auto& cs : sw->cases) {
            if (!cs.condition) emitBlock(cs.body, &endL, nullptr, &endL);
        }
    }
    emitLabel(endL);
}

void A64::emitReturn(Expr* v, int retLabel) {
    if (v) emitExpr(v);
    if (retLabel >= 0) b_imm(retLabel);
}

// =========================================================================
// Expressions
// =========================================================================
int A64::emitExpr(Expr* e) {
    if (!e) { loadConst(X0, 0); return X0; }
    if (auto n = dynamic_cast<NumberExpr*>(e)) {
        loadConst(X0, (uint64_t)(int64_t)n->value);
        return X0;
    }
    if (dynamic_cast<FloatExpr*>(e)) {
        cerr << "arm64: float literals are not supported yet\n";
        loadConst(X0, 0);
        return X0;
    }
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        emitStrAddr(X0, stringIdx(s->value));
        return X0;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (var(id->name) || global(id->name)) { emitLoadVar(X0, id->name); return X0; }
        cerr << "arm64: undefined variable '" << id->name << "'\n";
        loadConst(X0, 0);
        return X0;
    }
    if (dynamic_cast<AddressOfExpr*>(e)) { emitAddr(e); return X0; }
    if (auto der = dynamic_cast<DerefExpr*>(e)) {
        emitExpr(der->ptr.get());
        ldrswW(X0, X0, 0);
        return X0;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        if (u->op == "!") {
            emitExpr(u->operand.get());
            cmpImm(X0, 0);
            csetR(X0, 0);  // EQ
            return X0;
        }
        if (u->op == "~") {
            emitExpr(u->operand.get());
            u32(mvn(X0, X0));
            return X0;
        }
        if (u->op == "-") {
            emitExpr(u->operand.get());
            negReg(X0, X0);
            return X0;
        }
        cerr << "arm64: unsupported unary '" << u->op << "'\n";
        loadConst(X0, 0);
        return X0;
    }
    if (auto mem = dynamic_cast<MemberExpr*>(e)) {
        if (auto oid = dynamic_cast<IdentExpr*>(mem->object.get())) {
            if (auto v = var(oid->name)) {
                int total = v->off + fieldOffsetOf(v->type, mem->member);
                loadFromOff(X0, total);
                return X0;
            } else if (auto g = global(oid->name)) {
                loadGlobal(X0, g->off + fieldOffsetOf(g->type, mem->member));
                return X0;
            }
        }
        emitAddr(mem->object.get());
        addImmX0(fieldOffset(mem->object.get(), mem->member));
        ldrswW(X0, X0, 0);
        return X0;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        emitAddr(arr);
        ldrswW(X0, X0, 0);
        return X0;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) { emitCall(c); return X0; }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        if (isFloatExpr(b)) {
            cerr << "arm64: float operations are not supported yet\n";
            loadConst(X0, 0);
            return X0;
        }
        return emitBinInt(b);
    }
    cerr << "arm64: unhandled expression\n";
    loadConst(X0, 0);
    return X0;
}

int A64::emitBinInt(BinaryExpr* bin) {
    const string& op = bin->op;
    int64_t rconst = 0; bool rIsConst = getIntConst(bin->right.get(), rconst);

    if (op == "+" && rIsConst) { emitExpr(bin->left.get()); addImmX0(rconst); return X0; }
    if (op == "-" && rIsConst) { emitExpr(bin->left.get()); addImmX0(-rconst); return X0; }
    if (op == "*" && rIsConst && rconst > 0) {
        int64_t v = rconst;
        for (int sh = 0; sh <= 62; sh++) {
            if (v == (int64_t)1 << sh) {
                emitExpr(bin->left.get());
                if (sh == 0) return X0;
                loadConst(X1, (uint64_t)sh);
                lslR(X0, X0, X1);
                return X0;
            }
        }
    }
    int64_t lconst; bool lIsConst = getIntConst(bin->left.get(), lconst);
    if (lIsConst && !rIsConst) {
        if (op == "+") {
            emitExpr(bin->right.get());
            addImmX0(lconst);
            return X0;
        }
        if (op == "*" || op == "&" || op == "|" || op == "^") {
            emitExpr(bin->right.get());
            loadConst(X1, (uint64_t)(int64_t)lconst);
            if (op == "*") { mulR(X0, X0, X1); return X0; }
            if (op == "&") { andReg(X0, X0, X1); return X0; }
            if (op == "|") { orrReg(X0, X0, X1); return X0; }
            if (op == "^") { eorReg(X0, X0, X1); return X0; }
        }
    }

    // generic: X1 = left, X0 = right
    emitExpr(bin->left.get());
    pushX0();
    emitExpr(bin->right.get());
    popX1();

    if (op == "+") { addReg(X0, X1, X0); return X0; }
    if (op == "-") { subReg(X0, X1, X0); return X0; }
    if (op == "*") { mulR(X0, X1, X0); return X0; }
    if (op == "&") { andReg(X0, X1, X0); return X0; }
    if (op == "|") { orrReg(X0, X1, X0); return X0; }
    if (op == "^") { eorReg(X0, X1, X0); return X0; }
    if (op == "<<") { lslR(X0, X1, X0); return X0; }
    if (op == ">>") { asrR(X0, X1, X0); return X0; }
    if (op == "/" || op == "%" || op == "//") {
        sdivR(X2, X1, X0);            // X2 = left/right
        msubR(X3, X2, X0, X1);        // X3 = left - (left/right)*right = left%right
        if (op == "/") mov(X0, X2);
        else mov(X0, X3);
        return X0;
    }
    if (op == "%of") {
        mulR(X0, X1, X0);             // X0 = percent * base
        loadConst(X1, 100);           // X1 = 100
        sdivR(X0, X0, X1);            // X0 = product / 100
        return X0;
    }
    int cc = ccForOp(op);
    if (cc >= 0) {
        cmpReg(X1, X0);
        csetR(X0, cc);
        return X0;
    }
    cerr << "arm64: unsupported binary op '" << op << "'\n";
    loadConst(X0, 0);
    return X0;
}

// =========================================================================
// Calls and builtins
// =========================================================================
int A64::emitCall(CallExpr* c) {
    if (tryBuiltin(c)) return X0;
    if (funcOffsets.count(c->name)) {
        if (c->args.size() > 8) {
            cerr << "arm64: call '" << c->name << "' has more than 8 arguments "
                    "(not supported yet)\n";
            return X0;
        }
        // evaluate all args into 8-byte stack slots, then load into x0..x7
        size_t argsBytes = c->args.size() * 8;
        subSp((int)argsBytes);
        tempBytes += (int)argsBytes;
        for (size_t i = 0; i < c->args.size(); i++) {
            emitExpr(c->args[i].get());
            strX(X0, XSP, (uint32_t)(i * 8));
        }
        for (size_t i = 0; i < c->args.size(); i++) ldrX((int)i, XSP, (uint32_t)(i * 8));
        addSp((int)argsBytes);
        tempBytes -= (int)argsBytes;
        hasCalls = true;
        bl_fixup(c->name);
        return X0;
    }
    cerr << "arm64: call to unknown function '" << c->name << "'\n";
    loadConst(X0, 0);
    return X0;
}

bool A64::tryBuiltin(CallExpr* c) {
    const string& n = c->name;
    if (n == "print") {
        if (c->args.empty()) return true;
        auto a = c->args[0].get();
        if (auto s = dynamic_cast<StringExpr*>(a)) {
            (void)s;
            emitExpr(a);
            bl_fixup("uart_puts");
        } else if (dynamic_cast<FloatExpr*>(a) || isFloatExpr(a)) {
            cerr << "arm64: print() of a float is not supported yet\n";
            emitExpr(a);
            return true;
        } else {
            emitExpr(a);
            bl_fixup("uart_num");
        }
        loadConst(X0, '\n');
        bl_fixup("uart_putc");
        hasCalls = true;
        return true;
    }
    if (n == "delay_ms") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_delay");
        hasCalls = true;
        return true;
    }
    if (n == "abs") {
        emitExpr(c->args[0].get());
        u32(neg_reg(X1, X0));
        cmpImm(X0, 0);
        int skip = newLabel();
        b_cc(10, skip);   // GE -> keep X0
        mov(X0, X1);
        emitLabel(skip);
        return true;
    }
    if (n == "min" || n == "max") {
        emitExpr(c->args[0].get());
        pushX0();                    // stack: a
        emitExpr(c->args[1].get());
        popX1();                     // X1 = a, X0 = b
        cmpReg(X1, X0);
        int skip = newLabel();
        if (n == "min") b_cc(10, skip);  // a >= b -> keep b
        else b_cc(13, skip);             // a <= b -> keep b
        mov(X0, X1);                 // X0 = a
        emitLabel(skip);
        return true;
    }
    if (n == "clamp") {
        emitExpr(c->args[0].get());
        pushX0();                    // stack: x
        emitExpr(c->args[1].get());
        popX1();                     // X1 = x, X0 = lo
        cmpReg(X0, X1);              // lo vs x
        int s1 = newLabel();
        b_cc(12, s1);                // lo > x -> keep lo
        mov(X0, X1);                 // X0 = x
        emitLabel(s1);
        pushX0();
        emitExpr(c->args[2].get());
        popX1();                     // X1 = clamped, X0 = hi
        cmpReg(X0, X1);              // hi vs clamped
        int s2 = newLabel();
        b_cc(11, s2);                // hi < clamped -> keep hi
        mov(X0, X1);                 // X0 = clamped
        emitLabel(s2);
        return true;
    }
    if (n == "str_len") {
        if (c->args.empty()) return true;
        emitExpr(c->args[0].get());  // X0 = string addr
        mov(X1, X0);                 // X1 = cursor
        int L = newLabel(), done = newLabel();
        emitLabel(L);
        ldrsbX(X2, X1, 0);
        cbzR(X2, done);
        addImm(X1, X1, 1);
        b_imm(L);
        emitLabel(done);
        subReg(X0, X1, X0);          // X0 = length
        return true;
    }
    if (n == "gpio_init") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_init");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_set" || n == "gpio_clear") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup(n == "gpio_set" ? "__z_gpio_set" : "__z_gpio_clear");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_toggle") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_toggle");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_read") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_read");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_write") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());      // X0 = value
        pushX0();
        emitExpr(c->args[0].get());      // X0 = pin
        popX1();                         // X1 = value
        bl_fixup("__z_gpio_write");
        hasCalls = true;
        return true;
    }
    if (n == "led_on" || n == "led_off") {
        loadConst(X0, n == "led_on" ? 1 : 0);
        bl_fixup("__z_led_set");
        hasCalls = true;
        return true;
    }
    if (n == "led_toggle") {
        bl_fixup("__z_led_toggle");
        hasCalls = true;
        return true;
    }
    if (n == "uart_init") {
        // First arg is the pin; PL011 is fixed to GPIO14/15, so take baud only.
        if (c->args.size() > 1) emitExpr(c->args[1].get());
        else loadConst(X0, 115200);
        bl_fixup("__z_uart_init");
        hasCalls = true;
        return true;
    }
    if (n == "uart_write") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());      // X0 = byte
        bl_fixup("uart_putc");
        hasCalls = true;
        return true;
    }
    if (n == "uart_read") {
        bl_fixup("__z_uart_getc");       // X0 = -1 if nothing received
        hasCalls = true;
        return true;
    }
    if (n == "uart_print" || n == "uart_println") {
        if (c->args.size() < 2) return true;
        auto a = c->args[1].get();
        if (auto s = dynamic_cast<StringExpr*>(a)) {
            string txt = s->value;
            if (n == "uart_println") txt += "\r\n";
            emitStrAddr(X0, stringIdx(txt));
        } else {
            emitExpr(a);
        }
        bl_fixup("uart_puts");
        hasCalls = true;
        return true;
    }
    if (n == "uart_print_int") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());
        bl_fixup("uart_num");
        hasCalls = true;
        return true;
    }
    if (n == "delay_ms") {
        if (c->args.empty()) return true;
        emitExpr(c->args[0].get());
        bl_fixup("__z_delay");
        hasCalls = true;
        return true;
    }
    if (n == "delay_us") {
        if (c->args.empty()) return true;
        emitExpr(c->args[0].get());
        bl_fixup("__z_delay_us");
        hasCalls = true;
        return true;
    }
    if (n == "micros") {
        bl_fixup("__z_micros");
        hasCalls = true;
        return true;
    }
    if (n == "millis") {
        bl_fixup("__z_millis");
        hasCalls = true;
        return true;
    }
    return false;
}

// =========================================================================
// Conditional jumps
// =========================================================================
int A64::emitCondJump(Expr* c, int label, bool wantTrue) {
    int64_t cv;
    if (getIntConst(c, cv)) {
        if ((cv != 0) == wantTrue) b_imm(label);
        return 0;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(c)) {
        const string& op = b->op;
        if (op == "&&") {
            if (wantTrue) {
                int skip = newLabel();
                emitCondJump(b->left.get(), skip, false);
                emitCondJump(b->right.get(), label, true);
                emitLabel(skip);
            } else {
                emitCondJump(b->left.get(), label, false);
                emitCondJump(b->right.get(), label, false);
            }
            return 0;
        }
        if (op == "||") {
            if (wantTrue) {
                emitCondJump(b->left.get(), label, true);
                emitCondJump(b->right.get(), label, true);
            } else {
                int skip = newLabel();
                emitCondJump(b->left.get(), skip, true);
                emitCondJump(b->right.get(), label, false);
                emitLabel(skip);
            }
            return 0;
        }
        int cc = ccForOp(op);
        if (cc >= 0 && !isFloatExpr(b)) {
            emitExpr(b->left.get());
            pushX0();
            emitExpr(b->right.get());
            popX1();                  // X1 = left, X0 = right
            cmpReg(X1, X0);
            if (!wantTrue) cc = invCc(cc);
            b_cc(cc, label);
            return 0;
        }
    }
    emitExpr(c);
    if (wantTrue) cbnzR(X0, label);
    else cbzR(X0, label);
    return 0;
}

// =========================================================================
// Per-function state / frame allocation
// =========================================================================
void A64::resetFn() {
    code.clear();
    labelPositions.clear();
    branches.clear();
    callFixups.clear();
    strFixups.clear();
    vars.clear();
    nextLabel = 0;
    swCur = 0;
    swTempOff = 0;
    tempBytes = 0;
    frameSize = 0;
    retLabel = -1;
}

static int stmtSwitchCount(Stmt* s) {
    int c = 0;
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        c = 1;
        for (auto& cs : sw->cases) for (auto& x : cs.body.stmts) c += stmtSwitchCount(x.get());
        return c;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        for (auto& x : ifs->thenBlock.stmts) c += stmtSwitchCount(x.get());
        for (auto& x : ifs->elseBlock.stmts) c += stmtSwitchCount(x.get());
        return c;
    }
    if (auto ws = dynamic_cast<WhileStmt*>(s)) { for (auto& x : ws->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    if (auto ls = dynamic_cast<LoopStmt*>(s)) { for (auto& x : ls->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    if (auto fs = dynamic_cast<ForStmt*>(s)) { for (auto& x : fs->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    return c;
}

void A64::allocVarSlots(FunctionDecl* f) {
    struct LiveVar {
        string name;
        int size = 4;
        int first = 0;
        int last = 0;
        int slot = 0;
        bool used = false;
        bool isParam = false;
        Type type;
    };
    unordered_map<string, LiveVar> live;
    for (auto& p : f->params) {
        LiveVar lv; lv.name = p.name; lv.first = 0; lv.last = 0;
        lv.isParam = true; lv.type = p.type;
        lv.size = typeSize(p.type);
        live[p.name] = lv;
    }

    int stmtIdx = 0;
    int curStmt = 0;
    auto touch = [&](const string& name) {
        auto it = live.find(name);
        if (it == live.end()) return;
        it->second.used = true;
        if (curStmt > it->second.last) it->second.last = curStmt;
    };
    std::function<void(Expr*)> touchExpr = [&](Expr* e) {
        if (!e) return;
        if (auto id = dynamic_cast<IdentExpr*>(e)) { touch(id->name); return; }
        if (auto aof = dynamic_cast<AddressOfExpr*>(e)) { touch(aof->name); return; }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) { touchExpr(b->left.get()); touchExpr(b->right.get()); return; }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) { touchExpr(u->operand.get()); return; }
        if (auto m = dynamic_cast<MemberExpr*>(e)) { touchExpr(m->object.get()); return; }
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) { touchExpr(a->array.get()); touchExpr(a->index.get()); return; }
        if (auto d = dynamic_cast<DerefExpr*>(e)) { touchExpr(d->ptr.get()); return; }
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            touchExpr(c->receiver.get());
            for (auto& a : c->args) touchExpr(a.get());
            return;
        }
    };
    auto touchStmt = [&](Stmt* s) {
        if (auto v = dynamic_cast<VarDecl*>(s)) { touchExpr(v->init.get()); return; }
        if (auto r = dynamic_cast<ReturnStmt*>(s)) { touchExpr(r->value.get()); return; }
        if (auto es = dynamic_cast<ExprStmt*>(s)) { touchExpr(es->expr.get()); return; }
        if (auto a = dynamic_cast<AssignStmt*>(s)) {
            touch(a->name);
            touchExpr(a->indexExpr.get());
            touchExpr(a->value.get());
            return;
        }
        if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) { touchExpr(pa->ptr.get()); touchExpr(pa->value.get()); return; }
        if (auto ifs = dynamic_cast<IfStmt*>(s)) { touchExpr(ifs->condition.get()); return; }
        if (auto ws = dynamic_cast<WhileStmt*>(s)) { touchExpr(ws->condition.get()); return; }
        if (auto fs = dynamic_cast<ForStmt*>(s)) {
            touchExpr(fs->start.get()); touchExpr(fs->end.get()); touchExpr(fs->step.get());
            return;
        }
        if (auto sw = dynamic_cast<SwitchStmt*>(s)) { touchExpr(sw->condition.get()); return; }
    };

    std::function<void(Stmt*)> walk = [&](Stmt* s) {
        curStmt = stmtIdx++;
        auto declare = [&](const string& name, int size, const Type& t) {
            LiveVar lv; lv.name = name; lv.size = size;
            lv.first = curStmt; lv.last = curStmt; lv.type = t;
            live[name] = lv;
        };
        if (auto v = dynamic_cast<VarDecl*>(s)) {
            int sz = v->arraySize > 0 ? v->arraySize * elementSize(v->type) : elementSize(v->type);
            if (sz < 4) sz = 4;
            declare(v->name, sz, v->type);
        } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
            declare(fs->varName, 4, Type(TypeKind::Int));
        }
        touchStmt(s);
        if (auto ifs = dynamic_cast<IfStmt*>(s)) {
            for (auto& x : ifs->thenBlock.stmts) walk(x.get());
            for (auto& x : ifs->elseBlock.stmts) walk(x.get());
        } else if (auto ws = dynamic_cast<WhileStmt*>(s)) {
            for (auto& x : ws->body.stmts) walk(x.get());
        } else if (auto ls = dynamic_cast<LoopStmt*>(s)) {
            for (auto& x : ls->body.stmts) walk(x.get());
        } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
            for (auto& x : fs->body.stmts) walk(x.get());
        } else if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
            for (auto& cs : sw->cases) if (cs.condition) touchExpr(cs.condition.get());
            for (auto& cs : sw->cases) for (auto& x : cs.body.stmts) walk(x.get());
        }
    };
    for (auto& s : f->body.stmts) walk(s.get());

    vector<LiveVar*> locals;
    for (auto& kv : live) if (!kv.second.isParam) locals.push_back(&kv.second);
    sort(locals.begin(), locals.end(),
         [](const LiveVar* a, const LiveVar* b) { return a->first < b->first; });
    int off = 0;
    for (auto* lv : locals) {
        off = (off + 7) & ~7;
        lv->slot = off;
        off += (lv->size + 7) & ~7;
    }
    for (auto* lv : locals) {
        off = max(off, lv->slot + lv->size);
        VarInfo32 vi; vi.off = lv->slot; vi.type = lv->type;
        vi.isParam = false; vi.used = lv->used; vi.size = lv->size;
        vars[lv->name] = vi;
    }
    int swCount = 0;
    for (auto& s : f->body.stmts) swCount += stmtSwitchCount(s.get());
    swTempOff = off;
    int localsBytes = off + swCount * 4;

    // parameters get their own frame slots (only when used)
    for (int k = 0; k < (int)f->params.size(); k++) {
        auto it = live.find(f->params[k].name);
        if (it == live.end() || !it->second.used) continue;
        localsBytes = (localsBytes + 7) & ~7;
        VarInfo32 vi; vi.off = localsBytes; vi.type = f->params[k].type;
        vi.isParam = true; vi.used = true; vi.size = typeSize(f->params[k].type);
        vars[f->params[k].name] = vi;
        localsBytes += (vi.size + 7) & ~7;
    }

    frameSize = (localsBytes + 8 + 15) & ~15;   // +8 for saved LR, 16-align
}

// =========================================================================
// Global init / startup
// =========================================================================
void A64::emitGlobalInit() {
    for (auto& g : prog.globals) {
        auto gi = global(g->name);
        if (!gi || !g->init) continue;
        int64_t cv;
        if (getIntConst(g->init.get(), cv)) {
            loadConst(X0, (uint64_t)(int64_t)cv);
        } else {
            emitExpr(g->init.get());
        }
        storeGlobal(X0, gi->off);
    }
}

void A64::emitStartup() {
    resetFn();
    // X19 = page of data section, then + low 12 bits (patched after layout)
    startupAdrpPos = (int)code.size();
    u32(adrp(X19, 0));
    startupAddPos = (int)code.size();
    u32(add_imm(X19, X19, 0));
    // SP = top of RAM minus a margin (below the 0x3F000000 RPi peripherals;
    //     safe for both 512MB and 1GB Rasperry Pi boards).
    // MOVZ X31 would write XZR, so load into X0 then MOV SP, X0.
    loadConst(X0, 0x3C000000ull);
    u32(add_imm(XSP, X0, 0));   // MOV SP, X0  (ADD SP, X0, #0)
    emitGlobalInit();
    if (!entryName.empty()) bl_fixup(entryName);
    u32(b_imm_raw(0));   // spin: b .
    resolveBranches("__z_startup");
}

// =========================================================================
// Runtime support helpers (UART on QEMU virt PL011)
// =========================================================================
void A64::emitRuntime(const string& name) {
    resetFn();
    if (name == "uart_putc") {
        // x0 = char. Wait for TX FIFO to drain, then write DR.
        loadConst(X1, uartBase);
        int Lwait = newLabel();
        emitLabel(Lwait);
        ldrW(X2, X1, PL011_FR);
        tbnzR(X2, 5, Lwait);          // loop while TXFF (bit 5) set
        strbW(X0, X1, PL011_DR);
        ret();
    } else if (name == "uart_puts") {
        // x0 = NUL-terminated string
        loadConst(X1, uartBase);
        int Lloop = newLabel(), Ldone = newLabel();
        emitLabel(Lloop);
        ldrsbX(X2, X0, 0);
        cbzR(X2, Ldone);
        int Lwait = newLabel();
        emitLabel(Lwait);
        ldrW(X3, X1, PL011_FR);
        tbnzR(X3, 5, Lwait);
        strbW(X2, X1, PL011_DR);
        addImm(X0, X0, 1);
        b_imm(Lloop);
        emitLabel(Ldone);
        ret();
    } else if (name == "uart_num") {
        // x0 = signed int -> print decimal + (caller appends newline)
        int Ldigits = newLabel(), Lskipminus = newLabel(), Lloop = newLabel();
        subSp(56);
        strX(X30, XSP, 0);             // save LR (we call uart_puts below)
        addSpAddr(X1, 8);              // X1 = buf start
        addImm(X1, X1, 24);            // X1 = buf + 24 (end of digits area)
        mov(X2, X1);                   // X2 = cursor (moves left)
        u32(movz(X8, 0, 0));
        strbW(X8, X2, 0);              // NUL terminator at buf+24
        mov(X3, X0);                   // X3 = n
        u32(movz(X4, 0, 0));           // X4 = 0 -> minus flag (cleared)
        cmpImm(X3, 0);
        b_cc(10, Ldigits);             // n >= 0
        negReg(X3, X3);                // n = -n
        u32(movz(X4, 1, 0));           // X4 = 1 -> minus flag
        emitLabel(Ldigits);
        emitLabel(Lloop);
        u32(movz(X10, 10, 0));
        sdivR(X5, X3, X10);            // quot
        msubR(X6, X5, X10, X3);        // rem
        addImm(X6, X6, 48);            // '0'
        subImm(X2, X2, 1);
        strbW(X6, X2, 0);
        mov(X3, X5);
        cbnzR(X3, Lloop);
        // X4 == 1 if negative
        cmpImm(X4, 1);
        b_cc(1, Lskipminus);           // NE -> not negative
        subImm(X2, X2, 1);
        u32(movz(X6, '-', 0));
        strbW(X6, X2, 0);
        emitLabel(Lskipminus);
        mov(X0, X2);
        bl_fixup("uart_puts");
        ldrX(X30, XSP, 0);             // restore LR
        addSp(56);
        ret();
    } else if (name == "__z_delay") {
        // x0 = ms; approximate busy loop
        int Lout = newLabel(), Linner = newLabel(), Ldone = newLabel();
        cmpImm(X0, 0);
        b_cc(13, Ldone);               // ms <= 0
        mov(X1, X0);                   // X1 = ms
        loadConst(X9, prog.arm64ClockHz / 1000);
        emitLabel(Lout);
        mov(X2, X9);
        emitLabel(Linner);
        subImm(X2, X2, 1);
        cbnzR(X2, Linner);
        subImm(X1, X1, 1);
        cbnzR(X1, Lout);
        emitLabel(Ldone);
        ret();
    } else if (name == "__z_gpio_init") {
        // X0 = pin. Clear that pin's GPFSEL field, set it to 001 (output).
        mov(X10, X0);                     // pin
        loadConst(X9, gpioBase);
        loadConst(X11, 10);
        sdivR(X12, X10, X11);             // pin/10 (GPFSEL index)
        loadConst(X11, 4);
        mulR(X12, X11, X12);              // bank*4
        addReg(X9, X9, X12);              // X9 = GPFSEL addr
        loadConst(X11, 10);
        sdivR(X12, X10, X11);             // pin/10
        msubR(X11, X12, X11, X10);        // rem = pin % 10
        loadConst(X12, 3);
        mulR(X11, X11, X12);              // shift = rem*3
        ldrW(X13, X9, 0);                 // read GPFSEL
        loadConst(X14, 7);
        lslR(X14, X14, X11);              // 7 << shift
        loadConst(X15, 0xFFFFFFFFu);
        eorReg(X14, X14, X15);            // ~(7 << shift)
        andReg(X13, X13, X14);            // clear the field
        loadConst(X14, 1);
        lslR(X14, X14, X11);              // 1 << shift
        orrReg(X13, X13, X14);            // set to output
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_gpio_set" || name == "__z_gpio_clear") {
        // X0 = pin. Write bit to GPSET (0x1C) or GPCLR (0x28), with bank.
        uint32_t off = (name == "__z_gpio_set") ? 0x1Cu : 0x28u;
        mov(X10, X0);
        loadConst(X9, gpioBase + off);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);              // pin >> 5
        loadConst(X12, 4);
        mulR(X11, X11, X12);              // bank*4
        addReg(X9, X9, X11);
        loadConst(X11, 31);
        andReg(X11, X10, X11);            // pin & 31
        loadConst(X12, 1);
        lslR(X12, X12, X11);              // bit
        strW(X12, X9, 0);
        ret();
    } else if (name == "__z_gpio_read") {
        // X0 = pin -> 0/1 from GPLEV.
        mov(X10, X0);
        loadConst(X9, gpioBase + 0x34);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);
        loadConst(X12, 4);
        mulR(X11, X11, X12);
        addReg(X9, X9, X11);              // GPLEV addr
        ldrW(X13, X9, 0);
        loadConst(X11, 31);
        andReg(X11, X10, X11);
        loadConst(X12, 1);
        lslR(X12, X12, X11);              // bit
        andReg(X13, X13, X12);            // 0 or bit
        cmpImm(X13, 0);
        csetR(X0, 1);                     // NE -> 1
        ret();
    } else if (name == "__z_gpio_toggle") {
        // Read GPLEV; if the bit reads 0 -> GPSET, else -> GPCLR.
        mov(X10, X0);
        loadConst(X9, gpioBase);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);
        loadConst(X12, 4);
        mulR(X11, X11, X12);              // bank*4
        loadConst(X12, 31);
        andReg(X12, X10, X12);            // pin & 31
        loadConst(X13, 1);
        lslR(X13, X13, X12);              // bit
        mov(X14, X9);
        addReg(X14, X14, X11);
        loadConst(X15, 0x34);
        addReg(X14, X14, X15);            // GPLEV addr
        ldrW(X14, X14, 0);
        andReg(X14, X14, X13);            // 0 if currently low
        cmpImm(X14, 0);
        csetR(X12, 0);                    // 1 if low (EQ)
        loadConst(X14, 1);
        subReg(X12, X14, X12);            // 0 if low, 1 if high
        loadConst(X14, 0x0C);
        mulR(X12, X12, X14);              // 0 or 0x0C
        loadConst(X14, 0x1C);
        addReg(X12, X12, X14);            // 0x1C (set) or 0x28 (clear)
        addReg(X9, X9, X12);
        addReg(X9, X9, X11);
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_gpio_write") {
        // X0 = pin, X1 = value (any non-zero -> high).
        mov(X10, X0);
        mov(X11, X1);
        cmpImm(X11, 0);
        csetR(X11, 1);                    // 1 if val != 0
        loadConst(X12, 0x0C);
        mulR(X11, X11, X12);              // 0 or 0x0C
        loadConst(X12, 0x1C);
        addReg(X11, X11, X12);            // 0x1C (val!=0) or 0x28 (val==0)
        loadConst(X9, gpioBase);
        loadConst(X12, 5);
        lsrR(X12, X10, X12);              // pin >> 5
        loadConst(X13, 4);
        mulR(X12, X12, X13);              // bank*4
        loadConst(X13, 31);
        andReg(X13, X10, X13);            // pin & 31
        loadConst(X14, 1);
        lslR(X13, X13, X14);              // bit
        addReg(X9, X9, X11);
        addReg(X9, X9, X12);              // GPSET/GPCLR + bank
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_led_set" || name == "__z_led_toggle") {
        // Activity LED on led_gpio: configure as output, then write/toggle.
        subSp(16);
        strX(X30, XSP, 0);
        mov(X10, X0);                     // remember value for led_set
        loadConst(X0, ledGpio);
        bl_fixup("__z_gpio_init");
        if (name == "__z_led_set") {
            loadConst(X0, ledGpio);
            mov(X1, X10);
            bl_fixup("__z_gpio_write");
        } else {
            loadConst(X0, ledGpio);
            bl_fixup("__z_gpio_read");
            loadConst(X10, 1);
            eorReg(X0, X0, X10);          // flip
            mov(X1, X0);
            loadConst(X0, ledGpio);
            bl_fixup("__z_gpio_write");
        }
        ldrX(X30, XSP, 0);
        addSp(16);
        ret();
    } else if (name == "__z_uart_init") {
        // X0 = baud. GPIO 14/15 -> ALT0, then program the PL011 divisor
        // for a 48 MHz peripheral clock (standard Pi reference clock).
        mov(X11, X0);                     // baud
        loadConst(X9, gpioBase + 0x04);   // GPFSEL1
        ldrW(X12, X9, 0);
        loadConst(X13, 0x3F);
        loadConst(X14, 12);
        lslR(X13, X13, X14);              // 0x3F << 12 (pins 14,15)
        loadConst(X14, 0xFFFFFFFFu);
        eorReg(X13, X13, X14);            // ~mask
        andReg(X12, X12, X13);
        loadConst(X13, 0x24000);          // 4<<12 | 4<<15 = ALT0
        orrReg(X12, X12, X13);
        strW(X12, X9, 0);
        loadConst(X9, uartBase);
        loadConst(X12, 0);
        strW(X12, X9, PL011_CR);          // disable
        loadConst(X12, 16);
        mulR(X11, X11, X12);              // 16*baud
        loadConst(X12, 48000000);
        sdivR(X13, X12, X11);             // IBRD = clock/(16*baud)
        strW(X13, X9, PL011_IBRD);
        msubR(X13, X13, X11, X12);        // rem = clock - IBRD*16*baud
        loadConst(X14, 64);
        mulR(X13, X13, X14);              // rem*64
        sdivR(X13, X13, X11);             // FBRD
        strW(X13, X9, PL011_FBRD);
        loadConst(X12, 0x70);             // 8N1 + FIFO
        strW(X12, X9, PL011_LCRH);
        loadConst(X12, 0x301);            // UARTEN | TXE | RXE
        strW(X12, X9, PL011_CR);
        ret();
    } else if (name == "__z_uart_getc") {
        // X0 = -1 if RX FIFO empty, else the received byte.
        loadConst(X9, uartBase);
        int Lempty = newLabel();
        ldrW(X10, X9, PL011_FR);
        tbnzR(X10, 4, Lempty);            // RXFE (bit 4) -> empty
        ldrW(X0, X9, PL011_DR);
        ret();
        emitLabel(Lempty);
        loadConst(X0, 0xFFFFFFFFFFFFFFFFull);
        ret();
    } else if (name == "__z_micros") {
        // System timer CLO counts microseconds (1 MHz), 32-bit wrap.
        loadConst(X9, sysTimerBase);
        ldrW(X0, X9, 4);
        ret();
    } else if (name == "__z_millis") {
        loadConst(X9, sysTimerBase);
        ldrW(X0, X9, 4);
        loadConst(X10, 1000);
        sdivR(X0, X0, X10);
        ret();
    } else if (name == "__z_delay_us") {
        // X0 = us. Unsigned poll of CLO until it passes start + us.
        int Lbo = newLabel();
        loadConst(X9, sysTimerBase);
        mov(X10, X0);                     // us
        ldrW(X11, X9, 4);                 // start
        addReg(X12, X11, X10);            // end
        emitLabel(Lbo);
        ldrW(X11, X9, 4);                 // now
        cmpReg(X11, X12);
        b_cc(3, Lbo);                     // CC: now < end (unsigned)
        ret();
    } else {
        cerr << "arm64: unknown runtime '" << name << "'\n";
    }
    resolveBranches(name);
    FnImg out;
    out.name = name;
    out.bytes = code;
    out.bls = callFixups;
    out.strFixes = strFixups;
    runtimeImgs.push_back(move(out));
}

// =========================================================================
// Whole-program layout + binary emit
// =========================================================================
bool A64::compile(const string& outputPath) {
    // --- Raspberry Pi peripheral mapping from chip: (BCM2835/2837 -> Pi1-Pi3,
    //     BCM2711/Cortex-A72 -> Pi4) ---
    {
        const string& chip = prog.arm64Chip;
        bool pi4 = chip.find("bcm2711") != string::npos ||
                   chip.find("cortex-a72") != string::npos ||
                   chip.find("a72") != string::npos;
        periphBase   = pi4 ? 0xFE000000u : 0x3F000000u;
        gpioBase     = periphBase + 0x200000u;
        uartBase     = periphBase + 0x201000u;
        sysTimerBase = periphBase + 0x3000u;
        ledGpio      = pi4 ? 16 : 47;
    }

    // --- struct layouts: every field is 4 bytes ---
    structs.clear();
    for (auto& sd : prog.structs) {
        int off = 0;
        unordered_map<string, pair<int, Type>> fields;
        for (auto& f : sd->fields) {
            fields[f.name] = {off, f.type};
            off += 4;
        }
        structs[sd->name] = {off, move(fields)};
    }

    // --- globals: offsets from data section start (known before codegen) ---
    globals.clear();
    globalOrder.clear();
    int gOff = 0;
    for (auto& g : prog.globals) {
        int sz = g->arraySize > 0 ? g->arraySize * 4 : typeSize(g->type);
        if (sz < 4) sz = 4;
        gOff = (gOff + 7) & ~7;
        globals[g->name] = {gOff, sz, g->type};
        globalOrder.push_back(g->name);
        gOff += sz;
    }
    int globalBytesTotal = gOff;

    // --- function presence map; entry = "main" or first function ---
    funcOffsets.clear();
    funcOrder.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        funcOffsets[f->name] = 0;
        funcOrder.push_back(f->name);
    }
    entryName = funcOffsets.count("main") ? "main"
              : (funcOrder.empty() ? "" : funcOrder[0]);

    // --- emit user functions ---
    userImgs.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        resetFn();
        allocVarSlots(f.get());
        subSp(frameSize);
        strX(X30, XSP, (uint32_t)frameSize - 8);
        for (int k = 0; k < (int)f->params.size(); k++) {
            auto v = var(f->params[k].name);
            if (!v) continue;
            if (v->size == 8) strX(k, XSP, (uint32_t)v->off);
            else strW(k, XSP, (uint32_t)v->off);
        }
        retLabel = newLabel();
        emitBlock(f->body, nullptr, nullptr, nullptr);
        b_imm(retLabel);
        emitLabel(retLabel);
        ldrX(X30, XSP, (uint32_t)frameSize - 8);
        addSp(frameSize);
        ret();
        if (tempBytes != 0)
            cerr << "arm64: unbalanced stack in '" << f->name << "'\n";
        resolveBranches(f->name);
        FnImg out;
        out.name = f->name;
        out.bytes = code;
        out.bls = callFixups;
        out.strFixes = strFixups;
        userImgs.push_back(move(out));
    }

    // --- emit runtime helpers referenced from user code (transitive) ---
    runtimeImgs.clear();
    unordered_set<string> emittedRt;
    vector<string> pendingRt;
    auto isRuntime = [](const string& t) {
        return t.compare(0, 4, "__z_") == 0 || t == "uart_puts" ||
               t == "uart_num" || t == "uart_putc";
    };
    auto collectRt = [&](const FnImg& img) {
        for (auto& bl : img.bls)
            if (isRuntime(bl.target)) pendingRt.push_back(bl.target);
    };
    for (auto& img : userImgs) collectRt(img);
    for (size_t i = 0; i < pendingRt.size(); i++) {
        const string& n = pendingRt[i];
        if (emittedRt.count(n)) continue;
        emittedRt.insert(n);
        emitRuntime(n);
        collectRt(runtimeImgs.back());
    }

    // --- startup image ---
    emitStartup();
    vector<uint8_t> stBytes = code;
    vector<CallFix> stBls = callFixups;
    vector<StrFix> stStrFixes = strFixups;
    int stAdrp = startupAdrpPos;
    int stAdd = startupAddPos;

    // --- layout: startup | runtime | user | data ---
    size_t cursor = 0;
    size_t startupOff = cursor;
    cursor += stBytes.size();
    vector<size_t> rtOffsets;
    for (auto& img : runtimeImgs) {
        cursor = (cursor + 7u) & ~7u;
        rtOffsets.push_back(cursor);
        cursor += img.bytes.size();
    }
    vector<size_t> fnOffsets;
    for (auto& img : userImgs) {
        cursor = (cursor + 7u) & ~7u;
        fnOffsets.push_back(cursor);
        cursor += img.bytes.size();
    }

    // data section: globals (first) then strings
    size_t dataStart = (cursor + 7u) & ~7u;
    size_t p = dataStart + (size_t)globalBytesTotal;
    vector<uint32_t> strOfs(strings.size(), 0);
    for (size_t i = 0; i < strings.size(); i++) {
        p = (p + 3u) & ~3u;
        strOfs[i] = (uint32_t)p;
        p += strings[i].size() + 1;
    }
    size_t imageSize = (p + 15u) & ~15u;

    vector<uint8_t> img;
    img.assign(imageSize, 0);
    auto copyBlock = [&](size_t baseOff, const vector<uint8_t>& bytes) {
        for (size_t i = 0; i < bytes.size(); i++)
            img[baseOff + i] = bytes[i];
    };

    // resolve function addresses
    for (size_t i = 0; i < userImgs.size(); i++) funcOffsets[userImgs[i].name] = fnOffsets[i];
    for (size_t i = 0; i < runtimeImgs.size(); i++) funcOffsets[runtimeImgs[i].name] = rtOffsets[i];

    auto patchCalls = [&](size_t baseOff, const vector<CallFix>& bls) {
        for (auto& bl : bls) {
            auto it = funcOffsets.find(bl.target);
            if (it == funcOffsets.end()) continue;
            int64_t rel = (int64_t)it->second - (int64_t)(baseOff + (size_t)bl.pos);
            uint32_t imm26 = (uint32_t)(rel / 4);
            if (imm26 & 0x04000000u) imm26 |= 0xFC000000u;
            u32pat(img, (int)(baseOff + (size_t)bl.pos), bl_imm(imm26));
        }
    };

    // --- assemble ---
    copyBlock(startupOff, stBytes);
    if (stAdrp >= 0) {
        int32_t rel = (int32_t)((((int64_t)dataStart & ~0xFFFll) - ((int64_t)(startupOff + stAdrp) & ~0xFFFll)) >> 12);
        u32pat(img, (int)(startupOff + (size_t)stAdrp), adrp(X19, rel));
    }
    if (stAdd >= 0) {
        uint16_t low = (uint16_t)(dataStart & 0xFFF);
        u32pat(img, (int)(startupOff + (size_t)stAdd), add_imm(X19, X19, low));
    }
    patchCalls(startupOff, stBls);
    patchStrSlots(img, startupOff, dataStart, stStrFixes, strOfs);

    for (size_t i = 0; i < runtimeImgs.size(); i++) {
        copyBlock(rtOffsets[i], runtimeImgs[i].bytes);
        patchCalls(rtOffsets[i], runtimeImgs[i].bls);
        patchStrSlots(img, rtOffsets[i], dataStart, runtimeImgs[i].strFixes, strOfs);
    }
    for (size_t i = 0; i < userImgs.size(); i++) {
        copyBlock(fnOffsets[i], userImgs[i].bytes);
        patchCalls(fnOffsets[i], userImgs[i].bls);
        patchStrSlots(img, fnOffsets[i], dataStart, userImgs[i].strFixes, strOfs);
    }

    // strings
    for (size_t i = 0; i < strings.size(); i++) {
        size_t off = strOfs[i];
        if (off + strings[i].size() >= imageSize) {
            cerr << "arm64: string pool overflow\n";
            return false;
        }
        copy(strings[i].begin(), strings[i].end(), img.begin() + off);
        img[off + strings[i].size()] = 0;
    }

    ofstream out(outputPath, ios::binary);
    if (!out) { cerr << "arm64: cannot open '" << outputPath << "'\n"; return false; }
    out.write((const char*)img.data(), (streamsize)img.size());
    out.close();

    cerr << "arm64: image " << img.size() << " bytes, "
         << userImgs.size() << " function(s), "
         << strings.size() << " string(s), "
         << globals.size() << " global(s)\n";
    return true;
}

} // namespace

// =========================================================================
// Public entry point
// =========================================================================
bool Codegen::compileArm64(const std::string& outputPath) {
    A64 cg(prog);
    return cg.compile(outputPath);
}
