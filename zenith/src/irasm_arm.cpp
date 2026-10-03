#include "irasm_arm.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <utility>

// ====================================================================
// IRAsmArm implementation
//
// Lowers the optimized assembler-IR into a raw STM32F1 (ARMv7-M, Thumb-2)
// firmware image for QEMU's "stm32vldiscovery" machine:
//
//   qemu-system-arm -machine stm32vldiscovery -kernel fw.bin
//
// Memory model:
//   - the image is loaded by QEMU (-kernel) at IMAGE_BASE (0x08000000);
//     the first 16 words are the CM3 vector table,
//   - console output goes to the USART2 peripheral at 0x40004400 (the
//     peripheral QEMU wires to the serial chardev); the startup code
//     enables its clock (RCC APB1ENR) and configures BRR/CR1,
//   - every IR virtual register v is an 8-byte frame slot at [SP + 8*v];
//     each function allocates a frame of 8*maxSlot bytes and saves LR at
//     the top (push {lr} / pop {pc}); slots are accessed as 32-bit words
//     (int32 target: the top 4 bytes of each slot are unused),
//   - r0..r3 carry the first 4 argument registers (IR enforces nargs<=4),
//     r0 carries the result; r8=address, r10/r11=scratch. r4-r11 are
//     callee-saved, so runtime helpers save what they use,
//   - globals live in SRAM (a copy of the initialized image data is made
//     by the startup code to SRAM_BASE, so GLoad/GStore/PLoad work on
//     writable memory),
//   - absolute addresses (strings/globals/functions) are patched into
//     MOVW/MOVT pairs after the final layout (the binary is tied to
//     IMAGE_BASE),
//   - calls are real BL (relative) instructions patched after layout; the
//     BLX usage is avoided because on ARMv7-M (no ARM state) BLX Rm with
//     an even target is UNPREDICTABLE. Branches are relaxed to a far form
//     (MOVW/MOVT r12 + BX r12, target|1 for the Thumb bit) when the short
//     Thumb range is exceeded,
//   - float operations are not implemented: any float-tagged IR (a.off,
//     FConst/F*/FPStore/PrintFlt) throws, and main.cpp falls back to the
//     classic backend,
//   - PrintStr/PrintInt append CRLF like the x86 IR backend.
//
// Image layout: [vector table][startup][runtime helpers][user functions]
//               [globals (copied to SRAM)][string pool]
// ====================================================================

namespace {

constexpr uint32_t IMAGE_BASE = 0x08000000u;
constexpr uint32_t SRAM_BASE  = 0x20000000u;
constexpr uint32_t STACK_TOP  = 0x20002000u;   // 8 KB SRAM (F100VBT6)
constexpr uint32_t USART2     = 0x40004400u;
constexpr uint32_t RCC        = 0x40021000u;   // APB1ENR at +0x1C (USART2EN = bit 17)

enum : int {
    R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12,
    SP = 13, LR = 14, PC = 15
};

// ARM condition codes (same numbers as the arm64 backend's ccForOp).
enum : int {
    CC_EQ = 0, CC_NE = 1, CC_CS = 2, CC_CC = 3,
    CC_MI = 4, CC_PL = 5, CC_HI = 8, CC_LS = 9,
    CC_GE = 10, CC_LT = 11, CC_GT = 12, CC_LE = 13
};

// ---------------- 16-bit Thumb-1 encoders ----------------
static inline uint16_t encMovs16(int rd, int rm)        { return 0x0000u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encMovsImm16(int rd, uint8_t v)  { return 0x2000u | ((rd & 7) << 8) | v; }
static inline uint16_t encMov16(int rd, int rm)         { return 0x4600u | (((rd >> 3) & 1) << 7) | ((rm & 15) << 3) | (rd & 7); }
static inline uint16_t encAdds16(int rd, int rn, int rm){ return 0x1800u | ((rm & 7) << 6) | ((rn & 7) << 3) | (rd & 7); }
static inline uint16_t encSubs16(int rd, int rn, int rm){ return 0x1A00u | ((rm & 7) << 6) | ((rn & 7) << 3) | (rd & 7); }
static inline uint16_t encAddsImm16(int rd, uint8_t v)  { return 0x3000u | ((rd & 7) << 8) | v; }
static inline uint16_t encSubsImm16(int rd, uint8_t v)  { return 0x3800u | ((rd & 7) << 8) | v; }
static inline uint16_t encAnds16(int rd, int rm)        { return 0x4000u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encEors16(int rd, int rm)        { return 0x4040u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encOrrs16(int rd, int rm)        { return 0x4300u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encMuls16(int rd, int rm)        { return 0x4340u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encRsbs16(int rd, int rm)        { return 0x4240u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encMvns16(int rd, int rm)        { return 0x43C0u | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encCmps16(int rn, int rm)        { return 0x4280u | ((rm & 7) << 3) | (rn & 7); }
static inline uint16_t encCmpImm16(int rn, uint8_t v)   { return 0x2800u | ((rn & 7) << 8) | v; }
static inline uint16_t encLslImm16(int rd, int rm, int imm5) { return 0x0000u | ((imm5 & 31) << 6) | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encLsrImm16(int rd, int rm, int imm5) { return 0x0800u | ((imm5 & 31) << 6) | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encAsrImm16(int rd, int rm, int imm5) { return 0x1000u | ((imm5 & 31) << 6) | ((rm & 7) << 3) | (rd & 7); }
static inline uint16_t encLdr16(int rt, int rn, int off)      { return 0x6800u | (((off / 4) & 31) << 6) | ((rn & 7) << 3) | (rt & 7); }
static inline uint16_t encStr16(int rt, int rn, int off)      { return 0x6000u | (((off / 4) & 31) << 6) | ((rn & 7) << 3) | (rt & 7); }
static inline uint16_t encLdrb16(int rt, int rn, int off)     { return 0x7800u | ((off & 31) << 6) | ((rn & 7) << 3) | (rt & 7); }
static inline uint16_t encStrb16(int rt, int rn, int off)     { return 0x7000u | ((off & 31) << 6) | ((rn & 7) << 3) | (rt & 7); }
static inline uint16_t encLdrSp16(int rt, int off)            { return 0x9800u | ((rt & 7) << 8) | ((off / 4) & 0xFF); }
static inline uint16_t encStrSp16(int rt, int off)            { return 0x9000u | ((rt & 7) << 8) | ((off / 4) & 0xFF); }
static inline uint16_t encAddSp16(int imm7)                   { return 0xB000u | (imm7 & 0x7F); }
static inline uint16_t encSubSp16(int imm7)                   { return 0xB080u | (imm7 & 0x7F); }
static inline uint16_t encPush(int mask, bool lr)             { return 0xB400u | (lr ? 0x100u : 0) | (mask & 0xFF); }
static inline uint16_t encPop(int mask, bool pc)              { return 0xBC00u | (pc ? 0x100u : 0) | (mask & 0xFF); }
static inline uint16_t encBx(int rm)                          { return 0x4700u | ((rm & 15) << 3); }
static inline uint16_t encB16(int32_t rel)                    { return 0xE000u | (rel & 0x7FF); }
static inline uint16_t encBcc16(int cc, int32_t rel)          { return 0xD000u | ((cc & 15) << 8) | (rel & 0xFF); }

// ---------------- 32-bit Thumb-2 encoders ----------------
// The word is returned as (hw1 << 16) | hw2; hw1 goes to the lower
// address. All T2 register ALUs (add_w_r / sub_w_r / and_w / orr_w /
// eor_w / mvn_w) put "rd" in hw2 bits 11:8, as selected by capstone.
static inline uint32_t t2(uint16_t hw1, uint16_t hw2) { return ((uint32_t)hw1 << 16) | hw2; }

// 32-bit Thumb-2 BL: target = Align(PC+4,4) + disp (signed, ±16 MB).
static inline uint32_t encBl(int32_t disp) {
    uint32_t x = (uint32_t)disp & 0x1FFFFFFu;
    uint32_t S = (x >> 24) & 1, I1 = (x >> 23) & 1, I2 = (x >> 22) & 1;
    uint32_t imm10 = (x >> 12) & 0x3FF, imm11 = (x >> 1) & 0x7FF;
    uint32_t J1 = !(I1 ^ S), J2 = !(I2 ^ S);
    return t2(0xF000u | (S << 10) | imm10, 0xD000u | (J1 << 13) | (J2 << 11) | imm11);
}
static inline uint32_t encBlZero() { return encBl(0); }   // placeholder (patched later)

static inline uint32_t encMovw(int rd, uint32_t v) {
    uint32_t i = (v >> 11) & 1, imm4 = (v >> 12) & 0xF, imm3 = (v >> 8) & 7, imm8 = v & 0xFF;
    return t2(0xF240u | (i << 10) | imm4, (imm3 << 12) | ((rd & 15) << 8) | imm8);
}
static inline uint32_t encMovt(int rd, uint32_t v) {
    uint32_t i = (v >> 11) & 1, imm4 = (v >> 12) & 0xF, imm3 = (v >> 8) & 7, imm8 = v & 0xFF;
    return t2(0xF2C0u | (i << 10) | imm4, (imm3 << 12) | ((rd & 15) << 8) | imm8);
}
static inline uint32_t encAddTw2(int rd, int rn, uint32_t imm12) {
    uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
    return t2(0xF200u | (i << 10) | (rn & 15), (imm3 << 12) | ((rd & 15) << 8) | imm8);
}
static inline uint32_t encSubTw2(int rd, int rn, uint32_t imm12) {
    uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
    return t2(0xF2A0u | (i << 10) | (rn & 15), (imm3 << 12) | ((rd & 15) << 8) | imm8);
}
static inline uint32_t encAddRegT2(int rd, int rn, int rm) { return t2(0xEB00u | (rn & 15), ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encSubRegT2(int rd, int rn, int rm) { return t2(0xEBA0u | (rn & 15), ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encAndRegT2(int rd, int rn, int rm) { return t2(0xEA00u | (rn & 15), ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encOrrRegT2(int rd, int rn, int rm) { return t2(0xEA40u | (rn & 15), ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encEorRegT2(int rd, int rn, int rm) { return t2(0xEA80u | (rn & 15), ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encMvnT2(int rd, int rm)             { return t2(0xEA6Fu, ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encCmpRegT2(int rn, int rm)          { return t2(0xEBB0u | (rn & 15), 0x0F00u | (rm & 15)); }
static inline uint32_t encCmpImmT2(int rn, uint32_t imm12) {
    uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
    return t2(0xF1B0u | (i << 10) | (rn & 15), (imm3 << 12) | 0xF00u | imm8);
}
static inline uint32_t encLslT2(int rd, int rn, int rm)     { return t2(0xFA00u | (rn & 15), 0xF000u | ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encLsrT2(int rd, int rn, int rm)     { return t2(0xFA20u | (rn & 15), 0xF000u | ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encAsrT2(int rd, int rn, int rm)     { return t2(0xFA40u | (rn & 15), 0xF000u | ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encMulT2(int rd, int rn, int rm)     { return t2(0xFB00u | (rn & 15), 0xF000u | ((rd & 15) << 8) | (rm & 15)); }
static inline uint32_t encSdivT2(int rd, int rn, int rm)    { return t2(0xFB90u | (rn & 15), 0xF000u | ((rd & 15) << 8) | 0xF0u | (rm & 15)); }
static inline uint32_t encUdivT2(int rd, int rn, int rm)    { return t2(0xFBB0u | (rn & 15), 0xF000u | ((rd & 15) << 8) | 0xF0u | (rm & 15)); }
static inline uint32_t encMlsT2(int rd, int rn, int rm, int ra) { return t2(0xFB00u | (rn & 15), ((ra & 15) << 12) | ((rd & 15) << 8) | 0x10u | (rm & 15)); }
static inline uint32_t encLdrT2(int rt, int rn, uint32_t off)   { return t2(0xF8D0u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }
static inline uint32_t encStrT2(int rt, int rn, uint32_t off)   { return t2(0xF8C0u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }
static inline uint32_t encLdrbT2(int rt, int rn, uint32_t off)  { return t2(0xF890u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }
static inline uint32_t encStrbT2(int rt, int rn, uint32_t off)  { return t2(0xF880u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }
static inline uint32_t encLdrhT2(int rt, int rn, uint32_t off)  { return t2(0xF8B0u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }
static inline uint32_t encStrhT2(int rt, int rn, uint32_t off)  { return t2(0xF8A0u | (rn & 15), ((rt & 15) << 12) | (off & 0xFFF)); }

// signed compare conditions for Cmp / BrCC
//   "==" "!=" "<" "<=" ">" ">=" "u<" "u<=" "u>" "u>="
static int ccForOp(const std::string& op) {
    if (op == "==" ) return CC_EQ;
    if (op == "!=" ) return CC_NE;
    if (op == "<"  ) return CC_LT;
    if (op == "<=" ) return CC_LE;
    if (op == ">"  ) return CC_GT;
    if (op == ">=" ) return CC_GE;
    if (op == "u<" ) return CC_CC;
    if (op == "u<=") return CC_LS;
    if (op == "u>" ) return CC_HI;
    if (op == "u>=") return CC_CS;
    return -1;
}

static void patchH(std::vector<uint8_t>& buf, int pos, uint16_t v) {
    if (pos < 0 || pos + 1 >= (int)buf.size()) return;
    buf[(size_t)pos]     = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)(v >> 8);
}

static void patchU32(std::vector<uint8_t>& buf, int pos, uint32_t v) {
    if (pos < 0 || pos + 3 >= (int)buf.size()) return;
    buf[(size_t)pos]     = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)((v >> 8) & 0xFF);
    buf[(size_t)pos + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[(size_t)pos + 3] = (uint8_t)((v >> 24) & 0xFF);
}

// Replace a MOVW/MOVT pair at (base+pos) with an absolute 32-bit value.
// The pair was emitted as 4 zero bytes by AsmBuf::dataAddr.
static void patchMovwMovt(std::vector<uint8_t>& buf, int base, int pos, int rt, uint32_t v) {
    uint32_t w = encMovw(rt, v & 0xFFFF);
    uint32_t t = encMovt(rt, (v >> 16) & 0xFFFF);
    patchH(buf, base + pos,     (uint16_t)(w >> 16));
    patchH(buf, base + pos + 2, (uint16_t)(w & 0xFFFF));
    patchH(buf, base + pos + 4, (uint16_t)(t >> 16));
    patchH(buf, base + pos + 6, (uint16_t)(t & 0xFFFF));
}

// Patch a 4-byte BL at image-relative `pos` so it lands on `targetAbs`.
// QEMU (and capstone) compute the Thumb PC for BL as addr+4 without word
// alignment, so the displacement must use the unaligned PC to match.
static void patchBl(std::vector<uint8_t>& buf, int pos, uint32_t targetAbs) {
    uint32_t pc = (uint32_t)pos + 4u;
    int32_t disp = (int32_t)(targetAbs - 0x08000000u - pc);
    uint32_t w = encBl(disp);
    patchH(buf, pos,     (uint16_t)(w >> 16));
    patchH(buf, pos + 2, (uint16_t)(w & 0xFFFF));
}

// --------------------------------------------------------------------
// AsmBuf: per-function code buffer with labels, branches, data fixes.
// Branches are patched in-place (short form); far branches expand into
// MOVW/MOVT r12 + BX r12 whose targets are resolved during layout.
// Calls are 4-byte BL placeholders recorded for patching after layout.
// Absolute MOVW/MOVT pairs are recorded as Df records and patched once
// the final image layout is known.
// --------------------------------------------------------------------
struct AsmBuf {
    enum DfK {
        DfStr,        // IMAGE_BASE + dataStart + poolBase + strOff[strIdx]
        DfGlobal,     // SRAM_BASE + gOff + extra         (globals live in SRAM)
        DfFunc,       // IMAGE_BASE + imgStart[name]
        DfLabel,      // IMAGE_BASE + imgStart[fn] + labelPos[label]  (unused)
        DfStartSrc,   // IMAGE_BASE + dataStart           (startup global copy src)
        DfStartSize,  // globalBytes                      (startup copy size)
        DfStartEntry  // IMAGE_BASE + imgStart[entry]     (unused: entry goes through BL)
    };
    struct Br { int pos = 0; int label = -1; int cc = 0; int ord = -1; bool isCond = false; bool far = false; };
    struct Df { int pos = 0; int rt = 0; DfK kind = DfGlobal; int strIdx = -1; int label = -1; int extra = 0; std::string name; };
    struct Fj { int pos = 0; int label = -1; };
    struct Call { int pos = 0; std::string name; };

    std::vector<uint8_t> c;
    std::unordered_map<int, int> labelPos;
    std::vector<Br> brs;
    std::vector<Df> dfx;
    std::vector<Fj> fjs;
    std::vector<Call> calls;

    void h(uint16_t v) {
        c.push_back((uint8_t)(v & 0xFF));
        c.push_back((uint8_t)(v >> 8));
    }
    void t2_(uint32_t enc) {           // hw1 at the lower address
        h((uint16_t)(enc >> 16));
        h((uint16_t)(enc & 0xFFFF));
    }
    void label(int id) { labelPos[id] = (int)c.size(); }
    int labPos(int id) const { auto it = labelPos.find(id); return it == labelPos.end() ? -1 : it->second; }

    // short branches (patched later once the pass is final)
    void b(int L) { int p = (int)c.size(); h(0xE000); brs.push_back({ p, L, 0, -1, false, false }); }
    void bcc(int cc, int L) { int p = (int)c.size(); h(0xD000 | ((cc & 15) << 8)); brs.push_back({ p, L, cc, -1, true, false }); }
    // far branches: short branch (skipping the 10-byte tail) + MOVW/MOVT r12 + BX r12.
    // The MOVW/MOVT pair is patched with target|1 so BX keeps the Thumb bit.
    void farB(int L) {
        int p = (int)c.size();
        h(0); h(0); h(0); h(0);          // movw/movt r12, #0 (patched)
        h(encBx(R12));
        fjs.push_back({ p, L });
    }
    void farBcc(int cc, int L) {
        h(encBcc16(cc ^ 1, 4));          // b.!cc skip to pos+12 (past the tail)
        int p = (int)c.size();
        h(0); h(0); h(0); h(0);
        h(encBx(R12));
        fjs.push_back({ p, L });
    }

    // 4-byte BL call to `name` (address resolved after layout)
    void callRel(const std::string& name) {
        int p = (int)c.size();
        t2_(encBlZero());
        calls.push_back({ p, name });
    }

    void dataAddr(int rt, DfK kind, const std::string& name, int strIdx, int label, int extra) {
        int p = (int)c.size();
        h(0); h(0); h(0); h(0);          // movw/movt rt, #0 (patched)
        dfx.push_back({ p, rt, kind, strIdx, label, extra, name });
    }

    void movwImm(int rd, uint32_t v) { t2_(encMovw(rd, v)); }
    void movtImm(int rd, uint32_t v) { t2_(encMovt(rd, v)); }
    void loadConst32(int rd, uint32_t v) {
        movwImm(rd, v & 0xFFFF);
        if (v >> 16) movtImm(rd, (v >> 16) & 0xFFFF);
    }

    // Patch all short branches in-place (used by helpers/startup, whose
    // branches are tiny and never need the far form).
    void resolveShort() {
        for (auto& br : brs) {
            int t = labPos(br.label);
            if (t < 0) throw std::runtime_error("IR arm32: undefined label " + std::to_string(br.label));
            int64_t imm = ((int64_t)t - br.pos - 4) / 2;
            if (br.isCond) {
                if (imm < -128 || imm > 127) throw std::runtime_error("IR arm32: branch out of range");
                patchH(c, br.pos, encBcc16(br.cc, (int32_t)imm));
            } else {
                if (imm < -1024 || imm > 1023) throw std::runtime_error("IR arm32: branch out of range");
                patchH(c, br.pos, encB16((int32_t)imm));
            }
        }
    }
};

struct FnImg {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<AsmBuf::Df> dfx;
    std::vector<AsmBuf::Fj> fjs;
    std::vector<AsmBuf::Call> calls;
    std::unordered_map<int, int> labelPos;
};

// --------------------------------------------------------------------
// Function body emitter (slot machine: every virtual register is a frame
// slot; r0..r3 carry arguments, r0 the result). Excessive frames throw.
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// inline-asm encoder (Thumb-2 / ARMv7-M)
//
// Emits the parsed `asm { ... }` instructions for the STM32 target using
// native register names (r0..r15, sp, lr, pc). Only a small, testable
// subset is supported; unsupported mnemonics warn and are skipped.
// Numbers may be decimal or 0x-hex. Memory operands [rn], [rn, #imm].
// --------------------------------------------------------------------
struct AsmOpARM { int type = 0; int reg = 0; int64_t imm = 0; };   // 0=bool? 1=reg 2=imm 3=mem

static int asmRegARM(const std::string& s) {
    static const char* names[16] = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"};
    for (int i = 0; i < 16; i++) if (s == names[i]) return i;
    return -1;
}
static AsmOpARM parseAsmOpARM(const std::string& raw) {
    AsmOpARM o;
    std::string s = raw;
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.empty()) return o;
    if (s[0] == '[') {
        o.type = 3;
        size_t close = s.find(']');
        std::string inner = (close != std::string::npos) ? s.substr(1, close - 1) : s.substr(1);
        // strip optional leading/trailing whitespace; handle [rn] and [rn, #imm]
        std::string regPart, immPart;
        size_t comma = inner.find(',');
        regPart = (comma != std::string::npos) ? inner.substr(0, comma) : inner;
        immPart = (comma != std::string::npos) ? inner.substr(comma + 1) : "";
        while (!regPart.empty() && (regPart.front() == ' ' || regPart.front() == '\t')) regPart.erase(regPart.begin());
        while (!regPart.empty() && (regPart.back() == ' ' || regPart.back() == '\t')) regPart.pop_back();
        o.reg = asmRegARM(regPart);
        if (o.reg < 0) o.reg = 0;
        std::string t = immPart;
        while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(t.begin());
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
        if (!t.empty() && t[0] == '#') t.erase(t.begin());
        int64_t v = 0;
        try {
            if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) v = std::stoll(t.substr(2), nullptr, 16);
            else v = std::stoll(t, nullptr, 10);
        } catch (...) { v = 0; }
        o.imm = v;
        return o;
    }
    int ri = asmRegARM(s);
    if (ri >= 0) { o.type = 1; o.reg = ri; return o; }
    o.type = 2;
    std::string t = s;
    if (!t.empty() && t[0] == '#') t.erase(t.begin());
    int64_t v = 0;
    try {
        if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) v = std::stoll(t.substr(2), nullptr, 16);
        else v = std::stoll(t, nullptr, 10);
    } catch (...) { v = 0; }
    o.imm = v;
    return o;
}

static void encodeAsmARM(AsmBuf& a, const IRAsmBlock& blk) {
    for (auto& instr : blk.instrs) {
        std::string m = instr.mnemonic;
        for (auto& c : m) c = (char)tolower((unsigned char)c);
        AsmOpARM o1 = parseAsmOpARM(instr.op1);
        AsmOpARM o2 = parseAsmOpARM(instr.op2);

        if (m == "mov" || m == "movs") {
            if (o1.type == 1 && o2.type == 1) { a.h(encMov16(o1.reg, o2.reg)); continue; }
            if (o1.type == 1 && o2.type == 2 && o2.imm >= 0 && o2.imm <= 255) {
                if (o1.reg <= 7 && m == "movs") a.h(encMovsImm16(o1.reg, (uint8_t)o2.imm));
                else if (m == "movs") a.h(encMovsImm16(o1.reg, (uint8_t)o2.imm));
                else { a.t2_(encMovw(o1.reg, (uint32_t)o2.imm)); }
                continue;
            }
            if (o1.type == 1 && o2.type == 2) {   // movw/movt split
                uint32_t v = (uint32_t)o2.imm;
                a.t2_(encMovw(o1.reg, v & 0xFFFF));
                a.t2_(encMovt(o1.reg, (v >> 16) & 0xFFFF));
                continue;
            }
            fprintf(stderr, "Warning: IR arm32 asm: unsupported mov operands, skipped\n");
            continue;
        }
        if (m == "mvn") { if (o1.type == 1 && o2.type == 1) { a.t2_(encMvnT2(o1.reg, o2.reg)); } else fprintf(stderr, "Warning: IR arm32 asm: bad mvn\n"); continue; }
        if (m == "add" || m == "adds" || m == "sub" || m == "subs") {
            bool isSub = (m == "sub" || m == "subs");
            if (o1.type == 1 && o2.type == 1) {
                // add rd, rn  ->  add rd, rn, rd  (native mnemonic from parser is 2-op)
                int rn = o1.reg, rd = o1.reg;
                if (!instr.op2.empty()) rn = o2.reg;
                if (!instr.op3.empty()) rd = parseAsmOpARM(instr.op3).reg;
                if (rd < 0) rd = o1.reg;
                if (isSub) a.t2_(encSubRegT2(rd, o1.reg, rn));
                else       a.t2_(encAddRegT2(rd, o1.reg, rn));
                continue;
            }
            if (o1.type == 1 && o2.type == 2) {
                uint64_t imm = (uint64_t)o2.imm;
                if (o1.reg <= 7 && o2.imm >= 0 && o2.imm <= 7) {
                    if (isSub) a.h(encSubsImm16(o1.reg, (uint8_t)o2.imm));
                    else       a.h(encAddsImm16(o1.reg, (uint8_t)o2.imm));
                } else if (o2.imm >= 0 && o2.imm <= 4095) {
                    if (isSub) a.t2_(encSubTw2(o1.reg, o1.reg, (uint32_t)o2.imm));
                    else       a.t2_(encAddTw2(o1.reg, o1.reg, (uint32_t)o2.imm));
                } else {
                    // big immediate: load into r12, then add/sub
                    a.loadConst32(R12, (uint32_t)o2.imm);
                    if (isSub) a.t2_(encSubRegT2(o1.reg, o1.reg, R12));
                    else       a.t2_(encAddRegT2(o1.reg, o1.reg, R12));
                }
                continue;
            }
            fprintf(stderr, "Warning: IR arm32 asm: bad %s operands, skipped\n", m.c_str());
            continue;
        }
        if (m == "and" || m == "orr" || m == "eor" || m == "mul") {
            if (o1.type == 1 && o2.type == 1) {
                int rd = o1.reg, rn = o1.reg, rm = o2.reg;
                if (m == "and") a.t2_(encAndRegT2(rd, rn, rm));
                else if (m == "orr") a.t2_(encOrrRegT2(rd, rn, rm));
                else if (m == "eor") a.t2_(encEorRegT2(rd, rn, rm));
                else a.t2_(encMulT2(rd, rn, rm));
                continue;
            }
            fprintf(stderr, "Warning: IR arm32 asm: bad %s operands, skipped\n", m.c_str());
            continue;
        }
        if (m == "lsl" || m == "lsr" || m == "asr") {
            if (o1.type == 1 && o2.type == 1) {
                int rd = o1.reg, rn = o1.reg, rm = o2.reg;
                if (m == "lsr") a.t2_(encLsrT2(rd, rn, rm));
                else if (m == "asr") a.t2_(encAsrT2(rd, rn, rm));
                else a.t2_(encLslT2(rd, rn, rm));
                continue;
            }
            if (o1.type == 1 && o2.type == 2 && o1.reg <= 7 && o2.imm >= 0 && o2.imm <= 31) {
                // shift rd, rd, #imm32
                int rd = o1.reg;
                if (m == "lsr") { a.h(encLsrImm16(rd, rd, (int)o2.imm)); }
                else if (m == "asr") { a.h(encAsrImm16(rd, rd, (int)o2.imm)); }
                else { a.h(encLslImm16(rd, rd, (int)o2.imm)); }
                continue;
            }
            fprintf(stderr, "Warning: IR arm32 asm: bad %s operands, skipped\n", m.c_str());
            continue;
        }
        if (m == "cmp") {
            if (o1.type == 1 && o2.type == 1) { a.h(encCmps16(o1.reg, o2.reg)); continue; }
            if (o1.type == 1 && o2.type == 2 && o2.imm >= 0 && o2.imm <= 255) { a.h(encCmpImm16(o1.reg, (uint8_t)o2.imm)); continue; }
            fprintf(stderr, "Warning: IR arm32 asm: bad cmp operands, skipped\n");
            continue;
        }
        if (m == "ldr" && o1.type == 1 && o2.type == 3) {
            if (o2.imm >= 0 && o2.imm <= 4095 && (o2.imm & 3) == 0) a.t2_(encLdrT2(o1.reg, o2.reg, (uint32_t)o2.imm));
            else { a.t2_(encLdrT2(o1.reg, o2.reg, 0)); }
            continue;
        }
        if (m == "str" && o1.type == 1 && o2.type == 3) {
            if (o2.imm >= 0 && o2.imm <= 4095 && (o2.imm & 3) == 0) a.t2_(encStrT2(o1.reg, o2.reg, (uint32_t)o2.imm));
            else { a.t2_(encStrT2(o1.reg, o2.reg, 0)); }
            continue;
        }
        if (m == "bx" && o1.type == 1) { a.h(encBx(o1.reg)); continue; }
        if (m == "nop") { a.h(0xBF00); continue; }
        if (m == "push" && o1.type == 1) { a.h(encPush((1u << o1.reg) & 0xFF, false)); continue; }
        if (m == "pop" && o1.type == 1) { a.h(encPop((1u << o1.reg) & 0xFF, false)); continue; }
        // block movs: ldm/stm are not supported yet
        fprintf(stderr, "Warning: IR arm32 asm: unsupported instruction '%s', skipped\n", m.c_str());
    }
}

struct ArmFn {
    IRFunction& fn;
    const std::vector<IRAsmBlock>* asmBlocks;
    AsmBuf a;
    std::vector<int> pendingArgs;
    int nparams;
    int frame;
    int priv_ = -1;      // private labels (negative, never collide with IR labels)

    explicit ArmFn(IRFunction& f, const std::vector<IRAsmBlock>* ab) : fn(f), asmBlocks(ab) {
        nparams = f.nparams;
        int maxSlot = f.maxSlot > 0 ? f.maxSlot : 1;
        frame = 8 * maxSlot;
        if (frame > 4095)
            throw std::runtime_error("IR arm32: function frame too large");
    }

    int privLabel() { return priv_--; }

    void addUpTo(int rd, int64_t imm) {
        if (imm == 0) return;
        if (imm > 0) {
            uint64_t u = (uint64_t)imm;
            while (u) { uint32_t part = (uint32_t)(u & 0xFFF); if (part) a.t2_(encAddTw2(rd, rd, part)); u >>= 12; }
        } else {
            uint64_t u = (uint64_t)(-imm);
            while (u) { uint32_t part = (uint32_t)(u & 0xFFF); if (part) a.t2_(encSubTw2(rd, rd, part)); u >>= 12; }
        }
    }
    void addrNew(int64_t off) {
        a.h(encMov16(R8, SP));            // mov r8, sp
        addUpTo(R8, off);
    }
    // r8 = pointer value from slot, then r8 += off
    void addrOfPtr(int slotReg, int64_t off) {
        loadSlotTo(R8, slotReg, 0);
        addUpTo(R8, off);
    }
    void loadSlotTo(int rt, int slotReg, int64_t extra) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (rt <= 7 && off >= 0 && (off & 3) == 0 && off <= 1020)
            a.h(encLdrSp16(rt, (int)off));
        else if (off >= 0 && off <= 4095)
            a.t2_(encLdrT2(rt, SP, (uint32_t)off));
        else { addrNew(off); a.t2_(encLdrT2(rt, R8, 0)); }
    }
    void storeSlotFrom(int slotReg, int64_t extra, int rt) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (rt <= 7 && off >= 0 && (off & 3) == 0 && off <= 1020)
            a.h(encStrSp16(rt, (int)off));
        else if (off >= 0 && off <= 4095)
            a.t2_(encStrT2(rt, SP, (uint32_t)off));
        else { addrNew(off); a.t2_(encStrT2(rt, R8, 0)); }
    }
    void loadOperandR6(const IROperand& o) {
        if (o.kind == IROperand::Reg)      loadSlotTo(R6, o.reg, 0);
        else if (o.kind == IROperand::Imm) {
            int64_t v = o.imm;
            if (v >= 0 && v <= 255) a.h(encMovsImm16(R6, (uint8_t)v));
            else a.loadConst32(R6, (uint32_t)v);
        } else throw std::runtime_error("IR arm32: bad operand in integer op");
    }
    void loadOperandR7(const IROperand& o) {
        if (o.kind == IROperand::Reg)      loadSlotTo(R7, o.reg, 0);
        else if (o.kind == IROperand::Imm) {
            int64_t v = o.imm;
            if (v >= 0 && v <= 255) a.h(encMovsImm16(R7, (uint8_t)v));
            else a.loadConst32(R7, (uint32_t)v);
        } else throw std::runtime_error("IR arm32: bad operand in integer op");
    }

    void emitBin(const IRInstr& in) {
        loadOperandR6(in.b);
        loadOperandR7(in.c);
        switch (in.op) {
        case IROp::Add:  a.h(encAdds16(R6, R6, R7)); break;
        case IROp::Sub:  a.h(encSubs16(R6, R6, R7)); break;
        case IROp::And:  a.h(encAnds16(R6, R7)); break;
        case IROp::Or:   a.h(encOrrs16(R6, R7)); break;
        case IROp::Xor:  a.h(encEors16(R6, R7)); break;
        case IROp::Mul:  a.h(encMuls16(R6, R7)); break;
        case IROp::IDiv: a.t2_(encSdivT2(R6, R6, R7)); break;
        case IROp::UDiv: a.t2_(encUdivT2(R6, R6, R7)); break;
        case IROp::IMod: a.t2_(encSdivT2(R10, R6, R7)); a.t2_(encMlsT2(R6, R10, R7, R6)); break;
        case IROp::UMod: a.t2_(encUdivT2(R10, R6, R7)); a.t2_(encMlsT2(R6, R10, R7, R6)); break;
        case IROp::Shl:  a.t2_(encLslT2(R6, R6, R7)); break;
        case IROp::Shr:  a.t2_(encLsrT2(R6, R6, R7)); break;
        case IROp::Sar:  a.t2_(encAsrT2(R6, R6, R7)); break;
        default: throw std::runtime_error("IR arm32: bad binary op");
        }
        storeSlotFrom(in.a.reg, 0, R6);
    }

    bool emitOnce(std::unordered_set<int>& far) {
        int ord = 0;
        std::function<void(int, int)> brCC = [&](int cc, int L) {
            if (far.count(ord)) a.farBcc(cc, L);
            else a.bcc(cc, L);
            ++ord;
        };
        std::function<void(int)> br = [&](int L) {
            if (far.count(ord)) a.farB(L);
            else a.b(L);
            ++ord;
        };

        // prologue: save LR, allocate the frame, copy params into slots
        a.h(encPush(0, true));                          // push {lr}
        if (frame > 0) a.t2_(encSubTw2(SP, SP, frame));
        for (int v = 0; v < nparams; v++)
            a.t2_(encStrT2(v, SP, (uint32_t)(8 * v)));  // slot v at [sp + 8v]

        for (auto& in : fn.instrs) {
            if (in.garbage) continue;
            emitInstr(in, brCC, br);
        }

        // fall-off-the-end epilogue (unreachable, keeps the frame balanced)
        if (frame > 0) a.t2_(encAddTw2(SP, SP, frame));
        a.h(encPop(0, true));                           // pop {pc}

        bool changed = false;
        for (auto& b : a.brs) {
            if (b.far) continue;
            int t = a.labPos(b.label);
            if (t < 0) throw std::runtime_error("IR arm32: undefined label " + std::to_string(b.label));
            int64_t imm = ((int64_t)t - b.pos - 4) / 2;
            bool ok = b.isCond ? (imm >= -128 && imm <= 127) : (imm >= -1024 && imm <= 1023);
            if (!ok) { far.insert(b.ord); changed = true; }
        }
        return changed;
    }

    void emitBody() {
        std::unordered_set<int> far;
        for (;;) {
            a.c.clear(); a.brs.clear(); a.dfx.clear(); a.fjs.clear(); a.labelPos.clear();
            if (!emitOnce(far)) break;
        }
        // final: patch the short branches that stayed short
        for (auto& b : a.brs) {
            if (b.far) continue;
            int t = a.labPos(b.label);
            int64_t imm = ((int64_t)t - b.pos - 4) / 2;
            if (b.isCond) patchH(a.c, b.pos, encBcc16(b.cc, (int32_t)imm));
            else patchH(a.c, b.pos, encB16((int32_t)imm));
        }
    }

    void emitInstr(const IRInstr& in, std::function<void(int, int)>& brCC, std::function<void(int)>& br) {
        switch (in.op) {
        case IROp::Nop:
        case IROp::Func:
        case IROp::EndFunc:
            return;

        case IROp::Label:
            a.label(in.a.label);
            return;

        case IROp::Const: {
            int64_t v = in.b.imm;
            if (v >= 0 && v <= 255) a.h(encMovsImm16(R6, (uint8_t)v));
            else a.loadConst32(R6, (uint32_t)v);
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        }
        case IROp::FConst:
            throw std::runtime_error("IR arm32: float constants not supported");
        case IROp::Str:
            a.dataAddr(R8, AsmBuf::DfStr, "", in.b.strIdx, -1, 0);
            storeSlotFrom(in.a.reg, 0, R8);
            return;
        case IROp::Mov:
            loadSlotTo(R6, in.b.reg, 0);
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::LeaGlobal:
            a.dataAddr(R8, AsmBuf::DfGlobal, in.b.name, -1, -1, 0);
            storeSlotFrom(in.a.reg, 0, R8);
            return;
        case IROp::LeaSlot:
            addrNew((int64_t)in.b.reg * 8 + in.b.off);
            storeSlotFrom(in.a.reg, 0, R8);
            return;

        case IROp::Load:
        case IROp::Load32:
            loadSlotTo(R6, in.b.reg, in.label < 0 ? 0 : in.label);
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::Store:
        case IROp::Store32:
            loadSlotTo(R6, in.b.reg, 0);
            storeSlotFrom(in.a.reg, in.label < 0 ? 0 : in.label, R6);
            return;

        case IROp::GLoad:
        case IROp::GLoad32:
            a.dataAddr(R8, AsmBuf::DfGlobal, in.b.name, -1, -1, in.label < 0 ? 0 : in.label);
            a.t2_(encLdrT2(R6, R8, 0));
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::GStore:
        case IROp::GStore32:
            loadSlotTo(R6, in.b.reg, 0);
            a.dataAddr(R8, AsmBuf::DfGlobal, in.a.name, -1, -1, in.label < 0 ? 0 : in.label);
            a.t2_(encStrT2(R6, R8, 0));
            return;

        case IROp::PLoad:
        case IROp::PLoad32:
        case IROp::PLoad32Z:
            addrOfPtr(in.b.reg, in.b.off);
            a.t2_(encLdrT2(R6, R8, 0));
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::PLoadW:
            addrOfPtr(in.b.reg, in.b.off);
            a.t2_(encLdrhT2(R6, R8, 0));
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::PLoadB:
            addrOfPtr(in.b.reg, in.b.off);
            a.t2_(encLdrbT2(R6, R8, 0));
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::PStore:
        case IROp::PStore32:
            loadSlotTo(R6, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.t2_(encStrT2(R6, R8, 0));
            return;
        case IROp::PStoreW:
            loadSlotTo(R6, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.t2_(encStrhT2(R6, R8, 0));
            return;
        case IROp::PStoreB:
            loadSlotTo(R6, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.t2_(encStrbT2(R6, R8, 0));
            return;
        case IROp::FPStore:
            throw std::runtime_error("IR arm32: float stores not supported");

        case IROp::FLoad:
        case IROp::FStore:
        case IROp::FGLoad:
        case IROp::FGStore:
        case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
        case IROp::FMov: case IROp::FNeg: case IROp::I2F: case IROp::F2I:
            throw std::runtime_error("IR arm32: float operations not supported");

        case IROp::Arg:
            if (in.a.off != 0) throw std::runtime_error("IR arm32: float arguments not supported");
            pendingArgs.push_back(in.b.reg);
            return;

        case IROp::Call:
        case IROp::ICall: {
            if (in.a.off != 0) throw std::runtime_error("IR arm32: float call result not supported");
            if (in.b.kind == IROperand::Reg)
                throw std::runtime_error("IR arm32: indirect call through function pointer not supported");
            std::string target = in.b.name;
            if (in.op == IROp::ICall) {
                if (target == "halt") target = "__zt_halt";
                else throw std::runtime_error("IR arm32: unsupported import '" + target + "'");
            }
            int nargs = (int)in.c.imm;
            if (nargs > 4) throw std::runtime_error("IR arm32: more than 4 arguments");
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++)
                loadSlotTo(R0 + k, pendingArgs[k], 0);
            a.callRel(target);
            pendingArgs.clear();
            if (in.a.kind == IROperand::Reg) {
                a.h(encMov16(R6, R0));
                storeSlotFrom(in.a.reg, 0, R6);
            }
            return;
        }

        case IROp::PrintStr:
            if (in.a.kind == IROperand::StrIdx) {
                a.dataAddr(R0, AsmBuf::DfStr, "", in.a.strIdx, -1, 0);
            } else if (in.a.kind == IROperand::Reg) {
                loadSlotTo(R0, in.a.reg, 0);
            } else throw std::runtime_error("IR arm32: bad PrintStr operand");
            a.callRel("__z_print_string");
            return;
        case IROp::PrintInt:
            if (in.a.kind != IROperand::Reg)
                throw std::runtime_error("IR arm32: bad PrintInt operand");
            loadSlotTo(R0, in.a.reg, 0);
            a.callRel("__z_print_int");
            return;
        case IROp::PrintFlt:
            throw std::runtime_error("IR arm32: float printing not supported");

        case IROp::Exit:
            a.callRel("__zt_halt");
            return;

        case IROp::Ret: {
            if (in.a.off != 0) throw std::runtime_error("IR arm32: float return not supported");
            pendingArgs.clear();
            if (in.a.kind == IROperand::Reg) loadSlotTo(R0, in.a.reg, 0);
            if (frame > 0) a.t2_(encAddTw2(SP, SP, frame));
            a.h(encPop(0, true));                        // pop {pc}
            return;
        }

        case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor:
        case IROp::Mul: case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
        case IROp::Shl: case IROp::Shr: case IROp::Sar:
            emitBin(in);
            return;

        case IROp::Neg:
            loadSlotTo(R6, in.b.reg, 0);
            a.h(encRsbs16(R6, R6));
            storeSlotFrom(in.a.reg, 0, R6);
            return;
        case IROp::Not:
            loadSlotTo(R6, in.b.reg, 0);
            a.h(encMvns16(R6, R6));
            storeSlotFrom(in.a.reg, 0, R6);
            return;

        case IROp::Cmp: {
            if (in.a.off != 0) throw std::runtime_error("IR arm32: float compare not supported");
            loadOperandR6(in.b);
            loadOperandR7(in.c);
            a.h(encMovsImm16(R2, 0));                    // result = 0
            a.h(encCmps16(R6, R7));                      // CMP r6, r7
            int cc = ccForOp(in.cond);
            if (cc < 0) throw std::runtime_error("IR arm32: bad compare condition '" + in.cond + "'");
            int skip = privLabel();
            brCC(cc ^ 1, skip);                          // if NOT cond, keep 0
            a.h(encMovsImm16(R2, 1));                    // result = 1
            a.label(skip);
            storeSlotFrom(in.a.reg, 0, R2);
            return;
        }

        case IROp::Br:
            br(in.b.label);
            return;
        case IROp::BrZ:
            loadSlotTo(R6, in.a.reg, 0);
            a.h(encCmpImm16(R6, 0));
            brCC(CC_EQ, in.b.label);
            return;
        case IROp::BrNZ:
            loadSlotTo(R6, in.a.reg, 0);
            a.h(encCmpImm16(R6, 0));
            brCC(CC_NE, in.b.label);
            return;
        case IROp::BrCC: {
            if (in.a.off != 0) throw std::runtime_error("IR arm32: float branch not supported");
            loadOperandR6(in.a);
            loadOperandR7(in.b);
            a.h(encCmps16(R6, R7));                      // CMP r6, r7
            int cc = ccForOp(in.cond);
            if (cc < 0) throw std::runtime_error("IR arm32: bad branch condition '" + in.cond + "'");
            brCC(cc, in.c.label);
            return;
        }

        default:
            if (in.op == IROp::RawAsm) {
                if (!asmBlocks || in.a.strIdx < 0 || in.a.strIdx >= (int)asmBlocks->size())
                    throw std::runtime_error("IR arm32: bad inline asm block index");
                encodeAsmARM(a, (*asmBlocks)[in.a.strIdx]);
                return;
            }
            throw std::runtime_error("IR arm32: unhandled IR op " + std::to_string((int)in.op));
        }
    }
};

// --------------------------------------------------------------------
// Startup code (placed right after the vector table, at offset 64):
// set SP, enable USART2, configure it, copy the globals to SRAM, call
// the entry function, then spin.
// --------------------------------------------------------------------
static void buildStartup(AsmBuf& a, const std::string& entry) {
    // SP = STACK_TOP (0x20002000)
    a.loadConst32(R1, STACK_TOP);                // movw/movt r1
    a.h(encMov16(SP, R1));                       // mov sp, r1

    // RCC APB1ENR (0x4002101C) |= 0x00020000 (USART2EN)
    a.loadConst32(R1, RCC);
    a.t2_(encLdrT2(R2, R1, 0x1C));
    a.loadConst32(R3, 0x00020000u);
    a.h(encOrrs16(R2, R3));
    a.t2_(encStrT2(R2, R1, 0x1C));

    // USART2 (0x40004400): BRR = 4, CR1 = UE|TE|RE (0x200C)
    a.loadConst32(R1, USART2);
    a.h(encMovsImm16(R2, 4));
    a.t2_(encStrT2(R2, R1, 8));                  // BRR
    a.loadConst32(R2, 0x200C);
    a.t2_(encStrT2(R2, R1, 0x0C));               // CR1

    // copy globals from IMAGE[dst=IMAGE_BASE+dataStart] to SRAM_BASE
    a.dataAddr(R0, AsmBuf::DfStartSrc, "", -1, -1, 0);
    a.loadConst32(R1, SRAM_BASE);
    a.dataAddr(R2, AsmBuf::DfStartSize, "", -1, -1, 0);
    int Lc = 0, Ld = 1;
    a.label(Lc);
    a.h(encCmpImm16(R2, 0));
    a.bcc(CC_EQ, Ld);
    a.t2_(encLdrT2(R3, R0, 0));
    a.t2_(encStrT2(R3, R1, 0));
    a.h(encAddsImm16(R0, 4));
    a.h(encAddsImm16(R1, 4));
    a.h(encSubsImm16(R2, 4));
    a.b(Lc);
    a.label(Ld);

    // call the entry function, then spin
    a.callRel(entry);
    a.h(0xE7FE);                                 // b . (spin)
}

// --------------------------------------------------------------------
// Runtime helpers (__z_putc / __z_puts / __z_print_string /
// __z_print_int / __zt_halt). Only r0-r3 and (saved) r4-r7 are used,
// calls go through the patched-BL mechanism.
// --------------------------------------------------------------------
static FnImg buildHelper(const std::string& name) {
    AsmBuf a;
    // Helper-to-helper calls go through the same patched-BL mechanism.
    auto call = [&](const std::string& target) { a.callRel(target); };

    if (name == "__z_putc") {
        // r0 = char; wait for TXE (USART_SR bit 7) then write USART_DR
        a.loadConst32(R1, USART2);
        int Lw = 0;
        a.label(Lw);
        a.t2_(encLdrT2(R2, R1, 0));              // ldr r2,[r1,#0] (SR)
        a.h(encLslImm16(R2, R2, 24));            // lsls r2,r2,#24 (TXE -> N)
        a.bcc(CC_PL, Lw);                        // bpl Lw
        a.t2_(encStrbT2(R0, R1, 4));             // strb r0,[r1,#4] (DR)
        a.h(encBx(LR));
    } else if (name == "__z_puts") {
        // r0 = NUL-terminated string, no trailing newline
        a.h(encPush((1 << R4), true));           // push {r4, lr}
        a.h(encMov16(R4, R0));                   // r4 = ptr
        int Lloop = 0, Ldone = 1;
        a.label(Lloop);
        a.h(encLdrb16(R0, R4, 0));               // ldrb r0,[r4,#0]
        a.h(encCmpImm16(R0, 0));
        a.bcc(CC_EQ, Ldone);
        call("__z_putc");
        a.h(encAddsImm16(R4, 1));
        a.b(Lloop);
        a.label(Ldone);
        a.h(encPop((1 << R4), true));            // pop {r4, pc}
    } else if (name == "__z_print_string") {
        // r0 = string -> string + CRLF
        a.h(encPush(0, true));                   // push {lr}
        call("__z_puts");
        a.h(encMovsImm16(R0, 0x0D)); call("__z_putc");
        a.h(encMovsImm16(R0, 0x0A)); call("__z_putc");
        a.h(encPop(0, true));                    // pop {pc}
    } else if (name == "__z_print_int") {
        // r0 = int32 -> decimal digits + CRLF (16-byte stack buffer:
        // up to 10 digits + '-' + NUL fits). Unsigned division on the
        // negated value makes INT_MIN print as -2147483648.
        a.h(encPush((1 << R4) | (1 << R5) | (1 << R6) | (1 << R7), true));  // push {r4-r7,lr}
        a.h(encSubSp16(4));                      // sub sp,#16
        a.h(encMov16(R4, R0));                   // r4 = n
        a.h(encMovsImm16(R5, 0));                // sign = 0
        a.h(encCmpImm16(R4, 0));
        int Ld = 2, Ldig = 3, Lloop = 4;
        a.bcc(CC_GE, Ld);                        // bge Ld
        a.h(encRsbs16(R4, R4));                  // n = -n
        a.h(encMovsImm16(R5, 1));
        a.label(Ld);
        a.h(encMov16(R6, SP));                   // r6 = buffer end (sp+15)
        a.h(encAddsImm16(R6, 15));
        a.h(encMovsImm16(R1, 0));                // NUL terminator
        a.h(encStrb16(R1, R6, 0));
        a.h(encSubsImm16(R6, 1));                // digits start at sp+14
        a.h(encMovsImm16(R1, 10));
        a.label(Lloop);
        a.t2_(encUdivT2(R2, R4, R1));            // q = n/10 (unsigned)
        a.t2_(encMlsT2(R3, R2, R1, R4));         // r = n - q*10
        a.h(encAddsImm16(R3, 0x30));             // '0'
        a.h(encStrb16(R3, R6, 0));               // digit at buffer end, going left
        a.h(encSubsImm16(R6, 1));
        a.h(encMov16(R4, R2));                   // n = q
        a.h(encCmpImm16(R4, 0));
        a.bcc(CC_NE, Lloop);                     // bne Lloop
        a.h(encAddsImm16(R6, 1));                // r6 = most significant digit
        a.h(encCmpImm16(R5, 0));
        a.bcc(CC_EQ, Ldig);                      // no sign
        a.h(encSubsImm16(R6, 1));                // room for '-'
        a.h(encMovsImm16(R7, 0x2D));             // '-'
        a.h(encStrb16(R7, R6, 0));
        a.label(Ldig);
        a.h(encMov16(R0, R6));
        call("__z_puts");
        a.h(encMovsImm16(R0, 0x0D)); call("__z_putc");
        a.h(encMovsImm16(R0, 0x0A)); call("__z_putc");
        a.h(encAddSp16(4));                      // add sp,#16
        a.h(encPop((1 << R4) | (1 << R5) | (1 << R6) | (1 << R7), true));  // pop {r4-r7,pc}
    } else if (name == "__zt_halt") {
        a.h(0xE7FE);                             // b . (spin)
    } else {
        throw std::runtime_error("IR arm32: unknown helper " + name);
    }
    a.resolveShort();

    FnImg img;
    img.name = name;
    img.bytes.swap(a.c);
    img.dfx.swap(a.dfx);
    img.fjs.swap(a.fjs);
    img.calls.swap(a.calls);
    img.labelPos.swap(a.labelPos);
    return img;
}

static int globalOff(IRProgram& ir, const std::string& name) {
    int off = 0;
    for (auto& g : ir.globals) {
        if (!g.used) continue;
        off = (off + 7) & ~7;
        if (g.name == name) return off;
        off += g.size >= 8 ? 8 : 4;
    }
    return -1;
}

} // namespace

// ====================================================================
// compile
// ====================================================================
bool IRAsmArm::compile(const std::string& outputPath) {
    using std::vector;
    using std::string;
    using std::unordered_map;

    // ---- startup + runtime helpers (imgs[0] is the startup block) ----
    vector<FnImg> imgs;
    unordered_map<string, int> nameIdx;
    {
        AsmBuf a;
        buildStartup(a, ir_.entryFunc);
        a.resolveShort();
        FnImg img;
        img.bytes.swap(a.c);
        img.dfx.swap(a.dfx);
        img.fjs.swap(a.fjs);
        img.calls.swap(a.calls);
        img.labelPos.swap(a.labelPos);
        imgs.push_back(std::move(img));
    }
    static const char* helpers[] = {
        "__z_putc", "__z_puts", "__z_print_string", "__z_print_int", "__zt_halt"
    };
    for (const char* h : helpers) {
        FnImg img = buildHelper(h);
        nameIdx[h] = (int)imgs.size();
        imgs.push_back(std::move(img));
    }

    // ---- user function bodies ----
    int entryIdx = -1;
    for (auto& f : ir_.functions) {
        if (f.garbage || f.isExtern) continue;
        ArmFn em(f, &ir_.asmBlocks);
        em.emitBody();
        FnImg img;
        img.name = f.name;
        img.bytes.swap(em.a.c);
        img.dfx.swap(em.a.dfx);
        img.fjs.swap(em.a.fjs);
        img.calls.swap(em.a.calls);
        img.labelPos.swap(em.a.labelPos);
        nameIdx[f.name] = (int)imgs.size();
        imgs.push_back(std::move(img));
        if (f.name == ir_.entryFunc) entryIdx = (int)imgs.size() - 1;
    }

    if (entryIdx < 0) {
        std::cerr << "IR arm32: entry function '" << ir_.entryFunc << "' not found" << std::endl;
        return false;
    }

    // ---- data layout: globals (8-byte stride, 8-aligned), then strings ----
    int globalBytes = 0;
    for (auto& g : ir_.globals) {
        if (!g.used) continue;
        globalBytes = (globalBytes + 7) & ~7;
        globalBytes += g.size >= 8 ? 8 : 4;
    }
    int poolBase = (globalBytes + 7) & ~7;

    // make sure every string-initialized global has a pool entry
    for (auto& g : ir_.globals) {
        if (!g.used || !g.isString) continue;
        bool found = false;
        for (auto& s : ir_.strings)
            if (s == g.strValue) { found = true; break; }
        if (!found) ir_.strings.push_back(g.strValue);
    }
    vector<int> strOff(ir_.strings.size());
    int poolBytes = 0;
    for (size_t i = 0; i < ir_.strings.size(); i++) {
        strOff[i] = poolBytes;
        poolBytes += (int)ir_.strings[i].size() + 1;
    }
    int dataBytes = poolBase + poolBytes;

    // ---- assemble the image ----
    vector<uint8_t> image;
    image.reserve(1 << 15);

    auto pushU32 = [&](uint32_t v) {
        image.push_back((uint8_t)(v & 0xFF));
        image.push_back((uint8_t)((v >> 8) & 0xFF));
        image.push_back((uint8_t)((v >> 16) & 0xFF));
        image.push_back((uint8_t)((v >> 24) & 0xFF));
    };

    image.resize(64, 0);   // CM3 vector table (16 words), patched below

    vector<int> imgStart((size_t)imgs.size(), 0);
    for (size_t i = 0; i < imgs.size(); i++) {
        imgStart[i] = (int)image.size();
        image.insert(image.end(), imgs[i].bytes.begin(), imgs[i].bytes.end());
    }

    // pad the code section to 4 bytes (0xB000 = add sp,#0, never executed)
    while ((int)image.size() % 4 != 0) { image.push_back(0x00); image.push_back(0xB0); }
    const int dataStart = (int)image.size();
    image.resize((size_t)dataStart + (size_t)dataBytes, 0);

    // --- vector table: SP, reset (offset 64), unused IRQ -> spin ---
    {
        uint32_t spinAbs = IMAGE_BASE + (uint32_t)imgStart[0] + (uint32_t)imgs[0].bytes.size() - 2;
        patchU32(image, 0, STACK_TOP);
        patchU32(image, 4, (IMAGE_BASE + 64u) | 1u);
        for (int k = 2; k < 16; k++) patchU32(image, 4 * k, spinAbs | 1u);
    }

    // --- globals ---
    {
        int off = 0;
        for (auto& g : ir_.globals) {
            if (!g.used) continue;
            off = (off + 7) & ~7;
            int at = dataStart + off;
            if (g.isString) {
                int idx = 0;
                while (idx < (int)ir_.strings.size() && ir_.strings[(size_t)idx] != g.strValue) idx++;
                uint32_t addr = IMAGE_BASE + (uint32_t)(dataStart + poolBase + strOff[(size_t)idx]);
                std::memcpy(image.data() + at, &addr, 4);
            } else if (g.isFloat) {
                float f = (float)g.floatValue;
                std::memcpy(image.data() + at, &f, 4);
            } else {
                int64_t v = g.intValue;
                std::memcpy(image.data() + at, &v, 4);
            }
            off += g.size >= 8 ? 8 : 4;
        }
    }
    // --- string pool ---
    for (size_t i = 0; i < ir_.strings.size(); i++) {
        int at = dataStart + poolBase + strOff[(size_t)i];
        std::memcpy(image.data() + at, ir_.strings[(size_t)i].data(), ir_.strings[(size_t)i].size());
        image[(size_t)at + ir_.strings[(size_t)i].size()] = 0;
    }

    // ---- resolve MOVW/MOVT data addresses and far branches ----
    for (size_t i = 0; i < imgs.size(); i++) {
        int base = imgStart[i];
        for (auto& df : imgs[i].dfx) {
            uint32_t target = 0;
            switch (df.kind) {
            case AsmBuf::DfStr: {
                int idx = df.strIdx;
                if (idx < 0 || idx >= (int)strOff.size())
                    target = IMAGE_BASE + (uint32_t)(dataStart + poolBase);
                else
                    target = IMAGE_BASE + (uint32_t)(dataStart + poolBase + strOff[(size_t)idx]);
                break;
            }
            case AsmBuf::DfGlobal: {
                int goff = globalOff(ir_, df.name);
                if (goff < 0) {
                    std::cerr << "IR arm32: unknown global '" << df.name << "'" << std::endl;
                    return false;
                }
                target = SRAM_BASE + (uint32_t)goff + (uint32_t)df.extra;
                break;
            }
            case AsmBuf::DfFunc: {
                auto it = nameIdx.find(df.name);
                if (it == nameIdx.end()) {
                    std::cerr << "IR arm32: unknown callee '" << df.name << "'" << std::endl;
                    return false;
                }
                target = IMAGE_BASE + (uint32_t)imgStart[(size_t)it->second];
                break;
            }
            case AsmBuf::DfLabel: {
                auto it = imgs[i].labelPos.find(df.label);
                int lpos = (it != imgs[i].labelPos.end()) ? it->second : -1;
                target = IMAGE_BASE + (uint32_t)(base + lpos);
                break;
            }
            case AsmBuf::DfStartSrc:   target = IMAGE_BASE + (uint32_t)dataStart; break;
            case AsmBuf::DfStartSize:  target = (uint32_t)globalBytes; break;
            case AsmBuf::DfStartEntry: target = IMAGE_BASE + (uint32_t)imgStart[(size_t)entryIdx]; break;
            }
            patchMovwMovt(image, base, df.pos, df.rt, target);
        }
        for (auto& fj : imgs[i].fjs) {
            auto it = imgs[i].labelPos.find(fj.label);
            int lpos = (it != imgs[i].labelPos.end()) ? it->second : -1;
            uint32_t target = IMAGE_BASE + (uint32_t)(base + lpos);
            patchMovwMovt(image, base, fj.pos, R12, target | 1u);  // |1 keeps Thumb for BX
        }
        // calls: rel-BL placeholders, patched once every function address is known
        for (auto& cl : imgs[i].calls) {
            auto it = nameIdx.find(cl.name);
            if (it == nameIdx.end()) {
                std::cerr << "IR arm32: unknown callee '" << cl.name << "'" << std::endl;
                return false;
            }
            uint32_t target = IMAGE_BASE + (uint32_t)imgStart[(size_t)it->second];
            patchBl(image, base + cl.pos, target);
        }
    }

    // ---- write the binary ----
    std::ofstream fout(outputPath, std::ios::binary);
    if (!fout) {
        std::cerr << "IR arm32: cannot write " << outputPath << std::endl;
        exit(1);
    }
    fout.write((const char*)image.data(), (std::streamsize)image.size());
    fout.close();
    if (!fout) {
        std::cerr << "IR arm32: cannot write " << outputPath << std::endl;
        exit(1);
    }

    return true;
}