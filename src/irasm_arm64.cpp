#include "irasm_arm64.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <utility>

// ====================================================================
// IRAsmArm64 implementation
//
// Lowers the optimized assembler-IR into an AArch64 raw firmware image
// for QEMU's "virt" machine:
//
//   qemu-system-aarch64 -machine virt -cpu cortex-a53 -kernel fw.bin -nographic
//
// Memory model:
//   - the image is loaded by QEMU at IMAGE_BASE (0x40080000),
//   - console output goes to the PL011 UART at 0x09000000 (already up on
//     "virt"), using the FIFO TX flag like the classic ARM64 backend,
//   - every IR virtual register v is an 8-byte frame slot at [SP + 8*v];
//     each function allocates a frame of 8*maxSlot bytes (16-aligned),
//   - x0..x7 carry the first 8 argument registers (IR enforces nargs<=8),
//     x0 carries the result; x9..x11 are free scratch registers,
//   - absolute addresses (globals/strings) are patched into a MOVZ/MOVK
//     pair in the final layout (binary is tied to IMAGE_BASE),
//   - float operations are not implemented: any float-tagged IR (a.off,
//     FConst/F*/PrintFlt/FPStore) throws, and main.cpp falls back to the
//     classic backend,
//   - PrintStr/PrintInt append CRLF like the x86 IR backend.
//
// Image layout: [startup][runtime helpers][user functions][globals][strings]
// ====================================================================

namespace {

constexpr uint64_t IMAGE_BASE = 0x40080000ull;   // QEMU "virt" kernel load address
constexpr uint64_t STACK_TOP  = 0x47F00000ull;   // default "virt" RAM is 128 MB
constexpr uint32_t PL011_BASE = 0x09000000u;
constexpr uint32_t PL011_FR   = 0x18u;
constexpr uint32_t PL011_DR   = 0x00u;

enum : int {
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11,
    X30 = 30,
    XSP = 31, XZR = 31
};

// ---- AArch64 encoders (32-bit little-endian words) ----
static inline uint32_t encMovz(int rd, uint16_t imm16, int hw) { return 0xD2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd; }
static inline uint32_t encMovk(int rd, uint16_t imm16, int hw) { return 0xF2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd; }
static inline uint32_t encMov(int rd, int rn)                  { return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd; }
static inline uint32_t encAdd(int rd, int rn, uint16_t imm12, int sh = 0) { return 0x91000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encSub(int rd, int rn, uint16_t imm12, int sh = 0) { return 0xD1000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encSubs(int rd, int rn, uint16_t imm12, int sh = 0) { return 0xF1000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encCmp(int rn, uint16_t imm12)          { return encSubs(XZR, rn, imm12); }
static inline uint32_t encCmpReg(int rn, int rm)               { return 0xEB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)XZR; }
static inline uint32_t encAddReg(int rd, int rn, int rm)       { return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encSubReg(int rd, int rn, int rm)       { return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encAndReg(int rd, int rn, int rm)       { return 0x8A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encOrrReg(int rd, int rn, int rm)       { return 0xAA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encEorReg(int rd, int rn, int rm)       { return 0xCA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encMvn(int rd, int rm)                  { return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd; }
static inline uint32_t encNeg(int rd, int rm)                  { return 0xCB0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd; }
static inline uint32_t encLsl(int rd, int rn, int rm)          { return 0x9AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encLsr(int rd, int rn, int rm)          { return 0x9AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encAsr(int rd, int rn, int rm)          { return 0x9AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encMul(int rd, int rn, int rm)          { return 0x9B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encSdiv(int rd, int rn, int rm)         { return 0x9AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encUdiv(int rd, int rn, int rm)         { return 0x9AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encMsub(int rd, int rn, int rm, int ra) { return 0x9B008000u | ((uint32_t)rm << 16) | ((uint32_t)ra << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encAndsW(int rd, int rn, int rm)        { return 0x6A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encLdrX(int rt, int rn, uint16_t off)   { return 0xF9400000u | (((uint32_t)(off / 8)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encStrX(int rt, int rn, uint16_t off)   { return 0xF9000000u | (((uint32_t)(off / 8)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encLdrW(int rt, int rn, uint16_t off)   { return 0xB9400000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encStrW(int rt, int rn, uint16_t off)   { return 0xB9000000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encLdrbW(int rt, int rn, uint16_t off)  { return 0x39400000u | ((uint32_t)off << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encStrbW(int rt, int rn, uint16_t off)  { return 0x39000000u | ((uint32_t)off << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encLdrbWPost(int rt, int rn, int imm9)  { return 0x38400400u | ((uint32_t)(imm9 & 0x1FF) << 12) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encLdrswX(int rt, int rn, uint16_t off) { return 0xB9800000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encLdrhW(int rt, int rn, uint16_t off)   { return 0x79400000u | (((uint32_t)(off / 2)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encStrhW(int rt, int rn, uint16_t off)   { return 0x79000000u | (((uint32_t)(off / 2)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
static inline uint32_t encB(uint32_t imm26)                    { return 0x14000000u | (imm26 & 0x03FFFFFFu); }
static inline uint32_t encBl(uint32_t imm26)                   { return 0x94000000u | (imm26 & 0x03FFFFFFu); }
static inline uint32_t encBcond(uint32_t cond, uint32_t imm19) { return 0x54000000u | (cond & 15) | ((imm19 & 0x7FFFFu) << 5); }
static inline uint32_t encCbzx(int rt, uint32_t imm19)         { return 0xB4000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt; }
static inline uint32_t encCbnzx(int rt, uint32_t imm19)        { return 0xB5000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt; }
static inline uint32_t encCset(int rd, uint32_t cond)          { return 0x9A9F03E0u | (((cond ^ 1) & 15) << 12) | (uint32_t)rd; }
static inline uint32_t encRet()                                { return 0xD65F03C0u; }

// signed compare conditions for *Cmp(BrCC) with cond ==
//   "==" "!=" "<" "<=" ">" ">=" "u<" "u<=" "u>" "u>="
static int ccForOp(const std::string& op) {
    if (op == "==" ) return 0;   // EQ
    if (op == "!=" ) return 1;   // NE
    if (op == "<"  ) return 11;  // LT
    if (op == "<=" ) return 13;  // LE
    if (op == ">"  ) return 12;  // GT
    if (op == ">=" ) return 10;  // GE
    if (op == "u<" ) return 3;   // CC
    if (op == "u<=") return 9;   // LS
    if (op == "u>" ) return 8;   // HI
    if (op == "u>=") return 2;   // CS
    return -1;
}

void patchU32(std::vector<uint8_t>& buf, int pos, uint32_t v) {
    if (pos < 0 || pos + 3 >= (int)buf.size()) return;
    buf[(size_t)pos]     = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)((v >> 8) & 0xFF);
    buf[(size_t)pos + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[(size_t)pos + 3] = (uint8_t)((v >> 24) & 0xFF);
}

// --------------------------------------------------------------------
// AsmBuf: per-function code buffer with label / BL / data fixes.
// Labels and branches are resolved inside the buffer before it is
// placed in the final image (both targets and branches move together).
// BL targets and absolute data addresses are resolved during layout.
// --------------------------------------------------------------------
struct AsmBuf {
    struct Br { int pos = 0; int label = -1; int kind = 0; int cc = 0; int rt = 0; };  // 0=B 1=B.cond 2=Cbz 3=Cbnz
    struct Bl { int pos = 0; std::string target; };
    struct Df { int pos = 0; int rt = 0; bool isStr = false; int strIdx = -1; std::string name; int extra = 0; };

    std::vector<uint8_t> c;
    std::vector<int> labelPos;
    std::vector<Br> brs;
    std::vector<Bl> bls;
    std::vector<Df> dfx;

    void u32(uint32_t v) {
        c.push_back((uint8_t)(v & 0xFF));
        c.push_back((uint8_t)((v >> 8) & 0xFF));
        c.push_back((uint8_t)((v >> 16) & 0xFF));
        c.push_back((uint8_t)((v >> 24) & 0xFF));
    }
    void label(int id) {
        if (id >= (int)labelPos.size()) labelPos.resize(id + 1, -1);
        labelPos[id] = (int)c.size();
    }
    void b(int L)               { int p = (int)c.size(); u32(encB(0));            brs.push_back({ p, L, 0, 0, 0 }); }
    void bcc(int cc, int L)     { int p = (int)c.size(); u32(encBcond((uint32_t)cc, 0)); brs.push_back({ p, L, 1, cc, 0 }); }
    void cbz(int rt, int L)     { int p = (int)c.size(); u32(encCbzx(rt, 0));     brs.push_back({ p, L, 2, 0, rt }); }
    void cbnz(int rt, int L)    { int p = (int)c.size(); u32(encCbnzx(rt, 0));    brs.push_back({ p, L, 3, 0, rt }); }
    void bl(const std::string& name) {
        int p = (int)c.size(); u32(encBl(0));
        bls.push_back({ p, name });
    }

    // MOVZ/MOVK pair whose value is saturated from IMAGE_BASE + data offset.
    void dataAddr(int rt, bool isStr, int strIdx, const std::string& name, int extra) {
        int p = (int)c.size();
        u32(encMovz(rt, 0, 0));
        u32(encMovk(rt, 0, 1));
        dfx.push_back({ p, rt, isStr, strIdx, name, extra });
    }

    void loadConst(int rd, uint64_t v) {
        uint16_t w0 = (uint16_t)(v & 0xFFFF);
        uint16_t w1 = (uint16_t)((v >> 16) & 0xFFFF);
        uint16_t w2 = (uint16_t)((v >> 32) & 0xFFFF);
        uint16_t w3 = (uint16_t)((v >> 48) & 0xFFFF);
        if (w3 == 0 && w2 == 0 && w1 == 0) { u32(encMovz(rd, w0, 0)); }
        else if (w3 == 0 && w2 == 0)       { u32(encMovz(rd, w0, 0)); u32(encMovk(rd, w1, 1)); }
        else if (w3 == 0)                  { u32(encMovz(rd, w0, 0)); u32(encMovk(rd, w1, 1)); u32(encMovk(rd, w2, 2)); }
        else                               { u32(encMovz(rd, w0, 0)); u32(encMovk(rd, w1, 1)); u32(encMovk(rd, w2, 2)); u32(encMovk(rd, w3, 3)); }
    }

    void resolveBranches() {
        for (auto& br : brs) {
            int t = (br.label >= 0 && br.label < (int)labelPos.size()) ? labelPos[br.label] : -1;
            if (t < 0) throw std::runtime_error("IR arm64: undefined label " + std::to_string(br.label));
            int rel = t - br.pos;
            if (br.kind == 0) {
                int32_t imm26 = rel / 4;
                if (imm26 < -33554432 || imm26 > 33554431) throw std::runtime_error("IR arm64: B out of range");
                patchU32(c, br.pos, encB((uint32_t)imm26));
            } else {
                int32_t imm19 = rel / 4;
                if (imm19 < -262144 || imm19 > 262143) throw std::runtime_error("IR arm64: B.cond out of range");
                if (br.kind == 1)      patchU32(c, br.pos, encBcond((uint32_t)br.cc, (uint32_t)imm19));
                else if (br.kind == 2) patchU32(c, br.pos, encCbzx(br.rt, (uint32_t)imm19));
                else                   patchU32(c, br.pos, encCbnzx(br.rt, (uint32_t)imm19));
            }
        }
    }
};

// push rd += imm (small immediate chain, may be negative)
void addUpTo(AsmBuf& a, int rd, int64_t imm) {
    if (imm == 0) return;
    if (imm > 0) {
        uint64_t u = (uint64_t)imm;
        int sh = 0;
        while (u) { uint16_t part = (uint16_t)(u & 0xFFF); if (part) a.u32(encAdd(rd, rd, part, sh)); u >>= 12; sh += 1; }
    } else {
        uint64_t u = (uint64_t)(-imm);
        int sh = 0;
        while (u) { uint16_t part = (uint16_t)(u & 0xFFF); if (part) a.u32(encSub(rd, rd, part, sh)); u >>= 12; sh += 1; }
    }
}

struct FnImg {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<AsmBuf::Bl> bls;
    std::vector<AsmBuf::Df> dfx;
};

// --------------------------------------------------------------------
// Function body emitter (slot machine: every virtual register is a
// frame slot; x0..x7 carry arguments, x0 the result).
// --------------------------------------------------------------------
struct A64Fn {
    IRFunction& fn;
    AsmBuf a;
    std::vector<int> pendingArgs;
    int nparams;
    int frameAligned;
    int spAlloc;

    explicit A64Fn(IRFunction& f) : fn(f) {
        nparams = f.nparams;
        int maxSlot = f.maxSlot > 0 ? f.maxSlot : 1;
        frameAligned = ((8 * maxSlot) + 15) & ~15;
        spAlloc = frameAligned + 16;
        if (frameAligned / 8 > 4095)
            throw std::runtime_error("IR arm64: function frame too large");
    }

    void addrNew(int64_t off) {
        // stateless: X9 = SP + off (never depends on a previous X9 value)
        a.u32(encAdd(X9, XSP, 0));
        addUpTo(a, X9, off);
    }
    void loadSlotTo(int rt, int slotReg, int64_t extra) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095)
            a.u32(encLdrX(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encLdrX(rt, X9, 0)); }
    }
    void storeSlotFrom(int slotReg, int64_t extra, int rt) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095)
            a.u32(encStrX(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encStrX(rt, X9, 0)); }
    }
    void loadOperandX(int rt, const IROperand& o) {
        if (o.kind == IROperand::Reg)      loadSlotTo(rt, o.reg, 0);
        else if (o.kind == IROperand::Imm) a.loadConst(rt, (uint64_t)o.imm);
        else throw std::runtime_error("IR arm64: bad operand in integer op");
    }
    // X9 = pointer value from slot, then X9 += off
    void addrOfPtr(int slotReg, int64_t off) {
        loadSlotTo(X9, slotReg, 0);
        addUpTo(a, X9, off);
    }

    void emitBin(const IRInstr& in) {
        loadOperandX(X10, in.b);
        loadOperandX(X11, in.c);
        switch (in.op) {
        case IROp::Add:  a.u32(encAddReg(X10, X10, X11)); break;
        case IROp::Sub:  a.u32(encSubReg(X10, X10, X11)); break;
        case IROp::And:  a.u32(encAndReg(X10, X10, X11)); break;
        case IROp::Or:   a.u32(encOrrReg(X10, X10, X11)); break;
        case IROp::Xor:  a.u32(encEorReg(X10, X10, X11)); break;
        case IROp::Mul:  a.u32(encMul(X10, X10, X11)); break;
        case IROp::IDiv: a.u32(encSdiv(X10, X10, X11)); break;
        case IROp::UDiv: a.u32(encUdiv(X10, X10, X11)); break;
        case IROp::IMod: a.u32(encSdiv(X9, X10, X11)); a.u32(encMsub(X10, X9, X11, X10)); break;
        case IROp::UMod: a.u32(encUdiv(X9, X10, X11)); a.u32(encMsub(X10, X9, X11, X10)); break;
        case IROp::Shl:  a.u32(encLsl(X10, X10, X11)); break;
        case IROp::Shr:  a.u32(encLsr(X10, X10, X11)); break;
        case IROp::Sar:  a.u32(encAsr(X10, X10, X11)); break;
        default: throw std::runtime_error("IR arm64: bad binary op");
        }
        storeSlotFrom(in.a.reg, 0, X10);
    }

    void emitInstr(const IRInstr& in) {
        switch (in.op) {
        case IROp::Nop:
        case IROp::Func:
        case IROp::EndFunc:
            return;

        case IROp::Label:
            a.label(in.a.label);
            return;

        case IROp::Const:
            a.loadConst(X10, (uint64_t)in.b.imm);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::FConst:
            throw std::runtime_error("IR arm64: float constants not supported");

        case IROp::Str:
            a.dataAddr(X9, true, in.b.strIdx, "", 0);
            storeSlotFrom(in.a.reg, 0, X9);
            return;
        case IROp::Mov:
            loadSlotTo(X10, in.b.reg, 0);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::LeaGlobal:
            a.dataAddr(X9, false, -1, in.b.name, 0);
            storeSlotFrom(in.a.reg, 0, X9);
            return;
        case IROp::LeaSlot:
            addrNew((int64_t)in.b.reg * 8 + in.b.off);
            storeSlotFrom(in.a.reg, 0, X9);
            return;

        case IROp::Load:
            loadSlotTo(X10, in.b.reg, in.label < 0 ? 0 : in.label);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Load32:
            addrNew((int64_t)in.b.reg * 8 + (in.label < 0 ? 0 : in.label));
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Store:
            loadSlotTo(X10, in.b.reg, 0);
            storeSlotFrom(in.a.reg, in.label < 0 ? 0 : in.label, X10);
            return;
        case IROp::Store32:
            loadSlotTo(X10, in.b.reg, 0);
            addrNew((int64_t)in.a.reg * 8 + (in.label < 0 ? 0 : in.label));
            a.u32(encStrW(X10, X9, 0));
            return;

        case IROp::GLoad:
            a.dataAddr(X9, false, -1, in.b.name, in.label < 0 ? 0 : in.label);
            a.u32(encLdrX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::GLoad32:
            a.dataAddr(X9, false, -1, in.b.name, in.label < 0 ? 0 : in.label);
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::GStore:
            loadSlotTo(X10, in.b.reg, 0);
            a.dataAddr(X9, false, -1, in.a.name, in.label < 0 ? 0 : in.label);
            a.u32(encStrX(X10, X9, 0));
            return;
        case IROp::GStore32:
            loadSlotTo(X10, in.b.reg, 0);
            a.dataAddr(X9, false, -1, in.a.name, in.label < 0 ? 0 : in.label);
            a.u32(encStrW(X10, X9, 0));
            return;

        case IROp::PLoad:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoad32:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoad32Z:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoadW:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrhW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoadB:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrbW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PStore:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrX(X10, X9, 0));
            return;
        case IROp::PStore32:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrW(X10, X9, 0));
            return;
        case IROp::PStoreW:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrhW(X10, X9, 0));
            return;
        case IROp::PStoreB:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrbW(X10, X9, 0));
            return;
        case IROp::FPStore:
            throw std::runtime_error("IR arm64: float stores not supported");

        case IROp::FLoad:
        case IROp::FStore:
        case IROp::FGLoad:
        case IROp::FGStore:
        case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
        case IROp::FMov: case IROp::FNeg: case IROp::I2F: case IROp::F2I:
            throw std::runtime_error("IR arm64: float operations not supported");

        case IROp::Arg:
            if (in.a.off != 0) throw std::runtime_error("IR arm64: float arguments not supported");
            pendingArgs.push_back(in.b.reg);
            return;

        case IROp::Call:
        case IROp::ICall: {
            if (in.a.off != 0) throw std::runtime_error("IR arm64: float call result not supported");
            std::string target = in.b.name;
            if (in.op == IROp::ICall) {
                if (target == "halt") target = "__zt_halt";
                else throw std::runtime_error("IR arm64: unsupported import '" + target + "'");
            }
            int nargs = (int)in.c.imm;
            if (nargs > 8) throw std::runtime_error("IR arm64: more than 8 arguments");
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++)
                loadSlotTo(X0 + k, pendingArgs[k], 0);
            a.bl(target);
            pendingArgs.clear();
            if (in.a.kind == IROperand::Reg) {
                a.u32(encMov(X10, X0));
                storeSlotFrom(in.a.reg, 0, X10);
            }
            return;
        }

        case IROp::PrintStr:
            if (in.a.kind == IROperand::StrIdx) {
                a.dataAddr(X0, true, in.a.strIdx, "", 0);
            } else if (in.a.kind == IROperand::Reg) {
                loadSlotTo(X0, in.a.reg, 0);
            } else throw std::runtime_error("IR arm64: bad PrintStr operand");
            a.bl("__z_print_string");
            return;
        case IROp::PrintInt:
            loadSlotTo(X0, in.a.reg, 0);
            a.bl("__z_print_int");
            return;
        case IROp::PrintFlt:
            throw std::runtime_error("IR arm64: float printing not supported");

        case IROp::Exit:
            a.bl("__zt_halt");
            return;

        case IROp::Ret: {
            if (in.a.off != 0) throw std::runtime_error("IR arm64: float return not supported");
            pendingArgs.clear();
            if (in.a.kind == IROperand::Reg) loadSlotTo(X0, in.a.reg, 0);
            a.u32(encLdrX(X30, XSP, (uint16_t)frameAligned));
            addUpTo(a, XSP, spAlloc);
            a.u32(encRet());
            return;
        }

        case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor:
        case IROp::Mul: case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
        case IROp::Shl: case IROp::Shr: case IROp::Sar:
            emitBin(in);
            return;

        case IROp::Neg:
            loadSlotTo(X10, in.b.reg, 0);
            a.u32(encNeg(X10, X10));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Not:
            loadSlotTo(X10, in.b.reg, 0);
            a.u32(encMvn(X10, X10));
            storeSlotFrom(in.a.reg, 0, X10);
            return;

        case IROp::Cmp: {
            if (in.a.off != 0) throw std::runtime_error("IR arm64: float compare not supported");
            loadOperandX(X10, in.b);
            loadOperandX(X11, in.c);
            a.u32(encCmpReg(X10, X11));
            int cc = ccForOp(in.cond);
            if (cc < 0) throw std::runtime_error("IR arm64: bad compare condition '" + in.cond + "'");
            a.u32(encCset(X10, (uint32_t)cc));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        }

        case IROp::Br:
            a.b(in.b.label);
            return;
        case IROp::BrZ:
            loadSlotTo(X10, in.a.reg, 0);
            a.cbz(X10, in.b.label);
            return;
        case IROp::BrNZ:
            loadSlotTo(X10, in.a.reg, 0);
            a.cbnz(X10, in.b.label);
            return;
        case IROp::BrCC: {
            if (in.a.off != 0) throw std::runtime_error("IR arm64: float branch not supported");
            loadOperandX(X10, in.a);
            loadOperandX(X11, in.b);
            a.u32(encCmpReg(X10, X11));
            int cc = ccForOp(in.cond);
            if (cc < 0) throw std::runtime_error("IR arm64: bad branch condition '" + in.cond + "'");
            a.bcc(cc, in.c.label);
            return;
        }

        default:
            throw std::runtime_error("IR arm64: unhandled IR op " + std::to_string((int)in.op));
        }
    }

    void emitBody() {
        // prologue: allocate frame, save LR
        addUpTo(a, XSP, -spAlloc);
        a.u32(encStrX(X30, XSP, (uint16_t)frameAligned));

        // copy incoming params (x0..x7) into their frame slots
        for (int v = 0; v < nparams; v++) {
            if (v > 7) continue;   // guarded earlier: nargs <= 8
            a.u32(encStrX(v, XSP, (uint16_t)(v * 8)));
        }

        for (auto& irin : fn.instrs) {
            if (irin.garbage) continue;
            emitInstr(irin);
        }

        // fall-off-the-end epilogue (unreachable, keeps the frame balanced)
        a.u32(encLdrX(X30, XSP, (uint16_t)frameAligned));
        addUpTo(a, XSP, spAlloc);
        a.u32(encRet());

        a.resolveBranches();
    }
};

// --------------------------------------------------------------------
// Runtime helpers (__z_putc / __z_puts / __z_print_string /
// __z_print_int / __zt_halt).  Only caller-saved registers are used.
// --------------------------------------------------------------------
static FnImg buildHelper(const std::string& name) {
    AsmBuf a;
    if (name == "__z_putc") {
        // x0 = char; waits for the TX FIFO, writes PL011 DR
        a.u32(encMovz(X9, 0, 0));
        a.u32(encMovk(X9, (uint16_t)(PL011_BASE >> 16), 1));
        a.u32(encMovz(X10, 0x20, 0));            // TXFF mask
        int L = 0;
        a.label(L);
        a.u32(encLdrW(X11, X9, PL011_FR));       // FR
        a.u32(encAndsW(XZR, X11, X10));          // TST
        a.bcc(1, L);                             // b.ne Lwait
        a.u32(encStrbW(X0, X9, PL011_DR));
        a.u32(encRet());
    } else if (name == "__z_puts") {
        // x0 = NUL-terminated string, no trailing newline
        a.u32(encSub(XSP, XSP, 16));
        a.u32(encStrX(X30, XSP, 0));               // save LR
        a.u32(encMov(X1, X0));
        int Lloop = 0, Ldone = 1;
        a.label(Lloop);
        a.u32(encLdrbWPost(X2, X1, 1));
        a.cbz(X2, Ldone);
        a.u32(encMov(X0, X2));
        a.bl("__z_putc");
        a.b(Lloop);
        a.label(Ldone);
        a.u32(encLdrX(X30, XSP, 0));
        a.u32(encAdd(XSP, XSP, 16));
        a.u32(encRet());
    } else if (name == "__z_print_string") {
        // x0 = string -> string + CRLF
        a.u32(encSub(XSP, XSP, 16));
        a.u32(encStrX(X30, XSP, 0));               // save LR
        a.bl("__z_puts");
        a.u32(encMovz(X0, 0x0D, 0));             // '\r'
        a.bl("__z_putc");
        a.u32(encMovz(X0, 0x0A, 0));             // '\n'
        a.bl("__z_putc");
        a.u32(encLdrX(X30, XSP, 0));
        a.u32(encAdd(XSP, XSP, 16));
        a.u32(encRet());
    } else if (name == "__z_print_int") {
        // x0 = signed 64-bit -> decimal digits + CRLF (stack buffer)
        a.u32(encSub(XSP, XSP, 48));             // scratch frame
        a.u32(encStrX(X30, XSP, 0));             // save LR
        a.u32(encStrX(X0, XSP, 8));              // save n
        a.u32(encMov(X3, X0));                   // x3 = n
        a.u32(encMovz(X10, 10, 0));              // x10 = 10
        a.u32(encAdd(X2, XSP, 40));              // x2 = buf+40 (end)
        a.u32(encMovz(X11, 0, 0));
        a.u32(encStrbW(X11, X2, 0));             // NUL terminator
        a.u32(encMovz(X5, 0, 0));                // sign = 0
        a.u32(encCmp(X3, 0));
        int Ldigits = 0, Lsign = 1;
        a.bcc(10, Ldigits);                      // b.ge Ldigits
        a.u32(encNeg(X3, X3));
        a.u32(encMovz(X5, 1, 0));
        a.label(Ldigits);
        a.u32(encSub(X2, X2, 1));
        a.u32(encUdiv(X4, X3, X10));             // q = n / 10
        a.u32(encMsub(X11, X4, X10, X3));        // r = n - q*10
        a.u32(encAdd(X11, X11, 0x30));           // '0'
        a.u32(encStrbW(X11, X2, 0));
        a.u32(encMov(X3, X4));
        a.cbnz(X3, Ldigits);
        a.cbz(X5, Lsign);
        a.u32(encSub(X2, X2, 1));
        a.u32(encMovz(X11, 0x2D, 0));            // '-'
        a.u32(encStrbW(X11, X2, 0));
        a.label(Lsign);
        a.u32(encMov(X0, X2));
        a.bl("__z_puts");
        a.u32(encMovz(X0, 0x0D, 0));
        a.bl("__z_putc");
        a.u32(encMovz(X0, 0x0A, 0));
        a.bl("__z_putc");
        a.u32(encLdrX(X30, XSP, 0));
        a.u32(encAdd(XSP, XSP, 48));
        a.u32(encRet());
    } else if (name == "__zt_halt") {
        a.u32(encB(0));                          // b .
    } else {
        throw std::runtime_error("IR arm64: unknown helper " + name);
    }
    a.resolveBranches();

    FnImg img;
    img.name = name;
    img.bytes.swap(a.c);
    img.bls.swap(a.bls);
    img.dfx.swap(a.dfx);
    return img;
}

} // namespace

// ====================================================================
// compile
// ====================================================================
bool IRAsmArm64::compile(const std::string& outputPath) {
    using std::vector;
    using std::string;
    using std::unordered_map;

    // ---- runtime helpers (placed before the user functions, indices 0..4) ----
    vector<FnImg> imgs;
    unordered_map<string, int> nameIdx;
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
        A64Fn em(f);
        em.emitBody();
        FnImg img;
        img.name = f.name;
        img.bytes.swap(em.a.c);
        img.bls.swap(em.a.bls);
        img.dfx.swap(em.a.dfx);
        nameIdx[f.name] = (int)imgs.size();
        imgs.push_back(std::move(img));
        if (f.name == ir_.entryFunc) entryIdx = (int)imgs.size() - 1;
    }

    if (entryIdx < 0) {
        std::cerr << "IR arm64: entry function '" << ir_.entryFunc << "' not found" << std::endl;
        return false;
    }

    // ---- data layout: globals, then the string pool ----
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
        strOff[(size_t)i] = poolBytes;
        poolBytes += (int)ir_.strings[i].size() + 1;
    }
    int dataBytes = poolBase + poolBytes;

    // ---- assemble the image ----
    vector<uint8_t> image;
    image.reserve(1 << 16);

    auto pushU32 = [&](uint32_t v) {
        image.push_back((uint8_t)(v & 0xFF));
        image.push_back((uint8_t)((v >> 8) & 0xFF));
        image.push_back((uint8_t)((v >> 16) & 0xFF));
        image.push_back((uint8_t)((v >> 24) & 0xFF));
    };

    // startup: set SP, branch to the entry function, spin
    int entryBlPos = -1;
    {
        // MOVZ/MOVK with Rd=31 write XZR (discarded), so load X0 first,
        // then "mov sp, x0" (ADD SP, X0, #0).
        pushU32(encMovz(X0, (uint16_t)(STACK_TOP & 0xFFFF), 0));
        pushU32(encMovk(X0, (uint16_t)((STACK_TOP >> 16) & 0xFFFF), 1));
        pushU32(encAdd(XSP, X0, 0));
        entryBlPos = (int)image.size();
        pushU32(encBl(0));
        pushU32(encB(0));   // b . (spin after entry returns)
    }

    vector<int> imgStart((size_t)imgs.size(), 0);
    for (size_t i = 0; i < imgs.size(); i++) {
        imgStart[i] = (int)image.size();
        image.insert(image.end(), imgs[i].bytes.begin(), imgs[i].bytes.end());
    }

    const int dataStart = (int)image.size();
    image.resize((size_t)dataStart + (size_t)dataBytes, 0);

    // globals
    {
        int off = 0;
        for (auto& g : ir_.globals) {
            if (!g.used) continue;
            off = (off + 7) & ~7;
            int at = dataStart + off;
            if (g.isString) {
                int idx = 0;
                while (idx < (int)ir_.strings.size() && ir_.strings[(size_t)idx] != g.strValue) idx++;
                uint64_t addr = IMAGE_BASE + (uint64_t)(dataStart + poolBase + strOff[(size_t)idx]);
                std::memcpy(image.data() + at, &addr, 8);
            } else if (g.isFloat) {
                float f = (float)g.floatValue;
                std::memcpy(image.data() + at, &f, 4);
            } else {
                int64_t v = g.intValue;
                std::memcpy(image.data() + at, &v, 8);
            }
            off += g.size >= 8 ? 8 : 4;
        }
    }
    // string pool
    for (size_t i = 0; i < ir_.strings.size(); i++) {
        int at = dataStart + poolBase + strOff[(size_t)i];
        std::memcpy(image.data() + at, ir_.strings[(size_t)i].data(), ir_.strings[(size_t)i].size());
        image[(size_t)at + ir_.strings[(size_t)i].size()] = 0;
    }

    // ---- resolve BL targets ----
    // startup -> entry
    {
        int targetAbs = imgStart[(size_t)entryIdx];
        int blAbs = entryBlPos;
        int32_t rel = (int32_t)(targetAbs - blAbs);
        int32_t imm26 = rel / 4;
        if (imm26 < -33554432 || imm26 > 33554431) {
            std::cerr << "IR arm64: entry call out of range" << std::endl;
            return false;
        }
        patchU32(image, blAbs, encBl((uint32_t)imm26));
    }
    // helpers / user functions
    for (size_t i = 0; i < imgs.size(); i++) {
        int base = imgStart[i];
        for (auto& bl : imgs[i].bls) {
            auto it = nameIdx.find(bl.target);
            if (it == nameIdx.end()) {
                std::cerr << "IR arm64: unknown callee '" << bl.target << "'" << std::endl;
                return false;
            }
            int targetAbs = imgStart[(size_t)it->second];
            int32_t rel = (int32_t)(targetAbs - (base + bl.pos));
            int32_t imm26 = rel / 4;
            if (imm26 < -33554432 || imm26 > 33554431) continue;   // never for small images
            patchU32(image, base + bl.pos, encBl((uint32_t)imm26));
        }
        for (auto& df : imgs[i].dfx) {
            uint64_t target = 0;
            if (df.isStr) {
                if (df.strIdx < 0 || df.strIdx >= (int)strOff.size())
                    target = IMAGE_BASE + (uint64_t)(dataStart + poolBase);
                else
                    target = IMAGE_BASE + (uint64_t)(dataStart + poolBase + strOff[(size_t)df.strIdx]);
            } else {
                // find the global offset
                int goff = -1;
                int acc = 0;
                for (auto& g : ir_.globals) {
                    if (!g.used) continue;
                    acc = (acc + 7) & ~7;
                    if (g.name == df.name) { goff = acc; break; }
                    acc += g.size >= 8 ? 8 : 4;
                }
                if (goff < 0) {
                    std::cerr << "IR arm64: unknown global '" << df.name << "'" << std::endl;
                    return false;
                }
                target = IMAGE_BASE + (uint64_t)(dataStart + goff);
            }
            target += (uint64_t)df.extra;
            int p = base + df.pos;
            patchU32(image, p,     encMovz(df.rt, (uint16_t)(target & 0xFFFF), 0));
            patchU32(image, p + 4, encMovk(df.rt, (uint16_t)((target >> 16) & 0xFFFF), 1));
        }
    }

    // ---- write the binary ----
    std::ofstream fout(outputPath, std::ios::binary);
    if (!fout) {
        std::cerr << "IR arm64: cannot write " << outputPath << std::endl;
        return false;
    }
    fout.write((const char*)image.data(), (std::streamsize)image.size());
    fout.close();

    return true;
}