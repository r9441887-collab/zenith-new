#pragma once
// ====================================================================
// asm_a64.h — shared AArch64 encoding layer
//
// The instruction encoders, the per-function code buffer (labels, BL
// fixups, absolute data addresses) and the inline-`asm` encoder live here
// so that every AArch64 lowering of the assembler-IR shares one set of
// encoders:
//
//   src/irasm_arm64.cpp   bare-metal "app arm64" (QEMU virt / Raspberry Pi)
//   src/irasm_android.cpp  "app android" (ELF64 + raw Linux syscalls)
//
// Everything is `inline` and header-only: these are pure functions over
// uint32_t words, and keeping them out of line would only add call
// overhead to the innermost loop of a compiler backend.
// ====================================================================
#include "ir.h"
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <stdexcept>

enum : int {
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12,
    X13, X14, X15, X16, X17, X18, X19, X20, X21,
    X30 = 30,
    XSP = 31, XZR = 31
};

// ---- AArch64 encoders (32-bit little-endian words) ----
inline uint32_t encMovz(int rd, uint16_t imm16, int hw) { return 0xD2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd; }
inline uint32_t encMovk(int rd, uint16_t imm16, int hw) { return 0xF2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd; }
// MOVN: the bitwise complement of a 16-bit immediate, i.e. a short way to
// write the constants that are mostly ones (0, -1, page masks).
inline uint32_t encMovn(int rd, uint16_t imm16, int hw, bool is64) { return (is64 ? 0x92800000u : 0x12800000u) | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd; }
inline uint32_t encMov(int rd, int rn)                  { return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd; }
// ADRP: a PC-relative page address, always followed by an ADD with the
// page's low 12 bits. The pair is position independent, which is what lets a
// data base live in a register instead of a baked-in absolute address.
// immhi/immlo are the 19/2-bit fields of the byte offset >> 12.
inline uint32_t encAdrp(int rd, uint32_t immhi, uint32_t immlo) {
    return 0x90000000u | ((immhi & 0x7FFFFu) << 5) | ((immlo & 3u) << 29) | (uint32_t)rd;
}
// ADD/SUB immediate with an optional 12-bit left shift (used for the low 12
// bits half of an ADRP pair).
inline uint32_t encAddShifted(int rd, int rn, uint16_t imm12, int shift, bool isSub) {
    return (isSub ? 0xD1000000u : 0x91000000u) | ((uint32_t)(shift & 3) << 22) |
           ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t encAdd(int rd, int rn, uint16_t imm12, int sh = 0) { return 0x91000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encSub(int rd, int rn, uint16_t imm12, int sh = 0) { return 0xD1000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encSubs(int rd, int rn, uint16_t imm12, int sh = 0) { return 0xF1000000u | ((uint32_t)(sh ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encCmp(int rn, uint16_t imm12)          { return encSubs(XZR, rn, imm12); }
inline uint32_t encCmpReg(int rn, int rm)               { return 0xEB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)XZR; }
inline uint32_t encAddReg(int rd, int rn, int rm)       { return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encSubReg(int rd, int rn, int rm)       { return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encAndReg(int rd, int rn, int rm)       { return 0x8A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encOrrReg(int rd, int rn, int rm)       { return 0xAA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encEorReg(int rd, int rn, int rm)       { return 0xCA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encMvn(int rd, int rm)                  { return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd; }
inline uint32_t encNeg(int rd, int rm)                  { return 0xCB0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd; }
inline uint32_t encLsl(int rd, int rn, int rm)          { return 0x9AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encLsr(int rd, int rn, int rm)          { return 0x9AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encAsr(int rd, int rn, int rm)          { return 0x9AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encMul(int rd, int rn, int rm)          { return 0x9B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encSdiv(int rd, int rn, int rm)         { return 0x9AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encUdiv(int rd, int rn, int rm)         { return 0x9AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encMsub(int rd, int rn, int rm, int ra) { return 0x9B008000u | ((uint32_t)rm << 16) | ((uint32_t)ra << 10) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encAndsW(int rd, int rn, int rm)        { return 0x6A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encLdrX(int rt, int rn, uint16_t off)   { return 0xF9400000u | (((uint32_t)(off / 8)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encStrX(int rt, int rn, uint16_t off)   { return 0xF9000000u | (((uint32_t)(off / 8)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encLdrW(int rt, int rn, uint16_t off)   { return 0xB9400000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encStrW(int rt, int rn, uint16_t off)   { return 0xB9000000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encLdrbW(int rt, int rn, uint16_t off)  { return 0x39400000u | ((uint32_t)off << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encStrbW(int rt, int rn, uint16_t off)  { return 0x39000000u | ((uint32_t)off << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encLdrbWPost(int rt, int rn, int imm9)  { return 0x38400400u | ((uint32_t)(imm9 & 0x1FF) << 12) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encLdrswX(int rt, int rn, uint16_t off) { return 0xB9800000u | (((uint32_t)(off / 4)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encLdrhW(int rt, int rn, uint16_t off)   { return 0x79400000u | (((uint32_t)(off / 2)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encStrhW(int rt, int rn, uint16_t off)   { return 0x79000000u | (((uint32_t)(off / 2)) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encB(uint32_t imm26)                    { return 0x14000000u | (imm26 & 0x03FFFFFFu); }
inline uint32_t encBl(uint32_t imm26)                   { return 0x94000000u | (imm26 & 0x03FFFFFFu); }
inline uint32_t encBlr(uint32_t rn)                     { return 0xD63F0000u | ((rn & 31u) << 5); }   // blr Xn
inline uint32_t encBcond(uint32_t cond, uint32_t imm19) { return 0x54000000u | (cond & 15) | ((imm19 & 0x7FFFFu) << 5); }
inline uint32_t encCbzx(int rt, uint32_t imm19)         { return 0xB4000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt; }
inline uint32_t encCbnzx(int rt, uint32_t imm19)        { return 0xB5000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt; }
// CSET Rd, cond: the assembler-only alias of CSINC Rd, XZR, XZR, invert(cond).
inline uint32_t encCset(int rd, uint32_t cond)          { return 0x9A9F07E0u | (((cond ^ 1) & 15) << 12) | (uint32_t)rd; }
inline uint32_t encRet()                                { return 0xD65F03C0u; }
// SVC #imm16: the immediate lives in bits 20:5, not in the low half.
inline uint32_t encSvc(int64_t imm16)                   { return 0xD4000001u | (((uint32_t)imm16 & 0xFFFF) << 5); }
// Pair load/store: one instruction for two registers, which is what makes a
// prologue/epilogue worth writing. `mode` is 0 = plain signed offset,
// 1 = pre-indexed (writeback, used to allocate a frame), 2 = post-indexed
// (writeback, used to release one). The displacement is in bytes and must be
// a multiple of 8 in [-512, 504] for 64-bit pairs, or of 4 in [-256, 252]
// for 32-bit ones (the encoding scales it differently).
enum : int { kPairOffset = 0, kPairPre = 1, kPairPost = 2 };
inline uint32_t encPair(int op, int rt1, int rt2, int rn, int32_t disp, int mode, bool isLoad, bool is64) {
    // The displacement is a 7-bit signed field scaled by the access size, so
    // [-512, 504] for a qword and [-256, 252] for a word. Refuse anything
    // larger instead of silently wrapping: a frame that does not fit has to be
    // allocated with SUB, not with a STP that lands somewhere else entirely.
    const int32_t step = is64 ? 8 : 4;
    if (disp % step != 0 || disp < -64 * step || disp > 63 * step)
        throw std::runtime_error("asm_a64: STP/LDP displacement out of range");
    static const uint32_t st[3] = { 0xA9000000u, 0xA9800000u, 0xA8C00000u };
    static const uint32_t ld[3] = { 0xA9400000u, 0xA9C00000u, 0xA8C00000u };
    static const uint32_t stW[3] = { 0x29000000u, 0x29800000u, 0x28800000u };
    static const uint32_t ldW[3] = { 0x29400000u, 0x29C00000u, 0x28C00000u };
    const uint32_t* tbl = isLoad ? (is64 ? ld : ldW) : (is64 ? st : stW);
    uint32_t imm7 = (uint32_t)((disp / step) & 0x7F);
    return tbl[mode & 3] | (imm7 << 15) | ((uint32_t)rt2 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt1;
}
inline uint32_t encStpX(int rt1, int rt2, int rn, int32_t disp, int mode) { return encPair(0, rt1, rt2, rn, disp, mode, false, true); }
inline uint32_t encLdpX(int rt1, int rt2, int rn, int32_t disp, int mode) { return encPair(0, rt1, rt2, rn, disp, mode, true, true); }

// ---- single-precision float (Zenith's `float` is f32) ----
inline uint32_t encLdrS(int rt, int rn, uint16_t off)  { return 0xBD400000u | ((uint32_t)(off / 4) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encStrS(int rt, int rn, uint16_t off)  { return 0xBD000000u | ((uint32_t)(off / 4) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt; }
inline uint32_t encFaddS(int rd, int rn, int rm)       { return 0x1E202800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFsubS(int rd, int rn, int rm)       { return 0x1E203800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFmulS(int rd, int rn, int rm)       { return 0x1E200800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFdivS(int rd, int rn, int rm)       { return 0x1E201800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFmovS(int rd, int rn)               { return 0x1E204000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFnegS(int rd, int rn)               { return 0x1E214000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
// FMOV Sd, Wn — a float constant is built by materialising its 32 bits as an
// integer first, so no float-immediate encoding is needed anywhere.
inline uint32_t encFmovFromW(int sd, int wn)            { return 0x1E270000u | ((uint32_t)wn << 5) | (uint32_t)sd; }
inline uint32_t encFmovToW(int wd, int sn)              { return 0x1E260000u | ((uint32_t)sn << 5) | (uint32_t)wd; }
// FCVT <Sd>, <Dn> — destination register first, as in the ISA manual.
inline uint32_t encFcvtSd(int sd, int dn)              { return 0x1E624000u | ((uint32_t)dn << 5) | (uint32_t)sd; }  // f64 -> f32
inline uint32_t encFcvtDs(int dd, int sn)              { return 0x1E22C000u | ((uint32_t)sn << 5) | (uint32_t)dd; }  // f32 -> f64
inline uint32_t encFmovFromX(int dd, int xn)            { return 0x9E670000u | ((uint32_t)xn << 5) | (uint32_t)dd; }   // f64 <- x64
inline uint32_t encFcvtzsD(int xd, int dn)             { return 0x9E780000u | ((uint32_t)dn << 5) | (uint32_t)xd; }   // x64 <- f64
inline uint32_t encScvtfS(int sd, int xn, bool is64)   { return (is64 ? 0x9E220000u : 0x1E220000u) | ((uint32_t)xn << 5) | (uint32_t)sd; }
inline uint32_t encUcvtfS(int sd, int xn, bool is64)   { return (is64 ? 0x9E230000u : 0x1E230000u) | ((uint32_t)xn << 5) | (uint32_t)sd; }
inline uint32_t encFcvtzsS(int xd, int sn, bool is64)  { return (is64 ? 0x9E380000u : 0x1E380000u) | ((uint32_t)sn << 5) | (uint32_t)xd; }
inline uint32_t encFcmpS(int rn, int rm)               { return 0x1E202000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5); }

// ---- double-precision float ----
// Printing needs the fractional part of a value, and the cheap way to get it
// is to stay in f64: scale by 1e6 there and subtract the integer part. Doing
// that in f32 would read the low half of every f64 constant instead.
inline uint32_t encFaddD(int rd, int rn, int rm)       { return 0x1E602800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFsubD(int rd, int rn, int rm)       { return 0x1E603800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFmulD(int rd, int rn, int rm)       { return 0x1E600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFdivD(int rd, int rn, int rm)       { return 0x1E601800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFmovD(int rd, int rn)               { return 0x1E604000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFnegD(int rd, int rn)               { return 0x1E614000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFabsD(int rd, int rn)               { return 0x1E60C000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
inline uint32_t encFcmpD(int rn, int rm)               { return 0x1E602000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5); }
inline uint32_t encScvtfD(int dd, int xn)               { return 0x9E620000u | ((uint32_t)xn << 5) | (uint32_t)dd; }

// signed compare conditions for *Cmp(BrCC) with cond ==
//   "==" "!=" "<" "<=" ">" ">=" "u<" "u<=" "u>" "u>="
inline int ccForOp(const std::string& op) {
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

inline void patchU32(std::vector<uint8_t>& buf, int pos, uint32_t v) {
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
inline void addUpTo(AsmBuf& a, int rd, int64_t imm) {
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

// --------------------------------------------------------------------
// inline-asm encoder (AArch64)
//
// Emits the parsed `asm { ... }` instructions for the QEMU "virt" ARM64
// target. Register names: x0..x30, sp, lr, xzr/zr. A small testable
// subset is supported; unsupported mnemonics warn and are skipped.
// Numbers may be decimal or 0x-hex. Memory operands [xn] / [xn, #imm].
// --------------------------------------------------------------------
struct AsmOpA64 { int type = 0; int reg = 0; int64_t imm = 0; };   // 1=reg 2=imm 3=mem

inline int asmRegA64(const std::string& s) {
    static const char* names[32] = {
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
        "x10","x11","x12","x13","x14","x15","x16","x17","x18","x19",
        "x20","x21","x22","x23","x24","x25","x26","x27","x28","x29",
        "x30","xzr"
    };
    static const char* wnames[32] = {
        "w0","w1","w2","w3","w4","w5","w6","w7","w8","w9",
        "w10","w11","w12","w13","w14","w15","w16","w17","w18","w19",
        "w20","w21","w22","w23","w24","w25","w26","w27","w28","w29",
        "w30","wzr"
    };
    for (int i = 0; i < 32; i++) if (s == names[i]) return i;
    for (int i = 0; i < 32; i++) if (s == wnames[i]) return i;
    if (s == "sp" || s == "xsp") return XSP;
    if (s == "lr") return X30;
    if (s == "zr" || s == "wzr") return 31;
    return -1;
}
inline AsmOpA64 parseAsmOpA64(const std::string& raw) {
    AsmOpA64 o;
    std::string s = raw;
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.empty()) return o;
    if (s[0] == '[') {
        o.type = 3;
        size_t close = s.find(']');
        std::string inner = (close != std::string::npos) ? s.substr(1, close - 1) : s.substr(1);
        std::string regPart, immPart;
        size_t comma = inner.find(',');
        regPart = (comma != std::string::npos) ? inner.substr(0, comma) : inner;
        immPart = (comma != std::string::npos) ? inner.substr(comma + 1) : "";
        while (!regPart.empty() && (regPart.front() == ' ' || regPart.front() == '\t')) regPart.erase(regPart.begin());
        while (!regPart.empty() && (regPart.back() == ' ' || regPart.back() == '\t')) regPart.pop_back();
        o.reg = asmRegA64(regPart);
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
    int ri = asmRegA64(s);
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

inline void encodeAsmA64(AsmBuf& a, const IRAsmBlock& blk) {
    for (auto& instr : blk.instrs) {
        std::string m = instr.mnemonic;
        for (auto& c : m) c = (char)tolower((unsigned char)c);
        AsmOpA64 o1 = parseAsmOpA64(instr.op1);
        AsmOpA64 o2 = parseAsmOpA64(instr.op2);

        if (m == "mov") {
            if (o1.type == 1 && o2.type == 1) { a.u32(encMov(o1.reg, o2.reg)); continue; }
            if (o1.type == 1 && o2.type == 2) { a.loadConst(o1.reg, (uint64_t)o2.imm); continue; }
            fprintf(stderr, "Warning: IR arm64 asm: bad mov, skipped\n");
            continue;
        }
        if (m == "mvn") { if (o1.type == 1 && o2.type == 1) a.u32(encMvn(o1.reg, o2.reg)); else fprintf(stderr, "Warning: IR arm64 asm: bad mvn\n"); continue; }
        if (m == "neg") { if (o1.type == 1 && o2.type == 1) a.u32(encNeg(o1.reg, o2.reg)); else fprintf(stderr, "Warning: IR arm64 asm: bad neg\n"); continue; }

        if (m == "add" || m == "sub") {
            bool isSub = (m == "sub");
            if (o1.type == 1 && o2.type == 1) {
                int rd = o1.reg, rn = o1.reg, rm = o1.reg;
                int r2 = parseAsmOpA64(instr.op3).reg;
                rm = r2 >= 0 ? r2 : o2.reg;
                if (isSub) a.u32(encSubReg(rd, o1.reg, rm));
                else       a.u32(encAddReg(rd, o1.reg, rm));
                continue;
            }
            if (o1.type == 1 && o2.type == 2) {
                uint64_t u = (uint64_t)o2.imm;
                int sh = 0;
                while (u) { uint16_t part = (uint16_t)(u & 0xFFF); if (part) { if (isSub) a.u32(encSub(o1.reg, o1.reg, part, sh)); else a.u32(encAdd(o1.reg, o1.reg, part, sh)); } u >>= 12; sh += 1; }
                continue;
            }
            fprintf(stderr, "Warning: IR arm64 asm: bad %s, skipped\n", m.c_str());
            continue;
        }

        if (m == "and" || m == "orr" || m == "eor" || m == "mul") {
            if (o1.type == 1 && o2.type == 1) {
                int rd = o1.reg, rn = o1.reg, rm = o2.reg;
                if (m == "and") a.u32(encAndReg(rd, rn, rm));
                else if (m == "orr") a.u32(encOrrReg(rd, rn, rm));
                else if (m == "eor") a.u32(encEorReg(rd, rn, rm));
                else a.u32(encMul(rd, rn, rm));
                continue;
            }
            fprintf(stderr, "Warning: IR arm64 asm: bad %s, skipped\n", m.c_str());
            continue;
        }

        if (m == "lsl" || m == "lsr" || m == "asr") {
            if (o1.type == 1 && o2.type == 1) {
                int rd = o1.reg, rn = o1.reg, rm = o2.reg;
                if (m == "lsr") a.u32(encLsr(rd, rn, rm));
                else if (m == "asr") a.u32(encAsr(rd, rn, rm));
                else a.u32(encLsl(rd, rn, rm));
                continue;
            }
            fprintf(stderr, "Warning: IR arm64 asm: bad shift, skipped\n");
            continue;
        }

        if (m == "cmp") {
            if (o1.type == 1 && o2.type == 1) { a.u32(encCmpReg(o1.reg, o2.reg)); continue; }
            if (o1.type == 1 && o2.type == 2) { a.u32(encCmp(o1.reg, (uint16_t)(o2.imm & 0xFFF))); continue; }
            fprintf(stderr, "Warning: IR arm64 asm: bad cmp, skipped\n");
            continue;
        }

        if (m == "ldr" && o1.type == 1 && o2.type == 3) {
            if (o2.imm >= 0 && (o2.imm & 7) == 0 && o2.imm / 8 <= 4095) a.u32(encLdrX(o1.reg, o2.reg, (uint16_t)o2.imm));
            else a.u32(encLdrX(o1.reg, o2.reg, 0));
            continue;
        }
        if (m == "str" && o1.type == 1 && o2.type == 3) {
            if (o2.imm >= 0 && (o2.imm & 7) == 0 && o2.imm / 8 <= 4095) a.u32(encStrX(o1.reg, o2.reg, (uint16_t)o2.imm));
            else a.u32(encStrX(o1.reg, o2.reg, 0));
            continue;
        }
        if (m == "ldrb" && o1.type == 1 && o2.type == 3) { a.u32(encLdrbW(o1.reg, o2.reg, (uint16_t)(o2.imm & 0xFFF))); continue; }
        if (m == "strb" && o1.type == 1 && o2.type == 3) { a.u32(encStrbW(o1.reg, o2.reg, (uint16_t)(o2.imm & 0xFFF))); continue; }

        if (m == "nop") { a.u32(0xD503201Fu); continue; }
        if (m == "ret") { a.u32(encRet()); continue; }

        fprintf(stderr, "Warning: IR arm64 asm: unsupported instruction '%s', skipped\n", m.c_str());
    }
}

