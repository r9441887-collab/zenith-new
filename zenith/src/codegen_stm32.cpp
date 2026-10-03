// codegen_stm32.cpp — ARM Cortex-M (Thumb/Thumb-2) backend for "app stm32"
// =========================================================================
// Produces a flat firmware image (vector table + code + string pool) that can
// be flashed to STM32 at 0x08000000 (ST-Link / QEMU). All code is emitted as
// compact 16-bit Thumb instructions where possible; 32-bit Thumb-2 only when
// required (see src\вот и вот.txt for the full size/RAM optimization list).
// print() on this target blinks the on-board LED (led_pin:) instead of
// printing to a screen.
#include "codegen.h"
#include "ast.h"
#include <fstream>
#include <iostream>
#include <cctype>
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
#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

static filesystem::path stm32Path(const string& s) {
#ifdef _WIN32
    int wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (wlen > 0) {
        wstring ws((size_t)wlen, L'\0');
        if (MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, ws.data(), wlen) == 0)
            return filesystem::path(s);
        ws.resize((size_t)wlen - 1);
        return filesystem::path(ws);
    }
    return filesystem::path(s);
#else
    return filesystem::path(s);
#endif
}

namespace {

constexpr uint32_t FLASH_BASE = 0x08000000u;
constexpr uint32_t SRAM_BASE  = 0x20000000u;
constexpr int SP_REG = 13, LR_REG = 14, PC_REG = 15;

static inline int popcnt(int mask) { return __builtin_popcount(mask & 0xFF); }

struct McuCfg {
    bool f4 = false;                 // false = STM32F1xx style GPIO registers
    int gpioEnableBitBase = 2;       // RCCEN port-A bit: F1=2 (APB2ENR), F4/F7=0 (AHB1ENR)
    uint32_t gpioA = 0x40010800u;    // GPIOA base (F1)
    uint32_t rccReg = 0x40021018u;   // APB2ENR (F1)
    uint32_t crlOff = 0x00u;         // pin 0..7 config (F1)
    uint32_t crhOff = 0x04u;         // pin 8..15 config (F1)
    uint32_t moderOff = 0x00u;       // mode register (F4)
    uint32_t odrOff = 0x0Cu;         // ODR offset (F1)
    uint32_t bsrrOff = 0x10u;        // BSRR offset (F1)
    uint32_t idrOff = 0x08u;         // IDR offset (F1)
    uint32_t sramSize = 20u * 1024u; // F103C8 = 20 KB
    uint32_t flashSize = 64u * 1024u; // F103C8 = 64 KB flash
    int uartLoopCycles = 4;          // cycles per UART delay-loop iteration (M0+=3, M3/M4/M7=4)
};

enum class McuFamily { F1, F4, F7, L4, G0 };

McuFamily mcuFamily(const string& mcu) {
    string m = mcu;
    transform(m.begin(), m.end(), m.begin(), ::tolower);
    if (m.find("stm32f4") == 0) return McuFamily::F4;
    if (m.find("stm32f7") == 0) return McuFamily::F7;
    if (m.find("stm32l4") == 0) return McuFamily::L4;
    if (m.find("stm32g0") == 0) return McuFamily::G0;
    return McuFamily::F1;
}

// Parse "PC13" / "PA5" / "C13" / "A5" into (port letter A.., pin 0..15).
bool parsePin(const string& s, int& port, int& pin) {
    size_t i = 0;
    if (i < s.size() && (s[i] == 'P' || s[i] == 'p')) i++;
    if (i >= s.size()) return false;
    char c = (char)toupper((unsigned char)s[i]);
    if (c < 'A' || c > 'H') return false;
    port = c - 'A';
    i++;
    if (i >= s.size() || !isdigit((unsigned char)s[i])) return false;
    pin = atoi(s.c_str() + (int)i);
    return pin >= 0 && pin <= 15;
}

struct LitRef {
    enum Kind { Const, Str, Func } kind = Const;
    uint32_t val = 0;
    int strIdx = -1;
    string func;
};

struct BrRef {
    int pos = 0;        // code position of the branch instruction
    int label = -1;
    bool cond = false;
    int cc = 0;         // condition code, -1 for uncond
    int idx = 0;        // emission index (stable across relaxation attempts)
};

} // namespace

// =========================================================================
// Backend state machine (per compileStm32() call)
// =========================================================================
namespace {

void u16pat(vector<uint8_t>& buf, int pos, uint16_t v) {
    if (pos < 0 || pos + 1 >= (int)buf.size()) return;
    buf[(size_t)pos] = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)(v >> 8);
}

struct Stm32 {
    Program& prog;
    explicit Stm32(Program& p) : prog(p) {}
    McuCfg cfg;
    uint32_t flashBase, sramBase, sramSize;

    vector<uint8_t> code;
    size_t funcStart = 0;

    // labels (per current function)
    vector<int> labelPositions;
    int nextLabel = 0;
    int newLabel() { return nextLabel++; }

    // literal pools (per current function)
    vector<LitRef> lits;
    unordered_map<uint64_t, int> litConstMap;   // key -> slot (for dedup)
struct LitFixup { int pos; int slot; int rt; };
    vector<LitFixup> litFixups;
    vector<pair<int,int>> strPatch;   // code pos of pool slot, string idx
    vector<pair<int,string>> funcPatch; // code pos of pool slot, func name
    int litSlot(uint32_t v) {
        auto it = litConstMap.find(v);
        if (it != litConstMap.end()) return it->second;
        LitRef lr; lr.kind = LitRef::Const; lr.val = v;
        lits.push_back(lr);
        int s = (int)lits.size() - 1;
        litConstMap[v] = s;
        return s;
    }
    int litSlotStr(int si) {
        for (int i = 0; i < (int)lits.size(); i++)
            if (lits[i].kind == LitRef::Str && lits[i].strIdx == si) return i;
        LitRef lr; lr.kind = LitRef::Str; lr.strIdx = si;
        lits.push_back(lr);
        return (int)lits.size() - 1;
    }
    int litSlotFunc(const string& f) {
        for (int i = 0; i < (int)lits.size(); i++)
            if (lits[i].kind == LitRef::Func && lits[i].func == f) return i;
        LitRef lr; lr.kind = LitRef::Func; lr.func = f;
        lits.push_back(lr);
        return (int)lits.size() - 1;
    }

    // branches of current function
    vector<BrRef> branches;

    // strings (dedup)
    vector<string> strings;
    int stringIdx(const string& s) {
        for (int i = 0; i < (int)strings.size(); i++)
            if (strings[i] == s) return i;
        strings.push_back(s);
        return (int)strings.size() - 1;
    }

    // globals
    struct GInfo { uint32_t addr; int size; Type type; };
    unordered_map<string, GInfo> globals;
    vector<string> globalOrder;

    // struct layouts (32-bit model)
    unordered_map<string, pair<int, unordered_map<string, pair<int, Type>>>> structs;
    int structSize(const string& name);
    int typeSize(const Type& t, int arraySize = 0);

    // frame info
    struct VarInfo32 { int off; Type type; bool isParam; int stmtFirst, stmtLast; bool used; };
    unordered_map<string, VarInfo32> vars;
    int frameSize = 0;
    int savedBytes = 0;          // bytes pushed in prologue ({lr} = 4 or 0)
    int prologueBytes = 0;   // bytes pushed in prologue (8 or 0)
    int tempBytes = 0;       // bytes of live temp pushes on the stack (above the frame)
    int startupSpinPos = 0;  // offset of the 'b .' spin loop inside the startup image

    bool hasCalls = false;

    // BL fixups (resolved after full layout)
    struct CallFix { int pos; string target; };
    vector<CallFix> callFixups;

    unordered_map<string, size_t> funcOffsets;
    vector<string> funcOrder;
    string entryName;

    // ---- assembly primitives ----
    void u8(uint8_t b) { code.push_back(b); }
    void u16(uint16_t w) { u8((uint8_t)(w & 0xFF)); u8((uint8_t)(w >> 8)); }
    void u32(uint32_t w) { u16((uint16_t)(w & 0xFFFF)); u16((uint16_t)(w >> 16)); }

    // 16-bit Thumb-1
    void movs(int rd, int rm)      { u16((uint16_t)(0x0000 | ((rm & 7) << 3) | (rd & 7))); }          // MOVS Rd,Rm (LSLS #0)
    void movs_imm(int rd, uint32_t v) { u16((uint16_t)(0x2000 | ((rd & 7) << 8) | (v & 0xFF))); }
    void movh(int rd, int rm)      { u16((uint16_t)(0x4600 | (((rd >> 3) & 1) << 7) | (((rm >> 3) & 1) << 6) | ((rm & 7) << 3) | (rd & 7))); }
    void adds(int rd, int rn, int rm) { u16((uint16_t)(0x1800 | ((rm & 7) << 6) | ((rn & 7) << 3) | (rd & 7))); }
    void subs(int rd, int rn, int rm) { u16((uint16_t)(0x1A00 | ((rm & 7) << 6) | ((rn & 7) << 3) | (rd & 7))); }
    void adds_imm8(int rd, uint32_t v) { u16((uint16_t)(0x3000 | ((rd & 7) << 8) | (v & 0xFF))); }
    void subs_imm8(int rd, uint32_t v) { u16((uint16_t)(0x3800 | ((rd & 7) << 8) | (v & 0xFF))); }
    void adds_imm3(int rd, int rn, uint32_t v) { u16((uint16_t)(0x1C00 | ((rn & 7) << 6) | ((rd & 7) << 3) | (v & 7))); }
    void subs_imm3(int rd, int rn, uint32_t v) { u16((uint16_t)(0x1E00 | ((rn & 7) << 6) | ((rd & 7) << 3) | (v & 7))); }
    void ands(int rd, int rm)      { u16((uint16_t)(0x4000 | ((rm & 7) << 3) | (rd & 7))); }
    void eors(int rd, int rm)      { u16((uint16_t)(0x4040 | ((rm & 7) << 3) | (rd & 7))); }
    void lsls_reg(int rd, int rm)  { u16((uint16_t)(0x4080 | ((rm & 7) << 3) | (rd & 7))); }
    void lsrs_reg(int rd, int rm)  { u16((uint16_t)(0x40C0 | ((rm & 7) << 3) | (rd & 7))); }
    void asrs_reg(int rd, int rm)  { u16((uint16_t)(0x4100 | ((rm & 7) << 3) | (rd & 7))); }
    void adcs(int rd, int rm)      { u16((uint16_t)(0x4140 | ((rm & 7) << 3) | (rd & 7))); }
    void sbcs(int rd, int rm)      { u16((uint16_t)(0x4180 | ((rm & 7) << 3) | (rd & 7))); }
    void rsbs(int rd, int rm)      { u16((uint16_t)(0x4240 | ((rm & 7) << 3) | (rd & 7))); }
    void cmps(int rn, int rm)      { u16((uint16_t)(0x4280 | ((rm & 7) << 3) | (rn & 7))); }
    void orrs(int rd, int rm)      { u16((uint16_t)(0x4300 | ((rm & 7) << 3) | (rd & 7))); }
    void muls(int rd, int rm)      { u16((uint16_t)(0x4340 | ((rm & 7) << 3) | (rd & 7))); }
    void bics(int rd, int rm)      { u16((uint16_t)(0x4380 | ((rm & 7) << 3) | (rd & 7))); }
    void mvns(int rd, int rm)      { u16((uint16_t)(0x43C0 | ((rm & 7) << 3) | (rd & 7))); }
    void lsls_imm(int rd, int rm, uint32_t imm) { u16((uint16_t)(0x0000 | ((imm & 31) << 6) | ((rm & 7) << 3) | (rd & 7))); }
    void lsrs_imm(int rd, int rm, uint32_t imm) { u16((uint16_t)(0x0800 | ((imm & 31) << 6) | ((rm & 7) << 3) | (rd & 7))); }
    void asrs_imm(int rd, int rm, uint32_t imm) { u16((uint16_t)(0x1000 | ((imm & 31) << 6) | ((rm & 7) << 3) | (rd & 7))); }
    void cmp_imm(int rn, uint32_t v) { u16((uint16_t)(0x2800 | ((rn & 7) << 8) | (v & 0xFF))); }
    void ldr_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x6800 | (((off / 4) & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void str_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x6000 | (((off / 4) & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void ldr_sp(int rt, uint32_t off) { u16((uint16_t)(0x9800 | ((rt & 7) << 8) | ((off / 4) & 0xFF))); }
    void str_sp(int rt, uint32_t off) { u16((uint16_t)(0x9000 | ((rt & 7) << 8) | ((off / 4) & 0xFF))); }
    void ldrb_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x7800 | ((off & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void strb_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x7000 | ((off & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void ldrh_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x8800 | (((off / 2) & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void strh_off(int rt, int rn, uint32_t off) { u16((uint16_t)(0x8000 | (((off / 2) & 31) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void ldr_reg(int rt, int rn, int rm) { u16((uint16_t)(0x5800 | ((rm & 7) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void str_reg(int rt, int rn, int rm) { u16((uint16_t)(0x5000 | ((rm & 7) << 6) | ((rn & 7) << 3) | (rt & 7))); }
    void push(int mask, bool lr) {
        if (!lr) tempBytes += 4 * popcnt(mask);
        u16((uint16_t)(0xB400 | (lr ? 0x100 : 0) | (mask & 0xFF)));
    }
    void pop(int mask, bool pc) {
        if (!pc) tempBytes -= 4 * popcnt(mask);
        u16((uint16_t)(0xBC00 | (pc ? 0x100 : 0) | (mask & 0xFF)));
    }
    void add_sp(uint32_t imm7) { u16((uint16_t)(0xB000 | (imm7 & 0x7F))); }       // ADD SP, #imm7*4
    void sub_sp(uint32_t imm7) { u16((uint16_t)(0xB080 | (imm7 & 0x7F))); }       // SUB SP, #imm7*4
    void add_sp_reg(int rd, uint32_t imm8) { u16((uint16_t)(0xA800 | ((rd & 7) << 8) | (imm8 & 0xFF))); } // ADD Rd, SP, #imm8*4
    void it(int cond) { u16((uint16_t)(0xBF00 | ((cond & 15) << 4) | 0x08)); }
    void ite(int cond) {
        // ITE (two-instruction IT block: first THEN, second ELSE/inverted).
        // Ground truth (QEMU disassembler): ITE = mask 0x4 (0b0100),
        //   ITT = 0xC (0b1100), IT = 0x8. Conditions follow T,E / T,T / T.
        u16((uint16_t)(0xBF00 | ((cond & 15) << 4) | 0x04u));
    }
    void bx(int rm) { u16((uint16_t)(0x4700 | ((rm & 15) << 3))); }
    void blx(int rm) { u16((uint16_t)(0x4780 | ((rm & 15) << 3))); }
void b_cc(int cc, int label) {
        int idx = brIndex++;
        int p = (int)code.size();
        u16((uint16_t)(0xD000 | ((cc & 15) << 8)));
        branches.push_back({p, label, true, cc, idx});
    }
    void b_imm(int label) {
        int idx = brIndex++;
        int p = (int)code.size();
        u16((uint16_t)0xE000);
        branches.push_back({p, label, false, -1, idx});
    }
    void nop() { u16(0xBF00); }

    // 32-bit Thumb-2
    void movw(int rd, uint32_t v) {
        // MOVW: halfword1 = 1111 0 i 10 0100 imm4 ; imm4 is the low 4 bits
        uint32_t i = (v >> 11) & 1, imm4 = (v >> 12) & 0xF, imm3 = (v >> 8) & 7, imm8 = v & 0xFF;
        u16((uint16_t)(0xF240 | (i << 10) | imm4));
        u16((uint16_t)((imm3 << 12) | ((rd & 15) << 8) | imm8));
    }
    void movt(int rd, uint32_t v) {
        uint32_t i = (v >> 11) & 1, imm4 = (v >> 12) & 0xF, imm3 = (v >> 8) & 7, imm8 = v & 0xFF;
        u16((uint16_t)(0xF2C0 | (i << 10) | imm4));
        u16((uint16_t)((imm3 << 12) | ((rd & 15) << 8) | imm8));
    }
    void add_w(int rd, int rn, uint32_t imm12) {
        uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
        u16((uint16_t)(0xF200 | (i << 10) | (rn & 15)));
        u16((uint16_t)((imm3 << 12) | ((rd & 15) << 8) | imm8));
    }
    void sub_w(int rd, int rn, uint32_t imm12) {
        uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
        u16((uint16_t)(0xF2A0 | (i << 10) | (rn & 15)));
        u16((uint16_t)((imm3 << 12) | ((rd & 15) << 8) | imm8));
    }
    void ldr_w(int rt, int rn, uint32_t imm12) {
        u16((uint16_t)(0xF8D0 | (rn & 15)));
        u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF)));
    }
void str_w(int rt, int rn, uint32_t imm12) {
        u16((uint16_t)(0xF8C0 | (rn & 15)));
        u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF)));
    }
    // Thumb-2 data-processing (register) — support high registers r8-r15
    void add_w_r(int rd, int rn, int rm) {   // ADD.W Rd,Rn,Rm
        u16((uint16_t)(0xEB00 | (rn & 15)));
        u16((uint16_t)((rm & 15) << 8 | (rd & 15)));
    }
    void sub_w_r(int rd, int rn, int rm) {   // SUB.W Rd,Rn,Rm
        u16((uint16_t)(0xEBA0 | (rn & 15)));
        u16((uint16_t)((rm & 15) << 8 | (rd & 15)));
    }
    void mul_w_r(int rd, int rn, int rm) {   // MUL.W Rd,Rn,Rm
        u16((uint16_t)(0xFB00 | (rn & 15)));
        u16((uint16_t)(0xF000 | ((rd & 15) << 8) | (rm & 15)));
    }
    void cmp_w_r(int rn, int rm) {   // CMP.W Rn,Rm (set flags)
        u16((uint16_t)(0xEBB0 | (rn & 15)));
        u16((uint16_t)(0x0F00 | (rm & 15)));
    }
    void and_w(int rd, int rn, int rm) { u16((uint16_t)(0xEA00 | (rn & 15))); u16((uint16_t)((rm & 15) << 8 | (rd & 15))); }
    void orr_w(int rd, int rn, int rm) { u16((uint16_t)(0xEA40 | (rn & 15))); u16((uint16_t)((rm & 15) << 8 | (rd & 15))); }
    void eor_w(int rd, int rn, int rm) { u16((uint16_t)(0xEA80 | (rn & 15))); u16((uint16_t)((rm & 15) << 8 | (rd & 15))); }
    void bic_w(int rd, int rn, int rm) { u16((uint16_t)(0xEA20 | (rn & 15))); u16((uint16_t)((rm & 15) << 8 | (rd & 15))); }
    void mvn_w(int rd, int rm) {
        u16(0xEA6F); // Rn = 15 (SP/ZR)
        u16((uint16_t)((rm & 15) << 8 | (rd & 15)));
    }
    void lsl_w(int rd, int rn, int rm) { u16((uint16_t)(0xFA00 | (rn & 15))); u16((uint16_t)(0xF000 | ((rd & 15) << 8) | (rm & 15))); }
    void lsr_w(int rd, int rn, int rm) { u16((uint16_t)(0xFA20 | (rn & 15))); u16((uint16_t)(0xF000 | ((rd & 15) << 8) | (rm & 15))); }
    void asr_w(int rd, int rn, int rm) { u16((uint16_t)(0xFA40 | (rn & 15))); u16((uint16_t)(0xF000 | ((rd & 15) << 8) | (rm & 15))); }
    // Thumb-2 loads/stores with signed extend / halfword / byte, any register
    void ldrb_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF890 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void strb_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF880 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void ldrh_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF8B0 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void strh_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF8A0 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void ldrsb_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF990 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void ldrsh_w(int rt, int rn, uint32_t imm12) { u16((uint16_t)(0xF9B0 | (rn & 15))); u16((uint16_t)(((rt & 15) << 12) | (imm12 & 0xFFF))); }
    void cmp_w_imm(int rn, uint32_t imm12) {  // CMP.W Rn,#imm12 (unsigned)
        uint32_t i = (imm12 >> 11) & 1, imm3 = (imm12 >> 8) & 7, imm8 = imm12 & 0xFF;
        u16((uint16_t)(0xF1B0 | (i << 10) | (rn & 15)));
        u16((uint16_t)((imm3 << 12) | (0xFu << 8) | imm8));
    }

    // BL with fixup (resolved after layout)
    void bl_fixup(const string& target) {
        int p = (int)code.size();
        u16(0xF000); u16(0xF000); // placeholder
        callFixups.push_back({p, target});
    }

    // Load 32-bit constant into rt via movw/movt or literal pool.
    void loadConst(int rt, uint32_t v) {
        if (rt < 8) {
            if (v <= 0xFF) { movs_imm(rt, v); return; }
            if ((v & 0xFFFFFF00u) == 0xFFFFFF00u) { // -1..-256
                movs_imm(rt, (uint32_t)(0u - v - 1u) & 0xFFu);
                mvns(rt, rt);
                return;
            }
            if (v <= 0xFFFF) { movw(rt, v); return; }
        }
        // literal pool
        int p = (int)code.size();
        int slot = litSlot(v);
u16((uint16_t)(0x4800 | ((rt & 7) << 8))); // LDR rt,[pc,#imm]
        litFixups.push_back({p, slot, rt});
    }
    void loadStrAddr(int rt, int si) {
        int p = (int)code.size();
        int slot = litSlotStr(si);
        u16((uint16_t)(0x4800 | ((rt & 7) << 8)));
        litFixups.push_back({p, slot, rt});
    }
    void loadFuncAddr(int rt, const string& f) {
        int p = (int)code.size();
        int slot = litSlotFunc(f);
        u16((uint16_t)(0x4800 | ((rt & 7) << 8)));
        litFixups.push_back({p, slot, rt});
    }

    void emitLabel(int label) {
        if (label >= (int)labelPositions.size()) labelPositions.resize(label + 1, -1);
        labelPositions[label] = (int)code.size();
    }

    // ---- higher level ----
    VarInfo32* var(const string& n) { auto it = vars.find(n); return it == vars.end() ? nullptr : &it->second; }
    GInfo* global(const string& n) { auto it = globals.find(n); return it == globals.end() ? nullptr : &it->second; }

    Type varType(const string& n);
    bool isFloatExpr(Expr* e);

    // stack/pool helpers
    void loadFromOff(int rt, int off);    // r0 = [sp+off]  (any offset)
    void storeToOff(int rt, int off);     // [sp+off] = rt
    void emitLoadVar(int rt, const string& n);
    void emitStoreVar(const string& n, int reg);
    int emitExpr(Expr* e);
    int emitCall(CallExpr* c);
    void emitStmt(Stmt* s, int* breakLabel, int* continueLabel, int* endLabel);
    void emitAsmInstr(const AsmInstr& instr);
    void emitBlock(const Block& b, int* breakLabel, int* continueLabel, int* endLabel);
    int emitCondJump(Expr* c, int label, bool jumpIfTrue);
    void emitSwitch(SwitchStmt* sw);
    void emitReturn(Expr* v, int endLabel, int retLabel);
    bool tryBuiltin(CallExpr* c);
    bool tryTailCall(CallExpr* c);

    // per-function state / helpers
    int  retLabel = -1;
    int  swCur = 0;
    int  swTempOff = 0;
    int  brIndex = 0;
    int  lastFlushPos = 0;
    std::set<string> runtimeNeeded;
    enum class PinMode { Input, Output, InputPullUp, OpenDrain };
    std::map<string, PinMode> gpioPins; // pins used by gpio_* builtins ("A5", "C13", ...)
    void registerPin(const string& p, PinMode m) { gpioPins[p] = m; }
    bool needRt(const string& n) { runtimeNeeded.insert(n); return true; }

    // chip family (assigned in compile() before any function is emitted)
    McuFamily fam = McuFamily::F1;
    bool adcSupported = true;    // F1/F4/F7 only for now
    bool uartConfigured = false; // uart_init() was called with a real baud
    bool rxConfigured = false;   // uart_rx_init() was called with a real baud
    bool mbConfigured = false;   // modbus_rtu_init() was called
    bool i2cConfigured = false;  // i2c_init() was called
    bool rtcAlarmUsed = false;   // rtc_alarm_set() used: wire F1 EXTI17 + NVIC + vector
    bool flInited = false;       // __z_fl_init already emitted into this function
    bool rtcInited = false;      // __z_rtc_init already emitted
    bool adcInited = false;      // __z_adc_init already emitted into this function
    bool systickUsed = false;    // micros/millis/delay_us used: enable SysTick ISR
    bool rngUsed = false;        // random() used: seed __z_rng once at startup
    // SysTick configuration (computed in compile() before any function is emitted)
    uint32_t systickLoadVal = 0;    // SYST_RVR reload value for a 1 kHz tick
    uint32_t systickPerUsVal = 0;   // ticks per microsecond at the SysTick clock
    uint32_t systickCtrlVal = 0x3u; // SYST_CSR value (ENABLE|TICKINT [+CLKSOURCE])
    void emitGlobalConst(const string& g, uint32_t v);
    void uartSetupPin(const string& pin, int64_t baud, bool force);
    void rxSetupPin(const string& pin, int64_t baud, bool force);
    void i2cSetup(const string& sda, const string& scl);
    int  adcChannel(const string& pin);

    void resetFn();
    bool scanExprCalls(Expr* e);
    bool scanStmtCalls(Stmt* s);
    bool usesCalls(FunctionDecl* f);
    void allocVarSlots(FunctionDecl* f);
    void subSpImm(int bytes);
    void addSpImm(int bytes);
    Type fieldTypeOf(const Type& t, const string& m);
    void emitAddrBase(const string& name);

    struct FnImg {
        string name;
        vector<uint8_t> bytes;
        vector<CallFix> bls;
        vector<pair<int, int>> strSlots;
        vector<pair<int, string>> funcSlots;
    };
    void finalizeFn(FnImg& out);
    vector<FnImg> userImgs;
    vector<FnImg> runtimeImgs;
    vector<uint8_t> tableBytes;
    vector<uint32_t> strOfs;   // string offsets within flash string pool

    // expression / memory helpers
    int emitBinInt(BinaryExpr* bin);
    int emitBinFloat(BinaryExpr* bin);
    Type typeOf(Expr* e);
    int  elementSize(const Type& t);
    int  fieldOffsetOf(const Type& t, const string& member);
    int  fieldOffset(Expr* obj, const string& member);
    void addImmR0(int32_t v);
    void scaleR0By(int n);
    void addSpAddr(int rd, int off);   // rd = SP + off (any positive off)
    void emitAddr(Expr* path);

    // per-function literal pool management
    void flushPool(bool guarded);
    void resolveBranches(const string& funcName);

    // emission entrypoints
    bool emitFunction(FunctionDecl* f, FnImg& out);
    void emitVectorTable(uint32_t resetAddr, uint32_t defHandler);
    void emitRuntime(const string& name);
    void emitStartup();
    void emitRtGpioInit();
    void emitRtGlobalInit();
    bool compile(const string& outputPath);
};

} // namespace

// =========================================================================
// Type / layout helpers
// =========================================================================
int Stm32::structSize(const string& name) {
    auto it = structs.find(name);
    return it == structs.end() ? 4 : it->second.first;
}

int Stm32::typeSize(const Type& t, int arraySize) {
    if (arraySize > 0) return arraySize * 4;
    switch (t.kind) {
        case TypeKind::Struct: return structSize(t.structName);
        default: return 4;
    }
}

Type Stm32::varType(const string& n) {
    auto v = var(n);
    if (v) return v->type;
    auto g = global(n);
    if (g) return g->type;
    return Type(TypeKind::Int);
}

bool Stm32::isFloatExpr(Expr* e) {
    if (dynamic_cast<FloatExpr*>(e)) return true;
    if (dynamic_cast<NumberExpr*>(e)) return false;
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        auto v = var(id->name);
        if (v) return v->type.kind == TypeKind::Float;
        auto g = global(id->name);
        if (g) return g->type.kind == TypeKind::Float;
        return false;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e)) {
        if (auto oid = dynamic_cast<IdentExpr*>(m->object.get())) {
            Type bt = varType(oid->name);
            if (bt.kind == TypeKind::Struct) {
                auto it = structs.find(bt.structName);
                if (it != structs.end()) {
                    auto f = it->second.second.find(m->member);
                    if (f != it->second.second.end()) return f->second.second.kind == TypeKind::Float;
                }
            }
        }
        return false;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) return isFloatExpr(b->left.get()) || isFloatExpr(b->right.get());
    if (auto u = dynamic_cast<UnaryExpr*>(e)) return isFloatExpr(u->operand.get());
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) return isFloatExpr(a->array.get());
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        for (auto& f : prog.functions) {
            if (f->name == c->name && !f->isExtern) return f->returnType.kind == TypeKind::Float;
        }
    }
    return false;
}

// =========================================================================
// Stack / memory access
// =========================================================================
void Stm32::loadFromOff(int rt, int off) {
    int o = off + tempBytes;
    if (o >= 0 && o <= 1020 && o % 4 == 0) ldr_sp(rt, (uint32_t)o);
    else if (o >= 0 && o <= 4095) ldr_w(rt, SP_REG, (uint32_t)o);
    else { addSpAddr(rt, o); ldr_off(rt, rt, 0); }
}
void Stm32::storeToOff(int rt, int off) {
    int o = off + tempBytes;
    if (o >= 0 && o <= 1020 && o % 4 == 0) str_sp(rt, (uint32_t)o);
    else if (o >= 0 && o <= 4095) str_w(rt, SP_REG, (uint32_t)o);
    else {
        // address computation must not clobber the value in rt
        int scratch = (rt == 0) ? 1 : 0;
        addSpAddr(scratch, o);
        str_off(rt, scratch, 0);
    }
}

void Stm32::emitLoadVar(int rt, const string& n) {
    auto v = var(n);
    if (v) { loadFromOff(rt, v->off); return; }
    auto g = global(n);
    if (g) { loadConst(1, g->addr); ldr_off(rt, 1, 0); return; }
    // function reference (address)
    if (funcOffsets.count(n)) { loadFuncAddr(rt, n); return; }
    cerr << "stm32: undefined variable '" << n << "'\n";
    movs_imm(rt, 0);
}
void Stm32::emitStoreVar(const string& n, int reg) {
    auto v = var(n);
    if (v) { storeToOff(reg, v->off); return; }
    auto g = global(n);
    if (g) { loadConst(1, g->addr); str_off(reg, 1, 0); return; }
    cerr << "stm32: undefined variable '" << n << "'\n";
}

// =========================================================================
// UART / ADC helpers (commercial-builtin support)
// =========================================================================
// Stores a compile-time constant into an internal SRAM global.
void Stm32::emitGlobalConst(const string& g, uint32_t v) {
    auto gi = global(g);
    if (!gi) return;
    loadConst(0, v);
    loadConst(1, gi->addr);
    str_off(0, 1, 0);
}

// Registers the TX pin and (on first use, unless forced) writes the UART
// bit-bang config globals: BSRR register address, pin bitmask, half-bit
// delay-loop count = sysclk / (2 * baud * uartLoopCycles).
void Stm32::uartSetupPin(const string& pin, int64_t baud, bool force) {
    int port = 0, p = 0;
    if (!parsePin(pin, port, p)) { cerr << "stm32: bad uart pin '" << pin << "'\n"; return; }
    registerPin(pin, PinMode::Output);
    if (uartConfigured && !force) return;
    if (baud <= 0) baud = 9600;
    if (baud < 300) baud = 300;
    uint32_t bsrrAddr = cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff;
    emitGlobalConst("__z_uart_bsrr", bsrrAddr);
    emitGlobalConst("__z_uart_bit", 1u << p);
    uint32_t half = prog.sysclkHz / (2u * (uint32_t)baud * (uint32_t)cfg.uartLoopCycles);
    if (half < 1) half = 1;
    if (half > 0xFFFF) half = 0xFFFF;
    emitGlobalConst("__z_uart_half", half);
    uartConfigured = true;
}

// Registers the RX pin (input with pull-up) and writes the polled-RX config
// globals: IDR register address, pin bitmask, half-bit delay-loop count.
void Stm32::rxSetupPin(const string& pin, int64_t baud, bool force) {
    int port = 0, p = 0;
    if (!parsePin(pin, port, p)) { cerr << "stm32: bad uart rx pin '" << pin << "'\n"; return; }
    registerPin(pin, PinMode::InputPullUp);
    if (rxConfigured && !force) return;
    if (baud <= 0) baud = 9600;
    if (baud < 300) baud = 300;
    uint32_t idrAddr = cfg.gpioA + (uint32_t)port * 0x400u + cfg.idrOff;
    emitGlobalConst("__z_uart_rx_idr", idrAddr);
    emitGlobalConst("__z_uart_rx_bit", 1u << p);
    uint32_t half = prog.sysclkHz / (2u * (uint32_t)baud * (uint32_t)cfg.uartLoopCycles);
    if (half < 1) half = 1;
    if (half > 0xFFFF) half = 0xFFFF;
    emitGlobalConst("__z_uart_rx_half", half);
    rxConfigured = true;
}

// Registers the I2C SDA/SCL pins as open-drain outputs and writes the
// bit-bang config globals (per-pin BSRR/IDR addresses + half-period delay).
void Stm32::i2cSetup(const string& sda, const string& scl) {
    int port = 0, p = 0;
    if (!parsePin(sda, port, p)) { cerr << "stm32: bad i2c sda pin '" << sda << "'\n"; return; }
    registerPin(sda, PinMode::OpenDrain);
    int sport = port, sp = p;
    if (!parsePin(scl, port, p)) { cerr << "stm32: bad i2c scl pin '" << scl << "'\n"; return; }
    registerPin(scl, PinMode::OpenDrain);
    if (i2cConfigured) return;
    emitGlobalConst("__z_i2c_sda_bsrr", cfg.gpioA + (uint32_t)sport * 0x400u + cfg.bsrrOff);
    emitGlobalConst("__z_i2c_sda_bit",  1u << sp);
    emitGlobalConst("__z_i2c_sda_idr",  cfg.gpioA + (uint32_t)sport * 0x400u + cfg.idrOff);
    emitGlobalConst("__z_i2c_scl_bsrr", cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff);
    emitGlobalConst("__z_i2c_scl_bit",  1u << p);
    emitGlobalConst("__z_i2c_scl_idr",  cfg.gpioA + (uint32_t)port * 0x400u + cfg.idrOff);
    uint32_t half = prog.sysclkHz / (200000u * (uint32_t)cfg.uartLoopCycles); // 100 kHz
    if (half < 1) half = 1;
    if (half > 0xFFFF) half = 0xFFFF;
    emitGlobalConst("__z_i2c_half", half);
    i2cConfigured = true;
}

// Maps an analog-capable pin to its ADC channel (F1/F4/F7 share the map):
//   PA0..PA7 -> IN0..IN7, PB0/PB1 -> IN8/IN9, PC0..PC5 -> IN10..IN15.
int Stm32::adcChannel(const string& pin) {
    int port = 0, p = 0;
    if (!parsePin(pin, port, p)) return -1;
    if (port == 0 && p <= 7) return p;
    if (port == 1 && p <= 1) return 8 + p;
    if (port == 2 && p <= 5) return 10 + p;
    return -1;
}

// =========================================================================
// Integer binary operations
// =========================================================================
static int invCc(int cc) {
    switch (cc) {
        case 0: return 1;   // eq <-> ne
        case 1: return 0;
        case 10: return 11; // lt <-> ge
        case 11: return 10;
        case 12: return 13; // gt <-> le
        case 13: return 12;
        case 2: return 3;   // cs <-> cc
        case 3: return 2;
        default: return cc;
    }
}

// ARM condition codes for the comparison operators (flags from CMP left,right).
static int ccForOp(const string& op) {
    if (op == "==") return 0;   // EQ
    if (op == "!=") return 1;   // NE
    if (op == "<")  return 11;  // LT
    if (op == "<=") return 13;  // LE
    if (op == ">")  return 12;  // GT
    if (op == ">=") return 10;  // GE
    return -1;
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

// Emits r0 = r0 op r1 (r0=right, r1=left for non-commutative handled here)
int Stm32::emitBinInt(BinaryExpr* bin) {
    const string& op = bin->op;
    int64_t rconst = 0; bool rIsConst = getIntConst(bin->right.get(), rconst);

    if (op == "+" && rIsConst) {
        emitExpr(bin->left.get());
        if (rconst >= 0 && rconst <= 255) { adds_imm8(0, (uint32_t)rconst); return 0; }
        if (rconst > 255 && rconst <= 4095) { add_w(0, 0, (uint32_t)rconst); return 0; }
        if (rconst < 0 && rconst >= -255) { subs_imm8(0, (uint32_t)(-rconst)); return 0; }
        if (rconst < -255 && rconst >= -4095) { sub_w(0, 0, (uint32_t)(-rconst)); return 0; }
    }
    if (op == "-" && rIsConst) {
        emitExpr(bin->left.get());
        if (rconst >= 0 && rconst <= 255) { subs_imm8(0, (uint32_t)rconst); return 0; }
        if (rconst > 255 && rconst <= 4095) { sub_w(0, 0, (uint32_t)rconst); return 0; }
        if (rconst < 0 && rconst >= -255) { adds_imm8(0, (uint32_t)(-rconst)); return 0; }
        if (rconst < -255 && rconst >= -4095) { add_w(0, 0, (uint32_t)(-rconst)); return 0; }
    }
    // E1: multiply by a power of two -> single LSLS (2 bytes), no MULS.
    if (op == "*" && rIsConst && rconst > 0) {
        int64_t v = rconst;
        for (int sh = 0; sh <= 31; sh++) {
            if (v == (int64_t)1 << sh) {
                emitExpr(bin->left.get());
                if (sh == 0) return 0;
                lsls_imm(0, 0, (uint32_t)sh);
                return 0;
            }
        }
    }
    // left const, right not: for commutative ops evaluate right then add const.
    // Every path below must return: falling through would re-evaluate the right
    // operand (and double-execute any call on the right side).
    int64_t lconst; bool lIsConst = getIntConst(bin->left.get(), lconst);
    if (lIsConst && !rIsConst) {
        if (op == "+") {
            emitExpr(bin->right.get());
            if (lconst >= 0 && lconst <= 255) { adds_imm8(0, (uint32_t)lconst); return 0; }
            if (lconst > 255 && lconst <= 4095) { add_w(0, 0, (uint32_t)lconst); return 0; }
            if (lconst < 0 && lconst >= -255) { subs_imm8(0, (uint32_t)(-lconst)); return 0; }
            if (lconst < -255 && lconst >= -4095) { sub_w(0, 0, (uint32_t)(-lconst)); return 0; }
            loadConst(1, (uint32_t)(int32_t)lconst);
            adds(0, 0, 1);
            return 0;
        }
        if (op == "*" || op == "&" || op == "|" || op == "^") {
            emitExpr(bin->right.get());
            loadConst(1, (uint32_t)(int32_t)lconst);
            if (op == "*") { muls(0, 1); return 0; }
            if (op == "&") { ands(0, 1); return 0; }
            if (op == "|") { orrs(0, 1); return 0; }
            if (op == "^") { eors(0, 1); return 0; }
        }
    }

    // generic: left -> r0 (push), right -> r0, pop r1 = left
    emitExpr(bin->left.get());
    push(0x01, false);
    emitExpr(bin->right.get());
    pop(0x02, false); // r1 = left; r0 = right

    if (op == "+") { adds(0, 1, 0); return 0; }
    if (op == "-") { subs(0, 1, 0); return 0; }
    if (op == "*") { muls(0, 1); return 0; }
    if (op == "&") { ands(0, 1); return 0; }
    if (op == "|") { orrs(0, 1); return 0; }
    if (op == "^") { eors(0, 1); return 0; }
    if (op == "<<") { lsls_reg(1, 0); movs(0, 1); return 0; }
    if (op == ">>") { lsrs_reg(1, 0); movs(0, 1); return 0; }
    if (op == "/" || op == "%" || op == "//") {
        // r1=left, r0=right -> runtime signed div/mod (r0=num, r1=den)
        movs(2, 0);
        movs(0, 1);
        movs(1, 2);
        bl_fixup(op == "/" ? "__z_div" : "__z_mod");
        hasCalls = true;
        return 0;
    }
    if (op == "%of") {
        // r1=percent, r0=base -> (percent * base) / 100 (r0=num, r1=den)
        muls(0, 1);            // r0 = percent * base
        loadConst(1, 100);     // r1 = 100 (den)
        bl_fixup("__z_div");
        hasCalls = true;
        return 0;
    }

    // comparisons (value 0/1) : cmp left,right
    cmps(1, 0);
    int cc = 0;
    if (op == "==") cc = 0;
    else if (op == "!=") cc = 1;
    else if (op == "<") cc = 11;
    else if (op == "<=") cc = 13;
    else if (op == ">") cc = 12;
    else if (op == ">=") cc = 10;
    ite(cc);
    movs_imm(0, 1);
    movs_imm(0, 0);
    return 0;
}

// =========================================================================
// Float (soft-float) binary operations
// =========================================================================
int Stm32::emitBinFloat(BinaryExpr* bin) {
    const string& op = bin->op;
    // evaluate left -> float in r0; push; right -> float r0
    emitExpr(bin->left.get());
    if (!isFloatExpr(bin->left.get())) bl_fixup("__z_i2f");
    push(0x01, false);
    emitExpr(bin->right.get());
    if (!isFloatExpr(bin->right.get())) bl_fixup("__z_i2f");
    pop(0x02, false);  // r1 = left(float), r0 = right(float)
    // args for helpers: r0=left, r1=right
    movs(2, 0);
    movs(0, 1);
    movs(1, 2);
    string h;
    if (op == "+") h = "__z_fadd";
    else if (op == "-") h = "__z_fsub";
    else if (op == "*" || op == "/") {
        cerr << "stm32: Q16.16 '*' and '/' are disabled (broken math); "
                "use + - comparisons or int arithmetic\n";
        return 0;
    }
    else if (op == "==") h = "__z_fcmp";
    else if (op == "!=") h = "__z_fcmp";
    else if (op == "<") h = "__z_fcmp";
    else if (op == "<=") h = "__z_fcmp";
    else if (op == ">") h = "__z_fcmp";
    else if (op == ">=") h = "__z_fcmp";
    else { cerr << "stm32: unsupported float op '" << op << "'\n"; return 0; }
bl_fixup(h);
    if (op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=") {
        // __z_fcmp returns r0 = -1/0/1 -> normalize to a boolean 0/1
        int cc;
        if (op == "==") cc = 0;       // EQ
        else if (op == "!=") cc = 1;  // NE
        else if (op == "<") cc = 4;   // MI (negative)
        else if (op == "<=") cc = 13; // LE
        else if (op == ">") cc = 12;  // GT
        else cc = 10;                 // GE
        cmp_imm(0, 0);
        ite(cc);
        movs_imm(0, 1);
        movs_imm(0, 0);
    }
    return 0;
}
// =========================================================================
// Type helpers
// =========================================================================
Type Stm32::typeOf(Expr* e) {
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
    if (dynamic_cast<DerefExpr*>(e)) return Type(TypeKind::Int);
    if (auto c = dynamic_cast<CallExpr*>(e))
        for (auto& f : prog.functions)
            if (f->name == c->name && !f->isExtern) return f->returnType;
    return Type(TypeKind::Int);
}

int Stm32::elementSize(const Type& t) {
    return t.kind == TypeKind::Struct ? structSize(t.structName) : 4;
}

int Stm32::fieldOffsetOf(const Type& t, const string& member) {
    if (t.kind == TypeKind::Struct) {
        auto it = structs.find(t.structName);
        if (it != structs.end()) {
            auto f = it->second.second.find(member);
            if (f != it->second.second.end()) return f->second.first;
        }
    }
    cerr << "stm32: unknown field '" << member << "'\n";
    return 0;
}

int Stm32::fieldOffset(Expr* obj, const string& member) {
    return fieldOffsetOf(typeOf(obj), member);
}

// =========================================================================
// Small address arithmetic (r0 in/out)
// =========================================================================
void Stm32::addImmR0(int32_t v) {
    if (v == 0) return;
    if (v > 0 && v <= 255) { adds_imm8(0, (uint32_t)v); return; }
    if (v > 0 && v <= 4095) { add_w(0, 0, (uint32_t)v); return; }
    if (v < 0 && v >= -255) { subs_imm8(0, (uint32_t)(-v)); return; }
    if (v < 0 && v >= -4095) { sub_w(0, 0, (uint32_t)(-v)); return; }
    loadConst(1, (uint32_t)v);
    adds(0, 0, 1);
}

void Stm32::scaleR0By(int n) {
    if (n == 1) return;
    if (n == 2) { lsls_imm(0, 0, 1); return; }
    if (n == 4) { lsls_imm(0, 0, 2); return; }
    if (n == 8) { lsls_imm(0, 0, 3); return; }
    loadConst(1, (uint32_t)n);
    muls(0, 1);
}

// rd = SP + off. ADD.W imm12 covers only 0..4095, so larger frames are added in
// chunks (a local array bigger than ~1K words would otherwise get a truncated
// immediate and silently read/write the wrong address).
void Stm32::addSpAddr(int rd, int off) {
    if (off <= 4095) { add_w(rd, SP_REG, (uint32_t)off); return; }
    uint32_t rem = (uint32_t)off;
    uint32_t s = std::min(rem, 4095u);
    add_w(rd, SP_REG, s);
    rem -= s;
    while (rem > 0) {
        s = std::min(rem, 4095u);
        add_w(rd, rd, s);
        rem -= s;
    }
}

// Compute the effective address of a "path" expression into r0.
void Stm32::emitAddr(Expr* path) {
    if (auto id = dynamic_cast<IdentExpr*>(path)) {
        if (auto v = var(id->name)) {
            int o = v->off + tempBytes;
            if (o >= 0 && (o & 3) == 0 && o <= 1020) add_sp_reg(0, (uint32_t)(o >> 2));
            else addSpAddr(0, o);
            return;
        }
        auto g = global(id->name);
        if (g) { loadConst(0, g->addr); return; }
        if (funcOffsets.count(id->name)) { loadFuncAddr(0, id->name); return; }
        cerr << "stm32: undefined variable '" << id->name << "'\n";
        movs_imm(0, 0);
        return;
    }
    if (auto aof = dynamic_cast<AddressOfExpr*>(path)) {
        auto v = var(aof->name);
        if (v) {
            int o = v->off + tempBytes;
            if (o >= 0 && (o & 3) == 0 && o <= 1020) add_sp_reg(0, (uint32_t)(o >> 2));
            else addSpAddr(0, o);
            return;
        }
        auto g = global(aof->name);
        if (g) { loadConst(0, g->addr); return; }
        if (funcOffsets.count(aof->name)) { loadFuncAddr(0, aof->name); return; }
        cerr << "stm32: undefined variable '" << aof->name << "'\n";
        movs_imm(0, 0);
        return;
    }
    if (auto mem = dynamic_cast<MemberExpr*>(path)) {
        emitAddr(mem->object.get());
        addImmR0(fieldOffset(mem->object.get(), mem->member));
        return;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(path)) {
        int elem = elementSize(typeOf(arr->array.get()));
        emitAddr(arr->array.get());
        int64_t ci;
        if (getIntConst(arr->index.get(), ci)) {
            addImmR0((int32_t)(ci * elem));
        } else {
            push(0x01, false);
            emitExpr(arr->index.get());
            scaleR0By(elem);
            pop(0x02, false);
            adds(0, 1, 0);
        }
        return;
    }
    if (auto d = dynamic_cast<DerefExpr*>(path)) {
        emitExpr(d->ptr.get());
        return;
    }
    cerr << "stm32: unhandled address expression\n";
    movs_imm(0, 0);
}

// =========================================================================
// Expression dispatch
// =========================================================================
int Stm32::emitExpr(Expr* e) {
    if (!e) {
        movs_imm(0, 0);
        return 0;
    }
    if (auto n = dynamic_cast<NumberExpr*>(e)) {
        loadConst(0, (uint32_t)(int32_t)n->value);
        return 0;
    }
if (auto f = dynamic_cast<FloatExpr*>(e)) {
        float fl = (float)f->value;
        loadConst(0, (uint32_t)(int64_t)(fl * 65536.0f)); // Q16.16 soft-float
        return 0;
    }
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        loadStrAddr(0, stringIdx(s->value));
        return 0;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (var(id->name) || global(id->name)) { emitLoadVar(0, id->name); return 0; }
        if (funcOffsets.count(id->name)) { loadFuncAddr(0, id->name); return 0; }
        cerr << "stm32: undefined variable '" << id->name << "'\n";
        movs_imm(0, 0);
        return 0;
    }
    if (dynamic_cast<AddressOfExpr*>(e)) {
        emitAddr(e);
        return 0;
    }
    if (auto der = dynamic_cast<DerefExpr*>(e)) {
        emitExpr(der->ptr.get());
        ldr_off(0, 0, 0);
        return 0;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        if (u->op == "!") {
            emitExpr(u->operand.get());
            cmp_imm(0, 0);
            ite(0);
            movs_imm(0, 1);
            movs_imm(0, 0);
            return 0;
        }
        if (u->op == "~") {
            emitExpr(u->operand.get());
            mvns(0, 0);
            return 0;
        }
if (u->op == "-") {
            emitExpr(u->operand.get());
            rsbs(0, 0); // Q16.16 negation is plain two's-complement
            return 0;
        }
        cerr << "stm32: unsupported unary '" << u->op << "'\n";
        movs_imm(0, 0);
        return 0;
    }
    if (auto mem = dynamic_cast<MemberExpr*>(e)) {
        // C3: "s.field" of a local struct is read with a single SP-relative
        // LDR (merged var offset + field offset) instead of computing an
        // address first.
        if (auto oid = dynamic_cast<IdentExpr*>(mem->object.get())) {
            if (auto v = var(oid->name)) {
                int total = v->off + fieldOffsetOf(v->type, mem->member);
                int o = total + tempBytes;
                if (o >= 0 && o <= 1020 && (o & 3) == 0) {
                    ldr_sp(0, (uint32_t)o);
                    return 0;
                }
            } else if (auto g = global(oid->name)) {
                loadConst(1, g->addr);
                ldr_off(0, 1, (uint32_t)fieldOffsetOf(g->type, mem->member));
                return 0;
            }
        }
        emitAddr(mem->object.get());
        addImmR0(fieldOffset(mem->object.get(), mem->member));
        ldr_off(0, 0, 0);
        return 0;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        emitAddr(arr);
        ldr_off(0, 0, 0);
        return 0;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        emitCall(c);
        return 0;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        if (isFloatExpr(b)) return emitBinFloat(b);
        return emitBinInt(b);
    }
    cerr << "stm32: unhandled expression\n";
    movs_imm(0, 0);
    return 0;
}// =========================================================================
// Misc helpers
// =========================================================================
void Stm32::addSpImm(int bytes) {
    if (bytes <= 0) return;
    if ((bytes & 3) == 0 && bytes / 4 <= 127) { add_sp((uint32_t)(bytes / 4)); return; }
    if (bytes <= 4095) { add_w(SP_REG, SP_REG, (uint32_t)bytes); return; }
    while (bytes > 0) { int s = std::min(bytes, 4095); add_w(SP_REG, SP_REG, (uint32_t)s); bytes -= s; }
}
void Stm32::subSpImm(int bytes) {
    if (bytes <= 0) return;
    if ((bytes & 3) == 0 && bytes / 4 <= 127) { sub_sp((uint32_t)(bytes / 4)); return; }
    if (bytes <= 4095) { sub_w(SP_REG, SP_REG, (uint32_t)bytes); return; }
    while (bytes > 0) { int s = std::min(bytes, 4095); sub_w(SP_REG, SP_REG, (uint32_t)s); bytes -= s; }
}

Type Stm32::fieldTypeOf(const Type& t, const string& m) {
    if (t.kind == TypeKind::Struct) {
        auto it = structs.find(t.structName);
        if (it != structs.end()) {
            auto f = it->second.second.find(m);
            if (f != it->second.second.end()) return f->second.second;
        }
    }
    return Type(TypeKind::Int);
}

void Stm32::emitAddrBase(const string& name) {
    if (auto v = var(name)) {
        int o = v->off + tempBytes;
        if (o >= 0 && (o & 3) == 0 && o <= 1020) add_sp_reg(0, (uint32_t)(o >> 2));
        else add_w(0, SP_REG, (uint32_t)o);
        return;
    }
    auto g = global(name);
    if (g) { loadConst(0, g->addr); return; }
    cerr << "stm32: undefined variable '" << name << "'\n";
    movs_imm(0, 0);
}

// =========================================================================
// Function calls and builtins
// =========================================================================
int Stm32::emitCall(CallExpr* c) {
    if (tryBuiltin(c)) return 0;
    if (funcOffsets.count(c->name)) {
        for (int i = (int)c->args.size() - 1; i >= 0; i--) {
            emitExpr(c->args[i].get());
            push(0x01, false);
        }
        hasCalls = true;
        bl_fixup(c->name);
        if (!c->args.empty()) addSpImm((int)c->args.size() * 4);
        tempBytes = 0;   // args were popped above; sp is back to frame-relative
        return 0;
    }
    cerr << "stm32: call to unknown function '" << c->name << "'\n";
    movs_imm(0, 0);
    return 0;
}

// "return f(...)": jump straight into f. f's params sit exactly where we
// leave the args on the stack (param(k) is read at [entrySP + 4k]).
bool Stm32::tryTailCall(CallExpr* c) {
    if (!funcOffsets.count(c->name)) return false;
    for (int i = (int)c->args.size() - 1; i >= 0; i--) {
        emitExpr(c->args[i].get());
        push(0x01, false);
    }
    if (hasCalls) {
        // Our lr was clobbered by earlier calls in this function. Restore it
        // from the slot saved by the prologue: it sits below the frame at
        // [SP + frameSize] (tempBytes == argsBytes is added back by loadFromOff,
        // SP already points below the pushed args).
        int off = frameSize;
        loadFromOff(3, off);
        movh(LR_REG, 3);            // MOV LR, R3
    }
    loadFuncAddr(1, c->name);
    bx(1);
    return true;
}

static string litStr(Expr* e) {
    if (auto s = dynamic_cast<StringExpr*>(e)) return s->value;
    // bare pin names like gpio_set(PA5, ...) lex as identifiers
    if (auto id = dynamic_cast<IdentExpr*>(e)) return id->name;
    return "";
}

bool Stm32::tryBuiltin(CallExpr* c) {
    const string& n = c->name;
    if (n == "gpio_init") {
        // Pins used by gpio_* / led_* are configured by the startup code
        // (emitRtGpioInit via registerPin); nothing to do here.
        return true;
    }
    if (n == "gpio_write") {
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Output);
        int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad gpio pin '" << pin << "'\n"; return true; }
        // always configure pin here too (idempotent, tiny)
        emitExpr(c->args[1].get());   // r0 = value first (emitExpr may clobber r2)
        movs_imm(2, 1);
        cmp_imm(0, 0);
        ite(1); // NE
        lsls_imm(1, 2, (uint32_t)p);
        lsls_imm(1, 2, (uint32_t)(p + 16));
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff);
        str_off(1, 0, 0);
        return true;
    }
    if (n == "gpio_set" || n == "gpio_clear") {
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Output);
int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad gpio pin '" << pin << "'\n"; return true; }
        movs_imm(2, 1);
        lsls_imm(1, 2, (uint32_t)(n == "gpio_set" ? p : p + 16));
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff);
        str_off(1, 0, 0);
        return true;
    }
    if (n == "gpio_read") {
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Input);
        int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad gpio pin '" << pin << "'\n"; return true; }
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.idrOff);
        ldr_off(1, 0, 0);
        loadConst(2, 1u << p);
        ands(1, 2);
        cmp_imm(1, 0);
        ite(1);
        movs_imm(0, 1);
        movs_imm(0, 0);
        return true;
    }
    if (n == "led_on" || n == "led_off") {
        int port = 2, ledp = 13;
        parsePin(prog.ledPin, port, ledp);
        registerPin(prog.ledPin, PinMode::Output);
        bool setLevel = (n == "led_on") ? !prog.ledActiveLow : prog.ledActiveLow;
        movs_imm(2, 1);
        lsls_imm(1, 2, (uint32_t)(setLevel ? ledp : ledp + 16));
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff);
        str_off(1, 0, 0);
        return true;
    }
    if (n == "led_toggle") {
        int port = 2, ledp = 13;
        parsePin(prog.ledPin, port, ledp);
        registerPin(prog.ledPin, PinMode::Output);
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.odrOff);
        ldr_off(1, 0, 0);
        movs_imm(2, 1);
        lsls_imm(2, 2, (uint32_t)ledp);
        eors(1, 2);
        str_off(1, 0, 0);
        return true;
    }
    if (n == "print") {
        // evaluate arg side effects, then blink the on-board LED
        for (auto& a : c->args) {
            if (!dynamic_cast<StringExpr*>(a.get())) emitExpr(a.get());
        }
        int port = 2, ledp = 13;
        parsePin(prog.ledPin, port, ledp);
        registerPin(prog.ledPin, PinMode::Output);
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.odrOff);
        ldr_off(1, 0, 0);
        movs_imm(2, 1);
        lsls_imm(2, 2, (uint32_t)ledp);
        eors(1, 2);
        str_off(1, 0, 0);
        return true;
    }
    if (n == "delay_ms") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        needRt("__z_delay");
        bl_fixup("__z_delay");
        hasCalls = true;
        return true;
    }
    if (n == "abs") {
        emitExpr(c->args[0].get());
        cmp_imm(0, 0);
        ite(4); // MI
        rsbs(0, 0);
        nop();
        return true;
    }
    if (n == "min" || n == "max") {
        // r0=a, r1=b
        emitExpr(c->args[0].get());
        push(0x01, false);
        emitExpr(c->args[1].get());
        pop(0x02, false);      // r1 = a, r0 = b
        cmps(1, 0);            // cmp a, b
        if (n == "min") {
            ite(11); movs(0, 1); nop();   // LT: r0 = a
        } else {
            ite(11); nop(); movs(0, 1);   // LT: keep b, else a
        }
        return true;
    }
    if (n == "clamp") {
        // x -> r0
        emitExpr(c->args[0].get());
        push(0x01, false);
        emitExpr(c->args[1].get());   // lo
        pop(0x02, false);             // r1 = x, r0 = lo
        cmps(0, 1);                   // cmp lo, x  (lo > x => GT)
        ite(12); nop(); movs(0, 1);   // GT: keep lo; else r0 = x
        push(0x01, false);
        emitExpr(c->args[2].get());   // hi
        pop(0x02, false);             // r1 = clamped, r0 = hi
        cmps(0, 1);                   // cmp hi, clamped (clamped > hi => LT)
        ite(11); nop(); movs(0, 1);   // LT: keep hi; else r0 = clamped
        return true;
    }
    if (n == "str_len") {
        if (c->args.empty() || !dynamic_cast<StringExpr*>(c->args[0].get())) return true;
        string s = litStr(c->args[0].get());
        int L = newLabel(), D = newLabel();
        loadStrAddr(0, stringIdx(s));
        movs_imm(1, 0);
        emitLabel(L);
        ldrb_off(2, 0, 0);
        cmp_imm(2, 0);
        b_cc(0, D);
        adds_imm8(0, 1);
        adds_imm8(1, 1);
        b_imm(L);
        emitLabel(D);
        movs(0, 1);
        return true;
    }
    if (n == "uart_init") {
        // uart_init(pin, baud): bit-banged serial TX. Configures the pin and
        // stores the timing globals; later uart_write/print reuse them.
        if (c->args.empty()) { cerr << "stm32: uart_init(pin, baud)\n"; return true; }
        string pin = litStr(c->args[0].get());
        int64_t baud = 9600;
        if (c->args.size() > 1 && !getIntConst(c->args[1].get(), baud)) {
            cerr << "stm32: uart_init baud must be a compile-time constant (e.g. 9600)\n";
            baud = 9600;
        }
        uartSetupPin(pin, baud, true);
        return true;
    }
    if (n == "uart_write") {
        if (c->args.size() < 2) { cerr << "stm32: uart_write(pin, byte)\n"; return true; }
        uartSetupPin(litStr(c->args[0].get()), 9600, false);
        emitExpr(c->args[1].get());
        needRt("__z_uart_tx");
        bl_fixup("__z_uart_tx");
        hasCalls = true;
        return true;
    }
    if (n == "uart_print" || n == "uart_println") {
        if (c->args.size() < 2) { cerr << "stm32: " << n << "(pin, \"text\")\n"; return true; }
        uartSetupPin(litStr(c->args[0].get()), 9600, false);
        string s = litStr(c->args[1].get());
        if (n == "uart_println") s += "\r\n";
        loadStrAddr(0, stringIdx(s));
        needRt("__z_uart_str");
        bl_fixup("__z_uart_str");
        hasCalls = true;
        return true;
    }
    if (n == "uart_print_int") {
        if (c->args.size() < 2) { cerr << "stm32: uart_print_int(pin, number)\n"; return true; }
        uartSetupPin(litStr(c->args[0].get()), 9600, false);
        emitExpr(c->args[1].get());
        needRt("__z_uart_int");
        bl_fixup("__z_uart_int");
        hasCalls = true;
        return true;
    }
    if (n == "adc_read") {
        if (c->args.empty()) { cerr << "stm32: adc_read(pin)\n"; return true; }
        if (!adcSupported) {
            cerr << "stm32: adc_read is supported only on the stm32f1/f4/f7 lines for now\n";
            movs_imm(0, 0);
            return true;
        }
        int ch = adcChannel(litStr(c->args[0].get()));
        if (ch < 0) {
            cerr << "stm32: bad ADC pin (use PA0-PA7, PB0/PB1, PC0-PC5)\n";
            movs_imm(0, 0);
            return true;
        }
        if (!adcInited) {
            needRt("__z_adc_init");
            bl_fixup("__z_adc_init");
            hasCalls = true;
            adcInited = true;
        }
        loadConst(0, (uint32_t)ch);
        needRt("__z_adc_read");
        bl_fixup("__z_adc_read");
        hasCalls = true;
        return true;
    }
    // ---- polled UART RX -----------------------------------------------------
    if (n == "uart_rx_init") {
        if (c->args.empty()) { cerr << "stm32: uart_rx_init(pin, baud)\n"; return true; }
        string pin = litStr(c->args[0].get());
        int64_t baud = 9600;
        if (c->args.size() > 1 && !getIntConst(c->args[1].get(), baud)) {
            cerr << "stm32: uart_rx_init baud must be a compile-time constant (e.g. 9600)\n";
            baud = 9600;
        }
        rxSetupPin(pin, baud, true);
        return true;
    }
    if (n == "uart_rx_available") {
        // poll the RX bit machine; must be called every loop iteration
        string rxpin;
        if (!c->args.empty()) rxpin = litStr(c->args[0].get());
        rxSetupPin(rxpin, 9600, false);
        needRt("__z_uart_rx");
        bl_fixup("__z_uart_rx");
        hasCalls = true;
        auto gd = global("__z_uart_rx_done");
        if (gd) { loadConst(0, gd->addr); ldr_off(0, 0, 0); }
        return true;
    }
    if (n == "uart_read") {
        string rxpin;
        if (!c->args.empty()) rxpin = litStr(c->args[0].get());
        rxSetupPin(rxpin, 9600, false);
        auto gb = global("__z_uart_rx_byte");
        auto gd = global("__z_uart_rx_done");
        if (gb) { loadConst(0, gb->addr); ldr_off(0, 0, 0); }
        if (gd) { loadConst(1, gd->addr); movs_imm(2, 0); str_off(2, 1, 0); }
        return true;
    }
    if (n == "uart_read_timeout") {
        if (c->args.size() < 2) { cerr << "stm32: uart_read_timeout(pin, ms)\n"; return true; }
        rxSetupPin(litStr(c->args[0].get()), 9600, false);
        emitExpr(c->args[1].get());
        needRt("__z_uart_rx_await");
        bl_fixup("__z_uart_rx_await");
        hasCalls = true;
        return true;
    }
    // ---- bit-banged I2C master ----------------------------------------------
    if (n == "i2c_init") {
        if (c->args.size() < 2) { cerr << "stm32: i2c_init(sda, scl)\n"; return true; }
        i2cSetup(litStr(c->args[0].get()), litStr(c->args[1].get()));
        return true;
    }
    if (n == "i2c_scan") {
        i2cSetup("PB7", "PB6");   // pins already configured by i2c_init
        needRt("__z_i2c_scan");
        bl_fixup("__z_i2c_scan");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_write_reg") {
        if (c->args.size() < 3) { cerr << "stm32: i2c_write_reg(addr, reg, val)\n"; return true; }
        i2cSetup("PB7", "PB6");
        emitExpr(c->args[2].get()); push(0x01, false);
        emitExpr(c->args[1].get()); push(0x01, false);
        emitExpr(c->args[0].get());
        pop(0x02, false);
        pop(0x04, false);
        needRt("__z_i2c_write_reg");
        bl_fixup("__z_i2c_write_reg");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_read_reg") {
        if (c->args.size() < 2) { cerr << "stm32: i2c_read_reg(addr, reg)\n"; return true; }
        i2cSetup("PB7", "PB6");
        emitExpr(c->args[1].get()); push(0x01, false);
        emitExpr(c->args[0].get());
        pop(0x02, false);
        needRt("__z_i2c_read_reg");
        bl_fixup("__z_i2c_read_reg");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_write") {
        if (c->args.size() < 2) { cerr << "stm32: i2c_write(addr, data)\n"; return true; }
        i2cSetup("PB7", "PB6");
        emitExpr(c->args[1].get()); push(0x01, false);
        emitExpr(c->args[0].get());
        pop(0x02, false);
        needRt("__z_i2c_write");
        bl_fixup("__z_i2c_write");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_read") {
        if (c->args.empty()) { cerr << "stm32: i2c_read(addr)\n"; return true; }
        i2cSetup("PB7", "PB6");
        emitExpr(c->args[0].get());
        needRt("__z_i2c_read");
        bl_fixup("__z_i2c_read");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_mem_read") {
        if (c->args.size() < 3) { cerr << "stm32: i2c_mem_read(addr, reg, n)\n"; return true; }
        i2cSetup("PB7", "PB6");
        emitExpr(c->args[2].get()); push(0x01, false);
        emitExpr(c->args[1].get()); push(0x01, false);
        emitExpr(c->args[0].get());
        pop(0x02, false);
        pop(0x04, false);
        needRt("__z_i2c_mem_read");
        bl_fixup("__z_i2c_mem_read");
        hasCalls = true;
        return true;
    }
    if (n == "i2c_buf_read") {
        auto gb = global("__z_i2c_buf");
        if (gb && !c->args.empty()) {
            emitExpr(c->args[0].get());
            loadConst(1, gb->addr);
            adds(0, 1, 0);
            ldrb_off(0, 0, 0);
        }
        return true;
    }
    // ---- flash EEPROM emulation ---------------------------------------------
    if (n == "flash_eeprom_init") {
        if (fam == McuFamily::F4 || fam == McuFamily::F7) {
            cerr << "stm32: flash_eeprom_* not yet supported on F4/F7\n";
            return true;
        }
        if (!flInited) {
            needRt("__z_fl_init");
            bl_fixup("__z_fl_init");
            hasCalls = true;
            flInited = true;
        }
        return true;
    }
    if (n == "flash_eeprom_write") {
        if (c->args.size() < 2) { cerr << "stm32: flash_eeprom_write(addr, val)\n"; return true; }
        emitExpr(c->args[1].get()); push(0x01, false);
        emitExpr(c->args[0].get());
        pop(0x02, false);
        needRt("__z_fl_write");
        bl_fixup("__z_fl_write");
        hasCalls = true;
        return true;
    }
    if (n == "flash_eeprom_read") {
        if (c->args.empty()) { cerr << "stm32: flash_eeprom_read(addr)\n"; return true; }
        emitExpr(c->args[0].get());
        needRt("__z_fl_read");
        bl_fixup("__z_fl_read");
        hasCalls = true;
        return true;
    }
    // ---- RTC + low power (F1 for now) ---------------------------------------
    if (n == "rtc_init" || n == "rtc_set" || n == "rtc_get" ||
        n == "rtc_alarm_set" || n == "rtc_alarm_pending" ||
        n == "power_stop" || n == "power_standby") {
        if (fam != McuFamily::F1) {
            cerr << "stm32: " << n << " is supported only on the stm32f1 line for now\n";
            movs_imm(0, 0);
            return true;
        }
        if (n == "rtc_init") {
            if (!rtcInited) {
                needRt("__z_rtc_init");
                bl_fixup("__z_rtc_init");
                hasCalls = true;
                rtcInited = true;
            }
            return true;
        }
        if (n == "rtc_set") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            needRt("__z_rtc_set");
            bl_fixup("__z_rtc_set");
            hasCalls = true;
            return true;
        }
        if (n == "rtc_get") {
            needRt("__z_rtc_get");
            bl_fixup("__z_rtc_get");
            hasCalls = true;
            return true;
        }
        if (n == "rtc_alarm_set") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            needRt("__z_rtc_alarm_set");
            bl_fixup("__z_rtc_alarm_set");
            hasCalls = true;
            rtcAlarmUsed = true;
            return true;
        }
        if (n == "rtc_alarm_pending") {
            needRt("__z_rtc_alarm_pending");
            bl_fixup("__z_rtc_alarm_pending");
            hasCalls = true;
            return true;
        }
        if (n == "power_stop") {
            needRt("__z_power_stop");
            bl_fixup("__z_power_stop");
            hasCalls = true;
            return true;
        }
        needRt("__z_power_standby");
        bl_fixup("__z_power_standby");
        hasCalls = true;
        return true;
    }
    // ---- Modbus RTU slave ----------------------------------------------------
    if (n == "modbus_rtu_init") {
        if (c->args.size() < 4) {
            cerr << "stm32: modbus_rtu_init(tx, rx, addr, baud)\n";
            return true;
        }
        string tx = litStr(c->args[0].get());
        string rx = litStr(c->args[1].get());
        int64_t addr = 1, baud = 9600;
        getIntConst(c->args[2].get(), addr);
        if (c->args.size() > 3) getIntConst(c->args[3].get(), baud);
        uartSetupPin(tx, baud, true);
        int port = 0, p = 0;
        if (!parsePin(rx, port, p)) {
            cerr << "stm32: bad modbus rx pin '" << rx << "'\n";
            return true;
        }
        registerPin(rx, PinMode::InputPullUp);
        if (mbConfigured) return true;
        emitGlobalConst("__z_mb_idr", cfg.gpioA + (uint32_t)port * 0x400u + cfg.idrOff);
        emitGlobalConst("__z_mb_bit", 1u << p);
        uint32_t half = prog.sysclkHz / (2u * (uint32_t)baud * (uint32_t)cfg.uartLoopCycles);
        if (half < 1) half = 1;
        if (half > 0xFFFF) half = 0xFFFF;
        emitGlobalConst("__z_mb_half", half);
        emitGlobalConst("__z_mb_addr", (uint32_t)(addr & 0xFF));
        emitGlobalConst("__z_mb_st", 0);
        emitGlobalConst("__z_mb_bits", 0);
        emitGlobalConst("__z_mb_wait2", 0);
        emitGlobalConst("__z_mb_byte", 0);
        emitGlobalConst("__z_mb_cnt", 0);
        emitGlobalConst("__z_mb_sil", 0);
        mbConfigured = true;
        return true;
    }
    if (n == "modbus_rtu_poll") {
        needRt("__z_mb_poll");
        bl_fixup("__z_mb_poll");
        hasCalls = true;
        return true;
    }
    if (n == "modbus_reg_set") {
        if (c->args.size() < 2) { cerr << "stm32: modbus_reg_set(i, v)\n"; return true; }
        auto gr = global("__z_mb_regs");
        if (gr) {
            emitExpr(c->args[0].get());
            lsls_imm(0, 0, 2);
            push(0x01, false);
            emitExpr(c->args[1].get());
            pop(0x02, false);
            loadConst(2, gr->addr);
            adds(1, 2, 1);
            str_off(0, 1, 0);
        }
        return true;
    }
    if (n == "modbus_reg_get") {
        auto gr = global("__z_mb_regs");
        if (gr && !c->args.empty()) {
            emitExpr(c->args[0].get());
            lsls_imm(0, 0, 2);
            loadConst(1, gr->addr);
            adds(0, 1, 0);
            ldr_off(0, 0, 0);
        }
        return true;
    }
    // ---- GPIO toggle --------------------------------------------------------
    if (n == "gpio_toggle") {
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Output);
        int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad gpio pin '" << pin << "'\n"; return true; }
        loadConst(0, cfg.gpioA + (uint32_t)port * 0x400u + cfg.odrOff);
        ldr_off(1, 0, 0);
        movs_imm(2, 1);
        lsls_imm(2, 2, (uint32_t)p);
        eors(1, 2);
        str_off(1, 0, 0);
        return true;
    }
    // ---- system time (SysTick-based) ------------------------------------------
    if (n == "delay_us") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        systickUsed = true;
        needRt("__z_delay_us");
        bl_fixup("__z_delay_us");
        hasCalls = true;
        return true;
    }
    if (n == "micros") {
        systickUsed = true;
        needRt("__z_micros");
        bl_fixup("__z_micros");
        hasCalls = true;
        return true;
    }
    if (n == "millis") {
        systickUsed = true;
        needRt("__z_millis");
        bl_fixup("__z_millis");
        hasCalls = true;
        return true;
    }
    // ---- software PWM (bit-banged, one period) --------------------------------
    if (n == "pwm") {
        if (c->args.size() < 3) { cerr << "stm32: pwm(pin, duty, period)\n"; return true; }
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Output);
        int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad pwm pin '" << pin << "'\n"; return true; }
        emitGlobalConst("__z_pwm_bsrr", cfg.gpioA + (uint32_t)port * 0x400u + cfg.bsrrOff);
        emitGlobalConst("__z_pwm_bit", 1u << p);
        systickUsed = true;
        emitExpr(c->args[2].get()); push(0x01, false);   // period
        emitExpr(c->args[1].get());                      // duty
        pop(0x02, false);                                // r1 = period, r0 = duty
        needRt("__z_pwm");
        bl_fixup("__z_pwm");
        hasCalls = true;
        return true;
    }
    // ---- pseudo-random (LCG, 32-bit) -------------------------------------------
    if (n == "random") {
        if (c->args.size() < 2) { cerr << "stm32: random(min, max)\n"; return true; }
        auto gr = global("__z_rng");
        if (!gr) { movs_imm(0, 0); return true; }
        rngUsed = true;
        // span = max - min + 1
        emitExpr(c->args[0].get()); push(0x01, false);      // [min]
        emitExpr(c->args[1].get());                         // r0 = max
        pop(0x02, false);                                   // r1 = min, r0 = max
        subs(0, 0, 1);                                      // r0 = max - min
        adds_imm8(0, 1);                                    // r0 = span
        push(0x01, false);                                  // [min, span]
        // LCG: seed = seed * 1103515245 + 12345
        loadConst(0, gr->addr); ldr_off(0, 0, 0);
        loadConst(1, 1103515245u); muls(0, 1);
        loadConst(1, 12345u); adds(0, 0, 1);
        loadConst(1, gr->addr); str_off(0, 1, 0);
        lsrs_imm(0, 0, 16);                                 // r0 = seed >> 16
        pop(0x02, false);                                   // r1 = span
        needRt("__z_udiv"); bl_fixup("__z_udiv");           // r3 = value % span
        hasCalls = true;
        pop(0x02, false);                                   // r1 = min
        adds(0, 3, 1);                                      // r0 = rem + min
        return true;
    }
    // ---- pulse width measurement ------------------------------------------------
    if (n == "pulse_in") {
        if (c->args.size() < 3) { cerr << "stm32: pulse_in(pin, level, timeout)\n"; return true; }
        string pin = litStr(c->args[0].get());
        registerPin(pin, PinMode::Input);
        int port = 0, p = 0;
        if (!parsePin(pin, port, p)) { cerr << "stm32: bad pulse_in pin '" << pin << "'\n"; return true; }
        emitGlobalConst("__z_pulse_idr", cfg.gpioA + (uint32_t)port * 0x400u + cfg.idrOff);
        emitGlobalConst("__z_pulse_bit", 1u << p);
        systickUsed = true;
        emitExpr(c->args[2].get()); push(0x01, false);      // timeout
        emitExpr(c->args[1].get());                         // level
        pop(0x02, false);                                   // r1 = timeout, r0 = level
        needRt("__z_pulse_in");
        bl_fixup("__z_pulse_in");
        hasCalls = true;
        return true;
    }
    // ---- value remapping --------------------------------------------------------
    if (n == "map") {
        if (c->args.size() < 5) { cerr << "stm32: map(x, inMin, inMax, outMin, outMax)\n"; return true; }
        push(0x70, false);                                  // save r4,r5,r6
        // r4 = x - inMin
        emitExpr(c->args[0].get()); push(0x01, false);
        emitExpr(c->args[1].get()); pop(0x02, false);
        subs(0, 0, 1); movs(4, 0);
        // r6 = outMax ; r5 = outMax - outMin
        emitExpr(c->args[4].get()); movs(6, 0); push(0x01, false);
        emitExpr(c->args[3].get()); pop(0x02, false);
        subs(0, 1, 0); movs(5, 0);
        // r3 = inMax - inMin  (divisor)
        emitExpr(c->args[2].get()); push(0x01, false);
        emitExpr(c->args[1].get()); pop(0x02, false);
        subs(0, 1, 0); movs(3, 0);
        // num = r4 * r5
        movs(0, 4); muls(0, 5);
        movs(1, 3);
        needRt("__z_div"); bl_fixup("__z_div");             // r0 = num / den
        hasCalls = true;
        // result = quot + outMax - spanOut
        movs(1, 6); adds(0, 0, 1);
        movs(1, 5); subs(0, 0, 1);
        pop(0x70, false);                                   // restore r4,r5,r6
        return true;
    }
    return false;
}

// =========================================================================
// Branch / boolean helper
// =========================================================================
int Stm32::emitCondJump(Expr* c, int label, bool wantTrue) {
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
            push(0x01, false);
            emitExpr(b->right.get());
            pop(0x02, false);
            cmps(1, 0);
            if (!wantTrue) cc = invCc(cc);
            b_cc(cc, label);
            return 0;
        }
    }
    emitExpr(c);
    cmp_imm(0, 0);
    b_cc(wantTrue ? 1 : 0, label);
    return 0;
}

// =========================================================================
// Statements
// =========================================================================
void Stm32::emitBlock(const Block& b, int* brk, int* con, int* end) {
    for (auto& s : b.stmts) {
        emitStmt(s.get(), brk, con, end);
        if (!lits.empty() && (int)code.size() - lastFlushPos > 280) flushPool(true);
    }
}

void Stm32::emitStmt(Stmt* s, int* brk, int* con, int* end) {
    if (auto v = dynamic_cast<VarDecl*>(s)) {
        auto vi = var(v->name);
        if (vi && v->init) {
            emitExpr(v->init.get());
            storeToOff(0, vi->off);
        }
        return;
    }
    if (auto a = dynamic_cast<AssignStmt*>(s)) {
        if (a->memberPath.empty() && !a->indexExpr) {
            emitExpr(a->value.get());
            emitStoreVar(a->name, 0);
            return;
        }
        // C3: "s.field = v" of a local struct is a single SP-relative STR
        // (merged var offset + field offsets) when it fits in 124 bytes.
        if (!a->indexExpr) {
            if (auto v = var(a->name)) {
                int total = v->off;
                Type t = v->type;
                for (auto& m : a->memberPath) { total += fieldOffsetOf(t, m); t = fieldTypeOf(t, m); }
                if (total >= 0 && total <= 1020 && (total & 3) == 0) {
                    emitExpr(a->value.get());
                    storeToOff(0, total);
                    return;
                }
            }
        }
        emitAddrBase(a->name);
        if (a->indexExpr) {
            int elem = elementSize(varType(a->name));
            push(0x01, false);
            emitExpr(a->indexExpr.get());
            scaleR0By(elem);
            pop(0x02, false);
            adds(0, 1, 0);
        }
        int total = 0;
        Type t = varType(a->name);
        for (auto& m : a->memberPath) { total += fieldOffsetOf(t, m); t = fieldTypeOf(t, m); }
        addImmR0(total);
        push(0x01, false);
        emitExpr(a->value.get());
        movs(1, 0);
        pop(0x01, false);
        str_off(1, 0, 0);
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        emitAddr(pa->ptr.get());
        push(0x01, false);
        emitExpr(pa->value.get());
        movs(1, 0);
        pop(0x01, false);
        str_off(1, 0, 0);
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
        emitStoreVar(fs->varName, 0);
        emitLabel(startL);
        emitLoadVar(0, fs->varName);
        push(0x01, false);
        emitExpr(fs->end.get());
        pop(0x02, false);
        cmps(1, 0);
        int64_t sv = 1;
        bool sConst = fs->step ? getIntConst(fs->step.get(), sv) : false;
        int cc = (sConst && sv < 0) ? 13 : 10;  // LE for decreasing, GE otherwise
        b_cc(cc, doneL);
        emitBlock(fs->body, &doneL, &stepL, end);
        emitLabel(stepL);
        emitLoadVar(0, fs->varName);
        push(0x01, false);
        if (fs->step) emitExpr(fs->step.get()); else movs_imm(0, 1);
        pop(0x02, false);
        adds(0, 1, 0);
        emitStoreVar(fs->varName, 0);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) { emitSwitch(sw); return; }
    if (dynamic_cast<BreakStmt*>(s)) { if (brk) b_imm(*brk); return; }
    if (dynamic_cast<ContinueStmt*>(s)) { if (con) b_imm(*con); return; }
    if (auto r = dynamic_cast<ReturnStmt*>(s)) { emitReturn(r->value.get(), end ? *end : -1, retLabel); return; }
if (auto as = dynamic_cast<AsmStmt*>(s)) {
for (auto& instr : as->instrs) emitAsmInstr(instr);
        return;
    }
}

// =========================================================================
// Thumb inline assembler (asm {} / asm32 {} / asm16 {} blocks).
//
// Registers: r0-r15 with aliases sp(r13), lr(r14), pc(r15). Native operand
// width is 32-bit. Low registers r0-r7 use compact 16-bit encodings that set
// the condition flags (movs/adds/subs/...); high registers r8-r15 fall back
// to 32-bit Thumb-2 encodings (which generally do not set flags).
//
// Supported mnemonics:
//   mov rd, rm | mov rd, #imm        (any 32-bit immediate via movw/movt)
//   add/sub rd[, rn][, rm|#imm]      (imm: <=4095)
//   and/orr/eor/bic/mvn rd[, rn], rm
//   cmp rn, rm | cmp rn, #imm        (<=4095)
//   lsl/lsr/asr rd, rm[, #imm]       (immediate shifts only when rd==rm, <=31)
//   mul rd[, rn], rm
//   ldr/ldrb/ldrh/str/strb/strh/ldrsb/ldrsh rd, [rn, #offs]
//   ldr/str rd, [rn, rm]             (low registers only)
//   push/pop {r0-r7,...[,lr|pc]}     (high registers r8-r12 not supported)
//   b/b{cond} #disp                  (signed byte displacement from the
//                                    instruction; b: +-2 KB, b.cond: +-126 B)
//   bl <function name>               (call a Zenith function)
//   bx/blx rm, nop, wfi, wfe, sev, yield, svc #imm, bkpt #imm
// Condition-suffixed mnemonics are used (beq/bne/...) instead of 'b.eq'.
// =========================================================================
void Stm32::emitAsmInstr(const AsmInstr& instr) {
    const string mn = instr.mnemonic;

    auto trim = [](string s) {
        while (!s.empty() && (s[0] == ' ' || s[0] == '\t' || s[0] == '#')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        return s;
    };
    auto parseReg = [&](const string& raw, int& reg) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        if (s == "sp")  { reg = 13; return true; }
        if (s == "lr")  { reg = 14; return true; }
        if (s == "pc")  { reg = 15; return true; }
        if (s[0] == 'r' && s.size() > 1) {
            int v = 0; size_t i = 1;
            while (i < s.size() && isdigit((unsigned char)s[i])) { v = v * 10 + (s[i] - '0'); i++; }
            if (i == s.size() && v <= 15) { reg = v; return true; }
        }
        return false;
    };
    auto parseImm = [&](const string& raw, uint32_t& v, bool& neg) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        neg = false;
        if (s[0] == '-') { neg = true; s.erase(s.begin()); }
        if (s.empty()) return false;
        try {
            uint64_t val;
            size_t idx = 0;
            size_t b = (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 2 : 0;
            val = (uint64_t)std::stoull(s.substr(b), &idx, (b ? 16 : 0));
            if (idx != s.size() - b) return false;
            v = (uint32_t)val;
            return true;
        } catch (...) { return false; }
    };
    auto parseDisp = [&](const string& raw, int& disp) -> bool {
        uint32_t v; bool neg;
        if (!parseImm(raw, v, neg)) return false;
        disp = neg ? -(int)v : (int)v;
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
        cerr << "stm32: warning: unsupported asm '" << what << "', skipped\n";
    };
    auto badOperand = [&](const string& why) {
        cerr << "stm32: warning: asm '" << mn << "': " << why << ", skipped\n";
    };

    // ---- mov rd, rm | mov rd, #imm ----
    if (mn == "mov") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        uint32_t v; bool neg;
        if (parseImm(instr.op2, v, neg)) {
            if (neg) v = (uint32_t)(-((int64_t)v));   // build as 32-bit two's complement
            if (rd < 8 && v <= 0xFF) { movs_imm(rd, v); return; }
            if (rd < 8 && v >= 0xFFFFFF00u) { movs_imm(rd, 0u - v); mvns(rd, rd); return; }
            movw(rd, v & 0xFFFF);
            if (v > 0xFFFF) movt(rd, v >> 16);
            return;
        }
        int rm;
        if (!parseReg(instr.op2, rm)) { badOperand("bad source register"); return; }
        if (rd < 8 && rm < 8) movs(rd, rm);
        else movh(rd, rm);
        return;
    }

    // ---- movw/movt rd, #imm ----
    if (mn == "movw" || mn == "movt") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        uint32_t v; bool neg;
        if (!parseImm(instr.op2, v, neg)) { badOperand("bad immediate"); return; }
        if (neg) v = (uint32_t)(-((int64_t)v));
        if (mn == "movw") movw(rd, v & 0xFFFF);
        else movt(rd, (v >> 16) & 0xFFFF);
        return;
    }

    // ---- add/sub rd[, rn][, rm|#imm] ----
    if (mn == "add" || mn == "sub") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        int rn = rd;
        if (!instr.op2.empty() && !parseReg(instr.op2, rn)) {
            // add/sub rd, #imm  (second operand is an immediate)
            uint32_t v; bool neg;
            if (!parseImm(instr.op2, v, neg)) { badOperand("bad operand"); return; }
            int64_t val = neg ? -((int64_t)v) : (int64_t)v;
            bool isAdd = (mn == "add");
            int64_t mag = isAdd ? val : -val;
            if (mag < 0) { isAdd = !isAdd; mag = -mag; }  // add -x == sub x
            if (rd < 8 && mag <= 255) {
                if (isAdd) adds_imm8(rd, (uint32_t)mag); else subs_imm8(rd, (uint32_t)mag);
                return;
            }
            if (mag <= 4095) {
                if (isAdd) add_w(rd, rd, (uint32_t)mag); else sub_w(rd, rd, (uint32_t)mag);
                return;
            }
            badOperand("immediate out of range (0..4095)");
            return;
        }
        // rn is a register now
        if (instr.op3.empty()) {
            // rd = rd op rn
            if (rd < 8 && rn < 8) { rn = (rn == rd) ? rd : rn; if (mn == "add") adds(rd, rd, rn); else subs(rd, rd, rn); }
            else if (mn == "add") add_w_r(rd, rd, rn);
            else sub_w_r(rd, rd, rn);
            return;
        }
        uint32_t v; bool neg;
        if (parseImm(instr.op3, v, neg)) {
            int64_t val = neg ? -((int64_t)v) : (int64_t)v;
            bool isAdd = (mn == "add");
            int64_t mag = isAdd ? val : -val;
            if (mag < 0) { isAdd = !isAdd; mag = -mag; }
            if (rd < 8 && rn < 8 && mag <= 7) {
                if (isAdd) adds_imm3(rd, rn, (uint32_t)mag); else subs_imm3(rd, rn, (uint32_t)mag);
                return;
            }
            if (mag <= 4095) {
                if (isAdd) add_w(rd, rn, (uint32_t)mag); else sub_w(rd, rn, (uint32_t)mag);
                return;
            }
            badOperand("immediate out of range (0..4095)");
            return;
        }
        int rm;
        if (!parseReg(instr.op3, rm)) { badOperand("bad third operand"); return; }
        if (rd < 8 && rn < 8 && rm < 8) {
            if (mn == "add") adds(rd, rn, rm); else subs(rd, rn, rm);
        } else if (mn == "add") add_w_r(rd, rn, rm);
        else sub_w_r(rd, rn, rm);
        return;
    }

    // ---- cmp rn, rm | cmp rn, #imm ----
    if (mn == "cmp") {
        int rn;
        if (!parseReg(instr.op1, rn)) { badOperand("bad register"); return; }
        uint32_t v; bool neg;
        if (parseImm(instr.op2, v, neg)) {
            if (neg) v = (uint32_t)(-((int64_t)v));
            if (rn < 8 && v <= 255) { cmp_imm(rn, v); return; }
            if (v <= 4095) { cmp_w_imm(rn, v); return; }
            badOperand("cmp immediate out of range (0..4095)");
            return;
        }
        int rm;
        if (!parseReg(instr.op2, rm)) { badOperand("bad comparator register"); return; }
        if (rn < 8 && rm < 8) cmps(rn, rm);
        else cmp_w_r(rn, rm);
        return;
    }

    // ---- and/orr/eor/bic/mvn rd[, rn], rm ----
    if (mn == "and" || mn == "orr" || mn == "eor" || mn == "bic" || mn == "mvn") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        int rn = rd;
        if (!instr.op2.empty() && !parseReg(instr.op2, rn)) { badOperand("immediate not supported for this operation"); return; }
        int rm;
        if (!instr.op3.empty()) { if (!parseReg(instr.op3, rm)) { badOperand("bad third operand"); return; } }
        else rm = rn;   // 2-op form applies rm to the destination

        if (mn == "mvn") {  // 2-op only: rd = ~rm
            if (rd < 8 && rm < 8) mvns(rd, rm);
            else mvn_w(rd, rm);
            return;
        }
        if (rd < 8 && rm < 8 && rd == rn) {
            if (mn == "and") ands(rd, rm);
            else if (mn == "orr") orrs(rd, rm);
            else if (mn == "eor") eors(rd, rm);
            else bics(rd, rm);
            return;
        }
        if (mn == "and") and_w(rd, rn, rm);
        else if (mn == "orr") orr_w(rd, rn, rm);
        else if (mn == "eor") eor_w(rd, rn, rm);
        else bic_w(rd, rn, rm);
        return;
    }

    // ---- lsl/lsr/asr rd, rm[, #imm] ----
    if (mn == "lsl" || mn == "lsr" || mn == "asr") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        int rm;
        if (!parseReg(instr.op2, rm)) { badOperand("bad source register"); return; }
        uint32_t v; bool neg;
        if (parseImm(instr.op3, v, neg)) {
            if (neg || v > 31) { badOperand("shift count must be 0..31"); return; }
            if (rd != rm) { badOperand("immediate shifts require the destination to be the source (rD, rD, #imm)"); return; }
            if (rd >= 8) { badOperand("immediate shifts are only supported for r0-r7"); return; }
            if (mn == "lsl") lsls_imm(rd, rm, v);
            else if (mn == "lsr") lsrs_imm(rd, rm, v);
            else asrs_imm(rd, rm, v);
            return;
        }
        int rs = (instr.op3.empty()) ? rm : 0;
        if (!instr.op3.empty() && !parseReg(instr.op3, rs)) { badOperand("bad shift operand"); return; }
        // general register shift via Thumb-2 (any registers)
        if (mn == "lsl") lsl_w(rd, rm, rs);
        else if (mn == "lsr") lsr_w(rd, rm, rs);
        else asr_w(rd, rm, rs);
        return;
    }

    // ---- mul rd[, rn], rm ----
    if (mn == "mul") {
        int rd;
        if (!parseReg(instr.op1, rd)) { badOperand("bad destination register"); return; }
        int rn = rd;
        if (!instr.op2.empty() && !parseReg(instr.op2, rn)) { badOperand("bad operand"); return; }
        int rm = rn;
        if (!instr.op3.empty() && !parseReg(instr.op3, rm)) { badOperand("bad third operand"); return; }
        if (rd < 8 && rn < 8 && rm < 8 && rd == rn) muls(rd, rm);
        else mul_w_r(rd, rn, rm);
        return;
    }

    // ---- loads/stores ----
    auto memoryOp = [&](bool load, int width, bool sign) -> bool {
        int rt;
        if (!parseReg(instr.op1, rt)) { badOperand("bad register"); return false; }
        string m = trim(instr.op2);
        if (m.size() < 2 || m.front() != '[' || m.back() != ']') { badOperand("expected [base, offset]"); return false; }
        m = m.substr(1, m.size() - 2);
        size_t comma = m.find(',');
        string baseStr = comma == string::npos ? m : m.substr(0, comma);
        string offStr = comma == string::npos ? "" : m.substr(comma + 1);
        int rn;
        if (!parseReg(baseStr, rn)) { badOperand("bad base register"); return false; }
        uint32_t off = 0; bool imm = true;
        int rm = 0;
        if (!trim(offStr).empty()) {
            uint32_t v; bool neg;
            if (parseImm(offStr, v, neg)) {
                if (neg) { badOperand("negative offsets are not supported"); return false; }
                off = v;
            } else if (parseReg(offStr, rm)) {
                if (width != 4) { badOperand("register offset only supported for ldr/str"); return false; }
                if (rt > 7 || rn > 7 || rm > 7) { badOperand("register offset requires r0-r7"); return false; }
                if (load) ldr_reg(rt, rn, rm); else str_reg(rt, rn, rm);
                return true;
            } else { badOperand("bad offset"); return false; }
        }
        if (width == 1) {
            if (rn < 8 && off <= 31) { if (load) ldrb_off(rt, rn, off); else strb_off(rt, rn, off); return true; }
            if (off > 4095) { badOperand("byte offset out of range (0..4095)"); return false; }
            if (sign) { if (rt > 15) return false; if (mn == "ldrsb") ldrsb_w(rt, rn, off); else ldrsh_w(rt, rn, off); return true; }
            if (load) ldrb_w(rt, rn, off); else strb_w(rt, rn, off);
            return true;
        }
        if (width == 2) {
            if (off % 2) { badOperand("halfword offset must be even"); return false; }
            if (rn < 8 && off / 2 <= 31) { if (load) ldrh_off(rt, rn, off); else strh_off(rt, rn, off); return true; }
            if (off > 4095) { badOperand("halfword offset out of range (0..4094)"); return false; }
            if (sign) { if (mn == "ldrsh") ldrsh_w(rt, rn, off); else ldrsh_w(rt, rn, off); return true; }
            if (load) ldrh_w(rt, rn, off); else strh_w(rt, rn, off);
            return true;
        }
        // 32-bit word
        if (off % 4) { badOperand("word offset must be a multiple of 4"); return false; }
        if (rn < 8 && off / 4 <= 31) { if (load) ldr_off(rt, rn, off); else str_off(rt, rn, off); return true; }
        if (off > 4095) { badOperand("word offset out of range (0..4092)"); return false; }
        if (load) ldr_w(rt, rn, off); else str_w(rt, rn, off);
        return true;
    };
    if (mn == "ldr" || mn == "str") { memoryOp(mn == "ldr", 4, false); return; }
    if (mn == "ldrb" || mn == "strb") { memoryOp(mn == "ldrb", 1, false); return; }
    if (mn == "ldrh" || mn == "strh") { memoryOp(mn == "ldrh", 2, false); return; }
    if (mn == "ldrsb") { memoryOp(true, 1, true); return; }
    if (mn == "ldrsh") { memoryOp(true, 2, true); return; }

    // ---- push/pop {r0-r7,...} ----
    if (mn == "push" || mn == "pop") {
        string s = trim(instr.op1);
        if (s.size() < 2 || s.front() != '{' || s.back() != '}') { badOperand("expected {register list}"); return; }
        s = s.substr(1, s.size() - 2);
        uint32_t mask = 0;
        bool special = false;
        // split on commas, then interpret ranges "r0 - r3"
        vector<string> items;
        size_t pos = 0;
        while (pos <= s.size()) {
            size_t nxt = s.find(',', pos);
            if (nxt == string::npos) nxt = s.size();
            string item = trim(s.substr(pos, nxt - pos));
            if (!item.empty()) items.push_back(item);
            pos = nxt + 1;
            if (nxt == string::npos) break;
        }
        for (auto& item : items) {
            string it = trim(item);
            size_t dash = it.find('-');
            if (dash == string::npos) {
                if (mn == "push" && it == "lr") { special = true; continue; }
                if (mn == "pop" && it == "pc") { special = true; continue; }
                int rr;
                if (!parseReg(it, rr)) { badOperand("bad register in list"); return; }
                if (rr > 7) { badOperand("r8-r12 in push/pop are not supported"); return; }
                mask |= (1u << rr);
            } else {
                string a = trim(it.substr(0, dash));
                string b = trim(it.substr(dash + 1));
                int ra, rb;
                if (!parseReg(a, ra) || !parseReg(b, rb) || rb < ra) { badOperand("bad register range"); return; }
                if (rb > 7) { badOperand("r8-r12 in push/pop are not supported"); return; }
                for (int i = ra; i <= rb; i++) mask |= (1u << i);
            }
        }
        if (mn == "push") push((int)mask, special);
        else pop((int)mask, special);
        return;
    }

    // ---- branches ----
    auto branchDisp = [&](const string& raw, int& disp) -> bool {
        if (!parseDisp(raw, disp)) { badOperand("bad branch displacement"); return false; }
        if (disp & 1) { badOperand("branch displacement must be even"); return false; }
        return true;
    };
    if (mn == "b") {
        int disp;
        if (!branchDisp(instr.op1, disp)) return;
        int imm = (disp - 4) / 2;
        if (imm < -1024 || imm > 1023) { badOperand("b out of range (+-2 KB)"); return; }
        u16((uint16_t)(0xE000 | (imm & 0x7FF)));
        return;
    }
    if (mn.size() == 3 && mn[0] == 'b') {
        int cc = condCode(mn.substr(1));
        if (cc >= 0) {
            int disp;
            if (!branchDisp(instr.op1, disp)) return;
            int imm = (disp - 4) / 2;
            if (imm < -128 || imm > 127) { badOperand("b.cond out of range (+-126 B)"); return; }
            u16((uint16_t)(0xD000 | ((cc & 15) << 8) | (imm & 0xFF)));
            return;
        }
    }
    if (mn == "bl") {
        if (instr.op1.empty()) { badOperand("bl needs a function name"); return; }
        bl_fixup(trim(instr.op1));
        return;
    }
    if (mn == "bx" || mn == "blx") {
        int rm;
        if (!parseReg(instr.op1, rm)) { badOperand("bad register"); return; }
        if (mn == "bx") bx(rm); else blx(rm);
        return;
    }

    // ---- hints / specials ----
    if (mn == "nop")    { nop(); return; }
    if (mn == "yield")  { u16(0xBF10); return; }
    if (mn == "wfe")    { u16(0xBF20); return; }
    if (mn == "wfi")    { u16(0xBF30); return; }
    if (mn == "sev")    { u16(0xBF40); return; }
    if (mn == "svc") {
        uint32_t v; bool neg;
        uint8_t imm = 0;
        if (!instr.op1.empty() && parseImm(instr.op1, v, neg)) imm = (uint8_t)(v & 0xFF);
        u16((uint16_t)(0xDF00 | imm));
        return;
    }
    if (mn == "bkpt") {
        uint32_t v; bool neg;
        uint8_t imm = 0;
        if (!instr.op1.empty() && parseImm(instr.op1, v, neg)) imm = (uint8_t)(v & 0xFF);
        u16((uint16_t)(0xBE00 | imm));
        return;
    }

    unsupported(mn);
}

void Stm32::emitSwitch(SwitchStmt* sw) {
    int endL = newLabel();
    int defL = -1;
    int slot = swTempOff + 4 * (swCur++);
    emitExpr(sw->condition.get());
    storeToOff(0, slot);
    vector<int> caseLabels;
    for (auto& cs : sw->cases) {
        if (cs.condition) {
int L = newLabel();
            caseLabels.push_back(L);
            int64_t cv; bool cconst = getIntConst(cs.condition.get(), cv);
            if (cconst) {
                loadConst(0, (uint32_t)(int32_t)cv);
            } else {
                emitExpr(cs.condition.get());
            }
            loadFromOff(1, slot);
            cmps(1, 0);
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

void Stm32::emitReturn(Expr* v, int endLabel, int retLabel) {
    // Tail-call optimization is disabled (C11): tryTailCall pushes args but
    // never tears down the current frame/SP, corrupting the stack.
    if (v) emitExpr(v);
    if (retLabel >= 0) b_imm(retLabel);
    (void)endLabel;
}

// =========================================================================
// Literal pool (shared per function; flushed with a guarded jump-over)
// =========================================================================
void Stm32::flushPool(bool guarded) {
    if (lits.empty()) return;
    int overL = -1;
    if (guarded) { overL = newLabel(); b_imm(overL); }
    while ((int)code.size() & 3) u16(0xBF00);       // word-align pool
    int poolStart = (int)code.size();
    for (auto& fx : litFixups) {
        int a = (fx.pos + 4) & ~3;
        int off = poolStart + fx.slot * 4 - a;
        if (off < 0 || off > 1020 || (off & 3)) {
            cerr << "stm32: warning: literal out of LDR range (off=" << off << ")\n";
            off = 0;
        }
        u16pat(code, fx.pos, (uint16_t)(0x4800 | ((fx.rt & 7) << 8) | ((off >> 2) & 0xFF)));
    }
    for (auto& lr : lits) {
        if (lr.kind == LitRef::Const) u32(lr.val);
        else if (lr.kind == LitRef::Str) { strPatch.push_back({(int)code.size(), lr.strIdx}); u32(0); }
        else { funcPatch.push_back({(int)code.size(), lr.func}); u32(0); }
    }
    if (overL >= 0) emitLabel(overL);
    lits.clear();
    litConstMap.clear();
    litFixups.clear();
    lastFlushPos = (int)code.size();
}

void Stm32::resolveBranches(const string& funcName) {
    for (auto& b : branches) {
        int target = labelPositions[b.label];
        int imm = (target - (b.pos + 4)) / 2;
if (b.cond) {
            if (imm < -128 || imm > 127) { cerr << "stm32: Bcc out of range in " << funcName << "\n"; continue; }
            code[b.pos] = (uint8_t)(imm & 0xFF);
        } else {
            if (imm < -1024 || imm > 1023) { cerr << "stm32: B out of range in " << funcName << "\n"; continue; }
            code[b.pos] = (uint8_t)(imm & 0xFF);
            code[b.pos + 1] = (uint8_t)(0xE0 | ((imm >> 8) & 0x7));
        }
    }
}

// =========================================================================
// Per-function state
// =========================================================================
void Stm32::resetFn() {
    code.clear();
    labelPositions.clear();
    branches.clear();
    lits.clear();
    litConstMap.clear();
    litFixups.clear();
    strPatch.clear();
    funcPatch.clear();
    callFixups.clear();
    vars.clear();
    nextLabel = 0;
    brIndex = 0;
    swCur = 0;
    lastFlushPos = 0;
    funcStart = 0;
    tempBytes = 0;
}

static bool isInlineBuiltin(const string& n) {
    // delay_ms is deliberately NOT here: it emits a real BL to the runtime
    // loop, so a function that uses it must save lr (hasCalls == true).
    return n == "gpio_write" || n == "gpio_read" || n == "gpio_set" || n == "gpio_clear" ||
           n == "gpio_toggle" ||
           n == "led_on" || n == "led_off" || n == "led_toggle" || n == "print" ||
           n == "abs" || n == "min" || n == "max" || n == "clamp" || n == "str_len";
}

bool Stm32::scanExprCalls(Expr* e) {
    if (!e) return false;
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        if (!isInlineBuiltin(c->name)) return true;
        for (auto& a : c->args) if (scanExprCalls(a.get())) return true;
        return false;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        if ((b->op == "/" || b->op == "%" || b->op == "//") && !isFloatExpr(b)) return true;
        if (isFloatExpr(b)) return true;
        if (scanExprCalls(b->left.get())) return true;
        return scanExprCalls(b->right.get());
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) return scanExprCalls(u->operand.get());
    if (auto m = dynamic_cast<MemberExpr*>(e)) return scanExprCalls(m->object.get());
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) { if (scanExprCalls(a->array.get())) return true; return scanExprCalls(a->index.get()); }
    if (auto d = dynamic_cast<DerefExpr*>(e)) return scanExprCalls(d->ptr.get());
    return false;
}

bool Stm32::scanStmtCalls(Stmt* s) {
    if (!s) return false;
    if (auto v = dynamic_cast<VarDecl*>(s)) return scanExprCalls(v->init.get());
    if (auto a = dynamic_cast<AssignStmt*>(s)) { if (scanExprCalls(a->value.get())) return true; return scanExprCalls(a->indexExpr.get()); }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) { if (scanExprCalls(pa->ptr.get())) return true; return scanExprCalls(pa->value.get()); }
    if (auto es = dynamic_cast<ExprStmt*>(s)) return scanExprCalls(es->expr.get());
    if (auto r = dynamic_cast<ReturnStmt*>(s)) return scanExprCalls(r->value.get());
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        if (scanExprCalls(ifs->condition.get())) return true;
        for (auto& x : ifs->thenBlock.stmts) if (scanStmtCalls(x.get())) return true;
        for (auto& x : ifs->elseBlock.stmts) if (scanStmtCalls(x.get())) return true;
        return false;
    }
    if (auto ws = dynamic_cast<WhileStmt*>(s)) {
        if (scanExprCalls(ws->condition.get())) return true;
        for (auto& x : ws->body.stmts) if (scanStmtCalls(x.get())) return true;
        return false;
    }
    if (auto ls = dynamic_cast<LoopStmt*>(s)) {
        for (auto& x : ls->body.stmts) if (scanStmtCalls(x.get())) return true;
        return false;
    }
    if (auto fs = dynamic_cast<ForStmt*>(s)) {
        if (scanExprCalls(fs->start.get())) return true;
        if (scanExprCalls(fs->end.get())) return true;
        if (scanExprCalls(fs->step.get())) return true;
        for (auto& x : fs->body.stmts) if (scanStmtCalls(x.get())) return true;
        return false;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        if (scanExprCalls(sw->condition.get())) return true;
        for (auto& cs : sw->cases) {
            if (cs.condition && scanExprCalls(cs.condition.get())) return true;
            for (auto& x : cs.body.stmts) if (scanStmtCalls(x.get())) return true;
        }
        return false;
    }
    return false;
}

bool Stm32::usesCalls(FunctionDecl* f) {
    for (auto& x : f->body.stmts) if (scanStmtCalls(x.get())) return true;
    return false;
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

void Stm32::allocVarSlots(FunctionDecl* f) {
    // ---- D1: live ranges + slot sharing -----------------------------------
    // Each local variable (and for-loop counter) gets a linear [first,last]
    // statement range in program order. Variables whose ranges don't overlap
    // are packed into the same frame words, so the frame shrinks and the
    // stack doesn't grow as fast. (Switch temporaries live above the shared
    // area, so they keep the existing swTempOff scheme untouched.)
    struct LiveVar {
        string name;
        int size = 4;      // bytes, multiple of 4
        int first = 0;     // statement index of the declaration
        int last = 0;      // last statement index mentioning it
        int slot = 0;      // assigned frame offset
        bool used = false; // mentioned at least once
        bool isParam = false;
        Type type;
    };
    unordered_map<string, LiveVar> live;
    for (auto& p : f->params) {
        LiveVar lv; lv.name = p.name; lv.first = 0; lv.last = 0;
        lv.isParam = true; lv.type = p.type;
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
            touch(a->name);                       // write counts as a mention
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

    // C13: every local gets a unique stack slot. Linear-liveness slot sharing
    // is unsafe with loops, nested loops, address-escaped vars, and for end/step
    // reads, so each local owns its own frame words.
    vector<LiveVar*> locals;
    for (auto& kv : live) if (!kv.second.isParam) locals.push_back(&kv.second);
    sort(locals.begin(), locals.end(),
         [](const LiveVar* a, const LiveVar* b) { return a->first < b->first; });
    int off = 0;
    for (auto* lv : locals) {
        off = (off + 3) & ~3;
        lv->slot = off;
        off += (lv->size + 3) & ~3;
    }

    for (auto* lv : locals) {
        off = max(off, lv->slot + lv->size);
        VarInfo32 vi; vi.off = lv->slot; vi.type = lv->type;
        vi.isParam = false; vi.used = lv->used;
        vi.stmtFirst = lv->first; vi.stmtLast = lv->last;
        vars[lv->name] = vi;
    }
    int swCount = 0;
    for (auto& s : f->body.stmts) swCount += stmtSwitchCount(s.get());
    swTempOff = off;
    frameSize = off + swCount * 4;

    // ---- D2: parameters get a frame entry only when actually used --------
    // (unused parameters are simply never read, so no slot is wasted)
    for (int k = 0; k < (int)f->params.size(); k++) {
        auto it = live.find(f->params[k].name);
        if (it == live.end() || !it->second.used) continue;
        VarInfo32 vi; vi.off = savedBytes + frameSize + 4 * k;
        vi.type = f->params[k].type; vi.isParam = true; vi.used = true;
        vars[f->params[k].name] = vi;
    }
}

void Stm32::finalizeFn(FnImg& out) {
    out.bytes = code;
    out.bls = callFixups;
    out.strSlots = strPatch;
    out.funcSlots = funcPatch;
}

bool Stm32::emitFunction(FunctionDecl* f, FnImg& out) {
    // C12: always save LR. usesCalls() can miss runtime BLs (isFloatExpr reads
    // locals that don't exist yet), so every user function pushes/pops {lr}.
    hasCalls = true;
    savedBytes = 4;
    resetFn();
    allocVarSlots(f);
    push(0x00, true);            // push {lr}
    if (frameSize > 0) subSpImm(frameSize);
    retLabel = newLabel();
    emitBlock(f->body, nullptr, nullptr, nullptr);
    b_imm(retLabel);
    emitLabel(retLabel);
    if (frameSize > 0) addSpImm(frameSize);
    pop(0x00, true);             // pop {pc}
    flushPool(false);
    for (auto& b : branches) {
        int target = labelPositions[b.label];
        int imm = (target - (b.pos + 4)) / 2;
        bool oor = b.cond ? (imm < -128 || imm > 127) : (imm < -1024 || imm > 1023);
        if (oor) {
            // C10: the wide-branch trampoline is broken; fail loudly instead of
            // silently generating bad firmware.
            cerr << "stm32: branch out of range in function '" << f->name
                 << "' (function too large); split it into smaller functions\n";
            return false;
        }
    }
    resolveBranches(f->name);
    finalizeFn(out);
    return true;
}// =========================================================================
// Runtime support code (emitted only when needed - C9)
// =========================================================================
void Stm32::emitRuntime(const string& name) {
    resetFn();
    savedBytes = 0;
    frameSize = 0;
    if (name == "__z_delay") {
        int Lout = newLabel(), Linner = newLabel(), Ldone = newLabel();
        uint32_t inner = prog.sysclkHz / 3000;
        if (inner < 1) inner = 1;
        if (inner > 0xFFFF) inner = 0xFFFF;
        cmp_imm(0, 0);
        b_cc(13, Ldone);            // LE: ms <= 0 -> return immediately
        movs(1, 0);                 // r1 = ms
        emitLabel(Lout);
        loadConst(2, inner);
        emitLabel(Linner);
        subs_imm8(2, 1);
        b_cc(1, Linner);
        subs_imm8(1, 1);
        b_cc(1, Lout);
        emitLabel(Ldone);
        bx(LR_REG);
    } else if (name == "__z_delay_us") {
        // r0 = us. Busy-wait on micros() (requires the SysTick clock).
        int Ldw = newLabel(), Ldz = newLabel();
        push(0x30, true);               // push {r4, r5, lr}
        cmp_imm(0, 0);
        b_cc(13, Ldz);                  // LE: us <= 0 -> done
        movs(4, 0);                     // r4 = us
        bl_fixup("__z_micros");         // r0 = start
        adds(5, 0, 4);                  // r5 = start + us
        emitLabel(Ldw);
        bl_fixup("__z_micros");         // r0 = now
        subs(0, 0, 5);                  // r0 = now - end (unsigned)
        b_cc(3, Ldw);                   // CC: now < end -> keep waiting
        emitLabel(Ldz);
        pop(0x30, true);                // pop {r4, r5, pc}
    } else if (name == "__z_millis") {
        auto gm = global("__z_ms");
        if (gm) { loadConst(0, gm->addr); ldr_off(0, 0, 0); }
        bx(LR_REG);
    } else if (name == "__z_micros") {
        // r0 = ms*1000 + (RVR - CVR) / k, where k = ticks per microsecond.
        push(0x00, true);               // push {lr}
        auto gm = global("__z_ms");
        if (gm) { loadConst(0, gm->addr); ldr_off(1, 0, 0); }   // r1 = ms
        loadConst(0, 0xE000E018u); ldr_off(2, 0, 0);            // r2 = CVR
        loadConst(3, systickLoadVal);                           // r3 = LOAD
        subs(3, 3, 2);                                          // r3 = ticks into current ms
        loadConst(2, systickPerUsVal);                          // r2 = k
        movs(0, 3);
        bl_fixup("__z_udiv");                                   // r0 = us in current ms
        movs(2, 0);                                             // r2 = us
        movs(0, 1);                                             // r0 = ms
        loadConst(3, 1000);
        muls(0, 3);                                             // r0 = ms*1000
        adds(0, 0, 2);                                          // r0 = ms*1000 + us
        pop(0x00, true);                                        // pop {pc}
    } else if (name == "__z_systick_isr") {
        // 1 kHz SysTick handler: bump the __z_ms counter (reloads automatically).
        push(0x00, true);               // push {lr}
        auto gm = global("__z_ms");
        if (gm) {
            loadConst(0, gm->addr); ldr_off(1, 0, 0);
            movs_imm(2, 1); adds(1, 1, 2);
            str_off(1, 0, 0);
        }
        pop(0x00, true);                // pop {pc}
    } else if (name == "__z_pwm") {
        // r0 = duty (0..100), r1 = period us. Bit-bangs ONE period: high for
        // period*duty/100 us, then low for the rest (uses BSRR set/clear).
        int Lpdone = newLabel();
        push(0x30, true);               // push {r4, r5, lr}
        cmp_imm(0, 0);
        b_cc(13, Lpdone);               // duty <= 0 -> nothing
        movs(4, 0);                     // r4 = duty
        movs(5, 1);                     // r5 = period
        movs(0, 5); muls(0, 4);         // r0 = period * duty
        loadConst(1, 100);
        bl_fixup("__z_udiv");           // r0 = high_us
        movs(3, 0);                     // r3 = high_us
        auto gb = global("__z_pwm_bsrr");
        auto gt = global("__z_pwm_bit");
        if (gb && gt) {                 // BSRR = bit  -> high
            loadConst(0, gb->addr); ldr_off(1, 0, 0);
            loadConst(0, gt->addr); ldr_off(2, 0, 0);
            str_off(2, 1, 0);
        }
        movs(0, 3);
        bl_fixup("__z_delay_us");       // wait the high phase
        if (gb && gt) {                 // BSRR = bit << 16 -> low
            loadConst(0, gb->addr); ldr_off(1, 0, 0);
            loadConst(0, gt->addr); ldr_off(2, 0, 0);
            lsls_imm(2, 2, 16);
            str_off(2, 1, 0);
        }
        movs(0, 5); subs(0, 0, 3);      // r0 = period - high_us
        bl_fixup("__z_delay_us");       // wait the low phase
        emitLabel(Lpdone);
        pop(0x30, true);                // pop {r4, r5, pc}
    } else if (name == "__z_pulse_in") {
        // r0 = level (0/1), r1 = timeout us. Waits until the pin matches level,
        // then times the pulse until it changes; returns width in us or -1.
        int Lwait = newLabel(), Lmeas = newLabel(), Lms = newLabel(), Lto = newLabel();
        push(0x70, true);               // push {r4, r5, r6, lr}
        auto gidr = global("__z_pulse_idr");
        auto gbit = global("__z_pulse_bit");
        movs(4, 0);                     // r4 = level
        movs(5, 1);                     // r5 = timeout
        bl_fixup("__z_micros");
        adds(6, 0, 5);                  // r6 = deadline
        emitLabel(Lwait);
        bl_fixup("__z_micros");         // r0 = now
        subs(0, 0, 6);                  // now - deadline
        b_cc(2, Lto);                   // CS (now >= deadline) -> timeout
        if (gidr && gbit) {
            loadConst(0, gidr->addr); ldr_off(1, 0, 0);
            loadConst(0, gbit->addr); ldr_off(2, 0, 0);
            ands(1, 2); cmp_imm(1, 0);
            ite(1); movs_imm(3, 1); movs_imm(3, 0);   // r3 = bit ? 1 : 0
            cmps(3, 4);
            b_cc(0, Lmeas);             // EQ: pin == level -> start measuring
        }
        b_imm(Lwait);
        emitLabel(Lto);
        loadConst(0, 0xFFFFFFFFu);      // r0 = -1 (timeout)
        pop(0x70, true);                // pop {r4, r5, r6, pc}
        emitLabel(Lmeas);
        bl_fixup("__z_micros");
        movs(5, 0);                     // r5 = t_start
        emitLabel(Lms);
        bl_fixup("__z_micros");         // r0 = now
        movs(6, 0);                     // r6 = now (in case of loop exit)
        if (gidr && gbit) {
            loadConst(0, gidr->addr); ldr_off(1, 0, 0);
            loadConst(0, gbit->addr); ldr_off(2, 0, 0);
            ands(1, 2); cmp_imm(1, 0);
            ite(1); movs_imm(3, 1); movs_imm(3, 0);
            cmps(3, 4);
            b_cc(0, Lms);               // EQ: still same level -> keep polling
        }
        subs(0, 6, 5);                  // r0 = now - t_start
        pop(0x70, true);                // pop {r4, r5, r6, pc}
    } else if (name == "__z_udiv") {
        // r0=num, r1=den -> r0=quot, r3=rem (unsigned)
        int Lok = newLabel(), Lskip = newLabel(), Ltop = newLabel();
        push(0x00, true);           // push {lr}
        movs_imm(3, 0);             // remainder = 0
        cmp_imm(1, 0);
        b_cc(1, Lok);               // NE -> denominator nonzero
        movs_imm(0, 0);
        pop(0x00, true);            // pop {pc}
        emitLabel(Lok);
        movs_imm(2, 32);
        emitLabel(Ltop);
        lsls_imm(0, 0, 1);          // num <<= 1 (MSB -> C)
        adcs(3, 3);                 // r3 = r3 + r3 + C
        cmps(3, 1);
        b_cc(3, Lskip);             // rem < den
        subs(3, 3, 1);              // rem -= den
        adds_imm8(0, 1);            // set quotient bit
        emitLabel(Lskip);
        subs_imm8(2, 1);
        b_cc(1, Ltop);
        pop(0x00, true);
    } else if (name == "__z_div") {
        // r0=a, r1=b -> r0 = a/b (signed, trunc toward zero)
        int L2 = newLabel(), L3 = newLabel(), L4 = newLabel();
        push(0x20, true);           // push {r5, lr}
        movs_imm(5, 0);
        cmp_imm(0, 0);
        b_cc(10, L2);               // GE
        rsbs(0, 0);
        adds_imm8(5, 1);
        emitLabel(L2);
        cmp_imm(1, 0);
        b_cc(10, L3);
        rsbs(1, 1);
        adds_imm8(5, 1);
        emitLabel(L3);
        bl_fixup("__z_udiv");
        cmp_imm(5, 1);
        b_cc(1, L4);
        rsbs(0, 0);
        emitLabel(L4);
        pop(0x20, true);            // pop {r5, pc}
    } else if (name == "__z_mod") {
        // r0=a, r1=b -> r0 = a%b (sign of a)
        int L2 = newLabel(), L3 = newLabel(), L4 = newLabel();
        push(0x20, true);
        movs_imm(5, 0);
        cmp_imm(0, 0);
        b_cc(10, L2);
        rsbs(0, 0);
        adds_imm8(5, 1);
        emitLabel(L2);
        cmp_imm(1, 0);
        b_cc(10, L3);
        rsbs(1, 1);
        emitLabel(L3);
        bl_fixup("__z_udiv");
        movs(0, 3);                 // r0 = remainder
        cmp_imm(5, 1);
        b_cc(1, L4);
        rsbs(0, 0);
        emitLabel(L4);
        pop(0x20, true);
    } else if (name == "__z_i2f") {
        lsls_imm(0, 0, 16);         // Q16.16: int << 16
        bx(LR_REG);
    } else if (name == "__z_fadd") {
        adds(0, 0, 1);
        bx(LR_REG);
    } else if (name == "__z_fsub") {
        subs(0, 0, 1);
        bx(LR_REG);
    } else if (name == "__z_fmul") {
        // Q16.16 multiply: result = (a*b) >> 16, computed 32x32 -> 64 with the
        // 16-bit half decomposition (works on M0/M0+ which lack umull).
        //   a = aH:aL  b = bH:bL   ->  result = aH*bH<<16 + aH*bL + aL*bH + (aL*bL>>16)
        push(0xF0, true);               // push {r4-r7, lr}
        movs(6, 0);                     // r6 = a
        movs(7, 1);                     // r7 = b
        lsrs_imm(0, 6, 16);             // r0 = aH
        lsrs_imm(1, 7, 16);             // r1 = bH
        lsls_imm(2, 6, 16); lsrs_imm(2, 2, 16);  // r2 = aL
        lsls_imm(3, 7, 16); lsrs_imm(3, 3, 16);  // r3 = bL
        movs(4, 2); muls(4, 3);         // r4 = aL*bL
        movs(5, 2); muls(5, 1);         // r5 = aL*bH
        movs(6, 0); muls(6, 3);         // r6 = aH*bL
        movs(7, 0); muls(7, 1);         // r7 = aH*bH
        lsrs_imm(4, 4, 16);             // r4 = (aL*bL)>>16
        adds(5, 5, 6);                  // r5 = aL*bH + aH*bL
        adds(5, 5, 4);                  // r5 += (aL*bL)>>16
        lsls_imm(7, 7, 16);             // r7 = aH*bH<<16
        adds(0, 5, 7);                  // r0 = result
        pop(0xF0, true);                // pop {r4-r7, pc}
    } else if (name == "__z_fdiv") {
        int L2 = newLabel(), L3 = newLabel(), L4 = newLabel();
        push(0x20, true);
        movs_imm(5, 0);
        cmp_imm(0, 0);
        b_cc(10, L2);
        rsbs(0, 0);
        adds_imm8(5, 1);
        emitLabel(L2);
        cmp_imm(1, 0);
        b_cc(10, L3);
        rsbs(1, 1);
        adds_imm8(5, 1);
        emitLabel(L3);
        lsls_imm(0, 0, 16);
        bl_fixup("__z_udiv");
        cmp_imm(5, 1);
        b_cc(1, L4);
        rsbs(0, 0);
        emitLabel(L4);
        pop(0x20, true);
    } else if (name == "__z_fcmp") {
        int Lge = newLabel(), Leq = newLabel();
        cmps(0, 1);
        b_cc(10, Lge);              // GE
        movs_imm(0, 0);
        mvns(0, 0);                 // r0 = -1
        bx(LR_REG);
        emitLabel(Lge);
        b_cc(0, Leq);               // EQ
        movs_imm(0, 1);
        bx(LR_REG);
        emitLabel(Leq);
        movs_imm(0, 0);
        bx(LR_REG);
    } else if (name == "__z_uart_tx") {
        // Bit-banged UART TX, one byte in r0. Globals written by uart_init():
        //   __z_uart_bsrr = BSRR register address of the port
        //   __z_uart_bit  = (1 << pin) bitmask
        //   __z_uart_half = half-bit delay-loop iterations
        // Frame: 1 start bit (low), 8 data bits LSB first, 1 stop bit (high).
        push(0xF0, true);               // push {r4-r7, lr}
        auto gb  = global("__z_uart_bsrr");
        auto gbt = global("__z_uart_bit");
        auto gh  = global("__z_uart_half");
        if (gb)  { loadConst(1, gb->addr);  ldr_off(1, 1, 0); }
        if (gbt) { loadConst(2, gbt->addr); ldr_off(2, 2, 0); }
        if (gh)  { loadConst(3, gh->addr);  ldr_off(3, 3, 0); }
        // --- start bit (drive low) ---
        lsls_imm(5, 2, 16);             // r5 = bit << 16 (clear bit in BSRR)
        str_off(5, 1, 0);
        // wait one full bit (two halves)
        movs(6, 3);
        int Lu1 = newLabel();
        emitLabel(Lu1);
        subs_imm8(6, 1);
        b_cc(1, Lu1);
        movs(6, 3);
        int Lu2 = newLabel();
        emitLabel(Lu2);
        subs_imm8(6, 1);
        b_cc(1, Lu2);
        // --- 8 data bits, LSB first ---
        movs_imm(7, 0);                 // bit counter
        movs_imm(4, 1);                 // data mask
        int Lbit = newLabel();
        emitLabel(Lbit);
        lsls_imm(6, 2, 16);             // r6 = low value (bit << 16), computed before flags
        movs(5, 0);                     // r5 = byte
        ands(5, 4);                     // r5 = byte & mask
        cmp_imm(5, 0);
        ite(1);                         // ITE NE
        movs(5, 2);                     // NE: drive high
        movs(5, 6);                     // EQ: drive low
        str_off(5, 1, 0);
        // wait two half-bits
        movs(6, 3);
        int Ld1 = newLabel();
        emitLabel(Ld1);
        subs_imm8(6, 1);
        b_cc(1, Ld1);
        movs(6, 3);
        int Ld2 = newLabel();
        emitLabel(Ld2);
        subs_imm8(6, 1);
        b_cc(1, Ld2);
        adds_imm8(7, 1);
        lsls_imm(4, 4, 1);              // r4 = mask << 1 (advance to next data bit)
        cmp_imm(7, 8);
        b_cc(1, Lbit);                  // NE -> next bit
        // --- stop bit (drive high) ---
        str_off(2, 1, 0);
        movs(6, 3);
        int Ls1 = newLabel();
        emitLabel(Ls1);
        subs_imm8(6, 1);
        b_cc(1, Ls1);
        movs(6, 3);
        int Ls2 = newLabel();
        emitLabel(Ls2);
        subs_imm8(6, 1);
        b_cc(1, Ls2);
        pop(0xF0, true);                // pop {r4-r7, pc}
    } else if (name == "__z_uart_str") {
        // r0 = pointer to a NUL-terminated string; send it byte by byte.
        push(0x10, true);               // push {r4, lr}
        movs(4, 0);                     // r4 = pointer
        int Ls = newLabel(), LsEnd = newLabel();
        emitLabel(Ls);
        ldrb_off(0, 4, 0);
        cmp_imm(0, 0);
        b_cc(0, LsEnd);                 // EQ
        bl_fixup("__z_uart_tx");
        adds_imm8(4, 1);
        b_imm(Ls);
        emitLabel(LsEnd);
        pop(0x10, true);                // pop {r4, pc}
    } else if (name == "__z_uart_int") {
        // r0 = int32; send its decimal representation (with '-' if negative).
        // Digits are built right-to-left in __z_uart_buf, then sent via __z_uart_tx.
        push(0xF0, true);               // push {r4-r7, lr}
        auto gbuf = global("__z_uart_buf");
        uint32_t bufAddr = gbuf ? gbuf->addr : 0x20000000u;
        movs(4, 0);                     // r4 = value
        movs_imm(2, 0);                 // r2 = negative flag
        cmp_imm(4, 0);
        int Lge = newLabel();
        b_cc(10, Lge);                  // GE
        rsbs(4, 4);                     // value = -value
        adds_imm8(2, 1);                // neg = 1
        emitLabel(Lge);
        loadConst(5, bufAddr + 15);     // r5 = end of the 16-byte buffer
        movs_imm(7, 10);                // r7 = divisor
        movs_imm(6, 0);                 // r6 = digit count
        int Lito = newLabel();
        emitLabel(Lito);
        movs(0, 4);
        movs(1, 7);
        bl_fixup("__z_udiv");           // r0 = quot, r3 = rem
        adds_imm8(3, 48);               // rem -> ASCII digit
        subs_imm8(5, 1);
        strb_off(3, 5, 0);
        adds_imm8(6, 1);
        movs(4, 0);                     // value = quotient
        cmp_imm(4, 0);
        b_cc(1, Lito);                  // NE
        cmp_imm(2, 0);
        int Lneg = newLabel();
        b_cc(0, Lneg);                  // EQ
        subs_imm8(5, 1);
        movs_imm(3, '-');
        strb_off(3, 5, 0);
        adds_imm8(6, 1);
        emitLabel(Lneg);
        int Lsend = newLabel(), LsEnd = newLabel();
        emitLabel(Lsend);
        cmp_imm(6, 0);
        b_cc(13, LsEnd);                // LE
        ldrb_off(0, 5, 0);
        adds_imm8(5, 1);
        subs_imm8(6, 1);
        bl_fixup("__z_uart_tx");
        b_imm(Lsend);
        emitLabel(LsEnd);
        pop(0xF0, true);                // pop {r4-r7, pc}
    } else if (name == "__z_adc_init") {
        // Hardware ADC1 init (STM32F1/F4/F7): clock enable, prescaler, calibration.
        bool f1 = (fam == McuFamily::F1);
        uint32_t adcBase   = f1 ? 0x40012400u : 0x40012000u;
        uint32_t adcEnReg  = f1 ? 0x40021018u : 0x40023844u; // APB2ENR (F1) / (F4)
        uint32_t adcEnBit  = f1 ? 9u : 8u;
        uint32_t prescReg  = f1 ? 0x40021004u : 0x4002382Cu; // CFGR (F1) / CFGR2 (F4)
        uint32_t prescShift = f1 ? 14u : 30u;
        uint32_t maxClk    = f1 ? 14000000u : 36000000u;     // F1: 14 MHz, F4: 36 MHz
        uint32_t pclk = prog.sysclkHz;
        uint32_t div = 2, k = 0;
        while (div <= 8 && pclk / div > maxClk) { div += 2; k++; }
        if (k > 3) k = 3;
        loadConst(0, adcEnReg);
        ldr_off(1, 0, 0);
        loadConst(2, 1u << adcEnBit);
        orrs(1, 2);
        str_off(1, 0, 0);
        loadConst(0, prescReg);
        ldr_off(1, 0, 0);
        loadConst(2, 3u << prescShift);
        bics(1, 2);
        loadConst(2, k << prescShift);
        orrs(1, 2);
        str_off(1, 0, 0);
        loadConst(0, adcBase + 0x08u);  // CR2: ADON = 1
        ldr_off(1, 0, 0);
        loadConst(2, 1u);
        orrs(1, 2);
        str_off(1, 0, 0);
        loadConst(2, 1u << 3);          // RSTCAL
        orrs(1, 2);
        str_off(1, 0, 0);
        int Lc1 = newLabel();
        emitLabel(Lc1);
        ldr_off(1, 0, 0);
        loadConst(2, 1u << 3);
        ands(1, 2);
        cmp_imm(1, 0);
        b_cc(1, Lc1);                   // NE -> still calibrating
        loadConst(2, 1u << 2);          // CAL
        orrs(1, 2);
        str_off(1, 0, 0);
        int Lc2 = newLabel();
        emitLabel(Lc2);
        ldr_off(1, 0, 0);
        loadConst(2, 1u << 2);
        ands(1, 2);
        cmp_imm(1, 0);
        b_cc(1, Lc2);                   // NE -> still calibrating
        loadConst(2, 1u);               // ADON = 1 again (ready)
        orrs(1, 2);
        str_off(1, 0, 0);
        bx(LR_REG);
    } else if (name == "__z_adc_read") {
        // r0 = channel (0..15); returns the 12-bit sample in r0 (blocking).
        bool f1 = (fam == McuFamily::F1);
        uint32_t adcBase = f1 ? 0x40012400u : 0x40012000u;
        push(0x10, true);               // push {r4, lr}
        movs(4, 0);                     // r4 = channel
        adds(2, 4, 4);                  // r2 = 3 * channel
        adds(2, 2, 4);
        int Lch10 = newLabel(), Lsmp = newLabel();
        cmp_imm(4, 10);
        b_cc(2, Lch10);                 // CS -> channel >= 10
        loadConst(1, adcBase + 0x10u);  // SMPR2 (channels 0..9)
        b_imm(Lsmp);
        emitLabel(Lch10);
        movs(5, 4);
        subs_imm8(5, 10);               // r5 = channel - 10
        adds(2, 5, 5);                  // r2 = 3 * (channel - 10)
        adds(2, 2, 5);
        loadConst(1, adcBase + 0x0Cu);  // SMPR1 (channels 10..15)
        emitLabel(Lsmp);
        movs_imm(5, 7);
        lsls_reg(5, 2);                 // r5 = 7 << shift
        ldr_off(3, 1, 0);
        bics(3, 5);
        movs_imm(0, 5);
        lsls_reg(0, 2);                 // r0 = 5 << shift (>=55 cycle sample time)
        orrs(3, 0);
        str_off(3, 1, 0);
        loadConst(1, adcBase + 0x34u);  // SQR3: SQ1 = channel
        ldr_off(3, 1, 0);
        loadConst(0, 0x1Fu);
        bics(3, 0);
        movs(0, 4);
        orrs(3, 0);
        str_off(3, 1, 0);
        loadConst(1, adcBase + 0x08u);  // CR2: SWSTART = 1
        ldr_off(3, 1, 0);
        loadConst(0, 1u << 22);
        orrs(3, 0);
        str_off(3, 1, 0);
        int Leoc = newLabel();
        emitLabel(Leoc);
        loadConst(1, adcBase + 0x00u);  // SR: wait EOC
        ldr_off(3, 1, 0);
        loadConst(0, 2u);
        ands(3, 0);
        cmp_imm(3, 0);
        b_cc(0, Leoc);                  // EQ -> not ready
        loadConst(0, adcBase + 0x4Cu);  // DR
        ldr_off(0, 0, 0);
        pop(0x10, true);                // pop {r4, pc}
} else if (name == "__z_uart_rx") {
        // Polled RX bit machine, one step per call (call every loop iteration).
        // Globals: __z_uart_rx_idr/bit/half (config), st (0 idle / 1 in frame),
        // bits (data samples left), wait2 (half-steps until the next sample),
        // byte (byte being assembled), done (1 when a full byte is available).
        // Edge-locked sampling: 1.5 bit wait after the start edge, then 8
        // samples 1.5 bits apart (bit centers), then done.
        push(0xF0, true);               // push {r4-r7, lr}
        auto gst  = global("__z_uart_rx_st");
        auto gbts = global("__z_uart_rx_bits");
        auto gwt  = global("__z_uart_rx_wait2");
        auto gbt  = global("__z_uart_rx_byte");
        auto gdn  = global("__z_uart_rx_done");
        auto gidr = global("__z_uart_rx_idr");
        auto gbit = global("__z_uart_rx_bit");
        auto gh   = global("__z_uart_rx_half");
        if (!gst || !gbts || !gwt || !gbt || !gdn || !gidr || !gbit || !gh) {
            pop(0xF0, true);
        } else {
            loadConst(0, gst->addr);  ldr_off(4, 0, 0);   // r4 = st
            loadConst(0, gbt->addr);  ldr_off(5, 0, 0);   // r5 = byte
            loadConst(0, gbts->addr); ldr_off(6, 0, 0);   // r6 = bits
            loadConst(0, gwt->addr);  ldr_off(7, 0, 0);   // r7 = wait2
            int LrxIdle = newLabel(), LrxW = newLabel();
            int LrxSample = newLabel(), LrxZero = newLabel();
            int LrxDone = newLabel(), LrxAbort = newLabel(), LrxRet = newLabel();
            cmp_imm(4, 0);
            b_cc(0, LrxIdle);               // EQ -> idle
            // in frame: wait one half-bit
            loadConst(0, gh->addr);  ldr_off(0, 0, 0);
            emitLabel(LrxW);
            subs_imm8(0, 1);
            b_cc(1, LrxW);
            subs_imm8(7, 1);                // wait2--
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            cmp_imm(7, 0);
            b_cc(0, LrxSample);             // EQ -> sample now
            cmp_imm(7, 2);
            b_cc(1, LrxRet);                // NE -> nothing else this call
            cmp_imm(6, 8);
            b_cc(1, LrxRet);                // NE -> not the start-bit verify
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            cmp_imm(0, 0);
            b_cc(0, LrxAbort);              // EQ -> high: false start
            b_imm(LrxRet);
            emitLabel(LrxAbort);
            movs_imm(4, 0);
            loadConst(0, gst->addr); str_off(4, 0, 0);
            movs_imm(6, 0);
            loadConst(0, gbts->addr); str_off(6, 0, 0);
            movs_imm(7, 0);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            b_imm(LrxRet);
            emitLabel(LrxSample);
            // sample one data bit: byte = (byte >> 1) | (bit ? 0x80 : 0)
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            lsrs_imm(5, 5, 1);
            cmp_imm(0, 0);
            b_cc(0, LrxZero);               // EQ -> bit was 0
            movs_imm(0, 0x80);
            orrs(5, 0);
            emitLabel(LrxZero);
            loadConst(0, gbt->addr); str_off(5, 0, 0);
            subs_imm8(6, 1);
            loadConst(0, gbts->addr); str_off(6, 0, 0);
            cmp_imm(6, 0);
            b_cc(0, LrxDone);               // EQ -> all 8 bits sampled
            movs_imm(7, 3);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            b_imm(LrxRet);
            emitLabel(LrxDone);
            movs_imm(4, 0);
            loadConst(0, gst->addr); str_off(4, 0, 0);
            movs_imm(7, 0);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            loadConst(0, gdn->addr); movs_imm(1, 1); str_off(1, 0, 0);
            b_imm(LrxRet);
            emitLabel(LrxIdle);
            // idle: sample without waiting (catches the edge within ~ns)
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            cmp_imm(0, 0);
            b_cc(0, LrxRet);                // EQ -> line high, stay idle
            movs_imm(4, 1); movs_imm(6, 8); movs_imm(7, 3); movs_imm(5, 0);
            loadConst(0, gst->addr);  str_off(4, 0, 0);
            loadConst(0, gbts->addr); str_off(6, 0, 0);
            loadConst(0, gwt->addr);  str_off(7, 0, 0);
            loadConst(0, gbt->addr);  str_off(5, 0, 0);
            emitLabel(LrxRet);
            pop(0xF0, true);
        }
    } else if (name == "__z_uart_rx_await") {
        // r0 = timeout in ms. Polls __z_uart_rx until a byte is ready or the
        // timeout expires; returns the byte, or -1 (0xFFFFFFFF) on timeout.
        push(0xF0, true);               // push {r4-r7, lr}
        auto gdn = global("__z_uart_rx_done");
        auto gbt = global("__z_uart_rx_byte");
        uint32_t inner = prog.sysclkHz / 3000;
        if (inner < 1) inner = 1;
        if (inner > 0xFFFF) inner = 0xFFFF;
        movs(4, 0);                     // r4 = ms
        int LawO = newLabel(), LawI = newLabel(), LawG = newLabel(), LawT = newLabel();
        emitLabel(LawO);
        cmp_imm(4, 0);
        b_cc(13, LawT);                 // LE -> timeout
        loadConst(5, inner);
        emitLabel(LawI);
        bl_fixup("__z_uart_rx");
        loadConst(0, gdn->addr); ldr_off(0, 0, 0);
        cmp_imm(0, 0);
        b_cc(1, LawG);                  // NE -> byte ready
        subs_imm8(5, 1);
        b_cc(1, LawI);
        subs_imm8(4, 1);
        b_imm(LawO);
        emitLabel(LawG);
        loadConst(0, gbt->addr); ldr_off(0, 0, 0);
        loadConst(1, gdn->addr); movs_imm(2, 0); str_off(2, 1, 0);
        pop(0xF0, true);
        emitLabel(LawT);
        loadConst(0, 0xFFFFFFFFu);
        pop(0xF0, true);
    } else if (name == "__z_i2c_delay") {
        // Half-period delay for the I2C bit-bang (clobbers r6 only).
        auto gh = global("__z_i2c_half");
        int Ld = newLabel();
        loadConst(0, gh->addr); ldr_off(6, 0, 0);
        emitLabel(Ld);
        subs_imm8(6, 1);
        b_cc(1, Ld);
        bx(LR_REG);
    } else if (name == "__z_i2c_start") {
        // START: SDA falls while SCL high (open-drain: set = release/high).
        push(0xF0, true);               // push {r4-r7, lr}
        auto gsda_b = global("__z_i2c_sda_bsrr");
        auto gsda_t = global("__z_i2c_sda_bit");
        auto gscl_b = global("__z_i2c_scl_bsrr");
        auto gscl_t = global("__z_i2c_scl_bit");
        if (!gsda_b || !gsda_t || !gscl_b || !gscl_t) {
            pop(0xF0, true);
        } else {
            loadConst(0, gsda_b->addr); ldr_off(4, 0, 0);   // r4 = SDA BSRR
            loadConst(0, gsda_t->addr); ldr_off(5, 0, 0);   // r5 = SDA bit
            loadConst(0, gscl_b->addr); ldr_off(6, 0, 0);   // r6 = SCL BSRR
            loadConst(0, gscl_t->addr); ldr_off(7, 0, 0);   // r7 = SCL bit
            str_off(7, 6, 0);           // SCL high
            str_off(5, 4, 0);           // SDA high
            bl_fixup("__z_i2c_delay");
            lsls_imm(0, 5, 16);         // SDA low (BSRR reset bit)
            str_off(0, 4, 0);
            bl_fixup("__z_i2c_delay");
            lsls_imm(0, 7, 16);         // SCL low
            str_off(0, 6, 0);
            bl_fixup("__z_i2c_delay");
            pop(0xF0, true);
        }
    } else if (name == "__z_i2c_stop") {
        // STOP: SDA rises while SCL high.
        push(0xF0, true);
        auto gsda_b = global("__z_i2c_sda_bsrr");
        auto gsda_t = global("__z_i2c_sda_bit");
        auto gscl_b = global("__z_i2c_scl_bsrr");
        auto gscl_t = global("__z_i2c_scl_bit");
        if (!gsda_b || !gsda_t || !gscl_b || !gscl_t) {
            pop(0xF0, true);
        } else {
            loadConst(0, gsda_b->addr); ldr_off(4, 0, 0);
            loadConst(0, gsda_t->addr); ldr_off(5, 0, 0);
            loadConst(0, gscl_b->addr); ldr_off(6, 0, 0);
            loadConst(0, gscl_t->addr); ldr_off(7, 0, 0);
            lsls_imm(0, 7, 16);         // SCL low
            str_off(0, 6, 0);
            lsls_imm(0, 5, 16);         // SDA low
            str_off(0, 4, 0);
            bl_fixup("__z_i2c_delay");
            str_off(7, 6, 0);           // SCL high
            bl_fixup("__z_i2c_delay");
            str_off(5, 4, 0);           // SDA high
            bl_fixup("__z_i2c_delay");
            pop(0xF0, true);
        }
    } else if (name == "__z_i2c_w8") {
        // Write 8 bits MSB first + read ACK. r0 = byte -> r0 = 1 (ACK) / 0.
        push(0xF0, true);
        auto gsda_b = global("__z_i2c_sda_bsrr");
        auto gsda_t = global("__z_i2c_sda_bit");
        auto gscl_b = global("__z_i2c_scl_bsrr");
        auto gscl_t = global("__z_i2c_scl_bit");
        auto gidr = global("__z_i2c_sda_idr");
        if (!gsda_b || !gsda_t || !gscl_b || !gscl_t || !gidr) {
            pop(0xF0, true);
        } else {
            loadConst(0, gsda_b->addr); ldr_off(4, 0, 0);   // r4 = SDA BSRR
            loadConst(0, gsda_t->addr); ldr_off(5, 0, 0);   // r5 = SDA bit
            loadConst(0, gscl_b->addr); ldr_off(6, 0, 0);   // r6 = SCL BSRR
            loadConst(0, gscl_t->addr); ldr_off(7, 0, 0);   // r7 = SCL bit
            movs_imm(2, 8);             // bit counter
            int Lw = newLabel(), Lw1 = newLabel(), Lw2 = newLabel();
            int LwAck = newLabel(), LwEnd = newLabel();
            emitLabel(Lw);
            // SDA = (byte >> 7) & 1
            movs(3, 0);
            lsrs_imm(3, 3, 7);
            cmp_imm(3, 0);
            b_cc(0, Lw1);               // EQ -> bit 0: drive low
            str_off(5, 4, 0);           // bit 1: release (high)
            b_imm(Lw2);
            emitLabel(Lw1);
            lsls_imm(3, 5, 16);         // drive low
            str_off(3, 4, 0);
            emitLabel(Lw2);
            str_off(7, 6, 0);           // SCL high
            bl_fixup("__z_i2c_delay");
            lsls_imm(3, 7, 16);         // SCL low
            str_off(3, 6, 0);
            bl_fixup("__z_i2c_delay");
            lsls_imm(0, 0, 1);          // byte <<= 1
            subs_imm8(2, 1);
            b_cc(1, Lw);
            // ACK: release SDA, SCL high, read SDA
            str_off(5, 4, 0);
            str_off(7, 6, 0);
            bl_fixup("__z_i2c_delay");
            loadConst(0, gidr->addr); ldr_off(3, 0, 0);
            loadConst(0, gsda_t->addr); ldr_off(0, 0, 0);
            ands(3, 0);                 // r3 = SDA & bit (0 = ACK)
            lsls_imm(0, 7, 16);         // SCL low
            str_off(0, 6, 0);
            cmp_imm(3, 0);
            b_cc(0, LwAck);             // EQ -> ACK
            movs_imm(0, 0);             // NACK
            b_imm(LwEnd);
            emitLabel(LwAck);
            movs_imm(0, 1);
            emitLabel(LwEnd);
            pop(0xF0, true);
        }
    } else if (name == "__z_i2c_r8") {
        // Read 8 bits MSB first + send ACK/NACK. r0 = ack (0 = ACK, 1 = NACK)
        // -> r0 = byte read.
        push(0xF0, true);
        push(0x01, false);              // save ack param
        auto gsda_b = global("__z_i2c_sda_bsrr");
        auto gsda_t = global("__z_i2c_sda_bit");
        auto gscl_b = global("__z_i2c_scl_bsrr");
        auto gscl_t = global("__z_i2c_scl_bit");
        auto gidr = global("__z_i2c_sda_idr");
        if (!gsda_b || !gsda_t || !gscl_b || !gscl_t || !gidr) {
            pop(0x01, false);
            pop(0xF0, true);
        } else {
            loadConst(0, gsda_b->addr); ldr_off(4, 0, 0);
            loadConst(0, gsda_t->addr); ldr_off(5, 0, 0);
            loadConst(0, gscl_b->addr); ldr_off(6, 0, 0);
            loadConst(0, gscl_t->addr); ldr_off(7, 0, 0);
            movs_imm(2, 8);             // bit counter
            movs_imm(1, 0);             // r1 = byte
            int Lr = newLabel(), Lr1 = newLabel();
            int LrAck = newLabel(), Lr2 = newLabel();
            emitLabel(Lr);
            str_off(5, 4, 0);           // release SDA
            str_off(7, 6, 0);           // SCL high
            bl_fixup("__z_i2c_delay");
            loadConst(0, gidr->addr); ldr_off(3, 0, 0);
            loadConst(0, gsda_t->addr); ldr_off(0, 0, 0);
            ands(3, 0);
            lsls_imm(1, 1, 1);          // byte <<= 1
            cmp_imm(3, 0);
            b_cc(0, Lr1);               // EQ -> bit 0
            adds_imm8(1, 1);            // set bit 0
            emitLabel(Lr1);
            lsls_imm(3, 7, 16);         // SCL low
            str_off(3, 6, 0);
            bl_fixup("__z_i2c_delay");
            subs_imm8(2, 1);
            b_cc(1, Lr);
            // ACK/NACK phase: r0 = ack (0 = ACK -> drive low)
            pop(0x01, false);
            cmp_imm(0, 0);
            b_cc(0, LrAck);             // EQ -> ACK
            str_off(5, 4, 0);           // NACK: release SDA
            b_imm(Lr2);
            emitLabel(LrAck);
            lsls_imm(3, 5, 16);         // ACK: drive SDA low
            str_off(3, 4, 0);
            emitLabel(Lr2);
            str_off(7, 6, 0);           // SCL high
            bl_fixup("__z_i2c_delay");
            lsls_imm(3, 7, 16);         // SCL low
            str_off(3, 6, 0);
            movs(0, 1);                 // r0 = byte
            pop(0xF0, true);
        }
    } else if (name == "__z_i2c_scan") {
        // Return the first device address (1..0x7F) that ACKs, or 0.
        push(0xF0, true);
        movs_imm(4, 1);                 // r4 = addr
        int Lsc = newLabel(), LscF = newLabel(), LscN = newLabel();
        emitLabel(Lsc);
        cmp_imm(4, 0x80);
        b_cc(2, LscF);                  // CS: addr >= 0x80 -> done
        movs(0, 4);
        lsls_imm(0, 0, 1);              // addr << 1 (write)
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LscN);                  // EQ -> NACK, try next
        bl_fixup("__z_i2c_stop");
        movs(0, 4);
        pop(0xF0, true);
        emitLabel(LscN);
        bl_fixup("__z_i2c_stop");
        adds_imm8(4, 1);
        b_imm(Lsc);
        emitLabel(LscF);
        movs_imm(0, 0);
        pop(0xF0, true);
    } else if (name == "__z_i2c_write_reg") {
        // r0 = addr7, r1 = reg, r2 = val -> r0 = 1 (ok) / 0 (NACK).
        push(0xF0, true);
        movs(4, 0);                     // r4 = addr
        movs(5, 1);                     // r5 = reg
        movs(6, 2);                     // r6 = val
        int LwrN = newLabel();
        lsls_imm(0, 4, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LwrN);                  // EQ -> NACK
        movs(0, 5);
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LwrN);
        movs(0, 6);
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LwrN);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 1);
        pop(0xF0, true);
        emitLabel(LwrN);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 0);
        pop(0xF0, true);
    } else if (name == "__z_i2c_read_reg") {
        // r0 = addr7, r1 = reg -> r0 = byte, or 0xFF on NACK.
        push(0xF0, true);
        movs(4, 0);
        movs(5, 1);
        int LrrN = newLabel();
        lsls_imm(0, 4, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LrrN);
        movs(0, 5);
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LrrN);
        lsls_imm(0, 4, 1);              // restart: addr << 1 | 1
        adds_imm8(0, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LrrN);
        movs_imm(0, 1);                 // NACK (last byte)
        bl_fixup("__z_i2c_r8");
        push(0x01, false);
        bl_fixup("__z_i2c_stop");
        pop(0x01, false);
        pop(0xF0, true);
        emitLabel(LrrN);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 0xFF);
        pop(0xF0, true);
    } else if (name == "__z_i2c_write") {
        // r0 = addr7, r1 = data -> r0 = 1 (ok) / 0 (NACK).
        push(0xF0, true);
        movs(4, 0);
        movs(5, 1);
        int LwrN2 = newLabel();
        lsls_imm(0, 4, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LwrN2);
        movs(0, 5);
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LwrN2);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 1);
        pop(0xF0, true);
        emitLabel(LwrN2);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 0);
        pop(0xF0, true);
    } else if (name == "__z_i2c_read") {
        // r0 = addr7 -> r0 = byte, or 0xFF on NACK.
        push(0xF0, true);
        movs(4, 0);
        int LrdN = newLabel();
        lsls_imm(0, 4, 1);
        adds_imm8(0, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LrdN);
        movs_imm(0, 1);                 // NACK (last byte)
        bl_fixup("__z_i2c_r8");
        push(0x01, false);
        bl_fixup("__z_i2c_stop");
        pop(0x01, false);
        pop(0xF0, true);
        emitLabel(LrdN);
        bl_fixup("__z_i2c_stop");
        movs_imm(0, 0xFF);
        pop(0xF0, true);
    } else if (name == "__z_i2c_mem_read") {
        // r0 = addr7, r1 = reg, r2 = n (1..63) -> r0 = n (or -1); the bytes
        // land in the __z_i2c_buf global (byte-packed).
        push(0xF0, true);
        movs(4, 0);                     // r4 = addr
        movs(5, 1);                     // r5 = reg
        movs(6, 2);                     // r6 = n
        int LmrN = newLabel(), Lmr = newLabel(), LmrB = newLabel();
        int LmrAck = newLabel(), LmrR = newLabel();
        auto gb = global("__z_i2c_buf");
        lsls_imm(0, 4, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LmrN);
        movs(0, 5);
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LmrN);
        lsls_imm(0, 4, 1);
        adds_imm8(0, 1);
        bl_fixup("__z_i2c_start");
        bl_fixup("__z_i2c_w8");
        cmp_imm(0, 0);
        b_cc(0, LmrN);
        // read loop: i (r7) = 0..n-1; ack = (i + 1 == n) ? NACK : ACK
        movs_imm(7, 0);
        emitLabel(Lmr);
        cmps(7, 6);
        b_cc(2, LmrB);                  // CS: i >= n -> done
        movs(0, 7);
        adds_imm8(0, 1);
        cmps(0, 6);
        b_cc(0, LmrAck);                // EQ -> last byte
        movs_imm(0, 0);                 // ACK
        b_imm(LmrR);
        emitLabel(LmrAck);
        movs_imm(0, 1);                 // NACK
        emitLabel(LmrR);
        bl_fixup("__z_i2c_r8");
        loadConst(1, gb->addr);
        adds(1, 1, 7);                  // buf + i
        strb_off(0, 1, 0);
        adds_imm8(7, 1);
        b_imm(Lmr);
        emitLabel(LmrB);
        movs(0, 6);
        push(0x01, false);
        bl_fixup("__z_i2c_stop");
        pop(0x01, false);
        pop(0xF0, true);
        emitLabel(LmrN);
        bl_fixup("__z_i2c_stop");
        loadConst(0, 0xFFFFFFFFu);
        pop(0xF0, true);
    } else if (name == "__z_fl_prog") {
        // Program one 32-bit word. r0 = flash address (aligned), r1 = value.
        // F1: two 16-bit half-word writes (PG bit); L4/G0: one 32-bit write.
        bool f1 = (fam == McuFamily::F1);
        if (f1) {
            int Lw0 = newLabel(), Lw1 = newLabel(), Lw2 = newLabel();
            emitLabel(Lw0);             // wait BSY (SR bit0)
            loadConst(2, 0x4002200Cu); ldr_off(3, 2, 0);
            movs_imm(2, 1); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Lw0);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            movs_imm(2, 1); orrs(3, 2); loadConst(2, 0x40022010u); str_off(3, 2, 0);   // CR |= PG
            strh_off(1, 0, 0);          // low half-word
            emitLabel(Lw1);
            loadConst(2, 0x4002200Cu); ldr_off(3, 2, 0);
            movs_imm(2, 1); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Lw1);
            lsrs_imm(1, 1, 16);         // high half-word
            strh_off(1, 0, 4);
            emitLabel(Lw2);
            loadConst(2, 0x4002200Cu); ldr_off(3, 2, 0);
            movs_imm(2, 1); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Lw2);
            bx(LR_REG);
        } else {
            int Lw0 = newLabel(), Lw1 = newLabel();
            emitLabel(Lw0);             // wait BSY (SR bit16)
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            loadConst(2, 0x10000u); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Lw0);
            loadConst(2, 0x40022014u); ldr_off(3, 2, 0);
            movs_imm(2, 1); orrs(3, 2); loadConst(2, 0x40022014u); str_off(3, 2, 0);   // CR |= PG
            str_off(1, 0, 0);           // 32-bit write
            emitLabel(Lw1);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            loadConst(2, 0x10000u); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Lw1);
            bx(LR_REG);
        }
    } else if (name == "__z_fl_erase") {
        // Erase one flash page. r0 = page base address.
        bool f1 = (fam == McuFamily::F1);
        if (f1) {
            int Le0 = newLabel(), Le1 = newLabel();
            emitLabel(Le0);             // wait BSY
            loadConst(2, 0x4002200Cu); ldr_off(3, 2, 0);
            movs_imm(2, 1); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Le0);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            movs_imm(2, 2); orrs(3, 2); loadConst(2, 0x40022010u); str_off(3, 2, 0);   // CR |= PER
            loadConst(2, 0x40022014u); str_off(0, 2, 0);    // AR = page
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            loadConst(2, 0x40u); orrs(3, 2); loadConst(2, 0x40022010u); str_off(3, 2, 0);  // CR |= STRT
            emitLabel(Le1);
            loadConst(2, 0x4002200Cu); ldr_off(3, 2, 0);
            movs_imm(2, 1); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Le1);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            movs_imm(2, 2); bics(3, 2); loadConst(2, 0x40022010u); str_off(3, 2, 0);   // CR &= ~PER
            bx(LR_REG);
        } else {
            int Le0 = newLabel(), Le1 = newLabel();
            emitLabel(Le0);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            loadConst(2, 0x10000u); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Le0);
            loadConst(2, 0x40022014u); ldr_off(3, 2, 0);
            movs_imm(2, 2); orrs(3, 2); loadConst(2, 0x40022014u); str_off(3, 2, 0);   // CR |= PER
            loadConst(2, 0x40022018u); str_off(0, 2, 0);    // AR = page
            loadConst(2, 0x40022014u); ldr_off(3, 2, 0);
            loadConst(2, 0x10000u); orrs(3, 2); loadConst(2, 0x40022014u); str_off(3, 2, 0);  // CR |= STRT
            emitLabel(Le1);
            loadConst(2, 0x40022010u); ldr_off(3, 2, 0);
            loadConst(2, 0x10000u); ands(3, 2);
            cmp_imm(3, 0); b_cc(1, Le1);
            loadConst(2, 0x40022014u); ldr_off(3, 2, 0);
            movs_imm(2, 2); bics(3, 2); loadConst(2, 0x40022014u); str_off(3, 2, 0);
            bx(LR_REG);
        }
    } else if (name == "__z_fl_init") {
        // Find the EEPROM area (last two pages), unlock the flash controller
        // and select the page that currently holds the live records.
        push(0xF0, true);
        auto gcur = global("__z_fl_cur");
        auto goff = global("__z_fl_off");
        auto gps  = global("__z_fl_ps");
        bool f1 = (fam == McuFamily::F1);
        uint32_t keyr = f1 ? 0x40022004u : 0x40022008u;
        uint32_t pageSize = f1 ? 1024u : 2048u;
        uint32_t p0 = FLASH_BASE + cfg.flashSize - 2u * pageSize;
        uint32_t p1 = p0 + pageSize;
        if (!gcur || !goff || !gps) {
            pop(0xF0, true);
        } else {
            // unlock
            loadConst(0, keyr); loadConst(1, 0x45670123u); str_off(1, 0, 0);
            loadConst(0, keyr); loadConst(1, 0xCDEF89ABu); str_off(1, 0, 0);
            loadConst(4, p0); loadConst(5, p1); loadConst(6, pageSize);
            int Lc0 = newLabel(), Lc0e = newLabel(), Lc0s = newLabel();
            int Lc1 = newLabel(), Lc1e = newLabel(), Lc1s = newLabel();
            int LcP0 = newLabel(), LcEnd = newLabel();
            // count valid slots in p0 -> r1
            movs_imm(1, 0); movs_imm(7, 0);
            emitLabel(Lc0);
            cmps(7, 6);
            b_cc(2, Lc0e);              // CS: off >= pageSize -> done
            adds(3, 4, 7); ldr_off(3, 3, 0);
            loadConst(0, 0xFFFFFFFFu); cmps(3, 0);
            b_cc(0, Lc0s);              // EQ -> empty slot
            adds_imm8(1, 1);
            emitLabel(Lc0s);
            adds_imm8(7, 8);
            b_imm(Lc0);
            emitLabel(Lc0e);
            // count valid slots in p1 -> r2
            movs_imm(2, 0); movs_imm(7, 0);
            emitLabel(Lc1);
            cmps(7, 6);
            b_cc(2, Lc1e);
            adds(3, 5, 7); ldr_off(3, 3, 0);
            loadConst(0, 0xFFFFFFFFu); cmps(3, 0);
            b_cc(0, Lc1s);
            adds_imm8(2, 1);
            emitLabel(Lc1s);
            adds_imm8(7, 8);
            b_imm(Lc1);
            emitLabel(Lc1e);
            // pick the page with more valid slots (tie -> p0)
            cmps(2, 1);
            b_cc(13, LcP0);             // LE -> p0
            movs(4, 5);                 // cur = p1
            movs(1, 2);
            b_imm(LcEnd);
            emitLabel(LcP0);
            emitLabel(LcEnd);
            loadConst(0, gcur->addr); str_off(4, 0, 0);
            lsls_imm(1, 1, 3);          // off = count * 8
            loadConst(0, goff->addr); str_off(1, 0, 0);
            loadConst(0, gps->addr); loadConst(1, pageSize); str_off(1, 0, 0);
            pop(0xF0, true);
        }
    } else if (name == "__z_fl_write") {
        // r0 = key (0..4095), r1 = value. Appends a record {key, value} to
        // the current page; when the page fills, garbage-collects to the
        // other page (copy live records, erase, switch).
        push(0xF0, true);
        auto gcur = global("__z_fl_cur");
        auto goff = global("__z_fl_off");
        auto gps  = global("__z_fl_ps");
        bool f1 = (fam == McuFamily::F1);
        uint32_t pageSize = f1 ? 1024u : 2048u;
        uint32_t p0 = FLASH_BASE + cfg.flashSize - 2u * pageSize;
        uint32_t p1 = p0 + pageSize;
        if (!gcur || !goff || !gps) {
            pop(0xF0, true);
        } else {
            loadConst(2, 0xFFF); ands(0, 2); movs(4, 0);   // r4 = key
            movs(5, 1);                                     // r5 = value
            int LfwI = newLabel(), LfwW = newLabel();
            int LfwO = newLabel(), LfwT1 = newLabel(), LfwT2 = newLabel();
            int Lgc = newLabel(), Lgce = newLabel(), Lgcs = newLabel();
            // ensure init
            loadConst(0, gcur->addr); ldr_off(1, 0, 0);
            cmp_imm(1, 0);
            b_cc(1, LfwI);              // NE -> already initialized
            bl_fixup("__z_fl_init");
            emitLabel(LfwI);
            loadConst(0, gcur->addr); ldr_off(6, 0, 0);     // r6 = cur
            loadConst(0, goff->addr); ldr_off(7, 0, 0);     // r7 = off
            loadConst(0, gps->addr);  ldr_off(0, 0, 0);     // r0 = pageSize
            cmps(7, 0);
            b_cc(3, LfwW);              // CC: off < pageSize -> no GC
            // ---- GC ----
            push(0x20, false);          // save value (r5 becomes the dst offset)
            loadConst(2, p0); cmps(6, 2);
            b_cc(0, LfwO);              // EQ -> cur == p0 -> other = p1
            loadConst(2, p0);           // other = p0
            b_imm(LfwT2);
            emitLabel(LfwO);
            loadConst(2, p1);           // other = p1
            emitLabel(LfwT2);
            movs_imm(7, 0);             // src offset i
            movs_imm(5, 0);             // dst offset
            emitLabel(Lgc);
            loadConst(0, goff->addr); ldr_off(1, 0, 0);
            cmps(7, 1);
            b_cc(2, Lgce);              // CS: i >= off -> done
            adds(0, 6, 7); ldr_off(1, 0, 0);                // word0
            loadConst(0, 0xFFFFFFFFu); cmps(1, 0);
            b_cc(0, Lgcs);              // EQ -> empty slot
            loadConst(0, pageSize - 8u);  // leave room for the new record
            cmps(5, 0);
            b_cc(2, Lgce);              // CS: dst >= cap -> stop (oldest evicted)
            lsls_imm(0, 4, 1);          // newkey << 1
            loadConst(3, 0xFFFFE000u);
            orrs(0, 3);
            cmps(1, 0);
            b_cc(0, Lgcs);              // EQ -> stale record for the same key
            adds(0, 2, 5);              // addr = other + dst
            push(0x04, false);          // r2 is scratch across calls - save other
            bl_fixup("__z_fl_prog");
            pop(0x04, false);           // restore other
            adds(0, 6, 7); ldr_off(1, 0, 4);               // word1
            adds(0, 2, 5); adds_imm8(0, 4);
            push(0x04, false);
            bl_fixup("__z_fl_prog");
            pop(0x04, false);
            adds_imm8(5, 8);            // dst += 8
            emitLabel(Lgcs);
            adds_imm8(7, 8);            // i += 8
            b_imm(Lgc);
            emitLabel(Lgce);
            movs(0, 6);
            push(0x04, false);          // save other across erase
            bl_fixup("__z_fl_erase");
            pop(0x04, false);           // restore other
            movs(6, 2);                 // cur = other
            movs(7, 5);                 // off = dst
            pop(0x20, false);           // r5 = value
            emitLabel(LfwW);
            // ---- write the new record ----
            movs(0, 4);
            lsls_imm(0, 0, 1);
            loadConst(1, 0xFFFFE000u);
            orrs(0, 1);                 // r0 = word0
            movs(1, 0);                 // r1 = word0
            adds(0, 6, 7);              // addr = cur + off
            bl_fixup("__z_fl_prog");
            adds(0, 6, 7);
            adds_imm8(0, 4);
            movs(1, 5);                 // word1 = value
            bl_fixup("__z_fl_prog");
            adds_imm8(7, 8);
            loadConst(0, gcur->addr); str_off(6, 0, 0);
            loadConst(0, goff->addr); str_off(7, 0, 0);
            pop(0xF0, true);
        }
    } else if (name == "__z_fl_read") {
        // r0 = key (0..4095) -> r0 = stored value (0 if never written).
        // Scans the current page backwards so the newest record wins.
        push(0xF0, true);
        auto gcur = global("__z_fl_cur");
        auto goff = global("__z_fl_off");
        if (!gcur || !goff) {
            pop(0xF0, true);
        } else {
            loadConst(2, 0xFFF); ands(0, 2); movs(4, 0);   // r4 = key
            int LfrI = newLabel(), Lfr = newLabel(), Lfre = newLabel(), Lfrs = newLabel();
            loadConst(0, gcur->addr); ldr_off(1, 0, 0);
            cmp_imm(1, 0);
            b_cc(1, LfrI);              // NE -> already initialized
            bl_fixup("__z_fl_init");
            emitLabel(LfrI);
            loadConst(0, gcur->addr); ldr_off(5, 0, 0);     // r5 = cur
            loadConst(0, goff->addr); ldr_off(6, 0, 0);     // r6 = off
            movs(7, 6);
            subs_imm8(7, 8);            // r7 = off - 8
            emitLabel(Lfr);
            cmp_imm(7, 0);
            b_cc(11, Lfre);             // LT -> not found
            adds(0, 5, 7); ldr_off(1, 0, 0);                // word0
            loadConst(0, 0xFFFFFFFFu); cmps(1, 0);
            b_cc(0, Lfrs);              // EQ -> empty slot
            movs(0, 1);
            lsrs_imm(0, 0, 1);          // (word0 & 0x1FFF) >> 1
            loadConst(2, 0xFFF); ands(0, 2);
            cmps(0, 4);
            b_cc(1, Lfrs);              // NE -> not our key
            adds(0, 5, 7);
            ldr_off(0, 0, 4);           // word1 = value
            pop(0xF0, true);
            emitLabel(Lfrs);
            subs_imm8(7, 8);
            b_imm(Lfr);
            emitLabel(Lfre);
            movs_imm(0, 0);
            pop(0xF0, true);
        }
    } else if (name == "__z_rtc_init") {
        // F1 RTC init: PWR DBP, LSE via BDCR, prescaler 32768 -> 1 Hz,
        // counter reset to 0. Registers: RTC base 0x40002800.
        push(0x10, true);               // push {r4, lr}
        loadConst(0, 0x40007000u); ldr_off(1, 0, 0);
        loadConst(2, 0x100u); orrs(1, 2); str_off(1, 0, 0);   // PWR CR DBP = 1
        loadConst(0, 0x40021020u); ldr_off(1, 0, 0);
        movs_imm(2, 1); orrs(1, 2); str_off(1, 0, 0);        // BDCR BDRST = 1
        ldr_off(1, 0, 0); movs_imm(2, 1); bics(1, 2); str_off(1, 0, 0);
        ldr_off(1, 0, 0); movs_imm(2, 1); orrs(1, 2); str_off(1, 0, 0);  // LSEON
        int Lrd = newLabel();
        emitLabel(Lrd);                 // wait LSERDY
        ldr_off(1, 0, 0); movs_imm(2, 2); ands(1, 2);
        cmp_imm(1, 0); b_cc(0, Lrd);
        ldr_off(1, 0, 0);
        loadConst(2, 0x300u); bics(1, 2);
        loadConst(2, 0x100u); orrs(1, 2);                   // RTCSEL = 01 (LSE)
        loadConst(2, 0x8000u); orrs(1, 2);                  // RTCEN
        str_off(1, 0, 0);
        loadConst(0, 0x40002804u);      // CRL
        int Lrt = newLabel();
        emitLabel(Lrt);                 // wait RTOFF
        ldr_off(1, 0, 0); loadConst(2, 0x20u); ands(1, 2);
        cmp_imm(1, 0); b_cc(0, Lrt);
        ldr_off(1, 0, 0); movs_imm(2, 0x10); orrs(1, 2); str_off(1, 0, 0);  // CNF = 1
        loadConst(0, 0x4000280Cu); loadConst(1, 0x7FFFu); str_off(1, 0, 0); // PRLL
        loadConst(0, 0x40002808u); movs_imm(1, 0); str_off(1, 0, 0);        // PRLH
        loadConst(0, 0x40002818u); movs_imm(1, 0); str_off(1, 0, 0);        // CNTH
        loadConst(0, 0x4000281Cu); movs_imm(1, 0); str_off(1, 0, 0);        // CNTL
        loadConst(0, 0x40002804u); ldr_off(1, 0, 0);
        loadConst(2, 0x10u); bics(1, 2); str_off(1, 0, 0);  // CNF = 0
        pop(0x10, true);
    } else if (name == "__z_rtc_set") {
        // r0 = seconds since epoch -> RTC counter.
        push(0x10, true);
        movs(4, 0);
        loadConst(0, 0x40002804u);
        int Lst = newLabel();
        emitLabel(Lst);                 // wait RTOFF
        ldr_off(1, 0, 0); loadConst(2, 0x20u); ands(1, 2);
        cmp_imm(1, 0); b_cc(0, Lst);
        ldr_off(1, 0, 0); movs_imm(2, 0x10); orrs(1, 2); str_off(1, 0, 0);  // CNF = 1
        loadConst(0, 0x40002818u); movs(1, 4); lsrs_imm(1, 1, 16); str_off(1, 0, 0);  // CNTH
        loadConst(0, 0x4000281Cu); movs(1, 4); lsls_imm(1, 1, 16); lsrs_imm(1, 1, 16); str_off(1, 0, 0);  // CNTL
        loadConst(0, 0x40002804u); ldr_off(1, 0, 0);
        loadConst(2, 0x10u); bics(1, 2); str_off(1, 0, 0);  // CNF = 0
        pop(0x10, true);
    } else if (name == "__z_rtc_get") {
        // r0 = seconds (CNTH << 16 | CNTL; CNTL latches on CNTH read).
        push(0x10, true);
        loadConst(0, 0x4000281Cu); ldr_off(4, 0, 0);        // CNTL
        loadConst(0, 0x40002818u); ldr_off(0, 0, 0);        // CNTH
        lsls_imm(0, 0, 16);
        adds(0, 0, 4);
        pop(0x10, true);
    } else if (name == "__z_rtc_alarm_set") {
        // r0 = alarm seconds. Sets ALRH/ALRL, enables ALRE + ALRIE, wires
        // EXTI line 17 and NVIC IRQ41 (RTC_Alarm) so power_stop() wakes up.
        push(0x10, true);
        movs(4, 0);
        loadConst(0, 0x40002804u);
        int Lst2 = newLabel();
        emitLabel(Lst2);
        ldr_off(1, 0, 0); loadConst(2, 0x20u); ands(1, 2);
        cmp_imm(1, 0); b_cc(0, Lst2);
        ldr_off(1, 0, 0); movs_imm(2, 0x10); orrs(1, 2); str_off(1, 0, 0);  // CNF = 1
        loadConst(0, 0x40002820u); movs(1, 4); lsrs_imm(1, 1, 16); str_off(1, 0, 0);  // ALRH
        loadConst(0, 0x40002824u); movs(1, 4); lsls_imm(1, 1, 16); lsrs_imm(1, 1, 16); str_off(1, 0, 0);  // ALRL
        loadConst(0, 0x40002804u); ldr_off(1, 0, 0);
        loadConst(2, 0x10u); bics(1, 2); str_off(1, 0, 0);  // CNF = 0
        ldr_off(1, 0, 0); movs_imm(2, 4); orrs(1, 2); str_off(1, 0, 0);     // ALRE = 1
        loadConst(0, 0x40002800u); ldr_off(1, 0, 0);
        movs_imm(2, 1); orrs(1, 2); str_off(1, 0, 0);       // CRH ALRIE = 1
        loadConst(0, 0x40010400u); ldr_off(1, 0, 0);
        loadConst(2, 0x20000u); orrs(1, 2); str_off(1, 0, 0);               // EXTI IMR |= 1<<17
        loadConst(0, 0x40010408u); ldr_off(1, 0, 0);
        loadConst(2, 0x20000u); orrs(1, 2); str_off(1, 0, 0);               // EXTI RTSR |= 1<<17
        loadConst(0, 0xE000E104u); ldr_off(1, 0, 0);
        loadConst(2, 0x200u); orrs(1, 2); str_off(1, 0, 0);                 // NVIC ISER1 |= 1<<9
        auto gw = global("__z_rtc_woke");
        if (gw) {
            loadConst(0, gw->addr); movs_imm(1, 0); str_off(1, 0, 0);
        }
        pop(0x10, true);
    } else if (name == "__z_rtc_alarm_pending") {
        // r0 = 1 if the RTC alarm fired (clears the flag).
        push(0x10, true);
        int Lrp0 = newLabel();
        loadConst(0, 0x40002804u); ldr_off(1, 0, 0);
        movs_imm(2, 1); ands(1, 2);     // ALRF
        cmp_imm(1, 0);
        b_cc(0, Lrp0);                  // EQ -> not pending
        ldr_off(1, 0, 0); movs_imm(2, 1); bics(1, 2); str_off(1, 0, 0);  // clear
        movs_imm(0, 1);
        pop(0x10, true);
        emitLabel(Lrp0);
        movs_imm(0, 0);
        pop(0x10, true);
    } else if (name == "__z_rtc_isr") {
        // RTC_Alarm ISR: clear EXTI PR17 + RTC ALRF, flag the wakeup.
        push(0x00, true);               // push {lr}
        loadConst(0, 0x40010414u); ldr_off(1, 0, 0);
        loadConst(2, 0x20000u); orrs(1, 2); str_off(1, 0, 0);               // EXTI PR
        loadConst(0, 0x40002804u); ldr_off(1, 0, 0);
        movs_imm(2, 1); bics(1, 2); str_off(1, 0, 0);                       // RTC ALRF
        auto gw = global("__z_rtc_woke");
        if (gw) {
            loadConst(0, gw->addr); movs_imm(1, 1); str_off(1, 0, 0);
        }
        pop(0x00, true);                // pop {pc}
    } else if (name == "__z_power_stop") {
        // F1 STOP mode (PDDS=0, LPDS=0) + WFI. Wakes on the RTC alarm (or
        // any enabled EXTI); returns with the wake flag cleared.
        loadConst(0, 0x40007000u); ldr_off(1, 0, 0);
        loadConst(2, 0x3u); bics(1, 2); str_off(1, 0, 0);
        u16(0xBF30);                    // WFI
        auto gw = global("__z_rtc_woke");
        if (gw) {
            loadConst(0, gw->addr); movs_imm(1, 0); str_off(1, 0, 0);
        }
        bx(LR_REG);
    } else if (name == "__z_power_standby") {
        // F1 STANDBY mode (PDDS=1): WFI powers down; wakeup = system reset.
        int Lsb = newLabel();
        loadConst(0, 0x40007000u); ldr_off(1, 0, 0);
        loadConst(2, 0x1u); bics(1, 2);                 // LPDS = 0
        loadConst(2, 0x2u); orrs(1, 2);                 // PDDS = 1
        str_off(1, 0, 0);
        u16(0xBF30);                    // WFI
        emitLabel(Lsb);
        b_imm(Lsb);                     // never returns; spin if it does
    } else if (name == "__z_crc16") {
        // CRC-16 (Modbus, poly 0xA001). r0 = crc, r1 = byte -> r0 = crc.
        eors(0, 1);                     // crc ^= byte
        movs_imm(2, 8);
        int Lc = newLabel(), Lcs = newLabel();
        emitLabel(Lc);
        movs_imm(3, 1);
        ands(3, 0);                     // crc & 1
        lsrs_imm(0, 0, 1);              // crc >>= 1
        cmp_imm(3, 0);
        b_cc(0, Lcs);                   // EQ -> no poly
        loadConst(3, 0xA001u);
        eors(0, 3);
        emitLabel(Lcs);
        subs_imm8(2, 1);
        b_cc(1, Lc);
        bx(LR_REG);
    } else if (name == "__z_mb_send") {
        // r0 = byte count: send buf[0..count-1] via the UART TX bit-bang.
        push(0x10, true);               // push {r4, lr}
        auto gb = global("__z_mb_buf");
        movs(4, 0);                     // r4 = count
        movs_imm(7, 0);                 // i
        int Ls = newLabel(), Lse = newLabel();
        emitLabel(Ls);
        cmps(7, 4);
        b_cc(2, Lse);                   // CS: i >= count -> done
        loadConst(0, gb->addr);
        adds(0, 0, 7);
        ldrb_off(0, 0, 0);
        bl_fixup("__z_uart_tx");
        adds_imm8(7, 1);
        b_imm(Ls);
        emitLabel(Lse);
        pop(0x10, true);                // pop {r4, pc}
    } else if (name == "__z_mb_poll") {
        // Modbus RTU slave: poll the RX bit machine (half-bit cadence) and
        // collect bytes into __z_mb_buf. A frame is complete after 70 idle
        // half-bits (~3.5 chars at 9600). Validated frames are dispatched
        // (functions 3/6/16) and answered via the UART TX bit-bang.
        push(0xF0, true);               // push {r4-r7, lr}
        auto gst   = global("__z_mb_st");
        auto gbits = global("__z_mb_bits");
        auto gwt   = global("__z_mb_wait2");
        auto gbt   = global("__z_mb_byte");
        auto gcnt  = global("__z_mb_cnt");
        auto gsil  = global("__z_mb_sil");
        auto gaddr = global("__z_mb_addr");
        auto gidr  = global("__z_mb_idr");
        auto gbit  = global("__z_mb_bit");
        auto ghalf = global("__z_mb_half");
        auto gbuf  = global("__z_mb_buf");
        auto gregs = global("__z_mb_regs");
        if (!gst || !gbits || !gwt || !gbt || !gcnt || !gsil ||
            !gaddr || !gidr || !gbit || !ghalf || !gbuf || !gregs) {
            pop(0xF0, true);
        } else {
            int LmbIdle = newLabel(), LmbW = newLabel();
            int LmbSample = newLabel(), LmbZ = newLabel();
            int LmbGot = newLabel(), LmbAbort = newLabel(), LmbSil = newLabel();
            int LmbMatch = newLabel(), LmbFnc = newLabel(), LmbClr = newLabel();
            int LmbRet = newLabel(), LmbC = newLabel(), LmbCe = newLabel();
            int LmbF3 = newLabel(), LmbF6 = newLabel(), LmbF16 = newLabel();
            int LmbE02 = newLabel(), LmbSend = newLabel();
            int LmbS1 = newLabel(), LmbS2 = newLabel();
            int LmbF3L = newLabel(), LmbF3E = newLabel();
            int LmbF16L = newLabel(), LmbF16E = newLabel();
            int LmbCok = newLabel(), LmbCok2 = newLabel();
            int LmbN6 = newLabel(), LmbN16 = newLabel();
            int LmbN0 = newLabel(), LmbN64b = newLabel(), LmbN64c = newLabel();
            int LmbNoBc = newLabel(), LmbRetLE = newLabel(), LmbSilGE = newLabel();
            int LmbR1 = newLabel(), LmbR2 = newLabel(), LmbR3 = newLabel();
            // ---- RX bit machine (one step per call) ----
            loadConst(0, gst->addr);  ldr_off(4, 0, 0);
            loadConst(0, gbt->addr);  ldr_off(5, 0, 0);
            loadConst(0, gbits->addr); ldr_off(6, 0, 0);
            loadConst(0, gwt->addr);  ldr_off(7, 0, 0);
            cmp_imm(4, 0);
            b_cc(0, LmbIdle);               // EQ -> idle
            loadConst(0, ghalf->addr); ldr_off(0, 0, 0);
            emitLabel(LmbW);
            subs_imm8(0, 1);
            b_cc(1, LmbW);
            subs_imm8(7, 1);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            cmp_imm(7, 0);
            b_cc(0, LmbSample);             // EQ -> sample now
            cmp_imm(7, 2);
            b_cc(1, LmbR1);                 // NE -> wait for the 1.5-bit mark
            b_imm(LmbRet);
            emitLabel(LmbR1);
            cmp_imm(6, 8);
            b_cc(1, LmbR2);                 // NE -> still in stop bits
            b_imm(LmbRet);
            emitLabel(LmbR2);
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            cmp_imm(0, 0);
            b_cc(0, LmbAbort);              // EQ -> high: false start
            b_imm(LmbRet);
            emitLabel(LmbAbort);
            movs_imm(4, 0);
            loadConst(0, gst->addr); str_off(4, 0, 0);
            b_imm(LmbRet);
            emitLabel(LmbSample);
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            lsrs_imm(5, 5, 1);
            cmp_imm(0, 0);
            b_cc(0, LmbZ);
            movs_imm(0, 0x80);
            orrs(5, 0);
            emitLabel(LmbZ);
            loadConst(0, gbt->addr); str_off(5, 0, 0);
            subs_imm8(6, 1);
            loadConst(0, gbits->addr); str_off(6, 0, 0);
            cmp_imm(6, 0);
            b_cc(0, LmbGot);                // EQ -> byte complete
            movs_imm(7, 3);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            b_imm(LmbRet);
            emitLabel(LmbGot);
            movs_imm(4, 0);
            loadConst(0, gst->addr); str_off(4, 0, 0);
            movs_imm(7, 0);
            loadConst(0, gwt->addr); str_off(7, 0, 0);
            loadConst(0, gcnt->addr); ldr_off(2, 0, 0);     // r2 = cnt
            cmp_imm(2, 128);
            b_cc(10, LmbRetLE);             // GE (cnt >= 128) -> full: drop
            loadConst(0, gbuf->addr); adds(0, 0, 2);
            strb_off(5, 0, 0);                              // buf[cnt] = byte
            adds_imm8(2, 1);
            loadConst(0, gcnt->addr); str_off(2, 0, 0);
            b_imm(LmbRet);
            emitLabel(LmbRetLE);
            loadConst(0, gcnt->addr); movs_imm(1, 0); str_off(1, 0, 0);  // overflow: drop
            b_imm(LmbRet);
            emitLabel(LmbIdle);
            // idle: one half-bit wait per poll (this IS the Modbus time base)
            loadConst(0, ghalf->addr); ldr_off(0, 0, 0);
            int LmbI = newLabel();
            emitLabel(LmbI);
            subs_imm8(0, 1);
            b_cc(1, LmbI);
            loadConst(0, gidr->addr); ldr_off(0, 0, 0);
            loadConst(1, gbit->addr); ands(0, 1);
            cmp_imm(0, 0);
            b_cc(0, LmbSil);                // EQ -> line high: silence
            movs_imm(4, 1); movs_imm(6, 8); movs_imm(7, 3); movs_imm(5, 0);
            loadConst(0, gst->addr);  str_off(4, 0, 0);
            loadConst(0, gbits->addr); str_off(6, 0, 0);
            loadConst(0, gwt->addr);  str_off(7, 0, 0);
            loadConst(0, gbt->addr);  str_off(5, 0, 0);
            loadConst(0, gsil->addr); movs_imm(1, 0); str_off(1, 0, 0);
            b_imm(LmbRet);
            emitLabel(LmbSil);
            loadConst(0, gsil->addr); ldr_off(1, 0, 0);
            adds_imm8(1, 1);
            loadConst(0, gsil->addr); str_off(1, 0, 0);
            cmp_imm(1, 70);                 // 3.5 chars at 9600 = 70 half-bits
            b_cc(10, LmbSilGE);             // GE -> frame may be complete
            b_imm(LmbRet);
            emitLabel(LmbSilGE);
            loadConst(0, gcnt->addr); ldr_off(1, 0, 0);
            cmp_imm(1, 0);
            b_cc(1, LmbR3);                 // NE -> frame pending
            b_imm(LmbRet);
            emitLabel(LmbR3);
            // ---- frame complete: address check ----
            loadConst(0, gbuf->addr); ldrb_off(0, 0, 0);
            loadConst(1, gaddr->addr); ldr_off(1, 1, 0);
            cmps(0, 1);
            b_cc(0, LmbMatch);              // EQ -> ours
            cmp_imm(0, 0);
            b_cc(1, LmbNoBc);               // NE -> not ours, drop
            b_imm(LmbClr);
            emitLabel(LmbNoBc);
            movs_imm(3, 0);                 // broadcast: execute, no response
            push(0x01, false);
            b_imm(LmbFnc);
            emitLabel(LmbMatch);
            movs_imm(3, 1);
            push(0x01, false);
            emitLabel(LmbFnc);
            // ---- CRC check over buf[0..cnt-3] vs buf[cnt-2]|buf[cnt-1]<<8 ----
            loadConst(0, gcnt->addr); ldr_off(2, 0, 0);     // r2 = cnt
            cmp_imm(2, 4);
            b_cc(10, LmbCok);               // GE -> proceed
            b_imm(LmbClr);
            emitLabel(LmbCok);
            loadConst(5, 0xFFFFu);          // crc
            movs_imm(7, 0);
            emitLabel(LmbC);
            movs(1, 2);
            subs_imm8(1, 2);                // cnt - 2
            cmps(7, 1);
            b_cc(2, LmbCe);                 // CS: i >= cnt-2 -> done
            loadConst(0, gbuf->addr);
            adds(0, 0, 7);
            ldrb_off(1, 0, 0);
            movs(0, 5);
            bl_fixup("__z_crc16");
            movs(5, 0);
            adds_imm8(7, 1);
            b_imm(LmbC);
            emitLabel(LmbCe);
            loadConst(0, gbuf->addr);
            adds(0, 0, 2);
            subs_imm8(0, 2);                // buf + cnt - 2
            ldrb_off(1, 0, 0);              // crc lo
            adds_imm8(0, 1);
            ldrb_off(0, 0, 0);              // crc hi
            lsls_imm(0, 0, 8);
            orrs(0, 1);                     // expected crc
            cmps(5, 0);
            b_cc(0, LmbCok2);
            b_imm(LmbClr);                  // CRC mismatch, drop
            emitLabel(LmbCok2);
            // ---- dispatch on function code ----
            loadConst(0, gbuf->addr); ldrb_off(1, 0, 1);
            cmp_imm(1, 3);
            b_cc(0, LmbF3);
            cmp_imm(1, 6);
            b_cc(1, LmbN6);
            b_imm(LmbF6);
            emitLabel(LmbN6);
            cmp_imm(1, 16);
            b_cc(1, LmbN16);
            b_imm(LmbF16);
            emitLabel(LmbN16);
            // illegal function -> exception 01
            movs_imm(3, 0x81);
            strb_off(3, 0, 1);
            movs_imm(3, 1);
            strb_off(3, 0, 2);
            movs_imm(6, 3);
            b_imm(LmbSend);
            emitLabel(LmbE02);
            movs_imm(3, 0x83);
            strb_off(3, 0, 1);
            movs_imm(3, 2);
            strb_off(3, 0, 2);
            movs_imm(6, 3);
            b_imm(LmbSend);
            emitLabel(LmbF3);
            // read holding registers: start = buf[2..3], n = buf[4..5]
            loadConst(0, gbuf->addr);
            ldrb_off(1, 0, 2); lsls_imm(1, 1, 8);
            ldrb_off(3, 0, 3); orrs(1, 3);                 // r1 = start
            ldrb_off(3, 0, 4); lsls_imm(3, 3, 8);
            ldrb_off(2, 0, 5); orrs(3, 2);                 // r3 = n
            cmp_imm(3, 0);
            b_cc(0, LmbE02);                // EQ -> n == 0
            adds(2, 1, 3);
            cmp_imm(2, 64);
            b_cc(12, LmbE02);               // GT -> out of range
            movs_imm(3, 3);
            strb_off(3, 0, 1);
            // n = buf[4]<<8 | buf[5]
            loadConst(0, gbuf->addr);
            ldrb_off(3, 0, 4); lsls_imm(3, 3, 8);
            ldrb_off(2, 0, 5); orrs(3, 2);                 // r3 = n
            movs(2, 3);
            lsls_imm(2, 2, 1);              // n * 2
            strb_off(2, 0, 2);
            movs_imm(7, 0);
            emitLabel(LmbF3L);
            cmps(7, 3);
            b_cc(2, LmbF3E);                // CS: i >= n -> done
            loadConst(0, gregs->addr);
            adds(2, 1, 7);                  // start + i
            lsls_imm(2, 2, 2);
            adds(0, 0, 2);
            ldr_off(4, 0, 0);               // r4 = reg value
            loadConst(0, gbuf->addr);
            adds(0, 0, 7);
            lsls_imm(0, 0, 1);
            adds_imm8(0, 3);                // buf + 3 + 2i
            movs(1, 4);
            lsrs_imm(1, 1, 8);
            strb_off(1, 0, 0);              // hi
            movs(1, 4);
            movs_imm(2, 0xFF);
            ands(1, 2);
            strb_off(1, 0, 1);              // lo
            adds_imm8(7, 1);
            b_imm(LmbF3L);
            emitLabel(LmbF3E);
            // len = 3 + n*2
            loadConst(0, gbuf->addr);
            ldrb_off(3, 0, 4); lsls_imm(3, 3, 8);
            ldrb_off(2, 0, 5); orrs(3, 2);
            movs(6, 3);
            lsls_imm(6, 6, 1);
            adds_imm8(6, 3);
            b_imm(LmbSend);
            emitLabel(LmbF6);
            // write single: reg = buf[2..3], val = buf[4..5]
            loadConst(0, gbuf->addr);
            ldrb_off(1, 0, 2); lsls_imm(1, 1, 8);
            ldrb_off(3, 0, 3); orrs(1, 3);                 // r1 = reg
            cmp_imm(1, 64);
            b_cc(3, LmbN64b);               // CC: reg < 64 -> proceed
            b_imm(LmbE02);
            emitLabel(LmbN64b);
            ldrb_off(3, 0, 4); lsls_imm(3, 3, 8);
            ldrb_off(2, 0, 5); orrs(3, 2);                 // r3 = val
            loadConst(2, gregs->addr);
            lsls_imm(1, 1, 2);
            adds(1, 2, 1);
            str_off(3, 1, 0);               // regs[reg] = val
            movs_imm(6, 8);                 // echo the request
            b_imm(LmbSend);
            emitLabel(LmbF16);
            // write multiple: reg = buf[2..3], n = buf[4..5], data at buf[7..]
            loadConst(0, gbuf->addr);
            ldrb_off(1, 0, 2); lsls_imm(1, 1, 8);
            ldrb_off(3, 0, 3); orrs(1, 3);                 // r1 = reg
            ldrb_off(3, 0, 4); lsls_imm(3, 3, 8);
            ldrb_off(2, 0, 5); orrs(3, 2);                 // r3 = n
            cmp_imm(3, 0);
            b_cc(1, LmbN0);
            b_imm(LmbE02);
            emitLabel(LmbN0);
            adds(2, 1, 3);
            cmp_imm(2, 64);
            b_cc(13, LmbN64c);              // LE: reg + n <= 64 -> proceed
            b_imm(LmbE02);
            emitLabel(LmbN64c);
            movs_imm(7, 0);
            emitLabel(LmbF16L);
            cmps(7, 3);
            b_cc(2, LmbF16E);               // CS: i >= n -> done
            loadConst(0, gbuf->addr);
            adds(0, 0, 7);
            lsls_imm(0, 0, 1);
            adds_imm8(0, 7);                // buf + 7 + 2i
            ldrb_off(2, 0, 0); lsls_imm(2, 2, 8);
            ldrb_off(4, 0, 1); orrs(2, 4);                 // r2 = value
            loadConst(0, gregs->addr);
            adds(1, 1, 7);                  // reg + i
            lsls_imm(1, 1, 2);
            adds(1, 0, 1);
            str_off(2, 1, 0);
            adds_imm8(7, 1);
            b_imm(LmbF16L);
            emitLabel(LmbF16E);
            movs_imm(6, 6);                 // echo addr/fn/reg/n
            b_imm(LmbSend);
            // ---- build CRC, append, send (unless broadcast) ----
            emitLabel(LmbSend);
            pop(0x01, false);               // r0 = respond flag (0 = broadcast)
            cmp_imm(0, 0);
            b_cc(0, LmbClr);                // EQ -> broadcast: no response
            loadConst(5, 0xFFFFu);
            movs_imm(7, 0);
            emitLabel(LmbS1);
            cmps(7, 6);
            b_cc(2, LmbS2);                 // CS: i >= len -> done
            loadConst(0, gbuf->addr);
            adds(0, 0, 7);
            ldrb_off(1, 0, 0);
            movs(0, 5);
            bl_fixup("__z_crc16");
            movs(5, 0);
            adds_imm8(7, 1);
            b_imm(LmbS1);
            emitLabel(LmbS2);
            loadConst(0, gbuf->addr);
            adds(0, 0, 6);
            movs(1, 5);
            movs_imm(2, 0xFF);
            ands(1, 2);
            strb_off(1, 0, 0);              // crc lo
            adds_imm8(0, 1);
            movs(1, 5);
            lsrs_imm(1, 1, 8);
            strb_off(1, 0, 0);              // crc hi
            movs(0, 6);
            adds_imm8(0, 2);
            bl_fixup("__z_mb_send");
            emitLabel(LmbClr);
            loadConst(0, gcnt->addr); movs_imm(1, 0); str_off(1, 0, 0);
            loadConst(0, gsil->addr); movs_imm(1, 0); str_off(1, 0, 0);
            emitLabel(LmbRet);
            pop(0xF0, true);
        }
    } else {
        cerr << "stm32: unknown runtime '" << name << "'\n";
    }
    flushPool(false);
    resolveBranches(name);
    FnImg out;
    out.name = name;
    finalizeFn(out);
    runtimeImgs.push_back(out);
}

void Stm32::emitRtGpioInit() {
    for (auto& gp : gpioPins) {
        const string& pn = gp.first;
        int port = 0, pin = 0;
        if (!parsePin(pn, port, pin)) continue;
        loadConst(0, cfg.rccReg);
        ldr_off(1, 0, 0);
        loadConst(2, (uint32_t)(1u << (cfg.gpioEnableBitBase + port)));
        orrs(1, 2);
        str_off(1, 0, 0);
        uint32_t gpioBase = cfg.gpioA + (uint32_t)port * 0x400u;
        PinMode m = gp.second;
        if (cfg.f4) {
            // F4-style: MODER (0x00), OTYPER (0x04), PUPDR (0x0C)
            uint32_t shift = (uint32_t)(2 * (pin & 15));
            uint32_t moderVal = (m == PinMode::Input || m == PinMode::InputPullUp) ? 0u : 1u;
            loadConst(0, gpioBase + cfg.moderOff);
            ldr_off(1, 0, 0);
            loadConst(2, 0x3u << shift);
            bics(1, 2);
            loadConst(2, moderVal << shift);
            orrs(1, 2);
            str_off(1, 0, 0);
            if (m == PinMode::OpenDrain) {
                loadConst(0, gpioBase + 0x04u);     // OTYPER: OT = 1
                ldr_off(1, 0, 0);
                movs_imm(2, 1);
                lsls_imm(2, 2, (uint32_t)(pin & 15));
                orrs(1, 2);
                str_off(1, 0, 0);
            }
            if (m == PinMode::InputPullUp) {
                loadConst(0, gpioBase + 0x0Cu);     // PUPDR: 01 = pull-up
                ldr_off(1, 0, 0);
                loadConst(2, 0x3u << shift);
                bics(1, 2);
                loadConst(2, 1u << shift);
                orrs(1, 2);
                str_off(1, 0, 0);
            }
        } else {
            // F1-style: CRL/CRH nibbles: MODE[1:0], CNF[3:2]
            uint32_t regOff = pin < 8 ? cfg.crlOff : cfg.crhOff;
            uint32_t shift = (uint32_t)(4 * (pin & 7));
            uint32_t val;
            switch (m) {
                case PinMode::Input:       val = 0x0u; break;  // input floating
                case PinMode::InputPullUp: val = 0x2u; break;  // CNF=10 input pull-up/down
                case PinMode::OpenDrain:   val = 0x7u; break;  // CNF=01 open-drain, MODE=11
                default:                   val = 0x3u; break;  // output push-pull 50 MHz
            }
            loadConst(0, gpioBase + regOff);
            ldr_off(1, 0, 0);
            loadConst(2, 0xFu << shift);
            bics(1, 2);
            loadConst(2, val << shift);
            orrs(1, 2);
            str_off(1, 0, 0);
            if (m == PinMode::InputPullUp) {
                loadConst(0, gpioBase + 0x0Cu);     // ODR = 1 selects pull-up on F1
                ldr_off(1, 0, 0);
                movs_imm(2, 1);
                lsls_imm(2, 2, (uint32_t)pin);
                orrs(1, 2);
                str_off(1, 0, 0);
            }
        }
    }
}

void Stm32::emitRtGlobalInit() {
    for (auto& g : prog.globals) {
        auto gi = global(g->name);
        if (!gi || !g->init) continue;
        int64_t cv;
        if (getIntConst(g->init.get(), cv)) {
            loadConst(0, (uint32_t)(int32_t)cv);
            loadConst(1, gi->addr);
            str_off(0, 1, 0);
        }
    }
}

void Stm32::emitStartup() {
    resetFn();
    savedBytes = 0;
    frameSize = 0;
    // zero the whole SRAM (D3)
    int Lz = newLabel(), LzEnd = newLabel();
    loadConst(0, sramBase);
    loadConst(1, sramBase + sramSize);
    movs_imm(2, 0);
    emitLabel(Lz);
    cmps(0, 1);
    b_cc(2, LzEnd);                 // CS: ptr >= end (unsigned) -> done zeroing
    str_off(2, 0, 0);
    adds_imm8(0, 4);
    b_imm(Lz);
    emitLabel(LzEnd);
    emitRtGlobalInit();
    flushPool(true);   // keep startup literals within LDR PC-relative range
    emitRtGpioInit();
    flushPool(true);
    if (systickUsed) {
        // SysTick: RVR = load, CVR = 0, CSR = ENABLE|TICKINT|(CLKSOURCE)
        loadConst(0, 0xE000E014u);
        loadConst(1, systickLoadVal);
        str_off(1, 0, 0);
        loadConst(0, 0xE000E018u);
        movs_imm(1, 0);
        str_off(1, 0, 0);
        loadConst(0, 0xE000E010u);
        loadConst(1, systickCtrlVal);
        str_off(1, 0, 0);
    }
    if (rngUsed) {
        auto gr = global("__z_rng");
        if (gr) { loadConst(0, 0xD1B54A32u); loadConst(1, gr->addr); str_off(0, 1, 0); }
    }
    if (!entryName.empty()) bl_fixup(entryName);
    startupSpinPos = (int)code.size();
    u16(0xE7FE);                    // spin: b .  (also the default ISR handler)
    flushPool(false);
    resolveBranches("__z_startup");
}

void Stm32::emitVectorTable(uint32_t resetAddr, uint32_t defHandler) {
    tableBytes.clear();
    auto w = [&](uint32_t v) {
        tableBytes.push_back((uint8_t)(v & 0xFF));
        tableBytes.push_back((uint8_t)((v >> 8) & 0xFF));
        tableBytes.push_back((uint8_t)((v >> 16) & 0xFF));
        tableBytes.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    w(sramBase + sramSize);         // initial SP
    w(resetAddr | 1);               // Reset handler
    for (int i = 0; i < 14; i++) {
        uint32_t h = defHandler | 1;
        if (systickUsed && i == 13) {
            // entry 15 = SysTick exception
            auto it = funcOffsets.find("__z_systick_isr");
            h = (FLASH_BASE + (it == funcOffsets.end() ? 0u : it->second)) | 1;
        }
        w(h);
    }
    if (rtcAlarmUsed) {
        // F103: 43 peripheral IRQs (entries 16..58); RTC_Alarm = IRQ41 = entry 57.
        for (int i = 0; i < 43; i++) {
            uint32_t h = defHandler | 1;
            if (i == 41) {
                auto it = funcOffsets.find("__z_rtc_isr");
                h = (FLASH_BASE + (it == funcOffsets.end() ? 0u : it->second)) | 1;
            }
            w(h);
        }
    }
}

// =========================================================================
// Whole-program layout + binary emit
// =========================================================================
bool Stm32::compile(const string& outputPath) {
    // --- chip configuration -------------------------------------------------
    cfg = McuCfg();
    fam = mcuFamily(prog.mcu);
    adcSupported = (fam != McuFamily::L4 && fam != McuFamily::G0);
    cfg.f4 = (fam != McuFamily::F1);
    if (cfg.f4) {
        cfg.moderOff = 0x00u;        // F4-style GPIO (MODER/PUPDR/IDR/ODR/BSRR)
        cfg.bsrrOff  = 0x18u;
        cfg.idrOff   = 0x10u;
        cfg.odrOff   = 0x14u;
        cfg.gpioEnableBitBase = 0;   // GPIOAEN is bit 0 in the RCC enable register
        if (fam == McuFamily::F4 || fam == McuFamily::F7) {
            cfg.gpioA    = 0x40020000u;  // GPIOA base (AHB1)
            cfg.rccReg   = 0x40023830u;  // RCC->AHB1ENR
            cfg.sramSize = 128u * 1024u;
            cfg.flashSize = 1024u * 1024u;
        } else if (fam == McuFamily::L4) {
            cfg.gpioA    = 0x48000000u;  // GPIOA base (AHB2) — GPIOB at +0x400
            cfg.rccReg   = 0x4002104Cu;  // RCC->AHB2ENR
            cfg.sramSize = 128u * 1024u; // STM32L476 = 128 KB
            cfg.flashSize = 1024u * 1024u;
        } else if (fam == McuFamily::G0) {
            cfg.gpioA    = 0x50000000u;  // GPIOA base (AHB2)
            cfg.rccReg   = 0x40021038u;  // RCC->IOPENR
            cfg.sramSize = 32u * 1024u;  // STM32G071 = 32 KB
            cfg.flashSize = 128u * 1024u;
            cfg.uartLoopCycles = 3;      // Cortex-M0+
        }
    } else {
        cfg.sramSize = 20u * 1024u;  // F1 family default (McuCfg() registers)
    }
    if (prog.sramKb > 0) cfg.sramSize = prog.sramKb * 1024u;   // C17: sram_kb override
    if (cfg.sramSize < 2u * 1024u) cfg.sramSize = 2u * 1024u;  // sanity floor
    flashBase = FLASH_BASE;
    sramBase  = SRAM_BASE;
    sramSize  = cfg.sramSize;

    // --- SysTick clock for micros/millis/delay_us ----------------------------
    // systick: selects the SysTick source: HCLK (= sysclk) or HCLK/8.
    // LOAD = clock/1000 - 1 gives a 1 kHz interrupt -> __z_ms counter.
    {
        uint32_t sysClk = prog.sysclkHz != 0 ? prog.sysclkHz : 72000000u;
        uint32_t sysHz  = prog.systickHz != 0 ? prog.systickHz : sysClk;
        bool clkSrcHclk   = (sysHz == sysClk);
        bool clkSrcHclk8  = (sysHz != 0 && sysHz * 8u == sysClk);
        if (!clkSrcHclk && !clkSrcHclk8) {
            cerr << "stm32: systick clock must equal sysclk or sysclk/8 "
                    "(got " << prog.systickHz << "); using HCLK\n";
            clkSrcHclk = true;
            sysHz = sysClk;
        }
        if (sysHz < 1000) sysHz = 1000;
        if (sysHz > 0xFFFFFF00u) sysHz = 0xFFFFFF00u;  // keep RVR within 24 bits
        systickLoadVal  = sysHz / 1000 - 1;
        systickPerUsVal = sysHz / 1000000;
        if (systickPerUsVal < 1) systickPerUsVal = 1;
        systickCtrlVal  = clkSrcHclk ? 0x7u : 0x3u;  // ENABLE|TICKINT|CLKSOURCE
    }

    // --- struct layouts: every field occupies 4 bytes (D1) ------------------
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

    // --- globals in SRAM (SRAM_BASE up; zeroed by startup) -------------------
    globals.clear();
    globalOrder.clear();
    uint32_t gAddr = sramBase;
    for (auto& g : prog.globals) {
        int sz = g->arraySize > 0 ? g->arraySize * 4 : typeSize(g->type);
        if (sz < 4) sz = 4;
        gAddr = (gAddr + 3u) & ~3u;
        globals[g->name] = {gAddr, sz, g->type};
        globalOrder.push_back(g->name);
        gAddr += (uint32_t)sz;
    }

    // --- internal globals (UART bit-bang runtime, always present) ------------
    uint32_t ig = gAddr;
    auto addIntGlobal = [&](const string& name, int size) {
        ig = (ig + 3u) & ~3u;
        globals[name] = {ig, size, Type(TypeKind::Int)};
        globalOrder.push_back(name);
        ig += (uint32_t)size;
    };
    addIntGlobal("__z_uart_bsrr", 4); // BSRR register address of the TX port
    addIntGlobal("__z_uart_bit", 4);  // bitmask (1 << pin) of the TX pin
    addIntGlobal("__z_uart_half", 4); // half-bit delay-loop iterations
    addIntGlobal("__z_uart_buf", 16); // decimal buffer for uart_print_int
    // polled UART RX state
    addIntGlobal("__z_uart_rx_idr", 4);   // IDR address of the RX port
    addIntGlobal("__z_uart_rx_bit", 4);   // bitmask (1 << pin)
    addIntGlobal("__z_uart_rx_half", 4);  // half-bit delay-loop iterations
    addIntGlobal("__z_uart_rx_st", 4);    // 0 = idle, 1 = in frame
    addIntGlobal("__z_uart_rx_bits", 4);  // data bits left to sample (8..0)
    addIntGlobal("__z_uart_rx_wait2", 4); // half-steps until next sample
    addIntGlobal("__z_uart_rx_byte", 4);  // assembled byte
    addIntGlobal("__z_uart_rx_done", 4);  // 1 = a complete byte is available
    // bit-banged I2C master
    addIntGlobal("__z_i2c_sda_bsrr", 4);
    addIntGlobal("__z_i2c_sda_bit", 4);
    addIntGlobal("__z_i2c_sda_idr", 4);
    addIntGlobal("__z_i2c_scl_bsrr", 4);
    addIntGlobal("__z_i2c_scl_bit", 4);
    addIntGlobal("__z_i2c_scl_idr", 4);
    addIntGlobal("__z_i2c_half", 4);      // half-period delay at 100 kHz
    addIntGlobal("__z_i2c_buf", 64);      // mem_read destination buffer (bytes)
    // flash EEPROM emulation
    addIntGlobal("__z_fl_cur", 4);        // current page base address
    addIntGlobal("__z_fl_off", 4);        // next free byte offset in current page
    addIntGlobal("__z_fl_ps", 4);         // page size (1K F1, 2K L4/G0)
    // RTC (F1)
    addIntGlobal("__z_rtc_woke", 4);      // set by the RTC alarm ISR
    // Modbus RTU slave
    addIntGlobal("__z_mb_idr", 4);        // RX port IDR address
    addIntGlobal("__z_mb_bit", 4);        // RX pin bitmask
    addIntGlobal("__z_mb_half", 4);       // half-bit delay-loop iterations
    addIntGlobal("__z_mb_st", 4);         // RX bit machine state (0 idle / 1 in frame)
    addIntGlobal("__z_mb_bits", 4);       // data bits left to sample
    addIntGlobal("__z_mb_wait2", 4);      // half-steps until next sample
    addIntGlobal("__z_mb_byte", 4);       // byte being assembled
    addIntGlobal("__z_mb_cnt", 4);        // bytes in the frame buffer
    addIntGlobal("__z_mb_sil", 4);        // idle polls since last activity (half-bits)
    addIntGlobal("__z_mb_addr", 4);       // slave address (1..247)
    addIntGlobal("__z_mb_buf", 128);      // RX frame / TX response buffer (bytes)
    addIntGlobal("__z_mb_regs", 256);     // 64 holding registers x 4 bytes
    // SysTick-based time (micros/millis/delay_us), PWM, pulse_in, PRNG
    addIntGlobal("__z_ms", 4);            // millisecond counter (SysTick ISR)
    addIntGlobal("__z_rng", 4);           // LCG state for random()
    addIntGlobal("__z_pwm_bsrr", 4);      // BSRR register address of the PWM pin
    addIntGlobal("__z_pwm_bit", 4);       // bitmask of the PWM pin
    addIntGlobal("__z_pulse_idr", 4);     // IDR register address of the pulse_in pin
    addIntGlobal("__z_pulse_bit", 4);     // bitmask of the pulse_in pin
    gAddr = ig;

    // C17: keep a stack headroom below SRAM top (globals grow up from SRAM_BASE)
    constexpr uint32_t MIN_STACK = 1024;
    if (gAddr + MIN_STACK > sramBase + sramSize) {
        cerr << "stm32: globals overlap the stack area (sram_kb too small?)\n";
        return false;
    }

    // --- function presence map; entry = "main" or first function --------------
    funcOffsets.clear();
    funcOrder.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        funcOffsets[f->name] = 0;
        funcOrder.push_back(f->name);
    }
    entryName = funcOffsets.count("main") ? "main"
              : (funcOrder.empty() ? "" : funcOrder[0]);

    // --- emit user functions --------------------------------------------------
    userImgs.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        FnImg out;
        out.name = f->name;
        if (!emitFunction(f.get(), out)) return false;
        userImgs.push_back(move(out));
    }

    // --- emit runtime helpers referenced from user code (transitive) -----------
    runtimeImgs.clear();
    unordered_set<string> emittedRt;
    vector<string> pendingRt;
    auto collectRt = [&](const FnImg& img) {
        for (auto& bl : img.bls)
            if (bl.target.compare(0, 4, "__z_") == 0) pendingRt.push_back(bl.target);
    };
    for (auto& img : userImgs) collectRt(img);
    for (size_t i = 0; i < pendingRt.size(); i++) {
        const string& n = pendingRt[i];
        if (emittedRt.count(n)) continue;
        emittedRt.insert(n);
        emitRuntime(n);
        collectRt(runtimeImgs.back());
    }
    if (rtcAlarmUsed) {
        // RTC alarm ISR is referenced only from the vector table (no BL).
        emitRuntime("__z_rtc_isr");
    }
    if (systickUsed) {
        // SysTick ISR is referenced only from the vector table (no BL).
        emitRuntime("__z_systick_isr");
    }

    // --- startup image (reset handler: zero SRAM + init globals + GPIO + entry)
    resetFn();
    savedBytes = 0;
    frameSize = 0;
    emitStartup();
    vector<uint8_t> stBytes = move(code);
    vector<CallFix> stBls = callFixups;
    vector<pair<int, int>> stStrSlots = strPatch;
    vector<pair<int, string>> stFuncSlots = funcPatch;

    // --- layout: vector table | startup | functions | runtime | pool -----------
    size_t cursor = rtcAlarmUsed ? 236u : 64u; // F1 RTC alarm: 16 core + 43 IRQ entries
    uint32_t startupOff = (uint32_t)cursor;
    cursor += stBytes.size();
    vector<uint32_t> fnOffsets, rtOffsets;
    for (auto& img : userImgs) {
        cursor = (cursor + 3u) & ~3u;
        fnOffsets.push_back((uint32_t)cursor);
        cursor += img.bytes.size();
    }
    for (auto& img : runtimeImgs) {
        cursor = (cursor + 3u) & ~3u;
        rtOffsets.push_back((uint32_t)cursor);
        cursor += img.bytes.size();
    }
    size_t poolStart = (cursor + 3u) & ~3u;
    strOfs.assign(strings.size(), 0);
    size_t p = poolStart;
    for (size_t i = 0; i < strings.size(); i++) {
        p = (p + 3u) & ~3u;
        strOfs[i] = (uint32_t)p;
        p += strings[i].size() + 1;
    }
    size_t imageSize = p;

    uint32_t flashSize = cfg.flashSize;   // F1=64K, F4/F7/L4=1M, G0=128K
    if (imageSize > flashSize) {
        cerr << "stm32: image (" << imageSize << " bytes) exceeds flash size ("
             << flashSize << ")\n";
        return false;
    }

    for (size_t i = 0; i < userImgs.size(); i++) funcOffsets[userImgs[i].name] = fnOffsets[i];
    for (size_t i = 0; i < runtimeImgs.size(); i++) funcOffsets[runtimeImgs[i].name] = rtOffsets[i];

    // --- assemble the image -----------------------------------------------------
    vector<uint8_t> flash;
    flash.assign(imageSize, 0);
    auto putU32 = [&](size_t pos, uint32_t v) {
        if (pos + 3 >= flash.size()) return;
        flash[pos]     = (uint8_t)(v & 0xFF);
        flash[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
        flash[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
        flash[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
    };

    // vector table: SP, reset handler, 14 default handlers
    emitVectorTable(FLASH_BASE + startupOff,
                    FLASH_BASE + startupOff + (uint32_t)startupSpinPos);
    for (size_t i = 0; i < tableBytes.size(); i++) flash[i] = tableBytes[i];

    auto copyBlock = [&](size_t baseOff, const vector<uint8_t>& bytes) {
        for (size_t i = 0; i < bytes.size(); i++)
            flash[baseOff + i] = bytes[i];
    };

    // patch BL targets (user functions, runtime helpers, or startup labels)
    auto patchCalls = [&](size_t baseOff, const vector<CallFix>& bls) {
        for (auto& bl : bls) {
            auto it = funcOffsets.find(bl.target);
            if (it == funcOffsets.end()) continue;
            uint32_t pc = FLASH_BASE + (uint32_t)baseOff + (uint32_t)bl.pos;
            int32_t rel = (int32_t)((FLASH_BASE + it->second) - (pc + 4));
            uint32_t S   = ((uint32_t)rel >> 24) & 1u;
            uint32_t J1  = 1u ^ (S ^ (((uint32_t)rel >> 23) & 1u));
            uint32_t J2  = 1u ^ (S ^ (((uint32_t)rel >> 22) & 1u));
            uint32_t i10 = ((uint32_t)rel >> 12) & 0x3FFu;
            uint32_t i11 = ((uint32_t)rel >> 1)  & 0x7FFu;
            uint16_t h1 = (uint16_t)(0xF000u | (S << 10) | i10);
            uint16_t h2 = (uint16_t)(0xD000u | (J1 << 13) | (J2 << 11) | i11);
            size_t pos = baseOff + (size_t)bl.pos;
            flash[pos]     = (uint8_t)(h1 & 0xFF);
            flash[pos + 1] = (uint8_t)(h1 >> 8);
            flash[pos + 2] = (uint8_t)(h2 & 0xFF);
            flash[pos + 3] = (uint8_t)(h2 >> 8);
        }
    };
    auto patchSlots = [&](size_t baseOff,
                          const vector<pair<int, int>>& strSlots,
                          const vector<pair<int, string>>& fnSlots) {
        for (auto& sp : strSlots) {
            // strOfs[i] is already an absolute image offset (includes poolStart)
            uint32_t v = FLASH_BASE + strOfs[sp.second];
            putU32(baseOff + (size_t)sp.first, v);
        }
        for (auto& fp : fnSlots) {
            auto it = funcOffsets.find(fp.second);
            uint32_t v = FLASH_BASE + (it == funcOffsets.end() ? 0u : it->second);
            v |= 1u;   // C10: indirect calls jump via BX -> set the Thumb bit
            putU32(baseOff + (size_t)fp.first, v);
        }
    };

    // startup block
    copyBlock(startupOff, stBytes);
    patchCalls(startupOff, stBls);
    patchSlots(startupOff, stStrSlots, stFuncSlots);

    // user functions
    for (size_t i = 0; i < userImgs.size(); i++) {
        size_t off = fnOffsets[i];
        copyBlock(off, userImgs[i].bytes);
        patchCalls(off, userImgs[i].bls);
        patchSlots(off, userImgs[i].strSlots, userImgs[i].funcSlots);
    }
    // runtime helpers
    for (size_t i = 0; i < runtimeImgs.size(); i++) {
        size_t off = rtOffsets[i];
        copyBlock(off, runtimeImgs[i].bytes);
        patchCalls(off, runtimeImgs[i].bls);
        patchSlots(off, runtimeImgs[i].strSlots, runtimeImgs[i].funcSlots);
    }

    // --- write the file ---------------------------------------------------------
    // C4: actually copy the string pool contents into the image (was all zeros)
    for (size_t i = 0; i < strings.size(); i++) {
        size_t off = strOfs[i];
        if (off + strings[i].size() >= flash.size()) {
            cerr << "stm32: string pool overflow\n";
            return false;
        }
        copy(strings[i].begin(), strings[i].end(), flash.begin() + off);
        flash[off + strings[i].size()] = 0;
    }
    ofstream out(outputPath, ios::binary);
    if (!out) { cerr << "stm32: cannot open '" << outputPath << "'\n"; exit(1); }
    out.write((const char*)flash.data(), (streamsize)flash.size());
    out.close();
    if (!out) { cerr << "stm32: cannot write '" << outputPath << "'\n"; exit(1); }
    return true;
}

bool Codegen::compileStm32(const string& outputPath) {
    Stm32 cg(prog);
    return cg.compile(outputPath);
}