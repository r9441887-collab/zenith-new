// ====================================================================
// a64peephole.cpp — AArch64 machine-word peephole
//
// Every rule below is a statement about the encoded word, not about the
// IR, and every rule is local: it only ever looks at one or two adjacent
// words and never needs to know whether a register is live afterwards.
// The two facts that make that possible on AArch64:
//
//   * LDR/STR (unsigned immediate) never touch the flags or any register
//     other than their own, so a store immediately followed by a load of
//     the same address is a pure round trip through memory.
//   * 64-bit MOVZ with LSL #0 writes all 64 bits of its destination, so
//     it is dead as soon as the next instruction rewrites that register
//     without reading it.
//
// Word deletions shift every following byte offset, so the pass remaps
// AsmBuf's fixup positions (brs / bls / dfx) and labelPos. Words that
// carry a fixup or a label are never rewritten or removed.
// ====================================================================
#include "a64peephole.h"
#include <cstdlib>
#include <cstdio>

namespace {

A64PeepholeStats gStats;
bool gReported = false;

inline uint32_t getW(const std::vector<uint8_t>& c, int i) {
    const size_t o = (size_t)i * 4;
    return (uint32_t)c[o] | ((uint32_t)c[o + 1] << 8) | ((uint32_t)c[o + 2] << 16) | ((uint32_t)c[o + 3] << 24);
}
inline void setW(std::vector<uint8_t>& c, int i, uint32_t w) {
    const size_t o = (size_t)i * 4;
    c[o]     = (uint8_t)(w & 0xFF);
    c[o + 1] = (uint8_t)((w >> 8) & 0xFF);
    c[o + 2] = (uint8_t)((w >> 16) & 0xFF);
    c[o + 3] = (uint8_t)((w >> 24) & 0xFF);
}
inline void pushW(std::vector<uint8_t>& c, uint32_t w) {
    c.push_back((uint8_t)(w & 0xFF));
    c.push_back((uint8_t)((w >> 8) & 0xFF));
    c.push_back((uint8_t)((w >> 16) & 0xFF));
    c.push_back((uint8_t)((w >> 24) & 0xFF));
}

// ---- word classifiers (AArch64 encodings) ----
// LDR Xt, [Xn, #uimm12*8] and STR Xt, [Xn, #uimm12*8]. Bits 31..22 fix
// the whole form: size=11 (64-bit), V=0, bits 25:24=01 and opc=00/01
// select store/load, bit 21=0 and bit 23=0 rule out the unscaled (LDUR)
// and pre/post-indexed variants, which live in different bit patterns.
inline bool isLdrX(uint32_t w) { return (w & 0xFFC00000u) == 0xF9400000u; }
inline bool isStrX(uint32_t w) { return (w & 0xFFC00000u) == 0xF9000000u; }
inline int  ldstRt(uint32_t w) { return (int)(w & 31); }
inline int  ldstRn(uint32_t w) { return (int)((w >> 5) & 31); }
inline uint32_t ldstImm(uint32_t w) { return ((w >> 10) & 0xFFF) * 8; }
// Same effective address: base register (9:5) plus the 12-bit scaled
// displacement (21:10), i.e. every bit of the word except the opcode above
// bit 21 and the destination register below bit 5. Bits 10..5 -- the tail
// of the displacement and the whole base register -- are all part of the
// address, so none of them may be ignored.
inline bool sameAddr(uint32_t a, uint32_t b) { return ((a ^ b) & 0x003FFFFEu) == 0; }

// ADD Xd, Xn, #imm12 (64-bit, no LSL). SUBS/CMP set the flags as well, so
// they are deliberately not matched by the addZero rule.
inline bool isAddImmX(uint32_t w) { return (w & 0xFFE00000u) == 0x91000000u; }
// MOV Xd, Xn, i.e. the ORR Xd, XZR, Xn alias the emitters use. In this
// encoding the source sits in bits 20:16 (Rm), not in the Rn field at 9:5,
// which is fixed to zero by the alias.
inline bool isMovXd(uint32_t w) { return (w & 0xFFE0FFE0u) == 0xAA0003E0u; }
inline int  movSrc(uint32_t w) { return (int)((w >> 16) & 31); }
// MOVZ Xd, #imm16, LSL #0 -- a full 64-bit write of the destination.
inline bool isMovzX(uint32_t w) { return (w & 0xFFE00000u) == 0xD2800000u; }
// MOVN Xd, #imm16, LSL #0.
inline bool isMovnX(uint32_t w) { return (w & 0xFFE00000u) == 0x92800000u; }
// 64-bit pair load/store (STP/LDP): opc=10, V=0 and the 010 mode field pin
// the whole form, so Rt1/Rt2/Rn are the only variable part left.
inline bool isPairX(uint32_t w, bool isLoad, int& rt1, int& rt2, int& rn) {
    if ((w & 0xFEC00000u) != (isLoad ? 0xA9400000u : 0xA9000000u)) return false;
    rt1 = (int)(w & 31);
    rt2 = (int)((w >> 10) & 31);
    rn = (int)((w >> 5) & 31);
    return true;
}

// SUBS (immediate) sets the flags, so it is not an addZero candidate -- but
// it does define its destination like any other add.
inline bool isSubsImmX(uint32_t w) { return (w & 0xFFE00000u) == 0xF1000000u; }

// Every 64-bit form that defines bits 4:0 of the word, so that a single
// test catches "this instruction writes x30". Branches, compares against
// XZR and stores are deliberately absent: they do not define a register.
inline bool definesRd(uint32_t w) {
    return isMovzX(w) || isMovnX(w) || isAddImmX(w) || isSubsImmX(w) || isMovXd(w) || isLdrX(w) ||
           (w & 0x7FE0FC00u) == 0x0B000000u || (w & 0x7FE0FC00u) == 0x4B000000u ||   // ADD/SUB reg
           (w & 0x7FE0FC00u) == 0x6B000000u ||                                         // SUBS reg
           (w & 0x7F200000u) == 0x0A000000u ||                                         // AND/ORR/EOR/ANDS
           (w & 0x7FE08000u) == 0x1B000000u || (w & 0x7FE08000u) == 0x1B008000u ||   // MUL/MADD/MSUB
           (w & 0x7FE0FC00u) == 0x1AC00000u ||                                         // UDIV/SDIV/shifts
           (w & 0x1FE00000u) == 0x1A800000u;                                          // CSEL/CSINC/CSET
}

// Does `w` define all 64 bits of `reg` without reading `reg` first? Only
// the forms the backends actually emit are listed; anything unrecognised
// answers "no", which just leaves the MOVZ in place.
bool overwritesNoRead(uint32_t w, int reg) {
    if (isMovzX(w) || isMovnX(w)) return (int)(w & 31) == reg;
    if (isLdrX(w)) return ldstRt(w) == reg;
    if (isMovXd(w)) return (int)(w & 31) == reg && movSrc(w) != reg;
    if (isAddImmX(w)) return (int)(w & 31) == reg && ldstRn(w) != reg && (w & 0x003FFC00u) == 0;
    // ADD/SUB (shifted register), without the flag-setting S bit.
    if ((w & 0x7FE0FC00u) == 0x0B000000u || (w & 0x7FE0FC00u) == 0x4B000000u) {
        const int rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        return (int)(w & 31) == reg && rn != reg && rm != reg;
    }
    // AND/ORR/EOR/ANDS (shifted register).
    if ((w & 0x7F200000u) == 0x0A000000u) {
        const int rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        return (int)(w & 31) == reg && rn != reg && rm != reg;
    }
    // MUL/MADD/MSUB.
    if ((w & 0x7FE08000u) == 0x1B000000u || (w & 0x7FE08000u) == 0x1B008000u) {
        const int rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31), ra = (int)((w >> 10) & 31);
        return (int)(w & 31) == reg && rn != reg && rm != reg && ra != reg;
    }
    // UDIV/SDIV/LSL/LSR/ASR/ROR (2-source, register shift).
    if ((w & 0x7FE0FC00u) == 0x1AC00000u) {
        const int rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        return (int)(w & 31) == reg && rn != reg && rm != reg;
    }
    // CSEL/CSINC (Csel Rd, Rn, Rm, cond).
    if ((w & 0x1FE00000u) == 0x1A800000u) {
        const int rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        return (int)(w & 31) == reg && rn != reg && rm != reg;
    }
    return false;
}

}  // namespace

bool a64PeepholeEnabled() {
    const char* e = std::getenv("ZT_NO_PEEPHOLE");
    return !(e && *e);
}

// Identity offset table: useful when nothing is rewritten, and always the
// answer when the pass is switched off, so that callers can remap unconditionally.
static std::vector<int> identityNewPos(size_t nwords) {
    std::vector<int> t(nwords + 1, 0);
    for (size_t i = 0; i <= nwords; i++) t[i] = (int)i * 4;
    return t;
}

A64PeepholeRun a64Peephole(AsmBuf& a, const std::vector<int>& external) {
    A64PeepholeRun run;
    A64PeepholeStats& st = run.stats;
    if (a.c.empty() || (a.c.size() % 4) != 0) {
        run.newPos = identityNewPos(a.c.empty() ? 0 : a.c.size() / 4);
        return run;
    }
    const int nw = (int)(a.c.size() / 4);
    st.wordsIn = nw;
    st.wordsOut = nw;
    run.newPos = identityNewPos((size_t)nw);
    if (!a64PeepholeEnabled()) {
        // Off still reports the word count, so the summary line reads
        // "3292 -> 3292" instead of "0 -> 0": nothing changed, but what was
        // measured is stated either way.
        gStats.wordsIn += st.wordsIn;
        gStats.wordsOut += st.wordsOut;
        return run;
    }

    // A word that carries a fixup (b / b.cond / cbz / cbnz / bl / the MOVZ
    // of a data address), a label, or an offset the caller tracks on its own
    // must stay exactly where it is, so no rule is allowed to touch it.
    std::vector<char> pinned((size_t)nw, 0);
    auto pin = [&](int bytePos) {
        if (bytePos >= 0 && (bytePos % 4) == 0 && (bytePos / 4) < nw)
            pinned[(size_t)(bytePos / 4)] = 1;
    };
    for (const auto& br : a.brs) pin(br.pos);
    for (const auto& bl : a.bls) pin(bl.pos);
    for (const auto& df : a.dfx) pin(df.pos);
    for (int p : a.labelPos) pin(p);
    // External fixups are two words wide (ADRP + its low-12-bits ADD, MOVZ +
    // its MOVK): pinning both is what keeps `add xd, xd, #0` after an ADRP
    // from looking like a removable `addZero`. Pinning one word too many can
    // only cost an optimization, never correctness.
    for (int p : external) { pin(p); pin(p + 4); }

    std::vector<char> dead((size_t)nw, 0);

    // ---- leaf frame: the LR save/restore pair is a round trip ----------
    // A function that never calls anything never has its x30 overwritten,
    // so saving and reloading it is dead weight. The frame itself (the STP
    // that also allocates sp, or the SUB) is kept.
    if (a.bls.empty()) {
        int saveIdx = -1, loadIdx = -1;
        uint32_t frameOff = 0;
        bool otherX30 = false;
        for (int i = 0; i < nw && !otherX30; i++) {
            const uint32_t w = getW(a.c, i);
            if (isStrX(w) && ldstRt(w) == X30 && ldstRn(w) == XSP) {
                if (saveIdx >= 0) { otherX30 = true; break; }
                frameOff = ldstImm(w);
                saveIdx = i;
                continue;
            }
            if (isLdrX(w) && ldstRt(w) == X30 && ldstRn(w) == XSP) {
                if (loadIdx >= 0 || ldstImm(w) != frameOff) { otherX30 = true; break; }
                loadIdx = i;
                continue;
            }
            int t1 = 0, t2 = 0, prn = 0;
            if (isPairX(w, false, t1, t2, prn) || isPairX(w, true, t1, t2, prn)) {
                // The frame STP/LDP carries x30 but has to stay: it also
                // allocates (or releases) sp.
                if (t1 == X30 || t2 == X30) continue;
            }
            if (definesRd(w) && (int)(w & 31) == X30) { otherX30 = true; break; }
        }
        if (!otherX30 && saveIdx >= 0 && loadIdx >= 0 &&
            !pinned[(size_t)saveIdx] && !pinned[(size_t)loadIdx]) {
            dead[(size_t)saveIdx] = 1;
            dead[(size_t)loadIdx] = 1;
            st.leafLr++;
        }
    }

    // ---- local rewrites ----
    for (int i = 0; i + 1 < nw; i++) {
        if (dead[(size_t)i] || dead[(size_t)(i + 1)]) continue;
        if (pinned[(size_t)i] || pinned[(size_t)(i + 1)]) continue;
        const uint32_t w0 = getW(a.c, i);
        const uint32_t w1 = getW(a.c, i + 1);

        // STR Xt,[Xn,#o] ; LDR Xt,[Xn,#o] -- the load re-reads what the
        // store just wrote into the same register, so it changes nothing.
        // STR Xt,[Xn,#o] ; LDR Xu,[Xn,#o] -- same round trip, but the value
        // never has to travel through memory at all.
        if (isStrX(w0) && isLdrX(w1) && sameAddr(w0, w1)) {
            if (ldstRt(w0) == ldstRt(w1)) {
                dead[(size_t)(i + 1)] = 1;
                st.strLdrSame++;
            } else {
                setW(a.c, i + 1, encMov(ldstRt(w1), ldstRt(w0)));
                st.strLdrFwd++;
            }
            i++;
            continue;
        }
        // ADD Xd, Xn, #0 with d == n: a three-operand spelling of "do
        // nothing". d == 31 is excluded, so "mov xd, sp" is never lost.
        if (isAddImmX(w0) && ((w0 >> 10) & 0xFFF) == 0 && ((w0 >> 22) & 1) == 0 &&
            (int)(w0 & 31) == (int)((w0 >> 5) & 31) && (int)((w0 >> 5) & 31) != XSP) {
            dead[(size_t)i] = 1;
            st.addZero++;
            continue;
        }
        // MOV Xd, Xd.
        if (isMovXd(w0) && (int)(w0 & 31) == movSrc(w0)) {
            dead[(size_t)i] = 1;
            st.movSelf++;
            continue;
        }
        // MOVZ Xd, #v whose destination the next word rewrites from scratch.
        if (isMovzX(w0) && (int)(w0 & 31) != XSP && overwritesNoRead(w1, (int)(w0 & 31))) {
            dead[(size_t)i] = 1;
            st.deadMovz++;
            continue;
        }
    }

    const bool hits = st.strLdrSame || st.strLdrFwd || st.addZero ||
                      st.movSelf || st.deadMovz || st.leafLr;

    // Accumulate first: even a run that changed nothing contributes its word
    // count to the report.
    gStats.wordsIn += st.wordsIn;
    gStats.wordsOut += st.wordsOut;
    gStats.strLdrSame += st.strLdrSame;
    gStats.strLdrFwd += st.strLdrFwd;
    gStats.addZero += st.addZero;
    gStats.movSelf += st.movSelf;
    gStats.deadMovz += st.deadMovz;
    gStats.leafLr += st.leafLr;
    if (!hits) return run;

    // ---- compact and remap ----
    std::vector<uint32_t> out;
    out.reserve((size_t)nw);
    for (int i = 0; i < nw; i++) {
        run.newPos[(size_t)i] = (int)out.size() * 4;
        if (!dead[(size_t)i]) out.push_back(getW(a.c, i));
    }
    run.newPos[(size_t)nw] = (int)out.size() * 4;

    a.c.clear();
    a.c.reserve(out.size() * 4);
    for (uint32_t w : out) pushW(a.c, w);

    // Pinned words are never deleted, so every fixup and label lands on a
    // word that survived and maps to a real offset.
    auto remap = [&](int& p) {
        if (p >= 0 && (p % 4) == 0 && (p / 4) <= nw) p = run.newPos[(size_t)(p / 4)];
    };
    for (auto& br : a.brs) remap(br.pos);
    for (auto& bl : a.bls) remap(bl.pos);
    for (auto& df : a.dfx) remap(df.pos);
    for (int& p : a.labelPos) { if (p >= 0) remap(p); }

    st.wordsOut = (int)out.size();
    gStats.wordsOut = gStats.wordsOut - nw + (int)out.size();
    return run;
}

void a64PeepholeReset() {
    gStats = A64PeepholeStats();
    gReported = false;
}

A64PeepholeStats a64PeepholeTotals() {
    return gStats;
}

void a64PeepholeReport(const char* tag) {
    if (gReported || gStats.wordsIn == 0) return;
    gReported = true;
    const int hits = gStats.strLdrSame + gStats.strLdrFwd + gStats.addZero +
                     gStats.movSelf + gStats.deadMovz + gStats.leafLr;
    if (hits == 0) return;
    std::printf("a64 peephole: %d -> %d words (-%d), str/ldr %d, str/ldr->mov %d, "
                "add0 %d, mov-self %d, dead-movz %d, leaf-lr %d [%s]\n",
                gStats.wordsIn, gStats.wordsOut, gStats.wordsIn - gStats.wordsOut,
                gStats.strLdrSame, gStats.strLdrFwd, gStats.addZero,
                gStats.movSelf, gStats.deadMovz, gStats.leafLr, tag);
}
