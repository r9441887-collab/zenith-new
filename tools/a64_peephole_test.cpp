// ====================================================================
// a64_peephole_test.cpp — unit tests for the AArch64 machine-word pass
//
// The test drives AsmBuf directly: it builds a buffer word by word, runs
// the pass, and compares the result against hand-written expectations.
// Fixup remapping is checked explicitly, because a pass that rewrites
// code but leaves a stale label offset behind is worse than no pass.
//
// Compiled and run by `make test-peephole`; see Makefile.linux.
// ====================================================================
#include "../src/a64peephole.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static int gFail = 0;
static int gChecks = 0;

static void check(bool ok, const std::string& what) {
    gChecks++;
    if (!ok) {
        gFail++;
        std::printf("FAIL: %s\n", what.c_str());
    }
}

static std::vector<uint32_t> words(const AsmBuf& a) {
    std::vector<uint32_t> w;
    for (size_t i = 0; i + 3 < a.c.size(); i += 4)
        w.push_back((uint32_t)a.c[i] | ((uint32_t)a.c[i + 1] << 8) |
                    ((uint32_t)a.c[i + 2] << 16) | ((uint32_t)a.c[i + 3] << 24));
    return w;
}

static std::string hex(const std::vector<uint32_t>& w) {
    std::string s;
    char buf[16];
    for (size_t i = 0; i < w.size(); i++) {
        std::snprintf(buf, sizeof(buf), "%s%08x", i ? " " : "", w[i]);
        s += buf;
    }
    return s;
}

static AsmBuf make(const std::vector<uint32_t>& w) {
    AsmBuf a;
    for (uint32_t x : w) a.u32(x);
    return a;
}

// ---- 1. store -> load of the same slot, same register: load goes away ----
static void testStrLdrSame() {
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64), encAdd(X9, X9, 8)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 1, "strLdrSame counted");
    check(st.wordsIn == 3 && st.wordsOut == 2, "strLdrSame shrinks by one word");
    check(hex(words(a)) == hex({encStrX(X10, XSP, 64), encAdd(X9, X9, 8)}), "strLdrSame result");
}

// ---- 2. store -> load of the same slot, other register: becomes a MOV ----
static void testStrLdrFwd() {
    AsmBuf a = make({encStrX(X10, XSP, 8), encLdrX(X11, XSP, 8)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrFwd == 1, "strLdrFwd counted");
    check(st.wordsOut == 2, "strLdrFwd keeps the word count");
    check(hex(words(a)) == hex({encStrX(X10, XSP, 8), encMov(X11, X10)}), "strLdrFwd result");
}

// ---- 3. a different slot is a real load and must survive ----
static void testStrLdrDifferentSlot() {
    AsmBuf a = make({encStrX(X10, XSP, 8), encLdrX(X10, XSP, 16)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 0 && st.strLdrFwd == 0, "different slot is not a round trip");
    check(words(a).size() == 2, "different slot keeps both words");
}

// ---- 4. the same slot through a different base register is not folded ----
static void testStrLdrDifferentBase() {
    AsmBuf a = make({encStrX(X10, XSP, 8), encLdrX(X10, X9, 8)});
    a64Peephole(a);
    check(hex(words(a)) == hex({encStrX(X10, XSP, 8), encLdrX(X10, X9, 8)}), "different base survives");
}

// ---- 5. MOV Xd, Xd and ADD Xd, Xd, #0 ----
static void testSelfMoves() {
    AsmBuf a = make({encMov(X9, X9), encAdd(X10, X10, 0), encRet()});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.movSelf == 1, "movSelf counted");
    check(st.addZero == 1, "addZero counted");
    check(hex(words(a)) == hex({encRet()}), "self moves removed");
}

// ---- 6. "mov xd, sp" and "add xd, sp, #0" are values, not noise ----
static void testSpIsAValue() {
    AsmBuf a = make({encAdd(X9, XSP, 0), encMov(X10, XSP), encAdd(XSP, XSP, 0)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.addZero == 0 && st.movSelf == 0, "sp is never treated as a self move");
    check(words(a).size() == 3, "sp materialisation kept");
}

// ---- 7. a MOVZ that the next word overwrites ----
static void testDeadMovz() {
    AsmBuf a = make({encMovz(X9, 0x1234, 0), encLdrX(X9, XSP, 0)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.deadMovz == 1, "deadMovz counted");
    check(hex(words(a)) == hex({encLdrX(X9, XSP, 0)}), "dead movz removed");

    // ... but not when the next word reads the register it writes
    AsmBuf b = make({encMovz(X9, 0x1234, 0), encAddReg(X9, X9, X10)});
    check(a64Peephole(b).stats.deadMovz == 0, "movz feeding addReg is live");
    // ... and not a partial (MOVK-style) overwrite
    AsmBuf c = make({encMovz(X9, 0x1234, 0), encMovk(X9, 0x5678, 1)});
    check(a64Peephole(c).stats.deadMovz == 0, "movz feeding movk is live");
    // ... and a 32-bit MOVZ only writes half the register
    AsmBuf d = make({encMovz(X9, 0x1234, 0), encAddReg(X9, X9, X10)});
    check(a64Peephole(d).stats.deadMovz == 0, "no false deadMovz");
}

// ---- 8. a call-free frame does not have to save the LR ----
static void testLeafLr() {
    AsmBuf a = make({encStrX(X30, XSP, 504), encAddReg(X9, X9, X10), encLdrX(X30, XSP, 504), encRet()});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.leafLr == 1, "leafLr counted");
    check(hex(words(a)) == hex({encAddReg(X9, X9, X10), encRet()}), "leaf lr pair removed");

    // The Android prologue keeps the STP (it also allocates sp) and only
    // loses the redundant save/restore pair.
    AsmBuf b = make({encStpX(X30, XZR, XSP, -32, kPairPre), encStrX(X30, XSP, 504),
                     encLdrX(X30, XSP, 504), encAdd(XSP, XSP, 32), encRet()});
    A64PeepholeStats sb = a64Peephole(b).stats;
    check(sb.leafLr == 1, "leafLr with the frame STP counted");
    check(hex(words(b)) == hex({encStpX(X30, XZR, XSP, -32, kPairPre), encAdd(XSP, XSP, 32), encRet()}),
          "frame STP kept, lr pair removed");
}

// ---- 9. a function that calls something must keep its LR ----
static void testNonLeafKeepsLr() {
    AsmBuf a = make({encStrX(X30, XSP, 504), encBl(0), encLdrX(X30, XSP, 504), encRet()});
    a.bls.push_back({0, "f"});
    a.bls[0].pos = 4;
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.leafLr == 0, "no leafLr when the function calls out");
    check(hex(words(a)) == hex({encStrX(X30, XSP, 504), encBl(0), encLdrX(X30, XSP, 504), encRet()}),
          "lr pair kept in a non-leaf");
}

// ---- 10. a save without a matching reload is left alone ----
static void testUnbalancedLr() {
    AsmBuf a = make({encStrX(X30, XSP, 504), encRet()});
    check(a64Peephole(a).stats.leafLr == 0, "unbalanced lr is not touched");
}

// ---- 11. fixups and labels move with the code ----
static void testFixupRemap() {
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64), encCbzx(X9, 0)});
    a.label(0);            // label 0 sits after the deleted load, at byte 8
    a.labelPos[0] = 8;
    a.brs.push_back({8, 0, 2, 0, X9});   // the cbz at byte 8
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 1, "strLdrSame before a fixup");
    check(hex(words(a)) == hex({encStrX(X10, XSP, 64), encCbzx(X9, 0)}), "load dropped in front of a branch");
    check(a.brs[0].pos == 4, "branch position remapped to the new offset");
    check(a.labelPos[0] == 4, "label position remapped");
    a.resolveBranches();   // must not throw: the branch still has a target
    check(words(a)[1] == encCbzx(X9, 0), "resolved branch still targets the label");
}

// ---- 12. a pinned word is never rewritten ----
static void testPinnedWord() {
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64)});
    a.brs.push_back({4, -1, 0, 0, 0});   // a branch fixup parked on the load
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 0, "a word carrying a fixup is left alone");
    check(words(a).size() == 2, "pinned word kept");
}

// ---- 13. the pass is a no-op when switched off ----
static void testKillSwitch() {
    ::setenv("ZT_NO_PEEPHOLE", "1", 1);
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64)});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 0 && words(a).size() == 2, "ZT_NO_PEEPHOLE disables the pass");
    check(a64PeepholeEnabled() == false, "kill switch reported");
    ::unsetenv("ZT_NO_PEEPHOLE");
    check(a64PeepholeEnabled() == true, "kill switch is off by default");
}

// ---- 14. a real function body survives a round trip ----
static void testRealisticBody() {
    // sub sp, sp, #16 ; str x0,[sp] ; ldr x0,[sp] ; add sp, sp, #16 ; ret
    AsmBuf a = make({encSub(XSP, XSP, 16), encStrX(X0, XSP, 0), encLdrX(X0, XSP, 0),
                     encAdd(XSP, XSP, 16), encRet()});
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 1, "realistic body: one round trip");
    check(st.leafLr == 0, "realistic body: lr pair is not there to remove");
    check(hex(words(a)) == hex({encSub(XSP, XSP, 16), encStrX(X0, XSP, 0), encAdd(XSP, XSP, 16), encRet()}),
          "realistic body result");
}

// ---- 15. a branch landing in the middle of a window is respected ----
static void testBranchBetweenPair() {
    // The store is a branch target, so the pair is still local -- but a
    // label *between* the store and the load pins both and nothing moves.
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64)});
    a.labelPos.assign(2, -1);
    a.labelPos[0] = 0;
    a.labelPos[1] = 4;
    A64PeepholeStats st = a64Peephole(a).stats;
    check(st.strLdrSame == 0, "a labelled pair is left alone");
    check(words(a).size() == 2, "labelled words kept");
    check(a.labelPos[0] == 0 && a.labelPos[1] == 4, "labels unmoved");
}

// ---- 16. positions tracked outside AsmBuf survive the pass --------------
// A64Fn::dfs records the offset of an ADRP + ADD pair and the image patcher
// writes at that offset later, so the pair has to be declared. Without the
// declaration the ADD is a legal addZero hit and the patched address lands on
// whatever instruction followed it -- which is exactly how the --ir smoke
// test came to hang with no output at all.
static void testExternalPositions() {
    // adrp x19, #0 ; add x19, x19, #0 ; str x10, [sp, #64] ; ldr x10, [sp, #64]
    AsmBuf free = make({encAdrp(X19, 0, 0), encAdd(X19, X19, 0),
                        encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64)});
    A64PeepholeRun plain = a64Peephole(free);
    check(plain.stats.addZero == 1, "undeclared adrp add is treated as addZero");
    check(plain.stats.strLdrSame == 1, "and the round trip folds as well");
    check(words(free).size() == 2, "both the add and the load are removed");
    // A deleted word maps to the offset the next surviving word took, which
    // is why an undeclared position is a bug and not a shrug: it lands on a
    // different instruction instead of failing.
    check(plain.remap(0) == 0, "adrp is the first word and stays there");
    check(plain.remap(4) == 4, "deleted add points at the store behind it");
    check(plain.remap(8) == 4, "the store moved down by one word");
    check(plain.remap(12) == 8, "the deleted load points at the store too");

    AsmBuf declared = make({encAdrp(X19, 0, 0), encAdd(X19, X19, 0),
                            encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64)});
    A64PeepholeRun run = a64Peephole(declared, {0});
    check(run.stats.addZero == 0, "declared adrp add is not touched");
    check(run.stats.strLdrSame == 1, "the round trip behind it still folds");
    check(hex(words(declared)) == hex({encAdrp(X19, 0, 0), encAdd(X19, X19, 0), encStrX(X10, XSP, 64)}),
          "declared pair kept, redundant load dropped");
    check(run.remap(0) == 0 && run.remap(4) == 4, "declared pair unmoved");
    check(run.remap(8) == 8, "store unmoved");
    check(run.remap(12) == 12, "load position maps onto the store that followed");
}

// ---- 17. the pass is idempotent (PLAN.md section 1) ---------------------
static void testIdempotent() {
    AsmBuf a = make({encStrX(X10, XSP, 64), encLdrX(X10, XSP, 64),
                     encMovz(X9, 0x1234, 0), encLdrX(X9, XSP, 0),
                     encAdd(X10, X10, 0), encMov(X9, X9),
                     encStrX(X10, XSP, 64), encLdrX(X11, XSP, 64),
                     encRet()});
    a64Peephole(a);
    const std::string first = hex(words(a));
    const size_t n = words(a).size();
    A64PeepholeStats st = a64Peephole(a).stats;
    check(hex(words(a)) == first, "second run changes nothing");
    check(words(a).size() == n, "second run keeps the word count");
    check(st.strLdrSame == 0 && st.strLdrFwd == 0 && st.addZero == 0 &&
          st.movSelf == 0 && st.deadMovz == 0 && st.leafLr == 0,
          "second run reports no hits");
}

int main() {
    testStrLdrSame();
    testStrLdrFwd();
    testStrLdrDifferentSlot();
    testStrLdrDifferentBase();
    testSelfMoves();
    testSpIsAValue();
    testDeadMovz();
    testLeafLr();
    testNonLeafKeepsLr();
    testUnbalancedLr();
    testFixupRemap();
    testPinnedWord();
    testKillSwitch();
    testRealisticBody();
    testBranchBetweenPair();
    testExternalPositions();
    testIdempotent();

    std::printf("a64 peephole: %d checks, %d failed\n", gChecks, gFail);
    return gFail == 0 ? 0 : 1;
}
