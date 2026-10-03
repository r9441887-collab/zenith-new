#pragma once
// ====================================================================
// a64peephole.h — AArch64 machine-word peephole
//
// Runs on the encoded instruction words of an AsmBuf, i.e. *after* the
// assembler-IR has been lowered and *before* the branch/data fixups are
// resolved and the buffer is placed in the image. It is the only place
// where Zenith can see the real AArch64 encodings, so it is also the only
// place where the ISA's own redundancy can be used: an `add x0, x0, #0`,
// a `mov x0, x0` and a store/load round trip through the frame are not
// visible anywhere above this layer, and on AArch64 they are all one
// word shorter (or entirely free) once they are recognised.
//
// Nothing here is architecture-neutral: the patterns are matched on the
// AArch64 bit layouts, so the pass is wired into the two A64 backends
// only (`app arm64`, `app android`) and never runs for x86/WASM.
//
// Set ZT_NO_PEEPHOLE=1 to turn it off (byte-for-byte the old output).
// ====================================================================
#include "asm_a64.h"

// Counters, one per rewrite kind. Kept separate so the report can show
// which pattern actually fires on a given program instead of a single
// opaque "words saved" number.
struct A64PeepholeStats {
    int wordsIn = 0;
    int wordsOut = 0;
    int strLdrSame = 0;   // STR Xt,[Xn,#o] ; LDR Xt,[Xn,#o] -> the LDR is gone
    int strLdrFwd  = 0;   // STR Xt,[Xn,#o] ; LDR Xu,[Xn,#o] -> MOV Xu, Xt
    int addZero    = 0;   // ADD Xd, Xn, #0 with d == n
    int movSelf    = 0;   // MOV Xd, Xd
    int deadMovz   = 0;   // MOVZ Xd, #v whose destination is overwritten
    int leafLr     = 0;   // LR save/restore pair in a call-free function
};

bool a64PeepholeEnabled();

// One run of the pass over a single AsmBuf. `newPos` maps the byte offset a
// word had *before* the pass to the offset it ended up at; anything that
// tracked a position outside AsmBuf has to go through `remap`, and the very
// same positions have to be handed to `external` so they get pinned.
//
// Two places in the Android backend record raw byte offsets into an AsmBuf
// instead of going through AsmBuf::brs / bls / dfx:
//
//   * A64Fn::dfs, the ADRP + ADD data fixups (their ADD is the low-12-bits
//     half of the pair, so deleting it silently relocates the fixup);
//   * Startup::adrpPos / addPos / blPos, patched after the buffer is copied
//     into the image.
//
// Passing them in is not optional: without a pin, `add xd, xd, #0` right
// after an ADRP is a legal `addZero` hit, and the patcher then writes the
// pair's result over whatever instruction followed it.
struct A64PeepholeRun {
    A64PeepholeStats stats;
    std::vector<int> newPos;   // [old word index] -> new byte offset
    int remap(int oldBytePos) const {
        if (oldBytePos < 0) return oldBytePos;
        const size_t idx = (size_t)(oldBytePos / 4);
        if (idx >= newPos.size()) return oldBytePos;
        return newPos[idx];
    }
};

A64PeepholeRun a64Peephole(AsmBuf& a, const std::vector<int>& external = std::vector<int>());

// The pass runs once per buffer (per function, plus the helpers and the
// startup), so its counters are accumulated process-wide. A backend clears
// them before it starts and reads them back at the end, which is how the
// numbers reach the `IR android:` summary line in src/main.cpp.
void a64PeepholeReset();
A64PeepholeStats a64PeepholeTotals();

// Standalone one-liner for backends that have no summary line of their own
// (the bare-metal `app arm64` path). Prints nothing when nothing was hit.
void a64PeepholeReport(const char* tag);
