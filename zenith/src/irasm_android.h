#pragma once
#include "ir.h"
#include "a64peephole.h"
#include <cstdint>
#include <string>
#include <vector>

// ====================================================================
// IRAsmAndroid — the "app android" backend of the assembler-IR path
//
// Same IR as the bare-metal "app arm64" target, but for a real device:
//
//   * the output is an ELF64 AArch64 ET_EXEC executable, not a flat image,
//     so `adb push` / `./a.elf` on a device works;
//   * the runtime is raw Linux/AArch64 syscalls (svc #0) — no Bionic, no
//     PL011: stdout is fd 1 and the kernel does the rest;
//   * argc/argv/envp come off the stack the kernel built, and the page size
//     comes from the auxv, because Android devices do not agree on 4 KiB
//     (16 KiB and 64 KiB are also in the field);
//   * the API level selects the .note.android.ident revision and the
//     64 KiB segment alignment Android 15 (API 35) requires.
//
// Register convention (this backend's own, and the reason several
// optimizations below are possible at all):
//
//   x0..x7   syscall / call arguments, x0 the result
//   x9,x10   scratch (X9 also the data address scratch)
//   x11      scratch for the third operand
//   x19      base of the data segment (globals + string pool)
//   x20      argc
//   x21      the kernel's initial SP (argv, envp, auxv live here)
//   v0..v7   f32 scratch
//   x30      LR
//
// Every IR virtual register is an 8-byte frame slot at [SP + 8*v]; a float
// value lives in the low 4 bytes of its slot, which is what keeps one slot
// layout for both int and float code.
// ====================================================================
struct IRAsmAndroid {
    IRAsmAndroid(IRProgram& ir, uint32_t apiLevel, uint32_t minSdk)
        : ir_(ir), apiLevel_(apiLevel), minSdk_(minSdk) {}

    bool compile(const std::string& outputPath);

    // helpers actually referenced by the program (dead ones are never emitted)
    std::vector<std::string> emittedHelpers;
    // pages in one mmap page, from the auxv when available
    uint64_t auxPageSize = 0;
    // a64 peephole counters for this compile(), summed over every buffer the
    // pass saw (functions, helpers, startup); read back for the summary line
    A64PeepholeStats peepholeStats;

    IRProgram& ir_;
    uint32_t apiLevel_;
    uint32_t minSdk_;
};
