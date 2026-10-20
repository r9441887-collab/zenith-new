#pragma once
// ====================================================================
// andropt — the 'app android' optimization pass
//
// Runs after IROpt/IRSSA and before the backend, on the assembler-IR only,
// and only for `app android`. Everything it does is a property of Android
// and not of AArch64 or of Zenith in general:
//
//   * syscalls inlined        a helper that is one `svc #0` becomes the
//                             syscall itself — no BL, no frame, no register
//                             shuffling. The numbers and the error
//                             convention come from the asm-generic table
//                             Android inherits from Linux.
//   * literal writes fused    println("text") becomes a single write(2) with
//                             a length the compiler already knows, so the
//                             strlen walk and the second syscall for the
//                             newline disappear.
//   * API-level fallbacks     a syscall that only exists from Android N
//                             (getrandom from 28, statx from 30) is swapped
//                             for the pre-N implementation when the program
//                             declares `min_sdk:` below that. This is the one
//                             place in the compiler where the *device's*
//                             release level changes the emitted code.
//
// None of this is valid for another target: the bare-metal ARM64 backend has
// no kernel to call, the x86/WASM backends have no svc, and no other target
// has an API level. The pass therefore refuses to run without all three of
// the target, the platform and the API level.
// ====================================================================
#include "ir.h"
#include <cstdint>
#include <string>

// ---- what the pass did (reported by main.cpp) ----
struct AndroptStats {
    int syscallsInlined = 0;   // bl __z_getpid -> mov x8,#172; svc #0
    int writesFused = 0;       // println("x") -> one write(2), length known
    int fallbacks = 0;         // api-gated rewrites for older devices
    int instrsBefore = 0;
    int instrsAfter = 0;
};

// How a kernel -errno turns into the value Zenith sees.
// AArch64 hands errors back as -errno, i.e. in [-4095, -1]; read as an
// unsigned 64-bit value those sit just under 2^64, far above any user
// address, so "below -4095" is the success test.
enum AndroidClamp {
    kClampErrToZero = 0,     // -errno -> 0            (most calls)
    kClampZeroOkToOne = 1,   // "0 means success" -> 1, -errno -> 0
    kClampRaw = 2,           // hand the kernel value back untouched
};

// The runtime helpers that are a single syscall. `arity` is how many
// argument registers the kernel reads (x0..xN), which can be more than the
// Zenith-level call passes: the extra ones are forced to zero by the
// inliner, exactly as the helper body does.
//
// `inlinable` is 0 for the calls that need a different argument order than
// the Zenith builtin uses (openat/statx/unlinkat/mkdirat/renameat all take
// AT_FDCWD in front, memfd_create takes a flag) or a buffer on the stack
// (statx). Those keep their helper: the shuffle is not expressible as
// "load the arguments in order, then svc".
struct AndroidSyscall {
    const char* helper;
    int nr;
    int arity;
    int clamp;
    int minApi;        // first Android API level that exposes the syscall
    const char* legacy;   // pre-minApi helper, or null when there is none
    int inlinable;
};

extern const AndroidSyscall kAndroidSyscalls[];
extern const int kAndroidSyscallCount;

struct Andropt {
    Andropt(IRProgram& ir, uint32_t apiLevel, uint32_t minSdk)
        : ir_(ir), apiLevel_(apiLevel), minSdk_(minSdk) {}
    void run();
    AndroptStats stats;
    std::vector<std::string> notes;   // e.g. "random_bytes -> /dev/urandom"

private:
    IRProgram& ir_;
    uint32_t apiLevel_;
    uint32_t minSdk_;
    const AndroidSyscall* findSyscall(const std::string& helper) const;
    void inlineSyscalls();
    void fuseLiteralWrites();
    void apiGate();
    int poolString(const std::string& s);
};
