#pragma once
#include "ir.h"
#include <string>

// IRAsmWasm: lowers the optimized assembler-IR into a WebAssembly module.
//
// This is a *register-machine* backend: every scalar virtual register of the
// IR becomes a wasm local (i64 for ints/pointers, f32 for floats), so values
// live in the register file and are never spilled to memory unless they are
// int/float hybrids (which the shared allocation engine reports as spills).
// Multi-slot aggregates (structs/arrays) live in a soft-stack frame in linear
// memory, addressed relative to the SP global (#0).
//
// The module exports "_start" (entry function) and "memory", and imports the
// environment functions zt_print_str/int/float, zt_exit, zt_sleep, zt_rdtsc
// and zt_halt plus one import per `extern` function.
struct IRAsmWasm {
    IRAsmWasm(IRProgram& ir) : ir_(ir) {}
    bool compile(const std::string& outputPath);

    IRProgram& ir_;
};