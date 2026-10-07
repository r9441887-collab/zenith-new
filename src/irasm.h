#pragma once
#include "ir.h"
#include <string>

// IRAsm: lowers the optimized assembler-IR into a Windows x86-64 PE console
// executable.
//
// Calling conventions:
//   - User functions: custom stack convention. The caller stores each argument
//     (8 bytes) at [rsp + 8*i] for i in 0..nargs-1 and calls. The callee reads
//     them back at [rsp + 8 + 8*i] at entry and copies them into its own frame
//     slots. Integer returns go in RAX, float returns in XMM0 (low 32 bits).
//   - Imported functions (ICall): standard Win64 ABI (RCX/RDX/R8/R9 + XMM0-3,
//     stack args at [rsp+32+8*(i-4)], 32-byte shadow space reserved).
//
// Frame layout (after the prologue):
//   [rsp .. rsp+32)        shadow space for imported calls
//   [rsp+32 .. rsp+32+S)   function slots (S = maxSlot * 8)
//   F = frame size (>= 32+S, F % 16 == 8 so rsp is 16-aligned at call sites).
struct IRAsm {
    IRAsm(IRProgram& ir);
    bool compile(const std::string& outputPath);

    IRProgram& ir_;
};
