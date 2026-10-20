#pragma once
#include "ir.h"
#include <string>

namespace mix { struct MixContext; }

// IRAsmArm64: lowers the optimized assembler-IR into an AArch64 raw firmware
// image for QEMU's "virt" machine. Register machine over x0-x28 and v1-v31
// with a hybrid spill; console output goes through the PL011 UART.
struct IRAsmArm64 {
    IRAsmArm64(IRProgram& ir) : ir_(ir) {}
    bool compile(const std::string& outputPath);

    // C/C++ mix context (nullptr = no mixing). C function calls inside z code
    // become BLs to symbols merged into the image tail.
    mix::MixContext* mixCtx = nullptr;

    IRProgram& ir_;
};