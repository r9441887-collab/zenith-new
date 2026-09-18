#pragma once
#include "ir.h"
#include <string>

// IRAsmArm: lowers the optimized assembler-IR into an STM32F1 (ARMv7-M,
// Thumb-2) raw firmware image (int32 only; float-tagged IR throws so
// main.cpp can fall back to the classic backend). Console output goes
// through the USART2 peripheral, which is what QEMU's stm32vldiscovery
// machine wires to its serial chardev.
struct IRAsmArm {
    IRAsmArm(IRProgram& ir) : ir_(ir) {}
    bool compile(const std::string& outputPath);

    IRProgram& ir_;
};