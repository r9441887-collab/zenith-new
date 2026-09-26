// codegen_android.cpp — AArch64 backend for "app android"
// =========================================================================
// Target: Android 11 (API level 30) and newer, ABI arm64-v8a, as a native
// console / background executable.
//
// What comes out
// --------------
// A self-contained ELF64 AArch64 ET_EXEC executable:
//
//   EM_AARCH64 (183), ELFCLASS64, little-endian, ELFOSABI_NONE
//   e_entry   = 0x401000                (0x400000 base + header/note padding)
//   PT_NOTE   .note.android.ident      -> "Android" / "r30"
//   PT_LOAD   R+X   header + note + text
//   PT_LOAD   R+W   globals + string pool
//   PT_GNU_STACK  R+W (non-executable stack)
//
// There is deliberately **no** PT_INTERP and **no** DT_NEEDED:
//
//   * the kernel maps the two PT_LOAD segments and branches to e_entry, so the
//     binary does not need /system/bin/linker64 to start;
//   * there is no Bionic dependency at all — every OS service is a raw Linux
//     AArch64 syscall (number in x8, arguments in x0..x5, `svc #0`), exactly
//     the ABI Bionic itself sits on top of. Android and Linux share the
//     asm-generic syscall table, so the same numbers apply on both.
//
// That makes the result independent of the device's API level in practice: the
// `api_level` / `min_sdk` directives are recorded in .note.android.ident and
// validated at compile time, but they do not gate a single symbol, because
// there is no symbol versioning to satisfy. A binary built for Android 11 runs
// unchanged on any later release.
//
// Running it
// ----------
//   adb push prog /data/local/tmp/prog
//   adb shell chmod 755 /data/local/tmp/prog
//   adb shell /data/local/tmp/prog
//
// or from a terminal app / a background service manager. The process is an
// ordinary Linux process, so stdout goes to whatever fd 1 points at, exit
// status comes from main()'s return value (or from exit()), and it can be
// daemonised, put in an init.rc service, or driven by `am instrument`.
//
// Relationship to "app arm64"
// ---------------------------
// The instruction encoders, the expression/statement emitter, the switch, the
// frame layout and the builtins all come from codegen_arm64.cpp — a single
// A64 state machine with an `android` flag. This file only holds the entry
// point, because the backend is self-contained like the STM32/WASM ones and
// does not touch the x86 RVA/section infrastructure in codegen.cpp.
//
// What the `android` flag changes in that shared state machine:
//   * data model — LP64. Globals, locals and parameters occupy 8-byte slots
//     and are read/written with a full 64-bit register, so a pointer from
//     alloc() survives a round trip through an `int` variable. Struct fields
//     are 8-byte aligned. (Bare-metal `app arm64` keeps its 4-byte model.)
//   * start address — 0x400000 from the ELF base, not a board RAM address.
//   * the console — `print`/`println` write to fd 1 with write(2) instead of
//     poking the PL011 UART, so they work over adb, logcat and a service.
//   * the library — a small set of svc-based helpers: puts/putc/num, exit,
//     nanosleep, mmap/munmap, clock_gettime, getpid. alloc() records the
//     page-rounded length in a 16-byte header below the pointer it returns,
//     which is what lets free() release a block of any size.
//   * board peripherals (gpio_*, led_*, uart_*, spi_*, i2c_*, pwm_*) warn
//     and become no-ops, because there is no MMIO to talk to.
//
// Mixing C/C++ (--cc/--cxx) is rejected for this target: the objects would
// come from the host glibc, while Android needs Bionic.
//
// Testing
// -------
//   tools/android_smoke.z is a self-checking program (returns 0 only if every
//   assertion held) that runs under qemu-aarch64-static as well as on a
//   device. See release/документация/21_android.txt.
// =========================================================================
#include "codegen.h"
#include "ast.h"

// Codegen::compileAndroid() is defined at the bottom of codegen_arm64.cpp,
// next to compileArm64(), because both drive the same A64 state machine.
