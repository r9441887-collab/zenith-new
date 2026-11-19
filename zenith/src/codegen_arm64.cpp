// codegen_arm64.cpp — AArch64 backend for "app arm64"
// =========================================================================
// Produces a flat, position-independent AArch64 firmware image for QEMU:
//
//   qemu-system-aarch64 -machine virt -cpu cortex-a53 -kernel fw.bin -nographic
//   (or: -bios fw.bin)
//
// Image layout:
//   [startup] [runtime helpers] [user functions] [data]
//
// Data section: globals (first, offsets are known before codegen) then the
// string pool. X19 always points at the start of the data section, so globals
// are addressed as X19 + known-offset and strings as X19 + patched-offset
// (the offset is only known after layout, so string addresses are emitted as
// a 2-instruction MOVZ/MOVK slot that is patched once offsets are known).
//
// Calling convention (internal, AAPCS64-ish):
//   - Integer/pointer args in x0..x7 (up to 8); results in x0.
//   - x19 = data base (constant). x29/x30 = frame pointer / link register.
//   - SP is 16-byte aligned at all call boundaries.
//   - Locals live in the callee frame at [SP + off].
//   - print() writes to the Raspberry Pi PL011 at periphBase + 0x201000
//     (the default UART0 of the chip selected by the `chip:` directive).
//
// All integer values are 32-bit signed; loads use LDRSW so values are
// sign-extended into 64-bit registers (correct signed div/mod).
// =========================================================================
#include "codegen.h"
#include "ast.h"
#include "mix.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <functional>
#include <cmath>

using namespace std;

// =========================================================================
// AArch64 instruction encoders (32-bit little-endian words)
// =========================================================================
namespace {

enum : int {
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29,
    X30, XSP = 31, XZR = 31
};

// PL011 register offsets (base = uartBase, chosen from periphBase/chip in compile()).
constexpr uint32_t PL011_FR   = 0x18u;   // flag register
constexpr uint32_t PL011_DR   = 0x00u;   // data register
constexpr uint32_t PL011_IBRD = 0x24u;   // integer baud rate divisor
constexpr uint32_t PL011_FBRD = 0x28u;   // fractional baud rate divisor
constexpr uint32_t PL011_LCRH = 0x2Cu;   // line control (8N1 = 0x70)
constexpr uint32_t PL011_CR   = 0x30u;   // control (UARTEN|TXE|RXE = 0x301)

// ---- Linux/AArch64 syscall numbers (include/uapi/asm-generic/unistd.h) ----
// Android uses the very same table as Linux for the generic (asm-generic) ABI;
// Bionic is just a C library on top of it. The 'app android' backend talks to
// the kernel directly, so it needs no Bionic at all.
enum : uint32_t {
    SYS_NR_WRITE        = 64,   // write(fd, buf, count)
    SYS_NR_READ         = 63,   // read(fd, buf, count)
    SYS_NR_OPENAT       = 56,   // openat(dirfd, path, flags, mode)
    SYS_NR_CLOSE        = 57,   // close(fd)
    SYS_NR_EXIT         = 93,   // exit(status)
    SYS_NR_EXIT_GROUP   = 94,   // exit_group(status)
    SYS_NR_NANOSLEEP    = 101,  // nanosleep(req, rem)
    SYS_NR_CLOCK_GETTIME= 113,  // clock_gettime(clk_id, timespec*)
    SYS_NR_GETPID       = 172,  // getpid()
    SYS_NR_MUNMAP       = 215,  // munmap(addr, len)
    SYS_NR_MMAP         = 222,  // mmap(addr, len, prot, flags, fd, off)
    SYS_NR_FACCESSAT    = 48,   // faccessat(dirfd, path, mode)
    // Android 11 / 12 / 13 additions. All three releases sit far above the
    // levels these appeared on -- getrandom since API 28, memfd_create and
    // statx since API 30 -- so they are available on every supported target.
    SYS_NR_PREAD64      = 67,   // pread64(fd, buf, count, offset)
    SYS_NR_GETRANDOM    = 278,  // getrandom(buf, len, flags)
    SYS_NR_MEMFD_CREATE = 279,  // memfd_create(name, flags)
    SYS_NR_STATX        = 291,  // statx(dirfd, path, flags, mask, buf)
    // AArch64 uses the asm-generic table, so these numbers are the same on
    // every 64-bit Linux; Android inherits them unchanged. Cross-check every
    // entry against <asm-generic/unistd.h>: x86-64 numbers silently produce
    // syscalls that succeed at doing something else (77 is tee, 166 is umask).
    SYS_NR_MKDIRAT      = 34,   // mkdirat(dirfd, path, mode)
    SYS_NR_UNLINKAT     = 35,   // unlinkat(dirfd, path, flags)
    SYS_NR_RENAMEAT     = 38,   // renameat(olddirfd, old, newdirfd, new)
    SYS_NR_LSEEK        = 62,   // lseek(fd, offset, whence)
    SYS_NR_PWRITE64     = 68,   // pwrite64(fd, buf, count, offset)
    SYS_NR_FTRUNCATE    = 46,   // ftruncate(fd, length)
    SYS_NR_FSTAT        = 80,   // fstat(fd, statbuf)
    SYS_NR_FSYNC        = 82,   // fsync(fd)
    SYS_NR_UNAME        = 160,  // uname(utsname*)
    SYS_NR_GETUID       = 174,  // getuid()
    SYS_NR_GETEUID      = 175,  // geteuid()
    SYS_NR_GETGID       = 176,  // getgid()
    SYS_NR_SCHED_YIELD  = 124,  // sched_yield()
    SYS_NR_MADVISE      = 233,  // madvise(addr, len, advice)
};

// open(2) flags, as passed to openat(2)
enum : uint32_t { O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2,
                  O_CREAT = 0100, O_TRUNC = 01000, O_APPEND = 02000 };
// memfd_create(2) flags
enum : uint32_t { MFD_CLOEXEC = 1 };
// statx(2): which fields to fill in, and where stx_size lands in struct statx
enum : uint32_t { STATX_SIZE = 0x00000200u };
constexpr uint32_t STATX_STX_SIZE_OFF = 40;   // struct statx: __u64 stx_size
constexpr uint32_t STATX_BUF_BYTES     = 256;  // sizeof(struct statx)

// lseek(2) whence
enum : uint32_t { SEEK_SET_ = 0, SEEK_CUR_ = 1, SEEK_END_ = 2 };
// madvise(2) advice
enum : uint32_t { MADV_NORMAL_ = 0, MADV_RANDOM_ = 1, MADV_SEQUENTIAL_ = 2,
                  MADV_WILLNEED_ = 3, MADV_DONTNEED_ = 4 };

// asm-generic struct stat on 64-bit: every field is 8 bytes wide, so st_size
// sits at offset 48 and the whole thing is 128 bytes.
constexpr uint32_t STAT_ST_SIZE_OFF = 48;
constexpr uint32_t STAT_BUF_BYTES   = 128;
// asm-generic struct utsname: six char[65] fields, so each is 65 bytes apart.
constexpr uint32_t UTS_SYSNAME_OFF  = 0;
constexpr uint32_t UTS_NODENAME_OFF = 65;
constexpr uint32_t UTS_RELEASE_OFF  = 130;
constexpr uint32_t UTS_VERSION_OFF  = 195;
constexpr uint32_t UTS_MACHINE_OFF  = 260;
constexpr uint32_t UTS_BUF_BYTES    = 390;

// mmap prot/flags
enum : uint32_t { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4,
                  MAP_PRIVATE = 0x02, MAP_ANONYMOUS = 0x20 };
// AT_FDCWD for *at() syscalls
constexpr int64_t AT_FDCWD = -100;
// CLOCK_MONOTONIC / CLOCK_REALTIME
enum : uint32_t { CLOCK_REALTIME_ = 0, CLOCK_MONOTONIC_ = 1 };
// O_RDONLY for openat
enum : uint32_t { ANDROID_O_RDONLY = 0 };

// MOVZ Xd, #imm16 LSL #(hw*16)
inline uint32_t movz(int rd, uint16_t imm16, int hw) {
    return 0xD2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOVK Xd, #imm16 LSL #(hw*16)
inline uint32_t movk(int rd, uint16_t imm16, int hw) {
    return 0xF2800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOVN Xd, #imm16 LSL #(hw*16)
inline uint32_t movn(int rd, uint16_t imm16, int hw) {
    return 0x92800000u | ((uint32_t)(hw & 3) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// MOV Xd, Xn  (ORR Xd, XZR, Xn)
inline uint32_t mov_reg(int rd, int rn) {
    return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}
// ADD Xd, Xn, #imm (LSL #shift, shift 0 or 12)
inline uint32_t add_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0x91000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUB Xd, Xn, #imm
inline uint32_t sub_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0xD1000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUBS Xd, Xn, #imm
inline uint32_t subs_imm(int rd, int rn, uint16_t imm12, int shift = 0) {
    return 0xF1000000u | ((uint32_t)(shift ? 1 : 0) << 22) | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// CMP Xn, #imm  (SUBS XZR, Xn, #imm)
inline uint32_t cmp_imm(int rn, uint16_t imm12) {
    return subs_imm(XZR, rn, imm12);
}
// ADD Xd, Xn, Xm
inline uint32_t add_reg(int rd, int rn, int rm) {
    return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUB Xd, Xn, Xm
inline uint32_t sub_reg(int rd, int rn, int rm) {
    return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SUBS Xd, Xn, Xm
inline uint32_t subs_reg(int rd, int rn, int rm) {
    return 0xEB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// CMP Xn, Xm
inline uint32_t cmp_reg(int rn, int rm) {
    return subs_reg(XZR, rn, rm);
}
// AND Xd, Xn, Xm
inline uint32_t and_reg(int rd, int rn, int rm) {
    return 0x8A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// ORR Xd, Xn, Xm
inline uint32_t orr_reg(int rd, int rn, int rm) {
    return 0xAA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// EOR Xd, Xn, Xm
inline uint32_t eor_reg(int rd, int rn, int rm) {
    return 0xCA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MVN Xd, Xm  (ORN Xd, XZR, Xm)
inline uint32_t mvn(int rd, int rm) {
    return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
// NEG Xd, Xm  (SUB Xd, XZR, Xm)
inline uint32_t neg_reg(int rd, int rm) {
    return 0xCB0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
// LSL Xd, Xn, Xm
inline uint32_t lsl_reg(int rd, int rn, int rm) {
    return 0x9AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LSL Xd, Xn, #sh  (1 <= sh <= 63), encoded as UBFM with immr = 64-sh, imms = 63-sh.
// A shift-by-constant needs no scratch register, which matters here: the only
// free registers inside expression evaluation are the operands themselves.
inline uint32_t lsl_imm(int rd, int rn, int sh) {
    return 0xD3400000u | ((uint32_t)((64 - sh) & 63) << 16) | ((uint32_t)((63 - sh) & 63) << 10)
         | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LSR Xd, Xn, Xm
inline uint32_t lsr_reg(int rd, int rn, int rm) {
    return 0x9AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// ASR Xd, Xn, Xm
inline uint32_t asr_reg(int rd, int rn, int rm) {
    return 0x9AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LSR Wd, Wn, #imm  (UBFM Wd, Wn, imm, 31)
inline uint32_t lsr_w_imm(int rd, int rn, uint8_t imm) {
    return 0x53000000u | ((uint32_t)(imm & 31) << 16) | (31u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MUL Xd, Xn, Xm
inline uint32_t mul_reg(int rd, int rn, int rm) {
    return 0x9B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// SDIV Xd, Xn, Xm
inline uint32_t sdiv_reg(int rd, int rn, int rm) {
    return 0x9AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// MSUB Xd, Wn, Wm, Xa  (Xd = Xa - Wn*Wm)
inline uint32_t msub_reg(int rd, int rn, int rm, int ra) {
    return 0x9B008000u | ((uint32_t)rm << 16) | ((uint32_t)ra << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// LDR Xt, [Xn, #imm*8]  (unsigned offset, imm12 = offset/8)
inline uint32_t ldr_x(int rt, int rn, uint16_t imm12) {
    return 0xF9400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STR Xt, [Xn, #imm*8]
inline uint32_t str_x(int rt, int rn, uint16_t imm12) {
    return 0xF9000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDR Wt, [Xn, #imm*4]
inline uint32_t ldr_w(int rt, int rn, uint16_t imm12) {
    return 0xB9400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STR Wt, [Xn, #imm*4]
inline uint32_t str_w(int rt, int rn, uint16_t imm12) {
    return 0xB9000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRSW Xt, [Xn, #imm*4]  (32-bit signed load, sign-extended to 64)
inline uint32_t ldrsw(int rt, int rn, uint16_t imm12) {
    return 0xB9800000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRB Wt, [Xn, #imm]
inline uint32_t ldrb_w(int rt, int rn, uint16_t imm12) {
    return 0x39400000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// STRB Wt, [Xn, #imm]
inline uint32_t strb_w(int rt, int rn, uint16_t imm12) {
    return 0x39000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// LDRSB Xt, [Xn, #imm]  (signed byte load)
inline uint32_t ldrsb_x(int rt, int rn, uint16_t imm12) {
    return 0x39800000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// B label (imm26, offset from this instruction, /4)
inline uint32_t b_imm_raw(uint32_t imm26) {
    return 0x14000000u | (imm26 & 0x03FFFFFFu);
}
// BL label
inline uint32_t bl_imm(uint32_t imm26) {
    return 0x94000000u | (imm26 & 0x03FFFFFFu);
}
// B.cond label (imm19, /4)
inline uint32_t b_cond(uint32_t cond, uint32_t imm19) {
    return 0x54000000u | ((cond & 15)) | ((imm19 & 0x7FFFFu) << 5);
}
// CBZ Xt, label
inline uint32_t cbz(int rt, uint32_t imm19) {
    return 0xB4000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt;
}
// CBNZ Xt, label
inline uint32_t cbnz(int rt, uint32_t imm19) {
    return 0xB5000000u | ((imm19 & 0x7FFFFu) << 5) | (uint32_t)rt;
}
// TBNZ Wt, #bit, label  (test bit and branch if non-zero)
inline uint32_t tbnz_w(int rt, uint32_t bit, uint32_t imm14) {
    return 0x37000000u | ((bit & 31u) << 19) | ((imm14 & 0x3FFFu) << 5) | (uint32_t)rt;
}
// CSET Xd, cond  (= CSINC Xd, XZR, XZR, inv(cond))
// Bit 10 is what makes this CSINC rather than CSEL: CSEL with both operands
// tied to XZR would always yield 0, so every comparison would be false.
// Encodings cross-checked against clang for all 14 usable conditions.
inline uint32_t cset(int rd, uint32_t cond) {
    return 0x9A9F07E0u | (((cond ^ 1) & 15) << 12) | (uint32_t)rd;
}
// BLR Xn
inline uint32_t blr(int rn) {
    return 0xD63F0000u | ((uint32_t)rn << 5);
}
// BR Xn
inline uint32_t br(int rn) {
    return 0xD61F0000u | ((uint32_t)rn << 5);
}
// RET (X30)
inline uint32_t ret_instr() {
    return 0xD65F03C0u;
}
// NOP
inline uint32_t nop_instr() {
    return 0xD503201Fu;
}
// ADR Xd, label (imm21*4, relative)
inline uint32_t adr(int rd, int32_t imm21) {
    uint32_t immhi = (uint32_t)(imm21 >> 2) & 0x7FFFFu;
    uint32_t immlo = (uint32_t)imm21 & 3u;
    return 0x10000000u | (immlo << 29) | (immhi << 5) | (uint32_t)rd;
}
// ADRP Xd, label (imm21 in pages of 4096)
inline uint32_t adrp(int rd, int32_t imm21) {
    uint32_t immhi = (uint32_t)(imm21 >> 2) & 0x7FFFFu;
    uint32_t immlo = (uint32_t)imm21 & 3u;
    return 0x90000000u | (immlo << 29) | (immhi << 5) | (uint32_t)rd;
}

// ---- inline-asm support: 32-bit (W) ALU variants ----
inline uint32_t mov_w_reg(int rd, int rn) {  // MOV Wd, Wm (ORR Wd, WZR, Wm)
    return 0x2A0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}
inline uint32_t add_w_reg(int rd, int rn, int rm) {
    return 0x0B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sub_w_reg(int rd, int rn, int rm) {
    return 0x4B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t cmp_w_reg(int rn, int rm) {  // CMP Wn, Wm (SUBS WZR, Wn, Wm)
    return 0x6B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5);
}
inline uint32_t and_w_reg(int rd, int rn, int rm) {
    return 0x0A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t orr_w_reg(int rd, int rn, int rm) {
    return 0x2A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t eor_w_reg(int rd, int rn, int rm) {
    return 0x4A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t neg_w_reg(int rd, int rm) {  // NEG Wd, Wm (SUB Wd, WZR, Wm)
    return 0x4B0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mvn_x(int rd, int rm) {  // MVN Xd, Xm (ORN Xd, XZR, Xm)
    return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mvn_w(int rd, int rm) {  // MVN Wd, Wm (ORN Wd, WZR, Wm)
    return 0x2A2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
inline uint32_t mul_w_reg(int rd, int rn, int rm) {
    return 0x1B007C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sdiv_w_reg(int rd, int rn, int rm) {
    return 0x1AC00C00u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t udiv_x(int rd, int rn, int rm) {
    return 0x9AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t udiv_w(int rd, int rn, int rm) {
    return 0x1AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// 32-bit register shifts
inline uint32_t lsl_w_reg(int rd, int rn, int rm) {
    return 0x1AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t lsr_w_reg(int rd, int rn, int rm) {
    return 0x1AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_w_reg(int rd, int rn, int rm) {
    return 0x1AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t add_w_imm(int rd, int rn, uint16_t imm12) {
    return 0x11000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t sub_w_imm(int rd, int rn, uint16_t imm12) {
    return 0x51000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t cmp_w_imm(int rn, uint16_t imm12) {
    return 0x71000000u | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5);
}
// 64-bit register-offset loads/stores: LDR Xt,[Xn,Xm]
inline uint32_t ldr_x_reg(int rt, int rn, int rm) {
    return 0xF8600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t str_x_reg(int rt, int rn, int rm) {
    return 0xF8000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t ldr_w_reg(int rt, int rn, int rm) {
    return 0xB8600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t str_w_reg(int rt, int rn, int rm) {
    return 0xB8000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t ldrb_w_reg(int rt, int rn, int rm) {
    return 0x38600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
inline uint32_t strb_w_reg(int rt, int rn, int rm) {
    return 0x38000800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// 64-bit immediate shifts: UBFM/SBFM, sh 0..63
inline uint32_t lsl_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0xD3400000u | ((uint32_t)((64 - sh) & 63) << 16) | ((uint32_t)(63 - sh) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t lsr_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0xD3400000u | ((uint32_t)sh << 16) | (63u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_x_imm(int rd, int rn, uint8_t sh) {
    sh &= 63;
    return 0x93400000u | ((uint32_t)sh << 16) | (63u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// 32-bit immediate shifts (LSR W imm already exists as lsr_w_imm)
inline uint32_t lsl_w_imm(int rd, int rn, uint8_t sh) {
    sh &= 31;
    return 0x53000000u | ((uint32_t)((32 - sh) & 31) << 16) | ((uint32_t)(31 - sh) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}
inline uint32_t asr_w_imm(int rd, int rn, uint8_t sh) {
    sh &= 31;
    return 0x13000000u | ((uint32_t)sh << 16) | (31u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// RET Xn
inline uint32_t ret_reg(int rn) {
    return 0xD65F0000u | ((uint32_t)rn << 5);
}
// system hints
inline uint32_t yield_instr()  { return 0xD503203Fu; }
inline uint32_t wfe_instr()    { return 0xD503205Fu; }
inline uint32_t wfi_instr()    { return 0xD503207Fu; }
inline uint32_t sev_instr()    { return 0xD503209Fu; }
inline uint32_t svc_imm(uint16_t imm16) { return 0xD4000001u | ((uint32_t)imm16 << 5); }
inline uint32_t hlt_imm(uint16_t imm16) { return 0xD4400000u | ((uint32_t)imm16 << 5); }
inline uint32_t brk_imm(uint16_t imm16) { return 0xD4200000u | ((uint32_t)imm16 << 5); }

} // namespace

// =========================================================================
// AArch64 backend state machine (per compileArm64() call)
// =========================================================================
namespace {

void u32pat(vector<uint8_t>& buf, int pos, uint32_t v) {
    if (pos < 0 || pos + 3 >= (int)buf.size()) return;
    buf[(size_t)pos]     = (uint8_t)(v & 0xFF);
    buf[(size_t)pos + 1] = (uint8_t)((v >> 8) & 0xFF);
    buf[(size_t)pos + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[(size_t)pos + 3] = (uint8_t)((v >> 24) & 0xFF);
}

// ARM condition codes (AArch64, flags from CMP left,right).
static int ccForOp(const string& op) {
    if (op == "==") return 0;   // EQ
    if (op == "!=") return 1;   // NE
    if (op == "<")  return 11;  // LT
    if (op == "<=") return 13;  // LE
    if (op == ">")  return 12;  // GT
    if (op == ">=") return 10;  // GE
    return -1;
}

static int invCc(int cc) {
    switch (cc) {
        case 0:  return 1;
        case 1:  return 0;
        case 10: return 11;
        case 11: return 10;
        case 12: return 13;
        case 13: return 12;
        default: return cc;
    }
}

// ---- AArch64 FP encodings (f32 bits travel through the integer regs) ----
static inline uint32_t encFmovSW(int sd, int wn)   { return 0x1E270000u | ((uint32_t)wn << 5) | (uint32_t)sd; }
static inline uint32_t encFmovWS(int wd, int sn)   { return 0x1E260000u | ((uint32_t)sn << 5) | (uint32_t)wd; }
static inline uint32_t encFaddSx(int rd, int rn, int rm) { return 0x1E202800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFsubSx(int rd, int rn, int rm) { return 0x1E203800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFmulSx(int rd, int rn, int rm) { return 0x1E200800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFdivSx(int rd, int rn, int rm) { return 0x1E201800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFnegSx(int rd, int rn)   { return 0x1E214000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFcmpSx(int rn, int rm)   { return 0x1E202000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5); }
static inline uint32_t encScvtfSW(int sd, int wn)  { return 0x1E220000u | ((uint32_t)wn << 5) | (uint32_t)sd; }
static inline uint32_t encFcvtzsWS(int wn, int sn) { return 0x1E380000u | ((uint32_t)sn << 5) | (uint32_t)wn; }
// f32 -> f64 / f64 -> f32 and the f64 helpers used by the float printer
static inline uint32_t encFcvtDs(int dd, int sn)   { return 0x1E22C000u | ((uint32_t)sn << 5) | (uint32_t)dd; }
static inline uint32_t encFmovDX(int dd, int xn)   { return 0x9E670000u | ((uint32_t)xn << 5) | (uint32_t)dd; }
static inline uint32_t encFcvtzsDX(int xd, int dn) { return 0x9E780000u | ((uint32_t)dn << 5) | (uint32_t)xd; }
static inline uint32_t encFaddDx(int rd, int rn, int rm) { return 0x1E602800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFmulDx(int rd, int rn, int rm) { return 0x1E600800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFnegDx(int rd, int rn)   { return 0x1E614000u | ((uint32_t)rn << 5) | (uint32_t)rd; }
static inline uint32_t encFcmpDx(int rn, int rm)   { return 0x1E602000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5); }

static bool getIntConst(Expr* e, int64_t& v) {
    if (auto n = dynamic_cast<NumberExpr*>(e)) { v = n->value; return true; }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        int64_t cv;
        if (u->op == "-" && getIntConst(u->operand.get(), cv)) { v = -cv; return true; }
        return false;
    }
    return false;
}

enum class BrKind { B, Cond, Cbz, Cbnz, Tbnz };

struct BrRef {
    int pos = 0;
    int label = -1;
    BrKind kind = BrKind::B;
    int cc = 0;   // for Cond; also holds the bit for Tbnz
    int rt = 0;   // for Cbz/Cbnz
};

struct A64 {
    Program& prog;
    explicit A64(Program& p) : prog(p) {}

    // ---- per-compile state ----
    vector<uint8_t> code;
    vector<BrRef> branches;
    vector<int> labelPositions;
    int nextLabel = 0;
    int newLabel() { return nextLabel++; }
    void emitLabel(int label) {
        if (label >= (int)labelPositions.size()) labelPositions.resize(label + 1, -1);
        labelPositions[label] = (int)code.size();
    }

    // BL fixups (resolved after full layout)
    struct CallFix { int pos; string target; };
    vector<CallFix> callFixups;

    // `&func`: an ADR patched once the layout is known (resolved after full
    // layout, like the BL fixups above).
    struct AddrFix { int pos; int rt; string target; };
    vector<AddrFix> addrFixups;
    void addrFixup(int rt, const string& target) {
        int p = (int)code.size();
        u32(adr(rt, 0));
        addrFixups.push_back({p, rt, target});
    }

    // strings (dedup)
    vector<string> strings;
    int stringIdx(const string& s) {
        for (int i = 0; i < (int)strings.size(); i++)
            if (strings[i] == s) return i;
        strings.push_back(s);
        return (int)strings.size() - 1;
    }

    // globals: offsets from the start of the data section (known before codegen)
    struct GInfo { int off; int size; Type type; int arraySize = 0; };
    unordered_map<string, GInfo> globals;
    vector<string> globalOrder;

    // struct layouts (32-bit model: every field is 4 bytes; LP64 when android)
    unordered_map<string, pair<int, unordered_map<string, pair<int, Type>>>> structs;
    int structSize(const string& name) {
        auto it = structs.find(name);
        return it == structs.end() ? (android ? 8 : 4) : it->second.first;
    }
    // Size of one scalar. On 'app arm64' the historical model is a flat 4 bytes
    // per value (the QEMU firmware images never hold a real pointer). Android is
    // LP64, so pointers, strings and structs take their natural 8-byte size and
    // every slot is 8-byte aligned — otherwise a struct{ptr;int} would put the
    // int at offset 4 and the AArch64 unaligned-access rules would bite.
    int scalarSize(const Type& t) {
        if (android) {
            if (t.isPtr) return 8;
            if (t.kind == TypeKind::String) return 8;
            if (t.kind == TypeKind::Struct) return (structSize(t.structName) + 7) & ~7;
            return 4;   // Zenith int / float / bool stay 32-bit
        }
        if (t.kind == TypeKind::Struct) return structSize(t.structName);
        if (t.kind == TypeKind::String) return 8;
        return 4;
    }
    int typeSize(const Type& t, int arraySize = 0) {
        if (arraySize > 0) return arraySize * scalarSize(t);
        return scalarSize(t);
    }
    int elementSize(const Type& t) { return typeSize(t); }
    // Distance between successive switch temporaries. They are reached through
    // loadFromOff/storeToOff, which move a whole register on Android, so they
    // must be spaced 8 bytes apart there or they would overlap each other and
    // the last one would run into the saved link register.
    int swTempStride() const { return android ? 8 : 4; }
    // Round a byte size up to the model's natural alignment.
    int alignUp(int n, int a) { return (n + a - 1) & ~(a - 1); }

    // ---- frame info ----
    struct VarInfo32 { int off; Type type; bool isParam; bool used; int size; int arraySize = 0; };
    unordered_map<string, VarInfo32> vars;
    int frameSize = 0;      // whole frame (locals + saved LR), 16-aligned
    int tempBytes = 0;      // bytes of live temp values pushed above the frame
    int retLabel = -1;
    int swCur = 0;
    int swTempOff = 0;
    bool hasCalls = false;

    unordered_map<string, size_t> funcOffsets;
    vector<string> funcOrder;
    string entryName;

    // startup data-base fixups: positions of the ADRP / ADD that compute X19
    int startupAdrpPos = -1;
    int startupAddPos = -1;

    // ---- Raspberry Pi peripheral bases (selected in compile() from chip:) --
    uint32_t periphBase   = 0x3F000000u;   // BCM2835/2837 (Pi1-Pi3)
    uint32_t gpioBase     = 0x3F200000u;
    uint32_t uartBase     = 0x3F201000u;   // PL011
    uint32_t sysTimerBase = 0x3F003000u;   // 1 MHz microsecond counter (CLO @ +0x04)
    int ledGpio = 47;                      // Pi3 activity LED (Pi4 = 16)
    uint32_t stackTop = 0x3C000000u;       // top of RAM (1GB Pi); virt -> 0x47F00000
    uint64_t imageBase = 0x00080000u;      // where the image is loaded (kernel base)

    // C/C++ mixing: set by compileArm64() from the backend host Codegen.
    mix::MixContext* mixCtx = nullptr;

    // ===== 'app android' mode (AArch64 ELF64 for Android 11 / API 30) =====
    // Same instruction encoders and the same emit pipeline as 'app arm64', but
    // the container is an ELF executable instead of a flat image, the data model
    // is LP64, and every OS service is a raw Linux syscall rather than PL011
    // MMIO. There is no Bionic, no PT_INTERP and no DT_NEEDED, so the binary is
    // self-contained and needs nothing from the device but the kernel.
    bool android = false;
    uint32_t apiLevel = 30;    // api_level: (Android 11 == 30)
    uint32_t minSdk = 21;      // min_sdk: (Bionic's first LP64 level)
    string androidLabel;       // label: recorded in .note.android.ident
    uint64_t elfBase = 0x400000ull;   // ET_EXEC load base (page aligned)
    // argc as handed over by the kernel (X20 at _start), for the argc builtin.
    bool argcSaved = false;
    // The kernel's own stack pointer (X21 at _start). argv[] and envp[] are
    // laid out on that stack, so arg_get/env_get need it, not the current SP.
    bool spSaved = false;

    // ---- assembly primitives ----
    void u32(uint32_t v) {
        code.push_back((uint8_t)(v & 0xFF));
        code.push_back((uint8_t)((v >> 8) & 0xFF));
        code.push_back((uint8_t)((v >> 16) & 0xFF));
        code.push_back((uint8_t)((v >> 24) & 0xFF));
    }

    // Load 64-bit constant into rt.
    void loadConst(int rt, uint64_t v) {
        uint16_t lo = (uint16_t)(v & 0xFFFF);
        uint16_t hi = (uint16_t)((v >> 16) & 0xFFFF);
        uint16_t h3 = (uint16_t)((v >> 32) & 0xFFFF);
        uint16_t h4 = (uint16_t)((v >> 48) & 0xFFFF);
        if (h4 == 0 && h3 == 0 && hi == 0) {
            u32(movz(rt, lo, 0));
        } else if (h4 == 0 && h3 == 0) {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
        } else if (h4 == 0) {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
            u32(movk(rt, h3, 2));
        } else {
            u32(movz(rt, lo, 0));
            u32(movk(rt, hi, 1));
            u32(movk(rt, h3, 2));
            u32(movk(rt, h4, 3));
        }
    }

    void mov(int rd, int rn) { u32(mov_reg(rd, rn)); }
    void addImm(int rd, int rn, uint16_t imm12) { u32(add_imm(rd, rn, imm12)); }
    void subImm(int rd, int rn, uint16_t imm12) { u32(sub_imm(rd, rn, imm12)); }
    void cmpImm(int rn, uint16_t imm12) { u32(cmp_imm(rn, imm12)); }
    void addReg(int rd, int rn, int rm) { u32(add_reg(rd, rn, rm)); }
    void subReg(int rd, int rn, int rm) { u32(sub_reg(rd, rn, rm)); }
    void cmpReg(int rn, int rm) { u32(cmp_reg(rn, rm)); }
    void andReg(int rd, int rn, int rm) { u32(and_reg(rd, rn, rm)); }
    void orrReg(int rd, int rn, int rm) { u32(orr_reg(rd, rn, rm)); }
    void eorReg(int rd, int rn, int rm) { u32(eor_reg(rd, rn, rm)); }
    void negReg(int rd, int rm) { u32(neg_reg(rd, rm)); }
    void lslR(int rd, int rn, int rm) { u32(lsl_reg(rd, rn, rm)); }
    void lsrR(int rd, int rn, int rm) { u32(lsr_reg(rd, rn, rm)); }
    void asrR(int rd, int rn, int rm) { u32(asr_reg(rd, rn, rm)); }
    void mulR(int rd, int rn, int rm) { u32(mul_reg(rd, rn, rm)); }
    void sdivR(int rd, int rn, int rm) { u32(sdiv_reg(rd, rn, rm)); }
    void udivR(int rd, int rn, int rm) { u32(udiv_x(rd, rn, rm)); }
    void msubR(int rd, int rn, int rm, int ra) { u32(msub_reg(rd, rn, rm, ra)); }
    void ldrX(int rt, int rn, uint32_t off) { u32(ldr_x(rt, rn, (uint16_t)(off / 8))); }
    void strX(int rt, int rn, uint32_t off) { u32(str_x(rt, rn, (uint16_t)(off / 8))); }
    void ldrW(int rt, int rn, uint32_t off) { u32(ldr_w(rt, rn, (uint16_t)(off / 4))); }
    void strW(int rt, int rn, uint32_t off) { u32(str_w(rt, rn, (uint16_t)(off / 4))); }
    void ldrswW(int rt, int rn, uint32_t off) { u32(ldrsw(rt, rn, (uint16_t)(off / 4))); }
    void ldrbW(int rt, int rn, uint32_t off) { u32(ldrb_w(rt, rn, (uint16_t)off)); }
    void strbW(int rt, int rn, uint32_t off) { u32(strb_w(rt, rn, (uint16_t)off)); }
    void ldrsbX(int rt, int rn, uint32_t off) { u32(ldrsb_x(rt, rn, (uint16_t)off)); }
    void csetR(int rd, int cc) { u32(cset(rd, (uint32_t)cc)); }

    // branch emitters (fixups resolved per function)
    //
    // IMPORTANT: only ever pass condition codes 0x0-0xA (and 0xE/0xF) here.
    // Codes 0xB/0xC/0xD mean GT/LE/AL on real AArch64 but LT/GT/LE under the
    // ARM32 table, which is what QEMU 7.2's B.cond actually implements -- the
    // same three codes carry a different meaning in the two ISAs, and the
    // encodings agree only up to 0xA. Express "greater than" as
    // "not less than" (GE, 0xA) or "not less or equal" instead, and use
    // MI (0x4) for a strict "less than".
    void b_cc(int cc, int label) {
        int p = (int)code.size();
        u32(b_cond((uint32_t)cc, 0));
        branches.push_back({p, label, BrKind::Cond, cc, 0});
    }
    void b_imm(int label) {
        int p = (int)code.size();
        u32(b_imm_raw(0));
        branches.push_back({p, label, BrKind::B, -1, 0});
    }
    void cbzR(int rt, int label) {
        int p = (int)code.size();
        u32(cbz(rt, 0));
        branches.push_back({p, label, BrKind::Cbz, -1, rt});
    }
    void cbnzR(int rt, int label) {
        int p = (int)code.size();
        u32(cbnz(rt, 0));
        branches.push_back({p, label, BrKind::Cbnz, -1, rt});
    }
    void tbnzR(int rt, int bit, int label) {
        int p = (int)code.size();
        u32(tbnz_w(rt, (uint32_t)bit, 0));
        branches.push_back({p, label, BrKind::Tbnz, bit, rt});
    }

    void bl_fixup(const string& target) {
        int p = (int)code.size();
        u32(bl_imm(0));
        callFixups.push_back({p, target});
    }

    void ret() { u32(ret_instr()); }
    void nop() { u32(nop_instr()); }

    // ---- 'app android': raw Linux/AArch64 syscall (number in X8, args X0..X5) ----
    // The caller has already loaded the arguments; this only sets X8 and traps.
    void svcSys(uint32_t nr) { u32(movz(X8, (uint16_t)nr, 0)); u32(svc_imm(0)); }
    // write(fd=X0, buf=X1, len=X2)
    void sysWrite() { svcSys(SYS_NR_WRITE); }
    // Turn a kernel error into a plain 0. Must be called straight after the
    // svc, while X0 still holds the raw return value: on failure the kernel
    // hands back -errno, and read as unsigned 64-bit that lands in
    // [-4095, -1], i.e. just under 2^64 and far above any real user address.
    // So "below -4095" is exactly the success test, and anything else is a
    // failure. (ARM cond field: 3 = LO/CC, 14 = AL, 1 = NE.)
    void clampSysErr() {
        int Ldone = newLabel();
        loadConst(X1, (uint64_t)(int64_t)-4095);
        cmpReg(X0, X1);
        b_cc(3, Ldone);          // LO -> looks like a real value
        movzImm(X0, 0);          // else -errno -> report failure as 0
        emitLabel(Ldone);
    }
    // close(2) answers 0 on success and a negative errno on failure, so
    // clampSysErr() cannot be reused: its "is it below -4095" test reads the
    // successful 0 as a real return value. Invert the convention instead and
    // report 1 for success, 0 for -errno, to keep the 0-means-error API.
    void clampSysErrZeroOk() {
        movzImm(X1, 0);
        cmpReg(X0, X1);
        csetR(X0, 0);           // 1 if X0 == 0
    }
    // Copy a NUL-terminated byte string from srcReg into dstReg, writing at
    // most lenReg bytes plus the terminator. Returns the length in X0, or 0
    // if the buffer is too small to hold even the terminator.
    // Clobbers X5 and X6, so pass those as neither src, dst nor len.
    void emitCopyCstr(int dstReg, int srcReg, int lenReg, int Lfail) {
        int Lloop = newLabel(), Lnul = newLabel(), Lnext = newLabel();
        mov(X5, XZR);
        emitLabel(Lloop);
        cmpReg(X5, lenReg);
        b_cc(10, Lfail);        // GE -> no room left for the terminator
        ldrbW(X6, srcReg, 0);
        strbW(X6, dstReg, 0);
        cbzR(X6, Lnul);
        addImm(X5, X5, 1);
        addImm(srcReg, srcReg, 1);
        addImm(dstReg, dstReg, 1);
        b_imm(Lloop);
        emitLabel(Lnul);
        mov(X0, X5);
        b_imm(Lnext);
        emitLabel(Lfail);
        movzImm(X0, 0);
        emitLabel(Lnext);
    }
    void movzImm(int rd, uint32_t v) { u32(movz(rd, (uint16_t)(v & 0xFFFF), 0)); }

    // SUB SP, SP, #bytes (imm12 max 4095, chunked)
    void subSp(int bytes) {
        while (bytes > 0) {
            int s = std::min(bytes, 4095);
            u32(sub_imm(XSP, XSP, (uint16_t)s));
            bytes -= s;
        }
    }
    void addSp(int bytes) {
        while (bytes > 0) {
            int s = std::min(bytes, 4095);
            u32(add_imm(XSP, XSP, (uint16_t)s));
            bytes -= s;
        }
    }

    // ---- stack value spill/restore (used by binary expression evaluation) ----
    // The spill slot is a full 16 bytes, not 8: AArch64 requires SP to stay
    // 16-byte aligned at all times, and hardware raises an alignment fault
    // (SIGBUS) for a load/store whose base is a misaligned SP. qemu-user does
    // not check that, so a violation only ever shows up on a real device.
    void pushX0() { subSp(16); strX(X0, XSP, 0); tempBytes += 16; }
    void popX1()  { ldrX(X1, XSP, 0); addSp(16); tempBytes -= 16; }

    // X0 = X0 + v
    void addImmX0(int64_t v) {
        if (v == 0) return;
        if (v > 0 && v <= 4095) { addImm(X0, X0, (uint16_t)v); return; }
        if (v < 0 && v >= -4095) { subImm(X0, X0, (uint16_t)(-v)); return; }
        loadConst(X1, (uint64_t)v);
        addReg(X0, X0, X1);
    }

    // X0 *= stride, for a stride that is a power of two. A shift needs no
    // scratch register; anything else is left alone rather than guessing.
    void scaleX0(int64_t stride) {
        if (stride <= 1) return;
        if (stride & (stride - 1)) return;
        int sh = 0;
        while ((int64_t)1 << sh != stride) sh++;
        if (sh > 0 && sh < 64) u32(lsl_imm(X0, X0, sh));
    }

    // rd = SP + off  (any positive offset)
    void addSpAddr(int rd, int off) {
        int rem = off;
        bool first = true;
        while (rem > 0 || first) {
            int s = std::min(rem > 0 ? rem : 0, 4095);
            if (first) { u32(add_imm(rd, XSP, (uint16_t)s)); first = false; }
            else u32(add_imm(rd, rd, (uint16_t)s));
            rem -= s;
            if (rem <= 0) break;
        }
    }

    // load/store 32-bit value at [SP + off + tempBytes]
    // ---- element access through a pointer / field / index ----
    // `*(p)` is an `int` access, so it moves 4 bytes, matching what the
    // reference manual promises for `int`. It is deliberately NOT widened to
    // the 8-byte slot width that loadFromOff() uses for frame slots: a frame
    // slot always holds a whole value, whereas the pointee here is an int.
    // Reading a stored address back needs a real pointer type to say so, and
    // guessing 8 bytes would silently reinterpret every existing `*(p + n)`
    // on int data. See the `ptr<T>` work for the real fix.
    void loadElem(int rt, int rn) { ldrswW(rt, rn, 0); }
    void storeElem(int rt, int rn) { strW(rt, rn, 0); }

    // Typed value access through a computed address: pointers (and structs,
    // which the LP64 layout pads to their full width) move as 64-bit
    // quantities, int/float/bool as 32-bit ones.
    void loadTyped(int addrReg, const Type& t) {
        if (scalarSize(t) == 8) ldrX(X0, addrReg, 0);
        else loadElem(X0, addrReg);
    }
    void storeTyped(int addrReg, const Type& t) {   // value in X0
        if (scalarSize(t) == 8) strX(X0, addrReg, 0);
        else strW(X0, addrReg, 0);
    }

    void loadFromOff(int rt, int off) {
        // Android is LP64: every slot is 8-aligned and at least 8 bytes wide,
        // and a 64-bit pointer must survive a round trip through an `int`
        // variable, so load and store the full register there.
        if (android) { loadFromOff64(rt, off); return; }
        int o = off + tempBytes;
        if (o >= 0 && (o & 3) == 0 && o / 4 <= 4095) { ldrswW(rt, XSP, (uint32_t)o); return; }
        addSpAddr(X1, o);
        ldrswW(rt, X1, 0);
    }
    void storeToOff(int rt, int off) {
        if (android) { storeToOff64(rt, off); return; }
        int o = off + tempBytes;
        if (o >= 0 && (o & 3) == 0 && o / 4 <= 4095) { strW(rt, XSP, (uint32_t)o); return; }
        int scratch = (rt == X0) ? X1 : X0;
        addSpAddr(scratch, o);
        strW(rt, scratch, 0);
    }
    void loadFromOff64(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 7) == 0 && o / 8 <= 4095) { ldrX(rt, XSP, (uint32_t)o); return; }
        addSpAddr(X1, o);
        ldrX(rt, X1, 0);
    }
    void storeToOff64(int rt, int off) {
        int o = off + tempBytes;
        if (o >= 0 && (o & 7) == 0 && o / 8 <= 4095) { strX(rt, XSP, (uint32_t)o); return; }
        int scratch = (rt == X0) ? X1 : X0;
        addSpAddr(scratch, o);
        strX(rt, scratch, 0);
    }

    VarInfo32* var(const string& n) { auto it = vars.find(n); return it == vars.end() ? nullptr : &it->second; }
    GInfo* global(const string& n) { auto it = globals.find(n); return it == globals.end() ? nullptr : &it->second; }

    Type varType(const string& n) {
        auto v = var(n);
        if (v) return v->type;
        auto g = global(n);
        if (g) return g->type;
        return Type(TypeKind::Int);
    }

    // ---- global access (offset from data start, known before codegen) ----
    void loadGlobal(int rt, int off, int sz = 0) {
        if (android) sz = 8;   // LP64: slots are 8 wide and hold pointers
        if (sz == 8) {
            if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095) { ldrX(rt, X19, (uint32_t)off); return; }
            loadConst(X1, (uint64_t)off);
            addReg(X1, X19, X1);
            ldrX(rt, X1, 0);
            return;
        }
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095) { ldrswW(rt, X19, (uint32_t)off); return; }
        loadConst(X1, (uint64_t)off);
        addReg(X1, X19, X1);
        ldrswW(rt, X1, 0);
    }
    void storeGlobal(int rt, int off, int sz = 0) {
        if (android) sz = 8;   // LP64: slots are 8 wide and hold pointers
        if (sz == 8) {
            if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095) { strX(rt, X19, (uint32_t)off); return; }
            int scratch = (rt == X0) ? X1 : X0;
            loadConst(scratch, (uint64_t)off);
            addReg(scratch, X19, scratch);
            strX(rt, scratch, 0);
            return;
        }
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095) { strW(rt, X19, (uint32_t)off); return; }
        int scratch = (rt == X0) ? X1 : X0;
        loadConst(scratch, (uint64_t)off);
        addReg(scratch, X19, scratch);
        strW(rt, scratch, 0);
    }
    void loadStrAddrKnown(int rt, int off) {
        if (off >= 0 && off <= 4095) { u32(add_imm(rt, X19, (uint16_t)off)); return; }
        loadConst(X1, (uint64_t)off);
        addReg(rt, X19, X1);
    }

    // ---- string address with post-layout patch ----
    struct StrFix { int pos; int slot; };
    vector<StrFix> strFixups;
    // Emit: X1 = <patched str offset>; rt = X19 + X1  (3 fixed-size instructions)
    void emitStrAddr(int rt, int slot) {
        int pos = (int)code.size();
        u32(movz(X1, 0, 0));
        u32(movk(X1, 0, 1));
        strFixups.push_back({pos, slot});
        addReg(rt, X19, X1);
    }
    void patchStrSlots(vector<uint8_t>& img, size_t baseOff, size_t dataStart,
                       const vector<StrFix>& fixes, const vector<uint32_t>& strOfs) {
        for (auto& fx : fixes) {
            uint32_t v = strOfs[(size_t)fx.slot] - (uint32_t)dataStart;
            uint16_t lo = (uint16_t)(v & 0xFFFF);
            uint16_t hi = (uint16_t)((v >> 16) & 0xFFFF);
            size_t pos = baseOff + (size_t)fx.pos;
            u32pat(img, (int)pos, movz(X1, lo, 0));
            u32pat(img, (int)pos + 4, movk(X1, hi, 1));
        }
    }

    // emitLoadVar / emitStoreVar
    void emitLoadVar(int rt, const string& n) {
        auto v = var(n);
        if (v) {
            if (v->size == 8) loadFromOff64(rt, v->off);
            else loadFromOff(rt, v->off);
            return;
        }
        auto g = global(n);
        if (g) { loadGlobal(rt, g->off, g->size); return; }
        // Was: report and load 0, so a typo compiled into a binary that
        // silently used the wrong value while the compiler still exited 0.
        // generate() runs inside a try/catch in main() that returns 1.
        throw std::runtime_error("undefined variable '" + n + "'");
    }
    void emitStoreVar(const string& n, int reg) {
        auto v = var(n);
        if (v) {
            if (v->size == 8) storeToOff64(reg, v->off);
            else storeToOff(reg, v->off);
            return;
        }
        auto g = global(n);
        if (g) { storeGlobal(reg, g->off, g->size); return; }
        throw std::runtime_error("undefined variable '" + n + "'");
    }

    // ---- type helpers ----
    // Direct call (0), a function-pointer *variable* named c->name (1), or a
    // function-pointer field behind c->receiver (2). Plain method calls have
    // no funcptr-typed receiver and stay direct.
    int callCalleeKind(CallExpr* c, std::string& varName) {
        if (!c) return 0;
        if (c->receiver) {
            auto memb = dynamic_cast<MemberExpr*>(c->receiver.get());
            if (!memb) return 0;
            Type ft = typeOf(memb);
            if (ft.isFuncPtr()) return 2;
            return 0;
        }
        if (auto v = var(c->name)) { if (v->type.isFuncPtr()) { varName = c->name; return 1; } }
        if (auto g = global(c->name)) { if (g->type.isFuncPtr()) { varName = c->name; return 1; } }
        return 0;
    }

    // True when `n` names an *array* variable: there Type is the element
    // type, so Type.isPtr on it means "array of pointers", not a pointer we
    // should step through. A real pointer carries arraySize == 0.
    bool isArrayVar(const string& n) {
        if (auto v = var(n)) return v->arraySize > 0;
        if (auto g = global(n)) return g->arraySize > 0;
        return false;
    }
    bool isArrayExpr(Expr* e) {
        if (auto id = dynamic_cast<IdentExpr*>(e)) return isArrayVar(id->name);
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) return isArrayExpr(a->array.get());
        return false;
    }

    Type typeOf(Expr* e) {
        if (auto id = dynamic_cast<IdentExpr*>(e)) return varType(id->name);
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) {
            Type t = typeOf(a->array.get());
            // `p[i]` through a typed pointer yields the pointee, not the
            // pointer; a real array variable already carries the element type.
            if (t.isPtr && !isArrayExpr(a->array.get())) t.isPtr = false;
            return t;
        }
        if (auto d = dynamic_cast<DerefExpr*>(e)) {
            Type t = typeOf(d->ptr.get());
            if (t.isPtr) { t.isPtr = false; return t; }
            return Type(TypeKind::Int);
        }
        if (auto m = dynamic_cast<MemberExpr*>(e)) {
            Type ot = typeOf(m->object.get());
            if (ot.kind == TypeKind::Struct) {
                auto it = structs.find(ot.structName);
                if (it != structs.end()) {
                    auto f = it->second.second.find(m->member);
                    if (f != it->second.second.end()) return f->second.second;
                }
            }
            return Type(TypeKind::Int);
        }
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            // An indirect call through a function pointer: the return type
            // comes from the pointee signature, not from a same-named function.
            std::string fpVar;
            int ck = callCalleeKind(c, fpVar);
            if (ck != 0) {
                Type ft = (ck == 1) ? varType(fpVar) : typeOf(c->receiver.get());
                if (ft.isFuncPtr() && ft.fn) return ft.fn->ret;
            }
            for (auto& f : prog.functions)
                if (f->name == c->name) return f->returnType;
        }
        // Pointer arithmetic keeps the operand type: `fp + 2` for a
        // ptr<float> is still a float pointer, so `*(fp + 2)` loads (and
        // prints) as a float, not as an int.
        if (auto b = dynamic_cast<BinaryExpr*>(e)) return typeOf(b->left.get());
        return Type(TypeKind::Int);
    }
    int fieldOffsetOf(const Type& t, const string& member) {
        if (t.kind == TypeKind::Struct) {
            auto it = structs.find(t.structName);
            if (it != structs.end()) {
                auto f = it->second.second.find(member);
                if (f != it->second.second.end()) return f->second.first;
            }
        }
        cerr << "arm64: unknown field '" << member << "'\n";
        return 0;
    }
    int fieldOffset(Expr* obj, const string& member) { return fieldOffsetOf(typeOf(obj), member); }
    Type fieldTypeOf(const Type& t, const string& m) {
        if (t.kind == TypeKind::Struct) {
            auto it = structs.find(t.structName);
            if (it != structs.end()) {
                auto f = it->second.second.find(m);
                if (f != it->second.second.end()) return f->second.second;
            }
        }
        return Type(TypeKind::Int);
    }
    bool isFloatExpr(Expr* e) {
        if (dynamic_cast<FloatExpr*>(e)) return true;
        if (dynamic_cast<NumberExpr*>(e)) return false;
        if (auto id = dynamic_cast<IdentExpr*>(e)) {
            // ptr<float> is not a float value: it is an address.
            auto v = var(id->name);  if (v) return v->type.kind == TypeKind::Float && !v->type.isPtr;
            auto g = global(id->name); if (g) return g->type.kind == TypeKind::Float && !g->type.isPtr;
            return false;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) return isFloatExpr(b->left.get()) || isFloatExpr(b->right.get());
        if (auto u = dynamic_cast<UnaryExpr*>(e)) return isFloatExpr(u->operand.get());
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) {
            // The *element* type: for `p[i]` through a typed pointer that is
            // the pointee, which is exactly what typeOf() resolves.
            Type t = typeOf(a);
            return t.kind == TypeKind::Float && !t.isPtr;
        }
        if (auto m = dynamic_cast<MemberExpr*>(e)) {
            Type t = typeOf(m);
            return t.kind == TypeKind::Float && !t.isPtr;
        }
        if (auto d = dynamic_cast<DerefExpr*>(e)) {
            Type t = typeOf(d->ptr.get());
            return t.isPtr && t.kind == TypeKind::Float;
        }
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            std::string fpVar;
            int ck = callCalleeKind(c, fpVar);
            if (ck != 0) {
                Type ft = (ck == 1) ? varType(fpVar) : typeOf(c->receiver.get());
                if (ft.isFuncPtr() && ft.fn) return ft.fn->ret.kind == TypeKind::Float;
            }
            for (auto& f : prog.functions)
                if (f->name == c->name && !f->isExtern) return f->returnType.kind == TypeKind::Float;
        }
        return false;
    }

    // ---- address computation (result in X0) ----
    void emitAddr(Expr* path) {
        if (auto id = dynamic_cast<IdentExpr*>(path)) {
            // A typed pointer contributes its *value*: the address behind `p`
            // starts where p points, not at p's own slot (`p[i]`, `&p[i]`).
            // Arrays (arraySize > 0) -- including arrays *of* pointers --
            // keep their slot address.
            if (auto v = var(id->name)) {
                if (v->type.isPtr && v->arraySize == 0) { emitLoadVar(X0, id->name); return; }
                addSpAddr(X0, v->off + tempBytes); return;
            }
            auto g = global(id->name);
            if (g) {
                if (g->type.isPtr && g->arraySize == 0) { emitLoadVar(X0, id->name); return; }
                loadStrAddrKnown(X0, g->off); return;
            }
            throw std::runtime_error("undefined variable '" + id->name + "'");
        }
        if (auto aof = dynamic_cast<AddressOfExpr*>(path)) {
            if (aof->target) { emitAddr(aof->target.get()); return; }
            if (auto v = var(aof->name)) { addSpAddr(X0, v->off + tempBytes); return; }
            auto g = global(aof->name);
            if (g) { loadStrAddrKnown(X0, g->off); return; }
            for (auto& f : prog.functions)
                if (f->name == aof->name && !f->isExtern) {
                    addrFixup(X0, aof->name);   // `&func`
                    return;
                }
            throw std::runtime_error("undefined variable '" + aof->name + "'");
        }
        if (auto mem = dynamic_cast<MemberExpr*>(path)) {
            // A pointer-valued object (`po.y`, `n1.next.val`) contributes its
            // *value* — the hop through the pointer — while a struct-valued
            // one contributes its address.
            Type ot = typeOf(mem->object.get());
            if (ot.isPtr) emitExpr(mem->object.get());
            else emitAddr(mem->object.get());
            addImmX0(fieldOffset(mem->object.get(), mem->member));
            return;
        }
        if (auto arr = dynamic_cast<ArrayAccessExpr*>(path)) {
            Type bt = typeOf(arr->array.get());
            // `p[i]` steps by the pointee size; an array (or array of
            // pointers) already carries its element stride.
            int elem = elementSize(bt);
            if (bt.isPtr && !isArrayExpr(arr->array.get())) {
                Type pt = bt; pt.isPtr = false;
                elem = elementSize(pt);
            }
            emitAddr(arr->array.get());
            int64_t ci;
            if (getIntConst(arr->index.get(), ci)) {
                addImmX0(ci * elem);
            } else {
                pushX0();
                emitExpr(arr->index.get());
                if (elem == 4) { loadConst(X1, 2); lslR(X0, X0, X1); }
                else if (elem == 8) { loadConst(X1, 3); lslR(X0, X0, X1); }
                else if (elem > 1) { loadConst(X1, (uint64_t)elem); mulR(X0, X0, X1); }
                popX1();
                addReg(X0, X1, X0);
            }
            return;
        }
        if (auto d = dynamic_cast<DerefExpr*>(path)) {
            emitExpr(d->ptr.get());
            return;
        }
        if (auto bin = dynamic_cast<BinaryExpr*>(path)) {
            // Pointer arithmetic as an lvalue target: `*(p + off)`, `*(p - off)`,
            // `*(base + i * size)`. The address *is* the value of the
            // expression here, and emitBinInt() already folds the constant
            // forms and scales the indexed ones, so just evaluate it.
            if (bin->op == "+" || bin->op == "-") { emitBinInt(bin); return; }
        }
        cerr << "arm64: unhandled address expression\n";
        loadConst(X0, 0);
    }

    void emitAddrBase(const string& name) {
        if (auto v = var(name)) { addSpAddr(X0, v->off + tempBytes); return; }
        auto g = global(name); if (g) { loadStrAddrKnown(X0, g->off); return; }
        throw std::runtime_error("undefined variable '" + name + "'");
    }

    // Element stride (in bytes) for arithmetic on a typed pointer `p`.
    // ptr<T> is folded into Type{ kind = T, isPtr = true }, so the pointee is
    // fully described by kind/structName. Returns 1 when the operand is not a
    // pointer we can type, which leaves plain integer arithmetic untouched.
    int ptrElemStride(const Expr* e) {
        if (!e) return 1;
        if (auto id = dynamic_cast<const IdentExpr*>(e)) {
            Type t = varType(id->name);
            if (!t.isPtr || t.kind == TypeKind::Void) return 1;
            // The stride is the size of the pointee, not of the pointer: a
            // ptr<int> steps by 4 even though the pointer itself is 8 bytes.
            t.isPtr = false;
            int n = elementSize(t);
            return n > 0 ? n : 1;
        }
        if (auto bin = dynamic_cast<const BinaryExpr*>(e)) {
            if (bin->op == "+" || bin->op == "-") return ptrElemStride(bin->left.get());
        }
        if (auto aa = dynamic_cast<const ArrayAccessExpr*>(e)) return ptrElemStride(aa->array.get());
        if (auto un = dynamic_cast<const UnaryExpr*>(e)) {
            if (un->op == "*" || un->op == "&") return ptrElemStride(un->operand.get());
        }
        return 1;
    }

    // ---- expression / statement dispatch ----
    int emitExpr(Expr* e);
    int emitBinInt(BinaryExpr* bin);
    int emitBinFloat(BinaryExpr* bin);
    int emitCall(CallExpr* c);
    bool tryBuiltin(CallExpr* c);
    bool tryBuiltinMath(CallExpr* c);
    void emitStmt(Stmt* s, int* brk, int* con, int* end);
    void emitAsmInstr(const AsmInstr& instr);
    void emitBlock(const Block& b, int* brk, int* con, int* end);
    int emitCondJump(Expr* c, int label, bool wantTrue);
    void emitSwitch(SwitchStmt* sw);
    void emitReturn(Expr* v, int retLabel);
    void allocVarSlots(FunctionDecl* f);
    void resetFn();
    void emitRuntime(const string& name);
    void emitFloatPrintBody(const string& putsFn);
    // Android only: nanosleep(&{0, x0}, NULL) with x0 already in nanoseconds.
    void emitAndroidSleep() {
        subSp(32);
        movzImm(X1, 0);
        strX(X1, XSP, 0);                     // ts.tv_sec = 0
        strX(X0, XSP, 8);                     // ts.tv_nsec = ns
        addSpAddr(X0, 0);                     // X0 = &ts
        movzImm(X1, 0);                       // X1 = rem = NULL
        svcSys(SYS_NR_NANOSLEEP);
        addSp(32);
        ret();
    }
    void emitStartup();
    void emitGlobalInit();
    // 'app android': wrap the flat image in an ELF64 AArch64 executable.
    bool writeAndroidElf(const string& outputPath, const vector<uint8_t>& img,
                         size_t dataStart);
    void resolveBranches(const string& fn) {
        for (auto& b : branches) {
            int target = labelPositions[b.label];
            int pc = b.pos;
            switch (b.kind) {
                case BrKind::Cond: {
                    int imm19 = (target - pc) / 4;
                    if (imm19 < -262144 || imm19 > 262143) {
                        cerr << "arm64: B.cond out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, b_cond((uint32_t)b.cc, (uint32_t)(imm19 & 0x7FFFF)));
                    break;
                }
                case BrKind::Cbz:
                case BrKind::Cbnz: {
                    int imm19 = (target - pc) / 4;
                    if (imm19 < -262144 || imm19 > 262143) {
                        cerr << "arm64: CBZ/CBNZ out of range in '" << fn << "'\n";
                        continue;
                    }
                    uint32_t imm = (uint32_t)(imm19 & 0x7FFFF);
                    if (b.kind == BrKind::Cbz) u32pat(code, b.pos, cbz(b.rt, imm));
                    else u32pat(code, b.pos, cbnz(b.rt, imm));
                    break;
                }
                case BrKind::Tbnz: {
                    int imm14 = (target - pc) / 4;
                    if (imm14 < -8192 || imm14 > 8191) {
                        cerr << "arm64: TBNZ out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, tbnz_w(b.rt, (uint32_t)b.cc, (uint32_t)(imm14 & 0x3FFF)));
                    break;
                }
                case BrKind::B:
                default: {
                    int imm26 = (target - pc) / 4;
                    if (imm26 < -33554432 || imm26 > 33554431) {
                        cerr << "arm64: B out of range in '" << fn << "'\n";
                        continue;
                    }
                    u32pat(code, b.pos, b_imm_raw((uint32_t)(imm26 & 0x3FFFFFF)));
                    break;
                }
            }
        }
    }

    // ---- per-function images ----
    struct FnImg {
        string name;
        vector<uint8_t> bytes;
        vector<CallFix> bls;
        vector<AddrFix> adds;
        vector<StrFix> strFixes;
    };
    vector<FnImg> userImgs;
    vector<FnImg> runtimeImgs;

    bool compile(const string& outputPath);
};

// =========================================================================
// Statements
// =========================================================================
void A64::emitStmt(Stmt* s, int* brk, int* con, int* end) {
    if (auto v = dynamic_cast<VarDecl*>(s)) {
        auto vi = var(v->name);
        if (vi && v->init) {
            emitExpr(v->init.get());
            if (vi->size == 8) storeToOff64(X0, vi->off);
            else storeToOff(X0, vi->off);
        }
        return;
    }
    if (auto a = dynamic_cast<AssignStmt*>(s)) {
        if (a->memberPath.empty() && !a->indexExpr) {
            emitExpr(a->value.get());
            emitStoreVar(a->name, X0);
            return;
        }
        // Target address, hop-aware: a pointer-typed base contributes its
        // *value* (`pn.y` starts from *pn, not from pn's own slot), and a
        // pointer field in the middle of the chain is loaded before the walk
        // continues (`n1.next.val` walks through `next`).
        Type t = varType(a->name);
        bool ptrBase = t.isPtr && !isArrayVar(a->name);
        if (ptrBase) {
            emitLoadVar(X0, a->name);
            t.isPtr = false;
        } else if (auto v = var(a->name)) {
            addSpAddr(X0, v->off + tempBytes);
        } else if (auto g = global(a->name)) {
            loadStrAddrKnown(X0, g->off);
        } else {
            throw std::runtime_error("undefined variable '" + a->name + "'");
        }
        if (a->indexExpr) {
            int elem = scalarSize(t);
            pushX0();
            emitExpr(a->indexExpr.get());
            if (elem == 4) { loadConst(X1, 2); lslR(X0, X0, X1); }
            else if (elem == 8) { loadConst(X1, 3); lslR(X0, X0, X1); }
            else if (elem > 1) { loadConst(X1, (uint64_t)elem); mulR(X0, X0, X1); }
            popX1();
            addReg(X0, X1, X0);
        }
        for (size_t i = 0; i < a->memberPath.size(); i++) {
            const string& m = a->memberPath[i];
            Type ft = fieldTypeOf(t, m);
            addImmX0(fieldOffsetOf(t, m));
            if (i + 1 < a->memberPath.size() && ft.isPtr) {
                // hop: the next object lives behind this pointer
                if (scalarSize(ft) == 8) ldrX(X0, X0, 0);
                else loadElem(X0, X0);
                t = ft;
                t.isPtr = false;
            } else {
                t = ft;
            }
        }
        pushX0();
        emitExpr(a->value.get());
        mov(X1, X0);
        popX1();
        storeTyped(X1, t);
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        // The target is the *value* of the pointer expression, exactly as when
        // the same DerefExpr is read back in emitExpr(). emitAddr() cannot be
        // used here: for a bare identifier it yields the address of the
        // variable's own stack slot, so `*(p) = v` would overwrite the
        // variable p instead of the memory it points at. The store width
        // follows the pointee type (8 for pointers, 4 for int/float/bool).
        Type t = typeOf(pa->ptr.get());
        if (t.isPtr) t.isPtr = false;
        else t = Type(TypeKind::Int);
        emitExpr(pa->ptr.get());
        pushX0();
        emitExpr(pa->value.get());
        mov(X1, X0);
        popX1();
        storeTyped(X1, t);
        return;
    }
    if (auto es = dynamic_cast<ExprStmt*>(s)) { emitExpr(es->expr.get()); return; }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        int trueL = newLabel();
        int endL = newLabel();
        emitCondJump(ifs->condition.get(), trueL, true);
        emitBlock(ifs->elseBlock, brk, con, end);
        b_imm(endL);
        emitLabel(trueL);
        emitBlock(ifs->thenBlock, brk, con, end);
        emitLabel(endL);
        return;
    }
    if (auto ws = dynamic_cast<WhileStmt*>(s)) {
        int startL = newLabel();
        int doneL = newLabel();
        emitLabel(startL);
        emitCondJump(ws->condition.get(), doneL, false);
        emitBlock(ws->body, &doneL, &startL, end);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto ls = dynamic_cast<LoopStmt*>(s)) {
        int startL = newLabel();
        int doneL = newLabel();
        emitLabel(startL);
        emitBlock(ls->body, &doneL, &startL, end);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto fs = dynamic_cast<ForStmt*>(s)) {
        int startL = newLabel();
        int stepL = newLabel();
        int doneL = newLabel();
        emitExpr(fs->start.get());
        emitStoreVar(fs->varName, X0);
        emitLabel(startL);
        emitLoadVar(X0, fs->varName);
        pushX0();
        emitExpr(fs->end.get());
        popX1();                    // X1 = counter, X0 = end
        cmpReg(X1, X0);
        int64_t sv = 1;
        bool sConst = fs->step ? getIntConst(fs->step.get(), sv) : false;
        int cc = (sConst && sv < 0) ? 13 : 10;  // LE for decreasing, GE otherwise
        b_cc(cc, doneL);
        emitBlock(fs->body, &doneL, &stepL, end);
        emitLabel(stepL);
        emitLoadVar(X0, fs->varName);
        pushX0();
        if (fs->step) emitExpr(fs->step.get());
        else loadConst(X0, 1);
        popX1();
        addReg(X0, X1, X0);
        emitStoreVar(fs->varName, X0);
        b_imm(startL);
        emitLabel(doneL);
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) { emitSwitch(sw); return; }
    if (dynamic_cast<BreakStmt*>(s)) { if (brk) b_imm(*brk); return; }
    if (dynamic_cast<ContinueStmt*>(s)) { if (con) b_imm(*con); return; }
    if (auto r = dynamic_cast<ReturnStmt*>(s)) { emitReturn(r->value.get(), retLabel); return; }
    if (auto as = dynamic_cast<AsmStmt*>(s)) {
        for (auto& instr : as->instrs) emitAsmInstr(instr);
        return;
    }
}

void A64::emitBlock(const Block& b, int* brk, int* con, int* end) {
    for (auto& s : b.stmts) emitStmt(s.get(), brk, con, end);
}

// =========================================================================
// AArch64 inline assembler (asm {} / asm32 {} / asm16 {} blocks).
//
// Registers: x0-x30, w0-w30, sp, wsp, xzr/zr, wzr. 'asm' blocks are 64-bit
// register width everywhere; a register spelled 'w' selects a 32-bit
// (zero/sign-extending) operation. Memory operands use [base, offset] or
// [base, regoffset]; offsets are unscaled byte displacements, multiple of the
// access size for ldr/str. Branches take a signed byte displacement relative
// to the start of the branch instruction (b/bl = +-128 MB, b.cond/cbz/cbnz =
// +-1 MB); condition-suffixed mnemonics (beq/bne/...) are used instead of
// 'b.eq'.
// =========================================================================
void A64::emitAsmInstr(const AsmInstr& instr) {
    const string mn = instr.mnemonic;

    auto trim = [](string s) {
        while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        return s;
    };
    auto parseReg = [&](const string& raw, int& reg, bool& is64) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        if (s == "sp")  { reg = 31; is64 = true;  return true; }
        if (s == "wsp") { reg = 31; is64 = false; return true; }
        if (s == "xzr" || s == "zr") { reg = 31; is64 = true;  return true; }
        if (s == "wzr") { reg = 31; is64 = false; return true; }
        if ((s[0] == 'x' || s[0] == 'w') && s.size() > 1) {
            int v = 0;
            size_t i = 1;
            while (i < s.size() && isdigit((unsigned char)s[i])) { v = v * 10 + (s[i] - '0'); i++; }
            if (i == s.size() && v <= 30) { reg = v; is64 = (s[0] == 'x'); return true; }
        }
        return false;
    };
    auto parseImm = [&](const string& raw, int64_t& v) -> bool {
        string s = trim(raw);
        if (s.empty()) return false;
        if (s[0] == '#') s.erase(s.begin());
        if (s.empty()) return false;
        bool neg = false;
        if (s[0] == '-') { neg = true; s.erase(s.begin()); }
        if (s.empty()) return false;
        try {
            size_t idx = 0;
            int64_t val;
            if (s.size() >= 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
                val = (int64_t)std::stoull(s.substr(2), &idx, 16);
                if (idx != s.size() - 2) return false;
            } else {
                val = (int64_t)std::stoull(s, &idx, 10);
                if (idx != s.size()) return false;
            }
            v = neg ? -val : val;
            return true;
        } catch (...) { return false; }
    };
    auto parseDisp = [&](const string& raw, int& disp) -> bool {
        int64_t v;
        if (!parseImm(raw, v)) return false;
        disp = (int)v;
        return true;
    };
    auto condCode = [](const string& s) -> int {
        if (s == "eq") return 0;  if (s == "ne") return 1;
        if (s == "hs" || s == "cs") return 2;  if (s == "lo" || s == "cc") return 3;
        if (s == "mi") return 4;  if (s == "pl") return 5;
        if (s == "vs") return 6;  if (s == "vc") return 7;
        if (s == "hi") return 8;  if (s == "ls") return 9;
        if (s == "ge") return 10; if (s == "lt") return 11;
        if (s == "gt") return 12; if (s == "le") return 13;
        if (s == "al") return 14;
        return -1;
    };
    auto unsupported = [&](const string& what) {
        cerr << "arm64: warning: unsupported asm '" << what << "', skipped\n";
    };
    auto badOperand = [&](const string& why) {
        cerr << "arm64: warning: asm '" << mn << "': " << why << ", skipped\n";
    };

    // ---- register moves & immediate loads ----
    if (mn == "mov" || mn == "movz" || mn == "movk") {
        int rd, rn; bool d64, n64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int64_t imm;
        if (parseImm(instr.op2, imm)) {
            uint64_t v = d64 ? (uint64_t)imm : (uint64_t)(int32_t)(int64_t)imm;
            if (mn == "mov") { loadConst(rd, v); return; }
            int hw = (instr.op3.empty() || instr.op3 == "0") ? 0 : 1;
            uint16_t lo = (uint16_t)(v & 0xFFFF);
            if (mn == "movz") u32(movz(rd, lo, hw));
            else u32(movk(rd, lo, hw));
            return;
        }
        if (parseReg(instr.op2, rn, n64)) {
            if (d64 != n64) { badOperand("mixed x/w registers in mov"); return; }
            u32(d64 ? mov_reg(rd, rn) : mov_w_reg(rd, rn));
            return;
        }
        badOperand("expected register or immediate operand");
        return;
    }

    // ---- two- or three-operand ALU: add/sub/and/orr/eor/mul/sdiv/udiv ----
    auto aluBinary = [&](uint32_t (*xEnc)(int, int, int), uint32_t (*wEnc)(int, int, int),
                         uint32_t xImmBase, uint32_t wImmBase) -> bool {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return false; }
        int rn = rd; bool n64 = d64;
        if (!instr.op2.empty()) {
            if (!parseReg(instr.op2, rn, n64)) { badOperand("bad source register"); return false; }
            if (d64 != n64) { badOperand("mixed x/w registers"); return false; }
        }
        if (instr.op3.empty()) {
            // 2-operand form: rd = rd op rn
            u32(d64 ? xEnc(rd, rd, rn) : wEnc(rd, rd, rn));
            return true;
        }
        int64_t imm;
        if (parseImm(instr.op3, imm)) {
            if (xImmBase == 0) { badOperand("immediate not supported for this operation"); return false; }
            if (d64) {
                if (imm >= 0 && imm <= 4095) { u32(xImmBase | ((uint32_t)imm << 10) | ((uint32_t)rn << 5) | (uint32_t)rd); return true; }
                if (imm < 0 && imm >= -4095) { // ADD --> SUB
                    if (mn == "add") { u32(sub_imm(rd, rn, (uint16_t)(-imm))); return true; }
                    if (mn == "sub") { u32(add_imm(rd, rn, (uint16_t)(-imm))); return true; }
                }
            } else {
                if (imm >= 0 && imm <= 4095) { u32(wImmBase | ((uint32_t)imm << 10) | ((uint32_t)rn << 5) | (uint32_t)rd); return true; }
                if (imm < 0 && imm >= -4095) {
                    if (mn == "add") { u32(sub_w_imm(rd, rn, (uint16_t)(-imm))); return true; }
                    if (mn == "sub") { u32(add_w_imm(rd, rn, (uint16_t)(-imm))); return true; }
                }
            }
            badOperand("immediate out of encoded range (0..4095)");
            return false;
        }
        int rm; bool m64;
        if (!parseReg(instr.op3, rm, m64)) { badOperand("bad third operand"); return false; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return false; }
        u32(d64 ? xEnc(rd, rn, rm) : wEnc(rd, rn, rm));
        return true;
    };

    if (mn == "add") { aluBinary(add_reg, add_w_reg, 0x91000000u, 0x11000000u); return; }
    if (mn == "sub") { aluBinary(sub_reg, sub_w_reg, 0xD1000000u, 0x51000000u); return; }
    if (mn == "and") { aluBinary(and_reg, and_w_reg, 0, 0); return; }   // imm not supported for and
    if (mn == "orr") { aluBinary(orr_reg, orr_w_reg, 0, 0); return; }
    if (mn == "eor") { aluBinary(eor_reg, eor_w_reg, 0, 0); return; }

    if (mn == "mul") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad first source register"); return; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return; }
        int rm = rn; bool m64 = n64;
        if (!instr.op3.empty() && !parseReg(instr.op3, rm, m64)) { badOperand("bad second source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        u32(d64 ? mul_reg(rd, rn, rm) : mul_w_reg(rd, rn, rm));
        return;
    }
    if (mn == "sdiv" || mn == "udiv") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad first source register"); return; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return; }
        int rm = rn; bool m64 = n64;
        if (!instr.op3.empty() && !parseReg(instr.op3, rm, m64)) { badOperand("bad second source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        if (mn == "sdiv") u32(d64 ? sdiv_reg(rd, rn, rm) : sdiv_w_reg(rd, rn, rm));
        else              u32(d64 ? udiv_x(rd, rn, rm)    : udiv_w(rd, rn, rm));
        return;
    }

    // ---- unary ALU: neg/mvn ----
    if (mn == "neg" || mn == "mvn") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int rm; bool m64;
        if (!parseReg(instr.op2, rm, m64)) { badOperand("bad source register"); return; }
        if (d64 != m64) { badOperand("mixed x/w registers"); return; }
        if (mn == "neg") u32(d64 ? neg_reg(rd, rm) : neg_w_reg(rd, rm));
        else             u32(d64 ? mvn_x(rd, rm)   : mvn_w(rd, rm));
        return;
    }

    // ---- compare ----
    if (mn == "cmp") {
        int rn; bool n64;
        if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; }
        int64_t imm;
        if (parseImm(instr.op2, imm)) {
            if (imm >= 0 && imm <= 4095) { u32(n64 ? cmp_imm(rn, (uint16_t)imm) : cmp_w_imm(rn, (uint16_t)imm)); return; }
            if (imm < 0 && imm >= -4095) { // cmp rn, -v == adds rn, v
                u32(n64 ? add_imm(rn, rn, (uint16_t)(-imm)) : add_w_imm(rn, rn, (uint16_t)(-imm)));
                return;
            }
            badOperand("cmp immediate out of range (-4095..4095)");
            return;
        }
        int rm; bool m64;
        if (!parseReg(instr.op2, rm, m64)) { badOperand("bad comparator register"); return; }
        if (n64 != m64) { badOperand("mixed x/w registers"); return; }
        u32(n64 ? cmp_reg(rn, rm) : cmp_w_reg(rn, rm));
        return;
    }

    // ---- shifts: lsl/lsr/asr rd, rn, sh  (reg-reg or immediate) ----
    auto shift = [&]() -> bool {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return false; }
        int rn; bool n64;
        if (!parseReg(instr.op2, rn, n64)) { badOperand("bad source register"); return false; }
        if (d64 != n64) { badOperand("mixed x/w registers"); return false; }
        int64_t imm;
        if (parseImm(instr.op3, imm)) {
            if (d64) {
                if (imm < 0 || imm > 63) { badOperand("shift count must be 0..63"); return false; }
                if (mn == "lsl") u32(lsl_x_imm(rd, rn, (uint8_t)imm));
                else if (mn == "lsr") u32(lsr_x_imm(rd, rn, (uint8_t)imm));
                else u32(asr_x_imm(rd, rn, (uint8_t)imm));
                return true;
            } else {
                if (imm < 0 || imm > 31) { badOperand("shift count must be 0..31"); return false; }
                if (mn == "lsl") u32(lsl_w_imm(rd, rn, (uint8_t)imm));
                else if (mn == "lsr") u32(lsr_w_imm(rd, rn, (uint8_t)imm));
                else u32(asr_w_imm(rd, rn, (uint8_t)imm));
                return true;
            }
        }
        int rm; bool m64;
        if (instr.op3.empty() || !parseReg(instr.op3, rm, m64)) {
            if (instr.op3.empty()) rm = rn, m64 = n64;
            else { badOperand("bad shift operand"); return false; }
        }
        if (d64 != m64) { badOperand("mixed x/w registers"); return false; }
        if (mn == "lsl") u32(d64 ? lsl_reg(rd, rn, rm) : lsl_w_reg(rd, rn, rm));
        else if (mn == "lsr") u32(d64 ? lsr_reg(rd, rn, rm) : lsr_w_reg(rd, rn, rm));
        else u32(d64 ? asr_reg(rd, rn, rm) : asr_w_reg(rd, rn, rm));
        return true;
    };
    if (mn == "lsl" || mn == "lsr" || mn == "asr") { shift(); return; }

    // ---- memory: ldr/str/ldrb/strb/ldrsb/ldrsw ----
    auto memoryOp = [&](bool load, bool byte, bool signExtend) -> bool {
        int rt; bool t64;
        if (!parseReg(instr.op1, rt, t64)) { badOperand("bad register"); return false; }
        if (byte && t64) { badOperand("byte loads/stores require a 'w' register"); return false; }
        if (signExtend && !t64) { badOperand("ldrsb/ldrsw require an 'x' register"); return false; }
        string m = trim(instr.op2);
        if (m.size() < 2 || m.front() != '[' || m.back() != ']') { badOperand("expected [base, offset]"); return false; }
        m = m.substr(1, m.size() - 2);
        size_t comma = m.find(',');
        string baseStr = comma == string::npos ? m : m.substr(0, comma);
        string offStr = comma == string::npos ? "" : m.substr(comma + 1);
        int rn; bool n64;
        if (!parseReg(baseStr, rn, n64)) { badOperand("bad base register"); return false; }
        int rm = -1; bool m64 = true;
        int64_t off = 0;
        bool hasRegOff = false;
        if (!trim(offStr).empty()) {
            if (parseReg(offStr, rm, m64)) { hasRegOff = true; }
            else if (!parseImm(offStr, off)) { badOperand("bad offset"); return false; }
        }
        uint32_t scale = byte ? 1u : (signExtend ? 4u : (t64 ? 8u : 4u));
        if (hasRegOff) {
            if (byte) u32(load ? ldrb_w_reg(rt, rn, rm) : strb_w_reg(rt, rn, rm));
            else if (t64) u32(load ? ldr_x_reg(rt, rn, rm) : str_x_reg(rt, rn, rm));
            else u32(load ? ldr_w_reg(rt, rn, rm) : str_w_reg(rt, rn, rm));
            return true;
        }
        if (off < 0) { badOperand("negative immediate offsets are not supported"); return false; }
        if (byte) {
            if (off > 4095) { badOperand("byte offset out of range (0..4095)"); return false; }
            u32(signExtend ? ldrsb_x(rt, rn, (uint16_t)off)
                           : (load ? ldrb_w(rt, rn, (uint16_t)off) : strb_w(rt, rn, (uint16_t)off)));
            return true;
        }
        if (off % scale != 0) { badOperand("offset must be a multiple of the access size"); return false; }
        if (off / scale > 4095) { badOperand("offset out of range for this access size"); return false; }
        if (signExtend) {
            u32(ldrsw(rt, rn, (uint16_t)(off / 4)));
        } else if (t64) {
            u32(load ? ldr_x(rt, rn, (uint16_t)(off / 8)) : str_x(rt, rn, (uint16_t)(off / 8)));
        } else {
            u32(load ? ldr_w(rt, rn, (uint16_t)(off / 4)) : str_w(rt, rn, (uint16_t)(off / 4)));
        }
        return true;
    };
    if (mn == "ldr" || mn == "str") { memoryOp(mn == "ldr", false, false); return; }
    if (mn == "ldrb" || mn == "strb") { memoryOp(mn == "ldrb", true, false); return; }
    if (mn == "ldrsb") { memoryOp(true, true, true); return; }
    if (mn == "ldrsw") { memoryOp(true, false, true); return; }

    // ---- relative branches (signed byte displacement from the instruction) ----
    auto branchDisp = [&](const string& raw, int& disp) -> bool {
        if (!parseDisp(raw, disp)) { badOperand("bad branch displacement"); return false; }
        if (disp % 4 != 0) { badOperand("branch displacement must be a multiple of 4"); return false; }
        return true;
    };
    if (mn == "b" || mn == "bl") {
        int disp;
        if (!branchDisp(instr.op1, disp)) return;
        int32_t imm26 = disp / 4;
        if (imm26 < (int32_t)0xFE000000 || imm26 > 0x01FFFFFF) { badOperand("branch out of range (+-128 MB)"); return; }
        u32(mn == "b" ? b_imm_raw((uint32_t)(imm26 & 0x03FFFFFF)) : bl_imm((uint32_t)(imm26 & 0x03FFFFFF)));
        return;
    }
    if (mn.size() == 3 && mn[0] == 'b') {
        int cc = condCode(mn.substr(1));
        if (cc < 0) { unsupported(mn); return; }
        int disp;
        if (!branchDisp(instr.op1, disp)) return;
        int32_t imm19 = disp / 4;
        if (imm19 < -262144 || imm19 > 262143) { badOperand("b.cond out of range (+-1 MB)"); return; }
        u32(b_cond((uint32_t)cc, (uint32_t)(imm19 & 0x7FFFF)));
        return;
    }
    if (mn == "cbz" || mn == "cbnz") {
        int rt; bool t64;
        if (!parseReg(instr.op1, rt, t64)) { badOperand("bad register"); return; }
        int disp;
        if (!branchDisp(instr.op2, disp)) return;
        int32_t imm19 = disp / 4;
        if (imm19 < -262144 || imm19 > 262143) { badOperand("cbz/cbnz out of range (+-1 MB)"); return; }
        u32(mn == "cbz" ? cbz(rt, (uint32_t)(imm19 & 0x7FFFF)) : cbnz(rt, (uint32_t)(imm19 & 0x7FFFF)));
        return;
    }

    // ---- indirect branches / calls ----
    if (mn == "br" || mn == "blr") {
        int rn; bool n64;
        if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; }
        u32(mn == "br" ? br(rn) : blr(rn));
        return;
    }
    if (mn == "ret") {
        if (instr.op1.empty()) { ret(); }
        else { int rn; bool n64; if (!parseReg(instr.op1, rn, n64)) { badOperand("bad register"); return; } u32(ret_reg(rn)); }
        return;
    }

    // ---- condition set ----
    if (mn == "cset") {
        int rd; bool d64;
        if (!parseReg(instr.op1, rd, d64)) { badOperand("bad destination register"); return; }
        int cc = condCode(trim(instr.op2));
        if (cc < 0) { badOperand("bad condition flag"); return; }
        u32(cset(rd, (uint32_t)cc));
        return;
    }

    // ---- hints / specials ----
    if (mn == "nop")   { nop(); return; }
    if (mn == "wfi")   { u32(wfi_instr()); return; }
    if (mn == "wfe")   { u32(wfe_instr()); return; }
    if (mn == "sev")   { u32(sev_instr()); return; }
    if (mn == "yield") { u32(yield_instr()); return; }
    if (mn == "svc" || mn == "hlt" || mn == "brk") {
        int64_t imm;
        uint16_t v = 0;
        if (!instr.op1.empty() && parseImm(instr.op1, imm)) v = (uint16_t)(imm & 0xFFFF);
        if (mn == "svc") u32(svc_imm(v));
        else if (mn == "hlt") u32(hlt_imm(v));
        else u32(brk_imm(v));
        return;
    }

    unsupported(mn);
}

void A64::emitSwitch(SwitchStmt* sw) {
    int endL = newLabel();
    int defL = -1;
    int slot = swTempOff + swTempStride() * (swCur++);
    emitExpr(sw->condition.get());
    storeToOff(X0, slot);
    vector<int> caseLabels;
    for (auto& cs : sw->cases) {
        if (cs.condition) {
            int L = newLabel();
            caseLabels.push_back(L);
            int64_t cv; bool cconst = getIntConst(cs.condition.get(), cv);
            if (cconst) loadConst(X0, (uint64_t)(int64_t)(int32_t)cv);
            else emitExpr(cs.condition.get());
            loadFromOff(X1, slot);
            cmpReg(X1, X0);
            b_cc(0, L);
        } else {
            defL = newLabel();
        }
    }
    if (defL < 0) defL = endL;
    b_imm(defL);
    int ci = 0;
    for (auto& cs : sw->cases) {
        if (cs.condition) {
            emitLabel(caseLabels[ci++]);
            emitBlock(cs.body, &endL, nullptr, &endL);
            b_imm(endL);
        }
    }
    if (defL != endL) {
        emitLabel(defL);
        for (auto& cs : sw->cases) {
            if (!cs.condition) emitBlock(cs.body, &endL, nullptr, &endL);
        }
    }
    emitLabel(endL);
}

void A64::emitReturn(Expr* v, int retLabel) {
    if (v) emitExpr(v);
    if (retLabel >= 0) b_imm(retLabel);
}

// =========================================================================
// Expressions
// =========================================================================
int A64::emitExpr(Expr* e) {
    if (!e) { loadConst(X0, 0); return X0; }
    if (auto n = dynamic_cast<NumberExpr*>(e)) {
        loadConst(X0, (uint64_t)(int64_t)n->value);
        return X0;
    }
    if (auto fl = dynamic_cast<FloatExpr*>(e)) {
        // Float values travel through the integer registers/slots as raw
        // f32 bits; they move into the S registers only for arithmetic.
        uint32_t bits;
        float fv = (float)fl->value;
        std::memcpy(&bits, &fv, 4);
        loadConst(X0, (uint64_t)bits);
        return X0;
    }
    if (auto s = dynamic_cast<StringExpr*>(e)) {
        emitStrAddr(X0, stringIdx(s->value));
        return X0;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e)) {
        if (var(id->name) || global(id->name)) { emitLoadVar(X0, id->name); return X0; }
        throw std::runtime_error("undefined variable '" + id->name + "'");
    }
    if (dynamic_cast<AddressOfExpr*>(e)) { emitAddr(e); return X0; }
    if (auto der = dynamic_cast<DerefExpr*>(e)) {
        emitExpr(der->ptr.get());
        Type t = typeOf(der->ptr.get());
        if (t.isPtr) { t.isPtr = false; loadTyped(X0, t); }
        else loadElem(X0, X0);
        return X0;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e)) {
        if (u->op == "!") {
            emitExpr(u->operand.get());
            cmpImm(X0, 0);
            csetR(X0, 0);  // EQ
            return X0;
        }
        if (u->op == "~") {
            emitExpr(u->operand.get());
            u32(mvn(X0, X0));
            return X0;
        }
        if (u->op == "-") {
            emitExpr(u->operand.get());
            if (isFloatExpr(u->operand.get())) {
                u32(encFmovSW(0, X0));
                u32(encFnegSx(0, 0));
                u32(encFmovWS(X0, 0));
            } else {
                negReg(X0, X0);
            }
            return X0;
        }
        cerr << "arm64: unsupported unary '" << u->op << "'\n";
        loadConst(X0, 0);
        return X0;
    }
    if (auto mem = dynamic_cast<MemberExpr*>(e)) {
        Type ot = typeOf(mem->object.get());
        if (ot.isPtr) {
            // the object lives behind a pointer: load it, hop, then the field
            emitExpr(mem->object.get());
        } else if (auto oid = dynamic_cast<IdentExpr*>(mem->object.get())) {
            if (auto v = var(oid->name)) {
                int total = v->off + fieldOffsetOf(v->type, mem->member);
                loadFromOff(X0, total);
                return X0;
            } else if (auto g = global(oid->name)) {
                loadGlobal(X0, g->off + fieldOffsetOf(g->type, mem->member));
                return X0;
            }
            emitAddr(mem->object.get());
        } else {
            emitAddr(mem->object.get());
        }
        addImmX0(fieldOffset(mem->object.get(), mem->member));
        Type objT = ot;
        if (objT.isPtr) objT.isPtr = false;
        loadTyped(X0, fieldTypeOf(objT, mem->member));
        return X0;
    }
    if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        emitAddr(arr);
        Type et = typeOf(arr);   // element type (pointee for a typed pointer)
        loadTyped(X0, et);
        return X0;
    }
    if (auto c = dynamic_cast<CallExpr*>(e)) { emitCall(c); return X0; }
    if (auto b = dynamic_cast<BinaryExpr*>(e)) {
        if (isFloatExpr(b)) return emitBinFloat(b);
        return emitBinInt(b);
    }
    cerr << "arm64: unhandled expression\n";
    loadConst(X0, 0);
    return X0;
}

int A64::emitBinInt(BinaryExpr* bin) {
    const string& op = bin->op;
    int64_t rconst = 0; bool rIsConst = getIntConst(bin->right.get(), rconst);

    if (op == "+" && rIsConst) { emitExpr(bin->left.get()); addImmX0(rconst * ptrElemStride(bin->left.get())); return X0; }
    if (op == "-" && rIsConst) { emitExpr(bin->left.get()); addImmX0(-rconst * ptrElemStride(bin->left.get())); return X0; }
    if (op == "*" && rIsConst && rconst > 0) {
        int64_t v = rconst;
        for (int sh = 0; sh <= 62; sh++) {
            if (v == (int64_t)1 << sh) {
                emitExpr(bin->left.get());
                if (sh == 0) return X0;
                loadConst(X1, (uint64_t)sh);
                lslR(X0, X0, X1);
                return X0;
            }
        }
    }
    int64_t lconst; bool lIsConst = getIntConst(bin->left.get(), lconst);
    if (lIsConst && !rIsConst) {
        if (op == "+") {
            emitExpr(bin->right.get());
            addImmX0(lconst);
            return X0;
        }
        if (op == "*" || op == "&" || op == "|" || op == "^") {
            emitExpr(bin->right.get());
            loadConst(X1, (uint64_t)(int64_t)lconst);
            if (op == "*") { mulR(X0, X0, X1); return X0; }
            if (op == "&") { andReg(X0, X0, X1); return X0; }
            if (op == "|") { orrReg(X0, X0, X1); return X0; }
            if (op == "^") { eorReg(X0, X0, X1); return X0; }
        }
    }

    // generic: X1 = left, X0 = right
    emitExpr(bin->left.get());
    pushX0();
    emitExpr(bin->right.get());
    popX1();

    // Non-constant index: the fast paths above fold `p + 4` into the
    // immediate, here the element count has to be scaled at run time.
    // X1 is the pointer and X0 the index here, so it is X0 that gets scaled.
    if (op == "+" || op == "-") scaleX0(ptrElemStride(bin->left.get()));
    if (op == "+") { addReg(X0, X1, X0); return X0; }
    if (op == "-") { subReg(X0, X1, X0); return X0; }
    if (op == "*") { mulR(X0, X1, X0); return X0; }
    if (op == "&") { andReg(X0, X1, X0); return X0; }
    if (op == "|") { orrReg(X0, X1, X0); return X0; }
    if (op == "^") { eorReg(X0, X1, X0); return X0; }
    if (op == "<<") { lslR(X0, X1, X0); return X0; }
    // '>>' is a LOGICAL shift everywhere in Zenith: the x86 backends emit SHR
    // and the IR backends emit LSR. Emitting ASR here made this the one target
    // where '>>' meant something else, and it broke the -3r power-of-two
    // divide/remainder rewrite, whose formula is built on a logical shift --
    // the sign-correction step it relies on is a no-op under an arithmetic
    // one, so every negative dividend silently got a wrong quotient.
    if (op == ">>") { lsrR(X0, X1, X0); return X0; }
    if (op == "/" || op == "%" || op == "//") {
        sdivR(X2, X1, X0);            // X2 = left/right
        msubR(X3, X2, X0, X1);        // X3 = left - (left/right)*right = left%right
        if (op == "/") mov(X0, X2);
        else mov(X0, X3);
        return X0;
    }
    if (op == "%of") {
        mulR(X0, X1, X0);             // X0 = percent * base
        loadConst(X1, 100);           // X1 = 100
        sdivR(X0, X0, X1);            // X0 = product / 100
        return X0;
    }
    int cc = ccForOp(op);
    if (cc >= 0) {
        cmpReg(X1, X0);
        csetR(X0, cc);
        return X0;
    }
    cerr << "arm64: unsupported binary op '" << op << "'\n";
    loadConst(X0, 0);
    return X0;
}

// =========================================================================
// Float arithmetic: f32 values travel as raw bits in the integer registers
// and move into the S registers only for the operation itself.
// =========================================================================
int A64::emitBinFloat(BinaryExpr* bin) {
    const string& op = bin->op;
    bool flL = isFloatExpr(bin->left.get());
    bool flR = isFloatExpr(bin->right.get());
    emitExpr(bin->left.get());
    pushX0();
    emitExpr(bin->right.get());
    mov(X1, X0);
    popX1();                          // X1 = left, X0 = right
    if (flL) u32(encFmovSW(0, X1));
    else u32(encScvtfSW(0, X1));      // int operand: convert
    if (flR) u32(encFmovSW(1, X0));
    else u32(encScvtfSW(1, X0));
    if (op == "+") { u32(encFaddSx(0, 0, 1)); u32(encFmovWS(X0, 0)); return X0; }
    if (op == "-") { u32(encFsubSx(0, 0, 1)); u32(encFmovWS(X0, 0)); return X0; }
    if (op == "*") { u32(encFmulSx(0, 0, 1)); u32(encFmovWS(X0, 0)); return X0; }
    if (op == "/") { u32(encFdivSx(0, 0, 1)); u32(encFmovWS(X0, 0)); return X0; }
    int cc = ccForOp(op);
    if (cc >= 0) { u32(encFcmpSx(0, 1)); csetR(X0, cc); return X0; }
    cerr << "arm64: unsupported float op '" << op << "'\n";
    loadConst(X0, 0);
    return X0;
}

// =========================================================================
// Calls and builtins
// =========================================================================
int A64::emitCall(CallExpr* c) {
    if (tryBuiltin(c)) return X0;
    if (mixCtx && mixCtx->hasAny) {
        // C/C++ mixing: if the callee is provided by a mixed-in C/C++ object,
        // emit a direct BL to its (possibly mangled) symbol. The target address
        // is resolved by patchCalls once the merge has registered it.
        std::vector<Type> mixPtypes;
        for (auto& func : prog.functions) {
            if (func->isExtern && func->name == c->name) {
                for (auto& p : func->params) mixPtypes.push_back(p.type);
                break;
            }
        }
        if (mixCtx->providesLocal(c->name, mixPtypes)) {
            if (c->args.size() > 8) {
                cerr << "arm64: call '" << c->name << "' has more than 8 arguments "
                        "(not supported yet)\n";
                return X0;
            }
            size_t argsBytes = (c->args.size() * 8 + 15) & ~size_t(15);
            subSp((int)argsBytes);
            tempBytes += (int)argsBytes;
            for (size_t i = 0; i < c->args.size(); i++) {
                emitExpr(c->args[i].get());
                strX(X0, XSP, (uint32_t)(i * 8));
            }
            for (size_t i = 0; i < c->args.size(); i++) ldrX((int)i, XSP, (uint32_t)(i * 8));
            addSp((int)argsBytes);
            tempBytes -= (int)argsBytes;
            hasCalls = true;
            bl_fixup(mixCtx->localSymbol(c->name, mixPtypes));
            return X0;
        }
    }
    // Indirect call through a function pointer: stage the arguments into
    // stack slots first, evaluate the callee into x9 (it may itself contain
    // calls that clobber x0..x7), then load the argument registers back.
    {
        std::string fpVar;
        int ck = callCalleeKind(c, fpVar);
        if (ck != 0) {
            if (c->args.size() > 8) {
                cerr << "arm64: indirect call has more than 8 arguments "
                        "(not supported yet)\n";
                return X0;
            }
            size_t argsBytes = (c->args.size() * 8 + 15) & ~size_t(15);
            subSp((int)argsBytes);
            tempBytes += (int)argsBytes;
            for (size_t i = 0; i < c->args.size(); i++) {
                emitExpr(c->args[i].get());
                strX(X0, XSP, (uint32_t)(i * 8));
            }
            if (ck == 1) emitLoadVar(X9, fpVar);
            else { emitExpr(c->receiver.get()); mov(X9, X0); }
            for (size_t i = 0; i < c->args.size(); i++) ldrX((int)i, XSP, (uint32_t)(i * 8));
            addSp((int)argsBytes);
            tempBytes -= (int)argsBytes;
            hasCalls = true;
            u32(0xD63F0120u);            // blr x9
            return X0;
        }
    }
    if (funcOffsets.count(c->name)) {
        if (c->args.size() > 8) {
            cerr << "arm64: call '" << c->name << "' has more than 8 arguments "
                    "(not supported yet)\n";
            return X0;
        }
        // evaluate all args into 8-byte stack slots, then load into x0..x7
        size_t argsBytes = (c->args.size() * 8 + 15) & ~size_t(15);
        subSp((int)argsBytes);
        tempBytes += (int)argsBytes;
        for (size_t i = 0; i < c->args.size(); i++) {
            emitExpr(c->args[i].get());
            strX(X0, XSP, (uint32_t)(i * 8));
        }
        for (size_t i = 0; i < c->args.size(); i++) ldrX((int)i, XSP, (uint32_t)(i * 8));
        addSp((int)argsBytes);
        tempBytes -= (int)argsBytes;
        hasCalls = true;
        bl_fixup(c->name);
        return X0;
    }
    // An unresolved call used to warn and then evaluate to 0, so a typo in a
    // function name produced a binary that ran and quietly did the wrong
    // thing. resolveFixups() reports the same condition as an error on the
    // other backends; make it one here too.
    throw std::runtime_error("call to undefined function: '" + c->name + "'");
}

// abs / min / max / clamp — pure integer helpers shared by every AArch64
// target, so 'app android' and 'app arm64' cannot drift apart on them.
bool A64::tryBuiltinMath(CallExpr* c) {
    const string& n = c->name;
    if (n == "abs") {
        emitExpr(c->args[0].get());
        u32(neg_reg(X1, X0));
        cmpImm(X0, 0);
        int skip = newLabel();
        b_cc(10, skip);   // GE -> keep X0
        mov(X0, X1);
        emitLabel(skip);
        return true;
    }
    if (n == "min" || n == "max") {
        emitExpr(c->args[0].get());
        pushX0();                    // stack: a
        emitExpr(c->args[1].get());
        popX1();                     // X1 = a, X0 = b
        // "b <= a" is the same test as "a >= b" (GE, 0xA). Writing max the
        // other way round would need LE (0xC), which QEMU executes as GT.
        cmpReg(n == "min" ? X1 : X0, n == "min" ? X0 : X1);
        int skip = newLabel();
        b_cc(10, skip);              // a >= b (min) / b >= a (max) -> keep b
        mov(X0, X1);                 // X0 = a
        emitLabel(skip);
        return true;
    }
    if (n == "clamp") {
        emitExpr(c->args[0].get());
        pushX0();                    // stack: x
        emitExpr(c->args[1].get());
        popX1();                     // X1 = x, X0 = lo
        // "lo > x" is "x < lo", i.e. MI on (x - lo). A signed "x > lo" would
        // need GT (0xB), whose encoding QEMU evaluates as LT.
        cmpReg(X1, X0);              // cmp x, lo
        int s1 = newLabel();
        b_cc(4, s1);                 // MI -> x < lo -> keep lo
        mov(X0, X1);                 // X0 = x
        emitLabel(s1);
        pushX0();
        emitExpr(c->args[2].get());
        popX1();                     // X1 = clamped, X0 = hi
        // Likewise "hi < clamped" is MI on (hi - clamped).
        cmpReg(X0, X1);              // cmp hi, clamped
        int s2 = newLabel();
        b_cc(4, s2);                 // MI -> hi < clamped -> keep hi
        mov(X0, X1);                 // X0 = clamped
        emitLabel(s2);
        return true;
    }
    return false;
}

bool A64::tryBuiltin(CallExpr* c) {
    const string& n = c->name;

    // ftoi(x): float bits in X0 -> truncated int in X0.
    // itof(x): int in X0 -> float bits in X0.
    if (c->args.size() == 1 && n == "ftoi") {
        emitExpr(c->args[0].get());
        u32(encFmovSW(0, X0));
        u32(encFcvtzsWS(X0, 0));
        return true;
    }
    if (c->args.size() == 1 && n == "itof") {
        emitExpr(c->args[0].get());
        u32(encScvtfSW(0, X0));
        u32(encFmovWS(X0, 0));
        return true;
    }

    // =============================================================
    // 'app android' builtins. These shadow the PL011-based ones below,
    // which are meaningless without real hardware.
    // =============================================================
    if (android) {
        // print / println: a string, an int, or anything else -> decimal.
        // Unlike 'app arm64', print() does NOT append a newline (that matches
        // `app linux` and docs/07); use println() for the line break.
        if (n == "print" || n == "println" || n == "printLn") {
            // Exactly one value, the same rule the wasm and IR backends apply.
            // Taking args[0] and dropping the rest lost their side effects
            // without a word: println("wrote=", file_write(fd, buf, 16))
            // printed "wrote=" and never wrote the file. Falling through makes
            // the call an ordinary one, so it is reported instead of ignored.
            if (c->args.size() > 1) return false;
            if (c->args.empty()) return true;
            auto a = c->args[0].get();
            if (auto s = dynamic_cast<StringExpr*>(a)) {
                (void)s;
                emitExpr(a);
                bl_fixup("__z_puts");
            } else if (dynamic_cast<FloatExpr*>(a) || isFloatExpr(a)) {
                emitExpr(a);
                bl_fixup("__z_fnum");
            } else {
                emitExpr(a);
                bl_fixup("__z_num");
            }
            if (n != "print") {
                // __z_putc takes the character in x0, and x0 currently holds
                // whatever the value printer left behind.
                loadConst(X0, '\n');
                bl_fixup("__z_putc");
            }
            hasCalls = true;
            return true;
        }
        if (n == "sleep" || n == "delay_ms") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            bl_fixup("__z_sleep");
            hasCalls = true;
            return true;
        }
        if (n == "exit" || n == "exit_process" || n == "halt") {
            // halt() takes no argument and always reports success, which
            // matches the `app linux` behaviour.
            if (c->args.empty()) movzImm(X0, 0);
            else emitExpr(c->args[0].get());
            bl_fixup("__z_exit");
            hasCalls = true;
            return true;
        }
        if (n == "alloc" || n == "memNew") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 1);
            // Round the request up to a whole number of pages: mmap needs a
            // non-zero length and the kernel allocates in pages anyway.
            loadConst(X1, 4095);
            addReg(X0, X0, X1);
            u32(movn(X1, 0xFFF, 0));           // X1 = ~0xFFF
            andReg(X0, X0, X1);
            movzImm(X1, 0);
            cmpReg(X0, X1);
            int Lok = newLabel();
            b_cc(1, Lok);                      // NE -> length is usable as is
            movzImm(X0, 4096);                 // 0 rounds to 0: mmap rejects it
            emitLabel(Lok);
            bl_fixup("__z_alloc");
            hasCalls = true;
            return true;
        }
        if (n == "free" || n == "memDel") {
            // Android has no free(); release the mapping back. alloc() records
            // the rounded length in a header below the pointer, so free() needs
            // nothing but the pointer itself.
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_free");
            hasCalls = true;
            return true;
        }
        // CLOCK_MONOTONIC has no frequency, so the raw counter is
        // nanoseconds. Scale it down to match the bare-metal units, where
        // micros()/millis() read a 1 MHz counter. loadConst is required here:
        // movzImm only encodes 16 bits, so 1000000 would arrive truncated.
        if (n == "micros") {
            bl_fixup("__z_time_ns");
            loadConst(X1, 1000);
            sdivR(X0, X0, X1);
            hasCalls = true;
            return true;
        }
        if (n == "millis") {
            bl_fixup("__z_time_ns");
            loadConst(X1, 1000000);
            sdivR(X0, X0, X1);
            hasCalls = true;
            return true;
        }
        if (n == "rdtsc") { bl_fixup("__z_time_ns"); hasCalls = true; return true; }
        if (n == "getpid") { u32(movz(X0, 0, 0)); svcSys(SYS_NR_GETPID); return true; }
        if (n == "argc") { bl_fixup("__z_argc"); hasCalls = true; return true; }
        // File and memory-file access. The buffers are raw pointers, exactly
        // like alloc() hands back, so pass what alloc() or memfd_create()
        // returned. Paths are NUL-terminated byte pointers; a string literal
        // is one, a `string` variable is one too.
        //   file_open(path, flags)  -> fd        openat(AT_FDCWD, ...)
        //   file_read(fd, buf, len) -> n         read(2)
        //   file_write(fd, buf, len) -> n        write(2)
        //   file_pread(fd, buf, len, off) -> n   pread64(2), no seek
        //   file_close(fd)          -> 1         close(2), 1 on success
        //   file_size(path)         -> bytes     statx(2)
        //   random_bytes(buf, len)  -> n         getrandom(2)
        //   memfd_create(name)      -> fd        memfd_create(2)
        // A failing call returns 0, so test the result against 0.
        if (n == "file_open") {
            if (c->args.size() < 2) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: path
            emitExpr(c->args[1].get());
            popX1();                     // X1 = path, X0 = flags
            mov(X9, X0);                 // keep flags
            mov(X0, X1);                 // X0 = path
            mov(X1, X9);                 // X1 = flags
            bl_fixup("__z_file_open");
            hasCalls = true;
            return true;
        }
        if (n == "file_read" || n == "file_write") {
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: fd
            emitExpr(c->args[1].get());
            pushX0();                    // stack: fd, buf
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = len
            popX1();                     // X1 = buf
            mov(X9, X1);                 // park buf
            popX1();                     // X1 = fd
            mov(X0, X1);                 // X0 = fd
            mov(X1, X9);                 // X1 = buf
            bl_fixup(n == "file_read" ? "__z_file_read" : "__z_file_write");
            hasCalls = true;
            return true;
        }
        if (n == "file_pread") {
            if (c->args.size() < 4) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: fd
            emitExpr(c->args[1].get());
            pushX0();                    // stack: fd, buf
            emitExpr(c->args[2].get());
            pushX0();                    // stack: fd, buf, len
            emitExpr(c->args[3].get());
            mov(X3, X0);                 // X3 = offset
            popX1();                     // X1 = len
            mov(X2, X1);                 // X2 = len
            popX1();                     // X1 = buf
            mov(X9, X1);                 // park buf
            popX1();                     // X1 = fd
            mov(X0, X1);                 // X0 = fd
            mov(X1, X9);                 // X1 = buf
            bl_fixup("__z_file_pread");
            hasCalls = true;
            return true;
        }
        if (n == "file_close") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_file_close");
            hasCalls = true;
            return true;
        }
        if (n == "file_size") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_file_size");
            hasCalls = true;
            return true;
        }
        if (n == "random_bytes") {
            if (c->args.size() < 2) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: buf
            emitExpr(c->args[1].get());
            mov(X9, X0);                 // X9 = len
            popX1();                     // X1 = buf, X0 = len
            mov(X0, X1);                 // X0 = buf
            mov(X1, X9);                 // X1 = len
            bl_fixup("__z_random_bytes");
            hasCalls = true;
            return true;
        }
        if (n == "memfd_create") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_memfd_create");
            hasCalls = true;
            return true;
        }
        // ---- raw memory primitives ----
        // mem_copy(dst, src, len)  mem_set(ptr, byte, len)  mem_cmp(a, b, len)
        // All three take the same shape, so they share one marshalling block.
        // They work on bytes; the length is a byte count, not an int count.
        if (n == "mem_copy" || n == "mem_set" || n == "mem_cmp") {
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: a
            emitExpr(c->args[1].get());
            pushX0();                    // stack: a, b
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = len
            popX1();                     // X1 = b
            mov(X9, X1);                 // park b
            popX1();                     // X1 = a
            mov(X0, X1);                 // X0 = a
            mov(X1, X9);                 // X1 = b
            bl_fixup(n == "mem_copy" ? "__z_mem_copy"
                   : n == "mem_set"  ? "__z_mem_set" : "__z_mem_cmp");
            hasCalls = true;
            return true;
        }
        // ---- raw address-space control ----
        // mmap(len, prot, flags) / munmap(addr, len) / madvise(addr, len, how).
        // alloc() is the friendly wrapper; these expose the syscall itself so a
        // program can ask for a specific protection or release a mapping that
        // alloc() never handed out.
        if (n == "mmap") {                 // mmap(len, prot, flags) -> address
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: len
            emitExpr(c->args[1].get());
            pushX0();                    // stack: len, prot
            emitExpr(c->args[2].get());
            mov(X3, X0);                 // X3 = flags
            popX1();
            mov(X9, X1);                 // park prot
            popX1();
            mov(X0, XZR);                // X0 = addr, NULL -> kernel picks
            mov(X1, X2);                 // X1 = len
            mov(X2, X9);                 // X2 = prot
            bl_fixup("__z_mmap");
            hasCalls = true;
            return true;
        }
        if (n == "munmap") {              // munmap(addr, len) -> 1 on success
            if (c->args.size() < 2) return true;
            emitExpr(c->args[0].get());
            pushX0();
            emitExpr(c->args[1].get());
            mov(X9, X0);                 // park len
            popX1();                     // X1 = addr
            mov(X0, X1);                 // X0 = addr
            mov(X1, X9);                 // X1 = len
            bl_fixup("__z_munmap");
            hasCalls = true;
            return true;
        }
        if (n == "madvise") {             // madvise(addr, len, how) -> 1 ok
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();
            emitExpr(c->args[1].get());
            pushX0();
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = how
            popX1();
            mov(X9, X1);                 // park len
            popX1();
            mov(X0, X1);                 // X0 = addr
            mov(X1, X9);                 // X1 = len
            bl_fixup("__z_madvise");
            hasCalls = true;
            return true;
        }
        // ---- more file operations ----
        if (n == "file_lseek") {         // file_lseek(fd, off, whence)
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();
            emitExpr(c->args[1].get());
            pushX0();
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = whence
            popX1();
            mov(X9, X1);                 // park offset
            popX1();
            mov(X0, X1);                 // X0 = fd
            mov(X1, X9);                 // X1 = offset
            bl_fixup("__z_file_lseek");
            hasCalls = true;
            return true;
        }
        if (n == "file_pwrite") {        // file_pwrite(fd, buf, len, off)
            if (c->args.size() < 4) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: fd
            emitExpr(c->args[1].get());
            pushX0();                    // stack: fd, buf
            emitExpr(c->args[2].get());
            pushX0();                    // stack: fd, buf, len
            emitExpr(c->args[3].get());
            mov(X3, X0);                 // X3 = offset
            popX1();                     // X1 = len
            mov(X2, X1);                 // X2 = len
            popX1();                     // X1 = buf
            mov(X9, X1);                 // park buf
            popX1();                     // X1 = fd
            mov(X0, X1);                 // X0 = fd
            mov(X1, X9);                 // X1 = buf
            bl_fixup("__z_file_pwrite");
            hasCalls = true;
            return true;
        }
        if (n == "file_truncate" || n == "file_rename" || n == "file_mkdir" ||
            n == "file_unlink" || n == "file_fsync" || n == "file_fstat_size") {
            int want = (n == "file_truncate" || n == "file_rename" ||
                        n == "file_mkdir") ? 2 : 1;
            if ((int)c->args.size() < want) return true;
            emitExpr(c->args[0].get());
            if (want == 2) {
                // Evaluating the second argument may clobber any register, X0
                // included, so the first one is parked in X9. The second is
                // never pushed: it is already in X0 when the first argument
                // finishes evaluating, and pushing it would only leave a
                // second copy of the *first* value on the stack to pop.
                mov(X9, X0);             // X9 = first
                emitExpr(c->args[1].get());
                mov(X1, X0);             // X1 = second
                mov(X0, X9);             // X0 = first
            }
            bl_fixup(n == "file_truncate"    ? "__z_file_truncate"
                   : n == "file_rename"     ? "__z_file_rename"
                   : n == "file_mkdir"      ? "__z_file_mkdir"
                   : n == "file_unlink"     ? "__z_file_unlink"
                   : n == "file_fsync"      ? "__z_file_fsync"
                                            : "__z_file_fstat_size");
            hasCalls = true;
            return true;
        }
        // ---- process and system information ----
        if (n == "getuid" || n == "geteuid" || n == "getgid" ||
            n == "sys_sched_yield" || n == "sys_page_size") {
            if (n == "sys_page_size") {
                // No syscall for this: the AArch64 (and every 4K-page ARM64
                // Android device) page size is a fixed part of the ABI.
                movzImm(X0, 4096);
                return true;
            }
            bl_fixup(n == "getuid"           ? "__z_getuid"
                   : n == "geteuid"          ? "__z_geteuid"
                   : n == "getgid"           ? "__z_getgid"
                                            : "__z_sched_yield");
            hasCalls = true;
            return true;
        }
        if (n == "sys_exit_group") {      // sys_exit_group(code) -- never returns
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_exit_group");
            hasCalls = true;
            return true;
        }
        // sys_uname_field(buf, len, which): copies one utsname field into the
        // caller's buffer, NUL-terminated, and returns its length.
        if (n == "sys_uname_field") {
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: buf
            emitExpr(c->args[1].get());
            pushX0();                    // stack: buf, len
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = which
            popX1();
            mov(X9, X1);                 // park len
            popX1();
            mov(X0, X1);                 // X0 = buf
            mov(X1, X9);                 // X1 = len
            bl_fixup("__z_uname_field");
            hasCalls = true;
            return true;
        }
        // arg_get(i, buf, len) and env_get(name, buf, len): copy a NUL-
        // terminated string into the caller's buffer, return its length.
        if (n == "arg_get" || n == "env_get") {
            if (c->args.size() < 3) return true;
            emitExpr(c->args[0].get());
            pushX0();                    // stack: key
            emitExpr(c->args[1].get());
            pushX0();                    // stack: key, buf
            emitExpr(c->args[2].get());
            mov(X2, X0);                 // X2 = len
            popX1();
            mov(X9, X1);                 // park buf
            popX1();
            mov(X0, X1);                 // X0 = key
            mov(X1, X9);                 // X1 = buf
            bl_fixup(n == "arg_get" ? "__z_arg_get" : "__z_env_get");
            hasCalls = true;
            return true;
        }
        if (n == "abs" || n == "min" || n == "max" || n == "clamp")
            return tryBuiltinMath(c);
        if (n == "delay_us") {
            if (!c->args.empty()) emitExpr(c->args[0].get());
            else movzImm(X0, 0);
            bl_fixup("__z_delay_us");
            hasCalls = true;
            return true;
        }
    }

    if (n == "print") {
        if (c->args.empty()) return true;
        auto a = c->args[0].get();
        if (auto s = dynamic_cast<StringExpr*>(a)) {
            (void)s;
            emitExpr(a);
            bl_fixup("uart_puts");
        } else if (dynamic_cast<FloatExpr*>(a) || isFloatExpr(a)) {
            emitExpr(a);
            bl_fixup("uart_fnum");
        } else {
            emitExpr(a);
            bl_fixup("uart_num");
        }
        loadConst(X0, '\n');
        bl_fixup("uart_putc");
        hasCalls = true;
        return true;
    }
    if (n == "delay_ms") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_delay");
        hasCalls = true;
        return true;
    }
    if (n == "abs" || n == "min" || n == "max" || n == "clamp") return tryBuiltinMath(c);
    if (n == "str_len") {
        if (c->args.empty()) return true;
        emitExpr(c->args[0].get());  // X0 = string addr
        mov(X1, X0);                 // X1 = cursor
        int L = newLabel(), done = newLabel();
        emitLabel(L);
        ldrbW(X2, X1, 0);
        cbzR(X2, done);
        addImm(X1, X1, 1);
        b_imm(L);
        emitLabel(done);
        subReg(X0, X1, X0);          // X0 = length
        return true;
    }
    if (n == "gpio_init") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_init");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_set" || n == "gpio_clear") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup(n == "gpio_set" ? "__z_gpio_set" : "__z_gpio_clear");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_toggle") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_toggle");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_read") {
        if (!c->args.empty()) emitExpr(c->args[0].get());
        bl_fixup("__z_gpio_read");
        hasCalls = true;
        return true;
    }
    if (n == "gpio_write") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());      // X0 = value
        pushX0();
        emitExpr(c->args[0].get());      // X0 = pin
        popX1();                         // X1 = value
        bl_fixup("__z_gpio_write");
        hasCalls = true;
        return true;
    }
    if (n == "led_on" || n == "led_off") {
        loadConst(X0, n == "led_on" ? 1 : 0);
        bl_fixup("__z_led_set");
        hasCalls = true;
        return true;
    }
    if (n == "led_toggle") {
        bl_fixup("__z_led_toggle");
        hasCalls = true;
        return true;
    }
    if (n == "uart_init") {
        // First arg is the pin; PL011 is fixed to GPIO14/15, so take baud only.
        if (c->args.size() > 1) emitExpr(c->args[1].get());
        else loadConst(X0, 115200);
        bl_fixup("__z_uart_init");
        hasCalls = true;
        return true;
    }
    if (n == "uart_write") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());      // X0 = byte
        bl_fixup("uart_putc");
        hasCalls = true;
        return true;
    }
    if (n == "uart_read") {
        bl_fixup("__z_uart_getc");       // X0 = -1 if nothing received
        hasCalls = true;
        return true;
    }
    if (n == "uart_print" || n == "uart_println") {
        if (c->args.size() < 2) return true;
        auto a = c->args[1].get();
        if (auto s = dynamic_cast<StringExpr*>(a)) {
            string txt = s->value;
            if (n == "uart_println") txt += "\r\n";
            emitStrAddr(X0, stringIdx(txt));
        } else {
            emitExpr(a);
        }
        bl_fixup("uart_puts");
        hasCalls = true;
        return true;
    }
    if (n == "uart_print_int") {
        if (c->args.size() < 2) return true;
        emitExpr(c->args[1].get());
        bl_fixup("uart_num");
        hasCalls = true;
        return true;
    }
    if (n == "delay_us") {
        if (c->args.empty()) return true;
        emitExpr(c->args[0].get());
        bl_fixup("__z_delay_us");
        hasCalls = true;
        return true;
    }
    if (n == "micros") {
        bl_fixup("__z_micros");
        hasCalls = true;
        return true;
    }
    if (n == "millis") {
        bl_fixup("__z_millis");
        hasCalls = true;
        return true;
    }
    return false;
}

// =========================================================================
// Conditional jumps
// =========================================================================
int A64::emitCondJump(Expr* c, int label, bool wantTrue) {
    int64_t cv;
    if (getIntConst(c, cv)) {
        if ((cv != 0) == wantTrue) b_imm(label);
        return 0;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(c)) {
        const string& op = b->op;
        if (op == "&&") {
            if (wantTrue) {
                int skip = newLabel();
                emitCondJump(b->left.get(), skip, false);
                emitCondJump(b->right.get(), label, true);
                emitLabel(skip);
            } else {
                emitCondJump(b->left.get(), label, false);
                emitCondJump(b->right.get(), label, false);
            }
            return 0;
        }
        if (op == "||") {
            if (wantTrue) {
                emitCondJump(b->left.get(), label, true);
                emitCondJump(b->right.get(), label, true);
            } else {
                int skip = newLabel();
                emitCondJump(b->left.get(), skip, true);
                emitCondJump(b->right.get(), label, false);
                emitLabel(skip);
            }
            return 0;
        }
        int cc = ccForOp(op);
        if (cc >= 0 && !isFloatExpr(b)) {
            emitExpr(b->left.get());
            pushX0();
            emitExpr(b->right.get());
            popX1();                  // X1 = left, X0 = right
            cmpReg(X1, X0);
            if (!wantTrue) cc = invCc(cc);
            b_cc(cc, label);
            return 0;
        }
    }
    emitExpr(c);
    if (wantTrue) cbnzR(X0, label);
    else cbzR(X0, label);
    return 0;
}

// =========================================================================
// Per-function state / frame allocation
// =========================================================================
void A64::resetFn() {
    code.clear();
    labelPositions.clear();
    branches.clear();
    callFixups.clear();
    addrFixups.clear();
    strFixups.clear();
    vars.clear();
    nextLabel = 0;
    swCur = 0;
    swTempOff = 0;
    tempBytes = 0;
    frameSize = 0;
    retLabel = -1;
}

static int stmtSwitchCount(Stmt* s) {
    int c = 0;
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        c = 1;
        for (auto& cs : sw->cases) for (auto& x : cs.body.stmts) c += stmtSwitchCount(x.get());
        return c;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        for (auto& x : ifs->thenBlock.stmts) c += stmtSwitchCount(x.get());
        for (auto& x : ifs->elseBlock.stmts) c += stmtSwitchCount(x.get());
        return c;
    }
    if (auto ws = dynamic_cast<WhileStmt*>(s)) { for (auto& x : ws->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    if (auto ls = dynamic_cast<LoopStmt*>(s)) { for (auto& x : ls->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    if (auto fs = dynamic_cast<ForStmt*>(s)) { for (auto& x : fs->body.stmts) c += stmtSwitchCount(x.get()); return c; }
    return c;
}

void A64::allocVarSlots(FunctionDecl* f) {
    struct LiveVar {
        string name;
        int size = 4;
        int first = 0;
        int last = 0;
        int slot = 0;
        bool used = false;
        bool isParam = false;
        int arraySize = 0;
        Type type;
    };
    unordered_map<string, LiveVar> live;
    for (auto& p : f->params) {
        LiveVar lv; lv.name = p.name; lv.first = 0; lv.last = 0;
        lv.isParam = true; lv.type = p.type;
        lv.size = typeSize(p.type);
        live[p.name] = lv;
    }

    int stmtIdx = 0;
    int curStmt = 0;
    auto touch = [&](const string& name) {
        auto it = live.find(name);
        if (it == live.end()) return;
        it->second.used = true;
        if (curStmt > it->second.last) it->second.last = curStmt;
    };
    std::function<void(Expr*)> touchExpr = [&](Expr* e) {
        if (!e) return;
        if (auto id = dynamic_cast<IdentExpr*>(e)) { touch(id->name); return; }
        if (auto aof = dynamic_cast<AddressOfExpr*>(e)) {
            // `&x` keeps x alive through its name; `&arr[i]`/`&o.f` through
            // the target expression (whose root Ident is touched below).
            if (aof->target) touchExpr(aof->target.get());
            else touch(aof->name);
            return;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(e)) { touchExpr(b->left.get()); touchExpr(b->right.get()); return; }
        if (auto u = dynamic_cast<UnaryExpr*>(e)) { touchExpr(u->operand.get()); return; }
        if (auto m = dynamic_cast<MemberExpr*>(e)) { touchExpr(m->object.get()); return; }
        if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) { touchExpr(a->array.get()); touchExpr(a->index.get()); return; }
        if (auto d = dynamic_cast<DerefExpr*>(e)) { touchExpr(d->ptr.get()); return; }
        if (auto c = dynamic_cast<CallExpr*>(e)) {
            touchExpr(c->receiver.get());
            for (auto& a : c->args) touchExpr(a.get());
            return;
        }
    };
    auto touchStmt = [&](Stmt* s) {
        if (auto v = dynamic_cast<VarDecl*>(s)) { touchExpr(v->init.get()); return; }
        if (auto r = dynamic_cast<ReturnStmt*>(s)) { touchExpr(r->value.get()); return; }
        if (auto es = dynamic_cast<ExprStmt*>(s)) { touchExpr(es->expr.get()); return; }
        if (auto a = dynamic_cast<AssignStmt*>(s)) {
            touch(a->name);
            touchExpr(a->indexExpr.get());
            touchExpr(a->value.get());
            return;
        }
        if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) { touchExpr(pa->ptr.get()); touchExpr(pa->value.get()); return; }
        if (auto ifs = dynamic_cast<IfStmt*>(s)) { touchExpr(ifs->condition.get()); return; }
        if (auto ws = dynamic_cast<WhileStmt*>(s)) { touchExpr(ws->condition.get()); return; }
        if (auto fs = dynamic_cast<ForStmt*>(s)) {
            touchExpr(fs->start.get()); touchExpr(fs->end.get()); touchExpr(fs->step.get());
            return;
        }
        if (auto sw = dynamic_cast<SwitchStmt*>(s)) { touchExpr(sw->condition.get()); return; }
    };

    std::function<void(Stmt*)> walk = [&](Stmt* s) {
        curStmt = stmtIdx++;
        auto declare = [&](const string& name, int size, const Type& t, int arrSize = 0) {
            LiveVar lv; lv.name = name; lv.size = size;
            lv.first = curStmt; lv.last = curStmt; lv.type = t;
            lv.arraySize = arrSize;
            live[name] = lv;
        };
        if (auto v = dynamic_cast<VarDecl*>(s)) {
            int sz = v->arraySize > 0 ? v->arraySize * elementSize(v->type) : elementSize(v->type);
            if (sz < 4) sz = 4;
            // LP64 slots are accessed a full register wide on Android.
            if (android && sz < 8) sz = 8;
            declare(v->name, sz, v->type, v->arraySize);
        } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
            declare(fs->varName, 4, Type(TypeKind::Int));
        }
        touchStmt(s);
        if (auto ifs = dynamic_cast<IfStmt*>(s)) {
            for (auto& x : ifs->thenBlock.stmts) walk(x.get());
            for (auto& x : ifs->elseBlock.stmts) walk(x.get());
        } else if (auto ws = dynamic_cast<WhileStmt*>(s)) {
            for (auto& x : ws->body.stmts) walk(x.get());
        } else if (auto ls = dynamic_cast<LoopStmt*>(s)) {
            for (auto& x : ls->body.stmts) walk(x.get());
        } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
            for (auto& x : fs->body.stmts) walk(x.get());
        } else if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
            for (auto& cs : sw->cases) if (cs.condition) touchExpr(cs.condition.get());
            for (auto& cs : sw->cases) for (auto& x : cs.body.stmts) walk(x.get());
        }
    };
    for (auto& s : f->body.stmts) walk(s.get());

    vector<LiveVar*> locals;
    for (auto& kv : live) if (!kv.second.isParam) locals.push_back(&kv.second);
    sort(locals.begin(), locals.end(),
         [](const LiveVar* a, const LiveVar* b) { return a->first < b->first; });
    int off = 0;
    for (auto* lv : locals) {
        off = (off + 7) & ~7;
        lv->slot = off;
        off += (lv->size + 7) & ~7;
    }
    for (auto* lv : locals) {
        off = max(off, lv->slot + lv->size);
        VarInfo32 vi; vi.off = lv->slot; vi.type = lv->type;
        vi.isParam = false; vi.used = lv->used; vi.size = lv->size;
        vi.arraySize = lv->arraySize;
        vars[lv->name] = vi;
    }
    int swCount = 0;
    for (auto& s : f->body.stmts) swCount += stmtSwitchCount(s.get());
    swTempOff = off;
    int localsBytes = off + swCount * swTempStride();

    // parameters get their own frame slots (only when used)
    for (int k = 0; k < (int)f->params.size(); k++) {
        auto it = live.find(f->params[k].name);
        if (it == live.end() || !it->second.used) continue;
        localsBytes = (localsBytes + 7) & ~7;
        VarInfo32 vi; vi.off = localsBytes; vi.type = f->params[k].type;
        vi.isParam = true; vi.used = true; vi.size = typeSize(f->params[k].type);
        vars[f->params[k].name] = vi;
        localsBytes += (vi.size + 7) & ~7;
    }

    frameSize = (localsBytes + 8 + 15) & ~15;   // +8 for saved LR, 16-align
}

// =========================================================================
// Global init / startup
// =========================================================================
void A64::emitGlobalInit() {
    for (auto& g : prog.globals) {
        auto gi = global(g->name);
        if (!gi || !g->init) continue;
        int64_t cv;
        if (getIntConst(g->init.get(), cv)) {
            loadConst(X0, (uint64_t)(int64_t)cv);
        } else {
            emitExpr(g->init.get());
        }
        storeGlobal(X0, gi->off, gi->size);
    }
}

void A64::emitStartup() {
    resetFn();
    // X19 = page of data section, then + low 12 bits (patched after layout)
    startupAdrpPos = (int)code.size();
    u32(adrp(X19, 0));
    startupAddPos = (int)code.size();
    u32(add_imm(X19, X19, 0));

    if (android) {
        // The kernel already gave us a stack: SP points at argc, and the auxv
        // sits above the environment. Keep it — it is the only memory we are
        // guaranteed to own, and stashing argc costs one register.
        ldrX(X20, XSP, 0);              // X20 = argc
        argcSaved = true;
        // ADD X21, SP, #0 copies the stack pointer: mov_reg() cannot, because
        // it always encodes XZR as the source operand, and there SP would be
        // read as the zero register.
        addSpAddr(X21, 0);              // X21 = the kernel's stack, i.e. argv
        spSaved = true;
        emitGlobalInit();
        if (mixCtx && mixCtx->hasAny) bl_fixup("$mixcrt0");
        if (!entryName.empty()) bl_fixup(entryName);
        // main()'s return value becomes the process exit status, so a
        // `return 1` in main really does exit 1.
        svcSys(SYS_NR_EXIT_GROUP);
        u32(b_imm_raw(0));              // unreachable guard: b .
        resolveBranches("__z_startup");
        return;
    }

    // SP = top of RAM minus a margin (below the 0x3F000000 RPi peripherals;
    //     safe for both 512MB and 1GB Raspberry Pi boards).
    // MOVZ X31 would write XZR, so load into X0 then MOV SP, X0.
    loadConst(X0, stackTop);
    u32(add_imm(XSP, X0, 0));   // MOV SP, X0  (ADD SP, X0, #0)
    emitGlobalInit();
    // C/C++ mixing: run the merged C constructors (if any) before z's entry.
    if (mixCtx && mixCtx->hasAny) bl_fixup("$mixcrt0");
    if (!entryName.empty()) bl_fixup(entryName);
    u32(b_imm_raw(0));   // spin: b .
    resolveBranches("__z_startup");
}

// =========================================================================
// Runtime support helpers (UART on QEMU virt PL011)
// =========================================================================
// x0 = raw f32 bits -> print [-]digits.dddddd through putsFn; the caller
// appends the newline, exactly like __z_num/uart_num. f32 has no exact
// decimal form, so the value is scaled to micro-units in f64 (one rounding)
// and printed with six fractional digits -- the shape the other Zenith
// targets print. A magnitude that does not fit in an fcvtzs saturates; an
// approximate number beats garbage digits.
void A64::emitFloatPrintBody(const string& putsFn) {
    int Lneg = newLabel(), Lnonneg = newLabel(), Lscale = newLabel();
    int Lfrac = newLabel(), Lint = newLabel(), Ldone = newLabel();
    subSp(96);
    strX(X30, XSP, 80);                  // save LR across the puts call
    u32(encFmovSW(0, X0));               // s0 = the f32 bits
    loadConst(X10, 0);
    u32(encFmovDX(1, X10));              // d1 = 0.0
    loadConst(X10, 0x412E848000000000ull);   // 1e6
    u32(encFmovDX(2, X10));
    loadConst(X10, 0x3FE0000000000000ull);   // 0.5
    u32(encFmovDX(3, X10));
    u32(encFcvtDs(0, 0));                // d0 = (double) the f32
    u32(encFcmpDx(0, 1));                // against 0.0
    b_cc(4, Lneg);                       // MI -> negative
    b_imm(Lnonneg);
    emitLabel(Lneg);
    u32(encFnegDx(0, 0));
    movzImm(X9, 1);                      // the sign flag
    b_imm(Lscale);
    emitLabel(Lnonneg);
    movzImm(X9, 0);
    emitLabel(Lscale);
    u32(encFmulDx(0, 0, 2));             // micro units, all in f64: the
    u32(encFaddDx(0, 0, 3));             // + 0.5, so it rounds
    u32(encFcvtzsDX(10, 0));             // x10 = micro units
    loadConst(X11, 1000000);
    udivR(X3, X10, X11);                 // x3 = whole part
    msubR(X4, X3, X11, X10);             // x4 = fraction
    addSpAddr(X6, 48);                   // the text ends at sp+48
    movzImm(X8, 0);
    strbW(X8, X6, 0);                    // NUL at the end: __z_puts scans
    movzImm(X11, 6);
    emitLabel(Lfrac);                    // six zero-padded digits
    movzImm(X12, 10);
    udivR(X7, X4, X12);
    msubR(X5, X7, X12, X4);              // x5 = the digit
    addImm(X5, X5, 48);
    mov(X4, X7);                         // the next value is the quotient
    subImm(X6, X6, 1);
    strbW(X5, X6, 0);
    subImm(X11, X11, 1);
    cbnzR(X11, Lfrac);
    movzImm(X7, (uint32_t)'.');
    subImm(X6, X6, 1);
    strbW(X7, X6, 0);
    emitLabel(Lint);                     // the whole part, one digit minimum
    movzImm(X10, 10);
    udivR(X7, X3, X10);
    msubR(X5, X7, X10, X3);
    addImm(X5, X5, 48);
    subImm(X6, X6, 1);
    strbW(X5, X6, 0);
    mov(X3, X7);
    cbnzR(X3, Lint);
    cbzR(X9, Ldone);
    movzImm(X7, (uint32_t)'-');
    subImm(X6, X6, 1);
    strbW(X7, X6, 0);
    emitLabel(Ldone);
    // Laid down backwards: the cursor is the start, and the byte written at
    // sp+48 before the digits is the terminator -- so x0 holds a complete
    // C string for __z_puts/uart_puts (which scan for the NUL themselves).
    mov(X0, X6);
    bl_fixup(putsFn);
    ldrX(X30, XSP, 80);
    addSp(96);
    ret();
}

void A64::emitRuntime(const string& name) {
    resetFn();


    // =============================================================
    // 'app android': everything below is a raw Linux/AArch64 syscall.
    // No Bionic, no PL011 — stdout is fd 1 and the kernel does the rest.
    // =============================================================
    if (android) {
        if (name == "__z_puts") {
            // x0 = NUL-terminated string -> write(1, buf, strlen(buf))
            subSp(32);
            strX(X0, XSP, 0);                 // keep buf across the scan
            mov(X1, X0);                      // X1 = cursor
            movzImm(X2, 0);                   // X2 = length
            int Lloop = newLabel(), Ldone = newLabel();
            emitLabel(Lloop);
            ldrbW(X3, X1, 0);
            cbzR(X3, Ldone);
            addImm(X1, X1, 1);
            addImm(X2, X2, 1);
            b_imm(Lloop);
            emitLabel(Ldone);
            ldrX(X1, XSP, 0);                 // X1 = buf
            movzImm(X0, 1);                   // X0 = STDOUT_FILENO
            sysWrite();                       // X2 already holds the length
            addSp(32);
            ret();
        } else if (name == "__z_putc") {
            // x0 = char -> write(1, &ch, 1)
            subSp(16);
            strbW(X0, XSP, 0);
            movzImm(X0, 1);
            addSpAddr(X1, 0);                 // X1 = &ch
            movzImm(X2, 1);
            sysWrite();
            addSp(16);
            ret();
        } else if (name == "__z_num") {
            // x0 = signed int -> decimal digits (caller decides the newline)
            int Ldigits = newLabel(), Lskipminus = newLabel(), Lloop = newLabel();
            subSp(64);
            strX(X30, XSP, 0);                // save LR (we call __z_puts)
            addSpAddr(X1, 8);
            addImm(X1, X1, 24);               // cursor starts at buf+24
            mov(X2, X1);
            movzImm(X8, 0);
            strbW(X8, X2, 0);                 // NUL terminator
            mov(X3, X0);                      // X3 = n
            movzImm(X4, 0);                   // X4 = minus flag
            cmpImm(X3, 0);
            b_cc(10, Ldigits);                // n >= 0
            // Magnitude as |n| = -(n+1)+1. A plain negReg() cannot be used:
            // -INT64_MIN is still INT64_MIN, and the loop below then divided a
            // negative value, so the remainder came out negative and adding
            // '0' produced characters below '0' instead of digits.
            addImm(X3, X3, 1);
            negReg(X3, X3);
            addImm(X3, X3, 1);
            movzImm(X4, 1);
            emitLabel(Ldigits);
            emitLabel(Lloop);
            movzImm(X10, 10);
            udivR(X5, X3, X10);               // unsigned: for -2^63 the
            msubR(X6, X5, X10, X3);           // magnitude has the top bit set
            addImm(X6, X6, 48);               // + '0'
            subImm(X2, X2, 1);
            strbW(X6, X2, 0);
            mov(X3, X5);
            cbnzR(X3, Lloop);
            cmpImm(X4, 1);
            b_cc(1, Lskipminus);              // NE -> not negative
            subImm(X2, X2, 1);
            u32(movz(X6, '-', 0));
            strbW(X6, X2, 0);
            emitLabel(Lskipminus);
            mov(X0, X2);
            bl_fixup("__z_puts");
            ldrX(X30, XSP, 0);
            addSp(64);
            ret();
        } else if (name == "__z_fnum") {
            emitFloatPrintBody("__z_puts");
        } else if (name == "__z_exit") {
            // x0 = status -> exit_group(status); never returns
            svcSys(SYS_NR_EXIT_GROUP);
            ret();
        } else if (name == "__z_sleep") {
            // x0 = milliseconds -> convert to ns, then use the shared body
            loadConst(X1, 1000000ull);
            mulR(X0, X0, X1);
            emitAndroidSleep();
        } else if (name == "__z_delay_us") {
            // x0 = microseconds -> convert to ns, then use the shared body
            loadConst(X1, 1000ull);
            mulR(X0, X0, X1);
            emitAndroidSleep();
        } else if (name == "__z_alloc") {
            // x0 = size. Round the request up to a whole page, mmap it, and
            // stash the rounded length in a 16-byte header just below the
            // pointer we hand back, so free() knows how much to unmap.
            // mmap() returns page-aligned memory, so base+16 is still 16-byte
            // aligned -- the strongest alignment AArch64 wants of any scalar.
            // The mapping is zero filled, so this doubles as the calloc()
            // path. Returns 0 when the kernel refuses.
            subSp(16);
            strX(X0, XSP, 0);                    // remember the request
            ldrX(X9, XSP, 0);                    // X9 = requested size
            movzImm(X10, 0);
            cmpReg(X9, X10);
            int Lnonzero = newLabel();
            b_cc(1, Lnonzero);                   // NE -> size was non-zero
            loadConst(X9, 4096);                 // else give it one page
            emitLabel(Lnonzero);
            loadConst(X10, 4095);
            addReg(X9, X9, X10);                // X9 = size + 4095
            u32(movn(X11, 0xFFF, 0));            // X11 = ~0xFFF (page mask)
            andReg(X9, X9, X11);                // X9 = size rounded to a page
            movzImm(X0, 0);                      // addr = NULL -> kernel picks
            mov(X1, X9);
            movzImm(X2, PROT_READ | PROT_WRITE);
            movzImm(X3, MAP_PRIVATE | MAP_ANONYMOUS);
            u32(movn(X4, 0, 0));                  // X4 = -1 (no fd)
            movzImm(X5, 0);                      // offset = 0
            svcSys(SYS_NR_MMAP);
            // Kernel errors are -errno, i.e. in [-4095, -1]; read as unsigned
            // 64-bit those all sit just under 2^64, far above any real user
            // address. So "below -4095" is exactly the success test. (ARM cond
            // field: 3 = LO/CC, 14 = AL, 1 = NE.)
            loadConst(X1, (uint64_t)(int64_t)-4095);
            cmpReg(X0, X1);
            int Lok = newLabel();
            b_cc(3, Lok);                         // LO -> looks like an address
            movzImm(X0, 0);                       // else report failure
            int Ldone = newLabel();
            b_cc(14, Ldone);                      // AL -> always taken
            emitLabel(Lok);
            strX(X9, X0, 0);                      // [base] = rounded length
            loadConst(X1, 16);
            addReg(X0, X0, X1);                   // hand back base + 16
            emitLabel(Ldone);
            addSp(16);
            ret();
        } else if (name == "__z_free") {
            // x0 = pointer handed out by alloc(); the rounded length sits in
            // the 16-byte header right below it. 0 on success.
            subSp(16);
            strX(X0, XSP, 0);
            ldrX(X0, XSP, 0);
            u32(movn(X1, 15, 0));                 // X1 = -16
            addReg(X0, X0, X1);                   // X0 = base
            ldrX(X1, X0, 0);                      // X1 = rounded length
            svcSys(SYS_NR_MUNMAP);
            movzImm(X0, 0);
            addSp(16);
            ret();
        } else if (name == "__z_time_ns") {
            // clock_gettime(CLOCK_MONOTONIC, &ts) -> nanoseconds in x0.
            // AArch64 Linux takes clk_id in x0 and the timespec in x1.
            subSp(16);
            movzImm(X0, CLOCK_MONOTONIC_);
            addSpAddr(X1, 0);
            svcSys(SYS_NR_CLOCK_GETTIME);
            ldrX(X0, XSP, 0);                 // tv_sec
            ldrX(X1, XSP, 8);                 // tv_nsec
            loadConst(X2, 1000000000ull);
            mulR(X0, X0, X2);
            addReg(X0, X0, X1);
            addSp(16);
            ret();
        } else if (name == "__z_argc") {
            mov(X0, X20);
            ret();
        } else if (name == "__z_file_open") {
            // x0 = path, x1 = flags -> openat(AT_FDCWD, path, flags, 0666).
            // AArch64 Linux has no plain open(2); AT_FDCWD makes openat(2) the
            // equivalent. X9/X10 only carry values *into* the syscall, so the
            // kernel never sees them twice.
            mov(X9, X0);                          // path
            mov(X10, X1);                         // flags
            loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
            mov(X1, X9);
            mov(X2, X10);
            movzImm(X3, 0666);                    // rw for owner and group
            svcSys(SYS_NR_OPENAT);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_read" || name == "__z_file_write") {
            // x0 = fd, x1 = buf, x2 = len -> read(2) / write(2). The Zenith
            // argument order already matches the kernel's.
            svcSys(name == "__z_file_read" ? SYS_NR_READ : SYS_NR_WRITE);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_pread") {
            // x0 = fd, x1 = buf, x2 = len, x3 = offset -> pread64(2).
            // Reading by offset needs no seek, so one thread can pull several
            // ranges out of the same file.
            svcSys(SYS_NR_PREAD64);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_close") {
            // x0 = fd -> close(2), 1 on success / 0 on error.
            svcSys(SYS_NR_CLOSE);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_random_bytes") {
            // x0 = buf, x1 = len -> getrandom(2), no flags.
            // Android has had this since API 28, so it covers 11/12/13.
            // Unlike /dev/urandom there is no file descriptor to open and no
            // path to get wrong.
            movzImm(X2, 0);
            svcSys(SYS_NR_GETRANDOM);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_memfd_create") {
            // x0 = name -> memfd_create(2), MFD_CLOEXEC so the fd cannot leak
            // into a child process. The result is a normal fd: file_write,
            // file_pread and file_close all work on it, which makes it a
            // scratch buffer that never touches the filesystem.
            // Android has had this since API 30.
            movzImm(X1, MFD_CLOEXEC);
            svcSys(SYS_NR_MEMFD_CREATE);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_size") {
            // x0 = path -> size in bytes, 0 if the file cannot be stat'ed.
            // statx(2) landed in Android at API 30, which is where 11/12/13
            // all sit, so the plain size query needs no legacy fallback.
            // The 256-byte struct statx lives on our own frame: the kernel
            // writes into caller memory and we have nowhere else to put it.
            subSp(272);
            movzImm(X1, 0);
            strX(X1, XSP, 0);                     // clear stx_mask,
            strX(X1, XSP, 8);                     // stx_attributes,
            strX(X1, XSP, 16);                    // stx_nlink/uid/gid,
            strX(X1, XSP, 24);                    // stx_mode,
            strX(X1, XSP, 32);                    // stx_ino
            strX(X1, XSP, STATX_STX_SIZE_OFF);    // and stx_size
            mov(X9, X0);                          // path
            loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
            mov(X1, X9);
            movzImm(X2, 0);                       // flags
            loadConst(X3, STATX_SIZE);            // ask only for the size
            addSpAddr(X4, 0);                     // struct statx on our frame
            svcSys(SYS_NR_STATX);
            loadConst(X1, (uint64_t)(int64_t)-4095);
            cmpReg(X0, X1);
            int Lok = newLabel(), Lzero = newLabel(), Ldone = newLabel();
            b_cc(3, Lok);                         // LO -> not an -errno
            movzImm(X0, 0);
            b_imm(Ldone);
            emitLabel(Lok);
            addSpAddr(X1, 0);
            ldrX(X2, X1, 0);                      // stx_mask
            ldrX(X0, X1, STATX_STX_SIZE_OFF);     // stx_size
            loadConst(X3, STATX_SIZE);
            andReg(X2, X2, X3);                   // did the kernel fill it in?
            cbzR(X2, Lzero);
            b_imm(Ldone);
            emitLabel(Lzero);
            movzImm(X0, 0);                       // no size available
            emitLabel(Ldone);
            addSp(272);
            ret();
        } else if (name == "__z_mem_copy") {
            // x0 = dst, x1 = src, x2 = len -> copies len bytes, returns len.
            // memmove semantics: overlapping regions have to be walked in the
            // direction that cannot clobber a byte we have not read yet. Plain
            // user addresses are all below 2^63, so signed compares are safe.
            int Lwork = newLabel(), Lfwd = newLabel(), Ldone = newLabel();
            int Lback = newLabel();
            int Lfloop = newLabel(), Lfstep = newLabel();
            // A negative count must be rejected, not just tested for
            // non-zero: the countdown below only stops on exactly 0, so a
            // negative length would decrement forever.
            int Lbad = newLabel();
            cmpImm(X2, 0);
            b_cc(4, Lbad);              // MI -> negative
            b_cc(0, Lbad);              // EQ -> nothing copied
            mov(X6, X2);                // keep the count for the return value
            cmpReg(X0, X1);             // dst vs src
            b_cc(3, Lfwd);              // LO -> dst < src, forward is safe
            addReg(X3, X0, X2);          // X3 = dst + len
            addReg(X4, X1, X2);          // X4 = src + len
            // The copy is tested *after* the step, otherwise the last step
            // writes one byte below dst: with X3 == dst a GE test is still
            // true and the loop would run len+1 times.
            emitLabel(Lback);
            subImm(X3, X3, 1);
            subImm(X4, X4, 1);
            ldrbW(X5, X4, 0);
            strbW(X5, X3, 0);
            cmpReg(X3, X0);
            b_cc(8, Lback);             // HI -> X3 still above dst
            b_imm(Ldone);
            emitLabel(Lfwd);
            mov(X7, X2);
            emitLabel(Lfloop);
            cmpReg(X7, XZR);
            b_cc(1, Lfstep);            // NE -> bytes left
            b_imm(Ldone);
            emitLabel(Lfstep);
            ldrbW(X5, X1, 0);
            strbW(X5, X0, 0);
            addImm(X0, X0, 1);
            addImm(X1, X1, 1);
            subImm(X7, X7, 1);
            b_imm(Lfloop);
            emitLabel(Ldone);
            mov(X0, X6);
            ret();
            emitLabel(Lbad);
            movzImm(X0, 0);
            ret();
        } else if (name == "__z_mem_set") {
            // x0 = ptr, x1 = byte value, x2 = len -> fills len bytes.
            int Lwork = newLabel(), Ldone = newLabel();
            int Lloop = newLabel(), Lstep = newLabel();
            int Lbad = newLabel();
            cmpImm(X2, 0);
            b_cc(4, Lbad);              // MI -> negative
            b_cc(0, Lbad);              // EQ -> nothing filled
            mov(X6, X2);
            mov(X7, X2);
            emitLabel(Lloop);
            cmpReg(X7, XZR);
            b_cc(1, Lstep);
            b_imm(Ldone);
            emitLabel(Lstep);
            strbW(X1, X0, 0);          // only the low byte of X1 is stored
            addImm(X0, X0, 1);
            subImm(X7, X7, 1);
            b_imm(Lloop);
            emitLabel(Ldone);
            mov(X0, X6);
            ret();
            emitLabel(Lbad);
            movzImm(X0, 0);
            ret();
        } else if (name == "__z_mem_cmp") {
            // x0 = a, x1 = b, x2 = len -> 0 when equal, else the difference of
            // the first differing pair, so the sign matches memcmp(3).
            int Lwork = newLabel();
            int Lloop = newLabel(), Lstep = newLabel(), Ldiff = newLabel();
            int Lbad = newLabel();
            cmpImm(X2, 0);
            b_cc(4, Lbad);              // MI -> negative
            b_cc(0, Lbad);              // EQ -> equal by definition
            mov(X7, X2);
            emitLabel(Lloop);
            cmpReg(X7, XZR);
            b_cc(1, Lstep);
            movzImm(X0, 0);             // ran off the end -> equal
            ret();
            emitLabel(Lstep);
            ldrbW(X4, X0, 0);
            ldrbW(X5, X1, 0);
            cmpReg(X4, X5);
            b_cc(1, Ldiff);
            addImm(X0, X0, 1);
            addImm(X1, X1, 1);
            subImm(X7, X7, 1);
            b_imm(Lloop);
            emitLabel(Ldiff);
            subReg(X0, X4, X5);
            ret();
            emitLabel(Lbad);
            movzImm(X0, 0);
            ret();
        } else if (name == "__z_file_lseek") {
            // x0 = fd, x1 = offset, x2 = whence -> new offset, 0 on error.
            // A real offset is never negative, so clampSysErr() fits here.
            svcSys(SYS_NR_LSEEK);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_pwrite") {
            // x0 = fd, x1 = buf, x2 = len, x3 = offset -> bytes written.
            svcSys(SYS_NR_PWRITE64);
            A64::clampSysErr();
            ret();
        } else if (name == "__z_file_truncate") {
            // x0 = fd, x1 = length -> 1 on success. ftruncate reports 0, so
            // the "0 means error" convention has to be inverted again.
            svcSys(SYS_NR_FTRUNCATE);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_file_fsync") {
            // x0 = fd -> 1 on success, 0 on error.
            svcSys(SYS_NR_FSYNC);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_file_unlink") {
            // x0 = path -> 1 if the name was removed. unlinkat(2) with flags
            // 0 deletes a file; AT_REMOVEDIR would be needed for a directory.
            mov(X9, X0);
            loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
            mov(X1, X9);
            movzImm(X2, 0);
            svcSys(SYS_NR_UNLINKAT);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_file_rename") {
            // x0 = old path, x1 = new path -> 1 on success.
            mov(X9, X0);
            mov(X10, X1);
            loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
            mov(X1, X9);
            loadConst(X2, (uint64_t)(int64_t)AT_FDCWD);
            mov(X3, X10);
            svcSys(SYS_NR_RENAMEAT);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_file_mkdir") {
            // x0 = path, x1 = mode -> 1 on success.
            mov(X9, X0);
            mov(X10, X1);
            loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
            mov(X1, X9);
            mov(X2, X10);
            svcSys(SYS_NR_MKDIRAT);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_file_fstat_size") {
            // x0 = fd -> size in bytes, 0 if the fd cannot be sized.
            // SEEK_END on the descriptor gives the size with no struct stat
            // at all: fstat(2) would tie us to the per-ABI offset of st_size
            // and force a 128-byte frame for one field. The descriptor's own
            // offset is saved and put back, so the call is invisible to the
            // caller apart from its result.
            mov(X9, X0);                     // X9 = fd
            mov(X0, X9);                     // x0 = fd
            movzImm(X1, 0);                   // x1 = offset 0, "where am I?"
            movzImm(X2, 1);                   // x2 = SEEK_CUR
            svcSys(SYS_NR_LSEEK);            // X0 = current offset
            loadConst(X1, (uint64_t)(int64_t)-4095);
            cmpReg(X0, X1);
            int Lok = newLabel(), Ldone = newLabel(), Lsized = newLabel();
            b_cc(3, Lok);                     // LO -> not an -errno
            movzImm(X0, 0);
            b_imm(Ldone);
            emitLabel(Lok);
            mov(X10, X0);                    // X10 = saved offset
            mov(X0, X9);
            movzImm(X1, 0);
            movzImm(X2, 2);                   // SEEK_END
            svcSys(SYS_NR_LSEEK);            // X0 = size, or -errno
            // SEEK_END can fail on its own even when SEEK_CUR just succeeded:
            // the descriptor may have stopped being seekable, or the file may
            // have been replaced. The contract is "0 when the fd cannot be
            // sized", so an -errno must not reach the caller posing as a size
            // (a caller doing `if file_fstat_size(fd) > 0` would see -errno as a
            // huge positive after any widening). A failed lseek leaves the
            // offset where it was, so there is nothing to restore here.
            loadConst(X1, (uint64_t)(int64_t)-4095);
            cmpReg(X0, X1);
            b_cc(3, Lsized);                  // LO -> a real size
            movzImm(X0, 0);
            b_imm(Ldone);
            emitLabel(Lsized);
            mov(X11, X0);                    // X11 = size
            mov(X0, X9);                     // put the offset back
            mov(X1, X10);
            // SEEK_SET, not SEEK_CUR: X10 is the *absolute* saved position, so
            // seeking relative to the current one added the offset to itself
            // (a file at 128 came back at 256) and every later read/write on
            // that descriptor started from the wrong place.
            movzImm(X2, 0);                   // SEEK_SET
            svcSys(SYS_NR_LSEEK);            // best effort; X0 is discarded below
            mov(X0, X11);
            emitLabel(Ldone);
            ret();
        } else if (name == "__z_mmap") {
            // x0 = addr, x1 = len, x2 = prot, x3 = flags, x4 = fd, x5 = offset
            // -> mapping address. x4/x5 are argument registers the call site
            // never sets (mmap() here has no fd), so they are forced to 0: a
            // stale value there makes a MAP_ANONYMOUS mapping fail with EINVAL
            // when it lands in the offset slot.
            movzImm(X4, 0);                 // fd = 0
            movzImm(X5, 0);                 // offset = 0
            svcSys(SYS_NR_MMAP);
            clampSysErr();
            ret();
        } else if (name == "__z_munmap") {
            // x0 = addr, x1 = len -> 1 on success. munmap reports 0, so the
            // usual "0 means error" rule has to be inverted.
            svcSys(SYS_NR_MUNMAP);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_madvise") {
            // x0 = addr, x1 = len, x2 = how -> 1 on success.
            svcSys(SYS_NR_MADVISE);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_getuid") {
            svcSys(SYS_NR_GETUID);
            ret();
        } else if (name == "__z_geteuid") {
            svcSys(SYS_NR_GETEUID);
            ret();
        } else if (name == "__z_getgid") {
            svcSys(SYS_NR_GETGID);
            ret();
        } else if (name == "__z_sched_yield") {
            // Returns 0 on success, so invert to keep 0 meaning failure.
            svcSys(SYS_NR_SCHED_YIELD);
            A64::clampSysErrZeroOk();
            ret();
        } else if (name == "__z_exit_group") {
            // x0 = status -> exit_group(status); never returns.
            svcSys(SYS_NR_EXIT_GROUP);
            ret();
        } else if (name == "__z_uname_field") {
            // x0 = dst buffer, x1 = len, x2 = which (0..5 over utsname) ->
            // length copied, 0 on failure. The kernel wants a 390-byte
            // utsname, which is far too big to sit in a Zenith frame, so it
            // goes on our own frame and one field is copied out of it.
            subSp((UTS_BUF_BYTES + 15) & ~15u);
            // X1 and X2 are plain inputs here, not syscall arguments, and X0
            // becomes uname()'s return value, so park all three before the
            // svc or the caller's buffer pointer would be gone.
            mov(X9, X1);                     // X9 = len
            mov(X10, X2);                    // X10 = which
            mov(X11, X0);                    // X11 = caller's buffer
            // uname(2) takes a single pointer, in X0 -- there is no second
            // argument to set up. X0 doubles as the return value afterwards,
            // so the caller's buffer is parked in X11 first.
            addSpAddr(X0, 0);                 // X0 = &utsname on our frame
            svcSys(SYS_NR_UNAME);
            loadConst(X3, (uint64_t)(int64_t)-4095);
            cmpReg(X0, X3);
            int Lok = newLabel(), Lfail = newLabel(), Ldone = newLabel();
            int Lout = newLabel();
            b_cc(3, Lok);                     // LO -> not an -errno
            movzImm(X0, 0);
            b_imm(Ldone);
            emitLabel(Lout);
            movzImm(X0, 0);
            b_imm(Ldone);
            emitLabel(Lok);
            // Each utsname field is char[65], so the base is which * 65.
            // Anything outside 0..5 would read past the struct, so it is
            // rejected up front rather than clamped.
            loadConst(X3, 5);
            cmpReg(X10, X3);
            b_cc(8, Lout);              // HI -> which > 5
            cmpImm(X10, 0);
            b_cc(4, Lout);             // MI -> which < 0
            loadConst(X3, 65);
            mulR(X4, X10, X3);
            addSpAddr(X3, 0);
            addReg(X4, X4, X3);               // X4 = &utsname.field[which]
            emitCopyCstr(X11, X4, X9, Lfail);
            emitLabel(Ldone);
            addSp((UTS_BUF_BYTES + 15) & ~15u);
            ret();
        } else if (name == "__z_arg_get") {
            // x0 = index, x1 = dst, x2 = len -> length copied, 0 on failure.
            // X21 is the stack the kernel built: [argc][argv...][NULL][envp...],
            // so argv[i] lives at X21 + 8 + i*8.
            // The range test has to reject negatives separately: a signed
            // "index >= argc" is false for -1, which would then index argv
            // backwards off the front of the block and fault.
            cmpImm(X0, 0);
            int Lfail = newLabel();
            b_cc(4, Lfail);                  // MI -> negative index
            cmpReg(X0, X20);                 // index vs argc
            b_cc(10, Lfail);                 // GE -> out of range
            loadConst(X3, 8);
            mulR(X3, X0, X3);
            addReg(X3, X21, X3);
            addImm(X3, X3, 8);                // skip argc itself
            ldrX(X4, X3, 0);                 // X4 = argv[index]
            cbzR(X4, Lfail);
            emitCopyCstr(X1, X4, X2, Lfail);
            ret();
            emitLabel(Lfail);
            movzImm(X0, 0);
            ret();
        } else if (name == "__z_env_get") {
            // x0 = name, x1 = dst, x2 = len -> length of the value copied.
            // envp follows argv[] and its NULL: X21 + 16 + argc*8.
            loadConst(X3, 8);
            mulR(X3, X20, X3);
            addReg(X3, X21, X3);
            addImm(X3, X3, 16);
            mov(X11, X0);                    // X11 = name, survives the scan
            int Lscan = newLabel(), Lpfx = newLabel(), Lnext = newLabel();
            int Lfail = newLabel(), Lval = newLabel(), Lend = newLabel();
            emitLabel(Lscan);
            ldrX(X4, X3, 0);
            cbzR(X4, Lfail);                 // end of envp
            mov(X5, X11);                    // X5 = name cursor
            mov(X6, X4);                     // X6 = entry cursor
            emitLabel(Lpfx);
            ldrbW(X7, X5, 0);
            ldrbW(X8, X6, 0);
            // The end of the name has to be tested *before* the bytes are
            // compared. On a full match the name is exhausted while the entry
            // still has its '=' in front of us, so comparing first would see
            // 0 vs '=' , call it a mismatch and walk past the very entry
            // that was being looked for.
            cbzR(X7, Lend);                  // name exhausted
            cmpReg(X7, X8);
            b_cc(1, Lnext);                  // bytes differ -> not our variable
            addImm(X5, X5, 1);
            addImm(X6, X6, 1);
            b_imm(Lpfx);
            emitLabel(Lend);
            cmpImm(X8, '=');
            b_cc(0, Lval);                   // entry has "NAME=" -> value follows
            b_imm(Lnext);                    // entry is a strict prefix of name
            emitLabel(Lnext);
            addImm(X3, X3, 8);
            b_imm(Lscan);
            emitLabel(Lval);
            addImm(X4, X6, 1);               // X4 = just past the '='
            emitCopyCstr(X1, X4, X2, Lfail);
            ret();
            emitLabel(Lfail);
            movzImm(X0, 0);
            ret();
        } else {
            // A phone has no PL011/GPIO/SPI block behind fixed addresses, so
            // the bare-metal helpers have nothing to talk to. Say that plainly
            // instead of claiming the helper does not exist, which would read
            // like a compiler bug.
            static const char* kBoardPrefixes[] = {
                "__z_gpio_", "__z_led_", "__z_uart_", "__z_spi_",
                "__z_i2c_", "__z_pwm_", "__z_delay_spin_"
            };
            bool board = false;
            for (const char* pfx : kBoardPrefixes)
                if (name.compare(0, strlen(pfx), pfx) == 0) { board = true; break; }
            if (board)
                cerr << "android: warning: '" << name.substr(4)
                     << "' has no effect on Android (no board MMIO; "
                        "the only peripheral is the kernel, via svc)\n";
            else
                cerr << "android: unknown runtime helper '" << name << "'\n";
            movzImm(X0, 0);
            ret();
        }
    } else {

    if (name == "uart_putc") {
        // x0 = char. Wait for TX FIFO to drain, then write DR.
        loadConst(X1, uartBase);
        int Lwait = newLabel();
        emitLabel(Lwait);
        ldrW(X2, X1, PL011_FR);
        tbnzR(X2, 5, Lwait);          // loop while TXFF (bit 5) set
        strbW(X0, X1, PL011_DR);
        ret();
    } else if (name == "uart_puts") {
        // x0 = NUL-terminated string
        loadConst(X1, uartBase);
        int Lloop = newLabel(), Ldone = newLabel();
        emitLabel(Lloop);
        ldrbW(X2, X0, 0);
        cbzR(X2, Ldone);
        int Lwait = newLabel();
        emitLabel(Lwait);
        ldrW(X3, X1, PL011_FR);
        tbnzR(X3, 5, Lwait);
        strbW(X2, X1, PL011_DR);
        addImm(X0, X0, 1);
        b_imm(Lloop);
        emitLabel(Ldone);
        ret();
    } else if (name == "uart_num") {
        // x0 = signed int -> print decimal + (caller appends newline)
        int Ldigits = newLabel(), Lskipminus = newLabel(), Lloop = newLabel();
        subSp(64);
        strX(X30, XSP, 0);             // save LR (we call uart_puts below)
        addSpAddr(X1, 8);              // X1 = buf start
        addImm(X1, X1, 24);            // X1 = buf + 24 (end of digits area)
        mov(X2, X1);                   // X2 = cursor (moves left)
        u32(movz(X8, 0, 0));
        strbW(X8, X2, 0);              // NUL terminator at buf+24
        mov(X3, X0);                   // X3 = n
        u32(movz(X4, 0, 0));           // X4 = 0 -> minus flag (cleared)
        cmpImm(X3, 0);
        b_cc(10, Ldigits);             // n >= 0
        // |n| = -(n+1)+1, because -INT64_MIN overflows back onto itself.
        addImm(X3, X3, 1);
        negReg(X3, X3);
        addImm(X3, X3, 1);
        u32(movz(X4, 1, 0));           // X4 = 1 -> minus flag
        emitLabel(Ldigits);
        emitLabel(Lloop);
        u32(movz(X10, 10, 0));
        udivR(X5, X3, X10);            // quot, unsigned magnitude
        msubR(X6, X5, X10, X3);        // rem
        addImm(X6, X6, 48);            // '0'
        subImm(X2, X2, 1);
        strbW(X6, X2, 0);
        mov(X3, X5);
        cbnzR(X3, Lloop);
        // X4 == 1 if negative
        cmpImm(X4, 1);
        b_cc(1, Lskipminus);           // NE -> not negative
        subImm(X2, X2, 1);
        u32(movz(X6, '-', 0));
        strbW(X6, X2, 0);
        emitLabel(Lskipminus);
        mov(X0, X2);
        bl_fixup("uart_puts");
        ldrX(X30, XSP, 0);             // restore LR
        addSp(64);
        ret();
    } else if (name == "uart_fnum") {
        emitFloatPrintBody("uart_puts");
    } else if (name == "__z_delay") {
        // x0 = ms; approximate busy loop
        int Lout = newLabel(), Linner = newLabel(), Ldone = newLabel();
        cmpImm(X0, 0);
        // "ms <= 0" as EQ (0) plus MI (4). LE would be 0xC, which QEMU runs
        // as GT; 0xD (AL on AArch64) is not a comparison at all.
        b_cc(0, Ldone);                // EQ -> ms == 0
        b_cc(4, Ldone);                // MI -> ms < 0
        mov(X1, X0);                   // X1 = ms
        loadConst(X9, prog.arm64ClockHz / 1000);
        emitLabel(Lout);
        mov(X2, X9);
        emitLabel(Linner);
        subImm(X2, X2, 1);
        cbnzR(X2, Linner);
        subImm(X1, X1, 1);
        cbnzR(X1, Lout);
        emitLabel(Ldone);
        ret();
    } else if (name == "__z_gpio_init") {
        // X0 = pin. Clear that pin's GPFSEL field, set it to 001 (output).
        mov(X10, X0);                     // pin
        loadConst(X9, gpioBase);
        loadConst(X11, 10);
        sdivR(X12, X10, X11);             // pin/10 (GPFSEL index)
        loadConst(X11, 4);
        mulR(X12, X11, X12);              // bank*4
        addReg(X9, X9, X12);              // X9 = GPFSEL addr
        loadConst(X11, 10);
        sdivR(X12, X10, X11);             // pin/10
        msubR(X11, X12, X11, X10);        // rem = pin % 10
        loadConst(X12, 3);
        mulR(X11, X11, X12);              // shift = rem*3
        ldrW(X13, X9, 0);                 // read GPFSEL
        loadConst(X14, 7);
        lslR(X14, X14, X11);              // 7 << shift
        loadConst(X15, 0xFFFFFFFFu);
        eorReg(X14, X14, X15);            // ~(7 << shift)
        andReg(X13, X13, X14);            // clear the field
        loadConst(X14, 1);
        lslR(X14, X14, X11);              // 1 << shift
        orrReg(X13, X13, X14);            // set to output
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_gpio_set" || name == "__z_gpio_clear") {
        // X0 = pin. Write bit to GPSET (0x1C) or GPCLR (0x28), with bank.
        uint32_t off = (name == "__z_gpio_set") ? 0x1Cu : 0x28u;
        mov(X10, X0);
        loadConst(X9, gpioBase + off);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);              // pin >> 5
        loadConst(X12, 4);
        mulR(X11, X11, X12);              // bank*4
        addReg(X9, X9, X11);
        loadConst(X11, 31);
        andReg(X11, X10, X11);            // pin & 31
        loadConst(X12, 1);
        lslR(X12, X12, X11);              // bit
        strW(X12, X9, 0);
        ret();
    } else if (name == "__z_gpio_read") {
        // X0 = pin -> 0/1 from GPLEV.
        mov(X10, X0);
        loadConst(X9, gpioBase + 0x34);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);
        loadConst(X12, 4);
        mulR(X11, X11, X12);
        addReg(X9, X9, X11);              // GPLEV addr
        ldrW(X13, X9, 0);
        loadConst(X11, 31);
        andReg(X11, X10, X11);
        loadConst(X12, 1);
        lslR(X12, X12, X11);              // bit
        andReg(X13, X13, X12);            // 0 or bit
        cmpImm(X13, 0);
        csetR(X0, 1);                     // NE -> 1
        ret();
    } else if (name == "__z_gpio_toggle") {
        // Read GPLEV; if the bit reads 0 -> GPSET, else -> GPCLR.
        mov(X10, X0);
        loadConst(X9, gpioBase);
        loadConst(X11, 5);
        lsrR(X11, X10, X11);
        loadConst(X12, 4);
        mulR(X11, X11, X12);              // bank*4
        loadConst(X12, 31);
        andReg(X12, X10, X12);            // pin & 31
        loadConst(X13, 1);
        lslR(X13, X13, X12);              // bit
        mov(X14, X9);
        addReg(X14, X14, X11);
        loadConst(X15, 0x34);
        addReg(X14, X14, X15);            // GPLEV addr
        ldrW(X14, X14, 0);
        andReg(X14, X14, X13);            // 0 if currently low
        cmpImm(X14, 0);
        csetR(X12, 0);                    // 1 if low (EQ)
        loadConst(X14, 1);
        subReg(X12, X14, X12);            // 0 if low, 1 if high
        loadConst(X14, 0x0C);
        mulR(X12, X12, X14);              // 0 or 0x0C
        loadConst(X14, 0x1C);
        addReg(X12, X12, X14);            // 0x1C (set) or 0x28 (clear)
        addReg(X9, X9, X12);
        addReg(X9, X9, X11);
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_gpio_write") {
        // X0 = pin, X1 = value (any non-zero -> high).
        mov(X10, X0);
        mov(X11, X1);
        cmpImm(X11, 0);
        csetR(X11, 1);                    // 1 if val != 0
        loadConst(X12, 0x0C);
        mulR(X11, X11, X12);              // 0 or 0x0C
        loadConst(X12, 0x1C);
        addReg(X11, X11, X12);            // 0x1C (val!=0) or 0x28 (val==0)
        loadConst(X9, gpioBase);
        loadConst(X12, 5);
        lsrR(X12, X10, X12);              // pin >> 5
        loadConst(X13, 4);
        mulR(X12, X12, X13);              // bank*4
        loadConst(X13, 31);
        andReg(X13, X10, X13);            // pin & 31
        loadConst(X14, 1);
        lslR(X13, X13, X14);              // bit
        addReg(X9, X9, X11);
        addReg(X9, X9, X12);              // GPSET/GPCLR + bank
        strW(X13, X9, 0);
        ret();
    } else if (name == "__z_led_set" || name == "__z_led_toggle") {
        // Activity LED on led_gpio: configure as output, then write/toggle.
        subSp(16);
        strX(X30, XSP, 0);
        mov(X10, X0);                     // remember value for led_set
        loadConst(X0, ledGpio);
        bl_fixup("__z_gpio_init");
        if (name == "__z_led_set") {
            loadConst(X0, ledGpio);
            mov(X1, X10);
            bl_fixup("__z_gpio_write");
        } else {
            loadConst(X0, ledGpio);
            bl_fixup("__z_gpio_read");
            loadConst(X10, 1);
            eorReg(X0, X0, X10);          // flip
            mov(X1, X0);
            loadConst(X0, ledGpio);
            bl_fixup("__z_gpio_write");
        }
        ldrX(X30, XSP, 0);
        addSp(16);
        ret();
    } else if (name == "__z_uart_init") {
        // X0 = baud. GPIO 14/15 -> ALT0, then program the PL011 divisor
        // for a 48 MHz peripheral clock (standard Pi reference clock).
        mov(X11, X0);                     // baud
        loadConst(X9, gpioBase + 0x04);   // GPFSEL1
        ldrW(X12, X9, 0);
        loadConst(X13, 0x7F);
        loadConst(X14, 12);
        lslR(X13, X13, X14);              // 0x7F << 12 (pins 14..16: bits 12-18)
        loadConst(X14, 0xFFFFFFFFu);
        eorReg(X13, X13, X14);            // ~mask
        andReg(X12, X12, X13);
        loadConst(X13, 0x24000);          // 4<<12 | 4<<15 = ALT0
        orrReg(X12, X12, X13);
        strW(X12, X9, 0);
        // Disable the auxiliary mini-UART: GPIO14/15 default to its TXD/RXD,
        // and with the mux switched to the PL011 the mini-UART must not run.
        loadConst(X13, periphBase + 0x215000u);   // AUX_ENABLES
        loadConst(X12, 0);
        strW(X12, X13, 0);                // bit 0 = mini-UART off
        loadConst(X9, uartBase);
        loadConst(X12, 0);
        strW(X12, X9, PL011_CR);          // disable
        loadConst(X12, 16);
        mulR(X11, X11, X12);              // 16*baud
        loadConst(X12, 48000000);
        sdivR(X13, X12, X11);             // IBRD = clock/(16*baud)
        strW(X13, X9, PL011_IBRD);
        msubR(X13, X13, X11, X12);        // rem = clock - IBRD*16*baud
        loadConst(X14, 64);
        mulR(X13, X13, X14);              // rem*64
        sdivR(X13, X13, X11);             // FBRD
        strW(X13, X9, PL011_FBRD);
        loadConst(X12, 0x70);             // 8N1 + FIFO
        strW(X12, X9, PL011_LCRH);
        loadConst(X12, 0x301);            // UARTEN | TXE | RXE
        strW(X12, X9, PL011_CR);
        ret();
    } else if (name == "__z_uart_getc") {
        // X0 = -1 if RX FIFO empty, else the received byte.
        loadConst(X9, uartBase);
        int Lempty = newLabel();
        ldrW(X10, X9, PL011_FR);
        tbnzR(X10, 4, Lempty);            // RXFE (bit 4) -> empty
        ldrW(X0, X9, PL011_DR);
        ret();
        emitLabel(Lempty);
        loadConst(X0, 0xFFFFFFFFFFFFFFFFull);
        ret();
    } else if (name == "__z_micros") {
        // System timer CLO counts microseconds (1 MHz), 32-bit wrap.
        loadConst(X9, sysTimerBase);
        ldrW(X0, X9, 4);
        ret();
    } else if (name == "__z_millis") {
        loadConst(X9, sysTimerBase);
        ldrW(X0, X9, 4);
        loadConst(X10, 1000);
        sdivR(X0, X0, X10);
        ret();
    } else if (name == "__z_delay_us") {
        // X0 = us. Unsigned poll of CLO until it passes start + us.
        int Lbo = newLabel();
        loadConst(X9, sysTimerBase);
        mov(X10, X0);                     // us
        ldrW(X11, X9, 4);                 // start
        addReg(X12, X11, X10);            // end
        emitLabel(Lbo);
        ldrW(X11, X9, 4);                 // now
        cmpReg(X11, X12);
        b_cc(3, Lbo);                     // CC: now < end (unsigned)
        ret();
    } else {
        cerr << "arm64: unknown runtime '" << name << "'\n";
    }
    }   // end of the !android (PL011) helper chain
    resolveBranches(name);
    FnImg out;
    out.name = name;
    out.bytes = code;
    out.bls = callFixups;
    out.strFixes = strFixups;
    runtimeImgs.push_back(move(out));
}

// =========================================================================
// Whole-program layout + binary emit
// =========================================================================
bool A64::compile(const string& outputPath) {
    // --- peripheral mapping ---
    // "chip: virt" (or "qemu") selects the QEMU "virt" machine: PL011 at
    // 0x09000000, 128MB of RAM from 0x40000000 (kernel loaded at 0x40080000).
    // Everything else is a Raspberry Pi (BCM2835/2837 -> Pi1-P3, BCM2711 /
    // Cortex-A72 -> Pi4); the image is then loaded at 0x00080000.
    if (android) {
        // No board MMIO: the only "peripheral" is the kernel, reached through
        // svc. Keep the image base in step with the ELF load base so that any
        // absolute address baked in by the mix path stays inside the image.
        imageBase = elfBase;
    } else {
        const string& chip = prog.arm64Chip;
        bool virt = chip.find("virt") != string::npos ||
                    chip.find("qemu") != string::npos;
        if (virt) {
            periphBase   = 0x09000000u;
            gpioBase     = 0x09000000u;   // unused on virt
            uartBase     = 0x09000000u;   // PL011 (virt)
            sysTimerBase = 0x09004000u;   // virtual timer (informational)
            stackTop     = 0x47F00000u;   // top of 128MB RAM
            imageBase    = 0x40080000u;
        } else {
            bool pi4 = chip.find("bcm2711") != string::npos ||
                       chip.find("cortex-a72") != string::npos ||
                       chip.find("a72") != string::npos;
            periphBase   = pi4 ? 0xFE000000u : 0x3F000000u;
            gpioBase     = periphBase + 0x200000u;
            uartBase     = periphBase + 0x201000u;
            sysTimerBase = periphBase + 0x3000u;
            ledGpio      = pi4 ? 16 : 47;
            imageBase    = 0x00080000u;
        }
    }

    // --- struct layouts: 4 bytes per field, or LP64 with 8-byte alignment ---
    structs.clear();
    for (auto& sd : prog.structs) {
        int off = 0;
        unordered_map<string, pair<int, Type>> fields;
        for (auto& f : sd->fields) {
            if (android) off = alignUp(off, 8);
            fields[f.name] = {off, f.type};
            off += typeSize(f.type);
        }
        structs[sd->name] = {android ? alignUp(off, 8) : off, move(fields)};
    }

    // --- globals: offsets from data section start (known before codegen) ---
    globals.clear();
    globalOrder.clear();
    int gOff = 0;
    for (auto& g : prog.globals) {
        int sz = g->arraySize > 0 ? g->arraySize * scalarSize(g->type) : typeSize(g->type);
        if (sz < 4) sz = 4;
        // Every global is written a full register wide on Android, so round
        // short ones up rather than letting the store spill into the next slot.
        if (android && sz < 8) sz = 8;
        gOff = android ? alignUp(gOff, 8) : ((gOff + 7) & ~7);
        globals[g->name] = {gOff, sz, g->type, g->arraySize};
        globalOrder.push_back(g->name);
        gOff += sz;
    }
    int globalBytesTotal = gOff;

    // --- function presence map; entry = "main" or first function ---
    funcOffsets.clear();
    funcOrder.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        funcOffsets[f->name] = 0;
        funcOrder.push_back(f->name);
    }
    entryName = funcOffsets.count("main") ? "main"
              : (funcOrder.empty() ? "" : funcOrder[0]);

    // --- emit user functions ---
    userImgs.clear();
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        resetFn();
        allocVarSlots(f.get());
        subSp(frameSize);
        strX(X30, XSP, (uint32_t)frameSize - 8);
        for (int k = 0; k < (int)f->params.size(); k++) {
            auto v = var(f->params[k].name);
            if (!v) continue;
            if (v->size == 8 || android) strX(k, XSP, (uint32_t)v->off);
            else strW(k, XSP, (uint32_t)v->off);
        }
        retLabel = newLabel();
        emitBlock(f->body, nullptr, nullptr, nullptr);
        b_imm(retLabel);
        emitLabel(retLabel);
        ldrX(X30, XSP, (uint32_t)frameSize - 8);
        addSp(frameSize);
        ret();
        if (tempBytes != 0)
            cerr << "arm64: unbalanced stack in '" << f->name << "'\n";
        resolveBranches(f->name);
        FnImg out;
        out.name = f->name;
        out.bytes = code;
        out.bls = callFixups;
        out.adds = addrFixups;
        out.strFixes = strFixups;
        userImgs.push_back(move(out));
    }

    // --- emit runtime helpers referenced from user code (transitive) ---
    runtimeImgs.clear();
    unordered_set<string> emittedRt;
    vector<string> pendingRt;
    auto isRuntime = [](const string& t) {
        return t.compare(0, 4, "__z_") == 0 || t == "uart_puts" ||
               t == "uart_num" || t == "uart_putc" || t == "uart_fnum";
    };
    auto collectRt = [&](const FnImg& img) {
        for (auto& bl : img.bls)
            if (isRuntime(bl.target)) pendingRt.push_back(bl.target);
    };
    for (auto& img : userImgs) collectRt(img);
    for (size_t i = 0; i < pendingRt.size(); i++) {
        const string& n = pendingRt[i];
        if (emittedRt.count(n)) continue;
        emittedRt.insert(n);
        emitRuntime(n);
        collectRt(runtimeImgs.back());
    }

    // --- startup image ---
    emitStartup();
    vector<uint8_t> stBytes = code;
    vector<CallFix> stBls = callFixups;
    vector<AddrFix> stAdds = addrFixups;
    vector<StrFix> stStrFixes = strFixups;
    int stAdrp = startupAdrpPos;
    int stAdd = startupAddPos;

    // --- layout: startup | runtime | user | data ---
    size_t cursor = 0;
    size_t startupOff = cursor;
    cursor += stBytes.size();
    vector<size_t> rtOffsets;
    for (auto& img : runtimeImgs) {
        cursor = (cursor + 7u) & ~7u;
        rtOffsets.push_back(cursor);
        cursor += img.bytes.size();
    }
    vector<size_t> fnOffsets;
    for (auto& img : userImgs) {
        cursor = (cursor + 7u) & ~7u;
        fnOffsets.push_back(cursor);
        cursor += img.bytes.size();
    }

    // data section: globals (first) then strings.
    // For 'app android' the data region must start on a page boundary of its
    // own so the ELF can give code and data separate PT_LOAD segments (the
    // loader requires p_offset == p_vaddr (mod page size) for each). The zero
    // padding between the last instruction and the first global lives inside
    // the text segment, which is mapped read+execute and never written.
    size_t dataStart = android ? ((cursor + 0xFFFull) & ~0xFFFull)
                               : ((cursor + 7u) & ~7u);
    size_t p = dataStart + (size_t)globalBytesTotal;
    vector<uint32_t> strOfs(strings.size(), 0);
    for (size_t i = 0; i < strings.size(); i++) {
        p = (p + 3u) & ~3u;
        strOfs[i] = (uint32_t)p;
        p += strings[i].size() + 1;
    }
    size_t imageSize = (p + 15u) & ~15u;

    vector<uint8_t> img;
    img.assign(imageSize, 0);
    auto copyBlock = [&](size_t baseOff, const vector<uint8_t>& bytes) {
        for (size_t i = 0; i < bytes.size(); i++)
            img[baseOff + i] = bytes[i];
    };

    // resolve function addresses
    for (size_t i = 0; i < userImgs.size(); i++) funcOffsets[userImgs[i].name] = fnOffsets[i];
    for (size_t i = 0; i < runtimeImgs.size(); i++) funcOffsets[runtimeImgs[i].name] = rtOffsets[i];

    auto patchCalls = [&](size_t baseOff, const vector<CallFix>& bls) {
        for (auto& bl : bls) {
            auto it = funcOffsets.find(bl.target);
            if (it == funcOffsets.end()) continue;
            int64_t rel = (int64_t)it->second - (int64_t)(baseOff + (size_t)bl.pos);
            uint32_t imm26 = (uint32_t)(rel / 4);
            if (imm26 & 0x04000000u) imm26 |= 0xFC000000u;
            u32pat(img, (int)(baseOff + (size_t)bl.pos), bl_imm(imm26));
        }
    };
    auto patchAddrs = [&](size_t baseOff, const vector<AddrFix>& ads) {
        for (auto& ad : ads) {
            auto it = funcOffsets.find(ad.target);
            if (it == funcOffsets.end()) continue;
            int64_t rel = (int64_t)it->second - (int64_t)(baseOff + (size_t)ad.pos);
            u32pat(img, (int)(baseOff + (size_t)ad.pos), adr(ad.rt, (int32_t)rel));
        }
    };

    // --- assemble ---
    copyBlock(startupOff, stBytes);
    if (stAdrp >= 0) {
        int32_t rel = (int32_t)((((int64_t)dataStart & ~0xFFFll) - ((int64_t)(startupOff + stAdrp) & ~0xFFFll)) >> 12);
        u32pat(img, (int)(startupOff + (size_t)stAdrp), adrp(X19, rel));
    }
    if (stAdd >= 0) {
        uint16_t low = (uint16_t)(dataStart & 0xFFF);
        u32pat(img, (int)(startupOff + (size_t)stAdd), add_imm(X19, X19, low));
    }

    // ---- C/C++ mixing: merge C objects into the image tail ----
    if (mixCtx && mixCtx->hasAny) {
        // z function addresses (base-less image offsets) are the C-side
        // relocation base for C->z calls and data references.
        for (auto& fof : funcOffsets)
            mixCtx->zFuncRVAs[fof.first] = (uint64_t)fof.second;

        Codegen mixCg(prog);
        mixCg.mixCtx = this->mixCtx;
        std::unordered_map<std::string, uint64_t> mixFuncs;
        std::string mixErr;
        if (!mixCtx->flatMerge(mixCg, imageBase, img.size(), img, mixFuncs, mixErr)) {
            cerr << "arm64: mixing: " << mixErr << "\n";
            return false;
        }
        // register C functions + the ctor runner into funcOffsets so z->C
        // calls resolve through patchCalls.
        for (auto& fo : mixFuncs) funcOffsets[fo.first] = fo.second;
    }

    patchCalls(startupOff, stBls);
    patchAddrs(startupOff, stAdds);
    patchStrSlots(img, startupOff, dataStart, stStrFixes, strOfs);

    for (size_t i = 0; i < runtimeImgs.size(); i++) {
        copyBlock(rtOffsets[i], runtimeImgs[i].bytes);
        patchCalls(rtOffsets[i], runtimeImgs[i].bls);
        patchAddrs(rtOffsets[i], runtimeImgs[i].adds);
        patchStrSlots(img, rtOffsets[i], dataStart, runtimeImgs[i].strFixes, strOfs);
    }
    for (size_t i = 0; i < userImgs.size(); i++) {
        copyBlock(fnOffsets[i], userImgs[i].bytes);
        patchCalls(fnOffsets[i], userImgs[i].bls);
        patchAddrs(fnOffsets[i], userImgs[i].adds);
        patchStrSlots(img, fnOffsets[i], dataStart, userImgs[i].strFixes, strOfs);
    }

    // strings
    for (size_t i = 0; i < strings.size(); i++) {
        size_t off = strOfs[i];
        if (off + strings[i].size() >= imageSize) {
            cerr << "arm64: string pool overflow\n";
            return false;
        }
        copy(strings[i].begin(), strings[i].end(), img.begin() + off);
        img[off + strings[i].size()] = 0;
    }

    if (android) {
        if (!writeAndroidElf(outputPath, img, dataStart)) return false;
        cerr << "android: ELF64 AArch64 " << elfBase << ", api " << apiLevel
             << " (min " << minSdk << "), " << (img.size() - dataStart)
             << " bytes data, " << userImgs.size() << " function(s), "
             << strings.size() << " string(s), " << globals.size()
             << " global(s)\n";
        return true;
    }

    ofstream out(outputPath, ios::binary);
    if (!out) { cerr << "arm64: cannot open '" << outputPath << "'\n"; exit(1); }
    out.write((const char*)img.data(), (streamsize)img.size());
    out.close();
    if (!out) { cerr << "arm64: cannot write '" << outputPath << "'\n"; exit(1); }

    cerr << "arm64: image " << img.size() << " bytes, "
         << userImgs.size() << " function(s), "
         << strings.size() << " string(s), "
         << globals.size() << " global(s)\n";
    return true;
}

// =========================================================================
// 'app android': wrap the flat image in an ELF64 AArch64 executable
// =========================================================================
// File layout (everything page-aligned where the loader needs it):
//
//   0x0000  ELF header (64) + 4 program headers (56 each) = 288
//   0x0120  .note.android.ident   -> "Android\0" / "r<api>\0"
//   0x1000  text: startup + runtime helpers + user functions   (R+X)
//   0x1000 + <page-aligned>  data: globals + string pool     (R+W)
//
// There is no PT_INTERP and no DT_NEEDED: the kernel maps the two PT_LOADs and
// jumps straight to e_entry, so nothing from /system is required at run time.
// The load base is fixed (ET_EXEC), which is what Android's own `linker`
// expects for a non-PIE executable and what keeps every ADRP/ADD pair in the
// code valid without a relocation pass.
bool A64::writeAndroidElf(const string& outputPath, const vector<uint8_t>& img,
                          size_t dataStart) {
    // --- little-endian writers into a 64-byte scratch ---
    auto put8 = [](uint8_t* p, uint64_t v, int off, int n) {
        for (int i = 0; i < n; i++) p[off + i] = (uint8_t)((v >> (8 * i)) & 0xFF);
    };
    auto put16 = put8, put32 = put8, put64 = put8;

    const uint32_t kEHdrSize = 64, kPHdrSize = 56, kPHnum = 4;
    const uint32_t hdrSize = kEHdrSize + kPHnum * kPHdrSize;   // 288

    // .note.android.ident — the note Bionic's linker reads to learn which
    // platform an object was built against. Format: Elf64_Nhdr followed by the
    // name and the descriptor, both NUL-terminated and 4-byte aligned.
    string noteName = "Android";
    string noteDesc = "r" + to_string(apiLevel);   // "r30" == Android 11
    const uint32_t noteNameSz = (uint32_t)noteName.size() + 1;
    const uint32_t noteDescSz = (uint32_t)noteDesc.size() + 1;
    uint32_t noteSize = 12 + ((noteNameSz + 3) & ~3u) + ((noteDescSz + 3) & ~3u);
    const uint32_t kNTAndroidIdent = 1;

    const uint32_t noteOff = hdrSize;
    // The text segment starts page-aligned so that both PT_LOADs satisfy
    // p_offset == p_vaddr (mod 0x1000) and the mapping is accepted as-is.
    const uint64_t kPage = 0x1000;
    const uint64_t textSegOff = (noteOff + noteSize + kPage - 1) & ~(kPage - 1);
    const uint64_t dataSegOff = textSegOff + dataStart;
    const uint64_t dataLen = img.size() - dataStart;

    const uint32_t PF_X = 1, PF_W = 2, PF_R = 4;
    const uint32_t PT_LOAD = 1, PT_NOTE = 4, PT_GNU_STACK = 0x6474e551u;
    const uint16_t ET_EXEC = 2, EM_AARCH64 = 183, EV_CURRENT = 1;

    vector<uint8_t> out;
    out.assign((size_t)textSegOff, 0);
    out.insert(out.end(), img.begin(), img.end());

    uint8_t* e = out.data();
    uint8_t* ph = e + kEHdrSize;

    // ---- program headers ----
    auto writePhdr = [&](int i, uint32_t type, uint32_t flags, uint64_t off,
                        uint64_t vaddr, uint64_t filesz, uint64_t memsz,
                        uint64_t align) {
        uint8_t* p = ph + (size_t)i * kPHdrSize;
        put32(p, type, 0, 4);
        put32(p, flags, 4, 4);
        put64(p, off, 8, 8);
        put64(p, vaddr, 16, 8);
        put64(p, vaddr, 24, 8);       // p_paddr
        put64(p, filesz, 32, 8);
        put64(p, memsz, 40, 8);
        put64(p, align, 48, 8);
    };
    // 0: the API-level note
    writePhdr(0, PT_NOTE, PF_R, noteOff, elfBase + noteOff, noteSize, noteSize, 4);
    // 1: header + note + text, read+execute
    writePhdr(1, PT_LOAD, PF_R | PF_X, 0, elfBase, dataSegOff, dataSegOff, kPage);
    // 2: globals + strings, read+write
    writePhdr(2, PT_LOAD, PF_R | PF_W, dataSegOff, elfBase + dataSegOff,
              dataLen, dataLen, kPage);
    // 3: a non-executable stack. Android's loader refuses to run a process
    //    whose stack is executable, so state it explicitly.
    writePhdr(3, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0x10);

    // ---- the note itself ----
    {
        uint8_t* n = e + noteOff;
        put32(n, noteNameSz, 0, 4);
        put32(n, noteDescSz, 4, 4);
        put32(n, kNTAndroidIdent, 8, 4);
        memcpy(n + 12, noteName.c_str(), noteName.size() + 1);
        memcpy(n + 12 + ((noteNameSz + 3) & ~3u), noteDesc.c_str(), noteDesc.size() + 1);
    }

    // ---- ELF header ----
    memset(e, 0, kEHdrSize);
    e[0] = 0x7F; e[1] = 'E'; e[2] = 'L'; e[3] = 'F';
    e[4] = 2;                       // ELFCLASS64
    e[5] = 1;                       // ELFDATA2LSB (Android is always LE)
    e[6] = EV_CURRENT;
    e[7] = 0;                       // ELFOSABI_NONE — Android uses the generic
                                   // (Linux) ABI, so SYSV would be misleading
    put16(e, ET_EXEC, 16, 2);
    put16(e, EM_AARCH64, 18, 2);
    put32(e, EV_CURRENT, 20, 4);
    // e_entry: the startup code sits at image offset 0, which the text segment
    // places at file offset textSegOff — so the entry VA carries that offset.
    put64(e, elfBase + textSegOff, 24, 8);
    put64(e, kEHdrSize, 32, 8);     // e_phoff
    put64(e, 0, 40, 8);             // e_shoff — program headers only, like the
                                   // `app linux` writer: no section table
    put32(e, 0, 48, 4);             // e_flags
    put16(e, kEHdrSize, 52, 2);     // e_ehsize
    put16(e, kPHdrSize, 54, 2);     // e_phentsize
    put16(e, kPHnum, 56, 2);        // e_phnum
    put16(e, 64, 58, 2);            // e_shentsize
    put16(e, 0, 60, 2);             // e_shnum
    put16(e, 0, 62, 2);             // e_shstrndx

    ofstream f(outputPath, ios::binary);
    if (!f) { cerr << "android: cannot open '" << outputPath << "'\n"; exit(1); }
    f.write((const char*)out.data(), (streamsize)out.size());
    // Trailing marker, same convention as the ELF/PE writers: loaders ignore
    // trailing bytes, so this does not change how the file is executed.
    f.write((const char*)kZenithMagic, sizeof(kZenithMagic));
    f.close();
    if (!f) { cerr << "android: cannot write '" << outputPath << "'\n"; exit(1); }
    return true;
}

} // namespace

// =========================================================================
// Public entry point
// =========================================================================
bool Codegen::compileArm64(const std::string& outputPath) {
    A64 cg(prog);
    cg.mixCtx = this->mixCtx;
    return cg.compile(outputPath);
}

// Same encoders, ELF container instead of a flat image and raw syscalls
// instead of PL011 MMIO — this function is the entry point.
bool Codegen::compileAndroid(const std::string& outputPath) {
    A64 cg(prog);
    cg.mixCtx = this->mixCtx;
    cg.android = true;
    cg.apiLevel = prog.androidApiLevel;
    cg.minSdk = prog.androidMinSdk;
    cg.androidLabel = prog.androidLabel;
    // No chip/board MMIO on Android, so the Raspberry Pi defaults never apply.
    cg.elfBase = kLinuxLoadBase;
    return cg.compile(outputPath);
}
