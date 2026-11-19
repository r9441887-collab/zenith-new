#include "irasm_android.h"
#include "asm_a64.h"
#include "a64peephole.h"
#include "andropt.h"          // AndroidClamp: the contract with the pass
#include "codegen.h"          // kZenithMagic
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>

// ====================================================================
// IRAsmAndroid — "app android" through the assembler-IR
//
// The same IR as the bare-metal "app arm64" backend, aimed at a different
// machine: instead of a flat image for QEMU's virt board this produces an
// ELF64 AArch64 executable a phone can run, and instead of a PL011 the only
// output device is the kernel.
//
//   * the runtime is raw Linux/AArch64 syscalls (svc #0) — no Bionic, no
//     libc, nothing out of /system: the two PT_LOADs and e_entry are all the
//     loader needs;
//   * argc/argv/envp/auxv are read off the stack the kernel built, so
//     argc(), arg_get(), env_get() and the page size work with no startup
//     library;
//   * andropt has already turned the single-syscall helpers into
//     IROp::Syscall, so most runtime calls are one `svc #0` in the middle of
//     the code instead of a BL into a helper that does the same thing;
//   * print/println of a literal has become a single write(2) with a
//     compile-time length (see src/andropt.cpp).
//
// Register convention: x0..x7 arguments, x9/x10/x11 scratch, x19 data base,
// x20 argc, x21 the kernel's stack, v0..v7 f32 scratch, x30 LR. Every IR
// virtual register is an 8-byte frame slot at [SP + 8*v]; an f32 lives in the
// low 4 bytes of its slot, so int and float code share one frame layout.
//
// Image layout:
//   [startup][runtime helpers][user functions] | page boundary | [globals][strings]
// ====================================================================

namespace {

// ---- Linux/AArch64 syscall numbers (the asm-generic table) ----
enum : int {
    SYS_MKDIRAT = 34, SYS_UNLINKAT = 35, SYS_RENAMEAT = 38,
    SYS_OPENAT = 56, SYS_CLOSE = 57, SYS_LSEEK = 62, SYS_READ = 63,
    SYS_WRITE = 64, SYS_PREAD64 = 67, SYS_PWRITE64 = 68, SYS_FTRUNCATE = 46,
    SYS_FSYNC = 82, SYS_EXIT_GROUP = 94, SYS_CLOCK_GETTIME = 113,
    SYS_NANOSLEEP = 101, SYS_SCHED_YIELD = 124, SYS_UNAME = 160,
    SYS_GETUID = 174, SYS_GETEUID = 175, SYS_GETGID = 176, SYS_GETPID = 172,
    SYS_MUNMAP = 215, SYS_MMAP = 222, SYS_MADVISE = 233, SYS_GETRANDOM = 278,
    SYS_MEMFD_CREATE = 279, SYS_STATX = 291,
};

// One source of truth: andropt.cpp inlines these syscalls and this file
// writes the helper bodies, so a number that drifts apart between the two
// would silently turn an inlined call into the wrong syscall. The check runs
// once, when a helper body is built.
static int checkedSysNr(const char* helper, int bodyNr) {
    for (int i = 0; i < kAndroidSyscallCount; i++)
        if (std::strcmp(helper, kAndroidSyscalls[i].helper) == 0 &&
            kAndroidSyscalls[i].nr != bodyNr)
            throw std::runtime_error(std::string("android: syscall number mismatch for ") +
                                     helper + ": andropt " +
                                     std::to_string(kAndroidSyscalls[i].nr) +
                                     ", helper " + std::to_string(bodyNr));
    return bodyNr;
}

enum : int64_t {
    AT_FDCWD = -100,
    CLOCK_MONOTONIC_ = 1,
    PROT_READ_ = 1, PROT_WRITE_ = 2,
    MAP_PRIVATE_ = 2, MAP_ANONYMOUS_ = 0x20,
    MFD_CLOEXEC_ = 1,
    STATX_SIZE_ = 0x200,
    AT_PAGESZ_ = 6,             // the auxv entry that carries the page size
    UTS_BUF_BYTES = 390,        // sizeof(struct utsname) as Linux writes it
    UTS_FIELD = 65,             // every utsname field is char[65]
};
constexpr int STATX_STX_SIZE_OFF = 40;   // stx_size inside struct statx

// The page size the startup read out of the auxv is kept in the first 8 bytes
// of the data segment, ahead of the globals.
constexpr int PAGE_SIZE_WORD_OFF = 0;

constexpr uint64_t ELF_BASE = 0x400000ull;   // ET_EXEC load base (page aligned)

// --------------------------------------------------------------------
// A function body: raw code plus the fixups that need the final layout
// --------------------------------------------------------------------
struct DataFix {
    int pos = 0;        // offset of the ADRP (the ADD follows it)
    int rt = 0;
    bool isStr = false;
    int strIdx = -1;
    std::string name;   // a global, when isStr is false
};

struct FnImg {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<AsmBuf::Bl> bls;
    std::vector<DataFix> dfs;
};

// --------------------------------------------------------------------
// IR -> AArch64
//
// The same slot machine as the bare-metal backend, plus floats, plus the
// IROp::Syscall that andropt produces.
// --------------------------------------------------------------------
struct A64Fn {
    IRFunction& fn;
    const std::vector<IRAsmBlock>& asmBlocks;
    AsmBuf a;
    std::vector<DataFix> dfs;
    std::vector<int> pendingArgs;   // slot of each argument of the pending call
    int nparams;
    int frameAligned;
    int spAlloc;

    A64Fn(IRFunction& f, const std::vector<IRAsmBlock>& ab)
        : fn(f), asmBlocks(ab) {
        nparams = f.nparams;
        int maxSlot = f.maxSlot > 0 ? f.maxSlot : 1;
        frameAligned = ((8 * maxSlot) + 15) & ~15;
        spAlloc = frameAligned + 16;
        if (frameAligned / 8 > 4095)
            throw std::runtime_error("IR android: function frame too large");
    }

    // A label id is a slot in AsmBuf::labelPos, so it has to come from a
    // counter that advances on every request -- labelPos only grows when a
    // label is actually placed, so its size cannot name the next free id.
    int nLabels = 0;
    int newLabel() { return nLabels++; }

    // ---- address helpers ----
    void addrNew(int64_t off) {          // X9 = SP + off, no hidden state
        a.u32(encAdd(X9, XSP, 0));
        addUpTo(a, X9, off);
    }
    void addrOfPtr(int slotReg, int64_t off) {
        loadSlotTo(X9, slotReg, 0);
        addUpTo(a, X9, off);
    }
    void loadSlotTo(int rt, int slotReg, int64_t extra) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095)
            a.u32(encLdrX(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encLdrX(rt, X9, 0)); }
    }
    void storeSlotFrom(int slotReg, int64_t extra, int rt) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 7) == 0 && off / 8 <= 4095)
            a.u32(encStrX(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encStrX(rt, X9, 0)); }
    }
    // ADRP+ADD against the data base in x19: one pair of instructions, valid
    // wherever the loader put the segments, instead of a four-instruction
    // absolute MOVZ/MOVK of an address baked in at compile time.
    void dataAddrTo(int rt, bool isStr, int strIdx, const std::string& name) {
        int p = (int)a.c.size();
        a.u32(encAdrp(rt, 0, 0));
        a.u32(encAdd(rt, rt, 0));
        dfs.push_back({ p, rt, isStr, strIdx, name });
    }
    void loadOperandX(int rt, const IROperand& o) {
        if (o.kind == IROperand::Reg)      loadSlotTo(rt, o.reg, 0);
        else if (o.kind == IROperand::Imm) a.loadConst(rt, (uint64_t)o.imm);
        else throw std::runtime_error("IR android: bad operand in integer op");
    }
    void loadSlotF(int rt, int slotReg, int64_t extra) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095)
            a.u32(encLdrS(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encLdrS(rt, X9, 0)); }
    }
    void storeSlotF(int slotReg, int64_t extra, int rt) {
        int64_t off = (int64_t)slotReg * 8 + extra;
        if (off >= 0 && (off & 3) == 0 && off / 4 <= 4095)
            a.u32(encStrS(rt, XSP, (uint16_t)off));
        else { addrNew(off); a.u32(encStrS(rt, X9, 0)); }
    }
    // An FImm carries the raw f32 bits in a 64-bit immediate, so a constant
    // is one MOVZ/MOVK chain plus one FMOV.
    void loadOperandF(int rt, const IROperand& o) {
        if (o.kind == IROperand::Reg) { loadSlotF(rt, o.reg, 0); return; }
        if (o.kind == IROperand::FImm) {
            a.loadConst(X10, (uint64_t)(uint32_t)o.imm);
            a.u32(encFmovFromW(rt, X10));
            return;
        }
        throw std::runtime_error("IR android: bad operand in float op");
    }

    // ---- syscall result normalisation ----
    // Linux hands back -errno in x0 on failure; read as an unsigned 64-bit
    // value that sits in [-4095, -1], far above any user address, so "below
    // -4095" is exactly the success test.
    void clampErrToZero() {
        int Ldone = newLabel();
        a.loadConst(X1, (uint64_t)(int64_t)-4095);
        a.u32(encCmpReg(X0, X1));
        a.bcc(3, Ldone);                 // LO -> a real value
        a.u32(encMovz(X0, 0, 0));        // else -errno -> 0
        a.label(Ldone);
    }
    // Calls that answer 0 on success (close, ftruncate, munmap, ...) have to
    // be inverted, or a successful 0 would read as failure.
    void clampZeroOkToOne() {
        a.u32(encCmp(X0, 0));
        a.u32(encCset(X0, 0));           // 1 when x0 == 0
    }
    void applyClamp(int mode) {
        if (mode == kClampErrToZero) clampErrToZero();
        else if (mode == kClampZeroOkToOne) clampZeroOkToOne();
    }

    // ---- integer binary ops ----
    void emitBin(const IRInstr& in) {
        loadOperandX(X10, in.b);
        loadOperandX(X11, in.c);
        switch (in.op) {
        case IROp::Add:  a.u32(encAddReg(X10, X10, X11)); break;
        case IROp::Sub:  a.u32(encSubReg(X10, X10, X11)); break;
        case IROp::And:  a.u32(encAndReg(X10, X10, X11)); break;
        case IROp::Or:   a.u32(encOrrReg(X10, X10, X11)); break;
        case IROp::Xor:  a.u32(encEorReg(X10, X10, X11)); break;
        case IROp::Mul:  a.u32(encMul(X10, X10, X11)); break;
        case IROp::IDiv: a.u32(encSdiv(X10, X10, X11)); break;
        case IROp::UDiv: a.u32(encUdiv(X10, X10, X11)); break;
        case IROp::IMod: a.u32(encSdiv(X9, X10, X11)); a.u32(encMsub(X10, X9, X11, X10)); break;
        case IROp::UMod: a.u32(encUdiv(X9, X10, X11)); a.u32(encMsub(X10, X9, X11, X10)); break;
        case IROp::Shl:  a.u32(encLsl(X10, X10, X11)); break;
        case IROp::Shr:  a.u32(encLsr(X10, X10, X11)); break;
        case IROp::Sar:  a.u32(encAsr(X10, X10, X11)); break;
        default: throw std::runtime_error("IR android: bad binary op");
        }
        storeSlotFrom(in.a.reg, 0, X10);
    }

    // A float compare must use FCMP: comparing the 32 bits as an integer
    // would order NaN payloads and -0.0 == 0.0 wrongly. FCMP also sets
    // NZCV=0011 for an unordered result, which no ordered condition matches,
    // so each Zenith operator maps to exactly one condition.
    static int floatCc(const std::string& cond) {
        // FCMP leaves NZCV in the "FP" convention: N = A<B, C = A>=B,
        // V only on unordered. LS (C==0|Z) is A<=B and GE (N==V) is A>=B --
        // the old table had 5 (PL) for "<=" and 13 (LE) for ">=", which
        // compared the other way around.
        if (cond == "==") return 0;       // EQ
        if (cond == "!=") return 1;       // NE
        if (cond == "<")  return 4;       // MI (LT)
        if (cond == "<=") return 9;       // LS (LE)
        if (cond == ">")  return 12;      // GT
        if (cond == ">=") return 10;      // GE
        throw std::runtime_error("IR android: bad float condition '" + cond + "'");
    }

    void emitInstr(const IRInstr& in) {
        switch (in.op) {
        case IROp::Nop:
        case IROp::Func:
        case IROp::EndFunc:
            return;
        case IROp::Label:
            a.label(in.a.label);
            return;

        case IROp::Const:
            a.loadConst(X10, (uint64_t)in.b.imm);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::FConst: {
            // Zenith's `float` is single precision: the f32 bits live in the
            // low 4 bytes of an 8-byte slot.
            a.loadConst(X10, (uint64_t)(uint32_t)in.b.imm);
            a.u32(encFmovFromW(0, X10));
            storeSlotF(in.a.reg, 0, 0);
            return;
        }

        case IROp::Str:
            dataAddrTo(X10, true, in.b.strIdx, "");
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Mov:
            if (in.b.kind == IROperand::Reg) {
                loadSlotTo(X10, in.b.reg, 0);
            } else {
                a.loadConst(X10, (uint64_t)in.b.imm);
            }
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::LeaGlobal:
            dataAddrTo(X10, false, -1, in.b.name);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::LeaSlot:
            addrNew((int64_t)in.b.reg * 8 + in.b.off);
            storeSlotFrom(in.a.reg, 0, X9);
            return;

        case IROp::Load:
            loadSlotTo(X10, in.b.reg, in.label < 0 ? 0 : in.label);
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Load32:
            addrNew((int64_t)in.b.reg * 8 + (in.label < 0 ? 0 : in.label));
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Store:
            loadSlotTo(X10, in.b.reg, 0);
            storeSlotFrom(in.a.reg, in.label < 0 ? 0 : in.label, X10);
            return;
        case IROp::Store32:
            loadSlotTo(X10, in.b.reg, 0);
            addrNew((int64_t)in.a.reg * 8 + (in.label < 0 ? 0 : in.label));
            a.u32(encStrW(X10, X9, 0));
            return;

        case IROp::GLoad:
            dataAddrTo(X9, false, -1, in.b.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encLdrX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::GLoad32:
            dataAddrTo(X9, false, -1, in.b.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::GStore:
            loadSlotTo(X10, in.b.reg, 0);
            dataAddrTo(X9, false, -1, in.a.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encStrX(X10, X9, 0));
            return;
        case IROp::GStore32:
            loadSlotTo(X10, in.b.reg, 0);
            dataAddrTo(X9, false, -1, in.a.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encStrW(X10, X9, 0));
            return;

        case IROp::PLoad:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoad32:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrswX(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoad32Z:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoadW:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrhW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PLoadB:
            addrOfPtr(in.b.reg, in.b.off);
            a.u32(encLdrbW(X10, X9, 0));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::PStore:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrX(X10, X9, 0));
            return;
        case IROp::PStore32:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrW(X10, X9, 0));
            return;
        case IROp::PStoreW:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrhW(X10, X9, 0));
            return;
        case IROp::PStoreB:
            loadSlotTo(X10, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrbW(X10, X9, 0));
            return;
        case IROp::FPStore:
            // *(float*)(a.reg + a.off) = b.reg   (a is a pointer-valued slot)
            loadSlotF(0, in.b.reg, 0);
            addrOfPtr(in.a.reg, in.a.off);
            a.u32(encStrS(0, X9, 0));
            return;

        // The slot/global float forms carry the element offset in `label`,
        // exactly like Load/Store/GLoad/GStore, and name the *value* in b.
        case IROp::FLoad:            // a.reg = *(float*)(slot b + label)
            loadSlotF(0, in.b.reg, in.label < 0 ? 0 : in.label);
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::FStore:           // *(float*)(slot a + label) = b.reg
            loadSlotF(0, in.b.reg, 0);
            storeSlotF(in.a.reg, in.label < 0 ? 0 : in.label, 0);
            return;
        case IROp::FGLoad:           // a.reg = *(float*)(global b + label)
            dataAddrTo(X9, false, -1, in.b.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encLdrS(0, X9, 0));
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::FGStore:          // *(float*)(global a + label) = b.reg
            loadSlotF(0, in.b.reg, 0);
            dataAddrTo(X9, false, -1, in.a.name);
            addUpTo(a, X9, in.label < 0 ? 0 : in.label);
            a.u32(encStrS(0, X9, 0));
            return;

        case IROp::FAdd: case IROp::FSub: case IROp::FMul: case IROp::FDiv:
            loadOperandF(1, in.b);
            loadOperandF(2, in.c);
            if (in.op == IROp::FAdd)      a.u32(encFaddS(0, 1, 2));
            else if (in.op == IROp::FSub) a.u32(encFsubS(0, 1, 2));
            else if (in.op == IROp::FMul) a.u32(encFmulS(0, 1, 2));
            else                          a.u32(encFdivS(0, 1, 2));
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::FMov:
            loadOperandF(0, in.b);
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::FNeg:
            loadOperandF(0, in.b);
            a.u32(encFnegS(0, 0));
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::I2F:                   // int64 -> f32
            loadSlotTo(X10, in.b.reg, 0);
            a.u32(encScvtfS(0, X10, true));
            storeSlotF(in.a.reg, 0, 0);
            return;
        case IROp::F2I:                   // f32 -> int64
            loadSlotF(0, in.b.reg, 0);
            a.u32(encFcvtzsS(X10, 0, true));
            storeSlotFrom(in.a.reg, 0, X10);
            return;

        case IROp::Arg:
            // The value moves verbatim: an f32 travels in the low 32 bits of
            // its x-register, which is exactly how the callee's parameter
            // slot is filled, so no conversion and no v-register shuffling is
            // needed on either side of a call.
            pendingArgs.push_back(in.b.reg);
            return;

        case IROp::Syscall: {
            int nargs = (int)in.c.imm;
            if (nargs > 8) throw std::runtime_error("IR android: too many syscall arguments");
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++)
                loadSlotTo(X0 + k, pendingArgs[k], 0);
            pendingArgs.clear();
            a.u32(encMovz(X8, (uint16_t)in.a.imm, 0));   // every syscall nr < 2^16
            a.u32(encSvc(0));
            applyClamp(in.a.off);
            if (in.a.kind == IROperand::Reg) {
                a.u32(encMov(X10, X0));
                storeSlotFrom(in.a.reg, 0, X10);
            }
            return;
        }

        case IROp::Call:
        case IROp::ICall: {
            int nargs = (int)in.c.imm;
            if (nargs > 8) throw std::runtime_error("IR android: more than 8 arguments");
            if (in.op == IROp::ICall && in.b.kind == IROperand::Reg) {
                // Indirect call: the callee address sits in a frame slot.
                // X16 is the platform's inter-procedure-call scratch and is
                // never an argument register, so it survives the arg loads.
                loadSlotTo(X16, in.b.reg, 0);
                for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++)
                    loadSlotTo(X0 + k, pendingArgs[k], 0);
                pendingArgs.clear();
                a.u32(encBlr(X16));
            } else {
                for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++)
                    loadSlotTo(X0 + k, pendingArgs[k], 0);
                pendingArgs.clear();
                a.bl(in.b.name);
            }
            if (in.a.kind == IROperand::Reg) {
                if (in.a.off != 0) {
                    storeSlotF(in.a.reg, 0, 0);      // float return value in D0
                } else {
                    a.u32(encMov(X10, X0));
                    storeSlotFrom(in.a.reg, 0, X10);
                }
            }
            return;
        }

        case IROp::PrintStr:
            if (in.a.kind == IROperand::StrIdx) {
                dataAddrTo(X0, true, in.a.strIdx, "");
            } else if (in.a.kind == IROperand::Reg) {
                loadSlotTo(X0, in.a.reg, 0);
            } else throw std::runtime_error("IR android: bad PrintStr operand");
            a.u32(encMovz(X1, in.a.off != 0 ? 0 : 1, 0));   // x1 = newline?
            a.bl("__z_print_str");
            return;
        case IROp::PrintInt:
            loadSlotTo(X0, in.a.reg, 0);
            a.u32(encMovz(X1, in.a.off != 0 ? 0 : 1, 0));
            a.bl("__z_print_int");
            return;
        case IROp::PrintFlt:
            loadSlotF(0, in.a.reg, 0);
            a.u32(encFmovToW(X0, 0));
            a.u32(encMovz(X1, in.a.off != 0 ? 0 : 1, 0));
            a.bl("__z_print_float");
            return;

        case IROp::Exit:
            a.u32(encMovz(X8, SYS_EXIT_GROUP, 0));
            a.u32(encSvc(0));
            a.u32(encB(0));      // never reached
            return;

        case IROp::Ret: {
            pendingArgs.clear();
            if (in.a.kind == IROperand::Reg) loadSlotTo(X0, in.a.reg, 0);
            a.u32(encLdrX(X30, XSP, (uint16_t)frameAligned));
            addUpTo(a, XSP, spAlloc);
            a.u32(encRet());
            return;
        }

        case IROp::Add: case IROp::Sub: case IROp::And: case IROp::Or: case IROp::Xor:
        case IROp::Mul: case IROp::IDiv: case IROp::UDiv: case IROp::IMod: case IROp::UMod:
        case IROp::Shl: case IROp::Shr: case IROp::Sar:
            emitBin(in);
            return;
        case IROp::Neg:
            loadSlotTo(X10, in.b.reg, 0);
            a.u32(encNeg(X10, X10));
            storeSlotFrom(in.a.reg, 0, X10);
            return;
        case IROp::Not:
            loadSlotTo(X10, in.b.reg, 0);
            a.u32(encMvn(X10, X10));
            storeSlotFrom(in.a.reg, 0, X10);
            return;

        case IROp::Cmp:
            if (in.a.off != 0) {           // float compare
                loadOperandF(1, in.b);
                loadOperandF(2, in.c);
                a.u32(encFcmpS(1, 2));
                a.u32(encCset(X10, (uint32_t)floatCc(in.cond)));
            } else {
                loadOperandX(X10, in.b);
                loadOperandX(X11, in.c);
                a.u32(encCmpReg(X10, X11));
                int cc = ccForOp(in.cond);
                if (cc < 0) throw std::runtime_error("IR android: bad compare condition '" + in.cond + "'");
                a.u32(encCset(X10, (uint32_t)cc));
            }
            storeSlotFrom(in.a.reg, 0, X10);
            return;

        case IROp::Br:
            a.b(in.b.label);
            return;
        case IROp::BrZ:
            loadSlotTo(X10, in.a.reg, 0);
            a.cbz(X10, in.b.label);
            return;
        case IROp::BrNZ:
            loadSlotTo(X10, in.a.reg, 0);
            a.cbnz(X10, in.b.label);
            return;
        case IROp::BrCC: {
            if (in.a.off != 0) {           // float branch
                loadOperandF(1, in.a);
                loadOperandF(2, in.b);
                a.u32(encFcmpS(1, 2));
                a.bcc(floatCc(in.cond), in.c.label);
                return;
            }
            loadOperandX(X10, in.a);
            loadOperandX(X11, in.b);
            a.u32(encCmpReg(X10, X11));
            int cc = ccForOp(in.cond);
            if (cc < 0) throw std::runtime_error("IR android: bad branch condition '" + in.cond + "'");
            a.bcc(cc, in.c.label);
            return;
        }

        default:
            if (in.op == IROp::RawAsm) {
                if (in.a.strIdx < 0 || in.a.strIdx >= (int)asmBlocks.size())
                    throw std::runtime_error("IR android: bad inline asm block index");
                encodeAsmA64(a, asmBlocks[(size_t)in.a.strIdx]);
                return;
            }
            throw std::runtime_error("IR android: unhandled IR op " + std::to_string((int)in.op));
        }
    }

    void emitBody() {
        // Prologue: allocate the frame and save the LR at a fixed slot --
        // [sp + frameAligned], the last 16 bytes of the caller's frame -- so
        // the epilogue can restore it without knowing how sp was moved.
        if (spAlloc <= 504) {
            // one pair instruction does both, and zeroes the first slot
            a.u32(encStpX(X30, XZR, XSP, -spAlloc, kPairPre));
        } else {
            // STP's displacement is a 7-bit scaled field, so a big frame (more
            // than 504 bytes of slots) has to be allocated with SUB.
            addUpTo(a, XSP, -spAlloc);
        }
        a.u32(encStrX(X30, XSP, (uint16_t)frameAligned));
        for (int v = 0; v < nparams; v++) {
            if (v > 7) throw std::runtime_error("IR android: more than 8 parameters");
            a.u32(encStrX(v, XSP, (uint16_t)(v * 8)));
        }
        for (auto& irin : fn.instrs) {
            if (irin.garbage) continue;
            emitInstr(irin);
        }
        // fall-off-the-end epilogue (unreachable, keeps the frame balanced)
        a.u32(encLdrX(X30, XSP, (uint16_t)frameAligned));
        addUpTo(a, XSP, spAlloc);
        a.u32(encRet());
        // AArch64 machine-word peephole: last chance to see the real
        // encodings, still before the fixups are resolved. A64Fn::dfs holds
        // raw offsets into this buffer, so it has to be handed over for
        // pinning (the ADRP's ADD is a fixup half, not an addZero hit) and
        // remapped afterwards -- the image patcher writes at these offsets.
        {
            std::vector<int> external;
            external.reserve(dfs.size());
            for (const auto& d : dfs) external.push_back(d.pos);
            A64PeepholeRun run = a64Peephole(a, external);
            for (auto& d : dfs) d.pos = run.remap(d.pos);
        }
        a.resolveBranches();
    }
};

// ====================================================================
// Runtime helpers
//
// Only helpers the program actually calls are emitted, and the ones andropt
// inlined never appear at all. Every helper touches only x0..x11 (so x19-x21
// survive a call) and keeps SP 16-byte aligned.
// ====================================================================
struct Rt {
    AsmBuf a;
    // A label id is a slot in AsmBuf::labelPos, so it has to come from a
    // counter that advances on every request -- labelPos only grows when a
    // label is actually placed, so its size cannot name the next free id.
    int nLabels = 0;
    int newLabel() { return nLabels++; }
    void u32(uint32_t w) { a.u32(w); }
    void movz(int rd, uint32_t v) { a.u32(encMovz(rd, (uint16_t)(v & 0xFFFF), 0)); }
    void movn(int rd, uint16_t imm) { a.u32(encMovn(rd, imm, 0, true)); }
    void mov(int rd, int rn) { a.u32(encMov(rd, rn)); }
    void loadConst(int rd, uint64_t v) { a.loadConst(rd, v); }
    void addImm(int rd, int64_t v) { addUpTo(a, rd, v); }
    void subImm(int rd, int64_t v) { addUpTo(a, rd, -v); }
    void addReg(int rd, int rn, int rm) { a.u32(encAddReg(rd, rn, rm)); }
    void subReg(int rd, int rn, int rm) { a.u32(encSubReg(rd, rn, rm)); }
    void mul(int rd, int rn, int rm) { a.u32(encMul(rd, rn, rm)); }
    void udiv(int rd, int rn, int rm) { a.u32(encUdiv(rd, rn, rm)); }
    void msub(int rd, int rn, int rm, int ra) { a.u32(encMsub(rd, rn, rm, ra)); }
    void andReg(int rd, int rn, int rm) { a.u32(encAndReg(rd, rn, rm)); }
    void negReg(int rd, int rm) { a.u32(encNeg(rd, rm)); }
    void ldrbW(int rt, int rn, uint16_t off) { a.u32(encLdrbW(rt, rn, off)); }
    void strbW(int rt, int rn, uint16_t off) { a.u32(encStrbW(rt, rn, off)); }
    void ldrX(int rt, int rn, uint16_t off) { a.u32(encLdrX(rt, rn, off)); }
    void strX(int rt, int rn, uint16_t off) { a.u32(encStrX(rt, rn, off)); }
    void cmpImm(int rn, uint16_t imm) { a.u32(encCmp(rn, imm)); }
    void cmpReg(int rn, int rm) { a.u32(encCmpReg(rn, rm)); }
    void cbz(int rt, int L) { a.cbz(rt, L); }
    void cbnz(int rt, int L) { a.cbnz(rt, L); }
    void cset(int rd, int cc) { a.u32(encCset(rd, (uint32_t)cc)); }
    void b(int L) { a.b(L); }
    void bcc(int cc, int L) { a.bcc(cc, L); }
    void bl(const std::string& n) { a.bl(n); }
    void ret() { a.u32(encRet()); }
    void svc(int nr) { a.u32(encMovz(X8, (uint16_t)nr, 0)); a.u32(encSvc(0)); }
    void label(int L) { a.label(L); }
    void subSp(int bytes) { addImm(XSP, -bytes); }
    void addSp(int bytes) { addImm(XSP, bytes); }
    void spAddr(int rt, int64_t off) { a.u32(encAdd(rt, XSP, 0)); addUpTo(a, rt, off); }
    void dataAddr(int rt, int64_t off) { a.u32(encAdd(rt, X19, 0)); addUpTo(a, rt, off); }

    // -errno -> 0, straight after an svc while x0 still holds the result
    void clampErr() {
        int Ldone = newLabel();
        loadConst(X1, (uint64_t)(int64_t)-4095);
        cmpReg(X0, X1);
        bcc(3, Ldone);
        movz(X0, 0);
        label(Ldone);
    }
    // "0 means success" -> 1 on success
    void clampZeroOk() {
        movz(X1, 0);
        cmpReg(X0, X1);
        cset(X0, 0);
    }
    // write(2) to stdout: buf in x1, length in x2.
    void writeOut() {
        movz(X0, 1);
        svc(SYS_WRITE);
    }
    // nanosleep with a timespec built on our own frame; x0 = nanoseconds
    void sleepNs() {
        subSp(32);
        movz(X1, 0);
        strX(X1, XSP, 0);
        strX(X0, XSP, 8);
        spAddr(X0, 0);
        movz(X1, 0);
        svc(SYS_NANOSLEEP);
        addSp(32);
        ret();
    }
    // Copy a NUL-terminated string from src to dst, at most len bytes plus the
    // terminator; the length lands in x0, or 0 if the buffer is too small.
    // Clobbers x5/x6, so those are never src, dst or len.
    void copyCstr(int dst, int src, int len, int Lfail) {
        int Lloop = newLabel(), Lnul = newLabel(), Lnext = newLabel();
        movz(X5, 0);
        label(Lloop);
        cmpReg(X5, len);
        bcc(10, Lfail);              // GE -> not even room for the NUL
        ldrbW(X6, src, 0);
        strbW(X6, dst, 0);
        cbz(X6, Lnul);
        addImm(X5, 1);
        addImm(src, 1);
        addImm(dst, 1);
        b(Lloop);
        label(Lnul);
        mov(X0, X5);
        b(Lnext);
        label(Lfail);
        movz(X0, 0);
        label(Lnext);
    }
};

// --------------------------------------------------------------------
// Helper bodies
// --------------------------------------------------------------------
static FnImg buildHelper(const std::string& name) {
    Rt r;

    // Board helpers have nothing to talk to on a phone: there is no MMIO
    // behind a fixed address, the kernel is the only peripheral. Say so
    // instead of failing with "unknown helper", which reads like a bug.
    {
        static const char* kBoardPrefixes[] = {
            "__z_gpio_", "__z_led_", "__z_uart_", "__z_spi_",
            "__z_i2c_", "__z_pwm_", "__z_delay_spin_"
        };
        for (const char* pfx : kBoardPrefixes)
            if (name.compare(0, std::strlen(pfx), pfx) == 0) {
                std::cerr << "android: warning: '" << name.substr(4)
                          << "' has no effect on Android (no board MMIO; "
                             "the only peripheral is the kernel, via svc)\n";
                r.movz(X0, 0);
                r.ret();
                FnImg img;
                img.name = name;
                img.bytes.swap(r.a.c);
                return img;
            }
    }

    // A helper nobody has a body for would silently become an empty
    // function that runs into whatever is emitted next, so the name is checked
    // against the list of bodies below first. IRGen only ever calls one of
    // these (see IRGen::androidCallHelper).
    {
        static const char* kKnown[] = {
            "__z_alloc", "__z_argc", "__z_arg_get", "__z_delay_us",
            "__z_env_get", "__z_exit", "__z_file_close", "__z_file_fstat_size",
            "__z_file_fsync", "__z_file_lseek", "__z_file_mkdir", "__z_file_open",
            "__z_file_pread", "__z_file_pwrite", "__z_file_read", "__z_file_rename",
            "__z_file_size", "__z_file_size_legacy", "__z_file_truncate",
            "__z_file_unlink", "__z_file_write", "__z_free", "__z_geteuid",
            "__z_getgid", "__z_getpid", "__z_getuid", "__z_madvise", "__z_mem_cmp",
            "__z_mem_copy", "__z_mem_set", "__z_memfd_create", "__z_mmap",
            "__z_munmap", "__z_page_size", "__z_print_float", "__z_print_int",
            "__z_print_str", "__z_random_bytes", "__z_random_bytes_legacy",
            "__z_sched_yield", "__z_sleep", "__z_str_len", "__z_time_ns",
            "__z_uname_field"
        };
        bool known = false;
        for (const char* k : kKnown)
            if (name == k) { known = true; break; }
        if (!known) throw std::runtime_error("android: unknown runtime helper '" + name + "'");
    }

    if (name == "__z_print_str") {
        // x0 = NUL-terminated string, x1 = newline flag.
        //
        // The string pool is in the read-only part of the data segment, so the
        // trailing '\n' cannot simply be stored after it. The helper therefore
        // copies the line onto its own frame and puts the whole thing — text and
        // newline — out in a single write(2). The classic backend pays two
        // syscalls and two wakeups per line, plus a strlen walk; a literal
        // println does not even come here, because andropt turns it into one
        // write(2) with a compile-time length.
        //
        //   [sp+0]   the saved return address
        //   [sp+8]   the newline flag
        //   [sp+16]  the copy buffer (kStrBuf bytes)
        const int kStrBuf = 1024;
        const int kFrame = 16 + kStrBuf;     // 16 keeps sp 16-byte aligned
        int Lloop = r.newLabel(), Ldone = r.newLabel();
        int Lfull = r.newLabel(), Lout = r.newLabel();
        r.subSp(kFrame);
        r.strX(X30, XSP, 0);
        r.strX(X1, XSP, 8);
        r.spAddr(X9, 16);                    // x9 = the copy buffer
        r.mov(X10, X9);                      // x10 = the write cursor
        r.movz(X11, 0);                      // x11 = the length
        r.movz(X12, kStrBuf);
        r.mov(X1, X0);                       // x1 = the read cursor
        r.label(Lloop);
        r.cmpReg(X11, X12);
        r.bcc(10, Lfull);                    // GE -> the buffer is full
        r.ldrbW(X3, X1, 0);
        r.cbz(X3, Ldone);
        r.strbW(X3, X10, 0);
        r.addImm(X1, 1);
        r.addImm(X10, 1);
        r.addImm(X11, 1);
        r.b(Lloop);
        r.label(Ldone);
        r.ldrX(X3, XSP, 8);                  // the newline flag
        r.cbz(X3, Lout);
        r.movz(X4, (uint32_t)'\n');
        r.strbW(X4, X10, 0);
        r.addImm(X11, 1);
        r.b(Lout);
        r.label(Lfull);
        r.label(Lout);
        r.mov(X1, X9);
        r.mov(X2, X11);
        r.writeOut();                        // x1 = the buffer, x2 = the length
        r.ldrX(X30, XSP, 0);
        r.addSp(kFrame);
        r.ret();
    }
    if (name == "__z_print_int") {
        // x0 = value, x1 = newline flag -> one write(2) for the whole line.
        //
        //   [sp+0]   the value
        //   [sp+8]   the newline flag
        //   [sp+16]  the line buffer (32 bytes, built downwards from sp+48)
        //   [sp+56]  the saved return address
        int Lloop = r.newLabel(), Ldigits = r.newLabel(), Lskipminus = r.newLabel();
        int Lout = r.newLabel();
        r.subSp(64);
        r.strX(X30, XSP, 56);
        r.strX(X0, XSP, 0);
        r.strX(X1, XSP, 8);
        r.spAddr(X2, 48);                     // the digits end at sp+48
        r.movz(X3, 0);
        r.strbW(X3, X2, 0);                   // NUL, so a stray use cannot run off
        r.ldrX(X10, XSP, 8);                   // the newline flag
        r.cbz(X10, Ldigits);
        r.subImm(X2, 1);                      // the line is laid down backwards, so
        r.movz(X6, (uint32_t)'\n');           // the newline goes down first: it is
        r.strbW(X6, X2, 0);                   // the last byte of the line
        r.label(Ldigits);
        r.ldrX(X3, XSP, 0);
        r.movz(X4, 0);                        // x4 = negative flag
        r.cmpImm(X3, 0);
        r.bcc(10, Lloop);                     // GE -> no sign
        // |n| = -(n+1)+1: negating INT64_MIN overflows back onto itself.
        r.addImm(X3, 1);
        r.negReg(X3, X3);
        r.addImm(X3, 1);
        r.movz(X4, 1);
        r.label(Lloop);
        r.movz(X10, 10);
        r.udiv(X5, X3, X10);
        r.msub(X6, X5, X10, X3);               // remainder
        r.addImm(X6, 48);
        r.subImm(X2, 1);
        r.strbW(X6, X2, 0);
        r.mov(X3, X5);
        r.cbnz(X3, Lloop);
        r.cmpImm(X4, 1);
        r.bcc(1, Lskipminus);                 // NE -> not negative
        r.subImm(X2, 1);
        r.movz(X6, '-');
        r.strbW(X6, X2, 0);
        r.label(Lskipminus);
        r.label(Lout);
        // The digits were laid down backwards, so the line is [cursor, sp+48):
        // the cursor is where the line starts and the far end is its length.
        r.mov(X1, X2);
        r.spAddr(X9, 48);
        r.subReg(X2, X9, X2);
        r.writeOut();                       // x1 = start, x2 = length
        r.ldrX(X30, XSP, 56);
        r.addSp(64);
        r.ret();
    }
    if (name == "__z_print_float") {
        // x0 = f32 bits, x1 = newline flag.
        // f32 has no exact decimal form, so the value is scaled to
        // micro-units in f64 (one rounding) and printed as
        // [-]digits.dddddd -- six fractional digits, which is the shape the
        // other Zenith targets print. A magnitude that does not fit in an
        // fcvtzs saturates; an approximate number beats garbage digits.
        int Lneg = r.newLabel(), Lnonneg = r.newLabel(), Lscale = r.newLabel();
        int Lfrac = r.newLabel(), Lint = r.newLabel(), Ldone = r.newLabel();
        int Ldigits = r.newLabel(), Lout = r.newLabel();
        r.subSp(96);
        r.strX(X30, XSP, 80);
        r.strX(X1, XSP, 0);                   // the newline flag
        r.loadConst(X10, 0);
        r.u32(encFmovFromX(1, X10));          // d1 = 0.0
        r.loadConst(X10, 0x412E848000000000ull);   // 1e6
        r.u32(encFmovFromX(2, X10));
        r.loadConst(X10, 0x3FE0000000000000ull);   // 0.5
        r.u32(encFmovFromX(3, X10));
        r.u32(encFcvtDs(0, 0));               // d0 = (double) the f32
        r.u32(encFcmpD(0, 1));                // against 0.0
        r.bcc(4, Lneg);                       // MI -> negative
        r.b(Lnonneg);
        r.label(Lneg);
        r.u32(encFnegD(0, 0));
        r.movz(X9, 1);                        // the sign flag
        r.b(Lscale);
        r.label(Lnonneg);
        r.movz(X9, 0);
        r.label(Lscale);
        r.u32(encFmulD(0, 0, 2));             // micro units, all in f64: the
        r.u32(encFaddD(0, 0, 3));             // + 0.5, so it rounds
        r.u32(encFcvtzsD(10, 0));             // x10 = micro units
        r.loadConst(X11, 1000000);
        r.udiv(X3, X10, X11);                 // x3 = whole part
        r.msub(X4, X3, X11, X10);             // x4 = fraction
        r.spAddr(X6, 48);                     // the text ends at sp+48
        r.ldrX(X10, XSP, 0);                   // the newline flag
        r.cbz(X10, Ldigits);
        r.subImm(X6, 1);                      // built backwards, so the newline is
        r.movz(X7, (uint32_t)'\n');           // laid down first: it ends the line
        r.strbW(X7, X6, 0);
        r.label(Ldigits);
        r.movz(X11, 6);
        r.label(Lfrac);                       // six zero-padded digits
        r.movz(X12, 10);
        r.udiv(X7, X4, X12);
        r.msub(X5, X7, X12, X4);              // x5 = the digit
        r.addImm(X5, 48);
        r.mov(X4, X7);                        // the next value is the quotient
        r.subImm(X6, 1);
        r.strbW(X5, X6, 0);
        r.subImm(X11, 1);
        r.cbnz(X11, Lfrac);
        r.movz(X7, (uint32_t)'.');
        r.subImm(X6, 1);
        r.strbW(X7, X6, 0);
        r.label(Lint);                        // the whole part, one digit minimum
        r.movz(X10, 10);
        r.udiv(X7, X3, X10);
        r.msub(X5, X7, X10, X3);
        r.addImm(X5, 48);
        r.subImm(X6, 1);
        r.strbW(X5, X6, 0);
        r.mov(X3, X7);
        r.cbnz(X3, Lint);
        r.cbz(X9, Ldone);
        r.movz(X7, '-');
        r.subImm(X6, 1);
        r.strbW(X7, X6, 0);
        r.label(Ldone);
        r.label(Lout);
        // Laid down backwards, like __z_print_int: the cursor is the start.
        r.mov(X1, X6);
        r.spAddr(X9, 48);
        r.subReg(X2, X9, X6);
        r.writeOut();
        r.ldrX(X30, XSP, 80);
        r.addSp(96);
        r.ret();
    }
    if (name == "__z_str_len") {
        int Lloop = r.newLabel(), Ldone = r.newLabel();
        r.mov(X1, X0);
        r.label(Lloop);
        r.ldrbW(X2, X1, 0);
        r.cbz(X2, Ldone);
        r.addImm(X1, 1);
        r.b(Lloop);
        r.label(Ldone);
        r.subReg(X0, X1, X0);
        r.ret();
    }
    if (name == "__z_page_size") {
        // The startup read AT_PAGESZ out of the auxv, so this reports what the
        // device really uses. 4 KiB is not the only answer on Android (16 KiB
        // and 64 KiB are in the field) and a program that hardcodes 4096
        // breaks the moment it meets one.
        r.dataAddr(X0, PAGE_SIZE_WORD_OFF);
        r.ldrX(X0, X0, 0);
        r.ret();
    }
    if (name == "__z_alloc") {
        // x0 = size -> a page-rounded block, or 0.
        // The rounded length sits in a 16-byte header below the pointer, so
        // free() knows what to unmap. mmap returns page-aligned memory, so
        // base+16 is still 16-byte aligned, and the mapping is zero filled.
        int Lnonzero = r.newLabel(), Lok = r.newLabel(), Ldone = r.newLabel();
        r.subSp(16);
        r.strX(X0, XSP, 0);
        r.ldrX(X9, XSP, 0);
        r.movz(X10, 0);
        r.cmpReg(X9, X10);
        r.bcc(1, Lnonzero);                   // NE -> a real size
        r.loadConst(X9, 4096);                // else one page
        r.label(Lnonzero);
        r.addImm(X9, 4095);
        r.movn(X11, 0xFFF);
        r.andReg(X9, X9, X11);                // round up to a page
        r.movz(X0, 0);                        // addr = NULL
        r.mov(X1, X9);
        r.movz(X2, PROT_READ_ | PROT_WRITE_);
        r.movz(X3, MAP_PRIVATE_ | MAP_ANONYMOUS_);
        r.movn(X4, 0);                        // fd = -1
        r.movz(X5, 0);                        // offset = 0
        r.svc(SYS_MMAP);
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.strX(X9, X0, 0);                    // [base] = rounded length
        r.loadConst(X1, 16);
        r.addReg(X0, X0, X1);
        r.label(Ldone);
        r.addSp(16);
        r.ret();
    }
    if (name == "__z_free") {
        r.subSp(16);
        r.strX(X0, XSP, 0);
        r.ldrX(X0, XSP, 0);
        r.movn(X1, 15);
        r.addReg(X0, X0, X1);                 // x0 = base
        r.ldrX(X1, X0, 0);                    // x1 = length
        r.svc(SYS_MUNMAP);
        r.movz(X0, 0);
        r.addSp(16);
        r.ret();
    }
    if (name == "__z_time_ns") {
        // clock_gettime(CLOCK_MONOTONIC) -> nanoseconds. AArch64 Linux takes
        // the clock id in x0 and the timespec in x1.
        r.subSp(16);
        r.movz(X0, CLOCK_MONOTONIC_);
        r.spAddr(X1, 0);
        r.svc(SYS_CLOCK_GETTIME);
        r.ldrX(X0, XSP, 0);
        r.ldrX(X1, XSP, 8);
        r.loadConst(X2, 1000000000ull);
        r.mul(X0, X0, X2);
        r.addReg(X0, X0, X1);
        r.addSp(16);
        r.ret();
    }
    if (name == "__z_sleep") { r.loadConst(X1, 1000000ull); r.mul(X0, X0, X1); r.sleepNs(); }
    if (name == "__z_delay_us") { r.loadConst(X1, 1000ull); r.mul(X0, X0, X1); r.sleepNs(); }
    if (name == "__z_exit") { r.svc(checkedSysNr("__z_exit", SYS_EXIT_GROUP)); r.ret(); }
    if (name == "__z_getuid") { r.svc(SYS_GETUID); r.ret(); }
    if (name == "__z_geteuid") { r.svc(SYS_GETEUID); r.ret(); }
    if (name == "__z_getgid") { r.svc(SYS_GETGID); r.ret(); }
    if (name == "__z_getpid") { r.svc(SYS_GETPID); r.ret(); }
    if (name == "__z_argc") { r.mov(X0, X20); r.ret(); }
    if (name == "__z_sched_yield") { r.svc(SYS_SCHED_YIELD); r.clampZeroOk(); r.ret(); }

    if (name == "__z_file_open") {
        // x0 = path, x1 = flags -> openat(AT_FDCWD, path, flags, 0666).
        // AArch64 Linux has no plain open(2); AT_FDCWD is what makes openat the
        // equivalent. x9/x10 only carry values *into* the syscall, so the
        // kernel never sees them.
        r.mov(X9, X0);
        r.mov(X10, X1);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.mov(X2, X10);
        r.movz(X3, 0666);
        r.svc(checkedSysNr("__z_file_open", SYS_OPENAT));
        r.clampErr();
        r.ret();
    }
    if (name == "__z_file_read") { r.svc(checkedSysNr("__z_file_read", SYS_READ)); r.clampErr(); r.ret(); }
    if (name == "__z_file_write") { r.svc(checkedSysNr("__z_file_write", SYS_WRITE)); r.clampErr(); r.ret(); }
    if (name == "__z_file_pread") { r.svc(checkedSysNr("__z_file_pread", SYS_PREAD64)); r.clampErr(); r.ret(); }
    if (name == "__z_file_pwrite") { r.svc(checkedSysNr("__z_file_pwrite", SYS_PWRITE64)); r.clampErr(); r.ret(); }
    if (name == "__z_file_lseek") { r.svc(checkedSysNr("__z_file_lseek", SYS_LSEEK)); r.clampErr(); r.ret(); }
    if (name == "__z_file_close") { r.svc(checkedSysNr("__z_file_close", SYS_CLOSE)); r.clampZeroOk(); r.ret(); }
    if (name == "__z_file_fsync") { r.svc(checkedSysNr("__z_file_fsync", SYS_FSYNC)); r.clampZeroOk(); r.ret(); }
    if (name == "__z_file_truncate") { r.svc(checkedSysNr("__z_file_truncate", SYS_FTRUNCATE)); r.clampZeroOk(); r.ret(); }
    if (name == "__z_file_unlink") {
        r.mov(X9, X0);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.movz(X2, 0);
        r.svc(SYS_UNLINKAT);
        r.clampZeroOk();
        r.ret();
    }
    if (name == "__z_file_rename") {
        r.mov(X9, X0);
        r.mov(X10, X1);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.loadConst(X2, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X3, X10);
        r.svc(SYS_RENAMEAT);
        r.clampZeroOk();
        r.ret();
    }
    if (name == "__z_file_mkdir") {
        r.mov(X9, X0);
        r.mov(X10, X1);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.mov(X2, X10);
        r.svc(SYS_MKDIRAT);
        r.clampZeroOk();
        r.ret();
    }
    if (name == "__z_file_fstat_size") {
        // x0 = fd -> size in bytes, 0 if the fd cannot be sized.
        // SEEK_END on the descriptor needs no struct stat at all: fstat(2)
        // would tie us to the per-ABI offset of st_size and force a 128-byte
        // frame for one field. The descriptor's own offset is saved and put
        // back, so the call is invisible to the caller apart from its result.
        int Lok = r.newLabel(), Ldone = r.newLabel(), Lsized = r.newLabel();
        r.mov(X9, X0);
        r.mov(X0, X9);
        r.movz(X1, 0);
        r.movz(X2, 1);                        // SEEK_CUR
        r.svc(SYS_LSEEK);
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.mov(X10, X0);                       // the saved offset
        r.mov(X0, X9);
        r.movz(X1, 0);
        r.movz(X2, 2);                        // SEEK_END
        r.svc(SYS_LSEEK);
        // SEEK_END can fail on its own even when SEEK_CUR just worked, and an
        // -errno must never reach the caller posing as a size.
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lsized);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lsized);
        r.mov(X11, X0);
        r.mov(X0, X9);
        r.mov(X1, X10);
        r.movz(X2, 0);                        // SEEK_SET: X10 is absolute
        r.svc(SYS_LSEEK);
        r.mov(X0, X11);
        r.label(Ldone);
        r.ret();
    }
    if (name == "__z_file_size") {
        // x0 = path -> size in bytes, 0 if it cannot be stat'ed.
        // The 256-byte struct statx lives on our own frame: the kernel writes
        // into caller memory and there is nowhere else to put it.
        int Lok = r.newLabel(), Lzero = r.newLabel(), Ldone = r.newLabel();
        r.subSp(272);
        r.movz(X1, 0);
        r.strX(X1, XSP, 0);                   // clear stx_mask ...
        r.strX(X1, XSP, 8);
        r.strX(X1, XSP, 16);
        r.strX(X1, XSP, 24);
        r.strX(X1, XSP, 32);
        r.strX(X1, XSP, STATX_STX_SIZE_OFF);  // ... and stx_size
        r.mov(X9, X0);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.movz(X2, 0);
        r.loadConst(X3, STATX_SIZE_);
        r.spAddr(X4, 0);
        r.svc(checkedSysNr("__z_file_size", SYS_STATX));
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.spAddr(X1, 0);
        r.ldrX(X2, X1, 0);                    // stx_mask
        r.ldrX(X0, X1, STATX_STX_SIZE_OFF);   // stx_size
        r.loadConst(X3, STATX_SIZE_);
        r.andReg(X2, X2, X3);                 // did the kernel fill it in?
        r.cbz(X2, Lzero);
        r.b(Ldone);
        r.label(Lzero);
        r.movz(X0, 0);
        r.label(Ldone);
        r.addSp(272);
        r.ret();
    }
    if (name == "__z_file_size_legacy") {
        // The route for `min_sdk:` below 30, where statx(2) may not exist:
        // open the path, ask for the size with a seek, close it. More syscalls
        // than statx and it needs the path to be openable, but it works on
        // every device the program can be built for.
        //
        //   x0 = path -> size in bytes, 0 if it cannot be sized
        int Lok = r.newLabel(), Lok2 = r.newLabel(), Ldone = r.newLabel();
        r.subSp(16);
        r.strX(X0, XSP, 0);                  // the path
        r.mov(X9, X0);                       // x9 = the path
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.mov(X1, X9);
        r.movz(X2, 0);                       // O_RDONLY
        r.movz(X3, 0666);
        r.svc(checkedSysNr("__z_file_open", SYS_OPENAT));
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.mov(X9, X0);                       // the fd
        r.movz(X1, 0);
        r.movz(X2, 2);                       // SEEK_END
        r.svc(SYS_LSEEK);
        r.mov(X10, X0);                      // the size
        r.mov(X0, X9);
        r.movz(X1, 0);
        r.movz(X2, 0);
        r.svc(SYS_CLOSE);                    // best effort
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X10, X1);
        r.bcc(3, Lok2);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok2);
        r.mov(X0, X10);
        r.label(Ldone);
        r.addSp(16);
        r.ret();
    }
    if (name == "__z_random_bytes") {
        // x0 = buf, x1 = len -> getrandom(2), no flags. Unlike /dev/urandom
        // there is no descriptor to open and no path to get wrong; Android has
        // had it since API 28.
        r.movz(X2, 0);
        r.svc(checkedSysNr("__z_random_bytes", SYS_GETRANDOM));
        r.clampErr();
        r.ret();
    }
    if (name == "__z_random_bytes_legacy") {
        // The route for `min_sdk:` below 28: read(2) from /dev/urandom. It
        // costs an open and a close, and the kernel can throttle a device
        // that asks for too much, but it works everywhere. Returns the number
        // of bytes filled, 0 on failure, like getrandom.
        int Lok = r.newLabel(), Ldone = r.newLabel();
        r.subSp(48);
        r.strX(X0, XSP, 0);                  // the buffer
        r.strX(X1, XSP, 8);                  // the length
        // "/dev/urandom" is written straight onto the frame: no pool entry,
        // and the call site stays a plain call. Byte by byte, so the path is
        // the readable spelling of itself.
        r.spAddr(X9, 16);
        {
            const char* p = "/dev/urandom";
            for (int k = 0; k < 13; k++) {   // including the NUL
                r.movz(X3, (uint32_t)(uint8_t)p[k]);
                r.strbW(X3, X9, (uint16_t)k);
            }
        }
        r.mov(X1, X9);                       // x1 = the path
        r.movz(X2, 0);                       // O_RDONLY
        r.movz(X3, 0666);
        r.loadConst(X0, (uint64_t)(int64_t)AT_FDCWD);
        r.svc(SYS_OPENAT);
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.mov(X9, X0);                       // the fd survives the reload
        r.mov(X0, X9);                       // read(fd, buf, count)
        r.ldrX(X1, XSP, 0);                  // x1 = the buffer
        r.ldrX(X2, XSP, 8);                  // x2 = the length
        r.svc(SYS_READ);
        r.mov(X10, X0);                      // bytes read
        r.mov(X0, X9);
        r.svc(SYS_CLOSE);
        r.mov(X0, X10);
        r.loadConst(X1, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X1);
        r.bcc(3, Ldone);
        r.movz(X0, 0);
        r.label(Ldone);
        r.addSp(48);
        r.ret();
    }
    if (name == "__z_memfd_create") {
        // x0 = name -> memfd_create(2) with MFD_CLOEXEC, so the fd cannot leak
        // into a child process. The result is a normal fd: file_write,
        // file_pread and file_close all work on it, which makes it a scratch
        // buffer that never touches the filesystem. Android has had it since
        // API 30.
        r.movz(X1, MFD_CLOEXEC_);
        r.svc(checkedSysNr("__z_memfd_create", SYS_MEMFD_CREATE));
        r.clampErr();
        r.ret();
    }
    if (name == "__z_mmap") {
        // x0 = addr, x1 = len, x2 = prot, x3 = flags, x4 = fd, x5 = offset.
        // The last two are forced to 0: a stale value in the offset slot makes
        // a MAP_ANONYMOUS mapping fail with EINVAL.
        r.movz(X4, 0);
        r.movz(X5, 0);
        r.svc(checkedSysNr("__z_mmap", SYS_MMAP));
        r.clampErr();
        r.ret();
    }
    if (name == "__z_munmap") { r.svc(checkedSysNr("__z_munmap", SYS_MUNMAP)); r.clampZeroOk(); r.ret(); }
    if (name == "__z_madvise") { r.svc(checkedSysNr("__z_madvise", SYS_MADVISE)); r.clampZeroOk(); r.ret(); }
    if (name == "__z_mem_copy") {
        // x0 = dst, x1 = src, x2 = len -> memmove semantics: an overlapping
        // copy has to walk in the direction that cannot clobber a byte that
        // has not been read yet. A negative count is rejected outright,
        // because the countdown below only stops on exactly 0.
        int Lfwd = r.newLabel(), Ldone = r.newLabel(), Lback = r.newLabel();
        int Lfloop = r.newLabel(), Lfstep = r.newLabel(), Lbad = r.newLabel();
        r.cmpImm(X2, 0);
        r.bcc(4, Lbad);                        // MI -> negative
        r.bcc(0, Lbad);                        // EQ -> nothing copied
        r.mov(X6, X2);
        r.cmpReg(X0, X1);
        r.bcc(3, Lfwd);                        // LO -> dst < src: forward is safe
        r.addReg(X3, X0, X2);
        r.addReg(X4, X1, X2);
        // The bound is tested *after* the step: with X3 == dst a GE test is
        // still true, and the loop would run len+1 times and write one byte
        // below dst.
        r.label(Lback);
        r.subImm(X3, 1);
        r.subImm(X4, 1);
        r.ldrbW(X5, X4, 0);
        r.strbW(X5, X3, 0);
        r.cmpReg(X3, X0);
        r.bcc(8, Lback);                       // HI -> still above dst
        r.b(Ldone);
        r.label(Lfwd);
        r.mov(X7, X2);
        r.label(Lfloop);
        r.cmpReg(X7, XZR);
        r.bcc(1, Lfstep);
        r.b(Ldone);
        r.label(Lfstep);
        r.ldrbW(X5, X1, 0);
        r.strbW(X5, X0, 0);
        r.addImm(X0, 1);
        r.addImm(X1, 1);
        r.subImm(X7, 1);
        r.b(Lfloop);
        r.label(Ldone);
        r.mov(X0, X6);
        r.ret();
        r.label(Lbad);
        r.movz(X0, 0);
        r.ret();
    }
    if (name == "__z_mem_set") {
        int Ldone = r.newLabel(), Lloop = r.newLabel(), Lstep = r.newLabel(), Lbad = r.newLabel();
        r.cmpImm(X2, 0);
        r.bcc(4, Lbad);
        r.bcc(0, Lbad);
        r.mov(X6, X2);
        r.mov(X7, X2);
        r.label(Lloop);
        r.cmpReg(X7, XZR);
        r.bcc(1, Lstep);
        r.b(Ldone);
        r.label(Lstep);
        r.strbW(X1, X0, 0);                    // only the low byte of x1 is stored
        r.addImm(X0, 1);
        r.subImm(X7, 1);
        r.b(Lloop);
        r.label(Ldone);
        r.mov(X0, X6);
        r.ret();
        r.label(Lbad);
        r.movz(X0, 0);
        r.ret();
    }
    if (name == "__z_mem_cmp") {
        // x0 = a, x1 = b, x2 = len -> 0 when equal, else the difference of the
        // first differing pair, so the sign matches memcmp(3).
        int Lloop = r.newLabel(), Lstep = r.newLabel(), Ldiff = r.newLabel(), Lbad = r.newLabel();
        r.cmpImm(X2, 0);
        r.bcc(4, Lbad);
        r.bcc(0, Lbad);
        r.mov(X7, X2);
        r.label(Lloop);
        r.cmpReg(X7, XZR);
        r.bcc(1, Lstep);
        r.movz(X0, 0);
        r.ret();
        r.label(Lstep);
        r.ldrbW(X4, X0, 0);
        r.ldrbW(X5, X1, 0);
        r.cmpReg(X4, X5);
        r.bcc(1, Ldiff);
        r.addImm(X0, 1);
        r.addImm(X1, 1);
        r.subImm(X7, 1);
        r.b(Lloop);
        r.label(Ldiff);
        r.subReg(X0, X4, X5);
        r.ret();
        r.label(Lbad);
        r.movz(X0, 0);
        r.ret();
    }
    if (name == "__z_uname_field") {
        // x0 = dst buffer, x1 = len, x2 = which (0..5 over utsname) -> the
        // number of bytes copied, 0 on failure. The kernel wants a 390-byte
        // utsname, far too big for a Zenith frame, so it goes on our own
        // frame and one field is copied out of it.
        int Lok = r.newLabel(), Lfail = r.newLabel(), Ldone = r.newLabel();
        int Lout = r.newLabel();
        r.subSp((UTS_BUF_BYTES + 15) & ~15);
        // x1/x2 are inputs, not syscall arguments, and x0 becomes uname's
        // return value, so all three are parked before the svc.
        r.mov(X9, X1);
        r.mov(X10, X2);
        r.mov(X11, X0);
        r.spAddr(X0, 0);
        r.svc(SYS_UNAME);
        r.loadConst(X3, (uint64_t)(int64_t)-4095);
        r.cmpReg(X0, X3);
        r.bcc(3, Lok);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lout);
        r.movz(X0, 0);
        r.b(Ldone);
        r.label(Lok);
        r.loadConst(X3, 5);
        r.cmpReg(X10, X3);
        r.bcc(8, Lout);                        // HI -> which > 5
        r.cmpImm(X10, 0);
        r.bcc(4, Lout);                        // MI -> which < 0
        r.loadConst(X3, UTS_FIELD);
        r.mul(X4, X10, X3);
        r.spAddr(X3, 0);
        r.addReg(X4, X4, X3);                  // x4 = &utsname.field[which]
        r.copyCstr(X11, X4, X9, Lfail);
        r.label(Ldone);
        r.addSp((UTS_BUF_BYTES + 15) & ~15);
        r.ret();
    }
    if (name == "__z_arg_get") {
        // x0 = index, x1 = dst, x2 = len -> bytes copied, 0 on failure.
        // x21 is the stack the kernel built: [argc][argv...][NULL][envp...],
        // so argv[i] is at x21 + 8 + i*8. The range test has to reject
        // negatives separately: a signed "index >= argc" is false for -1,
        // which would then index argv backwards off the front.
        int Lfail = r.newLabel();
        r.cmpImm(X0, 0);
        r.bcc(4, Lfail);
        r.cmpReg(X0, X20);
        r.bcc(10, Lfail);
        r.loadConst(X3, 8);
        r.mul(X3, X0, X3);
        r.addReg(X3, X21, X3);
        r.addImm(X3, 8);                       // skip argc itself
        r.ldrX(X4, X3, 0);
        r.cbz(X4, Lfail);
        r.copyCstr(X1, X4, X2, Lfail);
        r.ret();
        r.label(Lfail);
        r.movz(X0, 0);
        r.ret();
    }
    if (name == "__z_env_get") {
        // x0 = name, x1 = dst, x2 = len -> the length of the value copied.
        // envp follows argv[] and its NULL: x21 + 16 + argc*8.
        int Lscan = r.newLabel(), Lpfx = r.newLabel(), Lnext = r.newLabel();
        int Lfail = r.newLabel(), Lval = r.newLabel(), Lend = r.newLabel();
        r.loadConst(X3, 8);
        r.mul(X3, X20, X3);
        r.addReg(X3, X21, X3);
        r.addImm(X3, 16);
        r.mov(X11, X0);                        // the name, across the scan
        r.label(Lscan);
        r.ldrX(X4, X3, 0);
        r.cbz(X4, Lfail);                      // end of envp
        r.mov(X5, X11);
        r.mov(X6, X4);
        r.label(Lpfx);
        r.ldrbW(X7, X5, 0);
        r.ldrbW(X8, X6, 0);
        // The end of the name has to be tested *before* the bytes are
        // compared: on a full match the name is exhausted while the entry
        // still has its '=' in front of us.
        r.cbz(X7, Lend);
        r.cmpReg(X7, X8);
        r.bcc(1, Lnext);
        r.addImm(X5, 1);
        r.addImm(X6, 1);
        r.b(Lpfx);
        r.label(Lend);
        r.cmpImm(X8, '=');
        r.bcc(0, Lval);
        r.b(Lnext);
        r.label(Lnext);
        r.addImm(X3, 8);
        r.b(Lscan);
        r.label(Lval);
        r.addImm(X6, 1);                        // just past the '='
        r.copyCstr(X1, X4, X2, Lfail);
        r.ret();
        r.label(Lfail);
        r.movz(X0, 0);
        r.ret();
    }

    // Every body above ends in `ret` and falls through to here: the helper is
    // the code emitted so far, with its internal branches resolved inside the
    // buffer so labels and code move together into the final layout.
    a64Peephole(r.a);
    r.a.resolveBranches();
    {
        FnImg img;
        img.name = name;
        img.bytes.swap(r.a.c);
        img.bls.swap(r.a.bls);
        return img;
    }
}

// --------------------------------------------------------------------
// Startup
//
// The kernel hands control over with SP pointing at argc, argv right above
// it, then envp, then the auxv. All three are read here, and the auxv is
// scanned for AT_PAGESZ so sys_page_size() can report what the device really
// uses instead of assuming 4 KiB.
//
// X19 = the data segment (ADRP+ADD, patched after layout), X20 = argc,
// X21 = the original SP. They are callee-saved in AAPCS64, and every helper
// here obeys that, so nothing has to save them per call.
// --------------------------------------------------------------------
struct Startup {
    AsmBuf a;
    int adrpPos = -1, addPos = -1, blPos = -1, blPos0 = -1;
    // See Rt::newLabel: the id must come from a counter, not from labelPos.
    int nLabels = 0;
    int newLabel() { return nLabels++; }
    void u32(uint32_t w) { a.u32(w); }
    void label(int L) { a.label(L); }
    void b(int L) { a.b(L); }
    void bcc(int cc, int L) { a.bcc(cc, L); }
    void cbz(int rt, int L) { a.cbz(rt, L); }
    void cbnz(int rt, int L) { a.cbnz(rt, L); }
    void mov(int rd, int rn) { a.u32(encMov(rd, rn)); }
    void movz(int rd, uint32_t v) { a.u32(encMovz(rd, (uint16_t)(v & 0xFFFF), 0)); }
    void loadConst(int rd, uint64_t v) { a.loadConst(rd, v); }
    void addImm(int rd, int64_t v) { addUpTo(a, rd, v); }
    void addReg(int rd, int rn, int rm) { a.u32(encAddReg(rd, rn, rm)); }
    void mul(int rd, int rn, int rm) { a.u32(encMul(rd, rn, rm)); }
    void ldrX(int rt, int rn, uint16_t off) { a.u32(encLdrX(rt, rn, off)); }
    void strX(int rt, int rn, uint16_t off) { a.u32(encStrX(rt, rn, off)); }
    void cmpImm(int rn, uint16_t imm) { a.u32(encCmp(rn, imm)); }
    void cmpReg(int rn, int rm) { a.u32(encCmpReg(rn, rm)); }

    void build(const std::string& entry, const std::vector<std::string>& globalsToInit) {
        (void)globalsToInit;
        // keep the callee-saved registers we are about to use
        u32(encStpX(X19, X20, XSP, -48, kPairPre));
        u32(encStpX(X21, X30, XSP, 16, kPairOffset));

        ldrX(X20, XSP, 48);              // X20 = argc
        // X21 = the stack the kernel built. The pair above moved sp down by
        // 48 first, so the original sp -- where argc and argv[] live -- is
        // sp + 48, not sp.
        u32(encAdd(X21, XSP, 48));

        // X19 = the data segment, patched once the layout is known
        adrpPos = (int)a.c.size();
        u32(encAdrp(X19, 0, 0));
        addPos = (int)a.c.size();
        u32(encAdd(X19, X19, 0));

        scanAuxvForPageSize();

        blPos = (int)a.c.size();
        a.bl(entry);
        // main()'s return value is the process exit status
        u32(encMovz(X8, SYS_EXIT_GROUP, 0));
        u32(encSvc(0));
        u32(encB(0));                    // unreachable guard
    }

    // The auxv starts after envp's NULL. Walking it is a loop over 16-byte
    // pairs looking for AT_PAGESZ; if it is not there the default 4 KiB stays,
    // which is right for every ARM64 Android device that exists. Only x9-x11
    // are touched, so x19 (the data base), x20 (argc) and x21 (the kernel's
    // stack) survive for the rest of the program.
    void scanAuxvForPageSize() {
        int Lenv = newLabel(), LafterEnv = newLabel();
        int Laux = newLabel(), Lstore = newLabel(), Lafter = newLabel();
        int Ldone = newLabel();
        // envp = x21 + 16 + argc*8: past argc, argv[] and its NULL
        a.u32(encAdd(X9, X21, 0));
        loadConst(X10, 8);
        mul(X9, X20, X10);
        addReg(X9, X9, X21);
        addImm(X9, 16);
        label(Lenv);
        ldrX(X10, X9, 0);
        cbz(X10, LafterEnv);                // the NULL that ends envp
        addImm(X9, 8);
        b(Lenv);
        label(LafterEnv);                   // x9 = the auxv
        label(Laux);
        ldrX(X11, X9, 0);                  // the auxv type
        cbz(X11, Ldone);                   // AT_NULL
        cmpImm(X11, AT_PAGESZ_);
        bcc(1, Lstore);                    // NE -> this is the one
        b(Lafter);
        label(Lstore);
        ldrX(X10, X9, 8);                  // the value
        strX(X10, X19, 0);                 // data[0] = the real page size
        b(Ldone);
        label(Lafter);
        addImm(X9, 16);
        b(Laux);
        label(Ldone);
    }
};

} // namespace

// ====================================================================
// compile
// ====================================================================
bool IRAsmAndroid::compile(const std::string& outputPath) {
    // The peephole runs per buffer, so start its counters over: the totals
    // are read back at the end and handed to the summary line in main.cpp.
    a64PeepholeReset();
    std::vector<FnImg> imgs;
    std::unordered_map<std::string, int> nameIdx;

    // ---- which helpers does this program actually reference? ----
    // Emitting all of them would put dead code in the text segment for every
    // build; a program that only prints needs none of the file helpers.
    std::unordered_set<std::string> wanted;
    for (auto& f : ir_.functions) {
        if (f.garbage) continue;
        for (auto& in : f.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::ICall || in.op == IROp::Call) {
                if (in.b.name.compare(0, 4, "__z_") == 0) wanted.insert(in.b.name);
            } else if (in.op == IROp::PrintStr) {
                wanted.insert("__z_print_str");
            } else if (in.op == IROp::PrintInt) {
                wanted.insert("__z_print_int");
            } else if (in.op == IROp::PrintFlt) {
                wanted.insert("__z_print_float");
            }
        }
    }
    std::vector<std::string> helperOrder;
    for (auto& h : wanted) {
        helperOrder.push_back(h);
        emittedHelpers.push_back(h);
    }
    std::sort(helperOrder.begin(), helperOrder.end());
    for (auto& h : helperOrder) {
        FnImg img = buildHelper(h);
        nameIdx[h] = (int)imgs.size();
        imgs.push_back(std::move(img));
    }

    // ---- user functions ----
    int entryIdx = -1;
    for (auto& f : ir_.functions) {
        if (f.garbage || f.isExtern) continue;
        A64Fn em(f, ir_.asmBlocks);
        em.emitBody();
        FnImg img;
        img.name = f.name;
        img.bytes.swap(em.a.c);
        img.bls.swap(em.a.bls);
        img.dfs.swap(em.dfs);
        nameIdx[f.name] = (int)imgs.size();
        imgs.push_back(std::move(img));
        if (f.name == ir_.entryFunc) entryIdx = (int)imgs.size() - 1;
    }
    if (entryIdx < 0) {
        std::cerr << "IR android: entry function '" << ir_.entryFunc << "' not found" << std::endl;
        return false;
    }
    std::string entryName = imgs[(size_t)entryIdx].name;

    // ---- data layout: the page-size word, then globals, then the string pool ----
    // Every string-initialised global needs a pool entry to point at.
    for (auto& g : ir_.globals) {
        if (!g.used || !g.isString) continue;
        bool found = false;
        for (auto& s : ir_.strings)
            if (s == g.strValue) { found = true; break; }
        if (!found) ir_.strings.push_back(g.strValue);
    }
    std::vector<int> globalOff(ir_.globals.size(), -1);
    int dataBytes = 8;                       // the page-size word
    for (size_t i = 0; i < ir_.globals.size(); i++) {
        const IRGlobal& g = ir_.globals[i];
        if (!g.used) continue;
        dataBytes = (dataBytes + 7) & ~7;
        globalOff[i] = dataBytes;
        dataBytes += g.size >= 8 ? 8 : 4;
    }
    int poolBase = (dataBytes + 7) & ~7;
    std::vector<int> strOff(ir_.strings.size());
    int poolBytes = 0;
    for (size_t i = 0; i < ir_.strings.size(); i++) {
        strOff[i] = poolBytes;
        poolBytes += (int)ir_.strings[i].size() + 1;
    }
    dataBytes = poolBase + poolBytes;

    // ---- ELF layout constants ----
    // The code+data image is written after the ELF header, the .note.android.ident
    // and a page of padding, so at run time it starts at imageBase. Addresses
    // that are *baked into* the data (a string global holds the address of its
    // pool entry) therefore have to include that offset; the ADRP/ADD pairs are
    // patched image-relative and need no adjustment.
    const uint32_t kEHdrSize = 64, kPHdrSize = 56, kPHnum = 4;
    const uint32_t hdrSize = kEHdrSize + kPHnum * kPHdrSize;   // 288
    const std::string noteName = "Android";
    const std::string noteDesc = "r" + std::to_string(apiLevel_);   // "r30" == Android 11
    const uint32_t noteNameSz = (uint32_t)noteName.size() + 1;
    const uint32_t noteDescSz = (uint32_t)noteDesc.size() + 1;
    const uint32_t noteSize = 12 + ((noteNameSz + 3) & ~3u) + ((noteDescSz + 3) & ~3u);
    // Android 15 (API 35) requires 64 KiB alignment for anything that ships as an
    // app; before that 4 KiB is enough and keeps the file smaller. The kernel
    // accepts both, the *loader policy* is what changed, so it is honoured per
    // API level.
    const uint64_t kPage = (apiLevel_ >= 35) ? 0x10000ull : 0x1000ull;
    const uint32_t noteOff = hdrSize;
    const uint64_t textSegOff = ((uint64_t)noteOff + noteSize + kPage - 1) & ~(kPage - 1);
    const uint64_t imageBase = ELF_BASE + textSegOff;   // the run-time base of `image`

    // ---- assemble ----
    std::vector<uint8_t> image;
    auto pushU32 = [&](uint32_t v) {
        image.push_back((uint8_t)(v & 0xFF));
        image.push_back((uint8_t)((v >> 8) & 0xFF));
        image.push_back((uint8_t)((v >> 16) & 0xFF));
        image.push_back((uint8_t)((v >> 24) & 0xFF));
    };

    Startup st;
    st.build(entryName, {});
    // Same story as A64Fn::dfs, but for the startup's own raw slots: adrpPos,
    // addPos and blPos are patched by absolute offset after st.a.c is copied
    // into the image below.
    {
        std::vector<int> external;
        external.push_back(st.adrpPos);
        external.push_back(st.addPos);
        external.push_back(st.blPos);
        external.push_back(st.blPos0);
        A64PeepholeRun run = a64Peephole(st.a, external);
        st.adrpPos = run.remap(st.adrpPos);
        st.addPos = run.remap(st.addPos);
        st.blPos = run.remap(st.blPos);
        st.blPos0 = run.remap(st.blPos0);
    }
    st.a.resolveBranches();     // the auxv walk is loops: they need real targets
    image.insert(image.end(), st.a.c.begin(), st.a.c.end());

    std::vector<int> imgStart(imgs.size(), 0);
    for (size_t i = 0; i < imgs.size(); i++) {
        imgStart[i] = (int)image.size();
        image.insert(image.end(), imgs[i].bytes.begin(), imgs[i].bytes.end());
    }

    // The data segment starts on its own page so the ELF can give code and
    // data separate PT_LOADs; the loader requires p_offset == p_vaddr
    // (mod page size) for each of them.
    int dataStart = (int)((image.size() + 0xFFFull) & ~0xFFFull);
    image.resize((size_t)dataStart + (size_t)dataBytes, 0);

    // globals
    for (size_t i = 0; i < ir_.globals.size(); i++) {
        const IRGlobal& g = ir_.globals[i];
        if (globalOff[i] < 0) continue;
        int at = dataStart + globalOff[i];
        if (g.isString) {
            int idx = 0;
            while (idx < (int)ir_.strings.size() && ir_.strings[(size_t)idx] != g.strValue) idx++;
            if (idx >= (int)strOff.size()) continue;
            uint64_t addr = imageBase + (uint64_t)(dataStart + poolBase + strOff[(size_t)idx]);
            std::memcpy(image.data() + at, &addr, 8);
        } else if (g.isFloat) {
            float f = (float)g.floatValue;
            std::memcpy(image.data() + at, &f, 4);
        } else {
            int64_t v = g.intValue;
            std::memcpy(image.data() + at, &v, 8);
        }
    }
    // the string pool
    for (size_t i = 0; i < ir_.strings.size(); i++) {
        int at = dataStart + poolBase + strOff[i];
        std::memcpy(image.data() + at, ir_.strings[i].data(), ir_.strings[i].size());
        image[(size_t)at + ir_.strings[i].size()] = 0;
    }
    // the default page size, until the auxv says otherwise
    {
        uint64_t ps = 4096;
        std::memcpy(image.data() + dataStart + PAGE_SIZE_WORD_OFF, &ps, 8);
    }

    // ---- resolve the startup's BL to the entry function ----
    {
        int targetAbs = imgStart[(size_t)entryIdx];
        int32_t rel = (int32_t)(targetAbs - st.blPos);
        int32_t imm26 = rel / 4;
        if (imm26 < -33554432 || imm26 > 33554431) {
            std::cerr << "IR android: entry call out of range" << std::endl;
            return false;
        }
        patchU32(image, st.blPos, encBl((uint32_t)imm26));
    }
    // ---- resolve the data base in the startup ----
    {
        int32_t pageDelta = (int32_t)(((int64_t)dataStart & ~0xFFFull) -
                                       ((int64_t)st.adrpPos & ~0xFFFull)) >> 12;
        if (pageDelta < -524288 || pageDelta > 524287) {
            std::cerr << "IR android: data segment out of ADRP range" << std::endl;
            return false;
        }
        uint32_t immlo = (uint32_t)(pageDelta & 3);
        uint32_t immhi = (uint32_t)((pageDelta >> 2) & 0x7FFFF);
        patchU32(image, st.adrpPos, encAdrp(X19, immhi, immlo));
        uint32_t lo12 = (uint32_t)(dataStart & 0xFFF);
        // the page offset is the ADD's shift + imm12
        patchU32(image, st.addPos, encAddShifted(X19, X19, (uint16_t)lo12, 0, false));
    }

    // ---- resolve BLs and data references in the function bodies ----
    for (size_t i = 0; i < imgs.size(); i++) {
        int base = imgStart[i];
        for (auto& bl : imgs[i].bls) {
            auto it = nameIdx.find(bl.target);
            if (it == nameIdx.end()) {
                std::cerr << "IR android: unknown callee '" << bl.target << "'" << std::endl;
                return false;
            }
            int32_t rel = (int32_t)(imgStart[(size_t)it->second] - (base + bl.pos));
            int32_t imm26 = rel / 4;
            if (imm26 < -33554432 || imm26 > 33554431) {
                std::cerr << "IR android: call to '" << bl.target << "' out of range" << std::endl;
                return false;
            }
            patchU32(image, base + bl.pos, encBl((uint32_t)imm26));
        }
        for (auto& df : imgs[i].dfs) {
            int64_t target = -1;
            if (df.isStr) {
                if (df.strIdx >= 0 && df.strIdx < (int)strOff.size())
                    target = (int64_t)dataStart + poolBase + strOff[(size_t)df.strIdx];
            } else {
                for (size_t g = 0; g < ir_.globals.size(); g++)
                    if (ir_.globals[g].name == df.name && globalOff[g] >= 0) {
                        target = (int64_t)dataStart + globalOff[g];
                        break;
                    }
                if (target < 0) {
                    // `&func`: the reference points into the text segment,
                    // resolved exactly like a direct call target.
                    auto fnit = nameIdx.find(df.name);
                    if (fnit != nameIdx.end())
                        target = (int64_t)imgStart[(size_t)fnit->second];
                }
            }
            if (target < 0) {
                std::cerr << "IR android: unresolved data reference '" << df.name << "'" << std::endl;
                return false;
            }
            int p = base + df.pos;
            int32_t pageDelta = (int32_t)(((target & ~0xFFFull) - ((int64_t)p & ~0xFFFull)) >> 12);
            if (pageDelta < -524288 || pageDelta > 524287) {
                std::cerr << "IR android: data reference out of ADRP range" << std::endl;
                return false;
            }
            patchU32(image, p, encAdrp(df.rt, (uint32_t)((pageDelta >> 2) & 0x7FFFF),
                                       (uint32_t)(pageDelta & 3)));
            patchU32(image, p + 4, encAddShifted(df.rt, df.rt, (uint16_t)(target & 0xFFF), 0, false));
        }
    }

    // ---- ELF64 container ----
    //   0x0000  ELF header + 4 program headers
    //   0x0120  .note.android.ident -> "Android\0" / "r<api>\0"
    //   page    text: startup + helpers + user functions (R+X)
    //   page    data: the page-size word + globals + strings (R+W)
    //
    // No PT_INTERP and no DT_NEEDED: the loader maps the two PT_LOADs and
    // jumps to e_entry, so nothing from /system is needed at run time. The
    // load base is fixed (ET_EXEC), which is what Android's linker expects
    // for a non-PIE executable and what keeps the ADRP/ADD pairs valid
    // without a relocation pass.
    {
        auto put = [](uint8_t* p, uint64_t v, int off, int n) {
            for (int i = 0; i < n; i++) p[off + i] = (uint8_t)((v >> (8 * i)) & 0xFF);
        };
        const uint32_t kNTAndroidIdent = 1;

        const uint64_t dataSegOff = textSegOff + (uint64_t)dataStart;
        const uint64_t dataLen = (uint64_t)image.size() - (uint64_t)dataStart;

        const uint32_t PF_X = 1, PF_W = 2, PF_R = 4;
        const uint32_t PT_LOAD = 1, PT_NOTE = 4, PT_GNU_STACK = 0x6474e551u;
        const uint16_t ET_EXEC = 2, EM_AARCH64 = 183, EV_CURRENT = 1;

        std::vector<uint8_t> out;
        out.assign((size_t)textSegOff, 0);
        out.insert(out.end(), image.begin(), image.end());

        uint8_t* e = out.data();
        uint8_t* ph = e + kEHdrSize;
        auto writePhdr = [&](int i, uint32_t type, uint32_t flags, uint64_t off,
                            uint64_t vaddr, uint64_t filesz, uint64_t memsz, uint64_t align) {
            uint8_t* p = ph + (size_t)i * kPHdrSize;
            put(p, type, 0, 4);
            put(p, flags, 4, 4);
            put(p, off, 8, 8);
            put(p, vaddr, 16, 8);
            put(p, vaddr, 24, 8);          // p_paddr
            put(p, filesz, 32, 8);
            put(p, memsz, 40, 8);
            put(p, align, 48, 8);
        };
        writePhdr(0, PT_NOTE, PF_R, noteOff, ELF_BASE + noteOff, noteSize, noteSize, 4);
        writePhdr(1, PT_LOAD, PF_R | PF_X, 0, ELF_BASE, dataSegOff, dataSegOff, kPage);
        writePhdr(2, PT_LOAD, PF_R | PF_W, dataSegOff, ELF_BASE + dataSegOff,
                  dataLen, dataLen, kPage);
        // Android's loader refuses a process with an executable stack, so
        // state that it is not one.
        writePhdr(3, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0x10);

        {
            uint8_t* n = e + noteOff;
            put(n, noteNameSz, 0, 4);
            put(n, noteDescSz, 4, 4);
            put(n, kNTAndroidIdent, 8, 4);
            std::memcpy(n + 12, noteName.c_str(), noteName.size() + 1);
            std::memcpy(n + 12 + ((noteNameSz + 3) & ~3u), noteDesc.c_str(), noteDesc.size() + 1);
        }

        std::memset(e, 0, kEHdrSize);
        e[0] = 0x7F; e[1] = 'E'; e[2] = 'L'; e[3] = 'F';
        e[4] = 2;                        // ELFCLASS64
        e[5] = 1;                        // ELFDATA2LSB (Android is always LE)
        e[6] = EV_CURRENT;
        e[7] = 0;                        // ELFOSABI_NONE: Android uses the
                                        // generic (Linux) ABI, so SYSV would
                                        // be misleading
        put(e, ET_EXEC, 16, 2);
        put(e, EM_AARCH64, 18, 2);
        put(e, EV_CURRENT, 20, 4);
        put(e, ELF_BASE + textSegOff, 24, 8);   // e_entry
        put(e, kEHdrSize, 32, 8);               // e_phoff
        put(e, 0, 40, 8);                       // e_shoff: program headers only
        put(e, 0, 48, 4);                       // e_flags
        put(e, kEHdrSize, 52, 2);               // e_ehsize
        put(e, kPHdrSize, 54, 2);               // e_phentsize
        put(e, kPHnum, 56, 2);                  // e_phnum
        put(e, 64, 58, 2);                      // e_shentsize
        put(e, 0, 60, 2);                       // e_shnum
        put(e, 0, 62, 2);                       // e_shstrndx

        std::ofstream f(outputPath, std::ios::binary);
        if (!f) {
            std::cerr << "IR android: cannot write " << outputPath << std::endl;
            exit(1);
        }
        f.write((const char*)out.data(), (std::streamsize)out.size());
        // Trailing marker: loaders ignore trailing bytes.
        f.write((const char*)kZenithMagic, sizeof(kZenithMagic));
        f.close();
        if (!f) {
            std::cerr << "IR android: cannot write " << outputPath << std::endl;
            exit(1);
        }
    }

    peepholeStats = a64PeepholeTotals();
    return true;
}
