#include "andropt.h"
#include <algorithm>
#include <cstring>

// ====================================================================
// The syscall table
//
// Linux/AArch64 uses the asm-generic syscall table (include/uapi/
// asm-generic/unistd.h) and Android inherits it unchanged — Bionic is just
// a C library on top of it, and a static binary does not even use Bionic.
// The numbers are therefore the same on every 64-bit Android device, which
// is what makes the inlining below safe.
//
// minApi is the API level that first exposed the call *in Android*; a device
// older than that may run a kernel without it, so the pass falls back.
// A raw static binary talks to the kernel, not to Bionic, so this is a
// conservative floor: `min_sdk:` is a promise about the device, and the
// promise is what the generated code has to keep.
// ====================================================================
const AndroidSyscall kAndroidSyscalls[] = {
    // inlinable: the Zenith arguments already sit in x0..xN in the order the
    // kernel reads them, so the call is just "mov x8, #nr; svc #0".
    { "__z_file_read",       63,  3, kClampRaw,           21, nullptr, 1 },
    { "__z_file_write",      64,  3, kClampRaw,           21, nullptr, 1 },
    { "__z_file_pread",      67,  4, kClampRaw,           21, nullptr, 1 },
    { "__z_file_pwrite",     68,  4, kClampRaw,           21, nullptr, 1 },
    { "__z_file_close",      57,  1, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_file_fsync",      82,  1, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_file_lseek",      62,  3, kClampRaw,           21, nullptr, 1 },
    { "__z_file_truncate",   46,  2, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_munmap",         215,  2, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_madvise",        233,  3, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_sched_yield",    124,  0, kClampZeroOkToOne,   21, nullptr, 1 },
    { "__z_getuid",         174,  0, kClampRaw,           21, nullptr, 1 },
    { "__z_geteuid",        175,  0, kClampRaw,           21, nullptr, 1 },
    { "__z_getgid",         176,  0, kClampRaw,           21, nullptr, 1 },
    { "__z_getpid",         172,  0, kClampRaw,           21, nullptr, 1 },
    { "__z_exit",            94,  1, kClampRaw,           21, nullptr, 1 },
    { "__z_mmap",           222,  6, kClampErrToZero,     21, nullptr, 1 },
    // getrandom landed in Android at API 28 and statx at API 30. Both have
    // a pre-existing equivalent, so a program that declares a lower
    // `min_sdk:` gets the older route instead of an ENOSYS at run time.
    { "__z_random_bytes",   278,  3, kClampErrToZero,     28, "__z_random_bytes_legacy", 1 },
    { "__z_file_size",      291,  5, kClampErrToZero,     30, "__z_file_size_legacy", 0 },
    // Not inlinable: the kernel wants AT_FDCWD in x0, and statx also needs a
    // 256-byte struct on a stack frame, so the argument order cannot be
    // produced by "load the arguments, then svc".
    { "__z_file_open",       56,  4, kClampErrToZero,     21, nullptr, 0 },
    { "__z_file_unlink",     35,  3, kClampZeroOkToOne,   21, nullptr, 0 },
    { "__z_file_rename",     38,  4, kClampZeroOkToOne,   21, nullptr, 0 },
    { "__z_file_mkdir",      34,  3, kClampZeroOkToOne,   21, nullptr, 0 },
    { "__z_memfd_create",   279,  2, kClampErrToZero,     30, nullptr, 0 },
};
const int kAndroidSyscallCount = (int)(sizeof(kAndroidSyscalls) / sizeof(kAndroidSyscalls[0]));

static int sysNr(const char* helper) {
    for (int i = 0; i < kAndroidSyscallCount; i++)
        if (std::strcmp(helper, kAndroidSyscalls[i].helper) == 0) return kAndroidSyscalls[i].nr;
    return -1;
}

const AndroidSyscall* Andropt::findSyscall(const std::string& helper) const {
    for (int i = 0; i < kAndroidSyscallCount; i++)
        if (helper == kAndroidSyscalls[i].helper) return &kAndroidSyscalls[i];
    return nullptr;
}

int Andropt::poolString(const std::string& s) {
    for (size_t i = 0; i < ir_.strings.size(); i++)
        if (ir_.strings[i] == s) return (int)i;
    ir_.strings.push_back(s);
    return (int)ir_.strings.size() - 1;
}

void Andropt::run() {
    for (auto& f : ir_.functions)
        if (!f.garbage) stats.instrsBefore += (int)f.instrs.size();

    apiGate();              // rewrite first: it decides which helper is called
    inlineSyscalls();      // then inline what is left that is a bare syscall
    fuseLiteralWrites();   // then fold literal output into one write(2)

    for (auto& f : ir_.functions)
        if (!f.garbage) stats.instrsAfter += (int)f.instrs.size();
}

// --------------------------------------------------------------------
// 1. One syscall, no helper
//
//   Arg 0 fd ; Arg 1 buf ; Arg 2 len ; ICall r __z_file_read 3
//     ->  Arg 0 fd ; Arg 1 buf ; Arg 2 len ; Syscall r, nr=63, clamp=raw
//
// The helper body was `svc #0; cmp x0, -4095; movz x0, 0; ret`, reached
// through a BL, a stack frame and a saved LR. All of that disappears: the
// syscall becomes three instructions in place (load the arguments, mov x8,
// svc) and the result lands straight in its frame slot.
// --------------------------------------------------------------------
void Andropt::inlineSyscalls() {
    for (auto& fn : ir_.functions) {
        if (fn.garbage) continue;
        auto& in = fn.instrs;
        for (size_t i = 0; i < in.size(); i++) {
            if (in[i].garbage || in[i].op != IROp::ICall) continue;
            const AndroidSyscall* sc = findSyscall(in[i].b.name);
            if (!sc || !sc->inlinable) continue;
            int nargs = (int)in[i].c.imm;
            if (nargs < 0 || nargs > sc->arity) continue;   // too many args
            if (in[i].b.kind == IROperand::Import && in[i].b.dll == "legacy") continue;

            // the Arg instructions have to sit directly in front of the call
            // and name frame slots, one per argument
            int first = (int)i;
            int seen = 0;
            bool ok = true;
            while (first > 0 && seen < nargs) {
                IRInstr& p = in[(size_t)first - 1];
                if (p.garbage || p.op != IROp::Arg) break;
                if (p.b.kind != IROperand::Reg || (int)p.a.imm != nargs - 1 - seen) { ok = false; break; }
                first--;
                seen++;
            }
            if (!ok || seen != nargs) continue;
            if (first > 0 && in[(size_t)first - 1].op == IROp::Arg &&
                !in[(size_t)first - 1].garbage)
                continue;   // more Args than the call consumes: leave it alone

            // extra argument registers the kernel reads but Zenith does not
            // pass are zero, the same value the helper body writes there
            int icall = (int)i;
            for (int k = nargs; k < sc->arity; k++) {
                int z = fn.maxSlot++;
                IRInstr c;
                c.op = IROp::Const;
                c.a = IROperand::mkReg(z);
                c.b = IROperand::mkImm(0);
                in.insert(in.begin() + icall, c);
                icall++;
                IRInstr ar;
                ar.op = IROp::Arg;
                ar.a = IROperand::mkImm(k);
                ar.b = IROperand::mkReg(z);
                in.insert(in.begin() + icall, ar);
                icall++;
            }

            IRInstr s;
            s.op = IROp::Syscall;
            s.a = in[(size_t)icall].a;
            s.a.imm = sc->nr;
            s.a.off = sc->clamp;
            s.c = IROperand::mkImm(sc->arity);
            s.cond = in[(size_t)icall].b.name;   // keep the name for reports/debug
            in[(size_t)icall] = s;
            i = (size_t)icall + 1;
            stats.syscallsInlined++;
        }
    }
}

// --------------------------------------------------------------------
// 2. println("text") is one write(2), not two plus a strlen walk
//
// The IR models output as "print the string, then the newline", and the
// backend's generic lowering is a call into the string printer followed by
// a second call for the '\n' — two write(2) syscalls and a scan over the
// bytes to measure them. When the argument is a literal the length is known
// here, at compile time, so the whole thing collapses into:
//
//   write(1, "text\n", 6)
//
// A single syscall, no call, no loop. This is the difference that shows up
// in `strace` output and in logcat: a program that prints a line of text
// costs the kernel one write instead of two.
// --------------------------------------------------------------------
void Andropt::fuseLiteralWrites() {
    for (auto& fn : ir_.functions) {
        if (fn.garbage) continue;
        auto& in = fn.instrs;
        for (size_t i = 0; i < in.size(); i++) {
            if (in[i].garbage || in[i].op != IROp::PrintStr) continue;
            if (in[i].a.kind != IROperand::StrIdx) continue;   // a variable: needs strlen
            if (in[i].a.off != 0) continue;                     // print(): no newline
            int idx = in[i].a.strIdx;
            if (idx < 0 || idx >= (int)ir_.strings.size()) continue;
            std::string s = ir_.strings[(size_t)idx];   // copy: poolString may reallocate
            if (s.empty()) continue;

            // the literal with its newline usually lives in the pool already
            // (println lowered both halves separately); if not, add it. Either
            // way the bytes end up in the read-only segment and the length is
            // a compile-time constant.
            int withNl = poolString(s + "\n");
            int n = (int)ir_.strings[(size_t)withNl].size();
            int fdSlot = fn.maxSlot++;
            int bufSlot = fn.maxSlot++;
            int lenSlot = fn.maxSlot++;

            std::vector<IRInstr> out;
            IRInstr c;
            c.op = IROp::Const;   c.a = IROperand::mkReg(fdSlot);
            c.b = IROperand::mkImm(1);                    // STDOUT_FILENO
            out.push_back(c);
            IRInstr ar;
            ar.op = IROp::Arg; ar.a = IROperand::mkImm(0); ar.b = IROperand::mkReg(fdSlot);
            out.push_back(ar);
            IRInstr st;
            st.op = IROp::Str; st.a = IROperand::mkReg(bufSlot);
            st.b = IROperand::str(withNl);
            out.push_back(st);
            ar.a = IROperand::mkImm(1); ar.b = IROperand::mkReg(bufSlot);
            out.push_back(ar);
            c.a = IROperand::mkReg(lenSlot); c.b = IROperand::mkImm(n);
            out.push_back(c);
            ar.a = IROperand::mkImm(2); ar.b = IROperand::mkReg(lenSlot);
            out.push_back(ar);
            IRInstr sc;
            sc.op = IROp::Syscall;
            sc.a = IROperand::mkReg(fn.maxSlot++);        // result: not used by println
            sc.a.imm = sysNr("__z_file_write");           // write
            sc.a.off = kClampRaw;                          // a partial write is fine
            sc.c = IROperand::mkImm(3);
            sc.cond = "write";
            out.push_back(sc);

            in.erase(in.begin() + (long)i);
            in.insert(in.begin() + (long)i, out.begin(), out.end());
            i += out.size() - 1;
            stats.writesFused++;
        }
    }
}

// --------------------------------------------------------------------
// 3. The device's release level decides the route
//
// `min_sdk:` is a promise about the device the binary is meant to run on.
// Two of the syscalls the runtime uses did not exist on the older releases
// that promise can cover:
//
//   getrandom  API 28  ->  open("/dev/urandom") + read + close
//   statx      API 30  ->  open + lseek(SEEK_END) + close
//
// Both substitutes need no new primitive: they are the same file helpers
// the rest of the runtime already uses, wrapped in a helper so the call
// site stays a call. A program that targets Android 11+ keeps the direct
// syscall; only a program that asks for an older device pays for the
// longer route.
// --------------------------------------------------------------------
void Andropt::apiGate() {
    for (auto& fn : ir_.functions) {
        if (fn.garbage) continue;
        for (auto& in : fn.instrs) {
            if (in.garbage || in.op != IROp::ICall) continue;
            const AndroidSyscall* sc = findSyscall(in.b.name);
            if (!sc || !sc->legacy || sc->minApi == 0) continue;
            if (minSdk_ >= (uint32_t)sc->minApi) continue;   // the device has it
            in.b.name = sc->legacy;
            stats.fallbacks++;
            notes.push_back(std::string(sc->helper) + " -> " + sc->legacy +
                            " (min_sdk " + std::to_string(minSdk_) + " < " +
                            std::to_string(sc->minApi) + ")");
        }
    }
}
