#include "codegen.h"
#include <cstdio>
#include <iostream>

// ============================================================================
// Linux builtin functions (app linux).
// Console I/O, timing, memory and process control go through raw x86-64
// Linux syscalls (no libc, no dynamic loader dependency). Graphics (X11) and
// GPU (Vulkan) builtins live in codegen_gui_x11.cpp / codegen_vulkan.cpp and
// are dispatched here through tryLinuxGUICall / tryLinuxVulkanCall.
//
// SysV syscall ABI (per linux x86_64):
//   nr   rax
//   arg1 rdi   arg2 rsi   arg3 rdx   arg4 r10   arg5 r8   arg6 r9
//   ret  rax
// Register pool numbers (== x86 encoding): 0=rax 1=rcx 2=rdx 3=rbx 6=rsi 7=rdi.
// ============================================================================

bool Codegen::tryLinuxGUICall(CallExpr* call, int& resultReg) {
    (void)call; (void)resultReg;
    // X11 GUI builtins: see codegen_gui_x11.cpp. Not present in this backend yet.
    return false;
}

bool Codegen::tryLinuxCall(CallExpr* call, int& resultReg) {
    const std::string& n = call->name;

    // ---- print(...) / println(s): write(1, value) + newline ----
    // Overloaded like the Windows/IR path: print("s") / print(int) /
    // print(float), each followed by a trailing newline ("\n" here).
    // eprint / eprintln do the same on fd=2 (stderr); eprintln takes the
    // argument as a raw NUL-terminated pointer (used by the selfhost lexer
    // to report errors exactly like src/lexer.cpp writes them to std::cerr).
    if (n == "print" || n == "printLn" || n == "println" ||
        n == "eprint" || n == "eprintLn" || n == "eprintln") {
        if (call->args.size() != 1) return false;

        const bool isErr = (n[0] == 'e');
        const int wfd = isErr ? 2 : 1;
        const bool wantNl = (n != "eprint");

        // Emits "mov edi,<fd>; mov eax,<nr>; syscall" — callers must have
        // already set rsi=buf and rdx=len. Uses caller-saved scratch only.
        auto wsys = [&](int fd, int nr) {
            emit8(0xBF); emit32((uint32_t)fd);   // mov edi, fd
            emit8(0xB8); emit32((uint32_t)nr);   // mov eax, nr
            emit8(0x0F); emit8(0x05);            // syscall
        };
        // write(1, buf, 1) where buf = stack byte, and the byte is in al.
        // (syscall clobbers rax, rcx, r11 — callers must re-establish state.)
        auto writeOneByte = [&]() {
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);      // sub rsp, 8
            emit8(0x88); emit8(0x04); emit8(0x24);                   // byte[rsp]=al
            emit8(0x48); emit8(0x89); emit8(0xE6);                   // mov rsi, rsp
            emit8(0xBA); emit32(1);                                  // mov edx, 1
            wsys(wfd, 1);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);      // add rsp, 8
        };

        // A `string` is an 8-byte pointer to a NUL-terminated UTF-8 literal in
        // .rdata, so a string-typed *variable* needs exactly the same handling
        // as a literal: put the pointer in rax and strlen/write it. Only
        // checking for StringExpr sent string variables down the integer branch
        // below, which printed the .rdata address instead of the text.
        bool isStringArg = dynamic_cast<StringExpr*>(call->args[0].get()) != nullptr;
        if (isErr) isStringArg = true;          // raw pointer -> NUL-string
        if (!isStringArg) {
            if (auto id = dynamic_cast<IdentExpr*>(call->args[0].get())) {
                VarInfo* vi = getVarInfo(id->name);
                if (vi && vi->type.kind == TypeKind::String && !vi->type.isPtr) isStringArg = true;
            }
        }

        if (isStringArg) {
            // ================= string argument =================
            int r = emitExpr(call->args[0].get());    // r holds the string pointer
            emitMovReg(0, r);                         // rax = ptr
            freeReg(r);

            // strlen scan: while ([rax+rcx] != 0) rcx++
            int again = newLabel();
            int done = newLabel();
            emit8(0x31); emit8(0xC9);                 // xor ecx, ecx
            emitLabel(again);
            emit8(0x80); emit8(0x3C); emit8(0x08); emit8(0x00);  // cmp byte [rax+rcx], 0
            emitJcc("==", done);
            emit8(0x48); emit8(0xFF); emit8(0xC1);    // inc rcx
            emitJmp(again);
            emitLabel(done);

            emit8(0x48); emit8(0x89); emit8(0xC6);    // mov rsi, rax  (buf)
            emit8(0x48); emit8(0x89); emit8(0xCA);    // mov rdx, rcx  (len)
            wsys(wfd, 1);                               // write(fd=1, buf, len)
        } else if (isFloatExpr(call->args[0].get())) {
            // ================= float argument =================
            // Emitted piece-by-piece like __zt_print_float (irasm.cpp):
            // sign write, integer digits write, '.', then each fraction digit.
            int fv = emitFloatExpr(call->args[0].get());
            emitMovssXmm(0, fv); freeXmmReg(fv);
            xmmRegsUsed = 1;                          // xmm0 = value

            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);      // sub rsp, 48

            // ---- sign: if negative, write '-' and clear the sign bit.
            int skipNegF = newLabel();
            emit8(0x66); emit8(0x0F); emit8(0x7E); emit8(0xC0);      // movd eax,xmm0
            emit8(0xA9); emit32(0x80000000);          // test eax,0x80000000
            emitJcc("==", skipNegF);
            emit8(0xB0); emit8(0x2D);                 // mov al,'-'
            writeOneByte();                           // write '-'
            {   int s = regsUsed; regsUsed = 0;
                int m = allocReg(); emitMovRegImm(m, 0x80000000);
                int mx = allocXmmReg(); if (mx < 0) mx = 0;
                emitMovdXmmFromGp(mx, m); freeReg(m); regsUsed = (uint8_t)s;
                emitXorps(0, mx); freeXmmReg(mx);
            }
            emitLabel(skipNegF);

            // ---- keep value, convert int part ----
            emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x44); emit8(0x24); emit8(0x20); // movss [rsp+32],xmm0
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xC0);             // cvttss2si rax,xmm0
            emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x10);             // [rsp+16]=rax (int)

            // ---- integer digits, backward from r8 = rsp+48, then write ----
            emit8(0x49); emit8(0x89); emit8(0xE0); emit8(0x49); emit8(0x83); emit8(0xC0); emit8(0x30); // r8=rsp+48
            emit8(0x45); emit8(0x31); emit8(0xC9);   // xor r9d,r9d
            int izF = newLabel(), iwF = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax,rax
            emitJcc("==", izF);
            emit8(0xB9); emit32(10);                 // ecx=10
            int ilpF = newLabel();
            emitLabel(ilpF);
            emit8(0x48); emit8(0x31); emit8(0xD2);   // xor edx,edx
            emit8(0x48); emit8(0xF7); emit8(0xF1);   // div rcx
            emit8(0x80); emit8(0xC2); emit8(0x30);   // add dl,'0'
            emit8(0x49); emit8(0xFF); emit8(0xC8);   // dec r8
            emit8(0x41); emit8(0x88); emit8(0x10);   // byte[r8]=dl
            emit8(0x41); emit8(0xFF); emit8(0xC1);   // inc r9d
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax
            emitJcc("!=", ilpF);
            emitJmp(iwF);
            emitLabel(izF);
            emit8(0x49); emit8(0xFF); emit8(0xC8);   // dec r8
            emit8(0x41); emit8(0xC6); emit8(0x00); emit8(0x30); // byte[r8]='0'
            emit8(0x41); emit8(0xFF); emit8(0xC1);   // inc r9d
            emitLabel(iwF);
            emit8(0x4C); emit8(0x89); emit8(0xC6);   // mov rsi,r8
            emit8(0x4C); emit8(0x89); emit8(0xCA);   // mov rdx,r9
            wsys(wfd, 1);                              // write integer digits

            // ---- '.'
            emit8(0xB0); emit8(0x2E);                 // mov al,'.'
            writeOneByte();

            // ---- fraction: xmm0 = value - (float)int
            emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x44); emit8(0x24); emit8(0x20); // xmm0=[rsp+32]
            emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x10);             // rcx=[rsp+16]
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xC9);             // cvtsi2ss xmm1,rcx
            emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC1);                          // subss xmm0,xmm1
            emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x44); emit8(0x24); emit8(0x20); // movss [rsp+32]=xmm0 (frac)

            emit8(0x41); emit8(0xBE); emit8(0x06); emit8(0x00); emit8(0x00); emit8(0x00); // r14d=6
            emitMovssXmmImm(2, 10.0f);               // xmm2=10
            int fTopF = newLabel(), fEndF = newLabel();
            emitLabel(fTopF);
            emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x44); emit8(0x24); emit8(0x20); // xmm0=[rsp+32](frac)
            emit8(0xF3); emit8(0x0F); emit8(0x59); emit8(0xC2);   // mulss xmm0,xmm2
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xD0);             // cvttss2si rdx,xmm0
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xDA);             // cvtsi2ss xmm3,rdx
            emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC3);   // subss xmm0,xmm3
            emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x44); emit8(0x24); emit8(0x20); // movss [rsp+32]=xmm0
            emit8(0x80); emit8(0xC2); emit8(0x30);   // add dl,'0'
            emit8(0x88); emit8(0xD0);                // mov al,dl
            writeOneByte();                          // write one fraction digit
            emit8(0x41); emit8(0xFF); emit8(0xCE);   // dec r14d
            emit8(0x45); emit8(0x85); emit8(0xF6);   // test r14d
            emitJcc("==", fEndF);
            emit8(0x66); emit8(0x0F); emit8(0x7E); emit8(0xC0);      // movd eax,xmm0
            emit8(0x85); emit8(0xC0);                // test eax,eax
            emitJcc("==", fEndF);
            emitJmp(fTopF);
            emitLabel(fEndF);

            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);   // add rsp, 48
        } else {
            // ================= int argument =================
            int r = emitExpr(call->args[0].get());
            emitMovReg(0, r); freeReg(r);             // rax = value

            // 32-byte buffer at [rsp]; digits written backwards from r8=rsp+24.
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);   // sub rsp, 32
            emit8(0x49); emit8(0x89); emit8(0xE0); emit8(0x49); emit8(0x83); emit8(0xC0); emit8(0x18); // r8=rsp+24
            emit8(0x45); emit8(0x31); emit8(0xC9);   // xor r9d, r9d

            // ---- sign: if rax < 0, write '-' first, then negate rax.
            int noNegL = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax,rax
            emitJcc(">=", noNegL);
            emit8(0x48); emit8(0x89); emit8(0x04); emit8(0x24);   // [rsp]=rax (value)
            emit8(0xB0); emit8(0x2D);                 // mov al,'-'
            writeOneByte();                           // write '-' (clobbers rax)
            emit8(0x48); emit8(0x8B); emit8(0x04); emit8(0x24);   // rax=[rsp] (value)
            emit8(0x48); emit8(0xF7); emit8(0xD8);   // neg rax
            emitLabel(noNegL);

            // ---- digits: div by 10
            emit8(0xB9); emit32(10);                 // ecx=10
            int dLp = newLabel(), dLd = newLabel();
            // handle 0 specially (loop without digits -> would print merely '-')
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax,rax
            emitJcc("==", dLd);
            emitLabel(dLp);
            emit8(0x48); emit8(0x31); emit8(0xD2);   // xor edx,edx
            emit8(0x48); emit8(0xF7); emit8(0xF1);   // div rcx
            emit8(0x80); emit8(0xC2); emit8(0x30);   // add dl,'0'
            emit8(0x49); emit8(0xFF); emit8(0xC8);   // dec r8
            emit8(0x41); emit8(0x88); emit8(0x10);   // byte[r8]=dl
            emit8(0x41); emit8(0xFF); emit8(0xC1);   // inc r9d
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax
            emitJcc("!=", dLp);
            emitLabel(dLd);

            // ---- value was 0: emit '0'
            int doneZ = newLabel();
            emit8(0x45); emit8(0x85); emit8(0xC9);   // test r9d
            emitJcc("!=", doneZ);
            emit8(0x49); emit8(0xFF); emit8(0xC8);   // dec r8
            emit8(0x41); emit8(0xC6); emit8(0x00); emit8(0x30); // byte[r8]='0'
            emit8(0x41); emit8(0xFF); emit8(0xC1);   // inc r9d
            emitLabel(doneZ);

            // ---- write digits
            emit8(0x4C); emit8(0x89); emit8(0xC6);   // mov rsi, r8
            emit8(0x4C); emit8(0x89); emit8(0xCA);   // mov rdx, r9
            wsys(wfd, 1);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32
        }

        // ---- trailing newline: write(fd, "\n", 1) from a stack byte ----
        if (wantNl) {
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);      // sub rsp, 8
            emit8(0xC6); emit8(0x04); emit8(0x24); emit8(0x0A);      // byte[rsp]=0x0A
            emit8(0x48); emit8(0x89); emit8(0xE6);                   // mov rsi, rsp
            emit8(0xBA); emit32(1);                                  // mov edx, 1
            wsys(wfd, 1);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);      // add rsp, 8
        }

        regsUsed = 1;
        xmmRegsUsed = 0;
        resultReg = 0;
        return true;
    }

    // ---- sleep(ms): nanosleep via syscall 35 (struct timespec {sec,nsec}) ----
    if (n == "sleep") {
        if (call->args.size() != 1) return false;
        int r = emitExpr(call->args[0].get());     // r holds milliseconds
        // Convert ms -> timespec into a stack scratch slot [rsp].
        // We need a writable 16-byte timespec; allocate it on the stack.
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 32

        // rax = ms ; rbx = bytes. sec = ms/1000, nsec = (ms%1000)*1000000.
        // Use signed division; ms is non-negative in practice.
        // Put ms in rax.
        emitMovReg(0, r);
        freeReg(r);
        // Copy to rcx (temp dividend), divide by 1000.
        emit8(0x48); emit8(0x89); emit8(0xC1);      // mov rcx, rax  (ms)

        // sec = ms / 1000  (unsigned): mov rax,rcx; xor edx,edx; mov ecx,1000; div ecx
        // eax = quotient(sec), edx = remainder(ms%1000)
        emit8(0x48); emit8(0x89); emit8(0xC8);      // mov rax, rcx
        emit8(0x31); emit8(0xD2);                   // xor edx, edx
        emit8(0xB9); emit32(1000);                  // mov ecx, 1000
        emit8(0xF7); emit8(0xF1);                   // div ecx   (edx:eax / ecx)

        // Store sec -> [rsp+0], nsec -> [rsp+8]
        emit8(0x48); emit8(0x89); emit8(0x04); emit8(0x24);     // mov [rsp], rax     (sec)
        // nsec = edx * 1000000
        emit8(0x89); emit8(0xD0);                   // mov eax, edx  (ms%1000)
        emit8(0x69); emit8(0xC0); emit8(0x40); emit8(0x42); emit8(0x0F); emit8(0x00); // imul eax, eax, 1000000
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x08); // mov [rsp+8], rax (nsec)

        emit8(0xB8); emit32(35);                    // mov eax, SYS_nanosleep (35)
        emit8(0x48); emit8(0x89); emit8(0xE7);      // mov rdi, rsp   (req)
        emit8(0x48); emit8(0x8D); emit8(0x74); emit8(0x24); emit8(0x10); // lea rsi,[rsp+16] (rem)
        emit8(0x0F); emit8(0x05);                   // syscall

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32

        regsUsed = 1;
        xmmRegsUsed = 0;
        resultReg = 0;
        return true;
    }

    // ---- halt() / exit(code): SYS_exit(60) ----
    if (n == "halt") {
        emitLinuxExitSyscall();
        regsUsed = 1;
        xmmRegsUsed = 0;
        resultReg = 0;
        return true;
    }
    if (n == "exit" || n == "exit_process") {
        if (call->args.size() == 1) {
            int r = emitExpr(call->args[0].get());
            emitMovReg(7, r);                       // rdi = code
            freeReg(r);
        } else {
            emit8(0x31); emit8(0xFF);               // xor edi, edi
        }
        // Prefer libc's exit() so its stdio buffers get flushed; a raw
        // exit_group syscall discarded anything puts()/printf() had buffered.
        // Falls back to the syscall for statically linked images.
        if (!emitLinuxExitViaLibc()) {
            emit8(0xB8); emit32(231);               // mov eax, SYS_exit_group
            emit8(0x0F); emit8(0x05);               // syscall
        }
        regsUsed = 1;
        xmmRegsUsed = 0;
        resultReg = 0;
        return true;
    }

        // ---- mem* allocation/access builtins (PE-совместимые) ----
        // Перенесены с Windows-пути (codegen_builtins.cpp) на Linux, поверх
        // того же bump-heap + free list, что использует alloc()/free().
        //   memNew(n)    -> ptr    (zero-fill, блок с заголовком 16 байт)
        //   memDel(p)    -> 0      (вернуть заголовок-блок в free list)
        //   memByte(p,o) -> int    (u8  по адресу p+o, ноль-расширение)
        //   memByteW(p,o,v)         (записать u8  по адресу p+o)
        //   memQ(p,o)    -> int    (u64 по адресу p+o)
        //   memQw(p,o,v)            (записать u64 по адресу p+o)
        if (n == "memNew" && call->args.size() == 1) {
            // Identical to alloc() but additionally zero-fills the payload.
            // Keeps rbx (totalSize, rounded+16) across the fill loop.
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int sizeReg = emitExpr(call->args[0].get());
            if (sizeReg != 1) { emitMovReg(1, sizeReg); freeReg(sizeReg); sizeReg = 1; }
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(15);   // add rcx, 15
            emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0);  // and rcx, -16
            emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);   // add rcx, 16 (header)
            emit8(0x48); emit8(0x89); emit8(0xCB);  // mov rbx, rcx (totalSize)
            emit8(0x48); emit8(0x8D); emit8(0x05);
            heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);   // rax = heapArea
            int mpBump = newLabel();
            int mpFail = newLabel();
            int mpDone = newLabel();
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0); // rdx = freeHead
            emit8(0x48); emit8(0x85); emit8(0xD2);   // test rdx, rdx
            emit8(0x0F); emit8(0x84);
            jmpFixups.push_back({code.size(), mpBump}); emit32(0);
            emit8(0x48); emit8(0x8B); emit8(0x4A); emit8(8);  // mov rcx, [rdx+8] (size)
            emit8(0x48); emit8(0x39); emit8(0xD9);   // cmp rcx, rbx
            emit8(0x0F); emit8(0x82);
            jmpFixups.push_back({code.size(), mpBump}); emit32(0);
            emit8(0x48); emit8(0x8B); emit8(0x0A);   // mov rcx, [rdx] (next)
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x31); emit8(0xC9);                 // xor ecx,ecx
            emit8(0x48); emit8(0x89); emit8(0x0A);   // mov [rdx], rcx
            emit8(0x48); emit8(0x8D); emit8(0x42); emit8(0x10);  // lea rax, [rdx+16]
            emitJmp(mpDone);
            emitLabel(mpBump);
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0); // rdx = offset
            emit8(0x48); emit8(0x89); emit8(0xD1);   // mov rcx, rdx
            emit8(0x48); emit8(0x01); emit8(0xD9);   // add rcx, rbx (newOffset)
            emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
            emit8(0x0F); emit8(0x87);
            jmpFixups.push_back({code.size(), mpFail}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x0D);
            heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x5C); emit8(0x10); emit8(8);  // mov [rax+rdx+8], rbx
            emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [rax+rdx+16]
            emitJmp(mpDone);
            emitLabel(mpFail);
            emit8(0x48); emit8(0x31); emit8(0xC0);   // xor eax,eax (fail=0)
            emitLabel(mpDone);
            // zero-fill payload: rep stosb with rcx = totalSize (incl. header,
            // harmless to also clear it). rbx still holds totalSize.
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax, rax
            int zSkip = newLabel();
            emitJcc("==", zSkip);
            emit8(0x48); emit8(0x89); emit8(0xC7);   // mov rdi, rax (ptr)
            emit8(0x48); emit8(0x89); emit8(0xD9);   // mov rcx, rbx (len)
            emit8(0xB0); emit8(0x00);                // mov al, 0
            emit8(0xF3); emit8(0x48); emit8(0xAA);   // rep stosb
            emitLabel(zSkip);
            freeReg(1); freeReg(2); freeReg(3);
            int r2 = allocReg(); if (r2 != 0) { emitMovReg(r2, 0); freeReg(0); }
            regsUsed = (uint8_t)(saved & ~(1 << r2));
            reloadRegs();
            regsUsed = (uint8_t)(saved | (1 << r2));
            resultReg = r2 >= 0 ? r2 : 0;
            return true;
        }
        if (n == "memDel" && call->args.size() == 1) {
            // Identical to free(): place block header back on the free list.
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int r = emitExpr(call->args[0].get());
            if (r != 1) { emitMovReg(1, r); freeReg(r); r = 1; }
            freeReg(1);
            emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0);  // lea rax, [rcx-16]
            emit8(0x48); emit8(0x8B); emit8(0x15);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emit8(0x48); emit8(0x89); emit8(0x10);   // mov [rax], rdx
            emit8(0x48); emit8(0x89); emit8(0x05);
            heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
            emitMovRegImm(0, 0);
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
// memByte(p,off) / memQ(p,off) — читать p[off]; ноль-расширение.
        auto memRead = [&](int sizeBytes) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int pr = emitExpr(call->args[0].get());
            if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
            emit8(0x50);   // push rax (p)
            int or_ = emitExpr(call->args[1].get());
            if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
            emit8(0x50);   // push rax (off)
            emit8(0x41); emit8(0x58);   // pop r8  (off)
            emit8(0x41); emit8(0x59);   // pop r9  (p)
            emit8(0x4D); emit8(0x01); emit8(0xC1);   // add r9, r8  (r9 = p+off)
            if (sizeBytes == 1)      { emit8(0x41); emit8(0x0F); emit8(0xB6); emit8(0x01); } // movzx eax, byte[r9]
            else if (sizeBytes == 2) { emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0x01); } // movzx eax, word[r9]
            else if (sizeBytes == 4) { emit8(0x41); emit8(0x8B); emit8(0x01); }              // mov eax, dword[r9]
            else                     { emit8(0x49); emit8(0x8B); emit8(0x01); }              // mov rax, qword[r9]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        };
        if (n == "memByte" && call->args.size() == 2) return memRead(1);
        if (n == "memQ"    && call->args.size() == 2) return memRead(8);
        // memByteW(p,off,v) / memQw(p,off,v) — писать v в p[off]
        auto memWrite = [&](int sizeBytes) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int pr = emitExpr(call->args[0].get());
            if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
            emit8(0x50);   // push rax (p)
            int or_ = emitExpr(call->args[1].get());
            if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
            emit8(0x50);   // push rax (off)
            int vr = emitExpr(call->args[2].get());
            if (vr != 0) { emitMovReg(0, vr); freeReg(vr); } else freeReg(0);
            emit8(0x50);   // push rax (v)
            emit8(0x41); emit8(0x58);   // pop r8  (v)
            emit8(0x41); emit8(0x59);   // pop r9  (off)
            emit8(0x41); emit8(0x5A);   // pop r10 (p)
            emit8(0x4D); emit8(0x01); emit8(0xCA);   // add r10, r9  (r10 = p+off)
            if (sizeBytes == 1)      { emit8(0x45); emit8(0x88); emit8(0x02); }              // mov [r10], r8b
            else if (sizeBytes == 2) { emit8(0x66); emit8(0x45); emit8(0x89); emit8(0x02); }  // mov [r10], r8w
            else if (sizeBytes == 4) { emit8(0x45); emit8(0x89); emit8(0x02); }              // mov [r10], r8d
            else                     { emit8(0x4D); emit8(0x89); emit8(0x02); }              // mov [r10], r8
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        };
        if (n == "memByteW" && call->args.size() == 3) return memWrite(1);
        if (n == "memQw"    && call->args.size() == 3) return memWrite(8);
    return false;
}

// ============================================================================
// Kernel-module builtins (app console/linux driver): print() -> _printk().
// printk is a variadic SysV function:
//   _printk(fmt, ...)  ->  rdi = fmt, rsi/rdx/rcx/r8/r9 = args, eax = count of
//   XMM regs used (ALWAYS zero here — we pass no float args).
// String args go through `mov rDI, sign-ext-imm32` + R_X86_64_32S (gcc
// -mcmodel=kernel style), so the same string machinery (koStrFixups) used by
// plain StringExpr references applies; the call site is a plain `call rel32`
// that buildKO() turns into R_X86_64_PC32 against the extern `_printk`.
// ============================================================================
bool Codegen::tryKOCall(CallExpr* call, int& resultReg) {
    const std::string& n = call->name;

    if (n == "print" || n == "printLn" || n == "println") {
        if (call->args.size() != 1) return false;

        // mov rdi, fmt (pointer to the string / "%d\n" for ints). A real .ko
        // wants sign-ext-imm32 (kernel addresses fit in 32 bits); a --obj
        // image is linked into a PIE host, where R_X86_64_32S is rejected —
        // it uses the same lea r,[rip+disp32] the string literals take.
        auto loadFmt = [&](int idx) {
            if (prog.objOutput) {
                emit8(0x48); emit8(0x8D); emit8(0x3D);   // lea rdi, [rip+disp32]
                strFixups.push_back({code.size(), idx});
                emit32(0);
                return;
            }
            emit8(0x48); emit8(0xC7); emit8(0xC7);   // mov rdi, imm32 (sign-ext)
            size_t fixupPos = code.size();
            emit32(0);
            koStrFixups.push_back({fixupPos, idx});
        };

        if (auto str = dynamic_cast<StringExpr*>(call->args[0].get())) {
            // WARNING: printk treats % in the format string specially; driver
            // authors must avoid '%' (use "%%" if literally needed).
            loadFmt(ensureString(str->value));
        } else if (isFloatExpr(call->args[0].get())) {
            std::cerr << "Error: print(float) is not supported in driver (kernel-module) mode; use an integer.\n";
            throw std::runtime_error("print(float) unsupported in .ko driver");
        } else {
            // String-typed variable -> _printk(ptr); anything else -> _printk("%d\n", int).
            bool isStrVar = false;
            if (auto id = dynamic_cast<IdentExpr*>(call->args[0].get())) {
                VarInfo* vi = getVarInfo(id->name);
                if (vi && vi->type.kind == TypeKind::String && !vi->type.isPtr) isStrVar = true;
            }
            int r = emitExpr(call->args[0].get());
            if (isStrVar) {
                emitMovReg(7, r);                        // rdi = string pointer
            } else {
                loadFmt(ensureString("%d\n"));           // rdi = "%d\n"
                emitMovReg(6, r);                        // rsi = value
            }
            freeReg(r);
        }

        emit8(0x31); emit8(0xC0);                    // xor eax, eax (no XMM args)
        emit8(0xE8);
        size_t fixupPos = code.size();
        emit32(0);
        koExtCallFixups.push_back({fixupPos, "_printk"});

        regsUsed = 0;
        xmmRegsUsed = 0;
        resultReg = 0;
        return true;
    }

    // ---- ring-0 hardware builtins ----
    // These only make sense inside a kernel module (they execute at CPL0 and
    // touch real hardware). They use the same register-preservation discipline
    // as the userspace builtins: everything is spilled, the instruction runs,
    // live registers are reloaded.
    if (prog.koDriver) {
        // rdtsc() -> 64-bit Time-Stamp Counter, for timing/profiling.
        if (n == "rdtsc" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            emit8(0x0F); emit8(0x31);   // rdtsc (edx:eax)
            emit8(0x48); emit8(0xC1); emit8(0xE2); emit8(0x20); // shl rdx, 32
            emit8(0x48); emit8(0x09); emit8(0xC2); // or rdx, rax
            emit8(0x48); emit8(0x89); emit8(0xD0); // mov rax, rdx
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }

        // io_delay() — classic post-port (0x80) two-cycle delay.
        if (n == "io_delay" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            emit8(0xBA); emit8(0x80); emit8(0x00); emit8(0x00); emit8(0x00); // mov edx, 0x80
            emit8(0xB0); emit8(0x00); // mov al, 0
            emit8(0xEE);              // out dx, al
            emit8(0xEE);              // out dx, al
            regsUsed = (uint8_t)saved;
            reloadRegs();
            regsUsed = 1;
            resultReg = 0;
            return true;
        }

        // outb(port, val): out dx, al
        if (n == "outb" && call->args.size() == 2) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int portReg = emitExpr(call->args[0].get());
            if (portReg != 0) { emitMovReg(0, portReg); freeReg(portReg); }
            else freeReg(0);
            emit8(0x50); // push port (rax)
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50); // push val (rax)
            emit8(0x58); // pop rax (val)
            emit8(0x5A); // pop rdx (port)
            emit8(0xEE); // out dx, al
            regsUsed = (uint8_t)saved;
            reloadRegs();
            regsUsed = 1;
            resultReg = 0;
            return true;
        }

        // inb(port) -> byte: in al, dx
        if (n == "inb" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int portReg = emitExpr(call->args[0].get());
            if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
            else freeReg(2);
            emit8(0xEC); // in al, dx
            emit8(0x0F); emit8(0xB6); emit8(0xC0); // movzx eax, al
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }

        // ---- KO memory access builtins (peek*/poke*) ----
        // Direct reads/writes of kernel memory at a raw address; the driver is
        // responsible for the pointer being valid (e.g. from kalloc/kzalloc).
        // Previously only reachable on EFI/Bare/GUI paths (tryBuiltinCall is
        // never dispatched for app linux), so drivers fell back to a bogus
        // `call` to a missing function -> stack-corrupting Oops. Now inlined.
        auto peek = [&](int sizeBytes) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            if (sizeBytes == 1)      { emit8(0x0F); emit8(0xB6); emit8(0x00); } // movzx eax, byte [rax]
            else if (sizeBytes == 2) { emit8(0x0F); emit8(0xB7); emit8(0x00); } // movzx eax, word [rax]
            else if (sizeBytes == 4) { emit8(0x8B); emit8(0x00); }              // mov eax, dword [rax]
            else                     { emit8(0x48); emit8(0x8B); emit8(0x00); } // mov rax, qword [rax]
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        };
        auto poke = [&](int sizeBytes) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int valReg = emitExpr(call->args[1].get());
            if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
            else freeReg(0);
            emit8(0x50);  // push rax (val)
            int addrReg = emitExpr(call->args[0].get());
            if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
            else freeReg(0);
            emit8(0x5A);  // pop rdx (val)
            if (sizeBytes == 1)      { emit8(0x88); emit8(0x10); }              // mov [rax], dl
            else if (sizeBytes == 2) { emit8(0x66); emit8(0x89); emit8(0x10); } // mov [rax], dx
            else if (sizeBytes == 4) { emit8(0x89); emit8(0x10); }              // mov [rax], edx
            else                     { emit8(0x48); emit8(0x89); emit8(0x10); } // mov [rax], rdx
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        };
        if (n == "peek8"  && call->args.size() == 1) return peek(1);
        if (n == "peek16" && call->args.size() == 1) return peek(2);
        if (n == "peek32" && call->args.size() == 1) return peek(4);
        if (n == "peek64" && call->args.size() == 1) return peek(8);
        if (n == "poke8"  && call->args.size() == 2) return poke(1);
        if (n == "poke16" && call->args.size() == 2) return poke(2);
        if (n == "poke32" && call->args.size() == 2) return poke(4);
        if (n == "poke64" && call->args.size() == 2) return poke(8);


        // ---- kernel API imports ----
        // Calls into exported kernel functions (SysV: rdi,rsi,rdx,rcx,r8,r9 +
        // rax result). Each symbol must have a matching SHN_UNDEF entry in
        // buildKO's syms[] (codegen_ko.cpp) or linking fails.
        auto koCall = [&](const std::string& sym) {
            emit8(0xE8);
            size_t fixupPos = code.size();
            emit32(0);
            koExtCallFixups.push_back({fixupPos, sym});
        };
        // kalloc(size) -> ptr  (kernel allocation with GFP_KERNEL = 0xCC0)
        // Maps to __kmalloc_noprof on kernel 6.12 "noprof" export names.
        // `alloc` is the portable spelling (the same name the userspace
        // backends route to the bump heap); in driver/--obj mode it maps here
        // so a source can allocate without target-specific builtins. A --obj
        // image runs in a userspace host, so there `alloc`/`free` are plain
        // libc malloc/free instead of the kernel allocator.
        if ((n == "kalloc" || n == "alloc") && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int r = emitExpr(call->args[0].get());
            if (r != 7) { emitMovReg(7, r); freeReg(r); }   // rdi = size
            else freeReg(7);
            if (prog.objOutput) {
                koCall("malloc");
            } else {
                emit8(0xBE); emit32(0xCC0);                    // mov esi, GFP_KERNEL
                koCall("__kmalloc_noprof");
            }
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
        // kfree(ptr) — `free` is the portable spelling of the same call.
        if ((n == "kfree" || n == "free") && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int r = emitExpr(call->args[0].get());
            if (r != 7) { emitMovReg(7, r); freeReg(r); }   // rdi = ptr
            else freeReg(7);
            koCall(prog.objOutput ? "free" : "kfree");
            regsUsed = (uint8_t)saved;
            reloadRegs();
            regsUsed = 1;
            resultReg = 0;
            return true;
        }
        // kzalloc(size) -> ptr  (kalloc + zero-fill; the classic kernel "calloc").
        // Allocates with __kmalloc_noprof and zeroes `size` bytes starting at the
        // returned pointer (rep stosb) before handing it to the caller.
        if (n == "kzalloc" && call->args.size() == 1) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            int r = emitExpr(call->args[0].get());
            if (r != 7) { emitMovReg(7, r); freeReg(r); }   // rdi = size
            else freeReg(7);
            // stash size in r12 (callee-saved, survives the __kmalloc call)
            emit8(0x49); emit8(0x89); emit8(0xFC);          // mov r12, rdi  (size)
            emit8(0xBE); emit32(0xCC0);                     // mov esi, GFP_KERNEL
            koCall("__kmalloc_noprof");
            // rax = ptr (or 0). Zero fill: if (ptr) for (i=0;i<size;i++) ptr[i]=0
            int l_zero = newLabel(), d_zero = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);          // test rax, rax
            emitJcc("==", d_zero);
            emit8(0x49); emit8(0x89); emit8(0xC7);          // mov r15, rax  (dst)
            emit8(0x48); emit8(0x89); emit8(0xC1);          // mov rcx, rax  (ptr for stosb)
            emit8(0x49); emit8(0x8B); emit8(0xD4);          // mov rdx, r12  (size)
            emit8(0xB0); emit8(0x00);                       // mov al, 0
            emit8(0xF3); emit8(0x48); emit8(0xAA);          // rep stosb
            emit8(0x4C); emit8(0x89); emit8(0xF8);          // mov rax, r15  (restore ptr)
            emitLabel(d_zero);
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
        // ktime_ms() -> int64 milliseconds since boot (boot clock).
        if (n == "ktime_ms" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            koCall("ktime_get_boot_fast_ns");
            // rax = ns; convert to ms: (ns + 500000) / 1000000 via unsigned div.
            emit8(0x48); emit8(0x05); emit32(500000);        // add rax, 500000
            emit8(0x48); emit8(0x31); emit8(0xD2);           // xor edx, edx
            emit8(0xBE); emit32(1000000);                    // mov esi, 1000000
            emit8(0x48); emit8(0xF7); emit8(0xF6);           // div rsi
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
        // ktime_ns() -> int64 nanoseconds since boot (boot clock, monotonic-ish)
        if (n == "ktime_ns" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            koCall("ktime_get_boot_fast_ns");
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
        // jiffies() -> int kernel internal timebase (volatile unsigned long)
        if (n == "jiffies" && call->args.size() == 0) {
            int saved = regsUsed;
            spillRegs();
            regsUsed = 0;
            emit8(0x48); emit8(0x8B); emit8(0x05);   // mov rax, [rip+disp32]
            size_t fixupPos = code.size();
            emit32(0);
            koDataFixups.push_back({fixupPos, "jiffies"});
            regsUsed = (uint8_t)(saved & ~1);
            reloadRegs();
            regsUsed = (uint8_t)(saved | 1);
            resultReg = 0;
            return true;
        }
    }

    return false;
}
