#include "codegen.h"

// =====================================================================
// Wayland client builtins for the Linux target (app linux) — raw socket
// + hand-encoded wire protocol. No libwayland, no libc: every byte of the
// display connection lives in the emitted x86-64 machine code.
//
//   wl_open()         -> connected display socket fd | -1
//   wl_list_globals() -> roundtrip: print all advertised registry globals
//                        as "interface:name:version" lines, return the count
//   wl_close(fd)      -> 0 | -1
//
// Wire protocol (little-endian, native on x86-64), header is 8 bytes:
//   u32 object id ; u16 opcode ; u16 message size (bytes incl the 8-byte
//   header; the high bits of libwayland's 32-bit size field are the opcode).
//   Payload: u (u32), i (i32), s (u32 byte-len incl NUL + NUL-terminated
//   string padded to 4), o (u32 object id), n (u32 new object id).
//
// Handshake built as a static .rdata blob:
//   wl_display.get_registry(new_id=2): id=1 opcode=1 size=12, arg u(2)
//   wl_display.sync(new_id=3):         id=1 opcode=0 size=12, arg u(3)
// The compositor answers with registry.global events (id 2) and finishes the
// roundtrip with callback.done (id 3). Events are parsed from the raw buffer.
//
// The display socket path is $XDG_RUNTIME_DIR/wayland-0. XDG_RUNTIME_DIR is
// scanned raw from the envp array, which _start stashes into wlEnvRVA before
// main runs. Socket: AF_UNIX/SOCK_STREAM (syscall 41), connect (42),
// read (0) / write (1), close (3).
// =====================================================================

// ============================================================================
// Usage pre-scan: mirrors detectVkUsage/detectNetSockUsage so
// buildLinuxImportData allocates the wl_* slots before buildELF patches them.
// ============================================================================
void detectWLExpr(Codegen* self, Expr* e, bool& used);
void detectWLStmt(Codegen* self, Stmt* s, bool& used);

void Codegen::detectWLUsage() {
    if (wlUsed) return;
    for (auto& func : prog.functions) {
        if (func->isExtern) continue;
        for (auto& stmt : func->body.stmts) detectWLStmt(this, stmt.get(), wlUsed);
        if (wlUsed) break;
    }
    for (auto& g : prog.globals) {
        if (g->init) detectWLExpr(this, g->init.get(), wlUsed);
        if (wlUsed) break;
    }
}

void detectWLExpr(Codegen* self, Expr* e, bool& used) {
    (void)self;
    if (!e) return;
    if (auto call = dynamic_cast<CallExpr*>(e)) {
        if (call->name.rfind("wl_", 0) == 0) used = true;
        for (auto& arg : call->args) detectWLExpr(self, arg.get(), used);
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        detectWLExpr(self, bin->left.get(), used);
        detectWLExpr(self, bin->right.get(), used);
    } else if (auto memb = dynamic_cast<MemberExpr*>(e)) {
        detectWLExpr(self, memb->object.get(), used);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        detectWLExpr(self, arr->array.get(), used);
        detectWLExpr(self, arr->index.get(), used);
    } else if (auto un = dynamic_cast<UnaryExpr*>(e)) {
        detectWLExpr(self, un->operand.get(), used);
    }
}

void detectWLStmt(Codegen* self, Stmt* s, bool& used) {
    (void)self;
    if (!s) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) {
        detectWLExpr(self, ret->value.get(), used);
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(s)) {
        detectWLExpr(self, exprStmt->expr.get(), used);
    } else if (auto varDecl = dynamic_cast<VarDecl*>(s)) {
        detectWLExpr(self, varDecl->init.get(), used);
    } else if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        detectWLExpr(self, ifs->condition.get(), used);
        for (auto& st : ifs->thenBlock.stmts) detectWLStmt(self, st.get(), used);
        for (auto& st : ifs->elseBlock.stmts) detectWLStmt(self, st.get(), used);
    } else if (auto wh = dynamic_cast<WhileStmt*>(s)) {
        detectWLExpr(self, wh->condition.get(), used);
        for (auto& st : wh->body.stmts) detectWLStmt(self, st.get(), used);
    } else if (auto loop = dynamic_cast<LoopStmt*>(s)) {
        for (auto& st : loop->body.stmts) detectWLStmt(self, st.get(), used);
    } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
        detectWLExpr(self, fs->start.get(), used);
        detectWLExpr(self, fs->end.get(), used);
        detectWLExpr(self, fs->step.get(), used);
        for (auto& st : fs->body.stmts) detectWLStmt(self, st.get(), used);
    }
}

// ============================================================================
// tryLinuxWLCall: emits the machine code for one wl_* builtin (resultReg set),
// or returns false for anything else. State kept in r12/r13/r14 (callee-saved,
// pushed here) plus rbx/r8 (syscall-preserved); SysV ABI: nr in rax, args in
// rdi,rsi,rdx,r10,r8,r9.
// ============================================================================
bool Codegen::tryLinuxWLCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;

    // Window / shm-framebuffer builtins live in codegen_wl_window.cpp.
    if (name == "wl_create_window" || name == "wl_present" ||
        name == "wl_process" || name == "wl_close_window" ||
        name == "wl_fb" || name == "wl_pixel")
        return tryLinuxWLWindowCall(call, resultReg);

    const bool isWLBuiltin = (name == "wl_open" || name == "wl_list_globals" ||
                              name == "wl_close");
    if (!isWLBuiltin) return false;
    if ((name == "wl_open" || name == "wl_list_globals") && !call->args.empty()) return false;
    if (name == "wl_close" && call->args.size() != 1) return false;

    wlUsed = true;

    // Staging mirrors net/vulkan: spill, pause allocation, push callee-saved
    // rdi (7) / rsi (6) and the out-of-pool r12/r13/r14.
    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);  // sub rsp, 8 (pad)
    emit8(0x57);              // push rdi
    emit8(0x56);              // push rsi
    emit8(0x41); emit8(0x54); // push r12
    emit8(0x41); emit8(0x55); // push r13
    emit8(0x41); emit8(0x56); // push r14

    int wlExit = newLabel();

    // lea reg, [rip + slotRVA] (general regs 0..15).
    auto leaRip = [&](int r, uint32_t rva) {
        if (r >= 8) emit8(0x4C); else emit8(0x48);
        emit8(0x8D);
        emit8((uint8_t)(0x05 | ((r & 7) << 3)));
        globalFixups.push_back({code.size(), rva});
        emit32(0);
    };
    // syscall with nr loaded into rax.
    auto svc = [&](uint32_t nr) {
        emit8(0xB8); emit32(nr);
        emit8(0x0F); emit8(0x05);
    };
    // pop the staged registers + the alignment pad, jump to the exit label.
    auto wlLeave = [&](int label) {
        emit8(0x41); emit8(0x5E);  // pop r14
        emit8(0x41); emit8(0x5D);  // pop r13
        emit8(0x41); emit8(0x5C);  // pop r12
        emit8(0x5E);               // pop rsi
        emit8(0x5F);               // pop rdi
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);  // add rsp, 8
        emitJmp(label);
    };
    // Inline decimal printer: writes u32 eax to stdout (div by 10 loop into a
    // reverse scratch buffer). Clobbers rax,rcx,rdx,rsi,rdi,r9 — preserves rbx,
    // r8, r12, r13, r14 (not r9: used as the transient divisor only).
    auto emitDecWrite = [&]() {
        leaRip(7, wlTmpRVA);                        // rdi = &scratch
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x1F); // rdi += 31
        emit8(0x51);                                // push rcx (event ptr saved)
        emit8(0x31); emit8(0xC9);                   // xor ecx, ecx (digit count)
        emit8(0x41); emit8(0xB9); emit32(10);       // r9d = 10
        int decTop = newLabel();
        emitLabel(decTop);
        emit8(0x31); emit8(0xD2);                   // xor edx, edx
        emit8(0x41); emit8(0xF7); emit8(0xF1);      // div r9d (eax=quot, edx=rem)
        emit8(0x80); emit8(0xC2); emit8(0x30);      // add dl, '0'
        emit8(0x48); emit8(0xFF); emit8(0xCF);      // dec rdi
        emit8(0x88); emit8(0x17);                   // mov [rdi], dl
        emit8(0xFF); emit8(0xC1);                   // inc ecx
        emit8(0x85); emit8(0xC0);                   // test eax, eax
        emitJcc("!=", decTop);
        emit8(0x48); emit8(0x89); emit8(0xFE);      // rsi = rdi (digits)
        emit8(0x48); emit8(0x89); emit8(0xCA);      // rdx = rcx (len)
        emit8(0xBF); emit32(1);                     // rdi = 1 (stdout)
        svc(1);                                     // write(1, digits, len)
        emit8(0x59);                                // pop rcx (restore event ptr)
    };

    // ---- wl_open() -> connected display socket fd | -1 ----
    if (name == "wl_open") {
        int done = newLabel();
        int sockFail = newLabel();          // socket() itself failed (fd not open)
        int envFail = newLabel();           // env missing / connect failed (fd open)
        int connFail = newLabel();

        // fd = socket(AF_UNIX=1, SOCK_STREAM|SOCK_CLOEXEC=0x80001, 0)
        emit8(0xBF); emit32(1);                 // rdi = AF_UNIX
        emit8(0xBE); emit32(0x80001);           // rsi = SOCK_STREAM | SOCK_CLOEXEC
        emit8(0xBA); emit32(0);                 // rdx = 0
        svc(41);                                // socket
        emitJcc("<", sockFail);                 // rax < 0 -> socket failed
        emit8(0x49); emit8(0x89); emit8(0xC4);  // r12 = fd

        // Build sun.sun_path = "$XDG_RUNTIME_DIR/wayland-0" at [wlPathRVA+2].
        leaRip(2, wlPathRVA);                   // rdx = &sun
        emit8(0x66); emit8(0xC7); emit8(0x02); emit16(1); // word [rdx] = AF_UNIX
        leaRip(7, wlPathRVA);
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x02); // rdi = &sun.sun_path
        emit8(0x49); emit8(0x89); emit8(0xF9);  // r9 = sun.sun_path base

        // Scan envp (rab slot wlEnvRVA) for the "XDG_RUNTIME_DIR=" prefix.
        leaRip(8, wlEnvRVA);
        emit8(0x4D); emit8(0x8B); emit8(0x00);  // r8 = [r8] (envp array)
        leaRip(7, wlXdgRVA);                    // rdi = prefix string
        int envNext = newLabel(), preCmp = newLabel(), envInc = newLabel();
        emitLabel(envNext);
        emit8(0x49); emit8(0x8B); emit8(0x30);  // rsi = [r8] (env string)
        emit8(0x48); emit8(0x85); emit8(0xF6);  // test rsi, rsi
        emitJcc("==", envFail);                 // end of envp -> no XDG_RUNTIME_DIR
        emit8(0x31); emit8(0xC9);               // xor ecx, ecx
        emitLabel(preCmp);
        emit8(0x8A); emit8(0x04); emit8(0x0E);  // mov al, [rsi+rcx]
        emit8(0x3A); emit8(0x04); emit8(0x0F);  // cmp al, [rdi+rcx]
        emitJcc("!=", envInc);                  // mismatch -> next env entry
        emit8(0xFF); emit8(0xC1);               // inc ecx
        emit8(0x83); emit8(0xF9); emit8(0x10);  // cmp ecx, 16 (prefix len)
        emit8(0x0F); emit8(0x82);               // jb preCmp
        jmpFixups.push_back({code.size(), preCmp});
        emit32(0);
        // Matched: rsi -> value, rdi -> sun.sun_path (rebase from r9).
        emit8(0x48); emit8(0x8D); emit8(0x76); emit8(0x10); // lea rsi, [rsi+16] (past '=')
        emit8(0x4C); emit8(0x89); emit8(0xCF);  // mov rdi, r9
        int copyLoop = newLabel(), copyDone2 = newLabel();
        emitLabel(copyLoop);
        emit8(0x8A); emit8(0x06);               // mov al, [rsi]
        emit8(0x88); emit8(0x07);               // mov [rdi], al
        emit8(0x48); emit8(0xFF); emit8(0xC6);  // inc rsi
        emit8(0x84); emit8(0xC0);               // test al, al
        emitJcc("==", copyDone2);               // stop at NUL (rdi still on it)
        emit8(0x48); emit8(0xFF); emit8(0xC7);  // inc rdi
        emitJmp(copyLoop);
        emitLabel(copyDone2);                   // rdi at value end; suffix overwrites the NUL

        // Append the fixed "/wayland-0" suffix from .rdata.
        leaRip(10, wlSfxRVA);                   // r10 = "/wayland-0"
        emit8(0x31); emit8(0xC9);               // xor ecx, ecx
        int sfxLoop = newLabel(), sfxDone = newLabel();
        emitLabel(sfxLoop);
        emit8(0x41); emit8(0x8A); emit8(0x04); emit8(0x0A); // mov al, [r10+rcx]
        emit8(0x84); emit8(0xC0);               // test al, al
        emitJcc("==", sfxDone);
        emit8(0x88); emit8(0x07);               // mov [rdi], al
        emit8(0x48); emit8(0xFF); emit8(0xC7);  // inc rdi
        emit8(0xFF); emit8(0xC1);               // inc ecx
        emitJmp(sfxLoop);
        emitLabel(sfxDone);
        emit8(0x31); emit8(0xC0);               // xor eax, eax
        emit8(0x88); emit8(0x07);               // mov [rdi], al (NUL)
        emit8(0x48); emit8(0xFF); emit8(0xC7);  // inc rdi

        // addrlen = (rdi - sun.sun_path_base) + 1
        emit8(0x48); emit8(0x89); emit8(0xF8);  // mov rax, rdi
        emit8(0x4C); emit8(0x29); emit8(0xC8);  // sub rax, r9
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(0x01); // add rax, 1

        // connect(fd, &sun, addrlen)
        leaRip(6, wlPathRVA);                   // rsi = &sun
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = addrlen
        emit8(0x4C); emit8(0x89); emit8(0xE7);  // rdi = fd
        emit8(0x45); emit8(0x31); emit8(0xD2);  // xor r10d, r10d
        svc(42);                                // connect
        emit8(0x85); emit8(0xC0);               // test eax, eax
        emitJcc("!=", connFail);                // connect failed -> close + -1
        // Success: remember the fd and return it.
        leaRip(2, wlFdRVA);
        emit8(0x4C); emit8(0x89); emit8(0x22);  // mov [rdx], r12
        emit8(0x4C); emit8(0x89); emit8(0xE0);  // mov rax, r12
        wlLeave(done);

        emitLabel(envInc);                      // env mismatch: advance + retry
        emit8(0x49); emit8(0x83); emit8(0xC0); emit8(0x08); // add r8, 8
        emitJmp(envNext);

        emitLabel(connFail);                    // fd is open here, close it
        emitJmp(envFail);
        emitLabel(envFail);
        svc(3);                                 // close(fd)
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        wlLeave(done);

        emitLabel(sockFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        wlLeave(done);

        emitLabel(done);
        emitJmp(wlExit);
        resultReg = 0;
    }

    // ---- wl_close(fd) -> 0 | -1 ----
    if (name == "wl_close") {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);         // fd -> rdi
        freeReg(a0);
        svc(3);                                 // close
        emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
        emitJcc(">=", done);                    // rax >= 0 -> return it
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitLabel(done);
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_list_globals() -> count of advertised registry globals | -1 ----
    if (name == "wl_list_globals") {
        int done = newLabel();
        int noFd = newLabel();
        int cbDone = newLabel();

        // Must have connected first (wl_open).
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);               // mov edi, [rdx] (fd)
        emit8(0x85); emit8(0xFF);               // test edi, edi
        emitJcc("<=", noFd);                    // fd <= 0 -> -1

        // Send the get_registry + sync handshake blob in one write().
        leaRip(6, wlInitReqRVA);
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(24); // rdx = 24
        svc(1);                                 // write(fd, blob, 24)
        emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
        emitJcc("<", noFd);

        // Read loop: batches of events until the sync callback's "done".
        // rbx = bytes read this batch ; r12 = parse offset ; r14 = count.
        int rdTop = newLabel(), rdEnd = newLabel(), pxLoop = newLabel();
        int rdNext = newLabel(), skipEvent = newLabel();
        emit8(0x45); emit8(0x31); emit8(0xF6);  // xor r14d, r14d (count=0)
        emitLabel(rdTop);
        leaRip(6, wlInRVA);                     // rsi = &inbuf
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(4096); // rdx = 4096
        svc(0);                                 // read(fd, inbuf, 4096)
        emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
        emitJcc("<=", rdEnd);                   // EOF/error -> stop
        emit8(0x89); emit8(0xC3);               // mov ebx, eax (n)
        leaRip(8, wlInRVA);                     // r8 = &inbuf
        emit8(0x45); emit8(0x31); emit8(0xE4);  // xor r12d, r12d (offset=0)

        emitLabel(pxLoop);
        emit8(0x49); emit8(0x39); emit8(0xDC);  // cmp r12, rbx (offset vs bytes read)
        emitJcc(">=", rdNext);                  // batch consumed -> read again
        emit8(0x4B); emit8(0x8D); emit8(0x0C); emit8(0x04); // rcx = &inbuf[r12] (lea rcx,[r8+r12])
        emit8(0x8B); emit8(0x39);               // mov edi, [rcx] (object id)
        emit8(0x85); emit8(0xFF);               // test edi, edi
        emitJcc("<=", skipEvent);               // bogus id -> skip
        emit8(0x83); emit8(0xFF); emit8(0x03);  // cmp edi, 3 (callback)
        emitJcc("==", cbDone);                  // wl_callback.done -> finish
        emit8(0x83); emit8(0xFF); emit8(0x01);  // cmp edi, 1 (display)
        emitJcc("==", skipEvent);               // delete_id/error: ignored here
        emit8(0x83); emit8(0xFF); emit8(0x02);  // cmp edi, 2 (registry)
        emitJcc("!=", skipEvent);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4] (opcode)
        emit8(0x85); emit8(0xC0);               // test eax, eax
        emitJcc("!=", skipEvent);               // only wl_registry.global (op 0)

        // ---- print this global as "interface:name:version" ----
        // 8-byte header: id(u32) opcode(u16) size(u16). wl_registry.global
        // payload: name [rcx+8], interface string len [rcx+12], bytes [rcx+16],
        // then version u32 at [rcx+16+align4(slen)].
        emit8(0x8B); emit8(0x41); emit8(0x0C);  // mov eax, [rcx+12] (slen)
        emit8(0x83); emit8(0xE8); emit8(0x01);  // sub eax, 1
        int ifaceSkip = newLabel();
        emit8(0x85); emit8(0xC0);               // test eax, eax
        emit8(0x0F); emit8(0x8E);               // jle ifaceSkip
        jmpFixups.push_back({code.size(), ifaceSkip});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = len
        emit8(0x48); emit8(0x8D); emit8(0x71); emit8(0x10); // rsi = &bytes[16]
        emit8(0xBF); emit32(1);                 // rdi = 1 (stdout)
        svc(1);                                 // write(1, iface, len)
        emitLabel(ifaceSkip);

        // ':' then the numeric global name.
        leaRip(6, wlColonRVA);
        emit8(0xBA); emit32(1);
        emit8(0xBF); emit32(1);
        svc(1);
        // syscall clobbers rcx/r11 (rcx = RIP after syscall), so reload the
        // event pointer (&inbuf[r12]) before touching the payload again.
        emit8(0x4B); emit8(0x8D); emit8(0x0C); emit8(0x04); // lea rcx, [r8+r12]
        emit8(0x8B); emit8(0x41); emit8(0x08);  // mov eax, [rcx+8] (global name)
        emitDecWrite();

        leaRip(6, wlColonRVA);
        emit8(0xBA); emit32(1);
        emit8(0xBF); emit32(1);
        svc(1);

        // ':' then the version: payload offset 16 + align4(slen) -> u32.
        emit8(0x4B); emit8(0x8D); emit8(0x0C); emit8(0x04); // lea rcx, [r8+r12] (reload)
        emit8(0x8B); emit8(0x41); emit8(0x0C);  // mov eax, [rcx+12] (slen)
        emit8(0x83); emit8(0xC0); emit8(0x03);  // add eax, 3
        emit8(0x83); emit8(0xE0); emit8(0xFC);  // and eax, ~3
        emit8(0x83); emit8(0xC0); emit8(0x10);  // add eax, 16
        emit8(0x8B); emit8(0x04); emit8(0x01);  // mov eax, [rcx+rax] (version)
        emitDecWrite();

        leaRip(6, wlNlRVA);
        emit8(0xBA); emit32(1);
        emit8(0xBF); emit32(1);
        svc(1);
        emit8(0x41); emit8(0xFF); emit8(0xC6);  // inc r14d (count++)

        emitLabel(skipEvent);
        emit8(0x4B); emit8(0x8D); emit8(0x0C); emit8(0x04); // lea rcx, [r8+r12] (reload)
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x06); // movzx eax, word[rcx+6] (size)
        emit8(0x49); emit8(0x01); emit8(0xC4);  // add r12, rax
        emitJmp(pxLoop);

        emitLabel(rdNext);
        emitJmp(rdTop);                         // next batch (sync may split)

        emitLabel(cbDone);
        emitLabel(rdEnd);
        emit8(0x4C); emit8(0x89); emit8(0xF0);  // mov rax, r14 (count)
        wlLeave(done);

        emitLabel(noFd);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        emitLabel(done);
        emitJmp(wlExit);
        resultReg = 0;
    }

    // ================= Common exit: restore the allocator view ================
    emitLabel(wlExit);
    regsUsed = 0;
    freeReg(1);
    freeReg(2);
    freeReg(3);
    int r = allocReg();
    if (r != 0) { emitMovReg(r, 0); freeReg(0); }
    regsUsed = (uint8_t)(saved & ~(1 << r));
    reloadRegs();
    regsUsed = (uint8_t)(saved | (1 << r));
    resultReg = r >= 0 ? r : 0;
    return true;
}