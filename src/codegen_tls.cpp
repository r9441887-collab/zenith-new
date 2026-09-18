#include "codegen.h"
#include "ast.h"
#include "tls_blob.h"

// =====================================================================
// TLS builtins — tls_connect/send/recv/close/last_error.
//
// Everything runs inside a position-independent freestanding x86-64 blob
// (src/tls_blob.h) that is appended to the .text section once (emitTlsBlob).
// The blob is SysV-internal: codegen stages op + args into rdi/rsi/rdx/rcx/
// r8/r9 and `call rel32` into its entry point (tlsrt_entry's opcode switch);
// the result returns in rax.
//
// The blob does synchronous socket I/O through io-slot function pointers
// (send/recv/closesocket) that live in the blob's own storage (inside .text).
// Because .text is normally read-only, codegen makes it writable for TLS apps
// and seeds those slots once via TLS_OP_IO_INIT, guarded by a .data flag. The
// pointers are read straight out of the PE IAT (`mov rax,[rip+disp]` reusing
// importCallFixups), so they stay correct under ASLR — the same trick the net_*
// builtins use.
//
//   tls_connect(sock, host) -> session handle | -1    (host = NUL-terminated)
//   tls_send(handle, buf, len) -> bytes sent | -1
//   tls_recv(handle, buf, len) -> bytes read | 0 (closed) | -1 (err)
//   tls_close(handle) -> 0 | -1
//   tls_last_error()  -> int TLS error code
// =====================================================================

void Codegen::detectTlsExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name.rfind("tls_", 0) == 0) tlsUsed = true;
        for (auto& arg : call->args) detectTlsExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectTlsExprUsage(bin->left.get());
        detectTlsExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectTlsExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectTlsExprUsage(arr->array.get());
        detectTlsExprUsage(arr->index.get());
    }
}

void Codegen::detectTlsStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectTlsExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectTlsExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectTlsExprUsage(assign->indexExpr.get());
        detectTlsExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectTlsExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectTlsExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectTlsStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectTlsStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectTlsExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectTlsStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectTlsStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectTlsExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectTlsExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectTlsStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectTlsExprUsage(fs->start.get());
        detectTlsExprUsage(fs->end.get());
        if (fs->step) detectTlsExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectTlsStmtUsage(s.get());
    }
}

void Codegen::detectTlsUsage() {
    if (!tlsUsed) {
        for (auto& func : prog.functions) {
            if (func->isExtern) continue;
            for (auto& stmt : func->body.stmts) detectTlsStmtUsage(stmt.get());
            if (tlsUsed) break;
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectTlsExprUsage(g->init.get());
        if (tlsUsed) break;
    }
}

// Appends the whole TLS blob to the .text code vector and resolves the label
// that all `call rel32` sites (in tryTlsCall / emitTlsIoInit) jump through.
// Must run after function codegen but before resolveJmpFixups. The blob's
// internal calls are relative to its own base, so it can sit anywhere in .text.
void Codegen::emitTlsBlob() {
    if (tlsBlobEmitted) return;
    tlsBlobEmitted = true;
    if (tlsEntryLabel < 0) tlsEntryLabel = newLabel();

    size_t blobStart = code.size();
    for (uint8_t b : kTlsBlob) emit8(b);

    // Resolve the entry label to the tlsrt_entry symbol inside the blob
    // (blobStart + its offset). We can't use emitLabel (that would give the
    // end of the blob) — write the position directly into labelPositions so
    // resolveJmpFixups computes the correct `call rel32` displacement.
    if ((size_t)((int)blobStart + (int)kTlstlsrt_entry) >= labelPositions.size())
        labelPositions.resize((size_t)blobStart + kTlstlsrt_entry + 1, -1);
    labelPositions[tlsEntryLabel] = (int)(blobStart + kTlstlsrt_entry);
}

// Seeds the blob's io-slot table (send/recv/closesocket) once, lazily, guarded
// by the .data flag TLS_IO_DONE. Function pointers are pulled from the PE IAT
// via RIP-relative loads, so they survive ASLR.
void Codegen::emitTlsIoInit() {
    int skip = newLabel();

    // mov rax,[rip+&tlsIoDone]; cmp qword [rax],0; jnz skip
    emit8(0x48); emit8(0x8D); emit8(0x05);
    tlsFixups.push_back({code.size(), TLS_IO_DONE}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0x38); emit8(0x00);   // cmp qword [rax], 0
    emitJcc("!=", skip);

    // send -> rsi (a1)
    emit8(0x48); emit8(0x8B); emit8(0x05);
    importCallFixups.push_back({code.size(), "send", "ws2_32.dll"}); emit32(0); // mov rax,[rip send]
    emit8(0x48); emit8(0x89); emit8(0xC6);               // mov rsi, rax
    // recv -> rdx (a2)
    emit8(0x48); emit8(0x8B); emit8(0x05);
    importCallFixups.push_back({code.size(), "recv", "ws2_32.dll"}); emit32(0);
    emit8(0x48); emit8(0x89); emit8(0xC2);               // mov rdx, rax
    // closesocket -> rcx (a3)
    emit8(0x48); emit8(0x8B); emit8(0x05);
    importCallFixups.push_back({code.size(), "closesocket", "ws2_32.dll"}); emit32(0);
    emit8(0x48); emit8(0x89); emit8(0xC1);               // mov rcx, rax
    // op = TLS_OP_IO_INIT (1) -> rdi
    emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(1);

    emitBlobEntryCall();

    // mark done: lea rax,[&tlsIoDone]; mov qword [rax],1
    emit8(0x48); emit8(0x8D); emit8(0x05);
    tlsFixups.push_back({code.size(), TLS_IO_DONE}); emit32(0);
    emit8(0x48); emit8(0xC7); emit8(0x00); emit32(1);

    emitLabel(skip);
}

// `call rel32` into the blob entry (tlsrt_entry). rdi=op, rsi=a1, rdx=a2,
// rcx=a3, r8=a4, r9=a5 (SysV) must already be staged. Result returns in rax.
void Codegen::emitBlobEntryCall() {
    emit8(0xE8);
    jmpFixups.push_back({code.size(), tlsEntryLabel});
    emit32(0);
}

bool Codegen::tryTlsCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isConn = (name == "tls_connect");
    const bool isXfer = (name == "tls_send" || name == "tls_recv");
    const bool isClose = (name == "tls_close");
    const bool isErr = (name == "tls_last_error");
    if (!isConn && !isXfer && !isClose && !isErr) return false;

    if (isConn && call->args.size() != 2) return false;
    if (isXfer && call->args.size() != 3) return false;
    if (isClose && call->args.size() != 1) return false;
    if (isErr && !call->args.empty()) return false;

    if (tlsEntryLabel < 0) tlsEntryLabel = newLabel();
    tlsUsed = true;

    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // rdi/rsi/rdx/rcx are allocator-backed (6,7,1,2) — pin after staging so a
    // later argument expression cannot clobber them.
    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7 || wantReg == 1 || wantReg == 2)
            regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };

    int tlsExit = newLabel();
    int done = newLabel();

    // ======= tls_connect(sock, host) -> session handle | -1 =======
    if (isConn) {
        emitTlsIoInit();                                 // seeds io slots (clobbers rsi/rdx/rcx) first
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);                 // sock -> rsi (a1)
        freeReg(a0); guard(6);

        Expr* host = call->args[1].get();
        StringExpr* lit = dynamic_cast<StringExpr*>(host);

        int a1 = emitExpr(host);
        if (a1 != 2) emitMovReg(2, a1);                 // host addr -> rdx (a2)
        freeReg(a1); guard(2);

        if (lit) {
            // mov rcx, literalLen   -> rcx = a3 (host_len)
            emit8(0x48); emit8(0xC7); emit8(0xC1); emit32((uint32_t)lit->value.size());
        } else {
            // strlen(rdx) -> rcx   (host is a NUL-terminated buffer)
            emit8(0x31); emit8(0xC9);                   // xor ecx, ecx (len = 0)
            int loop = newLabel(), strEnd = newLabel();
            emitLabel(loop);
            emit8(0x0F); emit8(0xB6); emit8(0x04); emit8(0x0E); // movzx eax, byte [rdx+rcx]
            emit8(0x84); emit8(0xC0);                   // test al, al
            emitJcc("==", strEnd);                      // NUL -> finished (len in rcx)
            emit8(0x48); emit8(0xFF); emit8(0xC1);      // inc rcx
            emit8(0xE9); jmpFixups.push_back({code.size(), loop}); emit32(0);
            emitLabel(strEnd);
        }
        guard(1);

        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(20); // op = TLS_OP_TLS_CONNECT
        emitBlobEntryCall();
        emitJmp(done);
    }

    // ======= tls_send/tls_recv(handle, buf, len) =======
    if (isXfer) {
        emitTlsIoInit();                                 // seeds io slots (clobbers rsi/rdx/rcx) first
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);                 // handle -> rsi (a1)
        freeReg(a0); guard(6);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 2) emitMovReg(2, a1);                 // buf -> rdx (a2)
        freeReg(a1); guard(2);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 1) emitMovReg(1, a2);                 // len -> rcx (a3)
        freeReg(a2); guard(1);

        emit8(0x48); emit8(0xC7); emit8(0xC7);
        emit32(name == "tls_send" ? 21 : 22);           // TLS_OP_TLS_SEND / TLS_OP_TLS_RECV
        emitBlobEntryCall();
        emitJmp(done);
    }

    // ======= tls_close(handle) =======
    if (isClose) {
        emitTlsIoInit();                                 // seeds io slots (clobbers rsi/rdx/rcx) first
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);                 // handle -> rsi (a1)
        freeReg(a0); guard(6);
        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(23); // op = TLS_OP_TLS_CLOSE
        emitBlobEntryCall();
        emitJmp(done);
    }

    // ======= tls_last_error() =======
    if (isErr) {
        emitTlsIoInit();
        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(24); // op = TLS_OP_TLS_LAST_ERROR
        emitBlobEntryCall();
        emitJmp(done);
    }

    emitLabel(done);
    emitJmp(tlsExit);

    // ============== Common exit: reseat result in an allocator register =====
    emitLabel(tlsExit);
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
