#include "codegen.h"
#include "ast.h"
#include "httpdl_blob.h"

// =====================================================================
// HTTP/HTTPS file-download builtins — http_download / http_download_ask /
// http_download_speed — for `app linux`.
//
// The whole engine runs inside the freestanding position-independent blob
// (src/httpdl_blob.h) appended to .text once (emitHttpDlBlob). It is
// SysV-internal: codegen stages op + args into rdi/rsi/rdx/rcx/r8/r9 and
// `call rel32` into its entry point (httpdl_entry), result returns in rax.
//
//   http_download(url, file)        -> int (0 ok | <0 error)
//   http_download_ask(url, file)    -> int (1 user declined | 0 | <0 error)
//   http_download_speed(url, file)  -> int (1 full-speed declined | 0 | <0)
//   http_server(port[, cert, key])  -> blocks in the accept loop (0 | <0 error)
//   http_download_ghreleases(owner, repo, pattern, file)  -> int (0 | -5 | <0)
//   http_download_ask_gh(owner, repo, branch, path, excl) -> int (0 | -5 | <0)
//   http_download_msiso(version[, file])                  -> int (0 | -5 | <0)
//   http_download_winpe(version[, file])                  -> int (0 | -5 | <0)
//   Windows PE = sources/boot.wim, pulled by byte-range GETs only
//   (never the whole .iso), ISO9660 layout parsed from the head range.
//
// The blob does its own DNS / TCP / TLS 1.2 (reusing the linked TLS core) /
// file I/O with raw syscalls — no OS imports, no libc.
// =====================================================================

static bool isHttpDlName(const std::string& n) {
    return n == "http_download" || n == "http_download_ask" ||
           n == "http_download_speed" || n == "http_server" ||
           n == "http_download_ghreleases" || n == "http_download_ask_gh" ||
           n == "http_download_msiso" || n == "http_download_winpe" ||
           n == "http_download_winpe_media" || n == "iso_extract" ||
           n == "http_download_iso";
}

void Codegen::detectHttpDlExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (isHttpDlName(call->name)) httpDlUsed = true;
        for (auto& arg : call->args) detectHttpDlExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectHttpDlExprUsage(bin->left.get());
        detectHttpDlExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectHttpDlExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectHttpDlExprUsage(arr->array.get());
        detectHttpDlExprUsage(arr->index.get());
    }
}

void Codegen::detectHttpDlStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectHttpDlExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectHttpDlExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectHttpDlExprUsage(assign->indexExpr.get());
        detectHttpDlExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectHttpDlExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectHttpDlExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectHttpDlStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectHttpDlStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectHttpDlExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectHttpDlStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectHttpDlStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectHttpDlExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectHttpDlExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectHttpDlStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectHttpDlExprUsage(fs->start.get());
        detectHttpDlExprUsage(fs->end.get());
        if (fs->step) detectHttpDlExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectHttpDlStmtUsage(s.get());
    }
}

void Codegen::detectHttpDlUsage() {
    if (httpDlUsed) return;
    for (auto& func : prog.functions) {
        if (func->isExtern) continue;
        for (auto& stmt : func->body.stmts) detectHttpDlStmtUsage(stmt.get());
        if (httpDlUsed) break;
    }
    if (httpDlUsed) return;
    for (auto& g : prog.globals) {
        if (g->init) detectHttpDlExprUsage(g->init.get());
        if (httpDlUsed) break;
    }
}

// Appends the whole download-I/O blob to .text and resolves the label that
// `call rel32` sites in tryHttpDlCall jump through. Must run after function
// codegen but before resolveJmpFixups. The blob's internal calls are relative
// to its own base and its .bss lives inside the image, so it can sit anywhere.
void Codegen::emitHttpDlBlob() {
    if (httpDlBlobEmitted) return;
    httpDlBlobEmitted = true;
    if (httpDlEntryLabel < 0) httpDlEntryLabel = newLabel();

    // The embedded TLS core uses 16-byte-aligned SIMD constant loads
    // (movdqa from .text). Align the section so those offsets stay valid
    // regardless of where the blob lands in the final image.
    while (code.size() % 16) emit8(0x90);  // NOP pad
    size_t blobStart = code.size();
    for (uint8_t b : kHttpdlBlob) emit8(b);

    if ((size_t)((int)blobStart + (int)HTTPDL_BLOB_ENTRY) >= labelPositions.size())
        labelPositions.resize((size_t)blobStart + HTTPDL_BLOB_ENTRY + 1, -1);
    labelPositions[httpDlEntryLabel] = (int)(blobStart + HTTPDL_BLOB_ENTRY);
}

bool Codegen::tryHttpDlCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    int op = 0;
    bool winPe = false;
    if (name == "http_download") op = 1;
    else if (name == "http_download_ask") op = 2;
    else if (name == "http_download_speed") op = 3;
    else if (name == "http_server") op = 4;
    else if (name == "http_download_ghreleases") op = 5;
    else if (name == "http_download_ask_gh") op = 6;
    else if (name == "http_download_msiso") op = 7;
    else if (name == "http_download_winpe") {
        op = 8;
        winPe = true;
    } else if (name == "http_download_winpe_media") {
        op = 9;
    } else if (name == "iso_extract" || name == "http_download_iso") {
        op = 8;
    } else return false;
    if (op == 4) {
        if (call->args.size() < 1 || call->args.size() > 3) return false;
    } else if (op == 5) {
        if (call->args.size() != 4) return false;
    } else if (op == 6) {
        if (call->args.size() != 5) return false;
    } else if (op == 7 || (op == 8 && winPe) || op == 9) {
        if (call->args.size() < 1 || call->args.size() > 2) return false;
    } else if (op == 8) {
        if (call->args.size() < 2 || call->args.size() > 3) return false;
    } else if (call->args.size() != 2) {
        return false;
    }

    if (httpDlEntryLabel < 0) httpDlEntryLabel = newLabel();
    httpDlUsed = true;

    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // rdi(7)/rsi(6)/rdx(2)/rcx(1) are allocator-backed; pin after staging so a
    // later argument expression cannot clobber them.
    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7 || wantReg == 1 || wantReg == 2)
            regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };

    // mov r8/r9, r64: REX.W(+B) 0x48/0x49, opcode 89 /r (MOV r/m64, r64);
    // modrm.reg = src (0-7), modrm.rm = dst&7 (REX.B supplies bit 3 for r8/r9).
    // The allocator never hands out r8/r9, so args that belong there are
    // staged through a scratch reg first.
    auto emitRx = [&](int dst, int src) {
        emit8((uint8_t)(0x48 | ((dst >= 8) ? 0x01 : 0)));   /* REX.W + REX.B */
        emit8(0x89);
        emit8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
    };

    int done = newLabel();
    int exitLabel = newLabel();

    if (op == 4) {
        // http_server(port[, cert, key]): port->rsi, cert->rdx, key->rcx.
        // cert/key are NUL-terminated string pointers; the blob computes their
        // lengths internally (same convention as http_download).
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);
        freeReg(a0); guard(6);

        if (call->args.size() >= 2) {
            int a1 = emitExpr(call->args[1].get());
            if (a1 != 2) emitMovReg(2, a1);
            freeReg(a1); guard(2);
        } else {
            emit8(0x31); emit8(0xD2);        // xor edx,edx (no cert)
            guard(2);
        }
        if (call->args.size() >= 3) {
            int a2 = emitExpr(call->args[2].get());
            if (a2 != 1) emitMovReg(1, a2);
            freeReg(a2); guard(1);
        } else {
            emit8(0x31); emit8(0xC9);        // xor ecx,ecx (no key)
            guard(1);
        }
    } else if (op >= 5 && op <= 9) {
        // SysV call ABI: a1=rsi a2=rdx a3=rcx a4=r8 a5=r9 (rdi = op).
        // Staged left-to-right, so evaluation order of the argument
        // expressions stays intact; r8/r9 values survive because they are
        // physical registers the allocator never touches.
        static const int kBlobRegs[5] = { 6, 2, 1, 8, 9 };
        int argc = (int)call->args.size();
        for (int i = 0; i < argc; i++) {
            int t = emitExpr(call->args[i].get());
            if (kBlobRegs[i] >= 8) {
                emitRx(kBlobRegs[i], t);
                freeReg(t);
            } else {
                if (t != kBlobRegs[i]) emitMovReg(kBlobRegs[i], t);
                freeReg(t);
                guard(kBlobRegs[i]);
            }
        }
        if (argc < 2) {
            emit8(0x31); emit8(0xD2);        // xor edx,edx (msiso: no file)
            guard(2);
        }
        if (op == 8) {
            if (argc < 3) {
                emit8(0x31); emit8(0xC9);
                guard(1);
            }
            emit8(0x41); emit8(0xC7); emit8(0xC0);
            emit32((uint32_t)(winPe ? 1 : 0));
        } else if (op == 9) {
            emit8(0x45); emit8(0x31); emit8(0xC0);
        }
    } else {
        // url -> rsi (a1)
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);
        freeReg(a0); guard(6);

        // file -> rdx (a2)
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 2) emitMovReg(2, a1);
        freeReg(a1); guard(2);
    }

    // op -> rdi
    emit8(0x48); emit8(0xC7); emit8(0xC7); emit32((uint32_t)op);
    guard(7);

    emit8(0xE8);
    jmpFixups.push_back({code.size(), httpDlEntryLabel});
    emit32(0);
    emitJmp(done);

    emitLabel(done);
    emitJmp(exitLabel);

    emitLabel(exitLabel);
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
