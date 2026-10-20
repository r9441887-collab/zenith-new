#include "codegen.h"
#include "ast.h"
#include "js_blob.h"

// =====================================================================
// JS builtins — js_reset / js_eval / js_result / js_error.
//
// A freestanding position-independent x86-64 JS engine (src/js_blob.h,
// generated from tools/jsrt.c) is appended to .text once (emitJsBlob) and
// invoked through `call rel32` into its entry point (jsrt_entry's opcode
// switch). Arg/result ABI is SysV-internal: op in rdi, a1 in rsi, a2 in rdx,
// a3 in rcx, result in rax. The blob never calls Windows APIs and keeps all
// its state (4 MiB arena + globals) in its own .bss, which codegen emits
// (zeroed) immediately after the code bytes; .text is made RWX when jsUsed.
//
//   js_reset()       -> int   clears arena + global env (idempotent)
//   js_eval(code)    -> int   runs a JS program; last expression result or any
//                             printed value is available via js_result()
//   js_result() -> str    string form of the last evaluated expression
//   js_error()  -> str    last error text (usually empty for now)
//
// Host callbacks: the engine's fs/net/tls/print builtins (JSOP require, __readFile,
// httpGet, ...) resolve through the blob's host-function table (g_host_fn[]),
// which JS_OP_SET_HOST fills once per js_eval call site (guarded by an RWX flag
// byte in .text); the engine then calls the installed address with SysV convention:
//     long cb(long a1, long a2, long a3, long a4)   // rdi rsi rdx rcx -> rax
// How a slot gets filled depends on the target:
//   PE     slots 0-12 -> Win64 thunks emitted by emitJsHostStubs(), which call
//          kernel32/ws2_32 (the only way out of there: no import table otherwise)
//   Linux  slots -> an implementation already sitting inside the blob
//          (tools/js_host_linux.c, raw syscalls), so the address is just
//          blobStart + its symbol offset — no stub code, nothing to patch.
// Unfilled slots (net/tls on Linux) stay NULL and the engine degrades gracefully.
// =====================================================================

namespace {

enum {
    JS_OP_RESET   = 0,
    JS_OP_EXEC    = 1,
    JS_OP_EXPR    = 2,
    JS_OP_RESULT  = 3,
    JS_OP_ERROR   = 4,
    JS_OP_NUM     = 5,
    JS_OP_SET_HOST = 6,
};

// g_host_fn slot indices in tools/jsrt.c (must match HOST_* there).
enum {
    HOST_FS_READ  = 0,   // (path, _, buf, cap)     -> bytesRead | -1
    HOST_FS_WRITE = 1,   // (path, _, data, len)    -> bytesWritten
    HOST_FS_EXISTS = 2,  // (path, _, _, _)         -> 1 | 0
    HOST_GET_CWD  = 3,   // (buf, cap, _, _)        -> length
    HOST_NET_CONN = 4,   // (host, port, _, _)      -> socket | -1
    HOST_NET_SEND = 5,   // (sock, buf, len, _)     -> bytes | -1
    HOST_NET_RECV = 6,   // (sock, buf, len, _)     -> bytes | -1
    HOST_NET_CLOSE = 7,  // (sock, _, _, _)         -> 0
    HOST_TLS_CONN = 8,   // (sock, host, _, _)      -> handshake handle | -1
    HOST_TLS_SEND = 9,   // (h, buf, len, _)        -> bytes | -1
    HOST_TLS_RECV = 10,  // (h, buf, len, _)        -> bytes | -1
    HOST_TLS_CLOSE = 11, // (h, _, _, _)            -> 0
    HOST_PRINT    = 12,  // (buf, len, _, _)        -> void
    HOST_EXEC     = 13,  // (cmd, _, outbuf, cap)   -> exit code, stdout captured
    HOST_FS_MKDIR = 14,  // (path, _, _, _)         -> 0 | -1
    HOST_FS_READDIR = 15,// (path, outbuf, cap, _)  -> len | -1, '\n'-separated
    HOST_FS_UNLINK = 16, // (path, _, _, _)         -> 0 | -1
    HOST_SLEEP    = 17,  // (ms, _, _, _)           -> 0
    HOST_FS_STAT  = 18,  // (path, outbuf, cap, _)  -> 0 | -1 ("size\0is_dir\0")
    HOST_RAND     = 19,  // (_, _, _, _)            -> random long (blob-internal)
    HOST_ENV      = 20,  // (key, outbuf, cap, _)   -> len | -1
    HOST_ARGS     = 21,  // (idx, outbuf, cap, _)   -> len | -1
    HOST_UNAME    = 22,  // (_, outbuf, cap, _)     -> len | -1
    HOST_COUNT    = 24,
    // PE covers 0..12 with Win64 thunks; the Linux target installs the rest too
    // (net/tls stay unset there — see kJsHostLinux below).
    JS_HOST_PE    = 13,
    JS_HOST_SLOTS = HOST_COUNT,
};

// Slots the ELF target can fill from tools/js_host_linux.c, whose code is
// already inside the blob: slot -> blob symbol offset. Installing a function
// is just recording (blobStart + sym) as the slot value, so nothing is stubbed
// out and nothing needs patching afterwards.
struct JsLinuxHost { int slot; uint32_t sym; };
const JsLinuxHost kJsHostLinux[] = {
    {HOST_FS_READ,   kJsJs_host_fs_read},
    {HOST_FS_WRITE,  kJsJs_host_fs_write},
    {HOST_FS_EXISTS, kJsJs_host_fs_exists},
    {HOST_GET_CWD,   kJsJs_host_get_cwd},
    {HOST_PRINT,     kJsJs_host_print},
    {HOST_EXEC,      kJsJs_host_exec},
    {HOST_FS_MKDIR,  kJsJs_host_fs_mkdir},
    {HOST_FS_READDIR,kJsJs_host_fs_readdir},
    {HOST_FS_UNLINK, kJsJs_host_fs_unlink},
    {HOST_SLEEP,     kJsJs_host_sleep},
    {HOST_FS_STAT,   kJsJs_host_fs_stat},
    {HOST_ENV,       kJsJs_host_env},
    {HOST_ARGS,      kJsJs_host_args},
    {HOST_UNAME,     kJsJs_host_uname},
};

// TLS blob opcodes (tlsrt.c; TLS_OP_IO_INIT=1 connects the winsock thunks).
enum {
    TLS_OP_IO_INIT    = 1,
    TLS_OP_TLS_CONNECT = 20,
    TLS_OP_TLS_SEND   = 21,
    TLS_OP_TLS_RECV   = 22,
    TLS_OP_TLS_CLOSE  = 23,
};

}  // namespace

void Codegen::detectJsExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name.rfind("js_", 0) == 0) jsUsed = true;
        for (auto& arg : call->args) detectJsExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectJsExprUsage(bin->left.get());
        detectJsExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectJsExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectJsExprUsage(arr->array.get());
        detectJsExprUsage(arr->index.get());
    }
}

void Codegen::detectJsStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectJsExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectJsExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectJsExprUsage(assign->indexExpr.get());
        detectJsExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectJsExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectJsExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectJsStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectJsStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectJsExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectJsStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectJsStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectJsExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectJsExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectJsStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectJsExprUsage(fs->start.get());
        detectJsExprUsage(fs->end.get());
        if (fs->step) detectJsExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectJsStmtUsage(s.get());
    }
}

void Codegen::detectJsUsage() {
    if (!jsUsed) {
        for (auto& func : prog.functions) {
            if (func->isExtern) continue;
            for (auto& stmt : func->body.stmts) detectJsStmtUsage(stmt.get());
            if (jsUsed) break;
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectJsExprUsage(g->init.get());
        if (jsUsed) break;
    }
}

// Appends the whole JS blob (code + zeroed .bss arena) to .text and resolves
// the label that all `call rel32` sites (tryJsCall) jump through. Must run
// after function codegen but before resolveJmpFixups. The blob's internal
// references are relative to its own base, so it can sit anywhere in .text.
void Codegen::emitJsBlob() {
    if (jsBlobEmitted) return;
    jsBlobEmitted = true;
    if (jsEntryLabel < 0) jsEntryLabel = newLabel();

    size_t blobStart = code.size();
    // The blob (engine + libgcc helpers, some of which use movaps/movapd) was
    // linked at a 16-byte aligned base; align its home in .text too, otherwise
    // aligned SSE loads/stores inside the blob #GP.
    while (blobStart % 16 != 0) { emit8(0); blobStart++; }
    for (uint8_t b : kJsBlob) emit8(b);

    // Zero-fill the blob's .bss (statics + 4 MiB arena) so the engine state
    // lives inside our RWX .text. kTlsJs__bss_end is the end of the arena.
    size_t bssEnd = (size_t)kJs__bss_end;
    if (bssEnd > kJsBlobSize) {
        size_t pad = bssEnd - kJsBlobSize;
        if (pad > (size_t)100000000) pad = 100000000;  // sanity guard (never hit)
        code.resize(code.size() + pad, 0);
    }

    // Resolve the entry label to the jsrt_entry symbol inside the blob
    // (blobStart + its offset), same approach as emitTlsBlob.
    if ((size_t)((int)blobStart + (int)kJsJsrt_entry) >= labelPositions.size())
        labelPositions.resize((size_t)blobStart + kJsJsrt_entry + 1, -1);
    labelPositions[jsEntryLabel] = (int)(blobStart + kJsJsrt_entry);

    if (prog.appType == AppType::Linux) {
        // Each installed slot points straight at its implementation inside the
        // blob (tools/js_host_linux.c) — same trick as the entry label above.
        if (jsHostFlagLabel >= 0) {
            size_t need = blobStart + kJsBlobSize;
            if (labelPositions.size() <= need) labelPositions.resize(need + 1, -1);
            for (const JsLinuxHost& h : kJsHostLinux)
                labelPositions[jsHostStubLabel[h.slot]] = (int)(blobStart + h.sym);
            // The "already installed" guard byte lives in RWX .text; on PE the
            // stubs emitter drops it after their scratch area.
            emitLabel(jsHostFlagLabel);
            emit8(0);
        }
    } else {
        // The engine's host callbacks (fs/net/tls/print stubs) follow the blob.
        emitJsHostStubs();
    }
}

// `call rel32` into the blob entry (jsrt_entry). rdi=op, rsi=a1, rdx=a2,
// rcx=a3 (SysV) must already be staged. Result returns in rax.
void Codegen::emitJsEntryCall() {
    emit8(0xE8);
    jmpFixups.push_back({code.size(), jsEntryLabel});
    emit32(0);
}

bool Codegen::tryJsCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isReset  = (name == "js_reset");
    const bool isEval   = (name == "js_eval");
    const bool isResult = (name == "js_result");
    const bool isError  = (name == "js_error");
    if (!isReset && !isEval && !isResult && !isError) return false;

    if (isEval && call->args.size() != 1) return false;
    if (!isEval && !call->args.empty()) return false;

    if (jsEntryLabel < 0) jsEntryLabel = newLabel();
    jsUsed = true;

    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // rdi/rsi/rdx/rcx are allocator-backed (7,6,2,1) — pin them as we stage so
    // a later argument expression cannot clobber an already-staged argument.
    auto guard = [&](int wantReg) {
        if (wantReg == 7 || wantReg == 6 || wantReg == 2 || wantReg == 1)
            regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };

    // ======= js_reset() =======
    if (isReset) {
        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(JS_OP_RESET);  // rdi = op
        emitJsEntryCall();
    }

    // ======= js_eval(code) =======
    if (isEval) {
        // Install the host callback table once (guarded by an RWX flag byte in
        // .text): fs/net/tls/print callbacks referenced from the first js_eval
        // (the engine's require()/httpGet()/print live in this table).
        const bool linuxHosts = prog.appType == AppType::Linux;
        if (jsHostFlagLabel < 0) {
            jsHostFlagLabel = newLabel();
            for (int s = 0; s < JS_HOST_SLOTS; s++) jsHostStubLabel[s] = newLabel();
        }
        int hostSkip = newLabel();
        emit8(0x48); emit8(0x8D); emit8(0x05);                // lea rax,[rip+&flag]
        jmpFixups.push_back({code.size(), jsHostFlagLabel}); emit32(0);
        emit8(0x80); emit8(0x38); emit8(0x00);                // cmp byte [rax], 0
        emitJcc("!=", hostSkip);                              // already installed?
        auto installHost = [&](int s) {
            emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(JS_OP_SET_HOST); // rdi = op
            emit8(0x48); emit8(0xC7); emit8(0xC6); emit32(s);              // rsi = slot
            emit8(0x48); emit8(0x8D); emit8(0x15);            // lea rdx,[rip+&stub]
            jmpFixups.push_back({code.size(), jsHostStubLabel[s]}); emit32(0);
            emitJsEntryCall();
        };
        if (linuxHosts) {
            for (const JsLinuxHost& h : kJsHostLinux) installHost(h.slot);
        } else {
            for (int s = 0; s < JS_HOST_PE; s++) installHost(s);
        }
        emit8(0x48); emit8(0x8D); emit8(0x05);                // lea rax,[rip+&flag]
        jmpFixups.push_back({code.size(), jsHostFlagLabel}); emit32(0);
        emit8(0xC6); emit8(0x00); emit8(0x01);                // mov byte [rax], 1
        emitLabel(hostSkip);

        Expr* codeArg = call->args[0].get();
        StringExpr* lit = dynamic_cast<StringExpr*>(codeArg);

        int a = emitExpr(codeArg);
        if (a != 6) emitMovReg(6, a);                    // code addr -> rsi (a1)
        freeReg(a); guard(6);

        if (lit) {
            emit8(0x48); emit8(0xC7); emit8(0xC2);       // mov rdx, literal length
            emit32((uint32_t)lit->value.size());
        } else {
            // strlen(rsi) -> rdx
            emit8(0x31); emit8(0xD2);                    // xor edx, edx (len = 0)
            int loop = newLabel(), strEnd = newLabel();
            emitLabel(loop);
            emit8(0x0F); emit8(0xB6); emit8(0x04); emit8(0x16); // movzx eax, byte [rsi+rdx]
            emit8(0x84); emit8(0xC0);                    // test al, al
            emitJcc("==", strEnd);
            emit8(0x48); emit8(0xFF); emit8(0xC2);       // inc rdx
            emit8(0xE9); jmpFixups.push_back({code.size(), loop}); emit32(0);
            emitLabel(strEnd);
        }
        guard(2);

        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(JS_OP_EXEC);  // rdi = op
        emitJsEntryCall();
        // Return the numeric value of the last result (0 for non-numeric/errors).
        emit8(0x48); emit8(0xC7); emit8(0xC7); emit32(JS_OP_NUM);   // rdi = op
        emitJsEntryCall();
    }

    // ======= js_result() / js_error() =======
    if (isResult || isError) {
        JsFixup::Slot slot = isResult ? JsFixup::JS_SLOT_RESULT : JsFixup::JS_SLOT_ERROR;
        // lea rsi,[rip+slot]  (a1 = out buffer)
        emit8(0x48); emit8(0x8D); emit8(0x35);
        jsFixups.push_back({code.size(), slot}); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(512);  // mov rdx, cap
        emit8(0x48); emit8(0xC7); emit8(0xC7);               // rdi = op
        emit32(isResult ? JS_OP_RESULT : JS_OP_ERROR);
        emitJsEntryCall();
        // Return the buffer address (the string), not the len rax holds now.
        emit8(0x48); emit8(0x8D); emit8(0x05);
        jsFixups.push_back({code.size(), slot}); emit32(0);  // lea rax,[rip+slot]
    }

    // ============== Common exit: reseat result in an allocator register =====
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

// =====================================================================
// JS engine host callbacks (13 SysV stubs).
//
// Each stub is called from the blob as
//     long stub(long a1, long a2, long a3, long a4)
// (SysV: rdi rsi rdx rcx -> rax) and must preserve rbx/rbp/r12-r15.
// The prologue pushes rbx,r12,r13,r14 and makes rsp 16-byte aligned with
// a 0x38 frame: [rsp]..[rsp+0x1f] is Win64 shadow space, [rsp+0x20..0x30]
// holds 7-arg stack slots, [rsp+0x38+] are the saved callee regs. Every
// Win64 call below runs with rsp == 0 (mod 16).
// =====================================================================
void Codegen::emitJsHostStubs() {
    if (jsHostFlagLabel < 0) return;   // no js_eval call site -> stubs unused
    if (jsWsaFlagLabel < 0) {
        jsWsaFlagLabel = newLabel();
        jsWsadataLabel = newLabel();
        jsAddrLabel = newLabel();
    }

    auto callImp = [&](const char* fn, const char* dll) {
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), fn, dll});
        emit32(0);
    };
    auto movqq = [&](int dst, int src) {   // mov dst, src  (Rex.W 8B form)
        uint8_t rex = 0x48 | ((dst >= 8) ? 0x04 : 0x00) | ((src >= 8) ? 0x01 : 0x00);
        emit8(rex); emit8(0x8B);
        emit8((uint8_t)(0xC0 + ((dst & 7) << 3) + (src & 7)));
    };
    auto movimm = [&](int reg, int32_t v) {   // mov rN, imm32 sign-extended (N = 0..7)
        emit8(0x48); emit8(0xC7); emit8((uint8_t)(0xC0 + reg)); emit32((uint32_t)v);
    };
    auto movqsp = [&](int disp, int32_t v) {  // mov qword [rsp+disp], imm32
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8((uint8_t)disp); emit32((uint32_t)v);
    };
    auto leaRax = [&](int label) {            // lea rax,[rip+&label]
        emit8(0x48); emit8(0x8D); emit8(0x05);
        jmpFixups.push_back({code.size(), label}); emit32(0);
    };
    auto leaRdx = [&](int label) {            // lea rdx,[rip+&label]
        emit8(0x48); emit8(0x8D); emit8(0x15);
        jmpFixups.push_back({code.size(), label}); emit32(0);
    };
    auto prologue = [&]() {
        emit8(0x48); emit8(0x53);                            // push rbx
        emit8(0x41); emit8(0x54);                            // push r12
        emit8(0x41); emit8(0x55);                            // push r13
        emit8(0x41); emit8(0x56);                            // push r14
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);  // sub rsp, 0x38
    };
    auto epilogue = [&]() {
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);  // add rsp, 0x38
        emit8(0x41); emit8(0x5E);                            // pop r14
        emit8(0x41); emit8(0x5D);                            // pop r13
        emit8(0x41); emit8(0x5C);                            // pop r12
        emit8(0x5B);                                         // pop rbx
        emit8(0xC3);                                         // ret
    };
    // Seeds the embedded tls blob's io-slot table with the winsock IAT thunks
    // (same pointers codegen's emitTlsIoInit uses), so the blob's TLS ops can
    // do socket I/O through Win64 functions. rdi/rsi/rdx/rcx are scratch here.
    auto tlsIoInit = [&]() {
        emit8(0x48); emit8(0x8B); emit8(0x05);               // mov rax,[rip+&send]
        importCallFixups.push_back({code.size(), "send", "ws2_32.dll"}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC6);               // mov rsi, rax
        emit8(0x48); emit8(0x8B); emit8(0x05);               // mov rax,[rip+&recv]
        importCallFixups.push_back({code.size(), "recv", "ws2_32.dll"}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC2);               // mov rdx, rax
        emit8(0x48); emit8(0x8B); emit8(0x05);               // mov rax,[rip+&closesocket]
        importCallFixups.push_back({code.size(), "closesocket", "ws2_32.dll"}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);               // mov rcx, rax
        movimm(7, TLS_OP_IO_INIT);                           // rdi = op
        emitBlobEntryCall();
    };

    // ===================== 0: fs_read (path, _, buf, cap) =====================
    {
        int lFailOpen = newLabel(), lFailRead = newLabel(), lClose = newLabel(), lDone = newLabel();
        emitLabel(jsHostStubLabel[0]);
        prologue();
        movqq(3, 7);               // rbx = path
        movqq(13, 2);              // r13 = buf
        movqq(14, 1);              // r14 = cap
        movqq(1, 3);               // rcx = path
        emit8(0xBA); emit32(0x80000000);              // edx = GENERIC_READ
        emit8(0x41); emit8(0xB8); emit32(3);          // r8d = FILE_SHARE_READ|WRITE
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d
        movqsp(0x20, 3);                              // OPEN_EXISTING
        movqsp(0x28, 0x80);                           // FILE_ATTRIBUTE_NORMAL
        movqsp(0x30, 0);                              // NULL template
        callImp("CreateFileA", "kernel32.dll");
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8(0xFF);   // cmp rax, -1
        emitJcc("==", lFailOpen);
        movqq(3, 0);               // rbx = handle
        movqq(1, 3);               // rcx = handle
        movqq(2, 13);              // rdx = buf
        emit8(0x4D); emit8(0x8B); emit8(0xC6);        // mov r8, r14 (cap)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x18);  // lea r9,[rsp+0x18]
        movqsp(0x20, 0);                              // NULL overlapped
        callImp("ReadFile", "kernel32.dll");
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", lFailRead);
        // ReadFile writes a DWORD to lpNumberOfBytesRead ([rsp+0x18]); a 64-bit
        // load would pull 4 stale shadow-space bytes into the upper dword. Use a
        // zero-extending 32-bit load so rax holds the true count.
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x18);  // mov eax,[rsp+0x18]
        emit8(0x49); emit8(0x89); emit8(0xC6);        // mov r14, rax (stash count; cap done)
        emitJmp(lClose);
        emitLabel(lFailRead);
        emit8(0x49); emit8(0xC7); emit8(0xC6); emit8(0xFF); emit8(0xFF); emit8(0xFF); emit8(0xFF);  // mov r14, -1
        emitLabel(lClose);
        movqq(1, 3);               // rcx = handle
        callImp("CloseHandle", "kernel32.dll");
        movqq(0, 14);              // mov rax, r14  (Win64 callees preserve r14)
        emitJmp(lDone);
        emitLabel(lFailOpen);
        movimm(0, -1);
        emitLabel(lDone);
        epilogue();
    }

    // ===================== 1: fs_write (path, _, data, len) =====================
    {
        int lFailOpen = newLabel(), lFailWrite = newLabel(), lClose = newLabel(), lDone = newLabel();
        emitLabel(jsHostStubLabel[1]);
        prologue();
        movqq(3, 7);               // rbx = path
        movqq(13, 2);              // r13 = data
        movqq(14, 1);              // r14 = len
        movqq(1, 3);
        emit8(0xBA); emit32(0x40000000);              // edx = GENERIC_WRITE
        emit8(0x45); emit8(0x31); emit8(0xC0);        // xor r8d, r8d
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d
        movqsp(0x20, 2);                              // CREATE_ALWAYS
        movqsp(0x28, 0x80);                           // FILE_ATTRIBUTE_NORMAL
        movqsp(0x30, 0);
        callImp("CreateFileA", "kernel32.dll");
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8(0xFF);
        emitJcc("==", lFailOpen);
        movqq(3, 0);               // rbx = handle
        movqq(1, 3);
        movqq(2, 13);              // rdx = data
        emit8(0x4D); emit8(0x8B); emit8(0xC6);        // mov r8, r14 (len)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x18);  // lea r9,[rsp+0x18]
        movqsp(0x20, 0);
        callImp("WriteFile", "kernel32.dll");
        emit8(0x85); emit8(0xC0);
        emitJcc("==", lFailWrite);
        // WriteFile writes a DWORD to lpNumberOfBytesWritten ([rsp+0x18]);
        // zero-extend 32-bit load, same as fs_read (avoid stale high dword).
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x18);  // mov eax,[rsp+0x18]
        emit8(0x49); emit8(0x89); emit8(0xC5);        // mov r13, rax (stash count; data done)
        emitJmp(lClose);
        emitLabel(lFailWrite);
        emit8(0x49); emit8(0xC7); emit8(0xC5); emit8(0xFF); emit8(0xFF); emit8(0xFF); emit8(0xFF);  // mov r13, -1
        emitLabel(lClose);
        movqq(1, 3);
        callImp("CloseHandle", "kernel32.dll");
        movqq(0, 13);              // mov rax, r13  (Win64 callees preserve r13)
        emitJmp(lDone);
        emitLabel(lFailOpen);
        movimm(0, -1);
        emitLabel(lDone);
        epilogue();
    }

    // ===================== 2: fs_exists (path, _, _, _) =====================
    {
        int lNo = newLabel(), lDone = newLabel();
        emitLabel(jsHostStubLabel[2]);
        prologue();
        movqq(1, 7);               // rcx = path
        movqq(3, 7);               // rbx = path (fall back harmless)
        emit8(0x31); emit8(0xD2);                       // xor edx, edx (dwDesiredAccess 0)
        emit8(0x41); emit8(0xB8); emit32(7);            // r8d = FILE_SHARE_READ|WRITE|DELETE
        emit8(0x45); emit8(0x31); emit8(0xC9);          // xor r9d, r9d
        movqsp(0x20, 3);                                // OPEN_EXISTING
        movqsp(0x28, 0x80);
        movqsp(0x30, 0);
        callImp("CreateFileA", "kernel32.dll");
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8(0xFF);
        emitJcc("==", lNo);
        movqq(1, 0);               // rcx = handle
        callImp("CloseHandle", "kernel32.dll");
        emit8(0xB8); emit32(1);
        emitJmp(lDone);
        emitLabel(lNo);
        emit8(0x31); emit8(0xC0);                       // xor eax, eax
        emitLabel(lDone);
        epilogue();
    }

    // ===================== 3: get_cwd (buf, cap, _, _) =====================
    {
        emitLabel(jsHostStubLabel[3]);
        prologue();
        movqq(1, 6);               // rcx = cap (a2)  — GetCurrentDirectoryA(nBufferLength, lpBuffer)
        movqq(2, 7);               // rdx = buf (a1)
        callImp("GetCurrentDirectoryA", "kernel32.dll");
        epilogue();
    }

    // ===================== 4: net_connect (host, port, _, _) =====================
    {
        int lWsaOk = newLabel(), lFail = newLabel(), lConnFail = newLabel(), lDone = newLabel();
        emitLabel(jsHostStubLabel[4]);
        prologue();
        movqq(3, 7);               // rbx = host
        movqq(12, 6);              // r12 = port
        // WSAStartup once (guard flag in scratch RWX).
        leaRax(jsWsaFlagLabel);
        emit8(0x80); emit8(0x38); emit8(0x00);          // cmp byte [rax], 0
        emitJcc("!=", lWsaOk);
        leaRdx(jsWsadataLabel);
        emit8(0xB9); emit32(0x0202);                    // ecx = MAKEWORD(2,2)
        callImp("WSAStartup", "ws2_32.dll");
        leaRax(jsWsaFlagLabel);
        emit8(0xC6); emit8(0x00); emit8(0x01);          // mov byte [rax], 1
        emitLabel(lWsaOk);
        movqq(1, 3);               // rcx = host
        callImp("gethostbyname", "ws2_32.dll");
        emit8(0x48); emit8(0x85); emit8(0xC0);          // test rax, rax
        emitJcc("==", lFail);
        emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x18);  // rcx = h_addr_list
        emit8(0x48); emit8(0x8B); emit8(0x09);               // rcx = h_addr_list[0]
        emit8(0x8B); emit8(0x01);                            // eax = IPv4
        emit8(0x4C); emit8(0x8D); emit8(0x15);               // r10 = &addr
        jmpFixups.push_back({code.size(), jsAddrLabel}); emit32(0);
        emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x04);  // [r10+4] = IPv4
        emit8(0x66); emit8(0x41); emit8(0xC7); emit8(0x42); emit8(0x00); emit16(2);  // [r10] = AF_INET
        emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0xC4);  // movzx eax, r12w (port)
        emit8(0x86); emit8(0xE0);                            // htons
        emit8(0x66); emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x02);  // [r10+2] = port
        emit8(0xB9); emit32(2);                              // ecx = AF_INET
        emit8(0xBA); emit32(1);                              // edx = SOCK_STREAM
        emit8(0x41); emit8(0xB8); emit32(6);                 // r8d = IPPROTO_TCP
        callImp("socket", "ws2_32.dll");
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8(0xFF);  // cmp rax, -1
        emitJcc("==", lFail);
        movqq(13, 0);              // r13 = sock
        movqq(1, 13);              // rcx = sock
        leaRdx(jsAddrLabel);       // rdx = &addr
        emit8(0x41); emit8(0xB8); emit32(16);                // r8d = sizeof(sockaddr_in)
        callImp("connect", "ws2_32.dll");
        emit8(0x85); emit8(0xC0);                            // test eax, eax
        emitJcc("!=", lConnFail);
        movqq(0, 13);              // rax = sock
        emitJmp(lDone);
        emitLabel(lConnFail);
        movqq(1, 13);              // rcx = sock
        callImp("closesocket", "ws2_32.dll");
        emitLabel(lFail);
        movimm(0, -1);
        emitLabel(lDone);
        epilogue();
    }

    // ===================== 5/6: net_send / net_recv (sock, buf, len) =========
    {
        emitLabel(jsHostStubLabel[5]);
        prologue();
        movqq(3, 7);               // rbx = sock
        movqq(12, 6);              // r12 = buf
        movqq(13, 2);              // r13 = len
        movqq(1, 3);
        emit8(0x49); emit8(0x8B); emit8(0xD4);        // mov rdx, r12
        emit8(0x4D); emit8(0x8B); emit8(0xC5);        // mov r8, r13
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d
        callImp("send", "ws2_32.dll");
        epilogue();
    }
    {
        emitLabel(jsHostStubLabel[6]);
        prologue();
        movqq(3, 7);
        movqq(12, 6);
        movqq(13, 2);
        movqq(1, 3);
        emit8(0x49); emit8(0x8B); emit8(0xD4);
        emit8(0x4D); emit8(0x8B); emit8(0xC5);
        emit8(0x45); emit8(0x31); emit8(0xC9);
        callImp("recv", "ws2_32.dll");
        epilogue();
    }

    // ===================== 7: net_close (sock) =====================
    {
        emitLabel(jsHostStubLabel[7]);
        prologue();
        movqq(1, 7);               // rcx = sock
        callImp("closesocket", "ws2_32.dll");
        epilogue();
    }

    // ===================== 8: tls_connect (sock, host) =====================
    {
        int lStrLoop = newLabel(), lStrEnd = newLabel();
        emitLabel(jsHostStubLabel[8]);
        prologue();
        movqq(3, 7);               // rbx = sock
        movqq(12, 6);              // r12 = host
        tlsIoInit();
        emit8(0x48); emit8(0x89); emit8(0xDE);        // mov rsi, rbx (sock -> a1)
        emit8(0x49); emit8(0x8B); emit8(0xD4);        // mov rdx, r12 (host -> a2)
        emit8(0x31); emit8(0xC9);                     // xor ecx, ecx (len = 0)
        emitLabel(lStrLoop);
        emit8(0x0F); emit8(0xB6); emit8(0x04); emit8(0x0A);  // movzx eax, byte [rdx+rcx]
        emit8(0x84); emit8(0xC0);                     // test al, al
        emitJcc("==", lStrEnd);
        emit8(0x48); emit8(0xFF); emit8(0xC1);        // inc rcx
        emit8(0xE9); jmpFixups.push_back({code.size(), lStrLoop}); emit32(0);
        emitLabel(lStrEnd);
        movimm(7, TLS_OP_TLS_CONNECT);                // rdi = op
        emitBlobEntryCall();
        epilogue();
    }

    // ===================== 9/10: tls_send / tls_recv (h, buf, len) ==========
    {
        emitLabel(jsHostStubLabel[9]);
        prologue();
        movqq(3, 7);               // rbx = handle
        movqq(12, 6);              // r12 = buf
        movqq(13, 2);              // r13 = len
        tlsIoInit();
        emit8(0x48); emit8(0x89); emit8(0xDE);        // mov rsi, rbx
        emit8(0x49); emit8(0x8B); emit8(0xD4);        // mov rdx, r12
        emit8(0x48); emit8(0x8B); emit8(0xCD);        // mov rcx, r13
        movimm(7, TLS_OP_TLS_SEND);                   // rdi = op
        emitBlobEntryCall();
        epilogue();
    }
    {
        emitLabel(jsHostStubLabel[10]);
        prologue();
        movqq(3, 7);
        movqq(12, 6);
        movqq(13, 2);
        tlsIoInit();
        emit8(0x48); emit8(0x89); emit8(0xDE);
        emit8(0x49); emit8(0x8B); emit8(0xD4);
        emit8(0x48); emit8(0x8B); emit8(0xCD);
        movimm(7, TLS_OP_TLS_RECV);                   // rdi = op
        emitBlobEntryCall();
        epilogue();
    }

    // ===================== 11: tls_close (h) =====================
    {
        emitLabel(jsHostStubLabel[11]);
        prologue();
        movqq(3, 7);               // rbx = handle
        tlsIoInit();
        emit8(0x48); emit8(0x89); emit8(0xDE);        // mov rsi, rbx
        movimm(7, TLS_OP_TLS_CLOSE);                  // rdi = op
        emitBlobEntryCall();
        epilogue();
    }

    // ===================== 12: print (buf, len) =====================
    {
        emitLabel(jsHostStubLabel[12]);
        prologue();
        movqq(3, 7);               // rbx = buf
        movqq(12, 6);              // r12 = len
        emit8(0xB9); emit32((uint32_t)-11);           // ecx = STD_OUTPUT_HANDLE
        callImp("GetStdHandle", "kernel32.dll");
        movqq(13, 0);              // r13 = hOut
        emit8(0x49); emit8(0x8B); emit8(0xCD);        // mov rcx, r13
        movqq(2, 3);                                  // mov rdx, rbx (buf)
        emit8(0x4D); emit8(0x8B); emit8(0xC4);        // mov r8, r12 (len)
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d
        movqsp(0x20, 0);                              // NULL lpNumberOfBytesWritten
        callImp("WriteFile", "kernel32.dll");
        emit8(0x31); emit8(0xC0);                     // xor eax, eax
        epilogue();
    }

    // ============ Scratch: WSA flag + WSADATA + sockaddr (RWX .text) ============
    emitLabel(jsWsadataLabel);
    for (int i = 0; i < 416; i++) emit8(0);
    emitLabel(jsAddrLabel);
    for (int i = 0; i < 16; i++) emit8(0);
    emitLabel(jsWsaFlagLabel);
    emit8(0);
    emitLabel(jsHostFlagLabel);
    emit8(0);
}