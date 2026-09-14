#include "codegen.h"
#include "ast.h"

// =====================================================================
// Socket builtins — TCP/UDP servers and clients over Winsock2 (ws2_32.dll).
//
// Real implementations (no stubs): the emitted code calls socket(), bind(),
// listen(), accept(), connect(), send(), recv(), sendto(), recvfrom(),
// closesocket(), gethostbyname(), inet_ntoa(), ioctlsocket() from the real
// ws2_32.dll, which is linked into the PE import table exactly like
// wininet.dll is for http_get. Works on `app console` and `app gui` targets.
//
// Available builtins
//   TCP:
//     net_tcp_listen(port)                 -> int (listening socket, or -1)
//     net_tcp_accept(serverSocket)         -> int (connected socket, or -1)
//     net_tcp_connect(host, port)          -> int (connected socket, or -1)
//     net_tcp_send(sock, data, len)        -> int (bytes sent, or -1)
//     net_tcp_recv(sock, buf, len)         -> int (bytes read, 0=closed, -1=err)
//     net_tcp_close(sock)                  -> int (0 ok, SOCKET_ERROR otherwise)
//   UDP:
//     net_udp_open(port)                   -> int (UDP socket, or -1; port 0 = any)
//     net_udp_send(sock, host, port, data, len) -> int (bytes sent, or -1)
//     net_udp_recv(sock, buf, len)         -> int (bytes read; sender stored)
//     net_udp_peer_ip()                    -> string (sender IP, from last recv)
//     net_udp_peer_port()                  -> int (sender port, from last recv)
//     net_udp_close(sock)                  -> int (0 ok, SOCKET_ERROR otherwise)
//   Control:
//     net_set_nonblocking(sock, enable)    -> int (0 ok, SOCKET_ERROR otherwise)
//     net_last_error()                     -> int (WSAGetLastError() result)
//
// host may be "localhost", "example.com" or "192.168.0.10". Buffer/data
// arguments are any pointer expression, typically &arrayVariable or a string.
// =====================================================================

void Codegen::detectNetSockExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name.rfind("net_", 0) == 0) netSocksUsed = true;
        for (auto& arg : call->args) detectNetSockExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectNetSockExprUsage(bin->left.get());
        detectNetSockExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectNetSockExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectNetSockExprUsage(arr->array.get());
        detectNetSockExprUsage(arr->index.get());
    }
}

void Codegen::detectNetSockStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectNetSockExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectNetSockExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectNetSockExprUsage(assign->indexExpr.get());
        detectNetSockExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectNetSockExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectNetSockExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectNetSockStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectNetSockStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectNetSockExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectNetSockStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectNetSockStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectNetSockExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectNetSockExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectNetSockStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectNetSockExprUsage(fs->start.get());
        detectNetSockExprUsage(fs->end.get());
        if (fs->step) detectNetSockExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectNetSockStmtUsage(s.get());
    }
}

void Codegen::detectNetSockUsage() {
    if (!netSocksUsed) {
        for (auto& func : prog.functions) {
            if (func->isExtern) continue;
            for (auto& stmt : func->body.stmts) detectNetSockStmtUsage(stmt.get());
            if (netSocksUsed) break;
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectNetSockExprUsage(g->init.get());
        if (netSocksUsed) break;
    }
}

// WSAStartup() runs once, lazily, guarded by a flag byte in .data. The two
// RIP-relative slot references emit zero placeholder displacements that
// buildPE patches from sockFixups.
void Codegen::emitNetWsaStartup() {
    int started = newLabel();

    emit8(0x48); emit8(0x8D); emit8(0x05);                 // rax = &wsaStarted
    sockFixups.push_back({code.size(), SOCK_WSA_STARTED}); emit32(0);
    emit8(0x80); emit8(0x38); emit8(0x00);                 // cmp byte [rax], 0
    emitJcc("!=", started);                               // already started?

    emit8(0x48); emit8(0x8D); emit8(0x15);                 // rdx = &WSADATA
    sockFixups.push_back({code.size(), SOCK_WSADATA}); emit32(0);
    emit8(0xB9); emit32(0x0202);                          // ecx = MAKEWORD(2,2)
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "WSAStartup", "ws2_32.dll"}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);

    emit8(0x48); emit8(0x8D); emit8(0x05);                 // rax = &wsaStarted
    sockFixups.push_back({code.size(), SOCK_WSA_STARTED}); emit32(0);
    emit8(0xC6); emit8(0x00); emit8(0x01);                // mov byte [rax], 1
    emitLabel(started);
}

bool Codegen::tryNetCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isTcp = (name == "net_tcp_listen" || name == "net_tcp_accept" ||
                        name == "net_tcp_connect" || name == "net_tcp_send" ||
                        name == "net_tcp_recv" || name == "net_tcp_close");
    const bool isUdp = (name == "net_udp_open" || name == "net_udp_send" ||
                        name == "net_udp_recv" || name == "net_udp_peer_ip" ||
                        name == "net_udp_peer_port" || name == "net_udp_close");
    const bool isCtl = (name == "net_set_nonblocking" || name == "net_last_error");
    if (!isTcp && !isUdp && !isCtl) return false;

    // Arity guards.
    if ((name == "net_tcp_listen" || name == "net_udp_open" || name == "net_tcp_accept" ||
         name == "net_tcp_close" || name == "net_udp_close") && call->args.size() != 1) return false;
    if (name == "net_tcp_connect" && call->args.size() != 2) return false;
    if ((name == "net_tcp_send" || name == "net_tcp_recv" || name == "net_udp_recv") && call->args.size() != 3) return false;
    if (name == "net_udp_send" && call->args.size() != 5) return false;
    if (name == "net_set_nonblocking" && call->args.size() != 2) return false;
    if ((name == "net_last_error" || name == "net_udp_peer_ip" || name == "net_udp_peer_port") && !call->args.empty()) return false;

    // Arguments are staged into callee-saved rdi/rsi/r12 so their values
    // survive the ws2_32 calls on the Win64 ABI; anything beyond rsi goes on
    // the stack (pushed, then popped back off before the common exit).
    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // Tell the register allocator rsi/rdi are busy after we staged a value
    // there so later argument expressions cannot clobber them.
    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7) regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };
    // mov r12, regX  (49 89 C4 | X<<3) — r12 is not in the alloc pool.
    auto movToR12 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC4 | (src << 3)));
    };

    // Pushed at the top of every handler; their logical contents were already
    // spilled by spillRegs(), pops restore the physical values.
    emit8(0x57);              // push rdi
    emit8(0x56);              // push rsi
    emit8(0x41); emit8(0x54); // push r12

    int netExit = newLabel();

    auto importCall = [&](const char* func) {
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), func, "ws2_32.dll"});
        emit32(0);
    };

    // net_tcp_listen(port) -> listening socket | -1 (always sets SO_REUSEADDR-ish
    // behavior implicitly via the standard bind/listen — a real server socket)
    if (name == "net_tcp_listen" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // port -> rdi
        freeReg(a0);
        emitNetWsaStartup();
        emit8(0xB9); emit32(2);                       // ecx = AF_INET
        emit8(0xBA); emit32(1);                       // edx = SOCK_STREAM
        emit8(0x41); emit8(0xB8); emit32(6);          // r8d = IPPROTO_TCP
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("socket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        int sockOk = newLabel(), bindOk = newLabel(), bindFail = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);        // test rax, rax
        emitJcc(">=", sockOk);                        // valid socket (INVALID_SOCKET is -1)
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(sockOk);
        emit8(0x48); emit8(0x89); emit8(0xC6);        // mov rsi, s
        emit8(0x0F); emit8(0xB7); emit8(0xC7);        // movzx eax, di (port)
        emit8(0x86); emit8(0xE0);                     // xchg al, ah (htons)
        emit8(0x48); emit8(0x8D); emit8(0x05);        // rax = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x66); emit8(0xC7); emit8(0x00); emit16(2);            // word [rax] = AF_INET
        emit8(0x66); emit8(0x89); emit8(0x40); emit8(0x02);          // word [rax+2] = port (network order)
        emit8(0xC7); emit8(0x40); emit8(0x04); emit32(0);            // dword [rax+4] = INADDR_ANY
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = s
        emit8(0x48); emit8(0x89); emit8(0xC2);        // rdx = &addr
        emit8(0x41); emit8(0xB8); emit32(16);         // r8d = sizeof(sockaddr_in)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("bind");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", bindOk);
        emitLabel(bindFail);                          // bind failed: close + -1
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = s
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("closesocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(bindOk);
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = s
        emit8(0xBA); emit32(0x7FFFFFFF);              // edx = SOMAXCONN
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("listen");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("!=", bindFail);                      // listen failed too
        emit8(0x48); emit8(0x89); emit8(0xF0);        // mov rax, s
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);                     // pop r12
        emit8(0x5E);                                  // pop rsi
        emit8(0x5F);                                  // pop rdi
        emitJmp(netExit);
    }

    // net_tcp_accept(server) -> client socket | -1 (non-blocking: -1 = none pending)
    if (name == "net_tcp_accept" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        emitNetWsaStartup();
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x31); emit8(0xD2);                     // edx = 0
        emit8(0x45); emit8(0x31); emit8(0xC0);        // r8d = 0
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("accept");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_tcp_connect(host, port) -> connected socket | -1
    if (name == "net_tcp_connect" && call->args.size() == 2) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 6) emitMovReg(6, a0);               // host -> rsi
        freeReg(a0);
        guard(6);
        int a1 = emitExpr(call->args[1].get());
        movToR12(a1);                                 // port -> r12
        freeReg(a1);
        emitNetWsaStartup();

        int hostFail = newLabel(), sockOk = newLabel(), connOk = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xF6);        // test rsi, rsi (host != 0?)
        emitJcc("==", hostFail);
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = host
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("gethostbyname");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0x85); emit8(0xC0);        // test rax, rax
        emitJcc("==", hostFail);
        emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x18);   // rcx = h_addr_list
        emit8(0x48); emit8(0x8B); emit8(0x09);               // rcx = h_addr_list[0]
        emit8(0x8B); emit8(0x01);                            // eax = IPv4
        emit8(0x4C); emit8(0x8D); emit8(0x15);        // r10 = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x04);  // [r10+4] = IPv4
        emit8(0x66); emit8(0x41); emit8(0xC7); emit8(0x42); emit8(0x00); emit16(2);  // [r10] = AF_INET
        emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0xC4);  // movzx eax, r12w (port)
        emit8(0x86); emit8(0xE0);                            // htons
        emit8(0x66); emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x02);  // [r10+2] = port

        emit8(0xB9); emit32(2);                       // ecx = AF_INET
        emit8(0xBA); emit32(1);                       // edx = SOCK_STREAM
        emit8(0x41); emit8(0xB8); emit32(6);          // r8d = IPPROTO_TCP
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("socket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", sockOk);
        emitJmp(hostFail);                            // socket() failed
        emitLabel(sockOk);
        emit8(0x48); emit8(0x89); emit8(0xC7);        // mov rdi, s
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x8D); emit8(0x15);        // rdx = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x41); emit8(0xB8); emit32(16);         // r8d = 16
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("connect");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", connOk);
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s (connect failed)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("closesocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitLabel(hostFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(connOk);
        emit8(0x48); emit8(0x89); emit8(0xF8);        // mov rax, rdi
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_tcp_send(sock, data, len) -> bytes sent | -1
    // net_tcp_recv(sock, buf, len)  -> bytes read | 0 (closed) | -1 (error)
    if ((name == "net_tcp_send" || name == "net_tcp_recv") && call->args.size() == 3) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // data/buf -> rsi
        freeReg(a1);
        guard(6);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 0) emitMovReg(0, a2);
        freeReg(a2);
        emit8(0x50);                                  // push rax (len -> [rsp])
        emitNetWsaStartup();
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x89); emit8(0xF2);        // rdx = buf
        emit8(0x4C); emit8(0x8B); emit8(0x04); emit8(0x24);  // mov r8, [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d (flags)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall(name == "net_tcp_send" ? "send" : "recv");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emitJmp(done);
        emitLabel(done);
        emit8(0x49); emit8(0x89); emit8(0xC3);        // mov r11, rax (save result)
        emit8(0x58);                                  // pop rax (len)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emit8(0x4C); emit8(0x89); emit8(0xD8);        // mov rax, r11
        emitJmp(netExit);
    }

    // net_tcp_close(sock) -> 0 | SOCKET_ERROR
    if (name == "net_tcp_close" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        emitNetWsaStartup();
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("closesocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // ============================= UDP =================================

    // net_udp_open(port) -> UDP socket | -1 (port 0 binds an ephemeral port)
    if (name == "net_udp_open" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // port -> rdi
        freeReg(a0);
        emitNetWsaStartup();
        emit8(0xB9); emit32(2);                       // ecx = AF_INET
        emit8(0xBA); emit32(2);                       // edx = SOCK_DGRAM
        emit8(0x41); emit8(0xB8); emit32(17);         // r8d = IPPROTO_UDP
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("socket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        int sockOk = newLabel(), bindOk = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", sockOk);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(sockOk);
        emit8(0x48); emit8(0x89); emit8(0xC6);        // mov rsi, s
        emit8(0x0F); emit8(0xB7); emit8(0xC7);        // movzx eax, di (port)
        emit8(0x86); emit8(0xE0);                     // htons
        emit8(0x4C); emit8(0x8D); emit8(0x15);        // r10 = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x66); emit8(0x41); emit8(0xC7); emit8(0x42); emit8(0x00); emit16(2);  // [r10] = AF_INET
        emit8(0x66); emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x02);  // [r10+2] = port
        emit8(0x41); emit8(0xC7); emit8(0x42); emit8(0x04); emit32(0);    // [r10+4] = INADDR_ANY
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = s
        emit8(0x4C); emit8(0x89); emit8(0xD2);        // rdx = &addr
        emit8(0x41); emit8(0xB8); emit32(16);         // r8d = 16
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("bind");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", bindOk);
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = s (bind failed)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("closesocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(bindOk);
        emit8(0x48); emit8(0x89); emit8(0xF0);        // mov rax, s
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_send(sock, host, port, data, len) -> bytes sent | -1
    if (name == "net_udp_send" && call->args.size() == 5) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // host -> rsi
        freeReg(a1);
        guard(6);
        int a2 = emitExpr(call->args[2].get());
        movToR12(a2);                                 // port -> r12
        freeReg(a2);
        int a3 = emitExpr(call->args[3].get());
        if (a3 != 0) emitMovReg(0, a3);
        freeReg(a3);
        emit8(0x50);                                  // push rax (data -> [rsp+8])
        int a4 = emitExpr(call->args[4].get());
        if (a4 != 0) emitMovReg(0, a4);
        freeReg(a4);
        emit8(0x50);                                  // push rax (len -> [rsp])
        // winsock order safety: gethostbyname() corrupts nothing but the
        // addr structure here, which is rebuilt below.

        emitNetWsaStartup();
        int hostFail = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xF6);        // test rsi, rsi (host)
        emitJcc("==", hostFail);
        emit8(0x48); emit8(0x89); emit8(0xF1);        // rcx = host
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("gethostbyname");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0x85); emit8(0xC0);        // test rax, rax
        emitJcc("==", hostFail);
        emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x18);   // rcx = h_addr_list
        emit8(0x48); emit8(0x8B); emit8(0x09);               // rcx = h_addr_list[0]
        emit8(0x8B); emit8(0x01);                            // eax = IPv4
        emit8(0x4C); emit8(0x8D); emit8(0x15);        // r10 = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x04);  // [r10+4] = IPv4
        emit8(0x66); emit8(0x41); emit8(0xC7); emit8(0x42); emit8(0x00); emit16(2);  // [r10] = AF_INET
        emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0xC4);  // movzx eax, r12w (port)
        emit8(0x86); emit8(0xE0);                            // htons
        emit8(0x66); emit8(0x41); emit8(0x89); emit8(0x42); emit8(0x02);  // [r10+2] = port

        // sendto(s, data, len, 0, &addr, 16)
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x08);  // rdx = [rsp+8] (data)
        emit8(0x4C); emit8(0x8B); emit8(0x04); emit8(0x24);              // r8 = [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d (flags)
        emit8(0x4C); emit8(0x8D); emit8(0x1D);        // r11 = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0x5C); emit8(0x24); emit8(0x20);  // [rsp+0x20] = &addr
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(16);   // [rsp+0x28] = 16
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x48);
        importCall("sendto");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x48);
        emitJmp(done);
        emitLabel(hostFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(done);
        emit8(0x49); emit8(0x89); emit8(0xC3);        // mov r11, rax (save result)
        emit8(0x58);                                  // pop rax (len)
        emit8(0x58);                                  // pop rax (data)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emit8(0x4C); emit8(0x89); emit8(0xD8);        // mov rax, r11
        emitJmp(netExit);
    }

    // net_udp_recv(sock, buf, len) -> bytes read | -1 (peer stored)
    if (name == "net_udp_recv" && call->args.size() == 3) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // buf -> rsi
        freeReg(a1);
        guard(6);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 0) emitMovReg(0, a2);
        freeReg(a2);
        emit8(0x50);                                  // push rax (len -> [rsp])
        emitNetWsaStartup();
        emit8(0x4C); emit8(0x8D); emit8(0x15);        // r10 = &addrLen
        sockFixups.push_back({code.size(), SOCK_PEER_LEN}); emit32(0);
        emit8(0x41); emit8(0xC7); emit8(0x02); emit32(16);  // dword [r10] = 16
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x89); emit8(0xF2);        // rdx = buf
        emit8(0x4C); emit8(0x8B); emit8(0x04); emit8(0x24);  // r8 = [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d (flags)
        emit8(0x4C); emit8(0x8D); emit8(0x15);        // r10 = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0x54); emit8(0x24); emit8(0x20);  // [rsp+0x20] = &addr
        emit8(0x4C); emit8(0x8D); emit8(0x1D);        // r11 = &addrLen
        sockFixups.push_back({code.size(), SOCK_PEER_LEN}); emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0x5C); emit8(0x24); emit8(0x28);  // [rsp+0x28] = &addrLen
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x48);
        importCall("recvfrom");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x48);
        emitJmp(done);
        emitLabel(done);
        emit8(0x49); emit8(0x89); emit8(0xC3);        // mov r11, rax
        emit8(0x58);                                  // pop rax (len)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emit8(0x4C); emit8(0x89); emit8(0xD8);        // mov rax, r11
        emitJmp(netExit);
    }

    // net_udp_peer_ip() -> string (inet_ntoa of the last packet's sender)
    if (name == "net_udp_peer_ip" && call->args.empty()) {
        int done = newLabel();
        emitNetWsaStartup();
        emit8(0x48); emit8(0x8D); emit8(0x05);        // rax = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(0x04);  // rax += 4 (&sin_addr)
        emit8(0x48); emit8(0x89); emit8(0xC1);        // rcx = rax
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("inet_ntoa");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_peer_port() -> int (ntohs of the last packet's sender port)
    if (name == "net_udp_peer_port" && call->args.empty()) {
        int done = newLabel();
        emit8(0x48); emit8(0x8D); emit8(0x05);        // rax = &addr
        sockFixups.push_back({code.size(), SOCK_PEER_ADDR}); emit32(0);
        emit8(0x0F); emit8(0xB7); emit8(0x40); emit8(0x02);  // movzx eax, word [rax+2]
        emit8(0x86); emit8(0xE0);                     // xchg al, ah (ntohs)
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_close(sock) -> 0 | SOCKET_ERROR
    if (name == "net_udp_close" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        emitNetWsaStartup();
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("closesocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // ========================== Control =================================

    // net_set_nonblocking(sock, enable) -> 0 | SOCKET_ERROR
    if (name == "net_set_nonblocking" && call->args.size() == 2) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // enable -> rsi
        freeReg(a1);
        guard(6);
        emitNetWsaStartup();
        emit8(0x4C); emit8(0x8D); emit8(0x05);        // r8 = &argp
        sockFixups.push_back({code.size(), SOCK_PEER_LEN}); emit32(0);
        emit8(0x41); emit8(0x89); emit8(0x30);        // dword [r8] = esi
        emit8(0x48); emit8(0x89); emit8(0xF9);        // rcx = s
        emit8(0xBA); emit32(0x8004667E);              // edx = FIONBIO
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("ioctlsocket");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_last_error() -> int
    if (name == "net_last_error" && call->args.empty()) {
        int done = newLabel();
        emitNetWsaStartup();
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("WSAGetLastError");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // ================= Common exit: restore the allocator view ================
    emitLabel(netExit);
    // The result value is in rax. Re-seat it in the register the allocator
    // believes owns the value, exactly like http_get does.
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