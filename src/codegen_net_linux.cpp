#include "codegen.h"

// =====================================================================
// Socket builtins for the Linux target (app linux) — raw syscall socket I/O.
//
// Mirrors the Windows ws2_32 backend (codegen_net.cpp) function-for-function
// so `app console` / `app linux` source stays portable:
//   TCP:  net_tcp_listen(port) / net_tcp_accept(s) / net_tcp_connect(host,port)
//          net_tcp_send(s,data,len) / net_tcp_recv(s,buf,len) / net_tcp_close(s)
//   UDP:  net_udp_open(port) / net_udp_send(s,host,port,data,len)
//          net_udp_recv(s,buf,len) / net_udp_peer_ip() / net_udp_peer_port()
//          net_udp_close(s)
//   Ctl:  net_set_nonblocking(s,on) / net_last_error()
//
// Everything uses the raw Linux x86-64 syscall ABI: nr in rax, args in
// rdi,rsi,rdx,r10,r8,r9 (arg4 is r10, NOT rcx). A successful syscall
// returns 0/positive; a failure returns -errno, which is clamped to the
// language contract (-1) while the positive errno is recorded in a .data
// slot read by net_last_error().
//
// Host resolution: "localhost" -> 127.0.0.1 (fast path); any other host must
// be a dotted IPv4 literal (raw syscalls have no resolver). DNS via
// /etc/resolv.conf is a future milestone.
//
// Registers: rdi/rsi/r12 are staged (callee-saved, surviving the syscalls,
// exactly like the Windows net backend); r8-r11, r13-r15 are free scratch
// (the allocator pool is only rax/rcx/rdx/rbx/rsi/rdi). The parser below
// treats every syscall's return conservatively: -errno on failure.
// =====================================================================

bool Codegen::tryLinuxNetCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isTcp = (name == "net_tcp_listen" || name == "net_tcp_accept" ||
                        name == "net_tcp_connect" || name == "net_tcp_send" ||
                        name == "net_tcp_recv" || name == "net_tcp_close");
    const bool isUdp = (name == "net_udp_open" || name == "net_udp_send" ||
                        name == "net_udp_recv" || name == "net_udp_peer_ip" ||
                        name == "net_udp_peer_port" || name == "net_udp_close");
    const bool isCtl = (name == "net_set_nonblocking" || name == "net_last_error");
    if (!isTcp && !isUdp && !isCtl) return false;

    // Arity guards (identical to the Windows backend).
    if ((name == "net_tcp_listen" || name == "net_udp_open" || name == "net_tcp_accept" ||
         name == "net_tcp_close" || name == "net_udp_close") && call->args.size() != 1) return false;
    if (name == "net_tcp_connect" && call->args.size() != 2) return false;
    if ((name == "net_tcp_send" || name == "net_tcp_recv" || name == "net_udp_recv") && call->args.size() != 3) return false;
    if (name == "net_udp_send" && call->args.size() != 5) return false;
    if (name == "net_set_nonblocking" && call->args.size() != 2) return false;
    if ((name == "net_last_error" || name == "net_udp_peer_ip" || name == "net_udp_peer_port") && !call->args.empty()) return false;

    netSocksUsed = true;

    // Layout slots (allocated by buildLinuxImportData under netSocksUsed).
    uint32_t peerRVA = sockPeerRVA;        // 16B sockaddr_in
    uint32_t peerLenRVA = sockPeerLenRVA;  // 8B addrlen
    uint32_t errRVA = linNetErrRVA;        // 8B last error
    uint32_t ipbufRVA = linNetIpBufRVA;    // 16B peer ip string

    // Staging mirrors the Windows backend: spill, pause allocation, push the
    // callee-saved rdi/rsi (pool regs 7/6) and r12 (outside the pool).
    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7) regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };
    // mov r12, regX  (49 89 C4 | X<<3) — r12 is not in the alloc pool.
    auto movToR12 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC4 | (src << 3)));
    };

    emit8(0x57);              // push rdi
    emit8(0x56);              // push rsi
    emit8(0x41); emit8(0x54); // push r12

    int netExit = newLabel();

    // lea reg, [rip + slotRVA] — handles general regs (0..15).
    auto leaRip = [&](int r, uint32_t rva) {
        if (r >= 8) emit8(0x4C); else emit8(0x48);   // REX.W (+ REX.R for r8-r15)
        emit8(0x8D);
        emit8((uint8_t)(0x05 | ((r & 7) << 3)));     // mod=00 rm=101 (rip+disp32)
        globalFixups.push_back({code.size(), rva});
        emit32(0);
    };

    // syscall with nr loaded into rax (0F 05). Args are set beforehand.
    auto svc = [&](uint32_t nr) {
        emit8(0xB8); emit32(nr);
        emit8(0x0F); emit8(0x05);
    };

    // rax holds -errno from a failed syscall: store +errno in the slot, set
    // rax = -1. Clobbers rax/rcx/r10 only.
    auto storeErr = [&]() {
        emit8(0x48); emit8(0x89); emit8(0xC1);      // mov rcx, rax
        emit8(0x48); emit8(0xF7); emit8(0xD9);      // neg rcx  -> +errno
        leaRip(10, errRVA);
        emit8(0x49); emit8(0x89); emit8(0x0A);      // mov [r10], rcx
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // mov rax, -1
    };

    // Resolve the host string in rsi into the sockaddr peer slot:
    //   "localhost"  -> 127.0.0.1 (fast path, 4 compare/load ops)
    //   "a.b.c.d" or "1.2" style -> dotted-quad parser (missing octets are 0)
    // Leaves rdx = &peer throughout; clobbers rax, rcx, r8, r9, rsi, flags.
    auto emitHostBuild = [&]() {
        int bparse = newLabel(), hdone = newLabel();
        leaRip(2, peerRVA);                            // rdx = &peer
        emit8(0x81); emit8(0x3E); emit32(0x61636F6C);  // cmp dword [rsi], 'loca'
        emitJcc("!=", bparse);
        emit8(0x81); emit8(0x7E); emit8(0x04); emit32(0x736F686C); // cmp dword [rsi+4], 'lhos'
        emitJcc("!=", bparse);
        emit8(0x80); emit8(0x7E); emit8(0x08); emit8(0x74);  // cmp byte [rsi+8], 't'
        emitJcc("!=", bparse);
        emit8(0x80); emit8(0x7E); emit8(0x09); emit8(0x00);  // cmp byte [rsi+9], 0
        emitJcc("!=", bparse);
        emit8(0xC7); emit8(0x42); emit8(0x04); emit32(0x0100007F); // peer[4] = 127.0.0.1
        emitJmp(hdone);
        emitLabel(bparse);
        emit8(0x4C); emit8(0x8D); emit8(0x4A); emit8(0x04);  // r9 = &peer.sin_addr
        emit8(0x45); emit8(0x31); emit8(0xC0);               // xor r8d, r8d (octet value)
        emit8(0x31); emit8(0xC9);                            // xor ecx, ecx (octet count)
        int pqTop = newLabel(), pqDot = newLabel(), pqStore = newLabel(), pqDone = newLabel();
        emitLabel(pqTop);
        emit8(0x0F); emit8(0xB6); emit8(0x06);         // movzx eax, byte [rsi]
        emit8(0x84); emit8(0xC0);                      // test al, al
        emitJcc("==", pqStore);                        // NUL -> store final octet
        emit8(0x3C); emit8(0x2E);                      // cmp al, '.'
        emitJcc("==", pqDot);
        emit8(0x2C); emit8(0x30);                      // sub al, '0'
        emit8(0x45); emit8(0x6B); emit8(0xC0); emit8(0x0A); // imul r8d, r8d, 10
        emit8(0x44); emit8(0x01); emit8(0xC0);         // add r8d, eax
        emit8(0x48); emit8(0xFF); emit8(0xC6);         // inc rsi
        emitJmp(pqTop);
        emitLabel(pqDot);
        emit8(0x49); emit8(0x88); emit8(0x01);         // mov byte [r9], r8b
        emit8(0x49); emit8(0xFF); emit8(0xC1);         // inc r9
        emit8(0x45); emit8(0x31); emit8(0xC0);         // xor r8d, r8d
        emit8(0x48); emit8(0xFF); emit8(0xC6);         // inc rsi
        emit8(0xFF); emit8(0xC1);                      // inc ecx
        emit8(0x83); emit8(0xF9); emit8(0x03);         // cmp ecx, 3
        emitJcc("==", pqTop);                          // 3rd dot: parse the 4th octet too
        emitJmp(pqTop);
        emitLabel(pqStore);
        emit8(0x49); emit8(0x88); emit8(0x01);         // mov byte [r9], r8b
        emitLabel(pqDone);
        emitLabel(hdone);
    };

    // Build the sockaddr_in family+port fields after the host string has been
    // resolved into [rdx+4] (sin_addr). rdx points at the peer slot; the
    // resolved address bytes must stay untouched.
    auto storePortAddr = [&]() {
        emit8(0x66); emit8(0xC7); emit8(0x02); emit16(2);          // word [rdx] = AF_INET
        emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0xC4);        // movzx eax, r12w
        emit8(0x86); emit8(0xE0);                                  // xchg al, ah (htons)
        emit8(0x66); emit8(0x89); emit8(0x42); emit8(0x02);        // word [rdx+2] = port
    };

    // Build a sockaddr_in in the peer slot from the staged port (r12): AF_INET,
    // port htons(r12w), INADDR_ANY. rdx already points at the peer slot.
    auto storeListenAddr = [&]() {
        emit8(0x66); emit8(0xC7); emit8(0x02); emit16(2);          // word [rdx] = AF_INET
        emit8(0x41); emit8(0x0F); emit8(0xB7); emit8(0xC4);        // movzx eax, r12w
        emit8(0x86); emit8(0xE0);                                  // xchg al, ah (htons)
        emit8(0x66); emit8(0x89); emit8(0x42); emit8(0x02);        // word [rdx+2] = port
        emit8(0xC7); emit8(0x42); emit8(0x04); emit32(0);          // dword [rdx+4] = INADDR_ANY
    };

    // net_tcp_listen(port) / net_udp_open(port) -> socket | -1
    // socket(AF_INET, type, proto) + bind(peer, ANY) [+ listen for TCP]
    if ((name == "net_tcp_listen" || name == "net_udp_open") && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // port -> rdi
        freeReg(a0);
        movToR12(7);                                  // r12 = port
        emit8(0xBF); emit32(2);                       // rdi = AF_INET
        emit8(0xBE); emit32(name == "net_tcp_listen" ? 1 : 2); // rsi = SOCK_STREAM / SOCK_DGRAM
        emit8(0xBA); emit32(name == "net_tcp_listen" ? 6 : 17); // rdx = IPPROTO_TCP / UDP
        svc(41);                                      // socket
        int sockOk = newLabel(), bindOk = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);        // test rax, rax
        emitJcc(">=", sockOk);
        storeErr();                                   // socket failed
        emitJmp(done);
        emitLabel(sockOk);
        emit8(0x48); emit8(0x89); emit8(0xC7);        // rdi = fd
        leaRip(2, peerRVA);                           // rdx = &peer
        storeListenAddr();
        emit8(0x48); emit8(0x89); emit8(0xD6);        // rsi = &peer
        emit8(0xBA); emit32(16);                      // rdx = sizeof(sockaddr_in)
        svc(49);                                      // bind
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", bindOk);
        storeErr();                                   // bind failed: errno + close
        svc(3);                                       // close(fd)
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(bindOk);
        if (name == "net_tcp_listen") {
            emit8(0xBE); emit32(128);                 // rsi = backlog
            svc(50);                                  // listen
            emit8(0x85); emit8(0xC0);                 // test eax, eax
            int bindFail = newLabel();
            emitJcc("!=", bindFail);
            emit8(0x48); emit8(0x89); emit8(0xF8);    // rax = fd
            emitJmp(done);
            emitLabel(bindFail);
            storeErr();                               // listen failed
            svc(3);                                   // close(fd)
            emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        } else {
            emit8(0x48); emit8(0x89); emit8(0xF8);    // rax = fd
        }
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);                     // pop r12
        emit8(0x5E);                                  // pop rsi
        emit8(0x5F);                                  // pop rdi
        emitJmp(netExit);
    }

    // net_tcp_accept(server) -> client socket | -1 (blocking)
    if (name == "net_tcp_accept" && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        emit8(0x31); emit8(0xF6);                     // xor esi, esi
        emit8(0x31); emit8(0xD2);                     // xor edx, edx
        svc(43);                                      // accept(fd, NULL, NULL)
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", done);
        storeErr();                                   // -1 (+errno stored)
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
        int hostFail = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xF6);        // test rsi, rsi (host != 0?)
        emitJcc("==", hostFail);
        int a1 = emitExpr(call->args[1].get());
        movToR12(a1);                                 // port -> r12
        freeReg(a1);
        emitHostBuild();                              // peer slot filled; rdx = &peer
        storePortAddr();                              // family + htons(port)
        int sockOk = newLabel(), connOk = newLabel();
        emit8(0xBF); emit32(2);                       // rdi = AF_INET
        emit8(0xBE); emit32(1);                       // rsi = SOCK_STREAM
        emit8(0xBA); emit32(6);                       // rdx = IPPROTO_TCP
        svc(41);                                      // socket
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", sockOk);
        storeErr();
        emitJmp(done);
        emitLabel(sockOk);
        emit8(0x48); emit8(0x89); emit8(0xC7);        // rdi = fd
        leaRip(6, peerRVA);                           // rsi = &peer
        emit8(0xBA); emit32(16);                      // rdx = sizeof
        svc(42);                                      // connect
        emit8(0x85); emit8(0xC0);                     // test eax, eax
        emitJcc("==", connOk);
        storeErr();                                   // connect failed: errno + close
        svc(3);                                       // close(fd)
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(connOk);
        emit8(0x48); emit8(0x89); emit8(0xF8);        // rax = fd
        emitJmp(done);
        emitLabel(hostFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_tcp_send(sock, data, len) / net_tcp_recv(sock, buf, len)
    if ((name == "net_tcp_send" || name == "net_tcp_recv") && call->args.size() == 3) {
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
        emit8(0x48); emit8(0x8B); emit8(0x14); emit8(0x24); // rdx = [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xD2);        // xor r10d, r10d (flags)
        svc(name == "net_tcp_send" ? 44 : 45);        // send / recv
        int ok = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", ok);
        storeErr();                                   // -1 on failure
        emitLabel(ok);
        emit8(0x49); emit8(0x89); emit8(0xC3);        // mov r11, rax (save result)
        emit8(0x58);                                  // pop rax (len)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emit8(0x4C); emit8(0x89); emit8(0xD8);        // mov rax, r11
        emitJmp(netExit);
    }

    // net_tcp_close(sock) / net_udp_close(sock) -> 0 | -1
    if ((name == "net_tcp_close" || name == "net_udp_close") && call->args.size() == 1) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        svc(3);                                       // close
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", done);
        storeErr();                                   // -1 (+errno stored)
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_send(sock, host, port, data, len) -> bytes | -1
    if (name == "net_udp_send" && call->args.size() == 5) {
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // host -> rsi
        freeReg(a1);
        guard(6);
        int hostFail = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xF6);        // test rsi, rsi (host != 0?)
        emitJcc("==", hostFail);
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
        emitHostBuild();                              // peer slot filled
        storePortAddr();                              // family + htons(port)
        leaRip(8, peerRVA);                           // r8 = &peer
        emit8(0x41); emit8(0xB9); emit32(16);         // r9 = sizeof(sockaddr_in)
        emit8(0x48); emit8(0x8B); emit8(0x74); emit8(0x24); emit8(0x08); // rsi = [rsp+8] (data)
        emit8(0x48); emit8(0x8B); emit8(0x14); emit8(0x24); // rdx = [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xD2);        // xor r10d, r10d (flags)
        svc(44);                                      // sendto
        int ok = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", ok);
        storeErr();
        emitLabel(ok);
        emit8(0x49); emit8(0x89); emit8(0xC3);        // mov r11, rax
        emit8(0x58);                                  // pop rax (len)
        emit8(0x58);                                  // pop rax (data)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
        emitLabel(hostFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_recv(sock, buf, len) -> bytes | -1 (sender stored; peer_ip/port)
    if (name == "net_udp_recv" && call->args.size() == 3) {
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);
        freeReg(a1);
        guard(6);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 0) emitMovReg(0, a2);
        freeReg(a2);
        emit8(0x50);                                  // push rax (len -> [rsp])
        leaRip(9, peerLenRVA);                        // r9 = &peerLen
        emit8(0x41); emit8(0xC7); emit8(0x01); emit32(16); // dword [r9] = sizeof
        emit8(0x48); emit8(0x8B); emit8(0x14); emit8(0x24); // rdx = [rsp] (len)
        emit8(0x45); emit8(0x31); emit8(0xD2);        // xor r10d, r10d (flags)
        leaRip(8, peerRVA);                           // r8 = &peer
        svc(45);                                      // recvfrom

        // On success format the sender ip into ipbuf (so peer_ip() is cheap);
        // on failure clamp to -1 and record errno.
        int fmtSkip = newLabel(), afterFmt = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);        // test rax, rax
        emitJcc("<", fmtSkip);
        emit8(0x49); emit8(0x89); emit8(0xC2);        // mov r10, rax (result)
        leaRip(15, peerRVA);                          // r15 = &peer
        leaRip(14, ipbufRVA);                         // r14 = &ipbuf

        // Per-octet emitter: formats byte[r15+4+off] into ipbuf as decimal,
        // append sep ('.' between octets, 0 as the trailing NUL).
        auto octet = [&](int off, uint8_t sep) {
            emit8(0x41); emit8(0x0F); emit8(0xB6); emit8(0x47); emit8((uint8_t)(4 + off)); // movzx eax, byte[r15+4+off]
            int skipH = newLabel(), printT = newLabel(), skipT = newLabel();
            emit8(0x3D); emit32(100);                 // cmp eax, 100
            emit8(0x0F); emit8(0x82);                 // jb  (unsigned)
            jmpFixups.push_back({code.size(), skipH});
            emit32(0);
            emit8(0x31); emit8(0xD2);                 // xor edx, edx
            emit8(0xB9); emit32(100);                 // mov ecx, 100
            emit8(0xF7); emit8(0xF1);                 // div ecx (eax=100s, edx=rem)
            emit8(0x04); emit8(0x30);                 // add al, '0'
            emit8(0x41); emit8(0x88); emit8(0x06);    // mov [r14], al
            emit8(0x49); emit8(0xFF); emit8(0xC6);    // inc r14
            emit8(0x89); emit8(0xD0);                 // mov eax, edx
            emit8(0x31); emit8(0xD2);                 // xor edx, edx
            emit8(0xB9); emit32(10);                  // mov ecx, 10
            emit8(0xF7); emit8(0xF1);                 // div ecx (eax=10s, edx=units)
            emitJmp(printT);                          // hundreds shown -> always show tens
            emitLabel(skipH);
            emit8(0x31); emit8(0xD2);                 // xor edx, edx
            emit8(0xB9); emit32(10);                  // mov ecx, 10
            emit8(0xF7); emit8(0xF1);                 // div ecx (eax=10s, edx=units)
            emit8(0x84); emit8(0xC0);                 // test al, al
            emitJcc("==", skipT);
            emitLabel(printT);
            emit8(0x04); emit8(0x30);                 // add al, '0'
            emit8(0x41); emit8(0x88); emit8(0x06);    // mov [r14], al
            emit8(0x49); emit8(0xFF); emit8(0xC6);    // inc r14
            emitLabel(skipT);
            emit8(0x89); emit8(0xD0);                 // mov eax, edx (units)
            emit8(0x04); emit8(0x30);                 // add al, '0'
            emit8(0x41); emit8(0x88); emit8(0x06);    // mov [r14], al
            emit8(0x49); emit8(0xFF); emit8(0xC6);    // inc r14
            emit8(0x41); emit8(0xC6); emit8(0x06); emit8(sep); // mov [r14], sep
            emit8(0x49); emit8(0xFF); emit8(0xC6);    // inc r14
        };
        octet(0, '.');
        octet(1, '.');
        octet(2, '.');
        octet(3, 0);                                   // NUL terminates
        emitJmp(afterFmt);
        emitLabel(fmtSkip);
        storeErr();                                   // rax = -1
        emit8(0x49); emit8(0x89); emit8(0xC2);        // mov r10, rax
        emitLabel(afterFmt);
        emit8(0x4D); emit8(0x89); emit8(0xD3);        // mov r11, r10
        emit8(0x58);                                  // pop rax (len)
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emit8(0x4C); emit8(0x89); emit8(0xD8);        // mov rax, r11
        emitJmp(netExit);
    }

    // net_udp_peer_ip() -> string (ipbuf, -- formatted by net_udp_recv)
    if (name == "net_udp_peer_ip" && call->args.empty()) {
        int done = newLabel();
        leaRip(0, ipbufRVA);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_udp_peer_port() -> int (ntohs of last packet's sender port)
    if (name == "net_udp_peer_port" && call->args.empty()) {
        int done = newLabel();
        leaRip(0, peerRVA);
        emit8(0x0F); emit8(0xB7); emit8(0x40); emit8(0x02); // movzx eax, word [rax+2]
        emit8(0x86); emit8(0xE0);                     // xchg al, ah
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_set_nonblocking(sock, enable) -> 0 | -1 (fcntl F_GETFL/F_SETFL)
    if (name == "net_set_nonblocking" && call->args.size() == 2) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // sock -> rdi
        freeReg(a0);
        guard(7);
        int a1 = emitExpr(call->args[1].get());
        movToR12(a1);                                 // enable -> r12
        freeReg(a1);
        emit8(0xBE); emit32(3);                       // rsi = F_GETFL
        svc(72);                                      // fcntl
        int getOk = newLabel(), setF = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", getOk);
        storeErr();
        emitJmp(done);
        emitLabel(getOk);
        emit8(0x4C); emit8(0x89); emit8(0xC0);        // mov r8, rax (original flags)
        emit8(0x4D); emit8(0x85); emit8(0xE4);        // test r12, r12
        emitJcc("==", setF);                          // r12 == 0 -> clear (keep rax)
        emit8(0x4C); emit8(0x89); emit8(0xC0);        // mov rax, r8
        emit8(0x0D); emit32(2048);                    // or eax, O_NONBLOCK
        emitLabel(setF);
        emit8(0x48); emit8(0x89); emit8(0xC2);        // mov rdx, rax (new flags)
        emit8(0xBE); emit32(4);                       // rsi = F_SETFL
        svc(72);                                      // fcntl
        int ok = newLabel();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc(">=", ok);
        storeErr();
        emitLabel(ok);
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // net_last_error() -> int (slot filled by storeErr)
    if (name == "net_last_error" && call->args.empty()) {
        int done = newLabel();
        leaRip(0, errRVA);
        emit8(0x8B); emit8(0x00);                     // mov eax, [rax]
        emitJmp(done);
        emitLabel(done);
        emit8(0x41); emit8(0x5C);
        emit8(0x5E);
        emit8(0x5F);
        emitJmp(netExit);
    }

    // ================= Common exit: restore the allocator view ================
    emitLabel(netExit);
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