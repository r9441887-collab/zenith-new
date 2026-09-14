#include "codegen.h"

// =====================================================================
// Wayland window / shm-framebuffer builtins for the Linux target
// (app linux) — raw socket + hand-encoded wire protocol on top of the
// wl_* base from codegen_wl_linux.cpp. No libwayland, no libc: every
// byte of the window handshake lives in the emitted x86-64 machine code.
//
//   wl_create_window(w, h, title) -> 0 (configured) | -1
//   wl_present()                  -> 0 | -1
//   wl_process()                  -> 0 (close requested) | 1 (keep going)
//   wl_close_window()             -> 0
//   wl_fb()                       -> shm framebuffer address (ARGB8888),
//                                    w*h*4 bytes, stride = w*4 | 0
//   wl_pixel(x, y, color)         -> stores u32 color at fb[(y*w+x)*4]
//
// Object ids: display=1, registry=2, sync-callback=3, wl_compositor=4,
// xdg_wm_base=5, wl_shm=6, wl_surface=7, xdg_surface=8, xdg_toplevel=9,
// wl_shm_pool=10, wl_buffer=11. libwayland-server stores each client's
// objects in a flat id array, so client-created (new_id) objects MUST be
// allocated densely in creation order starting at 2 (any gap -> EINVAL
// "invalid arguments"). The window path therefore reuses the registry(2)/
// callback(3) pair (wl_list_globals() and the window API must not be mixed).
//
// Wire format (little-endian): u32 object id | u16 opcode | u16 size
// (size = bytes incl the 8-byte header). Payload: u(u32), s(u32 len incl
// NUL + bytes padded to 4), o(u32), n(u32).
//
// Requests (validated against Wayland 1.x):
//   get_registry      id1 op1 size12  n=2
//   sync              id1 op0 size12  n=3
//   registry.bind     id2 op0 (u name) (s len interface) (u version) (n new)
//   create_surface    id4 op0 size12  n=7
//   get_xdg_surface   id5 op2 size16  n=8 o=7
//   get_toplevel      id8 op1 size12  n=9
//   set_title         id9 op2 size=12+align4(strlen+1)
//   set_app_id        id9 op3 size24  s="zenith-app"
//   create_pool       id6 op0 size20  u=memfd u=len n=10
//   create_buffer     id10 op0 size32  u=0 u=w u=h u=stride u=0x34325241 n=11
//   attach            id7 op1 size20  o=11 i=0 i=0
//   damage_buffer     id7 op9 size24  i=0 i=0 i=w i=h
//   commit            id7 op6 size8
//   ack_configure     id8 op4 size12  u=serial
//   pong              id5 op3 size12  u=serial
//   destroy           (surface id7 op0 / buffer id11 op0 / pool id10 op1)
//
// Events parsed: registry.global (id2 op0: name@+8, slen@+12, bytes@+16,
// version@16+align4(slen)); callback.done (id3); xdg_surface.configure
// (id8 op0: serial@+8); xdg_toplevel.close (id9 op1); xdg_wm_base.ping
// (id5 op0: serial@+8).
//
// Register discipline (all preserved across leaf syscalls):
//   r12 = w    r13 = title   r14 = h          (from call args)
//   r10       = wlOutRVA base (request scratch)
//   r8        = wlInRVA base (event buffer)
//   r9d/rax   = event parse offset inside a batch
//   rbx       = bytes read / message size / buffer length
// SysV: syscall clobbers rax, rcx (RIP), r11 only.
// =====================================================================

bool Codegen::tryLinuxWLWindowCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isWinBuiltin = (name == "wl_create_window" || name == "wl_present" ||
                               name == "wl_process" || name == "wl_close_window" ||
                               name == "wl_fb" || name == "wl_pixel");
    if (!isWinBuiltin) return false;
    if ((name == "wl_create_window" || name == "wl_pixel") && call->args.size() != 3)
        return false;
    if (name != "wl_create_window" && name != "wl_pixel" && !call->args.empty())
        return false;

    wlUsed = true;

    // Staging mirrors wl_linux/net/vulkan: spill, pause allocation, push
    // callee-saved rdi (7) / rsi (6) and the out-of-pool r12/r13/r14.
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

    auto leaRip = [&](int r, uint32_t rva) {
        if (r >= 8) emit8(0x4C); else emit8(0x48);
        emit8(0x8D);
        emit8((uint8_t)(0x05 | ((r & 7) << 3)));
        globalFixups.push_back({code.size(), rva});
        emit32(0);
    };
    auto svc = [&](uint32_t nr) {
        emit8(0xB8); emit32(nr);
        emit8(0x0F); emit8(0x05);
    };
    auto wlLeave = [&](int label) {
        emit8(0x41); emit8(0x5E);  // pop r14
        emit8(0x41); emit8(0x5D);  // pop r13
        emit8(0x41); emit8(0x5C);  // pop r12
        emit8(0x5E);               // pop rsi
        emit8(0x5F);               // pop rdi
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);  // add rsp, 8
        emitJmp(label);
    };

    // ---- u32 request field builders against [r10 + off] ----
    auto out32 = [&](int off, uint32_t v) {
        emit8(0x41); emit8(0xC7); emit8(0x42); emit8((uint8_t)(int8_t)off); emit32(v);
    };
    auto outReg32 = [&](int off, int reg) {
        if (reg >= 8) emit8(0x45); else emit8(0x41);
        emit8(0x89);  // MOV r/m32, r32
        emit8((uint8_t)(0x42 | ((reg & 7) << 3)));
        emit8((uint8_t)(int8_t)off);
    };
    auto outHeader = [&](int off, uint32_t id, uint16_t op, uint16_t sz) {
        out32(off, id);
        out32(off + 4, (uint32_t)op | ((uint32_t)sz << 16));
    };

    // ---- write(n) to the display fd from wlOutRVA (rax = result) ----
    auto writeOut = [&](uint32_t n) {
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                 // mov edi, [wlFdRVA] (fd)
        leaRip(6, wlOutRVA);                       // rsi = &out
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(n);   // rdx = n
        svc(1);
    };
    auto writeLen = [&]() {
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                 // mov edi, fd
        leaRip(6, wlOutRVA);                       // rsi = &out
        emit8(0x48); emit8(0x89); emit8(0xDA);     // mov rdx, rbx (len)
        svc(1);
    };
    auto writeOutCheck = [&](uint32_t n, int fail) {
        writeOut(n);
        emit8(0x48); emit8(0x85); emit8(0xC0);     // test rax, rax
        emitJcc("<", fail);
    };

    // sendmsg(fd, &msghdr, 0) with SCM_RIGHTS to pass a file descriptor.
    // Builds msghdr+iov+cmsg on the stack (96 bytes).
    auto writeOutFd = [&](uint32_t n, int fd_slot, int fail) {
        // sub rsp, 96 (aligned to 16: original rsp was 16-byte aligned after sub 8 + 5 pushes = 48, so 96 keeps alignment)
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(96);
        // Zero the 96 bytes (msghdr needs NULL/0 fields)
        emit8(0x31); emit8(0xC0);                     // xor eax, eax
        emit8(0x48); emit8(0x89); emit8(0xE7);        // mov rdi, rsp
        emit8(0xB9); emit32(24);                       // ecx = 24 (96/4 dwords)
        emit8(0xF3); emit8(0xAB);                      // rep stosd
        // Stack layout: [rsp+0..55] msghdr, [rsp+56..71] iovec, [rsp+72..95] cmsg

        // msghdr.msg_iov = rsp+56
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38); // lea rax,[rsp+56]
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x10); // mov [rsp+10h],rax
        // msghdr.msg_iovlen = 1
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x18); emit32(1);
        // msghdr.msg_control = rsp+72
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x48); // lea rax,[rsp+72]
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // mov [rsp+20h],rax
        // msghdr.msg_controllen = 24
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(24);
        // iovec.iov_base = wlOutRVA
        leaRip(0, wlOutRVA);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x38); // mov [rsp+38h],rax
        // iovec.iov_len = n
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(n);
        // cmsg.cmsg_len = 20
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x48); emit32(20);
        // cmsg.cmsg_level = SOL_SOCKET (1)
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(1);
        // cmsg.cmsg_type = SCM_RIGHTS (1)
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x54); emit32(1);
        // cmsg.cmsg_data[0] = fd from slot
        leaRip(2, fd_slot);
        emit8(0x8B); emit8(0x02);                     // mov eax, [rdx]
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x58); // mov [rsp+58h],eax

        // sendmsg(fd, &msghdr, 0)
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                     // mov edi, [wlFdRVA]
        emit8(0x48); emit8(0x89); emit8(0xE6);        // mov rsi, rsp
        emit8(0x31); emit8(0xD2);                     // xor edx, edx
        svc(46);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(96); // add rsp, 96
        emitJcc("<", fail);
    };

    // rcx = &inbuf[r9] (r8 = inbuf base, r9d = parse offset).
    auto leaEvent = [&]() {
        emit8(0x4B); emit8(0x8D); emit8(0x0C); emit8(0x08);  // lea rcx, [r8+r9]
    };

    // Save a register arg into the persistent scratch slots.
    auto movToR12 = [&](int s) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC4 | ((s & 7) << 3))); };
    auto movToR13 = [&](int s) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC5 | ((s & 7) << 3))); };
    auto movToR14 = [&](int s) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC6 | ((s & 7) << 3))); };

    // ---- wl_create_window(w, h, title) -> 0 | -1 ----
    if (name == "wl_create_window") {
        int done = newLabel();
        int noFd = newLabel();

        int a0 = emitExpr(call->args[0].get());
        movToR12(a0); freeReg(a0);                // r12 = w
        int a1 = emitExpr(call->args[1].get());
        movToR14(a1); freeReg(a1);                // r14 = h
        int a2 = emitExpr(call->args[2].get());
        movToR13(a2); freeReg(a2);                // r13 = title

        // fd must be open; reset the configured/closed flags.
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                 // mov edi, [wlFdRVA]
        emit8(0x85); emit8(0xFF);                 // test edi, edi
        emitJcc("<=", noFd);
        leaRip(0, wlConfiguredRVA);
        emit8(0xC7); emit8(0x00); emit32(0);
        leaRip(0, wlClosedRVA);
        emit8(0xC7); emit8(0x00); emit32(0);

        // ---- discovery: get_registry(new_id=2) + sync(new_id=3) = 24B ----
        leaRip(10, wlOutRVA);
        outHeader(0, 1, 1, 12);
        out32(8, 2);
        outHeader(12, 1, 0, 12);
        out32(20, 3);
        writeOutCheck(24, noFd);

        // ---- read loop: capture registry.global names until callback.done ----
        // r8 = &inbuf, rbx = n, r9d = offset.
        int rdTop = newLabel(), pxLoop = newLabel(), rdNext = newLabel();
        int skipEvent = newLabel();
        int chkXdg = newLabel(), chkShm = newLabel();
        int discDone = newLabel();
        emitLabel(rdTop);
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                 // mov edi, fd
        leaRip(6, wlInRVA);                        // rsi = &inbuf
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(4096); // rdx = 4096
        svc(0);                                    // read(fd, inbuf, 4096)
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<=", noFd);                       // EOF/err -> fail
        emit8(0x89); emit8(0xC3);                  // mov ebx, eax (n)
        leaRip(8, wlInRVA);                        // r8 = &inbuf
        emit8(0x45); emit8(0x31); emit8(0xC9);     // xor r9d, r9d (offset=0)

        emitLabel(pxLoop);
        emit8(0x49); emit8(0x39); emit8(0xD9);     // cmp r9, rbx
        emitJcc(">=", rdNext);                     // batch consumed -> read again
        leaEvent();                                // rcx = &inbuf[r9]
        emit8(0x8B); emit8(0x39);                  // mov edi, [rcx] (id)
        emit8(0x85); emit8(0xFF);                  // test edi, edi
        emitJcc("<=", skipEvent);
        emit8(0x83); emit8(0xFF); emit8(0x03);     // cmp edi, 3 (callback.done)
        emitJcc("==", discDone);
        emit8(0x83); emit8(0xFF); emit8(0x02);     // cmp edi, 2 (discovery registry)
        emitJcc("!=", skipEvent);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x85); emit8(0xC0);                  // only wl_registry.global (op 0)
        emitJcc("!=", skipEvent);

        // wl_registry.global payload: name@[+8], slen@[+12], bytes@[+16].
        emit8(0x8B); emit8(0x41); emit8(0x0C);     // mov eax, [rcx+12] (slen)
        emit8(0x83); emit8(0xF8); emit8(0x0E);     // cmp eax, 14 (len incl NUL)
        emitJcc("!=", chkXdg);
        // "wl_compositor\0\0" as LE dword pairs.
        emit8(0x81); emit8(0x79); emit8(0x10); emit32(0x635F6C77);
        emitJcc("!=", chkXdg);
        emit8(0x81); emit8(0x79); emit8(0x14); emit32(0x6F706D6F);
        emitJcc("!=", chkXdg);
        emit8(0x81); emit8(0x79); emit8(0x18); emit32(0x6F746973);
        emitJcc("!=", chkXdg);
        emit8(0x81); emit8(0x79); emit8(0x1C); emit32(0x00000072);
        emitJcc("!=", chkXdg);
        emit8(0x8B); emit8(0x41); emit8(0x08);     // mov eax, [rcx+8] (name)
        leaRip(1, wlWNameRVA);
        emit8(0x89); emit8(0x01);                  // mov [rcx], eax
        emitJmp(skipEvent);

        emitLabel(chkXdg);
        emit8(0x83); emit8(0xF8); emit8(0x0C);     // cmp eax, 12
        emitJcc("!=", chkShm);
        // "xdg_wm_base" as 3 LE dwords.
        emit8(0x81); emit8(0x79); emit8(0x10); emit32(0x5F676478);
        emitJcc("!=", chkShm);
        emit8(0x81); emit8(0x79); emit8(0x14); emit32(0x625F6D77);
        emitJcc("!=", chkShm);
        emit8(0x81); emit8(0x79); emit8(0x18); emit32(0x00657361);
        emitJcc("!=", chkShm);
        emit8(0x8B); emit8(0x41); emit8(0x08);
        leaRip(1, wlXdgNameRVA);
        emit8(0x89); emit8(0x01);
        emitJmp(skipEvent);

        emitLabel(chkShm);
        emit8(0x83); emit8(0xF8); emit8(0x07);     // cmp eax, 7
        emitJcc("!=", skipEvent);
        // "wl_shm\0" as 2 LE dwords.
        emit8(0x81); emit8(0x79); emit8(0x10); emit32(0x735F6C77);
        emitJcc("!=", skipEvent);
        emit8(0x81); emit8(0x79); emit8(0x14); emit32(0x00006D68);
        emitJcc("!=", skipEvent);
        emit8(0x8B); emit8(0x41); emit8(0x08);
        leaRip(1, wlShmNameRVA);
        emit8(0x89); emit8(0x01);

        emitLabel(skipEvent);
        leaEvent();
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x06); // movzx eax, word[rcx+6] (size)
        emit8(0x49); emit8(0x01); emit8(0xC1);     // add r9, rax
        emitJmp(pxLoop);

        emitLabel(rdNext);
        emitJmp(rdTop);

        emitLabel(discDone);

        // ---- registry.bind x3: compositor, xdg_wm_base, wl_shm ----
        // wl_compositor: (id2 op0 size40) name len14 "wl_compositor\0" v4 n4
        leaRip(10, wlOutRVA);
        outHeader(0, 2, 0, 40);
        leaRip(1, wlWNameRVA);
        emit8(0x8B); emit8(0x09);                  // mov ecx, [rcx] (name)
        outReg32(8, 1);
        out32(12, 14);
        leaRip(6, wlCompositorStrRVA);             // rsi = "wl_compositor"
        leaRip(7, wlOutRVA);
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x10); // rdi = &out[16]
        emit8(0xB9); emit32(13);                   // ecx = 13
        emit8(0xF3); emit8(0xA4);                  // rep movsb
        out32(32, 4);                              // version = 4
        out32(36, 4);                              // new_id = wl_compositor
        writeOutCheck(40, noFd);

        // xdg_wm_base: (id2 op0 size36) name len12 "xdg_wm_base" v4 n5
        leaRip(10, wlOutRVA);
        outHeader(0, 2, 0, 36);
        leaRip(1, wlXdgNameRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(8, 1);
        out32(12, 12);
        leaRip(6, wlXdgWmBaseStrRVA);
        leaRip(7, wlOutRVA);
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x10);
        emit8(0xB9); emit32(12);
        emit8(0xF3); emit8(0xA4);
        out32(28, 4);                              // version = 4
        out32(32, 5);                              // new_id = xdg_wm_base
        writeOutCheck(36, noFd);

        // wl_shm: (id2 op0 size32) name len7 "wl_shm\0" v1 n6
        leaRip(10, wlOutRVA);
        outHeader(0, 2, 0, 32);
        leaRip(1, wlShmNameRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(8, 1);
        out32(12, 7);
        leaRip(6, wlShmStrRVA);
        leaRip(7, wlOutRVA);
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x10);
        emit8(0xB9); emit32(7);
        emit8(0xF3); emit8(0xA4);
        out32(24, 1);                              // version = 1
        out32(28, 6);                              // new_id = wl_shm
        writeOutCheck(32, noFd);

        // ---- fixed group (64B): create_surface / get_xdg_surface /
        // get_toplevel / set_app_id("zenith-app") ----
        leaRip(10, wlOutRVA);
        outHeader(0, 4, 0, 12);                    // create_surface(n=7)
        out32(8, 7);
        outHeader(12, 5, 2, 16);                   // get_xdg_surface(n=8, o=7)
        out32(20, 8);
        out32(24, 7);
        outHeader(28, 8, 1, 12);                   // get_toplevel(n=9) on xdg_surface
        out32(36, 9);
        outHeader(40, 9, 3, 24);                   // set_app_id on xdg_toplevel
        out32(48, 11);                             // s len = 11
        out32(52, 0x696E657A);                     // "zeni"
        out32(56, 0x612D6874);                     // "th-a"
        out32(60, 0x00007070);                     // "pp\0\0"
        writeOutCheck(64, noFd);

        // ---- set_title: strlen(title)+1, message size grows ----
        emit8(0x4C); emit8(0x89); emit8(0xEE);     // mov rsi, r13 (title)
        emit8(0x31); emit8(0xC9);                  // xor ecx, ecx
        int stTop = newLabel(), stDone = newLabel();
        emitLabel(stTop);
        emit8(0x80); emit8(0x3C); emit8(0x0E); emit8(0x00); // cmp byte [rsi+rcx], 0
        emitJcc("==", stDone);
        emit8(0x48); emit8(0xFF); emit8(0xC1);     // inc rcx
        emitJmp(stTop);
        emitLabel(stDone);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(0x01); // add rcx, 1 (incl NUL)
        leaRip(10, wlOutRVA);
        out32(0, 9);                               // id = xdg_toplevel
        outReg32(8, 1);                            // [r10+8] = len (rcx)
        emit8(0x48); emit8(0x89); emit8(0xC8);     // mov rax, rcx
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(0x03); // add rax, 3
        emit8(0x48); emit8(0x83); emit8(0xE0); emit8(0xFC); // and rax, ~3
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(0x0C); // add rax, 12 (size)
        emit8(0x48); emit8(0x89); emit8(0xC3);     // mov rbx, rax (size)
        emit8(0x44); emit8(0x8B); emit8(0xC0);     // mov r8d, eax
        emit8(0x49); emit8(0xC1); emit8(0xE0); emit8(0x10); // shl r8, 16
        emit8(0x41); emit8(0x81); emit8(0xC8); emit32(2);   // or r8d, 2 (opcode)
        outReg32(4, 8);                            // [r10+4] = op|size<<16
        emit8(0x4C); emit8(0x89); emit8(0xEE);     // mov rsi, r13 (title)
        leaRip(7, wlOutRVA);
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x0C); // rdi = &out[12]
        emit8(0xF3); emit8(0xA4);                  // rep movsb (rcx bytes)
        writeLen();
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<", noFd);

        // ---- shm framebuffer: memfd -> ftruncate -> mmap ----
        leaRip(0, wlWinWRVA);
        emit8(0x44); emit8(0x89); emit8(0x20);     // mov [wlWinWRVA], r12d (w)
        leaRip(0, wlWinHRVA);
        emit8(0x44); emit8(0x89); emit8(0x30);     // mov [wlWinHRVA], r14d (h)
        leaRip(7, wlMemfdNameRVA);                 // rdi = "z-wl-fb"
        emit8(0x31); emit8(0xF6);                  // xor esi, esi (flags=0)
        svc(319);                                  // memfd_create
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<", noFd);
        leaRip(2, wlBufFdRVA);
        emit8(0x48); emit8(0x89); emit8(0x02);     // mov [wlBufFdRVA], rax (memfd)
        emit8(0x4C); emit8(0x89); emit8(0xE0);     // mov rax, r12
        emit8(0x49); emit8(0x0F); emit8(0xAF); emit8(0xC6); // imul rax, r14 (w*h)
        emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x02); // shl rax, 2 (w*h*4)
        emit8(0x48); emit8(0x89); emit8(0xC3);     // mov rbx, rax (len)
        leaRip(7, wlBufFdRVA);
        emit8(0x48); emit8(0x8B); emit8(0x3F);     // mov rdi, [wlBufFdRVA] (memfd)
        emit8(0x48); emit8(0x89); emit8(0xDE);     // mov rsi, rbx (len)
        svc(77);                                   // ftruncate(memfd, len)
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<", noFd);
        emit8(0x31); emit8(0xFF);                  // xor edi, edi (addr=0)
        emit8(0x48); emit8(0x89); emit8(0xDE);     // mov rsi, rbx (len)
        emit8(0xBA); emit32(3);                    // rdx = PROT_READ|PROT_WRITE
        emit8(0x41); emit8(0xBA); emit32(1);       // r10d = MAP_SHARED
        leaRip(8, wlBufFdRVA);
        emit8(0x45); emit8(0x8B); emit8(0x00);     // mov r8d, [r8] (memfd)
        emit8(0x45); emit8(0x31); emit8(0xC9);     // xor r9d, r9d (offset=0)
        svc(9);                                    // mmap
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<", noFd);
        leaRip(2, wlFbPtrRVA);
        emit8(0x48); emit8(0x89); emit8(0x02);     // mov [wlFbPtrRVA], rax
        leaRip(1, wlBufIdRVA);
        emit8(0xC7); emit8(0x01); emit32(11);      // buffer id = 11

        // ---- wl_shm.create_pool(id=10, fd, len) ----
        // fd is type 'f': delivered ONLY via SCM_RIGHTS, no u32 slot in body.
        // Wire: header(8) + new_id(4) + size(4) = 16 bytes total.
        leaRip(10, wlOutRVA);
        outHeader(0, 6, 0, 16);
        out32(8, 10);                                 // new_id = wl_shm_pool
        emit8(0x48); emit8(0x89); emit8(0xDA);     // mov rdx, rbx (len)
        outReg32(12, 2);                             // size = len
        writeOutFd(16, wlBufFdRVA, noFd);            // sendmsg with memfd via SCM_RIGHTS

        // ---- create_buffer(n=11, offset=0, w, h, stride, ARGB8888) ----
        // new_id comes first in the wire, then offset/w/h/stride/format.
        leaRip(10, wlOutRVA);
        outHeader(0, 10, 0, 32);
        out32(8, 11);                                // new_id = wl_buffer
        out32(12, 0);                                // offset = 0
        outReg32(16, 12);                            // width (r12d)
        outReg32(20, 14);                            // height (r14d)
        emit8(0x41); emit8(0x8B); emit8(0xC4);     // mov eax, r12d
        emit8(0xC1); emit8(0xE0); emit8(0x02);     // shl eax, 2 (stride = w*4)
        outReg32(24, 0);                            // stride
        out32(28, 0x34324258);                      // XBGR8888 ("XB24", advertised by server)
        writeOutCheck(32, noFd);

        // ---- first present: attach + damage_buffer + commit (52B) ----
        leaRip(10, wlOutRVA);
        outHeader(0, 7, 1, 20);                    // attach(buffer=11, 0, 0)
        leaRip(1, wlBufIdRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(8, 1);
        out32(12, 0);
        out32(16, 0);
        outHeader(20, 7, 9, 24);                   // damage_buffer(0, 0, w, h)
        out32(28, 0);
        out32(32, 0);
        leaRip(1, wlWinWRVA);
        emit8(0x8B); emit8(0x09);                  // mov ecx, [wlWinWRVA]
        outReg32(36, 1);
        leaRip(1, wlWinHRVA);
        emit8(0x8B); emit8(0x09);                  // mov ecx, [wlWinHRVA]
        outReg32(40, 1);
        outHeader(44, 7, 6, 8);                    // commit
        writeOutCheck(52, noFd);

        // ---- wait for xdg_surface.configure (blocking reads) ----
        int wTop = newLabel(), wParse = newLabel(), wSkip = newLabel();
        int chkTop = newLabel(), chkPing = newLabel();
        emitLabel(wTop);
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                  // mov edi, fd
        leaRip(6, wlInRVA);
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(4096);
        svc(0);                                    // read (blocking)
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<=", noFd);                       // EOF -> fail
        emit8(0x89); emit8(0xC3);                  // mov ebx, eax (n)
        leaRip(8, wlInRVA);                        // r8 = &inbuf
        emit8(0x45); emit8(0x31); emit8(0xC9);     // xor r9d, r9d

        emitLabel(wParse);
        emit8(0x49); emit8(0x39); emit8(0xD9);     // cmp r9, rbx
        emitJcc(">=", wTop);
        leaEvent();                                // rcx = &inbuf[r9]
        emit8(0x8B); emit8(0x39);                  // mov edi, [rcx] (id)
        emit8(0x85); emit8(0xFF);
        emitJcc("<=", wSkip);
        emit8(0x83); emit8(0xFF); emit8(0x08);     // cmp edi, 8 (xdg_surface)
        emitJcc("!=", chkTop);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", wSkip);                      // configure = op 0
        emit8(0x44); emit8(0x8B); emit8(0x69); emit8(0x08); // mov r13d, [rcx+8] (serial)
        leaRip(10, wlOutRVA);
        outHeader(0, 8, 4, 12);                    // ack_configure(serial) on xdg_surface
        outReg32(8, 13);                           // [r10+8] = r13d
        outHeader(12, 7, 6, 8);                    // commit on surface
        writeOutCheck(20, noFd);
        leaRip(0, wlConfiguredRVA);
        emit8(0xC7); emit8(0x00); emit32(1);       // configured = 1
        emit8(0x31); emit8(0xC0);                  // xor eax, eax (return 0)
        emitJmp(done);

        emitLabel(chkTop);
        emit8(0x83); emit8(0xFF); emit8(0x09);     // cmp edi, 9 (xdg_toplevel)
        emitJcc("!=", chkPing);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x83); emit8(0xF8); emit8(0x01);
        emitJcc("!=", wSkip);                      // close = op 1
        leaRip(0, wlClosedRVA);
        emit8(0xC7); emit8(0x00); emit32(1);       // closed = 1
        emit8(0x31); emit8(0xC0);                  // xor eax, eax
        emitJmp(done);

        emitLabel(chkPing);
        emit8(0x83); emit8(0xFF); emit8(0x05);     // cmp edi, 5 (xdg_wm_base)
        emitJcc("!=", wSkip);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", wSkip);                      // ping = op 0
        emit8(0x44); emit8(0x8B); emit8(0x69); emit8(0x08); // mov r13d, [rcx+8] (serial)
        leaRip(10, wlOutRVA);
        outHeader(0, 5, 3, 12);                    // pong(serial)
        outReg32(8, 13);
        writeOut(12);

        emitLabel(wSkip);
        leaEvent();
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x06); // movzx eax, word[rcx+6] (size)
        emit8(0x49); emit8(0x01); emit8(0xC1);     // add r9, rax
        emitJmp(wParse);

        emitLabel(noFd);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1); // rax = -1
        emitLabel(done);
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_present() -> 0 | -1 ----
    if (name == "wl_present") {
        int done = newLabel();
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                  // mov edi, fd
        emit8(0x85); emit8(0xFF);                  // test edi, edi
        emitJcc("<=", done);                       // no window -> -1
        leaRip(10, wlOutRVA);
        outHeader(0, 7, 1, 20);                    // attach(buffer, 0, 0)
        leaRip(1, wlBufIdRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(8, 1);
        out32(12, 0);
        out32(16, 0);
        outHeader(20, 7, 9, 24);                   // damage_buffer(0, 0, w, h)
        out32(28, 0);
        out32(32, 0);
        leaRip(1, wlWinWRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(36, 1);
        leaRip(1, wlWinHRVA);
        emit8(0x8B); emit8(0x09);
        outReg32(40, 1);
        outHeader(44, 7, 6, 8);                    // commit
        writeOut(52);
        emit8(0x31); emit8(0xC0);                  // xor eax, eax
        emitLabel(done);
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_process() -> 0 (close) | 1 (keep going) ----
    if (name == "wl_process") {
        int noData = newLabel();
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                  // mov edi, fd
        emit8(0x85); emit8(0xFF);                  // test edi, edi
        emitJcc("<=", noData);                     // not connected -> keep looping
        leaRip(6, wlInRVA);                        // rsi = &inbuf
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(4096); // rdx = 4096
        emit8(0x41); emit8(0xBA); emit32(0x40);    // r10d = MSG_DONTWAIT
        svc(45);                                   // recv(fd, inbuf, 4096, DONTWAIT)
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("<=", noData);                     // nothing pending / EOF
        emit8(0x89); emit8(0xC3);                  // mov ebx, eax (n)
        leaRip(8, wlInRVA);                        // r8 = &inbuf
        emit8(0x45); emit8(0x31); emit8(0xC9);     // xor r9d, r9d

        int pxLoop = newLabel(), chkPing = newLabel(), skipEvent = newLabel();
        emitLabel(pxLoop);
        emit8(0x49); emit8(0x39); emit8(0xD9);     // cmp r9, rbx
        emitJcc(">=", noData);                     // batch consumed
        leaEvent();                                // rcx = &inbuf[r9]
        emit8(0x8B); emit8(0x39);                  // mov edi, [rcx] (id)
        emit8(0x85); emit8(0xFF);
        emitJcc("<=", skipEvent);
        emit8(0x83); emit8(0xFF); emit8(0x09);     // cmp edi, 9 (xdg_toplevel)
        emitJcc("!=", chkPing);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x83); emit8(0xF8); emit8(0x01);
        emitJcc("!=", skipEvent);                  // close = op 1
        leaRip(0, wlClosedRVA);
        emit8(0xC7); emit8(0x00); emit32(1);       // closed = 1
        emit8(0x31); emit8(0xC0);                  // xor eax, eax (return 0)
        wlLeave(wlExit);

        emitLabel(chkPing);
        emit8(0x83); emit8(0xFF); emit8(0x05);     // cmp edi, 5 (xdg_wm_base)
        emitJcc("!=", skipEvent);
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x04); // movzx eax, word[rcx+4]
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", skipEvent);                  // ping = op 0
        emit8(0x44); emit8(0x8B); emit8(0x69); emit8(0x08); // mov r13d, [rcx+8] (serial)
        leaRip(10, wlOutRVA);
        outHeader(0, 5, 3, 12);                    // pong(serial)
        outReg32(8, 13);
        writeOut(12);

        emitLabel(skipEvent);
        leaEvent();
        emit8(0x0F); emit8(0xB7); emit8(0x41); emit8(0x06); // movzx eax, word[rcx+6] (size)
        emit8(0x49); emit8(0x01); emit8(0xC1);     // add r9, rax
        emitJmp(pxLoop);

        emitLabel(noData);
        emit8(0xB8); emit32(1);                    // rax = 1 (keep going)
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_close_window() -> 0 ----
    if (name == "wl_close_window") {
        int done = newLabel(), skipUnmap = newLabel(), skipFd = newLabel();
        leaRip(2, wlFdRVA);
        emit8(0x8B); emit8(0x3A);                  // mov edi, fd
        emit8(0x85); emit8(0xFF);                  // test edi, edi
        emitJcc("<=", done);                       // not connected -> nothing

        // destroy surface + buffer + pool (24B)
        leaRip(10, wlOutRVA);
        outHeader(0, 7, 0, 8);                     // wl_surface.destroy
        outHeader(8, 11, 0, 8);                    // wl_buffer.destroy
        outHeader(16, 10, 1, 8);                   // wl_shm_pool.destroy
        writeOut(24);

        // munmap(fb, w*h*4)
        leaRip(0, wlFbPtrRVA);
        emit8(0x48); emit8(0x8B); emit8(0x00);     // mov rax, [wlFbPtrRVA]
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("==", skipUnmap);
        emit8(0x49); emit8(0x89); emit8(0xC4);     // mov r12, rax (fb)
        leaRip(1, wlWinWRVA);
        emit8(0x8B); emit8(0x09);                  // mov ecx, [wlWinWRVA] (w)
        leaRip(0, wlWinHRVA);
        emit8(0x0F); emit8(0xAF); emit8(0x08);     // imul ecx, [rax] (h)
        emit8(0xC1); emit8(0xE1); emit8(0x02);     // shl ecx, 2
        emit8(0x48); emit8(0x89); emit8(0xCE);     // mov rsi, rcx (len)
        emit8(0x4C); emit8(0x89); emit8(0xE7);     // mov rdi, r12 (fb)
        svc(11);                                   // munmap
        emitLabel(skipUnmap);
        leaRip(1, wlFbPtrRVA);
        emit8(0x48); emit8(0xC7); emit8(0x01); emit32(0); // fb = 0

        // close(memfd)
        leaRip(0, wlBufFdRVA);
        emit8(0x48); emit8(0x8B); emit8(0x00);     // mov rax, [wlBufFdRVA]
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("==", skipFd);
        emit8(0x48); emit8(0x89); emit8(0xC7);     // mov rdi, rax
        svc(3);                                    // close
        emitLabel(skipFd);
        leaRip(1, wlBufFdRVA);
        emit8(0x48); emit8(0xC7); emit8(0x01); emit32(0); // memfd = 0

        // close(display fd) and drop the connection state
        leaRip(0, wlFdRVA);
        emit8(0x48); emit8(0x8B); emit8(0x00);     // mov rax, [wlFdRVA]
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("==", done);
        emit8(0x48); emit8(0x89); emit8(0xC7);     // mov rdi, rax
        svc(3);                                    // close
        leaRip(1, wlFdRVA);
        emit8(0x48); emit8(0xC7); emit8(0x01); emit32(0); // fd = 0

        emitLabel(done);
        emit8(0x31); emit8(0xC0);                  // xor eax, eax
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_fb() -> framebuffer address | 0 ----
    if (name == "wl_fb") {
        leaRip(0, wlFbPtrRVA);
        emit8(0x48); emit8(0x8B); emit8(0x00);     // mov rax, [wlFbPtrRVA]
        wlLeave(wlExit);
        resultReg = 0;
    }

    // ---- wl_pixel(x, y, color) -> 0 | -1 ----
    if (name == "wl_pixel") {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        movToR13(a0); freeReg(a0);                 // r13 = x
        int a1 = emitExpr(call->args[1].get());
        movToR14(a1); freeReg(a1);                 // r14 = y
        int a2 = emitExpr(call->args[2].get());
        movToR12(a2); freeReg(a2);                 // r12 = color

        leaRip(1, wlWinWRVA);                       // rcx = &w
        emit8(0x41); emit8(0x8B); emit8(0xC6);     // mov eax, r14d (y)
        emit8(0x0F); emit8(0xAF); emit8(0x01);     // imul eax, [rcx] (y*w)
        emit8(0x44); emit8(0x01); emit8(0xE8);     // add eax, r13d (x)
        emit8(0xC1); emit8(0xE0); emit8(0x02);     // shl eax, 2
        leaRip(2, wlFbPtrRVA);
        emit8(0x48); emit8(0x8B); emit8(0x12);     // mov rdx, [wlFbPtrRVA]
        emit8(0x48); emit8(0x85); emit8(0xD2);     // test rdx, rdx
        emitJcc("==", done);                       // no framebuffer -> -1
        emit8(0x48); emit8(0x01); emit8(0xD0);     // add rax, rdx
        emit8(0x44); emit8(0x89); emit8(0x20);     // mov [rax], r12d (color)
        emit8(0x31); emit8(0xC0);                  // xor eax, eax (return 0)
        emitLabel(done);
        wlLeave(wlExit);
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