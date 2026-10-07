// BIOS-mode builtins: emit 32-bit x86 code (bios/kernel_mode: dependent apps are forced to X86_32).
// All handlers follow the same convention as the other builtin files:
//   int saved = regsUsed; spillRegs(); regsUsed = 0;  -> emit code ->  regsUsed = saved&~1; reloadRegs(); regsUsed = saved|1; resultReg = 0; return true;

#include "codegen.h"
#include <cstdint>

bool Codegen::tryBIOSCall(CallExpr* call, int& resultReg) {
    if (wordSize != 32) return false;  // BIOS path is only valid for 32-bit output

    // ============== Keyboard ==============

    // char bios_get_char() -> returns AH=scancode, AL=ascii
    if (call->name == "bios_get_char" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xB4); emit8(0x00);       // mov ah, 0
        emit8(0xCD); emit8(0x16);       // int 0x16
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // int bios_check_key() -> returns 1 if a key is waiting, 0 otherwise
    if (call->name == "bios_check_key" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xB4); emit8(0x01);       // mov ah, 1
        emit8(0xCD); emit8(0x16);       // int 0x16
        emit8(0x0F); emit8(0x95); emit8(0xC0);  // setnz al
        emit8(0x0F); emit8(0xB6); emit8(0xC0);  // movzx eax, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Video ==============

    // void bios_set_cursor(int x, int y)
    if (call->name == "bios_set_cursor" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rx = emitExpr(call->args[0].get());
        if (rx != 0) { emitMovReg(0, rx); freeReg(rx); } else freeReg(0);
        emit8(0x50);                    // push eax  (x)
        int ry = emitExpr(call->args[1].get());
        if (ry != 0) { emitMovReg(0, ry); freeReg(ry); } else freeReg(0);
        emit8(0x50);                    // push eax  (y)
        emit8(0x5B);                    // pop ebx  (y)
        emit8(0x58);                    // pop eax  (x)
        emit8(0xB7); emit8(0x00);       // mov bh, 0
        emit8(0x88); emit8(0xC2);       // mov dl, al  (x)
        emit8(0x88); emit8(0xDE);       // mov dh, bl  (y)
        emit8(0xB4); emit8(0x02);       // mov ah, 2
        emit8(0xCD); emit8(0x10);       // int 0x10
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void bios_scroll(int lines)
    if (call->name == "bios_scroll" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0xB4); emit8(0x06);       // mov ah, 6
        emit8(0xB7); emit8(0x07);       // mov bh, 7
        emit8(0xB5); emit8(0x00);       // mov ch, 0
        emit8(0xB1); emit8(0x00);       // mov cl, 0
        emit8(0xB6); emit8(24);         // mov dh, 24
        emit8(0xB2); emit8(79);         // mov dl, 79
        emit8(0xCD); emit8(0x10);       // int 0x10
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void bios_video_mode(int mode)
    if (call->name == "bios_video_mode" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0xB4); emit8(0x00);       // mov ah, 0
        emit8(0xCD); emit8(0x10);       // int 0x10
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void bios_video_int(int value)  -> AH = value & 0xFF, then int 0x10
    if (call->name == "bios_video_int" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x8A); emit8(0xE0);       // mov ah, al
        emit8(0xCD); emit8(0x10);       // int 0x10
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Memory map ==============

    // int bios_memory_map() -> number of E820 entries written to a fixed buffer at 0x7E10
    if (call->name == "bios_memory_map" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x83); emit8(0xEC); emit8(8);       // sub esp, 8
        emit8(0xC7); emit8(0x04); emit8(0x24); emit8(0x10); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov dword [esp], 0x7E10
        emit8(0x31); emit8(0xDB);                 // xor ebx, ebx  (continuation)
        emit8(0x31); emit8(0xF6);                 // xor esi, esi  (entry count)
        emit8(0xBA); emit8(0x50); emit8(0x41); emit8(0x4D); emit8(0x53);  // mov edx, 0x534D4150 ('SMAP')
        int loop = newLabel();
        int done = newLabel();
        emitLabel(loop);
        emit8(0x8B); emit8(0x3C); emit8(0x24);    // mov edi, [esp]  (current buffer ptr)
        emit8(0xB8); emit8(0x20); emit8(0xE8); emit8(0x00); emit8(0x00);  // mov eax, 0xE820
        emit8(0xB9); emit8(24); emit8(0x00); emit8(0x00); emit8(0x00);    // mov ecx, 24
        emit8(0xCD); emit8(0x15);                 // int 0x15
        emit8(0x0F); emit8(0x82);                 // jc done  (call failed / end of list)
        jmpFixups.push_back({code.size(), done});
        emit32(0);
        emit8(0x3D); emit8(0x50); emit8(0x41); emit8(0x4D); emit8(0x53);  // cmp eax, 0x534D4150
        emitJcc("!=", done);                      // jne done
        emit8(0x46);                              // inc esi
        emit8(0x85); emit8(0xDB);                 // test ebx, ebx
        emitJcc("==", done);                      // je done
        emit8(0x81); emit8(0x04); emit8(0x24); emit8(24); emit8(0x00); emit8(0x00); emit8(0x00);  // add dword [esp], 24
        emitJmp(loop);
        emitLabel(done);
        emit8(0x89); emit8(0xF0);                 // mov eax, esi  (count)
        emit8(0x83); emit8(0xC4); emit8(8);       // add esp, 8
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Disk ==============

    // int bios_disk_read(int drive, int sector, int count, int buffer) -> 0 on success, -1 on error
    if (call->name == "bios_disk_read" && call->args.size() == 4) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r0 = emitExpr(call->args[0].get());   // drive
        if (r0 != 0) { emitMovReg(0, r0); freeReg(r0); } else freeReg(0);
        emit8(0x50);                              // push drive
        int r1 = emitExpr(call->args[1].get());   // sector (LBA)
        if (r1 != 0) { emitMovReg(0, r1); freeReg(r1); } else freeReg(0);
        emit8(0x50);                              // push sector
        int r2 = emitExpr(call->args[2].get());   // count
        if (r2 != 0) { emitMovReg(0, r2); freeReg(r2); } else freeReg(0);
        emit8(0x50);                              // push count
        int r3 = emitExpr(call->args[3].get());   // buffer
        if (r3 != 0) { emitMovReg(0, r3); freeReg(r3); } else freeReg(0);
        emit8(0x50);                              // push buffer
        emit8(0x83); emit8(0xEC); emit8(16);      // sub esp, 16  (DAP on stack)
        // After this: [esp+28]=drive, [esp+24]=sector, [esp+20]=count, [esp+16]=buffer
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x1C);  // mov eax, [esp+28]  (drive)
        emit8(0x88); emit8(0xC2);                 // mov dl, al  (drive)
        emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x00); emit8(16);  // mov byte [esp+0], 16  (DAP size)
        emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x01); emit8(0x00);  // mov byte [esp+1], 0  (reserved)
        emit8(0x66); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x14);  // mov ax, [esp+20]  (count)
        emit8(0x66); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x02);  // mov [esp+2], ax
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x10);  // mov eax, [esp+16]  (buffer)
        emit8(0x83); emit8(0xE0); emit8(0x0F);    // and eax, 0xF  (buffer offset)
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x04);  // mov [esp+4], eax
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x10);  // mov eax, [esp+16]  (buffer)
        emit8(0xC1); emit8(0xE8); emit8(4);       // shr eax, 4  (buffer segment)
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x06);  // mov [esp+6], eax
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x18);  // mov eax, [esp+24]  (sector = LBA low)
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x08);  // mov [esp+8], eax
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x0C); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);  // mov dword [esp+12], 0  (LBA high)
        emit8(0x89); emit8(0xE6);                 // mov esi, esp  (DS:SI -> DAP)
        emit8(0xB4); emit8(0x42);                 // mov ah, 0x42  (extended read)
        emit8(0xCD); emit8(0x13);                 // int 0x13
        emit8(0x0F); emit8(0x92); emit8(0xC0);    // setc al
        emit8(0x0F); emit8(0xB6); emit8(0xC0);    // movzx eax, al
        emit8(0xF7); emit8(0xD8);                 // neg eax  (0 on success, -1 on error)
        emit8(0x83); emit8(0xC4); emit8(32);      // add esp, 32
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== CPU control ==============

    if (call->name == "cli" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xFA);                    // cli
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "sti" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xFB);                    // sti
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "hlt" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xF4);                    // hlt
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "halt" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int lbl = newLabel();
        emitLabel(lbl);
        emit8(0xF4);                    // hlt
        emitJmp(lbl);                   // infinite loop
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "int" && call->args.size() == 1) {
        NumberExpr* num = dynamic_cast<NumberExpr*>(call->args[0].get());
        if (!num) return false;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xCD); emit8((uint8_t)(num->value & 0xFF));  // int imm8
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Port I/O ==============

    if (call->name == "inb" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int p = emitExpr(call->args[0].get());
        if (p != 2) { emitMovReg(2, p); freeReg(p); } else freeReg(2);
        emit8(0xEC);                    // in al, dx
        emit8(0x0F); emit8(0xB6); emit8(0xC0);  // movzx eax, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "inw" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int p = emitExpr(call->args[0].get());
        if (p != 2) { emitMovReg(2, p); freeReg(p); } else freeReg(2);
        emit8(0x66); emit8(0xED);       // in ax, dx
        emit8(0x0F); emit8(0xB7); emit8(0xC0);  // movzx eax, ax
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "ind" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int p = emitExpr(call->args[0].get());
        if (p != 2) { emitMovReg(2, p); freeReg(p); } else freeReg(2);
        emit8(0xED);                    // in eax, dx
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "outb" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rp = emitExpr(call->args[0].get());
        if (rp != 0) { emitMovReg(0, rp); freeReg(rp); } else freeReg(0);
        emit8(0x50);                    // push port
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        emit8(0x58);                    // pop eax  (value)
        emit8(0x5A);                    // pop edx  (port)
        emit8(0xEE);                    // out dx, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "outw" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rp = emitExpr(call->args[0].get());
        if (rp != 0) { emitMovReg(0, rp); freeReg(rp); } else freeReg(0);
        emit8(0x50);                    // push port
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        emit8(0x58);                    // pop eax  (value)
        emit8(0x5A);                    // pop edx  (port)
        emit8(0x66); emit8(0xEF);       // out dx, ax
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "outd" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rp = emitExpr(call->args[0].get());
        if (rp != 0) { emitMovReg(0, rp); freeReg(rp); } else freeReg(0);
        emit8(0x50);                    // push port
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        emit8(0x58);                    // pop eax  (value)
        emit8(0x5A);                    // pop edx  (port)
        emit8(0xEF);                    // out dx, eax
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Descriptor tables ==============

    if (call->name == "lidt" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x0F); emit8(0x01); emit8(0x18);  // lidt [eax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "lgdt" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x0F); emit8(0x01); emit8(0x10);  // lgdt [eax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Raw memory access ==============

    // int peek8(int addr) — zero-extended byte read
    if (call->name == "peek8" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x0F); emit8(0xB6); emit8(0x00);       // movzx eax, byte [eax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // int peek16(int addr) — zero-extended word read
    if (call->name == "peek16" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x0F); emit8(0xB7); emit8(0x00);       // movzx eax, word [eax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // int peek32(int addr)
    if (call->name == "peek32" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x8B); emit8(0x00);       // mov eax, [eax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void poke8(int addr, int value) — writes low 8 bits
    if (call->name == "poke8" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        int ra = emitExpr(call->args[0].get());
        if (ra != 0) { emitMovReg(0, ra); freeReg(ra); } else freeReg(0);
        emit8(0x5A);                    // pop edx  (value)
        emit8(0x88); emit8(0x10);       // mov [eax], dl
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void poke16(int addr, int value) — writes low 16 bits
    if (call->name == "poke16" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        int ra = emitExpr(call->args[0].get());
        if (ra != 0) { emitMovReg(0, ra); freeReg(ra); } else freeReg(0);
        emit8(0x5A);                    // pop edx  (value)
        emit8(0x66); emit8(0x89); emit8(0x10);  // mov [eax], dx
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void poke32(int addr, int value)
    if (call->name == "poke32" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rv = emitExpr(call->args[1].get());
        if (rv != 0) { emitMovReg(0, rv); freeReg(rv); } else freeReg(0);
        emit8(0x50);                    // push value
        int ra = emitExpr(call->args[0].get());
        if (ra != 0) { emitMovReg(0, ra); freeReg(ra); } else freeReg(0);
        emit8(0x5A);                    // pop edx  (value)
        emit8(0x89); emit8(0x10);       // mov [eax], edx
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== VGA text mode ==============

    // void vga_clear()
    if (call->name == "vga_clear" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi, 0xB8000
        emit8(0x66); emit8(0xB8); emit8(0x20); emit8(0x07);  // mov ax, 0x0720
        emit8(0xB9); emit8(0xD0); emit8(0x07); emit8(0x00); emit8(0x00);  // mov ecx, 2000
        emit8(0x66); emit8(0xF3); emit8(0xAB);  // rep stosw
        emit8(0xC7); emit8(0x04); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);  // mov dword [0x7E00], 0
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void vga_putc(char c, int attr)
    if (call->name == "vga_putc" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rc = emitExpr(call->args[0].get());
        if (rc != 0) { emitMovReg(0, rc); freeReg(rc); } else freeReg(0);
        emit8(0x50);                    // push char
        int ra = emitExpr(call->args[1].get());
        if (ra != 0) { emitMovReg(0, ra); freeReg(ra); } else freeReg(0);
        emit8(0x50);                    // push attr
        emit8(0x5B);                    // pop ebx  (attr)
        emit8(0x58);                    // pop eax  (char)
        emit8(0x8A); emit8(0xE3);       // mov ah, bl
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi, 0xB8000
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov ecx, [0x7E00]
        emit8(0x01); emit8(0xC9);       // add ecx, ecx
        emit8(0x01); emit8(0xCF);       // add edi, ecx
        emit8(0x66); emit8(0x89); emit8(0x07);  // mov [edi], ax
        emit8(0xFF); emit8(0x04); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // inc dword [0x7E00]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // int vga_print(char* str) -> returns 0
    if (call->name == "vga_print" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x89); emit8(0xC6);       // mov esi, eax  (str)
        emit8(0xBF); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // mov edi, 0xB8000
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov ecx, [0x7E00]
        emit8(0x01); emit8(0xC9);       // add ecx, ecx
        emit8(0x01); emit8(0xCF);       // add edi, ecx
        int loop = newLabel();
        int done = newLabel();
        emitLabel(loop);
        emit8(0x0F); emit8(0xB6); emit8(0x06);  // movzx eax, byte [esi]
        emit8(0x85); emit8(0xC0);       // test eax, eax
        emitJcc("==", done);            // jz done
        emit8(0xB4); emit8(0x07);       // mov ah, 7
        emit8(0x66); emit8(0x89); emit8(0x07);  // mov [edi], ax
        emit8(0x46);                    // inc esi
        emit8(0x83); emit8(0xC7); emit8(2);  // add edi, 2
        emitJmp(loop);
        emitLabel(done);
        emit8(0x89); emit8(0xF8);       // mov eax, edi
        emit8(0x2D); emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);  // sub eax, 0xB8000
        emit8(0xD1); emit8(0xE8);       // shr eax, 1
        emit8(0xA3); emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);  // mov [0x7E00], eax
        emit8(0xB8); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);  // mov eax, 0
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Framebuffer ==============

    // void fb_clear(int color)
    if (call->name == "fb_clear" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int r = emitExpr(call->args[0].get());
        if (r != 0) { emitMovReg(0, r); freeReg(r); } else freeReg(0);
        emit8(0x8B); emit8(0x3C); emit8(0x25); emit8(0x00); emit8(0x80); emit8(0x00); emit8(0x00);  // mov edi, [0x8000]  (addr)
        emit8(0x8B); emit8(0x0C); emit8(0x25); emit8(0x0C); emit8(0x80); emit8(0x00); emit8(0x00);  // mov ecx, [0x800C]  (width)
        emit8(0x0F); emit8(0xAF); emit8(0x0C); emit8(0x25); emit8(0x10); emit8(0x80); emit8(0x00); emit8(0x00);  // imul ecx, [0x8010]  (height)
        emit8(0xF3); emit8(0xAB);       // rep stosd
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // void fb_pixel(int x, int y, int color)
    if (call->name == "fb_pixel" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int rx = emitExpr(call->args[0].get());
        if (rx != 0) { emitMovReg(0, rx); freeReg(rx); } else freeReg(0);
        emit8(0x50);                    // push x
        int ry = emitExpr(call->args[1].get());
        if (ry != 0) { emitMovReg(0, ry); freeReg(ry); } else freeReg(0);
        emit8(0x50);                    // push y
        int rc = emitExpr(call->args[2].get());
        if (rc != 0) { emitMovReg(0, rc); freeReg(rc); } else freeReg(0);
        emit8(0x5A);                    // pop edx  (y)
        emit8(0x5B);                    // pop ebx  (x)
        emit8(0x8B); emit8(0x3C); emit8(0x25); emit8(0x00); emit8(0x80); emit8(0x00); emit8(0x00);  // mov edi, [0x8000]  (addr)
        emit8(0x8B); emit8(0x34); emit8(0x25); emit8(0x08); emit8(0x80); emit8(0x00); emit8(0x00);  // mov esi, [0x8008]  (pitch)
        emit8(0x0F); emit8(0xAF); emit8(0xF2);  // imul esi, edx
        emit8(0x01); emit8(0xF7);       // add edi, esi
        emit8(0x8D); emit8(0x3C); emit8(0x9F);  // lea edi, [edi+ebx*4]
        emit8(0x89); emit8(0x07);       // mov [edi], eax  (color)
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // int fb_width() / fb_height() / fb_pitch() / fb_bpp() / int fb_addr()
    auto fbFieldLoad = [&](const char* name, uint32_t addr) -> bool {
        if (call->name != name || !call->args.empty()) return false;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x8B); emit8(0x04); emit8(0x25);
        emit32(addr);                   // mov eax, [addr]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    };
    if (fbFieldLoad("fb_width", 0x800C)) return true;
    if (fbFieldLoad("fb_height", 0x8010)) return true;
    if (fbFieldLoad("fb_pitch", 0x8008)) return true;
    if (fbFieldLoad("fb_bpp", 0x8014)) return true;
    if (fbFieldLoad("fb_addr", 0x8000)) return true;

    return false;
}
