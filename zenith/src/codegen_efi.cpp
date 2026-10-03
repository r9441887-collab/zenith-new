// codegen_efi.cpp — EFI and Bare-metal built-in functions
// Handles: cli, sti, hlt, int(n), inb, inw, ind, outb, outw, outd
// halt, lidt, lgdt (bare/efi)
// vga_clear, vga_putc, vga_print (bare/BIOS only)
// gop_clear, gop_pixel, gop_rect, gop_char, gop_init (UEFI GOP)
// fb_width, fb_height, fb_pitch, fb_addr (framebuffer info)
// peek, poke (memory access)

#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include <iostream>
#include <vector>

using namespace std;
// =====================================================================
// Framebuffer info source for gop_*/fb_* builtins.
// EFI apps: RIP-relative read from win32Globals+24..+48 (populated from the
//           EFI_GRAPHICS_OUTPUT_PROTOCOL at the entry point).
// Bare apps: absolute read from the fixed loader addresses 0x8000..0x8018.
// `field` uses the fixed-address offsets (0=addr, 8=pitch, 12=width, 16=height,
// 20=bpp, 24=pixel format).
// =====================================================================

void Codegen::emitLoadFbInfo64(int r, int field) {
    if (prog.appType == AppType::EFI) {
        uint8_t rex = (r >= 8) ? 0x4C : 0x48;   // REX.W + REX.R for r8-r15
        emit8(rex); emit8(0x8B);
        emit8(0x05 | ((r & 7) << 3));           // mov r64, [rip + disp32]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 24 + (uint32_t)field});
        emit32(0);
    } else {
        uint8_t rex = (r >= 8) ? 0x4C : 0x48;
        emit8(rex); emit8(0x8B);
        emit8(0x04 | ((r & 7) << 3));           // mov r64, [disp32]
        emit8(0x25);
        emit32(0x8000 + (uint32_t)field);
    }
}

void Codegen::emitLoadFbInfo32(int r, int field) {
    if (prog.appType == AppType::EFI) {
        if (r >= 8) emit8(0x44);                // REX.R (no W) for r8-r15
        emit8(0x8B);
        emit8(0x05 | ((r & 7) << 3));           // mov r32, [rip + disp32]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 24 + (uint32_t)field});
        emit32(0);
    } else {
        if (r >= 8) emit8(0x44);
        emit8(0x8B);
        emit8(0x04 | ((r & 7) << 3));           // mov r32, [disp32]
        emit8(0x25);
        emit32(0x8000 + (uint32_t)field);
    }
}

void Codegen::emitImulFbInfo32(int r, int field) {
    if (prog.appType == AppType::EFI) {
        if (r >= 8) emit8(0x44);                // REX.R (no W) for r8-r15
        emit8(0x0F); emit8(0xAF);
        emit8(0x05 | ((r & 7) << 3));           // imul r32, [rip + disp32]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 24 + (uint32_t)field});
        emit32(0);
    } else {
        if (r >= 8) emit8(0x44);
        emit8(0x0F); emit8(0xAF);
        emit8(0x04 | ((r & 7) << 3));           // imul r32, [disp32]
        emit8(0x25);
        emit32(0x8000 + (uint32_t)field);
    }
}

// Swap the red/blue bytes of the color registers when the display is RGBX
// (PixelFormat 0): 0x00RRGGBB -> 0x00BBGGRR (bswap + ror 8; a plain bswap
// would also rotate the 0x00 high byte into the X lane). All gop_* drawing
// builtins keep their colors constant across the inner loops, so one
// conditional swap per color before the loops is enough.
// Clobbers: scratch (loaded with the cached PixelFormat), flags.
void Codegen::emitSwapColorsIfRgbx(int scratch, const std::vector<int>& colorRegs) {
    if (prog.appType != AppType::EFI && prog.appType != AppType::Bare) return;
    emitLoadFbInfo32(scratch, 24);              // PixelFormat lives at +24+24=+48
    if (scratch >= 8) emit8(0x45);              // REX.R|REX.B only for r8-r15
    emit8(0x85);                                // test scratch32, scratch32
    emit8(0xC0 | ((scratch & 7) << 3) | (scratch & 7));
    int skipLbl = newLabel();
    emitJcc("!=", skipLbl);                     // fmt != 0 -> already BGRX
    for (int cr : colorRegs) {
        bool hi = cr >= 8;
        if (hi) emit8(0x41);
        emit8(0x0F); emit8((uint8_t)(0xC8 + (cr & 7)));           // bswap r32
        if (hi) emit8(0x41);
        emit8(0xC1); emit8((uint8_t)(0xC8 + (cr & 7))); emit8(0x08); // ror r32, 8
    }
    emitLabel(skipLbl);
}

bool Codegen::tryEFICall(CallExpr* call, int& resultReg) {
    // VGA text-buffer builtins poke absolute VA 0xB8000 / cursor at 0x7E00.
    // Under UEFI long mode those pages are unmapped -> instant triple fault
    // that looks like a random black screen on real hardware. Reject them for
    // 'app efi' at compile time (Bare kernels keep them).
    if (prog.appType == AppType::EFI && call->name.rfind("vga_", 0) == 0) {
        return false;
    }

    // ======================== cli() ========================
    if (call->name == "cli" && call->args.size() == 0) {
        emit8(0xFA); // cli
        emitMovRegImm(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // ======================== sti() ========================
    if (call->name == "sti" && call->args.size() == 0) {
        emit8(0xFB); // sti
        emitMovRegImm(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // ======================== hlt() ========================
    if (call->name == "hlt" && call->args.size() == 0) {
        emit8(0xF4); // hlt
        emitMovRegImm(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // ======================== int(n) / interrupt(n) ========================
    if ((call->name == "int" || call->name == "interrupt") && call->args.size() == 1) {
        if (auto num = dynamic_cast<NumberExpr*>(call->args[0].get())) {
            emit8(0xCD); // INT imm8
            emit8((uint8_t)(num->value & 0xFF));
        }
        emitMovRegImm(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // ======================== inw(port) ========================
    if (call->name == "inw" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
        else freeReg(2);
        emit8(0x66); emit8(0xED); // in ax, dx
        emit8(0x0F); emit8(0xB7); emit8(0xC0); // movzx eax, ax
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ======================== ind(port) ========================
    if (call->name == "ind" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
        else freeReg(2);
        emit8(0xED); // in eax, dx
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ======================== outw(port, val) ========================
    if (call->name == "outw" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int valReg = emitExpr(call->args[1].get());
        if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (val)
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
        else freeReg(2);
        emit8(0x58);  // pop rax
        emit8(0x66); emit8(0xEF); // out dx, ax
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ======================== outd(port, val) ========================
    if (call->name == "outd" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int valReg = emitExpr(call->args[1].get());
        if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (val)
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
        else freeReg(2);
        emit8(0x58);  // pop rax
        emit8(0xEF); // out dx, eax
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ======================== lidt(ptr) ========================
    if (call->name == "lidt" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int ptrReg = emitExpr(call->args[0].get());
        if (ptrReg != 0) { emitMovReg(0, ptrReg); freeReg(ptrReg); }
        else freeReg(0);
        emit8(0x0F); emit8(0x01); emit8(0x18); // lidt [rax]
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ======================== lgdt(ptr) ========================
    if (call->name == "lgdt" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int ptrReg = emitExpr(call->args[0].get());
        if (ptrReg != 0) { emitMovReg(0, ptrReg); freeReg(ptrReg); }
        else freeReg(0);
        emit8(0x0F); emit8(0x01); emit8(0x10); // lgdt [rax]
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // VGA Functions (Bare/BIOS mode - direct VGA text mode 0xB8000)
    // =====================================================================

    // vga_clear() — fill VGA text buffer with spaces
    if (call->name == "vga_clear" && call->args.size() == 0) {
        // rdi = 0xB8000
        emit8(0x48); emit8(0xBF);
        emit8(0x00); emit8(0x80); emit8(0x0B);
        emit8(0x00); emit8(0x00); emit8(0x00);
        emit8(0x00); emit8(0x00); // 8-byte imm64 for movabs rdi
        // ax = 0x0720 (space + light gray attr)
        emit8(0x66); emit8(0xB8);
        emit8(0x20); emit8(0x07);
        // rcx = 2000 (80*25)
        emit8(0x48); emit8(0xC7); emit8(0xC1);
        emit8(0xD0); emit8(0x07); emit8(0x00); emit8(0x00);
        // rep stosw
        emit8(0x66); emit8(0xF3); emit8(0xAB);
        // Reset cursor at 0x7E00
        emit8(0x48); emit8(0xC7); emit8(0x04); emit8(0x25);
        emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);
        emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);
        emitMovRegImm(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // vga_putc(char, attr) — write char at cursor
    if (call->name == "vga_putc" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int charReg = emitExpr(call->args[0].get());
        if (charReg != 0) { emitMovReg(0, charReg); freeReg(charReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (char)
        int attrReg = emitExpr(call->args[1].get());
        if (attrReg != 0) { emitMovReg(0, attrReg); freeReg(attrReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (attr)
        emit8(0x5B);  // pop rbx (attr)
        emit8(0x58);  // pop rax (char)
        emit8(0x8A); emit8(0xE3); // mov ah, bl -> AL=char, AH=attr
        // rdi = 0xB8000
        emit8(0x48); emit8(0xBF);
        emit8(0x00); emit8(0x80); emit8(0x0B);
        emit8(0x00); emit8(0x00); emit8(0x00);
        emit8(0x00); emit8(0x00); // 8-byte imm64 for movabs rdi
        // rcx = cursor position at 0x7E00
        emit8(0x48); emit8(0x8B); emit8(0x0C); emit8(0x25);
        emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);
        // rdi += rcx * 2
        emit8(0x48); emit8(0x01); emit8(0xC9);
        emit8(0x48); emit8(0x01); emit8(0xCF);
        // mov [rdi], ax
        emit8(0x66); emit8(0x89); emit8(0x07);
        // Increment cursor
        emit8(0x48); emit8(0xFF); emit8(0x04); emit8(0x25);
        emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // vga_print(ptr) — print null-terminated string
    if (call->name == "vga_print" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int ptrReg = emitExpr(call->args[0].get());
        if (ptrReg != 0) { emitMovReg(0, ptrReg); freeReg(ptrReg); }
        else freeReg(0);
        emit8(0x48); emit8(0x89); emit8(0xC6); // mov rsi, rax (string pointer)
        // rdi = 0xB8000 + cursor*2
        emit8(0x48); emit8(0xBF);
        emit8(0x00); emit8(0x80); emit8(0x0B);
        emit8(0x00); emit8(0x00); emit8(0x00);
        emit8(0x00); emit8(0x00); // 8-byte imm64 for movabs rdi
        emit8(0x48); emit8(0x8B); emit8(0x0C); emit8(0x25);
        emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);
        emit8(0x48); emit8(0x01); emit8(0xCF);
        emit8(0x48); emit8(0x01); emit8(0xCF);
        
        int loopStart = newLabel();
        int loopEnd = newLabel();
        
        emitLabel(loopStart);
        // movzx eax, byte [rsi]
        emit8(0x0F); emit8(0xB6); emit8(0x06);
        // test eax, eax
        emit8(0x85); emit8(0xC0);
        emitJcc("e", loopEnd);
        // mov ah, 0x07 (attr)
        emit8(0xB4); emit8(0x07);
        // mov [rdi], ax
        emit8(0x66); emit8(0x89); emit8(0x07);
        // rsi++
        emit8(0x48); emit8(0xFF); emit8(0xC6);
        // rdi += 2
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x02);
        emitJmp(loopStart);
        
        emitLabel(loopEnd);
        // Update cursor
        emit8(0x48); emit8(0x89); emit8(0xF8); // mov rax, rdi
        emit8(0x48); emit8(0x2D);
        emit8(0x00); emit8(0x80); emit8(0x0B); emit8(0x00);
        emit8(0x48); emit8(0xD1); emit8(0xE8); // shr rax, 1
        emit8(0x48); emit8(0xA3);
        emit8(0x00); emit8(0x7E); emit8(0x00); emit8(0x00);
        emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x00);

        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // GOP Functions (UEFI Graphics Output Protocol mode)
    // Framebuffer info at fixed addresses:
    //   0x8000 = Framebuffer Address (64-bit)
    //   0x8008 = Pitch (bytes per scanline)
    //   0x800C = Width
    //   0x8010 = Height
    //   0x8014 = BPP
    //   0x8018 = Pixel Format
    // =====================================================================

    // gop_init() — check if GOP is available, returns 1 if available
    if (call->name == "gop_init" && call->args.size() == 0) {
        emitLoadFbInfo64(0, 0); // rax = framebuffer address
        emit8(0x48); emit8(0x85); emit8(0xC0); // test rax, rax
        emit8(0x0F); emit8(0x95); emit8(0xC0); // setnz al
        emit8(0x48); emit8(0x0F); emit8(0xB6); emit8(0xC0); // movzx rax, al
        regsUsed = 1; // mark RAX busy so emitBinaryExpr doesn't reuse it for tempReg
        resultReg = 0;
        return true;
    }

    // gop_clear(color) — fill the whole screen with color (0x00RRGGBB)
    if (call->name == "gop_clear" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int colorReg = emitExpr(call->args[0].get());
        if (colorReg != 0) { emitMovReg(0, colorReg); freeReg(colorReg); }
        else freeReg(0);
        // RGBX displays need R/B swapped once for the whole fill.
        emitSwapColorsIfRgbx(2, {0});           // scratch edx
        // rax = color; rdi = framebuffer; ecx = width*height; rep stosd
        emitLoadFbInfo64(7, 0);  // rdi = framebuffer
        emitLoadFbInfo32(1, 12); // ecx = width
        emitImulFbInfo32(1, 16); // ecx *= height
        emit8(0xF3); emit8(0xAB);                             // rep stosd
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // gop_pixel(x, y, color) — draw a single pixel
    if (call->name == "gop_pixel" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int xReg = emitExpr(call->args[0].get());
        if (xReg != 0) { emitMovReg(0, xReg); freeReg(xReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (x)
        int yReg = emitExpr(call->args[1].get());
        if (yReg != 0) { emitMovReg(0, yReg); freeReg(yReg); }
        else freeReg(0);
        emit8(0x50);  // push rax (y)
        int cReg = emitExpr(call->args[2].get());
        if (cReg != 0) { emitMovReg(0, cReg); freeReg(cReg); }
        else freeReg(0);
        // rax = color; stack: [rsp]=color, [rsp+8]=y, [rsp+16]=x
        emit8(0x50);               // push rax (color)
        emit8(0x41); emit8(0x5A);  // pop r10 (color, discard)
        emit8(0x41); emit8(0x58);  // pop r8 (y)
        emit8(0x41); emit8(0x59);  // pop r9 (x)
        emitSwapColorsIfRgbx(2, {0});           // scratch edx (dead here)
        // rdi = framebuffer + y*pitch + x*4
        emitLoadFbInfo64(7, 0);  // rdi = framebuffer
        emitLoadFbInfo32(6, 8);  // rsi = pitch (u32, zero-extends to r64)
        emit8(0x49); emit8(0x0F); emit8(0xAF); emit8(0xF0);   // imul rsi, r8 (pitch*y)
        emit8(0x48); emit8(0x01); emit8(0xF7);               // add rdi, rsi
        emit8(0x4A); emit8(0x8D); emit8(0x3C); emit8(0x8F);   // lea rdi, [rdi + r9*4]
        emit8(0x89); emit8(0x07);                             // mov [rdi], eax
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // gop_rect(x, y, w, h, color) — draw filled rectangle
    if (call->name == "gop_rect" && call->args.size() == 5) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        for (int i = 0; i < 4; i++) {
            int a = emitExpr(call->args[i].get());
            if (a != 0) { emitMovReg(0, a); freeReg(a); }
            else freeReg(0);
            emit8(0x50);  // push x/y/w/h
        }
        int colorReg = emitExpr(call->args[4].get());
        if (colorReg != 0) { emitMovReg(0, colorReg); freeReg(colorReg); }
        else freeReg(0);
        // rax = color; stack: [rsp]=h, [rsp+8]=w, [rsp+16]=y, [rsp+24]=x
        emit8(0x5A);               // pop rdx (h)
        emit8(0x59);               // pop rcx (w)
        emit8(0x41); emit8(0x58);  // pop r8 (y)
        emit8(0x41); emit8(0x59);  // pop r9 (x)
        emitSwapColorsIfRgbx(11, {0});          // scratch r11 (free until loops)
        // rbx = framebuffer
        emitLoadFbInfo64(3, 0);  // rbx = framebuffer
        // rsi = pitch (kept intact for per-row stepping below)
        emitLoadFbInfo32(6, 8);  // rsi = pitch (u32, zero-extends to r64)
        // rdi = y*pitch + framebuffer + x*4 (rdi must not be reused from a
        // previous call, and rsi must stay == pitch for the row loop)
        emit8(0x4C); emit8(0x89); emit8(0xC7);               // mov rdi, r8 (y)
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xFE);   // imul rdi, rsi (y*pitch)
        emit8(0x48); emit8(0x01); emit8(0xDF);               // add rdi, rbx (framebuffer)
        emit8(0x4A); emit8(0x8D); emit8(0x3C); emit8(0x8F);   // lea rdi, [rdi + r9*4]
        // r9 = row counter (0)
        emit8(0x45); emit8(0x31); emit8(0xC9);               // xor r9d, r9d
        int rowLbl = newLabel();
        int rowEndLbl = newLabel();
        emitLabel(rowLbl);
        emit8(0x4C); emit8(0x39); emit8(0xCA);               // cmp r9, rdx (h)
        emitJcc("e", rowEndLbl);
        // r8 = col counter (0)
        emit8(0x45); emit8(0x31); emit8(0xC0);               // xor r8d, r8d
        int colLbl = newLabel();
        int colEndLbl = newLabel();
        emitLabel(colLbl);
        emit8(0x4C); emit8(0x39); emit8(0xC1);               // cmp r8, rcx (w)
        emitJcc("e", colEndLbl);
        emit8(0x42); emit8(0x89); emit8(0x04); emit8(0x87);   // mov [rdi + r8*4], eax
        emit8(0x49); emit8(0xFF); emit8(0xC0);               // inc r8
        emitJmp(colLbl);
        emitLabel(colEndLbl);
        emit8(0x48); emit8(0x01); emit8(0xF7);               // add rdi, rsi (next row)
        emit8(0x49); emit8(0xFF); emit8(0xC1);               // inc r9
        emitJmp(rowLbl);
        emitLabel(rowEndLbl);
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // gop_char(x, y, ch, fg, bg) — draw a single 8x16 glyph (ASCII 32..126
    // from the embedded font, like gop_print) at (x, y). Non-printable chars
    // render as a space.
    if (call->name == "gop_char" && call->args.size() == 5) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        for (int i = 0; i < 4; i++) {
            int a = emitExpr(call->args[i].get());
            if (a != 0) { emitMovReg(0, a); freeReg(a); }
            else freeReg(0);
            emit8(0x50);  // push x/y/ch/fg
        }
        int bgReg = emitExpr(call->args[4].get());
        if (bgReg != 0) { emitMovReg(0, bgReg); freeReg(bgReg); }
        else freeReg(0);
        // rax = bg; stack: [rsp]=fg, [rsp+8]=ch, [rsp+16]=y, [rsp+24]=x
        emit8(0x41); emit8(0x58);               // pop r8 (fg)
        emit8(0x41); emit8(0x59);               // pop r9 (ch)
        emit8(0x41); emit8(0x5A);               // pop r10 (y)
        emit8(0x41); emit8(0x5B);               // pop r11 (x)
        emit8(0x49); emit8(0x89); emit8(0xC6);  // mov r14, rax (bg, survives the loop)
        emitSwapColorsIfRgbx(2, {14, 8});       // scratch edx; swap bg + fg
        // Glyph index = ch - 32 for printable ASCII, else 0 (space).
        emit8(0x44); emit8(0x89); emit8(0xC8);  // mov eax, r9d (ch)
        int blankIdx = newLabel();
        int haveIdx = newLabel();
        emit8(0x83); emit8(0xF8); emit8(0x20);  // cmp eax, 0x20
        emitJcc("<", blankIdx);
        emit8(0x83); emit8(0xF8); emit8(0x7E);  // cmp eax, 0x7E
        emitJcc(">", blankIdx);
        emit8(0x83); emit8(0xE8); emit8(0x20);  // sub eax, 0x20
        emitJmp(haveIdx);
        emitLabel(blankIdx);
        emit8(0x31); emit8(0xC0);               // xor eax, eax
        emitLabel(haveIdx);
        emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x04); // shl rax, 4 (glyph = idx*16)
        // r12 = font base (RIP-relative, same as emitGopGlyphLoop)
        emit8(0x4C); emit8(0x8D); emit8(0x25);  // lea r12, [rip + disp32]
        heapFixups.push_back({code.size(), fontCyrRVA});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xE2);  // mov rdx, r12
        emit8(0x48); emit8(0x01); emit8(0xC2);  // add rdx, rax (rdx = glyph ptr)
        // rbx = framebuffer, r13 = pitch (kept for per-row stepping below)
        emitLoadFbInfo64(3, 0);                 // rbx = framebuffer
        emitLoadFbInfo32(13, 8);                // r13d = pitch
        // rdi = y*pitch + framebuffer + x*4
        emit8(0x4C); emit8(0x89); emit8(0xD0);  // mov rax, r10 (y)
        emit8(0x49); emit8(0x0F); emit8(0xAF); emit8(0xC5); // imul rax, r13 (y*pitch)
        emit8(0x48); emit8(0x01); emit8(0xD8);  // add rax, rbx (+fb)
        emit8(0x4A); emit8(0x8D); emit8(0x04); emit8(0x98); // lea rax, [rax + r11*4] (+x*4)
        emit8(0x48); emit8(0x89); emit8(0xC7);  // mov rdi, rax
        // row loop 0..15 (r10 = row, r15 = col)
        emit8(0x45); emit8(0x31); emit8(0xD2);  // xor r10d, r10d
        int rowLbl = newLabel();
        int rowEndLbl = newLabel();
        emitLabel(rowLbl);
        emit8(0x49); emit8(0x83); emit8(0xFA); emit8(0x10); // cmp r10, 16
        emitJcc(">=", rowEndLbl);
        emit8(0x0F); emit8(0xB6); emit8(0x02);  // movzx eax, byte [rdx] (row byte)
        emit8(0x45); emit8(0x31); emit8(0xFF);  // xor r15d, r15d (col counter)
        int colLbl = newLabel();
        int colEndLbl = newLabel();
        int colSet = newLabel();
        int colNext = newLabel();
        emitLabel(colLbl);
        emit8(0x49); emit8(0x83); emit8(0xFF); emit8(0x08); // cmp r15, 8
        emitJcc(">=", colEndLbl);
        emit8(0xD0); emit8(0xE0);               // shl al, 1
        emit8(0x0F); emit8(0x82);               // jc (bit set -> fg) — emitJcc("<") would emit jl
        jmpFixups.push_back({code.size(), colSet});
        emit32(0);
        emit8(0x46); emit8(0x89); emit8(0x34); emit8(0xBF); // mov [rdi + r15*4], r14d (bg)
        emitJmp(colNext);
        emitLabel(colSet);
        emit8(0x46); emit8(0x89); emit8(0x04); emit8(0xBF); // mov [rdi + r15*4], r8d (fg)
        emitLabel(colNext);
        emit8(0x41); emit8(0xFF); emit8(0xC7);  // inc r15d
        emitJmp(colLbl);
        emitLabel(colEndLbl);
        emit8(0x4C); emit8(0x01); emit8(0xEF);  // add rdi, r13 (next row)
        emit8(0x48); emit8(0xFF); emit8(0xC2);  // inc rdx
        emit8(0x41); emit8(0xFF); emit8(0xC2);  // inc r10d
        emitJmp(rowLbl);
        emitLabel(rowEndLbl);
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // gop_print(x, y, str, fg, bg) — draw UTF-8 string with the embedded 8x16
    // Cyrillic font directly into the framebuffer.
    // Glyph table (font8x16_cyr.h): idx 0..94 = ASCII 32..126, idx 95 unused,
    // 96..127 = А..Я, 128..159 = а..п, 144..159 = р..я (D1 80..D1 8F), 160 = Ё, 161 = ё.
    // UTF-8 decode: D0 [81,90..AF,B0..BF] and D1 [80..8F,91]; anything else is skipped.
    if (call->name == "gop_print" && call->args.size() == 5) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        for (int i = 0; i < 4; i++) {
            int a = emitExpr(call->args[i].get());
            if (a != 0) { emitMovReg(0, a); freeReg(a); }
            else freeReg(0);
            emit8(0x50);  // push x/y/str/fg
        }
        int bgReg = emitExpr(call->args[4].get());
        if (bgReg != 0) { emitMovReg(0, bgReg); freeReg(bgReg); }
        else freeReg(0);
        // rax = bg; stack: [rsp]=fg, [rsp+8]=str, [rsp+16]=y, [rsp+24]=x
        // r8 = fg, rsi = str, r13 = y, rcx = x cursor, r9 = bg
        emit8(0x41); emit8(0x58);               // pop r8 (fg)
        emit8(0x5E);                            // pop rsi (str)
        emit8(0x41); emit8(0x5D);               // pop r13 (y)
        emit8(0x59);                            // pop rcx (x)
        emit8(0x49); emit8(0x89); emit8(0xC1);  // mov r9, rax (bg)
        emitGopGlyphLoop();
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // gop_print_hex(x, y, val, fg, bg) — print a 64-bit value as 16 hex digits.
    // Builds the hex string into a 24-byte stack buffer (16 chars + null + pad),
    // then reuses the same glyph-drawing loop as gop_print.
    if (call->name == "gop_print_hex" && call->args.size() == 5) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(24);  // sub rsp, 24
        int vReg = emitExpr(call->args[2].get());
        if (vReg != 0) { emitMovReg(0, vReg); freeReg(vReg); }
        else freeReg(0);
        emit8(0x48); emit8(0x89); emit8(0xE7);             // mov rdi, rsp (buffer)
        // rax = val; convert 16 nibbles (high first) into [rdi]
        for (int shift = 60; shift >= 0; shift -= 4) {
            emit8(0x48); emit8(0x89); emit8(0xC2);         // mov rdx, rax
            if (shift > 0) { emit8(0x48); emit8(0xC1); emit8(0xEA); emit8(shift); } // shr rdx, shift
            emit8(0x83); emit8(0xE2); emit8(0x0F);         // and edx, 0xF
            int isDigit = newLabel();
            int convDone = newLabel();
            emit8(0x83); emit8(0xFA); emit8(0x0A);         // cmp edx, 10
            emitJcc("<", isDigit);
            emit8(0x83); emit8(0xC2); emit8(0x37);         // add edx, 'A'-10
            emitJmp(convDone);
            emitLabel(isDigit);
            emit8(0x83); emit8(0xC2); emit8(0x30);         // add edx, '0'
            emitLabel(convDone);
            emit8(0x88); emit8(0x17);                      // mov [rdi], dl
            emit8(0x48); emit8(0xFF); emit8(0xC7);         // inc rdi
        }
        emit8(0xC6); emit8(0x07); emit8(0x00);             // mov byte [rdi], 0
        // push x, y, str, fg; bg in rax (mirror gop_print register setup)
        int xReg = emitExpr(call->args[0].get());
        if (xReg != 0) { emitMovReg(0, xReg); freeReg(xReg); }
        else freeReg(0);
        emit8(0x50);                                        // push x
        int yReg = emitExpr(call->args[1].get());
        if (yReg != 0) { emitMovReg(0, yReg); freeReg(yReg); }
        else freeReg(0);
        emit8(0x50);                                        // push y
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(16); // lea rax, [rsp+16] (buffer)
        emit8(0x50);                                        // push str
        int fReg = emitExpr(call->args[3].get());
        if (fReg != 0) { emitMovReg(0, fReg); freeReg(fReg); }
        else freeReg(0);
        emit8(0x50);                                        // push fg
        int bReg = emitExpr(call->args[4].get());
        if (bReg != 0) { emitMovReg(0, bReg); freeReg(bReg); }
        else freeReg(0);
        emit8(0x41); emit8(0x58);               // pop r8 (fg)
        emit8(0x5E);                            // pop rsi (str)
        emit8(0x41); emit8(0x5D);               // pop r13 (y)
        emit8(0x59);                            // pop rcx (x)
        emit8(0x49); emit8(0x89); emit8(0xC1);  // mov r9, rax (bg)
        emitGopGlyphLoop();
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(24);  // add rsp, 24
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // Framebuffer Info Functions
    // =====================================================================

    // fb_addr() — get framebuffer address
    if (call->name == "fb_addr" && call->args.size() == 0) {
        emitLoadFbInfo64(0, 0);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // fb_width() — get framebuffer width
    if (call->name == "fb_width" && call->args.size() == 0) {
        emitLoadFbInfo32(0, 12);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // fb_height() — get framebuffer height
    if (call->name == "fb_height" && call->args.size() == 0) {
        emitLoadFbInfo32(0, 16);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // fb_pitch() — get framebuffer pitch
    if (call->name == "fb_pitch" && call->args.size() == 0) {
        emitLoadFbInfo32(0, 8);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // fb_bpp() — get bits per pixel
    if (call->name == "fb_bpp" && call->args.size() == 0) {
        emitLoadFbInfo32(0, 20);
        regsUsed |= 1;
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // Memory Access Functions
    // =====================================================================

    // peek8(addr) — read byte
    if (call->name == "peek8" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int addrReg = emitExpr(call->args[0].get());
        if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
        else freeReg(0);
        emit8(0x0F); emit8(0xB6); emit8(0x00); // movzx eax, byte [rax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // peek16(addr) — read word
    if (call->name == "peek16" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int addrReg = emitExpr(call->args[0].get());
        if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
        else freeReg(0);
        emit8(0x0F); emit8(0xB7); emit8(0x00); // movzx eax, word [rax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // peek32(addr) — read 32-bit value
    if (call->name == "peek32" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int addrReg = emitExpr(call->args[0].get());
        if (addrReg != 0) { emitMovReg(0, addrReg); freeReg(addrReg); }
        else freeReg(0);
        emit8(0x8B); emit8(0x00); // mov eax, [rax]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // poke8(addr, val) — write byte
    if (call->name == "poke8" && call->args.size() == 2) {
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
        emit8(0x88); emit8(0x10); // mov [rax], dl
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // poke16(addr, val) — write word
    if (call->name == "poke16" && call->args.size() == 2) {
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
        emit8(0x66); emit8(0x89); emit8(0x10); // mov [rax], dx
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // poke32(addr, val) — write 32-bit value
    if (call->name == "poke32" && call->args.size() == 2) {
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
        emit8(0x89); emit8(0x10); // mov [rax], edx
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // Not recognized
    return false;
}

// =====================================================================
// Shared glyph-drawing loop for gop_print() and gop_print_hex().
//
// Expects on entry:
//   r8  = fg pixel
//   rsi = pointer to null-terminated string
//   r13 = y (top row of text)
//   rcx = x (left pixel column)
//   r9  = bg pixel
// Loads framebuffer/pitch/font itself, draws each char (8x16), and stops
// at the null terminator. Clobbers eax/rdx/rdi/r10/r11/r15 (volatile).
void Codegen::emitGopGlyphLoop() {
    emitSwapColorsIfRgbx(7, {8, 9});        // scratch edi; swap fg (r8) + bg (r9)
    emitLoadFbInfo64(3, 0);                 // rbx = framebuffer
    emitLoadFbInfo32(12, 8);                // r12d = pitch
    emit8(0x4C); emit8(0x8D); emit8(0x15);  // lea r10, [rip + disp32]
    heapFixups.push_back({code.size(), fontCyrRVA});
    emit32(0);

    int charLoop = newLabel();
    int doneLbl = newLabel();
    int isD0 = newLabel();
    int isD1 = newLabel();
    int unkPath = newLabel();
    int asciiPath = newLabel();
    int d0E = newLabel();
    int d0Lower = newLabel();
    int twoCommon = newLabel();
    int d1E = newLabel();
    int unk2 = newLabel();
    int skipChar = newLabel();
    int drawPath = newLabel();
    int rowLoop = newLabel();
    int colLoop = newLabel();
    int colSet = newLabel();
    int colNext = newLabel();
    int colEnd = newLabel();
    int advanceX = newLabel();

    // ---- char loop: load byte, decode to glyph index ----
    emitLabel(charLoop);
    emit8(0x0F); emit8(0xB6); emit8(0x06);              // movzx eax, byte [rsi]
    emit8(0x85); emit8(0xC0);                           // test eax, eax
    emitJcc("==", doneLbl);
    emit8(0x3C); emit8(0xD0);                           // cmp al, 0xD0
    emitJcc("==", isD0);
    emit8(0x3C); emit8(0xD1);                           // cmp al, 0xD1
    emitJcc("==", isD1);
    emit8(0x3C); emit8(0x20);                           // cmp al, 0x20
    emitJcc("<", unkPath);
    emit8(0x3C); emit8(0x7E);                           // cmp al, 0x7E
    emitJcc("<=", asciiPath);
    emitJmp(unkPath);
    emitLabel(asciiPath);
    emit8(0x83); emit8(0xE8); emit8(0x20);              // sub eax, 32
    emit8(0x48); emit8(0xFF); emit8(0xC6);              // inc rsi
    emitJmp(drawPath);

    emitLabel(isD0);
    emit8(0x0F); emit8(0xB6); emit8(0x56); emit8(0x01); // movzx edx, byte [rsi+1]
    emit8(0x81); emit8(0xFA); emit32(0x81);             // cmp edx, 0x81
    emitJcc("==", d0E);
    emit8(0x81); emit8(0xFA); emit32(0x90);             // cmp edx, 0x90
    emitJcc("<", unk2);
    emit8(0x81); emit8(0xFA); emit32(0xB0);             // cmp edx, 0xB0
    emitJcc(">=", d0Lower);
    emit8(0x81); emit8(0xEA); emit32(0x90);             // sub edx, 0x90
    emit8(0x83); emit8(0xC2); emit8(0x60);              // add edx, 96
    emitJmp(twoCommon);
    emitLabel(d0Lower);
    emit8(0x81); emit8(0xFA); emit32(0xC0);             // cmp edx, 0xC0
    emitJcc(">=", unk2);
    emit8(0x81); emit8(0xEA); emit32(0xB0);             // sub edx, 0xB0
    emit8(0x81); emit8(0xC2); emit32(0x80);             // add edx, 128
    emitJmp(twoCommon);
    emitLabel(d0E);
    emit8(0xBA); emit32(160);                           // mov edx, 160
    emitJmp(twoCommon);

    emitLabel(isD1);
    emit8(0x0F); emit8(0xB6); emit8(0x56); emit8(0x01); // movzx edx, byte [rsi+1]
    emit8(0x81); emit8(0xFA); emit32(0x91);             // cmp edx, 0x91
    emitJcc("==", d1E);
    emit8(0x81); emit8(0xFA); emit32(0x80);             // cmp edx, 0x80
    emitJcc("<", unk2);
    emit8(0x81); emit8(0xFA); emit32(0x90);             // cmp edx, 0x90
    emitJcc(">=", unk2);
    emit8(0x81); emit8(0xEA); emit32(0x80);             // sub edx, 0x80
    emit8(0x81); emit8(0xC2); emit32(0x90);             // add edx, 144
    emitJmp(twoCommon);
    emitLabel(d1E);
    emit8(0xBA); emit32(161);                           // mov edx, 161
    emitJmp(twoCommon);

    emitLabel(twoCommon);
    emit8(0x48); emit8(0x83); emit8(0xC6); emit8(0x02); // add rsi, 2
    emit8(0x89); emit8(0xD0);                           // mov eax, edx
    emitJmp(drawPath);

    emitLabel(unk2);
    emit8(0x48); emit8(0x83); emit8(0xC6); emit8(0x02); // add rsi, 2
    emitJmp(skipChar);
    emitLabel(unkPath);
    emit8(0x48); emit8(0xFF); emit8(0xC6);              // inc rsi
    emitLabel(skipChar);
    emitJmp(charLoop);

    // ---- draw glyph: eax = index, r10 = font base, rcx = x, r13 = y ----
    emitLabel(drawPath);
    emit8(0x4C); emit8(0x89); emit8(0xD2);              // mov rdx, r10
    emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x04); // shl rax, 4
    emit8(0x48); emit8(0x01); emit8(0xC2);              // add rdx, rax (rdx = glyph ptr)
    emit8(0x4C); emit8(0x89); emit8(0xE8);              // mov rax, r13 (y)
    emit8(0x49); emit8(0x0F); emit8(0xAF); emit8(0xC4); // imul rax, r12 (y*pitch)
    emit8(0x48); emit8(0x01); emit8(0xD8);              // add rax, rbx (+fb)
    emit8(0x48); emit8(0x8D); emit8(0x04); emit8(0x88); // lea rax, [rax + rcx*4] (+x*4)
    emit8(0x48); emit8(0x89); emit8(0xC7);              // mov rdi, rax
    emit8(0x45); emit8(0x31); emit8(0xDB);              // xor r11d, r11d (row counter)
    emitLabel(rowLoop);
    emit8(0x49); emit8(0x83); emit8(0xFB); emit8(0x10); // cmp r11, 16
    emitJcc(">=", advanceX);
    emit8(0x0F); emit8(0xB6); emit8(0x02);              // movzx eax, byte [rdx] (row byte)
    emit8(0x45); emit8(0x31); emit8(0xFF);              // xor r15d, r15d (col counter)
    emitLabel(colLoop);
    emit8(0x49); emit8(0x83); emit8(0xFF); emit8(0x08); // cmp r15, 8
    emitJcc(">=", colEnd);
    emit8(0xD0); emit8(0xE0);                           // shl al, 1
    emit8(0x0F); emit8(0x82);                           // jc (bit set -> fg) — emitJcc("<") would emit jl
    jmpFixups.push_back({code.size(), colSet});
    emit32(0);
    emit8(0x46); emit8(0x89); emit8(0x0C); emit8(0xBF); // mov [rdi + r15*4], r9d (bg)
    emitJmp(colNext);
    emitLabel(colSet);
    emit8(0x46); emit8(0x89); emit8(0x04); emit8(0xBF); // mov [rdi + r15*4], r8d (fg)
    emitLabel(colNext);
    emit8(0x41); emit8(0xFF); emit8(0xC7);              // inc r15d
    emitJmp(colLoop);
    emitLabel(colEnd);
    emit8(0x4C); emit8(0x01); emit8(0xE7);              // add rdi, r12 (next row)
    emit8(0x48); emit8(0xFF); emit8(0xC2);              // inc rdx
    emit8(0x41); emit8(0xFF); emit8(0xC3);              // inc r11d
    emitJmp(rowLoop);

    emitLabel(advanceX);
    emit8(0x48); emit8(0x83); emit8(0xC1); emit8(0x08); // add rcx, 8
    emitJmp(charLoop);

    emitLabel(doneLbl);
}
