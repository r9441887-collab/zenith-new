#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include <iostream>
#include <cstring>
#include <algorithm>

using namespace std;

void Codegen::emitSWInit() {
    // GetDC(hwnd) -> eax = hdc
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0x48); emit8(0x89); emit8(0xF1);                // rcx = hwnd
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "GetDC", "user32.dll"}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);

    // Save hdc, set up double-buffer
    emit8(0x89); emit8(0xC6);                              // esi = hdc

    // CreateCompatibleDC(hdc) -> hdcMem
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0x89); emit8(0xF1);                              // ecx = hdc
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "CreateCompatibleDC", "gdi32.dll"}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x10);   // [rbx+16] = hdcMem
    emit8(0x48); emit8(0x89); emit8(0xC2);                // rdx = hdcMem (for SelectObject)

    // Build BITMAPINFO on stack, call CreateDIBSection
    emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x60);
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(40);
    emit8(0x8B); emit8(0x43); emit8(0x20);                // eax = width
    emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x34);
    emit8(0x8B); emit8(0x43); emit8(0x24);                // eax = height
    emit8(0xF7); emit8(0xD8);                              // neg eax (top-down)
    emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x38);
    emit8(0x66); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x3C); emit16(1);
    emit8(0x66); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x3E); emit16(32);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x48); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x4C); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x54); emit32(0);
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x58); emit32(0);
    emit8(0x89); emit8(0xF1);                              // rcx = hdc
    emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x30);
    emit8(0x45); emit8(0x33); emit8(0xC0);
    emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x58);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "CreateDIBSection", "gdi32.dll"}); emit32(0);
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x18);   // [rbx+24] = hBitmap
    emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x58);
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x28);   // [rbx+40] = framebuffer
    emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x60);

    // SelectObject(hdcMem, hBitmap)
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x18);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "SelectObject", "gdi32.dll"}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);

    // ReleaseDC(hwnd, hdc)
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x08);
    emit8(0x89); emit8(0xF2);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "ReleaseDC", "user32.dll"}); emit32(0);
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
}

void Codegen::emitSWPresent() {
    // Allocate frame for GetDC + BitBlt + ReleaseDC
    emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x50);

    // GetDC(hwnd)
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x08);  // rcx = hwnd
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "GetDC", "user32.dll"});
    emit32(0);

    // Save hdc at [rsp+0x00]
    emit8(0x89); emit8(0x04); emit8(0x24);

    // BitBlt(hdc, 0, 0, width, height, hdcMem, 0, 0, SRCCOPY)
    emit8(0x8B); emit8(0x0C); emit8(0x24);
    emit8(0x33); emit8(0xD2);
    emit8(0x45); emit8(0x33); emit8(0xC0);
    emit8(0x44); emit8(0x8B); emit8(0x4B); emit8(0x20);
    emit8(0x8B); emit8(0x43); emit8(0x24);
    emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x10);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0);
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0x00CC0020);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "BitBlt", "gdi32.dll"});
    emit32(0);

    // ReleaseDC(hwnd, hdc)
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x08);
    emit8(0x8B); emit8(0x14); emit8(0x24);
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "ReleaseDC", "user32.dll"});
    emit32(0);
}

void Codegen::emitSWCleanup() {
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 0x20

    // DeleteDC([rbx+16])
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x10);  // mov rcx, [rbx+16]
    emit8(0x48); emit8(0x85); emit8(0xC9);               // test rcx, rcx
    emit8(0x74); emit8(0x06);                             // jz skipDC
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "DeleteDC", "gdi32.dll"});
    emit32(0);

    // DeleteObject([rbx+24])
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x18);  // mov rcx, [rbx+24]
    emit8(0x48); emit8(0x85); emit8(0xC9);               // test rcx, rcx
    emit8(0x74); emit8(0x06);                             // jz skipBmp
    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "DeleteObject", "gdi32.dll"});
    emit32(0);

    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 0x20
}
