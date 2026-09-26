#include "x86emit.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>

// ====================================================================
// Runtime helper for the http_json(url) builtin.
//
// The helper is a position-independent x86-64 routine emitted into the
// output program's .text (once, at the first http_json call site). It
// has no external calls and no rip-relative data, so it needs no fixups.
//
// Entry (set up by the http_json codegen wrapper):
//   rcx = HTTP status code (int32)
//   rdx = body length (bytes)
//   rsi = body buffer pointer (NET_BUF, raw HTML)
//   r8  = raw HTTP headers pointer (NET_HDR, CRLF/0-separated, from
//         HttpQueryInfoA with HTTP_QUERY_RAW_HEADERS_CRLF)
//   rdi = record buffer pointer (NET_JSON) with layout:
//         [+0]  int32 status
//         [+4]  int32 jsonLen
//         [+8]  int32 magic 'ZJSN' (print uses this to detect the record)
//         [+12] char json[jsonMax]            (escaped JSON text)
//         [+12+jsonMax]    int32 headLen
//         [+16+jsonMax]    char head[headMax] (reconstructed <head>)
//
// Exit: rax = record pointer.
//
// The helper's persistent registers: rbx=record, rbp=json cursor (later the
// head cursor), r12=json limit (later the head limit), r13=body, r14=bodyLen,
// r15=headers; flags dword in [rsp+16]; scratch dword in [rsp+24].
// Subroutines (findTitle/findHead/findMeta/findTitleClose/copyEscaped/
// copyRaw) clobber rax,rcx,rdx,rsi,rdi,r8,r9,r10,r11 and are reached via
// internal call/ret.
// ====================================================================

using namespace x86e;

namespace {

struct HJ {
    Em e;
    std::vector<int> labelPos;
    std::vector<std::pair<size_t, int>> fixups;
    int nextLabel = 0;

    HJ(std::vector<uint8_t>& code) : e(code) {}

    int newLabel() { return nextLabel++; }
    void label(int l) {
        if ((size_t)l >= labelPos.size()) labelPos.resize(l + 1, -1);
        labelPos[l] = (int)e.c.size();
    }
    void jcc(uint8_t cc, int l) { e.b(0x0F); e.b(cc); fixups.push_back({e.c.size(), l}); e.d(0); }
    void jmp(int l) { e.b(0xE9); fixups.push_back({e.c.size(), l}); e.d(0); }
    void call(int l) { e.b(0xE8); fixups.push_back({e.c.size(), l}); e.d(0); }

    void resolve() {
        for (auto& f : fixups) {
            if (f.second < 0 || (size_t)f.second >= labelPos.size()) continue;
            int32_t rel = labelPos[f.second] - (int32_t)(f.first + 4);
            e.c[f.first]     = (uint8_t)(rel & 0xFF);
            e.c[f.first + 1] = (uint8_t)((rel >> 8) & 0xFF);
            e.c[f.first + 2] = (uint8_t)((rel >> 16) & 0xFF);
            e.c[f.first + 3] = (uint8_t)((rel >> 24) & 0xFF);
        }
    }
};

// Emits code that stores a compile-time string at the cursor register
// `cur` and advances it. If the cursor is already at/past the limit (r12),
// the whole string is skipped so an overlong body can never overflow the
// record's output buffer.
void putStr(HJ& h, int cur, const char* s) {
    size_t n = strlen(s);
    size_t i = 0;
    int okL = h.newLabel();
    int endL = h.newLabel();
    h.e.cmp_r64_reg(cur, R_R12);
    h.jcc(0x82, okL);                            // jb: room left
    h.jmp(endL);
    h.label(okL);
    while (n - i >= 8) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v |= (uint64_t)(uint8_t)s[i + k] << (8 * k);
        h.e.mov_r64_imm64(R_RAX, v);
        h.e.mov_mem_r64(cur, 0, R_RAX);
        h.e.alu_imm_reg(0, cur, 8);
        i += 8;
    }
    if (n - i >= 4) {
        uint32_t v = 0;
        for (int k = 0; k < 4; k++) v |= (uint32_t)(uint8_t)s[i + k] << (8 * k);
        h.e.mov_r32_imm(R_RAX, v);
        h.e.mov_mem_r32(cur, 0, R_RAX);
        h.e.alu_imm_reg(0, cur, 4);
        i += 4;
    }
    if (n - i >= 2) {
        uint16_t v = (uint16_t)((uint8_t)s[i] | ((uint8_t)s[i + 1] << 8));
        h.e.mov_r32_imm(R_RAX, v);
        h.e.mov_mem_r16(cur, 0, R_RAX);
        h.e.alu_imm_reg(0, cur, 2);
        i += 2;
    }
    if (n - i >= 1) {
        h.e.mov_byte_mem_imm(cur, 0, (uint8_t)s[i]);
        h.e.inc_r64(cur);
    }
    h.label(endL);
}

// Boundary check for a tag name: RAX holds the char; jumps to `ok` if it
// is ' '/'\t'/'\r'/'\n'/'\'/'/'>', otherwise jumps to `notOk`.
void emitBoundaryChecks(HJ& h, int notOk) {
    int okL = h.newLabel();
    h.e.cmp_byte_reg_imm(R_RAX, ' ');
    h.jcc(0x84, okL);                            // je
    h.e.cmp_byte_reg_imm(R_RAX, 0x09);
    h.jcc(0x84, okL);
    h.e.cmp_byte_reg_imm(R_RAX, 0x0D);
    h.jcc(0x84, okL);
    h.e.cmp_byte_reg_imm(R_RAX, 0x0A);
    h.jcc(0x84, okL);
    h.e.cmp_byte_reg_imm(R_RAX, '/');
    h.jcc(0x84, okL);
    h.e.cmp_byte_reg_imm(R_RAX, '>');
    h.jcc(0x84, okL);
    h.jmp(notOk);
    h.label(okL);
}

// Generic tag-open finder subroutine:
//   input  r10 = scan start index
//   output r8  = '<' index (or -1), r9 = '>' index (or -1)
void emitFindTag(HJ& h, int sub, const char* name) {
    size_t len = strlen(name);
    int loopL = h.newLabel();
    int incrL = h.newLabel();
    int notFoundL = h.newLabel();
    int gtLoopL = h.newLabel();
    int gtFoundL = h.newLabel();

    h.label(sub);
    h.label(loopL);
    h.e.cmp_r64_reg(R_R10, R_R14);
    h.jcc(0x83, notFoundL);                          // jae
    h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 0);
    h.e.cmp_byte_reg_imm(R_RAX, '<');
    h.jcc(0x85, incrL);                              // jne
    h.e.lea_r64_mem(R_RAX, R_R10, (int)(2 + len));   // '<' + name + boundary
    h.e.cmp_r64_reg(R_RAX, R_R14);
    h.jcc(0x83, incrL);                              // jae
    for (size_t k = 0; k < len; k++) {
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, (int8_t)(1 + k));
        h.e.or_byte_reg_imm(R_RAX, 0x20);
        h.e.cmp_byte_reg_imm(R_RAX, (uint8_t)name[k]);
        h.jcc(0x85, incrL);                          // jne
    }
    h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, (int8_t)(1 + len));
    emitBoundaryChecks(h, incrL);
    h.e.mov_r64_reg(R_R8, R_R10);                    // r8 = '<' idx
    h.e.lea_r64_mem(R_R9, R_R10, (int)(1 + len));    // scan '>' from after name
    h.label(gtLoopL);
    h.e.cmp_r64_reg(R_R9, R_R14);
    h.jcc(0x83, incrL);                              // jae: no '>' -> keep scanning
    h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R9, 0);
    h.e.cmp_byte_reg_imm(R_RAX, '>');
    h.jcc(0x84, gtFoundL);
    h.e.inc_r64(R_R9);
    h.jmp(gtLoopL);
    h.label(gtFoundL);
    h.e.ret();
    h.label(incrL);
    h.e.inc_r64(R_R10);
    h.jmp(loopL);
    h.label(notFoundL);
    h.e.mov_r64_imm32(R_R8, -1);
    h.e.mov_r64_imm32(R_R9, -1);
    h.e.ret();
}

// Emits the "copy len (already capped to 512/1024 by caller)" pattern:
//   rsi = body+idx, rcx = len, rbp = json cursor; calls copyEscaped.
void emitCopyFromBodyEsc(HJ& h, int subEsc, int idxReg) {
    h.e.mov_r64_reg(R_RSI, R_R13);
    h.e.add_r64_reg(R_RSI, idxReg);
    h.call(subEsc);
}

} // namespace

std::vector<uint8_t> buildHttpJsonHelper(uint32_t jsonMax, uint32_t headMax) {
    std::vector<uint8_t> code;
    HJ h(code);

    // save callee-saved registers (helper is called from wrapper code)
    h.e.push_r(R_RBX);
    h.e.push_r(R_RBP);
    h.e.push_r(R_R12);
    h.e.push_r(R_R13);
    h.e.push_r(R_R14);
    h.e.push_r(R_R15);
    h.e.push_r(R_RSI);
    h.e.push_r(R_RDI);

    h.e.mov_r64_reg(R_RBX, R_RDI);                    // record
    h.e.mov_r64_reg(R_R13, R_RSI);                    // body
    h.e.mov_r64_reg(R_R14, R_RDX);                    // bodyLen
    h.e.mov_r64_reg(R_R15, R_R8);                     // headers
    h.e.mov_r32_reg(R_R9, R_RCX);                     // status
    h.e.lea_r64_mem(R_RBP, R_RBX, 12);                // json cursor
    h.e.lea_r64_mem(R_R12, R_RBX, (int)(12 + jsonMax - 128));  // json limit
    h.e.mov_mem_r32(R_RBX, 0, R_R9);                  // [rec+0] = status
    h.e.mov_mem_imm32(R_RBX, 4, 0);                   // [rec+4] = jsonLen (placeholder)
    h.e.mov_mem_imm32(R_RBX, 8, 0x4E534A5A);          // [rec+8] = magic 'ZJSN'

    // Jump over the subroutine bodies (they are reached only via call/ret);
    // without this the entry code would fall through into subEsc.
    int jsonPart = h.newLabel();
    h.jmp(jsonPart);

    // ================= subroutines =================
    int subEsc = h.newLabel();
    int subMeta = h.newLabel();
    int subTitle = h.newLabel();
    int subHead = h.newLabel();
    int subTitleClose = h.newLabel();
    int subRaw = h.newLabel();

    // ---- copyEscaped: rsi=src, rcx=len; rbp=cursor, r12=limit ----
    {
        int loopL = h.newLabel();
        int doneL = h.newLabel();
        int escQ = h.newLabel(), escBS = h.newLabel(), escN = h.newLabel();
        int escR = h.newLabel(), escT = h.newLabel(), escU = h.newLabel();
        int nextL = h.newLabel();
        int hiOk = h.newLabel(), loOk = h.newLabel();

        h.label(subEsc);
        h.label(loopL);
        h.e.test_r64_reg(R_RCX, R_RCX);
        h.jcc(0x84, doneL);                           // jz
        h.e.cmp_r64_reg(R_RBP, R_R12);
        h.jcc(0x83, doneL);                           // jae (out of space)
        h.e.movzx_r64_mem8(R_RAX, R_RSI, 0);
        h.e.cmp_byte_reg_imm(R_RAX, '"');
        h.jcc(0x84, escQ);
        h.e.cmp_byte_reg_imm(R_RAX, '\\');
        h.jcc(0x84, escBS);
        h.e.cmp_byte_reg_imm(R_RAX, 0x0A);
        h.jcc(0x84, escN);
        h.e.cmp_byte_reg_imm(R_RAX, 0x0D);
        h.jcc(0x84, escR);
        h.e.cmp_byte_reg_imm(R_RAX, 0x09);
        h.jcc(0x84, escT);
        h.e.cmp_byte_reg_imm(R_RAX, 0x20);
        h.jcc(0x82, escU);                            // jb (control char)
        h.e.mov_mem_r8(R_RBP, 0);                     // mov [rbp], al
        h.e.inc_r64(R_RBP);
        h.jmp(nextL);
        h.label(escQ);
        h.e.mov_mem_imm16(R_RBP, 0, 0x5C22);          // \"
        h.e.alu_imm_reg(0, R_RBP, 2);
        h.jmp(nextL);
        h.label(escBS);
        h.e.mov_mem_imm16(R_RBP, 0, 0x5C5C);          // \\
        h.e.alu_imm_reg(0, R_RBP, 2);
        h.jmp(nextL);
        h.label(escN);
        h.e.mov_mem_imm16(R_RBP, 0, 0x5C6E);          // \n
        h.e.alu_imm_reg(0, R_RBP, 2);
        h.jmp(nextL);
        h.label(escR);
        h.e.mov_mem_imm16(R_RBP, 0, 0x5C72);          // \r
        h.e.alu_imm_reg(0, R_RBP, 2);
        h.jmp(nextL);
        h.label(escT);
        h.e.mov_mem_imm16(R_RBP, 0, 0x5C74);          // \t
        h.e.alu_imm_reg(0, R_RBP, 2);
        h.jmp(nextL);
        h.label(escU);
        h.e.mov_mem_imm32(R_RBP, 0, 0x3030755C);      // \u00
        h.e.alu_imm_reg(0, R_RBP, 4);
        h.e.mov_r64_reg(R_RDX, R_RAX);
        h.e.shift_imm_reg(5, R_RDX, 4);               // shr rdx, 4
        h.e.and_r32_imm(R_RDX, 0xF);
        h.e.add_byte_imm(R_RDX, 0x30);
        h.e.cmp_byte_reg_imm(R_RDX, 0x39);
        h.jcc(0x86, hiOk);                            // jbe
        h.e.add_byte_imm(R_RDX, 7);
        h.label(hiOk);
        h.e.mov_mem_r8_reg(R_RBP, 4, R_RDX);
        h.e.mov_r64_reg(R_RDX, R_RAX);
        h.e.and_r32_imm(R_RDX, 0xF);
        h.e.add_byte_imm(R_RDX, 0x30);
        h.e.cmp_byte_reg_imm(R_RDX, 0x39);
        h.jcc(0x86, loOk);                            // jbe
        h.e.add_byte_imm(R_RDX, 7);
        h.label(loOk);
        h.e.mov_mem_r8_reg(R_RBP, 5, R_RDX);
        h.e.alu_imm_reg(0, R_RBP, 6);
        h.label(nextL);
        h.e.inc_r64(R_RSI);
        h.e.dec_reg64(R_RCX);
        h.jmp(loopL);
        h.label(doneL);
        h.e.ret();
    }

    // ---- tag finders ----
    emitFindTag(h, subTitle, "title");
    emitFindTag(h, subHead, "head");
    emitFindTag(h, subMeta, "meta");

    // ---- findTitleClose: r10=start; out r8 = '<' of '</title' or -1 ----
    {
        int loopL = h.newLabel();
        int incrL = h.newLabel();
        int notFoundL = h.newLabel();

        h.label(subTitleClose);
        h.label(loopL);
        h.e.cmp_r64_reg(R_R10, R_R14);
        h.jcc(0x83, notFoundL);                       // jae
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 0);
        h.e.cmp_byte_reg_imm(R_RAX, '<');
        h.jcc(0x85, incrL);
        h.e.lea_r64_mem(R_RAX, R_R10, 8);             // '</'+'title'+boundary
        h.e.cmp_r64_reg(R_RAX, R_R14);
        h.jcc(0x83, incrL);                           // jae
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 1);
        h.e.cmp_byte_reg_imm(R_RAX, '/');
        h.jcc(0x85, incrL);
        const char* title = "title";
        for (int k = 0; k < 5; k++) {
            h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, (int8_t)(2 + k));
            h.e.or_byte_reg_imm(R_RAX, 0x20);
            h.e.cmp_byte_reg_imm(R_RAX, (uint8_t)title[k]);
            h.jcc(0x85, incrL);
        }
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 7);
        emitBoundaryChecks(h, incrL);
        h.e.mov_r64_reg(R_R8, R_R10);
        h.e.ret();
        h.label(incrL);
        h.e.inc_r64(R_R10);
        h.jmp(loopL);
        h.label(notFoundL);
        h.e.mov_r64_imm32(R_R8, -1);
        h.e.ret();
    }

    // ---- copyRaw: rsi=src, rcx=len, rdi=dst, rdx=limit ----
    {
        int okL = h.newLabel();
        int doneL = h.newLabel();
        h.label(subRaw);
        h.e.mov_r64_reg(R_RAX, R_RDI);
        h.e.add_r64_reg(R_RAX, R_RCX);
        h.e.cmp_r64_reg(R_RAX, R_RDX);
        h.jcc(0x86, okL);                             // jbe: fits
        h.e.mov_r64_reg(R_RAX, R_RDX);
        h.e.sub_r64_reg(R_RAX, R_RDI);                // truncate to limit-dst
        h.e.mov_r64_reg(R_RCX, R_RAX);
        h.e.test_r64_reg(R_RCX, R_RCX);
        h.jcc(0x86, doneL);                           // jbe: nothing to copy
        h.label(okL);
        h.e.rep_movsb();
        h.label(doneL);
        h.e.ret();
    }

    // ================= JSON part =================
    h.label(jsonPart);
    putStr(h, R_RBP, "{\"status\":");
    // itoa(status in r9d) into cursor
    {
        int loopL = h.newLabel();
        h.e.sub_rsp_imm(32);
        h.e.lea_r64_mem(R_R10, R_RSP, 31);
        h.e.xor_reg32(R_R8);
        h.e.mov_r32_reg(R_RAX, R_R9);
        h.e.mov_r32_imm(R_RCX, 10);
        h.label(loopL);
        h.e.xor_reg32(R_RDX);
        h.e.f7_reg(6, R_RCX);                         // div rcx
        h.e.add_byte_imm(R_RDX, '0');
        h.e.mov_mem_r8_reg(R_R10, 0, R_RDX);
        h.e.dec_reg64(R_R10);
        h.e.inc_reg32(R_R8);
        h.e.test_r64_reg(R_RAX, R_RAX);
        h.jcc(0x85, loopL);                           // jnz
        h.e.inc_r64(R_RSI);
        h.e.mov_r64_reg(R_RSI, R_R10);
        h.e.inc_r64(R_RSI);                           // digits start
        h.e.mov_r64_reg(R_RDI, R_RBP);
        h.e.mov_r64_reg(R_RCX, R_R8);
        h.e.rep_movsb();
        h.e.add_r64_reg(R_RBP, R_R8);
        h.e.add_rsp_imm(32);
    }
    putStr(h, R_RBP, ",\"title\":\"");

    // title (escaped); flags bit1 = title found
    {
        int noTitleL = h.newLabel();
        int capL = h.newLabel();
        int haveLenL = h.newLabel();
        int lenOkL = h.newLabel();

        h.e.mov_r64_imm32(R_R10, 0);
        h.call(subTitle);
        h.e.cmp_r64_imm32(R_R8, -1);
        h.jcc(0x84, noTitleL);                        // je
        h.e.mov_r64_reg(R_R10, R_R9);
        h.e.inc_r64(R_R10);                           // title text start
        h.call(subTitleClose);
        h.e.mov_r64_reg(R_R10, R_R9);
        h.e.inc_r64(R_R10);                           // restore start (close clobbers r10)
        h.e.mov_r64_reg(R_RAX, R_R8);
        h.e.cmp_r64_imm32(R_RAX, -1);
        h.jcc(0x85, haveLenL);                        // jne: use close idx
        h.e.mov_r64_reg(R_RAX, R_R14);                // no close: body end
        h.label(haveLenL);
        h.e.sub_r64_reg(R_RAX, R_R10);                // len = end - start
        h.e.cmp_r64_imm32(R_RAX, 512);
        h.jcc(0x86, lenOkL);                          // jbe
        h.e.mov_r64_imm32(R_RAX, 512);
        h.label(lenOkL);
        h.e.mov_r64_reg(R_RCX, R_RAX);
        h.e.mov_r64_reg(R_RSI, R_R13);
        h.e.add_r64_reg(R_RSI, R_R10);
        h.call(subEsc);
        h.e.mov_r32_mem(R_RAX, R_RSP, 16);
        h.e.or_r32_imm(R_RAX, 2);                       // flags |= title found
        h.e.mov_mem_r32(R_RSP, 16, R_RAX);
        h.label(noTitleL);
    }
    putStr(h, R_RBP, "\",\"meta\":[");

    // metas (escaped); count in [rsp+24]; flags bit2 = meta found
    {
        int loopL = h.newLabel();
        int doneL = h.newLabel();
        int firstL = h.newLabel();
        int capL = h.newLabel();
        int lenOkL = h.newLabel();

        h.e.mov_mem_imm32(R_RSP, 24, 0);              // metaCount = 0
        h.e.mov_r64_imm32(R_R10, 0);
        h.call(subMeta);
        h.label(loopL);
        h.e.cmp_r64_reg(R_RBP, R_R12);
        h.jcc(0x83, doneL);                           // jae: buffer full
        h.e.cmp_r64_imm32(R_R8, -1);
        h.jcc(0x84, doneL);                           // je
        h.e.mov_r32_mem(R_RAX, R_RSP, 24);
        h.e.test_r64_reg(R_RAX, R_RAX);
        h.jcc(0x84, firstL);                          // jz: first meta, no comma
        putStr(h, R_RBP, ",");
        h.label(firstL);
        h.e.mov_r64_reg(R_RAX, R_R9);
        h.e.sub_r64_reg(R_RAX, R_R8);
        h.e.inc_r64(R_RAX);                           // len = '>' - '<' + 1
        h.e.cmp_r64_imm32(R_RAX, 1024);
        h.jcc(0x86, lenOkL);                          // jbe
        h.e.mov_r64_imm32(R_RAX, 1024);
        h.label(lenOkL);
        h.e.mov_r64_reg(R_RCX, R_RAX);
        h.e.mov_r64_reg(R_RSI, R_R13);
        h.e.add_r64_reg(R_RSI, R_R8);
        h.call(subEsc);
        h.e.mov_r32_mem(R_RAX, R_RSP, 24);
        h.e.inc_reg32(R_RAX);
        h.e.mov_mem_r32(R_RSP, 24, R_RAX);
        h.e.mov_r32_mem(R_RAX, R_RSP, 16);
        h.e.or_r32_imm(R_RAX, 4);                       // flags |= meta found
        h.e.mov_mem_r32(R_RSP, 16, R_RAX);
        h.e.mov_r64_reg(R_R10, R_R8);
        h.e.inc_r64(R_R10);
        h.call(subMeta);
        h.jmp(loopL);
        h.label(doneL);
    }
    putStr(h, R_RBP, "],\"headers\":{");

    // raw HTTP headers -> JSON object (skip the status line)
    {
        int loopL = h.newLabel();
        int doneL = h.newLabel();
        int skipL = h.newLabel();
        int noCommaL = h.newLabel();
        int lineScanL = h.newLabel();
        int lineEndL = h.newLabel();
        int colonScanL = h.newLabel();
        int noColonL = h.newLabel();
        int colonFoundL = h.newLabel();
        int trimL = h.newLabel();
        int trimNextL = h.newLabel();
        int valueEndL = h.newLabel();

        h.e.mov_r64_imm32(R_R10, 0);                  // line start
        h.e.xor_reg32(R_R9);                          // lineIdx = 0
        h.label(loopL);
        h.e.cmp_r64_imm32(R_R9, 64);
        h.jcc(0x83, doneL);                           // jae
        // find line end
        h.e.mov_r64_reg(R_R11, R_R10);
        h.e.mov_r64_imm32(R_RCX, 0);
        h.label(lineScanL);
        h.e.cmp_r64_imm32(R_RCX, 4096);
        h.jcc(0x83, lineEndL);                        // jae (cap)
        h.e.movzx_r64_mem8_idx(R_RAX, R_R15, R_R11, 0);
        h.e.test_r64_reg(R_RAX, R_RAX);
        h.jcc(0x84, lineEndL);                        // jz: NUL
        h.e.cmp_byte_reg_imm(R_RAX, 0x0A);
        h.jcc(0x84, lineEndL);                        // je
        h.e.cmp_byte_reg_imm(R_RAX, 0x0D);
        h.jcc(0x84, lineEndL);                        // je
        h.e.inc_r64(R_R11);
        h.e.inc_r64(R_RCX);
        h.jmp(lineScanL);
        h.label(lineEndL);
        h.e.mov_r64_reg(R_RAX, R_R11);
        h.e.sub_r64_reg(R_RAX, R_R10);                // lineLen
        h.e.test_r64_reg(R_RAX, R_RAX);
        h.jcc(0x84, doneL);                           // jz: empty line -> done
        h.e.cmp_r64_imm32(R_R9, 0);
        h.jcc(0x86, skipL);                           // jbe: first line = status line
        // lineIdx > 0: it's a header
        h.e.cmp_r64_imm32(R_R9, 1);
        h.jcc(0x86, noCommaL);                        // jbe: second line, no comma
        putStr(h, R_RBP, ",");
        h.label(noCommaL);
        putStr(h, R_RBP, "\"");
        // find ':'
        h.e.mov_r64_reg(R_RSI, R_R10);
        h.label(colonScanL);
        h.e.cmp_r64_reg(R_RSI, R_R11);
        h.jcc(0x83, noColonL);                        // jae: no colon in line
        h.e.movzx_r64_mem8_idx(R_RAX, R_R15, R_RSI, 0);
        h.e.cmp_byte_reg_imm(R_RAX, ':');
        h.jcc(0x84, colonFoundL);
        h.e.inc_r64(R_RSI);
        h.jmp(colonScanL);
        h.label(colonFoundL);
        // name = [r10, rsi)
        h.e.mov_r64_reg(R_RAX, R_RSI);
        h.e.sub_r64_reg(R_RAX, R_R10);
        h.e.mov_r64_reg(R_RCX, R_RAX);
        h.e.mov_r64_reg(R_RDI, R_RSI);                // save colon idx in rdi
        h.e.mov_r64_reg(R_RSI, R_R15);
        h.e.add_r64_reg(R_RSI, R_R10);
        h.call(subEsc);
        putStr(h, R_RBP, "\":\"");
        // value = [colon+1, r11), trim leading spaces/tabs
        h.e.mov_r64_reg(R_RSI, R_RDI);
        h.e.inc_r64(R_RSI);
        h.label(trimL);
        h.e.cmp_r64_reg(R_RSI, R_R11);
        h.jcc(0x83, valueEndL);                       // jae
        h.e.movzx_r64_mem8_idx(R_RAX, R_R15, R_RSI, 0);
        h.e.cmp_byte_reg_imm(R_RAX, ' ');
        h.jcc(0x84, trimNextL);
        h.e.cmp_byte_reg_imm(R_RAX, 0x09);
        h.jcc(0x84, trimNextL);
        h.jmp(valueEndL);
        h.label(trimNextL);
        h.e.inc_r64(R_RSI);
        h.jmp(trimL);
        h.label(valueEndL);
        h.e.mov_r64_reg(R_RAX, R_R11);
        h.e.sub_r64_reg(R_RAX, R_RSI);
        h.e.mov_r64_reg(R_RCX, R_RAX);
        h.e.mov_r64_reg(R_RAX, R_R15);
        h.e.add_r64_reg(R_RAX, R_RSI);
        h.e.mov_r64_reg(R_RSI, R_RAX);
        h.call(subEsc);
        putStr(h, R_RBP, "\"");
        h.jmp(skipL);
        h.label(noColonL);
        // no colon: whole line as one string (lineLen must be recomputed —
        // the colon scan clobbered rax)
        h.e.mov_r64_reg(R_RAX, R_R11);
        h.e.sub_r64_reg(R_RAX, R_R10);
        h.e.mov_r64_reg(R_RCX, R_RAX);                // lineLen
        h.e.mov_r64_reg(R_RSI, R_R15);
        h.e.add_r64_reg(R_RSI, R_R10);
        h.call(subEsc);
        putStr(h, R_RBP, "\"");
        h.label(skipL);
        h.e.inc_reg32(R_R9);                          // lineIdx++
        // advance past the line end (CR/LF) to the next line
        h.e.mov_r64_reg(R_R10, R_R11);
        int skipCrLf = h.newLabel();
        int skipNext = h.newLabel();
        h.label(skipCrLf);
        h.e.movzx_r64_mem8_idx(R_RAX, R_R15, R_R10, 0);
        h.e.cmp_byte_reg_imm(R_RAX, 0x0D);
        h.jcc(0x84, skipNext);                        // je
        h.e.cmp_byte_reg_imm(R_RAX, 0x0A);
        h.jcc(0x84, skipNext);                        // je
        h.e.cmp_byte_reg_imm(R_RAX, 0);
        h.jcc(0x84, doneL);                           // je: NUL -> headers done
        h.jmp(loopL);                                 // next line
        h.label(skipNext);
        h.e.inc_r64(R_R10);
        h.jmp(skipCrLf);
        h.label(doneL);
    }
    // ================= JSON tail =================
    // close the headers object; the JSON text is now complete
    putStr(h, R_RBP, "}");
    // jsonLen = jsonCursor - (record + 12)
    h.e.mov_r64_reg(R_RAX, R_RBP);
    h.e.sub_r64_reg(R_RAX, R_RBX);
    h.e.alu_imm_reg(5, R_RAX, 12);                    // sub rax, 12
    h.e.mov_mem_r32(R_RBX, 4, R_RAX);                 // [rec+4] = jsonLen

    // ================= <head> reconstruction =================
    // head cursor/limit live in rbp/r12; r10 = scan start, r13 = body,
    // r14 = bodyLen. Copies the raw contents of <head>...</head> (escaped
    // tags are NOT unescaped; body text is copied verbatim).
    h.e.lea_r64_mem(R_RBP, R_RBX, (int)(12 + jsonMax));              // head cursor
    h.e.lea_r64_mem(R_R12, R_RBX, (int)(12 + jsonMax + headMax));    // head limit
    h.e.mov_mem_imm32(R_RBX, (int)(12 + jsonMax), 0);                // headLen = 0
    h.e.mov_r64_imm32(R_R10, 0);
    h.call(subHead);                                  // r8='<', r9='>' of <head...>
    h.e.cmp_r64_imm32(R_R8, -1);
    {
        int noHead = h.newLabel();
        int scanHeadClose = h.newLabel();
        int headNext = h.newLabel();
        int headCloseOk = h.newLabel();
        int headCopy = h.newLabel();

        h.jcc(0x84, noHead);                          // je: no <head> tag
        // find '</head' starting after the open tag's '>'
        h.e.mov_r64_reg(R_R10, R_R9);
        h.e.inc_r64(R_R10);
        h.label(scanHeadClose);
        h.e.cmp_r64_reg(R_R10, R_R14);
        h.jcc(0x83, noHead);                          // jae
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 0);
        h.e.cmp_byte_reg_imm(R_RAX, '<');
        h.jcc(0x85, headNext);                        // jne
        h.e.lea_r64_mem(R_RAX, R_R10, 7);             // '</head' + boundary
        h.e.cmp_r64_reg(R_RAX, R_R14);
        h.jcc(0x83, headNext);                        // jae
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 1);
        h.e.cmp_byte_reg_imm(R_RAX, '/');
        h.jcc(0x85, headNext);                        // jne
        const char* headTag = "head";
        for (int k = 0; k < 4; k++) {
            h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, (int8_t)(2 + k));
            h.e.or_byte_reg_imm(R_RAX, 0x20);
            h.e.cmp_byte_reg_imm(R_RAX, (uint8_t)headTag[k]);
            h.jcc(0x85, headNext);                    // jne
        }
        h.e.movzx_r64_mem8_idx(R_RAX, R_R13, R_R10, 6);
        emitBoundaryChecks(h, headNext);
        h.jmp(headCopy);
        h.label(headNext);
        h.e.inc_r64(R_R10);
        h.jmp(scanHeadClose);
        h.label(headCopy);
        // head contents = body[r9+1 .. r10)
        h.e.mov_r64_reg(R_RAX, R_R10);
        h.e.sub_r64_reg(R_RAX, R_R9);
        h.e.alu_imm_reg(5, R_RAX, 1);                 // sub rax, 1
        h.e.mov_r64_reg(R_RCX, R_RAX);                // len
        h.e.mov_r64_reg(R_RSI, R_R13);
        h.e.add_r64_reg(R_RSI, R_R9);
        h.e.inc_r64(R_RSI);                           // src = body + r9 + 1
        h.e.mov_r64_reg(R_RDI, R_RBP);                // dst
        h.e.mov_r64_reg(R_RDX, R_R12);                // limit
        h.call(subRaw);
        // headLen = headCursor - (record + 12 + jsonMax)
        h.e.mov_r64_reg(R_RAX, R_RDI);
        h.e.lea_r64_mem(R_RDX, R_RBX, (int)(12 + jsonMax));
        h.e.sub_r64_reg(R_RAX, R_RDX);
        h.e.mov_mem_r32(R_RBX, (int)(12 + jsonMax), R_RAX);
        h.jmp(headCloseOk);
        h.label(noHead);
        h.label(headCloseOk);
    }

    // ================= epilogue =================
    h.e.pop_r(R_RDI);
    h.e.pop_r(R_RSI);
    h.e.pop_r(R_R15);
    h.e.pop_r(R_R14);
    h.e.pop_r(R_R13);
    h.e.pop_r(R_R12);
    h.e.pop_r(R_RBP);
    h.e.mov_r64_reg(R_RAX, R_RBX);                    // return record pointer
    h.e.pop_r(R_RBX);
    h.e.ret();
    h.resolve();
    return code;
}