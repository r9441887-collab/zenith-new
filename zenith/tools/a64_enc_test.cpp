// AArch64 encoder audit: every entry is one instruction in the assembler
// syntax the encoder is supposed to implement, next to the call that produces
// it. The program prints "asm text -> encoding" and the test compares that
// against a64_enc_golden.txt, which was assembled by clang, not by us. A
// mismatch means the hand-rolled bit layout in asm_a64.h drifted from the
// architecture.
//
// Build and run:  make -f Makefile.linux test-a64

#include "../src/asm_a64.h"

#include <cstdio>
#include <cstring>

struct Case {
    const char* asmText;
    uint32_t (*encode)();
};

#define CASE(text, call) {text, []() -> uint32_t { return call; }}

static const Case kCases[] = {
    CASE("mov x0, x1", encMov(0,1)),
    CASE("movz x0, #0x1234", encMovz(0,0x1234,0)),
    CASE("movz x0, #0x1234, lsl #16", encMovz(0,0x1234,1)),
    CASE("movk x0, #0x1234, lsl #32", encMovk(0,0x1234,2)),
    CASE("movn x0, #0xfff", encMovn(0,0xfff,0,true)),
    CASE("movn x0, #0", encMovn(0,0,0,true)),
    CASE("movn w0, #0", encMovn(0,0,0,false)),
    CASE("add x9, sp, #16", encAdd(9,31,16)),
    CASE("add x19, x19, #0x10", encAdd(19,19,0x10,0)),
    CASE("add x0, x1, x2", encAddReg(0,1,2)),
    CASE("sub x9, sp, #48", encSub(9,31,48)),
    CASE("sub x0, x1, x2", encSubReg(0,1,2)),
    CASE("subs xzr, x9, #1", encSubs(31,9,1)),
    CASE("cmp x0, #0", encCmp(0,0)),
    CASE("cmp x7, #4095", encCmp(7,4095)),
    CASE("cmp x0, x1", encCmpReg(0,1)),
    CASE("and x10, x10, x11", encAndReg(10,10,11)),
    CASE("orr x10, x10, x11", encOrrReg(10,10,11)),
    CASE("eor x10, x10, x11", encEorReg(10,10,11)),
    CASE("ands w10, w10, w11", encAndsW(10,10,11)),
    CASE("mvn x10, x10", encMvn(10,10)),
    CASE("neg x10, x10", encNeg(10,10)),
    CASE("lsl x10, x10, x11", encLsl(10,10,11)),
    CASE("lsr x10, x10, x11", encLsr(10,10,11)),
    CASE("asr x10, x10, x11", encAsr(10,10,11)),
    CASE("mul x10, x10, x11", encMul(10,10,11)),
    CASE("sdiv x10, x10, x11", encSdiv(10,10,11)),
    CASE("udiv x10, x10, x11", encUdiv(10,10,11)),
    CASE("msub x10, x9, x11, x10", encMsub(10,9,11,10)),
    CASE("ret", encRet()),
    CASE("svc #0", encSvc(0)),
    CASE("svc #60", encSvc(60)),
    CASE("cset x0, eq", encCset(0,0)),
    CASE("cset x0, ne", encCset(0,1)),
    CASE("cset x3, mi", encCset(3,4)),
    CASE("cset x0, lo", encCset(0,3)),
    CASE("cset x0, ge", encCset(0,10)),
    CASE("cset x0, ls", encCset(0,9)),
    CASE("cset x0, hi", encCset(0,8)),
    CASE("ldr x10, [sp, #8]", encLdrX(10,31,8)),
    CASE("str x10, [sp, #8]", encStrX(10,31,8)),
    CASE("ldr w10, [x9, #0]", encLdrW(10,9,0)),
    CASE("str w10, [x9, #0]", encStrW(10,9,0)),
    CASE("ldr x3, [x7, #32760]", encLdrX(3,7,32760)),
    CASE("str x3, [x7, #32760]", encStrX(3,7,32760)),
    CASE("ldrsw x3, [x7, #16380]", encLdrswX(3,7,16380)),
    CASE("ldrb w3, [x7, #255]", encLdrbW(3,7,255)),
    CASE("strb w3, [x7, #255]", encStrbW(3,7,255)),
    CASE("ldrh w3, [x7, #510]", encLdrhW(3,7,510)),
    CASE("strh w3, [x7, #510]", encStrhW(3,7,510)),
    CASE("ldr s3, [x7, #64]", encLdrS(3,7,64)),
    CASE("str s3, [x7, #64]", encStrS(3,7,64)),
    CASE("fadd s3, s7, s5", encFaddS(3,7,5)),
    CASE("fsub s3, s7, s5", encFsubS(3,7,5)),
    CASE("fmul s3, s7, s5", encFmulS(3,7,5)),
    CASE("fdiv s3, s7, s5", encFdivS(3,7,5)),
    CASE("fmov s3, s7", encFmovS(3,7)),
    CASE("fneg s3, s7", encFnegS(3,7)),
    CASE("fmov s3, w7", encFmovFromW(3,7)),
    CASE("fmov w3, s7", encFmovToW(3,7)),
    CASE("fcvt d3, s7", encFcvtDs(3,7)),
    CASE("fcvt s3, d7", encFcvtSd(3,7)),
    CASE("fmov d3, x7", encFmovFromX(3,7)),
    CASE("fcvtzs x3, d7", encFcvtzsD(3,7)),
    CASE("fcvtzs x3, s7", encFcvtzsS(3,7,true)),
    CASE("fcvtzs w3, s7", encFcvtzsS(3,7,false)),
    CASE("scvtf s3, x7", encScvtfS(3,7,true)),
    CASE("scvtf s3, w7", encScvtfS(3,7,false)),
    CASE("ucvtf s3, x7", encUcvtfS(3,7,true)),
    CASE("fcmp s3, s7", encFcmpS(3,7)),
    CASE("stp x30, xzr, [sp, #-64]!", encStpX(30,31,31,-64,kPairPre)),
    CASE("stp x21, x30, [sp, #16]", encStpX(21,30,31,16,kPairOffset)),
    CASE("ldp x29, x30, [sp], #16", encLdpX(29,30,31,16,kPairPost)),
    CASE("stp x3, x7, [x8, #-64]!", encStpX(3,7,8,-64,kPairPre)),
    CASE("stp w3, w7, [x8, #-64]!", encPair(0,3,7,8,-64,kPairPre,false,false)),
    CASE("stp x3, x7, [x8, #504]!", encStpX(3,7,8,504,kPairPre)),
    CASE("stp w3, w7, [x8, #252]!", encPair(0,3,7,8,252,kPairPre,false,false)),
    CASE("ldp x3, x7, [x8, #504]", encLdpX(3,7,8,504,kPairOffset)),
    CASE("ldp w3, w7, [x8, #252]", encPair(0,3,7,8,252,kPairOffset,true,false)),
    CASE("ldp w3, w7, [x8], #16", encPair(0,3,7,8,16,kPairPost,true,false)),
    CASE("fadd d3, d7, d5", encFaddD(3,7,5)),
    CASE("fsub d3, d7, d5", encFsubD(3,7,5)),
    CASE("fmul d3, d7, d5", encFmulD(3,7,5)),
    CASE("fdiv d3, d7, d5", encFdivD(3,7,5)),
    CASE("fmov d3, d7", encFmovD(3,7)),
    CASE("fneg d3, d7", encFnegD(3,7)),
    CASE("fabs d3, d7", encFabsD(3,7)),
    CASE("fcmp d3, d7", encFcmpD(3,7)),
    CASE("scvtf d3, x7", encScvtfD(3,7)),
};

int main() {
    for (const Case& c : kCases) {
        uint32_t w = c.encode();
        printf("%-28s %08x\n", c.asmText, w);
    }
    return 0;
}
