// ====================================================================
// irbugfind_test.cpp — unit tests for the IR-level bug finder
//
// The cases hand-build IRFunction bodies (no parser/codegen involved),
// run runBugFindIR, and check the emitted [ZT-IRxxx] codes. Positive
// cases assert presence of the expected code; negative cases assert that
// no warning was emitted (exempt shapes: `while 1` literal, IRGen switch
// dispatch, for-header meet, one-sided plain operands, dead code).
//
// Operand conventions the tests rely on (see irgen.cpp / src/ir.h):
//   Const/FConst/arith: a = dest, b/c = operands (divisor/shift amount = c)
//   Load:  a = dest reg, b = src slot
//   Store: a = dest slot, b = src value reg
//   Br/BrZ/BrNZ: target = b.label;  BrCC: operands = a/b, target = c.label
//
// Compiled and run by `make test-irbugfind`; see Makefile.linux.
// ====================================================================
#include "../src/irbugfind.h"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace {

IRInstr I(IROp op, IROperand a = IROperand::none(),
          IROperand b = IROperand::none(), IROperand c = IROperand::none(),
          const std::string& cond = "") {
    IRInstr in;
    in.op = op;
    in.a = a;
    in.b = b;
    in.c = c;
    in.cond = cond;
    return in;
}

IRInstr L(int id) {
    IRInstr in;
    in.op = IROp::Label;
    in.label = id;
    return in;
}

std::vector<std::string> codesOf(const std::vector<std::string>& warns) {
    std::vector<std::string> codes;
    for (const auto& w : warns) {
        size_t s = w.find("[ZT-");
        if (s == std::string::npos) continue;
        size_t e = w.find(']', s);
        if (e == std::string::npos) continue;
        codes.push_back(w.substr(s + 1, e - s - 1));
    }
    return codes;
}

struct Case {
    const char* name;
    std::vector<IRInstr> instrs;
    std::vector<std::string> want;
    bool expectClean = false;
    bool garbage = false;
};

const std::vector<Case>& cases() {
    static const std::vector<Case> v = {
        // ---- IR001: division by a constant zero (through a slot) ----
        {"001 div-zero-through-slot",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(1), IROperand::mkReg(0)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(1)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(7)),
             I(IROp::IDiv, IROperand::mkReg(3), IROperand::mkReg(2),
               IROperand::mkReg(1)),
             I(IROp::Ret, IROperand::mkReg(3)),
         },
         {"ZT-IR001"}, false},

        // ---- IR002: shift amount outside [0, 63] ----
        {"002 shift-amount-65",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(65)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(1)),
             I(IROp::Shl, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {"ZT-IR002"}, false},

        // ---- IR003: signed add overflow (INT64_MAX + 1) ----
        {"003 add-overflow",
         {
             I(IROp::Const, IROperand::mkReg(0),
               IROperand::mkImm(INT64_MAX)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(1)),
             I(IROp::Add, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {"ZT-IR003"}, false},

        // ---- IR004: branch on a known constant ----
        {"004 brz-plain-zero",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::BrZ, IROperand::mkReg(0), IROperand::lbl(0)),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR004"}, false},

        {"004 brnz-plain-zero",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::BrNZ, IROperand::mkReg(0), IROperand::lbl(0)),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR004"}, false},

        {"004 brcc-both-computed",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(1)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(1)),
             I(IROp::Add, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1)),                      // x = 2 (computed)
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(6)),
             I(IROp::Add, IROperand::mkReg(4), IROperand::mkReg(3),
               IROperand::mkReg(2)),                      // y = 8 (computed)
             I(IROp::BrCC, IROperand::mkReg(2), IROperand::mkReg(4),
               IROperand::lbl(0), "<"),                   // 2 < 8 always
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR004"}, false},

        {"004 brcc-same-register",
         {
             I(IROp::BrCC, IROperand::mkReg(7), IROperand::mkReg(7),
               IROperand::lbl(0), "=="),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR004"}, false},

        {"004 brcc-same-slot",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(5)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(5)),
             I(IROp::BrCC, IROperand::mkReg(0), IROperand::mkReg(1),
               IROperand::lbl(0), "<"),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR004"}, false},

        // ---- IR005: F2I of a NaN constant ----
        {"005 f2i-nan",
         {
             I(IROp::FConst, IROperand::mkReg(0),
               IROperand::fimmf(std::nanf(""))),
             I(IROp::F2I, IROperand::mkReg(1), IROperand::mkReg(0)),
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {"ZT-IR005"}, false},

        // ---- IR006: integer constant not representable in float32 ----
        {"006 i2f-loss-of-precision",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(16777217)),
             I(IROp::I2F, IROperand::mkReg(1), IROperand::mkReg(0)),
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {"ZT-IR006"}, false},

        // ---- IR007: a comparison decided by a known range ----
        // `x % 4` is in [-3, 3]: it can never equal 7.
        {"007 range-decided-false",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(4)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(7)),
             I(IROp::IMod, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(7)),
             I(IROp::Cmp, IROperand::mkReg(4), IROperand::mkReg(2),
               IROperand::mkReg(3), "=="),
             I(IROp::Ret, IROperand::mkReg(4)),
         },
         {"ZT-IR007"}, false},

        // the same check in branch position: IRGen lowers `if (r == 7)`
        // straight to BrCC, with no Cmp at all
        {"007 brcc-range-decided",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(4)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(7)),
             I(IROp::IMod, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(7)),
             I(IROp::BrCC, IROperand::mkReg(2), IROperand::mkReg(3),
               IROperand::lbl(0), "=="),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR007"}, false},

        // ---- IR008: a comparison whose operand is a comparison ----
        {"008 chained-cmp",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(3)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(4)),
             I(IROp::Cmp, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1), "<"),              // r2 = (a < b)
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(0)),
             I(IROp::Cmp, IROperand::mkReg(4), IROperand::mkReg(2),
               IROperand::mkReg(3), "=="),             // chained: 0/1 vs 0
             I(IROp::Ret, IROperand::mkReg(4)),
         },
         {"ZT-IR008"}, false},

        {"008 chained-brcc",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(3)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(4)),
             I(IROp::Cmp, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1), "<"),
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(0)),
             I(IROp::BrCC, IROperand::mkReg(2), IROperand::mkReg(3),
               IROperand::lbl(0), "=="),
             L(0),
             I(IROp::Ret),
         },
         {"ZT-IR008"}, false},

        // ---- IR009: a float compared with itself (NaN semantics) ----
        {"009 float-self-cmp",
         {
             I(IROp::FLoad, IROperand::mkReg(0), IROperand::slot(2)),
             I(IROp::FLoad, IROperand::mkReg(1), IROperand::slot(2)),
             [&] {
                 IRInstr cmp = I(IROp::Cmp, IROperand::mkReg(2),
                                 IROperand::mkReg(0), IROperand::mkReg(1),
                                 "==");
                 cmp.a.off = 1;   // float marker
                 return cmp;
             }(),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {"ZT-IR009"}, false},

        // ---- IR010: division of a value by itself ----
        {"010 self-division",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(5)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(5)),
             I(IROp::IDiv, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {"ZT-IR010"}, false},

        // ---- IR011: a loop whose step can never satisfy its guard ----
        // `while (i < 10) i--;` — the counter walks away from the guard.
        {"011 step-moves-away",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(0)),
             L(1),                                          // header
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(10)),
             I(IROp::BrCC, IROperand::mkReg(1), IROperand::mkReg(2),
               IROperand::lbl(2), "<"),
             I(IROp::Br, IROperand::none(), IROperand::lbl(3)),
             L(2),                                          // body
             I(IROp::Load, IROperand::mkReg(3), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(4), IROperand::mkImm(1)),
             I(IROp::Sub, IROperand::mkReg(5), IROperand::mkReg(3),
               IROperand::mkReg(4)),                        // i -= 1
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(5)),
             I(IROp::Br, IROperand::none(), IROperand::lbl(1)),
             L(3),                                          // end
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {"ZT-IR011"}, false},

        // `while (i != 10) i += 3;` — 0, 3, 6, 9, 12 ... never 10.
        {"011 stride-misses-limit",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(0)),
             L(1),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(10)),
             I(IROp::BrCC, IROperand::mkReg(1), IROperand::mkReg(2),
               IROperand::lbl(2), "!="),
             I(IROp::Br, IROperand::none(), IROperand::lbl(3)),
             L(2),
             I(IROp::Load, IROperand::mkReg(3), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(4), IROperand::mkImm(3)),
             I(IROp::Add, IROperand::mkReg(5), IROperand::mkReg(3),
               IROperand::mkReg(4)),                        // i += 3
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(5)),
             I(IROp::Br, IROperand::none(), IROperand::lbl(1)),
             L(3),
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {"ZT-IR011"}, false},

        // `for i = 0 to 10 step 0` — the counter never moves.
        {"011 step-zero",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(0)),
             L(1),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(10)),
             I(IROp::BrCC, IROperand::mkReg(1), IROperand::mkReg(2),
               IROperand::lbl(2), "<"),
             I(IROp::Br, IROperand::none(), IROperand::lbl(3)),
             L(2),
             I(IROp::Load, IROperand::mkReg(3), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(4), IROperand::mkImm(0)),
             I(IROp::Add, IROperand::mkReg(5), IROperand::mkReg(3),
               IROperand::mkReg(4)),                        // i += 0
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(5)),
             I(IROp::Br, IROperand::none(), IROperand::lbl(1)),
             L(3),
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {"ZT-IR011"}, false},

        // ---- negatives ----
        {"exempt brz-plain-one (while 1)",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(1)),
             I(IROp::BrZ, IROperand::mkReg(0), IROperand::lbl(0)),
             L(0),
             I(IROp::Ret),
         },
         {}, true},

        {"exempt switch dispatch (Cmp -> BrNZ)",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(1)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(1)),
             I(IROp::Cmp, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1), "=="),
             I(IROp::BrNZ, IROperand::mkReg(2), IROperand::lbl(0)),
             L(0),
             I(IROp::Ret),
         },
         {}, true},

        {"exempt brcc one plain side (for-step sign check)",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(2)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(0)),
             I(IROp::BrCC, IROperand::mkReg(0), IROperand::mkReg(1),
               IROperand::lbl(0), ">"),
             L(0),
             I(IROp::Ret),
         },
         {}, true},

        {"exempt for-header meet (loop backedge)",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(0)),
             L(1),                                          // loop header
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(10)),
             I(IROp::BrCC, IROperand::mkReg(1), IROperand::mkReg(2),
               IROperand::lbl(2), "<"),
             I(IROp::Br, IROperand::none(), IROperand::lbl(3)),
             L(2),                                          // body
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(1)),
             I(IROp::Load, IROperand::mkReg(4), IROperand::slot(0)),
             I(IROp::Add, IROperand::mkReg(5), IROperand::mkReg(4),
               IROperand::mkReg(3)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(5)),
             I(IROp::Br, IROperand::none(), IROperand::lbl(1)),
             L(3),                                          // end
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {}, true},

        {"exempt float brcc (NaN-safe)",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(2)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(3)),
             [&] {
                 IRInstr br = I(IROp::BrCC, IROperand::mkReg(0),
                                IROperand::mkReg(1), IROperand::lbl(0), "<");
                 br.a.off = 1;   // float marker
                 return br;
             }(),
             L(0),
             I(IROp::Ret),
         },
         {}, true},

        {"exempt dead code (unreachable div-by-zero)",
         {
             I(IROp::Br, IROperand::none(), IROperand::lbl(0)),
             L(1),                                          // dead
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(7)),
             I(IROp::IDiv, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             L(0),
             I(IROp::Ret),
         },
         {}, true},

        {"exempt unknown divisor",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(9)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(5)),
             I(IROp::IDiv, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {}, true},

        // IR007: `x % 4` may well be 1 — the ranges overlap.
        {"exempt range-overlaps",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(4)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(7)),
             I(IROp::IMod, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Const, IROperand::mkReg(3), IROperand::mkImm(1)),
             I(IROp::Cmp, IROperand::mkReg(4), IROperand::mkReg(2),
               IROperand::mkReg(3), "=="),
             I(IROp::Ret, IROperand::mkReg(4)),
         },
         {}, true},

        // IR008: the comparison result goes through memory first, so the
        // second compare sees a plain loaded value, not a chain.
        {"exempt bool-through-slot",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(3)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(4)),
             I(IROp::Cmp, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1), "<"),
             I(IROp::Store, IROperand::slot(8), IROperand::mkReg(2)),
             I(IROp::Load, IROperand::mkReg(5), IROperand::slot(8)),
             I(IROp::Const, IROperand::mkReg(6), IROperand::mkImm(1)),
             I(IROp::Cmp, IROperand::mkReg(7), IROperand::mkReg(5),
               IROperand::mkReg(6), "=="),
             I(IROp::Ret, IROperand::mkReg(7)),
         },
         {}, true},

        // IR008: `!x` is lowered to `Cmp x, 0`, never a chain.
        {"exempt logical-not",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(3)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(4)),
             I(IROp::Cmp, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1), "<"),
             I(IROp::Cmp, IROperand::mkReg(3), IROperand::mkReg(2),
               IROperand::mkImm(0), "=="),
             I(IROp::Ret, IROperand::mkReg(3)),
         },
         {}, true},

        // IR009: `f != f` is how NaN is tested (as at the AST level).
        {"exempt float nan-test",
         {
             I(IROp::FLoad, IROperand::mkReg(0), IROperand::slot(2)),
             I(IROp::FLoad, IROperand::mkReg(1), IROperand::slot(2)),
             [&] {
                 IRInstr cmp = I(IROp::Cmp, IROperand::mkReg(2),
                                 IROperand::mkReg(0), IROperand::mkReg(1),
                                 "!=");
                 cmp.a.off = 1;
                 return cmp;
             }(),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {}, true},

        // IR010: two different slots, two different values.
        {"exempt distinct-operands",
         {
             I(IROp::Load, IROperand::mkReg(0), IROperand::slot(5)),
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(6)),
             I(IROp::IDiv, IROperand::mkReg(2), IROperand::mkReg(0),
               IROperand::mkReg(1)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {}, true},

        // IR011: a conditional break leaves the loop somewhere the guard
        // does not gate, so the step alone proves nothing.
        {"exempt loop-with-break",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(0)),
             L(1),                                          // header
             I(IROp::Load, IROperand::mkReg(1), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(2), IROperand::mkImm(10)),
             I(IROp::BrCC, IROperand::mkReg(1), IROperand::mkReg(2),
               IROperand::lbl(2), "<"),
             I(IROp::Br, IROperand::none(), IROperand::lbl(3)),
             L(2),                                          // body
             I(IROp::Load, IROperand::mkReg(6), IROperand::slot(9)),
             I(IROp::Const, IROperand::mkReg(7), IROperand::mkImm(0)),
             I(IROp::BrCC, IROperand::mkReg(6), IROperand::mkReg(7),
               IROperand::lbl(3), "!="),                    // break
             I(IROp::Load, IROperand::mkReg(3), IROperand::slot(0)),
             I(IROp::Const, IROperand::mkReg(4), IROperand::mkImm(1)),
             I(IROp::Sub, IROperand::mkReg(5), IROperand::mkReg(3),
               IROperand::mkReg(4)),                        // i -= 1
             I(IROp::Store, IROperand::slot(0), IROperand::mkReg(5)),
             I(IROp::Br, IROperand::none(), IROperand::lbl(1)),
             L(3),                                          // end
             I(IROp::Ret, IROperand::mkReg(1)),
         },
         {}, true},

        {"exempt garbage function",
         {
             I(IROp::Const, IROperand::mkReg(0), IROperand::mkImm(0)),
             I(IROp::Const, IROperand::mkReg(1), IROperand::mkImm(7)),
             I(IROp::IDiv, IROperand::mkReg(2), IROperand::mkReg(1),
               IROperand::mkReg(0)),
             I(IROp::Ret, IROperand::mkReg(2)),
         },
         {}, true, true},
    };
    return v;
}

int failures = 0;

void runCase(const Case& c) {
    IRProgram prog;
    IRFunction f;
    f.name = "fn";
    f.instrs = c.instrs;
    f.garbage = c.garbage;
    prog.functions.push_back(f);

    std::vector<std::string> warns;
    runBugFindIR(prog, warns);
    auto codes = codesOf(warns);

    if (c.expectClean) {
        if (!codes.empty()) {
            std::printf("FAIL %-50s expected clean, got", c.name);
            for (auto& w : warns) std::printf("\n      %s", w.c_str());
            std::printf("\n");
            ++failures;
            return;
        }
        std::printf("ok   %-50s (clean)\n", c.name);
        return;
    }

    for (const auto& want : c.want) {
        bool found = false;
        for (const auto& code : codes)
            if (code == want) { found = true; break; }
        if (!found) {
            std::printf("FAIL %-50s missing %s (got", c.name, want.c_str());
            if (codes.empty())
                std::printf(" no warnings");
            else
                for (auto& code : codes) std::printf(" %s", code.c_str());
            std::printf(")\n");
            ++failures;
            return;
        }
    }

    // The reported line must name the function and an instruction index.
    if (warns.empty() ||
        warns[0].rfind("Warning: IR fn:", 0) != 0) {
        std::printf("FAIL %-50s bad warning format: %s\n", c.name,
                    warns.empty() ? "<none>" : warns[0].c_str());
        ++failures;
        return;
    }
    std::printf("ok   %-50s\n", c.name);
}

}  // namespace

int main() {
    for (const auto& c : cases()) runCase(c);
    std::printf("\nirbugfind: %d case(s), %d failed\n",
                (int)cases().size(), failures);
    return failures ? 1 : 0;
}
