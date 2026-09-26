#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <unordered_map>

// ====================================================================
// Zenith assembler-IR.
//
// The compiler pipeline is:
//   AST  ->  IRGen  ->  assembler-IR  ->  IROpt  ->  IRVerify  ->  IRAsm
//                                                                     |
//                                                                   .exe
//
// The IR is an assembly-like three-address intermediate. Virtual
// registers are stack slots in each function's frame (resolved by the
// IRAsm backend), so IR optimizations (dead-function->NOP, constant
// folding, strength reduction, dead-code elimination) can run freely
// without register-pressure concerns.
// ====================================================================

enum class IROp {
    Nop,
    Func,        // a.funcName = name, a.imm = nparams; marks function start
    EndFunc,     // end of function body
    Label,       // a.label = id
    Const,       // a.reg = b.imm (int64)
    FConst,      // a.reg = b.fimm (double, bits in b.imm)
    Str,         // a.reg = pointer to string pool[ b.strIdx ]
    Mov,         // a.reg = b.reg
    LeaGlobal,   // a.reg = address of global b.name
    LeaSlot,     // a.reg = address of frame slot b
    Load,        // a.reg = *(int64*)(frame slot b + b.off)
    Load32,      // a.reg = sext(*(int32*)(frame slot b + b.off))
    Store,       // *(int64*)(frame slot b + b.off) = c.reg
    Store32,     // *(int32*)(frame slot b + b.off) = (int32)c.reg
    GLoad,       // a.reg = *(int64*)(global b.name + b.off)
    GLoad32,     // a.reg = sext(*(int32*)(global b.name + b.off))
    GStore,      // *(int64*)(global b.name + b.off) = c.reg
    GStore32,    // *(int32*)(global b.name + b.off) = (int32)c.reg
    PLoad,       // a.reg = *(int64*)(b.reg + b.off)
    PLoad32,     // a.reg = sext(*(int32*)(b.reg + b.off))
    PLoad32Z,    // a.reg = zext(*(int32*)(b.reg + b.off))
    PLoadW,      // a.reg = zext(*(int16*)(b.reg + b.off))
    PLoadB,      // a.reg = zext(*(int8*)(b.reg + b.off))
    PStore,      // *(int64*)(b.reg + b.off) = c.reg
    PStore32,    // *(int32*)(b.reg + b.off) = (int32)c.reg
    PStoreW,     // *(int16*)(b.reg + b.off) = (int16)c.reg
    PStoreB,     // *(int8*)(b.reg + b.off) = (int8)c.reg
    FPStore,     // *(float*)(b.reg + b.off) = c.reg (float value)
    Arg,         // argument k (a.imm) value is in reg b.reg (followed by Call/ICall); a.off = float
    Add, Sub, Mul, IDiv, UDiv, IMod, UMod, And, Or, Xor, Shl, Shr, Sar,
    Neg, Not,
    FAdd, FSub, FMul, FDiv, FMov, FNeg, I2F, F2I,
    FLoad, FStore, FGLoad, FGStore,   // float load/store (slot/global, b.off)
    Cmp,        // a.reg = (cond  b.reg  c.reg) ? 1 : 0
    Br,         // b.label = target
    BrZ,        // if (a.reg == 0) goto b.label
    BrNZ,       // if (a.reg != 0) goto b.label
    BrCC,       // if (cond  a.reg  b.reg) goto c.label
    Call,       // a.reg = userFunc(b.name)(args in slots c.imm.. )  [c.imm = nargs]
    ICall,      // a.reg = import(b.name, b.dll)(args)               [c.imm = nargs]
    PrintStr,   // print string pool[ b.strIdx ] + newline
    PrintInt,   // print (int64 in a.reg) + newline
    PrintFlt,   // print (float in a.reg) as decimal + newline
    Exit,       // exit(a.reg)
    Ret,        // return (a.reg if used)
    RawAsm      // inline asm: a.strIdx = index into IRProgram::asmBlocks
};

struct IROperand {
    enum Kind { None, Reg, Imm, FImm, Label, Func, Import, Global, StrIdx, Slot } kind = None;
    int reg = 0;                 // Reg / Slot: register / frame slot id
    int64_t imm = 0;             // Imm: integer; FImm: bits of double
    int label = -1;              // Label
    int strIdx = -1;             // StrIdx
    int off = 0;                 // extra displacement for PLoad/PStore
    std::string name;            // Func/Import/Global name
    std::string dll;             // Import DLL

    static IROperand none() { return IROperand(); }
    static IROperand mkReg(int r) { IROperand o; o.kind = Reg; o.reg = r; return o; }
    static IROperand mkImm(int64_t v) { IROperand o; o.kind = Imm; o.imm = v; return o; }
    static IROperand fimm(double v) { IROperand o; o.kind = FImm; o.imm = bitsOf(v); return o; }
    // Single-precision float constant: the low 32 bits of the slot hold the
    // float bits (float slots are read/written with movss).
    static IROperand fimmf(float v) {
        IROperand o; o.kind = FImm;
        uint32_t u; std::memcpy(&u, &v, sizeof(u));
        o.imm = (int64_t)(uint64_t)u;
        return o;
    }
    static IROperand lbl(int l) { IROperand o; o.kind = Label; o.label = l; return o; }
    static IROperand slot(int s) { IROperand o; o.kind = Slot; o.reg = s; return o; }
    static IROperand str(int idx) { IROperand o; o.kind = StrIdx; o.strIdx = idx; return o; }
    static IROperand func(const std::string& n) { IROperand o; o.kind = Func; o.name = n; return o; }
    static IROperand imp(const std::string& n, const std::string& d) { IROperand o; o.kind = Import; o.name = n; o.dll = d; return o; }
    static IROperand glob(const std::string& n) { IROperand o; o.kind = Global; o.name = n; return o; }

    static uint64_t bitsOf(double d) { uint64_t u; static_assert(sizeof(u) == sizeof(d), "bits"); std::memcpy(&u, &d, sizeof(u)); return u; }
    double fval() const { double d; uint64_t u = (uint64_t)imm; std::memcpy(&d, &u, sizeof(d)); return d; }
};

struct IRInstr {
    IROp op = IROp::Nop;
    IROperand a, b, c;
    std::string cond;      // for Cmp / BrCC: "==" "!=" "<" "<=" ">" ">=" "u<" "u<=" "u>" "u>="
    std::string funcName;  // for Func / EndFunc
    int label = -1;        // for Label
    bool garbage = false;  // instruction was replaced by optimizer (NOP)
};

struct IRFunction {
    std::string name;
    std::vector<IRInstr> instrs;
    int nparams = 0;
    bool isExtern = false;
    std::string dllName;
    bool garbage = false;   // confirmed dead -> body replaced with NOP
    bool suspect = false;   // initially suspected dead
    int beforeInstrs = 0;   // stats
    int afterInstrs = 0;
    int beforeRam = 0;      // local slot bytes before opt
    int afterRam = 0;
    int foldedInstrs = 0;   // const-folds performed
    int strengthReduced = 0;
    int dceRemoved = 0;
    int deadBranches = 0;
    int memOpts = 0;        // load-after-store / load CSE / store-store / copy-prop
    int ssaCopies = 0;      // SSA de-SSA edge copies emitted
    int ssaHoisted = 0;     // SSA LICM hoists
    int ssaBranches = 0;    // SSA constant-condition branch folds

    // Contiguous slot runs allocated by IRGen for multi-slot locals
    // (structs, arrays). Slots inside a run are kept together by the
    // optimizer, so member/element offsets stay valid after slot removal.
    struct IRRun { int baseSlot = 0; int count = 1; };
    std::vector<IRRun> runs;
    int maxSlot = 0;                 // highest slot id used (+1)
    std::vector<uint8_t> slotUsed;   // per-slot live flag (size = maxSlot)
};

// One inline-`asm` statement (a sequence of raw assembly instructions).
// Kept verbatim (mnemonic + operand strings) so each target encoder can
// interpret the native syntax for its ISA. `wordSize` is 0 for native,
// otherwise an explicit 16/32/64 hint (x86 targets).
struct IRAsmBlock {
    struct Instr {
        std::string mnemonic;
        std::string op1, op2, op3;
    };
    std::vector<Instr> instrs;
    int32_t wordSize = 0;
};

struct IRGlobal {
    std::string name;
    int size = 8;
    bool isFloat = false;
    bool isString = false;
    int64_t intValue = 0;     // int/bool init (or float bits)
    double floatValue = 0.0;
    std::string strValue;     // string init
    bool used = true;
    bool isStruct = false;
};

struct IRProgram {
    std::vector<IRFunction> functions;
    std::vector<IRGlobal> globals;
    std::vector<std::string> strings;   // string pool (in .rdata)
    std::vector<IRAsmBlock> asmBlocks;  // inline asm statements
    std::string entryFunc = "main";

    // --- stats / report ---
    int suspects = 0;
    int confirmedGarbage = 0;
    int keptAfterCheck = 0;
    int nopReplacedFuncs = 0;
    int foldedInstrs = 0;
    int strengthReduced = 0;
    int dceRemoved = 0;
    int deadBranches = 0;
    int memOpts = 0;
    int ssaCopies = 0;
    int ssaHoisted = 0;
    int ssaBranches = 0;
    int removedGlobals = 0;
    int removedImports = 0;
    int ramSaved = 0;
    int fileSaved = 0;
    int beforeTotalInstrs = 0;
    int afterTotalInstrs = 0;
};

// Convenience helpers used by the optimizer / assembler.
struct IRBuilder {
    std::vector<IRInstr>& out;
    explicit IRBuilder(std::vector<IRInstr>& o) : out(o) {}
    void add(IROp op, IROperand a = IROperand::none(), IROperand b = IROperand::none(),
             IROperand c = IROperand::none(), const std::string& cond = "", int label = -1) {
        IRInstr in; in.op = op; in.a = a; in.b = b; in.c = c; in.cond = cond; in.label = label;
        out.push_back(in);
    }
};
