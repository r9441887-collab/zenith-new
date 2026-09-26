#include "irasm_wasm.h"
#include "iralloc.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>

// ====================================================================
// IRAsmWasm implementation
//
// Register machine on wasm locals:
//   - every scalar IR virtual register maps to a typed wasm local
//     (i64 for int/pointer values, f32 for float values); hybrid
//     values (used as both int and float) are spilled to frame slots,
//   - arithmetic and comparisons operate directly on the local
//     registers (3-address form), so there is no stack shuffling,
//   - multi-slot aggregates (structs/arrays) live in a soft-stack
//     frame in linear memory addressed from the SP global (#0),
//   - structured control flow is recovered from the IR labels with a
//     region-stack algorithm (block for forward joins, loop for
//     backward headers) and emitted as wasm block/loop/br.
// ====================================================================

namespace {

constexpr uint8_t WT_I32 = 0x7F;
constexpr uint8_t WT_I64 = 0x7E;
constexpr uint8_t WT_F32 = 0x7D;

// wasm opcodes used below
constexpr uint8_t OP_BLOCK = 0x02, OP_LOOP = 0x03, OP_END = 0x0B;
constexpr uint8_t OP_BR = 0x0C, OP_BR_IF = 0x0D, OP_RETURN = 0x0F, OP_UNREACHABLE = 0x00;
constexpr uint8_t OP_CALL = 0x10;
constexpr uint8_t OP_GET_LOCAL = 0x20, OP_SET_LOCAL = 0x21;
constexpr uint8_t OP_GET_GLOBAL = 0x23, OP_SET_GLOBAL = 0x24;
constexpr uint8_t OP_I32_CONST = 0x41, OP_I64_CONST = 0x42, OP_F32_CONST = 0x43;
constexpr uint8_t OP_I64_EQZ = 0x50;
constexpr uint8_t OP_I64_EQ = 0x51, OP_I64_NE = 0x52, OP_I64_LT_S = 0x53, OP_I64_LT_U = 0x54,
                     OP_I64_GT_S = 0x55, OP_I64_GT_U = 0x56, OP_I64_LE_S = 0x57, OP_I64_LE_U = 0x58,
                     OP_I64_GE_S = 0x59, OP_I64_GE_U = 0x5A;
constexpr uint8_t OP_F32_EQ = 0x5B, OP_F32_NE = 0x5C, OP_F32_LT = 0x5D, OP_F32_GT = 0x5E,
                     OP_F32_LE = 0x5F, OP_F32_GE = 0x60;
constexpr uint8_t OP_I64_ADD = 0x7C, OP_I64_SUB = 0x7D, OP_I64_MUL = 0x7E,
                     OP_I64_DIV_S = 0x7F, OP_I64_DIV_U = 0x80, OP_I64_REM_S = 0x81, OP_I64_REM_U = 0x82,
                     OP_I64_AND = 0x83, OP_I64_OR = 0x84, OP_I64_XOR = 0x85,
                     OP_I64_SHL = 0x86, OP_I64_SHR_U = 0x88, OP_I64_SHR_S = 0x87;
constexpr uint8_t OP_F32_ABS = 0x8B, OP_F32_NEG = 0x8C, OP_F32_ADD = 0x92, OP_F32_SUB = 0x93,
                     OP_F32_MUL = 0x94, OP_F32_DIV = 0x95;
constexpr uint8_t OP_I32_WRAP = 0xA7, OP_I64_EXT_S = 0xA8, OP_I64_EXT_U = 0xA9;
constexpr uint8_t OP_I64_TRUNC_F32 = 0xAC, OP_F32_CONV_I64_S = 0xB4;
constexpr uint8_t OP_I32_ADD = 0x6A, OP_I32_SUB = 0x6B;
constexpr uint8_t OP_I32_LOAD = 0x28, OP_I64_LOAD = 0x29, OP_F32_LOAD = 0x2A;
constexpr uint8_t OP_I32_LOAD8_U = 0x2D, OP_I32_LOAD16_U = 0x2F;
// native i64 loads with implicit sign/zero extension (replaces
// i32.load + i64.extend: one instruction instead of two)
constexpr uint8_t OP_I64_LOAD8_U = 0x31, OP_I64_LOAD16_U = 0x33,
                     OP_I64_LOAD32_S = 0x34, OP_I64_LOAD32_U = 0x35;
constexpr uint8_t OP_I32_STORE = 0x36, OP_I64_STORE = 0x37, OP_F32_STORE = 0x38,
                     OP_I32_STORE8 = 0x3A, OP_I32_STORE16 = 0x3B;
// native narrow i64 stores (no i32.wrap needed)
constexpr uint8_t OP_I64_STORE8 = 0x3C, OP_I64_STORE16 = 0x3D, OP_I64_STORE32 = 0x3E;
constexpr uint8_t OP_MEM_SIZE = 0x3F, OP_MEM_GROW = 0x40;
constexpr uint8_t OP_DROP = 0x1A;
constexpr uint8_t OP_I32_LE_S = 0x4C;
// bulk-memory proposal: 0xFC prefix, sub-op 0x0A = memory.copy, 0x0B = memory.fill
constexpr uint8_t OP_MISC_PREFIX = 0xFC;
constexpr uint8_t SUB_MEM_COPY = 0x0A, SUB_MEM_FILL = 0x0B;

struct Wasm {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void uleb(uint32_t v) {
        do { uint8_t t = v & 0x7F; v >>= 7; if (v) t |= 0x80; b.push_back(t); } while (v);
    }
    void sleb64(int64_t v) {
        bool more = true;
        while (more) {
            uint8_t t = v & 0x7F;
            v >>= 7;
            if ((v == 0 && !(t & 0x40)) || (v == -1 && (t & 0x40))) more = false;
            else t |= 0x80;
            b.push_back(t);
        }
    }
    void u32(uint32_t v) { uleb(v); }
    void name(const std::string& s) { u32((uint32_t)s.size()); b.insert(b.end(), s.begin(), s.end()); }
    void sect(uint8_t id, const std::vector<uint8_t>& body) { u8(id); uleb((uint32_t)body.size()); b.insert(b.end(), body.begin(), body.end()); }
};

struct Sig {
    std::vector<uint8_t> params;
    uint8_t result = 0;   // 0 = void
    std::string key() const {
        std::string k;
        k.push_back((char)params.size());
        for (uint8_t p : params) k.push_back((char)p);
        k.push_back((char)result);
        return k;
    }
};

struct Mod {
    std::vector<Sig> sigs;
    std::unordered_map<std::string, int> sigIdx;
    struct Imp { std::string module, name; int type; };
    std::vector<Imp> imports;
    struct Func { int type; std::string name; std::vector<uint8_t> body; };
    std::vector<Func> funcs;
    struct Glob { uint8_t type; int64_t init; bool mut; };
    std::vector<Glob> globals;
    struct Export { std::string name; uint8_t kind; int index; };
    std::vector<Export> exports;
    struct DataSeg { int off; std::vector<uint8_t> bytes; };
    std::vector<DataSeg> data;
    int memMinPages = 1;

    int typeOf(const Sig& s) {
        auto it = sigIdx.find(s.key());
        if (it != sigIdx.end()) return it->second;
        sigs.push_back(s);
        sigIdx[s.key()] = (int)sigs.size() - 1;
        return (int)sigs.size() - 1;
    }
    int addFunc(const std::string& name, const Sig& s) {
        funcs.push_back({ typeOf(s), name, {} });
        return (int)funcs.size() - 1;
    }
    int addImport(const std::string& module, const std::string& name, const Sig& s) {
        imports.push_back({ module, name, typeOf(s) });
        return (int)imports.size() - 1;
    }

    std::vector<uint8_t> finalize() {
        Wasm w;
        {
            Wasm tw;
            tw.uleb((uint32_t)sigs.size());
            for (auto& s : sigs) {
                tw.u8(0x60);
                tw.uleb((uint32_t)s.params.size());
                for (uint8_t p : s.params) tw.u8(p);
                if (s.result) { tw.uleb(1); tw.u8(s.result); }
                else tw.uleb(0);
            }
            w.sect(1, tw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)imports.size());
            for (auto& im : imports) {
                bw.name(im.module);
                bw.name(im.name);
                bw.u8(0x00);
                bw.uleb((uint32_t)im.type);
            }
            w.sect(2, bw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)funcs.size());
            for (auto& fn : funcs) bw.uleb((uint32_t)fn.type);
            w.sect(3, bw.b);
        }
        {
            Wasm bw;
            bw.uleb(1);
            bw.u8(0x00);
            bw.uleb((uint32_t)memMinPages);
            w.sect(5, bw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)globals.size());
            for (auto& g : globals) {
                bw.u8(g.type);
                bw.u8(g.mut ? 1 : 0);
                if (g.type == WT_I32) { bw.u8(OP_I32_CONST); bw.sleb64(g.init); }
                else { bw.u8(OP_I64_CONST); bw.sleb64(g.init); }
                bw.u8(OP_END);
            }
            w.sect(6, bw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)exports.size());
            for (auto& ex : exports) {
                bw.name(ex.name);
                bw.u8(ex.kind);
                bw.uleb((uint32_t)ex.index);
            }
            w.sect(7, bw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)funcs.size());
            for (auto& fn : funcs) {
                bw.uleb((uint32_t)fn.body.size());
                bw.b.insert(bw.b.end(), fn.body.begin(), fn.body.end());
            }
            w.sect(10, bw.b);
        }
        {
            Wasm bw;
            bw.uleb((uint32_t)data.size());
            for (auto& ds : data) {
                bw.u8(0x00);
                bw.u8(OP_I32_CONST); bw.sleb64(ds.off);
                bw.u8(OP_END);
                bw.uleb((uint32_t)ds.bytes.size());
                bw.b.insert(bw.b.end(), ds.bytes.begin(), ds.bytes.end());
            }
            w.sect(11, bw.b);
        }
        std::vector<uint8_t> out = w.b;
        out.insert(out.begin(), { 0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00 });
        return out;
    }
};

// --------------------------------------------------------------------
// per-function control-flow metadata
// --------------------------------------------------------------------
struct FuncFlow {
    std::unordered_map<int, int> labelPos;      // label id -> instr idx
    std::unordered_map<int, bool> isHeader;     // label id -> loop header?
    std::unordered_map<int, int> lastBackEdge;  // label id -> last (max) branch idx
};

// The wasm load/store memarg carries an alignment hint (log2 of the
// assumed byte alignment). It is only a hint (correctness never depends
// on it), but engines use it to pick wider/faster access paths, so we
// emit the true alignment wherever the address is provably aligned:
// frame slots (SP + 8*v) and global layout offsets.
static int alignBitsAt(int byteOff, int naturalLog2) {
    int a = 0;
    if ((byteOff & 7) == 0) a = 3;
    else if ((byteOff & 3) == 0) a = 2;
    else if ((byteOff & 1) == 0) a = 1;
    return a < naturalLog2 ? a : naturalLog2;
}

// --------------------------------------------------------------------
// per-function emission plan: fuses consecutive zero stores into one
// memory.fill (bulk memory).  The IR zero-initializes arrays with one
// `Store slot(base+k), zero` per slot; a single memory.fill replaces
// the whole run with 3 instructions.
// --------------------------------------------------------------------
struct EmitPlan {
    struct Item {
        bool isFill = false;
        int idx = 0;        // IR instr index (when !isFill)
        int slotBase = 0;   // first slot (when isFill)
        int count = 0;      // slots (when isFill)
    };
    std::vector<Item> items;
};

static EmitPlan buildPlan(IRFunction& fn) {
    EmitPlan p;
    std::vector<int> lastDef((size_t)std::max(1, fn.maxSlot), -1);
    auto flushRun = [&](std::vector<int>& runIdxs, int& runBase, int& runSrc,
                        bool& runActive) {
        if (runActive) {
            if ((int)runIdxs.size() >= 2) {
                EmitPlan::Item f;
                f.isFill = true;
                f.slotBase = runBase;
                f.count = (int)runIdxs.size();
                p.items.push_back(f);
            } else {
                for (int j : runIdxs) {
                    EmitPlan::Item it;
                    it.idx = j;
                    p.items.push_back(it);
                }
            }
            runActive = false;
            runIdxs.clear();
        }
    };
    int runBase = 0, runSrc = -1;
    bool runActive = false;
    std::vector<int> runIdxs;
    for (int i = 0; i < (int)fn.instrs.size(); i++) {
        const IRInstr& in = fn.instrs[i];
        if (in.garbage) continue;
        bool isDef = in.a.kind == IROperand::Reg &&
                     in.op != IROp::BrZ && in.op != IROp::BrNZ &&
                     in.op != IROp::PrintInt && in.op != IROp::PrintFlt &&
                     in.op != IROp::Exit && in.op != IROp::Ret;
        if (isDef) {
            if (in.op == IROp::Const && in.b.kind == IROperand::Imm && in.b.imm == 0)
                lastDef[(size_t)in.a.reg] = i;
            else
                lastDef[(size_t)in.a.reg] = -1;
        }
        bool storeZero = false;
        if (in.op == IROp::Store &&
            in.a.kind == IROperand::Slot &&
            (in.label < 0 || in.label == 0) &&
            in.b.kind == IROperand::Reg &&
            in.b.reg >= 0 && in.b.reg < (int)lastDef.size() &&
            lastDef[(size_t)in.b.reg] >= 0) {
            // the defining instruction must be a Const 0 with no
            // redefinition in between
            const IRInstr& def = fn.instrs[(size_t)lastDef[(size_t)in.b.reg]];
            storeZero = def.op == IROp::Const &&
                        def.b.kind == IROperand::Imm && def.b.imm == 0;
        }
        if (storeZero && runActive && in.b.reg == runSrc && in.a.reg == runBase + (int)runIdxs.size()) {
            runIdxs.push_back(i);
            continue;
        }
        flushRun(runIdxs, runBase, runSrc, runActive);
        if (storeZero) {
            runBase = in.a.reg;
            runSrc = in.b.reg;
            runActive = true;
            runIdxs.push_back(i);
        } else {
            EmitPlan::Item it;
            it.idx = i;
            p.items.push_back(it);
        }
    }
    flushRun(runIdxs, runBase, runSrc, runActive);
    return p;
}

static FuncFlow buildFlow(const IRFunction& fn) {
    FuncFlow f;
    for (int i = 0; i < (int)fn.instrs.size(); i++) {
        const IRInstr& in = fn.instrs[i];
        if (in.garbage) continue;
        if (in.op == IROp::Label) f.labelPos[in.a.label] = i;
    }
    for (int i = 0; i < (int)fn.instrs.size(); i++) {
        const IRInstr& in = fn.instrs[i];
        if (in.garbage) continue;
        int t = -1;
        if (in.op == IROp::Br) t = in.b.label;
        else if (in.op == IROp::BrZ || in.op == IROp::BrNZ) t = in.b.label;
        else if (in.op == IROp::BrCC) t = in.c.label;
        if (t < 0) continue;
        auto it = f.labelPos.find(t);
        if (it == f.labelPos.end()) continue;
        if (it->second < i) f.isHeader[t] = true;   // backward branch -> loop header
        auto& lb = f.lastBackEdge[t];
        if (i > lb) lb = i;
    }
    return f;
}

// --------------------------------------------------------------------
// function emitter
// --------------------------------------------------------------------
enum RegKind { REG_NONE, REG_I64, REG_F32, REG_SLOT };

struct Region {
    bool isLoop;
    int label;
};

struct FuncEm {
    Mod& mod;
    IRFunction& fn;
    std::vector<iralloc::VAlloc> types;
    std::vector<RegKind> kind;
    std::vector<int> local;
    Wasm code;
    int nparams;
    int newlineOff;
    int printStrImport;
    const std::unordered_map<std::string, int>& fns;
    const std::unordered_map<std::string, int>& imports;
    const FuncFlow& flow;
    const std::vector<int>& strOff;
    std::unordered_map<std::string, int>& globalAddr;
    const std::unordered_map<std::string, int>& globalAlign;
    EmitPlan plan;
    int scratch64 = -1, scratchF32 = -1;
    std::vector<int> pendingArgs;
    std::vector<bool> pendingArgF;
    std::vector<Region> regions;
    int frameBytes;
    const std::vector<bool>& paramFloat;
    std::vector<char> paramNeeded;   // param slot referenced by the body?
    std::unordered_map<int, int> pOpen, pClose, effOpen;
    std::vector<int> closeOrder;
    bool hasResult = false;
    bool resultIsFloat = false;
    const std::vector<std::string>* poolStrings = nullptr;

    FuncEm(Mod& m, IRFunction& f, int nlOff, int psi,
           const std::unordered_map<std::string, int>& fnmap,
           const std::unordered_map<std::string, int>& imp,
           const FuncFlow& fl, const std::vector<int>& soff,
           std::unordered_map<std::string, int>& gaddr,
           const std::unordered_map<std::string, int>& galign,
           const EmitPlan& pl,
           const std::vector<bool>& pf,
           const std::vector<std::string>* poolStrs)
        : mod(m), fn(f), newlineOff(nlOff), printStrImport(psi),
          fns(fnmap), imports(imp), flow(fl), strOff(soff), globalAddr(gaddr),
          globalAlign(galign), plan(pl),
          paramFloat(pf), poolStrings(poolStrs) {
        types.assign((size_t)f.maxSlot, iralloc::VAlloc());
        for (int i = 0; i < (int)f.instrs.size(); i++)
            if (!f.instrs[i].garbage) iralloc::markInstr(f.instrs[i], i, types.data());
        kind.assign((size_t)f.maxSlot, REG_NONE);
        local.assign((size_t)f.maxSlot, -1);
        nparams = f.nparams;
        frameBytes = 8 * f.maxSlot;
        // A param slot that the body never touches (neither loaded, stored,
        // nor address-taken) does not need the prologue copy from the wasm
        // local into the frame slot. iropt DCE already drops the dead IR
        // stores; this drops the matching backend prologue stores.
        paramNeeded.assign((size_t)nparams, 0);
        for (auto& in : f.instrs) {
            if (in.garbage) continue;
            switch (in.op) {
            case IROp::Load: case IROp::Load32: case IROp::FLoad:
            case IROp::LeaSlot:
                if (in.b.kind == IROperand::Slot && in.b.reg >= 0 && in.b.reg < nparams)
                    paramNeeded[in.b.reg] = 1;
                break;
            case IROp::Store: case IROp::Store32: case IROp::FStore:
                if (in.a.kind == IROperand::Slot && in.a.reg >= 0 && in.a.reg < nparams)
                    paramNeeded[in.a.reg] = 1;
                break;
            default: break;
            }
        }
        for (auto& in : f.instrs)
            if (!in.garbage && in.op == IROp::Ret && in.a.kind == IROperand::Reg) {
                hasResult = true;
                resultIsFloat = in.a.off != 0;
            }
        computeRegions();
    }

    // ---- region open/close planning ----
    // A structured-wasm block must open before any branch to its label and
    // close at the label.  IRGen emits labels in a linear order that is not
    // always LIFO-compatible with the branch positions (e.g. if/else:
    //   BrCC -> then; Br -> else; Label then; ...; Br -> join; Label else; Label join)
    // so a join block whose label comes after the else label must open BEFORE
    // the else block (its close is later).  effOpen[L] is the earliest IR
    // position at which block L may need to be open; when emitting a forward
    // branch we open every due outer region first (LIFO order).
    void computeRegions() {
        for (int i = 0; i < (int)fn.instrs.size(); i++) {
            auto& in = fn.instrs[i];
            if (in.garbage) continue;
            switch (in.op) {
            case IROp::Label:
                pClose[in.a.label] = i;
                break;
            case IROp::Br:
            case IROp::BrZ:
            case IROp::BrNZ:
                if (in.b.label >= 0) {
                    auto it = pOpen.find(in.b.label);
                    if (it == pOpen.end() || i < it->second) pOpen[in.b.label] = i;
                }
                break;
            case IROp::BrCC:
                if (in.c.label >= 0) {
                    auto it = pOpen.find(in.c.label);
                    if (it == pOpen.end() || i < it->second) pOpen[in.c.label] = i;
                }
                break;
            default:
                break;
            }
        }
        std::vector<int> labels;
        for (auto& kv : pClose) labels.push_back(kv.first);
        std::sort(labels.begin(), labels.end(),
                  [&](int a, int b) { return pClose[a] < pClose[b]; });
        for (int L : labels) {
            int e = pOpen.count(L) ? pOpen[L] : INT_MAX;
            for (int S : labels) {
                if (S == L) break;
                if (pOpen.count(S) && pOpen[S] < pClose[L] && effOpen[S] < e)
                    e = effOpen[S];
            }
            effOpen[L] = e;
        }
        closeOrder = labels;
        std::reverse(closeOrder.begin(), closeOrder.end());   // descending pClose
    }

    bool isRegionOpen(int label) {
        for (auto& r : regions)
            if (r.label == label) return true;
        return false;
    }

    std::string regionStackStr() {
        std::string s;
        for (auto& r : regions) {
            if (!s.empty()) s += ",";
            s += (r.isLoop ? "L" : "B") + std::to_string(r.label);
        }
        return s;
    }

    // locals: params 0..nparams-1, then i64 locals, then f32 locals
    // (the locals-section header declares in that same order)
    void assignRegs() {
        for (int v = 0; v < nparams; v++) {
            kind[v] = REG_I64;   // hybrid params travel as i64
            local[v] = v;
        }
        for (int v = 0; v < (int)types.size(); v++) {
            if (v < nparams) continue;
            if (types[v].floatUsed && types[v].intUsed) { kind[v] = REG_SLOT; continue; }
            if (!types[v].floatUsed && !types[v].intUsed) continue;
            kind[v] = types[v].floatUsed ? REG_F32 : REG_I64;
        }
        int next = nparams;
        bool hasSlot = false;
        for (int v = 0; v < (int)kind.size(); v++)
            if (kind[v] == REG_SLOT) { hasSlot = true; break; }
        for (int v = 0; v < (int)kind.size(); v++)
            if (v >= nparams && kind[v] == REG_I64) local[v] = next++;
        if (hasSlot) scratch64 = next++;
        for (int v = 0; v < (int)kind.size(); v++)
            if (v >= nparams && kind[v] == REG_F32) local[v] = next++;
        if (hasSlot) scratchF32 = next++;
    }

    std::vector<uint8_t> localsHeader() {
        int n64 = 0, nf = 0;
        for (int v = nparams; v < (int)kind.size(); v++) {
            if (kind[v] == REG_I64) n64++;
            else if (kind[v] == REG_F32) nf++;
        }
        if (scratch64 >= 0) n64++;
        if (scratchF32 >= 0) nf++;
        Wasm h;
        int groups = 0;
        if (n64 > 0) groups++;
        if (nf > 0) groups++;
        h.uleb((uint32_t)groups);
        if (n64 > 0) { h.uleb((uint32_t)n64); h.u8(WT_I64); }
        if (nf > 0) { h.uleb((uint32_t)nf); h.u8(WT_F32); }
        return h.b;
    }

    // ---- value emission helpers ----
    void getLocal(int idx) { code.u8(OP_GET_LOCAL); code.uleb((uint32_t)idx); }
    void setLocal(int idx) { code.u8(OP_SET_LOCAL); code.uleb((uint32_t)idx); }
    void constI64(int64_t v) { code.u8(OP_I64_CONST); code.sleb64(v); }
    void constI32(int32_t v) { code.u8(OP_I32_CONST); code.sleb64(v); }
    void callI(int idx) { code.u8(OP_CALL); code.uleb((uint32_t)idx); }
    void pushSP() { code.u8(OP_GET_GLOBAL); code.uleb(0); }

    void loadI64(int v) {
        if (kind[v] == REG_I64) getLocal(local[v]);
        else if (kind[v] == REG_SLOT) { addrOfSlot(v); code.u8(OP_I64_LOAD); code.uleb(3); code.uleb(0); }
        else if (kind[v] == REG_F32) { getLocal(local[v]); code.u8(OP_I64_TRUNC_F32); }
        else throw std::runtime_error("wasm: loadI64 of unused reg");
    }
    void loadF32(int v) {
        if (kind[v] == REG_F32) getLocal(local[v]);
        else if (kind[v] == REG_SLOT) { addrOfSlot(v); code.u8(OP_F32_LOAD); code.uleb(2); code.uleb(0); }
        else if (kind[v] == REG_I64) { getLocal(local[v]); code.u8(OP_F32_CONV_I64_S); }
        else throw std::runtime_error("wasm: loadF32 of unused reg");
    }
    void storeI64(int v) {
        if (kind[v] == REG_I64) setLocal(local[v]);
        else if (kind[v] == REG_SLOT) {
            // stack: [value] -> [addr, value]
            code.u8(OP_SET_LOCAL); code.uleb((uint32_t)scratch64);
            addrOfSlot(v);
            code.u8(OP_GET_LOCAL); code.uleb((uint32_t)scratch64);
            code.u8(OP_I64_STORE); code.uleb(3); code.uleb(0);
        }
        else if (kind[v] == REG_F32) { code.u8(OP_I64_TRUNC_F32); setLocal(local[v]); }
        else throw std::runtime_error("wasm: storeI64 of unused reg");
    }
    void storeF32(int v) {
        if (kind[v] == REG_F32) setLocal(local[v]);
        else if (kind[v] == REG_SLOT) {
            // stack: [value] -> [addr, value]
            code.u8(OP_SET_LOCAL); code.uleb((uint32_t)scratchF32);
            addrOfSlot(v);
            code.u8(OP_GET_LOCAL); code.uleb((uint32_t)scratchF32);
            code.u8(OP_F32_STORE); code.uleb(2); code.uleb(0);
        }
        else if (kind[v] == REG_I64) { code.u8(OP_F32_CONV_I64_S); setLocal(local[v]); }
        else throw std::runtime_error("wasm: storeF32 of unused reg");
    }
    void addrOfSlot(int v) { pushSP(); constI32((int32_t)(v * 8)); code.u8(OP_I32_ADD); }
    void addrOfSlotOff(int slot, int off) {
        pushSP(); constI32((int32_t)(slot * 8 + off)); code.u8(OP_I32_ADD);
    }
    // memarg: alignment hint for a frame-slot access (slot base is 8-aligned)
    void memargSlot(int off, int natLog2) {
        code.uleb((uint32_t)alignBitsAt(off, natLog2));
        code.uleb(0);
    }
    // memarg: alignment hint for a global access (layout-dependent)
    void memargGlobal(const std::string& name, int off, int natLog2) {
        int a = 0;
        auto it = globalAlign.find(name);
        if (it != globalAlign.end()) a = it->second;
        int o = alignBitsAt(off, 3);
        if (o < a) a = o;
        if (a > natLog2) a = natLog2;
        code.uleb((uint32_t)a);
        code.uleb(0);
    }
    void addrOfPtr(int base, int off) {
        loadI64(base);
        code.u8(OP_I32_WRAP);
        if (off) { constI32(off); code.u8(OP_I32_ADD); }
    }
    void addrOfGlobal(const std::string& name, int off) {
        auto it = globalAddr.find(name);
        if (it == globalAddr.end()) throw std::runtime_error("wasm: unknown global " + name);
        constI32((int32_t)(it->second + off));
    }
    void loadOperandI64(const IROperand& o) {
        if (o.kind == IROperand::Reg) loadI64(o.reg);
        else if (o.kind == IROperand::Imm) constI64(o.imm);
        else throw std::runtime_error("wasm: bad operand in i64 op");
    }
    void loadOperandF32(const IROperand& o) {
        if (o.kind == IROperand::Reg) loadF32(o.reg);
        else throw std::runtime_error("wasm: bad operand in f32 op");
    }

    void emitBinary(uint8_t opcode, int dst, const IROperand& a, const IROperand& b) {
        loadOperandI64(a);
        loadOperandI64(b);
        code.u8(opcode);
        storeI64(dst);
    }
    void emitFBinary(uint8_t opcode, int dst, const IROperand& a, const IROperand& b) {
        loadOperandF32(a);
        loadOperandF32(b);
        code.u8(opcode);
        storeF32(dst);
    }

    // ---- structured control flow ----
    void openRegion(bool isLoop, int label) {
        regions.push_back({ isLoop, label });
        code.u8(isLoop ? OP_LOOP : OP_BLOCK);
        code.u8(0x40);
        if (getenv("ZT_WASM_TRACE")) printf("    open %s lbl=%d stack=[%s]\n",
            isLoop ? "loop" : "block", label, regionStackStr().c_str());
    }
    void brTo(int depth) { code.u8(OP_BR); code.uleb((uint32_t)depth); }
    void brIfTo(int depth) { code.u8(OP_BR_IF); code.uleb((uint32_t)depth); }

    // open regions so a branch to `target` is valid at this position and
    // return the br depth to use.  The caller pushes the branch condition
    // (if any) AFTER this, so it lands inside the innermost opened block.
    int prepareBranch(int target, int curPos) {
        bool backward = flow.isHeader.count(target) && flow.isHeader.at(target);
        if (backward) {
            for (int k = (int)regions.size() - 1; k >= 0; k--) {
                if (regions[k].isLoop && regions[k].label == target) return (int)regions.size() - 1 - k;
            }
            throw std::runtime_error("wasm: backward branch to closed loop");
        }
        // open outer regions (closing later) that are due at this position
        // before the target's block, so block nesting stays LIFO-valid.
        // effOpen[L] marks the earliest position at which label L's block may
        // be required (e.g. an else-block that must wrap code emitted before
        // its own label).  But while a loop is open, labels whose blocks lie
        // beyond the loop's exit label belong to a later loop: opening them
        // here would bury the current loop and it could never close at its
        // exit.  The boundary is the first label position past the innermost
        // open loop's final back edge (that label IS the loop's exit and its
        // block still opens here, outermost of the loop's body blocks).
        int loopCut = INT_MAX;
        int loopDepth = -1;   // depth of innermost open loop (-1 if none)
        for (int k = (int)regions.size() - 1; k >= 0; k--) {
            if (regions[k].isLoop) {
                loopDepth = (int)regions.size() - 1 - k;
                auto it = flow.lastBackEdge.find(regions[k].label);
                if (it != flow.lastBackEdge.end()) {
                    int back = it->second;
                    for (auto& kv : pClose) {
                        if (kv.second > back && kv.second < loopCut) loopCut = kv.second;
                    }
                }
                break;
            }
        }
        for (int L : closeOrder) {
            if (L == target) continue;
            if (!pClose.count(L) || pClose[L] <= pClose[target]) continue;
            if (loopCut != INT_MAX && pClose[L] > loopCut) continue;
            auto eit = effOpen.find(L);
            if (eit == effOpen.end() || eit->second > curPos) continue;
            if (isRegionOpen(L)) continue;
            openRegion(false, L);
        }
        if (!isRegionOpen(target)) openRegion(false, target);
        for (int k = (int)regions.size() - 1; k >= 0; k--) {
            if (!regions[k].isLoop && regions[k].label == target) {
                int tDepth = (int)regions.size() - 1 - k;
                // A forward branch whose target block is an ancestor of the
                // innermost open loop is a break: it must exit that loop (the
                // target label's block was eagerly opened outside the loop).
                if (loopDepth >= 0 && tDepth > loopDepth) return loopDepth;
                return tDepth;
            }
        }
        throw std::runtime_error("wasm: forward branch to missing region");
    }

    void emitLabel(int label, int curPos) {
        if (getenv("ZT_WASM_TRACE")) printf("  [%d] Label %d stack=[%s]\n", curPos, label, regionStackStr().c_str());
        // loop header: eager blocks opened for labels inside the loop body
        // (their label positions lie between the header and the final back
        // edge) can never close while the loop is on top of the stack, so
        // close them here; they reopen inside the loop at their first branch
        if (flow.isHeader.count(label) && flow.isHeader.at(label)) {
            auto it = flow.lastBackEdge.find(label);
            int backEnd = it != flow.lastBackEdge.end() ? it->second : curPos;
            while (!regions.empty() && !regions.back().isLoop &&
                   pClose[regions.back().label] <= backEnd) {
                code.u8(OP_END);
                regions.pop_back();
            }
            openRegion(true, label);
            return;
        }
        // close forward-join blocks opened for this label
        while (!regions.empty() && !regions.back().isLoop && regions.back().label == label) {
            code.u8(OP_END);
            regions.pop_back();
        }
        // close loops whose final back edge is behind us
        while (!regions.empty() && regions.back().isLoop) {
            auto it = flow.lastBackEdge.find(regions.back().label);
            if (it == flow.lastBackEdge.end() || it->second < curPos) {
                code.u8(OP_END);
                regions.pop_back();
            } else break;
        }
    }

    void emitEpilogueRestore() {
        pushSP();
        constI32((int32_t)frameBytes);
        code.u8(OP_I32_ADD);
        code.u8(OP_SET_GLOBAL); code.uleb(0);
    }

    // ---- instruction emission ----
    void emitInstr(int idx) {
        const IRInstr& in = fn.instrs[idx];
        if (getenv("ZT_WASM_TRACE")) printf("  [%d] op=%d%s stack=[%s]\n", idx, (int)in.op,
            in.op == IROp::BrZ || in.op == IROp::BrNZ || in.op == IROp::Br || in.op == IROp::BrCC ? " (br)" : "",
            regionStackStr().c_str());
        switch (in.op) {
        case IROp::Nop:
        case IROp::Func:
        case IROp::EndFunc:
            return;

        case IROp::Label:
            emitLabel(in.a.label, idx);
            return;

        case IROp::Const:
            constI64(in.b.imm);
            storeI64(in.a.reg);
            return;

        case IROp::FConst: {
            code.u8(OP_F32_CONST);
            uint32_t bits = (uint32_t)in.b.imm;
            code.b.push_back((uint8_t)(bits & 0xFF));
            code.b.push_back((uint8_t)((bits >> 8) & 0xFF));
            code.b.push_back((uint8_t)((bits >> 16) & 0xFF));
            code.b.push_back((uint8_t)((bits >> 24) & 0xFF));
            storeF32(in.a.reg);
            return;
        }

        case IROp::Str: {
            int64_t off = in.b.strIdx >= 0 && (size_t)in.b.strIdx < strOff.size() ? strOff[in.b.strIdx] : 0;
            constI64(off);
            storeI64(in.a.reg);
            return;
        }

        case IROp::Mov:
            loadI64(in.b.reg);
            storeI64(in.a.reg);
            return;

        case IROp::LeaGlobal:
            addrOfGlobal(in.b.name, 0);
            code.u8(OP_I64_EXT_U);
            storeI64(in.a.reg);
            return;

        case IROp::LeaSlot:
            pushSP();
            constI32((int32_t)(in.b.reg * 8 + in.b.off));
            code.u8(OP_I32_ADD);
            code.u8(OP_I64_EXT_U);
            storeI64(in.a.reg);
            return;

        case IROp::Load:
            addrOfSlotOff(in.b.reg, in.label < 0 ? 0 : in.label);
            code.u8(OP_I64_LOAD); memargSlot(in.label < 0 ? 0 : in.label, 3);
            storeI64(in.a.reg);
            return;
        case IROp::Load32:
            addrOfSlotOff(in.b.reg, in.label < 0 ? 0 : in.label);
            code.u8(OP_I64_LOAD32_S); memargSlot(in.label < 0 ? 0 : in.label, 2);
            storeI64(in.a.reg);
            return;
        case IROp::Store:
            addrOfSlotOff(in.a.reg, in.label < 0 ? 0 : in.label);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE); memargSlot(in.label < 0 ? 0 : in.label, 3);
            return;
        case IROp::Store32:
            addrOfSlotOff(in.a.reg, in.label < 0 ? 0 : in.label);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE32); memargSlot(in.label < 0 ? 0 : in.label, 2);
            return;

        case IROp::GLoad:
            addrOfGlobal(in.b.name, in.label < 0 ? 0 : in.label);
            code.u8(OP_I64_LOAD); memargGlobal(in.b.name, in.label < 0 ? 0 : in.label, 3);
            storeI64(in.a.reg);
            return;
        case IROp::GLoad32:
            addrOfGlobal(in.b.name, in.label < 0 ? 0 : in.label);
            code.u8(OP_I64_LOAD32_S); memargGlobal(in.b.name, in.label < 0 ? 0 : in.label, 2);
            storeI64(in.a.reg);
            return;
        case IROp::GStore:
            addrOfGlobal(in.a.name, in.label < 0 ? 0 : in.label);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE); memargGlobal(in.a.name, in.label < 0 ? 0 : in.label, 3);
            return;
        case IROp::GStore32:
            addrOfGlobal(in.a.name, in.label < 0 ? 0 : in.label);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE32); memargGlobal(in.a.name, in.label < 0 ? 0 : in.label, 2);
            return;

        case IROp::PLoad:
            addrOfPtr(in.b.reg, in.b.off);
            code.u8(OP_I64_LOAD); code.uleb(0); code.uleb(0);
            storeI64(in.a.reg);
            return;
        case IROp::PLoad32:
            addrOfPtr(in.b.reg, in.b.off);
            code.u8(OP_I64_LOAD32_S); code.uleb(0); code.uleb(0);
            storeI64(in.a.reg);
            return;
        case IROp::PLoad32Z:
            addrOfPtr(in.b.reg, in.b.off);
            code.u8(OP_I64_LOAD32_U); code.uleb(0); code.uleb(0);
            storeI64(in.a.reg);
            return;
        case IROp::PLoadW:
            addrOfPtr(in.b.reg, in.b.off);
            code.u8(OP_I64_LOAD16_U); code.uleb(0); code.uleb(0);
            storeI64(in.a.reg);
            return;
        case IROp::PLoadB:
            addrOfPtr(in.b.reg, in.b.off);
            code.u8(OP_I64_LOAD8_U); code.uleb(0); code.uleb(0);
            storeI64(in.a.reg);
            return;
        case IROp::PStore:
            addrOfPtr(in.a.reg, in.a.off);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE); code.uleb(0); code.uleb(0);
            return;
        case IROp::PStore32:
            addrOfPtr(in.a.reg, in.a.off);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE32); code.uleb(0); code.uleb(0);
            return;
        case IROp::PStoreW:
            addrOfPtr(in.a.reg, in.a.off);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE16); code.uleb(0); code.uleb(0);
            return;
        case IROp::PStoreB:
            addrOfPtr(in.a.reg, in.a.off);
            loadI64(in.b.reg);
            code.u8(OP_I64_STORE8); code.uleb(0); code.uleb(0);
            return;
        case IROp::FPStore:
            addrOfPtr(in.a.reg, in.a.off);
            loadF32(in.b.reg);
            code.u8(OP_F32_STORE); code.uleb(2); code.uleb(0);
            return;

        case IROp::FLoad:
            addrOfSlotOff(in.b.reg, in.label < 0 ? 0 : in.label);
            code.u8(OP_F32_LOAD); memargSlot(in.label < 0 ? 0 : in.label, 2);
            storeF32(in.a.reg);
            return;
        case IROp::FStore:
            addrOfSlotOff(in.a.reg, in.label < 0 ? 0 : in.label);
            loadF32(in.b.reg);
            code.u8(OP_F32_STORE); memargSlot(in.label < 0 ? 0 : in.label, 2);
            return;
        case IROp::FGLoad:
            addrOfGlobal(in.b.name, in.label < 0 ? 0 : in.label);
            code.u8(OP_F32_LOAD); memargGlobal(in.b.name, in.label < 0 ? 0 : in.label, 2);
            storeF32(in.a.reg);
            return;
        case IROp::FGStore:
            addrOfGlobal(in.a.name, in.label < 0 ? 0 : in.label);
            loadF32(in.b.reg);
            code.u8(OP_F32_STORE); memargGlobal(in.a.name, in.label < 0 ? 0 : in.label, 2);
            return;

        case IROp::Arg:
            pendingArgs.push_back(in.b.reg);
            pendingArgF.push_back(in.a.off != 0);
            return;

        case IROp::Call:
        case IROp::ICall: {
            static const std::unordered_map<std::string, std::string> remap = {
                { "Sleep", "zt_sleep" }, { "GetProcessHeap", "__z_getheap" },
                { "HeapAlloc", "__z_malloc" }, { "HeapFree", "__z_free" },
                { "rdtsc", "__zt_rdtsc" }, { "halt", "__zt_halt" },
                { "memcpy", "__zt_memcpy" }, { "memset", "__zt_memset" },
            };
            std::string target = in.b.name;
            auto rit = remap.find(in.b.name);
            if (rit != remap.end()) target = rit->second;
            auto fit = fns.find(target);
            if (fit == fns.end()) {
                auto iit = imports.find(target);
                if (iit != imports.end()) fit = iit;
            }
            if (fit == fns.end())
                throw std::runtime_error("wasm: unknown callee " + in.b.name);
            int nargs = (int)in.c.imm;
            for (int k = 0; k < nargs && k < (int)pendingArgs.size(); k++) {
                if (pendingArgF[k]) loadF32(pendingArgs[k]);
                else loadI64(pendingArgs[k]);
            }
            callI(fit->second);
            pendingArgs.clear();
            pendingArgF.clear();
            if (in.a.kind == IROperand::Reg) {
                if (in.a.off) storeF32(in.a.reg);
                else storeI64(in.a.reg);
            }
            return;
        }

        case IROp::PrintStr: {
            if (in.a.kind == IROperand::Reg) {
                loadI64(in.a.reg);
                code.u8(OP_I32_WRAP);
            } else {
                int off = in.a.strIdx >= 0 && (size_t)in.a.strIdx < strOff.size() ? strOff[in.a.strIdx] : newlineOff;
                constI32((int32_t)off);
            }
            if (getenv("ZT_WASM_TRACE")) {
                const char* s = in.a.strIdx >= 0 && poolStrings && (size_t)in.a.strIdx < poolStrings->size()
                    ? poolStrings->at(in.a.strIdx).c_str() : "<r>";
                printf("  [%d] PrintStr \"%s\"\n", idx, s);
            }
            callI(printStrImport);
            return;
        }

        case IROp::PrintInt:
            loadI64(in.a.reg);
            callI(fns.at("zt_print_int"));
            return;
        case IROp::PrintFlt:
            loadF32(in.a.reg);
            callI(fns.at("zt_print_float"));
            return;

        case IROp::Exit:
            loadI64(in.a.reg);
            code.u8(OP_I32_WRAP);
            callI(fns.at("zt_exit"));
            code.u8(OP_UNREACHABLE);
            return;

        case IROp::Ret: {
            pendingArgs.clear();
            pendingArgF.clear();
            if (in.a.kind == IROperand::Reg) {
                if (in.a.off) loadF32(in.a.reg);
                else loadI64(in.a.reg);
            }
            emitEpilogueRestore();
            code.u8(OP_RETURN);
            return;
        }

        case IROp::Add:  emitBinary(OP_I64_ADD, in.a.reg, in.b, in.c); return;
        case IROp::Sub:  emitBinary(OP_I64_SUB, in.a.reg, in.b, in.c); return;
        case IROp::Mul:  emitBinary(OP_I64_MUL, in.a.reg, in.b, in.c); return;
        case IROp::IDiv: emitBinary(OP_I64_DIV_S, in.a.reg, in.b, in.c); return;
        case IROp::UDiv: emitBinary(OP_I64_DIV_U, in.a.reg, in.b, in.c); return;
        case IROp::IMod: emitBinary(OP_I64_REM_S, in.a.reg, in.b, in.c); return;
        case IROp::UMod: emitBinary(OP_I64_REM_U, in.a.reg, in.b, in.c); return;
        case IROp::And:  emitBinary(OP_I64_AND, in.a.reg, in.b, in.c); return;
        case IROp::Or:   emitBinary(OP_I64_OR, in.a.reg, in.b, in.c); return;
        case IROp::Xor:  emitBinary(OP_I64_XOR, in.a.reg, in.b, in.c); return;
        case IROp::Shl:  emitBinary(OP_I64_SHL, in.a.reg, in.b, in.c); return;
        case IROp::Shr:  emitBinary(OP_I64_SHR_U, in.a.reg, in.b, in.c); return;
        case IROp::Sar:  emitBinary(OP_I64_SHR_S, in.a.reg, in.b, in.c); return;

        case IROp::Neg: constI64(0); loadI64(in.b.reg); code.u8(OP_I64_SUB); storeI64(in.a.reg); return;
        case IROp::Not:
            constI64(-1);
            loadI64(in.b.reg);
            code.u8(OP_I64_XOR);
            storeI64(in.a.reg);
            return;

        case IROp::FAdd: emitFBinary(OP_F32_ADD, in.a.reg, in.b, in.c); return;
        case IROp::FSub: emitFBinary(OP_F32_SUB, in.a.reg, in.b, in.c); return;
        case IROp::FMul: emitFBinary(OP_F32_MUL, in.a.reg, in.b, in.c); return;
        case IROp::FDiv: emitFBinary(OP_F32_DIV, in.a.reg, in.b, in.c); return;
        case IROp::FNeg: loadF32(in.b.reg); code.u8(OP_F32_NEG); storeF32(in.a.reg); return;
        case IROp::FMov: loadF32(in.b.reg); storeF32(in.a.reg); return;
        case IROp::I2F: loadI64(in.b.reg); code.u8(OP_F32_CONV_I64_S); storeF32(in.a.reg); return;
        case IROp::F2I: loadF32(in.b.reg); code.u8(OP_I64_TRUNC_F32); storeI64(in.a.reg); return;

        case IROp::Cmp: {
            bool f = in.a.off != 0;
            uint8_t op;
            if (f) {
                loadOperandF32(in.b); loadOperandF32(in.c);
                if (in.cond == "==") op = OP_F32_EQ;
                else if (in.cond == "!=") op = OP_F32_NE;
                else if (in.cond == "<") op = OP_F32_LT;
                else if (in.cond == "<=") op = OP_F32_LE;
                else if (in.cond == ">") op = OP_F32_GT;
                else if (in.cond == ">=") op = OP_F32_GE;
                else throw std::runtime_error("wasm: bad float cond " + in.cond);
            } else {
                loadOperandI64(in.b); loadOperandI64(in.c);
                if (in.cond == "==") op = OP_I64_EQ;
                else if (in.cond == "!=") op = OP_I64_NE;
                else if (in.cond == "<") op = OP_I64_LT_S;
                else if (in.cond == "<=") op = OP_I64_LE_S;
                else if (in.cond == ">") op = OP_I64_GT_S;
                else if (in.cond == ">=") op = OP_I64_GE_S;
                else if (in.cond == "u<") op = OP_I64_LT_U;
                else if (in.cond == "u<=") op = OP_I64_LE_U;
                else if (in.cond == "u>") op = OP_I64_GT_U;
                else if (in.cond == "u>=") op = OP_I64_GE_U;
                else throw std::runtime_error("wasm: bad int cond " + in.cond);
            }
            code.u8(op);
            code.u8(OP_I64_EXT_U);
            storeI64(in.a.reg);
            return;
        }

        case IROp::Br:
            {
                int d = prepareBranch(in.b.label, idx);
                brTo(d);
                if (getenv("ZT_WASM_TRACE")) printf("      br -> L%d depth=%d\n", in.b.label, d);
            }
            return;

        case IROp::BrZ: {
            int d = prepareBranch(in.b.label, idx);
            loadI64(in.a.reg);
            code.u8(OP_I64_EQZ);
            brIfTo(d);
            if (getenv("ZT_WASM_TRACE")) printf("      brz -> L%d depth=%d\n", in.b.label, d);
            return;
        }

        case IROp::BrNZ: {
            int d = prepareBranch(in.b.label, idx);
            loadI64(in.a.reg);
            constI64(0);
            code.u8(OP_I64_NE);            // i64 != 0 -> i32 (br_if needs i32)
            brIfTo(d);
            return;
        }

        case IROp::BrCC: {
            bool f = in.a.off != 0;
            uint8_t op;
            if (f) {
                if (in.cond == "==") op = OP_F32_EQ;
                else if (in.cond == "!=") op = OP_F32_NE;
                else if (in.cond == "<") op = OP_F32_LT;
                else if (in.cond == "<=") op = OP_F32_LE;
                else if (in.cond == ">") op = OP_F32_GT;
                else if (in.cond == ">=") op = OP_F32_GE;
                else throw std::runtime_error("wasm: bad float cond " + in.cond);
            } else {
                if (in.cond == "==") op = OP_I64_EQ;
                else if (in.cond == "!=") op = OP_I64_NE;
                else if (in.cond == "<") op = OP_I64_LT_S;
                else if (in.cond == "<=") op = OP_I64_LE_S;
                else if (in.cond == ">") op = OP_I64_GT_S;
                else if (in.cond == ">=") op = OP_I64_GE_S;
                else if (in.cond == "u<") op = OP_I64_LT_U;
                else if (in.cond == "u<=") op = OP_I64_LE_U;
                else if (in.cond == "u>") op = OP_I64_GT_U;
                else if (in.cond == "u>=") op = OP_I64_GE_U;
                else throw std::runtime_error("wasm: bad int cond " + in.cond);
            }
            int d = prepareBranch(in.c.label, idx);
            if (f) { loadOperandF32(in.a); loadOperandF32(in.b); }
            else { loadOperandI64(in.a); loadOperandI64(in.b); }
            code.u8(op);
            brIfTo(d);
            if (getenv("ZT_WASM_TRACE")) printf("      brcc -> L%d depth=%d cond=%s\n", in.c.label, d, in.cond.c_str());
            return;
        }

        default:
            throw std::runtime_error("wasm: unhandled IR op " + std::to_string((int)in.op));
        }
    }

    void emitMemFill(int slotBase, int count) {
        pushSP();
        constI32((int32_t)(slotBase * 8));
        code.u8(OP_I32_ADD);
        constI32(0);
        constI32((int32_t)(count * 8));
        code.u8(OP_MISC_PREFIX); code.u8(SUB_MEM_FILL); code.u8(0x00);
    }

    void emitBody() {
        // prologue: frame allocation
        pushSP();
        constI32((int32_t)frameBytes);
        code.u8(OP_I32_SUB);
        code.u8(OP_SET_GLOBAL); code.uleb(0);

        // copy incoming params (wasm locals 0..nparams-1) into their frame
        // slots: the IR reads params through slots, never through locals
        for (int v = 0; v < nparams; v++) {
            if (!paramNeeded[v]) continue;   // slot never touched by the body
            addrOfSlot(v);
            getLocal(v);
            if (v < (int)paramFloat.size() && paramFloat[v]) {
                code.u8(OP_F32_STORE); code.uleb(2); code.uleb(0);
            } else {
                code.u8(OP_I64_STORE); code.uleb(3); code.uleb(0);
            }
        }

        for (auto& item : plan.items) {
            if (item.isFill) { emitMemFill(item.slotBase, item.count); continue; }
            emitInstr(item.idx);
        }
        // close remaining regions, restore SP, return, and close the function
        while (!regions.empty()) { code.u8(OP_END); regions.pop_back(); }
        emitEpilogueRestore();
        // fall-off-the-end path: unreachable in IR-emitted functions, but the
        // body must still validate against the function result type
        if (hasResult) {
            if (resultIsFloat) {
                code.u8(OP_F32_CONST);
                code.b.push_back(0); code.b.push_back(0);
                code.b.push_back(0); code.b.push_back(0);
            } else {
                constI64(0);
            }
        }
        code.u8(OP_RETURN);
        code.u8(OP_END);   // the function body itself is terminated by `end`
    }
};

} // namespace

// --------------------------------------------------------------------
// compile
// --------------------------------------------------------------------
bool IRAsmWasm::compile(const std::string& outputPath) {
    Mod mod;

    // built-in env imports (indices 0..6)
    Sig sp1;  sp1.params.push_back(WT_I32);
    Sig ip1;  ip1.params.push_back(WT_I64);
    Sig fp1;  fp1.params.push_back(WT_F32);
    Sig ex1;  ex1.params.push_back(WT_I32);
    Sig sl1;  sl1.params.push_back(WT_I64);
    Sig rd0;  rd0.result = WT_I64;
    Sig ht0;
    int zt_print_str = mod.addImport("env", "zt_print_str", sp1);
    mod.addImport("env", "zt_print_int", ip1);
    mod.addImport("env", "zt_print_float", fp1);
    mod.addImport("env", "zt_exit", ex1);
    mod.addImport("env", "zt_sleep", sl1);
    mod.addImport("env", "zt_rdtsc", rd0);
    mod.addImport("env", "zt_halt", ht0);
    std::unordered_map<std::string, int> imports;
    imports["zt_print_str"] = 0;
    imports["zt_print_int"] = 1;
    imports["zt_print_float"] = 2;
    imports["zt_exit"] = 3;
    imports["zt_sleep"] = 4;
    imports["zt_rdtsc"] = 5;
    imports["zt_halt"] = 6;
    // function table mirrors imports + defined functions so the emitter can
    // resolve every callee through one map
    std::unordered_map<std::string, int> fns;
    fns["zt_print_str"] = 0;
    fns["zt_print_int"] = 1;
    fns["zt_print_float"] = 2;
    fns["zt_exit"] = 3;
    fns["zt_sleep"] = 4;
    fns["zt_rdtsc"] = 5;
    fns["zt_halt"] = 6;

    // ---- memory layout ----
    std::vector<uint8_t> pool;
    std::vector<int> poolOff;
    for (auto& s : ir_.strings) {
        poolOff.push_back((int)pool.size());
        pool.insert(pool.end(), s.begin(), s.end());
        pool.push_back(0);
    }
    int newlineOff = (int)pool.size();
    pool.push_back('\n'); pool.push_back(0);
    int poolEnd = (int)pool.size();

    auto align8 = [](int x) { return (x + 7) & ~7; };
    int globalOff = align8(poolEnd);
    std::unordered_map<std::string, int> globalAddr;
    std::unordered_map<std::string, int> globalAlign;
    for (auto& g : ir_.globals) {
        if (!g.used) continue;
        globalAddr[g.name] = globalOff;
        int a = 0;
        if ((globalOff & 7) == 0) a = 3;
        else if ((globalOff & 3) == 0) a = 2;
        else if ((globalOff & 1) == 0) a = 1;
        globalAlign[g.name] = a;
        globalOff += g.size >= 8 ? 8 : 4;
    }
    int heapStart = align8(globalOff);
    int stackTop = heapStart + 0x80000;
    int memBytes = stackTop + 0x10000;
    mod.memMinPages = (memBytes + 65535) / 65536;

    // ---- globals: SP (0), heap (1) ----
    mod.globals.push_back({ WT_I32, stackTop, true });
    mod.globals.push_back({ WT_I32, heapStart, true });

    // ---- data: string pool, then global inits ----
    mod.data.push_back({ 0, pool });
    for (auto& g : ir_.globals) {
        if (!g.used) continue;
        int addr = globalAddr[g.name];
        std::vector<uint8_t> bytes;
        if (g.isString) {
            int64_t ptr = 0;
            for (size_t k = 0; k < ir_.strings.size(); k++)
                if (ir_.strings[k] == g.strValue) { ptr = poolOff[k]; break; }
            bytes.resize(8);
            std::memcpy(bytes.data(), &ptr, 8);
        } else if (g.isFloat) {
            bytes.resize(4);
            float f = (float)g.floatValue;
            std::memcpy(bytes.data(), &f, 4);
        } else {
            bytes.resize(8);
            int64_t v = g.intValue;
            std::memcpy(bytes.data(), &v, 8);
        }
        mod.data.push_back({ addr, bytes });
    }

    // ---- internal helpers ----
    Sig m3; m3.params.assign(3, WT_I64); m3.result = WT_I64;
    Sig v3; v3.params.assign(3, WT_I64);
    int mallocFunc = mod.addFunc("__z_malloc", m3);
    int freeFunc   = mod.addFunc("__z_free", v3);
    int heapFunc   = mod.addFunc("__z_getheap", rd0);
    int rdtscFunc  = mod.addFunc("__zt_rdtsc", rd0);
    int haltFunc   = mod.addFunc("__zt_halt", ht0);
    int memcpyFunc = mod.addFunc("__zt_memcpy", v3);
    int memsetFunc = mod.addFunc("__zt_memset", v3);
    fns["__z_malloc"] = mallocFunc;
    fns["__z_free"] = freeFunc;
    fns["__z_getheap"] = heapFunc;
    fns["__zt_rdtsc"] = rdtscFunc;
    fns["__zt_halt"] = haltFunc;
    fns["__zt_memcpy"] = memcpyFunc;
    fns["__zt_memset"] = memsetFunc;

    // ---- user function signatures (inferred from call sites) ----
    struct UFn { int idx; int nparams; };
    std::unordered_map<std::string, UFn> ufns;
    for (auto& f : ir_.functions) {
        if (f.garbage || f.isExtern) continue;
        Sig s;
        bool saw = false;
        for (auto& f2 : ir_.functions) {
            if (f2.garbage) continue;
            std::vector<bool> pending;
            for (auto& in : f2.instrs) {
                if (in.garbage) continue;
                if (in.op == IROp::Arg) pending.push_back(in.a.off != 0);
                else if (in.op == IROp::Call && in.b.name == f.name) {
                    if (!saw) {
                        int n = (int)in.c.imm;
                        for (int k = 0; k < n && k < (int)pending.size(); k++)
                            s.params.push_back(pending[k] ? WT_F32 : WT_I64);
                        saw = true;
                    }
                    pending.clear();
                } else if (in.op == IROp::Call || in.op == IROp::ICall) pending.clear();
            }
        }
        if (!saw) s.params.assign((size_t)f.nparams, WT_I64);
        for (auto& in : f.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::Ret && in.a.kind == IROperand::Reg)
                s.result = in.a.off ? WT_F32 : WT_I64;
        }
        int idx = mod.addFunc(f.name, s);
        ufns[f.name] = { idx, f.nparams };
        fns[f.name] = (int)mod.imports.size() + idx;   // call/export use global space
    }

    // ---- extern imports inferred from use sites ----
    {
        static const std::unordered_map<std::string, std::string> remap = {
            { "Sleep", "zt_sleep" }, { "GetProcessHeap", "__z_getheap" },
            { "HeapAlloc", "__z_malloc" }, { "HeapFree", "__z_free" },
            { "rdtsc", "__zt_rdtsc" }, { "halt", "__zt_halt" },
            { "memcpy", "__zt_memcpy" }, { "memset", "__zt_memset" },
        };
        for (auto& f2 : ir_.functions) {
            if (f2.garbage) continue;
            std::vector<bool> pending;
            for (auto& in : f2.instrs) {
                if (in.garbage) continue;
                if (in.op == IROp::Arg) pending.push_back(in.a.off != 0);
                else if (in.op == IROp::ICall) {
                    std::string nm = in.b.name;
                    if (!remap.count(nm) && !fns.count(nm)) {
                        Sig s;
                        int n = (int)in.c.imm;
                        for (int k = 0; k < n && k < (int)pending.size(); k++)
                            s.params.push_back(pending[k] ? WT_F32 : WT_I64);
                        if (in.a.kind == IROperand::Reg) s.result = in.a.off ? WT_F32 : WT_I64;
                        int idx = mod.addImport("env", nm, s);
                        imports[nm] = idx;
                        fns[nm] = idx;
                    }
                    pending.clear();
                } else if (in.op == IROp::Call) pending.clear();
            }
        }
    }

    // ---- helper bodies ----
    {
        // __z_getheap: global 1 as i64
        Wasm c;
        c.u8(OP_GET_GLOBAL); c.uleb(1);
        c.u8(OP_I64_EXT_U);
        c.u8(OP_RETURN);
        c.u8(OP_END);
        std::vector<uint8_t> body{ 0x00 };
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[heapFunc].body = body;
    }
    {
        // __z_malloc(heap, flags, size): bump-allocate from global 1.
        // extra locals: 3,4,5 = i64 (aligned size, old heap, new heap);
        //                6 = i32 (page delta)
        Wasm c;
        c.u8(OP_GET_LOCAL); c.uleb(2);
        c.u8(OP_I64_CONST); c.sleb64(15);
        c.u8(OP_I64_ADD);
        c.u8(OP_I64_CONST); c.sleb64(-16);
        c.u8(OP_I64_AND);
        c.u8(OP_SET_LOCAL); c.uleb(3);               // size = (size+15)&~15
        c.u8(OP_GET_GLOBAL); c.uleb(1);
        c.u8(OP_I64_EXT_U);
        c.u8(OP_SET_LOCAL); c.uleb(4);               // old = heap
        c.u8(OP_GET_LOCAL); c.uleb(4);
        c.u8(OP_GET_LOCAL); c.uleb(3);
        c.u8(OP_I64_ADD);
        c.u8(OP_SET_LOCAL); c.uleb(5);               // new = old + size
        // grow memory if the allocation crosses a page boundary
        c.u8(OP_BLOCK); c.u8(0x40);
        c.u8(OP_GET_LOCAL); c.uleb(5);
        c.u8(OP_I64_CONST); c.sleb64(65535);
        c.u8(OP_I64_ADD);
        c.u8(OP_I64_CONST); c.sleb64(16);
        c.u8(OP_I64_SHR_U);
        c.u8(OP_I32_WRAP);                           // pages needed
        c.u8(OP_MEM_SIZE); c.u8(0x00);
        c.u8(OP_I32_SUB);                            // delta = needed - cur
        c.u8(OP_SET_LOCAL); c.uleb(6);
        c.u8(OP_GET_LOCAL); c.uleb(6);
        c.u8(OP_I32_CONST); c.sleb64(0);
        c.u8(OP_I32_LE_S);
        c.u8(OP_BR_IF); c.uleb(0);                   // delta <= 0 -> skip
        c.u8(OP_MEM_SIZE); c.u8(0x00);
        c.u8(OP_GET_LOCAL); c.uleb(6);
        c.u8(OP_I32_ADD);                            // needed
        c.u8(OP_MEM_GROW); c.u8(0x00);
        c.u8(OP_DROP);                               // drop grow result
        c.u8(OP_END);
        c.u8(OP_GET_LOCAL); c.uleb(4);
        c.u8(OP_RETURN);
        c.u8(OP_END);
        std::vector<uint8_t> body;
        Wasm lh;
        lh.uleb(2);
        lh.uleb(3); lh.u8(WT_I64);
        lh.uleb(1); lh.u8(WT_I32);
        body = lh.b;
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[mallocFunc].body = body;
    }
    {
        // __z_free: no-op
        std::vector<uint8_t> body{ 0x00, OP_RETURN, OP_END };
        mod.funcs[freeFunc].body = body;
    }
    {
        // __zt_rdtsc: call import 5 (env.zt_rdtsc)
        std::vector<uint8_t> body;
        Wasm c;
        c.u8(OP_CALL); c.uleb(5);
        c.u8(OP_RETURN);
        c.u8(OP_END);
        body.push_back(0x00);
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[rdtscFunc].body = body;
    }
    {
        // __zt_halt: call import 6 (env.zt_halt), unreachable  
        std::vector<uint8_t> body;
        Wasm c;
        c.u8(OP_CALL); c.uleb(6);
        c.u8(OP_UNREACHABLE);
        c.u8(OP_END);
        body.push_back(0x00);
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[haltFunc].body = body;
    }
    {
        // __zt_memcpy(dst, src, len): i64 params -> wrap to i32, memory.copy
        std::vector<uint8_t> body{ 0x00 };
        Wasm c;
        for (int k = 0; k < 3; k++) {
            c.u8(OP_GET_LOCAL); c.uleb((uint32_t)k);
            c.u8(OP_I32_WRAP);
        }
        c.u8(OP_MISC_PREFIX); c.u8(SUB_MEM_COPY); c.u8(0x00); c.u8(0x00);
        c.u8(OP_RETURN);
        c.u8(OP_END);
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[memcpyFunc].body = body;
    }
    {
        // __zt_memset(dst, val, len): i64 params -> wrap to i32, memory.fill
        std::vector<uint8_t> body{ 0x00 };
        Wasm c;
        for (int k = 0; k < 3; k++) {
            c.u8(OP_GET_LOCAL); c.uleb((uint32_t)k);
            c.u8(OP_I32_WRAP);
        }
        c.u8(OP_MISC_PREFIX); c.u8(SUB_MEM_FILL); c.u8(0x00);
        c.u8(OP_RETURN);
        c.u8(OP_END);
        body.insert(body.end(), c.b.begin(), c.b.end());
        mod.funcs[memsetFunc].body = body;
    }

    // ---- emit user functions ----
    // float-ness of each parameter, inferred from call sites
    std::unordered_map<std::string, std::vector<bool>> paramF;
    for (auto& f : ir_.functions) {
        if (f.garbage || f.isExtern) continue;
        paramF[f.name].assign((size_t)f.nparams, false);
    }
    for (auto& f2 : ir_.functions) {
        if (f2.garbage) continue;
        std::vector<bool> pending;
        for (auto& in : f2.instrs) {
            if (in.garbage) continue;
            if (in.op == IROp::Arg) pending.push_back(in.a.off != 0);
            else if (in.op == IROp::Call) {
                auto it = paramF.find(in.b.name);
                if (it != paramF.end())
                    for (size_t k = 0; k < pending.size() && k < it->second.size(); k++)
                        if (pending[k]) it->second[k] = true;
                pending.clear();
            } else if (in.op == IROp::ICall) pending.clear();
        }
    }

    int startIdx = -1;
    for (auto& f : ir_.functions) {
        if (f.garbage || f.isExtern) continue;
        FuncFlow flow = buildFlow(f);
        EmitPlan plan = buildPlan(f);
        auto pit = paramF.find(f.name);
        std::vector<bool> pf = pit != paramF.end() ? pit->second : std::vector<bool>((size_t)f.nparams, false);
        FuncEm em(mod, f, newlineOff, zt_print_str, fns, imports, flow, poolOff, globalAddr, globalAlign, plan, pf, &ir_.strings);
        em.assignRegs();
        em.emitBody();
        std::vector<uint8_t> body = em.localsHeader();
        body.insert(body.end(), em.code.b.begin(), em.code.b.end());
        mod.funcs[ufns[f.name].idx].body = body;
        if (f.name == ir_.entryFunc) startIdx = (int)mod.imports.size() + ufns[f.name].idx;
    }

    if (startIdx < 0) {
        std::cerr << "IR wasm: entry function '" << ir_.entryFunc << "' not found" << std::endl;
        return false;
    }
    mod.exports.push_back({ "_start", 0x00, startIdx });
    mod.exports.push_back({ "memory", 0x02, 0 });

    std::vector<uint8_t> out = mod.finalize();
    std::ofstream fout(outputPath, std::ios::binary);
    if (!fout) { std::cerr << "IR wasm: cannot write " << outputPath << std::endl; return false; }
    fout.write((const char*)out.data(), (std::streamsize)out.size());
    return true;
}