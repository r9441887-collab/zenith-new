#include "codegen.h"
#include "ast.h"
#include "disasm_blob.h"

// =====================================================================
// Disasm builtins - disasm() over an embedded freestanding x86-64
// disassembler blob (tools/disasm_blob.cpp -> src/disasm_blob.h).
//
// The blob is appended to .text once (emitDisasmBlob) and invoked via
// `call rel32` into its entry (disasm_entry opcode switch). ABI is
// SysV-internal:
//     long long disasm_entry(op=rdi, dst=rsi, cap=rdx, src=rcx,
//                            srcLen=r8, base=r9, syntax=[rsp+8],
//                            flags=[rsp+16])
//   op 1 (mass): decode the whole src range into dst; return 0 if it fit,
//                else the exact byte count required.
//   op 2 (one):  decode a single instruction at src; return its length.
// The two mode globals (g_intel/g_addrPfx) live in the blob's own .data
// (inside RWX .text); entry sets them per call.
//
//   disasm(dst, cap, src, srclen, base)                      -> bytes | 0
//   disasm(dst, cap, src, srclen, base, syntax)              -> 0=Intel 1=AT&T
//   disasm(dst, cap, src, srclen, base, syntax, flags)       -> flags bit0 = "<addr>: "
//   disasm_one(src, srclen, base)                            -> instruction length
// dst is a caller-provided writable buffer (memNew/fileLoad header +16).
// The blob writes NUL-terminated asm text into it and returns the number of
// bytes needed (0 = fit).
// =====================================================================

namespace {
// SysV ABI register indices in this allocator: rdi=7, rsi=6, rdx=2, rcx=1.
// r8/r9 are not allocator regs; we emit REX-prefixed moves to them.
constexpr int kAbiOp = 7, kAbiDst = 6, kAbiCap = 2, kAbiSrc = 1;
}  // namespace

void Codegen::detectDisasmExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name == "disasm" || call->name == "disasm_one") disasmUsed = true;
        for (auto& arg : call->args) detectDisasmExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectDisasmExprUsage(bin->left.get());
        detectDisasmExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectDisasmExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectDisasmExprUsage(arr->array.get());
        detectDisasmExprUsage(arr->index.get());
    }
}

void Codegen::detectDisasmStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectDisasmExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectDisasmExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectDisasmExprUsage(assign->indexExpr.get());
        detectDisasmExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectDisasmExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectDisasmExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectDisasmStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectDisasmStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectDisasmExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectDisasmStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectDisasmStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectDisasmExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectDisasmExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectDisasmStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectDisasmExprUsage(fs->start.get());
        detectDisasmExprUsage(fs->end.get());
        if (fs->step) detectDisasmExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectDisasmStmtUsage(s.get());
    }
}

void Codegen::detectDisasmUsage() {
    if (!disasmUsed) {
        for (auto& func : prog.functions) {
            if (func->isExtern) continue;
            for (auto& stmt : func->body.stmts) detectDisasmStmtUsage(stmt.get());
            if (disasmUsed) break;
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectDisasmExprUsage(g->init.get());
        if (disasmUsed) break;
    }
}

// Appends the whole disassembler blob (code + its .data mode globals) to the
// .text vector and resolves the label that every `call rel32` site
// (tryDisasmCall) jumps through. Must run after function codegen but before
// resolveJmpFixups; internal references are position-relative so the blob can
// sit anywhere in .text. .text is made RWX by disasmUsed (mode globals live
// inside it).
void Codegen::emitDisasmBlob() {
    if (disasmBlobEmitted) return;
    disasmBlobEmitted = true;
    if (disasmEntryLabel < 0) disasmEntryLabel = newLabel();

    size_t blobStart = code.size();
    while (blobStart % 16 != 0) { emit8(0); blobStart++; }
    for (uint8_t b : kDsBlob) emit8(b);

    if ((size_t)((int)blobStart + (int)kDsBlobEntry) >= labelPositions.size())
        labelPositions.resize((size_t)blobStart + kDsBlobEntry + 1, -1);
    labelPositions[disasmEntryLabel] = (int)(blobStart + kDsBlobEntry);
}

// `call rel32` into the blob entry (disasm_entry). rdi=op, rsi=a1, rdx=a2,
// rcx=a3, r8=a4, r9=a5 (SysV) must already be staged. Result returns in rax.
void Codegen::emitDisasmEntryCall() {
    emit8(0xE8);
    jmpFixups.push_back({code.size(), disasmEntryLabel});
    emit32(0);
}

bool Codegen::tryDisasmCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isOne = (name == "disasm_one");
    const bool isMass = (name == "disasm");
    if (!isOne && !isMass) return false;

    // disasm(dst, cap, src, srclen, base[, syntax[, flags]])
    // disasm_one(src, srclen, base)
    const size_t needArgs = isMass ? 5 : 3;
    const size_t maxArgs = isMass ? 7 : 3;
    if (call->args.size() < needArgs || call->args.size() > maxArgs) return false;

    if (disasmEntryLabel < 0) disasmEntryLabel = newLabel();
    disasmUsed = true;

    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // Pin staged ABI regs (rdi/rsi/rdx/rcx are allocator regs 7/6/2/1).
    auto guard = [&](int wantReg) {
        if (wantReg == 7 || wantReg == 6 || wantReg == 2 || wantReg == 1)
            regsUsed = (uint8_t)(regsUsed | (uint8_t)(1 << wantReg));
    };
    // mov r8, <allocReg src>   (REX.W+R+B): 49 89 C0+s*8
    auto emitMovR8 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC0 + src * 8));
    };
    // mov r9, <allocReg src>   (REX.W+R+B): 49 89 C1+s*8  (rm=1, REX.B set)
    auto emitMovR9 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC1 + src * 8));
    };
    // Stage an argument expression into an ABI register. r8/r9 are not
    // allocator regs (emitExpr never touches them), so we feed them last and
    // free the temp immediately.
    auto stageAbi = [&](Expr* e, int abiReg) {
        int r = emitExpr(e);
        if (abiReg == 8) { emitMovR8(r); freeReg(r); return; }
        if (abiReg == 9) { emitMovR9(r); freeReg(r); return; }
        if (r != abiReg) { emitMovReg(abiReg, r); freeReg(r); }
        guard(abiReg);
    };

    // The blob entry reads stack args [rsp+8]=syntax, [rsp+16]=flags from its
    // pre-prologue rsp (SysV: arg7 sits at the caller's call-time rsp, arg8 at
    // rsp+8). So we store the args at the *current* rsp and issue a plain call.
    if (isMass) {
        emitMovRegImm(kAbiOp, 1);                                  // rdi = op(1)
        stageAbi(call->args[0].get(), kAbiDst);                    // dst  -> rsi
        stageAbi(call->args[1].get(), kAbiCap);                    // cap  -> rdx
        stageAbi(call->args[2].get(), kAbiSrc);                    // src  -> rcx
        stageAbi(call->args[3].get(), 8);                          // srclen -> r8
        stageAbi(call->args[4].get(), 9);                          // base -> r9
        // Evaluate syntax and flags via emitExpr (handles variables and literals).
        // arg7 -> [rsp], arg8 -> [rsp+8]
        auto storeStackSlot = [&](Expr* e, int slot) {
            if (!e) return;
            int r = emitExpr(e);
            if (r == 0) { freeReg(0); }
            else { emitMovReg(0, r); freeReg(r); }
            if (slot == 7) {
                emit8(0x48); emit8(0x89); emit8(0x04); emit8(0x24);       // mov [rsp], rax
            } else {
                emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x08);  // mov [rsp+8], rax
            }
        };
        storeStackSlot(call->args.size() >= 6 ? call->args[5].get() : nullptr, 7);  // [rsp]   = syntax
        storeStackSlot(call->args.size() >= 7 ? call->args[6].get() : nullptr, 8);  // [rsp+8] = flags

        emitDisasmEntryCall();
    } else {
        // disasm_one(src, srclen, base): op=2, syntax=0, flags=0, cap=1, dst=scratch
        int tmp = allocReg();
        emitMovRegImm(tmp, 0);
        emit8(0x48); emit8(0x89); emit8((uint8_t)(0x04 + tmp * 8)); emit8(0x24);       // [rsp] = syntax(0)
        emit8(0x48); emit8(0x89); emit8((uint8_t)(0x44 + tmp * 8)); emit8(0x24); emit8(0x08);  // [rsp+8] = flags(0)
        freeReg(tmp);

        emitMovRegImm(kAbiOp, 2);                                  // rdi = op(2)
        emit8(0x48); emit8(0x8D); emit8(0x74); emit8(0x24); emit8(0x00); // lea rsi, [rsp+0] (dst scratch)
        emitMovRegImm(kAbiCap, 1);                                 // rdx = cap(1)
        stageAbi(call->args[0].get(), kAbiSrc);                    // src  -> rcx
        stageAbi(call->args[1].get(), 8);                          // srclen -> r8
        stageAbi(call->args[2].get(), 9);                          // base -> r9

        emitDisasmEntryCall();
    }

    // Reseat the result (rax -> allocator reg) the same way TLS/JS do.
    regsUsed = 0;
    freeReg(1);
    freeReg(2);
    freeReg(3);
    int r = allocReg();
    if (r != 0) { emitMovReg(r, 0); freeReg(0); }
    regsUsed = (uint8_t)(saved & ~(uint8_t)(1 << r));
    reloadRegs();
    regsUsed = (uint8_t)(saved | (uint8_t)(1 << r));
    resultReg = r >= 0 ? r : 0;
    return true;
}