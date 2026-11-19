#include "codegen.h"
#include "spvasm.h"
#include <fstream>
#include <sstream>
#include <cstdint>
#include <vector>
#include <string>

// ============================================================================
// SPIR-V shader builtins (app linux): shader(kind, text) / shader_file(kind, path)
//
//   var vert = shader("vertex", "OpCapability Shader\n...")
//   var frag = shader_file("fragment", "frag.spvasm")
//
// Both return a pointer to a self-describing .rdata record:
//     struct { uint32_t codeSize; uint32_t words[]; }
// where `words` is the assembled binary SPIR-V module. `codeSize` is the byte
// length of the module (dropdown codeSize*4). This is exactly what the WSI
// layer needs for vkCreateShaderModule(pCode, codeSize).
//
// The raw asm text is collected at detect time (before buildLinuxImportData
// finalizes .rdata/.data RVAs), assembled once per unique shader during
// buildLinuxImportData, then each shader()/shader_file() call site just does a
// `lea reg, [rip + moduleRVA]` — the same slotRVA pattern as vk_*/wl_*.
// ============================================================================

// ===== Usage pre-scan: mirrors detectVkUsage so buildLinuxImportData can =====
// ===== reserve the .rdata slots before buildELF patches the slot refs.   =====
void Codegen::detectShaderUsage() {
    if (shaderUsed) return;
    for (auto& func : prog.functions) {
        if (func->isExtern) continue;
        for (auto& stmt : func->body.stmts) detectShaderStmtUsage(stmt.get());
        if (shaderUsed) { shaderUsed = true; return; }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectShaderExprUsage(g->init.get());
        if (shaderUsed) { shaderUsed = true; return; }
    }
}

void Codegen::detectShaderExprUsage(Expr* e) {
    if (!e) return;
    if (auto call = dynamic_cast<CallExpr*>(e)) {
        if (call->name == "shader" || call->name == "shader_file") {
            shaderUsed = true;
            registerShaderCall(call);
        }
        for (auto& arg : call->args) detectShaderExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        detectShaderExprUsage(bin->left.get());
        detectShaderExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(e)) {
        detectShaderExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        detectShaderExprUsage(arr->array.get());
        detectShaderExprUsage(arr->index.get());
    } else if (auto un = dynamic_cast<UnaryExpr*>(e)) {
        detectShaderExprUsage(un->operand.get());
    }
}

void Codegen::detectShaderStmtUsage(Stmt* s) {
    if (!s) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) {
        detectShaderExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(s)) {
        detectShaderExprUsage(exprStmt->expr.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(s)) {
        detectShaderExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        detectShaderExprUsage(ifs->condition.get());
        for (auto& st : ifs->thenBlock.stmts) detectShaderStmtUsage(st.get());
        for (auto& st : ifs->elseBlock.stmts) detectShaderStmtUsage(st.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(s)) {
        detectShaderExprUsage(wh->condition.get());
        for (auto& st : wh->body.stmts) detectShaderStmtUsage(st.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(s)) {
        for (auto& st : loop->body.stmts) detectShaderStmtUsage(st.get());
    } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
        detectShaderExprUsage(fs->start.get());
        detectShaderExprUsage(fs->end.get());
        detectShaderExprUsage(fs->step.get());
        for (auto& st : fs->body.stmts) detectShaderStmtUsage(st.get());
    }
}

// ============================================================================
// registerShaderCall: collect the (kind, text) of a shader()/shader_file() call
// into shaderRecs during the pre-scan. `shader_file` reads the .spvasm file at
// compile time (relative to the current working directory, like `include`).
// ============================================================================
void Codegen::registerShaderCall(CallExpr* call) {
    if (call->args.size() != 2) return;
    auto kindExpr = dynamic_cast<StringExpr*>(call->args[0].get());
    auto textExpr = dynamic_cast<StringExpr*>(call->args[1].get());
    if (!kindExpr || !textExpr) return;
    std::string key = textExpr->value;
    std::string text = textExpr->value;
    if (call->name == "shader_file") {
        std::ifstream file(text);
        if (!file) throw std::runtime_error("shader_file: cannot open '" + text + "'");
        std::stringstream ss;
        ss << file.rdbuf();
        text = ss.str();
    }
    for (auto& rec : shaderRecs)
        if (rec.key == key && rec.kind == kindExpr->value) return;
    shaderRecs.push_back({key, text, kindExpr->value, 0});
}

// ============================================================================
// tryShaderCall: emits `lea reg, [rip + moduleRVA]` for a shader()/shader_file()
// call whose RVA slot was reserved at buildLinuxImportData time.
// ============================================================================
bool Codegen::tryShaderCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    if (name != "shader" && name != "shader_file") return false;
    if (call->args.size() != 2) return false;
    auto kindExpr = dynamic_cast<StringExpr*>(call->args[0].get());
    auto textExpr = dynamic_cast<StringExpr*>(call->args[1].get());
    if (!kindExpr || !textExpr) return false;

    shaderUsed = true;

    // The record for this exact (kind, text) was collected during detect;
    // find it and lea rip-relative to its .rdata slot.
    for (auto& rec : shaderRecs) {
        if (rec.key == textExpr->value) {
            if (rec.rva == 0)
                throw std::runtime_error("shader module RVA not assigned (build order bug)");
            int r = allocReg();
            if (r >= 0) {
                if (r >= 8) emit8(0x4C); else emit8(0x48);
                emit8(0x8D);
                emit8((uint8_t)(0x05 | ((r & 7) << 3)));
                globalFixups.push_back({code.size(), rec.rva});
                emit32(0);
            }
            resultReg = r;
            return true;
        }
    }

    // Shouldn't get here: detectShaderUsage runs before emit. Fall back to an
    // error so a misuse (e.g. runtime-computed text) surfaces loudly.
    throw std::runtime_error("shader text was not registered by the pre-scan (internal error)");
}

// ============================================================================
// emitShaderModules: assembles every collected shader source into binary SPIR-V
// and appends self-describing records to .rdata. Called from
// buildLinuxImportData() after other .rdata content. Record layout:
//     [0] uint32 codeSize   (byte length of the module, multiple of 4)
//     [4] uint32 words[codeSize/4]
// The record RVA is stored back into shaderRecs[i].rva for tryShaderCall.
// ============================================================================
void Codegen::emitShaderModules() {
    for (auto& rec : shaderRecs) {
        if (rec.rva != 0) continue;
        std::vector<uint32_t> words;
        std::string err;
        if (!spv::assemble(rec.text, words, err)) {
            throw std::runtime_error("SPIR-V assembly failed: " + err);
        }
        rec.rva = rdataRVA + (uint32_t)rdata.size();
        uint32_t byteLen = (uint32_t)(words.size() * 4);
        auto push32 = [&](uint32_t v) {
            rdata.push_back((uint8_t)(v & 0xFF));
            rdata.push_back((uint8_t)((v >> 8) & 0xFF));
            rdata.push_back((uint8_t)((v >> 16) & 0xFF));
            rdata.push_back((uint8_t)((v >> 24) & 0xFF));
        };
        push32(byteLen);
        for (uint32_t w : words) push32(w);
        while (rdata.size() % 16 != 0) rdata.push_back(0);
    }
}