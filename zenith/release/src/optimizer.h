#pragma once
#include "ast.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <functional>

struct OptResult {
    std::vector<std::string> warnings;
    int removedFunctions = 0;
    int removedGlobals = 0;
    int removedStatements = 0;
    int strengthReduced = 0;   // mul/div rewrites to cheaper ops
    int propagated = 0;        // const/copy replacements
};

// Optimization levels (CLI flags -0r / -1r / -2r / -3r):
//   None  (-0r): no passes at all; dead code stays in the image.
//   Basic (-1r): unused function/global removal + constant folding +
//                algebraic simplification + local propagation.
//   Max   (-2r): Basic + aggressive size/RAM reduction (tiny-function
//                inlining, dead-store elimination) used by 'app stm32'.
//   Speed (-3r): Max + speed-only transforms that can trade code size for
//                speed (signed division/modulo by constant power of two is
//                rewritten into shifts/and, avoiding idiv / software div).
//                The div/mod rewrite is only applied when allowPow2Div is
//                set: the classic x86 Codegen backend (PE/EFI/BIOS/bare)
//                miscompiles the deep expression trees it produces, so
//                those targets get the rewrite only via the IR pipeline.
enum class OptLevel { None = 0, Basic = 1, Max = 2, Speed = 3 };

class Optimizer {
public:
    OptResult optimize(Program& prog, OptLevel level = OptLevel::Max,
                       bool allowPow2Div = true);

private:
    void findReachable(const std::string& funcName,
                       std::unordered_set<std::string>& reachable,
                       const Program& prog);

    void collectFuncRefsInExpr(Expr* expr, std::unordered_set<std::string>& refs, const Program& prog);
    void collectFuncRefsInStmt(Stmt* stmt, std::unordered_set<std::string>& refs, const Program& prog);
    void collectFuncRefsInBlock(const Block& block, std::unordered_set<std::string>& refs, const Program& prog);

    void collectGlobalRefsInExpr(Expr* expr, std::unordered_set<std::string>& refs, const Program& prog);
    void collectGlobalRefsInStmt(Stmt* stmt, std::unordered_set<std::string>& refs, const Program& prog);
    void collectGlobalRefsInBlock(const Block& block, std::unordered_set<std::string>& refs, const Program& prog);

    bool isUserFunc(const std::string& name, const Program& prog);
    bool isGlobal(const std::string& name, const Program& prog);

    // ---- sizeMode passes (STM32) ----
    void foldConstants(Program& prog, OptResult& result);
    void foldExpr(std::unique_ptr<Expr>& expr, OptResult& result);
    void foldStmt(Stmt* stmt, OptResult& result);
    void foldBlock(Block& block, OptResult& result);

    // ---- speed passes (all backends) ----
    // Algebraic identities + strength reduction (x*2^n -> x<<n, x+0 -> x,
    // !(a<b) -> a>=b, x-x -> 0, ...). Type-guarded so float semantics
    // (NaN / signed division / rounding) are never changed.
    void simplifyExprs(Program& prog, OptResult& result);
    void simplifyExpr(std::unique_ptr<Expr>& expr, OptResult& result);
    void simplifyStmt(Stmt* stmt, OptResult& result);
    void simplifyBlock(Block& block, OptResult& result);
    // Local constant / copy propagation: `var t: int = 5` (or `= x`) replaces
    // later reads of t with the constant / source, killing store+load pairs.
    void propagateLocals(Program& prog, OptResult& result);
    // Speed-level only: signed division/modulo by a constant power of two
    // becomes (x + ((x >> (w-1)) & (2^n-1))) >> n, i.e. shift/add instead of
    // idiv / software division. Requires the target word size to be known.
    void speedStrengthReduce(Program& prog, OptResult& result);
    void speedReduceExpr(std::unique_ptr<Expr>& expr, int wordBits, OptResult& result);
    void speedReduceStmt(Stmt* stmt, int wordBits, OptResult& result);
    void speedReduceBlock(Block& block, int wordBits, OptResult& result);
    bool allowPow2Div_ = true;   // false for the classic x86 Codegen backends
    // Type tracking used by simplifyExprs / propagateLocals to keep float
    // and signed-division semantics intact.
    struct VarKind { TypeKind kind = TypeKind::Void; std::string structName; };
    VarKind kindOfExpr(Expr* expr);
    bool exprDefinitelyInt(Expr* expr) { return kindOfExpr(expr).kind == TypeKind::Int; }
    // name -> declared type of globals; filled per compile run
    std::unordered_map<std::string, VarKind> globalKinds_;
    std::unordered_map<std::string, VarKind> funcRetKinds_;
    std::unordered_map<std::string, TypeKind> fieldKinds_;   // "Struct.field"
    std::unordered_map<std::string, VarKind> localKinds_;    // set per function
    void collectLocalKinds(const FunctionDecl& fn);
    void collectLocalKindsBlock(const Block& block, std::unordered_map<std::string, VarKind>& out);
    // C8: replace call sites of tiny getter-like functions (body = 1-3
    // "return expr") with the body expression (parameter substitution).
    void inlineTinyFunctions(Program& prog, OptResult& result);
    bool tryInlineCall(std::unique_ptr<Expr>& expr,
                       const std::unordered_map<std::string, FunctionDecl*>& tiny,
                       OptResult& result);
    bool substituteTinyBody(std::unique_ptr<Expr>& callSlot, CallExpr* call,
                            FunctionDecl* fn);
    void deadStoreElimination(Program& prog, OptResult& result);
    void collectLocalReads(Stmt* stmt, const std::unordered_set<std::string>& locals,
                           std::unordered_set<std::string>& reads);
    void collectLocalReadsExpr(Expr* expr, const std::unordered_set<std::string>& locals,
                               std::unordered_set<std::string>& reads);
    void collectLocalReadsBlock(const Block& block, const std::unordered_set<std::string>& locals,
                                std::unordered_set<std::string>& reads);
public:
    bool exprMayHaveSideEffects(Expr* expr);
    bool exprIsConstInt(Expr* expr, int64_t& val);

private:
    Expr* foldPureArith(Expr* e);
};
