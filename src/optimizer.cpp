#include "optimizer.h"
#include <algorithm>
#include <functional>
#include <optional>
#include <unordered_map>

// Deep-copy of an expression tree (used by the C8 tiny-function inliner).
static bool sameExpr(const Expr* a, const Expr* b);
static std::unique_ptr<NumberExpr> makeNum(int64_t v);

static std::unique_ptr<Expr> cloneExpr(const Expr* e) {
    if (!e) return nullptr;
    if (auto n = dynamic_cast<const NumberExpr*>(e)) {
        auto c = std::make_unique<NumberExpr>(); c->value = n->value; return c;
    }
    if (auto n = dynamic_cast<const FloatExpr*>(e)) {
        auto c = std::make_unique<FloatExpr>(); c->value = n->value; return c;
    }
    if (auto n = dynamic_cast<const StringExpr*>(e)) {
        auto c = std::make_unique<StringExpr>(); c->value = n->value; return c;
    }
    if (auto n = dynamic_cast<const IdentExpr*>(e)) {
        auto c = std::make_unique<IdentExpr>(); c->name = n->name; return c;
    }
    if (auto n = dynamic_cast<const AddressOfExpr*>(e)) {
        auto c = std::make_unique<AddressOfExpr>(); c->name = n->name; return c;
    }
    if (auto n = dynamic_cast<const UnaryExpr*>(e)) {
        auto c = std::make_unique<UnaryExpr>(); c->op = n->op; c->operand = cloneExpr(n->operand.get()); return c;
    }
    if (auto n = dynamic_cast<const BinaryExpr*>(e)) {
        auto c = std::make_unique<BinaryExpr>(); c->op = n->op;
        c->left = cloneExpr(n->left.get()); c->right = cloneExpr(n->right.get()); return c;
    }
    if (auto n = dynamic_cast<const MemberExpr*>(e)) {
        auto c = std::make_unique<MemberExpr>(); c->member = n->member; c->object = cloneExpr(n->object.get()); return c;
    }
    if (auto n = dynamic_cast<const ArrayAccessExpr*>(e)) {
        auto c = std::make_unique<ArrayAccessExpr>();
        c->array = cloneExpr(n->array.get()); c->index = cloneExpr(n->index.get()); return c;
    }
    if (auto n = dynamic_cast<const DerefExpr*>(e)) {
        auto c = std::make_unique<DerefExpr>(); c->ptr = cloneExpr(n->ptr.get()); return c;
    }
    if (auto n = dynamic_cast<const CallExpr*>(e)) {
        auto c = std::make_unique<CallExpr>(); c->name = n->name; c->receiver = cloneExpr(n->receiver.get());
        for (auto& a : n->args) c->args.push_back(cloneExpr(a.get()));
        return c;
    }
    return nullptr;
}

bool Optimizer::isUserFunc(const std::string& name, const Program& prog) {
    for (auto& f : prog.functions) {
        if (f->name == name && !f->isExtern) return true;
    }
    return false;
}

bool Optimizer::isGlobal(const std::string& name, const Program& prog) {
    for (auto& g : prog.globals) {
        if (g->name == name) return true;
    }
    return false;
}

void Optimizer::collectFuncRefsInExpr(Expr* expr, std::unordered_set<std::string>& refs, const Program& prog) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        refs.insert(call->name);
        // virtual dispatch targets are reachable through the vtable, not a
        // direct reference to call->name
        for (auto& vt : call->vtable) {
            refs.insert(vt.second);
        }
        collectFuncRefsInExpr(call->receiver.get(), refs, prog);
        for (auto& arg : call->args) {
            collectFuncRefsInExpr(arg.get(), refs, prog);
        }
    } else if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        if (isUserFunc(id->name, prog)) {
            refs.insert(id->name);
        }
    } else if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        collectFuncRefsInExpr(bin->left.get(), refs, prog);
        collectFuncRefsInExpr(bin->right.get(), refs, prog);
    } else if (auto unary = dynamic_cast<UnaryExpr*>(expr)) {
        collectFuncRefsInExpr(unary->operand.get(), refs, prog);
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        collectFuncRefsInExpr(memb->object.get(), refs, prog);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        collectFuncRefsInExpr(arr->array.get(), refs, prog);
        collectFuncRefsInExpr(arr->index.get(), refs, prog);
    } else if (auto deref = dynamic_cast<DerefExpr*>(expr)) {
        collectFuncRefsInExpr(deref->ptr.get(), refs, prog);
    } else if (auto addrOf = dynamic_cast<AddressOfExpr*>(expr)) {
        // &var / &func keeps the target alive (its address escapes). This
        // covers both user functions (reachability) and externs (usedExterns)
        // — e.g. a handler registered by address must survive the pass.
        for (auto& f : prog.functions) {
            if (f->name == addrOf->name) {
                refs.insert(addrOf->name);
                break;
            }
        }
    }
}

void Optimizer::collectFuncRefsInStmt(Stmt* stmt, std::unordered_set<std::string>& refs, const Program& prog) {
    if (!stmt) return;
    if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        collectFuncRefsInExpr(varDecl->init.get(), refs, prog);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        collectFuncRefsInExpr(ret->value.get(), refs, prog);
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        collectFuncRefsInExpr(exprStmt->expr.get(), refs, prog);
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        collectFuncRefsInExpr(assign->value.get(), refs, prog);
        collectFuncRefsInExpr(assign->indexExpr.get(), refs, prog);
        if (isUserFunc(assign->name, prog)) {
            refs.insert(assign->name);
        }
    } else if (auto ptrAssign = dynamic_cast<PtrAssignStmt*>(stmt)) {
        collectFuncRefsInExpr(ptrAssign->ptr.get(), refs, prog);
        collectFuncRefsInExpr(ptrAssign->value.get(), refs, prog);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        collectFuncRefsInExpr(ifStmt->condition.get(), refs, prog);
        collectFuncRefsInBlock(ifStmt->thenBlock, refs, prog);
        collectFuncRefsInBlock(ifStmt->elseBlock, refs, prog);
    } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        collectFuncRefsInExpr(whileStmt->condition.get(), refs, prog);
        collectFuncRefsInBlock(whileStmt->body, refs, prog);
    } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        collectFuncRefsInBlock(loopStmt->body, refs, prog);
    } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        collectFuncRefsInExpr(switchStmt->condition.get(), refs, prog);
        for (auto& sc : switchStmt->cases) {
            collectFuncRefsInExpr(sc.condition.get(), refs, prog);
            collectFuncRefsInBlock(sc.body, refs, prog);
        }
    } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        collectFuncRefsInExpr(forStmt->start.get(), refs, prog);
        collectFuncRefsInExpr(forStmt->end.get(), refs, prog);
        collectFuncRefsInExpr(forStmt->step.get(), refs, prog);
        collectFuncRefsInBlock(forStmt->body, refs, prog);
    } else if (dynamic_cast<AsmStmt*>(stmt)) {
        // AsmStmt may reference any function/global — conservatively mark nothing
    }
}

void Optimizer::collectFuncRefsInBlock(const Block& block, std::unordered_set<std::string>& refs, const Program& prog) {
    for (auto& stmt : block.stmts) {
        collectFuncRefsInStmt(stmt.get(), refs, prog);
    }
}

void Optimizer::collectGlobalRefsInExpr(Expr* expr, std::unordered_set<std::string>& refs, const Program& prog) {
    if (!expr) return;
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        if (isGlobal(id->name, prog)) {
            refs.insert(id->name);
        }
    } else if (auto call = dynamic_cast<CallExpr*>(expr)) {
        collectGlobalRefsInExpr(call->receiver.get(), refs, prog);
        for (auto& arg : call->args) {
            collectGlobalRefsInExpr(arg.get(), refs, prog);
        }
    } else if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        collectGlobalRefsInExpr(bin->left.get(), refs, prog);
        collectGlobalRefsInExpr(bin->right.get(), refs, prog);
    } else if (auto unary = dynamic_cast<UnaryExpr*>(expr)) {
        collectGlobalRefsInExpr(unary->operand.get(), refs, prog);
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        collectGlobalRefsInExpr(memb->object.get(), refs, prog);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        collectGlobalRefsInExpr(arr->array.get(), refs, prog);
        collectGlobalRefsInExpr(arr->index.get(), refs, prog);
    } else if (auto deref = dynamic_cast<DerefExpr*>(expr)) {
        collectGlobalRefsInExpr(deref->ptr.get(), refs, prog);
    } else if (auto addrOf = dynamic_cast<AddressOfExpr*>(expr)) {
        // &global takes the address: the variable must stay in the layout
        if (isGlobal(addrOf->name, prog)) {
            refs.insert(addrOf->name);
        }
    }
}

void Optimizer::collectGlobalRefsInStmt(Stmt* stmt, std::unordered_set<std::string>& refs, const Program& prog) {
    if (!stmt) return;
    if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        collectGlobalRefsInExpr(varDecl->init.get(), refs, prog);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        collectGlobalRefsInExpr(ret->value.get(), refs, prog);
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        collectGlobalRefsInExpr(exprStmt->expr.get(), refs, prog);
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        collectGlobalRefsInExpr(assign->value.get(), refs, prog);
        collectGlobalRefsInExpr(assign->indexExpr.get(), refs, prog);
        if (isGlobal(assign->name, prog)) {
            refs.insert(assign->name);
        }
    } else if (auto ptrAssign = dynamic_cast<PtrAssignStmt*>(stmt)) {
        collectGlobalRefsInExpr(ptrAssign->ptr.get(), refs, prog);
        collectGlobalRefsInExpr(ptrAssign->value.get(), refs, prog);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        collectGlobalRefsInExpr(ifStmt->condition.get(), refs, prog);
        collectGlobalRefsInBlock(ifStmt->thenBlock, refs, prog);
        collectGlobalRefsInBlock(ifStmt->elseBlock, refs, prog);
    } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        collectGlobalRefsInExpr(whileStmt->condition.get(), refs, prog);
        collectGlobalRefsInBlock(whileStmt->body, refs, prog);
    } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        collectGlobalRefsInBlock(loopStmt->body, refs, prog);
    } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        collectGlobalRefsInExpr(switchStmt->condition.get(), refs, prog);
        for (auto& sc : switchStmt->cases) {
            collectGlobalRefsInExpr(sc.condition.get(), refs, prog);
            collectGlobalRefsInBlock(sc.body, refs, prog);
        }
    } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        collectGlobalRefsInExpr(forStmt->start.get(), refs, prog);
        collectGlobalRefsInExpr(forStmt->end.get(), refs, prog);
        collectGlobalRefsInExpr(forStmt->step.get(), refs, prog);
        collectGlobalRefsInBlock(forStmt->body, refs, prog);
    } else if (dynamic_cast<AsmStmt*>(stmt)) {
        // AsmStmt may reference any function/global — conservatively mark nothing
    }
}

void Optimizer::collectGlobalRefsInBlock(const Block& block, std::unordered_set<std::string>& refs, const Program& prog) {
    for (auto& stmt : block.stmts) {
        collectGlobalRefsInStmt(stmt.get(), refs, prog);
    }
}

void Optimizer::findReachable(const std::string& funcName,
                               std::unordered_set<std::string>& reachable,
                               const Program& prog) {
    if (reachable.count(funcName)) return;
    if (!isUserFunc(funcName, prog)) return;
    reachable.insert(funcName);

    for (auto& func : prog.functions) {
        if (func->name == funcName && !func->isExtern) {
            std::unordered_set<std::string> refs;
            collectFuncRefsInBlock(func->body, refs, prog);
            for (auto& callee : refs) {
                findReachable(callee, reachable, prog);
            }
            break;
        }
    }
}

OptResult Optimizer::optimize(Program& prog, OptLevel level, bool allowPow2Div) {
    OptResult result;
    allowPow2Div_ = allowPow2Div;

    if (prog.isLibrary) return result;
    if (level == OptLevel::None) return result;

    // ================================================================
    // Passes:
    //   None  (-0r): nothing below runs.
    //   Basic (-1r): unused function/global removal + constant folding +
    //                algebraic simplification + local propagation
    //                (cross-backend speed passes; also used by app efi,
    //                arm64, wasm, gui, bios, bare).
    //   Max   (-2r): Basic + aggressive size/RAM reduction (tiny-function
    //                inlining, dead-store elimination) used by 'app stm32'.
    //   Speed (-3r): Max + speed-only transforms that may grow the code
    //                (signed division/modulo by constant powers of two
    //                become shifts/and, avoiding idiv and the software
    //                __z_div on Cortex-M0 STM32).
    // ================================================================
    if (level == OptLevel::Max || level == OptLevel::Speed) {
        inlineTinyFunctions(prog, result);
    }
    int maxIter = (level == OptLevel::Max || level == OptLevel::Speed) ? 5 : 4;
    for (int iter = 0; iter < maxIter; iter++) {
        int before = result.removedStatements;
        foldConstants(prog, result);
        simplifyExprs(prog, result);
        propagateLocals(prog, result);
        structuralClean(prog, result);
        pruneConstBranches(prog, result);
        cleanupIfShapes(prog, result);
        canonicalCmp(prog, result);
        pullPow2Products(prog, result);
        mergeNestedIfs(prog, result);
        if (level == OptLevel::Max || level == OptLevel::Speed)
            deadStoreElimination(prog, result);
        if (result.removedStatements == before) break;
    }
    if (level == OptLevel::Speed)
        speedStrengthReduce(prog, result);

    std::string entryFunc;
    for (auto& f : prog.functions) {
        if (f->name == "main" && !f->isExtern) {
            entryFunc = "main";
            break;
        }
    }
    if (entryFunc.empty()) {
        for (auto& f : prog.functions) {
            if (!f->isExtern) {
                entryFunc = f->name;
                break;
            }
        }
    }
    if (entryFunc.empty()) return result;

    std::unordered_set<std::string> reachable;
    findReachable(entryFunc, reachable, prog);

    // C/C++ mixing: functions that mixed-in objects may call are seeded as
    // reachable so the dead-code pass never strips them.
    for (auto& name : preserveFuncs) {
        if (isUserFunc(name, prog)) findReachable(name, reachable, prog);
    }

    // Functions referenced from global initializers must be kept as well
    // (e.g. `var x: int = compute()`) — otherwise the init code would call
    // into a function that got stripped.
    for (auto& g : prog.globals) {
        std::unordered_set<std::string> refs;
        collectFuncRefsInExpr(g->init.get(), refs, prog);
        for (auto& r : refs) {
            findReachable(r, reachable, prog);
        }
    }

    // Kernel-module driver cleanup: the cleanup_module wrapper invokes a user
    // function named 'cleanup' (if present). Mark it reachable AND walk its
    // callees (ring_pop etc.) so the dead-code pass keeps everything the
    // cleanup hook references. (A bare `insert` left the refs stripped and
    // the .ko build failed with "call to unknown function".)
    if (prog.koDriver && !prog.functions.empty()) {
        bool hasCleanup = false;
        for (auto& f : prog.functions)
            if (f->name == "cleanup" && !f->isExtern) { hasCleanup = true; break; }
        if (hasCleanup) {
            std::unordered_set<std::string> refs;
            for (auto& f : prog.functions)
                if (f->name == "cleanup" && !f->isExtern) {
                    collectFuncRefsInBlock(f->body, refs, prog);
                    break;
                }
            for (auto& r : refs)
                findReachable(r, reachable, prog);
            reachable.insert("cleanup");
        }
    }

    std::unordered_set<std::string> usedExterns;
    for (auto& func : prog.functions) {
        if (!func->isExtern && reachable.count(func->name)) {
            std::unordered_set<std::string> refs;
            collectFuncRefsInBlock(func->body, refs, prog);
            for (auto& name : refs) {
                if (!isUserFunc(name, prog)) {
                    usedExterns.insert(name);
                }
            }
        }
    }

    auto fit = std::remove_if(prog.functions.begin(), prog.functions.end(),
        [&](const std::unique_ptr<FunctionDecl>& func) {
            if (func->isExtern) {
                if (keepExterns.count(func->name)) return false;
                if (!usedExterns.count(func->name)) {
                    result.warnings.push_back("Warning: unused extern function '" + func->name + "'");
                    result.removedFunctions++;
                    return true;
                }
                return false;
            }
            if (keepExterns.count(func->name)) return false;
            if (!reachable.count(func->name)) {
                result.warnings.push_back("Warning: unused function '" + func->name + "'");
                result.removedFunctions++;
                return true;
            }
            return false;
        });
    prog.functions.erase(fit, prog.functions.end());

    std::unordered_set<std::string> usedGlobals;
    for (auto& func : prog.functions) {
        if (!func->isExtern && reachable.count(func->name)) {
            collectGlobalRefsInBlock(func->body, usedGlobals, prog);
        }
    }

    // A global referenced from another global's initializer must be kept too
    // (e.g. `var b: int = a` — `a` is only reachable through `b`'s init).
    bool globalChanged;
    do {
        globalChanged = false;
        for (auto& g : prog.globals) {
            if (usedGlobals.count(g->name)) {
                std::unordered_set<std::string> refs;
                collectGlobalRefsInExpr(g->init.get(), refs, prog);
                for (auto& r : refs) {
                    if (!usedGlobals.count(r)) {
                        usedGlobals.insert(r);
                        globalChanged = true;
                    }
                }
            }
        }
    } while (globalChanged);

    auto git = std::remove_if(prog.globals.begin(), prog.globals.end(),
        [&](const std::unique_ptr<VarDecl>& var) {
            if (!usedGlobals.count(var->name)) {
                result.warnings.push_back("Warning: unused global variable '" + var->name + "'");
                result.removedGlobals++;
                return true;
            }
            return false;
        });
    prog.globals.erase(git, prog.globals.end());

    return result;
}

// ====================================================================
// structural cleanups
// ====================================================================

// Does `e` (or any sub-expression, including call arguments) reference the
// variable/global `name`? Used to guard against moving/removing statements
// around a target whose own previous value is read on the right side.
static bool exprReferencesName(const Expr* e, const std::string& name) {
    if (!e) return false;
    if (auto id = dynamic_cast<const IdentExpr*>(e)) return id->name == name;
    if (auto aof = dynamic_cast<const AddressOfExpr*>(e)) return aof->name == name;
    if (auto u = dynamic_cast<const UnaryExpr*>(e)) return exprReferencesName(u->operand.get(), name);
    if (auto b = dynamic_cast<const BinaryExpr*>(e))
        return exprReferencesName(b->left.get(), name) || exprReferencesName(b->right.get(), name);
    if (auto m = dynamic_cast<const MemberExpr*>(e)) return exprReferencesName(m->object.get(), name);
    if (auto a = dynamic_cast<const ArrayAccessExpr*>(e))
        return exprReferencesName(a->array.get(), name) || exprReferencesName(a->index.get(), name);
    if (auto d = dynamic_cast<const DerefExpr*>(e)) return exprReferencesName(d->ptr.get(), name);
    if (auto c = dynamic_cast<const CallExpr*>(e)) {
        if (c->receiver && exprReferencesName(c->receiver.get(), name)) return true;
        for (auto& a : c->args) if (exprReferencesName(a.get(), name)) return true;
    }
    return false;
}

// Recurse into nested blocks first, then apply the linear statement-level
// cleanups for the current block.
static void structuralCleanBlock(Optimizer& opt, Block& block, OptResult& result) {
    for (auto& stmt : block.stmts) {
        if (auto ifs = dynamic_cast<IfStmt*>(stmt.get())) {
            structuralCleanBlock(opt, ifs->thenBlock, result);
            structuralCleanBlock(opt, ifs->elseBlock, result);
        } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
            structuralCleanBlock(opt, ws->body, result);
        } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
            structuralCleanBlock(opt, ls->body, result);
        } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
            structuralCleanBlock(opt, fs->body, result);
        } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
            for (auto& sc : sw->cases) structuralCleanBlock(opt, sc.body, result);
        }
    }

    size_t i = 0;
    while (i < block.stmts.size()) {
        Stmt* s = block.stmts[i].get();

        // 1) Dead code after return / break / continue in the same block.
        if (dynamic_cast<ReturnStmt*>(s) || dynamic_cast<BreakStmt*>(s) ||
            dynamic_cast<ContinueStmt*>(s)) {
            size_t tail = block.stmts.size() - (i + 1);
            for (size_t k = 0; k < tail; k++) {
                block.stmts.pop_back();
                result.removedStatements++;
            }
            break;
        }

        if (auto vd = dynamic_cast<VarDecl*>(s)) {
            // 2) `var x; x = v;` -> `var x = v;` (v must not read x, and x
            //    must be a plain non-array scalar).
            if (!vd->init && vd->arraySize == 0 && i + 1 < block.stmts.size()) {
                if (auto as = dynamic_cast<AssignStmt*>(block.stmts[i + 1].get())) {
                    if (as->name == vd->name && !as->indexExpr && as->memberPath.empty() &&
                        !exprReferencesName(as->value.get(), vd->name)) {
                        vd->init = std::move(as->value);
                        block.stmts.erase(block.stmts.begin() + (long)(i + 1));
                        result.removedStatements++;
                        continue;
                    }
                }
            }
        } else if (auto as = dynamic_cast<AssignStmt*>(s)) {
            if (!as->indexExpr && as->memberPath.empty()) {
                // 3) `x = x;` is a pure no-op.
                if (auto id = dynamic_cast<IdentExpr*>(as->value.get())) {
                    if (id->name == as->name) {
                        block.stmts.erase(block.stmts.begin() + (long)i);
                        result.removedStatements++;
                        continue;
                    }
                }
                // 4) Adjacent `x = v; x = v;` with a pure, target-independent
                //    v: the first store is fully overwritten, drop it.
                if (i + 1 < block.stmts.size()) {
                    if (auto as2 = dynamic_cast<AssignStmt*>(block.stmts[i + 1].get())) {
                        if (as2->name == as->name && !as2->indexExpr && as2->memberPath.empty() &&
                            !opt.exprMayHaveSideEffects(as->value.get()) &&
                            !exprReferencesName(as->value.get(), as->name) &&
                            sameExpr(as->value.get(), as2->value.get())) {
                            block.stmts.erase(block.stmts.begin() + (long)i);
                            result.removedStatements++;
                            continue;
                        }
                    }
                }
            }
        }
        i++;
    }
}

void Optimizer::structuralClean(Program& prog, OptResult& result) {
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        structuralCleanBlock(*this, f->body, result);
        // 6) trailing `return;` (void) in a function body is redundant.
        auto& stmts = f->body.stmts;
        if (!stmts.empty()) {
            if (auto r = dynamic_cast<ReturnStmt*>(stmts.back().get())) {
                if (!r->value) {
                    stmts.pop_back();
                    result.removedStatements++;
                }
            }
        }
    }
}

// ====================================================================
// sizeMode passes
// ====================================================================

bool Optimizer::exprIsConstInt(Expr* expr, int64_t& val) {
    if (!expr) return false;
    if (auto num = dynamic_cast<NumberExpr*>(expr)) { val = num->value; return true; }
    if (auto u = dynamic_cast<UnaryExpr*>(expr)) {
        int64_t cv;
        if (!exprIsConstInt(u->operand.get(), cv)) return false;
        if (u->op == "-") { val = -cv; return true; }
        if (u->op == "!") { val = (cv == 0) ? 1 : 0; return true; }
        if (u->op == "~") { val = ~cv; return true; }
        return false;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(expr)) {
        int64_t l, r;
        if (!exprIsConstInt(b->left.get(), l)) return false;
        if (!exprIsConstInt(b->right.get(), r)) return false;
        const std::string& op = b->op;
        if (op == "+") { val = l + r; return true; }
        if (op == "-") { val = l - r; return true; }
        if (op == "*") { val = l * r; return true; }
        if (op == "/") { if (r == 0) return false; if (l == INT64_MIN && r == -1) return false; val = l / r; return true; }
        if (op == "%" || op == "//") { if (r == 0) return false; if (l == INT64_MIN && r == -1) return false; val = l % r; return true; }
        if (op == "&") { val = l & r; return true; }
        if (op == "|") { val = l | r; return true; }
        if (op == "^") { val = l ^ r; return true; }
        if (op == "<<") { val = (int64_t)((uint64_t)l << (r & 63)); return true; }
        if (op == ">>") { val = (int64_t)((uint64_t)l >> (r & 63)); return true; }
        if (op == "==") { val = (l == r) ? 1 : 0; return true; }
        if (op == "!=") { val = (l != r) ? 1 : 0; return true; }
        if (op == "<")  { val = (l < r)  ? 1 : 0; return true; }
        if (op == "<=") { val = (l <= r) ? 1 : 0; return true; }
        if (op == ">")  { val = (l > r)  ? 1 : 0; return true; }
        if (op == ">=") { val = (l >= r) ? 1 : 0; return true; }
        if (op == "&&") { val = (l != 0 && r != 0) ? 1 : 0; return true; }
        if (op == "||") { val = (l != 0 || r != 0) ? 1 : 0; return true; }
        return false;
    }
    return false;
}

void Optimizer::foldExpr(std::unique_ptr<Expr>& expr, OptResult& result) {
    if (!expr) return;
    if (auto b = dynamic_cast<BinaryExpr*>(expr.get())) {
        foldExpr(b->left, result);
        foldExpr(b->right, result);
        // Constant string folding: "ab" + "cd" -> "abcd", equal/not-equal
        // comparisons between two literal strings fold to 0/1.
        if (auto ls = dynamic_cast<StringExpr*>(b->left.get())) {
            if (auto rs = dynamic_cast<StringExpr*>(b->right.get())) {
                const std::string& op = b->op;
                if (op == "+") {
                    auto s = std::make_unique<StringExpr>();
                    s->value = ls->value + rs->value;
                    result.removedStatements++;
                    expr = std::move(s);
                    return;
                }
                if (op == "==") { expr = makeNum(ls->value == rs->value ? 1 : 0); result.removedStatements++; return; }
                if (op == "!=") { expr = makeNum(ls->value != rs->value ? 1 : 0); result.removedStatements++; return; }
            }
        }
        int64_t l, r;
        if (exprIsConstInt(b->left.get(), l) && exprIsConstInt(b->right.get(), r)) {
            const std::string& op = b->op;
            // Only fold pure arithmetic; skip '/ %' by zero (exprIsConstInt already guards)
            if (op == "/" && r == 0) return;
            if ((op == "%" || op == "//") && r == 0) return;
            if ((op == "/" || op == "%" || op == "//") && l == INT64_MIN && r == -1) return;
            auto n = std::make_unique<NumberExpr>();
            n->value = 0;
            if (op == "+") n->value = l + r;
            else if (op == "-") n->value = l - r;
            else if (op == "*") n->value = l * r;
            else if (op == "/") n->value = l / r;
            else if (op == "%" || op == "//") n->value = l % r;
            else if (op == "&") n->value = l & r;
            else if (op == "|") n->value = l | r;
            else if (op == "^") n->value = l ^ r;
            else if (op == "<<") n->value = (int64_t)((uint64_t)l << (r & 63));
            else if (op == ">>") n->value = (int64_t)((uint64_t)l >> (r & 63));
            else if (op == "==") n->value = (l == r) ? 1 : 0;
            else if (op == "!=") n->value = (l != r) ? 1 : 0;
            else if (op == "<")  n->value = (l < r)  ? 1 : 0;
            else if (op == "<=") n->value = (l <= r) ? 1 : 0;
            else if (op == ">")  n->value = (l > r)  ? 1 : 0;
            else if (op == ">=") n->value = (l >= r) ? 1 : 0;
            else if (op == "&&") n->value = (l != 0 && r != 0) ? 1 : 0;
            else if (op == "||") n->value = (l != 0 || r != 0) ? 1 : 0;
            else return;
            result.removedStatements++;
            expr = std::move(n);
            return;
        }
        // Short-circuit folds with a single constant side. `&&`/`||` skip the
        // right operand, so a constant LEFT side decides the result without
        // ever touching the right one; a constant right side still evaluates
        // the left side (so only side-effect-free left operands qualify).
        if (b->op == "&&" || b->op == "||") {
            int64_t cv;
            if (exprIsConstInt(b->left.get(), cv)) {
                if (b->op == "||" && cv != 0) {
                    auto n = std::make_unique<NumberExpr>(); n->value = 1;
                    result.removedStatements++;
                    expr = std::move(n);
                    return;
                }
                if (b->op == "&&" && cv == 0) {
                    auto n = std::make_unique<NumberExpr>(); n->value = 0;
                    result.removedStatements++;
                    expr = std::move(n);
                    return;
                }
            }
            if (exprIsConstInt(b->right.get(), cv) && !exprMayHaveSideEffects(b->left.get())) {
                if (b->op == "||" && cv != 0) {
                    auto n = std::make_unique<NumberExpr>(); n->value = 1;
                    result.removedStatements++;
                    expr = std::move(n);
                    return;
                }
                if (b->op == "&&" && cv == 0) {
                    auto n = std::make_unique<NumberExpr>(); n->value = 0;
                    result.removedStatements++;
                    expr = std::move(n);
                    return;
                }
            }
        }
    } else if (auto u = dynamic_cast<UnaryExpr*>(expr.get())) {
        foldExpr(u->operand, result);
        int64_t cv;
        if (exprIsConstInt(u->operand.get(), cv)) {
            auto n = std::make_unique<NumberExpr>();
            if (u->op == "-") n->value = -cv;
            else if (u->op == "!") n->value = (cv == 0) ? 1 : 0;
            else if (u->op == "~") n->value = ~cv;
            else return;
            result.removedStatements++;
            expr = std::move(n);
            return;
        }
    } else if (auto call = dynamic_cast<CallExpr*>(expr.get())) {
        foldExpr(call->receiver, result);
        for (auto& a : call->args) foldExpr(a, result);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr.get())) {
        foldExpr(arr->array, result);
        foldExpr(arr->index, result);
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr.get())) {
        foldExpr(memb->object, result);
    } else if (auto deref = dynamic_cast<DerefExpr*>(expr.get())) {
        foldExpr(deref->ptr, result);
    }
}

void Optimizer::foldBlock(Block& block, OptResult& result) {
    for (auto& stmt : block.stmts) foldStmt(stmt.get(), result);

    // Remove / collapse statements whose control flow is statically known.
    size_t i = 0;
    while (i < block.stmts.size()) {
        Stmt* s = block.stmts[i].get();
        if (auto ifStmt = dynamic_cast<IfStmt*>(s)) {
            int64_t cv;
            if (exprIsConstInt(ifStmt->condition.get(), cv)) {
                bool takeThen = (cv != 0);
                auto& chosen = takeThen ? ifStmt->thenBlock.stmts : ifStmt->elseBlock.stmts;
                result.removedStatements++;
                if (chosen.empty()) {
                    block.stmts.erase(block.stmts.begin() + i);
                } else {
                    // Move the whole chosen block into a local before assigning
                    // over ifStmt: otherwise destroying ifStmt also destroys the
                    // `chosen` vector while we still use it (use-after-free).
                    auto chosenCopy = std::move(chosen);
                    block.stmts[i] = std::move(chosenCopy[0]);
                    for (size_t k = 1; k < chosenCopy.size(); k++) {
                        block.stmts.insert(block.stmts.begin() + i + k, std::move(chosenCopy[k]));
                    }
                }
                continue;
            }
        } else if (auto whileStmt = dynamic_cast<WhileStmt*>(s)) {
            int64_t cv;
            if (exprIsConstInt(whileStmt->condition.get(), cv) && cv == 0) {
                result.removedStatements++;
                block.stmts.erase(block.stmts.begin() + i);
                continue;
            }
        }
        i++;
    }
}

void Optimizer::foldStmt(Stmt* stmt, OptResult& result) {
    if (!stmt) return;
    if (auto vd = dynamic_cast<VarDecl*>(stmt)) {
        foldExpr(vd->init, result);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        foldExpr(ret->value, result);
    } else if (auto es = dynamic_cast<ExprStmt*>(stmt)) {
        foldExpr(es->expr, result);
    } else if (auto as = dynamic_cast<AssignStmt*>(stmt)) {
        foldExpr(as->indexExpr, result);
        foldExpr(as->value, result);
    } else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt)) {
        foldExpr(pa->ptr, result);
        foldExpr(pa->value, result);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        foldExpr(ifStmt->condition, result);
        foldBlock(ifStmt->thenBlock, result);
        foldBlock(ifStmt->elseBlock, result);
    } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        foldExpr(whileStmt->condition, result);
        foldBlock(whileStmt->body, result);
    } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        foldBlock(loopStmt->body, result);
    } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        foldExpr(switchStmt->condition, result);
        for (auto& sc : switchStmt->cases) {
            foldExpr(sc.condition, result);
            foldBlock(sc.body, result);
        }
    } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        foldExpr(forStmt->start, result);
        foldExpr(forStmt->end, result);
        foldExpr(forStmt->step, result);
        foldBlock(forStmt->body, result);
    }
}

void Optimizer::foldConstants(Program& prog, OptResult& result) {
    for (auto& g : prog.globals) foldExpr(g->init, result);
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        foldBlock(f->body, result);
    }
}

bool Optimizer::exprMayHaveSideEffects(Expr* expr) {
    if (!expr) return false;
    if (dynamic_cast<NumberExpr*>(expr)) return false;
    if (dynamic_cast<FloatExpr*>(expr)) return false;
    if (dynamic_cast<StringExpr*>(expr)) return false;
    if (dynamic_cast<IdentExpr*>(expr)) return false;
    if (auto u = dynamic_cast<UnaryExpr*>(expr)) return exprMayHaveSideEffects(u->operand.get());
    if (auto b = dynamic_cast<BinaryExpr*>(expr))
        return exprMayHaveSideEffects(b->left.get()) || exprMayHaveSideEffects(b->right.get());
    if (auto m = dynamic_cast<MemberExpr*>(expr)) return exprMayHaveSideEffects(m->object.get());
    if (auto a = dynamic_cast<ArrayAccessExpr*>(expr))
        return exprMayHaveSideEffects(a->array.get()) || exprMayHaveSideEffects(a->index.get());
    if (auto d = dynamic_cast<DerefExpr*>(expr)) return exprMayHaveSideEffects(d->ptr.get());
    if (dynamic_cast<AddressOfExpr*>(expr)) return false;
    if (auto c = dynamic_cast<CallExpr*>(expr)) {
        // Calls can be user functions or builtins — both may have side effects.
        return true;
    }
    return true;
}

void Optimizer::collectLocalReadsExpr(Expr* expr, const std::unordered_set<std::string>& locals,
                                      std::unordered_set<std::string>& reads) {
    if (!expr) return;
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        if (locals.count(id->name)) reads.insert(id->name);
    } else if (auto aof = dynamic_cast<AddressOfExpr*>(expr)) {
        // Taking the address of a local is a potential escape: the value may
        // be read later through the pointer, so the store must be kept.
        if (locals.count(aof->name)) reads.insert(aof->name);
    } else if (auto u = dynamic_cast<UnaryExpr*>(expr)) {
        collectLocalReadsExpr(u->operand.get(), locals, reads);
    } else if (auto b = dynamic_cast<BinaryExpr*>(expr)) {
        collectLocalReadsExpr(b->left.get(), locals, reads);
        collectLocalReadsExpr(b->right.get(), locals, reads);
    } else if (auto m = dynamic_cast<MemberExpr*>(expr)) {
        collectLocalReadsExpr(m->object.get(), locals, reads);
    } else if (auto a = dynamic_cast<ArrayAccessExpr*>(expr)) {
        collectLocalReadsExpr(a->array.get(), locals, reads);
        collectLocalReadsExpr(a->index.get(), locals, reads);
    } else if (auto d = dynamic_cast<DerefExpr*>(expr)) {
        collectLocalReadsExpr(d->ptr.get(), locals, reads);
    } else if (auto c = dynamic_cast<CallExpr*>(expr)) {
        collectLocalReadsExpr(c->receiver.get(), locals, reads);
        for (auto& arg : c->args) collectLocalReadsExpr(arg.get(), locals, reads);
    }
}

void Optimizer::collectLocalReadsBlock(const Block& block, const std::unordered_set<std::string>& locals,
                                       std::unordered_set<std::string>& reads) {
    for (auto& stmt : block.stmts) collectLocalReads(stmt.get(), locals, reads);
}

void Optimizer::collectLocalReads(Stmt* stmt, const std::unordered_set<std::string>& locals,
                                  std::unordered_set<std::string>& reads) {
    if (!stmt) return;
    if (auto vd = dynamic_cast<VarDecl*>(stmt)) {
        collectLocalReadsExpr(vd->init.get(), locals, reads);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        collectLocalReadsExpr(ret->value.get(), locals, reads);
    } else if (auto es = dynamic_cast<ExprStmt*>(stmt)) {
        collectLocalReadsExpr(es->expr.get(), locals, reads);
    } else if (auto as = dynamic_cast<AssignStmt*>(stmt)) {
        // LHS name is a write, not a read
        collectLocalReadsExpr(as->indexExpr.get(), locals, reads);
        collectLocalReadsExpr(as->value.get(), locals, reads);
    } else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt)) {
        collectLocalReadsExpr(pa->ptr.get(), locals, reads);
        collectLocalReadsExpr(pa->value.get(), locals, reads);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        collectLocalReadsExpr(ifStmt->condition.get(), locals, reads);
        collectLocalReadsBlock(ifStmt->thenBlock, locals, reads);
        collectLocalReadsBlock(ifStmt->elseBlock, locals, reads);
    } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt)) {
        collectLocalReadsExpr(whileStmt->condition.get(), locals, reads);
        collectLocalReadsBlock(whileStmt->body, locals, reads);
    } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt)) {
        collectLocalReadsBlock(loopStmt->body, locals, reads);
    } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt)) {
        collectLocalReadsExpr(switchStmt->condition.get(), locals, reads);
        for (auto& sc : switchStmt->cases) {
            collectLocalReadsExpr(sc.condition.get(), locals, reads);
            collectLocalReadsBlock(sc.body, locals, reads);
        }
    } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt)) {
        collectLocalReadsExpr(forStmt->start.get(), locals, reads);
        collectLocalReadsExpr(forStmt->end.get(), locals, reads);
        collectLocalReadsExpr(forStmt->step.get(), locals, reads);
        collectLocalReadsBlock(forStmt->body, locals, reads);
    }
}

// Recursively collect names declared by 'var' statements.
static void collectLocalDeclsBlock(const Block& block, std::unordered_set<std::string>& locals) {
    for (auto& stmt : block.stmts) {
        if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) locals.insert(vd->name);
        if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
            collectLocalDeclsBlock(ifStmt->thenBlock, locals);
            collectLocalDeclsBlock(ifStmt->elseBlock, locals);
        } else if (auto whileStmt = dynamic_cast<WhileStmt*>(stmt.get())) {
            collectLocalDeclsBlock(whileStmt->body, locals);
        } else if (auto loopStmt = dynamic_cast<LoopStmt*>(stmt.get())) {
            collectLocalDeclsBlock(loopStmt->body, locals);
        } else if (auto forStmt = dynamic_cast<ForStmt*>(stmt.get())) {
            collectLocalDeclsBlock(forStmt->body, locals);
        } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(stmt.get())) {
            for (auto& sc : switchStmt->cases) collectLocalDeclsBlock(sc.body, locals);
        }
    }
}

static bool removeDeadStoresInBlock(Optimizer& opt,
                                    Block& block,
                                    const std::unordered_set<std::string>& locals,
                                    const std::unordered_set<std::string>& localReads,
                                    const std::unordered_set<std::string>& globalReads,
                                    const std::unordered_set<std::string>& globals,
                                    OptResult& result) {
    bool changed = false;
    size_t i = 0;
    while (i < block.stmts.size()) {
        Stmt* s = block.stmts[i].get();
        if (auto vd = dynamic_cast<VarDecl*>(s)) {
            if (locals.count(vd->name) && !localReads.count(vd->name)) {
                if (!vd->init || !opt.exprMayHaveSideEffects(vd->init.get())) {
                    result.removedStatements++;
                    block.stmts.erase(block.stmts.begin() + i);
                    changed = true;
                    continue;
                }
                // init has side effects: keep the call, drop the variable
                auto es = std::make_unique<ExprStmt>();
                es->expr = std::move(vd->init);
                block.stmts[i] = std::move(es);
                result.removedStatements++;
                changed = true;
                i++;
                continue;
            }
        } else if (auto as = dynamic_cast<AssignStmt*>(s)) {
            bool plain = !as->indexExpr && as->memberPath.empty();
            bool deadLocal = plain && locals.count(as->name) && !localReads.count(as->name);
            bool deadGlobal = plain && globals.count(as->name) && !globalReads.count(as->name);
            if ((deadLocal || deadGlobal) && !opt.exprMayHaveSideEffects(as->value.get())) {
                result.removedStatements++;
                block.stmts.erase(block.stmts.begin() + i);
                changed = true;
                continue;
            }
        }
        // recurse into nested blocks
        if (auto ifStmt = dynamic_cast<IfStmt*>(s)) {
            changed |= removeDeadStoresInBlock(opt, ifStmt->thenBlock, locals, localReads, globalReads, globals, result);
            changed |= removeDeadStoresInBlock(opt, ifStmt->elseBlock, locals, localReads, globalReads, globals, result);
        } else if (auto whileStmt = dynamic_cast<WhileStmt*>(s)) {
            changed |= removeDeadStoresInBlock(opt, whileStmt->body, locals, localReads, globalReads, globals, result);
        } else if (auto loopStmt = dynamic_cast<LoopStmt*>(s)) {
            changed |= removeDeadStoresInBlock(opt, loopStmt->body, locals, localReads, globalReads, globals, result);
        } else if (auto forStmt = dynamic_cast<ForStmt*>(s)) {
            changed |= removeDeadStoresInBlock(opt, forStmt->body, locals, localReads, globalReads, globals, result);
        } else if (auto switchStmt = dynamic_cast<SwitchStmt*>(s)) {
            for (auto& sc : switchStmt->cases)
                changed |= removeDeadStoresInBlock(opt, sc.body, locals, localReads, globalReads, globals, result);
        }
        i++;
    }
    return changed;
}

void Optimizer::deadStoreElimination(Program& prog, OptResult& result) {
    std::unordered_set<std::string> globals;
    for (auto& g : prog.globals) globals.insert(g->name);

    // A global read from ANY function is live (writes to it must be kept),
    // so the read set is computed program-wide.
    std::unordered_set<std::string> programGlobalsRead;
    for (auto& func : prog.functions) {
        if (func->isExtern) continue;
        collectLocalReadsBlock(func->body, globals, programGlobalsRead);
    }

    for (auto& func : prog.functions) {
        if (func->isExtern) continue;

        std::unordered_set<std::string> locals;
        collectLocalDeclsBlock(func->body, locals);

        std::unordered_set<std::string> localReads;
        collectLocalReadsBlock(func->body, locals, localReads);

        removeDeadStoresInBlock(*this, func->body, locals, localReads,
                                programGlobalsRead, globals, result);
    }
}

// ====================================================================
// speed passes: expression classification
// ====================================================================

Optimizer::VarKind Optimizer::kindOfExpr(Expr* expr) {
    if (!expr) return {};
    if (dynamic_cast<NumberExpr*>(expr)) return { TypeKind::Int };
    if (dynamic_cast<FloatExpr*>(expr)) return { TypeKind::Float };
    if (auto id = dynamic_cast<IdentExpr*>(expr)) {
        auto it = localKinds_.find(id->name);
        if (it != localKinds_.end()) return it->second;
        auto g = globalKinds_.find(id->name);
        if (g != globalKinds_.end()) return g->second;
        return {};
    }
    if (auto u = dynamic_cast<UnaryExpr*>(expr)) {
        if (u->op == "!") return { TypeKind::Int };
        return kindOfExpr(u->operand.get());
    }
    if (auto b = dynamic_cast<BinaryExpr*>(expr)) {
        const std::string& op = b->op;
        if (op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" ||
            op == "&&" || op == "||")
            return { TypeKind::Int };
        VarKind l = kindOfExpr(b->left.get());
        VarKind r = kindOfExpr(b->right.get());
        if (op == "<<" || op == ">>") {
            if (l.kind == TypeKind::Int || r.kind == TypeKind::Int) return { TypeKind::Int };
            return {};
        }
        if (op == "&" || op == "|" || op == "^" || op == "%" || op == "//") {
            if (l.kind == TypeKind::Int && r.kind == TypeKind::Int) return { TypeKind::Int };
            return {};
        }
        if (op == "+" || op == "-" || op == "*" || op == "/") {
            if (l.kind == TypeKind::Float || r.kind == TypeKind::Float) return { TypeKind::Float };
            if (l.kind == TypeKind::Int && r.kind == TypeKind::Int) return { TypeKind::Int };
            return {};
        }
        return {};
    }
    if (auto m = dynamic_cast<MemberExpr*>(expr)) {
        if (auto oid = dynamic_cast<IdentExpr*>(m->object.get())) {
            auto it = localKinds_.find(oid->name);
            if (it == localKinds_.end()) it = globalKinds_.find(oid->name);
            if (it != localKinds_.end() && it->second.kind == TypeKind::Struct) {
                auto f = fieldKinds_.find(it->second.structName + "." + m->member);
                if (f != fieldKinds_.end()) return { f->second };
            }
        }
        return {};
    }
    if (auto c = dynamic_cast<CallExpr*>(expr)) {
        auto it = funcRetKinds_.find(c->name);
        if (it != funcRetKinds_.end()) return it->second;
        return {};
    }
    return {};
}

void Optimizer::collectLocalKindsBlock(const Block& block, std::unordered_map<std::string, VarKind>& out) {
    for (auto& stmt : block.stmts) {
        if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) {
            VarKind vk;
            if (vd->type.kind != TypeKind::Void) {
                vk.kind = vd->type.kind;
                vk.structName = vd->type.structName;
            } else if (vd->init) {
                // Inferred (`var x = <expr>`): derive the obvious cases.
                if (dynamic_cast<NumberExpr*>(vd->init.get())) vk.kind = TypeKind::Int;
                else if (dynamic_cast<FloatExpr*>(vd->init.get())) vk.kind = TypeKind::Float;
                else if (dynamic_cast<StringExpr*>(vd->init.get())) vk.kind = TypeKind::String;
                else vk.kind = kindOfExpr(vd->init.get()).kind;   // may stay Void = unknown
            }
            out[vd->name] = vk;
        }
        if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
            collectLocalKindsBlock(ifStmt->thenBlock, out);
            collectLocalKindsBlock(ifStmt->elseBlock, out);
        } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
            collectLocalKindsBlock(ws->body, out);
        } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
            collectLocalKindsBlock(ls->body, out);
        } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
            collectLocalKindsBlock(fs->body, out);
            if (!out.count(fs->varName)) out[fs->varName] = { TypeKind::Int };
        } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
            for (auto& sc : sw->cases) collectLocalKindsBlock(sc.body, out);
        }
    }
}

void Optimizer::collectLocalKinds(const FunctionDecl& fn) {
    localKinds_.clear();
    for (auto& p : fn.params) {
        VarKind vk; vk.kind = p.type.kind; vk.structName = p.type.structName;
        localKinds_[p.name] = vk;
    }
    collectLocalKindsBlock(fn.body, localKinds_);
}

// ====================================================================
// speed passes: algebraic simplification + strength reduction
// ====================================================================

static bool sameExpr(const Expr* a, const Expr* b) {
    if (!a || !b) return a == b;
    if (auto n = dynamic_cast<const NumberExpr*>(a))
        if (auto m = dynamic_cast<const NumberExpr*>(b)) return n->value == m->value;
    if (auto f = dynamic_cast<const FloatExpr*>(a))
        if (auto g = dynamic_cast<const FloatExpr*>(b)) return f->value == g->value;
    if (auto s = dynamic_cast<const StringExpr*>(a))
        if (auto t = dynamic_cast<const StringExpr*>(b)) return s->value == t->value;
    if (auto i = dynamic_cast<const IdentExpr*>(a))
        if (auto j = dynamic_cast<const IdentExpr*>(b)) return i->name == j->name;
    if (auto u = dynamic_cast<const UnaryExpr*>(a))
        if (auto v = dynamic_cast<const UnaryExpr*>(b))
            return u->op == v->op && sameExpr(u->operand.get(), v->operand.get());
    if (auto be = dynamic_cast<const BinaryExpr*>(a))
        if (auto bf = dynamic_cast<const BinaryExpr*>(b))
            return be->op == bf->op && sameExpr(be->left.get(), bf->left.get()) &&
                   sameExpr(be->right.get(), bf->right.get());
    if (auto m = dynamic_cast<const MemberExpr*>(a))
        if (auto n = dynamic_cast<const MemberExpr*>(b))
            return m->member == n->member && sameExpr(m->object.get(), n->object.get());
    if (auto d = dynamic_cast<const DerefExpr*>(a))
        if (auto e = dynamic_cast<const DerefExpr*>(b)) return sameExpr(d->ptr.get(), e->ptr.get());
    if (auto ca = dynamic_cast<const CallExpr*>(a)) {
        if (auto cb = dynamic_cast<const CallExpr*>(b)) {
            if (ca->name != cb->name || ca->args.size() != cb->args.size()) return false;
            for (size_t k = 0; k < ca->args.size(); k++)
                if (!sameExpr(ca->args[k].get(), cb->args[k].get())) return false;
            return true;
        }
    }
    return false;
}

static bool isPow2Const(int64_t v, int& shift) {
    if (v <= 0) return false;
    shift = 0;
    while ((v & 1) == 0) { v >>= 1; shift++; }
    return v == 1;
}

static std::unique_ptr<NumberExpr> makeNum(int64_t v) {
    auto n = std::make_unique<NumberExpr>();
    n->value = v;
    return n;
}

static std::unique_ptr<UnaryExpr> makeUnary(const std::string& op, std::unique_ptr<Expr> operand) {
    auto u = std::make_unique<UnaryExpr>();
    u->op = op;
    u->operand = std::move(operand);
    return u;
}

static std::unique_ptr<BinaryExpr> makeBinary(const std::string& op,
                                              std::unique_ptr<Expr> left,
                                              std::unique_ptr<Expr> right) {
    auto b = std::make_unique<BinaryExpr>();
    b->op = op;
    b->left = std::move(left);
    b->right = std::move(right);
    return b;
}

void Optimizer::simplifyExpr(std::unique_ptr<Expr>& expr, OptResult& result) {
    if (!expr) return;
    if (auto b = dynamic_cast<BinaryExpr*>(expr.get())) {
        simplifyExpr(b->left, result);
        simplifyExpr(b->right, result);

        const std::string& op = b->op;
        bool arith = op == "+" || op == "-" || op == "*" || op == "/" || op == "%" || op == "//";
        bool bitw  = op == "&" || op == "|" || op == "^";
        bool shift = op == "<<" || op == ">>";
        bool cmp   = op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=";
        if (!arith && !bitw && !shift && !cmp) return;

        int64_t lv = 0, rv = 0;
        bool lC = exprIsConstInt(b->left.get(), lv);
        bool rC = exprIsConstInt(b->right.get(), rv);
        bool lSide = exprMayHaveSideEffects(b->left.get());
        bool rSide = exprMayHaveSideEffects(b->right.get());
        bool lInt = exprDefinitelyInt(b->left.get());
        bool rInt = exprDefinitelyInt(b->right.get());

        // ---- same expression on both sides ----
        // (a < a) -> 0 is safe for floats too (NaN included); the ==/!=/<=/>=
        // forms differ for NaN, so they need integer operands.
        if (sameExpr(b->left.get(), b->right.get()) && !lSide && !rSide) {
            if (op == "-" || op == "^") {
                if (lInt && rInt) { expr = makeNum(0); result.removedStatements++; return; }
            } else if (op == "&" || op == "|") {
                if (lInt && rInt) { expr = std::move(b->left); result.removedStatements++; return; }
            } else if (op == "<" || op == ">") {
                expr = makeNum(0); result.removedStatements++; return;
            } else if (op == "==" || op == "<=" || op == ">=") {
                if (lInt && rInt) { expr = makeNum(1); result.removedStatements++; return; }
            } else if (op == "!=") {
                if (lInt && rInt) { expr = makeNum(0); result.removedStatements++; return; }
            }
        }

        // ---- arithmetic identities (integer only) ----
        if (arith && lInt && rInt) {
            if (op == "+") {
                if (rC && rv == 0) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == 0) { expr = std::move(b->right); result.removedStatements++; return; }
            } else if (op == "-") {
                if (rC && rv == 0) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == 0) {
                    expr = makeUnary("-", std::move(b->right));
                    result.removedStatements++; return;
                }
            } else if (op == "*") {
                if (rC && rv == 1) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == 1) { expr = std::move(b->right); result.removedStatements++; return; }
                if (rC && rv == 0 && !lSide) { expr = makeNum(0); result.removedStatements++; return; }
                if (lC && lv == 0 && !rSide) { expr = makeNum(0); result.removedStatements++; return; }
                if (rC && rv == -1) { expr = makeUnary("-", std::move(b->left)); result.removedStatements++; return; }
                if (lC && lv == -1) { expr = makeUnary("-", std::move(b->right)); result.removedStatements++; return; }
                int sh = 0;
                if (rC && isPow2Const(rv, sh) && sh > 0) {
                    expr = makeBinary("<<", std::move(b->left), makeNum(sh));
                    result.strengthReduced++; return;
                }
                if (lC && isPow2Const(lv, sh) && sh > 0) {
                    expr = makeBinary("<<", std::move(b->right), makeNum(sh));
                    result.strengthReduced++; return;
                }
                // negative power of two: x * -4 -> -(x << 2)
                if (rC && rv != INT64_MIN && rv < 0 && isPow2Const(-rv, sh) && sh > 0) {
                    expr = makeUnary("-", makeBinary("<<", std::move(b->left), makeNum(sh)));
                    result.strengthReduced++; return;
                }
                if (lC && lv != INT64_MIN && lv < 0 && isPow2Const(-lv, sh) && sh > 0) {
                    expr = makeUnary("-", makeBinary("<<", std::move(b->right), makeNum(sh)));
                    result.strengthReduced++; return;
                }
            } else if (op == "/") {
                // x / 1 -> x; x / -1 is skipped (INT64_MIN / -1 traps).
                if (rC && rv == 1) { expr = std::move(b->left); result.removedStatements++; return; }
            } else if (op == "%" || op == "//") {
                // x % 1 / x % -1 -> 0 (the INT64_MIN % -1 case is UB on the
                // target idiv too, so collapsing it to 0 is legal).
                if (rC && (rv == 1 || rv == -1)) { expr = makeNum(0); result.removedStatements++; return; }
            }
        }

        // ---- bitwise identities ----
        if (bitw) {
            if (op == "&") {
                if (rC && rv == 0 && !lSide) { expr = makeNum(0); result.removedStatements++; return; }
                if (lC && lv == 0 && !rSide) { expr = makeNum(0); result.removedStatements++; return; }
                if (rC && rv == -1 && lInt) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == -1 && rInt) { expr = std::move(b->right); result.removedStatements++; return; }
            } else if (op == "|") {
                if (rC && rv == 0 && lInt) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == 0 && rInt) { expr = std::move(b->right); result.removedStatements++; return; }
                if (rC && rv == -1 && !lSide) { expr = makeNum(-1); result.removedStatements++; return; }
                if (lC && lv == -1 && !rSide) { expr = makeNum(-1); result.removedStatements++; return; }
            } else if (op == "^") {
                if (rC && rv == 0 && lInt) { expr = std::move(b->left); result.removedStatements++; return; }
                if (lC && lv == 0 && rInt) { expr = std::move(b->right); result.removedStatements++; return; }
                if (rC && rv == -1 && lInt) { expr = makeUnary("~", std::move(b->left)); result.removedStatements++; return; }
                if (lC && lv == -1 && rInt) { expr = makeUnary("~", std::move(b->right)); result.removedStatements++; return; }
            }
        }

        // ---- shift identities ----
        if (shift && lInt && rInt && rC && rv == 0) {
            expr = std::move(b->left); result.removedStatements++; return;
        }
    } else if (auto u = dynamic_cast<UnaryExpr*>(expr.get())) {
        simplifyExpr(u->operand, result);
        if (u->op == "-" || u->op == "~") {
            if (auto inner = dynamic_cast<UnaryExpr*>(u->operand.get())) {
                if (inner->op == u->op) {
                    expr = std::move(inner->operand);
                    result.removedStatements++;
                    return;
                }
            }
        } else if (u->op == "!") {
            // !(a == b) -> a != b, !(a < b) -> a >= b ... (integers only;
            // for floats the NaN case differs).
            if (auto b = dynamic_cast<BinaryExpr*>(u->operand.get())) {
                const std::string& op = b->op;
                bool isCmp = op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=";
                if (isCmp && exprDefinitelyInt(b->left.get()) && exprDefinitelyInt(b->right.get())) {
                    std::string inv;
                    if (op == "==") inv = "!=";
                    else if (op == "!=") inv = "==";
                    else if (op == "<") inv = ">=";
                    else if (op == ">") inv = "<=";
                    else if (op == "<=") inv = ">";
                    else inv = "<";
                    expr = makeBinary(inv, std::move(b->left), std::move(b->right));
                    result.removedStatements++;
                    return;
                }
            }
        }
    } else if (auto call = dynamic_cast<CallExpr*>(expr.get())) {
        simplifyExpr(call->receiver, result);
        for (auto& a : call->args) simplifyExpr(a, result);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr.get())) {
        simplifyExpr(arr->array, result);
        simplifyExpr(arr->index, result);
    } else if (auto m = dynamic_cast<MemberExpr*>(expr.get())) {
        simplifyExpr(m->object, result);
    } else if (auto d = dynamic_cast<DerefExpr*>(expr.get())) {
        simplifyExpr(d->ptr, result);
    }
}

void Optimizer::simplifyStmt(Stmt* stmt, OptResult& result) {
    if (!stmt) return;
    if (auto vd = dynamic_cast<VarDecl*>(stmt)) {
        simplifyExpr(vd->init, result);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        simplifyExpr(ret->value, result);
    } else if (auto es = dynamic_cast<ExprStmt*>(stmt)) {
        simplifyExpr(es->expr, result);
    } else if (auto as = dynamic_cast<AssignStmt*>(stmt)) {
        simplifyExpr(as->indexExpr, result);
        simplifyExpr(as->value, result);
    } else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt)) {
        simplifyExpr(pa->ptr, result);
        simplifyExpr(pa->value, result);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        simplifyExpr(ifStmt->condition, result);
        simplifyBlock(ifStmt->thenBlock, result);
        simplifyBlock(ifStmt->elseBlock, result);
    } else if (auto ws = dynamic_cast<WhileStmt*>(stmt)) {
        simplifyExpr(ws->condition, result);
        simplifyBlock(ws->body, result);
    } else if (auto ls = dynamic_cast<LoopStmt*>(stmt)) {
        simplifyBlock(ls->body, result);
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        simplifyExpr(sw->condition, result);
        for (auto& sc : sw->cases) {
            simplifyExpr(sc.condition, result);
            simplifyBlock(sc.body, result);
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        simplifyExpr(fs->start, result);
        simplifyExpr(fs->end, result);
        simplifyExpr(fs->step, result);
        simplifyBlock(fs->body, result);
    }
}

void Optimizer::simplifyBlock(Block& block, OptResult& result) {
    for (auto& stmt : block.stmts) simplifyStmt(stmt.get(), result);
    // Drop `if <pure-cond>` with both branches empty: the condition is
    // evaluated only for its value, so it can be removed entirely.
    size_t i = 0;
    while (i < block.stmts.size()) {
        Stmt* s = block.stmts[i].get();
        if (auto ifStmt = dynamic_cast<IfStmt*>(s)) {
            if (ifStmt->thenBlock.stmts.empty() && ifStmt->elseBlock.stmts.empty() &&
                !exprMayHaveSideEffects(ifStmt->condition.get())) {
                result.removedStatements++;
                block.stmts.erase(block.stmts.begin() + i);
                continue;
            }
        }
        i++;
    }
}

void Optimizer::simplifyExprs(Program& prog, OptResult& result) {
    globalKinds_.clear();
    funcRetKinds_.clear();
    fieldKinds_.clear();
    for (auto& g : prog.globals) {
        VarKind vk; vk.kind = g->type.kind; vk.structName = g->type.structName;
        if (vk.kind == TypeKind::Void && g->init) {
            if (dynamic_cast<NumberExpr*>(g->init.get())) vk.kind = TypeKind::Int;
            else if (dynamic_cast<FloatExpr*>(g->init.get())) vk.kind = TypeKind::Float;
            else if (dynamic_cast<StringExpr*>(g->init.get())) vk.kind = TypeKind::String;
        }
        globalKinds_[g->name] = vk;
    }
    for (auto& f : prog.functions) {
        VarKind vk; vk.kind = f->returnType.kind; vk.structName = f->returnType.structName;
        funcRetKinds_[f->name] = vk;
    }
    for (auto& s : prog.structs)
        for (auto& fld : s->fields)
            fieldKinds_[s->name + "." + fld.name] = fld.type.kind;
    for (auto& g : prog.globals) simplifyExpr(g->init, result);
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        collectLocalKinds(*f);
        simplifyBlock(f->body, result);
    }
}

// ====================================================================
// speed passes: local constant / copy propagation
// ====================================================================

void Optimizer::propagateLocals(Program& prog, OptResult& result) {
    auto collectLocals = [&](const FunctionDecl& fn) -> std::unordered_set<std::string> {
        std::unordered_set<std::string> out;
        for (auto& p : fn.params) out.insert(p.name);
        std::function<void(const Block&)> walk = [&](const Block& block) {
            for (auto& stmt : block.stmts) {
                if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) out.insert(vd->name);
                if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
                    walk(ifStmt->thenBlock); walk(ifStmt->elseBlock);
                } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
                    walk(ws->body);
                } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
                    walk(ls->body);
                } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
                    walk(fs->body);
                } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
                    for (auto& sc : sw->cases) walk(sc.body);
                }
            }
        };
        walk(fn.body);
        return out;
    };
    auto collectAssignedBlock = [&](const Block& block) -> std::unordered_set<std::string> {
        std::unordered_set<std::string> out;
        std::function<void(const Block&)> walk = [&](const Block& block) {
            for (auto& stmt : block.stmts) {
                if (auto as = dynamic_cast<AssignStmt*>(stmt.get())) out.insert(as->name);
                if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
                    walk(ifStmt->thenBlock); walk(ifStmt->elseBlock);
                } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
                    walk(ws->body);
                } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
                    walk(ls->body);
                } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
                    walk(fs->body);
                } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
                    for (auto& sc : sw->cases) walk(sc.body);
                }
            }
        };
        walk(block);
        return out;
    };
    auto collectAssigned = [&](const FunctionDecl& fn) -> std::unordered_set<std::string> {
        return collectAssignedBlock(fn.body);
    };
    auto collectAddrTaken = [&](const FunctionDecl& fn) -> std::unordered_set<std::string> {
        std::unordered_set<std::string> out;
        std::function<void(const Expr*)> walkE = [&](const Expr* e) {
            if (!e) return;
            if (auto aof = dynamic_cast<const AddressOfExpr*>(e)) out.insert(aof->name);
            if (auto u = dynamic_cast<const UnaryExpr*>(e)) walkE(u->operand.get());
            else if (auto b = dynamic_cast<const BinaryExpr*>(e)) { walkE(b->left.get()); walkE(b->right.get()); }
            else if (auto m = dynamic_cast<const MemberExpr*>(e)) walkE(m->object.get());
            else if (auto a = dynamic_cast<const ArrayAccessExpr*>(e)) { walkE(a->array.get()); walkE(a->index.get()); }
            else if (auto d = dynamic_cast<const DerefExpr*>(e)) walkE(d->ptr.get());
            else if (auto c = dynamic_cast<const CallExpr*>(e)) {
                walkE(c->receiver.get());
                for (auto& a : c->args) walkE(a.get());
            }
        };
        std::function<void(const Block&)> walkS = [&](const Block& block) {
            for (auto& stmt : block.stmts) {
                if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) walkE(vd->init.get());
                else if (auto ret = dynamic_cast<ReturnStmt*>(stmt.get())) walkE(ret->value.get());
                else if (auto es = dynamic_cast<ExprStmt*>(stmt.get())) walkE(es->expr.get());
                else if (auto as = dynamic_cast<AssignStmt*>(stmt.get())) { walkE(as->indexExpr.get()); walkE(as->value.get()); }
                else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt.get())) { walkE(pa->ptr.get()); walkE(pa->value.get()); }
                else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
                    walkE(ifStmt->condition.get()); walkS(ifStmt->thenBlock); walkS(ifStmt->elseBlock);
                } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
                    walkE(ws->condition.get()); walkS(ws->body);
                } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
                    walkS(ls->body);
                } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
                    walkE(fs->start.get()); walkE(fs->end.get()); walkE(fs->step.get()); walkS(fs->body);
                } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
                    walkE(sw->condition.get());
                    for (auto& sc : sw->cases) { walkE(sc.condition.get()); walkS(sc.body); }
                }
            }
        };
        walkS(fn.body);
        return out;
    };

    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        std::unordered_set<std::string> locals = collectLocals(*f);
        std::unordered_set<std::string> assigned = collectAssigned(*f);
        std::unordered_set<std::string> addrTaken = collectAddrTaken(*f);

        // known[name] = propagated value. isConst: plain integer literal.
        // alias: the value of `name` equals the value of `alias` (a local
        // variable or parameter that is never re-assigned / address-taken).
        struct Known { bool isConst = false; int64_t value = 0; std::string alias; bool isAlias = false; };
        std::unordered_map<std::string, Known> known;
        auto killName = [&](const std::string& n) {
            known.erase(n);
            for (auto it = known.begin(); it != known.end();) {
                if (it->second.isAlias && it->second.alias == n) it = known.erase(it);
                else ++it;
            }
        };

        std::function<void(std::unique_ptr<Expr>&)> walkE = [&](std::unique_ptr<Expr>& e) {
            if (!e) return;
            if (auto id = dynamic_cast<IdentExpr*>(e.get())) {
                auto it = known.find(id->name);
                if (it != known.end()) {
                    if (it->second.isConst) {
                        e = makeNum(it->second.value);
                        result.removedStatements++;
                        result.propagated++;
                    } else if (it->second.isAlias) {
                        auto n = std::make_unique<IdentExpr>();
                        n->name = it->second.alias;
                        e = std::move(n);
                        result.removedStatements++;
                        result.propagated++;
                    }
                    return;
                }
            }
            if (auto u = dynamic_cast<UnaryExpr*>(e.get())) walkE(u->operand);
            else if (auto b = dynamic_cast<BinaryExpr*>(e.get())) { walkE(b->left); walkE(b->right); }
            else if (auto m = dynamic_cast<MemberExpr*>(e.get())) walkE(m->object);
            else if (auto a = dynamic_cast<ArrayAccessExpr*>(e.get())) { walkE(a->array); walkE(a->index); }
            else if (auto d = dynamic_cast<DerefExpr*>(e.get())) walkE(d->ptr);
            else if (auto c = dynamic_cast<CallExpr*>(e.get())) {
                walkE(c->receiver);
                for (auto& a : c->args) walkE(a);
            }
        };

        std::function<void(Block&)> walkS = [&](Block& block) {
            // Scope undo: a VarDecl binds a NEW variable that shadows any outer
            // variable with the same name; its known value must be forgotten
            // (restored) when the block ends, or propagation would leak the
            // inner value into the enclosing scope.
            std::vector<std::pair<std::string, std::optional<Known>>> scopeUndo;
            for (auto& stmt : block.stmts) {
                if (auto vd = dynamic_cast<VarDecl*>(stmt.get())) {
                    auto itPrev = known.find(vd->name);
                    if (itPrev != known.end()) scopeUndo.push_back({ vd->name, itPrev->second });
                    else scopeUndo.push_back({ vd->name, std::optional<Known>{} });
                    walkE(vd->init);
                    if (addrTaken.count(vd->name)) { killName(vd->name); continue; }
                    // const propagation (int-only; floats must stay floats)
                    VarKind vk; vk.kind = vd->type.kind;
                    if (vk.kind == TypeKind::Void && vd->init)
                        vk = kindOfExpr(vd->init.get());
                    if (vk.kind == TypeKind::Float) { killName(vd->name); continue; }
                    int64_t cv;
                    if (exprIsConstInt(vd->init.get(), cv)) {
                        Known k; k.isConst = true; k.value = cv;
                        known[vd->name] = k;
                        continue;
                    }
                    // copy propagation: var t = x, where x is a local that is
                    // never re-assigned and never address-taken.
                    if (auto id = dynamic_cast<IdentExpr*>(vd->init.get())) {
                        const std::string& src = id->name;
                        bool ok = locals.count(src) && !assigned.count(src) && !addrTaken.count(src);
                        if (ok) {
                            auto sit = known.find(src);
                            if (sit != known.end()) {
                                // source itself is known: inherit its value
                                known[vd->name] = sit->second;
                                continue;
                            }
                            Known k; k.isAlias = true; k.alias = src;
                            known[vd->name] = k;
                            continue;
                        }
                    }
                    killName(vd->name);
                } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt.get())) {
                    walkE(ret->value);
                } else if (auto es = dynamic_cast<ExprStmt*>(stmt.get())) {
                    walkE(es->expr);
                } else if (auto as = dynamic_cast<AssignStmt*>(stmt.get())) {
                    walkE(as->indexExpr);
                    walkE(as->value);
                    killName(as->name);
                } else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt.get())) {
                    walkE(pa->ptr);
                    walkE(pa->value);
                } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt.get())) {
                    walkE(ifStmt->condition);
                    walkS(ifStmt->thenBlock);
                    walkS(ifStmt->elseBlock);
                } else if (auto ws = dynamic_cast<WhileStmt*>(stmt.get())) {
                    // Loop-carried variables: a var assigned anywhere in the
                    // body is NOT constant at the condition or in the body
                    // (the body runs multiple times), so kill its known value
                    // before substituting anything.
                    for (auto& n : collectAssignedBlock(ws->body)) killName(n);
                    walkE(ws->condition);
                    walkS(ws->body);
                } else if (auto ls = dynamic_cast<LoopStmt*>(stmt.get())) {
                    for (auto& n : collectAssignedBlock(ls->body)) killName(n);
                    walkS(ls->body);
                } else if (auto fs = dynamic_cast<ForStmt*>(stmt.get())) {
                    walkE(fs->start);
                    walkE(fs->end);
                    walkE(fs->step);
                    killName(fs->varName);
                    for (auto& n : collectAssignedBlock(fs->body)) killName(n);
                    walkS(fs->body);
                } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt.get())) {
                    walkE(sw->condition);
                    for (auto& sc : sw->cases) {
                        walkE(sc.condition);
                        walkS(sc.body);
                    }
                }
            }
            for (auto& su : scopeUndo) {
                if (su.second) known[su.first] = *su.second;
                else known.erase(su.first);
            }
        };
        walkS(f->body);
    }
}

// ====================================================================
// speed-level (-3r): signed div/mod by constant power of two
// ====================================================================

// x / 2^n (truncating toward zero) == (x + ((x >> (w-1)) & (2^n-1))) >> n
// for any signed w-bit x (verified for INT_MIN). Cost: shift, and, add,
// shift — much cheaper than idiv on x86/EFI and than the software
// __z_div on Cortex-M0 STM32. Only runs at OptLevel::Speed because it
// trades code size for speed and evaluates x twice.
void Optimizer::speedReduceExpr(std::unique_ptr<Expr>& expr, int w, OptResult& result) {
    if (!expr) return;
    if (auto b = dynamic_cast<BinaryExpr*>(expr.get())) {
        speedReduceExpr(b->left, w, result);
        speedReduceExpr(b->right, w, result);
        if (!allowPow2Div_) return;   // classic x86 Codegen can't take the deep trees
        // Small-constant multiply -> shift + add/sub: x*3 -> (x<<1)+x,
        // x*7 -> (x<<3)-x, etc. Skips the pure powers of two that
        // simplifyExpr already rewrote into shifts; only fires at Speed.
        if (b->op == "*") {
            if (!exprDefinitelyInt(b->left.get()) || !exprDefinitelyInt(b->right.get())) return;
            if (exprMayHaveSideEffects(b->left.get()) || exprMayHaveSideEffects(b->right.get())) return;
            int64_t rv2 = 0;
            bool kOnRight = exprIsConstInt(b->right.get(), rv2);
            int64_t k;
            std::unique_ptr<Expr>* xp;
            if (kOnRight) { k = rv2; xp = &b->left; }
            else {
                if (!exprIsConstInt(b->left.get(), rv2)) return;
                k = rv2; xp = &b->right;
            }
            if (k == 0 || k == 1 || k == -1) return;
            __int128 ak = (k == INT64_MIN) ? (__int128)INT64_MAX + 1 : (k < 0 ? -(__int128)k : k);
            int foundA = -1, foundB = -1;
            bool usePlus = false;
            for (int a = 1; a <= 62; a++) {
                __int128 pa = (__int128)1 << a;
                if (pa > (ak + 1) * 2) break;
                for (int bb = 0; bb <= a; bb++) {
                    __int128 pb = (__int128)1 << bb;
                    if (pa + pb == ak) { foundA = a; foundB = bb; usePlus = true; a = 63; break; }
                    if (pa - pb == ak) { foundA = a; foundB = bb; usePlus = false; a = 63; break; }
                }
            }
            if (foundA < 0) return;
            auto xa = makeBinary("<<", cloneExpr(xp->get()), makeNum(foundA));
            auto xb = (foundB == 0)
                ? cloneExpr(xp->get())
                : makeBinary("<<", cloneExpr(xp->get()), makeNum(foundB));
            std::unique_ptr<Expr> inner = makeBinary(usePlus ? "+" : "-", std::move(xa), std::move(xb));
            if (k < 0) expr = makeUnary("-", std::move(inner));
            else expr = std::move(inner);
            result.strengthReduced++;
            return;
        }
        bool isDiv = b->op == "/";
        bool isMod = b->op == "%" || b->op == "//";
        if (!isDiv && !isMod) return;
        if (!exprDefinitelyInt(b->left.get()) || !exprDefinitelyInt(b->right.get())) return;
        int64_t rv = 0;
        if (!exprIsConstInt(b->right.get(), rv)) return;
        int n = 0;
        bool negDiv = false;
        if (isPow2Const(rv, n)) {
            negDiv = false;
        } else if (rv != INT64_MIN && rv < 0 && isPow2Const(-rv, n)) {
            negDiv = true;
        } else {
            return;
        }
        if (n < 1 || n >= w) return;
        if (exprMayHaveSideEffects(b->left.get())) return;   // x is evaluated multiple times
        // The language's '>>' is a LOGICAL shift in every backend (codegen /
        // irasm emit SHR), so the classic arithmetic-shift sequence cannot be
        // used. Build the trunc-toward-zero quotient from logical ops only:
        //   sign = x >> (w-1)             -> 0 or 1
        //   corr = (0 - sign) & mask      -> 0 or (2^n - 1)
        //   t    = x + corr               -> >= -1 (== -1 only when x == -2^n)
        //   q    = (t >> n) | ((0 - (t >> (w-1))) << (w-n))   (arithmetic >> n)
        //   r    = x - (q << n)
        auto x = std::move(b->left);
        auto xKeep = cloneExpr(x.get());   // copy used by the modulo result
        auto sign = makeBinary(">>", cloneExpr(x.get()), makeNum(w - 1));
        auto mask = makeNum((n >= 63) ? INT64_MAX : (((int64_t)1 << n) - 1));
        auto corr = makeBinary("&", makeBinary("-", makeNum(0), cloneExpr(sign.get())), std::move(mask));
        auto t = makeBinary("+", cloneExpr(x.get()), std::move(corr));
        // Both uses of t are materialized before either of them moves it.
        // Argument evaluation order is unspecified, so leaving
        // cloneExpr(t.get()) next to std::move(t) inside one call lets the
        // move run first and hands the clone a null pointer, which lands in
        // the tree as a null child and later throws the backends off.
        auto tForShift = cloneExpr(t.get());   // t >> n
        auto tForSign = std::move(t);          // t >> (w - 1)
        auto q = makeBinary("|",
                            makeBinary(">>", std::move(tForShift), makeNum(n)),
                            makeBinary("<<", makeBinary("-", makeNum(0),
                                        makeBinary(">>", std::move(tForSign), makeNum(w - 1))),
                                       makeNum(w - n)));
        if (isDiv) {
            if (negDiv) expr = makeUnary("-", std::move(q));
            else expr = std::move(q);
            result.strengthReduced++;
        } else {
            // r = x - (q << n); the sign of the remainder follows x, so a
            // negative divisor changes nothing here.
            expr = makeBinary("-", std::move(xKeep),
                              makeBinary("<<", std::move(q), makeNum(n)));
            result.strengthReduced++;
        }
    } else if (auto u = dynamic_cast<UnaryExpr*>(expr.get())) {
        speedReduceExpr(u->operand, w, result);
    } else if (auto call = dynamic_cast<CallExpr*>(expr.get())) {
        speedReduceExpr(call->receiver, w, result);
        for (auto& a : call->args) speedReduceExpr(a, w, result);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr.get())) {
        speedReduceExpr(arr->array, w, result);
        speedReduceExpr(arr->index, w, result);
    } else if (auto m = dynamic_cast<MemberExpr*>(expr.get())) {
        speedReduceExpr(m->object, w, result);
    } else if (auto d = dynamic_cast<DerefExpr*>(expr.get())) {
        speedReduceExpr(d->ptr, w, result);
    }
}

void Optimizer::speedReduceStmt(Stmt* stmt, int w, OptResult& result) {
    if (!stmt) return;
    if (auto vd = dynamic_cast<VarDecl*>(stmt)) {
        speedReduceExpr(vd->init, w, result);
    } else if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        speedReduceExpr(ret->value, w, result);
    } else if (auto es = dynamic_cast<ExprStmt*>(stmt)) {
        speedReduceExpr(es->expr, w, result);
    } else if (auto as = dynamic_cast<AssignStmt*>(stmt)) {
        speedReduceExpr(as->indexExpr, w, result);
        speedReduceExpr(as->value, w, result);
    } else if (auto pa = dynamic_cast<PtrAssignStmt*>(stmt)) {
        speedReduceExpr(pa->ptr, w, result);
        speedReduceExpr(pa->value, w, result);
    } else if (auto ifStmt = dynamic_cast<IfStmt*>(stmt)) {
        speedReduceExpr(ifStmt->condition, w, result);
        speedReduceBlock(ifStmt->thenBlock, w, result);
        speedReduceBlock(ifStmt->elseBlock, w, result);
    } else if (auto ws = dynamic_cast<WhileStmt*>(stmt)) {
        speedReduceExpr(ws->condition, w, result);
        speedReduceBlock(ws->body, w, result);
    } else if (auto ls = dynamic_cast<LoopStmt*>(stmt)) {
        speedReduceBlock(ls->body, w, result);
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        speedReduceExpr(sw->condition, w, result);
        for (auto& sc : sw->cases) {
            speedReduceExpr(sc.condition, w, result);
            speedReduceBlock(sc.body, w, result);
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        speedReduceExpr(fs->start, w, result);
        speedReduceExpr(fs->end, w, result);
        speedReduceExpr(fs->step, w, result);
        speedReduceBlock(fs->body, w, result);
    }
}

void Optimizer::speedReduceBlock(Block& block, int w, OptResult& result) {
    for (auto& stmt : block.stmts) speedReduceStmt(stmt.get(), w, result);
}

void Optimizer::speedStrengthReduce(Program& prog, OptResult& result) {
    int w = 0;
    switch (prog.arch) {
        case Arch::X86_64: case Arch::ARM64: w = 64; break;
        case Arch::X86_32: case Arch::ARM: w = 32; break;
        default: return;   // Auto: word size not fixed yet — skip
    }
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        collectLocalKinds(*f);
        speedReduceBlock(f->body, w, result);
    }
    for (auto& g : prog.globals) speedReduceExpr(g->init, w, result);
}

// ====================================================================
// C8: inline tiny getter-like functions (sizeMode)
// ====================================================================

bool Optimizer::substituteTinyBody(std::unique_ptr<Expr>& callSlot, CallExpr* call, FunctionDecl* fn) {
    // fn->body = [ReturnStmt(value = expr)]. Clone the body expression,
    // replace each param occurrence (at most one per param) with the
    // corresponding argument, and swap the result into the call slot.
    auto ret = dynamic_cast<ReturnStmt*>(fn->body.stmts[0].get());
    if (!ret || !ret->value) return false;
    if ((int)call->args.size() != (int)fn->params.size()) return false;

    auto newBody = cloneExpr(ret->value.get());
    if (!newBody) return false;

    std::unordered_map<std::string, int> pmap;
    for (int i = 0; i < (int)fn->params.size(); i++) pmap[fn->params[i].name] = i;

    struct Occ { std::unique_ptr<Expr>* slot; int argIdx; };
    std::vector<Occ> occs;
    bool bad = false;
    std::function<void(std::unique_ptr<Expr>&)> walk = [&](std::unique_ptr<Expr>& node) {
        if (!node || bad) return;
        if (auto id = dynamic_cast<IdentExpr*>(node.get())) {
            auto it = pmap.find(id->name);
            if (it != pmap.end()) occs.push_back({&node, it->second});
            return;
        }
        if (auto aof = dynamic_cast<AddressOfExpr*>(node.get())) {
            if (pmap.count(aof->name)) bad = true;   // &param: not supported
            return;
        }
        if (auto m = dynamic_cast<MemberExpr*>(node.get())) {
            if (auto oid = dynamic_cast<IdentExpr*>(m->object.get()))
                if (pmap.count(oid->name)) { bad = true; return; }
            walk(m->object);
            return;
        }
        if (auto a = dynamic_cast<ArrayAccessExpr*>(node.get())) {
            if (auto oid = dynamic_cast<IdentExpr*>(a->array.get()))
                if (pmap.count(oid->name)) { bad = true; return; }
            walk(a->array);
            walk(a->index);
            return;
        }
        if (auto b = dynamic_cast<BinaryExpr*>(node.get())) { walk(b->left); walk(b->right); return; }
        if (auto u = dynamic_cast<UnaryExpr*>(node.get())) { walk(u->operand); return; }
        if (auto d = dynamic_cast<DerefExpr*>(node.get())) { walk(d->ptr); return; }
        if (auto c = dynamic_cast<CallExpr*>(node.get())) {
            walk(c->receiver);
            for (auto& a : c->args) walk(a);
            return;
        }
    };
    walk(newBody);
    if (bad) return false;

    std::vector<int> occCount(fn->params.size(), 0);
    for (auto& oc : occs) occCount[oc.argIdx]++;
    for (int n : occCount) if (n > 1) return false;

    for (auto& oc : occs) {
        if (oc.argIdx >= 0 && oc.argIdx < (int)call->args.size() && call->args[oc.argIdx])
            *oc.slot = std::move(call->args[oc.argIdx]);
    }
    callSlot = std::move(newBody);
    return true;
}

bool Optimizer::tryInlineCall(std::unique_ptr<Expr>& expr,
                              const std::unordered_map<std::string, FunctionDecl*>& tiny,
                              OptResult& result) {
    if (!expr) return false;
    if (auto call = dynamic_cast<CallExpr*>(expr.get())) {
        auto it = tiny.find(call->name);
        if (it != tiny.end()) {
            // A virtual call must stay a call: the dispatch chain resolves the
            // target from the object's runtime class id, so it can never be
            // replaced with the static-type implementation's body.
            if (!call->isVirtual) {
                bool argsSafe = true;
                // The receiver is dropped by the substitution, so it must be
                // free of side effects too (getObj().tinyMethod() must not
                // silently lose the getObj() call).
                if (exprMayHaveSideEffects(call->receiver.get())) argsSafe = false;
                for (auto& a : call->args)
                    if (exprMayHaveSideEffects(a.get())) { argsSafe = false; break; }
                if (argsSafe && substituteTinyBody(expr, call, it->second)) {
                    result.removedStatements++;
                    // the freshly inlined body may call other tiny functions
                    tryInlineCall(expr, tiny, result);
                }
            }
            return true;
        }
        bool ch = tryInlineCall(call->receiver, tiny, result);
        for (auto& a : call->args) ch |= tryInlineCall(a, tiny, result);
        return ch;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(expr.get())) {
        bool ch = tryInlineCall(b->left, tiny, result);
        return tryInlineCall(b->right, tiny, result) || ch;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(expr.get())) return tryInlineCall(u->operand, tiny, result);
    if (auto m = dynamic_cast<MemberExpr*>(expr.get())) return tryInlineCall(m->object, tiny, result);
    if (auto a = dynamic_cast<ArrayAccessExpr*>(expr.get())) {
        bool ch = tryInlineCall(a->array, tiny, result);
        return tryInlineCall(a->index, tiny, result) || ch;
    }
    if (auto d = dynamic_cast<DerefExpr*>(expr.get())) return tryInlineCall(d->ptr, tiny, result);
    return false;
}

void Optimizer::inlineTinyFunctions(Program& prog, OptResult& result) {
    std::unordered_map<std::string, FunctionDecl*> tiny;
    for (auto& f : prog.functions) {
        if (f->isExtern || f->name == "main") continue;
        if (f->body.stmts.size() != 1) continue;
        auto ret = dynamic_cast<ReturnStmt*>(f->body.stmts[0].get());
        if (!ret || !ret->value) continue;
        // skip direct recursion
        bool recurses = false;
        std::function<void(Expr*)> scan = [&](Expr* e) {
            if (!e || recurses) return;
            if (auto c = dynamic_cast<CallExpr*>(e)) {
                if (c->name == f->name) recurses = true;
                scan(c->receiver.get());
                for (auto& a : c->args) scan(a.get());
            } else if (auto b = dynamic_cast<BinaryExpr*>(e)) { scan(b->left.get()); scan(b->right.get()); }
            else if (auto u = dynamic_cast<UnaryExpr*>(e)) { scan(u->operand.get()); }
            else if (auto m = dynamic_cast<MemberExpr*>(e)) { scan(m->object.get()); }
            else if (auto a = dynamic_cast<ArrayAccessExpr*>(e)) { scan(a->array.get()); scan(a->index.get()); }
            else if (auto d = dynamic_cast<DerefExpr*>(e)) { scan(d->ptr.get()); }
        };
        scan(ret->value.get());
        if (recurses) continue;
        tiny[f->name] = f.get();
    }
    if (tiny.empty()) return;

    for (auto& g : prog.globals) tryInlineCall(g->init, tiny, result);
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        std::function<void(Stmt*)> inlineStmt = [&](Stmt* s) {
            if (!s) return;
            if (auto v = dynamic_cast<VarDecl*>(s)) { tryInlineCall(v->init, tiny, result); return; }
            if (auto r = dynamic_cast<ReturnStmt*>(s)) { tryInlineCall(r->value, tiny, result); return; }
            if (auto es = dynamic_cast<ExprStmt*>(s)) { tryInlineCall(es->expr, tiny, result); return; }
            if (auto a = dynamic_cast<AssignStmt*>(s)) { tryInlineCall(a->indexExpr, tiny, result); tryInlineCall(a->value, tiny, result); return; }
            if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) { tryInlineCall(pa->ptr, tiny, result); tryInlineCall(pa->value, tiny, result); return; }
            if (auto ifs = dynamic_cast<IfStmt*>(s)) {
                tryInlineCall(ifs->condition, tiny, result);
                for (auto& x : ifs->thenBlock.stmts) inlineStmt(x.get());
                for (auto& x : ifs->elseBlock.stmts) inlineStmt(x.get());
                return;
            }
            if (auto ws = dynamic_cast<WhileStmt*>(s)) {
                tryInlineCall(ws->condition, tiny, result);
                for (auto& x : ws->body.stmts) inlineStmt(x.get());
                return;
            }
            if (auto ls = dynamic_cast<LoopStmt*>(s)) { for (auto& x : ls->body.stmts) inlineStmt(x.get()); return; }
            if (auto fs = dynamic_cast<ForStmt*>(s)) {
                tryInlineCall(fs->start, tiny, result);
                tryInlineCall(fs->end, tiny, result);
                tryInlineCall(fs->step, tiny, result);
                for (auto& x : fs->body.stmts) inlineStmt(x.get());
                return;
            }
            if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
                tryInlineCall(sw->condition, tiny, result);
                for (auto& cs : sw->cases) {
                    tryInlineCall(cs.condition, tiny, result);
                    for (auto& x : cs.body.stmts) inlineStmt(x.get());
                }
                return;
            }
        };
        for (auto& s : f->body.stmts) inlineStmt(s.get());
    }
}

// ====================================================================
// small peephole passes
//
// All of these are depth-neutral or shrink the tree on purpose: the
// classic x86 backends (PE/EFI/BIOS/bare) are known to miscompile deep
// expression trees, so nothing here may make an expression taller than
// what it replaced.
// ====================================================================

// Recurse into every statement that owns nested blocks.
template <typename F>
static void forEachNestedBlock(Stmt* s, F&& recurse) {
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        recurse(ifs->thenBlock);
        recurse(ifs->elseBlock);
    } else if (auto ws = dynamic_cast<WhileStmt*>(s)) {
        recurse(ws->body);
    } else if (auto ls = dynamic_cast<LoopStmt*>(s)) {
        recurse(ls->body);
    } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
        recurse(fs->body);
    } else if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        for (auto& sc : sw->cases) recurse(sc.body);
    }
}

// --------------------------------------------------------------------
// 1) constant loop bounds
// --------------------------------------------------------------------

// A `for` whose start/end/step are all constants runs a known number of
// times. Only the "never runs" answer is acted on; a known non-zero trip
// count is left for the backend rather than unrolled here.
//
// Constant `if` and `while 0` are already handled by foldStmt, so this pass
// deliberately covers only the `for` case.
static bool forLoopIsEmptyTrip(Optimizer& opt, ForStmt* fs) {
    int64_t from = 0, to = 0, step = 1;
    if (!opt.exprIsConstInt(fs->start.get(), from)) return false;
    if (!opt.exprIsConstInt(fs->end.get(), to)) return false;
    if (fs->step) {
        if (!opt.exprIsConstInt(fs->step.get(), step)) return false;
        if (step <= 0) return false;   // descending / zero: not handled
    }
    return from >= to;
}

static void pruneConstBranchesBlock(Optimizer& opt, Block& block, OptResult& result) {
    // Innermost first, so a nested constant loop is already gone by the time
    // this level inspects the statement.
    for (auto& stmt : block.stmts)
        forEachNestedBlock(stmt.get(), [&](Block& b) { pruneConstBranchesBlock(opt, b, result); });

    size_t i = 0;
    while (i < block.stmts.size()) {
        Stmt* s = block.stmts[i].get();
        if (auto fs = dynamic_cast<ForStmt*>(s)) {
            if (forLoopIsEmptyTrip(opt, fs)) {
                block.stmts.erase(block.stmts.begin() + (long)i);
                result.removedStatements++;
                continue;
            }
        }
        i++;
    }
}

void Optimizer::pruneConstBranches(Program& prog, OptResult& result) {
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        pruneConstBranchesBlock(*this, f->body, result);
    }
}

// --------------------------------------------------------------------
// 2) if-statement shapes
// --------------------------------------------------------------------

static bool endsWithJump(Stmt* s) {
    return dynamic_cast<ReturnStmt*>(s) || dynamic_cast<BreakStmt*>(s) ||
           dynamic_cast<ContinueStmt*>(s);
}

static void cleanupIfShapesBlock(Optimizer& opt, Block& block, OptResult& result) {
    for (auto& stmt : block.stmts)
        forEachNestedBlock(stmt.get(), [&](Block& b) { cleanupIfShapesBlock(opt, b, result); });

    size_t i = 0;
    while (i < block.stmts.size()) {
        auto ifs = dynamic_cast<IfStmt*>(block.stmts[i].get());
        if (ifs && ifs->condition && !ifs->elseBlock.stmts.empty()) {
            bool emptyThen = ifs->thenBlock.stmts.empty();
            bool thenJumps = !emptyThen && endsWithJump(ifs->thenBlock.stmts.back().get());

            if (emptyThen) {
                // `if c {} else {B}` -> `if !c {B}`. The condition is still
                // evaluated exactly once and in the same order, so no purity
                // requirement is needed here. `!` is only correct for an
                // integer condition: the backend implements it as a compare
                // against 0, which is wrong for floats (-0.0 is falsy but
                // its bit pattern is not 0).
                if (opt.exprDefinitelyInt(ifs->condition.get())) {
                    ifs->condition = makeUnary("!", std::move(ifs->condition));
                    ifs->thenBlock = std::move(ifs->elseBlock);
                    ifs->elseBlock = Block();
                    result.removedStatements++;
                    continue;
                }
            } else if (thenJumps) {
                // `if c {J} else {B}` -> `if c {J}` followed by `B`. The then
                // arm jumps away (return/break/continue), so B is reached
                // exactly when it used to be. The `if` itself must be kept:
                // dropping it would run B when c is true.
                std::vector<std::unique_ptr<Stmt>> moved;
                moved.reserve(ifs->elseBlock.stmts.size());
                for (auto& st : ifs->elseBlock.stmts) moved.push_back(std::move(st));
                ifs->elseBlock = Block();
                block.stmts.insert(block.stmts.begin() + (long)i + 1,
                                   std::make_move_iterator(moved.begin()),
                                   std::make_move_iterator(moved.end()));
                result.removedStatements++;
                continue;   // re-examine: a spliced `if` may fold again
            }
        }
        i++;
    }
}

void Optimizer::cleanupIfShapes(Program& prog, OptResult& result) {
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        cleanupIfShapesBlock(*this, f->body, result);
    }
}

// --------------------------------------------------------------------
// 3) comparison canonicalisation
// --------------------------------------------------------------------

static void canonicalCmpExpr(Optimizer& opt, std::unique_ptr<Expr>& e, OptResult& result) {
    if (!e) return;
    if (auto b = dynamic_cast<BinaryExpr*>(e.get())) {
        canonicalCmpExpr(opt, b->left, result);
        canonicalCmpExpr(opt, b->right, result);
        if (b->op != ">") return;
        // Integer-only: for floats `a > b` is not `b < a` under NaN.
        if (!opt.exprDefinitelyInt(b->left.get()) || !opt.exprDefinitelyInt(b->right.get())) return;
        // Swapping the operands reorders their evaluation, so both sides
        // have to be pure.
        if (opt.exprMayHaveSideEffects(b->left.get()) ||
            opt.exprMayHaveSideEffects(b->right.get())) return;
        auto swapped = makeBinary("<", std::move(b->right), std::move(b->left));
        e = std::move(swapped);
        result.removedStatements++;
        return;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e.get())) {
        canonicalCmpExpr(opt, u->operand, result);
    } else if (auto c = dynamic_cast<CallExpr*>(e.get())) {
        canonicalCmpExpr(opt, c->receiver, result);
        for (auto& a : c->args) canonicalCmpExpr(opt, a, result);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(e.get())) {
        canonicalCmpExpr(opt, arr->array, result);
        canonicalCmpExpr(opt, arr->index, result);
    } else if (auto m = dynamic_cast<MemberExpr*>(e.get())) {
        canonicalCmpExpr(opt, m->object, result);
    } else if (auto d = dynamic_cast<DerefExpr*>(e.get())) {
        canonicalCmpExpr(opt, d->ptr, result);
    }
}

static void canonicalCmpBlock(Optimizer& opt, Block& block, OptResult& result) {
    std::function<void(Stmt*)> stmt = [&](Stmt* s) {
        if (!s) return;
        if (auto vd = dynamic_cast<VarDecl*>(s)) canonicalCmpExpr(opt, vd->init, result);
        else if (auto rt = dynamic_cast<ReturnStmt*>(s)) canonicalCmpExpr(opt, rt->value, result);
        else if (auto es = dynamic_cast<ExprStmt*>(s)) canonicalCmpExpr(opt, es->expr, result);
        else if (auto as = dynamic_cast<AssignStmt*>(s)) {
            canonicalCmpExpr(opt, as->indexExpr, result);
            canonicalCmpExpr(opt, as->value, result);
        } else if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
            canonicalCmpExpr(opt, pa->ptr, result);
            canonicalCmpExpr(opt, pa->value, result);
        }
        forEachNestedBlock(s, [&](Block& b) {
            for (auto& inner : b.stmts) stmt(inner.get());
        });
    };
    for (auto& s : block.stmts) stmt(s.get());
}

void Optimizer::canonicalCmp(Program& prog, OptResult& result) {
    for (auto& g : prog.globals) canonicalCmpExpr(*this, g->init, result);
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        collectLocalKinds(*f);
        canonicalCmpBlock(*this, f->body, result);
    }
}

// --------------------------------------------------------------------
// 4) pull a power-of-two factor out of a product
// --------------------------------------------------------------------

// Matches the right operand as `y * 2^n` or as `y << n` (the second shape
// is what simplifyExprs has already produced by the time this runs, so both
// are needed for the pass to fire regardless of ordering).
static bool matchPow2Factor(Optimizer& opt, Expr* e, std::unique_ptr<Expr>& rest, int& shift) {
    auto b = dynamic_cast<BinaryExpr*>(e);
    if (!b) return false;
    int64_t c = 0;
    if (b->op == "<<" && opt.exprIsConstInt(b->right.get(), c) && c > 0 && c < 64) {
        rest = std::move(b->left);
        shift = (int)c;
        return true;
    }
    if (b->op != "*") return false;
    if (opt.exprIsConstInt(b->right.get(), c) && isPow2Const(c, shift) && shift > 0) {
        rest = std::move(b->left);
        return true;
    }
    if (opt.exprIsConstInt(b->left.get(), c) && isPow2Const(c, shift) && shift > 0) {
        rest = std::move(b->right);
        return true;
    }
    return false;
}

static void pullPow2Expr(Optimizer& opt, std::unique_ptr<Expr>& e, OptResult& result) {
    if (!e) return;
    if (auto b = dynamic_cast<BinaryExpr*>(e.get())) {
        pullPow2Expr(opt, b->left, result);
        pullPow2Expr(opt, b->right, result);
        if (b->op != "*") return;
        if (!opt.exprDefinitelyInt(b->left.get())) return;
        std::unique_ptr<Expr> rest;
        int shift = 0;
        if (!matchPow2Factor(opt, b->right.get(), rest, shift)) return;
        // Depth is unchanged: `x * (y * 8)` and `(x * y) << 3` are both two
        // levels, so this is safe for the depth-sensitive x86 backends too.
        auto product = makeBinary("*", std::move(b->left), std::move(rest));
        e = makeBinary("<<", std::move(product), makeNum(shift));
        result.strengthReduced++;
        result.removedStatements++;
        return;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e.get())) {
        pullPow2Expr(opt, u->operand, result);
    } else if (auto c = dynamic_cast<CallExpr*>(e.get())) {
        pullPow2Expr(opt, c->receiver, result);
        for (auto& a : c->args) pullPow2Expr(opt, a, result);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(e.get())) {
        pullPow2Expr(opt, arr->array, result);
        pullPow2Expr(opt, arr->index, result);
    } else if (auto m = dynamic_cast<MemberExpr*>(e.get())) {
        pullPow2Expr(opt, m->object, result);
    } else if (auto d = dynamic_cast<DerefExpr*>(e.get())) {
        pullPow2Expr(opt, d->ptr, result);
    }
}

static void pullPow2Block(Optimizer& opt, Block& block, OptResult& result) {
    std::function<void(Stmt*)> stmt = [&](Stmt* s) {
        if (!s) return;
        if (auto vd = dynamic_cast<VarDecl*>(s)) pullPow2Expr(opt, vd->init, result);
        else if (auto rt = dynamic_cast<ReturnStmt*>(s)) pullPow2Expr(opt, rt->value, result);
        else if (auto es = dynamic_cast<ExprStmt*>(s)) pullPow2Expr(opt, es->expr, result);
        else if (auto as = dynamic_cast<AssignStmt*>(s)) {
            pullPow2Expr(opt, as->indexExpr, result);
            pullPow2Expr(opt, as->value, result);
        } else if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
            pullPow2Expr(opt, pa->ptr, result);
            pullPow2Expr(opt, pa->value, result);
        }
        forEachNestedBlock(s, [&](Block& b) {
            for (auto& inner : b.stmts) stmt(inner.get());
        });
    };
    for (auto& s : block.stmts) stmt(s.get());
}

void Optimizer::pullPow2Products(Program& prog, OptResult& result) {
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        collectLocalKinds(*f);
        pullPow2Block(*this, f->body, result);
    }
}

// --------------------------------------------------------------------
// 5) merge an `if` whose only statement is another `if`
// --------------------------------------------------------------------

static void mergeNestedIfsBlock(Optimizer& opt, Block& block, OptResult& result) {
    for (auto& stmt : block.stmts)
        forEachNestedBlock(stmt.get(), [&](Block& b) { mergeNestedIfsBlock(opt, b, result); });

    size_t i = 0;
    while (i < block.stmts.size()) {
        auto ifs = dynamic_cast<IfStmt*>(block.stmts[i].get());
        if (ifs && ifs->elseBlock.stmts.empty() && ifs->thenBlock.stmts.size() == 1 &&
            ifs->condition) {
            auto inner = dynamic_cast<IfStmt*>(ifs->thenBlock.stmts[0].get());
            // `&&` needs int operands here; a string/float condition would
            // change meaning, so those are left alone.
            if (inner && inner->condition && inner->elseBlock.stmts.empty() &&
                opt.exprDefinitelyInt(ifs->condition.get()) &&
                opt.exprDefinitelyInt(inner->condition.get())) {
                auto merged = makeBinary("&&", std::move(ifs->condition),
                                         std::move(inner->condition));
                ifs->condition = std::move(merged);
                ifs->thenBlock = std::move(inner->thenBlock);
                result.removedStatements++;
                continue;   // the new body may hold another mergeable `if`
            }
        }
        i++;
    }
}

void Optimizer::mergeNestedIfs(Program& prog, OptResult& result) {
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        collectLocalKinds(*f);
        mergeNestedIfsBlock(*this, f->body, result);
    }
}
