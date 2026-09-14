#pragma once
#include "ast.h"
#include "ir.h"

// IRGen lowers the parsed AST (Program) into the assembler-IR.
// Unsupported constructs throw std::runtime_error with a clear message so
// main.cpp can fall back to the classic backend when --ir is used.
class IRGen {
public:
    IRGen(Program& ast, IRProgram& ir) : ast_(ast), ir_(ir) {}

    void generate();

private:
    Program& ast_;
    IRProgram& ir_;

    std::vector<IRInstr>* cur_ = nullptr;   // current function body
    IRFunction* curFn_ = nullptr;           // current function (for slot runs/stats)
    void recordRun(int base, int count);
    std::vector<int> breakStack_;
    std::vector<int> continueStack_;
    int labelCounter_ = 0;
    int poolNext_ = 0;                      // next free slot id (>= nparams)
    std::vector<int> freeSlots_;
    std::unordered_map<std::string, int> varSlots_;
    std::unordered_map<std::string, Type> varTypes_;
    std::unordered_map<std::string, bool> isGlobal_;
    std::unordered_map<std::string, StructLayout> structLayouts_;
    std::unordered_map<std::string, int> stringIndex_;

    int nparams_ = 0;

    int allocSlot();
    void freeSlot(int s);
    int newLabel();
    void add(IROp op, IROperand a = IROperand::none(), IROperand b = IROperand::none(),
             IROperand c = IROperand::none(), const std::string& cond = "", int label = -1);

    int ensureString(const std::string& s);
    void computeStructLayouts();

    bool isGlobalVar(const std::string& name) const;
    Type* varTypeOf(const std::string& name);
    Type* globalType(const std::string& name);
    bool structFieldInfo(const std::string& structName, const std::string& field,
                         int& off, Type& ft);
    int fieldOffset(const std::string& structName, const std::string& field);

    bool exprIsFloat(Expr* e);

    int emitExpr(Expr* e);
    int emitIntExpr(Expr* e);          // non-float, returns reg slot
    int emitFloatExpr(Expr* e);        // float, returns reg slot
    int emitCall(CallExpr* c);
    int emitLogicalExpr(Expr* e, int trueLabel, int falseLabel); // && / ||
    void emitBooleanValue(Expr* e, int trueLabel, int falseLabel);
    void emitBranchOnTrue(Expr* e, int trueLabel, int falseLabel);
    int emitMemberLoad(MemberExpr* m);
    int emitArrayAccess(ArrayAccessExpr* arr, bool isLoad);
    void emitAssign(AssignStmt* as);
    void emitStmt(Stmt* s);

    void emitGlobalInit(const std::string& name, VarDecl* g);
    int typeBytes(TypeKind k);
    int arrayElemBytes(const std::string& name);
    int scaleIdx(int idx, int elemBytes);
};
