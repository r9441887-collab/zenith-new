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

    // 'app android': lower the runtime builtins into the raw Linux/AArch64
    // syscall helpers of the Android backend instead of the Win32 imports the
    // other IR targets use, and adopt the Android data model (`*(p)` is a
    // 4-byte `int` window, like the classic backend's pointer store).
    // apiLevel/minSdk are the `api_level:` / `min_sdk:` directives; the pass
    // that needs them (andropt) reads them from the IR-level helpers instead.
    void setAndroid(uint32_t apiLevel, uint32_t minSdk) {
        android_ = true;
        apiLevel_ = apiLevel;
        minSdk_ = minSdk;
    }
    bool isAndroid() const { return android_; }

private:
    Program& ast_;
    IRProgram& ir_;
    bool android_ = false;
    uint32_t apiLevel_ = 30;
    uint32_t minSdk_ = 21;

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
    std::unordered_map<std::string, int> varArrays_;   // arraySize per variable (0 = scalar)
    std::vector<VarDecl*> runtimeGlobalInits_;         // globals with `= &x` initializers
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
    bool exprIsString(Expr* e);
    Type exprType(Expr* e);              // static type of an expression (Void if unknown)
    int typeSize(const Type& t);         // storage size / element stride in bytes
    int arraySizeOf(const std::string& name);

    int emitExpr(Expr* e);
    int emitIntExpr(Expr* e);          // non-float, returns reg slot
    int emitFloatExpr(Expr* e);        // float, returns reg slot
    int emitCall(CallExpr* c);
    int emitLogicalExpr(Expr* e, int trueLabel, int falseLabel); // && / ||
    void emitBooleanValue(Expr* e, int trueLabel, int falseLabel);
    void emitBranchOnTrue(Expr* e, int trueLabel, int falseLabel);
    int emitMemberLoad(MemberExpr* m);
    int emitArrayAccess(ArrayAccessExpr* arr, bool isLoad);
    int emitAddrOf(Expr* e);             // address of an lvalue -> slot
    int emitArrayAddr(ArrayAccessExpr* arr); // &base[index] -> slot
    int emitElemAddr(const std::string& name, Expr* index); // &name[index] -> slot
    void emitAssign(AssignStmt* as);
    void emitStmt(Stmt* s);

    void emitGlobalInit(const std::string& name, VarDecl* g);
    int typeBytes(TypeKind k);
    int arrayElemBytes(const std::string& name);
    int scaleIdx(int idx, int elemBytes);

    // --- 'app android' runtime ---
    // Returns a result slot when `c` names an Android builtin (a raw syscall
    // helper, a memory primitive or a print), or -1 to let the generic path
    // handle it. print/println are routed here as well: on Android `print`
    // must not append a line break, which the IR's newline-printing ops do.
    int androidCall(CallExpr* c);
    void androidPrint(Expr* arg, bool newline);
    int androidCallHelper(const char* helper, const std::vector<Expr*>& args);
    int androidCallHelper1(const char* helper, Expr* a0);
    int androidCallHelper2(const char* helper, Expr* a0, Expr* a1);
    int androidCallHelper3(const char* helper, Expr* a0, Expr* a1, Expr* a2);
    int androidCallHelper4(const char* helper, Expr* a0, Expr* a1, Expr* a2, Expr* a3);
    int androidScaledTime(int64_t divisor, bool negative);
};
