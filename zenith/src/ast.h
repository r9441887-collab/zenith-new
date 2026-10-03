#pragma once
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <unordered_map>

enum class TypeKind { Int, Float, Bool, Void, String, Vec2, Vec3, Color, Entity, Struct, FuncPtr };

enum class AppType { Console, GUI, EFI, BIOS, Bare, STM32, ARM64, WASM, Linux, Android };
enum class AppCategory { Tool, Game };
enum class RenderType { Software, DX11, Vulkan };
enum class AddressSpace { Virtual, Physical };
enum class KernelMode { Independent, Dependent };
enum class Arch { Auto, X86_32, X86_64, ARM, ARM64 };

// Signature of a function-pointer type: `ptr<func(int, float) -> bool>`.
// Declared after Type because it stores types by value.
struct FuncPtrSig;

struct Type {
    TypeKind kind = TypeKind::Void;
    std::string structName;
    bool isPtr = false;
    // >0 when the type came from `var a: [N]T`: a real array carries its
    // element count, a plain pointer to the same element type does not.
    // Lets codegen tell `ptr<T>` and `T[N]` apart (both are isPtr + T).
    int arraySize = 0;
    AddressSpace addrSpace = AddressSpace::Virtual;
    // Non-null exactly for kind == FuncPtr: the pointed-to function signature.
    std::shared_ptr<FuncPtrSig> fn;

    Type(TypeKind k = TypeKind::Void, std::string name = "", bool ptr = false, AddressSpace as = AddressSpace::Virtual)
        : kind(k), structName(std::move(name)), isPtr(ptr), addrSpace(as) {}

    bool isFuncPtr() const { return kind == TypeKind::FuncPtr && isPtr; }
};

struct FuncPtrSig {
    std::vector<Type> params;
    Type ret;                      // Void when the declaration said nothing
};

struct StructLayout {
    std::string name;
    int totalSize = 0;
    std::unordered_map<std::string, int> fieldOffsets;
    std::unordered_map<std::string, Type> fieldTypes;
};

struct Node {
    virtual ~Node() = default;
    int line = 0;   // 1-based source line the node was parsed from (0 = unknown)
};

struct Expr : Node {};
struct Stmt : Node {};

struct NumberExpr : Expr {
    int64_t value = 0;
};

struct FloatExpr : Expr {
    double value = 0.0;
};

struct IdentExpr : Expr {
    std::string name;
};

struct MemberExpr : Expr {
    std::unique_ptr<Expr> object;
    std::string member;
};

struct BinaryExpr : Expr {
    std::unique_ptr<Expr> left;
    std::string op;
    std::unique_ptr<Expr> right;
    // Written as "(...)" in the source: a pattern that only looks like a
    // mistake (a comparison nested in another expression) is intentional
    // then, and the bug finder must stay quiet about it.
    bool parenthesized = false;
};

struct DerefExpr : Expr {
    std::unique_ptr<Expr> ptr;
};

// `&x` — address of an lvalue. `name` covers the plain `&var` / `&func`
// spelling the backends know directly; `target` carries every other lvalue
// (`&obj.field`, `&arr[i]`, `&(*p)`), which the backends lower through
// emitAddrOf.
struct AddressOfExpr : Expr {
    std::string name;
    std::unique_ptr<Expr> target;

    bool hasTarget() const { return target != nullptr; }
};

struct UnaryExpr : Expr {
    std::string op;
    std::unique_ptr<Expr> operand;
};

struct ArrayAccessExpr : Expr {
    std::unique_ptr<Expr> array;
    std::unique_ptr<Expr> index;
};

struct CallExpr : Expr {
    std::string name;
    std::vector<std::unique_ptr<Expr>> args;
    std::unique_ptr<Expr> receiver;
    // Virtual dispatch: when isVirtual, the call is resolved at runtime by the
    // hidden `__classid` slot at offset 0 of the receiver object. vtable holds
    // { classID, mangledImpl } for every class in the static type's subtree that
    // declares/overrides the method; the LAST entry is the static-type impl and
    // serves as the fall-through default.
    bool isVirtual = false;
    std::vector<std::pair<int, std::string>> vtable;
};

struct StringExpr : Expr {
    std::string value;
};

struct Param {
    std::string name;
    Type type;
};

struct Block {
    std::vector<std::unique_ptr<Stmt>> stmts;
};

struct VarDecl : Stmt {
    std::string name;
    Type type;
    std::unique_ptr<Expr> init;
    int arraySize = 0;
    bool isConst = false;
};

struct ReturnStmt : Stmt {
    std::unique_ptr<Expr> value;
};

struct ExprStmt : Stmt {
    std::unique_ptr<Expr> expr;
};

struct AssignStmt : Stmt {
    std::string name;
    std::vector<std::string> memberPath;
    std::unique_ptr<Expr> indexExpr;
    std::unique_ptr<Expr> value;
};

struct PtrAssignStmt : Stmt {
    std::unique_ptr<Expr> ptr;
    std::unique_ptr<Expr> value;
};

struct IfStmt : Stmt {
    std::unique_ptr<Expr> condition;
    Block thenBlock;
    Block elseBlock;
};

struct WhileStmt : Stmt {
    std::unique_ptr<Expr> condition;
    Block body;
};

struct LoopStmt : Stmt {
    Block body;
};

struct SwitchCase {
    std::unique_ptr<Expr> condition; // nullptr for default
    Block body;
};

struct SwitchStmt : Stmt {
    std::unique_ptr<Expr> condition;
    std::vector<SwitchCase> cases;
};

struct BreakStmt : Stmt {};
struct ContinueStmt : Stmt {};

struct AsmInstr {
    std::string mnemonic;
    std::string op1;
    std::string op2;
    std::string op3;
};

struct AsmStmt : Stmt {
    std::vector<AsmInstr> instrs;
    int32_t wordSize = 0; // 0 = native target width (resolved per backend); 16/32/64 = explicit
};

struct ForStmt : Stmt {
    std::string varName;
    std::unique_ptr<Expr> start;
    std::unique_ptr<Expr> end;
    std::unique_ptr<Expr> step; // optional, nullptr means step=1
    Block body;
};

struct FunctionDecl : Node {
    std::string name;
    std::vector<Param> params;
    Type returnType;
    Block body;
    bool isExtern = false;
    std::string dllName;
};

struct StructField {
    std::string name;
    Type type;
};

struct StructDecl : Node {
    std::string name;
    std::vector<StructField> fields;
};

// One method of a class. When lowered it becomes a top-level function named
// "<ClassName>::<method>" whose first parameter is `this: ptr<ClassName>`.
struct ClassMethod {
    std::string name;
    std::vector<Param> params;
    Type returnType;
    Block body;
    bool isAbstract = false; // abstract method: signature only, no body
};

struct ClassDecl : Node {
    std::string name;
    std::string base;   // base class name ("" = no inheritance)
    std::vector<std::string> interfaces;  // names of implemented interfaces
    std::vector<StructField> fields;
    std::vector<ClassMethod> methods;
    bool isAbstract = false; // abstract class: cannot be instantiated
};

// An interface declares method signatures (no bodies). A class that lists the
// interface in `implements` must define every method. Interface references are
// handled as pointers and dispatch on the object's runtime class id, so the
// same hidden `__classid` machinery as virtual methods is reused.
struct InterfaceDecl : Node {
    std::string name;
    std::vector<ClassMethod> methods;
};

struct ImportDecl {
    std::string dllName;
    std::string module; // e.g. "thread" from @import("libs.dll::thread")
};

struct Program {
    std::vector<std::unique_ptr<FunctionDecl>> functions;
    std::vector<std::unique_ptr<VarDecl>> globals;
    std::vector<ImportDecl> imports;
    std::vector<std::unique_ptr<StructDecl>> structs;
    std::vector<std::unique_ptr<ClassDecl>> classes;
    std::vector<std::unique_ptr<InterfaceDecl>> interfaces;
    // class name -> runtime class id (stored in the hidden `__classid` slot)
    std::unordered_map<std::string, int> classIDs;
    AppType appType = AppType::Console;
    AppCategory appCategory = AppCategory::Tool;
    bool koDriver = false; // true if 'app console driver' / 'app linux driver' (Linux .ko module)
    // KO module metadata (emitted into .modinfo; parsed from comments / meta lines)
    std::string moduleDescription;   // "description=..."
    std::string moduleAuthor;        // "author=..."
    std::string moduleVersion;       // "version=..."
    RenderType renderType = RenderType::Software;
    bool isLibrary = false; // true if # [no_main] is present
    KernelMode kernelMode = KernelMode::Independent;
    bool kernelModeExplicit = false; // true if 'kernel_mode:' line was present
    // boot_services: manual — the stub skips its automatic
    // GetMemoryMap/ExitBootServices sequence for independent kernels; the
    // program performs it explicitly (via the uefi_call/efi_gslot builtins)
    // after finishing its own pre-EBS work (e.g. a UEFI file-system
    // snapshot of the boot medium). Default keeps historical auto-EBS.
    bool bootServicesManual = false;
    Arch arch = Arch::Auto;          // target architecture (Auto, X86_32, X86_64)
    int32_t asmWordSize = 64;        // asm-block default operand width (64 or 32)
    bool real16 = false;             // true = emit a pure 16-bit real-mode boot image (asm16)
    // ===== STM32 (app stm32) target configuration =====
    std::string mcu = "stm32f103";   // chip model (stm32f1xx / stm32f4xx families)
    std::string ledPin = "PC13";     // on-board LED pin used by print() (e.g. "PC13", "PA5")
    bool ledActiveLow = false;       // led_active_low: true = LED on when pin is LOW (e.g. Blue Pill PC13)
    uint32_t sysclkHz = 72000000;    // HCLK for delay_ms() calibration
    uint32_t systickHz = 0;          // systick: SysTick clock in Hz (0 = HCLK = sysclk)
    uint32_t sramKb = 0;             // sram_kb: override SRAM size (0 = auto per mcu)

    // ===== ARM64 (app arm64) target configuration =====
    std::string arm64Chip = "generic";   // ARM64 chip model
    uint64_t arm64ClockHz = 1000000000;  // clock frequency for delay calculations

    // ===== Android (app android) target configuration =====
    // Android 11 == API level 30. androidApiLevel is what the program is written
    // against and is the one value that reaches the output: it is recorded in
    // the emitted .note.android.ident note. androidMinSdk is the lowest device
    // level it is allowed to run on (Bionic's first LP64 level is 21, so
    // anything below that is rejected) and androidLabel is a free-form marker
    // for the program. Both are compile-time only: the generated binary uses
    // nothing but raw Linux syscalls, so it has no Bionic symbol version
    // dependency to satisfy and no library to name.
    uint32_t androidApiLevel = 30;
    uint32_t androidMinSdk = 21;
    std::string androidLabel;
};
