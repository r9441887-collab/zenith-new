#pragma once
#include "ast.h"
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <filesystem>

// 6-byte marker appended to every compiled binary so Zenith output can be
// recognized (trailing bytes are ignored by loaders, so execution is unchanged).
static constexpr uint8_t kZenithMagic[6] = { 'Z', 'e', 'n', 'i', 't', 'h' };

// ELF executables are ET_EXEC pinned at this base; all absolute VAs in the
// image (pointer cells, callback addresses) are LOAD_BASE + section RVA.
static constexpr uint32_t kLinuxLoadBase = 0x400000;

namespace mix {
class MixContext;
}

struct VarInfo {
    int offset;
    Type type;
    bool isGlobal = false;
    bool isConst = false;
};

class Codegen {
public:
    explicit Codegen(Program& prog);
    void generate(const std::string& outputPath);
    void generateWide(const std::wstring& outputPath);
    void writeIso(const std::string& binaryPath, const std::string& isoPath);
    void setCompilerDir(const std::string& dir);
    void setCompilerDir(const std::filesystem::path& dir) { compilerDir = dir; }
    // Optional DWARF debug-symbol generation. When enabled the compiler emits a
    // *separate* debug file (<output>.debug, a GNU-style ELF carrying the
    // .debug_* sections) — the main binary is left byte-for-byte unchanged.
    void setSourcePath(const std::string& p) { sourcePath = p; }
    bool emitDebugInfo = false;
    bool isLibrary = false;
    bool libOutput = false;
    bool embedDLLs = false;
    bool flatOutput = false;

    // ===== C/C++ mixing (src/mix.cpp) =====
    // _start/EntryPoint emits `call $mixcrt0` before the user entry function.
    void emitMixCrt0Call();
    // Adds the fixed image base to all fill-in machine-word absolute patches
    // (C data pointers, ctor-table entries) right before the container build.
    void applyMixAbsPatches(uint64_t imageBase);
    friend class mix::MixContext;
    mix::MixContext* mixCtx = nullptr;

    // ===== codegen_builtins.cpp =====
    bool tryBuiltinCall(CallExpr* call, int& resultReg);

    // ===== codegen_gui.cpp =====
    bool tryGUICall(CallExpr* call, int& resultReg);

    // ===== codegen_dx11.cpp =====
    void emitDX11Init();
    void emitDX11Present();
    void emitDX11Cleanup();

    // ===== codegen_dx11_shaders.cpp =====
    bool tryDX11Call(CallExpr* call, int& resultReg);
    bool tryEFICall(CallExpr* call, int& resultReg);
    bool tryBIOSCall(CallExpr* call, int& resultReg);
    void emitGopGlyphLoop();
    int ensureString(const std::string& s);

    // ===== codegen_stm32.cpp =====
    // Emits a flat Cortex-M (Thumb-2) firmware image for 'app stm32'.
    bool compileStm32(const std::string& outputPath);

    // ===== codegen_arm64.cpp =====
    // Emits a flat AArch64 firmware image for 'app arm64'.
    bool compileArm64(const std::string& outputPath);

    // ===== codegen_android.cpp =====
    // Emits an AArch64 ELF64 executable for 'app android' (Android 11+).
    bool compileAndroid(const std::string& outputPath);

    // ===== codegen_wasm.cpp =====
    // Emits a WebAssembly binary module for 'app wasm'.
    bool compileWasm(const std::string& outputPath);

    // ===== Linux target (app linux): ELF64, SysV ABI =====
    bool isLinux = false;   // true when building for 'app linux'
    bool tryLinuxCall(CallExpr* call, int& resultReg);   // codegen_builtins_linux.cpp
    bool tryLinuxGUICall(CallExpr* call, int& resultReg); // codegen_gui_x11.cpp
    bool tryLinuxVulkanCall(CallExpr* call, int& resultReg); // codegen_vulkan.cpp
    bool tryLinuxNetCall(CallExpr* call, int& resultReg); // codegen_net_linux.cpp
    bool tryLinuxWLCall(CallExpr* call, int& resultReg);  // codegen_wl_linux.cpp
    bool tryKOCall(CallExpr* call, int& resultReg);       // codegen_ko.cpp (kernel-module builtins)
    bool tryShaderCall(CallExpr* call, int& resultReg);   // codegen_shader.cpp (shader()/shader_file())
    void emitLinuxEntryPoint();   // codegen_elf.cpp / codegen.cpp
    void emitLinuxLibInit();      // shared-library ($so_init) initializer, codegen_elf.cpp
    void buildELFLib(const std::string& path);  // ET_DYN .so emitter (codegen_elf.cpp)
    void emitX11Init();           // codegen_gui_x11.cpp
    void emitX11Present();
    void emitX11Cleanup();
    void emitVkInit();            // codegen_vulkan.cpp
    void emitVkPresent();
    void emitVkCleanup();
    void buildELF(const std::string& path);
    void buildLinuxImportData();  // fills rdata/data (string pool + Linux globals) for 'app linux'
    void buildImportData();       // fills rdata/data + PE import table (Windows target)
    // ===== kernel-module (.ko) target (app console/linux driver) =====
    void buildKO(const std::string& path);  // codegen_ko.cpp: ET_REL .o + modpost/gcc/ld -> .ko
    void emitKOEntry();                     // init_module / cleanup_module wrappers -> .text
    void emitLinuxExitSyscall();  // _exit(0) via syscall, for Linux entry point returns
    void emitStartupRelocator();  // resolve OS imports via dlopen/dlsym at startup (codegen_elf.cpp)
    void detectLinuxNeed();
    // State slots for the Linux target (X11/Vulkan/socket/sound), resolved by buildELF.
    uint32_t linuxGlobalsRVA = 0;
    uint32_t linuxSndOpenedRVA = 0;
    uint32_t linuxSndHwoRVA = 0;
    // ABI mode. false = Win64 (rcx/rdx/r8/r9 + shadow), true = SysV (rdi/rsi/rdx/rcx/r8/r9).
    bool sysvAbi = false;

    // ===== codegen_sw.cpp =====
    void emitSWInit();
    void emitSWPresent();
    void emitSWCleanup();

    void emit8(uint8_t b);
    void emit16(uint16_t v);
    void emit32(uint32_t v);

private:
    void emit64(uint64_t v);

    int allocReg();
    void freeReg(int r);
    int allocXmmReg();
    void freeXmmReg(int r);
    uint8_t regsUsed = 0;
    uint8_t xmmRegsUsed = 0;

    void emitMovReg(int dst, int src);
    void emitMovRegImm(int r, int64_t val);
    void emitLoadRegFromBP(int r, int offset);
    void emitStoreToBP(int offset);
    void emitStoreRegToBP(int r, int offset);
    void emitLoadRegFromBP64(int r, int offset);
    void emitStoreRegToBP64(int r, int offset);
    void emitStoreToBP64(int offset);

void emitAdd(int dst, int src);
void emitSub(int dst, int src);
void emitImul(int dst, int src);
void emitAnd(int dst, int src);
void emitOr(int dst, int src);
void emitXor(int dst, int src);

    void emitMovssXmm(int xmmDst, int xmmSrc);
    void emitMovssXmmFromMem(int xmmDst, int gpReg, int offset);
    void emitMovssXmmToMem(int xmmDst, int gpReg, int offset);
    void emitMovssXmmImm(int xmmDst, float val);
    void emitAddss(int xmmDst, int xmmSrc);
    void emitSubss(int xmmDst, int xmmSrc);
    void emitMulss(int xmmDst, int xmmSrc);
    void emitDivss(int xmmDst, int xmmSrc);
    void emitUcomiss(int xmmA, int xmmB);
    void emitCvtsi2ss(int xmmDst, int gpSrc);
    void emitCvtss2si(int gpDst, int xmmSrc);
    void emitCvttss2si(int gpDst, int xmmSrc);
    void emitMovdGpFromXmm(int gpDst, int xmmSrc);
    void emitMovdXmmFromGp(int xmmDst, int gpSrc);
    void emitSqrtss(int xmmDst, int xmmSrc);
    void emitAndps(int xmmDst, int xmmSrc);
    void emitMinss(int xmmDst, int xmmSrc);
    void emitMaxss(int xmmDst, int xmmSrc);
    void emitXorps(int xmmDst, int xmmSrc);
    void emitRoundss(int xmmDst, int xmmSrc, uint8_t imm);
    int emitFloatMathCall(CallExpr* call);

    int nextLabel = 0;
    std::vector<int> labelPositions;
    int newLabel();
    void emitLabel(int label);
    void emitJmp(int label);
    void emitJcc(const std::string& cond, int label);

    std::vector<int> breakLabelStack;
    std::vector<int> continueLabelStack;

    bool isFloatExpr(Expr* expr);

    // ===== Large struct (>8 bytes) value handling =====
    // A non-pointer struct-typed value whose layout is bigger than one qword is
    // passed around in registers rax:rdx:r10 (k = ceil(totalSize/8), k<=3) or,
    // for arguments, copied qword-by-qword into consecutive 8-byte slots.
    int structTypeSize(const Type& t);
    int structValueQwords(Expr* e);   // 0 unless e is a >8B non-ptr struct value; else ceil(size/8)
    void emitStructAddrR10(Expr* e);  // address of an Ident/Member struct value into r10
    void emitStructRegs(Expr* e, int k);  // load/synthesize k qwords into rax:rdx:r10

    void emitEntryPoint();
    void emitFunction(FunctionDecl* func);
    int emitExpr(Expr* expr);
    int emitUnaryExpr(UnaryExpr* u);
    int emitExprKeepAlive(Expr* expr, int& keepReg);
    int emitExprKeepAliveR10(Expr* expr);
    int emitFloatExprKeepAliveR10(Expr* expr);
    void emitStmt(Stmt* stmt, const Type* stmtType = nullptr);
    void emitAsmInstr(const AsmInstr& instr, int32_t wordSize);
    void emitAsm16Instr(const AsmInstr& instr);
    int asmRegIndex(const std::string& name) const;
    // Firmware-service gate: in kernel_mode independent firmware calls
    // (efi_* / bios_*) are rejected with a useful error. Returns true if ok.
    bool builtinAllowed(const std::string& name);
    int emitFloatExpr(Expr* expr);
    int emitBinaryExpr(BinaryExpr* bin, bool isFloat);
    void emitFloatStoreToBP(int xmm, int offset);
    void emitFloatLoadFromBP(int xmm, int offset);
    void emitLeaR10FromBP(int offset);
    void emitLeaRegFromBP(int r, int offset);
    void emitLoadFromAddr(int gpDst, int addrReg, int offset);
    void emitStoreToAddr(int gpSrc, int addrReg, int offset);
    void emitLoad32FromAddr(int gpDst, int addrReg, int offset);
    void emitStore32ToAddr(int gpSrc, int addrReg, int offset);
    void emitFloatLoadFromAddr(int xmmDst, int addrReg, int offset);
    void emitFloatStoreToAddr(int xmmDst, int addrReg, int offset);
    void emitLoadR10FromBP64(int offset);
    void emitGlobalLoadR10(int offset);
    void emitLoadFromAddrR10(int gpDst, int offset);
    void emitLoad32FromAddrR10(int gpDst, int offset);
    void emitStoreToAddrR10(int offset);
    void emitStore32ToAddrR10(int offset);
    void emitFloatLoadFromAddrR10(int xmmDst, int offset);
    void emitFloatStoreToR10(int xmmDst, int offset);
    void emitLoadQwordDisp8(int dstReg, int baseReg, int disp);
    void emitStoreQwordDisp8(int srcReg, int baseReg, int disp);
    void emitIncQwordDisp8(int baseReg, int disp);
    void emitMovQwordDisp8Imm32(int baseReg, int disp, int32_t imm);

    // Framebuffer info access for gop_*/fb_* builtins (codegen_efi.cpp).
    // For EFI apps the info lives in win32Globals (populated from the GOP
    // protocol at startup); for Bare apps it is read from the fixed loader
    // addresses 0x8000..0x8018. `field` matches the fixed-address offset.
    void emitLoadFbInfo64(int r, int field);
    void emitLoadFbInfo32(int r, int field);
    void emitImulFbInfo32(int r, int field);
    // Real-hardware GOP support: if the cached PixelFormat is 0
    // (PixelRedGreenBlueReserved8BitPerColor, "RGBX"), byte-swap the given
    // color registers (32-bit halves) so 0x00RRGGBB colors render correctly.
    // OVMF/QEMU exposes BGRX, but many vendor firmwares expose RGBX as the
    // native mode. `scratch` must be a register dead at the call site.
    void emitSwapColorsIfRgbx(int scratch, const std::vector<int>& colorRegs);

    // RIP-relative access to user global variables (.data section)
    void emitGlobalLoadReg(int r, int offset);
    void emitGlobalLoadReg32(int r, int offset);
    void emitGlobalLoadReg32Abs(int r, int offset);
    void emitGlobalStoreReg64(int offset);
    void emitGlobalStoreReg32(int offset);
    void emitGlobalStoreReg32Abs(int r, int offset);
    void emitGlobalLeaReg(int r, int offset);
    void emitGlobalLeaR10(int offset);
    void emitGlobalFloatLoad(int xmm, int offset);
    void emitGlobalFloatStore(int xmm, int offset);
    void populateGlobalVarInfos();
    void emitGlobalInit();

    void spillRegs();
    void reloadRegs();
    int spillBase = 0;
    int locals = 0;

    struct CallFixup { size_t codePos; std::string target; };
    struct FuncRefFixup { size_t codePos; std::string target; };
    struct JmpFixup { size_t codePos; int targetPos; };
    struct StrFixup { size_t codePos; int stringIndex; };
    struct ImportCallFixup { size_t codePos; std::string funcName; std::string dllName; };
    struct GlobalFixup { size_t codePos; uint32_t targetRVA; };
    struct EmbeddedLEAFixup { size_t codePos; bool isRdata; };
    // KO mode: a direct `call` to an external kernel symbol (e.g. _printk).
    // Emitted as E8 <disp32>=0 + R_X86_64_PC32 against the unique strtab/undef
    // symbol; the addend -4 is baked in by codegen_ko.cpp.
    struct KOExtCallFixup { size_t codePos; std::string symbol; };
    std::vector<KOExtCallFixup> koExtCallFixups;
    // KO mode: a `mov rax, [rip+disp32]` load of an external kernel DATA
    // symbol (e.g. jiffies) — same fixup shape, same relocation.
    std::vector<KOExtCallFixup> koDataFixups;
    size_t koInitOffset = 0, koInitSize = 0;
    size_t koCleanupOffset = 0, koCleanupSize = 0;
    // KO mode string references emitted as `mov r, imm32` (R_X86_64_32S,
    // gcc -mcmodel=kernel style): addend = stringOffset, symbol = .rodata
    // section symbol. Separate from strFixups (LEA rip-relative + PC32) so
    // kernel-string encoding never mixes with userspace RIP-relative LEA.
    std::vector<StrFixup> koStrFixups;
    std::vector<EmbeddedLEAFixup> embeddedLEAFixups;
    std::vector<CallFixup> callFixups;
    std::vector<FuncRefFixup> funcRefFixups;
    std::vector<JmpFixup> jmpFixups;
    std::vector<StrFixup> strFixups;
    std::vector<ImportCallFixup> importCallFixups;
    struct ElfImportFixup { size_t codePos; std::string symbol; std::string soname; };
    std::vector<ElfImportFixup> elfImportFixups;
    // C/C++ mix: 8-byte absolute pointer cells in .data whose runtime value is
    // supplied by the dynamic loader. buildELF emits a GOT-style slot +
    // R_X86_64_64 relocation against the recorded soname for each entry.
    struct MixDynCell { uint32_t cellRVA; std::string symbol; std::string soname; };
    std::vector<MixDynCell> mixDynCells;
    // C/C++ mix: 8-byte data cells in .data that get an R_X86_64_COPY dynamic
    // relocation, mirroring a -no-pie link (libc globals like stdout/stderr
    // referenced via `mov sym(%rip),%reg` by -fno-pic GCC).
    struct CopyReloc { uint32_t cellRVA; std::string symbol; };
    std::vector<CopyReloc> copyRelocs;
    void resolveFixups();
    void resolveJmpFixups();
    void computeSectionRVAs();
    uint32_t estimateRdataSize();
    uint32_t estimateDataSize();
    void fixupSectionRVAs();
    void emitDllEntryPoint();
    void buildExportDir();
    void emitWin64WinAPI(int x64Convention, bool isFloat, const std::vector<std::pair<Type,int>>& args, int stackBytes);
    void printStructs();

    void collectStrings();
    void collectStmtStrings(Stmt* stmt);
    void collectExprStrings(Expr* expr);

    struct ExportEntry {
        std::string name;
        uint32_t funcRVA;
    };
    std::vector<ExportEntry> exportEntries;
    uint32_t exportDirRVA = 0;
    uint32_t exportDirSize = 0;

    void buildPE(const std::string& path);
    void writeBareFlatImage(const std::string& path);
    void writeBiosFlatImage(const std::string& path);
    // ===== 32-bit x86 backend (codegen_x8632.cpp) =====
    // A self-contained cdecl 32-bit emitter used when arch==X86_32 (bios and
    // bare+dependent apps). Produces the same flat image layout as
    // writeBiosFlatImage but with true 32-bit instruction encoding (no REX,
    // 32-bit registers/stack slots, args on the stack after [esp]).
    void emitX8632Function(FunctionDecl* func);
    void emitX8632Entry();
    void emitX8632Stmt(Stmt* stmt);
    int emitX8632Expr(Expr* expr);
    void emitX8632Call(CallExpr* call);
    void emitX8632Jmp(int label);
    void emitX8632Jcc(const std::string& cond, int label);
    void writeX8632Image(const std::string& path);
    // 32-bit helpers shared with the main 32-bit-aware emitters.
    void emitX8632MovRegImm(int r, int32_t v);
    void x8632AllocateBlockVars(const Block& block);
    bool emitX8632Builtin(CallExpr* call);
    int x8632FuncEndLabel = -1;
    // 32-bit frame helpers (emit8/emit32 are public; these emit [ebp+disp] forms).
    void x32LoadBPImpl(int r, int off);
    void x32StoreBPEaxImpl(int off);
    void x32StoreBPImpl(int r, int off);
    void x32LeaEaxBPImpl(int off);
    void writeReal16Image(const std::string& path);
    void emitReal16Function(FunctionDecl* func);
    void emitReal16Entry();
    void emitReal16Stmt(Stmt* stmt);
    int emitReal16Expr(Expr* expr);
    int emitReal16Call(CallExpr* call);
    void emitReal16Jmp(int label);
    void emitReal16Jcc(const std::string& cond, int label);
    std::vector<std::pair<size_t, int>> real16JmpFixups;
    std::vector<CallFixup> real16CallFixups;
    // {top, end} labels of enclosing loops for real16 break/continue
    std::vector<std::pair<int, int>> real16LoopStack;
    // {code pos of the A1/A3 imm16, global name} resolved in writeReal16Image
    std::vector<std::pair<int, std::string>> real16GlobalFixups;

    Program& prog;
    int wordSize = 64; // 32 or 64
    std::vector<uint8_t> code;
    std::vector<uint8_t> rdata;
    std::vector<uint8_t> data;

    std::unordered_map<std::string, size_t> funcOffsets;
    size_t entryPointCodeOffset;
    size_t entryExitProcessFixup;

    VarInfo* getVarInfo(const std::string& name);

    std::unordered_map<std::string, VarInfo> varInfos;
    int frameSize = 0;
    int funcEndLabel = -1;
    Type curFuncRetType;   // return type of the function currently being emitted

    std::vector<std::string> stringPool;
    std::vector<uint32_t> stringOffsets;
    uint32_t stringRVA = 0;

    struct HeapFixup { size_t codePos; uint32_t targetRVA; };
    std::vector<HeapFixup> heapFixups;
    uint32_t heapOffsetRVA = 0xFFFFFD00;
    uint32_t heapFreeHeadRVA = 0xFFFFFE00;
    uint32_t heapAreaRVA = 0xFFFFFF00;
    uint32_t randSeedRVA = 0;
    uint32_t win32GlobalsRVA = 0;
    // 64 KiB memory-map scratch in .bss (EFI independent-mode entry stub:
    // GetMemoryMap buffer before ExitBootServices). Resolved from sentinel
    // 0xFFFFFA00 in buildPE.
    uint32_t mmBufRVA = 0;

    // ===== Network builtins (http_get / http_last_error / http_json) =====
    // Slots referenced by http_get's emitted code. The small state slots live
    // in .data; the response buffer lives in .bss (zero-init, no file space).
    enum NetSlot {
        NET_STATUS = 0,      // 4 bytes: HTTP status code (e.g. 200)
        NET_STATUS_LEN,      // 4 bytes: in/out size for HttpQueryInfoA
        NET_BYTES_READ,      // 8 bytes: scratch for InternetReadFile
        NET_LEN,             // 8 bytes: total body bytes written to buffer
        NET_ERR,             // 8 bytes: last WinINet/GetLastError error code
        NET_BUF,             // NET_BUFFER_SIZE bytes: response body buffer (.bss)
        NET_HDR_LEN,         // 4 bytes: in/out size for the raw-headers query
        NET_HDR,             // NET_HDR_SIZE bytes: raw HTTP headers (.bss)
        NET_JSON             // JSON record buffer (.bss), see http_json layout
    };
    static constexpr uint32_t NET_BUFFER_SIZE = 256 * 1024;
    static constexpr uint32_t NET_BUF_RVA_SENTINEL = 0xFFFFFB00;
    static constexpr uint32_t NET_HDR_SIZE = 16 * 1024;
    // http_json record layout:
    //   [+0] int32 status  [+4] int32 jsonLen  [+8] magic 'ZJSN'
    //   [+12] char json[jsonMax]  [+12+jsonMax] int32 headLen
    //   [+16+jsonMax] char head[headMax]
    static constexpr uint32_t NET_JSON_MAX = 64 * 1024;
    static constexpr uint32_t NET_HEAD_MAX = 16 * 1024;
    static constexpr uint32_t NET_JSON_RECORD_SIZE = 16 + NET_JSON_MAX + NET_HEAD_MAX;
    struct NetFixup { size_t codePos; uint8_t slot; };
    std::vector<NetFixup> netFixups;
    bool httpGetUsed = false;
    bool httpJsonHelperEmitted = false;
    int httpJsonHelperLabel = -1;
    uint32_t netStatusRVA = 0;
    uint32_t netStatusLenRVA = 0;
    uint32_t netBytesReadRVA = 0;
    uint32_t netLenRVA = 0;
    uint32_t netErrRVA = 0;
    uint32_t netBufRVA = 0;
    uint32_t netHdrLenRVA = 0;
    uint32_t netHdrRVA = 0;
    uint32_t netJsonRVA = 0;
    void detectNetworkUsage();
    void detectNetworkExprUsage(Expr* expr);
    void detectNetworkStmtUsage(Stmt* stmt);

    // ===== Socket builtins (net_* TCP/UDP servers & clients via ws2_32.dll) =====
    enum SockSlot {
        SOCK_WSA_STARTED = 0,  // 8 bytes: 0 until WSAStartup() has succeeded once
        SOCK_WSADATA,          // 416 bytes: WSADATA handed to WSAStartup()
        SOCK_PEER_ADDR,        // 16 bytes: sockaddr_in scratch / last UDP peer
        SOCK_PEER_LEN          // 8 bytes: in/out addrlen for recvfrom + FIONBIO arg
    };
    struct SockFixup { size_t codePos; uint8_t slot; };
    std::vector<SockFixup> sockFixups;
    bool netSocksUsed = false;
    uint32_t sockWsaStartedRVA = 0;
    uint32_t sockWsadataRVA = 0;
    uint32_t sockPeerRVA = 0;
    uint32_t sockPeerLenRVA = 0;
    uint32_t linNetErrRVA = 0;      // Linux net: net_last_error() slot
    uint32_t linNetIpBufRVA = 0;    // Linux net: udp_peer_ip() string buffer

    // ===== Linux Vulkan (vk_* builtins, codegen_vulkan.cpp) runtime slots =====
    bool vkUsed = false;            // true once any vk_* builtin is seen/emitted
    uint32_t vkInstRVA = 0;         // 8 bytes: VkInstance handle
    uint32_t vkAppInfoRVA = 0;      // 48 bytes: VkApplicationInfo
    uint32_t vkInstInfoRVA = 0;     // 64 bytes: VkInstanceCreateInfo
    uint32_t vkFnTableRVA = 0;      // 8*6 bytes: resolved instance fn pointers
    uint32_t vkCountRVA = 0;        // 8 bytes: physical-device count for enumerate
    uint32_t vkPhyBufRVA = 0;       // 16*8 bytes: VkPhysicalDevice handle array
    uint32_t vkPropsRVA = 0;        // 512 bytes: VkPhysicalDeviceProperties
    uint32_t vkZenithStrRVA = 0;    // .rdata "Zenith" app/engine name
    uint32_t vkDestroyStrRVA = 0;   // .rdata "vkDestroyInstance"
    uint32_t vkEnumPhyStrRVA = 0;   // .rdata "vkEnumeratePhysicalDevices"
    uint32_t vkPhyPropsStrRVA = 0;  // .rdata "vkGetPhysicalDeviceProperties"
    uint32_t vkDevProcStrRVA = 0;   // .rdata "vkGetDeviceProcAddr"
    void detectVkUsage();

    // ===== Linux Vulkan WSI surface (vk_surface_*, codegen_wl_wsi.cpp) =====
    // Full 2D/3D render path: libwayland-client + VK_KHR_surface/
    // VK_KHR_wayland_surface + VK_KHR_swapchain. Everything is created lazily
    // inside vk_surface_init(w, h); frame loop = vk_surface_frame().
    bool vkSurfaceUsed = false;
    void detectVkSurfaceUsage();
    bool tryLinuxVkSurfaceCall(CallExpr* call, int& resultReg);
    // --- Wayland connection state (real wl_display* from libwayland) ---
    uint32_t wlSfcDisplayRVA = 0;   // 8B: wl_display*
    uint32_t wlSfcRegistryRVA = 0;  // 8B: wl_registry*
    uint32_t wlSfcCompositorRVA = 0;// 8B: wl_compositor*
    uint32_t wlSfcSurfaceRVA = 0;   // 8B: wl_surface*
    uint32_t wlSfcNameRVA = 0;      // 4B: registry name of wl_compositor
    // --- Vulkan surface/device/swapchain state ---
    uint32_t vkSfcSurfaceRVA = 0;   // 8B: VkSurfaceKHR
    uint32_t vkSfcGpuRVA = 0;       // 8B: VkPhysicalDevice
    uint32_t vkSfcQueueFamilyRVA = 0;// 4B: graphics+present queue family
    uint32_t vkSfcDeviceRVA = 0;    // 8B: VkDevice
    uint32_t vkSfcQueueRVA = 0;     // 8B: VkQueue
    uint32_t vkSfcSwapchainRVA = 0; // 8B: VkSwapchainKHR
    uint32_t vkSfcFormatRVA = 0;    // 4B: VkSurfaceFormatKHR.format
    uint32_t vkSfcExtentRVA = 0;    // 8B: {w,h} current extent
    uint32_t vkSfcImageCountRVA = 0;// 4B: swapchain image count
    uint32_t vkSfcRenderPassRVA = 0;// 8B: VkRenderPass
    uint32_t vkSfcPipeRVA = 0;      // 8B: VkPipeline
    uint32_t vkSfcFrameImageRVA = 0;// 4B: last acquired image index
    uint32_t vkSfcFrameCBRVA = 0;   // 8B: active command buffer
    uint32_t vkSfcViewRVA = 0;      // 8B: image view (single-target milestone)
    uint32_t vkSfcFbRVA = 0;        // 8B: framebuffer
    uint32_t vkSfcCmdRVA = 0;       // 8B: command buffer handle
    uint32_t vkSfcVbufRVA = 0;      // 8B: vertex buffer
    uint32_t vkSfcVbufMemRVA = 0;   // 8B: vertex buffer device memory
    // --- device-level fn table + struct scratch arena ---
    uint32_t vkSfcDevTableRVA = 0;  // 8 * 32 bytes
    uint32_t vkSfcScratchRVA = 0;   // 4096 bytes: struct build arena
    // --- instance extension array (2 x 8B absolute pointers), patched in
    // vk_instance_create when vkSurfaceUsed is set ---
    uint32_t vkExtArrayRVA = 0;
    // --- .rdata strings ---
    uint32_t vkSurfaceKHRStrRVA = 0;
    uint32_t vkWaylandSurfaceStrRVA = 0;
    uint32_t vkSwapchainStrRVA = 0;
    uint32_t vkCreateSurfaceStrRVA = 0;
    uint32_t vkDestroySurfStrRVA = 0;
    uint32_t vkDestroyDeviceStrRVA = 0;
    uint32_t vkSurfaceProcsStrRVA[40] = {};
    // --- labels for the wayland registry listener callbacks ---
    int wlSfcRegGlobalLabel = -1;
    int wlSfcRegRemoveLabel = -1;

    // ===== SPIR-V shader builtins (shader()/shader_file(), codegen_shader.cpp) =====
    // shader("vertex", "<spvasm>") and shader_file("vertex", "path.spvasm")
    // return a pointer to a .rdata record {uint32 codeSize; uint32 words[];} —
    // the assembled binary SPIR-V module. Assembly happens at build time in
    // buildLinuxImportData (spv::assemble); the returned record is self-
    // describing so the WSI layer can feed pCode/codeSize to vkCreateShaderModule.
    struct ShaderRec { std::string key; std::string text; std::string kind; uint32_t rva = 0; };
    std::vector<ShaderRec> shaderRecs;   // collected by detectShaderUsage
    bool shaderUsed = false;
    void detectShaderUsage();
    void detectShaderExprUsage(Expr* expr);
    void detectShaderStmtUsage(Stmt* stmt);
    void registerShaderCall(CallExpr* call);   // collect (kind, text) during detect
    void emitShaderModules();            // buildLinuxImportData tail, see codegen_shader.cpp

    // ===== Linux Wayland (wl_* builtins, codegen_wl_linux.cpp) runtime slots =====
    // Raw AF_UNIX socket + hand-encoded Wayland wire protocol (no libwayland).
    bool wlUsed = false;            // true once any wl_* builtin is seen/emitted
    uint32_t wlEnvRVA = 0;          // 8 bytes: envp pointer (stashed by _start)
    uint32_t wlFdRVA = 0;           // 8 bytes: connected Wayland socket fd
    uint32_t wlPathRVA = 0;         // 128 bytes: sockaddr_un path buffer
    uint32_t wlInRVA = 0;           // 4096 bytes: event receive buffer
    uint32_t wlTmpRVA = 0;          // 32 bytes: decimal format scratch
    uint32_t wlXdgRVA = 0;          // .rdata "XDG_RUNTIME_DIR="
    uint32_t wlSfxRVA = 0;          // .rdata "/wayland-0"
    uint32_t wlColonRVA = 0;        // .rdata ":"
    uint32_t wlNlRVA = 0;           // .rdata "\n"
    uint32_t wlInitReqRVA = 0;      // .rdata 32B: get_registry+sync request blob
    // ---- Wayland window / shm-buffer state (codegen_wl_window.cpp) ----
    uint32_t wlWNameRVA = 0;        // 4B registry name: wl_compositor global
    uint32_t wlXdgNameRVA = 0;      // 4B registry name: xdg_wm_base global
    uint32_t wlShmNameRVA = 0;      // 4B registry name: wl_shm global
    uint32_t wlSurfIdRVA = 0;       // 4B wl_surface object id
    uint32_t wlXdgIdRVA = 0;        // 4B xdg_surface object id
    uint32_t wlTopIdRVA = 0;        // 4B xdg_toplevel object id
    uint32_t wlShmIdRVA = 0;        // 4B wl_shm object id
    uint32_t wlPoolIdRVA = 0;       // 4B wl_shm_pool object id
    uint32_t wlBufIdRVA = 0;        // 4B wl_buffer object id
    uint32_t wlFbPtrRVA = 0;        // 8B mmap'd shm framebuffer pointer
    uint32_t wlBufFdRVA = 0;        // 8B memfd of the shm pool
    uint32_t wlWinWRVA = 0;         // 4B window width (framebuffer)
    uint32_t wlWinHRVA = 0;         // 4B window height (framebuffer)
    uint32_t wlConfiguredRVA = 0;   // 4B xdg_surface configured flag
    uint32_t wlClosedRVA = 0;       // 4B close-requested flag (ready to stop)
    uint32_t wlOutRVA = 0;          // 256B request-build scratch buffer
    uint32_t wlCompositorStrRVA = 0;// .rdata "wl_compositor"
    uint32_t wlXdgWmBaseStrRVA = 0; // .rdata "xdg_wm_base"
    uint32_t wlShmStrRVA = 0;       // .rdata "wl_shm"
    uint32_t wlMemfdNameRVA = 0;    // .rdata "z-wl-fb"
    uint32_t wlAppIdRVA = 0;        // .rdata "zenith-app"
    bool tryLinuxWLWindowCall(CallExpr* call, int& resultReg); // codegen_wl_window.cpp
    void detectWLUsage();
    bool tryNetCall(CallExpr* call, int& resultReg);
    void emitNetWsaStartup();
    void detectNetSockExprUsage(Expr* expr);
    void detectNetSockStmtUsage(Stmt* stmt);
    void detectNetSockUsage();

    // ===== Sound builtins (sound_* 8/16/24-bit PCM synthesis + waveOut) =====
    enum SoundSlot {
        SND_OPENED = 0,  // 8 bytes: 1 once waveOutOpen() succeeded (lazy-open guard)
        SND_HWO,         // 8 bytes: waveOut handle returned by waveOutOpen()
        SND_FMT,         // 24 bytes: WAVEFORMATEX (18 used, 6 pad)
        SND_BPF,         // 8 bytes: bytes per frame (channels * bits/8)
        SND_HDR,         // 56 bytes: WAVEHDR (48 used, 8 pad); dwFlags at +24
        SND_SEED,        // 8 bytes: LCG seed for the noise waveform
        SND_LUT          // 1024 bytes: int16 sine LUT (512 entries)
    };
    struct SoundFixup { size_t codePos; uint8_t slot; };
    std::vector<SoundFixup> soundFixups;
    bool soundUsed = false;
    bool soundGenHelperEmitted = false;
    int soundGenHelperLabel = -1;
    bool soundMixHelperEmitted = false;
    int soundMixHelperLabel = -1;
    uint32_t soundOpenedRVA = 0;
    uint32_t soundHwoRVA = 0;
    uint32_t soundFmtRVA = 0;
    uint32_t soundBpfRVA = 0;
    uint32_t soundHdrRVA = 0;
    uint32_t soundSeedRVA = 0;
    uint32_t soundLutRVA = 0;
    bool trySoundCall(CallExpr* call, int& resultReg);
    void emitSoundGenHelper();
    void emitSoundMixHelper();
    void detectSoundExprUsage(Expr* expr);
    void detectSoundStmtUsage(Stmt* stmt);
    void detectSoundUsage();

    // ===== TLS builtins (tls_connect/send/recv/close/last_error) =====
    // The freestanding crypto/TLS blob in src/tls_blob.h is appended to the
    // .text section once (emitTlsBlob) and invoked through `call rel32` into
    // its entry point (tlsrt_entry, opcode dispatcher). The blob is SysV
    // internal and does synchronous socket I/O via io-slot function pointers
    // (send/recv/closesocket) that codegen injects with TLS_OP_IO_INIT once,
    // guarded by a .data flag — the same ASLR-safe pattern as net_*.
    enum TlsSlot {
        TLS_IO_DONE = 0  // 8 bytes: 1 once the blob io-slot table is seeded
    };
    struct TlsFixup { size_t codePos; uint8_t slot; };
    std::vector<TlsFixup> tlsFixups;
    bool tlsUsed = false;
    bool tlsBlobEmitted = false;
    int tlsEntryLabel = -1;
    uint32_t tlsIoDoneRVA = 0;
    bool tryTlsCall(CallExpr* call, int& resultReg);
    void emitTlsBlob();
    void emitTlsIoInit();
    void emitBlobEntryCall();
    void detectTlsExprUsage(Expr* expr);
    void detectTlsStmtUsage(Stmt* stmt);
    void detectTlsUsage();

    // ===== HTTP/S file-download builtins (http_download/_ask/_speed) =====
    // Linux only. The freestanding download engine in src/httpdl_blob.h (the
    // download client LINKED TOGETHER with the TLS core) is appended to .text
    // once (emitHttpDlBlob) and invoked through `call rel32` into its entry
    // point (httpdl_entry, opcode dispatcher). The blob does raw-syscall
    // DNS/TCP/HTTPS(file) I/O; .text must be RWX (its .bss lives inside the
    // image, like the TLS blob). Windows PE apps use the wininet-based
    // implementation in codegen.cpp instead and never reference this blob.
    //   http_download(url, file)        -> int (0 ok | <0 error)
    //   http_download_ask(url, file)    -> int (1 user declined | 0 | <0)
    //   http_download_speed(url, file)  -> int (1 full speed declined | 0 | <0)
    bool httpDlUsed = false;
    bool httpDlBlobEmitted = false;
    int httpDlEntryLabel = -1;
    bool tryHttpDlCall(CallExpr* call, int& resultReg);
    void emitHttpDlBlob();
    void detectHttpDlExprUsage(Expr* expr);
    void detectHttpDlStmtUsage(Stmt* stmt);
    void detectHttpDlUsage();

    // ===== JS builtins (js_reset/js_eval/js_result/js_error over embedded JS blob) =====
    // Embeds tools/jsrt.c as a freestanding x86-64 blob (src/js_blob.h, SysV-internal
    // like the TLS blob). js_eval runs a JS program inside the blob's 4 MiB arena;
    // the arena lives in the blob's .bss which codegen emits (zeroed) right after the
    // blob in .text (made RWX by jsUsed). js_result/js_error copy the last
    // expression result / error string into .data slots the caller can read.
    //   js_reset()          -> int   (always 0; clears arena + globals)
    //   js_eval(code)       -> int   (runs statements; 0 on ok)
    //   js_result() -> str   (string form of the last evaluated expression)
    //   js_error()  -> str   (last error text, usually empty)
    struct JsFixup {
        size_t codePos;
        enum Slot { JS_SLOT_RESULT, JS_SLOT_ERROR };
        Slot slot;
    };
    std::vector<JsFixup> jsFixups;
    bool jsUsed = false;
    bool jsBlobEmitted = false;
    int jsEntryLabel = -1;
    uint32_t jsResultRVA = 0;
    uint32_t jsErrorRVA = 0;
    // JS host callbacks (jsrt.c g_host_fn table): the .z app never touches these
    // directly — js_eval installs the 13 stubs below via JS_OP_SET_HOST once,
    // guarded by an RWX flag byte living in .text (self-referential RIP-relative).
    int jsHostFlagLabel = -1;             // label of the "hosts installed" guard byte
    int jsHostStubLabel[13];              // label of each emitted host stub
    int jsWsaFlagLabel = -1;              // WSAStartup-once guard (net_connect stub)
    int jsWsadataLabel = -1;              // WSADATA scratch (416 B) for the stub
    int jsAddrLabel = -1;                 // sockaddr_in scratch for the stub
    void emitJsHostStubs();
    bool tryJsCall(CallExpr* call, int& resultReg);
    void emitJsBlob();
    void emitJsEntryCall();
    void detectJsExprUsage(Expr* expr);
    void detectJsStmtUsage(Stmt* stmt);
    void detectJsUsage();

    // ===== Disasm builtins (disasm/decompile over embedded disassembler blob) =====
    // Embeds tools/disasm_blob.cpp as a freestanding x86-64 blob
    // (src/disasm_blob.h). The blob is SysV-internal like the TLS/JS blobs and
    // decodes raw x86-64 into Intel or AT&T assembly text; it keeps two mode
    // globals (g_intel/g_addrPfx) in its own .data (appended right after its
    // code inside .text, made RWX by disasmUsed) so entry can switch syntax/
    // address prefixes per call without any external state.
    //   disasm(src, srclen, base, cap[, syntax[, flags]]) -> bytes needed | 0
    //       (op 1: decode the whole range into the ctx buffer)
    //   disasm(src, srclen, base, cap, syntax, flags) overload resolved by arity.
    struct DisFixup { size_t codePos; };
    bool disasmUsed = false;
    bool disasmBlobEmitted = false;
    int disasmEntryLabel = -1;
    bool tryDisasmCall(CallExpr* call, int& resultReg);
    void emitDisasmBlob();
    void emitDisasmEntryCall();
    void detectDisasmExprUsage(Expr* expr);
    void detectDisasmStmtUsage(Stmt* stmt);
    void detectDisasmUsage();

    std::vector<GlobalFixup> globalFixups;
    uint32_t globalsRVA = 0;
    int globalsSize = 0;
    std::unordered_map<std::string, int> globalOffsets;

    std::vector<uint8_t> gopGuidBlob;  // EFI GOP GUID bytes appended after the entry point (EFI apps)

    // ===== EFI entry-point diagnostics (serial COM1 + firmware ConOut) =====
    // Early-boot markers make real-hardware black screens debuggable: every
    // stage logs over 0x3F8 and prints a short status line through the
    // firmware console BEFORE the kernel owns the machine.
    struct EfiStrFixup { size_t codePos; std::string text; };
    std::vector<EfiStrFixup> efiStrFixups;  // lea rip-disps patched against UTF-16 blobs
    void emitEfiSerialInit();
    void emitEfiSerialChar(uint8_t c);
    void emitEfiSerialStr(const char* s);
    void emitEfiSerialHexEax();  // TEMP debug: hex-dump EAX over COM1
    void emitEfiConOut(const char* ascii);
    void emitEfiPanicTail();  // stall ~5s -> ResetSystem(warm) -> cli/hlt loop

    size_t wndProcOffset = 0;
    uint32_t classNameRVA = 0;
    uint32_t fontRVA = 0;      // 5x7 font blob in .rdata (GUI tool apps)
    uint32_t fontCyrRVA = 0;   // 8x16 Cyrillic font blob in .rdata (EFI gop_print)
    void emitWndProc();

    uint32_t iatRVA = 0;
    uint32_t dataRVA = 0x20000;

    uint32_t textRVA = 0x1000;
    uint32_t rdataRVA = 0x10000;

    std::unordered_map<std::string, StructLayout> structLayouts;
    void computeStructLayouts();
    void allocateBlockVars(const Block& block);

    struct ImportEntry {
        std::string funcName;
        std::string hintName;
        uint32_t hintNameRVA;
        uint32_t iatRVA;
    };
    struct ImportDLL {
        std::string dllName;
        std::vector<ImportEntry> entries;
        uint32_t descriptorRVA;
        uint32_t nameRVA;
        uint32_t iltRVA;
    };
    std::vector<ImportDLL> importDLLs;
    std::unordered_map<std::string, std::pair<std::string, uint32_t>> externFuncMap;

    struct EmbeddedDLL {
        std::string dllName;
        std::string moduleName;
        std::vector<uint8_t> bytes;
        struct FuncInfo { std::string name; };
        std::vector<FuncInfo> funcs;
        uint32_t blobRVA = 0;
        uint32_t blobSize = 0;
        uint32_t dllPathStrRVA = 0;
        std::vector<uint32_t> funcNameRVAs;
        std::vector<uint32_t> funcPtrRVAs;
    };
    std::vector<EmbeddedDLL> embeddedDLLs;
    uint32_t embeddedFullPathRVA = 0;
    uint32_t embeddedHFileRVA = 0;
    uint32_t embeddedHModuleRVA = 0;
    uint32_t embeddedWrittenRVA = 0;

    void readEmbeddedLibs();
    void emitEmbeddedLoader();

    uint32_t importDescCount = 0;
    uint32_t importDataSize = 0;

    std::filesystem::path compilerDir;
    std::filesystem::path outputDir;

    // ===== DWARF debug-symbol state (codegen_dwarf.cpp) =====
    // Collected during emitFunction/emitStmt and turned into a standalone
    // .debug sidecar after the container (PE/ELF) has been written. Offsets
    // are relative to the start of .text (code[0]); the writer adds the
    // per-target load address.
    struct DbgSubprogram {
        std::string name;
        size_t start = 0;   // code offset of the function prologue
        size_t end = 0;     // code offset just past the function epilogue
        int line = 0;
    };
    struct DbgLineEntry {
        size_t offset = 0;  // code offset of the first instruction of the statement
        int line = 0;
    };
    std::vector<DbgSubprogram> dbgSubprograms;
    std::vector<DbgLineEntry> dbgLines;
    std::string sourcePath;
    void writeDebugInfo(uint64_t imageBase, const std::string& outputPath);
};

// ===== httpjson_rt.cpp =====
// Builds the position-independent x86-64 routine that converts a fetched
// HTTP response (status + body + raw headers) into the 'ZJSN' JSON record.
std::vector<uint8_t> buildHttpJsonHelper(uint32_t jsonMax, uint32_t headMax);
