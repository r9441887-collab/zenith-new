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
    bool isLibrary = false;
    bool libOutput = false;
    bool embedDLLs = false;
    bool flatOutput = false;

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

    // ===== codegen_wasm.cpp =====
    // Emits a WebAssembly binary module for 'app wasm'.
    bool compileWasm(const std::string& outputPath);

    // ===== codegen_sw.cpp =====
    void emitSWInit();
    void emitSWPresent();
    void emitSWCleanup();

    void emit8(uint8_t b);

private:
    void emit16(uint16_t v);
    void emit32(uint32_t v);
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
    void emitGlobalStoreReg64(int offset);
    void emitGlobalStoreReg32(int offset);
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
    std::vector<EmbeddedLEAFixup> embeddedLEAFixups;
    std::vector<CallFixup> callFixups;
    std::vector<FuncRefFixup> funcRefFixups;
    std::vector<JmpFixup> jmpFixups;
    std::vector<StrFixup> strFixups;
    std::vector<ImportCallFixup> importCallFixups;
    void resolveFixups();
    void resolveJmpFixups();
    void computeSectionRVAs();
    uint32_t estimateRdataSize();
    uint32_t estimateDataSize();

    void buildImportData();
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
};

// ===== httpjson_rt.cpp =====
// Builds the position-independent x86-64 routine that converts a fetched
// HTTP response (status + body + raw headers) into the 'ZJSN' JSON record.
std::vector<uint8_t> buildHttpJsonHelper(uint32_t jsonMax, uint32_t headMax);
