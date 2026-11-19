#pragma once

// ---------------------------------------------------------------------------
// Temporary C ABI between the .z driver (src/main.z) and the C++ compiler core.
//
// This header exists only while the AST pipeline is being rewritten in
// Zenith. Each zffi_* entry point is a stand-in for a backend that has not
// landed yet:
//
//     zffi_parse          -> selfhost front end (already .z, reached via
//                            parseobj.o; this just marshals the blob)
//     zffi_configure      -> the "middle of main.cpp" (arch/app validation)
//     zffi_bugfind        -> src/bugfind.cpp       -> bugfind.z
//     zffi_optimize       -> src/optimizer.cpp     -> optimizer.z
//     zffi_codegen        -> src/codegen*.cpp      -> codegen.z + backends
//     zffi_preprocess*    -> src/use_resolver.cpp  -> include/use in .z
//     zffi_readFile       -> file builtins         -> pure .z
//     zffi_disasm         -> src/cmd_disasm.cpp    -> stays C++ (blob decoder)
//
// When a backend is rewritten it defines the same symbol, the C++
// implementation is deleted per the cleanup rule in PLAN.md, and this header
// shrinks by one declaration. Nothing in src/main.z changes.
//
// String convention: every `char** out` is a malloc'd, NUL-terminated buffer
// the caller must release with zffi_release(). `const char*` returns are owned
// by the callee and stay valid until the next zffi_* call.
// ---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zprog zprog;   // opaque Program

// ---- last error of the failing zffi_* call ("" when there was none) ----
const char* zffi_err(void);

// ===========================================================================
// Text stage
// ===========================================================================

// Reads a whole file. Returns 0 and a malloc'd buffer, or 1 (zffi_err()).
int  zffi_readFile(const char* path, char** out, long long* outLen);
void zffi_release(char* p);

// Reads every input file and merges them into one buffer, in array order,
// separated by '\n' — `zenith a.z b.z` compiles the list as a single unit.
int  zffi_readFiles(const char* const* files, int n, char** out,
                    long long* outLen);

// Recursively splices `include "file.z"` into one compilation unit. `filePath`
// is the entry source (it seeds the circular-include stack, and its directory
// resolves relative includes), exactly as main.cpp did it.
int zffi_preprocessIncludes(const char* src, int len, const char* filePath,
                            char** out);

// Expands `use <module>` (the standard library) for the given app type.
int zffi_expandUse(const char* src, int len, const char* baseDir,
                   const char* appType, char** out);

// '# [no_main]' anywhere in the source.
int zffi_hasNoMain(const char* src, int len);

// 'app <type>' directive on raw text; 1 when found and copied into out.
int zffi_scanAppType(const char* src, int len, char* out, int cap);

// ===========================================================================
// Front end
// ===========================================================================

// rc: 0 ok, 1 lexer overflow, 2 lexer token error, 3 parse error.
// On failure zffi_parseErr() / zffi_parseLine() describe it.
int        zffi_parse(const char* src, int len, zprog** out);
const char* zffi_parseErr(void);
long long   zffi_parseLine(void);

// ===========================================================================
// Configuration — the part of main.cpp that only mutates the Program
// ===========================================================================

#define Z_CFG_OBJ      1   // --obj: relocatable ET_REL output
#define Z_CFG_LIB      2   // --lib / --libs
#define Z_CFG_NO_MAIN  4   // source carries '# [no_main]'

// Applies the CLI arch flag, resolves Auto, validates app/arch combinations
// and the Android API levels, and sets isLibrary / objOutput / koDriver.
// archOpt: "" | "32bit" | "64bit" | "arm" | "arm64". 0 ok, 1 error.
int zffi_configure(zprog*, int flags, const char* archOpt);

// Program properties the driver needs for output naming and its own checks.
// AppType ids match enum class AppType in src/ast.h, in declaration order.
#define Z_APP_CONSOLE 0
#define Z_APP_GUI     1
#define Z_APP_EFI     2
#define Z_APP_BIOS    3
#define Z_APP_BARE    4
#define Z_APP_STM32   5
#define Z_APP_ARM64   6
#define Z_APP_WASM    7
#define Z_APP_LINUX   8
#define Z_APP_ANDROID 9

// Arch ids match enum class Arch in src/ast.h.
#define Z_ARCH_AUTO   0
#define Z_ARCH_X86_32 1
#define Z_ARCH_X86_64 2
#define Z_ARCH_ARM    3
#define Z_ARCH_ARM64  4

int zffi_appType(zprog*);
int zffi_arch(zprog*);
int zffi_real16(zprog*);
int zffi_kernelMode(zprog*);      // 0 independent, 1 dependent
int zffi_androidApi(zprog*);
int zffi_androidMinSdk(zprog*);
int zffi_hasFunctions(zprog*);
int zffi_isLibrary(zprog*);
int zffi_objOutput(zprog*);
int zffi_koDriver(zprog*);

// ===========================================================================
// Middle / back end
// ===========================================================================

// Static bug finder. Prints its own findings (stderr) and the one-line
// summary (stdout); returns 1 only when strict and something was found.
int zffi_bugfind(zprog*, const char* fileName, int enabled, int strict);

typedef struct {
    int removedFunctions;
    int removedGlobals;
    int removedStatements;
    int strengthReduced;
    int propagated;
} zoptstat;

// ---- C/C++ mixing (--cc / --cxx). Opaque mix::MixContext, same shape as
// zprog: the driver only drives it, all real work stays in C++. ----
#define Z_MIX_LINUX 0
#define Z_MIX_PE    1
#define Z_MIX_FLAT  2
#define Z_MIX_KO    3
#define Z_MIX_ARM64 4

void*       zffi_mixNew(int target, int cOptLevel);
int         zffi_mixAdd(void* ctx, const char* path, int isCpp);
int         zffi_mixPrelink(void* ctx);
int         zffi_mixHasAny(void* ctx);
int         zffi_mixHasCpp(void* ctx);
int         zffi_mixErrCount(void* ctx);
const char* zffi_mixErr(void* ctx, int i);
int         zffi_mixUndefCount(void* ctx, int isData);
const char* zffi_mixUndef(void* ctx, int isData, int i);
const char* zffi_mixDllFor(void* ctx, const char* sym);
// Applies the remaining main.cpp step (PE extern injection) and hands the
// context to codegen; ownership stays here.
int         zffi_mixFinish(void* ctx, zprog* p);

// ---- 'zenith build' (workspace.zen multi-file projects) ----
void* zffi_setNew(void);
// read + splice includes + expand `use`, exactly as main.cpp prepareSource().
// On a hard error this reports and exits(1), like the C++ did.
int   zffi_prepareSource(const char* filePath, const char* appType,
                         void* seen, char** out);
// Sorted list of *.z regular files in `dir`; -1 when `dir` is missing or is
// not a directory. Fills `out[0..return)` with heap copies the caller keeps.
long long zffi_listZ(const char* dir, long long* out, int max);
// main.cpp readFile(): empty string instead of an error when unreadable.
int   zffi_readFileQuiet(const char* path, char** out, long long* outLen);
void  zffi_setIsLibrary(zprog*, int v);
int   zffi_bugfindMap(zprog*, const char* fileName,
                      const char* const* lineMap, int lineMapN,
                      int enabled, int strict);
void* zffi_blobNew(void);
void  zffi_blobBytes(void* b, const void* p, int n);
void  zffi_blobU32(void* b, unsigned v);
int   zffi_blobWrite(void* b, const char* path);
void  zffi_blobFree(void* b);
int   zffi_remove(const char* path);
int   zffi_rmdirIfEmpty(const char* path);

// Dead-code / size / speed passes. keepAll pins every function (mixing and
// --obj have no entry point the DCE can seed from). Result is valid until
// the next zffi_optimize call.
const zoptstat* zffi_optimize(zprog*, int optLevel, int allowPow2Div,
                              int keepAll, int buildMode);

#define Z_CG_DEBUG   1   // -g / --debug (the driver already vetted the target)
#define Z_CG_EMBED   2   // --embed
#define Z_CG_LIB     4   // '[no_main]' / --lib: emit a library
#define Z_CG_LIBOUT  8   // --lib: custom .so output (codegen.libOutput)

// Runs Codegen. isoPath, when non-null, additionally wraps the result into a
// bootable ISO -- after the --iso validation below, exactly where main.cpp
// does it. Returns 0 ok, 1 codegen error, 2 post-codegen validation error
// (zffi_err(); main.cpp prints both with its own prefix).
int zffi_codegen(zprog*, const char* outPath, const char* srcPath,
                 const char* exeDir, const char* isoPath, int flags);
int zffi_codegen(zprog*, const char* outPath, const char* srcPath,
                 const char* exeDir, const char* isoPath, int flags);

void zffi_free(zprog*);

// ===========================================================================
// Utilities the driver cannot own
// ===========================================================================

const char* zffi_version(void);
int         zffi_disasm(int argc, char** argv);

// Directory containing the running compiler executable.
const char* zffi_exeDir(void);

// fs::create_directories, for --libs. 0 ok, 1 error (zffi_err()).
int zffi_mkdir(const char* path);

// Raw write(1, ...) — stdout without the newline that .z's print/println
// always append, so the driver can emit `a << b << std::endl`-style lines.
void        zffi_out(const char* s);

// ---- 'zenith new' ----
const char* zffi_cwd(void);                          // fs::current_path()
int         zffi_exists(const char* path);           // fs::exists
int         zffi_writeFile(const char* path, const char* content);  // 0/1 (zffi_err())

// ---- '--watch' (live reload) ----
long long   zffi_mtime(const char* path);            // st_mtime, 0 when missing
long long   zffi_launch(char** argv);                // fork+execvp -> pid, -1
long long   zffi_wait(int pid);                      // waitpid -> exit code, -1
void        zffi_kill(int pid);                      // SIGKILL + waitpid
void        zffi_sleepMs(int ms);

#ifdef __cplusplus
}
#endif
