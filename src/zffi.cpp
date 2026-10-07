// ---------------------------------------------------------------------------
// Temporary C ABI implementation: the C++ compiler core behind src/zffi.h.
//
// Every function here is a verbatim transplant of a fragment of the old
// src/main.cpp, kept byte-for-byte in behaviour so that zenith and zenith-z
// agree. Delete the matching function as its .z replacement lands (PLAN.md,
// "правило чистки"): what is left at the end is only the pure decoders that
// never move to Zenith.
// ---------------------------------------------------------------------------

#include "zffi.h"

#include "ast.h"
#include "bugfind.h"
#include "codegen.h"
#include "mix.h"
#include "optimizer.h"
#include "parseembed.h"
#include "use_resolver.h"
#include "main.h"

#include <unistd.h>
#include <csignal>
#include <sys/stat.h>
#include <sys/wait.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::string gErr;
static std::string gParseErr;
static long long gParseLine = 0;
static zoptstat gOpt;
static std::string gExeDir;

static char* dupBuf(const std::string& s) {
    char* p = (char*)std::malloc(s.size() + 1);
    if (!p) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

const char* zffi_err(void) { return gErr.c_str(); }

void zffi_release(char* p) { std::free(p); }

// ===========================================================================
// Text stage — src/main.cpp helpers, transplanted
// ===========================================================================

static bool readFileInto(const std::string& path, std::string& out, std::string& err) {
    std::ifstream f{path, std::ios::binary};
    if (!f.is_open()) {
        err = "cannot open file '" + path + "'";
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    // Strip UTF-8 BOM if present
    if (out.size() >= 3 &&
        (uint8_t)out[0] == 0xEF && (uint8_t)out[1] == 0xBB && (uint8_t)out[2] == 0xBF) {
        out = out.substr(3);
    }
    return true;
}

int zffi_readFile(const char* path, char** out, long long* outLen) {
    gErr.clear();
    std::string content, err;
    if (!readFileInto(path ? path : "", content, err)) {
        gErr = err;
        return 1;
    }
    char* p = dupBuf(content);
    if (!p) {
        gErr = "out of memory";
        return 1;
    }
    *out = p;
    if (outLen) *outLen = (long long)content.size();
    return 0;
}

// Strip top-level directives ('app', 'kernel_mode', 'asm_word_size',
// '@import', '# [no_main]') from an included file: only the main source file
// is allowed to define the application type.
static std::string stripHeaderDirectives(const std::string& content) {
    std::istringstream iss(content);
    std::string line, out;
    bool first = true;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        bool directive =
            (trimmed.rfind("app ", 0) == 0 || trimmed == "app" ||
             trimmed.rfind("kernel_mode", 0) == 0 ||
             trimmed.rfind("asm_word_size", 0) == 0 ||
             trimmed.rfind("@import", 0) == 0 ||
             trimmed.rfind("# [no_main]", 0) == 0);
        if (directive) continue;
        if (!first) out += "\n";
        out += line;
        first = false;
    }
    return out;
}

// Recursively splice `include "file.z"` lines. Included files are merged
// textually into one compilation unit, so their functions/globals become part
// of the same binary (one .efi), not copied or dynamically linked.
static bool preprocessIncludes(const std::string& source, const fs::path& dir,
                               int depth, std::vector<std::string>& stack,
                               std::set<std::string>& included,
                               std::string& out, std::string& err) {
    if (depth > 16) {
        err = "include nesting too deep (circular include?)";
        return false;
    }
    std::istringstream iss(source);
    std::string line;
    bool first = true;
    out.clear();
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        if (trimmed.rfind("include ", 0) == 0) {
            size_t q1 = trimmed.find('"');
            size_t q2 = trimmed.rfind('"');
            if (q1 == std::string::npos || q2 == std::string::npos || q2 <= q1) {
                err = "bad include syntax (expected: include \"file.z\"): " + trimmed;
                return false;
            }
            std::string incPath = trimmed.substr(q1 + 1, q2 - q1 - 1);
            fs::path full = dir.empty() ? fs::path(incPath) : (dir / incPath);
            std::string cano = full.string();
            for (auto& p : stack) {
                if (p == cano) {
                    err = "circular include of '" + cano + "'";
                    return false;
                }
            }
            std::string content, rerr;
            if (!readFileInto(full.string(), content, rerr)) {
                err = rerr;
                return false;
            }
            std::string cano2 = full.lexically_normal().string();
            if (included.count(cano2)) continue;   // include guard: splice once
            stack.push_back(cano);
            std::string processed;
            bool ok = preprocessIncludes(stripHeaderDirectives(content),
                                         full.parent_path(), depth + 1, stack,
                                         included, processed, err);
            stack.pop_back();
            if (!ok) return false;
            included.insert(cano2);
            if (!first) out += "\n";
            out += "# include: " + incPath + "\n" + processed;
            first = false;
            continue;
        }
        if (!first) out += "\n";
        out += line;
        first = false;
    }
    return true;
}

int zffi_preprocessIncludes(const char* src, int len, const char* filePath,
                            char** out) {
    gErr.clear();
    std::vector<std::string> stack;
    std::set<std::string> included;
    if (!src) { gErr = "no source"; return 1; }
    fs::path entry(filePath ? filePath : "");
    fs::path dir = entry.parent_path();
    std::string source(src, (size_t)(len < 0 ? (int)std::strlen(src) : len));
    stack.push_back(entry.string());
    std::string result, err;
    if (!preprocessIncludes(source, dir, 0, stack, included, result, err)) {
        gErr = err;
        return 1;
    }
    char* p = dupBuf(result);
    if (!p) { gErr = "out of memory"; return 1; }
    *out = p;
    return 0;
}

int zffi_expandUse(const char* src, int len, const char* baseDir,
                   const char* appType, char** out) {
    gErr.clear();
    if (!src) { gErr = "no source"; return 1; }
    std::string source(src, (size_t)(len < 0 ? (int)std::strlen(src) : len));
    std::string base = (baseDir && *baseDir) ? baseDir : ".";
    std::string err;
    if (!expandUseDirectives(source, base, appType ? appType : "", err)) {
        gErr = err;
        return 1;
    }
    char* p = dupBuf(source);
    if (!p) { gErr = "out of memory"; return 1; }
    *out = p;
    return 0;
}

int zffi_hasNoMain(const char* src, int len) {
    if (!src) return 0;
    std::string source(src, (size_t)(len < 0 ? (int)std::strlen(src) : len));
    bool inString = false;
    bool inLineComment = false;
    for (size_t i = 0; i < source.size(); i++) {
        char c = source[i];
        if (inLineComment) {
            if (c == '\n') inLineComment = false;
            continue;
        }
        if (inString) {
            if (c == '\\') { i++; continue; }
            if (c == '"') inString = false;
            continue;
        }
        if (c == '"') { inString = true; continue; }
        if (c == '#') {
            size_t j = i + 1;
            while (j < source.size() && (source[j] == ' ' || source[j] == '\t')) j++;
            if (source.substr(j, 9) == "[no_main]") return true;
            while (j < source.size() && source[j] != '\n') {
                if (source[j] == '[' && source.substr(j, 9) == "[no_main]") return true;
                j++;
            }
        }
    }
    return 0;
}

int zffi_scanAppType(const char* src, int len, char* out, int cap) {
    if (!src || !out || cap <= 0) return 0;
    std::string source(src, (size_t)(len < 0 ? (int)std::strlen(src) : len));
    std::istringstream in(source);
    std::string line;
    while (std::getline(in, line)) {
        size_t i = line.find_first_not_of(" \t\r");
        if (i == std::string::npos) continue;
        std::string t = line.substr(i);
        if (t.rfind("app ", 0) != 0) continue;
        std::istringstream ls(t.substr(4));
        std::string type;
        ls >> type;
        if (type.empty()) return 0;
        size_t n = type.size() < (size_t)(cap - 1) ? type.size() : (size_t)(cap - 1);
        std::memcpy(out, type.data(), n);
        out[n] = '\0';
        return 1;
    }
    return 0;
}

// ===========================================================================
// Front end
// ===========================================================================

int zffi_parse(const char* src, int len, zprog** out) {
    gParseErr.clear();
    gParseLine = 0;
    if (!src) { gParseErr = "no source"; return 3; }
    std::string source(src, (size_t)(len < 0 ? (int)std::strlen(src) : len));
    Program* prog = new Program();
    long long line = 0;
    int rc = parseZ(source, *prog, gParseErr, line);
    gParseLine = line;
    if (rc != 0) {
        delete prog;
        *out = nullptr;
        return rc;
    }
    *out = (zprog*)prog;
    return 0;
}

const char* zffi_parseErr(void) { return gParseErr.c_str(); }
long long   zffi_parseLine(void) { return gParseLine; }

// ===========================================================================
// Configuration — the middle of src/main.cpp
// ===========================================================================

int zffi_configure(zprog* p, int flags, const char* archOpt) {
    Program& prog = *(Program*)p;
    gErr.clear();

    prog.isLibrary = (flags & Z_CFG_NO_MAIN) || (flags & Z_CFG_LIB);

    if (flags & Z_CFG_OBJ) {
        prog.objOutput = true;
        prog.koDriver = true;
        if (prog.appType != AppType::Linux) {
            gErr = "--obj emits a Linux ELF object (ET_REL); "
                   "the source must be 'app linux' or 'app console' on a Linux host.\n";
            return 1;
        }
    }

    Arch cliArch = Arch::Auto;
    if (archOpt && *archOpt) {
        if (!std::strcmp(archOpt, "32bit")) cliArch = Arch::X86_32;
        else if (!std::strcmp(archOpt, "64bit")) cliArch = Arch::X86_64;
        else if (!std::strcmp(archOpt, "arm")) cliArch = Arch::ARM;
        else if (!std::strcmp(archOpt, "arm64")) cliArch = Arch::ARM64;
        else { gErr = std::string("unknown architecture option '") + archOpt + "'"; return 1; }
    }
    if (cliArch != Arch::Auto) prog.arch = cliArch;

    if (prog.arch == Arch::Auto) {
        if (prog.appType == AppType::STM32) prog.arch = Arch::ARM;
        else if (prog.appType == AppType::BIOS) prog.arch = Arch::X86_32;
        else if (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent)
            prog.arch = Arch::X86_32;
        else if (prog.appType == AppType::ARM64) prog.arch = Arch::ARM64;
        else if (prog.appType == AppType::Android) prog.arch = Arch::ARM64;
        else prog.arch = Arch::X86_64;
    } else {
        if (prog.appType == AppType::STM32 && prog.arch != Arch::ARM) {
            gErr = "'app stm32' requires Arch::ARM (Cortex-M)";
            return 1;
        }
        if (prog.appType == AppType::BIOS && prog.arch != Arch::X86_32) {
            gErr = "'app bios' requires --32bit (BIOS runs in 32-bit mode)";
            return 1;
        }
        if (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent &&
            prog.arch != Arch::X86_32) {
            gErr = "'app bare' with 'kernel_mode: dependent' requires --32bit "
                   "(needs 32-bit for BIOS calls)";
            return 1;
        }
        if (prog.appType == AppType::EFI && prog.arch != Arch::X86_64) {
            gErr = "'app efi' requires --64bit (UEFI is 64-bit)";
            return 1;
        }
        if (prog.appType == AppType::ARM64 && prog.arch != Arch::ARM64) {
            gErr = "'app arm64' requires --arm64 (UEFI/ARM64 is 64-bit)";
            return 1;
        }
        if (prog.appType == AppType::Android && prog.arch != Arch::ARM64) {
            gErr = "'app android' requires --arm64 (only the arm64-v8a ABI is supported)";
            return 1;
        }
    }

    if (prog.appType == AppType::Android) {
        if (prog.androidApiLevel < 21) {
            gErr = "api_level " + std::to_string(prog.androidApiLevel) +
                   " is below Android's first 64-bit level (21); "
                   "arm64-v8a requires api_level >= 21";
            return 1;
        }
        if (prog.androidMinSdk > prog.androidApiLevel) {
            gErr = "min_sdk (" + std::to_string(prog.androidMinSdk) +
                   ") is higher than api_level (" + std::to_string(prog.androidApiLevel) + ")";
            return 1;
        }
        if (prog.androidMinSdk < 21) {
            gErr = "min_sdk " + std::to_string(prog.androidMinSdk) +
                   " is below Android's first 64-bit level (21); "
                   "arm64-v8a requires min_sdk >= 21";
            return 1;
        }
    }
    return 0;
}

int zffi_appType(zprog* p) { return (int)((Program*)p)->appType; }
int zffi_arch(zprog* p) { return (int)((Program*)p)->arch; }
int zffi_real16(zprog* p) { return ((Program*)p)->real16 ? 1 : 0; }
int zffi_kernelMode(zprog* p) { return (int)((Program*)p)->kernelMode; }
int zffi_androidApi(zprog* p) { return (int)((Program*)p)->androidApiLevel; }
int zffi_androidMinSdk(zprog* p) { return (int)((Program*)p)->androidMinSdk; }
int zffi_hasFunctions(zprog* p) { return ((Program*)p)->functions.empty() ? 0 : 1; }
int zffi_objOutput(zprog* p) { return ((Program*)p)->objOutput ? 1 : 0; }
int zffi_koDriver(zprog* p) { return ((Program*)p)->koDriver ? 1 : 0; }
int zffi_isLibrary(zprog* p) { return ((Program*)p)->isLibrary ? 1 : 0; }

// ===========================================================================
// Middle / back end
// ===========================================================================

int zffi_bugfind(zprog* p, const char* fileName, int enabled, int strict) {
    if (!enabled) return 0;
    Program& prog = *(Program*)p;
    std::vector<std::string> warns;
    int n = runBugFind(prog, fileName ? fileName : "", warns, nullptr);
    for (auto& w : warns) std::cerr << w << std::endl;
    if (n > 0) {
        std::cout << "Bug check: " << n << " potential bug(s) found" << std::endl;
        if (strict) return 1;
    }
    return 0;
}

// Mixed-in C/C++ objects are linked after the optimizer runs, so they may
// reference any .z function (and any synthetic PE import stub) the DCE has
// not seen a use for. Same rule as main.cpp.
static mix::MixContext* g_mix = nullptr;

const zoptstat* zffi_optimize(zprog* p, int optLevel, int allowPow2Div,
                              int keepAll, int buildMode) {
    Program& prog = *(Program*)p;
    std::memset(&gOpt, 0, sizeof gOpt);

    OptLevel cliLevel = (optLevel >= 0) ? (OptLevel)optLevel
                      : (prog.appType == AppType::STM32 ? OptLevel::Max : OptLevel::Basic);

    Optimizer optimizer;
    if (keepAll || (g_mix && g_mix->hasAny)) {
        for (auto& f : prog.functions) {
            if (f->isExtern) optimizer.keepExterns.insert(f->name);
            else optimizer.preserveFuncs.insert(f->name);
        }
    }

    OptResult r = optimizer.optimize(prog, cliLevel, allowPow2Div != 0);
    for (auto& w : r.warnings) std::cerr << w << std::endl;
    if (r.removedFunctions > 0 || r.removedGlobals > 0) {
        std::cout << "Optimized: removed " << r.removedFunctions << " function(s), "
                  << r.removedGlobals << " global(s)" << std::endl;
    }
    // 'zenith build' prints a shorter size-mode line (no strength/propagated
    // counters) and no STM32 line -- main.cpp cmdBuild.
    if (buildMode) {
        if (r.removedStatements > 0) {
            std::cout << "Optimized (size mode): folded/removed " << r.removedStatements
                      << " statement(s)" << std::endl;
        }
    } else if (r.removedStatements > 0 || r.strengthReduced > 0 || r.propagated > 0) {
        std::cout << "Optimized (size mode): folded/removed " << r.removedStatements
                  << " statement(s), strength-reduced " << r.strengthReduced
                  << ", propagated " << r.propagated << std::endl;
    }
    if (!buildMode && optLevel >= 0 && prog.appType == AppType::STM32) {
        std::cout << "STM32 optimization level: -" << (int)cliLevel << "r" << std::endl;
    }

    gOpt.removedFunctions   = r.removedFunctions;
    gOpt.removedGlobals     = r.removedGlobals;
    gOpt.removedStatements  = r.removedStatements;
    gOpt.strengthReduced    = r.strengthReduced;
    gOpt.propagated         = r.propagated;
    return &gOpt;
}

// ---- 'zenith build' ----
namespace {
// main.cpp readFile(): an unreadable file is an empty string, not an error.
bool readFileQuietInto(const char* path, std::string& out) {
    out.clear();
    if (!path) return false;
    std::ifstream f(std::string(path), std::ios::binary);
    if (!f.is_open()) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}
}  // namespace

void* zffi_setNew(void) { return new std::set<std::string>(); }

int zffi_prepareSource(const char* filePath, const char* appType,
                       void* seen, char** out) {
    gErr.clear();
    if (!out) return 1;
    *out = nullptr;
    std::set<std::string>* seenSet = (std::set<std::string>*)seen;
    std::set<std::string> ownGuard;
    std::set<std::string>& incGuard = seenSet ? *seenSet : ownGuard;
    std::string content;
    readFileQuietInto(filePath, content);
    fs::path file(filePath ? filePath : "");
    std::vector<std::string> stack;
    stack.push_back(file.string());
    std::string src, err;
    if (!preprocessIncludes(content, file.parent_path(), 0, stack, incGuard,
                            src, err)) {
        // main.cpp preprocessIncludes() reports and exit(1)s itself.
        std::cerr << "Error: " << err << std::endl;
        exit(1);
    }
    std::string useErr;
    fs::path base = file.parent_path();
    if (!expandUseDirectives(src, base.empty() ? std::string(".") : base.string(),
                             appType ? appType : "", useErr, seenSet)) {
        std::cerr << "Error: " << (filePath ? filePath : "") << ": " << useErr
                  << std::endl;
        exit(1);
    }
    char* p = dupBuf(src);
    if (!p) { gErr = "out of memory"; return 1; }
    *out = p;
    return 0;
}

long long zffi_listZ(const char* dir, long long* out, int max) {
    gErr.clear();
    if (!dir || !out || max <= 0) return -1;
    std::error_code ec;
    fs::path d(dir);
    if (!fs::exists(d, ec) || !fs::is_directory(d, ec)) return -1;
    std::vector<std::string> files;
    for (auto it = fs::directory_iterator(d, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        if (it->path().extension() != ".z") continue;
        files.push_back(it->path().string());
    }
    std::sort(files.begin(), files.end());
    int n = 0;
    for (auto& f : files) {
        if (n >= max) break;
        char* c = strdup(f.c_str());
        if (!c) break;
        out[n++] = (long long)(intptr_t)c;
    }
    return n;
}

int zffi_readFileQuiet(const char* path, char** out, long long* outLen) {
    if (!out) return 1;
    *out = nullptr;
    if (outLen) *outLen = 0;
    std::string content;
    readFileQuietInto(path, content);
    char* p = dupBuf(content);
    if (!p) { gErr = "out of memory"; return 1; }
    *out = p;
    if (outLen) *outLen = (long long)content.size();
    return 0;
}

void zffi_setIsLibrary(zprog* p, int v) { ((Program*)p)->isLibrary = v != 0; }

int zffi_bugfindMap(zprog* p, const char* fileName,
                    const char* const* lineMap, int lineMapN,
                    int enabled, int strict) {
    if (!enabled) return 0;
    BugLineFileFn fn;
    if (lineMap && lineMapN > 0) {
        fn = [lineMap, lineMapN](int combinedLine) -> std::string {
            if (combinedLine > 0 && combinedLine - 1 < lineMapN &&
                lineMap[combinedLine - 1])
                return lineMap[combinedLine - 1];
            return "";
        };
    }
    Program& prog = *(Program*)p;
    std::vector<std::string> warns;
    int n = runBugFind(prog, fileName ? fileName : "", warns, fn);
    for (auto& w : warns) std::cerr << w << std::endl;
    if (n > 0) {
        std::cout << "Bug check: " << n << " potential bug(s) found" << std::endl;
        if (strict) return 1;
    }
    return 0;
}

// Little-endian byte accumulator for the ZLIBS DLL container.
void* zffi_blobNew(void) { return new std::string(); }
void zffi_blobBytes(void* b, const void* p, int n) {
    if (!b || !p || n <= 0) return;
    ((std::string*)b)->append((const char*)p, (size_t)n);
}
void zffi_blobU32(void* b, unsigned v) {
    if (!b) return;
    char le[4] = {(char)(v & 0xff), (char)((v >> 8) & 0xff),
                  (char)((v >> 16) & 0xff), (char)((v >> 24) & 0xff)};
    ((std::string*)b)->append(le, 4);
}
int zffi_blobWrite(void* b, const char* path) {
    gErr.clear();
    if (!b || !path) return 1;
    std::ofstream f(std::string(path), std::ios::binary | std::ios::trunc);
    if (!f.is_open()) { gErr = std::string("cannot create ") + path; return 1; }
    f.write(((std::string*)b)->data(), (std::streamsize)((std::string*)b)->size());
    if (!f.good()) { gErr = std::string("cannot write ") + path; return 1; }
    return 0;
}
void zffi_blobFree(void* b) { if (b) delete (std::string*)b; }

int zffi_remove(const char* path) {
    if (!path) return 0;
    std::error_code ec;
    fs::remove(fs::path(path), ec);
    return 0;
}
int zffi_rmdirIfEmpty(const char* path) {
    if (!path) return 0;
    std::error_code ec;
    fs::path d(path);
    if (!fs::exists(d, ec) || !fs::is_directory(d, ec)) return 0;
    bool empty = fs::directory_iterator(d, ec) == fs::directory_iterator();
    if (empty) fs::remove(d, ec);
    return 0;
}

void* zffi_mixNew(int target, int cOptLevel) {
    gErr.clear();
    mix::MixContext* c = new mix::MixContext();
    c->target = (mix::Target)target;
    c->cOptLevel = cOptLevel;
    return c;
}
int zffi_mixAdd(void* ctx, const char* path, int isCpp) {
    gErr.clear();
    std::string err;
    if (!((mix::MixContext*)ctx)->addSource(std::string(path ? path : ""),
                                            isCpp != 0, {}, err)) {
        gErr = err;
        return 1;
    }
    return 0;
}
int zffi_mixPrelink(void* ctx) {
    gErr.clear();
    std::string err;
    if (!((mix::MixContext*)ctx)->prelinkWindows(err)) { gErr = err; return 1; }
    return 0;
}
int zffi_mixHasAny(void* ctx) { return ((mix::MixContext*)ctx)->hasAny ? 1 : 0; }
int zffi_mixHasCpp(void* ctx) { return ((mix::MixContext*)ctx)->hasCpp ? 1 : 0; }
int zffi_mixErrCount(void* ctx) {
    return (int)((mix::MixContext*)ctx)->errors.size();
}
const char* zffi_mixErr(void* ctx, int i) {
    mix::MixContext* c = (mix::MixContext*)ctx;
    if (i < 0 || i >= (int)c->errors.size()) return "";
    return c->errors[i].c_str();
}
int zffi_mixUndefCount(void* ctx, int isData) {
    mix::MixContext* c = (mix::MixContext*)ctx;
    return (int)(isData ? c->undefData.size() : c->undefFuncs.size());
}
const char* zffi_mixUndef(void* ctx, int isData, int i) {
    mix::MixContext* c = (mix::MixContext*)ctx;
    const std::vector<std::string>& v = isData ? c->undefData : c->undefFuncs;
    if (i < 0 || i >= (int)v.size()) return "";
    return v[i].c_str();
}
const char* zffi_mixDllFor(void* ctx, const char* sym) {
    static thread_local std::string dll;
    dll = ((mix::MixContext*)ctx)->dllFor(std::string(sym ? sym : ""));
    return dll.c_str();
}
int zffi_mixFinish(void* ctx, zprog* p) {
    gErr.clear();
    mix::MixContext* c = (mix::MixContext*)ctx;
    try {
        // PE target: every undefined symbol the C objects call (or import as
        // data) must be present in the DLL import table, which buildImportData
        // builds from prog.functions extern declarations. Inject synthetic
        // externs, routing each symbol to the mingw runtime DLL that provides
        // it so load-time IAT resolution succeeds.
        if (c->target == mix::Target::WindowsPe) {
            auto injectExtern = [&](const std::string& sym) {
                // Strip the CRT-glue import pointer prefix: the DLL exports the
                // underlying name, not `__imp_<name>`.
                std::string base = sym;
                if (base.rfind("__imp_", 0) == 0) base = base.substr(6);
                Program& prog = *(Program*)p;
                for (auto& f : prog.functions)
                    if (f->isExtern && f->name == base) return;
                auto fd = std::make_unique<FunctionDecl>();
                fd->name = base;
                fd->isExtern = true;
                fd->dllName = c->dllFor(base);
                prog.functions.push_back(std::move(fd));
            };
            for (auto& sym : c->undefFuncs) injectExtern(sym);
            for (auto& sym : c->undefData) injectExtern(sym);
        }
    } catch (const std::exception& e) {
        gErr = e.what();
        return 1;
    }
    g_mix = c;
    return 0;
}

int zffi_codegen(zprog* p, const char* outPath, const char* srcPath,
                 const char* exeDir, const char* isoPath, int flags) {
    Program& prog = *(Program*)p;
    gErr.clear();
    try {
        Codegen codegen(prog);
        if (exeDir && *exeDir) codegen.setCompilerDir(std::string(exeDir));
        codegen.isLibrary = (flags & Z_CG_LIB) != 0;
        codegen.libOutput = (flags & Z_CG_LIBOUT) != 0;
        codegen.embedDLLs = (flags & Z_CG_EMBED) != 0;
        codegen.mixCtx = g_mix;
        if (isoPath && prog.appType == AppType::BIOS) codegen.flatOutput = true;
        if (flags & Z_CG_DEBUG) {
            codegen.emitDebugInfo = true;
            if (srcPath) codegen.setSourcePath(std::string(srcPath));
        }
        codegen.generate(outPath ? outPath : "a.elf");
        // --iso: main.cpp validates after codegen and only then writes the
        // image, so a rejected target still produced its binary.
        if (isoPath && *isoPath) {
            if (prog.appType != AppType::EFI &&
                prog.appType != AppType::Bare &&
                prog.appType != AppType::BIOS) {
                gErr = "--iso is only supported for 'app efi', 'app bare', or 'app bios'";
                return 2;
            }
            if (prog.isLibrary) {
                gErr = "--iso cannot be combined with library mode";
                return 2;
            }
            codegen.writeIso(outPath ? outPath : "a.elf", isoPath);
        }
    } catch (const std::exception& e) {
        gErr = e.what();
        return 1;
    }
    return 0;
}

void zffi_free(zprog* p) { delete (Program*)p; }

// ===========================================================================
// Utilities
// ===========================================================================

const char* zffi_version(void) { return "Zenith Compiler v2.0"; }

int zffi_disasm(int argc, char** argv) {
    try {
        std::vector<std::string> rest;
        for (int i = 0; i < argc; i++) rest.push_back(argv[i] ? argv[i] : "");
        return cmdDisasm(rest);
    } catch (const std::exception& e) {
        std::cerr << "Disasm error: " << e.what() << std::endl;
        return 1;
    }
}

int zffi_mkdir(const char* path) {
    if (!path || !*path) return 0;
    try {
        std::filesystem::create_directories(path);
    } catch (const std::exception& e) {
        gErr = e.what();
        return 1;
    }
    return 0;
}

// ===========================================================================
// 'zenith new' / '--watch' support (src/main.cpp: cmdNew, cmdWatch)
// ===========================================================================

void zffi_out(const char* s) {
    if (!s) return;
    size_t n = std::strlen(s);
    if (n) ::write(1, s, n);
}

const char* zffi_cwd(void) {
    static std::string cwd;
    try {
        cwd = fs::current_path().string();
    } catch (...) {
        cwd = ".";
    }
    return cwd.c_str();
}

int zffi_exists(const char* path) {
    if (!path || !*path) return 0;
    std::error_code ec;
    return fs::exists(path, ec) ? 1 : 0;
}

// main.cpp's writeFile: create the parent directory, then write the file,
// and (like it) abort with `Error: cannot write file '<path>'` on failure.
int zffi_writeFile(const char* path, const char* content) {
    gErr.clear();
    fs::path p(path ? path : "");
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f{p, std::ios::binary};
    if (!f.is_open()) {
        gErr = "cannot write file '" + std::string(path ? path : "") + "'";
        return 1;
    }
    if (content) f << content;
    return 0;
}

long long zffi_mtime(const char* path) {
    struct stat st;
    if (!path || stat(path, &st) != 0) return 0;
    return (long long)st.st_mtime;
}

long long zffi_launch(char** argv) {
    if (!argv || !argv[0]) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return (int)pid;
}

long long zffi_wait(int pid) {
    int st = 0;
    if (pid > 0) waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

void zffi_kill(int pid) {
    if (pid <= 0) return;
    ::kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
}

void zffi_sleepMs(int ms) { usleep((useconds_t)ms * 1000); }

const char* zffi_exeDir(void) {
    if (!gExeDir.empty()) return gExeDir.c_str();
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fs::path p(buf);
        if (p.has_parent_path()) gExeDir = p.parent_path().string();
    }
    if (gExeDir.empty()) gExeDir = fs::current_path().string();
    return gExeDir.c_str();
}
