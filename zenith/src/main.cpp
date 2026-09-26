#include "lexer.h"
#include "parser.h"
#include "use_resolver.h"
#include "codegen.h"
#include "optimizer.h"
#include "mix.h"
#include "irgen.h"
#include "iropt.h"
#include "andropt.h"
#include "irasm.h"
#include "irasm_wasm.h"
#include "irasm_arm.h"
#include "irasm_arm64.h"
#include "irasm_android.h"
#include "main.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <filesystem>
#include <cstdio>

#define WIN32_LEAN_AND_MEAN
#ifdef _WIN32
#include <windows.h>
#include <locale>
#endif
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#ifdef __linux__
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#endif

namespace fs = std::filesystem;

static const char* argv0 = nullptr;

static bool hasNoMain(const std::string& source) {
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
            // Also check for inline: "# [no_main]" anywhere on the line
            while (j < source.size() && source[j] != '\n') {
                if (source[j] == '[' && source.substr(j, 9) == "[no_main]") return true;
                j++;
            }
        }
    }
    return false;
}

// Strip top-level directives ('app', 'kernel_mode', 'asm_word_size',
// '@import', '# [no_main]') from an included file: only the main source
// file is allowed to define the application type.
static std::string readFile(const std::string& path);

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
// textually into one compilation unit, so their functions/globals become
// part of the same binary (one .efi), not copied or dynamically linked.
static std::string preprocessIncludes(const std::string& source,
                                      const fs::path& dir,
                                      int depth,
                                      std::vector<std::string>& stack,
                                      std::set<std::string>& included) {
    if (depth > 16) {
        std::cerr << "Error: include nesting too deep (circular include?)" << std::endl;
        exit(1);
    }
    std::istringstream iss(source);
    std::string line, out;
    bool first = true;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        if (trimmed.rfind("include ", 0) == 0) {
            size_t q1 = trimmed.find('"');
            size_t q2 = trimmed.rfind('"');
            if (q1 == std::string::npos || q2 == std::string::npos || q2 <= q1) {
                std::cerr << "Error: bad include syntax (expected: include \"file.z\"): "
                          << trimmed << std::endl;
                exit(1);
            }
            std::string incPath = trimmed.substr(q1 + 1, q2 - q1 - 1);
            fs::path full = dir.empty() ? fs::path(incPath) : (dir / incPath);
            std::string cano = full.string();
            for (auto& p : stack) {
                if (p == cano) {
                    std::cerr << "Error: circular include of '" << cano << "'" << std::endl;
                    exit(1);
                }
            }
            std::string content = readFile(full.string());
            std::string cano2 = full.lexically_normal().string();
            if (included.count(cano2)) continue;   // include guard: splice once
            stack.push_back(cano);
            std::string processed = preprocessIncludes(
                stripHeaderDirectives(content), full.parent_path(), depth + 1, stack, included);
            stack.pop_back();
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
    return out;
}

static std::string readFile(const std::string& path) {
#ifdef _WIN32
    // Use _wfopen to handle Cyrillic paths correctly on MinGW
    std::wstring wpath;
    {
        int wlen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
        if (wlen > 0) {
            wpath.resize(wlen - 1);
            MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &wpath[0], wlen);
        }
    }
    FILE* f = wpath.empty() ? nullptr : _wfopen(wpath.c_str(), L"rb");
#else
    FILE* f = std::fopen(path.c_str(), "rb");
#endif
    if (!f) {
        std::cerr << "Error: cannot open file '" << path << "'" << std::endl;
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return ""; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return ""; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return ""; }
    std::string content(sz, '\0');
    if (sz > 0) {
        size_t read = fread(&content[0], 1, sz, f);
        content.resize(read);
    }
    fclose(f);
    // Strip UTF-8 BOM if present
    if (content.size() >= 3 &&
        (uint8_t)content[0] == 0xEF &&
        (uint8_t)content[1] == 0xBB &&
        (uint8_t)content[2] == 0xBF) {
        content = content.substr(3);
    }
    return content;
}

// Scan the source for the `app <type>` directive. `use` modules are resolved
// before parsing, and the module to pick depends on the app type, so this has
// to happen on raw text. Returns "" when there is no app directive.
static std::string scanAppType(const std::string& src) {
    std::istringstream in(src);
    std::string line;
    while (std::getline(in, line)) {
        size_t i = line.find_first_not_of(" \t\r");
        if (i == std::string::npos) continue;
        std::string t = line.substr(i);
        if (t.rfind("app ", 0) != 0) continue;
        std::istringstream ls(t.substr(4));
        std::string type;
        ls >> type;
        return type;
    }
    return "";
}

static void writeFile(const std::string& path, const std::string& content) {
    fs::path p(path);
    fs::create_directories(p.parent_path());
    std::ofstream f{p, std::ios::binary};
    if (!f.is_open()) {
        std::cerr << "Error: cannot write file '" << path << "'" << std::endl;
        exit(1);
    }
    f << content;
}

// ============== --watch: live-reload loop (Windows app console / app gui) ==============

// Collect the source file plus every (recursive) `include "file.z"` so the
// watcher can monitor the whole compilation unit, not just the entry file.
// Portable: only uses readFile + std::filesystem.
static void collectSourceFilesImpl(const std::string& path, int depth,
                                   std::vector<std::string>& out,
                                   std::set<std::string>& seen) {
    if (depth > 16) return;
    std::string cano = fs::path(path).lexically_normal().string();
    if (!seen.insert(cano).second) return;
    out.push_back(cano);
    std::string content = readFile(path);
    fs::path dir = fs::path(cano).parent_path();
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        if (trimmed.rfind("include ", 0) != 0) continue;
        size_t q1 = trimmed.find('"');
        size_t q2 = trimmed.rfind('"');
        if (q1 == std::string::npos || q2 == std::string::npos || q2 <= q1) continue;
        std::string inc = trimmed.substr(q1 + 1, q2 - q1 - 1);
        fs::path full = dir.empty() ? fs::path(inc) : (dir / fs::path(inc));
        collectSourceFilesImpl(full.lexically_normal().string(), depth + 1, out, seen);
    }
}

static std::vector<std::string> collectSourceFiles(const std::string& input) {
    std::vector<std::string> out;
    std::set<std::string> seen;
    collectSourceFilesImpl(input, 0, out, seen);
    return out;
}

#ifdef _WIN32
static std::wstring toWidePath(const std::string& s) {
    std::wstring w;
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, NULL, 0);
    if (n > 1) {
        w.resize(n - 1);
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    }
    return w;
}

static std::string quoteArg(const std::string& s) {
    if (s.find(' ') != std::string::npos || s.find('\t') != std::string::npos)
        return "\"" + s + "\"";
    return s;
}

static HANDLE launchProcess(const std::wstring& cmdLine) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    std::wstring cmd = cmdLine;
    if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        return NULL;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static DWORD waitExitCode(HANDLE h) {
    WaitForSingleObject(h, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return code;
}

static void killProcess(HANDLE* hp) {
    if (!(*hp)) return;
    DWORD code = 0;
    if (GetExitCodeProcess(*hp, &code) && code == STILL_ACTIVE) {
        TerminateProcess(*hp, 0);
        WaitForSingleObject(*hp, 2000);
    }
    CloseHandle(*hp);
    *hp = NULL;
}

// Live-reload loop: compile (via a child zenith process that inherits this
// console) -> launch the output exe -> poll the sources' last-write times ->
// on change kill the old process, rebuild and relaunch. If a build fails the
// last good binary stays on screen so you can fix the error and save again.
static int cmdWatch(const std::string& progPathIn,
                    const std::vector<std::string>& childArgs,
                    const std::string& outFile,
                    const std::vector<std::string>& watchFiles) {
    char full[MAX_PATH];
    std::string progPath = progPathIn;
    if (GetFullPathNameA(progPathIn.c_str(), MAX_PATH, full, NULL) > 0) progPath = full;

    std::vector<FILETIME> stamps(watchFiles.size());
    for (size_t i = 0; i < watchFiles.size(); i++) {
        WIN32_FILE_ATTRIBUTE_DATA ad;
        if (GetFileAttributesExA(watchFiles[i].c_str(), GetFileExInfoStandard, &ad))
            stamps[i] = ad.ftLastWriteTime;
        else { stamps[i].dwLowDateTime = 0; stamps[i].dwHighDateTime = 0; }
    }

    std::wstring childCmd = toWidePath(quoteArg(progPath));
    for (size_t i = 0; i < childArgs.size(); i++) {
        childCmd += L" ";
        childCmd += toWidePath(quoteArg(childArgs[i]));
    }
    std::wstring gameCmd = toWidePath(quoteArg(outFile));

    HANDLE game = NULL;

    auto refreshStamps = [&]() {
        for (size_t i = 0; i < watchFiles.size(); i++) {
            WIN32_FILE_ATTRIBUTE_DATA ad;
            if (GetFileAttributesExA(watchFiles[i].c_str(), GetFileExInfoStandard, &ad))
                stamps[i] = ad.ftLastWriteTime;
        }
    };

    auto relaunchGame = [&]() {
        WIN32_FILE_ATTRIBUTE_DATA ad;
        if (!GetFileAttributesExA(outFile.c_str(), GetFileExInfoStandard, &ad)) {
            std::cerr << "[watch] " << outFile << " not built yet" << std::endl;
            return;
        }
        game = launchProcess(gameCmd);
        if (game) std::cout << "[watch] running " << outFile << std::endl;
        else std::cerr << "[watch] failed to start " << outFile << std::endl;
    };

    auto rebuild = [&]() {
        killProcess(&game);            // a running exe locks the output file
        Sleep(40);                     // let the file lock drop before rewriting
        std::cout << "[watch] building..." << std::endl;
        HANDLE h = launchProcess(childCmd);
        DWORD code = h ? waitExitCode(h) : (DWORD)-1;
        refreshStamps();               // re-baseline right after the save finished
        if (code != 0) {
            std::cerr << "[watch] build failed (exit " << code
                      << "); keeping last build" << std::endl;
            relaunchGame();
            return;
        }
        std::cout << "[watch] build ok, restarting" << std::endl;
        relaunchGame();
    };

    std::cout << "[watch] watching " << watchFiles.size() << " file(s):" << std::endl;
    for (size_t i = 0; i < watchFiles.size(); i++)
        std::cout << "          " << watchFiles[i] << std::endl;
    std::cout << "[watch] Ctrl+C to stop; edit & save a file to hot-reload" << std::endl;

    rebuild();

    for (;;) {
        Sleep(120);
        bool changed = false;
        for (size_t i = 0; i < watchFiles.size() && !changed; i++) {
            WIN32_FILE_ATTRIBUTE_DATA ad;
            if (GetFileAttributesExA(watchFiles[i].c_str(), GetFileExInfoStandard, &ad)) {
                if (CompareFileTime(&stamps[i], &ad.ftLastWriteTime) != 0) changed = true;
            }
        }
        if (!changed) continue;
        Sleep(80);                     // let the editor finish flushing the file
        std::cout << "[watch] change detected, rebuilding..." << std::endl;
        rebuild();
    }
    return 0;
}

#else // !_WIN32 : POSIX watch implementation (fork/exec + stat mtime + kill)

static void sleepMilli(int ms) { usleep((useconds_t)ms * 1000); }

static pid_t launchProcess(const std::string& exe, const std::vector<std::string>& args) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        std::vector<char*> av;
        for (auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr);
        execvp(av[0], av.data());
        _exit(127);
    }
    return pid;
}

static int waitExitCode(pid_t pid) {
    int st = 0;
    if (pid > 0) waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void killProcess(pid_t* hp) {
    if (!hp || *hp <= 0) return;
    ::kill(*hp, SIGKILL);
    waitpid(*hp, nullptr, 0);
    *hp = -1;
}

// live-reload: compile via a child zenith process, run the output, poll mtimes.
static int cmdWatch(const std::string& progPathIn,
                    const std::vector<std::string>& childArgs,
                    const std::string& outFile,
                    const std::vector<std::string>& watchFiles) {
    std::vector<long> stamps(watchFiles.size());
    auto stampOf = [](const std::string& p) -> long {
        struct stat st;
        if (stat(p.c_str(), &st) != 0) return 0;
        return (long)st.st_mtime;
    };
    for (size_t i = 0; i < watchFiles.size(); i++) stamps[i] = stampOf(watchFiles[i]);

    std::vector<std::string> childCmd;
    childCmd.push_back(progPathIn);          // argv[0]: recompile with this compiler
    childCmd.insert(childCmd.end(), childArgs.begin(), childArgs.end());
    std::vector<std::string> gameCmd = {outFile};
    pid_t game = -1;

    auto refreshStamps = [&]() {
        for (size_t i = 0; i < watchFiles.size(); i++) stamps[i] = stampOf(watchFiles[i]);
    };
    auto relaunchGame = [&]() {
        struct stat st;
        if (stat(outFile.c_str(), &st) != 0) {
            std::cerr << "[watch] " << outFile << " not built yet" << std::endl;
            return;
        }
        game = launchProcess(gameCmd[0], gameCmd);
        if (game > 0) std::cout << "[watch] running " << outFile << std::endl;
        else std::cerr << "[watch] failed to start " << outFile << std::endl;
    };
    auto rebuild = [&]() {
        killProcess(&game);
        sleepMilli(40);
        std::cout << "[watch] building..." << std::endl;
        int code = waitExitCode(launchProcess(childCmd[0], childCmd));
        refreshStamps();
        if (code != 0) {
            std::cerr << "[watch] build failed (exit " << code << "); keeping last build" << std::endl;
            relaunchGame();
            return;
        }
        std::cout << "[watch] build ok, restarting" << std::endl;
        relaunchGame();
    };

    std::cout << "[watch] watching " << watchFiles.size() << " file(s):" << std::endl;
    for (size_t i = 0; i < watchFiles.size(); i++)
        std::cout << "          " << watchFiles[i] << std::endl;
    std::cout << "[watch] Ctrl+C to stop; edit & save a file to hot-reload" << std::endl;

    rebuild();
    for (;;) {
        sleepMilli(120);
        bool changed = false;
        for (size_t i = 0; i < watchFiles.size() && !changed; i++) {
            if (stamps[i] != stampOf(watchFiles[i])) changed = true;
        }
        if (!changed) continue;
        sleepMilli(80);
        std::cout << "[watch] change detected, rebuilding..." << std::endl;
        rebuild();
    }
    return 0;
}
#endif // _WIN32

// Directory containing the running compiler executable (used to locate libs/
// and other runtime assets). Windows uses GetModuleFileNameW; Linux reads
// /proc/self/exe.
static fs::path getExeDir() {
#ifdef _WIN32
    wchar_t exePathW[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePathW, MAX_PATH);
    fs::path p(exePathW);
    return p.has_parent_path() ? p.parent_path() : fs::current_path();
#else
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fs::path p(buf);
        if (p.has_parent_path()) return p.parent_path();
    }
    return fs::current_path();
#endif
}

static void printUsage() {
    std::cout << "Zenith Compiler v2.0" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  zenith <input.z> -o <output>       Compile a single file" << std::endl;
    std::cout << "  zenith <input.z> -o out.hex --iso   Build bootable ISO (efi/bare/bios)" << std::endl;
    std::cout << "  zenith <input.z> --lib -o out.dll  Compile as DLL (custom output)" << std::endl;
    std::cout << "  zenith <input.z> --libs            Compile as DLL into libs/ folder" << std::endl;
    std::cout << "  zenith <input.z> --embed           Embed system DLLs into output" << std::endl;
    std::cout << "  zenith <input.z> --iso             Also build a bootable ISO image (efi/bare/bios)" << std::endl;
    std::cout << "  zenith <input.z> --ir              Compile via assembler-IR pipeline (IRGen+IROpt+IRAsm, app console)" << std::endl;
    std::cout << "  zenith <input.z> --no-opt          Disable all optimizations for this file (default is maximum)" << std::endl;
    std::cout << "  zenith <input.z> -g / --debug      Emit DWARF debug info in a separate <output>.debug file" << std::endl;
    std::cout << "                                   (the main binary is left byte-identical). Load in gdb with" << std::endl;
    std::cout << "                                   'symbol-file <output>.debug', or via debug-file-directory." << std::endl;
    std::cout << "  zenith <input.z> --watch           Live-reload: compile, run the app, and hot-restart it" << std::endl;
    std::cout << "                                   every time the code changes (Windows app console / app gui)" << std::endl;
    std::cout << "  zenith <input.z> --cc <f.c>        Compile f.c with the system C compiler and link it in" << std::endl;
    std::cout << "  zenith <input.z> --cxx <f.cpp>     Compile f.cpp with g++ and link it in (call via extern func)" << std::endl;
    std::cout << "                                   (C/C++ mixing: Linux ELF, PE console/gui/EFI, BIOS/Bare, KO)" << std::endl;
    std::cout << "  Opt levels:        -0r = no optimizations   -1r = basic   -2r = maximum size/RAM" << std::endl;
    std::cout << "                    -3r = -2r + speed (div/mod by const power of two -> shifts)" << std::endl;
    std::cout << "  Arch flags:        --32bit = x86-32   --64bit = x86-64   --arm = ARM32   --arm64 = AArch64" << std::endl;
    std::cout << "  App types:         set by the 'app' directive in the source, e.g." << std::endl;
    std::cout << "                     app linux  |  app arm64  |  app stm32  |  app android" << std::endl;
    std::cout << "                     app efi | bare | bios | wasm | console | gui ..." << std::endl;
    std::cout << "                     'app android' emits a static arm64-v8a ELF (API 21+); see" << std::endl;
    std::cout << "                     release/документация/21_android.txt" << std::endl;
    std::cout << "  zenith new <name>                   Create a new project" << std::endl;
    std::cout << "  zenith new --lib <name>             Create a new DLL project" << std::endl;
    std::cout << "  zenith build                        Build project from workspace.zen" << std::endl;
    std::cout << "  zenith build --lib                  Build as DLL and pack into libs.dll" << std::endl;
    std::cout << "  zenith disasm <file> <start> <end>  Disassemble a VA range of a built ELF/PE" << std::endl;
    std::cout << "                                   using the built-in disassembler blob" << std::endl;
    std::cout << "                                   (--att=|AT&T, --no-addr=hide address)" << std::endl;
}

static void printVersion() {
    std::cout << "Zenith Compiler v2.0" << std::endl;
    std::cout << "Zero-dependency x86_64 Windows compiler" << std::endl;
}

static int cmdNew(const std::string& projectName, bool libMode = false) {
    if (projectName.empty()) {
        std::cerr << "Error: project name required" << std::endl;
        std::cout << "Usage: zenith new [--lib] <name>" << std::endl;
        return 1;
    }

    fs::path projectDir = fs::current_path() / projectName;

    if (fs::exists(projectDir)) {
        std::cerr << "Error: directory '" << projectName << "' already exists" << std::endl;
        return 1;
    }

    // Create directories
    fs::create_directories(projectDir / "src");
    fs::create_directories(projectDir / "exe");

    if (libMode) {
#ifdef _WIN32
        // Create workspace.zen for DLL output
        writeFile((projectDir / "workspace.zen").string(),
            "# DLL project\n"
            "output dll\n"
            "src\n"
        );
#else
        // Linux: shared libraries are real .so consumed via ld.so (DT_NEEDED).
        // `platform linux` selects the .so/ELF path in zenith build.
        writeFile((projectDir / "workspace.zen").string(),
            "# Shared library project\n"
            "output dll\n"
            "platform linux\n"
            "src\n"
        );
#endif

        // Create src/main.z with [no_main] marker
        writeFile((projectDir / "src" / "main.z").string(),
            "app console\n"
            "\n"
            "# [no_main]\n"
            "\n"
            "func add(a: int, b: int) -> int\n"
            "    return a + b\n"
            "end\n"
        );

        std::cout << "DLL project '" << projectName << "' created:" << std::endl;
        std::cout << "  " << projectName << "/src/main.z    - library source" << std::endl;
        std::cout << "  " << projectName << "/workspace.zen - project config (output dll)" << std::endl;
        std::cout << "  " << projectName << "/exe/           - build output" << std::endl;
    } else {
        // Create workspace.zen
        writeFile((projectDir / "workspace.zen").string(),
            "src\n"
        );

        // Create src/main.z with Hello World
        writeFile((projectDir / "src" / "main.z").string(),
            "app console\n"
            "\n"
            "func main() -> int\n"
            "    print(\"Hello, World!\")\n"
            "    return 0\n"
            "end\n"
        );

        std::cout << "Project '" << projectName << "' created:" << std::endl;
        std::cout << "  " << projectName << "/src/main.z    - source code" << std::endl;
        std::cout << "  " << projectName << "/workspace.zen - project config" << std::endl;
        std::cout << "  " << projectName << "/exe/           - build output" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Next steps:" << std::endl;
    std::cout << "  cd " << projectName << std::endl;
    std::cout << "  zenith build" << (libMode ? " --lib" : "") << std::endl;

    return 0;
}

static int cmdBuild(bool libMode = false) {
    fs::path cwd = fs::current_path();
    fs::path workspaceFile = cwd / "workspace.zen";

    if (!fs::exists(workspaceFile)) {
        std::cerr << "Error: workspace.zen not found in current directory" << std::endl;
        std::cerr << "Run 'zenith new <name>' to create a project, or run this from a project directory." << std::endl;
        return 1;
    }

    // Parse workspace.zen
    std::ifstream wf(workspaceFile);
    if (!wf.is_open()) {
        std::cerr << "Error: cannot open workspace.zen" << std::endl;
        return 1;
    }

    std::vector<std::string> sourceDirs;
    // Library/dll target platform. Defaults to the host; a `platform linux`
    // or `platform windows` line in workspace.zen overrides it. Linux
    // libraries are real .so files consumed via ld.so (DT_NEEDED); Windows
    // libraries are .dll packed into the ZLIBS container for the embedded
    // PE loader.
#ifdef _WIN32
    bool platformLinux = false;
#else
    bool platformLinux = true;
#endif
    std::string line;
    while (std::getline(wf, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start, end - start + 1);
        // Skip comments after content (only # preceded by whitespace)
        size_t commentPos = std::string::npos;
        for (size_t i = 0; i < line.size(); i++) {
            if (line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t')) {
                commentPos = i;
                break;
            }
        }
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
            end = line.find_last_not_of(" \t\r\n");
            if (end == std::string::npos) continue;
            line = line.substr(0, end + 1);
        }
        // Check for "output dll" directive (after comment stripping)
        size_t trail = line.find_last_not_of(" \t\r\n");
        if (trail != std::string::npos) line = line.substr(0, trail + 1);
        if (line == "output dll") {
            libMode = true;
            continue;
        }
        if (line == "platform linux" || line == "platform windows") {
            platformLinux = (line == "platform linux");
            continue;
        }
        if (!line.empty()) {
            sourceDirs.push_back(line);
        }
    }
    wf.close();

    if (sourceDirs.empty()) {
        std::cerr << "Error: no source directories listed in workspace.zen" << std::endl;
        std::cerr << "Add directory names to workspace.zen, one per line." << std::endl;
        return 1;
    }

    // Collect all .z files from listed directories
    std::vector<fs::path> sourceFiles;
    for (auto& dir : sourceDirs) {
        fs::path dirPath = cwd / dir;
        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            std::cerr << "Warning: directory '" << dir << "' not found, skipping" << std::endl;
            continue;
        }
        for (auto& entry : fs::directory_iterator(dirPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".z") {
                sourceFiles.push_back(entry.path());
            }
        }
    }

    // Sort for deterministic compilation order
    std::sort(sourceFiles.begin(), sourceFiles.end());

    if (sourceFiles.empty()) {
        std::cerr << "Error: no .z files found in source directories" << std::endl;
        return 1;
    }

        // Determine output name from project directory
    std::string projectName = cwd.filename().string();
    fs::path exeDir = cwd / "exe";
    fs::create_directories(exeDir);

    if (libMode) {
        // In --lib mode: compile each .z file separately. On Windows each file
        // becomes libs_<base>.dll which are then packed into the ZLIBS libs.dll
        // container for the embedded loader. On Linux each file is emitted as a
        // real shared object libs_<base>.so (no pack) that the app imports via
        // `extern ... from "libs_<base>.so"` and ld.so binds at load time.
        fs::path compilerPath = getExeDir();

        // Output dir for the per-file libraries
        fs::path libDir = cwd / "lib";
        fs::create_directories(libDir);

        const std::string libExt = platformLinux ? ".so" : ".dll";

        // Collect all compiled library binaries
        struct DLLBinary {
            std::string name;
            std::vector<uint8_t> data;
        };
        std::vector<DLLBinary> libBinaries;

        for (auto& file : sourceFiles) {
            std::string baseName = file.stem().string();
            std::string libName = "libs_" + baseName + libExt;
            std::string libPath = (libDir / libName).string();

            // Read source
            std::string source = readFile(file.string());
            bool fileIsLib = hasNoMain(source);

            // Lex
            Lexer lexer(source);
            std::vector<Token> tokens;
            try {
                tokens = lexer.all();
            } catch (const std::exception& e) {
                std::cerr << "Lexer error in " << file << ": " << e.what() << std::endl;
                return 1;
            }
            for (auto& t : tokens) {
                if (t.kind == TokenKind::Error) {
                    std::cerr << "Lexer error in " << file << " at line " << t.line << ": " << t.text << std::endl;
                    return 1;
                }
            }

            // Parse
            Parser parser(tokens);
            Program prog;
            try {
                prog = parser.parse();
            } catch (const std::exception& e) {
                std::cerr << "Parser error in " << file << ": " << e.what() << std::endl;
                return 1;
            }

            prog.isLibrary = fileIsLib;

            // Generate code as library (DLL or .so)
            Codegen codegen(prog);
            codegen.setCompilerDir(compilerPath);
            codegen.isLibrary = true;
            codegen.libOutput = true;
            try {
                codegen.generate(libPath);
            } catch (const std::exception& e) {
                std::cerr << "Codegen error in " << file << ": " << e.what() << std::endl;
                return 1;
            }

            // Read compiled library into memory (Windows pack only)
            if (platformLinux) {
                std::cout << "Compiled: " << file << " -> " << libName << std::endl;
                continue;
            }
            DLLBinary db;
            db.name = libName;
            std::ifstream libFile(libPath, std::ios::binary | std::ios::ate);
            if (libFile.is_open()) {
                std::streamsize size = libFile.tellg();
                if (size > 0) {
                    libFile.seekg(0, std::ios::beg);
                    db.data.resize(size);
                    libFile.read((char*)db.data.data(), size);
                }
                libFile.close();
            } else {
                std::cerr << "Error: cannot read compiled library " << libPath << std::endl;
                return 1;
            }
            if (db.data.empty()) {
                std::cerr << "Error: compiled library is empty: " << libPath << std::endl;
                return 1;
            }
            libBinaries.push_back(std::move(db));
            std::cout << "Compiled: " << file << " -> " << libName << std::endl;
        }

        // Linux: leave the individual .so files in lib/ and return.
        // No ZLIBS container: the app links against the real .so via ld.so.
        if (platformLinux) {
            std::cout << "Shared library(ies) written to " << libDir.string() << std::endl;
            return 0;
        }

        // Pack all DLLs into libs.dll (in compiler's libs/ folder, overwriting the stub)
        fs::path libsDir = compilerPath / "libs";
        fs::create_directories(libsDir);
        std::string libsPath = (libsDir / "libs.dll").string();
        std::ofstream libsOut{fs::path(libsPath), std::ios::binary};
        if (!libsOut.is_open()) {
            std::cerr << "Error: cannot create libs.dll" << std::endl;
            return 1;
        }

        // Header: magic + count
        libsOut.write("ZLIBS", 5);
        uint8_t pad[3] = {0, 0, 0};
        libsOut.write((char*)pad, 3);
        uint32_t count = (uint32_t)libBinaries.size();
        libsOut.write((char*)&count, 4);

        // Write each entry: name_len, name, data_len, data
        for (auto& db : libBinaries) {
            uint32_t nameLen = (uint32_t)db.name.size();
            libsOut.write((char*)&nameLen, 4);
            libsOut.write(db.name.c_str(), nameLen);
            uint32_t dataLen = (uint32_t)db.data.size();
            libsOut.write((char*)&dataLen, 4);
            libsOut.write((char*)db.data.data(), dataLen);
        }
        libsOut.close();

        std::cout << "Packed " << libBinaries.size() << " DLLs into " << libsPath << std::endl;

        // Delete individual .dll files after successful packing
        for (auto& file : sourceFiles) {
            std::string baseName = file.stem().string();
            std::string dllName = "libs_" + baseName + ".dll";
            fs::path dllPath = libDir / dllName;
            if (fs::exists(dllPath)) {
                fs::remove(dllPath);
            }
        }
        // Remove temp lib/ dir if empty
        if (fs::exists(libDir) && fs::is_directory(libDir)) {
            bool empty = fs::directory_iterator(libDir) == fs::directory_iterator();
            if (empty) fs::remove(libDir);
        }
        std::cout << "Cleaned up temporary DLL files" << std::endl;

        return 0;
    }

    // Non-lib mode: concatenate all source files into single binary
#ifdef _WIN32
    std::string outputFile = (exeDir / (projectName + ".exe")).string();
#else
    std::string outputFile = (exeDir / (projectName + ".elf")).string();
#endif
    fs::path compilerPath = getExeDir();

    // Concatenate all source files
    // Strip "app" directives from non-first files (only first file keeps its app type)
    std::string combinedSource;
    bool firstFile = true;
    bool combinedIsLib = false;
    // Track which original file each combined line belongs to
    std::vector<std::string> lineSourceFile; // index = combined line (0-based)
    for (auto& file : sourceFiles) {
        std::string content = readFile(file.string());
        if (hasNoMain(content)) combinedIsLib = true;
        std::string fileStr = file.string();
        if (!firstFile) {
            combinedSource += "\n";
            lineSourceFile.push_back(fileStr);
            std::istringstream iss(content);
            std::string line;
            std::string filtered;
            bool firstLine = true;
            while (std::getline(iss, line)) {
                std::string trimmed = line;
                size_t s = trimmed.find_first_not_of(" \t");
                if (s != std::string::npos) trimmed = trimmed.substr(s);
                if (trimmed.find("app ") == 0 || trimmed.find("@import") == 0) continue;
                if (trimmed == "# [no_main]") continue;
                if (!firstLine) filtered += "\n";
                filtered += line;
                lineSourceFile.push_back(fileStr);
                firstLine = false;
            }
            combinedSource += filtered;
        } else {
            combinedSource += content;
            int lines = 0;
            for (char c : content) { if (c == '\n') lines++; }
            if (!content.empty() && content.back() != '\n') lines++;
            for (int i = 0; i < lines; i++) lineSourceFile.push_back(fileStr);
        }
        firstFile = false;
    }

    // Helper to find original file from combined line number
    auto findOriginalFile = [&](int combinedLine) -> std::string {
        if (combinedLine > 0 && combinedLine - 1 < (int)lineSourceFile.size())
            return lineSourceFile[combinedLine - 1];
        return "";
    };

    // Lex
    Lexer lexer(combinedSource);
    std::vector<Token> tokens;
    try {
        tokens = lexer.all();
    } catch (const std::exception& e) {
        std::cerr << "Lexer error: " << e.what() << std::endl;
        return 1;
    }

    // Check for lexer errors
    for (auto& t : tokens) {
        if (t.kind == TokenKind::Error) {
            std::string f = findOriginalFile(t.line);
            std::cerr << "Lexer error at line " << t.line;
            if (!f.empty()) std::cerr << " in " << f;
            std::cerr << ": " << t.text << std::endl;
            return 1;
        }
    }

    // Parse
    Parser parser(tokens);
    Program prog;
    try {
        prog = parser.parse();
    } catch (const std::exception& e) {
        std::cerr << "Parser error: " << e.what() << std::endl;
        return 1;
    }

    if (prog.functions.empty()) {
        std::cerr << "Error: no functions found in source" << std::endl;
        return 1;
    }

    // Optimize: remove unused functions and globals
    // For STM32 targets the optimizer runs in aggressive size/RAM mode.
    OptLevel level = (prog.appType == AppType::STM32) ? OptLevel::Max : OptLevel::Basic;
    Optimizer optimizer;
    OptResult optResult = optimizer.optimize(prog, level);
    for (auto& w : optResult.warnings) {
        std::cerr << w << std::endl;
    }
    if (optResult.removedFunctions > 0 || optResult.removedGlobals > 0) {
        std::cout << "Optimized: removed " << optResult.removedFunctions << " function(s), "
                  << optResult.removedGlobals << " global(s)" << std::endl;
    }
    if (optResult.removedStatements > 0) {
        std::cout << "Optimized (size mode): folded/removed " << optResult.removedStatements
                  << " statement(s)" << std::endl;
    }

    if (prog.appType == AppType::EFI) {
        fs::path p(outputFile);
        outputFile = (p.parent_path() / (p.stem().string() + ".efi")).string();
    }
    if (prog.appType == AppType::Bare || prog.appType == AppType::STM32) {
        size_t dot = outputFile.rfind('.');
        if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
        outputFile += ".bin";
    }
    if (prog.appType == AppType::WASM) {
        size_t dot = outputFile.rfind('.');
        if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
        outputFile += ".wasm";
    }
    // Generate code
    prog.isLibrary = combinedIsLib;
    Codegen codegen(prog);
    codegen.setCompilerDir(compilerPath);
    codegen.isLibrary = combinedIsLib;
    try {
        codegen.generate(outputFile);
    } catch (const std::exception& e) {
        std::cerr << "Codegen error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Build successful: " << outputFile << std::endl;

    return 0;
}

int main(int argc, char* argv[]) {
    argv0 = argv[0];
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string arg1 = argv[1];

    // zenith new [--lib] <name>
    if (arg1 == "new") {
        bool libMode = false;
        std::string name;
        for (int i = 2; i < argc; i++) {
            std::string a = argv[i];
            if (a == "--lib") libMode = true;
            else if (!a.empty() && a[0] != '-') {
                if (!name.empty()) {
                    std::cerr << "Warning: extra argument '" << a << "' ignored" << std::endl;
                } else {
                    name = a;
                }
            }
        }
        return cmdNew(name, libMode);
    }

    // zenith build [--lib]
    if (arg1 == "build") {
        bool libMode = false;
        for (int i = 2; i < argc; i++) {
            if (std::string(argv[i]) == "--lib") libMode = true;
        }
        try {
            return cmdBuild(libMode);
        } catch (const std::exception& e) {
            std::cerr << "Build error: " << e.what() << std::endl;
            return 1;
        }
    }

    // zenith disasm <binary> <startVA> <endVA> [--att|--no-addr]
    // Disassemble a VA range of a built ELF/PE with the embedded disasm blob.
    if (arg1 == "disasm") {
        std::vector<std::string> rest;
        for (int i = 2; i < argc; i++) rest.push_back(argv[i]);
        return cmdDisasm(rest);
    }

    // zenith <input.z> -o <output> [--lib]  (legacy single-file mode)
    std::string inputFile;
    std::string outputFile = "a.exe";
    bool libMode = false;
    bool libsMode = false;
    bool embedMode = false;
    bool isoMode = false;
    bool useIR = false;
    bool noOpt = false;
    bool watchMode = false;
    bool debugInfo = false;
    int optLevel = -1;   // -1 = auto (stm32: Max, others: Basic); set by -0r/-1r/-2r/--no-opt
    Arch cliArch = Arch::Auto;
    std::vector<std::string> mixCcFiles;   // --cc file.c
    std::vector<std::string> mixCxxFiles;  // --cxx file.cpp

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--version" || arg == "-v") {
            printVersion();
            return 0;
        }
        if (arg == "--lib") {
            libMode = true;
        } else if (arg == "--libs") {
            libsMode = true;
        } else if (arg == "--embed") {
            embedMode = true;
        } else if (arg == "--iso") {
            isoMode = true;
        } else if (arg == "--ir") {
            useIR = true;
        } else if (arg == "--no-opt") {
            noOpt = true;
        } else if (arg == "-g" || arg == "--debug") {
            debugInfo = true;
        } else if (arg == "-0r" || arg == "--0r") {
            optLevel = (int)OptLevel::None;
        } else if (arg == "-1r" || arg == "--1r") {
            optLevel = (int)OptLevel::Basic;
        } else if (arg == "-2r" || arg == "--2r") {
            optLevel = (int)OptLevel::Max;
        } else if (arg == "-3r" || arg == "--3r" || arg == "--speed") {
            optLevel = (int)OptLevel::Speed;
        } else if (arg == "--32bit") {
            cliArch = Arch::X86_32;
        } else if (arg == "--64bit") {
            cliArch = Arch::X86_64;
        } else if (arg == "--arm") {
            cliArch = Arch::ARM;
        } else if (arg == "--arm64") {
            cliArch = Arch::ARM64;
        } else if (arg == "--efi") {
            // handled below
        } else if (arg == "--watch") {
            watchMode = true;
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "-o") {
            std::cerr << "Error: -o requires an output filename" << std::endl;
            return 1;
        } else if ((arg == "--cc" || arg == "--cxx") && i + 1 < argc) {
            if (arg == "--cc") mixCcFiles.push_back(argv[++i]);
            else mixCxxFiles.push_back(argv[++i]);
        } else if (arg == "--cc" || arg == "--cxx") {
            std::cerr << "Error: " << arg << " requires a source file" << std::endl;
            return 1;
        } else if (!arg.empty() && arg[0] != '-') {
            if (!inputFile.empty()) {
                std::cerr << "Warning: extra input file '" << arg << "' ignored" << std::endl;
            } else {
                inputFile = arg;
            }
        }
    }

    if (inputFile.empty()) {
        std::cerr << "Error: no input file specified" << std::endl;
        printUsage();
        return 1;
    }

    // --libs: compile DLL into <exe_dir>/libs/<basename>.dll
    fs::path exeDir = getExeDir();

    if (libsMode) {
        libMode = true;
        fs::path libsDir = exeDir / "libs";
        fs::create_directories(libsDir);
#ifdef _WIN32
        // Extract basename from input file using wide API to avoid encoding issues
        std::wstring wInput;
        {
            // Convert input to wide using ACP (system codepage)
            int wlen = MultiByteToWideChar(CP_ACP, 0, inputFile.c_str(), -1, NULL, 0);
            if (wlen > 0) {
                wInput.resize(wlen - 1);
                MultiByteToWideChar(CP_ACP, 0, inputFile.c_str(), -1, &wInput[0], wlen);
            } else {
                // Fallback: try UTF-8
                wlen = MultiByteToWideChar(CP_UTF8, 0, inputFile.c_str(), -1, NULL, 0);
                if (wlen > 0) {
                    wInput.resize(wlen - 1);
                    MultiByteToWideChar(CP_UTF8, 0, inputFile.c_str(), -1, &wInput[0], wlen);
                } else {
                    wInput = L"output";
                }
            }
        }
        // Extract basename from wide path
        fs::path wSrcPath(wInput);
        std::wstring wBase = wSrcPath.stem().wstring();
        fs::path outPath = libsDir / (wBase + L".dll");
        // Convert output path to narrow using ACP (system codepage for std::ofstream)
        int ulen = WideCharToMultiByte(CP_ACP, 0, outPath.c_str(), -1, NULL, 0, NULL, NULL);
        if (ulen > 1) {
            outputFile.resize(ulen - 1);
            WideCharToMultiByte(CP_ACP, 0, outPath.c_str(), -1, &outputFile[0], ulen, NULL, NULL);
        }
#else
        fs::path outPath = libsDir / (fs::path(inputFile).stem().string() + ".so");
        outputFile = outPath.string();
#endif
    }

    // Read source (splicing `include "file.z"` recursively)
    std::string source = readFile(inputFile);
    {
        std::vector<std::string> incStack;
        incStack.push_back(fs::path(inputFile).string());
        std::set<std::string> included;
        source = preprocessIncludes(source, fs::path(inputFile).parent_path(), 0, incStack, included);
    }

    // Expand `use <module>` (the standard library). Runs on the already
    // include-expanded text; the app type picks the per-target module.
    {
        std::string appType = scanAppType(source);
        std::string useErr;
        std::string baseDir = fs::path(inputFile).parent_path().string();
        if (baseDir.empty()) baseDir = ".";
        if (!expandUseDirectives(source, baseDir, appType, useErr)) {
            std::cerr << "Error: " << useErr << std::endl;
            return 1;
        }
    }

    // Detect [no_main] before lexing
    bool sourceIsLib = hasNoMain(source);

    // Lex
    Lexer lexer(source);
    std::vector<Token> tokens;
    try {
        tokens = lexer.all();
    } catch (const std::exception& e) {
        std::cerr << "Lexer error: " << e.what() << std::endl;
        return 1;
    }

    // Check for lexer errors
    for (auto& t : tokens) {
        if (t.kind == TokenKind::Error) {
            std::cerr << "Lexer error at line " << t.line << ": " << t.text << std::endl;
            return 1;
        }
    }

    // Parse
    Parser parser(tokens);
    Program prog;
    try {
        prog = parser.parse();
    } catch (const std::exception& e) {
        std::cerr << "Parser error: " << e.what() << std::endl;
        return 1;
    }

    prog.isLibrary = sourceIsLib || libMode;

    // Apply CLI arch flag
    if (cliArch != Arch::Auto) {
        prog.arch = cliArch;
    }

    // Auto-detect/validate arch based on app type and kernel mode
    if (prog.arch == Arch::Auto) {
        if (prog.appType == AppType::STM32) {
            prog.arch = Arch::ARM; // ARM Cortex-M (Thumb-2)
        } else if (prog.appType == AppType::BIOS) {
            prog.arch = Arch::X86_32; // BIOS runs in 16/32-bit mode
        } else if (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent) {
            // bare + dependent needs 32-bit for BIOS calls
            prog.arch = Arch::X86_32;
        } else if (prog.appType == AppType::ARM64) {
            prog.arch = Arch::ARM64; // default to ARM64
        } else if (prog.appType == AppType::Android) {
            prog.arch = Arch::ARM64; // arm64-v8a is the only 64-bit Android ABI
        } else {
            prog.arch = Arch::X86_64; // default to 64-bit
        }
    } else {
        // Explicit arch provided - validate combinations
        if (prog.appType == AppType::STM32 && prog.arch != Arch::ARM) {
            std::cerr << "Error: 'app stm32' requires Arch::ARM (Cortex-M)" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::BIOS && prog.arch != Arch::X86_32) {
            std::cerr << "Error: 'app bios' requires --32bit (BIOS runs in 32-bit mode)" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent && prog.arch != Arch::X86_32) {
            std::cerr << "Error: 'app bare' with 'kernel_mode: dependent' requires --32bit (needs 32-bit for BIOS calls)" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::EFI && prog.arch != Arch::X86_64) {
            std::cerr << "Error: 'app efi' requires --64bit (UEFI is 64-bit)" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::ARM64 && prog.arch != Arch::ARM64) {
            std::cerr << "Error: 'app arm64' requires --arm64 (UEFI/ARM64 is 64-bit)" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::Android && prog.arch != Arch::ARM64) {
            std::cerr << "Error: 'app android' requires --arm64 "
                         "(only the arm64-v8a ABI is supported)" << std::endl;
            return 1;
        }
    }

    // Android level sanity checks — independent of how the arch was chosen.
    if (prog.appType == AppType::Android) {
        if (prog.androidApiLevel < 21) {
            std::cerr << "Error: api_level " << prog.androidApiLevel
                      << " is below Android's first 64-bit level (21); "
                         "arm64-v8a requires api_level >= 21" << std::endl;
            return 1;
        }
        if (prog.androidMinSdk > prog.androidApiLevel) {
            std::cerr << "Error: min_sdk (" << prog.androidMinSdk
                      << ") is higher than api_level (" << prog.androidApiLevel
                      << ")" << std::endl;
            return 1;
        }
        if (prog.androidMinSdk < 21) {
            std::cerr << "Error: min_sdk " << prog.androidMinSdk
                      << " is below Android's first 64-bit level (21); "
                         "arm64-v8a requires min_sdk >= 21" << std::endl;
            return 1;
        }
    }

    if (prog.functions.empty()) {
        std::cerr << "Error: no functions found in source" << std::endl;
        return 1;
    }

    // ===== C/C++ mixing: compile --cc/--cxx sources, parse the objects =====
    std::unique_ptr<mix::MixContext> mixCtx;
    if (!mixCcFiles.empty() || !mixCxxFiles.empty()) {
        if (prog.appType == AppType::STM32 || prog.appType == AppType::WASM) {
            std::cerr << "Error: C/C++ mixing is not supported for this target" << std::endl;
            return 1;
        }
        if (prog.appType == AppType::Android) {
            std::cerr << "Error: C/C++ mixing is not supported for 'app android' yet "
                         "(the AArch64 objects would need Bionic, not the host glibc)"
                      << std::endl;
            return 1;
        }
        mixCtx.reset(new mix::MixContext());
        if (prog.koDriver) mixCtx->target = mix::Target::KernelModule;
        else if (prog.appType == AppType::ARM64) mixCtx->target = mix::Target::Arm64;
        else if (prog.appType == AppType::Linux) mixCtx->target = mix::Target::LinuxElf;
        else if (prog.isLibrary || prog.appType == AppType::EFI ||
                 prog.appType == AppType::Console || prog.appType == AppType::GUI)
            mixCtx->target = mix::Target::WindowsPe;
        else
            mixCtx->target = mix::Target::Flat;
        // C/C++ optimizer level: mirror the zenith side (auto -> -O2).
        mixCtx->cOptLevel = (optLevel >= 0) ? optLevel : 1;
        for (auto& f : mixCcFiles) {
            std::string err;
            if (!mixCtx->addSource(f, false, {}, err)) {
                std::cerr << "Error: " << err << std::endl;
                return 1;
            }
        }
        for (auto& f : mixCxxFiles) {
            std::string err;
            if (!mixCtx->addSource(f, true, {}, err)) {
                std::cerr << "Error: " << err << std::endl;
                return 1;
            }
        }
        // PE target: fold the mingw CRT glue (libmingwex/libmingw32/libgcc)
        // into a single relocatable object so static-only helpers resolve while
        // libc/libstdc++ stay dynamic DLL imports. Replaces mixCtx's objects.
        if (mixCtx->target == mix::Target::WindowsPe) {
            std::string err;
            if (!mixCtx->prelinkWindows(err)) {
                std::cerr << "Error: " << err << std::endl;
                return 1;
            }
        }
        if (!mixCtx->errors.empty()) {
            for (auto& e : mixCtx->errors) std::cerr << "Warning: " << e << std::endl;
        }
        if (mixCtx->hasAny) {
            std::cout << "Mixing " << (mixCcFiles.size() + mixCxxFiles.size())
                      << " C/C++ source(s) ("
                      << (mixCtx->hasCpp ? "C++" : "C") << ")" << std::endl;
        }
        // PE target: every undefined symbol the C objects call (or import as
        // data) must be present in the DLL import table, which buildImportData
        // builds from prog.functions extern declarations. Inject synthetic
        // externs, routing each symbol to the mingw runtime DLL that provides
        // it (msvcrt.dll, libstdc++-6.dll, ...) so load-time IAT resolution
        // succeeds.
        if (mixCtx->target == mix::Target::WindowsPe) {
            auto injectExtern = [&](std::string sym, bool isData) {
                // Strip the CRT-glue import pointer prefix: the DLL exports the
                // underlying name, not `__imp_<name>`.
                std::string base = sym;
                if (base.rfind("__imp_", 0) == 0) base = base.substr(6);
                bool have = false;
                for (auto& f : prog.functions)
                    if (f->isExtern && f->name == base) { have = true; break; }
                if (have) return;
                auto fd = std::make_unique<FunctionDecl>();
                fd->name = base;
                fd->isExtern = true;
                fd->dllName = mixCtx->dllFor(base);
                prog.functions.push_back(std::move(fd));
                (void)isData;
            };
            for (auto& sym : mixCtx->undefFuncs) injectExtern(sym, false);
            for (auto& sym : mixCtx->undefData)   injectExtern(sym, true);
        }
    }

    // --watch: live-reload loop. Compile, launch, and whenever the source (or
    // any included file) changes, rebuild and hot-restart the running app.
    // Only Windows x86-64 'app console' / 'app gui' targets make sense here:
    // they are PE binaries you can run and hot-restart while a window/console
    // is open. stm32/efi/bios/bare/arm64/wasm have no Windows process to run.
    if (watchMode) {
        if (prog.isLibrary || libMode || libsMode || embedMode) {
            std::cerr << "Error: --watch cannot be combined with library/embed mode" << std::endl;
            return 1;
        }
        if (prog.appType != AppType::Console && prog.appType != AppType::GUI &&
            prog.appType != AppType::Linux) {
            std::cerr << "Error: --watch (live reload) works only for 'app console', 'app gui', "
                         "and 'app linux' targets" << std::endl;
            return 1;
        }
        // The recompile happens in a fresh child zenith process (same args,
        // minus --watch), so its console output/errors land right here.
        std::vector<std::string> childArgs;
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) != "--watch") childArgs.push_back(argv[i]);
        }
        std::vector<std::string> watchFiles = collectSourceFiles(inputFile);
        return cmdWatch(argv0, childArgs, outputFile, watchFiles);
    }

    // Optimize: remove unused functions and globals
    // For STM32 targets the optimizer runs in aggressive size/RAM mode.
    OptLevel cliLevel = (optLevel >= 0) ? (OptLevel)optLevel
                      : (prog.appType == AppType::STM32 ? OptLevel::Max : OptLevel::Basic);
    if (!noOpt) {
        Optimizer optimizer;
        // C/C++ mixing: keep every z function (mixed C objects may reference
        // any of them) and keep the synthetic PE import externs alive.
        if (mixCtx && mixCtx->hasAny) {
            for (auto& f : prog.functions) {
                if (f->isExtern) optimizer.keepExterns.insert(f->name);
                else optimizer.preserveFuncs.insert(f->name);
            }
        }
        // The AST-level signed pow2 div/mod rewrite builds deep expression
        // trees that the classic x86 Codegen backend (console/gui/efi/bios/
        // bare) miscompiles inside functions with parameters. Only the
        // stack-machine backends (stm32/arm64/wasm) take the rewrite; x86-64
        // still gets it through the IR pipeline.
        bool allowPow2Div = prog.appType == AppType::STM32 ||
                            prog.appType == AppType::ARM64 ||
                            prog.appType == AppType::Android ||
                            prog.appType == AppType::WASM;
        OptResult optResult = optimizer.optimize(prog, cliLevel, allowPow2Div);
        for (auto& w : optResult.warnings) {
            std::cerr << w << std::endl;
        }
        if (optResult.removedFunctions > 0 || optResult.removedGlobals > 0) {
            std::cout << "Optimized: removed " << optResult.removedFunctions << " function(s), "
                      << optResult.removedGlobals << " global(s)" << std::endl;
        }
        if (optResult.removedStatements > 0 || optResult.strengthReduced > 0 || optResult.propagated > 0) {
            std::cout << "Optimized (size mode): folded/removed " << optResult.removedStatements
                      << " statement(s), strength-reduced " << optResult.strengthReduced
                      << ", propagated " << optResult.propagated << std::endl;
        }
    }
    if (optLevel >= 0 && prog.appType == AppType::STM32) {
        std::cout << "STM32 optimization level: -" << (int)cliLevel << "r" << std::endl;
    }

    if (prog.appType == AppType::EFI) {
        if (outputFile == "a.exe") { outputFile = "BOOTX64.EFI"; }
        else { fs::path p(outputFile);
            if (p.extension() != ".efi" && p.extension() != ".EFI")
                outputFile = (p.parent_path() / (p.stem().string() + ".efi")).string(); }
    }
    if (prog.appType == AppType::Bare || prog.appType == AppType::STM32 ||
        (prog.appType == AppType::BIOS && isoMode)) {
        if (outputFile == "a.exe") { outputFile = "a.bin"; }
        else { size_t dot = outputFile.rfind('.');
            if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
            outputFile += ".bin"; }
    }
    if (prog.real16) {
        if (outputFile == "a.exe" || outputFile.empty()) { outputFile = "a.bin"; }
        else { size_t dot = outputFile.rfind('.');
            if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
            outputFile += ".bin"; }
    }
    if (prog.appType == AppType::WASM) {
        if (outputFile == "a.exe" || outputFile.empty()) { outputFile = "a.wasm"; }
        else { size_t dot = outputFile.rfind('.');
            if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
            outputFile += ".wasm"; }
    }
    if (prog.appType == AppType::Linux) {
        if (prog.koDriver) {
            // Kernel module: always end with '.ko'.
            if (outputFile == "a.exe" || outputFile.empty()) { outputFile = "a.ko"; }
            else { size_t dot = outputFile.rfind('.');
                if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
                outputFile += ".ko"; }
        } else {
            // Shared-library mode (--lib / --libs / output dll): produce .so.
            // Otherwise default to .elf executable.
            const char* ext = (sourceIsLib || libMode) ? ".so" : ".elf";
            if (outputFile == "a.exe" || outputFile.empty()) { outputFile = "a" + std::string(ext); }
            else { size_t dot = outputFile.rfind('.');
                if (dot != std::string::npos) outputFile = outputFile.substr(0, dot);
                outputFile += ext; }
        }
    }
// --ir: compile through the assembler-IR pipeline (IRGen -> IROpt -> IRAsm).
    // C/C++ mixing works through the IR path for the ARM64 target only; the
    // other IR backends fall through to the classic path when mixing.
    if (useIR && (!(mixCtx && mixCtx->hasAny) ||
                  prog.appType == AppType::ARM64)) {
        bool irOk = false;
        bool irTarget = (prog.appType == AppType::Console ||
                         prog.appType == AppType::WASM ||
                         prog.appType == AppType::STM32 ||
                         prog.appType == AppType::ARM64 ||
                         prog.appType == AppType::Android);
        if (!irTarget || sourceIsLib || libMode) {
            std::cerr << "IR: 'app " << (prog.appType == AppType::Console ? "console" : "non-console")
                      << "' / library mode is not supported by the IR backend, "
                      << "using the classic backend" << std::endl;
        } else {
            try {
                IRProgram ir;
                IRGen irgen(prog, ir);
                // 'app android': the runtime builtins become raw Linux/AArch64
                // syscalls and `*(p)` is a 4-byte window, so IRGen has to know
                // the target before it lowers anything.
                bool irAndroid = (prog.appType == AppType::Android);
                if (irAndroid) irgen.setAndroid(prog.androidApiLevel, prog.androidMinSdk);
                irgen.generate();
                if (getenv("ZT_DUMP_IR")) {
                    FILE* f = fopen("ir_dump.txt", "w");
                    if (f) {
                        for (auto& fn : ir.functions) {
                            fprintf(f, "FUNC %s nparams=%d\n", fn.name.c_str(), fn.nparams);
                            for (size_t j = 0; j < fn.instrs.size(); j++) {
                                auto& in = fn.instrs[j];
                                fprintf(f, "  %3zu op=%d g=%d a.k=%d a.reg=%d a.imm=%lld a.name=%s b.k=%d b.reg=%d b.imm=%lld b.name=%s off=%d cond=%s lab=%d aL=%d bL=%d\n",
                                        j, (int)in.op, in.garbage ? 1 : 0,
                                        (int)in.a.kind, in.a.reg, (long long)in.a.imm, in.a.name.c_str(),
                                        (int)in.b.kind, in.b.reg, (long long)in.b.imm, in.b.name.c_str(),
                                        in.a.off, in.cond.c_str(), in.label, in.a.label, in.b.label);
                            }
                        }
                        fclose(f);
                    }
                }
                int before = 0;
                for (auto& f : ir.functions) before += (int)f.instrs.size();
                if (!noOpt && !getenv("ZT_NO_OPT")) {
                    if (getenv("ZT_MIX_DEBUG") && mixCtx) {
                        std::cerr << "IROpt extraRoots:";
                        for (auto& u : mixCtx->undefFuncs) std::cerr << " " << u;
                        std::cerr << "\n";
                    }
                    IROpt::run(ir, optLevel == (int)OptLevel::Speed,
                               (mixCtx && mixCtx->hasAny) ? &mixCtx->undefFuncs : nullptr);
                }
                int after = 0;
                if (getenv("ZT_DUMP_IR2")) {
                    FILE* f = fopen("ir_dump2.txt", "w");
                    if (f) {
                        for (auto& fn : ir.functions) {
                            fprintf(f, "FUNC %s nparams=%d\n", fn.name.c_str(), fn.nparams);
                            for (size_t j = 0; j < fn.instrs.size(); j++) {
                                auto& in = fn.instrs[j];
                                fprintf(f, "  %3zu op=%d g=%d a.k=%d a.reg=%d a.imm=%lld a.name=%s b.k=%d b.reg=%d b.imm=%lld b.name=%s off=%d cond=%s lab=%d aL=%d bL=%d\n",
                                        j, (int)in.op, in.garbage ? 1 : 0,
                                        (int)in.a.kind, in.a.reg, (long long)in.a.imm, in.a.name.c_str(),
                                        (int)in.b.kind, in.b.reg, (long long)in.b.imm, in.b.name.c_str(),
                                        in.a.off, in.cond.c_str(), in.label, in.a.label, in.b.label);
                            }
                        }
                        fclose(f);
                    }
                }
                for (auto& f : ir.functions)
                    if (!f.garbage) after += (int)f.instrs.size();

                // ---- andropt: the Android-only pass ----
                // It runs after IROpt (so it sees the final IR) and before the
                // backend (so `svc #0` and the fused write(2) are already in
                // place). ZT_NO_ANDROPT turns it off, which is how the two
                // paths can be compared on the same source.
                AndroptStats andStats;
                if (irAndroid && !getenv("ZT_NO_ANDROPT")) {
                    Andropt pass(ir, prog.androidApiLevel, prog.androidMinSdk);
                    pass.run();
                    andStats = pass.stats;
                }
                bool ok = false;
                std::string androidNote;
                if (prog.appType == AppType::WASM) {
                    IRAsmWasm asm_(ir);
                    ok = asm_.compile(outputFile);
                } else if (prog.appType == AppType::STM32) {
                    IRAsmArm asm_(ir);
                    ok = asm_.compile(outputFile);
                } else if (prog.appType == AppType::ARM64) {
                    IRAsmArm64 asm_(ir);
                    asm_.mixCtx = mixCtx.get();
                    ok = asm_.compile(outputFile);
                } else if (prog.appType == AppType::Android) {
                    IRAsmAndroid asm_(ir, prog.androidApiLevel, prog.androidMinSdk);
                    ok = asm_.compile(outputFile);
                    if (ok) {
                        std::ostringstream n;
                        n << "IR android: API " << prog.androidApiLevel
                          << ", min_sdk " << prog.androidMinSdk
                          << ", andropt (syscalls inlined " << andStats.syscallsInlined
                          << ", writes fused " << andStats.writesFused
                          << ", api fallbacks " << andStats.fallbacks
                          << "), instructions " << andStats.instrsBefore << " -> "
                          << andStats.instrsAfter
                          << ", helpers " << asm_.emittedHelpers.size();
                        androidNote = n.str();
                    }
                } else {
                    IRAsm irasm(ir);
                    ok = irasm.compile(outputFile);
                }
                if (ok) {
                    std::cout << "IR: " << ir.functions.size() << " function(s), "
                              << "instructions " << before << " -> " << after
                              << ", folded " << ir.foldedInstrs
                              << ", strength-reduced " << ir.strengthReduced
                              << ", DCE " << ir.dceRemoved
                              << ", dead branches " << ir.deadBranches
                              << ", mem opts " << ir.memOpts
                              << ", SSA (copies " << ir.ssaCopies
                              << ", hoists " << ir.ssaHoisted
                              << ", br-folds " << ir.ssaBranches << ")"
                              << ", removed funcs " << ir.confirmedGarbage
                              << ", removed globals " << ir.removedGlobals
                              << ", RAM saved " << ir.ramSaved << " B"
                              << ", file saved " << ir.fileSaved << " B" << std::endl;
                    if (!androidNote.empty()) std::cout << androidNote << std::endl;
                    irOk = true;
                }
            } catch (const std::exception& e) {
                std::cerr << "IR: " << e.what() << " - falling back to the classic backend" << std::endl;
            }
        }
        if (irOk) return 0;
    }

    // Generate code
    Codegen codegen(prog);
    codegen.setCompilerDir(exeDir);
    codegen.isLibrary = sourceIsLib || libMode;
    codegen.libOutput = libMode;
    codegen.embedDLLs = embedMode;
    codegen.mixCtx = mixCtx.get();
    if (isoMode && prog.appType == AppType::BIOS) {
        codegen.flatOutput = true;
    }
    if (debugInfo) {
        if (prog.appType == AppType::BIOS || prog.appType == AppType::Bare ||
            prog.appType == AppType::ARM64 || prog.appType == AppType::Android ||
            prog.appType == AppType::WASM ||
            prog.arch != Arch::X86_64 || prog.real16) {
            std::cerr << "Warning: DWARF debug info is not supported for this target; ignoring -g/--debug" << std::endl;
        } else {
            codegen.emitDebugInfo = true;
            codegen.setSourcePath(inputFile);
        }
    }
    try {
        codegen.generate(outputFile);
    } catch (const std::exception& e) {
        std::cerr << "Codegen error: " << e.what() << std::endl;
        return 1;
    }

    // --iso: wrap the compiled boot image into a bootable ISO 9660 (El Torito)
    if (isoMode) {
        if (prog.appType != AppType::EFI &&
            prog.appType != AppType::Bare &&
            prog.appType != AppType::BIOS) {
            std::cerr << "Error: --iso is only supported for 'app efi', 'app bare', or 'app bios'" << std::endl;
            return 1;
        }
        if (libMode || sourceIsLib) {
            std::cerr << "Error: --iso cannot be combined with library mode" << std::endl;
            return 1;
        }
        fs::path op(outputFile);
        fs::path isoPath = op.has_parent_path()
            ? op.parent_path() / (op.stem().string() + ".iso")
            : fs::path(op.stem().string() + ".iso");
        codegen.writeIso(outputFile, isoPath.string());
    }

    return 0;
}
