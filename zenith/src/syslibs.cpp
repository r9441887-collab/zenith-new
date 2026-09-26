#include "syslibs.h"
#include "mixobj.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <algorithm>

#ifdef __linux__
#include <dlfcn.h>
#endif

namespace mix {

// ============================================================================
// Linux: probe the running system's shared libraries with dlopen/dlsym.
// ============================================================================

namespace {

struct LinuxSolibProbe {
    // Candidates in priority order. Only libraries that are actually present
    // on the host are used.
    std::vector<std::string> candidates = {
        "libc.so.6",
        "libm.so.6",
        "libstdc++.so.6",
        "libgcc_s.so.1",
        "libpthread.so.0",
        "librt.so.1",
        "libdl.so.2",
        "libz.so.1",
    };
    std::unordered_map<std::string, void*> handles;       // soname -> dlopen handle
    std::unordered_map<std::string, bool>  triedHandles;  // soname -> dlopen tried
    std::unordered_map<std::string, std::string> cache;   // symbol -> soname ("" = none)

    void* handleFor(const std::string& soname) {
        auto it = handles.find(soname);
        if (it != handles.end()) return it->second;
        if (triedHandles.count(soname)) return nullptr;
        triedHandles[soname] = true;
#ifdef __linux__
        void* h = dlopen(soname.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            // Fall back to a few explicit multiarch paths (some systems cannot
            // resolve the bare soname without the ld.so cache).
            static const char* dirs[] = {
                "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/",
                "/lib64/", "/usr/lib/x86_64-linux-gnu/",
                "/lib/", "/usr/lib/",
            };
            for (const char* d : dirs) {
                h = dlopen((std::string(d) + soname).c_str(), RTLD_NOW | RTLD_LOCAL);
                if (h) break;
            }
        }
        handles[soname] = h;
        return h;
#else
        handles[soname] = nullptr;
        return nullptr;
#endif
    }

    std::string providerOf(const std::string& sym) {
        auto it = cache.find(sym);
        if (it != cache.end()) return it->second;
        std::string result;
#ifdef __linux__
        for (const auto& soname : candidates) {
            void* h = handleFor(soname);
            if (!h) continue;
            if (dlsym(h, sym.c_str())) { result = soname; break; }
        }
#endif
        cache[sym] = result;
        return result;
    }
};

LinuxSolibProbe& linuxProbe() {
    static LinuxSolibProbe p;
    return p;
}

} // namespace

std::string linuxSonameFor(const std::string& sym) {
    std::string soname = linuxProbe().providerOf(sym);
    if (!soname.empty()) {
        if (getenv("ZT_MIX_DEBUG"))
            fprintf(stderr, "mix syslib: %s -> %s\n", sym.c_str(), soname.c_str());
        return soname;
    }
    return "libc.so.6";
}

bool linuxProbeFound(const std::string& sym) {
    return !linuxProbe().providerOf(sym).empty();
}

static size_t parseElfDynSym(const char* path, const std::string& name, int* kindOut);

namespace {
struct LinuxSymInfo { size_t size = 0; int kind = 0; bool seen = false; };
std::unordered_map<std::string, LinuxSymInfo> linuxSymCache;
} // namespace

// Looks up the named defined symbol in its provider DSO's .dynsym. Returns the
// symbol size; *kindOut (optional) = 1 for function/ifunc, 2 for object, 0 for
// unknown. Zero is returned both for missing symbols and zero-sized objects.
void linuxSymbolInfo(const std::string& sym, size_t* sizeOut, int* kindOut) {
    auto& c = linuxSymCache[sym];
    if (sizeOut) *sizeOut = c.seen ? c.size : 0;
    if (kindOut) *kindOut = c.seen ? c.kind : 0;
    if (c.seen) return;
    c.seen = true;
#ifdef __linux__
    LinuxSolibProbe& p = linuxProbe();
    std::string soname = p.providerOf(sym);
    bool dbg = getenv("ZT_MIX_DEBUG");
    if (dbg) fprintf(stderr, "ldyn %s -> provider '%s'\n", sym.c_str(), soname.c_str());
    if (!soname.empty()) {
        void* h = p.handleFor(soname);
        void* addr = h ? dlsym(h, sym.c_str()) : nullptr;
        if (dbg) fprintf(stderr, "         handle=%p dlsym=%p\n", h, addr);
        if (addr) {
            Dl_info info;
            if (dladdr(addr, &info) && info.dli_fname) {
                if (dbg) fprintf(stderr, "         file=%s\n", info.dli_fname);
                c.size = parseElfDynSym(info.dli_fname, sym, &c.kind);
            }
        }
    }
#endif
    if (sizeOut) *sizeOut = c.size;
    if (kindOut) *kindOut = c.kind;
}

size_t linuxDynSymSize(const std::string& sym) {
    size_t sz = 0;
    linuxSymbolInfo(sym, &sz, nullptr);
    return sz;
}

int linuxSymbolKind(const std::string& sym) {
    int k = 0;
    linuxSymbolInfo(sym, nullptr, &k);
    return k;
}

static size_t parseElfDynSym(const char* path, const std::string& name, int* kindOut) {
    if (kindOut) *kindOut = 0;
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    if (size < 64) { fclose(f); return 0; }
    std::vector<uint8_t> d((size_t)size);
    if (fread(d.data(), 1, (size_t)size, f) != (size_t)size) { fclose(f); return 0; }
    fclose(f);

    auto rd = [&](size_t off, size_t n) -> uint64_t {
        uint64_t v = 0;
        for (size_t i = 0; i < n && off + i < d.size(); i++) v |= (uint64_t)d[off + i] << (8 * i);
        return v;
    };
    uint16_t etype = (uint16_t)rd(16, 2);
    if (etype != 3) return 0;                          // only ET_DYN
    uint32_t shoff = (uint32_t)rd(40, 4);
    uint32_t shentsz = (uint32_t)rd(58, 2);
    uint32_t shnum = (uint32_t)rd(60, 2);
    uint32_t shstrndx = (uint32_t)rd(62, 2);
    if (shnum == 0) { shnum = (uint32_t)rd(shoff + 0, 4); shstrndx = (uint32_t)rd(shoff + 4, 4); }
    if (!shoff || shentsz < 64 || shnum > 65535 || shoff + (size_t)shnum * shentsz > d.size()) return 0;

    auto shdr = [&](uint32_t i, size_t fldOff) -> uint64_t {
        return rd(shoff + (size_t)i * shentsz + fldOff, 8);
    };
    std::vector<uint32_t> secType(shnum), secLink(shnum);
    std::vector<uint64_t> secOff(shnum), secSize(shnum), secEntsz(shnum);
    uint32_t dynsymIdx = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < shnum; i++) {
        uint32_t t = (uint32_t)shdr(i, 4);
        secType[i] = t;
        secOff[i] = shdr(i, 24);
        secSize[i] = shdr(i, 32);
        secLink[i] = (uint32_t)shdr(i, 40);
        secEntsz[i] = shdr(i, 56);
        if (t == 11) dynsymIdx = i;
    }
    if (dynsymIdx == 0xFFFFFFFFu || dynsymIdx >= shnum) return 0;
    uint64_t symtabOff = secOff[dynsymIdx], symtabSize = secSize[dynsymIdx];
    uint64_t symentsz = secEntsz[dynsymIdx];
    uint32_t strlink = secLink[dynsymIdx];
    uint64_t strtabOff = 0;
    if (strlink < shnum && secType[strlink] == 3) strtabOff = secOff[strlink];
    (void)0;
    size_t n = symtabSize / symentsz;
    (void)shstrndx;
    bool haveSymStr = (strtabOff != 0);
    bool dbg = getenv("ZT_MIX_DEBUG");
    if (dbg) fprintf(stderr, "         dynsym off=%llx size=%llx entsz=%llu n=%zu strtab off=%llx\n",
                     (unsigned long long)symtabOff, (unsigned long long)symtabSize,
                     (unsigned long long)symentsz, n, (unsigned long long)strtabOff);
    for (size_t i = 0; i < n; i++) {
        size_t off = (size_t)symtabOff + i * (size_t)symentsz;
        if (off + 24 > d.size()) break;
        uint32_t st_name = (uint32_t)rd(off, 4);
        uint8_t  st_info = (uint8_t)rd(off + 4, 1);
        uint16_t st_shndx = (uint16_t)rd(off + 6, 2);
        uint64_t st_size = rd(off + 16, 8);
        if (st_shndx == 0 || !haveSymStr) continue;    // SHN_UNDEF: not a definition
        size_t noff = (size_t)strtabOff + st_name;
        size_t end = noff;
        while (end < d.size() && d[end] != 0) end++;
        std::string nm((const char*)d.data() + noff, end - noff);
        if (nm == name) {
            if (dbg) fprintf(stderr, "         FOUND %s shndx=%u size=%llu\n", nm.c_str(), st_shndx,
                             (unsigned long long)st_size);
            if (kindOut) {
                // ELF symbol types: 2=STT_FUNC, 1=STT_OBJECT, 10=STT_GNU_IFUNC
                uint8_t t = st_info & 0xF;
                *kindOut = (t == 2 || t == 10) ? 1 : (t == 1 ? 2 : 0);
            }
            return (size_t)st_size;
        }
    }
    return 0;
}

// ============================================================================
// Windows: reverse-map mingw import libraries (symbol -> DLL).
// ============================================================================

namespace {

bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

std::string shellOut(const std::string& cmd) {
    std::string out;
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return out;
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
        buf[n] = 0;
        out += buf;
    }
    pclose(f);
    return out;
}

// Extracts the first DLL filename found anywhere in the ar archive bytes
// (import libraries embed the runtime DLL name in a .idata or deft member).
std::string archiveDllName(const std::vector<uint8_t>& data) {
    std::string cur;
    std::string best;
    for (size_t i = 0; i < data.size(); i++) {
        char c = (char)data[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '+' || c == '$';
        if (ok) cur.push_back(c);
        else {
            if (endsWith(cur, ".dll") && best.empty()) best = cur;
            cur.clear();
        }
    }
    if (endsWith(cur, ".dll") && best.empty()) best = cur;
    return best;
}

// Walks an ar (System V / GNU) archive and emits each regular member.
void forEachArchiveMember(const std::vector<uint8_t>& data,
                          const std::function<void(const std::string&, const uint8_t*, size_t)>& cb) {
    if (data.size() < 8 || memcmp(data.data(), "!<arch>\n", 8) != 0) return;
    static const char* MAGIC = "`\n";
    std::vector<uint8_t> longNames;
    char hdr[60];
    size_t pos = 8;
    while (pos + 60 <= data.size()) {
        memcpy(hdr, data.data() + pos, 60);
        if (memcmp(hdr + 58, MAGIC, 2) != 0) break;
        char name[17];
        memcpy(name, hdr, 16); name[16] = 0;
        size_t size = 0;
        for (int i = 0; i < 10 && hdr[48 + i] >= '0' && hdr[48 + i] <= '9'; i++)
            size = size * 10 + (size_t)(hdr[48 + i] - '0');
        size_t dstart = pos + 60;
        if (dstart + size > data.size()) break;

        std::string nm(name);
        while (!nm.empty() && nm.back() == ' ') nm.pop_back();

        if (nm == "//") {                 // GNU long-name string table
            longNames.assign(data.begin() + dstart, data.begin() + dstart + size);
        } else if (nm == "/" || nm == "/SYM64/") {
            // ranlib symbol tables: skip.
        } else if (!nm.empty() && nm.front() == '/' && nm.size() > 1) {
            size_t off = 0;
            for (size_t k = 1; k < nm.size() && nm[k] >= '0' && nm[k] <= '9'; k++)
                off = off * 10 + (size_t)(nm[k] - '0');
            nm.clear();
            if (off < longNames.size()) {
                size_t e = off;
                while (e < longNames.size() && longNames[e] != '\n' && longNames[e] != 0) e++;
                nm.assign((const char*)longNames.data() + off, e - off);
                if (!nm.empty() && nm.back() == '/') nm.pop_back();
            }
        }

        if (!nm.empty() && nm != "/" && nm != "//" && nm != "/SYM64/")
            cb(nm, data.data() + dstart, size);

        pos = dstart + size;
        if (size & 1) pos++;              // members are padded to even length
    }
}

} // namespace

struct MingwSymMap {
    bool built = false;
    bool toolchainFound = false;
    std::unordered_map<std::string, std::string> symToDll; // symbol -> runtime DLL

    void ensureBuilt();

    static std::string probePath(const std::string& compiler, const std::string& lib) {
        std::string out = shellOut(compiler + " -print-file-name=" + lib);
        // trim whitespace / newline
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) out.pop_back();
        if (out == lib || out.empty()) return "";
        return out;
    }

    void addImportLib(const std::string& path) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz <= 0 || sz > (1L << 31)) { fclose(f); return; }
        std::vector<uint8_t> data((size_t)sz);
        if (fread(data.data(), 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return; }
        fclose(f);

        std::string dll = archiveDllName(data);
        if (dll.empty()) return;
        toolchainFound = true;

        std::unordered_set<std::string> members;
        forEachArchiveMember(data, [&](const std::string& nm, const uint8_t* bytes, size_t size) {
            if (!endsWith(nm, ".o") || members.count(nm)) return;
            members.insert(nm);
            std::vector<uint8_t> obj(bytes, bytes + size);
            mixobj::Object m;
            if (!mixobj::readObjectBytes(obj, m) || !m.valid) return;
            // Only import-lib thunk members (they carry .idata sections) tell
            // us about symbols the DLL actually exports. Members without
            // .idata are static support objects and are ignored here.
            bool isThunk = false;
            for (auto& sec : m.sections)
                if (sec.name.rfind(".idata", 0) == 0) { isThunk = true; break; }
            if (!isThunk) return;
            for (auto& s : m.symbols) {
                if (s.name.empty() || s.bind == 0 || s.isSectionSym) continue;
                if (s.section < 0) continue;      // import thunks define their symbols
                // mingw import-lib members export `__imp_<sym>` for every DLL
                // data object (std::cout, ...) as NOTYPE as well as for
                // functions; accept both so C++ data symbols route correctly.
                symToDll[s.name] = dll;
                if (s.name.rfind("__imp_", 0) == 0)
                    symToDll[s.name.substr(6)] = dll; // __imp_printf -> printf
            }
        });

        if (getenv("ZT_MIX_DEBUG"))
            fprintf(stderr, "mix syslib: import lib %s -> %s (%zu symbols)\n",
                    path.c_str(), dll.c_str(), symToDll.size());
    }
};

void MingwSymMap::ensureBuilt() {
    if (built) return;
    built = true;

    const char* envCC = getenv("ZENITH_MINGW_CC");
    std::vector<std::string> compilers;
    if (envCC && *envCC) compilers.push_back(envCC);
    compilers.push_back("x86_64-w64-mingw32-gcc");
    compilers.push_back("i686-w64-mingw32-gcc");

    for (const auto& cc : compilers) {
        for (const char* lib : { "libmsvcrt.a", "libstdc++.dll.a", "libgcc_s.a", "libwinpthread.dll.a" }) {
            std::string path = probePath(cc, lib);
            if (!path.empty()) addImportLib(path);
        }
        break;  // only the first working compiler
    }
}

MingwSymMap& mingwMap() {
    static MingwSymMap m;
    return m;
}

// Fallback: Win32 API names that mixed C code (which may #include <windows.h>)
// can reference. Only exact names route here — prefix guessing would send
// symbols to the wrong DLL and break PE loading at startup.
struct Win32ApiName {
    const char* name;
    const char* dll;
};

static const Win32ApiName kWin32ApiNames[] = {
    // ---- kernel32.dll ----
    {"CreateFileA", "kernel32.dll"}, {"CreateFileW", "kernel32.dll"}, {"CreateFile2", "kernel32.dll"},
    {"ReadFile", "kernel32.dll"}, {"WriteFile", "kernel32.dll"}, {"ReadFileEx", "kernel32.dll"},
    {"WriteFileEx", "kernel32.dll"}, {"FlushFileBuffers", "kernel32.dll"}, {"SetFilePointer", "kernel32.dll"},
    {"SetFilePointerEx", "kernel32.dll"}, {"GetFileSize", "kernel32.dll"}, {"GetFileSizeEx", "kernel32.dll"},
    {"CloseHandle", "kernel32.dll"}, {"CreateProcessA", "kernel32.dll"}, {"CreateProcessW", "kernel32.dll"},
    {"ExitProcess", "kernel32.dll"}, {"TerminateProcess", "kernel32.dll"}, {"GetExitCodeProcess", "kernel32.dll"},
    {"WaitForSingleObject", "kernel32.dll"}, {"WaitForMultipleObjects", "kernel32.dll"}, {"WaitForSingleObjectEx", "kernel32.dll"},
    {"WaitForMultipleObjectsEx", "kernel32.dll"}, {"GetStdHandle", "kernel32.dll"}, {"SetStdHandle", "kernel32.dll"},
    {"GetConsoleWindow", "kernel32.dll"}, {"GetConsoleMode", "kernel32.dll"}, {"SetConsoleMode", "kernel32.dll"},
    {"WriteConsoleA", "kernel32.dll"}, {"WriteConsoleW", "kernel32.dll"}, {"ReadConsoleA", "kernel32.dll"},
    {"ReadConsoleW", "kernel32.dll"}, {"GetCommandLineA", "kernel32.dll"}, {"GetCommandLineW", "kernel32.dll"},
    {"GetModuleHandleA", "kernel32.dll"}, {"GetModuleHandleW", "kernel32.dll"}, {"GetModuleHandleExA", "kernel32.dll"},
    {"GetModuleHandleExW", "kernel32.dll"}, {"GetModuleFileNameA", "kernel32.dll"}, {"GetModuleFileNameW", "kernel32.dll"},
    {"LoadLibraryA", "kernel32.dll"}, {"LoadLibraryW", "kernel32.dll"}, {"LoadLibraryExA", "kernel32.dll"},
    {"LoadLibraryExW", "kernel32.dll"}, {"GetProcAddress", "kernel32.dll"}, {"FreeLibrary", "kernel32.dll"},
    {"GetSystemTime", "kernel32.dll"}, {"GetSystemTimeAsFileTime", "kernel32.dll"}, {"SystemTimeToFileTime", "kernel32.dll"},
    {"FileTimeToSystemTime", "kernel32.dll"}, {"GetLocalTime", "kernel32.dll"}, {"GetTickCount", "kernel32.dll"},
    {"GetTickCount64", "kernel32.dll"}, {"QueryPerformanceCounter", "kernel32.dll"}, {"QueryPerformanceFrequency", "kernel32.dll"},
    {"GetLastError", "kernel32.dll"}, {"SetLastError", "kernel32.dll"}, {"FormatMessageA", "kernel32.dll"},
    {"FormatMessageW", "kernel32.dll"}, {"GetCurrentProcess", "kernel32.dll"}, {"GetCurrentThread", "kernel32.dll"},
    {"GetCurrentProcessId", "kernel32.dll"}, {"GetCurrentThreadId", "kernel32.dll"}, {"GetEnvironmentVariableA", "kernel32.dll"},
    {"GetEnvironmentVariableW", "kernel32.dll"}, {"SetEnvironmentVariableA", "kernel32.dll"}, {"SetEnvironmentVariableW", "kernel32.dll"},
    {"ExpandEnvironmentStringsA", "kernel32.dll"}, {"ExpandEnvironmentStringsW", "kernel32.dll"}, {"GetTempPathA", "kernel32.dll"},
    {"GetTempPathW", "kernel32.dll"}, {"GetCurrentDirectoryA", "kernel32.dll"}, {"GetCurrentDirectoryW", "kernel32.dll"},
    {"SetCurrentDirectoryA", "kernel32.dll"}, {"SetCurrentDirectoryW", "kernel32.dll"}, {"GetComputerNameA", "kernel32.dll"},
    {"GetComputerNameW", "kernel32.dll"}, {"GetVersionExA", "kernel32.dll"}, {"GetVersionExW", "kernel32.dll"},
    {"HeapAlloc", "kernel32.dll"}, {"HeapFree", "kernel32.dll"}, {"HeapReAlloc", "kernel32.dll"},
    {"HeapCreate", "kernel32.dll"}, {"HeapDestroy", "kernel32.dll"}, {"GetProcessHeap", "kernel32.dll"},
    {"GlobalAlloc", "kernel32.dll"}, {"GlobalFree", "kernel32.dll"}, {"GlobalLock", "kernel32.dll"},
    {"GlobalUnlock", "kernel32.dll"}, {"LocalAlloc", "kernel32.dll"}, {"LocalFree", "kernel32.dll"},
    {"VirtualAlloc", "kernel32.dll"}, {"VirtualFree", "kernel32.dll"}, {"VirtualProtect", "kernel32.dll"},
    {"VirtualQuery", "kernel32.dll"}, {"GetProcessMemoryInfo", "kernel32.dll"}, {"CopyFileA", "kernel32.dll"},
    {"CopyFileW", "kernel32.dll"}, {"MoveFileA", "kernel32.dll"}, {"MoveFileW", "kernel32.dll"},
    {"MoveFileExA", "kernel32.dll"}, {"MoveFileExW", "kernel32.dll"}, {"DeleteFileA", "kernel32.dll"},
    {"DeleteFileW", "kernel32.dll"}, {"CreateDirectoryA", "kernel32.dll"}, {"CreateDirectoryW", "kernel32.dll"},
    {"RemoveDirectoryA", "kernel32.dll"}, {"RemoveDirectoryW", "kernel32.dll"}, {"FindFirstFileA", "kernel32.dll"},
    {"FindFirstFileW", "kernel32.dll"}, {"FindNextFileA", "kernel32.dll"}, {"FindNextFileW", "kernel32.dll"},
    {"FindClose", "kernel32.dll"}, {"GetFullPathNameA", "kernel32.dll"}, {"GetFullPathNameW", "kernel32.dll"},
    {"GetSystemDirectoryA", "kernel32.dll"}, {"GetSystemDirectoryW", "kernel32.dll"}, {"GetWindowsDirectoryA", "kernel32.dll"},
    {"GetWindowsDirectoryW", "kernel32.dll"}, {"GetLogicalDrives", "kernel32.dll"}, {"Sleep", "kernel32.dll"},
    {"SleepEx", "kernel32.dll"}, {"OutputDebugStringA", "kernel32.dll"}, {"OutputDebugStringW", "kernel32.dll"},
    {"MultiByteToWideChar", "kernel32.dll"}, {"WideCharToMultiByte", "kernel32.dll"}, {"GetProcessHeap", "kernel32.dll"},
    {"QueryPerformanceCounter", "kernel32.dll"}, {"GetStartupInfoA", "kernel32.dll"}, {"SetUnhandledExceptionFilter", "kernel32.dll"},
    {"IsDebuggerPresent", "kernel32.dll"}, {"DebugBreak", "kernel32.dll"}, {"GetProcessAffinityMask", "kernel32.dll"},
    {"SetProcessAffinityMask", "kernel32.dll"}, {"CreateEventA", "kernel32.dll"}, {"CreateEventW", "kernel32.dll"},
    {"SetEvent", "kernel32.dll"}, {"ResetEvent", "kernel32.dll"}, {"CreateMutexA", "kernel32.dll"},
    {"CreateMutexW", "kernel32.dll"}, {"ReleaseMutex", "kernel32.dll"}, {"CreateSemaphoreA", "kernel32.dll"},
    {"CreateSemaphoreW", "kernel32.dll"}, {"ReleaseSemaphore", "kernel32.dll"}, {"CreateThread", "kernel32.dll"},
    {"ExitThread", "kernel32.dll"}, {"GetThreadContext", "kernel32.dll"}, {"GetThreadTimes", "kernel32.dll"},
    {"GetProcessTimes", "kernel32.dll"}, {"SetThreadPriority", "kernel32.dll"}, {"GetThreadPriority", "kernel32.dll"},
    {"InitializeCriticalSection", "kernel32.dll"}, {"DeleteCriticalSection", "kernel32.dll"}, {"EnterCriticalSection", "kernel32.dll"},
    {"LeaveCriticalSection", "kernel32.dll"}, {"TryEnterCriticalSection", "kernel32.dll"}, {"GetUserDefaultLCID", "kernel32.dll"},
    {"GetSystemDefaultLCID", "kernel32.dll"}, {"GetACP", "kernel32.dll"}, {"GetOEMCP", "kernel32.dll"},
    {"GetLocaleInfoA", "kernel32.dll"}, {"GetLocaleInfoW", "kernel32.dll"}, {"LCMapStringA", "kernel32.dll"},
    {"LCMapStringW", "kernel32.dll"}, {"GetTimeZoneInformation", "kernel32.dll"}, {"GetTimeZoneInformationForYear", "kernel32.dll"},
    {"TlsAlloc", "kernel32.dll"}, {"TlsFree", "kernel32.dll"}, {"TlsGetValue", "kernel32.dll"},
    {"TlsSetValue", "kernel32.dll"}, {"FlsAlloc", "kernel32.dll"}, {"FlsFree", "kernel32.dll"},
    {"FlsGetValue", "kernel32.dll"}, {"FlsSetValue", "kernel32.dll"}, {"GetStartupInfoW", "kernel32.dll"},
    {"RaiseException", "kernel32.dll"}, {"GetExceptionCode", "kernel32.dll"}, {"IsProcessorFeaturePresent", "kernel32.dll"},
    // ---- user32.dll ----
    {"CreateWindowExA", "user32.dll"}, {"CreateWindowExW", "user32.dll"}, {"RegisterClassExA", "user32.dll"},
    {"RegisterClassExW", "user32.dll"}, {"RegisterClassA", "user32.dll"}, {"RegisterClassW", "user32.dll"},
    {"UnregisterClassA", "user32.dll"}, {"UnregisterClassW", "user32.dll"}, {"DefWindowProcA", "user32.dll"},
    {"DefWindowProcW", "user32.dll"}, {"DestroyWindow", "user32.dll"}, {"ShowWindow", "user32.dll"},
    {"UpdateWindow", "user32.dll"}, {"GetMessageA", "user32.dll"}, {"GetMessageW", "user32.dll"},
    {"PeekMessageA", "user32.dll"}, {"PeekMessageW", "user32.dll"}, {"TranslateMessage", "user32.dll"},
    {"DispatchMessageA", "user32.dll"}, {"DispatchMessageW", "user32.dll"}, {"PostQuitMessage", "user32.dll"},
    {"PostMessageA", "user32.dll"}, {"PostMessageW", "user32.dll"}, {"SendMessageA", "user32.dll"},
    {"SendMessageW", "user32.dll"}, {"SendMessageTimeoutA", "user32.dll"}, {"SendMessageTimeoutW", "user32.dll"},
    {"MessageBoxA", "user32.dll"}, {"MessageBoxW", "user32.dll"}, {"MessageBoxExA", "user32.dll"},
    {"MessageBoxExW", "user32.dll"}, {"LoadCursorA", "user32.dll"}, {"LoadCursorW", "user32.dll"},
    {"LoadCursorFromFileA", "user32.dll"}, {"SetCursor", "user32.dll"}, {"GetCursorPos", "user32.dll"},
    {"SetCursorPos", "user32.dll"}, {"ShowCursor", "user32.dll"}, {"GetDC", "user32.dll"},
    {"GetDCEx", "user32.dll"}, {"ReleaseDC", "user32.dll"}, {"GetWindowDC", "user32.dll"},
    {"GetClientRect", "user32.dll"}, {"GetWindowRect", "user32.dll"}, {"GetWindowLongA", "user32.dll"},
    {"GetWindowLongW", "user32.dll"}, {"GetWindowLongPtrA", "user32.dll"}, {"GetWindowLongPtrW", "user32.dll"},
    {"SetWindowLongA", "user32.dll"}, {"SetWindowLongW", "user32.dll"}, {"SetWindowLongPtrA", "user32.dll"},
    {"SetWindowLongPtrW", "user32.dll"}, {"GetWindowTextA", "user32.dll"}, {"GetWindowTextW", "user32.dll"},
    {"SetWindowTextA", "user32.dll"}, {"SetWindowTextW", "user32.dll"}, {"GetWindowTextLengthA", "user32.dll"},
    {"GetWindowTextLengthW", "user32.dll"}, {"BeginPaint", "user32.dll"}, {"EndPaint", "user32.dll"},
    {"InvalidateRect", "user32.dll"}, {"ValidateRect", "user32.dll"}, {"GetAsyncKeyState", "user32.dll"},
    {"GetKeyState", "user32.dll"}, {"GetKeyboardState", "user32.dll"}, {"SetKeyboardState", "user32.dll"},
    {"GetFocus", "user32.dll"}, {"SetFocus", "user32.dll"}, {"GetForegroundWindow", "user32.dll"},
    {"SetForegroundWindow", "user32.dll"}, {"GetActiveWindow", "user32.dll"}, {"SetActiveWindow", "user32.dll"},
    {"MoveWindow", "user32.dll"}, {"SetWindowPos", "user32.dll"}, {"GetClassNameA", "user32.dll"},
    {"GetClassNameW", "user32.dll"}, {"GetDesktopWindow", "user32.dll"}, {"GetParent", "user32.dll"},
    {"SetParent", "user32.dll"}, {"GetDlgItem", "user32.dll"}, {"ScreenToClient", "user32.dll"},
    {"ClientToScreen", "user32.dll"}, {"MapWindowPoints", "user32.dll"}, {"GetSystemMetrics", "user32.dll"},
    {"SystemParametersInfoA", "user32.dll"}, {"SystemParametersInfoW", "user32.dll"}, {"IsWindow", "user32.dll"},
    {"IsWindowVisible", "user32.dll"}, {"SetTimer", "user32.dll"}, {"KillTimer", "user32.dll"},
    {"EnableWindow", "user32.dll"}, {"IsWindowEnabled", "user32.dll"}, {"GetKeyboardLayout", "user32.dll"},
    {"GetKeyboardLayoutList", "user32.dll"}, {"ToUnicode", "user32.dll"}, {"ToAscii", "user32.dll"},
    {"SetCapture", "user32.dll"}, {"ReleaseCapture", "user32.dll"}, {"GetCapture", "user32.dll"},
    {"AdjustWindowRect", "user32.dll"}, {"AdjustWindowRectEx", "user32.dll"}, {"GetMenu", "user32.dll"},
    {"SetMenu", "user32.dll"}, {"DrawIcon", "user32.dll"}, {"DrawIconEx", "user32.dll"},
    {"GetSysColor", "user32.dll"}, {"GetSysColorBrush", "user32.dll"}, {"FillRect", "user32.dll"},
    {"LoadIconA", "user32.dll"}, {"LoadBitmapA", "user32.dll"}, {"wsprintfA", "user32.dll"},
    {"wsprintfW", "user32.dll"}, {"CreateMenu", "user32.dll"}, {"DestroyMenu", "user32.dll"},
    {"ChildWindowFromPoint", "user32.dll"}, {"WindowFromPoint", "user32.dll"}, {"GetCursor", "user32.dll"},
    {"GethCursor", "user32.dll"},
    // ---- gdi32.dll ----
    {"CreateDIBSection", "gdi32.dll"}, {"BitBlt", "gdi32.dll"}, {"StretchBlt", "gdi32.dll"},
    {"StretchDIBits", "gdi32.dll"}, {"SetDIBits", "gdi32.dll"}, {"GetDIBits", "gdi32.dll"},
    {"SelectObject", "gdi32.dll"}, {"DeleteObject", "gdi32.dll"}, {"DeleteDC", "gdi32.dll"},
    {"CreateCompatibleDC", "gdi32.dll"}, {"CreateCompatibleBitmap", "gdi32.dll"}, {"CreateBitmap", "gdi32.dll"},
    {"CreateSolidBrush", "gdi32.dll"}, {"CreatePen", "gdi32.dll"}, {"CreateBrushIndirect", "gdi32.dll"},
    {"CreateFontA", "gdi32.dll"}, {"CreateFontW", "gdi32.dll"}, {"GetStockObject", "gdi32.dll"},
    {"GetObjectA", "gdi32.dll"}, {"GetObjectW", "gdi32.dll"}, {"GetDCBrushColor", "gdi32.dll"},
    {"SetDCBrushColor", "gdi32.dll"}, {"SetBkColor", "gdi32.dll"}, {"SetBkMode", "gdi32.dll"},
    {"SetTextColor", "gdi32.dll"}, {"SetTextAlign", "gdi32.dll"}, {"TextOutA", "gdi32.dll"},
    {"TextOutW", "gdi32.dll"}, {"ExtTextOutA", "gdi32.dll"}, {"ExtTextOutW", "gdi32.dll"},
    {"Rectangle", "gdi32.dll"}, {"Ellipse", "gdi32.dll"}, {"MoveToEx", "gdi32.dll"},
    {"LineTo", "gdi32.dll"}, {"Polygon", "gdi32.dll"}, {"Polyline", "gdi32.dll"},
    {"FillRgn", "gdi32.dll"}, {"FrameRgn", "gdi32.dll"}, {"InvertRgn", "gdi32.dll"},
    {"PatBlt", "gdi32.dll"}, {"SetPixelV", "gdi32.dll"}, {"GetPixel", "gdi32.dll"},
    {"GetDeviceCaps", "gdi32.dll"}, {"SaveDC", "gdi32.dll"}, {"RestoreDC", "gdi32.dll"},
    {"IntersectClipRect", "gdi32.dll"}, {"ExcludeClipRect", "gdi32.dll"}, {"SelectClipRgn", "gdi32.dll"},
    {"CreateRectRgn", "gdi32.dll"}, {"CombineRgn", "gdi32.dll"}, {"GetUpdateRgn", "gdi32.dll"},
    {"SetViewportOrgEx", "gdi32.dll"}, {"SetWindowOrgEx", "gdi32.dll"}, {"SetViewportExtEx", "gdi32.dll"},
    {"SetROP2", "gdi32.dll"}, {"SetMapMode", "gdi32.dll"}, {"OffsetViewportOrgEx", "gdi32.dll"},
    {"GetCurrentObject", "gdi32.dll"}, {"SetGraphicsMode", "gdi32.dll"}, {"AlphaBlend", "gdi32.dll"},
    {"GetTextExtentPoint32A", "gdi32.dll"}, {"GetTextExtentPoint32W", "gdi32.dll"}, {"GetTextMetricsA", "gdi32.dll"},
    {"GetTextMetricsW", "gdi32.dll"}, {"SetBkColor", "gdi32.dll"}, {"GdiFlush", "gdi32.dll"},
    {"DeleteEnhMetaFile", "gdi32.dll"}, {"EnumFontFamiliesExA", "gdi32.dll"}, {"EnumFontFamiliesExW", "gdi32.dll"},
    // ---- advapi32.dll ----
    {"RegOpenKeyExA", "advapi32.dll"}, {"RegOpenKeyExW", "advapi32.dll"}, {"RegCreateKeyExA", "advapi32.dll"},
    {"RegCreateKeyExW", "advapi32.dll"}, {"RegQueryValueExA", "advapi32.dll"}, {"RegQueryValueExW", "advapi32.dll"},
    {"RegSetValueExA", "advapi32.dll"}, {"RegSetValueExW", "advapi32.dll"}, {"RegDeleteValueA", "advapi32.dll"},
    {"RegDeleteValueW", "advapi32.dll"}, {"RegDeleteKeyA", "advapi32.dll"}, {"RegDeleteKeyW", "advapi32.dll"},
    {"RegCloseKey", "advapi32.dll"}, {"GetUserNameA", "advapi32.dll"}, {"GetUserNameW", "advapi32.dll"},
    {"GetUserNameExA", "advapi32.dll"}, {"OpenProcessToken", "advapi32.dll"}, {"GetTokenInformation", "advapi32.dll"},
    {"LookupAccountNameA", "advapi32.dll"}, {"LookupAccountNameW", "advapi32.dll"}, {"LookupPrivilegeValueA", "advapi32.dll"},
    {"LookupPrivilegeValueW", "advapi32.dll"}, {"AdjustTokenPrivileges", "advapi32.dll"}, {"RegEnumKeyExA", "advapi32.dll"},
    {"RegEnumKeyExW", "advapi32.dll"}, {"RegEnumValueA", "advapi32.dll"}, {"RegEnumValueW", "advapi32.dll"},
    {"RegFlushKey", "advapi32.dll"},
    // ---- ws2_32.dll ----
    {"WSAStartup", "ws2_32.dll"}, {"WSACleanup", "ws2_32.dll"}, {"WSAGetLastError", "ws2_32.dll"},
    {"WSASetLastError", "ws2_32.dll"}, {"socket", "ws2_32.dll"}, {"connect", "ws2_32.dll"},
    {"bind", "ws2_32.dll"}, {"listen", "ws2_32.dll"}, {"accept", "ws2_32.dll"},
    {"shutdown", "ws2_32.dll"}, {"closesocket", "ws2_32.dll"}, {"send", "ws2_32.dll"},
    {"recv", "ws2_32.dll"}, {"sendto", "ws2_32.dll"}, {"recvfrom", "ws2_32.dll"},
    {"select", "ws2_32.dll"}, {"ioctlsocket", "ws2_32.dll"}, {"gethostbyname", "ws2_32.dll"},
    {"gethostbyaddr", "ws2_32.dll"}, {"getaddrinfo", "ws2_32.dll"}, {"freeaddrinfo", "ws2_32.dll"},
    {"getnameinfo", "ws2_32.dll"}, {"getservbyname", "ws2_32.dll"}, {"getservbyport", "ws2_32.dll"},
    {"getprotobyname", "ws2_32.dll"}, {"getsockopt", "ws2_32.dll"}, {"setsockopt", "ws2_32.dll"},
    {"getsockname", "ws2_32.dll"}, {"getpeername", "ws2_32.dll"}, {"inet_addr", "ws2_32.dll"},
    {"inet_ntoa", "ws2_32.dll"}, {"inet_pton", "ws2_32.dll"}, {"inet_ntop", "ws2_32.dll"},
    {"htonl", "ws2_32.dll"}, {"htons", "ws2_32.dll"}, {"ntohl", "ws2_32.dll"},
    {"ntohs", "ws2_32.dll"}, {"WSAHtons", "ws2_32.dll"}, {"WSAHtonl", "ws2_32.dll"},
    {"WSAStartup", "ws2_32.dll"}, {"WsControl", "ws2_32.dll"}, {"WSAGetHostbyname", "ws2_32.dll"},
    {"WSAGetHostbyaddr", "ws2_32.dll"},
    // ---- comdlg32.dll ----
    {"GetOpenFileNameA", "comdlg32.dll"}, {"GetOpenFileNameW", "comdlg32.dll"}, {"GetSaveFileNameA", "comdlg32.dll"},
    {"GetSaveFileNameW", "comdlg32.dll"}, {"ChooseColorA", "comdlg32.dll"}, {"ChooseColorW", "comdlg32.dll"},
    {"PrintDlgA", "comdlg32.dll"}, {"PrintDlgW", "comdlg32.dll"},
    // ---- shell32.dll ----
    {"ShellExecuteA", "shell32.dll"}, {"ShellExecuteW", "shell32.dll"}, {"ShellExecuteExA", "shell32.dll"},
    {"ShellExecuteExW", "shell32.dll"}, {"SHGetFolderPathA", "shell32.dll"}, {"SHGetFolderPathW", "shell32.dll"},
    {"SHGetKnownFolderPath", "shell32.dll"}, {"SHGetSpecialFolderPathA", "shell32.dll"}, {"SHGetSpecialFolderPathW", "shell32.dll"},
    {"SHBrowseForFolderA", "shell32.dll"}, {"SHBrowseForFolderW", "shell32.dll"}, {"DragQueryFileA", "shell32.dll"},
    {"DragQueryFileW", "shell32.dll"}, {"DragAcceptFiles", "shell32.dll"},
    // ---- winmm.dll ----
    {"waveOutOpen", "winmm.dll"}, {"waveOutClose", "winmm.dll"}, {"waveOutWrite", "winmm.dll"},
    {"waveOutPrepareHeader", "winmm.dll"}, {"waveOutUnprepareHeader", "winmm.dll"}, {"waveOutGetNumDevs", "winmm.dll"},
    {"waveOutSetVolume", "winmm.dll"}, {"waveOutGetVolume", "winmm.dll"}, {"waveInOpen", "winmm.dll"},
    {"waveInStart", "winmm.dll"}, {"waveInStop", "winmm.dll"}, {"timeGetTime", "winmm.dll"},
    {"timeBeginPeriod", "winmm.dll"}, {"timeEndPeriod", "winmm.dll"}, {"PlaySoundA", "winmm.dll"},
    {"PlaySoundW", "winmm.dll"}, {"mciSendStringA", "winmm.dll"}, {"mciSendStringW", "winmm.dll"},
    {"mixerOpen", "winmm.dll"}, {"mixerSetControlDetails", "winmm.dll"},
    // ---- ole32.dll ----
    {"CoInitialize", "ole32.dll"}, {"CoInitializeEx", "ole32.dll"}, {"CoUninitialize", "ole32.dll"},
    {"CoCreateInstance", "ole32.dll"}, {"CoTaskMemAlloc", "ole32.dll"}, {"CoTaskMemFree", "ole32.dll"},
    {"CoTaskMemRealloc", "ole32.dll"}, {"CLSIDFromString", "ole32.dll"}, {"StringFromCLSID", "ole32.dll"},
    {"CoAddRefServerProcess", "ole32.dll"}, {"CoReleaseServerProcess", "ole32.dll"}, {"PropVariantClear", "ole32.dll"},
    {"CoGetClassObject", "ole32.dll"},
    // ---- dxgi.dll ----
    {"CreateDXGIFactory", "dxgi.dll"}, {"CreateDXGIFactory1", "dxgi.dll"}, {"CreateDXGIFactory2", "dxgi.dll"},
    // ---- d3d11.dll ----
    {"D3D11CreateDevice", "d3d11.dll"}, {"D3D11CreateDeviceAndSwapChain", "d3d11.dll"},
    // ---- d3dcompiler_47.dll ----
    {"D3DCompile", "d3dcompiler_47.dll"}, {"D3DReadFileToBlob", "d3dcompiler_47.dll"}, {"D3DWriteBlobToFile", "d3dcompiler_47.dll"},
    // ---- uxtheme.dll ----
    {"SetWindowTheme", "uxtheme.dll"}, {"SetWindowThemeAttribute", "uxtheme.dll"}, {"OpenThemeData", "uxtheme.dll"},
    {"CloseThemeData", "uxtheme.dll"},
    // ---- userenv.dll ----
    {"GetUserProfileDirectoryA", "userenv.dll"}, {"GetUserProfileDirectoryW", "userenv.dll"},
    // ---- version.dll ----
    {"GetFileVersionInfoA", "version.dll"}, {"GetFileVersionInfoW", "version.dll"}, {"GetFileVersionInfoSizeA", "version.dll"},
    {"GetFileVersionInfoSizeW", "version.dll"}, {"VerQueryValueA", "version.dll"}, {"VerQueryValueW", "version.dll"},
    // ---- opengl32.dll ----
    {"wglCreateContext", "opengl32.dll"}, {"wglDeleteContext", "opengl32.dll"}, {"wglMakeCurrent", "opengl32.dll"},
    {"wglGetProcAddress", "opengl32.dll"}, {"wglChoosePixelFormat", "opengl32.dll"}, {"wglSwapBuffers", "opengl32.dll"},
    // ---- gdiplus.dll ----
    {"GdiplusStartup", "gdiplus.dll"}, {"GdiplusShutdown", "gdiplus.dll"}, {"GdipCreateBitmapFromFile", "gdiplus.dll"},
    {"GdipDisposeImage", "gdiplus.dll"},
};

std::string win32FallbackFor(const std::string& sym) {
    using namespace std;
    for (auto& e : kWin32ApiNames)
        if (sym == e.name) return e.dll;
    return "";
}

std::string mingwDllForImpl(const std::string& sym) {
    MingwSymMap& m = mingwMap();
    m.ensureBuilt();
    auto it = m.symToDll.find(sym);
    if (it != m.symToDll.end()) return it->second;

    std::string w32 = win32FallbackFor(sym);
    if (!w32.empty()) return w32;

    // If the mingw toolchain isn't even installed, guess by the mangled
    // prefix so `#include <string>/<iostream>` still works when the user
    // drops the runtime DLLs next to the produced .exe.
    if (!m.toolchainFound) {
        if (sym.rfind("_Z", 0) == 0 || sym.rfind("__Z", 0) == 0 ||
            sym == "_Znwm" || sym == "_Znam" || sym == "_ZdlPv" || sym == "_ZdaPv" ||
            sym.rfind("_ZNSt", 0) == 0 || sym.rfind("_ZSt", 0) == 0 ||
            sym.rfind("_ZNKSt", 0) == 0)
            return "libstdc++-6.dll";
        if (sym.rfind("_Unwind_", 0) == 0 || sym == "__gxx_personality_v0" ||
            sym == "__gxx_personality_seh0")
            return "libgcc_s_seh-1.dll";
        if (sym.rfind("pthread_", 0) == 0)
            return "libwinpthread-1.dll";
    }
    return "msvcrt.dll";
}

std::string mingwDllFor(const std::string& sym) {
    return mingwDllForImpl(sym);
}

bool mingwRouted(const std::string& sym) {
    MingwSymMap& m = mingwMap();
    m.ensureBuilt();
    if (m.symToDll.count(sym)) return true;
    if (!win32FallbackFor(sym).empty()) return true;
    // Mangled C++ / gcc-runtime fallbacks are still "known" routes.
    if (sym.rfind("_Z", 0) == 0 || sym == "_Znwm" || sym == "_Znam" ||
        sym == "_ZdlPv" || sym == "_ZdaPv")
        return true;
    return false;
}

} // namespace mix
