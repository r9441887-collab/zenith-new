// lexbridge — the compiler's lexer front-end, backed by tools/lextool
// (selfhost/lexer.z, the selfhost port of src/lexer.cpp). lexer.cpp is gone
// from the build: every tokenize request forks lextool, which writes a binary
// token dump (see tools/lextool_main.cpp for the format) that we parse back
// into std::vector<Token>.
//
// Lexer errors in the source itself are printed by lextool on stderr in the
// exact "Lexer error at line ..." format the old C++ lexer used, and are
// skipped — same semantics as Lexer::all(). false is returned only when the
// tool itself fails (missing binary, spawn error, bad dump).
#include "lexer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static bool fileExists(const std::string& p) {
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return false;
    std::fclose(f);
    return true;
}

static std::string findLextool() {
    if (const char* e = std::getenv("ZT_LEXTOOL")) {
        if (e[0] && fileExists(e)) return e;
    }
#ifdef __linux__
    // next to the zenith binary and up toward the repo root (build/linux/..)
    {
        char exe[4096];
        ssize_t n = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n > 0) {
            exe[n] = '\0';
            std::string dir(exe);
            size_t slash = dir.rfind('/');
            if (slash != std::string::npos) dir.resize(slash);
            const char* rel[] = { "/lextool", "/../tools/lextool",
                                  "/../../tools/lextool", "/../../../tools/lextool" };
            for (const char* r : rel) {
                std::string c = dir + r;
                if (fileExists(c)) return c;
            }
        }
    }
#endif
    const char* cands[] = {
        "tools/lextool",            // run from the repo root
        "build/linux/lextool",      // staged next to the binary
        "./tools/lextool",
    };
    for (const char* c : cands) {
        if (fileExists(c)) return c;
    }
    return "lextool";               // last resort: PATH lookup via system()
}

static std::string tempFile(const char* tag) {
#ifdef _WIN32
    char dir[MAX_PATH];
    char path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, dir)) return "";
    if (!GetTempFileNameA(dir, tag, 0, path)) return "";
    return path;
#else
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/tmp/zt_lex_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd < 0) return "";
    ::close(fd);
    return buf;
#endif
}

static void setEnvVar(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
#else
    ::setenv(k, v, 1);
#endif
}

static void unsetEnvVar(const char* k) {
#ifdef _WIN32
    _putenv_s(k, "");
#else
    ::unsetenv(k);
#endif
}

static bool readAll(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[8192];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, r);
    std::fclose(f);
    return true;
}

static void unlink_(const std::string& p) {
    if (!p.empty()) std::remove(p.c_str());
}

bool lexSource(const std::string& src, std::vector<Token>& out, std::string& err) {
    out.clear();

    std::string srcTmp = tempFile("src");
    std::string dumpTmp = tempFile("dump");
    if (srcTmp.empty() || dumpTmp.empty()) {
        err = "cannot create temporary files";
        return false;
    }

    {
        FILE* f = std::fopen(srcTmp.c_str(), "wb");
        if (!f) {
            err = "cannot write " + srcTmp;
            unlink_(srcTmp); unlink_(dumpTmp);
            return false;
        }
        if (!src.empty() && std::fwrite(src.data(), 1, src.size(), f) != src.size()) {
            std::fclose(f);
            err = "cannot write " + srcTmp;
            unlink_(srcTmp); unlink_(dumpTmp);
            return false;
        }
        std::fclose(f);
    }

    setEnvVar("ZT_LEX_SRC", srcTmp.c_str());
    setEnvVar("ZT_LEX_OUT", dumpTmp.c_str());
    std::string cmd = "\"" + findLextool() + "\"";
    int rc = std::system(cmd.c_str());
    unsetEnvVar("ZT_LEX_SRC");
    unsetEnvVar("ZT_LEX_OUT");

    if (rc != 0) {
        err = "lextool failed (exit " + std::to_string(rc) +
              "; build it with: zenith selfhost/lextool.z --cxx tools/lextool_main.cpp"
              " -o tools/lextool, or set ZT_LEXTOOL)";
        unlink_(srcTmp); unlink_(dumpTmp);
        return false;
    }

    std::string dump;
    if (!readAll(dumpTmp, dump)) {
        err = "lextool produced no token dump";
        unlink_(srcTmp); unlink_(dumpTmp);
        return false;
    }
    unlink_(srcTmp);
    unlink_(dumpTmp);

    size_t p = 0;
    auto rd32 = [&](bool& ok) -> uint32_t {
        if (p + 4 > dump.size()) { ok = false; return 0; }
        uint32_t v = (uint32_t)(uint8_t)dump[p] |
                     ((uint32_t)(uint8_t)dump[p + 1] << 8) |
                     ((uint32_t)(uint8_t)dump[p + 2] << 16) |
                     ((uint32_t)(uint8_t)dump[p + 3] << 24);
        p += 4; return v;
    };
    auto rd64 = [&](bool& ok) -> uint64_t {
        if (p + 8 > dump.size()) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)(uint8_t)dump[p + i] << (8 * i);
        p += 8; return v;
    };

    bool ok = true;
    if (dump.size() < 16 || std::memcmp(dump.data(), "ZTLX", 4) != 0) {
        err = "bad lextool dump (missing ZTLX magic)";
        return false;
    }
    p = 4;
    uint32_t ver = rd32(ok);
    uint64_t count = rd64(ok);
    if (!ok || ver != 1) {
        err = "bad lextool dump (version " + std::to_string(ver) + ")";
        return false;
    }

    out.reserve((size_t)count);
    for (uint64_t i = 0; i < count && ok; i++) {
        Token t;
        uint32_t kind = rd32(ok);
        uint32_t line = rd32(ok);
        uint32_t col = rd32(ok);
        uint64_t iv = rd64(ok);
        uint64_t fb = rd64(ok);
        uint32_t tl = rd32(ok);
        if (!ok || p + tl > dump.size()) { ok = false; break; }
        t.kind = (TokenKind)kind;
        t.line = (int)line;
        t.col = (int)col;
        t.intVal = (int64_t)iv;
        double fv;
        std::memcpy(&fv, &fb, 8);
        t.floatVal = fv;
        t.text.assign(dump.data() + p, tl);
        p += tl;
        out.push_back(t);
    }

    if (!ok || p != dump.size()) {
        err = "truncated lextool dump";
        out.clear();
        return false;
    }
    return true;
}
