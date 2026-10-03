// Differential-test bridge: exposes src/lexer.cpp to the Zenith selfhost
// lexer (selfhost/lexer.z) through extern C functions, for mix --cxx.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <vector>

// mix compiles C++ with -fno-exceptions: turn try/catch into plain branches
// so lexer.cpp's stoll/stod error paths still compile (they become skips).
#define try if (true)
#define catch(x) if (false); if (false)
#include "reference/lexer.cpp"
#undef try
#undef catch

extern "C" {

static std::string gFile;
static std::vector<Token> gToks;
static std::string gErrOut;
static Lexer* gLex = nullptr;

long long refLoadFile(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return 0; }
    rewind(f);
    gFile.assign((size_t)n, '\0');
    if (n > 0 && fread(&gFile[0], 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return (long long)(intptr_t)gFile.data();
}

long long refFileLen() {
    return (long long)gFile.size();
}

// Runs Lexer::all() with fd 2 redirected to a temp file so the "Lexer error
// at line ..." lines lexer.cpp writes to std::cerr can be compared byte for
// byte against the selfhost lexer's output.
long long refTokenize(const char* s, long long n) {
    fflush(stderr);
    int saved = dup(2);
    char path[] = "/tmp/zt_lexref_XXXXXX";
    int tfd = -1;
    bool redirected = false;
    if (saved >= 0) {
        tfd = mkstemp(path);
        if (tfd >= 0 && dup2(tfd, 2) >= 0) redirected = true;
        if (tfd >= 0) close(tfd);
    }

    Lexer lexer(std::string(s, (size_t)n));
    const std::vector<Token>& toks = lexer.all();
    gToks.assign(toks.begin(), toks.end());

    fflush(stderr);
    if (redirected) { dup2(saved, 2); close(saved); }
    else if (saved >= 0) close(saved);

    gErrOut.clear();
    if (redirected) {
        FILE* f = fopen(path, "rb");
        if (f) {
            char buf[4096];
            size_t r;
            while ((r = fread(buf, 1, sizeof(buf), f)) > 0) gErrOut.append(buf, r);
            fclose(f);
            unlink(path);
        }
    }
    return (long long)gToks.size();
}

long long refErrOutLen() { return (long long)gErrOut.size(); }
const char* refErrOut() { return gErrOut.c_str(); }

long long refCount() { return (long long)gToks.size(); }
long long refKind(long long i) { return (long long)gToks[(size_t)i].kind; }
long long refLine(long long i) { return (long long)gToks[(size_t)i].line; }
long long refCol(long long i) { return (long long)gToks[(size_t)i].col; }
long long refInt(long long i) { return (long long)gToks[(size_t)i].intVal; }
float refFloat(long long i) { return (float)gToks[(size_t)i].floatVal; }
const char* refTextPtr(long long i) { return gToks[(size_t)i].text.data(); }
long long refTextLen(long long i) { return (long long)gToks[(size_t)i].text.size(); }

// ---- Lexer::next() (per-token) API, mirrored by lexNext() in lexer.z ----
long long refNextInit(const char* s, long long n) {
    delete gLex;
    gLex = new Lexer(std::string(s, (size_t)n));
    gToks.clear();
    gErrOut.clear();
    return 1;
}

long long refNextScan() {
    if (!gLex) return -1;
    Token t = gLex->next();
    gToks.push_back(t);
    return (long long)gToks.size() - 1;
}

}  // extern "C"
