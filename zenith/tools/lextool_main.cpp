#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../src/lexer.h"

extern "C" {
void lexInit(long long src, long long len);
long long lexAll();
long long lexTokenCount();
long long lexKindAt(long long i);
long long lexLineAt(long long i);
long long lexColAt(long long i);
long long lexIntAt(long long i);
float lexFloatAt(long long i);
long long lexTextPtrAt(long long i);
long long lexTextLenAt(long long i);
}

static void put32(std::string& o, uint32_t v) {
    o.push_back((char)(v & 0xff)); o.push_back((char)((v >> 8) & 0xff));
    o.push_back((char)((v >> 16) & 0xff)); o.push_back((char)((v >> 24) & 0xff));
}
static void put64(std::string& o, uint64_t v) {
    for (int i = 0; i < 8; i++) o.push_back((char)((v >> (8 * i)) & 0xff));
}

extern "C" int lextool_main() {
    const char* srcPath = getenv("ZT_LEX_SRC");
    const char* outPath = getenv("ZT_LEX_OUT");
    if (!srcPath || !outPath) {
        std::fputs("lextool: ZT_LEX_SRC/ZT_LEX_OUT not set\n", stderr);
        return 2;
    }

    FILE* f = std::fopen(srcPath, "rb");
    if (!f) {
        std::fprintf(stderr, "lextool: cannot open %s\n", srcPath);
        return 2;
    }
    std::string src;
    char buf[8192];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof(buf), f)) > 0) src.append(buf, r);
    std::fclose(f);

    lexInit((long long)(intptr_t)src.data(), (long long)src.size());
    lexAll();
    long long n = lexTokenCount();

    std::string out;
    out += "ZTLX";
    put32(out, 1);
    put64(out, (uint64_t)n);
    for (long long i = 0; i < n; i++) {
        long long k = lexKindAt(i);
        put32(out, (uint32_t)(int32_t)k);
        put32(out, (uint32_t)(int32_t)lexLineAt(i));
        put32(out, (uint32_t)(int32_t)lexColAt(i));
        put64(out, (uint64_t)(int64_t)lexIntAt(i));
        double fv = (double)lexFloatAt(i);
        uint64_t bits;
        std::memcpy(&bits, &fv, 8);
        put64(out, bits);
        long long tl = lexTextLenAt(i);
        put32(out, (uint32_t)(int32_t)tl);
        if (tl > 0) {
            const char* p = (const char*)lexTextPtrAt(i);
            out.append(p, (size_t)tl);
            if (k == (long long)TokenKind::FloatLit) {
                double d = std::strtod(std::string(p, (size_t)tl).c_str(), nullptr);
                uint64_t db;
                std::memcpy(&db, &d, 8);
                std::memcpy(&out[out.size() - (size_t)tl - 4 - 8], &db, 8);
            }
        }
    }

    FILE* o = std::fopen(outPath, "wb");
    if (!o) {
        std::fprintf(stderr, "lextool: cannot write %s\n", outPath);
        return 2;
    }
    if (!out.empty() && std::fwrite(out.data(), 1, out.size(), o) != out.size()) {
        std::fclose(o);
        return 2;
    }
    std::fclose(o);
    return 0;
}
