// Host-side smoke test: maps the generated JS blob bytes into executable
// memory and calls jsrt_entry directly (host is Linux x86-64, so the blob's
// SysV-internal calling convention is ABI-compatible here). This exercises
// exactly the same path the Zenith codegen will use (blob bytes, not linking
// jsrt.c directly).
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include "js_blob.h"

typedef long (*Entry)(long, long, long, long, long, long);

#define JS_OP_RESET  0
#define JS_OP_EXEC   1
#define JS_OP_EXPR   2
#define JS_OP_RESULT 3
#define JS_OP_ERROR  4

static int g_fail = 0;
static Entry g_entry;

static void check(const char* what, const std::string& got, const std::string& want) {
    bool ok = got == want;
    printf("%-44s %s\n", what, ok ? "OK" : ("FAIL got=" + got + " want=" + want).c_str());
    if (!ok) g_fail++;
}

static std::string expr(const char* src) {
    g_entry(JS_OP_RESET, 0, 0, 0, 0, 0);
    if (g_entry(JS_OP_EXPR, (long)src, (long)strlen(src), 0, 0, 0) != 0)
        return "<perr>";
    char buf[512];
    long n = g_entry(JS_OP_RESULT, (long)buf, 511, 0, 0, 0);
    if (n < 0) return "<rerr>";
    g_entry(JS_OP_RESET, 0, 0, 0, 0, 0); /* reset state so one expr can't bleed into next */
    return std::string(buf, (size_t)n);
}

int main() {
    void* base = mmap(nullptr, kJsBlobSize + 0x500000, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(base, kJsBlob, kJsBlobSize);
    g_entry = (Entry)((char*)base + kJsBlobEntry);
    printf("js blob size=%u bytes, entry offset=0x%x (arena bss auto-zeroed by anon mmap)\n",
           kJsBlobSize, kJsBlobEntry);

    check("1+2", expr("1+2"), "3");
    check("(2+3)*4", expr("(2+3)*4"), "20");
    check("str +", expr("'ab'+'cd'"), "abcd");
    check("cmp <", expr("1<2"), "true");
    check("ternary", expr("1?2:3"), "2");
    check("obj .a", expr("({a:1}).a"), "1");
    check("arr[1]", expr("[1,2,3][1]"), "2");
    check("fn call", expr("(function(x){return x*2;})(21)"), "42");
    check("var+expr", expr("var x=10; x+5"), "15");
    check("for sum", expr("var s=0; for(var i=0;i<5;i=i+1){s=s+i} s"), "10");
    check("func decl", expr("function f(x){return x+1} f(41)"), "42");
    check("closure", expr("var x=1; function f(){x=x+1} f(); x"), "2");
    check("recursion", expr("function fac(n){if(n<=1){return 1} return n*fac(n-1)} fac(5)"), "120");
    check("shadowing", expr("var x=1; function f(){var x=2; return x} f()+x"), "3");

    printf(g_fail ? "SOME FAILED\n" : "ALL OK\n");
    return g_fail ? 1 : 0;
}