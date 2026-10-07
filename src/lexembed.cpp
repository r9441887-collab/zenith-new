// lexembed — the compiler's tokenizer, linked in as code.
//
// selfhost/lexer.z (the selfhost port of the old src/lexer.cpp) is compiled
// to a relocatable ELF object with the compiler's own --obj flag (see
// selfhost/lexobj.z and the LEXOBJ rules in Makefile.linux) and linked into
// this binary. lexSource() drives it in-process: lexInit -> lexAll -> the
// lex*At accessors. No fork, no temp files, no sidecar tool: the bytes of
// the z source go straight into the z lexer and the tokens come straight
// back out.
//
// In-source lexer errors are reported by the lexer itself on stderr in the
// exact "Lexer error at line ..." format the old C++ lexer used, and the
// offending token is skipped — same semantics as Lexer::all(). false is
// returned only when the source cannot be tokenized at all (the selfhost
// token cap), which used to surface as a bogus parse error much later.
#include "lexer.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
void zenith_obj_init();            // z global initializers; run once, first
void lexInit(long long src, long long len);
long long lexAll();
long long lexTokenCount();
long long lexOverflow();
long long lexKindAt(long long i);
long long lexLineAt(long long i);
long long lexColAt(long long i);
long long lexIntAt(long long i);
float lexFloatAt(long long i);
long long lexTextPtrAt(long long i);
long long lexTextLenAt(long long i);
}

// _printk is the only external symbol a --obj image may reach for output
// (print() in z code compiled that way). The kernel has it; a userspace host
// does not, so route it to stderr — the same stream the lexer's own
// eprintln() writes to.
extern "C" int _printk(const char* fmt, ...) {
    std::va_list ap;
    va_start(ap, fmt);
    int rc = std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    return rc;
}

bool lexSource(const std::string& src, std::vector<Token>& out, std::string& err) {
    out.clear();
    err.clear();

    // One-time z runtime bring-up: a --obj image has no _start, so globals
    // whose initializers need code (`var gLine: int = 1`, string pointers)
    // are set here, exactly once, before the first entry into z code.
    static const bool inited = []() { zenith_obj_init(); return true; }();
    (void)inited;

    lexInit((long long)(intptr_t)src.data(), (long long)src.size());
    lexAll();

    if (lexOverflow()) {
        err = "too many tokens (the selfhost lexer's per-file cap was hit)";
        return false;
    }

    long long n = lexTokenCount();
    out.reserve((size_t)n);
    for (long long i = 0; i < n; i++) {
        Token t;
        t.kind = (TokenKind)lexKindAt(i);
        t.line = (int)lexLineAt(i);
        t.col = (int)lexColAt(i);
        t.intVal = (int64_t)lexIntAt(i);
        long long tl = lexTextLenAt(i);
        const char* p = (const char*)lexTextPtrAt(i);
        if (tl > 0 && p) t.text.assign(p, (size_t)tl);
        // z float is f32, but the old C++ lexer stored doubles (std::stod)
        // and constant folding downstream sees those. Float literals are
        // re-parsed from their own text at full double precision — the same
        // trick the spawn bridge used — so ZT-BUG013 and the optimizer's
        // float comparisons behave exactly as before the selfhost migration.
        t.floatVal = (t.kind == TokenKind::FloatLit && !t.text.empty())
                         ? std::strtod(t.text.c_str(), nullptr)
                         : (double)lexFloatAt(i);
        out.push_back(std::move(t));
    }
    return true;
}
