// ====================================================================
// bugfind_test.cpp — unit tests for the static bug finder (AST level)
//
// Each case parses a source snippet, runs runBugFind, and checks which
// [ZT-BUGxxx] codes were emitted. Positive cases assert presence of the
// expected code; negative cases assert that no warning was emitted at all
// (clean idioms, exempt patterns: `while 1`, literal ranges, ...).
//
// Compiled and run by `make test-bugfind`; see Makefile.linux.
// ====================================================================
#include "../src/bugfind.h"
#include "../src/lexer.h"
#include "../src/parser.h"

#include <cstdio>
#include <exception>
#include <string>
#include <vector>

namespace {

// Extract "ZT-BUGxxx" tokens from warning lines.
std::vector<std::string> codesOf(const std::vector<std::string>& warns) {
    std::vector<std::string> codes;
    for (const auto& w : warns) {
        size_t s = w.find("[ZT-");
        if (s == std::string::npos) continue;
        size_t e = w.find(']', s);
        if (e == std::string::npos) continue;
        codes.push_back(w.substr(s + 1, e - s - 1));
    }
    return codes;
}

struct Case {
    const char* name;
    const char* src;
    std::vector<std::string> want;   // codes that must be present
    bool expectClean = false;        // no warnings at all
};

const std::vector<Case>& cases() {
    static const std::vector<Case> v = {
        // ---- ZT-BUG001: always-false condition ----
        {"001 while-literal-zero",
         "app console\n"
         "func f()\n"
         "    while 0\n"
         "        println(1)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG001"}, false},

        // ---- ZT-BUG002: always-true condition (non-literal root) ----
        {"002 computed-const-cond",
         "app console\n"
         "func f(x: int)\n"
         "    var s: int = 2 + 3\n"
         "    if s > 1\n"
         "        println(x)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG002"}, false},

        // ---- ZT-BUG003: impossible conjunction ----
        {"003 impossible-conjunction",
         "app console\n"
         "func f(x: int)\n"
         "    if x == 5 && x == 7\n"
         "        println(1)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG003"}, false},

        // ---- ZT-BUG004: self comparison ----
        {"004 self-comparison",
         "app console\n"
         "func f(x: int)\n"
         "    if x == x\n"
         "        println(1)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG004"}, false},

        // ---- ZT-BUG005: impossible equality (x*K == C) ----
        {"005 impossible-equality",
         "app console\n"
         "func f(x: int)\n"
         "    var a: int = x * 4 == 6\n"
         "    println(a)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG005"}, false},

        // ---- ZT-BUG006: division by constant zero ----
        {"006 division-by-zero",
         "app console\n"
         "func f(x: int)\n"
         "    var z: int = 0\n"
         "    var q: int = x / z\n"
         "    println(q)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG006"}, false},

        // ---- ZT-BUG007: constant index out of bounds ----
        {"007 const-index-oob",
         "app console\n"
         "func f()\n"
         "    var arr: [4]int\n"
         "    var v: int = arr[10]\n"
         "    println(v)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG007"}, false},

        // ---- ZT-BUG008: interval index out of bounds ----
        {"008 interval-index-oob",
         "app console\n"
         "func f()\n"
         "    var arr: [4]int\n"
         "    for i = 0, 10\n"
         "        var v: int = arr[i]\n"
         "        println(v)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG008"}, false},

        // ---- ZT-BUG009: mask index out of bounds ----
        {"009 mask-index-oob",
         "app console\n"
         "func f(x: int)\n"
         "    var arr: [4]int\n"
         "    var v: int = arr[x & 7]\n"
         "    println(v)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG009"}, false},

        // ---- ZT-BUG010: x % 2 == 1 for possibly-negative x ----
        {"010 odd-test-unsigned",
         "app console\n"
         "func f(x: int)\n"
         "    var a: int = x % 2 == 1\n"
         "    println(a)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG010"}, false},

        // ---- ZT-BUG011: constant-folded overflow ----
        {"011 overflow-const-fold",
         "app console\n"
         "func f(x: int)\n"
         "    var big: int = 9223372036854775807\n"
         "    var ov: int = big * 7\n"
         "    println(ov)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG011"}, false},

        {"011 shift-amount",
         "app console\n"
         "func f(x: int)\n"
         "    var s: int = x << 64\n"
         "    println(s)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG011"}, false},

        // ---- ZT-BUG012: int vs non-integral float constant ----
        {"012 int-vs-float",
         "app console\n"
         "func f(x: int)\n"
         "    var a: int = x == 1.5\n"
         "    println(a)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG012"}, false},

        // ---- ZT-BUG013: double vs float32 rounding changes the result ----
        {"013 float-precision-cmp",
         "app console\n"
         "func f()\n"
         "    var a: float = 0.1 + 0.2\n"
         "    if a == 0.3\n"
         "        println(1)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG013"}, false},

        // ---- ZT-BUG014: math domain ----
        {"014 sqrt-negative",
         "app console\n"
         "func f()\n"
         "    var v: float = sqrt(-1.0)\n"
         "    println(v)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG014"}, false},

        {"014 fmod-zero-divisor",
         "app console\n"
         "func f()\n"
         "    var v: float = fmod(1.5, 0.0)\n"
         "    println(v)\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG014"}, false},

        // ---- ZT-BUG015: for-loop with step 0 ----
        {"015 for-step-zero",
         "app console\n"
         "func f()\n"
         "    for i = 0, 10, 0\n"
         "        println(i)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG015"}, false},

        // ---- negatives ----
        {"clean routine",
         "app console\n"
         "func clean(x: int, i: int) -> int\n"
         "    var arr: [4]int\n"
         "    var z: int = x / 2\n"
         "    var m: int = x % 2\n"
         "    var b: int = m == 0\n"
         "    var idx: int = arr[x & 3]\n"
         "    var s: int = x << 10\n"
         "    var sum: int = x + i\n"
         "    while i < 10\n"
         "        i = i + 1\n"
         "    end\n"
         "    if x < 100\n"
         "        z = 1\n"
         "    end\n"
         "    return z + idx + s + sum + b\n"
         "end\n"
         "func main() -> int\n"
         "    return clean(7, 0)\n"
         "end\n",
         {}, true},

        {"exempt idioms (while 1, literal for-ranges)",
         "app console\n"
         "func f()\n"
         "    while 1\n"
         "        break\n"
         "    end\n"
         "    for i = 0, 4\n"
         "        println(i)\n"
         "    end\n"
         "    for i = 5, 5\n"
         "        println(i)\n"
         "    end\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        {"known-shift and signed odd test",
         "app console\n"
         "func f(x: int) -> int\n"
         "    var p: int = x % 2 == 0\n"
         "    if p\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG016: both sides have a known range ----
        {"016 range-decided-false",
         "app console\n"
         "func f() -> int\n"
         "    var acc: int = 0\n"
         "    for i = 0, 4\n"
         "        if i >= 4\n"
         "            acc = 1\n"
         "        end\n"
         "    end\n"
         "    return acc\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG016"}, false},

        {"016 mask-range-decided",
         "app console\n"
         "func f(x: int) -> int\n"
         "    var t: int = x & 15\n"
         "    if t > 20\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG016"}, false},

        {"016 exempt while-step advances",
         "app console\n"
         "func f() -> int\n"
         "    for i = 0, 4\n"
         "        while i < 4\n"
         "            i = i + 1\n"
         "        end\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG017: a comparison nested in a comparison ----
        {"017 chained-comparison",
         "app console\n"
         "func f(i: int) -> int\n"
         "    if 0 <= i < 10\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG017"}, false},

        {"017 exempt parenthesized",
         "app console\n"
         "func f(i: int) -> int\n"
         "    if (i < 10) == 1\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG018: step never walks to the bound ----
        {"018 step-moves-away",
         "app console\n"
         "func f(a: int, b: int) -> int\n"
         "    var i: int = a\n"
         "    var n: int = b\n"
         "    while i < n\n"
         "        i = i - 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG018"}, false},

        {"018 exempt step-advances",
         "app console\n"
         "func f(a: int, b: int) -> int\n"
         "    var i: int = a\n"
         "    while i < b\n"
         "        i = i + 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG019: i != limit the step never lands on ----
        {"019 stride-misses-limit",
         "app console\n"
         "func f() -> int\n"
         "    var i: int = 0\n"
         "    while i != 10\n"
         "        i = i + 3\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG019"}, false},

        {"019 exempt stride-hits-limit",
         "app console\n"
         "func f() -> int\n"
         "    var i: int = 1\n"
         "    while i != 10\n"
         "        i = i + 3\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG020: two comparisons that contradict each other ----
        {"020 mirrored-contradiction",
         "app console\n"
         "func f(a: int, b: int) -> int\n"
         "    if a < b && b < a\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG020"}, false},

        {"020 or-alternatives-clean",
         "app console\n"
         "func f(x: int) -> int\n"
         "    if x > 10 && (x == 3 || x == 12)\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG021: float compared with itself ----
        {"021 float-self-equality",
         "app console\n"
         "func f(a: float) -> int\n"
         "    if a == a\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG021"}, false},

        {"021 exempt nan-test",
         "app console\n"
         "func f(a: float) -> int\n"
         "    if a != a\n"
         "        return 1\n"
         "    end\n"
         "    return 0\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},

        // ---- ZT-BUG022: an expression divided by itself ----
        {"022 self-division",
         "app console\n"
         "func f(x: int) -> int\n"
         "    var q: int = x / x\n"
         "    var m: int = x % x\n"
         "    return q + m\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {"ZT-BUG022"}, false},

        {"022 exempt distinct-operands",
         "app console\n"
         "func f(x: int, y: int) -> int\n"
         "    var q: int = x / y\n"
         "    var c: int = 4 / 4\n"
         "    return q + c\n"
         "end\n"
         "func main() -> int\n    return 0\nend\n",
         {}, true},
    };
    return v;
}

int failures = 0;

void runCase(const Case& c) {
    std::vector<std::string> warns;
    try {
        std::vector<Token> tokens;
        std::string lexErr;
        if (!lexSource(c.src, tokens, lexErr)) {
            std::printf("FAIL %-45s lex error: %s\n", c.name, lexErr.c_str());
            ++failures;
            return;
        }
        Parser p(tokens);
        Program prog = p.parse();
        runBugFind(prog, "test.z", warns);
    } catch (const std::exception& e) {
        std::printf("FAIL %-45s parse/run error: %s\n", c.name, e.what());
        ++failures;
        return;
    }

    auto codes = codesOf(warns);

    if (c.expectClean) {
        if (!codes.empty()) {
            std::printf("FAIL %-45s expected clean, got", c.name);
            for (auto& w : warns) std::printf("\n      %s", w.c_str());
            std::printf("\n");
            ++failures;
            return;
        }
        std::printf("ok   %-45s (clean)\n", c.name);
        return;
    }

    for (const auto& want : c.want) {
        bool found = false;
        for (const auto& code : codes)
            if (code == want) { found = true; break; }
        if (!found) {
            std::printf("FAIL %-45s missing %s (got", c.name, want.c_str());
            if (codes.empty())
                std::printf(" no warnings");
            else
                for (auto& code : codes) std::printf(" %s", code.c_str());
            std::printf(")\n");
            ++failures;
            return;
        }
    }
    std::printf("ok   %-45s\n", c.name);
}

}  // namespace

int main() {
    for (const auto& c : cases()) runCase(c);
    std::printf("\nbugfind: %d case(s), %d failed\n",
                (int)cases().size(), failures);
    return failures ? 1 : 0;
}
