// Host-side direct test for the JS engine: links tools/jsrt.c as ordinary code
// and exercises the jsrt_entry ops (RESET/EXEC/EXPR/RESULT/ERROR).
// This mirrors how the blob will be called from codegen, minus mmap/position-independence.
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
long jsrt_entry(long op, long a1, long a2, long a3, long a4, long a5);
}

#define JS_OP_RESET  0
#define JS_OP_EXEC   1
#define JS_OP_EXPR   2
#define JS_OP_RESULT 3
#define JS_OP_ERROR  4
#define JS_OP_NUM    5

static int g_fail = 0;

static void check(const char* what, const char* src, const std::string& want) {
    jsrt_entry(JS_OP_RESET, 0, 0, 0, 0, 0);
    long rc = jsrt_entry(JS_OP_EXPR, (long)src, (long)strlen(src), 0, 0, 0);
    if (rc != 0) { printf("%-46s [parse-err]\n", what); g_fail++; return; }
    char buf[512]; long n = jsrt_entry(JS_OP_RESULT, (long)buf, 511, 0, 0, 0);
    std::string got = n < 0 ? "<err-result>" : std::string(buf, (size_t)n);
    bool ok = got == want;
    printf("%-46s %s\n", what, ok ? "OK" : ("FAIL got=" + got + " want=" + want).c_str());
    if (!ok) g_fail++;
}

/* expect EXPR to fail: rc==-1, non-empty JS_OP_ERROR text, engine still alive. */
static void checkErr(const char* what, const char* src) {
    jsrt_entry(JS_OP_RESET, 0, 0, 0, 0, 0);
    long rc = jsrt_entry(JS_OP_EXPR, (long)src, (long)strlen(src), 0, 0, 0);
    char eb[512]; long en = jsrt_entry(JS_OP_ERROR, (long)eb, 511, 0, 0, 0);
    std::string got(eb, (size_t)((en < 0) ? 0 : en));
    bool ok = (rc != 0) && !got.empty();
    printf("%-46s %s\n", what, ok ? "OK" : ("FAIL rc=" + std::to_string(rc) + " err='" + got + "'").c_str());
    if (!ok) g_fail++;
    /* engine must still work after the error */
    long retry = jsrt_entry(JS_OP_EXPR, (long)"1+1", 3, 0, 0, 0);
    if (retry != 0) { printf("%-46s FAIL engine broken after error\n", what); g_fail++; }
}

int main() {
    /* --- expressions --- */
    check("expr 1+2", "1+2", "3");
    check("expr (2+3)*4", "(2+3)*4", "20");
    check("str 'ab'+'cd'", "'ab'+'cd'", "abcd");
    check("7%3", "7%3", "1");
    check("1<2", "1<2", "true");
    check("2==2", "2==2", "true");
    check("true&&false", "true&&false", "false");
    check("1?2:3", "1?2:3", "2");
    check("({a:1}).a", "({a:1}).a", "1");
    check("[1,2,3][1]", "[1,2,3][1]", "2");
    check("f(5)=6", "(function(x){return x+1;})(5)", "6");
    check("f(6,7)=42", "(function(a,b){return a*b;})(6,7)", "42");

    /* --- statements --- */
    check("var x=10; x+5", "var x=10; x+5", "15");
    check("x=x+2; x*3", "var x=1; x=x+2; x*3", "9");
    check("if(x>3) x=100", "var x=5; if(x>3){x=100}else{x=0} x", "100");
    check("while sum", "var i=0; while(i<4){i=i+1} i", "4");
    check("for sum 0..4", "var s=0; for(var i=0;i<5;i=i+1){s=s+i} s", "10");
    check("obj assign", "var o={a:1}; o.a=99; o.a", "99");
    check("arr assign", "var a=[1,2,3]; a[0]=7; a[0]", "7");
    check("function f(21)=42", "function f(x){return x*2} f(21)", "42");
    check("closure inc", "var x=1; function f(){x=x+1} f(); x", "2");
    check("closure read", "var x=1; function f(){return x+1} f()+f()", "4");

    /* --- advanced --- */
    check("counter closure", "function mk(){var c=0; return function(){c=c+1; return c}} var f=mk(); f()+f()+f()", "6");
    check("nested loop", "var s=0; for(var i=0;i<3;i=i+1){for(var j=0;j<3;j=j+1){s=s+1}} s", "9");
    check("obj method", "var o={x:5}; function sety(o,v){o.y=v} sety(o,7); o.y", "7");
    check("++ postfix", "var i=5; var j=i++; i", "6");
    check("++ prefix", "var i=5; var j=++i; i", "6");
    check("+= compound", "var x=5; x+=10; x", "15");
    check("str == str", "'abc'=='abc'", "true");
    check("str < str", "'abc'<'abd'", "true");
    check("nested arr", "[[1,2],[3,4]][1][0]", "3");
    check("obj chain", "({a:{b:{c:42}}}).a.b.c", "42");
    check("recursion", "function fac(n){if(n<=1){return 1} return n*fac(n-1)} fac(5)", "120");
    check("array push-ish", "var a=[]; var i=0; while(i<3){a[i]=i*10; i=i+1} a[2]", "20");
    check("shadowing", "var x=1; function f(){var x=2; return x} f()+x", "3");
    check("early return", "function f(){return 5; return 999} f()", "5");

    /* --- flow control: break / continue / do-while --- */
    check("while+break", "var i=0; while(true){i=i+1; if(i==3){break}} i", "3");
    check("while+continue", "var i=0; var s=0; while(i<5){i=i+1; if(i%2==0){continue} s=s+i} s", "9");
    check("for+break", "var s=0; for(var i=0;i<100;i=i+1){if(i==4){break} s=s+i} s", "6");
    check("for+continue", "var s=0; for(var i=0;i<5;i=i+1){if(i==2){continue} s=s+i} s", "8");
    check("nested break", "var s=0; for(var i=0;i<3;i=i+1){for(var j=0;j<5;j=j+1){if(i==1){break} s=s+1}} s", "10");
    check("do-while", "var i=0; do{i=i+1}while(i<3) i", "3");
    check("do-while runs once", "var i=0; do{i=i+1}while(false) i", "1");
    check("do-while+break", "var i=0; var s=0; do{i=i+1; if(i>=3){break} s=s+i}while(true) s", "3");
    check("continue in function loop", "function f(){var s=0; for(var i=0;i<4;i=i+1){if(i==0){continue} s=s+i} return s} f()", "6");

    /* --- properties: .length, string indexing --- */
    check("str.length", "'hello'.length", "5");
    check("str index", "'hello'[1]", "e");
    check("str index oob", "'hi'[5]", "");
    check("arr.length", "[1,2,3,4].length", "4");
    check("arr length var", "var a=[7,8]; var n=a.length; n", "2");

    /* --- methods: push / pop, substring / charAt --- */
    check("arr.push returns len", "var a=[1,2]; var n=a.push(3); n", "3");
    check("arr.push mutates", "var a=[1,2]; a.push(3); a[2]", "3");
    check("arr.pop", "var a=[1,2,3]; a.pop()", "3");
    check("arr.pop shrinks", "var a=[1,2,3]; a.pop(); a.length", "2");
    check("arr.pop empty", "var a=[]; a.pop()+1", "1");
    check("substring one", "'hello'.substring(1,3)", "el");
    check("substring open-end", "'hello'.substring(2)", "llo");
    check("substring swap", "'abcde'.substring(4,1)", "bcd");
    check("charAt", "'hello'.charAt(0)", "h");
    check("charAt oob", "'hello'.charAt(99)", "");
    check("push+pop combo", "var a=[1]; a.push(2); a.push(3); a.pop()+a.length", "5");

    /* --- error reporting --- */
    checkErr("err call non-func", "var q = 5; q()");
    checkErr("err call undefined", "someMissing(1,2)");
    checkErr("err garbage input", "@ @ garbage");

    /* --- typeof / strict equality --- */
    check("typeof number", "typeof 5", "number");
    check("typeof string", "typeof 'abc'", "string");
    check("typeof bool", "typeof true", "boolean");
    check("typeof null", "typeof null", "object");
    check("typeof undefined var", "typeof missingVar", "undefined");
    check("=== same num", "1===1", "true");
    check("=== num vs str", "1==='1'", "false");
    check("!== num vs str", "1!=='1'", "true");
    check("=== str content", "'ab'==='ab'", "true");
    check("=== bool strict", "true===1", "false");
    check("=== null", "null===null", "true");

    /* --- global helpers: parseInt / parseFloat / isNaN / Number / String --- */
    check("parseInt", "parseInt('42')", "42");
    check("parseInt radix", "parseInt('ff',16)", "255");
    check("parseInt stops", "parseInt('12.9')", "12");
    check("parseInt junk", "parseInt('abc')", "NaN");
    check("parseFloat", "parseFloat('3.5')", "3.5");
    check("parseFloat int", "parseFloat('7xyz')", "7");
    check("isNaN num", "isNaN(5)", "false");
    check("isNaN str junk", "isNaN('xyz')", "true");
    check("isNaN str num", "isNaN('42')", "false");
    check("Number(str)", "Number('17')", "17");
    check("Number(bool)", "Number(true)", "1");
    check("Number(num)", "Number(9)", "9");
    check("String(num)", "String(123)", "123");
    check("String concat", "String(1+2)+'x'", "3x");

    /* --- Math.* --- */
    check("Math.floor", "Math.floor(3.7)", "3");
    check("Math.floor neg", "Math.floor(-2.1)", "-3");
    check("Math.abs", "Math.abs(-5)", "5");
    check("Math.min", "Math.min(3,9)", "3");
    check("Math.max", "Math.max(3,9)", "9");
    check("Math.sqrt", "Math.sqrt(16)", "4");
    check("Math.pow", "Math.pow(2,10)", "1024");
    check("Math.pow inv", "Math.pow(2,-1)", "0.5");
    /* --- more Math.* (no libm: Taylor/Newton impls in jsrt) --- */
    check("Math.ceil", "Math.ceil(4.2)", "5");
    check("Math.ceil neg", "Math.ceil(-4.2)", "-4");
    check("Math.round", "Math.round(3.5)", "4");
    check("Math.round neg", "Math.round(-2.5)", "-2");
    check("Math.trunc", "Math.trunc(3.9)", "3");
    check("Math.trunc neg", "Math.trunc(-3.9)", "-3");
    check("Math.sign pos", "Math.sign(9)", "1");
    check("Math.sign neg", "Math.sign(-5)", "-1");
    check("Math.sign zero", "Math.sign(0)", "0");
    check("Math.clz32", "Math.clz32(1)", "31");
    check("Math.clz32 zero", "Math.clz32(0)", "32");
    check("Math.clz32 hi", "Math.clz32(2147483648)", "0");
    check("Math.imul", "Math.imul(3,-2)", "-6");
    check("Math.imul wrap", "Math.imul(65536,65536)", "0");
    check("Math.imul big", "Math.imul(123456789,7)", "864197523");
    check("Math.exp 0", "Math.exp(0)", "1");
    check("Math.exp 1", "Math.abs(Math.exp(1)-2.718281828)<1e-5?1:0", "1");
    check("Math.expm1 0", "Math.expm1(0)", "0");
    check("Math.expm1", "Math.abs(Math.expm1(1)-1.718281828)<1e-5?1:0", "1");
    check("Math.log 1", "Math.log(1)", "0");
    check("Math.log e", "Math.abs(Math.log(Math.E)-1)<1e-6?1:0", "1");
    check("Math.log2", "Math.log2(8)", "3");
    check("Math.log10", "Math.log10(100)", "2");
    check("Math.log1p 0", "Math.log1p(0)", "0");
    check("Math.log1p", "Math.abs(Math.log1p(2)-1.0986123)<1e-6?1:0", "1");
    check("Math.cbrt", "Math.cbrt(27)", "3");
    check("Math.cbrt neg", "Math.cbrt(-8)", "-2");
    check("Math.cbrt small", "Math.abs(Math.cbrt(2)-1.259921)<1e-6?1:0", "1");
    check("Math.hypot", "Math.hypot(3,4)", "5");
    check("Math.hypot many", "Math.hypot(2,3,6)", "7");
    check("Math.sin 0", "Math.sin(0)", "0");
    check("Math.cos 0", "Math.cos(0)", "1");
    check("Math.tan 0", "Math.tan(0)", "0");
    check("Math.sin 1", "Math.abs(Math.sin(1)-0.841470985)<1e-6?1:0", "1");
    check("Math.cos 1", "Math.abs(Math.cos(1)-0.540302306)<1e-6?1:0", "1");
    check("Math.tan 1", "Math.abs(Math.tan(1)-1.5574077)<1e-4?1:0", "1");
    check("Math.sin pi2", "Math.abs(Math.sin(Math.PI/2)-1)<1e-6?1:0", "1");
    check("Math.cos pi", "Math.abs(Math.cos(Math.PI)+1)<1e-6?1:0", "1");
    check("Math.sin 100", "Math.abs(Math.sin(100)+0.5063656)<1e-5?1:0", "1");
    check("Math.asin 0", "Math.asin(0)", "0");
    check("Math.asin 1", "Math.abs(Math.asin(1)-1.5707963)<1e-6?1:0", "1");
    check("Math.acos 1", "Math.acos(1)", "0");
    check("Math.acos 0", "Math.abs(Math.acos(0)-1.5707963)<1e-6?1:0", "1");
    check("Math.atan 0", "Math.atan(0)", "0");
    check("Math.atan 1", "Math.abs(Math.atan(1)-0.78539816)<1e-6?1:0", "1");
    check("Math.atan 100", "Math.abs(Math.atan(100)-1.5607966)<1e-5?1:0", "1");
    check("Math.atan2 q1", "Math.abs(Math.atan2(1,1)-0.78539816)<1e-6?1:0", "1");
    check("Math.atan2 q2", "Math.abs(Math.atan2(-1,1)+0.78539816)<1e-6?1:0", "1");
    check("Math.atan2 pi", "Math.abs(Math.atan2(0,-1)-3.1415927)<1e-6?1:0", "1");
    check("Math.atan2 pi2", "Math.abs(Math.atan2(1,0)-1.5707963)<1e-6?1:0", "1");
    check("Math.atan2 inv", "Math.abs(Math.atan2(0,1))<1e-6?1:0", "1");
    check("Math.sinh 0", "Math.sinh(0)", "0");
    check("Math.cosh 0", "Math.cosh(0)", "1");
    check("Math.tanh 0", "Math.tanh(0)", "0");
    check("Math.sinh 1", "Math.abs(Math.sinh(1)-1.1752012)<1e-6?1:0", "1");
    check("Math.cosh 1", "Math.abs(Math.cosh(1)-1.5430806)<1e-6?1:0", "1");
    check("Math.tanh 1", "Math.abs(Math.tanh(1)-0.76159416)<1e-6?1:0", "1");
    check("Math.asinh 0", "Math.asinh(0)", "0");
    check("Math.acosh 1", "Math.acosh(1)", "0");
    check("Math.atanh 0", "Math.atanh(0)", "0");
    check("Math.asinh 1", "Math.abs(Math.asinh(1)-0.88137359)<1e-6?1:0", "1");
    check("Math.acosh 2", "Math.abs(Math.acosh(2)-1.3169579)<1e-6?1:0", "1");
    check("Math.atanh half", "Math.abs(Math.atanh(0.5)-0.54930615)<1e-6?1:0", "1");
    check("Math.fround", "Math.abs(Math.fround(1.1)-1.100000023841858)<1e-4?1:0", "1");
    check("Math.PI", "Math.PI>3.14&&Math.PI<3.15?1:0", "1");
    check("Math.E", "Math.E>2.71&&Math.E<2.72?1:0", "1");
    check("Math.SQRT2", "Math.SQRT2>1.41&&Math.SQRT2<1.42?1:0", "1");
    check("Math.LN2 close", "Math.abs(Math.LN2-0.69314718)<1e-6?1:0", "1");
    check("Math.const expr", "Math.abs(Math.exp(1)-Math.E)<1e-5?1:0", "1");
    check("Math.E via log1p", "Math.abs(Math.log1p(Math.E-1)-1)<1e-5?1:0", "1");

    /* --- string methods: indexOf/slice/substr/case/split --- */
    check("indexOf found", "'hello'.indexOf('l')", "2");
    check("indexOf missing", "'hello'.indexOf('z')", "-1");
    check("indexOf from", "'hello'.indexOf('l',3)", "3");
    check("slice", "'hello'.slice(1,3)", "el");
    check("slice neg", "'hello'.slice(-2)", "lo");
    check("slice open-end", "'hello'.slice(2)", "llo");
    check("substr", "'hello'.substr(1,3)", "ell");
    check("substr neg start", "'hello'.substr(-3)", "llo");
    check("toUpperCase", "'hello'.toUpperCase()", "HELLO");
    check("toLowerCase", "'HeLLo'.toLowerCase()", "hello");
    check("split", "'a,b,c'.split(',')[1]", "b");
    check("split count", "'a,b,c'.split(',').length", "3");
    check("split 2nd", "'x1y1z'.split('1')[1]", "y");
    check("split chars", "'ab'.split('')[1]", "b");
    check("split oob", "'a,b'.split(',')[5]+1", "1");

    /* --- array methods: join/indexOf/shift/unshift/slice --- */
    check("arr.join", "[1,2,3].join('-')", "1-2-3");
    check("arr.join default", "[1,2,3].join()", "1,2,3");
    check("arr.indexOf", "[10,20,30].indexOf(20)", "1");
    check("arr.indexOf miss", "[10,20,30].indexOf(99)", "-1");
    check("arr.shift", "var a=[1,2,3]; a.shift()", "1");
    check("arr.shift shrinks", "var a=[1,2,3]; a.shift(); a.length", "2");
    check("arr.unshift", "var a=[2,3]; a.unshift(1); a[0]", "1");
    check("arr.unshift len", "var a=[2,3]; a.unshift(1)", "3");
    check("arr.slice e0", "[1,2,3,4].slice(1,3)[0]", "2");
    check("arr slice e1", "[1,2,3,4].slice(1,3)[1]", "3");
    check("arr slice neg", "[1,2,3,4].slice(-2)[0]", "3");
    check("arr slice len", "[1,2,3,4].slice(1).length", "3");

    /* --- objects: delete / in / Object.keys --- */
    check("obj delete", "var o={a:1,b:2}; delete o.a; o.a", "undefined");
    check("delete returns true", "var o={a:1}; var d=delete o.a; d", "true");
    check("delete keeps b", "var o={a:1,b:2}; delete o.a; o.b", "2");
    check("in present", "'a' in {a:1,b:2}", "true");
    check("in absent", "'z' in {a:1,b:2}", "false");
    check("in array idx", "0 in [7,8]", "true");
    check("in array oob", "5 in [7,8]", "false");
    check("Object.keys count", "var o={a:1,b:2,c:3}; Object.keys(o)[2]", "c");
    check("Object.keys len", "Object.keys({x:9,y:8}).length", "2");

    /* --- template literals --- */
    check("template const", "`hello`", "hello");
    check("template expr", "var x=5; `x=${x}`", "x=5");
    check("template multi", "var a=1,b=2; `${a}+${b}=${a+b}`", "1+2=3");
    check("template mix", "`a ${1} b ${2}`", "a 1 b 2");

    /* --- switch / case / default --- */
    check("switch match", "var x=2; switch(x){case 1:{x=10} case 2:{x=20} default:{x=30}} x", "30");
    check("switch break", "var x=2; switch(x){case 1:{x=10; break} case 2:{x=20; break} default:{x=30}} x", "20");
    check("switch default only", "var x=9; var r=0; switch(x){case 1:{r=1; break} default:{r=5}} r", "5");
    check("switch no match no def", "var x=9; var r=0; switch(x){case 1:{r=1}} r", "0");
    check("switch string", "var x='b'; var r=''; switch(x){case 'a':{r='A'} case 'b':{r='B'; break} default:{r='Z'}} r", "B");
    check("switch fallthrough", "var x=1; var r=0; switch(x){case 1:{r=r+1} case 2:{r=r+10} default:{r=r+100}} r", "111");
    check("switch empty body", "var x=1; var r=0; switch(x){case 1: default:{r=9}} r", "9");
    check("switch nested case", "var x=2; var s=0; switch(x){case 1:{s=s+1} case 2:{s=s+2} case 3:{s=s+3}} s", "5");

    /* --- comments --- */
    check("line comment", "/* hi */ 1+2 // trailing", "3");
    check("block comment mid", "1+ /* c */ 2", "3");
    check("line comment in stmt", "var a=1; // note\n a+2", "3");

    /* --- Math: fractional powers / roots --- */
    check("Math.pow frac", "Math.pow(9,0.5)", "3");
    check("Math.pow root neg", "Math.pow(-8,1/3)", "-2");
    check("Math.pow root pos", "Math.pow(8,1/3)", "2");
    check("Math.pow zero zero", "Math.pow(0,0)", "1");
    check("Math.TAU", "Math.TAU", "6.283185307179586");

    /* --- first-class builtins --- */
    check("typeof Math", "typeof Math", "object");
    check("typeof Math.sqrt", "typeof Math.sqrt", "function");
    check("first-class Math member", "var f=Math.sqrt; f(16)", "4");
    check("map with builtin fn", "[1,4,9].map(Math.sqrt).join(',')", "1,2,3");
    check("typeof parseInt", "typeof parseInt", "function");
    check("first-class parseInt", "var f=parseInt; f('42')", "42");
    check("typeof Object", "typeof Object", "function");
    check("typeof Object.keys", "typeof Object.keys", "function");
    check("typeof JSON.parse", "typeof JSON.parse", "function");
    check("typeof console.log", "typeof console.log", "function");
    check("typeof console.warn", "typeof console.warn", "function");
    check("map with Object", "[1,2].map(Object).join(',')", "1,2");
    check("Array(n)", "Array(3).length", "3");
    check("Array.isArray", "Array.isArray([1])", "true");

    /* --- globalThis --- */
    check("typeof globalThis", "typeof globalThis", "object");
    check("globalThis alias", "globalThis.foo=5; foo", "5");
    check("globalThis.Math === Math", "globalThis.Math===Math", "true");
    check("delete global prop", "delete globalThis.zz; typeof zz", "undefined");

    /* --- eval --- */
    check("typeof eval", "typeof eval", "function");
    check("eval expr", "eval('1+2')", "3");
    check("eval sees locals", "(function(){var x=10; return eval('x+1')})()", "11");

    /* --- Object.freeze / Object.seal --- */
    check("freeze blocks write", "var o=Object.freeze({a:1}); o.a=5; o.a", "1");
    check("Object.isFrozen", "Object.isFrozen(Object.freeze({a:1}))", "true");
    check("Object.isSealed", "Object.isSealed(Object.seal({a:1}))", "true");
    check("seal blocks delete", "var o=Object.seal({a:1}); delete o.a; Object.keys(o).length", "1");

    /* --- JSON round-trip --- */
    check("JSON.parse idx", "JSON.parse('[1,2]')[1]", "2");
    check("JSON.stringify", "JSON.stringify({a:1,b:[2,'x']})", "{\"a\":1,\"b\":[2,\"x\"]}");

    printf(g_fail ? "SOME FAILED\n" : "ALL OK\n");
    return g_fail ? 1 : 0;
}