/* ================================================================
   JSRT - freestanding, position-independent x86-64 JavaScript core
   (Zenith's own embedded JS engine; no V8/QuickJS/Node, no libc).

#ifdef JS_DEBUG
#include <stdio.h>
#endif

   First-stage scope: core language
     - var/let/const, numbers, strings, booleans, null, undefined
     - arithmetic, comparisons, ===/!== strict equality, && || !, ternary
     - in, typeof x, delete obj.key
     - objects {}, arrays []
     - function decls + anonymous expressions, calls, closures
     - if/else, for, while, do-while, switch/case/default, break/continue, return
     - comments: // line, and slash-star block comments
     - template strings  `a=${expr} b=${x}`
     - strings/arrays: .length, s[i], push/pop, substring/charAt, indexOf,
       slice, substr, toUpperCase/toLowerCase (ASCII), split, join, shift,
       unshift
     - globals: parseInt/parseFloat/isNaN/Number/String, Math.floor/abs/min/
       max/sqrt/pow, Object.keys

   Compiled by HOST gcc as Linux x86-64 (SysV) with -ffreestanding -fno-pic,
   embedded into .exe .text as a blob (see tools/gen_js_blob.sh); invoked via
   `call rel32` into jsrt_entry (rdi=op, rsi=a1, rdx=a2, rcx=a3, ...).

   Memory: static bump arena in .bss. Everything allocated there; never freed
   within one script run (fine for lightweight eval). JS_OP_RESET rewinds.

   Objects/arrays are mutable: their property/element lists live in a "Box"
   reached through the Val payload, so assignment updates the shared list even
   when a Val is copied/returned.

   Entry ops:
     JS_OP_RESET  (no args)                      reset arena + globals
     JS_OP_EXEC   (a1=src, a2=len)               run a program (statements) -> 0 / -1
     JS_OP_EXPR   (a1=src, a2=len)               eval an expression, store result -> 0 / -1
     JS_OP_RESULT (a1=out, a2=cap)               copy last result as string -> strlen
     JS_OP_ERROR  (a1=out, a2=cap)               copy last error text -> strlen ("" if none)
     JS_OP_NUM    (no args)                      numeric value of last result (0 if non-num)

   Errors: a failed parse or a clear runtime error (e.g. calling a non-function)
   is reported through g_errbuf + g_had_error: EXEC/EXPR return -1, and
   JS_OP_ERROR returns the message. The parser is intentionally permissive, so
   not every malformed input is caught (e.g. `(1+2` parses as 1+2).
   ================================================================ */

#ifdef JS_DEBUG
#include <stdio.h>
#endif

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

/* ---- script heap: free-list allocator + mark-sweep GC ----
   Every allocation returns a zeroed payload (callers rely on that).
   Each block: [Bhdr 16B][payload]. Free blocks store their free-list
   link at the start of the payload. arena_alloc first tries the free
   list (first-fit, split), then bumps from h_off. When both fail it
   sets g_oom and returns 0; safe mark-sweep GC (heap_gc) runs only at
   top-level boundaries (between server requests), never mid-exec,
   so on a long-running server memory is reclaimed and reused.      */
#define JS_HEAP (16u << 20)   /* 16 MiB script heap */
#define HDR  16
#define MINBLK 32

typedef struct Bhdr { u64 size; u64 flags; } Bhdr;   /* flags: bit0 USED, bit1 MARK */
static unsigned char heap[JS_HEAP];
static u64 h_off;                /* bump top (bytes used) */
static Bhdr* g_freelist;         /* free blocks (link stored in payload) */
static int  g_oom;               /* set when an alloc failed mid-exec */
typedef struct ModEntry ModEntry;
static ModEntry* g_mod_cache;
/* Current module directory for nested require() resolution ("" = cwd).
   NULL at boot: the require entry point lazily allocates a runtime "." from
   the arena. It must NOT hold a .rodata literal here, because the embedded
   Windows blob runs at an arbitrary base and never relocates pointer values
   stored in .data (a raw literal offset would be dereferenced and fault). */
static const char* g_cur_dir;

/* Math.random PRNG (xoshiro128**-ish, seeded once per reset). */
static u64 g_rng[4];
static u64 rng_next(void){
    u64 t=g_rng[1]<<17;
    g_rng[2]^=g_rng[0]; g_rng[3]^=g_rng[1];
    g_rng[1]^=g_rng[2]; g_rng[0]^=g_rng[3];
    g_rng[2]^=t;
    g_rng[3]=(g_rng[3]<<45)|(g_rng[3]>>19);
    return g_rng[0];
}

/* GC pacing state (sweep is budgeted/resumable → server stays responsive):
   while g_gc_busy is set, arena_alloc ignores the free list (bump only). */
static int  g_gc_busy;
static unsigned char* g_gc_p;    /* sweep resume cursor */
static Bhdr* g_gc_fl;            /* free list under construction */

static int  h_in_heap(void* p){ return (unsigned char*)p>=heap && (unsigned char*)p<heap+JS_HEAP; }
static Bhdr* b_hdr(void* p){ return (Bhdr*)((unsigned char*)p - HDR); }
static Bhdr** b_next(Bhdr* b){ return (Bhdr**)((unsigned char*)b + HDR); }

static void* arena_alloc(u64 sz){
    u64 need = (sz + HDR + 15) & ~(u64)15;
    if(need < MINBLK) need = MINBLK;
    if(!g_gc_busy){
        Bhdr** pp=&g_freelist;
        while(*pp){
            Bhdr* b=*pp;
            if(b->size>=need){
                if(b->size-need>=MINBLK){
                    Bhdr* tail=(Bhdr*)((unsigned char*)b+need);
                    tail->size=b->size-need; tail->flags=0;
                    *pp=tail;
                    *b_next(tail)=0;
                    b->flags=1; b->size=need;
                } else {
                    *pp = *b_next(b);
                    b->flags=1;
                }
                unsigned char* payload=(unsigned char*)b+HDR;
                for(u64 i=0;i<need-HDR;i++) payload[i]=0;
                return payload;
            }
            pp=b_next(b);
        }
    }
    if(h_off+need<=JS_HEAP){
        Bhdr* b=(Bhdr*)(heap+h_off);
        b->size=need; b->flags=1;
        unsigned char* payload=(unsigned char*)b+HDR;
        for(u64 i=0;i<need-HDR;i++) payload[i]=0;
        h_off+=need;
        return payload;
    }
    g_oom=1;
    return 0;
}
static void heap_gc_start(void);
static int  heap_gc_step(void);
static void arena_reset(void){
    h_off=0; g_freelist=0; g_oom=0; g_mod_cache=0;
    g_gc_busy=0; g_gc_p=0; g_gc_fl=0;
    /* Seed Math.random (splitmix64) — deterministic per boot so tests are stable. */
    static u64 boot_n=0; boot_n++;
    u64 z=boot_n+0x9E3779B97F4A7C15ull;
    for(int i=0;i<4;i++){ z+=(z<<30); z^=z>>6; z+=(z<<14); z^=z>>9; z+=(z<<24); g_rng[i]=z; }
}

static u64 xstrlen(const char* s){ u64 n=0; while(s[n])n++; return n; }
#ifdef JS_DEBUG
#include <stdio.h>
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) do{}while(0)
#endif
static int xstrcmp(const char*a,const char*b){ while(*a&&*a==*b){a++;b++;} return (int)((unsigned char)*a-(unsigned char)*b); }
static const char* xstrstr(const char* h, const char* n){
    if(!*n) return h;
    u64 nl=xstrlen(n);
    for(const char* p=h; *p; p++){
        if(*p==*n){
            u64 i=0; while(i<nl && p[i] && p[i]==n[i]) i++;
            if(i==nl) return p;
        }
    }
    return 0;
}
static void xmemcpy(void*d,const void*s,u64 n){ unsigned char*dd=(unsigned char*)d; const unsigned char*ss=(const unsigned char*)s; for(u64 i=0;i<n;i++)dd[i]=ss[i]; }
static char* kerndup(const char* s);

/* ================================================================
   VALUES
   ================================================================ */
typedef struct Node Node;
typedef struct Env Env;
typedef struct Box Box;

#define V_NUM  0
#define V_STR  1
#define V_BOOL 2
#define V_OBJ  3
#define V_ARR  4
#define V_FUNC 5
#define V_NULL 6
#define V_UNDEF 7

typedef struct {
    unsigned tag;
    double num;      /* numeric value if V_NUM */
    u64    p;        /* payload: Str* | Box* | Node* (func) */
} Val;

typedef struct { u64 len; const char* data; } Str;
struct Box { Node* head; Box* proto; };

#define vnum(d)     ((Val){V_NUM,  (double)(d), 0})
#define vbool(b)    ((Val){V_BOOL, (b)?1:0,     0})
#define vnull()     ((Val){V_NULL, 0,           0})
#define vundef()    ((Val){V_UNDEF,0,           0})
#define vstrof(s)   ((Val){V_STR,  0,           (u64)(s)})
#define vobjof(b)   ((Val){V_OBJ,  0,           (u64)(b)})
#define varrb(b)    ((Val){V_ARR,  0,           (u64)(b)})
#define vfnof(n)    ((Val){V_FUNC, 0,           (u64)(n)})

static Str* _str(Val v){ return (Str*)v.p; }
static Box* _box(Val v){ return (Box*)v.p; }
static Node* _fn(Val v){ return (Node*)v.p; }

static Str* mkstr(const char* s, u64 n){
    Str* r=(Str*)arena_alloc(sizeof(Str));
    if(!r) return 0;
    char* d=(char*)arena_alloc(n+1); if(!d) return 0;
    xmemcpy(d,s,n); d[n]=0; r->len=n; r->data=d;
    return r;
}

/* ================================================================
   AST / PROP NODES
   ================================================================ */
struct Node {
    int   kind;
    char* key;        /* ident / member / operator / prop name */
    u64   ival;       /* int literal / count / flags */
    char* rflags; u64 rflen;   /* regex flags (NK_REGEX -> box marker) */
    Node* a; Node* b; Node* c; Node* d;
    Node* next;
    Val   val;        /* literal value / prop value / env slot value */
    Env*  def;        /* defining (closure) env for NK_FUNC */
    Box*  proto;      /* prototype box for NK_FUNC (shared across instances) */
};

#define NK_NUM     1
#define NK_STR     2
#define NK_BOOL    3
#define NK_IDENT   4
#define NK_OBJ     5
#define NK_ARR     6
#define NK_FUNC    7
#define NK_VAR     8
#define NK_ASSIGN  9
#define NK_BIN    10
#define NK_UNARY  11
#define NK_IF     12
#define NK_WHILE  13
#define NK_FOR    14
#define NK_BLOCK  15
#define NK_RETURN 16
#define NK_CALL   17
#define NK_MEMBER 18
#define NK_POST   19
#define NK_EMPTY  20
#define NK_STMTS  21
#define NK_TRIN   22
#define NK_UNDEF  23
#define NK_NULL   24
#define NK_LIST   25
#define NK_DO     26
#define NK_BREAK  27
#define NK_CONTINUE 28
#define NK_TEMPLATE 29
#define NK_SWITCH 30
#define NK_CASE   31
#define NK_DEFAULT 32
#define NK_TPL_EXPR 33
#define NK_NEW     34
#define NK_ASYNC   35
#define NK_AWAIT   36
#define NK_NATIVE  99   /* native builtin method ref (V_FUNC marker) */
#define NK_REGEX   37   /* regex literal: key=pattern, rflags -> box at eval */

static Node* mkn(int kind){
    Node* n=(Node*)arena_alloc(sizeof(Node));
    if(!n) return 0;
    n->kind=kind; n->key=0; n->ival=0; n->rflags=0; n->rflen=0; n->a=n->b=n->c=n->d=n->next=0; n->val=vundef();
    return n;
}

/* ================================================================
   LEXER
   ================================================================ */
typedef struct { const char* src; u64 pos,len; } Lexer;
static Lexer g_lex;

#define T_NUM 0
#define T_STR 1
#define T_IDENT 2
#define T_LBRACE 3
#define T_RBRACE 4
#define T_LPAREN 5
#define T_RPAREN 6
#define T_LBRACK 7
#define T_RBRACK 8
#define T_COMMA 9
#define T_SEMI 10
#define T_COLON 11
#define T_DOT 12
#define T_QUESTION 13
#define T_ASSIGN 14
#define T_PLUS 15
#define T_MINUS 16
#define T_STAR 17
#define T_SLASH 18
#define T_PERCENT 19
#define T_EQ 20
#define T_NE 21
#define T_LT 22
#define T_GT 23
#define T_LE 24
#define T_GE 25
#define T_ANDAND 26
#define T_OROR 27
#define T_NOT 28
#define T_EOF 29
#define T_VAR 30
#define T_LET 31
#define T_CONST 32
#define T_IF 33
#define T_ELSE 34
#define T_WHILE 35
#define T_FOR 36
#define T_RETURN 37
#define T_FUNC 38
#define T_TRUE 39
#define T_FALSE 40
#define T_NULL 41
#define T_PLUSASSIGN 42
#define T_MINUSASSIGN 43
#define T_STARASSIGN 44
#define T_SLASHASSIGN 45
#define T_PLUSPLUS 46
#define T_MINUSMINUS 47
#define T_DO 48
#define T_BREAK 49
#define T_CONTINUE 50
#define T_EQEQEQ 51
#define T_NEQNEQ 52
#define T_TYPEOF 53
#define T_DELETE 54
#define T_IN 55
#define T_SWITCH 56
#define T_CASE 57
#define T_DEFAULT 58
#define T_BACKTICK 59
#define T_NEW 60
#define T_THIS 61
#define T_INSTANCEOF 62
#define T_ASYNC 63
#define T_AWAIT 64
#define T_ARROW 65
#define T_REGEX 66

typedef struct { int kind; double num; char* str; u64 slen; u64 pos; char* rflags; u64 rflen; } Token;
static Token g_tok;

static int isws(char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; }
static int lex_hex(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
static void emit_cp_u(char* buf,u32* n,u32 cp){
    if(cp>0x10FFFF || (cp>=0xD800&&cp<=0xDFFF)) cp=0xFFFD;
    if(cp<=0x7F){ buf[(*n)++]=(char)cp; }
    else if(cp<=0x7FF){ buf[(*n)++]=(char)(0xC0|(cp>>6)); buf[(*n)++]=(char)(0x80|(cp&0x3F)); }
    else if(cp<=0xFFFF){ buf[(*n)++]=(char)(0xE0|(cp>>12)); buf[(*n)++]=(char)(0x80|((cp>>6)&0x3F)); buf[(*n)++]=(char)(0x80|(cp&0x3F)); }
    else { buf[(*n)++]=(char)(0xF0|(cp>>18)); buf[(*n)++]=(char)(0x80|((cp>>12)&0x3F)); buf[(*n)++]=(char)(0x80|((cp>>6)&0x3F)); buf[(*n)++]=(char)(0x80|(cp&0x3F)); }
}
static int isalpha_(char c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||c=='$'; }
static int isalnum_(char c){ return isalpha_(c)||(c>='0'&&c<='9'); }

static int keyw(const char* s){
    if(!xstrcmp(s,"var"))return T_VAR; if(!xstrcmp(s,"let"))return T_LET;
    if(!xstrcmp(s,"const"))return T_CONST; if(!xstrcmp(s,"if"))return T_IF;
    if(!xstrcmp(s,"else"))return T_ELSE; if(!xstrcmp(s,"while"))return T_WHILE;
    if(!xstrcmp(s,"for"))return T_FOR; if(!xstrcmp(s,"return"))return T_RETURN;
    if(!xstrcmp(s,"function"))return T_FUNC; if(!xstrcmp(s,"true"))return T_TRUE;
    if(!xstrcmp(s,"false"))return T_FALSE; if(!xstrcmp(s,"null"))return T_NULL;
    if(!xstrcmp(s,"do"))return T_DO; if(!xstrcmp(s,"break"))return T_BREAK;
    if(!xstrcmp(s,"continue"))return T_CONTINUE; if(!xstrcmp(s,"typeof"))return T_TYPEOF;
    if(!xstrcmp(s,"delete"))return T_DELETE; if(!xstrcmp(s,"in"))return T_IN;
    if(!xstrcmp(s,"switch"))return T_SWITCH; if(!xstrcmp(s,"case"))return T_CASE;
    if(!xstrcmp(s,"default"))return T_DEFAULT;
    if(!xstrcmp(s,"new"))return T_NEW; if(!xstrcmp(s,"this"))return T_THIS;
    if(!xstrcmp(s,"instanceof"))return T_INSTANCEOF;
    if(!xstrcmp(s,"async"))return T_ASYNC; if(!xstrcmp(s,"await"))return T_AWAIT;
    return -1;
}
static int tok_ends_operand(int k){
    switch(k){
        case T_NUM: case T_STR: case T_IDENT: case T_TRUE: case T_FALSE: case T_NULL:
        case T_RPAREN: case T_RBRACK: case T_RBRACE: case T_THIS: case T_PLUSPLUS:
        case T_MINUSMINUS: case T_BACKTICK: case T_REGEX: return 1;
    }
    return 0;
}
static void next_tok(void){
    Lexer* L=&g_lex;
    for(;;){
        while(L->pos<L->len && isws(L->src[L->pos])) L->pos++;
        if(L->pos+1<L->len && L->src[L->pos]=='/' && L->src[L->pos+1]=='/'){     /* // line comment */
            while(L->pos<L->len && L->src[L->pos]!='\n') L->pos++;
            continue;
        }
        if(L->pos+1<L->len && L->src[L->pos]=='/' && L->src[L->pos+1]=='*'){     /* /* block comment */
            L->pos+=2;
            while(L->pos+1<L->len && !(L->src[L->pos]=='*' && L->src[L->pos+1]=='/')) L->pos++;
            L->pos+=2; if(L->pos>L->len) L->pos=L->len;
            continue;
        }
        break;
    }
    Token* t=&g_tok;
    t->pos=L->pos;
    if(L->pos>=L->len){ t->kind=T_EOF; t->str=0; t->slen=0; return; }
    char c=L->src[L->pos];
    if(c>='0'&&c<='9'){
        if(c=='0' && L->pos+1<L->len && (L->src[L->pos+1]=='x'||L->src[L->pos+1]=='X')){
            /* hex literal */
            u64 p=L->pos+2; double vh=0; int any=0;
            while(p<L->len){ int h=lex_hex(L->src[p]); if(h<0) break; vh=vh*16+h; any=1; p++; }
            if(any){ L->pos=p; t->kind=T_NUM; t->num=vh; return; }
            /* else fall through to 0 + ident below */
        }
        double v=0; int frac=0; double sc=1;
        while(L->pos<L->len){
            char d=L->src[L->pos];
            if(d=='.'&&!frac){ frac=1; L->pos++; continue; }
            if(d>='0'&&d<='9'){ if(frac){sc*=0.1;v+=(d-'0')*sc;} else v=v*10+(d-'0'); L->pos++; continue; }
            if(d=='e'||d=='E'){
                u64 p=L->pos+1; int esign=1;
                if(p<L->len && (L->src[p]=='+'||L->src[p]=='-')){ if(L->src[p]=='-') esign=-1; p++; }
                if(p<L->len && L->src[p]>='0'&&L->src[p]<='9'){
                    L->pos=p; u64 e=0;
                    while(L->pos<L->len && L->src[L->pos]>='0'&&L->src[L->pos]<='9'){ e=e*10+(u64)(L->src[L->pos]-'0'); if(e>10000)e=10000; L->pos++; }
                    if(e>400){ v = esign<0 ? 0.0 : (1.0/0.0); }
                    else for(u64 k=0;k<e;k++) v = esign<0? v*0.1 : v*10.0;
                    continue;
                }
            }
            break;
        }
        t->kind=T_NUM; t->num=v; return;
    }
    if(isalpha_(c)){
        u64 s=L->pos;
        while(L->pos<L->len && isalnum_(L->src[L->pos])) L->pos++;
        char* id=(char*)arena_alloc(L->pos-s+1);
        xmemcpy(id,L->src+s,L->pos-s); id[L->pos-s]=0;
        t->slen=L->pos-s; int kw=keyw(id);
        t->kind= kw>=0?kw:T_IDENT; t->str=id; return;
    }
    if(c=='\''||c=='"'){
        char q=c; u64 s=++L->pos;
        {
            unsigned cap=(unsigned)((L->len-s)*4+4);
            char* str=(char*)arena_alloc(cap);
            u64 p=s; u32 n=0;
            while(p<L->len && L->src[p]!=q){
                if(L->src[p]=='\\' && p+1<L->len){
                    char e=L->src[p+1];
                    if(e=='n'){ str[n++]='\n'; p+=2; }
                    else if(e=='t'){ str[n++]='\t'; p+=2; }
                    else if(e=='r'){ str[n++]='\r'; p+=2; }
                    else if(e=='b'){ str[n++]=8; p+=2; }
                    else if(e=='f'){ str[n++]=12; p+=2; }
                    else if(e=='v'){ str[n++]=11; p+=2; }
                    else if(e=='x'){
                        p+=2; u32 cp=0; int ok=1;
                        for(int k2=0;k2<2;k2++){ int h= (p<L->len)? lex_hex(L->src[p]) : -1; if(h<0){ ok=0; break; } cp=cp*16+(u32)h; p++; }
                        if(ok) emit_cp_u(str,&n,cp);
                        else str[n++]='x';
                    }
                    else if(e=='u'){
                        if(p+2<L->len && L->src[p+2]=='{'){
                            p+=3; u32 cp=0; int got=0;
                            while(p<L->len && L->src[p]!='}'){ int h=lex_hex(L->src[p]); if(h<0){ got=0; break; } cp=cp*16+(u32)h; got=1; p++; }
                            if(p<L->len) p++;
                            if(got) emit_cp_u(str,&n,cp);
                            else { str[n++]='u'; str[n++]='{'; }
                        } else {
                            p+=2; u32 cp=0; int ok=1;
                            for(int k2=0;k2<4;k2++){ int h= (p<L->len)? lex_hex(L->src[p]) : -1; if(h<0){ ok=0; break; } cp=cp*16+(u32)h; p++; }
                            if(ok && cp>=0xD800 && cp<0xDC00){
                                /* surrogate pair: try \uXXXX low surrogate */
                                u32 lo=0; int lok=1;
                                if(p+1<L->len && L->src[p]=='\\' && L->src[p+1]=='u'){
                                    u64 q2=p+2; int vok=1;
                                    for(int k2=0;k2<4;k2++){ int h= (q2<L->len)? lex_hex(L->src[q2]) : -1; if(h<0){ vok=0; break; } lo=lo*16+(u32)h; q2++; }
                                    if(vok && lo>=0xDC00 && lo<=0xDFFF){
                                        emit_cp_u(str,&n,0x10000+((cp-0xD800)<<10)+(lo-0xDC00));
                                        p=q2; continue;
                                    }
                                } else { (void)lok; }
                                emit_cp_u(str,&n,cp);
                            } else if(ok) emit_cp_u(str,&n,cp);
                            else str[n++]='u';
                        }
                    }
                    else if(e=='0'){ str[n++]=0; p+=2; }
                    else if(e==q){ str[n++]=q; p+=2; }
                    else if(e=='\\'){ str[n++]='\\'; p+=2; }
                    else { str[n++]=e; p+=2; }   /* \q gives q for any other char */
                } else {
                    str[n++]=L->src[p++];
                }
            }
            str[n]=0;
            L->pos=p; if(L->pos<L->len) L->pos++;
            t->kind=T_STR; t->str=str; t->slen=n; return;
        }
    }
    #define TWO(a,b,A,B) if(c==a&&L->pos+1<L->len&&L->src[L->pos+1]==b){t->kind=A;L->pos+=2;return;}
    if(c=='='&&L->pos+2<L->len&&L->src[L->pos+1]=='='&&L->src[L->pos+2]=='='){ t->kind=T_EQEQEQ; L->pos+=3; return; }
    if(c=='!'&&L->pos+2<L->len&&L->src[L->pos+1]=='='&&L->src[L->pos+2]=='='){ t->kind=T_NEQNEQ; L->pos+=3; return; }
    TWO('=','=',T_EQ,T_EQ); TWO('!','=',T_NE,T_NE); TWO('<','=',T_LE,T_LE); TWO('>','=',T_GE,T_GE);
    TWO('&','&',T_ANDAND,T_ANDAND); TWO('|','|',T_OROR,T_OROR);
    TWO('+','=',T_PLUSASSIGN,T_PLUSASSIGN); TWO('-','=',T_MINUSASSIGN,T_MINUSASSIGN);
    TWO('*','=',T_STARASSIGN,T_STARASSIGN); TWO('/','=',T_SLASHASSIGN,T_SLASHASSIGN);
    TWO('+','+',T_PLUSPLUS,T_PLUSPLUS); TWO('-','-',T_MINUSMINUS,T_MINUSMINUS);
    TWO('=','>',T_ARROW,T_ARROW);
    #undef TWO
    switch(c){
        case '{':t->kind=T_LBRACE;break; case '}':t->kind=T_RBRACE;break;
        case '(':t->kind=T_LPAREN;break; case ')':t->kind=T_RPAREN;break;
        case '[':t->kind=T_LBRACK;break; case ']':t->kind=T_RBRACK;break;
        case ',':t->kind=T_COMMA;break; case ';':t->kind=T_SEMI;break;
        case ':':t->kind=T_COLON;break; case '.':t->kind=T_DOT;break;
        case '?':t->kind=T_QUESTION;break;
        case '=':t->kind=T_ASSIGN;break; case '+':t->kind=T_PLUS;break;
        case '-':t->kind=T_MINUS;break; case '*':t->kind=T_STAR;break;
        case '/': {
            int isreg = !tok_ends_operand(g_tok.kind);
            u64 re_e = 0;
            if(isreg){
                u64 p=L->pos+1; int inclass=0;
                while(p<L->len){
                    char rc=L->src[p];
                    if(rc=='\\'){ p+=2; continue; }
                    if(rc=='[') inclass=1;
                    else if(rc==']') inclass=0;
                    else if(rc=='\n') break;
                    else if(rc=='/' && !inclass) break;
                    p++;
                }
                if(p<L->len && L->src[p]=='/' && p>L->pos+1) re_e=p;
            }
            if(re_e){
                u64 patlen=re_e-(L->pos+1);
                char* pat=(char*)arena_alloc(patlen+1);
                xmemcpy(pat,L->src+L->pos+1,patlen); pat[patlen]=0;
                u64 q=re_e+1; char fl[9]; int fn=0;
                while(q<L->len && fn<8){
                    char rc=L->src[q];
                    if((rc>='a'&&rc<='z')||(rc>='A'&&rc<='Z')){ fl[fn++]=rc; q++; }
                    else break;
                }
                char* rf=(char*)arena_alloc(fn+1);
                xmemcpy(rf,fl,fn); rf[fn]=0;
                t->kind=T_REGEX; t->str=pat; t->slen=patlen; t->rflags=rf; t->rflen=(u64)fn;
                L->pos=q; return;
            }
            t->kind=T_SLASH;break;
        }
        case '%':t->kind=T_PERCENT;break;
        case '<':t->kind=T_LT;break; case '>':t->kind=T_GT;break;
        case '!':t->kind=T_NOT;break;
        case '`':t->kind=T_BACKTICK;break;
        default: t->kind=T_EOF; break;
    }
    L->pos++;
}
static int peek_is(int k){ return g_tok.kind==k; }
static void eat(int k){ if(g_tok.kind==k) next_tok(); }
static void set_err(const char* s);   /* forward: defined near heap/error section */

/* ================================================================
   STRICT SYNTAX ERROR TRACKING
   Real JS rejects malformed input with a SyntaxError; parse_* helpers
   below abort the recursive descent the moment syntax is invalid
   (unknown token, missing closer `)]}`, missing ':' in ?:, garbage
   after a statement) instead of silently dropping it.
   ================================================================ */
static int g_parse_abort;
static char g_syn_stop[64];           /* scratch for "SyntaxError: expected X" msgs */
static int syn_err(const char* msg){
    set_err(msg);
    g_parse_abort=1;
    return 1;
}
static int mk_expected_msg(const char* what){
    /* build "SyntaxError: expected <what>" without libc (freestanding blob) */
    g_syn_stop[0]=0;
    const char* p="SyntaxError: expected ";
    u64 n=xstrlen(p); if(n>=sizeof(g_syn_stop)) n=sizeof(g_syn_stop)-1;
    xmemcpy(g_syn_stop,p,n);
    u64 m=xstrlen(what); if(n+m>=sizeof(g_syn_stop)) m=sizeof(g_syn_stop)-1-n;
    xmemcpy(g_syn_stop+n,what,m); g_syn_stop[n+m]=0;
    return syn_err(g_syn_stop);
}
static int expect_tok(int k, const char* what){
    if(peek_is(k)){ next_tok(); return 0; }
    return mk_expected_msg(what);
}
static int expect_name(const char* what){
    if(peek_is(T_IDENT)){ next_tok(); return 0; }
    if(g_tok.kind>=T_VAR && g_tok.kind<=T_ARROW){ next_tok(); return 0; } /* keywords are valid property names */
    return mk_expected_msg(what);
}
/* tokens that may legally end a statement in this engine (JS without
   newline-sensitivity performs automatic semicolon insertion only at a
   line terminator; since the lexer drops newlines, every statement must
   end at ';', '}', EOF or a dedicated closing context) */
static int stmt_boundary_ok(void){
    switch(g_tok.kind){
        case T_SEMI: case T_EOF: case T_RBRACE: case T_ELSE:
        case T_RPAREN: case T_CASE: case T_DEFAULT: case T_WHILE:
            return 1;
    }
    return 0;
}
static int sync_stmt_end(void){
    if(!stmt_boundary_ok()) return syn_err("SyntaxError: expected ';'");
    return 0;
}

/* ================================================================
   PARSER (recursive descent)
   ================================================================ */
static Node* parse_expr(void);
static Node* parse_stmt(void);
static Node* parse_block(void);
static Node* parse_template(void);

/* `text ${expr} more` — parts are NK_STR literals and NK_TPL_EXPR expressions. */
static Node* parse_template(void){
    Node* n=mkn(NK_TEMPLATE);
    Node** tail=&n->a;
    for(;;){
        u64 s=g_lex.pos;
        while(g_lex.pos<g_lex.len && g_lex.src[g_lex.pos]!='`'){
            if(g_lex.src[g_lex.pos]=='$' && g_lex.pos+1<g_lex.len && g_lex.src[g_lex.pos+1]=='{') break;
            g_lex.pos++;
        }
        u64 lit=g_lex.pos-s;
        char* buf=(char*)arena_alloc(lit+1); if(!buf) return n;
        xmemcpy(buf,g_lex.src+s,lit); buf[lit]=0;
        Node* part=mkn(NK_STR); part->val=vstrof(mkstr(buf,lit));
        *tail=part; tail=&part->next;
        if(g_lex.pos>=g_lex.len) break;
        if(g_lex.src[g_lex.pos]=='`') break;
        g_lex.pos+=2; next_tok();
        Node* e=parse_expr();
        Node* ex=mkn(NK_TPL_EXPR); ex->a=e;
        *tail=ex; tail=&ex->next;
        if(peek_is(T_RBRACE)){
            g_lex.pos = g_tok.pos+1;   /* rewind just past '}'; literal scan reads raw source, no next_tok */
        } else { g_lex.pos=g_lex.len; break; }
    }
    if(g_lex.pos<g_lex.len && g_lex.src[g_lex.pos]=='`') g_lex.pos++;
    next_tok();
    return n;
}

static Node* parse_obj(void){
    next_tok(); /* { */
    Node* n=mkn(NK_OBJ);
    Node** tail=&n->a;
    while(!peek_is(T_RBRACE) && !peek_is(T_EOF)){
        if(!(peek_is(T_IDENT)||peek_is(T_STR)||(g_tok.kind>=T_VAR && g_tok.kind<=T_ARROW))){ syn_err("SyntaxError: expected property name"); return n; }
        char* k=g_tok.str; next_tok();
        if(expect_tok(T_COLON,"':'")) return n;
        Node* v=parse_expr();
        Node* prop=mkn(NK_ASSIGN);
        prop->key=kerndup(k);
        prop->a=v;
        *tail=prop; tail=&prop->next;
        if(peek_is(T_COMMA)){ next_tok(); if(peek_is(T_RBRACE)) break; } else break;
    }
    expect_tok(T_RBRACE,"'}'");
    return n;
}
static Node* parse_arr(void){
    next_tok(); /* [ */
    Node* n=mkn(NK_ARR);
    Node** tail=&n->a;
    while(!peek_is(T_RBRACK) && !peek_is(T_EOF)){
        Node* e=parse_expr();
        *tail=e; tail=&e->next;
        if(peek_is(T_COMMA)){ next_tok(); if(peek_is(T_RBRACK)) break; } else break;
    }
    expect_tok(T_RBRACK,"']'");
    return n;
}
static Node* parse_params(void){
    expect_tok(T_LPAREN,"'('");
    Node* list=mkn(NK_LIST);
    Node** tail=&list->a;
    while(!peek_is(T_RPAREN) && !peek_is(T_EOF)){
        if(!peek_is(T_IDENT)){ syn_err("SyntaxError: expected parameter name"); return list; }
        Node* p=mkn(NK_IDENT); p->key=kerndup(g_tok.str); next_tok();
        *tail=p; tail=&p->next;
        if(peek_is(T_COMMA)){ next_tok(); if(peek_is(T_RPAREN)) break; }
    }
    expect_tok(T_RPAREN,"')'");
    return list;
}
static Node* parse_block(void){
    expect_tok(T_LBRACE,"'{'");
    Node* b=mkn(NK_BLOCK);
    Node** tail=&b->a;
    while(!peek_is(T_RBRACE) && !peek_is(T_EOF)){
        Node* s=parse_stmt();
        *tail=s; tail=&s->next;
    }
    expect_tok(T_RBRACE,"'}'");
    return b;
}
static Node* parse_fn(void){
    next_tok(); /* function */
    Node* n=mkn(NK_FUNC);
    if(peek_is(T_IDENT)){ n->key=kerndup(g_tok.str); next_tok(); }
    n->a=parse_params();
    n->b=parse_block();
    return n;
}
static Node* parse_primary(void);
static int ws_char(char c){ return c==' '||c=='\n'||c=='\t'||c=='\r'; }
static int id_start(char c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||c=='$'; }
static int id_char(char c){ return id_start(c)||(c>='0'&&c<='9'); }
/* scan raw source right after '(' for the arrow-param pattern: [ident (,ident)*] ')'=>'. */
static int arrow_params_ahead(u64 pos){
    u64 p=pos, len=g_lex.len;
    while(p<len && ws_char(g_lex.src[p])) p++;
    for(;;){
        while(p<len && ws_char(g_lex.src[p])) p++;
        if(p>=len) return 0;
        if(g_lex.src[p]==')'){
            p++;
            while(p<len && ws_char(g_lex.src[p])) p++;
            if(p+1<len && g_lex.src[p]=='=' && g_lex.src[p+1]=='>') return 1;
            return 0;
        }
        if(!id_start(g_lex.src[p])) return 0;
        p++;
        while(p<len && id_char(g_lex.src[p])) p++;
        while(p<len && ws_char(g_lex.src[p])) p++;
        if(p>=len) return 0;
        if(g_lex.src[p]==','){ p++; continue; }
        if(g_lex.src[p]==')'){
            p++;
            while(p<len && ws_char(g_lex.src[p])) p++;
            if(p+1<len && g_lex.src[p]=='=' && g_lex.src[p+1]=='>') return 1;
            return 0;
        }
        return 0;
    }
}
/* called with current token = '=>': builds arrow-function node over param list */
static Node* parse_arrow_body(Node* params){
    if(!peek_is(T_ARROW)){ syn_err("SyntaxError: expected '=>'"); return mkn(NK_UNDEF); }
    next_tok();
    Node* n=mkn(NK_FUNC); n->a=params; n->ival=3; /* arrow */
    if(peek_is(T_LBRACE)){ n->b=parse_block(); }
    else {
        Node* e=parse_expr();
        Node* ret=mkn(NK_RETURN); ret->a=e;
        Node* body=mkn(NK_BLOCK); body->a=ret;
        n->b=body;
    }
    return n;
}
/* single-identifier arrow:  x => expr */
static Node* parse_arrow_single(Node* id){
    Node* params=mkn(NK_LIST); if(!params) return mkn(NK_UNDEF);
    params->a=id; id->next=0;
    return parse_arrow_body(params);
}
/* callee for `new`: primary + member/index chain, but stops BEFORE a call `(` */
static Node* parse_new_callee(void){
    Node* e=parse_primary();
    for(;;){
        if(peek_is(T_DOT)){
            next_tok();
            char* name = kerndup(g_tok.str);
            if(expect_name("property name after '.'")) break;
            Node*n=mkn(NK_MEMBER); n->a=e; n->key=name; n->b=0; e=n;
        } else if(peek_is(T_LBRACK)){
            next_tok(); Node* idx=parse_expr(); if(expect_tok(T_RBRACK,"']'")) break;
            Node*n=mkn(NK_MEMBER); n->a=e; n->key=0; n->b=idx; e=n;
        } else break;
    }
    return e;
}
/* parse `(a,b,c)` if present; always returns an arg list node */
static Node* parse_call_args(void){
    Node* args=mkn(NK_LIST);
    if(!peek_is(T_LPAREN)) return args;
    next_tok();
    Node** tail=&args->a;
    while(!peek_is(T_RPAREN) && !peek_is(T_EOF)){
        Node* a=parse_expr();
        *tail=a; tail=&a->next;
        if(peek_is(T_COMMA)){ next_tok(); if(peek_is(T_RPAREN)) break; } else break;
    }
    expect_tok(T_RPAREN,"')'");
    return args;
}
static Node* parse_primary(void){
    switch(g_tok.kind){
        case T_NUM: { Node*n=mkn(NK_NUM); n->val=vnum(g_tok.num); next_tok(); return n; }
        case T_STR: { Node*n=mkn(NK_STR); n->val=vstrof(mkstr(g_tok.str,g_tok.slen)); next_tok(); return n; }
        case T_REGEX: {
            Node*n=mkn(NK_REGEX); n->key=kerndup(g_tok.str);
            n->rflags=g_tok.rflags; n->rflen=g_tok.rflen; next_tok(); return n;
        }
        case T_TRUE: { Node*n=mkn(NK_BOOL); n->val=vbool(1); next_tok(); return n; }
        case T_FALSE:{ Node*n=mkn(NK_BOOL); n->val=vbool(0); next_tok(); return n; }
        case T_NULL: { Node*n=mkn(NK_NULL); next_tok(); return n; }
        case T_IDENT:{ Node*n=mkn(NK_IDENT); n->key=kerndup(g_tok.str); next_tok(); return n; }
        case T_THIS: { Node*n=mkn(NK_IDENT); n->key=kerndup("this"); next_tok(); return n; }
        case T_NEW: {
            next_tok();
            Node* callee=parse_new_callee();
            Node* args=parse_call_args();
            Node*n=mkn(NK_NEW); n->a=callee; n->b=args; return n;
        }
        case T_LPAREN:{ u64 after_paren=g_tok.pos+1;
            if(arrow_params_ahead(after_paren)){
                g_lex.pos=g_tok.pos; next_tok();            /* re-lex '(' */
                Node* params=parse_params();                 /* consumes ( .. ) */
                return parse_arrow_body(params);             /* current token is '=>' */
            }
            next_tok(); Node*e=parse_expr(); expect_tok(T_RPAREN,"')'"); return e; }
        case T_LBRACE: return parse_obj();
        case T_LBRACK: return parse_arr();
        case T_FUNC: return parse_fn();
        case T_ASYNC:
            next_tok();
            if(peek_is(T_FUNC)){ Node* f=parse_fn(); f->ival=2; return f; }
            /* otherwise treat `async` as a plain identifier */
            g_tok.kind=T_IDENT; g_tok.str=(char*)"async"; g_tok.slen=5; g_tok.num=0;
            { Node*n=mkn(NK_IDENT); n->key=kerndup("async"); return n; }
        case T_BACKTICK: return parse_template();
        case T_EOF:
            syn_err("SyntaxError: Unexpected end of input");
            return mkn(NK_UNDEF);
        default:
            syn_err("SyntaxError: Unexpected token");
            next_tok();
            return mkn(NK_UNDEF);
    }
}
static Node* parse_postfix(void){
    Node* e=parse_primary();
    if(peek_is(T_ARROW) && e->kind==NK_IDENT){
        return parse_arrow_single(e);
    }
    for(;;){
        if(peek_is(T_DOT)){
            next_tok();
            char* name = kerndup(g_tok.str);
            if(expect_name("property name after '.'")) break;
            Node*n=mkn(NK_MEMBER); n->a=e; n->key=name; n->b=0; e=n;
        } else if(peek_is(T_LBRACK)){
            next_tok(); Node* idx=parse_expr(); if(expect_tok(T_RBRACK,"']'")) break;
            Node*n=mkn(NK_MEMBER); n->a=e; n->key=0; n->b=idx; e=n;
        } else if(peek_is(T_LPAREN)){
            next_tok();
            Node* args=mkn(NK_LIST);
            Node** tail=&args->a;
            while(!peek_is(T_RPAREN) && !peek_is(T_EOF)){
                Node* a=parse_expr();
                *tail=a; tail=&a->next;
                if(peek_is(T_COMMA)){ next_tok(); if(peek_is(T_RPAREN)) break; } else break;
            }
            if(expect_tok(T_RPAREN,"')'")) break;
            Node*n=mkn(NK_CALL); n->a=e; n->b=args; e=n;
        } else if(peek_is(T_PLUSPLUS)){
            next_tok(); Node*n=mkn(NK_POST); n->key=(char*)"++"; n->a=e; e=n;
        } else if(peek_is(T_MINUSMINUS)){
            next_tok(); Node*n=mkn(NK_POST); n->key=(char*)"--"; n->a=e; e=n;
        } else break;
    }
    return e;
}
static Node* parse_unary(void){
    if(peek_is(T_MINUS)){ next_tok(); Node*n=mkn(NK_UNARY); n->key=(char*)"-"; n->a=parse_unary(); return n; }
    if(peek_is(T_NOT)){ next_tok(); Node*n=mkn(NK_UNARY); n->key=(char*)"!"; n->a=parse_unary(); return n; }
    if(peek_is(T_PLUS)){ next_tok(); return parse_unary(); }
    if(peek_is(T_TYPEOF)){ next_tok(); Node*n=mkn(NK_UNARY); n->key=(char*)"typeof"; n->a=parse_unary(); return n; }
    if(peek_is(T_DELETE)){ next_tok(); Node*n=mkn(NK_UNARY); n->key=(char*)"delete"; n->a=parse_unary(); return n; }
    if(peek_is(T_PLUSPLUS)){ next_tok(); Node*n=mkn(NK_POST); n->key=(char*)"++"; n->a=parse_unary(); n->ival=1; return n; }
    if(peek_is(T_MINUSMINUS)){ next_tok(); Node*n=mkn(NK_POST); n->key=(char*)"--"; n->a=parse_unary(); n->ival=1; return n; }
    if(peek_is(T_AWAIT)){ next_tok(); Node*n=mkn(NK_AWAIT); n->a=parse_unary(); return n; }
    return parse_postfix();
}
static Node* parse_mul(void){
    Node* e=parse_unary();
    while(peek_is(T_STAR)||peek_is(T_SLASH)||peek_is(T_PERCENT)){
        int k=g_tok.kind; next_tok();
        const char* op = k==T_STAR?"*":k==T_SLASH?"/":"%";
        Node*n=mkn(NK_BIN); n->key=kerndup(op); n->a=e; n->b=parse_unary(); e=n;
    }
    return e;
}
static Node* parse_add(void){
    Node* e=parse_mul();
    while(peek_is(T_PLUS)||peek_is(T_MINUS)){
        int k=g_tok.kind; next_tok();
        Node*n=mkn(NK_BIN); n->key=kerndup(k==T_PLUS?"+":"-"); n->a=e; n->b=parse_mul(); e=n;
    }
    return e;
}
static Node* parse_cmp(void){
    Node* e=parse_add();
    while(peek_is(T_LT)||peek_is(T_GT)||peek_is(T_LE)||peek_is(T_GE)||peek_is(T_EQ)||peek_is(T_NE)||peek_is(T_EQEQEQ)||peek_is(T_NEQNEQ)||peek_is(T_IN)||peek_is(T_INSTANCEOF)){
        int k=g_tok.kind; next_tok();
        const char* op = k==T_LT?"<":k==T_GT?">":k==T_LE?"<=":k==T_GE?">=":k==T_EQ?"==":k==T_NE?"!=":k==T_EQEQEQ?"===":k==T_NEQNEQ?"!==":k==T_INSTANCEOF?"instanceof":"in";
        Node*n=mkn(NK_BIN); n->key=kerndup(op); n->a=e; n->b=parse_add(); e=n;
    }
    return e;
}
static Node* parse_and(void){
    Node* e=parse_cmp();
    while(peek_is(T_ANDAND)){ next_tok(); Node*n=mkn(NK_BIN); n->key=kerndup("&&"); n->a=e; n->b=parse_cmp(); e=n; }
    return e;
}
static Node* parse_or(void){
    Node* e=parse_and();
    while(peek_is(T_OROR)){ next_tok(); Node*n=mkn(NK_BIN); n->key=kerndup("||"); n->a=e; n->b=parse_and(); e=n; }
    return e;
}
static Node* parse_ternary(void){
    Node* cond=parse_or();
    if(peek_is(T_QUESTION)){
        next_tok(); Node*a=parse_expr();
        expect_tok(T_COLON,"':' after ?");
        Node*b=parse_expr();
        Node*n=mkn(NK_TRIN); n->a=cond; n->b=a; n->c=b;
        return n;
    }
    return cond;
}
static Node* parse_assign(void){
    Node* lhs=parse_ternary();
    if(peek_is(T_ASSIGN)||peek_is(T_PLUSASSIGN)||peek_is(T_MINUSASSIGN)||peek_is(T_STARASSIGN)||peek_is(T_SLASHASSIGN)){
        int k=g_tok.kind; next_tok();
        const char* op = k==T_ASSIGN?"=":k==T_PLUSASSIGN?"+=":k==T_MINUSASSIGN?"-=":k==T_STARASSIGN?"*=":"/=";
        Node*n=mkn(NK_ASSIGN); n->key=kerndup(op); n->a=lhs; n->b=parse_assign(); return n;
    }
    return lhs;
}
static Node* parse_expr(void){ return parse_assign(); }

static Node* parse_stmt(void){
    if(peek_is(T_SEMI)){ next_tok(); return mkn(NK_EMPTY); }
    if(peek_is(T_LBRACE)) return parse_block();
    if(peek_is(T_VAR)||peek_is(T_LET)||peek_is(T_CONST)){
        next_tok();
        Node* d=mkn(NK_VAR);
        Node** tail=&d->a;
        while(1){
            Node* one=mkn(NK_VAR);
            if(!peek_is(T_IDENT)){ syn_err("SyntaxError: expected variable name"); break; }
            one->key=kerndup(g_tok.str); next_tok();
            if(peek_is(T_ASSIGN)){ next_tok(); one->a=parse_assign(); }
            *tail=one; tail=&one->next;
            if(peek_is(T_COMMA)){ next_tok(); } else break;
        }
        if(sync_stmt_end()) return d;
        eat(T_SEMI);
        return d;
    }
    if(peek_is(T_IF)){
        next_tok(); if(expect_tok(T_LPAREN,"'(' after if")) return mkn(NK_EMPTY);
        Node* cond=parse_expr(); if(expect_tok(T_RPAREN,"')' after condition")) return mkn(NK_EMPTY);
        Node* n=mkn(NK_IF); n->a=cond; n->b=parse_stmt();
        if(peek_is(T_ELSE)){ next_tok(); n->c=parse_stmt(); }
        return n;
    }
    if(peek_is(T_WHILE)){
        next_tok(); if(expect_tok(T_LPAREN,"'(' after while")) return mkn(NK_EMPTY);
        Node* cond=parse_expr(); if(expect_tok(T_RPAREN,"')' after condition")) return mkn(NK_EMPTY);
        Node*n=mkn(NK_WHILE); n->a=cond; n->b=parse_stmt(); return n;
    }
    if(peek_is(T_DO)){
        next_tok();
        Node*n=mkn(NK_DO);
        n->b=parse_stmt();                    /* body */
        if(peek_is(T_WHILE)){
            next_tok(); if(expect_tok(T_LPAREN,"'(' after while")) return n;
            n->a=parse_expr(); expect_tok(T_RPAREN,"')'");
        }
        eat(T_SEMI);
        return n;
    }
    if(peek_is(T_SWITCH)){
        next_tok(); if(expect_tok(T_LPAREN,"'(' after switch")) return mkn(NK_EMPTY);
        Node* cond=parse_expr(); if(expect_tok(T_RPAREN,"')' after switch")) return mkn(NK_EMPTY);
        if(expect_tok(T_LBRACE,"'{'")) return mkn(NK_EMPTY);
        Node*n=mkn(NK_SWITCH); n->a=cond; n->b=0;
        Node** tail=&n->b;
        while(!peek_is(T_RBRACE) && !peek_is(T_EOF)){
            Node* g=0;
            if(peek_is(T_CASE)){
                next_tok(); Node* cv=parse_expr();
                if(expect_tok(T_COLON,"':' after case")) return n;
                g=mkn(NK_CASE); g->a=cv;
            }
            else if(peek_is(T_DEFAULT)){
                next_tok();
                if(expect_tok(T_COLON,"':' after default")) return n;
                g=mkn(NK_DEFAULT);
            }
            else break;
            Node* blk=mkn(NK_BLOCK); Node** bt=&blk->a;
            while(!peek_is(T_CASE)&&!peek_is(T_DEFAULT)&&!peek_is(T_RBRACE)&&!peek_is(T_EOF)){
                Node* s=parse_stmt();
                *bt=s; bt=&s->next;
            }
            g->b=blk;
            *tail=g; tail=&g->next;
        }
        expect_tok(T_RBRACE,"'}'");
        return n;
    }
    if(peek_is(T_BREAK)){ next_tok(); eat(T_SEMI); return mkn(NK_BREAK); }
    if(peek_is(T_CONTINUE)){ next_tok(); eat(T_SEMI); return mkn(NK_CONTINUE); }
    if(peek_is(T_FOR)){
        next_tok(); if(expect_tok(T_LPAREN,"'(' after for")) return mkn(NK_EMPTY);
        Node* n=mkn(NK_FOR);
        if(!peek_is(T_SEMI)){ n->a=parse_stmt(); } eat(T_SEMI);
        if(!peek_is(T_SEMI)&&!peek_is(T_RPAREN)) n->b=parse_expr();
        eat(T_SEMI);
        if(!peek_is(T_RPAREN)) n->c=parse_expr();
        if(expect_tok(T_RPAREN,"')' after for")) return n;
        n->d=parse_stmt();   /* body */
        return n;
    }
    if(peek_is(T_RETURN)){
        next_tok();
        Node*n=mkn(NK_RETURN);
        if(!peek_is(T_SEMI)&&!peek_is(T_RBRACE)&&!peek_is(T_EOF)){ n->a=parse_expr(); sync_stmt_end(); }
        eat(T_SEMI);
        return n;
    }
    if(peek_is(T_FUNC)){
        Node* fn=parse_fn();
        Node* d=mkn(NK_VAR); d->key=fn->key; d->a=fn; d->ival=1; /* decl; no boundary check: ends at '}' */
        return d;
    }
    if(peek_is(T_ASYNC)){
        next_tok();
        if(peek_is(T_FUNC)){
            Node* fn=parse_fn(); fn->ival=2;
            Node* d=mkn(NK_VAR); d->key=fn->key; d->a=fn; d->ival=1; /* async decl; ends at '}' */
            return d;
        }
        /* `async` used as a plain identifier */
        g_tok.kind=T_IDENT; g_tok.str=(char*)"async"; g_tok.slen=5; g_tok.num=0;
        g_lex.pos = g_tok.pos + 5;   /* rewind is approximate; token rebuilt above */
        Node* e=parse_expr();
        if(sync_stmt_end()) return e;
        eat(T_SEMI);
        return e;
    }
    Node* e=parse_expr();
    if(sync_stmt_end()) return e;
    eat(T_SEMI);
    return e;
}

/* ================================================================
   ENVIRONMENT
   ================================================================ */
struct Env { Env* parent; Node* names; };
static Env* g_global_env;

static char* kerndup(const char* s){
    u64 n=xstrlen(s);
    char* d=(char*)arena_alloc(n+1); if(!d) return 0;
    xmemcpy(d,s,n); d[n]=0; return d;
}

static Env* env_new(Env* parent){ Env* e=(Env*)arena_alloc(sizeof(Env)); if(!e)return 0; e->parent=parent; e->names=0; return e; }
static int env_has_local(Env* e,const char* name){
    for(Node* p=e->names;p;p=p->next) if(p->key && !xstrcmp(p->key,name)) return 1;
    return 0;
}
static Node* env_find(Env* e,const char* name){
    for(Env* s=e;s;s=s->parent)
        for(Node* p=s->names;p;p=p->next)
            if(p->key && !xstrcmp(p->key,name)) return p;
    return 0;
}
static void env_def(Env* e,const char* name,Val v){
    Node* p=(Node*)arena_alloc(sizeof(Node)); if(!p)return;
    p->key=kerndup(name); p->val=v; p->next=e->names; e->names=p;
}
static void env_set(Env* e,const char* name,Val v){
    Node* p=env_find(e,name);
    if(p){ p->val=v; return; }
    env_def(e,name,v);
}

/* ================================================================
   HOST CALLBACK TABLE — function pointers set by emitted init code.
   Each slot is a SysV function(long a1, long a2, long a3, long a4).
   The compiler emits small stubs that translate SysV→Win64 and call
   the real Windows APIs; at startup it passes their addresses here.
   ================================================================ */
typedef long (*host_fn_t)(long,long,long,long);
#define HOST_FS_READ    0   /* (path, _, buf, cap) -> bytesRead | -1   */
#define HOST_FS_WRITE   1   /* (path, _, data, len) -> bytesWritten    */
#define HOST_FS_EXISTS  2   /* (path, _, _, _)      -> 1|0             */
#define HOST_GET_CWD    3   /* (buf, cap, _, _)     -> length          */
#define HOST_NET_CONN   4   /* (host, port, _, _)   -> socket | -1    */
#define HOST_NET_SEND   5   /* (sock, buf, len, _)  -> bytes | -1     */
#define HOST_NET_RECV   6   /* (sock, buf, len, _)  -> bytes | -1     */
#define HOST_NET_CLOSE  7   /* (sock, _, _, _)       -> 0              */
#define HOST_TLS_CONN   8   /* (sock, host, _, _)   -> handle | -1    */
#define HOST_TLS_SEND   9   /* (h, buf, len, _)     -> bytes | -1     */
#define HOST_TLS_RECV  10   /* (h, buf, len, _)     -> bytes | -1     */
#define HOST_TLS_CLOSE 11   /* (h, _, _, _)          -> 0              */
#define HOST_PRINT     12   /* (buf, len, _, _)      -> void           */
#define HOST_EXEC      13   /* (cmd, _, outbuf, cap) -> exitcode; stdout into outbuf */
#define HOST_FS_MKDIR  14   /* (path, _, _, _)       -> 0 | -1         */
#define HOST_FS_READDIR 15  /* (path, outbuf, cap, _)-> len | -1; '\n'-list */
#define HOST_FS_UNLINK 16   /* (path, _, _, _)       -> 0 | -1         */
#define HOST_SLEEP     17   /* (ms, _, _, _)          -> 0              */
#define HOST_FS_STAT   18   /* (path, outbuf, cap, _) -> 0|1|-1; outbuf="size\0is_dir\0" */
#define HOST_RAND      19   /* (_, _, _, _)           -> random long     */
#define HOST_ENV       20   /* (key, outbuf, cap, _)  -> len|-1 (env var value) */
#define HOST_ARGS      21   /* (idx, outbuf, cap, _)  -> len|-1 (argv[idx])    */
#define HOST_UNAME     22   /* (_, outbuf, cap, _)    -> len|-1 (uname string) */
#define HOST_COUNT     24

static host_fn_t g_host_fn[HOST_COUNT];
static char g_fs_buf[256*1024]; /* host writes file data here */

/* ================================================================
   MODULE CACHE (CommonJS) — linked list keyed by resolved path.
   ================================================================ */
typedef struct ModEntry {
    char* path;
    Val   exports;
    struct ModEntry* next;
} ModEntry;

/* ================================================================
   PATH HELPERS (pure C, no libc — string ops only)
   ================================================================ */
static int path_is_sep(char c){ return c=='/' || c=='\\'; }

static int path_ends_with(const char* s, const char* suffix){
    u64 sl=xstrlen(s), fl=xstrlen(suffix);
    if(fl>sl) return 0;
    return !xstrcmp(s+sl-fl, suffix);
}

/* Write result = base + "/" + name into arena. Caller owns the pointer. */
static char* path_join(const char* base, const char* name){
    u64 bl=xstrlen(base), nl=xstrlen(name);
    char* r=(char*)arena_alloc(bl+1+nl+1);
    xmemcpy(r,base,bl); r[bl]='/'; xmemcpy(r+bl+1,name,nl); r[bl+1+nl]=0;
    return r;
}

/* Return dirname (everything before last '/'). If no '/', return ".".
   The separator itself is excluded and trailing slashes are stripped, so
   "a/b" and "a/b/" both dirname to "a" — keeps node_modules up-walks sane. */
static const char* path_dirname(const char* p){
    u64 pl=xstrlen(p);
    if(pl==0) return ".";
    s64 i=(s64)pl-1;
    while(i>0 && p[i]=='/') i--;      /* strip trailing slashes */
    while(i>=0 && p[i]!='/') i--;     /* walk back to the separator */
    if(i<0) return ".";
    if(i==0) return "/";              /* "/x" -> "/" ; "/" -> "/" */
    char* r=(char*)arena_alloc((u64)i+1);
    xmemcpy(r,p,(u64)i); r[i]=0;
    return r;
}

/* Try to load `main` field from a package.json located at pj. On success writes
   a fresh copy into arena and sets *out. Returns 1 on found, 0 on missing. */
static int json_field(const char* pj, const char* field, char** out){
    if(!g_host_fn[HOST_FS_READ]) return 0;
    static char pbuf[512];
    long n=g_host_fn[HOST_FS_READ]((long)pj,0,(long)pbuf,(long)sizeof(pbuf)-1);
    if(n<=0) return 0;
    pbuf[n]=0;
    /* search for  "field" : "value"  (simple scanner) */
    const char* p=pbuf;
    u64 fl=xstrlen(field);
    for(;;){
        const char* f=xstrstr(p,field);
        if(!f) return 0;
        /* ensure it's preceded by '"' and followed by '"' */
        const char* q=f; while(q>pbuf&&(*q!='"'&&*q!=' '&&*q!='\t')) q--;
        const char* r=f+fl;
        if(f>pbuf && f[-1]=='"' && *r=='"'){
            const char* c=r+1;
            while(*c&&*c!=':') c++;
            if(*c==':'){
                c++;
                while(*c&&(*c==' '||*c=='\t')) c++;
                if(*c=='"'){
                    c++;
                    const char* vs=c; u64 vl=0;
                    while(*c&&*c!='"'){ c++; vl++; }
                    if(*c=='"'){
                        static char tmp[512];
                        if(vl>511) vl=511;
                        for(u64 i=0;i<vl;i++) tmp[i]=vs[i]; tmp[vl]=0;
                        char* r2=(char*)arena_alloc(vl+1);
                        xmemcpy(r2,tmp,vl+1);
                        *out=r2; return 1;
                    }
                }
            }
        }
        p=f+fl;
    }
}

/* Try candidates rooted at a package path `pkg` (which may be a dir or a file):
   1. pkg itself           2. pkg.js      3. pkg.json
   4. pkg/index.js         5. pkg/package.json -> "main"
   Sets *outPath on first hit; returns 1/0. */
static int try_resolve_in(const char* pkg, const char** outPath){
    if(!g_host_fn[HOST_FS_EXISTS]) return 0;
    u64 pl=xstrlen(pkg);
    int ext = path_ends_with(pkg,".js") || path_ends_with(pkg,".json");
    /* An extensionless path is a package dir: never resolve to the dir itself.
       Only exact-match paths that already carry a known file extension. */
    if(ext && g_host_fn[HOST_FS_EXISTS]((long)pkg,0,0,0)==1){ *outPath=pkg; return 1; }

    char* t=(char*)arena_alloc(pl+5); xmemcpy(t,pkg,pl); xmemcpy(t+pl,".js",3); t[pl+3]=0;
    if(g_host_fn[HOST_FS_EXISTS]((long)t,0,0,0)==1){ *outPath=t; return 1; }

    char* tj=(char*)arena_alloc(pl+7); xmemcpy(tj,pkg,pl); xmemcpy(tj+pl,".json",5); tj[pl+5]=0;
    if(g_host_fn[HOST_FS_EXISTS]((long)tj,0,0,0)==1){ *outPath=tj; return 1; }

    char* idx=(char*)arena_alloc(pl+10); xmemcpy(idx,pkg,pl); xmemcpy(idx+pl,"/index.js",9); idx[pl+9]=0;
    if(g_host_fn[HOST_FS_EXISTS]((long)idx,0,0,0)==1){ *outPath=idx; return 1; }

    /* package.json "main": resolve main relative to pkg dir. */
    char* pj=(char*)arena_alloc(pl+14); xmemcpy(pj,pkg,pl); xmemcpy(pj+pl,"/package.json",13); pj[pl+13]=0;
    if(g_host_fn[HOST_FS_EXISTS]((long)pj,0,0,0)==1){
        char* mainv=0;
        if(json_field(pj,"main",&mainv) && mainv){
            /* if main already ends in .js/.json use as-is, else append */
            char* mp=path_join(pkg, mainv);
            /* avoid re-reading package.json of mainv dir (it's a file path) */
            return try_resolve_in(mp, outPath);
        }
    }
    return 0;
}

/* Resolve a relative/absolute id against directory `from`. */
static int resolve_direct(const char* id, const char* from, const char** outPath){
    const char* base = id[0]=='/' ? "" : from;
    const char* cand = id[0]=='/' ? id : path_join(base, id);
    u64 cl=xstrlen(cand);
    /* If the id already has an extension, try exact first */
    if(path_ends_with(cand,".js")||path_ends_with(cand,".json")){
        if(g_host_fn[HOST_FS_EXISTS]){
            if(g_host_fn[HOST_FS_EXISTS]((long)cand,0,0,0)==1){ *outPath=cand; return 1; }
        }
        return 0;
    }
    if(path_ends_with(cand,"/")){
        char* idx=(char*)arena_alloc(cl+10); xmemcpy(idx,cand,cl); xmemcpy(idx+cl,"index.js",8); idx[cl+8]=0;
        if(g_host_fn[HOST_FS_EXISTS]){
            if(g_host_fn[HOST_FS_EXISTS]((long)idx,0,0,0)==1){ *outPath=idx; return 1; }
        }
        return 0;
    }
    return try_resolve_in(cand, outPath);
}

/* Walk up from `from` (a directory) looking for node_modules/{id}.
   Starts with `base` as an absolute starting directory if known. */
static int resolve_module(const char* id, const char* from, const char** outPath){
    if(!id || !from) return 0;

    /* Relative / absolute: resolve directly */
    if(id[0]=='.' || id[0]=='/'){
        return resolve_direct(id, from, outPath);
    }

    /* Bare specifier: walk up from `from`, converting "." to cwd. */
    char* base=0;
    if(!xstrcmp(from,".") || !from[0]){
        char* cwd=(char*)arena_alloc(1024);
        long n= g_host_fn[HOST_GET_CWD]? g_host_fn[HOST_GET_CWD]((long)cwd,1024,0,0):0;
        if(n>0 && n<1023){ cwd[n]=0; base=cwd; }
        else { base=(char*)arena_alloc(2); base[0]='.'; base[1]=0; }
    } else {
        u64 fl=xstrlen(from); base=(char*)arena_alloc(fl+1);
        xmemcpy(base,from,fl); base[fl]=0;
    }

    for(int depth=0; depth<64; depth++){
        const char* nm=path_join(base,"node_modules");
        const char* pkg=path_join(nm,id);
        if(try_resolve_in(pkg, outPath)) return 1;
        const char* up=path_dirname(base);
        if(!xstrcmp(up,base)) break;   /* reached filesystem root */
        base=(char*)up;
    }

    /* System-wide fallback (POSIX dev host): /usr/lib/node_modules/{id} */
    if(g_host_fn[HOST_FS_EXISTS]){
        const char* sys=path_join(path_join("/usr/lib","node_modules"), id);
        if(try_resolve_in(sys, outPath)) return 1;
    }
    return 0;
}

/* Check module cache by path string. */
static ModEntry* mod_cache_find(const char* path){
    for(ModEntry* m=g_mod_cache; m; m=m->next)
        if(!xstrcmp(m->path, path)) return m;
    return 0;
}
static void mod_cache_add(const char* path, Val exports){
    ModEntry* m=(ModEntry*)arena_alloc(sizeof(ModEntry));
    m->path=(char*)path; m->exports=exports; m->next=g_mod_cache; g_mod_cache=m;
}

static Val call_require_impl(const char* id, const char* from_dir);
static int parse_program(const char* src, u64 len, Node** out);
static int js_exec_in(const char* src, u64 len, Env* env);
static int call_http_get(const char* url, Val* out);

/* ================================================================
   EVALUATOR
   ================================================================ */
static int  g_flow;      /* 0 normal, 1 return, 2 break, 3 continue */
static Val  g_flow_val;
static void exec_stmt(Node* n, Env* env);

/* Run `body` with flow reset to 0 so a break/continue from inside cannot
   escape the loop that owns it. If the body ends with flow still 0, restore
   the caller's flow; otherwise leave it (1=return propagates up, 2/3 are
   consumed by the loop itself). */
static void exec_loop_body(Node* body, Env* env){
    int fs=g_flow; g_flow=0;
    if(body) exec_stmt(body,env);
    if(g_flow==0) g_flow=fs;
}

static double to_num(Val v){
    if(v.tag==V_NUM) return v.num;
    if(v.tag==V_BOOL) return v.num!=0;
    if(v.tag==V_STR){ Str*s=_str(v); double r=0; u64 i=0; int neg=0;
        while(i<s->len&&s->data[i]==' ')i++;
        if(i<s->len&&s->data[i]=='-'){neg=1;i++;}
        while(i<s->len&&s->data[i]>='0'&&s->data[i]<='9'){r=r*10+(s->data[i]-'0');i++;}
        return neg?-r:r; }
    return 0;
}
static int to_bool(Val v){
    if(v.tag==V_BOOL) return v.num!=0;
    if(v.tag==V_NUM) return v.num!=0;
    if(v.tag==V_STR) return _str(v)->len!=0;
    if(v.tag==V_UNDEF||v.tag==V_NULL) return 0;
    return 1;
}
static char* kdup(const char* s){
    u64 n=xstrlen(s); char* b=(char*)arena_alloc(n+1);
    if(!b) return (char*)s;
    xmemcpy(b,s,n); b[n]=0; return b;
}
static char* num_str(double v){
    if(v!=v) return kdup("NaN");
    if(v==(double)(1.0/0.0)) return kdup("Infinity");
    if(v==(double)(-1.0/0.0)) return kdup("-Infinity");
    int neg=0; if(v<0){ neg=1; v=-v; }
    char tmp[40]; int k=0;
    if(v>=9.0e18){
        /* huge magnitude: significant digits + e+exp (safe, no s64 overflow) */
        double m=v; long e=0;
        while(m>=10.0){ m/=10.0; e++; if(e>400){ m=9.9; e=400; break; } }
        char et[16]; int ek=0; long ee=e;
        if(ee==0) et[ek++]='0';
        while(ee>0){ et[ek++]='0'+(int)(ee%10); ee/=10; }
        char* out=(char*)arena_alloc(48); int o=0;
        if(neg) out[o++]='-';
        int d=(int)m; out[o++]='0'+d;
        double fr=m-d;
        out[o++]='.';
        for(int i=0;i<6;i++){ fr*=10; int dig=(int)fr; out[o++]='0'+dig; fr-=dig; }
        while(o>0&&out[o-1]=='0')o--;
        if(o>0&&out[o-1]=='.')o--;
        out[o++]='e'; out[o++]='+';
        while(ek>0)out[o++]=et[--ek]; out[o]=0;
        return out;
    }
    s64 n=(s64)v;
    if(v==(double)n){
        if(n==0){ char* b=(char*)arena_alloc(2); b[0]='0'; b[1]=0; return b; }
        while(n>0){ tmp[k++]='0'+(int)(n%10); n/=10; }
        char* out=(char*)arena_alloc(k+1+neg); int o=0; if(neg)out[o++]='-';
        while(k>0) out[o++]=tmp[--k]; out[o]=0; return out;
    }
    s64 ip=(s64)v; double fp=v-(double)ip;
    if(ip==0) tmp[k++]='0';
    while(ip>0){ tmp[k++]='0'+(int)(ip%10); ip/=10; }
    char* out=(char*)arena_alloc(k+10+neg); int o=0; if(neg)out[o++]='-';
    while(k>0)out[o++]=tmp[--k];
    out[o++]='.';
    for(int i=0;i<8;i++){ fp*=10; int dig=(int)fp; out[o++]='0'+dig; fp-=dig; }
    while(o>0&&out[o-1]=='0')o--;
    if(o>0&&out[o-1]=='.')o--;
    out[o]=0; return out;
}
static Val box_get(Box* b,const char* key);   /* fwd: regex repr in str_of_val */
static const char* str_of_val(Val v){
    if(v.tag==V_STR) return _str(v)->data;
    if(v.tag==V_NUM) return num_str(v.num);
    if(v.tag==V_BOOL) return v.num?"true":"false";
    if(v.tag==V_NULL) return "null";
    if(v.tag==V_UNDEF) return "undefined";
    if(v.tag==V_FUNC) return "[Function]";
    if(v.tag==V_ARR) return "[object Array]";
    if(v.tag==V_OBJ){
        Box* b=(Box*)v.p;
        if(b){
            Val p=box_get(b,"$<r"); 
            if(p.tag==V_STR && box_get(b,"$<f").tag==V_STR){
                /* regex -> /pattern/flags */
                const char* pd=_str(p)->data; u64 pl=_str(p)->len;
                Val f=box_get(b,"$<f"); const char* fd=_str(f)->data; u64 fl=_str(f)->len;
                char* buf=(char*)arena_alloc(pl+fl+3); if(!buf) return "[object Object]";
                buf[0]='/'; xmemcpy(buf+1,pd,pl); buf[1+pl]='/';
                if(fl){ xmemcpy(buf+2+pl,fd,fl); }
                buf[2+pl+fl]=0;
                return buf;
            }
        }
        return "[object Object]";
    }
    return "";
}
static u64 val_to_buf(char* out,u64 cap,Val v){
    const char* s=str_of_val(v); u64 n=xstrlen(s);
    if(n>cap-1)n=cap-1; xmemcpy(out,s,n); out[n]=0; return n;
}
static Val add_vals(Val l, Val r){
    if(l.tag==V_STR||r.tag==V_STR){
        const char* ls=str_of_val(l); const char* rs=str_of_val(r);
        u64 ln=xstrlen(ls), rn=xstrlen(rs);
        char* buf=(char*)arena_alloc(ln+rn+1); if(!buf) return vnum(0);
        xmemcpy(buf,ls,ln); xmemcpy(buf+ln,rs,rn); buf[ln+rn]=0;
        return vstrof(mkstr(buf,ln+rn));
    }
    return vnum(to_num(l)+to_num(r));
}

static int eq_val(Val a, Val b);
static int g_had_error;
static void set_err(const char* s);
static void clear_err(void);
static Val eval(Node* n, Env* env);
static Val call_func(Val fnv, Node* args, Env* caller, Val thisv);
static void exec_stmt(Node* n, Env* env);
static void assign_to(Node* lv, Env* env, Val v);
static Val g_last_result;

/* --- async subsystem (Promise/microtask/macrotask) fwd decls --- */
static Box* promise_new(void);
static Val  promise_settle(Box* p, Val v, int reject);
static void mtq_push(Box* job);
static void run_microtask(Box* job);
static void master_pump(long budget);
static Val promise_then(Box* p, Node* args, Env* env);
static Val promise_catch(Box* p, Node* args, Env* env);
static Val promise_ctor(Node* args, Env* env);
static Val promise_static(Node* args, Env* env, int which);  /* 0=resolve,1=reject */
static Val promise_all(Node* args, Env* env);
static Val async_await_value(Val p, Env* env);
static Box* g_mtq_head; static Box* g_mtq_tail;
static Box* g_tmq_head; static Box* g_tmq_tail;
static long g_async_await_nest;
static void mark_async_roots(void);
static int is_promise(Box* b);
static long timer_create(Node* args, Env* env, int interval);
static int tmq_remove(long id);

/* ================================================================
   MARK-SWEEP GC (top-level safepoints only)
   Responds to the block header mark bit (bit1 of flags). Only blocks
   reachable from roots get marked; the sweep then rebuilds the free
   list from garbage + free runs, so their memory is reused later.
   ================================================================ */
static void mark_raw(void* p){
    if(!p || !h_in_heap(p)) return;
    Bhdr* h=b_hdr(p); h->flags|=2;
}
static void mark_node_iter(Node* n);   /* fwd: uses mark_val */
static void mark_env(Env* e);          /* fwd: used to mark closure envs */
static void mark_box(Box* b){
    for(; b; b=b->proto){
        Bhdr* h=b_hdr(b);
        if(h->flags&2) continue;
        h->flags|=2;
        mark_node_iter(b->head);
    }
}
static void mark_val(Val v){
    switch(v.tag){
        case V_STR: {
            Str* s=_str(v);
            if(!s) break;
            mark_raw(s); mark_raw((void*)s->data);
            break;
        }
        case V_OBJ: case V_ARR: {
            Box* b=_box(v);
            if(!b) break;
            mark_box(b);
            break;
        }
        case V_FUNC: if(v.p) mark_node_iter(_fn(v)); break;
        default: break;
    }
}
static void mark_node_iter(Node* n){
    while(n){
        Bhdr* h=b_hdr(n);
        if(!(h->flags&2)){
            h->flags|=2;
            if(n->key) mark_raw(n->key);
            if(n->def) mark_env(n->def);
            mark_val(n->val);
            if(n->proto) mark_box(n->proto);
            if(n->a) mark_node_iter(n->a);
            if(n->b) mark_node_iter(n->b);
            if(n->c) mark_node_iter(n->c);
            if(n->d) mark_node_iter(n->d);
        }
        n=n->next;
    }
}
static void mark_env(Env* e){
    for(Env* s=e; s; s=s->parent){
        Bhdr* h=b_hdr(s);
        if(h->flags&2) continue;
        h->flags|=2;
        mark_node_iter(s->names);
    }
}
static u64 g_gc_steps_used;

/* ==== mark phase (fast: O(reachable set)) ==== */
static void heap_gc_start(void){
    mark_env(g_global_env);
    mark_val(g_last_result);
    mark_async_roots();
    for(ModEntry* m=g_mod_cache; m; m=m->next){
        mark_raw(m); mark_raw(m->path); mark_val(m->exports);
    }
    g_gc_p=heap;
    g_gc_fl=0;
    g_gc_busy=1;
    g_gc_steps_used=0;
}

/* Sweep a bounded number of blocks per call. Returns 1 when finished.
   The work is spread across top-level invocations so a long-running
   server never pauses for more than one short step (~<1 ms). */
#define GC_BUDGET 131072   /* max blocks processed per step */

static int heap_gc_step(void){
    if(!g_gc_busy) return 1;
    unsigned char* p=g_gc_p;
    unsigned char* end=heap+h_off;
    u64 budget=GC_BUDGET;
    while(p<end && budget>0){
        Bhdr* b=(Bhdr*)p;
        if(b->size<MINBLK || b->size>(u64)(end-p)){
            /* defensive: malformed header must never deadlock the sweep;
               finalize with what we have (leftover blocks get re-examined
               on the next GC cycle). */
            p=end;
            break;
        }
        if((b->flags&1) && (b->flags&2)){
            /* live block: keep, clear mark */
            b->flags&=~2;
            p+=b->size; budget--;
            continue;
        }
        /* garbage/used-unmarked or already-free: coalesce bounded run */
        u64 run=0;
        unsigned char* q=p;
        while(q<end && budget>0){
            Bhdr* b2=(Bhdr*)q;
            if((b2->flags&1) && (b2->flags&2)) break;   /* live stops run */
            if(b2->size<MINBLK || b2->size>(u64)(end-q)){ break; }
            run+=b2->size;
            q=p+run;
            budget--;
        }
        if(p+run>=end){
            /* trailing region → roll back bump top, do not freelist it */
            h_off=p-heap;
            p=end;
            break;
        }
        b->size=run; b->flags=0;
        *b_next(b)=g_gc_fl; g_gc_fl=b;
        p+=run;
    }
    if(p<end){
        g_gc_p=p;
        g_gc_steps_used++;
        return 0;               /* still sweeping */
    }
    g_freelist=g_gc_fl;
    g_gc_busy=0; g_gc_p=0; g_gc_fl=0;
    g_oom=0;
    return 1;
}

/* append to a box's list, creating it if needed. Returns 1 on ok. */
static int box_set(Box* b, const char* key, Val v){
    Node* e=b->head;
    for(;e;e=e->next){ if(e->key&&key&&!xstrcmp(e->key,key)){ e->val=v; return 1; } }
    Node* nn=(Node*)arena_alloc(sizeof(Node)); if(!nn)return 0;
    if(key) nn->key=kerndup(key);
    nn->val=v; nn->next=0;
    if(!b->head){ b->head=nn; return 1; }
    e=b->head; while(e->next)e=e->next; e->next=nn;
    return 1;
}
/* set array element at numeric index (extend with undef as needed) */
static void arr_set_idx(Box* b, int idx, Val v){
    Node* e=b->head; int i=0; Node* prev=0;
    for(;e;e=e->next,i++){ if(i==idx){ e->val=v; return; } prev=e; }
    while(i<idx){ Node* nn=(Node*)arena_alloc(sizeof(Node)); if(!nn)return; nn->val=vundef(); nn->next=0;
        if(prev)prev->next=nn; else b->head=nn; prev=nn; i++; }
    Node* nn=(Node*)arena_alloc(sizeof(Node)); if(!nn)return; nn->val=v; nn->next=0;
    if(prev)prev->next=nn; else b->head=nn;
}
static Val box_get(Box* b,const char* key){
    for(Node* e=b->head;e;e=e->next) if(e->key&&!xstrcmp(e->key,key)) return e->val;
    return vundef();
}
/* get with prototype-chain walk (own wins; prototype consulted only if key absent) */
static int box_has(Box* b,const char* key);
static Val box_get_ext(Box* b,const char* key){
    for(Box* s=b; s; s=s->proto){
        if(box_has(s,key)) return box_get(s,key);
    }
    return vundef();
}
static int box_has_ext(Box* b,const char* key){
    for(Box* s=b; s; s=s->proto) if(box_has(s,key)) return 1;
    return 0;
}
static Val box_get_idx(Box* b,int idx){
    int i=0; for(Node* e=b->head;e;e=e->next,i++) if(i==idx) return e->val;
    return vundef();
}
static int box_len(Box* b){ int c=0; for(Node* e=b->head;e;e=e->next)c++; return c; }
static Node* mk_box_node(Val v){
    Node* nn=(Node*)arena_alloc(sizeof(Node)); if(!nn) return 0;
    nn->key=0; nn->val=v; nn->next=0; return nn;
}
static void box_append(Box* b, Val v){
    Node* nn=mk_box_node(v); if(!nn) return;
    if(!b->head){ b->head=nn; return; }
    Node* e=b->head; while(e->next) e=e->next;
    e->next=nn;
}
static Val box_pop(Box* b){
    if(!b->head) return vundef();
    Node* e=b->head; Node* prev=0;
    while(e->next){ prev=e; e=e->next; }
    if(prev) prev->next=0; else b->head=0;
    return e->val;
}
static int box_del(Box* b,const char* key){
    Node* e=b->head; Node* prev=0;
    for(;e;e=e->next){
        if(e->key&&!xstrcmp(e->key,key)){ if(prev)prev->next=e->next; else b->head=e->next; return 1; }
        prev=e;
    }
    return 0;
}
static int box_has(Box* b,const char* key){
    for(Node* e=b->head;e;e=e->next) if(e->key&&!xstrcmp(e->key,key)) return 1;
    return 0;
}
static Val box_shift(Box* b){
    if(!b->head) return vundef();
    Node* h=b->head; b->head=h->next;
    return h->val;
}
static void box_unshift(Box* b, Val v){
    Node* nn=mk_box_node(v); if(!nn) return;
    nn->next=b->head; b->head=nn;
}
static int box_del_idx(Box* b, int idx){
    Node* e=b->head; Node* prev=0; int i=0;
    for(;e;e=e->next,i++){
        if(i==idx){ if(prev)prev->next=e->next; else b->head=e->next; return 1; }
        prev=e;
    }
    return 0;
}
static Box* new_box(void){
    Box* b=(Box*)arena_alloc(sizeof(Box));   /* arena_alloc zeroes: head=0, proto=0 */
    return b;
}
/* get-or-create a user function's `.prototype` box (NK_FUNC only) */
static Box* func_proto(Node* f){
    if(!f || f->kind!=NK_FUNC) return 0;
    if(!f->proto){
        f->proto=new_box();
        if(f->proto) box_set(f->proto,"constructor",vfnof(f));
    }
    return f->proto;
}

/* ---------- strict equality (===) ---------- */
static int eq_strict(Val a,Val b){
    if(a.tag!=b.tag) return 0;
    switch(a.tag){
        case V_NUM: return a.num==b.num;
        case V_STR: return a.p==b.p || !xstrcmp(_str(a)->data,_str(b)->data);
        case V_BOOL: return (a.num!=0)==(b.num!=0);
        case V_OBJ: case V_ARR: case V_FUNC: return a.p==b.p;
        case V_NULL: case V_UNDEF: return 1;
    }
    return 0;
}

/* ---------- string helpers ---------- */
static int mem_eq(const char* a,const char* b,u64 n){
    for(u64 i=0;i<n;i++) if(a[i]!=b[i]) return 0;
    return 1;
}
static long str_find(const Str* hay,const Str* ndl,long from){
    if(from<0) from=0;
    u64 n=hay->len, m=ndl->len;
    if(m==0) return from<=(long)n?(long)from:-1;
    for(u64 i=(u64)from; i+m<=n; i++){
        int eq=1;
        for(u64 k=0;k<m;k++) if(hay->data[i+k]!=ndl->data[k]){ eq=0; break; }
        if(eq) return (long)i;
    }
    return -1;
}
static Str* str_map_case(const Str* s,int up){
    char* buf=(char*)arena_alloc(s->len+1); if(!buf) return 0;
    for(u64 i=0;i<s->len;i++){
        char c=s->data[i];
        if(up && c>='a'&&c<='z') c=(char)(c-'a'+'A');
        else if(!up && c>='A'&&c<='Z') c=(char)(c-'A'+'a');
        buf[i]=c;
    }
    buf[s->len]=0;
    return mkstr(buf,s->len);
}
static Val js_str_slice(Str* s, Val a0, int hasA1, Val a1){
    long n=(long)s->len;
    long b=(long)to_num(a0), e=hasA1?(long)to_num(a1):n;
    if(b<0){ b=n+b; if(b<0)b=0; } else if(b>n) b=n;
    if(e<0){ e=n+e; if(e<0)e=0; } else if(e>n) e=n;
    if(e<b) e=b;
    u64 len=(u64)(e-b);
    if(!len) return vstrof(mkstr("",0));
    char* buf=(char*)arena_alloc(len+1); if(!buf) return vundef();
    xmemcpy(buf,s->data+b,len); buf[len]=0;
    return vstrof(mkstr(buf,len));
}
static Val js_str_substr(Str* s, Val a0, int hasA1, Val a1){
    long n=(long)s->len;
    long st=(long)to_num(a0);
    if(st<0){ st=n+st; if(st<0)st=0; }
    if(st>=n) return vstrof(mkstr("",0));
    long ln = hasA1? (long)to_num(a1) : n-st;
    if(ln<0) ln=0;
    if(st+ln>n) ln=n-st;
    u64 len=(u64)ln;
    if(!len) return vstrof(mkstr("",0));
    char* buf=(char*)arena_alloc(len+1); if(!buf) return vundef();
    xmemcpy(buf,s->data+st,len); buf[len]=0;
    return vstrof(mkstr(buf,len));
}
static Val js_str_split(Str* s, int hasSep, Val sepv){
    Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b) return vundef();
    b->head=0;
    if(!hasSep || sepv.tag!=V_STR || _str(sepv)->len==0){
        /* no separator / empty separator -> split into chars */
        if(!hasSep || sepv.tag!=V_STR){ box_append(b,vstrof(mkstr(s->data,s->len))); return varrb(b); }
        for(u64 i=0;i<s->len;i++) box_append(b, vstrof(mkstr(s->data+i,1)));
        return varrb(b);
    }
    Str* sep=_str(sepv);
    u64 start=0;
    for(;;){
        long hit=str_find(s,sep,(long)start);
        if(hit<0){ box_append(b,vstrof(mkstr(s->data+start,s->len-start))); break; }
        box_append(b,vstrof(mkstr(s->data+start,(u64)hit-start)));
        start=(u64)hit+sep->len;
        if(start>=s->len){ box_append(b,vstrof(mkstr("",0))); break; }
    }
    return varrb(b);
}

/* ---------- numeric helpers (no libm) ---------- */
static double js_sqrt(double x){
    if(x<=0) return 0;
    double r=x>1?x:1;
    for(int i=0;i<40;i++){ r=(r+x/r)*0.5; }
    return r;
}
static double js_floor(double x){
    s64 n=(s64)x;
    return (double)((x<0 && x!=(double)n)? n-1 : n);
}
static double js_pow(double a,double b){
    if(!(b==(double)(long)b)) return 0;
    long e=(long)b;
    if(a==0) return e<=0? 1 : 0;
    int neg=e<0; if(neg)e=-e;
    double r=1, base=a;
    while(e>=1){ if(e&1) r*=base; base*=base; e>>=1; }
    return neg? 1.0/r : r;
}
/* Math constants (match ECMA-262 double literals) */
static const double JS_PI=3.141592653589793, JS_TAU=6.283185307179586,
     JS_HALF_PI=1.5707963267948966, JS_E=2.718281828459045,
     JS_LN2=0.6931471805599453, JS_LN10=2.302585092994046,
     JS_LOG2E=1.4426950408889634, JS_LOG10E=0.4342944819032518,
     JS_SQRT2=1.4142135623730951, JS_SQRT1_2=0.7071067811865476;

static double js_round(double x){ return js_floor(x+0.5); }
static double js_ceil(double x){ return -js_floor(-x); }
static double js_trunc(double x){ return (x<9.2e18&&x>-9.2e18)? (double)(s64)x : x; }
static double js_sign(double x){ return x>0?1.0:(x<0?-1.0:0.0); }
static double js_uint32(double x){
    double t=x-js_floor(x/4294967296.0)*4294967296.0;
    if(t<0) t+=4294967296.0; return t;
}
static double js_clz32(double x){
    unsigned v=(unsigned)(s64)js_uint32(x);
    int n=0; unsigned m=0x80000000u;
    while(n<32 && !(v&m)){ n++; m>>=1; }
    return (double)n;
}
static double js_imul(double a,double b){
    unsigned ua=(unsigned)(s64)js_uint32(a), ub=(unsigned)(s64)js_uint32(b);
    unsigned long long p=(unsigned long long)ua*ub;
    int r=(int)(unsigned)(p & 0xFFFFFFFFull);
    return (double)r;
}
static double js_exp(double x){
    double n=js_round(x/JS_LN2), r=x-n*JS_LN2;
    double s=1.0;
    for(int i=22;i>=1;i--) s=1.0+s*r/i;
    if(n>=0){ for(long i=0;i<(long)n;i++) s*=2.0; }
    else { for(long i=0;i<-(long)n;i++) s*=0.5; }
    return s;
}
static double js_expm1(double x){
    if(x==0) return 0;
    double t=1.0, s=0.0;
    for(int k=1;k<40;k++){ t*=x/k; s+=t; if(t<1e-18&&t>-1e-18) break; }
    return s;
}
static double js_log(double x){
    if(x<=0) return 0;
    double e=0, m=x;
    while(m>=2.0){ m*=0.5; e+=1.0; }
    while(m<1.0){ m*=2.0; e-=1.0; }
    double a=(m-1.0)/(m+1.0), a2=a*a;
    double term=a, sum=0.0;
    for(int i=1;i<=49;i+=2){ sum+=term/i; term*=a2; }
    return 2.0*sum + e*JS_LN2;
}
static double js_log1p(double x){
    if(x==0) return 0;
    if(x<=-1.0) return 0;
    double a=x/(2.0+x), a2=a*a;
    double term=a, sum=0.0;
    for(int i=1;i<=49;i+=2){ sum+=term/i; term*=a2; }
    return 2.0*sum;
}
static double js_cbrt(double x){
    if(x==0) return 0;
    int neg=x<0; if(neg)x=-x;
    double r=js_exp(js_log(x)/3.0);
    return neg?-r:r;
}
static double js_sin(double x){
    double r=x-js_round(x/JS_TAU)*JS_TAU;
    double r2=r*r, t=r, sum=r;
    for(int k=3;k<=25;k+=2) t*=-r2/((double)k*(k-1)), sum+=t;
    return sum;
}
static double js_cos(double x){
    double r=x-js_round(x/JS_TAU)*JS_TAU;
    double r2=r*r, t=1.0, sum=1.0;
    for(int k=2;k<=24;k+=2) t*=-r2/((double)k*(k-1)), sum+=t;
    return sum;
}
static double js_tan(double x){
    double c=js_cos(x);
    if(c==0) return 0;
    return js_sin(x)/c;
}
static double js_atan(double x){
    int neg=x<0; if(neg)x=-x;
    if(x>=9.2e18) return neg?-JS_HALF_PI:JS_HALF_PI;
    int k=0;
    while(x>0.5){ x=x/(1.0+js_sqrt(1.0+x*x)); k++; }
    double t=x, t2=t*t, term=t, sum=0.0;
    for(int i=1;i<=29;i+=2){ sum+=term/i; term*=-t2; }
    double r=sum; while(k-->0) r*=2.0;
    return neg?-r:r;
}
static double js_atan2(double y,double x){
    if(x==0&&y==0) return 0;
    if(x==0) return y>0?JS_HALF_PI:-JS_HALF_PI;
    double a=js_atan(y/x);
    if(x>0) return a;
    return y>=0? a+JS_PI : a-JS_PI;
}
static double js_asin(double x){
    if(x>=1) return JS_HALF_PI;
    if(x<=-1) return -JS_HALF_PI;
    return js_atan(x/js_sqrt(1.0-x*x));
}
static double js_acos(double x){ return JS_HALF_PI-js_asin(x); }
static double js_sinh(double x){ double e=js_exp(x); return (e-1.0/e)*0.5; }
static double js_cosh(double x){ double e=js_exp(x); return (e+1.0/e)*0.5; }
static double js_tanh(double x){ double e=js_exp(2.0*x); return (e-1.0)/(e+1.0); }
static double js_asinh(double x){ return js_log(x+js_sqrt(x*x+1.0)); }
static double js_acosh(double x){ return x<1?0:js_log(x+js_sqrt(x*x-1.0)); }
static double js_atanh(double x){
    if(x<=-1||x>=1) return 0;
    if(x==0) return 0;
    return 0.5*js_log((1.0+x)/(1.0-x));
}
static double js_fround(double x){ float f=(float)x; return (double)f; }
static double math_const(const char* key,int* ok){
    double v=0; *ok=1;
    if(!xstrcmp(key,"PI")) v=JS_PI;
    else if(!xstrcmp(key,"E")) v=JS_E;
    else if(!xstrcmp(key,"LN2")) v=JS_LN2;
    else if(!xstrcmp(key,"LN10")) v=JS_LN10;
    else if(!xstrcmp(key,"LOG2E")) v=JS_LOG2E;
    else if(!xstrcmp(key,"LOG10E")) v=JS_LOG10E;
    else if(!xstrcmp(key,"SQRT2")) v=JS_SQRT2;
    else if(!xstrcmp(key,"SQRT1_2")) v=JS_SQRT1_2;
    else *ok=0;
    return v;
}

static double str_to_int_any(const Str* s,int base,int* anyOut);
static double str_to_int(const Str* s,int base){
    int any; return str_to_int_any(s,base,&any);
}
static double str_to_int_any(const Str* s,int base,int* anyOut){
    u64 i=0; int neg=0;
    while(i<s->len && s->data[i]==' ') i++;
    if(i<s->len&&(s->data[i]=='+'||s->data[i]=='-')){ neg=(s->data[i]=='-'); i++; }
    double r=0; int any=0;
    for(;i<s->len;i++){
        char ch=s->data[i]; int d;
        if(ch>='0'&&ch<='9') d=ch-'0';
        else if(ch>='a'&&ch<='z') d=ch-'a'+10;
        else if(ch>='A'&&ch<='Z') d=ch-'A'+10;
        else break;
        if(d>=base) break;
        r=r*base+d; any=1;
    }
    if(anyOut) *anyOut=any;
    return any? (neg?-r:r) : 0;
}
static double str_to_float(const Str* s,int* anyOut){
    u64 i=0; int neg=0;
    while(i<s->len && s->data[i]==' ') i++;
    if(i<s->len&&(s->data[i]=='+'||s->data[i]=='-')){ neg=(s->data[i]=='-'); i++; }
    double ip=0, fp=0; int any=0; u64 j=i;
    while(j<s->len&&s->data[j]>='0'&&s->data[j]<='9'){ ip=ip*10+(s->data[j]-'0'); j++; any=1; }
    if(j<s->len&&s->data[j]=='.'){
        j++; double sc=0.1;
        while(j<s->len&&s->data[j]>='0'&&s->data[j]<='9'){ fp+=(s->data[j]-'0')*sc; sc*=0.1; j++; any=1; }
    }
    if(anyOut) *anyOut=any;
    return any? (neg?-(ip+fp):(ip+fp)) : 0;
}
static int is_int_val(Val v){
    if(v.tag!=V_NUM) return 0;
    double x=v.num;
    return !(x!=x) && x!=(double)(1.0/0.0) && x!=(double)(-1.0/0.0) && x==(double)(s64)x;
}

/* ---------- global helper functions + pseudo-global Math/Object ---------- */
static Val call_math(const char* name, Node* args, Env* env){
    Node* a0n = args? args->a : 0;
    Node* a1n = a0n? a0n->next : 0;
    Val a0 = a0n? eval(a0n,env) : vundef();
    Val a1 = a1n? eval(a1n,env) : vundef();
    double x=to_num(a0), y=a1n? to_num(a1) : 0;
    if(!xstrcmp(name,"floor")) return vnum(js_floor(x));
    if(!xstrcmp(name,"ceil")) return vnum(js_ceil(x));
    if(!xstrcmp(name,"round")) return vnum(js_round(x));
    if(!xstrcmp(name,"trunc")) return vnum(js_trunc(x));
    if(!xstrcmp(name,"sign")) return vnum(js_sign(x));
    if(!xstrcmp(name,"abs")) return vnum(x<0?-x:x);
    if(!xstrcmp(name,"random")){
        /* returns in [0,1) — 53-bit precision via upper/lower halves */
        u64 r=rng_next();
        double v=(double)(r>>11)*0x1.0p-53;
        return vnum(v);
    }
    if(!xstrcmp(name,"min")){
        double r=x;
        for(Node* p=a0n?a0n->next:0; p; p=p->next){ double v=to_num(eval(p,env)); if(v<r)r=v; }
        return vnum(a0n? r : 0);
    }
    if(!xstrcmp(name,"max")){
        double r=x;
        for(Node* p=a0n?a0n->next:0; p; p=p->next){ double v=to_num(eval(p,env)); if(v>r)r=v; }
        return vnum(a0n? r : 0);
    }
    if(!xstrcmp(name,"sqrt")) return vnum(js_sqrt(x));
    if(!xstrcmp(name,"cbrt")) return vnum(js_cbrt(x));
    if(!xstrcmp(name,"pow")) return vnum(js_pow(x,y));
    if(!xstrcmp(name,"hypot")){
        double s=x*x;
        for(Node* p=a0n?a0n->next:0; p; p=p->next){ double v=to_num(eval(p,env)); s+=v*v; }
        return vnum(js_sqrt(s));
    }
    if(!xstrcmp(name,"exp")) return vnum(js_exp(x));
    if(!xstrcmp(name,"expm1")) return vnum(js_expm1(x));
    if(!xstrcmp(name,"log")) return vnum(js_log(x));
    if(!xstrcmp(name,"log1p")) return vnum(js_log1p(x));
    if(!xstrcmp(name,"log2")){
        double r=js_log(x)/JS_LN2, p=1.0; int k=0;
        while(p<=x && k<53){ if(p==x) return vnum((double)k); p*=2.0; k++; }
        return vnum(r);
    }
    if(!xstrcmp(name,"log10")){
        double r=js_log(x)/JS_LN10, p=1.0; int k=0;
        while(p<=x && k<20){ if(p==x) return vnum((double)k); p*=10.0; k++; }
        return vnum(r);
    }
    if(!xstrcmp(name,"sin")) return vnum(js_sin(x));
    if(!xstrcmp(name,"cos")) return vnum(js_cos(x));
    if(!xstrcmp(name,"tan")) return vnum(js_tan(x));
    if(!xstrcmp(name,"asin")) return vnum(js_asin(x));
    if(!xstrcmp(name,"acos")) return vnum(js_acos(x));
    if(!xstrcmp(name,"atan")) return vnum(js_atan(x));
    if(!xstrcmp(name,"atan2")) return vnum(js_atan2(x,y));
    if(!xstrcmp(name,"sinh")) return vnum(js_sinh(x));
    if(!xstrcmp(name,"cosh")) return vnum(js_cosh(x));
    if(!xstrcmp(name,"tanh")) return vnum(js_tanh(x));
    if(!xstrcmp(name,"asinh")) return vnum(js_asinh(x));
    if(!xstrcmp(name,"acosh")) return vnum(js_acosh(x));
    if(!xstrcmp(name,"atanh")) return vnum(js_atanh(x));
    if(!xstrcmp(name,"clz32")) return vnum(js_clz32(x));
    if(!xstrcmp(name,"imul")) return vnum(js_imul(x,y));
    if(!xstrcmp(name,"fround")) return vnum(js_fround(x));
    return vundef();
}
static Val call_objkeys(Node* args, Env* env){
    Node* a0n = args? args->a : 0;
    Val a0 = a0n? eval(a0n,env) : vundef();
    if(!(a0.tag==V_OBJ||a0.tag==V_ARR)) return vundef();
    Box* src=_box(a0);
    Box* nb=(Box*)arena_alloc(sizeof(Box)); if(!nb) return vundef();
    nb->head=0;
    for(Node* e=src->head;e;e=e->next){
        if(!e->key) continue;
        box_append(nb, vstrof(mkstr(e->key,xstrlen(e->key))));
    }
    return varrb(nb);
}
static Val call_objvalues(Node* args, Env* env, int entries){
    Node* a0n = args? args->a : 0;
    Val a0 = a0n? eval(a0n,env) : vundef();
    if(!(a0.tag==V_OBJ||a0.tag==V_ARR)) return vundef();
    Box* src=_box(a0);
    Box* nb=(Box*)arena_alloc(sizeof(Box)); if(!nb) return vundef();
    nb->head=0;
    for(Node* e=src->head;e;e=e->next){
        if(!e->key) continue;
        if(!entries){ box_append(nb, e->val); continue; }
        Box* kv=(Box*)arena_alloc(sizeof(Box)); if(!kv) return vundef();
        kv->head=0;
        box_append(kv, vstrof(mkstr(e->key,xstrlen(e->key))));
        box_append(kv, e->val);
        box_append(nb, varrb(kv));
    }
    return varrb(nb);
}

/* ================================================================
   REGEX (ECMA-262 subset): literals /pat/flags, new RegExp, matcher.
   A regex value is a marker box: "$<r" = pattern, "$<f" = flags,
   "$<l" = lastIndex. The matcher is a backtracking instruction VM.
   ================================================================ */
#define RG_TAG "$<r"
#define RG_FLAG "$<f"
#define RG_LAST "$<l"
#define RG_I 1
#define RG_M 2
#define RG_S 4
#define RG_G 8

static int rg_flags_int(const char* f,u64 fl){
    int r=0;
    for(u64 i=0;i<fl;i++){
        if(f[i]=='i')r|=RG_I; else if(f[i]=='m')r|=RG_M;
        else if(f[i]=='s')r|=RG_S; else if(f[i]=='g')r|=RG_G;
    }
    return r;
}
static int rg_is(Val v){
    return v.tag==V_OBJ && box_get(_box(v),RG_TAG).tag==V_STR
        && box_get(_box(v),RG_FLAG).tag==V_STR;
}
static Val rg_new(const char* pat,u64 pl,const char* fl,u64 fll){
    Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b) return vundef();
    b->head=0;
    box_set(b,RG_TAG,vstrof(mkstr(pat,pl)));
    box_set(b,RG_FLAG,vstrof(mkstr(fl,fll)));
    box_set(b,RG_LAST,vnum(0));
    return vobjof(b);
}
static Val rg_pattern(Box* b){ return box_get(b,RG_TAG); }
static Val rg_flags_v(Box* b){ return box_get(b,RG_FLAG); }
static int rg_lastindex(Box* b){ Val v=box_get(b,RG_LAST); return v.tag==V_NUM?(int)v.num:0; }
static void rg_setlast(Box* b,int n){ box_set(b,RG_LAST,vnum((double)n)); }

/* ---- matcher VM ---- */
#define ROP_CH      1
#define ROP_CLS     2
#define ROP_W       3
#define ROP_D       4
#define ROP_SP      5
#define ROP_DOT     6
#define ROP_BOUND   7
#define ROP_CARET   8
#define ROP_DOLLAR  9
#define ROP_SAVE   10
#define ROP_SPLIT  11
#define ROP_JMP    12
#define ROP_MATCH  13
#define ROP_FAIL   14
#define ROP_BACKREF 15
#define ROP_STR    16
#define ROP_POSA   17   /* a=scratch slot: save sp, then zero-width content runs */
#define ROP_GOAL   18   /* a=scratch slot: restore sp (positive lookahead ok) */
#define ROP_NEGSP  19   /* a=slot: negative lookahead branch start */
#define ROP_NEGOK  20   /* content matched => fail entire attempt */
typedef struct { int op; u64 a; u64 b; u64 c; } RI;
typedef struct { int lo, hi; } RPR;
typedef struct { int neg; int np; RPR pr[24]; } RCls;

static RI*  rg_ins;   static int rg_ni, rg_ncapc;
static int  rgs_nslot;

#define RG_CAP() do{ if(rg_ni+4>rg_ncapc){ int nx=(rg_ni+8)*2; RI* nw=(RI*)arena_alloc((u64)nx*sizeof(RI)); \
    xmemcpy(nw,rg_ins,(u64)rg_ni*sizeof(RI)); rg_ins=nw; rg_ncapc=nx; } }while(0)
static int rg_emit(int op,u64 a,u64 b,u64 c){
    RG_CAP();
    RI* p=&rg_ins[rg_ni]; p->op=op; p->a=a; p->b=b; p->c=c;
    return rg_ni++;
}
static int rg_patch(int pc,int target){ if(pc>=0&&pc<rg_ni) rg_ins[pc].a=(u64)target; return target; }

typedef struct {
    int pc; int sp; int goal;
    int caps[40];
} RFrame;

static int rg_fold_ci(int c){ if(c>='a'&&c<='z') return c-32; return c; }

static int rg_wordc(int c){ return (c>='0'&&c<='9')||(c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'; }
static int rg_spacec(int c){ return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\f'||c=='\v'; }

static int rg_cp_at(const char* s,u64 i,u64 len,int* adv){
    unsigned char c=(unsigned char)s[i];
    if(c<0x80){ *adv=1; return c; }
    if(c>=0xF0&&(int)(len-i)>=4){ *adv=4; return ((c&7)<<18)|(((unsigned char)s[i+1]&0x3F)<<12)|(((unsigned char)s[i+2]&0x3F)<<6)|((unsigned char)s[i+3]&0x3F); }
    if(c>=0xE0&&(int)(len-i)>=3){ *adv=3; return ((c&15)<<12)|(((unsigned char)s[i+1]&0x3F)<<6)|((unsigned char)s[i+2]&0x3F); }
    if(c>=0xC0&&(int)(len-i)>=2){ *adv=2; return ((c&31)<<6)|((unsigned char)s[i+1]&0x3F); }
    *adv=1; return c;
}
static int rg_utf8(u32 cp,unsigned char out[4]){
    if(cp<=0x7F){ out[0]=(unsigned char)cp; return 1; }
    if(cp<=0x7FF){ out[0]=(unsigned char)(0xC0|(cp>>6)); out[1]=(unsigned char)(0x80|(cp&0x3F)); return 2; }
    if(cp<=0xFFFF){ out[0]=(unsigned char)(0xE0|(cp>>12)); out[1]=(unsigned char)(0x80|((cp>>6)&0x3F)); out[2]=(unsigned char)(0x80|(cp&0x3F)); return 3; }
    out[0]=(unsigned char)(0xF0|(cp>>18)); out[1]=(unsigned char)(0x80|((cp>>12)&0x3F)); out[2]=(unsigned char)(0x80|((cp>>6)&0x3F)); out[3]=(unsigned char)(0x80|(cp&0x3F)); return 4;
}

/* class-table helpers */
static int rg_cls_add(RCls* c,int lo,int hi){ if(c->np<24){ c->pr[c->np].lo=lo; c->pr[c->np].hi=hi; c->np++; } return 1; }
static int rg_cls_hit(RCls* c,int ch){
    int neg=c->neg; int hit=0;
    for(int i=0;i<c->np;i++) if(ch>=c->pr[i].lo&&ch<=c->pr[i].hi){ hit=1; break; }
    return neg? !hit : hit;
}

/* compile one char-class starting at p[i] (the char AFTER '['). Returns pos after ']', or -1. */
static int rg_compile_class(RCls* c,const char* p,int plen,int i){
    c->neg=c->np=0;
    if(i>=plen) return -1;
    if(p[i]=='^'){ c->neg=1; i++; if(i<plen&&p[i]==']'){ rg_cls_add(c,']',']'); i++; } }
    int first=1;
    while(i<plen){
        if(p[i]==']'&&!first) return i+1;
        first=0;
        if(p[i]=='\\'&&i+1<plen){
            char e=p[i+1];
            if(e=='d'||e=='D'){ if(e=='D')c->neg=!c->neg; rg_cls_add(c,'0','9'); i+=2; continue; }
            if(e=='w'||e=='W'){ if(e=='W')c->neg=!c->neg; rg_cls_add(c,'0','9'); rg_cls_add(c,'a','z'); rg_cls_add(c,'A','Z'); rg_cls_add(c,'_','_'); i+=2; continue; }
            if(e=='s'||e=='S'){ if(e=='S')c->neg=!c->neg; rg_cls_add(c,9,13); rg_cls_add(c,32,32); i+=2; continue; }
            if(e=='n'){ rg_cls_add(c,10,10); i+=2; continue; }
            if(e=='t'){ rg_cls_add(c,9,9); i+=2; continue; }
            if(e=='r'){ rg_cls_add(c,13,13); i+=2; continue; }
            if(e=='f'){ rg_cls_add(c,12,12); i+=2; continue; }
            if(e=='v'){ rg_cls_add(c,11,11); i+=2; continue; }
            if(e=='u'&&i+6<=plen){
                u32 cp=0; int ok=1;
                for(int k=0;k<4;k++){ char h=p[i+2+k]; int hv=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:(h>='A'&&h<='F')?h-'A'+10:-1; if(hv<0){ok=0;break;} cp=cp*16+(u32)hv; }
                if(ok){ unsigned char t4[4]; int ul=rg_utf8(cp,t4); int lo2=0,hi2=0;
                    /* store all bytes as one ranged pair list of -CLASSU- markers */
                    for(int k=0;k<ul;k++) rg_cls_add(c,t4[k],t4[k]);
                    i+=6; continue; }
            }
            rg_cls_add(c,(unsigned char)e,(unsigned char)e); i+=2; continue;
        }
        unsigned char lo=(unsigned char)p[i];
        if(i+2<plen && p[i+1]=='-' && p[i+2]!=']'){
            unsigned char hi=(unsigned char)p[i+2];
            if(p[i+2]=='\\'&&i+3<plen) hi=(unsigned char)p[i+3];
            rg_cls_add(c,lo,hi);
            i+= (p[i+2]=='\\')?4:3;
            continue;
        }
        rg_cls_add(c,lo,lo);
        i++;
    }
    return -1;
}

static int xmemcmp(const void* a,const void* b,u64 n){
    const unsigned char* aa=(const unsigned char*)a; const unsigned char* bb=(const unsigned char*)b;
    for(u64 i=0;i<n;i++) if(aa[i]!=bb[i]) return 1;
    return 0;
}

/* ------------------ compiler state ------------------ */
static const char* rg_cp; static int rg_cpl; static int rg_cpi;
static int rg_cng;            /* running capture-group counter */
static int rg_cscr;           /* scratch-slot counter (allocated after 2*maxgroups) */
static int rg_groups;         /* final group count */
static int rg_calt(void);     /* fwd: groups/lookarounds recurse into alternation */

/* atom end position for quantifier pre-scan (peeks, does not consume) */
static int rg_atom_end(void){
    int p=rg_cpi; if(p>=rg_cpl) return p;
    char c=rg_cp[p];
    if(c=='('){
        p+= (p+1<rg_cpl && rg_cp[p+1]=='?')?3:1;
        int d=0;
        while(p<rg_cpl){
            char q=rg_cp[p];
            if(q=='\\'){ p+=2; continue; }
            if(q=='['){ while(p<rg_cpl){ if(rg_cp[p]=='\\')p+=2; else if(rg_cp[p]==']'){p++;break;} else p++; } continue; }
            if(q=='(') d++;
            if(q==')'){ if(d==0) return p+1; d--; }
            p++;
        }
        return p;
    }
    if(c=='['){
        for(int i=p+1;i<rg_cpl;i++){ char q=rg_cp[i]; if(q=='\\'){i++;continue;} if(q==']')return i+1; }
        return rg_cpl;
    }
    if(c=='\\'){
        if(p+1<rg_cpl){ char e=rg_cp[p+1];
            if(e=='u') return p+6;
            if(e=='x') return p+4;
            return p+2; }
        return p+1;
    }
    return p+1;
}

static int rg_is_zeroatom(void){
    char c=rg_cp[rg_cpi];
    if(c=='^'||c=='$') return 1;
    if(c=='\\'&&rg_cpi+1<rg_cpl){ char e=rg_cp[rg_cpi+1]; if(e=='b'||e=='B') return 1; }
    return 0;
}

/* compiles the body of ONE atom (not quantifier); advances rg_cpi past it.
   Returns 0 ok, -1 compile error. */
static int rg_atom_body(void){
    char c=rg_cp[rg_cpi];
    if(c=='('){
        if(rg_cpi+1<rg_cpl && rg_cp[rg_cpi+1]=='?'){
            char m = (rg_cpi+2<rg_cpl)? rg_cp[rg_cpi+2] : 0;
            if(m==':'){
                rg_cpi+=3;
                rg_calt();
                if(rg_cpi<rg_cpl && rg_cp[rg_cpi]==')') rg_cpi++; else return -1;
                return 0;
            }
            if(m=='='){
                rg_cpi+=3;
                int scr=32+(rg_cscr++&7);
                rg_emit(ROP_POSA,scr,0,0);
                rg_calt();
                if(rg_cpi<rg_cpl && rg_cp[rg_cpi]==')') rg_cpi++; else return -1;
                rg_emit(ROP_GOAL,scr,0,0);
                return 0;
            }
            if(m=='!'){
                rg_cpi+=3;
                int scr=32+(rg_cscr++&7);
                int s=rg_emit(ROP_SPLIT,0,0,0);
                rg_calt();
                if(rg_cpi<rg_cpl && rg_cp[rg_cpi]==')') rg_cpi++; else return -1;
                rg_emit(ROP_NEGOK,scr,0,0);
                rg_patch(s,rg_ni);
                return 0;
            }
            rg_cpi+=2;
        }
        int slot=rg_cng; rg_cng++;
        rg_cpi++;
        rg_emit(ROP_SAVE,slot*2,0,0);
        rg_calt();
        if(rg_cpi<rg_cpl && rg_cp[rg_cpi]==')') rg_cpi++; else return -1;
        rg_emit(ROP_SAVE,slot*2+1,0,0);
        return 0;
    }
    if(c=='['){
        RCls cl; int end=rg_compile_class(&cl,rg_cp,rg_cpl,rg_cpi+1);
        if(end<0) return -1;
        RCls* c2=(RCls*)arena_alloc(sizeof(RCls)); if(!c2) return -1;
        *c2=cl;
        rg_emit(ROP_CLS,0,(u64)c2,0);
        rg_cpi=end;
        return 0;
    }
    if(c=='\\'){
        if(rg_cpi+1>=rg_cpl) return -1;
        char e=rg_cp[rg_cpi+1];
        if(e=='d'||e=='D'){ rg_emit(ROP_D,(u64)(e=='D'?1:0),0,0); rg_cpi+=2; return 0; }
        if(e=='w'||e=='W'){ rg_emit(ROP_W,(u64)(e=='W'?1:0),0,0); rg_cpi+=2; return 0; }
        if(e=='s'||e=='S'){ rg_emit(ROP_SP,(u64)(e=='S'?1:0),0,0); rg_cpi+=2; return 0; }
        if(e=='b'){ rg_emit(ROP_BOUND,0,0,0); rg_cpi+=2; return 0; }
        if(e=='B'){ rg_emit(ROP_BOUND,1,0,0); rg_cpi+=2; return 0; }
        if(e=='n'){ rg_emit(ROP_CH,10,0,0); rg_cpi+=2; return 0; }
        if(e=='t'){ rg_emit(ROP_CH,9,0,0); rg_cpi+=2; return 0; }
        if(e=='r'){ rg_emit(ROP_CH,13,0,0); rg_cpi+=2; return 0; }
        if(e=='f'){ rg_emit(ROP_CH,12,0,0); rg_cpi+=2; return 0; }
        if(e=='v'){ rg_emit(ROP_CH,11,0,0); rg_cpi+=2; return 0; }
        if(e=='u'){
            u32 cp=0; int ok=1;
            if(rg_cpi+6>rg_cpl) ok=0;
            for(int k=0;k<4 && ok;k++){ char h=rg_cp[rg_cpi+2+k]; int hv=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:(h>='A'&&h<='F')?h-'A'+10:-1; if(hv<0){ok=0;break;} cp=cp*16+(u32)hv; }
            if(ok && cp>=0xD800 && cp<0xDC00 && rg_cpi+12<=rg_cpl){
                u32 lo=0; int ok2=1;
                if(!(rg_cp[rg_cpi+6]=='\\'&&rg_cp[rg_cpi+7]=='u')) ok2=0;
                for(int k=0;k<4 && ok2;k++){ char h=rg_cp[rg_cpi+8+k]; int hv=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:(h>='A'&&h<='F')?h-'A'+10:-1; if(hv<0){ok2=0;break;} lo=lo*16+(u32)hv; }
                if(ok2 && lo>=0xDC00 && lo<=0xDFFF){ cp=0x10000+((cp-0xD800)<<10)+(lo-0xDC00); rg_cpi+=12; }
                else rg_cpi+=6;
            } else {
                rg_cpi+= (ok?6:2);
            }
            if(!ok) rg_emit(ROP_CH,(u64)'u',0,0);
            else {
                unsigned char t4[4]; int tl=rg_utf8(cp,t4);
                if(tl==1) rg_emit(ROP_CH,(u64)t4[0],0,0);
                else { rg_emit(ROP_STR,(u64)t4,tl,0); }
            }
            return 0;
        }
        if(e>=49&&e<=57){
            rg_emit(ROP_BACKREF,(u64)(e-49),0,0);
            rg_cpi+=2;
            return 0;
        }
        rg_emit(ROP_CH,(u64)(unsigned char)e,0,0);
        rg_cpi+=2;
        return 0;
    }
    if(c=='.'){ rg_emit(ROP_DOT,0,0,0); rg_cpi++; return 0; }
    if(c=='^'){ rg_emit(ROP_CARET,0,0,0); rg_cpi++; return 0; }
    if(c=='$'){ rg_emit(ROP_DOLLAR,0,0,0); rg_cpi++; return 0; }
    rg_emit(ROP_CH,(u64)(unsigned char)c,0,0);
    rg_cpi++;
    return 0;
}

/* one atom + its quantifier */
static int rg_catom(void){
    int astart=rg_cpi;
    int ea=rg_atom_end();
    int qmin=1,qmax=1,hasq=0;
    int qend=-1;
    if(ea<rg_cpl){
        char q=rg_cp[ea];
        if(q=='*'){ qmin=0; qmax=-1; hasq=1; qend=ea+1; }
        else if(q=='+'){ qmin=1; qmax=-1; hasq=1; qend=ea+1; }
        else if(q=='?'){ qmin=0; qmax=1; hasq=1; qend=ea+1; }
        else if(q=='{'){
            int p=ea+1; int n1=-1,n2=-1; int ok=1;
            while(p<rg_cpl&&rg_cp[p]>='0'&&rg_cp[p]<='9'){ n1=(n1<0?0:n1)*10+(rg_cp[p]-'0'); if(n1>100){n1=100;} p++; }
            if(n1<0) ok=0;
            if(ok&&p<rg_cpl&&rg_cp[p]=='}'){ qmin=qmax=n1; hasq=1; qend=p+1; }
            else if(ok&&p<rg_cpl&&rg_cp[p]==','){
                p++;
                if(p<rg_cpl&&rg_cp[p]=='}'){ qmin=n1; qmax=-1; hasq=1; qend=p+1; }
                else { n2=0;
                    while(p<rg_cpl&&rg_cp[p]>='0'&&rg_cp[p]<='9'){ n2=n2*10+(rg_cp[p]-'0'); if(n2>100){n2=100;} p++; }
                    if(p<rg_cpl&&rg_cp[p]=='}'){ qmin=n1; qmax=n2; hasq=1; qend=p+1; }
                }
            }
        }
    }
    if(hasq==0){ int r=rg_atom_body(); return r; }
    if(rg_is_zeroatom()){ int r=rg_atom_body(); if(r>=0) rg_cpi=qend; return r; }   /* anchors/lookaheads: quantifier ignored */
    /* '?' : SPLIT OUT; body; OUT */
    if(qmin==0&&qmax==1){
        int g=rg_emit(ROP_SPLIT,0,0,0);
        if(rg_atom_body()<0) return -1;
        rg_patch(g,rg_ni);
        rg_cpi=qend;
        return 0;
    }
    /* '*' : SPLIT OUT; L: body; SPLIT OUT; SPLIT FAIL; JMP L; FAIL; OUT */
    if(qmin==0&&qmax<0){
        int g0=rg_emit(ROP_SPLIT,0,0,0);
        int L=rg_ni;
        if(rg_atom_body()<0) return -1;
        int g1=rg_emit(ROP_SPLIT,0,0,0);
        int f=rg_emit(ROP_SPLIT,0,0,0);
        rg_emit(ROP_JMP,(u64)L,0,0);
        int F=rg_emit(ROP_FAIL,0,0,0);
        int OUT=rg_ni;
        rg_patch(g0,OUT); rg_patch(g1,OUT); rg_patch(f,F);
        rg_cpi=qend;
        return 0;
    }
    /* '+' : body; L? : SPLIT OUT; SPLIT FAIL; JMP L; FAIL; OUT */
    if(qmin==1&&qmax<0){
        int L=rg_ni;
        if(rg_atom_body()<0) return -1;
        int g=rg_emit(ROP_SPLIT,0,0,0);
        int f=rg_emit(ROP_SPLIT,0,0,0);
        rg_emit(ROP_JMP,(u64)L,0,0);
        int F=rg_emit(ROP_FAIL,0,0,0);
        int OUT=rg_ni;
        rg_patch(g,OUT); rg_patch(f,F);
        rg_cpi=qend;
        return 0;
    }
    /* {m} : m straight-line copies */
    if(qmax==qmin){
        for(int i=0;i<qmin;i++){ rg_cpi=astart; if(rg_atom_body()<0) return -1; }
        rg_cpi=qend;
        return 0;
    }
    /* {m,} : (m) mandatory then greedy */
    if(qmax<0){
        for(int i=0;i<qmin;i++){ rg_cpi=astart; if(rg_atom_body()<0) return -1; }
        int bstart=rg_ni;
        if((rg_cpi=astart, rg_atom_body())<0) return -1;
        int g=rg_emit(ROP_SPLIT,0,0,0);
        rg_emit(ROP_JMP,(u64)bstart,0,0);
        rg_patch(g,rg_ni);
        rg_cpi=qend;
        return 0;
    }
    /* {m,n} : m mandatory then (n-m) optional guards */
    if(qmin>qmax){ qmin=qmax; }
    for(int i=0;i<qmin;i++){ rg_cpi=astart; if(rg_atom_body()<0) return -1; }
    int guards[24]; int ng=0;
    for(int k=qmin;k<qmax && ng<24;k++){
        guards[ng]=rg_emit(ROP_SPLIT,0,0,0); ng++;
        rg_cpi=astart;
        if(rg_atom_body()<0) return -1;
    }
    if(ng>0){
        for(int k=0;k<ng;k++) rg_patch(guards[k], (k+1<ng)? guards[k+1] : rg_ni);
    }
    rg_cpi=qend;
    return 0;
}

/* sequence of atoms until '|' / ')' / end */
static int rg_cseq(void){
    for(;;){
        if(rg_cpi>=rg_cpl) break;
        char c=rg_cp[rg_cpi];
        if(c=='|'||c==')') break;
        int bp=rg_cpi; int before=rg_ni;
        if(rg_catom()<0) return -1;
        if(rg_cpi==bp && rg_ni==before) break;
    }
    return 0;
}

/* alternation: branch1; JMP join; SPLIT; branch2; JMP join; SPLIT; ... join */
static int rg_calt(void){
    int s=rg_emit(ROP_SPLIT,0,0,0);
    if(s<0) return -1;
    if(rg_cseq()<0) return -1;
    char nc = (rg_cpi<rg_cpl)? rg_cp[rg_cpi] : 0;
    if(nc=='|'){
        rg_cpi++;
        int j=rg_emit(ROP_JMP,0,0,0);
        rg_patch(s, rg_ni);
        if(j<0) return -1;
        if(rg_calt()<0) return -1;
        rg_patch(j, rg_ni);
    } else {
        int j=rg_emit(ROP_JMP,0,0,0);
        int f=rg_emit(ROP_FAIL,0,0,0);
        rg_patch(s, f);
        rg_patch(j, rg_ni);
    }
    return 0;
}

/* top-level compile; returns 0 ok, -1 error. sets rg_groups. */
static int rg_compile(const char* p,int pl){
    rg_cp=p; rg_cpl=pl; rg_cpi=0;
    rg_cng=0; rg_cscr=0;
    rg_ni=0; rg_ncapc=0; rg_ins=0;
    if(rg_calt()<0) return -1;
    rg_emit(ROP_MATCH,0,0,0);
    rg_groups=rg_cng;
    return 0;
}

/* ------------------ runtime ------------------ */
static int rgs_endpos;
static int rgs_out[40];
static int rg_run(const char* s,int slen,int fl,int startsp,int* out_end){
    RFrame st[384];
    int tind=0;
    int pc=0, sp=startsp;
    int caps[40];
    for(int i=0;i<40;i++) caps[i]=-1;
    long steps=0;
    for(;;){
        if(++steps>2000000) goto rgfail;
        RI* in=&rg_ins[pc];
        int op=in->op;
        switch(op){
            case ROP_CH: {
                int m=(sp<slen) && ((fl&RG_I)? (rg_fold_ci((u32)(unsigned char)s[sp])==rg_fold_ci((u32)in->a)) : ((unsigned char)s[sp]==(unsigned char)in->a));
                if(!m) goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_CLS: {
                int ok=0;
                if(sp<slen){
                    int ch=(unsigned char)s[sp];
                    RCls* c=(RCls*)in->b;
                    if(fl&RG_I){
                        int ch2=(ch>='a'&&ch<='z')? ch-32 : ch;
                        for(int i=0;i<c->np;i++){
                            int lo=c->pr[i].lo, hi=c->pr[i].hi;
                            int lo2=(lo>='a'&&lo<='z')? lo-32 : lo;
                            int hi2=(hi>='a'&&hi<='z')? hi-32 : hi;
                            if(ch2>=lo2&&ch2<=hi2){ ok=1; break; }
                        }
                        if(c->neg) ok=!ok;
                    } else ok=rg_cls_hit(c,ch);
                }
                if(!ok) goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_W: {
                int neg=(int)in->a; int ok=0;
                if(sp<slen){ ok=rg_wordc((unsigned char)s[sp]); if(neg)ok=!ok; }
                else ok=neg;
                if(!ok) goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_D: {
                int neg=(int)in->a; int ok=0;
                if(sp<slen){ int ch=(unsigned char)s[sp]; ok=(ch>='0'&&ch<='9'); if(neg)ok=!ok; }
                else ok=neg;
                if(!ok) goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_SP: {
                int neg=(int)in->a; int ok=0;
                if(sp<slen){ ok=rg_spacec((unsigned char)s[sp]); if(neg)ok=!ok; }
                else ok=neg;
                if(!ok) goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_DOT: {
                if(sp>=slen) goto rgfail;
                if(!(fl&RG_S)&&s[sp]=='\n') goto rgfail;
                sp++; pc++; continue;
            }
            case ROP_CARET: {
                int ok=(sp==0);
                if((fl&RG_M)&&!ok) ok=(sp>0&&s[sp-1]=='\n');
                if(!ok) goto rgfail;
                pc++; continue;
            }
            case ROP_DOLLAR: {
                int ok=(sp>=slen);
                if((fl&RG_M)&&!ok) ok=(sp<slen&&s[sp]=='\n');
                if(!ok) goto rgfail;
                pc++; continue;
            }
            case ROP_BOUND: {
                int neg=(int)in->a;
                int p= (sp>0&&rg_wordc((unsigned char)s[sp-1]));
                int n= (sp<slen&&rg_wordc((unsigned char)s[sp]));
                int isb=(p!=n);
                if(neg) isb=!isb;
                if(!isb) goto rgfail;
                pc++; continue;
            }
            case ROP_SAVE: {
                caps[(int)in->a]=sp;
                pc++; continue;
            }
            case ROP_SPLIT: {
                if(tind>=380) goto rgfail;
                RFrame* nf=&st[tind];
                nf->pc=(int)in->a; nf->sp=sp;
                xmemcpy(nf->caps,caps,(u64)rgs_nslot*4);
                tind++;

                pc++; continue;
            }
            case ROP_JMP: pc=(int)in->a; continue;
            case ROP_MATCH: {

                rgs_endpos=sp;
                for(int i=0;i<rgs_nslot;i++) rgs_out[i]=caps[i];
                if(out_end) *out_end=sp;
                return 1;
            }
            case ROP_FAIL: goto rgfail;
            case ROP_BACKREF: {
                int g=(int)in->a;
                int a2=g*2, b2=g*2+1;
                if(caps[a2]<0||caps[b2]<0) goto rgfail;
                int cl=caps[b2]-caps[a2];
                if(cl<0||sp+cl>slen) goto rgfail;
                if(xmemcmp(s+caps[a2],s+sp,(u64)cl)) goto rgfail;
                sp+=cl; pc++; continue;
            }
            case ROP_STR: {
                const char* t=(const char*)in->b; int L=(int)in->c;
                if(sp+L>slen) goto rgfail;
                if(xmemcmp(t,s+sp,(u64)L)) goto rgfail;
                sp+=L; pc++; continue;
            }
            case ROP_POSA: {
                caps[(int)in->a]=sp;
                pc++; continue;
            }
            case ROP_GOAL: {
                sp=caps[(int)in->a];
                pc++; continue;
            }
            case ROP_NEGOK: {
                return 0;
            }
        }
        continue;
        rgfail:

        if(tind<=0) return 0;
        tind--;
        pc=st[tind].pc; sp=st[tind].sp;
        xmemcpy(caps,st[tind].caps,(u64)rgs_nslot*4);
    }
}

/* find leftmost match starting at or after `start` (inclusive). Returns
   match index, or -1. Sets *out_ep and fills caps[0..rgs_nslot). */
static int rg_find(const char* s,int slen,int fl,int start,int* out_ep){
    rgs_nslot=40;
    for(int i=start;i<=slen;i++){
        int e=0;
        if(rg_run(s,slen,fl,i,&e)){
            *out_ep=e;
            return i;
        }
    }
    return -1;
}

/* top-level matcher over engine strings. Returns match index (>=0), -1 none,
   -2 compile error. Sets *out_ep. */
/* top-level matcher over engine strings. Returns match index (>=0), -1 none,
   -2 compile error. Sets *out_ep. */
static int rg_match_from(const char* pat,u64 pl,const char* fl,u64 fll,
                        const char* src,u64 sl,int start,int* out_ep){
    if(rg_compile(pat,(int)pl)<0) return -2;
    return rg_find(src,(int)sl,rg_flags_int(fl,fll),start,out_ep);
}
static int rg_match_src(const char* pat,u64 pl,const char* fl,u64 fll,
                        const char* src,u64 sl,int* out_ep){
    return rg_match_from(pat,pl,fl,fll,src,sl,0,out_ep);
}

/* build the exec result array (or null). Uses current rgs_out with rg_groups groups. */
static Val rg_exec_array(const char* src,u64 sl,int idx,int ep){
    if(idx<0) return vnull();
    Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b) return vnull();
    b->head=0;
    int g=rg_groups;
    if(g>15) g=15;
    box_append(b, vstrof(mkstr(src+idx, (u64)(ep-idx))));
    for(int i=0;i<g;i++){
        int a=rgs_out[i*2], b2=rgs_out[i*2+1];
        if(a>=0&&b2>=a) box_append(b, vstrof(mkstr(src+a,(u64)(b2-a))));
        else box_append(b, vundef());
    }
    box_set(b,"index",vnum((double)idx));
    box_set(b,"input",vstrof(mkstr(src,sl)));
    return varrb(b);
}

static Val rg_make(const char* pat,u64 pl,const char* fl,u64 fll){
    return rg_new(pat,pl,fl,fll);
}

/* expand "$&", "$1".."$9", "$$" in a replacement string; writes to out. */
static u64 rg_expand_repl(char* out,u64 cap,const char* rs,u64 rl,
                          const char* s,int si,int ep,int* caps,int ng){
    u64 o=0;
    for(u64 i=0;i<rl && o+1<cap;i++){
        char c=rs[i];
        if(c=='$' && i+1<rl){
            char d=rs[i+1];
            if(d=='$'){ out[o++]='$'; i++; }
            else if(d=='&'){
                for(int k=si;k<ep && o+1<cap;k++) out[o++]=s[k];
                i++;
            }
            else if(d=='\''||d=='`'){ i++; }
            else if(d>='1'&&d<='9'){
                int g=d-'0';
                int a2=g-1;
                int a=caps[a2*2], b=caps[a2*2+1];
                if(g<=ng && a>=0 && b>=a){ for(int k=a;k<b && o+1<cap;k++) out[o++]=s[k]; }
                i++;
            }
            else out[o++]='$';
        } else out[o++]=c;
    }
    out[o]=0;
    return o;
}

/* ================================================================
   CORE STDLIB HELPERS (modern-JS methods over the plain engine types)
   Map/Set use marker boxes: "$<x" = tag ("Map"/"Set"), "$<e" = V_ARR
   of entries (Map: [k,v] pair arrays; Set: bare values).
   ================================================================ */
#define MK_TAG  "$<x"
#define MK_ENT  "$<e"

static Box* mkset_new(const char* which){
    Box* b=new_box(); if(!b) return 0;
    box_set(b,MK_TAG,vstrof(mkstr(which,xstrlen(which))));
    Box* e=new_box(); if(!e) return 0;
    box_set(b,MK_ENT,varrb(e));
    return b;
}
static const char* mkset_tag(Box* b){
    Val t=b? box_get(b,MK_TAG) : vundef();
    return t.tag==V_STR? _str(t)->data : 0;
}
static Box* mkset_entries(Box* b){
    Val e=box_get(b,MK_ENT);
    return e.tag==V_ARR? _box(e) : 0;
}
static long mkset_size(Box* b){ Box* eb=mkset_entries(b); return eb? box_len(eb) : 0; }
static Val mkset_pair_new(Val k,Val v){
    Box* p=new_box(); if(!p) return vundef();
    box_append(p,k); box_append(p,v);
    return varrb(p);
}
static int mkset_has(Box* b,Val k){
    Box* eb=mkset_entries(b); if(!eb) return 0;
    for(Node* e=eb->head;e;e=e->next){
        if(e->val.tag==V_ARR){ Box* p=_box(e->val); if(p->head && eq_strict(p->head->val,k)) return 1; }
        else if(eq_strict(e->val,k)) return 1;
    }
    return 0;
}
static Val mkset_get(Box* b,Val k){
    Box* eb=mkset_entries(b); if(!eb) return vundef();
    for(Node* e=eb->head;e;e=e->next){
        if(e->val.tag!=V_ARR) continue;
        Box* p=_box(e->val);
        if(p->head && eq_strict(p->head->val,k)){ Node* n2=p->head->next; return n2? n2->val : vundef(); }
    }
    return vundef();
}
static void mkset_set(Box* b,Val k,Val v){
    Box* eb=mkset_entries(b); if(!eb) return;
    for(Node* e=eb->head;e;e=e->next){
        if(e->val.tag!=V_ARR) continue;
        Box* p=_box(e->val);
        if(p->head && eq_strict(p->head->val,k)){
            Node* n2=p->head->next;
            if(n2) n2->val=v; else box_append(p,v);
            return;
        }
    }
    Val pair=mkset_pair_new(k,v);
    if(pair.tag!=V_UNDEF) box_append(eb,pair);
}
static void mkset_add(Box* b,Val v){ if(mkset_has(b,v)) return; Box* eb=mkset_entries(b); if(eb) box_append(eb,v); }
static int mkset_delete(Box* b,Val k){
    Box* eb=mkset_entries(b); if(!eb) return 0;
    Node* prev=0;
    for(Node* e=eb->head;e;e=e->next){
        int hit=0;
        if(e->val.tag==V_ARR){ Box* p=_box(e->val); if(p->head && eq_strict(p->head->val,k)) hit=1; }
        else if(eq_strict(e->val,k)) hit=1;
        if(hit){ if(prev) prev->next=e->next; else eb->head=e->next; return 1; }
        prev=e;
    }
    return 0;
}
static void mkset_clear(Box* b){ Box* eb=mkset_entries(b); if(eb) eb->head=0; }

/* ---- array helpers ---- */
static Box* js_arr_clone(Box* b){
    Box* nb=new_box(); if(!nb) return 0;
    for(Node* e=b->head;e;e=e->next) box_append(nb,e->val);
    return nb;
}
static void js_sort_box(Box* b, Val cmp, Env* env){
    int len=box_len(b);
    if(len>1){
        for(int i=0;i<len-1;i++) for(int j=0;j<len-1-i;j++){
            Node* ea=b->head; for(int k2=0;k2<j&&ea;k2++) ea=ea->next;
            Node* eb=ea?ea->next:0;
            if(!ea||!eb) continue;
            int swap=0;
            if(cmp.tag==V_FUNC){
                Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                if(!argl||!an0||!an1) continue;
                argl->a=an0; an0->next=an1; an0->val=ea->val; an1->val=eb->val;
                Val r=call_func(cmp,argl,env,vundef());
                if(g_had_error) return;
                swap=to_num(r)>0;
            } else {
                const char* sa=str_of_val(ea->val); const char* sb=str_of_val(eb->val);
                swap=xstrcmp(sa,sb)>0;
            }
            if(swap){ Val tv=ea->val; ea->val=eb->val; eb->val=tv; }
        }
    }
}
static void js_arr_flatten_into(Box* src,int depth,Box* out){
    if(depth<=0){ for(Node* e=src->head;e;e=e->next) box_append(out,e->val); return; }
    for(Node* e=src->head;e;e=e->next){
        if(e->val.tag==V_ARR) js_arr_flatten_into(_box(e->val),depth-1,out);
        else box_append(out,e->val);
    }
}
/* nested-array aware join: V_ARR elements stringify via recursive comma-join */
static u64 arr_join_req(Box* b,const char* sep,u64 sl,int depth){
    u64 tl=0; int cnt=0;
    for(Node* e=b->head;e;e=e->next){
        if(e->val.tag==V_ARR && depth>0) tl+=arr_join_req(_box(e->val),",",1,depth-1);
        else tl+=xstrlen(str_of_val(e->val));
        cnt++;
    }
    if(cnt>0) tl+=(u64)(cnt-1)*sl;
    if(tl>(1u<<24)) return 1u<<24;
    return tl;
}
static void arr_join_fill(Box* b,const char* sep,u64 sl,char* buf,u64* o,int depth){
    int first=1;
    for(Node* e=b->head;e;e=e->next){
        if(!first && sl){ xmemcpy(buf+*o,sep,sl); *o+=sl; }
        first=0;
        if(e->val.tag==V_ARR && depth>0){ arr_join_fill(_box(e->val),",",1,buf,o,depth-1); continue; }
        const char* s2=str_of_val(e->val); u64 l2=xstrlen(s2);
        xmemcpy(buf+*o,s2,l2); *o+=l2;
    }
}
static Val js_arr_join_str(Box* b,const char* sep,u64 sl){
    u64 tl=arr_join_req(b,sep,sl,10);
    if(tl>=(1u<<24)) return vstrof(mkstr("",0));
    char* buf=(char*)arena_alloc(tl+1); if(!buf) return vundef();
    u64 o=0; arr_join_fill(b,sep,sl,buf,&o,10); buf[o]=0;
    return vstrof(mkstr(buf,o));
}
static Val arr_value_at(Box* b,long i){
    Node* e=b->head; long t=0;
    while(e && t<i){ e=e->next; t++; }
    return e? e->val : vundef();
}

/* ---- URI percent-encoding helpers ---- */
static int hex_val2(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
static int uri_unreserved(char c){
    return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~';
}
static int uri_reserved(char c){
    return c=='/'||c==';'||c=='?'||c==':'||c=='@'||c=='&'||c=='='||c=='+'||c=='$'||c==','||c=='#';
}
static const char URI_HEX[]="0123456789ABCDEF";
static char* uri_encode(const char* s, u64 n, int keep_reserved, u64* outn){
    char* b=(char*)arena_alloc(n*3+1); if(!b){ *outn=0; return 0; }
    u64 o=0;
    for(u64 i=0;i<n;i++){
        unsigned char c=(unsigned char)s[i];
        if(uri_unreserved((char)c) || (keep_reserved && uri_reserved((char)c))) b[o++]=c;
        else { b[o++]='%'; b[o++]=URI_HEX[c>>4]; b[o++]=URI_HEX[c&15]; }
    }
    b[o]=0; *outn=o; return b;
}
static char* uri_decode(const char* s, u64 n, u64* outn){
    char* b=(char*)arena_alloc(n+1); if(!b){ *outn=0; return 0; }
    u64 o=0;
    for(u64 i=0;i<n;i++){
        if(s[i]=='%' && i+2<n){
            int h=hex_val2(s[i+1]), l=hex_val2(s[i+2]);
            if(h>=0&&l>=0){ b[o++]=(char)(h*16+l); i+=2; continue; }
        } else if(s[i]=='+' && s[i+0]){ /* handled by caller convention */ }
        b[o++]=s[i];
    }
    b[o]=0; *outn=o; return b;
}

/* ---- UTF-8 code point helpers ---- */
static u32 utf8_decode_cp(const char* s,u64 len,u64* adv){
    u32 c=(unsigned char)s[0];
    if(c<0x80){ *adv=1; return c; }
    u32 v=0; u64 need=0; u64 i=1;
    if((c&0xE0)==0xC0){ need=1; v=c&0x1F; }
    else if((c&0xF0)==0xE0){ need=2; v=c&0x0F; }
    else if((c&0xF8)==0xF0){ need=3; v=c&0x07; }
    else { *adv=1; return c; }
    while(i<len && i<=need){ unsigned char cc=(unsigned char)s[i]; if((cc&0xC0)!=0x80) break; v=(v<<6)|(cc&0x3F); i++; }
    *adv=i; return v;
}
static char* utf8_encode_cp(u32 cp,int* outn){
    char* b=(char*)arena_alloc(5); if(!b){ *outn=0; return 0; }
    if(cp<0x80){ b[0]=(char)cp; *outn=1; }
    else if(cp<0x800){ b[0]=(char)(0xC0|(cp>>6)); b[1]=(char)(0x80|(cp&0x3F)); *outn=2; }
    else if(cp<0x10000){ b[0]=(char)(0xE0|(cp>>12)); b[1]=(char)(0x80|((cp>>6)&0x3F)); b[2]=(char)(0x80|(cp&0x3F)); *outn=3; }
    else { b[0]=(char)(0xF0|(cp>>18)); b[1]=(char)(0x80|((cp>>12)&0x3F)); b[2]=(char)(0x80|((cp>>6)&0x3F)); b[3]=(char)(0x80|(cp&0x3F)); *outn=4; }
    return b;
}

/* ---- string replace helper (plain-string pattern) ---- */
static Val js_str_replace_helper(const Str* s, const Str* ndl, Val a1, Env* env, int global){
    u64 slen=s->len, nlen=ndl->len;
    /* replacement text or callable */
    int fn = (a1.tag==V_FUNC);
    Val csv = fn? vundef() : a1;
    const char* rp = fn? 0 : str_of_val(csv);
    u64 rpl = fn? 0 : xstrlen(rp);
    u64 cap = slen + (fn? slen : slen + rpl) + 8;
    if(cap>(1u<<24)) cap=(1u<<24);
    char* buf=(char*)arena_alloc(cap); if(!buf) return vundef();
    u64 o=0; u64 pos=0; int replaced=0;
    while(pos<=slen && (!replaced || global)){
        long at=str_find(s,ndl,(long)pos);
        if(at<0) break;
        if((u64)at>pos){ u64 n2=at-pos; if(o+n2>cap) n2=cap-o; xmemcpy(buf+o,s->data+pos,n2); o+=n2; }
        if(fn){
            Node* argl=mkn(NK_LIST); Node* am=mkn(NK_STR);
            if(!argl||!am) return vundef();
            argl->a=am; am->val=vstrof(mkstr(s->data+at,nlen));
            Val r=call_func(a1,argl,env,vundef());
            if(g_had_error) return vundef();
            const char* rs=str_of_val(r); u64 rl2=xstrlen(rs);
            if(o+rl2>cap) rl2=cap-o; xmemcpy(buf+o,rs,rl2); o+=rl2;
        } else {
            u64 i=0;
            while(i<rpl && o<cap){
                if(rp[i]=='$' && i+1<rpl){
                    if(rp[i+1]=='$'){ buf[o++]='$'; i+=2; continue; }
                    if(rp[i+1]=='&'){ u64 k=nlen; if(o+k>cap)k=cap-o; xmemcpy(buf+o,s->data+at,k); o+=k; i+=2; continue; }
                    if(rp[i+1]=='`'){ u64 k=at; if(o+k>cap)k=cap-o; xmemcpy(buf+o,s->data,k); o+=k; i+=2; continue; }
                    if(rp[i+1]=='\''){ u64 k=slen-(at+nlen); if(o+k>cap)k=cap-o; xmemcpy(buf+o,s->data+at+nlen,k); o+=k; i+=2; continue; }
                }
                buf[o++]=rp[i++];
            }
        }
        pos=(u64)at+nlen;
        replaced=1;
    }
    if(o+nlen<cap && pos<=slen){ u64 n2=slen-pos; if(o+n2>cap) n2=cap-o; xmemcpy(buf+o,s->data+pos,n2); o+=n2; }
    buf[o]=0;
    return vstrof(mkstr(buf,o));
}

/* ================================================================
   BUILT-IN MODULES + console / JSON
   fs, path, base64  via require('fs') etc.; console.*, JSON.* via
   member dispatch (call_builtin_member).
   ================================================================ */

/* Build a V_OBJ module object from a descriptor of {name, ...?}. For our
   builtins the object is a plain Box holding string->string/num entries. */
static Val builtin_obj(void){ Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b) return vundef(); b->head=0; return vobjof(b); }

/* Eval args[0..] of a call; n = count. */
static Node* argn(Node* args,int i){ Node* p=args?args->a:0; while(p&&i){p=p->next;i--;} return p; }

/* console.log / console.error: print each arg's string form joined by " " + "\n". */
static Val builtin_console(const char* key, Node* args, Env* env){
    if(xstrcmp(key,"log") && xstrcmp(key,"error")) return vundef();
    (void)key;
    /* Lightweight string builder over the arena (cap bounded). */
    enum { CAP = 8192 };
    char* buf=(char*)arena_alloc(CAP); u64 n=0; int first=1;
    for(Node* p=args?args->a:0; p && n<CAP-2; p=p->next){
        Val v=eval(p,env); const char* s=str_of_val(v); u64 sl=xstrlen(s);
        if(!first && n<CAP-1) buf[n++]=' ';
        first=0;
        for(u64 i=0;i<sl && n<CAP-1;i++) buf[n++]=s[i];
    }
    if(n<CAP-1) buf[n++]='\n';
    buf[n]=0;
    if(g_host_fn[HOST_PRINT]) g_host_fn[HOST_PRINT]((long)buf,(long)n,0,0);
    return vundef();
}

/* ---- base64 ---- */
static const char B64C[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static Val builtin_base64(const char* key, Node* args, Env* env){
    if(!xstrcmp(key,"encode")){
        Node* a0n=argn(args,0); if(!a0n) return vundef();
        Str* s=_str(eval(a0n,env));
        u64 sl=s->len;
        char* out=(char*)arena_alloc(sl*4/3+8);
        u64 o=0, i=0;
        while(i+2<sl){
            u32 x=(unsigned char)s->data[i]<<16|(unsigned char)s->data[i+1]<<8|(unsigned char)s->data[i+2];
            out[o++]=B64C[(x>>18)&63]; out[o++]=B64C[(x>>12)&63];
            out[o++]=B64C[(x>>6)&63]; out[o++]=B64C[x&63];
            i+=3;
        }
        if(i+1==sl){
            u32 x=(unsigned char)s->data[i]<<16;
            out[o++]=B64C[(x>>18)&63]; out[o++]=B64C[(x>>12)&63]; out[o++]='='; out[o++]='=';
        } else if(i+2==sl){
            u32 x=(unsigned char)s->data[i]<<16|(unsigned char)s->data[i+1]<<8;
            out[o++]=B64C[(x>>18)&63]; out[o++]=B64C[(x>>12)&63]; out[o++]=B64C[(x>>6)&63]; out[o++]='=';
        }
        out[o]=0;
        return vstrof(mkstr(out,o));
    }
    if(!xstrcmp(key,"decode")){
        Node* a0n=argn(args,0); if(!a0n) return vundef();
        Str* s=_str(eval(a0n,env));
        static int rev[256]; static int rev_init=0;
        if(!rev_init){ for(int i=0;i<256;i++)rev[i]=-1; for(int i=0;i<64;i++)rev[(int)B64C[i]]=i; rev_init=1; }
        char* out=(char*)arena_alloc(s->len+1); u64 o=0; int acc=0, nbits=-8;
        for(u64 i=0;i<s->len;i++){
            char c=s->data[i]; if(c=='='||c=='\n'||c=='\r') continue;
            int d=rev[(int)c]; if(d<0) break;
            acc=(acc<<6)|d; nbits+=6;
            if(nbits>=0){ out[o++]=(char)((acc>>nbits)&0xFF); nbits-=8; }
        }
        return vstrof(mkstr(out,o));
    }
    return vundef();
}

/* ---- path ---- */
static Val builtin_path(const char* key, Node* args, Env* env){
    Node* a0n=argn(args,0); Node* a1n=argn(args,1); Node* a2n=argn(args,2);
    Val a0=a0n? eval(a0n,env):vundef();
    Val a1=a1n? eval(a1n,env):vundef();
    if(!xstrcmp(key,"join")){
        /* join all string args with '/' (dedup separators simply) */
        u64 cap=128; for(Node* p=args?args->a:0;p;p=p->next) cap+=xstrlen(str_of_val(eval(p,env)))+2;
        char* out=(char*)arena_alloc(cap); u64 o=0; int first=1;
        for(Node* p=args?args->a:0;p;p=p->next){
            const char* s=str_of_val(eval(p,env)); u64 sl=xstrlen(s);
            if(!first && o && out[o-1]!='/' && sl && s[0]!='/') out[o++]='/';
            first=0;
            for(u64 i=0;i<sl;i++) out[o++]=s[i];
        }
        out[o]=0;
        return vstrof(mkstr(out,o));
    }
    if(!xstrcmp(key,"basename")){
        if(a0.tag!=V_STR) return vundef();
        const char* s=_str(a0)->data; u64 sl=_str(a0)->len;
        s64 i=(s64)sl-1; while(i>=0 && s[i]!='/' && s[i]!='\\') i--;
        u64 start=(u64)i+1;
        if(a1n){ /* strip extension if given */
            Val ext=a1n? eval(a1n,env):vundef();
            if(ext.tag==V_STR){
                u64 el=_str(ext)->len;
                if(el<=sl-start && !xstrcmp(s+ (sl-el), _str(ext)->data)) sl-=el;
            }
        }
        return vstrof(mkstr(s+start, sl-start));
    }
    if(!xstrcmp(key,"extname")){
        if(a0.tag!=V_STR) return vundef();
        const char* s=_str(a0)->data; u64 sl=_str(a0)->len;
        s64 i=(s64)sl-1; s64 dot=-1;
        for(;i>=0;i--){ if(s[i]=='.'&&dot<0) dot=i; if(s[i]=='/'||s[i]=='\\') break; }
        if(dot<=0 || dot == (s64)sl-1) return vstrof(mkstr("",0));
        u64 st=(u64)dot; return vstrof(mkstr(s+st, sl-st));
    }
    if(!xstrcmp(key,"dirname")){
        if(a0.tag!=V_STR) return vundef();
        const char* s=_str(a0)->data; u64 sl=_str(a0)->len;
        s64 i=(s64)sl-1; while(i>=0 && s[i]!='/' && s[i]!='\\') i--;
        if(i<0) return vstrof(mkstr(".",1));
        if(i==0) return vstrof(mkstr("/",1));
        return vstrof(mkstr(s,(u64)i));
    }
    return vundef();
}

/* ---- JSON.stringify (recursive) ---- */
static void json_put_str(char* o,u64* n,u64 cap,const char* s,u64 sl){
    o[(*n)++]='"';
    for(u64 i=0;i<sl && *n<cap-8;i++){
        unsigned char c=(unsigned char)s[i];
        if(c=='"'){ o[(*n)++]='\\'; o[(*n)++]='"'; }
        else if(c=='\\'){ o[(*n)++]='\\'; o[(*n)++]='\\'; }
        else if(c=='\n'){ o[(*n)++]='\\'; o[(*n)++]='n'; }
        else if(c=='\t'){ o[(*n)++]='\\'; o[(*n)++]='t'; }
        else if(c=='\r'){ o[(*n)++]='\\'; o[(*n)++]='r'; }
        else if(c=='\b'){ o[(*n)++]='\\'; o[(*n)++]='b'; }
        else if(c=='\f'){ o[(*n)++]='\\'; o[(*n)++]='f'; }
        else if(c<0x20){
            o[(*n)++]='\\'; o[(*n)++]='u'; o[(*n)++]='0'; o[(*n)++]='0';
            static const char H[]="0123456789abcdef";
            o[(*n)++]=H[(c>>4)&15]; o[(*n)++]=H[c&15];
        }
        else o[(*n)++]=c;
    }
    o[(*n)++]='"';
}
static void json_stringify(Val v,char* o,u64* n,u64 cap,int depth){
    if(depth>64) return;
    switch(v.tag){
        case V_NULL: o[(*n)++]='n';o[(*n)++]='u';o[(*n)++]='l';o[(*n)++]='l'; break;
        case V_UNDEF: o[(*n)++]='n';o[(*n)++]='u';o[(*n)++]='l';o[(*n)++]='l'; break;
        case V_BOOL: { const char* s=v.num?"true":"false"; u64 sl=v.num?4:5; for(u64 i=0;i<sl;i++)o[(*n)++]=s[i]; break; }
        case V_NUM: { const char* s=num_str(v.num); u64 sl=xstrlen(s); for(u64 i=0;i<sl;i++)o[(*n)++]=s[i]; break; }
        case V_STR: json_put_str(o,n,cap,_str(v)->data,_str(v)->len); break;
        case V_ARR:{
            Box* b=_box(v); Node* e=b->head; int first=1; o[(*n)++]='[';
            for(; e; e=e->next){ if(!first) o[(*n)++]=','; first=0; json_stringify(e->val,o,n,cap,depth+1); }
            o[(*n)++]=']'; break;
        }
        case V_OBJ:{
            Box* b=_box(v); Node* e=b->head; int first=1; o[(*n)++]='{';
            for(; e; e=e->next){
                if(!e->key) continue;
                if(!first) o[(*n)++]=','; first=0;
                json_put_str(o,n,cap,e->key,xstrlen(e->key));
                o[(*n)++]=':';
                json_stringify(e->val,o,n,cap,depth+1);
            }
            o[(*n)++]='}'; break;
        }
        default: o[(*n)++]='n';o[(*n)++]='u';o[(*n)++]='l';o[(*n)++]='l'; break;
    }
}
static Val builtin_json_stringify(Node* args, Env* env){
    Node* a0n=argn(args,0); if(!a0n) return vstrof(mkstr("undefined",9));
    Val v=eval(a0n,env);
    enum { CAP=65536 };
    char* o=(char*)arena_alloc(CAP); u64 n=0;
    json_stringify(v,o,&n,CAP,0); o[n]=0;
    return vstrof(mkstr(o,n));
}
/* ---- JSON.parse (recursive descent) ---- */
static Val json_parse_recur(const char** p);
static void json_skipws(const char** p){ while(**p==' '||**p=='\t'||**p=='\n'||**p=='\r') (*p)++; }
static Val json_parse_recur(const char** p){
    json_skipws(p);
    char c=**p;
    if(c=='{'){
        (*p)++; Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b)return vundef(); b->head=0;
        json_skipws(p);
        if(**p=='}'){ (*p)++; return vobjof(b); }
        for(;;){
            json_skipws(p);
            if(**p!='"') return vundef();
            (*p)++;
            u64 sl=0; const char* ks=*p;
            while(**p && **p!='"'){ (*p)++; sl++; }
            if(**p!='"') return vundef(); (*p)++;
            char* key=(char*)arena_alloc(sl+1); xmemcpy(key,ks,sl); key[sl]=0;
            json_skipws(p); if(**p!=':') return vundef(); (*p)++;
            Val vv=json_parse_recur(p);
            box_set(b,key,vv);
            json_skipws(p);
            if(**p==','){ (*p)++; continue; }
            if(**p=='}'){ (*p)++; return vobjof(b); }
            return vundef();
        }
    }
    if(c=='['){
        (*p)++; Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b)return vundef(); b->head=0;
        json_skipws(p);
        if(**p==']'){ (*p)++; return varrb(b); }
        int i=0;
        for(;;){
            Val vv=json_parse_recur(p);
            arr_set_idx(b,i,vv); i++;
            json_skipws(p);
            if(**p==','){ (*p)++; continue; }
            if(**p==']'){ (*p)++; return varrb(b); }
            return vundef();
        }
    }
    if(c=='"'){
        (*p)++;
        /* upper bound: source remaining length (escapes make output <= input) */
        u64 rem=xstrlen(*p)+1;
        char* s=(char*)arena_alloc(rem+1); u64 sl=0;
        while(**p && **p!='"'){
            char ch=**p;
            if(ch=='\\'){ (*p)++;
                char e=**p;
                if(e=='n'){ s[sl++]='\n'; }
                else if(e=='t'){ s[sl++]='\t'; }
                else if(e=='r'){ s[sl++]='\r'; }
                else if(e=='b'){ s[sl++]='\b'; }
                else if(e=='f'){ s[sl++]='\f'; }
                else { s[sl++]=e; }  /* \" \\ \/ (unicode escapes approx) */
                (*p)++;
            } else { s[sl++]=ch; (*p)++; }
        }
        s[sl]=0;
        if(**p=='"') (*p)++;
        return vstrof(mkstr(s,sl));
    }
    if(c=='t'){ (*p)++;(*p)++;(*p)++;(*p)++; return vbool(1); }      /* true */
    if(c=='f'){ (*p)++;(*p)++;(*p)++;(*p)++;(*p)++; return vbool(0); } /* false */
    if(c=='n'){ (*p)++;(*p)++;(*p)++;(*p)++; return vnull(); }       /* null */
    if(c=='-'||(c>='0'&&c<='9')){
        int neg=0; if(c=='-'){ neg=1; (*p)++; c=**p; }
        double r=0; int any=0;
        while(**p>='0'&&**p<='9'){ r=r*10+(**p-'0'); (*p)++; any=1; }
        double fr=0,sc=0.1;
        if(**p=='.'){ (*p)++;
            while(**p>='0'&&**p<='9'){ fr+=(**p-'0')*sc; sc*=0.1; (*p)++; }
        }
        if(!any) return vundef();
        double vx=neg?-(r+fr):(r+fr);
        return vnum(vx);
    }
    return vundef();
}
static Val builtin_json_parse(Node* args, Env* env){
    Node* a0n=argn(args,0); if(!a0n) return vundef();
    Str* s=_str(eval(a0n,env));
    char* src=(char*)arena_alloc(s->len+1); xmemcpy(src,s->data,s->len); src[s->len]=0;
    const char* p=src;
    Val v=json_parse_recur(&p);
    return v;
}

/* Returns 1 if (mod,key) is a recognized builtin module function. */
static int builtin_handles(const char* mod, const char* key){
    if(!mod||!key) return 0;
    if(!xstrcmp(mod,"console")) return !xstrcmp(key,"log")||!xstrcmp(key,"error");
    if(!xstrcmp(mod,"path"))    return !xstrcmp(key,"join")||!xstrcmp(key,"basename")
                                  ||!xstrcmp(key,"extname")||!xstrcmp(key,"dirname");
    if(!xstrcmp(mod,"base64"))  return !xstrcmp(key,"encode")||!xstrcmp(key,"decode");
    if(!xstrcmp(mod,"JSON"))    return !xstrcmp(key,"stringify")||!xstrcmp(key,"parse");
    if(!xstrcmp(mod,"String"))  return !xstrcmp(key,"fromCharCode")||!xstrcmp(key,"fromCodePoint")
                                  ||!xstrcmp(key,"raw");
    if(!xstrcmp(mod,"Number"))  return !xstrcmp(key,"isInteger")||!xstrcmp(key,"isSafeInteger")
                                  ||!xstrcmp(key,"isFinite")||!xstrcmp(key,"isNaN")
                                  ||!xstrcmp(key,"parseInt")||!xstrcmp(key,"parseFloat");
    if(!xstrcmp(mod,"Array"))   return !xstrcmp(key,"isArray")||!xstrcmp(key,"from")||!xstrcmp(key,"of");
    if(!xstrcmp(mod,"Map"))     return !xstrcmp(key,"ctor");
    if(!xstrcmp(mod,"Set"))     return !xstrcmp(key,"ctor");
    if(!xstrcmp(mod,"RegExp"))  return !xstrcmp(key,"ctor");
    if(!xstrcmp(mod,"Object"))  return !xstrcmp(key,"assign")||!xstrcmp(key,"hasOwn")||!xstrcmp(key,"is")
                                  ||!xstrcmp(key,"fromEntries")||!xstrcmp(key,"getOwnPropertyNames");
    if(!xstrcmp(mod,"fs"))      return !xstrcmp(key,"readFileSync")||!xstrcmp(key,"writeFileSync")
                                  ||!xstrcmp(key,"existsSync")||!xstrcmp(key,"mkdirSync")
                                  ||!xstrcmp(key,"readdirSync")||!xstrcmp(key,"unlinkSync")
                                  ||!xstrcmp(key,"statSync");
    if(!xstrcmp(mod,"os"))      return !xstrcmp(key,"platform")||!xstrcmp(key,"eol");
    return 0;
}

/* Unified dispatcher for builtin member calls: fs.*, path.*, base64.*,
   console.*, JSON.* (also reached from require of builtin modules). */
static Val call_builtin_member(const char* mod, const char* key, Node* args, Env* env){
    if(!mod || !key) return vundef();
    if(!xstrcmp(mod,"console")) return builtin_console(key,args,env);
    if(!xstrcmp(mod,"path"))    return builtin_path(key,args,env);
    if(!xstrcmp(mod,"base64"))  return builtin_base64(key,args,env);
    if(!xstrcmp(mod,"JSON")){
        if(!xstrcmp(key,"stringify")) return builtin_json_stringify(args,env);
        if(!xstrcmp(key,"parse"))     return builtin_json_parse(args,env);
        return vundef();
    }
    if(!xstrcmp(mod,"String")){
        if(!xstrcmp(key,"fromCharCode")){
            enum { CAP=256 };
            char* buf=(char*)arena_alloc(CAP+1); if(!buf) return vundef();
            u64 n=0;
            for(Node* p=args?args->a:0; p && n<CAP; p=p->next){
                double c=to_num(eval(p,env));
                buf[n++]=(char)(int)c;
            }
            buf[n]=0;
            return vstrof(mkstr(buf,n));
        }
        if(!xstrcmp(key,"fromCodePoint")){
            enum { CAP=512 };
            char* buf=(char*)arena_alloc(CAP); if(!buf) return vundef();
            u64 n=0;
            for(Node* p=args?args->a:0; p && n<CAP-4; p=p->next){
                double c=to_num(eval(p,env));
                if(c<0 || c>0x10FFFF) return vstrof(mkstr("",0));
                int ln=0; char* enc=utf8_encode_cp((u32)c,&ln);
                if(!enc) return vundef();
                xmemcpy(buf+n,enc,(u64)ln); n+=(u64)ln;
            }
            return vstrof(mkstr(buf,n));
        }
        if(!xstrcmp(key,"raw")){
            Node* a0n=argn(args,0); Val tmpl=a0n? eval(a0n,env) : vundef();
            if(tmpl.tag!=V_OBJ) return vundef();
            Val raw=box_get(_box(tmpl),"raw");
            Box* rb = raw.tag==V_ARR? _box(raw) : 0;
            if(!rb) return vundef();
            Node* a1n=argn(args,1);
            /* build: raw[0] + subst[0] + raw[1] + ... as a string */
            u64 tl=0; for(Node* e=rb->head;e;e=e->next) tl+=xstrlen(str_of_val(e->val));
            Node* sub=a1n; for(int k=0;k<(int)box_len(rb)-1;k++){ if(sub){ tl+=xstrlen(str_of_val(eval(sub,env))); sub=sub->next; } }
            if(tl>(1u<<24)) return vundef();
            char* buf=(char*)arena_alloc(tl+1); if(!buf) return vundef();
            u64 o=0; int idx=0; sub=a1n;
            for(Node* e=rb->head;e;e=e->next,idx++){
                const char* s=str_of_val(e->val); u64 l=xstrlen(s); xmemcpy(buf+o,s,l); o+=l;
                if(sub && idx<(int)box_len(rb)-1){ const char* ss=str_of_val(eval(sub,env)); u64 l2=xstrlen(ss); xmemcpy(buf+o,ss,l2); o+=l2; sub=sub->next; }
            }
            buf[o]=0;
            return vstrof(mkstr(buf,o));
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Number")){
        Node* a0n=argn(args,0);
        Val a0=a0n? eval(a0n,env) : vundef();
        if(!xstrcmp(key,"isInteger")) return vbool(is_int_val(a0));
        if(!xstrcmp(key,"isSafeInteger")){
            if(a0.tag==V_NUM){ double x=a0.num;
                return vbool(is_int_val(a0) && x>=-9007199254740991.0 && x<=9007199254740991.0); }
            return vbool(0);
        }
        if(!xstrcmp(key,"isFinite")){
            if(a0.tag!=V_NUM) return vbool(0);
            double x=a0.num;
            return vbool(!(x!=x) && x!=(double)(1.0/0.0) && x!=(double)(-1.0/0.0));
        }
        if(!xstrcmp(key,"isNaN")){
            if(a0.tag!=V_NUM) return vbool(0);
            return vbool(a0.num!=a0.num);
        }
        if(!xstrcmp(key,"parseInt")){
            Node* a1n=argn(args,1);
            int base=a1n? (int)to_num(eval(a1n,env)) : 10;
            if(a0.tag==V_STR){ int any; double v=str_to_int_any(_str(a0),base,&any); return vnum(any?v:(0.0/0.0)); }
            if(a0.tag==V_NUM) return vnum(a0.num);
            return vnum(0.0/0.0);
        }
        if(!xstrcmp(key,"parseFloat")){
            if(a0.tag==V_STR){ int any; double v=str_to_float(_str(a0),&any); return vnum(any?v:(0.0/0.0)); }
            if(a0.tag==V_NUM) return a0;
            return vnum(0.0/0.0);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Array")){
        Node* a0n=argn(args,0);
        Val a0=a0n? eval(a0n,env) : vundef();
        Node* a1n=argn(args,1);
        if(!xstrcmp(key,"isArray")) return vbool(a0.tag==V_ARR);
        if(!xstrcmp(key,"of")){
            Box* out=new_box(); if(!out) return vundef();
            for(Node* p=args?args->a:0; p; p=p->next) box_append(out,eval(p,env));
            return varrb(out);
        }
        if(!xstrcmp(key,"from")){
            Box* out=new_box(); if(!out) return vundef();
            /* array-like: array, string, or object with a numeric length */
            if(a0.tag==V_ARR){ for(Node* e=_box(a0)->head;e;e=e->next) box_append(out,e->val); }
            else if(a0.tag==V_STR){ Str* s=_str(a0); for(u64 i=0;i<s->len;i++){ char ch=s->data[i]; box_append(out,vstrof(mkstr(&ch,1))); } }
            else if(a0.tag==V_OBJ){
                Val lnv=box_get(_box(a0),"length");
                long n=(long)to_num(lnv);
                for(long i=0;i<n;i++) box_append(out,box_get_idx(_box(a0),(int)i));
            } else return varrb(out);
            if(a1n){
                Val fn=eval(a1n,env);
                if(fn.tag==V_FUNC){
                    Box* mapped=new_box(); if(!mapped) return vundef();
                    int idx=0;
                    for(Node* e=out->head;e;e=e->next,idx++){
                        Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                        if(!argl||!an0||!an1) return vundef();
                        argl->a=an0; an0->next=an1; an0->val=e->val; an1->val=vnum((double)idx);
                        box_append(mapped,call_func(fn,argl,env,vundef()));
                        if(g_had_error) return vundef();
                    }
                    return varrb(mapped);
                }
            }
            return varrb(out);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Map")){
        if(!xstrcmp(key,"ctor")){
            Box* b=mkset_new("Map"); if(!b) return vundef();
            /* new Map(iterable) minimal: array of [k,v] pairs */
            Node* a0n=argn(args,0);
            if(a0n){
                Val it=eval(a0n,env);
                if(it.tag==V_ARR){
                    for(Node* e=_box(it)->head;e;e=e->next){
                        if(e->val.tag!=V_ARR) continue;
                        Box* pair=_box(e->val);
                        if(pair->head){ Val k=pair->head->val; Val v=pair->head->next? pair->head->next->val : vundef(); mkset_set(b,k,v); }
                    }
                } else if(it.tag==V_OBJ){ /* plain-object seed: keys->values */
                    Box* ob=_box(it);
                    if(!box_has(ob,MK_TAG)){
                        for(Node* e=ob->head;e;e=e->next) if(e->key) mkset_set(b,vstrof(mkstr(e->key,xstrlen(e->key))),e->val);
                    }
                }
            }
            return vobjof(b);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Set")){
        if(!xstrcmp(key,"ctor")){
            Box* b=mkset_new("Set"); if(!b) return vundef();
            Node* a0n=argn(args,0);
            if(a0n){
                Val it=eval(a0n,env);
                if(it.tag==V_ARR){ for(Node* e=_box(it)->head;e;e=e->next) mkset_add(b,e->val); }
                else if(it.tag==V_STR){ Str* s=_str(it); for(u64 i=0;i<s->len;i++){ char ch=s->data[i]; mkset_add(b,vstrof(mkstr(&ch,1))); } }
            }
            return vobjof(b);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"RegExp")){
        if(!xstrcmp(key,"ctor")){
            const char* pat=""; u64 pl=0; const char* fl=""; u64 fll=0;
            int fromregex=0;
            Node* a0n=argn(args,0);
            if(a0n){
                Val p=eval(a0n,env);
                if(p.tag==V_STR){ pat=_str(p)->data; pl=_str(p)->len; }
                else if(rg_is(p)){ Val pv=rg_pattern(_box(p)); pat=_str(pv)->data; pl=_str(pv)->len; fromregex=1; }
            }
            Node* a1n=argn(args,1);
            if(a1n){
                Val f=eval(a1n,env);
                if(f.tag==V_STR){ fl=_str(f)->data; fll=_str(f)->len; }
            } else if(fromregex){
                Val fv=rg_flags_v(_box(eval(argn(args,0),env)));
                if(fv.tag==V_STR){ fl=_str(fv)->data; fll=_str(fv)->len; }
            }
            return rg_new(pat,pl,fl,fll);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Object")){
        if(!xstrcmp(key,"is")){
            Node* a0n=argn(args,0); Node* a1n=argn(args,1);
            Val x=a0n? eval(a0n,env) : vundef();
            Val y=a1n? eval(a1n,env) : vundef();
            if(x.tag==V_NUM && y.tag==V_NUM){
                double a=x.num, b=y.num;
                if(a!=a && b!=b) return vbool(1);
                if(a!=b) return vbool(0);
                if(a==0 && b==0){ int sa=(1.0/a)>0, sb=(1.0/b)>0; return vbool(sa==sb); }
                return vbool(1);
            }
            return vbool(eq_strict(x,y));
        }
        if(!xstrcmp(key,"fromEntries")){
            Node* a0n=argn(args,0); Val it=a0n? eval(a0n,env) : vundef();
            Box* out=new_box(); if(!out) return vundef();
            if(it.tag==V_ARR){
                for(Node* e=_box(it)->head;e;e=e->next){
                    if(e->val.tag!=V_ARR) continue;
                    Box* pair=_box(e->val);
                    if(pair->head){
                        Val k=pair->head->val; Val v=pair->head->next? pair->head->next->val : vundef();
                        box_set(out,str_of_val(k),v);
                    }
                }
            } else if(it.tag==V_OBJ && !box_has(_box(it),MK_TAG)){
                for(Node* e=_box(it)->head;e;e=e->next){
                    if(e->val.tag!=V_ARR||!e->val.p) continue;
                    Box* pair=_box(e->val);
                    if(pair->head){ Val k=pair->head->val; Val v=pair->head->next? pair->head->next->val : vundef(); box_set(out,str_of_val(k),v); }
                }
            }
            return vobjof(out);
        }
        if(!xstrcmp(key,"getOwnPropertyNames")){
            Node* a0n=argn(args,0); Val o=a0n? eval(a0n,env) : vundef();
            Box* out=new_box(); if(!out) return vundef();
            if(o.tag==V_OBJ||o.tag==V_ARR){
                for(Node* e=_box(o)->head;e;e=e->next){
                    if(!e->key) continue;
                    box_append(out,vstrof(mkstr(e->key,xstrlen(e->key))));
                }
            }
            return varrb(out);
        }
        return vundef();
    }
    if(!xstrcmp(mod,"Object")){
        if(!xstrcmp(key,"assign")){
            Node* a0n=argn(args,0); if(!a0n) return vundef();
            Val t=eval(a0n,env);
            if(t.tag!=V_OBJ && t.tag!=V_ARR) return t;
            Box* tb=_box(t);
            for(Node* p=args?a0n->next:0; p; p=p->next){
                Val v=eval(p,env);
                if(v.tag==V_OBJ){ for(Node* e=_box(v)->head;e;e=e->next) if(e->key) box_set(tb,e->key,e->val); }
                else if(v.tag==V_ARR){ int i=0; for(Node* e=_box(v)->head;e;e=e->next,i++) arr_set_idx(tb,i,e->val); }
            }
            return t;
        }
        if(!xstrcmp(key,"hasOwn")){
            Node* a0n=argn(args,0); Node* a1n=argn(args,1);
            Val obj=a0n? eval(a0n,env):vundef(); Val key=a1n? eval(a1n,env):vundef();
            if(obj.tag!=V_OBJ && obj.tag!=V_ARR) return vbool(0);
            return vbool(box_has(_box(obj),str_of_val(key)));
        }
        return vundef();
    }
    if(!xstrcmp(mod,"fs")){
        Val undef=vundef();
        Node* a0n=argn(args,0); Node* a1n=argn(args,1);
        Val a0=a0n? eval(a0n,env):vundef(); Val a1=a1n? eval(a1n,env):vundef();
        if(!xstrcmp(key,"readFileSync")||!xstrcmp(key,"readfile")){
            if(!g_host_fn[HOST_FS_READ]||a0.tag!=V_STR){ set_err("fs.readFileSync unavailable"); return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            long n=g_host_fn[HOST_FS_READ]((long)path,0,(long)g_fs_buf,(long)sizeof(g_fs_buf)-1);
            if(n<0){ set_err("fs.readFileSync: cannot read"); return undef; }
            return vstrof(mkstr(g_fs_buf,(u64)n));
        }
        if(!xstrcmp(key,"writeFileSync")){
            if(!g_host_fn[HOST_FS_WRITE]||a0.tag!=V_STR){ return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            const char* data=""; u64 dlen=0;
            if(a1.tag==V_STR){ Str* ds=_str(a1); data=ds->data; dlen=ds->len; }
            else { data=str_of_val(a1); dlen=xstrlen(data); }
            long w=g_host_fn[HOST_FS_WRITE]((long)path,0,(long)data,(long)dlen);
            return vnum((double)w);
        }
        if(!xstrcmp(key,"existsSync")){
            if(!g_host_fn[HOST_FS_EXISTS]||a0.tag!=V_STR){ return vbool(0); }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            return vbool(g_host_fn[HOST_FS_EXISTS]((long)path,0,0,0)==1);
        }
        if(!xstrcmp(key,"mkdirSync")){
            if(!g_host_fn[HOST_FS_MKDIR]||a0.tag!=V_STR){ return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            return vnum((double)g_host_fn[HOST_FS_MKDIR]((long)path,0,0,0));
        }
        if(!xstrcmp(key,"readdirSync")){
            if(!g_host_fn[HOST_FS_READDIR]||a0.tag!=V_STR){ return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            char* list=(char*)arena_alloc(32768);
            long n=g_host_fn[HOST_FS_READDIR]((long)path,(long)list,32768,0);
            if(n<0) return vundef();
            /* split on '\n' into array */
            Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b)return vundef(); b->head=0;
            u64 start=0, i;
            for(i=0;i<(u64)n;i++){ if(list[i]=='\n'){ if(i>start) box_append(b,vstrof(mkstr(list+start,i-start))); start=i+1; } }
            if(i>start) box_append(b,vstrof(mkstr(list+start,i-start)));
            return varrb(b);
        }
        if(!xstrcmp(key,"unlinkSync")){
            if(!g_host_fn[HOST_FS_UNLINK]||a0.tag!=V_STR){ return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            return vnum((double)g_host_fn[HOST_FS_UNLINK]((long)path,0,0,0));
        }
        if(!xstrcmp(key,"statSync")){
            if(!g_host_fn[HOST_FS_STAT]||a0.tag!=V_STR){ return undef; }
            Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
            xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
            char* ob=(char*)arena_alloc(128);
            long rc=g_host_fn[HOST_FS_STAT]((long)path,(long)ob,128,0);
            if(rc<0) return vundef();
            /* ob layout: size\0is_dir\0 */
            Box* so=(Box*)arena_alloc(sizeof(Box)); if(!so) return vundef(); so->head=0;
            u64 sz=0; int isd=0;
            { const char* p=ob; u64 v=0; while(*p>='0'&&*p<='9'){ v=v*10+(u64)(*p-'0'); p++; } sz=v; while(*p) p++; p++; isd=(*p=='1'); }
            box_set(so,"size",vnum((double)sz));
            box_set(so,"isDirectory",vbool(isd));
            return vobjof(so);
        }
        return undef;
    }
    if(!xstrcmp(mod,"os")){
        if(!xstrcmp(key,"platform")){
            /* Query via __uname host call, or default to "unknown" */
            if(!g_host_fn[HOST_UNAME]) return vstrof(mkstr("unknown",7));
            char* ob=(char*)arena_alloc(256);
            long n=g_host_fn[HOST_UNAME](0,(long)ob,256,0);
            if(n<0) return vstrof(mkstr("unknown",7));
            return vstrof(mkstr(ob,(u64)n));
        }
        if(!xstrcmp(key,"eol")){
            return vstrof(mkstr("\n",1));
        }
        return vundef();
    }
    return vundef();
}

/* require() of a builtin module name returns a module object whose members
   are native method refs, dispatched by call_func -> call_builtin_member. */
static Val make_native_method(const char* mod, const char* method){
    Node* nn=mkn(NK_NATIVE);
    if(!nn) return vundef();
    u64 ml=xstrlen(mod), kl=xstrlen(method);
    char* s=(char*)arena_alloc(ml+kl+2);
    if(!s) return vundef();
    xmemcpy(s,mod,ml); s[ml]=0x1F;
    xmemcpy(s+ml+1,method,kl); s[ml+1+kl]=0;
    nn->key=s;
    return vfnof(nn);
}
static void builtin_register_method(Box* b,const char* mod,const char* method){
    Val f=make_native_method(mod,method);
    if(f.tag!=V_UNDEF) box_set(b,method,f);
}
static Val builtin_module_by_name(const char* id){
    Val o=builtin_obj(); if(o.tag==V_UNDEF) return o;
    Box* b=_box(o);
    if(!xstrcmp(id,"fs")){
        builtin_register_method(b,"fs","readFileSync");
        builtin_register_method(b,"fs","writeFileSync");
        builtin_register_method(b,"fs","existsSync");
        builtin_register_method(b,"fs","mkdirSync");
        builtin_register_method(b,"fs","readdirSync");
        builtin_register_method(b,"fs","unlinkSync");
        builtin_register_method(b,"fs","statSync");
    } else if(!xstrcmp(id,"path")){
        builtin_register_method(b,"path","join");
        builtin_register_method(b,"path","basename");
        builtin_register_method(b,"path","extname");
        builtin_register_method(b,"path","dirname");
    } else if(!xstrcmp(id,"base64")){
        builtin_register_method(b,"base64","encode");
        builtin_register_method(b,"base64","decode");
    } else if(!xstrcmp(id,"console")){
        builtin_register_method(b,"console","log");
        builtin_register_method(b,"console","error");
    } else if(!xstrcmp(id,"JSON")){
        builtin_register_method(b,"JSON","stringify");
        builtin_register_method(b,"JSON","parse");
    } else if(!xstrcmp(id,"os")){
        builtin_register_method(b,"os","platform");
        builtin_register_method(b,"os","eol");
    }
    return o;
}
static int is_builtin_module(const char* id){
    return !xstrcmp(id,"fs") || !xstrcmp(id,"path") || !xstrcmp(id,"base64")
        || !xstrcmp(id,"console") || !xstrcmp(id,"json") || !xstrcmp(id,"os");
}
static int call_global(const char* fname, Node* args, Env* env, Val* out){
    Node* a0n = args? args->a : 0;
    Node* a1n = a0n? a0n->next : 0;
    Val a0 = a0n? eval(a0n,env) : vundef();
    Val a1 = a1n? eval(a1n,env) : vundef();
    if(!xstrcmp(fname,"parseInt")){
        int base = a1n? (int)to_num(a1) : 10;
        if(base<2||base>36) base=10;
        if(a0.tag==V_STR){ int any; double v=str_to_int_any(_str(a0),base,&any); *out=vnum(any?v:0.0/0.0); return 1; }
        if(a0.tag==V_NUM){ *out=vnum(a0.num==a0.num? a0.num : 0.0/0.0); return 1; }
        *out=vnum(0.0/0.0); return 1;
    }
    if(!xstrcmp(fname,"parseFloat")){
        if(a0.tag==V_STR){ int any; double v=str_to_float(_str(a0),&any); *out=vnum(any?v:0.0/0.0); return 1; }
        if(a0.tag==V_NUM){ *out=a0; return 1; }
        *out=vnum(0.0/0.0); return 1;
    }
    if(!xstrcmp(fname,"isNaN")){
        if(a0.tag==V_NUM){ *out=vbool(a0.num!=a0.num); return 1; }
        if(a0.tag==V_STR){ int any; str_to_float(_str(a0),&any); *out=vbool(!any); return 1; }
        if(a0.tag==V_BOOL){ *out=vbool(0); return 1; }
        *out=vbool(1); return 1;
    }
    if(!xstrcmp(fname,"isFinite")){
        if(a0.tag==V_NUM){ double x=a0.num; *out=vbool(!(x!=x) && !(x==(double)(1.0/0.0)) && !(x==(double)(-1.0/0.0))); return 1; }
        if(a0.tag==V_STR){ int any; double v=str_to_float(_str(a0),&any); *out=vbool(any && !(v!=v) && !(v==(double)(1.0/0.0)) && !(v==(double)(-1.0/0.0))); return 1; }
        *out=vbool(0); return 1;
    }
    if(!xstrcmp(fname,"isInteger")){
        if(a0.tag==V_NUM){ double x=a0.num; *out=vbool(x==x && x!=(double)(1.0/0.0) && x!=(double)(-1.0/0.0) && x==(double)(s64)x); return 1; }
        *out=vbool(0); return 1;
    }
    if(!xstrcmp(fname,"isSafeInteger")){
        if(a0.tag==V_NUM){ double x=a0.num;
            *out=vbool(x==x && x!=(double)(1.0/0.0) && x!=(double)(-1.0/0.0) && x==(double)(s64)x
                && x>=-9007199254740991.0 && x<=9007199254740991.0); return 1; }
        *out=vbool(0); return 1;
    }
    if(!xstrcmp(fname,"encodeURIComponent")){
        if(a0.tag==V_STR){ u64 n2; char* s=uri_encode(_str(a0)->data,_str(a0)->len,0,&n2); if(s){ *out=vstrof(mkstr(s,n2)); return 1; } }
        return 1;
    }
    if(!xstrcmp(fname,"encodeURI")){
        if(a0.tag==V_STR){ u64 n2; char* s=uri_encode(_str(a0)->data,_str(a0)->len,1,&n2); if(s){ *out=vstrof(mkstr(s,n2)); return 1; } }
        return 1;
    }
    if(!xstrcmp(fname,"decodeURIComponent") || !xstrcmp(fname,"decodeURI")){
        if(a0.tag==V_STR){ u64 n2; char* s=uri_decode(_str(a0)->data,_str(a0)->len,&n2); if(s){ *out=vstrof(mkstr(s,n2)); return 1; } }
        return 1;
    }
    if(!xstrcmp(fname,"atob")){
        if(a0.tag==V_STR){
            Str* s=_str(a0);
            /* base64 decode, ignore invalid chars */
            u64 cap=s->len/4*3+4; char* rbuf=(char*)arena_alloc(cap+1); if(!rbuf){ *out=vundef(); return 1; }
            int run=0; u32 acc=0; u64 o=0;
            for(u64 i=0;i<s->len;i++){
                char c=s->data[i]; int v=-1;
                if(c>='A'&&c<='Z')v=c-'A';
                else if(c>='a'&&c<='z')v=c-'a'+26;
                else if(c>='0'&&c<='9')v=c-'0'+52;
                else if(c=='+')v=62;
                else if(c=='/')v=63;
                else if(c=='='){ break; }
                if(v<0) continue;
                acc=(acc<<6)|(u32)v; run++;
                if(run==4){ rbuf[o++]=(char)(acc>>16); rbuf[o++]=(char)(acc>>8); rbuf[o++]=(char)acc; run=0; acc=0; }
            }
            if(run==2){ rbuf[o++]=(char)(acc>>4); }
            else if(run==3){ rbuf[o++]=(char)(acc>>10); rbuf[o++]=(char)(acc>>2); }
            rbuf[o]=0;
            *out=vstrof(mkstr(rbuf,o)); return 1;
        }
        return 1;
    }
    if(!xstrcmp(fname,"btoa")){
        if(a0.tag!=V_STR){ *out=vstrof(mkstr("",0)); return 1; }
        Str* s=_str(a0);
        u64 cap=s->len/3*4+8; char* rbuf=(char*)arena_alloc(cap+1); if(!rbuf){ *out=vundef(); return 1; }
        u64 o=0; u64 i=0;
        static const char B64T[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        while(i+3<=s->len){
            u32 v=((unsigned char)s->data[i]<<16)|((unsigned char)s->data[i+1]<<8)|(unsigned char)s->data[i+2];
            rbuf[o++]=B64T[(v>>18)&63]; rbuf[o++]=B64T[(v>>12)&63]; rbuf[o++]=B64T[(v>>6)&63]; rbuf[o++]=B64T[v&63];
            i+=3;
        }
        u64 rem=s->len-i;
        if(rem==1){ u32 v=(unsigned char)s->data[i]<<16; rbuf[o++]=B64T[(v>>18)&63]; rbuf[o++]=B64T[(v>>12)&63]; rbuf[o++]='='; rbuf[o++]='='; }
        else if(rem==2){ u32 v=((unsigned char)s->data[i]<<16)|((unsigned char)s->data[i+1]<<8); rbuf[o++]=B64T[(v>>18)&63]; rbuf[o++]=B64T[(v>>12)&63]; rbuf[o++]=B64T[(v>>6)&63]; rbuf[o++]='='; }
        rbuf[o]=0;
        *out=vstrof(mkstr(rbuf,o)); return 1;
    }
    if(!xstrcmp(fname,"Number")){
        if(a0.tag==V_NUM){ *out=a0; return 1; }
        if(a0.tag==V_STR){ int any; double v=str_to_float(_str(a0),&any); *out=vnum(any?v:0); return 1; }
        if(a0.tag==V_BOOL){ *out=vnum(a0.num?1:0); return 1; }
        *out=vnum(0); return 1;
    }
    if(!xstrcmp(fname,"String")){
        const char* s=str_of_val(a0); u64 n=xstrlen(s);
        *out=vstrof(mkstr(s,n)); return 1;
    }

    /* ---------- require(id) — CommonJS module loader ---------- */
    if(!xstrcmp(fname,"require")){
        if(a0.tag!=V_STR){ set_err("require expects string"); return 1; }
        /* from_dir: current module dir (set during module exec) or runtime ".".
           Allocate the "." from the arena (never a .rodata literal) so the
           pointer is valid in the non-relocating Windows blob too. */
        const char* from=g_cur_dir;
        if(!from){
            char* dd=(char*)arena_alloc(2);
            if(dd){ dd[0]='.'; dd[1]=0; from=dd; }
            else from="";
        }
        *out = call_require_impl(_str(a0)->data, from);
        return 1;
    }

    /* ---------- Host-backed I/O builtins ---------- */
    if(!xstrcmp(fname,"__readFile") || !xstrcmp(fname,"readFileSync")){
        if(!g_host_fn[HOST_FS_READ]){ *out=vundef(); return 1; }
        if(a0.tag!=V_STR){ set_err("readFile expects string path"); return 1; }
        Str* sp=_str(a0);
        /* null-terminate for CreateFileA */
        char* path=(char*)arena_alloc(sp->len+1);
        xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
        long n=g_host_fn[HOST_FS_READ]((long)path,0,(long)g_fs_buf,(long)sizeof(g_fs_buf));
        if(n<0){ *out=vundef(); return 1; }
        *out=vstrof(mkstr(g_fs_buf,(u64)n));
        return 1;
    }
    if(!xstrcmp(fname,"__writeFile") || !xstrcmp(fname,"writeFileSync")){
        if(!g_host_fn[HOST_FS_WRITE]){ *out=vundef(); return 1; }
        if(a0.tag!=V_STR){ *out=vundef(); return 1; }
        Str* sp=_str(a0);
        char* path=(char*)arena_alloc(sp->len+1);
        xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
        const char* data=""; u64 dlen=0;
        if(a1.tag==V_STR){ Str* ds=_str(a1); data=ds->data; dlen=ds->len; }
        else { data=str_of_val(a1); dlen=xstrlen(data); }
        long w=g_host_fn[HOST_FS_WRITE]((long)path,0,(long)data,(long)dlen);
        *out=vnum((double)w);
        return 1;
    }
    if(!xstrcmp(fname,"__exists")){
        if(!g_host_fn[HOST_FS_EXISTS]){ *out=vbool(0); return 1; }
        if(a0.tag!=V_STR){ *out=vbool(0); return 1; }
        Str* sp=_str(a0);
        char* path=(char*)arena_alloc(sp->len+1);
        xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
        *out=vbool(g_host_fn[HOST_FS_EXISTS]((long)path,0,0,0)==1);
        return 1;
    }
    if(!xstrcmp(fname,"__print") || !xstrcmp(fname,"printStr")){
        if(!g_host_fn[HOST_PRINT]){ return 1; }
        const char* s=str_of_val(a0);
        u64 sl=xstrlen(s);
        g_host_fn[HOST_PRINT]((long)s,(long)sl,0,0);
        return 1;
    }
    if(!xstrcmp(fname,"__getCwd")){
        if(!g_host_fn[HOST_GET_CWD]){ *out=vundef(); return 1; }
        char* buf=(char*)arena_alloc(512);
        long n=g_host_fn[HOST_GET_CWD]((long)buf,512,0,0);
        if(n<0){ *out=vundef(); return 1; }
        *out=vstrof(mkstr(buf,(u64)n));
        return 1;
    }
    if(!xstrcmp(fname,"__exec")){
        if(!g_host_fn[HOST_EXEC]){ *out=vnum(-1); return 1; }
        char* cmd=0;
        if(a0.tag==V_STR){ Str* sp=_str(a0); cmd=(char*)arena_alloc(sp->len+1); xmemcpy(cmd,sp->data,sp->len); cmd[sp->len]=0; }
        else { cmd=(char*)str_of_val(a0); }
        char* outbuf=(char*)arena_alloc(32768);
        long rc=g_host_fn[HOST_EXEC]((long)cmd,0,(long)outbuf,32768);
        *out=vnum((double)rc);
        return 1;
    }
    if(!xstrcmp(fname,"__sleep")){
        if(!g_host_fn[HOST_SLEEP]){ *out=vundef(); return 1; }
        g_host_fn[HOST_SLEEP]((long)to_num(a0),0,0,0);
        *out=vundef(); return 1;
    }
    if(!xstrcmp(fname,"__stat")){
        if(!g_host_fn[HOST_FS_STAT]||a0.tag!=V_STR){ *out=vundef(); return 1; }
        Str* sp=_str(a0); char* path=(char*)arena_alloc(sp->len+1);
        xmemcpy(path,sp->data,sp->len); path[sp->len]=0;
        char* ob=(char*)arena_alloc(128);
        long rc=g_host_fn[HOST_FS_STAT]((long)path,(long)ob,128,0);
        if(rc<0){ *out=vundef(); return 1; }
        Box* so=(Box*)arena_alloc(sizeof(Box)); if(!so){ *out=vundef(); return 1; } so->head=0;
        u64 sz=0; int isd=0;
        { const char* p=ob; u64 v=0; while(*p>='0'&&*p<='9'){ v=v*10+(u64)(*p-'0'); p++; } sz=v; while(*p) p++; p++; isd=(*p=='1'); }
        box_set(so,"size",vnum((double)sz));
        box_set(so,"isDirectory",vbool(isd));
        *out=vobjof(so); return 1;
    }
    if(!xstrcmp(fname,"__rand")){
        *out=vnum((double)(s64)(rng_next()&0x7FFFFFFFFFFFFFFFULL)); return 1;
    }
    if(!xstrcmp(fname,"__env")){
        if(!g_host_fn[HOST_ENV]||a0.tag!=V_STR){ *out=vundef(); return 1; }
        Str* sp=_str(a0); char* key=(char*)arena_alloc(sp->len+1);
        xmemcpy(key,sp->data,sp->len); key[sp->len]=0;
        char* ob=(char*)arena_alloc(4096);
        long n=g_host_fn[HOST_ENV]((long)key,(long)ob,4096,0);
        if(n<0){ *out=vundef(); return 1; }
        *out=vstrof(mkstr(ob,(u64)n)); return 1;
    }
    if(!xstrcmp(fname,"__args")){
        if(!g_host_fn[HOST_ARGS]){ *out=vundef(); return 1; }
        char* ob=(char*)arena_alloc(4096);
        long n=g_host_fn[HOST_ARGS]((long)to_num(a0),(long)ob,4096,0);
        if(n<0){ *out=vundef(); return 1; }
        *out=vstrof(mkstr(ob,(u64)n)); return 1;
    }
    if(!xstrcmp(fname,"__uname")){
        if(!g_host_fn[HOST_UNAME]){ *out=vundef(); return 1; }
        char* ob=(char*)arena_alloc(256);
        long n=g_host_fn[HOST_UNAME](0,(long)ob,256,0);
        if(n<0){ *out=vundef(); return 1; }
        *out=vstrof(mkstr(ob,(u64)n)); return 1;
    }

    /* ---------- HTTP client ---------- */
    if(!xstrcmp(fname,"httpGet") || !xstrcmp(fname,"httpsGet")){
        if(a0.tag==V_STR) call_http_get(_str(a0)->data, out);
        else *out=vundef();
        return 1;
    }

    /* ---------- Net/TLS builtins via host table ---------- */
    if(!xstrcmp(fname,"netConnect")){
        if(!g_host_fn[HOST_NET_CONN]){ *out=vnum(-1); return 1; }
        if(a0.tag!=V_STR){ *out=vnum(-1); return 1; }
        Str* sp=_str(a0);
        char* host=(char*)arena_alloc(sp->len+1);
        xmemcpy(host,sp->data,sp->len); host[sp->len]=0;
        long port=a1n? (long)to_num(a1) : 443;
        *out=vnum((double)g_host_fn[HOST_NET_CONN]((long)host,port,0,0));
        return 1;
    }
    if(!xstrcmp(fname,"netSend")){
        if(!g_host_fn[HOST_NET_SEND]){ *out=vnum(-1); return 1; }
        long sock=(long)to_num(a0);
        const char* data=""; u64 dlen=0;
        if(a1.tag==V_STR){ Str* ds=_str(a1); data=ds->data; dlen=ds->len; }
        *out=vnum((double)g_host_fn[HOST_NET_SEND](sock,(long)data,(long)dlen,0));
        return 1;
    }
    if(!xstrcmp(fname,"netRecv")){
        if(!g_host_fn[HOST_NET_RECV]){ *out=vnum(-1); return 1; }
        long sock=(long)to_num(a0);
        long cap=a1n? (long)to_num(a1) : (long)sizeof(g_fs_buf);
        if(cap>(long)sizeof(g_fs_buf)) cap=(long)sizeof(g_fs_buf);
        long n=g_host_fn[HOST_NET_RECV](sock,(long)g_fs_buf,cap,0);
        if(n<=0){ *out=vnum((double)n); return 1; }
        *out=vstrof(mkstr(g_fs_buf,(u64)n));
        return 1;
    }
    if(!xstrcmp(fname,"netClose")){
        if(!g_host_fn[HOST_NET_CLOSE]){ *out=vnum(0); return 1; }
        g_host_fn[HOST_NET_CLOSE]((long)to_num(a0),0,0,0);
        *out=vnum(0);
        return 1;
    }
    if(!xstrcmp(fname,"tlsConnect")){
        if(!g_host_fn[HOST_TLS_CONN]){ *out=vnum(-1); return 1; }
        long sock=(long)to_num(a0);
        if(a1.tag!=V_STR){ *out=vnum(-1); return 1; }
        Str* sp=_str(a1);
        char* host=(char*)arena_alloc(sp->len+1);
        xmemcpy(host,sp->data,sp->len); host[sp->len]=0;
        *out=vnum((double)g_host_fn[HOST_TLS_CONN](sock,(long)host,0,0));
        return 1;
    }
    if(!xstrcmp(fname,"tlsSend")){
        if(!g_host_fn[HOST_TLS_SEND]){ *out=vnum(-1); return 1; }
        long h=(long)to_num(a0);
        const char* data=""; u64 dlen=0;
        if(a1.tag==V_STR){ Str* ds=_str(a1); data=ds->data; dlen=ds->len; }
        *out=vnum((double)g_host_fn[HOST_TLS_SEND](h,(long)data,(long)dlen,0));
        return 1;
    }
    if(!xstrcmp(fname,"tlsRecv")){
        if(!g_host_fn[HOST_TLS_RECV]){ *out=vnum(-1); return 1; }
        long h=(long)to_num(a0);
        long cap=a1n? (long)to_num(a1) : (long)sizeof(g_fs_buf);
        if(cap>(long)sizeof(g_fs_buf)) cap=(long)sizeof(g_fs_buf);
        long n=g_host_fn[HOST_TLS_RECV](h,(long)g_fs_buf,cap,0);
        if(n<=0){ *out=vnum((double)n); return 1; }
        *out=vstrof(mkstr(g_fs_buf,(u64)n));
        return 1;
    }
    if(!xstrcmp(fname,"tlsClose")){
        if(!g_host_fn[HOST_TLS_CLOSE]){ *out=vnum(0); return 1; }
        g_host_fn[HOST_TLS_CLOSE]((long)to_num(a0),0,0,0);
        *out=vnum(0);
        return 1;
    }

    /* ---------- timers / async scheduling ---------- */
    if(!xstrcmp(fname,"setTimeout")||!xstrcmp(fname,"setInterval")||!xstrcmp(fname,"setImmediate")){
        int iv = !xstrcmp(fname,"setInterval");
        long id=timer_create(args,env,iv);
        if(id<0) return 1;
        *out=vnum((double)id);
        return 1;
    }
    if(!xstrcmp(fname,"clearTimeout")||!xstrcmp(fname,"clearInterval")){
        tmq_remove((long)to_num(a0));
        *out=vnull();
        return 1;
    }

    return 0;
}

/* ================================================================
   REQUIRE() IMPLEMENTATION — runs after evaluator, needs exec_stmt
   ================================================================ */

/* Execute source as a module: create env with module.exports/exports/require/etc. */
static Val call_require_impl(const char* id, const char* from_dir){
    if(!id || !from_dir) return vundef();

    /* 0. Builtin module (fs/path/base64/console/json): no file I/O. */
    if(is_builtin_module(id)) return builtin_module_by_name(id);

    /* 1. Resolve module path */
    const char* resolved=0;
    if(!resolve_module(id, from_dir, &resolved)){
        set_err("module not found");
        return vundef();
    }

    /* 2. Check cache by resolved path */
    ModEntry* cached=mod_cache_find(resolved);
    if(cached) return cached->exports;

    /* 3. Read source file */
    if(!g_host_fn[HOST_FS_READ]){ set_err("fs not available"); return vundef(); }
    u64 plen=xstrlen(resolved);
    char* pathbuf=(char*)arena_alloc(plen+1);
    xmemcpy(pathbuf,resolved,plen); pathbuf[plen]=0;
    long nread=g_host_fn[HOST_FS_READ]((long)pathbuf,0,(long)g_fs_buf,(long)sizeof(g_fs_buf)-1);
    if(nread<0){ set_err("cannot read module"); return vundef(); }
    g_fs_buf[nread]=0; /* null-terminate for parser */

    /* 4. Create module env with exports / module / meta */
    Env* mod_env=env_new(0);

    Box* ex_box=(Box*)arena_alloc(sizeof(Box)); if(!ex_box) return vundef();
    ex_box->head=0;
    Val exports=vobjof(ex_box);
    env_def(mod_env,"exports",exports);

    Box* mo_box=(Box*)arena_alloc(sizeof(Box)); if(!mo_box) return vundef();
    mo_box->head=0;
    Val mod_obj=vobjof(mo_box);
    box_set(mo_box,"exports",exports);
    env_def(mod_env,"module",mod_obj);

    const char* dir=path_dirname(resolved);
    env_def(mod_env,"__dirname",vstrof(mkstr(dir,xstrlen(dir))));
    env_def(mod_env,"__filename",vstrof(mkstr(resolved,plen)));

    /* 5. Execute module source (with require builtin bound to this dir) */
    clear_err();
    const char* saved_dir=g_cur_dir;
    g_cur_dir=dir;
    js_exec_in(g_fs_buf,(u64)nread,mod_env);
    g_cur_dir=saved_dir;

    /* 6. module.exports = X reassignment wins over `exports`:
       read the current module.exports property, else use env exports. */
    Val final_exports = box_get(mo_box,"exports");
    if(final_exports.tag==V_UNDEF){
        Node* ex_node=env_find(mod_env,"exports");
        final_exports = ex_node ? ex_node->val : exports;
    }

    /* 7. Cache and return */
    if(!g_oom) mod_cache_add(resolved, final_exports);
    return final_exports;
}

/* ================================================================
   SIMPLE HTTP CLIENT (HTTP/1.1 GET/POST over TCP+TLS)
   ================================================================ */

/* Helper: send all bytes via host tls/net */
static long send_all(long h, const char* data, long len){
    long sent=0;
    while(sent<len){
        long n=g_host_fn[HOST_TLS_SEND]? g_host_fn[HOST_TLS_SEND](h,(long)(data+sent),len-sent,0) : 0;
        if(n<=0) break;
        sent+=n;
    }
    return sent;
}

/* Simple HTTP GET over TLS. Returns body string (or empty on error). */
static char g_http_buf[512*1024];
static Val http_get_tls(const char* host, long port, const char* path){
    if(!g_host_fn[HOST_NET_CONN] || !g_host_fn[HOST_TLS_CONN]
       || !g_host_fn[HOST_TLS_SEND] || !g_host_fn[HOST_TLS_RECV]
       || !g_host_fn[HOST_NET_CLOSE] || !g_host_fn[HOST_TLS_CLOSE]) return vundef();

    /* TCP connect */
    char* hbuf=(char*)arena_alloc(xstrlen(host)+1);
    xmemcpy(hbuf,host,xstrlen(host)); hbuf[xstrlen(host)]=0;
    long sock=g_host_fn[HOST_NET_CONN]((long)hbuf,port,0,0);
    if(sock<0) return vundef();

    /* TLS connect */
    long tlsh=g_host_fn[HOST_TLS_CONN](sock,(long)hbuf,0,0);
    if(tlsh<0){ g_host_fn[HOST_NET_CLOSE](sock,0,0,0); return vundef(); }

    /* Build HTTP/1.1 request (bounds-checked against the stack buffer) */
    char req[2048];
    int rlen=0;
    u64 plen=xstrlen(path), hlen=xstrlen(host);
    if(plen>1024) plen=1024;
    if(hlen>512) hlen=512;
    xmemcpy(req,"GET ",4); rlen+=4;
    xmemcpy(req+rlen,path,plen); rlen+=(int)plen;
    xmemcpy(req+rlen," HTTP/1.1\r\n",11); rlen+=11;
    xmemcpy(req+rlen,"Host: ",6); rlen+=6;
    xmemcpy(req+rlen,host,hlen); rlen+=(int)hlen;
    xmemcpy(req+rlen,"\r\n",2); rlen+=2;
    xmemcpy(req+rlen,"Connection: close\r\n\r\n",20); rlen+=20;
    if(rlen>(int)sizeof(req)) rlen=(int)sizeof(req);

    send_all(tlsh, req, rlen);

    /* Read response into static buffer (no heap churn on long-running use) */
    char* resp=g_http_buf;
    const long cap=(long)sizeof(g_http_buf);
    long total=0;
    while(total<cap-1){
        long n=g_host_fn[HOST_TLS_RECV](tlsh,(long)(resp+total),1024,0);
        if(n<=0) break;
        total+=n;
    }
    resp[total]=0;

    /* Find body after CRLFCRLF */
    char* body=resp;
    long i;
    for(i=0;i<total-3;i++){
        if(resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n'){
            body=resp+i+4; break;
        }
    }
    long bodyLen=total-(long)(body-resp);

    g_host_fn[HOST_TLS_CLOSE](tlsh,0,0,0);
    g_host_fn[HOST_NET_CLOSE](sock,0,0,0);

    if(bodyLen<0) bodyLen=0;
    return vstrof(mkstr(body,(u64)bodyLen));
}

/* JS: httpGet(url) → response string */
static int call_http_get(const char* url, Val* out){
    if(!url) return 0;
    const char* p=url;
    int https=0;
    /* Parse scheme (prefix match, bounded by string) */
    if(p[0]=='h'&&p[1]=='t'&&p[2]=='t'&&p[3]=='p'&&p[4]==':'&&p[5]=='/'&&p[6]=='/'){
        p+=7;
    } else if(p[0]=='h'&&p[1]=='t'&&p[2]=='t'&&p[3]=='p'&&p[4]=='s'&&p[5]==':'&&p[6]=='/'&&p[7]=='/'){
        https=1; p+=8;
    } else return 0;

    /* Parse host */
    const char* hstart=p;
    while(*p && *p!=':' && *p!='/') p++;
    long hostlen=p-hstart;
    if(hostlen<=0) return 0;
    char* host=(char*)arena_alloc((u64)(hostlen+1));
    if(!host) return 0;
    xmemcpy(host,hstart,(u64)hostlen); host[hostlen]=0;

    /* Parse port */
    long port=https?443:80;
    if(*p==':'){
        p++; port=0;
        while(*p>='0'&&*p<='9'){ port=port*10+(*p-'0'); p++; }
        if(port<=0) port=https?443:80;
    }

    /* Parse path (rest of the string) */
    const char* path = (*p=='/') ? p : "/";

    *out = http_get_tls(host, port, path);
    return 1;
}

/* built-in method dispatch: base.method(args). Returns vundef for unknowns. */
static Val call_method_v(Val base, const char* name, Node* args, Env* env){
    Node* a0n = args? args->a : 0;
    Node* a1n = a0n? a0n->next : 0;
    Val a0 = a0n? eval(a0n,env) : vundef();
    Val a1 = a1n? eval(a1n,env) : vundef();
    if(!name) return vundef();
    if(base.tag==V_ARR){
        Box* b=_box(base);
        if(!xstrcmp(name,"push")){ box_append(b,a0); return vnum((double)box_len(b)); }
        if(!xstrcmp(name,"pop")) return box_pop(b);
        if(!xstrcmp(name,"shift")) return box_shift(b);
        if(!xstrcmp(name,"unshift")){ box_unshift(b,a0); return vnum((double)box_len(b)); }
        if(!xstrcmp(name,"indexOf")){
            int idx=-1; int i=0;
            for(Node* e=b->head;e;e=e->next,i++) if(eq_strict(e->val,a0)){ idx=i; break; }
            return vnum((double)idx);
        }
        if(!xstrcmp(name,"join")){
            const char* sep = a0n? (a0.tag==V_STR? _str(a0)->data : str_of_val(a0)) : ",";
            u64 sl=(a0n&&a0.tag==V_STR)? _str(a0)->len : a0n? xstrlen(sep) : 1;
            return js_arr_join_str(b,sep,sl);
        }
        if(!xstrcmp(name,"slice")){
            long n=(long)box_len(b);
            long st=(long)to_num(a0);
            long en=a1n? (long)to_num(a1) : n;
            if(st<0){ st=n+st; if(st<0)st=0; } else if(st>n) st=n;
            if(en<0){ en=n+en; if(en<0)en=0; } else if(en>n) en=n;
            if(en<st) en=st;
            Box* nb=(Box*)arena_alloc(sizeof(Box)); if(!nb) return vundef();
            nb->head=0;
            int i=0;
            for(Node* e=b->head; e && i<en; e=e->next,i++) if(i>=st) box_append(nb,e->val);
            return varrb(nb);
        }
        if(!xstrcmp(name,"reverse")){
            Node* prev=0; Node* cur=b->head;
            while(cur){ Node* nx=cur->next; cur->next=prev; prev=cur; cur=nx; }
            b->head=prev;
            return base;
        }
        if(!xstrcmp(name,"concat")){
            Box* nb=(Box*)arena_alloc(sizeof(Box)); if(!nb) return vundef();
            nb->head=0;
            for(Node* e=b->head;e;e=e->next) box_append(nb,e->val);
            for(Node* p=args?args->a:0; p; p=p->next){
                Val v=eval(p,env);
                if(v.tag==V_ARR){ for(Node* e=_box(v)->head;e;e=e->next) box_append(nb,e->val); }
                else box_append(nb,v);
            }
            return varrb(nb);
        }
        if(!xstrcmp(name,"includes")){
            for(Node* e=b->head;e;e=e->next) if(eq_strict(e->val,a0)) return vbool(1);
            return vbool(0);
        }
        if(!xstrcmp(name,"forEach")||!xstrcmp(name,"map")||!xstrcmp(name,"filter")){
            int mode = !xstrcmp(name,"forEach")?0:(!xstrcmp(name,"map")?1:2);
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            Box* out=0;
            if(mode){ out=(Box*)arena_alloc(sizeof(Box)); if(!out) return vundef(); out->head=0; }
            int idx=0;
            for(Node* e=b->head; e; e=e->next, idx++){
                Node* argl=mkn(NK_LIST); if(!argl) return vundef();
                Node* arg0=mkn(NK_STR); if(!arg0) return vundef();
                arg0->val=e->val;
                Node* arg1=mkn(NK_STR); if(!arg1) return vundef();
                argl->a=arg0; arg0->next=arg1; arg1->val=vnum((double)idx);
                Val r=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
                if(mode==1) box_append(out,r);
                else if(mode==2 && to_bool(r)) box_append(out,e->val);
            }
            return mode? varrb(out) : vundef();
        }
        if(!xstrcmp(name,"find")||!xstrcmp(name,"findIndex")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            int getidx = !xstrcmp(name,"findIndex");
            int idx=0;
            for(Node* e=b->head; e; e=e->next, idx++){
                Node* argl=mkn(NK_LIST); if(!argl) return vundef();
                Node* arg0=mkn(NK_STR); if(!arg0) return vundef();
                arg0->val=e->val;
                Node* arg1=mkn(NK_STR); if(!arg1) return vundef();
                argl->a=arg0; arg0->next=arg1; arg1->val=vnum((double)idx);
                Val r=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
                if(to_bool(r)) return getidx? vnum((double)idx) : e->val;
            }
            return getidx? vnum(-1.0) : vundef();
        }
        if(!xstrcmp(name,"some")||!xstrcmp(name,"every")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            int every = !xstrcmp(name,"every");
            int idx=0;
            for(Node* e=b->head; e; e=e->next, idx++){
                Node* argl=mkn(NK_LIST); if(!argl) return vundef();
                Node* arg0=mkn(NK_STR); if(!arg0) return vundef();
                arg0->val=e->val;
                Node* arg1=mkn(NK_STR); if(!arg1) return vundef();
                argl->a=arg0; arg0->next=arg1; arg1->val=vnum((double)idx);
                Val r=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
                if(to_bool(r)){
                    if(!every) return vbool(1);
                } else if(every) return vbool(0);
            }
            return vbool(every);
        }
        if(!xstrcmp(name,"reduce")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            Node* e=b->head;
            Val acc;
            if(a1n) acc=a1;
            else if(e){ acc=e->val; e=e->next; }
            else return vundef();
            for(; e; e=e->next){
                Node* argl=mkn(NK_LIST); if(!argl) return vundef();
                Node* arg0=mkn(NK_STR); if(!arg0) return vundef();
                Node* arg1=mkn(NK_STR); if(!arg1) return vundef();
                argl->a=arg0; arg0->next=arg1;
                arg0->val=acc; arg1->val=e->val;
                acc=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
            }
            return acc;
        }
        if(!xstrcmp(name,"splice")){
            long n=(long)box_len(b);
            long st=(long)to_num(a0); if(st<0){ st=n+st; if(st<0)st=0; } else if(st>n) st=n;
            long dc;
            if(!a1n) dc=n-st;
            else { dc=(long)to_num(a1); if(dc<0)dc=0; if(st+dc>n) dc=n-st; }
            Box* removed=(Box*)arena_alloc(sizeof(Box)); if(!removed) return vundef(); removed->head=0;
            Node* e=b->head; int i=0;
            while(e && i<st){ e=e->next; i++; }
            Node* del_start=e;
            while(e && i<st+dc){ Node* nx=e->next; box_append(removed,e->val); e=nx; i++; }
            Node* after=e;
            if(del_start==b->head) b->head=after;
            else { Node* prev=b->head; while(prev && prev->next!=del_start) prev=prev->next; if(prev) prev->next=after; }
            Node* ins=0, *ins_tail=0;
            for(Node* p=a1n?a1n->next:0; p; p=p->next){ Node* nn=mk_box_node(eval(p,env)); if(!nn) continue;
                if(!ins){ ins=nn; ins_tail=nn; } else { ins_tail->next=nn; ins_tail=nn; } }
            if(ins){ ins_tail->next=after;
                if(st==0) b->head=ins;
                else { Node* prev=b->head; int j=0; while(prev && j<st-1){ prev=prev->next; j++; } if(prev) prev->next=ins; }
            }
            return varrb(removed);
        }
        if(!xstrcmp(name,"sort")){
            js_sort_box(b,a0,env);
            if(g_had_error) return vundef();
            return base;
        }
        if(!xstrcmp(name,"keys")||!xstrcmp(name,"values")||!xstrcmp(name,"entries")){
            int mode=!xstrcmp(name,"keys")?0:(!xstrcmp(name,"values")?1:2);
            Box* nb=(Box*)arena_alloc(sizeof(Box)); if(!nb) return vundef(); nb->head=0;
            int idx=0;
            for(Node* e=b->head;e;e=e->next,idx++){
                if(mode==0) box_append(nb,vnum((double)idx));
                else if(mode==1) box_append(nb,e->val);
                else { Box* kv=(Box*)arena_alloc(sizeof(Box)); if(!kv) continue; kv->head=0;
                    box_append(kv,vnum((double)idx)); box_append(kv,e->val); box_append(nb,varrb(kv)); }
            }
            return varrb(nb);
        }
        /* ---- modern-JS array methods ---- */
        if(!xstrcmp(name,"lastIndexOf")){
            long n=(long)box_len(b);
            long from=a1n? (long)to_num(a1) : n-1;
            if(from<0){ from+=n; if(from<0) from=-1; } else if(from>=n) from=n-1;
            long i=0; int idx=-1;
            for(Node* q=b->head;q;q=q->next,i++) if(i<=from && eq_strict(q->val,a0)) idx=(int)i;
            return vnum((double)idx);
        }
        if(!xstrcmp(name,"at")){
            long n=(long)box_len(b);
            long i=(long)to_num(a0);
            if(i<0) i+=n;
            if(i<0||i>=n) return vundef();
            return box_get_idx(b,(int)i);
        }
        if(!xstrcmp(name,"fill")){
            Node* a2n=a1n? a1n->next : 0;
            Val a2=a2n? eval(a2n,env) : vundef();
            long n=(long)box_len(b);
            long st=a1n? (long)to_num(a1) : 0;
            long en=a2n? (long)to_num(a2) : n;
            if(st<0){ st+=n; if(st<0) st=0; } else if(st>n) st=n;
            if(en<0){ en+=n; if(en<0) en=0; } else if(en>n) en=n;
            if(en<st) en=st;
            long idx=0;
            for(Node* q=b->head;q;q=q->next,idx++) if(idx>=st && idx<en) q->val=a0;
            return base;
        }
        if(!xstrcmp(name,"flat")){
            long depth=a0n? (long)to_num(a0) : 1;
            if(depth<0) depth=0; if(depth>64) depth=64;
            Box* nb=new_box(); if(!nb) return vundef();
            js_arr_flatten_into(b,(int)depth,nb);
            return varrb(nb);
        }
        if(!xstrcmp(name,"flatMap")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            Box* mapped=new_box(); if(!mapped) return vundef();
            int idx=0;
            for(Node* e=b->head;e;e=e->next,idx++){
                Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                if(!argl||!an0||!an1) return vundef();
                argl->a=an0; an0->next=an1; an0->val=e->val; an1->val=vnum((double)idx);
                Val r=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
                if(r.tag==V_ARR){ for(Node* q=_box(r)->head;q;q=q->next) box_append(mapped,q->val); }
                else box_append(mapped,r);
            }
            return varrb(mapped);
        }
        if(!xstrcmp(name,"reduceRight")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            Box* rev=new_box(); if(!rev) return vundef();
            Node* cur=b->head; Node* top=0;
            while(cur){ Node* nn=mk_box_node(cur->val); if(!nn) return vundef(); nn->next=top; top=nn; cur=cur->next; }
            rev->head=top;
            Node* e=rev->head;
            Val acc;
            if(a1n) acc=a1;
            else if(e){ acc=e->val; e=e->next; }
            else return vundef();
            for(; e; e=e->next){
                Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                if(!argl||!an0||!an1) return vundef();
                argl->a=an0; an0->next=an1; an0->val=acc; an1->val=e->val;
                acc=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
            }
            return acc;
        }
        if(!xstrcmp(name,"findLast")||!xstrcmp(name,"findLastIndex")){
            if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
            int getidx=!xstrcmp(name,"findLastIndex");
            long n=(long)box_len(b);
            for(long i=n-1;i>=0;i--){
                Val v=arr_value_at(b,i);
                Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                if(!argl||!an0||!an1) return vundef();
                argl->a=an0; an0->next=an1; an0->val=v; an1->val=vnum((double)i);
                Val r=call_func(a0,argl,env,vundef());
                if(g_had_error) return vundef();
                if(to_bool(r)) return getidx? vnum((double)i) : v;
            }
            return getidx? vnum(-1.0) : vundef();
        }
        if(!xstrcmp(name,"copyWithin")){
            Node* a2n=a1n? a1n->next : 0;
            Val a2=a2n? eval(a2n,env) : vundef();
            long n=(long)box_len(b);
            long t=(long)to_num(a0); if(t<0){ t+=n; if(t<0)t=0; } else if(t>n) t=n;
            long st=a1n? (long)to_num(a1) : 0; if(st<0){ st+=n; if(st<0)st=0; } else if(st>n) st=n;
            long en=a2n? (long)to_num(a2) : n; if(en<0){ en+=n; if(en<0)en=0; } else if(en>n) en=n;
            if(en<st) en=st;
            long len=en-st;
            long avail=n-t; if(avail<len) len=avail;
            if(len<0) len=0;
            Val* tmp=(Val*)arena_alloc(sizeof(Val)*(u64)len+1);
            if(!tmp) return vundef();
            for(long i=0;i<len;i++) tmp[i]=arr_value_at(b,st+i);
            for(long i=0;i<len;i++) arr_set_idx(b,(int)(t+i),tmp[i]);
            return base;
        }
        if(!xstrcmp(name,"toReversed")){
            Box* nb=new_box(); if(!nb) return vundef();
            Node* cur=b->head; Node* top=0;
            while(cur){ Node* nn=mk_box_node(cur->val); if(!nn) return vundef(); nn->next=top; top=nn; cur=cur->next; }
            nb->head=top;
            return varrb(nb);
        }
        if(!xstrcmp(name,"toSorted")){
            Box* nb=js_arr_clone(b); if(!nb) return vundef();
            js_sort_box(nb,a0,env);
            if(g_had_error) return vundef();
            return varrb(nb);
        }
        if(!xstrcmp(name,"toSpliced")){
            long n=(long)box_len(b);
            long st=a0n? (long)to_num(a0) : 0;
            if(st<0){ st+=n; if(st<0)st=0; } else if(st>n) st=n;
            long dc;
            if(!a1n) dc=n-st;
            else { dc=(long)to_num(a1); if(dc<0)dc=0; if(st+dc>n) dc=n-st; }
            Box* nb=new_box(); if(!nb) return vundef();
            for(long i=0;i<st;i++) box_append(nb,arr_value_at(b,i));
            for(Node* p=a1n? a1n->next : 0; p; p=p->next) box_append(nb,eval(p,env));
            for(long i=st+dc;i<n;i++) box_append(nb,arr_value_at(b,i));
            return varrb(nb);
        }
        if(!xstrcmp(name,"with")){
            long n=(long)box_len(b);
            long i=a0n? (long)to_num(a0) : 0;
            if(i<0) i+=n;
            if(i<0||i>=n){ set_err("RangeError: index out of range"); return vundef(); }
            Val nv=a1n? eval(a1n,env) : vundef();
            Box* nb=js_arr_clone(b); if(!nb) return vundef();
            arr_set_idx(nb,(int)i,nv);
            return varrb(nb);
        }
        if(!xstrcmp(name,"toString")||!xstrcmp(name,"valueOf")||!xstrcmp(name,"toLocaleString")){
            if(!xstrcmp(name,"valueOf")) return base;
            return js_arr_join_str(b,",",1);
        }
        return vundef();
    }
    if(base.tag==V_STR){
        Str* s=_str(base);
        if(!xstrcmp(name,"substring")){
            long st=(long)to_num(a0), en;
            if(!a1n) en=(long)s->len;
            else { en=(long)to_num(a1); if(en<0)en=0; if(en>(long)s->len)en=(long)s->len; }
            if(st<0) st=0; if(st>(long)s->len) st=(long)s->len;
            if(st>en){ long t=st; st=en; en=t; }
            u64 n=(u64)(en-st);
            char* buf=(char*)arena_alloc(n+1); if(!buf) return vundef();
            xmemcpy(buf, s->data+st, n); buf[n]=0;
            return vstrof(mkstr(buf,n));
        }
        if(!xstrcmp(name,"charAt")){
            long i=(long)to_num(a0);
            if(i<0||i>=(long)s->len) return vstrof(mkstr("",0));
            char ch=s->data[i];
            return vstrof(mkstr(&ch,1));
        }
        if(!xstrcmp(name,"indexOf")){
            if(!a0n || a0.tag!=V_STR){ if(!a0n) return vnum(0); return vnum(-1); }
            long from = a1n? (long)to_num(a1) : 0;
            return vnum((double)str_find(s,_str(a0),from));
        }
        if(!xstrcmp(name,"lastIndexOf")){
            if(!a0n || a0.tag!=V_STR){ if(!a0n) return vnum(0); return vnum(-1); }
            Str* ndl=_str(a0);
            long n=(long)s->len, m=(long)ndl->len;
            long from = a1n? (long)to_num(a1) : -1;
            if(from<0 || from>n) from=n;
            if(m==0) return vnum((double)from);
            if(from > n-m) from=n-m;
            for(long i=from; i>=0; i--){
                int eq=1;
                for(long k=0;k<m;k++) if(s->data[i+k]!=ndl->data[k]){ eq=0; break; }
                if(eq) return vnum((double)i);
            }
            return vnum(-1.0);
        }
        if(!xstrcmp(name,"padStart")||!xstrcmp(name,"padEnd")){
            int isend = !xstrcmp(name,"padEnd");
            long tgt=(long)to_num(a0); if(tgt<0) tgt=0;
            if(tgt<=(long)s->len) return base;
            const char* pad = a1n&&a1.tag==V_STR? _str(a1)->data : " ";
            u64 plen = a1n&&a1.tag==V_STR? _str(a1)->len : 1;
            u64 blen=(u64)tgt;
            if(blen>(1u<<24)) return vundef();
            char* buf=(char*)arena_alloc(blen+1); if(!buf) return vundef();
            if(!isend){
                u64 o=0, need=blen-s->len;
                while(o<need){ u64 k=need-o<plen? need-o:plen; xmemcpy(buf+o,pad,k); o+=k; }
                xmemcpy(buf+o,s->data,s->len);
            } else {
                xmemcpy(buf,s->data,s->len);
                u64 o=s->len;
                while(o<blen){ u64 k=blen-o<plen? blen-o:plen; xmemcpy(buf+o,pad,k); o+=k; }
            }
            buf[blen]=0;
            return vstrof(mkstr(buf,blen));
        }
        if(!xstrcmp(name,"slice")) return js_str_slice(s,a0,a1n!=0,a1);
        if(!xstrcmp(name,"substr")) return js_str_substr(s,a0,a1n!=0,a1);
        if(!xstrcmp(name,"toUpperCase")){ Str* r=str_map_case(s,1); return r? vstrof(r) : vundef(); }
        if(!xstrcmp(name,"toLowerCase")){ Str* r=str_map_case(s,0); return r? vstrof(r) : vundef(); }
        if(!xstrcmp(name,"split")){
            if(rg_is(a0)){
                Box* rb=_box(a0);
                Val pv=rg_pattern(rb), fv=rg_flags_v(rb);
                const char* pd=_str(pv)->data; u64 pl=_str(pv)->len;
                const char* fd=_str(fv)->data; u64 fll=_str(fv)->len;
                long limit = a1n? (long)to_num(a1) : 999999999L;
                if(limit<0) limit=0;
                Box* out=new_box(); if(!out) return vundef();
                int cursor=0;
                for(int it=0;it<100000 && (long)box_len(out)<limit;it++){
                    if(cursor>=(int)s->len) break;
                    int ep=0;
                    int idx=rg_match_from(pd,pl,fd,fll,s->data,s->len,cursor,&ep);
                    if(idx==-2){ set_err("invalid regular expression"); return vundef(); }
                    if(idx<0 || idx>=(int)s->len) break;
                    box_append(out,vstrof(mkstr(s->data+cursor,(u64)(idx-cursor))));
                    cursor = (ep>idx)? ep : idx+1;
                }
                if((long)box_len(out)<limit && cursor<=(int)s->len)
                    box_append(out,vstrof(mkstr(s->data+cursor,s->len-(u64)cursor)));
                return varrb(out);
            }
            return js_str_split(s,a0n!=0,a0);
        }
        if(!xstrcmp(name,"trim")){
            u64 i=0; while(i<s->len && (s->data[i]==' '||s->data[i]=='\n'||s->data[i]=='\t'||s->data[i]=='\r')) i++;
            u64 j=s->len; while(j>i && (s->data[j-1]==' '||s->data[j-1]=='\n'||s->data[j-1]=='\t'||s->data[j-1]=='\r')) j--;
            return vstrof(mkstr(s->data+i,j-i));
        }
        if(!xstrcmp(name,"startsWith")||!xstrcmp(name,"endsWith")||!xstrcmp(name,"includes")){
            if(a0.tag!=V_STR) return vbool(0);
            Str* p=_str(a0);
            if(!xstrcmp(name,"startsWith")){
                if(p->len>s->len) return vbool(0);
                return vbool(mem_eq(s->data,p->data,p->len));
            }
            if(!xstrcmp(name,"endsWith")){
                if(p->len>s->len) return vbool(0);
                return vbool(mem_eq(s->data+s->len-p->len,p->data,p->len));
            }
            return vbool(str_find(s,p,0)>=0);
        }
        if(!xstrcmp(name,"repeat")){
            long n=(long)to_num(a0);
            if(n<=0) return vstrof(mkstr("",0));
            u64 tl=s->len*(u64)n;
            if(tl > (1u<<24)) return vstrof(mkstr("",0));
            char* buf=(char*)arena_alloc(tl+1); if(!buf) return vundef();
            for(u64 i=0;i<(u64)n;i++) xmemcpy(buf+i*s->len,s->data,s->len);
            buf[tl]=0;
            return vstrof(mkstr(buf,tl));
        }
        if(!xstrcmp(name,"charCodeAt")){
            long i=(long)to_num(a0);
            if(i<0||i>=(long)s->len) return vnum(0.0/0.0);
            return vnum((double)((unsigned char)s->data[i]));
        }
        if(!xstrcmp(name,"at")){
            long n=(long)s->len;
            long i=(long)to_num(a0);
            if(i<0) i+=n;
            if(i<0||i>=n) return vundef();
            char ch=s->data[i]; return vstrof(mkstr(&ch,1));
        }
        if(!xstrcmp(name,"trimStart")||!xstrcmp(name,"trimLeft")){
            u64 i=0; while(i<s->len && (s->data[i]==' '||s->data[i]=='\n'||s->data[i]=='\t'||s->data[i]=='\r')) i++;
            return vstrof(mkstr(s->data+i,s->len-i));
        }
        if(!xstrcmp(name,"trimEnd")||!xstrcmp(name,"trimRight")){
            u64 j=s->len; while(j>0 && (s->data[j-1]==' '||s->data[j-1]=='\n'||s->data[j-1]=='\t'||s->data[j-1]=='\r')) j--;
            return vstrof(mkstr(s->data,j));
        }
        if(!xstrcmp(name,"concat")){
            u64 tl=s->len;
            int argsc=0;
            for(Node* p=args?args->a:0;p;p=p->next){ tl+=xstrlen(str_of_val(eval(p,env))); argsc++; }
            if(tl>(1u<<24)) return vundef();
            char* buf=(char*)arena_alloc(tl+1); if(!buf) return vundef();
            u64 o=0; xmemcpy(buf+o,s->data,s->len); o+=s->len;
            for(Node* p=args?args->a:0;p;p=p->next){
                const char* s2=str_of_val(eval(p,env)); u64 l2=xstrlen(s2);
                xmemcpy(buf+o,s2,l2); o+=l2;
            }
            buf[o]=0;
            return vstrof(mkstr(buf,o));
        }
        if(!xstrcmp(name,"replace")||!xstrcmp(name,"replaceAll")){
            if(rg_is(a0)){
                Box* rb=_box(a0);
                Val pv=rg_pattern(rb), fv=rg_flags_v(rb);
                const char* pd=_str(pv)->data; u64 pl=_str(pv)->len;
                const char* fd=_str(fv)->data; u64 fll=_str(fv)->len;
                int fx=rg_flags_int(fd,fll);
                int global = (fx&RG_G) || !xstrcmp(name,"replaceAll");
                Val rpl=a1n? a1 : vstrof(mkstr("",0));
                int isfunc=rpl.tag==V_FUNC;
                const char* rs= isfunc? "" : str_of_val(rpl);
                u64 rl= isfunc? 0 : xstrlen(rs);
                u64 cap=s->len*6+128; if(cap>(1u<<24))cap=(1u<<24);
                char* buf=(char*)arena_alloc(cap+1); if(!buf) return vundef();
                u64 o=0; int cursor=0; int first=1;
                for(int it=0; it<100000; it++){
                    if(!global&&!first) break;
                    first=0;
                    int ep=0, idx;
                    if(global) idx=rg_match_from(pd,pl,fd,fll,s->data,s->len,cursor,&ep);
                    else idx=rg_match_src(pd,pl,fd,fll,s->data,s->len,&ep);
                    if(idx==-2){ set_err("invalid regular expression"); return vundef(); }
                    if(idx<0) break;
                    for(int k=cursor;k<idx&&o+1<cap;k++) buf[o++]=s->data[k];
                    if(isfunc){
                        Node* argl=mkn(NK_LIST); if(!argl) return vundef();
                        Node** tail=&argl->a;
                        int ng2=rg_groups; if(ng2>15)ng2=15;
                        for(int i=0;i<=ng2;i++){
                            Node* an=mkn(NK_STR); if(!an) break;
                            if(i==0) an->val=vstrof(mkstr(s->data+idx,(u64)(ep-idx)));
                            else if(rgs_out[(i-1)*2]>=0&&rgs_out[(i-1)*2+1]>=rgs_out[(i-1)*2])
                                an->val=vstrof(mkstr(s->data+rgs_out[(i-1)*2],(u64)(rgs_out[(i-1)*2+1]-rgs_out[(i-1)*2])));
                            else an->val=vundef();
                            *tail=an; tail=&an->next;
                        }
                        Node* an=mkn(NK_NUM); if(an){ an->val=vnum((double)idx); *tail=an; tail=&an->next; }
                        Node* as2=mkn(NK_STR); if(as2){ as2->val=vstrof(mkstr(s->data,s->len)); *tail=as2; tail=&as2->next; }
                        Val rr=isfunc? call_func(rpl,argl,env,base) : vundef();
                        const char* r2=str_of_val(rr); u64 r2l=xstrlen(r2);
                        for(u64 k2=0;k2<r2l&&o+1<cap;k2++) buf[o++]=r2[k2];
                    } else {
                        u64 w=rg_expand_repl(buf+o,cap>o?cap-o:1,rs,rl,s->data,idx,ep,rgs_out,rg_groups);
                        o+=w;
                    }
                    cursor = (ep>idx)? ep : idx+1;
                    if(cursor>(int)s->len) break;
                }
                for(int k=cursor;k<(int)s->len&&o+1<cap;k++) buf[o++]=s->data[k];
                buf[o]=0;
                return vstrof(mkstr(buf,o));
            }
            if(a0.tag!=V_STR) return base;
            Str* ndl=_str(a0);
            if(ndl->len==0){
                /* empty pattern: replace at each char boundary */
                Val rpl=a1n? a1 : vstrof(mkstr("",0));
                if(rpl.tag==V_FUNC) return base; /* function repl with empty pattern is rare; keep original */
                const char* rs=str_of_val(rpl); u64 rl=xstrlen(rs);
                u64 cap=s->len*(rl+1)+8; if(cap>(1u<<24)) cap=(1u<<24);
                char* buf=(char*)arena_alloc(cap+1); if(!buf) return vundef();
                u64 o=0;
                if(!xstrcmp(name,"replaceAll")){
                    for(u64 i=0;i<=s->len;i++){ if(o+rl<cap){ xmemcpy(buf+o,rs,rl); o+=rl; } if(i<s->len) buf[o++]=s->data[i]; }
                } else {
                    if(o+rl<cap){ xmemcpy(buf+o,rs,rl); o+=rl; }
                    for(u64 i=0;i<s->len;i++) buf[o++]=s->data[i];
                }
                buf[o]=0;
                return vstrof(mkstr(buf,o));
            }
            Val rpl=a1n? a1 : vstrof(mkstr("",0));
            return js_str_replace_helper(s,ndl,rpl,env, !xstrcmp(name,"replaceAll"));
        }
        if(!xstrcmp(name,"match")){
            if(rg_is(a0)){
                Box* rb=_box(a0);
                Val pv=rg_pattern(rb), fv=rg_flags_v(rb);
                const char* pd=_str(pv)->data; u64 pl=_str(pv)->len;
                const char* fd=_str(fv)->data; u64 fll=_str(fv)->len;
                if(rg_flags_int(fd,fll)&RG_G){
                    Box* out=new_box(); if(!out) return vnull();
                    int cursor=0;
                    for(int it=0;it<100000;it++){
                        int ep=0;
                        int idx=rg_match_from(pd,pl,fd,fll,s->data,s->len,cursor,&ep);
                        if(idx==-2){ set_err("invalid regular expression"); return vnull(); }
                        if(idx<0) break;
                        box_append(out,vstrof(mkstr(s->data+idx,(u64)(ep-idx))));
                        cursor = (ep>idx)? ep : idx+1;
                        if(cursor>(int)s->len) break;
                    }
                    if(out->head==0) return vnull();
                    return varrb(out);
                }
                int ep=0;
                int idx=rg_match_src(pd,pl,fd,fll,s->data,s->len,&ep);
                if(idx==-2){ set_err("invalid regular expression"); return vnull(); }
                if(idx<0) return vnull();
                return rg_exec_array(s->data,s->len,idx,ep);
            }
            if(a0.tag!=V_STR) return vnull();
            Str* ndl=_str(a0);
            long at=str_find(s,ndl,0);
            if(at<0) return vnull();
            Box* out=new_box(); if(!out) return vnull();
            if(ndl->len==0){ box_append(out,vstrof(mkstr("",0))); return varrb(out); }
            box_append(out,vstrof(mkstr(s->data+at,ndl->len)));
            return varrb(out);
        }
        if(!xstrcmp(name,"search")){
            if(rg_is(a0)){
                Box* rb=_box(a0);
                Val pv=rg_pattern(rb), fv=rg_flags_v(rb);
                int ep=0;
                int idx=rg_match_src(_str(pv)->data,_str(pv)->len,_str(fv)->data,_str(fv)->len,s->data,s->len,&ep);
                if(idx==-2){ set_err("invalid regular expression"); return vnum(-1.0); }
                return vnum(idx<0?-1.0:(double)idx);
            }
            if(a0.tag!=V_STR) return vnum(-1.0);
            return vnum((double)str_find(s,_str(a0),0));
        }
        if(!xstrcmp(name,"codePointAt")){
            long i=(long)to_num(a0);
            if(i<0||i>=(long)s->len) return vundef();
            u64 adv=0; u32 cp=utf8_decode_cp(s->data+i,s->len-(u64)i,&adv);
            return vnum((double)cp);
        }
        if(!xstrcmp(name,"localeCompare")){
            const char* other = a0n? str_of_val(a0) : "";
            int c=xstrcmp(s->data,other);
            return vnum(c<0?-1.0:(c>0?1.0:0.0));
        }
        if(!xstrcmp(name,"valueOf")||!xstrcmp(name,"toString")) return base;
        return vundef();
    }
    if(base.tag==V_NUM){
        if(!xstrcmp(name,"toFixed")){
            int places= a0n? (int)to_num(a0) : 0;
            if(places<0) places=0; if(places>18) places=18;  /* s64-safe */
            double v=base.num;
            if(v!=v) return vstrof(mkstr("NaN",3));
            if(v==(double)(1.0/0.0)) return vstrof(mkstr("Infinity",8));
            if(v==(double)(-1.0/0.0)) return vstrof(mkstr("-Infinity",9));
            int neg=0; if(v<0){ neg=1; v=-v; }
            if(v > 9.0e18) return vstrof(mkstr(neg?"9e+18":"1e+19",5));
            s64 scale=1; for(int i=0;i<places;i++) scale*=10;
            s64 total=(s64)(v*(double)scale + 0.5 + 1e-9);   /* epsilon defuses binary-approx into decimal rounding */
            s64 ip=total/scale, frac=total%scale;
            char tmp[48]; int k=0;
            if(ip==0) tmp[k++]='0';
            else { s64 t=ip; while(t>0){ tmp[k++]='0'+(int)(t%10); t/=10; } }
            u64 ol=(u64)neg+k+(places?1+places:0)+1;
            char* out=(char*)arena_alloc(ol); int o=0;
            if(neg) out[o++]='-';
            while(k>0) out[o++]=tmp[--k];
            if(places>0){
                out[o++]='.';
                s64 m=1; for(int i=1;i<places;i++) m*=10;   /* 10^(places-1) */
                for(int i=0;i<places;i++){ s64 d=frac/m; out[o++]='0'+(int)d; frac-=d*m; m/=10; }
            }
            out[o]=0;
            return vstrof(mkstr(out,o));
        }
        if(!xstrcmp(name,"toString")){
            int radix= a0n? (int)to_num(a0) : 10;
            if(radix<2||radix>36) return vstrof(mkstr("NaN",3));
            double v=base.num;
            if(v!=v) return vstrof(mkstr("NaN",3));
            if(v==(double)(1.0/0.0)) return vstrof(mkstr("Infinity",8));
            if(v==(double)(-1.0/0.0)) return vstrof(mkstr("-Infinity",9));
            int neg=0; if(v<0){ neg=1; v=-v; }
            s64 ip=(s64)v;
            char tmp[64]; int k=0;
            if(ip==0) tmp[k++]='0';
            else { s64 t=ip; while(t>0){ int d=(int)(t%radix); tmp[k++]=d<10?'0'+d:'a'+d-10; t/=radix; } }
            u64 ol=(u64)neg+k+1;
            char* out=(char*)arena_alloc(ol); int o=0;
            if(neg) out[o++]='-';
            while(k>0) out[o++]=tmp[--k];
            out[o]=0;
            return vstrof(mkstr(out,o));
        }
        if(!xstrcmp(name,"toExponential")){
            double v=base.num;
            if(v!=v) return vstrof(mkstr("NaN",3));
            if(v==(double)(1.0/0.0)) return vstrof(mkstr("Infinity",8));
            if(v==(double)(-1.0/0.0)) return vstrof(mkstr("-Infinity",9));
            int neg=0; if(v<0){ neg=1; v=-v; }
            int dp=a0n? (int)to_num(a0) : -2;      /* -2 = default ("as needed") */
            if(dp<-2) dp=-2; if(dp>20) dp=20;
            char* out=(char*)arena_alloc(96); if(!out) return vundef();
            int o=0;
            if(v==0){
                if(neg) out[o++]='-';
                out[o++]='0';
                int nd=dp>0?dp:0;
                if(nd>0){ out[o++]='.'; for(int i=0;i<nd;i++) out[o++]='0'; }
            } else {
                long e=0; double m=v;
                if(m>=1.0){ while(m>=10.0){ m/=10.0; e++; } }
                else { while(m<1.0 && e>-400){ m*=10.0; e--; } }
                int nd = dp>=0? dp : 14;             /* cap: default 14 sig digits */
                double sc=1; for(int i=0;i<nd;i++) sc*=10;
                s64 total=(s64)(m*sc + 0.5 + 1e-9);
                if(total>= (s64)(sc*10)){ total/=10; e++; }
/* strip trailing zeros (for default mode) or keep exactly dp decimals */
                int sig=nd+1;
                if(dp<0){
                    while(sig>1 && (total%10)==0){ total/=10; sig--; sc/=10; }
                }
                if(neg) out[o++]='-';
                s64 p=sc;
                for(int k=0;k<sig;k++){
                    int d=(int)(total/p); if(d<0)d=0; if(d>9)d=9;
                    out[o++]='0'+d; total-=d*p; p/=10;
                    if(k==0 && sig>1) out[o++]='.';
                }
            }
            /* exponent */
            {
                long e=(v==0)?0:0;
                if(v!=0){ double m=v; long ee=0; if(m>=1.0){ while(m>=10.0){ m/=10.0; ee++; } } else { while(m<1.0){ m*=10.0; ee--; } } e=ee; }
                char et[10]; int ek=0; long ae=e<0?-e:e;
                if(ae==0) et[ek++]='0';
                while(ae>0){ et[ek++]='0'+(int)(ae%10); ae/=10; }
                while(ek==0) et[ek++]='0';
                out[o++]='e'; out[o++]= e<0? '-':'+';
                while(ek>0) out[o++]=et[--ek];
            }
            out[o]=0;
            return vstrof(mkstr(out,o));
        }
        if(!xstrcmp(name,"toPrecision")){
            double v=base.num;
            if(v!=v) return vstrof(mkstr("NaN",3));
            if(v==(double)(1.0/0.0)) return vstrof(mkstr("Infinity",8));
            if(v==(double)(-1.0/0.0)) return vstrof(mkstr("-Infinity",9));
            if(!a0n) return vstrof(mkstr(num_str(v),xstrlen(num_str(v))));
            int p=(int)to_num(a0); if(p<1) p=1; if(p>21) p=21;
            int neg=0; double av=v; if(av<0){ neg=1; av=-av; }
            if(av==0){
                char* out=(char*)arena_alloc(64); int o=0;
                if(neg) out[o++]='-';
                out[o++]='0';
                if(p>1){ out[o++]='.'; for(int i=1;i<p;i++) out[o++]='0'; }
                out[o]=0;
                return vstrof(mkstr(out,o));
            }
            long e=0; double m=av;
            if(m>=1.0){ while(m>=10.0){ m/=10.0; e++; if(e>400)break; } }
            else { while(m<1.0 && e>-400){ m*=10.0; e--; } }
            if(e>=p || e< -6){
                /* exponential: p-1 fraction digits */
                int nd=p-1;
                double sc=1; for(int i=0;i<nd;i++) sc*=10;
                s64 total=(s64)(m*sc+0.5+1e-9);
                if(total>= (s64)(sc*10)){ total/=10; e++; }
                char* out=(char*)arena_alloc(96); int o=0;
                if(neg) out[o++]='-';
                s64 q=sc; int sig=nd+1;
                for(int k=0;k<sig;k++){ int d=(int)(total/q); if(d<0)d=0; if(d>9)d=9; out[o++]='0'+d; total-=d*q; q/=10; if(k==0 && sig>1) out[o++]='.'; }
                char et[10]; int ek=0; long ae=e<0?-e:e; if(ae==0) et[ek++]='0';
                while(ae>0){ et[ek++]='0'+(int)(ae%10); ae/=10; }
                while(ek==0) et[ek++]='0';
                out[o++]='e'; out[o++]= e<0? '-':'+';
                while(ek>0) out[o++]=et[--ek];
                out[o]=0;
                return vstrof(mkstr(out,o));
            }
            /* fixed form with (p-e-1) decimals, e>=0 => scale = 10^(p-e-1) */
            long dp=p-e-1;
            double sc10=1; for(long i=0;i<dp;i++) sc10*=10;
            s64 total=(s64)(av*sc10+0.5+1e-9);
            char tmp[48]; int k=0; s64 t=total;
            if(t==0){ tmp[k++]='0'; }
            else { while(t>0){ tmp[k++]='0'+(int)(t%10); t/=10; } }
            char* out=(char*)arena_alloc(96); int o=0;
            if(neg) out[o++]='-';
            /* total has (e+1) integer digits plus dp decimals */
            long idigits=e+1;
            if(total==0){ idigits=1; }
            if(dp==0 && total==0 && idigits==1){
                long consumed=0;
                for(int i=0;i<dp && consumed<k;i++){ out[o++]=tmp[--k]; }
                while(k>0) out[o++]=tmp[--k];
                out[o]=0; return vstrof(mkstr(out,o));
            }
            if(dp<=0){
                while(k>0) out[o++]=tmp[--k];
                out[o]=0; return vstrof(mkstr(out,o));
            }
            /* split integer and fraction from k digits of total */
            /* int part = total / 10^dp; frac = total % 10^dp */
            s64 ip=total/(s64)sc10, fr=total%(s64)sc10;
            {
                char it[32]; int ik=0; s64 u=ip; if(u==0) it[ik++]='0';
                while(u>0){ it[ik++]='0'+(int)(u%10); u/=10; }
                char ft[40]; int fk=0; s64 f=fr;
                for(long i=0;i<dp;i++){ ft[fk++]='0'+(int)(f%10); f/=10; }
                while(ik>0) out[o++]=it[--ik];
                out[o++]='.';
                while(fk>0) out[o++]=ft[--fk];
            }
            out[o]=0;
            return vstrof(mkstr(out,o));
        }
        return vundef();
    }
    if(base.tag==V_OBJ){
        Box* b=_box(base);
        const char* mtag=mkset_tag(b);
        if(mtag){
            if(!xstrcmp(mtag,"Map")){
                if(!xstrcmp(name,"has")) return vbool(mkset_has(b,a0));
                if(!xstrcmp(name,"get")) return mkset_get(b,a0);
                if(!xstrcmp(name,"set")){ mkset_set(b,a0,a1); return base; }
                if(!xstrcmp(name,"delete")) return vbool(mkset_delete(b,a0));
                if(!xstrcmp(name,"clear")){ mkset_clear(b); return vundef(); }
                if(!xstrcmp(name,"size")) return vnum((double)mkset_size(b));
                if(!xstrcmp(name,"keys")||!xstrcmp(name,"values")||!xstrcmp(name,"entries")){
                    Box* eb=mkset_entries(b); if(!eb) return vundef();
                    Box* out=new_box(); if(!out) return vundef();
                    int wantkeys=!xstrcmp(name,"keys");
                    for(Node* e=eb->head;e;e=e->next){
                        Val k=vundef(), v=vundef();
                        if(e->val.tag==V_ARR){ Box* p=_box(e->val); if(p->head){ k=p->head->val; Node* n2=p->head->next; v=n2? n2->val : vundef(); } }
                        else { k=e->val; v=e->val; }
                        if(wantkeys) box_append(out,k);
                        else if(!xstrcmp(name,"values")) box_append(out,v);
                        else { Val pair=mkset_pair_new(k,v); if(pair.tag!=V_UNDEF) box_append(out,pair); }
                    }
                    return varrb(out);
                }
                if(!xstrcmp(name,"forEach")){
                    if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
                    Box* eb=mkset_entries(b); if(!eb) return vundef();
                    for(Node* e=eb->head;e;e=e->next){
                        Val k=vundef(), v=vundef();
                        if(e->val.tag==V_ARR){ Box* p=_box(e->val); if(p->head){ k=p->head->val; Node* n2=p->head->next; v=n2? n2->val : vundef(); } }
                        else { k=e->val; v=e->val; }
                        Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                        if(!argl||!an0||!an1) return vundef();
                        argl->a=an0; an0->next=an1; an0->val=v; an1->val=k;
                        call_func(a0,argl,env,base);
                        if(g_had_error) return vundef();
                    }
                    return vundef();
                }
                return vundef();
            }
            if(!xstrcmp(mtag,"Set")){
                if(!xstrcmp(name,"add")){ mkset_add(b,a0); return base; }
                if(!xstrcmp(name,"has")) return vbool(mkset_has(b,a0));
                if(!xstrcmp(name,"delete")) return vbool(mkset_delete(b,a0));
                if(!xstrcmp(name,"clear")){ mkset_clear(b); return vundef(); }
                if(!xstrcmp(name,"size")) return vnum((double)mkset_size(b));
                if(!xstrcmp(name,"values")||!xstrcmp(name,"keys")||!xstrcmp(name,"entries")){
                    Box* eb=mkset_entries(b); if(!eb) return vundef();
                    Box* out=new_box(); if(!out) return vundef();
                    int wantentries=!xstrcmp(name,"entries");
                    for(Node* e=eb->head;e;e=e->next){
                        if(wantentries){ Val pair=mkset_pair_new(e->val,e->val); if(pair.tag!=V_UNDEF) box_append(out,pair); }
                        else box_append(out,e->val);
                    }
                    return varrb(out);
                }
                if(!xstrcmp(name,"forEach")){
                    if(a0.tag!=V_FUNC){ set_err("callback is not a function"); return vundef(); }
                    Box* eb=mkset_entries(b); if(!eb) return vundef();
                    for(Node* e=eb->head;e;e=e->next){
                        Node* argl=mkn(NK_LIST); Node* an0=mkn(NK_STR); Node* an1=mkn(NK_STR);
                        if(!argl||!an0||!an1) return vundef();
                        argl->a=an0; an0->next=an1; an0->val=e->val; an1->val=e->val;
                        call_func(a0,argl,env,base);
                        if(g_had_error) return vundef();
                    }
                    return vundef();
                }
                return vundef();
            }
        }
        if(rg_is(base)){
            Val pv=rg_pattern(b), fv=rg_flags_v(b);
            const char* pd= _str(pv)->data; u64 pl= _str(pv)->len;
            const char* fd= _str(fv)->data; u64 fll= _str(fv)->len;
            if(!xstrcmp(name,"test")){
                Str* s = a0.tag==V_STR? _str(a0) : 0;
                if(!s){ set_err("regex test: expected string"); return vundef(); }
                int ep=0;
                int idx=rg_match_src(pd,pl,fd,fll,s->data,s->len,&ep);
                if(idx==-2){ set_err("invalid regular expression"); return vundef(); }
                rg_setlast(b,0);
                return vbool(idx>=0);
            }
            if(!xstrcmp(name,"exec")){
                Str* s = a0.tag==V_STR? _str(a0) : 0;
                if(!s){ set_err("regex exec: expected string"); return vundef(); }
                int fx=rg_flags_int(fd,fll);
                int start= (fx&RG_G)? rg_lastindex(b) : 0;
                int ep=0;
                int idx=rg_match_from(pd,pl,fd,fll,s->data,s->len,start,&ep);
                if(idx==-2){ set_err("invalid regular expression"); return vundef(); }
                if(idx<0){ rg_setlast(b,0); return vnull(); }
                if(fx&RG_G) rg_setlast(b,ep);
                return rg_exec_array(s->data,s->len,idx,ep);
            }
            if(!xstrcmp(name,"toString")){
                char* buf=(char*)arena_alloc(pl+fll+3); u64 o=0;
                buf[o++]='/'; xmemcpy(buf+o,pd,pl); o+=pl; buf[o++]='/';
                xmemcpy(buf+o,fd,fll); o+=fll; buf[o]=0;
                return vstrof(mkstr(buf,o));
            }
            return vundef();
        }
        if(is_promise(b)){
            if(!xstrcmp(name,"then")) return promise_then(b,args,env);
            if(!xstrcmp(name,"catch")) return promise_catch(b,args,env);
        }
        Val f=box_get_ext(b,name);
        if(f.tag==V_FUNC) return call_func(f,args,env,base);
        return vundef();
    }
    return vundef();
}

#define MAX_CALL_DEPTH 500
static int g_depth;

/* call a function value with args list; `thisv` is the `this` binding */
static Val call_func(Val fnv, Node* args, Env* caller, Val thisv){
    Node* fn=_fn(fnv);
    if(fn && fn->kind==NK_NATIVE && fn->key){
        /* native builtin method ref: key = "module\x1Fmethod" */
        const char* sep=fn->key;
        while(*sep && *sep!=0x1F) sep++;
        if(*sep==0x1F){
            u64 ml=(u64)(sep-fn->key);
            if(ml==7 && mem_eq(fn->key,"promise",7)){
                const char* meth=sep+1;
                if(!xstrcmp(meth,"ctor")) return promise_ctor(args, caller);
                Env* d=fn->def;
                Node* pn = d? env_find(d,"$p") : 0;
                Val pv = pn? pn->val : vundef();
                if(pv.tag==V_OBJ && box_has(_box(pv),"$_s")){
                    if(!xstrcmp(meth,"resolve")){
                        Node* a0n=args? args->a:0;
                        promise_settle(_box(pv), a0n? eval(a0n,caller) : vundef(), 0);
                        return vundef();
                    }
                    if(!xstrcmp(meth,"reject")){
                        Node* a0n=args? args->a:0;
                        promise_settle(_box(pv), a0n? eval(a0n,caller) : vundef(), 1);
                        return vundef();
                    }
                }
                if(!xstrcmp(meth,"allstep")){
                    Env* d2=fn->def;
                    Val res=env_find(d2,"$res")->val;
                    Val out=env_find(d2,"$out")->val;
                    Val nv =env_find(d2,"$n")->val;
                    Val iv =env_find(d2,"$i")->val;
                    Node* a0n=args? args->a:0;
                    Val vv = a0n? eval(a0n,caller) : vundef();
                    if(out.tag==V_ARR){ arr_set_idx(_box(out),(int)to_num(iv),vv); }
                    long k=(long)to_num(env_find(d2,"$k")->val)+1;
                    env_set(d2,"$k",vnum((double)k));
                    long nn=(long)to_num(nv);
                    if(k>=nn && res.tag==V_OBJ) promise_settle(_box(res), out, 0);
                    return vundef();
                }
                if(!xstrcmp(meth,"allrej")){
                    Env* d3=fn->def;
                    Val res=env_find(d3,"$res")->val;
                    Node* a0n=args? args->a:0;
                    if(res.tag==V_OBJ) promise_settle(_box(res), a0n? eval(a0n,caller) : vundef(), 1);
                    return vundef();
                }
            }
            char* mod=(char*)arena_alloc(ml+1);
            if(mod){ xmemcpy(mod,fn->key,ml); mod[ml]=0; }
            return call_builtin_member(mod?mod:(char*)fn->key, sep+1, args, caller);
        }
    }
    Env* base = (fn && fn->kind!=NK_NATIVE && fn->def) ? fn->def : caller;
    if(g_depth>=MAX_CALL_DEPTH){
        set_err("stack overflow: call depth exceeded");
        return vundef();
    }
    g_depth++;
    Env* callee=env_new(base);
    if(thisv.tag!=V_UNDEF) env_def(callee,"this",thisv);
    Node* p = fn->a? fn->a->a : 0;   /* NK_LIST -> first param */
    Node* a = args? args->a : 0;
    while(p){
        Val av = a? eval(a,caller) : vundef();
        env_def(callee, p->key, av);
        p=p->next; if(a)a=a->next;
    }
    int saved=g_flow; Val sv=g_flow_val;
    g_flow=0; g_flow_val=vundef();
    if(fn->b){ for(Node* s=fn->b->a; s && g_flow==0; s=s->next) exec_stmt(s,callee); }
    Val r = g_flow==1? g_flow_val : vundef();
    g_flow=saved; g_flow_val=sv;
    g_depth--;
    if(fn && fn->ival==2){
        /* async function: wrap result in an already-fulfilled promise */
        Box* p=promise_new(); if(!p) return r;
        promise_settle(p, r, 0);
        return vobjof(p);
    }
    return r;
}

/* ================================================================
   ASYNC SUBSYSTEM — Promise + microtask queue + macrotask timers.
   Pipeline runs at the end of each top-level execution and on
   JS_OP_PUMP; awaiting inside async code spins the pipeline.
   ================================================================ */
#define MAX_ASYNC_ITERS 100000

static int is_promise(Box* b){ return b && box_has(b,"$_s"); }

static Box* promise_new(void){
    Box* b=new_box(); if(!b) return 0;
    box_set(b,"$_s",vnum(0));
    box_set(b,"$_v",vundef());
    return b;
}

static Box* box_link_next(Box* b){
    Val v=box_get(b,"$_n");
    return (v.tag==V_OBJ)? _box(v) : 0;
}
static void box_link_append(Box** head, Box** tail, Box* b){
    box_set(b,"$_n",vundef());
    if(*tail){ box_set(*tail,"$_n",vobjof(b)); *tail=b; }
    else { *head=b; *tail=b; }
}
static void mtq_push(Box* job){ box_link_append(&g_mtq_head,&g_mtq_tail,job); }
static void tmq_push(Box* t){ box_link_append(&g_tmq_head,&g_tmq_tail,t); }

/* settle: set state, remember value, flush pending continuations as jobs */
static Val promise_settle(Box* p, Val v, int reject){
    if(!p) return vundef();
    Val st=box_get(p,"$_s");
    if(st.tag==V_NUM && (long)st.num!=0) return vundef();
    box_set(p,"$_s",vnum(reject?2:1));
    box_set(p,"$_v",v);
    while(is_promise(p)){
        Val hd=box_get(p,"$_c0");
        if(hd.tag!=V_OBJ) break;
        Box* job=_box(hd);
        box_set(p,"$_c0", box_get(job,"$_n"));
        /* select the right handler for this state and enqueue */
        Val h = reject? box_get(job,"$_h") : box_get(job,"$_f");
        box_set(job,"$_f", h);
        box_set(job,"$_v", v);
        if(h.tag!=V_FUNC) box_set(job,"$_r", vnum(reject?1:0));
        else box_set(job,"$_r", vnum(0));
        mtq_push(job);
    }
    return vobjof(p);
}

/* run a queued job: either a `.then` continuation or a bare callback */
static void run_microtask(Box* job){
    Val fn=box_get(job,"$_f");
    Val v =box_get(job,"$_v");
    int hasc = box_has(job,"$_c");
    Val child = hasc? box_get(job,"$_c") : vundef();
    if(fn.tag==V_FUNC){
        Node* argl=mkn(NK_LIST);
        if(argl){ Node* a0=mkn(NK_STR); if(a0){ a0->val=v; argl->a=a0; } }
        Val res = call_func(fn, argl, g_global_env, vundef());
        if(g_had_error) return;
        if(hasc && child.tag==V_OBJ) promise_settle(_box(child), res, 0);
    } else if(hasc && child.tag==V_OBJ){
        Val rf=box_get(job,"$_r");
        promise_settle(_box(child), v, rf.tag==V_NUM && (long)rf.num!=0);
    }
}

static long g_timer_seq;
static void run_timer(Box* t){
    Val fn=box_get(t,"$_f");
    long iv=(long)box_get(t,"$iv").num;
    if(fn.tag==V_FUNC) call_func(fn, 0, g_global_env, vundef());
    if(!iv) tmq_remove((long)box_get(t,"$id").num);   /* one-shot: drop after firing (callback may already have cleared it) */
}
static int tmq_remove(long id){
    Box* prev=0;
    for(Box* t=g_tmq_head; t; ){
        Val idv=box_get(t,"$id");
        if(idv.tag==V_NUM && (long)idv.num==id){
            box_set(t,"$iv",vnum(0));           /* prevent run_timer from re-queuing */
            Box* nxt=box_link_next(t);
            if(prev){ box_set(prev,"$_n", vobjof(nxt)); }
            else { g_tmq_head=nxt; }
            if(g_tmq_tail==t) g_tmq_tail= prev? prev:0;
            return 1;
        }
        prev=t; t=box_link_next(t);
    }
    return 0;
}

/* drain microtasks; run one macrotask per pass when queues non-empty */
static void master_pump(long budget){
    long it=0;
    while(it<budget){
        int progressed=0;
        while(g_mtq_head){
            Box* j=g_mtq_head;
            Box* nxt=box_link_next(j);
            box_set(j,"$_n",vundef());
            g_mtq_head=nxt;
            if(!nxt) g_mtq_tail=0;
            it++;
            run_microtask(j);
            if(g_had_error) return;
            if(it>=budget) return;
        }
        if(g_tmq_head && g_async_await_nest==0){
            run_timer(g_tmq_head);     /* timer stays in queue while running; run_timer manages placement */
            if(g_had_error) return;
            it++;
            if(it>=budget) return;
        }
        progressed = (g_tmq_head!=0);
        if(!g_mtq_head && !g_tmq_head) return;
        if(!progressed) break;
    }
}

/* await: spin the pipeline until the promise settles (synchronous engine) */
static Val async_await_value(Val p, Env* env){
    (void)env;
    if(p.tag!=V_OBJ || !is_promise(_box(p))) return p;
    Box* b=_box(p);
    g_async_await_nest++;
    long guard=0;
    while(guard++<MAX_ASYNC_ITERS){
        if(g_had_error) break;
        Val st=box_get(b,"$_s");
        if(st.tag==V_NUM && (long)st.num!=0) break;
        master_pump(1000);
    }
    g_async_await_nest--;
    Val st=box_get(b,"$_s");
    if(st.tag==V_NUM && (long)st.num==2) return vundef();      /* rejected -> undefined */
    if(st.tag==V_NUM && (long)st.num==1) return box_get(b,"$_v");
    return p;                                                   /* unresolved fallback */
}

/* --- Promise API --- */
static Val promise_then(Box* p, Node* args, Env* env){
    if(!is_promise(p)) return vundef();
    Val onf = args&&args->a? eval(args->a,env) : vundef();
    Val onr = args&&args->a&&args->a->next? eval(args->a->next,env) : vundef();
    Box* child=promise_new(); if(!child) return vundef();
    Box* job=new_box(); if(!job) return vundef();
    box_set(job,"$_c",vobjof(child));
    box_set(job,"$_f", onf.tag==V_FUNC? onf : vnull());
    box_set(job,"$_h", onr.tag==V_FUNC? onr : vnull());
    box_set(job,"$_v",vundef());
    box_set(job,"$_r",vnum(0));
    box_set(job,"$_n",vundef());
    Val st=box_get(p,"$_s");
    if(st.tag==V_NUM && (long)st.num==0){
        /* pending -> keep continuation in the promise */
        Val hd=box_get(p,"$_c0");
        if(hd.tag==V_OBJ){
            Box* cur=_box(hd);
            while(box_get(cur,"$_n").tag==V_OBJ) cur=_box(box_get(cur,"$_n"));
            box_set(cur,"$_n",vobjof(job));
        } else box_set(p,"$_c0",vobjof(job));
        return vobjof(child);
    }
    if((long)st.num==1){
        box_set(job,"$_f", box_get(job,"$_f"));
        box_set(job,"$_v", box_get(p,"$_v"));
        if(box_get(job,"$_f").tag!=V_FUNC) box_set(job,"$_r",vnum(0));
        mtq_push(job);
    } else {
        Val h=box_get(job,"$_h");
        box_set(job,"$_f", h.tag==V_FUNC? h : vnull());
        box_set(job,"$_v", box_get(p,"$_v"));
        if(h.tag!=V_FUNC) box_set(job,"$_r",vnum(1));
        mtq_push(job);
    }
    return vobjof(child);
}

static Val promise_catch(Box* p, Node* args, Env* env){
    if(!is_promise(p)) return vundef();
    Node* two=mkn(NK_LIST); if(!two) return vundef();
    Node* und=mkn(NK_UNDEF); if(!und) return vundef();
    und->val=vundef();
    two->a=und;
    und->next = args? args->a : 0;
    return promise_then(p, two, env);
}

static Val promise_ctor(Node* args, Env* env){
    Box* p=promise_new(); if(!p) return vundef();
    Val ex = args&&args->a? eval(args->a,env) : vundef();
    if(ex.tag==V_FUNC){
        Val res=make_native_method("promise","resolve");
        Val rej=make_native_method("promise","reject");
        Node* fr=_fn(res); if(fr){ Env* e=env_new(env); if(e) env_def(e,"$p",vobjof(p)); fr->def=e; }
        Node* fj=_fn(rej); if(fj){ Env* e=env_new(env); if(e) env_def(e,"$p",vobjof(p)); fj->def=e; }
        Node* argl=mkn(NK_LIST);
        if(argl){
            Node* a0=mkn(NK_STR); Node* a1=mkn(NK_STR);
            if(a0){ a0->val=res; argl->a=a0; }
            if(a1){ if(a0) a0->next=a1; else argl->a=a1; a1->val=rej; }
        }
        call_func(ex, argl, env, vundef());
    }
    return vobjof(p);
}

static Val promise_static(Node* args, Env* env, int which){
    Val v = args&&args->a? eval(args->a,env) : vundef();
    if(!which && v.tag==V_OBJ && is_promise(_box(v))) return v;
    Box* p=promise_new(); if(!p) return vundef();
    promise_settle(p, v, which?1:0);
    return vobjof(p);
}

static Val promise_all(Node* args, Env* env){
    Box* out=new_box(); if(!out) return vundef();
    Box* res=promise_new(); if(!res) return vundef();
    Box* items=new_box(); if(!items) return vobjof(res);
    Node* p2=args? args->a:0;
    if(p2 && !p2->next){
        Val v0=eval(p2,env);
        if(v0.tag==V_ARR){ for(Node* e=_box(v0)->head;e;e=e->next) box_append(items,e->val); }
        else box_append(items,v0);
    } else {
        for(;p2;p2=p2->next) box_append(items,eval(p2,env));
    }
    long n=box_len(items);
    if(n==0){ promise_settle(res, varrb(out), 0); return vobjof(res); }
    Env* shared=env_new(env); if(!shared) return vobjof(res);
    env_def(shared,"$res",vobjof(res));
    env_def(shared,"$out",varrb(out));
    env_def(shared,"$n",vnum((double)n));
    env_def(shared,"$k",vnum(0));
    long idx=0;
    for(Node* e=items->head; e; e=e->next, idx++){
        Val v=e->val;
        if(v.tag==V_OBJ && is_promise(_box(v))){
            Env* ce=env_new(shared); if(!ce) continue;
            env_def(ce,"$i",vnum((double)idx));
            Val f=make_native_method("promise","allstep");
            Val rj=make_native_method("promise","allrej");
            Node* fr=_fn(f); if(fr) fr->def=ce;
            Node* frj=_fn(rj); if(frj) frj->def=ce;
            if(fr && f.tag!=V_UNDEF && rj.tag!=V_UNDEF){
                Node* al=mkn(NK_LIST);
                Node* af=mkn(NK_STR); Node* ar=mkn(NK_STR);
                if(al&&af&&ar){ af->val=f; ar->val=rj; af->next=ar; al->a=af; }
                if(al) promise_then(_box(v), al, env);
            }
            if(fr && frj && fr->def==0) fr->def=shared;
            if(frj && frj->def==0) frj->def=shared;
        } else {
            arr_set_idx(out,(int)idx,v);
            long k=(long)to_num(env_find(shared,"$k")->val)+1;
            env_set(shared,"$k",vnum((double)k));
        }
    }
    long kk=(long)to_num(env_find(shared,"$k")->val);
    if(kk>=n) promise_settle(res, varrb(out), 0);
    return vobjof(res);
}

static long timer_create(Node* args, Env* env, int interval){
    Node* a0n=args? args->a:0;
    Val fn = a0n? eval(a0n,env) : vundef();
    if(fn.tag!=V_FUNC){ set_err("setTimeout: first arg is not a function"); return -1; }
    Box* t=new_box(); if(!t) return -1;
    long id=++g_timer_seq;
    box_set(t,"$id",vnum((double)id));
    box_set(t,"$iv",vnum(interval?1:0));
    box_set(t,"$_f",fn);
    box_set(t,"$_n",vundef());
    tmq_push(t);
    return id;
}

/* --- GC roots for schedule queues --- */
static void mark_async_roots(void){
    if(g_mtq_head) mark_box(g_mtq_head);
    if(g_tmq_head) mark_box(g_tmq_head);
}

static void exec_stmt(Node* n, Env* env){
    if(!n) return;
    if(g_oom) return;
    switch(n->kind){
        case NK_EMPTY: return;
        case NK_BLOCK:
            for(Node* s=n->a; s && g_flow==0; s=s->next) exec_stmt(s,env);
            return;
        case NK_STMTS:
            for(Node* s=n->a?n->a:n; s && g_flow==0; s=s->next) exec_stmt(s,env);
            return;
        case NK_VAR: {
            if(n->ival==1 && n->key){                     /* function declaration */
                env_def(env, n->key, eval(n->a, env));
                return;
            }
            for(Node* one=n->a; one; one=one->next){
                if(!env_has_local(env, one->key))
                    env_def(env, one->key, vundef());
                if(one->a) env_set(env, one->key, eval(one->a, env));
            }
            return;
        }
        case NK_ASSIGN: {
            Val rhs=eval(n->b, env);
            const char* op=n->key;
            if(op && xstrcmp(op,"=")){
                Val base=eval(n->a, env);
                Val r=vundef();
                if(!xstrcmp(op,"+=")) r=add_vals(base,rhs);
                else if(!xstrcmp(op,"-=")) r=vnum(to_num(base)-to_num(rhs));
                else if(!xstrcmp(op,"*=")) r=vnum(to_num(base)*to_num(rhs));
                else if(!xstrcmp(op,"/=")) r=vnum(to_num(base)/to_num(rhs));
                else if(!xstrcmp(op,"%=")){ s64 rd=(s64)to_num(rhs); if(rd!=0) r=vnum((double)((s64)to_num(base)%rd)); }
                else r=rhs;
                assign_to(n->a, env, r);
                return;
            }
            assign_to(n->a, env, rhs);
            return;
        }
        case NK_IF: {
            if(to_bool(eval(n->a,env))) { if(n->b) exec_stmt(n->b,env); }
            else if(n->c) exec_stmt(n->c,env);
            return;
        }
        case NK_WHILE: {
            while(g_flow==0){
                if(!to_bool(eval(n->a,env))) break;
                exec_loop_body(n->b,env);
                if(g_flow==2){ g_flow=0; break; }
                if(g_flow==3){ g_flow=0; continue; }
                if(g_flow!=0) break;
            }
            return;
        }
        case NK_DO: {
            do {
                exec_loop_body(n->b,env);
                if(g_flow==2){ g_flow=0; break; }
                if(g_flow==3){ g_flow=0; continue; }
                if(g_flow!=0) break;
            } while(g_flow==0 && to_bool(eval(n->a,env)));
            return;
        }
        case NK_BREAK: { g_flow=2; return; }
        case NK_CONTINUE: { g_flow=3; return; }
        case NK_SWITCH: {
            Val cond=eval(n->a,env);
            Node* pick=0;
            for(Node* g=n->b;g;g=g->next){
                if(g->kind==NK_CASE && eq_strict(cond,eval(g->a,env))){ pick=g; break; }
            }
            if(!pick){
                for(Node* g=n->b;g;g=g->next)
                    if(g->kind==NK_DEFAULT){ pick=g; break; }
            }
            if(pick){
                int run=0;
                for(Node* g=n->b; g && g_flow==0; g=g->next){
                    if(g==pick) run=1;
                    if(run){
                        if(g->b && g->b->a) exec_stmt(g->b,env);
                        if(g_flow==2){ g_flow=0; break; }   /* break out of switch */
                        if(g_flow==1||g_flow==3) break;
                    }
                }
            }
            return;
        }
        case NK_FOR: {
            /* for(init;cond;update) body */
            Node* body=n->d;
            if(n->a){
                Env* sub=env_new(env);
                exec_stmt(n->a,sub);
                while(g_flow==0){
                    if(n->b && !to_bool(eval(n->b,sub))) break;
                    exec_loop_body(body,sub);
                    if(g_flow==2){ g_flow=0; break; }
                    if(g_flow==3){ g_flow=0; if(n->c) eval(n->c,sub); continue; }
                    if(g_flow!=0) break;
                    if(n->c) eval(n->c,sub);
                }
            } else {
                while(g_flow==0){
                    if(n->b && !to_bool(eval(n->b,env))) break;
                    exec_loop_body(body,env);
                    if(g_flow==2){ g_flow=0; break; }
                    if(g_flow==3){ g_flow=0; if(n->c) eval(n->c,env); continue; }
                    if(g_flow!=0) break;
                    if(n->c) eval(n->c,env);
                }
            }
            return;
        }
        case NK_RETURN: {
            g_flow=1;
            g_flow_val = n->a? eval(n->a,env) : vundef();
            return;
        }
        default: {
            /* expression statement */
            g_last_result = eval(n,env);
            return;
        }
    }
}

/* assign into an lvalue (node evaluated in env) */
static void assign_to(Node* lv, Env* env, Val v){
    if(lv->kind==NK_IDENT){ env_set(env,lv->key,v); return; }
    if(lv->kind==NK_MEMBER){
        Val base=eval(lv->a,env);
        if(base.tag==V_OBJ){
            Box* b=_box(base);
            if(!lv->key){ /* numeric index -> key = "i" */
                char* ns=num_str(to_num(eval(lv->b,env)));
                box_set(b, ns, v);
            } else if(rg_is(base) && !xstrcmp(lv->key,"lastIndex")){
                box_set(b, RG_LAST, v);
            } else box_set(b, lv->key, v);
        } else if(base.tag==V_ARR){
            Box* b=_box(base);
            if(!lv->key) arr_set_idx(b, (int)to_num(eval(lv->b,env)), v);
            else box_set(b, lv->key, v);
        } else if(base.tag==V_FUNC && lv->key && !xstrcmp(lv->key,"prototype")){
            if(v.tag==V_OBJ || v.tag==V_ARR){ Node* f=_fn(base); if(f) f->proto=_box(v); }
        }
    }
}

/* read an rvalue */
static Val eval(Node* n, Env* env){
    if(!n) return vundef();
    if(g_oom) return vundef();
    switch(n->kind){
        case NK_NUM: return vnum(n->val.num);
        case NK_STR: return n->val;
        case NK_BOOL: return n->val;
        case NK_UNDEF: return vundef();
        case NK_NULL: return vnull();
        case NK_IDENT: {
            Node* slot=env_find(env,n->key);
            return slot? slot->val : vundef();
        }
        case NK_OBJ: {
            Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b)return vundef();
            b->head=0;
            for(Node* p=n->a; p; p=p->next){
                Val pv = p->a? eval(p->a,env) : vundef();
                box_set(b, p->key, pv);
            }
            return vobjof(b);
        }
        case NK_ARR: {
            Box* b=(Box*)arena_alloc(sizeof(Box)); if(!b)return vundef();
            b->head=0; int i=0;
            for(Node* e=n->a; e; e=e->next,i++){ arr_set_idx(b,i, eval(e,env)); }
            return varrb(b);
        }
        case NK_FUNC: if(n->def==0) n->def=env; return vfnof(n);
        case NK_MEMBER: {
            if(n->a && n->a->kind==NK_IDENT && n->key && !xstrcmp(n->a->key,"Math")){
                int ok=0; double c=math_const(n->key,&ok);
                if(ok) return vnum(c);
            }
            if(n->a && n->a->kind==NK_IDENT && n->key && !xstrcmp(n->a->key,"Number")){
                if(!xstrcmp(n->key,"MAX_SAFE_INTEGER")) return vnum(9007199254740991.0);
                if(!xstrcmp(n->key,"MIN_SAFE_INTEGER")) return vnum(-9007199254740991.0);
                if(!xstrcmp(n->key,"EPSILON")) return vnum(2.220446049250313e-16);
                if(!xstrcmp(n->key,"MAX_VALUE")) return vnum(1.7976931348623157e308);
                if(!xstrcmp(n->key,"MIN_VALUE")) return vnum(5.0e-324);
                if(!xstrcmp(n->key,"NaN")) return vnum(0.0/0.0);
                if(!xstrcmp(n->key,"POSITIVE_INFINITY")) return vnum(1.0/0.0);
                if(!xstrcmp(n->key,"NEGATIVE_INFINITY")) return vnum(-1.0/0.0);
            }
            Val base=eval(n->a,env);
            if(base.tag==V_OBJ){
                Box* b=_box(base);
                if(!n->key) return box_get_idx(b,(int)to_num(eval(n->b,env)));
                {
                    const char* mt=mkset_tag(b);
                    if(mt && !xstrcmp(n->key,"size")) return vnum((double)mkset_size(b));
                }
                if(rg_is(base)){
                    if(!xstrcmp(n->key,"lastIndex")) return box_get(b,RG_LAST);
                    if(!xstrcmp(n->key,"source")) return rg_pattern(b);
                    if(!xstrcmp(n->key,"flags")) return rg_flags_v(b);
                    Val fv=rg_flags_v(b);
                    u64 fll= fv.tag==V_STR? _str(fv)->len : 0;
                    const char* fd= fv.tag==V_STR? _str(fv)->data : "";
                    if(!xstrcmp(n->key,"global")) return vbool(rg_flags_int(fd,fll)&RG_G);
                    if(!xstrcmp(n->key,"ignoreCase")) return vbool(rg_flags_int(fd,fll)&RG_I);
                    if(!xstrcmp(n->key,"multiline")) return vbool(rg_flags_int(fd,fll)&RG_M);
                    if(!xstrcmp(n->key,"dotAll")) return vbool(rg_flags_int(fd,fll)&RG_S);
                    if(!xstrcmp(n->key,"sticky")) return vbool(0);
                    if(!xstrcmp(n->key,"unicode")) return vbool(0);
                }
                return box_get_ext(b, n->key);
            }
            if(base.tag==V_FUNC && n->key && !xstrcmp(n->key,"prototype")){
                Box* p=func_proto(_fn(base));
                return p? vobjof(p) : vundef();
            }
            if(base.tag==V_ARR){
                Box* b=_box(base);
                if(!n->key) return box_get_idx(b,(int)to_num(eval(n->b,env)));
                if(!xstrcmp(n->key,"length")) return vnum((double)box_len(b));
                return box_get_ext(b, n->key);
            }
            if(base.tag==V_STR){
                Str* s=_str(base);
                if(!n->key){ long i=(long)to_num(eval(n->b,env));
                    if(i<0||i>=(long)s->len) return vstrof(mkstr("",0));
                    char ch=s->data[i]; return vstrof(mkstr(&ch,1));
                }
                if(!xstrcmp(n->key,"length")) return vnum((double)s->len);
                return vundef();
            }
            return vundef();
        }
        case NK_CALL: {
            /* built-in method call like "abc".substring(0,1) or arr.push(x) */
            if(n->a && n->a->kind==NK_MEMBER){
                Node* m=n->a;
                if(m->a && m->a->kind==NK_IDENT){
                    if(!xstrcmp(m->a->key,"Promise") && m->key){
                        if(!xstrcmp(m->key,"resolve")) return promise_static(n->b,env,0);
                        if(!xstrcmp(m->key,"reject")) return promise_static(n->b,env,1);
                        if(!xstrcmp(m->key,"all")) return promise_all(n->b,env);
                    }
                    if(!xstrcmp(m->a->key,"Array") && m->key && !xstrcmp(m->key,"isArray")){
                        Node* a0n=n->b? n->b->a : 0;
                        Val v = a0n? eval(a0n,env) : vundef();
                        return vbool(v.tag==V_ARR);
                    }
                    if(!xstrcmp(m->a->key,"Math")) return call_math(m->key,n->b,env);
                    if(!xstrcmp(m->a->key,"Object") && m->key && !xstrcmp(m->key,"keys"))
                        return call_objkeys(n->b,env);
                    if(!xstrcmp(m->a->key,"Object") && m->key && (!xstrcmp(m->key,"values")||!xstrcmp(m->key,"entries")))
                        return call_objvalues(n->b,env, !xstrcmp(m->key,"entries"));
                    if(!xstrcmp(m->a->key,"Object") && m->key && !xstrcmp(m->key,"create")){
                        Node* a0n=n->b? n->b->a : 0;
                        Val p = a0n? eval(a0n,env) : vnull();
                        Box* nb=new_box(); if(!nb) return vundef();
                        if(p.tag==V_OBJ || p.tag==V_ARR) nb->proto=_box(p);
                        else if(p.tag!=V_NULL) set_err("Object.create: prototype must be an object or null");
                        return vobjof(nb);
                    }
                    if(!xstrcmp(m->a->key,"Object") && m->key && !xstrcmp(m->key,"getPrototypeOf")){
                        Node* a0n=n->b? n->b->a : 0;
                        Val p = a0n? eval(a0n,env) : vundef();
                        if(p.tag!=V_OBJ && p.tag!=V_ARR) return vnull();
                        Box* pr=_box(p)->proto;
                        return pr? vobjof(pr) : vnull();
                    }
                    if(!xstrcmp(m->a->key,"Object") && m->key && !xstrcmp(m->key,"hasOwn")){
                        Node* a0n=n->b? n->b->a : 0;
                        Node* a1n=a0n? a0n->next : 0;
                        Val obj = a0n? eval(a0n,env) : vundef();
                        Val key = a1n? eval(a1n,env) : vundef();
                        if(obj.tag!=V_OBJ && obj.tag!=V_ARR) return vbool(0);
                        const char* ks = str_of_val(key);
                        return vbool(box_has(_box(obj),ks));
                    }
                    /* reserved builtin modules: fs/path/base64/console/JSON (like Math) */
                    if(builtin_handles(m->a->key, m->key))
                        return call_builtin_member(m->a->key, m->key, n->b, env);
                    Val base=eval(m->a,env);
                    if(m->key && (base.tag==V_OBJ||base.tag==V_ARR)){
                        Box* bo=_box(base);
                        Val f=box_get_ext(bo,m->key);
                        if(f.tag==V_FUNC) return call_func(f,n->b,env,base);
                        if(is_promise(bo)){
                            if(!xstrcmp(m->key,"then")) return promise_then(bo,n->b,env);
                            if(!xstrcmp(m->key,"catch")) return promise_catch(bo,n->b,env);
                        }
                    }
                    return call_method_v(base, m->key, n->b, env);
                }
                Val base=eval(m->a,env);
                if(m->key && (base.tag==V_OBJ||base.tag==V_ARR)){
                    Box* bo=_box(base);
                    Val f=box_get_ext(bo,m->key);
                    if(f.tag==V_FUNC) return call_func(f,n->b,env,base);
                    if(is_promise(bo)){
                        if(!xstrcmp(m->key,"then")) return promise_then(bo,n->b,env);
                        if(!xstrcmp(m->key,"catch")) return promise_catch(bo,n->b,env);
                    }
                }
                return call_method_v(base, m->key, n->b, env);
            }
            if(n->a && n->a->kind==NK_IDENT){
                Val r=vundef();
                if(call_global(n->a->key, n->b, env, &r)) return r;
            }
            Val callee=eval(n->a,env);
            if(callee.tag==V_FUNC) return call_func(callee, n->b, env, vundef());
            set_err("call of non-function");
            return vundef();
        }
        case NK_AWAIT: {
            Val v=eval(n->a,env);
            return async_await_value(v, env);
        }
        case NK_UNARY: {
            Val a=eval(n->a,env);
            if(!xstrcmp(n->key,"-")) return vnum(-to_num(a));
            if(!xstrcmp(n->key,"!")) return vbool(!to_bool(a));
            if(!xstrcmp(n->key,"typeof")){
                const char* t;
                switch(a.tag){
                    case V_NUM: t="number"; break;
                    case V_STR: t="string"; break;
                    case V_BOOL: t="boolean"; break;
                    case V_FUNC: t="function"; break;
                    case V_NULL: t="object"; break;
                    case V_UNDEF: t="undefined"; break;
                    default: t="object"; break;
                }
                u64 n2=xstrlen(t);
                return vstrof(mkstr(t,n2));
            }
            if(!xstrcmp(n->key,"delete")){
                Node* tgt=n->a;
                if(tgt && tgt->kind==NK_MEMBER){
                    Val bv=eval(tgt->a,env);
                    if(bv.tag==V_OBJ){ if(tgt->key) box_del(_box(bv),tgt->key); else box_del_idx(_box(bv),(int)to_num(eval(tgt->b,env))); }
                }
                return vbool(1);
            }
            return a;
        }
        case NK_BIN: {
            const char* op=n->key;
            if(!xstrcmp(op,"&&")){ Val l=eval(n->a,env); if(!to_bool(l)) return l; return eval(n->b,env); }
            if(!xstrcmp(op,"||")){ Val l=eval(n->a,env); if(to_bool(l)) return l; return eval(n->b,env); }
            Val l=eval(n->a,env); Val r=eval(n->b,env);
            if(!xstrcmp(op,"+")){
                if(l.tag==V_STR||r.tag==V_STR){
                    const char* ls=str_of_val(l); const char* rs=str_of_val(r);
                    u64 ln=xstrlen(ls), rn=xstrlen(rs);
                    char* buf=(char*)arena_alloc(ln+rn+1); xmemcpy(buf,ls,ln); xmemcpy(buf+ln,rs,rn); buf[ln+rn]=0;
                    return vstrof(mkstr(buf,ln+rn));
                }
                return vnum(to_num(l)+to_num(r));
            }
            if(!xstrcmp(op,"-")) return vnum(to_num(l)-to_num(r));
            if(!xstrcmp(op,"*")) return vnum(to_num(l)*to_num(r));
            if(!xstrcmp(op,"/")) return vnum(to_num(l)/to_num(r));
            if(!xstrcmp(op,"%")){ double rd=to_num(r); s64 rr=(s64)rd; if(rr==0) return vnum(0.0/0.0); return vnum((double)((s64)to_num(l)%rr)); }
            if(!xstrcmp(op,"==")) return vbool(eq_val(l,r));
            if(!xstrcmp(op,"!=")) return vbool(!eq_val(l,r));
            if(!xstrcmp(op,"===")) return vbool(eq_strict(l,r));
            if(!xstrcmp(op,"!==")) return vbool(!eq_strict(l,r));
            if(!xstrcmp(op,"in")){
                if(r.tag==V_OBJ){
                    Box* b=_box(r);
                    if(l.tag==V_STR) return vbool(box_has_ext(b,_str(l)->data));
                    if(l.tag==V_NUM){ char* ns=num_str(to_num(l)); return vbool(box_has_ext(b,ns)); }
                    return vbool(0);
                }
                if(r.tag==V_ARR){
                    if(l.tag==V_NUM || l.tag==V_BOOL){ long i=(long)to_num(l); return vbool(i>=0 && i<box_len(_box(r))); }
                    return vbool(0);
                }
                return vbool(0);
            }
            if(!xstrcmp(op,"instanceof")){
                if(r.tag!=V_FUNC) return vbool(0);
                Box* proto=func_proto(_fn(r));
                if(!proto) return vbool(0);
                if(l.tag==V_OBJ || l.tag==V_ARR){
                    for(Box* s=_box(l)->proto; s; s=s->proto) if(s==proto) return vbool(1);
                }
                return vbool(0);
            }
            if(l.tag==V_STR && r.tag==V_STR){
                const char* ls=str_of_val(l); const char* rs=str_of_val(r);
                int c=xstrcmp(ls,rs);
                if(!xstrcmp(op,"<")) return vbool(c<0);
                if(!xstrcmp(op,">")) return vbool(c>0);
                if(!xstrcmp(op,"<=")) return vbool(c<=0);
                if(!xstrcmp(op,">=")) return vbool(c>=0);
            }
            if(!xstrcmp(op,"<")) return vbool(to_num(l)<to_num(r));
            if(!xstrcmp(op,">")) return vbool(to_num(l)>to_num(r));
            if(!xstrcmp(op,"<=")) return vbool(to_num(l)<=to_num(r));
            if(!xstrcmp(op,">=")) return vbool(to_num(l)>=to_num(r));
            return vundef();
        }
        case NK_TRIN: return to_bool(eval(n->a,env))? eval(n->b,env): eval(n->c,env);
        case NK_REGEX: {
            const char* pat=n->key? n->key : "";
            const char* fl=n->rflags? n->rflags : "";
            return rg_make(pat,n->key? xstrlen(n->key):0,
                           fl, n->rflen);
        }
        case NK_NEW: {
            Val c=eval(n->a,env);
            if(c.tag!=V_FUNC){ set_err("new of non-function"); return vundef(); }
            Box* proto=func_proto(_fn(c));
            Box* inst=new_box(); if(!inst) return vundef();
            inst->proto=proto;
            Val thisv=vobjof(inst);
            Val r=call_func(c, n->b, env, thisv);
            if(g_had_error) return vundef();
            if(r.tag==V_OBJ||r.tag==V_ARR) return r;
            return thisv;
        }
        case NK_TPL_EXPR: return eval(n->a,env);
        case NK_TEMPLATE: {
            u64 tl=1;
            for(Node* p=n->a;p;p=p->next){
                if(p->kind==NK_STR) tl+=_str(p->val)->len;
                else tl+=xstrlen(str_of_val(eval(p->a,env)));
            }
            char* buf=(char*)arena_alloc(tl); if(!buf) return vundef();
            u64 o=0;
            for(Node* p=n->a;p;p=p->next){
                if(p->kind==NK_STR){ u64 ln=_str(p->val)->len; xmemcpy(buf+o,_str(p->val)->data,ln); o+=ln; }
                else { const char* s2=str_of_val(eval(p->a,env)); u64 l2=xstrlen(s2); xmemcpy(buf+o,s2,l2); o+=l2; }
            }
            buf[o]=0;
            return vstrof(mkstr(buf,o));
        }
        case NK_ASSIGN: {
            const char* op=n->key;
            Val v=eval(n->b,env);
            if(op && !xstrcmp(op,"=")){ assign_to(n->a,env,v); return v; }
            Val base=eval(n->a,env);
            Val r=vundef();
            if(!xstrcmp(op,"+=")) r=add_vals(base,v);
            else if(!xstrcmp(op,"-=")) r=vnum(to_num(base)-to_num(v));
            else if(!xstrcmp(op,"*=")) r=vnum(to_num(base)*to_num(v));
            else if(!xstrcmp(op,"/=")) r=vnum(to_num(base)/to_num(v));
            else if(!xstrcmp(op,"%=")){ s64 rd=(s64)to_num(v); if(rd!=0) r=vnum((double)((s64)to_num(base)%rd)); }
            else r=v;
            assign_to(n->a,env,r);
            return r;
        }
        case NK_POST: {
            Val old=eval(n->a,env); Val base=eval(n->a,env);
            double delta = !xstrcmp(n->key,"++")? 1.0 : -1.0;
            double newv=to_num(base)+delta;
            assign_to(n->a,env, vnum(newv));
            return n->ival? vnum(newv) : old;
        }
        case NK_IF: if(to_bool(eval(n->a,env))){ if(n->b)exec_stmt(n->b,env);} else if(n->c) exec_stmt(n->c,env); return vundef();
        case NK_WHILE: exec_stmt(n,env); return vundef();
        case NK_DO: exec_stmt(n,env); return vundef();
        case NK_BREAK: g_flow=2; return vundef();
        case NK_CONTINUE: g_flow=3; return vundef();
        case NK_BLOCK: for(Node*s=n->a;s&&g_flow==0;s=s->next)exec_stmt(s,env); return vundef();
        case NK_VAR:
        case NK_EMPTY: return vundef();
        case NK_STMTS: for(Node*s=n->a;s&&g_flow==0;s=s->next) exec_stmt(s,env); return vundef();
        case NK_FOR: exec_stmt(n,env); return vundef();
        case NK_RETURN: { g_flow=1; g_flow_val = n->a? eval(n->a,env) : vundef(); return g_flow_val; }
        default: return vundef();
    }
}

static int eq_val(Val a, Val b){
    if(a.tag==V_NULL||a.tag==V_UNDEF||b.tag==V_NULL||b.tag==V_UNDEF)
        return (a.tag==V_NULL||a.tag==V_UNDEF)&&(b.tag==V_NULL||b.tag==V_UNDEF);
    if(a.tag==V_NUM||b.tag==V_NUM||a.tag==V_BOOL||b.tag==V_BOOL) return to_num(a)==to_num(b);
    if(a.tag==V_STR && b.tag==V_STR) return !xstrcmp(_str(a)->data,_str(b)->data);
    if(a.tag==V_OBJ&&b.tag==V_OBJ) return a.p==b.p;
    if(a.tag==V_ARR&&b.tag==V_ARR) return a.p==b.p;
    return 0;
}


static char g_errbuf[512];

static void set_err(const char* s){
    g_errbuf[0]=0;
    if(s){ u64 n=xstrlen(s); if(n>511)n=511; xmemcpy(g_errbuf,s,n); g_errbuf[n]=0; }
    g_had_error=1;
}
static void clear_err(void){ g_had_error=0; g_errbuf[0]=0; }

static int parse_program(const char* src, u64 len, Node** out){
    g_lex.src=src; g_lex.pos=0; g_lex.len=len;
    g_tok.kind=-1;   /* pre-first-token: '/' starts a regex literal */
    g_parse_abort=0; g_syn_stop[0]=0;
    next_tok();
    Node* prog=mkn(NK_BLOCK);
    Node** tail=&prog->a;
    while(!peek_is(T_EOF) && !g_parse_abort){
        Node* s=parse_stmt();
        *tail=s; tail=&s->next;
    }
    if(g_parse_abort || !g_had_error && g_lex.pos<g_lex.len){
        if(!g_had_error) set_err("parse error: unexpected input");
        return -1;
    }
    *out=prog;
    return 0;
}

static int js_exec(const char* src, u64 len){
    clear_err();
    Node* prog;
    if(parse_program(src,len,&prog)) return -1;
    g_flow=0; g_flow_val=vundef();
    exec_stmt(prog, g_global_env);
    return g_had_error?-1:0;
}
static int js_expr(const char* src, u64 len){
    clear_err();
    Node* prog;
    if(parse_program(src,len,&prog)) return -1;
    g_flow=0; g_flow_val=vundef();
    g_last_result=vundef();
    exec_stmt(prog, g_global_env);
    return g_had_error?-1:0;
}

/* Execute source in a given Env (module scope); does not touch global env. */
static int js_exec_in(const char* src, u64 len, Env* env){
    clear_err();
    Node* prog;
    if(parse_program(src,len,&prog)) return -1;
    g_flow=0; g_flow_val=vundef();
    exec_stmt(prog, env);
    return g_had_error?-1:0;
}

typedef enum {
    JS_OP_RESET=0, JS_OP_EXEC=1, JS_OP_EXPR=2, JS_OP_RESULT=3, JS_OP_ERROR=4, JS_OP_NUM=5,
    JS_OP_SET_HOST=6, JS_OP_HEAPSTAT=7, JS_OP_PUMP=8
} JsOp;

static void env_init_global(void){
    g_global_env=env_new(0);
    env_def(g_global_env,"NaN",vnum(0.0/0.0));
    env_def(g_global_env,"Infinity",vnum(1.0/0.0));
    {
        Val P=make_native_method("promise","ctor");
        if(P.tag!=V_UNDEF) env_def(g_global_env,"Promise",P);
    }
    {
        Val M=make_native_method("Map","ctor");
        if(M.tag!=V_UNDEF) env_def(g_global_env,"Map",M);
        Val S=make_native_method("Set","ctor");
        if(S.tag!=V_UNDEF) env_def(g_global_env,"Set",S);
        Val R=make_native_method("RegExp","ctor");
        if(R.tag!=V_UNDEF) env_def(g_global_env,"RegExp",R);
    }
}

long jsrt_entry(long op, long a1, long a2, long a3, long a4, long a5){
    (void)a4; (void)a5;
    switch(op){
        case JS_OP_RESET:
            arena_reset();
            env_init_global();
            g_mtq_head=0; g_mtq_tail=0; g_tmq_head=0; g_tmq_tail=0;
            g_async_await_nest=0; g_timer_seq=0;
            g_flow=0; g_depth=0; clear_err(); g_last_result=vundef();
            return 0;
        case JS_OP_SET_HOST:
            /* a1=slot index, a2=function pointer */
            if(a1>=0 && a1<HOST_COUNT){ g_host_fn[a1]=(host_fn_t)a2; return 0; }
            return -1;
        case JS_OP_EXEC:
        case JS_OP_EXPR:
            /* Lazy env init: runtime must not crash if host executes
               source without an explicit JS_OP_RESET first. */
            if(!g_global_env) env_init_global();
            /* Top-level safe point: reclaim + reuse heap, spread across calls
               so a long-running server never pauses longer than one short
               GC step (budgeted sweep, see heap_gc_step). */
            if(!g_gc_busy && (g_oom || h_off > JS_HEAP/2)) heap_gc_start();
            if(g_gc_busy) heap_gc_step();
            if(g_oom) return -1;
            if(op==JS_OP_EXEC){ js_exec((const char*)a1, (u64)a2); if(!g_had_error) master_pump(MAX_ASYNC_ITERS); return g_had_error?-1:0; }
            js_expr((const char*)a1, (u64)a2); if(!g_had_error) master_pump(MAX_ASYNC_ITERS); return g_had_error?-1:0;
        case JS_OP_PUMP:
            master_pump(a1>0? a1 : MAX_ASYNC_ITERS);
            return g_had_error?-1:0;
        case JS_OP_RESULT:
            return (long)val_to_buf((char*)a1,(u64)a2,g_last_result);
        case JS_OP_ERROR:
            { const char* s=g_errbuf; u64 n=xstrlen(s); if(n>(u64)a2-1)n=(u64)a2-1; xmemcpy((char*)a1,s,n); ((char*)a1)[n]=0; return (long)n; }
        case JS_OP_NUM:
            { Val v=g_last_result;
              if(v.tag!=V_NUM) return 0;
              if(v.num!=v.num || v.num==(double)(1.0/0.0) || v.num==(double)(-1.0/0.0)) return 0;
              return (long)v.num; }
        case JS_OP_HEAPSTAT:
            /* heap bytes in use (monitoring / GC stress) */
            return (long)h_off;
        default: return -1;
    }
}
