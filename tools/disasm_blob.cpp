// ============================================================================
// disasm_blob.cpp — freestanding x86-64 disassembler (Intel + AT&T syntax)
// ============================================================================
// Compiled by tools/gen_disasm_blob.sh into a position-independent blob
// (tools/disasm_blob.ld), embedded as src/disasm_blob.h and appended to the
// Zenith .text section of every binary that uses the disasm()/decompile()
// builtins. Zenith codegen calls into it via `call rel32` after staging args
// into rdi/rsi/rdx/rcx/r8/r9 (SysV), exactly like jsrt/tlsrt — a native
// disassembler lives INSIDE the language: no external tool, Apache-2.0 clean.
//
// Entry: disasm_entry(op, a1, a2, a3, a4, a5, s1, s2) -> rax
//   op 1  mass mode:
//       a1=dst a2=cap a3=src a4=srcLen a5=base  (s1=syntax, s2=flags)
//       Decodes the leading complete instructions of [src,srcLen), writes
//       "<addr>: instr\n" lines (or plain lines when flag bit0 is 0) into dst
//       up to cap bytes. Returns 0 when everything fit, else the number of
//       output bytes required. syntax: 0=Intel 1=AT&T.
//   op 2  single-instruction mode:
//       a1=dst a2=cap a3=src a4=srcLen a5=addr (base/addr) (s1=syntax)
//       Decodes exactly one instruction. Returns its byte length (>0), or 0
//       on truncation / undecodable data.
// ============================================================================

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef int s32;

// ---- small builder ----
typedef struct { char* out; int cap; int len; } Blob;
static void bC(Blob* b, char c) { if (b->len < b->cap) b->out[b->len] = c; b->len++; }
static void bS(Blob* b, const char* s) { while (*s) bC(b, *s++); }
static void bHex(Blob* b, u64 v, int upper) {
    char tmp[20]; int n = 0;
    if (v == 0) { bC(b, '0'); return; }
    while (v) { int d = (int)(v & 15); tmp[n++] = (char)(d < 10 ? '0'+d : (upper ? 'A' : 'a') + d - 10); v >>= 4; }
    while (n) bC(b, tmp[--n]);
}
static void b0x(Blob* b, u64 v) { bS(b, "0x"); bHex(b, v, 0); }
static void b0xU(Blob* b, u64 v) { bS(b, "0x"); bHex(b, v, 1); }

static s32 sg8(u8 v)   { return (v & 0x80) ? (s32)v - 256 : (s32)v; }
static s64 sg32(u32 v) { return (v & 0x80000000u) ? (s64)(s32)v : (s64)v; }

// ---- register names (fixed-stride arrays: pointer-free, position-independent) ----
typedef struct { char b[8]; } S8;
static const S8 R64[16] = {
    {{'r','a','x'}},{{'r','c','x'}},{{'r','d','x'}},{{'r','b','x'}},
    {{'r','s','p'}},{{'r','b','p'}},{{'r','s','i'}},{{'r','d','i'}},
    {{'r','8'}},{{'r','9'}},{{'1','0'}},{{'r','1','1'}},
    {{'r','1','2'}},{{'r','1','3'}},{{'r','1','4'}},{{'r','1','5'}},
};
static const S8 R32[16] = {
    {{'e','a','x'}},{{'e','c','x'}},{{'e','d','x'}},{{'e','b','x'}},
    {{'e','s','p'}},{{'e','b','p'}},{{'e','s','i'}},{{'e','d','i'}},
    {{'r','8','d'}},{{'r','9','d'}},{{'r','1','0','d'}},{{'r','1','1','d'}},
    {{'r','1','2','d'}},{{'r','1','3','d'}},{{'r','1','4','d'}},{{'r','1','5','d'}},
};
static const S8 R16[16] = {
    {{'a','x'}},{{'c','x'}},{{'d','x'}},{{'b','x'}},
    {{'s','p'}},{{'b','p'}},{{'s','i'}},{{'d','i'}},
    {{'r','8','w'}},{{'r','9','w'}},{{'r','1','0','w'}},{{'r','1','1','w'}},
    {{'r','1','2','w'}},{{'r','1','3','w'}},{{'r','1','4','w'}},{{'r','1','5','w'}},
};
static const S8 R8N[16] = {
    {{'a','l'}},{{'c','l'}},{{'d','l'}},{{'b','l'}},
    {{'s','p','l'}},{{'b','p','l'}},{{'s','i','l'}},{{'d','i','l'}},
    {{'r','8','b'}},{{'r','9','b'}},{{'r','1','0','b'}},{{'r','1','1','b'}},
    {{'r','1','2','b'}},{{'r','1','3','b'}},{{'r','1','4','b'}},{{'r','1','5','b'}},
};
static const S8 R8H[4] = {{'a','h'},{'c','h'},{'d','h'},{'b','h'}};
static const S8 SEG[6] = {{'e','s'},{'c','s'},{'s','s'},{'d','s'},{'f','s'},{'g','s'}};
static const S8 ALU[8] = {{'a','d','d'},{'o','r'},{'a','d','c'},{'s','b','b'},
                          {'a','n','d'},{'s','u','b'},{'x','o','r'},{'c','m','p'}};
static const S8 JCC[16] = {{'j','o'},{'j','n','o'},{'j','b'},{'j','a','e'},{'j','e'},{'j','n','e'},
                           {'j','b','e'},{'j','a'},{'j','s'},{'j','n','s'},{'j','p'},{'j','n','p'},
                           {'j','l'},{'j','g','e'},{'j','l','e'},{'j','g'}};
static const S8 SCC[16] = {{'s','e','t','o'},{'s','e','t','n','o'},{'s','e','t','b'},{'s','e','t','a','e'},
                           {'s','e','t','e'},{'s','e','t','n','e'},{'s','e','t','b','e'},{'s','e','t','a'},
                           {'s','e','t','s'},{'s','e','t','n','s'},{'s','e','t','p'},{'s','e','t','n','p'},
                           {'s','e','t','l'},{'s','e','t','g','e'},{'s','e','t','l','e'},{'s','e','t','g'}};
static const S8 CMC[16] = {{'c','m','o','v','o'},{'c','m','o','v','n','o'},{'c','m','o','v','b'},{'c','m','o','v','a','e'},
                           {'c','m','o','v','e'},{'c','m','o','v','n','e'},{'c','m','o','v','b','e'},{'c','m','o','v','a'},
                           {'c','m','o','v','s'},{'c','m','o','v','n','s'},{'c','m','o','v','p'},{'c','m','o','v','n','p'},
                           {'c','m','o','v','l'},{'c','m','o','v','g','e'},{'c','m','o','v','l','e'},{'c','m','o','v','g'}};
static const S8 GRP2[8] = {{'r','o','l'},{'r','o','r'},{'r','c','l'},{'r','c','r'},{'s','h','l'},{'s','h','r'},{'s','a','r'},{'s','a','r'}};
static const S8 BTX[4] = {{'b','t'},{'b','t','s'},{'b','t','r'},{'b','t','c'}};
static const S8 UNXN[8] = {{},{},{'n','o','t'},{'n','e','g'},{'m','u','l'},{'i','m','u','l'},{'d','i','v'},{'i','d','i','v'}};

// copy a fixed-stride table string into a Blob
static void bT(Blob* b, const S8* t, int i) {
    const char* p = t[i].b;
    while (*p) bC(b, *p++);
}
static const S8 GRPU[8] = {{'i','n','c'},{'d','e','c'},{'c','a','l','l'},{'c','a','l','l'},
                           {'j','m','p'},{'j','m','p'},{'p','u','s','h'},{}};

typedef struct {
    int rex;    // raw REX byte (0 = none)
    int rexw;   // REX.W bit
    int opsz;   // operand size in bytes: 1/2/4/8
    int f2, f3; // F2 / F3 prefixes
    int s66;
} Pref;

static void regName(Blob* b, int r, int sz, int rex) {
    if (sz == 1) {
        if (!rex && r < 4 && !(r & 4)) bT(b, R8H, r & 3);
        else bT(b, R8N, r);
    } else if (sz == 2) bT(b, R16, r);
    else if (sz == 4) bT(b, R32, r);
    else bT(b, R64, r);
}
static void segName(Blob* b, int v) { bT(b, SEG, v & 5); }

// ---- decoder ----
typedef struct {
    u8* ip;
    u8* ipEnd;
    u64 va;
    Pref p;
} Dec;

static int rd8(Dec* d, int* ok) {
    if (d->ip + 1 > d->ipEnd) { *ok = 0; return 0; }
    *ok = 1; u8 v = *d->ip++; d->va++;
    return v;
}
static u16 rd16(Dec* d, int* ok) {
    u8 a = rd8(d, ok); if (!*ok) return 0;
    u8 c = rd8(d, ok); if (!*ok) return 0;
    return (u16)(a | (c << 8));
}
static u32 rd32(Dec* d, int* ok) {
    u32 v = 0;
    for (int i = 0; i < 4; i++) { u8 c = rd8(d, ok); if (!*ok) return 0; v |= (u32)c << (8*i); }
    return v;
}
static u64 rd64(Dec* d, int* ok) {
    u64 v = 0;
    for (int i = 0; i < 8; i++) { u8 c = rd8(d, ok); if (!*ok) return 0; v |= (u64)c << (8*i); }
    return v;
}

// ---- ModRM / SIB ----
typedef struct {
    int mod, reg, rm;
    int base, idx, scale;
    int rip;
    s32 disp;
    int hasDisp;
} ModRM;

static void rdSib(Dec* d, ModRM* m, int* ok) {
    u8 s = rd8(d, ok); if (!*ok) return;
    m->scale = 1 << ((s >> 6) & 3);
    m->idx = ((s >> 3) & 7) | (((d->p.rex >> 2) & 1) << 3);
    m->base = (s & 7) | ((d->p.rex & 1) << 3);
    if (m->idx == 4) m->idx = -1;
    if (m->mod == 0 && m->base == 5) { m->disp = (s32)rd32(d, ok); m->base = -1; m->rip = 0; m->hasDisp = 1; }
    else if (m->mod == 1) { m->disp = sg8(rd8(d, ok)); m->hasDisp = 1; }
    else if (m->mod == 2) { m->disp = (s32)rd32(d, ok); m->hasDisp = 1; }
}

static void rdModRM(Dec* d, ModRM* m, int* ok) {
    u8 b = rd8(d, ok); if (!*ok) return;
    m->mod = (b >> 6) & 3;
    m->reg = ((b >> 3) & 7) | (((d->p.rex >> 2) & 1) << 3);
    m->rm  = (b & 7) | ((d->p.rex & 1) << 3);
    m->base = -1; m->idx = -1; m->scale = 1; m->rip = 0; m->hasDisp = 0; m->disp = 0;
    if (m->mod == 3) return;
    if (m->rm == 4) { rdSib(d, m, ok); return; }
    if (m->mod == 0 && m->rm == 5) { m->disp = (s32)rd32(d, ok); m->rip = 1; m->hasDisp = 1; }
    else if (m->mod == 0) { m->base = m->rm; }
    else if (m->mod == 1) { m->disp = sg8(rd8(d, ok)); m->base = m->rm; m->hasDisp = 1; }
    else { m->disp = (s32)rd32(d, ok); m->base = m->rm; m->hasDisp = 1; }
}

// ---- mode (globals live in .data, blob layout covers .data) ----
static int g_intel = 1;
static int g_addrPfx = 1;
static void modeSet(int syntax, int withAddr) { g_intel = (syntax == 0); g_addrPfx = withAddr; }

// ---- memory operand printing (Intel [..] / AT&T disp(base,idx*sc)) ----
static void printMem(Blob* b, Dec* d, ModRM* m) {
    if (g_intel) bC(b, '[');
    if (m->rip) {
        u64 t = d->va + (s64)m->disp;
        bS(b, "rip");
        bC(b, '+'); b0x(b, t);
    } else {
        int written = 0;
        if (m->base >= 0) {
            if (!g_intel) bC(b, '%');
            bT(b, R64, m->base);
            written = 1;
        }
        if (m->idx >= 0) {
            if (written) bC(b, '+');
            if (!g_intel) bC(b, '%');
            bT(b, R64, m->idx);
            if (m->scale > 1) { bC(b, '*'); bHex(b, (u64)m->scale, 1); }
            written = 1;
        }
        if (m->hasDisp && m->disp != 0) {
            s64 disp = (s64)m->disp;
            if (disp < 0) { bC(b, '-'); b0x(b, (u64)(-disp)); }
            else {
                if (written) bC(b, '+');
                b0x(b, (u64)disp);
            }
            written = 1;
        }
        if (!written) bS(b, "0");
    }
    if (g_intel) bC(b, ']');
}
static void printRm(Blob* b, Dec* d, ModRM* m, int sz) {
    if (m->mod == 3) regName(b, m->rm, sz, d->p.rex);
    else printMem(b, d, m);
}
static void printImm(Blob* b, u64 v) {
    if (!g_intel) bC(b, '$');
    b0x(b, v);
}
static void printImmSgn(Blob* b, s64 v) {
    if (!g_intel) bC(b, '$');
    if (v < 0) { bC(b, '-'); b0x(b, (u64)(-v)); }
    else b0x(b, (u64)v);
}
static void printAcc(Blob* b, const char* acc) {
    if (g_intel) bS(b, acc);
    else { bC(b, '%'); bS(b, acc); }
}
// accumulator names, pointer-free
static const S8 ACC[3] = {{'r','a','x'},{'a','x'},{'e','a','x'}};
// register-name of mnemonic for 0x63 (R64-Ed)
static void accOf(Blob* b, int sz) { bT(b, ACC, sz == 8 ? 0 : sz == 2 ? 1 : 2); }

// ============================================================================
// instruction groups
// ============================================================================
// op 0x00-0x3D: form = op & 7
//   0 rm8,r8  1 rm,r  2 r8,rm8  3 r,rm  4 al,imm8  5 acc,imm
static int dec_grp1(Dec* d, Blob* b, u8 op) {
    // mnemonic: ALU[(op>>3)&7]
    int form = op & 7;
    ModRM m; int ok = 1;
    if (form == 4) {
        int v = rd8(d, &ok); if (!ok) return 0;
        if (g_intel) { bT(b, ALU, (op >> 3) & 7); bS(b, " al, "); b0x(b, v); }
        else { bT(b, ALU, (op >> 3) & 7); bS(b, " $"); b0x(b, v); bS(b, ", %al"); }
        return 1;
    }
    if (form == 5) {
        u64 iv;
        if (d->p.opsz == 8) iv = sg32(rd32(d, &ok));
        else if (d->p.opsz == 2) iv = rd16(d, &ok);
        else iv = rd32(d, &ok);
        if (!ok) return 0;
        if (g_intel) { bT(b, ALU, (op >> 3) & 7); bC(b, ' '); accOf(b, d->p.opsz); bS(b, ", "); printImmSgn(b, (s64)(s32)iv); }
        else { bT(b, ALU, (op >> 3) & 7); bC(b, ' '); printImmSgn(b, (s64)(s32)iv); bS(b, ", %"); accOf(b, d->p.opsz); }
        return 1;
    }
    rdModRM(d, &m, &ok); if (!ok) return 0;
    int sz = (form == 0 || form == 2) ? 1 : d->p.opsz;
    if (g_intel) {
        bT(b, ALU, (op >> 3) & 7); bC(b, ' ');
        if (form == 0 || form == 1) { printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
        else { regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
    } else {
        bT(b, ALU, (op >> 3) & 7); bC(b, ' ');
        if (form == 2 || form == 3) { regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
        else { printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
    }
    return 1;
}

// 0x80-0x83: ALU rm, imm
static int dec_grp1imm(Dec* d, Blob* b, u8 op) {
    ModRM m; int ok = 1;
    rdModRM(d, &m, &ok); if (!ok) return 0;
    const int mng = m.reg & 7;
    int sz = (op == 0x80 || op == 0x82) ? 1 : d->p.opsz;
    s64 immVal;
    if (op == 0x80 || op == 0x82) immVal = sg8(rd8(d, &ok));
    else if (op == 0x83) immVal = sg8(rd8(d, &ok));
    else if (d->p.opsz == 8) immVal = sg32(rd32(d, &ok));
    else if (d->p.opsz == 2) immVal = rd16(d, &ok);
    else immVal = rd32(d, &ok);
    if (!ok) return 0;
    if (g_intel) { bT(b, ALU, mng); bC(b, ' '); printRm(b, d, &m, sz); bS(b, ", "); printImmSgn(b, immVal); }
    else { bT(b, ALU, mng); bC(b, ' '); printImmSgn(b, immVal); bS(b, ", "); printRm(b, d, &m, sz); }
    return 1;
}

// 0xC0/C1/D0/D1/D2/D3 shift/rotate
static int dec_grp2(Dec* d, Blob* b, u8 op) {
    ModRM m; int ok = 1;
    rdModRM(d, &m, &ok); if (!ok) return 0;
    const int mng = m.reg & 7;
    int sz = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : d->p.opsz;
    if (g_intel) {
        bT(b, GRP2, mng); bC(b, ' '); printRm(b, d, &m, sz);
        if (op == 0xC0 || op == 0xC1) { int v = rd8(d, &ok); if (!ok) return 0; bS(b, ", "); b0x(b, v); }
        else if (op == 0xD0 || op == 0xD1) bS(b, ", 1");
        else bS(b, ", cl");
    } else {
        bT(b, GRP2, mng); bC(b, ' ');
        if (op == 0xC0 || op == 0xC1) { int v = rd8(d, &ok); if (!ok) return 0; bS(b, "$"); b0x(b, v); bS(b, ", "); }
        else if (op == 0xD0 || op == 0xD1) bS(b, "$1, ");
        else bS(b, "%cl, ");
        printRm(b, d, &m, sz);
    }
    return 1;
}

// 0xF6/0xF7
static void dec_unary(Blob* b, const S8* tab, int i, Dec* d, ModRM* m, int sz) {
    bT(b, tab, i); bC(b, ' '); printRm(b, d, m, sz);
}
static int dec_grp3(Dec* d, Blob* b, u8 op) {
    ModRM m; int ok = 1;
    rdModRM(d, &m, &ok); if (!ok) return 0;
    int sz = (op == 0xF6) ? 1 : d->p.opsz;
    int g = m.reg & 7;
    if (g == 0 || g == 1) {
        s64 immVal;
        if (op == 0xF6) immVal = rd8(d, &ok);
        else if (d->p.opsz == 8) immVal = sg32(rd32(d, &ok));
        else if (d->p.opsz == 2) immVal = rd16(d, &ok);
        else immVal = rd32(d, &ok);
        if (!ok) return 0;
        if (g_intel) { bS(b, "test "); printRm(b, d, &m, sz); bS(b, ", "); printImmSgn(b, immVal); }
        else { bS(b, "test "); printImmSgn(b, immVal); bS(b, ", "); printRm(b, d, &m, sz); }
    } else {
        dec_unary(b, UNXN, g, d, &m, sz);
    }
    return 1;
}

static int dec_grpFE(Dec* d, Blob* b) {
    ModRM m; int ok = 1;
    rdModRM(d, &m, &ok); if (!ok) return 0;
    int g = m.reg & 7;
    if (g == 0) dec_unary(b, GRPU, 0, d, &m, 1);
    else if (g == 1) dec_unary(b, GRPU, 1, d, &m, 1);
    else return 0;
    return 1;
}
static int dec_grpFF(Dec* d, Blob* b) {
    ModRM m; int ok = 1;
    rdModRM(d, &m, &ok); if (!ok) return 0;
    int g = m.reg & 7;
    switch (g) {
        case 0: dec_unary(b, GRPU, 0, d, &m, d->p.opsz); break;
        case 1: dec_unary(b, GRPU, 1, d, &m, d->p.opsz); break;
        case 2: dec_unary(b, GRPU, 2, d, &m, 8); break;
        case 4: dec_unary(b, GRPU, 4, d, &m, 8); break;
        case 6: dec_unary(b, GRPU, 6, d, &m, 8); break;
        default: return 0;
    }
    return 1;
}

// ============================================================================
// two-byte opcodes (0F xx)
// ============================================================================
static int dec_two(Dec* d, Blob* b, u8 op2) {
    ModRM m; int ok = 1;
    switch (op2) {
        case 0x05: bS(b, "syscall"); return 1;
        case 0x07: bS(b, "sysret"); return 1;
        case 0x0B: bS(b, "ud2"); return 1;
        case 0x1F:
            rdModRM(d, &m, &ok); if (!ok) return 0;
            bS(b, "nop");
            if (m.mod != 3) { bC(b, ' '); printRm(b, d, &m, d->p.opsz); }
            return 1;
        case 0x31: bS(b, "rdtsc"); return 1;
        case 0x34: bS(b, "sysenter"); return 1;
        case 0x35: bS(b, "sysexit"); return 1;
        case 0xA2: bS(b, "cpuid"); return 1;
        case 0xB1: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "cmpxchg "); printRm(b, d, &m, d->p.opsz); bS(b, ", "); regName(b, m.reg, d->p.opsz, d->p.rex); }
            else { bS(b, "cmpxchg "); regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz); }
            return 1;
        }
        case 0xC0: case 0xC1: {
            int sz = (op2 == 0xC0) ? 1 : d->p.opsz;
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "xadd "); printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
            else { bS(b, "xadd "); regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
            return 1;
        }
        case 0xA3: case 0xAB: case 0xB3: case 0xBB: {
            int idx = (op2 == 0xA3) ? 0 : (op2 == 0xAB) ? 1 : (op2 == 0xB3) ? 2 : 3;
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bT(b, BTX, idx); bC(b, ' '); printRm(b, d, &m, d->p.opsz); bS(b, ", "); regName(b, m.reg, d->p.opsz, d->p.rex); }
            else { bT(b, BTX, idx); bC(b, ' '); regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz); }
            return 1;
        }
        case 0xBA: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            int v = rd8(d, &ok); if (!ok) return 0;
            int gi = m.reg & 3;
            if (g_intel) { bT(b, BTX, gi); bC(b, ' '); printRm(b, d, &m, d->p.opsz); bS(b, ", "); b0x(b, v); }
            else { bT(b, BTX, gi); bS(b, " $"); b0x(b, v); bS(b, ", "); printRm(b, d, &m, d->p.opsz); }
            return 1;
        }
        case 0xAF: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "imul "); regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz); }
            else { bS(b, "imul "); printRm(b, d, &m, d->p.opsz); bS(b, ", "); regName(b, m.reg, d->p.opsz, d->p.rex); }
            return 1;
        }
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: {
            int z = (op2 == 0xB6 || op2 == 0xB7);
            int srcSz = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
            int dstSz = d->p.rexw ? 8 : 4;
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (z) { if (g_intel) { bS(b, "movzx "); regName(b, m.reg, dstSz, d->p.rex); bS(b, ", "); printRm(b, d, &m, srcSz); }
                     else { bS(b, "movzx "); printRm(b, d, &m, srcSz); bS(b, ", "); regName(b, m.reg, dstSz, d->p.rex); } }
            else   { if (g_intel) { bS(b, "movsx "); regName(b, m.reg, dstSz, d->p.rex); bS(b, ", "); printRm(b, d, &m, srcSz); }
                     else { bS(b, "movsx "); printRm(b, d, &m, srcSz); bS(b, ", "); regName(b, m.reg, dstSz, d->p.rex); } }
            return 1;
        }
        case 0xBC: case 0xBD: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (d->p.f3 && op2 == 0xBD) bS(b, "lzcnt ");
            else if (d->p.f3 && op2 == 0xBC) bS(b, "tzcnt ");
            else bS(b, (op2 == 0xBD) ? "bsr " : "bsf ");
            regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz);
            return 1;
        }
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
            int r = (op2 - 0xC8) | ((d->p.rex & 1) << 3);
            bS(b, "bswap "); regName(b, r, 4, d->p.rex);
            return 1;
        }
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            bT(b, CMC, op2 - 0x40); bC(b, ' ');
            regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz);
            return 1;
        }
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            bT(b, SCC, op2 - 0x90); bC(b, ' '); printRm(b, d, &m, 1);
            return 1;
        }
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
            s64 rel = sg32(rd32(d, &ok)); if (!ok) return 0;
            u64 t = d->va + rel;
            bT(b, JCC, op2 - 0x80); bC(b, ' '); b0x(b, t);
            return 1;
        }
        case 0x01: {
            u8 m2 = rd8(d, &ok); if (!ok) return 0;
            int reg = (m2 >> 3) & 7;
            ModRM m3; m3.mod = (m2 >> 6) & 3; m3.reg = 0; m3.rm = m2 & 7;
            m3.base = -1; m3.idx = -1; m3.scale = 1; m3.rip = 0; m3.hasDisp = 0; m3.disp = 0;
            const char* nm = 0;
            switch (reg) {
                case 0: nm = "sgdt"; break;
                case 1: nm = "sidt"; break;
                case 2: nm = "lgdt"; break;
                case 3: nm = "lidt"; break;
                case 4: nm = "smsw"; break;
                case 6: nm = "lmsw"; break;
                default: return 0;
            }
            if (m3.mod == 3) {
                bS(b, nm); bC(b, ' '); regName(b, m3.rm, 8, d->p.rex);
            } else {
                m3.base = m3.rm;
                if (m3.rm == 4) { m3.base = -1; rdSib(d, &m3, &ok); if (!ok) return 0; }
                bS(b, nm); bC(b, ' '); printMem(b, d, &m3);
            }
            return 1;
        }
        default:
            return 0;
    }
}

// ============================================================================
// single-byte opcode dispatch
// ============================================================================
static int decodeOne(Dec* d, Blob* b) {
    int ok = 1;
    u8 op = rd8(d, &ok);
    if (!ok) return 0;
    int sz, v;
    ModRM m;
    s64 rel;
    u64 iv;

    // arithmetic 0x00-0x3D
    if (op <= 0x3D && ((op >> 3) & 7) <= 7 && (op & 7) <= 5)
        return dec_grp1(d, b, op);

    switch (op) {
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {
            int r = (op - 0x50) | ((d->p.rex & 1) << 3);
            bS(b, "push "); regName(b, r, 8, d->p.rex);
            return 1;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            int r = (op - 0x58) | ((d->p.rex & 1) << 3);
            bS(b, "pop "); regName(b, r, 8, d->p.rex);
            return 1;
        }
        case 0x68: { u32 vv = rd32(d, &ok); if (!ok) return 0;
            bS(b, "push "); printImmSgn(b, sg32(vv)); return 1; }
        case 0x6A: { v = rd8(d, &ok); if (!ok) return 0;
            bS(b, "push "); printImmSgn(b, sg8(v)); return 1; }
        case 0x69: case 0x6B: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            s64 immVal;
            if (op == 0x6B) immVal = sg8(rd8(d, &ok));
            else if (d->p.opsz == 8) immVal = sg32(rd32(d, &ok));
            else if (d->p.opsz == 2) immVal = rd16(d, &ok);
            else immVal = rd32(d, &ok);
            if (!ok) return 0;
            if (g_intel) { bS(b, "imul "); regName(b, m.reg, d->p.opsz, d->p.rex); bS(b, ", "); printRm(b, d, &m, d->p.opsz); bS(b, ", "); printImmSgn(b, immVal); }
            else { bS(b, "imul "); printImmSgn(b, immVal); bS(b, ", "); printRm(b, d, &m, d->p.opsz); bS(b, ", "); regName(b, m.reg, d->p.opsz, d->p.rex); }
            return 1;
        }
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            rel = sg8(rd8(d, &ok)); if (!ok) return 0;
            u64 t = d->va + rel;
            bT(b, JCC, op - 0x70); bC(b, ' '); b0x(b, t);
            return 1;
        }
        case 0x80: case 0x81: case 0x82: case 0x83:
            return dec_grp1imm(d, b, op);
        case 0x84: case 0x85: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            sz = (op == 0x84) ? 1 : d->p.opsz;
            if (g_intel) { bS(b, "test "); printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
            else { bS(b, "test "); regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
            return 1;
        }
        case 0x86: case 0x87: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            sz = (op == 0x86) ? 1 : d->p.opsz;
            if (g_intel) { bS(b, "xchg "); printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
            else { bS(b, "xchg "); regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
            return 1;
        }
        case 0x88: case 0x89: case 0x8A: case 0x8B: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            sz = (op == 0x88 || op == 0x8A) ? 1 : d->p.opsz;
            if (op == 0x88 || op == 0x89) {
                if (g_intel) { bS(b, "mov "); printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
                else { bS(b, "mov "); regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
            } else {
                if (g_intel) { bS(b, "mov "); regName(b, m.reg, sz, d->p.rex); bS(b, ", "); printRm(b, d, &m, sz); }
                else { bS(b, "mov "); printRm(b, d, &m, sz); bS(b, ", "); regName(b, m.reg, sz, d->p.rex); }
            }
            return 1;
        }
        case 0x8C: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "mov "); printRm(b, d, &m, 2); bS(b, ", "); segName(b, m.reg); }
            else { bS(b, "mov "); segName(b, m.reg); bS(b, ", "); printRm(b, d, &m, 2); }
            return 1;
        }
        case 0x8D: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (m.mod == 3) return 0;
            int dstSz = d->p.rexw ? 8 : 4;
            if (g_intel) { bS(b, "lea "); regName(b, m.reg, dstSz, d->p.rex); bS(b, ", "); printMem(b, d, &m); }
            else { bS(b, "lea "); printMem(b, d, &m); bS(b, ", "); regName(b, m.reg, dstSz, d->p.rex); }
            return 1;
        }
        case 0x8E: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "mov "); segName(b, m.reg); bS(b, ", "); printRm(b, d, &m, 2); }
            else { bS(b, "mov "); printRm(b, d, &m, 2); bS(b, ", "); segName(b, m.reg); }
            return 1;
        }
        case 0x8F: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            bS(b, "pop "); printRm(b, d, &m, 8);
            return 1;
        }
        case 0x90: bS(b, "nop"); return 1;
        case 0x98:
            if (d->p.rexw) bS(b, "cdqe");
            else bS(b, "cwde");
            return 1;
        case 0x99:
            if (d->p.rexw) bS(b, "cqo");
            else bS(b, "cdq");
            return 1;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            sz = (op == 0xA0 || op == 0xA2) ? 1 : d->p.opsz;
            u64 off = d->p.s66 ? 0 : rd64(d, &ok); if (!ok) return 0;
            int toAcc = (op == 0xA0 || op == 0xA1);
            int zx = (op == 0xA0 || op == 0xA2);
            if (g_intel) {
                bS(b, "mov ");
                if (toAcc) { if (zx) bS(b, "al"); else accOf(b, sz); bS(b, ", ["); b0x(b, off); bS(b, "]"); }
                else { bS(b, "["); b0x(b, off); bS(b, "], "); if (zx) bS(b, "al"); else accOf(b, sz); }
            } else {
                bS(b, "mov ");
                if (toAcc) { printImm(b, off); bS(b, ", "); bS(b, zx ? "al" : ""); if (!zx) accOf(b, sz); }
                else { bS(b, zx ? "al" : ""); if (!zx) accOf(b, sz); bS(b, ", "); printImm(b, off); }
            }
            return 1;
        }
        case 0xA4: bS(b, "movsb"); return 1;
        case 0xA5: bS(b, (d->p.opsz == 8) ? "movsq" : "movsl"); return 1;
        case 0xA6: bS(b, "cmpsb"); return 1;
        case 0xA7: bS(b, (d->p.opsz == 8) ? "cmpsq" : "cmpsl"); return 1;
        case 0xAA: bS(b, "stosb"); return 1;
        case 0xAB: bS(b, (d->p.opsz == 8) ? "stosq" : "stosl"); return 1;
        case 0xAC: bS(b, "lodsb"); return 1;
        case 0xAD: bS(b, (d->p.opsz == 8) ? "lodsq" : "lodsl"); return 1;
        case 0xAE: bS(b, "scasb"); return 1;
        case 0xAF: bS(b, (d->p.opsz == 8) ? "scasq" : "scasl"); return 1;
        case 0xA8: {
            v = rd8(d, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "test al, "); b0x(b, v); }
            else { bS(b, "test $"); b0x(b, v); bS(b, ", %al"); }
            return 1;
        }
        case 0xA9: {
            s64 ivv;
            if (d->p.opsz == 8) ivv = sg32(rd32(d, &ok));
            else if (d->p.opsz == 2) ivv = rd16(d, &ok);
            else ivv = rd32(d, &ok);
            if (!ok) return 0;
            if (g_intel) { bS(b, "test "); accOf(b, d->p.opsz == 8 ? 8 : 4); bS(b, ", "); printImmSgn(b, ivv); }
            else { bS(b, "test "); printImmSgn(b, ivv); bS(b, ", %"); accOf(b, d->p.opsz == 8 ? 8 : 4); }
            return 1;
        }
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
            int r = (op - 0xB0) | ((d->p.rex & 1) << 3);
            v = rd8(d, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "mov "); regName(b, r, 1, d->p.rex); bS(b, ", "); b0x(b, v); }
            else { bS(b, "movb $"); b0x(b, v); bS(b, ", "); regName(b, r, 1, d->p.rex); }
            return 1;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            int r = (op - 0xB8) | ((d->p.rex & 1) << 3);
            if (d->p.opsz == 8) iv = rd64(d, &ok);
            else if (d->p.opsz == 2) iv = rd16(d, &ok);
            else iv = rd32(d, &ok);
            if (!ok) return 0;
            if (g_intel) { bS(b, "mov "); regName(b, r, d->p.opsz, d->p.rex); bS(b, ", "); b0x(b, iv); }
            else { bS(b, "movq $"); b0x(b, iv); bS(b, ", "); regName(b, r, 8, d->p.rex); }
            return 1;
        }
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            return dec_grp2(d, b, op);
        case 0xC2: {
            u16 n = rd16(d, &ok); if (!ok) return 0;
            if (g_intel) { bS(b, "ret 0x"); bHex(b, n, 0); }
            else { bS(b, "ret $"); bHex(b, n, 0); }
            return 1;
        }
        case 0xC3: bS(b, "ret"); return 1;
        case 0xC6: case 0xC7: {
            rdModRM(d, &m, &ok); if (!ok) return 0;
            sz = (op == 0xC6) ? 1 : d->p.opsz;
            s64 immVal;
            if (op == 0xC6) immVal = sg8(rd8(d, &ok));
            else if (d->p.opsz == 8) immVal = sg32(rd32(d, &ok));
            else if (d->p.opsz == 2) immVal = rd16(d, &ok);
            else immVal = rd32(d, &ok);
            if (!ok) return 0;
            const char* suf = sz == 1 ? "b" : sz == 2 ? "w" : sz == 4 ? "l" : "q";
            if (g_intel) { bS(b, "mov "); printRm(b, d, &m, sz); bS(b, ", "); printImmSgn(b, immVal); }
            else { bS(b, "mov"); bS(b, suf); bC(b, ' '); printImmSgn(b, immVal); bS(b, ", "); printRm(b, d, &m, sz); }
            return 1;
        }
        case 0xC9: bS(b, "leave"); return 1;
        case 0xCC: bS(b, "int3"); return 1;
        case 0xCD: { v = rd8(d, &ok); if (!ok) return 0;
            bS(b, "int 0x"); bHex(b, v, 0); return 1; }
        case 0xE8: { rel = sg32(rd32(d, &ok)); if (!ok) return 0;
            bS(b, "call 0x"); bHex(b, d->va + rel, 0); return 1; }
        case 0xE9: { rel = sg32(rd32(d, &ok)); if (!ok) return 0;
            bS(b, "jmp 0x"); bHex(b, d->va + rel, 0); return 1; }
        case 0xEB: { rel = sg8(rd8(d, &ok)); if (!ok) return 0;
            bS(b, "jmp 0x"); bHex(b, d->va + rel, 0); return 1; }
        case 0xEC: bS(b, "in al, dx"); return 1;
        case 0xED: bS(b, "in eax, dx"); return 1;
        case 0xEE: bS(b, "out dx, al"); return 1;
        case 0xEF: bS(b, "out dx, eax"); return 1;
        case 0xF4: bS(b, "hlt"); return 1;
        case 0xF5: bS(b, "cmc"); return 1;
        case 0xF6: case 0xF7: return dec_grp3(d, b, op);
        case 0xF8: bS(b, "clc"); return 1;
        case 0xF9: bS(b, "stc"); return 1;
        case 0xFA: bS(b, "cli"); return 1;
        case 0xFB: bS(b, "sti"); return 1;
        case 0xFC: bS(b, "cld"); return 1;
        case 0xFD: bS(b, "std"); return 1;
        case 0xFE: return dec_grpFE(d, b);
        case 0xFF: return dec_grpFF(d, b);
        case 0x0F: {
            u8 op2 = rd8(d, &ok); if (!ok) return 0;
            return dec_two(d, b, op2);
        }
        case 0x63:
            if (d->p.rexw) { rdModRM(d, &m, &ok); if (!ok) return 0; bS(b, "movsxd "); regName(b, m.reg, 8, d->p.rex); bS(b, ", "); printRm(b, d, &m, 4); }
            else return 0;
            return 1;
        default:
            return 0;
    }
}

// ============================================================================
// full instruction decode (prefix scan + dispatch) — returns byte length
// ============================================================================
static int decodeInstr(Dec* d, Blob* b) {
    u8* save = d->ip;
    u64 saveVa = d->va;
    int opsz = 4;
    int saw66 = 0, sawf2 = 0, sawf3 = 0, rexV = 0;
    for (;;) {
        if (d->ip >= d->ipEnd) return 0;
        u8 v = *d->ip;
        if (v == 0x66) { saw66 = 1; d->ip++; d->va++; }
        else if (v == 0x67) { d->ip++; d->va++; }
        else if (v == 0xF0) { d->ip++; d->va++; }
        else if (v == 0xF2) { sawf2 = 1; d->ip++; d->va++; }
        else if (v == 0xF3) { sawf3 = 1; d->ip++; d->va++; }
        else if (v == 0x26 || v == 0x2E || v == 0x36 || v == 0x3E || v == 0x64 || v == 0x65) { d->ip++; d->va++; }
        else break;
    }
    if (d->ip < d->ipEnd && (*d->ip & 0xF0) == 0x40) { rexV = *d->ip; d->ip++; d->va++; }
    d->p.rex = rexV;
    d->p.rexw = (rexV & 8) ? 1 : 0;
    if (d->p.rexw) opsz = 8; else if (saw66) opsz = 2;
    d->p.opsz = opsz;
    d->p.f2 = sawf2;
    d->p.f3 = sawf3;
    d->p.s66 = saw66;

    if (g_addrPfx) { b0x(b, saveVa); bS(b, ": "); }
    if (!decodeOne(d, b)) {
        // undecodable: emit the first byte as a db literal
        if (save + 1 > d->ipEnd) return 0;
        bS(b, "db 0x");
        bHex(b, *save, 0);
        bC(b, '\n');
        d->ip = save + 1;
        d->va = saveVa + 1;
        return 1;
    }
    int consumed = (int)(d->ip - save);
    bC(b, '\n');
    return consumed > 0 ? consumed : 1;
}

// ============================================================================
// entries
// ============================================================================
// Entry. ABI (SysV): rdi=op, rsi=dst, rdx=cap, rcx=src, r8=srcLen, r9=base,
// then stack args (after the return address): [rsp+8]=syntax, [rsp+16]=flags.
// Result returns in rax. (Zenith stages r8/r9 via small REX-prefixed movs in
// codegen_disasm.cpp; syntax/flags go on the stack.)
extern "C" long long disasm_entry(u64 op, u64 dst, u64 cap, u64 src,
                                  u64 srcLen, u64 base, u64 syntax, u64 flags) {
    if (op == 1) {
        if (srcLen > 0x7FFFFFFFL || cap > 0x7FFFFFFFL || cap == 0) return -1;
        modeSet((int)syntax, (int)(flags & 1));
        // pass 1: compute needed size with a null sink
        u64 need = 0;
        {
            Dec d; d.ip = (u8*)(long)src; d.ipEnd = d.ip + srcLen; d.va = base;
            Blob sink; sink.out = 0; sink.cap = 0; sink.len = 0;
            while (d.ip < d.ipEnd) {
                sink.len = 0;                 // reset per instruction
                int slen = decodeInstr(&d, &sink);
                if (slen <= 0) { d.ip++; d.va++; }
                need += (u64)sink.len;
            }
        }
        if (need > cap) return (long long)need;
        // pass 2: real fill
        {
            Dec d; d.ip = (u8*)(long)src; d.ipEnd = d.ip + srcLen; d.va = base;
            Blob out; out.out = (char*)(long)dst; out.cap = (int)cap; out.len = 0;
            while (d.ip < d.ipEnd) {
                int slen = decodeInstr(&d, &out);
                if (slen <= 0) { d.ip++; d.va++; }
            }
            if (out.len < (int)cap) out.out[out.len] = 0;
            return 0;
        }
    }
    if (op == 2) {
        if (srcLen > 0x7FFFFFFFL || cap > 0x7FFFFFFFL || cap == 0 || srcLen == 0) return 0;
        modeSet((int)syntax, 0);
        Dec d; d.ip = (u8*)(long)src; d.ipEnd = d.ip + srcLen; d.va = base;
        Blob out; out.out = (char*)(long)dst; out.cap = (int)cap; out.len = 0;
        int slen = decodeInstr(&d, &out);
        if (slen <= 0) return 0;
        if (out.len < (int)cap) out.out[out.len] = 0;
        return slen;
    }
    return 0;
}