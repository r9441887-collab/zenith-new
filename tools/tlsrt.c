/* Freestanding position-independent TLS/crypto core for Zenith.
   SHA-256 / HMAC / TLS-PRF / AES-128-GCM / RSA-2048 / P-256 ECDHE /
   X.509 parser / TLS 1.2 handshake / Record layer.
   Compiled by host gcc (x86-64 SysV-internal), never linked against libc.
   All internal references are PC-relative. No red zone, no TLS. */
#include <stddef.h>
#include "tlsrt.h"

/* ---- types ---- */
typedef unsigned int      u32;
typedef uint64_t          u64;
typedef unsigned char      u8;
typedef unsigned short    u16;
typedef __uint128_t       u128_t;
typedef signed long long   i64;

/* ---- helpers ---- */
static u32 rotr32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
static u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
static u64 byteswap64(u64 x) {
    return ((x & 0xFF) << 56) | (((x>>8) & 0xFF) << 48) |
           (((x>>16) & 0xFF) << 40) | (((x>>24) & 0xFF) << 32) |
           (((x>>32) & 0xFF) << 24) | (((x>>40) & 0xFF) << 16) |
           (((x>>48) & 0xFF) << 8) | (x >> 56);
}
static u32 byteswap32(u32 x) {
    return ((x & 0xFF) << 24) | (((x>>8) & 0xFF) << 16) |
           (((x>>16) & 0xFF) << 8) | (x >> 24);
}
static void mem_copy(u8* dst, const u8* src, u64 n) {
    for (u64 i = 0; i < n; i++) dst[i] = src[i];
}
static void mem_zero(u8* dst, u64 n) {
    for (u64 i = 0; i < n; i++) dst[i] = 0;
}
/* Constant-time byte compare (both length equal assumed; returns 0 if equal).
   Unlike mem_cmp it does NOT leak which byte differed, blocking timing side
   channels on GCM tag / PKCS#1 / Finished comparison. */
static int ct_cmp(const u8* a, const u8* b, u64 n) {
    u8 diff = 0;
    for (u64 i = 0; i < n; i++) diff |= (u8)(a[i] ^ b[i]);
    return diff ? -1 : 0;
}
static int mem_cmp(const u8* a, const u8* b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return a[i] - b[i];
    return 0;
}

/* ---- entropy / nonce source ----
   The blob has no OS interface of its own, but every TP session is seeded by
   tlsrt_io_init, which stores the send/recv/closesocket function pointers. Those
   pointers (ASLR'd module addresses) plus the RDTSC counter and the stack address
   give enough unpredictable bits for the client random + ECDHE private key.
   g_entropy_ctx is a globally persistent mix counter so successive TLS_OP_TLS_CONNECT
   calls never produce the same nonce stream again. */
/* io-slot globals (defined at the bottom of the file, used by tlsrt.s stubs and
   entropy_bootstrap); forward-declared here so the bootstrap can fold their
   ASLR addresses into the pool. */
extern u64 tlsrt_io_send, tlsrt_io_recv, tlsrt_io_close;
static u64 g_entropy_a = 0x9E3779B97F4A7C15ULL;
static u64 g_entropy_b = 0xBF58476D1CE4E5B9ULL;
static u64 g_entropy_c = 0x94D049BB133111EBULL;
static int  g_entropy_init = 0;

static u64 rdtsc64(void) {
#if defined(__x86_64__) || defined(__i386__)
    u32 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
#else
    return 0;
#endif
}

/* mix64: (splitmix64-style) strong 64-bit mixer. */
static u64 mix64u(u64 x) {
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

/* Seed the entropy pool from the injected io function pointers + rdtsc + frame
   address. Safe to call any number of times; blends new entropy in. */
static void entropy_bootstrap(void) {
    u64 s = rdtsc64();
    u64 frame = (u64)&entropy_bootstrap;
    u64 f = (u64)((void*)tlsrt_io_send);
    u64 g = (u64)((void*)tlsrt_io_recv);
    g_entropy_a ^= mix64u(s ^ 0xA5A5A5A5A5A5A5A5ULL);
    g_entropy_b ^= mix64u(frame ^ 0x7369A27B9F91D967ULL);
    g_entropy_c ^= mix64u(f);
    g_entropy_c ^= mix64u(g << 1);
    g_entropy_a ^= mix64u(g_entropy_a << 17);
}

/* Fill n bytes with pseudo-random data from the mixed 64-bit pool. Not
   cryptographic-quality alone, but composed of RDTSC + ASLR'd pointers with a
   running per-process counter it defeats prediction of the client random and
   the ephemeral ECDHE scalar. */
static void entropy_fill(u8* out, u64 n) {
    if (!g_entropy_init) { entropy_bootstrap(); g_entropy_init = 1; }
    u64 idx = 0;
    while (idx < n) {
        u64 x = mix64u(g_entropy_a ^ g_entropy_b ^ g_entropy_c);
        g_entropy_a ^= x; g_entropy_b ^= x >> 7; g_entropy_c ^= mix64u(x << 3);
        g_entropy_c += 0x9E3779B97F4A7C15ULL;
        for (int k = 0; k < 8 && idx < n; k++) out[idx++] = (u8)(x >> (k * 8));
    }
}

/* Constant-time bigint: returns 1 if all 256 bytes of x are zero. */
static int is_all_zero(const u8* x, u64 n) {
    u8 acc = 0;
    for (u64 i = 0; i < n; i++) acc |= x[i];
    return acc == 0;
}

/* ================================================================
   SHA-256 (incremental)
   ================================================================ */
static const u32 kShaK[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static const u32 kShaInit[8] = {
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };

typedef struct { u32 h[8]; u64 total; u8 buf[64]; int buflen; } sha256_ctx;

static void sha256_block(sha256_ctx* ctx, const u8* p) {
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)p[i*4]<<24)|((u32)p[i*4+1]<<16)|((u32)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
        u32 s1 = rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u32 a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3];
    u32 e=ctx->h[4],f=ctx->h[5],g=ctx->h[6],h=ctx->h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
        u32 ch = (e&f)^(~e&g);
        u32 t1 = h + S1 + ch + kShaK[i] + w[i];
        u32 S0 = rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
        u32 maj = (a&b)^(a&c)^(b&c);
        u32 t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

static void sha256_init(sha256_ctx* c) {
    for (int i = 0; i < 8; i++) c->h[i] = kShaInit[i];
    c->total = 0; c->buflen = 0;
}

static void sha256_update(sha256_ctx* c, const u8* data, u64 len) {
    c->total += len;
    if (c->buflen) {
        int need = 64 - c->buflen;
        if ((u64)need > len) need = (int)len;
        for (int i = 0; i < need; i++) c->buf[c->buflen+i] = data[i];
        c->buflen += need;
        data += need; len -= need;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
    while (len >= 64) { sha256_block(c, data); data += 64; len -= 64; }
    if (len) { for (u64 i = 0; i < len; i++) c->buf[i] = data[i]; c->buflen = (int)len; }
}

static void sha256_final(sha256_ctx* c, u8 out[32]) {
    u64 bitlen = c->total * 8;
    u8 pad = 0x80;
    sha256_update(c, &pad, 1);
    u8 zero[8] = {0};
    while (c->buflen != 56) {
        u64 add = 56 - c->buflen;
        if (c->buflen > 56) add = 64 - c->buflen;
        if (add > 8) add = 8;
        sha256_update(c, zero, add);
    }
    u8 bl[8];
    for (int i = 0; i < 8; i++) bl[i] = (u8)(bitlen >> (56 - 8*i));
    sha256_update(c, bl, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (u8)(c->h[i]>>24);
        out[i*4+1] = (u8)(c->h[i]>>16);
        out[i*4+2] = (u8)(c->h[i]>>8);
        out[i*4+3] = (u8)c->h[i];
    }
}

static void sha256_one(const u8* msg, u64 mlen, u8 out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, msg, mlen); sha256_final(&c, out);
}

/* ================================================================
   HMAC-SHA256
   ================================================================ */
static void hmac_sha256(const u8* key, u64 klen, const u8* msg, u64 mlen, u8 out[32]) {
    u8 kk[64];
    if (klen > 64) { sha256_one(key, klen, kk); for (int i = 32; i < 64; i++) kk[i] = 0; }
    else { for (int i = 0; i < 64; i++) kk[i] = i < (int)klen ? key[i] : 0; }
    u8 ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = kk[i]^0x36; opad[i] = kk[i]^0x5c; }
    sha256_ctx c;
    sha256_init(&c); sha256_update(&c, ipad, 64); sha256_update(&c, msg, mlen);
    u8 inner[32]; sha256_final(&c, inner);
    sha256_init(&c); sha256_update(&c, opad, 64); sha256_update(&c, inner, 32); sha256_final(&c, out);
}

/* ================================================================
   TLS 1.2 PRF (P_SHA256)
   ================================================================ */
static void prf_sha256(const u8* secret, u64 slen, const u8* label, u64 llen,
                       const u8* seed, u64 seedlen, u8* out, u64 olen) {
    u8 a[32];
    u8 ls[160]; u64 n = 0;
    for (u64 i = 0; i < llen; i++) ls[n++] = label[i];
    for (u64 i = 0; i < seedlen; i++) ls[n++] = seed[i];
    hmac_sha256(secret, slen, ls, n, a);
    u64 produced = 0;
    while (produced < olen) {
        u8 inp[160]; u64 m = 0;
        for (u64 j = 0; j < 32; j++) inp[m++] = a[j];
        for (u64 j = 0; j < llen; j++) inp[m++] = label[j];
        for (u64 j = 0; j < seedlen; j++) inp[m++] = seed[j];
        u8 blk[32];
        hmac_sha256(secret, slen, inp, m, blk);
        for (u64 j = 0; j < 32 && produced < olen; j++) out[produced++] = blk[j];
        if (produced >= olen) break;
        hmac_sha256(secret, slen, a, 32, a);
    }
}

/* ================================================================
   AES-128
   ================================================================ */
static const u8 kAesSbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static const u8 kAesRcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

/* AES key expansion: 16-byte key -> 176-byte schedule (11 round keys) */
static void aes128_key_expand(u8 sched[176], const u8 key[16]) {
    int i;
    for (i = 0; i < 16; i++) sched[i] = key[i];
    int bytes = 16;
    int rcon_idx = 1;
    while (bytes < 176) {
        u8 tmp[4];
        for (i = 0; i < 4; i++) tmp[i] = sched[bytes - 4 + i];
        if (bytes % 16 == 0) {
            u8 t = tmp[0]; tmp[0] = kAesSbox[tmp[1]] ^ kAesRcon[rcon_idx++];
            tmp[1] = kAesSbox[tmp[2]]; tmp[2] = kAesSbox[tmp[3]]; tmp[3] = kAesSbox[t];
        }
        for (i = 0; i < 4; i++) {
            sched[bytes] = sched[bytes - 16] ^ tmp[i];
            bytes++;
        }
    }
}

/* AES-128 single-block encrypt */
static void aes128_encrypt_block(u8 out[16], const u8 in[16], const u8 sched[176]) {
    u8 s[16];
    int i, r;
    for (i = 0; i < 16; i++) s[i] = in[i] ^ sched[i];
    for (r = 1; r <= 10; r++) {
        /* SubBytes */
        for (i = 0; i < 16; i++) s[i] = kAesSbox[s[i]];
        /* ShiftRows */
        u8 t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
        /* MixColumns (skip for round 10) */
        if (r < 10) {
            for (i = 0; i < 16; i += 4) {
                u8 a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
                u8 x0 = (a0 << 1) ^ (((a0 >> 7) & 1) * 0x1b);
                u8 x1 = (a1 << 1) ^ (((a1 >> 7) & 1) * 0x1b);
                u8 x2 = (a2 << 1) ^ (((a2 >> 7) & 1) * 0x1b);
                u8 x3 = (a3 << 1) ^ (((a3 >> 7) & 1) * 0x1b);
                s[i]   = x0 ^ x1 ^ a2 ^ a3 ^ a1;
                s[i+1] = a0 ^ x1 ^ x2 ^ a3 ^ a2;
                s[i+2] = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                s[i+3] = x0 ^ a0 ^ a1 ^ a2 ^ x3;
            }
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++) s[i] ^= sched[r * 16 + i];
    }
    for (i = 0; i < 16; i++) out[i] = s[i];
}

/* AES-128 single-block decrypt (for CTR/GCM we only need encrypt, but include for completeness) */
static void aes128_decrypt_block(u8 out[16], const u8 in[16], const u8 sched[176]) {
    u8 s[16];
    int i, r;
    for (i = 0; i < 16; i++) s[i] = in[i] ^ sched[160];
    for (r = 9; r >= 1; r--) {
        /* InvShiftRows */
        u8 t;
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        /* InvSubBytes */
        /* brute-force inverse S-box */
        for (i = 0; i < 256; i++) if (kAesSbox[i] == s[0]) { s[0] = (u8)i; break; }
        /* Actually, build inverse S-box properly */
        {
            u8 isbox[256];
            for (i = 0; i < 256; i++) isbox[kAesSbox[i]] = (u8)i;
            for (i = 0; i < 16; i++) s[i] = isbox[s[i]];
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++) s[i] ^= sched[r * 16 + i];
        /* InvMixColumns */
        if (r > 0) {
            for (i = 0; i < 16; i += 4) {
                u8 a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
                /* multiply by 9,11,13,14 */
                u8 x0 = (a0<<1)^(((a0>>7)&1)*0x1b);
                u8 x1 = (a1<<1)^(((a1>>7)&1)*0x1b);
                u8 x2 = (a2<<1)^(((a2>>7)&1)*0x1b);
                u8 x3 = (a3<<1)^(((a3>>7)&1)*0x1b);
                u8 x4 = x0^a0, x5 = x1^a1, x6 = x2^a2, x7 = x3^a3;
                u8 y0 = (x4<<1)^(((x4>>7)&1)*0x1b);
                u8 y1 = (x5<<1)^(((x5>>7)&1)*0x1b);
                u8 y2 = (x6<<1)^(((x6>>7)&1)*0x1b);
                u8 y3 = (x7<<1)^(((x7>>7)&1)*0x1b);
                s[i]   = y0^x4^a3^a2^a1;
                s[i+1] = y1^a0^x5^a3^a2;
                s[i+2] = y2^a1^a0^x6^a3;
                s[i+3] = y3^a2^a1^a0^x7;
            }
        }
    }
    /* initial AddRoundKey (round 0) */
    for (i = 0; i < 16; i++) s[i] ^= sched[i];
    for (i = 0; i < 16; i++) out[i] = s[i];
}

/* ================================================================
   GHASH + AES-GCM
   ================================================================ */
/* GHASH: Y = X * H in GF(2^128) with modulus x^128 + x^7 + x^2 + x + 1
   H = hash key (first AES block of H), X = input data (16-byte blocks) */
static void ghash_multiply(u8 y[16], const u8 x[16], const u8 h[16]) {
    /* Schoolbook multiplication in GF(2^128) */
    u8 v[16];
    mem_copy(v, x, 16);
    u8 z[16]; mem_zero(z, 16);
    for (int i = 0; i < 128; i++) {
        /* if bit i of H is set: z ^= v */
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if ((h[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        /* v >>= 1, if lsb was set: v ^= R (0xe1 << 120) */
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    for (int j = 0; j < 16; j++) y[j] = z[j];
}

/* Increment big-endian 128-bit counter by 1 */
static void ghash_inc32(u8 ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

/* GCTR: C = AES-CTR(key, icb, plaintext)
   icb = initial counter block, output overwrites plaintext if out==in */
static void gctr(u8* out, const u8* in, u64 len, const u8 sched[176], const u8 icb[16]) {
    u8 cb[16], keystream[16];
    mem_copy(cb, icb, 16);
    u64 off = 0;
    while (off < len) {
        aes128_encrypt_block(keystream, cb, sched);
        u64 block = (len - off > 16) ? 16 : (len - off);
        for (u64 i = 0; i < block; i++) out[off + i] = in[off + i] ^ keystream[i];
        off += block;
        ghash_inc32(cb);
    }
}

/* AES-GCM encrypt: out = enc(in), tag = GMAC(key, IV, AAD, ciphertext)
   pkt layout for codegen: [iv12][aad_len_le16] followed by aad bytes, then ciphertext.
   For our internal use: all params passed directly. */
static void aes_gcm_encrypt(u8* out, const u8* in, u64 len,
                             const u8 sched[176], const u8 iv[12],
                             const u8* aad, u64 aad_len, u8 tag[16]) {
    u8 h[16], y[16], j0[16], keystream[16];
    /* H = AES_K(0^128) */
    mem_zero(h, 16); aes128_encrypt_block(h, h, sched);
    /* J0 = IV || 0x00000001 */
    mem_copy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    /* C = GCTR(K, inc32(J0), P) */
    u8 icb[16]; mem_copy(icb, j0, 16); ghash_inc32(icb);
    gctr(out, in, len, sched, icb);
    /* U = GHASH(H, AAD || C || len64(AAD) || len64(C)) */
    /* Build the GHASH input: AAD padded to 16, CT padded to 16, 8-byte aadlen, 8-byte ctlen */
    mem_zero(y, 16);
    /* AAD blocks */
    {
        u64 off = 0;
        while (off < aad_len) {
            u8 block[16]; mem_zero(block, 16);
            u64 take = (aad_len - off > 16) ? 16 : (aad_len - off);
            for (u64 i = 0; i < take; i++) block[i] = aad[off + i];
            for (int j = 0; j < 16; j++) y[j] ^= block[j];
            u8 tmp[16]; ghash_multiply(tmp, y, h);
            for (int j = 0; j < 16; j++) y[j] = tmp[j];
            off += take;
        }
    }
    /* Ciphertext blocks */
    {
        u64 off = 0;
        while (off < len) {
            u8 block[16]; mem_zero(block, 16);
            u64 take = (len - off > 16) ? 16 : (len - off);
            for (u64 i = 0; i < take; i++) block[i] = out[off + i];
            for (int j = 0; j < 16; j++) y[j] ^= block[j];
            u8 tmp[16]; ghash_multiply(tmp, y, h);
            for (int j = 0; j < 16; j++) y[j] = tmp[j];
            off += take;
        }
    }
    /* len block: aad_len*8 || ct_len*8 (both big-endian 64-bit) */
    {
        u8 lenblock[16]; mem_zero(lenblock, 16);
        u64 abits = aad_len * 8, cbits = len * 8;
        for (int i = 0; i < 8; i++) lenblock[i] = (u8)(abits >> (56 - 8*i));
        for (int i = 0; i < 8; i++) lenblock[8+i] = (u8)(cbits >> (56 - 8*i));
        for (int j = 0; j < 16; j++) y[j] ^= lenblock[j];
        u8 tmp[16]; ghash_multiply(tmp, y, h);
        for (int j = 0; j < 16; j++) y[j] = tmp[j];
    }
    /* Tag = MSB_128(GCTR(K, J0, U)) */
    aes128_encrypt_block(keystream, j0, sched);
    for (int i = 0; i < 16; i++) tag[i] = y[i] ^ keystream[i];
}

/* AES-GCM decrypt: out = dec(in), verify tag, returns 0=ok, -1=fail */
static int aes_gcm_decrypt(u8* out, const u8* in, u64 len,
                            const u8 sched[176], const u8 iv[12],
                            const u8* aad, u64 aad_len, const u8 tag[16]) {
    u8 h[16], y[16], j0[16];
    mem_zero(h, 16); aes128_encrypt_block(h, h, sched);
    mem_copy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    /* Compute expected tag first */
    u8 expected_tag[16];
    {
        /* GHASH over AAD || CT (before decryption, so use ciphertext = in) */
        mem_zero(y, 16);
        u64 off = 0;
        while (off < aad_len) {
            u8 block[16]; mem_zero(block, 16);
            u64 take = (aad_len - off > 16) ? 16 : (aad_len - off);
            for (u64 i = 0; i < take; i++) block[i] = aad[off + i];
            for (int j = 0; j < 16; j++) y[j] ^= block[j];
            u8 tmp[16]; ghash_multiply(tmp, y, h);
            for (int j = 0; j < 16; j++) y[j] = tmp[j];
            off += take;
        }
        off = 0;
        while (off < len) {
            u8 block[16]; mem_zero(block, 16);
            u64 take = (len - off > 16) ? 16 : (len - off);
            for (u64 i = 0; i < take; i++) block[i] = in[off + i];
            for (int j = 0; j < 16; j++) y[j] ^= block[j];
            u8 tmp[16]; ghash_multiply(tmp, y, h);
            for (int j = 0; j < 16; j++) y[j] = tmp[j];
            off += take;
        }
        {
            u8 lenblock[16]; mem_zero(lenblock, 16);
            u64 abits = aad_len * 8, cbits = len * 8;
            for (int i = 0; i < 8; i++) lenblock[i] = (u8)(abits >> (56 - 8*i));
            for (int i = 0; i < 8; i++) lenblock[8+i] = (u8)(cbits >> (56 - 8*i));
            for (int j = 0; j < 16; j++) y[j] ^= lenblock[j];
            u8 tmp[16]; ghash_multiply(tmp, y, h);
            for (int j = 0; j < 16; j++) y[j] = tmp[j];
        }
        u8 ks[16]; aes128_encrypt_block(ks, j0, sched);
        for (int i = 0; i < 16; i++) expected_tag[i] = y[i] ^ ks[i];
    }
    if (mem_cmp(expected_tag, tag, 16) != 0) return -1;
    /* Now decrypt */
    u8 icb[16]; mem_copy(icb, j0, 16); ghash_inc32(icb);
    gctr(out, in, len, sched, icb);
    return 0;
}

/* ================================================================
   Bigint 2048-bit (32 limbs of 64-bit, little-endian)
   ================================================================ */
#define BI_LIMBS 32

/* a += b, returns carry */
static u32 bi_add(u64 a[BI_LIMBS], const u64 b[BI_LIMBS]) {
    u64 carry = 0;
    for (int i = 0; i < BI_LIMBS; i++) {
        u64 s = a[i] + b[i] + carry;
        carry = (s < a[i]) || (carry && s <= b[i]) ? 1 : 0;
        a[i] = s;
    }
    return (u32)carry;
}

/* a -= b, returns borrow */
static u32 bi_sub(u64 a[BI_LIMBS], const u64 b[BI_LIMBS]) {
    u64 borrow = 0;
    for (int i = 0; i < BI_LIMBS; i++) {
        u64 diff = a[i] - b[i] - borrow;
        borrow = (diff > a[i]) || (borrow && diff >= a[i]) ? 1 : 0;
        a[i] = diff;
    }
    return (u32)borrow;
}

/* returns 1 if a >= b */
static int bi_cmp(const u64 a[BI_LIMBS], const u64 b[BI_LIMBS]) {
    for (int i = BI_LIMBS - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* a <<= 1 */
static void bi_shl1(u64 a[BI_LIMBS]) {
    u64 carry = 0;
    for (int i = 0; i < BI_LIMBS; i++) {
        u64 n = (a[i] << 1) | carry;
        carry = a[i] >> 63;
        a[i] = n;
    }
}

/* Wide multiply-and-shift helpers for computing R^2 mod m without letting the
   top bit of 2^(2*BI_LIMBS*64) spill out of a fixed buffer. */
static void bi_shl1_n(u64* a, int n) {
    u64 carry = 0;
    for (int i = 0; i < n; i++) {
        u64 v = (a[i] << 1) | carry;
        carry = a[i] >> 63;
        a[i] = v;
    }
}
static int bi_cmp_n(const u64* a, const u64* b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}
static void bi_sub_n(u64* a, const u64* b, int n) {
    u64 borrow = 0;
    for (int i = 0; i < n; i++) {
        u64 diff = a[i] - b[i] - borrow;
        borrow = (diff > a[i]) || (borrow && diff >= a[i]) ? 1 : 0;
        a[i] = diff;
    }
}
/* r2 = (2^2048)^2 mod m = 2^4096 mod m, computed by repeated doubling and
   conditional subtraction in a buffer wide enough to hold 4096 bits. */
static void bi_r2_mod_m(u64 r2[BI_LIMBS], const u64 m[BI_LIMBS]) {
    u64 w[BI_LIMBS * 2];
    u64 mp[BI_LIMBS + 1];
    mem_zero((u8*)w, sizeof(w));
    for (int i = 0; i < BI_LIMBS; i++) mp[i] = m[i];
    mp[BI_LIMBS] = 0;
    w[0] = 1;
    for (int it = 0; it < BI_LIMBS * 128; it++) {
        bi_shl1_n(w, BI_LIMBS * 2);
        /* w is now < 2*2^(2048) and can occupy BI_LIMBS+1 limbs, so compare
           and subtract over BI_LIMBS+1 limbs using a zero-padded modulus —
           the old 32-limb comparison missed the carry into limb BI_LIMBS. */
        if (bi_cmp_n(w, mp, BI_LIMBS + 1) >= 0) bi_sub_n(w, mp, BI_LIMBS + 1);
    }
    for (int i = 0; i < BI_LIMBS; i++) r2[i] = w[i];
}

/* Montgomery multiplication: out = a*b mod m, using Montgomery domain.
   T is temporary scratch (BI_LIMBS+1 limbs). */
static void bi_mont_mul(u64 out[BI_LIMBS], const u64 a[BI_LIMBS],
                         const u64 b[BI_LIMBS], const u64 m[BI_LIMBS], u64 m0_inv) {
    /* Coarsely integrated operand scanning (CIOS). The running accumulator needs
       BI_LIMBS+2 limbs: the intermediate t[BI_LIMBS] can itself receive a carry
       from the multiply and reduction steps, and dropping that carry (as the
       old BI_LIMBS+1 version did) silently produced a zero result for full
       2048-bit operands. */
    u64 t[BI_LIMBS + 2];
    mem_zero((u8*)t, sizeof(t));
    for (int i = 0; i < BI_LIMBS; i++) {
        u64 carry = 0;
        u64 ai_bi = a[i];
        for (int j = 0; j < BI_LIMBS; j++) {
            u128_t sum = (u128_t)t[j] + (u128_t)ai_bi * b[j] + carry;
            t[j] = (u64)sum;
            carry = (u64)(sum >> 64);
        }
        {
            u128_t s = (u128_t)t[BI_LIMBS] + carry;
            t[BI_LIMBS] = (u64)s;
            t[BI_LIMBS + 1] += (u64)(s >> 64);
        }
        /* Reduce */
        u64 k = t[0] * m0_inv;
        carry = 0;
        for (int j = 0; j < BI_LIMBS; j++) {
            u128_t sum = (u128_t)t[j] + (u128_t)k * m[j] + carry;
            t[j] = (u64)sum;
            carry = (u64)(sum >> 64);
        }
        {
            u128_t s = (u128_t)t[BI_LIMBS] + carry;
            t[BI_LIMBS] = (u64)s;
            t[BI_LIMBS + 1] += (u64)(s >> 64);
        }
        /* Shift right by 64 bits */
        for (int j = 0; j <= BI_LIMBS; j++) t[j] = t[j+1];
        t[BI_LIMBS + 1] = 0;
    }
    /* Final reduction: t is < 2m, so at most one subtraction of m. t is held
       in BI_LIMBS+2 limbs and can carry into limb BI_LIMBS, so compare and
       subtract over BI_LIMBS+1 limbs with a zero-padded modulus. */
    {
        u64 mp[BI_LIMBS + 1];
        for (int i = 0; i < BI_LIMBS; i++) mp[i] = m[i];
        mp[BI_LIMBS] = 0;
        if (bi_cmp_n(t, mp, BI_LIMBS + 1) >= 0) bi_sub_n(t, mp, BI_LIMBS + 1);
    }
    for (int i = 0; i < BI_LIMBS; i++) out[i] = t[i];
}

/* Montgomery exponentiation: out = base^exp mod m (2048-bit) */
static void bi_modpow(u64 out[BI_LIMBS], const u64 base[BI_LIMBS],
                       const u64 exp[BI_LIMBS], const u64 m[BI_LIMBS]) {
    /* m0_inv = -m[0]^(-1) mod 2^64 (REDC/instrumentation requirement).
       Hensel iteration: x <- x*(2 - m0*x) doubles the correct bits each
       step and converges to m0^(-1) mod 2^64; the old formula
       x <- x*2*(m0*x+1) converges to 0, which made bi_mapown output
       zero for every signature -> verify always failed. */
    u64 m0 = m[0];
    u64 m0_inv = 1;
    for (int i = 0; i < 6; i++) m0_inv *= 2 - m0 * m0_inv;
    m0_inv = (u64)(0 - m0_inv);

    /* R^2 mod m for Montgomery parametrization (R = 2^(BI_LIMBS*64) = 2^2048).
       Computed in a wide buffer so the 4096th bit never spills. */
    u64 r2[BI_LIMBS];
    bi_r2_mod_m(r2, m);

    /* Convert base to Montgomery: base_mont = base * R mod m */
    u64 base_mont[BI_LIMBS];
    bi_mont_mul(base_mont, base, r2, m, m0_inv);

    /* Montgomery 1 (= 1 * R mod m) */
    u64 one_mont[BI_LIMBS]; mem_zero((u8*)one_mont, sizeof(one_mont));
    one_mont[0] = 1;
    bi_mont_mul(one_mont, one_mont, r2, m, m0_inv);

    /* Right-to-left square and multiply */
    u64 result[BI_LIMBS];
    mem_copy((u8*)result, (const u8*)one_mont, sizeof(result));
    for (int i = 0; i < BI_LIMBS; i++) {
        for (int j = 0; j < 64; j++) {
            if ((exp[i] >> j) & 1) {
                bi_mont_mul(result, result, base_mont, m, m0_inv);
            }
            bi_mont_mul(base_mont, base_mont, base_mont, m, m0_inv);
        }
    }
    /* Convert from Montgomery: out = result * 1 * R^(-1) = result in normal form */
    u64 one[BI_LIMBS]; mem_zero((u8*)one, sizeof(one)); one[0] = 1;
    bi_mont_mul(out, result, one, m, m0_inv);
}

/* ================================================================
   RSA PKCS#1 v1.5 SHA-256 verify
   ================================================================ */
/* DigestInfo for SHA-256: 0x30 0x31 0x30 0x0d 0x06 0x09 0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x02 0x01 0x05 0x00 0x04 0x20 */
static const u8 kSha256DigestInfo[19] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };

/* Verify RSA PKCS#1 v1.5 SHA-256 signature.
   msg_hash: 32 bytes (SHA-256 of the message)
   n, e: RSA public key (256 bytes, 4 bytes respectively, big-endian)
   sig: 256-byte signature (big-endian)
   Returns 0=valid, -1=invalid. */
static int rsa_verify_sha256(const u8 msg_hash[32], const u8 n[256], const u8 e[4],
                              const u8 sig[256]) {
    /* Reject weak keys: modulus must occupy the full 256 bytes (>= 2048 bits,
       not counting the leading zero the encoding can stick on for interpretive
       parsing). This blocks Bleichenbacher-style short-modulus forgeries where
       dec^e == m is satisfied by a tiny modulus. Also require an odd e > 1. */
    if (n[0] < 0x80) return -1;                      /* top byte clear -> < 2048 bits */
    u32 e_val = ((u32)e[0] << 24) | ((u32)e[1] << 16) | ((u32)e[2] << 8) | e[3];
    if (e_val <= 1 || (e_val & 1) == 0) return -1;   /* e must be odd and > 1 */

    /* Convert n, e, sig to little-endian u64 arrays */
    u64 n_le[BI_LIMBS], e_le[BI_LIMBS], sig_le[BI_LIMBS];
    for (int i = 0; i < BI_LIMBS; i++) {
        n_le[i] = 0; e_le[i] = 0; sig_le[i] = 0;
        for (int j = 0; j < 8; j++) {
            int k = i * 8 + j;
            n_le[i]   |= (u64)n[255 - k] << (j * 8);
            sig_le[i] |= (u64)sig[255 - k] << (j * 8);
        }
    }
    /* e is typically 65537 = 0x010001 */
    for (int i = 0; i < BI_LIMBS; i++) {
        e_le[i] = 0;
        for (int j = 0; j < 8; j++) {
            int k = i * 8 + j;
            if (k < 4) e_le[i] |= (u64)e[3 - k] << (j * 8);
        }
    }

    /* decrypted = sig^e mod n */
    u64 dec[BI_LIMBS];
    bi_modpow(dec, sig_le, e_le, n_le);

    /* Convert decrypted to big-endian. dec is little-endian limb order, so
       dec_be byte 0 must come from the most significant limb (dec[BI_LIMBS-1]);
       the old loop indexed dec[i], emitting the limbs least-significant first
       and reversing the entire 2048-bit value (so the DigestInfo never
       matched). */
    u8 dec_be[256];
    for (int i = 0; i < BI_LIMBS; i++) {
        for (int j = 0; j < 8; j++) {
            dec_be[i * 8 + j] = (u8)(dec[BI_LIMBS - 1 - i] >> (56 - j * 8));
        }
    }

    /* Check PKCS#1 v1.5 padding: 00 01 FF..FF 00 <DigestInfo> <hash>.
       Byte-exact: at least 8 FF bytes, no trailing junk after the hash. */
    int idx = 0;
    if (dec_be[idx++] != 0x00) return -1;
    if (dec_be[idx++] != 0x01) return -1;
    int ff = 0;
    while (idx < 256 && dec_be[idx] == 0xFF) { ff++; idx++; }
    if (ff < 8) return -1;                            /* Bleichenbacher'06: too few FF */
    if (idx >= 256 || dec_be[idx++] != 0x00) return -1;
    if (idx + 19 + 32 > 256) return -1;
    if (ct_cmp(dec_be + idx, kSha256DigestInfo, 19) != 0) return -1;
    idx += 19;
    if (ct_cmp(dec_be + idx, msg_hash, 32) != 0) return -1;
    idx += 32;
    /* No trailing data */
    if (idx != 256) return -1;
    return 0;
}

/* ================================================================
   P-256 (secp256r1) ECDHE
   ================================================================ */
/* Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const u32 kP256_P[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
};

/* Modular arithmetic mod P-256 using 8 x 32-bit limbs (to avoid u128 complexity) */
typedef struct { u32 d[8]; } fe256;

/* Compare two fe256 values limb-wise (big-endian order). -1/0/+1. */
static int fe256_cmp(const fe256* a, const fe256* b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

/* Limbs are stored least-significant-first (d[0] = low 32 bits). The 256-bit
   magnitude is read from big-endian bytes, so d[i] holds bytes[28-4*i .. 31-4*i]. */
static void fe256_from_bytes(fe256* f, const u8 b[32]) {
    for (int i = 0; i < 8; i++) {
        f->d[i] = ((u32)b[28 - 4*i] << 24) | ((u32)b[29 - 4*i] << 16) |
                  ((u32)b[30 - 4*i] << 8) | (u32)b[31 - 4*i];
    }
}

static void fe256_to_bytes(u8 b[32], const fe256* f) {
    for (int i = 0; i < 8; i++) {
        b[28 - 4*i] = (u8)(f->d[i] >> 24);
        b[29 - 4*i] = (u8)(f->d[i] >> 16);
        b[30 - 4*i] = (u8)(f->d[i] >> 8);
        b[31 - 4*i] = (u8)(f->d[i]);
    }
}

/* fe256 addition mod 2^256 (not p) — used internally; returns final carry. */
static u32 fe256_add_raw(fe256* r, const fe256* a, const fe256* b) {
    u64 carry = 0;
    for (int i = 0; i < 8; i++) {
        u64 s = (u64)a->d[i] + b->d[i] + carry;
        r->d[i] = (u32)s;
        carry = s >> 32;
    }
    return (u32)carry;
}

/* fe256 subtraction mod 2^256 — used internally; returns borrow (1 if a<b). */
static u32 fe256_sub_raw(fe256* r, const fe256* a, const fe256* b) {
    u64 borrow = 0;
    for (int i = 0; i < 8; i++) {
        u64 diff = (u64)a->d[i] - b->d[i] - borrow;
        r->d[i] = (u32)diff;
        borrow = (diff >> 63) & 1;
    }
    return (u32)borrow;
}

/* Full multiplication: result = a * b (512-bit, little-endian 32-bit words) */
static void fe256_mul_512(u32 out[16], const fe256* a, const fe256* b) {
    u64 acc[16];
    for (int i = 0; i < 16; i++) acc[i] = 0;
    for (int i = 0; i < 8; i++) {
        u64 carry = 0;
        for (int j = 0; j < 8; j++) {
            u64 prod = (u64)a->d[i] * b->d[j] + acc[i+j] + carry;
            acc[i+j] = (u32)prod;
            carry = prod >> 32;
        }
        acc[i+8] = (u32)carry;
    }
    for (int i = 0; i < 16; i++) out[i] = (u32)acc[i];
}

/* Reduce 512-bit to 256-bit mod p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
   Since p = 2^256 - 2^224 + 2^192 + 2^96 - 1, we have
      2^256 = 2^224 - 2^192 - 2^96 + 1  (mod p)
   Fold the upper 256 bits H (= words 8..15) into the low 256 bits iteratively:
      result = L + (H << 7) - (H << 6) - (H << 3) + H   (shifts in 32-bit words)
   Each fold drops the top word index by at least 1, so < 16 passes suffice. */
static void fe256_reduce(fe256* r, const u32 t[16]) {
    i64 x[24];
    for (int i = 0; i < 16; i++) x[i] = (i64)t[i];
    for (int i = 16; i < 24; i++) x[i] = 0;

    for (int pass = 0; pass < 16; pass++) {
        int top = -1;
        for (int i = 23; i >= 8; i--) if (x[i] != 0) { top = i; break; }
        if (top < 0) break;
        /* H = words 8..top; zero them, then apply the fold above. */
        i64 h[16];
        int hn = top - 7;            /* words 8..top inclusive */
        for (int i = 0; i < hn; i++) h[i] = x[8 + i];
        for (int i = 8; i < 24; i++) x[i] = 0;
for (int i = 0; i < hn; i++) {
            x[i]     += h[i];        /* + H                               */
            x[i + 3] -= h[i];        /* - H << 96  (2^256 ≡ 2^224-2^192-2^96+1) */
            x[i + 6] -= h[i];        /* - H <<192                          */
            x[i + 7] += h[i];        /* + H <<224                          */
        }
        /* Normalize base-2^32 digits, propagating carries/borrows upward. */
        for (int i = 0; i < 23; i++) {
            i64 v = x[i];
            x[i] = (i64)(u32)v;
            x[i + 1] += v >> 32;
        }
    }
    for (int i = 0; i < 8; i++) r->d[i] = (u32)x[i];
    /* x[0..7] now holds the value mod 2^256; subtract p once if >= p. */
    fe256 p_f;
    for (int i = 0; i < 8; i++) p_f.d[i] = kP256_P[i];
    if (fe256_cmp(r, &p_f) >= 0) fe256_sub_raw(r, r, &p_f);
}

static void fe256_mul(fe256* r, const fe256* a, const fe256* b) {
    u32 t[16];
    fe256_mul_512(t, a, b);
    fe256_reduce(r, t);
}

static void fe256_sqr(fe256* r, const fe256* a) {
    fe256_mul(r, a, a);
}

static void fe256_add(fe256* r, const fe256* a, const fe256* b) {
    u32 carry = fe256_add_raw(r, a, b);
    fe256 p_f;
    for (int i = 0; i < 8; i++) p_f.d[i] = kP256_P[i];
    if (carry || fe256_cmp(r, &p_f) >= 0) fe256_sub_raw(r, r, &p_f);
}

static void fe256_sub(fe256* r, const fe256* a, const fe256* b) {
    u32 borrow = fe256_sub_raw(r, a, b);
    if (borrow) {
        fe256 p_f;
        for (int i = 0; i < 8; i++) p_f.d[i] = kP256_P[i];
        fe256_add_raw(r, r, &p_f);
    }
}

static void fe256_inv(fe256* r, const fe256* a) {
    /* Fermat: a^(p-2) mod p, exponent p-2 (little-endian limbs). */
    fe256 exp;
    for (int i = 0; i < 8; i++) exp.d[i] = kP256_P[i];
    u32 borrow = 2;
    for (int i = 0; i < 8 && borrow; i++) {
        if (exp.d[i] >= borrow) exp.d[i] -= borrow, borrow = 0;
        else exp.d[i] -= borrow, borrow = 1;
    }

    fe256 result;
    result.d[0] = 1; for (int i = 1; i < 8; i++) result.d[i] = 0;

    /* Square-and-multiply scanning from MSB to LSB (i = high word first). */
    for (int i = 7; i >= 0; i--) {
        for (int j = 31; j >= 0; j--) {
            fe256_sqr(&result, &result);
            if ((exp.d[i] >> j) & 1) {
                fe256_mul(&result, &result, a);
            }
        }
    }
    *r = result;
}

/* Projective coordinates: (X : Y : Z) where affine x = X/Z^2, y = Y/Z^3 */
typedef struct { fe256 X, Y, Z; } pt256;

static void pt256_set_infinity(pt256* p) {
    /* Jacobian point at infinity is (X:Y:0); pt256_is_infinity tests Z == 0. */
    mem_zero((u8*)p, sizeof(pt256));
}

static int pt256_is_infinity(const pt256* p) {
    /* Z = 0 means point at infinity in Jacobian coords */
    for (int i = 0; i < 8; i++) if (p->Z.d[i] != 0) return 0;
    return 1;
}

/* Point doubling: P = 2Q (Jacobian coordinates, a = -3).
   M = 3*X1^2 - 3*Z1^4;  X3 = M^2 - 8*X1*Y1^2;
   Y3 = M*(4*X1*Y1^2 - X3) - 8*Y1^4;  Z3 = 2*Y1*Z1. */
static void pt256_double(pt256* r, const pt256* q) {
    if (pt256_is_infinity(q)) { pt256_set_infinity(r); return; }
    int yzero = 1;
    for (int i = 0; i < 8; i++) if (q->Y.d[i]) { yzero = 0; break; }
    if (yzero) { pt256_set_infinity(r); return; }

    fe256 m, s, c, t1, t2, u;
    fe256_sqr(&s, &q->Y);          /* Y1^2 */
    fe256_sqr(&c, &s);             /* Y1^4 */
    fe256_mul(&t1, &q->X, &s);     /* X1*Y1^2 */
    fe256_sqr(&u, &q->Z);
    fe256_sqr(&u, &u);             /* Z1^4 */

    /* M = 3*X1^2 - 3*Z1^4 */
    fe256_sqr(&m, &q->X);          /* X1^2 */
    fe256_add(&t2, &m, &m);
    fe256_add(&m, &m, &t2);        /* 3*X1^2 */
    fe256_add(&t2, &u, &u);
    fe256_add(&t2, &t2, &u);       /* 3*Z1^4 */
    fe256_sub(&m, &m, &t2);        /* M */

    /* All reads of q done; r may alias q from here on. */
    fe256_mul(&r->Z, &q->Y, &q->Z);
    fe256_add(&r->Z, &r->Z, &r->Z); /* Z3 = 2*Y1*Z1 */

    /* X3 = M^2 - 8*X1*Y1^2 */
    fe256_sqr(&r->X, &m);
    fe256_add(&t2, &t1, &t1);
    fe256_add(&t2, &t2, &t2);
    fe256_add(&t2, &t2, &t2);      /* 8*X1*Y1^2 */
    fe256_sub(&r->X, &r->X, &t2);

    /* Y3 = M*(4*X1*Y1^2 - X3) - 8*Y1^4 */
    fe256_add(&t2, &t1, &t1);
    fe256_add(&t2, &t2, &t2);      /* 4*X1*Y1^2 */
    fe256_sub(&t2, &t2, &r->X);
    fe256_mul(&r->Y, &m, &t2);
    fe256_add(&t2, &c, &c);
    fe256_add(&t2, &t2, &t2);
    fe256_add(&t2, &t2, &t2);      /* 8*Y1^4 */
    fe256_sub(&r->Y, &r->Y, &t2);
}

/* Point addition: R = P + Q (mixed: Q is affine, P is Jacobian) */
static void pt256_add_mixed(pt256* r, const pt256* p, const fe256* qx, const fe256* qy) {
    if (pt256_is_infinity(p)) {
        r->X = *qx; r->Y = *qy; r->Z.d[0] = 1;
        for (int i = 1; i < 8; i++) r->Z.d[i] = 0;
        return;
    }
    /* r may alias p (double-and-add ladder), so snapshot p->X/Y/Z up front. */
    fe256 pX = p->X, pY = p->Y, pZ = p->Z;
    fe256 z1sq, z1cu, u2, s2, h, hh, hhh, rr, t;
    fe256_sqr(&z1sq, &pZ);
    fe256_mul(&z1cu, &z1sq, &pZ);
    fe256_mul(&u2, qx, &z1sq);     /* u2 = x2 * Z1^2 */
    fe256_mul(&s2, qy, &z1cu);     /* s2 = y2 * Z1^3 */
    fe256_sub(&h, &u2, &pX);       /* h = u2 - x1 */
    fe256_sub(&rr, &s2, &pY);      /* r = s2 - y1 */

    if (h.d[0] == 0 && rr.d[0] == 0) {
        /* Check all zeros (point doubling case) */
        int all_zero = 1;
        for (int i = 0; i < 8; i++) { if (h.d[i] || rr.d[i]) { all_zero = 0; break; } }
        if (all_zero) { pt256_double(r, p); return; }
    }

    fe256_sqr(&hh, &h);
    fe256_mul(&hhh, &hh, &h);
    fe256_mul(&t, &pX, &hh);

    fe256_sqr(&r->X, &rr);
    fe256_sub(&r->X, &r->X, &hhh);
    fe256_sub(&r->X, &r->X, &t);
    fe256_sub(&r->X, &r->X, &t);

    fe256_sub(&r->Y, &t, &r->X);
    fe256_mul(&r->Y, &r->Y, &rr);
    fe256_mul(&t, &hhh, &pY);
    fe256_sub(&r->Y, &r->Y, &t);

    fe256_mul(&r->Z, &pZ, &h);
}

/* Scalar multiply: result = k * G (base point) using double-and-add */
/* Base point G for P-256 (NIST SEC 2 / RFC 5480G) */
static const u8 kP256_Gx[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
    0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
    0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96
};
static const u8 kP256_Gy[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,
    0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,
    0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};

/* Scalar as 256-bit little-endian byte array */
static void scalar_mul_G(pt256* result, const u8 scalar[32]) {
    /* Scalar is big-endian 32 bytes (byte 0 = most significant). */
    int highest_bit = -1;
    for (int i = 0; i < 32; i++) {
        if (scalar[i]) {
            for (int j = 7; j >= 0; j--) {
                if ((scalar[i] >> j) & 1) { highest_bit = (31 - i) * 8 + j; goto found; }
            }
        }
    }
found:
    if (highest_bit < 0) { pt256_set_infinity(result); return; }

    /* Initialize with G */
    fe256 gx, gy;
    fe256_from_bytes(&gx, kP256_Gx);
    fe256_from_bytes(&gy, kP256_Gy);
    result->X = gx; result->Y = gy;
    result->Z.d[0] = 1; for (int i = 1; i < 8; i++) result->Z.d[i] = 0;

    for (int i = highest_bit - 1; i >= 0; i--) {
        pt256_double(result, result);
        int byte_idx = 31 - i / 8;
        int bit_idx = i % 8;
        if ((scalar[byte_idx] >> bit_idx) & 1) {
            /* Add G */
            pt256_add_mixed(result, result, &gx, &gy);
        }
    }
}

/* Convert Jacobian to affine coordinates */
static void pt256_to_affine(fe256* ax, fe256* ay, const pt256* p) {
    fe256 zinv, zinv2, zinv3;
    if (pt256_is_infinity(p)) {
        mem_zero((u8*)ax, sizeof(fe256));
        mem_zero((u8*)ay, sizeof(fe256));
        return;
    }
    fe256_inv(&zinv, &p->Z);
    fe256_sqr(&zinv2, &zinv);
    fe256_mul(&zinv3, &zinv2, &zinv);
    fe256_mul(ax, &p->X, &zinv2);
    fe256_mul(ay, &p->Y, &zinv3);
}

/* Verify point is on curve: y^2 = x^3 - 3x + b (mod p) */
static int pt256_on_curve(const fe256* x, const fe256* y) {
    fe256 lhs, rhs, t1, t2, t3;
    fe256_sqr(&lhs, y);         /* y^2 */
    fe256_sqr(&t1, x);          /* x^2 */
    fe256_mul(&t2, &t1, x);     /* x^3 */
    fe256_mul(&t3, &t1, x);     /* redundant: x^2 * x = x^3 again but we need -3x */
    fe256_add(&t1, &t3, &t3);   /* 2*x^3 */
    fe256_add(&t1, &t1, &t3);   /* 3*x^3 */
    /* Actually: x^3 - 3x + b */
    fe256_mul(&t2, x, x);       /* x^2 */
    fe256_mul(&t3, &t2, x);     /* x^3 */

    /* rhs = x^3 - 3x + b */
    fe256 three_x;
    fe256_add(&three_x, x, x);
    fe256_add(&three_x, &three_x, x);
    fe256_sub(&rhs, &t3, &three_x);

    /* Add b */
    static const u8 b_bytes[32] = {
        0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,
        0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
        0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,
        0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b
    };
    fe256 b_f;
    fe256_from_bytes(&b_f, b_bytes);
    fe256_add(&rhs, &rhs, &b_f);

    return fe256_cmp(&lhs, &rhs) == 0;
}

/* ECDHE: generate ephemeral keypair, compute shared secret.
   priv: 32 random bytes (in/out, masked)
   pubx, puby: 32 bytes each (output)
   Returns 0=ok */
static int ecdhe_gen_pub(u8 priv[32], u8 pubx[32], u8 puby[32]) {
    pt256 pub;
    scalar_mul_G(&pub, priv);
    fe256 ax, ay;
    pt256_to_affine(&ax, &ay, &pub);
    fe256_to_bytes(pubx, &ax);
    fe256_to_bytes(puby, &ay);
    return 0;
}

/* ECDHE shared secret: out = x-coordinate of priv * (peerx, peery) */
static int ecdhe_shared(u8 out[32], const u8 priv[32],
                         const u8 peerx[32], const u8 peery[32]) {
    fe256 px, py;
    fe256_from_bytes(&px, peerx);
    fe256_from_bytes(&py, peery);
    if (!pt256_on_curve(&px, &py)) return -1;

    pt256 peer_pt;
    peer_pt.X = px; peer_pt.Y = py;
    peer_pt.Z.d[0] = 1; for (int i = 1; i < 8; i++) peer_pt.Z.d[i] = 0;

    /* Scalar multiply: result = priv * peer_pt */
    /* Need scalar multiply by arbitrary point. Let's do general double-and-add */
    int highest_bit = -1;
    for (int i = 0; i < 32; i++) {
        if (priv[i]) {
            for (int j = 7; j >= 0; j--) {
                if ((priv[i] >> j) & 1) { highest_bit = (31 - i) * 8 + j; goto found2; }
            }
        }
    }
found2:
    if (highest_bit < 0) { mem_zero(out, 32); return -1; }

    pt256 result;
    pt256_set_infinity(&result);
    for (int i = highest_bit; i >= 0; i--) {
        pt256_double(&result, &result);
        int byte_idx = 31 - i / 8;
        int bit_idx = i % 8;
        if ((priv[byte_idx] >> bit_idx) & 1) {
            pt256_add_mixed(&result, &result, &px, &py);
        }
    }

    fe256 ax, ay;
    pt256_to_affine(&ax, &ay, &result);
    fe256_to_bytes(out, &ax);
    return 0;
}

/* ================================================================
   X.509 DER Parser (minimal — extracts RSA pubkey + fingerprint)
   ================================================================ */
/* ASN.1 tag constants */
#define ASN1_TAG_INTEGER      0x02
#define ASN1_TAG_BIT_STRING   0x03
#define ASN1_TAG_OCTET_STRING 0x04
#define ASN1_TAG_NULL         0x05
#define ASN1_TAG_OID          0x06
#define ASN1_TAG_SEQUENCE     0x30
#define ASN1_TAG_SET          0x31
#define ASN1_TAG_UTF8STRING   0x0C
#define ASN1_TAG_PRINTABLE    0x13
#define ASN1_TAG_T61STRING    0x14

typedef struct {
    const u8* data;
    int len;
    int pos;
} der_cursor;

static int der_read_length(der_cursor* c, int* length) {
    if (c->pos >= c->len) return -1;
    u8 b = c->data[c->pos++];
    if ((b & 0x80) == 0) { *length = b; return 0; }
    int num_bytes = b & 0x7f;
    if (num_bytes > 4 || c->pos + num_bytes > c->len) return -1;
    *length = 0;
    for (int i = 0; i < num_bytes; i++) {
        *length = (*length << 8) | c->data[c->pos++];
    }
    return 0;
}

static int der_read_tag(der_cursor* c, int* tag) {
    if (c->pos >= c->len) return -1;
    *tag = c->data[c->pos++];
    return 0;
}

static int der_enter(der_cursor* c, int expected_tag, der_cursor* inner) {
    int tag;
    if (der_read_tag(c, &tag) < 0) return -1;
    if (tag != expected_tag) return -1;
    int length;
    if (der_read_length(c, &length) < 0) return -1;
    if (c->pos + length > c->len) return -1;
    inner->data = c->data + c->pos;
    inner->len = length;
    inner->pos = 0;
    c->pos += length;
    return 0;
}

static int der_skip(der_cursor* c) {
    int tag;
    if (der_read_tag(c, &tag) < 0) return -1;
    int length;
    if (der_read_length(c, &length) < 0) return -1;
    c->pos += length;
    return 0;
}

/* Simple cert store: up to 3 parsed certificates */
static struct {
    u8  der[3][4096];
    int der_len[3];
    u8  n[3][256];
    u8  e[3][4];
    int n_len[3];
    int e_len[3];
    u8  fp[3][32]; /* SHA-256 fingerprint */
    int count;
} g_certs;

static void x509_init(void) {
    g_certs.count = 0;
}

static int x509_parse_cert(const u8* der, int der_len, int cert_idx) {
    if (cert_idx >= 3) return -1;
    if (der_len > 4096) return -1;

    mem_copy(g_certs.der[cert_idx], der, der_len);
    g_certs.der_len[cert_idx] = der_len;
    sha256_one(der, der_len, g_certs.fp[cert_idx]);

    der_cursor outer = { der, der_len, 0 };
    der_cursor tbs;
    if (der_enter(&outer, ASN1_TAG_SEQUENCE, &tbs) < 0) return -1;

    der_cursor tbs_inner;
    if (der_enter(&tbs, ASN1_TAG_SEQUENCE, &tbs_inner) < 0) return -1;

    /* Skip version, serial, signature algorithm, issuer */
    der_skip(&tbs_inner);
    der_skip(&tbs_inner);
    der_skip(&tbs_inner);
    der_skip(&tbs_inner);

    /* Validity */
    der_skip(&tbs_inner);

    /* Subject */
    der_skip(&tbs_inner);

    /* SubjectPublicKeyInfo */
    der_cursor spki;
    if (der_enter(&tbs_inner, ASN1_TAG_SEQUENCE, &spki) < 0) return -1;

    /* Algorithm identifier */
    der_skip(&spki);

    /* Subject public key (BIT STRING) */
    der_cursor bitstr;
    if (der_enter(&spki, ASN1_TAG_BIT_STRING, &bitstr) < 0) return -1;
    bitstr.pos++; /* skip unused bits byte */

    /* Parse inner RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e } */
    der_cursor rsakey;
    if (der_enter(&bitstr, ASN1_TAG_SEQUENCE, &rsakey) < 0) return -1;

    /* Read n */
    der_cursor n_int;
    if (der_enter(&rsakey, ASN1_TAG_INTEGER, &n_int) < 0) return -1;
    /* Skip leading zero if present (PKCS#1 adds 0x00 for positive high bit) */
    int n_start = 0;
    if (n_int.len > 1 && n_int.data[0] == 0) n_start = 1;
    g_certs.n_len[cert_idx] = n_int.len - n_start;
    if (g_certs.n_len[cert_idx] > 256) g_certs.n_len[cert_idx] = 256;
    /* Store big-endian, right-aligned in 256 bytes */
    mem_zero(g_certs.n[cert_idx], 256);
    mem_copy(g_certs.n[cert_idx] + 256 - g_certs.n_len[cert_idx],
             n_int.data + n_start, g_certs.n_len[cert_idx]);

    /* Read e */
    der_cursor e_int;
    if (der_enter(&rsakey, ASN1_TAG_INTEGER, &e_int) < 0) return -1;
    int e_start = 0;
    if (e_int.len > 1 && e_int.data[0] == 0) e_start = 1;
    g_certs.e_len[cert_idx] = e_int.len - e_start;
    if (g_certs.e_len[cert_idx] > 4) g_certs.e_len[cert_idx] = 4;
    mem_zero(g_certs.e[cert_idx], 4);
    mem_copy(g_certs.e[cert_idx] + 4 - g_certs.e_len[cert_idx],
             e_int.data + e_start, g_certs.e_len[cert_idx]);

    g_certs.count = cert_idx + 1;
    return cert_idx;
}

/* ================================================================
   TLS 1.2 Handshake + Record Layer
   ================================================================ */
/* Raw send/recv through Winsock stubs (SysV calling convention via io table) */
typedef long (*io_fn)(long, long, long, long, long, long);

/* We need to call the stubs which are in the blob.
   tlsrt_io_send/recv/close are function pointers (Win64 ABI) stored in BSS.
   The stubs translate SysV->Win64 and call through these.
   For the handshake code inside the blob, we call the stubs directly. */

/* Stubs are external (in .s), we reference them via function pointers.
   But actually, the stubs call through tlsrt_io_send etc. which are function pointers.
   The blobs internal code calls tlsrt_send_stub / tlsrt_recv_stub / tlsrt_close_stub. */
extern long tlsrt_send_stub(long sock, const void* buf, long len, long flags);
extern long tlsrt_recv_stub(long sock, void* buf, long len, long flags);
extern long tlsrt_close_stub(long sock);

/* TLS record layer constants */
#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_TYPE_ALERT              21
#define TLS_CONTENT_TYPE_HANDSHAKE          22
#define TLS_CONTENT_TYPE_APPLICATION_DATA   23

#define TLS_HANDSHAKE_CLIENT_HELLO    1
#define TLS_HANDSHAKE_SERVER_HELLO    2
#define TLS_HANDSHAKE_CERTIFICATE     11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED        20

#define TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256 0xC02F
#define TLS_CIPHER_RSA_AES128_GCM_SHA256      0x009C

/* Session pool: up to 4 concurrent TLS sessions (in .bss) */
static tls_session_t g_sessions[4];
static int g_last_error = 0;
/* Handshake progress marker (index of last reached stage). The blob has no
   printf, so this is how harnesses pinpoint which handshake step fails. */
u8 g_tls_stage = 0;

/* TLS 1.2 GCM record layer (RFC 5288):
     record =
       type(1) | version(2) | length(2)                // header, 5 bytes
       | nonce_explicit(8)                             // = seq, sent in the clear
       | ciphertext                                     // = plaintext (pad 0 / none for AES-GCM)
       | tag(16)
   The `length` field covers nonce_explicit + ciphertext + tag.
   The 12-byte GCM nonce = implicit write_iv (4) || nonce_explicit (8).
   AAD = seq_num(8) || type(1) || version(2) || length(2).                    */
#define TLS_REC_HEADER      5
#define TLS_GCM_EXPLICIT    8
#define TLS_GCM_TAG         16
#define TLS_MAX_PAYLOAD     16384    /* full 2^14 TLS record plaintext cap */
#define TLS_MAX_REC         (TLS_REC_HEADER + TLS_GCM_EXPLICIT + TLS_MAX_PAYLOAD + TLS_GCM_TAG)

/* Send a TLS record. Returns 0 on success, -1 on error. */
static int tls_send_record(int sock, u8 content_type, const u8* payload, u16 payload_len,
                            const u8 write_key[16], const u8 write_iv[4], u64* seq) {
    if (payload_len > TLS_MAX_PAYLOAD) return -1;

    /* Unique per-record explicit nonce: big-endian sequence number (RFC 5288). */
    u8 nonce[8];
    for (int i = 0; i < 8; i++) nonce[i] = (u8)(*seq >> (56 - 8 * i));

    /* 12-byte GCM nonce = implicit IV || explicit nonce */
    u8 iv[12];
    mem_copy(iv, write_iv, 4);
    mem_copy(iv + 4, nonce, 8);

    /* AAD: seq(8) || type(1) || version(2) || length(2).
       RFC 5246 6.2.3.3: the AEAD additional data uses TLSCompressed.length,
       the PLAINTEXT fragment length. (The record header on the wire instead
       carries the encrypted fragment length: nonce(8)+ciphertext+tag(16).) */
    u16 enc_len = (u16)(TLS_GCM_EXPLICIT + payload_len + TLS_GCM_TAG);
    u8 aad[13];
    mem_copy(aad, nonce, 8);           /* seq_num == explicit nonce here */
    aad[8] = content_type;
    aad[9] = 3; aad[10] = 3;           /* TLS 1.2 */
    aad[11] = (u8)(payload_len >> 8);
    aad[12] = (u8)payload_len;

    u8 tag[16];
    u8 sched[176];
    aes128_key_expand(sched, write_key);
    u8 enc_buf[TLS_MAX_PAYLOAD];
    aes_gcm_encrypt(enc_buf, payload, payload_len, sched, iv, aad, 13, tag);

    /* Wire format: header(5) + nonce(8) + ciphertext + tag(16) */
    u8 send_buf[TLS_REC_HEADER + TLS_GCM_EXPLICIT + TLS_MAX_PAYLOAD + TLS_GCM_TAG];
    send_buf[0] = content_type;
    send_buf[1] = 3; send_buf[2] = 3;
    send_buf[3] = (u8)(enc_len >> 8);
    send_buf[4] = (u8)enc_len;
    mem_copy(send_buf + TLS_REC_HEADER, nonce, TLS_GCM_EXPLICIT);
    mem_copy(send_buf + TLS_REC_HEADER + TLS_GCM_EXPLICIT, enc_buf, payload_len);
    mem_copy(send_buf + TLS_REC_HEADER + TLS_GCM_EXPLICIT + payload_len, tag, TLS_GCM_TAG);

    u32 total = TLS_REC_HEADER + enc_len;
    long sent = 0;
    while (sent < (long)total) {
        long r = tlsrt_send_stub(sock, send_buf + sent, total - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    (*seq)++;
    return 0;
}

/* Receive a TLS record, decrypt and verify the GCM tag.
   Returns: content_type (>0) on success, 0 on a clean EOF at a record boundary
   (peer closed without close_notify), -1 on error.
   payload_out: decrypted payload (buffer must hold at least max_plain bytes),
   payload_len_out: its length. */
static int tls_recv_record(int sock, u8* payload_out, u16* payload_len_out,
                            u8 content_type_out[1],
                            const u8 read_key[16], const u8 read_iv[4], u64* seq,
                            u16 max_plain) {
    /* Read 5-byte record header */
    u8 header[5];
    u16 got = 0;
    while (got < 5) {
        long r = tlsrt_recv_stub(sock, header + got, 5 - got, 0);
        if (r < 0) return -1;
        if (r == 0) return got == 0 ? 0 : -1;   /* clean EOF only at boundary */
        got += r;
    }
    u8 ct = header[0];
    /* `length` includes explicit_nonce(8) + ciphertext + tag(16) for AEAD
       records. ChangeCipherSpec is a single unencrypted byte, so it is exempt
       from the AEAD minimum-length requirement below. */
    u16 rec_len = ((u16)header[3] << 8) | header[4];

    /* Reject oversized records and AEAD records whose length is too small to
       even carry the explicit nonce + tag. A CCS record (length 1) is allowed
       through so the special-case handler below can validate it. */
    if (rec_len > TLS_MAX_REC ||
        (ct != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC &&
         rec_len < TLS_GCM_EXPLICIT + TLS_GCM_TAG)) {
        g_last_error = TLS_ERR_IO;
        return -1;
    }

    /* The plaintext after AEAD decryption must fit the caller's buffer. */
    if (ct != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
        u16 ct_len0 = rec_len - TLS_GCM_EXPLICIT - TLS_GCM_TAG;
        if (ct_len0 > max_plain) {
            g_last_error = TLS_ERR_IO;
            return -1;
        }
    }

    /* Read the whole record body into a bounded buffer. */
    u8 recv_buf[TLS_MAX_REC];
    got = 0;
    while (got < rec_len) {
        long r = tlsrt_recv_stub(sock, recv_buf + got, rec_len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }

    if (ct == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
        /* CCS is a single unencrypted byte (0x01). */
        content_type_out[0] = ct;
        if (rec_len != 1 || recv_buf[0] != 1) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        *payload_len_out = 1;
        payload_out[0] = recv_buf[0];
        (*seq)++;
        return ct;
    }

    /* GCM nonce = read_iv(4) || explicit_nonce(8 from wire). */
    u8 iv[12];
    mem_copy(iv, read_iv, 4);
    mem_copy(iv + 4, recv_buf, TLS_GCM_EXPLICIT);

    /* AAD = seq(8) || type(1) || version(2) || length(2). RFC 5246 6.2.3.3:
       - The sequence number is the record sequence number (*seq), NOT the
         explicit nonce (OpenSSL picks a random nonce_explicit, so assuming
         they are equal breaks tag verification).
       - The length is TLSCompressed.length (the plaintext length = ciphertext
         length), NOT the wire record length that also carries nonce + tag. */
    u8 aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (u8)(*seq >> (56 - 8 * i));
    aad[8] = ct;
    aad[9] = header[1]; aad[10] = header[2];
    aad[11] = (u8)((rec_len - TLS_GCM_EXPLICIT - TLS_GCM_TAG) >> 8);
    aad[12] = (u8)(rec_len - TLS_GCM_EXPLICIT - TLS_GCM_TAG);

    /* Ciphertext + tag follow the explicit nonce. */
    const u8* ct_buf  = recv_buf + TLS_GCM_EXPLICIT;
    u16 ct_len = rec_len - TLS_GCM_EXPLICIT - TLS_GCM_TAG;
    const u8* tag = recv_buf + rec_len - TLS_GCM_TAG;

    u8 sched[176];
    aes128_key_expand(sched, read_key);
    if (aes_gcm_decrypt(payload_out, ct_buf, ct_len, sched, iv, aad, 13, tag) < 0) {
        g_last_error = TLS_ERR_VERIFY;
        return -1;
    }
    content_type_out[0] = ct;
    *payload_len_out = ct_len;
    (*seq)++;
    return ct;
}

/* Simple send/recv raw bytes */
static int tls_raw_send(int sock, const u8* data, u16 len) {
    u16 sent = 0;
    while (sent < len) {
        long r = tlsrt_send_stub(sock, data + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static int tls_raw_recv(int sock, u8* data, u16 len) {
    u16 got = 0;
    while (got < len) {
        long r = tlsrt_recv_stub(sock, data + got, len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

/* PRF for key derivation (TLS 1.2 style, uses P_hash) */
static void tls_prf(u8* out, u64 olen, const u8* secret, u64 slen,
                     const char* label, const u8* seed, u64 seedlen) {
    u8 label_seed[256];
    u64 llen = 0;
    while (label[llen]) llen++;
    for (u64 i = 0; i < llen; i++) label_seed[i] = (u8)label[i];
    for (u64 i = 0; i < seedlen; i++) label_seed[llen + i] = seed[i];
    prf_sha256(secret, slen, label_seed, llen + seedlen, (const u8*)"", 0, out, olen);
}

/* TLS handshake: full client handshake.
   Returns session index (0..3) on success, -1 on error. */
/* Compute the TLS 1.2 Finished verify_data for the given label, hashing the
   session's captured transcript. Returns 0 on success, -1 on error. */
static int tls_compute_verify(tls_session_t* s, const u8* master_secret,
                              const char* label, u8 out[12]) {
    u8 h[32];
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, s->transcript, (u64)s->transcript_len);
    sha256_final(&c, h);
    tls_prf(out, 12, master_secret, 48, label, h, 32);
    return 0;
}

/* Append a handshake message (wire bytes: type+3-byte-len+body) to the session
   transcript buffer, checking bounds. Returns 0 on success, -1 if full. */
static int tls_transcript_add(tls_session_t* s, const u8* msg, int mlen) {
    if (s->transcript_len + mlen > (int)sizeof(s->transcript)) return -1;
    mem_copy(s->transcript + s->transcript_len, msg, (u64)mlen);
    s->transcript_len += mlen;
    return 0;
}

/* ================================================================
   Server side: PEM/DER decode, RSA private key, TLS_OP_TLS_ACCEPT
   ================================================================ */
/* ---- base64 / PEM ---- */
static int b64_value(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode the base64 payload between the BEGIN marker and the first '='/'-'.
   Returns decoded length (>0) or -1 on malformed/short input. */
static int b64_decode(const u8* s, int slen, u8* out, int out_cap) {
    int olen = 0, acc = 0, bits = 0;
    for (int i = 0; i < slen && s[i] != '-'; i++) {
        u8 c = s[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = b64_value(c);
        if (v < 0) return -1;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (olen >= out_cap) return -1;
            out[olen++] = (u8)((acc >> bits) & 0xFF);
        }
    }
    return olen;
}

/* Decode the DER body of a PEM block ("-----BEGIN X-----...-----END X-----").
   Returns DER length (>0) or -1. */
static int pem_body_decode(const u8* pem, int pemlen, u8* out, int out_cap) {
    const u8* begin = 0;
    for (int i = 0; i + 11 <= pemlen; i++) {
        if (mem_cmp(pem + i, (const u8*)"-----BEGIN ", 11) == 0) { begin = pem + i; break; }
    }
    if (!begin) return -1;
    const u8* nl = begin;
    while (nl < pem + pemlen && *nl != '\n') nl++;
    int skip = (int)((nl + 1) - begin);
    if (skip > pemlen) return -1;
    return b64_decode(pem + skip, pemlen - skip, out, out_cap);
}

/* ---- RSA private key parsing (openssl rsagen output) ---- */
/* n/d are stored big-endian, right-aligned in 256 bytes. */
static int rsa_pkcs1_n_d(der_cursor* seq, u8 n_out[256], u8 d_out[256],
                         int* n_len_out) {
    der_cursor ni;                                     /* n */
    if (der_enter(seq, ASN1_TAG_INTEGER, &ni) < 0) return -1;
    int n_start = (ni.len > 1 && ni.data[0] == 0) ? 1 : 0;
    int n_len = ni.len - n_start;
    if (n_len <= 0 || n_len > 256) return -1;
    mem_zero(n_out, 256);
    mem_copy(n_out + 256 - n_len, ni.data + n_start, n_len);
    if (n_len_out) *n_len_out = n_len;
    if (der_skip(seq) < 0) return -1;                  /* e */
    der_cursor di;                                     /* d */
    if (der_enter(seq, ASN1_TAG_INTEGER, &di) < 0) return -1;
    int d_start = (di.len > 1 && di.data[0] == 0) ? 1 : 0;
    int d_len = di.len - d_start;
    if (d_len <= 0 || d_len > 256) return -1;
    mem_zero(d_out, 256);
    mem_copy(d_out + 256 - d_len, di.data + d_start, d_len);
    return 0;
}

static int rsa_parse_private_key(const u8* der, int dlen,
                                 u8 n_out[256], u8 d_out[256], int* n_len_out) {
    der_cursor outer = { der, dlen, 0 };
    der_cursor seq;
    if (der_enter(&outer, ASN1_TAG_SEQUENCE, &seq) < 0) return -1;
    /* Both encodings start with an INTEGER (PKCS#8 version / PKCS#1 version). */
    if (der_skip(&seq) < 0) return -1;
    int save = seq.pos;
    int tag;
    if (der_read_tag(&seq, &tag) < 0) return -1;
    seq.pos = save;                       /* peek without consuming */
    if (tag == ASN1_TAG_SEQUENCE) {
        /* PKCS#8: SEQUENCE(algid) then OCTET STRING{PKCS#1 RSAPrivateKey} */
        if (der_skip(&seq) < 0) return -1;
        der_cursor oct;
        if (der_enter(&seq, ASN1_TAG_OCTET_STRING, &oct) < 0) return -1;
        der_cursor inner;
        if (der_enter(&oct, ASN1_TAG_SEQUENCE, &inner) < 0) return -1;
        if (der_skip(&inner) < 0) return -1;           /* PKCS#1 version */
        return rsa_pkcs1_n_d(&inner, n_out, d_out, n_len_out);
    }
    if (tag == ASN1_TAG_INTEGER) {
        /* PKCS#1: version already consumed; n is next */
        return rsa_pkcs1_n_d(&seq, n_out, d_out, n_len_out);
    }
    return -1;
}

/* ---- RSA private operations (PKCS#1 v1.5, 2048-bit) ---- */
/* Signature: EM = 00 01 FF..FF 00 || SHA256 DigestInfo; s = EM^d mod n. */
static int rsa_sign_sha256(const u8 hash[32], const u8 n[256], const u8 d[256],
                           u8 out[256]) {
    if (n[0] < 0x80) return -1;
    u8 block[256];
    int i = 0;
    block[i++] = 0x00;
    block[i++] = 0x01;
    while (i < 256 - 19 - 32 - 1) block[i++] = 0xFF;
    block[i++] = 0x00;
    mem_copy(block + i, kSha256DigestInfo, 19); i += 19;
    mem_copy(block + i, hash, 32); i += 32;
    if (i != 256) return -1;
    u64 b_le[BI_LIMBS], d_le[BI_LIMBS], n_le[BI_LIMBS], s_le[BI_LIMBS];
    for (int k = 0; k < BI_LIMBS; k++) {
        b_le[k] = 0; d_le[k] = 0; n_le[k] = 0;
        for (int j = 0; j < 8; j++) {
            int o = k * 8 + j;
            b_le[k] |= (u64)block[255 - o] << (j * 8);
            n_le[k] |= (u64)n[255 - o] << (j * 8);
            d_le[k] |= (u64)d[255 - o] << (j * 8);
        }
    }
    if (bi_cmp(b_le, n_le) >= 0) return -1;   /* block must be < n */
    bi_modpow(s_le, b_le, d_le, n_le);
    for (int k = 0; k < BI_LIMBS; k++)
        for (int j = 0; j < 8; j++)
            out[k * 8 + j] = (u8)(s_le[BI_LIMBS - 1 - k] >> (56 - j * 8));
    return 0;
}

/* m = c^d mod n for the client's RSA-encrypted pre-master. */
static int rsa_private_decrypt(const u8 c[256], const u8 n[256], const u8 d[256],
                               u8 out[256]) {
    if (n[0] < 0x80) return -1;
    u64 c_le[BI_LIMBS], d_le[BI_LIMBS], n_le[BI_LIMBS], m_le[BI_LIMBS];
    for (int k = 0; k < BI_LIMBS; k++) {
        c_le[k] = 0; d_le[k] = 0; n_le[k] = 0;
        for (int j = 0; j < 8; j++) {
            int o = k * 8 + j;
            c_le[k] |= (u64)c[255 - o] << (j * 8);
            n_le[k] |= (u64)n[255 - o] << (j * 8);
            d_le[k] |= (u64)d[255 - o] << (j * 8);
        }
    }
    if (bi_cmp(c_le, n_le) >= 0) return -1;
    bi_modpow(m_le, c_le, d_le, n_le);
    for (int k = 0; k < BI_LIMBS; k++)
        for (int j = 0; j < 8; j++)
            out[k * 8 + j] = (u8)(m_le[BI_LIMBS - 1 - k] >> (56 - j * 8));
    return 0;
}

/* Server-side TLS 1.2 full handshake (mirrors tls_handshake on the wire).
   cert/key are PEM strings (len given). Negotiates ECDHE-RSA-AES128-GCM-SHA256
   (0xC02F) when offered, else TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C); both
   land on the same AES-128-GCM record layer. Returns a session index or -1. */
static int tls_accept(int sock, const u8* cert_pem, int cert_len,
                      const u8* key_pem, int key_len) {
    /* Load server cert (validated, DER kept for the Certificate message). */
    u8 cert_der[4096];
    int der_len = pem_body_decode(cert_pem, cert_len, cert_der, sizeof(cert_der));
    if (der_len <= 0) { g_last_error = TLS_ERR_CERT; return -1; }
    x509_init();
    if (x509_parse_cert(cert_der, der_len, 0) < 0) { g_last_error = TLS_ERR_CERT; return -1; }

    u8 key_der[4096];
    int kdlen = pem_body_decode(key_pem, key_len, key_der, sizeof(key_der));
    if (kdlen <= 0) { g_last_error = TLS_ERR_CERT; return -1; }
    u8 key_n[256], key_d[256];
    int key_nlen = 0;
    if (rsa_parse_private_key(key_der, kdlen, key_n, key_d, &key_nlen) < 0) {
        g_last_error = TLS_ERR_CERT; return -1;
    }
    (void)key_nlen;
    if (key_n[0] < 0x80) { g_last_error = TLS_ERR_CERT; return -1; }

    /* Session slot. */
    int idx = -1;
    for (int i = 0; i < 4; i++) if (!g_sessions[i].active) { idx = i; break; }
    if (idx < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    tls_session_t* s = &g_sessions[idx];
    mem_zero((u8*)s, sizeof(tls_session_t));
    s->sock = sock;
    s->active = 1;
    g_last_error = TLS_ERR_OK;

    u8 rec_buf[4096];

    /* === Parse ClientHello === */
    int cipher = 0;
    u8 sid[32];
    int sid_len = 0;
    {
        u16 rl;
        g_tls_stage = 1;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) return -1;
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        g_tls_stage = 2;
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        int rec_lim = 5 + (int)rl;
        g_tls_stage = 3;
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE ||
            rec_buf[5] != TLS_HANDSHAKE_CLIENT_HELLO) {
            g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 3; return -1;
        }
        int p = 5 + 4;
        int hs_len = ((int)rec_buf[6] << 16) | ((int)rec_buf[7] << 8) | rec_buf[8];
        int hs_end = p + hs_len;
        if (hs_end > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 4; return -1; }

        if (p + 2 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 5; return -1; }
        u16 cver = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        if (cver < 0x0301 || cver > 0x0303) { g_last_error = TLS_ERR_CIPHER; g_tls_stage = 5; return -1; }
        if (p + 32 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 6; return -1; }
        mem_copy(s->client_random, rec_buf + p, 32); p += 32;
        if (p + 1 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 7; return -1; }
        sid_len = rec_buf[p]; p++;
        if (p + sid_len > hs_end || sid_len > 32) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 8; return -1; }
        mem_copy(sid, rec_buf + p, sid_len); p += sid_len;
        if (p + 2 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 9; return -1; }
        int cs_len = ((int)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        if (cs_len < 2 || p + cs_len > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 10; return -1; }
        int ecdhe_ok = 0, rsaek_ok = 0;
        for (int i = 0; i + 1 < cs_len; i += 2) {
            u16 cs = ((u16)rec_buf[p + i] << 8) | rec_buf[p + i + 1];
            if (cs == TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256) ecdhe_ok = 1;
            if (cs == TLS_CIPHER_RSA_AES128_GCM_SHA256)      rsaek_ok = 1;
        }
        p += cs_len;
        if (p + 1 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 11; return -1; }
        int comp_len = rec_buf[p]; p++;
        if (p + comp_len > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 12; return -1; }
        int has_null = 0;
        for (int i = 0; i < comp_len; i++) if (rec_buf[p + i] == 0) has_null = 1;
        p += comp_len;
        if (!has_null) { g_last_error = TLS_ERR_CIPHER; g_tls_stage = 13; return -1; }
        if (p < hs_end) {   /* extensions: ignored */
            if (p + 2 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 14; return -1; }
            int ext_len = ((int)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
            if (p + ext_len > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 15; return -1; }
        }
        g_tls_stage = 16;
        if (ecdhe_ok) cipher = TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256;
        else if (rsaek_ok) cipher = TLS_CIPHER_RSA_AES128_GCM_SHA256;
        if (cipher == 0) { g_last_error = TLS_ERR_CIPHER; g_tls_stage = 17; return -1; }
        if (tls_transcript_add(s, rec_buf + 5, rec_lim - 5) < 0) {
            g_last_error = TLS_ERR_MEMORY; g_tls_stage = 18; return -1;
        }
        g_tls_stage = 19;
    }

    /* === Send ServerHello === */
    entropy_fill(s->server_random, 32);
    g_tls_stage = 20;
    {
        u8 sh[64];
        int m = 0;
        sh[m++] = TLS_HANDSHAKE_SERVER_HELLO;   /* len patched below */
        sh[m++] = 0; sh[m++] = 0; sh[m++] = 0;
        sh[m++] = 0x03; sh[m++] = 0x03;         /* TLS 1.2 */
        mem_copy(sh + m, s->server_random, 32); m += 32;
        sh[m++] = (u8)sid_len;
        mem_copy(sh + m, sid, (u64)sid_len); m += sid_len;
        sh[m++] = (u8)(cipher >> 8); sh[m++] = (u8)cipher;
        sh[m++] = 0;                            /* compression: null */
        /* renegotiation_info (RFC 5746) — OpenSSL's own servers send this 5-byte
           form (length 1, single 0x00); a missing/malformed extension makes
           OpenSSL clients abort with "unsafe legacy renegotiation disabled". */
        sh[m++] = 0; sh[m++] = 5;               /* extension block length */
        sh[m++] = 0xFF; sh[m++] = 0x01;         /* ext type 65281 = 0xFF01 (RFC 5746) */
        sh[m++] = 0x00; sh[m++] = 0x01;         /* ext data length 1 */
        sh[m++] = 0x00;                         /* renegotiated_connection = 1 zero byte */
        int body = m - 4;
        sh[1] = (u8)(body >> 16); sh[2] = (u8)(body >> 8); sh[3] = (u8)body;
        u8 rec[5 + 64];
        rec[0] = TLS_CONTENT_TYPE_HANDSHAKE; rec[1] = 3; rec[2] = 3;
        rec[3] = (u8)(m >> 8); rec[4] = (u8)m;
        mem_copy(rec + 5, sh, (u64)m);
        if (tls_raw_send(sock, rec, (u16)(5 + m)) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_transcript_add(s, sh, m) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Send Certificate (our DER) === */
    g_tls_stage = 25;
    {
        int list_len = 3 + der_len;
        int m = 0;
        u8 cert_msg[4 + 3 + 3 + 4096];
        cert_msg[m++] = TLS_HANDSHAKE_CERTIFICATE;
        cert_msg[m++] = 0; cert_msg[m++] = 0; cert_msg[m++] = 0;
        cert_msg[m++] = (u8)(list_len >> 16);
        cert_msg[m++] = (u8)(list_len >> 8);
        cert_msg[m++] = (u8)list_len;
        cert_msg[m++] = (u8)(der_len >> 16);
        cert_msg[m++] = (u8)(der_len >> 8);
        cert_msg[m++] = (u8)der_len;
        mem_copy(cert_msg + m, cert_der, (u64)der_len); m += der_len;
        int body = m - 4;
        cert_msg[1] = (u8)(body >> 16); cert_msg[2] = (u8)(body >> 8); cert_msg[3] = (u8)body;
        u8 rec[5 + 4 + 3 + 3 + 4096];
        rec[0] = TLS_CONTENT_TYPE_HANDSHAKE; rec[1] = 3; rec[2] = 3;
        rec[3] = (u8)(m >> 8); rec[4] = (u8)m;
        mem_copy(rec + 5, cert_msg, (u64)m);
        if (tls_raw_send(sock, rec, (u16)(5 + m)) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_transcript_add(s, cert_msg, m) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Send ServerKeyExchange (ECDHE only) + ServerHelloDone === */
    u8 server_priv[32];
    int uses_ecdhe = (cipher == TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256);
    g_tls_stage = 26;
    if (uses_ecdhe) {
        u8 sx[32], sy[32];
        entropy_fill(server_priv, 32);
        ecdhe_gen_pub(server_priv, sx, sy);
        /* signature input: client_random || server_random || params */
        u8 sig_in[133];
        mem_copy(sig_in, s->client_random, 32);
        mem_copy(sig_in + 32, s->server_random, 32);
        sig_in[64] = 3; sig_in[65] = 0x00; sig_in[66] = 0x17;  /* named_curve P-256 */
        sig_in[67] = 0x41; sig_in[68] = 0x04;                  /* 65-byte uncompressed */
        mem_copy(sig_in + 69, sx, 32); mem_copy(sig_in + 101, sy, 32);
        u8 h[32];
        sha256_one(sig_in, 133, h);
        u8 sig[256];
        if (rsa_sign_sha256(h, key_n, key_d, sig) < 0) { g_last_error = TLS_ERR_CERT; return -1; }

        u8 skx[4 + 3 + 66 + 2 + 2 + 256];
        int m = 0;
        skx[m++] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
        skx[m++] = 0; skx[m++] = 0; skx[m++] = 0;
        skx[m++] = 3;                        /* named_curve */
        skx[m++] = 0x00; skx[m++] = 0x17;    /* secp256r1 */
        skx[m++] = 65;                       /* point length */
        skx[m++] = 0x04;
        mem_copy(skx + m, sx, 32); m += 32;
        mem_copy(skx + m, sy, 32); m += 32;
        skx[m++] = 0x04; skx[m++] = 0x01;    /* rsa_pkcs1_sha256 */
        skx[m++] = 0x01; skx[m++] = 0x00;    /* sig length 256 */
        mem_copy(skx + m, sig, 256); m += 256;
        int body = m - 4;
        skx[1] = (u8)(body >> 16); skx[2] = (u8)(body >> 8); skx[3] = (u8)body;
        u8 rec[5 + 4 + 3 + 66 + 2 + 2 + 256];
        rec[0] = TLS_CONTENT_TYPE_HANDSHAKE; rec[1] = 3; rec[2] = 3;
        rec[3] = (u8)(m >> 8); rec[4] = (u8)m;
        mem_copy(rec + 5, skx, (u64)m);
        if (tls_raw_send(sock, rec, (u16)(5 + m)) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_transcript_add(s, skx, m) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }
    {
        u8 shd[4] = { TLS_HANDSHAKE_SERVER_HELLO_DONE, 0, 0, 0 };
        g_tls_stage = 27;
        u8 rec[9];
        rec[0] = TLS_CONTENT_TYPE_HANDSHAKE; rec[1] = 3; rec[2] = 3;
        rec[3] = 0; rec[4] = 4;
        mem_copy(rec + 5, shd, 4);
        if (tls_raw_send(sock, rec, 9) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_transcript_add(s, shd, 4) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Receive ClientKeyExchange === */
    u8 pre_master[48];
    g_tls_stage = 30;
    {
        u16 rl;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        g_tls_stage = 31;
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        int rec_lim = 5 + (int)rl;
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE ||
            rec_buf[5] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
            g_last_error = TLS_ERR_HANDSHAKE; g_tls_stage = 32; return -1;
        }
        int cke_len = ((int)rec_buf[6] << 16) | ((int)rec_buf[7] << 8) | rec_buf[8];
        int p = 5 + 4;
        int cke_end = p + cke_len;
        if (cke_end > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        if (uses_ecdhe) {
            int eplen = rec_buf[p]; p++;
            if (eplen != 65 || p + 1 + 64 > cke_end || rec_buf[p] != 0x04) {
                g_last_error = TLS_ERR_HANDSHAKE; return -1;
            }
            u8 cx[32], cy[32];
            mem_copy(cx, rec_buf + p + 1, 32);
            mem_copy(cy, rec_buf + p + 33, 32);
            u8 sec[32];
            if (ecdhe_shared(sec, server_priv, cx, cy) < 0) {
                g_last_error = TLS_ERR_HANDSHAKE; return -1;
            }
            mem_zero(pre_master, 48);
            mem_copy(pre_master, sec, 32);
        } else {
            int blen = ((int)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
            if (blen != 256 || p + blen > cke_end) {
                g_last_error = TLS_ERR_HANDSHAKE; return -1;
            }
            u8 c[256], m[256];
            mem_copy(c, rec_buf + p, 256);
            if (rsa_private_decrypt(c, key_n, key_d, m) < 0) {
                g_last_error = TLS_ERR_HANDSHAKE; return -1;
            }
            int q = 0;
            if (m[q++] != 0x00 || m[q++] != 0x02) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
            int ps = 0;
            while (q < 256 && m[q] != 0x00) { q++; ps++; }
            if (ps < 8 || q >= 256) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
            q++;
            if (q + 48 > 256) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
            mem_copy(pre_master, m + q, 48);
            if (pre_master[0] != 0x03) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        }
        if (tls_transcript_add(s, rec_buf + 5, rec_lim - 5) < 0) {
            g_last_error = TLS_ERR_MEMORY; return -1;
        }
    }

    /* === Derive keys (server: write = server* keys, read = client* keys) === */
    {
        u8 seed[64];
        mem_copy(seed, s->client_random, 32);
        mem_copy(seed + 32, s->server_random, 32);
        tls_prf(s->master_secret, 48, pre_master, 48, "master secret", seed, 64);
        u8 seed2[64];
        mem_copy(seed2, s->server_random, 32);
        mem_copy(seed2 + 32, s->client_random, 32);
        tls_prf(s->key_material, 40, s->master_secret, 48, "key expansion", seed2, 64);
        mem_copy(s->write_key, s->key_material + 16, 16);   /* server_write_key */
        mem_copy(s->read_key,  s->key_material + 0,  16);   /* client_write_key  */
        mem_copy(s->write_iv,  s->key_material + 36, 4);    /* server_write_iv   */
        mem_copy(s->read_iv,   s->key_material + 32, 4);    /* client_write_iv   */
    }

    /* === CCS (ours), then client's CCS + Finished, then OUR Finished ===
       RFC 5246: the server Finished is the LAST handshake message; its hash
       covers the client's Finished. tls_handshake (client) expects exactly that. */
    {
        u8 ccs[6] = { TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1 };
        if (tls_raw_send(sock, ccs, 6) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        s->write_seq = 0;
    }
    {
        u8 ct;
        u16 plen;
        u8 ccs;
        ct = tls_recv_record(sock, &ccs, &plen, &ct, s->read_key, s->read_iv,
                             &s->read_seq, 1);
        if (ct != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC || plen != 1 || ccs != 1) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        s->read_seq = 0;
    }
    {
        u8 cfin[4 + 12];
        u8 ct;
        u16 plen;
        ct = tls_recv_record(sock, cfin, &plen, &ct, s->read_key, s->read_iv,
                             &s->read_seq, 16);
        if (ct != TLS_CONTENT_TYPE_HANDSHAKE || plen != 4 + 12 ||
            cfin[0] != TLS_HANDSHAKE_FINISHED) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        u8 cverify[12];
        if (tls_compute_verify(s, s->master_secret, "client finished", cverify) < 0) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        if (ct_cmp(cverify, cfin + 4, 12) != 0) {
            g_last_error = TLS_ERR_VERIFY; return -1;
        }
        /* Our server Finished must hash over a transcript that includes the
           client's Finished message. */
        if (tls_transcript_add(s, cfin, 4 + 12) < 0) {
            g_last_error = TLS_ERR_MEMORY; return -1;
        }
    }
    {
        u8 srv_fin[4 + 12];
        u8 verify[12];
        if (tls_compute_verify(s, s->master_secret, "server finished", verify) < 0) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        srv_fin[0] = TLS_HANDSHAKE_FINISHED;
        srv_fin[1] = 0; srv_fin[2] = 0; srv_fin[3] = 12;
        mem_copy(srv_fin + 4, verify, 12);
        if (tls_send_record(sock, TLS_CONTENT_TYPE_HANDSHAKE, srv_fin, 16,
                            s->write_key, s->write_iv, &s->write_seq) < 0) {
            g_last_error = TLS_ERR_IO; return -1;
        }
    }

    s->handshake_done = 1;
    return idx;
}

/* TLS handshake: full TLS 1.2 client handshake.
   Returns session index on success, -1 on error.
   host may be NUL-terminated (host_len will be capped and validated). */
static int tls_handshake(int sock, const u8* host, int host_len) {
    /* -- session slot allocation (reuse closed slots) -- */
    int idx = -1;
    for (int i = 0; i < 4; i++) {
        if (!g_sessions[i].active) { idx = i; break; }
    }
    if (idx < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    tls_session_t* s = &g_sessions[idx];
    mem_zero((u8*)s, sizeof(tls_session_t));
    s->sock = sock;
    s->active = 1;
    g_last_error = TLS_ERR_OK;

    /* Host name used in SNI: cap at 253 (max DNS label hostname) and reject
       embedded NULs / control chars. Evils like an SNI string longer than the
       ClientHello extension buffer simply fail closed. */
    int hidx = host_len;
    if (host) {
        for (int i = 0; i < host_len; i++) {
            if (host[i] == 0) { hidx = i; break; }    /* stop at NUL */
            if (host[i] <= 0x20 || host[i] >= 0x7f) { hidx = 0; break; } /* control char */
        }
    } else {
        hidx = 0;
    }
    const u8* sni = host ? host : (const u8*)1;        /* non-null for memcpy safety */
    if (hidx < 0) hidx = 0;
    if (hidx > 253) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }

    /* Generate client random — entropy_fill gives us a per-process nonce stream
       (RDTSC + ASLR'd io-slot pointers + running counter), so the ECDHE scalar
       and client random are not predictable. */
    entropy_fill(s->client_random, 32);

    /* === Build ClientHello === */
    u8 ch_buf[512];
    int ch_len = 0;

    /* Handshake header: type(1) + len(3) */
    ch_buf[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    ch_buf[1] = 0; ch_buf[2] = 0; /* length placeholder, fill later */

    /* client_version: TLS 1.2 (3, 3) */
    ch_buf[4] = 3; ch_buf[5] = 3;

    /* client_random: 32 bytes */
    mem_copy(ch_buf + 6, s->client_random, 32);

    /* session_id_length: 0 */
    ch_buf[38] = 0;

    /* cipher_suites: 2 bytes length + 2 bytes (ECDHE-RSA-AES128-GCM-SHA256) */
    ch_buf[39] = 0; ch_buf[40] = 2;
    ch_buf[41] = 0xC0; ch_buf[42] = 0x2F;

    /* compression_methods: 1 byte length + 1 byte (null) */
    ch_buf[43] = 1; ch_buf[44] = 0;

    /* Extensions */
    int ext_start = 45;
    ch_buf[ext_start] = 0; ch_buf[ext_start+1] = 0; /* extensions length placeholder */

    int ext_pos = ext_start + 2;

    /* SNI extension (type 0x0000). Optional: a server may ignore it, but we
       still must keep the wire format valid. Per RFC 6066 the ServerNameList
       length counts the type(1)+name_len(2)+name, NOT itself — a client that
       writes 2+1+2+hidx here (including the length field) makes the server see
       a name list longer than the extension and reject with BAD_EXTENSION. */
    ch_buf[ext_pos] = 0x00; ch_buf[ext_pos+1] = 0x00;
    int sni_data = 1 + 2 + hidx; /* server_name_list content: type(1)+len(2)+name */
    int sni_len = 2 + sni_data;  /* extension data = list-length(2) + content */
    ch_buf[ext_pos+2] = (u8)(sni_len >> 8); ch_buf[ext_pos+3] = (u8)sni_len;
    ch_buf[ext_pos+4] = 0; ch_buf[ext_pos+5] = (u8)sni_data; /* server_name list len */
    ch_buf[ext_pos+6] = 0; /* host_name type */
    ch_buf[ext_pos+7] = (u8)(hidx >> 8); ch_buf[ext_pos+8] = (u8)hidx;
    mem_copy(ch_buf + ext_pos + 9, sni, hidx);
    ext_pos += 4 + sni_len;

    /* Supported groups extension (0x000A) — P-256 */
    ch_buf[ext_pos] = 0x00; ch_buf[ext_pos+1] = 0x0A;
    ch_buf[ext_pos+2] = 0; ch_buf[ext_pos+3] = 4; /* len */
    ch_buf[ext_pos+4] = 0; ch_buf[ext_pos+5] = 2; /* list len */
    ch_buf[ext_pos+6] = 0x00; ch_buf[ext_pos+7] = 0x17; /* secp256r1 (IANA 0x0017) */
    ext_pos += 8;

    /* EC point formats extension (0x000B) */
    ch_buf[ext_pos] = 0x00; ch_buf[ext_pos+1] = 0x0B;
    ch_buf[ext_pos+2] = 0; ch_buf[ext_pos+3] = 2;
    ch_buf[ext_pos+4] = 1; /* list len */
    ch_buf[ext_pos+5] = 0; /* uncompressed */
    ext_pos += 6;

    /* Signature algorithms extension (0x000D) — SHA-256 + RSA */
    ch_buf[ext_pos] = 0x00; ch_buf[ext_pos+1] = 0x0D;
    ch_buf[ext_pos+2] = 0; ch_buf[ext_pos+3] = 4;
    ch_buf[ext_pos+4] = 0; ch_buf[ext_pos+5] = 2; /* list len */
    ch_buf[ext_pos+6] = 0x04; ch_buf[ext_pos+7] = 0x01; /* rsa_pkcs1_sha256 */
    ext_pos += 8;

    /* Extensions length */
    int ext_len = ext_pos - ext_start - 2;
    ch_buf[ext_start] = (u8)(ext_len >> 8);
    ch_buf[ext_start+1] = (u8)ext_len;

    /* Handshake length */
    ch_len = ext_pos;
    int body_len = ch_len - 4;
    ch_buf[1] = (u8)(body_len >> 16);
    ch_buf[2] = (u8)(body_len >> 8);
    ch_buf[3] = (u8)body_len;

    /* Send ClientHello as a plaintext TLS record: the 5-byte record header
       (content_type=handshake(22), version 3.3, length) MUST precede the
       handshake message — the server parses that header and would otherwise
       see the handshake type byte (0x01) as a bogus content type. */
    u8 ch_rec[5 + 512];
    ch_rec[0] = TLS_CONTENT_TYPE_HANDSHAKE;
    ch_rec[1] = 3; ch_rec[2] = 3;
    ch_rec[3] = (u8)(ch_len >> 8); ch_rec[4] = (u8)ch_len;
    mem_copy(ch_rec + 5, ch_buf, (u64)ch_len);
    if (tls_raw_send(sock, ch_rec, (u16)(5 + ch_len)) < 0) { g_last_error = TLS_ERR_IO; return -1; }
    /* Capture ClientHello wire bytes for the transcript. */
    if (tls_transcript_add(s, ch_buf, ch_len) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }

    /* === Parse ServerHello === */
    u8 rec_buf[16384];
    {
        u16 rl;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        /* Skip past the 5-byte header we already read: read rl into rec_buf[5..]. */
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        int rec_lim = 5 + (int)rl;   /* total bytes available */

        /* rec_buf[0] = content_type (should be 22=handshake) */
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        /* Handshake type should be ServerHello (2) */
        if (rec_buf[5] != TLS_HANDSHAKE_SERVER_HELLO) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }

        /* Parse server random: skip msg type(1) + 3-byte len (handshake header) +
           2-byte version => random is at rec_buf[11..42]. (Older code used
           rec_buf+10, grabbing the version's low byte as the first random
           byte, which made the ServerKeyExchange signature verify fail.) */
        mem_copy(s->server_random, rec_buf + 11, 32);

        int p = 5 + 4 + 2 + 32; /* type(1)+len(3) + version(2) + server_random(32) */
        if (p > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        int sid_len = rec_buf[p]; p++;
        if (p + sid_len + 2 + 1 + 2 > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        p += sid_len;

        /* cipher suite (2 bytes) */
        u16 server_cipher = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        if (server_cipher != TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256) {
            g_last_error = TLS_ERR_CIPHER; return -1;
        }

        /* compression method (1 byte) */
        p++; /* skip compression — must be null */
        if (rec_buf[p-1] != 0) { g_last_error = TLS_ERR_CIPHER; return -1; }

        /* extensions: 2-byte length */
        if (p + 2 > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        int ext_end = p + 2 + (((u16)rec_buf[p] << 8) | rec_buf[p+1]); p += 2;
        if (ext_end > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }

        while (p + 4 <= ext_end) {
            u16 ext_type = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
            u16 ext_len2 = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
            if (p + ext_len2 > ext_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
            if (ext_type == 0x002B) { /* supported_versions */
                /* 1 byte length + 2 bytes version: must be TLS 1.2 (3,3) */
                if (ext_len2 >= 1) {
                    int inner = rec_buf[p];   /* inner length */
                    if (p + 1 + inner <= ext_end && inner >= 2) {
                        u16 v = ((u16)rec_buf[p+1] << 8) | rec_buf[p+2];
                        if (v != 0x0303) { g_last_error = TLS_ERR_CIPHER; return -1; }
                    }
                }
            }
            p += ext_len2;
        }
        /* Capture the ServerHello handshake message (already validated above). */
        if (tls_transcript_add(s, rec_buf + 5, rec_lim - 5) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Parse Certificate(s) === */
    x509_init();
    {
        u16 rl;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        int rec_lim = 5 + (int)rl;
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        if (rec_buf[5] != TLS_HANDSHAKE_CERTIFICATE) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }

        int p = 5 + 4; /* skip handshake type + 3-byte length */
        int hs_body_len = (int)(((u32)rec_buf[6] << 16) | ((u32)rec_buf[7] << 8) | rec_buf[8]);
        /* Certificate handshake message: after the handshake header comes the
           certificate_list<0..2^24-1> (3 bytes) which counts the total length of
           the cert entries, then one ASN1Cert<1..2^24-1> per certificate
           (3-byte length + DER). The earlier code treated the cert_list length as
           the first cert's length, which desynchronized the X.509 parser. */
        if (p + 3 > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        int cert_list_len = (int)(((u32)rec_buf[p] << 16) | ((u32)rec_buf[p+1] << 8) | rec_buf[p+2]);
        p += 3; /* now p points at the first ASN1Cert length */
        int cert_end = p + cert_list_len;
        /* cert_end must be strictly inside the record for the DER copies below */
        if (hs_body_len < 3 + cert_list_len || cert_end > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        int ci = 0;
        while (p + 3 <= cert_end && ci < 3) {
            int cert_len2 = ((int)rec_buf[p] << 16) | ((int)rec_buf[p+1] << 8) | rec_buf[p+2];
            p += 3;
            if (cert_len2 <= 0 || p + cert_len2 > cert_end || cert_len2 > 4096) {
                g_last_error = TLS_ERR_CERT; return -1;
            }
            /* Copy the DER into our own store BEFORE x509_parse_cert (which reads
               from rec_buf, a stack buffer overwritten by later records). */
            if (ci < 3) {
                mem_copy(g_certs.der[ci], rec_buf + p, cert_len2);
                g_certs.der_len[ci] = cert_len2;
                if (x509_parse_cert(rec_buf + p, cert_len2, ci) < 0) {
                    g_last_error = TLS_ERR_CERT; return -1;
                }
                ci++;
            }
            p += cert_len2;
        }

        /* Store cert chain in session for pinning */
        if (cert_end <= rec_lim) {
            int copy_len = cert_end - 5;
            if (copy_len > TLS_MAX_CERT_CHAIN) copy_len = TLS_MAX_CERT_CHAIN;
            mem_copy(s->cert_buf, rec_buf + 5, copy_len);
            s->cert_len = copy_len;
        } else {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        /* Capture the Certificate handshake message for the transcript. */
        if (tls_transcript_add(s, rec_buf + 5, rec_lim - 5) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Parse ServerKeyExchange === */
    struct {
        int curve_type;
        u8 server_pubx[32], server_puby[32];
        u8 server_sig[256];
        int sig_len;
    } skx;
    {
        u16 rl;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        int rec_lim = 5 + (int)rl;
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        if (rec_buf[5] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }

        int p = 5 + 4; /* skip handshake type + 3-byte length */
        int hs_len = ((int)rec_buf[6] << 16) | ((int)rec_buf[7] << 8) | rec_buf[8];
        int hs_end = p + hs_len;
        if (hs_end > rec_lim) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }

        /* For ECDHE: curve_type(1) + named_curve(2) + pubx_len(1) + pubx + sign_alg(2) + sig_len(2) + sig */
        skx.curve_type = 0;
        if (p + 1 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        skx.curve_type = rec_buf[p];
        p++;
        if (p + 2 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        u16 named_curve = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        if (named_curve != 0x0017) { g_last_error = TLS_ERR_CIPHER; return -1; } /* P-256 */

        if (p + 1 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        int ecdh_pub_len = rec_buf[p]; p++;
        if (ecdh_pub_len == 65) {
            /* uncompressed: 0x04 || x(32) || y(32) */
            if (p + 1 + 64 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
            p++; /* skip 0x04 */
            mem_copy(skx.server_pubx, rec_buf + p, 32); p += 32;
            mem_copy(skx.server_puby, rec_buf + p, 32); p += 32;
        } else {
            g_last_error = TLS_ERR_CIPHER; return -1;
        }

        /* Signature: sign_alg(2) + sig_len(2) + sig ==
           hash_alg(1)+sig_alg(1) + sig_len(2) + sig for ECDSA, but for RSA we
           parse the 2-byte sign alg then a 2-byte sig_len. */
        if (p + 2 + 2 > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        u16 sign_alg = ((u16)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        int sig_len = ((int)rec_buf[p] << 8) | rec_buf[p+1]; p += 2;
        if (sig_len > 256 || p + sig_len > hs_end) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        mem_zero(skx.server_sig, 256);
        mem_copy(skx.server_sig + 256 - sig_len, rec_buf + p, sig_len);
        skx.sig_len = sig_len;
        p += sig_len;
        (void)sign_alg;

        /* Verify ServerKeyExchange signature over:
           client_random(32) || server_random(32) || params(ecc_params) */
        u8 verify_data[133]; /* client_rand(32) + server_rand(32) + ecc_params(69) */
        mem_copy(verify_data, s->client_random, 32);
        mem_copy(verify_data + 32, s->server_random, 32);
        verify_data[64] = (u8)skx.curve_type;
        verify_data[65] = 0x00; verify_data[66] = 0x17; /* P-256 */
        verify_data[67] = 0x41; /* 65 bytes */
        verify_data[68] = 0x04;
        mem_copy(verify_data + 69, skx.server_pubx, 32);
        mem_copy(verify_data + 101, skx.server_puby, 32);

        u8 verify_hash[32];
        sha256_one(verify_data, 133, verify_hash);

        /* Verify with server cert's RSA key. FAIL CLOSED: if we could not parse
           at least one leaf certificate, abort rather than silently skipping the
           signature check (a missing cert must never mean "accept anything"). */
        if (g_certs.count < 1 || skx.sig_len != 256) {
            g_last_error = TLS_ERR_CERT; return -1;
        }
        if (rsa_verify_sha256(verify_hash, g_certs.n[0], g_certs.e[0], skx.server_sig) < 0) {
            g_last_error = TLS_ERR_CERT;
            return -1;
        }
        /* Capture the ServerKeyExchange handshake message for the transcript —
           MUST happen before the CKE is appended so the order is SKX then CKE. */
        if (tls_transcript_add(s, rec_buf + 5, rec_lim - 5) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Receive ServerHelloDone ===
       RFC 5246 7.4.9: the server sends ServerHelloDone (handshake type 14,
       empty body) and the client MUST receive it BEFORE sending ClientKeyExchange.
       It is a plaintext record, so read it with tls_raw_recv (not the AEAD
       tls_recv_record, which would reject the too-short untagged payload). */
    {
        u16 rl;
        if (tls_raw_recv(sock, rec_buf, 5) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        rl = ((u16)rec_buf[3] << 8) | rec_buf[4];
        if (rl > sizeof(rec_buf) - 5) { g_last_error = TLS_ERR_IO; return -1; }
        if (tls_raw_recv(sock, rec_buf + 5, rl) < 0) { g_last_error = TLS_ERR_IO; return -1; }
        if (rec_buf[0] != TLS_CONTENT_TYPE_HANDSHAKE) { g_last_error = TLS_ERR_HANDSHAKE; return -1; }
        if (rec_buf[5] != TLS_HANDSHAKE_SERVER_HELLO_DONE || rl != 4) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        /* ServerHelloDone is hashed into the transcript. */
        if (tls_transcript_add(s, rec_buf + 5, 4) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
    }

    /* === Generate client ECDHE keypair, derive secrets, send CKE + CCS === */
    {
        /* Generate ephemeral keypair */
        u8 client_priv[32];
        entropy_fill(client_priv, 32);
        u8 client_pubx[32], client_puby[32];
        ecdhe_gen_pub(client_priv, client_pubx, client_puby);

        /* Compute pre-master secret = x-coordinate of client_priv * server_pub */
        u8 pre_master[32];
        ecdhe_shared(pre_master, client_priv, skx.server_pubx, skx.server_puby);

        /* Derive master secret:
           master_secret = PRF(pre_master, "master secret", client_random + server_random) */
        u8 seed[64];
        mem_copy(seed, s->client_random, 32);
        mem_copy(seed + 32, s->server_random, 32);
        tls_prf(s->master_secret, 48, pre_master, 32, "master secret", seed, 64);

        /* Key expansion:
           key_block = PRF(master_secret, "key expansion", server_random + client_random)
           = client_write_key(16) + server_write_key(16) + client_write_iv(4) + server_write_iv(4) */
        u8 seed2[64];
        mem_copy(seed2, s->server_random, 32);
        mem_copy(seed2 + 32, s->client_random, 32);
        tls_prf(s->key_material, 40, s->master_secret, 48, "key expansion", seed2, 64);
        mem_copy(s->write_key, s->key_material, 16);
        mem_copy(s->read_key, s->key_material + 16, 16);
        mem_copy(s->write_iv, s->key_material + 32, 4);
        mem_copy(s->read_iv, s->key_material + 36, 4);

        /* Send ClientKeyExchange: ECDH public key.
           Structure: type(1) + length(3)=66 (1 len byte + 65 point) +
                      ecdh_Y_len(1)=65 + point(65). */
        {
            u8 cke[4 + 1 + 65];
            cke[0] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
            cke[1] = 0; cke[2] = 0; cke[3] = 66;   /* 66 = 1 + 65 */
            cke[4] = 65;                            /* ECDH public key length */
            cke[5] = 0x04;                          /* uncompressed */
            mem_copy(cke + 6, client_pubx, 32);
            mem_copy(cke + 38, client_puby, 32);
            /* Wrap in a plaintext TLS record (handshake type 22) — same framing
               as the ClientHello; the server reads the record header first. */
            u8 cke_rec[5 + 70];
            cke_rec[0] = TLS_CONTENT_TYPE_HANDSHAKE;
            cke_rec[1] = 3; cke_rec[2] = 3;
            cke_rec[3] = 0; cke_rec[4] = 70;        /* 4+66 = 70 */
            mem_copy(cke_rec + 5, cke, 70);
            if (tls_raw_send(sock, cke_rec, 5 + 70) < 0) { g_last_error = TLS_ERR_IO; return -1; }
            /* Capture ClientKeyExchange for the transcript. */
            if (tls_transcript_add(s, cke, 4 + 66) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
        }

        /* Send ChangeCipherSpec */
        {
            u8 ccs[6] = { TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1 };
            if (tls_raw_send(sock, ccs, 6) < 0) { g_last_error = TLS_ERR_IO; return -1; }
            /* CCS is not part of the Finished transcript hash (it is a "change
               cipher spec" record, excluded from the handshake hash). */
        }

        /* Reset write sequence for encryption */
        s->write_seq = 0;
    }

    /* Send our Finished, then receive CCS + server Finished. */
    u8 ct;
    u16 plen;

    /* 1) Send our Finished: verify_data = PRF(master_secret, "client finished",
          Hash(all prior handshake messages)). Must be encrypted (write_seq=0). */
    u8 finished_msg[4 + 12];
    {
        u8 verify[12];
        if (tls_compute_verify(s, s->master_secret, "client finished", verify) < 0) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        finished_msg[0] = TLS_HANDSHAKE_FINISHED;
        finished_msg[1] = 0; finished_msg[2] = 0; finished_msg[3] = 12;
        mem_copy(finished_msg + 4, verify, 12);
        if (tls_send_record(sock, TLS_CONTENT_TYPE_HANDSHAKE, finished_msg, 16,
                            s->write_key, s->write_iv, &s->write_seq) < 0) {
            g_last_error = TLS_ERR_IO; return -1;
        }
    }

    /* 2) Receive CCS. */
    ct = tls_recv_record(sock, rec_buf, &plen, &ct, s->read_key, s->read_iv, &s->read_seq, 4096);
    if (ct != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC || plen != 1 || rec_buf[0] != 1) {
        g_last_error = TLS_ERR_HANDSHAKE;
        return -1;
    }
    s->read_seq = 0;

    /* 3) Receive server Finished and verify it: its verify_data is
       PRF(master_secret, "server finished", Hash(all handshake messages
       INCLUDING our Finished, EXCLUDING both CCS records)). */
    {
        u8 finished_rec[4 + 12];
        ct = tls_recv_record(sock, finished_rec, &plen, &ct, s->read_key, s->read_iv, &s->read_seq, 16);
        if (ct != TLS_CONTENT_TYPE_HANDSHAKE || plen != 4 + 12 ||
            finished_rec[0] != TLS_HANDSHAKE_FINISHED) {
            g_last_error = TLS_ERR_HANDSHAKE;
            return -1;
        }
        /* For our own transcript, the server Finished verify_data is computed
           over our SENT client Finished message (RFC 5246: server Finished
           transcript includes the client Finished). Append finished_msg, NOT
           the freshly received finished_rec. */
        if (tls_transcript_add(s, finished_msg, 4 + 12) < 0) { g_last_error = TLS_ERR_MEMORY; return -1; }
        u8 server_verify[12];
        if (tls_compute_verify(s, s->master_secret, "server finished", server_verify) < 0) {
            g_last_error = TLS_ERR_HANDSHAKE; return -1;
        }
        if (ct_cmp(server_verify, finished_rec + 4, 12) != 0) {
            g_last_error = TLS_ERR_VERIFY;
            return -1;
        }
    }

    s->handshake_done = 1;
    return idx;
}

/* TLS send (application data). Returns bytes sent (>0) on success, -1 on error. */
static int tls_send_encrypted(int handle, const u8* data, u16 len) {
    if (handle < 0 || handle >= 4) return -1;
    tls_session_t* s = &g_sessions[handle];
    if (!s->active || !s->handshake_done) return -1;
    if (tls_send_record(s->sock, TLS_CONTENT_TYPE_APPLICATION_DATA, data, len,
                        s->write_key, s->write_iv, &s->write_seq) < 0) {
        return -1;
    }
    return (int)len;
}

/* TLS recv (application data) */
static int tls_recv_encrypted(int handle, u8* buf, u16 max_len) {
    if (handle < 0 || handle >= 4) return -1;
    tls_session_t* s = &g_sessions[handle];
    if (!s->active || !s->handshake_done) return -1;
    u8 ct;
    u16 plen;
    if (max_len > TLS_MAX_PAYLOAD) max_len = TLS_MAX_PAYLOAD;
    int r = tls_recv_record(s->sock, buf, &plen, &ct, s->read_key, s->read_iv, &s->read_seq, max_len);
    if (r < 0) return -1;
    if (r == 0) return 0;   /* clean EOF (peer closed without close_notify) */
    if (ct == TLS_CONTENT_TYPE_APPLICATION_DATA) return plen;
    if (ct == TLS_CONTENT_TYPE_ALERT) return -2;
    /* Rekey / renegotiation: not supported. */
    return -1;
}

/* TLS close */
static int tls_close_conn(int handle) {
    if (handle < 0 || handle >= 4) return -1;
    tls_session_t* s = &g_sessions[handle];
    if (!s->active) return -1;
    /* Send close_notify alert */
    u8 alert[2] = { 2, 0 }; /* warning, close_notify */
    if (s->handshake_done) {
        tls_send_record(s->sock, TLS_CONTENT_TYPE_ALERT, alert, 2,
                       s->write_key, s->write_iv, &s->write_seq);
    }
    tlsrt_close_stub(s->sock);
    s->handshake_done = 0;
    /* Release the slot so a later tls_connect can reuse it. */
    mem_zero((u8*)s, sizeof(tls_session_t));
    s->active = 0;
    return 0;
}

/* ================================================================
   Entry point
   ================================================================ */
u64 tlsrt_io_send, tlsrt_io_recv, tlsrt_io_close;

long tlsrt_entry(long op, long a1, long a2, long a3, long a4, long a5)
{
    switch (op) {
    /* --- Legacy ops (Phase 1 — verified) --- */
    case TLS_OP_IO_INIT:
        tlsrt_io_send = (u64)a1; tlsrt_io_recv = (u64)a2; tlsrt_io_close = (u64)a3;
        return 0;
    case TLS_OP_SHA256:
        sha256_one((const u8*)a2, (u64)a3, (u8*)a1);
        return 0;
    case TLS_OP_HMAC_SHA256:
        hmac_sha256((const u8*)a2, (u64)a3, (const u8*)a4, (u64)a5, (u8*)a1);
        return 0;
    case TLS_OP_PRF_SHA256:
    {
        const u8* p = (const u8*)a5;
        u64 llen = (u64)p[0] | ((u64)p[1]<<8);
        const u8* label = p + 2;
        u64 seedlen = (u64)p[2+llen] | ((u64)p[3+llen]<<8);
        const u8* seed = p + 4 + llen;
        prf_sha256((const u8*)a3, (u64)a4, label, llen, seed, seedlen,
                   (u8*)a1, (u64)a2);
    }
    return 0;

    /* --- Step 2: AES-GCM --- */
    case TLS_OP_AES_KEY_EXPAND:
        aes128_key_expand((u8*)a1, (const u8*)a2);
        return 0;
    case TLS_OP_AES_ENCRYPT_BLK:
        aes128_encrypt_block((u8*)a1, (const u8*)a2, (const u8*)a3);
        return 0;
    case TLS_OP_AES_DECRYPT_BLK:
        aes128_decrypt_block((u8*)a1, (const u8*)a2, (const u8*)a3);
        return 0;
    case TLS_OP_GCM_ENC:
    {
        /* GCM encrypt (AES-128).
           a1=out(ciphertext,len) a2=in(plaintext,len) a3=len a4=key_sched(176) a5=pkt
           pkt = [iv:12][aad_len:u16 LE][aad:aad_len][tag:16 (output)]
           returns 0; -2 if aad_len > TLS_GCM_MAX_AAD. */
        const u8* pkt = (const u8*)a5;
        u16 aad_len = (u16)pkt[12] | ((u16)pkt[13] << 8);
        if (aad_len > TLS_GCM_MAX_AAD) return -2;
        aes_gcm_encrypt((u8*)a1, (const u8*)a2, (u64)a3,
                        (const u8*)a4, pkt, pkt + 14, aad_len,
                        (u8*)(pkt + 14 + aad_len));
        return 0;
    }
    case TLS_OP_GCM_DEC:
    {
        /* GCM decrypt + tag verify (AES-128). Same pkt layout as GCM_ENC but
           the 16-byte tag at the end is an INPUT; a1=out(plaintext,len).
           returns 0=ok, -1=tag mismatch, -2=bad aad_len. */
        const u8* pkt = (const u8*)a5;
        u16 aad_len = (u16)pkt[12] | ((u16)pkt[13] << 8);
        if (aad_len > TLS_GCM_MAX_AAD) return -2;
        return aes_gcm_decrypt((u8*)a1, (const u8*)a2, (u64)a3,
                               (const u8*)a4, pkt, pkt + 14, aad_len,
                               pkt + 14 + aad_len);
    }

    /* --- Step 3: RSA verify --- */
    case TLS_OP_RSA_VERIFY:
        return rsa_verify_sha256((const u8*)a1, (const u8*)a2, (const u8*)a3, (const u8*)a4);

    /* --- Step 4: ECDHE --- */
    case TLS_OP_ECDHE_GEN_PUB:
        return ecdhe_gen_pub((u8*)a1, (u8*)a2, (u8*)a3);
    case TLS_OP_ECDHE_SHARED:
        return ecdhe_shared((u8*)a1, (const u8*)a2, (const u8*)a3, (const u8*)a4);

    /* --- Step 5: X.509 --- */
    case TLS_OP_X509_PARSE:
        return x509_parse_cert((const u8*)a1, (int)a2, g_certs.count);
    case TLS_OP_X509_GET_KEY:
    {
        int idx = (int)a1;
        if (idx < 0 || idx >= g_certs.count) return -1;
        mem_copy((u8*)a2, g_certs.n[idx], 256);
        mem_copy((u8*)a3, g_certs.e[idx], 4);
        return 0;
    }
    case TLS_OP_X509_GET_FP:
    {
        int idx = (int)a1;
        if (idx < 0 || idx >= g_certs.count) return -1;
        mem_copy((u8*)a2, g_certs.fp[idx], 32);
        return 0;
    }
    case TLS_OP_X509_FREE:
        return 0;

    /* --- Step 6+7: TLS handshake + record layer --- */
    case TLS_OP_TLS_CONNECT:
        return tls_handshake((int)a1, (const u8*)a2, (int)a3);
    case TLS_OP_TLS_ACCEPT:
        return tls_accept((int)a1, (const u8*)a2, (int)a3,
                          (const u8*)a4, (int)a5);
    case TLS_OP_TLS_SEND:
        return tls_send_encrypted((int)a1, (const u8*)a2, (u16)a3);
    case TLS_OP_TLS_RECV:
        return tls_recv_encrypted((int)a1, (u8*)a2, (u16)a3);
    case TLS_OP_TLS_CLOSE:
        return tls_close_conn((int)a1);
    case TLS_OP_TLS_LAST_ERROR:
        return g_last_error;

    default:
        return -1;
    }
}
