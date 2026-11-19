// Host-side smoke test: maps the generated TLS blob bytes into executable
// memory and calls its entry point directly (host is Linux x86-64, so the
// blob's SysV-internal convention is ABI-compatible here).
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include "tls_blob.h"
#include "../tools/tlsrt.h"

typedef long (*Entry)(long, long, long, long, long, long);

static int g_fail = 0;

static std::string hex(const unsigned char* p, int n) {
    const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; i++) { s += d[p[i]>>4]; s += d[p[i]&15]; }
    return s;
}

static void check(const std::string& what, const std::string& got, const std::string& want) {
    bool ok = got == want;
    printf("%-40s %s\n", what.c_str(), ok ? "OK" : ("FAIL got="+got+" want="+want).c_str());
    if (!ok) g_fail++;
}

int main() {
    void* base = mmap(nullptr, kTlsBlobSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(base, kTlsBlob, kTlsBlobSize);
    Entry entry = (Entry)((char*)base + TLS_BLOB_ENTRY);
    printf("blob size=%u bytes, entry offset=0x%x\n", kTlsBlobSize, TLS_BLOB_ENTRY);

    // SHA-256("") and SHA-256("abc")
    {
        unsigned char out[32];
        entry(TLS_OP_SHA256, (long)out, 0, 0, 0, 0);
        check("sha256 empty",
              hex(out,32), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        const char* abc = "abc";
        entry(TLS_OP_SHA256, (long)out, (long)abc, 3, 0, 0);
        check("sha256 abc",
              hex(out,32), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    // HMAC-SHA256 RFC 4231 test case 1: key=0x0b*20, data="Hi There"
    {
        unsigned char key[20], want[32];
        unsigned char out[32];
        memset(key, 0x0b, 20);
        const char* msg = "Hi There";
        entry(TLS_OP_SHA256, (long)want, (long)key, 20, 0, 0); // temp fill
        // want vector computed below via HMAC op
        if (entry(TLS_OP_HMAC_SHA256, (long)out, (long)key, 20, (long)msg, 8) != 0)
            { printf("hmac returned nonzero\n"); g_fail++; }
        check("hmac-sha256 rfc4231#1",
              hex(out,32), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    // TLS 1.2 PRF (RFC 5246 6.3): P_SHA256(secret, label+seed).
    // seedlen=30 (all 30 chars are fed). Reference computed with Python's
    // hmac module on the same inputs; matched the blob implementation exactly.
    {
        static const unsigned char secret[] = "secret";
        // packed arg layout for TLS_OP_PRF_SHA256: [u16 llen][label][u16 seedlen][seed]
        unsigned char pkt[256];
        const char* label = "label"; int llen = 5;
        const char* seed = "seed0seed1seed2seed3seed4seed5"; int seedlen = 30;
        pkt[0] = (unsigned char)llen; pkt[1] = 0;
        memcpy(pkt+2, label, llen);
        pkt[2+llen] = (unsigned char)seedlen; pkt[3+llen] = 0;
        memcpy(pkt+4+llen, seed, seedlen);
        unsigned char out[64];
        entry(TLS_OP_PRF_SHA256, (long)out, 64, (long)secret, 6, (long)pkt);
        printf("prf-sha256 (label+seed)  first16=%s\n", hex(out,16).c_str());
        // expected from Python's hmac (hermetic known value):
        check("prf-sha256 known", hex(out,16),
              "bc033a25a744bd8850ca162c00478f70");
    }

    // AES-128-GCM + ECDHE: reference vectors from python cryptography (OpenSSL
    // EVP) and NIST SP 800-38D test cases 1-2.
    {
        static const unsigned char z16[16] = {0}, ivA[12] = {0};
        static const unsigned char keyC[16]  = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        static const unsigned char ivC[12]   = {0,1,2,3,4,5,6,7,8,9,10,11};
        static const unsigned char keyD[16]  = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
        static const unsigned char keyE[16]  = {0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef};
        unsigned char ivD[12], ivE[12], ptC[64], ptE[257], aadE[40];
        for (int i = 0; i < 12; i++) { ivD[i] = 0xa0; ivE[i] = 1; }
        for (int i = 0; i < 64; i++) ptC[i] = (unsigned char)i;
        for (int i = 0; i < 257; i++) ptE[i] = 'y';
        for (int i = 0; i < 40; i++)  aadE[i] = 'x';
        const char* aadC = "additional authenticated data";
        const char* aadD = "aad short";
        const char* ptD  = "plaintext data, not aligned to block size!!";

        struct Vec { const char* name; const unsigned char* key; const unsigned char* iv;
                     const unsigned char* aad; int aad_len; const unsigned char* pt; int pt_len;
                     const char* ct_hex; const char* tag_hex; };
        Vec vecs[] = {
            {"gcm A", z16, ivA, (const unsigned char*)"", 0, (const unsigned char*)"", 0, "",
             "58e2fccefa7e3061367f1d57a4e7455a"},
            {"gcm B", z16, ivA, (const unsigned char*)"", 0, z16, 16,
             "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
            {"gcm C", keyC, ivC, (const unsigned char*)aadC, (int)strlen(aadC), ptC, 64,
             "936da5cd621ef15343db6b813aae7e07a33708f547f8ebe1fe38eb360859bc73a585f9d4d0a591c468dd23cceca4f9bdfcae26c330b2004c167748e9967128db",
             "672b7e7f2fb83abbc5a5e4e810bfff43"},
            {"gcm D", keyD, ivD, (const unsigned char*)aadD, (int)strlen(aadD), (const unsigned char*)ptD, (int)strlen(ptD),
             "78d14292d9f95965f09bd4952e903edab3ff88c489855dc66b611ab5a1661017fc511f26cb75b12ee8a84a",
             "13f2ad1413155f79a15ccf1fd2dfb125"},
            {"gcm E", keyE, ivE, aadE, 40, ptE, 257,
             "2732b854aecdf9a8e9ae9aed9ccc172a8123ead00c709cd7044230f7dcb89a1ca7f71eadefed1a496a73f3a13e0acf276bbfb37f00f37bfecae7ccbf3e0001a2b507bb6af9ebcb68ff37165cade26760c717cd76fdcbca40ab444897a02cc68fd4d5e31bc6a7c42e6d0c21d4377f322052909973c39810e4021e5cab08878bb9f9152080353eef864f8356beb0cde58bf2283bce4f1a6a2564996a052b76befbdafc6cb2084a039162f340cc14c76db26b319aad71ae03e006d5283c28f3f4e3f88d98c5b89b1a48a17fa4e331c2f2057502d24ec35021729e531664ea50af697547570a9a3610cbbd7deaa13c2b80f6aaac42c09e1d33b66c3223805c77942164",
             "30d29478af30fd4ffe297a9860fc478e"},
        };
        for (size_t v = 0; v < sizeof(vecs)/sizeof(vecs[0]); v++) {
            Vec& p = vecs[v];
            unsigned char sched[176], pkt[TLS_GCM_PKT_SIZE], ct[288], pt2[288];
            memset(pkt, 0, sizeof pkt);
            memcpy(pkt, p.iv, TLS_GCM_IV_SIZE);
            pkt[12] = (unsigned char)(p.aad_len & 0xff);
            pkt[13] = (unsigned char)(p.aad_len >> 8);
            memcpy(pkt+14, p.aad, p.aad_len);
            entry(TLS_OP_AES_KEY_EXPAND, (long)sched, (long)p.key, 0, 0, 0);
            long rc = entry(TLS_OP_GCM_ENC, (long)ct, (long)p.pt, p.pt_len, (long)sched, (long)pkt);
            if (rc != 0) { printf("gcm enc rc=%ld\n", rc); g_fail++; }
            check(std::string(p.name)+" ct", hex(ct, p.pt_len), p.ct_hex);
            check(std::string(p.name)+" tag", hex(pkt+14+p.aad_len, 16), p.tag_hex);
            rc = entry(TLS_OP_GCM_DEC, (long)pt2, (long)ct, p.pt_len, (long)sched, (long)pkt);
            if (rc != 0) { printf("%s dec rc=%ld\n", p.name, rc); g_fail++; }
            else if (memcmp(pt2, p.pt, p.pt_len) != 0) { printf("%s dec pt mismatch\n", p.name); g_fail++; }
            else printf("%-40s %s\n", (std::string(p.name)+" dec").c_str(), "OK");
        }
        // tampered tag must be rejected
        {
            unsigned char sched[176], pkt[TLS_GCM_PKT_SIZE], ct[32];
            memset(pkt, 0, sizeof pkt);
            memcpy(pkt, ivA, 12);
            pkt[12] = 0; pkt[13] = 0;
            entry(TLS_OP_AES_KEY_EXPAND, (long)sched, (long)z16, 0, 0, 0);
            entry(TLS_OP_GCM_ENC, (long)ct, (long)z16, 16, (long)sched, (long)pkt);
            pkt[14+0+15] ^= 1;  /* flip one tag byte */
            long rc = entry(TLS_OP_GCM_DEC, (long)ct, (long)ct, 16, (long)sched, (long)pkt);
            printf("%-40s %s\n", "gcm bad tag rejected", rc == -1 ? "OK" : "FAIL");
            if (rc != -1) g_fail++;
        }
        // aad_len above TLS_GCM_MAX_AAD must be rejected
        {
            unsigned char pkt[TLS_GCM_PKT_SIZE];
            memset(pkt, 0, sizeof pkt);
            pkt[12] = (unsigned char)(500 & 0xff);
            pkt[13] = (unsigned char)(500 >> 8);
            long rc = entry(TLS_OP_GCM_ENC, (long)0, (long)0, 0, (long)0, (long)pkt);
            printf("%-40s %s\n", "gcm huge aad rejected", rc == -2 ? "OK" : "FAIL");
            if (rc != -2) g_fail++;
        }
    }

    // P-256 ECDHE: full key exchange matches OpenSSL reference vector.
    {
        unsigned char privA[32], privB[32];
        memset(privA, 0x11, 32); memset(privB, 0x22, 32);
        unsigned char pubAx[32], pubAy[32], pubBx[32], pubBy[32];
        if (entry(TLS_OP_ECDHE_GEN_PUB, (long)privA, (long)pubAx, (long)pubAy, 0, 0) != 0) { printf("genpub a rc\n"); g_fail++; }
        if (entry(TLS_OP_ECDHE_GEN_PUB, (long)privB, (long)pubBx, (long)pubBy, 0, 0) != 0) { printf("genpub b rc\n"); g_fail++; }
        unsigned char ab[32], ba[32];
        long rc = entry(TLS_OP_ECDHE_SHARED, (long)ab, (long)privA, (long)pubBx, (long)pubBy, 0);
        if (rc != 0) { printf("ecdhe ab rc=%ld\n", rc); g_fail++; }
        rc = entry(TLS_OP_ECDHE_SHARED, (long)ba, (long)privB, (long)pubAx, (long)pubAy, 0);
        if (rc != 0) { printf("ecdhe ba rc=%ld\n", rc); g_fail++; }
        check("ecdhe ab ref", hex(ab,32),
              "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6");
        check("ecdhe symmetric", hex(ab,32), hex(ba,32));

        // priv = 1 -> public key must be the base point G.
        {
            unsigned char priv1[32], px[32], py[32];
            memset(priv1, 0, 32); priv1[31] = 1;
            entry(TLS_OP_ECDHE_GEN_PUB, (long)priv1, (long)px, (long)py, 0, 0);
            check("ecdhe priv=1 -> Gx", hex(px,32),
                  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
            check("ecdhe priv=1 -> Gy", hex(py,32),
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        }
    }

    if (!g_fail) printf("ALL OK\n");
    return g_fail ? 1 : 0;
}