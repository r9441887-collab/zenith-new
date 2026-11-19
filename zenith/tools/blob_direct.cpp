// Direct host link test: links tools/tlsrt.c as ordinary code (no blob mapping)
// to validate crypto correctness independent of the blob-mapping pipeline.
#include <cstdio>
#include <cstring>
#include <string>
#include "tlsrt.h"
extern "C" void tlsrt_sha256(const unsigned char*, unsigned long long, unsigned char[32]);
extern "C" void tlsrt_hmac_sha256(const unsigned char*, unsigned long long,
                                  const unsigned char*, unsigned long long, unsigned char[32]);
extern "C" void tlsrt_prf_sha256(const unsigned char*, unsigned long long,
                                 const unsigned char*, unsigned long long,
                                 const unsigned char*, unsigned long long,
                                 unsigned char*, unsigned long long);

static int g_fail = 0;
static std::string hex(const unsigned char* p, int n) {
    const char* d = "0123456789abcdef"; std::string s;
    for (int i = 0; i < n; i++) { s += d[p[i]>>4]; s += d[p[i]&15]; }
    return s;
}
static void check(const char* what, const std::string& got, const std::string& want) {
    bool ok = got == want;
    printf("%-36s %s\n", what, ok ? "OK" : ("FAIL got="+got).c_str());
    if (!ok) g_fail++;
}

int main() {
    unsigned char out[32], want[32];
    const char* abc = "abc";
    tlsrt_entry(TLS_OP_SHA256, (long)out, (long)abc, 3, 0, 0);
    check("sha256 abc", hex(out,32),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    unsigned char key[20]; memset(key, 0x0b, 20);
    const char* msg = "Hi There";
    tlsrt_entry(TLS_OP_HMAC_SHA256, (long)out, (long)key, 20, (long)msg, 8);
    check("hmac-sha256 rfc4231#1", hex(out,32),
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    const unsigned char secret[] = "secret";
    const char* label = "label"; int llen = 5;
    const char* seed = "seed0seed1seed2seed3seed4seed5"; int seedlen = 30;
    unsigned char pkt[64];
    pkt[0] = (unsigned char)llen; pkt[1] = 0;
    memcpy(pkt+2, label, llen);
    pkt[2+llen] = (unsigned char)seedlen; pkt[3+llen] = 0;
    memcpy(pkt+4+llen, seed, seedlen);
    unsigned char prfout[16];
    tlsrt_entry(TLS_OP_PRF_SHA256, (long)prfout, 16, (long)secret, 6, (long)pkt);
    check("prf-sha256 known", hex(prfout,16), "bc033a25a744bd8850ca162c00478f70");

    // AES-128-GCM reference vectors (NIST SP 800-38D + OpenSSL EVP).
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
            tlsrt_entry(TLS_OP_AES_KEY_EXPAND, (long)sched, (long)p.key, 0, 0, 0);
            long rc = tlsrt_entry(TLS_OP_GCM_ENC, (long)ct, (long)p.pt, p.pt_len, (long)sched, (long)pkt);
            if (rc != 0) { printf("gcm enc rc=%ld\n", rc); g_fail++; }
            check((std::string(p.name)+" ct").c_str(), hex(ct, p.pt_len), p.ct_hex);
            check((std::string(p.name)+" tag").c_str(), hex(pkt+14+p.aad_len, 16), p.tag_hex);
            rc = tlsrt_entry(TLS_OP_GCM_DEC, (long)pt2, (long)ct, p.pt_len, (long)sched, (long)pkt);
            if (rc != 0) { printf("%s dec rc=%ld\n", p.name, rc); g_fail++; }
            else if (memcmp(pt2, p.pt, p.pt_len) != 0) { printf("%s dec pt mismatch\n", p.name); g_fail++; }
            else printf("%-36s %s\n", (std::string(p.name)+" dec").c_str(), "OK");
        }
        {
            unsigned char sched[176], pkt[TLS_GCM_PKT_SIZE], ct[32];
            memset(pkt, 0, sizeof pkt); memcpy(pkt, ivA, 12);
            pkt[12] = 0; pkt[13] = 0;
            tlsrt_entry(TLS_OP_AES_KEY_EXPAND, (long)sched, (long)z16, 0, 0, 0);
            tlsrt_entry(TLS_OP_GCM_ENC, (long)ct, (long)z16, 16, (long)sched, (long)pkt);
            pkt[14+0+15] ^= 1;
            long rc = tlsrt_entry(TLS_OP_GCM_DEC, (long)ct, (long)ct, 16, (long)sched, (long)pkt);
            check("gcm bad tag rejected", rc == -1 ? "-1" : "err", "-1");
        }
        {
            unsigned char pkt[TLS_GCM_PKT_SIZE];
            memset(pkt, 0, sizeof pkt);
            pkt[12] = (unsigned char)(500 & 0xff);
            pkt[13] = (unsigned char)(500 >> 8);
            long rc = tlsrt_entry(TLS_OP_GCM_ENC, 0, 0, 0, 0, (long)pkt);
            check("gcm huge aad rejected", rc == -2 ? "-2" : "err", "-2");
        }
    }

    // P-256 ECDHE full exchange (OpenSSL reference vector).
    {
        unsigned char privA[32], privB[32];
        memset(privA, 0x11, 32); memset(privB, 0x22, 32);
        unsigned char pubAx[32], pubAy[32], pubBx[32], pubBy[32];
        tlsrt_entry(TLS_OP_ECDHE_GEN_PUB, (long)privA, (long)pubAx, (long)pubAy, 0, 0);
        tlsrt_entry(TLS_OP_ECDHE_GEN_PUB, (long)privB, (long)pubBx, (long)pubBy, 0, 0);
        unsigned char ab[32], ba[32];
        long rc = tlsrt_entry(TLS_OP_ECDHE_SHARED, (long)ab, (long)privA, (long)pubBx, (long)pubBy, 0);
        if (rc != 0) { printf("ecdhe ab rc=%ld\n", rc); g_fail++; }
        rc = tlsrt_entry(TLS_OP_ECDHE_SHARED, (long)ba, (long)privB, (long)pubAx, (long)pubAy, 0);
        if (rc != 0) { printf("ecdhe ba rc=%ld\n", rc); g_fail++; }
        check("ecdhe ab ref", hex(ab,32),
              "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6");
        check("ecdhe symmetric", hex(ab,32), hex(ba,32));

        {
            unsigned char priv1[32], px[32], py[32];
            memset(priv1, 0, 32); priv1[31] = 1;
            tlsrt_entry(TLS_OP_ECDHE_GEN_PUB, (long)priv1, (long)px, (long)py, 0, 0);
            check("ecdhe priv=1 -> Gx", hex(px,32),
                  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
            check("ecdhe priv=1 -> Gy", hex(py,32),
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        }
    }

    printf(g_fail ? "SOME FAILED\n" : "ALL OK\n");
    return g_fail ? 1 : 0;
}