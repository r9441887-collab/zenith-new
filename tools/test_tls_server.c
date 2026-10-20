/* Host-side unit test for the server-side helpers added to tlsrt.c:
   PEM decode, RSA private key parsing, rsa_sign_sha256, rsa_private_decrypt.
   Compiles tlsrt.c directly. Usage: ./test_tls_server <cert.pem> <key.pem> */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

long tlsrt_send_stub(long s, const void* b, long l, long f) { (void)s;(void)b;(void)l;(void)f; return -1; }
long tlsrt_recv_stub(long s, void* b, long l, long f) { (void)s;(void)b;(void)l;(void)f; return -1; }
long tlsrt_close_stub(long s) { (void)s; return -1; }

#define main tlsrt_c_main_unused
#include "tlsrt.c"
#undef main

static char* read_file(const char* path, long* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char* s = (char*)malloc((size_t)n + 1);
    if (!s) return 0;
    if (fread(s, 1, (size_t)n, f) != (size_t)n) { free(s); fclose(f); return 0; }
    s[n] = 0; fclose(f);
    *out_len = n;
    return s;
}

#define CHECK(x, what) do { int ok_ = (x); if (!ok_) { printf("FAIL: %s\n", what); return 1; } } while (0)

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: %s cert.pem key.pem\n", argv[0]); return 2; }
    long clen = 0, klen = 0;
    char* cert = read_file(argv[1], &clen);
    char* key = read_file(argv[2], &klen);
    if (!cert || !key) { printf("FAIL reading files\n"); return 1; }

    u8 cert_der[4096], key_der[4096];
    int der_len = pem_body_decode((const u8*)cert, (int)clen, cert_der, sizeof(cert_der));
    printf("cert DER decode: %d bytes (expect >0)\n", der_len);
    CHECK(der_len > 0 && cert_der[0] == 0x30 && cert_der[1] == 0x82, "cert DER header");

    u8 n_c[256], e_c[4];
    x509_init();
    int cs = 0;
    cs = x509_parse_cert(cert_der, der_len, 0);
    CHECK(cs >= 0, "x509_parse_cert");
    mem_copy(n_c, g_certs.n[0], 256);
    mem_copy(e_c, g_certs.e[0], 4);
    printf("cert n[0]=0x%02x n_len=%d, e=0x%08x\n", n_c[0], g_certs.n_len[0],
           ((u32)e_c[0]<<24)|((u32)e_c[1]<<16)|((u32)e_c[2]<<8)|e_c[3]);
    CHECK(n_c[0] >= 0x80, "cert modulus >=2048 bits");

    int kdlen = pem_body_decode((const u8*)key, (int)klen, key_der, sizeof(key_der));
    printf("key DER decode: %d bytes\n", kdlen);
    CHECK(kdlen > 0, "key DER decode");

    u8 n_k[256], d_k[256];
    int nlen = 0;
    CHECK(rsa_parse_private_key(key_der, kdlen, n_k, d_k, &nlen) == 0, "rsa_parse_private_key");
    printf("key n[0]=0x%02x n_len=%d\n", n_k[0], nlen);
    CHECK(n_k[0] >= 0x80, "key modulus >=2048 bits");
    CHECK(ct_cmp(n_c, n_k, 256) == 0, "cert n == key n");

    /* rsa_sign -> rsa_verify round-trip */
    u8 h[32];
    for (int i = 0; i < 32; i++) h[i] = (u8)(i * 7 + 3);
    u8 sig[256];
    CHECK(rsa_sign_sha256(h, n_k, d_k, sig) == 0, "rsa_sign_sha256");
    CHECK(rsa_verify_sha256(h, n_c, e_c, sig) == 0, "verify(sign(h)) == ok");
    h[0] ^= 0xFF;
    CHECK(rsa_verify_sha256(h, n_c, e_c, sig) != 0, "tampered hash rejected");

    /* rsa_private_decrypt: m = c^d mod n where c = m^e mod n using e=65537 */
    {
        u8 m[256];
        memset(m, 0, 256);
        m[255] = 0x3E; m[254] = 0xF1; m[253] = 0xA9;   /* arbitrary plaintext */
        u64 e_le[BI_LIMBS] = {0};
        e_le[0] = 65537;
        u64 n_le[BI_LIMBS];
        u64 m_le[BI_LIMBS], c_le[BI_LIMBS];
        memset(n_le, 0, sizeof(n_le));
        for (int k = 0; k < BI_LIMBS; k++) {
            n_le[k] = 0; m_le[k] = 0;
            for (int j = 0; j < 8; j++) {
                int o = k * 8 + j;
                n_le[k] |= (u64)n_k[255 - o] << (j * 8);
                m_le[k] |= (u64)m[255 - o] << (j * 8);
            }
        }
        CHECK(bi_cmp(m_le, n_le) < 0, "m < n");
        bi_modpow(c_le, m_le, e_le, n_le);
        u8 c[256];
        for (int k = 0; k < BI_LIMBS; k++)
            for (int j = 0; j < 8; j++)
                c[k * 8 + j] = (u8)(c_le[BI_LIMBS - 1 - k] >> (56 - j * 8));
        u8 m2[256];
        CHECK(rsa_private_decrypt(c, n_k, d_k, m2) == 0, "rsa_private_decrypt");
        printf("decrypt: m[0]=0x%02x m[255]=0x%02x\n", m2[0], m2[255]);
        CHECK(ct_cmp(m, m2, 256) == 0, "private encrypt/decrypt round-trip");
    }

    printf("ALL SERVER-SIDE CRYPTO CHECKS PASSED\n");
    free(cert); free(key);
    return 0;
}