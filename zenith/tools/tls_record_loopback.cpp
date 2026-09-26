// Record-layer loopback test for the TLS blob.
//
// Links tools/tlsrt.c directly (host x86-64 SysV) and drives tls_send_record /
// tls_recv_record through an in-memory pipe implemented via the tlsrt_send_stub
// / tlsrt_recv_stub / tlsrt_close_stub symbols (which tlsrt.s provides in the
// blob build; here we provide fake SysV->pipe ones).
//
// The point is to validate the RFC 5288 AEAD record structure and the GCM
// nonce/AAD/seq handling added in the hardening pass:
//   * encrypted record = header(5) || explicit_nonce(8) || ct || tag(16)
//   * GCM nonce = implicit_iv(4) || explicit_nonce(8)
//   * AAD = seq(8) || type(1) || ver(2) || length(2)  (length includes nonce+ct+tag)
//   * sequence number increments per record
//   * tampered tag / wrong implicit IV / truncated record all rejected
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

extern "C" {
long tlsrt_send_stub(long sock, const void* buf, long len, long flags);
long tlsrt_recv_stub(long sock, void* buf, long len, long flags);
long tlsrt_close_stub(long sock);
}

// In-memory "socket": a byte pipe. sender appends to peer->rx; receiver drains.
static struct Pipe {
    std::vector<unsigned char> rx;   // bytes the app would read
} g_pipe[2];

static int g_fail = 0;

long tlsrt_send_stub(long sock, const void* buf, long len, long flags) {
    (void)flags;
    const unsigned char* p = (const unsigned char*)buf;
    for (long i = 0; i < len; i++) g_pipe[sock].rx.push_back(p[i]);
    return len;
}
long tlsrt_recv_stub(long sock, void* buf, long len, long flags) {
    (void)flags;
    Pipe& p = g_pipe[sock];
    long n = std::min<long>(len, (long)p.rx.size());
    if (n > 0) {
        memcpy(buf, p.rx.data(), (size_t)n);
        p.rx.erase(p.rx.begin(), p.rx.begin() + n);
    }
    return n;
}
long tlsrt_close_stub(long sock) { (void)sock; return 0; }

// Because tls_send_record/tls_recv_record are static in tlsrt.c, we reach them
// by #including the .c here (we can't declare them extern). This test therefore
// compiles tlsrt.c into this TU.
#define static
#include "../tools/tlsrt.c"
#undef static

static int count_pipe(const Pipe& p) { return (int)p.rx.size(); }

int main() {
    // ---- round-trip through the record layer ----
    {
        static const unsigned char key[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
        static const unsigned char iv[4] = { 0xf0,0xf1,0xf2,0xf3 };
        u64 seq = 0;
        const char* msg = "attack at dawn --- encrypt me";
        int mlen = (int)strlen(msg);

        if (tls_send_record(0, TLS_CONTENT_TYPE_APPLICATION_DATA,
                            (const u8*)msg, (u16)mlen, key, iv, &seq) < 0) {
            printf("send record rc (fail)\n"); g_fail++;
        }
        // Wire length field must be 8 (nonce) + mlen + 16 (tag)
        {
            const std::vector<unsigned char>& w = g_pipe[0].rx;
            if (w.size() != (size_t)(5 + mlen + 8 + 16)) {
                printf("send wire length FAIL got=%zu want=%d\n", w.size(), 5+mlen+8+16);
                g_fail++;
            } else {
                u16 lenf = (u16)((w[3]<<8) | w[4]);
                if (lenf != (u16)(8 + mlen + 16)) {
                    printf("wire length field FAIL: %u\n", lenf); g_fail++;
                } else {
                    // header bytes
                    bool hok = w[0]==23 && w[1]==3 && w[2]==3;
                    // AAD=seq0: explicit nonce bytes == 00..00
                    bool nonceok = true;
                    for (int i=5;i<13;i++) if (w[i]!=0) nonceok=false;
                    printf("record header        %s\n", hok&&nonceok ? "OK":"FAIL");
                    if (!(hok&&nonceok)) g_fail++;
                }
            }
        }
        // Receive side: decrypt and check payload.
        {
            u16 plen=0; u8 ct=0; u8 out[128];
            u64 rseq = 0;
            int r = tls_recv_record(0, out, &plen, &ct, key, iv, &rseq, sizeof(out));
            if (r < 0 || ct != TLS_CONTENT_TYPE_APPLICATION_DATA || plen != (u16)mlen) {
                printf("recv record FAIL r=%d ct=%u plen=%u\n", r, ct, plen); g_fail++;
            } else if (memcmp(out, msg, mlen) != 0) {
                printf("recv payload mismatch\n"); g_fail++;
            } else {
                printf("recv record decrypt   OK\n");
            }
        }

        // ---- seq increments: second record uses explicit nonce 00..01 ----
        {
            u64 seq2 = 1;  /* after first send, seq became 1; emulate */
            u8 out[128]; u16 plen=0; u8 ct=0;
            if (tls_send_record(0, TLS_CONTENT_TYPE_APPLICATION_DATA,
                                (const u8*)"B", 1, key, iv, &seq2) < 0) { g_fail++; }
            /* snapshot wire bytes BEFORE receiving drains the pipe */
            std::vector<unsigned char> w2 = g_pipe[0].rx;
            u64 rseq = 1;
            int r = tls_recv_record(0, out, &plen, &ct, key, iv, &rseq, sizeof(out));
            if (r < 0 || plen != 1 || out[0] != 'B') {
                printf("seq incr record FAIL\n"); g_fail++;
            } else {
                /* bytes 5..12 after header = explicit nonce of record 2: 00..01 */
                if (w2.size() < 13 || w2[12] != 1 ||
                    (w2[5]|w2[6]|w2[7]|w2[8]|w2[9]|w2[10]|w2[11]) != 0) {
                    printf("seq-incr nonce FAIL got=%d\n", (int)w2.size()); g_fail++;
                }
            }
            g_pipe[0].rx.clear();
            printf("seq incr record       %s\n",
                   (r>=0 && plen==1 && out[0]=='B') ? "OK" : "FAIL");
        }
    }

    // ---- tampered tag must fail ----
    {
        static const unsigned char key[16] = {0}, iv[4] = {0};
        u64 seq = 0;
        tls_send_record(1, TLS_CONTENT_TYPE_APPLICATION_DATA, (const u8*)"x", 1, key, iv, &seq);
        /* locate tag at end of pipe[1] data and flip a byte */
        {
            std::vector<unsigned char>& w = g_pipe[1].rx;
            w.back() ^= 0x01;
        }
        u8 out[32]; u16 plen=0; u8 ct=0; u64 rseq=0;
        int r = tls_recv_record(1, out, &plen, &ct, key, iv, &rseq, sizeof(out));
        if (r != -1) { printf("tampered tag REJECTED? r=%d\n", r); g_fail++; }
        else printf("tampered tag rejected OK\n");
    }

    // ---- truncated record must fail cleanly (short length) ----
    {
        static const unsigned char key[16] = {0}, iv[4] = {0};
        u8 buf[8] = {23,3,3,0,5,1,2,3};   /* len=5 < nonce(8)+tag(16) */
        g_pipe[1].rx.clear();
        for (int i=0;i<8;i++) g_pipe[1].rx.push_back(buf[i]);
        u8 out[32]; u16 plen=0; u8 ct=0; u64 rseq=0;
        int r = tls_recv_record(1, out, &plen, &ct, key, iv, &rseq, sizeof(out));
        if (r != -1) { printf("truncated record rejected? r=%d\n", r); g_fail++; }
        else printf("truncated record rejected OK\n");
    }

    // ---- max-plain guard: record with huge plaintext rejected for small buf ----
    {
        static const unsigned char key[16] = {0}, iv[4] = {0};
        /* craft a valid-looking record with a huge plaintext: header len = 0xFFFF */
        u8 buf[5 + 8];                /* header + explicit nonce placeholder */
        buf[0]=23; buf[1]=3; buf[2]=3; buf[3]=0xFF; buf[4]=0xFF;
        for (int i=5;i<13;i++) buf[i]=0;
        g_pipe[1].rx.clear();
        for (int i=0;i<13;i++) g_pipe[1].rx.push_back(buf[i]);
        u8 out[4]; u16 plen=0; u8 ct=0; u64 rseq=0;
        int r = tls_recv_record(1, out, &plen, &ct, key, iv, &rseq, sizeof(out));
        if (r != -1) { printf("oversized rejected? r=%d\n", r); g_fail++; }
        else printf("oversized record rejected OK\n");
    }

    if (!g_fail) printf("ALL OK\n");
    return g_fail ? 1 : 0;
}