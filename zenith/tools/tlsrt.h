/* Interface between Zenith codegen and the TLS blob. The blob is freestanding
   x86-64 code (SysV-internal) embedded into the .exe text section. All entry
   calls go through tlsrt_entry with op + up to 5 64-bit args in
   rdi/rsi/rdx/rcx/r8/r9; the result returns in rax.

   ABI discipline enforced by codegen_tls.cpp:
     - arguments staged into the SysV registers above, then `call rel32`
       (0xE8) into the blob offset (image VMA == offset).
     - The blob leaves the shadow space intact and never touches the red zone
       (-mno-red-zone) so the surrounding Win64-emitted code stays valid.

   Synchronous handshake runs INSIDE the blob: it blocks in recv/send stubs.
   Socket function pointers are injected via TLS_OP_IO_INIT (copied from the
   PE IAT by codegen). */
#ifndef TLSRT_H
#define TLSRT_H

#include <stdint.h>

#define TLS_OP_IO_INIT         1   /* a1=send, a2=recv, a3=closesocket */
#define TLS_OP_SHA256          2   /* a1=out32, a2=msg, a3=len        */
#define TLS_OP_HMAC_SHA256     3   /* a1=out32, a2=key, a3=klen, a4=msg, a5=mlen */
#define TLS_OP_PRF_SHA256      4   /* a1=out, a2=olen, a3=secret, a4=slen, a5=label+seed pkt */

/* --- Step 2: AES-GCM --- */
#define TLS_OP_AES_ENCRYPT_BLK 5   /* a1=out16, a2=in16, a3=key_sched(176) */
#define TLS_OP_AES_DECRYPT_BLK 6   /* a1=out16, a2=in16, a3=key_sched(176) */
#define TLS_OP_AES_KEY_EXPAND  7   /* a1=sched(176), a2=key(16)           */
#define TLS_OP_GCM_ENC         8   /* a1=out(ct,len) a2=in(pt,len) a3=len a4=key_sched(176) a5=pkt; tag written back to pkt */
#define TLS_OP_GCM_DEC         9   /* a1=out(pt,len) a2=in(ct,len) a3=len a4=key_sched(176) a5=pkt; 0=ok -1=bad tag -2=bad aad_len */
/* GCM op packet (a5), 14+aad_len+16 bytes: [0..11]=iv(12) [12..13]=aad_len(LE u16)
   then aad_len inline AAD bytes, then the 16-byte GCM tag (GCM_ENC writes it in
   place, GCM_DEC reads it from there). */
#define TLS_GCM_IV_SIZE        12
#define TLS_GCM_TAG_SIZE       16
#define TLS_GCM_MAX_AAD        256  /* max inline AAD bytes accepted by the GCM ops */
#define TLS_GCM_PKT_SIZE       (TLS_GCM_IV_SIZE + 2 + TLS_GCM_MAX_AAD + TLS_GCM_TAG_SIZE)  /* 286: fixed-size callers' buffer */

/* --- Step 3: RSA verify --- */
#define TLS_OP_RSA_VERIFY      10  /* a1=msg(32=SHA256), a2=n(256), a3=e(4), a4=sig(256), a5=pkcs1_hash_oid_len */
                                   /* returns 0=ok, -1=fail */
#define TLS_OP_BIGINT_MODEXP   11  /* a1=out(256), a2=base(256), a3=exp(256), a4=mod(256) — 2048-bit */

/* --- Step 4: P-256 ECDHE --- */
#define TLS_OP_ECDHE_GEN_PUB   12  /* a1=priv(32), a2=pubx(32), a3=puby(32) — generate ephemeral */
#define TLS_OP_ECDHE_SHARED    13  /* a1=out(32), a2=priv(32), a3=peerx(32), a4=peery(32) — shared secret */

/* --- Step 5: X.509 --- */
#define TLS_OP_X509_PARSE      14  /* a1=cert_der, a2=cert_len — returns internal handle (0=fail) */
#define TLS_OP_X509_GET_KEY    15  /* a1=handle, a2=out_n(256), a3=out_e(4) — RSA pubkey */
#define TLS_OP_X509_GET_FP     16  /* a1=handle, a2=out_fp(32) — SHA-256 fingerprint of DER */
#define TLS_OP_X509_FREE       17  /* a1=handle — release */

/* --- Step 6+7: TLS handshake + record layer --- */
#define TLS_OP_TLS_CONNECT     20  /* a1=sock, a2=host_str, a3=host_len — does full handshake, returns session handle */
#define TLS_OP_TLS_SEND        21  /* a1=handle, a2=data, a3=len — encrypted send, returns bytes sent */
#define TLS_OP_TLS_RECV        22  /* a1=handle, a2=buf, a3=len — encrypted recv, returns bytes read */
#define TLS_OP_TLS_CLOSE       23  /* a1=handle — close_notify + cleanup */
#define TLS_OP_TLS_LAST_ERROR  24  /* no args — returns last TLS error code */
#define TLS_OP_TLS_ACCEPT      25  /* a1=sock, a2=cert_pem, a3=cert_len, a4=key_pem, a5=key_len
                                        — server-side handshake (TLS_RSA_WITH_AES_128_GCM), returns
                                        session handle (see TLS_OP_TLS_ACCEPT_SRV) */

#define TLS_ERR_OK               0
#define TLS_ERR_HANDSHAKE       -1
#define TLS_ERR_IO              -2
#define TLS_ERR_CERT            -3
#define TLS_ERR_VERIFY          -4
#define TLS_ERR_CIPHER          -5
#define TLS_ERR_MEMORY          -6

/* Max cert chain: 3 certs * 4096 bytes = 12 KiB */
#define TLS_MAX_CERT_CHAIN  (3 * 4096)

/* Session state blob — lives in .bss, one per connection */
typedef struct {
    uint8_t  master_secret[48];
    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint8_t  key_material[40];  /* 2*key(16) + 2*iv(4) = 40 bytes */
    uint8_t  write_key[16];
    uint8_t  read_key[16];
    uint8_t  write_iv[4];
    uint8_t  read_iv[4];
    uint64_t write_seq;
    uint64_t read_seq;
    int      sock;
    int      last_error;
    int      handshake_done;
    int      active;          /* 1 once TLS_OP_TLS_CONNECT successfully allocates this slot */
    /* Server cert (DER) for optional pinning */
    uint8_t  cert_buf[TLS_MAX_CERT_CHAIN];
    int      cert_len;
    /* Handshake transcript: exact wire bytes of every handshake message in
       order (client_hello, server_hello, certificate, server_key_exchange,
       [client_key_exchange]). Hashed for the Finished verify_data. */
    uint8_t  transcript[16384];
    int      transcript_len;
} tls_session_t;

#ifdef __cplusplus
extern "C" {
#endif
long tlsrt_entry(long op, long a1, long a2, long a3, long a4, long a5);
#ifdef __cplusplus
}
#endif

#endif
