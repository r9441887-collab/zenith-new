/* Freestanding HTTP/HTTPS file-download engine and minimal static file server
   for Zenith (Linux). Raw x86-64 syscalls only (socket/connect/send/recv/open/
   write/read/close/setsockopt/bind/listen/accept/fstat/getdents64/nanosleep/
   clock_gettime); TLS 1.2 transport + server-side handshake is delegated to the
   TLS blob (tlsrt.o, linked into the SAME image) through tlsrt_entry opcodes.

   Entry: httpdl_entry(op, a1, a2, a3, a4, a5)  (SysV args, result in rax)
     op 1: http_download(url, file)          -> 0 ok | <0 error
     op 2: http_download_ask(url, file)      -> 0 ok | -5 (file not on server)
     op 3: http_download_speed(url, file)    -> 1 declined | 0 ok | <0 error
     op 4: http_server(port[, cert, key])    -> blocks forever (server loop)
     op 5: http_download_ghreleases(owner, repo, pattern, file)
             -> 0 ok | -5 (no matching asset) | <0 error
     op 6: http_download_ask_gh(owner, repo, branch, path, excl_file)
             -> 0 ok | -5 (excluded file not in listing) | <0 error
     op 7: http_download_msiso(version[, file])
             -> 0 ok (existing file of matching size is skipped)
                | -5 (no link found for version) | <0 error

   op 5 lists GitHub /releases/latest, filters the asset names by a pattern
   (prefix/suffix around an optional '*') and downloads the first match.
   op 6 asks the server about a file to EXCLUDE in a repo folder: the
   contents API is walked recursively (depth <= 4, <= 128 files) and, when
   the excluded file IS present, every other file is downloaded through its
   raw download_url. op 7 grabs the current official Windows ISO link list
   (massgrave.dev, refreshed monthly, files hosted on Microsoft's static
   CDN), picks the best link for `version`, does a HEAD size probe and
   skips the download when a local file of the same size already exists.

   op 2 asks the SERVER, not the user: the caller gives a base URL (a folder)
   and the exact name of one file to EXCLUDE. It first probes GET <base>/<file>;
   a 404 means the server says "you cannot skip that file" -> Zenith error -5
   and nothing is downloaded. If the file IS there (200) the server says "yes,
   you may skip it", so the whole listing of <base>/ is fetched and every file
   except the excluded one is downloaded into the current working directory.
   http/https both work; cookies and redirects are shared across all requests
   of one operation. (op 3 still asks the user about the Wi-Fi channel and, on
   "no", throttles the transfer to a conservative rate.)

   Error codes (returned to the Zenith builtin):
       -1 bad URL / buffer overflow
       -2 DNS resolution failed
       -3 TCP connect failed
       -4 TLS handshake / transport failed / server key load failed
       -5 HTTP status error (non-2xx, too many redirects, or excluded file 404)
       -6 local file could not be opened / written
       -7 socket I/O error
   Redirections (3xx + Location) are followed up to 6 times, including
   relative Location values.

   The TLS blob performs its synchronous record I/O through io-slot function
   pointers (tlsrt_io_send/recv/close). Because this whole engine is Linux
   syscall-only, those three slots are seeded here with the tiny Win64-ABI
   raw-syscall wrappers defined in httpdl.s (the blob calls them through its
   SysV->Win64 stubs).

   Compiled by host gcc: -ffreestanding -fno-stack-protector -fno-builtin
   -fpic -fno-common -mno-red-zone. No libc, no red zone, no TLS. */
#include <stddef.h>
#include "tlsrt.h"

typedef unsigned char      u8;
typedef unsigned short    u16;
typedef unsigned int      u32;
typedef unsigned long     u64;
typedef signed long       i64;

/* ---- x86-64 syscall numbers ---- */
#define NR_read         0
#define NR_write        1
#define NR_open         2
#define NR_close        3
#define NR_nanosleep    35
#define NR_socket       41
#define NR_connect      42
#define NR_sendto       44
#define NR_recvfrom     45
#define NR_setsockopt   54
#define NR_clock_gettime 228

#define AF_INET         2
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define IPPROTO_UDP     17
#define SOL_SOCKET      1
#define SO_RCVTIMEO     20
#define SO_REUSEADDR    2
#define O_RDONLY        0
#define O_WRONLY        1
#define O_CREAT         64
#define O_TRUNC         512
#define O_DIRECTORY     (65536)          /* x86-64 Linux O_DIRECTORY */
#define O_NOFOLLOW      (131072)
#define STDOUT          1
#define STDIN           0

#define HTTP_REDIR_MAX  6
#define HTTP_CHUNK      (16384)          /* == TLS_MAX_PAYLOAD, one TLS record */
#define SPEED_CAP       (4u * 1024 * 1024)  /* bytes/sec when full speed declined */
#define MAX_LIST_FILES  128              /* files fetched by one ask operation */
#define MAX_FILE_NAME   256              /* single basename / listing entry */
#define MAX_GH_URL      512              /* full URL per listing entry            */

/* ---- syscall helpers (no libc) ----
   All syscalls are tiny assembly wrappers in httpdl.s (SysV args in the usual
   registers; one `syscall`). Return values come back in rax (-errno on error). */
extern i64 httpdl_sys_read(i64 fd, void* buf, i64 len);
extern i64 httpdl_sys_pread(i64 fd, void* buf, i64 len, i64 pos);
extern i64 httpdl_sys_write(i64 fd, const void* buf, i64 len);
extern i64 httpdl_sys_open(const char* path, i64 flags, i64 mode);
extern i64 httpdl_sys_close(i64 fd);
extern i64 httpdl_sys_rename(const char* from, const char* to);
extern i64 httpdl_sys_unlink(const char* path);
extern i64 httpdl_sys_mkdir(const char* path, i64 mode);
extern i64 httpdl_sys_getpid(void);
extern i64 httpdl_sys_nanosleep(const long* req, long* rem);
extern i64 httpdl_sys_socket(i64 domain, i64 type, i64 proto);
extern i64 httpdl_sys_connect(i64 fd, const void* addr, i64 len);
extern i64 httpdl_sys_sendto(i64 fd, const void* buf, i64 len, i64 flags,
                             const void* addr, i64 addrlen);
extern i64 httpdl_sys_recvfrom(i64 fd, void* buf, i64 len, i64 flags,
                               void* addr, i64* addrlen);
extern i64 httpdl_sys_setsockopt(i64 fd, i64 level, i64 opt,
                                 const void* val, i64 vlen);
extern i64 httpdl_sys_clock_gettime(i64 clk, long* tp);
extern i64 httpdl_sys_bind(i64 fd, const void* addr, i64 len);
extern i64 httpdl_sys_listen(i64 fd, i64 backlog);
extern i64 httpdl_sys_accept(i64 fd, void* addr, void* addrlen);
extern i64 httpdl_sys_fstat(i64 fd, void* stat);
extern i64 httpdl_sys_getdents64(i64 fd, void* buf, i64 len);

/* clock_gettime(CLOCK_MONOTONIC) -> time in milliseconds, -1 on error */
static i64 mono_ms(void) {
    long tv[2];            /* secs, nsecs */
    if (httpdl_sys_clock_gettime(1, tv) < 0) return -1;
    return tv[0] * 1000L + tv[1] / 1000000L;
}

static int write_all(i64 fd, const void* buf, i64 len) {
    const u8* p = (const u8*)buf;
    while (len > 0) {
        i64 n = httpdl_sys_write(fd, p, len);
        if (n == -4) continue;
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int pread_all(i64 fd, void* buf, i64 len, i64 pos) {
    u8* p = (u8*)buf;
    while (len > 0) {
        i64 n = httpdl_sys_pread(fd, p, len, pos);
        if (n == -4) continue;
        if (n <= 0) return -1;
        p += n;
        pos += n;
        len -= n;
    }
    return 0;
}

/* ---- small string helpers ---- */
static u64 s_len(const u8* s) { u64 n = 0; while (s[n]) n++; return n; }
static void s_copy(u8* dst, const u8* src, u64 n) {
    for (u64 i = 0; i < n; i++) dst[i] = src[i];
}
static void s_zero(u8* dst, u64 n) { for (u64 i = 0; i < n; i++) dst[i] = 0; }

/* fill a 16-byte sockaddr_in buffer byte-by-byte (no aliasing games):
   family AF_INET, port/addr in network byte order. */
static void fill_sa(u8 sa[16], u32 ip, i64 port) {
    s_zero(sa, 16);
    sa[0] = 2; sa[1] = 0;                                  /* AF_INET (LE) */
    sa[2] = (u8)(port >> 8); sa[3] = (u8)port;             /* htons */
    sa[4] = (u8)(ip >> 24); sa[5] = (u8)(ip >> 16);
    sa[6] = (u8)(ip >> 8); sa[7] = (u8)ip;
}
static int s_cmp(const u8* a, const u8* b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return a[i] - b[i];
    return 0;
}
/* case-insensitive compare of s against (lowercase) literal */
static int s_ci_cmp(const u8* s, const char* lit) {
    for (;;) {
        u8 c = *s++;
        char L = *lit++;
        if (c >= 'A' && c <= 'Z') c = (u8)(c - 'A' + 'a');
        if (c != (u8)L) return (int)c - (int)(u8)L;
        if (L == 0) return 0;
    }
}
static int s_ci_ncmp(const u8* s, const char* lit, u64 n) {
    for (u64 k = 0; k < n; k++) {
        u8 c = s[k];
        char L = (char)lit[k];
        if (c >= 'A' && c <= 'Z') c = (u8)(c - 'A' + 'a');
        if (c != (u8)L) return 1;
    }
    return 0;
}
static int s_ci_eq(const u8* s, const char* lit) { return s_ci_cmp(s, lit) == 0; }
static u8* s_find(u8* s, u8 c) { while (*s) { if (*s == c) return s; s++; } return 0; }
static u8* s_find_str(u8* hay, u64 hlen, const u8* needle, u64 nlen) {
    if (nlen == 0) return hay;
    if (nlen > hlen) return 0;
    for (u64 i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && (nlen == 1 || s_cmp(hay + i, needle, nlen) == 0))
            return hay + i;
    }
    return 0;
}
static u64 s_digit(u8 c) { return (c >= '0' && c <= '9') ? (u64)(c - '0') : (u64)-1; }

/* linear string builder (bounds-checked; NUL-terminates when it fits) */
static int cat(u8* d, i64 cap, i64* pos, const u8* s) {
    u64 l = s_len(s);
    if (*pos + (i64)l + 1 >= cap) return -1;
    s_copy(d + *pos, s, l);
    *pos += (i64)l;
    d[*pos] = 0;
    return 0;
}
static int catc(u8* d, i64 cap, i64* pos, u8 c) {
    if (*pos + 2 >= cap) return -1;
    d[(*pos)++] = c;
    d[*pos] = 0;
    return 0;
}

/* true when substring `lit` (lowercase) occurs in s within first slen bytes */
static int s_ci_in(const u8* s, i64 slen, const char* lit) {
    u64 n = 0;
    while (lit[n]) n++;
    if (slen < (i64)n) return 0;
    for (i64 i = 0; i + (i64)n <= slen; i++)
        if (s_ci_ncmp(s + i, lit, n) == 0) return 1;
    return 0;
}

/* pointer to the last path segment of a '/' separated NUL string (no copy) */
static const u8* base_name(const u8* s) {
    const u8* b = s;
    while (*s) { if (*s == '/') b = s + 1; s++; }
    return b;
}

/* ---- minimal JSON sub-parser (GitHub API responses) ----
   Input is NUL-terminated. All str helpers are used as out-buffers. */
static const u8* j_ws(const u8* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}
/* decode JSON string at *p ('"' opener) into out; returns ptr past quote */
static const u8* j_str(const u8* p, u8* out, i64 cap, i64* olen) {
    if (*p != '"') return 0;
    p++;
    i64 n = 0;
    while (*p) {
        u8 c = *p;
        if (c == '"') { *olen = n; out[n] = 0; return p + 1; }
        if (c == '\\') {
            p++;
            u8 e = *p;
            if (!e) return 0;
            if (e == 'n') c = '\n';
            else if (e == 't') c = '\t';
            else if (e == 'r') c = '\r';
            else if (e == 'b') c = '\b';
            else if (e == 'f') c = '\f';
            else if (e == 'u') { p += 4; c = '?'; }
            else c = e;
        }
        if (n + 1 < cap) out[n++] = c;
        p++;
    }
    return 0;
}
/* skip one JSON value at *p; returns ptr just past it, or 0 */
static const u8* j_end(const u8* p) {
    p = j_ws(p);
    u8 c = *p;
    if (!c) return 0;
    if (c == '"') {
        p++;
        while (*p) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') { p++; return p; }
            p++;
        }
        return 0;
    }
    if (c == '{' || c == '[') {
        u8 close = (c == '{') ? '}' : ']';
        p++;
        for (;;) {
            p = j_ws(p);
            if (*p == close) { p++; return p; }
            if (!*p) return 0;
            if (*p == ',') { p++; continue; }
            p = j_end(p);
            if (!p) return 0;
        }
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    return p;
}
/* inside object (p at '{'): find `key`, *vbeg..*vend span its raw value */
static int j_find2(const u8* p, const char* key, const u8** vbeg, const u8** vend) {
    u8 kbuf[48];
    p = j_ws(p);
    if (*p != '{') return -1;
    p++;
    i64 kl = 0;
    while (key[kl]) kl++;
    for (;;) {
        p = j_ws(p);
        if (!*p || *p == '}') return -1;
        if (*p == ',') { p++; continue; }
        if (*p != '"') return -1;
        i64 kk;
        p = j_str(p, kbuf, sizeof(kbuf), &kk);
        if (!p) return -1;
        p = j_ws(p);
        if (*p != ':') return -1;
        p++;
        p = j_ws(p);
        if (!*p) return -1;
        if (kk == kl && s_cmp(kbuf, (const u8*)key, (u64)kl) == 0) {
            *vbeg = p;
            p = j_end(p);
            if (!p) return -1;
            *vend = p;
            return 0;
        }
        p = j_end(p);
        if (!p) return -1;
    }
}
/* iterate an array: p is the cursor (initially at '['); each call yields the
   raw span of the next element and returns the cursor for the following call
   (or 0 when the array is exhausted / the input is malformed). */
static const u8* j_arr(const u8* p, const u8** elem, i64* elen) {
    p = j_ws(p);
    if (!*p) return 0;
    if (*p == '[') p++;
    for (;;) {
        p = j_ws(p);
        if (!*p) return 0;
        if (*p == ']') return 0;
        if (*p == ',') { p++; continue; }
        *elem = p;
        p = j_end(p);
        if (!p) return 0;
        *elen = (i64)(p - *elem);
        return p;
    }
}

static u64 xorshift(void) {
    static u64 g_xs = 0x9E3779B97F4A7C15ULL;
    g_xs ^= g_xs << 13; g_xs ^= g_xs >> 7; g_xs ^= g_xs << 17;
    return g_xs;
}

/* ---- TLS blob interop (io slots live in the linked tlsrt.o image) ---- */
extern void httpdl_io_seed(void);   /* asm: RIP-relative slot seeding */

static void tls_init_io(void) {
    httpdl_io_seed();
}

/* ---- working buffers (bss; blob pads the image out to __bss_end) ---- */
static u8  g_url[2048];                 /* current URL (rewritten on redirects) */
static u8  g_host[256];                 /* NUL-terminated host name            */
static u8  g_path[1024];                /* NUL-terminated request path          */
static i64 g_port;                      /* 80 / 443 or explicit                */
static u8  g_req[8192];                 /* request (GET/HEAD + Host + Cookie)  */
static u8  g_hdr[8192];                 /* response header buffer               */
static u8  g_chunk[HTTP_CHUNK];         /* body read chunk                      */
static u8  g_buf[4096];                 /* misc (dns q/response, file reads)    */

/* ---- cookie jar (persists across all requests of one operation) ---- */
static u8  g_cookies[1024];             /* "name=value;name=value;"             */
static i64 g_cookies_len;
static u8  g_cookie_host[256];          /* host the jar belongs to              */
static int g_cookie_host_valid;

/* ---- ask / ghreleases / msiso: listing + extracted names + URLs ---- */
static u8  g_listing[131072];           /* HTML body / JSON response           */
static u8  g_files[MAX_LIST_FILES][MAX_FILE_NAME];
static u8  g_gh_urls[MAX_LIST_FILES][MAX_GH_URL];  /* full URL per entry     */
static u16 g_gh_len[MAX_LIST_FILES];    /* URL length (bytes)                   */
static int g_gh_count;                  /* entries collected                   */
static int g_gh_excl_idx;               /* index of the excluded file, or -1   */
static u8  g_gh_owner[128];             /* repo identity for recursive walk    */
static u8  g_gh_repo[128];
static u8  g_gh_branch[128];
static i64 g_last_content_len;          /* Content-Length of last probe        */

/* ---- generic <a href> parser ----
   Scans an HTML/autoindex body and collects the anchor href values.
   In list mode (want_urls=0) the old autoindex semantics apply: relative
   basenames only, no '/', '\', '?' and no '.'/'..' entries. In URL mode
   (want_urls=1, used by http_download_msiso) absolute http(s) URLs are kept
   in the g_gh_urls pool (up to MAX_GH_URL chars) while g_files[] holds the
   same text truncated to MAX_FILE_NAME for display and matching. HTML
   entities (&amp; &quot; &#39; &#34; &#63; &lt; &gt; &apos;) are decoded.
   Returns the entry count. */
static int parse_hrefs(const u8* src, i64 srclen, int want_urls) {
    int n = 0;
    i64 p = 0;
    while (p < srclen && n < MAX_LIST_FILES) {
        const u8* a = s_find_str((u8*)src + p, (u64)(srclen - p), (const u8*)"<a", 2);
        if (!a) break;
        p = (i64)(a - src) + 2;
        i64 q = p;
        while (q < srclen && (src[q] == ' ' || src[q] == '\t' || src[q] == '\n' ||
                              src[q] == '\r')) q++;
        if (q + 5 >= srclen || src[q] != 'h' || src[q + 1] != 'r' ||
            src[q + 2] != 'e' || src[q + 3] != 'f') continue;
        q += 4;
        while (q < srclen && (src[q] == ' ' || src[q] == '\t')) q++;
        if (q >= srclen || src[q] != '=') continue;
        q++;
        while (q < srclen && (src[q] == ' ' || src[q] == '\t')) q++;
        if (q >= srclen) break;
        i64 vstart, vend;
        if (src[q] == '"' || src[q] == '\'') {
            u8 d = src[q];
            q++;
            vstart = q;
            while (q < srclen && src[q] != d) q++;
            vend = q;
            if (q < srclen) q++;
        } else {
            vstart = q;
            while (q < srclen && src[q] != ' ' && src[q] != '\t' && src[q] != '\n' &&
                   src[q] != '\r' && src[q] != '>') q++;
            vend = q;
        }
        p = q;
        if (vend - vstart <= 0) continue;

        /* decode entities into a scratch buffer */
        u8 tmp[1024];
        i64 tl = 0;
        i64 k = vstart;
        while (k < vend && tl < (i64)(int)sizeof(tmp) - 1) {
            u8 c = src[k];
            if (c == '&') {
                i64 rem = vend - k;
                u64 ent = 0;      /* 1:&amp; 2:&quot; 3:&#..; 4:&lt; 5:&gt; 6:&apos; */
                if (rem >= 5 && src[k + 1] == 'a' && src[k + 2] == 'm' && src[k + 3] == 'p') ent = 1;
                else if (rem >= 6 && src[k + 1] == 'q' && src[k + 2] == 'u' && src[k + 3] == 'o' && src[k + 4] == 't') ent = 2;
                else if (rem >= 4 && src[k + 1] == '#') {
                    if (src[k + 2] == '3' && src[k + 3] == '9') ent = 3;
                    else if (src[k + 2] == '3' && src[k + 3] == '4') ent = 3;
                    else if (src[k + 2] == '6' && src[k + 3] == '3') ent = 3;
                }
                else if (rem >= 4 && src[k + 1] == 'l' && src[k + 2] == 't') ent = 4;
                else if (rem >= 4 && src[k + 1] == 'g' && src[k + 2] == 't') ent = 5;
                else if (rem >= 7 && src[k + 1] == 'a' && src[k + 2] == 'p' && src[k + 3] == 'o' && src[k + 4] == 's') ent = 2;
                if (ent) {
                    u8 ch;
                    i64 adv;
                    if (ent == 1) { ch = '&'; adv = 4; }
                    else if (ent == 2) { ch = '"'; adv = 5; }
                    else if (ent == 5) { ch = '>'; adv = 3; }
                    else { ch = '<'; adv = 3; }
                    if (ent == 3) { ch = '\''; adv = 4; }
                    if (k + adv < vend && src[k + adv] == ';') adv++;
                    tmp[tl++] = ch;
                    k += adv;
                    continue;
                }
            }
            tmp[tl++] = c;
            k++;
        }
        tmp[tl] = 0;
        if (tl == 0) continue;

        if (want_urls) {
            if (tmp[0] == '#') continue;
            if (!(tl > 7 && s_ci_ncmp(tmp, "http://", 7) == 0) &&
                !(tl > 8 && s_ci_ncmp(tmp, "https://", 8) == 0)) continue;
        } else {
            if (tmp[0] == '?') continue;
            if (tmp[tl - 1] == '/') continue;
            if (tl == 1 && tmp[0] == '.') continue;
            if (tl == 2 && tmp[0] == '.' && tmp[1] == '.') continue;
            int bad = 0;
            for (i64 i = 0; i < tl; i++)
                if (tmp[i] == '/' || tmp[i] == '\\' || tmp[i] == '?') { bad = 1; break; }
            if (bad) continue;
        }

        /* deduplicate against already collected entries */
        int dup = 0;
        for (int d = 0; d < n; d++) {
            u8* prow = g_gh_urls[d];
            u64 dl = s_len(want_urls ? prow : g_files[d]);
            if (dl == (u64)tl && s_cmp(want_urls ? prow : g_files[d],
                                       tmp, (u64)tl) == 0) { dup = 1; break; }
        }
        if (dup) continue;

        if ((u64)tl >= MAX_GH_URL) continue;
        u8* crow = g_gh_urls[n];
        s_copy(crow, tmp, (u64)tl);
        crow[tl] = 0;
        g_gh_len[n] = (u16)tl;
        i64 ncopy = tl;
        if (ncopy >= (i64)MAX_FILE_NAME) ncopy = (i64)MAX_FILE_NAME - 1;
        s_copy(g_files[n], tmp, (u64)ncopy);
        g_files[n][ncopy] = 0;
        n++;
    }
    return n;
}

/* size (bytes) of an existing local file, or -1 when it cannot be opened.
   stat layout: Linux struct stat on x86-64 has st_size at byte offset 48. */
static i64 local_size(const u8* path) {
    i64 fd = httpdl_sys_open((const char*)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    u8 st[144];
    if (httpdl_sys_fstat(fd, st) < 0) { httpdl_sys_close(fd); return -1; }
    httpdl_sys_close(fd);
    i64 sz = 0;
    for (int i = 0; i < 8; i++) sz |= (i64)st[48 + i] << (8 * i);
    return sz;
}

/* match `name` against a pattern: optional single '*' separates a required
   prefix from a required suffix; without '*' the whole pattern is the prefix. */
static int match_pattern(const u8* name, i64 nlen, const u8* pat) {
    u64 pl = s_len(pat);
    i64 star = -1;
    for (u64 i = 0; i < pl; i++)
        if (pat[i] == '*') { star = (i64)i; break; }
    i64 pre = star >= 0 ? star : (i64)pl;
    i64 suf = star >= 0 ? (i64)pl - star - 1 : 0;
    if (pre > nlen) return 0;
    if (s_cmp(name, pat, (u64)pre) != 0) return 0;
    if (suf > 0) {
        if (nlen < pre + suf) return 0;
        if (s_cmp(name + nlen - suf, pat + star + 1, (u64)suf) != 0) return 0;
    }
    return 1;
}

/* ---- DNS ----
   Resolve `host` to an IPv4 address (network byte order) using, in order:
     1. dotted-quad literal passthrough
     2. /etc/hosts
     3. UDP A-record query to each nameserver from /etc/resolv.conf
        (defaulting to 8.8.8.8 / 1.1.1.1) */
static int ip_parse(const u8* s, u32* ip_out) {
    u32 parts[4];
    int np = 0;
    while (np < 4) {
        u64 d = s_digit(*s);
        if (d == (u64)-1) return -1;
        u64 v = 0;
        while (*s && *s >= '0' && *s <= '9') {
            v = v * 10 + (u64)(*s - '0');
            if (v > 255) return -1;
            s++;
        }
        parts[np++] = (u32)v;
        if (np == 4) break;
        if (*s != '.') return -1;
        s++;
    }
    if (*s) return -1;                  /* trailing junk */
    *ip_out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return 0;
}

static int hosts_lookup(const u8* host, u32* ip_out) {
    i64 fd = httpdl_sys_open("/etc/hosts", 0, 0);
    if (fd < 0) return -1;
    i64 n = httpdl_sys_read(fd, g_buf, (i64)sizeof(g_buf));
    httpdl_sys_close(fd);
    if (n <= 0) return -1;
    u8* end = g_buf + n;
    u8* line = g_buf;
    u8 tmp[256];
    while (line < end) {
        u8* h = line;
        u8* nl = line;
        while (nl < end && *nl != '\n') nl++;
        line = nl + 1;
        /* tokenize: first = ip, rest = hostnames */
        u8* p = h;
        u8* ipend = 0;
        for (;;) {
            while (p < nl && (*p == ' ' || *p == '\t')) p++;
            if (p >= nl) break;
            u8* tok = p;
            while (p < nl && *p != ' ' && *p != '\t' && *p != '\n') p++;
            if (!ipend) { ipend = p; continue; }
            u64 l = (u64)(p - tok);
            if (l >= sizeof(tmp)) l = sizeof(tmp) - 1;
            s_copy(tmp, tok, l); tmp[l] = 0;
            if (s_ci_eq(tmp, (const char*)host)) {
                u64 il = (u64)(ipend - h);
                if (il >= sizeof(tmp)) il = sizeof(tmp) - 1;
                s_copy(tmp, h, il); tmp[il] = 0;
                if (ip_parse(tmp, ip_out) == 0) return 0;
            }
        }
    }
    return -1;
}

static int resolv_servers(u32* list) {
    int count = 0;
    i64 fd = httpdl_sys_open("/etc/resolv.conf", 0, 0);
    if (fd >= 0) {
        i64 n = httpdl_sys_read(fd, g_buf, (i64)sizeof(g_buf));
        httpdl_sys_close(fd);
        if (n > 0) {
            u8* end = g_buf + n;
            u8* p = g_buf;
            while (p < end && count < 3) {
                while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
                if (p >= end) break;
                /* word-boundary match: "nameserver" must be followed by
                   whitespace (s_ci_eq would require a NUL byte here) */
                if (p + 10 <= end && s_ci_ncmp(p, "nameserver", 10) == 0 &&
                    (p + 10 >= end || p[10] == ' ' || p[10] == '\t' || p[10] == '\r' ||
                     p[10] == '\n')) {
                    p += 10;                      /* "nameserver" len */
                    while (p < end && (*p == ' ' || *p == '\t')) p++;
                    u8* ip = p;
                    while (p < end && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') p++;
                    u8 save = *p; *p = 0;
                    u32 a;
                    if (ip_parse(ip, &a) == 0 && count < 3) list[count++] = a;
                    *p = save;
                    /* skip rest of line */
                    while (p < end && *p != '\n') p++;
                } else {
                    while (p < end && *p != '\n') p++;
                }
            }
        }
    }
    if (count == 0) {
        /* out-of-the-box fallbacks */
        list[count++] = (8u << 24) | (8u << 16) | (8u << 8) | 8u;   /* 8.8.8.8 */
        if (count < 3) list[count++] = (1u << 24) | (1u << 16) | (1u << 8) | 1u;
    }
    return count;
}

static int dns_query(const u8* name, u32 server, u32* ip_out) {
    u8 q[512];
    /* build a query name */
    u64 qpos = 12;
    u64 sl = s_len(name);
    u64 labelstart = 0;
    for (u64 i = 0; i <= sl; i++) {
        if (i == sl || name[i] == '.') {
            u64 lablen = i - labelstart;
            if (lablen > 63) return -1;
            if (lablen == 0) return -1;
            if (qpos + lablen + 2 > sizeof(q)) return -1;
            q[qpos++] = (u8)lablen;
            s_copy(q + qpos, name + labelstart, lablen);
            qpos += lablen;
            labelstart = i + 1;
            if (i == sl) break;
        }
    }
    if (qpos + 5 > sizeof(q)) return -1;
    q[qpos++] = 0;                          /* root */
    q[qpos++] = 0; q[qpos++] = 1;           /* QTYPE = A */
    q[qpos++] = 0; q[qpos++] = 1;           /* QCLASS = IN */
    q[0] = (u8)(xorshift() & 0xFF); q[1] = (u8)((xorshift() >> 8) & 0xFF);  /* id */
    q[2] = 1; q[3] = 0;                     /* RD=1 (flags = 0x0100) */
    q[4] = 0; q[5] = 1;                     /* QDCOUNT */
    q[6] = 0; q[7] = 0; q[8] = 0; q[9] = 0; /* rest 0 */
    q[10] = 0; q[11] = 0;

    i64 fd = httpdl_sys_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return -1;
    long tv[2] = { 2, 0 };                  /* 2 s recv timeout */
    httpdl_sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, (i64)sizeof(tv));
    {
        u8 sa[16];
        fill_sa(sa, server, 53);
        if (httpdl_sys_sendto(fd, q, (i64)qpos, 0, sa, 16) < 0) { httpdl_sys_close(fd); return -1; }
    }
    i64 r = httpdl_sys_recvfrom(fd, q, (i64)sizeof(q), 0, 0, 0);
    httpdl_sys_close(fd);
    if (r < 12) return -1;
    {
        /* rcode must be 0 */
        if ((q[3] & 0x0F) != 0) return -1;
        u16 ancount = (u16)((q[6] << 8) | q[7]);
        if (ancount == 0) return -1;
        /* skip question section: it repeats the encoded name from the query */
        u16 qdcount = (u16)((q[4] << 8) | q[5]);
        u64 p = 12;
        for (int i = 0; i < qdcount; i++) {
            for (;;) {
                if (p >= (u64)r) return -1;
                u8 l = q[p++];
                if (l == 0) break;
                if ((l & 0xC0) == 0xC0) { p++; break; }
                p += l;
            }
            p += 4;
        }
        for (int i = 0; i < ancount; i++) {
            if (p + 10 > (u64)r) return -1;
            u8 l = q[p];
            if ((l & 0xC0) == 0xC0) p += 2;          /* compressed name */
            else {
                for (;;) {
                    u8 ll = q[p++];
                    if (ll == 0) break;
                    if ((ll & 0xC0) == 0xC0) { p++; break; }
                    if (p + ll > (u64)r) return -1;
                    p += ll;
                }
            }
            u16 type  = (u16)((q[p] << 8) | q[p + 1]);
            u16 rdlen = (u16)((q[p + 8] << 8) | q[p + 9]);
            if (p + 10 + rdlen > (u64)r) return -1;
            if (type == 1 && rdlen == 4) {
                *ip_out = ((u32)q[p + 10] << 24) | ((u32)q[p + 11] << 16) |
                          ((u32)q[p + 12] << 8) | q[p + 13];
                return 0;
            }
            p += 10 + rdlen;
        }
    }
    return -1;
}

static int resolve_host(const u8* host, u32* ip_out) {
    if (ip_parse(host, ip_out) == 0) return 0;
    if (hosts_lookup(host, ip_out) == 0) return 0;
    u32 servers[3];
    int n = resolv_servers(servers);
    for (int i = 0; i < n; i++)
        if (dns_query(host, servers[i], ip_out) == 0) return 0;
    return -1;
}

/* ---- URL parsing ----
   Parses g_url and fills g_host / g_path / g_port + scheme (0=http, 1=https). */
static int parse_url(u8* url, int* scheme_out) {
    u8* p = url;
    int scheme = -1;
    if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' &&
        p[4] == ':' && p[5] == '/' && p[6] == '/') { scheme = 0; p += 7; }
    else if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' &&
             p[4] == 's' && p[5] == ':' && p[6] == '/' && p[7] == '/') {
        scheme = 1; p += 8;
    }
    if (scheme < 0) return -1;

    u8* host = p;
    i64 default_port = scheme == 1 ? 443 : 80;
    /* host[/:*]. */
    while (*p && *p != '/' && *p != ':' && *p != '?') p++;
    u8* hostend = p;
    i64 port = default_port;
    if (*p == ':') {
        p++;
        port = 0;
        while (*p >= '0' && *p <= '9') { port = port * 10 + (i64)(*p - '0'); p++; }
        if (port <= 0 || port > 65535) return -1;
    }
    if (hostend == host) return -1;
    if (hostend - host + 1 > (i64)sizeof(g_host)) return -1;
    s_copy(g_host, host, (u64)(hostend - host));
    g_host[hostend - host] = 0;

    /* path */
    u8* path = p;
    if (*p == 0) { path = (u8*)"/"; }
    u64 plen = s_len(path);
    if (plen >= sizeof(g_path)) return -1;
    s_copy(g_path, path, plen); g_path[plen] = 0;

    g_port = port;
    *scheme_out = scheme;
    return 0;
}

/* ---- console prompts (raw stdin/stdout) ---- */
static int ask_yes_no(const char* prompt) {
    u8 c;
    httpdl_sys_write(STDOUT, prompt, (i64)s_len((const u8*)prompt));
    i64 n = httpdl_sys_read(STDIN, &c, 1);
    int yes = (n == 1 && (c == 'y' || c == 'Y'));
    while (n == 1 && c != '\n') { n = httpdl_sys_read(STDIN, &c, 1); }  /* drain line */
    return yes;
}

/* ---- cookie jar ----
   Set-Cookie headers accumulate pairs "name=value" (the first part before the
   ';', i.e. the actual cookie) into g_cookies, one per ';'. A later Set-Cookie
   with the same name replaces the earlier one. The jar is only sent back to
   the host that set it (cookies_sync_host drops it on a host change), and it
   is reused across all requests of one operation (probe -> listing -> files). */
static void cookie_clear(void) {
    g_cookies_len = 0;
    g_cookie_host_valid = 0;
}

static void cookie_add(const u8* val, i64 vlen) {
    i64 end = vlen;
    for (i64 i = 0; i < vlen; i++) if (val[i] == ';') { end = i; break; }
    while (end > 0 && (val[end - 1] == ' ' || val[end - 1] == '\t')) end--;
    if (end <= 0) return;
    i64 eq = -1;
    for (i64 i = 0; i < end; i++) if (val[i] == '=') { eq = i; break; }
    if (eq <= 0) return;                /* no name=value pair */
    if (eq > 255) return;               /* name longer than the host buffer    */
    const u8* nv = val + eq + 1;
    i64 nlen = end - eq - 1;
    if (nlen > 1023) nlen = 1023;

    /* rebuild the jar: keep every segment whose name differs, drop the old
       value of the current name, append the new pair */
    u8 tmp[1024];
    i64 tlen = 0;
    i64 pos = 0;
    while (pos < g_cookies_len) {
        i64 se = pos;
        while (se < g_cookies_len && g_cookies[se] != ';') se++;
        i64 segl = se - pos;
        i64 sc = -1;
        for (i64 i = 0; i < segl; i++) if (g_cookies[pos + i] == '=') { sc = i; break; }
        int same = (sc == eq);
        if (same) {
            for (i64 k = 0; k < eq; k++) if (g_cookies[pos + k] != val[k]) { same = 0; break; }
        }
        if (!same) {
            if (tlen + segl + 1 > (i64)sizeof(tmp)) break;
            for (i64 i = 0; i < segl; i++) tmp[tlen + i] = g_cookies[pos + i];
            tlen += segl;
            tmp[tlen++] = ';';
        }
        pos = se + 1;
    }
    if (tlen + eq + 1 + nlen + 1 > (i64)sizeof(tmp)) return;   /* jar too full */
    for (i64 i = 0; i < eq; i++) tmp[tlen + i] = val[i];
    tlen += eq;
    tmp[tlen++] = '=';
    for (i64 i = 0; i < nlen; i++) tmp[tlen + i] = nv[i];
    tlen += nlen;
    tmp[tlen++] = ';';
    for (i64 i = 0; i < tlen; i++) g_cookies[i] = tmp[i];
    g_cookies_len = tlen;

    {   /* cookies belong to the host we just talked to */
        u64 hlen = s_len(g_host);
        if (hlen >= sizeof(g_cookie_host)) hlen = sizeof(g_cookie_host) - 1;
        s_copy(g_cookie_host, g_host, hlen);
        g_cookie_host[hlen] = 0;
        g_cookie_host_valid = 1;
    }
}

/* Reset the jar when the current request targets a different host. */
static void cookies_sync_host(void) {
    if (!g_cookie_host_valid) return;
    u64 i = 0;
    while (g_cookie_host[i] && g_host[i]) {
        if (g_cookie_host[i] != g_host[i]) { cookie_clear(); return; }
        i++;
    }
    if (g_cookie_host[i] != g_host[i]) cookie_clear();
}

/* ---- transport abstraction: 0 = plain HTTP, 1 = TLS ---- */
static i64 t_send(int mode, i64 fd, i64 handle, const u8* data, int len) {
    if (mode == 1) {
        int off = 0;
        while (off < len) {
            int n = (len - off > HTTP_CHUNK) ? HTTP_CHUNK : (len - off);
            i64 r = tlsrt_entry(TLS_OP_TLS_SEND, handle, (i64)(data + off),
                                (i64)n, 0, 0);
            if (r != n) return -1;
            off += (int)r;
        }
        return len;
    }
    int off = 0;
    while (off < len) {
        i64 r = httpdl_sys_sendto(fd, data + off, (i64)(len - off), 0, 0, 0);
        if (r <= 0) return -1;
        off += (int)r;
    }
    return len;
}

static i64 t_recv(int mode, i64 fd, i64 handle, u8* data, int max) {
    if (mode == 1) return tlsrt_entry(TLS_OP_TLS_RECV, handle, (i64)data,
                                     (i64)max, 0, 0);
    return httpdl_sys_recvfrom(fd, data, max, 0, 0, 0);
}

static void t_close(int mode, i64 fd, i64 handle) {
    if (mode == 1) {
        if (handle >= 0) tlsrt_entry(TLS_OP_TLS_CLOSE, handle, 0, 0, 0, 0);
    }
    httpdl_sys_close(fd);
}

/* Build the request (GET or HEAD) into g_req, with Host, User-Agent and the
   accumulated Cookie header (if the jar belongs to the current host).
   Returns length or -1. */
static int s_num(u8* out, i64 v) {
    char t[24];
    int n = 0;
    do { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    int p = 0;
    while (n > 0) out[p++] = (u8)t[--n];
    return p;
}

static int dec_i64(const u8* s, i64 n, i64 max, i64* out) {
    if (n <= 0 || n > 18) return -1;
    i64 v = 0;
    for (i64 i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        if (v > (max - (s[i] - '0')) / 10) return -1;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 0;
}

static int parse_content_range(const u8* s, i64 n, i64* start, i64* end) {
    while (n > 0 && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    if (n < 7 || s_ci_ncmp(s, "bytes ", 6) != 0) return -1;
    s += 6;
    n -= 6;
    i64 p = 0;
    while (p < n && s[p] >= '0' && s[p] <= '9') p++;
    if (p == 0 || dec_i64(s, p, 9223372036854775807LL, start) != 0 || p >= n || s[p] != '-')
        return -1;
    s += p + 1;
    n -= p + 1;
    p = 0;
    while (p < n && s[p] >= '0' && s[p] <= '9') p++;
    if (p == 0 || dec_i64(s, p, 9223372036854775807LL, end) != 0 || p >= n || s[p] != '/')
        return -1;
    s += p + 1;
    n -= p + 1;
    if (*start < 0 || *end < *start) return -1;
    if (n == 1 && s[0] == '*') return 0;
    if (n <= 0) return -1;
    i64 total;
    if (dec_i64(s, n, 9223372036854775807LL, &total) != 0 || total <= *end) return -1;
    return 0;
}

static int build_request(int scheme, int hostlen, const char* method,
                         i64 rstart, i64 rend) {
    u64 pos = 0;
    const u8* preamble = (const u8*)" HTTP/1.1\r\nHost: ";   /* 17 bytes */
    const u8* tail = (const u8*)"\r\nUser-Agent: zenith\r\nAccept: */*\r\n"
                                "Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
    u64 tlen = s_len(tail);
    u64 plen = s_len(g_path);
    u64 mlen = s_len((const u8*)method);
    u64 cookie_part = 0;
    if (g_cookies_len > 0 && g_cookie_host_valid)
        cookie_part = 8 + (u64)g_cookies_len + 3;   /* "Cookie: " jar ";\r\n" */
    u64 range_part = 0;
    if (rstart >= 0 && rstart <= rend)
        range_part = 52;   /* "Range: bytes=" 13 + 2*19 digits + '-' = 52 */
    if (pos + mlen + plen + 17 + (u64)hostlen + 16 + tlen + cookie_part +
        range_part + 1 > sizeof(g_req)) return -1;
    s_copy(g_req + pos, (const u8*)method, mlen); pos += mlen;
    g_req[pos++] = ' ';
    s_copy(g_req + pos, g_path, plen); pos += plen;
    s_copy(g_req + pos, preamble, 17); pos += 17;
    s_copy(g_req + pos, g_host, (u64)hostlen); pos += (u64)hostlen;
    if ((scheme == 1 && g_port != 443) || (scheme == 0 && g_port != 80)) {
        char pnum[8]; int pn = 0;
        i64 pp = g_port;
        do { pnum[pn++] = (char)('0' + (pp % 10)); pp /= 10; } while (pp);
        g_req[pos++] = ':';
        for (int k = pn - 1; k >= 0; k--) g_req[pos++] = (u8)pnum[k];
    }
    if (cookie_part > 0) {
        s_copy(g_req + pos, (const u8*)"\r\nCookie: ", 10); pos += 10;
        i64 ci = 0;
        while (ci < g_cookies_len) {
            i64 ce = ci;
            while (ce < g_cookies_len && g_cookies[ce] != ';') ce++;
            s_copy(g_req + pos, g_cookies + ci, ce - ci); pos += ce - ci;
            g_req[pos++] = ';';
            g_req[pos++] = ' ';
            ci = ce + 1;
        }
        pos -= 2;                       /* drop trailing "; " */
    }
    if (range_part > 0) {
        s_copy(g_req + pos, (const u8*)"\r\nRange: bytes=", 15); pos += 15;
        pos += (u64)s_num(g_req + pos, rstart);
        g_req[pos++] = '-';
        pos += (u64)s_num(g_req + pos, rend);
    }
    s_copy(g_req + pos, tail, tlen); pos += tlen;
    g_req[pos] = 0;
    return (int)pos;
}

/* Resolve a (possibly relative) Location header against the current URL.
   Writes the absolute URL to g_url. Returns 0 ok, -1 fail. */
static int resolve_location(u8* loc, int scheme, int loclen) {
    u8 tmp[2048];
    if (loclen <= 0 || loclen >= (i64)sizeof(tmp)) return -1;
    s_copy(tmp, loc, (u64)loclen); tmp[loclen] = 0;

    if (tmp[0] == 'h' && tmp[1] == 't' && tmp[2] == 't' && tmp[3] == 'p') {
        if ((u64)loclen + 1 > sizeof(g_url)) return -1;
        s_copy(g_url, tmp, (u64)loclen + 1);
        return 0;
    }
    /* scheme://host[:port] prefix */
    int sp = scheme == 1 ? 8 : 7;
    u64 hostlen = s_len(g_host);
    u64 base = sp + hostlen;
    static u8 prefix[1024];
    s_copy(prefix, (const u8*)(scheme == 1 ? "https://" : "http://"), (u64)sp);
    s_copy(prefix + sp, g_host, hostlen);
    if (g_port != (scheme == 1 ? 443 : 80)) {
        char pnum[8]; int pn = 0; i64 pp = g_port;
        do { pnum[pn++] = (char)('0' + (pp % 10)); pp /= 10; } while (pp);
        prefix[base++] = ':';
        for (int k = pn - 1; k >= 0; k--) prefix[base++] = (u8)pnum[k];
    }
    if (tmp[0] == '/') {
        if (base + (u64)loclen + 1 > sizeof(g_url)) return -1;
        s_copy(g_url, prefix, base);
        s_copy(g_url + base, tmp, (u64)loclen);
        g_url[base + (u64)loclen] = 0;
        return 0;
    }
    /* relative to the current directory part of the path */
    u64 plen = s_len(g_path);
    u64 cut = plen;
    for (u64 i = plen; i > 0; i--) {
        if (g_path[i - 1] == '/') { cut = i; break; }
    }
    if (base + cut + (u64)loclen + 1 > sizeof(g_url)) return -1;
    s_copy(g_url, prefix, base);
    s_copy(g_url + base, g_path, cut);
    s_copy(g_url + base + cut, tmp, (u64)loclen);
    g_url[base + cut + (u64)loclen] = 0;
    return 0;
}

/* ---- the actual fetch driver ----
   Fetches `url` (following redirects up to HTTP_REDIR_MAX and applying the
   cookie jar) and handles the body per `mode`:
     mode 0: discard the body (HEAD probe)
     mode 1: write it to `file` (opened O_TRUNC only after a 2xx status)
     mode 2: buffer it into to_mem (mem_cap bytes; *mem_len = bytes stored)
   Returns:
     0   success (2xx; body handled per mode)
     >0  the final HTTP status when the last non-redirect response was not 2xx
     <0  runtime error code (-1..-7); -5 also on redirect exhaustion
   `full`: 1 = no throttling, 0 = throttle the transfer to SPEED_CAP (op 3). */
static long http_fetch(const u8* url, const u8* method, int mode,
                       const u8* file, u8* to_mem, i64 mem_cap, i64* mem_len,
                       i64 full, i64 rstart, i64 rend) {
    u64 ulen = s_len(url);
    if (ulen >= sizeof(g_url)) return -1;
    s_copy(g_url, url, ulen); g_url[ulen] = 0;

    i64 start_ms = mono_ms();

    for (int attempt = 0; attempt <= HTTP_REDIR_MAX; attempt++) {
        int scheme;
        if (parse_url(g_url, &scheme) != 0) return -1;
        cookies_sync_host();

        u32 ip;
        if (resolve_host(g_host, &ip) != 0) return -2;

        /* TCP connect */
        u8 sa[16];
        fill_sa(sa, ip, g_port);
        i64 fd = httpdl_sys_socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -3;
        if (httpdl_sys_connect(fd, sa, 16) < 0) { httpdl_sys_close(fd); return -3; }

        i64 tls = -1;
        if (scheme == 1) {
            tls_init_io();
            i64 hlen = s_len(g_host);
            tls = tlsrt_entry(TLS_OP_TLS_CONNECT, fd, (i64)g_host, hlen, 0, 0);
            if (tls < 0) {
                httpdl_sys_close(fd); return -4;
            }
        }

        int reqlen = build_request(scheme, (int)s_len(g_host), (const char*)method, rstart, rend);
        if (reqlen < 0) { t_close(scheme, fd, tls); return -1; }
        if (t_send(scheme, fd, tls, g_req, reqlen) < 0) {
            t_close(scheme, fd, tls); return -7;
        }

        /* read header block into g_hdr until CRLFCRLF (bounded) */
        u64 hlen = 0, hdrEnd = 0;         /* hdrEnd = bytes of headers incl. terminator */
        int hdone = 0;
        while (hlen < sizeof(g_hdr)) {
            i64 r = t_recv(scheme, fd, tls, g_hdr + hlen,
                           (int)(sizeof(g_hdr) - hlen));
            if (r < 0) { t_close(scheme, fd, tls); return -7; }
            if (r == 0) {
                if (hlen == 0) { t_close(scheme, fd, tls); return -7; }
                break;                       /* headers truncated but usable */
            }
            hlen += (u64)r;
            /* may also have pulled body bytes past the terminator: those
               bytes stay in g_hdr and are written from there below (slurped) */
            u8* sep = s_find_str(g_hdr, hlen, (const u8*)"\r\n\r\n", 4);
            if (!sep) sep = s_find_str(g_hdr, hlen, (const u8*)"\n\n", 2);
            if (sep) {
                hdrEnd = (u64)((sep - g_hdr) + (sep[0] == '\r' ? 4 : 2));
                hdone = 1;
                break;
            }
        }
        (void)hdone;
        if (hdrEnd == 0) hdrEnd = hlen;   /* no terminator: no body available */

        /* status line: "HTTP/x.y NNN ..." */
        if (hlen < 12 || !(g_hdr[0] == 'H' && g_hdr[1] == 'T' && g_hdr[2] == 'T' &&
                           g_hdr[3] == 'P')) {
            t_close(scheme, fd, tls); return -7;
        }
        int status = 0;
        int si = 4;
        /* skip "HTTP/1.x " -> first status digit */
        while (si < (i64)hlen && g_hdr[si] != ' ') si++;
        si++;
        for (int k = 0; k < 3 && si < (i64)hlen; k++) {
            if (g_hdr[si] < '0' || g_hdr[si] > '9') break;
            status = status * 10 + (g_hdr[si] - '0');
            si++;
        }

        i64 content_len = -1;
        i64 range_start = -1;
        i64 range_end = -1;
        u8* loc = 0;
        i64 loclen = 0;
        {
            u64 p = 0;
            while (p < hdrEnd) {
                u8* eol = s_find_str(g_hdr + p, hdrEnd - p, (const u8*)"\r\n", 2);
                u8* lf = s_find_str(g_hdr + p, hdrEnd - p, (const u8*)"\n", 1);
                if (lf && (!eol || lf < eol)) eol = lf;
                if (!eol) eol = g_hdr + hdrEnd;
                u64 linelen = (u64)(eol - (g_hdr + p));
                u8* colon = s_find_str(g_hdr + p, linelen, (const u8*)":", 1);
                if (colon) {
                    u64 namelen = (u64)(colon - (g_hdr + p));
                    u8* val = colon + 1;
                    while (val < eol && (*val == ' ' || *val == '\t')) val++;
                    u64 vallen = (u64)(eol - val);
                    while (vallen > 0 && (val[vallen - 1] == ' ' || val[vallen - 1] == '\t')) vallen--;
                    if (namelen == 14 && s_ci_ncmp(g_hdr + p, "content-length", 14) == 0) {
                        i64 parsed;
                        if (dec_i64(val, (i64)vallen, 9223372036854775807LL, &parsed) == 0)
                            content_len = parsed;
                    } else if (namelen == 13 && s_ci_ncmp(g_hdr + p, "content-range", 13) == 0) {
                        i64 a, b;
                        if (parse_content_range(val, (i64)vallen, &a, &b) == 0) {
                            range_start = a;
                            range_end = b;
                        }
                    } else if (namelen == 8 && s_ci_ncmp(g_hdr + p, "location", 8) == 0) {
                        loc = val;
                        loclen = (i64)vallen;
                    } else if (namelen == 10 && s_ci_ncmp(g_hdr + p, "set-cookie", 10) == 0) {
                        cookie_add(val, (i64)vallen);
                    }
                }
                p = (u64)(eol - g_hdr) + (eol < g_hdr + hdrEnd && *eol == '\r' &&
                                           eol + 1 < g_hdr + hdrEnd && eol[1] == '\n' ? 2 : 1);
            }
        }

        g_last_content_len = content_len;   /* for HEAD probes (msiso skip)     */

        /* redirects */
        if (status >= 300 && status <= 399 && loc && loclen > 0 && status != 304) {
            if (resolve_location(loc, scheme, (int)loclen) != 0) { t_close(scheme, fd, tls); return -5; }
            t_close(scheme, fd, tls);
            continue;                 /* next attempt with the new g_url */
        }
        if (status < 200 || status >= 300) { t_close(scheme, fd, tls); return (long)status; }
        /* byte-range fetches are only correct when the server honors Range
           with a 206; a 200 would silently return the WHOLE file */
        if (rstart >= 0) {
            if (status != 206 || range_start != rstart || range_end < range_start ||
                range_end > rend ||
                (content_len >= 0 && content_len != range_end - range_start + 1)) {
                t_close(scheme, fd, tls); return -9;
            }
        }

        /* body: open the file only once we know the status is 2xx */
        i64 f = -1;
        if (mode == 1) {
            f = httpdl_sys_open((const char*)file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (f < 0) { t_close(scheme, fd, tls); return -6; }
        }

        i64 rec_total = 0;            /* bytes received from the network */
        i64 stored = 0;               /* bytes actually written / stored */
        /* body bytes that arrived together with the header block */
        i64 slurped = (i64)hlen - (i64)hdrEnd;
        if (slurped > 0) {
            if (content_len >= 0 && slurped > content_len) slurped = content_len;
            if (rstart >= 0 && slurped > range_end - range_start + 1) slurped = range_end - range_start + 1;
            rec_total = slurped;
            if (mode == 1) {
                if (write_all(f, g_hdr + hdrEnd, slurped) != 0) {
                    httpdl_sys_close(f);
                    t_close(scheme, fd, tls);
                    return -6;
                }
                stored = slurped;
            } else if (mode == 2) {
                if (mem_cap > 0) {
                    i64 take = slurped < mem_cap ? slurped : mem_cap;
                    s_copy(to_mem, g_hdr + hdrEnd, (u64)take);
                    stored = take;
                }
            }
        }
        for (;;) {
            if (content_len >= 0 && rec_total >= content_len) break;
            i64 want = HTTP_CHUNK;
            if (content_len >= 0 && content_len - rec_total < want) want = content_len - rec_total;
            i64 r = t_recv(scheme, fd, tls, g_chunk, (int)want);
            if (r < 0) {
                if (f >= 0) httpdl_sys_close(f);
                t_close(scheme, fd, tls);
                return -7;
            }
            if (r == 0) break;              /* server closed the connection */
            rec_total += r;
            if (mode == 1) {
                if (write_all(f, g_chunk, r) != 0) {
                    httpdl_sys_close(f);
                    t_close(scheme, fd, tls);
                    return -6;
                }
                stored += r;
            } else if (mode == 2 && stored < mem_cap) {
                i64 take = r;
                if (stored + take > mem_cap) take = mem_cap - stored;
                s_copy(to_mem + stored, g_chunk, (u64)take);
                stored += take;
            }

            if (!full && r > 0) {
                i64 now = mono_ms();
                if (now > 0 && start_ms > 0) {
                    i64 want_ms = (i64)(((u64)rec_total * 1000) / SPEED_CAP);
                    i64 el = now - start_ms;
                    if (el < want_ms) {
                        long req[2] = { (want_ms - el) / 1000, ((want_ms - el) % 1000) * 1000000L };
                        long rem[2];
                        httpdl_sys_nanosleep(req, rem);
                    }
                }
            }
        }

        if (f >= 0) httpdl_sys_close(f);
        t_close(scheme, fd, tls);
        if (content_len >= 0 && rec_total != content_len) return -7;
        if (rstart >= 0 && rec_total != range_end - range_start + 1) return -9;
        if (mode == 2 && mem_len) *mem_len = stored;
        return 0;
    }
    return -5;                          /* too many redirects */
}

/* op 1 (http_download) and op 3 (http_download_speed): fetch one file. Any
   non-2xx final status becomes the -5 Zenith error. */
static long httpdl_run(const u8* url, const u8* file, i64 full) {
    long r = http_fetch(url, (const u8*)"GET", 1, file, 0, 0, 0, full, -1, -1);
    if (r > 0) return -5;
    return r;
}

/* op 2 (http_download_ask): ask the SERVER whether it is OK to skip `file`.
   Hmm- careful — semantics per PLAN.md: probe <base>/<file>; a non-2xx reply
   (404) means "you cannot skip this file" -> Zenith error -5 and nothing is
   downloaded. A 2xx reply means "yes, skip it", so the whole listing of
   <base>/ is fetched and every file except `file` is downloaded into cwd. */
static long httpdl_ask(const u8* url, const u8* file) {
    cookie_clear();
    u64 flen = s_len(file);
    if (flen == 0 || flen >= MAX_FILE_NAME) return -1;

    /* normalize the base folder URL to end in '/' */
    u8 base[2048];
    u64 ulen = s_len(url);
    if (ulen == 0 || ulen >= sizeof(base) - 1) return -1;
    s_copy(base, url, ulen);
    if (base[ulen - 1] != '/') base[ulen++] = '/';
    base[ulen] = 0;
    u64 blen = ulen;

    /* step A: probe the excluded file (HEAD). Cookies from this reply are kept
       and reused for the listing and every per-file request below. */
    u8 probe[2048];
    if (blen + flen >= sizeof(probe)) return -1;
    s_copy(probe, base, blen);
    s_copy(probe + blen, file, flen);
    probe[blen + flen] = 0;
    long r = http_fetch(probe, (const u8*)"HEAD", 0, 0, 0, 0, 0, 1, -1, -1);
    if (r > 0) return -5;               /* "no" — the file is not on the server */
    if (r < 0) return r;

    /* step B: fetch the autoindex listing of the folder */
    i64 llen = 0;
    r = http_fetch(base, (const u8*)"GET", 2, 0, g_listing,
                   (i64)sizeof(g_listing), &llen, 1, -1, -1);
    if (r > 0) return -5;
    if (r < 0) return r;

    /* step C: pull every <a href=".."> anchor out of the listing (reused HTML
       parser); the excluded file stays in the list and is skipped in step D. */
    int n = parse_hrefs(g_listing, llen, 0);
    if (n < 0) return -1;

    /* step D: download every non-excluded file into the current directory */
    for (int i = 0; i < n; i++) {
        u64 nlen = s_len(g_files[i]);
        if (nlen == flen && s_cmp(g_files[i], file, flen) == 0) continue;  /* excluded */
        u8 furl[2048];
        if (blen + nlen + 1 > sizeof(furl)) continue;
        s_copy(furl, base, blen);
        s_copy(furl + blen, g_files[i], nlen);
        furl[blen + nlen] = 0;
        long rr = http_fetch(furl, (const u8*)"GET", 1, g_files[i], 0, 0, 0, 1, -1, -1);
        if (rr > 0) return -5;
        if (rr < 0) return rr;
    }
    return 0;
}

/* ---- op 5: GitHub Releases latest asset (http_download_ghreleases) ----
   GET https://api.github.com/repos/<owner>/<repo>/releases/latest, scan the
   "assets" array, pick the first asset whose "name" matches `pattern`
   (single '*' = prefix/suffix split) and download its browser_download_url
   into `file`. 404 / no matching asset -> -5. */
static long httpdl_ghreleases(const u8* owner, const u8* repo,
                              const u8* pattern, const u8* file) {
    if (!owner || !repo || !pattern || !file) return -1;
    if (s_len(owner) == 0 || s_len(repo) == 0 ||
        s_len(pattern) == 0 || s_len(file) == 0) return -1;

    u8 api[2048];
    i64 al = 0;
    if (cat(api, (i64)sizeof(api), &al, (const u8*)"https://api.github.com/repos/") ||
        cat(api, (i64)sizeof(api), &al, owner) ||
        catc(api, (i64)sizeof(api), &al, '/') ||
        cat(api, (i64)sizeof(api), &al, repo) ||
        cat(api, (i64)sizeof(api), &al, (const u8*)"/releases/latest")) return -1;

    cookie_clear();
    i64 blen = 0;
    long r = http_fetch(api, (const u8*)"GET", 2, 0, g_listing,
                        (i64)sizeof(g_listing), &blen, 1, -1, -1);
    if (r > 0) return -5;               /* repo/release not found */
    if (r < 0) return r;
    g_listing[blen] = 0;

    const u8* av = 0, * ae = 0;
    if (j_find2(g_listing, "assets", &av, &ae) != 0) return -5;
    const u8* cur = av;
    for (;;) {
        const u8* el = 0;
        i64 elen = 0;
        cur = j_arr(cur, &el, &elen);
        if (!el) break;
        u8 name[512], url[512];
        i64 nlen = 0, ulen = 0;
        const u8* nv = 0, * ne = 0;
        int hasn = (el[0] == '{') && (j_find2(el, "name", &nv, &ne) == 0) &&
                   (j_str(nv, name, sizeof(name), &nlen) != 0);
        const u8* bv = 0, * be = 0;
        int hasu = (el[0] == '{') &&
                   (j_find2(el, "browser_download_url", &bv, &be) == 0) &&
                   (j_str(bv, url, sizeof(url), &ulen) != 0);
        if (hasn && hasu && ulen > 0 && match_pattern(name, nlen, pattern)) {
            url[ulen] = 0;
            long rr = http_fetch(url, (const u8*)"GET", 1, file, 0, 0, 0, 1, -1, -1);
            if (rr > 0) return -5;
            if (rr < 0) return rr;
            return 0;
        }
        if (!cur) break;
    }
    return -5;
}

/* ---- op 6: GitHub folder listing, ask about one file, fetch the rest ----
   The contents API is walked recursively (depth <= 4, <= 128 files). Every
   regular file is recorded (basename in g_files[], raw download_url in the
   URL pool). When the excluded file IS in that set, all other recorded files
   are downloaded into the current working directory; otherwise -> -5. */
static long gh_walk(const u8* upath, const u8* excl, int depth) {
    u8 api[2048];
    i64 al = 0;
    if (cat(api, (i64)sizeof(api), &al, (const u8*)"https://api.github.com/repos/") ||
        cat(api, (i64)sizeof(api), &al, g_gh_owner) ||
        catc(api, (i64)sizeof(api), &al, '/') ||
        cat(api, (i64)sizeof(api), &al, g_gh_repo) ||
        cat(api, (i64)sizeof(api), &al, (const u8*)"/contents/")) return -1;
    if (s_len(upath) > 0 && cat(api, (i64)sizeof(api), &al, upath)) return -1;
    if (s_len(g_gh_branch) > 0) {
        if (cat(api, (i64)sizeof(api), &al, (const u8*)"?ref=") ||
            cat(api, (i64)sizeof(api), &al, g_gh_branch)) return -1;
    }

    i64 blen = 0;
    long r = http_fetch(api, (const u8*)"GET", 2, 0, g_listing,
                        (i64)sizeof(g_listing), &blen, 1, -1, -1);
    if (r > 0) {
        if (r == 404 || r == 410) return 0;   /* missing folder/ref */
        return -5;
    }
    if (r < 0) return r;
    g_listing[blen] = 0;

    const u8* cur = (const u8*)g_listing;
    for (;;) {
        const u8* el = 0;
        i64 elen = 0;
        cur = j_arr(cur, &el, &elen);
        if (!el) break;
        if (el[0] != '{') continue;           /* not an object entry */
        u8 name[256], type[16], durl[MAX_GH_URL];
        i64 nlen = 0, tlen = 0, dlen = 0;
        const u8* v = 0, * e = 0;
        int hasn = j_find2(el, "name", &v, &e) == 0 &&
                   j_str(v, name, sizeof(name), &nlen) != 0;
        int hast = j_find2(el, "type", &v, &e) == 0 &&
                   j_str(v, type, sizeof(type), &tlen) != 0;
        if (!hasn || !hast) continue;
        name[nlen] = 0;
        type[tlen] = 0;
        if (s_ci_eq(type, "dir")) {
            if (depth >= 4 || g_gh_count >= MAX_LIST_FILES || nlen == 0) continue;
            u8 sub[1024];
            i64 sl = 0;
            if (s_len(upath) > 0) {
                if (cat(sub, (i64)sizeof(sub), &sl, upath)) continue;
                if (catc(sub, (i64)sizeof(sub), &sl, '/')) continue;
            }
            if (cat(sub, (i64)sizeof(sub), &sl, name)) continue;
            long rr = gh_walk(sub, excl, depth + 1);
            if (rr < 0) return rr;
        } else {
            int hasd = j_find2(el, "download_url", &v, &e) == 0 &&
                       j_str(v, durl, sizeof(durl), &dlen) != 0;
            if (!hasd || dlen <= 0 || dlen >= MAX_GH_URL ||
                g_gh_count >= MAX_LIST_FILES) continue;
            durl[dlen] = 0;
            i64 ncopy = nlen;
            if (ncopy >= (i64)MAX_FILE_NAME) ncopy = (i64)MAX_FILE_NAME - 1;
            s_copy(g_files[g_gh_count], name, (u64)ncopy);
            g_files[g_gh_count][ncopy] = 0;
            s_copy(g_gh_urls[g_gh_count], durl, (u64)dlen);
            g_gh_urls[g_gh_count][dlen] = 0;
            g_gh_len[g_gh_count] = (u16)dlen;
            if (g_gh_excl_idx < 0 &&
                s_ci_cmp(g_files[g_gh_count], (const char*)excl) == 0)
                g_gh_excl_idx = g_gh_count;
            g_gh_count++;
        }
    }
    return 0;
}

static long httpdl_ask_gh(const u8* owner, const u8* repo, const u8* branch,
                          const u8* path, const u8* excl) {
    if (!owner || !repo || !branch || !path || !excl) return -1;
    if (s_len(owner) == 0 || s_len(repo) == 0 || s_len(excl) == 0) return -1;

    const u8* upath = path;
    while (upath[0] == '/') upath++;

    u64 ol = s_len(owner), rl = s_len(repo), bl = s_len(branch);
    if (ol >= sizeof(g_gh_owner) || rl >= sizeof(g_gh_repo) ||
        bl >= sizeof(g_gh_branch)) return -1;
    s_copy(g_gh_owner, owner, ol); g_gh_owner[ol] = 0;
    s_copy(g_gh_repo, repo, rl); g_gh_repo[rl] = 0;
    s_copy(g_gh_branch, branch, bl); g_gh_branch[bl] = 0;

    cookie_clear();
    g_gh_count = 0;
    g_gh_excl_idx = -1;

    long r = gh_walk(upath, base_name(excl), 0);
    if (r < 0) return r;
    if (g_gh_excl_idx < 0) return -5;   /* the excluded file is not on the server */
    if (g_gh_count <= 1) return 0;      /* nothing but the excluded file */

    for (int i = 0; i < g_gh_count; i++) {
        if (i == g_gh_excl_idx) continue;
        long rr = http_fetch(g_gh_urls[i], (const u8*)"GET", 1, g_files[i],
                             0, 0, 0, 1, -1, -1);
        if (rr > 0) return -5;
        if (rr < 0) return rr;
    }
    return 0;
}

/* ---- op 7: official Windows .iso (http_download_msiso) ----
   massgrave.dev publishes the refreshed (monthly) Microsoft CDN links:
     windows_11_links -> x64 Consumer/Education/Pro en-us .. other locales
     windows_10_links -> same layout post-EOL (buzzheavier.com mirrors)
   Pick the best .iso anchor for `version`, HEAD it for a size probe, skip
   when a local file of that size already exists, else GET the whole file. */

static int s_gh_token_noop(const u8* t) {
    if (s_ci_cmp(t, "11") == 0) return 1;
    if (s_ci_cmp(t, "10") == 0) return 1;
    if (s_ci_cmp(t, "windows") == 0) return 1;
    if (s_ci_cmp(t, "win") == 0) return 1;
    if (s_ci_cmp(t, "iso") == 0) return 1;
    if (s_ci_cmp(t, "microsoft") == 0) return 1;
    return 0;
}

/* best link index in g_gh_urls for `version`, or -1 */
static int ms_select(const u8* version) {
    i64 vlen = (i64)s_len(version);
    int ntok = 0;
    u8 tok[8][32];
    i64 st = 0;
    for (i64 i = 0; i <= vlen && ntok < 8; i++) {
        if (i == vlen || version[i] == '-' || version[i] == '_' || version[i] == ' ') {
            if (i > st && i - st < (i64)sizeof(tok[0])) {
                s_copy(tok[ntok], version + st, (u64)(i - st));
                tok[ntok][i - st] = 0;
                ntok++;
            }
            st = i + 1;
        }
    }

    int has_loc = 0, has_arm = 0;
    for (int t = 0; t < ntok; t++) {
        if (s_len(tok[t]) == 5 && tok[t][2] == '-') has_loc = 1;
        if (s_ci_cmp(tok[t], "arm64") == 0 || s_ci_cmp(tok[t], "arm") == 0) has_arm = 1;
    }

    int best = -1, best_score = -1000000;
    for (int k = 0; k < g_gh_count; k++) {
        const u8* url = g_gh_urls[k];
        const u8* nb = base_name(url);
        i64 nbl = (i64)s_len(nb);
        if (!(nbl > 4 && nb[nbl - 4] == '.' && nb[nbl - 3] == 'i' &&
              nb[nbl - 2] == 's' && nb[nbl - 1] == 'o')) continue;
        int ok = 1;
        for (int t = 0; t < ntok; t++) {
            if (s_gh_token_noop(tok[t])) continue;
            if (!s_ci_in(nb, nbl, (const char*)tok[t])) { ok = 0; break; }
        }
        if (!ok) continue;
        int sc = 0;
        for (int t = 0; t < ntok; t++)
            if (s_len(tok[t]) == 5 && tok[t][2] == '-' &&
                s_ci_in(nb, nbl, (const char*)tok[t])) sc += 3;
        if (!has_loc && s_ci_in(nb, nbl, "en-us")) sc += 2;
        if (has_arm) { if (s_ci_in(nb, nbl, "arm64")) sc += 4; }
        else if (s_ci_in(nb, nbl, "x64")) sc += 2;
        if (sc > best_score) { best_score = sc; best = k; }
    }
    return best;
}

/* "Win11_25H2_Consumer_x64_en-us.iso" style name from a CDN URL basename */
static void ms_mkname(const u8* url, u8* out, i64 cap) {
    const u8* b = base_name(url);
    i64 blen = (i64)s_len(b);
    if (blen > 4 && b[blen - 4] == '.' && b[blen - 3] == 'i' &&
        b[blen - 2] == 's' && b[blen - 1] == 'o') blen -= 4;

    char feat[8] = "Latest";
    int zi = -1;
    if (s_ci_in(b, blen, "26h2")) zi = 0;
    else if (s_ci_in(b, blen, "26h1")) zi = 1;
    else if (s_ci_in(b, blen, "25h2")) zi = 2;
    else if (s_ci_in(b, blen, "24h2")) zi = 3;
    else if (s_ci_in(b, blen, "23h2")) zi = 4;
    else if (s_ci_in(b, blen, "22h2")) zi = 5;
    else if (s_ci_in(b, blen, "21h2")) zi = 6;
    if (zi >= 0) {
        static const u8 f26h2[] = "26h2", f26h1[] = "26h1", f25h2[] = "25h2",
                          f24h2[] = "24h2", f23h2[] = "23h2", f22h2[] = "22h2",
                          f21h2[] = "21h2";
        const u8* vk = (zi == 0) ? f26h2 : (zi == 1) ? f26h1 : (zi == 2) ? f25h2
                 : (zi == 3) ? f24h2 : (zi == 4) ? f23h2 : (zi == 5) ? f22h2 : f21h2;
        int z = 0;
        for (int c = 0; c < 4 && vk[c]; c++) {
            char ch = (char)vk[c];
            if (ch == 'h') ch = 'H';
            feat[z++] = ch;
        }
        feat[z] = 0;
    }

    i64 bld = -1;
    for (i64 i = 0; i + 5 <= blen; i++) {
        if (b[i] >= '0' && b[i] <= '9' && b[i + 1] >= '0' && b[i + 1] <= '9' &&
            b[i + 2] >= '0' && b[i + 2] <= '9' && b[i + 3] >= '0' && b[i + 3] <= '9' &&
            b[i + 4] >= '0' && b[i + 4] <= '9') {
            i64 v = 0;
            i64 k2 = i;
            while (k2 < blen && b[k2] >= '0' && b[k2] <= '9' && (k2 - i) < 6) {
                v = v * 10 + (b[k2] - '0');
                k2++;
            }
            bld = v;
            break;
        }
    }
    const char* major = (bld >= 0 && bld < 22000) ? "10" : "11";

    const char* ed = "Multi";
    if (s_ci_in(b, blen, "server")) ed = "Server";
    else if (s_ci_in(b, blen, "ltsc")) ed = "LTSC";
    else if (s_ci_in(b, blen, "business")) ed = "Business";
    else if (s_ci_in(b, blen, "consumer")) ed = "Consumer";
    const char* ar = s_ci_in(b, blen, "arm64") ? "arm64" : "x64";

    i64 lc = blen;
    while (lc > 0 && b[lc - 1] != '_') lc--;
    i64 loclen = lc > 0 ? blen - lc : 0;
    char loc[32];
    if (loclen > 0 && loclen < (i64)sizeof(loc)) {
        s_copy((u8*)loc, b + lc, (u64)loclen);
        loc[loclen] = 0;
    } else {
        s_copy((u8*)loc, (const u8*)"en-us", 5);
        loc[5] = 0;
    }

    i64 pos = 0;
    cat(out, cap, &pos, (const u8*)"Win");
    cat(out, cap, &pos, (const u8*)major);
    catc(out, cap, &pos, '_');
    cat(out, cap, &pos, (const u8*)feat);
    catc(out, cap, &pos, '_');
    cat(out, cap, &pos, (const u8*)ed);
    catc(out, cap, &pos, '_');
    cat(out, cap, &pos, (const u8*)ar);
    catc(out, cap, &pos, '_');
    cat(out, cap, &pos, (const u8*)loc);
    cat(out, cap, &pos, (const u8*)".iso");
}

/* Pick the best .iso URL for `version` from the massgrave links page.
   Fetches the page into g_listing, parses the anchors, runs ms_select,
   copies the chosen absolute URL into out_url (NUL-terminated).
   Returns 0 ok, -1 bad args, -5 nothing matched, <0 transport error. */
static long ms_pick_url(const u8* version, u8* out_url, i64 cap) {
    if (!version || s_len(version) == 0 || !out_url || cap <= 0) return -1;
    cookie_clear();

    const char* page = (version[0] == '1' && version[1] == '0')
                           ? "https://massgrave.dev/windows_10_links"
                           : "https://massgrave.dev/windows_11_links";
    i64 plen = s_len((const u8*)page);
    if (plen >= (i64)sizeof(g_url)) return -1;
    s_copy(g_url, (const u8*)page, (u64)plen);
    g_url[plen] = 0;

    i64 llen = 0;
    long r = http_fetch(g_url, (const u8*)"GET", 2, 0, g_listing,
                        (i64)sizeof(g_listing), &llen, 1, -1, -1);
    if (r > 0) return -5;
    if (r < 0) return r;
    g_listing[llen] = 0;

    int n = parse_hrefs(g_listing, llen, 1);
    if (n == 0) return -5;
    g_gh_count = n;

    int best = ms_select(version);
    if (best < 0) return -5;
    u8* url = g_gh_urls[best];
    i64 ulen = s_len(url);
    if (ulen >= cap) return -1;
    s_copy(out_url, url, (u64)ulen);
    out_url[ulen] = 0;
    return 0;
}

static long httpdl_msiso(const u8* version, const u8* file) {
    u8 url[MAX_FILE_NAME * 4];
    long r = ms_pick_url(version, url, (i64)sizeof(url));
    if (r != 0) return r;

    u8 out[MAX_FILE_NAME];
    if (file && s_len(file) > 0) {
        u64 fl = s_len(file);
        if (fl >= sizeof(out)) return -1;
        s_copy(out, file, fl);
        out[fl] = 0;
    } else {
        ms_mkname(url, out, (i64)sizeof(out));
    }

    /* HEAD size probe: a local file of the same size is already there */
    r = http_fetch(url, (const u8*)"HEAD", 0, 0, 0, 0, 0, 1, -1, -1);
    if (r > 0) return -5;
    if (r < 0) return r;
    if (g_last_content_len > 0 && local_size(out) == g_last_content_len) return 0;

    r = http_fetch(url, (const u8*)"GET", 1, out, 0, 0, 0, 1, -1, -1);
    if (r > 0) return -5;
    if (r < 0) return r;
    return 0;
}

#define ISO_LB_SIZE       2048
#define ISO_DESC_OFFSET   (16 * ISO_LB_SIZE)
#define ISO_DESC_MAX      (32 * ISO_LB_SIZE)
#define ISO_PATH_MAX      2048
#define ISO_META_MAX      64
#define ISO_PART_MAX      (ISO_PATH_MAX + 64)

static u8 g_sec[ISO_LB_SIZE];

typedef struct {
    int remote;
    i64 fd;
    i64 size;
    const u8* local_path;
    const u8* url;
    u8 meta[ISO_META_MAX];
} iso_source;

typedef struct {
    u32 lba;
    u32 len;
    int is_dir;
} iso_entry;

typedef struct {
    iso_entry root;
    int joliet;
} iso_view;

#define UDF_MAX_EXTENTS 256

typedef struct {
    u32 lba;
    u32 len;
} udf_extent;

typedef struct {
    u64 len;
    int is_dir;
    int n_ext;
    udf_extent ext[UDF_MAX_EXTENTS];
} udf_file;

typedef struct {
    u32 part_start;
    u32 root_lba;
} udf_view;

static u16 iso_le16(const u8* p) {
    return (u16)((u16)p[0] | ((u16)p[1] << 8));
}

static u32 iso_le32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static u8 iso_lower(u8 c) {
    return c >= 'A' && c <= 'Z' ? (u8)(c + 32) : c;
}

static int iso_ci_ncmp(const u8* a, const u8* b, i64 n) {
    for (i64 i = 0; i < n; i++) {
        if (iso_lower(a[i]) != iso_lower(b[i])) return 0;
    }
    return 1;
}

static i64 iso_name_length(const u8* name, i64 n) {
    i64 semicolon = -1;
    for (i64 i = n - 1; i >= 0; i--) {
        if (name[i] == ';') {
            semicolon = i;
            break;
        }
    }
    if (semicolon > 0) {
        int digits = semicolon + 1 < n;
        for (i64 i = semicolon + 1; i < n; i++) {
            if (name[i] < '0' || name[i] > '9') digits = 0;
        }
        if (digits) n = semicolon;
    }
    if (n > 0 && name[n - 1] == '.') n--;
    return n;
}

static int iso_primary_name_eq(const u8* name, i64 name_len,
                               const u8* target, i64 target_len) {
    i64 n = iso_name_length(name, name_len);
    i64 m = iso_name_length(target, target_len);
    return n == m && iso_ci_ncmp(name, target, n);
}

static int iso_utf8_put(u8* out, i64 cap, i64 pos, u32 cp) {
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
    if (cp <= 0x7F) {
        if (pos >= cap) return -1;
        out[pos++] = (u8)cp;
    } else if (cp <= 0x7FF) {
        if (pos + 2 > cap) return -1;
        out[pos++] = (u8)(0xC0 | (cp >> 6));
        out[pos++] = (u8)(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        if (pos + 3 > cap) return -1;
        out[pos++] = (u8)(0xE0 | (cp >> 12));
        out[pos++] = (u8)(0x80 | ((cp >> 6) & 0x3F));
        out[pos++] = (u8)(0x80 | (cp & 0x3F));
    } else {
        if (pos + 4 > cap) return -1;
        out[pos++] = (u8)(0xF0 | (cp >> 18));
        out[pos++] = (u8)(0x80 | ((cp >> 12) & 0x3F));
        out[pos++] = (u8)(0x80 | ((cp >> 6) & 0x3F));
        out[pos++] = (u8)(0x80 | (cp & 0x3F));
    }
    return (int)pos;
}

static int iso_joliet_name(const u8* name, i64 name_len, u8* out, i64 cap, i64* out_len) {
    i64 n = iso_name_length(name, name_len);
    i64 pos = 0;
    for (i64 i = 0; i < n;) {
        if (i + 1 >= n) return -1;
        u32 cp = ((u32)name[i] << 8) | name[i + 1];
        i += 2;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 1 >= n) cp = 0xFFFD;
            else {
                u32 low = ((u32)name[i] << 8) | name[i + 1];
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    i += 2;
                } else {
                    cp = 0xFFFD;
                }
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        pos = iso_utf8_put(out, cap, pos, cp);
        if (pos < 0) return -1;
    }
    *out_len = pos;
    return 0;
}

static int iso_is_remote(const u8* source) {
    i64 n = s_len(source);
    return (n >= 7 && s_ci_ncmp(source, "http://", 7) == 0) ||
           (n >= 8 && s_ci_ncmp(source, "https://", 8) == 0);
}

static int iso_build_meta_path(iso_source* source) {
    const u8 prefix[] = "/tmp/.zenith-iso-";
    const u8 middle[] = "-meta.tmp";
    static const u8 hex[] = "0123456789abcdef";
    i64 pos = 0;
    i64 n = (i64)sizeof(prefix) - 1;
    s_copy(source->meta, prefix, (u64)n);
    pos = n;
    i64 pid = httpdl_sys_getpid();
    if (pid <= 0) pid = 1;
    pos += s_num(source->meta + pos, pid);
    source->meta[pos++] = '-';
    u64 value = (u64)(unsigned long)source->url;
    for (int i = 15; i >= 0; i--) {
        source->meta[pos++] = hex[value & 15];
        value >>= 4;
    }
    n = (i64)sizeof(middle) - 1;
    s_copy(source->meta + pos, middle, (u64)n);
    pos += n;
    if (pos >= ISO_META_MAX) return -1;
    source->meta[pos] = 0;
    return 0;
}

static long iso_source_init(iso_source* source, const u8* path) {
    source->remote = iso_is_remote(path);
    source->fd = -1;
    source->size = 0;
    source->local_path = 0;
    source->url = 0;
    source->meta[0] = 0;
    if (source->remote) {
        if (s_len(path) >= 2048) return -1;
        source->url = path;
        return iso_build_meta_path(source);
    }
    source->local_path = path;
    i64 fd = httpdl_sys_open((const char*)path, O_RDONLY, 0);
    if (fd < 0) return -6;
    long sb[32];
    if (httpdl_sys_fstat(fd, sb) < 0 ||
        (sb[3] & 0170000) != 0100000 || sb[6] <= 0) {
        httpdl_sys_close(fd);
        return -7;
    }
    source->fd = fd;
    source->size = sb[6];
    return 0;
}

static void iso_source_done(iso_source* source) {
    if (source->fd >= 0) httpdl_sys_close(source->fd);
    if (source->remote && source->meta[0]) httpdl_sys_unlink((const char*)source->meta);
    source->fd = -1;
}

static long iso_open_range(iso_source* source, i64 offset, i64 len,
                           i64* fd_out, int* close_out, i64* len_out) {
    if (offset < 0 || len <= 0) return -5;
    *close_out = 0;
    if (len_out) *len_out = 0;
    if (!source->remote) {
        if (offset > source->size || len > source->size - offset) return -5;
        *fd_out = source->fd;
        if (len_out) *len_out = len;
        return 0;
    }
    i64 end = offset + len - 1;
    if (end < offset) return -5;
    long r = http_fetch(source->url, (const u8*)"GET", 1, source->meta,
                        0, 0, 0, 1, offset, end);
    if (r > 0) return -5;
    if (r < 0) return r;
    i64 actual = local_size(source->meta);
    if (actual <= 0 || actual > len) {
        httpdl_sys_unlink((const char*)source->meta);
        return -9;
    }
    if (len_out) *len_out = actual;
    i64 fd = httpdl_sys_open((const char*)source->meta, O_RDONLY | O_NOFOLLOW, 0);
    if (fd < 0) {
        httpdl_sys_unlink((const char*)source->meta);
        return -6;
    }
    *fd_out = fd;
    *close_out = 1;
    return 0;
}

static u64 udf_le64(const u8* p) {
    u64 v = 0;
    for (int i = 0; i < 8; i++) v |= (u64)p[i] << (i * 8);
    return v;
}

static long udf_read_sector(iso_source* source, i64 lba, u8* out) {
    i64 fd;
    i64 range_len;
    int close_fd;
    long r = iso_open_range(source, lba * ISO_LB_SIZE, ISO_LB_SIZE,
                            &fd, &close_fd, &range_len);
    if (r != 0) return r;
    if (range_len != ISO_LB_SIZE) {
        if (close_fd) httpdl_sys_close(fd);
        return -5;
    }
    r = pread_all(fd, out, ISO_LB_SIZE, source->remote ? 0 : lba * ISO_LB_SIZE);
    if (close_fd) httpdl_sys_close(fd);
    return r == 0 ? 0 : -7;
}

static long udf_init(iso_source* source, udf_view* view) {
    u8 sec[ISO_LB_SIZE];
    i64 fd;
    i64 range_len;
    int close_fd;
    i64 main_lba;
    i64 scan_len;
    i64 read_len;
    int have_lvd = 0;
    int have_pd = 0;
    int main_ok = 1;
    u16 wanted_partition = 0;
    u32 part_start = 0;
    u32 part_len = 0;
    view->root_lba = 0;
    long r = udf_read_sector(source, 256, sec);
    if (r != 0) return r;
    if (iso_le16(sec) != 2) return -5;
    i64 main_extent_len = (i64)(iso_le32(sec + 16) & 0x3fffffff);
    main_lba = iso_le32(sec + 20);
    if (main_extent_len < ISO_LB_SIZE) return -5;
    scan_len = (main_extent_len / ISO_LB_SIZE) * ISO_LB_SIZE;
    if (scan_len > 64 * ISO_LB_SIZE) scan_len = 64 * ISO_LB_SIZE;
    r = iso_open_range(source, main_lba * ISO_LB_SIZE, scan_len, &fd,
                       &close_fd, &range_len);
    if (r != 0) return r;
    read_len = range_len < scan_len ? range_len : scan_len;
    for (i64 off = 0; off + ISO_LB_SIZE <= read_len; off += ISO_LB_SIZE) {
        i64 read_off = source->remote ? off : main_lba * ISO_LB_SIZE + off;
        if (pread_all(fd, sec, ISO_LB_SIZE, read_off) != 0) {
            if (close_fd) httpdl_sys_close(fd);
            return -7;
        }
        u16 tag = iso_le16(sec);
        if (tag == 6) {
            if (iso_le32(sec + 212) != ISO_LB_SIZE) {
                main_ok = 0;
                break;
            }
            if (iso_le32(sec + 264) < 6) {
                main_ok = 0;
                break;
            }
            if (iso_le32(sec + 268) < 1) {
                main_ok = 0;
                break;
            }
            const u8* map = sec + 440;
            if (map[0] != 1) {
                main_ok = 0;
                break;
            }
            wanted_partition = iso_le16(map + 4);
            have_lvd = 1;
        } else if (tag == 5) {
            if (!have_lvd || iso_le16(sec + 22) != wanted_partition) {
                main_ok = 0;
                break;
            }
            part_start = iso_le32(sec + 188);
            part_len = iso_le32(sec + 192);
            have_pd = 1;
        }
    }
    if (close_fd) httpdl_sys_close(fd);
    if (!main_ok || !have_lvd) return -5;
    if (!have_pd) return -5;
    if (part_start == 0) return -5;
    if (part_len == 0) return -5;
    if (!source->remote) {
        i64 part_offset = (i64)part_start * ISO_LB_SIZE;
        if (part_offset > source->size ||
            (i64)part_len > (source->size - part_offset) / ISO_LB_SIZE) return -5;
    }
    u32 fsd_sectors = part_len < 64 ? part_len : 64;
    r = iso_open_range(source, (i64)part_start * ISO_LB_SIZE,
                       (i64)fsd_sectors * ISO_LB_SIZE, &fd, &close_fd,
                       &range_len);
    if (r != 0) return r;
    read_len = range_len < (i64)fsd_sectors * ISO_LB_SIZE
                   ? range_len : (i64)fsd_sectors * ISO_LB_SIZE;
    for (i64 off = 0; off + ISO_LB_SIZE <= read_len; off += ISO_LB_SIZE) {
        i64 read_off = source->remote ? off : (i64)part_start * ISO_LB_SIZE + off;
        if (pread_all(fd, sec, ISO_LB_SIZE, read_off) != 0) {
            if (close_fd) httpdl_sys_close(fd);
            return -7;
        }
        if (iso_le16(sec) != 0x100) continue;
        u32 root_block = iso_le32(sec + 404);
        u16 root_partition = iso_le16(sec + 408);
        if (root_partition != 0) {
            if (close_fd) httpdl_sys_close(fd);
            return -5;
        }
        u64 root_lba = (u64)part_start + root_block;
        if (root_lba > 0xffffffffULL) {
            if (close_fd) httpdl_sys_close(fd);
            return -5;
        }
        view->part_start = part_start;
        view->root_lba = (u32)root_lba;
        if (close_fd) httpdl_sys_close(fd);
        return 0;
    }
    if (close_fd) httpdl_sys_close(fd);
    return -5;
}

static long udf_parse_icb(iso_source* source, const udf_view* view,
                           i64 lba, udf_file* out) {
    u8 sec[ISO_LB_SIZE];
    i64 info_len;
    i64 ad_base;
    i64 ad_len;
    long r = udf_read_sector(source, lba, sec);
    if (r != 0) return r;
    u16 tag = iso_le16(sec);
    if (tag != 0x105 && tag != 0x10a) return -5;
    int ad_type = sec[27];
    int type = iso_le16(sec + 34) & 7;
    if (type == 3) return -5;
    if (tag == 0x105) {
        info_len = (i64)udf_le64(sec + 56);
        ad_base = 176 + (i64)iso_le32(sec + 168);
        ad_len = iso_le32(sec + 172);
    } else {
        info_len = (i64)udf_le64(sec + 64);
        ad_base = 216 + (i64)iso_le32(sec + 208);
        ad_len = iso_le32(sec + 212);
    }
    if (info_len < 0 || ad_base < 0 || ad_len < 0 ||
        ad_base + ad_len > ISO_LB_SIZE) return -5;
    out->len = (u64)info_len;
    out->is_dir = ad_type == 4;
    out->n_ext = 0;
    i64 ad_size = type == 0 ? 8 : type == 1 ? 16 : type == 2 ? 20 : 0;
    if (ad_size == 0) return -5;
    for (i64 p = ad_base; p + ad_size <= ad_base + ad_len; p += ad_size) {
        u32 raw = iso_le32(sec + p);
        u32 extent_type = raw & 0xc0000000;
        u32 extent_len = raw & 0x3fffffff;
        if (extent_type == 0x80000000 || extent_type == 0xc0000000 ||
            extent_len == 0) continue;
        if (extent_type != 0 && extent_type != 0x40000000) return -5;
        u32 block;
        if (type == 0) {
            block = iso_le32(sec + p + 4);
        } else if (type == 1) {
            block = iso_le32(sec + p + 4);
            if (iso_le16(sec + p + 8) != 0) return -5;
        } else {
            block = iso_le32(sec + p + 12);
            if (iso_le16(sec + p + 16) != 0) return -5;
        }
        if (out->n_ext >= UDF_MAX_EXTENTS) return -5;
        u64 physical = (u64)view->part_start + block;
        if (physical > 0xffffffffULL) return -5;
        out->ext[out->n_ext].lba = (u32)physical;
        out->ext[out->n_ext].len = extent_len;
        out->n_ext++;
    }
    if (info_len > 0 && out->n_ext == 0) return -5;
    return 0;
}

static long udf_read_data(iso_source* source, const udf_file* file,
                          u8* dst, i64 cap, i64* out_len) {
    if (file->len > (u64)cap) return -5;
    i64 done = 0;
    for (int i = 0; i < file->n_ext; i++) {
        if (done >= (i64)file->len) break;
        i64 take = file->ext[i].len;
        if (take > (i64)file->len - done) take = (i64)file->len - done;
        if (take <= 0) continue;
        i64 fd;
        i64 range_len;
        int close_fd;
        long r = iso_open_range(source, (i64)file->ext[i].lba * ISO_LB_SIZE,
                                take, &fd, &close_fd, &range_len);
        if (r != 0) return r;
        if (range_len < take) {
            if (close_fd) httpdl_sys_close(fd);
            return -7;
        }
        i64 read_off = source->remote ? 0 : (i64)file->ext[i].lba * ISO_LB_SIZE;
        r = pread_all(fd, dst + done, take, read_off);
        if (close_fd) httpdl_sys_close(fd);
        if (r != 0) return -7;
        done += take;
    }
    if ((u64)done != file->len) return -5;
    if (out_len) *out_len = done;
    return 0;
}

static u8 udf_lower_ascii(u8 c) {
    if (c >= 'A' && c <= 'Z') return (u8)(c + ('a' - 'A'));
    return c;
}

static int udf_name_eq(const u8* name, i64 name_len,
                       const u8* target, i64 target_len) {
    if (name_len <= 0 || target_len <= 0 || target_len > 255) return 0;
    if (name[0] == 16) {
        if ((name_len - 1) % 2 != 0) return 0;
        if ((name_len - 1) / 2 != target_len) return 0;
        for (i64 i = 0; i < target_len; i++) {
            u32 cp = ((u32)name[1 + 2 * i] << 8) | name[2 + 2 * i];
            if (cp > 0xff) return 0;
            if (udf_lower_ascii((u8)cp) != udf_lower_ascii(target[i])) return 0;
        }
        return 1;
    }
    if (name[0] == 8) {
        if (name_len - 1 != target_len) return 0;
        for (i64 i = 0; i < target_len; i++) {
            if (udf_lower_ascii(name[1 + i]) != udf_lower_ascii(target[i])) return 0;
        }
        return 1;
    }
    return 0;
}

static long udf_find_child(iso_source* source, const udf_view* view,
                           const udf_file* dir, const u8* target,
                           i64 target_len, udf_file* out) {
    if (!dir->is_dir || dir->len == 0) return -5;
    i64 dir_len = 0;
    long r = udf_read_data(source, dir, g_listing, (i64)sizeof(g_listing),
                           &dir_len);
    if (r != 0) return r;
    for (i64 pos = 0; pos + 38 <= dir_len;) {
        if (iso_le16(g_listing + pos) != 0x101) return -5;
        i64 name_len = g_listing[pos + 19];
        i64 imp_len = iso_le16(g_listing + pos + 36);
        i64 desc_len = (38 + name_len + imp_len + 3) & ~3LL;
        if (pos + desc_len > dir_len) return -5;
        u8 characteristics = g_listing[pos + 18];
        if (!(characteristics & 0x04) && !(characteristics & 0x08) &&
            udf_name_eq(g_listing + pos + 38, name_len, target, target_len)) {
            if (iso_le16(g_listing + pos + 28) != 0) return -5;
            u32 block = iso_le32(g_listing + pos + 24);
            u64 physical = (u64)view->part_start + block;
            if (physical > 0xffffffffULL) return -5;
            r = udf_parse_icb(source, view, (i64)physical, out);
            if (r != 0) return r;
            if ((out->is_dir != 0) != ((characteristics & 0x02) != 0)) return -5;
            return 0;
        }
        pos += desc_len;
    }
    return -5;
}

static long udf_lookup_path(iso_source* source, const udf_view* view,
                            const u8* path, udf_file* out) {
    udf_file current;
    long r = udf_parse_icb(source, view, view->root_lba, &current);
    if (r != 0 || !current.is_dir) return -5;
    const u8* p = path;
    while (*p == '/' || *p == '\\') p++;
    while (*p) {
        const u8* start = p;
        while (*p && *p != '/' && *p != '\\') p++;
        i64 len = (i64)(p - start);
        if (len == 1 && start[0] == '.') goto next_separator;
        if (len == 2 && start[0] == '.' && start[1] == '.') return -5;
        if (len == 0 || len > 255) return -5;
        udf_file child;
        r = udf_find_child(source, view, &current, start, len, &child);
        if (r != 0) return r;
        current = child;
        if (!*p) {
            if (current.is_dir) return -5;
            *out = current;
            return 0;
        }
        if (!current.is_dir) return -5;
next_separator:
        while (*p == '/' || *p == '\\') p++;
    }
    return -5;
}

static long udf_to_iso_entry(const udf_file* file, iso_entry* out) {
    if (file->is_dir || file->n_ext != 1 || file->len > 0xffffffffULL ||
        file->ext[0].len < file->len) return -5;
    out->lba = file->ext[0].lba;
    out->len = (u32)file->len;
    out->is_dir = 0;
    return 0;
}

static int iso_parse_entry(const u8* p, i64 len, iso_entry* out) {
    i64 name_len = p[32];
    if (name_len == 0 || 33 + name_len > len) return -1;
    out->lba = iso_le32(p + 2);
    out->len = iso_le32(p + 10);
    out->is_dir = (p[25] & 0x02) != 0;
    return 0;
}

static long iso_read_volume(iso_source* source, iso_view* view) {
    i64 fd;
    i64 range_len;
    int close_fd;
    long r = iso_open_range(source, ISO_DESC_OFFSET, ISO_DESC_MAX, &fd,
                            &close_fd, &range_len);
    if (r != 0) return r;
    i64 off = 0;
    int have_primary = 0;
    int have_joliet = 0;
    iso_entry primary_root;
    iso_entry joliet_root;
    while (off + ISO_LB_SIZE <= range_len) {
        i64 read_off = source->remote ? off : ISO_DESC_OFFSET + off;
        if (pread_all(fd, g_sec, ISO_LB_SIZE, read_off) != 0) {
            if (close_fd) httpdl_sys_close(fd);
            return -7;
        }
        off += ISO_LB_SIZE;
        u8 type = g_sec[0];
        if (type == 255) break;
        if ((type == 1 || type == 2) && iso_parse_entry(g_sec + 156, 34,
                                                       type == 1 ? &primary_root : &joliet_root) == 0) {
            if (iso_le16(g_sec + 128) != ISO_LB_SIZE) {
                if (close_fd) httpdl_sys_close(fd);
                return -5;
            }
            if (type == 1) have_primary = 1;
            else if (g_sec[88] == '%' && g_sec[89] == '/' &&
                     (g_sec[90] == '@' || g_sec[90] == 'C' || g_sec[90] == 'E'))
                have_joliet = 1;
        }
    }
    if (close_fd) httpdl_sys_close(fd);
    if (!have_primary) return -5;
    view->root = primary_root;
    view->joliet = have_joliet;
    if (have_joliet) view->root = joliet_root;
    return 0;
}

static long iso_find_child(iso_source* source, const iso_entry* dir,
                           const u8* target, i64 target_len, int joliet,
                           iso_entry* out) {
    if (!dir->is_dir || dir->len == 0) return -5;
    i64 offset = (i64)dir->lba * ISO_LB_SIZE;
    i64 fd;
    i64 range_len;
    int close_fd;
    long r = iso_open_range(source, offset, dir->len, &fd, &close_fd,
                            &range_len);
    if (r != 0) return r;
    if (range_len != dir->len) {
        if (close_fd) httpdl_sys_close(fd);
        return -7;
    }
    i64 dir_off = 0;
    while (dir_off < dir->len) {
        i64 take = dir->len - dir_off;
        if (take > ISO_LB_SIZE) take = ISO_LB_SIZE;
        i64 read_off = source->remote ? dir_off : offset + dir_off;
        if (pread_all(fd, g_sec, take, read_off) != 0) {
            if (close_fd) httpdl_sys_close(fd);
            return -7;
        }
        i64 pos = 0;
        while (pos + 33 <= take) {
            u8 rec_len = g_sec[pos];
            if (rec_len == 0) break;
            if (rec_len < 33 || pos + rec_len > take) {
                if (close_fd) httpdl_sys_close(fd);
                return -7;
            }
            iso_entry child;
            if (iso_parse_entry(g_sec + pos, rec_len, &child) == 0 &&
                !(g_sec[pos + 25] & 0x80)) {
                i64 name_len = g_sec[pos + 32];
                int match = 0;
                if (joliet) {
                    u8 decoded[1024];
                    i64 decoded_len = 0;
                    match = iso_joliet_name(g_sec + pos + 33, name_len,
                                            decoded, (i64)sizeof(decoded),
                                            &decoded_len) == 0 &&
                            decoded_len == iso_name_length(target, target_len) &&
                            iso_ci_ncmp(decoded, target, decoded_len);
                } else {
                    match = iso_primary_name_eq(g_sec + pos + 33, name_len,
                                                target, target_len);
                }
                if (match) {
                    if (close_fd) httpdl_sys_close(fd);
                    *out = child;
                    return 0;
                }
            }
            pos += rec_len;
        }
        dir_off += take;
    }
    if (close_fd) httpdl_sys_close(fd);
    return -5;
}

static long iso_lookup_path(iso_source* source, const iso_entry* root,
                            const u8* path, int joliet, iso_entry* out) {
    iso_entry current = *root;
    const u8* p = path;
    while (*p == '/' || *p == '\\') p++;
    while (*p) {
        const u8* start = p;
        while (*p && *p != '/' && *p != '\\') p++;
        i64 len = (i64)(p - start);
        if (len == 1 && start[0] == '.') goto next_separator;
        if (len == 2 && start[0] == '.' && start[1] == '.') return -5;
        if (len == 0 || len > 255) return -5;
        iso_entry child;
        long r = iso_find_child(source, &current, start, len, joliet, &child);
        if (r != 0) return r;
        current = child;
        if (!*p) {
            if (current.is_dir) return -5;
            *out = current;
            return 0;
        }
        if (!current.is_dir) return -5;
next_separator:
        while (*p == '/' || *p == '\\') p++;
    }
    return -5;
}

static long iso_lookup(iso_source* source, const iso_view* view,
                       const u8* path, iso_entry* out) {
    if (view->joliet) {
        long r = iso_lookup_path(source, &view->root, path, 1, out);
        if (r == 0) return 0;
        if (r != -5) return r;
    }
    return iso_lookup_path(source, &view->root, path, 0, out);
}

static int iso_default_output(const u8* path, u8* out, i64 cap) {
    const u8* start = path;
    for (const u8* p = path; *p; p++) {
        if (*p == '/' || *p == '\\') start = p + 1;
    }
    i64 len = (i64)(s_len(path) - (u64)(start - path));
    while (len > 0 && (start[len - 1] == '/' || start[len - 1] == '\\')) len--;
    if (len <= 0) {
        if (cap < 10) return -1;
        s_copy(out, (const u8*)"extracted", 9);
        out[9] = 0;
        return 0;
    }
    if (len >= cap) return -1;
    s_copy(out, start, (u64)len);
    out[len] = 0;
    return 0;
}

static int iso_same_path(const u8* a, const u8* b) {
    i64 n = s_len(a);
    i64 m = s_len(b);
    return n == m && s_cmp(a, b, (u64)n) == 0;
}

static int iso_make_part_path(iso_source* source, const u8* output,
                              u8* part, i64 cap) {
    i64 pos = 0;
    i64 out_len = s_len(output);
    s_copy(part, output, (u64)out_len);
    pos = out_len;
    const u8 suffix[] = ".zenith-";
    s_copy(part + pos, suffix, (i64)sizeof(suffix) - 1);
    pos += (i64)sizeof(suffix) - 1;
    i64 pid = httpdl_sys_getpid();
    if (pid <= 0) pid = 1;
    pos += s_num(part + pos, pid);
    part[pos++] = '-';
    static const u8 hex[] = "0123456789abcdef";
    u64 value = (u64)(unsigned long)source->url;
    for (int i = 15; i >= 0; i--) {
        part[pos++] = hex[value & 15];
        value >>= 4;
    }
    s_copy(part + pos, (const u8*)".part", 5);
    pos += 5;
    if (pos >= cap) return -1;
    part[pos] = 0;
    return 0;
}

static long iso_copy_local(iso_source* source, iso_entry file, const u8* output) {
    u8 part[ISO_PART_MAX];
    if (iso_make_part_path(source, output, part, (i64)sizeof(part)) != 0) return -1;
    i64 start = (i64)file.lba * ISO_LB_SIZE;
    i64 remaining = file.len;
    if (start < 0 || start > source->size || remaining > source->size - start) return -5;
    i64 fd = httpdl_sys_open((const char*)part, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) return -6;
    i64 pos = start;
    while (remaining > 0) {
        i64 take = remaining;
        if (take > (i64)sizeof(g_chunk)) take = (i64)sizeof(g_chunk);
        if (pread_all(source->fd, g_chunk, take, pos) != 0 || write_all(fd, g_chunk, take) != 0) {
            httpdl_sys_close(fd);
            httpdl_sys_unlink((const char*)part);
            return -7;
        }
        pos += take;
        remaining -= take;
    }
    if (httpdl_sys_close(fd) < 0 || httpdl_sys_rename((const char*)part,
                                                        (const char*)output) < 0) {
        httpdl_sys_unlink((const char*)part);
        return -6;
    }
    return 0;
}

static long iso_download_remote(iso_source* source, iso_entry file, const u8* output) {
    u8 part[ISO_PART_MAX];
    if (iso_make_part_path(source, output, part, (i64)sizeof(part)) != 0) return -1;
    i64 start = (i64)file.lba * ISO_LB_SIZE;
    i64 len = file.len;
    if (len <= 0) return -5;
    long r = http_fetch(source->url, (const u8*)"GET", 1, part,
                        0, 0, 0, 1, start, start + len - 1);
    if (r > 0) {
        httpdl_sys_unlink((const char*)part);
        return -5;
    }
    if (r < 0) {
        httpdl_sys_unlink((const char*)part);
        return r;
    }
    if (local_size(part) != len) {
        httpdl_sys_unlink((const char*)part);
        return -9;
    }
    if (httpdl_sys_rename((const char*)part, (const char*)output) < 0) {
        httpdl_sys_unlink((const char*)part);
        return -6;
    }
    return 0;
}

static long iso_extract_impl(const u8* source_path, const u8* iso_path,
                             const u8* requested_output, int skip_same) {
    if (!source_path || !iso_path) return -1;
    i64 source_len = s_len(source_path);
    i64 iso_path_len = s_len(iso_path);
    if (source_len == 0 || iso_path_len == 0 ||
        source_len >= 2048 || iso_path_len >= ISO_PATH_MAX) return -1;
    iso_source source;
    long r = iso_source_init(&source, source_path);
    if (r != 0) return r;
    iso_view view;
    iso_entry file;
    udf_view udf;
    udf_file udf_target;
    r = iso_read_volume(&source, &view);
    if (r == 0) r = iso_lookup(&source, &view, iso_path, &file);
    if (r == -5) {
        r = udf_init(&source, &udf);
        if (r == 0) {
            r = udf_lookup_path(&source, &udf, iso_path, &udf_target);
            if (r == 0) r = udf_to_iso_entry(&udf_target, &file);
        }
    }
    if (r != 0) {
        iso_source_done(&source);
        return r;
    }
    u8 output[ISO_PATH_MAX];
    if (requested_output && s_len(requested_output) > 0) {
        i64 out_len = s_len(requested_output);
        if (out_len >= ISO_PATH_MAX) {
            iso_source_done(&source);
            return -1;
        }
        s_copy(output, requested_output, (u64)out_len);
        output[out_len] = 0;
    } else if (iso_default_output(iso_path, output, (i64)sizeof(output)) != 0) {
        iso_source_done(&source);
        return -1;
    }
    if (!source.remote && iso_same_path(source_path, output)) {
        iso_source_done(&source);
        return -1;
    }
    if (skip_same && local_size(output) == (i64)file.len) {
        iso_source_done(&source);
        return 0;
    }
    if (source.remote) r = iso_download_remote(&source, file, output);
    else r = iso_copy_local(&source, file, output);
    iso_source_done(&source);
    return r;
}

static long httpdl_winpe(const u8* version, const u8* file) {
    u8 url[MAX_FILE_NAME * 4];
    long r = ms_pick_url(version, url, (i64)sizeof(url));
    if (r != 0) return r;
    u8 out[MAX_FILE_NAME];
    if (file && s_len(file) > 0) {
        u64 fl = s_len(file);
        if (fl >= sizeof(out)) return -1;
        s_copy(out, file, fl);
        out[fl] = 0;
    } else {
        s_copy(out, (const u8*)"boot.wim", 8);
        out[8] = 0;
    }
    return iso_extract_impl(url, (const u8*)"/sources/boot.wim", out, 1);
}

static int winpe_path_join(u8* out, i64 cap, const u8* base, const u8* leaf) {
    i64 n = s_len(base);
    i64 l = s_len(leaf);
    if (n <= 0 || l <= 0 || n >= cap) return -1;
    s_copy(out, base, (u64)n);
    if (out[n - 1] != '/') {
        if (n + 1 >= cap) return -1;
        out[n++] = '/';
    }
    if (l >= cap - n) return -1;
    s_copy(out + n, leaf, (u64)l);
    out[n + l] = 0;
    return 0;
}

static int winpe_is_dir(const u8* path) {
    i64 fd = httpdl_sys_open((const char*)path,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (fd < 0) return 0;
    httpdl_sys_close(fd);
    return 1;
}

static int winpe_ensure_dir(const u8* path) {
    i64 r = httpdl_sys_mkdir((const char*)path, 0755);
    if (r == 0) return 0;
    if (r == -17 && winpe_is_dir(path)) return 0;
    return -6;
}

static int winpe_ensure_dir_path(const u8* path) {
    u8 tmp[ISO_PATH_MAX];
    i64 n = s_len(path);
    if (n <= 0 || n >= (i64)sizeof(tmp)) return -1;
    s_copy(tmp, path, (u64)n);
    tmp[n] = 0;
    while (n > 1 && tmp[n - 1] == '/') tmp[--n] = 0;
    i64 start = tmp[0] == '/' ? 1 : 0;
    for (i64 i = start; i < n; i++) {
        if (tmp[i] != '/') continue;
        if (i == start) continue;
        tmp[i] = 0;
        i64 r = winpe_ensure_dir(tmp);
        tmp[i] = '/';
        if (r != 0) return r;
    }
    return winpe_ensure_dir(tmp);
}

static int winpe_stage_path(const u8* final_path, u8* out, i64 cap) {
    i64 n = s_len(final_path);
    i64 pid = httpdl_sys_getpid();
    if (pid <= 0) pid = 1;
    if (n <= 0 || n >= cap) return -1;
    s_copy(out, final_path, (u64)n);
    i64 p = n;
    const u8 prefix[] = ".zenith-tmp-";
    i64 q = (i64)sizeof(prefix) - 1;
    if (p + q + 24 >= cap) return -1;
    s_copy(out + p, prefix, (u64)q);
    p += q;
    p += s_num(out + p, pid);
    out[p++] = '.';
    out[p++] = 'p';
    out[p++] = 'a';
    out[p++] = 'r';
    out[p++] = 't';
    out[p] = 0;
    return 0;
}

static void winpe_cleanup_stages(u8 stages[][ISO_PATH_MAX], int count) {
    for (int i = 0; i < count; i++) {
        if (stages[i][0]) httpdl_sys_unlink((const char*)stages[i]);
    }
}

static long httpdl_winpe_media(const u8* version, const u8* dir) {
    static const u8 iso_paths[4][64] = {
        "/boot/boot.sdi",
        "/efi/boot/bootx64.efi",
        "/efi/microsoft/boot/bcd",
        "/sources/boot.wim"
    };
    static const u8 output_paths[4][64] = {
        "boot/boot.sdi",
        "EFI/BOOT/BOOTX64.EFI",
        "EFI/Microsoft/Boot/BCD",
        "sources/boot.wim"
    };
    u8 url[MAX_FILE_NAME * 4];
    u8 root[ISO_PATH_MAX];
    u8 path[ISO_PATH_MAX];
    u8 finals[4][ISO_PATH_MAX];
    u8 stages[4][ISO_PATH_MAX];
    if (!version) return -1;
    long r = ms_pick_url(version, url, (i64)sizeof(url));
    if (r != 0) return r;
    if (!dir || s_len(dir) == 0) dir = (const u8*)".";
    i64 root_len = s_len(dir);
    if (root_len <= 0 || root_len >= (i64)sizeof(root)) return -1;
    s_copy(root, dir, (u64)root_len);
    root[root_len] = 0;
    if (winpe_ensure_dir_path(root) != 0) return -6;
    for (int i = 0; i < 4; i++) {
        if (winpe_path_join(finals[i], ISO_PATH_MAX, root, output_paths[i]) != 0)
            return -1;
        if (winpe_path_join(path, ISO_PATH_MAX, root, output_paths[i]) != 0)
            return -1;
        i64 slash = 0;
        for (i64 j = 1; path[j]; j++) if (path[j] == '/') slash = j;
        path[slash] = 0;
        if (winpe_ensure_dir_path(path) != 0) return -6;
        path[slash] = '/';
        if (winpe_stage_path(finals[i], stages[i], ISO_PATH_MAX) != 0)
            return -1;
    }
    for (int i = 0; i < 4; i++) {
        r = iso_extract_impl(url, iso_paths[i], stages[i], 0);
        if (r != 0) {
            winpe_cleanup_stages(stages, 4);
            return r;
        }
    }
    for (int i = 0; i < 4; i++) {
        if (httpdl_sys_rename((const char*)stages[i],
                              (const char*)finals[i]) < 0) {
            winpe_cleanup_stages(stages, 4);
            return -6;
        }
        stages[i][0] = 0;
    }
    return 0;
}

/* ---- HTTP / HTTPS server (op 4) ----
   http_server(port[, cert, key]): blocking bind(0.0.0.0)/listen/accept loop
   serving the current working directory. "/" returns an autoindex page in the
   style of python's http.server; "/name" streams the file (200 + Content-Length,
   no body for HEAD); anything else is 404. With a cert/key the accepted socket
   goes through a server-side TLS 1.2 handshake (TLS_OP_TLS_ACCEPT) first. */

static i64 u8_num(u8* out, i64 v) {
    char t[24];
    int n = 0;
    do { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    i64 p = 0;
    while (n > 0) out[p++] = (u8)t[--n];
    return p;
}

static i64 srv_header(u8* out, i64 cap, int code, const char* reason,
                      i64 clen, const char* ctype) {
    static const u8 a[] = "HTTP/1.1 ";
    static const u8 b[] = "\r\nContent-Length: ";
    static const u8 c[] = "\r\nContent-Type: ";
    static const u8 d[] = "\r\nConnection: close\r\n\r\n";
    i64 p = 0, l;
    l = (i64)sizeof(a) - 1; if (p + l > cap) return -1; s_copy(out + p, a, l); p += l;
    l = u8_num(out + p, (i64)code); p += l;
    if (p + 1 > cap) return -1;
    out[p++] = ' ';
    l = s_len((const u8*)reason); if (p + l > cap) return -1; s_copy(out + p, (const u8*)reason, l); p += l;
    l = (i64)sizeof(b) - 1; if (p + l > cap) return -1; s_copy(out + p, b, l); p += l;
    l = u8_num(out + p, clen); p += l;
    l = (i64)sizeof(c) - 1; if (p + l > cap) return -1; s_copy(out + p, c, l); p += l;
    l = s_len((const u8*)ctype); if (p + l > cap) return -1; s_copy(out + p, (const u8*)ctype, l); p += l;
    l = (i64)sizeof(d) - 1; if (p + l > cap) return -1; s_copy(out + p, d, l); p += l;
    return p;
}

static void srv_404(int mode, i64 fd, i64 handle) {
    static const u8 b[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                          "Connection: close\r\n\r\n";
    t_send(mode, fd, handle, b, (int)sizeof(b) - 1);
}

static const char* srv_ctype(const u8* name, i64 nlen) {
    if (nlen >= 5 && s_ci_eq(name + nlen - 5, ".html")) return "text/html; charset=utf-8";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".txt"))  return "text/plain; charset=utf-8";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".css"))  return "text/css; charset=utf-8";
    if (nlen >= 3 && s_ci_eq(name + nlen - 3, ".js"))   return "application/javascript";
    if (nlen >= 5 && s_ci_eq(name + nlen - 5, ".json")) return "application/json";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".png"))  return "image/png";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".jpg"))  return "image/jpeg";
    if (nlen >= 5 && s_ci_eq(name + nlen - 5, ".jpeg")) return "image/jpeg";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".gif"))  return "image/gif";
    if (nlen >= 4 && s_ci_eq(name + nlen - 4, ".svg"))  return "image/svg+xml";
    return "application/octet-stream";
}

static void srv_listing(int mode, i64 fd, i64 handle, int is_head) {
    static const u8 prefix[] = "<html><head><title>Directory listing for /</title></head>"
                               "<body><h2>Directory listing for /</h2><pre>\n";
    static const u8 suffix[] = "</pre><hr></body></html>\n";
    static const u8 tag1[] = "<a href=\"";
    static const u8 tag2[] = "\">";
    static const u8 tag3[] = "</a>\n";
    i64 cap = (i64)sizeof(g_listing);
    i64 at = 0;
    i64 l = (i64)sizeof(prefix) - 1;
    if (at + l > cap) { srv_404(mode, fd, handle); return; }
    s_copy(g_listing + at, prefix, l); at += l;

    i64 d = httpdl_sys_open((const char*)".", O_RDONLY | O_DIRECTORY, 0);
    if (d >= 0) {
        for (;;) {
            i64 r = httpdl_sys_getdents64(d, g_chunk, (i64)sizeof(g_chunk));
            if (r <= 0) break;
            i64 off = 0;
            while (off < r) {
                u8* de = g_chunk + off;
                u16 reclen = (u16)(de[16] | (de[17] << 8));
                if (reclen < 20 || off + (i64)reclen > r) break;
                off += (i64)reclen;
                u8 dtype = de[18];
                const u8* nm = de + 19;
                u64 nl = s_len(nm);
                if (nl == 0) continue;
                if ((nl == 1 && nm[0] == '.') || (nl == 2 && nm[0] == '.' && nm[1] == '.')) continue;
                int isdir = (dtype == 4);
                i64 need = (i64)(sizeof(tag1) - 1) + (i64)(nl + (isdir ? 1 : 0));
                need += (i64)(sizeof(tag2) - 1) + (i64)(nl + (isdir ? 1 : 0));
                need += (i64)(sizeof(tag3) - 1);
                if (at + need + (i64)(sizeof(suffix) - 1) > cap) break;
                s_copy(g_listing + at, tag1, sizeof(tag1) - 1); at += sizeof(tag1) - 1;
                s_copy(g_listing + at, nm, nl); at += (i64)nl;
                if (isdir) g_listing[at++] = '/';
                s_copy(g_listing + at, tag2, sizeof(tag2) - 1); at += sizeof(tag2) - 1;
                s_copy(g_listing + at, nm, nl); at += (i64)nl;
                if (isdir) g_listing[at++] = '/';
                s_copy(g_listing + at, tag3, sizeof(tag3) - 1); at += sizeof(tag3) - 1;
            }
        }
        httpdl_sys_close(d);
    }
    l = (i64)sizeof(suffix) - 1;
    if (at + l <= cap) { s_copy(g_listing + at, suffix, l); at += l; }

    i64 hl = srv_header(g_req, sizeof(g_req), 200, "OK", at,
                        "text/html; charset=utf-8");
    if (hl < 0) return;
    if (t_send(mode, fd, handle, g_req, (int)hl) < 0) return;
    if (!is_head && at > 0) t_send(mode, fd, handle, g_listing, (int)at);
}

/* Serve one accepted connection (mode 0 = plain, 1 = TLS). Always closes with
   a 404 on malformed input; the caller closes the socket afterwards. */
static void srv_serve(int mode, i64 fd, i64 handle) {
    i64 got = 0;
    while (got < (i64)sizeof(g_buf) - 1) {
        i64 r = t_recv(mode, fd, handle, g_buf + got,
                       (int)(sizeof(g_buf) - 1 - got));
        if (r <= 0) return;
        got += r;
        if (s_find_str(g_buf, (u64)got, (const u8*)"\r\n\r\n", 4) ||
            s_find_str(g_buf, (u64)got, (const u8*)"\n\n", 2)) break;
    }
    g_buf[got] = 0;

    /* request line: METHOD SP target SP HTTP/1.x */
    u8* sp = s_find(g_buf, ' ');
    if (!sp || sp == g_buf) { srv_404(mode, fd, handle); return; }
    u64 mlen = (u64)(sp - g_buf);
    int is_head = (mlen == 4 && s_ci_eq(g_buf, "HEAD"));
    if (mlen != 3 && mlen != 4) { srv_404(mode, fd, handle); return; }
    u8* path = sp + 1;
    u8* sp2 = s_find(path, ' ');
    u64 plen = sp2 ? (u64)(sp2 - path) : s_len(path);
    for (u64 i = 0; i < plen; i++) if (path[i] == '?') { plen = i; break; }

    if (plen == 1 && path[0] == '/') { srv_listing(mode, fd, handle, is_head); return; }
    if (plen == 0 || path[0] != '/') { srv_404(mode, fd, handle); return; }

    {
        const u8* name = path + 1;
        u64 nlen = plen - 1;                 /* plen >= 2 here (checked above) */
        if (nlen == 0 || nlen >= (u64)MAX_FILE_NAME) { srv_404(mode, fd, handle); return; }
        u8 fname[MAX_FILE_NAME];
        for (u64 i = 0; i < nlen; i++) {
            if (name[i] == '/' || name[i] == '\\') { srv_404(mode, fd, handle); return; }
            fname[i] = name[i];
        }
        fname[nlen] = 0;
        if (nlen == 1 && fname[0] == '.') { srv_404(mode, fd, handle); return; }
        if (nlen == 2 && fname[0] == '.' && fname[1] == '.') { srv_404(mode, fd, handle); return; }

        i64 f = httpdl_sys_open((const char*)fname, O_RDONLY, 0);
        if (f < 0) { srv_404(mode, fd, handle); return; }
        u8 st[144];
        if (httpdl_sys_fstat(f, st) < 0) {
            httpdl_sys_close(f); srv_404(mode, fd, handle); return;
        }
        u16 fmode = (u16)(st[24] | (st[25] << 8));
        if ((fmode & 0xF000) == 0x4000) {           /* directory */
            httpdl_sys_close(f); srv_404(mode, fd, handle); return;
        }
        u64 size = 0;
        for (int i = 0; i < 8; i++) size |= (u64)st[48 + i] << (8 * i);
        const char* ct = srv_ctype(fname, (i64)nlen);
        i64 hl = srv_header(g_req, sizeof(g_req), 200, "OK", (i64)size, ct);
        if (hl < 0) { httpdl_sys_close(f); return; }
        t_send(mode, fd, handle, g_req, (int)hl);
        if (!is_head) {
            u64 left = size;
            while (left > 0) {
                i64 want = HTTP_CHUNK;
                if ((u64)want > left) want = (i64)left;
                i64 r = httpdl_sys_read(f, g_chunk, want);
                if (r <= 0) break;
                if (t_send(mode, fd, handle, g_chunk, (int)r) < 0) break;
                left -= (u64)r;
            }
        }
        httpdl_sys_close(f);
    }
}

static long http_server(i64 port, const u8* cert, const u8* key) {
    int https = 0;
    i64 certlen = 0, keylen = 0;
    if (cert && key) {
        certlen = s_len(cert);
        keylen = s_len(key);
        if (certlen > 0 && keylen > 0) https = 1;
    }
    i64 ls = httpdl_sys_socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return -3;
    {
        long one = 1;
        httpdl_sys_setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, (i64)sizeof(one));
    }
    u8 sa[16];
    fill_sa(sa, 0, port);               /* 0.0.0.0 */
    if (httpdl_sys_bind(ls, sa, 16) < 0) { httpdl_sys_close(ls); return -4; }
    if (httpdl_sys_listen(ls, 16) < 0) { httpdl_sys_close(ls); return -4; }
    for (;;) {
        i64 c = httpdl_sys_accept(ls, 0, 0);
        if (c < 0) {
            long req[2] = { 0, 1000000L };      /* 1 ms, avoid busy loop on EINTR */
            long rem[2];
            httpdl_sys_nanosleep(req, rem);
            continue;
        }
        i64 h = -1;
        int mode = 0;
        if (https) {
            tls_init_io();
            h = tlsrt_entry(TLS_OP_TLS_ACCEPT, c, (i64)cert, certlen,
                            (i64)key, keylen);
            if (h < 0) { httpdl_sys_close(c); continue; }
            mode = 1;
        }
        srv_serve(mode, c, h);
        t_close(mode, c, h);
    }
    return 0;
}

long httpdl_entry(long op, long a1, long a2, long a3, long a4, long a5) {
    (void)a5;
    const u8* url = (const u8*)a1;
    const u8* file = (const u8*)a2;
    switch (op) {
        case 1:  if (!url || !file) return -1;
                 cookie_clear();
                 return httpdl_run(url, file, 1);
        case 2:  if (!url || !file) return -1;
                 return httpdl_ask(url, file);
        case 3:  if (!url || !file) return -1;
                 cookie_clear();
                 return httpdl_run(url, file,
                                   ask_yes_no("Отдать почти весь канал? (y/n) "));
        case 4:  return http_server(a1, (const u8*)a2, (const u8*)a3);
        case 5:  if (!a1 || !a2 || !a3 || !a4) return -1;
                 return httpdl_ghreleases((const u8*)a1, (const u8*)a2,
                                          (const u8*)a3, (const u8*)a4);
        case 6:  if (!a1 || !a2 || !a3 || !a4 || !a5) return -1;
                 return httpdl_ask_gh((const u8*)a1, (const u8*)a2,
                                      (const u8*)a3, (const u8*)a4,
                                      (const u8*)a5);
        case 7:  if (!a1) return -1;
                 return httpdl_msiso((const u8*)a1, (const u8*)a2);
        case 8:
            if (a4 == 1) {
                if (!a1) return -1;
                return httpdl_winpe((const u8*)a1, (const u8*)a2);
            }
            if (a4 != 0 || !a1 || !a2) return -1;
            cookie_clear();
             return iso_extract_impl((const u8*)a1, (const u8*)a2,
                                     (const u8*)a3, 0);
         case 9:  if (!a1) return -1;
                  return httpdl_winpe_media((const u8*)a1, (const u8*)a2);
         default: return -1;
    }
}
