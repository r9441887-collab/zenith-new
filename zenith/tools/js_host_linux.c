/* Linux host half of the JS engine's callback table (g_host_fn[] in jsrt.c).
 *
 * The engine never talks to the OS itself: fs/print/exec/env/... go through
 * `long fn(long a1, long a2, long a3, long a4)` slots that the embedder fills
 * in with JS_OP_SET_HOST. On Windows the embedder (emitJsHostStubs in
 * src/codegen_js.cpp) emits Win64 thunks into kernel32/ws2_32, because those
 * symbols only exist through the PE import table. On Linux there is no import
 * table to lean on, and the rest of `app linux` deliberately runs without
 * libc, so the host side lives here instead: raw x86-64 syscalls, compiled by
 * the same freestanding -fpic flags as the engine and linked into the same
 * blob image. codegen then installs these functions' addresses directly — no
 * stub code, no fixups, and it works at whatever base the blob lands at.
 *
 * Syscall ABI: nr in rax, args in rdi/rsi/rdx/r10/r8/r9, result in rax
 * (-errno on failure). Signatures and semantics match tools/js_native_host.cpp
 * (the native test harness), so a .z program behaves the same on both.
 *
 * Slots 4-11 (net/tls) and 19 (rand) are not provided here: the engine treats
 * an unset slot as "unavailable" and degrades (netConnect -> -1, httpGet ->
 * undefined). Math.random() needs no host at all, and net/tls on Linux would
 * want the DNS resolver, which raw syscalls do not have.
 */

#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_stat        4
#define SYS_pipe        22
#define SYS_access      21
#define SYS_dup2        33
#define SYS_nanosleep   35
#define SYS_fork        57
#define SYS_execve      59
#define SYS_exit        60
#define SYS_wait4       61
#define SYS_uname       63
#define SYS_getcwd      79
#define SYS_mkdir       83
#define SYS_unlink      87
#define SYS_getdents64  217

#define O_WRONLY        1
#define O_CREAT         64
#define O_TRUNC         512

#define S_IFMT          0170000
#define S_IFDIR         0040000

static long sys3(long nr, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c)
                 : "rcx", "r11", "memory");
    return r;
}

static long sys6(long nr, long a, long b, long c, long d, long e, long f) {
    register long r10 asm("r10") = d;
    register long r8 asm("r8") = e;
    register long r9 asm("r9") = f;
    long r;
    asm volatile("syscall" : "=a"(r)
                 : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return r;
}

static long xlen(const char* s) {
    long n = 0;
    while (s[n]) n++;
    return n;
}

static void xcpy(char* d, const char* s, long n) {
    long i;
    for (i = 0; i < n; i++) d[i] = s[i];
}

/* Decimal digits of v into out; returns the length. tmp holds the reversal. */
static long fmt_ulong(long v, char* out) {
    char tmp[24];
    long n = 0, m = 0;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v > 0) { tmp[m++] = (char)('0' + v % 10); v /= 10; }
    while (m > 0) out[n++] = tmp[--m];
    return n;
}

/* ---- 0/1/2/3: file system ---------------------------------------------- */

long js_host_fs_read(long path, long a2, long buf, long cap) {
    long fd, total = 0;
    (void)a2;
    if (cap <= 0) return 0;
    fd = sys3(SYS_open, path, 0, 0);
    if (fd < 0) return -1;
    while (total < cap) {
        long n = sys3(SYS_read, fd, buf + total, cap - total);
        if (n <= 0) break;
        total += n;
    }
    sys3(SYS_close, fd, 0, 0);
    return total;
}

long js_host_fs_write(long path, long a2, long data, long len) {
    long fd, total = 0;
    (void)a2;
    if (len < 0) return -1;
    fd = sys3(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    while (total < len) {
        long n = sys3(SYS_write, fd, data + total, len - total);
        if (n <= 0) break;
        total += n;
    }
    sys3(SYS_close, fd, 0, 0);
    return total;
}

long js_host_fs_exists(long path, long a2, long a3, long a4) {
    (void)a2; (void)a3; (void)a4;
    return sys3(SYS_access, path, 0, 0) >= 0 ? 1 : 0;
}

long js_host_get_cwd(long buf, long cap, long a3, long a4) {
    (void)a3; (void)a4;
    if (sys3(SYS_getcwd, buf, cap, 0) < 0) return -1;
    return xlen((const char*)buf);
}

/* ---- 12: print ---------------------------------------------------------- */

long js_host_print(long buf, long len, long a3, long a4) {
    long total = 0;
    (void)a3; (void)a4;
    while (total < len) {
        long n = sys3(SYS_write, 1, buf + total, len - total);
        if (n <= 0) break;
        total += n;
    }
    return 0;
}

/* ---- 14/16/17/18: mkdir / unlink / sleep / stat ------------------------- */

long js_host_fs_mkdir(long path, long a2, long a3, long a4) {
    (void)a2; (void)a3; (void)a4;
    return sys3(SYS_mkdir, path, 0755, 0) < 0 ? -1 : 0;
}

long js_host_fs_unlink(long path, long a2, long a3, long a4) {
    (void)a2; (void)a3; (void)a4;
    return sys3(SYS_unlink, path, 0, 0) < 0 ? -1 : 0;
}

long js_host_sleep(long ms, long a2, long a3, long a4) {
    long ts[2];
    (void)a2; (void)a3; (void)a4;
    if (ms <= 0) return 0;
    ts[0] = ms / 1000;
    ts[1] = (ms % 1000) * 1000000;
    sys3(SYS_nanosleep, (long)ts, 0, 0);
    return 0;
}

/* outbuf layout expected by the engine: "size\0is_dir\0". */
long js_host_fs_stat(long path, long outbuf, long cap, long a4) {
    long st[24];   /* kernel struct stat is 144 B — keep slack for layout drift */
    unsigned long size;
    unsigned int mode;
    long n, p = 0;
    char* ob = (char*)outbuf;
    (void)a4;
    if (cap < 8) return -1;
    if (sys3(SYS_stat, path, (long)st, 0) < 0) return -1;
    /* x86-64 struct stat: st_mode at 24 (u32), st_size at 48 (i64). */
    mode = (unsigned int)(st[3] & 0xFFFFFFFF);
    size = (unsigned long)st[6];
    n = fmt_ulong((long)size, ob);
    p = n;
    ob[p++] = 0;
    ob[p++] = ((mode & S_IFMT) == S_IFDIR) ? '1' : '0';
    ob[p++] = 0;
    return 0;
}

/* ---- 15: readdir -> '\n'-separated names -------------------------------- */

long js_host_fs_readdir(long path, long outbuf, long cap, long a4) {
    char dbuf[1024];
    long fd, total = 0;
    (void)a4;
    if (cap <= 0) return -1;
    fd = sys3(SYS_open, path, 0, 0);
    if (fd < 0) return -1;
    for (;;) {
        long n = sys3(SYS_getdents64, fd, (long)dbuf, sizeof(dbuf));
        long off = 0;
        if (n <= 0) break;
        while (off < n) {
            unsigned char* e = (unsigned char*)dbuf + off;
            unsigned int reclen = (unsigned int)e[16] | ((unsigned int)e[17] << 8);
            char* name = (char*)(e + 19);
            long nl = 0;
            if (reclen == 0) break;
            while (name[nl]) nl++;
            if (!(nl == 1 && name[0] == '.') && !(nl == 2 && name[0] == '.' && name[1] == '.')) {
                if (total + nl + 1 > cap) { off = n; break; }
                xcpy((char*)outbuf + total, name, nl);
                total += nl;
                ((char*)outbuf)[total++] = '\n';
            }
            off += (long)reclen;
        }
    }
    sys3(SYS_close, fd, 0, 0);
    return total;
}

/* ---- 22: uname -> os.platform() ---------------------------------------- */

long js_host_uname(long a1, long outbuf, long cap, long a4) {
    char u[400];
    long i = 0;
    (void)a1; (void)a4;
    if (cap <= 0) return -1;
    if (sys3(SYS_uname, (long)u, 0, 0) < 0) return -1;
    while (u[i] && i < cap - 1) i++;
    xcpy((char*)outbuf, u, i);
    ((char*)outbuf)[i] = 0;
    return i;
}

/* ---- 20/21: environment and argv, read from /proc ----------------------- */

static char g_procbuf[65536];

/* Reads path into g_procbuf, NUL-terminated; returns the byte count or -1. */
static long read_proc(const char* path) {
    long fd = sys3(SYS_open, (long)path, 0, 0);
    long total = 0;
    if (fd < 0) return -1;
    while (total < (long)sizeof(g_procbuf) - 1) {
        long n = sys3(SYS_read, fd, (long)g_procbuf + total,
                      (long)sizeof(g_procbuf) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    g_procbuf[total] = 0;
    sys3(SYS_close, fd, 0, 0);
    return total;
}

long js_host_env(long key, long outbuf, long cap, long a4) {
    const char* k = (const char*)key;
    long kn = xlen(k), pos = 0, n;
    (void)a4;
    if (cap <= 0) return -1;
    n = read_proc("/proc/self/environ");
    if (n < 0) return -1;
    while (pos < n) {
        const char* e = g_procbuf + pos;
        long el = 0;
        while (pos + el < n && e[el]) el++;
        if (el > kn && e[kn] == '=') {
            long i, vl = el - kn - 1;
            const char* v = e + kn + 1;
            if (vl > cap - 1) vl = cap - 1;
            for (i = 0; i < vl; i++) ((char*)outbuf)[i] = v[i];
            ((char*)outbuf)[vl] = 0;
            return vl;
        }
        pos += el + 1;
    }
    return -1;
}

long js_host_args(long idx, long outbuf, long cap, long a4) {
    long pos = 0, n, cur = 0;
    (void)a4;
    if (cap <= 0 || idx < 0) return -1;
    n = read_proc("/proc/self/cmdline");
    if (n <= 0) return -1;
    while (pos < n) {
        const char* a = g_procbuf + pos;
        long al = 0;
        while (pos + al < n && a[al]) al++;
        if (cur == idx) {
            long i, l = al;
            if (l > cap - 1) l = cap - 1;
            for (i = 0; i < l; i++) ((char*)outbuf)[i] = a[i];
            ((char*)outbuf)[l] = 0;
            return l;
        }
        cur++;
        pos += al + 1;
    }
    return -1;
}

/* ---- 13: exec -> run `cmd` through /bin/sh, stdout into outbuf ---------- */

/* Builds an envp[] pointer array out of /proc/self/environ. The flat buffer
   is NUL-separated and double-NUL terminated, which is exactly the kernel's
   environ layout once split into pointers. Returns the entry count. */
static long build_envp(char** envp, long max) {
    long n = read_proc("/proc/self/environ");
    long pos = 0, cnt = 0;
    if (n <= 0) { envp[0] = 0; return 0; }
    while (pos < n && cnt < max - 1) {
        envp[cnt++] = g_procbuf + pos;
        while (pos < n && g_procbuf[pos]) pos++;
        pos++;
    }
    envp[cnt] = 0;
    return cnt;
}

long js_host_exec(long cmd, long a2, long outbuf, long cap) {
    int pfd[2];                    /* pipe(2) writes two ints, not two longs */
    long rfd, wfd;
    long pid, st = 0, total = 0;
    (void)a2;
    if (cap <= 0) return -1;
    if (sys3(SYS_pipe, (long)pfd, 0, 0) < 0) return -1;
    rfd = pfd[0];
    wfd = pfd[1];
    pid = sys3(SYS_fork, 0, 0, 0);
    if (pid < 0) {
        sys3(SYS_close, rfd, 0, 0);
        sys3(SYS_close, wfd, 0, 0);
        return -1;
    }
    if (pid == 0) {
        char* argv[4];
        char* envp[256];
        sys3(SYS_close, rfd, 0, 0);
        if (wfd != 1) {
            sys3(SYS_dup2, wfd, 1, 0);
            sys3(SYS_close, wfd, 0, 0);
        }
        argv[0] = "sh";
        argv[1] = "-c";
        argv[2] = (char*)cmd;
        argv[3] = 0;
        build_envp(envp, 256);
        sys3(SYS_execve, (long)"/bin/sh", (long)argv, (long)envp);
        sys3(SYS_exit, 127, 0, 0);
        for (;;) asm volatile("" ::: "memory");
    }
    sys3(SYS_close, wfd, 0, 0);
    /* Fill outbuf, then keep draining: a child blocked on a full pipe would
       never exit, so the tail is discarded instead of left unread. */
    for (;;) {
        char drain[512];
        long dst = (total < cap - 1) ? (outbuf + total) : (long)drain;
        long want = (total < cap - 1) ? (cap - 1 - total) : (long)sizeof(drain);
        long n = sys3(SYS_read, rfd, dst, want);
        if (n <= 0) break;
        if (total < cap - 1) total += n;
    }
    ((char*)outbuf)[total] = 0;
    sys3(SYS_close, rfd, 0, 0);
    sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0);
    if (st & 0x7F) return -1;              /* stopped/killed by a signal */
    return (st >> 8) & 0xFF;               /* WEXITSTATUS */
}
