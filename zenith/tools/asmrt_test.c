/* Loads the flat asmrt blob into an anonymous RWX mapping and drives it
   through the documented ABI, so the PIC image can be diffed against the
   bytes real NASM produces for the same source.

   usage: asmrt_test <blob.bin> <entry_off> <mem_size> <source.asm> [--show]
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <stddef.h>

/* Watchdog: a hang inside the blob is almost always a lexer/parser loop that
   forgot to advance the cursor. Report the blob offset so it can be mapped
   back to a symbol with nm. */
void *g_base;   /* for gdb/watchdog: blob offset == addr - g_base */

/* Called once the blob is mapped and copied, so gdb can "break gdb_gate" and
   only then set breakpoints at absolute blob offsets. The global store is
   what keeps the call from being optimised away -- a function whose body is
   only an empty asm block is dropped at -O1, and the breakpoint then never
   fires, which looks exactly like a mysterious jump into the middle of the
   blob. */
volatile int g_gate_hit;
__attribute__((noinline)) void gdb_gate(void)
{
    __asm__ __volatile__("" ::: "memory");
    g_gate_hit = 1;
}

static void blob_offset(const char *what, void *uc, siginfo_t *si)
{
    ucontext_t *c = (ucontext_t *)uc;
    unsigned long rip = (unsigned long)c->uc_mcontext.gregs[REG_RIP];
    unsigned long rbx = (unsigned long)c->uc_mcontext.gregs[REG_RBX];
    unsigned long r11 = (unsigned long)c->uc_mcontext.gregs[REG_R11];
    unsigned long r12 = (unsigned long)c->uc_mcontext.gregs[REG_R12];
    unsigned long r13 = (unsigned long)c->uc_mcontext.gregs[REG_R13];
    unsigned long r14 = (unsigned long)c->uc_mcontext.gregs[REG_R14];
    unsigned long r15 = (unsigned long)c->uc_mcontext.gregs[REG_R15];
    unsigned long b = (unsigned long)g_base;
    unsigned long rcx = (unsigned long)c->uc_mcontext.gregs[REG_RCX];
    unsigned long rdi = (unsigned long)c->uc_mcontext.gregs[REG_RDI];
    unsigned long rsi = (unsigned long)c->uc_mcontext.gregs[REG_RSI];
    unsigned long r8  = (unsigned long)c->uc_mcontext.gregs[REG_R8];
    unsigned long r9  = (unsigned long)c->uc_mcontext.gregs[REG_R9];
    unsigned long r10 = (unsigned long)c->uc_mcontext.gregs[REG_R10];
    unsigned long rdx = (unsigned long)c->uc_mcontext.gregs[REG_RDX];
    fprintf(stderr, "%s: rip=+0x%lx rax=+0x%lx rbx=+0x%lx r11=+0x%lx r12=+0x%lx r13=+0x%lx\n"
            "     r14=+0x%lx r15=+0x%lx rcx=+0x%lx rdi=+0x%lx rsi=+0x%lx\n"
            "     rdx=+0x%lx r8=+0x%lx r9=+0x%lx r10=+0x%lx\n",
            what, rip - b,
            (unsigned long)c->uc_mcontext.gregs[REG_RAX] - b, rbx - b, r11 - b,
            r12 - b, r13 - b, r14 - b, r15 - b, rcx - b, rdi - b, rsi - b,
            rdx - b, r8 - b, r9 - b, r10 - b);
    if (si) fprintf(stderr, "     fault addr=+0x%lx code=%d\n",
                    (unsigned long)si->si_addr - b, si->si_code);
    {
        unsigned long *sp = (unsigned long *)c->uc_mcontext.gregs[REG_RSP];
        fprintf(stderr, "     rsp=%lx\n     stack:", (unsigned long)sp - b);
        for (int i = 0; i < 10; i++) fprintf(stderr, " +0x%lx", sp[i] - b);
        fprintf(stderr, "\n");
    }
    _exit(3);
}

static void on_alarm(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    blob_offset("WATCHDOG", uc, si);
}

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    blob_offset("SEGV", uc, si);
}

typedef long long (*asmfn)(long long op, void *a1, long long a2, void *a3,
                           long long a4, long long a5);

static char *slurp(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); exit(1); }
    struct stat st;
    fstat(fd, &st);
    char *buf = malloc((size_t)st.st_size + 1);
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0) { perror("read"); exit(1); }
    buf[n] = 0;
    *len = (size_t)n;
    return buf;
}

static void hexdump(const char *tag, const unsigned char *p, size_t n)
{
    printf("%s (%zu):\n", tag, n);
    for (size_t i = 0; i < n; i++) {
        if (i % 16 == 0) printf("  %04zx  ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15) putchar('\n');
    }
    if (n % 16) putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: %s <blob> <entry_off> <mem_size> <src.asm> [--show]\n", argv[0]); return 2; }
    unsigned long entry_off = strtoul(argv[2], NULL, 0);
    unsigned long mem_size = strtoul(argv[3], NULL, 0);
    int show = (argc > 5 && !strcmp(argv[5], "--show"));

    size_t blob_len;
    char *blob = slurp(argv[1], &blob_len);
    size_t src_len;
    char *src = slurp(argv[4], &src_len);

    if (mem_size < blob_len) mem_size = blob_len;
    /* the flat image omits .bss, so the mapping must cover it: the caller
       passes __bss_end from the linker script. Fresh anonymous pages are the
       zeroed arena the blob expects. */
    /* Fixed address so gdb can break at absolute blob offsets. Try a few
       candidate bases; fall back to the kernel choice. */
    static const unsigned long want[] = {
        0x00007f0000000000UL, 0x0000600000000000UL, 0x0000400000000000UL,
        0x0000300000000000UL, 0x0000500000000000UL
    };
    void *base = MAP_FAILED;
    for (size_t i = 0; i < sizeof want / sizeof *want && base == MAP_FAILED; i++)
        base = mmap((void *)want[i], mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (base == MAP_FAILED)
        base = mmap(NULL, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fprintf(stderr, "#base=%p\n", base);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    memcpy(base, blob, blob_len);
    if (entry_off >= blob_len) { fprintf(stderr, "entry offset out of range\n"); return 1; }
    g_base = base;
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_alarm;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGALRM, &sa, NULL);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        setvbuf(stdout, NULL, _IONBF, 0);
    }
    /* Must come after the blob is in place, otherwise gdb plants its INT3
       traps into freshly mapped zero pages and the memcpy below wipes them. */
    gdb_gate();
    alarm(3);
    asmfn asm_entry = (asmfn)((char *)base + entry_off);

    unsigned char *dst = calloc(1, 65536);
    char err[512];

    /* op 3: sizing pass, must not write anything */
    long long need = asm_entry(3, dst, 65536, src, (long long)src_len, 0);
    printf("need = %lld (0x%llx)\n", need, (unsigned long long)need);

    /* op 1: real assembly */
    memset(dst, 0xCC, 4096);
    long long got = asm_entry(1, dst, 65536, src, (long long)src_len, 0);
    printf("got  = %lld (0x%llx)\n", got, (unsigned long long)got);

    long long elen = asm_entry(2, err, sizeof err, 0, 0, 0);
    printf("err  = %lld \"%.*s\"\n", elen, (int)elen, err);

    if (got < 0) { printf("FAIL: negative size\n"); return 1; }
    if (show) hexdump("out", dst, (size_t)got);
    else { for (long long i = 0; i < got; i++) printf("%02x", dst[i]); putchar('\n'); }

    if (need != got) { printf("FAIL: sizing %lld != emit %lld\n", need, got); return 1; }
    printf("OK\n");
    return 0;
}
