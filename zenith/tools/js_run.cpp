// Minimal runner for the JS engine under a sanitizer build: feeds one .js file
// (or stdin) to jsrt_entry(EXEC) and prints the result / error text, then
// installs the Linux host slots (tools/js_host_linux.c) so fs/exec/env/... builtins
// are exercisable from the harness too.
// Build (see Makefile.linux target test-js-asan):
//   gcc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
//       -c tools/jsrt.c -o jsrt_asan.o
//   gcc -O1 -g -fsanitize=address,undefined -c tools/js_host_linux.c -o js_host.o
//   g++ -O1 -g -fsanitize=address,undefined tools/js_run.cpp jsrt_asan.o js_host.o -o js_run
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
long jsrt_entry(long op, long a1, long a2, long a3, long a4, long a5);
long js_host_fs_read(long path, long a2, long buf, long cap);
long js_host_fs_write(long path, long a2, long data, long len);
long js_host_fs_exists(long path, long a2, long a3, long a4);
long js_host_get_cwd(long buf, long cap, long a3, long a4);
long js_host_print(long buf, long len, long a3, long a4);
long js_host_exec(long cmd, long a2, long outbuf, long cap);
long js_host_fs_mkdir(long path, long a2, long a3, long a4);
long js_host_fs_readdir(long path, long outbuf, long cap, long a4);
long js_host_fs_unlink(long path, long a2, long a3, long a4);
long js_host_sleep(long ms, long a2, long a3, long a4);
long js_host_fs_stat(long path, long outbuf, long cap, long a4);
long js_host_env(long key, long outbuf, long cap, long a4);
long js_host_args(long idx, long outbuf, long cap, long a4);
long js_host_uname(long a1, long outbuf, long cap, long a4);
}

#define JS_OP_RESET     0
#define JS_OP_EXEC      1
#define JS_OP_RESULT    3
#define JS_OP_ERROR     4
#define JS_OP_NUM       5
#define JS_OP_SET_HOST  6

#define HOST_FS_READ     0
#define HOST_FS_WRITE    1
#define HOST_FS_EXISTS   2
#define HOST_GET_CWD     3
#define HOST_PRINT      12
#define HOST_EXEC       13
#define HOST_FS_MKDIR   14
#define HOST_FS_READDIR 15
#define HOST_FS_UNLINK  16
#define HOST_SLEEP      17
#define HOST_FS_STAT    18
#define HOST_ENV        20
#define HOST_ARGS       21
#define HOST_UNAME      22

static void install_linux_host() {
    struct { int slot; long fn; } table[] = {
        {HOST_FS_READ,     (long)&js_host_fs_read},
        {HOST_FS_WRITE,    (long)&js_host_fs_write},
        {HOST_FS_EXISTS,   (long)&js_host_fs_exists},
        {HOST_GET_CWD,     (long)&js_host_get_cwd},
        {HOST_PRINT,       (long)&js_host_print},
        {HOST_EXEC,        (long)&js_host_exec},
        {HOST_FS_MKDIR,    (long)&js_host_fs_mkdir},
        {HOST_FS_READDIR,  (long)&js_host_fs_readdir},
        {HOST_FS_UNLINK,   (long)&js_host_fs_unlink},
        {HOST_SLEEP,       (long)&js_host_sleep},
        {HOST_FS_STAT,     (long)&js_host_fs_stat},
        {HOST_ENV,         (long)&js_host_env},
        {HOST_ARGS,        (long)&js_host_args},
        {HOST_UNAME,       (long)&js_host_uname},
    };
    for (auto& e : table) jsrt_entry(JS_OP_SET_HOST, e.slot, e.fn, 0, 0, 0);
}

int main(int argc, char** argv) {
    std::string src;
    if (argc > 1) {
        FILE* f = fopen(argv[1], "rb");
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) src.append(buf, n);
        fclose(f);
    } else {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) src.append(buf, n);
    }

    jsrt_entry(JS_OP_RESET, 0, 0, 0, 0, 0);
    install_linux_host();
    long rc = jsrt_entry(JS_OP_EXEC, (long)src.data(), (long)src.size(), 0, 0, 0);

    char buf[4096];
    long n = jsrt_entry(JS_OP_RESULT, (long)buf, sizeof(buf) - 1, 0, 0, 0);
    if (n > 0) { buf[n] = 0; printf("result=%s\n", buf); }

    char eb[4096];
    long en = jsrt_entry(JS_OP_ERROR, (long)eb, sizeof(eb) - 1, 0, 0, 0);
    if (en > 0) { eb[en] = 0; printf("error=%s\n", eb); }

    long num = jsrt_entry(JS_OP_NUM, 0, 0, 0, 0, 0);
    printf("rc=%ld num=%ld\n", rc, num);
    return 0;
}
