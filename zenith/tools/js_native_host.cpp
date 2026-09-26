#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>

extern "C" long jsrt_entry(long op, long a1, long a2, long a3, long a4, long a5);

static long js_exec(const char* s){ return jsrt_entry(1,(long)s,(long)strlen(s),0,0,0); }
static long js_expr(const char* s){ return jsrt_entry(2,(long)s,(long)strlen(s),0,0,0); }

static char fs_buf[256 * 1024];

static long h_fs_read(long path, long a2, long buf, long cap) {
    int fd = open((const char *)path, O_RDONLY);
    if (fd < 0) return -1;
    long n = read(fd, (void *)buf, (size_t)cap);
    close(fd);
    return n;
}
static long h_fs_write(long path, long a2, long data, long len) {
    int fd = open((const char *)path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    long n = write(fd, (const void *)data, (size_t)len);
    close(fd);
    return n;
}
static long h_fs_exists(long path, long a2, long a3, long a4) {
    return access((const char *)path, F_OK) == 0 ? 1 : 0;
}
static long h_get_cwd(long buf, long cap, long a3, long a4) {
    if (getcwd((char *)buf, (size_t)cap)) return (long)strlen((char *)buf);
    return 0;
}
static long h_print(long buf, long len, long a3, long a4) {
    fwrite((const void *)buf, 1, (size_t)len, stdout);
    return 0;
}
static long h_exec(long cmd, long a2, long outbuf, long outcap) {
    FILE* fp = popen((const char*)cmd, "r");
    if (!fp) return -1;
    long total = 0;
    while (total < outcap - 1) {
        size_t n = fread((char*)outbuf + total, 1, (size_t)(outcap - 1 - total), fp);
        if (n == 0) break;
        total += (long)n;
    }
    int rc = pclose(fp);
    return rc == -1 ? -1 : 0;  /* return exit status: 0 on success */
}
static long h_mkdir(long path, long a2, long a3, long a4) {
    return mkdir((const char*)path, 0755) == 0 ? 0 : -1;
}
static long h_readdir(long path, long outbuf, long outcap, long a4) {
    DIR* d = opendir((const char*)path);
    if (!d) return -1;
    long total = 0;
    for (struct dirent* e; (e = readdir(d)) != 0;) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        long nl = (long)strlen(e->d_name);
        if (total + nl + 1 > outcap) break;
        memcpy((char*)outbuf + total, e->d_name, nl);
        total += nl;
        ((char*)outbuf)[total++] = '\n';
    }
    closedir(d);
    return total;
}
static long h_unlink(long path, long a2, long a3, long a4) {
    return unlink((const char*)path) == 0 ? 0 : -1;
}
static long h_sleep(long ms, long a2, long a3, long a4) {
    usleep((useconds_t)ms * 1000);
    return 0;
}
static long h_stat(long path, long outbuf, long outcap, long a4) {
    struct stat st;
    if (stat((const char*)path, &st) != 0) return -1;
    char* ob = (char*)outbuf;
    long n = (long)snprintf(ob, (size_t)(outcap > 0 ? outcap : 1), "%lld", (long long)st.st_size);
    if (n < 0) n = 0; if (n >= outcap) n = outcap - 1;
    long p = n;
    ob[p++] = '\0';
    ob[p++] = S_ISDIR(st.st_mode) ? '1' : '0';
    ob[p++] = '\0';
    return p - 1 - n - 1;  /* kept for symmetry; engine parses "size\0is_dir\0" */
}
static long h_rand(long a1, long a2, long a3, long a4) {
    return (long)rand();
}
static int g_argc; static char** g_argv;
static long h_env(long key, long outbuf, long outcap, long a4) {
    const char* v = getenv((const char*)key);
    if (!v) return -1;
    long n = (long)strlen(v);
    if (n > outcap - 1) n = outcap - 1;
    memcpy((char*)outbuf, v, (size_t)n);
    ((char*)outbuf)[n] = '\0';
    return n;
}
static long h_args(long idx, long outbuf, long outcap, long a4) {
    if (idx < 0 || idx >= g_argc) return -1;
    const char* v = g_argv[idx];
    long n = (long)strlen(v);
    if (n > outcap - 1) n = outcap - 1;
    memcpy((char*)outbuf, v, (size_t)n);
    ((char*)outbuf)[n] = '\0';
    return n;
}
static long h_uname(long a1, long outbuf, long outcap, long a4) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    const char* v = u.sysname;
    long n = (long)strlen(v);
    if (n > outcap - 1) n = outcap - 1;
    memcpy((char*)outbuf, v, (size_t)n);
    ((char*)outbuf)[n] = '\0';
    return n;
}

int main(int argc, char **argv) {
    jsrt_entry(0, 0, 0, 0, 0, 0); /* RESET */
    g_argc = argc; g_argv = argv;

    long fns[24];
    for (int i = 0; i < 24; i++) fns[i] = 0;
    fns[0] = (long)h_fs_read;  fns[1] = (long)h_fs_write; fns[2] = (long)h_fs_exists;
    fns[3] = (long)h_get_cwd;  fns[12] = (long)h_print;
    fns[13] = (long)h_exec;    fns[14] = (long)h_mkdir;
    fns[15] = (long)h_readdir; fns[16] = (long)h_unlink; fns[17] = (long)h_sleep;
    fns[18] = (long)h_stat;    fns[19] = (long)h_rand;
    fns[20] = (long)h_env;     fns[21] = (long)h_args;   fns[22] = (long)h_uname;
    for (int i = 0; i < 24; i++) {
        if (fns[i]) jsrt_entry(6, i, fns[i], 0, 0, 0); /* SET_HOST */
    }

    char buf[1024];
    if (argc > 1 && strcmp(argv[1], "require") == 0) {
        long rc = js_exec("var f = require('./jsmod_a.js'); f(19, 23);");
        printf("exec rc=%ld\n", rc);
        long n = jsrt_entry(3, (long)buf, sizeof(buf) - 1, 0, 0, 0);
        printf("result=[%.*s] n=%ld\n", (int)n, buf, n);
    } else if (argc > 1 && strcmp(argv[1], "builtin") == 0) {
        long rc = js_exec(
            "var fs = require('fs');"
            "fs.writeFileSync('/tmp/jb.txt','0123456789');"
            "var s0 = fs.readFileSync('/tmp/jb.txt');"
            "var b = require('base64');"
            "var e = b.encode(s0);"
            "var d = b.decode(e);"
            "console.log('fs read=' + s0);"
            "console.log('b64=' + e);"
            "console.log('dec=' + d);"
            "var p = require('path');"
            "console.log('path join=' + p.join('/a','b','c'));"
            "console.log('base=' + p.basename('/x/y/z.txt'));"
            "console.log('ext=' + p.extname('/x/y/z.txt'));"
            "console.log('dir=' + p.dirname('/x/y/z.txt'));"
            "var j = JSON.stringify({a:1,b:[true,null,'s'],c:2.5});"
            "console.log('json=' + j);"
            "var r = Math.random();"
            "console.log('rand>=0=' + (r>=0));"
            "console.log('rr<1=' + (r<1));"
            "1;");
        printf("builtin rc=%ld\n", rc);
        long n = jsrt_entry(3, (long)buf, sizeof(buf) - 1, 0, 0, 0);
        printf("result=[%.*s] n=%ld\n", (int)n, buf, n);
    } else if (argc > 1 && strcmp(argv[1], "pkg") == 0) {
        /* require a bare specifier that resolves via node_modules + package.json main */
        long rc = js_exec("var pkg = require('myb'); pkg;");
        printf("pkg rc=%ld\n", rc);
        long n = jsrt_entry(3, (long)buf, sizeof(buf) - 1, 0, 0, 0);
        printf("result=[%.*s] n=%ld\n", (int)n, buf, n);
    } else {
        long rc = js_exec("var c = __readFile('jhost.txt'); c.length;");
        printf("exec rc=%ld\n", rc);
        long n = jsrt_entry(3, (long)buf, sizeof(buf) - 1, 0, 0, 0);
        printf("read len=[%.*s]\n", (int)n, buf);
        rc = js_expr("__exists('jhost.txt') ? 33 : 77;");
        printf("existsnum=%ld\n", jsrt_entry(5, 0, 0, 0, 0, 0));
    }
    return 0;
}