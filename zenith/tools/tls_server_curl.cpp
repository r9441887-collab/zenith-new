// Realistic client interop: same TLS server, driven by `curl -k https://...`.
// Catches any renegotiation_info / client-behavior gaps openssl s_client masks.
//
// Usage: ./tls_server_curl <port> <cert.pem> <key.pem>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include "tls_blob.h"
#include "../tools/tlsrt.h"

typedef long (*Entry)(long, long, long, long, long, long);
extern "C" long win_send(long, char*, long, long);
extern "C" long win_recv(long, char*, long, long);
extern "C" long win_close(long);

static Entry g_entry;

static std::string read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    std::string s((size_t)n, '\0');
    if (n > 0 && fread(&s[0], 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f);
    return s;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4) { printf("usage: %s <port> <cert.pem> <key.pem>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);
    std::string cert = read_file(argv[2]);
    std::string key = read_file(argv[3]);

    void* base = mmap(nullptr, kTlsBlobSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(base, kTlsBlob, kTlsBlobSize);
    g_entry = (Entry)((char*)base + TLS_BLOB_ENTRY);
    g_entry(TLS_OP_IO_INIT, (long)(void*)win_send, (long)(void*)win_recv,
            (long)(void*)win_close, 0, 0);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if (bind(ls, (sockaddr*)&sa, sizeof sa) < 0 || listen(ls, 4) < 0) {
        perror("bind/listen"); return 2;
    }

    std::thread acceptor([&]() {
        int c = accept(ls, nullptr, nullptr);
        if (c < 0) { perror("accept"); return; }
        long h = g_entry(TLS_OP_TLS_ACCEPT, c, (long)cert.data(), (long)cert.size(),
                         (long)key.data(), (long)key.size());
        fprintf(stderr, "[srv] ACCEPT returned %ld\n", h);
        if (h < 0) {
            fprintf(stderr, "[srv] last_error=%ld\n",
                    g_entry(TLS_OP_TLS_LAST_ERROR,0,0,0,0,0));
            fprintf(stderr, "[srv] stage=%u\n", *(uint8_t*)((char*)base + kTlsg_tls_stage));
            close(c); return;
        }
        char buf[4096];
        std::string req;
        for (int i = 0; i < 20; i++) {
            long n = g_entry(TLS_OP_TLS_RECV, h, (long)buf, (long)sizeof buf,0,0);
            if (n <= 0) break;
            req.append(buf, (size_t)n);
            if (req.find("\r\n\r\n") != std::string::npos) break;
        }
        fprintf(stderr, "[srv] got request (%zu bytes): %s\n", req.size(),
                req.substr(0, 40).c_str());
        const char* resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nZENITH!";
        g_entry(TLS_OP_TLS_SEND, h, (long)resp, (long)strlen(resp),0,0);
        g_entry(TLS_OP_TLS_CLOSE, h,0,0,0,0);
        close(c);
    });

    char cmd[512];
    snprintf(cmd, sizeof cmd,
             "curl -ksv -o - -w '\\n[CURL rc %%{http_code}]' "
             "https://127.0.0.1:%d/ 2>&1", port);
    FILE* p = popen(cmd, "r");
    if (!p) { perror("popen"); return 2; }
    char line[4096];
    std::string out;
    while (fgets(line, sizeof line, p)) out += line;
    int rc2 = pclose(p);
    acceptor.join();
    close(ls);

    printf("--- curl output (%zu bytes) ---\n%s\n", out.size(), out.c_str());
    printf("pclose rc=%d\n", rc2);
    int ok = out.find("ZENITH!") != std::string::npos &&
             out.find("200") != std::string::npos;
    printf(ok ? "CURL INTEROP OK\n" : "CURL INTEROP FAIL\n");
    return ok ? 0 : 1;
}