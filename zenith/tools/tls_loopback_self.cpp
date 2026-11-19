// End-to-end TLS loopback test: maps the generated TLS blob into executable
// memory (same as tls_peer_loopback.cpp), then runs OUR server handshake
// (TLS_OP_TLS_ACCEPT) and OUR client handshake (TLS_OP_TLS_CONNECT) against
// each other over a real bidirectional socketpair, and does an encrypted
// round-trip in BOTH directions.
//
// Usage: ./tls_loopback_self <cert.pem> <key.pem>
//
// Exit 0 = two handshakes + two-way application-data round-trip succeeded.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include "tls_blob.h"
#include "../tools/tlsrt.h"

typedef long (*Entry)(long, long, long, long, long, long);

extern "C" long win_send(long, char*, long, long);
extern "C" long win_recv(long, char*, long, long);
extern "C" long win_close(long);

static Entry g_entry;
static long g_result_server = -999;
static long g_result_client = -999;

static std::string read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string s;
    s.resize((size_t)n);
    if (n > 0 && fread(&s[0], 1, (size_t)n, f) != (size_t)n) { exit(2); }
    fclose(f);
    return s;
}

static long txn(long op, std::initializer_list<long> args) {
    long a[5] = {0,0,0,0,0};
    int i = 0; for (long v : args) { if (i < 5) a[i++] = v; }
    return g_entry(op, a[0], a[1], a[2], a[3], a[4]);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3) {
        printf("usage: %s <cert.pem> <key.pem>\n", argv[0]);
        return 2;
    }
    std::string cert = read_file(argv[1]);
    std::string key  = read_file(argv[2]);

    void* base = mmap(nullptr, kTlsBlobSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(base, kTlsBlob, kTlsBlobSize);
    g_entry = (Entry)((char*)base + TLS_BLOB_ENTRY);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) { perror("socketpair"); return 2; }

    g_entry(TLS_OP_IO_INIT, (long)(void*)win_send, (long)(void*)win_recv,
            (long)(void*)win_close, 0, 0);

    /* Server handshake on sp[0]; client handshake on sp[1]. */
    std::thread srver([&]() {
        fprintf(stderr, "[t] server: calling TLS_OP_TLS_ACCEPT\n");
        g_result_server = txn(TLS_OP_TLS_ACCEPT, {
            sp[0], (long)cert.data(), (long)cert.size(),
            (long)key.data(), (long)key.size() });
        fprintf(stderr, "[t] server: ACCEPT returned %ld\n", g_result_server);
        if (g_result_server < 0)
            fprintf(stderr, "[t] server: last_error=%ld\n",
                    txn(TLS_OP_TLS_LAST_ERROR, {}));
    });
    fprintf(stderr, "[t] main: calling TLS_OP_TLS_CONNECT\n");
    g_result_client = txn(TLS_OP_TLS_CONNECT, {
        sp[1], (long)"localhost", 9 });
    fprintf(stderr, "[t] main: CONNECT returned %ld\n", g_result_client);
    srver.join();

    printf("client handle=%ld server handle=%ld\n", g_result_client, g_result_server);
    if (g_result_server < 0 || g_result_client < 0) {
        printf("FAIL handshake client=%ld server=%ld last_error=%ld\n",
               g_result_client, g_result_server,
               txn(TLS_OP_TLS_LAST_ERROR, {}));
        return 1;
    }
    long hS = g_result_server, hC = g_result_client;
    fprintf(stderr, "[t] roundtrip: client h=%ld server h=%ld\n", hC, hS);

    /* Round-trip both directions with distinct payloads. */
    const char* c2s = "hello from the CLIENT over our TLS";
    const char* s2c = "hello from the SERVER over our TLS";
    fprintf(stderr, "[t] client TLS_SEND (c2s)\n");
    long sent = txn(TLS_OP_TLS_SEND, { hC, (long)c2s, (long)strlen(c2s) });
    if (sent != (long)strlen(c2s)) { printf("FAIL client send\n"); return 1; }
    fprintf(stderr, "[t] server TLS_SEND (s2c)\n");
    sent = txn(TLS_OP_TLS_SEND, { hS, (long)s2c, (long)strlen(s2c) });
    if (sent != (long)strlen(s2c)) { printf("FAIL server send\n"); return 1; }
    fprintf(stderr, "[t] server TLS_RECV loop\n");

    char buf[512];
    std::string got;
    char cbuf[512];
    std::string server_got;
    size_t want_srv = strlen(c2s), want_cli = strlen(s2c);
    int guard = 0;
    while (server_got.size() < want_srv && guard++ < 50) {
        long n = txn(TLS_OP_TLS_RECV, { hS, (long)cbuf, (long)sizeof cbuf });
        if (n <= 0) break;
        server_got.append(cbuf, (size_t)n);
    }
    fprintf(stderr, "[t] client TLS_RECV loop\n");
    guard = 0;
    while (got.size() < want_cli && guard++ < 50) {
        long n = txn(TLS_OP_TLS_RECV, { hC, (long)buf, (long)sizeof buf });
        if (n <= 0) break;
        got.append(buf, (size_t)n);
    }

    printf("server received (%zu): %s\n", server_got.size(), server_got.c_str());
    printf("client received (%zu): %s\n", got.size(), got.c_str());

    int fail = 0;
    if (server_got != c2s) { printf("FAIL server side payload mismatch\n"); fail = 1; }
    if (got != s2c) { printf("FAIL client side payload mismatch\n"); fail = 1; }

    txn(TLS_OP_TLS_CLOSE, { hC }); close(sp[1]);
    txn(TLS_OP_TLS_CLOSE, { hS }); close(sp[0]);
    return fail ? 1 : 0;
}