// End-to-end TLS handshake test: maps the generated TLS blob into executable
// memory (same as blob_smoke.cpp), seeds its io-slots with real send/recv/close
// trampolines, opens a TCP socket to a live OpenSSL TLS 1.2 server, runs the
// hardened client handshake (TLS_OP_TLS_CONNECT), then does an encrypted
// request/response round-trip over the TLS session.
//
// Usage: ./tls_peer_loopback <host> <port> <http-host>
//   host     — TCP peer (e.g. 127.0.0.1)
//   port     — TLS port
//   http-host— SNI / Host header (e.g. localhost or example.test)
//
// Exit 0 = handshake + one application-data round-trip succeeded.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tls_blob.h"
#include "../tools/tlsrt.h"

typedef long (*Entry)(long, long, long, long, long, long);

extern "C" long win_send(long, char*, long, long);
extern "C" long win_recv(long, char*, long, long);
extern "C" long win_close(long);

static int g_fail = 0;

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("usage: %s <host> <port> <http-host>\n", argv[0]);
        return 2;
    }
    const char* host = argv[1];
    int port = atoi(argv[2]);
    const char* http_host = argv[3];

    /* ---- map the blob ---- */
    void* base = mmap(nullptr, kTlsBlobSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(base, kTlsBlob, kTlsBlobSize);
    Entry entry = (Entry)((char*)base + TLS_BLOB_ENTRY);

    /* ---- TCP connect ---- */
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        printf("ERROR getaddrinfo\n"); return 2;
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { perror("socket"); return 2; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 2; }
    freeaddrinfo(res);
    printf("TCP connected fd=%d\n", sock);

    /* ---- seed io slots (op 1) ---- */
    entry(TLS_OP_IO_INIT, (long)(void*)win_send, (long)(void*)win_recv, (long)(void*)win_close, 0, 0);

    /* ---- run the handshake (op 20) ---- */
    long h = entry(TLS_OP_TLS_CONNECT, sock, (long)http_host, (long)strlen(http_host), 0, 0);
    if (h < 0) {
        long err = entry(TLS_OP_TLS_LAST_ERROR, 0,0,0,0,0);
        printf("FAIL handshake handle=%ld last_error=%ld\n", h, err);
        close(sock);
        return 1;
    }
    printf("handshake OK handle=%ld\n", h);

    /* ---- send an HTTP/1.1 request over TLS ---- */
    std::string req = "GET / HTTP/1.1\r\nHost: ";
    req += http_host;
    req += "\r\nConnection: close\r\n\r\n";
    long sent = entry(TLS_OP_TLS_SEND, h, (long)req.data(), (long)req.size(), 0, 0);
    if (sent != (long)req.size()) {
        printf("FAIL send sent=%ld want=%zu\n", sent, req.size());
        entry(TLS_OP_TLS_CLOSE, h, 0,0,0,0); close(sock);
        return 1;
    }
    printf("request sent (%ld bytes)\n", sent);

    /* ---- read the response ---- */
    int timeout = 0;
    char buf[4096];
    std::string resp;
    while (timeout < 20) {
        long n = entry(TLS_OP_TLS_RECV, h, (long)buf, (long)sizeof buf, 0, 0);
        if (n < 0) { printf("FAIL recv n=%ld\n", n); break; }
        if (n == 0) break;
        resp.append(buf, (size_t)n);
        if (n < (long)sizeof buf) { /* try once more, then stop */ }
        timeout++;
    }

    bool ok = resp.find("HTTP/1.1") == 0 || resp.find("HTTP/1.0") == 0;
    printf("response (%zu bytes) starts: %.*s\n",
           resp.size(), (int)(resp.size()<80?resp.size():80), resp.c_str());
    entry(TLS_OP_TLS_CLOSE, h, 0,0,0,0);
    close(sock);
    if (!ok) { printf("FAIL no HTTP response\n"); g_fail = 1; }

    return g_fail ? 1 : 0;
}