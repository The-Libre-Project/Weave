/*
 * wget_probe.c — Task 01b contingency closure target.
 *
 * Minimal MinGW HTTP/1.0 GET to http://example.com. Same wire pattern as
 * ws2_probe.c (socket → connect → send → recv → close) but routed through
 * CRT stdio (fwrite, fprintf) instead of raw WriteFile — this exercises the
 * msvcrt FILE* / __acrt_iob_func path that wget depends on, without pulling
 * wget's full CRT startup (getaddrinfo-in-thread, gnulib wakeup-pair,
 * OpenSSL, locale init, signal handlers, etc).
 *
 * Rationale: if Task 01b dispatch 3c-K closes wget_ws2_gate end-to-end, this
 * probe is shelved. If wget continues to expose further CRT/ws2 gaps beyond
 * reasonable scope, this probe becomes the Task 01b closure target — it
 * demonstrates "MinGW + ws2 + CRT stdio HTTP GET" works under Weave with a
 * deterministic, tight import surface.
 *
 * Compile (from macOS host with mingw-w64):
 *   x86_64-w64-mingw32-gcc -O2 -o wget_probe.exe wget_probe.c -lws2_32
 *
 * Exit: 0 on successful send+recv. Non-zero on WSA / CRT failure.
 * Success signal: stdout contains "Example Domain".
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "wget_probe: WSAStartup failed\n");
        return 1;
    }

    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo("example.com", "80", &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "wget_probe: getaddrinfo failed\n");
        WSACleanup();
        return 2;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "wget_probe: socket() failed\n");
        freeaddrinfo(res);
        WSACleanup();
        return 3;
    }

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        fprintf(stderr, "wget_probe: connect() failed err=%d\n", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(res);
        WSACleanup();
        return 4;
    }
    freeaddrinfo(res);

    static const char req[] =
        "GET / HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "User-Agent: weave-wget-probe/1\r\n"
        "Connection: close\r\n"
        "\r\n";
    const int req_len = (int)(sizeof(req) - 1);

    int sent = 0;
    while (sent < req_len) {
        int n = send(s, req + sent, req_len - sent, 0);
        if (n <= 0) {
            fprintf(stderr, "wget_probe: send() failed err=%d\n", WSAGetLastError());
            closesocket(s);
            WSACleanup();
            return 5;
        }
        sent += n;
    }

    char buf[4096];
    int total = 0;
    while (total < 32 * 1024) {
        int n = recv(s, buf, sizeof(buf) - 1, 0);
        if (n == 0) break;
        if (n == SOCKET_ERROR) {
            fprintf(stderr, "wget_probe: recv() failed err=%d\n", WSAGetLastError());
            closesocket(s);
            WSACleanup();
            return 6;
        }
        fwrite(buf, 1, (size_t)n, stdout);
        total += n;
    }
    fflush(stdout);

    closesocket(s);
    WSACleanup();
    return 0;
}
