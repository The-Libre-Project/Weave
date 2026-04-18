/*
 * ws2_probe.c — Task 01 second-app network validation target.
 *
 * Minimal blocking TCP client. Does exactly:
 *   WSAStartup → socket → connect → send → recv (until EOF or buffer full) → close.
 *
 * Target: http://example.com (93.184.216.34:80). Issues a minimal HTTP/1.0 GET
 * and writes whatever the server returns to stdout. The test asserts stdout
 * contains "Example Domain" — same success signal as curl_ws2_gate and the
 * pivoted wget_ws2_gate, but with a deterministic, tight import surface:
 * only ws2_32, kernel32, and msvcrt (minimal CRT calls — GetStdHandle +
 * WriteFile rather than fprintf).
 *
 * Meaningfully different from plink (M3 gate): plink uses WSAEventSelect /
 * WFMO / edge-triggered POLLOUT tracking; this probe uses blocking connect +
 * blocking recv loop. Validates that the ws2 path works when nobody registers
 * an event handle.
 *
 * Compile (from macOS host with mingw-w64):
 *   x86_64-w64-mingw32-gcc -O2 -o ws2_probe.exe ws2_probe.c -lws2_32
 *
 * Exit: 0 on successful send+recv (may be 0 bytes if peer closes immediately;
 * test checks stdout content, not byte count). Non-zero on WSA failure.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

static void write_stdout(const char *buf, DWORD len) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(h, buf, len, &written, NULL);
}

static void write_stderr_cstr(const char *s) {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD len = 0;
    while (s[len]) len++;
    DWORD written = 0;
    WriteFile(h, s, len, &written, NULL);
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        write_stderr_cstr("ws2_probe: WSAStartup failed\n");
        return 1;
    }

    /* example.com — use getaddrinfo so we exercise DNS too. */
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo("example.com", "80", &hints, &res) != 0 || res == NULL) {
        write_stderr_cstr("ws2_probe: getaddrinfo failed\n");
        WSACleanup();
        return 2;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        write_stderr_cstr("ws2_probe: socket() failed\n");
        freeaddrinfo(res);
        WSACleanup();
        return 3;
    }

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        write_stderr_cstr("ws2_probe: connect() failed\n");
        closesocket(s);
        freeaddrinfo(res);
        WSACleanup();
        return 4;
    }
    freeaddrinfo(res);

    static const char req[] =
        "GET / HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "User-Agent: weave-ws2-probe/1\r\n"
        "Connection: close\r\n"
        "\r\n";
    const int req_len = (int)(sizeof(req) - 1);

    int sent = 0;
    while (sent < req_len) {
        int n = send(s, req + sent, req_len - sent, 0);
        if (n <= 0) {
            write_stderr_cstr("ws2_probe: send() failed\n");
            closesocket(s);
            WSACleanup();
            return 5;
        }
        sent += n;
    }

    /* Drain response. Cap at 32 KB so we can't spin forever on a slow peer. */
    char buf[4096];
    int total = 0;
    while (total < 32 * 1024) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n == 0) break;          /* peer closed */
        if (n == SOCKET_ERROR) {
            write_stderr_cstr("ws2_probe: recv() failed\n");
            closesocket(s);
            WSACleanup();
            return 6;
        }
        write_stdout(buf, (DWORD)n);
        total += n;
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
