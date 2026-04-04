/*
 * hello.c — minimal Win32 console app for Weave testing.
 *
 * Uses WriteConsoleW via GetStdHandle to print "Hello, World!" and exits.
 * This is the primary test target for Phase 0 / Phase 1 PE loader work.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o hello.exe hello.c -lkernel32
 */

#include <windows.h>

int main(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const wchar_t *msg = L"Hello, World!\n";
    DWORD written = 0;
    WriteConsoleW(hOut, msg, 14, &written, NULL);
    ExitProcess(0);
}
