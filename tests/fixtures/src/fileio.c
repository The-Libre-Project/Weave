/*
 * fileio.c — Win32 file I/O test target for Weave testing.
 *
 * Creates a temp file, writes a string to it, reads it back, and prints
 * the contents to stdout. Tests a broader kernel32 surface than hello.c.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o fileio.exe fileio.c -lkernel32
 */

#include <windows.h>

int main(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Create a temp file */
    HANDLE hFile = CreateFileW(
        L"weave_test_tmp.txt",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        const wchar_t *err = L"CreateFileW failed\n";
        DWORD written = 0;
        WriteConsoleW(hOut, err, 19, &written, NULL);
        ExitProcess(1);
    }

    /* Write to it */
    const char *data = "Hello from fileio!\n";
    DWORD written = 0;
    WriteFile(hFile, data, 19, &written, NULL);

    /* Seek back to start */
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    /* Read it back */
    char buf[64] = {0};
    DWORD bytesRead = 0;
    ReadFile(hFile, buf, 63, &bytesRead, NULL);

    CloseHandle(hFile);

    /* Delete the temp file */
    DeleteFileW(L"weave_test_tmp.txt");

    /* Print what we read */
    DWORD wout = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, bytesRead, &wout, NULL);

    ExitProcess(0);
}
