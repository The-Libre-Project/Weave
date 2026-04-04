/*
 * registry_basic.c — Win32 registry read test for Weave.
 *
 * Opens HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion,
 * queries "CurrentVersion", and prints it to stdout.
 * Also tests RegCreateKeyExW + RegSetValueExW round-trip.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o registry_basic.exe registry_basic.c -ladvapi32 -lkernel32
 */

#include <windows.h>
#include <stdio.h>

static void print(const char *s) {
    DWORD w;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)strlen(s), &w, NULL);
}

int main(void)
{
    /* ── Read a pre-populated key ──────────────────────────────────────────── */
    HKEY hKey = NULL;
    LONG ret = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey
    );

    if (ret != ERROR_SUCCESS) {
        print("registry_basic: RegOpenKeyExW failed\n");
        ExitProcess(1);
    }

    wchar_t buf[128] = {0};
    DWORD bufSize = sizeof(buf);
    DWORD regType = 0;
    ret = RegQueryValueExW(hKey, L"CurrentVersion", NULL, &regType, (LPBYTE)buf, &bufSize);

    if (ret != ERROR_SUCCESS) {
        print("registry_basic: RegQueryValueExW failed\n");
        RegCloseKey(hKey);
        ExitProcess(1);
    }

    /* Convert wide to narrow for printing */
    char narrow[128] = {0};
    WideCharToMultiByte(CP_ACP, 0, buf, -1, narrow, sizeof(narrow), NULL, NULL);
    print("CurrentVersion: ");
    print(narrow);
    print("\n");

    RegCloseKey(hKey);

    /* ── Write and read back a custom value ───────────────────────────────── */
    HKEY hTestKey = NULL;
    DWORD disposition = 0;
    ret = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\WeaveSmokeTest",
        0, NULL, 0, KEY_ALL_ACCESS, NULL,
        &hTestKey, &disposition
    );

    if (ret != ERROR_SUCCESS) {
        print("registry_basic: RegCreateKeyExW failed\n");
        ExitProcess(1);
    }

    const wchar_t *testVal = L"hello_weave";
    ret = RegSetValueExW(
        hTestKey, L"TestValue", 0, REG_SZ,
        (const BYTE *)testVal,
        (DWORD)((wcslen(testVal) + 1) * sizeof(wchar_t))
    );

    if (ret != ERROR_SUCCESS) {
        print("registry_basic: RegSetValueExW failed\n");
        RegCloseKey(hTestKey);
        ExitProcess(1);
    }

    /* Read it back */
    wchar_t readBuf[64] = {0};
    DWORD readSize = sizeof(readBuf);
    ret = RegQueryValueExW(hTestKey, L"TestValue", NULL, NULL, (LPBYTE)readBuf, &readSize);

    if (ret != ERROR_SUCCESS) {
        print("registry_basic: round-trip RegQueryValueExW failed\n");
        RegCloseKey(hTestKey);
        ExitProcess(1);
    }

    char narrow2[64] = {0};
    WideCharToMultiByte(CP_ACP, 0, readBuf, -1, narrow2, sizeof(narrow2), NULL, NULL);
    print("TestValue: ");
    print(narrow2);
    print("\n");

    RegCloseKey(hTestKey);

    print("registry_basic: all checks passed\n");
    ExitProcess(0);
}
