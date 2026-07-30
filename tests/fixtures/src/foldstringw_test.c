/*
 * foldstringw_test.c — FoldStringW gate test for Weave.
 *
 * Uses no CRT and no standard library. Imports only from ntdll.dll
 * and kernel32.dll so the PE has no msvcrt segment initializers.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o tests/fixtures/bin/foldstringw_test.exe \
 *     tests/fixtures/src/foldstringw_test.c \
 *     -nostdlib -nostartfiles -lkernel32 \
 *     -Wl,--entry,entry
 */

/* ---------- minimal type definitions ---------- */

typedef unsigned short      wchar_t;
typedef unsigned short      USHORT;
typedef unsigned long       ULONG;
typedef long                LONG;
typedef unsigned long long  ULONG_PTR;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef LONG                NTSTATUS;
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef wchar_t*            LPWSTR;
typedef const wchar_t*      LPCWSTR;
typedef void*               LPVOID;
typedef const void*         LPCVOID;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define NULL           ((PVOID)0)
#define FALSE          0
#define TRUE           1
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

#define NORM_IGNORECASE 0x00000001
#define MAP_FOLDCZONE   0x00000010

/* IO_STATUS_BLOCK for NtWriteFile */
typedef struct {
    NTSTATUS  Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

/* ---------- NT API declarations — imported from ntdll.dll ---------- */

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, PVOID apc_routine, PVOID apc_ctx,
    IO_STATUS_BLOCK* iosb, LPVOID buffer, ULONG length,
    PVOID byte_offset, PVOID key);

__declspec(dllimport) NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_status);

/* ---------- Kernel32 API declarations — imported from kernel32.dll ---------- */

__declspec(dllimport) HANDLE GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) int    FoldStringW(DWORD dwMapFlags, LPCWSTR lpSrcStr,
                                          int cchSrc, LPWSTR lpDestStr, int cchDest);
__declspec(dllimport) BOOL   WriteFile(HANDLE hFile, LPCVOID lpBuffer,
                                        DWORD nNumberOfBytesToWrite,
                                        DWORD* lpNumberOfBytesWritten,
                                        LPVOID lpOverlapped);

/* ---------- helpers ---------- */

static HANDLE g_stdout;

static void write_str(const char* s) {
    DWORD len = 0;
    while (s[len]) len++;
    IO_STATUS_BLOCK iosb = {0};
    NtWriteFile(g_stdout, NULL, NULL, NULL, &iosb, (void*)s, len, NULL, NULL);
}

static void write_num(DWORD val) {
    char buf[16];
    int i = 15;
    buf[15] = '\0';
    if (val == 0) { buf[--i] = '0'; }
    while (val > 0 && i > 0) {
        buf[--i] = '0' + (val % 10);
        val /= 10;
    }
    IO_STATUS_BLOCK iosb = {0};
    NtWriteFile(g_stdout, NULL, NULL, NULL, &iosb, buf + i, 15 - i, NULL, NULL);
}

static void write_phase_pass(const char* label) {
    write_str("PHASE: "); write_str(label); write_str(" PASS\n");
}

static void write_phase_fail(const char* label) {
    write_str("PHASE: "); write_str(label); write_str(" FAIL\n");
}

/* ---------- test cases ---------- */

static int ret;
static wchar_t buf[256];

static int test_no_flags(void) {
    const wchar_t src[] = {'H','e','l','l','o',0};
    ret = FoldStringW(0, src, -1, buf, 256);
    if (ret != 5 || buf[0] != L'H' || buf[1] != L'e' || buf[2] != L'l'
        || buf[3] != L'l' || buf[4] != L'o') {
        write_phase_fail("A1_no_flags");
        return 0;
    }
    write_phase_pass("A1_no_flags");
    return 1;
}

static int test_norm_ignorecase_ascii(void) {
    const wchar_t src[] = {'H','E','L','L','O',0};
    ret = FoldStringW(NORM_IGNORECASE, src, -1, buf, 256);
    if (ret != 5 || buf[0] != L'h' || buf[1] != L'e' || buf[2] != L'l'
        || buf[3] != L'l' || buf[4] != L'o') {
        write_phase_fail("A2_NORM_IGNORECASE_ASCII");
        return 0;
    }
    write_phase_pass("A2_NORM_IGNORECASE_ASCII");
    return 1;
}

static int test_norm_ignorecase_unicode(void) {
    /* "ABCÄÜÖ" → "abcäüö" using explicit arrays to avoid UTF-8 source issues */
    const wchar_t src[]    = {'A','B','C',0xC4,0xDC,0xD6,0};
    const wchar_t expect[] = {'a','b','c',0xE4,0xFC,0xF6};
    ret = FoldStringW(NORM_IGNORECASE, src, -1, buf, 256);
    if (ret != 6) {
        write_phase_fail("A3_NORM_IGNORECASE_Unicode_len");
        return 0;
    }
    for (int i = 0; i < 6; i++) {
        if (buf[i] != expect[i]) {
            write_phase_fail("A3_NORM_IGNORECASE_Unicode_content");
            return 0;
        }
    }
    write_phase_pass("A3_NORM_IGNORECASE_Unicode");
    return 1;
}

static int test_map_foldczone(void) {
    const wchar_t src[] = {'H','E','L','L','O',0};
    wchar_t d[256];
    ret = FoldStringW(MAP_FOLDCZONE, src, -1, d, 256);
    if (ret != 5 || d[0] != L'h' || d[1] != L'e' || d[2] != L'l'
        || d[3] != L'l' || d[4] != L'o') {
        write_phase_fail("A4_MAP_FOLDCZONE");
        return 0;
    }
    write_phase_pass("A4_MAP_FOLDCZONE");
    return 1;
}

static int test_empty_src(void) {
    const wchar_t src[] = {0};
    ret = FoldStringW(NORM_IGNORECASE, src, -1, buf, 256);
    if (ret != 0) {
        write_phase_fail("A5a_empty_string");
        return 0;
    }
    write_phase_pass("A5a_empty_string");
    return 1;
}

static int test_cch_src_zero(void) {
    const wchar_t src[] = {'H','e','l','l','o',0};
    ret = FoldStringW(NORM_IGNORECASE, src, 0, buf, 256);
    if (ret != 0) {
        write_phase_fail("A5b_cch_src_zero");
        return 0;
    }
    write_phase_pass("A5b_cch_src_zero");
    return 1;
}

static int test_size_query(void) {
    const wchar_t src[] = {'H','e','l','l','o',0};
    ret = FoldStringW(NORM_IGNORECASE, src, -1, NULL, 0);
    if (ret != 5) {
        write_phase_fail("A5c_size_query");
        return 0;
    }
    write_phase_pass("A5c_size_query");
    return 1;
}

static int test_buffer_too_small(void) {
    const wchar_t src[] = {'H','e','l','l','o',0};
    wchar_t small_buf[2];
    ret = FoldStringW(NORM_IGNORECASE, src, -1, small_buf, 2);
    if (ret != 5) {
        write_phase_fail("A5d_buffer_too_small_ret");
        return 0;
    }
    if (small_buf[0] != L'h' || small_buf[1] != L'e') {
        write_phase_fail("A5d_buffer_too_small_content");
        return 0;
    }
    write_phase_pass("A5d_buffer_too_small");
    return 1;
}

/* ---------- entry point ---------- */

void entry(void) {
    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    int passed = 0, total = 0;

    total++; passed += test_no_flags();
    total++; passed += test_norm_ignorecase_ascii();
    total++; passed += test_norm_ignorecase_unicode();
    total++; passed += test_map_foldczone();
    total++; passed += test_empty_src();
    total++; passed += test_cch_src_zero();
    total++; passed += test_size_query();
    total++; passed += test_buffer_too_small();

    write_str("PHASE: foldstringw_gate ");
    write_num(passed); write_str("/"); write_num(total); write_str(" passed\n");

    if (passed == total) {
        write_str("PHASE: all_tests_passed\n");
        NtTerminateProcess(NULL, STATUS_SUCCESS);
    } else {
        NtTerminateProcess(NULL, (NTSTATUS)1);
    }
}
