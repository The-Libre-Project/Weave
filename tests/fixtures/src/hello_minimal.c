/*
 * hello_minimal.c — Phase 0 test target.
 *
 * Calls exactly three NT functions — the ones Weave must implement for Phase 0:
 *   - RtlInitUnicodeString  (set up a text string in Windows format)
 *   - NtWriteFile           (write bytes to stdout)
 *   - NtTerminateProcess    (exit the process)
 *
 * No CRT. No standard library. Imports only ntdll.dll.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o hello_minimal.exe hello_minimal.c \
 *     -nostdlib -nostartfiles -lntdll \
 *     -Wl,--entry,entry
 */

/* ---------- minimal type definitions (no headers available without CRT) ---------- */

typedef unsigned short      USHORT;
typedef unsigned long       ULONG;
typedef long                LONG;
typedef unsigned long long  ULONG_PTR;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef LONG                NTSTATUS;

#define STATUS_SUCCESS  ((NTSTATUS)0)
#define NULL            ((PVOID)0)

/* Windows "unicode string" struct — used by RtlInitUnicodeString */
typedef struct {
    USHORT  Length;         /* byte length of string, NOT including null terminator */
    USHORT  MaximumLength;  /* byte length of buffer */
    USHORT* Buffer;         /* UTF-16 character data */
} UNICODE_STRING;

/* NT I/O status block — NtWriteFile writes its result here */
typedef struct {
    NTSTATUS  Status;
    ULONG_PTR Information;  /* bytes written on success */
} IO_STATUS_BLOCK;

/* ---------- NT API declarations — imported from ntdll.dll ---------- */

__declspec(dllimport) void     RtlInitUnicodeString(UNICODE_STRING* dest, const USHORT* src);
__declspec(dllimport) NTSTATUS NtWriteFile(HANDLE file, HANDLE event, PVOID apc_routine,
                                            PVOID apc_ctx, IO_STATUS_BLOCK* iosb,
                                            PVOID buffer, ULONG length,
                                            PVOID byte_offset, PVOID key);
__declspec(dllimport) NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_status);

/* ---------- get the stdout handle ----------
 *
 * GetStdHandle(STD_OUTPUT_HANDLE) is the canonical way to get the stdout handle.
 * We import it from kernel32 since building with -nostdlib means no <windows.h>.
 */
__declspec(dllimport) HANDLE __stdcall GetStdHandle(unsigned long n_std_handle);
#define STD_OUTPUT_HANDLE ((unsigned long)-11)

static HANDLE get_stdout(void) {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

/* ---------- entry point ---------- */

void entry(void) {
    /*
     * 1. RtlInitUnicodeString — wire up the API.
     *    Builds a UNICODE_STRING describing a label. We don't print this;
     *    we just need to call the function so Weave has to implement it.
     */
    UNICODE_STRING label;
    RtlInitUnicodeString(&label, L"weave");

    /*
     * 2. NtWriteFile — write "Hello, World!\n" to stdout.
     *    We write raw bytes (ASCII). Weave maps this to Linux write().
     */
    IO_STATUS_BLOCK iosb = {0};
    char msg[] = "Hello, World!\n";
    NtWriteFile(get_stdout(), NULL, NULL, NULL, &iosb,
                msg, sizeof(msg) - 1,  /* length excludes null terminator */
                NULL, NULL);

    /*
     * 3. NtTerminateProcess — exit cleanly.
     *    NULL for the process handle means "current process" in NT semantics.
     */
    NtTerminateProcess(NULL, STATUS_SUCCESS);
}
