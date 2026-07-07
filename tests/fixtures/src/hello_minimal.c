// hello_minimal.c -- Phase 0 test target.
// Calls exactly three NT functions:
//   RtlInitUnicodeString, NtWriteFile (to a hardcoded handle), NtTerminateProcess
// Compile:
//   x86_64-w64-mingw32-gcc -o hello_minimal.exe hello_minimal.c \
//     -nostdlib -nostartfiles -lntdll \
//     -Wl,--entry,entry

typedef unsigned short      USHORT;
typedef unsigned long       ULONG;
typedef long                LONG;
typedef unsigned long long  ULONG_PTR;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef LONG                NTSTATUS;

#define STATUS_SUCCESS  ((NTSTATUS)0)
#define NULL            ((PVOID)0)

typedef struct { USHORT Length, MaximumLength; USHORT* Buffer; } UNICODE_STRING;
typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK;

void     RtlInitUnicodeString(UNICODE_STRING* dest, const USHORT* src);
NTSTATUS NtWriteFile(HANDLE file, HANDLE event, PVOID apc_routine,
                     PVOID apc_ctx, IO_STATUS_BLOCK* iosb,
                     PVOID buffer, ULONG length,
                     PVOID byte_offset, PVOID key);
NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_status);

// Use a known-good stdout handle. On Windows the first console handle
// assigned by the OS is typically 0x7; Weave assigns handles sequentially.
static HANDLE get_stdout(void) { return (HANDLE)(ULONG_PTR)7; }

void entry(void) {
    UNICODE_STRING label;
    RtlInitUnicodeString(&label, L"weave");

    IO_STATUS_BLOCK iosb;
    char msg[] = "Hello, World!\n";
    NtWriteFile(get_stdout(), NULL, NULL, NULL, &iosb,
                msg, sizeof(msg) - 1, NULL, NULL);

    NtTerminateProcess(NULL, STATUS_SUCCESS);
}
