// hello_minimal.c -- Phase 0 test target.
// Calls exactly two NT functions: NtWriteFile, NtTerminateProcess
// Uses a hardcoded stdout handle. No string literals, no stdlib.
// Compile:
//   x86_64-w64-mingw32-gcc -o hello_minimal.exe hello_minimal.c \
//     -nostdlib -nostartfiles -lntdll \
//     -Wl,--entry,entry

typedef unsigned long       ULONG;
typedef long                LONG;
typedef unsigned long long  ULONG_PTR;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef LONG                NTSTATUS;

#define STATUS_SUCCESS  ((NTSTATUS)0)

typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK;

NTSTATUS NtWriteFile(HANDLE file, HANDLE event, PVOID apc_routine,
                     PVOID apc_ctx, IO_STATUS_BLOCK* iosb,
                     PVOID buffer, ULONG length,
                     PVOID byte_offset, PVOID key);
NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_status);

void entry(void) {
    char buf[] = {72, 101, 108, 108, 111, 10};
    IO_STATUS_BLOCK iosb;
    NtWriteFile((HANDLE)(ULONG_PTR)7, 0, 0, 0, &iosb, buf, 6, 0, 0);
    NtTerminateProcess(0, STATUS_SUCCESS);
}
