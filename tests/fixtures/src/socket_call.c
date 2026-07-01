/*
 * socket_call.c — test PE that invokes raw Linux socket() syscall (NR 41)
 * to verify seccomp blocks the disallowed syscall with SIGSYS.
 *
 * Uses GCC inline assembly to issue the Linux x86-64 `syscall` instruction
 * directly. Since seccomp is applied to the entire child process before the
 * PE entry point runs, this triggers SECCOMP_RET_KILL_PROCESS → SIGSYS,
 * which terminates the child and breaks the IPC socketpair.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o socket_call.exe socket_call.c -lkernel32
 */

#include <windows.h>

int main(void) {
    long ret;
    __asm__ volatile(
        "mov $41, %%rax\n"   /* SYS_socket */
        "mov $2, %%rdi\n"    /* AF_INET */
        "mov $1, %%rsi\n"    /* SOCK_STREAM */
        "mov $0, %%rdx\n"    /* protocol */
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        :
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    ExitProcess(0);
}
