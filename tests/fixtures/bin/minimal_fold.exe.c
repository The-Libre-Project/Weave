#include <windows.h>
int main(void) {
    wchar_t buf[256];
    DWORD written;
    const char *msg;
    /* Test A1: no flags */
    int ret = FoldStringW(0, L" Hello\,