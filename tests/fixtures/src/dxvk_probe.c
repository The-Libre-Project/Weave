#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE h = LoadLibraryA("d3d9.dll");
    if (!h) {
        fprintf(stderr, "dxvk_probe: LoadLibraryA(\"d3d9.dll\") returned NULL\n");
        return 1;
    }

    FARPROC fn = GetProcAddress(h, "Direct3DCreate9");
    if (!fn) {
        fprintf(stderr, "dxvk_probe: GetProcAddress(\"Direct3DCreate9\") returned NULL\n");
        return 2;
    }

    printf("dxvk OK: Direct3DCreate9 at %p\n", (void*)fn);
    return 0;
}
