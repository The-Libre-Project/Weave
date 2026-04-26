#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE h = LoadLibraryA("vulkan-1.dll");
    if (!h) {
        fprintf(stderr, "vulkan_probe: LoadLibraryA(\"vulkan-1.dll\") returned NULL\n");
        return 1;
    }

    typedef int (*PFN_vkEnumerateInstanceExtensionProperties)(
        const char *pLayerName, unsigned int *pPropertyCount, void *pProperties);

    PFN_vkEnumerateInstanceExtensionProperties fn =
        (PFN_vkEnumerateInstanceExtensionProperties)
        GetProcAddress(h, "vkEnumerateInstanceExtensionProperties");
    if (!fn) {
        fprintf(stderr, "vulkan_probe: GetProcAddress(\"vkEnumerateInstanceExtensionProperties\") returned NULL\n");
        return 2;
    }

    unsigned int count = 0;
    int result = fn(NULL, &count, NULL);
    if (result != 0) {
        fprintf(stderr, "vulkan_probe: vkEnumerateInstanceExtensionProperties returned %d (expected 0 = VK_SUCCESS)\n", result);
        return 3;
    }

    printf("vulkan OK: %u extensions\n", count);
    return 0;
}
