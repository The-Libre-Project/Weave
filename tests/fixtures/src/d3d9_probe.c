#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define D3D_SDK_VERSION                    32
#define D3DDEVTYPE_HAL                     1
#define D3DCREATE_SOFTWARE_VERTEXPROCESSING 0x00000020L
#define D3DCLEAR_TARGET                    0x00000001L
#define D3D_OK                             0

/* Minimal D3DPRESENT_PARAMETERS — only the fields we set */
typedef struct {
    UINT  BackBufferWidth, BackBufferHeight;
    DWORD BackBufferFormat;
    UINT  BackBufferCount;
    DWORD MultiSampleType, MultiSampleQuality;
    DWORD SwapEffect;
    HWND  hDeviceWindow;
    BOOL  Windowed;
    BOOL  EnableAutoDepthStencil;
    DWORD AutoDepthStencilFormat, Flags;
    UINT  FullScreen_RefreshRateInHz, PresentationInterval;
} D3DPRESENT_PARAMETERS;

typedef void* (*PFN_Direct3DCreate9)(UINT);
typedef HRESULT (*PFN_CreateDevice)(void*, UINT, UINT, HWND, DWORD,
                                    D3DPRESENT_PARAMETERS*, void**);
typedef HRESULT (*PFN_Clear)(void*, DWORD, void*, DWORD, DWORD, float, DWORD);
typedef HRESULT (*PFN_Present)(void*, void*, void*, HWND, void*);

static void* vtfn(void* obj, int slot) {
    return (*(void***)obj)[slot];
}

static LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    return DefWindowProcA(h, m, w, l);
}

int main(void) {
    fprintf(stderr, "d3d9_probe: STEP 1 GetModuleHandleA\n");
    /* 1. Register window class and create an 320x240 window */
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = GetModuleHandleA(NULL);
    fprintf(stderr, "d3d9_probe: STEP 2 RegisterClassA hInstance=%p\n", (void*)wc.hInstance);
    wc.lpszClassName = "d3d9_probe_class";
    if (!RegisterClassA(&wc)) {
        fprintf(stderr, "d3d9_probe: RegisterClassA failed\n"); return 1;
    }
    fprintf(stderr, "d3d9_probe: STEP 3 CreateWindowExA\n");
    HWND hwnd = CreateWindowExA(0, "d3d9_probe_class", "d3d9_probe",
                                WS_POPUP | WS_VISIBLE, 0, 0, 320, 240,
                                NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) {
        fprintf(stderr, "d3d9_probe: CreateWindowExA failed\n"); return 2;
    }
    /* Ensure the X11 window is mapped before DXVK creates a Vulkan surface
       on it.  Weave's user32 only maps when WS_VISIBLE is set on the style. */
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    fprintf(stderr, "d3d9_probe: STEP 4 LoadLibraryA hwnd=%p\n", (void*)hwnd);

    /* 2. Load d3d9.dll and get Direct3DCreate9 */
    HMODULE hd3d9 = LoadLibraryA("d3d9.dll");
    if (!hd3d9) {
        fprintf(stderr, "d3d9_probe: LoadLibraryA(d3d9.dll) failed\n"); return 3;
    }
    fprintf(stderr, "d3d9_probe: STEP 5 GetProcAddress\n");
    PFN_Direct3DCreate9 pCreate9 =
        (PFN_Direct3DCreate9)GetProcAddress(hd3d9, "Direct3DCreate9");
    if (!pCreate9) {
        fprintf(stderr, "d3d9_probe: GetProcAddress(Direct3DCreate9) failed\n"); return 4;
    }

    fprintf(stderr, "d3d9_probe: STEP 6 Direct3DCreate9\n");
    /* 3. Create IDirect3D9 */
    void* d3d9 = pCreate9(D3D_SDK_VERSION);
    if (!d3d9) {
        fprintf(stderr, "d3d9_probe: Direct3DCreate9 returned NULL\n"); return 5;
    }
    fprintf(stderr, "d3d9_probe: STEP 7 CreateDevice d3d9=%p\n", d3d9);

    /* 4. Create device */
    D3DPRESENT_PARAMETERS pp = {0};
    pp.BackBufferWidth  = 320;
    pp.BackBufferHeight = 240;
    pp.BackBufferFormat = 0;
    pp.BackBufferCount  = 1;
    pp.SwapEffect       = 1;
    pp.hDeviceWindow    = hwnd;
    pp.Windowed         = TRUE;

    void* dev = NULL;
    PFN_CreateDevice pCreateDevice = (PFN_CreateDevice)vtfn(d3d9, 16);
    HRESULT hr = pCreateDevice(d3d9, 0, D3DDEVTYPE_HAL, hwnd,
                               D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (hr != D3D_OK || !dev) {
        fprintf(stderr, "d3d9_probe: CreateDevice failed hr=0x%08lx\n", hr); return 6;
    }
    fprintf(stderr, "d3d9_probe: STEP 8 Clear dev=%p\n", dev);

    /* 5. Clear to solid red 0xFFFF0000 */
    PFN_Clear pClear = (PFN_Clear)vtfn(dev, 43);
    hr = pClear(dev, 0, NULL, D3DCLEAR_TARGET, 0xFFFF0000, 1.0f, 0);
    if (hr != D3D_OK) {
        fprintf(stderr, "d3d9_probe: Clear failed hr=0x%08lx\n", hr); return 7;
    }
    fprintf(stderr, "d3d9_probe: STEP 9 Present\n");

    /* 6. Present */
    PFN_Present pPresent = (PFN_Present)vtfn(dev, 17);
    hr = pPresent(dev, NULL, NULL, NULL, NULL);
    if (hr != D3D_OK) {
        fprintf(stderr, "d3d9_probe: Present failed hr=0x%08lx\n", hr); return 8;
    }

    fprintf(stderr, "d3d9_probe: STEP 10 done\n");
    printf("d3d9_probe OK\n");

    /* Hold the window long enough for the gate's pixel sampler (which fires
       at the 20s mark of the 60s deadline) to read red back from the X
       server.  Without this the probe exits in ~400ms and the surface is
       destroyed before any sample is taken. */
    fflush(stderr);
    fflush(stdout);
    Sleep(25000);
    return 0;
}
