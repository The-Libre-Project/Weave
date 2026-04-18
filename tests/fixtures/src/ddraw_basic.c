/*
 * ddraw_basic.c — Minimal DirectDraw Lock/Blt/Verify gate fixture for Weave.
 *
 * Task 04 gate. Exercises the full Lock -> write -> Unlock -> Blt COLORFILL ->
 * Lock -> readback path through weave-ddraw's dispatch-3 implementation.
 *
 * Pipeline:
 *   DirectDrawCreate           -> PHASE: ddraw_created
 *   SetCooperativeLevel        -> PHASE: coop_set
 *   CreateSurface (offscreen)  -> PHASE: surface_created
 *   Lock + write pattern       -> PHASE: locked / PHASE: pixels_written
 *   Unlock                     -> (no phase)
 *   Blt DDBLT_COLORFILL        -> PHASE: blt_colorfill
 *   Lock READONLY + readback   -> PHASE: blt_verified  (exit 0)
 *                              or PHASE: blt_mismatch  (exit 2)
 *
 * The C side treats the LPDIRECTDRAW returned by DirectDrawCreate as an
 * LPDIRECTDRAW4 — weave-ddraw's DirectDrawCreate returns an IDirectDraw4
 * vtbl directly (weave-ddraw/src/lib.rs::DirectDrawCreate). This avoids a
 * QueryInterface hop (weave-ddraw's dd_QueryInterface returns E_NOINTERFACE).
 *
 * Byte-order contract: weave-ddraw's do_blt writes
 *   dst_row[off..off+4].copy_from_slice(&color.to_le_bytes());
 * so a caller-visible DWORD lpSurface[0] equals dwFillColor exactly on
 * little-endian x86-64. We verify with a native u32 compare.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o ddraw_basic.exe ddraw_basic.c \
 *     -lkernel32 -luser32 -lddraw
 */

#include <windows.h>
#include <ddraw.h>

/* WriteFile+GetStdHandle logging — MinGW static CRT printf is unsafe under
 * Weave's ucrt stubs (see CLAUDE.md gotchas). Every log path below uses
 * WriteFile on STD_ERROR_HANDLE directly. */
#define LOG(msg) do { \
    DWORD _w; \
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), msg "\n", \
              (DWORD)(sizeof(msg)), &_w, NULL); \
} while (0)

static void log_hex2(const char *label, DWORD expected, DWORD actual)
{
    /* "PHASE: blt_mismatch expected=%08X actual=%08X\n" rendered by hand
     * because printf is off limits (see LOG note above). */
    char buf[128];
    const char *hex = "0123456789ABCDEF";
    int i = 0;
    while (label[i] && i < 80) { buf[i] = label[i]; i++; }
    buf[i++] = ' '; buf[i++] = 'e'; buf[i++] = 'x'; buf[i++] = 'p'; buf[i++] = '=';
    buf[i++] = '0'; buf[i++] = 'x';
    for (int s = 28; s >= 0; s -= 4) buf[i++] = hex[(expected >> s) & 0xF];
    buf[i++] = ' '; buf[i++] = 'a'; buf[i++] = 'c'; buf[i++] = 't'; buf[i++] = '=';
    buf[i++] = '0'; buf[i++] = 'x';
    for (int s = 28; s >= 0; s -= 4) buf[i++] = hex[(actual >> s) & 0xF];
    buf[i++] = '\n';
    DWORD _w;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)i, &_w, NULL);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    LOG("ddraw_basic: start");

    /* -- 1. DirectDrawCreate ---------------------------------------------- */
    LPDIRECTDRAW pDD1 = NULL;
    HRESULT hr = DirectDrawCreate(NULL, &pDD1, NULL);
    if (FAILED(hr) || pDD1 == NULL) {
        LOG("ddraw_basic: DirectDrawCreate failed");
        ExitProcess(10);
    }
    /* weave-ddraw returns an IDirectDraw4 vtbl directly from DirectDrawCreate
     * (weave-ddraw/src/lib.rs:1281 — DirectDrawCreate -> FakeDirectDraw4::new_boxed).
     * v1 and v4 vtables share the first 25 slots for QI/AddRef/Release/
     * Compact..WaitForVerticalBlank — see mingw-w64 ddraw.h:1385 (IDirectDraw)
     * and :1688 (IDirectDraw4). Cast the pointer so we can call the v4
     * IDirectDraw4_* macros that accept DDSURFACEDESC2. */
    LPDIRECTDRAW4 pDD = (LPDIRECTDRAW4)pDD1;
    LOG("PHASE: ddraw_created");

    /* -- 2. SetCooperativeLevel ------------------------------------------- */
    /* HWND=NULL is accepted by weave-ddraw's dd_SetCooperativeLevel (it stores
     * hwnd/flags as AtomicU* and returns DD_OK — see weave-ddraw/src/lib.rs
     * :1169). DDSCL_NORMAL (mingw-w64 ddraw.h:968 — 0x00000008). */
    hr = IDirectDraw4_SetCooperativeLevel(pDD, NULL, DDSCL_NORMAL);
    if (FAILED(hr)) {
        LOG("ddraw_basic: SetCooperativeLevel failed");
        ExitProcess(11);
    }
    LOG("PHASE: coop_set");

    /* -- 3. CreateSurface (offscreen 640x480x32bpp) ----------------------- */
    DDSURFACEDESC2 ddsd;
    ZeroMemory(&ddsd, sizeof(ddsd));
    ddsd.dwSize         = sizeof(DDSURFACEDESC2);
    ddsd.dwFlags        = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.dwWidth        = 640;
    ddsd.dwHeight       = 480;
    /* DDSCAPS_OFFSCREENPLAIN — mingw-w64 ddraw.h:281 (0x00000040). No primary
     * surface needed for a Lock/Blt-only verification. weave-ddraw's
     * dd_CreateSurface respects DDSD_WIDTH|DDSD_HEIGHT and always allocates a
     * 32bpp BGRA buffer (weave-ddraw/src/lib.rs:1080-1090). */
    ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;

    LPDIRECTDRAWSURFACE4 pSurf = NULL;
    hr = IDirectDraw4_CreateSurface(pDD, &ddsd, &pSurf, NULL);
    if (FAILED(hr) || pSurf == NULL) {
        LOG("ddraw_basic: CreateSurface failed");
        ExitProcess(12);
    }
    LOG("PHASE: surface_created");

    /* -- 4. Lock + write known pattern ------------------------------------ */
    DDSURFACEDESC2 lockDesc;
    ZeroMemory(&lockDesc, sizeof(lockDesc));
    lockDesc.dwSize = sizeof(DDSURFACEDESC2);
    hr = IDirectDrawSurface4_Lock(pSurf, NULL, &lockDesc,
                                  DDLOCK_WRITEONLY | DDLOCK_WAIT, NULL);
    if (FAILED(hr) || lockDesc.lpSurface == NULL || lockDesc.lPitch <= 0) {
        LOG("ddraw_basic: Lock (write) failed or returned null lpSurface");
        ExitProcess(13);
    }
    LOG("PHASE: locked");

    /* Paint a deterministic marker so we can tell Lock wrote valid fields.
     * The Blt COLORFILL below overwrites the whole surface, so this pattern
     * is strictly a sanity check on the Lock path. */
    {
        DWORD *row0 = (DWORD *)lockDesc.lpSurface;
        row0[0] = 0xCAFEBABEu;
        DWORD *row10 = (DWORD *)((BYTE *)lockDesc.lpSurface + 10 * lockDesc.lPitch);
        row10[10] = 0xDEADBEEFu;
    }
    LOG("PHASE: pixels_written");

    hr = IDirectDrawSurface4_Unlock(pSurf, NULL);
    if (FAILED(hr)) {
        LOG("ddraw_basic: Unlock after write failed");
        ExitProcess(14);
    }

    /* -- 5. Blt DDBLT_COLORFILL ------------------------------------------- */
    DDBLTFX bltfx;
    ZeroMemory(&bltfx, sizeof(bltfx));
    bltfx.dwSize        = sizeof(DDBLTFX);
    /* Sentinel 0xAABBCCDD. weave-ddraw writes via &color.to_le_bytes() so the
     * memory becomes [DD CC BB AA] and a native u32 read on x86-64
     * little-endian yields 0xAABBCCDD exactly (weave-ddraw/src/lib.rs:460). */
    const DWORD kFill = 0xAABBCCDDu;
    bltfx.dwFillColor   = kFill;

    hr = IDirectDrawSurface4_Blt(pSurf, NULL, NULL, NULL,
                                 DDBLT_COLORFILL | DDBLT_WAIT, &bltfx);
    if (FAILED(hr)) {
        LOG("ddraw_basic: Blt COLORFILL failed");
        ExitProcess(15);
    }
    LOG("PHASE: blt_colorfill");

    /* -- 6. Lock (read) + verify ------------------------------------------ */
    DDSURFACEDESC2 readDesc;
    ZeroMemory(&readDesc, sizeof(readDesc));
    readDesc.dwSize = sizeof(DDSURFACEDESC2);
    hr = IDirectDrawSurface4_Lock(pSurf, NULL, &readDesc,
                                  DDLOCK_READONLY | DDLOCK_WAIT, NULL);
    if (FAILED(hr) || readDesc.lpSurface == NULL || readDesc.lPitch <= 0) {
        LOG("ddraw_basic: Lock (read) failed or returned null lpSurface");
        ExitProcess(16);
    }

    DWORD px0 = ((DWORD *)readDesc.lpSurface)[0];
    DWORD pxMid = ((DWORD *)((BYTE *)readDesc.lpSurface + 240 * readDesc.lPitch))[320];

    /* Unlock regardless of verdict so we don't leave the surface locked. */
    IDirectDrawSurface4_Unlock(pSurf, NULL);

    if (px0 != kFill || pxMid != kFill) {
        log_hex2("PHASE: blt_mismatch[0,0]", kFill, px0);
        log_hex2("PHASE: blt_mismatch[320,240]", kFill, pxMid);
        IDirectDrawSurface4_Release(pSurf);
        IDirectDraw4_Release(pDD);
        ExitProcess(2);
    }

    LOG("PHASE: blt_verified");

    /* -- 7. Cleanup ------------------------------------------------------- */
    IDirectDrawSurface4_Release(pSurf);
    IDirectDraw4_Release(pDD);
    ExitProcess(0);
    return 0; /* unreachable */
}
