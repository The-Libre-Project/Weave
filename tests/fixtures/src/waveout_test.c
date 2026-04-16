/*
 * waveout_test.c — Minimal Win32 waveOut + GUI test for Weave.
 *
 * Creates a blue-filled window, opens a waveOut device, prepares and writes
 * a 1-second silence PCM buffer, runs a message loop for 5 seconds, then
 * cleans up and exits. All PHASE markers are written to stderr so they appear
 * in cargo test --nocapture output.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o waveout_test.exe waveout_test.c \
 *     -lkernel32 -luser32 -lgdi32 -lwinmm
 */

#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>

/* 1 second of stereo 16-bit 44100 Hz silence */
#define PCM_SAMPLES   44100
#define PCM_CHANNELS  2
#define PCM_BITS      16
#define PCM_BUF_BYTES (PCM_SAMPLES * PCM_CHANNELS * (PCM_BITS / 8))

static HWAVEOUT   g_hWaveOut  = NULL;
static WAVEHDR    g_waveHdr;
static char       g_pcmBuf[PCM_BUF_BYTES]; /* zero-initialised = silence */
static DWORD      g_startTick = 0;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        /* Fill background solid blue — pixel-check target for Gate 2 */
        RECT rc = {0, 0, 640, 480};
        HBRUSH blue = CreateSolidBrush(RGB(0, 0, 255));
        FillRect(hdc, &rc, blue);
        DeleteObject(blue);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_TIMER: {
        /* 5-second run timer — post quit to end the message loop */
        DWORD elapsed = GetTickCount() - g_startTick;
        if (elapsed >= 5000) {
            PostQuitMessage(0);
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd;

    /* --- Window setup ---------------------------------------------------- */
    WNDCLASSW wc    = {0};
    wc.lpfnWndProc  = WndProc;
    wc.hInstance    = hInst;
    wc.lpszClassName = L"WaveoutTest";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassW(&wc)) {
        fprintf(stderr, "waveout_test: RegisterClassW failed\n");
        ExitProcess(1);
    }

    HWND hwnd = CreateWindowExW(
        0, L"WaveoutTest", L"Weave waveOut Test",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        NULL, NULL, hInst, NULL
    );

    if (!hwnd) {
        fprintf(stderr, "waveout_test: CreateWindowExW failed\n");
        ExitProcess(1);
    }

    ShowWindow(hwnd, nShow ? nShow : SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    /* --- waveOut ---------------------------------------------------------- */
    WAVEFORMATEX wfx;
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = PCM_CHANNELS;
    wfx.nSamplesPerSec  = PCM_SAMPLES;
    wfx.wBitsPerSample  = PCM_BITS;
    wfx.nBlockAlign     = (wfx.nChannels * wfx.wBitsPerSample) / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize          = 0;

    MMRESULT rc = waveOutOpen(
        &g_hWaveOut,
        WAVE_MAPPER,
        &wfx,
        0,       /* dwCallback */
        0,       /* dwCallbackInstance */
        CALLBACK_NULL
    );

    if (rc == MMSYSERR_NOERROR) {
        fprintf(stderr, "PHASE: waveout_opened\n");

        /* Prepare a 1-second silence buffer */
        ZeroMemory(&g_waveHdr, sizeof(g_waveHdr));
        g_waveHdr.lpData         = g_pcmBuf;
        g_waveHdr.dwBufferLength = PCM_BUF_BYTES;

        rc = waveOutPrepareHeader(g_hWaveOut, &g_waveHdr, sizeof(WAVEHDR));
        if (rc == MMSYSERR_NOERROR) {
            rc = waveOutWrite(g_hWaveOut, &g_waveHdr, sizeof(WAVEHDR));
            if (rc == MMSYSERR_NOERROR) {
                fprintf(stderr, "PHASE: waveout_wrote\n");
            } else {
                fprintf(stderr, "waveout_test: waveOutWrite returned %u\n", rc);
            }
        } else {
            fprintf(stderr, "waveout_test: waveOutPrepareHeader returned %u\n", rc);
        }
    } else {
        fprintf(stderr, "waveout_test: waveOutOpen returned %u (not MMSYSERR_NOERROR)\n", rc);
    }

    /* --- Message loop (5 seconds, PeekMessage-based to avoid WM_TIMER dependency) --- */
    g_startTick = GetTickCount();
    DWORD deadline = GetTickCount() + 5000;
    MSG m;
    while (GetTickCount() < deadline) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            if (m.message == WM_QUIT) goto cleanup;
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        Sleep(10);  /* yield to avoid CPU spin */
    }
cleanup:

    /* --- Cleanup ---------------------------------------------------------- */
    if (g_hWaveOut) {
        waveOutReset(g_hWaveOut);
        if (g_waveHdr.dwFlags & WHDR_PREPARED) {
            waveOutUnprepareHeader(g_hWaveOut, &g_waveHdr, sizeof(WAVEHDR));
        }
        waveOutClose(g_hWaveOut);
        fprintf(stderr, "PHASE: waveout_closed\n");
    }

    ExitProcess(0);
}
