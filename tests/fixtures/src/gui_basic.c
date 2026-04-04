/*
 * gui_basic.c — Minimal Win32 GUI test for Weave.
 *
 * Creates a window, processes messages until WM_PAINT fires once,
 * draws a filled rectangle and text, then exits with code 0.
 * Designed to be run headless under Xvfb in CI.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o gui_basic.exe gui_basic.c -luser32 -lgdi32 -lkernel32
 */

#include <windows.h>

static int g_painted = 0;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        /* Fill background white */
        RECT rc = {0, 0, 320, 240};
        HBRUSH white = (HBRUSH)GetStockObject(WHITE_BRUSH);
        FillRect(hdc, &rc, white);

        /* Draw a blue rectangle */
        HBRUSH blue = CreateSolidBrush(RGB(0, 0, 255));
        HBRUSH old = (HBRUSH)SelectObject(hdc, blue);
        Rectangle(hdc, 10, 10, 100, 80);
        SelectObject(hdc, old);
        DeleteObject(blue);

        /* Draw text */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(0, 0, 0));
        TextOutW(hdc, 10, 100, L"Weave GUI OK", 12);

        EndPaint(hwnd, &ps);
        g_painted = 1;
        PostQuitMessage(0);
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

    /* Write progress to stdout */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *msg1 = "gui_basic: registering window class\n";
    DWORD written;
    WriteFile(hOut, msg1, 36, &written, NULL);

    WNDCLASSW wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"WeaveTest";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassW(&wc)) {
        const char *err = "gui_basic: RegisterClassW failed\n";
        WriteFile(hOut, err, 33, &written, NULL);
        ExitProcess(1);
    }

    const char *msg2 = "gui_basic: creating window\n";
    WriteFile(hOut, msg2, 27, &written, NULL);

    HWND hwnd = CreateWindowExW(
        0, L"WeaveTest", L"Weave Test Window",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 240,
        NULL, NULL, hInst, NULL
    );

    if (!hwnd) {
        const char *err = "gui_basic: CreateWindowExW failed\n";
        WriteFile(hOut, err, 34, &written, NULL);
        ExitProcess(1);
    }

    ShowWindow(hwnd, nShow ? nShow : SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    const char *msg3 = "gui_basic: entering message loop\n";
    WriteFile(hOut, msg3, 33, &written, NULL);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    const char *msg4 = "gui_basic: message loop done\n";
    WriteFile(hOut, msg4, 29, &written, NULL);

    ExitProcess(g_painted ? 0 : 2);
}
