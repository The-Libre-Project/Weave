/*
 * sdl2_audio_test.c — SDL2 video + audio integration test for Weave M2.
 *
 * Initialises SDL2 video and audio, opens a SDL_OpenAudio PCM device, renders
 * colored rectangles each frame for 60 seconds, then cleans up and exits.
 * PHASE markers written to stderr so they appear in cargo test --nocapture.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc \
 *     -o tests/fixtures/bin/sdl2_audio_test.exe \
 *     tests/fixtures/src/sdl2_audio_test.c \
 *     -I/tmp/SDL2-2.32.2/x86_64-w64-mingw32/include/SDL2 \
 *     -L/tmp/SDL2-2.32.2/x86_64-w64-mingw32/lib \
 *     -lSDL2 -lkernel32 -luser32 -lwinmm \
 *     -mwindows
 */

#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <windows.h>

/* Use WriteFile+GetStdHandle for logging — avoids MinGW static CRT (_lock stub crash) */
#define LOG(msg) do { \
    DWORD _w; \
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), msg "\n", \
              (DWORD)(sizeof(msg)), &_w, NULL); \
} while(0)

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    /* --- Init video + audio ------------------------------------------------ */
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) != 0) {
        LOG("sdl2_audio_test: SDL_Init failed");
        ExitProcess(1);
    }
    LOG("PHASE: sdl2_audio_init");

    /* --- Window ------------------------------------------------------------ */
    SDL_Window *window = SDL_CreateWindow(
        "Weave SDL2 Audio Test",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        640, 480,
        SDL_WINDOW_SHOWN
    );
    if (!window) {
        LOG("sdl2_audio_test: SDL_CreateWindow failed");
        SDL_Quit();
        ExitProcess(1);
    }
    LOG("PHASE: sdl2_audio_window");

    /* --- Renderer ---------------------------------------------------------- */
    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    if (!renderer) {
        LOG("sdl2_audio_test: SDL_CreateRenderer failed");
        SDL_DestroyWindow(window);
        SDL_Quit();
        ExitProcess(1);
    }
    LOG("PHASE: sdl2_audio_renderer");

    /* --- Audio ------------------------------------------------------------- */
    SDL_AudioSpec want;
    SDL_zero(want);
    want.freq     = 44100;
    want.format   = AUDIO_S16;
    want.channels = 2;
    want.samples  = 4096;
    want.callback = NULL; /* push-mode — caller queues data via SDL_QueueAudio */

    if (SDL_OpenAudio(&want, NULL) == 0) {
        LOG("PHASE: sdl2_audio_opened");
        SDL_PauseAudio(0); /* start playback; our silent waveOut stubs handle gracefully */
    } else {
        LOG("sdl2_audio_test: SDL_OpenAudio failed (non-fatal)");
    }

    /* --- Game loop (60 seconds — M2 stability gate) -------------------------- */
    Uint32 start      = SDL_GetTicks();
    int    loop_logged = 0;

    for (;;) {
        /* Poll events */
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT) goto done;
        }

        /* Render frame: dark-blue background + moving white rect */
        SDL_SetRenderDrawColor(renderer, 0, 0, 200, 255);
        SDL_RenderClear(renderer);

        Uint32 ticks = SDL_GetTicks();
        SDL_Rect r = { (int)((ticks / 10) % 600), 200, 40, 40 };
        SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
        SDL_RenderFillRect(renderer, &r);

        SDL_RenderPresent(renderer);

        /* Log once on first iteration */
        if (!loop_logged) {
            LOG("PHASE: sdl2_audio_loop_ok");
            loop_logged = 1;
        }

        /* 60-second run limit — M2 stability criterion */
        if (ticks - start >= 60000) break;

        SDL_Delay(16); /* ~60 fps */
    }

done:
    /* --- Cleanup ----------------------------------------------------------- */
    SDL_CloseAudio();
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    LOG("PHASE: sdl2_audio_done");

    ExitProcess(0);
}
