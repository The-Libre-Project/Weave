#include <windows.h>
#include <mmsystem.h>

// PHASE markers for test gate assertions
#define LOG(msg) do { \
    DWORD _w; \
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), msg "\n", \
              (DWORD)(sizeof(msg)), &_w, NULL); \
} while(0)

int main() {
    // Open default waveOut device
    HWAVEOUT hwo;
    WAVEFORMATEX wfx = {
        .wFormatTag = WAVE_FORMAT_PCM,
        .nChannels = 2,
        .nSamplesPerSec = 44100,
        .wBitsPerSample = 16,
        .nBlockAlign = 4,
        .nAvgBytesPerSec = 176400,
    };
    
    MMRESULT res = waveOutOpen(&hwo, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
    if (res != MMSYSERR_NOERROR) {
        LOG("PHASE: waveout_open_failed");
        return 1;
    }
    LOG("PHASE: waveout_opened");
    
    // Write a short silent buffer
    char buffer[4096] = {0};
    WAVEHDR wh = { .lpData = buffer, .dwBufferLength = sizeof(buffer) };
    waveOutPrepareHeader(hwo, &wh, sizeof(wh));
    waveOutWrite(hwo, &wh, sizeof(wh));
    LOG("PHASE: waveout_written");
    
    // Wait briefly for playback
    Sleep(100);
    
    waveOutUnprepareHeader(hwo, &wh, sizeof(wh));
    waveOutClose(hwo);
    LOG("PHASE: waveout_done");
    return 0;
}
