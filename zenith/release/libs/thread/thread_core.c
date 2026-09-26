#define LIBS_EXPORTS
#include "thread_core.h"
#include <windows.h>

typedef struct {
    ThreadFunc func;
    void*      arg;
} ThreadWrapperArg;

static DWORD __attribute__((stdcall)) threadWrapper(void* param) {
    ThreadWrapperArg warg = *(ThreadWrapperArg*)param;
    free(param);
    warg.func(warg.arg);
    return 0;
}

ThreadHandle threadCreate(ThreadFunc func, void* arg) {
    ThreadWrapperArg* warg = (ThreadWrapperArg*)malloc(sizeof(ThreadWrapperArg));
    if (!warg) return NULL;
    warg->func = func;
    warg->arg  = arg;

    HANDLE h = CreateThread(NULL, 0, threadWrapper, warg, 0, NULL);
    if (!h) {
        free(warg);
        return NULL;
    }
    return (ThreadHandle)h;
}

int threadJoin(ThreadHandle handle) {
    if (!handle) return -1;
    DWORD result = WaitForSingleObject((HANDLE)handle, INFINITE);
    if (result == WAIT_OBJECT_0) {
        DWORD exitCode;
        GetExitCodeThread((HANDLE)handle, &exitCode);
        CloseHandle((HANDLE)handle);
        return (int)exitCode;
    }
    CloseHandle((HANDLE)handle);
    return -1;
}

int threadDetach(ThreadHandle handle) {
    if (!handle) return -1;
    int result = CloseHandle((HANDLE)handle) ? 0 : -1;
    return result;
}

void threadSleepMs(int ms) {
    Sleep((DWORD)ms);
}

void threadYield() {
    SwitchToThread();
}

unsigned int threadGetId() {
    return (unsigned int)GetCurrentThreadId();
}

int threadEqual(unsigned int id1, unsigned int id2) {
    return id1 == id2 ? 1 : 0;
}
