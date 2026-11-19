#define LIBS_EXPORTS
#include "thread_mutex.h"
#include <windows.h>

MutexHandle mutexCreate() {
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)malloc(sizeof(CRITICAL_SECTION));
    if (!cs) return NULL;
    InitializeCriticalSection(cs);
    return (MutexHandle)cs;
}

int mutexLock(MutexHandle handle) {
    if (!handle) return -1;
    EnterCriticalSection((CRITICAL_SECTION*)handle);
    return 0;
}

int mutexTryLock(MutexHandle handle) {
    if (!handle) return -1;
    return TryEnterCriticalSection((CRITICAL_SECTION*)handle) ? 0 : 1;
}

int mutexUnlock(MutexHandle handle) {
    if (!handle) return -1;
    LeaveCriticalSection((CRITICAL_SECTION*)handle);
    return 0;
}

void mutexDestroy(MutexHandle handle) {
    if (!handle) return;
    DeleteCriticalSection((CRITICAL_SECTION*)handle);
    free(handle);
}

CondHandle condCreate() {
    HANDLE h = CreateEvent(NULL, FALSE, FALSE, NULL);
    return (CondHandle)h;
}

int condWait(CondHandle cond, MutexHandle mutex) {
    if (!cond || !mutex) return -1;
    LeaveCriticalSection((CRITICAL_SECTION*)mutex);
    WaitForSingleObject((HANDLE)cond, INFINITE);
    EnterCriticalSection((CRITICAL_SECTION*)mutex);
    return 0;
}

int condTimedWait(CondHandle cond, MutexHandle mutex, int ms) {
    if (!cond || !mutex) return -1;
    LeaveCriticalSection((CRITICAL_SECTION*)mutex);
    DWORD result = WaitForSingleObject((HANDLE)cond, (DWORD)ms);
    EnterCriticalSection((CRITICAL_SECTION*)mutex);
    return (result == WAIT_OBJECT_0) ? 0 : 1;
}

int condSignal(CondHandle cond) {
    if (!cond) return -1;
    return SetEvent((HANDLE)cond) ? 0 : -1;
}

int condBroadcast(CondHandle cond) {
    if (!cond) return -1;
    return PulseEvent((HANDLE)cond) ? 0 : -1;
}

void condDestroy(CondHandle cond) {
    if (!cond) return;
    CloseHandle((HANDLE)cond);
}
