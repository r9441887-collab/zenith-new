#define LIBS_EXPORTS
#include "thread_async.h"
#include "thread_core.h"
#include "thread_mutex.h"
#include <windows.h>
#include <stdlib.h>

typedef struct {
    FutureResult result;
    MutexHandle  mutex;
    CondHandle   cond;
    ThreadHandle thread;
    int          detached;
} AsyncTask;

typedef struct {
    AsyncTask** items;
    int count;
    int capacity;
} AsyncGroup;

static void* __attribute__((stdcall)) asyncWorker(void* param) {
    AsyncTask* task = (AsyncTask*)param;

    typedef void* (__attribute__((stdcall)) *RealFunc)(void*);
    RealFunc realFunc = (RealFunc)task->result.data;

    void* retval = realFunc(NULL);

    mutexLock(task->mutex);
    task->result.ready   = 1;
    task->result.value   = (long long)(intptr_t)retval;
    task->result.data    = retval;
    mutexUnlock(task->mutex);

    condSignal(task->cond);
    return retval;
}

FutureHandle asyncRun(void* (__attribute__((stdcall)) *func)(void*), void* arg) {
    (void)arg;
    AsyncTask* task = (AsyncTask*)calloc(1, sizeof(AsyncTask));
    if (!task) return NULL;

    task->mutex = mutexCreate();
    task->cond  = condCreate();
    task->result.ready  = 0;
    task->result.error  = 0;
    task->result.value  = 0;
    task->result.data   = (void*)func;
    task->detached = 0;

    task->thread = threadCreate(asyncWorker, task);
    if (!task->thread) {
        mutexDestroy(task->mutex);
        condDestroy(task->cond);
        free(task);
        return NULL;
    }

    return (FutureHandle)task;
}

int asyncReady(FutureHandle handle) {
    if (!handle) return -1;
    AsyncTask* task = (AsyncTask*)handle;
    mutexLock(task->mutex);
    int ready = task->result.ready;
    mutexUnlock(task->mutex);
    return ready;
}

int asyncWait(FutureHandle handle) {
    if (!handle) return -1;
    AsyncTask* task = (AsyncTask*)handle;
    mutexLock(task->mutex);
    while (!task->result.ready) {
        condWait(task->cond, task->mutex);
    }
    mutexUnlock(task->mutex);
    return task->result.error;
}

int asyncTimedWait(FutureHandle handle, int ms) {
    if (!handle) return -1;
    AsyncTask* task = (AsyncTask*)handle;
    mutexLock(task->mutex);
    if (!task->result.ready) {
        condTimedWait(task->cond, task->mutex, ms);
    }
    int ready = task->result.ready;
    mutexUnlock(task->mutex);
    return ready ? task->result.error : 1;
}

long long asyncGet(FutureHandle handle) {
    asyncWait(handle);
    if (!handle) return 0;
    AsyncTask* task = (AsyncTask*)handle;
    return task->result.value;
}

void* asyncGetData(FutureHandle handle) {
    asyncWait(handle);
    if (!handle) return NULL;
    AsyncTask* task = (AsyncTask*)handle;
    return task->result.data;
}

void asyncDestroy(FutureHandle handle) {
    if (!handle) return;
    AsyncTask* task = (AsyncTask*)handle;
    asyncWait(handle);
    if (task->detached) {
        threadDetach(task->thread);
    } else {
        CloseHandle((HANDLE)task->thread);
    }
    mutexDestroy(task->mutex);
    condDestroy(task->cond);
    free(task);
}

FutureHandle asyncAllCreate(int count) {
    AsyncGroup* group = (AsyncGroup*)calloc(1, sizeof(AsyncGroup));
    if (!group) return NULL;
    group->items    = (AsyncTask**)calloc(count, sizeof(AsyncTask*));
    group->count    = 0;
    group->capacity = count;
    return (FutureHandle)group;
}

int asyncAllAdd(FutureHandle group, FutureHandle future) {
    if (!group || !future) return -1;
    AsyncGroup* g = (AsyncGroup*)group;
    if (g->count >= g->capacity) return -1;
    g->items[g->count++] = (AsyncTask*)future;
    return 0;
}

int asyncAllWait(FutureHandle group) {
    if (!group) return -1;
    AsyncGroup* g = (AsyncGroup*)group;
    for (int i = 0; i < g->count; i++) {
        asyncWait((FutureHandle)g->items[i]);
    }
    return 0;
}

void asyncAllDestroy(FutureHandle group) {
    if (!group) return;
    AsyncGroup* g = (AsyncGroup*)group;
    for (int i = 0; i < g->count; i++) {
        asyncDestroy((FutureHandle)g->items[i]);
    }
    free(g->items);
    free(g);
}
