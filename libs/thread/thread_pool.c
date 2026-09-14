#define LIBS_EXPORTS
#include "thread_pool.h"
#include "thread_core.h"
#include "thread_mutex.h"
#include <windows.h>
#include <stdlib.h>

typedef struct {
    PoolTaskFunc func;
    void*        arg;
    int          used;
} PoolTask;

typedef struct {
    ThreadPoolHandle pool;
    PoolTask         task;
} WorkerArg;

typedef struct {
    ThreadHandle*    threads;
    int              numThreads;

    PoolTask*        queue;
    int              queueSize;
    int              queueHead;
    int              queueTail;
    int              queueCount;

    MutexHandle      mutex;
    CondHandle       notEmpty;
    CondHandle       notFull;
    CondHandle       allDone;

    int              shutdown;
    int              activeTasks;
    int              totalPending;
} ThreadPool;

static void* __attribute__((stdcall)) workerThread(void* param) {
    WorkerArg* warg = (WorkerArg*)param;
    ThreadPool* pool = (ThreadPool*)warg->pool;

    while (1) {
        mutexLock(pool->mutex);

        while (pool->queueCount == 0 && !pool->shutdown) {
            condWait(pool->notEmpty, pool->mutex);
        }

        if (pool->shutdown && pool->queueCount == 0) {
            mutexUnlock(pool->mutex);
            break;
        }

        PoolTask task;
        task.func = pool->queue[pool->queueHead].func;
        task.arg  = pool->queue[pool->queueHead].arg;
        pool->queueHead = (pool->queueHead + 1) % pool->queueSize;
        pool->queueCount--;
        pool->activeTasks++;

        condSignal(pool->notFull);
        mutexUnlock(pool->mutex);

        task.func(task.arg);

        mutexLock(pool->mutex);
        pool->activeTasks--;
        if (pool->activeTasks == 0 && pool->queueCount == 0) {
            condSignal(pool->allDone);
        }
        mutexUnlock(pool->mutex);
    }

    free(warg);
    return NULL;
}

ThreadPoolHandle poolCreate(int numThreads) {
    if (numThreads <= 0) numThreads = 4;

    ThreadPool* pool = (ThreadPool*)calloc(1, sizeof(ThreadPool));
    if (!pool) return NULL;

    pool->numThreads = numThreads;
    pool->queueSize  = 256;
    pool->queueHead  = 0;
    pool->queueTail  = 0;
    pool->queueCount = 0;
    pool->shutdown   = 0;
    pool->activeTasks = 0;
    pool->totalPending = 0;

    pool->mutex    = mutexCreate();
    pool->notEmpty = condCreate();
    pool->notFull  = condCreate();
    pool->allDone  = condCreate();

    pool->queue = (PoolTask*)calloc(pool->queueSize, sizeof(PoolTask));
    pool->threads = (ThreadHandle*)calloc(numThreads, sizeof(ThreadHandle));

    for (int i = 0; i < numThreads; i++) {
        WorkerArg* warg = (WorkerArg*)malloc(sizeof(WorkerArg));
        warg->pool = (ThreadPoolHandle)pool;
        pool->threads[i] = threadCreate(workerThread, warg);
    }

    return (ThreadPoolHandle)pool;
}

int poolSubmit(ThreadPoolHandle handle, PoolTaskFunc func, void* arg) {
    if (!handle || !func) return -1;
    ThreadPool* pool = (ThreadPool*)handle;

    mutexLock(pool->mutex);

    while (pool->queueCount >= pool->queueSize && !pool->shutdown) {
        condWait(pool->notFull, pool->mutex);
    }

    if (pool->shutdown) {
        mutexUnlock(pool->mutex);
        return -1;
    }

    pool->queue[pool->queueTail].func = func;
    pool->queue[pool->queueTail].arg  = arg;
    pool->queueTail = (pool->queueTail + 1) % pool->queueSize;
    pool->queueCount++;
    pool->totalPending++;

    condSignal(pool->notEmpty);
    mutexUnlock(pool->mutex);
    return 0;
}

int poolWaitAll(ThreadPoolHandle handle) {
    if (!handle) return -1;
    ThreadPool* pool = (ThreadPool*)handle;

    mutexLock(pool->mutex);
    while (pool->queueCount > 0 || pool->activeTasks > 0) {
        condWait(pool->allDone, pool->mutex);
    }
    mutexUnlock(pool->mutex);
    return 0;
}

int poolPending(ThreadPoolHandle handle) {
    if (!handle) return 0;
    ThreadPool* pool = (ThreadPool*)handle;
    mutexLock(pool->mutex);
    int count = pool->queueCount;
    mutexUnlock(pool->mutex);
    return count;
}

int poolActive(ThreadPoolHandle handle) {
    if (!handle) return 0;
    ThreadPool* pool = (ThreadPool*)handle;
    mutexLock(pool->mutex);
    int count = pool->activeTasks;
    mutexUnlock(pool->mutex);
    return count;
}

void poolDestroy(ThreadPoolHandle handle) {
    if (!handle) return;
    ThreadPool* pool = (ThreadPool*)handle;

    mutexLock(pool->mutex);
    pool->shutdown = 1;
    condBroadcast(pool->notEmpty);
    mutexUnlock(pool->mutex);

    for (int i = 0; i < pool->numThreads; i++) {
        threadJoin(pool->threads[i]);
    }

    mutexDestroy(pool->mutex);
    condDestroy(pool->notEmpty);
    condDestroy(pool->notFull);
    condDestroy(pool->allDone);
    free(pool->queue);
    free(pool->threads);
    free(pool);
}
