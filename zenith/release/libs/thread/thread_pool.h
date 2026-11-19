#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LIBS_EXPORTS
#define LIBS_API __declspec(dllexport)
#else
#define LIBS_API __declspec(dllimport)
#endif

typedef void* ThreadPoolHandle;
typedef void  (*PoolTaskFunc)(void*);

LIBS_API ThreadPoolHandle poolCreate(int numThreads);
LIBS_API int              poolSubmit(ThreadPoolHandle pool, PoolTaskFunc func, void* arg);
LIBS_API int              poolWaitAll(ThreadPoolHandle pool);
LIBS_API int              poolPending(ThreadPoolHandle pool);
LIBS_API int              poolActive(ThreadPoolHandle pool);
LIBS_API void             poolDestroy(ThreadPoolHandle pool);

#ifdef __cplusplus
}
#endif
#endif
