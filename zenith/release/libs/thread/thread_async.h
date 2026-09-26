#ifndef THREAD_ASYNC_H
#define THREAD_ASYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LIBS_EXPORTS
#define LIBS_API __declspec(dllexport)
#else
#define LIBS_API __declspec(dllimport)
#endif

typedef void* FutureHandle;

typedef struct {
    int   ready;
    int   error;
    long long value;
    void* data;
} FutureResult;

LIBS_API FutureHandle asyncRun(void* (__attribute__((stdcall)) *func)(void*), void* arg);
LIBS_API int          asyncReady(FutureHandle handle);
LIBS_API int          asyncWait(FutureHandle handle);
LIBS_API int          asyncTimedWait(FutureHandle handle, int ms);
LIBS_API long long    asyncGet(FutureHandle handle);
LIBS_API void*        asyncGetData(FutureHandle handle);
LIBS_API void         asyncDestroy(FutureHandle handle);

LIBS_API FutureHandle asyncAllCreate(int count);
LIBS_API int          asyncAllAdd(FutureHandle group, FutureHandle future);
LIBS_API int          asyncAllWait(FutureHandle group);
LIBS_API void         asyncAllDestroy(FutureHandle group);

#ifdef __cplusplus
}
#endif
#endif
