#ifndef THREAD_MUTEX_H
#define THREAD_MUTEX_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LIBS_EXPORTS
#define LIBS_API __declspec(dllexport)
#else
#define LIBS_API __declspec(dllimport)
#endif

typedef void* MutexHandle;
typedef void* CondHandle;

LIBS_API MutexHandle mutexCreate();
LIBS_API int          mutexLock(MutexHandle handle);
LIBS_API int          mutexTryLock(MutexHandle handle);
LIBS_API int          mutexUnlock(MutexHandle handle);
LIBS_API void         mutexDestroy(MutexHandle handle);

LIBS_API CondHandle   condCreate();
LIBS_API int          condWait(CondHandle cond, MutexHandle mutex);
LIBS_API int          condTimedWait(CondHandle cond, MutexHandle mutex, int ms);
LIBS_API int          condSignal(CondHandle cond);
LIBS_API int          condBroadcast(CondHandle cond);
LIBS_API void         condDestroy(CondHandle cond);

#ifdef __cplusplus
}
#endif
#endif
