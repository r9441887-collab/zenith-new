#ifndef THREAD_CORE_H
#define THREAD_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LIBS_EXPORTS
#define LIBS_API __declspec(dllexport)
#else
#define LIBS_API __declspec(dllimport)
#endif

typedef void* ThreadHandle;
typedef void* (__attribute__((stdcall)) *ThreadFunc)(void*);

LIBS_API ThreadHandle threadCreate(ThreadFunc func, void* arg);
LIBS_API int          threadJoin(ThreadHandle handle);
LIBS_API int          threadDetach(ThreadHandle handle);
LIBS_API void         threadSleepMs(int ms);
LIBS_API void         threadYield();
LIBS_API unsigned int threadGetId();
LIBS_API int          threadEqual(unsigned int id1, unsigned int id2);

#ifdef __cplusplus
}
#endif
#endif
