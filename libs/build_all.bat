@echo off
echo Building Zenith libs v0.8.1...
echo.

set CC=gcc
set CFLAGS=-shared -O2 -Wall -Wextra -std=c11
set OUTDIR=bin

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [1/4] libs_thread.dll (core thread functions)
%CC% %CFLAGS% -o "%OUTDIR%/libs_thread.dll" thread/thread_core.c -lkernel32 -Wl,--out-implib,"%OUTDIR%/libthread_core.a" -Wl,--kill-at
if %ERRORLEVEL% neq 0 (echo FAILED & exit /b 1)

echo [2/4] libs_mutex.dll (mutex + condition variables)
%CC% %CFLAGS% -o "%OUTDIR%/libs_mutex.dll" thread/thread_mutex.c -lkernel32 -Wl,--out-implib,"%OUTDIR%/libmutex.a" -Wl,--kill-at
if %ERRORLEVEL% neq 0 (echo FAILED & exit /b 1)

echo [3/4] libs_async.dll (futures + promises, depends on thread+mutex)
%CC% %CFLAGS% -o "%OUTDIR%/libs_async.dll" thread/thread_async.c "%OUTDIR%/libs_thread.dll" "%OUTDIR%/libs_mutex.dll" -Wl,--out-implib,"%OUTDIR%/libasync.a" -Wl,--kill-at
if %ERRORLEVEL% neq 0 (echo FAILED & exit /b 1)

echo [4/4] libs_threadpool.dll (thread pool, depends on thread+mutex)
%CC% %CFLAGS% -o "%OUTDIR%/libs_threadpool.dll" thread/thread_pool.c "%OUTDIR%/libs_thread.dll" "%OUTDIR%/libs_mutex.dll" -Wl,--out-implib,"%OUTDIR%/libthreadpool.a" -Wl,--kill-at
if %ERRORLEVEL% neq 0 (echo FAILED & exit /b 1)

echo.
echo [OK] All modules built in %OUTDIR%/
echo.
echo  libs_thread.dll     - threads (CreateThread, Join, Sleep, Yield)
echo  libs_mutex.dll      - mutex + condvars (Lock, TryLock, Wait, Signal)
echo  libs_async.dll      - futures/promises (Run, Wait, Get, All)
echo  libs_threadpool.dll - thread pool (Create, Submit, WaitAll)
echo.
echo Use in Zenith:
echo   @import("libs_thread.dll")
echo   extern func threadCreate(func: int, arg: int) -> int
echo.
echo Or import a specific module from libs.dll:
echo   @import("libs.dll::thread")
echo.
