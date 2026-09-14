@echo off
setlocal
REM ============================================================
REM  Zenith Installer build script
REM  Compiles zenith_installer.z (written in Zenith) and assembles
REM  a self-contained release payload folder containing:
REM    zenith.exe, src\, libs\, документация\, LICENSE,
REM    zenith_installer.exe
REM  Running release\zenith_installer.exe installs all of these.
REM ============================================================

set ROOT=%~dp0
set RELEASE=%ROOT%release

REM ROOTN = ROOT without trailing backslash (for PowerShell -Root argument,
REM where a trailing backslash inside quotes would escape the closing quote)
set ROOTN=%ROOT%
if "%ROOTN:~-1%"=="\" set ROOTN=%ROOTN:~0,-1%

echo ============================================================
echo [1/2] Compiling zenith_installer.z  -> zenith_installer.exe
echo ============================================================
"%ROOT%build\zenith.exe" "%ROOT%zenith_installer.z" -o "%ROOT%zenith_installer.exe"
if errorlevel 1 (
    echo *** COMPILE FAILED ***
    exit /b 1
)

echo.
echo ============================================================
echo [2/2] Assembling release payload in %RELEASE%
echo ============================================================
if exist "%RELEASE%" rmdir /s /q "%RELEASE%"
mkdir "%RELEASE%"

REM compiler + installer
copy /y "%ROOT%build\zenith.exe"            "%RELEASE%\zenith.exe"           >nul
copy /y "%ROOT%zenith_installer.exe"        "%RELEASE%\zenith_installer.exe" >nul

REM sources
robocopy "%ROOT%src" "%RELEASE%\src" /E /NFL /NDL /NJH /NJS /NC /NS >nul

REM runtime libraries
robocopy "%ROOT%libs" "%RELEASE%\libs" /E /NFL /NDL /NJH /NJS /NC /NS >nul

REM russian documentation (Cyrillic folder name; copy via a .ps1 helper to
REM avoid cmd codepage/BOM issues)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0copy_docs.ps1" -Root "%ROOTN%" -Release "%RELEASE%"
if errorlevel 1 (
    echo *** documentation copy FAILED ***
)

REM license
copy /y "%ROOT%LICENSE" "%RELEASE%\LICENSE" >nul

echo.
echo Done. Payload ready:
dir "%RELEASE%"
echo.
echo Run:  %RELEASE%\zenith_installer.exe
echo To make a portable ZIP, zip the contents of release\ .
endlocal
