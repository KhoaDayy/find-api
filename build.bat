@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   Game API Hook - Build Script
echo ============================================
echo.

:: Create output dir
if not exist "build" mkdir build

:: ----- Try MSVC Developer Command Prompt (already in path) -----
where cl >nul 2>&1
if %ERRORLEVEL% equ 0 goto :msvc_build

:: ----- Try loading MSVC via vcvarsall -----
set "VCVARS="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
)

if defined VCVARS (
    echo [*] Loading MSVC environment...
    call "%VCVARS%" x64 >nul 2>&1
    goto :msvc_build
)

:: ----- Try MinGW / GCC -----
where g++ >nul 2>&1
if %ERRORLEVEL% equ 0 goto :gcc_build

echo [!] No C++ compiler found.
echo [!] Install Visual Studio Build Tools or MinGW-w64.
goto :end

:msvc_build
echo [*] Compiler: MSVC (x64)
echo.

echo [1/2] Building GameHook.dll ...
cl /nologo /LD /O2 /EHsc /MD ^
    /I"lib\minhook\include" /I"src" ^
    src\dllmain.cpp ^
    lib\minhook\src\buffer.c ^
    lib\minhook\src\hook.c ^
    lib\minhook\src\trampoline.c ^
    lib\minhook\src\hde\hde64.c ^
    /Fe:"build\GameHook.dll" /Fo:"build\\" ^
    /link user32.lib winhttp.lib /OUT:"build\GameHook.dll"
if errorlevel 1 goto :fail

echo.
echo [2/2] Building Injector.exe ...
cl /nologo /O2 /EHsc /MD ^
    src\injector.cpp ^
    /Fe:"build\Injector.exe" /Fo:"build\\"
if errorlevel 1 goto :fail
goto :ok

:gcc_build
echo [*] Compiler: MinGW / GCC
echo.

echo [1/2] Building GameHook.dll ...
g++ -shared -O2 -std=c++17 ^
    -I"lib\minhook\include" -I"src" ^
    src\dllmain.cpp ^
    lib\minhook\src\buffer.c ^
    lib\minhook\src\hook.c ^
    lib\minhook\src\trampoline.c ^
    lib\minhook\src\hde\hde64.c ^
    -luser32 -lwinhttp -static ^
    -o build\GameHook.dll
if errorlevel 1 goto :fail

echo [2/2] Building Injector.exe ...
g++ -O2 -std=c++17 src\injector.cpp -static -o build\Injector.exe
if errorlevel 1 goto :fail
goto :ok

:ok
echo.
echo ============================================
echo   BUILD OK
echo   build\GameHook.dll
echo   build\Injector.exe
echo ============================================
echo.
echo Usage:
echo   1. Copy build\GameHook.dll and build\Injector.exe
echo      to the same folder (+ Scripts\api_logger.lua)
echo   2. Start yysls.exe (the game)
echo   3. Run Injector.exe as Administrator
echo   4. Press F5 in the hook console to inject
echo   5. Check api_log.txt for captured API calls
echo.
goto :end

:fail
echo.
echo [!] Build FAILED. Check errors above.

:end
pause
