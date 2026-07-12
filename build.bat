@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================
echo   Face Share Capture Hook - Build
echo ============================================
echo.

if not exist "build" mkdir build
if not exist "build\bin" mkdir build\bin
if not exist "build\bin\Scripts" mkdir build\bin\Scripts
if not exist "build\bin\captures" mkdir build\bin\captures
if not exist "build\obj" mkdir build\obj

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="
set "VSINSTALL="

if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSINSTALL=%%i"
)

if defined VSINSTALL if exist "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"

if defined VCVARS (
  echo [*] Loading MSVC x64: %VCVARS%
  call "%VCVARS%" x64
  if errorlevel 1 (
    echo [!] vcvarsall failed
    goto :fail
  )
  goto :msvc_build
)

where g++ >nul 2>&1
if %ERRORLEVEL% equ 0 goto :gcc_build

echo [!] No MSVC vcvarsall or g++ found.
echo [!] Install VS Build Tools with Desktop C++ workload.
goto :fail

:msvc_build
where cl >nul 2>&1
if errorlevel 1 (
  echo [!] cl.exe not in PATH after vcvarsall
  goto :fail
)
echo [*] Compiler: MSVC
echo.

echo [1/2] GameHook.dll ...
cl /nologo /LD /O2 /EHsc /MD /std:c++17 /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE ^
  /I"lib\minhook\include" /I"src" ^
  src\dllmain.cpp ^
  src\hook\config.cpp ^
  src\hook\capture_writer.cpp ^
  src\hook\redact.cpp ^
  src\hook\winhttp_capture.cpp ^
  src\hook\lua_runtime_hook.cpp ^
  lib\minhook\src\buffer.c ^
  lib\minhook\src\hook.c ^
  lib\minhook\src\trampoline.c ^
  lib\minhook\src\hde\hde64.c ^
  /Fo"build\obj\\" ^
  /Fe:"build\bin\GameHook.dll" ^
  /link /DLL user32.lib winhttp.lib psapi.lib advapi32.lib
if errorlevel 1 goto :fail

echo [2/2] Injector.exe ...
cl /nologo /O2 /EHsc /MD /std:c++17 /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE ^
  src\injector.cpp ^
  /Fo"build\obj\\" ^
  /Fe:"build\bin\Injector.exe"
if errorlevel 1 goto :fail

copy /Y "Scripts\face_share_logger.lua" "build\bin\Scripts\" >nul
rem Always ship safe defaults (lua_hook OFF). Never overwrite with a local
rem debug config that may re-enable pattern hooks and crash the game.
if exist "hook_config.example.json" (
  copy /Y "hook_config.example.json" "build\bin\hook_config.example.json" >nul
  copy /Y "hook_config.example.json" "build\bin\hook_config.json" >nul
)
goto :ok

:gcc_build
echo [*] Compiler: MinGW g++
g++ -shared -O2 -std=c++17 -I"lib/minhook/include" -I"src" ^
  src/dllmain.cpp src/hook/config.cpp src/hook/capture_writer.cpp src/hook/redact.cpp ^
  src/hook/winhttp_capture.cpp src/hook/lua_runtime_hook.cpp ^
  lib/minhook/src/buffer.c lib/minhook/src/hook.c lib/minhook/src/trampoline.c lib/minhook/src/hde/hde64.c ^
  -luser32 -lwinhttp -lpsapi -static -o build/bin/GameHook.dll
if errorlevel 1 goto :fail
g++ -O2 -std=c++17 src/injector.cpp -static -o build/bin/Injector.exe
if errorlevel 1 goto :fail
copy /Y Scripts\face_share_logger.lua build\bin\Scripts\ >nul
if exist hook_config.example.json (
  copy /Y hook_config.example.json build\bin\hook_config.example.json >nul
  copy /Y hook_config.example.json build\bin\hook_config.json >nul
)
goto :ok

:ok
if not exist "build\bin\GameHook.dll" goto :fail
if not exist "build\bin\Injector.exe" goto :fail
if not exist "build\bin\Scripts\face_share_logger.lua" goto :fail
if not exist "build\bin\hook_config.json" if not exist "build\bin\hook_config.example.json" goto :fail

echo.
echo ============================================
echo   BUILD OK
echo   build\bin\GameHook.dll
echo   build\bin\Injector.exe
echo   build\bin\Scripts\face_share_logger.lua
echo   build\bin\hook_config.json  (lua_hook OFF by default)
echo ============================================
echo.
echo IMPORTANT: do NOT use the old hook\GameHook.dll (Mar build).
echo Use only build\bin\*
echo.
echo Usage:
echo   1. Start game fully into world
echo   2. Run build\bin\Injector.exe as Admin
echo   3. Check build\bin\hook_boot.log  (no console by default)
echo   4. In-game Face Share once
echo   5. captures in build\bin\captures\
echo.
echo Optional: set GAMEHOOK_CONSOLE=1 before inject for AllocConsole.
echo Lua pattern hook stays OFF unless you edit hook_config.json.
echo.
exit /b 0

:fail
echo.
echo [!] Build FAILED.
exit /b 1
