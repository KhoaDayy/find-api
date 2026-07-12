/*
 * GameHook.dll — passive Face FilePicker share capture only.
 * Boot is deferred and fail-soft so a bad pattern match does not take
 * down the game process during LoadLibrary.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

#include "MinHook.h"
#include "hook/capture_writer.h"
#include "hook/config.h"
#include "hook/lua_runtime_hook.h"
#include "hook/winhttp_capture.h"

using namespace face_capture;

static HMODULE g_hSelf = nullptr;
static HookConfig g_cfg;
static std::string g_dllDir;
static HANDLE g_initThread = nullptr;
static bool g_running = true;
static bool g_consoleReady = false;

static std::string GetDllDir() {
  char path[MAX_PATH] = {};
  GetModuleFileNameA(g_hSelf, path, MAX_PATH);
  char *p = strrchr(path, '\\');
  if (p)
    *(p + 1) = '\0';
  return path;
}

// Always available even if AllocConsole fails under anti-cheat.
static void BootLog(const char *fmt, ...) {
  char dir[MAX_PATH] = {};
  if (g_hSelf)
    GetModuleFileNameA(g_hSelf, dir, MAX_PATH);
  char *slash = strrchr(dir, '\\');
  if (slash)
    *(slash + 1) = '\0';
  else
    dir[0] = '\0';

  char path[MAX_PATH] = {};
  _snprintf_s(path, _TRUNCATE, "%shook_boot.log", dir);

  FILE *f = nullptr;
  if (fopen_s(&f, path, "a") != 0 || !f)
    return;

  SYSTEMTIME st{};
  GetLocalTime(&st);
  fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond,
          st.wMilliseconds);

  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fflush(f);
  fclose(f);
}

// AllocConsole is a common anti-cheat tripwire. Only open if
// GAMEHOOK_CONSOLE=1 is set in the process environment.
static void TryOpenConsole() {
  if (g_consoleReady)
    return;
  char env[8] = {};
  if (GetEnvironmentVariableA("GAMEHOOK_CONSOLE", env, sizeof(env)) == 0 ||
      env[0] != '1') {
    BootLog("console disabled (set GAMEHOOK_CONSOLE=1 to enable)");
    return;
  }
  if (!AllocConsole()) {
    BootLog("AllocConsole failed err=%lu (continuing without console)",
            GetLastError());
    return;
  }
  FILE *fp = nullptr;
  freopen_s(&fp, "CONOUT$", "w", stdout);
  freopen_s(&fp, "CONOUT$", "w", stderr);
  freopen_s(&fp, "CONIN$", "r", stdin);
  SetConsoleTitleA("Face Share Capture Hook");
  g_consoleReady = true;
}

static void ConPrint(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  BootLog("%s", buf);
  if (g_consoleReady) {
    printf("%s\n", buf);
    fflush(stdout);
  }
}

// No C++ objects with destructors in functions that use __try.
static int InitHooksNoExcept() {
  TryOpenConsole();
  g_dllDir = GetDllDir();

  ConPrint("========================================");
  ConPrint("  Face FilePicker Share Capture");
  ConPrint("  Passive only — no request mutation");
  ConPrint("========================================");
  ConPrint("DLL dir: %s", g_dllDir.c_str());

  g_cfg = LoadConfig(g_dllDir);
  ConPrint("Config: lua_hook=%d winhttp=%d script=%s",
           g_cfg.enable_lua_hook ? 1 : 0, g_cfg.enable_winhttp_hook ? 1 : 0,
           g_cfg.lua_script.c_str());

  std::string out = ResolvePath(g_dllDir, g_cfg.output_file);
  InitCaptureWriter(out);
  ConPrint("Capture: %s", out.c_str());
  ConPrint("Boot log: %shook_boot.log", g_dllDir.c_str());
  ConPrint("F5 = re-inject Lua logger");
  ConPrint("========================================");

  WriteCaptureEvent("native", "dll_loaded",
                    "{\"dll_dir\":" + JsonString(g_dllDir) +
                        ",\"output\":" + JsonString(out) + "}");

  if (MH_Initialize() != MH_OK) {
    ConPrint("[!] MinHook init failed");
    WriteCaptureEvent("native", "error", "{\"error\":\"minhook_init_failed\"}");
    return 1;
  }
  ConPrint("[+] MinHook ready");

  if (g_cfg.enable_winhttp_hook) {
    if (InstallWinHttpCapture(g_cfg))
      ConPrint("[+] WinHTTP capture installed (filepicker allowlist)");
    else
      ConPrint("[!] WinHTTP capture failed (non-fatal)");
  } else {
    ConPrint("[*] WinHTTP capture disabled by config");
  }

  if (g_cfg.enable_lua_hook) {
    if (InstallLuaRuntimeHook(g_cfg, g_dllDir))
      ConPrint("[+] Lua runtime hook installed (injects on next pcall)");
    else
      ConPrint("[!] Lua hook failed (signatures/module). WinHTTP may still work.");
  } else {
    ConPrint("[*] Lua hook disabled by config (safer default)");
  }

  ConPrint("[*] Init complete. Use Face Share in-game.");
  WriteCaptureEvent("native", "init_complete", "{\"ok\":true}");
  return 0;
}

static DWORD WINAPI InitThread(LPVOID) {
  // Stay out of DllMain loader lock; wait past early process init.
  Sleep(3000);

  int rc = 1;
  __try {
    rc = InitHooksNoExcept();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    BootLog("FATAL SEH in InitThread code=0x%08lX", GetExceptionCode());
    return 1;
  }

  while (g_running) {
    if (GetAsyncKeyState(VK_F5) & 1) {
      ConPrint("[*] F5: re-inject Lua");
      RequestLuaInject();
    }
    Sleep(100);
  }
  return (DWORD)rc;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_hSelf = hModule;
    DisableThreadLibraryCalls(hModule);
    // Minimal work only — no MinHook / pattern scan here
    BootLog("DllMain ATTACH pid=%lu", GetCurrentProcessId());
    g_initThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    if (!g_initThread)
      BootLog("CreateThread failed err=%lu", GetLastError());
  } else if (reason == DLL_PROCESS_DETACH) {
    // Process teardown: do not touch hooks/heaps here. Detours may still be
    // on other threads; MH_Uninitialize under loader lock is a crash source.
    BootLog("DllMain DETACH (skip MH_Uninitialize)");
    g_running = false;
  }
  return TRUE;
}
