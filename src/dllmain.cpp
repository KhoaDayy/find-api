/*
 * GameHook.dll — passive Face FilePicker share capture only.
 * Boot is deferred and fail-soft so a bad step does not take down the game.
 *
 * Boot order (Lua-first):
 *   config → capture dir/JSONL → MH_Initialize → Lua signatures/hook
 *   → optional WinHTTP background wait (only if enable_winhttp_fallback)
 *
 * MSVC rule: never put __try in a function that constructs C++ objects
 * with destructors (error C2712). SEH lives only in pure C wrappers.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

#include "MinHook.h"
#include "hook/capture_writer.h"
#include "hook/config.h"
#include "hook/lua_hook_state.h"
#include "hook/lua_runtime_hook.h"
#include "hook/winhttp_capture.h"

using namespace face_capture;

static HMODULE g_hSelf = nullptr;
static HookConfig g_cfg;
static std::string g_dllDir;
static std::string g_capturePath;
static HANDLE g_initThread = nullptr;
static volatile LONG g_running = 1;
static bool g_consoleReady = false;

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

static void TryOpenConsole(bool forceFromConfig) {
  if (g_consoleReady)
    return;
  char env[8] = {};
  bool envOn =
      GetEnvironmentVariableA("GAMEHOOK_CONSOLE", env, sizeof(env)) > 0 &&
      env[0] == '1';
  if (!forceFromConfig && !envOn) {
    BootLog("console disabled (enable_console / GAMEHOOK_CONSOLE=1)");
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
  BootLog("console enabled");
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

// --- C++ steps (no __try) ---

static int Step_LoadConfig() {
  char path[MAX_PATH] = {};
  GetModuleFileNameA(g_hSelf, path, MAX_PATH);
  char *p = strrchr(path, '\\');
  if (p)
    *(p + 1) = '\0';
  g_dllDir.assign(path);
  g_cfg = LoadConfig(g_dllDir);
  return 0;
}

static bool EnsureDirectoryTree(const char *dirPath) {
  if (!dirPath || !*dirPath)
    return false;
  char buf[MAX_PATH] = {};
  strncpy_s(buf, dirPath, _TRUNCATE);
  size_t n = strlen(buf);
  while (n > 0 && (buf[n - 1] == '\\' || buf[n - 1] == '/')) {
    buf[--n] = '\0';
  }
  for (char *p = buf; *p; ++p) {
    if (*p == '\\' || *p == '/') {
      char save = *p;
      *p = '\0';
      if (buf[0] && !(buf[1] == ':' && buf[2] == '\0')) {
        if (!CreateDirectoryA(buf, nullptr)) {
          DWORD e = GetLastError();
          if (e != ERROR_ALREADY_EXISTS)
            return false;
        }
      }
      *p = save;
    }
  }
  if (buf[0] && !(buf[1] == ':' && buf[2] == '\0')) {
    if (!CreateDirectoryA(buf, nullptr)) {
      DWORD e = GetLastError();
      if (e != ERROR_ALREADY_EXISTS)
        return false;
    }
  }
  return true;
}

static int Step_InitCapture() {
  g_capturePath = ResolveCaptureOutputPath(g_dllDir, g_cfg);

  // Parent directory for JSONL.
  char dir[MAX_PATH] = {};
  strncpy_s(dir, g_capturePath.c_str(), _TRUNCATE);
  char *slash = strrchr(dir, '\\');
  if (!slash)
    slash = strrchr(dir, '/');
  if (slash)
    *slash = '\0';

  if (!EnsureDirectoryTree(dir)) {
    DWORD e = GetLastError();
    ConPrint("[!] create capture dir failed path=%s err=%lu — fallback DLL/captures",
             dir, e);
    g_capturePath = g_dllDir + "captures\\face_share_capture.jsonl";
    std::string fb = g_dllDir + "captures";
    if (!EnsureDirectoryTree(fb.c_str())) {
      ConPrint("[!] fallback capture dir also failed err=%lu", GetLastError());
    } else {
      ConPrint("[+] fallback capture dir: %s", fb.c_str());
    }
  } else {
    ConPrint("[+] capture dir ready: %s", dir);
  }

  InitCaptureWriter(g_capturePath);
  ConPrint("Capture JSONL: %s", g_capturePath.c_str());

  // Verify file can be opened by re-checking attributes after InitCaptureWriter.
  DWORD attr = GetFileAttributesA(g_capturePath.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES) {
    // File may not exist until first write; check parent only.
    ConPrint("[*] capture file not yet on disk (writer will create on first event)");
  } else {
    ConPrint("[+] capture file exists");
  }
  return 0;
}

static int Step_MinHook() {
  MH_STATUS st = MH_Initialize();
  if (st != MH_OK) {
    ConPrint("[!] MinHook init failed status=%d", (int)st);
    return 1;
  }
  ConPrint("[+] MinHook initialized");
  return 0;
}

// Short optional wait — never blocks Lua. Max 15s per requirements.
static DWORD WINAPI WinHttpWaitThread(LPVOID) {
  char reason[128] = {};
  const int maxTries = 15;
  for (int i = 0; i < maxTries && InterlockedCompareExchange(&g_running, 1, 1) == 1;
       i++) {
    if (GetModuleHandleA("winhttp.dll")) {
      if (InstallWinHttpCapture(g_cfg, reason, sizeof(reason))) {
        ConPrint("[+] WinHTTP capture installed (%s) after %ds", reason, i);
      } else {
        ConPrint("[!] WinHTTP present but install failed: %s", reason);
      }
      return 0;
    }
    if (i == 0 || (i + 1) % 5 == 0)
      ConPrint("[*] waiting for winhttp.dll ... %ds", i);
    Sleep(1000);
  }
  if (InterlockedCompareExchange(&g_running, 1, 1) == 1)
    ConPrint("WINHTTP_NOT_LOADED");
  return 0;
}

static int Step_WinHttp() {
  // Prefer new flag; enable_winhttp_hook is kept in sync by LoadConfig.
  if (!g_cfg.enable_winhttp_fallback && !g_cfg.enable_winhttp_hook) {
    ConPrint("WINHTTP_FALLBACK_DISABLED");
    return 0;
  }
  if (GetModuleHandleA("winhttp.dll")) {
    char reason[128] = {};
    if (InstallWinHttpCapture(g_cfg, reason, sizeof(reason))) {
      ConPrint("[+] WinHTTP capture installed (%s)", reason);
      return 0;
    }
    ConPrint("[!] WinHTTP install failed: %s", reason);
    return 0;
  }
  ConPrint("[*] winhttp.dll not loaded yet — background wait (15s, non-blocking)");
  HANDLE h = CreateThread(nullptr, 0, WinHttpWaitThread, nullptr, 0, nullptr);
  if (h)
    CloseHandle(h);
  else
    ConPrint("[!] failed to start winhttp wait thread err=%lu", GetLastError());
  return 0;
}

static int Step_Lua() {
  if (!g_cfg.enable_lua_hook) {
    ConPrint("[*] Lua hook disabled by config");
    return 0;
  }
  if (InstallLuaRuntimeHook(g_cfg, g_dllDir))
    ConPrint("[+] Lua runtime hook installed (injects on next pcall / F5)");
  else
    ConPrint("[!] Lua full inject unavailable state=%s (probe/scan in captures/)",
             GetLuaHookStateName());
  return 0;
}

static int Step_WriteInitComplete() {
  LuaHookState st = GetLuaHookState();
  const char *name = LuaHookStateName(st);
  bool installed = st == LuaHookState::Installed || st == LuaHookState::Injected;
  WriteCaptureEvent(
      "native", "init_complete",
      std::string("{\"ok\":true,\"lua_requested\":") +
          (g_cfg.enable_lua_hook ? "true" : "false") +
          ",\"lua_hook_state\":" + JsonString(name) +
          ",\"lua_hook_installed\":" + (installed ? "true" : "false") +
          ",\"winhttp_fallback\":" +
          (g_cfg.enable_winhttp_fallback ? "true" : "false") + "}");
  return 0;
}

// No C++ std objects with destructors — SEH-safe.
static int Step_RequestLua() {
  char reason[160] = {};
  if (RequestLuaInject(reason, sizeof(reason))) {
    ConPrint("F5 injection armed");
  } else {
    ConPrint("F5 ignored: %s", reason[0] ? reason : "LUA_HOOK_NOT_INSTALLED");
  }
  return 0;
}

// --- SEH gates: no C++ objects with destructors ---

static int SehCall(const char *name, int (*fn)()) {
  int rc = 1;
  __try {
    rc = fn();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    BootLog("step SEH %s code=0x%08lX", name, GetExceptionCode());
    return -1;
  }
  BootLog("step leave: %s rc=%d", name, rc);
  return rc;
}

static bool g_consoleWanted = false;

static int SehTryOpenConsole() {
  __try {
    TryOpenConsole(g_consoleWanted);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    BootLog("TryOpenConsole SEH code=0x%08lX", GetExceptionCode());
    return -1;
  }
  return 0;
}

static int RunStep(const char *name, int (*fn)()) {
  BootLog("step enter: %s", name);
  return SehCall(name, fn);
}

static DWORD WINAPI InitThread(LPVOID) {
  Sleep(3000);

  // Config first so enable_console is known, then optional AllocConsole.
  if (RunStep("load_config", Step_LoadConfig) < 0) {
    BootLog("FATAL: load_config crashed — abort init");
    return 1;
  }
  g_consoleWanted = g_cfg.enable_console;
  SehTryOpenConsole();

  ConPrint("========================================");
  ConPrint("  Face FilePicker Share Capture");
  ConPrint("  Passive only — Lua-first, no mutation");
  ConPrint("========================================");

  ConPrint("DLL dir: %s", g_dllDir.c_str());
  ConPrint("Config: lua_hook=%d winhttp_fallback=%d console=%d script=%s capture_dir=%s",
           g_cfg.enable_lua_hook ? 1 : 0, g_cfg.enable_winhttp_fallback ? 1 : 0,
           g_cfg.enable_console ? 1 : 0, g_cfg.lua_script.c_str(),
           g_cfg.capture_dir.c_str());
  ConPrint("Boot log: %shook_boot.log", g_dllDir.c_str());
  ConPrint("========================================");

  // Capture I/O first so signature diagnostics always have a JSONL sink.
  if (RunStep("init_capture", Step_InitCapture) < 0)
    ConPrint("[!] Capture writer step failed — continuing (boot log only)");

  if (RunStep("minhook", Step_MinHook) != 0) {
    ConPrint("[!] Abort: MinHook unavailable");
    return 1;
  }

  // Lua BEFORE optional WinHTTP — never blocked by winhttp wait.
  RunStep("lua", Step_Lua);
  RunStep("winhttp", Step_WinHttp);

  RunStep("write_init_complete", Step_WriteInitComplete);

  {
    LuaHookState st = GetLuaHookState();
    if (st == LuaHookState::Installed || st == LuaHookState::Injected)
      ConPrint("[*] Init complete: Lua hook installed. Press F5 to arm injection.");
    else if (st == LuaHookState::SignatureMissing)
      ConPrint("[*] Init complete: Lua capture unavailable — lua_load signature missing. "
               "Do not press F5. See captures/lua_signature_probe.json");
    else if (st == LuaHookState::SignatureAmbiguous)
      ConPrint("[*] Init complete: Lua capture unavailable — signature ambiguous.");
    else if (st == LuaHookState::PcallObserverOnly)
      ConPrint("[*] Init complete: pcall observer only (no inject). F5 ignored.");
    else if (st == LuaHookState::Disabled)
      ConPrint("[*] Init complete: Lua hook disabled.");
    else
      ConPrint("[*] Init complete: lua_hook_state=%s", LuaHookStateName(st));
  }

  while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
    if (GetAsyncKeyState(VK_F5) & 1) {
      // Direct call — RequestLuaInject is atomic and must not AV.
      // Still wrap in SEH for defense in depth.
      RunStep("request_lua", Step_RequestLua);
    }
    Sleep(100);
  }
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_hSelf = hModule;
    DisableThreadLibraryCalls(hModule);
    BootLog("DllMain ATTACH pid=%lu", GetCurrentProcessId());
    g_initThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    if (!g_initThread)
      BootLog("CreateThread failed err=%lu", GetLastError());
  } else if (reason == DLL_PROCESS_DETACH) {
    BootLog("DllMain DETACH (skip MH_Uninitialize)");
    InterlockedExchange(&g_running, 0);
  }
  return TRUE;
}
