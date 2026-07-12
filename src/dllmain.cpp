/*
 * GameHook.dll — passive Face FilePicker share capture only.
 * Does not modify return values, replay tokens, or bypass anti-cheat.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
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
static HANDLE g_consoleThread = nullptr;
static bool g_running = true;

static std::string GetDllDir() {
  char path[MAX_PATH];
  GetModuleFileNameA(g_hSelf, path, MAX_PATH);
  char *p = strrchr(path, '\\');
  if (p)
    *(p + 1) = '\0';
  return path;
}

static DWORD WINAPI ConsoleThread(LPVOID) {
  AllocConsole();
  FILE *fp = nullptr;
  freopen_s(&fp, "CONOUT$", "w", stdout);
  freopen_s(&fp, "CONOUT$", "w", stderr);
  SetConsoleTitleA("Face Share Capture Hook");

  printf("========================================\n");
  printf("  Face FilePicker Share Capture\n");
  printf("  Passive only — no request mutation\n");
  printf("========================================\n");
  printf("Config: %shook_config.json\n", g_dllDir.c_str());
  printf("Output: %s\n", ResolvePath(g_dllDir, g_cfg.output_file).c_str());
  printf("F5 = re-inject Lua logger\n");
  printf("========================================\n\n");

  while (g_running) {
    if (GetAsyncKeyState(VK_F5) & 1) {
      RequestLuaInject();
    }
    Sleep(100);
  }
  return 0;
}

static DWORD WINAPI InitThread(LPVOID) {
  Sleep(500); // let process settle
  g_dllDir = GetDllDir();
  g_cfg = LoadConfig(g_dllDir);

  std::string out = ResolvePath(g_dllDir, g_cfg.output_file);
  InitCaptureWriter(out);

  WriteCaptureEvent("native", "dll_loaded",
                    "{\"dll_dir\":" + JsonString(g_dllDir) +
                        ",\"output\":" + JsonString(out) + "}");

  if (MH_Initialize() != MH_OK) {
    printf("[!] MinHook init failed\n");
    WriteCaptureEvent("native", "error", "{\"error\":\"minhook_init_failed\"}");
    return 1;
  }

  if (g_cfg.enable_winhttp_hook) {
    if (InstallWinHttpCapture(g_cfg))
      printf("[+] WinHTTP capture installed (filepicker allowlist)\n");
    else
      printf("[!] WinHTTP capture failed\n");
  }

  if (g_cfg.enable_lua_hook) {
    if (InstallLuaRuntimeHook(g_cfg, g_dllDir))
      printf("[+] Lua runtime hook installed\n");
    else
      printf("[!] Lua runtime hook failed (check signatures / target process)\n");
  }

  g_consoleThread = CreateThread(nullptr, 0, ConsoleThread, nullptr, 0, nullptr);
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_hSelf = hModule;
    DisableThreadLibraryCalls(hModule);
    CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
  } else if (reason == DLL_PROCESS_DETACH) {
    g_running = false;
    UninstallWinHttpCapture();
    UninstallLuaRuntimeHook();
    MH_Uninitialize();
    ShutdownCaptureWriter();
  }
  return TRUE;
}
