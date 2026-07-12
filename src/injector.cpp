/*
 *  Injector.cpp  –  Injects GameHook.dll into wwm.exe
 *  No TlHelp32.h dependency (uses runtime-loaded functions)
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Manual TlHelp32 definitions ---------- */
#define TH32CS_SNAPPROCESS 0x00000002

typedef struct {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD th32ModuleID;
  DWORD cntThreads;
  DWORD th32ParentProcessID;
  LONG pcPriClassBase;
  DWORD dwFlags;
  WCHAR szExeFile[MAX_PATH];
} MY_PROCESSENTRY32W;

typedef HANDLE(WINAPI *CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL(WINAPI *Process32FirstW_t)(HANDLE, MY_PROCESSENTRY32W *);
typedef BOOL(WINAPI *Process32NextW_t)(HANDLE, MY_PROCESSENTRY32W *);

static CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = NULL;
static Process32FirstW_t pProcess32FirstW = NULL;
static Process32NextW_t pProcess32NextW = NULL;

static int InitToolhelp() {
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  if (!k32)
    return 0;
  pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)GetProcAddress(
      k32, "CreateToolhelp32Snapshot");
  pProcess32FirstW = (Process32FirstW_t)GetProcAddress(k32, "Process32FirstW");
  pProcess32NextW = (Process32NextW_t)GetProcAddress(k32, "Process32NextW");
  return pCreateToolhelp32Snapshot && pProcess32FirstW && pProcess32NextW;
}

static DWORD FindPid(const wchar_t *name) {
  DWORD pid = 0;
  HANDLE snap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  MY_PROCESSENTRY32W pe;
  memset(&pe, 0, sizeof(pe));
  pe.dwSize = sizeof(pe);
  if (pProcess32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (pProcess32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pid;
}

/* Read target_process from hook_config.json next to injector (ASCII only). */
static void LoadTargetProcess(wchar_t *out, size_t outCount) {
  wcscpy_s(out, outCount, L"yysls.exe");
  wchar_t cfgPath[MAX_PATH];
  GetModuleFileNameW(NULL, cfgPath, MAX_PATH);
  wchar_t *sl = wcsrchr(cfgPath, L'\\');
  if (sl)
    wcscpy_s(sl + 1, MAX_PATH - (size_t)(sl - cfgPath + 1), L"hook_config.json");
  else
    wcscpy_s(cfgPath, L"hook_config.json");

  FILE *f = nullptr;
  if (_wfopen_s(&f, cfgPath, L"rb") != 0 || !f)
    return;
  char buf[4096] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  if (!n)
    return;
  buf[n] = 0;
  const char *key = "\"target_process\"";
  char *p = strstr(buf, key);
  if (!p)
    return;
  p = strchr(p + strlen(key), '"');
  if (!p)
    return;
  p++;
  char *e = strchr(p, '"');
  if (!e || e <= p || (size_t)(e - p) >= 120)
    return;
  char narrow[128] = {0};
  memcpy(narrow, p, (size_t)(e - p));
  MultiByteToWideChar(CP_UTF8, 0, narrow, -1, out, (int)outCount);
}

int wmain(int argc, wchar_t **argv) {
  wchar_t target[128];
  LoadTargetProcess(target, 128);
  if (argc >= 2 && argv[1] && argv[1][0])
    wcscpy_s(target, argv[1]);

  printf("=== Face Share Capture Injector ===\n");
  wprintf(L"Target: %s\n\n", target);

  if (!InitToolhelp()) {
    printf("[!] Failed to load Toolhelp functions\n");
    system("pause");
    return 1;
  }

  /* --- resolve DLL path (same dir as injector) --- */
  wchar_t dllPath[MAX_PATH];
  GetModuleFileNameW(NULL, dllPath, MAX_PATH);
  wchar_t *sl = wcsrchr(dllPath, L'\\');
  if (sl)
    wcscpy_s(sl + 1, MAX_PATH - (size_t)(sl - dllPath + 1), L"GameHook.dll");
  else
    wcscpy_s(dllPath, L"GameHook.dll");

  wprintf(L"DLL : %s\n", dllPath);

  if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
    printf("[!] GameHook.dll not found next to Injector.exe\n");
    system("pause");
    return 1;
  }

  /* --- find process --- */
  wprintf(L"[*] Looking for %s ...\n", target);
  DWORD pid = FindPid(target);
  if (!pid) {
    /* also try alternate common names */
    if (_wcsicmp(target, L"yysls.exe") == 0)
      pid = FindPid(L"wwm.exe");
    else if (_wcsicmp(target, L"wwm.exe") == 0)
      pid = FindPid(L"yysls.exe");
  }
  if (!pid) {
    printf("[*] Waiting for game to start ...\n");
    while (!pid) {
      pid = FindPid(target);
      if (!pid && _wcsicmp(target, L"yysls.exe") == 0)
        pid = FindPid(L"wwm.exe");
      if (!pid && _wcsicmp(target, L"wwm.exe") == 0)
        pid = FindPid(L"yysls.exe");
      Sleep(1000);
    }
  }
  printf("[+] PID = %lu\n", pid);

  /* --- open process --- */
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProc) {
    printf("[!] OpenProcess failed (err %lu). Run as Admin.\n", GetLastError());
    system("pause");
    return 1;
  }

  /* --- write DLL path into remote memory --- */
  size_t cb = (wcslen(dllPath) + 1) * sizeof(wchar_t);
  LPVOID pRemote =
      VirtualAllocEx(hProc, NULL, cb, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemote || !WriteProcessMemory(hProc, pRemote, dllPath, cb, NULL)) {
    printf("[!] Memory allocation / write failed\n");
    CloseHandle(hProc);
    system("pause");
    return 1;
  }

  /* --- create remote thread => LoadLibraryW --- */
  FARPROC pLoadLib =
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  HANDLE hThread = CreateRemoteThread(
      hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemote, 0, NULL);

  if (!hThread) {
    printf("[!] CreateRemoteThread failed (err %lu). Anti-cheat?\n",
           GetLastError());
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    system("pause");
    return 1;
  }

  printf("[*] Waiting for LoadLibraryW remote thread...\n");
  DWORD wait = WaitForSingleObject(hThread, 15000);
  if (wait != WAIT_OBJECT_0) {
    printf("[!] Remote thread wait failed/timeout (wait=%lu err=%lu)\n", wait,
           GetLastError());
  }

  DWORD remoteExit = 0;
  if (!GetExitCodeThread(hThread, &remoteExit)) {
    printf("[!] GetExitCodeThread failed (err %lu)\n", GetLastError());
  } else {
    // LoadLibraryW returns HMODULE in exit code (low 32 bits on x64)
    printf("[*] LoadLibraryW exit code = 0x%08lX\n", remoteExit);
    if (remoteExit == 0) {
      printf("[!] LoadLibraryW returned NULL — DLL failed to load in the game.\n");
      printf("    Common causes:\n");
      printf("    - GameHook.dll not next to Injector.exe\n");
      printf("    - Missing runtime (VS Redistributable x64)\n");
      printf("    - Anti-cheat blocked LoadLibrary\n");
      printf("    - Wrong arch (must be x64)\n");
    } else {
      printf("[+] DLL module handle looks non-null (inject call succeeded).\n");
      printf("    If the GAME still closed: GameHook init crashed inside the process.\n");
      printf("    Check hook_boot.log next to GameHook.dll after restarting the game.\n");
    }
  }

  // Confirm game process still alive
  DWORD procCode = STILL_ACTIVE;
  if (GetExitCodeProcess(hProc, &procCode) && procCode != STILL_ACTIVE) {
    printf("[!] Game process exited during inject (code=%lu).\n", procCode);
    printf("    That usually means the DLL crashed the game on load/init.\n");
  } else {
    printf("[+] Game process still running.\n");
  }

  CloseHandle(hThread);
  VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
  CloseHandle(hProc);

  printf("\nDone. Press any key to close Injector...\n");
  system("pause");
  return 0;
}
