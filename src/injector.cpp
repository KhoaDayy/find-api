/*
 *  Injector.cpp  –  Injects GameHook.dll into the game process.
 *  Supports:
 *    Injector.exe
 *    Injector.exe wwm.exe
 *    Injector.exe --pid 20716
 *  No TlHelp32.h dependency for process enum (uses runtime-loaded functions)
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

/* Defaults + optional target_process / target_processes from hook_config.json */
static void LoadTargetList(wchar_t names[][128], int *count, int maxCount) {
  *count = 0;
  const wchar_t *defaults[] = {L"wwm.exe", L"yysls.exe", L"WhereWindsMeet.exe"};
  for (int i = 0; i < 3 && *count < maxCount; i++) {
    wcscpy_s(names[*count], 128, defaults[i]);
    (*count)++;
  }

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
  char buf[8192] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  if (!n)
    return;
  buf[n] = 0;

  // Prefer target_processes array
  const char *keyArr = "\"target_processes\"";
  char *p = strstr(buf, keyArr);
  if (p) {
    char *lb = strchr(p, '[');
    char *rb = lb ? strchr(lb, ']') : nullptr;
    if (lb && rb) {
      int c = 0;
      char *i = lb + 1;
      while (i < rb && c < maxCount) {
        char *q1 = strchr(i, '"');
        if (!q1 || q1 >= rb)
          break;
        char *q2 = strchr(q1 + 1, '"');
        if (!q2 || q2 > rb)
          break;
        char narrow[128] = {0};
        size_t len = (size_t)(q2 - q1 - 1);
        if (len >= sizeof(narrow))
          len = sizeof(narrow) - 1;
        memcpy(narrow, q1 + 1, len);
        MultiByteToWideChar(CP_UTF8, 0, narrow, -1, names[c], 128);
        c++;
        i = q2 + 1;
      }
      if (c > 0)
        *count = c;
      return;
    }
  }

  // Legacy single target_process
  const char *key = "\"target_process\"";
  p = strstr(buf, key);
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
  MultiByteToWideChar(CP_UTF8, 0, narrow, -1, names[0], 128);
  *count = 1;
}

static int DoInject(DWORD pid, const wchar_t *dllPath) {
  printf("[+] PID = %lu\n", pid);

  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProc) {
    printf("[!] OpenProcess failed (err %lu). Run as Admin.\n", GetLastError());
    return 1;
  }

  size_t cb = (wcslen(dllPath) + 1) * sizeof(wchar_t);
  LPVOID pRemote =
      VirtualAllocEx(hProc, NULL, cb, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemote || !WriteProcessMemory(hProc, pRemote, dllPath, cb, NULL)) {
    printf("[!] Memory allocation / write failed\n");
    CloseHandle(hProc);
    return 1;
  }

  FARPROC pLoadLib =
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  HANDLE hThread = CreateRemoteThread(
      hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemote, 0, NULL);

  if (!hThread) {
    printf("[!] CreateRemoteThread failed (err %lu). Anti-cheat?\n",
           GetLastError());
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProc);
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
      printf("    Check hook_boot.log next to GameHook.dll.\n");
    }
  }

  DWORD procCode = STILL_ACTIVE;
  if (GetExitCodeProcess(hProc, &procCode) && procCode != STILL_ACTIVE) {
    printf("[!] Game process exited during inject (code=%lu).\n", procCode);
  } else {
    printf("[+] Game process still running.\n");
  }

  CloseHandle(hThread);
  VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
  CloseHandle(hProc);
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  printf("=== Face Share Capture Injector ===\n");
  printf("Usage: Injector.exe [--pid N] [process.exe]\n\n");

  if (!InitToolhelp()) {
    printf("[!] Failed to load Toolhelp functions\n");
    system("pause");
    return 1;
  }

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

  DWORD pid = 0;
  wchar_t targets[8][128];
  int targetCount = 0;
  LoadTargetList(targets, &targetCount, 8);

  // Parse args: --pid N  or  process.exe
  for (int i = 1; i < argc; i++) {
    if (!argv[i])
      continue;
    if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
      pid = (DWORD)_wtoi(argv[i + 1]);
      i++;
      continue;
    }
    if (argv[i][0] == L'-')
      continue;
    // treat as process name — put first
    wcscpy_s(targets[0], 128, argv[i]);
    targetCount = 1;
  }

  if (pid) {
    printf("[*] Using --pid %lu\n", pid);
  } else {
    printf("[*] Looking for:");
    for (int i = 0; i < targetCount; i++)
      wprintf(L" %s", targets[i]);
    printf("\n");

    for (int i = 0; i < targetCount && !pid; i++)
      pid = FindPid(targets[i]);

    if (!pid) {
      printf("[*] Waiting for game to start ...\n");
      while (!pid) {
        for (int i = 0; i < targetCount && !pid; i++)
          pid = FindPid(targets[i]);
        Sleep(1000);
      }
    }
  }

  int rc = DoInject(pid, dllPath);

  printf("\nDone. Press any key to close Injector...\n");
  system("pause");
  return rc;
}
