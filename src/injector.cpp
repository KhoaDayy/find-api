/*
 *  Injector.cpp  –  Injects GameHook.dll into yysls.exe
 *  No TlHelp32.h dependency (uses runtime-loaded functions)
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

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

int wmain() {
  const wchar_t *target = L"yysls.exe";

  printf("=== Direct DLL Injector ===\n");
  printf("Target: yysls.exe\n\n");

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
  printf("[*] Looking for %ls ...\n", target);
  DWORD pid = FindPid(target);
  if (!pid) {
    printf("[*] Waiting for game to start ...\n");
    while (!pid) {
      pid = FindPid(target);
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

  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);
  VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
  CloseHandle(hProc);

  return 0;
}
