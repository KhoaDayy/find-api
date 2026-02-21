#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstring>
#include <stdio.h>
#include <string>
#include <winhttp.h>

#include "MinHook.h"
#include "pattern_scan.h"

/* --- runtime Psapi (avoid header issues) --- */
typedef struct {
  LPVOID lpBaseOfDll;
  DWORD SizeOfImage;
  LPVOID EntryPoint;
} MY_MODULEINFO;

typedef BOOL(WINAPI *GetModuleInformation_t)(HANDLE hProcess, HMODULE hModule,
                                             MY_MODULEINFO *lpmodinfo,
                                             DWORD cb);

static GetModuleInformation_t pGetModuleInformation = nullptr;

static bool InitPsapi() {
  HMODULE h = LoadLibraryA("Psapi.dll");
  if (!h)
    h = LoadLibraryA("kernel32.dll");
  if (!h)
    return false;
  pGetModuleInformation =
      (GetModuleInformation_t)GetProcAddress(h, "GetModuleInformation");
  if (!pGetModuleInformation)
    pGetModuleInformation =
        (GetModuleInformation_t)GetProcAddress(h, "K32GetModuleInformation");
  return pGetModuleInformation != nullptr;
}

/* ============================================================
 *  CONFIG
 * ============================================================ */
#define TARGET_MODULE "yysls.exe"
#define SESSION_FILE "C:\\Users\\AD\\Desktop\\find api\\session.txt"

/* ============================================================
 *  Lua 5.4 compatible types
 * ============================================================ */
typedef void *lua_State;
typedef const char *(__cdecl *lua_Reader)(lua_State *L, void *ud, size_t *sz);

typedef int(__cdecl *lua_load_fn)(lua_State *L, lua_Reader reader, void *data,
                                  const char *chunkname, const char *mode);

typedef int(__cdecl *lua_pcallk_fn)(lua_State *L, int nargs, int nresults,
                                    int msgh, void *ctx, void *k);

/* ============================================================
 *  Globals
 * ============================================================ */
static HMODULE g_hSelf = NULL;
static lua_load_fn g_lua_load = nullptr;
static lua_pcallk_fn g_lua_pcallk_orig = nullptr;
static bool g_pendingInject = false;
static bool g_inInjection = false;
static bool g_running = true;

/* ============================================================
 *  Session capture globals
 * ============================================================ */
static char g_lastSession[256] = {0};
static bool g_sessionSaved = false;

static void SaveSession(const char *session) {
  if (!session || strlen(session) < 5)
    return;

  // Don't save duplicates
  if (strcmp(g_lastSession, session) == 0 && g_sessionSaved)
    return;

  strncpy(g_lastSession, session, sizeof(g_lastSession) - 1);
  g_lastSession[sizeof(g_lastSession) - 1] = '\0';
  g_sessionSaved = true;

  FILE *f = fopen(SESSION_FILE, "w");
  if (f) {
    fprintf(f, "%s", session);
    fclose(f);
    printf("[SESSION] Saved: %s\n", session);
  }
}

// Extract session= from URL string
static void TryExtractSession(const char *url, size_t len) {
  if (!url || len < 10)
    return;

  // Search for "session=" in the string
  for (size_t i = 0; i + 8 < len; i++) {
    if (memcmp(url + i, "session=", 8) == 0) {
      const char *start = url + i + 8;
      size_t remaining = len - i - 8;

      // Find end of session value (& or space or end)
      size_t slen = 0;
      while (slen < remaining && slen < 200 && start[slen] != '&' &&
             start[slen] != ' ' && start[slen] != '\0' && start[slen] != '\r' &&
             start[slen] != '\n') {
        slen++;
      }

      if (slen > 5 && slen < 200) {
        char sess[256] = {0};
        memcpy(sess, start, slen);
        sess[slen] = '\0';
        SaveSession(sess);
      }
      return;
    }
  }
}

// Extract session= from wide string URL
static void TryExtractSessionW(const wchar_t *url, size_t wlen) {
  if (!url || wlen < 10)
    return;

  // Convert to narrow string for easier parsing
  char narrow[4096] = {0};
  size_t maxLen = (wlen < sizeof(narrow) - 1) ? wlen : sizeof(narrow) - 1;
  for (size_t i = 0; i < maxLen; i++) {
    narrow[i] = (char)(url[i] & 0xFF);
  }
  narrow[maxLen] = '\0';

  TryExtractSession(narrow, maxLen);
}

/* ============================================================
 *  WinHTTP Hook - WinHttpOpenRequest (Sniffer)
 * ============================================================ */
typedef HINTERNET(WINAPI *WinHttpOpenRequest_fn)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags);

static WinHttpOpenRequest_fn g_origWinHttpOpenRequest = nullptr;

static HINTERNET WINAPI Detour_WinHttpOpenRequest(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags) {

  // Convert path/URL to narrow string for printing
  char nObjName[512] = {0};
  if (pwszObjectName) {
    size_t wlen = wcslen(pwszObjectName);
    TryExtractSessionW(pwszObjectName, wlen);

    size_t maxLen = (wlen < sizeof(nObjName) - 1) ? wlen : sizeof(nObjName) - 1;
    for (size_t i = 0; i < maxLen; i++) {
      nObjName[i] = (char)(pwszObjectName[i] & 0xFF);
    }
    nObjName[maxLen] = '\0';
  }

  char nVerb[16] = {0};
  if (pwszVerb) {
    size_t vlen = wcslen(pwszVerb);
    size_t maxVlen = (vlen < 15) ? vlen : 15;
    for (size_t i = 0; i < maxVlen; i++)
      nVerb[i] = (char)(pwszVerb[i] & 0xFF);
  }

  printf("\n[WinHTTP] %s %s\n", pwszVerb ? nVerb : "GET", nObjName);

  return g_origWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName,
                                  pwszVersion, pwszReferrer, ppwszAcceptTypes,
                                  dwFlags);
}

/* ============================================================
 *  WinHTTP Hook - WinHttpSendRequest (Sniffer)
 * ============================================================ */
typedef BOOL(WINAPI *WinHttpSendRequest_fn)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext);

static WinHttpSendRequest_fn g_origWinHttpSendRequest = nullptr;

static BOOL WINAPI Detour_WinHttpSendRequest(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext) {

  printf("\n[WinHTTP] ---> SEND REQUEST\n");

  // Print Headers if available
  if (lpszHeaders && dwHeadersLength > 0) {
    TryExtractSessionW(lpszHeaders, dwHeadersLength);

    // Output headers for RE (Limit to 512 chars to avoid spam)
    char hdr[1024] = {0};
    size_t maxHdr =
        (dwHeadersLength < sizeof(hdr) - 1) ? dwHeadersLength : sizeof(hdr) - 1;
    for (size_t i = 0; i < maxHdr; i++) {
      hdr[i] = (char)(lpszHeaders[i] & 0xFF);
    }
    hdr[maxHdr] = '\0';
    printf("[HEADERS]\n%s\n", hdr);
  }

  // Print Payload (lpOptional) if available
  if (lpOptional && dwOptionalLength > 0) {
    char payloadStr[2048] = {0};
    DWORD cpyLen = (dwOptionalLength < (sizeof(payloadStr) - 1))
                       ? dwOptionalLength
                       : (sizeof(payloadStr) - 1);
    memcpy(payloadStr, lpOptional, cpyLen);
    payloadStr[cpyLen] = '\0';

    // Check if payload is printable ASCII/JSON, otherwise print hex
    bool isPrintable = true;
    for (DWORD i = 0; i < cpyLen; i++) {
      if (payloadStr[i] < 32 && payloadStr[i] != '\n' &&
          payloadStr[i] != '\r' && payloadStr[i] != '\t') {
        isPrintable = false;
        break;
      }
    }

    if (isPrintable) {
      printf("[PAYLOAD] (len=%lu)\n%s\n", dwOptionalLength, payloadStr);
    } else {
      printf("[PAYLOAD RAW] (len=%lu) <Non-printable binary data, possibly "
             "msgpack>\n",
             dwOptionalLength);
      // Print first 32 bytes hex for id
      printf("HEX: ");
      for (DWORD i = 0; i < 32 && i < dwOptionalLength; i++) {
        printf("%02X ", ((unsigned char *)lpOptional)[i]);
      }
      printf("\n");
    }
  }
  printf("[WinHTTP] <--- END SEND REQUEST\n\n");

  return g_origWinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength,
                                  lpOptional, dwOptionalLength, dwTotalLength,
                                  dwContext);
}

/* ============================================================
 *  LoadS struct + reader  (mirrors Lua 5.4 lauxlib.c)
 * ============================================================ */
struct LoadS {
  const char *s;
  size_t size;
};

static const char *__cdecl lua_reader_cb(lua_State * /*L*/, void *ud,
                                         size_t *sz) {
  LoadS *ls = (LoadS *)ud;
  if (ls->size == 0) {
    *sz = 0;
    return nullptr;
  }
  *sz = ls->size;
  const char *r = ls->s;
  ls->size = 0;
  return r;
}

/* ============================================================
 *  Helpers
 * ============================================================ */
static std::string GetDllDir() {
  char path[MAX_PATH];
  GetModuleFileNameA(g_hSelf, path, MAX_PATH);
  char *p = strrchr(path, '\\');
  if (p)
    *(p + 1) = '\0';
  return path;
}

static std::string ReadTextFile(const std::string &path) {
  FILE *f = fopen(path.c_str(), "rb");
  if (!f)
    return "";
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::string buf(len, '\0');
  fread(&buf[0], 1, len, f);
  fclose(f);
  return buf;
}

/* ============================================================
 *  Inject Lua script through the game's own lua_load
 * ============================================================ */
static void InjectLuaScript(lua_State *L) {
  std::string scriptPath = GetDllDir() + "Scripts\\api_logger.lua";
  std::string script = ReadTextFile(scriptPath);

  if (script.empty()) {
    printf("[!] Cannot read script: %s\n", scriptPath.c_str());
    return;
  }

  LoadS ls = {script.c_str(), script.size()};
  printf("[*] lua_load  (size=%zu)  L=%p\n", script.size(), L);

  int rc = g_lua_load(L, lua_reader_cb, &ls, "=(api_logger)", "t");
  printf("[*] lua_load  -> %d\n", rc);
  if (rc != 0) {
    printf("[!] lua_load failed (%d)\n", rc);
    return;
  }

  rc = g_lua_pcallk_orig(L, 0, 0, 0, nullptr, nullptr);
  printf("[*] lua_pcall -> %d\n", rc);
  if (rc != 0) {
    printf("[!] lua_pcall failed (%d)\n", rc);
    return;
  }

  printf("[+] api_logger.lua injected OK!\n");
}

/* ============================================================
 *  Detour  –  lua_pcallk
 * ============================================================ */
static int __cdecl Detour_lua_pcallk(lua_State *L, int nargs, int nresults,
                                     int msgh, void *ctx, void *k) {
  if (g_pendingInject && !g_inInjection) {
    g_pendingInject = false;
    g_inInjection = true;
    __try {
      InjectLuaScript(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      printf("[!] SEH exception during injection\n");
    }
    g_inInjection = false;
  }
  return g_lua_pcallk_orig(L, nargs, nresults, msgh, ctx, k);
}

/* ============================================================
 *  Signatures
 * ============================================================ */
static const char *SIG_LUA_LOAD =
    "48 89 5C 24 10 56 48 83 EC 50 49 8B D9 48 8B F1 "
    "4D 8B C8 4C 8B C2 48 8D 54 24 20";

static const char *SIG_LUA_PCALL =
    "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58 "
    "49 63 C1 41 8B E8 48 8B F9 45 85 C9";

/* ============================================================
 *  Setup WinHTTP hooks for session capture
 * ============================================================ */
static bool SetupWinHttpHooks() {
  HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
  if (!hWinHttp) {
    hWinHttp = LoadLibraryA("winhttp.dll");
  }
  if (!hWinHttp) {
    printf("[!] winhttp.dll not found\n");
    return false;
  }

  // Hook WinHttpOpenRequest
  void *pOpenRequest = GetProcAddress(hWinHttp, "WinHttpOpenRequest");
  if (pOpenRequest) {
    if (MH_CreateHook(pOpenRequest, (LPVOID)&Detour_WinHttpOpenRequest,
                      (LPVOID *)&g_origWinHttpOpenRequest) == MH_OK) {
      MH_EnableHook(pOpenRequest);
      printf("[+] Hooked WinHttpOpenRequest\n");
    }
  }

  // Hook WinHttpSendRequest
  void *pSendRequest = GetProcAddress(hWinHttp, "WinHttpSendRequest");
  if (pSendRequest) {
    if (MH_CreateHook(pSendRequest, (LPVOID)&Detour_WinHttpSendRequest,
                      (LPVOID *)&g_origWinHttpSendRequest) == MH_OK) {
      MH_EnableHook(pSendRequest);
      printf("[+] Hooked WinHttpSendRequest\n");
    }
  }

  return (g_origWinHttpOpenRequest || g_origWinHttpSendRequest);
}

/* ============================================================
 *  Worker thread
 * ============================================================ */
static DWORD WINAPI MainThread(LPVOID) {
  AllocConsole();
  SetConsoleTitleA("Game API Hook  |  F5 = Inject  |  F6 = Exit");
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);

  printf("========================================\n");
  printf("  Game API Hook  +  Session Capture\n");
  printf("  Target : %s\n", TARGET_MODULE);
  printf("========================================\n\n");

  /* --- wait for module --- */
  HMODULE hMod = nullptr;
  printf("[*] Waiting for module %s ...\n", TARGET_MODULE);
  while (!hMod && g_running) {
    hMod = GetModuleHandleA(TARGET_MODULE);
    if (!hMod)
      Sleep(200);
  }
  if (!hMod)
    return 0;

  if (!InitPsapi()) {
    printf("[!] Failed to load Psapi functions\n");
    return 0;
  }

  MY_MODULEINFO mi = {};
  pGetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi));
  printf("[+] %s  base=%p  size=0x%lX\n", TARGET_MODULE, mi.lpBaseOfDll,
         mi.SizeOfImage);

  /* --- signature scan --- */
  uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
  uintptr_t addrLoad = PatternScan(base, mi.SizeOfImage, SIG_LUA_LOAD);
  uintptr_t addrPcall = PatternScan(base, mi.SizeOfImage, SIG_LUA_PCALL);

  if (!addrLoad)
    printf("[!] lua_load  signature NOT found (Lua injection disabled)\n");
  if (!addrPcall)
    printf("[!] lua_pcall signature NOT found (Lua injection disabled)\n");

  if (addrLoad && addrPcall) {
    printf("[+] lua_load  @ %p  (+0x%llX)\n", (void *)addrLoad,
           (unsigned long long)(addrLoad - base));
    printf("[+] lua_pcall @ %p  (+0x%llX)\n", (void *)addrPcall,
           (unsigned long long)(addrPcall - base));

    g_lua_load = (lua_load_fn)addrLoad;

    if (MH_CreateHook((LPVOID)addrPcall, (LPVOID)&Detour_lua_pcallk,
                      (LPVOID *)&g_lua_pcallk_orig) == MH_OK) {
      MH_EnableHook((LPVOID)addrPcall);
      printf("[+] Lua hooks installed!\n");
    }
  }

  /* --- MinHook Init --- */
  if (MH_Initialize() != MH_OK) {
    printf("[!] MH_Initialize failed\n");
    return 0;
  }
  printf("[*] Setting up WinHTTP session capture...\n");
  if (SetupWinHttpHooks()) {
    printf("[+] WinHTTP hooks active - session will be auto-captured!\n");
  } else {
    printf("[!] WinHTTP hooks failed - try manual session capture\n");
  }

  printf("\n[*] Press F5 to inject api_logger.lua\n");
  printf("[*] Press F6 to unhook & exit\n");
  printf("[*] Session auto-saves to: %s\n\n", SESSION_FILE);

  /* --- hotkey loop --- */
  while (g_running) {
    if (GetAsyncKeyState(VK_F5) & 0x1) {
      printf("[>] F5 – injection armed\n");
      g_pendingInject = true;
    }
    if (GetAsyncKeyState(VK_F6) & 0x1) {
      printf("[>] F6 – shutting down\n");
      g_running = false;
    }

    // Show session status periodically
    static int tick = 0;
    if (++tick % 100 == 0 && g_sessionSaved) {
      printf("[SESSION] Current: %.20s...\n", g_lastSession);
    }

    Sleep(100);
  }

  /* --- cleanup --- */
  MH_DisableHook(MH_ALL_HOOKS);
  MH_Uninitialize();
  printf("[*] Hooks removed.\n");
  FreeConsole();
  FreeLibraryAndExitThread(g_hSelf, 0);
  return 0;
}

/* ============================================================
 *  DllMain
 * ============================================================ */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_hSelf = hModule;
    DisableThreadLibraryCalls(hModule);
    CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
  }
  return TRUE;
}
