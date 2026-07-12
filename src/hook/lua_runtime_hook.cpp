#include "hook/lua_runtime_hook.h"
#include "MinHook.h"
#include "hook/capture_writer.h"
#include "pattern_scan.h"
#include <Windows.h>
#include <mutex>
#include <set>
#include <string>

namespace face_capture {
namespace {

typedef void *lua_State;
typedef const char *(__cdecl *lua_Reader)(lua_State *L, void *ud, size_t *sz);
typedef int(__cdecl *lua_load_fn)(lua_State *L, lua_Reader reader, void *data,
                                  const char *chunkname, const char *mode);
typedef int(__cdecl *lua_pcallk_fn)(lua_State *L, int nargs, int nresults, int msgh, void *ctx,
                                    void *k);

typedef struct {
  LPVOID lpBaseOfDll;
  DWORD SizeOfImage;
  LPVOID EntryPoint;
} MY_MODULEINFO;

typedef BOOL(WINAPI *GetModuleInformation_t)(HANDLE, HMODULE, MY_MODULEINFO *, DWORD);

lua_load_fn g_lua_load = nullptr;
lua_pcallk_fn g_lua_pcallk_orig = nullptr;

HookConfig g_cfg;
std::string g_dllDir;
std::string g_scriptPath;
std::mutex g_stateMu;
std::set<lua_State *> g_injected;
bool g_pendingInject = true;
thread_local bool g_insideLuaInjection = false;

struct LoadS {
  const char *s;
  size_t size;
};

const char *__cdecl lua_reader_cb(lua_State *, void *ud, size_t *sz) {
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

std::string ReadTextFile(const std::string &path) {
  FILE *f = fopen(path.c_str(), "rb");
  if (!f)
    return {};
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (len <= 0) {
    fclose(f);
    return {};
  }
  std::string buf((size_t)len, '\0');
  fread(&buf[0], 1, (size_t)len, f);
  fclose(f);
  return buf;
}

void InjectLuaScript(lua_State *L) {
  if (!g_lua_load || !g_lua_pcallk_orig || !L)
    return;
  {
    std::lock_guard<std::mutex> lock(g_stateMu);
    if (g_injected.count(L))
      return;
  }

  std::string script = ReadTextFile(g_scriptPath);
  if (script.empty()) {
    WriteCaptureEvent("native", "lua_inject_error",
                      "{\"error\":\"script_not_found\",\"path\":" + JsonString(g_scriptPath) +
                          "}");
    printf("[!] Cannot read script: %s\n", g_scriptPath.c_str());
    return;
  }

  std::string outPath = ResolvePath(g_dllDir, g_cfg.output_file);
  // escape backslashes for Lua string
  std::string outEsc;
  for (char c : outPath) {
    if (c == '\\')
      outEsc += "\\\\";
    else if (c == '"')
      outEsc += "\\\"";
    else
      outEsc += c;
  }

  std::string preamble = std::string("-- face_share_logger injected\n") +
                         "_G.__FACE_CAPTURE_OUTPUT = \"" + outEsc + "\"\n" +
                         "_G.__FACE_CAPTURE_FULL = " +
                         (g_cfg.capture_full_face_data ? "true" : "false") + "\n";
  std::string full = preamble + script;

  LoadS ls{full.c_str(), full.size()};
  printf("[*] lua_load size=%zu L=%p\n", full.size(), L);
  int rc = g_lua_load(L, lua_reader_cb, &ls, "=(face_share_logger)", "t");
  printf("[*] lua_load -> %d\n", rc);
  if (rc != 0) {
    WriteCaptureEvent("native", "lua_load_failed", "{\"code\":" + std::to_string(rc) + "}");
    return;
  }
  rc = g_lua_pcallk_orig(L, 0, 0, 0, nullptr, nullptr);
  printf("[*] lua_pcall -> %d\n", rc);
  if (rc != 0) {
    WriteCaptureEvent("native", "lua_pcall_failed", "{\"code\":" + std::to_string(rc) + "}");
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_stateMu);
    g_injected.insert(L);
  }
  WriteCaptureEvent("native", "lua_injected",
                    "{\"script\":" + JsonString(g_scriptPath) + "}");
  printf("[+] face_share_logger.lua injected OK L=%p\n", L);
}

int __cdecl Detour_lua_pcallk(lua_State *L, int nargs, int nresults, int msgh, void *ctx,
                              void *k) {
  if (g_pendingInject && !g_insideLuaInjection && L) {
    bool need = false;
    {
      std::lock_guard<std::mutex> lock(g_stateMu);
      need = g_injected.find(L) == g_injected.end();
    }
    if (need) {
      g_insideLuaInjection = true;
      try {
        InjectLuaScript(L);
      } catch (...) {
        printf("[!] Exception during lua inject\n");
      }
      g_insideLuaInjection = false;
    }
  }
  return g_lua_pcallk_orig(L, nargs, nresults, msgh, ctx, k);
}

bool GetModuleExecRange(const char *modName, uintptr_t &base, size_t &size) {
  HMODULE h = GetModuleHandleA(modName);
  if (!h)
    return false;
  HMODULE ps = LoadLibraryA("Psapi.dll");
  GetModuleInformation_t gmi = nullptr;
  if (ps) {
    gmi = (GetModuleInformation_t)GetProcAddress(ps, "GetModuleInformation");
    if (!gmi)
      gmi = (GetModuleInformation_t)GetProcAddress(ps, "K32GetModuleInformation");
  }
  if (!gmi)
    gmi = (GetModuleInformation_t)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                                 "K32GetModuleInformation");
  if (!gmi)
    return false;
  MY_MODULEINFO mi{};
  if (!gmi(GetCurrentProcess(), h, &mi, sizeof(mi)))
    return false;
  base = (uintptr_t)mi.lpBaseOfDll;
  size = (size_t)mi.SizeOfImage;
  return base && size;
}

} // namespace

bool InstallLuaRuntimeHook(const HookConfig &cfg, const std::string &dllDir) {
  g_cfg = cfg;
  g_dllDir = dllDir;
  g_scriptPath = ResolvePath(dllDir, cfg.lua_script);
  g_pendingInject = true;

  const char *mods[] = {cfg.target_process.c_str(), "yysls.exe", "wwm.exe", nullptr};
  uintptr_t base = 0;
  size_t size = 0;
  const char *used = nullptr;
  for (int i = 0; mods[i]; i++) {
    if (GetModuleExecRange(mods[i], base, size)) {
      used = mods[i];
      break;
    }
  }
  if (!base) {
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"target_module_not_found\"}");
    printf("[!] Target module not found for Lua patterns\n");
    return false;
  }

  auto loadHits = PatternScanAll(base, size, cfg.sig_lua_load.c_str());
  auto pcallHits = PatternScanAll(base, size, cfg.sig_lua_pcall.c_str());
  printf("[*] Pattern lua_load matches=%zu lua_pcall matches=%zu module=%s\n", loadHits.size(),
         pcallHits.size(), used ? used : "?");
  WriteCaptureEvent("native", "pattern_scan",
                    std::string("{\"module\":") + JsonString(used ? used : "") +
                        ",\"lua_load_matches\":" + std::to_string(loadHits.size()) +
                        ",\"lua_pcall_matches\":" + std::to_string(pcallHits.size()) + "}");

  if (loadHits.size() != 1 || pcallHits.size() != 1) {
    printf("[!] Refusing to hook: need exactly 1 match each (got load=%zu pcall=%zu)\n",
           loadHits.size(), pcallHits.size());
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"ambiguous_or_missing_signature\"}");
    return false;
  }

  g_lua_load = (lua_load_fn)loadHits[0];
  void *pcallAddr = (void *)pcallHits[0];

  if (MH_CreateHook(pcallAddr, (LPVOID)&Detour_lua_pcallk, (LPVOID *)&g_lua_pcallk_orig) !=
      MH_OK) {
    printf("[!] MH_CreateHook lua_pcallk failed\n");
    return false;
  }
  if (MH_EnableHook(pcallAddr) != MH_OK) {
    printf("[!] MH_EnableHook lua_pcallk failed\n");
    return false;
  }

  WriteCaptureEvent("native", "lua_hook_installed",
                    "{\"script\":" + JsonString(g_scriptPath) + "}");
  printf("[+] Lua runtime hook installed; will inject on next pcall\n");
  printf("[*] Script: %s\n", g_scriptPath.c_str());
  return true;
}

void UninstallLuaRuntimeHook() {
  std::lock_guard<std::mutex> lock(g_stateMu);
  g_injected.clear();
  g_pendingInject = false;
}

void RequestLuaInject() {
  std::lock_guard<std::mutex> lock(g_stateMu);
  g_injected.clear();
  g_pendingInject = true;
  printf("[*] Lua re-inject requested (F5)\n");
}

} // namespace face_capture
