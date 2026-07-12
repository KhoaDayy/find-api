#include "hook/lua_runtime_hook.h"
#include "MinHook.h"
#include "hook/capture_writer.h"
#include "pattern_scan.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <set>
#include <string>
#include <vector>

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

std::string HexPtr(uintptr_t p) {
  char b[32];
  _snprintf_s(b, _TRUNCATE, "0x%llX", (unsigned long long)p);
  return b;
}

void BootPrintf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  // Also append to hook_boot.log via a tiny open (no shared BootLog linkage).
  char dir[MAX_PATH] = {};
  GetModuleFileNameA(nullptr, dir, MAX_PATH); // process exe — fine for visibility
  // Prefer DLL-adjacent boot log: path stored in g_dllDir when set.
  std::string logPath =
      g_dllDir.empty() ? std::string("hook_boot.log") : (g_dllDir + "hook_boot.log");
  FILE *f = nullptr;
  if (fopen_s(&f, logPath.c_str(), "a") == 0 && f) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond,
            st.wMilliseconds, buf);
    fflush(f);
    fclose(f);
  }
  printf("%s\n", buf);
  fflush(stdout);
}

void InjectLuaScript(lua_State *L) {
  if (!g_lua_load || !g_lua_pcallk_orig || !L)
    return;
  {
    std::lock_guard<std::mutex> lock(g_stateMu);
    if (g_injected.count(L))
      return;
  }

  BootPrintf("lua_State observed %p", L);
  BootPrintf("face_share_logger.lua load started");

  std::string script = ReadTextFile(g_scriptPath);
  if (script.empty()) {
    WriteCaptureEvent("native", "lua_inject_error",
                      "{\"error\":\"script_not_found\",\"path\":" + JsonString(g_scriptPath) +
                          "}");
    BootPrintf("[!] Cannot read script: %s", g_scriptPath.c_str());
    return;
  }

  std::string outPath = ResolveCaptureOutputPath(g_dllDir, g_cfg);
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
  BootPrintf("lua_load size=%zu L=%p", full.size(), L);
  int rc = g_lua_load(L, lua_reader_cb, &ls, "=(face_share_logger)", "t");
  BootPrintf("lua_load rc=%d", rc);
  if (rc != 0) {
    WriteCaptureEvent("native", "lua_load_failed", "{\"code\":" + std::to_string(rc) + "}");
    // Cannot safely read Lua error string without lua_tolstring — leave code only.
    return;
  }
  rc = g_lua_pcallk_orig(L, 0, 0, 0, nullptr, nullptr);
  BootPrintf("lua_pcall rc=%d", rc);
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
  BootPrintf("face_share_logger.lua injected OK L=%p", L);
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
        BootPrintf("[!] Exception during lua inject");
      }
      g_insideLuaInjection = false;
    }
  }
  return g_lua_pcallk_orig(L, nargs, nresults, msgh, ctx, k);
}

GetModuleInformation_t ResolveGetModuleInformation() {
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
  return gmi;
}

bool GetModuleExecRange(HMODULE h, uintptr_t &base, size_t &size) {
  if (!h)
    return false;
  GetModuleInformation_t gmi = ResolveGetModuleInformation();
  if (!gmi)
    return false;
  MY_MODULEINFO mi{};
  if (!gmi(GetCurrentProcess(), h, &mi, sizeof(mi)))
    return false;
  base = (uintptr_t)mi.lpBaseOfDll;
  size = (size_t)mi.SizeOfImage;
  return base && size;
}

bool GetModuleExecRangeByName(const char *modName, uintptr_t &base, size_t &size) {
  return GetModuleExecRange(GetModuleHandleA(modName), base, size);
}

std::string NarrowPath(const wchar_t *w) {
  if (!w)
    return {};
  char buf[MAX_PATH] = {};
  WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, MAX_PATH, nullptr, nullptr);
  return buf;
}

std::string DirOf(const std::string &path) {
  size_t p = path.find_last_of("\\/");
  if (p == std::string::npos)
    return {};
  return path.substr(0, p + 1);
}

std::string BaseName(const std::string &path) {
  size_t p = path.find_last_of("\\/");
  if (p == std::string::npos)
    return path;
  return path.substr(p + 1);
}

bool IEquals(const std::string &a, const std::string &b) {
  if (a.size() != b.size())
    return false;
  for (size_t i = 0; i < a.size(); i++) {
    if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
      return false;
  }
  return true;
}

bool ContainsI(const std::string &hay, const char *needle) {
  std::string h = hay, n = needle;
  for (char &c : h)
    c = (char)std::tolower((unsigned char)c);
  for (char &c : n)
    c = (char)std::tolower((unsigned char)c);
  return h.find(n) != std::string::npos;
}

// Game-dir modules only (same directory as main exe). Skip system DLLs.
struct ScanCandidate {
  std::string name;
  std::string path;
  HMODULE hmod = nullptr;
  uintptr_t base = 0;
  size_t size = 0;
};

std::vector<ScanCandidate> CollectGameModules(const HookConfig &cfg) {
  std::vector<ScanCandidate> out;

  char exePath[MAX_PATH] = {};
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string gameDir = DirOf(exePath);
  std::string exeName = BaseName(exePath);

  // Always include main EXE first.
  {
    ScanCandidate c;
    c.name = exeName;
    c.path = exePath;
    c.hmod = GetModuleHandleA(nullptr);
    if (GetModuleExecRange(c.hmod, c.base, c.size))
      out.push_back(c);
  }

  // Named targets from config (if different from main).
  for (const auto &tp : cfg.target_processes) {
    if (IEquals(tp, exeName))
      continue;
    HMODULE h = GetModuleHandleA(tp.c_str());
    if (!h)
      continue;
    ScanCandidate c;
    c.name = tp;
    char p[MAX_PATH] = {};
    GetModuleFileNameA(h, p, MAX_PATH);
    c.path = p;
    c.hmod = h;
    if (GetModuleExecRange(h, c.base, c.size))
      out.push_back(c);
  }

  // Other modules loaded from the game directory with lua-ish names.
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                         GetCurrentProcessId());
  if (snap == INVALID_HANDLE_VALUE)
    return out;

  MODULEENTRY32W me{};
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      std::string path = NarrowPath(me.szExePath);
      std::string name = NarrowPath(me.szModule);
      if (path.empty())
        continue;
      // Same directory as game only.
      if (!gameDir.empty() && !IEquals(DirOf(path), gameDir))
        continue;
      // Skip if already listed.
      bool dup = false;
      for (const auto &e : out) {
        if (e.hmod == me.hModule) {
          dup = true;
          break;
        }
      }
      if (dup)
        continue;
      // Prefer modules that look related to script runtime.
      bool interesting = ContainsI(name, "lua") || ContainsI(name, "script") ||
                         ContainsI(name, "hexm") || ContainsI(name, "wwm") ||
                         ContainsI(name, "yysls") || ContainsI(name, "engine") ||
                         ContainsI(name, "client");
      if (!interesting)
        continue;
      ScanCandidate c;
      c.name = name;
      c.path = path;
      c.hmod = me.hModule;
      if (GetModuleExecRange(me.hModule, c.base, c.size))
        out.push_back(c);
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return out;
}

struct SigResult {
  size_t matches = 0;
  uintptr_t selected = 0;
  std::string status; // ok | SIGNATURE_NOT_FOUND | SIGNATURE_AMBIGUOUS
};

SigResult EvaluateSig(const std::vector<uintptr_t> &hits) {
  SigResult r;
  r.matches = hits.size();
  if (hits.empty()) {
    r.status = "SIGNATURE_NOT_FOUND";
    r.selected = 0;
  } else if (hits.size() == 1) {
    r.status = "ok";
    r.selected = hits[0];
  } else {
    r.status = "SIGNATURE_AMBIGUOUS";
    r.selected = 0; // never first-match when ambiguous
  }
  return r;
}

void EmitSigEvent(const char *name, uintptr_t base, const SigResult &r) {
  std::string data = "{";
  data += "\"name\":" + JsonString(name) + ",";
  data += "\"matches\":" + std::to_string(r.matches) + ",";
  data += "\"selected_address\":";
  if (r.selected)
    data += JsonString(HexPtr(r.selected));
  else
    data += "null";
  data += ",\"selected_offset\":";
  if (r.selected && base)
    data += JsonString(HexPtr(r.selected - base));
  else
    data += "null";
  data += ",\"status\":" + JsonString(r.status);
  data += "}";
  WriteCaptureEvent("native", "lua_signature", data);
  BootPrintf("sig %s matches=%zu status=%s addr=%s", name, r.matches, r.status.c_str(),
             r.selected ? HexPtr(r.selected).c_str() : "null");
}

} // namespace

bool InstallLuaRuntimeHook(const HookConfig &cfg, const std::string &dllDir) {
  g_cfg = cfg;
  g_dllDir = dllDir;
  g_scriptPath = ResolvePath(dllDir, cfg.lua_script);
  g_pendingInject = true;

  // Script resolve diagnostics.
  DWORD attr = GetFileAttributesA(g_scriptPath.c_str());
  bool exists = attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
  size_t fsize = 0;
  if (exists) {
    std::string t = ReadTextFile(g_scriptPath);
    fsize = t.size();
  }
  WriteCaptureEvent("native", "lua_script_resolved",
                    "{\"path\":" + JsonString(g_scriptPath) +
                        ",\"exists\":" + JsonBool(exists) +
                        ",\"size\":" + std::to_string(fsize) + "}");
  BootPrintf("lua_script_resolved path=%s exists=%d size=%zu", g_scriptPath.c_str(),
             exists ? 1 : 0, fsize);
  if (!exists) {
    BootPrintf("[!] Lua script missing — abort install");
    return false;
  }

  char exePath[MAX_PATH] = {};
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string exeName = BaseName(exePath);

  auto candidates = CollectGameModules(cfg);
  if (candidates.empty()) {
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"target_module_not_found\"}");
    BootPrintf("[!] No game modules for Lua pattern scan");
    return false;
  }

  // Primary scan start event (main module).
  {
    const auto &m = candidates[0];
    WriteCaptureEvent(
        "native", "lua_scan_start",
        std::string("{\"pid\":") + std::to_string(GetCurrentProcessId()) +
            ",\"exe\":" + JsonString(exeName) + ",\"module\":" + JsonString(m.name) +
            ",\"base\":" + JsonString(HexPtr(m.base)) +
            ",\"image_size\":" + std::to_string(m.size) + "}");
    BootPrintf("lua_scan_start pid=%lu exe=%s module=%s base=%s size=%zu",
               GetCurrentProcessId(), exeName.c_str(), m.name.c_str(),
               HexPtr(m.base).c_str(), m.size);
  }

  uintptr_t chosenLoad = 0;
  uintptr_t chosenPcall = 0;
  std::string chosenModule;

  for (const auto &m : candidates) {
    auto loadHits = PatternScanAll(m.base, m.size, cfg.sig_lua_load.c_str());
    auto pcallHits = PatternScanAll(m.base, m.size, cfg.sig_lua_pcall.c_str());
    SigResult loadR = EvaluateSig(loadHits);
    SigResult pcallR = EvaluateSig(pcallHits);

    WriteCaptureEvent(
        "native", "lua_scan_module",
        std::string("{\"name\":") + JsonString(m.name) + ",\"path\":" + JsonString(m.path) +
            ",\"size\":" + std::to_string(m.size) +
            ",\"lua_load_matches\":" + std::to_string(loadR.matches) +
            ",\"lua_pcall_matches\":" + std::to_string(pcallR.matches) + "}");
    BootPrintf("scan module=%s size=%zu load=%zu pcall=%zu", m.name.c_str(), m.size,
               loadR.matches, pcallR.matches);

    // Per-signature detail on the module we are considering.
    EmitSigEvent("lua_load", m.base, loadR);
    EmitSigEvent("lua_pcallk", m.base, pcallR);

    if (loadR.status == "ok" && pcallR.status == "ok" && !chosenLoad) {
      chosenLoad = loadR.selected;
      chosenPcall = pcallR.selected;
      chosenModule = m.name;
      // Keep scanning remaining modules for diagnostics, but lock first exact pair.
    }
  }

  if (!chosenLoad || !chosenPcall) {
    BootPrintf("[!] Refusing to hook: no module with exactly 1 lua_load + 1 lua_pcallk");
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"SIGNATURE_NOT_FOUND_OR_AMBIGUOUS\"}");
    return false;
  }

  BootPrintf("lua_load resolved %s", HexPtr(chosenLoad).c_str());
  BootPrintf("lua_pcallk resolved %s module=%s", HexPtr(chosenPcall).c_str(),
             chosenModule.c_str());

  g_lua_load = (lua_load_fn)chosenLoad;
  void *pcallAddr = (void *)chosenPcall;

  MH_STATUS stCreate =
      MH_CreateHook(pcallAddr, (LPVOID)&Detour_lua_pcallk, (LPVOID *)&g_lua_pcallk_orig);
  if (stCreate != MH_OK) {
    BootPrintf("[!] MH_CreateHook lua_pcallk failed status=%d", (int)stCreate);
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"MH_CreateHook\",\"status\":" +
                          std::to_string((int)stCreate) + "}");
    return false;
  }
  BootPrintf("lua_pcallk hook created");

  MH_STATUS stEnable = MH_EnableHook(pcallAddr);
  if (stEnable != MH_OK) {
    BootPrintf("[!] MH_EnableHook lua_pcallk failed status=%d", (int)stEnable);
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"MH_EnableHook\",\"status\":" +
                          std::to_string((int)stEnable) + "}");
    return false;
  }
  BootPrintf("lua_pcallk hook enabled");

  WriteCaptureEvent("native", "lua_hook_installed",
                    "{\"script\":" + JsonString(g_scriptPath) +
                        ",\"module\":" + JsonString(chosenModule) +
                        ",\"lua_load\":" + JsonString(HexPtr(chosenLoad)) +
                        ",\"lua_pcallk\":" + JsonString(HexPtr(chosenPcall)) + "}");
  BootPrintf("[+] Lua runtime hook installed; will inject on next pcall");
  BootPrintf("[*] Script: %s", g_scriptPath.c_str());
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
  BootPrintf("F5 injection armed");
}

} // namespace face_capture
