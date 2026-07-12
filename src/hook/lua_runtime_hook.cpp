#include "hook/lua_runtime_hook.h"
#include "MinHook.h"
#include "hook/capture_writer.h"
#include "hook/lua_signature_probe.h"
#include "hook/lua_signatures.h"
#include "pattern_scan.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace face_capture {
namespace {

typedef void *lua_State;
typedef const char *(__cdecl *lua_Reader)(lua_State *L, void *ud, size_t *sz);
typedef int(__cdecl *lua_load_fn)(lua_State *L, lua_Reader reader, void *data,
                                  const char *chunkname, const char *mode);
// luaL_loadbufferx(L, buff, size, name, mode)
typedef int(__cdecl *luaL_loadbufferx_fn)(lua_State *L, const char *buff, size_t sz,
                                          const char *name, const char *mode);
typedef int(__cdecl *lua_pcallk_fn)(lua_State *L, int nargs, int nresults, int msgh, void *ctx,
                                    void *k);

typedef struct {
  LPVOID lpBaseOfDll;
  DWORD SizeOfImage;
  LPVOID EntryPoint;
} MY_MODULEINFO;

typedef BOOL(WINAPI *GetModuleInformation_t)(HANDLE, HMODULE, MY_MODULEINFO *, DWORD);

lua_load_fn g_lua_load = nullptr;
luaL_loadbufferx_fn g_lua_loadbufferx = nullptr;
lua_pcallk_fn g_lua_pcallk_orig = nullptr;
LuaLoaderKind g_loaderKind = LuaLoaderKind::None;

HookConfig g_cfg;
std::string g_dllDir;
std::string g_scriptPath;

// --- Atomic / fixed-capacity state (no std::mutex / std::set on hot paths) ---
static volatile LONG g_hookState = (LONG)LuaHookState::Disabled;
static volatile LONG g_pendingInject = 0;
// F6 one-shot CN→Global arm; consumed in InjectLuaScript bootstrap.
static volatile LONG g_pendingCnToGlobalArm = 0;
static bool g_cnToGlobalEnabled = false;
static SRWLOCK g_stateLock = SRWLOCK_INIT;
static constexpr int kMaxInjected = 8;
static lua_State *g_injectedStates[kMaxInjected] = {};
static volatile LONG g_injectedCount = 0;
static thread_local bool g_insideLuaInjection = false;
static volatile LONG g_pcallObsCount = 0;
static constexpr LONG kMaxPcallObs = 20;

struct LoadS {
  const char *s;
  size_t size;
};

void SetHookState(LuaHookState s) { InterlockedExchange(&g_hookState, (LONG)s); }

LuaHookState GetHookStateLocal() { return (LuaHookState)InterlockedCompareExchange(&g_hookState, 0, 0); }

void BootPrintf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  std::string logPath =
      g_dllDir.empty() ? std::string("hook_boot.log") : (g_dllDir + "hook_boot.log");
  FILE *f = nullptr;
  if (fopen_s(&f, logPath.c_str(), "a") == 0 && f) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            buf);
    fflush(f);
    fclose(f);
  }
  printf("%s\n", buf);
  fflush(stdout);
}

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

bool StateAlreadyInjected(lua_State *L) {
  AcquireSRWLockShared(&g_stateLock);
  bool hit = false;
  LONG n = g_injectedCount;
  if (n > kMaxInjected)
    n = kMaxInjected;
  for (LONG i = 0; i < n; i++) {
    if (g_injectedStates[i] == L) {
      hit = true;
      break;
    }
  }
  ReleaseSRWLockShared(&g_stateLock);
  return hit;
}

// Returns false if table full (still safe — skip inject, do not crash).
bool TryMarkInjected(lua_State *L) {
  AcquireSRWLockExclusive(&g_stateLock);
  LONG n = g_injectedCount;
  for (LONG i = 0; i < n && i < kMaxInjected; i++) {
    if (g_injectedStates[i] == L) {
      ReleaseSRWLockExclusive(&g_stateLock);
      return true;
    }
  }
  if (n >= kMaxInjected) {
    ReleaseSRWLockExclusive(&g_stateLock);
    return false;
  }
  g_injectedStates[n] = L;
  InterlockedExchange(&g_injectedCount, n + 1);
  ReleaseSRWLockExclusive(&g_stateLock);
  return true;
}

void InjectLuaScript(lua_State *L) {
  const bool haveLoader =
      (g_loaderKind == LuaLoaderKind::LuaLLoadBufferX && g_lua_loadbufferx) ||
      (g_loaderKind == LuaLoaderKind::LuaLoad && g_lua_load);
  if (!haveLoader || !g_lua_pcallk_orig || !L)
    return;
  // Allow re-run when F5 arms pending again so script reentry can rescan.
  // (Do not early-return on StateAlreadyInjected.)

  BootPrintf("lua_State observed %p", L);
  BootPrintf("face_share_logger.lua load started kind=%s", LuaLoaderKindName(g_loaderKind));

  std::string script = ReadTextFile(g_scriptPath);
  if (script.empty()) {
    WriteCaptureEvent("native", "lua_inject_error",
                      "{\"error\":\"script_not_found\",\"path\":" + JsonString(g_scriptPath) + "}");
    BootPrintf("[!] Cannot read script: %s", g_scriptPath.c_str());
    return;
  }

  // Separate absolute Lua JSONL (avoid contention with native capture file).
  std::string luaOut = g_dllDir + "captures\\face_share_capture_lua.jsonl";
  {
    std::string capDir = g_dllDir + "captures";
    CreateDirectoryA(capDir.c_str(), nullptr);
  }
  BootPrintf("lua_output_path=%s", luaOut.c_str());
  WriteCaptureEvent("native", "lua_output_configured",
                    std::string("{\"path\":") + JsonString(luaOut) +
                        ",\"absolute\":true}");

  // Long-bracket path: safe, no escape issues for Windows paths.
  std::string eq = "==";
  if (luaOut.find("]==]") != std::string::npos)
    eq = "===";
  std::string pendingPath = g_dllDir + "captures\\pending_cn_to_global.json";
  std::string resultPath = g_dllDir + "captures\\cn_to_global_result.json";
  if (pendingPath.find("]==]") != std::string::npos || resultPath.find("]==]") != std::string::npos)
    eq = "===";
  const bool armCn =
      g_cnToGlobalEnabled &&
      InterlockedCompareExchange(&g_pendingCnToGlobalArm, 0, 1) == 1;
  if (armCn)
    BootPrintf("cn_to_global arm flag consumed; pending=%s", pendingPath.c_str());

  std::string preamble =
      std::string("-- face_share_logger bootstrap\n") + "_G.__FACE_CAPTURE_OUTPUT = [" + eq +
      "[" + luaOut + "]" + eq + "]\n" + "_G.__FACE_CAPTURE_FULL = " +
      (g_cfg.capture_full_face_data ? "true" : "false") + "\n" +
      "_G.__FACE_CAPTURE_PENDING_PATH = [" + eq + "[" + pendingPath + "]" + eq + "]\n" +
      "_G.__FACE_CAPTURE_RESULT_PATH = [" + eq + "[" + resultPath + "]" + eq + "]\n" +
      "_G.__FACE_CAPTURE_CN_TO_GLOBAL_ENABLED = " +
      (g_cnToGlobalEnabled ? "true" : "false") + "\n" +
      "_G.__FACE_CAPTURE_ARM_CN_GLOBAL = " + (armCn ? "true" : "false") + "\n";
  std::string full = preamble + script;
  BootPrintf("lua_bootstrap_bytes=%zu arm_cn=%d", full.size(), armCn ? 1 : 0);

  int rc = -1;
  if (g_loaderKind == LuaLoaderKind::LuaLLoadBufferX && g_lua_loadbufferx) {
    BootPrintf("loader luaL_loadbufferx size=%zu L=%p", full.size(), L);
    rc = g_lua_loadbufferx(L, full.data(), full.size(), "=(face_share_logger)", "t");
    BootPrintf("loader rc=%d", rc);
  } else if (g_lua_load) {
    LoadS ls{full.c_str(), full.size()};
    BootPrintf("loader lua_load size=%zu L=%p", full.size(), L);
    rc = g_lua_load(L, lua_reader_cb, &ls, "=(face_share_logger)", "t");
    BootPrintf("loader rc=%d", rc);
  }
  if (rc != 0) {
    WriteCaptureEvent("native", "lua_load_failed",
                      "{\"code\":" + std::to_string(rc) + ",\"kind\":" +
                          JsonString(LuaLoaderKindName(g_loaderKind)) + "}");
    // Do not call pcall; do not retry-spam (pending already cleared by detour).
    return;
  }
  rc = g_lua_pcallk_orig(L, 0, 0, 0, nullptr, nullptr);
  BootPrintf("lua_pcall rc=%d", rc);
  if (rc != 0) {
    WriteCaptureEvent("native", "lua_pcall_failed", "{\"code\":" + std::to_string(rc) + "}");
    return;
  }

  if (!TryMarkInjected(L)) {
    BootPrintf("[!] injected-state table full; script ran (reentry/rescan ok)");
  }
  SetHookState(LuaHookState::Injected);
  WriteCaptureEvent("native", "lua_injected",
                    "{\"script\":" + JsonString(g_scriptPath) + ",\"kind\":" +
                        JsonString(LuaLoaderKindName(g_loaderKind)) +
                        ",\"lua_output\":" + JsonString(luaOut) + "}");
  BootPrintf("face_share_logger.lua injected OK L=%p", L);
}

int __cdecl Detour_lua_pcallk(lua_State *L, int nargs, int nresults, int msgh, void *ctx,
                              void *k) {
  LuaHookState st = GetHookStateLocal();

  // Observer-only: never inject.
  if (st == LuaHookState::PcallObserverOnly) {
    LONG c = InterlockedIncrement(&g_pcallObsCount);
    if (c <= kMaxPcallObs) {
      char data[192];
      _snprintf_s(data, _TRUNCATE,
                  "{\"state\":\"%p\",\"nargs\":%d,\"nresults\":%d,\"count\":%ld}", L, nargs,
                  nresults, (long)c);
      WriteCaptureEvent("native", "lua_pcall_observed", data);
    }
    return g_lua_pcallk_orig(L, nargs, nresults, msgh, ctx, k);
  }

  // Inject only when installed/injected and pending arm set.
  const bool haveLoader =
      (g_loaderKind == LuaLoaderKind::LuaLLoadBufferX && g_lua_loadbufferx) ||
      (g_loaderKind == LuaLoaderKind::LuaLoad && g_lua_load);
  if ((st == LuaHookState::Installed || st == LuaHookState::Injected) &&
      InterlockedCompareExchange(&g_pendingInject, 0, 0) != 0 && !g_insideLuaInjection && L &&
      haveLoader) {
    if (!StateAlreadyInjected(L)) {
      g_insideLuaInjection = true;
      // Clear pending after first attempt so spam does not re-enter forever on failure.
      InterlockedExchange(&g_pendingInject, 0);
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

  {
    ScanCandidate c;
    c.name = exeName;
    c.path = exePath;
    c.hmod = GetModuleHandleA(nullptr);
    if (GetModuleExecRange(c.hmod, c.base, c.size))
      out.push_back(c);
  }

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

  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
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
      if (!gameDir.empty() && !IEquals(DirOf(path), gameDir))
        continue;
      bool dup = false;
      for (const auto &e : out) {
        if (e.hmod == me.hModule) {
          dup = true;
          break;
        }
      }
      if (dup)
        continue;
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
  const char *status = "SIGNATURE_NOT_FOUND";
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
    r.selected = 0;
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
  BootPrintf("sig %s matches=%zu status=%s addr=%s", name, r.matches, r.status,
             r.selected ? HexPtr(r.selected).c_str() : "null");
}

bool InstallPcallObserver(void *pcallAddr) {
  MH_STATUS stCreate =
      MH_CreateHook(pcallAddr, (LPVOID)&Detour_lua_pcallk, (LPVOID *)&g_lua_pcallk_orig);
  if (stCreate != MH_OK) {
    BootPrintf("[!] MH_CreateHook pcall observer failed status=%d", (int)stCreate);
    return false;
  }
  MH_STATUS stEnable = MH_EnableHook(pcallAddr);
  if (stEnable != MH_OK) {
    BootPrintf("[!] MH_EnableHook pcall observer failed status=%d", (int)stEnable);
    return false;
  }
  SetHookState(LuaHookState::PcallObserverOnly);
  InterlockedExchange(&g_pendingInject, 0);
  WriteCaptureEvent("native", "lua_pcall_observer_installed",
                    "{\"inject\":false,\"max_events\":20}");
  BootPrintf("[+] pcall observer installed (no inject)");
  return true;
}

} // namespace

LuaHookState GetLuaHookState() { return GetHookStateLocal(); }

const char *GetLuaHookStateName() { return LuaHookStateName(GetHookStateLocal()); }

bool InstallLuaRuntimeHook(const HookConfig &cfg, const std::string &dllDir) {
  g_cfg = cfg;
  g_dllDir = dllDir;
  g_scriptPath = ResolvePath(dllDir, cfg.lua_script);
  g_cnToGlobalEnabled = cfg.enable_cn_to_global_conversion;
  InterlockedExchange(&g_pendingCnToGlobalArm, 0);
  InterlockedExchange(&g_pendingInject, 0);
  InterlockedExchange(&g_injectedCount, 0);
  InterlockedExchange(&g_pcallObsCount, 0);
  AcquireSRWLockExclusive(&g_stateLock);
  memset(g_injectedStates, 0, sizeof(g_injectedStates));
  ReleaseSRWLockExclusive(&g_stateLock);
  g_lua_load = nullptr;
  g_lua_loadbufferx = nullptr;
  g_lua_pcallk_orig = nullptr;
  g_loaderKind = LuaLoaderKind::None;

  if (!cfg.enable_lua_hook) {
    SetHookState(LuaHookState::Disabled);
    BootPrintf("[*] Lua hook disabled by config");
    return false;
  }

  SetHookState(LuaHookState::Scanning);

  DWORD attr = GetFileAttributesA(g_scriptPath.c_str());
  bool exists = attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
  size_t fsize = 0;
  if (exists) {
    std::string t = ReadTextFile(g_scriptPath);
    fsize = t.size();
  }
  WriteCaptureEvent("native", "lua_script_resolved",
                    "{\"path\":" + JsonString(g_scriptPath) + ",\"exists\":" + JsonBool(exists) +
                        ",\"size\":" + std::to_string(fsize) + "}");
  BootPrintf("lua_script_resolved path=%s exists=%d size=%zu", g_scriptPath.c_str(),
             exists ? 1 : 0, fsize);

  // Fingerprint main module
  ModuleFingerprint fp{};
  FingerprintModule(GetModuleHandleA(nullptr), fp);
  WriteCaptureEvent(
      "native", "module_fingerprint",
      std::string("{\"module\":") + JsonString(fp.module) + ",\"image_size\":" +
          std::to_string(fp.image_size) + ",\"pe_timestamp\":" + std::to_string(fp.pe_timestamp) +
          ",\"text_rva\":" + JsonString(HexPtr(fp.text_rva)) +
          ",\"text_size\":" + std::to_string(fp.text_size) + ",\"file_version\":" +
          JsonString(fp.file_version) + ",\"sha256\":" + JsonString(fp.sha256) + "}");
  BootPrintf("module fingerprint sha256=%s size=%zu ver=%s", fp.sha256.c_str(), fp.image_size,
             fp.file_version.c_str());

  auto candidates = CollectGameModules(cfg);
  if (candidates.empty()) {
    SetHookState(LuaHookState::SignatureMissing);
    WriteCaptureEvent("native", "lua_hook_error", "{\"error\":\"target_module_not_found\"}");
    BootPrintf("[!] No game modules for Lua pattern scan");
    return false;
  }

  {
    const auto &m = candidates[0];
    WriteCaptureEvent("native", "lua_scan_start",
                      std::string("{\"pid\":") + std::to_string(GetCurrentProcessId()) +
                          ",\"exe\":" + JsonString(m.name) + ",\"module\":" + JsonString(m.name) +
                          ",\"base\":" + JsonString(HexPtr(m.base)) +
                          ",\"image_size\":" + std::to_string(m.size) + "}");
  }

  // Patterns: fingerprint DB first (build-specific), else config/legacy.
  std::string sigLoad = cfg.sig_lua_load;
  std::string sigPcall = cfg.sig_lua_pcall;
  std::string sigLoadBuf = "";
  unsigned expectInnerRva = 0;
  const char *buildId = "legacy-default";
  for (int i = 0; i < kLuaSignatureBuildCount; i++) {
    const auto &b = kLuaSignatureBuilds[i];
    if (b.module_sha256 && b.module_sha256[0] && !fp.sha256.empty() &&
        fp.sha256 == b.module_sha256) {
      buildId = b.id;
      if (b.sig_lua_load && b.sig_lua_load[0])
        sigLoad = b.sig_lua_load;
      else
        sigLoad.clear(); // do not fall back to wrong-build lua_load
      if (b.sig_lua_pcallk && b.sig_lua_pcallk[0])
        sigPcall = b.sig_lua_pcallk;
      if (b.sig_luaL_loadbufferx && b.sig_luaL_loadbufferx[0])
        sigLoadBuf = b.sig_luaL_loadbufferx;
      expectInnerRva = b.inner_lua_load_rva;
      BootPrintf("signature DB match build=%s", b.id);
      break;
    }
  }

  uintptr_t chosenLoad = 0;       // classic lua_load if any
  uintptr_t chosenLoadBufX = 0;   // luaL_loadbufferx
  uintptr_t chosenPcall = 0;
  std::string chosenModule;
  bool anyAmbiguous = false;
  bool sawPcall = false;
  bool loadBufXUnique = false;

  for (const auto &m : candidates) {
    SigResult pcallR{};
    if (!sigPcall.empty()) {
      auto pcallHits = PatternScanAll(m.base, m.size, sigPcall.c_str());
      pcallR = EvaluateSig(pcallHits);
      EmitSigEvent("lua_pcallk", m.base, pcallR);
      if (pcallR.status && strcmp(pcallR.status, "SIGNATURE_AMBIGUOUS") == 0)
        anyAmbiguous = true;
      if (pcallR.selected)
        sawPcall = true;
      if (pcallR.selected && !chosenPcall) {
        chosenPcall = pcallR.selected;
        chosenModule = m.name;
      }
    }

    SigResult loadR{};
    if (!sigLoad.empty()) {
      auto loadHits = PatternScanAll(m.base, m.size, sigLoad.c_str());
      loadR = EvaluateSig(loadHits);
      EmitSigEvent("lua_load", m.base, loadR);
      if (loadR.status && strcmp(loadR.status, "SIGNATURE_AMBIGUOUS") == 0)
        anyAmbiguous = true;
      if (loadR.selected && pcallR.selected && !chosenLoad) {
        chosenLoad = loadR.selected;
        if (!chosenPcall)
          chosenPcall = pcallR.selected;
        chosenModule = m.name;
      }
    }

    // Preferred: luaL_loadbufferx (build-specific). Require exact 1 match + inner call.
    if (!sigLoadBuf.empty() && !chosenLoadBufX) {
      auto lbHits = PatternScanAll(m.base, m.size, sigLoadBuf.c_str());
      SigResult lbR = EvaluateSig(lbHits);
      EmitSigEvent("luaL_loadbufferx", m.base, lbR);
      BootPrintf("luaL_loadbufferx matches=%zu status=%s", lbR.matches, lbR.status);
      WriteCaptureEvent(
          "native", "luaL_loadbufferx_scan",
          std::string("{\"module\":") + JsonString(m.name) +
              ",\"matches\":" + std::to_string(lbR.matches) +
              ",\"status\":" + JsonString(lbR.status) + "}");

      if (lbR.status && strcmp(lbR.status, "SIGNATURE_AMBIGUOUS") == 0)
        anyAmbiguous = true;

      if (lbR.selected && pcallR.selected) {
        bool innerOk = true;
        if (expectInnerRva) {
          // Find E8 in first 48 bytes of wrapper; must target module_base+expectInnerRva.
          innerOk = false;
          const uint8_t *p = (const uint8_t *)lbR.selected;
          for (int off = 0; off + 5 <= 48; off++) {
            if (p[off] != 0xE8)
              continue;
            int32_t rel = *(const int32_t *)(p + off + 1);
            uintptr_t dest = lbR.selected + (uintptr_t)off + 5 + (intptr_t)rel;
            uintptr_t expect = m.base + (uintptr_t)expectInnerRva;
            BootPrintf("luaL_loadbufferx E8@+%d -> %s expect %s", off, HexPtr(dest).c_str(),
                       HexPtr(expect).c_str());
            if (dest == expect) {
              innerOk = true;
              break;
            }
          }
        }
        if (innerOk) {
          chosenLoadBufX = lbR.selected;
          chosenPcall = pcallR.selected;
          chosenModule = m.name;
          loadBufXUnique = (lbR.matches == 1);
          BootPrintf("luaL_loadbufferx resolved %s (unique=%d)", HexPtr(chosenLoadBufX).c_str(),
                     loadBufXUnique ? 1 : 0);
        } else {
          BootPrintf("[!] luaL_loadbufferx rejected: inner call != 0x%X", expectInnerRva);
          WriteCaptureEvent("native", "lua_hook_error",
                            "{\"error\":\"INNER_LOADER_MISMATCH\"}");
        }
      }
    }

    WriteCaptureEvent(
        "native", "lua_scan_module",
        std::string("{\"name\":") + JsonString(m.name) + ",\"path\":" + JsonString(m.path) +
            ",\"size\":" + std::to_string(m.size) +
            ",\"lua_load_matches\":" + std::to_string(loadR.matches) +
            ",\"lua_pcall_matches\":" + std::to_string(pcallR.matches) +
            ",\"loadbufferx\":" + (chosenLoadBufX ? "true" : "false") + "}");
  }

  // Always run diagnostic probe (fail-soft).
  {
    std::string probePath = ResolvePath(dllDir, cfg.capture_dir + "/lua_signature_probe.json");
    for (char &ch : probePath)
      if (ch == '/')
        ch = '\\';
    char dir[MAX_PATH] = {};
    strncpy_s(dir, probePath.c_str(), _TRUNCATE);
    char *sl = strrchr(dir, '\\');
    if (sl) {
      *sl = 0;
      CreateDirectoryA(dir, nullptr);
    }
    char perr[128] = {};
    if (RunLuaSignatureProbe(cfg, dllDir, fp, chosenPcall, probePath, perr, sizeof(perr)))
      BootPrintf("[+] signature probe written: %s (%s)", probePath.c_str(), perr);
    else
      BootPrintf("[!] signature probe failed: %s", perr);
  }

  // Prefer loadbufferx when unique + pcall OK.
  const bool useLoadBufX = chosenLoadBufX && chosenPcall && loadBufXUnique;
  const bool useClassic = chosenLoad && chosenPcall && !useLoadBufX;

  if (!useLoadBufX && !useClassic) {
    if (anyAmbiguous)
      SetHookState(LuaHookState::SignatureAmbiguous);
    else
      SetHookState(LuaHookState::SignatureMissing);

    BootPrintf("[!] Refusing full Lua inject: need unique loader + pcall (build=%s)", buildId);
    WriteCaptureEvent(
        "native", "lua_hook_error",
        std::string("{\"error\":\"") +
            (anyAmbiguous ? "SIGNATURE_AMBIGUOUS" : "SIGNATURE_NOT_FOUND") +
            "\",\"build\":" + JsonString(buildId) + "}");

    if (cfg.enable_pcall_observer_when_loader_missing && chosenPcall && sawPcall) {
      if (InstallPcallObserver((void *)chosenPcall))
        return false;
    }
    return false;
  }

  if (!exists) {
    SetHookState(LuaHookState::SignatureMissing);
    BootPrintf("[!] Lua script missing — abort install");
    return false;
  }

  if (useLoadBufX) {
    g_loaderKind = LuaLoaderKind::LuaLLoadBufferX;
    g_lua_loadbufferx = (luaL_loadbufferx_fn)chosenLoadBufX;
    g_lua_load = nullptr;
    BootPrintf("loader kind=luaL_loadbufferx %s", HexPtr(chosenLoadBufX).c_str());
  } else {
    g_loaderKind = LuaLoaderKind::LuaLoad;
    g_lua_load = (lua_load_fn)chosenLoad;
    g_lua_loadbufferx = nullptr;
    BootPrintf("loader kind=lua_load %s", HexPtr(chosenLoad).c_str());
  }
  BootPrintf("lua_pcallk resolved %s module=%s", HexPtr(chosenPcall).c_str(),
             chosenModule.c_str());

  void *pcallAddr = (void *)chosenPcall;

  MH_STATUS stCreate =
      MH_CreateHook(pcallAddr, (LPVOID)&Detour_lua_pcallk, (LPVOID *)&g_lua_pcallk_orig);
  if (stCreate != MH_OK) {
    SetHookState(LuaHookState::CreateHookFailed);
    BootPrintf("[!] MH_CreateHook lua_pcallk failed status=%d", (int)stCreate);
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"MH_CreateHook\",\"status\":" + std::to_string((int)stCreate) +
                          "}");
    return false;
  }
  BootPrintf("lua_pcallk hook created");

  MH_STATUS stEnable = MH_EnableHook(pcallAddr);
  if (stEnable != MH_OK) {
    SetHookState(LuaHookState::EnableHookFailed);
    BootPrintf("[!] MH_EnableHook lua_pcallk failed status=%d", (int)stEnable);
    WriteCaptureEvent("native", "lua_hook_error",
                      "{\"error\":\"MH_EnableHook\",\"status\":" + std::to_string((int)stEnable) +
                          "}");
    return false;
  }
  BootPrintf("lua_pcallk hook enabled");

  SetHookState(LuaHookState::Installed);
  // Arm once so first pcall injects without requiring F5.
  InterlockedExchange(&g_pendingInject, 1);

  WriteCaptureEvent(
      "native", "lua_hook_installed",
      std::string("{\"script\":") + JsonString(g_scriptPath) + ",\"module\":" +
          JsonString(chosenModule) + ",\"build\":" + JsonString(buildId) +
          ",\"loader_kind\":" + JsonString(LuaLoaderKindName(g_loaderKind)) +
          ",\"loader\":" +
          JsonString(HexPtr(useLoadBufX ? chosenLoadBufX : chosenLoad)) +
          ",\"lua_pcallk\":" + JsonString(HexPtr(chosenPcall)) + "}");
  BootPrintf("[+] Lua runtime hook installed kind=%s; inject armed for next pcall",
             LuaLoaderKindName(g_loaderKind));
  return true;
}

void UninstallLuaRuntimeHook() {
  InterlockedExchange(&g_pendingInject, 0);
  SetHookState(LuaHookState::Disabled);
  AcquireSRWLockExclusive(&g_stateLock);
  memset(g_injectedStates, 0, sizeof(g_injectedStates));
  InterlockedExchange(&g_injectedCount, 0);
  ReleaseSRWLockExclusive(&g_stateLock);
}

bool RequestLuaInject(char *reason, size_t reasonN) {
  LuaHookState st = GetHookStateLocal();
  if (!LuaHookStateAllowsF5(st)) {
    const char *why = LuaHookStateF5RejectReason(st);
    if (reason && reasonN)
      _snprintf_s(reason, reasonN, _TRUNCATE, "%s", why);
    return false;
  }
  // Atomic arm only — no mutex, no clear of injected states.
  InterlockedExchange(&g_pendingInject, 1);
  if (reason && reasonN)
    _snprintf_s(reason, reasonN, _TRUNCATE, "armed");
  return true;
}

bool RequestCnToGlobalArm(char *reason, size_t reasonN) {
  if (!g_cnToGlobalEnabled) {
    if (reason && reasonN)
      _snprintf_s(reason, reasonN, _TRUNCATE, "CN_TO_GLOBAL_DISABLED");
    return false;
  }
  LuaHookState st = GetHookStateLocal();
  if (!LuaHookStateAllowsF5(st)) {
    const char *why = LuaHookStateF5RejectReason(st);
    if (reason && reasonN)
      _snprintf_s(reason, reasonN, _TRUNCATE, "%s", why && why[0] ? why : "LUA_HOOK_NOT_INSTALLED");
    return false;
  }
  // Pending file existence check (Lua re-validates contents).
  std::string pendingPath = g_dllDir + "captures\\pending_cn_to_global.json";
  DWORD attr = GetFileAttributesA(pendingPath.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
    if (reason && reasonN)
      _snprintf_s(reason, reasonN, _TRUNCATE, "PENDING_FILE_MISSING");
    BootPrintf("[!] F6: pending file missing: %s", pendingPath.c_str());
    return false;
  }
  InterlockedExchange(&g_pendingCnToGlobalArm, 1);
  InterlockedExchange(&g_pendingInject, 1);
  WriteCaptureEvent("native", "cn_to_global_arm_requested",
                    std::string("{\"pending\":") + JsonString(pendingPath) + "}");
  BootPrintf("F6: CN→Global arm requested; inject armed");
  if (reason && reasonN)
    _snprintf_s(reason, reasonN, _TRUNCATE, "armed");
  return true;
}

} // namespace face_capture
