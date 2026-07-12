#include "hook/config.h"
#include <Windows.h>
#include <fstream>
#include <sstream>

namespace face_capture {
namespace {

std::string ReadFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f)
    return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Minimal JSON string field extractor: "key": "value" or "key": true/false
std::string GetString(const std::string &j, const char *key, const std::string &def) {
  std::string pat = std::string("\"") + key + "\"";
  size_t p = j.find(pat);
  if (p == std::string::npos)
    return def;
  p = j.find(':', p);
  if (p == std::string::npos)
    return def;
  p = j.find_first_not_of(" \t\r\n", p + 1);
  if (p == std::string::npos)
    return def;
  if (j[p] == '"') {
    size_t e = j.find('"', p + 1);
    if (e == std::string::npos)
      return def;
    return j.substr(p + 1, e - p - 1);
  }
  return def;
}

bool GetBool(const std::string &j, const char *key, bool def) {
  std::string pat = std::string("\"") + key + "\"";
  size_t p = j.find(pat);
  if (p == std::string::npos)
    return def;
  p = j.find(':', p);
  if (p == std::string::npos)
    return def;
  p = j.find_first_not_of(" \t\r\n", p + 1);
  if (p == std::string::npos)
    return def;
  if (j.compare(p, 4, "true") == 0)
    return true;
  if (j.compare(p, 5, "false") == 0)
    return false;
  return def;
}

// True if key is present (so we can distinguish "missing" from default).
bool HasKey(const std::string &j, const char *key) {
  return j.find(std::string("\"") + key + "\"") != std::string::npos;
}

// Parse "key": ["a","b"] — best-effort, no nested arrays.
std::vector<std::string> GetStringArray(const std::string &j, const char *key) {
  std::vector<std::string> out;
  std::string pat = std::string("\"") + key + "\"";
  size_t p = j.find(pat);
  if (p == std::string::npos)
    return out;
  p = j.find(':', p);
  if (p == std::string::npos)
    return out;
  p = j.find('[', p);
  if (p == std::string::npos)
    return out;
  size_t end = j.find(']', p + 1);
  if (end == std::string::npos)
    return out;
  size_t i = p + 1;
  while (i < end) {
    size_t q1 = j.find('"', i);
    if (q1 == std::string::npos || q1 >= end)
      break;
    size_t q2 = j.find('"', q1 + 1);
    if (q2 == std::string::npos || q2 > end)
      break;
    out.push_back(j.substr(q1 + 1, q2 - q1 - 1));
    i = q2 + 1;
  }
  return out;
}

} // namespace

HookConfig LoadConfig(const std::string &dllDir) {
  HookConfig c;
  std::string path = dllDir + "hook_config.json";
  std::string j = ReadFile(path);
  if (j.empty())
    return c;

  auto procs = GetStringArray(j, "target_processes");
  if (!procs.empty()) {
    c.target_processes = procs;
    c.target_process = procs[0];
  } else {
    c.target_process = GetString(j, "target_process", c.target_process);
    c.target_processes.clear();
    c.target_processes.push_back(c.target_process);
  }

  c.lua_script = GetString(j, "lua_script", c.lua_script);
  c.capture_dir = GetString(j, "capture_dir", c.capture_dir);
  // Prefer explicit output_file; else keep default under capture_dir.
  if (HasKey(j, "output_file"))
    c.output_file = GetString(j, "output_file", c.output_file);
  else if (!c.capture_dir.empty())
    c.output_file = c.capture_dir + "/face_share_capture.jsonl";

  c.enable_lua_hook = GetBool(j, "enable_lua_hook", c.enable_lua_hook);
  c.enable_lua_debug_hook =
      GetBool(j, "enable_lua_debug_hook", c.enable_lua_debug_hook);
  c.enable_pcall_observer_when_loader_missing = GetBool(
      j, "enable_pcall_observer_when_loader_missing",
      c.enable_pcall_observer_when_loader_missing);

  // New name preferred; accept legacy enable_winhttp_hook.
  if (HasKey(j, "enable_winhttp_fallback")) {
    c.enable_winhttp_fallback =
        GetBool(j, "enable_winhttp_fallback", c.enable_winhttp_fallback);
  } else if (HasKey(j, "enable_winhttp_hook")) {
    c.enable_winhttp_fallback =
        GetBool(j, "enable_winhttp_hook", c.enable_winhttp_fallback);
  }
  c.enable_winhttp_hook = c.enable_winhttp_fallback;

  c.capture_only_filepicker =
      GetBool(j, "capture_only_filepicker", c.capture_only_filepicker);
  c.redact_secrets = GetBool(j, "redact_secrets", c.redact_secrets);
  c.capture_full_face_data =
      GetBool(j, "capture_full_face_data", c.capture_full_face_data);
  c.unsafe_save_session = GetBool(j, "unsafe_save_session", c.unsafe_save_session);

  std::string s1 = GetString(j, "sig_lua_load", "");
  if (!s1.empty())
    c.sig_lua_load = s1;
  std::string s2 = GetString(j, "sig_lua_pcall", "");
  if (!s2.empty())
    c.sig_lua_pcall = s2;
  return c;
}

std::string ResolvePath(const std::string &dllDir, const std::string &rel) {
  if (rel.empty())
    return dllDir;
  if (rel.size() > 1 && (rel[1] == ':' || rel[0] == '\\' || rel[0] == '/'))
    return rel;
  return dllDir + rel;
}

std::string ResolveCaptureOutputPath(const std::string &dllDir, const HookConfig &cfg) {
  std::string rel = cfg.output_file;
  if (rel.empty()) {
    std::string dir = cfg.capture_dir.empty() ? "captures" : cfg.capture_dir;
    rel = dir + "/face_share_capture.jsonl";
  }
  // Normalize forward slashes for Windows fopen.
  for (char &ch : rel) {
    if (ch == '/')
      ch = '\\';
  }
  return ResolvePath(dllDir, rel);
}

} // namespace face_capture
