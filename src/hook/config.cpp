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

} // namespace

HookConfig LoadConfig(const std::string &dllDir) {
  HookConfig c;
  std::string path = dllDir + "hook_config.json";
  std::string j = ReadFile(path);
  if (j.empty())
    return c;
  c.target_process = GetString(j, "target_process", c.target_process);
  c.lua_script = GetString(j, "lua_script", c.lua_script);
  c.output_file = GetString(j, "output_file", c.output_file);
  c.enable_lua_hook = GetBool(j, "enable_lua_hook", c.enable_lua_hook);
  c.enable_winhttp_hook = GetBool(j, "enable_winhttp_hook", c.enable_winhttp_hook);
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
  if (rel.size() > 1 && (rel[1] == ':' || rel[0] == '\\' || rel[0] == '/'))
    return rel;
  return dllDir + rel;
}

} // namespace face_capture
