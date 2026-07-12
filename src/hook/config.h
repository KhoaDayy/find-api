#pragma once
#include <string>
#include <vector>

namespace face_capture {

struct HookConfig {
  // Legacy single-name field (first of target_processes after load).
  std::string target_process = "wwm.exe";
  std::vector<std::string> target_processes = {
      "wwm.exe", "yysls.exe", "WhereWindsMeet.exe"};

  std::string lua_script = "Scripts/face_share_logger.lua";
  std::string capture_dir = "captures";
  // Full JSONL path; if empty, derived as capture_dir/face_share_capture.jsonl
  std::string output_file = "captures/face_share_capture.jsonl";

  // Lua-first default: capture Face Share without requiring winhttp.dll.
  bool enable_lua_hook = true;
  // Optional WinHTTP allowlist capture (OFF by default — game may never load it).
  bool enable_winhttp_fallback = false;
  // Alias kept for older configs / code paths.
  bool enable_winhttp_hook = false;
  // Never auto-enable; reserved for future optional diagnostics only.
  bool enable_lua_debug_hook = false;

  bool capture_only_filepicker = true;
  bool redact_secrets = true;
  bool capture_full_face_data = false;
  bool unsafe_save_session = false;

  std::string sig_lua_load =
      "48 89 5C 24 10 56 48 83 EC 50 49 8B D9 48 8B F1 "
      "4D 8B C8 4C 8B C2 48 8D 54 24 20";
  std::string sig_lua_pcall =
      "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58 "
      "49 63 C1 41 8B E8 48 8B F9 45 85 C9";
};

// Load hook_config.json next to DLL. Missing file => defaults.
HookConfig LoadConfig(const std::string &dllDir);

// Resolve relative path against dllDir.
std::string ResolvePath(const std::string &dllDir, const std::string &rel);

// Build absolute JSONL path from capture_dir / output_file.
std::string ResolveCaptureOutputPath(const std::string &dllDir, const HookConfig &cfg);

} // namespace face_capture
