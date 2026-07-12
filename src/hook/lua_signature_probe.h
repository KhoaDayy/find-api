#pragma once
#include "hook/config.h"
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <string>

namespace face_capture {

struct ModuleFingerprint {
  std::string module;
  std::string path;
  size_t image_size = 0;
  uint32_t pe_timestamp = 0;
  uint32_t text_rva = 0;
  uint32_t text_size = 0;
  std::string file_version;
  std::string sha256;
  uintptr_t base = 0;
};

// Fill fingerprint for a loaded module (or nullptr = main EXE).
bool FingerprintModule(HMODULE hmod, ModuleFingerprint &out);

// Diagnostic-only probe. Never installs hooks. Writes JSON (capped ~2MB).
// pcallAddr: if non-zero, known exact lua_pcallk VA from prior scan.
bool RunLuaSignatureProbe(const HookConfig &cfg, const std::string &dllDir,
                          const ModuleFingerprint &fp, uintptr_t pcallAddr,
                          const std::string &outJsonPath, char *err, size_t errN);

// Offline PE file probe (no process). Same JSON schema.
bool RunLuaSignatureProbeFile(const char *modulePath, const HookConfig &cfg,
                              const std::string &outJsonPath, char *err,
                              size_t errN);

} // namespace face_capture
