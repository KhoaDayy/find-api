#pragma once
#include "hook/config.h"
#include <cstddef>

namespace face_capture {

// Install WinHTTP detours only if winhttp.dll is already loaded.
// outReason: optional ASCII reason for boot log (may be null).
bool InstallWinHttpCapture(const HookConfig &cfg, char *outReason = nullptr,
                           size_t reasonN = 0);
void UninstallWinHttpCapture();

} // namespace face_capture
