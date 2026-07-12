#pragma once
#include "hook/config.h"
#include <string>

namespace face_capture {

bool InstallWinHttpCapture(const HookConfig &cfg);
void UninstallWinHttpCapture();

} // namespace face_capture
