#pragma once
#include "hook/config.h"
#include <string>

namespace face_capture {

bool InstallLuaRuntimeHook(const HookConfig &cfg, const std::string &dllDir);
void UninstallLuaRuntimeHook();
void RequestLuaInject(); // F5

} // namespace face_capture
