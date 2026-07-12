#pragma once
#include "hook/config.h"
#include "hook/lua_hook_state.h"
#include <cstddef>
#include <string>

namespace face_capture {

bool InstallLuaRuntimeHook(const HookConfig &cfg, const std::string &dllDir);
void UninstallLuaRuntimeHook();

// F5 path: atomic only. Returns false if hook not installed.
// reason: optional ASCII buffer for boot log.
bool RequestLuaInject(char *reason = nullptr, size_t reasonN = 0);

// F6: arm one-shot CN→Global conversion + reinject so Lua can load pending file.
// Requires enable_cn_to_global_conversion and installed Lua hook.
bool RequestCnToGlobalArm(char *reason = nullptr, size_t reasonN = 0);

LuaHookState GetLuaHookState();
const char *GetLuaHookStateName();

} // namespace face_capture
