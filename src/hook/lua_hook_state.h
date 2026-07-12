#pragma once
#include <Windows.h>

namespace face_capture {

// Stored in Interlocked LONG — keep values stable.
enum class LuaHookState : LONG {
  Disabled = 0,
  Scanning = 1,
  SignatureMissing = 2,
  SignatureAmbiguous = 3,
  CreateHookFailed = 4,
  EnableHookFailed = 5,
  Installed = 6,
  Injected = 7,
  PcallObserverOnly = 8,
};

enum class LuaLoaderKind : LONG {
  None = 0,
  LuaLoad = 1,
  LuaLLoadBufferX = 2,
};

inline const char *LuaHookStateName(LuaHookState s) {
  switch (s) {
  case LuaHookState::Disabled:
    return "disabled";
  case LuaHookState::Scanning:
    return "scanning";
  case LuaHookState::SignatureMissing:
    return "signature_missing";
  case LuaHookState::SignatureAmbiguous:
    return "signature_ambiguous";
  case LuaHookState::CreateHookFailed:
    return "create_hook_failed";
  case LuaHookState::EnableHookFailed:
    return "enable_hook_failed";
  case LuaHookState::Installed:
    return "installed";
  case LuaHookState::Injected:
    return "injected";
  case LuaHookState::PcallObserverOnly:
    return "pcall_observer_only";
  default:
    return "unknown";
  }
}

inline bool LuaHookStateAllowsF5(LuaHookState s) {
  return s == LuaHookState::Installed || s == LuaHookState::Injected;
}

inline const char *LuaHookStateF5RejectReason(LuaHookState s) {
  switch (s) {
  case LuaHookState::Disabled:
    return "LUA_HOOK_DISABLED";
  case LuaHookState::Scanning:
    return "LUA_HOOK_STILL_SCANNING";
  case LuaHookState::SignatureMissing:
    return "LUA_HOOK_NOT_INSTALLED_SIGNATURE_MISSING";
  case LuaHookState::SignatureAmbiguous:
    return "LUA_HOOK_NOT_INSTALLED_SIGNATURE_AMBIGUOUS";
  case LuaHookState::CreateHookFailed:
    return "LUA_HOOK_NOT_INSTALLED_CREATE_FAILED";
  case LuaHookState::EnableHookFailed:
    return "LUA_HOOK_NOT_INSTALLED_ENABLE_FAILED";
  case LuaHookState::PcallObserverOnly:
    return "LUA_HOOK_PCALL_OBSERVER_ONLY_NO_INJECT";
  case LuaHookState::Installed:
  case LuaHookState::Injected:
    return "";
  default:
    return "LUA_HOOK_NOT_INSTALLED";
  }
}

} // namespace face_capture
