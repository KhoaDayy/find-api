#pragma once
// Embedded signature DB for known WWM builds.
// Fuzzy / unmatched builds never auto-hook — exact match only.
//
// After a successful probe on a new build, add a row with module_sha256 +
// exact patterns. Do not reuse another build's patterns without fingerprint.

namespace face_capture {

struct LuaSignatureBuild {
  const char *id;
  const char *module_sha256; // empty = legacy / any (exact scan still required)
  const char *sig_lua_load;
  const char *sig_lua_pcallk;
  const char *sig_luaL_loadbufferx; // optional alternate loader
  const char *notes;
};

// Legacy prologue patterns from pre-Lite builds (may be 0 matches on current Lite).
inline constexpr const char *kLegacyLuaLoad =
    "48 89 5C 24 10 56 48 83 EC 50 49 8B D9 48 8B F1 "
    "4D 8B C8 4C 8B C2 48 8D 54 24 20";

inline constexpr const char *kLegacyLuaPcallk =
    "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58 "
    "49 63 C1 41 8B E8 48 8B F9 45 85 C9";

// Optional luaL_loadbufferx candidates — empty until probe verifies.
inline constexpr const char *kEmptySig = "";

inline const LuaSignatureBuild kLuaSignatureBuilds[] = {
    {"legacy-default", "", kLegacyLuaLoad, kLegacyLuaPcallk, kEmptySig,
     "Default pre-Lite patterns; use only when exact unique hits"},
};

inline constexpr int kLuaSignatureBuildCount =
    (int)(sizeof(kLuaSignatureBuilds) / sizeof(kLuaSignatureBuilds[0]));

} // namespace face_capture
