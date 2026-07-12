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
  const char *sig_lua_load;           // classic lua_load (optional)
  const char *sig_lua_pcallk;
  const char *sig_luaL_loadbufferx; // preferred inject adapter when set
  const char *notes;
  // If non-zero: E8 in loadbufferx body must resolve to module_base + this RVA.
  unsigned inner_lua_load_rva;
};

// Legacy prologue patterns from pre-Lite builds (may be 0 matches on current Lite).
inline constexpr const char *kLegacyLuaLoad =
    "48 89 5C 24 10 56 48 83 EC 50 49 8B D9 48 8B F1 "
    "4D 8B C8 4C 8B C2 48 8D 54 24 20";

inline constexpr const char *kLegacyLuaPcallk =
    "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58 "
    "49 63 C1 41 8B E8 48 8B F9 45 85 C9";

// WWM Lite (sha 0cfdfcc6…): luaL_loadbufferx @ runtime RVA 0x486F0A0
// Full function: frame, save buff/size/mode, lea reader, call lua_load, epilogue.
inline constexpr const char *kWwmLiteLoadBufferX =
    "48 83 EC 48 "
    "48 8B 44 24 70 "
    "48 89 54 24 30 "
    "48 8D 15 ?? ?? ?? ?? "
    "4C 89 44 24 38 "
    "4C 8D 44 24 30 "
    "48 89 44 24 20 "
    "E8 ?? ?? ?? ?? "
    "48 83 C4 48 "
    "C3";

// Sibling luaL_loadstring (diagnostic / future) — not used for inject.
inline constexpr const char *kWwmLiteLoadString =
    "48 83 EC 48 "
    "48 89 54 24 30 "
    "48 C7 C0 FF FF FF FF "
    "48 FF C0 "
    "80 3C 02 00 "
    "75 F7 "
    "4C 8B CA "
    "48 89 44 24 38 "
    "48 8D 15 ?? ?? ?? ?? "
    "48 C7 44 24 20 00 00 00 00 "
    "4C 8D 44 24 30 "
    "E8 ?? ?? ?? ?? "
    "48 83 C4 48 "
    "C3";

inline constexpr const char *kEmptySig = "";

inline const LuaSignatureBuild kLuaSignatureBuilds[] = {
    {"legacy-default", "", kLegacyLuaLoad, kLegacyLuaPcallk, kEmptySig,
     "Default pre-Lite patterns; use only when exact unique hits", 0},
    {"wwm-lite-0cfdfcc6",
     "0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1",
     kEmptySig, // classic lua_load not used for inject on this build
     kLegacyLuaPcallk, kWwmLiteLoadBufferX,
     "WWM Lite: luaL_loadbufferx sibling wrappers → lua_load @ 0x486C600",
     0x486C600u},
};

inline constexpr int kLuaSignatureBuildCount =
    (int)(sizeof(kLuaSignatureBuilds) / sizeof(kLuaSignatureBuilds[0]));

} // namespace face_capture
