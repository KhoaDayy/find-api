# Face FilePicker Share Capture Hook

Passive logger only. No request mutation, no token replay, no live out-of-game upload.

## Build

```bat
build.bat
```

Outputs (under `build\bin` or `build\Release`):

- `GameHook.dll`
- `Injector.exe`
- `Scripts/face_share_logger.lua`
- `hook_config.json`

## Run

1. Copy the entire output folder together (DLL + Injector + Scripts + config).
2. Start the game (`target_process` in `hook_config.json`, default `yysls.exe`; injector also tries `wwm.exe`).
3. Wait until you are fully in the world (not launcher/login splash).
4. Run `Injector.exe` as Administrator from the **same folder** as `GameHook.dll`.
5. Read Injector output:
   - `LoadLibraryW exit code = 0` → DLL did not load (path/AC/redistributable).
   - Game process exits → DLL init crashed; open `hook_boot.log` next to the DLL.
6. If a console titled **Face Share Capture Hook** appears, init survived.
7. Default config is **Lua-first**: `enable_lua_hook: true`, `enable_winhttp_fallback: false`.
8. In-game: open **Face Share** once (press **F5** to re-arm Lua inject if needed).
9. Capture file: `captures/face_share_capture.jsonl`  
   Boot diagnostics: `hook_boot.log`

## Parse

```bash
node scripts/parse_filepicker_capture.js captures/face_share_capture.jsonl
```

## Config (`hook_config.json`)

| Key | Default | Meaning |
|-----|---------|---------|
| `target_processes` | `wwm.exe`, `yysls.exe`, `WhereWindsMeet.exe` | Injector search list + Lua scan names |
| `lua_script` | `Scripts/face_share_logger.lua` | Injected logger |
| `capture_dir` | `captures` | JSONL directory (created on boot) |
| `enable_lua_hook` | **true** | Pattern-scan `lua_pcallk` + inject logger |
| `enable_winhttp_fallback` | **false** | Optional WinHTTP allowlist (15s wait, non-blocking) |
| `enable_lua_debug_hook` | false | Reserved; never auto-enables `debug.sethook` |
| `capture_only_filepicker` | true | Filter non-face-fp traffic (WinHTTP path) |
| `redact_secrets` | true | Redact token/session headers |
| `capture_full_face_data` | false | Never write full R67 by default |
| `unsafe_save_session` | false | **Do not** write session.txt |

Injector: `Injector.exe`, `Injector.exe wwm.exe`, or `Injector.exe --pid 20716`.

## Architecture

```
Injector.exe [--pid N]
  → LoadLibraryW(GameHook.dll)
       → create captures/
       → MinHook
       → scan game-dir modules for lua_load / lua_pcallk (exact 1 match each)
       → lua_pcallk detour → inject face_share_logger.lua (once per lua_State)
       → optional WinHTTP worker only if enable_winhttp_fallback=true
       → captures/face_share_capture.jsonl
```

Legacy `Scripts/api_logger.lua` is **not** the default (kept as legacy only).

## Safety

- Return values of game functions are not modified.
- Tokens/sessions/cookies are redacted.
- Face data stored as `{__face_data__, length, hash}` only.
- Live FilePicker upload remains gated by `ENABLE_LIVE_FACE_UPLOAD` + `UPLOAD_SCHEMA_VERIFIED`.

## What a good capture should prove

1. Lua events: `face_share_start`, `upload_plain_text`, `token_rpc_*`, `filepicker_callback`
2. WinHTTP `http_exchange` with POST `/h72face*/file/new/`
3. Exact `Content-Type` and token header name
4. Body kind: `json` vs `raw_face_data` vs `multipart`
5. `pict_url` / `object_key` on response
6. No raw token/session/full R67 in the JSONL file
