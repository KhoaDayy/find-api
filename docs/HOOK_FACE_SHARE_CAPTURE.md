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
3. Run `Injector.exe` as Administrator.
4. Console: F5 re-injects Lua logger (e.g. after loading character).
5. In-game: open **Face Share** once (the flow that uploads face data).
6. Capture file: `captures/face_share_capture.jsonl`

## Parse

```bash
node scripts/parse_filepicker_capture.js captures/face_share_capture.jsonl
```

## Config (`hook_config.json`)

| Key | Default | Meaning |
|-----|---------|---------|
| `target_process` | `yysls.exe` | Module name for Lua pattern scan |
| `lua_script` | `Scripts/face_share_logger.lua` | Injected logger |
| `output_file` | `captures/face_share_capture.jsonl` | JSONL events |
| `enable_lua_hook` | true | Pattern-scan + inject |
| `enable_winhttp_hook` | true | WinHTTP allowlisted capture |
| `capture_only_filepicker` | true | Filter non-face-fp traffic |
| `redact_secrets` | true | Redact token/session headers |
| `capture_full_face_data` | false | Never write full R67 by default |
| `unsafe_save_session` | false | **Do not** write session.txt |

## Architecture

```
Injector.exe
  → LoadLibraryW(GameHook.dll)
       → MinHook
       → lua_pcallk detour → inject face_share_logger.lua (once per lua_State)
       → WinHTTP Connect/Open/Send/Write/Read/Close (filepicker hosts only)
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
