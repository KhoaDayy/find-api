# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Research tooling for **Where Winds Meet** face/profile data. Three layers:

1. **Face API** (`src/wwm/`) — Node inventory/cache/resolve server
2. **Game hook** (`src/hook/`, `src/dllmain.cpp`) — passive in-process Face Share → FilePicker capture
3. **Legacy explorer** (`player_api.js` + `src/services/`) — simple player/club lookup UI

Educational / personal research only. Use only the operator's own sessions. Never commit secrets, captures with full face payloads, or session keys.

## Commands

```bash
npm install
npm test                          # all unit tests (assert-based, no framework)
npm run test:parsers              # single suite — also: test:inventory, test:cache,
                                  # test:hardening, test:resolve, test:fpmeta,
                                  # test:upload, test:hook
npm run start:wwm                 # Face API → http://localhost:3005
node player_api.js                # legacy explorer → http://localhost:3003

# diagnostics
npm run inspect:face -- --server CN --id 0111452488
npm run inspect:fp -- --compare
npm run parse:capture -- path/to/capture.jsonl

# FilePicker capture parse / dry-run (upload stays gated off)
node Scripts/parse_filepicker_capture.js captures/face_share_capture.jsonl
node Scripts/parse_filepicker_capture.js --dry-run-token --region CN
```

### Hook build (Windows x64)

```bat
build.bat
:: → build\bin\GameHook.dll, Injector.exe, Scripts\, hook_config.json
```

Requires VS Build Tools (MSVC x64) or MinGW `g++`. CMake alternative: root `CMakeLists.txt` (also optional font injector targets).

CI: `.github/workflows/build-hook.yml` builds on hook-related paths and publishes Release `hook-<shortsha>`.

**Always use `build\bin\*`** — never the old prebuilt `hook\` / `hook cn\` folders.

## Architecture

### Face API (`npm run start:wwm`)

```
src/wwm/server.js          listen + graceful SQLite shutdown
src/wwm/app.js             Express: /health, /ready, routes
src/wwm/routes/            faceInventory / faceCache / faceResolve
src/wwm/services/          business logic (inventory, resolve, cache, FilePicker)
src/wwm/client.js          HTTPS + msgpack upstream (DNS via 8.8.8.8, keepAlive)
src/wwm/session.js         dual-region session resolution
src/config/regions.js      CN vs SEA hosts, CDN allowlists, short-code regex
src/parsers/               short codes (yysls_|wwm_facedata_R…) + long face (R67/D67)
src/storage/               node:sqlite WAL cache (migrations via PRAGMA user_version)
src/utils/                 hash, redact, logger
```

Request flow (inventory):

`faceInventoryRoute` → `inventoryService` → community plan list → long face codes → optional `cacheIngestService` → SQLite

Request flow (resolve):

`faceResolveRoute` → `shortCodeResolveService` → CDN download (`filePickerDownloadService`) → extract `$.face_data` → hash/cache

Key domain facts (live-verified, don't "fix" without evidence):

- Global + CN short codes can share one `face_hash`
- CDN body is often JSON: `pid`, `face_data`, `dressing`, `hostnum`, `face_share_type`
- Inventory returns long codes only — it does **not** invent FilePicker short codes from `plan_id`
- Metadata role `filepicker_metadata_owner` ≠ original author

### Sessions & env

| Source (first hit per region) | |
|-------------------------------|--|
| `WWM_SESSION_KEY_CN` / `WWM_SESSION_KEY_GLOBAL` | preferred |
| `GAME_SESSION` | both regions |
| `session.cn.txt` / `session.global.txt` / `session.txt` | files at repo root |

Other env: `DATABASE_PATH` (default `./data/faces.db`), `ENABLE_FACE_CACHE`, `CACHE_STORE_LONG_CODE`, `PORT`/`WWM_PORT` (3005), `LOG_LEVEL`.

Live FilePicker **upload is disabled** unless both:

```env
ENABLE_LIVE_FACE_UPLOAD=true
UPLOAD_SCHEMA_VERIFIED=true
```

Do not set `UPLOAD_SCHEMA_VERIFIED` until a real in-game Share capture proves Content-Type, token placement, and body shape. See `docs/C6_UPLOAD_STATIC_TRACE.md`. Dry-run builders live in `filePickerUploadRequestBuilder.js` / `filePickerTokenProvider.js`.

### Game hook (passive only)

```
Injector.exe → LoadLibraryW(GameHook.dll)
  MinHook
  WinHTTP Connect/Open/Send/Write/Read/Close  (filepicker hosts; default ON)
  optional lua_pcallk detour → Scripts/face_share_logger.lua  (default OFF)
  → captures/face_share_capture.jsonl
```

Sources: `src/dllmain.cpp` (fail-soft boot, SEH isolated from C++ unwind — MSVC C2712), `src/hook/*`, `src/injector.cpp`, vendored MinHook under `lib/minhook/`.

Config: copy `hook_config.example.json` → `hook_config.json` (gitignored). Defaults are **Lua-first**: `enable_lua_hook: true`, `enable_winhttp_fallback: false`, redaction on, full face data off. Boot never waits on WinHTTP before Lua. Injector: `Injector.exe --pid <pid>`. Boot log: `hook_boot.log` next to the DLL. Optional console: `GAMEHOOK_CONSOLE=1`.

Details: `docs/HOOK_FACE_SHARE_CAPTURE.md`.

### Legacy player explorer

`player_api.js` on port 3003 uses older `src/client.js` + `src/services/playerService.js` / `clubService.js` and `src/constants.js` (`SERVERS` hosts). Separate from the WWM face stack. UI: `index.html`.

Note: `src/constants.js` has hard-coded absolute session paths and a default key leftover — prefer env/`session.txt`; do not expand that pattern in new code. New work should go through `src/wwm/session.js`.

### Tests

Plain Node assert scripts in `test/*.test.js` — no Jest/Mocha. Run one file with `node test/<name>.test.js` or the matching `npm run test:*` script.

### Safety conventions for edits

- Redact tokens/sessions/long face payloads in logs and captures (`src/utils/redact.js`, hook `src/hook/redact.*`).
- Keep CDN/upload hosts on allowlists in `regions.js` / capture parser.
- Do not enable live upload or un-redacted capture by default.
- Gitignores secrets, `data/`, `build/`, `captures/`, `*.dll`/`*.exe`, local hook dirs, and dump artifacts — don't force-add them.
)
