# find-api

Tools for **Where Winds Meet** profile / face data research:

| Area | What it does |
|------|----------------|
| **Face API** | Inventory, cache, and short-code resolve (Node) |
| **Game hook** | Passive in-process capture of Face Share → FilePicker |
| **Legacy explorer** | Simple player / club lookup UI |

Educational / research use only. Respect the game ToS and only use **your own** session and accounts.

---

## Quick start (Face API)

```bash
git clone https://github.com/KhoaDayy/find-api.git
cd find-api
npm install
```

Create `.env` (never commit it):

```env
WWM_SESSION_KEY_CN=...
WWM_SESSION_KEY_GLOBAL=...
# or GAME_SESSION=... for both

DATABASE_PATH=./data/faces.db
ENABLE_FACE_CACHE=true
CACHE_STORE_LONG_CODE=true
ENABLE_LIVE_FACE_UPLOAD=false
UPLOAD_SCHEMA_VERIFIED=false
```

```bash
npm test
npm run start:wwm
# → http://localhost:3005
```

| Check | |
|-------|--|
| `GET /health` | Process up |
| `GET /ready` | DB + session flags (no secrets) |

---

## Face API (`npm run start:wwm`)

### Inventory

```http
GET /face_inventory?id={number_id}&server=CN|SEA
GET /face_inventory?name={nickname}&server=CN|SEA
```

| Query | Default | Description |
|-------|---------|-------------|
| `type` | `all` | `all` \| `face` \| `makeup` \| `unknown` |
| `include_long_code` | `1` | `0` keeps hash/length only |
| `include_raw` | `0` | Redacted plan raw |
| `include_empty_plans` | `0` | Plans without face payload |
| `persist` | on if cache enabled | Write to SQLite |

Community inventory → long face codes (`R67` / `D67`).  
Does **not** invent FilePicker short codes from `plan_id`.

### Cache

```http
GET /face_cache/:faceHash
GET /face_cache/lookup?alias=ART...|plan_id|short|sha256:...
```

### Short-code resolve (CDN read-only)

```http
POST /face_resolve
Content-Type: application/json

{ "input": "wwm_facedata_R37_...", "include_long_code": true, "persist": true }
```

Also: `GET /face_resolve?code=...`

| Fact (live-verified) | |
|----------------------|--|
| Global + China short codes can share one `face_hash` | |
| CDN object is often JSON: `pid`, `face_data`, `dressing`, `hostnum`, `face_share_type` | |
| Face payload path | `$.face_data` |
| Global wrappers may embed CN `pid`/`hostnum` | metadata role: `filepicker_metadata_owner` (not “original author”) |

### Diagnostics

```bash
npm run inspect:face -- --server CN --id 0111452488
npm run inspect:fp -- --compare
npm run parse:capture -- path/to/capture.har
```

### Upload status

Out-of-game FilePicker **upload is not enabled**.

Dry-run builders and capture parsing only:

```bash
node Scripts/parse_filepicker_capture.js --dry-run-token --region CN
node Scripts/parse_filepicker_capture.js capture.jsonl
```

Live send requires **both** (default off):

```env
ENABLE_LIVE_FACE_UPLOAD=true
UPLOAD_SCHEMA_VERIFIED=true
```

Do not set `UPLOAD_SCHEMA_VERIFIED` until a real in-game Share capture proves Content-Type, token placement, and body shape. See [docs/C6_UPLOAD_STATIC_TRACE.md](docs/C6_UPLOAD_STATIC_TRACE.md).

---

## Game hook (passive capture)

Injected logger for the Face Share → FilePicker path. **Observe only** — no return-value edits, no token replay.

### Download (no local compiler)

1. Open [Releases](https://github.com/KhoaDayy/find-api/releases) or [Actions → Build Windows Hook](https://github.com/KhoaDayy/find-api/actions/workflows/build-hook.yml)
2. Download the latest `wwm-face-share-hook-*.zip` / artifact
3. Unzip so `GameHook.dll`, `Injector.exe`, `Scripts/`, and config sit together
4. Start the game (`yysls.exe` / `wwm.exe` per config)
5. Run `Injector.exe` as Administrator (or `Injector.exe --pid <pid>`) → F5 re-arms Lua inject
6. Trigger **Face Share** once in-game
7. Parse:

```bash
node Scripts/parse_filepicker_capture.js captures/face_share_capture.jsonl
```

Copy `hook_config.example.json` → `hook_config.json` for local overrides (gitignored).

### Build locally

Requires Visual Studio Build Tools (x64) or MinGW:

```bat
build.bat
:: → build\bin\
```

Details: [docs/HOOK_FACE_SHARE_CAPTURE.md](docs/HOOK_FACE_SHARE_CAPTURE.md).

CI also publishes a GitHub Release (`hook-<shortsha>`) on successful `main` builds.

---

## Legacy player explorer

```bash
# session.txt or env — your key only
node player_api.js
# → http://localhost:3003
```

| Endpoint | |
|----------|--|
| `GET /lookup?id=` / `?name=` | Player search |
| `GET /club_search?name=` | Club search |
| `GET /id?keyword=` | Redirect helper |

UI: `index.html`.

---

## Layout

```
src/wwm/           Face inventory, cache, resolve API
src/hook/          C++ capture (Lua-first inject; optional WinHTTP fallback)
src/storage/       SQLite face cache
src/parsers/       Short-code / long-face parsers
Scripts/           face_share_logger.lua + JS diagnostics
test/              Unit tests (npm test)
docs/              Hook + upload static analysis
build.bat          Local MSVC/MinGW hook build
.github/workflows  Windows x64 hook CI + Releases
```

---

## Safety

- Use only **your** session / accounts.
- Never commit `session.txt`, `.env`, databases, raw captures, or full face payloads.
- Hook capture redacts tokens, sessions, and long face data by default.
- Prebuilt DLLs are **not** in the git tree — use Releases / Actions only.

---

## License / disclaimer

Research tooling for personal education. Not affiliated with NetEase. You are responsible for compliance with applicable terms and law.
