# Where Winds Meet (WWM) API Explorer

A premium, high-performance API Explorer and Backend Service for the "Where Winds Meet" game. This project provides a bridge between game data and external applications (like Discord bots) while offering a beautiful web interface for manual lookups.

## 🚀 Features

- **Player Lookup**: Search for players by **Number ID** or **Nickname** across multiple game regions (SEA & CN).
- **Club Search**: Query global guilds, martial arts clubs, and player associations.
- **Auto-Server Search**: Intelligent parallel searching across all known server regions with extremely low latency.
- **Face Plan Converter**: Migration tool for legacy face plan data.
- **Premium UI**: iOS-style glassmorphic dashboard with real-time JSON syntax highlighting and mobile-first design.
- **Data Enrichment**: Fetching extra details including fashion scores, cover images, online status, and character portraits.

## 🛠 Tech Stack

- **Backend**: Node.js, Express.js
- **Data Protocol**: Msgpack (MessagePack) integration for game-native communication.
- **Networking**: Custom DNS caching and HTTPS agent for optimized API calls.
- **Frontend**: Tailwind CSS, Vanilla JavaScript, Glassmorphism Aesthetics.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/KhoaDayy/find-api.git
   cd find-api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure your session:
   Create a `session.txt` file in the root directory and paste your valid game session key.

4. Start the server:
   ```bash
   node player_api.js
   ```

## 🖥 API Endpoints

Legacy (`node player_api.js`, port 3003):

- **GET `/lookup?name={nickname}`**: Search player by name.
- **GET `/lookup?id={number_id}`**: Search player by ID.
- **GET `/club_search?name={club_name}`**: Search for a club/guild.
- **GET `/id?keyword={text}`**: Intelligent redirect based on input type (Numeric ID vs Name).

WWM face inventory (`npm run start:wwm`, port 3005):

- **GET `/face_inventory?id={number_id}&server=CN|SEA`**
- **GET `/face_inventory?name={nickname}&server=CN|SEA`**

Optional query:

| Param | Default | Meaning |
|-------|---------|---------|
| `type` | `all` | `all` \| `face` \| `makeup` \| `unknown` |
| `include_long_code` | `1` | `0` drops long payload but keeps hash/length |
| `include_raw` | `0` | redacted plan raw |
| `include_empty_plans` | `0` | plans without `view_data.face_data` |
| `persist` | `1` if cache on | write inventory into SQLite cache |

Cache (local SQLite):

- **GET `/face_cache/:faceHash`**
- **GET `/face_cache/lookup?alias=ART...|plan_id|short|sha256:...`**

Short-code resolve (CDN download, **no upload**):

- **POST `/face_resolve`** body `{ "input": "wwm_facedata_R37_...", "include_long_code": true, "persist": true }`
- **GET `/face_resolve?code=...`**

Verified live: Global + China short codes for the same face return identical `face_hash` and map to one faces row with two `regional_codes` (status `verified`).

FilePicker JSON wrapper (C5.1) for share objects is typically:

```json
{ "pid", "face_data", "dressing", "hostnum", "face_share_type" }
```

- Face payload path: `$.face_data`
- **No `plan_id`** in wrapper → no automatic ART alias from short code alone
- Global wrapper embeds the **same CN `pid` + `hostnum`** as China → bot can show CN Author UID when input is Global (`metadata_source: global_filepicker_wrapper.cn_source_metadata`)
- Owner role is `filepicker_metadata_owner`, **not** `original_author`

Diagnostic:

```bash
node scripts/inspect_filepicker_object.js --compare
```

### FilePicker upload (C6 — capture only, no live send)

Static trace: `docs/C6_UPLOAD_STATIC_TRACE.md`

```bash
# Dry-run token / upload request models (never sends)
node scripts/parse_filepicker_capture.js --dry-run-token --region CN
node scripts/parse_filepicker_capture.js --dry-run-upload --region GLOBAL --body-json path/to/wrapper.json

# Parse a HAR / JSON / log capture from your own client (tokens redacted)
node scripts/parse_filepicker_capture.js path/to/capture.har
node scripts/parse_filepicker_capture.js path/to/capture.json --correlate debug/filepicker-CN-....json
```

Live upload requires **both**:

```
ENABLE_LIVE_FACE_UPLOAD=true
UPLOAD_SCHEMA_VERIFIED=true
```

Default both false. Schema is **not** verified until a real capture proves Content-Type + token placement + body shape.

Health:

- **GET `/health`** — process up
- **GET `/ready`** — DB integrity + session presence (booleans only, no secrets)

Env:

```
DATABASE_PATH=./data/faces.db
ENABLE_FACE_CACHE=true
CACHE_STORE_LONG_CODE=true
```

`CACHE_STORE_LONG_CODE=false` still stores hashes/metadata/aliases/codes but omits long payload (`[omitted]`) — re-ingest with long code needed later to fill.

**Not implemented yet:** FilePicker upload / token / creating new short codes.

### Face inventory notes (important)

- This is **community inventory → long Face Data** (`R67` / `D67`).
- It does **not** return FilePicker face short codes (`wwm_facedata_R37_*` / `yysls_facedata_R37_*`).
- `plan_id` is **not** a FilePicker object key. Do not build short codes from it.
- `picture_url` is a **preview asset**; `preview_object_key` is only parsed from that URL.
- Active equipped slot is currently **unknown** (`is_active: null`) — designer/redis do not expose a confirmed index in samples.
- Plan author (`plan.pid` → redis `number_id`) is **not** necessarily the player currently using the plan.

Diagnostic CLI (raw schema, no HTTP):

```bash
node scripts/inspect_player_face.js --server CN --id 0111452488
```

## 📂 Project Structure

- `player_api.js`: Legacy player/club API.
- `src/wwm/`: Face inventory API (client, services, routes).
- `src/parsers/`: Short-code / long-face parsers (no network).
- `src/hook/`: **Face share capture** (C++ modules: config, WinHTTP, Lua inject, redact).
- `Scripts/face_share_logger.lua`: Default passive Lua logger (not generic api_logger).
- `hook_config.json`: Paths/flags next to GameHook.dll (no hard-coded user paths).
- `scripts/inspect_player_face.js` / `inspect_filepicker_object.js` / `parse_filepicker_capture.js`
- `docs/HOOK_FACE_SHARE_CAPTURE.md`: How to build/run capture.
- `docs/C6_UPLOAD_STATIC_TRACE.md`: What is CERTAIN vs UNKNOWN for upload.
- Legacy: `Scripts/api_logger.lua` (not default).

### Game hook (passive capture)

Local (requires VS Build Tools x64 or MinGW g++):

```bat
build.bat
:: output: build\bin\GameHook.dll, Injector.exe, Scripts\, hook_config.json
```

**Cloud build (no local compiler):**

1. GitHub → **Actions** → **Build Windows Hook**
2. **Run workflow** (`workflow_dispatch`) or push changes under `src/hook/**`, `build.bat`, etc.
3. When the run succeeds, open the run → **Artifacts** → download `wwm-face-share-hook-<sha>`
4. Unzip → run `Injector.exe` next to `GameHook.dll` (as Admin) while the game is running
5. In-game Face Share once → parse:

```bash
node scripts/parse_filepicker_capture.js captures/face_share_capture.jsonl
```

Copy `hook_config.example.json` to `hook_config.json` if needed (personal config is gitignored).

See `docs/HOOK_FACE_SHARE_CAPTURE.md` and `docs/C6_UPLOAD_STATIC_TRACE.md`.

**Safety**

- Capture is **passive logging only** (no return-value edits, no token replay).
- Upload schema is **not verified** until you have a real JSONL from in-game Share.
- Do **not** set `UPLOAD_SCHEMA_VERIFIED=true` before that runtime verification.
- Never commit `session.txt`, `.env`, raw captures, or full Face Data.

## ⚠️ Disclaimer

This tool is designed for educational and data exploration purposes. Please ensure compliance with the game's terms of service.

---
Developed for the **Where Winds Meet** community.
