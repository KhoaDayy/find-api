# C6A — Static FilePicker upload trace

Sources: iKasu2k/WWM_Lua_Dump (decompiled), TekMonts stubs, live C5.1 download wrappers.

## Certainty legend

- **CERTAIN** — readable in dump or proven live
- **HIGH** — strong inference from callers/constants + live
- **UNKNOWN** — decompiler destroyed evidence; needs capture

---

## Call chain (CERTAIN structure)

```
FaceShareController:init(kwargs)
  face_data = kwargs.face_data
  guise_data = kwargs.guise_data
  → upload_face_data()
       → G.filepicker_manager:upload_plain_text_to_filepicker(
            encode_upload_data, callback, nil, PIC_FROM_SYSTEM)
            // hex_fp_review_id NOT passed in FaceShare call (nil/omitted in dump)
       → callback(result, content, detail)
            detail.pict_url → split("/") → QR face_url:{segment}
```

Token path (CERTAIN structure, mangled details):

```
add_upload_task(task, usage, from, hex_fp_review_id)
  task.review_id = hex_fp_review_id
  review from G.datam.fp_review_config[hex_fp_review_id].review
       or REVIEW_VERIFYING
  if no token → _get_server_token(TOKEN_FOR_UPLOAD, url, review, hex_fp_review_id)
       params include: device_name, review, + review_id field (name mangled)
       rpc_gen_filepicker_token(params, usage, url)
  rpc_server_filepicker_token(server_token, usage, url, review)
       FACE_TAG "_face_123_face_" → face_filepicker_manager:gen_server_token_back
  gen_server_token_back: strip _token_tag prefix → _server_token → _real_upload_file
  _real_upload_file: task.content → _read_upload_file_callback
  _read_upload_file_callback:
       POST self._fp_post_url  (FACE_SERVICE_URL / FOREIGN_FACE_SERVICE_URL)
       body = content (string/bytes)
       headers = ??? (UNKNOWN — decompile wiped table)
  _upload_finish_callback → callback(result, content, detail)
```

## 1. Upload content type

| Claim | Status |
|---|---|
| Manager API is `upload_plain_text_to_filepicker(content, ...)` | CERTAIN |
| FaceShare passes `encode_upload_data` derived from `self.face_data` | CERTAIN (name) |
| Encoding uses avatar / hostnum | HIGH (line mangled: `avatar.hostnum(upload_data)`) |
| Content is JSON string of 5-field wrapper | **HIGH from live download**, not proven as *upload* body |
| Content is raw R67 only | POSSIBLE if server wraps — **UNKNOWN** without capture |
| cjson.encode used before upload | UNKNOWN (cjson required in file; encode site mangled / used elsewhere for QR protocol) |

**Live download body (CERTAIN, C5.1):**

```json
{
  "pid": "...",
  "face_data": "R67...",
  "dressing": { "...": { "view_no", "slot_no", "ID", "owning", "ex", "own_type" } },
  "hostnum": 10011,
  "face_share_type": 2
}
```

This proves **stored object** shape, not necessarily **client upload body** (server may wrap).

## 2. Where wrapper is built

| Claim | Status |
|---|---|
| Built inside FaceShareController:upload_face_data | UNKNOWN (decompile shows face_data → encode_upload_data only) |
| Built by caller before opening FaceShareWindow | UNKNOWN (FaceShareWindow required from pure_face_create_page; open kwargs site not clean) |
| kwargs include `face_data` + `guise_data` | CERTAIN |
| Table with exactly pid/face_data/dressing/hostnum/face_share_type in client | **NOT FOUND** as clean source in dumps |

## 3. dressing source

| Claim | Status |
|---|---|
| Live objects contain multi-slot dressing map | CERTAIN |
| Comes from avatar guise/dressing state | HIGH (guise_data on FaceShare; imp_face dressing helpers exist) |
| Empty dressing allowed | UNKNOWN |
| Optional field | UNKNOWN |

## 4. face_share_type = 2

| Claim | Status |
|---|---|
| Live value is integer 2 | CERTAIN |
| `face_consts.RIGHT_SHARE_TYPE = 2` exists | CERTAIN |
| RIGHT_SHARE_TYPE **is** the source of wrapper field face_share_type | **HYPOTHESIS only** — name is UI right-panel share mode, not proven as payload field |
| Enum / server-assigned | UNKNOWN |

**Do not equate PIC_REVIEW_FACE_SHARE=12 with REVIEW_ID_FACE_SHARE=129.**

| Constant | Value | Role (CERTAIN name only) |
|---|---|---|
| PIC_REVIEW_FACE_SHARE | 12 | picture review enum family |
| REVIEW_ID_FACE_SHARE | 129 | review_id family for fp_review_config |
| PIC_FROM_SYSTEM | pic_from_system | `from` arg on FaceShare upload |
| TOKEN_FOR_UPLOAD | 1 | usage for token gen |
| FACE_TAG | _face_123_face_ | token routing tag |
| FACE_SERVICE_URL | https://fp.ps.netease.com/h72face/file/new/ | CN upload POST base |
| FOREIGN_FACE_SERVICE_URL | https://fp.ps.easebar.com/h72facesg/file/new/ | Global upload POST base |

Which of 12 vs 129 is `hex_fp_review_id` for face share: **UNKNOWN** (FaceShare call does not pass review_id in dump).

## 5. HTTP upload request

| Piece | Status |
|---|---|
| Method POST | CERTAIN |
| URL = face filepicker `/file/new/` host | CERTAIN (constants + `_fp_post_url`) |
| Body = task content string | CERTAIN |
| Content-Type | UNKNOWN |
| Token header name / query / body | UNKNOWN |
| Multipart vs raw | UNKNOWN (plain_text path suggests raw/text body, not proven) |
| Response `detail.pict_url` | CERTAIN (callback field name) |
| Object key = last path segment of pict_url | HIGH |

## 6. Cases for C6C (need capture)

| Case | Meaning |
|---|---|
| A | Client uploads JSON wrapper as-is |
| B | Client uploads raw R67; server wraps metadata |
| C | Multipart JSON + extra fields |
| D | Other |

**Cannot choose A–D without capture.** Live download proves stored shape only.

## 7. What capture must prove

1. Exact body bytes (JSON vs R67 vs multipart)  
2. Content-Type  
3. Token placement  
4. Token RPC params (usage, url, review, review_id keys)  
5. Whether 12 or 129 is used  
6. Upload response schema  
7. Re-download object equals upload body (or server-normalized)

---

*Generated for find-api C6 — do not treat UNKNOWN items as implemented.*
