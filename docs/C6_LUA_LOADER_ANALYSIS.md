# C6 — WWM Lite Lua loader analysis

**Module SHA-256 (on-disk fingerprint):** `0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1`  
**lua_pcallk RVA:** `0x486C270` (exact matches=1, VA `0x14486C270`)  
**Legacy lua_load matches:** 0  
**Runtime hook enabled:** **NO**

## Important constraint

On-disk `wwm.exe` is **packed** (PE section `RawSize=0` for `.text`).  
Runtime image at base `0x140000000` is what the hook/probe sees.  
Candidate bytes come from **live probe** `first32` + call-site windows — **not** from the packed file.

Therefore:

- Signature uniqueness (`matches==1`) **cannot** be proven offline from the file alone.
- Runtime injection stays **disabled** until a live image scan confirms unique patterns.

## Best candidates (hypothesis, not enabled)

| RVA | Kind (hypothesis) | Conf | Near-pcall callers | Role |
|-----|-------------------|------|--------------------|------|
| **0x486F0A0** | `luaL_loadbufferx` | 85 | `0x214FD3B`, `0x490E8CF` | Primary loader candidate |
| **0x486F0E0** | `luaL_loadstring` (partial) | 60 | `0x1F7EEA9`, `0x2F6242D` | strlen(RDX) wrapper |

### 1. Exact loader RVA (candidate)

- **Primary:** `0x486F0A0`
- **Secondary wrapper:** `0x486F0E0` (not fully proven as loadstring→bufferx)

### 2. Loader kind

- `0x486F0A0` → **`luaL_loadbufferx`** (hypothesis, conf 85)
- `0x486F0E0` → **`luaL_loadstring`** (partial, conf 60)

### 3. Prototype

```c
// 0x486F0A0 hypothesis
int luaL_loadbufferx(
  lua_State *L,      // rcx
  const char *buff,  // rdx
  size_t sz,         // r8
  const char *name,  // r9
  const char *mode   // stack; seen via [rsp+70h] after sub rsp,48h
);

// 0x486F0E0 hypothesis
int luaL_loadstring(lua_State *L /*rcx*/, const char *s /*rdx*/);
```

### 4. Call graph evidence

**0x486F0A0 first32:**

```
sub  rsp, 48h
mov  rax, [rsp+70h]       ; 5th arg (mode?)
mov  [rsp+30h], rdx       ; save buff
lea  rdx, [rip+0x10EB]    ; constant string
mov  [rsp+38h], r8        ; save size
lea  r8, [rsp+30h]
```

**0x486F0E0 first32:**

```
sub  rsp, 48h
mov  [rsp+30h], rdx
mov  rax, -1
inc  rax
cmp  byte ptr [rdx+rax], 0
jne  $-3                  ; strlen(RDX)
mov  r9, rdx
```

F0E0→F0A0 chain: **NOT proven** (body after strlen not in probe window).

### 5. Relation to lua_pcallk

| pcall call RVA | F0E0 nearby | F0A0 nearby | after `test eax,eax` |
|----------------|-------------|-------------|----------------------|
| `0x1F7EEA9` | yes | | yes |
| `0x214FD3B` | | yes | |
| `0x2F6242D` | yes | | yes |
| `0x490E8CF` | | yes | yes |

Load-like call appears in nearby targets of pcall sites that check EAX status.

### 6. Xref `=(load)`

- String RVA: `0x68E7068`
- Code xrefs: **not resolved** offline (needs full runtime `.text`)

### 7. Signature patterns (provisional)

**0x486F0A0:**

```
48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 ?? ?? ?? ?? 4C 89 44 24 38 4C 8D
```

**0x486F0E0:**

```
48 83 EC 48 48 89 54 24 30 48 C7 C0 FF FF FF FF 48 FF C0 80 3C 02 00 75 F7 4C 8B CA
```

### 8. Unique match count

**Unknown** — packed PE prevents `.text` scan. Must re-run with `--pid` while game is live.

### 9. Confidence

- F0A0 as loadbufferx-shaped: **85** (structure + pcall proximity)
- F0E0 as loadstring-shaped: **60** (strlen only)
- Chain F0E0→F0A0: **not established**
- Safe to enable inject: **0** until uniqueness proven

### 10. Hypotheses rejected

| RVA | Reason |
|-----|--------|
| `0x4868C80` | stack top arithmetic helper |
| `0x4868CA0` | stack index helper |
| `0x4868D50` | TValue move helper |
| `0x4868D90` | stack access helper |
| Legacy `lua_load` pattern | 0 matches |

## Runtime enable criteria (not met)

1. module sha256 match — OK  
2. loader signature exact matches == 1 on **runtime** image — **blocked**  
3. pcall matches == 1 — OK  
4. full prototype / inner call proven — **partial**  

## How to finish (game running, Admin)

```bat
python scripts/analyze_lua_loader.py ^
  --module "C:\Program Files\wwm\wwm_lite\Engine\Binaries\Win64r\wwm.exe" ^
  --probe captures\lua_signature_probe.json ^
  --pid <wwm_pid> ^
  --out captures\lua_loader_analysis.json ^
  --report docs\C6_LUA_LOADER_ANALYSIS.md
```

## Safety

- No fuzzy hooks.
- No live FilePicker upload.
- **UPLOAD_SCHEMA_VERIFIED** remains false / unset.
