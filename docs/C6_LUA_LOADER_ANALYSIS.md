# C6 — WWM Lite Lua loader analysis (verification pass)

**Module SHA-256:** `0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1`  
**lua_pcallk RVA:** `0x486C270` (matches=1)  
**Legacy lua_load matches:** 0  
**Runtime hook enabled:** **NO** (`verified: false`)

Machine-readable: run `Scripts/verify_lua_loader.py` → `captures/lua_loader_verification.json` (gitignored under `captures/`).

## Final verdict object

```json
{
  "verified": false,
  "loader_rva": "0x486F0A0",
  "loader_kind": "luaL_loadbufferx",
  "prototype": "int __cdecl(lua_State* L, const char* buff, size_t size, const char* name, const char* mode)",
  "loadstring_wrapper_rva": "0x486F0E0",
  "loadstring_calls_loader": false,
  "pcall_flow_verified": true,
  "load_string_xref_verified": false,
  "signature_matches": null,
  "confidence": 75,
  "enable_runtime": false
}
```

## 1. Relation `0x486F0E0` → `0x486F0A0`

| Check | Result |
|-------|--------|
| F0E0 receives RCX=L, RDX=string | **YES** (callers) |
| F0E0 strlen(RDX) in prologue | **YES** |
| F0E0 calls F0A0 with (L, buf, len, name, mode) | **NOT PROVEN** — body truncated after `mov r9, rdx` in probe first32 |

**Conclusion:** F0E0 is loadstring-**shaped**, but cannot be classified as `luaL_loadstring` wrapping F0A0 until full body is read from a live process.

## 2. Prototype of `0x486F0A0` (from callers, not prologue alone)

### Strongest caller: `0x490E8B1` → F0A0 → pcall `0x490E8CF`

```
lea  r9, [rip+const]       ; name
mov  [rsp+0x20], rbp       ; mode (5th arg)
lea  rdx, [rsp+0x30]       ; buff
mov  rcx, rdi              ; L
call 0x486F0A0
test eax, eax
jne  fail
...
call 0x486C270             ; lua_pcallk
test eax, eax
```

### Thin wrapper: `0x214FD15` → F0A0 → pcall `0x214FD3B`

```
mov  rbx, rcx              ; save L
mov  [rsp+0x20], 0         ; mode = NULL
call 0x486F0A0             ; rdx/r8/r9 from caller
test eax, eax
jne  skip_pcall
xor  r9d,r9d / r8d / edx
mov  [rsp+0x20], 0
mov  rcx, rbx
call 0x486C270             ; pcall only if load OK
```

| Arg | Semantic |
|-----|----------|
| RCX | `lua_State* L` |
| RDX | `const char* buff` |
| R8 | `size_t size` (prologue also saves r8 to `[rsp+0x38]`) |
| R9 | `const char* name` (set by caller or default inside) |
| `[rsp+20h]` | `const char* mode` (often 0 / NULL) |
| EAX return | Lua status; `test eax,eax` before pcall |

**Kind hypothesis remains `luaL_loadbufferx`.** Inner call to `lua_load` still not visible (body incomplete).

## 3. Load → pcall flow — **VERIFIED**

| Loader call | Loader | `test eax` | pcall | `test eax` after pcall |
|-------------|--------|------------|-------|-------------------------|
| `0x1F7EE86` | F0E0 | yes | `0x1F7EEA9` | yes |
| `0x214FD15` | F0A0 | yes | `0x214FD3B` | (success path) |
| `0x2F623F8` | F0E0 | yes | `0x2F6242D` | yes |
| `0x490E8B1` | F0A0 | yes | `0x490E8CF` | yes |

Canonical pattern:

```
call loader
test eax, eax
jnz  fail
… setup nargs …
call lua_pcallk   ; 0x486C270
test eax, eax
```

## 4. Xref `=(load)` (`0x68E7068`)

- String present in probe anchors.
- **No** RIP-relative code xref found inside pcall capture windows.
- **Not verified.**

## 5. Exact signature

**Provisional pattern for F0A0:**

```
48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 ?? ?? ?? ?? 4C 89 44 24 38 4C 8D 44 24 30
```

| Requirement | Status |
|-------------|--------|
| Unique match on full runtime `.text` | **UNKNOWN** |
| Locked to SHA `0cfdfcc6…` | ready once unique |

On-disk PE is **packed** (`RawSize=0`). Uniqueness **cannot** be proven without `--pid` while game runs (Admin) or an unpacked dump.

## 6. Why still not enabling runtime

Need **all**:

1. SHA match — OK  
2. `signature_matches == 1` on **runtime** image — **blocked**  
3. pcall flow verified — **OK**  
4. Full prototype / F0E0→F0A0 chain — **partial**  
5. Optional `=(load)` xref — missing  

Until (2) is green, inject stays off.

## 7. How to finish (game running as Admin)

```bat
python Scripts/analyze_lua_loader.py ^
  --module "C:\Program Files\wwm\wwm_lite\Engine\Binaries\Win64r\wwm.exe" ^
  --probe captures\lua_signature_probe.json ^
  --pid <wwm_pid> ^
  --out captures\lua_loader_analysis.json ^
  --report docs\C6_LUA_LOADER_ANALYSIS.md

python Scripts/verify_lua_loader.py ^
  --probe captures\lua_signature_probe.json ^
  --out captures\lua_loader_verification.json
```

Need from live read (≥0x100 bytes at F0A0 and F0E0):

- F0E0’s `call` target after strlen (must be F0A0 for loadstring chain)
- F0A0’s inner `call` (parser / `lua_load`)
- Unique pattern scan of full `.text` pages

Only then: build-specific `luaL_loadbufferx` adapter + CI artifact.

## Safety

- No fuzzy hooks  
- No live FilePicker upload  
- **UPLOAD_SCHEMA_VERIFIED** remains false  
