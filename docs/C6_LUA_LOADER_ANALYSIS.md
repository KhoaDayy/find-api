# C6 — WWM Lite Lua loader analysis (sibling wrappers + adapter)

**Module SHA-256:** `0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1`  
**lua_pcallk RVA:** `0x486C270`  
**Runtime adapter:** build-specific **`luaL_loadbufferx`** when in-process scan finds **exactly 1** match and inner `E8` → `0x486C600`.

## Wrapper model (verified structure)

```
0x486F0A0  luaL_loadbufferx-like  ──┐
                                     ├── call 0x486C600  (lua_load)
0x486F0E0  luaL_loadstring-like   ──┘
```

**Relationship:** siblings (both call the same core loader).  
**Not** F0E0 → F0A0.

### 0x486F0A0 (inject adapter)

```
sub  rsp, 48h
mov  rax, [rsp+70h]          ; mode (5th arg)
mov  [rsp+30h], rdx          ; buff
lea  rdx, [rip+rel]          ; reader callback (~0x48701A0)
mov  [rsp+38h], r8           ; size
lea  r8, [rsp+30h]           ; &context {buff,size}
mov  [rsp+20h], rax          ; mode
call 0x486C600               ; lua_load(L, reader, data, name, mode)
add  rsp, 48h
ret
```

Prototype:

```c
int luaL_loadbufferx(lua_State *L, const char *buff, size_t size,
                     const char *name, const char *mode);
```

### 0x486F0E0 (sibling, not used for inject)

```
sub rsp,48h
mov [rsp+30h], rdx
strlen(RDX)
mov r9, rdx                  ; chunkname = source string
mov [rsp+38h], rax           ; len
lea rdx, [rip+rel]           ; same reader family
mov [rsp+20h], 0             ; mode = NULL
lea r8, [rsp+30h]
call 0x486C600
add rsp,48h
ret
```

### 0x486C600

Core **`lua_load`**: `(L, reader, data, chunkname, mode)`.  
Inject uses the **bufferx wrapper**, not this address directly.

## Load → pcall (proven)

Multiple probe sites:

```
call F0A0|F0E0
test eax, eax
jnz  fail
call 0x486C270   ; lua_pcallk
test eax, eax
```

## Signature (in-process, not packed file)

Pattern for F0A0 (wildcards on RIP/E8 rel32):

```
48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 ?? ?? ?? ??
4C 89 44 24 38 4C 8D 44 24 30 48 89 44 24 20 E8 ?? ?? ?? ??
48 83 C4 48 C3
```

Enable rules (`src/hook/lua_signatures.h` build `wwm-lite-0cfdfcc6`):

1. File SHA-256 matches fingerprint (from disk path of module)  
2. F0A0 pattern **matches == 1** in process image  
3. pcall pattern **matches == 1**  
4. First `E8` in F0A0 body targets `module_base + 0x486C600`  

Fail closed otherwise.

## Inject path

```c
rc = luaL_loadbufferx(L, script, len, "=(face_share_logger)", "t");
if (rc != 0) { log; return; }  // no pcall, no retry spam
rc = lua_pcallk_orig(L, 0, 0, 0, NULL, NULL);
```

Pending inject is cleared after first attempt (success or fail).

## External scan note

`Scripts/scan_runtime_sigs.py` needs Admin `OpenProcess` (err 5 without elevation).  
Uniqueness is enforced **inside** `GameHook.dll` after inject (same process — no OpenProcess).

## Safety

- No fuzzy hooks  
- No live FilePicker upload  
- **UPLOAD_SCHEMA_VERIFIED** remains false  
