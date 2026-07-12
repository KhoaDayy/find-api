------------------------------------------------------------
-- face_share_logger.lua
-- Passive capture of Face FilePicker share flow only.
-- Never mutates return values. Never logs full R67 / tokens.
-- No debug.sethook.
------------------------------------------------------------

local LOGGER_VERSION = "1.4.0-instance"

if _G.__face_share_logger_v1 then
  print("[FACE_CAP_BOOT] logger_reentry")
  local rescan = rawget(_G, "__face_share_logger_rescan")
  if type(rescan) == "function" then
    local ok, err = pcall(rescan)
    if type(_G.__face_capture_emit) == "function" then
      pcall(_G.__face_capture_emit, "logger_reentry_rescan", {
        ok = ok,
        error = ok and nil or tostring(err),
      })
    else
      print("[FACE_CAP_BOOT] logger_reentry_rescan ok=" .. tostring(ok) .. " err=" .. tostring(err))
    end
  else
    print("[FACE_CAP_BOOT] logger_reentry no rescan function")
  end
  return
end
_G.__face_share_logger_v1 = true

local OUTPUT = _G.__FACE_CAPTURE_OUTPUT or "captures/face_share_capture_lua.jsonl"
local CAPTURE_FULL = _G.__FACE_CAPTURE_FULL == true
local WRITER_BACKEND = "file" -- flipped to console_only if io missing
local FILE_WRITE_OK = false
local FILE_WRITE_ERR = nil

local FACE_TAG = "_face_123_face_"
local share_seq = 0
local current_share_id = nil
local hooked = {} -- [fn_identity] = true
local install_deadline = os.clock() + 30
local installed_count = 0
local discovery_reported = {} -- [path] = true

local IMPORTANT = {
  logger_loaded = true,
  logger_start = true,
  logger_reentry = true,
  logger_reentry_rescan = true,
  rescan_start = true,
  rescan_complete = true,
  hook_discovery = true,
  hook_installed = true,
  hook_install_failed = true,
  object_probe = true,
  method_probe = true,
  installer_done = true,
  installer_timeout = true,
  installer_no_timer = true,
  face_share_enter = true,
  face_share_start = true,
  upload_plain_text_enter = true,
  upload_plain_text = true,
  token_rpc_request = true,
  token_rpc_response = true,
  real_upload_enter = true,
  real_upload = true,
  upload_callback = true,
  filepicker_callback = true,
  pict_url_found = true,
}

------------------------------------------------------------
-- Minimal JSON encoder (depth/item limited, cycle-safe)
------------------------------------------------------------
local function json_escape(s)
  s = tostring(s)
  s = s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
  return s
end

local function is_face_data(s)
  if type(s) ~= "string" or #s < 4 then return false end
  local p = s:sub(1, 3)
  if p == "R67" or p == "r67" or p == "D67" or p == "d67" then return true end
  if s:find("|*|", 1, true) and #s > 40 then return true end
  return false
end

local function djb2_hex(s)
  local h = 5381
  for i = 1, #s do
    h = (h * 33 + s:byte(i)) % 4294967296
  end
  return string.format("%08x", h)
end

local function face_placeholder(s)
  return {
    __face_data__ = true,
    length = #s,
    hash_djb2 = djb2_hex(s),
    prefix = s:sub(1, 3),
  }
end

local function sanitize(v, depth, seen, items)
  depth = depth or 0
  seen = seen or {}
  items = items or { n = 0 }
  if depth > 5 then return "<max_depth>" end
  local t = type(v)
  if t == "nil" then return nil end
  if t == "boolean" or t == "number" then return v end
  if t == "string" then
    if is_face_data(v) and not CAPTURE_FULL then
      return face_placeholder(v)
    end
    if v:find(FACE_TAG, 1, true) == 1 then
      return FACE_TAG .. "***|len=" .. #v
    end
    if v:find("session=", 1, true) then
      return v:gsub("session=[^&%s]+", "session=***")
    end
    if #v > 400 then return v:sub(1, 120) .. "...[len=" .. #v .. "]" end
    return v
  end
  if t == "table" then
    if seen[v] then return "<cycle>" end
    seen[v] = true
    local out = {}
    for k, val in pairs(v) do
      items.n = items.n + 1
      if items.n > 80 then
        out["__truncated__"] = true
        break
      end
      local ks = tostring(k)
      local kl = ks:lower()
      if kl:find("token", 1, true) or kl == "session" or kl:find("cookie", 1, true)
          or kl:find("authorization", 1, true) then
        if type(val) == "string" then
          out[ks] = "***|len=" .. #val
        else
          out[ks] = "***"
        end
      elseif ks == "face_data" and type(val) == "string" and not CAPTURE_FULL then
        out[ks] = face_placeholder(val)
      else
        out[ks] = sanitize(val, depth + 1, seen, items)
      end
    end
    return out
  end
  return tostring(v)
end

local function encode(v)
  local t = type(v)
  if v == nil then return "null" end
  if t == "boolean" then return v and "true" or "false" end
  if t == "number" then return tostring(v) end
  if t == "string" then return '"' .. json_escape(v) .. '"' end
  if t == "table" then
    local n = #v
    local is_arr = n > 0
    if is_arr then
      for i = 1, n do
        if v[i] == nil then is_arr = false break end
      end
    end
    if is_arr then
      local parts = {}
      for i = 1, n do parts[i] = encode(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local parts = {}
    for k, val in pairs(v) do
      parts[#parts + 1] = '"' .. json_escape(tostring(k)) .. '":' .. encode(val)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return '"' .. json_escape(tostring(v)) .. '"'
end

local function try_write_file(line)
  if type(io) ~= "table" then
    return false, "io=nil"
  end
  if type(io.open) ~= "function" then
    return false, "io.open_type=" .. type(io.open)
  end
  local f, err = io.open(OUTPUT, "a")
  if not f then
    return false, "open_fail path=" .. tostring(OUTPUT) .. " err=" .. tostring(err)
  end
  local wok, werr = pcall(function()
    f:write(line)
    f:write("\n")
  end)
  local cok, cerr = pcall(function()
    f:close()
  end)
  if not wok then
    return false, "write_fail err=" .. tostring(werr)
  end
  if not cok then
    return false, "close_fail err=" .. tostring(cerr)
  end
  return true, nil
end

local function emit(event, data)
  local ts = (os.time() or 0) * 1000
  local payload = data or {}
  if type(payload) == "table" then
    payload = sanitize(payload)
    if type(payload) == "table" then
      payload.writer_backend = WRITER_BACKEND
    end
  end
  local row = {
    schema_version = 1,
    timestamp_ms = ts,
    source = "lua",
    event = event,
    share_id = current_share_id or "",
    region = "UNKNOWN",
    data = payload,
  }
  local line = encode(row)

  -- Always print compact JSON for console diagnostics (never swallowed).
  print("[FACE_CAP_JSON] " .. line)

  local ok, err = try_write_file(line)
  if ok then
    FILE_WRITE_OK = true
  else
    FILE_WRITE_ERR = err
    if WRITER_BACKEND ~= "console_only" then
      -- stay on file attempts; mark console fallback for diagnostics
      if type(io) ~= "table" or type(io.open) ~= "function" then
        WRITER_BACKEND = "console_only"
      end
    end
    print("[FACE_CAP_EMIT_FAIL] " .. tostring(err))
  end

  if IMPORTANT[event] then
    print("[FACE_CAP] " .. tostring(event))
  end
end

_G.__face_capture_emit = emit

------------------------------------------------------------
-- Engine object helpers (table | instance | userdata | class)
------------------------------------------------------------
local TARGET_METHODS = {
  "upload_plain_text_to_filepicker",
  "_add_upload_task",
  "_get_server_token",
  "gen_server_token_back",
  "_real_upload_file",
  "http_fetch",
  "rpc_gen_filepicker_token",
  "rpc_server_filepicker_token",
  "upload_face_data",
  "share_face_data",
  "on_click_share",
  "do_share",
  "upload_face_plan",
  "create_face_plan",
}

local function runtime_type(v)
  local ok, t = pcall(type, v)
  return ok and t or "<type_error>"
end

local function is_indexable(v)
  local t = runtime_type(v)
  return t == "table" or t == "instance" or t == "userdata" or t == "class"
end

local function safe_get(obj, key)
  if obj == nil then return false, nil, "nil_object" end
  local ok, value = pcall(function()
    return obj[key]
  end)
  return ok, value, ok and nil or tostring(value)
end

local function safe_set(obj, key, value)
  if obj == nil then return false, "nil_object" end
  local ok, err = pcall(function()
    obj[key] = value
  end)
  return ok, ok and nil or tostring(err)
end

local function safe_tostring(v)
  local ok, s = pcall(tostring, v)
  if not ok then return "<tostring_error>" end
  s = tostring(s)
  if #s > 120 then s = s:sub(1, 120) .. "..." end
  return s
end

local function probe_instance_writable(obj)
  if not is_indexable(obj) then return false end
  local key = "__face_cap_probe_" .. tostring(math.floor((os.clock() or 0) * 1e6) % 1000000)
  local ok_get, orig = safe_get(obj, key)
  if not ok_get then return false end
  local ok_set = safe_set(obj, key, true)
  if not ok_set then return false end
  local ok_rb, rb = safe_get(obj, key)
  pcall(function()
    if orig == nil then
      safe_set(obj, key, nil)
    else
      safe_set(obj, key, orig)
    end
  end)
  return ok_rb and rb == true
end

local function filtered_keys(obj, maxn)
  maxn = maxn or 150
  local out = {}
  if runtime_type(obj) ~= "table" then return out end
  local n = 0
  for k, v in pairs(obj) do
    local ks = tostring(k):lower()
    if ks:find("upload", 1, true) or ks:find("token", 1, true) or ks:find("file", 1, true)
        or ks:find("picker", 1, true) or ks:find("share", 1, true) or ks:find("face", 1, true)
        or ks:find("server", 1, true) or ks:find("manager", 1, true) or ks:find("class", 1, true)
        or ks == "cls" or ks:find("instance", 1, true) or ks:find("get_instance", 1, true) then
      out[#out + 1] = { key = tostring(k), type = runtime_type(v) }
      n = n + 1
      if n >= maxn then break end
    end
  end
  return out
end

-- Discover where a method lives: instance / module / metatable.__index / class table
local function resolve_method_owner(obj, name, object_path)
  local result = {
    object_path = object_path,
    ["function"] = name,
    found = false,
    callable = false,
    owner = nil,
    owner_kind = nil,
    owner_runtime_type = nil,
  }
  if not is_indexable(obj) then return result end

  local ok, val = safe_get(obj, name)
  if ok and runtime_type(val) == "function" then
    result.found = true
    result.callable = true
    result.owner = obj
    result.owner_kind = runtime_type(obj) == "table" and "module" or "instance"
    result.owner_runtime_type = runtime_type(obj)
    -- Prefer metatable.__index table if method also lives there
    local okmt, mt = pcall(getmetatable, obj)
    if okmt and runtime_type(mt) == "table" then
      local oki, idx = safe_get(mt, "__index")
      if oki and runtime_type(idx) == "table" then
        local okm, mv = safe_get(idx, name)
        if okm and runtime_type(mv) == "function" then
          result.owner = idx
          result.owner_kind = "metatable_index"
          result.owner_runtime_type = "table"
        end
      end
    end
    return result
  end

  local okmt, mt = pcall(getmetatable, obj)
  if okmt and runtime_type(mt) == "table" then
    local oki, idx = safe_get(mt, "__index")
    if oki and runtime_type(idx) == "table" then
      local okm, mv = safe_get(idx, name)
      if okm and runtime_type(mv) == "function" then
        result.found = true
        result.callable = true
        result.owner = idx
        result.owner_kind = "metatable_index"
        result.owner_runtime_type = "table"
        return result
      end
    end
    local okm2, mv2 = safe_get(mt, name)
    if okm2 and runtime_type(mv2) == "function" then
      result.found = true
      result.callable = true
      result.owner = mt
      result.owner_kind = "class_table"
      result.owner_runtime_type = "table"
      return result
    end
  end

  -- class-ish fields on module tables
  if runtime_type(obj) == "table" then
    for _, ck in ipairs({ "FilePickerManager", "Manager", "Class", "cls", "class" }) do
      local okc, cls = safe_get(obj, ck)
      if okc and is_indexable(cls) then
        local okm, mv = safe_get(cls, name)
        if okm and runtime_type(mv) == "function" then
          result.found = true
          result.callable = true
          result.owner = cls
          result.owner_kind = "class_table"
          result.owner_runtime_type = runtime_type(cls)
          return result
        end
      end
    end
  end

  return result
end

local function probe_object(obj, object_path)
  local rt = runtime_type(obj)
  local info = {
    object_path = object_path,
    runtime_type = rt,
    tostring_safe = safe_tostring(obj),
    metatable_type = "none",
    index_type = "none",
    instance_writable = false,
    methods = {},
    filtered_keys = {},
  }
  if not is_indexable(obj) then
    emit("object_probe", info)
    return info
  end

  local okmt, mt = pcall(getmetatable, obj)
  if okmt and mt ~= nil then
    info.metatable_type = runtime_type(mt)
    if runtime_type(mt) == "table" then
      local oki, idx = safe_get(mt, "__index")
      if oki then info.index_type = runtime_type(idx) end
    end
  end

  if rt == "instance" or rt == "userdata" then
    info.instance_writable = probe_instance_writable(obj)
  end

  if runtime_type(obj) == "table" then
    info.filtered_keys = filtered_keys(obj, 150)
  elseif info.metatable_type == "table" and okmt then
    local oki, idx = safe_get(mt, "__index")
    if oki and runtime_type(idx) == "table" then
      info.filtered_keys = filtered_keys(idx, 150)
    end
  end

  for _, name in ipairs(TARGET_METHODS) do
    local r = resolve_method_owner(obj, name, object_path)
    info.methods[#info.methods + 1] = {
      ["function"] = name,
      found = r.found,
      callable = r.callable,
      owner_kind = r.owner_kind,
      owner_runtime_type = r.owner_runtime_type,
    }
    if r.found then
      emit("method_probe", {
        object_path = object_path,
        ["function"] = name,
        callable = true,
        owner_kind = r.owner_kind,
        owner_runtime_type = r.owner_runtime_type,
      })
    end
  end

  emit("object_probe", info)
  return info
end

------------------------------------------------------------
-- Safe hook helper (preserve multi-return + mid nils)
------------------------------------------------------------
local function already_hooked(fn)
  return hooked[fn] == true
end

local function mark_hooked(fn)
  hooked[fn] = true
end

local function report_discovery(object_path, fn_name, found, was_hooked, extra)
  local key = tostring(object_path) .. "." .. tostring(fn_name)
  if discovery_reported[key] and found and not was_hooked then
    return
  end
  discovery_reported[key] = true
  local data = {
    object_path = object_path,
    ["function"] = fn_name,
    found = not not found,
    hooked = not not was_hooked,
  }
  if type(extra) == "table" then
    for k, v in pairs(extra) do data[k] = v end
  end
  emit("hook_discovery", data)
end

-- Generalized: owner may be table/instance/userdata indexable.
local function wrap_method(owner, name, object_path, owner_kind, before_fn, after_fn)
  if not is_indexable(owner) then
    report_discovery(object_path or "?", name, false, false, { owner_kind = owner_kind })
    return false
  end
  local okg, original, gerr = safe_get(owner, name)
  if not okg or runtime_type(original) ~= "function" then
    report_discovery(object_path or "?", name, false, false, {
      owner_kind = owner_kind,
      get_error = gerr,
    })
    return false
  end
  if already_hooked(original) then
    report_discovery(object_path or "?", name, true, false, { owner_kind = owner_kind })
    return false
  end

  local wrapper
  wrapper = function(...)
    if before_fn then
      local okb, errb = pcall(before_fn, ...)
      if not okb then print("[FACE_CAP] before err " .. tostring(errb)) end
    end
    local results = table.pack(original(...))
    if after_fn then
      local oka, erra = pcall(function()
        after_fn(true, table.unpack(results, 1, results.n))
      end)
      if not oka then print("[FACE_CAP] after err " .. tostring(erra)) end
    end
    return table.unpack(results, 1, results.n)
  end

  local oks, serr = safe_set(owner, name, wrapper)
  if not oks then
    emit("hook_install_failed", {
      object_path = object_path,
      ["function"] = name,
      owner_kind = owner_kind,
      error = serr,
    })
    return false
  end

  local okr, rb = safe_get(owner, name)
  if not okr or rb ~= wrapper then
    emit("hook_install_failed", {
      object_path = object_path,
      ["function"] = name,
      owner_kind = owner_kind,
      error = "readback_mismatch",
    })
    -- best-effort restore
    pcall(function() safe_set(owner, name, original) end)
    return false
  end

  mark_hooked(original)
  mark_hooked(wrapper)
  installed_count = installed_count + 1
  report_discovery(object_path or "?", name, true, true, {
    owner_kind = owner_kind,
    owner_runtime_type = runtime_type(owner),
  })
  emit("hook_installed", {
    name = name,
    object_path = object_path,
    ["function"] = name,
    owner_kind = owner_kind,
    owner_runtime_type = runtime_type(owner),
  })
  return true
end

-- Back-compat alias used by older call sites
local function wrap_fn(owner, name, object_path, before_fn, after_fn)
  local r = resolve_method_owner(owner, name, object_path)
  if r.found and r.owner then
    return wrap_method(r.owner, name, object_path, r.owner_kind, before_fn, after_fn)
  end
  return wrap_method(owner, name, object_path, runtime_type(owner), before_fn, after_fn)
end

local function content_kind(content)
  if type(content) ~= "string" then
    if type(content) == "table" then return "json" end
    return "unknown"
  end
  local s = content:match("^%s*(.*)$") or content
  if s:sub(1, 2) == "--" or s:find("Content%-Disposition", 1, true) then
    return "multipart"
  end
  if s:find("=", 1, true) and s:find("&", 1, true) and not s:find("{", 1, true) then
    return "form"
  end
  if s:sub(1, 1) == "{" or s:sub(1, 1) == "[" then return "json" end
  if is_face_data(s) then return "raw_face_data" end
  -- high control-char ratio → binary-ish
  local ctrl = 0
  local n = math.min(#s, 64)
  for i = 1, n do
    local b = s:byte(i)
    if b < 9 or (b > 13 and b < 32) then ctrl = ctrl + 1 end
  end
  if n > 0 and ctrl / n > 0.2 then return "binary" end
  return "unknown"
end

local function summarize_content(content)
  local kind = content_kind(content)
  local out = { content_type = type(content), content_kind = kind }
  if type(content) == "string" then
    out.content_length = #content
    if kind == "raw_face_data" then
      out.face_data = face_placeholder(content)
    elseif kind == "json" then
      local keys = {}
      for k in content:gmatch('"([%w_]+)"%s*:') do
        keys[#keys + 1] = k
        if #keys >= 20 then break end
      end
      out.content_keys = keys
      if content:find('"face_data"', 1, true) then
        out.has_face_data_field = true
      end
      out.pid = content:match('"pid"%s*:%s*"(.-)"')
      local hostnum = content:match('"hostnum"%s*:%s*(%d+)')
      local fst = content:match('"face_share_type"%s*:%s*(%d+)')
      out.hostnum = hostnum and tonumber(hostnum) or nil
      out.face_share_type = fst and tonumber(fst) or nil
      out.has_dressing = content:find('"dressing"', 1, true) ~= nil
    end
  elseif type(content) == "table" then
    out.content_keys = {}
    for k, _ in pairs(content) do
      out.content_keys[#out.content_keys + 1] = tostring(k)
    end
    if type(content.face_data) == "string" then
      out.face_data = face_placeholder(content.face_data)
    end
    out.pid = content.pid
    out.hostnum = content.hostnum
    out.face_share_type = content.face_share_type
    out.has_dressing = content.dressing ~= nil
  end
  return out
end

------------------------------------------------------------
-- Target hooks
------------------------------------------------------------
local function try_hook_FaceShare(mod, object_path)
  if not is_indexable(mod) then return 0 end
  local path = object_path or "FaceShareController"
  local okc, ctl = safe_get(mod, "FaceShareController")
  if not (okc and is_indexable(ctl)) then ctl = mod end
  local n = 0
  for _, mname in ipairs({
    "upload_face_data", "share_face_data", "on_click_share", "do_share",
    "upload_face_plan", "create_face_plan",
  }) do
    local r = resolve_method_owner(ctl, mname, path)
    if r.found and r.owner then
      local ok = wrap_method(r.owner, mname, path, r.owner_kind, function(self, ...)
        share_seq = share_seq + 1
        current_share_id = tostring(os.time()) .. "-" .. tostring(share_seq)
        local has_fd, has_gd = false, false
        if is_indexable(self) then
          local _, fd = safe_get(self, "face_data")
          local _, gd = safe_get(self, "guise_data")
          has_fd = fd ~= nil
          has_gd = gd ~= nil
        end
        emit("face_share_enter", {
          share_id = current_share_id,
          method = mname,
          has_face_data = has_fd,
          has_guise_data = has_gd,
        })
        emit("face_share_start", { share_id = current_share_id, method = mname })
      end, function(ok, ...)
        emit("face_share_end", { ok = ok, method = mname })
      end)
      if ok then n = n + 1 end
    end
  end
  return n
end

local function install_upload_plain_wrapper(M, object_path)
  if not is_indexable(M) then return false end
  local name = "upload_plain_text_to_filepicker"
  local r = resolve_method_owner(M, name, object_path)
  if not (r.found and r.owner) then
    report_discovery(object_path, name, false, false)
    return false
  end
  local owner = r.owner
  local okg, original = safe_get(owner, name)
  if not okg or runtime_type(original) ~= "function" then
    report_discovery(object_path, name, false, false)
    return false
  end
  if already_hooked(original) then
    report_discovery(object_path, name, true, false, { owner_kind = r.owner_kind })
    return false
  end

  local wrapper = function(self, content, callback, usage, from, expiresAfter, hex_fp_review_id, ...)
    local sum = summarize_content(content)
    pcall(emit, "upload_plain_text_enter", {
      usage = usage,
      from = from,
      expiresAfter = expiresAfter,
      hex_fp_review_id = hex_fp_review_id,
      callback_present = runtime_type(callback) == "function",
      content = sum,
    })
    pcall(emit, "upload_plain_text", {
      usage = usage,
      from = from,
      content = sum,
    })

    local cb = callback
    if runtime_type(callback) == "function" then
      local orig_cb = callback
      cb = function(result, c2, detail, ...)
        local dkeys, pict, okey = {}, nil, nil
        if is_indexable(detail) then
          -- shallow key list only for tables
          if runtime_type(detail) == "table" then
            for k, _ in pairs(detail) do dkeys[#dkeys + 1] = tostring(k) end
          end
          local _, p1 = safe_get(detail, "pict_url")
          local _, p2 = safe_get(detail, "url")
          pict = p1 or p2
          if runtime_type(pict) == "string" then
            okey = pict:match("/file/([^%?%s]+)")
          end
        end
        pcall(emit, "upload_callback", {
          success = not not result,
          detail_keys = dkeys,
          pict_url = pict,
          object_key = okey,
        })
        pcall(emit, "filepicker_callback", {
          success = not not result,
          detail_keys = dkeys,
          pict_url = pict,
          object_key = okey,
        })
        if runtime_type(pict) == "string" and #pict > 0 then
          pcall(emit, "pict_url_found", { pict_url = pict, object_key = okey })
        end
        return orig_cb(result, c2, detail, ...)
      end
    end

    return original(self, content, cb, usage, from, expiresAfter, hex_fp_review_id, ...)
  end

  local oks = safe_set(owner, name, wrapper)
  if not oks then
    emit("hook_install_failed", {
      object_path = object_path,
      ["function"] = name,
      owner_kind = r.owner_kind,
      error = "assignment_failed",
    })
    return false
  end
  local okr, rb = safe_get(owner, name)
  if not okr or rb ~= wrapper then
    emit("hook_install_failed", {
      object_path = object_path,
      ["function"] = name,
      owner_kind = r.owner_kind,
      error = "readback_mismatch",
    })
    pcall(function() safe_set(owner, name, original) end)
    return false
  end

  mark_hooked(original)
  mark_hooked(wrapper)
  installed_count = installed_count + 1
  report_discovery(object_path, name, true, true, {
    owner_kind = r.owner_kind,
    owner_runtime_type = r.owner_runtime_type,
  })
  emit("hook_installed", {
    name = name,
    object_path = object_path,
    ["function"] = name,
    owner_kind = r.owner_kind,
    owner_runtime_type = r.owner_runtime_type,
  })
  return true
end

local function try_hook_FilePicker(mod, object_path)
  if not is_indexable(mod) then return 0 end
  local path = object_path or "filepicker_manager"
  probe_object(mod, path)

  local okm, M = safe_get(mod, "FilePickerManager")
  if not (okm and is_indexable(M)) then M = mod end
  if M ~= mod then probe_object(M, path .. ".FilePickerManager") end

  local n = 0
  if install_upload_plain_wrapper(M, path) then n = n + 1 end
  -- also try on original mod (instance may hold methods via mt)
  if M ~= mod and install_upload_plain_wrapper(mod, path) then n = n + 1 end

  local function hook_one(owner, mname, before)
    local r = resolve_method_owner(owner, mname, path)
    if r.found and r.owner then
      if wrap_method(r.owner, mname, path, r.owner_kind, before) then
        n = n + 1
      end
    end
  end

  for _, owner in ipairs({ M, mod }) do
    hook_one(owner, "_add_upload_task", function(self, task, usage, from, hex_fp_review_id, ...)
      emit("add_upload_task", {
        usage = usage,
        from = from,
        hex_fp_review_id = hex_fp_review_id,
        task_type = runtime_type(task),
      })
    end)
    hook_one(owner, "_get_server_token", function(self, usage, url, review, hex_fp_review_id)
      emit("token_rpc_request", {
        via = "_get_server_token",
        usage = usage,
        url = url,
        review = review,
        hex_fp_review_id = hex_fp_review_id,
      })
    end)
    hook_one(owner, "gen_server_token_back", function(self, server_token_with_tag, usage, url, review)
      local tok = server_token_with_tag
      local tagged = runtime_type(tok) == "string" and tok:sub(1, #FACE_TAG) == FACE_TAG
      emit("token_rpc_response", {
        via = "gen_server_token_back",
        token_tagged = tagged,
        token_prefix = tagged and FACE_TAG or nil,
        token_length = runtime_type(tok) == "string" and #tok or 0,
        token = runtime_type(tok) == "string" and (tagged and (FACE_TAG .. "***") or "***") or nil,
        usage = usage,
        url = url,
        review = review,
      })
    end)
    hook_one(owner, "_real_upload_file", function(self, ...)
      local post = nil
      if is_indexable(self) then
        local _, p1 = safe_get(self, "_fp_post_url")
        local _, p2 = safe_get(self, "fp_post_url")
        post = p1 or p2
      end
      local has_tok = false
      if is_indexable(self) then
        local _, t = safe_get(self, "_server_token")
        has_tok = t ~= nil
      end
      emit("real_upload_enter", {
        fp_post_url = post,
        has_server_token = has_tok,
        argc = select("#", ...),
      })
      emit("real_upload", {
        fp_post_url = post,
        has_server_token = has_tok,
      })
    end)
    hook_one(owner, "http_fetch", function(self, ...)
      emit("http_fetch", { argc = select("#", ...) })
    end)
  end
  return n
end

local function try_hook_rpc_module(mod, modname)
  if not is_indexable(mod) then return 0 end
  local path = modname or "rpc"
  local n = 0
  local r1 = resolve_method_owner(mod, "rpc_gen_filepicker_token", path)
  if r1.found and r1.owner then
    if wrap_method(r1.owner, "rpc_gen_filepicker_token", path, r1.owner_kind, function(self, params, usage, url, ...)
      emit("token_rpc_request", {
        via = "rpc_gen_filepicker_token",
        params = sanitize(params),
        usage = usage,
        url = url,
        module = modname,
      })
    end) then n = n + 1 end
  else
    report_discovery(path, "rpc_gen_filepicker_token", false, false)
  end
  local r2 = resolve_method_owner(mod, "rpc_server_filepicker_token", path)
  if r2.found and r2.owner then
    if wrap_method(r2.owner, "rpc_server_filepicker_token", path, r2.owner_kind, function(self, server_token, usage, url, review, ...)
      local tagged = runtime_type(server_token) == "string" and server_token:sub(1, #FACE_TAG) == FACE_TAG
      emit("token_rpc_response", {
        via = "rpc_server_filepicker_token",
        token_tagged = tagged,
        token_prefix = tagged and FACE_TAG or nil,
        token_length = runtime_type(server_token) == "string" and #server_token or 0,
        usage = usage,
        url = url,
        review = review,
        module = modname,
      })
      emit("rpc_server_filepicker_token", {
        token_tagged = tagged,
        token_length = runtime_type(server_token) == "string" and #server_token or 0,
        usage = usage,
        url = url,
        module = modname,
      })
    end) then n = n + 1 end
  else
    report_discovery(path, "rpc_server_filepicker_token", false, false)
  end
  return n
end

-- Walk a dotted path on a root table / indexable (G.foo.bar)
local function resolve_path(root, dotted)
  local cur = root
  for part in string.gmatch(dotted, "[^%.]+") do
    if not is_indexable(cur) then return nil end
    local ok, v = safe_get(cur, part)
    if not ok then return nil end
    cur = v
  end
  return cur
end

local function count_package_loaded()
  local n = 0
  if type(package) == "table" and type(package.loaded) == "table" then
    for _ in pairs(package.loaded) do
      n = n + 1
    end
  end
  return n
end

local function list_candidate_modules(maxn)
  maxn = maxn or 50
  local names = {}
  if type(package) ~= "table" or type(package.loaded) ~= "table" then
    return names
  end
  for modname, mod in pairs(package.loaded) do
    if type(modname) == "string" then
      local mn = modname:lower()
      if mn:find("face", 1, true) or mn:find("filepicker", 1, true)
          or mn:find("picker", 1, true) or mn:find("upload", 1, true) then
        names[#names + 1] = { name = modname, type = type(mod) }
        if #names >= maxn then break end
      end
    end
  end
  return names
end

-- Idempotent: wrap_method / already_hooked prevent double-wrap.
local function scan_and_hook()
  local installed_before = installed_count
  local candidates_found = 0
  local instance_candidates = 0
  local module_candidates = 0
  local class_candidates = 0
  local callable_methods_found = 0
  local writable_instances = 0
  local found_mods = {}

  local function note_probe(info)
    if not info then return end
    local rt = info.runtime_type
    if rt == "instance" or rt == "userdata" then
      instance_candidates = instance_candidates + 1
      if info.instance_writable then writable_instances = writable_instances + 1 end
    elseif rt == "table" then
      module_candidates = module_candidates + 1
    elseif rt == "class" then
      class_candidates = class_candidates + 1
    end
    for _, m in ipairs(info.methods or {}) do
      if m.callable then callable_methods_found = callable_methods_found + 1 end
    end
  end

  for modname, mod in pairs(package.loaded or {}) do
    if type(modname) == "string" and is_indexable(mod) then
      local mn = modname:lower()
      local face_share = mn:find("face", 1, true) and mn:find("share", 1, true)
      local face_extra = mn:find("face_community", 1, true) or mn:find("face_make", 1, true)
          or mn:find("face_create", 1, true)
      if face_share or face_extra or mn:find("face_share", 1, true) then
        found_mods[#found_mods + 1] = modname
        candidates_found = candidates_found + 1
        print("[FACE_CAP_BOOT] package.loaded face*: " .. modname .. " type=" .. runtime_type(mod))
        note_probe(probe_object(mod, modname))
        try_hook_FaceShare(mod, modname)
      end
      if mn:find("filepicker", 1, true) or mn:find("imp_filepicker", 1, true) then
        found_mods[#found_mods + 1] = modname
        candidates_found = candidates_found + 1
        print("[FACE_CAP_BOOT] package.loaded filepicker: " .. modname .. " type=" .. runtime_type(mod))
        try_hook_FilePicker(mod, modname)
        try_hook_rpc_module(mod, modname)
      end
    end
  end
  print("[FACE_CAP_BOOT] package.loaded hits=" .. tostring(#found_mods))

  local G_type = runtime_type(G)
  local fpm_type = "n/a"
  local ffpm_type = "n/a"
  print("[FACE_CAP_BOOT] G type=" .. G_type)
  if is_indexable(G) then
    local _, fpm = safe_get(G, "filepicker_manager")
    local _, ffpm = safe_get(G, "face_filepicker_manager")
    fpm_type = runtime_type(fpm)
    ffpm_type = runtime_type(ffpm)
    print("[FACE_CAP_BOOT] G.filepicker_manager type=" .. fpm_type)
    print("[FACE_CAP_BOOT] G.face_filepicker_manager type=" .. ffpm_type)
    local _, uim = safe_get(G, "ui_manager")
    local _, wim = safe_get(G, "window_manager")
    print("[FACE_CAP_BOOT] G.ui_manager type=" .. runtime_type(uim))
    print("[FACE_CAP_BOOT] G.window_manager type=" .. runtime_type(wim))

    if is_indexable(fpm) then
      candidates_found = candidates_found + 1
      note_probe(probe_object(fpm, "G.filepicker_manager"))
      try_hook_FilePicker(fpm, "G.filepicker_manager")
    else
      report_discovery("G.filepicker_manager", "*", false, false)
    end
    if is_indexable(ffpm) then
      candidates_found = candidates_found + 1
      note_probe(probe_object(ffpm, "G.face_filepicker_manager"))
      try_hook_FilePicker(ffpm, "G.face_filepicker_manager")
    else
      report_discovery("G.face_filepicker_manager", "*", false, false)
    end

    local paths = {
      "filepicker_manager",
      "face_filepicker_manager",
      "datam.fp_review_config",
    }
    for _, p in ipairs(paths) do
      local obj = resolve_path(G, p)
      print("[FACE_CAP_BOOT] G." .. p .. " type=" .. runtime_type(obj))
      if is_indexable(obj) and p:find("filepicker", 1, true) then
        candidates_found = candidates_found + 1
        try_hook_FilePicker(obj, "G." .. p)
      end
    end
  else
    report_discovery("G", "*", false, false)
  end

  -- Known modules by exact name
  for _, exact in ipairs({
    "hexm.client.manager.filepicker.filepicker_manager",
    "hexm.client.entities.server.player_avatar_members.imp_filepicker",
  }) do
    local mod = package.loaded and package.loaded[exact]
    if is_indexable(mod) then
      candidates_found = candidates_found + 1
      print("[FACE_CAP_BOOT] exact module " .. exact .. " type=" .. runtime_type(mod))
      note_probe(probe_object(mod, exact))
      try_hook_FilePicker(mod, exact)
      try_hook_rpc_module(mod, exact)
    end
  end

  local fsc = rawget(_G, "FaceShareController")
  print("[FACE_CAP_BOOT] FaceShareController type=" .. runtime_type(fsc))
  if is_indexable(fsc) then
    candidates_found = candidates_found + 1
    note_probe(probe_object(fsc, "FaceShareController"))
    try_hook_FaceShare(fsc, "FaceShareController")
  else
    report_discovery("FaceShareController", "upload_face_data", false, false)
  end

  local installed_after = installed_count
  return {
    installed_before = installed_before,
    installed_after = installed_after,
    newly_installed = math.max(0, installed_after - installed_before),
    candidates_found = candidates_found,
    instance_candidates = instance_candidates,
    module_candidates = module_candidates,
    class_candidates = class_candidates,
    callable_methods_found = callable_methods_found,
    writable_instances = writable_instances,
    package_loaded_count = count_package_loaded(),
    G_type = G_type,
    filepicker_manager_type = fpm_type,
    face_filepicker_manager_type = ffpm_type,
    FaceShareController_type = runtime_type(fsc),
    candidate_modules = list_candidate_modules(50),
    writer_backend = WRITER_BACKEND,
    file_write_ok = FILE_WRITE_OK,
  }
end

local function important_hooked()
  return installed_count >= 1
end

local function do_rescan(reason)
  reason = reason or "manual"
  emit("rescan_start", {
    reason = reason,
    installed_count = installed_count,
    package_loaded_count = count_package_loaded(),
    G_type = type(G),
  })
  local ok, result = pcall(scan_and_hook)
  if not ok then
    emit("rescan_complete", {
      ok = false,
      error = tostring(result),
      reason = reason,
      installed_before = installed_count,
      installed_after = installed_count,
      newly_installed = 0,
    })
    return nil
  end
  result = result or {}
  result.ok = true
  result.reason = reason
  emit("rescan_complete", result)
  return result
end

_G.__face_share_logger_rescan = function()
  return do_rescan("global")
end

------------------------------------------------------------
-- Installer retry: 500ms, max 30s, no debug.sethook
------------------------------------------------------------
print("[FACE_CAP_BOOT] logger_loaded")
print("[FACE_CAP_BOOT] version=" .. LOGGER_VERSION)
print("[FACE_CAP_BOOT] io_type=" .. type(io))
print("[FACE_CAP_BOOT] io_open_type=" .. tostring(type(io) == "table" and type(io.open) or "n/a"))
print("[FACE_CAP_BOOT] output=" .. tostring(OUTPUT))
print("[FACE_CAP_BOOT] package.config=" .. tostring(package and package.config or "n/a"))
do
  local cwd = "?"
  pcall(function()
    if type(io) == "table" and type(io.popen) == "function" then
      local p = io.popen("cd")
      if p then
        cwd = (p:read("*l") or "?"):gsub("%s+$", "")
        p:close()
      end
    end
  end)
  print("[FACE_CAP_BOOT] cwd=" .. tostring(cwd))
end

if type(io) ~= "table" or type(io.open) ~= "function" then
  WRITER_BACKEND = "console_only"
  print("[FACE_CAP_BOOT] writer_backend=console_only (io unavailable)")
end

emit("logger_loaded", {
  logger = "face_share_logger",
  version = LOGGER_VERSION,
  output = OUTPUT,
  capture_full = CAPTURE_FULL,
  writer_backend = WRITER_BACKEND,
  io_type = type(io),
  io_open_type = type(io) == "table" and type(io.open) or "n/a",
  absolute_output = tostring(OUTPUT):match("^[A-Za-z]:\\") ~= nil
    or tostring(OUTPUT):sub(1, 1) == "/",
})
emit("logger_start", {
  output = OUTPUT,
  capture_full = CAPTURE_FULL,
  version = LOGGER_VERSION,
  writer_backend = WRITER_BACKEND,
})

local function installer()
  if os.clock() > install_deadline then
    emit("installer_timeout", {
      installed_count = installed_count,
      important_hooked = important_hooked(),
      writer_backend = WRITER_BACKEND,
      file_write_ok = FILE_WRITE_OK,
      file_write_err = FILE_WRITE_ERR,
      rescan_required = not important_hooked(),
    })
    return
  end
  do_rescan("installer")
  if important_hooked() and installed_count >= 3 then
    emit("installer_done", {
      installed_count = installed_count,
      writer_backend = WRITER_BACKEND,
      file_write_ok = FILE_WRITE_OK,
      rescan_required = false,
    })
    return
  end

  local scheduled = false
  pcall(function()
    if G and G.timer and G.timer.add_timer then
      G.timer:add_timer(0.5, installer)
      scheduled = true
    end
  end)
  if not scheduled then
    emit("installer_no_timer", {
      installed_count = installed_count,
      rescan_required = true,
      note = "F5 reinject will call __face_share_logger_rescan",
    })
  end
end

installer()
print("[FACE_CAP_BOOT] face_share_logger " .. LOGGER_VERSION .. " loaded")
print("[FACE_CAP_BOOT] F5 reinject triggers reentry rescan")
print("[FACE_CAP_BOOT] file_write_ok=" .. tostring(FILE_WRITE_OK) .. " err=" .. tostring(FILE_WRITE_ERR))
