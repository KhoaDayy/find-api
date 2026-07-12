------------------------------------------------------------
-- face_share_logger.lua
-- Passive capture of Face FilePicker share flow only.
-- Never mutates return values. Never logs full R67 / tokens.
-- No debug.sethook.
------------------------------------------------------------

local LOGGER_VERSION = "1.1.0-lua-first"

if _G.__face_share_logger_v1 then
  print("[FACE_CAP] already loaded")
  return
end
_G.__face_share_logger_v1 = true

local OUTPUT = _G.__FACE_CAPTURE_OUTPUT or "captures/face_share_capture.jsonl"
local CAPTURE_FULL = _G.__FACE_CAPTURE_FULL == true

local FACE_TAG = "_face_123_face_"
local share_seq = 0
local current_share_id = nil
local hooked = {} -- [fn_identity] = true
local install_deadline = os.clock() + 30
local installed_count = 0
local discovery_reported = {} -- [path] = true

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

local function emit(event, data)
  local ts = (os.time() or 0) * 1000
  local row = {
    schema_version = 1,
    timestamp_ms = ts,
    source = "lua",
    event = event,
    share_id = current_share_id or "",
    region = "UNKNOWN",
    data = sanitize(data or {}),
  }
  local line = encode(row)
  pcall(function()
    local f = io.open(OUTPUT, "a")
    if f then
      f:write(line .. "\n")
      f:close()
    end
  end)
  print("[FACE_CAP] " .. event)
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

local function report_discovery(object_path, fn_name, found, was_hooked)
  local key = tostring(object_path) .. "." .. tostring(fn_name)
  if discovery_reported[key] and found then
    -- still emit once more if we just hooked
    if not was_hooked then return end
  end
  discovery_reported[key] = true
  emit("hook_discovery", {
    object_path = object_path,
    ["function"] = fn_name,
    found = not not found,
    hooked = not not was_hooked,
  })
end

local function wrap_fn(owner, name, object_path, before_fn, after_fn)
  if type(owner) ~= "table" then
    report_discovery(object_path or "?", name, false, false)
    return false
  end
  local original = owner[name]
  if type(original) ~= "function" then
    report_discovery(object_path or "?", name, false, false)
    return false
  end
  if already_hooked(original) then
    report_discovery(object_path or "?", name, true, false)
    return false
  end

  local wrapper
  wrapper = function(...)
    if before_fn then
      local okb, errb = pcall(before_fn, ...)
      if not okb then print("[FACE_CAP] before err " .. tostring(errb)) end
    end

    -- Call original exactly once; pack preserves mid-nil returns.
    local results = table.pack(original(...))

    if after_fn then
      local oka, erra = pcall(function()
        after_fn(true, table.unpack(results, 1, results.n))
      end)
      if not oka then print("[FACE_CAP] after err " .. tostring(erra)) end
    end

    return table.unpack(results, 1, results.n)
  end

  -- Install without touching original identity bookkeeping incorrectly
  owner[name] = wrapper
  mark_hooked(original)
  mark_hooked(wrapper)
  installed_count = installed_count + 1
  report_discovery(object_path or "?", name, true, true)
  emit("hook_installed", { name = name, object_path = object_path })
  return true
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
  if type(mod) ~= "table" then return end
  local ctl = mod.FaceShareController or mod
  local path = object_path or "FaceShareController"
  if type(ctl) == "table" then
    wrap_fn(ctl, "upload_face_data", path, function(self, ...)
      share_seq = share_seq + 1
      current_share_id = tostring(os.time()) .. "-" .. tostring(share_seq)
      emit("face_share_enter", {
        share_id = current_share_id,
        has_face_data = self and self.face_data ~= nil,
        has_guise_data = self and self.guise_data ~= nil,
        face_data_summary = type(self and self.face_data) == "string" and summarize_content(self.face_data) or nil,
      })
      -- legacy alias event name
      emit("face_share_start", { share_id = current_share_id })
    end, function(ok, ...)
      emit("face_share_end", { ok = ok })
    end)
  end
end

local function install_upload_plain_wrapper(M, object_path)
  if type(M) ~= "table" then return end
  local name = "upload_plain_text_to_filepicker"
  local original = M[name]
  if type(original) ~= "function" then
    report_discovery(object_path, name, false, false)
    return
  end
  if already_hooked(original) or M.__face_cap_upload_wrap then
    report_discovery(object_path, name, true, false)
    return
  end
  M.__face_cap_upload_wrap = true

  M[name] = function(self, content, callback, usage, from, expiresAfter, hex_fp_review_id, ...)
    local sum = summarize_content(content)
    pcall(emit, "upload_plain_text_enter", {
      usage = usage,
      from = from,
      expiresAfter = expiresAfter,
      hex_fp_review_id = hex_fp_review_id,
      callback_present = type(callback) == "function",
      content = sum,
    })
    pcall(emit, "upload_plain_text", {
      usage = usage,
      from = from,
      content = sum,
    })

    local cb = callback
    if type(callback) == "function" then
      local orig_cb = callback
      cb = function(result, c2, detail, ...)
        local dkeys, pict, okey = {}, nil, nil
        if type(detail) == "table" then
          for k, _ in pairs(detail) do dkeys[#dkeys + 1] = tostring(k) end
          pict = detail.pict_url or detail.url
          if type(pict) == "string" then
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
        if type(pict) == "string" and #pict > 0 then
          pcall(emit, "pict_url_found", { pict_url = pict, object_key = okey })
        end
        return orig_cb(result, c2, detail, ...)
      end
    end

    return original(self, content, cb, usage, from, expiresAfter, hex_fp_review_id, ...)
  end

  mark_hooked(original)
  mark_hooked(M[name])
  installed_count = installed_count + 1
  report_discovery(object_path, name, true, true)
end

local function try_hook_FilePicker(mod, object_path)
  if type(mod) ~= "table" then return end
  local M = mod.FilePickerManager or mod
  local path = object_path or "filepicker_manager"

  install_upload_plain_wrapper(M, path)

  wrap_fn(M, "_add_upload_task", path, function(self, task, usage, from, hex_fp_review_id, ...)
    emit("add_upload_task", {
      usage = usage,
      from = from,
      hex_fp_review_id = hex_fp_review_id,
      task_type = type(task),
    })
  end)

  wrap_fn(M, "_get_server_token", path, function(self, usage, url, review, hex_fp_review_id)
    emit("token_rpc_request", {
      via = "_get_server_token",
      usage = usage,
      url = url,
      review = review,
      hex_fp_review_id = hex_fp_review_id,
    })
  end)

  wrap_fn(M, "gen_server_token_back", path, function(self, server_token_with_tag, usage, url, review)
    local tok = server_token_with_tag
    local tagged = type(tok) == "string" and tok:sub(1, #FACE_TAG) == FACE_TAG
    emit("token_rpc_response", {
      via = "gen_server_token_back",
      token_tagged = tagged,
      token_prefix = tagged and FACE_TAG or nil,
      token_length = type(tok) == "string" and #tok or 0,
      token = type(tok) == "string" and (tagged and (FACE_TAG .. "***") or "***") or nil,
      usage = usage,
      url = url,
      review = review,
    })
  end)

  wrap_fn(M, "_real_upload_file", path, function(self, ...)
    local post = nil
    pcall(function()
      post = self._fp_post_url or self.fp_post_url
    end)
    emit("real_upload_enter", {
      fp_post_url = post,
      has_server_token = self and self._server_token ~= nil,
      argc = select("#", ...),
    })
    emit("real_upload", {
      fp_post_url = post,
      has_server_token = self and self._server_token ~= nil,
    })
  end)

  wrap_fn(M, "http_fetch", path, function(self, ...)
    emit("http_fetch", { argc = select("#", ...) })
  end)
end

local function try_hook_rpc_module(mod, modname)
  if type(mod) ~= "table" then return end
  local path = modname or "rpc"
  if type(mod.rpc_gen_filepicker_token) == "function" then
    wrap_fn(mod, "rpc_gen_filepicker_token", path, function(self, params, usage, url, ...)
      emit("token_rpc_request", {
        via = "rpc_gen_filepicker_token",
        params = sanitize(params),
        usage = usage,
        url = url,
        module = modname,
      })
      emit("rpc_gen_filepicker_token", {
        params = sanitize(params),
        usage = usage,
        url = url,
        module = modname,
      })
    end)
  else
    report_discovery(path, "rpc_gen_filepicker_token", false, false)
  end
  if type(mod.rpc_server_filepicker_token) == "function" then
    wrap_fn(mod, "rpc_server_filepicker_token", path, function(self, server_token, usage, url, review, ...)
      local tagged = type(server_token) == "string" and server_token:sub(1, #FACE_TAG) == FACE_TAG
      emit("token_rpc_response", {
        via = "rpc_server_filepicker_token",
        token_tagged = tagged,
        token_prefix = tagged and FACE_TAG or nil,
        token_length = type(server_token) == "string" and #server_token or 0,
        usage = usage,
        url = url,
        review = review,
        module = modname,
      })
      emit("rpc_server_filepicker_token", {
        token_tagged = tagged,
        token_length = type(server_token) == "string" and #server_token or 0,
        usage = usage,
        url = url,
        module = modname,
      })
    end)
  else
    report_discovery(path, "rpc_server_filepicker_token", false, false)
  end
end

-- Walk a dotted path on a root table (G.foo.bar)
local function resolve_path(root, dotted)
  local cur = root
  for part in string.gmatch(dotted, "[^%.]+") do
    if type(cur) ~= "table" then return nil end
    cur = cur[part]
  end
  return cur
end

local function scan_and_hook()
  for modname, mod in pairs(package.loaded) do
    if type(modname) == "string" and type(mod) == "table" then
      local mn = modname:lower()
      if mn:find("face_share", 1, true) then
        try_hook_FaceShare(mod, modname)
      end
      if mn:find("filepicker", 1, true) then
        try_hook_FilePicker(mod, modname)
        try_hook_rpc_module(mod, modname)
      end
    end
  end

  if type(G) == "table" then
    if type(G.filepicker_manager) == "table" then
      try_hook_FilePicker(G.filepicker_manager, "G.filepicker_manager")
    else
      report_discovery("G.filepicker_manager", "*", false, false)
    end
    if type(G.face_filepicker_manager) == "table" then
      try_hook_FilePicker(G.face_filepicker_manager, "G.face_filepicker_manager")
      wrap_fn(G.face_filepicker_manager, "gen_server_token_back", "G.face_filepicker_manager",
        function(self, server_token, usage, url, review)
          local tagged = type(server_token) == "string" and server_token:sub(1, #FACE_TAG) == FACE_TAG
          emit("token_rpc_response", {
            via = "face_filepicker_manager.gen_server_token_back",
            token_tagged = tagged,
            token_length = type(server_token) == "string" and #server_token or 0,
            usage = usage,
            url = url,
            review = review,
          })
        end)
    end

    -- Common manager paths (best-effort)
    local paths = {
      "filepicker_manager",
      "face_filepicker_manager",
      "datam.fp_review_config",
    }
    for _, p in ipairs(paths) do
      local obj = resolve_path(G, p)
      if type(obj) == "table" and p:find("filepicker", 1, true) then
        try_hook_FilePicker(obj, "G." .. p)
      end
    end
  end
end

local function important_hooked()
  -- At least one of the core upload entrypoints
  return installed_count >= 1
end

------------------------------------------------------------
-- Installer retry: 500ms, max 30s, no debug.sethook
------------------------------------------------------------
emit("logger_loaded", {
  logger = "face_share_logger",
  version = LOGGER_VERSION,
  output = OUTPUT,
  capture_full = CAPTURE_FULL,
})
emit("logger_start", { output = OUTPUT, capture_full = CAPTURE_FULL, version = LOGGER_VERSION })

local function installer()
  if os.clock() > install_deadline then
    emit("installer_timeout", {
      installed_count = installed_count,
      important_hooked = important_hooked(),
    })
    return
  end
  pcall(scan_and_hook)
  if important_hooked() and installed_count >= 3 then
    emit("installer_done", { installed_count = installed_count })
    _G.__face_share_logger_rescan = scan_and_hook
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
    -- No game timer: rely on F5 re-inject / manual rescan.
    -- Avoid debug.sethook (explicitly disabled).
  end
  _G.__face_share_logger_rescan = scan_and_hook
end

installer()
print("[FACE_CAP] face_share_logger " .. LOGGER_VERSION .. " loaded; scanning package.loaded")
print("[FACE_CAP] output=" .. OUTPUT)
print("[FACE_CAP] call __face_share_logger_rescan() or F5 reinject to rescan modules")
