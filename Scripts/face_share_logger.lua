------------------------------------------------------------
-- face_share_logger.lua
-- Passive capture of Face FilePicker share flow only.
-- Never mutates return values. Never logs full R67 / tokens.
------------------------------------------------------------

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
local install_deadline = os.clock() + 60
local installed_count = 0

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

-- Simple djb2 hash when no SHA available (still better than raw dump)
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
    -- array?
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
-- Safe hook helper
------------------------------------------------------------
local function already_hooked(fn)
  return hooked[fn] == true
end

local function mark_hooked(fn)
  hooked[fn] = true
end

local function wrap_fn(owner, name, before_fn, after_fn)
  if type(owner) ~= "table" then return false end
  local original = owner[name]
  if type(original) ~= "function" then return false end
  if already_hooked(original) then return false end

  local wrapper
  wrapper = function(...)
    local okb, errb = true, nil
    if before_fn then
      okb, errb = pcall(before_fn, ...)
      if not okb then print("[FACE_CAP] before err " .. tostring(errb)) end
    end

    local results = table.pack(pcall(original, ...))
    local ok = results[1]
    if after_fn then
      local oka, erra = pcall(after_fn, ok, table.unpack(results, 2, results.n))
      if not oka then print("[FACE_CAP] after err " .. tostring(erra)) end
    end

    if not ok then
      error(results[2], 0)
    end
    return table.unpack(results, 2, results.n)
  end

  owner[name] = wrapper
  mark_hooked(original)
  mark_hooked(wrapper)
  installed_count = installed_count + 1
  emit("hook_installed", { name = name })
  return true
end

local function content_kind(content)
  if type(content) ~= "string" then return "non_string", nil end
  local t = content:match("^%s*")
  local s = content:sub(#t + 1)
  if s:sub(1, 1) == "{" or s:sub(1, 1) == "[" then return "json_wrapper", content end
  if is_face_data(content) then return "raw_face_data", content end
  return "unknown", content
end

local function summarize_content(content)
  local kind = content_kind(content)
  local out = { content_type = type(content), content_kind = kind }
  if type(content) == "string" then
    out.content_length = #content
    if kind == "raw_face_data" then
      out.face_data = face_placeholder(content)
    elseif kind == "json_wrapper" then
      -- extract keys roughly
      local keys = {}
      for k in content:gmatch('"([%w_]+)"%s*:') do
        keys[#keys + 1] = k
        if #keys >= 20 then break end
      end
      out.content_keys = keys
      local fd = content:match('"face_data"%s*:%s*"(.-)"')
      -- face_data may be huge with escapes; fallback length via find
      if content:find('"face_data"', 1, true) then
        out.has_face_data_field = true
      end
      local pid = content:match('"pid"%s*:%s*"(.-)"')
      local hostnum = content:match('"hostnum"%s*:%s*(%d+)')
      local fst = content:match('"face_share_type"%s*:%s*(%d+)')
      out.pid = pid
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
local function try_hook_FaceShare(mod)
  if type(mod) ~= "table" then return end
  -- class table may hold methods on .FaceShareController or module itself
  local ctl = mod.FaceShareController or mod
  if type(ctl) == "table" and type(ctl.upload_face_data) == "function" then
    wrap_fn(ctl, "upload_face_data", function(self, ...)
      share_seq = share_seq + 1
      current_share_id = tostring(os.time()) .. "-" .. tostring(share_seq)
      emit("face_share_start", {
        share_id = current_share_id,
        has_face_data = self and self.face_data ~= nil,
        has_guise_data = self and self.guise_data ~= nil,
        face_data_summary = type(self and self.face_data) == "string" and summarize_content(self.face_data) or nil,
      })
    end, function(ok, ...)
      emit("face_share_end", { ok = ok })
    end)
  end
end

local function try_hook_FilePicker(mod)
  if type(mod) ~= "table" then return end
  local M = mod.FilePickerManager or mod

  wrap_fn(M, "upload_plain_text_to_filepicker", function(self, content, callback, usage, from, expiresAfter, hex_fp_review_id)
    local sum = summarize_content(content)
    -- wrap callback
    if type(callback) == "function" and not already_hooked(callback) then
      local orig_cb = callback
      local wrapped = function(result, c2, detail, ...)
        local dkeys = {}
        local pict, okey
        if type(detail) == "table" then
          for k, _ in pairs(detail) do dkeys[#dkeys + 1] = tostring(k) end
          pict = detail.pict_url or detail.url
          if type(pict) == "string" then
            okey = pict:match("/file/([%w]+)$") or pict:match("/file/([^%?%s]+)")
          end
        end
        emit("filepicker_callback", {
          success = result and true or false,
          detail_keys = dkeys,
          pict_url = pict,
          object_key = okey,
        })
        return orig_cb(result, c2, detail, ...)
      end
      mark_hooked(orig_cb)
      mark_hooked(wrapped)
      -- replace arg in ... not possible cleanly; re-call path:
      -- We cannot mutate args after before_fn in wrap_fn easily without custom wrap.
      -- So install a specialized wrapper instead if not yet.
    end
    emit("upload_plain_text", {
      usage = usage,
      from = from,
      expiresAfter = expiresAfter,
      hex_fp_review_id = hex_fp_review_id,
      callback_present = type(callback) == "function",
      content = sum,
    })
  end)

  -- Specialized re-wrap for callback capture
  if type(M.upload_plain_text_to_filepicker) == "function" then
    local orig = M.upload_plain_text_to_filepicker
    -- if we already wrapped via wrap_fn, orig is wrapper; find not double-special
    if not M.__face_cap_cb_wrap then
      M.__face_cap_cb_wrap = true
      local current = M.upload_plain_text_to_filepicker
      M.upload_plain_text_to_filepicker = function(self, content, callback, usage, from, expiresAfter, hex_fp_review_id, ...)
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
            pcall(emit, "filepicker_callback", {
              success = not not result,
              detail_keys = dkeys,
              pict_url = pict,
              object_key = okey,
            })
            return orig_cb(result, c2, detail, ...)
          end
        end
        return current(self, content, cb, usage, from, expiresAfter, hex_fp_review_id, ...)
      end
    end
  end

  wrap_fn(M, "_get_server_token", function(self, usage, url, review, hex_fp_review_id)
    emit("token_rpc_request", {
      via = "_get_server_token",
      usage = usage,
      url = url,
      review = review,
      hex_fp_review_id = hex_fp_review_id,
    })
  end)

  wrap_fn(M, "gen_server_token_back", function(self, server_token_with_tag, usage, url, review)
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

  wrap_fn(M, "_real_upload_file", function(self, ...)
    local post = nil
    pcall(function()
      post = self._fp_post_url or self.fp_post_url
    end)
    emit("real_upload", {
      fp_post_url = post,
      has_server_token = self and self._server_token ~= nil,
      argc = select("#", ...),
    })
  end)
end

local function try_hook_rpc_module(mod, modname)
  if type(mod) ~= "table" then return end
  -- methods may be on metatable or as fields
  if type(mod.rpc_gen_filepicker_token) == "function" then
    wrap_fn(mod, "rpc_gen_filepicker_token", function(self, params, usage, url, ...)
      emit("rpc_gen_filepicker_token", {
        params = sanitize(params),
        usage = usage,
        url = url,
        module = modname,
      })
    end)
  end
  if type(mod.rpc_server_filepicker_token) == "function" then
    wrap_fn(mod, "rpc_server_filepicker_token", function(self, server_token, usage, url, review, ...)
      local tagged = type(server_token) == "string" and server_token:sub(1, #FACE_TAG) == FACE_TAG
      emit("rpc_server_filepicker_token", {
        token_tagged = tagged,
        token_prefix = tagged and FACE_TAG or nil,
        token_length = type(server_token) == "string" and #server_token or 0,
        usage = usage,
        url = url,
        review = review,
        module = modname,
      })
    end)
  end
end

local TARGET_MOD_SUBSTR = {
  "face_share_page_window",
  "filepicker_manager",
  "filepicker",
  "imp_filepicker",
}

local function scan_and_hook()
  for modname, mod in pairs(package.loaded) do
    if type(modname) == "string" and type(mod) == "table" then
      local mn = modname:lower()
      if mn:find("face_share_page_window", 1, true) then
        try_hook_FaceShare(mod)
      end
      if mn:find("filepicker_manager", 1, true) or mn:find("filepicker.filepicker", 1, true) then
        try_hook_FilePicker(mod)
      end
      if mn:find("imp_filepicker", 1, true) or mn:find("filepicker", 1, true) then
        try_hook_rpc_module(mod, modname)
        -- also face_filepicker_manager global
      end
    end
  end
  -- globals
  if type(G) == "table" then
    if type(G.filepicker_manager) == "table" then try_hook_FilePicker(G.filepicker_manager) end
    if type(G.face_filepicker_manager) == "table" then
      try_hook_FilePicker(G.face_filepicker_manager)
      wrap_fn(G.face_filepicker_manager, "gen_server_token_back", function(self, server_token, usage, url, review)
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
  end
end

------------------------------------------------------------
-- Installer retry (no busy loop)
------------------------------------------------------------
emit("logger_start", { output = OUTPUT, capture_full = CAPTURE_FULL })

local function installer()
  if os.clock() > install_deadline then
    emit("installer_timeout", { installed_count = installed_count })
    return
  end
  pcall(scan_and_hook)
  -- schedule next: prefer game timer if present
  local scheduled = false
  pcall(function()
    if G and G.timer and G.timer.add_timer then
      G.timer:add_timer(0.5, installer)
      scheduled = true
    end
  end)
  if not scheduled then
    -- fallback: hook next package.loaded assignment is hard; use coroutine yield not available.
    -- Use debug.sethook briefly only to count calls — avoid. Instead rely on periodic pcall from game.
    -- Store installer on global for F5 re-run
  end
  _G.__face_share_logger_rescan = scan_and_hook
end

installer()
-- also scan immediately a few times via chained pcall from hooked pcall — user presses F5 to rescan
print("[FACE_CAP] face_share_logger loaded; scanning package.loaded")
print("[FACE_CAP] output=" .. OUTPUT)
print("[FACE_CAP] call __face_share_logger_rescan() or F5 reinject to rescan modules")
