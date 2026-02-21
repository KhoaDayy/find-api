------------------------------------------------------------
--  api_logger.lua  v3  –  Deep RPC + HTTP capture
--  Hook directly into BHttpRequest & rpcdecorator
------------------------------------------------------------

local LOG_DIR  = "C:\\Users\\AD\\Desktop\\find api"
local LOG_FILE = LOG_DIR .. "\\api_log.txt"

if _G.__api_logger_v3 then
    print("[API] v3 already loaded, skipping.")
    return
end
_G.__api_logger_v3 = true

------------------------------------------------------------
--  Utilities
------------------------------------------------------------
local function log(msg)
    local line = os.date("[%H:%M:%S] ") .. tostring(msg)
    pcall(function()
        local f = io.open(LOG_FILE, "a")
        if f then f:write(line .. "\n"); f:close() end
    end)
    print("[API] " .. tostring(msg))
end

local function dump(v, depth)
    depth = depth or 0
    if depth > 4 then return tostring(v) end
    local t = type(v)
    if t == "table" then
        local parts = {}
        local n = 0
        for k, val in pairs(v) do
            n = n + 1
            if n > 40 then parts[#parts+1] = "...+" .. (n) .. " more"; break end
            parts[#parts+1] = tostring(k) .. "=" .. dump(val, depth + 1)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    elseif t == "string" then
        if #v > 500 then return '"' .. v:sub(1,500) .. '...[' .. #v .. ']"' end
        return '"' .. v .. '"'
    elseif t == "userdata" then
        -- Try to get useful info from userdata
        local ok, str = pcall(tostring, v)
        return ok and str or "<userdata>"
    end
    return tostring(v)
end

-- Clear old log
pcall(function()
    local f = io.open(LOG_FILE, "w"); if f then f:write(""); f:close() end
end)

log("========================================")
log("  API Logger v3 - Deep RPC/HTTP Capture")
log("========================================")

------------------------------------------------------------
--  Method 1: Hook BHttpRequest (captures URL + body)
------------------------------------------------------------
local http_hooked = false
pcall(function()
    for modname, mod in pairs(package.loaded) do
        if type(modname) == "string" and type(mod) == "table" then
            -- Hook HttpBase.BHttpRequest
            if modname:find("HttpBase") then
                log("[SCAN] Found " .. modname)
                for k, v in pairs(mod) do
                    log("  key: " .. tostring(k) .. " type: " .. type(v))
                end
            end

            -- Hook BHttpClient functions
            if modname:find("BHttpClient") then
                log("[SCAN] Found " .. modname)
                for k, v in pairs(mod) do
                    log("  key: " .. tostring(k) .. " type: " .. type(v))
                end

                -- Hook http_request: captures URL, method, body
                if mod.http_request and type(mod.http_request) == "function" then
                    local orig = mod.http_request
                    mod.http_request = function(self, ...)
                        log(">>>>>>>>>> HTTP REQUEST <<<<<<<<<<")
                        log("  self: " .. dump(self, 1))
                        local args = {...}
                        for i, a in ipairs(args) do
                            log("  arg" .. i .. ": " .. dump(a, 2))
                        end
                        log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                        return orig(self, ...)
                    end
                    http_hooked = true
                    log("[OK] Hooked http_request!")
                end

                -- Hook BHTTPSClient
                if mod.BHTTPSClient and type(mod.BHTTPSClient) == "function" then
                    local orig = mod.BHTTPSClient
                    mod.BHTTPSClient = function(...)
                        log(">>>>>>>>>> HTTPS CLIENT CREATE <<<<<<<<<<")
                        local args = {...}
                        for i, a in ipairs(args) do
                            log("  arg" .. i .. ": " .. dump(a, 2))
                        end
                        log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                        return orig(...)
                    end
                    log("[OK] Hooked BHTTPSClient!")
                end
            end
        end
    end
end)

------------------------------------------------------------
--  Method 2: Hook rpcdecorator (captures RPC method names)
------------------------------------------------------------
local rpc_hooked = false
pcall(function()
    for modname, mod in pairs(package.loaded) do
        if type(modname) == "string" and type(mod) == "table" then
            if modname:find("rpcdecorator") then
                log("[SCAN] Found " .. modname)
                for k, v in pairs(mod) do
                    log("  key: " .. tostring(k) .. " type: " .. type(v))
                end

                -- Hook is_rpc_method
                if mod.is_rpc_method and type(mod.is_rpc_method) == "function" then
                    local orig = mod.is_rpc_method
                    mod.is_rpc_method = function(...)
                        local result = orig(...)
                        local args = {...}
                        log("RPC is_rpc_method: " .. dump(args, 2) .. " => " .. tostring(result))
                        return result
                    end
                    log("[OK] Hooked is_rpc_method!")
                end

                -- Hook the rpc call function (line 38 in rpcdecorator)
                -- This is likely the __call metamethod or a wrapper
                if mod.call_rpc and type(mod.call_rpc) == "function" then
                    local orig = mod.call_rpc
                    mod.call_rpc = function(...)
                        log("========== RPC CALL (decorator) ==========")
                        local args = {...}
                        for i, a in ipairs(args) do
                            log("  arg" .. i .. ": " .. dump(a, 2))
                        end
                        log("===========================================")
                        return orig(...)
                    end
                    rpc_hooked = true
                    log("[OK] Hooked call_rpc!")
                end
            end

            -- Hook RpcMethodArgs.convert
            if modname:find("RpcMethodArgs") then
                log("[SCAN] Found " .. modname)
                for k, v in pairs(mod) do
                    log("  key: " .. tostring(k) .. " type: " .. type(v))
                end

                if mod.convert and type(mod.convert) == "function" then
                    local orig = mod.convert
                    mod.convert = function(self, ...)
                        log("===== RpcMethodArgs.convert =====")
                        log("  self: " .. dump(self, 2))
                        local args = {...}
                        for i, a in ipairs(args) do
                            log("  arg" .. i .. ": " .. dump(a, 2))
                        end
                        local result = orig(self, ...)
                        log("  result: " .. dump(result, 2))
                        log("=================================")
                        return result
                    end
                    log("[OK] Hooked RpcMethodArgs.convert!")
                end
            end
        end
    end
end)

------------------------------------------------------------
--  Method 3: Hook net_call_rpc
------------------------------------------------------------
pcall(function()
    for modname, mod in pairs(package.loaded) do
        if type(modname) == "string" and type(mod) == "table" then
            if modname:find("net_call_rpc") then
                log("[SCAN] net_call_rpc: " .. modname)
                for k, v in pairs(mod) do
                    if type(v) == "function" then
                        log("  func: " .. tostring(k))
                        -- Hook ALL functions in this module
                        local orig = v
                        local fname = tostring(k)
                        mod[k] = function(...)
                            log("NET_RPC >> " .. fname)
                            local args = {...}
                            for i = 1, math.min(#args, 8) do
                                log("  arg" .. i .. ": " .. dump(args[i], 1))
                            end
                            return orig(...)
                        end
                    end
                end
                log("[OK] Hooked all net_call_rpc functions!")
            end
        end
    end
end)

------------------------------------------------------------
--  Method 4: Hook AsioServerProxy.callserver
------------------------------------------------------------
pcall(function()
    for modname, mod in pairs(package.loaded) do
        if type(modname) == "string" and modname:find("AsioServerProxy") then
            log("[SCAN] " .. modname)

            local function deep_hook(tbl, label)
                if type(tbl) ~= "table" then return end
                for k, v in pairs(tbl) do
                    if type(v) == "function" then
                        local orig = v
                        local fname = tostring(k)
                        tbl[k] = function(...)
                            log("ASIO >> " .. fname .. " (" .. label .. ")")
                            local args = {...}
                            for i = 1, math.min(#args, 6) do
                                log("  arg" .. i .. ": " .. dump(args[i], 1))
                            end
                            return orig(...)
                        end
                    end
                end
            end

            deep_hook(mod, "module")
            local mt = getmetatable(mod)
            if mt then
                deep_hook(mt, "mt")
                if mt.__index and type(mt.__index) == "table" then
                    deep_hook(mt.__index, "mt.__index")
                end
            end
        end
    end
end)

------------------------------------------------------------
--  Method 5: Focused debug.sethook for player_card window
------------------------------------------------------------
pcall(function()
    debug.sethook(function(event)
        if event ~= "call" then return end
        local info = debug.getinfo(2, "Snlf")
        if not info or not info.source then return end

        local src = info.source:lower()
        local name = info.name or ""

        -- Only log player_card and HTTP/RPC calls
        local dominated = false
        local targets = {
            "player_card", "name_card",
            "bhttpclient", "httpbase",
            "rpcdecorator", "rpcmethodargs",
            "net_call_rpc", "asioserverproxy",
            "asiogateclient",
        }

        for _, kw in ipairs(targets) do
            if src:find(kw, 1, true) then
                dominated = true
                break
            end
        end

        if not dominated then return end

        -- Capture args
        local args_parts = {}
        pcall(function()
            local i = 1
            while i <= 12 do
                local argname, argval = debug.getlocal(2, i)
                if not argname then break end
                if not argname:match("^%(") then
                    args_parts[#args_parts+1] = argname .. "=" .. dump(argval, 1)
                end
                i = i + 1
            end
        end)

        local args_str = #args_parts > 0 and "  (" .. table.concat(args_parts, ", ") .. ")" or ""
        log("TRACE " .. name .. "  @" .. info.source .. ":" .. (info.currentline or "?") .. args_str)

    end, "c")
    log("[OK] debug.sethook installed (focused)")
end)

log("")
log("Ready! View a player profile now.")
log("Log: " .. LOG_FILE)
