-- API Host Capture Script v1
-- Purpose: Capture the API hostname used by the GLOBAL/SEA version
-- Inject this into wwm.exe (Global version) and open any player profile
-- The captured host will be saved to api_host_captured.txt

local LOG_FILE = "C:\\Users\\AD\\Desktop\\find api\\api_host_captured.txt"

function log(msg)
    local f = io.open(LOG_FILE, "a")
    if f then f:write(os.date("[%H:%M:%S] ") .. msg .. "\n"); f:close() end
    print("[HostCapture] " .. msg)
end

log("========================================")
log("  HOST CAPTURE v1 - GLOBAL/SEA VERSION")
log("========================================")

-- 1. Hook UwsgiHelper to capture the base URL
local uwsgi_helper = package.loaded["hexm.common.uwsgi_helper"]
if uwsgi_helper then
    log("[+] UwsgiHelper found! Dumping all keys:")
    for k, v in pairs(uwsgi_helper) do
        log("    " .. tostring(k) .. " = " .. tostring(v) .. " (" .. type(v) .. ")")
        -- If it's a string, it might be the host URL
        if type(v) == "string" and (v:find("http") or v:find("netease") or v:find("ms-prod") or v:find("://")) then
            log("    >>> POSSIBLE HOST: " .. v)
        end
    end
    
    -- Hook all functions to see URLs being passed
    for k, v in pairs(uwsgi_helper) do
        if type(v) == "function" then
            local orig = v
            local fname = k
            uwsgi_helper[k] = function(...)
                local args = {...}
                log("\n[CALL] uwsgi_helper." .. fname .. "()")
                for i, arg in ipairs(args) do
                    if type(arg) == "string" then
                        log("  arg[" .. i .. "] = \"" .. arg .. "\"")
                        if arg:find("http") or arg:find("://") or arg:find("netease") then
                            log("  >>> URL FOUND: " .. arg)
                        end
                    elseif type(arg) == "table" then
                        log("  arg[" .. i .. "] = table:")
                        for tk, tv in pairs(arg) do
                            log("    " .. tostring(tk) .. " = " .. tostring(tv))
                            if type(tv) == "string" and (tv:find("http") or tv:find("://")) then
                                log("    >>> URL IN TABLE: " .. tv)
                            end
                        end
                    else
                        log("  arg[" .. i .. "] = " .. tostring(arg))
                    end
                end
                return orig(...)
            end
            log("  Hooked: " .. fname)
        end
    end
else
    log("[!] UwsgiHelper NOT in package.loaded")
end

-- 2. Scan _G for uwsgi_manager to find host config
if G then
    log("\n[*] Scanning G for uwsgi/http configs...")
    
    if G.uwsgi_manager then
        log("[+] G.uwsgi_manager found!")
        -- Dump entire object
        for k, v in pairs(G.uwsgi_manager) do
            log("  " .. tostring(k) .. " = " .. tostring(v) .. " (" .. type(v) .. ")")
            if type(v) == "string" and (v:find("http") or v:find("://") or v:find("netease")) then
                log("  >>> HOST CONFIG: " .. v)
            end
        end
        -- Check metatable
        local mt = getmetatable(G.uwsgi_manager)
        if mt then
            log("  [metatable found]")
            if type(mt.__index) == "table" then
                for k, v in pairs(mt.__index) do
                    log("    mt." .. tostring(k) .. " = " .. tostring(v) .. " (" .. type(v) .. ")")
                    if type(v) == "string" and (v:find("http") or v:find("://")) then
                        log("    >>> HOST IN MT: " .. v)
                    end
                end
            end
        end
    else
        log("[!] G.uwsgi_manager not found")
    end
    
    -- Search ALL of G for host-related strings
    log("\n[*] Deep scan _G for host/URL strings...")
    for k, v in pairs(G) do
        if type(v) == "string" and (v:find("ms%-prod") or v:find("netease%.com") or v:find("http")) then
            log("  G." .. tostring(k) .. " = " .. v)
        end
    end
end

-- 3. Scan package.loaded for any module containing host URL
log("\n[*] Scanning ALL loaded packages for host URLs...")
for name, mod in pairs(package.loaded) do
    if type(name) == "string" and type(mod) == "table" then
        for k, v in pairs(mod) do
            if type(v) == "string" and (v:find("ms%-prod") or v:find("%.netease%.com") or v:find("uwsgi") and v:find("http")) then
                log("  [" .. name .. "]." .. tostring(k) .. " = " .. v)
            end
        end
    end
end

-- 4. Hook BHTTPClient if exists
log("\n[*] Looking for BHTTPClient...")
for name, mod in pairs(package.loaded) do
    if type(name) == "string" and (name:find("http") or name:find("HTTP") or name:find("bhttpclient") or name:find("BHTTPClient")) then
        log("[+] HTTP Module: " .. name)
        if type(mod) == "table" then
            for k, v in pairs(mod) do
                log("    " .. tostring(k) .. " (" .. type(v) .. ")")
            end
        end
    end
end

-- Try to find BHTTPClient in _G
if BHTTPClient then
    log("[+] BHTTPClient found in _G!")
    for k, v in pairs(BHTTPClient) do
        log("    " .. tostring(k) .. " (" .. type(v) .. ")")
    end
end

-- 5. Check game config for server info
local config_modules = {
    "hexm.common.config",
    "hexm.client.config", 
    "hexm.common.server_config",
    "hexm.client.server_config",
    "hexm.common.network_config",
    "hexm.client.network_config",
    "hexm.common.uwsgi_config",
    "hexm.client.manager.uwsgi_manager",
}

log("\n[*] Checking config modules...")
for _, modname in ipairs(config_modules) do
    local mod = package.loaded[modname]
    if mod then
        log("[+] " .. modname .. " found!")
        if type(mod) == "table" then
            for k, v in pairs(mod) do
                log("    " .. tostring(k) .. " = " .. tostring(v))
            end
        end
    end
end

log("\n========================================")
log("  CAPTURE READY")
log("  Open any player profile to trigger")
log("  API calls and capture the host URL")
log("========================================")
