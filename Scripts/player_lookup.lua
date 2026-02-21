-- Player Lookup Script v1
-- Calls the game's internal API directly via UwsgiHelper
-- This bypasses the HOTP/signature requirement since it uses the game's own auth

local LOG_FILE = "C:\\Users\\AD\\Desktop\\find api\\player_lookup_result.txt"
local RESULT_FILE = "C:\\Users\\AD\\Desktop\\find api\\player_data.json"

-- Target player ID to look up
local TARGET_NUMBER_ID = "0017698248"

function log(msg)
    local f = io.open(LOG_FILE, "a")
    if f then f:write(os.date("[%H:%M:%S] ") .. msg .. "\n"); f:close() end
    print("[PlayerLookup] " .. msg)
end

function save_result(data)
    local f = io.open(RESULT_FILE, "w")
    if f then f:write(data); f:close() end
end

-- JSON encoder (minimal, for tables)
local function table_to_json(t)
    if type(t) ~= "table" then
        if type(t) == "string" then return '"' .. t .. '"' end
        if type(t) == "boolean" then return tostring(t) end
        if t == nil then return "null" end
        return tostring(t)
    end
    
    -- Check if array
    local is_array = (#t > 0) or next(t) == nil
    if is_array and #t > 0 then
        local parts = {}
        for i, v in ipairs(t) do
            parts[#parts + 1] = table_to_json(v)
        end
        return "[" .. table.concat(parts, ",") .. "]"
    else
        local parts = {}
        for k, v in pairs(t) do
            if type(k) == "string" then
                parts[#parts + 1] = '"' .. k .. '":' .. table_to_json(v)
            end
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
end

-- Pretty print table (recursive)
local function dump_table(t, indent)
    indent = indent or ""
    if type(t) ~= "table" then
        log(indent .. tostring(t))
        return
    end
    for k, v in pairs(t) do
        if type(v) == "table" then
            log(indent .. tostring(k) .. ":")
            dump_table(v, indent .. "  ")
        else
            log(indent .. tostring(k) .. " = " .. tostring(v))
        end
    end
end

log("========================================")
log("  Player Lookup v1 - INTERNAL API CALL")
log("========================================")

-- METHOD 1: Use UwsgiHelper directly
local uwsgi_helper = package.loaded["hexm.common.uwsgi_helper"]
local uwsgi_manager = nil

-- Try to find uwsgi_manager from G
if G and G.uwsgi_manager then
    uwsgi_manager = G.uwsgi_manager
    log("[*] Found G.uwsgi_manager")
end

if uwsgi_helper then
    log("[*] Found hexm.common.uwsgi_helper")
    log("[*] Dumping uwsgi_helper functions:")
    for k, v in pairs(uwsgi_helper) do
        log("    " .. tostring(k) .. " (" .. type(v) .. ")")
    end
else
    log("[!] uwsgi_helper NOT found in package.loaded")
end

-- Try to find post_to_uwsgi function
local post_func = nil

if uwsgi_helper then
    -- Check for common function names
    for _, name in ipairs({"post_to_uwsgi", "http_request", "post", "request"}) do
        if uwsgi_helper[name] then
            post_func = uwsgi_helper[name]
            log("[+] Found function: uwsgi_helper." .. name)
            break
        end
    end
end

-- METHOD 2: Try uwsgi_manager
if not post_func and uwsgi_manager then
    log("[*] Trying uwsgi_manager methods:")
    for k, v in pairs(uwsgi_manager) do
        if type(v) == "function" then
            log("    " .. tostring(k))
        end
    end
    
    for _, name in ipairs({"post_to_uwsgi", "http_request", "post", "request"}) do
        if uwsgi_manager[name] then
            post_func = uwsgi_manager[name]
            log("[+] Found function: uwsgi_manager." .. name)
            break
        end
    end
end

-- METHOD 3: Search through hexm.client.manager.uwsgi_manager
local mgr_module = package.loaded["hexm.client.manager.uwsgi_manager"]
if mgr_module then
    log("[*] Found hexm.client.manager.uwsgi_manager")
    for k, v in pairs(mgr_module) do
        log("    " .. tostring(k) .. " (" .. type(v) .. ")")
    end
end

-- Now try to make the actual API call
if post_func then
    log("")
    log("[*] === STEP 1: Find player by Number ID ===")
    log("[*] Target: " .. TARGET_NUMBER_ID)
    
    -- Callback for find_people
    local function on_find_result(success, data)
        log("[*] Find result callback:")
        log("    success = " .. tostring(success))
        if data then
            log("    data type = " .. type(data))
            if type(data) == "table" then
                dump_table(data, "    ")
                save_result(table_to_json(data))
                log("[*] Result saved to " .. RESULT_FILE)
            elseif type(data) == "string" then
                log("    data = " .. data)
                save_result(data)
            end
        else
            log("    data = nil")
        end
    end
    
    -- Try calling post_to_uwsgi
    -- Common signatures:
    -- post_to_uwsgi(endpoint, payload_table, callback)
    -- post_to_uwsgi(self, endpoint, payload_table, callback)
    -- http_request(self, method, url, payload, headers, callback)
    
    local payload = {
        number_id = TARGET_NUMBER_ID,
        force_search = false
    }
    
    log("[*] Calling API with payload:")
    dump_table(payload, "    ")
    
    -- Try different call patterns
    local ok, err = pcall(function()
        if uwsgi_manager then
            -- Object method style: uwsgi_manager:post_to_uwsgi(endpoint, payload, callback)
            post_func(uwsgi_manager, "/flk/find_people/by_number_id", payload, on_find_result)
        else
            -- Static function style
            post_func("/flk/find_people/by_number_id", payload, on_find_result)
        end
    end)
    
    if ok then
        log("[*] API call dispatched! Check callback for results...")
    else
        log("[!] API call FAILED: " .. tostring(err))
        
        -- Try alternative call patterns
        log("[*] Trying alternative patterns...")
        
        local ok2, err2 = pcall(function()
            post_func("/flk/find_people/by_number_id", payload)
        end)
        
        if ok2 then
            log("[*] Alt pattern 1 succeeded (no callback)")
        else
            log("[!] Alt pattern 1 failed: " .. tostring(err2))
        end
    end
else
    log("[!] Could not find any post/request function!")
    log("[*] Scanning ALL loaded packages for uwsgi/http functions...")
    
    local found_modules = {}
    for name, mod in pairs(package.loaded) do
        if type(name) == "string" and type(mod) == "table" then
            if name:find("uwsgi") or name:find("http") or name:find("network") then
                found_modules[#found_modules + 1] = name
                log("  MODULE: " .. name)
                for k, v in pairs(mod) do
                    if type(v) == "function" then
                        log("    func: " .. tostring(k))
                    end
                end
            end
        end
    end
    
    if #found_modules == 0 then
        log("[!] No uwsgi/http/network modules found!")
    end
end

log("")
log("========================================")
log("  Scan Complete")
log("========================================")
