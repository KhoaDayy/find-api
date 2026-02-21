-- Session Capture Script v1
-- Purpose: Capture fresh session key from game for external API use
-- Hooks UwsgiHelper to intercept ALL API calls and extract the session

local LOG_FILE = "C:\\Users\\AD\\Desktop\\find api\\api_log.txt"
local SESSION_FILE = "C:\\Users\\AD\\Desktop\\find api\\session.txt"

function log(msg)
    local f = io.open(LOG_FILE, "a")
    if f then f:write(os.date("[%H:%M:%S] ") .. msg .. "\n"); f:close() end
    print("[SessionCapture] " .. msg)
end

function save_session(key)
    local f = io.open(SESSION_FILE, "w")
    if f then f:write(key); f:close() end
    log(">>> SESSION SAVED to session.txt: " .. key)
end

log("========================================")
log("  Session Capture v1 - HOOK ALL CALLS")
log("========================================")

local captured = false

-- Hook UwsgiHelper
local uwsgi_helper = package.loaded["hexm.common.uwsgi_helper"]
if uwsgi_helper then
    log("[+] UwsgiHelper found!")
    
    -- Try to find and hook http_request or post_to_uwsgi
    for k, v in pairs(uwsgi_helper) do
        if type(v) == "function" then
            log("  Found function: " .. k)
        end
    end
    
    -- Hook post_to_uwsgi
    if uwsgi_helper.post_to_uwsgi then
        local orig = uwsgi_helper.post_to_uwsgi
        uwsgi_helper.post_to_uwsgi = function(self, endpoint, payload, callback, ...)
            log(">>> post_to_uwsgi: " .. tostring(endpoint))
            
            -- Try to extract session from self (UwsgiManager)
            if not captured and self then
                -- Check for session in self
                for sk, sv in pairs(self) do
                    if type(sv) == "string" and #sv > 5 and #sv < 50 then
                        if sk == "session" or sk == "session_key" or sk == "_session" or sk == "sessionKey" then
                            log(">>> FOUND SESSION KEY in self." .. tostring(sk) .. ": " .. sv)
                            save_session(sv)
                            captured = true
                        end
                    end
                end
                
                -- Try metatable
                if not captured then
                    local mt = getmetatable(self)
                    if mt and type(mt.__index) == "table" then
                        for sk, sv in pairs(mt.__index) do
                            if type(sv) == "string" and #sv > 5 and #sv < 50 then
                                if sk == "session" or sk == "session_key" or sk == "_session" then
                                    log(">>> FOUND SESSION KEY in mt." .. tostring(sk) .. ": " .. sv)
                                    save_session(sv)
                                    captured = true
                                end
                            end
                        end
                    end
                end
                
                -- Dump all string fields of self to find session
                if not captured then
                    log("[*] Dumping self fields to find session...")
                    for sk, sv in pairs(self) do
                        if type(sv) == "string" and #sv > 5 and #sv < 100 then
                            log("    self." .. tostring(sk) .. " = " .. sv)
                        end
                    end
                end
            end
            
            -- Log payload keys
            if type(payload) == "table" then
                local keys = {}
                for pk, _ in pairs(payload) do
                    keys[#keys+1] = tostring(pk)
                end
                log("    payload keys: " .. table.concat(keys, ", "))
            end
            
            return orig(self, endpoint, payload, callback, ...)
        end
        log("[+] Hooked post_to_uwsgi!")
    end
    
    -- Also hook http_request if exists (this is what BHTTPClient uses)
    if uwsgi_helper.http_request then
        local orig_http = uwsgi_helper.http_request
        uwsgi_helper.http_request = function(self, ...)
            local args = {...}
            log(">>> http_request called")
            for i, arg in ipairs(args) do
                if type(arg) == "string" then
                    log("    arg[" .. i .. "] = " .. arg:sub(1, 200))
                    -- Check if URL contains session param
                    local sess = arg:match("session=([^&]+)")
                    if sess and not captured then
                        log(">>> SESSION FROM URL: " .. sess)
                        save_session(sess)
                        captured = true
                    end
                end
            end
            return orig_http(self, ...)
        end
        log("[+] Hooked http_request!")
    end
else
    log("[!] UwsgiHelper NOT found")
end

-- Also try to get session from G.uwsgi_manager directly
if G and G.uwsgi_manager then
    log("[*] Checking G.uwsgi_manager for session...")
    for k, v in pairs(G.uwsgi_manager) do
        if type(v) == "string" then
            log("    G.uwsgi_manager." .. tostring(k) .. " = " .. v)
            if k == "session" or k == "session_key" or k == "_session" or k == "sessionKey" then
                log(">>> DIRECT SESSION: " .. v)
                save_session(v)
                captured = true
            end
        end
    end
end

log("")
if captured then
    log(">>> SESSION CAPTURED SUCCESSFULLY!")
else
    log(">>> Session not found yet. Open profile or do any action to trigger API call.")
end
log("========================================")
