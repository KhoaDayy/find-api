-- ============================================
-- FIND SEARCH ENDPOINT
-- Chạy script này, vào game và thực hiện
-- TÌM KIẾM NGƯỜI CHƠI BẰNG TÊN
-- Script sẽ log ra endpoint + payload chính xác
-- ============================================

local LOG = "C:\\Users\\AD\\Desktop\\find api\\search_endpoint.txt"

local function log(s)
    local f = io.open(LOG, "a")
    if f then f:write(os.date("[%H:%M:%S] ") .. s .. "\n"); f:close() end
    print("[SearchCapture] " .. s)
end

local function dump_table(t, indent)
    indent = indent or "  "
    if type(t) ~= "table" then return tostring(t) end
    local result = "{\n"
    for k, v in pairs(t) do
        result = result .. indent .. tostring(k) .. " = "
        if type(v) == "table" then
            result = result .. dump_table(v, indent .. "  ")
        else
            result = result .. tostring(v)
        end
        result = result .. "\n"
    end
    return result .. "}"
end

log("========================================")
log("  SEARCH ENDPOINT FINDER")
log("  -> Vào game và TÌM KIẾM PLAYER BẰNG TÊN")
log("========================================")

-- Hook BHTTPClient để bắt TẤT CẢ requests
local BHTTPClient = require and require("hexm.common.BHTTPClient")
    or package.loaded["hexm.common.BHTTPClient"]
    or package.loaded["BHTTPClient"]

if BHTTPClient then
    log("[+] BHTTPClient found!")

    -- Hook tất cả method có thể gửi request
    for fname, func in pairs(BHTTPClient) do
        if type(func) == "function" then
            local orig = func
            BHTTPClient[fname] = function(self, ...)
                local args = {...}
                -- Lọc ra các request liên quan đến search/find
                local interesting = false
                for _, v in ipairs(args) do
                    if type(v) == "string" then
                        if v:find("find") or v:find("search") or v:find("role") or
                           v:find("people") or v:find("player") then
                            interesting = true
                        end
                    end
                end

                if interesting then
                    log("\n[!!!] REQUEST CAPTURED: BHTTPClient." .. fname)
                    for i, v in ipairs(args) do
                        if type(v) == "string" then
                            log("  arg[" .. i .. "] = \"" .. v .. "\"")
                        elseif type(v) == "table" then
                            log("  arg[" .. i .. "] (table) = " .. dump_table(v))
                        end
                    end
                end

                return orig(self, ...)
            end
        end
    end
else
    log("[-] BHTTPClient NOT found, trying uwsgi_helper...")

    -- Fallback: hook uwsgi_helper
    local modules_to_try = {
        "hexm.common.uwsgi_helper",
        "app.common.uwsgi_helper",
        "common.uwsgi_helper",
        "uwsgi_helper"
    }

    for _, mod_name in ipairs(modules_to_try) do
        local ok, mod = pcall(require, mod_name)
        if ok and mod then
            log("[+] Found module: " .. mod_name)

            for fname, func in pairs(mod) do
                if type(func) == "function" then
                    local orig = func
                    mod[fname] = function(...)
                        local args = {...}
                        -- Bắt TẤT CẢ request để log
                        log("\n[CALL] " .. mod_name .. "." .. fname)
                        for i, v in ipairs(args) do
                            if type(v) == "string" then
                                log("  arg[" .. i .. "] = \"" .. v .. "\"")
                            elseif type(v) == "table" then
                                log("  arg[" .. i .. "] = " .. dump_table(v))
                            end
                        end
                        return orig(...)
                    end
                end
            end
            break
        end
    end
end

log("[*] Hook installed! Bây giờ hãy thực hiện TÌM KIẾM NGƯỜI CHƠI BẰNG TÊN trong game!")
