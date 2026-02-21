-- v15b - INTERCEPT callbacks (fixed varargs)
local LOG = "C:\\Users\\AD\\Desktop\\find api\\api_log.txt"
local RFILE = "C:\\Users\\AD\\Desktop\\find api\\lookup_response.txt"

local function log(s)
    pcall(function()
        local f = io.open(LOG, "a")
        if f then f:write(tostring(s) .. "\n"); f:close() end
    end)
end

local function d(v, n)
    n = n or 0
    if n > 4 then return "..." end
    if v == nil then return "nil" end
    local t = type(v)
    if t == "string" then return v end
    if t == "number" or t == "boolean" then return tostring(v) end
    if t == "table" or t == "instance" then
        local p = {}
        pcall(function()
            for k, vv in pairs(v) do
                if #p < 30 then
                    p[#p+1] = tostring(k).."="..d(vv, n+1)
                end
            end
        end)
        return "{"..table.concat(p, ",").."}"
    end
    return tostring(v)
end

log("=== v15b INTERCEPT ===")

pcall(function()
    local mod = package.loaded["hexm.common.uwsgi_helper"]
    if not mod or not mod.UwsgiHelper then log("!no mod"); return end
    local cls = mod.UwsgiHelper
    local orig = cls.post_to_uwsgi
    if not orig then log("!no post"); return end

    cls.post_to_uwsgi = function(self, ep, pl, cb, extra1, extra2)
        local eps = tostring(ep)
        local dominated = string.find(eps, "redis_player") or string.find(eps, "fashion")
        if not dominated then
            return orig(self, ep, pl, cb, extra1, extra2)
        end

        log("[CALL] " .. eps)

        if cb and type(cb) == "function" then
            local wrapped = function(r1, r2, r3, r4, r5)
                pcall(function()
                    log("[RESP] " .. eps)
                    if r1 ~= nil then log("  r1(" .. type(r1) .. ")=" .. string.sub(tostring(r1), 1, 100)) end
                    if r2 ~= nil then log("  r2(" .. type(r2) .. ")=" .. string.sub(d(r2), 1, 2000)) end
                    if r3 ~= nil then log("  r3(" .. type(r3) .. ")=" .. string.sub(d(r3), 1, 500)) end

                    -- Save fashion responses
                    if string.find(eps, "fashion") then
                        pcall(function()
                            local rf = io.open(RFILE, "a")
                            if rf then
                                rf:write("[" .. eps .. "]\n" .. d(r2) .. "\n\n")
                                rf:close()
                            end
                        end)
                    end

                    -- Check redis_player response for shot_img
                    if string.find(eps, "redis_player") and r2 ~= nil then
                        pcall(function()
                            for pid, pdata in pairs(r2) do
                                pcall(function()
                                    local base = pdata.base
                                    if base then
                                        log("  [BASE] " .. tostring(pid) .. " name=" .. tostring(base.name) .. " shot=" .. tostring(base.shot_img))
                                    end
                                end)
                                pcall(function()
                                    local fashion = pdata.fashion
                                    if fashion then
                                        log("  [FASHION] " .. tostring(pid) .. " " .. d(fashion))
                                    end
                                end)
                                pcall(function()
                                    local head = pdata.head
                                    if head then
                                        log("  [HEAD] " .. tostring(pid) .. " icon=" .. tostring(head.role_icon))
                                    end
                                end)
                            end
                        end)
                    end
                end)
                return cb(r1, r2, r3, r4, r5)
            end
            return orig(self, ep, pl, wrapped, extra1, extra2)
        end

        return orig(self, ep, pl, cb, extra1, extra2)
    end
    log("[+] HOOKED v15b")
end)

log("=== v15b READY ===")
