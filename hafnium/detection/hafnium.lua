-- HAFNIUM targeting Exchange Servers with 0-day exploits
-- ref: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
-- Compatible OS: windows
-- Binding Events:
--   Process Create
--   Etw DNS
--
-- version 2
--   - added binding and check for dns event
--   - added check on suspicious powershell process creation


if __engine_version < 2 then
    return
end

local version = 2

local function notify()
    local title = "HAFNIUM Behaviour detected: v" .. version
    local notes = ""
    local impact = 100
    local tags = {"hafnium"}
    create_alert({event}, title, impact, notes, tags)
end

local function check_w3p_parent()
    if event.process.get_parent_ofn() == "w3wp.exe"
        and event.process.get_parent_cmd_line():lower():find("msexchangeowaapppool")
    then return true
    end
    return false
end

local function cmd()
    if not check_w3p_parent() then return false end
    if event.process.get_ofn() ~= "cmd.exe" then return false end
    return true
end

local function net_del_exchange()
    if event.process.get_ofn() ~= "net.exe" then return false end
    local cmdline = event.process.get_cmd_line():lower()
    if cmdline:find("exchange organization administrators")
        and cmdline:find("/del")
        and cmdline:find("group")
        then return true end
    return false
end

local function powershell_bypass()
    if event.process.get_ofn() ~= "powershell.exe" then return false end
    local cmdline = event.process.get_cmd_line():lower()
    if cmdline:find("-ep bypass") and cmdline:find("sqbfafg") then
        return true
    end
    return false
end

local function dns_malicious()
    local known_providers = {
        "p.estonine.com",
    }
    for _, provider in ipairs(known_providers) do
        if event.data.queryName:match(provider) then
            return true
        end
    end
    return false
end

if (event.is_process_created() and (cmd() or net_del_exchange() or powershell_bypass()))
    or (event.is_dns_actvity() and dns_malicious()) then
    notify()
end
