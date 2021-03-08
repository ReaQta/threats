-- HAFNIUM targeting Exchange Servers with 0-day exploits
-- ref: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
-- Compatible OS: windows
-- Binding Events:
--   Process Create

if __engine_version < 2 then
    return
end

local version = 1

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

if not event.is_process_created() then return end
if cmd() or net_del_exchange() then
    notify()
end