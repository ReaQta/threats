-- FIN8 Behaviour detection for August 2021:
-- ref: https://businessinsights.bitdefender.com/deep-dive-into-a-fin8-attack-a-forensic-investigation
-- Compatible OS: windows
-- Binding Events:
-- 	Process Create
--	Etw DNS
-- Version 1

if __engine_version < 4 then
    return false
end

local version = 1

local function notify()
    local title = "FIN8 Behaviour detected: v" .. version
    local notes = ""
    local impact = 100
    local tags = {"FIN8", "IOC"}
    create_alert({event}, title, impact, notes, tags)
end

local psStringFormat = {
    "%-nop %-ep bypass %-c %$pw='[%g%s]+';%$pa='sys';iex %(New%-Object System%.Net%.WebClient%)%.DownloadString%('[%g]+'%)",
    "%-nop %-ep bypass %-c C:\\[%gs]+%.ps1%s+B4a0f3AE251b7689CFdDe1",
    "%[System%.Reflection%.Assembly%]::Load%(%(%[WmiClass%]'root\\cimv2:Win32_Base64Class'%)%.Properties%['Prop'%]%.Value%);%[MSDAC%.PerfOSChecker%]::StartCheck%(%)"
}

local function checkCmd()
    local ofn = event.process.program.filename
    local pofn = event.process.get_parent_ofn()

    local cmdline = event.data.cmdLine:lower()
    local wmiexecString = "1> \\\\127%.0%.0%.1\\ADMIN%$\\__%d%d%d%d%d%d%d%d%d%d%.%d+ 2>&1"
    if (ofn ~= "cmd.exe" and ofn ~= "powershell.exe" and ofn ~= "wmiprvse.exe") then
        return false
    end

    -- detects use wmiexec.py
    if pofn == "wmiprvse.exe" and cmdline:match(wmiexecString:lower()) then
        return true
    end

    -- detects fin8 specific commands
    for i, v in ipairs(psStringFormat) do
        if string.match(cmdline, v:lower()) then
            return true
        end
    end
    return false
end

local function checkDns()
    query = event.data.queryName:lower()
    ofn = event.process.program.filename

    if ofn == "powershell.exe" and query:match("sslip%.io$") then
        return true
    end
    if
        ofn == "wmiprvse.exe" and
            (query:match("api%-cdn%.net") or query:match("git%-api%.com") or query:match("api%-cdnw5%.net"))
     then
        return true
    end
    return false
end

if (event.is_dns_actvity() and checkDns()) or (event.is_process_created() and checkCmd()) then
    notify()
end
