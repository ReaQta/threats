-- APT41 detection rule
-- ref: https://documents.trendmicro.com/assets/white_papers/wp-earth-baku-an-apt-group-targeting-indo-pacific-countries.pdf
-- Compatible OS: windows
-- Binding Events:
--   Registry Persistence
--   Process Created
--
-- version 1
--   - ServiceDLL persistence detection
--   - Installutil.exe parent of msdtc.exe
--   - Installutil.exe spawned from scheduled task

if __engine_version < 4 then
    return
end

local version = 1
Title = "APT41 behaviour detected v" .. version
Impact = 100

local function notify(notes, tags)
    create_alert({event}, Title, Impact, notes, tags)
end

local function service_dll_persistence()
    if
        event.process.program.filename == "reg.exe" and event.parentProcess.program.filename == "cmd.exe" and
            event.data.name == "servicedll"
     then
        notify("APT41 ServiceDLL behaviour detected", {"apt41", "servicedll"})
        return true
    end
    return false
end

local function installutil_behaviour()
    if (event.process.program.filename == "msdtc.exe" and event.parentProcess.program.filename == "installutil.exe") then
        notify("APT41 InstallUtil.exe behaviour detected", {"apt41", "installutil.exe", "T1118", "T1218.004"})
        return true
    end
    return false
end

if event.is_reg_persistence() then
    service_dll_persistence()
elseif event.is_process_created() then
    installutil_behaviour()
end
