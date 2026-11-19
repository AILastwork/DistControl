#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\DistControl"),
    [Alias("DataDir")]
    [string]$ProgramDataDir = (Join-Path $env:LOCALAPPDATA "DistControl"),
    [string]$ServiceName = "dkclient",
    [string]$TargetUserSid,
    [string]$UserStartMenuDir = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\DistControl"),
    [string]$UserDesktopDir = ([Environment]::GetFolderPath("DesktopDirectory")),
    [switch]$RemoveData,
    [switch]$SkipMsiUnregister,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'ClientLifecycle.ps1')
try {
    $script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $script:Utf8NoBomEncoding
    $OutputEncoding = $script:Utf8NoBomEncoding
}
catch {
}
$EffectiveTargetUserSid = if ([string]::IsNullOrWhiteSpace($TargetUserSid)) { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { $TargetUserSid.Trim() }
$UninstallRegistryPath = "Registry::HKEY_USERS\$EffectiveTargetUserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\DistControl"
$ClientStartupShortcut = Join-Path (Split-Path -Parent $UserStartMenuDir) "Startup\DistControl dkclient.lnk"
$AgentServiceName = Get-ClientAgentServiceName $EffectiveTargetUserSid
$MsiUpgradeCode = "{8E2503E8-7098-4FF1-9278-7AC5C473E0CF}"
# "Apply once" filter of the DistControlInstall task in the distcontrol GPO; used when the
# GPO history copy is not available. Ids found in the history are always used as well.
$DefaultGpoInstallRunOnceId = "{C8382FB5-55BD-4A93-80B5-EDD381BA5034}"
$MachineInstallContextRegistryPath = "$ClientContextsRegistryPath\$EffectiveTargetUserSid"
$InteractiveDkClientTaskName = "DistControl Interactive dkclient"
$LogsDir = Join-Path $ProgramDataDir "logs"
$ManagedHubRoutesPath = Join-Path $ProgramDataDir "managed-hub-routes.json"
$script:UninstallLogPath = $null

function Write-UninstallLogLine([string]$Message) {
    if ([string]::IsNullOrWhiteSpace($script:UninstallLogPath)) {
        return
    }

    try {
        $line = "[{0}] {1}{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message, [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:UninstallLogPath, $line, $script:Utf8NoBomEncoding)
    }
    catch {
    }
}

function Write-Step([string]$Message) {
    Write-Host "[DistControl] $Message"
    Write-UninstallLogLine "[DistControl] $Message"
}

function Start-UninstallLog {
    if ($DryRun) {
        return
    }

    try {
        $root = if ($RemoveData) { Join-Path ([System.IO.Path]::GetTempPath()) "DistControl-logs" } else { $LogsDir }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $script:UninstallLogPath = Join-Path $root ("uninstall-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        [System.IO.File]::WriteAllText($script:UninstallLogPath, "", $script:Utf8NoBomEncoding)
        Write-Step "Uninstall log: $script:UninstallLogPath"
    }
    catch {
        Write-Host "[DistControl] WARNING: Cannot start uninstall log: $($_.Exception.Message)"
    }
}

function Convert-UninstallErrorToHuman([string]$Message) {
    $lower = if ($Message) { $Message.ToLowerInvariant() } else { "" }
    if ($lower.Contains("administrator") -or
        $lower.Contains("access is denied") -or
        $lower.Contains("отказано в доступе") -or
        $lower.Contains("unauthorizedaccess")) {
        return "Не хватило прав. Запустите удаление от имени администратора."
    }
    if ($lower.Contains("dkcl64.exe is still running") -or
        $lower.Contains("stop dkcl64.exe")) {
        return "Процесс dkcl64.exe продолжает работать. Закройте DistControl, остановите службу dkclient или перезагрузите компьютер."
    }
    if ($lower.Contains("service") -or
        $lower.Contains("sc.exe")) {
        return "Windows не дала остановить или удалить службу dkclient. Проверьте службу в services.msc и повторите удаление."
    }
    if ($lower.Contains("remove-item") -or
        $lower.Contains("ownership") -or
        $lower.Contains("acl")) {
        return "Не удалось удалить файл или папку из-за прав доступа. Подробности ниже в журнале."
    }
    return "Удаление остановилось из-за технической ошибки. Подробности ниже в этом журнале."
}

function Write-UninstallErrorDetails([object]$Record) {
    $message = if ($Record -and $Record.Exception) { $Record.Exception.Message } else { "$Record" }
    $human = Convert-UninstallErrorToHuman $message
    Write-Host "[DistControl] USER-ERROR: $human"
    Write-Host "[DistControl] ERROR: $message"
    Write-UninstallLogLine "[DistControl] USER-ERROR: $human"
    Write-UninstallLogLine "[DistControl] ERROR: $message"
    if ($Record -and $Record.Exception) {
        Write-UninstallLogLine "[DistControl] ERROR TYPE: $($Record.Exception.GetType().FullName)"
    }
    if ($Record -and $Record.InvocationInfo) {
        Write-UninstallLogLine "[DistControl] ERROR SCRIPT: $($Record.InvocationInfo.ScriptName)"
        Write-UninstallLogLine "[DistControl] ERROR LINE: $($Record.InvocationInfo.ScriptLineNumber)"
        Write-UninstallLogLine "[DistControl] ERROR COMMAND: $($Record.InvocationInfo.Line)"
    }
    if ($Record -and $Record.ScriptStackTrace) {
        Write-UninstallLogLine "[DistControl] ERROR STACK: $($Record.ScriptStackTrace)"
    }
}

function Write-UninstallEnvironmentSummary {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $identity = "<unknown>"
    }
    Write-Step "Environment: computer=$env:COMPUTERNAME; processUser=$identity; targetUserSid=$EffectiveTargetUserSid; installDir=$InstallDir; dataDir=$ProgramDataDir; service=$ServiceName; removeData=$RemoveData"
}

trap {
    Write-UninstallErrorDetails $_
    Exit-ClientLifecycleLock
    exit 1
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this uninstaller from an elevated Administrator console."
    }
}

function Invoke-External([string]$FilePath, [string[]]$Arguments) {
    if ($DryRun) {
        Write-Step "DRY-RUN: $FilePath $($Arguments -join ' ')"
        return
    }

    $output = & $FilePath @Arguments 2>&1
    foreach ($line in @($output)) {
        Write-Host $line
        Write-UninstallLogLine "[external] $line"
    }
    if ($LASTEXITCODE -ne 0) {
        if ($FilePath -eq 'sc.exe' -and $Arguments[0] -eq 'delete' -and $LASTEXITCODE -in @(1060, 1072)) {
            Write-Step 'Service is already absent or marked for deletion'
            return
        }
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-ExternalOptional([string]$FilePath, [string[]]$Arguments, [string]$WarningPrefix) {
    if ($DryRun) {
        Write-Step "DRY-RUN: $FilePath $($Arguments -join ' ')"
        return
    }

    $output = & $FilePath @Arguments 2>&1
    foreach ($line in @($output)) {
        Write-Host $line
        Write-UninstallLogLine "[external] $line"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Step ("WARNING: {0}: exit code {1}: {2} {3}" -f $WarningPrefix, $LASTEXITCODE, $FilePath, ($Arguments -join ' '))
    }
}

function Test-DirectoryPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    return (Get-Item -LiteralPath $Path -Force).PSIsContainer
}

function Repair-RemovalAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $takeownArgs = @("/F", $Path, "/A")
    $icaclsArgs = @(
        $Path,
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F"
    )

    if (Test-DirectoryPath $Path) {
        $takeownArgs += @("/R", "/D", "Y")
        $icaclsArgs += @("/T", "/C")
    }

    Invoke-ExternalOptional "takeown.exe" $takeownArgs "Cannot take ownership before removal"
    Invoke-ExternalOptional "icacls.exe" $icaclsArgs "Cannot grant removal ACL"
}

function Remove-PathSafe([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    Write-Step "Remove $Path"
    if (-not $DryRun) {
        $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $allowed = @($InstallDir, $ProgramDataDir, $UserStartMenuDir, $ClientStartupShortcut, (Join-Path $UserDesktopDir 'DistControl.lnk'), $SharedRuntimeDirectory, $SharedRuntimeStateDirectory)
        if (@($allowed | Where-Object { [string]::Equals([IO.Path]::GetFullPath($_).TrimEnd('\'), $resolved, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
            throw "Unsafe removal target: $resolved"
        }
        Repair-RemovalAcl $Path
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Remove-UninstallEntry {
    Write-Step "Remove Windows uninstall entry"
    if ($DryRun) { return }
    $hiveName = $null
    try {
        $entryPath = $UninstallRegistryPath
        if (-not (Test-Path -LiteralPath "Registry::HKEY_USERS\$EffectiveTargetUserSid")) {
            $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$EffectiveTargetUserSid"
            $profile = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $profileKey).ProfileImagePath)
            $hiveFile = Join-Path $profile 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $hiveFile)) { return }
            $hiveName = "DistControlUninstall-$EffectiveTargetUserSid"
            Invoke-External 'reg.exe' @('load', "HKU\$hiveName", $hiveFile)
            $entryPath = "Registry::HKEY_USERS\$hiveName\Software\Microsoft\Windows\CurrentVersion\Uninstall\DistControl"
        }
        if (Test-Path -LiteralPath $entryPath) { Remove-Item -LiteralPath $entryPath -Force }
    }
    finally {
        if ($hiveName) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            Invoke-ExternalOptional 'reg.exe' @('unload', "HKU\$hiveName") 'Cannot unload the target user registry hive'
        }
    }
}

function Remove-MachineInstallContext {
    if (-not (Test-Path -LiteralPath $MachineInstallContextRegistryPath)) {
        return
    }

    Write-Step "Remove machine uninstall context"
    if (-not $DryRun) {
        Remove-Item -LiteralPath $MachineInstallContextRegistryPath -Force
    }
}

function Get-MsiRelatedProductCodes {
    $codes = @()
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        foreach ($code in $installer.RelatedProducts($MsiUpgradeCode)) {
            if (-not [string]::IsNullOrWhiteSpace($code)) {
                $codes += [string]$code
            }
        }
    }
    catch {
        Write-Step "WARNING: cannot query Windows Installer products: $($_.Exception.Message)"
    }
    return $codes
}

function Remove-MsiRegistration {
    # The MSI package only carries the setup bootstrapper. When the client is removed
    # through Uninstall-DistControl.exe the MSI product stays registered, and a later
    # "msiexec /i" from GPO then only reconfigures it instead of installing the client.
    $codes = @(Get-MsiRelatedProductCodes)
    if ($codes.Count -eq 0) {
        Write-Step "No DistControl Client MSI registration found"
        return
    }
    foreach ($code in $codes) {
        $logPath = Join-Path $env:WINDIR ("Temp\DistControl-MSI-unregister-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        Write-Step "Remove DistControl Client MSI registration $code (log: $logPath)"
        if ($DryRun) { continue }
        $process = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList @("/x", $code, "/qn", "/norestart", "DISTCONTROLCLIENTREMOVED=1", "/l*v", "`"$logPath`"") `
            -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -in @(0, 1605, 3010)) {
            Write-Step "MSI registration $code removed (exit code $($process.ExitCode))"
        }
        else {
            Write-Step "WARNING: msiexec /x $code returned exit code $($process.ExitCode). Remove 'DistControl Client' in Programs and Features manually."
        }
    }
}

function Get-GpoInstallRunOnceIds {
    # Ids of the "Apply once" filters of DistControl install tasks from GPO preferences.
    # Group Policy keeps a copy of every applied preference in its history folder.
    $ids = New-Object System.Collections.Generic.List[string]
    $patterns = @(
        (Join-Path $env:ProgramData "Microsoft\Group Policy\History\*\$EffectiveTargetUserSid\Preferences\ScheduledTasks\ScheduledTasks.xml")
    )
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$EffectiveTargetUserSid"
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($profilePath) {
        $patterns += Join-Path ([Environment]::ExpandEnvironmentVariables($profilePath)) "AppData\Local\Microsoft\Group Policy\History\*\Preferences\ScheduledTasks\ScheduledTasks.xml"
    }
    foreach ($file in @(Get-ChildItem -Path $patterns -ErrorAction SilentlyContinue)) {
        try {
            [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($task in @($xml.SelectNodes("/ScheduledTasks/*"))) {
                if ([string]$task.GetAttribute("name") -notlike "DistControl*") { continue }
                foreach ($filter in @($task.SelectNodes("Filters/FilterRunOnce"))) {
                    $id = [string]$filter.GetAttribute("id")
                    if ($id -and -not $ids.Contains($id)) { $ids.Add($id) }
                }
            }
        }
        catch {
            Write-Step "WARNING: cannot read GPO preferences $($file.FullName): $($_.Exception.Message)"
        }
    }
    if (-not $ids.Contains($DefaultGpoInstallRunOnceId)) { $ids.Add($DefaultGpoInstallRunOnceId) }
    return $ids
}

function Reset-GpoInstallRunOnce {
    # The GPO install task runs once per user ("Apply once"). Clear that mark for the
    # removed user so the task installs the client again on the next policy refresh.
    # Only DistControl task marks are removed; marks of other policies are kept.
    $loadedHive = $null
    try {
        $ids = @(Get-GpoInstallRunOnceIds)
        $hiveRoot = "HKEY_USERS\$EffectiveTargetUserSid"
        if (-not (Test-Path -LiteralPath "Registry::$hiveRoot")) {
            $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$EffectiveTargetUserSid"
            $profilePath = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
            $ntuser = if ($profilePath) { Join-Path ([Environment]::ExpandEnvironmentVariables($profilePath)) "NTUSER.DAT" } else { $null }
            if (-not $ntuser -or -not (Test-Path -LiteralPath $ntuser)) {
                Write-Step "GPO install mark: user profile not found, nothing to reset"
                return
            }
            if ($DryRun) {
                Write-Step "GPO install mark: would load $ntuser to reset $($ids -join ', ')"
                return
            }
            $loadedHive = "HKU\DistControlUninstall_" + ($EffectiveTargetUserSid -replace '-', '_')
            & reg.exe load $loadedHive $ntuser | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $loadedHive = $null
                Write-Step "WARNING: cannot load $ntuser; GPO install mark was not reset"
                return
            }
            $hiveRoot = $loadedHive -replace '^HKU', 'HKEY_USERS'
        }

        $runOnceKey = "Registry::$hiveRoot\Software\Microsoft\Group Policy\Client\RunOnce"
        if (-not (Test-Path -LiteralPath $runOnceKey)) {
            Write-Step "GPO install mark: not set"
            return
        }
        $values = (Get-Item -LiteralPath $runOnceKey).GetValueNames()
        $found = $false
        foreach ($id in $ids) {
            if ($values -notcontains $id) { continue }
            $found = $true
            Write-Step "Reset GPO install mark $id"
            if (-not $DryRun) {
                Remove-ItemProperty -LiteralPath $runOnceKey -Name $id
            }
        }
        if (-not $found) {
            Write-Step "GPO install mark: not set"
        }
    }
    catch {
        Write-Step "WARNING: cannot reset GPO install mark: $($_.Exception.Message)"
    }
    finally {
        if ($loadedHive) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            & reg.exe unload $loadedHive | Out-Null
        }
    }
}

function Remove-ManagedHubRoutes {
    if (-not (Test-Path -LiteralPath $ManagedHubRoutesPath)) {
        return
    }

    Write-Step "Remove routes managed for DistKontrolUSB hubs"
    try {
        $manifest = Get-Content -LiteralPath $ManagedHubRoutesPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($route in @($manifest.routes)) {
            $destination = [string]$route.destination
            $gateway = [string]$route.gateway
            $interfaceIndex = [int]$route.interfaceIndex
            if ([string]::IsNullOrWhiteSpace($destination) -or
                [string]::IsNullOrWhiteSpace($gateway) -or
                $interfaceIndex -le 0) {
                continue
            }

            Write-Step "Remove managed route: $destination/32 via $gateway if $interfaceIndex"
            if (-not $DryRun) {
                $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$destination/32" -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -eq $gateway -and $_.ifIndex -eq $interfaceIndex })
                if ($existing.Count -gt 0) {
                    Invoke-ExternalOptional "route.exe" @(
                        "delete", $destination, "mask", "255.255.255.255", $gateway, "if", "$interfaceIndex"
                    ) "Cannot remove the managed route to DistKontrolUSB hub $destination"
                }
            }
        }
    }
    catch {
        Write-Step "WARNING: Cannot read or remove managed hub routes: $($_.Exception.Message)"
    }

    if (-not $DryRun) {
        Remove-Item -LiteralPath $ManagedHubRoutesPath -Force -ErrorAction SilentlyContinue
    }
}

function Stop-InstalledDkClientProcess([string]$ClientDirectory = $InstallDir) {
    $exePath = Join-Path $ClientDirectory "dkcl64.exe"
    if ($DryRun) {
        Write-Step "DRY-RUN: stop dkcl64.exe from $exePath"
        return
    }

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'dkcl64.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -and ([string]::Equals($_.ExecutablePath, $exePath, [StringComparison]::OrdinalIgnoreCase)) })
        if ($processes.Count -eq 0) {
            return
        }

        Write-Step "Stop dkcl64.exe processes from install directory, attempt $attempt, count=$($processes.Count)"
        foreach ($process in $processes) {
            Write-Step "Stop dkcl64.exe process $($process.ProcessId)"
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500
    }

    $remaining = @(Get-CimInstance Win32_Process -Filter "Name = 'dkcl64.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and ([string]::Equals($_.ExecutablePath, $exePath, [StringComparison]::OrdinalIgnoreCase)) })
    if ($remaining.Count -gt 0) {
        throw "dkcl64.exe is still running from $exePath after stop attempts. Remaining processes: $($remaining.Count)"
    }
}

if (-not $DryRun) {
    Start-UninstallLog
    Write-UninstallEnvironmentSummary
    Assert-Admin
    Enter-ClientLifecycleLock
}
else {
    Write-UninstallEnvironmentSummary
}

if ($EffectiveTargetUserSid -notmatch '^S-1-(\d+-)+\d+$') {
    throw "TargetUserSid has an invalid value: $EffectiveTargetUserSid"
}
foreach ($path in @($InstallDir, $ProgramDataDir, $UserStartMenuDir, $UserDesktopDir)) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [System.IO.Path]::IsPathRooted($path)) {
        throw "Uninstall path must be absolute: $path"
    }
}
Assert-ClientRemovalPaths $EffectiveTargetUserSid $InstallDir $ProgramDataDir $UserStartMenuDir $UserDesktopDir

$contexts = @(Get-RegisteredClientContexts)
$currentContext = @($contexts | Where-Object TargetUserSid -eq $EffectiveTargetUserSid | Select-Object -First 1)
if ($currentContext.Count -gt 0 -and -not [string]::Equals(
    [IO.Path]::GetFullPath($currentContext[0].InstallDir).TrimEnd('\'),
    [IO.Path]::GetFullPath($InstallDir).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The uninstaller directory does not match the registered client owner.'
}
$otherClients = @($contexts | Where-Object TargetUserSid -ne $EffectiveTargetUserSid)
$removeSharedRuntime = $otherClients.Count -eq 0
$servicesToRemove = @($AgentServiceName)
if ($removeSharedRuntime) { $servicesToRemove += $ServiceName }
# Compatibility: only remove the old agent if its binary belongs to this client.
$legacyAgent = Get-CimInstance Win32_Service -Filter "Name = 'DistControlAgent'" -ErrorAction SilentlyContinue
if ($legacyAgent -and $legacyAgent.PathName -like ('*' + $InstallDir + '\DistControl.Agent.exe*')) {
    $servicesToRemove += 'DistControlAgent'
}

foreach ($serviceToRemove in $servicesToRemove) {
    $service = Get-Service -Name $serviceToRemove -ErrorAction SilentlyContinue
    if (-not $service) { continue }
    Write-Step "Stop service $serviceToRemove"
    if (-not $DryRun -and $service.Status -ne "Stopped") {
        Stop-Service -Name $serviceToRemove -Force -ErrorAction SilentlyContinue
        try {
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(20))
        }
        catch {
            Write-Step "WARNING: service $ServiceName did not report Stopped in time; continuing with process cleanup."
        }
    }
    Write-Step "Delete service $serviceToRemove"
    $service.Dispose()
    Invoke-External "sc.exe" @("delete", $serviceToRemove)
    Start-Sleep -Milliseconds 500
}

$interactiveTask = if ($removeSharedRuntime) { Get-ScheduledTask -TaskName $InteractiveDkClientTaskName -ErrorAction SilentlyContinue } else { $null }
if ($interactiveTask) {
    Write-Step "Remove scheduled task $InteractiveDkClientTaskName"
    if (-not $DryRun) {
        Stop-ScheduledTask -TaskName $InteractiveDkClientTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $InteractiveDkClientTaskName -Confirm:$false
    }
}

# Stop only applications from this user's installation, including an open UI.
if (-not $DryRun) {
    $root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        if ($process.Name -in @('DistControl.exe', 'DistControl.Admin.exe', 'DistControl.Agent.exe', 'dkcl64.exe') -and
            $process.ExecutablePath -and $process.ExecutablePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($removeSharedRuntime) {
    Stop-InstalledDkClientProcess
    Stop-InstalledDkClientProcess $SharedRuntimeDirectory
    # The shared backend no longer has any consumers.
    $ManagedHubRoutesPath = Join-Path $SharedRuntimeStateDirectory 'managed-hub-routes.json'
    Remove-ManagedHubRoutes
    $ManagedHubRoutesPath = Join-Path $ProgramDataDir 'managed-hub-routes.json'
    Remove-ManagedHubRoutes
}

Remove-PathSafe $ClientStartupShortcut

Remove-PathSafe $UserStartMenuDir
Remove-PathSafe (Join-Path $UserDesktopDir "DistControl.lnk")

Remove-PathSafe $InstallDir

if ($RemoveData) {
    Remove-PathSafe $ProgramDataDir
}
else {
    Write-Step "Keep data directory $ProgramDataDir"
}

if ($removeSharedRuntime) {
    Remove-PathSafe $SharedRuntimeDirectory
    Remove-PathSafe $SharedRuntimeStateDirectory
}
Remove-UninstallEntry
Remove-MachineInstallContext
if ((Test-Path -LiteralPath $LegacyClientContextRegistryPath) -and
    (Get-ItemProperty -LiteralPath $LegacyClientContextRegistryPath).TargetUserSid -eq $EffectiveTargetUserSid) {
    if (-not $DryRun) { Remove-Item -LiteralPath $LegacyClientContextRegistryPath -Force }
}

if ($SkipMsiUnregister -or -not $removeSharedRuntime) {
    Write-Step "Skip MSI unregistration (called from MSI uninstall)"
}
else {
    Remove-MsiRegistration
}

Reset-GpoInstallRunOnce

Write-Step "Uninstall completed"
Exit-ClientLifecycleLock
