#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "DiskControl"),
    [string]$ProgramDataDir = (Join-Path $env:ProgramData "DiskControl"),
    [string]$ServiceName = "dkclient",
    [switch]$RemoveData,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
try {
    $script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $script:Utf8NoBomEncoding
    $OutputEncoding = $script:Utf8NoBomEncoding
}
catch {
}
$UninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskControl"
$ClientStartupShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\DiskControl dkclient.lnk"
$LogsDir = Join-Path $ProgramDataDir "logs"
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
    Write-Host "[DiskControl] $Message"
    Write-UninstallLogLine "[DiskControl] $Message"
}

function Start-UninstallLog {
    if ($DryRun) {
        return
    }

    try {
        $root = if ($RemoveData) { Join-Path ([System.IO.Path]::GetTempPath()) "DiskControl-logs" } else { $LogsDir }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $script:UninstallLogPath = Join-Path $root ("uninstall-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        [System.IO.File]::WriteAllText($script:UninstallLogPath, "", $script:Utf8NoBomEncoding)
        Write-Step "Uninstall log: $script:UninstallLogPath"
    }
    catch {
        Write-Host "[DiskControl] WARNING: Cannot start uninstall log: $($_.Exception.Message)"
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
        return "Процесс dkcl64.exe продолжает работать. Закройте DiskControl, остановите службу dkclient или перезагрузите компьютер."
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
    Write-Host "[DiskControl] USER-ERROR: $human"
    Write-Host "[DiskControl] ERROR: $message"
    Write-UninstallLogLine "[DiskControl] USER-ERROR: $human"
    Write-UninstallLogLine "[DiskControl] ERROR: $message"
    if ($Record -and $Record.Exception) {
        Write-UninstallLogLine "[DiskControl] ERROR TYPE: $($Record.Exception.GetType().FullName)"
    }
    if ($Record -and $Record.InvocationInfo) {
        Write-UninstallLogLine "[DiskControl] ERROR SCRIPT: $($Record.InvocationInfo.ScriptName)"
        Write-UninstallLogLine "[DiskControl] ERROR LINE: $($Record.InvocationInfo.ScriptLineNumber)"
        Write-UninstallLogLine "[DiskControl] ERROR COMMAND: $($Record.InvocationInfo.Line)"
    }
    if ($Record -and $Record.ScriptStackTrace) {
        Write-UninstallLogLine "[DiskControl] ERROR STACK: $($Record.ScriptStackTrace)"
    }
}

function Write-UninstallEnvironmentSummary {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $identity = "<unknown>"
    }
    Write-Step "Environment: computer=$env:COMPUTERNAME; processUser=$identity; installDir=$InstallDir; programDataDir=$ProgramDataDir; service=$ServiceName; removeData=$RemoveData"
}

trap {
    Write-UninstallErrorDetails $_
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
        Repair-RemovalAcl $Path
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Remove-UninstallEntry {
    if (-not (Test-Path -LiteralPath $UninstallRegistryPath)) {
        return
    }

    Write-Step "Remove Windows uninstall entry"
    if (-not $DryRun) {
        Remove-Item -LiteralPath $UninstallRegistryPath -Force
    }
}

function Stop-InstalledDkClientProcess {
    $exePath = Join-Path $InstallDir "dkcl64.exe"
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
}
else {
    Write-UninstallEnvironmentSummary
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Step "Stop service $ServiceName"
    if (-not $DryRun -and $service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        try {
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(20))
        }
        catch {
            Write-Step "WARNING: service $ServiceName did not report Stopped in time; continuing with process cleanup."
        }
    }
    Write-Step "Delete service $ServiceName"
    Invoke-External "sc.exe" @("delete", $ServiceName)
    Start-Sleep -Milliseconds 500
}

Stop-InstalledDkClientProcess

Remove-PathSafe $ClientStartupShortcut

$startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\DiskControl"
Remove-PathSafe $startMenu

$publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
Remove-PathSafe (Join-Path $publicDesktop "DiskControl.lnk")

Remove-UninstallEntry
Stop-InstalledDkClientProcess
Remove-PathSafe $InstallDir

if ($RemoveData) {
    Remove-PathSafe $ProgramDataDir
}
else {
    Write-Step "Keep data directory $ProgramDataDir"
}

Write-Step "Uninstall completed"
