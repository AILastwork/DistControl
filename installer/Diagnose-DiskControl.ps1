#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "DiskControl"),
    [string]$ProgramDataDir = (Join-Path $env:ProgramData "DiskControl"),
    [string]$ServiceName = "dkclient"
)

$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ReleaseDir = Join-Path $Root "build\x64\Release"
$PolicyPath = Join-Path $ProgramDataDir "allow.json"
$LogsDir = Join-Path $ProgramDataDir "logs"
$ClientStartupShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\DiskControl dkclient.lnk"

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title =="
}

function Write-Check([string]$Name, [bool]$Ok, [string]$Details = "") {
    $state = if ($Ok) { "OK" } else { "WARN" }
    if ($Details) {
        Write-Host ("[{0}] {1}: {2}" -f $state, $Name, $Details)
    }
    else {
        Write-Host ("[{0}] {1}" -f $state, $Name)
    }
}

Write-Host "DiskControl diagnostics"
Write-Host ("Time: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Host ("User: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host ("Computer: {0}" -f $env:COMPUTERNAME)
Write-Host ("OS: {0}" -f ([Environment]::OSVersion.VersionString))
Write-Host ("64-bit OS: {0}" -f [Environment]::Is64BitOperatingSystem)
Write-Host ("64-bit process: {0}" -f [Environment]::Is64BitProcess)

Write-Section "Files"
$candidateDirs = @($InstallDir, $ReleaseDir, $Root) | Select-Object -Unique
foreach ($dir in $candidateDirs) {
    if (-not (Test-Path -LiteralPath $dir)) {
        Write-Check "Directory" $false $dir
        continue
    }

    Write-Check "Directory" $true $dir
    foreach ($name in @("DiskControl.exe", "DiskControl.Admin.exe", "dkcl64.exe", "dkcl.ini")) {
        $path = Join-Path $dir $name
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path
            Write-Check $name $true ("{0} bytes, {1}" -f $item.Length, $item.LastWriteTime)
        }
        else {
            Write-Check $name $false "not found here"
        }
    }
}

Write-Section "Policy"
if (Test-Path -LiteralPath $PolicyPath) {
    $policyItem = Get-Item -LiteralPath $PolicyPath
    Write-Check "allow.json exists" $true ("{0} bytes, {1}" -f $policyItem.Length, $PolicyPath)
    try {
        $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $assignments = @($policy.userAssignments).Count
        Write-Check "allow.json parses" $true ("userAssignments={0}, pipeName={1}" -f $assignments, $policy.pipeName)
    }
    catch {
        Write-Check "allow.json parses" $false $_.Exception.Message
    }
}
else {
    Write-Check "allow.json exists" $false $PolicyPath
}

Write-Section "Service and pipe"
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$startupExists = Test-Path -LiteralPath $ClientStartupShortcut
if ($service) {
    Write-Check "service $ServiceName" $true ("Status={0}, StartType={1}" -f $service.Status, $service.StartType)
    try {
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $serviceConfig = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
        Write-Check "service account" $true $serviceConfig.ObjectName
        Write-Check "service image" $true $serviceConfig.ImagePath
    }
    catch {
        Write-Check "service registry details" $false $_.Exception.Message
    }
}
else {
    Write-Check "service $ServiceName" $false "not installed"
}

$pipePath = "\\.\pipe\$ServiceName"
Write-Check "pipe $pipePath" (Test-Path $pipePath) "Test-Path result"

Write-Section "Client process"
Write-Check "unexpected user startup shortcut" (-not $startupExists) $ClientStartupShortcut
Get-CimInstance Win32_Process -Filter "Name = 'dkcl64.exe'" -ErrorAction SilentlyContinue |
    Select-Object ProcessId, ExecutablePath, CommandLine |
    Format-List

Write-Section "Logs"
if (Test-Path -LiteralPath $LogsDir) {
    Write-Check "logs directory" $true $LogsDir
    Get-ChildItem -LiteralPath $LogsDir -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 8 FullName, Length, LastWriteTime |
        Format-Table -AutoSize
}
else {
    Write-Check "logs directory" $false $LogsDir
}

Write-Section "Notes"
Write-Host "If DiskControl.Admin.exe closes immediately, send the newest startup-YYYYMMDD.log from the logs directory."
Write-Host "If there is no startup log at all, the app may be blocked by antivirus/AppLocker or launched from an old package."
