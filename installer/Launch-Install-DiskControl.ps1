#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$NoStartService,
    [switch]$NoDesktopShortcut,
    [string]$UsageStateDir = $env:DISKCONTROL_USAGE_STATE_DIR,
    [string]$ServiceAccount = $env:DISKCONTROL_SERVICE_ACCOUNT,
    [string]$TargetUserSid = $env:DISTCONTROL_TARGET_USER_SID,
    [string]$TargetProfileDir = $env:DISTCONTROL_TARGET_PROFILE_DIR,
    [string]$InstallDir = $env:DISTCONTROL_INSTALL_DIR,
    [string]$ProgramDataDir = $env:DISTCONTROL_DATA_DIR,
    [string]$TargetRoamingAppDataDir = $env:DISTCONTROL_ROAMING_APPDATA_DIR,
    [string]$UserStartMenuDir = $env:DISTCONTROL_START_MENU_DIR,
    [string]$UserDesktopDir = $env:DISTCONTROL_DESKTOP_DIR
)

$ErrorActionPreference = "Stop"
$InstallScript = Join-Path $PSScriptRoot "Install-DiskControl.ps1"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-Argument([string]$Value) {
    '"' + ($Value -replace '"', '\"') + '"'
}

if (-not (Test-Path -LiteralPath $InstallScript)) {
    throw "Install script not found: $InstallScript"
}

if ([string]::IsNullOrWhiteSpace($TargetUserSid)) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $TargetUserSid = $identity.User.Value
    if ([string]::IsNullOrWhiteSpace($ServiceAccount)) {
        $ServiceAccount = $identity.Name
    }
}
if ([string]::IsNullOrWhiteSpace($ServiceAccount)) {
    $sid = New-Object Security.Principal.SecurityIdentifier($TargetUserSid)
    $ServiceAccount = $sid.Translate([Security.Principal.NTAccount]).Value
}
if ([string]::IsNullOrWhiteSpace($TargetProfileDir)) {
    $TargetProfileDir = $env:USERPROFILE
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $TargetProfileDir "AppData\Local\Programs\DistControl"
}
if ([string]::IsNullOrWhiteSpace($ProgramDataDir)) {
    $ProgramDataDir = Join-Path $TargetProfileDir "AppData\Local\DistControl"
}
if ([string]::IsNullOrWhiteSpace($TargetRoamingAppDataDir)) {
    $TargetRoamingAppDataDir = Join-Path $TargetProfileDir "AppData\Roaming"
}
if ([string]::IsNullOrWhiteSpace($UserStartMenuDir)) {
    $UserStartMenuDir = Join-Path $TargetRoamingAppDataDir "Microsoft\Windows\Start Menu\Programs\DistControl"
}
if ([string]::IsNullOrWhiteSpace($UserDesktopDir)) {
    $UserDesktopDir = Join-Path $TargetProfileDir "Desktop"
}

$installParams = @{
    SkipBuild = $true
    ServiceAccount = $ServiceAccount
    TargetUserSid = $TargetUserSid
    TargetProfileDir = $TargetProfileDir
    InstallDir = $InstallDir
    ProgramDataDir = $ProgramDataDir
    TargetRoamingAppDataDir = $TargetRoamingAppDataDir
    UserStartMenuDir = $UserStartMenuDir
    UserDesktopDir = $UserDesktopDir
}
$installArgs = @(
    "-SkipBuild",
    "-ServiceAccount", (Quote-Argument $ServiceAccount),
    "-TargetUserSid", (Quote-Argument $TargetUserSid),
    "-TargetProfileDir", (Quote-Argument $TargetProfileDir),
    "-InstallDir", (Quote-Argument $InstallDir),
    "-ProgramDataDir", (Quote-Argument $ProgramDataDir),
    "-TargetRoamingAppDataDir", (Quote-Argument $TargetRoamingAppDataDir),
    "-UserStartMenuDir", (Quote-Argument $UserStartMenuDir),
    "-UserDesktopDir", (Quote-Argument $UserDesktopDir)
)
if ($NoStartService) {
    $installParams.NoStartService = $true
    $installArgs += "-NoStartService"
}
if ($NoDesktopShortcut) {
    $installParams.NoDesktopShortcut = $true
    $installArgs += "-NoDesktopShortcut"
}
if (-not [string]::IsNullOrWhiteSpace($UsageStateDir)) {
    $installParams.UsageStateDir = $UsageStateDir
    $installArgs += @("-UsageStateDir", (Quote-Argument $UsageStateDir))
}

if (Test-Admin) {
    & $InstallScript @installParams
    if ($?) {
        exit 0
    }
    exit 1
}

$powerShellArgs = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-WindowStyle",
    "Hidden",
    "-File",
    (Quote-Argument $InstallScript)
) + $installArgs

$process = Start-Process -FilePath "powershell.exe" -ArgumentList ($powerShellArgs -join " ") -Verb RunAs -WindowStyle Hidden -Wait -PassThru
exit $process.ExitCode
