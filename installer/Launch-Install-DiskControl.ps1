#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$NoStartService,
    [switch]$NoDesktopShortcut,
    [string]$UsageStateDir = $env:DISKCONTROL_USAGE_STATE_DIR
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

$installParams = @{
    SkipBuild = $true
}
$installArgs = @("-SkipBuild")
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
