#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir,
    [Alias("DataDir")]
    [string]$ProgramDataDir,
    [string]$TargetUserSid,
    [string]$UserStartMenuDir,
    [string]$UserDesktopDir,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$UninstallScript = Join-Path $PSScriptRoot "Uninstall-DiskControl.ps1"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-Argument([string]$Value) {
    '"' + ($Value -replace '"', '\"') + '"'
}

if (-not (Test-Path -LiteralPath $UninstallScript)) {
    throw "Uninstall script not found: $UninstallScript"
}

$uninstallParams = @{}
$uninstallArgs = @()
foreach ($entry in @(
    @{ Name = "InstallDir"; Value = $InstallDir },
    @{ Name = "ProgramDataDir"; Value = $ProgramDataDir },
    @{ Name = "TargetUserSid"; Value = $TargetUserSid },
    @{ Name = "UserStartMenuDir"; Value = $UserStartMenuDir },
    @{ Name = "UserDesktopDir"; Value = $UserDesktopDir }
)) {
    if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
        $uninstallParams[$entry.Name] = $entry.Value
        $uninstallArgs += "-$($entry.Name)"
        $uninstallArgs += (Quote-Argument $entry.Value)
    }
}
if ($RemoveData) {
    $uninstallParams.RemoveData = $true
    $uninstallArgs += "-RemoveData"
}

if (Test-Admin) {
    & $UninstallScript @uninstallParams
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
    (Quote-Argument $UninstallScript)
) + $uninstallArgs

$process = Start-Process -FilePath "powershell.exe" -ArgumentList ($powerShellArgs -join " ") -Verb RunAs -WindowStyle Hidden -Wait -PassThru
exit $process.ExitCode
