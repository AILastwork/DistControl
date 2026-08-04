#Requires -Version 5.1
[CmdletBinding()]
param(
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
