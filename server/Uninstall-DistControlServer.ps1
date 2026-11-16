#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDirectory = "$env:ProgramFiles\DistControl Server",
    [string]$DataDirectory = "$env:ProgramData\DistControlServer",
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$serviceName = "DistControlServer"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Milliseconds 700
}
Get-NetFirewallRule -DisplayName "DistControl Server" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $InstallDirectory) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
}
if ($RemoveData -and (Test-Path -LiteralPath $DataDirectory)) {
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force
}
Write-Host "DistControl Server удалён."
if (-not $RemoveData) { Write-Host "Данные сохранены: $DataDirectory" }
