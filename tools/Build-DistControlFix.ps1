#Requires -Version 5.1
# Builds dist\DistControlFix.exe: a small window around tools\Switch-DistControlUser.ps1.
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "dist\DistControlFix.exe")
)

$ErrorActionPreference = "Stop"
$sourceDir = Join-Path $PSScriptRoot "DistControlFix"
$script = Join-Path $PSScriptRoot "Switch-DistControlUser.ps1"
$csc = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $csc) { throw "C# compiler (.NET Framework 4) not found." }

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
& $csc /nologo /codepage:65001 /target:winexe /platform:anycpu `
    "/win32manifest:$(Join-Path $sourceDir 'DistControlFix.manifest')" `
    "/resource:$script,Switch-DistControlUser.ps1" `
    "/out:$OutputPath" `
    /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    (Join-Path $sourceDir "DistControlFix.cs")
if ($LASTEXITCODE -ne 0) { throw "DistControlFix build failed." }
Write-Host "Built: $OutputPath"
