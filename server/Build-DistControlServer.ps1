#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot "bin"
}
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$source = Join-Path $root "src\DistControl.Server"
$compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $compiler)) {
    throw "C# compiler not found: $compiler"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = Join-Path $OutputDirectory "DistControl.Server.exe"
& $compiler /nologo /codepage:65001 /target:exe /platform:x64 `
    "/out:$output" `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    (Join-Path $source "Models.cs") `
    (Join-Path $source "ServerStore.cs") `
    (Join-Path $source "ServerHost.cs") `
    (Join-Path $source "Program.cs")
if ($LASTEXITCODE -ne 0) { throw "DistControl.Server build failed." }
Write-Host "Server: $output"
