#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dist = Join-Path $root "dist"
$payload = Join-Path $dist "DistControl-Installer.zip"
$output = Join-Path $dist "DistControl-SystemService-Test-Setup.exe"
$stub = Join-Path $dist "DistControl-SystemService-Test-Setup.stub.exe"
$legacyOutput = Join-Path $dist "DistControl-Interactive-Test-Setup.exe"
$source = Join-Path $PSScriptRoot "SetupBootstrapper.cs"
$credentialCheck = Join-Path $PSScriptRoot "CredentialCheck.cs"
$manifest = Join-Path $PSScriptRoot "SetupBootstrapper.manifest"
$marker = [Text.Encoding]::ASCII.GetBytes("DKSETUP1")

& (Join-Path $PSScriptRoot "Build-InstallerPackage.ps1") -SkipBuild:$SkipBuild
if ($LASTEXITCODE -ne 0) {
    throw "Base installer payload build failed."
}

$compiler = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) {
    throw "C# compiler was not found."
}

Remove-Item -LiteralPath $stub, $output, $legacyOutput -Force -ErrorAction SilentlyContinue
& $compiler /nologo /codepage:65001 /target:winexe /platform:x64 `
    /define:SYSTEM_DKCLIENT_TEST `
    "/win32manifest:$manifest" "/out:$stub" `
    /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    /reference:System.Security.dll /reference:System.IO.Compression.dll `
    /reference:System.IO.Compression.FileSystem.dll `
    $source (Join-Path $PSScriptRoot "SetupDefaults.cs") $credentialCheck
if ($LASTEXITCODE -ne 0) {
    throw "System-service test bootstrapper build failed."
}

$payloadInfo = Get-Item -LiteralPath $payload
$target = [IO.File]::Open($output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try {
    foreach ($path in @($stub, $payload)) {
        $input = [IO.File]::OpenRead($path)
        try { $input.CopyTo($target) } finally { $input.Dispose() }
    }
    $length = [BitConverter]::GetBytes([Int64]$payloadInfo.Length)
    $target.Write($length, 0, $length.Length)
    $target.Write($marker, 0, $marker.Length)
}
finally {
    $target.Dispose()
    Remove-Item -LiteralPath $stub -Force -ErrorAction SilentlyContinue
}

$hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
Write-Host "System-service test setup: $output"
Write-Host "SHA256: $hash"
