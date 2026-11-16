#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$SetupOutputPath
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root "dist\DistControl-Server.zip"
}
if ([string]::IsNullOrWhiteSpace($SetupOutputPath)) {
    $SetupOutputPath = Join-Path $root "dist\DistControl-Server-Setup.exe"
}
& (Join-Path $root "tools\Build-CentralComponents.ps1")
if ($LASTEXITCODE -ne 0) { throw "Central components build failed." }

$stage = Join-Path $env:TEMP ("DistControl-server-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $stage "bin") -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $root "build\central\DistControl.Server.exe") -Destination (Join-Path $stage "bin\DistControl.Server.exe")
    Copy-Item -LiteralPath (Join-Path $root "build\central\DistControl.CentralAdmin.exe") -Destination (Join-Path $stage "bin\DistControl.CentralAdmin.exe")
    Copy-Item -LiteralPath (Join-Path $root "build\x64\Release\DistControl.Admin.exe") -Destination (Join-Path $stage "bin\DistControl.Admin.exe")
    foreach ($name in @("Install-DistControlServer.ps1", "Uninstall-DistControlServer.ps1", "README.md")) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $OutputPath -Force
    Write-Host "Server package: $OutputPath"
    Write-Host "SHA256: $((Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash)"

    $compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    $setupSource = Join-Path $PSScriptRoot "ServerSetupBootstrapper.cs"
    $setupManifest = Join-Path $PSScriptRoot "ServerSetupBootstrapper.manifest"
    $setupStub = Join-Path $stage "DistControl-Server-Setup.stub.exe"
    & $compiler /nologo /codepage:65001 /target:winexe /platform:x64 `
        "/win32manifest:$setupManifest" `
        "/out:$setupStub" `
        /reference:System.Windows.Forms.dll `
        /reference:System.Drawing.dll `
        /reference:System.ServiceProcess.dll `
        /reference:System.Security.dll `
        /reference:System.IO.Compression.dll `
        /reference:System.IO.Compression.FileSystem.dll `
        $setupSource
    if ($LASTEXITCODE -ne 0) { throw "Server setup executable build failed." }

    New-Item -ItemType Directory -Path (Split-Path -Parent $SetupOutputPath) -Force | Out-Null
    if (Test-Path -LiteralPath $SetupOutputPath) { Remove-Item -LiteralPath $SetupOutputPath -Force }
    $output = [System.IO.File]::Open($SetupOutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try {
        foreach ($inputPath in @($setupStub, $OutputPath)) {
            $input = [System.IO.File]::OpenRead($inputPath)
            try { $input.CopyTo($output) } finally { $input.Dispose() }
        }
        $lengthBytes = [BitConverter]::GetBytes([Int64](Get-Item -LiteralPath $OutputPath).Length)
        $markerBytes = [Text.Encoding]::ASCII.GetBytes("DCSRV001")
        $output.Write($lengthBytes, 0, $lengthBytes.Length)
        $output.Write($markerBytes, 0, $markerBytes.Length)
    }
    finally {
        $output.Dispose()
    }
    Write-Host "Server setup executable: $SetupOutputPath"
    Write-Host "SHA256: $((Get-FileHash -LiteralPath $SetupOutputPath -Algorithm SHA256).Hash)"
}
finally {
    if ([IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
}
