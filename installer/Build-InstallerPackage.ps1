#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipSetupExe,
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [string]$CertificatePassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ReleaseDir = Join-Path $Root "build\x64\Release"
$DistDir = Join-Path $Root "dist"
$StageDir = Join-Path $DistDir "DiskControl-Installer"
$ZipPath = Join-Path $DistDir "DiskControl-Installer.zip"
$SetupExePath = Join-Path $DistDir "DiskControl-Setup.exe"
$SetupStubPath = Join-Path $DistDir "DiskControl-Setup.stub.exe"
$SetupSourcePath = Join-Path $PSScriptRoot "SetupBootstrapper.cs"
$SetupManifestPath = Join-Path $PSScriptRoot "SetupBootstrapper.manifest"
$UninstallExePath = Join-Path $DistDir "Uninstall-DiskControl.exe"
$UninstallSourcePath = Join-Path $PSScriptRoot "UninstallBootstrapper.cs"
$UninstallManifestPath = Join-Path $PSScriptRoot "UninstallBootstrapper.manifest"
$SignScriptPath = Join-Path $PSScriptRoot "Sign-DiskControl.ps1"
$PayloadMarker = "DKSETUP1"

function Copy-IntoStage([string]$RelativePath) {
    $source = Join-Path $Root $RelativePath
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing package input: $source"
    }

    $destination = Join-Path $StageDir $RelativePath
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

function Copy-IntoStageAs([string]$Source, [string]$RelativeDestination) {
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Missing package input: $Source"
    }

    $destination = Join-Path $StageDir $RelativeDestination
    $parent = Split-Path -Parent $destination
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $Source -Destination $destination -Force
}

function Get-CSharpCompiler {
    $candidates = @(
        (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "C# compiler was not found. Cannot build DiskControl-Setup.exe."
}

function Add-FileToStream([System.IO.Stream]$Output, [string]$Path) {
    $input = [System.IO.File]::OpenRead($Path)
    try {
        $input.CopyTo($Output)
    }
    finally {
        $input.Dispose()
    }
}

function Build-SetupExe {
    if ($SkipSetupExe) {
        return
    }

    if (-not (Test-Path -LiteralPath $SetupSourcePath)) {
        throw "Missing setup bootstrapper source: $SetupSourcePath"
    }
    if (-not (Test-Path -LiteralPath $SetupManifestPath)) {
        throw "Missing setup bootstrapper manifest: $SetupManifestPath"
    }

    $csc = Get-CSharpCompiler
    $setupOutputPath = $SetupExePath
    if (Test-Path -LiteralPath $SetupStubPath) {
        Remove-Item -LiteralPath $SetupStubPath -Force
    }
    if (Test-Path -LiteralPath $SetupExePath) {
        try {
            Remove-Item -LiteralPath $SetupExePath -Force
        }
        catch {
            $setupOutputPath = Join-Path $DistDir ("DiskControl-Setup-{0}.exe" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
            Write-Warning "Cannot replace $SetupExePath. It may still be running. Building $setupOutputPath instead."
        }
    }

    & $csc `
        /nologo `
        /codepage:65001 `
        /target:winexe `
        /platform:x64 `
        "/win32manifest:$SetupManifestPath" `
        "/out:$SetupStubPath" `
        /reference:System.Windows.Forms.dll `
        /reference:System.Drawing.dll `
        /reference:System.IO.Compression.dll `
        /reference:System.IO.Compression.FileSystem.dll `
        $SetupSourcePath

    if ($LASTEXITCODE -ne 0) {
        throw "Setup bootstrapper build failed."
    }

    $zipInfo = Get-Item -LiteralPath $ZipPath
    $output = [System.IO.File]::Open($setupOutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try {
        Add-FileToStream $output $SetupStubPath
        Add-FileToStream $output $ZipPath
        $lengthBytes = [BitConverter]::GetBytes([Int64]$zipInfo.Length)
        $markerBytes = [Text.Encoding]::ASCII.GetBytes($PayloadMarker)
        $output.Write($lengthBytes, 0, $lengthBytes.Length)
        $output.Write($markerBytes, 0, $markerBytes.Length)
    }
    finally {
        $output.Dispose()
    }

    Remove-Item -LiteralPath $SetupStubPath -Force
    Write-Host "Setup executable: $setupOutputPath"
    return $setupOutputPath
}

function Build-UninstallExe {
    if (-not (Test-Path -LiteralPath $UninstallSourcePath)) {
        throw "Missing uninstall bootstrapper source: $UninstallSourcePath"
    }
    if (-not (Test-Path -LiteralPath $UninstallManifestPath)) {
        throw "Missing uninstall bootstrapper manifest: $UninstallManifestPath"
    }

    $csc = Get-CSharpCompiler
    if (Test-Path -LiteralPath $UninstallExePath) {
        Remove-Item -LiteralPath $UninstallExePath -Force
    }

    & $csc `
        /nologo `
        /codepage:65001 `
        /target:winexe `
        /platform:x64 `
        "/win32manifest:$UninstallManifestPath" `
        "/out:$UninstallExePath" `
        /reference:System.Windows.Forms.dll `
        $UninstallSourcePath

    if ($LASTEXITCODE -ne 0) {
        throw "Uninstall bootstrapper build failed."
    }

    Write-Host "Uninstall executable: $UninstallExePath"
}

function Invoke-CodeSigning([string[]]$Files) {
    if (-not $CertificateThumbprint -and -not $CertificatePath) {
        Write-Host "Signing skipped: no certificate was provided."
        return
    }

    if (-not (Test-Path -LiteralPath $SignScriptPath)) {
        throw "Missing signing script: $SignScriptPath"
    }

    $args = @("-File", $SignScriptPath, "-TimestampUrl", $TimestampUrl, "-Files") + $Files
    if ($CertificateThumbprint) {
        $args += @("-CertificateThumbprint", $CertificateThumbprint)
    }
    if ($CertificatePath) {
        $args += @("-CertificatePath", $CertificatePath)
    }
    if ($CertificatePassword) {
        $args += @("-CertificatePassword", $CertificatePassword)
    }

    powershell.exe -NoProfile -ExecutionPolicy Bypass @args
    if ($LASTEXITCODE -ne 0) {
        throw "Code signing failed."
    }
}

if (-not $SkipBuild) {
    & (Join-Path $Root "build-vs.cmd") Release
    if ($LASTEXITCODE -ne 0) {
        throw "Release build failed."
    }
}

Invoke-CodeSigning -Files @(
    (Join-Path $ReleaseDir "DiskControl.exe"),
    (Join-Path $ReleaseDir "DiskControl.Admin.exe")
)

Build-UninstallExe
Invoke-CodeSigning -Files @($UninstallExePath)

if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

foreach ($relative in @(
    "install.cmd",
    "uninstall.cmd",
    "installer\Install-DiskControl.ps1",
    "installer\Uninstall-DiskControl.ps1",
    "installer\Launch-Install-DiskControl.ps1",
    "installer\Launch-Uninstall-DiskControl.ps1",
    "installer\Sign-DiskControl.ps1",
    "README.md",
    "DiskControl-guide.html",
    "dkcl64.exe",
    "dkcl.ini",
    "allowlist.example.json"
)) {
    Copy-IntoStage $relative
}

Copy-IntoStageAs $UninstallExePath "Uninstall-DiskControl.exe"

foreach ($relative in @(
    "build\x64\Release\DiskControl.exe",
    "build\x64\Release\DiskControl.Admin.exe"
)) {
    Copy-IntoStage $relative
}

if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -Force

Write-Host "Installer package: $ZipPath"
$builtSetupPath = Build-SetupExe
if ($builtSetupPath -and (Test-Path -LiteralPath $builtSetupPath)) {
    Invoke-CodeSigning -Files @($builtSetupPath)
}
