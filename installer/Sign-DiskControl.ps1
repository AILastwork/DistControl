#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [string]$CertificatePassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string[]]$Files
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Get-SignTool {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "signtool.exe was not found. Install Windows SDK or Visual Studio Build Tools."
}

function Resolve-DefaultFiles {
    @(
        (Join-Path $Root "build\x64\Release\DiskControl.exe"),
        (Join-Path $Root "build\x64\Release\DiskControl.Admin.exe"),
        (Join-Path $Root "dist\DiskControl-Setup.exe")
    ) | Where-Object { Test-Path -LiteralPath $_ }
}

if (-not $CertificateThumbprint -and -not $CertificatePath) {
    throw "Provide -CertificateThumbprint or -CertificatePath. SmartScreen cannot be fixed without code signing."
}

if (-not $Files -or $Files.Count -eq 0) {
    $Files = Resolve-DefaultFiles
}

if (-not $Files -or $Files.Count -eq 0) {
    throw "No files to sign."
}

$signTool = Get-SignTool

foreach ($file in $Files) {
    $resolved = (Resolve-Path -LiteralPath $file).Path
    $args = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")

    if ($CertificatePath) {
        $args += @("/f", $CertificatePath)
        if ($CertificatePassword) {
            $args += @("/p", $CertificatePassword)
        }
    }
    else {
        $args += @("/sha1", $CertificateThumbprint)
    }

    $args += $resolved
    Write-Host "[DiskControl] Signing $resolved"
    & $signTool @args
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[DiskControl] Signing completed"
