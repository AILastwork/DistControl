#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$release = Join-Path $root "build\x64\Release"
$central = Join-Path $root "build\central"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root ("dist\DistControl-Update-{0}.zip" -f $Version)
}

& (Join-Path $PSScriptRoot "Build-CentralComponents.ps1")
if ($LASTEXITCODE -ne 0) { throw "Central components build failed." }

$files = @(
    @{ Source = (Join-Path $release "DistControl.exe"); Target = "DistControl.exe" },
    @{ Source = (Join-Path $release "DistControl.Admin.exe"); Target = "DistControl.Admin.exe" },
    @{ Source = (Join-Path $central "DistControl.Agent.exe"); Target = "DistControl.Agent.exe" },
    @{ Source = (Join-Path $central "DistControl.Updater.exe"); Target = "DistControl.Updater.exe" }
)
$stage = Join-Path $env:TEMP ("DistControl-update-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    $manifestFiles = @()
    foreach ($file in $files) {
        if (-not (Test-Path -LiteralPath $file.Source)) { throw "Missing update input: $($file.Source)" }
        $target = Join-Path $stage $file.Target
        Copy-Item -LiteralPath $file.Source -Destination $target -Force
        $manifestFiles += [ordered]@{ path = $file.Target; sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash }
    }
    [ordered]@{ version = $Version; files = $manifestFiles } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage "manifest.json") -Encoding UTF8
    $parent = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $OutputPath -Force
    Write-Host "Update package: $OutputPath"
    Write-Host "SHA256: $((Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash)"
}
finally {
    if ([IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
}
