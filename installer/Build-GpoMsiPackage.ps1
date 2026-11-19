#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$Version = "0.8.21",
    [string]$DefaultServerUrl = "http://10.14.32.179:8765",
    [string]$DefaultUsageStateDirectory = "\\dfs\fs\IT\soft\DistKontrol\time",
    [string]$GpoMsiUncDirectory = "\\dfs\fs\IT\GPO\distcontrol"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $Root "dist"
$GpoDir = Join-Path $DistDir "GPO"
$BaseMsi = Join-Path $DistDir "DistControl-Client-$Version.msi"
$OutputMsi = Join-Path $GpoDir "DistControl-Client-GPO-$Version.msi"
$OutputHash = "$OutputMsi.sha256"
$OutputReadme = Join-Path $GpoDir "README-GPO.txt"
$ReadmeTemplate = Join-Path $PSScriptRoot "GPO-README.ru.txt"

& (Join-Path $PSScriptRoot "Build-MsiPackage.ps1") `
    -SkipBuild:$SkipBuild `
    -Version $Version `
    -DefaultServerUrl $DefaultServerUrl `
    -DefaultUsageStateDirectory $DefaultUsageStateDirectory
if ($LASTEXITCODE -ne 0) {
    throw "DistControl MSI build failed."
}

if (-not (Test-Path -LiteralPath $BaseMsi)) {
    throw "Built MSI was not found: $BaseMsi"
}

New-Item -ItemType Directory -Path $GpoDir -Force | Out-Null
Copy-Item -LiteralPath $BaseMsi -Destination $OutputMsi -Force

$hash = (Get-FileHash -LiteralPath $OutputMsi -Algorithm SHA256).Hash
[IO.File]::WriteAllText(
    $OutputHash,
    "$hash  $(Split-Path -Leaf $OutputMsi)`r`n",
    (New-Object Text.UTF8Encoding($false)))

if (-not (Test-Path -LiteralPath $ReadmeTemplate)) {
    throw "GPO README template was not found: $ReadmeTemplate"
}
$readme = [IO.File]::ReadAllText($ReadmeTemplate, [Text.Encoding]::UTF8)
$readme = $readme.Replace("{{VERSION}}", $Version)
$readme = $readme.Replace("{{SERVER_URL}}", $DefaultServerUrl)
$readme = $readme.Replace("{{TIME_DIRECTORY}}", $DefaultUsageStateDirectory)
$msiUncPath = $GpoMsiUncDirectory.TrimEnd("\") + "\DistControl-Client-GPO-$Version.msi"
$readme = $readme.Replace("{{MSI_UNC_PATH}}", $msiUncPath)
# UTF-16LE with BOM opens correctly even in legacy Windows text viewers.
[IO.File]::WriteAllText($OutputReadme, $readme, [Text.Encoding]::Unicode)

Write-Host "GPO MSI package: $OutputMsi"
Write-Host "GPO README:      $OutputReadme"
Write-Host "SHA256:         $hash"
