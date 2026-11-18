#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$Version = "0.8.13",
    [string]$DefaultServerUrl = "http://10.14.32.179:8765",
    [string]$DefaultUsageStateDirectory = "\\dfs\fs\IT\soft\DistKontrol\time",
    [string]$WixVersion = "3.14.1"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $Root "dist"
$BuildToolsDir = Join-Path $Root "build\tools"
$WixDir = Join-Path $BuildToolsDir "wix-$WixVersion"
$WixPackage = Join-Path $BuildToolsDir "wix-$WixVersion.nupkg"
$WixZip = Join-Path $BuildToolsDir "wix-$WixVersion.zip"
$Candle = Join-Path $WixDir "tools\candle.exe"
$Light = Join-Path $WixDir "tools\light.exe"
$Wxs = Join-Path $PSScriptRoot "msi\DistControl.Client.wxs"
$SetupExe = Join-Path $DistDir "DistControl-Setup.exe"
$ObjDir = Join-Path $Root "build\msi"
$WixObj = Join-Path $ObjDir "DistControl.Client.wixobj"
$Output = Join-Path $DistDir "DistControl-Client-$Version.msi"
$HashOutput = "$Output.sha256"

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "MSI version must contain three numeric parts, for example 0.8.13."
}
if ([string]::IsNullOrWhiteSpace($DefaultServerUrl)) {
    throw "DefaultServerUrl is required."
}
if ([string]::IsNullOrWhiteSpace($DefaultUsageStateDirectory)) {
    throw "DefaultUsageStateDirectory is required."
}

& (Join-Path $PSScriptRoot "Build-InstallerPackage.ps1") `
    -SkipBuild:$SkipBuild `
    -DefaultServerUrl $DefaultServerUrl `
    -DefaultUsageStateDirectory $DefaultUsageStateDirectory
if ($LASTEXITCODE -ne 0) {
    throw "DistControl setup build failed."
}

if (-not (Test-Path -LiteralPath $Candle) -or -not (Test-Path -LiteralPath $Light)) {
    Write-Host "Download WiX Toolset $WixVersion to $WixDir"
    New-Item -ItemType Directory -Path $BuildToolsDir -Force | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://www.nuget.org/api/v2/package/wix/$WixVersion" `
        -OutFile $WixPackage
    Copy-Item -LiteralPath $WixPackage -Destination $WixZip -Force
    if (Test-Path -LiteralPath $WixDir) {
        Remove-Item -LiteralPath $WixDir -Recurse -Force
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($WixZip, $WixDir)
    Remove-Item -LiteralPath $WixPackage, $WixZip -Force -ErrorAction SilentlyContinue
}

foreach ($path in @($Candle, $Light, $Wxs, $SetupExe)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required MSI build input is missing: $path"
    }
}

New-Item -ItemType Directory -Path $ObjDir -Force | Out-Null
Remove-Item -LiteralPath $WixObj, $Output, $HashOutput -Force -ErrorAction SilentlyContinue

& $Candle -nologo -arch x64 `
    "-dProductVersion=$Version" `
    "-dSetupExePath=$SetupExe" `
    -out $WixObj $Wxs
if ($LASTEXITCODE -ne 0) {
    throw "WiX candle.exe failed."
}

& $Light -nologo -out $Output $WixObj
if ($LASTEXITCODE -ne 0) {
    throw "WiX light.exe failed."
}

$hash = (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash
[IO.File]::WriteAllText($HashOutput, "$hash  $(Split-Path -Leaf $Output)`r`n", (New-Object Text.UTF8Encoding($false)))
Write-Host "MSI package: $Output"
Write-Host "Defaults: server=$DefaultServerUrl; time=$DefaultUsageStateDirectory"
Write-Host "SHA256: $hash"
