#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root "build\central"
}
$compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $compiler)) { throw "C# compiler not found: $compiler" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Build-CSharp([string]$Name, [string[]]$Sources, [string[]]$References, [string]$Target = "exe", [string]$Manifest = "") {
    $output = Join-Path $OutputDirectory $Name
    $arguments = @("/nologo", "/codepage:65001", "/target:$Target", "/platform:x64", "/out:$output")
    $arguments += $References | ForEach-Object { "/reference:$_" }
    if (-not [string]::IsNullOrWhiteSpace($Manifest)) { $arguments += "/win32manifest:$Manifest" }
    $arguments += $Sources
    & $compiler @arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name build failed." }
    Write-Host "$Name`: $output"
}

Build-CSharp "DistControl.Agent.exe" `
    @((Join-Path $root "src\DistControl.Agent\Program.cs")) `
    @("System.ServiceProcess.dll", "System.Web.Extensions.dll", "System.Security.dll", "System.IO.Compression.dll", "System.IO.Compression.FileSystem.dll")

Build-CSharp "DistControl.Updater.exe" `
    @((Join-Path $root "src\DistControl.Updater\Program.cs")) `
    @("System.ServiceProcess.dll", "System.Web.Extensions.dll")

Build-CSharp "DistControl.CentralAdmin.exe" `
    @((Join-Path $root "src\DistControl.CentralAdmin\Program.cs")) `
    @("System.Windows.Forms.dll", "System.Drawing.dll", "System.Web.Extensions.dll", "System.Security.dll", "System.DirectoryServices.dll", "System.DirectoryServices.AccountManagement.dll", "System.IO.Compression.dll", "System.IO.Compression.FileSystem.dll") `
    "winexe" `
    (Join-Path $root "src\DistControl.CentralAdmin\DistControl.CentralAdmin.manifest")

& (Join-Path $root "server\Build-DistControlServer.ps1") -OutputDirectory $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw "DistControl.Server build failed." }
