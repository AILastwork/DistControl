#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AssemblyPath
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AssemblyPath)) {
    $AssemblyPath = Join-Path $PSScriptRoot "..\build\central\DistControl.CentralAdmin.exe"
}
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$formType = $assembly.GetType("DistControl.CentralAdmin.MainForm", $true)
$flags = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static

function New-TestPolicy([int]$PrimaryCount, [int]$SecondaryCount) {
    $primary = for ($i = 1; $i -le $PrimaryCount; $i++) {
        [ordered]@{ endpoint = "hub-primary-$i"; nickname = "Token $i"; product = "Rutoken" }
    }
    $secondary = for ($i = 1; $i -le $SecondaryCount; $i++) {
        [ordered]@{ endpoint = "hub-secondary-$i"; nickname = "Other $i"; product = "Rutoken" }
    }
    return ([ordered]@{
        vpnProfiles = @()
        userAssignments = @(
            [ordered]@{ users = @("OSNOVA\test"); groups = @(); allowedDevices = @($primary) }
            [ordered]@{ users = @("OSNOVA\other"); groups = @(); allowedDevices = @($secondary) }
        )
    } | ConvertTo-Json -Depth 6 -Compress)
}

$summarize = $formType.GetMethod("SummarizePolicyChange", $flags)
$before = [string](New-TestPolicy 1 23)
$after = [string](New-TestPolicy 142 23)
$summaryArguments = New-Object object[] 2
$summaryArguments[0] = $before
$summaryArguments[1] = $after
$summary = $summarize.Invoke($null, $summaryArguments)
if ($summary.BeforeCount -ne 24 -or $summary.AfterCount -ne 165 -or
    $summary.AddedCount -ne 141 -or $summary.RemovedCount -ne 0 -or -not $summary.IsMassExpansion) {
    throw "Mass policy expansion was not summarized correctly."
}

$createSession = $formType.GetMethod("CreatePolicyEditSessionDirectory", $flags)
$settingsRoot = Join-Path $env:TEMP ("DistControl-policy-session-test-" + [Guid]::NewGuid().ToString("N"))
$settingsPath = Join-Path $settingsRoot "settings.json"
[IO.Directory]::CreateDirectory($settingsRoot) | Out-Null
try {
    $sessionArguments = New-Object object[] 2
    $sessionArguments[0] = [string]$settingsPath
    $sessionArguments[1] = [string]"client-1"
    $first = $createSession.Invoke($null, $sessionArguments)
    $second = $createSession.Invoke($null, $sessionArguments)
    if ($first -eq $second -or -not [IO.Directory]::Exists($first) -or -not [IO.Directory]::Exists($second)) {
        throw "Concurrent policy editors did not receive isolated directories."
    }
}
finally {
    if ([IO.Directory]::Exists($settingsRoot)) { [IO.Directory]::Delete($settingsRoot, $true) }
}

Write-Host "Central policy editing safety tests passed."
