#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AssemblyPath
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AssemblyPath)) {
    $AssemblyPath = Join-Path $PSScriptRoot "..\build\central\DistControl.Server.exe"
}
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$storeType = $assembly.GetType("DistControl.Server.ServerStore", $true)
$requestType = $assembly.GetType("DistControl.Server.EnrollRequest", $true)
$hubUpdateType = $assembly.GetType("DistControl.Server.HubConfigurationUpdateRequest", $true)
$heartbeatType = $assembly.GetType("DistControl.Server.HeartbeatRequest", $true)
$testDirectory = Join-Path $env:TEMP ("DistControl-enrollment-test-" + [Guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($testDirectory) | Out-Null

try {
    $hashMethod = $storeType.GetMethod("Hash", [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static)
    $legacyTokenHash = $hashMethod.Invoke($null, [object[]]@([string]"existing-client-token"))
    $legacyData = [ordered]@{
        SchemaVersion = 1
        EnrollmentCode = "123456"
        AdminKeyHash = "legacy"
        Clients = @([ordered]@{
            Id = "existing-client"
            TokenHash = $legacyTokenHash
            MachineName = "WRK-OLD"
            UserName = "OSNOVA\old"
            PolicyJson = '{"vpnProfiles":[],"userAssignments":[]}'
        })
        Logs = @()
        Updates = @()
        Audit = @()
    } | ConvertTo-Json -Depth 6 -Compress
    [IO.File]::WriteAllText((Join-Path $testDirectory "server-data.json"), $legacyData, (New-Object Text.UTF8Encoding($false)))
    $store = [Activator]::CreateInstance($storeType, @([string]$testDirectory))
    $migratedData = [IO.File]::ReadAllText((Join-Path $testDirectory "server-data.json"))
    if ($migratedData -match 'EnrollmentCode|AdminKeyHash|123456|legacy') {
        throw "Legacy enrollment and administrator secrets were not removed during migration."
    }
    [void]$store.AuthenticateClient("existing-client", "existing-client-token")
    $request = [Activator]::CreateInstance($requestType)
    $request.RequestToken = "test-request-secret"
    $request.MachineName = "WRK-TEST"
    $request.UserName = "OSNOVA\test"
    $request.AppVersion = "0.8.1"
    $request.AgentVersion = "0.8.1"

    $pending = $store.Enroll($request, "10.0.0.10")
    if ($pending.Approved -or [string]::IsNullOrWhiteSpace($pending.RequestId)) {
        throw "Pending enrollment was not created."
    }
    if ($store.ListPendingEnrollments().Count -ne 1) {
        throw "Pending enrollment list is incorrect."
    }

    $store.DecideEnrollment($pending.RequestId, $true, "OSNOVA\domain-admin")
    $approved = $store.Enroll($request, "10.0.0.10")
    if (-not $approved.Approved -or [string]::IsNullOrWhiteSpace($approved.ClientToken)) {
        throw "Approved enrollment did not issue a token."
    }
    [void]$store.AuthenticateClient($approved.ClientId, $approved.ClientToken)

    $heartbeat = [Activator]::CreateInstance($heartbeatType)
    $heartbeat.CurrentManualHubs = "10.14.0.71:6565,10.14.0.72:6565"
    $store.Heartbeat($approved.ClientId, $approved.ClientToken, $heartbeat, "10.0.0.10")
    $discovered = $store.GetHubConfiguration()
    if ($discovered.DiscoveredManualHubs -ne "10.14.0.71:6565,10.14.0.72:6565") {
        throw "Current USB servers were not discovered from the client heartbeat."
    }

    $hubUpdate = [Activator]::CreateInstance($hubUpdateType)
    $hubUpdate.ManualHubs = "10.14.0.71:6565`n10.14.0.72 10.14.0.71:6565"
    $hubs = $store.UpdateHubConfiguration($hubUpdate, "OSNOVA\domain-admin")
    if ($hubs.ManualHubs -ne "10.14.0.71:6565,10.14.0.72:6565" -or
        [string]::IsNullOrWhiteSpace($hubs.Revision)) {
        throw "USB server configuration was not normalized or versioned."
    }
    Write-Host "Server enrollment workflow passed."
}
finally {
    if ([IO.Directory]::Exists($testDirectory)) {
        [IO.Directory]::Delete($testDirectory, $true)
    }
}
