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
$policyUpdateType = $assembly.GetType("DistControl.Server.PolicyUpdateRequest", $true)
$logRequestType = $assembly.GetType("DistControl.Server.LogUploadRequest", $true)
$logItemType = $assembly.GetType("DistControl.Server.LogUploadItem", $true)
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
    $request.AppVersion = "0.8.5"
    $request.AgentVersion = "0.8.5"

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

    $smallPolicy = [ordered]@{
        vpnProfiles = @()
        userAssignments = @([ordered]@{
            users = @("OSNOVA\test")
            groups = @()
            allowedDevices = @([ordered]@{ endpoint = "hub-1"; nickname = "Token 1"; product = "Rutoken" })
        })
    } | ConvertTo-Json -Depth 6 -Compress
    $smallUpdate = [Activator]::CreateInstance($policyUpdateType)
    $smallUpdate.ExpectedRevision = $store.GetPolicyForAdmin($approved.ClientId).Revision
    $smallUpdate.PolicyJson = $smallPolicy
    $smallUpdate.Actor = "OSNOVA\domain-admin"
    [void]$store.UpdatePolicy($approved.ClientId, $smallUpdate)

    $largeDevices = for ($i = 1; $i -le 20; $i++) {
        [ordered]@{ endpoint = "hub-$i"; nickname = "Token $i"; product = "Rutoken" }
    }
    $largePolicy = [ordered]@{
        vpnProfiles = @()
        userAssignments = @([ordered]@{
            users = @("OSNOVA\test")
            groups = @()
            allowedDevices = @($largeDevices)
        })
    } | ConvertTo-Json -Depth 6 -Compress
    $largeUpdate = [Activator]::CreateInstance($policyUpdateType)
    $largeUpdate.ExpectedRevision = $store.GetPolicyForAdmin($approved.ClientId).Revision
    $largeUpdate.PolicyJson = $largePolicy
    $largeUpdate.Actor = "OSNOVA\domain-admin"
    $massRejected = $false
    try { [void]$store.UpdatePolicy($approved.ClientId, $largeUpdate) }
    catch { $massRejected = $true }
    if (-not $massRejected) { throw "Unconfirmed mass policy expansion was accepted." }
    if ($store.GetPolicyForAdmin($approved.ClientId).PolicyJson -ne $smallPolicy) {
        throw "Rejected mass policy expansion still modified the stored policy."
    }

    $largeUpdate.ConfirmMassExpansion = $true
    [void]$store.UpdatePolicy($approved.ClientId, $largeUpdate)
    if ($store.GetPolicyForAdmin($approved.ClientId).PolicyJson -ne $largePolicy) {
        throw "Confirmed mass policy expansion was not saved."
    }

    $heartbeat = [Activator]::CreateInstance($heartbeatType)
    $heartbeat.CurrentManualHubs = "10.14.0.71:6565,10.14.0.72:6565"
    $store.Heartbeat($approved.ClientId, $approved.ClientToken, $heartbeat, "10.0.0.10")
    $discovered = $store.GetHubConfiguration()
    if ($discovered.DiscoveredManualHubs -ne "10.14.0.71:6565,10.14.0.72:6565") {
        throw "Current USB servers were not discovered from the client heartbeat."
    }

    $logRequest = [Activator]::CreateInstance($logRequestType)
    foreach ($logData in @(
        @{ Id = "audit-line"; FileName = "audit-20261116.csv"; Text = "audit" },
        @{ Id = "trace-line"; FileName = "trace-20261116.log"; Text = "trace" }
    )) {
        $item = [Activator]::CreateInstance($logItemType)
        $item.Id = $logData.Id
        $item.FileName = $logData.FileName
        $item.Text = $logData.Text
        [void]$logRequest.Items.Add($item)
    }
    [void]$store.AppendLogs($approved.ClientId, $approved.ClientToken, $logRequest)
    $centralLogs = $store.ListLogs($approved.ClientId, 100)
    if ($centralLogs.Count -ne 1 -or $centralLogs[0].FileName -ne "audit-20261116.csv") {
        throw "Technical files were uploaded to the central token journal."
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
