#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AssemblyPath
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AssemblyPath)) {
    $AssemblyPath = Join-Path $PSScriptRoot "..\build\central\DistControl.Agent.exe"
}
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$workerType = $assembly.GetType("DistControl.Agent.AgentWorker", $true)
$flags = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
$validate = $workerType.GetMethod("ValidateHubEndpoints", $flags)
$updateIni = $workerType.GetMethod("UpdateManualHubs", $flags)
if (-not $validate -or -not $updateIni) { throw "Agent hub configuration methods were not found." }

$addresses = $validate.Invoke($null, [object[]]@([string]"10.14.0.71:6565, 10.14.0.72"))
if ($addresses.Count -ne 2 -or $addresses[0] -ne "10.14.0.71" -or $addresses[1] -ne "10.14.0.72") {
    throw "Agent did not parse USB server addresses correctly."
}

$testDirectory = Join-Path $env:TEMP ("DistControl-agent-hubs-" + [Guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($testDirectory) | Out-Null
try {
    $ini = Join-Path $testDirectory "dkcl.ini"
    [IO.File]::WriteAllText($ini, "[General]`r`nMainFrameWidth=800`r`n[Settings]`r`nManualHubs=10.14.0.70:6565`r`n", [Text.Encoding]::ASCII)
    $updateIni.Invoke($null, [object[]]@([string]$ini, [string]"10.14.0.71:6565,10.14.0.72:6565"))
    $content = [IO.File]::ReadAllText($ini)
    if ($content -notmatch 'ManualHubs=10\.14\.0\.71:6565,10\.14\.0\.72:6565' -or
        $content -match '10\.14\.0\.70') {
        throw "Agent did not update ManualHubs in dkcl.ini correctly."
    }

    $configPath = Join-Path $testDirectory "agent.json"
    $policyPath = Join-Path $testDirectory "allow.json"
    [IO.File]::WriteAllText($policyPath, '{"vpnProfiles":[],"userAssignments":[]}', [Text.Encoding]::UTF8)
    [IO.File]::WriteAllText($configPath, (@{
        PolicyPath = $policyPath
        InstallDirectory = $testDirectory
        LogsDirectory = (Join-Path $testDirectory "logs")
        NetworkStatePath = (Join-Path $testDirectory "network-state.json")
    } | ConvertTo-Json), [Text.Encoding]::UTF8)
    $worker = [Activator]::CreateInstance($workerType, [object[]]@([string]$configPath))
    $worker.Initialize()
    $readCurrent = $workerType.GetMethod("ReadCurrentManualHubs", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
    $current = [string]$readCurrent.Invoke($worker, $null)
    if ($current -ne "10.14.0.71:6565,10.14.0.72:6565") {
        throw "Agent did not read the current ManualHubs value from dkcl.ini."
    }
    $applyRoutes = $workerType.GetMethod("ApplyHubRoutes", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
    $emptyAddresses = [Activator]::CreateInstance($applyRoutes.GetParameters()[0].ParameterType)
    $routeArguments = New-Object object[] 1
    $routeArguments[0] = $emptyAddresses
    $applyRoutes.Invoke($worker, $routeArguments) | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $testDirectory "managed-hub-routes.json"))) {
        throw "Agent route synchronization did not create its state file."
    }
    Write-Host "Agent USB server configuration tests passed."
}
finally {
    if ([IO.Directory]::Exists($testDirectory)) { [IO.Directory]::Delete($testDirectory, $true) }
}
