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
$recordType = $assembly.GetType("DistControl.CentralAdmin.CentralLogRecord", $true)
$listType = [Collections.Generic.List``1].MakeGenericType($recordType)
$records = [Activator]::CreateInstance($listType)

$lines = @(
    '2026-11-16 10:00:00,OSNOVA\ivanov,S-1-5-21-1,USE,hub-Gr-1.1,TEST LLC,Rutoken,OK,"profileName=VPN - TEST; publicIp=203.0.113.10"',
    '2026-11-16 10:30:00,OSNOVA\ivanov,S-1-5-21-1,STOP USING OWN,hub-Gr-1.1,TEST LLC,Rutoken,OK,Disconnected',
    '2026-11-16 11:00:00,OSNOVA\petrov,S-1-5-21-2,USE,hub-Gr-1.2,OTHER LLC,Rutoken,ERROR,technical=test'
)
foreach ($line in $lines) {
    $record = [Activator]::CreateInstance($recordType)
    $record.FileName = "audit-20261116.csv"
    $record.Text = $line
    [void]$records.Add($record)
}

$flags = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
$build = $formType.GetMethod("BuildTokenSessions", $flags)
$arguments = New-Object object[] 2
$arguments[0] = $records
$arguments[1] = "WRK-TEST"
$sessions = $build.Invoke($null, $arguments)
if ($sessions.Count -ne 2) {
    throw "Expected two human-readable token sessions, got $($sessions.Count); input records: $($records.Count)."
}
$sessions | ForEach-Object { Write-Verbose ("session user={0}; token={1}; connected={2}; disconnected={3}; status={4}" -f $_.User,$_.Token,$_.Connected,$_.Disconnected,$_.Status) }
$completed = @($sessions | Where-Object { $_.User -eq "OSNOVA\ivanov" -and $null -ne $_.Disconnected })
if ($completed.Count -ne 1 -or $completed[0].Token -ne "TEST LLC" -or
    $completed[0].Network -ne "VPN - TEST / IP 203.0.113.10") {
    throw "Completed token session was assembled incorrectly: count=$($completed.Count), token=$($completed[0].Token), network=$($completed[0].Network)."
}
$duration = ([datetime]$completed[0].Disconnected) - ([datetime]$completed[0].Connected)
if ($duration.TotalMinutes -ne 30) { throw "Unexpected session duration: $duration" }
if (@($sessions | Where-Object { $_.User -eq "OSNOVA\petrov" -and $null -eq $_.Disconnected }).Count -ne 1) {
    throw "Failed connection was not translated into a human-readable status."
}
Write-Host "Central token journal presentation tests passed."
