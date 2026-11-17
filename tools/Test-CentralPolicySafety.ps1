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
$buildEditorArguments = $formType.GetMethod("BuildPolicyEditorArguments", $flags)
$editorArguments = $buildEditorArguments.Invoke($null, @(
    [string]'C:\Temp\WRK-380 policy\allow.json',
    [string]'WRK-380',
    [string]'OSNOVA\o.ponomarenko'))
if ($editorArguments -notmatch '--computer "WRK-380"' -or
    $editorArguments -notmatch '--target-user "OSNOVA\\o\.ponomarenko"' -or
    $editorArguments -notmatch '--policy "C:\\Temp\\WRK-380 policy\\allow\.json"') {
    throw "Selected computer context was not passed to the policy editor."
}
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

$port = Get-Random -Minimum 21000 -Maximum 49000
$serverJob = Start-Job -ArgumentList $port -ScriptBlock {
    param([int]$Port)
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    try {
        $client = $listener.AcceptTcpClient()
        try {
            $reader = [IO.StreamReader]::new($client.GetStream(), [Text.Encoding]::ASCII, $false, 1024, $true)
            $contentLength = $null
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
                if ($line.StartsWith("Content-Length:", [StringComparison]::OrdinalIgnoreCase)) {
                    $contentLength = [int64]$line.Substring($line.IndexOf(':') + 1).Trim()
                }
            }
            $body = [Text.Encoding]::UTF8.GetBytes("{}")
            $header = [Text.Encoding]::ASCII.GetBytes(
                "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: 2`r`nConnection: close`r`n`r`n")
            $stream = $client.GetStream()
            $stream.Write($header, 0, $header.Length)
            $stream.Write($body, 0, $body.Length)
            $stream.Flush()
            $bodyText = ""
            if ($contentLength -gt 0) {
                $buffer = New-Object char[] $contentLength
                [void]$reader.ReadBlock($buffer, 0, $buffer.Length)
                $bodyText = -join $buffer
            }
            return "$contentLength|$bodyText"
        }
        finally { $client.Dispose() }
    }
    finally { $listener.Stop() }
}
try {
    Start-Sleep -Milliseconds 500
    $apiType = $assembly.GetType("DistControl.CentralAdmin.CentralApi", $true)
    $api = [Activator]::CreateInstance($apiType, $true)
    $apiType.GetField("ServerUrl").SetValue($api, "http://127.0.0.1:$port")
    $jsonMethod = $apiType.GetMethod("Json").MakeGenericMethod([object])
    [void]$jsonMethod.Invoke($api, @([string]"POST", [string]"/empty-post", $null))
    $postedLength = Receive-Job -Job $serverJob -Wait
    if ($postedLength -ne "2|{}") { throw "Empty POST did not send the required empty JSON object." }
}
finally {
    Stop-Job -Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue
}

Write-Host "Central policy editing safety tests passed."
