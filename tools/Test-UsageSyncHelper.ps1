#Requires -Version 5.1
[CmdletBinding()]
param([string]$Executable)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $Executable) {
    $Executable = Join-Path $root 'build\x64\Release\DistControl.exe'
}
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$testRoot = Join-Path $root 'build\usage sync smoke'
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$shared = Join-Path $testRoot 'shared usage.json'
$local = Join-Path $testRoot 'local queue.json'
$encoding = New-Object Text.UTF8Encoding($false)
$previousLocalAppData = $env:LOCALAPPDATA

function Write-TestJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 20), $encoding)
}

function Run-Helper {
    $arguments = '--sync-usage --shared-usage "{0}" --local-usage "{1}" --pipe DistControl.Smoke.Nonexistent.{2}' -f $shared, $local, $PID
    $process = Start-Process -FilePath $Executable -ArgumentList $arguments -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'The usage helper did not finish without a window.'
        }
        $process.Refresh()
        return $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
}

try {
    $env:LOCALAPPDATA = $testRoot
    $peer = @{
        endpoint = 'SMOKE-HUB-Gr-1.1'; nickname = 'Peer token'; product = 'Rutoken'
        user = 'DOMAIN\peer'; computer = 'OTHER-PC'; updatedAt = '2026-09-15T09:00:00'
        publicIp = '203.0.113.11'; connectionId = 'PEER-SESSION'
    }
    Write-TestJson $shared @{ active = @($peer) }
    Write-TestJson $local @{ version = '1'; sharedPath = $shared; active = @(); cache = @(); pending = @() }
    if ((Run-Helper) -ne 0) { throw 'Cache-only helper failed.' }
    $state = Get-Content -LiteralPath $local -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($state.cache).Count -ne 1 -or $state.cache[0].connectionId -ne 'PEER-SESSION') {
        throw 'The helper did not refresh the local cache.'
    }

    $ours = @{
        endpoint = 'SMOKE-HUB-Gr-1.2'; nickname = 'Queued token'; product = 'Rutoken'
        user = 'DOMAIN\test'; computer = $env:COMPUTERNAME; updatedAt = '2026-09-15T09:01:00'
        publicIp = '203.0.113.12'; connectionId = 'QUEUED-SESSION'; operationId = 'SMOKE-CONNECT'
    }
    Write-TestJson $local @{
        version = '1'; sharedPath = $shared; active = @($ours); cache = @($peer)
        pending = @(@{ id = 'SMOKE-CHANGE'; action = 'use'; record = $ours })
    }
    if ((Run-Helper) -ne 1) { throw 'Missing service must produce a retryable helper failure.' }
    $state = Get-Content -LiteralPath $local -Raw -Encoding UTF8 | ConvertFrom-Json
    $remote = Get-Content -LiteralPath $shared -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($state.pending).Count -ne 1 -or $state.pending[0].record.publicIp -ne $ours.publicIp -or
        $state.pending[0].record.updatedAt -ne $ours.updatedAt -or @($remote.active).Count -ne 1) {
        throw 'Retryable failure must preserve the original metadata and shared records.'
    }
    Write-Output 'Usage helper smoke passed: hidden execution, quoted paths, cache refresh and durable retry.'
}
finally {
    $env:LOCALAPPDATA = $previousLocalAppData
}
