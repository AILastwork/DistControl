#Requires -Version 5.1
[CmdletBinding()]
param([string]$AssemblyPath)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AssemblyPath)) {
    $AssemblyPath = Join-Path $PSScriptRoot "..\build\central\DistControl.Agent.exe"
}
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$workerType = $assembly.GetType("DistControl.Agent.AgentWorker", $true)
$logMethod = $workerType.GetMethod("Log", [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic)
$directory = Join-Path $env:TEMP ("DistControl-agent-safety-" + [Guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($directory) | Out-Null
try {
    $worker = [Activator]::CreateInstance($workerType, @([string](Join-Path $directory "agent.json")))
    [void]$logMethod.Invoke($worker, @([string]("x" * (5 * 1024 * 1024))))
    [void]$logMethod.Invoke($worker, @([string]"rotation-check"))
    $log = Join-Path $directory "agent.log"
    if (-not [IO.File]::Exists($log) -or -not [IO.File]::Exists($log + ".1")) {
        throw "Agent log rotation did not create the current and archived files."
    }
    if ((Get-Item -LiteralPath $log).Length -ge 5MB) {
        throw "Current agent log is still above the rotation limit."
    }
    Write-Host "Agent log safety checks passed."
}
finally {
    if ([IO.Directory]::Exists($directory)) { [IO.Directory]::Delete($directory, $true) }
}
