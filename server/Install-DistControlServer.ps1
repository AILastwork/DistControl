#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDirectory = "$env:ProgramFiles\DistControl Server",
    [string]$ListenUrl = "http://+:8765/",
    [string]$DataDirectory = "$env:ProgramData\DistControlServer",
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$serviceName = "DistControlServer"
$source = Join-Path $PSScriptRoot "bin\DistControl.Server.exe"
if (-not (Test-Path -LiteralPath $source)) { throw "Сначала соберите сервер: $source" }
$installedServer = Join-Path $InstallDirectory "DistControl.Server.exe"

function Copy-FileWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
            return
        }
        catch {
            if ($attempt -eq 10) {
                throw "Не удалось обновить файл '$Destination'. Закройте запущенные программы DistControl и повторите установку. Причина: $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 500
        }
    }
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Write-Host "Останавливаем действующую службу DistControl Server..."
        Stop-Service -Name $serviceName -Force
        $existing.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }
}

# После остановки службы процесс иногда ещё несколько секунд удерживает EXE.
foreach ($process in @(Get-Process -Name "DistControl.Server" -ErrorAction SilentlyContinue)) {
    try {
        if ([string]::Equals($process.Path, $installedServer, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Завершаем оставшийся процесс DistControl Server..."
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit(10000)
        }
    }
    catch {
        throw "Не удалось завершить старый процесс DistControl Server. Причина: $($_.Exception.Message)"
    }
}

if ($existing) {
    sc.exe delete $serviceName | Out-Null
    $deleteDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deleteDeadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Старая служба DistControl Server ещё завершается. Подождите несколько секунд и повторите установку."
    }
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
icacls.exe $DataDirectory /inheritance:r /grant:r `
    "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Не удалось защитить каталог данных сервера: $DataDirectory" }
Copy-FileWithRetry -Source $source -Destination $installedServer
foreach ($optional in @("DistControl.CentralAdmin.exe", "DistControl.Admin.exe")) {
    $candidate = Join-Path $PSScriptRoot "bin\$optional"
    if (Test-Path -LiteralPath $candidate) {
        Copy-FileWithRetry -Source $candidate -Destination (Join-Path $InstallDirectory $optional)
    }
}

$binary = '"{0}" --service --url "{1}" --data "{2}"' -f $installedServer, $ListenUrl, $DataDirectory
New-Service -Name $serviceName -BinaryPathName $binary -DisplayName "DistControl Server" -StartupType Automatic | Out-Null
if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
    Get-NetFirewallRule -DisplayName "DistControl Server" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "DistControl Server" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
}
Start-Service -Name $serviceName

Write-Host "DistControl Server установлен и запущен."
Write-Host "API: $ListenUrl"
Write-Host "Административный доступ: текущая доменная учетная запись должна входить в Domain Admins."
