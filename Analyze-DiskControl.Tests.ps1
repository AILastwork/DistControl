$ErrorActionPreference = "Stop"

$source = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "DiskControl.ps1")
$functionsStart = $source.IndexOf("# FUNCTIONS START")
$entryPoint = $source.IndexOf("# SCRIPT ENTRY POINT")
if ($functionsStart -lt 0 -or $entryPoint -lt 0 -or $entryPoint -le $functionsStart) {
    throw "В DiskControl.ps1 не найдены маркеры блока функций."
}
$functionsOnly = $source.Substring(
    $functionsStart,
    $entryPoint - $functionsStart
)
Invoke-Expression $functionsOnly

$sample = @"
OFFICE-HUB-Gr-1 (192.168.1.10:7575)
KeyOne (OFFICE-HUB-Gr-1.3)
KeyTwo (OFFICE-HUB-Gr-1.4)
"@

$devices = @(ConvertFrom-DkList -Text $sample)
if ($devices.Count -ne 2) {
    throw "Ожидалось 2 устройства, получено: $($devices.Count)."
}
if ($devices[0].Endpoint -ne "OFFICE-HUB-Gr-1.3") {
    throw "Неожиданный адрес первого устройства: $($devices[0].Endpoint)"
}

$devices[0].Nickname = "BANK-KEY-01"
$devices[0].Product = "Rutoken"
$rules = @([pscustomobject]@{
    endpoint = "OFFICE-HUB-Gr-1.3"
    nickname = "BANK-KEY-01"
    product = "Rutoken"
})

if (-not (Test-AllowedDevice -Device $devices[0] -Rules $rules)) {
    throw "Устройство должно соответствовать белому списку."
}

$devices[0].Nickname = "OTHER-KEY"
if (Test-AllowedDevice -Device $devices[0] -Rules $rules) {
    throw "Несовпадающее имя устройства должно блокировать доступ."
}

$principal = New-Object psobject
$principal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value {
    param($group)
    return $group -eq "DOMAIN\Бухгалтерия"
}

$accessConfig = [pscustomobject]@{
    userAssignments = @(
        [pscustomobject]@{
            users = @("DOMAIN\ivanov")
            groups = @()
            allowedDevices = @(
                [pscustomobject]@{
                    endpoint = "OFFICE-HUB-Gr-1.3"
                    nickname = "BANK-KEY-01"
                    product = "Rutoken"
                }
            )
        },
        [pscustomobject]@{
            users = @()
            groups = @("DOMAIN\Бухгалтерия")
            allowedDevices = @(
                [pscustomobject]@{
                    endpoint = "OFFICE-HUB-Gr-2.4"
                    nickname = "REPORT-KEY-01"
                    product = ""
                }
            )
        }
    )
}

$ivanovContext = [pscustomobject]@{
    FullName = "DOMAIN\ivanov"
    ShortName = "ivanov"
    Sid = "S-1-5-21-1000"
    Principal = $principal
}
$ivanovRules = @(Get-EffectiveDeviceRules `
    -Config $accessConfig `
    -UserContext $ivanovContext)
if ($ivanovRules.Count -ne 2) {
    throw "Иванов должен получить личный и групповой ключи."
}

$unknownPrincipal = New-Object psobject
$unknownPrincipal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value {
    param($group)
    return $false
}
$unknownContext = [pscustomobject]@{
    FullName = "DOMAIN\unknown"
    ShortName = "unknown"
    Sid = "S-1-5-21-2000"
    Principal = $unknownPrincipal
}
$unknownRules = @(Get-EffectiveDeviceRules `
    -Config $accessConfig `
    -UserContext $unknownContext)
if ($unknownRules.Count -ne 0) {
    throw "Пользователь без назначения не должен получать устройства."
}

Write-Host "Все тесты пройдены."
