#Requires -Version 5.1
<#
.SYNOPSIS
    Переводит клиент DistControl на компьютере на нового сотрудника.

.DESCRIPTION
    Используется, когда за компьютером меняется сотрудник, а клиент ставится через
    GPO-задачу "DistControlInstall" с "Применить один раз" и DISTCONTROLTARGETUSERSID=%LogonUserSid%.

    Скрипт запускается с машины администратора и работает с удалённым ПК через
    планировщик (schtasks /s) и административный ресурс C$. WinRM не нужен.

    На удалённом ПК от имени СИСТЕМА он:
      1. Находит установленный клиент (служба DistControlAgent) и его владельца.
      2. Если клиент принадлежит другому пользователю, удаляет его штатным
         Uninstall-DiskControl.ps1 и снимает регистрацию MSI "DistControl Client".
         Данные старого пользователя (AppData\Local\DistControl) не удаляются.
      3. Сбрасывает у нового пользователя отметку "уже выполнено" для GPO-задачи,
         чтобы она запустилась для него ещё раз.
    После этого новому сотруднику нужно выполнить gpupdate /force или перелогиниться.

.PARAMETER ComputerName
    Имя компьютера, например WRK-156.

.PARAMETER NewUser
    Логин нового сотрудника: OSNOVA\i.ivanov или просто i.ivanov.

.PARAMETER RunOnceFilterId
    Идентификатор фильтра "Применить один раз" у задачи в GPO. По умолчанию -
    задача DistControlInstall-0.8.18 политики distcontrol. Если задачу пересоздать
    в GPO, значение поменяется: его видно в User\Preferences\ScheduledTasks\ScheduledTasks.xml
    (элемент FilterRunOnce, атрибут id).

.EXAMPLE
    .\tools\Switch-DistControlUser.ps1 -ComputerName WRK-156 -NewUser a.test -WhatIf
    Только показать, что будет сделано.

.EXAMPLE
    .\tools\Switch-DistControlUser.ps1 -ComputerName WRK-156 -NewUser a.test
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,

    [Parameter(Mandatory = $true)]
    [string]$NewUser,

    [string]$Domain = $env:USERDOMAIN,

    [string]$RunOnceFilterId = "{C8382FB5-55BD-4A93-80B5-EDD381BA5034}",

    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

# Runs on the target computer as SYSTEM. Kept ASCII-only on purpose.
$WorkerScript = @'
param(
    [Parameter(Mandatory = $true)][string]$NewUserSid,
    [Parameter(Mandatory = $true)][string]$RunOnceFilterId,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$UpgradeCode = "{8E2503E8-7098-4FF1-9278-7AC5C473E0CF}"
$exitCode = 0

function Say([string]$Text) { Write-Output "[worker] $Text" }

function Get-MsiProducts {
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        return @($installer.RelatedProducts($UpgradeCode) | Where-Object { $_ })
    }
    catch {
        Say "WARNING: cannot query Windows Installer: $($_.Exception.Message)"
        return @()
    }
}

function Get-ProfileSid([string]$ProfileDir) {
    foreach ($key in Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") {
        $path = (Get-ItemProperty -LiteralPath $key.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and [string]::Equals([Environment]::ExpandEnvironmentVariables($path).TrimEnd('\'), $ProfileDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            return $key.PSChildName
        }
    }
    return $null
}

function Get-ProfileDirBySid([string]$Sid) {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    $path = (Get-ItemProperty -LiteralPath $key -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($path) { return [Environment]::ExpandEnvironmentVariables($path) }
    return $null
}

try {
    # 1. Find the installed client and its owner.
    $imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DistControlAgent" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    $needUninstall = $false
    if ($imagePath -and $imagePath -match '"?([^"]+?)\\DistControl\.Agent\.exe') {
        $installDir = $Matches[1]
        $profileDir = $null
        $oldSid = $null
        if ($installDir -match '^(.+?)\\AppData\\Local\\Programs\\DistControl$') {
            $profileDir = $Matches[1]
            $oldSid = Get-ProfileSid $profileDir
        }
        Say "Client found: installDir=$installDir; profile=$profileDir; ownerSid=$oldSid"
        if ($oldSid -and $oldSid -eq $NewUserSid) {
            Say "Client already belongs to the new user. Nothing to uninstall."
        }
        elseif (-not $profileDir -or -not $oldSid) {
            throw "Cannot determine the owner of the installed client ($installDir). Remove it manually."
        }
        else {
            $needUninstall = $true
        }
    }
    else {
        Say "Client service DistControlAgent not found."
    }

    # 2. Uninstall the old user's client.
    if ($needUninstall) {
        $source = Join-Path $installDir "installer\Uninstall-DiskControl.ps1"
        if (-not (Test-Path -LiteralPath $source)) {
            throw "Uninstall script not found: $source"
        }
        $psArgs = @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $null,
            "-InstallDir", $installDir,
            "-ProgramDataDir", (Join-Path $profileDir "AppData\Local\DistControl"),
            "-TargetUserSid", $oldSid,
            "-UserStartMenuDir", (Join-Path $profileDir "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\DistControl"),
            "-UserDesktopDir", (Join-Path $profileDir "Desktop")
        )
        if ($DryRun) {
            Say "DRY RUN: would run $source for owner $oldSid"
        }
        else {
            $copy = Join-Path $env:WINDIR "Temp\dc-switch-Uninstall-DiskControl.ps1"
            Copy-Item -LiteralPath $source -Destination $copy -Force
            $psArgs[4] = $copy
            Say "Uninstall client of $oldSid"
            & powershell.exe @psArgs 2>&1 | ForEach-Object { Write-Output "  $_" }
            $code = $LASTEXITCODE
            Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
            if ($code -ne 0) { throw "Uninstall-DiskControl.ps1 failed with exit code $code" }
            if (Get-Service -Name DistControlAgent -ErrorAction SilentlyContinue) {
                throw "Service DistControlAgent still exists after uninstall."
            }
        }
    }

    # 3. Remove the MSI registration if it is still there (older clients did not do it).
    foreach ($code in Get-MsiProducts) {
        if (-not $needUninstall -and (Get-Service -Name DistControlAgent -ErrorAction SilentlyContinue)) {
            Say "MSI $code kept: the client belongs to the new user."
            continue
        }
        if ($DryRun) { Say "DRY RUN: would run msiexec /x $code"; continue }
        $log = Join-Path $env:WINDIR ("Temp\DistControl-switch-msi-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        Say "Remove MSI registration $code"
        $p = Start-Process msiexec.exe -ArgumentList @("/x", $code, "/qn", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
        if ($p.ExitCode -notin @(0, 1605, 3010)) { throw "msiexec /x $code returned $($p.ExitCode), log: $log" }
        Say "MSI registration removed (exit code $($p.ExitCode))"
    }

    # 4. Reset the GPP "apply once" flag for the new user.
    $runOnceSubKey = "Software\Microsoft\Group Policy\Client\RunOnce"
    $loadedHive = $null
    if (Test-Path "Registry::HKEY_USERS\$NewUserSid") {
        $hiveRoot = "HKEY_USERS\$NewUserSid"
    }
    else {
        $newProfile = Get-ProfileDirBySid $NewUserSid
        $ntuser = if ($newProfile) { Join-Path $newProfile "NTUSER.DAT" } else { $null }
        if ($ntuser -and (Test-Path -LiteralPath $ntuser)) {
            $loadedHive = "HKU\DCSwitch_$($NewUserSid -replace '-', '_')"
            if (-not $DryRun) {
                & reg.exe load $loadedHive $ntuser | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Cannot load registry hive $ntuser" }
            }
            $hiveRoot = $loadedHive -replace '^HKU', 'HKEY_USERS'
        }
        else {
            $hiveRoot = $null
            Say "New user has no profile on this computer yet: the GPO task will run at the first logon."
        }
    }
    if ($hiveRoot) {
        try {
            $runOnceKey = "Registry::$hiveRoot\$runOnceSubKey"
            $hasFlag = $false
            if (Test-Path $runOnceKey) {
                $hasFlag = $null -ne (Get-ItemProperty -LiteralPath $runOnceKey -Name $RunOnceFilterId -ErrorAction SilentlyContinue)
            }
            if (-not $hasFlag) {
                Say "Run-once flag $RunOnceFilterId is not set for the new user."
            }
            elseif ($DryRun) {
                Say "DRY RUN: would reset run-once flag $RunOnceFilterId"
            }
            else {
                Remove-ItemProperty -LiteralPath $runOnceKey -Name $RunOnceFilterId
                Say "Run-once flag $RunOnceFilterId reset."
            }
        }
        finally {
            if ($loadedHive -and -not $DryRun) {
                [GC]::Collect()
                & reg.exe unload $loadedHive | Out-Null
            }
        }
    }
    Say "Done."
}
catch {
    Say "ERROR: $($_.Exception.Message)"
    $exitCode = 1
}
Write-Output "EXIT=$exitCode"
exit $exitCode
'@

function Resolve-UserSid([string]$Login) {
    $account = if ($Login.Contains("\")) { $Login } else { "$Domain\$Login" }
    try {
        return ([Security.Principal.NTAccount]$account).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Не удалось найти пользователя $account в домене."
    }
}

$sid = Resolve-UserSid $NewUser
Write-Host "Компьютер: $ComputerName"
Write-Host "Новый сотрудник: $NewUser ($sid)"

if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
    throw "Компьютер $ComputerName недоступен по сети."
}
$remoteTemp = "\\$ComputerName\C$\Windows\Temp"
if (-not (Test-Path -LiteralPath $remoteTemp)) {
    throw "Нет доступа к $remoteTemp. Нужны права администратора на $ComputerName."
}

$dryRun = -not $PSCmdlet.ShouldProcess($ComputerName, "Удалить клиент DistControl прежнего сотрудника и подготовить установку для $NewUser")
if ($dryRun) {
    Write-Host "Режим проверки: на компьютере ничего не меняется." -ForegroundColor Yellow
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$taskName = "DC-Switch-User-$stamp"
$workerName = "dc-switch-worker-$stamp.ps1"
$cmdName = "dc-switch-worker-$stamp.cmd"
$outName = "DistControl-switch-user-$stamp.txt"

$workerArgs = "-NewUserSid $sid -RunOnceFilterId `"$RunOnceFilterId`""
if ($dryRun) { $workerArgs += " -DryRun" }
$cmdText = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"C:\Windows\Temp\$workerName`" $workerArgs > `"C:\Windows\Temp\$outName`" 2>&1`r`n"

Set-Content -LiteralPath (Join-Path $remoteTemp $workerName) -Value $WorkerScript -Encoding ASCII -WhatIf:$false
Set-Content -LiteralPath (Join-Path $remoteTemp $cmdName) -Value $cmdText -Encoding ASCII -WhatIf:$false
$outPath = Join-Path $remoteTemp $outName

try {
    & schtasks.exe /create /s $ComputerName /tn $taskName /ru SYSTEM /sc once /st 23:59 /f /tr "C:\Windows\Temp\$cmdName" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Не удалось создать задачу на $ComputerName (schtasks /create)." }
    & schtasks.exe /run /s $ComputerName /tn $taskName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Не удалось запустить задачу на $ComputerName (schtasks /run)." }

    Write-Host "Выполняется на $ComputerName..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $finished = $false
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $outPath) -and (Select-String -LiteralPath $outPath -Pattern '^EXIT=' -Quiet)) {
            $finished = $true
            break
        }
        [Threading.Thread]::Sleep(3000)
    }

    if (Test-Path -LiteralPath $outPath) {
        Get-Content -LiteralPath $outPath | ForEach-Object { Write-Host $_ }
    }
    if (-not $finished) {
        throw "Нет ответа за $TimeoutSeconds с. Журнал: $outPath"
    }
    $ok = Select-String -LiteralPath $outPath -Pattern '^EXIT=0' -Quiet
}
finally {
    & schtasks.exe /delete /s $ComputerName /tn $taskName /f 2>$null | Out-Null
    Remove-Item -LiteralPath (Join-Path $remoteTemp $workerName), (Join-Path $remoteTemp $cmdName) -Force -ErrorAction SilentlyContinue -WhatIf:$false
}

if (-not $ok) {
    Write-Host "Ошибка. Подробности выше и в $outPath" -ForegroundColor Red
    exit 1
}
if ($dryRun) {
    Write-Host "Проверка завершена. Запустите без -WhatIf, чтобы выполнить." -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "Готово. Пусть $NewUser войдёт на $ComputerName (или выполнит gpupdate /force в своём сеансе)." -ForegroundColor Green
    Write-Host "Через минуту клиент установится на него. Затем подтвердите компьютер в DistControl Central Admin, если появится заявка."
}
