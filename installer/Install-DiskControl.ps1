#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = $(if ([string]::IsNullOrWhiteSpace($env:DISTCONTROL_INSTALL_DIR)) { Join-Path $env:LOCALAPPDATA "Programs\DistControl" } else { $env:DISTCONTROL_INSTALL_DIR }),
    [Alias("DataDir")]
    [string]$ProgramDataDir = $(if ([string]::IsNullOrWhiteSpace($env:DISTCONTROL_DATA_DIR)) { Join-Path $env:LOCALAPPDATA "DistControl" } else { $env:DISTCONTROL_DATA_DIR }),
    [string]$ServiceName = "dkclient",
    [string]$ServiceDisplayName = "DistKontrolUSB Client",
    [string]$ServiceAccount = $env:DISKCONTROL_SERVICE_ACCOUNT,
    [string]$TargetUserSid = $env:DISTCONTROL_TARGET_USER_SID,
    [string]$TargetProfileDir = $env:DISTCONTROL_TARGET_PROFILE_DIR,
    [string]$TargetRoamingAppDataDir = $(if ([string]::IsNullOrWhiteSpace($env:DISTCONTROL_ROAMING_APPDATA_DIR)) { $env:APPDATA } else { $env:DISTCONTROL_ROAMING_APPDATA_DIR }),
    [string]$UserStartMenuDir = $(if ([string]::IsNullOrWhiteSpace($env:DISTCONTROL_START_MENU_DIR)) { Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\DistControl" } else { $env:DISTCONTROL_START_MENU_DIR }),
    [string]$UserDesktopDir = $(if ([string]::IsNullOrWhiteSpace($env:DISTCONTROL_DESKTOP_DIR)) { [Environment]::GetFolderPath("DesktopDirectory") } else { $env:DISTCONTROL_DESKTOP_DIR }),
    [string]$UsageStateDir = $env:DISKCONTROL_USAGE_STATE_DIR,
    [string]$ConfigureVpn = $env:DISKCONTROL_VPN_CONFIGURE,
    [string]$VpnProfileIdInput = $env:DISKCONTROL_VPN_ID,
    [string]$VpnName = $env:DISKCONTROL_VPN_NAME,
    [string]$VpnServer = $env:DISKCONTROL_VPN_SERVER,
    [string]$VpnPsk = $env:DISKCONTROL_VPN_PSK,
    [string]$VpnExpectedIp = $env:DISKCONTROL_VPN_EXPECTED_IP,
    [string]$VpnTokenIdentity = $env:DISKCONTROL_VPN_TOKEN,
    [string]$VpnProfilesFile = $env:DISKCONTROL_VPN_PROFILES_FILE,
    [securestring]$ServicePassword,
    [switch]$SkipBuild,
    [switch]$NoStartService,
    [switch]$NoDesktopShortcut,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
try {
    $script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $script:Utf8NoBomEncoding
    $OutputEncoding = $script:Utf8NoBomEncoding
}
catch {
}
$ProductName = "DistControl"
$ProductVersion = "0.6.3"
$Publisher = "DistControl"
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ReleaseDir = Join-Path $SourceRoot "build\x64\Release"
$PolicyPath = Join-Path $ProgramDataDir "allow.json"
$StateDir = Join-Path $ProgramDataDir "state"
$UsageStateRoot = if ([string]::IsNullOrWhiteSpace($UsageStateDir)) { $StateDir } else { $UsageStateDir.TrimEnd('\', '/') }
$UsageStatePath = Join-Path $UsageStateRoot "usage.json"
$LogsDir = Join-Path $ProgramDataDir "logs"
$InstallerDir = Join-Path $InstallDir "installer"
$ManagedHubRoutesPath = Join-Path $ProgramDataDir "managed-hub-routes.json"
$EffectiveTargetUserSid = if ([string]::IsNullOrWhiteSpace($TargetUserSid)) { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { $TargetUserSid.Trim() }
$TargetUserAcl = "*$EffectiveTargetUserSid"
$UserProgramsRoot = Split-Path -Parent $UserStartMenuDir
$ClientStartupShortcut = Join-Path $UserProgramsRoot "Startup\DistControl dkclient.lnk"
$UninstallRegistryPath = "Registry::HKEY_USERS\$EffectiveTargetUserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\DistControl"
$LegacyInstallDir = Join-Path $env:ProgramFiles "DiskControl"
$LegacyDistControlInstallDir = Join-Path $env:ProgramFiles "DistControl"
$LegacyProgramDataDir = Join-Path $env:ProgramData "DiskControl"
$LegacyLocalAppDataDir = if ([string]::IsNullOrWhiteSpace($TargetProfileDir)) { Join-Path $env:LOCALAPPDATA "DiskControl" } else { Join-Path $TargetProfileDir "AppData\Local\DiskControl" }
$LegacyUninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskControl"
$LegacyDistControlUninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DistControl"
$script:InstallLogPath = $null
$script:InstallWarnings = New-Object System.Collections.Generic.List[string]
$VpnProfileId = if ([string]::IsNullOrWhiteSpace($VpnProfileIdInput)) { "" } else { $VpnProfileIdInput.Trim() }

function Write-InstallLogLine([string]$Message) {
    if ([string]::IsNullOrWhiteSpace($script:InstallLogPath)) {
        return
    }

    try {
        $line = "[{0}] {1}{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message, [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:InstallLogPath, $line, $script:Utf8NoBomEncoding)
    }
    catch {
    }
}

function Write-Step([string]$Message) {
    Write-Host "[DistControl] $Message"
    Write-InstallLogLine "[DistControl] $Message"
}

function Assert-AbsoluteDirectoryParameter([string]$Name, [string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.TrimStart().StartsWith("-") -or
        -not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Name must be an absolute path. Got: $Path"
    }
}

function Assert-UsageStateDirectory {
    if ([string]::IsNullOrWhiteSpace($UsageStateRoot) -or
        $UsageStateRoot.TrimStart().StartsWith("-") -or
        -not [System.IO.Path]::IsPathRooted($UsageStateRoot)) {
        throw "UsageStateDir must be an absolute local or UNC folder path. Got: $UsageStateRoot"
    }
    if ($UsageStateRoot.EndsWith(".json", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "UsageStateDir must be a folder path, not usage.json: $UsageStateRoot"
    }
}

function Normalize-FullPath([string]$Path) {
    try {
        return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    }
    catch {
        return $Path.TrimEnd('\', '/')
    }
}

function Test-LocalProgramDataUsageStatePath {
    $defaultUsageStatePath = Join-Path $StateDir "usage.json"
    return [string]::Equals(
        (Normalize-FullPath $UsageStatePath),
        (Normalize-FullPath $defaultUsageStatePath),
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Write-InstallWarning([string]$Message) {
    $script:InstallWarnings.Add($Message) | Out-Null
    Write-Host "[DistControl] WARNING: $Message"
    Write-InstallLogLine "[DistControl] WARNING: $Message"
}

function Start-InstallLog {
    if ($DryRun) {
        return
    }

    try {
        New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
        $script:InstallLogPath = Join-Path $LogsDir ("install-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        [System.IO.File]::WriteAllText($script:InstallLogPath, "", $script:Utf8NoBomEncoding)
        Write-Step "Install log: $script:InstallLogPath"
    }
    catch {
        Write-Host "[DistControl] WARNING: Cannot start install log: $($_.Exception.Message)"
    }
}

function Stop-InstallLog {
}

function Convert-InstallErrorToHuman([string]$Message) {
    $lower = if ($Message) { $Message.ToLowerInvariant() } else { "" }
    if ($lower.Contains("administrator") -or
        $lower.Contains("access is denied") -or
        $lower.Contains("отказано в доступе") -or
        $lower.Contains("unauthorizedaccess")) {
        return "Не хватило прав. Запустите установку от имени администратора и проверьте права на локальные папки DistControl выбранного пользователя."
    }
    if ($lower.Contains("password") -or
        $lower.Contains("log on as a service") -or
        $lower.Contains("new-service") -or
        $lower.Contains("account") -or
        $lower.Contains("service account") -or
        $lower.Contains("неудача входа")) {
        return "Windows не смогла зарегистрировать или запустить службу под указанной учетной записью. Проверьте логин, пароль и право входа в качестве службы."
    }
    if ($lower.Contains("dkcl64.exe is still running") -or
        $lower.Contains("conflicting dkcl64.exe")) {
        return "Старый процесс dkcl64.exe не удалось остановить. Закройте DistControl, остановите службу dkclient или перезагрузите компьютер."
    }
    if ($lower.Contains("close distcontrol before installation")) {
        return "Перед обновлением закройте окна DistControl и DistControl Admin, затем запустите установщик ещё раз."
    }
    if ($lower.Contains("usage state") -or
        $lower.Contains("usagestatedir") -or
        $lower.Contains("network share") -or
        $lower.Contains("unc")) {
        return "Проблема с общей папкой таймеров usage.json. Проверьте путь и права чтения/записи."
    }
    if ($lower.Contains("pipe did not become ready") -or
        $lower.Contains("dkclient pipe")) {
        return "Служба dkclient запущена, но штатный клиент не подготовил канал управления. Проверьте доступность хабов из dkcl.ini и файлы профиля пользователя в AppData\Roaming."
    }
    if ($lower.Contains("service") -or
        $lower.Contains("start-service") -or
        $lower.Contains("running state")) {
        return "Служба dkclient не запустилась. Проверьте пароль учетной записи службы, dkcl.ini и журнал событий Windows."
    }
    if ($lower.Contains("required file") -or
        $lower.Contains("installer input")) {
        return "В установочном пакете не найден обязательный файл. Используйте свежий DistControl-Setup.exe."
    }
    if ($lower.Contains("route.exe") -or
        $lower.Contains("physical ipv4 default gateway") -or
        $lower.Contains("distkontrolusb hub route")) {
        return "Не удалось закрепить локальный маршрут к USB-хабам. Проверьте подключение к рабочей сети и повторите установку от имени администратора."
    }
    return "Установка остановилась из-за технической ошибки. Подробности ниже в этом журнале."
}

function Write-InstallErrorDetails([object]$Record) {
    $message = if ($Record -and $Record.Exception) { $Record.Exception.Message } else { "$Record" }
    $human = Convert-InstallErrorToHuman $message
    Write-Host "[DistControl] USER-ERROR: $human"
    Write-Host "[DistControl] ERROR: $message"
    Write-InstallLogLine "[DistControl] USER-ERROR: $human"
    Write-InstallLogLine "[DistControl] ERROR: $message"
    if ($Record -and $Record.Exception) {
        Write-InstallLogLine "[DistControl] ERROR TYPE: $($Record.Exception.GetType().FullName)"
    }
    if ($Record -and $Record.InvocationInfo) {
        Write-InstallLogLine "[DistControl] ERROR SCRIPT: $($Record.InvocationInfo.ScriptName)"
        Write-InstallLogLine "[DistControl] ERROR LINE: $($Record.InvocationInfo.ScriptLineNumber)"
        Write-InstallLogLine "[DistControl] ERROR COMMAND: $($Record.InvocationInfo.Line)"
    }
    if ($Record -and $Record.ScriptStackTrace) {
        Write-InstallLogLine "[DistControl] ERROR STACK: $($Record.ScriptStackTrace)"
    }
}

function Write-InstallEnvironmentSummary {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $identity = "<unknown>"
    }
    Write-Step "Environment: computer=$env:COMPUTERNAME; processUser=$identity; targetUserSid=$EffectiveTargetUserSid; targetProfile=$TargetProfileDir; installDir=$InstallDir; dataDir=$ProgramDataDir; policy=$PolicyPath; usage=$UsageStatePath; service=$ServiceName; serviceAccount=$ServiceAccount; source=$SourceRoot"
}

function Assert-TargetUserContext {
    if ($EffectiveTargetUserSid -notmatch '^S-1-(\d+-)+\d+$') {
        throw "TargetUserSid has an invalid value: $EffectiveTargetUserSid"
    }
    Assert-AbsoluteDirectoryParameter "TargetRoamingAppDataDir" $TargetRoamingAppDataDir
    Assert-AbsoluteDirectoryParameter "UserStartMenuDir" $UserStartMenuDir
    Assert-AbsoluteDirectoryParameter "UserDesktopDir" $UserDesktopDir
}

trap {
    Write-InstallErrorDetails $_
    Stop-InstallLog
    exit 1
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated Administrator console."
    }
}

function Invoke-External([string]$FilePath, [string[]]$Arguments) {
    if ($DryRun) {
        Write-Step "DRY-RUN: $FilePath $($Arguments -join ' ')"
        return
    }

    $output = & $FilePath @Arguments 2>&1
    foreach ($line in @($output)) {
        Write-Host $line
        Write-InstallLogLine "[external] $line"
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-ExternalOptional([string]$FilePath, [string[]]$Arguments, [string]$WarningPrefix) {
    if ($DryRun) {
        Write-Step "DRY-RUN: $FilePath $($Arguments -join ' ')"
        return
    }

    $output = & $FilePath @Arguments 2>&1
    foreach ($line in @($output)) {
        Write-Host $line
        Write-InstallLogLine "[external] $line"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-InstallWarning ("{0}: exit code {1}: {2} {3}" -f $WarningPrefix, $LASTEXITCODE, $FilePath, ($Arguments -join ' '))
    }
}

function Resolve-ShortcutTarget([string]$Target) {
    if ([string]::IsNullOrWhiteSpace($Target) -or $Target.TrimStart().StartsWith("-")) {
        throw "Shortcut target is invalid: $Target"
    }

    if ([System.IO.Path]::IsPathRooted($Target)) {
        return [System.IO.Path]::GetFullPath($Target)
    }

    $command = Get-Command $Target -ErrorAction SilentlyContinue
    if ($command -and $command.Source) {
        return $command.Source
    }

    throw "Shortcut target must be an absolute path or resolvable command: $Target"
}

function Resolve-ShortcutWorkingDirectory([string]$WorkingDirectory, [string]$Target) {
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        return Split-Path -Parent $Target
    }

    if ($WorkingDirectory.TrimStart().StartsWith("-") -or -not [System.IO.Path]::IsPathRooted($WorkingDirectory)) {
        throw "Shortcut working directory must be an absolute path. Got: $WorkingDirectory"
    }

    return [System.IO.Path]::GetFullPath($WorkingDirectory)
}

function Try-StartService([string]$Name) {
    Write-Step "Start service $Name"
    if ($DryRun) {
        return
    }

    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        if ($service.Status -eq "Running") {
            Write-Step "Service $Name is already running"
            return
        }

        Start-Service -Name $Name -ErrorAction Stop
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(20))
        $service.Refresh()
        if ($service.Status -ne "Running") {
            throw "Service status is $($service.Status)."
        }
        Write-Step "Service $Name is running"
    }
    catch {
        throw ("Service {0} was installed but did not reach Running state: {1}. Check the account password, Log on as a service right, dkcl.ini, and Windows Event Viewer." -f $Name, $_.Exception.Message)
    }
}

function Wait-ServiceDeleted([string]$Name) {
    if ($DryRun) {
        return
    }

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "Service $Name is still present after delete request. Close Services.msc or related service windows and retry."
}

function Stop-ExistingService([string]$Name) {
    $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $existing -or $existing.Status -eq "Stopped") {
        return
    }

    Write-Step "Stop service $Name"
    if (-not $DryRun) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            Start-Sleep -Milliseconds 500
            $existing.Refresh()
            if ($existing.Status -eq "Stopped") {
                return
            }
        }
        throw "Service $Name did not stop in time."
    }
}

function Remove-ExistingService([string]$Name) {
    $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        return
    }

    Write-Step "Remove existing service $Name"
    Stop-ExistingService $Name

    if ($DryRun) {
        Write-Step "DRY-RUN: sc.exe delete $Name"
    }
    else {
        & sc.exe delete $Name
        if ($LASTEXITCODE -eq 1072) {
            Write-Step "Service $Name is already marked for deletion"
        }
        elseif ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: sc.exe delete $Name"
        }
    }
    Wait-ServiceDeleted $Name
}

function Stop-InstalledDkClientProcess {
    if ($DryRun) {
        Write-Step "DRY-RUN: stop all dkcl64.exe processes before service registration"
        return
    }

    try {
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            $processes = @(Get-Process -Name "dkcl64" -ErrorAction SilentlyContinue)
            if ($processes.Count -eq 0) {
                return
            }

            Write-Step "Stop conflicting dkcl64.exe processes, attempt $attempt, count=$($processes.Count)"
            foreach ($process in $processes) {
                $path = try { $process.Path } catch { $null }
                $displayPath = if ($path) { $path } else { "<protected process>" }
                Write-Step "Stop conflicting dkcl64.exe process $($process.Id): $displayPath"
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }

            Start-Sleep -Milliseconds 500
        }

        $remaining = @(Get-Process -Name "dkcl64" -ErrorAction SilentlyContinue)
        if ($remaining.Count -gt 0) {
            throw "dkcl64.exe is still running after stop attempts. Remaining processes: $($remaining.Count)"
        }
    }
    catch {
        throw ("Cannot stop a conflicting dkcl64.exe process before service registration: {0}" -f $_.Exception.Message)
    }
}

function Remove-DkClientStartup {
    if (-not (Test-Path -LiteralPath $ClientStartupShortcut)) {
        return
    }

    Write-Step "Remove client startup shortcut"
    if (-not $DryRun) {
        Remove-Item -LiteralPath $ClientStartupShortcut -Force
    }
}

function Resolve-DefaultServiceAccount {
    try {
        return [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        if ($env:USERDOMAIN -and $env:USERNAME) {
            return "$env:USERDOMAIN\$env:USERNAME"
        }
        return $env:USERNAME
    }
}

function Resolve-ServiceCredential {
    $account = $ServiceAccount
    if ([string]::IsNullOrWhiteSpace($account)) {
        $account = Resolve-DefaultServiceAccount
    }

    $password = $ServicePassword
    $checkedBySetup = $false
    if (-not $password -and -not [string]::IsNullOrEmpty($env:DISKCONTROL_SERVICE_PASSWORD)) {
        # DistControl-Setup.exe has already checked this password.
        $password = ConvertTo-SecureString $env:DISKCONTROL_SERVICE_PASSWORD -AsPlainText -Force
        $checkedBySetup = $true
    }

    if (-not $password) {
        if ($DryRun) {
            Write-Step "DRY-RUN: service account would be $account"
            return $null
        }

        Write-Host ""
        Write-Host "DistControl will run dkclient service as: $account"
        Write-Host "Enter this Windows account password. It is passed to Windows Service Control Manager."
        $wrongAttempts = 0
        while ($true) {
            $password = Read-Host -Prompt "Password for $account" -AsSecureString
            if (-not $password -or $password.Length -eq 0) {
                throw "Service account password is required."
            }
            if (Test-ServiceAccountPassword $account $password ([ref]$wrongAttempts) -AllowRetry) {
                break
            }
        }
        $checkedBySetup = $true
    }

    if (-not $password) {
        throw "Service account password is required."
    }
    if (-not $checkedBySetup -and -not $DryRun) {
        $ignored = 0
        [void](Test-ServiceAccountPassword $account $password ([ref]$ignored))
    }

    return New-Object System.Management.Automation.PSCredential($account, $password)
}

# Checks the password with a network logon right after it is entered. Returns
# $true to continue, $false to ask again; throws when installation must stop.
# Only wrong passwords count towards the limit (the domain lockout policy
# counts them too).
function Test-ServiceAccountPassword([string]$Account, [securestring]$Password, [ref]$WrongAttempts, [switch]$AllowRetry) {
    if (-not ("CredentialCheck" -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot "CredentialCheck.cs")
    }
    $plain = [IntPtr]::Zero
    $logonError = 0
    try {
        $plain = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Password)
        $logonError = [CredentialCheck]::Validate($Account, [Runtime.InteropServices.Marshal]::PtrToStringUni($plain))
    }
    finally {
        if ($plain -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($plain)
        }
    }
    $result = [CredentialCheck]::Classify($logonError)
    $message = [CredentialCheck]::Message($result, $Account, $logonError)
    if ($result -eq [CredentialCheckResult]::Valid) {
        Write-Step "Service account password checked"
        return $true
    }
    if ([CredentialCheck]::CountsAsWrongPassword($result)) {
        $WrongAttempts.Value++
        Write-InstallLogLine "[DistControl] Service account password check failed: wrong password, attempt $($WrongAttempts.Value)"
        if (-not $AllowRetry -or $WrongAttempts.Value -ge [CredentialCheck]::MaximumWrongPasswordAttempts) {
            throw "$message Installation stopped after $($WrongAttempts.Value) wrong attempt(s) so that the account is not locked by the domain policy."
        }
        Write-Host "$message Attempts left: $([CredentialCheck]::MaximumWrongPasswordAttempts - $WrongAttempts.Value)."
        return $false
    }
    if ([CredentialCheck]::MayContinueUnverified($result)) {
        Write-InstallWarning "$message Installation continues without a password check; the service will not start if the password is wrong."
        return $true
    }
    throw $message
}

function Resolve-PrivilegeIdentity([string]$Account) {
    try {
        $sid = (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier])
        return "*" + $sid.Value
    }
    catch {
        Write-InstallWarning ("Cannot resolve service account '{0}' to SID. secedit will try the account name directly: {1}" -f $Account, $_.Exception.Message)
        return $Account
    }
}

function Grant-LogonAsServiceRight([string]$Account) {
    Write-Step "Grant 'Log on as a service' to $Account"
    if ($DryRun) {
        return
    }

    $identity = Resolve-PrivilegeIdentity $Account
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("DiskControl-SeServiceLogonRight-" + [Guid]::NewGuid().ToString("N"))
    [System.IO.Directory]::CreateDirectory($tempDir) | Out-Null
    $exportPath = Join-Path $tempDir "export.inf"
    $importPath = Join-Path $tempDir "import.inf"
    $databasePath = Join-Path $tempDir "secedit.sdb"

    try {
        & secedit.exe /export /cfg $exportPath /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "secedit export failed with exit code $LASTEXITCODE"
        }

        $existingLine = Get-Content -LiteralPath $exportPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "^\s*SeServiceLogonRight\s*=" } |
            Select-Object -First 1

        $values = @()
        if ($existingLine) {
            $raw = ($existingLine -split "=", 2)[1]
            $values = @($raw -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }

        $alreadyPresent = $false
        foreach ($value in $values) {
            if ([string]::Equals($value, $identity, [StringComparison]::OrdinalIgnoreCase)) {
                $alreadyPresent = $true
                break
            }
        }

        if (-not $alreadyPresent) {
            $values += $identity
        }

        $rightLine = "SeServiceLogonRight = " + ($values -join ",")
        $content = @(
            "[Unicode]",
            "Unicode=yes",
            "[Version]",
            'signature="$CHICAGO$"',
            "Revision=1",
            "[Privilege Rights]",
            $rightLine
        )
        Set-Content -LiteralPath $importPath -Encoding Unicode -Value $content

        & secedit.exe /configure /db $databasePath /cfg $importPath /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "secedit configure failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        try {
            if ([System.IO.Directory]::Exists($tempDir)) {
                [System.IO.Directory]::Delete($tempDir, $true)
            }
        }
        catch {
            Write-InstallWarning ("Cannot remove temporary secedit directory '{0}': {1}" -f $tempDir, $_.Exception.Message)
        }
    }
}

function Copy-RequiredFile([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Required file not found: $Source"
    }
    Write-Step "Copy $Source -> $Destination"
    if (-not $DryRun) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
}

function Test-ValidPolicy([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        return $false
    }

    try {
        $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        return $null -ne $json.userAssignments
    }
    catch {
        return $false
    }
}

function New-EmptyPolicyText {
@"
{
  "pipeName": "dkclient",
  "refreshSeconds": 5,
  "usageStatePath": "$(($UsageStatePath -replace '\\', '\\'))",
  "vpnProfiles": [],
  "userAssignments": []
}
"@
}

function Test-VpnConfigurationRequested {
    return [string]::Equals($ConfigureVpn, "1", [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($ConfigureVpn, "true", [StringComparison]::OrdinalIgnoreCase)
}

function ConvertFrom-VpnInstallField([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

function ConvertFrom-VpnInstallSecret([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }
    if (-not $script:VpnCryptographyLoaded) {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
        $script:VpnCryptographyLoaded = $true
    }
    $encrypted = [Convert]::FromBase64String($Value)
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
        return [Text.Encoding]::UTF8.GetString($plain)
    }
    finally {
        [Array]::Clear($plain, 0, $plain.Length)
    }
}

function Get-VpnInstallProfiles {
    $profiles = @()
    if (-not [string]::IsNullOrWhiteSpace($VpnProfilesFile)) {
        if (-not (Test-Path -LiteralPath $VpnProfilesFile)) {
            throw "VPN profiles input file does not exist: $VpnProfilesFile"
        }
        foreach ($line in [System.IO.File]::ReadAllLines($VpnProfilesFile, [Text.Encoding]::UTF8)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            $fields = $line.Split([char]9)
            if ($fields.Count -ne 6 -and $fields.Count -ne 7) {
                throw "VPN profiles input contains an invalid record."
            }
            $profiles += [pscustomobject]@{
                Id = ConvertFrom-VpnInstallField $fields[0]
                Name = ConvertFrom-VpnInstallField $fields[1]
                Server = ConvertFrom-VpnInstallField $fields[2]
                Psk = ConvertFrom-VpnInstallSecret $fields[3]
                ExpectedIpsText = ConvertFrom-VpnInstallField $fields[4]
                TokenIdentity = ConvertFrom-VpnInstallField $fields[5]
            }
        }
        $ids = @{}
        $names = @{}
        foreach ($profile in $profiles) {
            Assert-VpnInstallProfile $profile
            $idKey = $profile.Id.Trim().ToLowerInvariant()
            $nameKey = $profile.Name.Trim().ToLowerInvariant()
            if ($ids.ContainsKey($idKey)) {
                throw "VPN profile ID is duplicated: $($profile.Id)"
            }
            if ($names.ContainsKey($nameKey)) {
                throw "Windows VPN connection name is duplicated: $($profile.Name)"
            }
            $ids[$idKey] = $true
            $names[$nameKey] = $true
        }
        return $profiles
    }

    if (Test-VpnConfigurationRequested) {
        $profiles += [pscustomobject]@{
            Id = $VpnProfileId
            Name = $VpnName
            Server = $VpnServer
            Psk = $VpnPsk
            ExpectedIpsText = $VpnExpectedIp
            TokenIdentity = $VpnTokenIdentity
        }
    }
    return $profiles
}

function Get-VpnExpectedIps([object]$Profile) {
    return @(([string]$Profile.ExpectedIpsText -split '[,;\r\n]') |
        ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Assert-VpnInstallProfile([object]$Profile) {
    if ([string]::IsNullOrWhiteSpace($Profile.Id) -or
        [string]::IsNullOrWhiteSpace($Profile.Name) -or
        [string]::IsNullOrWhiteSpace($Profile.Server) -or
        [string]::IsNullOrWhiteSpace($Profile.Psk)) {
        throw "Each VPN profile requires ID, Windows name, server and pre-shared key."
    }
    if ($Profile.Id -notmatch '^[A-Za-z0-9._-]+$') {
        throw "VPN profile ID contains unsupported characters: $($Profile.Id)"
    }
    $expectedIps = Get-VpnExpectedIps $Profile
    if ($expectedIps.Count -eq 0) {
        throw "VPN profile '$($Profile.Id)' requires at least one expected public IP."
    }
    foreach ($expectedIp in $expectedIps) {
        $parsedIp = $null
        if (-not [Net.IPAddress]::TryParse($expectedIp, [ref]$parsedIp)) {
            throw "VPN expected public IP is invalid for profile '$($Profile.Id)': $expectedIp"
        }
    }
}

function Install-VpnProfiles([object[]]$Profiles) {
    throw "DistControl installer does not create or update Windows VPN profiles. Configure them in Windows and assign them in DistControl Admin."
}

function Assert-DistControlApplicationsClosed {
    if ($DryRun) {
        Write-Step "DRY-RUN: check that DistControl and DistControl Admin are closed"
        return
    }

    $installRoots = @($InstallDir, $LegacyInstallDir, $LegacyDistControlInstallDir) |
        ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }
    $running = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in @("DistControl.exe", "DistControl.Admin.exe", "DiskControl.exe", "DiskControl.Admin.exe") -and
            $_.ExecutablePath -and
            ($installRoots | Where-Object { $_.ExecutablePath.StartsWith($_ + "\", [StringComparison]::OrdinalIgnoreCase) })
        })
    if ($running.Count -gt 0) {
        $names = ($running | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }) -join ", "
        throw "Close DistControl before installation. Running applications: $names"
    }
}

function Copy-MigrationFile([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source) -or (Test-Path -LiteralPath $Destination)) {
        return
    }

    Write-Step "Migrate $Source -> $Destination"
    if ($DryRun) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Merge-MigrationLogs([string]$SourceDirectory) {
    if (-not (Test-Path -LiteralPath $SourceDirectory)) {
        return
    }

    foreach ($file in @(Get-ChildItem -LiteralPath $SourceDirectory -File -ErrorAction SilentlyContinue)) {
        Copy-MigrationFile $file.FullName (Join-Path $LogsDir $file.Name)
    }
}

function Test-DkClientPipeReady([string]$Name, [int]$Attempts = 15) {
    Write-Step "Check that dkclient is ready to return the token list"
    if ($DryRun) {
        Write-Step "DRY-RUN: connect to \\.\pipe\$Name and send LIST"
        return
    }

    $lastReason = "канал ещё не создан"
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $pipe = $null
        try {
            $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
                ".", $Name,
                [System.IO.Pipes.PipeDirection]::InOut,
                [System.IO.Pipes.PipeOptions]::Asynchronous)
            $pipe.Connect(1000)
            try {
                $pipe.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Message
            }
            catch {
            }

            $request = [Text.Encoding]::UTF8.GetBytes("LIST")
            $pipe.Write($request, 0, $request.Length)
            $pipe.Flush()

            $buffer = New-Object byte[] (1024 * 1024)
            $readTask = $pipe.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait(3000)) {
                throw "ответ на LIST не получен за 3 секунды"
            }
            $read = $readTask.Result
            if ($read -le 0) {
                throw "получен пустой ответ на LIST"
            }

            Write-Step "dkclient is ready: token list received"
            return
        }
        catch {
            $lastReason = $_.Exception.Message
            Write-Step "dkclient is not ready yet, attempt $attempt of ${Attempts}: $lastReason"
            Start-Sleep -Milliseconds 700
        }
        finally {
            if ($pipe) {
                $pipe.Dispose()
            }
        }
    }

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $serviceStatus = if ($service) { $service.Status } else { "NotFound" }
    # Installation is complete at this point; the service often needs a restart
    # of Windows or a new sign-in after the USB driver was installed.
    Write-InstallWarning (("Служба dkclient пока не отдала список токенов (состояние: {0}; причина: {1}). " +
        "Установка завершена; перезагрузите компьютер или войдите в Windows заново и откройте DistControl. " +
        "Если токены не появятся, запустите diagnose.cmd.") -f $serviceStatus, $lastReason)
}

function Migrate-LegacyData {
    Write-Step "Check legacy DiskControl data"
    Copy-MigrationFile (Join-Path $LegacyProgramDataDir "allow.json") $PolicyPath
    Copy-MigrationFile (Join-Path $LegacyProgramDataDir "usage.json") $UsageStatePath
    Copy-MigrationFile (Join-Path $LegacyProgramDataDir "managed-hub-routes.json") $ManagedHubRoutesPath
    Copy-MigrationFile (Join-Path $LegacyLocalAppDataDir "network-state.json") (Join-Path $StateDir "network-state.json")
    Merge-MigrationLogs (Join-Path $LegacyProgramDataDir "logs")
    Merge-MigrationLogs (Join-Path $LegacyLocalAppDataDir "logs")
}

function Initialize-DkClientUserProfile {
    $sourceConfig = Join-Path $InstallDir "dkcl.ini"
    $profileConfig = Join-Path $TargetRoamingAppDataDir "dkcl.ini"
    $profileMarker = Join-Path $TargetRoamingAppDataDir "dkcl64.ini"
    Write-Step "Prepare DistKontrolUSB settings for the selected Windows user"

    if ($DryRun) {
        Write-Step "DRY-RUN: copy $sourceConfig -> $profileConfig"
        Write-Step "DRY-RUN: create $profileMarker"
    }
    else {
        New-Item -ItemType Directory -Path $TargetRoamingAppDataDir -Force | Out-Null
        if (-not (Test-Path -LiteralPath $profileConfig)) {
            Copy-Item -LiteralPath $sourceConfig -Destination $profileConfig -Force
        }
        if (-not (Test-Path -LiteralPath $profileMarker)) {
            [System.IO.File]::WriteAllText($profileMarker, "", $script:Utf8NoBomEncoding)
        }
    }

    foreach ($path in @($profileConfig, $profileMarker)) {
        Set-ProtectedAcl $path @(
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            "${TargetUserAcl}:M"
        )
    }
}

function Preserve-ConfiguredUsageStatePath {
    if (-not [string]::IsNullOrWhiteSpace($UsageStateDir) -or -not (Test-ValidPolicy $PolicyPath)) {
        return
    }

    try {
        $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $configuredPath = [string]$policy.usageStatePath
        $legacyDefaults = @(
            (Join-Path $LegacyProgramDataDir "usage.json"),
            (Join-Path $LegacyLocalAppDataDir "usage.json")
        )
        if ([string]::IsNullOrWhiteSpace($configuredPath) -or
            $legacyDefaults -contains $configuredPath) {
            return
        }

        $script:UsageStatePath = $configuredPath
        $script:UsageStateRoot = Split-Path -Parent $configuredPath
        Write-Step "Keep configured external usage state path: $configuredPath"
    }
    catch {
        Write-InstallWarning "Cannot preserve usageStatePath from migrated policy: $($_.Exception.Message)"
    }
}

function Get-DistKontrolManualHubAddresses([string]$IniPath) {
    if (-not (Test-Path -LiteralPath $IniPath)) {
        return @()
    }

    $settingsSection = $false
    $rawValue = $null
    foreach ($line in [System.IO.File]::ReadAllLines($IniPath)) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("[") -and $trimmed.EndsWith("]")) {
            $settingsSection = [string]::Equals(
                $trimmed.Trim('[', ']'),
                "Settings",
                [StringComparison]::OrdinalIgnoreCase)
            continue
        }
        if ($settingsSection -and $trimmed -match '^ManualHubs\s*=\s*(.*)$') {
            $rawValue = $Matches[1]
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return @()
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    foreach ($endpoint in @($rawValue -split ',')) {
        $value = $endpoint.Trim()
        if ($value -notmatch '^([^:]+)(?::\d+)?$') {
            Write-InstallWarning "Cannot create a local route for invalid ManualHubs entry: $value"
            continue
        }

        $addressText = $Matches[1].Trim()
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$address) -or
            $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            Write-InstallWarning "Cannot create a local route for non-IPv4 ManualHubs entry: $value"
            continue
        }
        if (-not $addresses.Contains($addressText)) {
            $addresses.Add($addressText)
        }
    }
    return @($addresses)
}

function Get-PhysicalDefaultRoute {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
        Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric)
    foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq "Up" -and $adapter.HardwareInterface) {
            return $route
        }
    }
    return $null
}

function Remove-PreviouslyManagedHubRoutes {
    if (-not (Test-Path -LiteralPath $ManagedHubRoutesPath)) {
        return
    }

    try {
        $manifest = Get-Content -LiteralPath $ManagedHubRoutesPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($route in @($manifest.routes)) {
            $destination = [string]$route.destination
            $gateway = [string]$route.gateway
            $interfaceIndex = [int]$route.interfaceIndex
            if ([string]::IsNullOrWhiteSpace($destination) -or
                [string]::IsNullOrWhiteSpace($gateway) -or
                $interfaceIndex -le 0) {
                continue
            }

            Write-Step "Remove previously managed hub route: $destination/32 via $gateway if $interfaceIndex"
            if (-not $DryRun) {
                $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$destination/32" -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -eq $gateway -and $_.ifIndex -eq $interfaceIndex })
                if ($existing.Count -gt 0) {
                    Invoke-ExternalOptional "route.exe" @(
                        "delete", $destination, "mask", "255.255.255.255", $gateway, "if", "$interfaceIndex"
                    ) "Cannot remove the previous managed route to DistKontrolUSB hub $destination"
                }
            }
        }
    }
    catch {
        Write-InstallWarning "Cannot read or remove the previous managed hub routes: $($_.Exception.Message)"
    }

    if (-not $DryRun) {
        Remove-Item -LiteralPath $ManagedHubRoutesPath -Force -ErrorAction SilentlyContinue
    }
}

function Write-ManagedHubRouteManifest([System.Collections.IEnumerable]$Routes) {
    if ($DryRun) {
        return
    }
    $manifest = [ordered]@{
        version = 1
        createdAt = (Get-Date).ToString("o")
        routes = @($Routes)
    }
    [System.IO.File]::WriteAllText(
        $ManagedHubRoutesPath,
        ($manifest | ConvertTo-Json -Depth 4),
        $script:Utf8NoBomEncoding)
}

function Set-DistKontrolHubRoutes([string]$IniPath) {
    $hubAddresses = @(Get-DistKontrolManualHubAddresses $IniPath)
    if ($hubAddresses.Count -eq 0) {
        Write-InstallWarning "No IPv4 addresses were found in dkcl.ini ManualHubs. Full-tunnel VPN may block access to DistKontrolUSB hubs."
        return
    }

    if ($DryRun) {
        Write-Step "DRY-RUN: inspect the physical gateway and configure routes for $($hubAddresses.Count) DistKontrolUSB hubs"
        return
    }

    $physicalRoute = Get-PhysicalDefaultRoute
    if (-not $physicalRoute) {
        Write-InstallWarning "A physical IPv4 default gateway was not found. Routes to DistKontrolUSB hubs were not created."
        return
    }

    $gateway = [string]$physicalRoute.NextHop
    $interfaceIndex = [int]$physicalRoute.ifIndex
    Write-Step "Configure local routes to DistKontrolUSB hubs: gateway=$gateway; interface=$($physicalRoute.InterfaceAlias); ifIndex=$interfaceIndex; hubs=$($hubAddresses.Count)"

    Remove-PreviouslyManagedHubRoutes
    $managedRoutes = New-Object System.Collections.Generic.List[object]
    foreach ($address in $hubAddresses) {
        $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$address/32" -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $gateway -and $_.ifIndex -eq $interfaceIndex })
        if ($existing.Count -gt 0) {
            Write-Step "Keep existing route to DistKontrolUSB hub: $address/32 via $gateway if $interfaceIndex"
            continue
        }

        Write-Step "Add persistent route to DistKontrolUSB hub: $address/32 via $gateway if $interfaceIndex"
        if (-not $DryRun) {
            Invoke-External "route.exe" @(
                "-p", "add", $address, "mask", "255.255.255.255", $gateway,
                "metric", "1", "if", "$interfaceIndex"
            )
        }
        $managedRoutes.Add([ordered]@{
            destination = $address
            gateway = $gateway
            interfaceIndex = $interfaceIndex
        })
        Write-ManagedHubRouteManifest $managedRoutes
    }

    Write-ManagedHubRouteManifest $managedRoutes
}

function Set-PolicyVpnConfigurations([object[]]$InstallProfiles) {
    if ($InstallProfiles.Count -eq 0) {
        return
    }
    Write-Step "Configure VPN policy metadata: profiles=$($InstallProfiles.Count)"

    try {
        if (Test-Path -LiteralPath $PolicyPath) {
            $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        elseif ($DryRun) {
            $policy = [pscustomobject]@{
                pipeName = "dkclient"
                refreshSeconds = 5
                usageStatePath = $UsageStatePath
                userAssignments = @()
            }
        }
        else {
            throw "Policy file does not exist: $PolicyPath"
        }

        $profiles = @()
        foreach ($existingProfile in @($policy.vpnProfiles)) {
            if ($existingProfile) {
                $profiles += $existingProfile
            }
        }

        foreach ($installProfile in $InstallProfiles) {
            $profile = [pscustomobject]@{
                id = $installProfile.Id
                name = $installProfile.Name
                serverAddress = $installProfile.Server
                tunnelType = "L2TP"
                expectedPublicIps = @(Get-VpnExpectedIps $installProfile)
                ipCheckUrl = "https://api.ipify.org"
                enabled = $true
            }
            $updatedProfiles = @()
            $replaced = $false
            foreach ($existingProfile in $profiles) {
                if ([string]::Equals([string]$existingProfile.id, [string]$installProfile.Id, [StringComparison]::OrdinalIgnoreCase)) {
                    $updatedProfiles += $profile
                    $replaced = $true
                    }
                else {
                    $updatedProfiles += $existingProfile
                }
            }
            if (-not $replaced) {
                $updatedProfiles += $profile
            }
            $profiles = $updatedProfiles

            $mapped = 0
            if (-not [string]::IsNullOrWhiteSpace($installProfile.TokenIdentity)) {
                foreach ($assignment in @($policy.userAssignments)) {
                    foreach ($device in @($assignment.allowedDevices)) {
                        $matches = [string]::Equals([string]$device.endpoint, [string]$installProfile.TokenIdentity, [StringComparison]::OrdinalIgnoreCase) -or
                            [string]::Equals([string]$device.nickname, [string]$installProfile.TokenIdentity, [StringComparison]::OrdinalIgnoreCase)
                        if (-not $matches) {
                            continue
                        }
                        if ($device.PSObject.Properties["vpnProfile"]) {
                            $device.vpnProfile = $installProfile.Id
                        }
                        else {
                            $device | Add-Member -MemberType NoteProperty -Name "vpnProfile" -Value $installProfile.Id
                        }
                        $mapped++
                    }
                }
                if ($mapped -eq 0) {
                    Write-InstallWarning "VPN profile was created, but token '$($installProfile.TokenIdentity)' was not found in current allow.json. Assign it later in DistControl Admin."
                }
            }
        }

        if ($policy.PSObject.Properties["vpnProfiles"]) {
            $policy.vpnProfiles = $profiles
        }
        else {
            $policy | Add-Member -MemberType NoteProperty -Name "vpnProfiles" -Value $profiles
        }

        $text = $policy | ConvertTo-Json -Depth 32
        if (-not $DryRun) {
            [System.IO.File]::WriteAllText($PolicyPath, $text + [Environment]::NewLine, $script:Utf8NoBomEncoding)
        }
    }
    catch {
        throw "Cannot update VPN metadata in policy $PolicyPath`: $($_.Exception.Message)"
    }
}

function Initialize-Policy {
    if (Test-ValidPolicy $PolicyPath) {
        Write-Step "Keep existing policy: $PolicyPath"
        return
    }

    if ((Test-Path -LiteralPath $PolicyPath) -and ((Get-Item -LiteralPath $PolicyPath).Length -gt 0)) {
        $backup = "$PolicyPath.invalid-$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
        Write-Step "Backup invalid policy to $backup"
        if (-not $DryRun) {
            Copy-Item -LiteralPath $PolicyPath -Destination $backup -Force
        }
    }

    # Only an explicitly supplied allowlist.json may seed a production install.
    # The example contains demonstration assignments and must never grant access.
    $seedCandidates = @((Join-Path $SourceRoot "allowlist.json"))

    foreach ($seed in $seedCandidates) {
        if ((Test-Path -LiteralPath $seed) -and (Test-ValidPolicy $seed)) {
            Write-Step "Create policy from $seed"
            if (-not $DryRun) {
                Copy-Item -LiteralPath $seed -Destination $PolicyPath -Force
            }
            return
        }
    }

    Write-Step "Create empty policy: $PolicyPath"
    if (-not $DryRun) {
        Set-Content -LiteralPath $PolicyPath -Encoding UTF8 -Value (New-EmptyPolicyText)
    }
}

function Set-PolicyUsageStatePath {
    Write-Step "Configure usage state path: $UsageStatePath"
    if ($DryRun) {
        return
    }

    try {
        $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $property = $policy.PSObject.Properties["usageStatePath"]
        if ($property) {
            $property.Value = $UsageStatePath
        }
        else {
            $policy | Add-Member -MemberType NoteProperty -Name "usageStatePath" -Value $UsageStatePath
        }

        $text = $policy | ConvertTo-Json -Depth 32
        [System.IO.File]::WriteAllText($PolicyPath, $text + [Environment]::NewLine, $script:Utf8NoBomEncoding)
    }
    catch {
        throw "Cannot update usageStatePath in policy $PolicyPath`: $($_.Exception.Message)"
    }
}

function Initialize-UsageState {
    if ($DryRun) {
        Write-Step "DRY-RUN: initialize usage state: $UsageStatePath"
        return
    }

    if (Test-Path -LiteralPath $UsageStatePath) {
        Write-Step "Keep existing usage state: $UsageStatePath"
        return
    }

    Write-Step "Create usage state: $UsageStatePath"
    Set-Content -LiteralPath $UsageStatePath -Encoding UTF8 -Value "{`n  `"active`": []`n}"
}

function Test-UsageStateAccess {
    Write-Step "Validate usage state access: $UsageStatePath"
    if ($DryRun) {
        return
    }

    try {
        $stream = [System.IO.File]::Open($UsageStatePath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        $stream.Close()
    }
    catch {
        throw "Cannot read/write usage state file $UsageStatePath. Check network share and NTFS permissions: $($_.Exception.Message)"
    }
}

function Test-DirectoryPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    return (Get-Item -LiteralPath $Path -Force).PSIsContainer
}

function Repair-AclControl([string]$Path, [switch]$Recursive) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $arguments = @("/F", $Path, "/A")
    if ($Recursive -and (Test-DirectoryPath $Path)) {
        $arguments += @("/R", "/D", "Y")
    }

    if ($DryRun) {
        Write-Step "DRY-RUN: takeown.exe $($arguments -join ' ')"
        return
    }

    & takeown.exe @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-InstallWarning ("Cannot take ownership of {0}: exit code {1}" -f $Path, $LASTEXITCODE)
    }
}

function Set-ProtectedAcl([string]$Path, [string[]]$Grants, [switch]$Recursive) {
    Repair-AclControl $Path -Recursive:$Recursive

    # Add explicit rights before removing inherited ACEs. Some hosts drop admin write
    # access when inheritance is removed first, which makes the next icacls call fail.
    $grantArguments = @($Path, "/grant:r") + $Grants
    if ($Recursive -and (Test-DirectoryPath $Path)) {
        $grantArguments += @("/T", "/C")
    }

    Invoke-External "icacls.exe" $grantArguments
    Invoke-External "icacls.exe" @($Path, "/inheritance:r")
    Invoke-External "icacls.exe" $grantArguments
}

function Set-DirectoryAcl {
    Write-Step "Configure ACL"

    Set-ProtectedAcl $InstallDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "${TargetUserAcl}:(OI)(CI)RX"
    ) -Recursive

    Set-ProtectedAcl $ProgramDataDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)M",
        "${TargetUserAcl}:(OI)(CI)RX"
    ) -Recursive

    Set-ProtectedAcl $LogsDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)M",
        "${TargetUserAcl}:(OI)(CI)M"
    ) -Recursive

    Set-ProtectedAcl $StateDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)M",
        "${TargetUserAcl}:(OI)(CI)M"
    ) -Recursive

    Set-ProtectedAcl $PolicyPath @(
        "*S-1-5-18:F",
        "*S-1-5-32-544:M",
        "${TargetUserAcl}:R"
    )

    if (Test-LocalProgramDataUsageStatePath) {
        Set-ProtectedAcl $UsageStatePath @(
            "*S-1-5-18:F",
            "*S-1-5-32-544:M",
            "${TargetUserAcl}:M"
        )
    }
    else {
        Write-Step "Skip ACL rewrite for external usage state path: $UsageStatePath"
    }
}

function Set-DkClientFilesAcl {
    $exePath = Join-Path $InstallDir "dkcl64.exe"
    $iniPath = Join-Path $InstallDir "dkcl.ini"
    $identity = Resolve-PrivilegeIdentity "NT SERVICE\$ServiceName"
    Write-Step "Restrict dkcl64.exe and dkcl.ini to the dkclient service SID"
    Set-ProtectedAcl $exePath @(
        "*S-1-5-18:F",
        "*S-1-5-32-544:F",
        "${identity}:RX"
    )
    Set-ProtectedAcl $iniPath @(
        "*S-1-5-18:F",
        "*S-1-5-32-544:F",
        "${identity}:R"
    )
}

function New-Shortcut([string]$Path, [string]$Target, [string]$Arguments = "", [string]$WorkingDirectory = $InstallDir) {
    Write-Step "Create shortcut $Path"
    if ($DryRun) {
        return
    }

    $resolvedTarget = Resolve-ShortcutTarget $Target
    $resolvedWorkingDirectory = Resolve-ShortcutWorkingDirectory $WorkingDirectory $resolvedTarget
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $resolvedTarget
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $resolvedWorkingDirectory
    $shortcut.Save()

    $saved = $shell.CreateShortcut($Path)
    if ($saved.TargetPath -ne $resolvedTarget) {
        throw "Shortcut verification failed for $Path. Expected target: $resolvedTarget. Actual target: $($saved.TargetPath)"
    }
}

function Install-Shortcuts {
    $startMenu = $UserStartMenuDir
    $uninstallExe = Join-Path $InstallDir "Uninstall-DistControl.exe"
    $uninstallContextArguments = "--install-dir `"$InstallDir`" --data-dir `"$ProgramDataDir`" --user-sid `"$EffectiveTargetUserSid`" --start-menu-dir `"$UserStartMenuDir`" --desktop-dir `"$UserDesktopDir`""
    New-Shortcut (Join-Path $startMenu "DistControl.lnk") (Join-Path $InstallDir "DistControl.exe")
    New-Shortcut (Join-Path $startMenu "DistControl Admin.lnk") (Join-Path $InstallDir "DistControl.Admin.exe") "--policy `"$PolicyPath`""
    New-Shortcut (Join-Path $startMenu "DistControl Guide.lnk") (Join-Path $InstallDir "DistControl-guide.html")
    if (Test-Path -LiteralPath $uninstallExe) {
        New-Shortcut (Join-Path $startMenu "Uninstall DistControl.lnk") $uninstallExe $uninstallContextArguments
    }
    else {
        $scriptArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallerDir\Launch-Uninstall-DiskControl.ps1`" -InstallDir `"$InstallDir`" -DataDir `"$ProgramDataDir`" -TargetUserSid `"$EffectiveTargetUserSid`" -UserStartMenuDir `"$UserStartMenuDir`" -UserDesktopDir `"$UserDesktopDir`""
        New-Shortcut (Join-Path $startMenu "Uninstall DistControl.lnk") "powershell.exe" $scriptArguments
    }

    if (-not $NoDesktopShortcut) {
        New-Shortcut (Join-Path $UserDesktopDir "DistControl.lnk") (Join-Path $InstallDir "DistControl.exe")
    }
}

function Remove-LegacyDiagnostics {
    $startMenu = $UserStartMenuDir
    foreach ($path in @(
        (Join-Path $startMenu "DistControl Diagnostics.lnk"),
        (Join-Path $InstallerDir "Diagnose-DiskControl.ps1"),
        (Join-Path $InstallDir "diagnose.cmd")
    )) {
        if ($DryRun) {
            Write-Step "DRY-RUN: Remove legacy diagnostics $path"
            continue
        }

        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}

function Remove-LegacyBranding {
    $commonPrograms = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $commonDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $userDiskControlStartMenu = Join-Path (Split-Path -Parent $UserStartMenuDir) "DiskControl"
    foreach ($path in @(
        (Join-Path $commonPrograms "DiskControl"),
        (Join-Path $commonPrograms "DistControl"),
        (Join-Path $commonDesktop "DiskControl.lnk"),
        (Join-Path $commonDesktop "DistControl.lnk"),
        (Join-Path $commonPrograms "Startup\DiskControl dkclient.lnk"),
        (Join-Path $commonPrograms "Startup\DistControl dkclient.lnk"),
        $userDiskControlStartMenu,
        (Join-Path $UserDesktopDir "DiskControl.lnk")
    )) {
        if ($DryRun) {
            Write-Step "DRY-RUN: remove legacy branding $path"
        }
        elseif (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($registryPath in @($LegacyUninstallRegistryPath, $LegacyDistControlUninstallRegistryPath)) {
        if (-not $DryRun -and (Test-Path -LiteralPath $registryPath)) {
            Remove-Item -LiteralPath $registryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-LegacyInstallDirectory {
    $currentPath = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    foreach ($candidate in @(
        @{ Path = $LegacyInstallDir; Expected = (Join-Path $env:ProgramFiles "DiskControl") },
        @{ Path = $LegacyDistControlInstallDir; Expected = (Join-Path $env:ProgramFiles "DistControl") }
    )) {
        if (-not (Test-Path -LiteralPath $candidate.Path)) {
            continue
        }

        $expectedPath = [System.IO.Path]::GetFullPath($candidate.Expected).TrimEnd('\')
        $legacyPath = [System.IO.Path]::GetFullPath($candidate.Path).TrimEnd('\')
        if (-not [string]::Equals($legacyPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($legacyPath, $currentPath, [StringComparison]::OrdinalIgnoreCase)) {
            Write-InstallWarning "Старая папка установки не удалена: проверка безопасного пути не пройдена ($legacyPath)."
            continue
        }

        Write-Step "Remove legacy application directory $legacyPath"
        if ($DryRun) {
            continue
        }

        try {
            Remove-Item -LiteralPath $legacyPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-InstallWarning "Не удалось удалить старую папку $legacyPath. Новая версия установлена, папку можно удалить после закрытия старого приложения. Причина: $($_.Exception.Message)"
        }
    }
}

function Get-DirectorySizeKb([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    $bytes = 0L
    Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $bytes += $_.Length
    }

    return [int][Math]::Ceiling($bytes / 1KB)
}

function Set-RegistryValue([string]$Path, [string]$Name, [object]$Value, [string]$Type = "String") {
    if ($DryRun) {
        Write-Step "DRY-RUN: registry $Path $Name=$Value"
        return
    }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Register-UninstallEntry {
    Write-Step "Register Windows uninstall entry"
    if (-not $DryRun) {
        New-Item -Path $UninstallRegistryPath -Force | Out-Null
    }

    $uninstallScript = Join-Path $InstallerDir "Launch-Uninstall-DiskControl.ps1"
    $uninstallExe = Join-Path $InstallDir "Uninstall-DistControl.exe"
    $contextArguments = "--install-dir `"$InstallDir`" --data-dir `"$ProgramDataDir`" --user-sid `"$EffectiveTargetUserSid`" --start-menu-dir `"$UserStartMenuDir`" --desktop-dir `"$UserDesktopDir`""
    if ((Test-Path -LiteralPath $uninstallExe) -or $DryRun) {
        $uninstallCommand = "`"$uninstallExe`" $contextArguments"
        $quietUninstallCommand = "`"$uninstallExe`" $contextArguments"
    }
    else {
        $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`" -InstallDir `"$InstallDir`" -DataDir `"$ProgramDataDir`" -TargetUserSid `"$EffectiveTargetUserSid`" -UserStartMenuDir `"$UserStartMenuDir`" -UserDesktopDir `"$UserDesktopDir`""
        $quietUninstallCommand = $uninstallCommand
    }

    Set-RegistryValue $UninstallRegistryPath "DisplayName" $ProductName
    Set-RegistryValue $UninstallRegistryPath "DisplayVersion" $ProductVersion
    Set-RegistryValue $UninstallRegistryPath "Publisher" $Publisher
    Set-RegistryValue $UninstallRegistryPath "InstallLocation" $InstallDir
    Set-RegistryValue $UninstallRegistryPath "DisplayIcon" (Join-Path $InstallDir "DistControl.exe")
    Set-RegistryValue $UninstallRegistryPath "UninstallString" $uninstallCommand
    Set-RegistryValue $UninstallRegistryPath "QuietUninstallString" $quietUninstallCommand
    Set-RegistryValue $UninstallRegistryPath "NoModify" 1 "DWord"
    Set-RegistryValue $UninstallRegistryPath "NoRepair" 1 "DWord"
    Set-RegistryValue $UninstallRegistryPath "EstimatedSize" (Get-DirectorySizeKb $InstallDir) "DWord"
}

$VirtualHereHardwareId = "ROOT\VHUSB3HC"
$script:VirtualHereDriverInstalledNow = $false

function Find-VirtualHereDriverInf {
    foreach ($candidate in @(
        (Join-Path $SourceRoot "drivers\vhusb3hc\vhusb3hc.inf"),
        (Join-Path $SourceRoot "driver-export\virtualhere-vhusb3hc\vhusb3hc.inf")
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Test-VirtualHereDevicePresent {
    $devices = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
        Where-Object { @($_.HardwareID) -contains $VirtualHereHardwareId })
    return $devices.Count -gt 0
}

function Test-VirtualHereDriverInStore {
    $output = & pnputil.exe /enum-drivers 2>$null
    return [bool](@($output) | Where-Object { $_ -match '\bvhusb3hc\.inf\b' })
}

# Installs the VirtualHere USB 3 host controller used by dkcl64.exe, so that the
# DistKontrol client does not have to install it with its own UAC prompt on the
# first start. The virtual device is created like devcon does it, without
# shipping extra tools. An existing device is left untouched.
function Install-VirtualHereDriver {
    Write-Step "Check VirtualHere USB driver used by DistKontrolUSB"
    if (Test-VirtualHereDevicePresent) {
        Write-Step "VirtualHere USB 3 host controller is already installed"
        return
    }

    $infPath = Find-VirtualHereDriverInf
    if (-not $infPath) {
        Write-InstallWarning "VirtualHere driver package is not included in this installer; dkcl64.exe will install it on first start and may ask for administrator rights."
        return
    }
    if (-not [Environment]::Is64BitProcess) {
        Write-InstallWarning "Installer runs in 32-bit PowerShell and cannot install the 64-bit VirtualHere driver; dkcl64.exe will install it on first start."
        return
    }
    if ($DryRun) {
        Write-Step "DRY-RUN: pnputil /add-driver `"$infPath`" /install"
        Write-Step "DRY-RUN: create device $VirtualHereHardwareId"
        return
    }

    try {
        if (-not (Test-VirtualHereDriverInStore)) {
            $output = & pnputil.exe /add-driver $infPath /install 2>&1
            foreach ($line in @($output)) {
                Write-InstallLogLine "[external] $line"
            }
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
                throw "pnputil exit code $LASTEXITCODE"
            }
        }

        if (-not ("DistControlRootDevice" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class DistControlRootDevice
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetINFClassW(string infName, out Guid classGuid, StringBuilder className, int classNameSize, out int requiredSize);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid, IntPtr hwndParent);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiCreateDeviceInfoW(IntPtr deviceInfoSet, string deviceName, ref Guid classGuid, string deviceDescription, IntPtr hwndParent, int creationFlags, ref SP_DEVINFO_DATA deviceInfoData);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property, byte[] propertyBuffer, int propertyBufferSize);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiCallClassInstaller(int installFunction, IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);
    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwndParent, string hardwareId, string fullInfPath, int installFlags, out bool rebootRequired);

    private const int DICD_GENERATE_ID = 1;
    private const int SPDRP_HARDWAREID = 1;
    private const int DIF_REGISTERDEVICE = 0x19;
    private const int INSTALLFLAG_FORCE = 1;

    public static bool Install(string infPath, string hardwareId)
    {
        Guid classGuid;
        StringBuilder className = new StringBuilder(64);
        int required;
        if (!SetupDiGetINFClassW(infPath, out classGuid, className, className.Capacity, out required))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiGetINFClass");
        }
        IntPtr set = SetupDiCreateDeviceInfoList(ref classGuid, IntPtr.Zero);
        if (set == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfoList");
        }
        try
        {
            SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
            data.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
            if (!SetupDiCreateDeviceInfoW(set, className.ToString(), ref classGuid, null, IntPtr.Zero, DICD_GENERATE_ID, ref data))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfo");
            }
            byte[] ids = Encoding.Unicode.GetBytes(hardwareId + "\0\0");
            if (!SetupDiSetDeviceRegistryPropertyW(set, ref data, SPDRP_HARDWAREID, ids, ids.Length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiSetDeviceRegistryProperty");
            }
            if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref data))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCallClassInstaller");
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }
        bool reboot;
        if (!UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, hardwareId, infPath, INSTALLFLAG_FORCE, out reboot))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateDriverForPlugAndPlayDevices");
        }
        return reboot;
    }
}
"@
        }

        Write-Step "Create VirtualHere USB 3 host controller device"
        $rebootRequired = [DistControlRootDevice]::Install((Resolve-Path -LiteralPath $infPath).Path, $VirtualHereHardwareId)
        $script:VirtualHereDriverInstalledNow = $true
        Write-Step "VirtualHere USB driver installed"
        if ($rebootRequired) {
            Write-InstallWarning "Windows requests a restart to finish the VirtualHere USB driver installation."
        }
    }
    catch {
        Write-InstallWarning "VirtualHere USB driver was not installed: $($_.Exception.Message). dkcl64.exe will try to install it on first start."
    }
}

function Register-DkClientService {
    $exePath = Join-Path $InstallDir "dkcl64.exe"
    $iniPath = Join-Path $InstallDir "dkcl.ini"
    $binPath = "`"$exePath`" -n --config=`"$iniPath`""
    $credential = Resolve-ServiceCredential
    $serviceAccountName = if ($credential) { $credential.UserName } else { Resolve-DefaultServiceAccount }

    Remove-DkClientStartup
    Remove-ExistingService $ServiceName
    Stop-InstalledDkClientProcess
    Grant-LogonAsServiceRight $serviceAccountName
    Write-Step "Create service $ServiceName as $serviceAccountName"
    if ($DryRun) {
        Write-Step "DRY-RUN: New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $ServiceDisplayName -StartupType Automatic -Credential $serviceAccountName"
    }
    else {
        New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $ServiceDisplayName -StartupType Automatic -Credential $credential | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $binPath
    }

    Invoke-External "sc.exe" @("sidtype", $ServiceName, "unrestricted")
    Set-DkClientFilesAcl
    Invoke-ExternalOptional "sc.exe" @("description", $ServiceName, "DistKontrolUSB client used by DistControl.") "Cannot set service description"
    Invoke-ExternalOptional "sc.exe" @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/60000/restart/60000") "Cannot set service recovery policy"

    if (-not $NoStartService) {
        Try-StartService $ServiceName
        Test-DkClientPipeReady $ServiceName $(if ($script:VirtualHereDriverInstalledNow) { 40 } else { 15 })
    }
}

if (-not $DryRun) {
    Assert-Admin
    Assert-AbsoluteDirectoryParameter "InstallDir" $InstallDir
    Assert-AbsoluteDirectoryParameter "ProgramDataDir" $ProgramDataDir
    Assert-TargetUserContext
    Assert-UsageStateDirectory
    Start-InstallLog
    Write-InstallEnvironmentSummary
}
else {
    Assert-AbsoluteDirectoryParameter "InstallDir" $InstallDir
    Assert-AbsoluteDirectoryParameter "ProgramDataDir" $ProgramDataDir
    Assert-TargetUserContext
    Assert-UsageStateDirectory
    Write-InstallEnvironmentSummary
}

if (-not $SkipBuild) {
    $buildScript = Join-Path $SourceRoot "build-vs.cmd"
    if (Test-Path -LiteralPath $buildScript) {
        Write-Step "Build Release"
        Invoke-External $buildScript @("Release")
    }
}

$required = @(
    (Join-Path $ReleaseDir "DistControl.exe"),
    (Join-Path $ReleaseDir "DistControl.Admin.exe"),
    (Join-Path $SourceRoot "dkcl64.exe"),
    (Join-Path $SourceRoot "dkcl.ini")
)
foreach ($file in $required) {
    if (-not (Test-Path -LiteralPath $file)) {
        throw "Required installer input is missing: $file"
    }
}

Write-Step "Create directories"
if (-not $DryRun) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    New-Item -ItemType Directory -Path $InstallerDir -Force | Out-Null
    New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

Migrate-LegacyData
Preserve-ConfiguredUsageStatePath
if (-not $DryRun) {
    New-Item -ItemType Directory -Path $UsageStateRoot -Force | Out-Null
}

Assert-DistControlApplicationsClosed
Stop-ExistingService $ServiceName
Stop-InstalledDkClientProcess

Copy-RequiredFile (Join-Path $ReleaseDir "DistControl.exe") (Join-Path $InstallDir "DistControl.exe")
Copy-RequiredFile (Join-Path $ReleaseDir "DistControl.Admin.exe") (Join-Path $InstallDir "DistControl.Admin.exe")
Copy-RequiredFile (Join-Path $SourceRoot "dkcl64.exe") (Join-Path $InstallDir "dkcl64.exe")
Copy-RequiredFile (Join-Path $SourceRoot "dkcl.ini") (Join-Path $InstallDir "dkcl.ini")
Set-DistKontrolHubRoutes (Join-Path $SourceRoot "dkcl.ini")

foreach ($uninstallCandidate in @(
    (Join-Path $SourceRoot "Uninstall-DistControl.exe"),
    (Join-Path $SourceRoot "dist\Uninstall-DistControl.exe")
)) {
    if (Test-Path -LiteralPath $uninstallCandidate) {
        Copy-RequiredFile $uninstallCandidate (Join-Path $InstallDir "Uninstall-DistControl.exe")
        break
    }
}

foreach ($optional in @("README.md", "DistControl-guide.html", "allowlist.example.json")) {
    $source = Join-Path $SourceRoot $optional
    if (Test-Path -LiteralPath $source) {
        Copy-RequiredFile $source (Join-Path $InstallDir $optional)
    }
}

foreach ($installerFile in @(
    "Install-DiskControl.ps1",
    "Uninstall-DiskControl.ps1",
    "Launch-Install-DiskControl.ps1",
    "Launch-Uninstall-DiskControl.ps1",
    "CredentialCheck.cs"
)) {
    $source = Join-Path $SourceRoot "installer\$installerFile"
    if (Test-Path -LiteralPath $source) {
        Copy-RequiredFile $source (Join-Path $InstallerDir $installerFile)
    }
}

Remove-LegacyDiagnostics
Initialize-Policy
Set-PolicyUsageStatePath
Write-Step "VPN profiles are managed in Windows and assigned to tokens in DistControl Admin; installer does not create or update VPN connections"
Initialize-UsageState
Set-DirectoryAcl
Initialize-DkClientUserProfile
Test-UsageStateAccess
Install-VirtualHereDriver
Register-DkClientService
Remove-LegacyInstallDirectory
Remove-LegacyBranding
Install-Shortcuts
Register-UninstallEntry

Write-Step "Installation completed"
Write-Host "InstallDir: $InstallDir"
Write-Host "Policy:     $PolicyPath"
Write-Host "Usage:      $UsageStatePath"
Write-Host "Service:    $ServiceName"
if ($script:InstallWarnings.Count -gt 0) {
    Write-Host "Warnings:"
    foreach ($warning in $script:InstallWarnings) {
        Write-Host " - $warning"
    }
}
Stop-InstallLog
exit 0
