#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "DiskControl"),
    [string]$ProgramDataDir = (Join-Path $env:ProgramData "DiskControl"),
    [string]$ServiceName = "dkclient",
    [string]$ServiceDisplayName = "DistKontrolUSB Client",
    [string]$ServiceAccount = $env:DISKCONTROL_SERVICE_ACCOUNT,
    [string]$UsageStateDir = $env:DISKCONTROL_USAGE_STATE_DIR,
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
$ProductName = "DiskControl"
$ProductVersion = "0.1.0"
$Publisher = "DiskControl"
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ReleaseDir = Join-Path $SourceRoot "build\x64\Release"
$PolicyPath = Join-Path $ProgramDataDir "allow.json"
$UsageStateRoot = if ([string]::IsNullOrWhiteSpace($UsageStateDir)) { $ProgramDataDir } else { $UsageStateDir.TrimEnd('\', '/') }
$UsageStatePath = Join-Path $UsageStateRoot "usage.json"
$LogsDir = Join-Path $ProgramDataDir "logs"
$InstallerDir = Join-Path $InstallDir "installer"
$ClientStartupShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\DiskControl dkclient.lnk"
$UninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskControl"
$script:InstallLogPath = $null
$script:InstallWarnings = New-Object System.Collections.Generic.List[string]

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
    Write-Host "[DiskControl] $Message"
    Write-InstallLogLine "[DiskControl] $Message"
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
    $defaultUsageStatePath = Join-Path $ProgramDataDir "usage.json"
    return [string]::Equals(
        (Normalize-FullPath $UsageStatePath),
        (Normalize-FullPath $defaultUsageStatePath),
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Write-InstallWarning([string]$Message) {
    $script:InstallWarnings.Add($Message) | Out-Null
    Write-Host "[DiskControl] WARNING: $Message"
    Write-InstallLogLine "[DiskControl] WARNING: $Message"
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
        Write-Host "[DiskControl] WARNING: Cannot start install log: $($_.Exception.Message)"
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
        return "Не хватило прав. Запустите установку от имени администратора и проверьте права на папки Program Files и ProgramData."
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
        return "Старый процесс dkcl64.exe не удалось остановить. Закройте DiskControl, остановите службу dkclient или перезагрузите компьютер."
    }
    if ($lower.Contains("usage state") -or
        $lower.Contains("usagestatedir") -or
        $lower.Contains("network share") -or
        $lower.Contains("unc")) {
        return "Проблема с общей папкой таймеров usage.json. Проверьте путь и права чтения/записи."
    }
    if ($lower.Contains("service") -or
        $lower.Contains("start-service") -or
        $lower.Contains("running state")) {
        return "Служба dkclient не запустилась. Проверьте пароль учетной записи службы, dkcl.ini и журнал событий Windows."
    }
    if ($lower.Contains("required file") -or
        $lower.Contains("installer input")) {
        return "В установочном пакете не найден обязательный файл. Используйте свежий DiskControl-Setup.exe."
    }
    return "Установка остановилась из-за технической ошибки. Подробности ниже в этом журнале."
}

function Write-InstallErrorDetails([object]$Record) {
    $message = if ($Record -and $Record.Exception) { $Record.Exception.Message } else { "$Record" }
    $human = Convert-InstallErrorToHuman $message
    Write-Host "[DiskControl] USER-ERROR: $human"
    Write-Host "[DiskControl] ERROR: $message"
    Write-InstallLogLine "[DiskControl] USER-ERROR: $human"
    Write-InstallLogLine "[DiskControl] ERROR: $message"
    if ($Record -and $Record.Exception) {
        Write-InstallLogLine "[DiskControl] ERROR TYPE: $($Record.Exception.GetType().FullName)"
    }
    if ($Record -and $Record.InvocationInfo) {
        Write-InstallLogLine "[DiskControl] ERROR SCRIPT: $($Record.InvocationInfo.ScriptName)"
        Write-InstallLogLine "[DiskControl] ERROR LINE: $($Record.InvocationInfo.ScriptLineNumber)"
        Write-InstallLogLine "[DiskControl] ERROR COMMAND: $($Record.InvocationInfo.Line)"
    }
    if ($Record -and $Record.ScriptStackTrace) {
        Write-InstallLogLine "[DiskControl] ERROR STACK: $($Record.ScriptStackTrace)"
    }
}

function Write-InstallEnvironmentSummary {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $identity = "<unknown>"
    }
    Write-Step "Environment: computer=$env:COMPUTERNAME; processUser=$identity; installDir=$InstallDir; programDataDir=$ProgramDataDir; policy=$PolicyPath; usage=$UsageStatePath; service=$ServiceName; serviceAccount=$ServiceAccount; source=$SourceRoot"
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
    if (-not $password -and -not [string]::IsNullOrEmpty($env:DISKCONTROL_SERVICE_PASSWORD)) {
        $password = ConvertTo-SecureString $env:DISKCONTROL_SERVICE_PASSWORD -AsPlainText -Force
    }

    if (-not $password) {
        if ($DryRun) {
            Write-Step "DRY-RUN: service account would be $account"
            return $null
        }

        Write-Host ""
        Write-Host "DiskControl will run dkclient service as: $account"
        Write-Host "Enter this Windows account password. It is passed to Windows Service Control Manager."
        $password = Read-Host -Prompt "Password for $account" -AsSecureString
    }

    if (-not $password) {
        throw "Service account password is required."
    }

    return New-Object System.Management.Automation.PSCredential($account, $password)
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
  "userAssignments": []
}
"@
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
        "*S-1-5-32-545:(OI)(CI)RX"
    ) -Recursive

    Set-ProtectedAcl $ProgramDataDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)M",
        "*S-1-5-32-545:(OI)(CI)RX"
    ) -Recursive

    Set-ProtectedAcl $LogsDir @(
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)M",
        "*S-1-5-32-545:(OI)(CI)M"
    ) -Recursive

    Set-ProtectedAcl $PolicyPath @(
        "*S-1-5-18:F",
        "*S-1-5-32-544:M",
        "*S-1-5-32-545:R"
    )

    if (Test-LocalProgramDataUsageStatePath) {
        Set-ProtectedAcl $UsageStatePath @(
            "*S-1-5-18:F",
            "*S-1-5-32-544:M",
            "*S-1-5-32-545:M"
        )
    }
    else {
        Write-Step "Skip ACL rewrite for external usage state path: $UsageStatePath"
    }
}

function Set-DkClientExecutableAcl([string]$Account) {
    $exePath = Join-Path $InstallDir "dkcl64.exe"
    $identity = Resolve-PrivilegeIdentity $Account
    Write-Step "Restrict dkcl64.exe execute ACL to service account"
    Set-ProtectedAcl $exePath @(
        "*S-1-5-18:F",
        "*S-1-5-32-544:F",
        "${identity}:RX"
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
    $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\DiskControl"
    $uninstallExe = Join-Path $InstallDir "Uninstall-DiskControl.exe"
    New-Shortcut (Join-Path $startMenu "DiskControl.lnk") (Join-Path $InstallDir "DiskControl.exe")
    New-Shortcut (Join-Path $startMenu "DiskControl Admin.lnk") (Join-Path $InstallDir "DiskControl.Admin.exe")
    New-Shortcut (Join-Path $startMenu "DiskControl Guide.lnk") (Join-Path $InstallDir "DiskControl-guide.html")
    if (Test-Path -LiteralPath $uninstallExe) {
        New-Shortcut (Join-Path $startMenu "Uninstall DiskControl.lnk") $uninstallExe
    }
    else {
        New-Shortcut (Join-Path $startMenu "Uninstall DiskControl.lnk") "powershell.exe" "-NoProfile -ExecutionPolicy Bypass -File `"$InstallerDir\Launch-Uninstall-DiskControl.ps1`""
    }

    if (-not $NoDesktopShortcut) {
        $publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
        New-Shortcut (Join-Path $publicDesktop "DiskControl.lnk") (Join-Path $InstallDir "DiskControl.exe")
    }
}

function Remove-LegacyDiagnostics {
    $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\DiskControl"
    foreach ($path in @(
        (Join-Path $startMenu "DiskControl Diagnostics.lnk"),
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
    $uninstallExe = Join-Path $InstallDir "Uninstall-DiskControl.exe"
    if ((Test-Path -LiteralPath $uninstallExe) -or $DryRun) {
        $uninstallCommand = "`"$uninstallExe`""
        $quietUninstallCommand = "`"$uninstallExe`""
    }
    else {
        $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
        $quietUninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
    }

    Set-RegistryValue $UninstallRegistryPath "DisplayName" $ProductName
    Set-RegistryValue $UninstallRegistryPath "DisplayVersion" $ProductVersion
    Set-RegistryValue $UninstallRegistryPath "Publisher" $Publisher
    Set-RegistryValue $UninstallRegistryPath "InstallLocation" $InstallDir
    Set-RegistryValue $UninstallRegistryPath "DisplayIcon" (Join-Path $InstallDir "DiskControl.exe")
    Set-RegistryValue $UninstallRegistryPath "UninstallString" $uninstallCommand
    Set-RegistryValue $UninstallRegistryPath "QuietUninstallString" $quietUninstallCommand
    Set-RegistryValue $UninstallRegistryPath "NoModify" 1 "DWord"
    Set-RegistryValue $UninstallRegistryPath "NoRepair" 1 "DWord"
    Set-RegistryValue $UninstallRegistryPath "EstimatedSize" (Get-DirectorySizeKb $InstallDir) "DWord"
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
    Set-DkClientExecutableAcl $serviceAccountName
    Grant-LogonAsServiceRight $serviceAccountName
    Write-Step "Create service $ServiceName as $serviceAccountName"
    if ($DryRun) {
        Write-Step "DRY-RUN: New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $ServiceDisplayName -StartupType Automatic -Credential $serviceAccountName"
    }
    else {
        New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $ServiceDisplayName -StartupType Automatic -Credential $credential | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $binPath
    }

    Invoke-ExternalOptional "sc.exe" @("description", $ServiceName, "DistKontrolUSB client used by DiskControl.") "Cannot set service description"
    Invoke-ExternalOptional "sc.exe" @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/60000/restart/60000") "Cannot set service recovery policy"

    if (-not $NoStartService) {
        Try-StartService $ServiceName
    }
}

if (-not $DryRun) {
    Assert-Admin
    Assert-AbsoluteDirectoryParameter "InstallDir" $InstallDir
    Assert-AbsoluteDirectoryParameter "ProgramDataDir" $ProgramDataDir
    Assert-UsageStateDirectory
    Start-InstallLog
    Write-InstallEnvironmentSummary
}
else {
    Assert-AbsoluteDirectoryParameter "InstallDir" $InstallDir
    Assert-AbsoluteDirectoryParameter "ProgramDataDir" $ProgramDataDir
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
    (Join-Path $ReleaseDir "DiskControl.exe"),
    (Join-Path $ReleaseDir "DiskControl.Admin.exe"),
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
    New-Item -ItemType Directory -Path $UsageStateRoot -Force | Out-Null
}

Stop-ExistingService $ServiceName
Stop-InstalledDkClientProcess

Copy-RequiredFile (Join-Path $ReleaseDir "DiskControl.exe") (Join-Path $InstallDir "DiskControl.exe")
Copy-RequiredFile (Join-Path $ReleaseDir "DiskControl.Admin.exe") (Join-Path $InstallDir "DiskControl.Admin.exe")
Copy-RequiredFile (Join-Path $SourceRoot "dkcl64.exe") (Join-Path $InstallDir "dkcl64.exe")
Copy-RequiredFile (Join-Path $SourceRoot "dkcl.ini") (Join-Path $InstallDir "dkcl.ini")

foreach ($uninstallCandidate in @(
    (Join-Path $SourceRoot "Uninstall-DiskControl.exe"),
    (Join-Path $SourceRoot "dist\Uninstall-DiskControl.exe")
)) {
    if (Test-Path -LiteralPath $uninstallCandidate) {
        Copy-RequiredFile $uninstallCandidate (Join-Path $InstallDir "Uninstall-DiskControl.exe")
        break
    }
}

foreach ($optional in @("README.md", "DiskControl-guide.html", "allowlist.example.json")) {
    $source = Join-Path $SourceRoot $optional
    if (Test-Path -LiteralPath $source) {
        Copy-RequiredFile $source (Join-Path $InstallDir $optional)
    }
}

foreach ($installerFile in @(
    "Install-DiskControl.ps1",
    "Uninstall-DiskControl.ps1",
    "Launch-Install-DiskControl.ps1",
    "Launch-Uninstall-DiskControl.ps1"
)) {
    $source = Join-Path $SourceRoot "installer\$installerFile"
    if (Test-Path -LiteralPath $source) {
        Copy-RequiredFile $source (Join-Path $InstallerDir $installerFile)
    }
}

Remove-LegacyDiagnostics
Initialize-Policy
Set-PolicyUsageStatePath
Initialize-UsageState
Set-DirectoryAcl
Test-UsageStateAccess
Register-DkClientService
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
