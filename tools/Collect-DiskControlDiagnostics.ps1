#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "DiskControl"),
    [string]$ProgramDataDir = (Join-Path $env:ProgramData "DiskControl"),
    [string]$ServiceName = "dkclient",
    [string]$PipeName = "dkclient",
    [string]$OutputRoot = $env:TEMP,
    [int]$PipeTimeoutMs = 5000,
    [switch]$SkipPipeProbe,
    [switch]$SkipUsageWriteTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

try {
    $script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $script:Utf8NoBomEncoding
    $OutputEncoding = $script:Utf8NoBomEncoding
}
catch {
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$computer = $env:COMPUTERNAME
$safeComputer = ($computer -replace '[^\w.-]', '_')
$baseName = "DiskControl-Diagnostics-$safeComputer-$timestamp"
$outDir = Join-Path $OutputRoot $baseName
$zipPath = Join-Path $OutputRoot ($baseName + ".zip")

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Join-OutPath {
    param([Parameter(Mandatory)][string]$Name)
    return (Join-Path $outDir $Name)
}

function Write-TextFile {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    $path = Join-OutPath $Name
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($path, $Text, $script:Utf8NoBomEncoding)
}

function Add-Section {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)][string]$Title
    )
    [void]$Builder.AppendLine("")
    [void]$Builder.AppendLine(("== {0} ==" -f $Title))
}

function Add-Line {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    [void]$Builder.AppendLine($Text)
}

function Invoke-Capture {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    $path = Join-OutPath $Name
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    try {
        $output = & $ScriptBlock 2>&1 | Out-String -Width 4096
        [System.IO.File]::WriteAllText($path, $output, $script:Utf8NoBomEncoding)
    }
    catch {
        [System.IO.File]::WriteAllText($path, ("ERROR: " + $_.Exception.ToString()), $script:Utf8NoBomEncoding)
    }
}

function Copy-IfExists {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$DestinationName
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $destination = Join-OutPath $DestinationName
    $parent = Split-Path -Parent $destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    try {
        Copy-Item -LiteralPath $Source -Destination $destination -Recurse -Force -ErrorAction Stop
    }
    catch {
        Write-TextFile ($DestinationName + ".copy-error.txt") $_.Exception.ToString()
    }
}

function Get-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-FileInventory {
    param([string[]]$Paths)

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            [pscustomobject]@{
                Path = $path
                Exists = $false
                Type = ""
                Length = ""
                LastWriteTime = ""
                Sha256 = ""
                Version = ""
            }
            continue
        }

        $item = Get-Item -LiteralPath $path -Force
        $hash = ""
        $version = ""
        if (-not $item.PSIsContainer) {
            try { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch { $hash = "ERROR: $($_.Exception.Message)" }
            try { $version = $item.VersionInfo.FileVersion } catch { $version = "" }
        }

        [pscustomobject]@{
            Path = $item.FullName
            Exists = $true
            Type = if ($item.PSIsContainer) { "Directory" } else { "File" }
            Length = if ($item.PSIsContainer) { "" } else { $item.Length }
            LastWriteTime = $item.LastWriteTime
            Sha256 = $hash
            Version = $version
        }
    }
}

function Invoke-DkCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string]$Pipe = $PipeName,
        [int]$TimeoutMs = $PipeTimeoutMs
    )

    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        ".",
        $Pipe,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )

    try {
        $client.Connect($TimeoutMs)
        $client.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Message

        $request = [System.Text.Encoding]::UTF8.GetBytes($Command)
        $client.Write($request, 0, $request.Length)
        $client.Flush()

        $buffer = New-Object byte[] 65536
        $response = New-Object System.IO.MemoryStream
        try {
            do {
                $async = $client.BeginRead($buffer, 0, $buffer.Length, $null, $null)
                if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                    throw "Pipe read timed out after $TimeoutMs ms for command $Command"
                }

                $count = $client.EndRead($async)
                if ($count -gt 0) {
                    $response.Write($buffer, 0, $count)
                }
            } while (-not $client.IsMessageComplete -and $count -gt 0)

            return [System.Text.Encoding]::UTF8.GetString($response.ToArray()).Trim([char]0)
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $client.Dispose()
    }
}

function ConvertFrom-DkList {
    param([string]$Text)

    $result = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($line in ($Text -split "\r?\n")) {
        $endpointMatch = [regex]::Match($line, "\((?<endpoint>[^()\s]+-Gr-\d+\.\d+)\)")
        if (-not $endpointMatch.Success) {
            continue
        }

        $endpoint = $endpointMatch.Groups["endpoint"].Value
        if ($seen.ContainsKey($endpoint)) {
            continue
        }
        $seen[$endpoint] = $true

        $name = ($line -replace '^\s*(\*+\s*)?(-->\s*)?', '')
        $name = ($name -replace '\s*\([^()]*-Gr-\d+\.\d+\).*$', '').Trim()
        $inUse = ""
        $usageMatch = [regex]::Match($line, "\(In-use by:(?<usage>.+?)\)\s*$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($usageMatch.Success) {
            $inUse = $usageMatch.Groups["usage"].Value.Trim()
        }

        $result.Add([pscustomobject]@{
            Endpoint = $endpoint
            NicknameFromList = $name
            InUseByFromList = $inUse
        })
    }

    return @($result | Sort-Object Endpoint)
}

function Get-JsonPropertyValue {
    param(
        [object]$Object,
        [string]$Name
    )
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Test-DirectoryWrite {
    param([string]$Path)

    $targetDir = $Path
    if ([string]::IsNullOrWhiteSpace($targetDir)) {
        return "SKIPPED: empty path"
    }
    if ([System.IO.Path]::GetExtension($targetDir)) {
        $targetDir = Split-Path -Parent $targetDir
    }
    if ([string]::IsNullOrWhiteSpace($targetDir)) {
        return "SKIPPED: cannot resolve parent directory for $Path"
    }
    if (-not (Test-Path -LiteralPath $targetDir)) {
        return "FAIL: directory does not exist: $targetDir"
    }

    $testPath = Join-Path $targetDir ("diskcontrol-write-test-{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
    try {
        "write-test $(Get-Date -Format o)" | Set-Content -LiteralPath $testPath -Encoding UTF8 -ErrorAction Stop
        Remove-Item -LiteralPath $testPath -Force -ErrorAction Stop
        return "OK: write/delete succeeded in $targetDir"
    }
    catch {
        try {
            if (Test-Path -LiteralPath $testPath) {
                Remove-Item -LiteralPath $testPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
        return "FAIL: $($_.Exception.Message) Path=$targetDir"
    }
}

$policyPath = Join-Path $ProgramDataDir "allow.json"
$logsDir = Join-Path $ProgramDataDir "logs"
$usageStatePath = ""
$policy = $null

if (Test-Path -LiteralPath $policyPath) {
    try {
        $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $policyPipe = Get-JsonPropertyValue $policy "pipeName"
        if (-not [string]::IsNullOrWhiteSpace($policyPipe)) {
            $PipeName = $policyPipe
        }
        $usageStatePath = [string](Get-JsonPropertyValue $policy "usageStatePath")
    }
    catch {
        $policy = $null
    }
}

$summary = New-Object System.Text.StringBuilder
Add-Line $summary "DiskControl diagnostics"
Add-Line $summary ("CreatedAt: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Add-Line $summary ("Computer: {0}" -f $env:COMPUTERNAME)
Add-Line $summary ("UserEnv: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
try { Add-Line $summary ("WhoAmI: {0}" -f (& whoami.exe)) } catch { Add-Line $summary ("WhoAmI: ERROR {0}" -f $_.Exception.Message) }
try { Add-Line $summary ("WindowsIdentity: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name)) } catch { }
Add-Line $summary ("IsAdmin: {0}" -f (Get-IsAdmin))
Add-Line $summary ("PowerShell: {0}" -f $PSVersionTable.PSVersion)
Add-Line $summary ("OS: {0}" -f ([Environment]::OSVersion.VersionString))
Add-Line $summary ("InstallDir: {0}" -f $InstallDir)
Add-Line $summary ("ProgramDataDir: {0}" -f $ProgramDataDir)
Add-Line $summary ("PolicyPath: {0}" -f $policyPath)
Add-Line $summary ("PipeName: {0}" -f $PipeName)
Add-Line $summary ("UsageStatePath: {0}" -f $usageStatePath)

Add-Section $summary "Quick findings"
if (-not (Get-IsAdmin)) {
    Add-Line $summary "WARN: Script is not elevated. Some ACL/service data may be incomplete."
}
if (-not (Test-Path -LiteralPath $InstallDir)) {
    Add-Line $summary "WARN: InstallDir not found."
}
if (-not (Test-Path -LiteralPath $ProgramDataDir)) {
    Add-Line $summary "WARN: ProgramDataDir not found."
}
if (-not (Test-Path -LiteralPath $policyPath)) {
    Add-Line $summary "WARN: allow.json not found."
}
if ($policy) {
    $assignments = @(Get-JsonPropertyValue $policy "userAssignments")
    Add-Line $summary ("PolicyAssignments: {0}" -f $assignments.Count)
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Add-Line $summary ("Service: {0}, Status={1}, StartType={2}" -f $ServiceName, $service.Status, $service.StartType)
}
else {
    Add-Line $summary ("WARN: Service {0} not found." -f $ServiceName)
}

if (-not $SkipUsageWriteTest -and $usageStatePath) {
    Add-Line $summary ("UsageStateWriteTest: {0}" -f (Test-DirectoryWrite $usageStatePath))
}

Write-TextFile "summary.txt" $summary.ToString()

Invoke-Capture "system\environment.txt" {
    Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture
    ""
    "whoami:"
    whoami /all
    ""
    "PowerShell:"
    $PSVersionTable
}

Invoke-Capture "system\ipconfig.txt" { ipconfig /all }
Invoke-Capture "system\net-use.txt" { net use }
Invoke-Capture "system\time.txt" { Get-Date; w32tm /query /status }

$importantPaths = @(
    $InstallDir,
    $ProgramDataDir,
    $logsDir,
    $policyPath,
    (Join-Path $InstallDir "DiskControl.exe"),
    (Join-Path $InstallDir "DiskControl.Admin.exe"),
    (Join-Path $InstallDir "dkcl64.exe"),
    (Join-Path $InstallDir "dkcl.ini"),
    (Join-Path $InstallDir "Uninstall-DiskControl.exe"),
    (Join-Path $InstallDir "installer"),
    (Join-Path $InstallDir "installer\Uninstall-DiskControl.ps1")
)
if ($usageStatePath) {
    $importantPaths += $usageStatePath
    $usageParent = Split-Path -Parent $usageStatePath
    if ($usageParent) {
        $importantPaths += $usageParent
    }
}

Invoke-Capture "files\inventory.txt" { Get-FileInventory ($importantPaths | Select-Object -Unique) | Format-Table -AutoSize -Wrap }
Invoke-Capture "files\acl-icacls.txt" {
    foreach ($path in ($importantPaths | Select-Object -Unique)) {
        "### $path"
        if (Test-Path -LiteralPath $path) {
            icacls.exe $path
        }
        else {
            "MISSING"
        }
        ""
    }
}
Invoke-Capture "files\acl-powershell.txt" {
    foreach ($path in ($importantPaths | Select-Object -Unique)) {
        "### $path"
        if (Test-Path -LiteralPath $path) {
            Get-Acl -LiteralPath $path | Format-List
        }
        else {
            "MISSING"
        }
        ""
    }
}

if (Test-Path -LiteralPath $policyPath) {
    Copy-IfExists $policyPath "config\allow.json"
    Invoke-Capture "config\policy-summary.txt" {
        $p = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        [pscustomobject]@{
            PipeName = $p.pipeName
            RefreshSeconds = $p.refreshSeconds
            UsageStatePath = $p.usageStatePath
            AssignmentCount = @($p.userAssignments).Count
        } | Format-List
        ""
        $assignmentRows = foreach ($assignment in @($p.userAssignments)) {
            [pscustomobject]@{
                Users = (@($assignment.users) -join "; ")
                Groups = (@($assignment.groups) -join "; ")
                DeviceCount = @($assignment.allowedDevices).Count
            }
        }
        $assignmentRows | Format-Table -AutoSize -Wrap
    }
}

Copy-IfExists (Join-Path $InstallDir "dkcl.ini") "config\dkcl.ini"

if (Test-Path -LiteralPath $logsDir) {
    New-Item -ItemType Directory -Path (Join-OutPath "logs") -Force | Out-Null
    Get-ChildItem -LiteralPath $logsDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(audit|startup|install|uninstall)-.*\.(csv|log)$' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 30 |
        ForEach-Object {
            Copy-IfExists $_.FullName ("logs\" + $_.Name)
        }
}

Invoke-Capture "service\get-service.txt" { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-List * }
Invoke-Capture "service\sc-query.txt" { sc.exe queryex $ServiceName; ""; sc.exe qc $ServiceName }
Invoke-Capture "service\registry.txt" {
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (Test-Path -LiteralPath $serviceKey) {
        Get-ItemProperty -LiteralPath $serviceKey | Format-List *
    }
    else {
        "Service registry key not found: $serviceKey"
    }
}
Invoke-Capture "service\service-security.txt" { sc.exe sdshow $ServiceName }
Invoke-Capture "process\dkcl64-processes.txt" {
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'dkcl64.exe'" -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        $owner = $null
        try { $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner } catch { }
        [pscustomobject]@{
            ProcessId = $process.ProcessId
            ParentProcessId = $process.ParentProcessId
            ExecutablePath = $process.ExecutablePath
            CommandLine = $process.CommandLine
            SessionId = $process.SessionId
            Owner = if ($owner -and $owner.ReturnValue -eq 0) { "$($owner.Domain)\$($owner.User)" } else { "" }
        }
    }
}
Invoke-Capture "process\diskcontrol-processes.txt" {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @("DiskControl.exe", "DiskControl.Admin.exe", "dkcl64.exe") } |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, SessionId |
        Format-Table -AutoSize -Wrap
}

Invoke-Capture "registry\uninstall-entry.txt" {
    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskControl"
    if (Test-Path -LiteralPath $key) {
        Get-ItemProperty -LiteralPath $key | Format-List *
    }
    else {
        "Uninstall registry key not found."
    }
}

Invoke-Capture "shortcuts\shortcuts.txt" {
    $paths = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\DiskControl"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"),
        ([Environment]::GetFolderPath("CommonDesktopDirectory"))
    )
    foreach ($path in $paths) {
        "### $path"
        if (Test-Path -LiteralPath $path) {
            Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Format-Table FullName, Length, LastWriteTime -AutoSize -Wrap
        }
        else {
            "MISSING"
        }
        ""
    }
}

Invoke-Capture "events\system-service-control-manager.txt" {
    Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ProviderName = "Service Control Manager"
        StartTime = (Get-Date).AddDays(-2)
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "dkclient|DiskControl|dkcl64" } |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Format-List
}
Invoke-Capture "events\application-diskcontrol.txt" {
    Get-WinEvent -FilterHashtable @{
        LogName = "Application"
        StartTime = (Get-Date).AddDays(-2)
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "DiskControl|dkclient|dkcl64|DistKontrol" -or $_.ProviderName -match "DiskControl|Application Error|Windows Error Reporting" } |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
        Format-List
}

if (-not $SkipPipeProbe) {
    Invoke-Capture "pipe\probe.txt" {
        $pipePath = "\\.\pipe\$PipeName"
        "PipePath: $pipePath"
        "Test-Path: $(Test-Path $pipePath)"
        ""
        "LIST:"
        try {
            $list = Invoke-DkCommand -Command "LIST" -Pipe $PipeName -TimeoutMs $PipeTimeoutMs
            $list
            [System.IO.File]::WriteAllText((Join-OutPath "pipe\LIST.raw.txt"), $list, $script:Utf8NoBomEncoding)

            $devices = @(ConvertFrom-DkList $list)
            $devices | Export-Csv -LiteralPath (Join-OutPath "pipe\LIST.parsed.csv") -NoTypeInformation -Encoding UTF8
            ""
            "Parsed device count: $($devices.Count)"
            if ($devices.Count -gt 0) {
                $first = $devices[0].Endpoint
                ""
                "DEVICE INFO,$($first):"
                $info = Invoke-DkCommand -Command ("DEVICE INFO,{0}" -f $first) -Pipe $PipeName -TimeoutMs $PipeTimeoutMs
                $info
                [System.IO.File]::WriteAllText((Join-OutPath "pipe\DEVICE-INFO-first.raw.txt"), $info, $script:Utf8NoBomEncoding)
            }
        }
        catch {
            "ERROR: $($_.Exception.ToString())"
        }
    }
}
else {
    Write-TextFile "pipe\probe.txt" "Skipped by -SkipPipeProbe."
}

if (-not $SkipUsageWriteTest) {
    Invoke-Capture "usage-state\write-test.txt" {
        if ($usageStatePath) {
            Test-DirectoryWrite $usageStatePath
        }
        else {
            "SKIPPED: usageStatePath is empty or allow.json could not be parsed."
        }
    }
}
else {
    Write-TextFile "usage-state\write-test.txt" "Skipped by -SkipUsageWriteTest."
}

Invoke-Capture "uninstall\blocked-delete-check.txt" {
    $dkclPath = Join-Path $InstallDir "dkcl64.exe"
    "Target: $dkclPath"
    if (Test-Path -LiteralPath $dkclPath) {
        "Exists: true"
        "Processes using dkcl64.exe path:"
        Get-CimInstance Win32_Process -Filter "Name = 'dkcl64.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $dkclPath, [StringComparison]::OrdinalIgnoreCase) } |
            Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine, SessionId |
            Format-List
        ""
        "ACL:"
        icacls.exe $dkclPath
    }
    else {
        "Exists: false"
    }
}

try {
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    $itemsToZip = Get-ChildItem -LiteralPath $outDir -Force
    if ($itemsToZip.Count -eq 0) {
        throw "Diagnostic folder is empty."
    }
    Compress-Archive -LiteralPath $itemsToZip.FullName -DestinationPath $zipPath -Force
    Write-Host "DiskControl diagnostics package created:"
    Write-Host $zipPath
}
catch {
    Write-Host "Diagnostics were collected, but zip creation failed:"
    Write-Host $_.Exception.Message
    Write-Host "Folder:"
    Write-Host $outDir
}
