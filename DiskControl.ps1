param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "allowlist.json"),
    [switch]$NoGui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# FUNCTIONS START
function Read-Configuration {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Файл конфигурации не найден: $Path"
    }

    $config = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if (-not $config.pipeName) {
        throw "В конфигурации обязательно поле pipeName."
    }
    if (-not $config.userAssignments) {
        throw "В userAssignments должно быть хотя бы одно назначение."
    }

    foreach ($assignment in $config.userAssignments) {
        $usersProperty = $assignment.PSObject.Properties["users"]
        $groupsProperty = $assignment.PSObject.Properties["groups"]
        $users = if ($usersProperty) { @($usersProperty.Value) } else { @() }
        $groups = if ($groupsProperty) { @($groupsProperty.Value) } else { @() }

        if ($users.Count -eq 0 -and $groups.Count -eq 0) {
            throw "В каждом назначении нужен пользователь users или группа groups."
        }
        if (-not $assignment.allowedDevices) {
            throw "В каждом назначении должен быть список allowedDevices."
        }

        foreach ($rule in $assignment.allowedDevices) {
            if (-not $rule.endpoint -or $rule.endpoint -notmatch "^.+-Gr-\d+\.\d+$") {
                throw "Для каждого устройства нужен endpoint вида HUB-Gr-1.3."
            }
        }
    }

    return $config
}

function Get-CurrentUserContext {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)

    return [pscustomobject]@{
        FullName  = $identity.Name
        ShortName = [Environment]::UserName
        Sid       = $identity.User.Value
        Principal = $principal
    }
}

function Test-IdentityMatch {
    param(
        [Parameter(Mandatory)][string]$ConfiguredIdentity,
        [Parameter(Mandatory)]$UserContext
    )

    $candidates = @(
        [string]$UserContext.FullName,
        [string]$UserContext.ShortName,
        [string]$UserContext.Sid
    )

    foreach ($candidate in $candidates) {
        if ([string]::Equals(
            $ConfiguredIdentity,
            $candidate,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }

    return $false
}

function Get-EffectiveDeviceRules {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$UserContext
    )

    $rules = New-Object System.Collections.ArrayList

    foreach ($assignment in $Config.userAssignments) {
        $matches = $false
        $usersProperty = $assignment.PSObject.Properties["users"]
        $groupsProperty = $assignment.PSObject.Properties["groups"]
        $users = if ($usersProperty) { @($usersProperty.Value) } else { @() }
        $groups = if ($groupsProperty) { @($groupsProperty.Value) } else { @() }

        foreach ($user in $users) {
            if ($user -and (Test-IdentityMatch `
                -ConfiguredIdentity ([string]$user) `
                -UserContext $UserContext)) {
                $matches = $true
                break
            }
        }

        if (-not $matches) {
            foreach ($group in $groups) {
                if ($group -and $UserContext.Principal.IsInRole([string]$group)) {
                    $matches = $true
                    break
                }
            }
        }

        if ($matches) {
            foreach ($rule in $assignment.allowedDevices) {
                [void]$rules.Add($rule)
            }
        }
    }

    $unique = @{}
    foreach ($rule in $rules) {
        $key = "{0}|{1}|{2}" -f $rule.endpoint, $rule.nickname, $rule.product
        $unique[$key.ToLowerInvariant()] = $rule
    }

    return @($unique.Values)
}

function Invoke-DkCommand {
    param(
        [Parameter(Mandatory)][string]$PipeName,
        [Parameter(Mandatory)][string]$Command,
        [int]$TimeoutMs = 3000
    )

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        ".",
        $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None
    )

    try {
        $pipe.Connect($TimeoutMs)
        $pipe.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Message

        $request = [System.Text.Encoding]::UTF8.GetBytes($Command)
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()

        $buffer = New-Object byte[] 65536
        $response = New-Object System.IO.MemoryStream
        try {
            do {
                $count = $pipe.Read($buffer, 0, $buffer.Length)
                if ($count -gt 0) {
                    $response.Write($buffer, 0, $count)
                }
            } while (-not $pipe.IsMessageComplete -and $count -gt 0)

            return [System.Text.Encoding]::UTF8.GetString($response.ToArray()).Trim([char]0)
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $pipe.Dispose()
    }
}

function Get-FieldValue {
    param(
        [string]$Text,
        [string]$Field
    )

    $match = [regex]::Match(
        $Text,
        "(?im)^\s*" + [regex]::Escape($Field) + "\s*:\s*(.+?)\s*$"
    )
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }
    return ""
}

function ConvertFrom-DkList {
    param([string]$Text)

    $seen = @{}
    foreach ($line in ($Text -split "\r?\n")) {
        $match = [regex]::Match($line, "\((?<endpoint>[^()\s]+-Gr-\d+\.\d+)\)")
        if (-not $match.Success) {
            continue
        }

        $endpoint = $match.Groups["endpoint"].Value
        if (-not $seen.ContainsKey($endpoint)) {
            $seen[$endpoint] = [pscustomobject]@{
                Endpoint = $endpoint
                Nickname = ""
                Product  = ""
                InUseBy  = ""
            }
        }
    }

    return @($seen.Values | Sort-Object Endpoint)
}

function Test-AllowedDevice {
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)]$Rules
    )

    foreach ($rule in $Rules) {
        if (-not [string]::Equals(
            [string]$rule.endpoint,
            [string]$Device.Endpoint,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            continue
        }

        if ($rule.nickname -and -not [string]::Equals(
            [string]$rule.nickname,
            [string]$Device.Nickname,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            continue
        }

        if ($rule.product -and -not [string]::Equals(
            [string]$rule.product,
            [string]$Device.Product,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            continue
        }

        return $true
    }

    return $false
}

function Get-AllowedDevices {
    param(
        $Config,
        [Parameter(Mandatory)]$Rules
    )

    if (@($Rules).Count -eq 0) {
        return @()
    }

    $list = Invoke-DkCommand -PipeName $Config.pipeName -Command "LIST"
    $devices = ConvertFrom-DkList -Text $list

    foreach ($device in $devices) {
        $details = Invoke-DkCommand `
            -PipeName $Config.pipeName `
            -Command ("DEVICE INFO,{0}" -f $device.Endpoint)

        $device.Nickname = Get-FieldValue -Text $details -Field "NICKNAME"
        $device.Product = Get-FieldValue -Text $details -Field "PRODUCT"
        $device.InUseBy = Get-FieldValue -Text $details -Field "IN USE BY"
    }

    return @($devices | Where-Object {
        Test-AllowedDevice -Device $_ -Rules $Rules
    })
}

function Start-VendorClient {
    param($Config)

    if (-not $Config.clientExecutable) {
        return
    }

    $clientPath = [Environment]::ExpandEnvironmentVariables(
        [string]$Config.clientExecutable
    )
    if (-not [System.IO.Path]::IsPathRooted($clientPath)) {
        $clientPath = Join-Path $PSScriptRoot $clientPath
    }

    if (-not (Test-Path -LiteralPath $clientPath -PathType Leaf)) {
        throw "Клиент производителя не найден: $clientPath"
    }

    Start-Process -FilePath $clientPath | Out-Null
    Start-Sleep -Seconds 2
}

function Format-Device {
    param($Device)

    $nickname = if ($Device.Nickname) { $Device.Nickname } else { "(без имени)" }
    $product = if ($Device.Product) { $Device.Product } else { "(продукт неизвестен)" }
    $status = switch ($Device.InUseBy) {
        "NO ONE" { "свободно" }
        "YOU" { "подключено на этом компьютере" }
        "" { "состояние неизвестно" }
        default { "использует: $($Device.InUseBy)" }
    }

    return "{0} | {1} | {2} | {3}" -f $Device.Endpoint, $nickname, $product, $status
}

# SCRIPT ENTRY POINT
$config = Read-Configuration -Path $ConfigPath
$userContext = Get-CurrentUserContext
$allowedRules = @(Get-EffectiveDeviceRules `
    -Config $config `
    -UserContext $userContext)

if ($NoGui) {
    [pscustomobject]@{
        User = $userContext.FullName
        AllowedDevices = @(Get-AllowedDevices `
            -Config $config `
            -Rules $allowedRules)
    } | ConvertTo-Json -Depth 5
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "DiskControl — разрешённые USB-ключи"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(850, 430)
$form.MinimumSize = New-Object System.Drawing.Size(700, 350)

$intro = New-Object System.Windows.Forms.Label
$intro.Text = "Пользователь: $($userContext.FullName). Показаны только назначенные USB-ключи."
$intro.AutoSize = $true
$intro.Location = New-Object System.Drawing.Point(12, 15)
$form.Controls.Add($intro)

$deviceList = New-Object System.Windows.Forms.ListBox
$deviceList.Location = New-Object System.Drawing.Point(12, 45)
$deviceList.Size = New-Object System.Drawing.Size(808, 250)
$deviceList.Anchor = "Top,Bottom,Left,Right"
$deviceList.DisplayMember = "Display"
$form.Controls.Add($deviceList)

$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Обновить"
$refreshButton.Location = New-Object System.Drawing.Point(12, 315)
$refreshButton.Size = New-Object System.Drawing.Size(110, 32)
$refreshButton.Anchor = "Bottom,Left"
$form.Controls.Add($refreshButton)

$useButton = New-Object System.Windows.Forms.Button
$useButton.Text = "Подключить"
$useButton.Location = New-Object System.Drawing.Point(132, 315)
$useButton.Size = New-Object System.Drawing.Size(110, 32)
$useButton.Anchor = "Bottom,Left"
$form.Controls.Add($useButton)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = "Отключить"
$stopButton.Location = New-Object System.Drawing.Point(252, 315)
$stopButton.Size = New-Object System.Drawing.Size(110, 32)
$stopButton.Anchor = "Bottom,Left"
$form.Controls.Add($stopButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Готово."
$statusLabel.AutoEllipsis = $true
$statusLabel.Location = New-Object System.Drawing.Point(12, 360)
$statusLabel.Size = New-Object System.Drawing.Size(808, 25)
$statusLabel.Anchor = "Bottom,Left,Right"
$form.Controls.Add($statusLabel)

function Update-DeviceList {
    $statusLabel.Text = "Обновление списка..."
    $form.Refresh()
    try {
        if ($allowedRules.Count -eq 0) {
            $deviceList.Items.Clear()
            $statusLabel.Text = "Для пользователя $($userContext.FullName) устройства не назначены."
            return
        }

        $devices = @(Get-AllowedDevices `
            -Config $config `
            -Rules $allowedRules)
        $deviceList.Items.Clear()
        foreach ($device in $devices) {
            $deviceList.Items.Add([pscustomobject]@{
                Display = Format-Device -Device $device
                Device  = $device
            }) | Out-Null
        }
        $statusLabel.Text = "Найдено разрешённых устройств: $($devices.Count)"
    }
    catch {
        $deviceList.Items.Clear()
        $statusLabel.Text = $_.Exception.Message
    }
}

function Invoke-SelectedDeviceCommand {
    param([string]$Command)

    if (-not $deviceList.SelectedItem) {
        $statusLabel.Text = "Сначала выберите устройство."
        return
    }

    try {
        $device = $deviceList.SelectedItem.Device
        if (-not (Test-AllowedDevice -Device $device -Rules $allowedRules)) {
            throw "Выбранное устройство больше не разрешено."
        }

        $current = @(Get-AllowedDevices `
            -Config $config `
            -Rules $allowedRules | Where-Object {
            $_.Endpoint -eq $device.Endpoint
        })
        if ($current.Count -ne 1) {
            throw "Устройство недоступно или больше не соответствует белому списку."
        }

        $response = Invoke-DkCommand `
            -PipeName $config.pipeName `
            -Command ("{0},{1}" -f $Command, $device.Endpoint)

        $statusLabel.Text = if ($response) {
            $response
        }
        else {
            "Команда $Command отправлена."
        }
        Update-DeviceList
    }
    catch {
        $statusLabel.Text = $_.Exception.Message
    }
}

$refreshButton.Add_Click({ Update-DeviceList })
$useButton.Add_Click({ Invoke-SelectedDeviceCommand -Command "USE" })
$stopButton.Add_Click({ Invoke-SelectedDeviceCommand -Command "STOP USING" })

$form.Add_Shown({
    if ($allowedRules.Count -eq 0) {
        Update-DeviceList
        return
    }

    try {
        Get-AllowedDevices -Config $config -Rules $allowedRules | Out-Null
    }
    catch {
        try {
            Start-VendorClient -Config $config
        }
        catch {
            $statusLabel.Text = $_.Exception.Message
        }
    }
    Update-DeviceList
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = [Math]::Max(2, [int]$config.refreshSeconds) * 1000
$timer.Add_Tick({ Update-DeviceList })
$timer.Start()

[void]$form.ShowDialog()
$timer.Dispose()
