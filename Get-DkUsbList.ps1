Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-DkCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string]$PipeName = "dkclient",
        [int]$TimeoutMs = 5000
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

$rawList = Invoke-DkCommand -Command "LIST"
$rawList | Set-Content -LiteralPath ".\dk-list-raw.txt" -Encoding UTF8

$devices = @(ConvertFrom-DkList -Text $rawList)
foreach ($device in $devices) {
    $rawInfo = Invoke-DkCommand -Command ("DEVICE INFO,{0}" -f $device.Endpoint)
    $device.Nickname = Get-FieldValue -Text $rawInfo -Field "NICKNAME"
    $device.Product = Get-FieldValue -Text $rawInfo -Field "PRODUCT"
    $device.InUseBy = Get-FieldValue -Text $rawInfo -Field "IN USE BY"
}

$devices | Sort-Object Endpoint | Format-Table -AutoSize
$devices |
    Sort-Object Endpoint |
    Export-Csv -LiteralPath ".\dk-usb-list.csv" -NoTypeInformation -Encoding UTF8
$devices |
    Sort-Object Endpoint |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath ".\dk-usb-list.json" -Encoding UTF8

