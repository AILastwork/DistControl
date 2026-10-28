#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$Commit,
    [Parameter(Mandatory = $true)][string]$NotesFile,
    [Parameter(Mandatory = $true)][string[]]$Assets
)

$ErrorActionPreference = 'Stop'
$repository = 'AILastwork/DistControl'
$api = "https://api.github.com/repos/$repository"
$assetFiles = @($Assets | ForEach-Object { Get-Item -LiteralPath $_ })
$notes = Get-Content -LiteralPath $NotesFile -Raw -Encoding UTF8

# Reuse the Git credential helper without printing or persisting its response.
$credentialLines = "protocol=https`nhost=github.com`n`n" | git credential fill
if ($LASTEXITCODE -ne 0) { throw 'GitHub credentials are not available.' }
$credential = @{}
foreach ($line in $credentialLines) {
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2) { $credential[$parts[0]] = $parts[1] }
}
if ([string]::IsNullOrWhiteSpace($credential['password'])) {
    throw 'GitHub credentials are not available.'
}
$headers = @{
    Authorization = 'Bearer ' + $credential['password']
    Accept = 'application/vnd.github+json'
    'User-Agent' = 'DistControl-Release'
    'X-GitHub-Api-Version' = '2022-11-28'
}

try {
    $release = $null
    try {
        $release = Invoke-RestMethod -Uri "$api/releases/tags/$Tag" -Headers $headers
    } catch {
        if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 404) { throw }
    }
    if (-not $release) {
        $body = @{
            tag_name = $Tag
            target_commitish = $Commit
            name = "DistControl $($Tag.TrimStart('v'))"
            body = $notes
            draft = $true
            prerelease = $false
        } | ConvertTo-Json
        $release = Invoke-RestMethod -Method Post -Uri "$api/releases" -Headers $headers `
            -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    }
    foreach ($file in $assetFiles) {
        $existing = @($release.assets | Where-Object name -eq $file.Name)
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing.Count -gt 0) {
            if ($existing[0].size -ne $file.Length -or
                ($existing[0].digest -and $existing[0].digest -ne "sha256:$hash")) {
                throw "Existing release asset differs: $($file.Name)."
            }
            continue
        }
        $uploadBase = $release.upload_url -replace '\{.*$', ''
        if (-not $uploadBase.StartsWith('https://uploads.github.com/')) {
            throw 'Unexpected GitHub asset upload host.'
        }
        $uri = $uploadBase + '?name=' + [Uri]::EscapeDataString($file.Name)
        $asset = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers `
            -ContentType 'application/octet-stream' -InFile $file.FullName -TimeoutSec 60
        if ($asset.size -ne $file.Length) { throw "Uploaded asset size mismatch: $($file.Name)." }
        Write-Output "Uploaded: $($file.Name)"
    }
    if ($release.draft) {
        $body = @{ draft = $false; make_latest = 'true' } | ConvertTo-Json
        $release = Invoke-RestMethod -Method Patch -Uri "$api/releases/$($release.id)" `
            -Headers $headers -ContentType 'application/json' -Body $body
    }
    $verified = Invoke-RestMethod -Uri "$api/releases/tags/$Tag" -Headers $headers
    if ($verified.draft) { throw 'GitHub release is still a draft.' }
    Write-Output "Published: $($verified.html_url)"
    $verified.assets | Select-Object name, size, digest, browser_download_url | ConvertTo-Json
} finally {
    $headers.Clear()
    $credential.Clear()
    $credentialLines = $null
}
