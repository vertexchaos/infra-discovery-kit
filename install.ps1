<#
.SYNOPSIS
    Bootstrap for Infra Discovery Kit: download a pinned release, verify its SHA-256, run it.
.DESCRIPTION
    Quick start (run in an elevated Windows PowerShell on a DC or domain-joined host):

        irm https://raw.githubusercontent.com/vertexchaos/infra-discovery-kit/v0.1.2/install.ps1 | iex

    With options:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/vertexchaos/infra-discovery-kit/v0.1.2/install.ps1))) -NoRun

    The kit itself is read-only. This bootstrap only writes to the destination folder (default %TEMP%)
    and sets the execution policy to Bypass for the current PowerShell process only.
#>
param(
    [string]$Version = '0.1.2',
    [string]$Destination = (Join-Path $env:TEMP "infra-discovery-kit-$Version"),
    [switch]$NoRun
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$base = "https://github.com/vertexchaos/infra-discovery-kit/releases/download/v$Version"
$zipName = "infra-discovery-kit-$Version.zip"
$zipPath = Join-Path $env:TEMP $zipName

Write-Host "Downloading $zipName ..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/$zipName" -OutFile $zipPath
$sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content
if ($sums -is [byte[]]) { $sums = [System.Text.Encoding]::ASCII.GetString($sums) }

$expected = $null
foreach ($line in ($sums -split "`r?`n")) {
    if ($line -match "^([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($zipName))\s*$") { $expected = $Matches[1].ToUpper() }
}
if (-not $expected) { throw "SHA256SUMS has no entry for $zipName." }
$actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
if ($actual -ne $expected) {
    Remove-Item $zipPath -Force
    throw "Checksum mismatch for $zipName. Expected $expected, got $actual. Nothing was run."
}
Write-Host "SHA-256 verified: $actual"

# Extract in one .NET call, retrying in case antivirus briefly locks freshly written scripts.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
$expectedFiles = @($zip.Entries | Where-Object { $_.Name }).Count
$zip.Dispose()

$attempt = 0
while ($true) {
    $attempt++
    try {
        if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $Destination)
        break
    }
    catch {
        if ($attempt -ge 3) {
            throw "Could not extract the kit after 3 attempts: $($_.Exception.Message) Antivirus may be scanning the files; run the command again, or extract $zipPath manually."
        }
        Write-Host "Extraction attempt $attempt failed ($($_.Exception.Message)). Retrying..."
        Start-Sleep -Seconds 3
    }
}

$extracted = @(Get-ChildItem $Destination -Recurse -File).Count
if ($extracted -lt $expectedFiles -or -not (Test-Path (Join-Path $Destination 'Invoke-Discovery.ps1'))) {
    throw "Extraction incomplete: $extracted of $expectedFiles files in $Destination. Nothing was run."
}
Get-ChildItem $Destination -Recurse -File | Unblock-File
Write-Host "Kit extracted to $Destination ($extracted files)"

if ($NoRun) {
    Write-Host "Skipping the run (-NoRun). Start it with:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$Destination\Invoke-Discovery.ps1`" -Report"
    return
}

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& (Join-Path $Destination 'Invoke-Discovery.ps1') -Report -OutputPath (Join-Path $Destination 'output')
Write-Host ""
Write-Host "Done. Evidence (JSON + .sha256) and the HTML report are in: $(Join-Path $Destination 'output')"
