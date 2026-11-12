<#
.SYNOPSIS
    Infra Discovery Kit: read-only collection run.
.DESCRIPTION
    Runs the selected collectors, writes one JSON run file plus a SHA-256 hash into the output folder,
    and optionally builds the as-built HTML report. Nothing in the scanned environment is changed.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-Discovery.ps1 -Report
#>
[CmdletBinding()]
param(
    [ValidateSet('ActiveDirectory')]
    [string[]]$Modules = @('ActiveDirectory'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'output'),
    [int]$StaleDays = 90,
    [switch]$Report
)

$ErrorActionPreference = 'Stop'
$version = '0.1.2'

. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'collectors\ActiveDirectory.ps1')

$collectors = @{
    ActiveDirectory = { Get-IdkActiveDirectory -StaleDays $StaleDays }
}

$runId = (Get-Date).ToString('yyyyMMdd-HHmmss')
$run = [ordered]@{
    tool           = 'infra-discovery-kit'
    version        = $version
    run_id         = $runId
    collected_at   = (Get-Date).ToUniversalTime().ToString('o')
    collected_by   = "$env:USERDOMAIN\$env:USERNAME"
    collected_from = $env:COMPUTERNAME
    sample         = $false
    modules        = [ordered]@{}
}

foreach ($module in $Modules) {
    Write-Host "Collecting $module ..."
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $collectors[$module]
        $status = if ($result.errors.Count -gt 0) { 'partial' } else { 'ok' }
        $run.modules[$module] = [ordered]@{ status = $status; duration_s = [math]::Round($timer.Elapsed.TotalSeconds, 1); errors = @($result.errors); data = $result.data }
    }
    catch {
        $run.modules[$module] = [ordered]@{ status = 'failed'; duration_s = [math]::Round($timer.Elapsed.TotalSeconds, 1); errors = @([ordered]@{ step = 'module'; message = $_.Exception.Message }); data = $null }
    }
    Write-Host ("  {0} ({1}s, {2} errors)" -f $run.modules[$module].status, $run.modules[$module].duration_s, @($run.modules[$module].errors).Count)
}

if (-not (Test-Path $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath) }
$jsonPath = Join-Path $OutputPath "run-$runId.json"
$run | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding UTF8
$hash = (Get-FileHash -Path $jsonPath -Algorithm SHA256).Hash
"$hash  run-$runId.json" | Set-Content -Path "$jsonPath.sha256" -Encoding ASCII
Write-Host "Evidence: $jsonPath"
Write-Host "SHA-256:  $hash"

if ($Report) {
    & (Join-Path $PSScriptRoot 'New-IdkReport.ps1') -InputPath $jsonPath
}
