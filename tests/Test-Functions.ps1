# Calls the shared helpers and the report pipeline for real (not just parsing).
# Safe to run anywhere: no domain access, no native tools beyond an allowlist refusal check.
#   powershell -ExecutionPolicy Bypass -File .\tests\Test-Functions.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'rules\AdRules.ps1')

$failures = New-Object System.Collections.ArrayList
function Check([string]$Name, [bool]$Condition) {
    if ($Condition) { Write-Host "PASS $Name" -ForegroundColor Green }
    else { Write-Host "FAIL $Name" -ForegroundColor Red; [void]$failures.Add($Name) }
}

# Invoke-IdkStep must accept an empty error list (regression: v0.1.2 crashed on the first step).
$errs = New-Object System.Collections.ArrayList
$value = Invoke-IdkStep -Name 'ok-step' -Errors $errs -Script { 42 }
Check 'Invoke-IdkStep accepts empty Errors and returns the value' ($value -eq 42 -and $errs.Count -eq 0)

$value = Invoke-IdkStep -Name 'bad-step' -Errors $errs -Script { throw 'boom' }
Check 'Invoke-IdkStep records a failure and returns null' ($null -eq $value -and $errs.Count -eq 1 -and $errs[0].step -eq 'bad-step')

# Allowlist refuses anything not read-only.
$refused = $false
try { Invoke-IdkNative -FilePath 'repadmin' -Arguments @('/syncall') | Out-Null } catch { $refused = $_.Exception.Message -like 'Refused*' }
Check 'Invoke-IdkNative refuses non-allowlisted commands' $refused

# Rules over the sample produce the expected findings.
$sample = Get-Content (Join-Path $root 'samples\contoso-sample.json') -Raw | ConvertFrom-Json
$f = @(Get-IdkAdFindings -Ad $sample.modules.ActiveDirectory.data -Now ([datetime]'2026-11-11'))
$ids = ($f | ForEach-Object { $_.id }) -join ','
Check "Sample yields 9 findings ($ids)" ($f.Count -eq 9)
Check 'Sample flags single DC, FRS and PDC local clock' ($ids -match 'AD-001' -and $ids -match 'AD-004' -and $ids -match 'AD-005')

# Report renders a failed-module banner.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "idk-test-$([guid]::NewGuid().ToString('N'))"
[void](New-Item -ItemType Directory -Path $tmp)
try {
    $failedRun = [ordered]@{ tool = 'infra-discovery-kit'; version = 'test'; run_id = 't'; collected_at = 'now'; collected_by = 'x'; collected_from = 'y'; sample = $false
        modules = [ordered]@{ ActiveDirectory = [ordered]@{ status = 'failed'; duration_s = 0; errors = @([ordered]@{ step = 'module'; message = 'test failure' }); data = $null } } }
    $json = Join-Path $tmp 'run-t.json'
    $failedRun | ConvertTo-Json -Depth 8 | Set-Content $json -Encoding UTF8
    & (Join-Path $root 'New-IdkReport.ps1') -InputPath $json | Out-Null
    $html = Get-Content ([System.IO.Path]::ChangeExtension($json, '.html')) -Raw
    Check 'Report shows a banner when a module failed' ($html -match 'Module ActiveDirectory failed' -and $html -match 'test failure')
}
finally { Remove-Item $tmp -Recurse -Force }

if ($failures.Count -gt 0) { exit 1 }
Write-Host 'All function tests passed.' -ForegroundColor Green
