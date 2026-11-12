# Fails if any collector or shared helper contains a state-changing command.
# Run before every release:  powershell -File .\tests\Test-ReadOnly.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$files = @(Get-ChildItem -Path (Join-Path $root 'collectors'), (Join-Path $root 'lib') -Filter *.ps1 -Recurse)

$bannedVerbs = 'Set', 'New', 'Remove', 'Add', 'Enable', 'Disable', 'Start', 'Stop', 'Restart', 'Rename', 'Move', 'Clear', 'Reset', 'Install', 'Uninstall', 'Register', 'Unregister', 'Grant', 'Revoke', 'Update', 'Write', 'Out', 'Export'
# Allowed exceptions: object construction only, never environment changes.
$allowedCommands = 'New-Object', 'Out-String', 'Out-Null'
$bannedNative = '/fix', '/set', '/config', '/resync', '/update', '/setmigrationstate', '/delete', '/remove', '/syncall', '/replicate', '/force'

$problems = New-Object System.Collections.ArrayList
foreach ($f in $files) {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$parseErrors)
    foreach ($e in $parseErrors) { [void]$problems.Add("$($f.Name): parse error: $($e.Message)") }

    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $commands) {
        $name = $c.GetCommandName()
        if (-not $name) { continue }
        if ($allowedCommands -contains $name) { continue }
        $verb = ($name -split '-')[0]
        if ($name -like '*-*' -and $bannedVerbs -contains $verb) {
            [void]$problems.Add("$($f.Name):$($c.Extent.StartLineNumber): banned command $name")
        }
    }
    $strings = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
    foreach ($s in $strings) {
        foreach ($b in $bannedNative) {
            if ($s.Value -ieq $b -or $s.Value -ilike "$b *" -or $s.Value -ilike "$b`:*") {
                [void]$problems.Add("$($f.Name):$($s.Extent.StartLineNumber): banned native switch '$($s.Value)'")
            }
        }
    }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Host "FAIL $_" -ForegroundColor Red }
    exit 1
}
Write-Host "PASS read-only lint: $($files.Count) files checked." -ForegroundColor Green
