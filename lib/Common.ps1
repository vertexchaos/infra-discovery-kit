# Shared helpers for collectors. Read-only: nothing here changes the environment.

# Native commands the kit may run. Anything else is refused.
$script:IdkAllowedNative = @(
    'repadmin /replsummary',
    'dfsrmig /getglobalstate',
    'w32tm /query',
    'dcdiag /q'
)

function Invoke-IdkNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $commandLine = ("$FilePath " + ($Arguments -join ' ')).Trim()
    $allowed = $false
    foreach ($prefix in $script:IdkAllowedNative) {
        if ($commandLine.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $allowed = $true }
    }
    if (-not $allowed) { throw "Refused: '$commandLine' is not on the read-only allowlist." }

    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        return [ordered]@{ command = $commandLine; available = $false; exit_code = $null; output = $null }
    }
    # Native stderr must not become a terminating error under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String
    return [ordered]@{ command = $commandLine; available = $true; exit_code = $LASTEXITCODE; output = $output.Trim() }
}

# Runs one step; on failure records the error and returns $null so the run continues.
function Invoke-IdkStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.ArrayList]$Errors
    )
    try { & $Script }
    catch {
        [void]$Errors.Add([ordered]@{ step = $Name; message = $_.Exception.Message })
        $null
    }
}
