# Findings rules for the ActiveDirectory module. Input: the module's data from a run JSON (PSCustomObject).
# Rules run at report time, so they can be improved and re-run over old evidence.

function New-IdkFinding {
    param([string]$Id, [string]$Severity, [string]$Title, [string]$Evidence, [string]$Recommendation, [string]$Catalog = 'T1')
    [pscustomobject][ordered]@{ id = $Id; severity = $Severity; title = $Title; evidence = $Evidence; recommendation = $Recommendation; catalog = $Catalog }
}

# Microsoft extended-support end dates for DC operating systems.
$script:IdkOsEndOfSupport = [ordered]@{
    '2008' = [datetime]'2020-01-14'
    '2012' = [datetime]'2023-10-10'
    '2016' = [datetime]'2027-01-12'
    '2019' = [datetime]'2029-01-09'
    '2022' = [datetime]'2031-10-14'
}

# .NET Framework reports levels above 2012 R2 as "Unknown", so name them from the numeric level.
$script:IdkModeNames = @{ 0 = 'Windows 2000'; 1 = 'Windows Server 2003 interim'; 2 = 'Windows Server 2003'; 3 = 'Windows Server 2008'; 4 = 'Windows Server 2008 R2'; 5 = 'Windows Server 2012'; 6 = 'Windows Server 2012 R2'; 7 = 'Windows Server 2016'; 10 = 'Windows Server 2025' }
function Get-IdkModeLabel {
    param($Mode, $Level)
    if ($null -ne $Level -and $script:IdkModeNames.ContainsKey([int]$Level)) { return "$($script:IdkModeNames[[int]$Level]) (level $Level)" }
    return "$Mode (level $Level)"
}

function Get-IdkAdFindings {
    param([Parameter(Mandatory)]$Ad, [datetime]$Now = (Get-Date))
    $findings = New-Object System.Collections.ArrayList

    foreach ($d in @($Ad.domains)) {
        $dcs = @($d.domain_controllers)

        # AD-001: single DC
        if ($dcs.Count -lt 2) {
            [void]$findings.Add((New-IdkFinding 'AD-001' 'High' "Domain $($d.name) has only $($dcs.Count) domain controller" `
                "Domain controllers found: $(($dcs | ForEach-Object { $_.name }) -join ', ')" `
                'Add a second DC, ideally in another site or availability zone, as a global catalog with AD-integrated DNS. Point DHCP/DNS clients at both.'))
        }

        # AD-002: DC operating system support
        foreach ($dc in $dcs) {
            if (-not $dc.os) { continue }
            foreach ($ver in $script:IdkOsEndOfSupport.Keys) {
                if ($dc.os -match "Server $ver") {
                    $end = $script:IdkOsEndOfSupport[$ver]
                    $days = [int]($end - $Now).TotalDays
                    if ($days -lt 0) {
                        [void]$findings.Add((New-IdkFinding 'AD-002' 'High' "$($dc.name) runs an unsupported OS" "$($dc.os); extended support ended $($end.ToString('yyyy-MM-dd'))." `
                            'Build replacement DCs on a supported Windows Server version, move roles, then demote and clean up this DC.'))
                    } elseif ($days -le 365) {
                        [void]$findings.Add((New-IdkFinding 'AD-002' 'Medium' "$($dc.name) OS support ends in $days days" "$($dc.os); extended support ends $($end.ToString('yyyy-MM-dd'))." `
                            'Plan replacement DCs on Windows Server 2022/2025 before the end-of-support date.'))
                    }
                    break
                }
            }
        }

        # AD-003: functional levels (7 = Windows Server 2016)
        if ($null -ne $d.mode_level -and [int]$d.mode_level -lt 7) {
            [void]$findings.Add((New-IdkFinding 'AD-003' 'Medium' "Domain $($d.name) functional level is below 2016" "Domain functional level: $(Get-IdkModeLabel $d.mode $d.mode_level)." `
                'After all DCs run 2016 or later, raise the domain and then the forest functional level.'))
        }
    }
    if ($null -ne $Ad.forest.mode_level -and [int]$Ad.forest.mode_level -lt 7) {
        [void]$findings.Add((New-IdkFinding 'AD-003' 'Medium' 'Forest functional level is below 2016' "Forest functional level: $(Get-IdkModeLabel $Ad.forest.mode $Ad.forest.mode_level)." `
            'Raise the forest functional level once every domain is at 2016 or later.'))
    }

    # AD-004: SYSVOL replication engine
    $dfsr = $Ad.native.dfsr_state
    if ($dfsr -and $dfsr.available -and $dfsr.output -notmatch 'Eliminated') {
        [void]$findings.Add((New-IdkFinding 'AD-004' 'High' 'SYSVOL may still replicate with FRS' "dfsrmig /getglobalstate: $($dfsr.output)" `
            'Migrate SYSVOL to DFSR (dfsrmig states Prepared -> Redirected -> Eliminated) before adding Windows Server 2019+ DCs.'))
    }

    # AD-005 / AD-006: time sources
    $vmicFix = 'On virtualized DCs, disable the Hyper-V time provider (HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider, Enabled = 0; the boot-time correction still applies) so DCs follow the domain hierarchy.'
    foreach ($t in @($Ad.time)) {
        if (-not $t.source) { continue }
        $localClock = $t.source -match 'Local CMOS Clock|Free-running System Clock'
        $hostClock = $t.source -match 'VM IC Time Synchronization Provider'
        if ($t.is_pdc) {
            if ($localClock) {
                [void]$findings.Add((New-IdkFinding 'AD-005' 'High' "PDC emulator $($t.dc) uses its local clock" "w32tm /query /source: $($t.source)" `
                    'Configure the PDC emulator alone to sync from a reliable source (NTP pool, or 169.254.169.123 in AWS). Leave all other machines on NT5DS.'))
            } elseif ($hostClock) {
                [void]$findings.Add((New-IdkFinding 'AD-005' 'High' "PDC emulator $($t.dc) takes its time from the Hyper-V host" "w32tm /query /source: $($t.source)" `
                    "The whole domain then follows the host's clock, and host drift or a restored checkpoint becomes domain-wide time skew. $vmicFix Then point the PDC emulator at an external NTP source."))
            }
        }
        elseif ($hostClock) {
            [void]$findings.Add((New-IdkFinding 'AD-006' 'Medium' "$($t.dc) takes its time from the Hyper-V host" "w32tm /query /source: $($t.source)" `
                "$vmicFix Verify with w32tm /query /source: it should show another DC."))
        }
        elseif ($localClock -or $t.source -notmatch '\.') {
            [void]$findings.Add((New-IdkFinding 'AD-006' 'Medium' "$($t.dc) does not follow the domain time hierarchy" "w32tm /query /source: $($t.source)" `
                'Reset non-PDC DCs to the domain hierarchy (NT5DS), then verify with w32tm /query /status.'))
        }
    }

    # AD-012: dcdiag failed tests
    $diag = $Ad.native.dcdiag
    if ($diag -and $diag.available -and $diag.output) {
        $failedTests = @([regex]::Matches($diag.output, 'failed test\s+(\S+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        if ($failedTests.Count -gt 0) {
            [void]$findings.Add((New-IdkFinding 'AD-012' 'Medium' "dcdiag reports failed tests: $($failedTests -join ', ')" "dcdiag /q: $(($diag.output -replace '\s+', ' ').Trim())" `
                'Run dcdiag /v /test:<name> on the DC for detail, and check the related event log (DFS Replication for DFSREvent). Resolve before any DC change.'))
        }
    }

    # AD-007: replication failures
    $repl = $Ad.native.replsummary
    if ($repl -and $repl.available -and $repl.output) {
        $failing = @()
        foreach ($line in ($repl.output -split "`r?`n")) {
            if ($line -match '^\s*(\S+)\s+\S+\s+(\d+)\s*/\s*(\d+)') {
                if ([int]$Matches[2] -gt 0) { $failing += "$($Matches[1]) ($($Matches[2])/$($Matches[3]) failing)" }
            }
        }
        if ($failing.Count -gt 0 -or $repl.output -match 'operational errors') {
            [void]$findings.Add((New-IdkFinding 'AD-007' 'High' 'Active Directory replication failures' "repadmin /replsummary: $($failing -join '; ')" `
                'Resolve replication errors (repadmin /showrepl for detail) before any DC change. Never add or demote DCs while replication is failing.'))
        }
    }

    # AD-008 .. AD-010: account hygiene
    $acc = $Ad.accounts
    if ($acc) {
        if ([int]$acc.stale_users -gt 0 -or [int]$acc.stale_computers -gt 0) {
            [void]$findings.Add((New-IdkFinding 'AD-008' 'Low' 'Stale enabled accounts' "$($acc.stale_users) of $($acc.enabled_users) enabled users and $($acc.stale_computers) of $($acc.enabled_computers) enabled computers have no logon in $($acc.stale_days) days (or never)." `
                'Review with the business, then disable, wait, and delete. Exclude service accounts after confirming their use.'))
        }
        if ([int]$acc.password_never_expires -gt 0) {
            [void]$findings.Add((New-IdkFinding 'AD-009' 'Low' 'Accounts with passwords that never expire' "$($acc.password_never_expires) enabled users." `
                'Move service accounts to gMSAs where possible; apply the password policy to people.'))
        }
        if ([int]$acc.admincount_users -gt 5) {
            [void]$findings.Add((New-IdkFinding 'AD-010' 'Low' 'Many accounts are or were privileged' "$($acc.admincount_users) enabled users have adminCount=1." `
                'Review privileged group membership and remove standing access that is not needed.'))
        }
    }

    # AD-011: sites with DCs but no subnets (only matters with more than one site)
    $sites = @($Ad.sites)
    if ($sites.Count -gt 1) {
        foreach ($s in $sites) {
            if (@($s.servers).Count -gt 0 -and @($s.subnets).Count -eq 0) {
                [void]$findings.Add((New-IdkFinding 'AD-011' 'Low' "Site $($s.name) has DCs but no subnets" "Servers: $(@($s.servers) -join ', ')" `
                    'Define the subnets for this site in AD Sites and Services so clients find their nearest DC.'))
            }
        }
    }

    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    return @($findings | Sort-Object { $order[$_.severity] }, id)
}
