<#
.SYNOPSIS
    Builds a self-contained as-built HTML report from an Infra Discovery Kit run file.
.DESCRIPTION
    Reads run JSON only (works offline), runs the findings rules, and writes <run>.html next to the input.
.EXAMPLE
    .\New-IdkReport.ps1 -InputPath .\samples\contoso-sample.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [string]$OutputPath,
    [datetime]$Now = (Get-Date)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'rules\AdRules.ps1')

$run = Get-Content -Path $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $OutputPath) { $OutputPath = [System.IO.Path]::ChangeExtension($InputPath, '.html') }

function Enc([object]$Value) { [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function ConvertTo-IdkTable {
    param([object[]]$Rows, [string[]]$Columns, [string[]]$Headers)
    if (-not $Headers) { $Headers = $Columns }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append("<th>$(Enc $h)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in @($Rows)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $r.$c
            if ($v -is [System.Array]) { $v = ($v -join ', ') }
            if ($v -is [bool]) { $v = if ($v) { 'Yes' } else { 'No' } }
            [void]$sb.Append("<td>$(Enc $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    if (@($Rows).Count -eq 0) { [void]$sb.Append("<tr><td colspan=`"$($Columns.Count)`" class=`"muted`">None found</td></tr>") }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}

# Logical diagram: one column per AD site, one box per DC, with role badges.
function New-IdkSiteDiagram {
    param($Ad)
    $sites = @($Ad.sites)
    $dcsByName = @{}
    $pdcs = @{}
    foreach ($d in @($Ad.domains)) {
        $pdcs[$d.pdc_emulator] = $true
        foreach ($dc in @($d.domain_controllers)) { $dcsByName[$dc.name] = $dc }
    }
    $colW = 260; $gap = 24; $boxH = 64; $pad = 16; $headH = 44
    $maxServers = 1
    foreach ($s in $sites) { if (@($s.servers).Count -gt $maxServers) { $maxServers = @($s.servers).Count } }
    $width = [math]::Max(1, $sites.Count) * ($colW + $gap) + $gap
    $height = $headH + $maxServers * ($boxH + $pad) + $pad + 40
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<svg class=`"diagram`" viewBox=`"0 0 $width $height`" role=`"img`" aria-label=`"AD sites and domain controllers`">")
    $x = $gap
    foreach ($s in $sites) {
        $siteH = $height - 20
        [void]$sb.Append("<rect x=`"$x`" y=`"10`" width=`"$colW`" height=`"$siteH`" rx=`"10`" class=`"site`"/>")
        [void]$sb.Append("<text x=`"$($x + 14)`" y=`"36`" class=`"site-name`">Site: $(Enc $s.name)</text>")
        $subnets = (@($s.subnets) -join ', ')
        if (-not $subnets) { $subnets = 'no subnets defined' }
        [void]$sb.Append("<text x=`"$($x + 14)`" y=`"$($siteH + 2)`" class=`"site-sub`">$(Enc $subnets)</text>")
        $y = $headH + 6
        foreach ($srv in @($s.servers)) {
            $dc = $dcsByName[$srv]
            $badges = @()
            if ($pdcs[$srv]) { $badges += 'PDC' }
            if ($dc -and $dc.is_gc) { $badges += 'GC' }
            if ($dc -and @($dc.roles).Count -gt 0) { $badges += "$(@($dc.roles).Count) FSMO" }
            $short = ($srv -split '\.')[0]
            [void]$sb.Append("<rect x=`"$($x + 12)`" y=`"$y`" width=`"$($colW - 24)`" height=`"$boxH`" rx=`"6`" class=`"dc`"/>")
            [void]$sb.Append("<text x=`"$($x + 24)`" y=`"$($y + 24)`" class=`"dc-name`">$(Enc $short)</text>")
            $meta = @()
            if ($dc) { $meta += $dc.ip; $meta += (($dc.os -replace 'Windows Server ', 'WS ') -replace ' (Standard|Datacenter).*', '') }
            [void]$sb.Append("<text x=`"$($x + 24)`" y=`"$($y + 44)`" class=`"dc-meta`">$(Enc ($meta -join ' | '))</text>")
            if ($badges.Count -gt 0) {
                [void]$sb.Append("<text x=`"$($x + $colW - 24)`" y=`"$($y + 24)`" text-anchor=`"end`" class=`"dc-badge`">$(Enc ($badges -join ' | '))</text>")
            }
            $y += $boxH + $pad
        }
        $x += $colW + $gap
    }
    [void]$sb.Append('</svg>')
    $sb.ToString()
}

$ad = $run.modules.ActiveDirectory
$adData = if ($ad) { $ad.data } else { $null }
$findings = if ($adData) { Get-IdkAdFindings -Ad $adData -Now $Now } else { @() }

$counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
foreach ($f in $findings) { $counts[$f.severity]++ }

$body = New-Object System.Text.StringBuilder
$title = if ($adData) { "As-built: $($adData.forest.name)" } else { 'As-built report' }

foreach ($m in $run.modules.PSObject.Properties) {
    if ($m.Value.status -eq 'failed') {
        $msgs = (@($m.Value.errors) | ForEach-Object { "$($_.step): $($_.message)" }) -join ' | '
        [void]$body.Append("<div class=`"banner failed`">Module $(Enc $m.Name) failed, so this report has no data for it. Error: $(Enc $msgs)</div>")
    }
}
if ($run.sample) {
    [void]$body.Append('<div class="banner">SAMPLE REPORT: fictional data for demonstration. Not a real environment.</div>')
}
[void]$body.Append("<header><div class=`"kicker`">Infra Discovery Kit v$(Enc $run.version) &middot; read-only assessment</div><h1>$(Enc $title)</h1>")
[void]$body.Append("<p class=`"meta`">Collected $(Enc $run.collected_at) by $(Enc $run.collected_by) from $(Enc $run.collected_from) &middot; run $(Enc $run.run_id)</p></header>")

# Summary
[void]$body.Append('<section><h2>Summary</h2><div class="tiles">')
foreach ($sev in 'High', 'Medium', 'Low') {
    [void]$body.Append("<div class=`"tile sev-$($sev.ToLower())`"><div class=`"num`">$($counts[$sev])</div><div>$sev findings</div></div>")
}
if ($adData) {
    $dcTotal = 0; foreach ($d in @($adData.domains)) { $dcTotal += @($d.domain_controllers).Count }
    [void]$body.Append("<div class=`"tile`"><div class=`"num`">$dcTotal</div><div>domain controllers</div></div>")
    [void]$body.Append("<div class=`"tile`"><div class=`"num`">$(@($adData.sites).Count)</div><div>AD sites</div></div>")
}
[void]$body.Append('</div></section>')

# Findings
[void]$body.Append('<section><h2>Findings</h2>')
if (@($findings).Count -eq 0) { [void]$body.Append('<p class="muted">No findings.</p>') }
foreach ($f in $findings) {
    [void]$body.Append("<article class=`"finding sev-$($f.severity.ToLower())`"><div class=`"f-head`"><span class=`"sev`">$(Enc $f.severity)</span><span class=`"fid`">$(Enc $f.id)</span><strong>$(Enc $f.title)</strong></div>")
    [void]$body.Append("<p><span class=`"label`">Evidence</span> $(Enc $f.evidence)</p><p><span class=`"label`">Recommendation</span> $(Enc $f.recommendation)</p></article>")
}
[void]$body.Append('</section>')

if ($adData) {
    # Diagram
    [void]$body.Append('<section><h2>Logical diagram</h2>')
    [void]$body.Append((New-IdkSiteDiagram -Ad $adData))
    [void]$body.Append('</section>')

    # Forest and domains
    [void]$body.Append('<section><h2>Forest and domains</h2>')
    $forestRow = [pscustomobject]@{ name = $adData.forest.name; mode = (Get-IdkModeLabel $adData.forest.mode $adData.forest.mode_level); schema = $adData.forest.schema_master; naming = $adData.forest.naming_master; gcs = $adData.forest.global_catalogs }
    [void]$body.Append((ConvertTo-IdkTable -Rows @($forestRow) -Columns name, mode, schema, naming, gcs -Headers 'Forest', 'Functional level', 'Schema master', 'Domain naming master', 'Global catalogs'))
    $domainRows = @($adData.domains | Select-Object name, @{ n = 'mode'; e = { Get-IdkModeLabel $_.mode $_.mode_level } }, pdc_emulator, rid_master, infrastructure_master)
    [void]$body.Append((ConvertTo-IdkTable -Rows $domainRows -Columns name, mode, pdc_emulator, rid_master, infrastructure_master -Headers 'Domain', 'Functional level', 'PDC emulator', 'RID master', 'Infrastructure master'))
    [void]$body.Append('</section>')

    # DCs
    [void]$body.Append('<section><h2>Domain controllers</h2>')
    $dcRows = foreach ($d in @($adData.domains)) { foreach ($dc in @($d.domain_controllers)) { $dc | Select-Object @{n = 'domain'; e = { $d.name } }, name, ip, os, site, is_gc, roles } }
    [void]$body.Append((ConvertTo-IdkTable -Rows @($dcRows) -Columns domain, name, ip, os, site, is_gc, roles -Headers 'Domain', 'Name', 'IP', 'Operating system', 'Site', 'Global catalog', 'FSMO roles'))
    [void]$body.Append('</section>')

    # Sites
    [void]$body.Append('<section><h2>Sites and subnets</h2>')
    [void]$body.Append((ConvertTo-IdkTable -Rows @($adData.sites) -Columns name, subnets, servers, site_links -Headers 'Site', 'Subnets', 'Servers', 'Site links'))
    [void]$body.Append('</section>')

    # Time
    [void]$body.Append('<section><h2>Time synchronization</h2>')
    [void]$body.Append((ConvertTo-IdkTable -Rows @($adData.time) -Columns dc, is_pdc, source -Headers 'DC', 'PDC emulator', 'Current time source'))
    [void]$body.Append('</section>')

    # Accounts
    if ($adData.accounts) {
        $a = $adData.accounts
        $accRows = @(
            [pscustomobject]@{ item = 'Enabled users'; value = $a.enabled_users },
            [pscustomobject]@{ item = "Stale users (no logon in $($a.stale_days) days)"; value = $a.stale_users },
            [pscustomobject]@{ item = 'Enabled computers'; value = $a.enabled_computers },
            [pscustomobject]@{ item = "Stale computers (no logon in $($a.stale_days) days)"; value = $a.stale_computers },
            [pscustomobject]@{ item = 'Password never expires'; value = $a.password_never_expires },
            [pscustomobject]@{ item = 'adminCount=1 users'; value = $a.admincount_users },
            [pscustomobject]@{ item = 'Group Policy objects'; value = $adData.gpo_count }
        )
        [void]$body.Append('<section><h2>Accounts and policy</h2>')
        [void]$body.Append((ConvertTo-IdkTable -Rows $accRows -Columns item, value -Headers 'Item', 'Count'))
        [void]$body.Append('</section>')
    }

    # Raw evidence
    [void]$body.Append('<section><h2>Appendix: command evidence</h2>')
    foreach ($p in $adData.native.PSObject.Properties) {
        $n = $p.Value
        if (-not $n) { continue }
        $out = if ($n.available) { $n.output } else { '(tool not available on the collection host)' }
        [void]$body.Append("<details><summary><code>$(Enc $n.command)</code></summary><pre>$(Enc $out)</pre></details>")
    }
    if (@($ad.errors).Count -gt 0) {
        [void]$body.Append('<h3>Collection errors</h3>')
        [void]$body.Append((ConvertTo-IdkTable -Rows @($ad.errors) -Columns step, message -Headers 'Step', 'Message'))
    }
    [void]$body.Append('</section>')
}

$hashFile = "$InputPath.sha256"
$hashNote = if (Test-Path $hashFile) { (Get-Content $hashFile -Raw).Trim() } else { (Get-FileHash -Path $InputPath -Algorithm SHA256).Hash + '  (computed at report time)' }
[void]$body.Append("<footer>Evidence file SHA-256: <code>$(Enc $hashNote)</code><br>Generated $(Enc ($Now.ToString('yyyy-MM-dd HH:mm'))) by Infra Discovery Kit. Collection was read-only; no changes were made to the environment.</footer>")

$css = @'
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#dedbd2;--card:#fff;--accent:#2f5d8a;--high:#b3261e;--med:#b26a00;--low:#4a6b3a;--site:#eef3f8;--dc:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#3a3935;--card:#1f1f1d;--accent:#8ab4e0;--high:#f2867e;--med:#f0b35a;--low:#9cc488;--site:#1e2833;--dc:#262624}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 64px}
.banner{background:var(--med);color:#fff;padding:8px 12px;border-radius:6px;font-weight:600;margin-bottom:16px}.banner.failed{background:var(--high)}
.kicker{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.06em}h1{margin:4px 0 4px;font-size:28px}
.meta{color:var(--muted);margin:0 0 8px}h2{font-size:20px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:36px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.tile .num{font-size:28px;font-weight:700}
.tile.sev-high .num{color:var(--high)}.tile.sev-medium .num{color:var(--med)}.tile.sev-low .num{color:var(--low)}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--muted);border-radius:6px;padding:10px 14px;margin:10px 0}
.finding.sev-high{border-left-color:var(--high)}.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}
.f-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.sev{font-weight:700;font-size:12px;text-transform:uppercase}
.sev-high .sev{color:var(--high)}.sev-medium .sev{color:var(--med)}.sev-low .sev{color:var(--low)}.fid{color:var(--muted);font-family:Consolas,monospace;font-size:13px}
.finding p{margin:6px 0}.label{display:inline-block;min-width:118px;color:var(--muted);font-size:13px}
.table-wrap{overflow-x:auto;margin:10px 0}table{border-collapse:collapse;width:100%;background:var(--card)}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top;font-size:14px}th{background:var(--site)}
.muted{color:var(--muted)}pre{white-space:pre-wrap;background:var(--card);border:1px solid var(--line);padding:10px;border-radius:6px;font-size:12.5px}
details{margin:8px 0}summary{cursor:pointer}
.diagram{width:100%;height:auto;max-height:520px}.site{fill:var(--site);stroke:var(--line)}.dc{fill:var(--dc);stroke:var(--accent)}
.site-name{font-weight:700;font-size:15px;fill:var(--fg)}.site-sub{font-size:12px;fill:var(--muted)}.dc-name{font-weight:700;font-size:15px;fill:var(--fg)}
.dc-meta{font-size:12px;fill:var(--muted)}.dc-badge{font-size:12px;font-weight:700;fill:var(--accent)}
footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:12px}
@media print{.banner{-webkit-print-color-adjust:exact;print-color-adjust:exact}details{display:block}details>pre{display:block}}
'@

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(Enc $title)</title><style>$css</style></head>
<body><main>$($body.ToString())</main></body></html>
"@

Set-Content -Path $OutputPath -Value $html -Encoding UTF8
Write-Host "Report: $OutputPath ($(@($findings).Count) findings)"
