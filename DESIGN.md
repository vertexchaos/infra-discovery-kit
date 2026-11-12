# Infra Discovery Kit: design

**Status:** v0.1. Started 2026-11-11.

## 1. The problem

Most infrastructure projects have the same shape:

> "Confirm what this environment actually does → find what depends on it → change it safely → leave documentation the team can run it from."

Typical examples:
- Adding DC redundancy, or retiring a legacy domain controller.
- Retiring an old on-prem server ("what is it actually doing?").
- A modernization roadmap that starts from an honest current state.
- Any change where evidence has to be preserved before touching production.

Done by hand, that's hours of ad-hoc commands and copy-paste per environment. The kit turns it into one read-only run that produces evidence, findings and an as-built report.

## 2. Goals and non-goals

**Goals**
1. **Read-only, provably.** The kit never changes the environment it scans, and a test enforces that (§6).
2. **Zero install.** Copy one folder and run it. Uses Windows PowerShell 5.1 and built-in .NET, so no RSAT, no modules and no internet are needed for the core.
3. **Evidence first.** Raw output is kept as JSON with a timestamp, who ran it, from which host, and a SHA-256 hash. It answers the "preserve evidence before changes" requirement.
4. **Partial failure is fine.** Each collector step that fails is recorded with its error, and the run continues.
5. **Client-ready output.** A self-contained HTML as-built report with a logical diagram and ranked findings, which prints cleanly to PDF.
6. **Reuse across jobs.** Every module writes the same envelope, so reports, diffs ("before vs after cutover") and dashboards work for every module.

**Non-goals (v0.x)**
- Remediation or "fix" switches of any kind. Fixes stay manual, approved and logged.
- An agent or service left running on client machines (that's the separate T7 product).
- Continuous monitoring.

## 3. Architecture

```
 Collectors (read-only)        Analyzer (rules)          Renderers
 ─────────────────────         ────────────────          ─────────
 ActiveDirectory.ps1  ┐                                  ┌─ As-built HTML (v0.1)
 WindowsServer.ps1    ├──► run JSON  ──►  findings  ──►  ├─ Findings CSV (v0.2)
 HyperV.ps1           │   (+ SHA-256)    (id, severity,  ├─ Before/after diff (v0.2)
 VMware.ps1           │                  evidence, fix)  └─ Word export (later)
 M365.ps1             ┘
```

- **Collectors** gather data only. Each returns `@{ data = ...; errors = @(...) }`.
- **The analyzer** runs **at report time**, not collection time. Rules can improve later and be re-run over old evidence without touching the client again.
- **Renderers** only read run JSON, so they can be developed and tested offline against sample files.

### Run file envelope

```json
{
  "tool": "infra-discovery-kit",
  "version": "0.1.0",
  "run_id": "20261111-153000",
  "collected_at": "2026-11-11T23:30:00Z",
  "collected_by": "CONTOSO\\jvaldes-ro",
  "collected_from": "MGMT01",
  "sample": false,
  "modules": {
    "ActiveDirectory": {
      "status": "ok | partial | failed",
      "duration_s": 12.4,
      "errors": [{ "step": "time.DC02", "message": "..." }],
      "data": { }
    }
  }
}
```

### Findings shape

```json
{ "id": "AD-004", "severity": "High", "title": "SYSVOL still replicates with FRS",
  "evidence": "dfsrmig /getglobalstate: ...", "recommendation": "...", "catalog": "T1" }
```

Severity is **High** (outage or blocker risk), **Medium** (supportability or security debt), **Low** (hygiene) or **Info**.

## 4. Modules and roadmap

| Version | Module | Collects | Typical client ask |
|---|---|---|---|
| **0.1** | **ActiveDirectory** | Forest/domain modes; FSMO; DCs (OS, IP, site, GC); sites, subnets, links; trusts; replication summary; SYSVOL DFSR/FRS state; time source per DC; stale users/computers; adminCount and password-never-expires counts; GPO count | DC redundancy, AD modernization, retire an old DC |
| 0.2 | WindowsServer | Roles/features; shares and sizes; printers; services and scheduled tasks running as domain accounts; listening ports; installed apps | "What is this server actually doing?" |
| 0.2 | Dependency sampler | Repeated `Get-NetTCPConnection` snapshots on DCs/servers over N hours; DNS records pointing at the server's IPs; SPNs; Kerberos 4769 / LDAP 2889 events if already logged | "What breaks if we turn it off?" |
| 0.2 | Diff renderer | Compare two runs (before/after cutover) | "Prove nothing changed / was lost" (T4) |
| 0.3 | HyperV | Hosts, VMs, cluster, CSV, checkpoints, integration services | Hyper-V cluster design / 2008 retirement |
| 0.3 | VMware | via PowerCLI if present: vCenter, hosts, datastores, multipathing, snapshots older than N days, VM tools | Snapshot cleanup, storage/encryption work |
| 0.3 | Nutanix | Prism v3 REST, read-only user: clusters, hosts, VMs, storage containers | Nutanix deploy/migration |
| 0.4 | M365 / Entra | Graph, read-only app or delegated: "Anyone" links, guests, stale accounts, ownerless sites, labels, licenses | Copilot readiness, offboarding cleanup (T5) |
| 0.4 | Backup | Veeam/WSB job state, last successful restore points, DC system-state age | DR readiness (T6) |

**Dependency discovery note.** Turning on LDAP diagnostics logging (for event 2889) **is a change**, so the kit never does it. The design doc for the client lists it as an optional, approved step. The kit only reads logs that already exist, plus passive connection sampling.

## 5. Findings rules in v0.1 (AD)

| ID | Severity | Rule | Why clients care |
|---|---|---|---|
| AD-001 | High | A domain has only one DC | Loss of one server stops authentication |
| AD-002 | High / Medium | DC OS out of support (2008/2012) or ending within 12 months (2016 ends 2027-01-12) | Security and support; blocks new features |
| AD-003 | Medium | Domain/forest functional level below 2016 | Blocks newer DCs and features |
| AD-004 | High | SYSVOL migration not in `Eliminated` state (FRS) | FRS blocks adding Server 2019+ DCs |
| AD-005 | High | PDC emulator uses its local clock | Domain-wide time drift → Kerberos failures |
| AD-006 | Medium | A non-PDC DC doesn't follow the domain hierarchy | Inconsistent time |
| AD-007 | High | Replication failures in `repadmin /replsummary` | Divergent directory, lingering objects |
| AD-008 | Low | Stale enabled users/computers (no logon in N days) | Attack surface, licensing |
| AD-009 | Low | Users with password-never-expires | Credential hygiene |
| AD-010 | Low | Many accounts with adminCount=1 | Privileged sprawl to review |
| AD-011 | Low | A site with DCs but no subnets | Clients authenticate against the wrong site |

## 6. Safety model

- **Allowed operations:** `Get-*` cmdlets, .NET `System.DirectoryServices` reads, and an allowlist of native queries: `repadmin /replsummary`, `dfsrmig /getglobalstate`, `w32tm /query ...`, `dcdiag /q`. `dcdiag /fix` and anything with `/set`, `/config` or `/resync` are banned.
- **Lint test:** `tests/Test-ReadOnly.ps1` parses every collector and fails on banned verbs (`Set-`, `New-`, `Remove-`, `Add-`, `Enable-`, `Disable-`, `Start-`, `Stop-`, `Restart-`, `Invoke-WebRequest` etc.) and on banned native switches. Run it before every release.
- **Credentials:** never collected. No password hashes, no LAPS attributes, no secrets. The kit runs as whatever account starts it. The docs recommend a dedicated read-only account (Domain Users is enough for most AD reads; `repadmin`/`dcdiag` need more).
- **Data handling:** output stays in the local `output/` folder. Planned v0.2 `-Redact` switch: replace names/IPs with stable tokens for sample reports and portfolio use.
- **Integrity:** every run file gets a `.sha256` next to it, so the client can verify evidence wasn't edited.

## 7. Packaging and distribution

- Each version is a GitHub release with a zip asset and a `SHA256SUMS` file.
- **Quick start:** `install.ps1` is a bootstrap for `irm ... | iex`. It downloads the pinned release zip, verifies its SHA-256 and runs the kit from `%TEMP%`. The execution-policy bypass applies to that PowerShell process only.
- **Locked-down environments:** download the zip, verify it against `SHA256SUMS`, then run `powershell -ExecutionPolicy Bypass -File .\Invoke-Discovery.ps1 -Report`.
- **Later:** Authenticode-signed scripts, because many organizations block unsigned PowerShell.
- Ships with a sample report built from fictional `contoso.local` data (`samples/`).
