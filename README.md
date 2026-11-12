# Infra Discovery Kit

Read-only discovery for Windows infrastructure. One run collects evidence and flags risks, then writes an as-built report a team can operate the environment from.

**v0.1** covers Active Directory: forest and domains, FSMO roles, domain controllers, sites and subnets, trusts, replication, SYSVOL (FRS/DFSR), time sources, and account hygiene. Hyper-V, VMware, Nutanix, Windows Server roles and Microsoft 365 are on the [roadmap](DESIGN.md#4-modules-and-roadmap).

## Quick start

Run this in an elevated **Windows PowerShell** on a domain controller or a domain-joined management host:

```powershell
irm https://raw.githubusercontent.com/vertexchaos/infra-discovery-kit/v0.1.1/install.ps1 | iex
```

The bootstrap:
1. Downloads the pinned v0.1.1 release zip.
2. Verifies the zip against the release's `SHA256SUMS`, and refuses to run on a mismatch.
3. Extracts it to `%TEMP%\infra-discovery-kit-0.1.1`.
4. Runs the collection and builds the report into its `output\` folder.

To download and verify without running:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/vertexchaos/infra-discovery-kit/v0.1.1/install.ps1))) -NoRun
```

### Environments that don't allow `irm | iex`

1. Download `infra-discovery-kit-0.1.1.zip` and `SHA256SUMS` from the [release page](https://github.com/vertexchaos/infra-discovery-kit/releases/tag/v0.1.1).
2. Check the hash: `Get-FileHash .\infra-discovery-kit-0.1.1.zip -Algorithm SHA256`.
3. Extract the zip and run `powershell -ExecutionPolicy Bypass -File .\Invoke-Discovery.ps1 -Report`.

## Output

- **`run-<timestamp>.json`:** raw evidence, plus who ran it, from where and when.
- **`run-<timestamp>.json.sha256`:** the hash, so you can show the evidence wasn't edited.
- **`run-<timestamp>.html`:** a self-contained as-built report with ranked findings, a logical site/DC diagram, configuration tables and the raw command output. It prints cleanly to PDF.

See [`samples/contoso-sample.html`](samples/contoso-sample.html) for a report built from fictional data. Download it and open it in a browser.

## Read-only by design

- Uses only `Get-*` cmdlets, built-in .NET `System.DirectoryServices` reads, and an allowlist of native queries: `repadmin /replsummary`, `dfsrmig /getglobalstate`, `w32tm /query`, `dcdiag /q`. Anything else is refused at runtime.
- `tests/Test-ReadOnly.ps1` parses every collector and fails on state-changing commands or switches.
- Never collects passwords, hashes, LAPS attributes or other secrets.
- No modules or RSAT required. Needs Windows PowerShell 5.1.

**Permissions:** an ordinary domain user can read most of AD. `repadmin` and `dcdiag` give fuller results when run as a Domain Admin on a DC.

## Findings in v0.1

| ID | Checks |
|---|---|
| AD-001 | Domain has a single DC |
| AD-002 | DC OS out of support, or ending within 12 months |
| AD-003 | Domain or forest functional level below 2016 |
| AD-004 | SYSVOL still on FRS |
| AD-005 | PDC emulator on its local clock |
| AD-006 | Other DCs not following the domain time hierarchy |
| AD-007 | Replication failures |
| AD-008–010 | Stale accounts, password-never-expires, privileged sprawl |
| AD-011 | Sites with DCs but no subnets |

Design notes: [DESIGN.md](DESIGN.md).
