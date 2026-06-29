# Changelog

All notable changes to doze_sec are recorded here. This is the project release
history; the per-run `ChangeLog_<timestamp>.txt` files under `C:\SecurityAudit`
are a separate, machine-specific record of changes each audit made.

## 7.3

### New: `-dnsprobe` active DNS integrity probe (opt-in)
Adds an opt-in active DNS check (Section 3, `tools/dns_probe.ps1`). When
`-dnsprobe` is passed, the audit resolves a fixed list of **legitimate**
Windows / Defender / connectivity domains and flags any that fail to resolve
or resolve to a non-public IP (0.0.0.0 / loopback / private / link-local) — the
signature of malware blackholing update/AV traffic via a DNS or HOSTS hijack
(T1562.001). It also inventories the configured DNS resolvers.

**Safe by design:** it never resolves attacker / `ioc_domains.txt` C2 entries,
so it sends no outbound queries to malicious infrastructure. That
higher-fidelity but OPSEC-risky variant remains deferred (see THREAT_MODEL.md).
Off by default; gated like `-vt`. A blackhole signature raises the exit code to
WARNING and is surfaced as a finding in the live summary + HTML Findings Index
(under ACTIVE COMPROMISE INDICATORS), not just buried in the Section 3 body. The
new script is parsed and executed by the helpers-ps51 CI job.

## 7.2

Accuracy and trust release. Every change below makes the tool report reality
more faithfully — no false alarms, and a change log / undo script that lists
only changes actually made.

### CTI / IOC false-positive fixes
- **Registry IOC sweep (18h):** value-based entries now fire only when the
  value equals the *malicious* value (`HIVE\KEY|Value|BadValue`). Hardened
  settings such as `EnableLUA=1` and `RunAsPPL=1` are no longer flagged as
  compromise indicators.
- **Baseline cleanup:** stripped non-discriminating `# CTI-AUTO` entries that a
  prior `-updateTTP` mirror had committed into the shipped IOC lists
  (`ioc_processes.txt`, `ioc_registry.txt`, `ioc_file_paths.txt`,
  `ttp_manifest.txt`), e.g. `msbuild`, ubiquitous registry keys like `RunMRU`,
  and overly-broad path globs. The shipped baseline is now purely hand-curated.
- **Browser extensions:** expanded the first-party component allowlist so Edge /
  Chrome / Brave built-ins are not flagged as sideloaded.

### `-updateTTP` no longer pollutes the repo
- Merges are written only to the runtime `C:\SecurityAudit\ThreatLists`, never
  back into the git checkout — so `git pull` is never blocked and the baseline
  cannot drift.
- **New `-resetTTP` flag:** restores the runtime ThreatLists to the pristine
  shipped baseline (clears runtime `ioc_*.txt` / `ttp_manifest.txt`). Combine
  with `-updateTTP` for "clean slate, then fresh pull."

### Reporting accuracy
- **System event log cleared (event 104)** is now `WARNING`, not `CRITICAL`
  (Windows updates / driver installs / disk cleanup routinely clear it). The
  Security log (1102) clearing — the real attacker cover-up signal — stays
  `CRITICAL`.
- **HTML report Findings Index:** a panel at the top lists every CRITICAL and
  WARNING finding, each linking to its section. Dashboard counts now come from
  the report's own verdict line (previously inflated by incidental matches).
  The HTML generator moved to a CI-tested `tools/report_html.ps1`.
- **Change log / undo now record only real changes:**
  - INIT 11 (F8 boot menu) logs `displaybootmenu` / `timeout` changes only when
    the value actually differs from the target — no more phantom
    `was "5" -- set to "5"` entries.
  - INIT 12 (System Restore Point) logs `[CREATED]` only when a restore point
    was actually created (Windows throttles these to one per 24h).

### Counts synced
`ioc_processes` 77→54, `ioc_registry` 37→25, `ttp_manifest` / techniques 77→48,
total indicators 320→283 (README / THREAT_MODEL / readMe).

### Hardening — extract risky inline PowerShell from the INIT path
The crash class behind the INIT 12 and HTML regressions is PowerShell built by
echoing lines into a temp file: a single mis-escaped cmd metacharacter aborts
the whole audit. Extracted the remaining nested INIT-path blocks into
CI-tested `tools/*.ps1` (no cmd escaping):
`self_update_check.ps1` (INIT 10 self-update), `disk_info.ps1` (INIT 13 VM /
SSD / disk-detail / free-space), `smart_health.ps1` (INIT 14 WMI health
fallback), alongside the earlier `report_html.ps1` and `srp_check.ps1`. The
helpers-ps51 CI job now parses and executes all of them. Behavior is
unchanged; this only removes the escaping hazard.

## 7.1 and earlier

See the git history. 7.1 introduced the SENTINEL-X CTI integration, the HTML
report, the `-updateTTP` / `-importTTP` pipeline, and the real-Windows
smoke-test CI.
