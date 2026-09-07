# Changelog

All notable changes to doze_sec are recorded here. This is the project release
history; the per-run `ChangeLog_<timestamp>.txt` files under `C:\SecurityAudit`
are a separate, machine-specific record of changes each audit made.

## Unreleased

### Confirmed on a real machine: the Sticky Keys ledger raise works, debt retired
The Sticky Keys finding now reaches the findings ledger on the owner's own
Windows 11 machine, not merely on a CI runner:
`WARNING|13|T1546.008|Sticky Keys shortcut enabled - Shift x5 triggers
sethc.exe at the logon screen`. Its remediation and the matching undo are both
present in the generated scripts.

Its `addfix` had been triggered by `($joined -match 'Sticky Keys shortcut
enabled') -or (led 'WARNING' '13' 'T1546.008' 'Sticky Keys')`. The first half
was deliberate temporary debt: matching the DASHBOARD PROSE is exactly what
queued an elevated command for a finding the tool did not count, and it was
kept only until the ledger half could be shown to fire on real hardware. It
has, so the prose half is gone and the trigger is the ledger alone.

The same report confirms the rest of the chain end to end: the header reads
`0 CRITICAL / 9 WARNING -- 30 DASHBOARD CHECKS PASSED`, `FINDINGS COUNTED: 9`,
and the ledger holds exactly 9 rows. Header, count and ledger agree, with no
`AUDITGAP` anywhere in the report.

### Fixed: the driver signature grade could not be tested at all
`tools/driver_audit.ps1` decided whether a kernel driver is unsigned with a
bare `Get-AuthenticodeSignature` inline in its scan loop, with no injection
point — unlike `service_signature_check.ps1`, `module_inspect.ps1` and
`proc_path_grade.ps1`, which all grade behind an injectable probe. The rule
most likely to be wrong was the only one no test could exercise.

It is now a pure `Get-DriverVerdict` behind `$script:SigProbe` /
`$script:HashProbe`, with a `-SelfTest` covering eight cases in both
directions. No behaviour change. One case asserts the emitted message still
matches the regex `tests/benign_corpus.txt` keys on, so rewording it can no
longer silently decouple that entry.

Two latent platform dependencies surfaced and were removed:
`[IO.Path]::GetFileName` treats `\` as a separator only on Windows, so off
Windows it returned the entire path and every known-bad *name* rule stopped
matching; and `Join-Path` resolves the drive and throws when it does not
exist, which a pure grading function must not depend on.

### Corrected: the driver-catalog gap does not exist, and bthmodem is a TRUE finding
Three documents — `README.md`, `docs/design/backlog.md` and
`tests/benign_corpus.txt` — asserted that `Get-AuthenticodeSignature` cannot
read driver-store catalog signatures, and that `bthmodem.sys` reporting
`NotSigned` on the owner's machine was therefore a false positive needing a
`WinVerifyTrust` catalog-member lookup. All three were wrong, and none of the
claim had ever been measured.

Measured on the owner's own machine (Windows 11 26200, elevated, CryptSvc
running, 5,493 catalogs present and readable):

```
Total .sys: 467
   Valid/Catalog      = 464
   Valid/Authenticode = 2
   NotSigned/None     = 1     <- bthmodem.sys, alone
```

and direct queries of BOTH catalog databases, by SHA256 and by SHA1, all
returned *no catalog covers this file*, with `SignatureType=None` and no
signer. Catalogs are keyed by file hash and they accumulate, so a
legitimately-shipped-but-superseded Microsoft driver would very likely still
match one of the 5,493. Matching none means those bytes are not a version
Microsoft shipped to that machine.

**The tool's warning is correct.** The planned fix would have suppressed it.

The `[driver-catalog-signed-inbox]` corpus entry is removed rather than
reworded — it claimed a benign cause that does not exist, for a finding that
appears to be true, and an entry like that teaches a reader to dismiss a real
one. A tombstone comment records the measurement so it is not re-added on the
dead theory. README and the backlog are corrected in place.

*Why* that one file has no catalog — corruption, a third-party or OEM package,
an odd servicing outcome, or tampering, which all produce the same answer — is
open and tracked in the backlog.

### Measured: PowerShell 5.1 already reads driver catalog signatures
The backlog, the README and `tests/benign_corpus.txt` all held that
`Get-AuthenticodeSignature` cannot read driver-store catalog signatures, and
that `bthmodem.sys` reporting `NotSigned` was therefore a false positive
needing `WinVerifyTrust` with a catalog-member lookup.

Measured on a real runner (Windows Server 2025 26100, PowerShell 5.1.26100):
all 457 drivers in `System32\drivers` reported `Status=Valid`, and every one
sampled reported `SignatureType=Catalog`. **5.1 already resolves driver
catalogs.** The planned P/Invoke would have solved a problem that does not
exist, and would have suppressed a warning that may be correct.

The false positive does not reproduce on a clean machine at all. On the
owner's machine `bthmodem.sys` is the *only* driver reporting `NotSigned` —
one file, not many — which rules out a broken catalog subsystem and points at
that single driver being genuinely uncovered. Diagnosis continues against the
machine where it actually happens; no fix is shipped on a theory again.

### Fixed: no `:dz_ps_scan` block had ever raised a finding
`:dz_ps_scan` read its severity back through a `for /f` backtick whose command
began with a quoted absolute path. cmd runs such a command through `cmd /c`,
which strips the leading and trailing quote when the line begins with one, so
the invocation was mangled, produced no output, and `DZ_BLKSEV` kept its `OK`
default. All eighteen call sites in both bats were affected — Office macro
policy, Secure Boot, AMSI-bypass traces in PowerShell logs, RDP shadowing and
the nation-state TTP blocks all printed findings into the report that reached
neither the findings ledger, `FINDINGS COUNTED`, the section verdict nor the
exit code.

Only checks carrying a marker backstop survived, and the backstop masked the
failure rather than exposing it: the ASR block raises its message from the
marker precisely *when the grade came back `OK`*, so its ledger row looked like
proof the grader worked.

The grade is now read through a file and `set /p`. `DZ_BLKSEV` starts at
`DZ_NOGRADE` rather than `OK`, so a grade that is never read is declared an
`AUDITGAP` instead of passing as clean.

**Reports will show more findings than before.** Nothing new is being detected;
these are checks that were already printing into the report while the verdict
ignored them.

### Fixed: the HTML dashboard rendered 0/0/0 on machines with real findings
`report_html` builds its dashboard by matching the text report's verdict line.
When that header gained ledger-derived counts its separator changed from `/` to
` -- `, the regex stopped matching, and the cards rendered zero while the text
report showed the true numbers. The CI fixture still used the old format, so a
test existed and proved nothing. All shapes are now matched, the fixture is the
current one, and all three counts are asserted.

### Fixed: the summary header contradicted `FINDINGS COUNTED`
The header counted dashboard tiles, so a report could read
`0 CRITICAL / 3 WARNING / 30 PASSED` and end `FINDINGS COUNTED: 7`. The
CRITICAL and WARNING halves now derive from the same ledger; the third number
stays a tile count and says so.

### Fixed: Sticky Keys printed a finding that was never counted
Section 13 printed `[WARN] Sticky Keys shortcut ENABLED` — a spelling none of
the three gates recognised. `[CRITICAL]` and `[WARNING]` are now the report's
entire severity vocabulary, enforced on the `%REPORT%` and `%PSRUN%` paths.

### Fixed: MSIX package binaries reported as unsigned
MSIX signs the package, not each inner file, so `Get-AuthenticodeSignature` on
the inner `.exe` correctly returns `NotSigned`. `SignatureKind` is now the
oracle: `Store`/`System` are inventory, `Developer`/`Enterprise` and `None`
stay findings, and an unresolvable package fails closed.

### Fixed: false positives on HOSTS, COM CLSIDs, BITS and browser extensions
A machine's own hostname mapped to its own private address is no longer a DNS
hijack; a dangling vendor COM registration is context; an empty BITS notify
command line is not a finding; and a store-installed extension is graded on
provenance rather than permissions alone.

### New gates
`tests/assert_printed_findings_raised.ps1`, `tests/assert_header_matches_ledger.ps1`,
`tools/lint_ps51_portability.ps1`, and artifact parity in `tools/lint_docs_drift.ps1`.

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
