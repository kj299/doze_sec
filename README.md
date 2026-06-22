# doze_sec

Windows 10/11 security forensic audit tool with SENTINEL-X CTI integration.

**Version 7.2** | 18-section audit | 48 MITRE ATT&CK techniques | 10 IOC categories

Detection-and-response aid, not real-time protection — see [THREAT_MODEL.md](THREAT_MODEL.md) for exactly what is and is not covered.

## What It Does

Standalone batch script that audits a Windows workstation for nation-state TTPs, ransomware indicators, credential theft artifacts, persistence mechanisms, and misconfigurations. Produces a timestamped text report, a navigable HTML report with color-coded findings, and a color-coded terminal summary.

## Scripts

| Script | Requires Admin | Description |
|--------|:-:|-------------|
| `doze_sec.bat` | Yes | Full 18-section audit with all checks |
| `doze_sec_noAdmin.bat` | No | Adaptive audit. Admin-only checks marked `[DEFERRED]` |

## Quick Start

```
:: Full audit (right-click > Run as administrator)
doze_sec.bat

:: Non-admin audit
doze_sec_noAdmin.bat -noAdmin

:: Skip restore point + skip GitHub update
doze_sec.bat -nosrp -sdu

:: Refresh threat intel before audit
doze_sec.bat -updateTTP

:: Include VirusTotal lookups for priority files (requires ~/.vt_token)
doze_sec.bat -vt

:: All options
doze_sec.bat -help
```

## Switches

| Switch | Script | Description |
|--------|--------|-------------|
| `-dev` | Both | Bypass unsupported OS check (Server, Win8.1, unknown builds) |
| `-resume` | Both | Skip pre-flight steps 8-14 (used by RunOnce after reboot) |
| `-sdu` | Both | Skip threat intel list update from GitHub |
| `-nosrp` | Both | Skip System Restore Point creation |
| `-noAdmin` | noAdmin only | Run without elevation; defers admin-only checks |
| `-updateTTP` | Admin only | Refresh ThreatLists/ via SENTINEL-X CTI skill (requires Claude Code CLI) |
| `-importTTP <file>` | Admin only | Merge TTP rows from a pipe-delimited file (offline alternative to `-updateTTP`; no Claude CLI needed) |
| `-vt` | Both | Section 18j+18l: query VirusTotal for SHA256 of priority files + remote IP reputation. Requires `~/.vt_token` |
| `-noVtSelf` | Both | Skip the automatic pre-flight VT integrity check on script-critical binaries (default: runs whenever `~/.vt_token` exists and network is up) |
| `-ctiSkill <file>` | Admin only | Per-run override for the SENTINEL-X CTI skill file used by `-updateTTP` (1.2.0+: `standalone\cyber-threat-intel-prompt.md`; pre-1.2.0: `cyber_threat_skill.yaml`). Beats `DOZESEC_CTI_SKILL` env var and auto-discovery |
| `-noConsoleLog` | Both | Skip console-output capture (default ON). Without this switch, stdout+stderr are tee'd to `C:\SecurityAudit\AuditConsole_<TS>.log` so crashes leave a debuggable trace |
| `-help` | Both | Show usage guide with section descriptions |

## Output Files

Every run produces (timestamped, so multiple runs don't clobber each other):

| Path | Always | Description |
|------|:-:|-------------|
| `C:\SecurityAudit\SecurityReport_<TS>.txt` | yes | Text report (everything `>>`-redirected during the audit) |
| `C:\SecurityAudit\SecurityReport_<TS>.html` | yes | HTML report (color-coded, generated at end) |
| `C:\SecurityAudit\AuditConsole_<TS>.log` | yes (unless `-noConsoleLog`) | Full stdout+stderr console capture — primary debug source if the script crashes mid-run |
| `C:\SecurityAudit\ChangeLog_<TS>.txt` | yes | Auto-applied configuration changes |
| `C:\SecurityAudit\Undo_<TS>.bat` | yes | Rollback commands for the ChangeLog |
| `C:\SecurityAudit\Remediation_<TS>.ps1` | when findings exist | Suggested remediation script (user must review + flip the gate) |
| `C:\SecurityAudit\SmartData\` | yes | SMART disk-health snapshots |
| `C:\SecurityAudit\EventExports\` | yes | Windows event log exports |
| `C:\SecurityAudit\ThreatLists\` | yes | Local IOC lists + CTI manifest |

All artifacts from a single run share the same `<TS>`, so they group naturally when sorted by name.

## Audit Sections

### Pre-Flight (INIT 1-14)

Temp path check, admin detection, OS version, OS compatibility, Safe Mode, log directory creation, resume detection, RunOnce key, network connectivity, self-update, F8 boot menu, System Restore Point, disk config, SMART health.

### Security Audit (1-18)

| # | Section | Admin Required | Key Detections |
|---|---------|:-:|----------------|
| 1 | System identity and patch level | No | Unpatched OS, CVE exposure |
| 2 | User accounts and privilege audit | No | Rogue accounts, SID anomalies |
| 3 | Network configuration and connections | No | C2 callbacks, DNS anomalies, open shares |
| 4 | Running processes | No | LOLBins, RMM tools, suspicious paths |
| 5 | Startup and persistence | No | Run keys, Winlogon, IFEO debuggers |
| 6 | Scheduled tasks | No | Malicious tasks, action-path detection (PS CSV, Task-To-Run column only) |
| 7 | Windows services | Partial | Authenticode signature gating per service binary (vendor allowlist + revocation + expiry + bad-path); unusual accounts |
| 8 | Firewall configuration | Yes | Disabled profiles, risky rules |
| 9 | Defender and AV status | Yes | Disabled Defender, exclusions, tamper; ASR rules audit (per-rule mode + key-rule warnings) |
| 10 | SMB, RDP, remote access | Partial | SMBv1, NLA bypass, open RDP |
| 11 | PowerShell security | Partial | Unrestricted execution, logging gaps |
| 12 | Credential and LSASS protection | No | PPL disabled, WDigest, Credential Guard |
| 13 | System hardening | Partial | UAC, BitLocker, SecureBoot, test signing; Office macro policy (VBAWarnings, MOTW macro block), Mark-of-the-Web preservation, SmartScreen |
| 14 | Suspicious files | No | ADS streams, double extensions, recent EXE/DLL/PS/VBS in user `%TEMP%` and `C:\Windows\Temp` (admin) |
| 15 | Installed software and drivers | No | Unsigned drivers, vulnerable software; browser-extension inventory (T1176) — flags sideloaded/dev-mode, malware-favored permissions, policy force-installs across Chrome/Edge/Brave/Vivaldi/Firefox |
| 16 | Event log anomalies | Partial | Log clearing (1102), brute force (4625), lateral (4624) |
| 17 | Nation-state threat indicators | No | MDDR 2023-2025 TTPs, portproxy, WMI persistence (CommandLine + ActiveScript consumers; SCM defaults allowlisted by Name+Query) |
| 18 | CTI-driven IOC sweep | No | SENTINEL-X file-based + inline CTI checks |

## Section 18: CTI IOC Sweep

Reads structured IOC files from `ThreatLists/` and matches against the live system, then runs inline CTI checks for advanced threats. Both `doze_sec.bat` (admin) and `doze_sec_noAdmin.bat` execute the full 18a-18i file-based sweep; `IOC_HITS` increments per sub-check and rolls up into the live security scorecard verdict.

**File-based checks (18a-18i):**

| Sub | Check | Method |
|-----|-------|--------|
| 18a | Process name IOC match | `wmic process` vs `ioc_processes.txt` |
| 18b | Named pipe IOC match | PowerShell pipe enum vs `ioc_named_pipes.txt` |
| 18c | Service IOC match | PowerShell service enum vs `ioc_services.txt` |
| 18d | Malware staging paths | `Test-Path` vs `ioc_file_paths.txt` |
| 18e | Scheduled task IOC match | `schtasks` (PS CSV) vs `ioc_scheduled_tasks.txt` -- TaskName + Task To Run columns only |
| 18f | DNS cache C2 domains | `ipconfig /displaydns` vs `ioc_domains.txt` |
| 18g | LOLBin command patterns | `wmic process` vs `ioc_lolbins.txt` |
| 18h | Registry IOC check | `reg query` vs `ioc_registry.txt` |
| 18i | TTP coverage summary | `ttp_manifest.txt` dump |
| 18j | VirusTotal hash reputation (opt-in via `-vt`) | `Get-FileHash` SHA256 -> VT API; capped at 20 priority files; rate-limited for free tier |
| 18k | Local hash IOC match (always-on) | `Get-FileHash` SHA256 vs `ioc_hashes.txt`; offline complement to 18j |
| 18l | VirusTotal IP reputation (opt-in via `-vt`) | `Get-NetTCPConnection` (Established) -> VT API; capped at 10 public remote IPs; rate-limited for free tier |

**Inline CTI checks:**
- Sliver / Havoc / Brute Ratel named pipes
- DLL search order hijacking (T1574.001)
- Browser credential store access via DPAPI (T1555.003)
- AiTM phishing token cache artifacts (T1557.001)
- Ransomware file extension survey (T1486)
- BYOVD vulnerable driver detection (T1562.001)
- COM object hijacking (T1546.015) -- vendor-allowlist with word-boundary anchors, plus Authenticode signature, revocation (Test-Certificate), and expiry checks; labels distinguish trusted-signer vs unexpected-signer when paired with bad-path
- Cloud CLI token theft (Azure/AWS/GCP)
- OpenSSH server lateral movement surface
- LOLBin download cradles in Event 4688 (admin only)
- AMSI bypass patterns in PowerShell logs (admin only)
- Suspicious service installs from Event 7045 (admin only)
- Explicit credential logons from Event 4648 (admin only)

## ThreatLists/

Plain-text IOC files. One entry per line. `#` = comment.

| File | Entries | Format | Content |
|------|:-------:|--------|---------|
| `ioc_processes.txt` | 54 | Process name | Ransomware, C2, cred tools, recon (FP-prone RMM/admin-tool entries removed) |
| `ioc_named_pipes.txt` | 32 | Pipe name | Cobalt Strike, Sliver, Havoc, Mythic, PsExec |
| `ioc_services.txt` | 24 | Service name | C2 implants, BYOVD, ransomware (legitimate RMM/HWMonitor entries removed) |
| `ioc_registry.txt` | 25 | `HIVE\Path\|Value\|BadVal` | Persistence, COM hijack, defense evasion (value-state entries gated on the malicious value) |
| `ioc_file_paths.txt` | 44 | File path | Staging dirs, webshells, driver drops |
| `ioc_scheduled_tasks.txt` | 19 | Task name/path | Fake updates, APT persistence, ransomware pre-staging |
| `ioc_domains.txt` | 21 | Domain fragment | C2 infra, tunneling (bare TLDs and legit DoH endpoints removed) |
| `ioc_hashes.txt` | 12 | `SHA256\|Family\|Source` | BYOVD drivers, CS loaders, ransomware |
| `ioc_lolbins.txt` | 52 | Command fragment | certutil, mshta, regsvr32, encoded PS (overbroad PS aliases removed) |
| `ttp_manifest.txt` | 48 | `TechID\|Tactic\|Name\|Actors\|Detection` | MITRE ATT&CK v14+ mapping |

Counts are for the shipped baseline (`-updateTTP` grows the runtime copies). Re-derive anytime: `grep -cv "^#" ThreatLists/<file>` (or PowerShell `(Get-Content <file> | Where-Object {$_ -notmatch '^\s*(#|$)'}).Count`).

## Threat Coverage

**Nation-State APT:** Volt Typhoon, Salt Typhoon, Midnight Blizzard, Forest Blizzard, Scattered Spider, Lazarus Group, Flax Typhoon, Linen Typhoon, Violet Typhoon, Peach Sandstorm, Mango Sandstorm, APT29

**Ransomware:** LockBit 3.0, BlackCat/ALPHV, Akira, Play, Royal, Black Basta, Rhysida, Medusa

**Credential Theft:** BYOVD drivers, Mimikatz variants, Kerberoasting, NTLM relay, LSASS dumping, Pass-the-Hash, DPAPI abuse

**C2 Frameworks:** Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic, Nighthawk, PoshC2, Merlin

**LOLBins:** certutil, mshta, regsvr32, rundll32, msiexec, bitsadmin, cmstp, installutil, wmic, forfiles, cscript

Full tactic-by-tactic and threat-class coverage matrices — including explicit non-goals, inherent limitations, and known gaps — are in [THREAT_MODEL.md](THREAT_MODEL.md).

## Exit Codes

| Code | Meaning | Script |
|:----:|---------|--------|
| 0 | Success - all checks passed | Both |
| 1 | Fatal error | Both |
| 2 | Warning - issues found (review report) | Both |
| 3 | Unsupported OS (use `-dev` to override) | Both |
| 4 | Reboot pending | Both |
| 5 | Running from TEMP directory (move script) | Both |
| 6 | Partial audit - non-admin, checks deferred | noAdmin only |
| 7 | Pre-flight VT integrity check FAILED (script-critical binary flagged) | Both |
| 8 | Audit complete - CRITICAL findings present (2 = warnings only) | Both |

Code 8 fires when the live-summary verdict is ACTION REQUIRED (at least one CRITICAL check). It outranks 2, 4, and 6 — critical findings are the most actionable signal — but never the fatal/abort codes 1, 3, 5, 7. Automation can treat 0 as clean, 2/6 as review, 8 as incident-response trigger.

Checks that cannot run (missing IOC list, failed process/pipe/service/DNS enumeration) now report `[SKIPPED]` in the report instead of looking clean, and the TOP FINDINGS block carries a COVERAGE NOTE with the skipped count.

## Output

**Admin mode:**
```
C:\SecurityAudit\
  SecurityReport_YYYYMMDD_HHMMSS.txt    Plain text report
  SecurityReport_YYYYMMDD_HHMMSS.html   HTML report (dark theme, navigable)
  ChangeLog_YYYYMMDD_HHMMSS.txt         Changes made by the script
  Undo_YYYYMMDD_HHMMSS.bat              Reversal script
  SmartData\                             SMART disk health exports
  EventExports\                          Windows event log exports
  ThreatLists\                           IOC file copies
```

The HTML report features a navigation sidebar, color-coded findings (green/yellow/red), collapsible detail sections, and a dashboard with CRITICAL/WARNING/PASSED/INFO counts.

**Non-admin mode:** Same structure under `%USERPROFILE%\SecurityAudit\` — except `AuditConsole_<TS>.log`, which is always written to `C:\SecurityAudit\` (the console-capture wrapper runs before the output directory is selected; standard users can create that directory on a default Windows ACL)

## Requirements

- Windows 10 or Windows 11 (client editions)
- PowerShell 5.1+ (included with Windows)
- cmd.exe or Windows Terminal with ANSI color support
- Administrator privileges for full audit (optional with `-noAdmin`)
- [smartmontools](https://www.smartmontools.org/wiki/Download) (optional, for detailed SMART data)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (optional, for `-updateTTP`)
- [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (optional, for `-vt`)

## CTI Skill Integration

The `-updateTTP` switch invokes the [SENTINEL-X CTI skill](https://github.com/kj299/threat-intel) via Claude Code CLI to pull current threat intelligence and auto-generate detection blocks.

```
doze_sec.bat -updateTTP
```

Requires:
1. Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`) and authenticated via `claude /login` — no extra session/file tokens needed
2. The [threat-intel](https://github.com/kj299/threat-intel) repo cloned somewhere the script can find the skill file: `standalone\cyber-threat-intel-prompt.md` (threat-intel 1.2.0+, preferred — self-contained with the full SKILL workflow and the 1.5.0 starter-first SIEM rules) or the legacy `cyber_threat_skill.yaml` (pre-1.2.0). Do **not** point the script at `spec.yaml` alone — it omits the workflow and SIEM rules.

The skill file + existing IOC list are piped to `claude -p` via stdin (the documented headless context path); no `--file` flag is used.

**Skill 1.5.0+ compatibility:** the skill's `delimited_batch_export` rows may carry two extra trailing fields (`Source`, `Confidence`) — the sanitizer accepts 8-field rows and trims them to the 6 fields the pipeline uses. Skill 1.5.0 also mandates concrete SIEM starter queries (at least one Splunk SPL and one Sentinel KQL, built on normalized schemas) in every response; the prompt channels them below a `==== SIEM QUERIES ====` marker and doze_sec saves that section verbatim to `<output dir>\ThreatLists\siem_queries_<yyyyMMdd>.txt` as an analyst artifact. The saved queries are never parsed or executed by the audit — SPL/KQL pipes and `<PLACEHOLDERS>` would be rejected by the row sanitizer in any case, so they cannot reach the IOC files or generated detection blocks.

### Skill path resolution

When `-updateTTP` runs, the script resolves the CTI skill file in this order (highest precedence first):

1. `-ctiSkill <path>` switch (per-run override, doesn't persist)
2. `DOZESEC_CTI_SKILL` env var (persists across runs via `setx`)
3. Auto-discovery across these layouts, relative to `doze_sec\` (first hit wins; the 1.2.0+ standalone prompt is preferred over the legacy yaml):
   - `..\threat-intel\standalone\cyber-threat-intel-prompt.md` (sibling)
   - `..\prompts\threat-intel\standalone\cyber-threat-intel-prompt.md`
   - `..\skills\threat-intel\standalone\cyber-threat-intel-prompt.md`
   - `.\threat-intel\standalone\cyber-threat-intel-prompt.md` (vendored)
   - the same four roots with the legacy `cyber_threat_skill.yaml` (pre-1.2.0 clones)
4. Interactive prompt — if all of the above miss, the script asks for a path on stdin; press ENTER to skip the update.

**Per-run override (won't touch anything else):**

```powershell
.\doze_sec.bat -updateTTP -ctiSkill 'C:\path\to\threat-intel\standalone\cyber-threat-intel-prompt.md'
```

**Persist for future shells:**

```powershell
setx DOZESEC_CTI_SKILL 'C:\path\to\threat-intel\standalone\cyber-threat-intel-prompt.md'
```

On success the script echoes `[OK] CTI skill: <resolved-path> (source: <where it came from>)` so you can see which knob fired. On failure it names the file, lists every path it tried, and tells you which switch/env var to use to fix it.

## Offline TTP Import (`-importTTP`)

If you can't run Claude Code (air-gapped network, policy restriction, etc.), maintain your own pipe-delimited TTP feed and import it directly:

```
doze_sec.bat -importTTP C:\path\to\my_ttps.txt
```

**File format** -- one row per line, no header, fields separated by `|`:

```
MITRE_ID|Name|Detection_Method|Detection_Value|Severity|Actor
T1059.001|PowerShell Encoded Cmd|process name|powershell.exe|WARNING|APT29
T1543.003|Sliver Pipe Persistence|named pipe|sliverpb_|CRITICAL|Sliver
T1547.001|HKCU Run Persistence|registry key|HKCU\Software\Microsoft\Windows\CurrentVersion\Run|INFO|Generic
```

**`Detection_Method` must be one of**: `registry key`, `event id`, `process name`, `file path`, `named pipe`, `wmi query`. Other values cause the row to be dropped during sanitization.

**`Detection_Value` is sanitized**: rows containing shell metacharacters (`"` `'` `` ` `` `$` `;` `|` `&` `<` `>` `(` `)` `{` `}` `^`), longer than 260 chars, or non-ASCII-printable are dropped before merge. Same sanitizer as `-updateTTP` -- both LLM-generated and user-supplied input is treated as untrusted.

**Where TTP rows go after import**: process names append to `ThreatLists/ioc_processes.txt`, named pipes to `ioc_named_pipes.txt`, and detection commands are emitted to `%OUTDIR%\ThreatLists\ttp_generated_checks.bat` (sourced by Section 18 on subsequent runs).

Source the file from any CTI feed: MISP exports, AlienVault OTX pulses, internal SOC enrichment, vendor feeds, etc. The sanitizer treats all input the same.

**Sample feed**: [`samples/sample_ttps.txt`](samples/sample_ttps.txt) has 15 example rows covering all six `Detection_Method` types. Use it as a smoke-test for the import pipeline:

```
doze_sec.bat -importTTP samples\sample_ttps.txt
```

Replace with your real feed before relying on the merged IOCs.

## VirusTotal Hash Reputation (`-vt`)

Section 18j queries the [VirusTotal v3 API](https://docs.virustotal.com/reference/file-info) for SHA256 hashes of priority files on disk and reports per-file engine consensus. Only the hash is sent — file contents are never uploaded.

**Setup:**

1. Get a free API key at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).
2. Save it to `%USERPROFILE%\.vt_token` (single line, no quotes, no `Bearer` prefix):

   ```powershell
   Set-Content -Path "$env:USERPROFILE\.vt_token" -Value 'your_vt_api_key_here'
   icacls "$env:USERPROFILE\.vt_token" /inheritance:r /grant:r "$($env:USERNAME):F"
   ```

3. Run the audit with `-vt`:

   ```
   doze_sec.bat -vt
   ```

**What gets checked:**

`-vt` enables three sub-checks (each gated by the same `~/.vt_token` and rate-limit):

1. **Section 18j — file hash reputation:** SHA256 of recent (`<30d`) `.sys` drivers in `C:\Windows\System32\drivers\` (admin only) plus recent (`<7d`) `.exe` / `.dll` / `.ps1` / `.vbs` in `%TEMP%`, `~\Downloads`, `%LOCALAPPDATA%\Temp`, `C:\Windows\Temp`. Capped at 20 files. Per-file: `[CRITICAL] N/M engines flagged`, `[OK] 0/M clean`, `[INFO] not in VT corpus`.
2. **Section 18l — IP reputation:** All Established TCP connections via `Get-NetTCPConnection` (falls back to `netstat -ano`), filtered to public-routable IPs only (RFC1918 / link-local / loopback / multicast / CGNAT skipped). Capped at 10 unique remote IPs. Per-IP: `[CRITICAL] N malicious / S suspicious / M engines (AS owner, country)`, `[WARNING]` if suspicious-only, `[OK] 0/M clean`.
3. **Pre-flight binary integrity** (see "Automatic pre-flight integrity check" below): runs even without `-vt` whenever `~/.vt_token` exists and network is up.

Free-tier rate limit is 4 lookups/min — the script sleeps 16 s between calls. A full `-vt` run (20 hashes + 10 IPs + 4 self-check binaries = 34 lookups) takes ~9 minutes and uses 34 of your 500 daily free-tier lookups. Section 18k local hash match (always-on, offline) complements these without consuming any quota.

**Threat model note:** the API key is read at script start and held in process memory only. As with `DOZESEC_TOKEN`, prefer a token scoped narrowly (free-tier VT keys cannot be scoped further; create a dedicated VT account for incident-response use and rotate after).

### Automatic pre-flight integrity check

Whenever `~/.vt_token` exists **and** network is available, every audit run also performs a pre-flight VT lookup on the script-critical binaries (`%PWSH%`, `wmic.exe`, `wevtutil.exe`, `reg.exe`) before any audit data is collected. This adds ~50 seconds to startup and aborts the audit with `EXIT_CODE=7` if any of those binaries is flagged malicious by VT — a tampered system binary would invalidate every downstream finding (e.g. a backdoored `wmic.exe` could hide the attacker's process from the LOLBin scan).

To skip the pre-flight check (e.g. for fast iteration during development), pass `-noVtSelf`. The script will still run, just without the integrity gate.

This check runs on the SAME 4-lookups-per-minute free-tier rate limit as `-vt`, so combining `-vt` with the pre-flight check uses ~24 of the 500 daily lookups per audit run.

## Self-Update and IOC Download from a Private Repo

If the `doze_sec` repo is private, `raw.githubusercontent.com` returns 404 for anonymous requests and the INIT 10/14 update check reports:

```
[INFO] Update check: 404 (repo is private and no GitHub PAT found).
```

To enable self-update and the GitHub IOC-list download against a private repo, provide a GitHub Personal Access Token via one of:

### Option 1: Environment variable (recommended for one-off runs)

```powershell
$env:DOZESEC_TOKEN = 'github_pat_...'
.\doze_sec.bat
```

### Option 2: Token file (persistent, user-scoped)

```powershell
Set-Content -Path "$env:USERPROFILE\.dozesec_token" -Value 'github_pat_...'
icacls "$env:USERPROFILE\.dozesec_token" /inheritance:r /grant:r "$($env:USERNAME):F"
```

Env var wins over token file when both are set.

### Token requirements

Create a **fine-grained** PAT at [github.com/settings/personal-access-tokens](https://github.com/settings/personal-access-tokens) with:

| Setting | Value |
|---------|-------|
| Resource owner | Owner of the `doze_sec` repo |
| Repository access | Only select repositories → `doze_sec` |
| Repository permissions | **Contents: Read-only** (that is sufficient) |
| Expiration | Whatever fits your rotation cadence (30/60/90 days) |

**Do not use a classic token** with broad scopes. Fine-grained, single-repo, read-only is the minimum and the safest.

### Troubleshooting by error code

| HTTP | Meaning | Fix |
|------|---------|-----|
| 404 (no token) | Repo is private | Create a PAT and set `DOZESEC_TOKEN` |
| 404 (with token) | Token scope is wrong | PAT is not scoped to this repo; re-create it |
| 401 | Token invalid or expired | Rotate the PAT |
| 403 | Rate-limited or scope-restricted | Wait or narrow the request |

### Threat model note

Running a PAT-bearing script on a compromised endpoint exposes the token. Prefer:
- A token scoped to a *read-only* repo (e.g., a dedicated `doze_sec-mirror` repo that the org owns)
- Short expiration
- Revoke immediately after incident-response use

If those trade-offs are not acceptable, make the repo public or skip the update check entirely (the script works fine without it).

## Contributing

### Batch comment rule (enforced by lint)

Never use `::` comments inside parenthesized blocks (`if (...)`, `for ... do (...)`, `else (...)`) — cmd.exe parses `::` as a label there, not a comment, and a `)` in the comment text closes the block prematurely (issues #35, #36, #39, #108). Use `rem` inside blocks; `::` is fine at top level.

Run the lint before committing batch changes (built-in PowerShell, works on every Windows 10/11 build — no extra dependencies):

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1
```

CI runs the same check on every push and pull request. See `CLAUDE.md` for the full list of cmd.exe parsing traps this repo has hit.

## Roadmap

All 12 items surfaced by the multi-agent audit have been resolved (see closed [`audit-deferred`](https://github.com/kj299/doze_sec/issues?q=is%3Aclosed+label%3Aaudit-deferred) issues). New work is tracked via the regular [Issues](https://github.com/kj299/doze_sec/issues) tab.

## License

For personal and organizational security use. Not for redistribution without permission.
