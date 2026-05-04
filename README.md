# doze_sec

Windows 10/11 security forensic audit tool with SENTINEL-X CTI integration.

**Version 7.1** | 18-section audit | 48 MITRE ATT&CK techniques | 10 IOC categories

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
| `-vt` | Both | Section 18j: query VirusTotal for SHA256 of priority files. Requires `~/.vt_token` |
| `-noVtSelf` | Both | Skip the automatic pre-flight VT integrity check on script-critical binaries (default: runs whenever `~/.vt_token` exists and network is up) |
| `-help` | Both | Show usage guide with section descriptions |

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
| 7 | Windows services | Partial | Unsigned services, unusual accounts |
| 8 | Firewall configuration | Yes | Disabled profiles, risky rules |
| 9 | Defender and AV status | Yes | Disabled Defender, exclusions, tamper |
| 10 | SMB, RDP, remote access | Partial | SMBv1, NLA bypass, open RDP |
| 11 | PowerShell security | Partial | Unrestricted execution, logging gaps |
| 12 | Credential and LSASS protection | No | PPL disabled, WDigest, Credential Guard |
| 13 | System hardening | Partial | UAC, BitLocker, SecureBoot, test signing |
| 14 | Suspicious files | No | ADS streams, double extensions, recent EXE/DLL/PS/VBS in user `%TEMP%` and `C:\Windows\Temp` (admin) |
| 15 | Installed software and drivers | No | Unsigned drivers, vulnerable software |
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
| `ioc_registry.txt` | 26 | `HIVE\Path\|Value` | Persistence, COM hijack, defense evasion |
| `ioc_file_paths.txt` | 44 | File path | Staging dirs, webshells, driver drops |
| `ioc_scheduled_tasks.txt` | 19 | Task name/path | Fake updates, APT persistence, ransomware pre-staging |
| `ioc_domains.txt` | 21 | Domain fragment | C2 infra, tunneling (bare TLDs and legit DoH endpoints removed) |
| `ioc_hashes.txt` | 12 | `SHA256\|Family\|Source` | BYOVD drivers, CS loaders, ransomware |
| `ioc_lolbins.txt` | 52 | Command fragment | certutil, mshta, regsvr32, encoded PS (overbroad PS aliases removed) |
| `ttp_manifest.txt` | 48 | `TechID\|Tactic\|Name\|Actors\|Detection` | MITRE ATT&CK v14+ mapping |

## Threat Coverage

**Nation-State APT:** Volt Typhoon, Salt Typhoon, Midnight Blizzard, Forest Blizzard, Scattered Spider, Lazarus Group, Flax Typhoon, Linen Typhoon, Violet Typhoon, Peach Sandstorm, Mango Sandstorm, APT29

**Ransomware:** LockBit 3.0, BlackCat/ALPHV, Akira, Play, Royal, Black Basta, Rhysida, Medusa

**Credential Theft:** BYOVD drivers, Mimikatz variants, Kerberoasting, NTLM relay, LSASS dumping, Pass-the-Hash, DPAPI abuse

**C2 Frameworks:** Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic, Nighthawk, PoshC2, Merlin

**LOLBins:** certutil, mshta, regsvr32, rundll32, msiexec, bitsadmin, cmstp, installutil, wmic, forfiles, cscript

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

**Non-admin mode:** Same structure under `%USERPROFILE%\SecurityAudit\`

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
1. Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`)
2. The [threat-intel](https://github.com/kj299/threat-intel) repo cloned as a sibling directory

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

- Recent (`<30d`) `.sys` drivers in `C:\Windows\System32\drivers\` (admin only)
- Recent (`<7d`) `.exe` / `.dll` / `.ps1` / `.vbs` in `%TEMP%`, `~\Downloads`, `%LOCALAPPDATA%\Temp`, `C:\Windows\Temp`

The candidate set is capped at 20 files. Free-tier rate limit is 4 lookups/min, so the script sleeps 16 s between calls — full 20-file run takes ~5 minutes. Per-file results: `[CRITICAL] N/M engines flagged`, `[OK] 0/M clean`, `[INFO] not in VT corpus`, or `[ERROR]` for HTTP 401 (bad key) / 429 (rate limit).

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

## Roadmap

Open coverage gaps and cleanup items surfaced by the multi-agent audit are tracked under the [`audit-deferred`](https://github.com/kj299/doze_sec/issues?q=is%3Aopen+label%3Aaudit-deferred) label. Highlights:

| # | Item | Tier |
|--|------|------|
| [#9](https://github.com/kj299/doze_sec/issues/9) | Section 7 service-path allowlist bypass (Authenticode signature gating) | HIGH |
| [#11](https://github.com/kj299/doze_sec/issues/11) | `HKCU\Wow6432Node\Run` + other-user HKU persistence enumeration | MED |
| [#12](https://github.com/kj299/doze_sec/issues/12) | Event 4688 time-window guard (currently `-MaxEvents N` only) | MED |
| [#14](https://github.com/kj299/doze_sec/issues/14) | Local hash matching against `ioc_hashes.txt` (complements `-vt` network check) | MED |
| [#15](https://github.com/kj299/doze_sec/issues/15) | noAdmin self-update should refresh all 10 IOC files (currently only `ioc_hashes.txt`) | MED |
| [#17](https://github.com/kj299/doze_sec/issues/17) | noAdmin per-section verdicts: distinguish CLEAN vs PARTIAL when checks were DEFERRED | MED |

Plus 6 LOW-tier cleanup items ([full list](https://github.com/kj299/doze_sec/issues?q=is%3Aopen+label%3Aaudit-deferred)).

## License

For personal and organizational security use. Not for redistribution without permission.
