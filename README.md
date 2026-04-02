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
| 6 | Scheduled tasks | No | Malicious tasks, suspicious paths |
| 7 | Windows services | Partial | Unsigned services, unusual accounts |
| 8 | Firewall configuration | Yes | Disabled profiles, risky rules |
| 9 | Defender and AV status | Yes | Disabled Defender, exclusions, tamper |
| 10 | SMB, RDP, remote access | Partial | SMBv1, NLA bypass, open RDP |
| 11 | PowerShell security | Partial | Unrestricted execution, logging gaps |
| 12 | Credential and LSASS protection | No | PPL disabled, WDigest, Credential Guard |
| 13 | System hardening | Partial | UAC, BitLocker, SecureBoot, test signing |
| 14 | Suspicious files | No | ADS streams, double extensions, staging dirs |
| 15 | Installed software and drivers | No | Unsigned drivers, vulnerable software |
| 16 | Event log anomalies | Partial | Log clearing (1102), brute force (4625), lateral (4624) |
| 17 | Nation-state threat indicators | No | MDDR 2023-2025 TTPs, portproxy, WMI persistence |
| 18 | CTI-driven IOC sweep | No | SENTINEL-X file-based + inline CTI checks |

## Section 18: CTI IOC Sweep

Reads structured IOC files from `ThreatLists/` and matches against the live system, then runs inline CTI checks for advanced threats.

**File-based checks (18a-18i):**

| Sub | Check | Method |
|-----|-------|--------|
| 18a | Process name IOC match | `wmic process` vs `ioc_processes.txt` |
| 18b | Named pipe IOC match | PowerShell pipe enum vs `ioc_named_pipes.txt` |
| 18c | Service IOC match | PowerShell service enum vs `ioc_services.txt` |
| 18d | Malware staging paths | `Test-Path` vs `ioc_file_paths.txt` |
| 18e | Scheduled task IOC match | `schtasks` vs `ioc_scheduled_tasks.txt` |
| 18f | DNS cache C2 domains | `ipconfig /displaydns` vs `ioc_domains.txt` |
| 18g | LOLBin command patterns | `wmic process` vs `ioc_lolbins.txt` |
| 18h | Registry IOC check | `reg query` vs `ioc_registry.txt` |
| 18i | TTP coverage summary | `ttp_manifest.txt` dump |

**Inline CTI checks:**
- Sliver / Havoc / Brute Ratel named pipes
- DLL search order hijacking (T1574.001)
- Browser credential store access via DPAPI (T1555.003)
- AiTM phishing token cache artifacts (T1557.001)
- Ransomware file extension survey (T1486)
- BYOVD vulnerable driver detection (T1562.001)
- COM object hijacking (T1546.015)
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
| `ioc_processes.txt` | 77 | Process name | Ransomware, C2, cred tools, RMM, APT |
| `ioc_named_pipes.txt` | 46 | Pipe name | Cobalt Strike, Sliver, Havoc, Mythic, PsExec |
| `ioc_services.txt` | 45 | Service name | RMM, BYOVD, fake updates, implants |
| `ioc_registry.txt` | 49 | `HIVE\Path\|Value` | Persistence, COM hijack, defense evasion |
| `ioc_file_paths.txt` | 57 | File path | Staging dirs, webshells, driver drops |
| `ioc_scheduled_tasks.txt` | 38 | Task name/path | Fake updates, APT persistence, C2 callbacks |
| `ioc_domains.txt` | 55 | Domain fragment | C2 infra, tunneling, DGA TLDs |
| `ioc_hashes.txt` | 10 | `SHA256\|Family\|Source` | BYOVD drivers, CS loaders, ransomware |
| `ioc_lolbins.txt` | 97 | Command fragment | certutil, mshta, regsvr32, PowerShell obfuscation |
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

## CTI Skill Integration

The `-updateTTP` switch invokes the [SENTINEL-X CTI skill](https://github.com/kj299/threat-intel) via Claude Code CLI to pull current threat intelligence and auto-generate detection blocks.

```
doze_sec.bat -updateTTP
```

Requires:
1. Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`)
2. The [threat-intel](https://github.com/kj299/threat-intel) repo cloned as a sibling directory

## License

For personal and organizational security use. Not for redistribution without permission.
