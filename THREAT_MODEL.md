# Threat Model and Coverage

What this tool protects against, how, and — just as important — what it does
not. Read this before relying on doze_sec as part of a security posture.

## Protection model

doze_sec is a **point-in-time forensic audit**, not real-time protection. Its
goal is to make a compromise or a weak configuration *visible* and give the
user a safe, reviewable path to fix it. The protection chain it supports:

1. **Prevention** is delegated to the platform: Defender, firewall, UAC,
   Secure Boot, BitLocker, SmartScreen. doze_sec *audits that these are on
   and untampered* (Sections 8, 9, 13) rather than duplicating them.
2. **Detection** is doze_sec's core job: 14 pre-flight checks + 18 audit
   sections + a CTI-driven IOC sweep (Section 18) covering 77 MITRE ATT&CK
   techniques and 320 indicators across 10 IOC categories.
3. **Response** is user-gated by design: a severity-sorted report (text +
   HTML), a suggested remediation script behind an explicit
   I-read-and-understand gate, and an undo script for the few changes the
   audit itself makes (F8 boot menu; everything else is read-only).

## Coverage by MITRE ATT&CK tactic

Every endpoint-relevant tactic has at least partial coverage. "Where" lists
the primary audit sections.

| Tactic | Coverage | Where |
|---|---|---|
| Initial Access | Partial — artifacts, not prevention | S1 (patch level), S14 (HTML smuggling, Downloads), S18 AiTM token cache |
| Execution | Yes | S4 (processes, LOLBins), S11 (PowerShell), S16 (4688), S18g |
| Persistence | Strong | S5 (Run/Winlogon/IFEO/AppInit/Active Setup), S6 (tasks), S7 (services), S17 (WMI subscriptions), S18 (COM hijack, registry IOCs) |
| Privilege Escalation | Yes | S13 (UAC, accessibility binaries T1546.008), S16 (4672/4732) |
| Defense Evasion | Strong | S9 (Defender tamper/exclusions), S18 (AMSI bypass, BYOVD drivers), S16 (1102 log clear) |
| Credential Access | Strong | S12 (LSASS PPL, WDigest, NTLM, Credential Guard), S16 (4769 Kerberoast, 4776), S18 (browser/cloud cred stores) |
| Discovery | Yes | S17 (4688 discovery commands: nltest, dsquery, ntdsutil) |
| Lateral Movement | Yes | S10 (SMBv1, RDP/NLA, WinRM, sshd), S17/S18 (PsExec pipes, portproxy) |
| Collection | Partial | S14 (staging dirs, ADS), manifest T1560 |
| Command & Control | Strong | S3 (connections, DNS cache, hosts), S18 (C2 pipes/domains, VT IP reputation, tunneling tools) |
| Exfiltration | Partial | S3/S18l (connections + IP reputation); no DLP / content inspection |
| Impact | Strong (ransomware) | S18 (precursor commands T1490, extension survey T1486, encryptor hashes) |

Reconnaissance and Resource Development are attacker-side tactics with no
endpoint footprint to audit; they are out of scope by nature.

## Coverage by threat class

| Threat class | Coverage | Notes |
|---|---|---|
| Ransomware | Strong | Precursors, extensions, hashes, services, tasks for LockBit, BlackCat/ALPHV, Akira, RansomHub, Qilin, Play, Royal, Black Basta, Rhysida, Medusa, more |
| Nation-state APT | Strong | 12 named groups (Volt/Salt/Flax/Linen/Violet Typhoon, Forest/Midnight Blizzard, Sandstorms, Lazarus/DPRK Sleets, APT29, Scattered Spider) |
| C2 frameworks | Strong | Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic, Nighthawk, PoshC2, Merlin — pipes, domains, hashes, IP reputation |
| Credential theft | Strong | Mimikatz/LSASS/PtH/Kerberoast/NTLM-relay detection plus hardening-state audit |
| Infostealers / loaders | Good | Process IOCs (Lumma, StealC, Rhadamanthys, DarkGate, PikaBOT, Latrodectus, HijackLoader), browser cred-store access |
| LOLBin abuse | Strong | 52 command-line patterns + Event 4688 download-cradle sweep |
| BYOVD / EDR killers | Strong | Known vulnerable drivers by name and SHA256 |
| Supply chain | Partial | Installed-software inventory, driver/service Authenticode gating, rogue root certs, VT hash reputation — cannot vet vendor build pipelines |
| Phishing / social engineering | Partial | Detects artifacts (HTML smuggling, AiTM token-cache touches, staged payloads); cannot stop a user clicking |
| Cloud / identity token theft | Partial | Azure/AWS/GCP/kubectl credential-file presence and recency; tenant-side (Entra/M365) auditing is out of scope |
| Network MitM / rogue infra | Limited | hosts file, ARP table, portproxy, DNS cache; no traffic capture, no router/SOHO visibility |
| Rootkits / firmware | Limited | Secure Boot state, driver signing, known BYOVD names/hashes; no UEFI/firmware scanning — a kernel rootkit can defeat user-mode auditing |
| Zero-days / novel malware | Inherent limit | Detection is IOC- and configuration-based plus some behavioral signals (events, staging paths); unknown tooling with no known indicators can evade it |
| Insider threat / DLP | Out of scope | No content inspection or user-behavior analytics |
| DoS / availability attacks | Out of scope | Nothing to audit at endpoint level |
| Mobile, IoT, macOS, Linux, Server | Out of scope | Windows 10/11 client editions only (Server is explicitly blocked, INIT 4) |

## Non-goals

doze_sec is **not** an antivirus, EDR, or firewall and does not block
anything in real time. It does not auto-remediate (remediation requires the
user to review and flip an explicit gate). It audits one endpoint at a time;
it is not fleet management. If you need real-time protection, keep Defender
(or another AV), the firewall, UAC, and SmartScreen enabled — Sections 8, 9,
and 13 verify exactly that.

## Inherent limitations

- **Point-in-time**: a clean audit means clean *now*; re-run on a schedule
  and after any suspicious event.
- **IOC freshness**: indicator lists age. INIT 10/14 warns when upstream
  lists are stale (>60 days); refresh with `-updateTTP` (or `-importTTP`
  offline). A stale list silently narrows detection.
- **Admin vs non-admin**: `doze_sec_noAdmin.bat` defers Security-event-log
  and several deep checks (`[DEFERRED]`, exit code 6). Full coverage
  requires the admin variant.
- **Graceful degradation can be silent**: several PowerShell probes use
  `-ErrorAction SilentlyContinue`; on a locked-down host a sub-check can
  come back empty rather than failed.
- **DNS check is cache-only**: a C2 domain never resolved on the host (or
  flushed) leaves no cache entry.
- **VirusTotal checks are opt-in** (`-vt` + API key) and rate-limited on
  the free tier.
- **Trust anchor**: the audit runs on the host it inspects. INIT 9/14's
  VirusTotal self-integrity pre-flight hash-checks the binaries the audit
  depends on, but a sufficiently privileged implant can lie to any
  user-mode tool.

## Getting full protection value

1. Run `doze_sec.bat` as Administrator (not the noAdmin variant) on a
   regular cadence and after anything suspicious.
2. Use `-vt` with a VirusTotal API key for hash and IP reputation.
3. Refresh threat intel with `-updateTTP` (or `-importTTP`) when INIT 10/14
   reports stale lists.
4. Read the TOP FINDINGS block first; treat `[CRITICAL]` entries as
   incident-response triggers, not chores.
5. Keep the platform protections the audit verifies (Defender, firewall,
   UAC, Secure Boot, BitLocker) enabled — they are the prevention layer.

## Known detection gaps (roadmap candidates)

Found during the v7.1 coverage review; tracked for future work:

- Attack Surface Reduction (ASR) rule state and Office macro policy
  (`VBAWarnings`, Mark-of-the-Web handling) are not explicitly audited.
- Exit code does not distinguish `[CRITICAL]` from `[WARNING]` (both
  roll up to 2); calling automation cannot triage on exit code alone.
- Browser extensions are not inventoried (only credential-store access
  times).
- No active resolution probe for C2 domains (cache-only by design — an
  active probe would itself generate suspicious traffic; needs care).
- Sub-check failures suppressed by `-ErrorAction SilentlyContinue` could
  be surfaced as `[SKIPPED]` instead of appearing clean.
