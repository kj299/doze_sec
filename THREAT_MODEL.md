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
   sections + a CTI-driven IOC sweep (Section 18) covering 48 MITRE ATT&CK
   techniques and 283 indicators across 10 IOC categories.
3. **Response** is user-gated by design: a severity-sorted report (text +
   HTML), a suggested remediation script behind an explicit
   I-read-and-understand gate, and an undo script for the few changes the
   audit itself makes (F8 boot menu; everything else is read-only).

## Coverage by MITRE ATT&CK tactic

Every endpoint-relevant tactic has at least partial coverage. "Where" lists
the primary audit sections.

| Tactic | Coverage | Where |
|---|---|---|
| Initial Access | Partial — artifacts, not prevention | S1 (patch level), S13 (Office macro policy, MOTW, SmartScreen state), S14 (HTML smuggling, Downloads), S18 AiTM token cache |
| Execution | Yes | S4 (processes, LOLBins), S11 (PowerShell), S16 (4688), S18g |
| Persistence | Strong | S5 (Run/Winlogon/IFEO/AppInit/Active Setup), S6 (tasks), S7 (services), S17 (WMI subscriptions), S18 (COM hijack, registry IOCs) |
| Privilege Escalation | Yes | S13 (UAC, accessibility binaries T1546.008), S16 (4672/4732) |
| Defense Evasion | Strong | S9 (Defender tamper/exclusions, ASR rule state), S18 (AMSI bypass, BYOVD drivers), S16 (1102 log clear) |
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
| Infostealers / loaders | Good | Process IOCs (Lumma, StealC, Rhadamanthys, DarkGate, PikaBOT, Latrodectus, HijackLoader), browser cred-store access, malicious browser-extension inventory (T1176) |
| LOLBin abuse | Strong | 52 command-line patterns + Event 4688 download-cradle sweep |
| BYOVD / EDR killers | Strong | Known vulnerable drivers by name and SHA256 |
| Supply chain | Partial | Installed-software inventory, driver/service Authenticode gating, rogue root certs, VT hash reputation — cannot vet vendor build pipelines |
| Phishing / social engineering | Partial | Detects artifacts (HTML smuggling, AiTM token-cache touches, staged payloads) and audits the macro/MOTW/SmartScreen/ASR settings that blunt malicious attachments; cannot stop a user clicking |
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
- **Graceful degradation can be silent outside Section 18**: Section 18's
  file-based IOC sub-checks now report `[SKIPPED]` (with a COVERAGE NOTE
  count in TOP FINDINGS) when an IOC list is missing or an enumeration
  fails, but probes in other sections still use
  `-ErrorAction SilentlyContinue` and can come back empty rather than
  failed on a locked-down host.
- **DNS check is cache-only**: a C2 domain never resolved on the host (or
  flushed) leaves no cache entry.
- **VirusTotal checks are opt-in** (`-vt` + API key) and rate-limited on
  the free tier.
- **User-profile path heuristic is signature-gated to cut false positives**:
  scheduled tasks and processes whose binary lives under `%AppData%` are
  flagged `[CRITICAL]` only when that binary is *not* validly
  Authenticode-signed; validly-signed per-user updaters (Brave, Chrome,
  Zoom, Teams) are reported `[INFO]` instead. `\Temp\`, `\Downloads\`,
  `\Users\Public\`, and `\ProgramData\update` stay `[CRITICAL]` regardless
  of signature. Trade-off: malware that runs validly-signed (stolen or
  abused cert) from `%AppData%` is downgraded to `[INFO]` — Section 18's
  IOC hash/name sweeps and the cert-validation checks remain the backstop
  for that case.
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

- ~~Attack Surface Reduction (ASR) rule state and Office macro policy
  (`VBAWarnings`, Mark-of-the-Web handling) are not explicitly audited.~~
  **Closed:** Section 9 now audits all 19 documented ASR rules by name and
  mode and warns when key rules are not in Block mode; Section 13 audits
  per-app `VBAWarnings` and `blockcontentexecutionfrominternet`,
  `SaveZoneInformation` (MOTW preservation), and SmartScreen state.
- ~~Exit code does not distinguish `[CRITICAL]` from `[WARNING]` (both
  roll up to 2); calling automation cannot triage on exit code alone.~~
  **Closed:** exit code 8 = audit complete with CRITICAL findings
  (the dashboard's ACTION REQUIRED verdict); 2 remains warnings-only.
- ~~Browser extensions are not inventoried (only credential-store access
  times).~~ **Closed:** Section 15 runs `tools/browser_extensions.ps1`
  (MITRE T1176) — inventories Chrome/Edge/Brave/Vivaldi/Firefox extensions
  for the current user and flags sideloaded/developer-mode/non-store
  add-ons, malware-favored permissions (nativeMessaging, debugger, proxy,
  *Capture), broad host access combined with interception permissions, and
  policy force-installs; a locked/corrupt profile reports `[SKIPPED]`.
- **Active DNS probing — split into a safe half (shipped) and a risky half
  (still deferred by design).**
  - *Cache-only baseline:* Section 18f checks for known-bad C2 domains by
    reading the machine's local DNS resolver cache (`ipconfig /displaydns`).
    It only sees domains the host has *already* looked up recently; cache
    entries expire (TTL) and a reboot/flush clears them — so a C2 domain
    never resolved, or aged out, leaves no cache evidence.
  - *Safe active probe — SHIPPED behind `-dnsprobe` (Section 3,
    `tools/dns_probe.ps1`):* the audit actively resolves a fixed list of
    *legitimate* Windows/Defender/connectivity domains and flags any that
    fail to resolve or resolve to a non-public IP — the signature of malware
    blackholing update/AV traffic via a DNS or HOSTS hijack (T1562.001). It
    queries only known-good infrastructure, so it sends **no** outbound
    lookups to attacker domains. Off by default; opt-in like `-vt`.
  - *Risky active probe — still DEFERRED by design:* resolving the
    `ioc_domains.txt` C2 entries themselves would generate outbound DNS
    queries *from the audited host to attacker-controlled infrastructure*.
    That can tip off an operator that the host is being investigated and
    trips the organization's own network IDS/DNS-monitoring (the audit would
    manufacture the very "host contacted C2" alert it is supposed to find).
    Not implemented; if ever built it must be its own explicit opt-in,
    ideally resolved only against a trusted internal resolver or restricted
    to sinkhole-safe lookups. Until then, C2-domain detection stays
    cache-only (18f) by design.
- ~~Sub-check failures suppressed by `-ErrorAction SilentlyContinue` could
  be surfaced as `[SKIPPED]` instead of appearing clean.~~
  **Closed for Section 18 and the highest-severity Section 1-17 sites:**
  Section 18's missing-IOC-list and failed process/pipe/service/DNS
  enumerations emit `[SKIPPED]` with a TOP FINDINGS COVERAGE NOTE;
  Section 4 (process/LOLBin/RMM) now enumerates via CIM with `[SKIPPED]`
  on failure (no longer wmic-dependent — removed in Win11 24H2+, the
  same false-clean class); Section 9 Defender exclusion checks report
  `[SKIPPED]` when `Get-MpPreference` fails (Defender off / third-party
  AV) instead of "no exclusions". A follow-up extended `[SKIPPED]` to the
  genuine false-cleans in the rest of the audit body: Section 5 IFEO
  debugger-hijack scan, Section 7 unquoted-service-path scan, Section 14
  Temp ADS scan, the Cobalt-Strike and next-gen-C2 named-pipe checks
  (catch now emits `[SKIPPED]` so it counts in the COVERAGE NOTE), and
  the three Section 17 WMI permanent-subscription checks (which also
  fail closed if `Get-WMIObject` is unavailable, e.g. under PowerShell
  7). Checks intentionally left as plain `[OK]` because an empty result
  is genuinely correct, not a masked failure: Section 3 proxy (Internet
  Settings keys are always present), the Section 5 HKEY_USERS Run-key
  walk (informational, per-subkey `Test-Path` guarded), and the Section
  17 RMM running/installed checks (`Get-Process`/Uninstall-key empties
  mean "not present"). Probes elsewhere may still degrade silently, but
  the high-value verdict checks across Sections 4-18 now fail visibly.
- ~~Section 5 raw-dumped the Run/RunOnce keys and printed a bare
  `[IFEO HIT]` with no verdict, and Section 2 raw-dumped `net user guest`
  with no verdict — an encoded-PowerShell autorun, an IFEO Debugger on a
  non-accessibility binary, and an enabled Guest account all scrolled past
  as clean (issue #138, confirmed by the detection harness).~~
  **Closed:** Section 5 runs `tools/persistence_eval.ps1`, which flags
  autorun commands with encoded-PowerShell / hidden-window / LOLBin-download
  content (or execution from `\Temp\`, `\Downloads\`, `\Public\`) and
  escalates *any* IFEO Debugger value (not only the accessibility binaries
  Section 13 already escalates to CRITICAL). Section 2 evaluates the Guest
  account by well-known SID (`-501`, locale-independent) and warns when it
  is enabled. All three are `required` cases in the detection harness.
