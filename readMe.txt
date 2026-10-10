================================================================================
  doze_sec - Windows Security Forensic Audit Tool
  Version 7.3 | SENTINEL-X CTI Integration | HTML Report Output
================================================================================

WHAT IT DOES
--------------------------------------------------------------------------------
doze_sec is a standalone Windows batch script that performs an 18-section
security forensic audit of a Windows 10/11 workstation. It checks for
nation-state TTPs, ransomware indicators, credential theft artifacts,
persistence mechanisms, and misconfigurations -- then produces a detailed
report with a color-coded live summary.

Two versions are included:

  doze_sec.bat          Full audit. Requires administrator privileges.
  doze_sec_noAdmin.bat  Adaptive audit. Runs with or without admin.
                        Checks that need admin are marked [DEFERRED].


QUICK START
--------------------------------------------------------------------------------
  IMPORTANT - run it from the extracted release folder. The script finds its
  helpers (tools\) and IOC data (ThreatLists\) by path relative to itself, so
  those folders must sit next to the .bat exactly as they ship in the archive.
  Extract the whole archive and run the .bat in place. Copying ONLY the .bat
  elsewhere - or into C:\Windows\System32 - breaks helper discovery and the
  audit aborts with exit code 1. No install or path setup is needed.

  Full audit (admin):
    Right-click doze_sec.bat > Run as administrator

  Non-admin audit:
    Open cmd.exe (normal user) and run:
    doze_sec_noAdmin.bat -noAdmin

  See all options:
    doze_sec_noAdmin.bat -help


COMMAND-LINE SWITCHES
--------------------------------------------------------------------------------
  -noAdmin      Run without admin. Defers checks that require elevation.
                (doze_sec_noAdmin.bat only)

  -dev          Bypass unsupported OS check. Use on Server editions,
                Windows 8.1, or unrecognised builds for testing.

  -resume       Skip pre-flight steps 8-14. Used automatically by the
                RunOnce key if a previous run was interrupted.

  -sdu          Skip threat intel list update from GitHub.

  -nosrp        Skip System Restore Point creation. Saves 30-60 seconds.

  -updateTTP    Refresh ThreatLists/ IOC files before the audit via the
                SENTINEL-X CTI skill. (doze_sec.bat only; requires the
                Claude Code CLI). With skill 1.5.0+, SIEM starter queries
                (SPL/KQL) from the skill are saved verbatim to
                ThreatLists\siem_queries_[date].txt for analysts -- they
                are never executed by the audit.

  -importTTP <file>  Merge TTP rows from a pipe-delimited file into
                ThreatLists/ -- offline alternative to -updateTTP, no
                Claude CLI needed. (doze_sec.bat only)

  -ctiSkill <file>  Per-run override for the CTI skill file used by
                -updateTTP. threat-intel 1.2.0+ uses
                standalone\cyber-threat-intel-prompt.md; older clones
                use the legacy cyber_threat_skill.yaml. (doze_sec.bat only)

  -vt           Query VirusTotal for SHA256 hashes of priority files
                (Section 18j) and remote IP reputation (Section 18l).
                Requires an API key in %USERPROFILE%\.vt_token.

  -dnsprobe     Active DNS integrity probe (Section 3). Actively resolves
                a fixed list of LEGITIMATE Windows/Defender/connectivity
                domains and flags any that fail to resolve or resolve to a
                non-public IP -- the signature of malware blackholing
                update/AV traffic via DNS/HOSTS hijack (T1562.001). Safe:
                never resolves attacker/C2 domains. Off by default.

  -noVtSelf     Skip the automatic pre-flight VT integrity check on
                script-critical binaries (default: runs whenever
                ~/.vt_token exists and the network is up).

  -noConsoleLog Skip console-output capture. By default stdout+stderr
                are tee'd to AuditConsole_[timestamp].log in the output
                folder (C:\SecurityAudit, or %USERPROFILE%\SecurityAudit
                with -noAdmin) so crashes leave a debuggable trace.

  -help         Show full usage guide with section descriptions.
  -h, /?, --help  (aliases)


EXIT CODES
--------------------------------------------------------------------------------
  0   Success - all checks passed, no issues found
  1   Fatal pre-flight error - audit did NOT run (no report produced). Causes:
      the tools\ helper folder is missing (only the .bat was copied, or the
      download is incomplete), Windows PowerShell was not found, or the admin
      script was launched without elevation. Fix the named cause and re-run
      from the release folder. Never a security finding - only "could not run."
  2   Warning - audit complete but issues found (review report)
  3   Unsupported OS - use -dev to override
  4   Reboot pending - Section 1 lists what is queued and whether it predates the last boot; Restart, not Shut down
  5   Ran from TEMP directory - move the script and re-run
  6   Partial audit - non-admin mode, some checks deferred
  7   Pre-flight VT integrity check failed - script-critical binary flagged
  8   Audit complete - CRITICAL findings present (2 = warnings only;
      treat 8 as an incident-response trigger)


OUTPUT FILES
--------------------------------------------------------------------------------
  Admin mode:
    C:\SecurityAudit\SecurityReport_[timestamp].txt      Plain text report
    C:\SecurityAudit\SecurityReport_[timestamp].html     HTML report (navigable)
    C:\SecurityAudit\ChangeLog_[timestamp].txt           Changes made
    C:\SecurityAudit\Undo_[timestamp].bat                Reversal script
    C:\SecurityAudit\SmartData\
    C:\SecurityAudit\EventExports\
    C:\SecurityAudit\ThreatLists\

  Non-admin mode:
    %USERPROFILE%\SecurityAudit\SecurityReport_[timestamp].txt
    %USERPROFILE%\SecurityAudit\SecurityReport_[timestamp].html
    (same subdirectory structure, including AuditConsole_[timestamp].log;
    a -noAdmin run writes nothing at the root of C:)

  The HTML report opens automatically after the audit completes. It features
  a dark-theme dashboard with CRITICAL/WARNING/PASSED/INFO counts, a
  navigation sidebar, color-coded findings, and collapsible detail sections.


AUDIT SECTIONS (18 total)
--------------------------------------------------------------------------------
  Pre-flight (INIT 1-14):
    1.  Temp path check            8.  RunOnce resume key
    2.  Admin detection            9.  Network connectivity
    3.  OS version detection       10. Self-update check
    4.  OS compatibility           11. F8 boot menu *
    5.  Safe Mode detection        12. System Restore Point *
    6.  Log directory creation     13. Disk config / free space
    7.  Resume detection           14. SMART disk health *

  Security Audit:
    1.  System identity and patch level
    2.  User accounts and privilege audit
    3.  Network configuration and live connections
    4.  Running processes (LOLBins, RMM tools, suspicious paths)
    5.  Startup and persistence mechanisms (Run keys, Winlogon, IFEO)
    6.  Scheduled tasks
    7.  Windows services audit (partial without admin)
    8.  Firewall configuration *
    9.  Windows Defender and AV status, ASR rules audit *
    10. SMB, RDP, and remote access (partial without admin)
    11. PowerShell security (partial without admin)
    12. Credential and LSASS protection
    13. System hardening (UAC, BitLocker*, SecureBoot*, drivers*,
        Office macro policy, Mark-of-the-Web, SmartScreen)
    14. Suspicious files and file system anomalies
    15. Installed software and driver audit + browser-extension inventory
    16. Windows Event Log anomalies (partial without admin)
    17. Nation-state threat indicators (MDDR 2023-2025)
    18. CTI-driven IOC sweep (SENTINEL-X threat intelligence)

  * = requires administrator privileges


SECTION 18: CTI-DRIVEN IOC SWEEP
--------------------------------------------------------------------------------
Section 18 reads structured IOC files from ThreatLists/ and matches them
against the live system. It works fully without admin.

  Sub-checks (file-based, run on every audit):
    18a  Process name IOC match
    18b  Named pipe IOC match (C2 frameworks)
    18c  Service IOC match
    18d  Malware staging file path check
    18e  Scheduled task IOC match
    18f  DNS cache C2 domain match
    18g  LOLBin command-line pattern match
    18h  Suspicious registry key check
    18i  MITRE ATT&CK TTP coverage summary
    18k  Local SHA256 hash IOC match (offline, always-on)

  Sub-checks (VirusTotal, opt-in via -vt + API key):
    18j  VirusTotal file hash reputation (priority files)
    18l  VirusTotal IP reputation (active remote connections)

  Plus inline CTI checks: DLL search-order hijacking, BYOVD vulnerable
  drivers, AMSI bypass artifacts, ransomware precursors and file
  extensions, COM object hijacking, browser/cloud credential access,
  AiTM token cache artifacts, OpenSSH lateral-movement surface, and more.


THREATLISTS/ IOC FILES
--------------------------------------------------------------------------------
Plain-text indicator files consumed by Section 18. One entry per line.
Lines starting with # are comments.

  ioc_processes.txt        Malicious process names (ransomware, C2, cred tools)
  ioc_named_pipes.txt      C2 named pipes (Cobalt Strike, Sliver, Havoc, etc.)
  ioc_services.txt         Malicious service names (RMM, BYOVD, fake updates)
  ioc_registry.txt         Suspicious registry keys and values
  ioc_file_paths.txt       Known malware staging paths (Temp, AppData, Public)
  ioc_scheduled_tasks.txt  Malicious task names and path patterns
  ioc_domains.txt          C2 domain patterns and suspicious TLDs
  ioc_hashes.txt           SHA256 hashes of known malware (BYOVD, ransomware)
  ioc_lolbins.txt          LOLBin command-line abuse patterns
  ttp_manifest.txt         MITRE ATT&CK v14+ technique map (48 techniques)

  Entry counts per file are listed in README.md (ThreatLists/ section),
  along with the command to re-derive them from the live files.


THREAT COVERAGE
--------------------------------------------------------------------------------
  Nation-State APT:
    Volt Typhoon, Salt Typhoon, Midnight Blizzard, Forest Blizzard,
    Scattered Spider, Lazarus Group, Flax Typhoon, Linen Typhoon,
    Violet Typhoon, Peach Sandstorm, Mango Sandstorm, APT29

  Ransomware:
    LockBit 3.0, BlackCat/ALPHV, Akira, Play, Royal, Black Basta,
    Rhysida, Medusa

  Credential Theft:
    BYOVD drivers, Mimikatz variants, Kerberoasting, NTLM relay,
    LSASS dumping, Pass-the-Hash, DPAPI abuse

  C2 Frameworks:
    Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic, Nighthawk,
    PoshC2, Merlin

  Supply Chain:
    Trojanized packages, compromised update mechanisms

  LOLBins:
    certutil, mshta, regsvr32, rundll32, msiexec, bitsadmin,
    cmstp, installutil, wmic, forfiles


RUNNING FROM A USB STICK
--------------------------------------------------------------------------------
  The audit installs nothing, so it can travel on a USB stick. The stick only
  CARRIES the files: the audit runs inside the PC's own Windows. Nothing here
  makes the stick bootable -- never boot a PC from it (see below). If the PC
  is not yours, read docs\second-machine.md first: ask the owner; on a work PC
  get IT's written OK, because its security software may alert them.

  1. MAKE THE STICK (on your own laptop, PowerShell as administrator, in your
     doze_sec checkout):

       powershell -NoProfile -ExecutionPolicy Bypass -File tools\make_usb_stick.ps1

     It lists your drives and numbers only the USB sticks it accepts (every
     other drive is shown with the reason). Type the number, then the drive
     letter to confirm; nothing is written before that. -Drive E: names the
     stick instead; -ListCandidates only lists.

     It accepts only a drive on the USB bus that is not the Windows disk, and
     it NEVER formats anything. It copies the tool to E:\doze_sec without
     .git, without the test harness (the scripts that plant fake malware or
     create a user account) and without itself, and keeps a SHA-256 manifest
     on your laptop. Then eject, plug back in, and run the -Verify command it
     prints. If Windows says the stick must be formatted: File Explorer,
     right-click it, Format, exFAT. FORMATTING ERASES EVERY FILE ON THAT
     DRIVE -- check the letter, and that it is not a BitLocker-locked or
     Mac-formatted stick holding files you need.

     NO GIT, OR THE CHANGE IS NOT MERGED YET? The script needs no git. On
     GitHub: the branch, Code, Download ZIP; Extract All with the destination
     set to the folder the ZIP is in (the ZIP holds its own folder, and the
     default destination adds another). That folder is doze_sec- plus the
     branch name with every / turned into - (for claude/code-review-3qcjyn:
     doze_sec-claude-code-review-3qcjyn). Test-Path the script's full path
     (...\doze_sec-claude-code-review-3qcjyn\tools\make_usb_stick.ps1) and
     run the command above with that path. Every text file goes onto the stick with Windows
     line endings, which a download lacks, so the stick is the same.

  2. RUN IT on the other PC, straight from the stick (nothing copied):

       powershell -NoProfile -ExecutionPolicy Bypass -File E:\doze_sec\tests\field_test.ps1

     Once as administrator if you can, then once in a normal window. Leave
     the stick in until it prints OK or FAIL, and take it out before the PC
     restarts. Or copy E:\doze_sec to C:\Users\<name>\doze_sec (not Documents,
     which OneDrive may upload; never a Temp folder) and run it from there.
     Results are written on that PC (C:\SecurityAudit and
     C:\Users\<name>\SecurityAudit): copy them to the stick OUTSIDE
     E:\doze_sec (e.g. E:\results\<PC name>), then delete them from the PC.
     Anything added inside E:\doze_sec reads as tampering back home.
     If it prints AUDIT NOT PERFORMED, IT policy blocks the audit. STOP; do
     not work around it.

  3. BACK HOME, before opening anything on the stick, run the checker kept on
     this laptop (the -Verify command the make run printed, or from your
     checkout) -- never anything from the stick:

       powershell -NoProfile -ExecutionPolicy Bypass -File tools\make_usb_stick.ps1 -Verify

     (with no drive named it asks which stick to check, which needs PowerShell
     as administrator; in a normal window name it: -Drive E: -Verify)

     Any tool file the visited PC changed, any link, and any new file at the
     stick root that could run is listed -- that is itself worth reporting;
     keep that stick as it is (evidence) and use a new one. Move E:\results
     to your laptop and delete it from the stick before the stick travels
     again. Read the .txt report. Never run anything from the stick on your
     own laptop. If it says UNVERIFIED and lists manifests, the stick may have
     a new volume ID (another USB port) AND a change: run it again with
     -Manifest "<the path it lists>" to see what changed.

  WHY THE STICK IS NOT BOOTABLE: booting from it would start a different
  Windows, and the audit checks the Windows that is running -- it would
  describe the stick, not the PC. Windows' own bootable stick (a recovery
  drive) has no PowerShell, so the audit could not start there anyway.
  DO NOT BOOT THE PC FROM THE STICK, CHANGE ITS BOOT SETTINGS, OR LEAVE THE
  STICK IN WHILE IT RESTARTS: on a PC with BitLocker or device encryption it
  can demand the 48-digit recovery key at the next start, and without the key
  you cannot get to any file on it again. For a check from outside the running
  Windows, use the built-in Microsoft Defender Offline scan (Windows Security >
  Virus & threat protection > Scan options). It needs an x64 PC with Defender
  as the active antivirus and the recovery environment enabled (reagentc /info
  in an elevated window: "Windows RE status: Enabled"), or it silently does
  nothing -- and have the BitLocker recovery key in hand first.


REQUIREMENTS
--------------------------------------------------------------------------------
  - Windows 10 or Windows 11 (client editions)
  - PowerShell 5.1+ (included with Windows 10/11)
  - Windows Terminal or cmd.exe with ANSI support for colored output
  - Administrator privileges for full audit (optional with -noAdmin)
  - smartmontools (optional, for detailed SMART data):
    https://www.smartmontools.org/wiki/Download
  - Claude Code CLI (optional, for -updateTTP):
    npm install -g @anthropic-ai/claude-code
  - VirusTotal API key (optional, for -vt and the pre-flight integrity
    check): https://www.virustotal.com/gui/my-apikey


CONSOLE COLOR SCHEME
--------------------------------------------------------------------------------
  Green      INIT steps completing successfully
  Cyan       Audit section progress (e.g., [3/18] Scanning network...)
  Red        Fatal errors, EXIT codes
  Magenta    Deferred checks (non-admin mode)
  Yellow     Warnings in final summary
  White/Bold Banner headers and dividers

  The live security summary uses PowerShell Write-Host for colored output:
  Red        CRITICAL findings (immediate action required)
  Yellow     WARNING findings (review recommended)
  Green      PASSED checks
  Cyan       Fix instructions


KNOWN LIMITATIONS
--------------------------------------------------------------------------------
  - wmic is deprecated in newer Windows 11 builds. The script falls back
    to PowerShell equivalents where possible.

  - Free space detection may return 0 bytes on Intel RAID volumes via wmic.
    A PowerShell Get-PSDrive fallback is used automatically.

  - The Security event log (Events 1102, 4624, 4625, 4688, etc.) requires
    administrator privileges to read. In non-admin mode, System, PowerShell,
    and Defender event logs are still checked.

  - Running from the TEMP directory is blocked (exit code 5) because
    cleanup operations may delete the script mid-run.

  - System Restore Point creation fails in Safe Mode on Windows 10.
    This is a known Microsoft bug with no workaround.

  - VirusTotal checks (-vt) are opt-in, need an API key, and are
    rate-limited on the free tier (4 lookups/min) -- a full -vt run adds
    several minutes. The pre-flight integrity check aborts the audit
    with exit code 7 if a script-critical binary is flagged malicious.

  - Threat indicator lists age. INIT 10/14 warns when upstream lists are
    more than 60 days old; refresh with -updateTTP (Claude CLI) or
    -importTTP (offline file).

  - The audit is point-in-time detection, not real-time protection.
    See THREAT_MODEL.md for the full coverage matrix, non-goals, and
    inherent limitations.


DOCUMENTATION
--------------------------------------------------------------------------------
  README.md         Canonical documentation: switches, output files,
                    IOC entry counts, CTI skill integration, private-repo
                    tokens, VirusTotal setup, contributing + lint rule.
  THREAT_MODEL.md   What the tool protects against and what it does not:
                    coverage by MITRE ATT&CK tactic and threat class,
                    non-goals, inherent limitations, known gaps.
  CLAUDE.md         Developer notes: cmd.exe parsing traps, the rem-only-
                    inside-parens rule (enforced by CI lint), conventions.

  Contributors: run the batch lint before committing .bat changes:
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1


PROJECT STRUCTURE
--------------------------------------------------------------------------------
  doze_sec/
    doze_sec.bat              Main audit script (requires admin)
    doze_sec_noAdmin.bat      Adaptive audit (admin or non-admin)
    readMe.txt                This file (quick plain-text guide)
    README.md                 Canonical documentation
    THREAT_MODEL.md           Coverage matrices, non-goals, limitations
    CLAUDE.md                 Developer / contributor notes
    version.txt               Current version (7.3)
    ThreatLists/
      ioc_processes.txt       Process name IOCs
      ioc_named_pipes.txt     Named pipe IOCs
      ioc_services.txt        Service name IOCs
      ioc_registry.txt        Registry key IOCs
      ioc_file_paths.txt      File path IOCs
      ioc_scheduled_tasks.txt Scheduled task IOCs
      ioc_domains.txt         C2 domain IOCs
      ioc_hashes.txt          SHA256 hash IOCs
      ioc_lolbins.txt         LOLBin pattern IOCs
      ttp_manifest.txt        MITRE ATT&CK TTP manifest
    tools/
      threat_list_sync.ps1    INIT 10/14 incremental IOC list sync
      ttp_merge.ps1           -updateTTP / -importTTP merge engine
      vt_check.ps1            Section 18j VirusTotal hash reputation
      vt_ip_check.ps1         Section 18l VirusTotal IP reputation
      vt_self_check.ps1       Pre-flight binary integrity check
      ioc_hash_check.ps1      Section 18k offline hash IOC match
      service_signature_check.ps1  Section 7 Authenticode gating
      scheduled_tasks_full.ps1     Section 6 full task inventory
      browser_extensions.ps1       Section 15 browser-extension inventory (T1176)
      report_format.ps1 / top_findings.ps1 / select_lines.ps1
                              Report formatting helpers
      lint_batch_comments.ps1 Batch comment lint (run by CI)
    .github/workflows/
      lint.yml                CI: batch comment lint on every push/PR


LICENSE
--------------------------------------------------------------------------------
  For personal and organizational security use. Not for redistribution
  without permission.

================================================================================
