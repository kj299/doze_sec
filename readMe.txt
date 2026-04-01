================================================================================
  doze_sec - Windows Security Forensic Audit Tool
  Version 7.0 | SENTINEL-X CTI Integration
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

  -updateTTP    Refresh ThreatLists/ IOC files before the audit.

  -help         Show full usage guide with section descriptions.
  -h, /?, --help  (aliases)


EXIT CODES
--------------------------------------------------------------------------------
  0   Success - all checks passed, no issues found
  1   Fatal error - check console output for details
  2   Warning - audit complete but issues found (review report)
  3   Unsupported OS - use -dev to override
  4   Reboot pending - reboot the system, then re-run
  5   Ran from TEMP directory - move the script and re-run
  6   Partial audit - non-admin mode, some checks deferred


OUTPUT FILES
--------------------------------------------------------------------------------
  Admin mode:
    C:\SecurityAudit\SecurityReport_[timestamp].txt
    C:\SecurityAudit\SmartData\
    C:\SecurityAudit\EventExports\
    C:\SecurityAudit\ThreatLists\

  Non-admin mode:
    %USERPROFILE%\SecurityAudit\SecurityReport_[timestamp].txt
    (same subdirectory structure)


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
    9.  Windows Defender and AV status *
    10. SMB, RDP, and remote access (partial without admin)
    11. PowerShell security (partial without admin)
    12. Credential and LSASS protection
    13. System hardening (UAC, BitLocker*, SecureBoot*, drivers*)
    14. Suspicious files and file system anomalies
    15. Installed software and driver audit
    16. Windows Event Log anomalies (partial without admin)
    17. Nation-state threat indicators (MDDR 2023-2025)
    18. CTI-driven IOC sweep (SENTINEL-X threat intelligence)

  * = requires administrator privileges


SECTION 18: CTI-DRIVEN IOC SWEEP
--------------------------------------------------------------------------------
Section 18 reads structured IOC files from ThreatLists/ and matches them
against the live system. It works fully without admin.

  Sub-checks:
    18a  Process name IOC match
    18b  Named pipe IOC match (C2 frameworks)
    18c  Service IOC match
    18d  Malware staging file path check
    18e  Scheduled task IOC match
    18f  DNS cache C2 domain match
    18g  LOLBin command-line pattern match
    18h  Suspicious registry key check
    18i  MITRE ATT&CK TTP coverage summary


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
    LSASS dumping, Pass-the-Hash

  C2 Frameworks:
    Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic, Nighthawk

  Supply Chain:
    Trojanized packages, compromised update mechanisms

  LOLBins:
    certutil, mshta, regsvr32, rundll32, msiexec, bitsadmin,
    cmstp, installutil, wmic, forfiles


REQUIREMENTS
--------------------------------------------------------------------------------
  - Windows 10 or Windows 11 (client editions)
  - PowerShell 5.1+ (included with Windows 10/11)
  - Windows Terminal or cmd.exe with ANSI support for colored output
  - Administrator privileges for full audit (optional with -noAdmin)
  - smartmontools (optional, for detailed SMART data):
    https://www.smartmontools.org/wiki/Download


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


PROJECT STRUCTURE
--------------------------------------------------------------------------------
  doze_sec/
    doze_sec.bat              Main audit script (requires admin)
    doze_sec_noAdmin.bat      Adaptive audit (admin or non-admin)
    readMe.txt                This file
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


LICENSE
--------------------------------------------------------------------------------
  For personal and organizational security use. Not for redistribution
  without permission.

================================================================================
