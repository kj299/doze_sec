@echo off
:: ====================================================================
::  WIN11 SECURITY FORENSIC AUDIT  v7.1
::  CMD-COMPATIBLE: All PowerShell runs via temp .ps1 file (-File mode).
::  Nation-state TTPs: Microsoft MDDR 2023.
::
::  COMMAND-LINE SWITCHES:
::    -dev       Bypass unsupported OS check (testing/research use)
::    -resume    Resume after interrupted run (skips pre-flight steps)
::    -sdu       Skip threat intel list update from GitHub
::    -nosrp     Skip System Restore Point creation
::    -updateTTP Run CTI skill via Claude Code to pull latest TTPs and
::               auto-generate new detection blocks (requires Claude Code CLI)
::    -importTTP <file>  Merge TTP rows from a pipe-delimited file into
::               ThreatLists/ -- offline alternative to -updateTTP that
::               skips the Claude CLI dependency
::    -vt        Query VirusTotal for SHA256 hashes of priority files
::               (Section 18j). Requires API key in %USERPROFILE%\.vt_token
::    -noVtSelf  Skip the automatic pre-flight binary integrity check
::               (which runs whenever ~/.vt_token exists and network is up)
::
::  EXIT CODES:
::    0  Success
::    1  Error (usually fatal - check console output)
::    2  Warning (audit complete but issues found - check report)
::    3  Unsupported OS (use -dev to override)
::    4  Exit pending reboot (reboot then re-run)
::    5  Script is running from the TEMP directory (not allowed)
::
::  OUTPUT: C:\SecurityAudit\SecurityReport_[timestamp].txt
::  SMART:  C:\SecurityAudit\SmartData\
::  LOGS:   C:\SecurityAudit\EventExports\
:: ====================================================================
setlocal enabledelayedexpansion

:: ---- Script identity and config ----
set "SCRIPT_VERSION=7.1"
set "SCRIPT_NAME=WIN11_SecurityAudit"
set "SCRIPT_PATH=%~dp0%~nx0"
:: Set UPDATE_URL to your GitHub raw base URL to enable self-update checks.
:: Leave as-is to skip the update check (placeholder is detected and skipped).
set "UPDATE_URL=https://raw.githubusercontent.com/kj299/doze_sec/main"

:: ---- Console color setup (ANSI escape codes, Win10 1607+) ----
for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "C_RESET=%ESC%[0m"
set "C_RED=%ESC%[91m"
set "C_GREEN=%ESC%[92m"
set "C_YELLOW=%ESC%[93m"
set "C_BLUE=%ESC%[94m"
set "C_MAGENTA=%ESC%[95m"
set "C_CYAN=%ESC%[96m"
set "C_WHITE=%ESC%[97m"
set "C_BOLD=%ESC%[1m"
set "C_DIM=%ESC%[2m"

:: ---- Runtime state variables ----
set "EXIT_CODE=0"
set "DEV_MODE=0"
set "RESUME_MODE=0"
set "SKIP_THREAT_UPDATE=0"
set "SKIP_SRP=0"
set "UPDATE_TTP=0"
set "IMPORT_TTP_FILE="
set "VT_CHECK=0"
set "VT_SELF_SKIP=0"
set "IOC_HITS=0"
set "NETWORK_AVAIL=0"
set "SAFE_MODE=0"
set "SKIP_DEFRAG=no"
set "SMART_WARN=0"
set "FREE_BEFORE=0"
set "FREE_AFTER=0"
set "OS_BUILD=0"
set "OS_VER=unknown"
set "OS_PTYPE=1"
set "WIN_GEN=unknown"
set "IE_VER=unknown"
set "SMARTCTL_PATH="

:: ====================================================================
:: SWITCH PARSING
:: ====================================================================
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="-help"       goto :show_help
if /i "%~1"=="--help"      goto :show_help
if /i "%~1"=="-h"          goto :show_help
if /i "%~1"=="/?"          goto :show_help
if /i "%~1"=="-dev"        set "DEV_MODE=1"
if /i "%~1"=="-resume"     set "RESUME_MODE=1"
if /i "%~1"=="-sdu"        set "SKIP_THREAT_UPDATE=1"
if /i "%~1"=="-nosrp"      set "SKIP_SRP=1"
if /i "%~1"=="-updateTTP"  set "UPDATE_TTP=1"
if /i "%~1"=="-importTTP"  goto :parse_importttp
if /i "%~1"=="-vt"         set "VT_CHECK=1"
if /i "%~1"=="-noVtSelf"   set "VT_SELF_SKIP=1"
shift
goto :parse_args
:parse_importttp
shift
if "%~1"=="" (
    echo  [ERROR] -importTTP requires a file path argument.
    echo  Example: %~nx0 -importTTP C:\path\to\ttp_feed.txt
    exit /b 1
)
set "IMPORT_TTP_FILE=%~1"
set "UPDATE_TTP=1"
shift
goto :parse_args
:args_done
goto :help_done

:show_help
echo.
echo.
echo  %C_BOLD%%C_WHITE%====================================================================
echo   WIN11 SECURITY FORENSIC AUDIT  v%SCRIPT_VERSION%
echo   SENTINEL-X CTI Integration
echo  ====================================================================%C_RESET%
echo.
echo  %C_BOLD%USAGE:%C_RESET%  %C_CYAN%%~nx0%C_RESET% [switches]
echo.
echo  %C_BOLD%SWITCHES:%C_RESET%
echo.
echo    %C_GREEN%-dev%C_RESET%         Bypass the unsupported-OS check. Use on Server editions,
echo                 Windows 8.1, or unrecognised builds for testing/research.
echo.
echo    %C_GREEN%-resume%C_RESET%      Skip pre-flight steps 8-14 (RunOnce key, network, self-update,
echo                 F8 boot menu, SRP, disk config, SMART). Used automatically
echo                 by the RunOnce key if a previous run was interrupted by a
echo                 reboot or crash.
echo.
echo    %C_GREEN%-sdu%C_RESET%         Skip threat intel list update from the configured GitHub
echo                 URL. Useful on air-gapped systems or slow connections.
echo.
echo    %C_GREEN%-nosrp%C_RESET%       Skip System Restore Point creation. Saves 30-60 seconds
echo                 if you already have a recent restore point.
echo.
echo    %C_GREEN%-updateTTP%C_RESET%   Refresh the ThreatLists/ IOC files before the audit.
echo                 Requires network. Downloads latest indicators from the
echo                 configured threat intelligence source.
echo.
echo    %C_GREEN%-importTTP%C_RESET% ^<file^>
echo                 Merge TTP rows from a pipe-delimited file into the
echo                 ThreatLists/ IOC files. Same sanitization and merge
echo                 pipeline as -updateTTP but skips the Claude Code CLI
echo                 dependency -- useful when AI LLMs are unavailable or
echo                 you maintain your own CTI feed (MISP export, OTX
echo                 pulse, internal SOC enrichment, etc.).
echo                 File format (one row per line, no header):
echo                   MITRE_ID^|Name^|Detection_Method^|Detection_Value^|Severity^|Actor
echo                 Detection_Method must be one of: registry key, event id,
echo                 process name, file path, named pipe, wmi query.
echo                 Detection_Value is sanitized -- shell metacharacters
echo                 (quotes, ;, ^|, ^&, ^<, ^>, parens, braces, ^^) cause the
echo                 row to be dropped.
echo.
echo    %C_GREEN%-vt%C_RESET%          Query VirusTotal for SHA256 hashes of priority files
echo                 (recent EXE/DLL/PS/VBS in TEMP/Downloads/AppData and
echo                 recent drivers in System32\drivers). Requires a VT API
echo                 key in %%USERPROFILE%%\.vt_token (single line, no quotes).
echo                 Capped at 20 files; free-tier rate limit ~16 s/file
echo                 (~5 min for the full set). Only hashes are sent; file
echo                 contents are never uploaded.
echo.
echo    %C_GREEN%-noVtSelf%C_RESET%    Skip the automatic pre-flight VT integrity check on
echo                 the script-critical binaries (PWSH, wmic, wevtutil, reg).
echo                 By default that check runs whenever %%USERPROFILE%%\.vt_token
echo                 exists and the network is up. Adds ~50 s to startup but
echo                 detects tampered system binaries before any audit data
echo                 is collected. Audit aborts with EXIT_CODE=7 if any
echo                 binary is flagged malicious by VT.
echo.
echo    %C_GREEN%-help, -h, /?, --help%C_RESET%
echo                 Show this help screen and exit.
echo.
echo  %C_BOLD%EXAMPLES:%C_RESET%
echo.
echo    Run as Administrator (full audit):
echo      Right-click ^> Run as administrator
echo      %~nx0
echo.
echo    Run on unsupported OS for research:
echo      %~nx0 -dev
echo.
echo    Combine switches:
echo      %~nx0 -nosrp -sdu
echo.
echo  %C_BOLD%AUDIT SECTIONS (18 total):%C_RESET%
echo.
echo    Pre-flight (INIT 1-14):
echo      Temp path check, admin detection, OS version, Safe Mode,
echo      log dirs, resume detection, RunOnce key, network check,
echo      self-update, F8 boot menu, SRP, disk config, SMART
echo.
echo    Security Audit:
echo      1.  System identity and patch level
echo      2.  User accounts and privilege audit
echo      3.  Network configuration and live connections
echo      4.  Running processes (LOLBins, RMM tools, suspicious paths)
echo      5.  Startup and persistence mechanisms
echo      6.  Scheduled tasks
echo      7.  Windows services audit
echo      8.  Firewall configuration
echo      9.  Windows Defender and AV status
echo      10. SMB, RDP and remote access
echo      11. PowerShell security
echo      12. Credential and LSASS protection
echo      13. System hardening
echo      14. Suspicious files and file system anomalies
echo      15. Installed software and driver audit
echo      16. Windows Event Log anomalies
echo      17. Nation-state threat indicators
echo      18. CTI-driven IOC sweep (SENTINEL-X threat intelligence)
echo.
echo  %C_BOLD%SECTION 18 -- CTI IOC SWEEP:%C_RESET%
echo    Reads IOC files from ThreatLists/ and matches against the live
echo    system. Sub-checks:
echo      18a  Process name IOC match
echo      18b  Named pipe IOC match (C2 frameworks)
echo      18c  Service IOC match
echo      18d  Malware staging file path check
echo      18e  Scheduled task IOC match
echo      18f  DNS cache C2 domain match
echo      18g  LOLBin command-line pattern match
echo      18h  Suspicious registry key check
echo      18i  MITRE ATT^&CK TTP coverage summary
echo.
echo  %C_BOLD%IOC FILES (ThreatLists/ directory):%C_RESET%
echo    ioc_processes.txt       Malicious process names
echo    ioc_named_pipes.txt     C2 named pipes
echo    ioc_services.txt        Malicious service names
echo    ioc_registry.txt        Suspicious registry keys
echo    ioc_file_paths.txt      Known malware staging paths
echo    ioc_scheduled_tasks.txt Malicious task names
echo    ioc_domains.txt         C2 domains
echo    ioc_hashes.txt          SHA256 malware hashes
echo    ioc_lolbins.txt         LOLBin command patterns
echo    ttp_manifest.txt        MITRE ATT^&CK technique map
echo.
echo  %C_BOLD%EXIT CODES:%C_RESET%
echo    0  Success -- all checks passed
echo    1  Fatal error (check console output)
echo    2  Warning -- audit complete but issues found
echo    3  Unsupported OS (use -dev to override)
echo    4  Reboot pending (reboot then re-run)
echo    5  Script ran from TEMP directory (move and re-run)
echo.
echo  %C_BOLD%OUTPUT:%C_RESET%
echo    C:\SecurityAudit\SecurityReport_[timestamp].txt
echo    SMART data:    C:\SecurityAudit\SmartData\
echo    Event exports: C:\SecurityAudit\EventExports\
echo    IOC copies:    C:\SecurityAudit\ThreatLists\
echo.
echo  %C_BOLD%THREAT COVERAGE:%C_RESET%
echo    APT/Nation-State: Volt Typhoon, Salt Typhoon, Midnight Blizzard,
echo      Forest Blizzard, Scattered Spider, Lazarus Group, Flax Typhoon,
echo      Linen Typhoon, Violet Typhoon, Peach/Mango Sandstorm, APT29
echo    Ransomware: LockBit 3.0, BlackCat/ALPHV, Akira, Play, Royal,
echo      Black Basta, Rhysida, Medusa
echo    Credential: BYOVD, Mimikatz variants, Kerberoasting, NTLM relay
echo    C2 Frameworks: Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic
echo    Supply Chain: Trojanized packages, compromised update mechanisms
echo.
echo  ====================================================================
echo.
endlocal & exit /b 0
:help_done

:: ====================================================================
:: -updateTTP / -importTTP HANDLER
::   -updateTTP : invoke SENTINEL-X CTI skill via Claude Code CLI to
::                generate fresh TTP rows
::   -importTTP <file> : skip the LLM call and use the supplied
::                pipe-delimited file as the TTP source
:: Both feed into the same sanitization + IOC merge pipeline below.
:: ====================================================================
if "%UPDATE_TTP%"=="0" goto :skip_ttp_update

echo.
echo ====================================================================
if defined IMPORT_TTP_FILE (
    echo  -importTTP: Loading TTP rows from %IMPORT_TTP_FILE%
) else (
    echo  -updateTTP: Invoking CTI Skill via Claude Code
)
echo ====================================================================
echo.

:: Ensure OUTDIR is set before use (main OUTDIR set later, but -updateTTP runs early)
if not defined OUTDIR set "OUTDIR=C:\SecurityAudit"
if not exist "%OUTDIR%\ThreatLists" mkdir "%OUTDIR%\ThreatLists" 2>nul
:: Compute today's date as locale-independent yyyyMMdd via PowerShell.
:: %date% is locale-dependent (US=ddd MM/DD/YYYY, ISO=YYYY-MM-DD, DE=DD.MM.YYYY,
:: etc.) and substring slicing produces garbage on non-US systems.
for /f "usebackq" %%i in (`powershell -NoProfile -Command "Get-Date -Format yyyyMMdd"`) do set "TTP_TODAY=%%i"
if not defined TTP_TODAY set "TTP_TODAY=unknown"
set "TTP_OUTPUT=%OUTDIR%\ThreatLists\ttp_update_%TTP_TODAY%.txt"
set "TTP_BLOCKS=%OUTDIR%\ThreatLists\ttp_generated_checks.bat"

if defined IMPORT_TTP_FILE (
    if not exist "%IMPORT_TTP_FILE%" (
        echo  [ERROR] -importTTP file not found: %IMPORT_TTP_FILE%
        echo  Skipping TTP merge.
        goto :skip_ttp_update
    )
    copy /y "%IMPORT_TTP_FILE%" "%TTP_OUTPUT%" >nul 2>&1
    if errorlevel 1 (
        echo  [ERROR] Failed to copy %IMPORT_TTP_FILE% to %TTP_OUTPUT%.
        goto :skip_ttp_update
    )
    echo  [OK] Loaded TTP rows from %IMPORT_TTP_FILE%. Skipping CTI skill call.
    echo  [INFO] Output staged at: %TTP_OUTPUT%
    goto :sanitize_ttp_output
)

echo  This will call the SENTINEL-X Cyber Threat Intelligence skill
echo  to pull the latest TTPs and generate new detection blocks.
echo.

:: Check Claude Code CLI is available
where claude >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Claude Code CLI not found in PATH.
    echo  Install: https://docs.anthropic.com/en/docs/claude-code
    echo  Or run: npm install -g @anthropic-ai/claude-code
    echo.
    echo  Tip: pre-stage TTP rows in a pipe-delimited file and use
    echo       %~nx0 -importTTP ^<file^>  to skip the Claude CLI dependency.
    echo.
    echo  Falling back to existing TTP checks.
    goto :skip_ttp_update
)

set "CTI_SKILL_PATH=%~dp0..\threat-intel\cyber_threat_skill.yaml"

if not exist "%CTI_SKILL_PATH%" (
    echo  [WARN] CTI skill file not found at: %CTI_SKILL_PATH%
    echo  Cannot generate TTP update. Using existing checks.
    goto :skip_ttp_update
)

:: Collect existing IOC entries for deduplication
:: Use a GUID for the temp filename so a same-user local attacker cannot pre-create/race the path
for /f "usebackq delims=" %%g in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "IOC_GUID=%%g"
if not defined IOC_GUID set "IOC_GUID=%RANDOM%%RANDOM%%RANDOM%"
set "EXISTING_IOCS=%TEMP%\existing_iocs_%IOC_GUID%.txt"
if exist "%~dp0ThreatLists" (
    type "%~dp0ThreatLists\ioc_processes.txt" 2>nul | findstr /v /r "^#" > "%EXISTING_IOCS%" 2>nul
    type "%~dp0ThreatLists\ioc_named_pipes.txt" 2>nul | findstr /v /r "^#" >> "%EXISTING_IOCS%" 2>nul
    type "%~dp0ThreatLists\ttp_manifest.txt" 2>nul | findstr /v /r "^#" >> "%EXISTING_IOCS%" 2>nul
)

echo  [*] Querying CTI skill for latest Windows endpoint TTPs...
echo  [*] Output: %TTP_OUTPUT%
echo  [*] Mode: INCREMENTAL (merging with existing IOCs)
echo.

:: Call Claude Code with the CTI skill context to generate TTP intel
:: The prompt instructs incremental-only output and provides existing IOCs for dedup
claude -p "You are operating as the SENTINEL-X CTI Skill defined in this file. Today is %date%. Analyze the CURRENT threat landscape (2025-2026) for Windows 10/11 endpoints. IMPORTANT: Output ONLY NEW TTPs that are NOT already in the existing IOC list below. Do not duplicate existing detections. Output a structured list of up to 20 NEW TTPs. For each TTP provide: MITRE_ID, Name, Detection_Method (registry key, event ID, file path, process name, named pipe, or WMI query), Detection_Value (the exact IOC string), Severity (CRITICAL/WARNING/INFO), and Actor (threat group). Format as pipe-delimited CSV: MITRE_ID|Name|Detection_Method|Detection_Value|Severity|Actor. No headers, no explanation, just the data rows. EXISTING IOCs (do NOT duplicate these):" --file "%CTI_SKILL_PATH%" --file "%EXISTING_IOCS%" > "%TTP_OUTPUT%" 2>&1
if exist "%EXISTING_IOCS%" del "%EXISTING_IOCS%" >nul 2>&1

if %errorlevel% neq 0 (
    echo  [WARN] Claude Code returned an error. Using existing TTP checks.
    goto :skip_ttp_update
)

rem Detect specific Claude CLI auth failures that get captured into TTP_OUTPUT
rem instead of being raised as a non-zero exit (the CLI exits 0 but writes the
rem error message into stdout, which the sanitizer would later reject as
rem "wrong field count" -- confusing).
findstr /c:"CLAUDE_CODE_SESSION_ACCESS_TOKEN" "%TTP_OUTPUT%" >nul 2>&1
if not errorlevel 1 (
    echo  [ERROR] Claude Code CLI requires CLAUDE_CODE_SESSION_ACCESS_TOKEN to
    echo          be set for --file uploads. Two ways to proceed:
    echo            ^(a^) Set the env var with your Claude Code session token, then re-run
    echo                ^(see Anthropic Claude Code docs for how to obtain it^), or
    echo            ^(b^) Use:  %~nx0 -importTTP ^<file^>
    echo                to skip the Claude CLI dependency entirely. The pipe-delimited
    echo                file feeds into the same sanitizer + IOC merge.
    del "%TTP_OUTPUT%" >nul 2>&1
    goto :skip_ttp_update
)
findstr /i /c:"please run /login" /c:"not authenticated" /c:"not logged in" "%TTP_OUTPUT%" >nul 2>&1
if not errorlevel 1 (
    echo  [ERROR] Claude Code CLI is not authenticated. Run `claude` interactively
    echo          first to log in, or use:  %~nx0 -importTTP ^<file^>  instead.
    del "%TTP_OUTPUT%" >nul 2>&1
    goto :skip_ttp_update
)

if not exist "%TTP_OUTPUT%" (
    echo  [WARN] No output from CTI skill. Using existing checks.
    goto :skip_ttp_update
)

:sanitize_ttp_output
:: ====================================================================
:: SANITIZE CTI OUTPUT: drop any row whose Detection_Value contains
:: shell or PowerShell metacharacters, to prevent code injection when
:: the value is later emitted into TTP_BLOCKS or merged into the IOC
:: source files. Applies identically to LLM-generated rows (-updateTTP)
:: and user-supplied import files (-importTTP) -- both are untrusted.
:: Metachars are expressed as [char] codes in the PS below so we never
:: have to escape them through CMD.
::   Blocked char codes: 34 39 96 36 59 124 38 60 62 40 41 123 125 94
::   (double/single/backtick quotes, dollar, semicolon, pipe, amp,
::    angle brackets, parens, braces, caret)
:: ====================================================================
:: Ensure IOC_GUID is set (the -importTTP path skips the earlier
:: EXISTING_IOCS computation that sets it).
if not defined IOC_GUID (
    for /f "usebackq delims=" %%g in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "IOC_GUID=%%g"
)
if not defined IOC_GUID set "IOC_GUID=%RANDOM%%RANDOM%%RANDOM%"
set "TTP_SANITIZER_REPORT=%TEMP%\ttp_sanitize_%IOC_GUID%.log"
:: Note: %PWSH% is not resolved until later in setup; use plain 'powershell' here.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$src='%TTP_OUTPUT%'; $lines=Get-Content -LiteralPath $src -ErrorAction SilentlyContinue; $allow=@('registry key','event id','process name','file path','named pipe','wmi query'); $bad=[char[]]@(34,39,96,36,59,124,38,60,62,40,41,123,125,94); $safe=New-Object System.Collections.Generic.List[string]; $sample=New-Object System.Collections.Generic.List[string]; $dropFields=0; $dropLen=0; $dropMethod=0; $dropMeta=0; $dropAscii=0; foreach($l in $lines){ if(-not $l -or $l.Trim() -eq ''){continue}; $p=$l -split '\|'; if($p.Count -ne 6){$dropFields++; if($sample.Count -lt 3){$sample.Add('  - wrong field count: '+($l.Substring(0,[math]::Min(120,$l.Length))))}; continue}; $m=$p[2].Trim().ToLower(); $v=$p[3].Trim(); if($v.Length -eq 0 -or $v.Length -gt 260){$dropLen++; if($sample.Count -lt 3){$sample.Add('  - length out of range: '+($l.Substring(0,[math]::Min(120,$l.Length))))}; continue}; if($allow -notcontains $m){$dropMethod++; if($sample.Count -lt 3){$sample.Add('  - method ['+$m+'] not in allowlist: '+($l.Substring(0,[math]::Min(120,$l.Length))))}; continue}; if($v.IndexOfAny($bad) -ne -1){$dropMeta++; if($sample.Count -lt 3){$sample.Add('  - shell metacharacter in value: '+($l.Substring(0,[math]::Min(120,$l.Length))))}; continue}; if($v -notmatch '^[\x20-\x7E]+$'){$dropAscii++; if($sample.Count -lt 3){$sample.Add('  - non-ASCII printable in value: '+($l.Substring(0,[math]::Min(120,$l.Length))))}; continue}; $safe.Add($l) }; Set-Content -LiteralPath $src -Value $safe -Encoding ASCII; $totalDrop = $dropFields + $dropLen + $dropMethod + $dropMeta + $dropAscii; Write-Output ('  [SANITIZE] Kept: '+$safe.Count+'  Dropped: '+$totalDrop); if ($totalDrop -gt 0) { Write-Output ('  [SANITIZE]   - wrong field count   : '+$dropFields); Write-Output ('  [SANITIZE]   - length out of range : '+$dropLen); Write-Output ('  [SANITIZE]   - method not allowlist: '+$dropMethod); Write-Output ('  [SANITIZE]   - shell metacharacter : '+$dropMeta); Write-Output ('  [SANITIZE]   - non-ASCII printable : '+$dropAscii) }; if ($safe.Count -eq 0 -and $sample.Count -gt 0) { Write-Output '  [SANITIZE] First dropped row(s) (first 120 chars):'; $sample | ForEach-Object { Write-Output $_ } }" > "%TTP_SANITIZER_REPORT%" 2>&1
type "%TTP_SANITIZER_REPORT%"
del "%TTP_SANITIZER_REPORT%" >nul 2>&1

:: Abort the update if nothing survived sanitization
:: (use file size: ~za resolves to a plain numeric byte count with no prefix)
set "TTP_SAFE_SIZE=0"
for %%a in ("%TTP_OUTPUT%") do set "TTP_SAFE_SIZE=%%~za"
if "%TTP_SAFE_SIZE%"=="0" (
    echo  [WARN] CTI output failed sanitization ^(all rows dropped^). Skipping update.
    del "%TTP_OUTPUT%" >nul 2>&1
    goto :skip_ttp_update
)

echo  [OK] CTI intelligence retrieved. Generating detection blocks...

:: Parse the TTP output and generate batch detection commands
:: Each line: MITRE_ID|Name|Detection_Method|Detection_Value|Severity|Actor
:: INCREMENTAL: Append to existing TTP_BLOCKS if present, don't overwrite
if not exist "%TTP_BLOCKS%" (
    (
        echo @echo off
        echo :: ====================================================================
        echo :: AUTO-GENERATED TTP DETECTION BLOCKS
        echo :: Source: SENTINEL-X CTI Skill via Claude Code
        echo :: Re-generate: doze_sec.bat -updateTTP
        echo :: ====================================================================
        echo echo.^>^> "%%REPORT%%"
        echo echo --- [CTI-AUTO] Auto-Generated TTP Checks from SENTINEL-X ---^>^> "%%REPORT%%"
    ) > "%TTP_BLOCKS%"
)
echo :: --- Update: %date% %time% --->> "%TTP_BLOCKS%"

:: Process each TTP line from the CTI output
for /f "usebackq tokens=1-6 delims=|" %%a in ("%TTP_OUTPUT%") do (
    :: %%a=MITRE_ID %%b=Name %%c=Detection_Method %%d=Detection_Value %%e=Severity %%f=Actor
    if /i "%%c"=="registry key" (
        echo echo --- [CTI-AUTO][%%a] %%b ^(%%f^) ---^>^> "%%REPORT%%">> "%TTP_BLOCKS%"
        echo reg query "%%d"^>^> "%%REPORT%%" 2^>^&1>> "%TTP_BLOCKS%"
    )
    if /i "%%c"=="event ID" (
        echo echo --- [CTI-AUTO][%%a] %%b ^(%%f^) ---^>^> "%%REPORT%%">> "%TTP_BLOCKS%"
        echo wevtutil qe Security /q:"*[System[(EventID=%%d)]]" /c:10 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Account Name"^>^> "%%REPORT%%" 2^>^&1>> "%TTP_BLOCKS%"
    )
    if /i "%%c"=="process name" (
        echo echo --- [CTI-AUTO][%%a] %%b ^(%%f^) ---^>^> "%%REPORT%%">> "%TTP_BLOCKS%"
        echo echo Get-CimInstance Win32_Process -Filter "name='%%d'" -EA SilentlyContinue ^| Select-Object Name,ProcessId,ExecutablePath ^| Format-Table -AutoSize ^> "%%PSRUN%%">> "%TTP_BLOCKS%"
        echo "%%PWSH%%" -NoProfile -ExecutionPolicy Bypass -File "%%PSRUN%%"^>^> "%%REPORT%%" 2^>^&1>> "%TTP_BLOCKS%"
    )
    if /i "%%c"=="file path" (
        echo echo --- [CTI-AUTO][%%a] %%b ^(%%f^) ---^>^> "%%REPORT%%">> "%TTP_BLOCKS%"
        echo if exist "%%d" ^(echo [%%e] %%b IOC found: %%d^>^> "%%REPORT%%"^) else ^(echo [OK] %%b check clear.^>^> "%%REPORT%%"^)>> "%TTP_BLOCKS%"
    )
    if /i "%%c"=="named pipe" (
        echo echo --- [CTI-AUTO][%%a] %%b ^(%%f^) ---^>^> "%%REPORT%%">> "%TTP_BLOCKS%"
        echo echo try{$p=Get-ChildItem \\.\pipe\ -EA SilentlyContinue ^| Where-Object {$_.Name -match '%%d'}; if($p){'[%%e] %%b pipe detected: '+($p.Name -join ', ')}else{'[OK] %%b pipe check clear.'}}catch{'[INFO] Pipe check unavailable.'} ^> "%%PSRUN%%">> "%TTP_BLOCKS%"
        echo "%%PWSH%%" -NoProfile -ExecutionPolicy Bypass -File "%%PSRUN%%"^>^> "%%REPORT%%" 2^>^&1>> "%TTP_BLOCKS%"
    )
)

:: Merge new IOCs into ThreatLists files incrementally
set "SCRIPT_THREATS=%~dp0ThreatLists"
if exist "%SCRIPT_THREATS%" (
    for /f "usebackq tokens=1-6 delims=|" %%a in ("%TTP_OUTPUT%") do (
        if /i "%%c"=="process name" (
            findstr /x /c:"%%d" "%SCRIPT_THREATS%\ioc_processes.txt" >nul 2>&1
            if !errorlevel! neq 0 (
                echo # CTI-AUTO %date% [%%a] %%f>> "%SCRIPT_THREATS%\ioc_processes.txt"
                echo %%d>> "%SCRIPT_THREATS%\ioc_processes.txt"
            )
        )
        if /i "%%c"=="named pipe" (
            findstr /x /c:"%%d" "%SCRIPT_THREATS%\ioc_named_pipes.txt" >nul 2>&1
            if !errorlevel! neq 0 (
                echo # CTI-AUTO %date% [%%a] %%f>> "%SCRIPT_THREATS%\ioc_named_pipes.txt"
                echo %%d>> "%SCRIPT_THREATS%\ioc_named_pipes.txt"
            )
        )
        if /i "%%c"=="file path" (
            findstr /x /c:"%%d" "%SCRIPT_THREATS%\ioc_file_paths.txt" >nul 2>&1
            if !errorlevel! neq 0 (
                echo # CTI-AUTO %date% [%%a] %%f>> "%SCRIPT_THREATS%\ioc_file_paths.txt"
                echo %%d>> "%SCRIPT_THREATS%\ioc_file_paths.txt"
            )
        )
    )
    echo  [OK] New IOCs merged into ThreatLists/ files.
)

echo  [OK] Generated: %TTP_BLOCKS%
echo  [*] Auto-generated checks will execute during Section 18.
echo.

:: Remove the sanitized CTI response; keeping it serves no purpose
:: and leaks content from other runs if the folder is later shared.
if exist "%TTP_OUTPUT%" del "%TTP_OUTPUT%" >nul 2>&1

:skip_ttp_update

:: ====================================================================
:: [INIT 1/14] TEMP EXECUTION DETECTION (Exit code 5)
:: ====================================================================
:: Prevent running from TEMP - TEMP is one of the first paths wiped by
:: cleanup operations and can cause the script to self-delete mid-run.
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR_TRIMMED=%SCRIPT_DIR:~0,-1%"

if /i "%SCRIPT_DIR_TRIMMED%"=="%TEMP%" goto :err_tempdir
if /i "%SCRIPT_DIR_TRIMMED%"=="%TMP%"  goto :err_tempdir

:: Normalize for comparison - TEMP can be expressed via different env vars
for /f "usebackq" %%a in (`echo %TEMP%`) do set "TEMP_NORM=%%a"
if /i "%SCRIPT_DIR_TRIMMED%"=="%TEMP_NORM%" goto :err_tempdir

echo %C_GREEN%[INIT 1/14]%C_RESET% Execution path: OK (not running from TEMP)
goto :tempcheck_done
:err_tempdir
echo.
echo  %C_RED%[EXIT 5]%C_RESET% This script is running from the TEMP directory.
echo  This is not allowed. Move the script to a permanent location
echo  such as your Desktop or C:\Tools\ and run it from there.
echo.
set "EXIT_CODE=5"
:: Stub file vars for early exit so :end_script code never writes to empty path
if not defined CHANGELOG set "CHANGELOG=NUL"
if not defined UNDO_BAT  set "UNDO_BAT=NUL"
goto :end_script
:tempcheck_done

:: ====================================================================
:: EARLY PATH AND POWERSHELL SETUP
:: (Must happen before any PS calls or report file creation)
:: ====================================================================
set "OUTDIR=C:\SecurityAudit"
if not exist "%OUTDIR%"             mkdir "%OUTDIR%"
if not exist "%OUTDIR%\SmartData"   mkdir "%OUTDIR%\SmartData"
if not exist "%OUTDIR%\EventExports" mkdir "%OUTDIR%\EventExports"
if not exist "%OUTDIR%\ThreatLists" mkdir "%OUTDIR%\ThreatLists"

:: ---- Compute TIMESTAMP first (needed by changelog, undo, and report filenames) ----
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%I"
:: Trim trailing whitespace/CR that wmic appends to output
set "DT=%DT: =%"
:: Build timestamp - if wmic failed (DT empty), fall back to %date%/%time%
if defined DT (
    set "TIMESTAMP=!DT:~0,8!_!DT:~8,6!"
)
:: Validate: wmic may have returned empty or a non-date value
if "!TIMESTAMP!"=="__" set "TIMESTAMP="
if "!TIMESTAMP!"=="_" set "TIMESTAMP="
if not defined TIMESTAMP (
    :: Fallback: parse %date% as YYYY-MM-DD or MM/DD/YYYY and %time%
    :: This is locale-dependent but good enough for a filename
    set "_D=!date:/=-!"
    set "_D=!_D: =_!"
    set "_T=!time::=-!"
    set "_T=!_T: =0!"
    set "TIMESTAMP=!_D!_!_T:~0,8!"
    set "TIMESTAMP=!TIMESTAMP: =0!"
    :: Final fallback: random-based name that at least won't collide
    if "!TIMESTAMP!"=="__0-0-0" set "TIMESTAMP=NODATE_!RANDOM!_!RANDOM!"
)

:: ---- Initialize Undo script and Change Log --------------------------
set "CHANGELOG=%OUTDIR%\ChangeLog_!TIMESTAMP!.txt"
set "UNDO_BAT=%OUTDIR%\Undo_!TIMESTAMP!.bat"
echo @echo off> "!UNDO_BAT!"
echo :: ==================================================================>> "!UNDO_BAT!"
echo :: WIN11_SecurityAudit -- UNDO SCRIPT>> "!UNDO_BAT!"
(echo :: Generated: !TIMESTAMP!)>> "!UNDO_BAT!"
echo :: Run AS ADMINISTRATOR to reverse changes made by the audit script.>> "!UNDO_BAT!"
echo :: Only changes that are NOT security improvements are listed here.>> "!UNDO_BAT!"
echo :: Security-improving changes (Defender, UAC, etc.) are intentional>> "!UNDO_BAT!"
echo :: and must be reversed manually if desired.>> "!UNDO_BAT!"
echo :: ==================================================================>> "!UNDO_BAT!"
echo.>> "!UNDO_BAT!"
echo echo Reversing WIN11_SecurityAudit changes...>> "!UNDO_BAT!"
echo.>> "!UNDO_BAT!"

echo WIN11_SecurityAudit v%SCRIPT_VERSION% -- Change Log> "!CHANGELOG!"
(echo Run: !TIMESTAMP!)>> "!CHANGELOG!"
echo Host: %COMPUTERNAME%>> "!CHANGELOG!"
echo ================================================================>> "!CHANGELOG!"
echo.>> "!CHANGELOG!"
echo NOTE: Security-improving changes the script recommends applying>> "!CHANGELOG!"
echo are NOT tracked here -- only changes the script made automatically.>> "!CHANGELOG!"
echo.>> "!CHANGELOG!"

set "REPORT=%OUTDIR%\SecurityReport_!TIMESTAMP!.txt"
set "REPORT_HTML=%OUTDIR%\SecurityReport_!TIMESTAMP!.html"
set "PSRUN=%TEMP%\AuditPS_!TIMESTAMP!.ps1"
set "SCRIPT_CHANGED=0"

:: Locate PowerShell
where powershell >nul 2>&1
if %errorlevel% equ 0 (
    set "PWSH=powershell"
) else (
    if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
        set "PWSH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
    ) else (
        echo [FATAL] PowerShell not found. Cannot continue.
        set "EXIT_CODE=1"
        goto :end_script
    )
)

:: ====================================================================
:: [INIT 2/14] ADMINISTRATOR RIGHTS DETECTION
:: ====================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  %C_BOLD%%C_RED%[FATAL] Must be run as Administrator.%C_RESET%
    echo  Right-click the script and choose "Run as administrator".
    echo.
    set "EXIT_CODE=1"
    goto :end_script
)
echo %C_GREEN%[INIT 2/14]%C_RESET% Administrator privileges: OK

:: ---- Create report header (admin confirmed, report is safe to write) ----
echo ====================================================================>> "%REPORT%"
(echo   WIN11 SECURITY FORENSIC AUDIT  v%SCRIPT_VERSION%)>> "%REPORT%"
echo   Generated : %date%  %time%>> "%REPORT%"
echo   Host      : %COMPUTERNAME%>> "%REPORT%"
echo   User      : %USERNAME%>> "%REPORT%"
echo   Domain    : %USERDOMAIN%>> "%REPORT%"
(echo   Script    : %SCRIPT_PATH%)>> "%REPORT%"
echo   PS Engine : %PWSH%>> "%REPORT%"
(echo   Switches  : Dev=%DEV_MODE%  Resume=%RESUME_MODE%  SkipSRP=%SKIP_SRP%  IsAdmin=1)>> "%REPORT%"
echo ====================================================================>> "%REPORT%"
echo.>> "%REPORT%"
echo  TABLE OF CONTENTS>> "%REPORT%"
echo  ------------------------------------------------------------------>> "%REPORT%"
echo   1. System Identity and Patch Level>> "%REPORT%"
echo   2. User Accounts and Privilege Audit>> "%REPORT%"
echo   3. Network Configuration and Live Connections>> "%REPORT%"
echo   4. Running Processes>> "%REPORT%"
echo   5. Startup and Persistence Mechanisms>> "%REPORT%"
echo   6. Scheduled Tasks>> "%REPORT%"
echo   7. Windows Services Audit>> "%REPORT%"
echo   8. Windows Firewall Configuration>> "%REPORT%"
echo   9. Windows Defender and AV Status>> "%REPORT%"
echo  10. SMB, RDP and Remote Access>> "%REPORT%"
echo  11. PowerShell Security Configuration>> "%REPORT%"
echo  12. Credential Protection and LSASS Hardening>> "%REPORT%"
echo  13. System Hardening Configuration>> "%REPORT%"
echo  14. Suspicious Files and File System Anomalies>> "%REPORT%"
echo  15. Installed Software and Driver Audit>> "%REPORT%"
echo  16. Windows Event Log Anomalies>> "%REPORT%"
echo  17. Nation-State Threat Indicators>> "%REPORT%"
echo  18. CTI-Driven IOC Sweep (SENTINEL-X)>> "%REPORT%"
echo  ------------------------------------------------------------------>> "%REPORT%"
echo.>> "%REPORT%"

echo %C_BOLD%%C_WHITE%[*] %SCRIPT_NAME% v%SCRIPT_VERSION% starting...%C_RESET%
echo %C_DIM%[*] Report: %REPORT%%C_RESET%
echo.

:: ====================================================================
:: [INIT 3/14] WINDOWS AND IE VERSION DETECTION
:: ====================================================================
echo %C_GREEN%[INIT 3/14]%C_RESET% Detecting Windows and IE version...
echo ====================================================================>> "%REPORT%"
echo  PRE-FLIGHT INITIALIZATION>> "%REPORT%"
echo ====================================================================>> "%REPORT%"
echo.>> "%REPORT%"
echo --- [INIT 3/14] Windows and IE Version Detection --->> "%REPORT%"

for /f "tokens=2 delims==" %%a in ('wmic os get BuildNumber /value 2^>nul') do (
    if not "%%a"=="" set "OS_BUILD=%%a"
)
for /f "tokens=2 delims==" %%a in ('wmic os get Version /value 2^>nul') do (
    if not "%%a"=="" set "OS_VER=%%a"
)
for /f "tokens=2 delims==" %%a in ('wmic os get ProductType /value 2^>nul') do (
    if not "%%a"=="" set "OS_PTYPE=%%a"
)
:: Strip trailing whitespace / carriage returns
set "OS_BUILD=%OS_BUILD: =%"
set "OS_PTYPE=%OS_PTYPE: =%"

:: IE version - try svcVersion first, then Version key
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Internet Explorer" /v svcVersion 2^>nul') do set "IE_VER=%%a"
if "%IE_VER%"=="unknown" (
    for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Internet Explorer" /v Version 2^>nul') do set "IE_VER=%%a"
)

:: Classify Windows generation for conditional command selection
if %OS_BUILD% GEQ 22000                                   set "WIN_GEN=Win11"
if %OS_BUILD% GEQ 10240 if %OS_BUILD% LSS 22000           set "WIN_GEN=Win10"
if %OS_BUILD% GEQ 9600  if %OS_BUILD% LSS 10240           set "WIN_GEN=Win8.1"
if %OS_BUILD% GEQ 9200  if %OS_BUILD% LSS 9600            set "WIN_GEN=Win8"
if %OS_BUILD% GEQ 7600  if %OS_BUILD% LSS 9200            set "WIN_GEN=Win7"

(echo Windows Generation : %WIN_GEN%)>> "%REPORT%"
(echo Windows Build      : %OS_BUILD%)>> "%REPORT%"
(echo Windows Version    : %OS_VER%)>> "%REPORT%"
echo Product Type       : %OS_PTYPE%  (1=Client/Workstation  2=DomainController  3=Server)>> "%REPORT%"
echo IE Version         : %IE_VER%  (legacy ref only - Edge is primary browser on Win10/11)>> "%REPORT%"
echo.>> "%REPORT%"
echo %C_GREEN%[INIT 3/14]%C_RESET% %WIN_GEN% Build %OS_BUILD%  IE %IE_VER%  ProductType %OS_PTYPE%

:: ====================================================================
:: [INIT 4/14] UNSUPPORTED OS CHECK (Exit code 3)
:: ====================================================================
echo %C_GREEN%[INIT 4/14]%C_RESET% Checking OS compatibility...
echo --- [INIT 4/14] OS Compatibility Check --->> "%REPORT%"
set "OS_BLOCK_REASON="

if "%OS_PTYPE%"=="2" set "OS_BLOCK_REASON=Domain Controller (ProductType 2)"
if "%OS_PTYPE%"=="3" set "OS_BLOCK_REASON=Server OS (ProductType 3) - many checks behave differently on Server"
if "%WIN_GEN%"=="Win7"  set "OS_BLOCK_REASON=Windows 7 (EOL - missing commands used by this script)"
if "%WIN_GEN%"=="Win8"  set "OS_BLOCK_REASON=Windows 8 (EOL)"
if "%WIN_GEN%"=="unknown" set "OS_BLOCK_REASON=Unrecognised Windows version (Build %OS_BUILD%)"

if "%OS_BLOCK_REASON%"=="" goto :os_check_passed

echo  [UNSUPPORTED] %OS_BLOCK_REASON%>> "%REPORT%"
if "%DEV_MODE%"=="1" (
    echo  [WARNING] Unsupported OS: %OS_BLOCK_REASON%>> "%REPORT%"
    echo  [WARNING] -dev override active. Continuing on unsupported OS.>> "%REPORT%"
    echo  [WARNING] Some checks may fail or return incorrect results.>> "%REPORT%"
    echo %C_GREEN%[INIT 4/14]%C_RESET% WARN: %OS_BLOCK_REASON% -- -dev override active, continuing.
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    goto :os_check_passed
)
echo.
echo  %C_RED%[EXIT 3]%C_RESET% Unsupported OS detected: %OS_BLOCK_REASON%
echo  This script targets Windows 10 and Windows 11 client editions.
echo  Use the -dev switch to run anyway on unsupported versions.
echo  Example:  WIN11_SecurityAudit.bat -dev
echo.
echo  [BLOCKED] Use -dev to override. Exiting.>> "%REPORT%"
set "EXIT_CODE=3"
goto :end_script
:os_check_passed
(echo  [OK] OS supported: %WIN_GEN% Build %OS_BUILD%)>> "%REPORT%"
echo %C_GREEN%[INIT 4/14]%C_RESET% OS check: OK (%WIN_GEN%)
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 5/14] SAFE MODE DETECTION
:: ====================================================================
echo %C_GREEN%[INIT 5/14]%C_RESET% Detecting boot mode...
echo --- [INIT 5/14] Safe Mode Detection --->> "%REPORT%"
echo  Command: wmic computersystem get BootupState /value ^| findstr /i "safe">> "%REPORT%"
wmic computersystem get BootupState /value 2>nul | findstr /i "safe" >nul 2>&1
if %errorlevel% equ 0 (
    set "SAFE_MODE=1"
    echo  [INFO] Running in Safe Mode.>> "%REPORT%"
    echo  System Restore Point creation not supported in Safe Mode.>> "%REPORT%"
    echo  This is a known Windows 10 bug with no workaround. Use normal mode for SRP.>> "%REPORT%"
    echo %C_GREEN%[INIT 5/14]%C_RESET% Safe Mode: YES - SRP skipped due to Win10 bug
) else (
    echo  [OK] Normal mode boot.>> "%REPORT%"
    echo %C_GREEN%[INIT 5/14]%C_RESET% Safe Mode: No - normal boot
)
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 6/14] LOG DIRECTORY CREATION
:: ====================================================================
echo --- [INIT 6/14] Log Directories --->> "%REPORT%"
echo  Report    : %REPORT%>> "%REPORT%"
echo  HTML Report: %REPORT_HTML%>> "%REPORT%"
echo  SMART data: %OUTDIR%\SmartData>> "%REPORT%"
echo  Event logs: %OUTDIR%\EventExports>> "%REPORT%"
echo  Threat IPs: %OUTDIR%\ThreatLists>> "%REPORT%"
echo.>> "%REPORT%"
echo %C_GREEN%[INIT 6/14]%C_RESET% Log dirs: %OUTDIR%

:: ====================================================================
:: [INIT 7/14] DETECT RESUME FROM PREVIOUS RUN
:: ====================================================================
echo %C_GREEN%[INIT 7/14]%C_RESET% Checking for previous interrupted run...
echo --- [INIT 7/14] Resume Detection --->> "%REPORT%"
if "%RESUME_MODE%"=="1" (
    echo  [RESUME] Resuming interrupted run. Pre-flight steps 8-14 skipped.>> "%REPORT%"
    echo  SRP, update checks, F8, SMART were completed in the previous run.>> "%REPORT%"
    echo.>> "%REPORT%"
    echo %C_GREEN%[INIT 7/14]%C_RESET% RESUME mode active - jumping to audit sections.
    goto :preflight_complete
)
echo  [OK] Fresh run detected. No interrupted session found.>> "%REPORT%"
echo.>> "%REPORT%"
echo %C_GREEN%[INIT 7/14]%C_RESET% Fresh run. Proceeding with full pre-flight.

:: ====================================================================
:: [INIT 8/14] CREATE RUNONCE RESUME ENTRY
:: ====================================================================
echo %C_GREEN%[INIT 8/14]%C_RESET% Creating RunOnce resume entry...
echo --- [INIT 8/14] RunOnce Resume Key --->> "%REPORT%"
echo  Command: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "*%SCRIPT_NAME%_resume" /t REG_SZ /d "\"%~f0\" -resume" /f>> "%REPORT%"
echo  If this run is interrupted (reboot/crash), Windows will automatically>> "%REPORT%"
echo  re-run the script with the -resume switch on next login.>> "%REPORT%"
echo  Key: HKCU\...\RunOnce  Value: *%SCRIPT_NAME%_resume>> "%REPORT%"
echo  The * prefix forces execution even in Safe Mode.>> "%REPORT%"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "*%SCRIPT_NAME%_resume" /t REG_SZ /d "\"%~f0\" -resume" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] RunOnce key created successfully.>> "%REPORT%"
    echo %C_GREEN%[INIT 8/14]%C_RESET% RunOnce key created - auto-deleted on clean exit.
    echo [TEMPORARY] RunOnce resume key created.>> "%CHANGELOG%"
    echo             Key: HKCU\...\RunOnce\*%SCRIPT_NAME%_resume>> "%CHANGELOG%"
    echo             Status: AUTO-DELETED at end of audit on clean exit.>> "%CHANGELOG%"
    echo             Manual undo if needed: reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "*%SCRIPT_NAME%_resume" /f>> "%CHANGELOG%"
    echo.>> "%CHANGELOG%"
) else (
    echo  [WARNING] Could not create RunOnce key. Resume will not be available.>> "%REPORT%"
    echo %C_GREEN%[INIT 8/14]%C_RESET% RunOnce key creation failed - non-fatal.
)
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 9/14] NETWORK CONNECTIVITY CHECK
:: ====================================================================
echo %C_GREEN%[INIT 9/14]%C_RESET% Checking network connectivity...
echo --- [INIT 9/14] Network Connectivity --->> "%REPORT%"
echo  Command: ping -n 1 -w 2000 8.8.8.8>> "%REPORT%"

ping -n 1 -w 2000 8.8.8.8 >nul 2>&1
if %errorlevel% equ 0 (
    set "NETWORK_AVAIL=1"
    echo  [OK] Network connected - Google DNS reachable.>> "%REPORT%"
    echo %C_GREEN%[INIT 9/14]%C_RESET% Network: Connected
    goto :netcheck_done
)
ping -n 1 -w 2000 1.1.1.1 >nul 2>&1
if %errorlevel% equ 0 (
    set "NETWORK_AVAIL=1"
    echo  [OK] Network connected - Cloudflare DNS reachable.>> "%REPORT%"
    echo %C_GREEN%[INIT 9/14]%C_RESET% Network: Connected via fallback ping
    goto :netcheck_done
)
echo  [INFO] No network detected. Update and threat list checks will be skipped.>> "%REPORT%"
echo %C_GREEN%[INIT 9/14]%C_RESET% Network: Not available. Skipping update checks.
:netcheck_done
echo.>> "%REPORT%"

:: ====================================================================
:: VT SELF-INTEGRITY CHECK
:: Runs when network is up AND ~/.vt_token exists AND -noVtSelf was
:: not passed. Hashes the script-critical binaries (PWSH host, wmic,
:: wevtutil, reg) and queries VirusTotal. Aborts the audit with
:: EXIT_CODE=7 if any are flagged malicious -- a tampered system
:: binary would invalidate every downstream finding.
:: ====================================================================
if "%NETWORK_AVAIL%"=="1" if "%VT_SELF_SKIP%"=="0" if exist "%USERPROFILE%\.vt_token" (
    echo %C_GREEN%[INIT 9/14]%C_RESET% VT integrity check on critical binaries ^(~50s^)...
    echo --- [INIT 9/14] VT Pre-flight Integrity Check --->> "%REPORT%"
    echo  Command: powershell -File tools\vt_self_check.ps1>> "%REPORT%"
    if exist "%SCRIPT_DIR%tools\vt_self_check.ps1" (
        "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\vt_self_check.ps1" -Binaries "%PWSH%","%SystemRoot%\System32\wbem\wmic.exe","%SystemRoot%\System32\wevtutil.exe","%SystemRoot%\System32\reg.exe" >> "%REPORT%" 2>&1
        rem PS script exit codes: 0=clean, 1=MALICIOUS (HARD FAIL), 2=skipped/error.
        rem Use delayed expansion since we are inside a parenthesized block;
        rem percent-errorlevel-percent would expand at block-parse time, not runtime.
        if !errorlevel! equ 1 (
            echo  [CRITICAL] Pre-flight VT integrity check FAILED -- script-critical binary flagged.>> "%REPORT%"
            echo  [CRITICAL] Aborting audit. See report for details.>> "%REPORT%"
            echo %C_RED%[CRITICAL]%C_RESET% Script-critical binary flagged by VirusTotal. Audit aborted.
            echo %C_RED%[CRITICAL]%C_RESET% See %REPORT% for the offending hash and engine count.
            set "EXIT_CODE=7"
            goto :final_exit
        )
    ) else (
        echo  [INFO] vt_self_check.ps1 not found at "%SCRIPT_DIR%tools\vt_self_check.ps1">> "%REPORT%"
        echo  [INFO] Pre-flight VT integrity check skipped. To enable, ensure the>> "%REPORT%"
        echo         tools folder ships alongside doze_sec.bat ^(both must live in>> "%REPORT%"
        echo         the same directory^), then re-run.>> "%REPORT%"
    )
    echo.>> "%REPORT%"
)

:: ====================================================================
:: [INIT 10/14] SELF-UPDATE CHECK
:: ====================================================================
echo %C_GREEN%[INIT 10/14]%C_RESET% Checking for script updates...
echo --- [INIT 10/14] Self-Update Check --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path -LiteralPath $tf^){ $token = ^(Get-Content -LiteralPath $tf -Raw -EA SilentlyContinue^).Trim^(^) } }">> "%REPORT%"

if "%NETWORK_AVAIL%"=="0" (
    echo  [SKIP] No network available.>> "%REPORT%"
    echo %C_GREEN%[INIT 10/14]%C_RESET% Skipped - no network available.
    goto :update_done
)

:: Detect unconfigured placeholder URL and skip silently
echo %UPDATE_URL% | findstr /c:"YOURUSERNAME" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [SKIP] UPDATE_URL not configured. Set it at the top of this script.>> "%REPORT%"
    echo %C_GREEN%[INIT 10/14]%C_RESET% Update URL not configured - set UPDATE_URL at top of script.
    goto :update_done
)

echo  Fetching remote version from: %UPDATE_URL%/version.txt>> "%REPORT%"
echo $localVer='%SCRIPT_VERSION%' > "%PSRUN%"
echo $remoteUrl='%UPDATE_URL%/version.txt' >> "%PSRUN%"
:: Load GitHub PAT for private repo access. Priority: env var -^> token file.
:: To set: $env:DOZESEC_TOKEN = 'github_pat_xxx'  or write PAT to %USERPROFILE%\.dozesec_token
echo $token = $env:DOZESEC_TOKEN >> "%PSRUN%"
echo if(-not $token){ $tf = Join-Path $env:USERPROFILE '.dozesec_token'; if(Test-Path -LiteralPath $tf){ $token = (Get-Content -LiteralPath $tf -Raw -EA SilentlyContinue).Trim() } } >> "%PSRUN%"
echo $headers = @{ 'User-Agent' = 'doze_sec' } >> "%PSRUN%"
echo if($token){ $headers['Authorization'] = "Bearer $token" } >> "%PSRUN%"
echo try { >> "%PSRUN%"
echo   $remoteVer=(Invoke-WebRequest $remoteUrl -UseBasicParsing -TimeoutSec 10 -Headers $headers -EA Stop).Content.Trim() >> "%PSRUN%"
echo   Write-Output ('  Remote version : '+$remoteVer) >> "%PSRUN%"
echo   Write-Output ('  Local version  : '+$localVer) >> "%PSRUN%"
echo   $rv = $remoteVer -replace '[^^0-9.]','' >> "%PSRUN%"
echo   $lv = $localVer -replace '[^^0-9.]','' >> "%PSRUN%"
echo   $rv = $rv.Trim('.'); $lv = $lv.Trim('.') >> "%PSRUN%"
echo   if([version]$rv -gt [version]$lv) { >> "%PSRUN%"
echo     Write-Output '[UPDATE AVAILABLE] A newer version exists. Download from:' >> "%PSRUN%"
echo     Write-Output ('  %UPDATE_URL%/%SCRIPT_NAME%.bat') >> "%PSRUN%"
echo     Write-Output 'Verify SHA256 hash after downloading before running.' >> "%PSRUN%"
echo   } else { >> "%PSRUN%"
echo     Write-Output '[OK] Script is current (no update required).' >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } catch { >> "%PSRUN%"
echo   $sc=$null; try{ $sc=[int]$_.Exception.Response.StatusCode }catch{} >> "%PSRUN%"
echo   if($sc -eq 401){ Write-Output '  [INFO] Update check: authentication failed (HTTP 401). GitHub PAT is invalid, expired, or lacks Contents:Read on this repo.' } >> "%PSRUN%"
echo   elseif($sc -eq 403){ Write-Output '  [INFO] Update check: forbidden (HTTP 403). Token may be rate-limited or scope-restricted.' } >> "%PSRUN%"
echo   elseif($sc -eq 404 -and $token){ Write-Output '  [INFO] Update check: 404 even with token. PAT does not grant access to this repo; verify it is scoped to kj299/doze_sec.' } >> "%PSRUN%"
echo   elseif($sc -eq 404){ Write-Output '  [INFO] Update check: 404 (repo is private and no GitHub PAT found). Set $env:DOZESEC_TOKEN or write PAT to %USERPROFILE%\.dozesec_token. Self-update disabled; this is not a scan failure.' } >> "%PSRUN%"
echo   elseif($sc){ Write-Output ('  [INFO] Update check failed (HTTP '+$sc+'): '+$_.Exception.Message) } >> "%PSRUN%"
echo   else{ Write-Output ('  [INFO] Update check failed: '+$_.Exception.Message) } >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%"

:: Threat intel list update (use -sdu to skip)
if "%SKIP_THREAT_UPDATE%"=="1" (
    echo  [SKIP] Threat list update skipped via -sdu switch.>> "%REPORT%"
    goto :update_done
)
echo  Checking for updated threat indicator lists...>> "%REPORT%"
echo  Mode: INCREMENTAL (new entries merged, existing preserved)>> "%REPORT%"
echo $baseUrl='%UPDATE_URL%/ThreatLists' > "%PSRUN%"
echo $localDir='%SCRIPT_DIR%ThreatLists' >> "%PSRUN%"
echo $files=@('ioc_processes.txt','ioc_named_pipes.txt','ioc_services.txt','ioc_registry.txt','ioc_file_paths.txt','ioc_scheduled_tasks.txt','ioc_domains.txt','ioc_hashes.txt','ioc_lolbins.txt','ttp_manifest.txt') >> "%PSRUN%"
echo $token = $env:DOZESEC_TOKEN >> "%PSRUN%"
echo if(-not $token){ $tf = Join-Path $env:USERPROFILE '.dozesec_token'; if(Test-Path -LiteralPath $tf){ $token = (Get-Content -LiteralPath $tf -Raw -EA SilentlyContinue).Trim() } } >> "%PSRUN%"
echo $headers = @{ 'User-Agent' = 'doze_sec' } >> "%PSRUN%"
echo if($token){ $headers['Authorization'] = "Bearer $token" } >> "%PSRUN%"
echo $updated=0; $skipped=0 >> "%PSRUN%"
echo foreach($f in $files){ >> "%PSRUN%"
echo   $url="$baseUrl/$f"; $dest=Join-Path $localDir $f >> "%PSRUN%"
echo   try{ >> "%PSRUN%"
echo     $remote=Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 10 -Headers $headers -EA Stop >> "%PSRUN%"
echo     $newLines=$remote.Content -split "`n" ^| ForEach-Object {$_.Trim()} ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo     if(Test-Path $dest){ >> "%PSRUN%"
echo       $existing=Get-Content $dest ^| ForEach-Object {$_.Trim()} ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo       $added=0 >> "%PSRUN%"
echo       foreach($line in $newLines){ >> "%PSRUN%"
echo         if($existing -notcontains $line){ >> "%PSRUN%"
echo           Add-Content $dest "# Added by -updateTTP on $(Get-Date -Format yyyy-MM-dd)" >> "%PSRUN%"
echo           Add-Content $dest $line >> "%PSRUN%"
echo           $added++ >> "%PSRUN%"
echo         } >> "%PSRUN%"
echo       } >> "%PSRUN%"
echo       if($added -gt 0){'  [OK] '+$f+': '+$added+' new entries merged'; $updated++} >> "%PSRUN%"
echo       else{'  [OK] '+$f+': already up to date'; $skipped++} >> "%PSRUN%"
echo     }else{ >> "%PSRUN%"
echo       [System.IO.File]::WriteAllText($dest,$remote.Content,(New-Object System.Text.UTF8Encoding $false)) >> "%PSRUN%"
echo       '  [OK] '+$f+': downloaded (new file)'; $updated++ >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   }catch{'  [INFO] '+$f+': not available at remote URL'; $skipped++} >> "%PSRUN%"
echo } >> "%PSRUN%"
echo "  Summary: $updated files updated, $skipped unchanged/unavailable" >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
:update_done
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 11/14] ENABLE F8 SAFE MODE SELECTION
:: ====================================================================
echo %C_GREEN%[INIT 11/14]%C_RESET% Re-enabling F8 Safe Mode selection...
echo --- [INIT 11/14] F8 Boot Menu --->> "%REPORT%"
echo  Command: bcdedit /enum {bootmgr}>> "%REPORT%"
echo  Re-enables the F8 key during boot for Safe Mode access.>> "%REPORT%"
echo  Enabled by default on Win7 and Server 2012/2012 R2.>> "%REPORT%"
echo  Disabled by default on Windows 8 and later (by design for fast boot).>> "%REPORT%"

if "%WIN_GEN%"=="Win7" (
    echo  [SKIP] Win7 - F8 is already enabled by default.>> "%REPORT%"
    echo %C_GREEN%[INIT 11/14]%C_RESET% Skipped - Win7 F8 already enabled by default.
    goto :f8_done
)

:: Capture current bcdedit state BEFORE making any changes
set "PREV_BOOTMENU=absent"
set "PREV_TIMEOUT=absent"
bcdedit /enum {bootmgr} 2>nul > "%TEMP%\bcd_snap_%TIMESTAMP%.txt"
if exist "%TEMP%\bcd_snap_%TIMESTAMP%.txt" (
    for /f "tokens=2" %%a in ('findstr /i "displaybootmenu" "%TEMP%\bcd_snap_%TIMESTAMP%.txt"') do set "PREV_BOOTMENU=%%a"
    for /f "tokens=2" %%a in ('findstr /i "^timeout" "%TEMP%\bcd_snap_%TIMESTAMP%.txt"') do set "PREV_TIMEOUT=%%a"
    del "%TEMP%\bcd_snap_%TIMESTAMP%.txt" >nul 2>&1
)

bcdedit /set {bootmgr} displaybootmenu yes >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] Boot menu re-enabled - bcdedit displaybootmenu=yes.>> "%REPORT%"
    echo  [CHANGED] Was: displaybootmenu=%PREV_BOOTMENU%  Now: yes>> "%REPORT%"
    bcdedit /timeout 5 >nul 2>&1
    echo  [OK] Boot timeout set to 5 seconds.>> "%REPORT%"
    (echo  [CHANGED] Was: timeout=%PREV_TIMEOUT%  Now: 5)>> "%REPORT%"
    echo %C_GREEN%[INIT 11/14]%C_RESET% F8 boot menu re-enabled - 5 second timeout set.

    :: Log the changes
    echo [CHANGED] bcdedit {bootmgr} displaybootmenu: was "%PREV_BOOTMENU%" -- set to "yes">> "%CHANGELOG%"
    echo [CHANGED] bcdedit {bootmgr} timeout: was "%PREV_TIMEOUT%" -- set to "5">> "%CHANGELOG%"
    echo.>> "%CHANGELOG%"
    set "SCRIPT_CHANGED=1"

    :: Write undo commands
    echo echo Restoring boot menu settings...>> "%UNDO_BAT%"
    if "%PREV_BOOTMENU%"=="absent" (
        echo bcdedit /deletevalue {bootmgr} displaybootmenu>> "%UNDO_BAT%"
    ) else (
        echo bcdedit /set {bootmgr} displaybootmenu %PREV_BOOTMENU%>> "%UNDO_BAT%"
    )
    if "%PREV_TIMEOUT%"=="absent" (
        echo bcdedit /deletevalue {bootmgr} timeout>> "%UNDO_BAT%"
    ) else (
        (echo bcdedit /timeout %PREV_TIMEOUT%)>> "%UNDO_BAT%"
    )
    echo echo Boot menu settings restored.>> "%UNDO_BAT%"
    echo.>> "%UNDO_BAT%"
) else (
    echo  [WARNING] Could not set displaybootmenu. May already be set or bcdedit restricted.>> "%REPORT%"
    echo %C_GREEN%[INIT 11/14]%C_RESET% F8 re-enable returned non-zero - non-fatal.
)
:f8_done
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 12/14] SYSTEM RESTORE POINT
:: ====================================================================
echo %C_GREEN%[INIT 12/14]%C_RESET% Creating System Restore Point...
echo --- [INIT 12/14] System Restore Point --->> "%REPORT%"
(echo  Description: Pre-WIN11-Security-Audit-v%SCRIPT_VERSION%)>> "%REPORT%"
echo  Note: Vista and later ONLY. Client OS ONLY. Not supported on Server.>> "%REPORT%"
echo  Known Win10 bug: SRP creation FAILS in Safe Mode with no workaround.>> "%REPORT%"
echo  If you require a restore point, always run this script in Normal mode.>> "%REPORT%"

if "%SKIP_SRP%"=="1" (
    echo  [SKIP] -nosrp switch active.>> "%REPORT%"
    echo %C_GREEN%[INIT 12/14]%C_RESET% SRP skipped via -nosrp switch.
    goto :srp_done
)
if "%SAFE_MODE%"=="1" (
    echo  [SKIP] In Safe Mode - SRP not possible. Win10 known bug with no workaround.>> "%REPORT%"
    echo %C_GREEN%[INIT 12/14]%C_RESET% SRP skipped - Safe Mode Windows 10 known bug.
    goto :srp_done
)
if "%OS_PTYPE%" NEQ "1" (
    echo  [SKIP] Server or Domain Controller OS - SRP not supported.>> "%REPORT%"
    echo %C_GREEN%[INIT 12/14]%C_RESET% SRP skipped - Server or DC OS not supported.
    goto :srp_done
)
if "%WIN_GEN%"=="Win7" (
    echo  [SKIP] Skipped on Win7 - use built-in System Restore manually.>> "%REPORT%"
    echo %C_GREEN%[INIT 12/14]%C_RESET% SRP skipped - Win7, use built-in System Restore manually.
    goto :srp_done
)

echo  Creating... (can take 30-60 seconds)
echo Try { > "%PSRUN%"
echo   Enable-ComputerRestore -Drive "$env:SystemDrive\" -EA SilentlyContinue >> "%PSRUN%"
echo   Checkpoint-Computer -Description "Pre-WIN11-Security-Audit-v%SCRIPT_VERSION%" -RestorePointType "MODIFY_SETTINGS" -EA Stop >> "%PSRUN%"
echo   Write-Output "  [OK] System Restore Point created successfully." >> "%PSRUN%"
echo } Catch { >> "%PSRUN%"
echo   Write-Output ("  [WARN] SRP failed: "+$_.Exception.Message) >> "%PSRUN%"
echo   Write-Output "       To fix: Control Panel ^> System ^> System Protection ^> Configure ^> Enable" >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: Log SRP to changelog (SRP is a safety net -- cannot be undone but is always desirable)
echo [CREATED] System Restore Point: "Pre-WIN11-Security-Audit-v%SCRIPT_VERSION%">> "%CHANGELOG%"
echo           This is a safety net -- it lets you roll back any changes made AFTER this point.>> "%CHANGELOG%"
echo           Undo (if desired): Control Panel ^> System ^> System Protection ^> System Restore>> "%CHANGELOG%"
(echo           Select the restore point named Pre-WIN11-Security-Audit-v%SCRIPT_VERSION%)>> "%CHANGELOG%"
echo           NOTE: This is intentional and recommended. Only remove it if you are certain.>> "%CHANGELOG%"
echo.>> "%CHANGELOG%"
set "SCRIPT_CHANGED=1"
:srp_done
echo.>> "%REPORT%"

:: ====================================================================
:: [INIT 13/14] DISK CONFIGURATION AND FREE SPACE
:: ====================================================================
echo %C_GREEN%[INIT 13/14]%C_RESET% Checking disk configuration and available space...
echo --- [INIT 13/14] Disk Configuration --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue">> "%REPORT%"
echo  Determines: SSD/HDD/VM/error. Sets SKIP_DEFRAG flag accordingly.>> "%REPORT%"
echo  SKIP_DEFRAG values: no=HDD, yes_ssd=SSD, yes_vm=VirtualDisk, yes_error=SmartCTL error>> "%REPORT%"

:: VM detection
echo $cs=Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue > "%PSRUN%"
echo if($cs) { >> "%PSRUN%"
echo   Write-Output ('Manufacturer: '+$cs.Manufacturer+'  Model: '+$cs.Model) >> "%PSRUN%"
echo   if($cs.Manufacturer -match 'VMware^|QEMU^|Xen^|Bochs^|Parallels^|innotek' -or $cs.Model -match 'Virtual^|VMware^|VirtualBox^|KVM^|HVM domU') { >> "%PSRUN%"
echo     Write-Output '[VM DETECTED] Running inside a virtual machine. Defrag will be skipped.' >> "%PSRUN%"
echo   } else { >> "%PSRUN%"
echo     Write-Output '[OK] Physical hardware (not a known VM hypervisor).' >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: Get a single word output to set SKIP_DEFRAG variable in cmd
echo $cs=Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue > "%PSRUN%"
echo if($cs -and ($cs.Manufacturer -match 'VMware^|QEMU^|Xen^|Bochs^|Parallels^|innotek' -or $cs.Model -match 'Virtual^|VMware^|VirtualBox^|KVM^|HVM domU')){'yes_vm'}else{'no'} >> "%PSRUN%"
for /f "usebackq" %%a in (`%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2^>nul`) do set "VM_CHECK=%%a"
if /i "%VM_CHECK%"=="yes_vm" set "SKIP_DEFRAG=yes_vm"

:: SSD detection
echo $d=Get-PhysicalDisk -EA SilentlyContinue ^| Where-Object {$_.MediaType -eq 'SSD'} > "%PSRUN%"
echo if($d){'yes_ssd'}else{'no'} >> "%PSRUN%"
for /f "usebackq" %%a in (`%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2^>nul`) do set "SSD_CHECK=%%a"
if /i "%SSD_CHECK%"=="yes_ssd" set "SKIP_DEFRAG=yes_ssd"

echo.>> "%REPORT%"
echo Disk type flag: SKIP_DEFRAG=%SKIP_DEFRAG%>> "%REPORT%"
echo  no=HDD (defrag OK)  yes_ssd=SSD (skip defrag)  yes_vm=VM (skip defrag)>> "%REPORT%"

:: Disk detail report
echo.>> "%REPORT%"
echo --- Physical Disk Details --->> "%REPORT%"
echo  Command: powershell -Command "Get-PhysicalDisk -EA SilentlyContinue">> "%REPORT%"
echo $pd=Get-PhysicalDisk -EA SilentlyContinue > "%PSRUN%"
echo if($pd){ >> "%PSRUN%"
echo   $pd ^| Select-Object FriendlyName,MediaType,BusType,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},OperationalStatus,HealthStatus ^| Format-Table -AutoSize >> "%PSRUN%"
echo } else { >> "%PSRUN%"
echo   Get-CimInstance Win32_DiskDrive ^| Select-Object Model,MediaType,Status,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} ^| Format-Table -AutoSize >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Free Space on System Drive Before Audit --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='%SystemDrive%'" -EA SilentlyContinue^).FreeSpace">> "%REPORT%"
:: Primary: PowerShell Get-CimInstance (works on all Win10/11 including 24H2+)
echo (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='%SystemDrive%'" -EA SilentlyContinue).FreeSpace > "%PSRUN%"
for /f "usebackq" %%a in (`%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2^>nul`) do (
    if not "%%a"=="" if not "%%a"=="0" set "FREE_BEFORE=%%a"
)
:: Fallback: wmic (for older systems where CIM may not be available)
if not "%FREE_BEFORE%"=="0" goto :freebefore_done
for /f "tokens=2 delims==" %%a in ('wmic logicaldisk where "DeviceID=^'%SystemDrive%^'" get FreeSpace /value 2^>nul') do (
    if not "%%a"=="" set "FREE_BEFORE=%%a"
)
set "FREE_BEFORE=%FREE_BEFORE: =%"
:freebefore_done
echo System drive: %SystemDrive%>> "%REPORT%"
echo Free space  : %FREE_BEFORE% bytes>> "%REPORT%"
echo.>> "%REPORT%"
echo %C_GREEN%[INIT 13/14]%C_RESET% Disk: SKIP_DEFRAG=%SKIP_DEFRAG%  Free: %FREE_BEFORE% bytes

:: ====================================================================
:: [INIT 14/14] SMART DISK HEALTH CHECK
:: ====================================================================
echo %C_GREEN%[INIT 14/14]%C_RESET% Running SMART disk health check...
echo ====================================================================>> "%REPORT%"
echo  [INIT 14/14] SMART DISK HEALTH CHECK>> "%REPORT%"
echo  Alert statuses: Error, Degraded, Unknown, PredFail, Service,>> "%REPORT%"
echo                  Stressed, NonRecover, Unhealthy, Warning, FAILED>> "%REPORT%"
echo  smartctl (smartmontools) used if installed; WMI used as fallback.>> "%REPORT%"
echo  Install smartmontools for richer SMART attribute data:>> "%REPORT%"
echo    https://www.smartmontools.org/wiki/Download>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

:: Locate smartctl.exe
if exist "%ProgramFiles%\smartmontools\bin\smartctl.exe"       set "SMARTCTL_PATH=%ProgramFiles%\smartmontools\bin\smartctl.exe"
if exist "%ProgramFiles(x86)%\smartmontools\bin\smartctl.exe"  set "SMARTCTL_PATH=%ProgramFiles(x86)%\smartmontools\bin\smartctl.exe"
if exist "%SCRIPT_DIR%smartctl.exe"                            set "SMARTCTL_PATH=%SCRIPT_DIR%smartctl.exe"
where smartctl.exe >nul 2>&1
if %errorlevel% equ 0 (
    for /f %%p in ('where smartctl.exe 2^>nul') do set "SMARTCTL_PATH=%%p"
)

:: Dispatch to native or WMI path via call -- avoids a "goto :smart_wmi_fallback"
:: pattern that crashed on some Windows builds with "system cannot find the batch
:: label specified". The if/else body holds only `call :label` (single token, no
:: bare parens) so it parses cleanly; the subroutines stay at top-level scope so
:: their existing heredocs with bare parens like `($disk in $d)` remain valid.
if "%SMARTCTL_PATH%"=="" (
    call :_smart_wmi_run
) else (
    call :_smart_native_run
)
goto :smart_done

:_smart_native_run
echo --- smartctl SMART Report --->> "%REPORT%"
echo  Command: "%SMARTCTL_PATH%" --scan>> "%REPORT%"
echo Using: %SMARTCTL_PATH%>> "%REPORT%"
"%SMARTCTL_PATH%" --scan 2>nul>> "%REPORT%"
echo.>> "%REPORT%"

:: Run on each physical drive 0-7; smartctl exits non-zero if drive bad
for /l %%n in (0,1,7) do (
    "%SMARTCTL_PATH%" -i -H "\\.\PhysicalDrive%%n" > "%OUTDIR%\SmartData\Drive%%n_%TIMESTAMP%.txt" 2>nul
    if exist "%OUTDIR%\SmartData\Drive%%n_%TIMESTAMP%.txt" (
        echo --- PhysicalDrive%%n --->> "%REPORT%"
        echo  Command: type "%OUTDIR%\SmartData\Drive%%n_%TIMESTAMP%.txt">> "%REPORT%"
        type "%OUTDIR%\SmartData\Drive%%n_%TIMESTAMP%.txt">> "%REPORT%"
        type "%OUTDIR%\SmartData\Drive%%n_%TIMESTAMP%.txt" 2>nul | findstr /i /c:"FAILED" /c:"Error" /c:"Degraded" /c:"PredFail" >nul 2>&1
        if !errorlevel! equ 0 (
            echo [WARNING] SMART failure status on PhysicalDrive%%n - BACK UP DATA NOW>> "%REPORT%"
            set "SMART_WARN=1"
        )
    )
)
goto :eof

:_smart_wmi_run
echo --- WMI Disk Health (smartctl not found - WMI fallback) --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_DiskDrive -EA SilentlyContinue">> "%REPORT%"
echo For full SMART attribute data install smartmontools.>> "%REPORT%"
echo.>> "%REPORT%"
echo $warn=$false > "%PSRUN%"
echo $d=Get-CimInstance Win32_DiskDrive -EA SilentlyContinue >> "%PSRUN%"
echo foreach($disk in $d) { >> "%PSRUN%"
echo   $gb=[math]::Round($disk.Size/1GB,1) >> "%PSRUN%"
echo   Write-Output ('Drive: '+$disk.Model+'  Size: '+$gb+'GB  Status: '+$disk.Status) >> "%PSRUN%"
echo   if($disk.Status -and $disk.Status -notmatch '^OK$') { >> "%PSRUN%"
echo     $warn=$true >> "%PSRUN%"
echo     Write-Output ('[WARNING] '+$disk.Model+' reports status: '+$disk.Status) >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo try { >> "%PSRUN%"
echo   $pd=Get-PhysicalDisk -EA Stop >> "%PSRUN%"
echo   $pd ^| Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus ^| Format-Table -AutoSize >> "%PSRUN%"
echo   $bad=$pd ^| Where-Object {$_.HealthStatus -ne 'Healthy'} >> "%PSRUN%"
echo   if($bad) { >> "%PSRUN%"
echo     $warn=$true >> "%PSRUN%"
echo     Write-Output '[WARNING] Unhealthy physical disk detected. Check above for details.' >> "%PSRUN%"
echo   } else { >> "%PSRUN%"
echo     Write-Output '[OK] All physical disks report Healthy status.' >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } catch {} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: Capture WMI health status for SMART_WARN flag
echo $d=Get-CimInstance Win32_DiskDrive -EA SilentlyContinue > "%PSRUN%"
echo $bad=$d ^| Where-Object {$_.Status -and $_.Status -notmatch '^OK$'} >> "%PSRUN%"
echo try { >> "%PSRUN%"
echo   $pd=Get-PhysicalDisk -EA Stop >> "%PSRUN%"
echo   $badpd=$pd ^| Where-Object {$_.HealthStatus -ne 'Healthy'} >> "%PSRUN%"
echo   if($bad -or $badpd){'warn'}else{'ok'} >> "%PSRUN%"
echo } catch { if($bad){'warn'}else{'ok'} } >> "%PSRUN%"
for /f "usebackq" %%a in (`%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2^>nul`) do set "WMI_HEALTH=%%a"
if /i "%WMI_HEALTH%"=="warn" set "SMART_WARN=1"
goto :eof

:smart_done
if "%SMART_WARN%"=="1" (
    echo.>> "%REPORT%"
    echo [WARNING] One or more drives report SMART/health failure. Back up data immediately.>> "%REPORT%"
    echo [WARNING] Do not run this script again until drives are replaced or verified.>> "%REPORT%"
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    echo %C_GREEN%[INIT 14/14]%C_RESET% SMART: WARNING - drive health issue detected
) else (
    echo.>> "%REPORT%"
    echo [OK] All drives healthy.>> "%REPORT%"
    echo %C_GREEN%[INIT 14/14]%C_RESET% SMART: All drives healthy
)
echo.>> "%REPORT%"

:: ====================================================================
:: PRE-FLIGHT COMPLETE - Begin security audit sections
:: ====================================================================
:preflight_complete
echo.>> "%REPORT%"
echo ====================================================================>> "%REPORT%"
echo  PRE-FLIGHT COMPLETE - Starting 18-Section Security Audit>> "%REPORT%"
(echo  OS       : %WIN_GEN%  Build %OS_BUILD%  ProductType %OS_PTYPE%)>> "%REPORT%"
(echo  Disk     : SKIP_DEFRAG=%SKIP_DEFRAG%  Free=%FREE_BEFORE% bytes)>> "%REPORT%"
(echo  SafeMode : %SAFE_MODE%   Network: %NETWORK_AVAIL%   Resume: %RESUME_MODE%)>> "%REPORT%"
(echo  Exit code so far: %EXIT_CODE%  [0=clean, 2=warning accumulated])>> "%REPORT%"
echo ====================================================================>> "%REPORT%"
echo.>> "%REPORT%"

echo.
echo %C_BOLD%%C_WHITE%====================================================================
echo  Pre-flight complete. Starting 18-section security audit...%C_RESET%
echo %C_BOLD%%C_WHITE%====================================================================%C_RESET%
echo.

:: ====================================================================
set "SEC1_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[1/18]%C_RESET% Collecting system identity and patch level...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [1/18] SYSTEM IDENTITY AND PATCH LEVEL>> "%REPORT%"
echo  THREAT: Unpatched OS as exploit entry point (T1190)>> "%REPORT%"
echo  MDDR 2023: Forest Blizzard used CVE-2023-23397 (Outlook zero-day)>> "%REPORT%"
echo       and Mulberry Typhoon used CVE-2022-27518. Patch fast.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

systeminfo | findstr /i /c:"OS Name" /c:"OS Version" /c:"System Boot" /c:"Domain" /c:"Logon Server" /c:"Total Physical" /c:"Hotfix">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Last 20 Hotfixes (newest first) --->> "%REPORT%"
echo  Command: powershell -Command "Get-HotFix">> "%REPORT%"
echo Get-HotFix ^| Sort-Object InstalledOn -Descending -EA SilentlyContinue ^| Select-Object -First 20 HotFixID,InstalledOn,Description ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Pending Reboot Check --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'^){$reboot=$true">> "%REPORT%"
echo $reboot=$false > "%PSRUN%"
echo if(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'){$reboot=$true; '[REBOOT PENDING] Windows Update requires a reboot.'} >> "%PSRUN%"
echo if(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'){$reboot=$true; '[REBOOT PENDING] Component Based Servicing pending reboot.'} >> "%PSRUN%"
echo try{ $pnd=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA Stop; if($pnd){$reboot=$true; '[REBOOT PENDING] PendingFileRenameOperations set.' }}catch{} >> "%PSRUN%"
echo if(-not $reboot){'[OK] No pending reboot detected.'} >> "%PSRUN%"
echo if($reboot){ New-Item "$env:TEMP\dz_reboot_needed.txt" -Force ^| Out-Null } >> "%PSRUN%"
del "%TEMP%\dz_reboot_needed.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_reboot_needed.txt" (
    echo [EXIT 4] A reboot is pending. Reboot the system then re-run the audit.>> "%REPORT%"
    echo [EXIT 4] Results may be incomplete until the pending reboot is applied.>> "%REPORT%"
    set "EXIT_CODE=4"
    del "%TEMP%\dz_reboot_needed.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- Windows Update Last Run --->> "%REPORT%"
echo  Command: powershell -Command "try{$r=^(New-Object -ComObject Microsoft.Update.AutoUpdate^).Results; $r ^| Select-Object LastSearchSuccessDate,LastInstallationSuccessDate ^| Format-List}catch{'WU COM object unavailable.'}">> "%REPORT%"
echo try{$r=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results; $r ^| Select-Object LastSearchSuccessDate,LastInstallationSuccessDate ^| Format-List}catch{'WU COM object unavailable.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 1/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC1_PREV_CODE%" (
    echo  [SECTION 1/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 1/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC2_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[2/18]%C_RESET% Auditing user accounts and privileges...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [2/18] USER ACCOUNTS AND PRIVILEGE AUDIT>> "%REPORT%"
echo  THREAT: Hidden backdoor local admin accounts (T1136.001)>> "%REPORT%"
echo  MDDR 2023: Russian and Iranian actors create accounts post-compromise.>> "%REPORT%"
echo       North Korean actors use RMM tools as backup persistent access.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- All Local Users --->> "%REPORT%"
echo  Command: net user>> "%REPORT%"
echo  [INFO] Local user account inventory.>> "%REPORT%"
net user>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Detailed Account Info: LastLogon, PasswordLastSet, SID --->> "%REPORT%"
echo  Command: powershell -Command "Get-LocalUser">> "%REPORT%"
echo  [INFO] Account details for privilege audit.>> "%REPORT%"
echo Get-LocalUser ^| Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,SID ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Local Administrators Group --->> "%REPORT%"
echo  Command: net localgroup administrators>> "%REPORT%"
net localgroup administrators>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Remote Desktop Users Group --->> "%REPORT%"
echo  Command: net localgroup "Remote Desktop Users">> "%REPORT%"
net localgroup "Remote Desktop Users">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Guest Account (must be Disabled) --->> "%REPORT%"
echo  Command: net user guest>> "%REPORT%"
net user guest>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Local Password Policy --->> "%REPORT%"
echo  Command: net accounts>> "%REPORT%"
net accounts>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- All Account SIDs --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_UserAccount -EA SilentlyContinue">> "%REPORT%"
echo Get-CimInstance Win32_UserAccount -EA SilentlyContinue ^| Select-Object Name,SID,Disabled,PasswordExpires,PasswordChangeable ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 2/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC2_PREV_CODE%" (
    echo  [SECTION 2/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 2/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC3_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[3/18]%C_RESET% Scanning network connections and configuration...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [3/18] NETWORK CONFIGURATION AND LIVE CONNECTIONS>> "%REPORT%"
echo  THREAT: C2 beaconing, exfiltration, MITM proxy (T1071)>> "%REPORT%"
echo  MDDR 2023: Volt Typhoon routes C2 through SOHO routers and custom>> "%REPORT%"
echo       VPNs. Match netstat PIDs against Section 4 process list.>> "%REPORT%"
echo       HOSTS tampering redirects domains. Proxy = traffic interception.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Network Adapter Config --->> "%REPORT%"
echo  Command: ipconfig /all>> "%REPORT%"
echo  [INFO] Reference data - review for network anomalies.>> "%REPORT%"
ipconfig /all>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- All TCP/UDP Connections with PIDs --->> "%REPORT%"
echo  Command: netstat -ano>> "%REPORT%"
echo  [INFO] Full connection listing for correlation with process analysis.>> "%REPORT%"
netstat -ano>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- ESTABLISHED Connections --->> "%REPORT%"
echo  Command: netstat -ano ^| findstr /c:"ESTABLISHED">> "%REPORT%"
netstat -ano | findstr /c:"ESTABLISHED">> "%REPORT%" 2>&1
echo  [INFO] Review ESTABLISHED connections against known-good baselines.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- LISTENING Ports --->> "%REPORT%"
echo  Command: netstat -ano ^| findstr /c:"LISTENING">> "%REPORT%"
netstat -ano | findstr /c:"LISTENING">> "%REPORT%" 2>&1
echo  [INFO] Review listening ports for unexpected services.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- DNS Cache (random subdomains = DNS-tunnel C2) --->> "%REPORT%"
echo  Command: ipconfig /displaydns>> "%REPORT%"
echo  [INFO] DNS cache for C2/tunneling analysis.>> "%REPORT%"
ipconfig /displaydns>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- ARP Cache --->> "%REPORT%"
echo  Command: arp -a>> "%REPORT%"
echo  [INFO] ARP table for network device mapping.>> "%REPORT%"
arp -a>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Open Network Shares --->> "%REPORT%"
echo  Command: net share>> "%REPORT%"
echo  [INFO] Network share exposure inventory.>> "%REPORT%"
net share>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Routing Table --->> "%REPORT%"
echo  Command: route print>> "%REPORT%"
echo  [INFO] Routing table for network path analysis.>> "%REPORT%"
route print>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- HOSTS File (SAFE: only 127.0.0.1 and ::1 localhost entries) --->> "%REPORT%"
echo  Command: type "%WINDIR%\System32\drivers\etc\hosts">> "%REPORT%"
type "%WINDIR%\System32\drivers\etc\hosts">> "%REPORT%" 2>&1
type "%WINDIR%\System32\drivers\etc\hosts" 2>nul | findstr /v /r "^#" | findstr /v /r "^$" | findstr /v /c:"127.0.0.1" /c:"::1" | findstr /r "[0-9]" >nul 2>&1
if !errorlevel! equ 0 (
    echo  [WARNING] Non-standard entries found in HOSTS file. Review for DNS hijacking.>> "%REPORT%"
) else (
    echo  [OK] HOSTS file contains only standard entries.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- Proxy Settings --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue">> "%REPORT%"
echo $p=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue > "%PSRUN%"
echo if($p){$pe=if($p.ProxyEnable){'1 [ENABLED]'}else{'0 [DISABLED]'};Write-Output "ProxyEnable : $pe";if($p.ProxyServer){Write-Output "ProxyServer : $($p.ProxyServer)"}else{Write-Output 'ProxyServer : [OK] Not configured'};if($p.AutoConfigURL){Write-Output "AutoConfigURL: $($p.AutoConfigURL)"}else{Write-Output 'AutoConfigURL: [OK] Not configured'}}else{Write-Output '[OK] No proxy settings in registry'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo $p=(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue).ProxyServer > "%PSRUN%"
echo if($p){Write-Output ('HKLM ProxyServer: '+$p)}else{Write-Output 'HKLM ProxyServer: [OK] Not configured'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Saved WiFi Profiles --->> "%REPORT%"
echo  Command: netsh wlan show profiles>> "%REPORT%"
echo  [INFO] Saved wireless network history.>> "%REPORT%"
netsh wlan show profiles>> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 3/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC3_PREV_CODE%" (
    echo  [SECTION 3/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 3/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC4_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[4/18]%C_RESET% Enumerating running processes...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [4/18] RUNNING PROCESSES>> "%REPORT%"
echo  THREAT: Process injection, hollowing, masquerading (T1055)>> "%REPORT%"
echo  MDDR 2023: Volt Typhoon uses LOLBins (native Windows binaries) so>> "%REPORT%"
echo       malware appears as legitimate system tools. Any process from>> "%REPORT%"
echo       Temp, AppData, Downloads, or Public = critical IOC.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- All Processes: PID, PPID, Name, Path --->> "%REPORT%"
echo  Command: powershell -Command "Get-Process">> "%REPORT%"
echo  [INFO] Complete process tree for forensic analysis.>> "%REPORT%"
echo Get-Process ^| Select-Object Id,@{N='PPID';E={(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId='+$_.Id) -EA SilentlyContinue).ParentProcessId}},Name,Path ^| Sort-Object Name ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Full Command Lines --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_Process -EA SilentlyContinue">> "%REPORT%"
echo  [INFO] Full command lines for behavioral analysis.>> "%REPORT%"
echo Get-CimInstance Win32_Process -EA SilentlyContinue ^| Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- HIGH SUSPICION: Processes from Temp, AppData, Downloads, Public --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,ExecutablePath ^| findstr /i /c:"\Temp\" /c:"\AppData\" /c:"\Downloads\" /c:"\Recycle" /c:"\Users\Public">> "%REPORT%"
:: \ProgramData\ removed -- legitimate vendor agents (Dropbox, OneDrive, Cisco
:: AnyConnect, EDR/AV) routinely run from there. Section 18a IOC sweep catches
:: known-bad ProgramData process names against ioc_processes.txt.
wmic process get Name,ProcessId,ExecutablePath | findstr /i /c:"\Temp\" /c:"\AppData\" /c:"\Downloads\" /c:"\Recycle" /c:"\Users\Public">> "%REPORT%" 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Suspicious process paths found above. Investigate now.>> "%REPORT%"
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] No processes from suspicious locations.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- LOLBin Processes (mshta, certutil, regsvr32, cmstp, wscript) --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,ExecutablePath,CommandLine>> "%REPORT%"
wmic process get Name,ProcessId,ExecutablePath,CommandLine > "%TEMP%\dz_pipe.tmp" 2>nul
if errorlevel 1 (
    echo [INFO] wmic unavailable -- LOLBin process check skipped.>> "%REPORT%"
) else (
    findstr /i /c:"mshta" /c:"regsvr32" /c:"certutil" /c:"cmstp" /c:"wscript" /c:"cscript" /c:"msiexec" /c:"installutil" "%TEMP%\dz_pipe.tmp">> "%REPORT%"
    if errorlevel 1 echo [OK] No LOLBin processes currently running.>> "%REPORT%"
)
del "%TEMP%\dz_pipe.tmp" 2>nul

echo.>> "%REPORT%"
echo --- Remote Monitoring and Management Tools (DPRK/Iran C2 vector) --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,ExecutablePath ^| findstr /i /c:"ScreenConnect" /c:"AnyDesk" /c:"TeamViewer" /c:"Ammyy" /c:"RustDesk" /c:"Splashtop" /c:"Atera" /c:"Kaseya" /c:"ConnectWise">> "%REPORT%"
wmic process get Name,ProcessId,ExecutablePath | findstr /i /c:"ScreenConnect" /c:"AnyDesk" /c:"TeamViewer" /c:"Ammyy" /c:"RustDesk" /c:"Splashtop" /c:"Atera" /c:"Kaseya" /c:"ConnectWise">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 4/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC4_PREV_CODE%" (
    echo  [SECTION 4/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 4/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC5_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[5/18]%C_RESET% Checking startup and persistence locations...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [5/18] STARTUP AND PERSISTENCE MECHANISMS>> "%REPORT%"
echo  THREAT: Run keys, Winlogon hijack, IFEO, AppInit, BootExecute (T1547)>> "%REPORT%"
echo  MDDR 2023: Iranian actors use MischiefTut (PS backdoor) and BellaCiao>> "%REPORT%"
echo       (dropper) for persistence. Russian actors use HTML-smuggled payloads.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- HKCU Run Keys (current user, native + WoW6432Node) --->> "%REPORT%"
echo  Command: reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce">> "%REPORT%" 2>&1
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%" 2>&1
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce">> "%REPORT%" 2>&1
echo  [INFO] Review Run key entries for unexpected persistence.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- HKLM Run Keys (system, native + WoW6432Node) --->> "%REPORT%"
echo  Command: reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%" 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce">> "%REPORT%" 2>&1
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run">> "%REPORT%" 2>&1
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce">> "%REPORT%" 2>&1
echo  [INFO] Review Run key entries for unexpected persistence.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Other Users' Run Keys (HKU\^<SID^> enumeration) --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue">> "%REPORT%"
echo  Walks loaded user hives under HKEY_USERS for additional Run/RunOnce>> "%REPORT%"
echo  persistence not visible from the current HKCU. Skips system SIDs>> "%REPORT%"
echo  (S-1-5-18/19/20) and the .DEFAULT hive.>> "%REPORT%"
echo $loadedHives = Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue ^| Where-Object { $_.Name -match 'S-1-5-21-' } > "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($hive in $loadedHives) { >> "%PSRUN%"
echo   $sid = $hive.PSChildName >> "%PSRUN%"
echo   foreach ($sub in 'Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce') { >> "%PSRUN%"
echo     $path = "Registry::HKEY_USERS\$sid\$sub" >> "%PSRUN%"
echo     if (Test-Path $path) { >> "%PSRUN%"
echo       $values = Get-ItemProperty $path -EA SilentlyContinue >> "%PSRUN%"
echo       if ($values) { $values.PSObject.Properties ^| Where-Object { $_.Name -notmatch '^^PS' } ^| ForEach-Object { $hits += "  HKU\$sid\$sub\$($_.Name) = $($_.Value)" } } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[INFO] Run/RunOnce entries in other-user hives:'; $hits } else { '[OK] No Run/RunOnce entries in other-user hives.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Startup Folders --->> "%REPORT%"
echo  Command: dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" /a /b>> "%REPORT%"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" /a /b>> "%REPORT%" 2>&1
dir "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp" /a /b>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Winlogon Hijack Check --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit>> "%REPORT%"
echo     SAFE - Userinit : C:\Windows\system32\userinit.exe,>> "%REPORT%"
echo     SAFE - Shell    : explorer.exe>> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit>> "%REPORT%" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- AppInit_DLLs (non-empty = DLL loaded into every GUI process) --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs>> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs>> "%REPORT%" 2>&1
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- IFEO Debugger Hijacking --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'">> "%REPORT%"
echo $hits=Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' ^| ForEach-Object {$d=Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue; if($d){'[IFEO HIT] '+$_.PSChildName+' =^> '+$d.Debugger}}; if($hits){$hits}else{'[OK] No IFEO Debugger hijacks.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- BootExecute (SAFE: autocheck autochk * only) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Active Setup StubPath --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s ^| findstr /i /c:"StubPath">> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s | findstr /i /c:"StubPath">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 5/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC5_PREV_CODE%" (
    echo  [SECTION 5/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 5/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC6_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[6/18]%C_RESET% Enumerating scheduled tasks...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [6/18] SCHEDULED TASKS>> "%REPORT%"
echo  THREAT: Task-based persistence (T1053.005)>> "%REPORT%"
echo  MDDR 2023: Flax Typhoon and Volt Typhoon use scheduled tasks that>> "%REPORT%"
echo       launch programs from TEMP. Microsoft MDDR recommends marking>> "%REPORT%"
echo       such tasks as unsafe for investigation.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Full Task Listing --->> "%REPORT%"
echo  Command: powershell -File tools\scheduled_tasks_full.ps1>> "%REPORT%"
echo  [INFO] Complete scheduled task inventory.>> "%REPORT%"
if exist "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1">> "%REPORT%" 2>&1
) else (
    schtasks /query /fo LIST /v>> "%REPORT%" 2>&1
)

echo.>> "%REPORT%"
echo --- CRITICAL: Tasks with Actions in Suspicious Paths --->> "%REPORT%"
echo  Command: powershell -File tools\scheduled_tasks_full.ps1 -Mode Suspicious>> "%REPORT%"
if exist "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1" -Mode Suspicious>> "%REPORT%" 2>&1
) else (
    echo  [INFO] Helper missing; falling back to truncated schtasks CSV scan.>> "%REPORT%"
    schtasks /query /fo CSV /v 2>nul | findstr /i /c:"\Temp" /c:"\AppData" /c:"\Downloads" /c:"\Users\Public" /c:"\ProgramData\update">> "%REPORT%" 2>&1
)

echo.>> "%REPORT%"
echo --- Tasks Running as SYSTEM --->> "%REPORT%"
echo  Command: powershell -File tools\scheduled_tasks_full.ps1 -Mode System>> "%REPORT%"
if exist "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\scheduled_tasks_full.ps1" -Mode System>> "%REPORT%" 2>&1
) else (
    schtasks /query /fo CSV /v 2>nul | findstr /i /c:"SYSTEM">> "%REPORT%" 2>&1
)
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 6/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC6_PREV_CODE%" (
    echo  [SECTION 6/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 6/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC7_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[7/18]%C_RESET% Auditing Windows services...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [7/18] WINDOWS SERVICES AUDIT>> "%REPORT%"
echo  THREAT: Malicious service, unquoted path (T1543.003)>> "%REPORT%"
echo  MDDR 2023: DPRK actors installed RMM tools as services for C2.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Services Authenticode Signature Gating --->> "%REPORT%"
echo  Command: powershell -File tools\service_signature_check.ps1>> "%REPORT%"
echo  Per-service Authenticode signature evaluation: signer must be on the>> "%REPORT%"
echo  vendor allowlist (\b-anchored), cert must pass revocation+expiry, and>> "%REPORT%"
echo  binary path must not be under Temp/AppData/Downloads/Public. Replaces>> "%REPORT%"
echo  the prior path-substring allowlist that was bypassed by installing>> "%REPORT%"
echo  to "C:\Program Files\anything\".>> "%REPORT%"
if exist "%SCRIPT_DIR%tools\service_signature_check.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\service_signature_check.ps1" >> "%REPORT%" 2>&1
) else (
    echo  [INFO] tools\service_signature_check.ps1 not found -- service signature gating skipped.>> "%REPORT%"
    echo Get-CimInstance Win32_Service ^| Where-Object {$_.PathName -and $_.PathName -notmatch 'system32^|SysWOW64^|Program Files^|MpKsl^|Windows Defender^|SecurityHealth^|MsMpEng'} ^| Select-Object Name,State,StartMode,PathName ^| Format-Table -AutoSize -Wrap > "%PSRUN%"
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
)

echo.>> "%REPORT%"
echo --- Unquoted Service Paths with Spaces --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_Service">> "%REPORT%"
echo $v=Get-CimInstance Win32_Service ^| Where-Object {$_.PathName -and $_.PathName -notmatch '^\x22' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^^[A-Za-z]:\\Windows\\'}; if($v){$v ^| Select-Object Name,StartMode,PathName ^| Format-Table -AutoSize -Wrap}else{'[OK] No unquoted service paths found.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- All Services State --->> "%REPORT%"
echo  Command: sc query type= all state= all>> "%REPORT%"
echo  [INFO] Complete service inventory.>> "%REPORT%"
sc query type= all state= all>> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 7/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC7_PREV_CODE%" (
    echo  [SECTION 7/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 7/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC8_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[8/18]%C_RESET% Checking firewall configuration...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [8/18] WINDOWS FIREWALL CONFIGURATION>> "%REPORT%"
echo  THREAT: Disabled firewall or rogue allow rules (T1562.004)>> "%REPORT%"
echo  MDDR 2023: Russian and Iranian actors added inbound rules to keep>> "%REPORT%"
echo       backdoor access open post-compromise.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- All Firewall Profile Status --->> "%REPORT%"
echo  Command: netsh advfirewall show allprofiles>> "%REPORT%"
echo  [INFO] Complete firewall profile configuration.>> "%REPORT%"
netsh advfirewall show allprofiles>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Inbound ALLOW Rules --->> "%REPORT%"
echo  Command: netsh advfirewall firewall show rule name=all dir=in action=allow ^| findstr /i /c:"Rule Name" /c:"LocalPort" /c:"RemoteIP" /c:"Enabled" /c:"Program" /c:"Action">> "%REPORT%"
netsh advfirewall firewall show rule name=all dir=in action=allow | findstr /i /c:"Rule Name" /c:"LocalPort" /c:"RemoteIP" /c:"Enabled" /c:"Program" /c:"Action">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Outbound BLOCK Rules --->> "%REPORT%"
echo  Command: netsh advfirewall firewall show rule name=all dir=out action=block ^| findstr /i /c:"Rule Name" /c:"RemoteIP" /c:"Enabled" /c:"Program">> "%REPORT%"
netsh advfirewall firewall show rule name=all dir=out action=block | findstr /i /c:"Rule Name" /c:"RemoteIP" /c:"Enabled" /c:"Program">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 8/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC8_PREV_CODE%" (
    echo  [SECTION 8/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 8/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC9_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[9/18]%C_RESET% Checking Defender and AV configuration...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [9/18] WINDOWS DEFENDER AND ANTIVIRUS STATUS>> "%REPORT%"
echo  THREAT: AV disabled, tampered, exclusion abuse (T1562.001)>> "%REPORT%"
echo  MDDR 2023: Nation-state actors add exclusions as first step after>> "%REPORT%"
echo       gaining admin, making Defender blind to their implants.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Defender Core Status --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpComputerStatus">> "%REPORT%"
echo Get-MpComputerStatus ^| Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,IsTamperProtected,AMEngineVersion,AntivirusSignatureLastUpdated ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Defender Disabled Flags --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpPreference">> "%REPORT%"
echo Get-MpPreference ^| Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,DisableBlockAtFirstSeen,MAPSReporting ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- CRITICAL: Exclusion Paths --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpPreference^).ExclusionPath">> "%REPORT%"
echo $e=(Get-MpPreference).ExclusionPath; if($e){'[WARNING] Exclusion paths found:'; $e}else{'[OK] No path exclusions.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- CRITICAL: Exclusion Processes --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpPreference^).ExclusionProcess">> "%REPORT%"
echo $e=(Get-MpPreference).ExclusionProcess; if($e){'[WARNING] Exclusion processes found:'; $e}else{'[OK] No process exclusions.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- CRITICAL: Exclusion Extensions --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpPreference^).ExclusionExtension">> "%REPORT%"
echo $e=(Get-MpPreference).ExclusionExtension; if($e){'[WARNING] Exclusion extensions found:'; $e}else{'[OK] No extension exclusions.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- ASR Rules and Threat History --->> "%REPORT%"
echo  Command: powershell -Command "Get-MpPreference">> "%REPORT%"
echo Get-MpPreference ^| Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo Get-MpThreatDetection ^| Select-Object ActionSuccess,InitialDetectionTime,ThreatID,DomainUser,ProcessName ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 9/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC9_PREV_CODE%" (
    echo  [SECTION 9/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 9/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC10_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[10/18]%C_RESET% Checking SMB and remote access...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [10/18] SMB, RDP AND REMOTE ACCESS>> "%REPORT%"
echo  THREAT: EternalBlue SMBv1, RDP brute force (T1021, CVE-2017-0144)>> "%REPORT%"
echo  MDDR 2023: Russian actors phished then password-sprayed across NATO>> "%REPORT%"
echo       member states. Forest Blizzard used Exchange Web Services>> "%REPORT%"
echo       to access mailboxes post-compromise with modified folder perms.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- SMBv1 Status (MUST be Disabled) --->> "%REPORT%"
echo  Command: powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol">> "%REPORT%"
echo try{Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol ^| Select-Object FeatureName,State ^| Format-List}catch{'Unable to query SMBv1 state.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- SMB Server Security Config --->> "%REPORT%"
echo  Command: powershell -Command "Get-SmbServerConfiguration">> "%REPORT%"
echo Get-SmbServerConfiguration ^| Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,RejectUnencryptedAccess,EnableSecuritySignature ^| Format-List > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- RDP Status: fDenyTSConnections (0=ON, 1=OFF) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- RDP NLA: UserAuthentication=1=NLA ON (required) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- WinRM and SSH Status --->> "%REPORT%"
echo  Command: sc query WinRM>> "%REPORT%"
sc query WinRM>> "%REPORT%" 2>nul
set "_SSHD_HIT="
sc query sshd >nul 2>nul && set "_SSHD_HIT=1"
if defined _SSHD_HIT (
    sc query sshd>> "%REPORT%" 2>nul
) else (
    echo [OK] OpenSSH Server ^(sshd^) not installed.>> "%REPORT%"
)
set "_SSHD_HIT="
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 10/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC10_PREV_CODE%" (
    echo  [SECTION 10/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 10/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC11_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[11/18]%C_RESET% Checking PowerShell security...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [11/18] POWERSHELL SECURITY CONFIGURATION>> "%REPORT%"
echo  THREAT: PSv2 downgrade, AMSI bypass, encoded commands (T1059.001)>> "%REPORT%"
echo  MDDR 2023: Iranian Mint Sandstorm used MischiefTut - a custom PS>> "%REPORT%"
echo       backdoor for recon and tool delivery. Check history for:>> "%REPORT%"
echo       IEX, DownloadString, -enc, -Bypass, Add-MpPreference.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Execution Policy All Scopes --->> "%REPORT%"
echo  Command: powershell -Command "Get-ExecutionPolicy -List ^| Format-Table -AutoSize">> "%REPORT%"
echo Get-ExecutionPolicy -List ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- PowerShell Version Table --->> "%REPORT%"
echo  Command: powershell -Command "$PSVersionTable ^| Format-Table -AutoSize">> "%REPORT%"
echo $PSVersionTable ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- PSv2 Engine Status (MUST be Disabled) --->> "%REPORT%"
echo  Command: powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root">> "%REPORT%"
echo try{Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root ^| Select-Object FeatureName,State ^| Format-List}catch{'Unable to query PSv2 state.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Logging Policy --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty "$base\ScriptBlockLogging" -Name EnableScriptBlockLogging -EA SilentlyContinue^).EnableScriptBlockLogging">> "%REPORT%"
echo $base='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' > "%PSRUN%"
echo $sbl=(Get-ItemProperty "$base\ScriptBlockLogging" -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging >> "%PSRUN%"
echo $ml=(Get-ItemProperty "$base\ModuleLogging" -Name EnableModuleLogging -EA SilentlyContinue).EnableModuleLogging >> "%PSRUN%"
echo $tr=(Get-ItemProperty "$base\Transcription" -Name EnableTranscripting -EA SilentlyContinue).EnableTranscripting >> "%PSRUN%"
echo if($sbl -eq 1){'ScriptBlockLogging  : [OK] ENABLED (GPO)'}else{'ScriptBlockLogging  : [WARN] Not enabled - PS commands not logged to Event 4104'} >> "%PSRUN%"
echo if($ml  -eq 1){'ModuleLogging       : [OK] ENABLED (GPO)'}else{'ModuleLogging       : [OK] Not configured (optional)'} >> "%PSRUN%"
echo if($tr  -eq 1){'Transcription       : [OK] ENABLED (GPO)'}else{'Transcription       : [OK] Not configured (optional)'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Recent PS Command History --->> "%REPORT%"
echo  Command: powershell -Command "Get-Content '%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -EA SilentlyContinue ^| Select-Object -Last 50">> "%REPORT%"
if not exist "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" goto :pshistnone
echo [FOUND] PS history file. Last 50 commands:>> "%REPORT%"
echo Get-Content '%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -EA SilentlyContinue ^| Select-Object -Last 50 > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
goto :pshistdone
:pshistnone
echo [INFO] No PS history file found.>> "%REPORT%"
:pshistdone
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 11/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC11_PREV_CODE%" (
    echo  [SECTION 11/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 11/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC12_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[12/18]%C_RESET% Checking credential and LSASS protection...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [12/18] CREDENTIAL PROTECTION AND LSASS HARDENING>> "%REPORT%"
echo  THREAT: Mimikatz, Pass-the-Hash, LSASS dump (T1003.001)>> "%REPORT%"
echo  MDDR 2023: Forest Blizzard (Russia), Peach Sandstorm (Iran), Jade>> "%REPORT%"
echo       Sleet (DPRK) used custom credential stealers. Forest Blizzard>> "%REPORT%"
echo       exploited CVE-2023-23397 to force NTLM auth without user click.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Credential Guard and Device Guard --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard">> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- LSASS PPL: SAFE=RunAsPPL=1 --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- WDigest: SAFE=UseLogonCredential=0 (1=plaintext in RAM) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential>> "%REPORT%" 2>nul
if errorlevel 1 (echo [OK] WDigest UseLogonCredential not set -- Win11 default does not cache plaintext credentials.)>> "%REPORT%"

echo.>> "%REPORT%"
echo --- NTLM Level: SAFE=LmCompatibilityLevel=5 (NTLMv2 only) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- LSA Security Packages (rogue DLL = credential implant) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages">> "%REPORT%"
echo     EXPECTED: kerberos msv1_0 schannel wdigest tspkg pku2u>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- LSA Notification Packages (expected: scecli only) --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages">> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- LsaCfgFlags: 0=disabled, 1=UEFI lock, 2=no lock --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags>> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags>> "%REPORT%" 2>nul
if errorlevel 1 (echo [INFO] LsaCfgFlags not set -- Credential Guard not explicitly configured ^(may still be on if VBS-managed^).)>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Full LSA Key --->> "%REPORT%"
echo  Command: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa">> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 12/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC12_PREV_CODE%" (
    echo  [SECTION 12/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 12/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC13_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[13/18]%C_RESET% Checking system hardening settings...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [13/18] SYSTEM HARDENING CONFIGURATION>> "%REPORT%"
echo  THREAT: UAC bypass, boot tamper, USB autorun, WSH abuse (T1548)>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- UAC Config --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA ^&^& set "_LUA_HIT=1">> "%REPORT%"
:: Each value gets an individual presence check via the _FLAG pattern
:: (mirrors the _AR_HIT/_ADFS_HIT/_SSHD_HIT idiom used elsewhere). A
:: missing EnableLUA or ConsentPromptBehaviorAdmin is unusual on Win10/11
:: defaults; surfacing absence as [WARNING] catches a plausible (if rare)
:: tampering path. LocalAccountTokenFilterPolicy is normally absent --
:: report that as [OK].
set "_LUA_HIT="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >nul 2>nul && set "_LUA_HIT=1"
if defined _LUA_HIT (
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA>> "%REPORT%" 2>nul
) else (
    echo [WARNING] EnableLUA registry value MISSING -- unusual on Win10/11; investigate for tampering.>> "%REPORT%"
)
set "_LUA_HIT="
set "_CPBA_HIT="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin >nul 2>nul && set "_CPBA_HIT=1"
if defined _CPBA_HIT (
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin>> "%REPORT%" 2>nul
) else (
    echo [WARNING] ConsentPromptBehaviorAdmin registry value MISSING -- unusual on Win10/11; investigate for tampering.>> "%REPORT%"
)
set "_CPBA_HIT="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy>> "%REPORT%" 2>nul
if errorlevel 1 (echo [OK] LocalAccountTokenFilterPolicy not set -- default remote-admin token filtering applies.)>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Secure Boot --->> "%REPORT%"
echo  Command: powershell -Command "try{$sb=Confirm-SecureBootUEFI; if^($sb^){'[OK] Secure Boot ENABLED.'}else{'[WARNING] Secure Boot DISABLED.'}}catch{'[INFO] Secure Boot query not supported ^(may be legacy BIOS^).'}">> "%REPORT%"
echo try{$sb=Confirm-SecureBootUEFI; if($sb){'[OK] Secure Boot ENABLED.'}else{'[WARNING] Secure Boot DISABLED.'}}catch{'[INFO] Secure Boot query not supported (may be legacy BIOS).'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- BitLocker --->> "%REPORT%"
echo  Command: powershell -Command "Get-BitLockerVolume">> "%REPORT%"
echo try{Get-BitLockerVolume ^| Select-Object MountPoint,EncryptionMethod,VolumeStatus,ProtectionStatus ^| Format-Table -AutoSize}catch{'BitLocker cmdlet unavailable on this edition.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
manage-bde -status>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Driver Signature Enforcement --->> "%REPORT%"
echo  Command: bcdedit /enum ^| findstr /i /c:"testsigning" /c:"nointegritychecks">> "%REPORT%"
bcdedit /enum | findstr /i /c:"testsigning" /c:"nointegritychecks">> "%REPORT%" 2>&1
bcdedit /enum 2>nul | findstr /i /c:"testsigning Yes" >nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] testsigning enabled. Unsigned kernel drivers can load.>> "%REPORT%"
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] Driver signature enforcement active.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- AutoRun/AutoPlay: SAFE=NoDriveTypeAutoRun=0xFF --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun ^&^& set "_AR_HIT=1">> "%REPORT%"
set "_AR_HIT="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun>> "%REPORT%" 2>nul && set "_AR_HIT=1"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun>> "%REPORT%" 2>nul && set "_AR_HIT=1"
if not defined _AR_HIT (echo [INFO] NoDriveTypeAutoRun not pinned via policy -- default OS behavior applies.)>> "%REPORT%"
set "_AR_HIT="

echo.>> "%REPORT%"
echo --- Windows Script Host: SAFE=Enabled=0 --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled>> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled>> "%REPORT%" 2>nul
if errorlevel 1 (echo [INFO] WSH Enabled value not set -- default is enabled. Disable via policy if .vbs/.js execution is not required.)>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Remote Registry: SAFE=STOPPED and Disabled --->> "%REPORT%"
echo  Command: sc query RemoteRegistry>> "%REPORT%"
sc query RemoteRegistry>> "%REPORT%" 2>&1
echo.>> "%REPORT%"

echo --- Accessibility Binary Integrity (T1546.008 - Linen/Violet Typhoon) --->> "%REPORT%"
echo THREAT: Attackers replace or IFEO-hijack accessibility binaries activated at the login>> "%REPORT%"
echo screen (sethc.exe, utilman.exe etc.) to get a SYSTEM cmd prompt with no credentials.>> "%REPORT%"
echo Works via WinRE file swap (BitLocker stops this) or IFEO registry Debugger value.>> "%REPORT%"
echo MITRE ATT^&CK: T1546.008 ^| Nation-state: Linen Typhoon, Violet Typhoon (MSTIC 2025)>> "%REPORT%"
echo.>> "%REPORT%"
echo --- [T1546.008] IFEO Debugger Hijack on Accessibility Binaries --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty $key -Name Debugger -EA SilentlyContinue">> "%REPORT%"
echo $accBins = @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') > "%PSRUN%"
echo $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' >> "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($b in $accBins) { >> "%PSRUN%"
echo   $key = Join-Path $ifeoBase $b >> "%PSRUN%"
echo   $d = Get-ItemProperty $key -Name Debugger -EA SilentlyContinue >> "%PSRUN%"
echo   if ($d) { $hits += '[CRITICAL] IFEO Debugger hijack: '+$b+' -^> '+$d.Debugger } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits) { $hits; Write-Output '[^^!^^!] Accessibility IFEO hijack = SYSTEM-level login-screen backdoor. Remove Debugger value immediately.' } else { '[OK] No IFEO Debugger hijacks on accessibility binaries.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [T1546.008] Accessibility Binary File Signature Check --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $f^) {">> "%REPORT%"
echo $accBins = @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') > "%PSRUN%"
echo $sysDir = "$env:SystemRoot\System32" >> "%PSRUN%"
echo $bad = @() >> "%PSRUN%"
echo foreach ($b in $accBins) { >> "%PSRUN%"
echo   $f = Join-Path $sysDir $b >> "%PSRUN%"
echo   if (Test-Path $f) { >> "%PSRUN%"
echo     $sig = Get-AuthenticodeSignature $f >> "%PSRUN%"
echo     if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft') { >> "%PSRUN%"
echo       Write-Output ('[OK] '+$b+' - Microsoft signature valid') >> "%PSRUN%"
echo     } else { >> "%PSRUN%"
echo       $bad += $b >> "%PSRUN%"
echo       Write-Output ('[CRITICAL] '+$b+' - Signature: '+$sig.Status+' / '+$sig.SignerCertificate.Subject) >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } else { Write-Output ('[WARN] '+$b+' - not found in System32') } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($bad.Count -gt 0) { Write-Output '[^^!^^!] Replace tampered binaries: sfc /scannow or restore from WinRE.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [T1546.008] Sticky Keys Shortcut Status --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags -EA SilentlyContinue^).Flags">> "%REPORT%"
echo $stickyFlags = (Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags -EA SilentlyContinue).Flags > "%PSRUN%"
echo $utilFlags   = (Get-ItemProperty 'HKCU:\Control Panel\Accessibility\UtilityManager' -Name Flags -EA SilentlyContinue).Flags >> "%PSRUN%"
echo if ($null -ne $stickyFlags) { >> "%PSRUN%"
echo   if (($stickyFlags -band 0x02) -gt 0) { >> "%PSRUN%"
echo     Write-Output '[WARN] Sticky Keys shortcut ENABLED (Shift x5 activates at login screen)' >> "%PSRUN%"
echo     Write-Output '       Disable: Settings ^> Accessibility ^> Keyboard ^> Sticky Keys shortcut OFF' >> "%PSRUN%"
echo   } else { Write-Output '[OK] Sticky Keys shortcut disabled (sethc.exe not triggerable at login)' } >> "%PSRUN%"
echo } else { Write-Output '[INFO] Sticky Keys flags not set in registry (default: shortcut enabled on fresh installs)' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 13/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC13_PREV_CODE%" (
    echo  [SECTION 13/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 13/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC14_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[14/18]%C_RESET% Scanning file system for suspicious files...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [14/18] SUSPICIOUS FILES AND FILE SYSTEM ANOMALIES>> "%REPORT%"
echo  THREAT: Dropper staging, ADS hiding, System32 tampering (T1564)>> "%REPORT%"
echo  MDDR 2023: Iranian BellaCiao staged in Temp/AppData.>> "%REPORT%"
echo       Midnight Blizzard used HTML smuggling (large .html attachments).>> "%REPORT%"
echo       DPRK Ruby Sleet signed malware with stolen legitimate cert.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Executables in User Temp (Last 7 Days) --->> "%REPORT%"
echo  Command: forfiles /p "%TEMP%" /s /d -7 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%"
forfiles /p "%TEMP%" /s /d -7 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%TEMP%" /s /d -7 /m "*.dll" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%TEMP%" /s /d -7 /m "*.ps1" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%TEMP%" /s /d -7 /m "*.vbs" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Executables in System Temp (C:\Windows\Temp, Last 7 Days) --->> "%REPORT%"
echo  Command: forfiles /p "%WINDIR%\Temp" /s /d -7 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%"
echo  Catches SYSTEM-context staging (post-priv-esc payload drops).>> "%REPORT%"
forfiles /p "%WINDIR%\Temp" /s /d -7 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%WINDIR%\Temp" /s /d -7 /m "*.dll" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%WINDIR%\Temp" /s /d -7 /m "*.ps1" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
forfiles /p "%WINDIR%\Temp" /s /d -7 /m "*.vbs" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- HTML Smuggling: Large HTML/HTA in Downloads (Midnight Blizzard) --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem -Path ^([System.Environment]::GetFolderPath^('UserProfile'^)+'\Downloads'^) -Recurse -Include '*.html','*.htm','*.hta' -EA SilentlyContinue">> "%REPORT%"
echo Get-ChildItem -Path ([System.Environment]::GetFolderPath('UserProfile')+'\Downloads') -Recurse -Include '*.html','*.htm','*.hta' -EA SilentlyContinue ^| Where-Object {$_.Length -gt 200000} ^| Select-Object FullName,@{N='SizeKB';E={[math]::Round($_.Length/1024,1)}},LastWriteTime ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Executables in Downloads --->> "%REPORT%"
echo  Command: dir "%USERPROFILE%\Downloads" /s /a /b ^| findstr /i /c:".exe" /c:".dll" /c:".ps1" /c:".bat" /c:".vbs" /c:".js" /c:".hta" /c:".scr" /c:".msi">> "%REPORT%"
dir "%USERPROFILE%\Downloads" /s /a /b 2>nul | findstr /i /c:".exe" /c:".dll" /c:".ps1" /c:".bat" /c:".vbs" /c:".js" /c:".hta" /c:".scr" /c:".msi">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Executables in AppData --->> "%REPORT%"
echo  Command: dir "%APPDATA%" /s /a /b ^| findstr /i /c:".exe" /c:".dll">> "%REPORT%"
dir "%APPDATA%" /s /a /b 2>nul | findstr /i /c:".exe" /c:".dll">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- NTFS Alternate Data Streams in Temp --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem -Path $env:TEMP -Recurse -EA SilentlyContinue">> "%REPORT%"
echo $f=$false; Get-ChildItem -Path $env:TEMP -Recurse -EA SilentlyContinue ^| ForEach-Object {try{$s=Get-Item $_.FullName -Stream * -EA Stop ^| Where-Object {$_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier'}; if($s){$f=$true;'[ADS FOUND] '+$_.FullName+' :: '+($s.Stream -join ', ')}}catch{}}; if(-not $f){'[OK] No suspicious ADS in Temp.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- System32 Executables Modified Last 14 Days --->> "%REPORT%"
echo  Command: forfiles /p "%WINDIR%\System32" /d -14 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%"
forfiles /p "%WINDIR%\System32" /d -14 /m "*.exe" /c "cmd /c echo @path @fdate @ftime">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 14/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC14_PREV_CODE%" (
    echo  [SECTION 14/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 14/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC15_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[15/18]%C_RESET% Auditing installed software and drivers...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [15/18] INSTALLED SOFTWARE AND DRIVER AUDIT>> "%REPORT%"
echo  THREAT: Trojanized software, rogue kernel drivers (T1195, T1014)>> "%REPORT%"
echo  MDDR 2023: North Korean Citrine Sleet: 3CX supply chain attack.>> "%REPORT%"
echo       Ruby Sleet: signed malware with stolen IT security certificate.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Installed Programs (64-bit) --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s ^| findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%" 2>&1
echo  [INFO] Software inventory for supply chain analysis.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Installed Programs (32-bit) --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s ^| findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%" 2>&1
echo  [INFO] 32-bit software inventory.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Per-User Installed Programs --->> "%REPORT%"
echo  Command: reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s ^| findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /c:"DisplayName" /c:"DisplayVersion" /c:"InstallDate">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Running Kernel Drivers --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_SystemDriver">> "%REPORT%"
echo Get-CimInstance Win32_SystemDriver ^| Where-Object {$_.Started -eq $true} ^| Select-Object Name,State,PathName ^| Sort-Object Name ^| Format-Table -AutoSize > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo  [INFO] Kernel driver inventory. Unsigned or unexpected drivers = high risk.>> "%REPORT%"

echo.>> "%REPORT%"
echo --- Driver Signature Log (run sigverif.exe as admin to generate) --->> "%REPORT%"
echo  Command: type "%WINDIR%\System32\sigverif.txt">> "%REPORT%"
if not exist "%WINDIR%\System32\sigverif.txt" goto :nosigtxt
type "%WINDIR%\System32\sigverif.txt">> "%REPORT%" 2>&1
goto :sigtxtdone
:nosigtxt
echo [INFO] sigverif.txt not found. Run: sigverif.exe as admin.>> "%REPORT%"
:sigtxtdone
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 15/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC15_PREV_CODE%" (
    echo  [SECTION 15/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 15/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC16_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[16/18]%C_RESET% Pulling Windows Event Log anomalies...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [16/18] WINDOWS EVENT LOG ANOMALIES>> "%REPORT%"
echo  THREAT: Log wiping, brute force, privilege escalation (T1070.001)>> "%REPORT%"
echo  MDDR 2023: 1102 = logs cleared (attacker cover-up). Russian actors>> "%REPORT%"
echo       password-sprayed at scale (Event 4625 spikes). DPRK/Iran>> "%REPORT%"
echo       cleared logs after destructive operations.>> "%REPORT%"
echo  IF EVENT 1102 EXISTS AND YOU DID NOT CLEAR IT = ACTIVE BREACH>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo --- Log Cleared (1102=Security cleared, 104=System cleared) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=1102^)]]" /c:10 /rd:true /f:text>> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /c:10 /rd:true /f:text>> "%REPORT%" 2>&1
wevtutil qe System /q:"*[System[(EventID=104)]]" /c:10 /rd:true /f:text>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- New Account Created - Event 4720 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4720^)]]" /c:10 /rd:true /f:text>> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4720)]]" /c:10 /rd:true /f:text>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Added to Administrators - Event 4732 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4732^)]]" /c:10 /rd:true /f:text>> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4732)]]" /c:10 /rd:true /f:text>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Special Privilege Logon - Event 4672 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4672^)]]" /c:20 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Account Name" /c:"Privileges">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4672)]]" /c:20 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Account Name" /c:"Privileges">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Failed Logins - Event 4625 (spray = many accounts, same source) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4625^)]]" /c:25 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Account Name" /c:"Failure Reason" /c:"Source Network" /c:"Logon Type">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:25 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Account Name" /c:"Failure Reason" /c:"Source Network" /c:"Logon Type">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Successful Logins - Event 4624 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4624^)]]" /c:25 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Account Name" /c:"Logon Type" /c:"Source Network">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:25 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Account Name" /c:"Logon Type" /c:"Source Network">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- New Service Installed - Event 7045 --->> "%REPORT%"
echo  Command: wevtutil qe System /q:"*[System[^(EventID=7045^)]]" /c:20 /rd:true /f:text>> "%REPORT%"
wevtutil qe System /q:"*[System[(EventID=7045)]]" /c:20 /rd:true /f:text > "%TEMP%\dz_pipe.tmp" 2>nul
if errorlevel 1 (
    echo [INFO] wevtutil unavailable or System log inaccessible -- 7045 check skipped.>> "%REPORT%"
) else (
    findstr /c:"TimeCreated" /c:"ServiceName" /c:"ImagePath" /c:"AccountName" "%TEMP%\dz_pipe.tmp">> "%REPORT%"
    if errorlevel 1 echo [OK] No recent service install events ^(7045^) found.>> "%REPORT%"
)
del "%TEMP%\dz_pipe.tmp" 2>nul

echo.>> "%REPORT%"
echo --- Scheduled Task Changes - Events 4698, 4702 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4698 or EventID=4702^)]]" /c:20 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Task Name" /c:"Subject">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4698 or EventID=4702)]]" /c:20 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Task Name" /c:"Subject">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- PS Script Block Executions - Event 4104 --->> "%REPORT%"
echo  Command: powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'">> "%REPORT%"
echo $evts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -EA SilentlyContinue > "%PSRUN%"
echo $skip = 'AuditPS_\d{8}_\d{6}\.ps1^|doze_sec_noAdmin\.bat^|doze_sec\.bat' >> "%PSRUN%"
echo if($evts){ >> "%PSRUN%"
echo   $shown = @($evts ^| Where-Object { $p = if($_.Properties.Count -ge 5){[string]$_.Properties[4].Value}else{''}; $p -notmatch $skip }) ^| Select-Object -First 30 >> "%PSRUN%"
echo   if($shown){ >> "%PSRUN%"
echo     foreach($e in $shown){ >> "%PSRUN%"
echo       Write-Output ('TimeCreated: '+$e.TimeCreated.ToString('s')) >> "%PSRUN%"
echo       $msg = $e.Message -split "`n" >> "%PSRUN%"
echo       $msg ^| Where-Object { $_ -match '^^ScriptBlock ID:^|^^Path:' } ^| ForEach-Object { Write-Output ('  ' + $_.Trim()) } >> "%PSRUN%"
echo       Write-Output '' >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } else { Write-Output '[OK] No external PS Script Block events (audit-self events filtered).' } >> "%PSRUN%"
echo } else { Write-Output '[OK] No PS Script Block events found.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: Compute UTC ISO timestamp for 24h ago. Used by all subsequent
:: wevtutil 4688 queries as an XPath SystemTime predicate so the
:: results are scoped to the last 24h regardless of how many events
:: the Security log has rotated through. Without this guard,
:: /c:N /rd:true on a busy system could be only the last few minutes.
for /f "usebackq" %%i in (`powershell -NoProfile -Command "(Get-Date).ToUniversalTime().AddHours(-24).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')"`) do set "WEVT_24H_AGO=%%i"
if not defined WEVT_24H_AGO set "WEVT_24H_AGO=1970-01-01T00:00:00.000Z"

echo.>> "%REPORT%"
echo --- Process Creation - Event 4688 (last 24h) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4688^)]]" /c:200 /rd:true /f:text ^| select_lines.ps1 "TimeCreated" "Process Name" "Creator Process" "Command Line">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4688) and TimeCreated[@SystemTime>='%WEVT_24H_AGO%']]]" /c:200 /rd:true /f:text > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" "TimeCreated" "Process Name" "Creator Process" "Command Line">> "%REPORT%" 2>&1
del "%TEMP%\dz_evt.tmp" 2>nul

echo.>> "%REPORT%"
echo --- Defender Alerts: 1116=Detected, 1117=Action --->> "%REPORT%"
echo  Command: wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /q:"*[System[^(EventID=1116 or EventID=1117^)]]" /c:20 /rd:true /f:text>> "%REPORT%"
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /q:"*[System[(EventID=1116 or EventID=1117)]]" /c:20 /rd:true /f:text>> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- Kerberos RC4 Tickets - Event 4769 (Kerberoasting IOC) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4769^)]]" /c:20 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Account Name" /c:"Service Name" /c:"Ticket Encryption">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4769)]]" /c:20 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Account Name" /c:"Service Name" /c:"Ticket Encryption">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- NTLM Auth - Event 4776 (Forest Blizzard relay IOC) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4776^)]]" /c:20 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Logon Account" /c:"Source Workstation" /c:"Error Code">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4776)]]" /c:20 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Logon Account" /c:"Source Workstation" /c:"Error Code">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: ====================================================================

:: ---- Section 16/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC16_PREV_CODE%" (
    echo  [SECTION 16/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 16/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC17_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[17/18]%C_RESET% Nation-state threat indicators from MDDR 2023...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
(echo  [17/18] NATION-STATE THREAT INDICATORS - MDDR 2023)>> "%REPORT%"
echo  Volt Typhoon (China): LOLBin abuse, portproxy C2, SOHO pivot>> "%REPORT%"
echo  Forest Blizzard (Russia): CVE-2023-23397 NTLM relay, EWS pivot>> "%REPORT%"
echo  Midnight Blizzard (Russia): OAuth token replay, HTML smuggling>> "%REPORT%"
echo  Peach/Mango Sandstorm (Iran): GoldenSAML/ADFS, cloud pivot>> "%REPORT%"
echo  Jade/Diamond/Citrine/Ruby Sleet (DPRK): RMM tools, signed malware>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

echo.>> "%REPORT%"
echo --- [VOLT TYPHOON] netsh PortProxy C2 Tunnel Rules --->> "%REPORT%"
echo  Command: netsh interface portproxy show all>> "%REPORT%"
netsh interface portproxy show all>> "%REPORT%" 2>&1
netsh interface portproxy show all 2>nul | findstr /c:"Listen" >nul 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] netsh portproxy rules ACTIVE. Volt Typhoon C2 tunnel IOC.>> "%REPORT%"
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] No netsh portproxy rules.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- [VOLT TYPHOON] LOLBin Abuse in Event 4688 (last 24h) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4688^)]]" /c:500 /rd:true /f:text ^| select_lines.ps1 "certutil" "mshta" "regsvr32" "cmstp" "installutil" "odbcconf">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4688) and TimeCreated[@SystemTime>='%WEVT_24H_AGO%']]]" /c:500 /rd:true /f:text > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" "certutil" "mshta" "regsvr32" "cmstp" "installutil" "odbcconf">> "%REPORT%" 2>&1
del "%TEMP%\dz_evt.tmp" 2>nul

echo.>> "%REPORT%"
echo --- [VOLT TYPHOON] Discovery Commands in Event 4688 (last 24h) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4688^)]]" /c:500 /rd:true /f:text ^| select_lines.ps1 "nltest" "net group" "dsquery" "ldifde" "ntdsutil" "csvde">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4688) and TimeCreated[@SystemTime>='%WEVT_24H_AGO%']]]" /c:500 /rd:true /f:text > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" "nltest" "net group" "dsquery" "ldifde" "ntdsutil" "csvde">> "%REPORT%" 2>&1
del "%TEMP%\dz_evt.tmp" 2>nul

echo.>> "%REPORT%"
echo --- [MIDNIGHT BLIZZARD] OAuth Identity Registrations --->> "%REPORT%"
echo  Command: reg query "HKCU\Software\Microsoft\Office\16.0\Common\Identity\Identities" /s>> "%REPORT%"
reg query "HKCU\Software\Microsoft\Office\16.0\Common\Identity\Identities" /s>> "%REPORT%" 2>nul
if %errorlevel% neq 0 echo [OK] No Office/AAD OAuth identity registrations found (Midnight Blizzard check clear).>> "%REPORT%"

echo.>> "%REPORT%"
echo --- [MIDNIGHT/AQUA BLIZZARD] Large HTML/HTA in Temp (HTML Smuggling) --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem -Path $env:TEMP -Recurse -Include '*.html','*.htm','*.hta' -EA SilentlyContinue">> "%REPORT%"
echo $r = @(Get-ChildItem -Path $env:TEMP -Recurse -Include '*.html','*.htm','*.hta' -EA SilentlyContinue ^| Where-Object {$_.Length -gt 200000}); if($r.Count -gt 0){ '[WARNING] Large HTML/HTA files in Temp:'; $r ^| Select-Object FullName,@{N='SizeKB';E={[math]::Round($_.Length/1024,1)}},LastWriteTime ^| Format-Table -AutoSize } else { '[OK] No oversized HTML/HTA files in user TEMP.' } > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [FOREST BLIZZARD] CVE-2023-23397 Outlook .msg Artefacts --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem -Path ^([System.Environment]::GetFolderPath^('LocalApplicationData'^)+'\Microsoft\Outlook'^) -Recurse -Include '*.msg','*.oft' -EA SilentlyContinue">> "%REPORT%"
echo $r = @(Get-ChildItem -Path ([System.Environment]::GetFolderPath('LocalApplicationData')+'\Microsoft\Outlook') -Recurse -Include '*.msg','*.oft' -EA SilentlyContinue ^| Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-90)}); if($r.Count -gt 0){ '[WARNING] Recent Outlook .msg/.oft artefacts (review for CVE-2023-23397 NTLM relay):'; $r ^| Select-Object FullName,LastWriteTime ^| Format-Table -AutoSize } else { '[OK] No recent Outlook .msg/.oft artefacts (Outlook profile may be absent).' } > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [PEACH SANDSTORM] ADFS Service (GoldenSAML attack surface) --->> "%REPORT%"
echo  Command: sc query adfssrv ^&^& set "_ADFS_HIT=1">> "%REPORT%"
set "_ADFS_HIT="
sc query adfssrv >nul 2>nul && set "_ADFS_HIT=1"
reg query "HKLM\SOFTWARE\Microsoft\ADFS" >nul 2>nul && set "_ADFS_HIT=1"
if defined _ADFS_HIT (
    sc query adfssrv>> "%REPORT%" 2>nul
    reg query "HKLM\SOFTWARE\Microsoft\ADFS">> "%REPORT%" 2>nul
    echo [WARNING] ADFS detected -- GoldenSAML attack surface present.>> "%REPORT%"
) else (
    echo [OK] ADFS not installed -- no GoldenSAML attack surface.>> "%REPORT%"
)
set "_ADFS_HIT="

echo.>> "%REPORT%"
echo --- [MANGO SANDSTORM] Azure AD Connect (on-prem to cloud pivot) --->> "%REPORT%"
echo  Command: sc query ADSync ^&^& set "_AAD_HIT=1">> "%REPORT%"
set "_AAD_HIT="
sc query ADSync >nul 2>nul && set "_AAD_HIT=1"
reg query "HKLM\SOFTWARE\Microsoft\Azure AD Connect" >nul 2>nul && set "_AAD_HIT=1"
if defined _AAD_HIT (
    sc query "ADSync">> "%REPORT%" 2>nul
    reg query "HKLM\SOFTWARE\Microsoft\Azure AD Connect">> "%REPORT%" 2>nul
    echo [WARNING] Azure AD Connect detected -- on-prem to cloud pivot surface present.>> "%REPORT%"
) else (
    echo [OK] Azure AD Connect not installed -- no on-prem to cloud pivot.>> "%REPORT%"
)
set "_AAD_HIT="

echo.>> "%REPORT%"
echo --- [ALL ACTORS] Password Spray Analysis (Event 4625 unique accounts) --->> "%REPORT%"
echo  Command: powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security'">> "%REPORT%"
echo $evts=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 200 -EA SilentlyContinue > "%PSRUN%"
echo if($evts){ >> "%PSRUN%"
echo   $xml=$evts ^| ForEach-Object {[xml]$_.ToXml()} >> "%PSRUN%"
echo   $accts=$xml ^| ForEach-Object {$_.Event.EventData.Data ^| Where-Object {$_.Name -eq 'TargetUserName'} ^| ForEach-Object {$_.'#text'}} ^| Sort-Object -Unique >> "%PSRUN%"
echo   Write-Output ('Unique target accounts in last 200 failed logins: '+$accts.Count) >> "%PSRUN%"
echo   if($accts.Count -gt 10){'[WARNING] High unique account count - possible password spray attack'} >> "%PSRUN%"
echo }else{'[INFO] No 4625 events or insufficient privileges.'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [DPRK] RMM Tool Processes (Diamond/Jade Sleet IOC) --->> "%REPORT%"
echo  Command: powershell -Command "Get-Process -Name $t -EA SilentlyContinue">> "%REPORT%"
echo $rmm=@('ScreenConnect','AnyDesk','TeamViewer','Ammyy','RustDesk','Splashtop','Atera','Kaseya','ConnectWise','BeyondTrust','Bomgar','LogMeIn','RemotePC') > "%PSRUN%"
echo $found=$false >> "%PSRUN%"
echo foreach($t in $rmm){$p=Get-Process -Name $t -EA SilentlyContinue; if($p){$found=$true;'[RMM RUNNING] '+$t+' PID:'+$p.Id}} >> "%PSRUN%"
echo if(-not $found){'[OK] No unexpected RMM tool processes.'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [DPRK] RMM Software Installed --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty $r -EA SilentlyContinue">> "%REPORT%"
echo $rmm=@('ScreenConnect','AnyDesk','TeamViewer','Ammyy','RustDesk','Splashtop','Atera','Kaseya','ConnectWise','BeyondTrust','Bomgar','LogMeIn','RemotePC') > "%PSRUN%"
echo $regs=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') >> "%PSRUN%"
echo $found=$false >> "%PSRUN%"
echo foreach($r in $regs){Get-ItemProperty $r -EA SilentlyContinue ^| ForEach-Object {$n=$_.DisplayName; foreach($t in $rmm){if($n -and $n -match $t){$found=$true;'[RMM INSTALLED] '+$n}}}} >> "%PSRUN%"
echo if(-not $found){'[OK] No unexpected RMM software found.'} >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [ALL ACTORS] Cobalt Strike Named Pipes (MDDR: most abused C2 tool) --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem \\.\pipe\ -EA SilentlyContinue">> "%REPORT%"
echo try{$pipes=Get-ChildItem \\.\pipe\ -EA SilentlyContinue ^| Where-Object {$_.Name -match 'postex_^|msagent_^|MSSE-^|metsvc^|beacon^|cobaltstrike^|status_'}; if($pipes){$pipes ^| Select-Object Name; '[WARNING] Possible Cobalt Strike pipes detected.'}else{'[OK] No Cobalt Strike default named pipes.'}}catch{'[INFO] Named pipe enumeration unavailable.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [ALL ACTORS] WMI Permanent Subscriptions (stealthy persistence) --->> "%REPORT%"
echo  Command: powershell -Command "Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue">> "%REPORT%"
echo $subs=@(Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue ^| Where-Object { -not ( ($_.Name -eq 'SCM Event Log Filter' -and $_.Query -like '*MSFT_SCMEventLogEvent*') -or ($_.Name -in @('BVTConsumer','BVTFilter','RmAssistEventLog')) ) }); if($subs.Count -gt 0){'[WARNING] Non-default WMI EventFilters found:'; $subs ^| Select-Object Name,Query ^| Format-Table -AutoSize}else{'[OK] No non-default WMI EventFilter subscriptions (default Microsoft filters allowlisted).'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo $cons=Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -EA SilentlyContinue; if($cons){'[WARNING] WMI CommandLine Consumers found:'; $cons ^| Select-Object Name,CommandLineTemplate ^| Format-Table -AutoSize}else{'[OK] No WMI CommandLineEventConsumer.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo $acons=Get-WMIObject -Namespace root\subscription -Class ActiveScriptEventConsumer -EA SilentlyContinue; if($acons){'[WARNING] WMI ActiveScript (VBScript/JScript) Consumers found:'; $acons ^| Select-Object Name,ScriptingEngine,@{n='ScriptText';e={if($_.ScriptText.Length -gt 200){$_.ScriptText.Substring(0,200)+'...[truncated]'}else{$_.ScriptText}}} ^| Format-List}else{'[OK] No WMI ActiveScriptEventConsumer.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [CHINA/VOLT TYPHOON] Kerberos RC4 Encryption Types --->> "%REPORT%"
echo  Command: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes>> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes>> "%REPORT%" 2>nul
if errorlevel 1 (echo [INFO] SupportedEncryptionTypes not pinned -- Kerberos uses defaults ^(may include RC4-HMAC^). To restrict to AES, set value 0x18.)>> "%REPORT%"

echo.>> "%REPORT%"
echo --- [DPRK/RUBY SLEET] Recently Installed Root Certificates --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem Cert:\LocalMachine\Root">> "%REPORT%"
echo $r = @(Get-ChildItem Cert:\LocalMachine\Root ^| Where-Object {$_.NotBefore -gt (Get-Date).AddDays(-90)}); if($r.Count -gt 0){ '[WARNING] Root certificates installed in last 90 days (Ruby Sleet drops fake roots):'; $r ^| Select-Object Subject,Thumbprint,NotBefore,NotAfter ^| Format-Table -AutoSize } else { '[OK] No new root certificates installed in last 90 days.' } > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

echo.>> "%REPORT%"
echo --- [VOLT TYPHOON] VPN Client Processes --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,ExecutablePath>> "%REPORT%"
wmic process get Name,ProcessId,ExecutablePath > "%TEMP%\dz_pipe.tmp" 2>nul
if errorlevel 1 (
    echo [INFO] wmic unavailable -- VPN client process check skipped.>> "%REPORT%"
) else (
    findstr /i /c:"FortiClient" /c:"GlobalProtect" /c:"pulse" /c:"ivanti" /c:"vpnclient" "%TEMP%\dz_pipe.tmp">> "%REPORT%"
    if errorlevel 1 echo [OK] No targeted VPN client processes running.>> "%REPORT%"
)
del "%TEMP%\dz_pipe.tmp" 2>nul
echo.>> "%REPORT%"

echo --- [LINEN/VIOLET TYPHOON] Accessibility Login-Screen Backdoor (T1546.008) --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty ^(Join-Path $base $b^) -Name Debugger -EA SilentlyContinue">> "%REPORT%"
echo MITRE T1546.008: Chinese nation-state actors Linen Typhoon and Violet Typhoon were>> "%REPORT%"
echo observed using accessibility binary hijacking alongside SharePoint CVE exploitation.>> "%REPORT%"
echo Two methods: (1) WinRE file swap of sethc.exe/utilman.exe with cmd.exe (BitLocker>> "%REPORT%"
echo stops this); (2) IFEO Debugger registry entry (no file modification needed, bypasses>> "%REPORT%"
echo Windows Resource Protection). Pressing Shift x5 or Win+U at login screen then gives>> "%REPORT%"
echo an unauthenticated SYSTEM-level command prompt. Effective against RDP connections too.>> "%REPORT%"
echo.>> "%REPORT%"
echo Check IFEO Debugger entries for all 7 known accessibility targets: >> "%REPORT%"
echo $accBins = @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') > "%PSRUN%"
echo $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' >> "%PSRUN%"
echo $any = $false >> "%PSRUN%"
echo foreach ($b in $accBins) { >> "%PSRUN%"
echo   $d = Get-ItemProperty (Join-Path $base $b) -Name Debugger -EA SilentlyContinue >> "%PSRUN%"
echo   if ($d) { $any = $true; Write-Output ('[CRITICAL][T1546.008] '+$b+' IFEO Debugger = '+$d.Debugger) } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if (-not $any) { Write-Output '[OK] No IFEO accessibility backdoor entries found (Linen/Violet Typhoon check).' } >> "%PSRUN%"
echo Write-Output '' >> "%PSRUN%"
echo # Check whether Defender has logged Win32/AccessibilityEscalation detection >> "%PSRUN%"
echo $det = Get-MpThreatDetection -EA SilentlyContinue ^| Where-Object { $_.ThreatName -match 'AccessibilityEscalation' } >> "%PSRUN%"
echo if ($det) { Write-Output ('[CRITICAL] Defender previously detected Win32/AccessibilityEscalation on this system.'); $det ^| Select-Object ThreatName,ActionSuccess,InitialDetectionTime ^| Format-Table -AutoSize } else { Write-Output '[OK] No Win32/AccessibilityEscalation Defender detections on record.' } >> "%PSRUN%"
echo Write-Output '' >> "%PSRUN%"
echo # Check file hashes for sethc.exe and utilman.exe (most commonly replaced) >> "%PSRUN%"
echo foreach ($b in @('sethc.exe','utilman.exe')) { >> "%PSRUN%"
echo   $f = "$env:SystemRoot\System32\$b" >> "%PSRUN%"
echo   if (Test-Path $f) { >> "%PSRUN%"
echo     $h = (Get-FileHash $f -Algorithm SHA256).Hash >> "%PSRUN%"
echo     $sig = Get-AuthenticodeSignature $f >> "%PSRUN%"
echo     Write-Output ($b+' SHA256: '+$h) >> "%PSRUN%"
echo     Write-Output ($b+' Signature: '+$sig.Status+' / '+$sig.SignerCertificate.Subject) >> "%PSRUN%"
echo     if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { Write-Output ('[CRITICAL] '+$b+' may have been replaced with a non-Microsoft binary^^!') } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"


:: ---- Section 17/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC17_PREV_CODE%" (
    echo  [SECTION 17/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 17/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
set "SEC18_PREV_CODE=%EXIT_CODE%"
echo %C_CYAN%[18/18]%C_RESET% CTI-enhanced TTP detection (2024-2026 threat landscape)...
:: ====================================================================
echo ====================================================================>> "%REPORT%"
echo  [18/18] CTI-DRIVEN IOC SWEEP AND TTP DETECTION>> "%REPORT%"
echo  Source: SENTINEL-X CTI Skill + MITRE ATT^&CK v15+>> "%REPORT%"
echo  IOC Files: %SCRIPT_DIR%ThreatLists\>> "%REPORT%"
echo  Coverage: APT, Ransomware, Credential, Supply Chain, LOLBins, C2,>> "%REPORT%"
echo  DLL hijacking, BYOVD, AiTM phishing, COM hijacking, cloud token theft,>> "%REPORT%"
echo  living-off-the-cloud techniques, and 2024-2026 threat landscape TTPs.>> "%REPORT%"
echo  Scanned: %date% %time%>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

:: Check if ThreatLists directory exists with IOC files
:: Try script directory first, then output directory as fallback
set "IOCDIR=%SCRIPT_DIR%ThreatLists"
if not exist "%IOCDIR%\ioc_processes.txt" set "IOCDIR=%OUTDIR%\ThreatLists"
if not exist "%IOCDIR%\ioc_processes.txt" (
    echo  [SKIP] No ThreatLists directory found at:>> "%REPORT%"
    echo    Checked: %SCRIPT_DIR%ThreatLists\>> "%REPORT%"
    echo    Checked: %OUTDIR%\ThreatLists\>> "%REPORT%"
    echo  [INFO] Place IOC files in either location or run with -updateTTP.>> "%REPORT%"
    echo %C_MAGENTA%[18/18] Skipped%C_RESET% - no IOC files found. Continuing with inline CTI checks.
    goto :sec18_ctilive
)
echo  IOC directory: %IOCDIR%>> "%REPORT%"

:: Copy IOC files to output dir for reference
if not exist "%OUTDIR%\ThreatLists" mkdir "%OUTDIR%\ThreatLists"
copy "%IOCDIR%\*.txt" "%OUTDIR%\ThreatLists\" >nul 2>&1

echo.>> "%REPORT%"
echo --- [18a] Process IOC Match --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,ExecutablePath ^| findstr /i /g:"%IOCDIR%\ioc_processes.txt" ^| findstr /v /c:"#">> "%REPORT%"
echo  Matching running processes against ioc_processes.txt>> "%REPORT%"
wmic process get Name,ProcessId,ExecutablePath 2>nul | findstr /i /g:"%IOCDIR%\ioc_processes.txt" | findstr /v /c:"#">> "%REPORT%" 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] Process IOC matches found above. Investigate immediately.>> "%REPORT%"
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] No process IOC matches.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- [18b] Named Pipe IOC Match --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem \\.\pipe\ -EA SilentlyContinue">> "%REPORT%"
echo  Matching named pipes against ioc_named_pipes.txt>> "%REPORT%"
echo $iocFile='%IOCDIR%\ioc_named_pipes.txt' > "%PSRUN%"
echo $patterns=Get-Content $iocFile ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo $pipes=Get-ChildItem \\.\pipe\ -EA SilentlyContinue >> "%PSRUN%"
echo $hits=@() >> "%PSRUN%"
echo foreach($p in $patterns){try{$m=$pipes ^| Where-Object {$_.Name -match $p}; if($m){$hits+=$m}}catch{}} >> "%PSRUN%"
echo if($hits.Count -gt 0){$hits ^| Select-Object -Unique Name; '[WARNING] Named pipe IOC matches found.'; New-Item "$env:TEMP\dz_iochit_18b.txt" -Force ^| Out-Null}else{'[OK] No named pipe IOC matches.'} >> "%PSRUN%"
del "%TEMP%\dz_iochit_18b.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_iochit_18b.txt" (
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    del "%TEMP%\dz_iochit_18b.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- [18c] Service IOC Match --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_Service -EA SilentlyContinue">> "%REPORT%"
echo  Matching services against ioc_services.txt>> "%REPORT%"
echo $iocFile='%IOCDIR%\ioc_services.txt' > "%PSRUN%"
echo $patterns=Get-Content $iocFile ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo $svcs=Get-CimInstance Win32_Service -EA SilentlyContinue >> "%PSRUN%"
echo $hits=@() >> "%PSRUN%"
echo foreach($p in $patterns){try{$m=$svcs ^| Where-Object {$_.Name -match $p -or $_.DisplayName -match $p}; if($m){$hits+=$m}}catch{}} >> "%PSRUN%"
echo if($hits.Count -gt 0){$hits ^| Select-Object Name,State,PathName ^| Format-Table -AutoSize; '[WARNING] Service IOC matches found.'; New-Item "$env:TEMP\dz_iochit_18c.txt" -Force ^| Out-Null}else{'[OK] No service IOC matches.'} >> "%PSRUN%"
del "%TEMP%\dz_iochit_18c.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_iochit_18c.txt" (
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    del "%TEMP%\dz_iochit_18c.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- [18d] Suspicious File Path IOC Check --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $expanded^){$hits+=$expanded}">> "%REPORT%"
echo  Checking for known malware staging paths from ioc_file_paths.txt>> "%REPORT%"
echo $iocFile='%IOCDIR%\ioc_file_paths.txt' > "%PSRUN%"
echo $paths=Get-Content $iocFile ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo $hits=@() >> "%PSRUN%"
echo foreach($p in $paths){ >> "%PSRUN%"
echo   $expanded=[System.Environment]::ExpandEnvironmentVariables($p.Trim()) >> "%PSRUN%"
echo   if(Test-Path $expanded){$hits+=$expanded} >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if($hits.Count -gt 0){'[CRITICAL] Known malware staging files found:'; $hits; '[ACTION] Quarantine these files immediately.'; New-Item "$env:TEMP\dz_iochit_18d.txt" -Force ^| Out-Null}else{'[OK] No known malware staging files found.'} >> "%PSRUN%"
del "%TEMP%\dz_iochit_18d.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_iochit_18d.txt" (
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    del "%TEMP%\dz_iochit_18d.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- [18e] Scheduled Task IOC Match --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $iocFile^) { Get-Content $iocFile">> "%REPORT%"
echo  Matching scheduled task NAMES and ACTIONS against ioc_scheduled_tasks.txt>> "%REPORT%"
echo $iocFile = '%IOCDIR%\ioc_scheduled_tasks.txt' > "%PSRUN%"
echo $patterns = if (Test-Path $iocFile) { Get-Content $iocFile ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} } >> "%PSRUN%"
echo $tasks = (schtasks /query /fo CSV /v 2^>$null) ^| ConvertFrom-Csv -EA SilentlyContinue >> "%PSRUN%"
echo if (-not $tasks) { '[INFO] schtasks returned no data -- IOC check skipped.' } elseif (-not $patterns) { '[INFO] ioc_scheduled_tasks.txt missing or empty.' } else { $hits = @(); foreach ($p in $patterns) { $rx = $p.Trim(); $hits += $tasks ^| Where-Object { ($_.TaskName -match $rx) -or ($_."Task To Run" -match $rx) } }; $hits = @($hits ^| Sort-Object TaskName,'Task To Run' -Unique); if ($hits.Count -gt 0) { $hits ^| Select-Object TaskName,'Task To Run' ^| Format-Table -AutoSize; '[WARNING] Scheduled task IOC matches found.'; New-Item "$env:TEMP\dz_iochit_18e.txt" -Force ^| Out-Null } else { '[OK] No scheduled task IOC matches.' } } >> "%PSRUN%"
del "%TEMP%\dz_iochit_18e.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_iochit_18e.txt" (
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    del "%TEMP%\dz_iochit_18e.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- [18f] DNS Cache C2 Domain Match --->> "%REPORT%"
echo  Command: ipconfig /displaydns ^| findstr /i /g:"%IOCDIR%\ioc_domains.txt" ^| findstr /v /c:"#">> "%REPORT%"
echo  Matching DNS cache against ioc_domains.txt>> "%REPORT%"
ipconfig /displaydns 2>nul | findstr /i /g:"%IOCDIR%\ioc_domains.txt" | findstr /v /c:"#">> "%REPORT%" 2>&1
if %errorlevel% equ 0 (
    echo [WARNING] C2 domain IOC matches found in DNS cache above.>> "%REPORT%"
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] No C2 domain IOC matches in DNS cache.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- [18g] LOLBin Command-Line Pattern Match --->> "%REPORT%"
echo  Command: wmic process get Name,ProcessId,CommandLine ^| select_lines.ps1 -PatternFile "%IOCDIR%\ioc_lolbins.txt">> "%REPORT%"
echo  Matching process command lines against ioc_lolbins.txt>> "%REPORT%"
wmic process get Name,ProcessId,CommandLine > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" -PatternFile "%IOCDIR%\ioc_lolbins.txt">> "%REPORT%" 2>&1
:: Capture select_lines's exit before del overwrites errorlevel. select_lines
:: mirrors findstr's convention: 0 = at least one match emitted, 1 = none.
set "_SELECT_EXIT=!errorlevel!"
del "%TEMP%\dz_evt.tmp" 2>nul
if "!_SELECT_EXIT!"=="0" (
    echo [CRITICAL] LOLBin abuse patterns detected in running processes.>> "%REPORT%"
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
) else (
    echo [OK] No LOLBin abuse patterns in running processes.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- [18h] Registry IOC Check --->> "%REPORT%"
echo  Command: powershell -Command "Get-ItemProperty $psPath -Name $valName -EA Stop">> "%REPORT%"
echo  Checking suspicious registry keys from ioc_registry.txt>> "%REPORT%"
echo $iocFile='%IOCDIR%\ioc_registry.txt' > "%PSRUN%"
echo $lines=Get-Content $iocFile ^| Where-Object {$_ -and $_ -notmatch '^\s*#'} >> "%PSRUN%"
echo $hits=@() >> "%PSRUN%"
echo foreach($line in $lines){ >> "%PSRUN%"
echo   $parts=$line.Split('^|'); $keyPath=$parts[0]; $valName=if($parts.Count -gt 1){$parts[1]}else{$null} >> "%PSRUN%"
echo   $psPath=$keyPath -replace '^HKLM\\','HKLM:\' -replace '^HKCU\\','HKCU:\' >> "%PSRUN%"
echo   try{ >> "%PSRUN%"
echo     if($valName){$v=Get-ItemProperty $psPath -Name $valName -EA Stop; $hits+="$keyPath\$valName = $($v.$valName)"} >> "%PSRUN%"
echo     else{if(Test-Path $psPath){$hits+="$keyPath [EXISTS]"}} >> "%PSRUN%"
echo   }catch{} >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if($hits.Count -gt 0){'[WARNING] Suspicious registry IOCs found:'; $hits; New-Item "$env:TEMP\dz_iochit_18h.txt" -Force ^| Out-Null}else{'[OK] No suspicious registry IOC matches.'} >> "%PSRUN%"
del "%TEMP%\dz_iochit_18h.txt" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
if exist "%TEMP%\dz_iochit_18h.txt" (
    set /a IOC_HITS+=1
    if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
    del "%TEMP%\dz_iochit_18h.txt" 2>nul
)

echo.>> "%REPORT%"
echo --- [18i] TTP Coverage Summary --->> "%REPORT%"
echo  Command: findstr /v /c:"#" "%IOCDIR%\ttp_manifest.txt" ^| findstr /v /r "^^$">> "%REPORT%"
echo  MITRE ATT^&CK techniques covered by this audit:>> "%REPORT%"
if exist "%IOCDIR%\ttp_manifest.txt" (
    findstr /v /c:"#" "%IOCDIR%\ttp_manifest.txt" | findstr /v /r "^$">> "%REPORT%" 2>&1
) else (
    echo  [INFO] ttp_manifest.txt not found.>> "%REPORT%"
)

if "%VT_CHECK%"=="1" (
    echo.>> "%REPORT%"
    echo --- [18j] VirusTotal File Hash Reputation --->> "%REPORT%"
    echo  Command: powershell -File tools\vt_check.ps1>> "%REPORT%"
    echo  Querying VirusTotal for SHA256 hashes of priority candidate files.>> "%REPORT%"
    echo  Source: https://docs.virustotal.com/reference/file-info ^| API key from %%USERPROFILE%%\.vt_token>> "%REPORT%"
    echo  NOTE: only file hashes are submitted; file contents are never uploaded.>> "%REPORT%"
    if exist "%SCRIPT_DIR%tools\vt_check.ps1" (
        "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\vt_check.ps1">> "%REPORT%" 2>&1
        if exist "%TEMP%\dz_iochit_18j.txt" (
            set /a IOC_HITS+=1
            if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
            del "%TEMP%\dz_iochit_18j.txt" 2>nul
        )
    ) else (
        echo  [INFO] tools\vt_check.ps1 not found -- VT check skipped.>> "%REPORT%"
    )
)

if "%VT_CHECK%"=="1" (
    echo.>> "%REPORT%"
    echo --- [18l] VirusTotal IP Reputation --->> "%REPORT%"
    echo  Command: powershell -File tools\vt_ip_check.ps1>> "%REPORT%"
    echo  Querying VirusTotal for active TCP remote endpoints ^(public IPs only^).>> "%REPORT%"
    echo  Source: https://docs.virustotal.com/reference/ip-info ^| API key from %%USERPROFILE%%\.vt_token>> "%REPORT%"
    echo  NOTE: only IP literals are submitted; connection metadata is never sent.>> "%REPORT%"
    if exist "%SCRIPT_DIR%tools\vt_ip_check.ps1" (
        "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\vt_ip_check.ps1">> "%REPORT%" 2>&1
        if exist "%TEMP%\dz_iochit_18l.txt" (
            set /a IOC_HITS+=1
            if !EXIT_CODE! LSS 2 set "EXIT_CODE=2"
            del "%TEMP%\dz_iochit_18l.txt" 2>nul
        )
    ) else (
        echo  [INFO] tools\vt_ip_check.ps1 not found -- VT IP check skipped.>> "%REPORT%"
    )
)

:: Section 18k: local SHA256 hash matching against ioc_hashes.txt.
:: Always-on (offline-only, no rate limit, no API key, no network).
:: Complements 18j (-vt) which does network reputation lookups.
echo.>> "%REPORT%"
echo --- [18k] Local Hash IOC Match (ioc_hashes.txt) --->> "%REPORT%"
echo  Command: powershell -File tools\ioc_hash_check.ps1>> "%REPORT%"
echo  Hashing priority files on disk and matching SHA256 against ioc_hashes.txt.>> "%REPORT%"
echo  No network calls; complements [18j] -vt VirusTotal lookup.>> "%REPORT%"
if exist "%SCRIPT_DIR%tools\ioc_hash_check.ps1" (
    if exist "%IOCDIR%\ioc_hashes.txt" (
        del "%TEMP%\dz_iochit_18k.txt" 2>nul
        "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\ioc_hash_check.ps1" -IocFile "%IOCDIR%\ioc_hashes.txt" >> "%REPORT%" 2>&1
        if exist "%TEMP%\dz_iochit_18k.txt" (
            set /a IOC_HITS+=1
            if !EXIT_CODE! LSS 2 set "EXIT_CODE=2"
            del "%TEMP%\dz_iochit_18k.txt" 2>nul
        )
    ) else (
        echo  [INFO] %IOCDIR%\ioc_hashes.txt not found -- local hash check skipped.>> "%REPORT%"
    )
) else (
    echo  [INFO] tools\ioc_hash_check.ps1 not found -- local hash check skipped.>> "%REPORT%"
)

echo.>> "%REPORT%"
echo --- [18 SUMMARY] IOC Sweep Results --->> "%REPORT%"
if "!IOC_HITS!"=="0" (
    echo [OK] No threat indicator matches found across all IOC categories.>> "%REPORT%"
) else (
    echo [WARNING] !IOC_HITS! IOC category matches found. Review [WARNING] and [CRITICAL] entries above.>> "%REPORT%"
)
echo.>> "%REPORT%"

:: Entry point for the inline CTI checks. Reached either by falling through
:: from the IOC-file sweep above (normal flow) or by `goto :sec18_ctilive`
:: in the no-IOC-files-found path. Both flows land here so the inline checks
:: always run regardless of IOC file availability.
:sec18_ctilive
:: --- [CTI] Sliver / Havoc / Brute Ratel Named Pipes (next-gen C2) ---
echo.>> "%REPORT%"
echo --- [CTI] Sliver / Havoc / Brute Ratel C2 Named Pipes --->> "%REPORT%"
echo  Command: powershell -Command "Get-ChildItem \\.\pipe\ -EA SilentlyContinue">> "%REPORT%"
echo try{$pipes=Get-ChildItem \\.\pipe\ -EA SilentlyContinue ^| Where-Object {$_.Name -match 'sliverpb^|havoc^|bruteratel^|badger_^|b4_^|_krbtgt^|dcetest^|systemd-^|svc_pivot'}; if($pipes){$pipes ^| Select-Object Name; '[WARNING] Possible next-gen C2 named pipes detected.'}else{'[OK] No Sliver/Havoc/BruteRatel default pipes.'}}catch{'[INFO] Pipe enumeration unavailable.'} > "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] DLL Search Order Hijacking (T1574.001) ---
echo.>> "%REPORT%"
echo --- [CTI][T1574.001] DLL Search Order Hijacking - Suspicious DLLs in System Paths --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $f^) {">> "%REPORT%"
echo $suspDlls = @('version.dll','winhttp.dll','dbghelp.dll','dbgcore.dll','wer.dll','ualapi.dll','WTSAPI32.dll','msasn1.dll','npmproxy.dll') > "%PSRUN%"
echo $sysDirs = @("$env:SystemRoot\System32","$env:SystemRoot\SysWOW64","$env:ProgramFiles","${env:ProgramFiles(x86)}") >> "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($dir in $sysDirs) { >> "%PSRUN%"
echo   foreach ($dll in $suspDlls) { >> "%PSRUN%"
echo     $f = Join-Path $dir $dll >> "%PSRUN%"
echo     if (Test-Path $f) { >> "%PSRUN%"
echo       $sig = Get-AuthenticodeSignature $f -EA SilentlyContinue >> "%PSRUN%"
echo       if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { >> "%PSRUN%"
echo         $hits += $f + ' [SIG: ' + $sig.Status + ']' >> "%PSRUN%"
echo       } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[WARNING][T1574.001] Unsigned/suspicious DLLs in system paths:'; $hits ^| ForEach-Object { '  '+$_ } } else { '[OK] No suspicious unsigned DLLs found in system paths.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] LOLBin Download/Execute Chains (T1105+T1059) ---
echo.>> "%REPORT%"
echo --- [CTI][T1105+T1059] LOLBin Download Cradles in Event 4688 (last 24h) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4688^)]]" /c:1000 /rd:true /f:text ^| select_lines.ps1 "bitsadmin" "certutil -urlcache" "curl " "wget" "Invoke-WebRequest" "Start-BitsTransfer" "desktopimgdownldr" "esentutl">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4688) and TimeCreated[@SystemTime>='%WEVT_24H_AGO%']]]" /c:1000 /rd:true /f:text > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" "bitsadmin" "certutil -urlcache" "curl " "wget" "Invoke-WebRequest" "Start-BitsTransfer" "desktopimgdownldr" "esentutl">> "%REPORT%" 2>&1
del "%TEMP%\dz_evt.tmp" 2>nul

:: --- [CTI] AMSI Bypass Artifacts in PowerShell Logs (T1562.001) ---
echo.>> "%REPORT%"
echo --- [CTI][T1562.001] AMSI Bypass Patterns in PowerShell Event 4104 --->> "%REPORT%"
echo  Command: powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'">> "%REPORT%"
echo $evts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 -EA SilentlyContinue > "%PSRUN%"
echo $amsi = @('AmsiUtils','amsiInitFailed','AmsiScanBuffer','SetProtectedState','Reflection.Assembly','System.Management.Automation.AmsiUtils','amsiscanbuffer','amsi.dll','Unmanaged.*amsi') >> "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo if ($evts) { >> "%PSRUN%"
echo   foreach ($e in $evts) { >> "%PSRUN%"
echo     foreach ($p in $amsi) { >> "%PSRUN%"
echo       if ($e.Message -match $p) { $hits += ('['+$e.TimeCreated+'] Pattern: '+$p); break } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[WARNING][T1562.001] AMSI bypass attempts detected in PS logs:'; $hits ^| Select-Object -First 10 ^| ForEach-Object { '  '+$_ } } else { '[OK] No AMSI bypass patterns in recent PowerShell Script Block logs.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] Credential Access via DPAPI (T1555.003 / T1555.004) ---
echo.>> "%REPORT%"
echo --- [CTI][T1555.003] Browser Credential Store Access (DPAPI) --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $p^) {">> "%REPORT%"
echo $paths = @( > "%PSRUN%"
echo   "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data", >> "%PSRUN%"
echo   "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data", >> "%PSRUN%"
echo   "$env:APPDATA\Mozilla\Firefox\Profiles" >> "%PSRUN%"
echo ) >> "%PSRUN%"
echo $recent = @() >> "%PSRUN%"
echo foreach ($p in $paths) { >> "%PSRUN%"
echo   if (Test-Path $p) { >> "%PSRUN%"
echo     $item = Get-Item $p -EA SilentlyContinue >> "%PSRUN%"
echo     if ($item.LastAccessTime -gt (Get-Date).AddHours(-24)) { >> "%PSRUN%"
echo       $recent += $p + ' accessed ' + $item.LastAccessTime >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($recent.Count -gt 0) { '[INFO] Browser credential stores accessed in last 24h (may be normal browser activity):'; $recent ^| ForEach-Object { '  '+$_ } } else { '[OK] No unusual recent access to browser credential stores.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] AiTM Phishing / Token Theft Artifacts (T1557.001) ---
echo.>> "%REPORT%"
echo --- [CTI][T1557.001] AiTM Phishing - Suspicious AAD Token Cache --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $tp^) {">> "%REPORT%"
echo $tokenPaths = @( > "%PSRUN%"
echo   "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache", >> "%PSRUN%"
echo   "$env:LOCALAPPDATA\Microsoft\Credentials", >> "%PSRUN%"
echo   "$env:LOCALAPPDATA\.IdentityService" >> "%PSRUN%"
echo ) >> "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($tp in $tokenPaths) { >> "%PSRUN%"
echo   if (Test-Path $tp) { >> "%PSRUN%"
echo     $files = Get-ChildItem $tp -Recurse -EA SilentlyContinue ^| Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } >> "%PSRUN%"
echo     if ($files) { $hits += $tp + ': ' + $files.Count + ' file(s) modified in last 2h' } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[INFO] Recent AAD/token cache activity (correlate with login events):'; $hits ^| ForEach-Object { '  '+$_ } } else { '[OK] No unusual recent token cache modifications.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] Ransomware Precursors (T1490 + T1486) ---
echo.>> "%REPORT%"
echo --- [CTI][T1490] Ransomware Precursors - VSS/BCDEdit/Recovery Tampering (last 24h) --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4688^)]]" /c:1000 /rd:true /f:text ^| select_lines.ps1 "vssadmin delete" "wmic shadowcopy" "bcdedit /set {default} recoveryenabled no" "wbadmin delete" "disableshadowcopy">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4688) and TimeCreated[@SystemTime>='%WEVT_24H_AGO%']]]" /c:1000 /rd:true /f:text > "%TEMP%\dz_evt.tmp" 2>nul
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\select_lines.ps1" -Path "%TEMP%\dz_evt.tmp" "vssadmin delete" "wmic shadowcopy" "bcdedit /set {default} recoveryenabled no" "wbadmin delete" "disableshadowcopy">> "%REPORT%" 2>&1
del "%TEMP%\dz_evt.tmp" 2>nul

echo.>> "%REPORT%"
echo --- [CTI][T1486] Ransomware File Extension Survey --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $d^) {">> "%REPORT%"
echo $exts = @('.encrypted','.locked','.crypt','.locky','.cerber','.zepto','.thor','.aesir','.zzzzz','.WNCRY','.wcry','.rdmk','.PLAY','.black','.basta','.royal','.akira','.lockbit','.clop') > "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($d in @($env:USERPROFILE,"$env:SystemDrive\Users\Public",$env:TEMP)) { >> "%PSRUN%"
echo   if (Test-Path $d) { >> "%PSRUN%"
echo     foreach ($ext in $exts) { >> "%PSRUN%"
echo       $f = Get-ChildItem $d -Filter "*$ext" -Recurse -EA SilentlyContinue -Depth 3 ^| Select-Object -First 3 >> "%PSRUN%"
echo       if ($f) { $hits += $f ^| ForEach-Object { $_.FullName } } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[CRITICAL][T1486] Files with ransomware-associated extensions found:'; $hits ^| Select-Object -First 20 ^| ForEach-Object { '  '+$_ } } else { '[OK] No files with known ransomware extensions in user directories.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] EDR/AV Tampering via Driver Load (T1562.001) ---
echo.>> "%REPORT%"
echo --- [CTI][T1562.001] Kernel Driver Tampering (BYOVD - Bring Your Own Vulnerable Driver) --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $f^) { $hits += $f }">> "%REPORT%"
echo $byovd = @('RTCore64.sys','DBUtil_2_3.sys','gdrv.sys','cpuz141.sys','AsIO64.sys','HW64.sys','WinIO64.sys','IQVW64E.sys','kprocesshacker.sys','ProcExp152.sys','zemana.sys','viragt64.sys') > "%PSRUN%"
echo $drvDir = "$env:SystemRoot\System32\drivers" >> "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo foreach ($drv in $byovd) { >> "%PSRUN%"
echo   $f = Join-Path $drvDir $drv >> "%PSRUN%"
echo   if (Test-Path $f) { $hits += $f } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[CRITICAL][T1562.001] Known BYOVD (vulnerable driver) files present:'; $hits ^| ForEach-Object { '  '+$_ }; '[WARNING] Attackers use these to disable EDR/AV from kernel. Remove immediately.' } else { '[OK] No known BYOVD exploit drivers found in drivers directory.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] Suspicious Service Creation - Event 7045 Anomalies ---
echo.>> "%REPORT%"
echo --- [CTI][T1543.003] Suspicious Service Installs (Event 7045 from Temp/Public) --->> "%REPORT%"
echo  Command: powershell -Command "Get-WinEvent -FilterHashtable @{LogName='System'">> "%REPORT%"
echo $evts = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 50 -EA SilentlyContinue > "%PSRUN%"
echo $hits = @() >> "%PSRUN%"
echo if ($evts) { >> "%PSRUN%"
echo   foreach ($e in $evts) { >> "%PSRUN%"
echo     $msg = $e.Message >> "%PSRUN%"
echo     if ($msg -match '\\Temp\\^|\\AppData\\^|\\Users\\Public\\^|\\Downloads\\^|cmd\.exe^|powershell^|mshta^|regsvr32') { >> "%PSRUN%"
echo       $hits += '['+$e.TimeCreated+'] '+($msg -replace '[\r\n]+',' ' ^| Select-Object -First 1) >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($hits.Count -gt 0) { '[WARNING][T1543.003] Suspicious service installations found:'; $hits ^| Select-Object -First 10 ^| ForEach-Object { '  '+$_ } } else { '[OK] No suspicious service installations in recent Event 7045 logs.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] COM Object Hijacking (T1546.015) ---
echo.>> "%REPORT%"
echo --- [CTI][T1546.015] COM Object Hijacking - User CLSID Overrides --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $clsids^) {">> "%REPORT%"
echo $defProp = [char]40 + 'default' + [char]41 > "%PSRUN%"
echo $clsids = 'HKCU:\Software\Classes\CLSID' >> "%PSRUN%"
echo $vendor = @() >> "%PSRUN%"
echo $flagged = @() >> "%PSRUN%"
echo $trusted = '\bMicrosoft\b^|\bAdobe\b^|\bBrave\b^|\bGoogle\b^|\bMozilla\b^|\bWinSCP\b^|\bCisco\b^|\bCitrix\b^|\bLogitech\b^|\bVMware\b^|\bDropbox\b^|\bZoom\b^|\bApple\b^|\bNVIDIA\b^|\bIntel\b^|\bRealtek\b^|\bLenovo\b^|\bHP Inc\b^|\bDell\b' >> "%PSRUN%"
echo if (Test-Path $clsids) { >> "%PSRUN%"
echo   foreach ($k in (Get-ChildItem $clsids -EA SilentlyContinue)) { >> "%PSRUN%"
echo     $sv = Get-ItemProperty "$($k.PSPath)\InprocServer32" -Name $defProp -EA SilentlyContinue >> "%PSRUN%"
echo     if ($sv -and $sv.$defProp -and $sv.$defProp -notmatch 'Microsoft^|Windows^|System32') { >> "%PSRUN%"
echo       $dll = [string]$sv.$defProp >> "%PSRUN%"
echo       $entry = $k.PSChildName + ' -^> ' + $dll >> "%PSRUN%"
echo       $bad = ($dll -match '\\Temp\\^|\\Downloads\\^|\\Public\\') >> "%PSRUN%"
echo       $sig = $null; try { $sig = Get-AuthenticodeSignature -FilePath $dll -EA Stop } catch {} >> "%PSRUN%"
echo       $certIssue = '' >> "%PSRUN%"
echo       if ($sig -and $sig.SignerCertificate) { >> "%PSRUN%"
echo         try { if (-not (Test-Certificate -Cert $sig.SignerCertificate -EA Stop)) { $certIssue = 'cert-invalid' } } catch {} >> "%PSRUN%"
echo         if ($certIssue -eq '' -and $sig.SignerCertificate.NotAfter -lt (Get-Date) -and -not $sig.TimeStamperCertificate) { $certIssue = 'cert-expired' } >> "%PSRUN%"
echo       } >> "%PSRUN%"
echo       if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match $trusted -and -not $bad -and $certIssue -eq '') { >> "%PSRUN%"
echo         $cn = (($sig.SignerCertificate.Subject -split ',')[0]) -replace '^^CN=','' >> "%PSRUN%"
echo         $vendor += $entry + '   [signed: ' + $cn + ']' >> "%PSRUN%"
echo       } else { >> "%PSRUN%"
echo         if ($null -eq $sig) { $why = 'no-file' } elseif ($certIssue) { $why = if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match $trusted) { 'trusted-but-' + $certIssue } else { $certIssue } } elseif ($sig.Status -eq 'Valid') { $why = if ($sig.SignerCertificate.Subject -match $trusted) { 'trusted-signer' } else { 'unexpected-signer' } } elseif ($sig.Status -eq 'NotSigned') { $why = 'unsigned' } else { $why = [string]$sig.Status } >> "%PSRUN%"
echo         if ($bad) { $why = $why + ' bad-path' } >> "%PSRUN%"
echo         $flagged += $entry + '   [' + $why + ']' >> "%PSRUN%"
echo       } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($flagged.Count -gt 0) { '[WARNING][T1546.015] Suspicious COM CLSID overrides ('+$flagged.Count+'):'; $flagged ^| Select-Object -First 15 ^| ForEach-Object { '  '+$_ } } >> "%PSRUN%"
echo if ($vendor.Count -gt 0) { '[INFO][T1546.015] Vendor-registered user CLSID overrides ('+$vendor.Count+', expected):'; $vendor ^| Select-Object -First 15 ^| ForEach-Object { '  '+$_ } } >> "%PSRUN%"
echo if ($flagged.Count -eq 0 -and $vendor.Count -eq 0) { '[OK] No user-level COM CLSID overrides.' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] Living-off-the-Cloud: Azure/M365 CLI Token Files ---
echo.>> "%REPORT%"
echo --- [CTI] Cloud Token Theft - Azure/AWS/GCP CLI Credential Files --->> "%REPORT%"
echo  Command: powershell -Command "Test-Path $c.Path^) {">> "%REPORT%"
echo $cloudCreds = @( > "%PSRUN%"
echo   @{Name='Azure CLI';Path="$env:USERPROFILE\.azure\accessTokens.json"}, >> "%PSRUN%"
echo   @{Name='Azure CLI MSAL';Path="$env:USERPROFILE\.azure\msal_token_cache.json"}, >> "%PSRUN%"
echo   @{Name='AWS CLI';Path="$env:USERPROFILE\.aws\credentials"}, >> "%PSRUN%"
echo   @{Name='GCP';Path="$env:APPDATA\gcloud\credentials.db"}, >> "%PSRUN%"
echo   @{Name='GCP ADC';Path="$env:APPDATA\gcloud\application_default_credentials.json"}, >> "%PSRUN%"
echo   @{Name='kubectl';Path="$env:USERPROFILE\.kube\config"} >> "%PSRUN%"
echo ) >> "%PSRUN%"
echo $found = @() >> "%PSRUN%"
echo foreach ($c in $cloudCreds) { >> "%PSRUN%"
echo   if (Test-Path $c.Path) { >> "%PSRUN%"
echo     $item = Get-Item $c.Path >> "%PSRUN%"
echo     $found += $c.Name + ': ' + $c.Path + ' (modified: ' + $item.LastWriteTime + ')' >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($found.Count -gt 0) { '[INFO] Cloud CLI credential files present (verify these are expected):'; $found ^| ForEach-Object { '  '+$_ } } else { '[OK] No cloud CLI credential files found (no cloud attack surface from local tokens).' } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1

:: --- [CTI] Explicit Credential Logon - Event 4648 (T1078) ---
echo.>> "%REPORT%"
echo --- [CTI][T1078] Explicit Credential Logons - Event 4648 --->> "%REPORT%"
echo  Command: wevtutil qe Security /q:"*[System[^(EventID=4648^)]]" /c:20 /rd:true /f:text ^| findstr /c:"TimeCreated" /c:"Subject:" /c:"Account Name" /c:"Target Server">> "%REPORT%"
wevtutil qe Security /q:"*[System[(EventID=4648)]]" /c:20 /rd:true /f:text | findstr /c:"TimeCreated" /c:"Subject:" /c:"Account Name" /c:"Target Server">> "%REPORT%" 2>&1

:: --- [CTI] SSH Server (OpenSSH) Enabled Check ---
echo.>> "%REPORT%"
echo --- [CTI] OpenSSH Server Lateral Movement Surface --->> "%REPORT%"
echo  Command: powershell -Command "Get-Service sshd -EA SilentlyContinue">> "%REPORT%"
echo $ssh = Get-Service sshd -EA SilentlyContinue > "%PSRUN%"
echo if ($ssh -and $ssh.Status -eq 'Running') { >> "%PSRUN%"
echo   $authKeys = "$env:ProgramData\ssh\administrators_authorized_keys" >> "%PSRUN%"
echo   '[WARNING] OpenSSH Server (sshd) is RUNNING' >> "%PSRUN%"
echo   if (Test-Path $authKeys) { >> "%PSRUN%"
echo     $lines = (Get-Content $authKeys -EA SilentlyContinue).Count >> "%PSRUN%"
echo     '[INFO] administrators_authorized_keys has ' + $lines + ' key(s) - verify each is legitimate' >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } elseif ($ssh) { >> "%PSRUN%"
echo   '[OK] OpenSSH Server installed but not running.' >> "%PSRUN%"
echo } else { >> "%PSRUN%"
echo   '[OK] OpenSSH Server not installed.' >> "%PSRUN%"
echo } >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1
echo.>> "%REPORT%"

:: --- [CTI-AUTO] Execute auto-generated TTP blocks from -updateTTP ---
set "TTP_BLOCKS=%OUTDIR%\ThreatLists\ttp_generated_checks.bat"
if exist "%TTP_BLOCKS%" (
    echo.>> "%REPORT%"
    echo --- Executing auto-generated CTI detection blocks --->> "%REPORT%"
    echo %C_CYAN%[18/18]%C_RESET% Running auto-generated TTP checks from SENTINEL-X...
    call "%TTP_BLOCKS%"
)

:: ---- Section 18/18 verdict -----------------------------------------------
echo.>> "%REPORT%"
if "%EXIT_CODE%"=="%SEC18_PREV_CODE%" (
    echo  [SECTION 18/18 RESULT: CLEAN -- no issues detected]>> "%REPORT%"
) else (
    echo  [SECTION 18/18 RESULT: ISSUES FOUND -- review [WARNING] entries above]>> "%REPORT%"
)
echo ====================================================================>> "%REPORT%"
:: ====================================================================
:: POST-AUDIT: FREE SPACE CAPTURE AND LIVE SECURITY SUMMARY
:: ====================================================================
echo --- Post-Audit Free Space --->> "%REPORT%"
echo  Command: powershell -Command "Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='%SystemDrive%'" -EA SilentlyContinue^).FreeSpace">> "%REPORT%"
echo (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='%SystemDrive%'" -EA SilentlyContinue).FreeSpace > "%PSRUN%"
for /f "usebackq" %%a in (`%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2^>nul`) do (
    if not "%%a"=="" if not "%%a"=="0" set "FREE_AFTER=%%a"
)
if not "%FREE_AFTER%"=="0" goto :freeafter_done
for /f "tokens=2 delims==" %%a in ('wmic logicaldisk where "DeviceID=^'%SystemDrive%^'" get FreeSpace /value 2^>nul') do (
    if not "%%a"=="" set "FREE_AFTER=%%a"
)
set "FREE_AFTER=%FREE_AFTER: =%"
:freeafter_done
echo Free space before audit : %FREE_BEFORE% bytes>> "%REPORT%"
echo Free space after audit  : %FREE_AFTER% bytes>> "%REPORT%"
echo.>> "%REPORT%"

echo.
echo %C_BOLD%%C_WHITE%====================================================================
echo  Computing live security summary...
echo ====================================================================%C_RESET%
echo.

set "SUMFILE=%TEMP%\AuditSummary_%TIMESTAMP%.txt"
set "SUMCODE=%TEMP%\AuditCode_%TIMESTAMP%.txt"
set "REMEDIATION=%OUTDIR%\Remediation_!TIMESTAMP!.ps1"

:: ---- Seed remediation script with a safety header -------------------
:: The script self-aborts unless the user edits the FIRST LINE to flip
:: the IReadAndUnderstand flag. This prevents running a half-baked
:: remediation by accident.
echo # ============================================================== > "%REMEDIATION%"
echo # Remediation script generated by doze_sec v%SCRIPT_VERSION% >> "%REMEDIATION%"
echo # Host: %COMPUTERNAME%    Generated: %date% %time% >> "%REMEDIATION%"
echo # ============================================================== >> "%REMEDIATION%"
echo # REVIEW EVERY LINE BEFORE RUNNING. Some commands reboot or >> "%REMEDIATION%"
echo # change security-critical settings. Run as ADMIN, from a >> "%REMEDIATION%"
echo # trusted PowerShell session. >> "%REMEDIATION%"
echo # >> "%REMEDIATION%"
echo # To enable execution, change $IReadAndUnderstand=$false to $true >> "%REMEDIATION%"
echo # and remove the 'exit 1' below. >> "%REMEDIATION%"
echo # ============================================================== >> "%REMEDIATION%"
echo $IReadAndUnderstand=$false >> "%REMEDIATION%"
echo if(-not $IReadAndUnderstand){ Write-Host '[ABORT] Open Remediation script, review commands, flip $IReadAndUnderstand=$true, then re-run.' -Fore Yellow; exit 1 } >> "%REMEDIATION%"
echo Write-Host 'Applying remediation commands. Press Ctrl+C now to abort.' -Fore Cyan; Start-Sleep -Seconds 3 >> "%REMEDIATION%"
echo. >> "%REMEDIATION%"

:: ---- Write PS summary script ----------------------------------------
:: Uses echo >> PSRUN approach (proven reliable, avoids all batch/PS escaping issues)
echo $sw='%SMART_WARN%' > "%PSRUN%"
echo $isAdmin='1' >> "%PSRUN%"
echo $scf='%SUMCODE%' >> "%PSRUN%"
echo $rem='%REMEDIATION%' >> "%PSRUN%"
echo $r=@();$cr=0;$wa=0;$pa=0;$inf=0 >> "%PSRUN%"
echo function ck($s,$m,$d=''){$icon=if($s-eq 'CRIT'){'[^^!^^! CRITICAL ^^!^^!]'}elseif($s-eq 'WARN'){'[  WARNING   ]'}elseif($s-eq 'PASS'){'[    OK      ]'}else{'[    INFO    ]'};$script:r+='  '+$icon+'  '+$m;if($d){$script:r+='                     Fix: '+$d};switch($s){'CRIT'{$script:cr++}'WARN'{$script:wa++}'PASS'{$script:pa++}'INFO'{$script:inf++}}} >> "%PSRUN%"
echo function sec($t){$script:r+='';$script:r+=('  --- '+$t+' ').PadRight(70,'-')} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== ACTIVE COMPROMISE =============================================
echo sec 'ACTIVE COMPROMISE INDICATORS' >> "%PSRUN%"
echo $ev=Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 1 -EA SilentlyContinue;if($ev){ck 'CRIT' 'Security event log was CLEARED' ('At '+$ev.TimeCreated+' -- attacker erased evidence. Treat as active compromise.')}else{ck 'PASS' 'Security event log has not been cleared'} >> "%PSRUN%"
echo $ev=Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 1 -EA SilentlyContinue;if($ev){ck 'CRIT' 'System event log was CLEARED' ('At '+$ev.TimeCreated)}else{ck 'PASS' 'System event log has not been cleared'} >> "%PSRUN%"
echo $ev=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 5 -EA SilentlyContinue;if($ev){ck 'WARN' "New local accounts created: $(@($ev).Count) events" 'Review account names in Section 16'}else{ck 'PASS' 'No new local account creation events - 4720'} >> "%PSRUN%"
echo $ev=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732} -MaxEvents 5 -EA SilentlyContinue;if($ev){ck 'WARN' "Users added to Administrators: $(@($ev).Count) events" 'Review account names in Section 16'}else{ck 'PASS' 'No unexpected additions to Administrators group - 4732'} >> "%PSRUN%"
echo $pp=(netsh interface portproxy show all 2^>$null)^|Out-String;if($pp -match '\d+\.\d+'){ck 'CRIT' 'netsh portproxy tunnel rules are ACTIVE' 'Volt Typhoon C2 IOC. Remove: netsh interface portproxy reset. See Section 17.'}else{ck 'PASS' 'No netsh portproxy tunnel rules - Volt Typhoon check'} >> "%PSRUN%"
echo try{$pipes=Get-ChildItem \\.\pipe\ -EA Stop^|Where-Object{$_.Name -match 'postex_^|msagent_^|MSSE-^|metsvc'};if($pipes){ck 'CRIT' ('Cobalt Strike named pipes detected: '+@($pipes).Count) ('Pipes: '+($pipes.Name -join ', ')+'. Active C2. See Section 17.')}else{ck 'PASS' 'No Cobalt Strike default named pipes detected'}}catch{ck 'INFO' 'Named pipe check unavailable'} >> "%PSRUN%"
echo $subs=@(Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue ^| Where-Object { -not ( ($_.Name -eq 'SCM Event Log Filter' -and $_.Query -like '*MSFT_SCMEventLogEvent*') -or ($_.Name -in @('BVTConsumer','BVTFilter','RmAssistEventLog')) ) });if($subs.Count -gt 0){ck 'CRIT' ('Non-default WMI EventFilter subscriptions present: '+$subs.Count) 'Stealthy reboot-persistent implant. See Section 17. Remove: Get-WMIObject -NS root\subscription -Class __EventFilter ^| Remove-WMIObject'}else{ck 'PASS' 'No non-default WMI permanent EventFilter subscriptions'} >> "%PSRUN%"
echo $sus=@(Get-CimInstance Win32_Process -EA SilentlyContinue^|Where-Object{$_.ExecutablePath -match '\\Temp\\^|\\AppData\\^|\\Downloads\\^|\\Users\\Public\\'});if($sus.Count -gt 0){ck 'CRIT' ('Processes from suspicious paths: '+$sus.Count) ('Names: '+(($sus^|Select-Object -Exp Name^|Sort-Object -Unique) -join ', ')+'. See Section 4.')}else{ck 'PASS' 'No processes running from Temp / AppData / Downloads'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== CREDENTIAL PROTECTION =========================================
echo sec 'CREDENTIAL PROTECTION  (Section 12)' >> "%PSRUN%"
echo $v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL;if($v -eq 1){ck 'PASS' 'LSASS PPL protection enabled (RunAsPPL=1)'}elseif($null -eq $v){ck 'WARN' 'LSASS PPL not configured' 'Add RunAsPPL=dword:1 to HKLM\SYSTEM\...\Lsa and reboot. Prevents Mimikatz credential dump.'}else{ck 'CRIT' ('LSASS PPL DISABLED (RunAsPPL='+$v+')') 'Set RunAsPPL=1 in HKLM\SYSTEM\...\Lsa and reboot. Mimikatz can dump all credentials.'} >> "%PSRUN%"
echo $v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential;if($v -eq 1){ck 'CRIT' 'WDigest ENABLED -- plaintext passwords are cached in RAM' 'Set UseLogonCredential=0 in HKLM\...\WDigest and reboot immediately'}elseif($v -eq 0){ck 'PASS' 'WDigest disabled (UseLogonCredential=0)'}else{ck 'PASS' 'WDigest not set (default off on Win8.1+)'} >> "%PSRUN%"
echo $v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel;if($v -ge 5){ck 'PASS' ('NTLM hardened: NTLMv2 only (Level='+$v+')')}elseif($v -ge 3){ck 'WARN' ('NTLM partially hardened (Level='+$v+')') 'Set LmCompatibilityLevel=5. GPO: Network security: LAN Manager authentication level.'}else{ck 'WARN' ('NTLMv1 allowed (Level='+$v+')') 'Set LmCompatibilityLevel=5 in HKLM\...\Lsa. NTLMv1 is crackable and relayable.'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== WINDOWS DEFENDER ==============================================
echo sec 'WINDOWS DEFENDER  (Section 9)' >> "%PSRUN%"
echo $mp=Get-MpComputerStatus -EA SilentlyContinue >> "%PSRUN%"
echo if($mp){if($mp.RealTimeProtectionEnabled){ck 'PASS' 'Real-time protection enabled'}else{ck 'CRIT' 'Real-time protection DISABLED' 'Run: Set-MpPreference -DisableRealtimeMonitoring $false'};if($mp.IsTamperProtected){ck 'PASS' 'Tamper protection enabled'}else{ck 'WARN' 'Tamper protection disabled' 'Enable via Windows Security ^> Virus and threat protection settings'};$age=$mp.AntivirusSignatureAge;if($age -lt 3){ck 'PASS' "Signatures current ($age days old)"}elseif($age -lt 7){ck 'WARN' "Signatures aging: $age days old" 'Run: Update-MpSignature'}else{ck 'CRIT' "Signatures OUTDATED: $age days old" 'Run: Update-MpSignature or Windows Update now'}}else{ck 'INFO' 'Cannot query Defender - third-party AV or WMI issue'} >> "%PSRUN%"
echo $mpp=Get-MpPreference -EA SilentlyContinue;if($mpp){$ep=@($mpp.ExclusionPath^|Where-Object{$_});$epr=@($mpp.ExclusionProcess^|Where-Object{$_});if($ep.Count -gt 0){ck 'WARN' "Defender path exclusions configured: $($ep.Count) paths" 'Exclusions hide malware from Defender. Verify each is legitimate. See Section 9.'}else{ck 'PASS' 'No Defender path exclusions configured'};if($epr.Count -gt 0){ck 'WARN' "Defender process exclusions configured: $($epr.Count)" 'Verify each is legitimate. See Section 9.'}else{ck 'PASS' 'No Defender process exclusions configured'}} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== ATTACK SURFACE ================================================
echo sec 'ATTACK SURFACE  (Sections 8, 10, 11)' >> "%PSRUN%"
echo $fwOn=(netsh advfirewall show allprofiles 2^>$null^|Select-String 'State\s+ON').Count;if($fwOn -ge 3){ck 'PASS' 'All three firewall profiles enabled - Domain, Private, Public'}else{ck 'CRIT' "Firewall DISABLED on $(3-$fwOn) profiles" 'Fix: netsh advfirewall set allprofiles state on'} >> "%PSRUN%"
echo $s1=(Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB1Protocol;if($s1 -eq $false){ck 'PASS' 'SMBv1 disabled (EternalBlue not exploitable)'}elseif($s1 -eq $true){ck 'CRIT' 'SMBv1 ENABLED (EternalBlue CVE-2017-0144)' 'Run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'}else{ck 'INFO' 'SMBv1 state unavailable -- see Section 10'} >> "%PSRUN%"
echo $psv2=Get-CimInstance Win32_OptionalFeature -Filter 'Name=''MicrosoftWindowsPowerShellV2Root''' -EA SilentlyContinue;if($psv2 -and $psv2.InstallState -eq 1){ck 'WARN' 'PowerShell v2 ENABLED (AMSI downgrade possible)' 'Run: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'}elseif($psv2){ck 'PASS' 'PowerShell v2 disabled'}else{ck 'INFO' 'PSv2 state unavailable -- see Section 11'} >> "%PSRUN%"
echo $rdp=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections;if($rdp -eq 1){ck 'PASS' 'RDP is disabled'}else{$nla=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -EA SilentlyContinue).UserAuthentication;if($nla -eq 1){ck 'PASS' 'RDP enabled with NLA (Network Level Authentication)'}else{ck 'WARN' 'RDP enabled WITHOUT NLA' 'Set UserAuthentication=1 in HKLM\...\RDP-Tcp or via Group Policy'}} >> "%PSRUN%"
echo $wmr=Get-Service WinRM -EA SilentlyContinue;if($wmr -and $wmr.Status -eq 'Running'){ck 'WARN' 'WinRM RUNNING (remote PowerShell enabled)' 'Disable: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled'}else{ck 'PASS' 'WinRM not running'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== SYSTEM HARDENING ==============================================
echo sec 'SYSTEM HARDENING  (Sections 11, 13)' >> "%PSRUN%"
echo $lua=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -EA SilentlyContinue).EnableLUA;$cpb=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue).ConsentPromptBehaviorAdmin;if($lua -eq 1 -and ($cpb -eq 2 -or $cpb -eq 5)){ck 'PASS' ('UAC on with prompt (EnableLUA=1, ConsentPrompt='+$cpb+')')}elseif($lua -eq 0){ck 'CRIT' 'UAC DISABLED -- all processes auto-elevate silently' 'Set EnableLUA=1 in HKLM\...\Policies\System and reboot'}elseif($cpb -eq 0){ck 'WARN' 'UAC auto-elevates without prompting (ConsentPromptBehaviorAdmin=0)' 'Set ConsentPromptBehaviorAdmin=2 for secure desktop confirmation'}else{ck 'WARN' ('UAC not fully hardened (EnableLUA='+$lua+', ConsentPrompt='+$cpb+')') 'Recommend: EnableLUA=1, ConsentPromptBehaviorAdmin=2'} >> "%PSRUN%"
echo $ts=bcdedit /enum 2^>$null^|Select-String 'testsigning\s+yes';if($ts){ck 'WARN' 'Driver signature enforcement DISABLED (testsigning=Yes)' 'Unsigned kernel drivers can load. Fix: bcdedit /set testsigning off'}else{ck 'PASS' 'Driver signature enforcement active'} >> "%PSRUN%"
echo try{$bl=Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop;if($bl.ProtectionStatus -eq 'On'){ck 'PASS' ('BitLocker ON for '+$env:SystemDrive+' ('+$bl.EncryptionMethod+')')}else{ck 'WARN' ('BitLocker OFF for '+$env:SystemDrive) 'Drive unencrypted -- data readable if drive removed. Enable: manage-bde -on C:'}}catch{ck 'INFO' 'BitLocker status unavailable -- see Section 13'} >> "%PSRUN%"
echo $sbl=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging;if($sbl -eq 1){ck 'PASS' 'PS Script Block Logging enabled (Event 4104 active)'}else{ck 'WARN' 'PS Script Block Logging NOT enabled' 'Set EnableScriptBlockLogging=1 in HKLM\...\ScriptBlockLogging via GPO'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== PERSISTENCE INTEGRITY =========================================
echo sec 'PERSISTENCE INTEGRITY  (Sections 5, 6, 7)' >> "%PSRUN%"
echo $ui=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -EA SilentlyContinue).Userinit;if($ui -match '^C:\\Windows\\[Ss]ystem32\\userinit\.exe,?\s*$'){ck 'PASS' ('Winlogon Userinit clean: '+$ui.Trim())}else{ck 'CRIT' ('Winlogon Userinit MODIFIED: '+$ui) 'Expected: C:\Windows\system32\userinit.exe, -- malware hijacks this at every login'} >> "%PSRUN%"
echo $sh=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -EA SilentlyContinue).Shell;if($sh -match '^explorer\.exe$'){ck 'PASS' 'Winlogon Shell clean (explorer.exe)'}else{ck 'CRIT' ('Winlogon Shell MODIFIED: '+$sh) 'Expected: explorer.exe only. Fix via regedit: HKLM\...\Winlogon\Shell'} >> "%PSRUN%"
echo $ai=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -EA SilentlyContinue).AppInit_DLLs;if([string]::IsNullOrWhiteSpace($ai)){ck 'PASS' 'AppInit_DLLs empty (no injected DLL)'}else{ck 'CRIT' ('AppInit_DLLs set: '+$ai) 'DLL loads into every GUI process. Clear AppInit_DLLs in HKLM\...\Windows immediately.'} >> "%PSRUN%"
echo $tsk=schtasks /query /fo CSV /v 2^>$null^|Select-String '\\Temp\\^|\\AppData\\';if($tsk){ck 'WARN' "Tasks running from Temp/AppData: $(@($tsk).Count) matches" 'Strong IOC. Review task details in Section 6.'}else{ck 'PASS' 'No scheduled tasks running from Temp or AppData'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== ACCESSIBILITY BINARY INTEGRITY (T1546.008) ====================
echo sec 'ACCESSIBILITY BINARY INTEGRITY  T1546.008  (Section 13)' >> "%PSRUN%"
echo $accBins = @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') >> "%PSRUN%"
echo $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' >> "%PSRUN%"
echo $ifeoHits = @(); foreach ($b in $accBins) { $d = Get-ItemProperty (Join-Path $ifeoBase $b) -Name Debugger -EA SilentlyContinue; if ($d) { $ifeoHits += $b+' -^> '+$d.Debugger } } >> "%PSRUN%"
echo if ($ifeoHits.Count -gt 0) { ck 'CRIT' "IFEO Debugger hijack on $($ifeoHits.Count) accessibility binaries" "Affected: $($ifeoHits -join '; '). Pressing Shift x5 or Win+U at login = SYSTEM shell. Delete Debugger value in HKLM\...\IFEO\[binary]" } else { ck 'PASS' 'No IFEO Debugger hijacks on accessibility binaries - T1546.008' } >> "%PSRUN%"
echo $sysDir = "$env:SystemRoot\System32"; $badSig = @() >> "%PSRUN%"
echo foreach ($b in $accBins) { $f = Join-Path $sysDir $b; if (Test-Path $f) { $sig = Get-AuthenticodeSignature $f; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { $badSig += $b } } } >> "%PSRUN%"
echo if ($badSig.Count -gt 0) { ck 'CRIT' ('Accessibility binary signature INVALID: '+($badSig -join ', ')) 'Binaries may have been replaced with cmd.exe. Run: sfc /scannow or restore from WinRE.' } else { ck 'PASS' 'All 7 accessibility binaries carry valid Microsoft signatures' } >> "%PSRUN%"
echo $sf = (Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags -EA SilentlyContinue).Flags >> "%PSRUN%"
echo if ($null -ne $sf -and ($sf -band 0x02) -gt 0) { ck 'WARN' 'Sticky Keys shortcut enabled (Shift x5 triggers at login screen)' 'Reduces attack surface: Settings ^> Accessibility ^> Keyboard ^> Sticky Keys shortcut OFF' } else { ck 'PASS' 'Sticky Keys shortcut disabled (no unauthenticated login-screen trigger)' } >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== DISK HEALTH ===================================================
echo sec 'DISK HEALTH  (Pre-flight INIT 14)' >> "%PSRUN%"
echo if($sw -eq '1'){ck 'CRIT' 'SMART failure on one or more drives' 'Back up all data NOW. See SmartData\ folder. Replace failing drive before continuing.'}else{ck 'PASS' 'All drives report healthy SMART status'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== CTI IOC SWEEP ================================================
echo sec 'CTI IOC SWEEP  (Section 18 - SENTINEL-X)' >> "%PSRUN%"
echo $iocHits='%IOC_HITS%' >> "%PSRUN%"
echo if($iocHits -gt 0){ck 'CRIT' "CTI IOC sweep: $iocHits category matches found" 'Review Section 18 for specific IOC matches. Investigate all CRITICAL and WARNING entries.'}else{ck 'PASS' 'CTI IOC sweep: no threat indicator matches across all categories'} >> "%PSRUN%"
echo. >> "%PSRUN%"

:: ===== COMPOSE AND OUTPUT SUMMARY ====================================
echo $bar = '#' * 70 >> "%PSRUN%"
echo $status = if($cr -gt 0){'ACTION REQUIRED  --  '+$cr+' CRITICAL  /  '+$wa+' WARNING  /  '+$pa+' PASSED'}elseif($wa -gt 0){'REVIEW RECOMMENDED  --  0 CRITICAL  /  '+$wa+' WARNING  /  '+$pa+' PASSED'}else{'ALL '+$pa+' CHECKS PASSED  --  System appears clean'} >> "%PSRUN%"
echo '' >> "%PSRUN%"
echo $bar >> "%PSRUN%"
echo '##' >> "%PSRUN%"
echo ('##  SECURITY AUDIT SUMMARY  --  ' + $env:COMPUTERNAME) >> "%PSRUN%"
echo ('##  ' + (Get-Date -Format 'yyyy-MM-dd  HH:mm:ss')) >> "%PSRUN%"
echo '##' >> "%PSRUN%"
echo ('##  ' + $status) >> "%PSRUN%"
echo '##' >> "%PSRUN%"
echo $bar >> "%PSRUN%"
echo foreach ($line in $r) { $line } >> "%PSRUN%"
echo '' >> "%PSRUN%"
echo $bar >> "%PSRUN%"
echo if ($cr -gt 0) { >> "%PSRUN%"
echo '  NEXT STEPS -- CRITICAL issues found:' >> "%PSRUN%"
echo '  1. Isolate this machine from the network NOW' >> "%PSRUN%"
echo '  2. Do NOT reboot -- volatile RAM evidence will be lost' >> "%PSRUN%"
echo '  3. Image the drive before any remediation (forensic preservation)' >> "%PSRUN%"
echo '  4. Apply the Fix listed next to each CRITICAL item above' >> "%PSRUN%"
echo '  5. Report nation-state indicators to CISA: cisa.gov/report' >> "%PSRUN%"
echo } elseif ($wa -gt 0) { >> "%PSRUN%"
echo '  NEXT STEPS -- No active compromise found. Apply these improvements:' >> "%PSRUN%"
echo '  1. Apply the Fix listed next to each WARNING above' >> "%PSRUN%"
echo '  2. Priority: Credential ^> Defender ^> Attack Surface ^> Hardening' >> "%PSRUN%"
echo '  3. Re-run this audit after fixing to confirm clean' >> "%PSRUN%"
echo } else { >> "%PSRUN%"
echo '  System security posture is good.' >> "%PSRUN%"
echo '  Recommendation: re-run this audit monthly.' >> "%PSRUN%"
echo } >> "%PSRUN%"
echo $bar >> "%PSRUN%"
echo '' >> "%PSRUN%"
echo if ($cr -gt 0) { 'CRIT' ^| Out-File $scf -Encoding ASCII } elseif ($wa -gt 0) { 'WARN' ^| Out-File $scf -Encoding ASCII } else { 'OK' ^| Out-File $scf -Encoding ASCII } >> "%PSRUN%"

:: ---- Emit runnable fix commands for known findings -----------------
:: Scans $r (the rendered findings) and appends PS commands to $rem
:: for every finding with a safe, reversible auto-fix. Manual-only
:: findings (Winlogon tamper, IFEO hijack, ransomware IOCs, etc.) are
:: intentionally excluded.
echo function addfix($tag,$cmd){ Add-Content -LiteralPath $rem -Value ('# '+$tag); Add-Content -LiteralPath $rem -Value $cmd; Add-Content -LiteralPath $rem -Value '' } >> "%PSRUN%"
echo $joined = ($r -join "`n") >> "%PSRUN%"
echo if($joined -match 'LSASS PPL DISABLED^|LSASS PPL not configured'){ addfix 'Enable LSASS PPL protection (reboot required)' "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force; Write-Host 'RunAsPPL set. Reboot required.'" } >> "%PSRUN%"
echo if($joined -match 'WDigest ENABLED'){ addfix 'Disable WDigest plaintext credential cache (reboot required)' "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'NTLMv1 allowed^|NTLM partially hardened'){ addfix 'Harden NTLM to NTLMv2-only' "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'Firewall DISABLED'){ addfix 'Enable all Windows Firewall profiles' "Set-NetFirewallProfile -All -Enabled True" } >> "%PSRUN%"
echo if($joined -match 'SMBv1 ENABLED'){ addfix 'Disable SMBv1 (EternalBlue mitigation)' "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" } >> "%PSRUN%"
echo if($joined -match 'PowerShell v2 ENABLED'){ addfix 'Disable PowerShell v2 (AMSI downgrade mitigation)' "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart" } >> "%PSRUN%"
echo if($joined -match 'RDP enabled WITHOUT NLA'){ addfix 'Require Network Level Authentication for RDP' "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'WinRM RUNNING'){ addfix 'Stop and disable WinRM' "Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled" } >> "%PSRUN%"
echo if($joined -match 'UAC DISABLED'){ addfix 'Re-enable UAC (reboot required)' "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'UAC auto-elevates'){ addfix 'Restore UAC prompt on secure desktop' "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'testsigning=Yes^|testsigning\s*=\s*Yes'){ addfix 'Disable test-signing (re-enforce driver signatures)' "bcdedit /set testsigning off" } >> "%PSRUN%"
echo if($joined -match 'PS Script Block Logging NOT'){ addfix 'Enable PowerShell Script Block Logging' "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'AppInit_DLLs set'){ addfix 'Clear AppInit_DLLs (remove DLL injection vector)' "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value '' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name LoadAppInit_DLLs -Value 0 -Type DWord -Force" } >> "%PSRUN%"
echo if($joined -match 'Sticky Keys shortcut enabled'){ addfix 'Disable Sticky Keys shortcut at login screen' "Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags -Value '506' -Force" } >> "%PSRUN%"
echo if($joined -match 'portproxy tunnel rules are ACTIVE'){ addfix 'Remove netsh portproxy tunnels (Volt Typhoon IOC)' "netsh interface portproxy reset" } >> "%PSRUN%"
echo if($joined -match 'WMI EventFilter subscriptions present'){ addfix 'Remove non-default WMI permanent EventFilter subscriptions (preserves Microsoft defaults)' "$ms=@('SCM Event Log Filter','BVTConsumer','BVTFilter','RmAssistEventLog'); Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -EA SilentlyContinue ^| Where-Object { $_.Name -notin $ms } ^| Remove-CimInstance; Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -EA SilentlyContinue ^| Where-Object { $_.Name -notin $ms } ^| Remove-CimInstance; Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -EA SilentlyContinue ^| Where-Object { $_.Filter -notmatch ($ms -join '^|') } ^| Remove-CimInstance" } >> "%PSRUN%"
echo if($joined -match 'Accessibility binary signature INVALID'){ addfix 'Restore corrupted system binaries' "sfc /scannow; DISM /Online /Cleanup-Image /RestoreHealth" } >> "%PSRUN%"
echo if($joined -match 'Real-time protection DISABLED'){ addfix 'Re-enable Defender real-time protection' "Set-MpPreference -DisableRealtimeMonitoring \$false" } >> "%PSRUN%"
echo if($joined -match 'Signatures OUTDATED^|Signatures aging'){ addfix 'Update Defender signatures' "Update-MpSignature" } >> "%PSRUN%"
echo if($joined -match 'Tamper protection disabled'){ addfix 'Enable Defender tamper protection (via Windows Security UI)' "Write-Host 'Tamper Protection is UI-managed. Open: Windows Security > Virus and threat protection > Manage settings > Tamper Protection > On'" } >> "%PSRUN%"
echo if(-not (Get-Content -LiteralPath $rem ^| Where-Object { $_ -match '^Set-^|^Disable-^|^Enable-^|^netsh^|^bcdedit^|^Update-^|^Stop-^|^sfc^|^New-^|^Get-^|^Remove-' })){ Add-Content -LiteralPath $rem -Value '# No auto-fixable findings detected. The system is either clean or the findings require manual remediation (see the report).' } >> "%PSRUN%"
echo $fixCount = @(Get-Content -LiteralPath $rem ^| Where-Object { $_ -match '^Set-^|^Disable-^|^Enable-^|^netsh^|^bcdedit^|^Update-^|^Stop-^|^sfc^|^New-^|^Get-^|^Remove-' }).Count >> "%PSRUN%"
echo Write-Output '' >> "%PSRUN%"
echo Write-Output '######################################################################' >> "%PSRUN%"
echo Write-Output '##  REMEDIATION SCRIPT' >> "%PSRUN%"
echo Write-Output ('##  Location : ' + $rem) >> "%PSRUN%"
echo Write-Output ('##  Fixes    : ' + $fixCount + ' auto-fix command(s) queued') >> "%PSRUN%"
echo Write-Output '##' >> "%PSRUN%"
echo Write-Output '##  TO APPLY:' >> "%PSRUN%"
echo Write-Output '##    1. Open the script and REVIEW every command' >> "%PSRUN%"
echo Write-Output '##    2. Change $IReadAndUnderstand=$false to $true' >> "%PSRUN%"
echo Write-Output '##    3. Run from elevated PowerShell:' >> "%PSRUN%"
echo Write-Output ('##       powershell -NoProfile -ExecutionPolicy Bypass -File "' + $rem + '"') >> "%PSRUN%"
echo Write-Output '##' >> "%PSRUN%"
echo Write-Output '##  After running, re-run doze_sec to verify.' >> "%PSRUN%"
echo Write-Output '######################################################################' >> "%PSRUN%"
echo Write-Output '' >> "%PSRUN%"

:: ---- Format the report: insert section terminators for unambiguous boundaries ----
if exist "%SCRIPT_DIR%tools\report_format.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\report_format.ps1" -Report "%REPORT%" 2>nul
)

:: ---- Prepend TOP FINDINGS summary so analysts see the headline issues first ----
if exist "%SCRIPT_DIR%tools\top_findings.ps1" (
    "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\top_findings.ps1" -Report "%REPORT%" 2>nul
)

:: ---- Run PS, show on screen, append to report ----------------------
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" > "%SUMFILE%" 2>&1
if exist "%SUMFILE%" (
    type "%SUMFILE%"
    echo.>> "%REPORT%"
    type "%SUMFILE%">> "%REPORT%"
) else (
    echo  [WARNING] Live summary could not run - PWSH failed to produce output.>> "%REPORT%"
    echo  [WARNING] Check PowerShell execution policy or PWSH path.>> "%REPORT%"
    echo.
    echo  [WARN] Live summary skipped - PowerShell produced no output.
    echo  Check execution policy: Get-ExecutionPolicy -List
    echo.
)

:: Read summary exit token, update EXIT_CODE
set "SUM_RESULT=OK"
if exist "%SUMCODE%" (
    for /f "usebackq tokens=* delims=" %%a in ("%SUMCODE%") do set "SUM_RESULT=%%a"
    del "%SUMCODE%" >nul 2>&1
)
set "SUM_RESULT=%SUM_RESULT: =%"
if /i "%SUM_RESULT%"=="CRIT" if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
if /i "%SUM_RESULT%"=="WARN" if %EXIT_CODE% LSS 2 set "EXIT_CODE=2"
if exist "%SUMFILE%" del "%SUMFILE%" >nul 2>&1

echo.
echo ====================================================================
if "%EXIT_CODE%"=="0" echo  %C_BOLD%%C_GREEN%RESULT: All checks passed.%C_RESET%
if "%EXIT_CODE%"=="2" echo  %C_BOLD%%C_YELLOW%RESULT: Issues found. See SUMMARY at end of report.%C_RESET%
echo  Report : %REPORT%
echo ====================================================================
echo.


:: ====================================================================
:: END OF AUDIT - Exit handler
:: ====================================================================
:end_script

echo ====================================================================>> "%REPORT%"
(echo  EXIT CODE: %EXIT_CODE%)>> "%REPORT%"
echo  0=Success  1=Error  2=Warning  3=UnsupportedOS  4=RebootPending  5=RanFromTEMP>> "%REPORT%"
if "%EXIT_CODE%"=="0" echo  STATUS: Clean run - no fatal issues encountered.>> "%REPORT%"
if "%EXIT_CODE%"=="1" echo  STATUS: Fatal error. Check console output above for details.>> "%REPORT%"
if "%EXIT_CODE%"=="2" echo  STATUS: Audit complete with warnings. Review [WARNING] items in report.>> "%REPORT%"
if "%EXIT_CODE%"=="3" echo  STATUS: Unsupported OS. Use -dev switch to override.>> "%REPORT%"
if "%EXIT_CODE%"=="4" echo  STATUS: Reboot pending. Reboot and re-run the audit.>> "%REPORT%"
if "%EXIT_CODE%"=="5" echo  STATUS: Script ran from TEMP directory. Move script and re-run.>> "%REPORT%"
echo ====================================================================>> "%REPORT%"

:: Delete RunOnce key on clean exit (0=success, 2=warning both count as "completed")
if "%EXIT_CODE%"=="0" reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "*%SCRIPT_NAME%_resume" /f >nul 2>&1
if "%EXIT_CODE%"=="2" reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "*%SCRIPT_NAME%_resume" /f >nul 2>&1

:: Clean up temp PS1 file
if exist "%PSRUN%" del "%PSRUN%" >nul 2>&1

:: Screen summary
echo.
echo %C_BOLD%====================================================================%C_RESET%
echo  %C_BOLD%%C_WHITE%AUDIT COMPLETE%C_RESET%
if "%EXIT_CODE%"=="0" echo  Exit code  : %C_GREEN%%EXIT_CODE%%C_RESET%
if "%EXIT_CODE%"=="1" echo  Exit code  : %C_RED%%EXIT_CODE%%C_RESET%
if "%EXIT_CODE%"=="2" echo  Exit code  : %C_YELLOW%%EXIT_CODE%%C_RESET%
if "%EXIT_CODE%"=="3" echo  Exit code  : %C_YELLOW%%EXIT_CODE%%C_RESET%
if "%EXIT_CODE%"=="4" echo  Exit code  : %C_YELLOW%%EXIT_CODE%%C_RESET%
if "%EXIT_CODE%"=="5" echo  Exit code  : %C_RED%%EXIT_CODE%%C_RESET%
echo  %C_DIM%0=Success  1=Error  2=Warning  3=UnsupportedOS  4=Reboot  5=TEMP%C_RESET%
echo  Report     : %C_CYAN%%REPORT%%C_RESET%
echo  HTML Report: %C_CYAN%%REPORT_HTML%%C_RESET%
if exist "%REMEDIATION%" (
    echo  %C_BOLD%%C_YELLOW%^>^> REMEDIATION: %REMEDIATION%%C_RESET%
    echo  %C_DIM%   Review every line, set $IReadAndUnderstand=$true, then run as admin%C_RESET%
)
if "%SMART_WARN%"=="1" echo  %C_BOLD%%C_RED%SMART WARN : Drive health issue detected - back up data immediately%C_RESET%
if "%EXIT_CODE%"=="2"  echo  %C_YELLOW%WARNINGS   : Review all [WARNING] entries in the report%C_RESET%
echo %C_BOLD%====================================================================%C_RESET%

:: ---- Changes made to this system ------------------------------------
if "%SCRIPT_CHANGED%"=="1" (
    echo.
    echo ====================================================================
    echo  CHANGES MADE TO THIS SYSTEM BY THE AUDIT SCRIPT:
    echo ====================================================================
    if exist "%CHANGELOG%" (
        type "%CHANGELOG%"
    ) else (
        echo  [INFO] No change log file found.
    )
    echo.
    echo  Full change log : %CHANGELOG%
    echo  Undo script     : %UNDO_BAT%
    echo  Run Undo script AS ADMINISTRATOR to reverse boot menu changes.
    echo ====================================================================
    echo.
    :: Append changelog to report as well
    echo.>> "%REPORT%"
    echo ====================================================================>> "%REPORT%"
    echo  CHANGES MADE TO THIS SYSTEM BY THE AUDIT SCRIPT>> "%REPORT%"
    echo ====================================================================>> "%REPORT%"
    if exist "%CHANGELOG%" type "%CHANGELOG%">> "%REPORT%"
    echo  Undo script: %UNDO_BAT%>> "%REPORT%"
    echo ====================================================================>> "%REPORT%"
) else (
    echo.
    echo  No system changes were made by this audit run.
    echo.
)

:: Finalize undo bat (only if something was changed)
if "%SCRIPT_CHANGED%"=="1" (
    echo.>> "%UNDO_BAT%"
    echo echo All undo operations complete.>> "%UNDO_BAT%"
    echo pause>> "%UNDO_BAT%"
)
echo.

:: ====================================================================
:: GENERATE HTML REPORT
:: ====================================================================
echo %C_CYAN%Generating HTML report...%C_RESET%
echo $reportPath = '%REPORT%' > "%PSRUN%"
echo $htmlPath = '%REPORT_HTML%' >> "%PSRUN%"
echo $lines = Get-Content $reportPath -Encoding UTF8 >> "%PSRUN%"
echo Add-Type -AssemblyName System.Web >> "%PSRUN%"
echo $html = [System.Text.StringBuilder]::new() >> "%PSRUN%"
echo [void]$html.AppendLine('^<^^!DOCTYPE html^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<html lang="en"^>^<head^>^<meta charset="UTF-8"^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<title^>Security Audit Report^</title^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<style^>') >> "%PSRUN%"
echo [void]$html.AppendLine('body{font-family:Consolas,monospace;margin:0;background:#1a1a2e;color:#e0e0e0}') >> "%PSRUN%"
echo [void]$html.AppendLine('.wrap{display:flex}') >> "%PSRUN%"
echo [void]$html.AppendLine('nav{position:fixed;top:0;left:0;width:260px;height:100vh;overflow-y:auto;background:#16213e;padding:16px;box-sizing:border-box;border-right:2px solid #0f3460}') >> "%PSRUN%"
echo [void]$html.AppendLine('nav h2{color:#56cfe1;font-size:14px;margin:0 0 12px}') >> "%PSRUN%"
echo [void]$html.AppendLine('nav a{display:block;color:#a8b2d1;text-decoration:none;padding:4px 0;font-size:12px}') >> "%PSRUN%"
echo [void]$html.AppendLine('nav a:hover{color:#56cfe1}') >> "%PSRUN%"
echo [void]$html.AppendLine('main{margin-left:270px;padding:20px;max-width:1100px}') >> "%PSRUN%"
echo [void]$html.AppendLine('.section{margin-bottom:24px;border:1px solid #0f3460;border-radius:6px;padding:16px;background:#16213e}') >> "%PSRUN%"
echo [void]$html.AppendLine('.section h2{color:#56cfe1;margin-top:0;font-size:16px;border-bottom:1px solid #0f3460;padding-bottom:8px}') >> "%PSRUN%"
echo [void]$html.AppendLine('.ok{color:#00d26a;font-weight:bold;overflow-wrap:anywhere}') >> "%PSRUN%"
echo [void]$html.AppendLine('.warn{color:#ffc107;font-weight:bold;overflow-wrap:anywhere}') >> "%PSRUN%"
echo [void]$html.AppendLine('.crit{color:#ff4444;font-weight:bold;background:#3a0000;padding:4px 8px;border-radius:3px;overflow-wrap:anywhere}') >> "%PSRUN%"
echo [void]$html.AppendLine('.info{color:#17a2b8;overflow-wrap:anywhere}') >> "%PSRUN%"
echo [void]$html.AppendLine('details{margin:8px 0}') >> "%PSRUN%"
echo [void]$html.AppendLine('summary{cursor:pointer;color:#a8b2d1;font-size:13px}') >> "%PSRUN%"
echo [void]$html.AppendLine('summary:hover{color:#56cfe1}') >> "%PSRUN%"
echo [void]$html.AppendLine('pre{background:#0a0a1a;padding:12px;border-radius:4px;font-size:12px;line-height:1.4;color:#c8c8c8;max-height:400px;overflow-x:auto;overflow-y:auto;white-space:pre-wrap;overflow-wrap:anywhere}') >> "%PSRUN%"
echo [void]$html.AppendLine('.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card{padding:16px;border-radius:6px;text-align:center}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card h3{margin:0;font-size:28px}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card p{margin:4px 0 0;font-size:12px}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card-ok{background:#0a3d0a;border:1px solid #00d26a}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card-warn{background:#3d3a0a;border:1px solid #ffc107}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card-crit{background:#3d0a0a;border:1px solid #ff4444}') >> "%PSRUN%"
echo [void]$html.AppendLine('.card-info{background:#0a2a3d;border:1px solid #17a2b8}') >> "%PSRUN%"
echo [void]$html.AppendLine('^</style^>^</head^>^<body^>') >> "%PSRUN%"
echo $secNum = 0; $okCount = 0; $warnCount = 0; $critCount = 0; $infoCount = 0 >> "%PSRUN%"
echo $navLinks = [System.Text.StringBuilder]::new() >> "%PSRUN%"
echo $bodyContent = [System.Text.StringBuilder]::new() >> "%PSRUN%"
echo $inPre = $false >> "%PSRUN%"
echo foreach ($line in $lines) { >> "%PSRUN%"
echo   $esc = [System.Web.HttpUtility]::HtmlEncode($line) >> "%PSRUN%"
echo   if ($line -match '^\s*\[(\d+)/18\]\s+(.+)$') { >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>'); $inPre = $false } >> "%PSRUN%"
echo     $secNum = $Matches[1]; $secTitle = $Matches[2].Trim() >> "%PSRUN%"
echo     [void]$navLinks.AppendLine('^<a href="#sec'+$secNum+'"^>'+$secNum+'. '+$secTitle+'^</a^>') >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^</div^>^<div class="section" id="sec'+$secNum+'"^>^<h2^>['+$secNum+'/18] '+[System.Web.HttpUtility]::HtmlEncode($secTitle)+'^</h2^>') >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^<details open^>^<summary^>Section output^</summary^>^<pre^>') >> "%PSRUN%"
echo     $inPre = $true >> "%PSRUN%"
echo   } elseif ($line -match '\[OK\]') { >> "%PSRUN%"
echo     $okCount++ >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>'); $inPre = $false } >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^<div class="ok"^>'+$esc+'^</div^>') >> "%PSRUN%"
echo     if (-not $inPre) { [void]$bodyContent.AppendLine('^<details^>^<summary^>Details^</summary^>^<pre^>'); $inPre = $true } >> "%PSRUN%"
echo   } elseif ($line -match '\[WARNING\]' -or $line -match '\[WARN\]') { >> "%PSRUN%"
echo     $warnCount++ >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>'); $inPre = $false } >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^<div class="warn"^>'+$esc+'^</div^>') >> "%PSRUN%"
echo     if (-not $inPre) { [void]$bodyContent.AppendLine('^<details^>^<summary^>Details^</summary^>^<pre^>'); $inPre = $true } >> "%PSRUN%"
echo   } elseif ($line -match '\[CRITICAL\]' -or $line -match '\[CRIT\]') { >> "%PSRUN%"
echo     $critCount++ >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>'); $inPre = $false } >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^<div class="crit"^>'+$esc+'^</div^>') >> "%PSRUN%"
echo     if (-not $inPre) { [void]$bodyContent.AppendLine('^<details^>^<summary^>Details^</summary^>^<pre^>'); $inPre = $true } >> "%PSRUN%"
echo   } elseif ($line -match '\[INFO\]') { >> "%PSRUN%"
echo     $infoCount++ >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>'); $inPre = $false } >> "%PSRUN%"
echo     [void]$bodyContent.AppendLine('^<div class="info"^>'+$esc+'^</div^>') >> "%PSRUN%"
echo     if (-not $inPre) { [void]$bodyContent.AppendLine('^<details^>^<summary^>Details^</summary^>^<pre^>'); $inPre = $true } >> "%PSRUN%"
echo   } elseif ($line -match '^-{60,}\s*$') { >> "%PSRUN%"
echo     ^# Section terminator inserted by tools/report_format.ps1. The HTML >> "%PSRUN%"
echo     ^# layout already delimits sections via collapsible ^<details^> blocks, >> "%PSRUN%"
echo     ^# so the text-only horizontal rule would just clutter the rendered output. >> "%PSRUN%"
echo     # skipped >> "%PSRUN%"
echo   } else { >> "%PSRUN%"
echo     if ($inPre) { [void]$bodyContent.AppendLine($esc) } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo } >> "%PSRUN%"
echo if ($inPre) { [void]$bodyContent.AppendLine('^</pre^>^</details^>^</div^>') } >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="wrap"^>^<nav^>^<h2^>DOZE_SEC AUDIT^</h2^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<a href="#dashboard"^>Dashboard^</a^>') >> "%PSRUN%"
echo [void]$html.AppendLine($navLinks.ToString()) >> "%PSRUN%"
echo [void]$html.AppendLine('^<a href="#remediation" style="color:#ffc107"^>Rollback Script^</a^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^</nav^>^<main^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div id="dashboard"^>^<h1 style="color:#56cfe1;margin-top:0"^>Security Audit Report^</h1^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="dashboard"^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="card card-crit"^>^<h3^>'+$critCount+'^</h3^>^<p^>CRITICAL^</p^>^</div^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="card card-warn"^>^<h3^>'+$warnCount+'^</h3^>^<p^>WARNING^</p^>^</div^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="card card-ok"^>^<h3^>'+$okCount+'^</h3^>^<p^>PASSED^</p^>^</div^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^<div class="card card-info"^>^<h3^>'+$infoCount+'^</h3^>^<p^>INFO^</p^>^</div^>') >> "%PSRUN%"
echo [void]$html.AppendLine('^</div^>^</div^>^<div class="section"^>') >> "%PSRUN%"
echo [void]$html.AppendLine($bodyContent.ToString()) >> "%PSRUN%"
:: ---- Rollback/Remediation section (embeds fixes + full script) -----
echo $remPath = '%REMEDIATION%' >> "%PSRUN%"
echo if (Test-Path $remPath) { >> "%PSRUN%"
echo   $remLines = Get-Content $remPath -Encoding UTF8 >> "%PSRUN%"
echo   $fixes = @() >> "%PSRUN%"
echo   for ($i = 0; $i -lt $remLines.Count - 1; $i++) { >> "%PSRUN%"
echo     $l = $remLines[$i]; $n = $remLines[$i+1] >> "%PSRUN%"
echo     if ($l.StartsWith('# ') -and $n -match '^^(Set-^|Disable-^|Enable-^|netsh^|bcdedit^|Update-^|Stop-^|sfc^|New-^|Get-^|Remove-^|Write-Host)') { >> "%PSRUN%"
echo       $fixes += [PSCustomObject]@{ Desc = $l.Substring(2).Trim(); Cmd = $n.Trim() } >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo   [void]$html.AppendLine('^<div class="section" id="remediation" style="border-color:#ffc107"^>^<h2 style="color:#ffc107;border-bottom-color:#ffc107"^>Rollback Script: Proposed Fixes^</h2^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<p^>^<strong^>Location:^</strong^> ^<code^>' + [System.Web.HttpUtility]::HtmlEncode($remPath) + '^</code^>^</p^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<p^>This script reverts risky configurations detected above back to safe defaults. ^<strong^>Review every command before running.^</strong^>^</p^>') >> "%PSRUN%"
echo   if ($fixes.Count -gt 0) { >> "%PSRUN%"
echo     [void]$html.AppendLine('^<p^>^<strong^>' + $fixes.Count + ' auto-fix command(s) queued:^</strong^>^</p^>') >> "%PSRUN%"
echo     [void]$html.AppendLine('^<ul style="list-style:none;padding-left:0"^>') >> "%PSRUN%"
echo     foreach ($f in $fixes) { >> "%PSRUN%"
echo       [void]$html.AppendLine('^<li style="margin-bottom:10px;padding:10px;background:#0f3460;border-radius:4px;border-left:3px solid #ffc107"^>') >> "%PSRUN%"
echo       [void]$html.AppendLine('^<div style="color:#ffc107;font-weight:bold;margin-bottom:4px"^>' + [System.Web.HttpUtility]::HtmlEncode($f.Desc) + '^</div^>') >> "%PSRUN%"
echo       [void]$html.AppendLine('^<code style="display:block;color:#a8b2d1;font-size:11px;word-break:break-all"^>' + [System.Web.HttpUtility]::HtmlEncode($f.Cmd) + '^</code^>^</li^>') >> "%PSRUN%"
echo     } >> "%PSRUN%"
echo     [void]$html.AppendLine('^</ul^>') >> "%PSRUN%"
echo   } else { >> "%PSRUN%"
echo     [void]$html.AppendLine('^<p^>^<em^>No auto-fixable findings detected. Remediation file contains the safety header only.^</em^>^</p^>') >> "%PSRUN%"
echo   } >> "%PSRUN%"
echo   [void]$html.AppendLine('^<h3 style="color:#56cfe1;margin-top:16px;font-size:14px"^>To Apply^</h3^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<ol^>^<li^>Open the script and review every command.^</li^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<li^>Change ^<code^>$IReadAndUnderstand=$false^</code^> to ^<code^>$true^</code^>.^</li^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<li^>Run from elevated PowerShell: ^<code^>powershell -NoProfile -ExecutionPolicy Bypass -File "' + [System.Web.HttpUtility]::HtmlEncode($remPath) + '"^</code^>^</li^>^</ol^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^<details^>^<summary^>Full script contents^</summary^>^<pre^>' + [System.Web.HttpUtility]::HtmlEncode(($remLines -join "`n")) + '^</pre^>^</details^>') >> "%PSRUN%"
echo   [void]$html.AppendLine('^</div^>') >> "%PSRUN%"
echo } >> "%PSRUN%"
echo [void]$html.AppendLine('^</main^>^</div^>^</body^>^</html^>') >> "%PSRUN%"
echo $html.ToString() ^| Out-File $htmlPath -Encoding UTF8 >> "%PSRUN%"
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%" 2>&1
if exist "%REPORT_HTML%" (
    echo %C_GREEN%[OK]%C_RESET% HTML report: %REPORT_HTML%
) else (
    echo %C_YELLOW%[WARN]%C_RESET% HTML generation failed. Text report available.
)
if exist "%REPORT_HTML%" (
    echo Opening HTML report...
    start "" "%REPORT_HTML%"
) else (
    if exist "%REPORT%" (
        echo Opening text report...
        start "" notepad "%REPORT%"
    )
)

:: endlocal and exit /b MUST be on one line.
:: cmd.exe expands %EXIT_CODE% before executing, so the value is
:: captured before endlocal clears all setlocal variables.
:: Splitting them onto two lines means exit /b sees an empty var.
:final_exit
endlocal & exit /b %EXIT_CODE%

