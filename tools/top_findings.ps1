# top_findings.ps1 -- Prepend a TOP FINDINGS summary block to the audit report.
#
# Walks the report after all sections complete, collects every [CRITICAL]
# and [WARNING] finding, looks up an analyst-friendly "Why it matters"
# explanation, sorts by severity, and prepends a summary block right
# before Section 1 (after pre-flight INIT headers).
#
# Output looks like:
#
#   ====================================================================
#    TOP FINDINGS (highest severity first) -- review these first
#   ====================================================================
#
#    1. [CRITICAL] Section: [17/18] NATION-STATE THREAT INDICATORS
#       Finding: [CRITICAL] Non-default WMI EventFilter subscriptions present: 2
#       Why it matters: Non-default WMI persistence subscription. Survives
#         reboots without an EXE on disk -- stealthy, common in APT toolkits.
#
#    2. [WARNING] Section: [12/18] CREDENTIAL AND LSASS PROTECTION
#       Finding: [WARNING] LSASS PPL not configured
#       Why it matters: LSASS Protected Process Light is disabled or unset.
#         Without PPL, Mimikatz can dump cleartext credentials from LSASS.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File top_findings.ps1 -Report <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$Report,
    [int]$MaxFindings = 10
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Report)) { return }
# Detect line-ending style from raw bytes so we can preserve it on write.
# Get-Content strips \r, so we can't infer CRLF vs LF from the parsed lines.
$rawBytes = [System.IO.File]::ReadAllBytes($Report)
$rawText = [System.Text.Encoding]::UTF8.GetString($rawBytes)
$useCRLF = ($rawText -match "`r`n")
$nl = if ($useCRLF) { "`r`n" } else { "`n" }
$lines = $rawText -split "`r?`n"
if (-not $lines -or $lines.Count -eq 0) { return }

# Why-it-matters lookup table. Pattern -> explanation. Patterns are
# regex matched against the FULL finding line (case-insensitive).
# Add to this table as new findings are introduced.
$whyTable = [ordered]@{
    'LSASS PPL DISABLED|LSASS PPL not configured|LSASS PPL not enabled|LSASS protection set but not in effect' = 'LSASS Protected Process Light is disabled or unset. Without PPL, Mimikatz can dump cleartext credentials directly from LSASS memory.'
    'WDigest ENABLED'      = 'WDigest plaintext credential caching is on. Attackers extract cleartext passwords from LSASS using documented techniques.'
    'NTLMv1 allowed'       = 'NTLMv1 is crackable in minutes via Responder + hashcat. Set LmCompatibilityLevel=5 to require NTLMv2.'
    'Firewall DISABLED'    = 'Windows Firewall is off, removing host-level network filtering. Lateral movement and inbound C2 become easier.'
    'SMBv1 ENABLED'        = 'SMBv1 is the protocol exploited by EternalBlue / WannaCry. It must be disabled in 2024+.'
    'UAC DISABLED'         = 'No prompt before privilege elevation. Any malware running as user gets silent admin via auto-elevating processes.'
    'portproxy tunnel rules are ACTIVE' = 'netsh portproxy rules are an active Volt Typhoon TTP for hiding C2 traffic behind the local interface.'
    'runs from .*\(T1036 masquerading\)' = 'A Windows system-process name running from a directory Windows never uses: an implant wearing a familiar name so Task Manager reads as normal. The path proves the file is not the Windows binary, not what it is: check its signature (Get-AuthenticodeSignature) and what started it, and treat a match as an incident.'
    'tried to read LSASS memory' = 'Defender''s rule against reading LSASS memory caught a program asking for access to it. LSASS holds the credentials of everyone signed in, so a program reading its memory is how passwords and tokens get stolen. Read the program named on the line: Microsoft says many ordinary programs ask for access they do not need, and names Google Chrome''s updater, so an updater or a vendor program you installed, validly signed, under Program Files, is the common harmless cause. A program from a temporary folder, a download folder or a user profile, or one you do not recognise, is the finding. If the line says the access was recorded but NOT blocked, the rule is only watching and the read went through: Section 9 offers to switch it to blocking.'
    'BITS recorded an UPLOAD that has already happened' = 'Windows'' own log says a file was SENT from this machine to a web address, and that transfer is finished -- the job is gone from the queue, so this record is the only trace of it. Read the file named on the line: if it is yours (your documents, a browser profile, a mail store, a key file, an archive you did not make) treat it as data theft that has already occurred, and assume whatever it held is gone. Change the passwords used on this machine from a different, clean one, and do not wipe the log -- whoever investigates will want it. Some management software uploads diagnostics on purpose, so a collector that belongs to your company, named rather than a bare address, with a file that is diagnostics rather than your own, is the benign case. If the line is CRITICAL it is because the collector is a bare public address with no name behind it, which has no routine cause.'
    'BITS wrote a file straight into an autostart folder' = 'A background transfer wrote a file directly into a Startup folder, which means Windows runs that file at the next sign-in. Nothing legitimate does this: installers write to Program Files and create a shortcut, they do not stream an executable into Startup. Treat the file named on the line as hostile, look at Section 5''s Startup-folder list for what else is there, and expect it to have run already if anyone has signed in since the time on the line.'
    'BITS transferred to or from a bare IP address' = 'A background transfer went to or from an address with no name behind it. Windows Update, the browsers'' updaters and an on-premises update cache all use names, so a bare address has no routine cause -- it is how a transfer avoids a name that could be blocked or recognised. A private address (10.x, 192.168.x, 172.16-31.x) is NOT reported here, because an on-premises WSUS server or distribution point is reached that way; what is reported is a public one. Look up the address, and read it together with Section 3''s network connections.'
    'A BITS transfer was driven by a program running from a staging folder' = 'The program that asked Windows to move this file was itself running from the shared Public folder or the recycle bin, or from a temporary or downloads folder while not validly signed. An updater runs from Program Files; a program in one of those folders using a Windows service to fetch or send files is how an intrusion moves data without making its own network connections. The folder alone is not the signal -- ordinary installers run from Downloads and from temporary folders, and those are only reported here when the binary is still present and unsigned.'
    'An archive made on this machine is password-protected AND split into volumes' = 'An archive in a staging folder (Downloads, a temp folder, the Public folder or the recycle bin) carries no download mark -- so no browser fetched it; it was made or copied here -- and it is both password-protected and cut into volumes. That is the exact shape Microsoft''s intrusion reports describe for Volt Typhoon, HAFNIUM and NICKEL: collected files packed with rar.exe or 7z.exe so they can be sent out in pieces and read by nobody who intercepts them. Nothing legitimate on a personal machine does both. Treat it as data theft in preparation or already under way: do not delete it before noting its path, size and time; look at Section 4 and Section 16 for what made it; and assume whatever it holds has been chosen for taking.'
    'An archive made on this machine is password-protected and packs credential files|An archive made on this machine is split into volumes and packs credential files' = 'An archive made or copied here (no download mark) is hidden or split AND its visible entry names include a credential-class file: a mail store (.pst/.ost), a password database (.kdbx), a private key, a copy of a registry hive or of ntds.dit, or a browser''s saved-password store. The names beneath the line are what the archive itself says it holds. A backup you made would not normally be split or hidden; treat anything else as credentials packed to leave, change the passwords involved from a clean machine, and keep the file as evidence.'
    'An archive made on this machine is password-protected' = 'A password-protected archive sits in a staging folder with no download mark, so no browser fetched it: it was made here, or copied here, or synced by the OneDrive client (which Microsoft documents as writing no mark). Two benign causes: a backup you protected yourself, and a protected archive OneDrive synced for you. The attacker''s cause is the same shape with a different author. Open it with your archiver: if you know what it is, it is yours; if you do not, it is collected data packed so nobody can read it in transit.'
    'An archive made on this machine is split into volumes' = 'An archive cut into volumes (.part1.rar, .r00, .z01, .7z.001) sits in a staging folder with no download mark. Splitting is how a large collection is sent out in pieces that each pass a size limit; a person splits an archive to fit removable media or an upload cap, which is the benign cause. If a 7z is named, the line may also say its password could not be determined: 7-Zip compresses its header by default, and this audit decompresses it, but not when it is coded with something other than LZMA, larger than the decode cap, out of decode time, or damaged. Open the first volume with your archiver and see what the set holds; the other parts may already have left.'
    'An archive made on this machine packs credential files' = 'A plain archive (no password, one volume) made or copied here holds, by its own entry names, a credential-class file: a mail store, a password database, a private key, a hive copy or a browser''s saved-password store. A backup you made is the common benign cause, which is why this is WARNING and not CRITICAL; the names beneath the line say what it holds. If you did not make it, someone collected those files on purpose.'
    'An archive carries a download mark but sits in ' = 'An archive of the packed-to-leave shape (password-protected and split into volumes, or hidden or split and holding credential files) carries a download mark -- yet it sits in the Public folder, a system temp folder, ProgramData or the recycle bin, and no browser saves a download there. A download mark is a few lines in a stream that any program can write (Set-Content -Stream Zone.Identifier), so it does not clear this shape in this place. If you moved a download here yourself, that is the benign cause; otherwise read it as made here: the line names the origin the mark records, or says it records none.'
    'An archive made on this machine may be password-protected' = 'An archive whose header does not say whether it is password-protected (a 7z header this audit could not decompress -- coded with something other than LZMA, larger than the decode cap, out of decode time, or failing its CRC -- or a damaged archive that cannot be read through) sits in the shared Public folder, where nothing unpacks and nothing routine saves archives. Open it with your archiver: a password prompt answers the question.'
    'file\(s\) in staging folder .* could not be read by an administrator' = 'A file in a staging folder could not be opened even with administrator rights, so whether it is an archive was not checked and the all-clear does not cover it. Staging folders hold nothing an administrator is normally denied: check the file with icacls and Get-Acl, and who owns it.'
    'could not be listed by an administrator -- archives there were NOT checked' = 'A staging folder could not be listed even with administrator rights, so archives in it were not examined and the all-clear does not cover it. A folder an administrator cannot open is itself unusual: check its permissions (icacls <folder>) and who owns it.'
    'is queued to UPLOAD a file off this machine' = 'A Background Intelligent Transfer Service job is set up to send a file FROM this machine to a web address. BITS is a Windows service, so the transfer continues after you log off, survives restarts and does not look like a program of its own on the network. The lines beneath the finding name the file that would leave and the collector it would go to. Some management software does this on purpose -- a ConfigMgr management point receives client uploads this way, and diagnostics tools ship a .cab the same way -- so the owner account and the collector are what tell that apart from an intrusion: a collector that belongs to your company, named rather than a bare IP address, with a file that is diagnostics rather than your own documents. If the finding is CRITICAL, it is because the collector is a bare public IP address with no name behind it, or because the file is one of yours: your own documents, desktop, downloads or OneDrive folder, a browser profile with its saved passwords, a mail store, a password database or a private key, a copy of a registry hive from Windows'' own config folder, or something read out of a volume shadow copy. A certificate file is named rather than treated as a key, because a .pem is as often a public certificate as a private one. In that case treat it as data theft in progress: do not resume or delete the job before noting its details, remove it with Remove-BitsTransfer once they are recorded, and assume whatever the file holds is already gone.'
    'is EXCLUDED from Defender' = 'A program has been excluded from Defender''s rule against reading LSASS memory, so it can read the credentials in LSASS and leave no record at all. Microsoft documents that this rule ignores ordinary antivirus exclusions and honours only its own, so an exclusion here was set deliberately for this rule. If you or your IT department did not add it, treat it as someone preparing to steal credentials: remove the exclusion and look at what that program is.'
    'Silent-process-exit monitoring is ENABLED' = 'Windows has been told to watch this program exit and act on it, which is what makes the dump settings beneath it apply. For LSASS, nothing in Windows configures this by itself: a person did, with a debugger, a dump tool, or by hand. If that person was not you, your IT department or an incident responder, treat it as preparation to capture the credentials in LSASS''s memory.'
    'is configured to have its memory DUMPED when it exits' = 'This program is set up so that Windows writes its memory to a file when it exits. For LSASS that file holds the credentials of everyone signed in, and anyone who can read the file can use them. The line names the folder it would be written to. Remove the setting once whoever asked for it no longer needs it; until then every restart can leave another copy of the credentials on disk.'
    'Error Reporting is configured to write a dump of' = 'Windows Error Reporting has been set up to write a memory dump of this program specifically. For LSASS that file holds the credentials of everyone signed in. A support engineer may ask for this to diagnose a crash; nothing in Windows sets it for LSASS on its own.'
    'A memory dump of' = 'A file holding a program''s memory is on disk. For LSASS that file holds the credentials of everyone who signed in since the last restart, in a form an attacker can use directly, and copying the file is all that is needed. If you did not create it: do not delete it (whoever investigates will want it), change the passwords used on this machine from a different, clean computer, and treat the account as compromised. The line gives the file''s path, size and the time it was written -- that time is when the credentials were taken.'
    'is a copy of LSASS' = 'A second process holding a copy of LSASS''s memory, made by process snapshotting or reflection: credential-dumping tools make one and read the copy instead of LSASS, so LSASS itself is never read. Windows does not copy LSASS on a healthy machine; an administrator''s own dump (ProcDump -r) does. Treat it as credential theft in progress unless you made the dump yourself: note the copy''s and its parent''s PIDs and start times beneath the finding, check Section 12 for the Event 4688 record, and change the passwords used on this machine from a different, clean one.'
    'is a copy of its parent' = 'A system process whose parent has its own name and image is a copy of it (process snapshotting or reflection). Windows Error Reporting copies a hung process this way while it reports on it, and so does code injection by forking, which runs the attacker''s code in the copy. Check whether WerFault.exe is running and the copy is gone on a second look; a copy that stays is the finding.'
    'lsass\.exe was copied at' = 'The Security log recorded lsass.exe created by lsass.exe itself (Event 4688): a copy of LSASS, the record credential-dumping tools leave when they read a copy instead of LSASS. Unless you made a dump of LSASS yourself at that time, treat it as credential theft: change the passwords used on this machine from a different, clean one, and look at what else ran around that time (Section 16 lists Event 4688).'
    'lsass\.exe was started at .* by ' = 'The Security log recorded the real lsass.exe started by something other than wininit.exe (Event 4688). Windows starts LSASS once, at boot, from wininit.exe: look at the process named as its starter.'
    'has the wrong parent:' ='Windows starts each system process from one parent (svchost.exe only from services.exe, lsass.exe and services.exe only from wininit.exe), so a different parent -- or a parent that is gone where the real one cannot exit -- means something else started it, even if the file sits in System32. Read the child: and parent: lines beneath the finding: a parent line that says the number now belongs to a later process means the real parent exited and its PID was reused. Known benign shapes: a process-isolated Windows container (its own tree on the host; check whether the parent chain leads to the container runtime), and a program run in a Sandboxie-Plus sandbox (the parent is SandboxieDcomLaunch.exe or SandboxieRpcSs.exe under the Sandboxie-Plus install directory).'
    'Windows runs one \S+' = 'Windows runs exactly one wininit.exe, services.exe, lsass.exe and LsaIso.exe, and one csrss.exe per session: a second one is an impostor even when its own parent looks right -- the shape of a renamed chain (a fake wininit starting a fake services starting an implant). The instance: lines show each copy''s parent, session, path and start time; the one with the odd path, parent or start time is the impostor.'
    'runs in session \d+ -- Windows runs' = 'wininit.exe, services.exe, lsass.exe and LsaIso.exe run only in session 0, and winlogon.exe never does: a copy in the wrong session was not started by Windows.'
    'WMI EventFilter|WMI permanent EventFilter|EventFilter subscriptions present' = 'Non-default WMI permanent subscription. Survives reboots without an EXE on disk -- stealthy, common in APT toolkits (APT29, FIN8).'
    'ActiveScript.*Consumer' = 'WMI ActiveScript consumer hosts an inline VBScript/JScript payload. Even stealthier than CommandLineEventConsumer.'
    'named-pipe check NOT performed' = 'The named pipes could not be listed (or came back empty), so a C2 framework''s default pipe would go unseen. This is missing coverage, not a finding; re-run elevated and check that nothing interferes with listing \\.\pipe\.'
    'Cobalt Strike named pipes detected|Possible Cobalt Strike pipes detected|Cobalt Strike default named pipes present' = 'Active Cobalt Strike C2 beacon. Treat as live compromise -- isolate the host immediately.'
    'Possible next-gen C2 named pipes detected|Sliver|Brute Ratel|Havoc' = 'Next-gen post-exploitation C2 framework named pipe detected. Treat as live compromise.'
    'Suspicious process paths|Suspicious paths' = 'Process running from \Temp\, \AppData\, \Downloads\, \Public\, or \Recycle -- attacker-favored staging directory.'
    'IFEO Debugger hijack' = 'Image File Execution Options Debugger redirect = accessibility-binary hijack (T1546.008). SYSTEM shell on login screen via Shift x5.'
    'testsigning.*[Yy]es|Test.Signing.*[Ee]nabled' = 'testsigning=yes allows unsigned kernel driver loads. Often used by BYOVD (Bring Your Own Vulnerable Driver) adversaries.'
    'Service .* failed Authenticode|service\(s\) failed Authenticode'    = 'Service binary failed Authenticode gating. Unsigned / unexpected-signer / bad-path services are common T1543.003 persistence indicators -- review the listed binaries against known-good vendors.'
    'scheduled task\(s\) with actions in suspicious locations|Tasks with Actions in Suspicious' = 'A scheduled task launches a binary from \Temp\, \AppData\, \Downloads\, \Public\, or \ProgramData\update. Unsigned binaries here are a common persistence TTP (T1053.005); validly-signed per-user updaters (Brave/Zoom/Chrome) are downgraded to [INFO].'
    'IOC category matches found' = 'One or more Section 18 CTI sub-checks matched a known-bad indicator (process / pipe / service / file / DNS / LOLBin / registry / hash). Review the per-sub-check [WARNING]/[CRITICAL] lines in Section 18.'
    'Process IOC matches found above' = 'A running process''s name, PID or path holds an ioc_processes.txt entry (credential dumpers, tunnelling and exfiltration tools, ransomware names). The matching line is printed just above it in Section 18a. It is a substring match: confirm with Get-Process -Id <PID> | Format-List Path, Company and Get-AuthenticodeSignature on the path before acting.'
    'C2 domain IOC matches found in DNS cache' = 'The DNS client cache holds a name containing an ioc_domains.txt fragment, so something on this PC resolved it recently, or HOSTS lists it. The matching cache lines are printed above it in Section 18f. Several fragments are developer tunnels (ngrok.io, trycloudflare.com); ask who uses them before treating it as C2.'
    'IOC match NOT performed|LOLBin pattern match NOT performed|IOC sweep NOT performed' = 'A Section 18 match could not run: its list could not be read or holds no entries, or Windows would not list what it matches against (processes, pipes, services, scheduled tasks). This is a gap, not a clean result -- these checks used to print [OK] or [SKIPPED] and raise nothing. The line says which. For a list, check that the ThreatLists folder next to the report (or in the tool folder) holds it; for a listing, run the Command: line printed above it.'
    'LOLBin abuse patterns detected' = 'A running process command line holds an ioc_lolbins.txt pattern: a built-in Windows binary used the way attackers use it (download, decode, proxy execution). The matching command lines are printed above it in Section 18g; read each and ask whether you started it.'
    'Suspicious registry IOCs found' = 'A registry value matched the ioc_registry.txt threat list (persistence Run keys, COM hijack, defense-evasion toggles). Cross-check the listed key against the IOC source and recent changes.'
    'Service IOC matches found' = 'A service name or display name holds an ioc_services.txt entry (remote-execution services such as PSEXESVC, look-alikes of real Windows services, BYOVD driver services). The matching services are listed above it in Section 18c with their binary path. It is a substring match, and PsExec leaves PSEXESVC behind after legitimate admin use: check the binary path and its signature before acting.'
    'Named pipe IOC matches found' = 'A named pipe holds an ioc_named_pipes.txt pattern, the default pipe names of C2 frameworks (Cobalt Strike postex_/msagent_/status_, Sliver, Metasploit). The pipes are listed above it in Section 18b. Find the owning process: Get-ChildItem \\.\pipe\ shows the names; a Sysinternals handle search names the process holding one.'
    'Scheduled task IOC matches found' = 'A scheduled task''s path or action holds an ioc_scheduled_tasks.txt entry (persistence tasks named after Windows or vendor updaters). The matching tasks and their full actions are listed above it in Section 18e. Read the action: Get-ScheduledTask -TaskPath <path> -TaskName <name> | Select-Object -ExpandProperty Actions.'
    'Known malware staging files found' = 'A file on disk matched an ioc_file_paths.txt entry (attacker staging location). VERIFY each path before acting: overly-broad path IOCs (e.g. a browser Cookies file, \Downloads\*.iso, \Startup\*.lnk) can match ubiquitous legitimate files and produce false positives -- prune such entries from ioc_file_paths.txt or upstream.'
    'Non-standard entries found in HOSTS' = 'The HOSTS file has entries beyond localhost. Malware uses HOSTS to blackhole security/AV update domains or redirect traffic (DNS hijacking). Review each non-localhost line.'
    'BYOVD'                = 'Known vulnerable driver present on disk. Attackers load these to disable EDR from kernel mode. Read the kernel: line first -- LOADED means it is in the kernel now; on disk only with no install event fits a tool such as Process Explorer having extracted it. Look the full sha256 up at loldrivers.io; the install: line gives the timeline.'
    'Security event log was cleared at .* before this PC took its current name' = 'The clear record names a different computer than this one and predates Windows'' install date here: it was written before this PC took its current name, as when a Windows image is prepared (every log cleared at once) and then renamed on first boot. If this PC was ever called that other name while you were using it, the clear happened in its own life: treat it as a compromise. If you built this image, or got it from a source you trust, that is the explanation. If not, treat it as a compromise: whatever happened before the clear is gone.'
    'System event log was cleared at .* often benign' = 'Windows clears the System log itself after some updates, driver installs and disk cleanup, so this alone is often benign. The Security log 1102 is the cover-up signal, and Section 16 grades it on its own line.'
    'Event log ''[^'']+'' was cleared at' = 'A specific event log was cleared. A security tool''s own log (Sysmon, PowerShell) is where an intruder''s actions were recorded, and clearing it is how they are hidden. The Event 104 record names the account that cleared it.'
    'Security event log was CLEARED|System event log was CLEARED' = 'Event log clearing (1102/104) is a textbook anti-forensics move. Treat as evidence of recent attacker activity.'
    'COM CLSID overrides|COM Object Hijacking' = 'HKCU CLSID InprocServer32 overrides are a T1546.015 persistence technique. Often paired with DLL search-order hijacking.'
    '\bflagged by:\s*\d+\s*engine' = 'VirusTotal flagged this IP / file across multiple engines. Cross-reference with the per-IP local process owner above.'
    'PendingFileRenameOperations' = 'Files are queued to be renamed or deleted at the next restart; the operations are listed beneath this finding. A legitimate installer or the Defender platform update mid-flow is the usual cause; malware completing an install is the other. Read the paths. The [INFO] line beneath says whether the flag was written before or after the last boot: before means it survived a restart (re-created, or never processed because Fast Startup "Shut down" does not run the queue -- use Restart).'
    'Windows Update requires a reboot|Component Based Servicing has a reboot queued' = 'Windows Update or servicing is waiting for a restart. Run the audit after a Restart (not Shut down) for a complete picture; the [INFO] line beneath says whether the flag predates the last boot.'
    'AppInit_DLLs set'    = 'AppInit_DLLs causes a DLL to be injected into every GUI process. Legacy persistence technique; should be empty on modern Windows.'
    'Sticky Keys'          = 'Sticky Keys shortcut at the login screen is a remote unauthenticated trigger for sethc.exe (which attackers commonly hijack to launch cmd.exe as SYSTEM).'
    'Process-creation command-line logging is DISABLED' = 'Event 4688 records that a process started; without ProcessCreationIncludeCmdLine_Enabled it omits the command line, which is where an encoded PowerShell payload, a LOLBin argument or a download URL lives. Turning it on records arguments that can include secrets typed on a command line, so the log needs the same protection as the Security log.'
    'PS Script Block Logging NOT enabled' = 'Event 4104 is the record of what PowerShell actually ran. Without it a fileless or in-memory attack leaves nothing to read afterwards. The stage-1 remediation script sets EnableScriptBlockLogging=1; nothing else changes.'
    'account\(s\) are HIDDEN from the sign-in screen' = 'SpecialAccounts\UserList hides an account from the sign-in screen and from Settings. Covert access is the attacker shape; some sandboxes and service products hide their own accounts the same way. The line names the accounts: one you did not create, or whose name you do not recognise, is the finding -- check its group membership and last logon in Section 2.'
    'Key ASR rule not in Block mode' = 'Attack Surface Reduction rules stop the Office-macro, script and ransomware tradecraft Defender sees most. Stage 1 of the remediation puts the five key rules in Audit mode (logs, blocks nothing); review Event 1122 for a few days, then stage 2 switches them to Block.'
    'New root certificate'  = 'A new root CA cert was installed in the last 90 days. DPRK Ruby Sleet drops fake roots to MITM TLS-secured channels.'
    'KrbRelayUp|Kerberos RC4' = 'Kerberos misconfig that enables relay / ticket-forging attacks (Forest Blizzard / NTLM relay).'
    'AutoRun.*Default|NoDriveTypeAutoRun'  = 'AutoRun for removable media is not restricted to the safe default. USB worms (Lazarus DTrack, older banking trojans) abuse this.'
    'BitLocker.*[Dd]isabled|BitLocker.*OFF' = 'Disk encryption is off. Lost / stolen device exposes all data, and offline attacks against the OS are trivial.'
    '[Ss]ecure ?Boot.*[Dd]isabled|SecureBoot.*OFF' = 'Secure Boot is disabled. Bootkits and pre-OS rootkits can persist below Windows defenses.'
    'RDP enabled WITHOUT NLA|Network Level Authentication.*disabled' = 'RDP without NLA exposes the pre-auth attack surface to network-reachable adversaries (BlueKeep family).'
    '[Aa]udit [Pp]olicy.*[Mm]issing|advaudit.*not [Ss]et' = 'Critical audit subcategory is not logging. Detection-blind for this event class going forward.'
    'USB ?Storage.*[Ee]nabled|RemovableStorage' = 'USB mass-storage class is enabled. Data-exfil and worm-spread risk.'
    'AlwaysInstallElevated' = 'AlwaysInstallElevated is set -- any user-launched MSI runs as SYSTEM. T1548.002 privilege escalation.'
    'Defender (real-time protection|antivirus) is OFF|DisableRealtimeMonitoring is SET|Defender antimalware service is not enabled' = 'Microsoft Defender is not protecting this machine in real time and no other antivirus reported control of it: files are not scanned as they are written or run. If a third-party product is installed, Section 9 would say Defender is in passive mode instead. Otherwise re-enable it (Set-MpPreference -DisableRealtimeMonitoring $false) and find what turned it off -- malware disables real-time protection first.'
    'Tamper Protection is OFF' = 'Tamper Protection stops an attacker who gains admin from silently switching Defender and its logging off. Turn it on in Windows Security > Virus & threat protection settings; it is not scriptable by design.'
    'Defender signatures are \d+ day' = 'Defender definitions are stale, so recent malware families are not recognised. Run Update-MpSignature or check why Windows Update is not delivering them (Section 1 shows the last update run).'
    'Disable(BehaviorMonitoring|BlockAtFirstSeen|IOAVProtection|ScriptScanning) is set|Defender (antispyware|on-access) protection is off' = 'A Defender protection layer is switched off by policy: behaviour monitoring, cloud first-sight blocking, download scanning, script scanning, on-access or antispyware protection. Each is a documented defence-evasion step (T1562.001); re-enable it with Set-MpPreference and find who set it.'
    'Defender.*[Dd]isabled|RealTimeProtection.*[Ff]alse|MpPreference.*[Dd]isabled' = 'Microsoft Defender real-time protection is off. Hosts running without AV/EDR are far more likely to be compromised.'
    'PSReadLine .* history|ConsoleHost_history' = 'PowerShell command history file is readable. Often contains plaintext credentials accidentally typed into scripts.'
    'WinRM RUNNING' = 'WinRM is listening. Combined with low-priv credentials, enables lateral movement via PSRemoting and PowerShell over WinRM.'
    'sshd.*[Rr]unning|OpenSSH Server.*RUNNING' = 'OpenSSH Server is running on Windows. Verify authorized_keys lists are legit; check sshd_config for password-auth and root-login policy.'
    'cert-(invalid|expired|revoked)' = 'Authenticode signing cert failed validation. Stolen-cert malware (3CX, CCleaner) is the canonical scenario.'
    'unsigned bad-path|trusted-signer bad-path|unexpected-signer bad-path' = 'Service binary in an adversary-favored path (\Temp\, \AppData\, \Downloads\, \Public\). Investigate service install timestamp + parent process.'
    # Section 17 baseline diff. The reason in parentheses on the line says why
    # the change was or was not forgiven; the was/now lines beneath a CHANGED
    # item are the evidence.
    'NEW listening port since baseline' = 'A process accepts connections that was not listening when the baseline was saved. Read the owner and bind address after the arrow: a loopback-only bind (127.0.0.1 / ::1) is unreachable from the network; a bind to 0.0.0.0 or :: by a process you do not recognise is how an implant takes calls. Section 3 lists the connection.'
    'NEW (local administrator|root CA certificate) since baseline' = 'A new local administrator or root CA is never routine: one is a takeover, the other is how TLS interception is installed. Remove it unless you added it yourself.'
    'NEW (service|scheduled task|kernel driver|autorun/persistence value) since baseline' = 'Something registered to run since the baseline was saved. The reason in parentheses says why it was not forgiven (unsigned, staging path, suspicious argument, a COM-handler task outside the Windows paths). A validly signed install you recognise is noise; an unsigned binary, a staging path or a suspicious argument is persistence matching no signature.'
    'CHANGED (service|scheduled task|kernel driver|autorun/persistence value) since baseline' = 'A registered item points somewhere else than when the baseline was saved. Compare the was/now lines beneath it: a path that differs only in a version segment, with the new binary validly signed, is an update; a new directory, a new signer, an unsigned binary, a changed start mode or a changed argument is a replaced binary or a repointed command.'
    'CHANGED listening port since baseline' = 'A listener changed owner or moved from loopback to a network-reachable address. Read was/now: the same port now bound to 0.0.0.0 or :: is reachable from outside; a new owner outside the system RPC processes is a process taking over a port.'
}

function Get-WhyMatters {
    param([string]$Line)
    foreach ($pat in $whyTable.Keys) {
        if ($Line -match $pat) { return $whyTable[$pat] }
    }
    return $null
}

# Walk the report and collect findings with their parent section context.
# Track BOTH the most recent main section header (`[N/18] TITLE` inside a
# `=====` box) and the most recent sub-section header (`--- Title ---`).
# Findings are tagged with `MainSection > SubSection` so the analyst sees
# both levels of context in the summary.
$currentMain = '(pre-section)'
$currentSub = $null
$findings = New-Object System.Collections.Generic.List[object]
$skipped = 0
for ($li = 0; $li -lt $lines.Count; $li++) {
    $L = $lines[$li]
    # Main section: a bracketed [N/18] or [INIT N/14] inside a ===== box
    if ($L -match '^\s*\[(\d+/18|INIT \d+/14)\]\s+(.+?)\s*$') {
        $currentMain = "[$($matches[1])] $($matches[2])"
        $currentSub = $null  # reset sub when entering a new main section
        continue
    }
    # Sub-section: --- Title ---
    if ($L -match '^---\s(.+?)\s---\s*$') {
        $currentSub = $matches[1]
        continue
    }
    if ($L -match '^\s*\[SKIPPED\]') {
        $skipped++
        continue
    }
    if ($L -match '^\s*\[(CRITICAL|WARNING)\]') {
        $sev = $matches[1]
        $sect = if ($currentSub) { "$currentMain > $currentSub" } else { $currentMain }
        # When the finding line ends in ':' it promises a list of the matched
        # items (tasks, registry hits, services, etc.). Capture up to 6 of the
        # immediately-following non-blank lines so the TOP FINDINGS summary
        # shows WHICH items matched, not just a dangling header. Stop at a
        # blank line, a divider, a Command: echo, or the next finding/section.
        $detail = New-Object System.Collections.Generic.List[string]
        if ($L.TrimEnd().EndsWith(':')) {
            for ($dj = $li + 1; $dj -lt $lines.Count -and $detail.Count -lt 6; $dj++) {
                $dl = $lines[$dj]
                if ($dl.Trim() -eq '') { break }
                if ($dl -match '^\s*\[(CRITICAL|WARNING|OK|INFO|SKIPPED)\]') { break }
                if ($dl -match '^={3,}') { break }
                if ($dl -match '^---\s.+\s---\s*$') { break }
                if ($dl -match '^\s*\[(\d+/18|INIT \d+/14)\]') { break }
                if ($dl -match '^\s*Command:') { break }
                $detail.Add($dl.TrimEnd())
            }
        }
        $findings.Add([pscustomobject]@{
            Severity = $sev
            Section  = $sect
            Line     = $L.Trim()
            Why      = (Get-WhyMatters -Line $L)
            Detail   = @($detail.ToArray())
        }) | Out-Null
    }
}

# Build TOP FINDINGS block (always emitted, even for clean reports)
$block = New-Object System.Collections.Generic.List[string]
$block.Add('====================================================================')

if ($findings.Count -eq 0) {
    $block.Add(' TOP FINDINGS: CLEAN')
    $block.Add('====================================================================')
    $block.Add('')
    $block.Add(' No CRITICAL or WARNING findings detected.')
    $block.Add(' No issues surfaced by the checks that ran. This is NOT a statement that the')
    $block.Add(' system is clean -- see READ THIS FIRST above. Recommendation: re-run monthly.')
    $block.Add('')
    $block.Add('====================================================================')
    $block.Add('')
} else {
    $block.Add(' TOP FINDINGS (highest severity first) -- review these first')
    $block.Add('====================================================================')
    $block.Add('')
    $sevOrder = @{ 'CRITICAL' = 0; 'WARNING' = 1 }
    $top = $findings | Sort-Object { $sevOrder[$_.Severity] } | Select-Object -First $MaxFindings
    $rank = 0
    $fallbackWhy = 'No specific analyst note mapped for this finding. Consult the full section body below for context.'
    foreach ($f in $top) {
        $rank++
        # Default truncation cap of 220 chars to keep the summary block scannable.
        # Skip truncation entirely for findings that contain a backslash -- these
        # are Windows file paths or registry paths, and cutting them mid-string
        # destroys the most actionable information the analyst needs (the exact
        # path to the artifact). HTML rendering wraps long lines via the
        # word-break CSS on `pre` and the severity divs, so a long path stays
        # visible without horizontal scrolling.
        $shortLine = $f.Line
        $hasPath = ($shortLine -match '\\')
        if (-not $hasPath -and $shortLine.Length -gt 220) {
            $shortLine = $shortLine.Substring(0,217) + '...'
        }
        $block.Add(" $rank. [$($f.Severity)] Section: $($f.Section)")
        $block.Add("    Finding: $shortLine")
        # Detail lines (the actual matched items) for list-style findings, so
        # the analyst sees WHICH tasks/keys/services matched without scrolling
        # to the full section body.
        if ($f.Detail -and @($f.Detail).Count -gt 0) {
            foreach ($d in @($f.Detail)) {
                $dd = $d.Trim()
                if ($dd -eq '') { continue }
                if ($dd.Length -gt 110) { $dd = $dd.Substring(0,107) + '...' }
                $block.Add("      - $dd")
            }
        }
        # Why-It-Matters text. Use the mapped explanation when present, otherwise
        # emit a generic fallback so the analyst is never left wondering whether
        # the absence of a note means "low severity" or "unmapped pattern".
        $why = if ($f.Why) { $f.Why } else { $fallbackWhy }
        $wrapped = New-Object System.Collections.Generic.List[string]
        while ($why.Length -gt 75) {
            $split = $why.LastIndexOf(' ', 75)
            if ($split -lt 1) { $split = 75 }
            $wrapped.Add($why.Substring(0, $split))
            $why = $why.Substring($split).TrimStart()
        }
        if ($why.Length -gt 0) { $wrapped.Add($why) }
        $first = $true
        foreach ($w in $wrapped) {
            if ($first) { $block.Add("    Why it matters: $w"); $first = $false }
            else        { $block.Add("                    $w") }
        }
        $block.Add('')
    }
    if ($findings.Count -gt $MaxFindings) {
        $block.Add(" ...$($findings.Count - $MaxFindings) more finding(s) below. Full detail in the per-section body.")
        $block.Add('')
    }
    $block.Add('====================================================================')
    $block.Add('')
}

# Coverage transparency: checks that could not run announce themselves with
# [SKIPPED] lines. Surface the count here so a "CLEAN" verdict is never read
# as full coverage when parts of the audit silently could not execute.
if ($skipped -gt 0) {
    $block.Add(" COVERAGE NOTE: $skipped check(s) reported [SKIPPED] and were NOT performed.")
    $block.Add(' The verdict above covers only the checks that ran. Search the report')
    $block.Add(' for [SKIPPED] to see which checks were missed and why.')
    $block.Add('')
    $block.Add('====================================================================')
    $block.Add('')
}

# Find insertion point: right before the [1/18] section header.
$prependIndex = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^={5,}\s*$' -and $i + 1 -lt $lines.Count -and $lines[$i + 1] -match '^\s*\[1/18\]') {
        $prependIndex = $i
        break
    }
}

if ($prependIndex -eq 0) {
    # Fallback: append at the END if we can't find Section 1
    $newReport = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) { $newReport.Add($l) }
    $newReport.Add('')
    foreach ($l in $block) { $newReport.Add($l) }
} else {
    $newReport = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $prependIndex; $i++) { $newReport.Add($lines[$i]) }
    foreach ($l in $block) { $newReport.Add($l) }
    for ($i = $prependIndex; $i -lt $lines.Count; $i++) { $newReport.Add($lines[$i]) }
}

# Write with preserved line endings (CRLF on Windows-generated reports).
$bytes = [System.Text.Encoding]::UTF8.GetBytes(($newReport -join $nl) + $nl)
[System.IO.File]::WriteAllBytes($Report, $bytes)
