# rmm_check.ps1 -- remote-access (RMM) tools running or installed (T1219).
# AnyDesk, TeamViewer, ScreenConnect and their kind let someone else see and
# control this PC. They are legitimate products, and they are also what an
# intruder -- or a person with a few minutes at the keyboard -- installs to
# come back later.
#
# Three inline checks did this, and none of them reached the findings ledger:
#   Section 4   select_lines over the process dump for nine names: a plain
#               substring over whole lines, so "Atera" matched any process or
#               path containing "Lateral"; the matches were printed untagged.
#   Section 17  Get-Process -Name <product name>: ScreenConnect runs as
#               ScreenConnect.ClientService and Splashtop as SRService, so
#               most products were missed; a hit printed "[RMM RUNNING]".
#   Section 17  DisplayName -match <token> over the Uninstall keys with errors
#               silenced: a failed read printed "[OK] No unexpected RMM
#               software found."; a hit printed "[RMM INSTALLED]".
# "[RMM RUNNING]" and "[RMM INSTALLED]" are outside the report's severity
# vocabulary, so a running remote-access tool was counted nowhere.
#
# DECIDED BY THE OWNER (2026-11-11): a running tool AND an installed one are
# each a counted WARNING. Someone who installed TeamViewer on purpose gets
# that warning on every audit; so the line carries what they need to dismiss
# it in one look (which product, the file, who signed it), and the benign
# case is catalogued in tests\benign_corpus.txt.
#
# THE RULE (pure, pinned by -SelfTest):
#   * one product table. Process names are matched from their START, plus
#     the product's own install folder; display names at WORD EDGES. A name
#     that only contains a product name is never a match: "Lateral" is not
#     Atera and "Collateral Manager" is not either;
#   * the table is NAMES, not proof. A renamed binary is not caught here
#     (THREAT_MODEL residual); a signed binary under a product's name is
#     still the finding -- the signature is context, never an excuse;
#   * running processes come from Section 4's own snapshot (-TreePath), the
#     same measurement its other checks read, never a second enumeration;
#   * the snapshot missing or empty, or an Uninstall root that could not be
#     read, is "[WARNING] ... NOT performed" with its own marker. A hit and a
#     gap are independent: both are raised. HKLM's native Uninstall key
#     exists on every Windows; its Wow6432Node and HKCU twins may not, and
#     their absence is an answer;
#   * nothing found says how much was examined.
# Markers: dz_rmm_run_hit, dz_rmm_inst_hit, dz_rmm_gap. State:
# dz_rmm_state.txt  run=<n|gap>,inst=<n|gap|n+gap>.
#
# Usage:
#   powershell -File tools\rmm_check.ps1 -TreePath <dz_proc4_tree.tmp> [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\rmm_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    # Section 4's process tree: PID|PPID|CreatedUtcTicks|SessionId|Path|Name.
    [string]$TreePath,
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # Only CI changes this: throwaway keys standing in for the three
    # Uninstall roots, so every state runs through the real reader.
    [string[]]$UninstallRoots,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_rmm_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    # An empty value is no verdict, never a marker.
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    # A process name, a registry value or an error goes into the report as
    # text: no control characters, and capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    return $t
}

# Proc: the process name WITHOUT .exe, anchored at its START and ended at a
# word edge or the end -- the portable and quick-support forms are how these
# tools usually arrive in a scam, and nothing is installed then: a browser
# saves a second download as "AnyDesk (1).exe", TeamViewer's quick support is
# TeamViewerQS.exe, RustDesk's portable runs under its download name
# (rustdesk-1.3.2-x86_64.exe). A name that only CONTAINS a product name
# ("MyAnyDeskNotes", "LateralHelper") is not a match. Dir: the product's own
# install folder in the path, the second criterion, for a helper binary under
# a name the table does not list. Disp: the Uninstall DisplayName, at word
# edges. All three are names, not proof.
$script:Products = @(
    @{ Name = 'ScreenConnect (ConnectWise Control)'; Proc = '^ScreenConnect\.'; Dir = '\\ScreenConnect Client( \(|\\)'; Disp = '\bScreenConnect\b|\bConnectWise Control\b' },
    @{ Name = 'AnyDesk'; Proc = '^AnyDesk\b'; Dir = '\\AnyDesk\\'; Disp = '\bAnyDesk\b' },
    @{ Name = 'TeamViewer'; Proc = '^TeamViewer|^tv_(w32|x64)$'; Dir = '\\TeamViewer\\'; Disp = '\bTeamViewer\b' },
    @{ Name = 'Ammyy Admin'; Proc = '^AA_v3\b|^Ammyy'; Dir = '\\Ammyy\\'; Disp = '\bAmmyy\b' },
    @{ Name = 'RustDesk'; Proc = '^rustdesk\b'; Dir = '\\RustDesk\\'; Disp = '\bRustDesk\b' },
    @{ Name = 'Splashtop'; Proc = '^SR(Service|Manager|Agent|Server|Feature|AppPB)$|^strwinclt$|^Splashtop'; Dir = '\\Splashtop\\'; Disp = '\bSplashtop\b' },
    @{ Name = 'Atera'; Proc = '^AteraAgent$|^AgentPackage'; Dir = '\\ATERA Networks\\'; Disp = '\bAtera\b' },
    @{ Name = 'Kaseya'; Proc = '^AgentMon$|^Kaseya'; Dir = '\\Kaseya\\'; Disp = '\bKaseya\b' },
    @{ Name = 'ConnectWise Automate (LabTech)'; Proc = '^LT(SVC|SvcMon|Tray)$'; Dir = '\\LabTech\\'; Disp = '\bConnectWise Automate\b|\bLabTech\b' },
    @{ Name = 'BeyondTrust Remote Support (Bomgar)'; Proc = '^bomgar-'; Dir = '\\Bomgar\\|\\BeyondTrust\\Remote Support'; Disp = '\bBomgar\b|\bBeyondTrust Remote Support\b' },
    # Hamachi is LogMeIn's VPN, not its remote-control product, and installs
    # under "LogMeIn Hamachi\", which the Dir pattern does not match.
    @{ Name = 'LogMeIn / GoTo'; Proc = '^LogMeIn|^LMIGuardianSvc$|^lmi_rescue|^g2ax_'; Dir = '\\LogMeIn\\|\\LogMeIn Rescue'; Disp = '\bLogMeIn\b(?! Hamachi)|\bGoToAssist\b' },
    @{ Name = 'RemotePC'; Proc = '^RemotePC'; Dir = '\\RemotePC\\'; Disp = '\bRemotePC\b' }
)

# PURE. The product a process name belongs to, or ''.
function Get-RmmProductForProcess {
    param([string]$ProcessName, [string]$Path = '')
    $n = ([string]$ProcessName).Trim() -replace '\.exe$', ''
    if (-not $n) { return '' }
    foreach ($p in $script:Products) { if ($n -match $p.Proc) { return [string]$p.Name } }
    if ($Path) { foreach ($p in $script:Products) { if ([string]$Path -match $p.Dir) { return [string]$p.Name } } }
    return ''
}
# PURE. The product an Uninstall DisplayName belongs to, or ''.
function Get-RmmProductForDisplay {
    param([string]$DisplayName)
    $n = ([string]$DisplayName).Trim()
    if (-not $n) { return '' }
    foreach ($p in $script:Products) { if ($n -match $p.Disp) { return [string]$p.Name } }
    return ''
}

# PURE. $Proc: @{ Error; Count }. $Running: @( @{ Product; Name; Pid; Path;
# Sig } ). $Roots: @( @{ Name; State = ok|nokey|unreadable; Required; Error;
# Count; Unreadable = @(subkey names) } ). $Installed: @( @{ Product;
# Display; Version; Publisher } ). Returns @{ Lines; RunHit; InstHit; Gap;
# State }.
function Get-RmmVerdict {
    param($Proc, $Running, $Roots, $Installed)
    $out = New-Object System.Collections.ArrayList
    $r = @{ RunHit = $false; InstHit = $false; Gap = $false }
    $gloss = '[INFO] These are legitimate products that many people install on purpose. If you did not put this one here, someone else may be able to see and control this PC: find out who installed it before removing it.'
    # --- running ---
    $runState = ''
    $run = @($Running | Where-Object { $null -ne $_ })
    if ($null -eq $Proc -or [string]$Proc.Error -or [int]$Proc.Count -le 0) {
        $why = if ($null -ne $Proc -and [string]$Proc.Error) { ConvertTo-PrintableText ([string]$Proc.Error) } else { 'the process snapshot holds no processes' }
        [void]$out.Add(('[WARNING] Remote-access tool check (running) NOT performed -- Section 4''s process snapshot could not be read (' + $why + '), so a running remote-access tool would go unseen (T1219).'))
        $r.Gap = $true; $runState = 'gap'
    } else {
        foreach ($x in $run) {
            $where = if ([string]$x.Path) { ConvertTo-PrintableText ([string]$x.Path) } else { 'path not readable from this token' }
            $sig = if ([string]$x.Sig) { ConvertTo-PrintableText ([string]$x.Sig) } else { 'signature not read' }
            [void]$out.Add(('[WARNING] Remote-access tool RUNNING: ' + [string]$x.Product + ' -- ' + (ConvertTo-PrintableText ([string]$x.Name)) + ' (PID ' + [string]$x.Pid + '), ' + $where + '; ' + $sig + ' (T1219)'))
        }
        if ($run.Count -gt 0) { $r.RunHit = $true }
        else { [void]$out.Add(('[OK] No known remote-access tool running (' + [string]$Proc.Count + ' process(es) in Section 4''s snapshot, matched from the start of the name, or by the product''s install folder).')) }
        $runState = [string]$run.Count
    }
    # --- installed ---
    $inst = @($Installed | Where-Object { $null -ne $_ })
    $bad = New-Object System.Collections.ArrayList
    $entries = 0
    $roots = @($Roots | Where-Object { $null -ne $_ })
    if ($roots.Count -eq 0) { [void]$bad.Add('no Uninstall key was read') }
    foreach ($k in $roots) {
        $st = [string]$k.State
        if ($st -eq 'ok') {
            $entries += [int]$k.Count
            $u = @($k.Unreadable | Where-Object { [string]$_ })
            if ($u.Count -gt 0) { [void]$bad.Add(([string]$u.Count + ' entr(y/ies) under ' + [string]$k.Name + ' could not be read (' + (@($u | Select-Object -First 3 | ForEach-Object { ConvertTo-PrintableText ([string]$_) }) -join ', ') + $(if ($u.Count -gt 3) { ', ...' } else { '' }) + ')')) }
        } elseif ($st -eq 'nokey') {
            if ($k.Required) { [void]$bad.Add(([string]$k.Name + ' was not found, and it exists on every Windows')) }
        } else {
            [void]$bad.Add(([string]$k.Name + ' could not be read (' + $(if ([string]$k.Error) { ConvertTo-PrintableText ([string]$k.Error) } else { 'no result' }) + ')'))
        }
    }
    foreach ($x in $inst) {
        $ver = if ([string]$x.Version) { ' ' + (ConvertTo-PrintableText ([string]$x.Version)) } else { '' }
        $pub = if ([string]$x.Publisher) { ', publisher ' + (ConvertTo-PrintableText ([string]$x.Publisher)) } else { ', no publisher recorded' }
        [void]$out.Add(('[WARNING] Remote-access tool INSTALLED: ' + (ConvertTo-PrintableText ([string]$x.Display)) + $ver + $pub + ' (T1219)'))
    }
    if ($inst.Count -gt 0) { $r.InstHit = $true }
    if ($bad.Count -gt 0) {
        $r.Gap = $true
        [void]$out.Add(('[WARNING] Remote-access tool check (installed) NOT performed in full -- ' + ($bad.ToArray() -join '; ') + ', so an installed remote-access tool there would go unseen (T1219).'))
    } elseif ($inst.Count -eq 0) {
        [void]$out.Add(('[OK] No known remote-access tool installed (' + [string]$entries + ' installed-program entr(y/ies) examined, matched at word edges).'))
    }
    if ($r.RunHit -or $r.InstHit) { [void]$out.Add($gloss) }
    $instState = if ($bad.Count -gt 0 -and $inst.Count -gt 0) { ([string]$inst.Count + '+gap') } elseif ($bad.Count -gt 0) { 'gap' } else { [string]$inst.Count }
    $r.Lines = @($out.ToArray()); $r.State = ('run=' + $runState + ',inst=' + $instState)
    return $r
}

# Live. The tree Section 4 wrote: PID|PPID|ticks|session|Path|Name.
function Read-ProcessTree {
    param([string]$File)
    if (-not $File) { return @{ Error = 'no snapshot path was given'; Count = 0; Items = @() } }
    try {
        $lines = @(Get-Content -LiteralPath $File -ErrorAction Stop)
    } catch { return @{ Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Count = 0; Items = @() } }
    $items = New-Object System.Collections.ArrayList
    foreach ($l in $lines) {
        $f = ([string]$l).Split('|', 6)
        if ($f.Count -lt 6 -or -not $f[5]) { continue }
        [void]$items.Add(@{ Pid = $f[0]; Path = $f[4]; Name = $f[5] })
    }
    return @{ Error = ''; Count = $items.Count; Items = @($items.ToArray()) }
}
function Read-Signature {
    param([string]$File)
    if (-not $File) { return 'no file path to check a signature on' }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $File -ErrorAction Stop
        if ([string]$s.Status -eq 'Valid' -and $s.SignerCertificate) { return ('validly signed by ' + [string]$s.SignerCertificate.Subject) }
        return ('NOT validly signed (' + [string]$s.Status + ')')
    } catch { return ('signature not readable (' + $_.Exception.GetType().Name + ')') }
}
# Live. One Uninstall root: every entry's DisplayName, and what could not be
# read named, never dropped.
function Read-UninstallRoot {
    param([string]$KeyPath, [bool]$Required)
    $res = @{ Name = $KeyPath; State = 'ok'; Required = $Required; Error = ''; Count = 0; Unreadable = @(); Entries = @() }
    $k = $null
    try { $k = Get-Item -LiteralPath $KeyPath -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { $res.State = 'nokey'; return $res }
        $res.State = 'unreadable'; $res.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $res
    }
    $names = @()
    try { $names = @($k.GetSubKeyNames()) } catch { $res.State = 'unreadable'; $res.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $res }
    $bad = New-Object System.Collections.ArrayList
    $ents = New-Object System.Collections.ArrayList
    foreach ($n in $names) {
        try {
            $sk = $k.OpenSubKey($n)
            if ($null -eq $sk) { [void]$bad.Add($n); continue }
            $d = [string]$sk.GetValue('DisplayName', '')
            if ($d) { [void]$ents.Add(@{ Display = $d; Version = [string]$sk.GetValue('DisplayVersion', ''); Publisher = [string]$sk.GetValue('Publisher', '') }) }
            $sk.Close()
        } catch { [void]$bad.Add($n) }
    }
    $res.Count = $names.Count; $res.Unreadable = @($bad.ToArray()); $res.Entries = @($ents.ToArray())
    return $res
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    # --- names: whole process names, word edges in display names ---
    T 'AnyDesk.exe is AnyDesk' ((Get-RmmProductForProcess 'AnyDesk.exe') -eq 'AnyDesk') (Get-RmmProductForProcess 'AnyDesk.exe')
    T 'ScreenConnect.ClientService.exe is ScreenConnect (the product name alone never ran as a process)' ((Get-RmmProductForProcess 'ScreenConnect.ClientService.exe') -like 'ScreenConnect*') ''
    T 'SRService.exe is Splashtop, which no product-name search finds' ((Get-RmmProductForProcess 'SRService.exe') -eq 'Splashtop') ''
    T 'TeamViewer_Service.exe and tv_x64.exe are TeamViewer' (((Get-RmmProductForProcess 'TeamViewer_Service.exe') -eq 'TeamViewer') -and ((Get-RmmProductForProcess 'tv_x64.exe') -eq 'TeamViewer')) ''
    T 'LateralHelper.exe is NOT Atera (the old substring match said it was)' ((Get-RmmProductForProcess 'LateralHelper.exe') -eq '') (Get-RmmProductForProcess 'LateralHelper.exe')
    T 'a name that only CONTAINS a product name is not matched (MyAnyDeskNotes.exe, AnyDeskHelperTool.exe)' (((Get-RmmProductForProcess 'MyAnyDeskNotes.exe') -eq '') -and ((Get-RmmProductForProcess 'AnyDeskHelperTool.exe') -eq '')) ''
    T 'the portable and quick-support forms are found: AnyDesk (1).exe, TeamViewerQS.exe, rustdesk-1.3.2-x86_64.exe, SplashtopSOS.exe' (((Get-RmmProductForProcess 'AnyDesk (1).exe') -eq 'AnyDesk') -and ((Get-RmmProductForProcess 'TeamViewerQS_x64.exe') -eq 'TeamViewer') -and ((Get-RmmProductForProcess 'rustdesk-1.3.2-x86_64.exe') -eq 'RustDesk') -and ((Get-RmmProductForProcess 'SplashtopSOS.exe') -eq 'Splashtop')) ''
    T 'Kaseya VSA 10, LogMeIn Rescue, GoToAssist, Bomgar and Atera''s package names are found' (((Get-RmmProductForProcess 'Kaseya.AgentEndpoint.exe') -eq 'Kaseya') -and ((Get-RmmProductForProcess 'lmi_rescue_srv.exe') -like 'LogMeIn*') -and ((Get-RmmProductForProcess 'g2ax_comm_expert.exe') -like 'LogMeIn*') -and ((Get-RmmProductForProcess 'bomgar-pac.exe') -like 'BeyondTrust*') -and ((Get-RmmProductForProcess 'AgentPackageHeartbeat.exe') -eq 'Atera')) ''
    T 'a helper under an unlisted name is found by the product''s own install folder' ((Get-RmmProductForProcess -ProcessName 'gcapi.exe' -Path 'C:\Program Files (x86)\AnyDesk\gcapi.exe') -eq 'AnyDesk') ''
    T 'srtasks.exe (System Restore) is not Splashtop, and Hamachi''s folder is not LogMeIn remote control' (((Get-RmmProductForProcess -ProcessName 'srtasks.exe' -Path 'C:\Windows\System32\srtasks.exe') -eq '') -and ((Get-RmmProductForProcess -ProcessName 'hamachi-2.exe' -Path 'C:\Program Files (x86)\LogMeIn Hamachi\hamachi-2.exe') -eq '')) ''
    T 'svchost.exe, explorer.exe and an empty name are nothing' (((Get-RmmProductForProcess 'svchost.exe') -eq '') -and ((Get-RmmProductForProcess 'explorer.exe') -eq '') -and ((Get-RmmProductForProcess '') -eq '')) ''
    T 'the match ignores letter case' ((Get-RmmProductForProcess 'ANYDESK.EXE') -eq 'AnyDesk') ''
    T '"AnyDesk" and "TeamViewer 15" in the installed list are found' (((Get-RmmProductForDisplay 'AnyDesk') -eq 'AnyDesk') -and ((Get-RmmProductForDisplay 'TeamViewer 15') -eq 'TeamViewer')) ''
    T '"Collateral Manager" and "Lateral Tools" are NOT Atera (word edges, not substrings)' (((Get-RmmProductForDisplay 'Collateral Manager') -eq '') -and ((Get-RmmProductForDisplay 'Lateral Tools') -eq '')) ''
    T '"Atera Agent" is Atera' ((Get-RmmProductForDisplay 'Atera Agent') -eq 'Atera') ''
    T '"LogMeIn Hamachi" is LogMeIn''s VPN, not its remote-control product; "LogMeIn Rescue Technician Console" is' (((Get-RmmProductForDisplay 'LogMeIn Hamachi') -eq '') -and ((Get-RmmProductForDisplay 'LogMeIn Rescue Technician Console') -like 'LogMeIn*')) ''
    T '"BeyondTrust Privilege Management" is not a remote-access tool; "BeyondTrust Remote Support Jump Client" is' (((Get-RmmProductForDisplay 'BeyondTrust Privilege Management') -eq '') -and ((Get-RmmProductForDisplay 'BeyondTrust Remote Support Jump Client') -like 'BeyondTrust*')) ''

    # --- verdicts ---
    $pOk = @{ Error = ''; Count = 180 }
    $rootOk = @{ Name = 'HKLM:\...\Uninstall'; State = 'ok'; Required = $true; Error = ''; Count = 90; Unreadable = @() }
    $rootNo = @{ Name = 'HKCU:\...\Uninstall'; State = 'nokey'; Required = $false; Error = ''; Count = 0; Unreadable = @() }
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootOk, $rootNo) -Installed @(); $t = $v.Lines -join "`n"
    T 'nothing running, nothing installed: two [OK] lines that say how much was examined, nothing raised' ((-not ($v.RunHit -or $v.InstHit -or $v.Gap)) -and $v.State -eq 'run=0,inst=0' -and $t -match '(?m)^\[OK\] No known remote-access tool running \(180 process' -and $t -match '(?m)^\[OK\] No known remote-access tool installed \(90 installed-program') $t
    $runA = @{ Product = 'AnyDesk'; Name = 'AnyDesk.exe'; Pid = '4242'; Path = 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe'; Sig = 'validly signed by CN=AnyDesk Software GmbH' }
    $v = Get-RmmVerdict -Proc $pOk -Running @($runA) -Roots @($rootOk) -Installed @(); $t = $v.Lines -join "`n"
    T 'AnyDesk running: a WARNING that names the product, the file, the PID and the signer' ($v.RunHit -and (-not $v.InstHit) -and $v.State -eq 'run=1,inst=0' -and $t -match '(?m)^\[WARNING\] Remote-access tool RUNNING: AnyDesk -- AnyDesk\.exe \(PID 4242\), C:\\Program Files \(x86\)\\AnyDesk\\AnyDesk\.exe; validly signed by CN=AnyDesk Software GmbH \(T1219\)$') $t
    T 'a validly signed tool is still the finding: the signature is context, never an excuse' ($v.RunHit) ''
    T 'the explanation beside a finding is [INFO], so the WARNING lines equal the findings' (@($v.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1 -and $t -match '(?m)^\[INFO\] These are legitimate products') $t
    $instT = @{ Product = 'TeamViewer'; Display = 'TeamViewer'; Version = '15.50.5'; Publisher = 'TeamViewer' }
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootOk) -Installed @($instT); $t = $v.Lines -join "`n"
    T 'TeamViewer installed and not running: a WARNING of its own (the owner''s decision), with version and publisher' ($v.InstHit -and (-not $v.RunHit) -and $v.State -eq 'run=0,inst=1' -and $t -match '(?m)^\[WARNING\] Remote-access tool INSTALLED: TeamViewer 15\.50\.5, publisher TeamViewer \(T1219\)$') $t
    $v = Get-RmmVerdict -Proc $pOk -Running @($runA) -Roots @($rootOk) -Installed @($instT)
    T 'running AND installed: both raised, each under its own marker' ($v.RunHit -and $v.InstHit -and $v.State -eq 'run=1,inst=1') ($v.Lines -join ' | ')
    $v = Get-RmmVerdict -Proc @{ Error = 'ItemNotFoundException: Cannot find path dz_proc4_tree.tmp'; Count = 0 } -Running @() -Roots @($rootOk) -Installed @(); $t = $v.Lines -join "`n"
    T 'the process snapshot could not be read: a raised gap, never "[OK] No known remote-access tool running"' ($v.Gap -and (-not $v.RunHit) -and $v.State -eq 'run=gap,inst=0' -and $t -match '(?m)^\[WARNING\] Remote-access tool check \(running\) NOT performed -- ' -and $t -notmatch 'tool running \(') $t
    $v = Get-RmmVerdict -Proc @{ Error = ''; Count = 0 } -Running @() -Roots @($rootOk) -Installed @()
    T 'a snapshot with no processes in it is a gap, not a quiet machine' ($v.Gap -and $v.State -like 'run=gap,*') ($v.Lines -join ' | ')
    $rootBad = @{ Name = 'HKLM:\...\Uninstall'; State = 'unreadable'; Required = $true; Error = 'SecurityException: Requested registry access is not allowed.'; Count = 0; Unreadable = @() }
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootBad) -Installed @(); $t = $v.Lines -join "`n"
    T 'the Uninstall key could not be read: a raised gap, never "[OK] No known remote-access tool installed" (the old block printed [OK])' ($v.Gap -and $v.State -eq 'run=0,inst=gap' -and $t -match '(?m)^\[WARNING\] Remote-access tool check \(installed\) NOT performed in full -- ' -and $t -notmatch 'tool installed \(') $t
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @(@{ Name = 'HKLM:\...\Uninstall'; State = 'nokey'; Required = $true; Error = ''; Count = 0; Unreadable = @() }) -Installed @()
    T 'HKLM''s own Uninstall key not found (it exists on every Windows): a gap' ($v.Gap -and ($v.Lines -join ' ') -match 'exists on every Windows') ($v.Lines -join ' | ')
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootOk, $rootNo) -Installed @()
    T 'no per-user Uninstall key is an answer, not a gap' (-not $v.Gap) ($v.Lines -join ' | ')
    $rootPart = @{ Name = 'HKLM:\...\Uninstall'; State = 'ok'; Required = $true; Error = ''; Count = 90; Unreadable = @('{GUID-1}', 'Locked App') }
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootPart) -Installed @($instT); $t = $v.Lines -join "`n"
    T 'a finding AND entries that could not be read: both raised, and the unread entries are named' ($v.InstHit -and $v.Gap -and $v.State -eq 'run=0,inst=1+gap' -and $t -match '2 entr\(y/ies\) under .* could not be read \(\{GUID-1\}, Locked App\)') $t
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @() -Installed @()
    T 'no Uninstall key read at all is a gap, never an [OK]' ($v.Gap -and ($v.Lines -join ' ') -notmatch 'tool installed \(') ($v.Lines -join ' | ')
    $v = Get-RmmVerdict -Proc $pOk -Running @(@{ Product = 'AnyDesk'; Name = 'AnyDesk.exe'; Pid = '7'; Path = ''; Sig = '' }) -Roots @($rootOk) -Installed @()
    T 'a running tool whose path this token cannot read is still the finding, and says so' ($v.RunHit -and ($v.Lines -join ' ') -match 'path not readable from this token') ($v.Lines -join ' | ')
    $v = Get-RmmVerdict -Proc $pOk -Running @() -Roots @($rootOk) -Installed @(@{ Product = 'AnyDesk'; Display = ('AnyDesk' + [char]10 + '[OK] fine'); Version = ''; Publisher = '' })
    T 'a line break inside a DisplayName cannot forge an [OK] line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails rmm_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] rmm_check self-test: a remote-access tool running or installed is a WARNING that names the file and its signer; process names match from their start or by the product''s install folder, program names at word edges, never as substrings; and a snapshot or Uninstall key that could not be read is a raised gap, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
$v = $null
try {
    $tree = Read-ProcessTree -File $TreePath
    $running = @()
    foreach ($p in @($tree.Items)) {
        $prod = Get-RmmProductForProcess -ProcessName ([string]$p.Name) -Path ([string]$p.Path)
        if ($prod) { $running += @{ Product = $prod; Name = [string]$p.Name; Pid = [string]$p.Pid; Path = [string]$p.Path; Sig = (Read-Signature ([string]$p.Path)) } }
    }
    $rootSpec = @()
    if ($UninstallRoots -and $UninstallRoots.Count -gt 0) {
        $first = $true
        foreach ($u in $UninstallRoots) { $rootSpec += @{ Path = $u; Required = $first }; $first = $false }
    } else {
        $rootSpec = @(
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Required = $true },
            @{ Path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Required = $false },
            @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Required = $false }
        )
    }
    $roots = @(); $installed = @()
    foreach ($rs in $rootSpec) {
        $rr = Read-UninstallRoot -KeyPath $rs.Path -Required ([bool]$rs.Required)
        $roots += $rr
        foreach ($e in @($rr.Entries)) {
            $prod = Get-RmmProductForDisplay ([string]$e.Display)
            if ($prod) { $installed += @{ Product = $prod; Display = [string]$e.Display; Version = [string]$e.Version; Publisher = [string]$e.Publisher } }
        }
    }
    $v = Get-RmmVerdict -Proc $tree -Running $running -Roots $roots -Installed $installed
} catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^run=(\d+|gap),inst=(\d+|gap|\d+\+gap)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'rmm_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.RunHit) { Write-Marker -Name 'rmm_run_hit' -Sev 'hit' }
if ($v.InstHit) { Write-Marker -Name 'rmm_inst_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'rmm_gap' -Sev 'WARNING' }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('rmm_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
