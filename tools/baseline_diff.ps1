# baseline_diff.ps1 -- baseline capture and differential analysis.
#
# WHY THIS IS THE MOST IMPORTANT DETECTION IN THE TOOL: every other check asks
# "does this match something we already know is bad?" That question cannot be
# answered for a bespoke implant built for one target -- which is exactly what a
# capable or state-level actor deploys. This check asks a different question:
# "is anything DIFFERENT from how this machine used to be?" A new kernel driver,
# a new service, a new admin, a new listening port, or a new persistence value
# that was not here last week is suspicious regardless of whether anyone has
# ever written a signature for it. Change detection is how you catch tooling
# nobody has catalogued.
#
# HONEST LIMITATION -- STATED IN THE OUTPUT, NOT JUST HERE: a baseline captured
# on an ALREADY-COMPROMISED machine records the implant as "normal", and it will
# never be reported again. This is a change detector from the moment of capture
# forward, NOT a clean-room reference. Capture it as early as possible in a
# device's life, ideally right after a clean install. The report says so plainly
# so nobody mistakes a quiet diff for proof of health.
#
# MODES
#   -Mode Save -Path <file>   Capture the current state to a snapshot file.
#   -Mode Diff -Path <file>   Compare current state to the snapshot and report
#                             NEW / CHANGED / REMOVED. No baseline yet => an
#                             [INFO] line telling the user how to create one
#                             (never a failure, never a fake clean).
#
# SNAPSHOT FORMAT: one record per line, `CATEGORY|KEY|DETAIL`, sorted, so the
# file is deterministic and diffable by eye or by tool. KEY is the stable
# identity (what makes two records "the same thing"); DETAIL is what may change.
# Privacy-conscious: paths, names, hashes and signer CNs only -- never file
# contents, never user documents, no network or telemetry of any kind.
#
# CATEGORIES: DRV (loaded kernel drivers, hashed -- bounded and highest value),
# SVC (services), TASK (scheduled tasks), RUN (autorun/persistence registry
# values), PORT (listening ports), ADMIN (local administrators), CERT (root CA
# certificates -- a new root CA is how TLS interception is installed).
#
# FALSE-POSITIVE CONTROL: Windows Update legitimately adds drivers and services,
# so a NEW item that is validly MICROSOFT-signed is reported [INFO] rather than
# raised. NEW unsigned/non-Microsoft binaries, and any NEW admin, listening
# port, persistence value or root CA, are WARNING -- those are not routine.
# REMOVED items are reported [INFO]: uninstalls are normal, and the goal here is
# to inform, not to bury the user in noise. CHANGED (same identity, different
# binary hash or signer) is WARNING -- that is the shape of a replaced binary.
#
# MARKER: writes the severity word to $env:TEMP\dz_baseline.txt; the caller
# raises via :dz_finding. No marker when nothing noteworthy changed.
#
# Windows PowerShell 5.1 compatible. Read-only apart from writing the snapshot
# and the marker. Executed by the helpers-ps51 CI job (save/diff round-trip).

[CmdletBinding()]
param(
    [ValidateSet('Save', 'Diff')][string]$Mode = 'Diff',
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxReport = 40
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}
# Field separators and newlines must never appear inside a record field, or one
# record stops being one parseable line (same rule as the findings ledger).
function CleanField {
    param([string]$s)
    if ($null -eq $s) { return '' }
    return (($s -replace '[|\r\n]', ' ').Trim())
}

# Is this binary validly signed by Microsoft? Used to keep Windows Update noise
# out of the NEW-item findings without silencing third-party additions.
function Test-MsSigned {
    param([string]$FilePath)
    if (-not $FilePath) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($FilePath.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
    if ($p -match '^"') { $p = $p.Trim('"') }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $false }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return $false }
    return ($sig.SignerCertificate.Subject -match '\bMicrosoft\b|\bWindows\b')
}

# Pull the first plausible executable path out of a service ImagePath /
# scheduled-task action so signature checks have something to work with.
function Get-BinPath {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $s = $Raw.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { return $s.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($s, '^[^\s]+\.(exe|sys|dll)', 'IgnoreCase')
    if ($m.Success) { return $m.Value }
    return $s
}

# ---- Collect the current state ------------------------------------------
function Get-Snapshot {
    $recs = New-Object System.Collections.Generic.List[string]
    $sysroot = $env:SystemRoot

    # DRV -- loaded kernel drivers, hashed. Bounded set, highest value: a new or
    # swapped kernel driver is the single most consequential change on a host.
    try {
        foreach ($d in (Get-CimInstance Win32_SystemDriver -EA Stop)) {
            $pn = [string]$d.PathName
            if (-not $pn) { continue }
            $pn = $pn -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $sysroot
            $pn = [Environment]::ExpandEnvironmentVariables($pn.Trim('"'))
            $h = ''
            try { if (Test-Path -LiteralPath $pn -PathType Leaf) { $h = (Get-FileHash -LiteralPath $pn -Algorithm SHA256 -EA Stop).Hash } } catch {}
            $recs.Add(('DRV|{0}|{1} sha256={2}' -f (CleanField $d.Name), (CleanField $pn), $h))
        }
    } catch {}

    # SVC -- services by name; DETAIL carries the image path and start mode, so a
    # service repointed at a new binary shows up as CHANGED.
    try {
        foreach ($s in (Get-CimInstance Win32_Service -EA Stop)) {
            $recs.Add(('SVC|{0}|{1} start={2}' -f (CleanField $s.Name), (CleanField $s.PathName), (CleanField $s.StartMode)))
        }
    } catch {}

    # TASK -- scheduled tasks by full path; DETAIL carries the action.
    try {
        foreach ($t in (Get-ScheduledTask -EA Stop)) {
            $act = ''
            try { $act = (($t.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -join ' ; ') } catch {}
            $recs.Add(('TASK|{0}{1}|{2}' -f (CleanField $t.TaskPath), (CleanField $t.TaskName), (CleanField $act)))
        }
    } catch {}

    # RUN -- autorun / persistence registry values. The classic locations plus
    # the subsystem load points audited elsewhere in Section 5.
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',
        'HKLM:\SOFTWARE\Microsoft\Netsh'
    )
    foreach ($k in $runKeys) {
        try {
            if (-not (Test-Path $k)) { continue }
            $props = Get-ItemProperty -Path $k -EA Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                $recs.Add(('RUN|{0}\{1}|{2}' -f (CleanField $k), (CleanField $p.Name), (CleanField ([string]$p.Value))))
            }
        } catch {}
    }

    # PORT -- listening sockets. A new listener is how an implant takes calls.
    try {
        foreach ($c in (Get-NetTCPConnection -State Listen -EA Stop)) {
            $pname = ''
            try { $pname = (Get-Process -Id $c.OwningProcess -EA Stop).ProcessName } catch {}
            $recs.Add(('PORT|tcp/{0}|{1}' -f (CleanField ([string]$c.LocalPort)), (CleanField $pname)))
        }
    } catch {
        # Get-NetTCPConnection is absent on very old builds -- fall back to netstat
        # rather than silently recording no listeners (a false clean).
        try {
            foreach ($line in (& netstat -ano 2>$null)) {
                if ($line -notmatch '^\s*TCP\s') { continue }
                if ($line -notmatch 'LISTENING') { continue }
                $f = ($line -split '\s+') | Where-Object { $_ }
                if ($f.Count -lt 5) { continue }
                $lp = ($f[1] -split ':')[-1]
                $recs.Add(('PORT|tcp/{0}|pid={1}' -f (CleanField $lp), (CleanField $f[4])))
            }
        } catch {}
    }

    # ADMIN -- local Administrators membership. A new admin is a takeover.
    try {
        foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -EA Stop)) {
            $recs.Add(('ADMIN|{0}|{1}' -f (CleanField ([string]$m.Name)), (CleanField ([string]$m.PrincipalSource))))
        }
    } catch {
        try {
            $out = & net localgroup Administrators 2>$null
            $on = $false
            foreach ($line in $out) {
                if ($line -match '^-+$') { $on = $true; continue }
                if ($line -match '^The command completed') { $on = $false; continue }
                if ($on -and $line.Trim()) { $recs.Add(('ADMIN|{0}|net' -f (CleanField $line))) }
            }
        } catch {}
    }

    # CERT -- machine root CAs. A new root CA is how TLS interception is planted.
    try {
        foreach ($c in (Get-ChildItem Cert:\LocalMachine\Root -EA Stop)) {
            $recs.Add(('CERT|{0}|{1}' -f (CleanField $c.Thumbprint), (CleanField $c.Subject)))
        }
    } catch {}

    return ($recs | Sort-Object -Unique)
}

$snapshot = Get-Snapshot

if ($Mode -eq 'Save') {
    $header = @(
        '# doze_sec baseline snapshot -- CATEGORY|KEY|DETAIL, sorted.',
        '# Captured: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        '# NOTE: a baseline taken on an already-compromised machine records the',
        '# implant as normal. This is a change detector from now forward, not a',
        '# clean-room reference. Capture as early in the device life as possible.'
    )
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -LiteralPath $Path -Value ($header + $snapshot) -Encoding ASCII -EA Stop
        '--- Baseline Snapshot (saved) ---'
        "[OK] Baseline saved: $Path"
        "[OK] $($snapshot.Count) state record(s) captured (drivers, services, tasks, autoruns, ports, admins, root CAs)."
        '[INFO] A baseline captured on an already-compromised machine records the implant as normal.'
        '[INFO] It detects CHANGE from this moment forward -- it is not proof the current state is clean.'
    } catch {
        "[SKIPPED] Could not write baseline to ${Path}: $($_.Exception.Message)"
    }
    return
}

# ---- Diff mode -----------------------------------------------------------
'--- [BASELINE] Differential analysis vs saved baseline ---'
if (-not (Test-Path -LiteralPath $Path)) {
    "[INFO] No baseline found at $Path -- differential analysis not performed."
    '[INFO] Create one with:  doze_sec.bat -baseline save'
    '[INFO] Change detection is the strongest signal this tool has against a'
    '[INFO] targeted implant that matches no known signature. Capturing a'
    '[INFO] baseline early -- ideally on a freshly installed device -- is the'
    '[INFO] single most useful thing you can do to make future runs meaningful.'
    Write-Marker -Name 'baseline' -Sev 'OK'
    return
}

$old = @{}
try {
    foreach ($ln in (Get-Content -LiteralPath $Path -EA Stop)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Length -lt 2) { continue }
        $key = $f[0] + '|' + $f[1]
        $detail = ''
        if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
        $old[$key] = $detail
    }
} catch {
    "[SKIPPED] Baseline unreadable: $($_.Exception.Message)"
    Write-Marker -Name 'baseline' -Sev 'WARNING'
    return
}

$new = @{}
foreach ($ln in $snapshot) {
    $f = $ln.Split('|')
    if ($f.Length -lt 2) { continue }
    $key = $f[0] + '|' + $f[1]
    $detail = ''
    if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
    $new[$key] = $detail
}

# NEW items that are validly Microsoft-signed are almost always Windows Update
# doing its job -- reported for the record, but not raised.
$catLabel = @{
    'DRV' = 'kernel driver'; 'SVC' = 'service'; 'TASK' = 'scheduled task'
    'RUN' = 'autorun/persistence value'; 'PORT' = 'listening port'
    'ADMIN' = 'local administrator'; 'CERT' = 'root CA certificate'
}
$sev = 'OK'
$added = @(); $changed = @(); $removed = @()

foreach ($k in $new.Keys) {
    if ($old.ContainsKey($k)) {
        if ($old[$k] -ne $new[$k]) { $changed += $k }
    } else {
        $added += $k
    }
}
foreach ($k in $old.Keys) { if (-not $new.ContainsKey($k)) { $removed += $k } }

$addShown = 0
foreach ($k in ($added | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = $catLabel[$cat]
    if (-not $lbl) { $lbl = $cat }
    $detail = $new[$k]
    # Signature-gate the binary-backed categories to keep update noise down.
    $msSigned = $false
    if ($cat -eq 'DRV' -or $cat -eq 'SVC' -or $cat -eq 'TASK') {
        $bin = Get-BinPath ($detail -replace ' sha256=[0-9A-Fa-f]*$', '' -replace ' start=\w+$', '')
        $msSigned = Test-MsSigned $bin
    }
    $itemSev = 'WARNING'
    if ($msSigned) { $itemSev = 'INFO' }
    $addShown++
    if ($addShown -le $MaxReport) {
        if ($itemSev -eq 'INFO') {
            "[INFO] NEW $lbl since baseline (Microsoft-signed, likely a Windows update): $id"
        } else {
            "[WARNING] NEW $lbl since baseline: $id  =>  $detail"
        }
    }
    if ($itemSev -eq 'WARNING') { $sev = Get-MaxSev $sev 'WARNING' }
}
if ($addShown -gt $MaxReport) { "[INFO] ...and $($addShown - $MaxReport) more new item(s) not listed (report cap $MaxReport)." }

$chShown = 0
foreach ($k in ($changed | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = $catLabel[$cat]
    if (-not $lbl) { $lbl = $cat }
    $chShown++
    if ($chShown -le $MaxReport) {
        "[WARNING] CHANGED $lbl since baseline: $id"
        "          was: $($old[$k])"
        "          now: $($new[$k])"
    }
    $sev = Get-MaxSev $sev 'WARNING'
}
if ($chShown -gt $MaxReport) { "[INFO] ...and $($chShown - $MaxReport) more changed item(s) not listed (report cap $MaxReport)." }

$rmShown = 0
foreach ($k in ($removed | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = $catLabel[$cat]
    if (-not $lbl) { $lbl = $cat }
    $rmShown++
    # Removals are reported but not raised: uninstalls and update churn are
    # normal, and burying a real NEW finding under removal noise helps nobody.
    if ($rmShown -le $MaxReport) { "[INFO] REMOVED $lbl since baseline: $id" }
}
if ($rmShown -gt $MaxReport) { "[INFO] ...and $($rmShown - $MaxReport) more removed item(s) not listed (report cap $MaxReport)." }

if ($added.Count -eq 0 -and $changed.Count -eq 0 -and $removed.Count -eq 0) {
    "[OK] No change from the saved baseline across $($new.Count) tracked state record(s)."
} else {
    "[INFO] Baseline diff summary: $($added.Count) new, $($changed.Count) changed, $($removed.Count) removed (of $($new.Count) tracked records)."
}
'[INFO] A quiet diff means nothing changed since the baseline was taken -- not that the baseline itself was clean.'

Write-Marker -Name 'baseline' -Sev $sev
