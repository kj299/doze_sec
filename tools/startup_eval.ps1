# startup_eval.ps1 -- evaluate Startup-folder contents (T1547.001) and
# AppCert DLLs (T1546.009). Invoked from Section 5 of doze_sec.bat /
# doze_sec_noAdmin.bat.
#
# WHY: Section 5 raw-dumped both the per-user and common Startup folders with
# `dir` and never evaluated them -- a dropped .lnk/.exe/.bat/.vbs scrolled past
# with no verdict. That is the SAME dump-without-verdict gap class as the
# Run-key/IFEO/Guest gaps (issue #138); this closes it for the other classic
# T1547.001 autorun location. AppCert_DLLs is added alongside because it is
# the uncovered sibling of AppInit_DLLs (already evaluated in Section 5): every
# DLL listed loads into any process that calls CreateProcess* -- broader and
# stealthier than AppInit, and unlike AppInit it is not disabled by Secure Boot.
#
# STARTUP FOLDERS (T1547.001)
#   Enumerated: the invoking user's Startup folder and the common (all-users)
#   Startup folder, resolved via Environment.GetFolderPath so localized Windows
#   installs work (a hard-coded "Start Menu\Programs\Startup" path is wrong on
#   non-English Windows -- the same localization trap that made the old netsh
#   firewall scrape misreport).
#
#   Severity is tiered to keep false positives near zero. Legitimate installers
#   DO drop items here (OneDrive, Teams, vendor updaters), so presence alone is
#   never a finding:
#     CRITICAL -- item (or a shortcut's target) lives under a staging path
#                 (\Temp\, \Downloads\, \Public\, \ProgramData\update), or a
#                 shortcut's target/arguments carry strong backdoor content
#                 (encoded PowerShell, LOLBin download-and-exec).
#     WARNING  -- script/scriptlet file types that have no business auto-running
#                 (.vbs .js .jse .vbe .wsf .wsh .hta .ps1 .bat .cmd .scr .pif),
#                 or an .exe/.dll that is unsigned or has an invalid signature.
#     OK       -- validly-signed executables and ordinary shortcuts to them.
#   .lnk files are followed to their target via the Shell COM API (read-only)
#   so a shortcut pointing at malware in \Temp\ is judged on its TARGET, which
#   is how this technique is actually used.
#
# APPCERT DLLS (T1546.009)
#   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls -- empty
#   on a stock Windows install. Any value is noteworthy; the listed DLL is put
#   through the same Authenticode gate used for Credential Provider DLLs, so a
#   legitimately-signed enterprise agent degrades to WARNING rather than
#   crying CRITICAL.
#
# MARKERS: writes the severity word (CRITICAL/WARNING) to
# $env:TEMP\dz_startup_folder.txt and $env:TEMP\dz_appcert.txt; the caller
# reads each and raises via :dz_finding. No marker is written when clean.
#
# Windows PowerShell 5.1 compatible. Read-only (filesystem + registry reads,
# plus marker writes under TEMP). Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP
)

$ErrorActionPreference = 'Continue'

# Timestamps on a persistence finding: WHEN did this appear? For someone working
# out whether an implant predates a relationship, a job, or a break-in, that is
# the question the finding itself never answered. Both halves are optional --
# whichever is unavailable is simply omitted.
#
# TWO LIMITS, STATED IN THE REPORT TOO, because a timestamp presented without
# them is worse than none:
#   * Registry last-write is per KEY, not per value. Changing ANY value in a Run
#     key updates the whole key, so this is an upper bound on when THIS entry
#     appeared, not a precise date for it.
#   * File times are trivially forged (timestomping, T1070.006). An attacker who
#     cares sets them to whatever they like.
function Get-WhenLine {
    param([string]$KeyPath = '', [string]$FilePath = '')
    $parts = @()
    if ($KeyPath) {
        try {
            $k = Get-Item -LiteralPath $KeyPath -EA Stop
            $lw = $k.LastWriteTime
            if ($null -ne $lw) { $parts += ("registry key last modified {0}" -f $lw.ToString('yyyy-MM-dd HH:mm:ss')) }
        } catch {}
    }
    if ($FilePath) {
        try {
            $f = Get-Item -LiteralPath $FilePath -EA Stop
            $parts += ("file written {0}" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
            # Creation AFTER last-write is the classic timestomp tell, so show
            # creation whenever the two disagree in either direction.
            if ($f.CreationTime -and $f.CreationTime -ne $f.LastWriteTime) {
                $parts += ("created {0}" -f $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))
            }
        } catch {}
    }
    if ($parts.Count -eq 0) { return $null }
    return ("  when: {0}" -f ($parts -join '  |  '))
}

# Emitted once, immediately before the first timestamped finding in this tool's
# output, so the numbers are never read as more precise than they are.
$script:whenCaveatShown = $false
function Write-WhenCaveat {
    if ($script:whenCaveatShown) { return }
    $script:whenCaveatShown = $true
    '  note: registry times are per KEY (any value change updates them) and file times can be forged (timestomping, T1070.006) -- treat them as leads, not proof.'
}

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$psNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

$trusted   = '\bMicrosoft\b|\bWindows\b'
$badPathRx = '\\Temp\\|\\Downloads\\|\\Public\\|\\ProgramData\\update'
# Strong command-content indicators, kept in sync with persistence_eval.ps1.
$strongContent = @(
    '-enc(odedcommand)?\b',
    '-e\s+[A-Za-z0-9+/=]{24,}',
    'frombase64string',
    'downloadstring', 'downloadfile',
    '(invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b)[^\r\n]*https?:',
    '(iex|invoke-expression)\s*[\(\$]', '\|\s*(iex|invoke-expression)\b',
    'mshta\s+https?:', 'mshta\s+javascript',
    'certutil[^\r\n]*-urlcache', 'certutil[^\r\n]*-decode',
    'bitsadmin[^\r\n]*/transfer',
    'regsvr32[^\r\n]*/i:http', 'regsvr32[^\r\n]*scrobj', 'rundll32[^\r\n]*javascript'
)
# Script/scriptlet types that should never be auto-starting from a Startup
# folder. .scr/.pif are legacy executable types used to disguise binaries.
$scriptExt = @('.vbs', '.js', '.jse', '.vbe', '.wsf', '.wsh', '.hta',
               '.ps1', '.bat', '.cmd', '.scr', '.pif')

function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}

# Authenticode gate shared by both checks (same tiering as the Credential
# Provider DLL gate in logon_persistence.ps1).
function Get-FileVerdict {
    param([string]$Path)
    if (-not $Path) { return @{ Sev = 'CRITICAL'; Why = 'no target path' } }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if ($p -match $badPathRx) { return @{ Sev = 'CRITICAL'; Why = "staging path: $p" } }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ Sev = 'CRITICAL'; Why = "target not found: $p" } }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return @{ Sev = 'WARNING'; Why = "unsigned/invalid signature: $p" } }
    if ($sig.SignerCertificate.Subject -notmatch $trusted) { return @{ Sev = 'OK'; Why = "signed by $(($sig.SignerCertificate.Subject -split ',')[0])" } }
    return @{ Sev = 'OK'; Why = "Microsoft-signed: $p" }
}

# Resolve a .lnk to its target + arguments without executing it. WScript.Shell
# is read-only here; if COM is unavailable the caller falls back to judging the
# shortcut file itself rather than reporting a false clean.
function Resolve-Shortcut {
    param([string]$LnkPath)
    $sh = $null
    try {
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($LnkPath)
        return @{ Ok = $true; Target = [string]$lnk.TargetPath; Args = [string]$lnk.Arguments }
    } catch {
        return @{ Ok = $false; Target = ''; Args = '' }
    } finally {
        if ($sh) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
    }
}

# ---- 1. Startup folders (T1547.001) --------------------------------------
'--- [T1547.001] Startup folder contents (evaluated) ---'
$startupSev = 'OK'
$folders = @()
foreach ($sf in @('Startup', 'CommonStartup')) {
    $path = $null
    try { $path = [Environment]::GetFolderPath($sf) } catch {}
    if ($path) { $folders += $path }
}
if (-not $folders.Count) {
    '[SKIPPED] Could not resolve the Startup folder paths -- check NOT performed.'
    $startupSev = 'WARNING'
} else {
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) {
            "[OK] Startup folder not present: $folder"
            continue
        }
        $items = $null
        $enumOk = $true
        try { $items = @(Get-ChildItem -LiteralPath $folder -File -Force -EA Stop) } catch { $enumOk = $false }
        if (-not $enumOk) {
            "[SKIPPED] Could not enumerate $folder -- check NOT performed."
            $startupSev = Get-MaxSev $startupSev 'WARNING'
            continue
        }
        # desktop.ini is folder metadata, not an autorun.
        $items = @($items | Where-Object { $_.Name -ne 'desktop.ini' })
        if (-not $items.Count) {
            "[OK] Startup folder empty: $folder"
            continue
        }
        foreach ($it in $items) {
            $ext = $it.Extension.ToLowerInvariant()
            $sev = 'OK'
            $why = ''
            if ($ext -eq '.lnk') {
                $r = Resolve-Shortcut -LnkPath $it.FullName
                if (-not $r.Ok) {
                    $sev = 'WARNING'; $why = 'shortcut target could not be resolved -- inspect manually'
                } else {
                    $combined = ($r.Target + ' ' + $r.Args)
                    foreach ($s in $strongContent) {
                        if ($combined -match $s) { $sev = 'CRITICAL'; $why = "shortcut command content ($s): $combined"; break }
                    }
                    if ($sev -eq 'OK') {
                        $tExt = ''
                        try { $tExt = [IO.Path]::GetExtension($r.Target).ToLowerInvariant() } catch {}
                        if ($scriptExt -contains $tExt) {
                            $sev = 'WARNING'; $why = "shortcut to an auto-running script: $($r.Target)"
                        } else {
                            $v = Get-FileVerdict -Path $r.Target
                            $sev = $v.Sev; $why = "shortcut -> $($v.Why)"
                        }
                    }
                }
            } elseif ($scriptExt -contains $ext) {
                $sev = 'WARNING'; $why = "auto-running script file ($ext)"
                if ($it.FullName -match $badPathRx) { $sev = 'CRITICAL'; $why = "auto-running script under a staging path" }
            } else {
                $v = Get-FileVerdict -Path $it.FullName
                $sev = $v.Sev; $why = $v.Why
            }

            if ($sev -eq 'OK') {
                "[OK] Startup item: $($it.Name)  ($why)"
            } else {
                "[$sev] Startup item '$($it.Name)' in $folder -- $why"
                Write-WhenCaveat
                $w = Get-WhenLine -FilePath $it.FullName
                if ($w) { $w }
                $startupSev = Get-MaxSev $startupSev $sev
            }
        }
    }
}
if ($startupSev -eq 'OK') { '[OK] No suspicious Startup-folder autoruns.' }
Write-Marker -Name 'startup_folder' -Sev $startupSev

# ---- 2. AppCert DLLs (T1546.009) -----------------------------------------
''
'--- [T1546.009] AppCert DLLs (load into every CreateProcess caller) ---'
$appcertSev = 'OK'
$acKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
$acOk = $true
$acProps = $null
try {
    if (Test-Path $acKey) { $acProps = Get-ItemProperty -Path $acKey -EA Stop }
} catch { $acOk = $false }
if (-not $acOk) {
    '[SKIPPED] AppCertDlls key could not be read -- check NOT performed.'
    $appcertSev = 'WARNING'
} elseif (-not $acProps) {
    '[OK] AppCertDlls not present or empty (stock Windows).'
} else {
    $any = $false
    foreach ($p in $acProps.PSObject.Properties) {
        # Exact-name skip, not a '^PS' prefix match -- see persistence_eval.ps1.
        # A prefix match also hid any real value named e.g. "PSHelper".
        if ($psNoteProps -contains $p.Name) { continue }
        $val = [string]$p.Value
        if (-not $val) { continue }
        $any = $true
        $v = Get-FileVerdict -Path $val
        # Any AppCert DLL is noteworthy: a validly-signed one is still a
        # process-wide injection point, so OK degrades to WARNING here.
        $sev = if ($v.Sev -eq 'OK') { 'WARNING' } else { $v.Sev }
        "[$sev] AppCert DLL '$($p.Name)' => $val -- $($v.Why)"
        Write-WhenCaveat
        $w = Get-WhenLine -KeyPath $acKey -FilePath $val
        if ($w) { $w }
        $appcertSev = Get-MaxSev $appcertSev $sev
    }
    if (-not $any) { '[OK] AppCertDlls not present or empty (stock Windows).' }
}
Write-Marker -Name 'appcert' -Sev $appcertSev
