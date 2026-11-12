# sshd_check.ps1 -- is the OpenSSH Server running (T1021.004)? An attacker who
# adds a key to administrators_authorized_keys has a remote administrator
# shell that survives a password change.
#
# The check was an inline block:
#   $ssh = Get-Service sshd -EA SilentlyContinue
#   if ($ssh -and $ssh.Status -eq 'Running') {...} elseif ($ssh) {...}
#   else { '[OK] OpenSSH Server not installed.' }
# A service manager that did not answer left $ssh empty and printed "not
# installed" -- the WinRM defect, in a second service. Section 10's raw dump
# had the same hole in cmd: any failure of "sc query sshd" printed
# "[OK] OpenSSH Server (sshd) not installed."
#
# THE RULE (pure, in Get-SshdVerdict, pinned by -SelfTest; the winrm_check
# shape):
#   * Get-Service answered: Running (or about to be) is the WARNING the bats
#     always printed; Stopped is [OK] installed but not running;
#   * Get-Service failed: the service manager is asked directly (sc.exe
#     query, EXIT CODE only -- its text is localized). 1060 is its own "does
#     not exist" and the only way to read "[OK] not installed"; 5 on a
#     standard-user token is [DEFERRED - ADMIN REQUIRED]; anything else is a
#     raised gap;
#   * the authorized-keys file is context: how many keys, or that it could
#     not be read. It never decides.
# Markers: dz_sshd_hit / dz_sshd_gap / dz_sshd_deferred. State:
# dz_sshd_state.txt  sshd=<running|stopped|absent|gap|deferred>.
#
# Usage:
#   powershell -File tools\sshd_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\sshd_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes these: a service name that does not exist drives the
    # sc.exe path through the real readers, and a scratch keys file.
    [string]$ServiceName = 'sshd',
    [string]$KeysFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_sshd_state.txt' }

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
    # An error message goes into the report as text: no control characters.
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

# PURE. $Svc: @{ Status; StartType; Error } (Status '' when Get-Service
# failed). $Sc: $null (not asked) or @{ Code; Error }. $Keys: $null or
# @{ Exists; Count; Error }. Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-SshdVerdict {
    param($Svc, $Sc = $null, $Keys = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $status = [string]$Svc.Status
    if ($status) {
        $st = if ([string]$Svc.StartType) { ', startup type ' + (ConvertTo-PrintableText ([string]$Svc.StartType)) } else { '' }
        if (@('Running', 'StartPending', 'ContinuePending') -contains $status) {
            [void]$out.Add('[WARNING] OpenSSH Server (sshd) is RUNNING')
            [void]$out.Add(('[INFO] Read by Get-Service: status ' + (ConvertTo-PrintableText $status) + $st + '.'))
            if ($null -ne $Keys) {
                if ([string]$Keys.Error) { [void]$out.Add(('[INFO] administrators_authorized_keys could not be read (' + (ConvertTo-PrintableText ([string]$Keys.Error)) + ') -- the keys that grant an administrator shell were NOT counted.')) }
                elseif ($Keys.Exists) { [void]$out.Add(('[INFO] administrators_authorized_keys has ' + [string]$Keys.Count + ' key(s) - verify each is legitimate')) }
                else { [void]$out.Add('[INFO] No administrators_authorized_keys file: no key grants an administrator shell from that file.') }
            }
            return @{ Lines = @($out.ToArray()); Hit = $true; Gap = $false; Deferred = 0; State = 'sshd=running' }
        }
        if ($status -eq 'Stopped') {
            [void]$out.Add('[OK] OpenSSH Server installed but not running.')
            [void]$out.Add(('[INFO] Read by Get-Service: status Stopped' + $st + '.'))
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'sshd=stopped' }
        }
        [void]$out.Add(('[WARNING] OpenSSH Server check NOT performed -- the sshd service is in the transitional state ' + (ConvertTo-PrintableText $status) + $st + ', neither running nor stopped; re-run the audit to grade it (T1021.004).'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'sshd=gap' }
    }
    $svcErr = ConvertTo-PrintableText ([string]$Svc.Error)
    $code = if ($null -ne $Sc) { [int]$Sc.Code } else { -1 }
    if ($code -eq 1060) {
        [void]$out.Add('[OK] OpenSSH Server not installed.')
        [void]$out.Add('[INFO] The service manager reports that the sshd service does not exist (sc.exe query exit 1060).')
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'sshd=absent' }
    }
    $scSaid = if ($null -eq $Sc) { 'not asked' } elseif ($code -lt 0) { ('could not be run (' + (ConvertTo-PrintableText ([string]$Sc.Error)) + ')') } else { ('exit ' + $code) }
    $why = ('Get-Service: ' + $(if ($svcErr) { $svcErr } else { 'no answer' }) + '; sc.exe query: ' + $scSaid)
    if ($code -eq 5 -and -not $IsElevated) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] OpenSSH Server check: a standard-user token cannot query the sshd service (' + $why + ') -- re-run as administrator to check it.'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 1; State = 'sshd=deferred' }
    }
    [void]$out.Add(('[WARNING] OpenSSH Server check NOT performed -- the sshd service could not be queried (' + $why + '), so a running SSH server would go unseen (T1021.004).'))
    return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'sshd=gap' }
}

function Read-Service {
    try {
        $s = Get-Service -Name $ServiceName -ErrorAction Stop
        $t = ''
        try { $t = [string]$s.StartType } catch {}
        return @{ Status = [string]$s.Status; StartType = $t; Error = '' }
    } catch { return @{ Status = ''; StartType = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}
function Read-Sc {
    try {
        $exe = Join-Path $env:SystemRoot 'System32\sc.exe'
        $null = & $exe query $ServiceName 2>&1
        return @{ Code = [int]$LASTEXITCODE; Error = '' }
    } catch { return @{ Code = -1; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}
function Read-Keys {
    $f = $KeysFile; if (-not $f) { $f = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys' }
    try {
        $dir = Split-Path -Parent $f
        # The folder's own listing says whether the file is there.
        if (-not [IO.Directory]::Exists($dir) -or @([IO.Directory]::GetFiles($dir, (Split-Path -Leaf $f))).Count -eq 0) { return @{ Exists = $false; Count = 0; Error = '' } }
        $n = @(Get-Content -LiteralPath $f -ErrorAction Stop | Where-Object { ([string]$_).Trim() -and ([string]$_).Trim() -notmatch '^#' }).Count
        return @{ Exists = $true; Count = $n; Error = '' }
    } catch { return @{ Exists = $true; Count = 0; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $nf = @{ Status = ''; StartType = ''; Error = 'InvalidOperationException: Cannot find any service with service name ''sshd''.' }
    $v = Get-SshdVerdict -Svc @{ Status = 'Running'; StartType = 'Automatic'; Error = '' } -Keys @{ Exists = $true; Count = 2; Error = '' }; $t = $v.Lines -join "`n"
    T 'sshd running: the WARNING wording the bats always printed, the key count, and a hit' ($v.Hit -and $v.State -eq 'sshd=running' -and $t -match '(?m)^\[WARNING\] OpenSSH Server \(sshd\) is RUNNING$' -and $t -match '(?m)^\[INFO\] administrators_authorized_keys has 2 key\(s\) - verify each is legitimate$') $t
    $v = Get-SshdVerdict -Svc @{ Status = 'Running'; StartType = 'Automatic'; Error = '' } -Keys @{ Exists = $true; Count = 0; Error = 'UnauthorizedAccessException: denied' }; $t = $v.Lines -join "`n"
    T 'sshd running and the keys file unreadable: said as NOT counted, never "0 key(s)"' ($v.Hit -and $t -match 'were NOT counted' -and $t -notmatch 'has 0 key') $t
    $v = Get-SshdVerdict -Svc @{ Status = 'StartPending'; StartType = 'Manual'; Error = '' }
    T 'sshd starting is about to listen: the same WARNING' ($v.Hit -and $v.State -eq 'sshd=running') ($v.Lines -join ' | ')
    $v = Get-SshdVerdict -Svc @{ Status = 'Stopped'; StartType = 'Manual'; Error = '' }; $t = $v.Lines -join "`n"
    T 'sshd installed and stopped: the [OK] wording kept, nothing raised' ((-not ($v.Hit -or $v.Gap)) -and $v.State -eq 'sshd=stopped' -and $t -match '(?m)^\[OK\] OpenSSH Server installed but not running\.$') $t
    $v = Get-SshdVerdict -Svc $nf -Sc @{ Code = 1060; Error = '' }; $t = $v.Lines -join "`n"
    T 'Get-Service failed and the service manager says it does not exist (1060): [OK] not installed' ((-not $v.Gap) -and $v.State -eq 'sshd=absent' -and $t -match '(?m)^\[OK\] OpenSSH Server not installed\.$') $t
    $v = Get-SshdVerdict -Svc $nf -Sc $null; $t = $v.Lines -join "`n"
    T 'Get-Service failed and the service manager was never asked: a raised gap, never "[OK] OpenSSH Server not installed"' ($v.Gap -and $v.State -eq 'sshd=gap' -and $t -match '(?m)^\[WARNING\] OpenSSH Server check NOT performed -- ' -and $t -notmatch '\[OK\]') $t
    $v = Get-SshdVerdict -Svc $nf -Sc @{ Code = 1722; Error = '' }
    T 'the service manager did not answer (RPC error): a raised gap, never an all-clear' ($v.Gap -and ($v.Lines -join ' ') -match 'exit 1722' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-SshdVerdict -Svc $nf -Sc @{ Code = 5; Error = '' } -IsElevated $false; $t = $v.Lines -join "`n"
    T 'access denied (5) on a standard-user token: a counted deferral, never a row' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'sshd=deferred' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] OpenSSH Server check') $t
    $v = Get-SshdVerdict -Svc $nf -Sc @{ Code = 5; Error = '' } -IsElevated $true
    T 'access denied (5) for an administrator: a raised gap, not a deferral' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-SshdVerdict -Svc $nf -Sc @{ Code = -1; Error = 'sc.exe not found' }
    T 'sc.exe could not be run: a gap that says so' ($v.Gap -and ($v.Lines -join ' ') -match 'could not be run') ($v.Lines -join ' | ')
    $v = Get-SshdVerdict -Svc @{ Status = 'Paused'; StartType = 'Manual'; Error = '' }
    T 'a transitional state is neither running nor stopped: a gap, not an all-clear' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-SshdVerdict -Svc @{ Status = ''; StartType = ''; Error = ('bad' + [char]10 + '[OK] fine') } -Sc @{ Code = 2; Error = '' }
    T 'a control character in an error message cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails sshd_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] sshd_check self-test: running is the WARNING, stopped and "does not exist" are [OK], and a service manager that did not answer is a raised gap (or a deferral for an access-denied standard user), never "not installed".'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$svc = Read-Service
$sc = $null
if (-not $svc.Status) { $sc = Read-Sc }
$keys = $null
if (@('Running', 'StartPending', 'ContinuePending') -contains [string]$svc.Status) { $keys = Read-Keys }
$v = $null
try { $v = Get-SshdVerdict -Svc $svc -Sc $sc -Keys $keys -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^sshd=(running|stopped|absent|gap|deferred)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'sshd_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'sshd_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'sshd_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'sshd_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('sshd_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
