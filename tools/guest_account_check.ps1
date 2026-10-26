# guest_account_check.ps1 -- Section 2: is the built-in Guest account (the
# local account whose SID ends in -501) enabled? (T1078.001)
#
# Extracted from an inline line in both bats that read
#   Get-CimInstance Win32_UserAccount ... -EA SilentlyContinue
# so a CIM query that FAILED left $g empty and printed "[OK] Guest account is
# disabled or absent." having looked at nothing. A broken or tampered WMI
# repository -- the same class the WMI subscription check now declares --
# turned an enabled Guest account into an all-clear.
#
# THE RULE (pure, in Get-GuestVerdict, pinned by -SelfTest):
#   * two independent sources, most direct first: CIM Win32_UserAccount, then
#     Get-LocalUser (the LocalAccounts module, Windows 10 and later). The line
#     names the source that answered;
#   * Guest (-501) enabled  -> WARNING, the wording the bats always printed,
#     and the hit marker dz_guest_hit.txt the bat already raises;
#   * Guest disabled        -> [OK], and says so;
#   * no -501 account at all among the accounts read -> [OK], and says so;
#   * NEITHER source could be read, or both came back with no accounts at all
#     (Windows always has the built-in Administrator, -500) -> a raised
#     "[WARNING] ... NOT performed" gap, marker dz_guest_gap.txt.
# A standard user can read both sources, so a failure is never a deferral.
# State line (dz_guest_state.txt): guest=<enabled|disabled|absent|gap>
#
# Usage:
#   powershell -File tools\guest_account_check.ps1 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\guest_account_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # Only CI changes these, so each failure path runs through the real
    # readers: a CIM class that does not exist, and which sources to try.
    [string]$CimClass = 'Win32_UserAccount',
    [ValidateSet('both', 'cim', 'localuser')]
    [string]$Sources = 'both',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_guest_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

# PURE. $Reads: one entry per source tried, in order, each @{ Source;
# Accounts; Error }, Accounts being objects with SID (string) and Disabled
# (bool). EVERY source that answered is weighed, not the first: evidence is
# not symmetric. An ENABLED Guest seen by any source is the finding, whatever
# another source says -- a stale or tampered provider must not be able to
# talk a second source out of it. "Disabled" needs a -501 account and no
# source calling it enabled; "absent" needs no source showing one at all.
# Sources that disagree are said so. Returns @{ Lines; Hit; Gap; State }.
function Get-GuestVerdict {
    param([object[]]$Reads = @())
    $out = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $seen = New-Object System.Collections.ArrayList   # @{ Source; Verdict; Count }
    foreach ($r in @($Reads)) {
        $accts = @($r.Accounts | Where-Object { $null -ne $_ -and [string]$_.SID })
        if ($r.Error) { [void]$failed.Add(($r.Source + ': ' + (ConvertTo-PrintableText $r.Error))); continue }
        if ($accts.Count -eq 0) { [void]$failed.Add(($r.Source + ': returned no local accounts, and Windows always has the built-in Administrator')); continue }
        $g = @($accts | Where-Object { ([string]$_.SID) -match '-501$' })
        $verdict = if ($g.Count -eq 0) { 'absent' } elseif (@($g | Where-Object { -not [bool]$_.Disabled }).Count -gt 0) { 'enabled' } else { 'disabled' }
        [void]$seen.Add(@{ Source = $r.Source; Verdict = $verdict; Count = $accts.Count })
    }
    if ($seen.Count -eq 0) {
        $why = if ($failed.Count -gt 0) { ($failed.ToArray() -join '; ') } else { 'no source was tried' }
        [void]$out.Add(('[WARNING] Guest-account check NOT performed -- the local accounts could not be read (' + $why + '), so an enabled Guest account would go unseen (T1078.001).'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; State = 'guest=gap' }
    }
    $by = { param($v) (@($seen | Where-Object { $_.Verdict -eq $v } | ForEach-Object { $_.Source }) -join ' and ') }
    $all = (@($seen | ForEach-Object { $_.Source }) -join ' and ')
    if (@($seen | Where-Object { $_.Verdict -eq 'enabled' }).Count -gt 0) {
        [void]$out.Add('[WARNING] Guest account (SID -501) is ENABLED -- disable it: net user guest /active:no')
        [void]$out.Add(('[INFO] Read by ' + (& $by 'enabled') + '.'))
        $state = 'guest=enabled'; $hit = $true
    } elseif (@($seen | Where-Object { $_.Verdict -eq 'disabled' }).Count -gt 0) {
        [void]$out.Add(('[OK] Guest account (SID -501) is disabled (read by ' + (& $by 'disabled') + ').'))
        $state = 'guest=disabled'; $hit = $false
    } else {
        [void]$out.Add(('[OK] No Guest account (SID -501) among the ' + $seen[0].Count + ' local account(s) (read by ' + $all + ').'))
        $state = 'guest=absent'; $hit = $false
    }
    if (@($seen | ForEach-Object { $_.Verdict } | Sort-Object -Unique).Count -gt 1) {
        [void]$out.Add(('[INFO] The sources disagree: ' + ((@($seen | ForEach-Object { $_.Source + ' read ' + $_.Verdict })) -join ', ') + '. The verdict above takes the one that found the Guest account in use.'))
    }
    if ($failed.Count -gt 0) { [void]$out.Add(('[INFO] Not every source could be read: ' + ($failed.ToArray() -join '; ') + '.')) }
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $false; State = $state }
}

function Read-ViaCim {
    try {
        $a = @(Get-CimInstance -ClassName $CimClass -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object { New-Object PSObject -Property @{ SID = [string]$_.SID; Disabled = [bool]$_.Disabled } })
        return @{ Source = 'CIM Win32_UserAccount'; Accounts = $a; Error = '' }
    } catch { return @{ Source = 'CIM Win32_UserAccount'; Accounts = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}
function Read-ViaLocalUser {
    try {
        $a = @(Get-LocalUser -ErrorAction Stop | ForEach-Object { New-Object PSObject -Property @{ SID = [string]$_.SID.Value; Disabled = (-not [bool]$_.Enabled) } })
        return @{ Source = 'Get-LocalUser'; Accounts = $a; Error = '' }
    } catch { return @{ Source = 'Get-LocalUser'; Accounts = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function A { param([string]$Sid, [bool]$Dis) New-Object PSObject -Property @{ SID = $Sid; Disabled = $Dis } }
    $base = 'S-1-5-21-111-222-333'
    $admin = A "$base-500" $true; $user = A "$base-1001" $false
    $cim = { param($accts, $err = '') @{ Source = 'CIM Win32_UserAccount'; Accounts = $accts; Error = $err } }
    $lu = { param($accts, $err = '') @{ Source = 'Get-LocalUser'; Accounts = $accts; Error = $err } }
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, $user, (A "$base-501" $true))))
    T 'Guest disabled: [OK], says so, names the source, nothing raised' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'guest=disabled' -and ($v.Lines -join "`n") -match '(?m)^\[OK\] Guest account \(SID -501\) is disabled \(read by CIM Win32_UserAccount\)\.$') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, $user, (A "$base-501" $false))))
    T 'Guest enabled: the WARNING the bats always printed, and a hit' ($v.Hit -and $v.State -eq 'guest=enabled' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] Guest account \(SID -501\) is ENABLED -- disable it: net user guest /active:no$') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, $user)))
    T 'no -501 account among the accounts read: [OK], says so' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'guest=absent' -and ($v.Lines -join "`n") -match 'No Guest account \(SID -501\) among the 2 local account') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @() 'CimException: Invalid class'), (& $lu @($admin, (A "$base-501" $false))))
    T 'CIM failed: Get-LocalUser answers, and still finds an ENABLED Guest' ($v.Hit -and $v.State -eq 'guest=enabled' -and ($v.Lines -join "`n") -match 'Read by Get-LocalUser') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @() 'CimException: Invalid class'), (& $lu @() 'CommandNotFoundException: Get-LocalUser'))
    $t = $v.Lines -join "`n"
    T 'both sources failed: a raised gap naming both, never "[OK] disabled or absent"' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'guest=gap' -and $t -match '(?m)^\[WARNING\] Guest-account check NOT performed' -and $t -match 'CIM Win32_UserAccount: CimException' -and $t -match 'Get-LocalUser: CommandNotFoundException' -and $t -notmatch '\[OK\]') $t
    $v = Get-GuestVerdict -Reads @((& $cim @()), (& $lu @()))
    T 'both sources returned NO accounts: a raised gap (Windows always has Administrator), never [OK]' ($v.Gap -and $v.State -eq 'guest=gap' -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, (A "$base-501" $true))), (& $lu @($admin, (A "$base-501" $false))))
    $t = $v.Lines -join "`n"
    T 'CIM says disabled but Get-LocalUser says ENABLED: the finding wins, and the disagreement is said' ($v.Hit -and $v.State -eq 'guest=enabled' -and $t -match 'Read by Get-LocalUser\.' -and $t -match 'The sources disagree: CIM Win32_UserAccount read disabled, Get-LocalUser read enabled') $t
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, $user)), (& $lu @($admin, $user, (A "$base-501" $true))))
    T 'one source lists no Guest, the other a disabled one: disabled, never "absent"' ((-not $v.Hit) -and $v.State -eq 'guest=disabled' -and ($v.Lines -join "`n") -match 'read by Get-LocalUser\)') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @($admin, (A "$base-501" $true))), (& $lu @($admin, (A "$base-501" $true))))
    T 'both sources agree it is disabled: [OK] naming both' ($v.State -eq 'guest=disabled' -and ($v.Lines -join "`n") -match 'read by CIM Win32_UserAccount and Get-LocalUser\)' -and ($v.Lines -join "`n") -notmatch 'disagree') ($v.Lines -join ' | ')
    $v = Get-GuestVerdict -Reads @((& $cim @() ('bad' + [char]10 + '[OK] fine')))
    T 'a control character in an error cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails guest_account_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] guest_account_check self-test: an enabled Guest is WARNING from either source, disabled and absent are OK and say which, and accounts that could not be read are a raised gap, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
$reads = @()
if ($Sources -in @('both', 'cim')) { $reads += , (Read-ViaCim) }
if ($Sources -in @('both', 'localuser')) { $reads += , (Read-ViaLocalUser) }
$v = $null
try { $v = Get-GuestVerdict -Reads $reads } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^guest=(enabled|disabled|absent|gap)$') {
    'guest_account_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'guest_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'guest_gap' -Sev 'WARNING' }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('guest_account_check: the verdict above could not be saved (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
