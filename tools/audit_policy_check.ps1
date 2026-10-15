# audit_policy_check.ps1 -- verify the host is actually GENERATING the events
# the audit's event-log checks depend on. Invoked from Section 16.
#
# WHY THIS EXISTS (a whole class of false-cleans): the audit reads Security
# events -- 4688 process creation, 4624/4625 logon, 4720 account creation,
# 1102 log-clear -- and reports "[OK] no suspicious ..." when it finds none.
# But stock Windows does NOT audit process creation, and NEVER records process
# command lines without an explicit policy. So on a default box "no suspicious
# process-creation events" almost always means "process creation is not being
# audited" -- reported to the user as clean. For someone deciding whether their
# device is safe, that silent blindness is the most dangerous kind of result.
#
# This check makes the blindness VISIBLE: it reports which high-value audit
# subcategories are off, so a downstream "clean" event check is understood as
# "clean, AND the events were actually being recorded" rather than "clean
# because nothing was watching."
#
# LOCALE SAFETY: subcategories are addressed by their locale-independent GUIDs
# (the display names auditpol prints are localized -- the same trap that made
# the old netsh firewall scrape misreport on non-English Windows). The
# command-line-inclusion signal is read straight from the registry, which is
# fully locale-independent. The auditpol Inclusion-Setting text ("Success" /
# "No Auditing") IS localized; that parse is best-effort and its result is
# clearly labelled, while the registry cmdline signal is definitive everywhere.
#
# SEVERITY: WARNING (never CRITICAL). Auditing being off is the DEFAULT on a
# fresh install, not proof of tampering -- but it does mean the event-based
# detections cannot be trusted as clean, which the user must know. If auditpol
# itself cannot run, the check reports [SKIPPED] rather than a false [OK].
#
# MARKER: writes the severity word to $env:TEMP\dz_auditpol.txt; the caller
# reads it and raises via :dz_finding. No marker when everything is enabled.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

# ---------------------------------------------------------------------------
# PURE VERDICTS. auditpol's CSV in, classification out; no process, no
# registry. The judgement lives here so it can be pinned against real rows
# (an English header, a localized header, "Success and Failure", "Erfolg").
# ---------------------------------------------------------------------------

# Subcategory GUID -> Inclusion Setting, located POSITIONALLY: the GUID literal
# is locale-invariant, the header row is not (see the comment in the live
# path below for the German/Japanese failure this replaces).
function ConvertFrom-AuditpolCsv {
    param([string[]]$Lines)
    $rows = @{}
    foreach ($line in @($Lines)) {
        $f = [string]$line -split ','
        for ($i = 0; $i -lt $f.Count - 1; $i++) {
            if ($f[$i].Trim() -match '^\{?0cce[0-9a-f]{4}-') {
                $rows[$f[$i].Trim().Trim('{','}').ToLower()] = $f[$i + 1].Trim()
                break
            }
        }
    }
    return $rows
}

# One subcategory: is the success side being recorded?
#   contains "Success"            -> ON  (covers "Success" and "Success and Failure")
#   "No Auditing" / "Failure" / empty -> OFF, a finding
#   anything else                 -> the text is localized and cannot be
#                                    classified; say so, never fabricate OFF
function Get-AuditRowVerdict {
    param([string]$Name, [string]$Setting, [string]$Feeds, [string]$Guid = '', [bool]$Context = $false)
    # A CONTEXT row tells the reader which evidence is kept and which is not,
    # and is NEITHER a finding NOR evidence that auditing is on. It is decided
    # FIRST, before the Success test: Windows ships a SACL on LSASS that records
    # attempts to read its memory, but only while Kernel Object auditing is on,
    # and Microsoft's default for that subcategory is Off. Grading its absence
    # would raise on nearly every machine; letting its PRESENCE through the
    # [OK] branch below was worse, and is what the first version did -- on a
    # machine where all four graded rows were unreadable (a localized Windows)
    # but this one was on, the coverage block then read
    # "Audit visibility : OK" for subcategories it had failed to read. That is
    # the regression PR #248 paid for, reintroduced by one misplaced branch, so
    # both of this row's wordings are [INFO] and neither is a graded phrase.
    if ($Context) {
        $shownC = if ($Setting) { $Setting } else { '(not set)' }
        if ($Setting -and $Setting -match 'Success') {
            return @{ Line = "[INFO] $Name IS being recorded [$shownC] -- $Feeds."; Sev = 'OK'; Context = $true }
        }
        # The same rule as the graded rows: a setting whose text this check
        # cannot classify is reported as unread, never fabricated as off.
        if ($Setting -and $Setting -notmatch '^(No Auditing|Failure)$') {
            return @{ Line = "[INFO] $Name state could not be read [$shownC] -- $Feeds. Whether it is being recorded is not established (localized Windows); verify: auditpol /get /subcategory:$Guid"; Sev = 'OK'; Context = $true }
        }
        return @{ Line = "[INFO] $Name is not being recorded [$shownC] -- $Feeds. Not a finding: Windows leaves this subcategory off by default."; Sev = 'OK'; Context = $true }
    }
    if ($Setting -and $Setting -match 'Success') {
        return @{ Line = "[OK] $Name auditing is ON -- feeds $Feeds."; Sev = 'OK' }
    }
    if ($Setting -and $Setting -notmatch '^(No Auditing|Failure)$') {
        return @{ Line = "[WARNING] $Name auditing state could not be read -- auditpol reported '$Setting', which this check cannot classify (localized Windows). Verify manually: auditpol /get /subcategory:$Guid"; Sev = 'WARNING'; Gap = $true }
    }
    $shown = if ($Setting) { $Setting } else { '(not set)' }
    return @{ Line = "[WARNING] $Name auditing is OFF [$shown] -- a clean result for the $Feeds may only mean these events are not being recorded (T1562.002)."; Sev = 'WARNING' }
}

# ProcessCreationIncludeCmdLine_Enabled: 1 is the only value that records the
# command line. Absent, 0, or anything else means 4688 carries no payload.
function Get-CmdLineVerdict {
    param($Value)
    # REG_DWORD arrives as Int32, but a hand-written REG_SZ '1' means the same
    # thing to Windows; compare the text so both count, and nothing else does.
    if ($null -ne $Value -and ([string]$Value).Trim() -eq '1') {
        return @{ Line = '[OK] Process-creation command-line logging is ENABLED (4688 events include the command line).'; Sev = 'OK' }
    }
    return @{ Line = '[WARNING] Process-creation command-line logging is DISABLED -- even audited 4688 events omit the command line, hiding the actual payload of a malicious launch (T1562.002).'; Sev = 'WARNING' }
}

# Subcategories whose absence blinds a detection the audit actually performs.
# GUIDs are locale-independent; names are for the report only.
$script:Subs = @(
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation (4688)';         Feeds = 'suspicious-process, service-install and LOLBin event checks' },
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon (4624/4625)';                Feeds = 'logon / failed-logon and lateral-movement checks' },
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management (4720/4732)'; Feeds = 'new-account and admin-group-change checks' },
    # {0CCE922F} is Audit_PolicyChange_AuditPolicy (ntsecapi.h). This row used
    # to query {0CCE9217}, which is Audit_Logon_AccountLockout -- a different
    # subcategory in a different category that happens to ship default=Success
    # on Windows client. So the exact T1562.002 action this row exists to catch,
    # `auditpol /set /subcategory:{0CCE922F-...} /success:disable`, left the
    # queried subcategory untouched and the tool reported "[OK] Audit Policy
    # Change (4719) auditing is ON" while 4719 was in fact blinded. The one
    # check that tells the reader whether tamper-detection is live was reporting
    # the opposite of the truth. Verified against Microsoft's Auditing Constants
    # and asserted on a real Windows runner by the helpers-ps51 CI job.
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change (4719)';        Feeds = 'detection of auditing being turned off by an attacker' },
    # CONTEXT ONLY (Context = $true): Windows 10 and later ship a SACL on
    # LSASS.exe that logs attempts to read its memory (Microsoft, "What's new in
    # Windows 10, version 1507": S:(AU;SAFA;0x0010;;;WD), 0x0010 being
    # PROCESS_VM_READ), and those records appear only while THIS subcategory is
    # on. Microsoft's Policy CSP gives its default as Off, and describes the
    # events as high-volume with "little to no security relevance", so the audit
    # does not ask for them and does not grade their absence -- it says, once,
    # that this evidence is not being kept.
    @{ Guid = '{0CCE921F-69AE-11D9-BED3-505054503030}'; Name = 'Kernel Object (4656/4663: attempts to read LSASS memory)'; Context = $true; Feeds = 'when it is on, Windows records which program tried to read another process''s memory, including LSASS; when it is off, nothing records that' }
)

# PURE: the whole subcategory table, graded. Rows maps a lowercase, brace-less
# GUID to the setting text auditpol reported. Extracted so the TABLE plumbing is
# tested, not only one row at a time: a mutation that stopped passing the
# Context flag through failed no case while the self-test called the verdict
# function directly.
function Get-AuditRowsReport {
    param($Subs, $Rows)
    $out = New-Object System.Collections.ArrayList
    $sev = 'OK'; $gapSev = 'OK'
    foreach ($s in @($Subs)) {
        $set = $Rows[$s.Guid.ToLower().Trim('{', '}')]
        $isCtx = $false; if ($s.ContainsKey('Context')) { $isCtx = [bool]$s.Context }
        $v = Get-AuditRowVerdict -Name $s.Name -Setting ([string]$set) -Feeds $s.Feeds -Guid $s.Guid -Context $isCtx
        [void]$out.Add($v.Line)
        if ($v.Sev -ne 'OK') { if ($v.Gap) { $gapSev = 'WARNING' } else { $sev = 'WARNING' } }
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    # A real `auditpol /get /subcategory:<guids> /r` answer from an English
    # Windows 11 host: the header row, then one row per GUID asked for. The
    # blank first line is what auditpol prints.
    $english = @(
        '',
        'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
        'Z4NEE52,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,',
        'Z4NEE52,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,',
        'Z4NEE52,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},No Auditing,',
        'Z4NEE52,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,'
    )
    $rows = ConvertFrom-AuditpolCsv -Lines $english
    T 'the English CSV yields one setting per GUID (4 rows, header ignored)' ($rows.Count -eq 4) ("count=" + $rows.Count)
    T 'Process Creation reads Success' ($rows['0cce922b-69ae-11d9-bed3-505054503030'] -eq 'Success') ''
    T 'Logon reads Success and Failure' ($rows['0cce9215-69ae-11d9-bed3-505054503030'] -eq 'Success and Failure') ''
    T 'User Account Management reads No Auditing' ($rows['0cce9235-69ae-11d9-bed3-505054503030'] -eq 'No Auditing') ''
    # A localized header: the column titles are not English, the GUID is.
    $german = @(
        'Computername,Richtlinienziel,Unterkategorie,GUID der Unterkategorie,Einschlusseinstellung,Ausschlusseinstellung',
        'PC01,System,Prozesserstellung,{0CCE922B-69AE-11D9-BED3-505054503030},Erfolg,',
        'PC01,System,Anmelden,{0CCE9215-69AE-11D9-BED3-505054503030},Keine Uberwachung,'
    )
    $g = ConvertFrom-AuditpolCsv -Lines $german
    T 'a localized header still yields the rows (GUID is found positionally, not by column name)' ($g.Count -eq 2) ("count=" + $g.Count)
    T 'the localized setting text is carried through untouched' ($g['0cce922b-69ae-11d9-bed3-505054503030'] -eq 'Erfolg') ''
    T 'an empty or absent CSV yields no rows and no error' ((ConvertFrom-AuditpolCsv -Lines @()).Count -eq 0 -and (ConvertFrom-AuditpolCsv -Lines $null).Count -eq 0) ''

    $feeds = 'suspicious-process, service-install and LOLBin event checks'
    $v = Get-AuditRowVerdict -Name 'Process Creation (4688)' -Setting 'Success' -Feeds $feeds
    T 'Success is ON' ($v.Sev -eq 'OK' -and $v.Line -match '^\[OK\] Process Creation \(4688\) auditing is ON') $v.Line
    $v = Get-AuditRowVerdict -Name 'Logon (4624/4625)' -Setting 'Success and Failure' -Feeds $feeds
    T '"Success and Failure" is ON (the success side is recorded)' ($v.Sev -eq 'OK') $v.Line
    $v = Get-AuditRowVerdict -Name 'User Account Management (4720/4732)' -Setting 'No Auditing' -Feeds $feeds
    T 'No Auditing is OFF -- WARNING, and the line says clean may mean unrecorded' ($v.Sev -eq 'WARNING' -and $v.Line -match 'auditing is OFF \[No Auditing\].*may only mean these events are not being recorded') $v.Line
    $v = Get-AuditRowVerdict -Name 'Logon (4624/4625)' -Setting 'Failure' -Feeds $feeds
    T 'Failure alone is OFF: successful logons are not recorded, which is what the logon checks read' ($v.Sev -eq 'WARNING' -and $v.Line -match 'OFF \[Failure\]') $v.Line
    $v = Get-AuditRowVerdict -Name 'Process Creation (4688)' -Setting '' -Feeds $feeds
    T 'an empty setting is OFF and shown as (not set)' ($v.Sev -eq 'WARNING' -and $v.Line -match '\[\(not set\)\]') $v.Line
    $v = Get-AuditRowVerdict -Name 'Process Creation (4688)' -Setting 'Erfolg' -Feeds $feeds -Guid '{0CCE922B-69AE-11D9-BED3-505054503030}'
    T 'a localized setting (Erfolg) is a raised gap ([WARNING] not classified), never reported as OFF' ($v.Sev -eq 'WARNING' -and $v.Line -match '^\[WARNING\].*cannot classify \(localized Windows\)' -and $v.Line -notmatch 'auditing is OFF') $v.Line
    T '...and the gap line hands the reader the exact auditpol command' ($v.Line -match 'auditpol /get /subcategory:\{0CCE922B-69AE-11D9-BED3-505054503030\}') $v.Line
    $v = Get-AuditRowVerdict -Name 'Logon (4624/4625)' -Setting 'Keine Uberwachung' -Feeds $feeds
    T 'a localized OFF is also a raised gap: the tool does not guess which language means off' ($v.Line -match '^\[WARNING\]') $v.Line

    $c = Get-CmdLineVerdict -Value 1
    T 'cmdline DWORD 1 is ENABLED' ($c.Sev -eq 'OK') $c.Line
    $c = Get-CmdLineVerdict -Value 0
    T 'cmdline DWORD 0 is DISABLED' ($c.Sev -eq 'WARNING') $c.Line
    $c = Get-CmdLineVerdict -Value $null
    T 'cmdline value absent is DISABLED (the Windows default)' ($c.Sev -eq 'WARNING') $c.Line
    $c = Get-CmdLineVerdict -Value '1'
    T 'cmdline stored as REG_SZ "1" still counts as ENABLED' ($c.Sev -eq 'OK') $c.Line
    $c = Get-CmdLineVerdict -Value 'yes'
    T 'cmdline junk text is DISABLED, not enabled by accident' ($c.Sev -eq 'WARNING') $c.Line

    # The CONTEXT row: it names evidence that is not being kept, and it is never
    # a finding and never evidence of auditing being on.
    $cx = Get-AuditRowVerdict -Name 'Kernel Object (4656/4663: attempts to read LSASS memory)' -Setting 'No Auditing' -Feeds 'when it is on, Windows records which program tried to read another process''s memory, including LSASS; when it is off, nothing records that' -Context $true
    T 'a CONTEXT row that is off prints [INFO], raises nothing, and uses none of the graded phrases' ($cx.Sev -eq 'OK' -and $cx.Context -eq $true -and $cx.Line -cmatch '^\[INFO\] Kernel Object .* is not being recorded \[No Auditing\]' -and $cx.Line -cnotmatch 'auditing is (ON|OFF)') $cx.Line
    # The real table, graded end to end: the four graded rows on, Kernel Object
    # off. Exactly one [INFO], no WARNING, nothing raised.
    $allOn = @{}
    foreach ($sb in $script:Subs) { $allOn[$sb.Guid.ToLower().Trim('{', '}')] = 'Success' }
    $allOn['0cce921f-69ae-11d9-bed3-505054503030'] = 'No Auditing'
    $tr = Get-AuditRowsReport -Subs $script:Subs -Rows $allOn
    T 'the real table with Kernel Object off: one [INFO] line, no WARNING, nothing raised (the live plumbing, not one row)' ($tr.Sev -eq 'OK' -and $tr.GapSev -eq 'OK' -and @($tr.Lines | Where-Object { $_ -cmatch '^\[INFO\] Kernel Object ' }).Count -eq 1 -and @($tr.Lines | Where-Object { $_ -cmatch '^\[WARNING\]' }).Count -eq 0 -and $tr.Lines.Count -eq $script:Subs.Count) ($tr.Lines -join ' | ')
    $tr = Get-AuditRowsReport -Subs $script:Subs -Rows @{}
    T 'nothing recorded at all: every graded row WARNS, the context row still only informs' ($tr.Sev -eq 'WARNING' -and @($tr.Lines | Where-Object { $_ -cmatch '^\[WARNING\]' }).Count -eq ($script:Subs.Count - 1) -and @($tr.Lines | Where-Object { $_ -cmatch '^\[INFO\] Kernel Object ' }).Count -eq 1) ($tr.Lines -join ' | ')
    T 'exactly one row in the shipped table is context-only, and it is Kernel Object' (@($script:Subs | Where-Object { $_.ContainsKey('Context') -and $_.Context }).Count -eq 1 -and @($script:Subs | Where-Object { $_.ContainsKey('Context') -and $_.Context })[0].Guid -eq '{0CCE921F-69AE-11D9-BED3-505054503030}') ''
    $cx = Get-AuditRowVerdict -Name 'Kernel Object (4656/4663: attempts to read LSASS memory)' -Setting 'Success and Failure' -Feeds 'x' -Context $true
    $cxl = Get-AuditRowVerdict -Name 'Kernel Object (4656/4663: attempts to read LSASS memory)' -Setting 'Erfolg' -Feeds 'x' -Guid '{0CCE921F-69AE-11D9-BED3-505054503030}' -Context $true
    T 'a CONTEXT row whose setting is localized is reported as unread, never fabricated as off' ($cxl.Sev -eq 'OK' -and $cxl.Line -cmatch '^\[INFO\] Kernel Object .* state could not be read \[Erfolg\]' -and $cxl.Line -notmatch 'is not being recorded' -and $cxl.Line -match 'auditpol /get /subcategory:\{0CCE921F') $cxl.Line
    T 'a CONTEXT row that is ON is also [INFO] and never says the graded phrase: it is not evidence that the audit''s own subcategories are on' ($cx.Sev -eq 'OK' -and $cx.Context -eq $true -and $cx.Line -cmatch '^\[INFO\] Kernel Object .* IS being recorded \[Success and Failure\]' -and $cx.Line -cnotmatch 'auditing is (ON|OFF)') $cx.Line
    # The shape that broke it: a localized Windows where none of the four
    # graded rows can be read, and this one is on.
    $loc = @{}
    foreach ($sb in $script:Subs) { $loc[$sb.Guid.ToLower().Trim('{', '}')] = 'Erfolg' }
    $loc['0cce921f-69ae-11d9-bed3-505054503030'] = 'Success and Failure'
    $tr = Get-AuditRowsReport -Subs $script:Subs -Rows $loc
    T 'all four graded rows unreadable while Kernel Object is ON: four raised gaps, and no line that could certify audit visibility' ($tr.GapSev -eq 'WARNING' -and @($tr.Lines | Where-Object { $_ -cmatch 'auditing is ON' }).Count -eq 0 -and @($tr.Lines | Where-Object { $_ -cmatch '^\[WARNING\].*cannot classify' }).Count -eq 4) ($tr.Lines -join ' | ')
    $cx = Get-AuditRowVerdict -Name 'Process Creation (4688)' -Setting 'No Auditing' -Feeds 'x'
    T 'without -Context the same setting is still a WARNING (the four graded rows are untouched)' ($cx.Sev -eq 'WARNING' -and $cx.Line -cmatch 'auditing is OFF') $cx.Line
    T 'the cannot-classify row is flagged as a GAP (it feeds the auditpol_gap marker, never the finding row)' ((Get-AuditRowVerdict -Name 'Logon' -Setting 'Erfolg' -Feeds 'x').Gap -eq $true -and -not (Get-AuditRowVerdict -Name 'Logon' -Setting 'No Auditing' -Feeds 'x').Gap) ''
    if ($fails) { Write-Output "[FAIL] $fails audit_policy_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] audit_policy_check self-test: real auditpol rows parse by GUID under any header, Success and Failure is ON, a localized setting is stated as unread rather than reported OFF.'
    exit 0
}

'--- [T1562.002/DS0026] Audit-policy visibility (are the events even being logged?) ---'
$sev = 'OK'

$gapSev = 'OK'
$subs = $script:Subs

$apOk = $true
$rows = @{}
try {
    $guidList = ($subs | ForEach-Object { $_.Guid }) -join ','
    $csv = & auditpol /get ("/subcategory:$guidList") /r 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $csv) { $apOk = $false }
    else {
        # Locate each row by its GUID POSITIONALLY, not by English column name.
        # auditpol localizes its /r header row -- on Japanese Windows the
        # "Subcategory GUID" column is titled in katakana, on German in
        # German -- so `$line.'Subcategory GUID'` returns $null on
        # any non-English Windows -- $rows stayed empty and all four
        # subcategories were then reported OFF, with '(not set)' giving the
        # reader no hint that this was a parse failure rather than a real
        # finding. A German or Japanese user got four fabricated WARNINGs and a
        # downgraded audit-visibility verdict on a correctly configured machine.
        # ConvertFrom-AuditpolCsv finds the field that looks like a GUID and
        # takes the next field as its setting; -SelfTest pins a German header.
        $rows = ConvertFrom-AuditpolCsv -Lines @($csv)
    }
} catch { $apOk = $false }

if (-not $apOk) {
    '[WARNING] auditpol could not be queried -- audit-policy visibility NOT verified (needs admin).'
    $gapSev = 'WARNING'
} else {
    # "Success" present => the success events this feeds are being recorded.
    # "No Auditing" or empty => blind. The setting TEXT is localized too, so a
    # third case exists: the row was found but its value is in a language this
    # script cannot classify. Reporting that as "auditing is OFF" would be a
    # fabricated finding, so Get-AuditRowVerdict reports it as unread. A row
    # marked Context is named, never graded.
    $rep = Get-AuditRowsReport -Subs $subs -Rows $rows
    foreach ($l in $rep.Lines) { $l }
    if ($rep.Sev -ne 'OK') { $sev = 'WARNING' }
    if ($rep.GapSev -ne 'OK') { $gapSev = 'WARNING' }
}

# Command-line inclusion in 4688 -- locale-independent registry signal. Without
# it, even when 4688 is on, the events carry no command line, so any check that
# inspects a process command line from the log is blind to the payload.
$cmdKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$cmd = $null
try { $cmd = (Get-ItemProperty -Path $cmdKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled } catch {}
$cv = Get-CmdLineVerdict -Value $cmd
$cv.Line
if ($cv.Sev -ne 'OK') { $sev = 'WARNING' }

Write-Marker -Name 'auditpol' -Sev $sev
# A gap is its own row: the bat raises dz_auditpol_gap.txt with gap wording.
if ($gapSev -ne 'OK') { Write-Marker -Name 'auditpol_gap' -Sev $gapSev }
