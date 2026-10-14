# lsass_dump_config.ps1 -- settings that would have LSASS's memory written to a
# file, and any such file already on disk (T1003.001). Section 12.
#
# WHY. A copy of LSASS made to read its secrets lives for seconds, so the live
# snapshot will rarely catch one (Section 4) and the Security log holds the
# record only while process creation is audited (Section 12's companion check,
# lsass_copy_events.ps1). This check reads what PERSISTS whatever the auditing
# state: the three documented ways Windows can be told to write a memory dump
# of a named program, all of them an ordinary registry write, and none of them
# read by this audit before now.
#
#   * Silent process exit monitoring. Microsoft ("Registry Entries for Silent
#     Process Exit"): turning it on "sets the FLG_MONITOR_SILENT_PROCESS_EXIT
#     flag in ... Image File Execution Options\<ProcessName>\GlobalFlag" (that
#     flag is 0x200), and the per-program settings live under
#     ...\SilentProcessExit\<ProcessName>: ReportingMode (0x2 is LOCAL_DUMP,
#     "a dump file is created for the monitored process"), LocalDumpFolder
#     (default "%TEMP%\Silent Process Exit"), DumpType, MonitorProcess.
#   * Windows Error Reporting local dumps. Microsoft ("Collecting User-Mode
#     Dumps"): ...\Windows Error Reporting\LocalDumps[\<ProcessName>] with
#     DumpFolder, DumpCount, DumpType (2 is a full dump).
#   * A dump file already written, where those settings point.
#
# GRADE THE VALUES, NEVER THE KEY. Microsoft documents
# IFEO\LSASS.exe\AuditLevel=00000008 for LSA protection's audit mode, which is
# on by default on a clean-installed Windows 11 22H2 or later, so the IFEO key
# for lsass.exe EXISTS on healthy machines and says nothing by itself. The same
# mistake once reported an empty leftover PortProxy key as an indicator
# (CLAUDE.md, "Key existence is not evidence").
#
# WHAT IT CANNOT SEE, said where it applies: a program that dumps LSASS without
# asking Windows to do it leaves none of these settings -- only, perhaps, the
# file. A dump written somewhere this check does not look is invisible, so the
# OK line names the folders it looked in rather than claiming none exists.
#
# MARKERS (the log_gap_check idiom): dz_lsadump.txt holds the highest severity
# found; dz_lsadump_gap.txt when a key could not be read at all (its own ledger
# row); dz_lsadump_deferred.txt holds the count a standard-user token could not
# perform, added to DEFERRED_COUNT, never a ledger row.
#
# -ImageName is the program whose dump settings are read; the audit leaves it
# at lsass.exe. CI points it at a harmless test name to prove the grading
# without touching the runner's real LSASS (the -Image idiom of
# lsass_copy_events.ps1).
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    [string]$ImageName = 'lsass.exe',
    [int]$Elevated = -1,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write turns a
    # finding into a CLEAN section. Create the directory, and let a genuine
    # write failure print instead of vanishing.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING' -or $B -eq 'WARNING') { return 'WARNING' }
    return 'OK'
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

# PURE: a registry value that holds flags. Windows accepts a REG_DWORD here and
# tools write a REG_SZ decimal or 0x string, so all three must read the same;
# the type of GlobalFlag in particular is not documented. $null when it cannot
# be read as a number -- never 0, which would read as "no flags set".
function ConvertTo-FlagNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) { return [long]$Value }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $null }
    if ($t -match '^0[xX]([0-9A-Fa-f]{1,16})$') { return [Convert]::ToInt64($Matches[1], 16) }
    if ($t -match '^\d{1,19}$') { return [long]$t }
    return $null
}

# PURE: everything read, graded.
#   GlobalFlag   the IFEO GlobalFlag value as read (any type), or $null
#   AuditLevel   the IFEO AuditLevel value, or $null (context only)
#   SilentExit   $null, or @{ ReportingMode; LocalDumpFolder; DumpType; MonitorProcess }
#   WerImage     $null, or @{ DumpFolder; DumpType; DumpCount }   (per-image)
#   WerGlobal    $null, or @{ DumpFolder; DumpType; DumpCount }   (all programs)
#   DumpFiles    @( @{ Path; Length; Modified } ) found where the settings point
#   LookedIn     the folders that were searched, for the OK line
#   ReadErrors   @( 'key: reason' ) -- a key that could not be read at all
function Get-DumpConfigReport {
    param([string]$ImageName = 'lsass.exe', $GlobalFlag = $null, $AuditLevel = $null,
          $SilentExit = $null, $WerImage = $null, $WerGlobal = $null,
          $DumpFiles = @(), $LookedIn = @(), $ReadErrors = @(), [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $sev = 'OK'; $gapSev = 'OK'; $deferred = 0
    $img = ConvertTo-PrintableText $ImageName
    $silentMonitor = 'Image File Execution Options\' + $img + '\GlobalFlag'
    # The sentence about credentials belongs to LSASS alone: pointed at any
    # other program (as CI does, to prove the grading without touching the
    # real LSASS) the lines must not borrow its consequence.
    $isLsass = ($img -ieq 'lsass.exe')
    $credLine = ''
    if ($isLsass) { $credLine = ' For LSASS that file would hold the credentials that were in its memory.' }

    # FLG_MONITOR_SILENT_PROCESS_EXIT (0x200): Windows watches this program's
    # exit, which is what makes the SilentProcessExit settings below apply.
    $gf = ConvertTo-FlagNumber $GlobalFlag
    if ($null -ne $GlobalFlag -and $null -eq $gf) {
        [void]$out.Add(('[WARNING] ' + $silentMonitor + ' is set to a value this check could not read as a number (' + (ConvertTo-PrintableText ([string]$GlobalFlag)) + ') -- silent-process-exit monitoring for ' + $img + ' NOT determined. Verify: reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $img + '" /v GlobalFlag'))
        $gapSev = 'WARNING'
    } elseif ($null -ne $gf -and ($gf -band 0x200)) {
        [void]$out.Add(('[WARNING] Silent-process-exit monitoring is ENABLED for ' + $img + ': ' + $silentMonitor + ' = 0x' + ('{0:X}' -f $gf) + ' has the 0x200 flag set, so Windows watches this program''s exit and applies the settings below (T1003.001).'))
        $sev = Get-MaxSev $sev 'WARNING'
    }

    if ($null -ne $SilentExit) {
        $rm = ConvertTo-FlagNumber $SilentExit.ReportingMode
        $folder = ([string]$SilentExit.LocalDumpFolder).Trim()
        if (-not $folder) { $folder = '%TEMP%\Silent Process Exit (the documented default)' }
        $dt = ([string]$SilentExit.DumpType).Trim(); if (-not $dt) { $dt = 'not set' }
        if ($null -ne $rm -and ($rm -band 0x2)) {
            [void]$out.Add(('[WARNING] ' + $img + ' is configured to have its memory DUMPED when it exits: SilentProcessExit\' + $img + ' ReportingMode = 0x' + ('{0:X}' -f $rm) + ' includes LOCAL_DUMP (0x2), writing to ' + (ConvertTo-PrintableText $folder) + ' (DumpType ' + (ConvertTo-PrintableText $dt) + ') (T1003.001).' + $credLine))
            $sev = Get-MaxSev $sev 'WARNING'
        }
        $mon = ([string]$SilentExit.MonitorProcess).Trim()
        if ($null -ne $rm -and ($rm -band 0x1) -and $mon) {
            [void]$out.Add(('[WARNING] ' + $img + ' is configured to START A PROGRAM when it exits: SilentProcessExit\' + $img + ' ReportingMode = 0x' + ('{0:X}' -f $rm) + ' includes 0x1 and MonitorProcess = ' + (ConvertTo-PrintableText $mon) + ' (T1003.001).'))
            $sev = Get-MaxSev $sev 'WARNING'
        }
        if (($null -eq $rm) -or (-not ($rm -band 0x3))) {
            [void]$out.Add(('[INFO] SilentProcessExit\' + $img + ' exists with ReportingMode ' + (ConvertTo-PrintableText ([string]$SilentExit.ReportingMode)) + ' -- neither a dump (0x2) nor a monitor program (0x1); named, not graded.'))
        }
    }

    foreach ($w in @(@{ K = $WerImage; Where = ('LocalDumps\' + $img); Img = $true },
                     @{ K = $WerGlobal; Where = 'LocalDumps (every program)'; Img = $false })) {
        if ($null -eq $w.K) { continue }
        $dt = ConvertTo-FlagNumber $w.K.DumpType
        $fold = ([string]$w.K.DumpFolder).Trim()
        if (-not $fold) { $fold = '%LOCALAPPDATA%\CrashDumps (the documented default); for a service, the system profile' }
        $what = 'DumpType ' + (ConvertTo-PrintableText ([string]$w.K.DumpType)) + ', folder ' + (ConvertTo-PrintableText $fold)
        if ($w.Img) {
            [void]$out.Add(('[WARNING] Windows Error Reporting is configured to write a dump of ' + $img + ' specifically: ' + $w.Where + ' (' + $what + ') (T1003.001).' + $credLine))
            $sev = Get-MaxSev $sev 'WARNING'
        } elseif ($null -ne $dt -and $dt -eq 2) {
            # Not LSASS-specific: a general debugging setting an administrator
            # or a vendor may have set. Named, never graded -- raising it would
            # teach the reader to ignore this check.
            [void]$out.Add(('[INFO] Windows Error Reporting is set to write FULL dumps for every program that crashes (' + $w.Where + ', ' + $what + ') -- a general debugging setting, not specific to ' + $img + '; named, not graded.'))
        }
    }

    foreach ($f in @($DumpFiles)) {
        if ($null -eq $f) { continue }
        $sz = ''
        if ($null -ne $f.Length) { $sz = ', ' + [string][math]::Round(([double]$f.Length) / 1MB, 1) + ' MB' }
        $when = ''
        if ($null -ne $f.Modified) { $when = ', written ' + ([datetime]$f.Modified).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z' }
        # A dump file this tool's own detection harness planted is still
        # reported -- hiding it would hide the real thing too, and unlike an
        # event-log record a file can be deleted -- but the line says what it
        # is, so a leftover after a failed cleanup cannot send its owner into
        # an incident response over a 15-byte test file.
        $mine = ''
        if (([string]$f.Path) -match 'dz_selftest') {
            $mine = ' This file''s name carries dz_selftest, the marker this tool''s own detection harness uses: if tests\detection_selftest.ps1 has been run on this machine, this is that test file, it holds nothing, and tests\cleanup_selftest.ps1 deletes it.'
        }
        $advice = ''
        if ($isLsass) { $advice = ' Such a file holds the credentials that were in LSASS''s memory, and anyone who can read the file can use them. If you did not create it, treat it as credential theft: change the passwords used on this machine from a different, clean one, and keep the file for whoever investigates.' }
        [void]$out.Add(('[CRITICAL] A memory dump of ' + $img + ' is on disk: ' + (ConvertTo-PrintableText ([string]$f.Path)) + $sz + $when + ' (T1003.001).' + $advice + $mine))
        $sev = Get-MaxSev $sev 'CRITICAL'
    }

    foreach ($e in @($ReadErrors)) {
        if (-not $e) { continue }
        if (-not $IsElevated) {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + (ConvertTo-PrintableText ([string]$e)) + ' -- re-run as administrator.'))
            $deferred++
        } else {
            [void]$out.Add(('[WARNING] Dump settings for ' + $img + ' NOT checked -- ' + (ConvertTo-PrintableText ([string]$e)) + '.'))
            $gapSev = 'WARNING'
        }
    }

    # AuditLevel is the LSA-protection audit setting Microsoft documents, on by
    # default on Windows 11 22H2+. It is named so a reader who sees a value
    # under this key knows which one is ordinary.
    $al = ConvertTo-FlagNumber $AuditLevel
    if ($null -ne $al) {
        [void]$out.Add(('[INFO] Image File Execution Options\' + $img + '\AuditLevel = ' + [string]$al + ' -- the LSA-protection audit setting Microsoft documents (on by default on Windows 11 22H2 and later); not a dump setting.'))
    }

    if ($sev -eq 'OK' -and $gapSev -eq 'OK' -and $deferred -eq 0) {
        $where = 'the documented dump folders'
        if (@($LookedIn).Count -gt 0) { $where = (@($LookedIn) | ForEach-Object { ConvertTo-PrintableText ([string]$_) }) -join '; ' }
        [void]$out.Add(('[OK] Nothing is configured to write a memory dump of ' + $img + ', and no such dump was found in ' + $where + '. A program that dumps it without asking Windows leaves no setting here.'))
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev; Deferred = $deferred }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function Rep { param($h) if ($null -eq $h) { $h = @{} }
        Get-DumpConfigReport -ImageName 'lsass.exe' -GlobalFlag $h.GlobalFlag -AuditLevel $h.AuditLevel -SilentExit $h.SilentExit -WerImage $h.WerImage -WerGlobal $h.WerGlobal -DumpFiles @($h.DumpFiles) -LookedIn @('C:\Windows\Temp', 'C:\Users\u\AppData\Local\Temp\Silent Process Exit') -ReadErrors @($h.ReadErrors) -IsElevated ([bool]$(if ($null -eq $h.IsElevated) { $true } else { $h.IsElevated })) }

    $r = Rep @{}
    $j = $r.Lines -join "`n"
    T 'a machine with none of these settings: OK, naming the folders looked in, and it does not claim no dump exists anywhere' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'OK' -and $j -cmatch '^\[OK\] Nothing is configured to write a memory dump of lsass\.exe, and no such dump was found in C:\\Windows\\Temp; C:\\Users\\u\\AppData\\Local\\Temp\\Silent Process Exit\. A program that dumps it without asking Windows leaves no setting here\.$') $j

    # The benign shape: LSA protection's audit mode, which ships on.
    $r = Rep @{ AuditLevel = 8 }
    $j = $r.Lines -join "`n"
    T 'AuditLevel=8 alone is the documented LSA-protection setting: OK, named as ordinary, never a finding' ($r.Sev -eq 'OK' -and $j -match '\[INFO\] Image File Execution Options\\lsass\.exe\\AuditLevel = 8 -- the LSA-protection audit setting Microsoft documents' -and $j -match '\[OK\] Nothing is configured') $j

    # GlobalFlag 0x200, in each form a real machine can hold it.
    foreach ($form in @(512, '512', '0x200', '0X200')) {
        $r = Rep @{ GlobalFlag = $form }
        T ('GlobalFlag with the 0x200 flag is a WARNING whether it is a number or a string (' + [string]$form + ')') ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'Silent-process-exit monitoring is ENABLED for lsass\.exe: .*GlobalFlag = 0x200 has the 0x200 flag set') ($r.Lines -join ' | ')
    }
    $r = Rep @{ GlobalFlag = 0x200 -bor 0x40 }
    T 'the flag is read as a bit, not an equality: 0x240 still carries 0x200' ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'GlobalFlag = 0x240 has the 0x200 flag set') ($r.Lines -join ' | ')
    $r = Rep @{ GlobalFlag = 0x40 }
    T 'a GlobalFlag without 0x200 is not this check''s business' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -notmatch 'Silent-process-exit monitoring is ENABLED') ($r.Lines -join ' | ')
    $r = Rep @{ GlobalFlag = 'yes please' }
    T 'a GlobalFlag that cannot be read as a number is a declared gap, never read as no flags set' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'NOT determined') ($r.Lines -join ' | ')

    # SilentProcessExit: a dump, a monitor program, and neither.
    $r = Rep @{ SilentExit = @{ ReportingMode = 2; LocalDumpFolder = 'C:\dumps'; DumpType = 2 } }
    $j = $r.Lines -join "`n"
    T 'ReportingMode with LOCAL_DUMP names the folder and the dump type' ($r.Sev -eq 'WARNING' -and $j -match 'configured to have its memory DUMPED when it exits: SilentProcessExit\\lsass\.exe ReportingMode = 0x2 includes LOCAL_DUMP \(0x2\), writing to C:\\dumps \(DumpType 2\)') $j
    $r = Rep @{ SilentExit = @{ ReportingMode = 2 } }
    T 'with no folder set, the documented default is named rather than left blank' (($r.Lines -join "`n") -match 'writing to %TEMP%\\Silent Process Exit \(the documented default\)') ($r.Lines -join ' | ')
    $r = Rep @{ SilentExit = @{ ReportingMode = 1; MonitorProcess = 'C:\x\m.exe' } }
    T 'ReportingMode 0x1 with a MonitorProcess names the program that would start' ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'START A PROGRAM when it exits.*MonitorProcess = C:\\x\\m\.exe') ($r.Lines -join ' | ')
    $r = Rep @{ SilentExit = @{ ReportingMode = 3; LocalDumpFolder = 'C:\d'; MonitorProcess = 'C:\x\m.exe' } }
    T 'ReportingMode 0x3 is both, and says both' ($r.Sev -eq 'WARNING' -and @($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 2) ($r.Lines -join ' | ')
    $r = Rep @{ SilentExit = @{ ReportingMode = 4 } }
    T 'a SilentProcessExit key with neither bit is named, not graded' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -match '\[INFO\] SilentProcessExit\\lsass\.exe exists with ReportingMode 4 -- neither a dump') ($r.Lines -join ' | ')

    # Windows Error Reporting.
    $r = Rep @{ WerImage = @{ DumpType = 2; DumpFolder = 'C:\wer' } }
    T 'a WER LocalDumps key for lsass.exe specifically is a WARNING' ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'Error Reporting is configured to write a dump of lsass\.exe specifically: LocalDumps\\lsass\.exe \(DumpType 2, folder C:\\wer\)') ($r.Lines -join ' | ')
    $r = Rep @{ WerGlobal = @{ DumpType = 2 } }
    T 'the GLOBAL full-dump setting is named as a general debugging setting, never graded' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -match '\[INFO\] Windows Error Reporting is set to write FULL dumps for every program') ($r.Lines -join ' | ')
    $r = Rep @{ WerGlobal = @{ DumpType = 1 } }
    T 'a global mini-dump setting says nothing at all' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -notmatch 'Error Reporting') ($r.Lines -join ' | ')

    # The file itself.
    $r = Rep @{ DumpFiles = @(@{ Path = 'C:\Users\u\AppData\Local\Temp\lsass.DMP'; Length = 51380224; Modified = (New-Object DateTime 2026, 10, 2, 7, 15, 0, ([DateTimeKind]::Utc)) }) }
    $j = $r.Lines -join "`n"
    T 'a dump FILE of lsass on disk is CRITICAL, with its path, size and time, and says what to do' ($r.Sev -eq 'CRITICAL' -and $j -cmatch '^\[CRITICAL\] A memory dump of lsass\.exe is on disk: C:\\Users\\u\\AppData\\Local\\Temp\\lsass\.DMP, 49 MB, written 2026-10-02 07:15:00Z \(T1003\.001\)\.' -and $j -match 'change the passwords used on this machine from a different, clean one') $j
    $r = Get-DumpConfigReport -ImageName 'dz_ci_dummy.exe' -DumpFiles @(@{ Path = 'C:\d\dz_ci_dummy.dmp' }) -LookedIn @('C:\d')
    T 'a dump of another program is still CRITICAL, without LSASS''s consequence or its advice' ($r.Sev -eq 'CRITICAL' -and ($r.Lines -join "`n") -match 'A memory dump of dz_ci_dummy\.exe is on disk' -and ($r.Lines -join "`n") -notmatch 'credential|LSASS|lsass') ($r.Lines -join ' | ')
    T 'the dump file outranks the settings' ((Rep @{ GlobalFlag = 512; DumpFiles = @(@{ Path = 'C:\x\lsass.dmp' }) }).Sev -eq 'CRITICAL') ''

    # A key that could not be read.
    $r = Rep @{ ReadErrors = @('the Image File Execution Options key for lsass.exe could not be read (Requested registry access is not allowed)') }
    T 'elevated, an unreadable key is a raised gap, never folded into the OK line' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'WARNING' -and ($r.Lines -join "`n") -match '\[WARNING\] Dump settings for lsass\.exe NOT checked' -and ($r.Lines -join "`n") -notmatch '\[OK\]') ($r.Lines -join ' | ')
    $r = Rep @{ ReadErrors = @('the Image File Execution Options key for lsass.exe could not be read (denied)'); IsElevated = $false }
    T 'on a standard-user token the same unreadable key is a counted deferral, never a ledger row' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'OK' -and $r.Deferred -eq 1 -and ($r.Lines -join "`n") -match '^\[DEFERRED - ADMIN REQUIRED\]' -and ($r.Lines -join "`n") -notmatch '\[OK\]') ($r.Lines -join ' | ')

    # Another image name (how CI proves the grading without touching LSASS).
    $r = Get-DumpConfigReport -ImageName 'dz_ci_dummy.exe' -GlobalFlag 512 -SilentExit @{ ReportingMode = 2; LocalDumpFolder = 'C:\d' } -LookedIn @('C:\d')
    $j = $r.Lines -join "`n"
    T 'pointed at another program, every line names that program and none mentions LSASS' ($r.Sev -eq 'WARNING' -and $j -match 'ENABLED for dz_ci_dummy\.exe' -and $j -match 'SilentProcessExit\\dz_ci_dummy\.exe' -and $j -notmatch 'LSASS' -and $j -notmatch 'lsass') $j

    $r = Rep @{ DumpFiles = @(@{ Path = 'C:\Users\u\AppData\Local\Temp\Silent Process Exit\lsass_dz_selftest.dmp' }) }
    $j = $r.Lines -join "`n"
    T 'a dump file left by this tool''s own harness is still CRITICAL, and the line says what it is' ($r.Sev -eq 'CRITICAL' -and $j -match 'A memory dump of lsass\.exe is on disk: C:\\Users\\u\\AppData\\Local\\Temp\\Silent Process Exit\\lsass_dz_selftest\.dmp' -and $j -match 'carries dz_selftest, the marker this tool''s own detection harness uses' -and $j -match 'cleanup_selftest\.ps1 deletes it') $j
    T 'an ordinary dump file carries no such sentence' (((Rep @{ DumpFiles = @(@{ Path = 'C:\x\lsass.dmp' }) }).Lines -join "`n") -notmatch 'dz_selftest') ''
    T 'a control character in a value cannot start a report line' ((((Rep @{ GlobalFlag = ('bad' + [char]10 + '[OK] fake') }).Lines -join "`n") -notmatch '(?m)^\[OK\] fake') -and @((Rep @{ SilentExit = @{ ReportingMode = 2; LocalDumpFolder = ('C:\x' + [char]13 + 'y') } }).Lines | Where-Object { $_ -match '[\x00-\x1F]' }).Count -eq 0) ''
    T 'a flag value reads the same from a number, a decimal string and a hex string' ((ConvertTo-FlagNumber 512) -eq 512 -and (ConvertTo-FlagNumber '512') -eq 512 -and (ConvertTo-FlagNumber '0x200') -eq 512 -and $null -eq (ConvertTo-FlagNumber 'x') -and $null -eq (ConvertTo-FlagNumber $null)) ''

    if ($fails) { Write-Output "[FAIL] $fails lsass_dump_config self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] lsass_dump_config self-test: a dump-on-exit setting or a dump file for LSASS is a finding, the documented LSA-protection AuditLevel and the global full-dump setting are named but never graded, an unreadable value is a declared gap rather than no flags set, and the OK line names where it looked.'
    exit 0
}

if (-not $MarkerDir) { $MarkerDir = $env:TEMP }
$img = $ImageName
if (-not $img) { $img = 'lsass.exe' }
'--- [T1003.001] Settings that would write a memory dump of ' + $img + ', and any such dump on disk ---'

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

$readErrors = New-Object System.Collections.ArrayList
function Get-Values {
    # One key read: its properties as a hashtable, $null when the key is absent,
    # and a recorded error when it exists but cannot be read. An absent key and
    # a key this token cannot open are different answers, and only the second
    # is a gap.
    param([string]$Path, [string]$Describe)
    try {
        if (-not (Test-Path -LiteralPath $Path -EA Stop)) { return $null }
        $p = Get-ItemProperty -LiteralPath $Path -EA Stop
        $h = @{}
        foreach ($n in @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) { $h[$n.Name] = $n.Value }
        return $h
    } catch {
        [void]$readErrors.Add($Describe + ' could not be read (' + $_.Exception.Message + ')')
        return $null
    }
}

$ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $img
$spePath  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\' + $img
$werBase  = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'

$ifeo = Get-Values -Path $ifeoPath -Describe ('the Image File Execution Options key for ' + $img)
$spe  = Get-Values -Path $spePath  -Describe ('the SilentProcessExit key for ' + $img)
$werI = Get-Values -Path ($werBase + '\' + $img) -Describe ('the Windows Error Reporting LocalDumps key for ' + $img)
$werG = Get-Values -Path $werBase -Describe 'the Windows Error Reporting LocalDumps key'

$globalFlag = $null; $auditLevel = $null
if ($null -ne $ifeo) {
    if ($ifeo.ContainsKey('GlobalFlag')) { $globalFlag = $ifeo['GlobalFlag'] }
    if ($ifeo.ContainsKey('AuditLevel')) { $auditLevel = $ifeo['AuditLevel'] }
}
$silentExit = $null
if ($null -ne $spe) {
    $silentExit = @{ ReportingMode = $spe['ReportingMode']; LocalDumpFolder = $spe['LocalDumpFolder']; DumpType = $spe['DumpType']; MonitorProcess = $spe['MonitorProcess'] }
}
$werImage = $null
if ($null -ne $werI) { $werImage = @{ DumpFolder = $werI['DumpFolder']; DumpType = $werI['DumpType']; DumpCount = $werI['DumpCount'] } }
$werGlobal = $null
if ($null -ne $werG) { $werGlobal = @{ DumpFolder = $werG['DumpFolder']; DumpType = $werG['DumpType']; DumpCount = $werG['DumpCount'] } }

# Where a dump of this program would land: the folders the settings name, plus
# the two documented defaults. Only files whose name holds the program's base
# name count, so an unrelated dump in a shared folder is not reported as this
# program's.
$base = $img
if ($base -match '^(.+)\.[^.]+$') { $base = $Matches[1] }
$folders = New-Object System.Collections.ArrayList
# Each default folder is built only when the variable it needs is set:
# Join-Path with a null path throws, and an error line in the report is noise
# the reader did not ask for.
$defaults = New-Object System.Collections.ArrayList
if ($env:TEMP) { [void]$defaults.Add((Join-Path $env:TEMP 'Silent Process Exit')) }
if ($env:LOCALAPPDATA) { [void]$defaults.Add((Join-Path $env:LOCALAPPDATA 'CrashDumps')) }
if ($env:windir) { [void]$defaults.Add((Join-Path $env:windir 'System32\config\systemprofile\AppData\Local\CrashDumps')) }
foreach ($cand in (@(
    ([string]$(if ($null -ne $silentExit) { $silentExit.LocalDumpFolder } else { '' })),
    ([string]$(if ($null -ne $werImage) { $werImage.DumpFolder } else { '' })),
    ([string]$(if ($null -ne $werGlobal) { $werGlobal.DumpFolder } else { '' }))
) + @($defaults.ToArray()))) {
    $c = ([string]$cand).Trim()
    if (-not $c) { continue }
    try { $c = [Environment]::ExpandEnvironmentVariables($c) } catch { }
    if ($folders -notcontains $c) { [void]$folders.Add($c) }
}
$dumpFiles = New-Object System.Collections.ArrayList
foreach ($f in $folders) {
    try {
        if (-not (Test-Path -LiteralPath $f -EA Stop)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f -Filter ('*' + $base + '*.dmp') -File -Force -EA Stop)) {
            [void]$dumpFiles.Add(@{ Path = $file.FullName; Length = $file.Length; Modified = $file.LastWriteTimeUtc })
        }
    } catch {
        [void]$readErrors.Add($f + ' could not be listed (' + $_.Exception.Message + ')')
    }
}

$report = Get-DumpConfigReport -ImageName $img -GlobalFlag $globalFlag -AuditLevel $auditLevel `
    -SilentExit $silentExit -WerImage $werImage -WerGlobal $werGlobal `
    -DumpFiles @($dumpFiles.ToArray()) -LookedIn @($folders.ToArray()) `
    -ReadErrors @($readErrors.ToArray()) -IsElevated ($Elevated -eq 1)
foreach ($l in $report.Lines) { $l }
Write-Marker -Name 'lsadump' -Sev $report.Sev
if ($report.GapSev -ne 'OK') { Write-Marker -Name 'lsadump_gap' -Sev $report.GapSev }
if ($report.Deferred -gt 0) { Write-Marker -Name 'lsadump_deferred' -Sev ([string]$report.Deferred) }
