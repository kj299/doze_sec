# file_walk_check.ps1 -- three checks that walk a folder tree and used to
# read a folder they could not open as a folder with nothing in it:
#   -Check TempAds     Section 14: alternate data streams on files under TEMP
#                      (T1564.004).
#   -Check TempHtml    Section 17: HTML/HTA files over 200 KB under TEMP
#                      (HTML smuggling staging, T1027.006).
#   -Check OutlookMsg  Section 17: .msg/.oft files written in the last 90 days
#                      under the user's Outlook data folder (T1566.001).
#
# Each was an inline line built on
#   Get-ChildItem -Recurse ... -EA SilentlyContinue
# (and, for the stream read, an empty catch{}). A folder or file the walk
# could not read was dropped without a word, and the line then printed
# "[OK] No suspicious ADS in Temp." / "[OK] No oversized HTML/HTA files" /
# "[OK] No recent Outlook .msg/.oft artefacts (Outlook profile may be
# absent)" -- the last one whether or not it had looked.
#
# THE RULE (pure, in Get-WalkVerdict, pinned by -SelfTest): grade what is
# readable, and NAME and COUNT what is not.
#   * a hit is the finding, wording kept, whatever else could not be read;
#     what could not be read is raised BESIDE it (hit and gap are
#     independent facts);
#   * no hit, but folders or files could not be read, or the time budget ran
#     out -> "[WARNING] ... NOT performed in full" with its own gap marker.
#     NEVER a deferral: these are the user's OWN folders, so a denial
#     there is not explained by a standard-user token (a deny ACE on a
#     staging folder is exactly what it would look like);
#   * the root folder: TEMP missing or unreadable is a gap (it always
#     exists); a missing Outlook data folder is a real answer -- "[OK] No
#     Outlook data folder for this user" -- and says so;
#   * nothing unreadable and no hit -> [OK], with how many files were
#     examined and how long it took;
#   * a file that vanished between the listing and the read is TEMP churn,
#     counted in the [INFO] line, never a gap;
#   * junctions and symbolic links are not followed: a link can loop, or lead
#     to a whole drive. Each one skipped is COUNTED AND NAMED in an [INFO]
#     line -- the old inline walk followed them, so this is said, not
#     silent. A cloud-synced folder is a reparse point but not a link, and
#     is walked;
#   * a folder path too long for the ordinary form is asked for again in the
#     \\?\ form before it is called unreadable;
#   * the time budget is per check: 180 s for the stream read (one call per
#     file), 60 s for the other two.
# Markers: dz_ads_hit / dz_ads_gap, dz_htmltemp_hit / _gap,
# dz_outlookmsg_hit / _gap; and
# dz_<name>_done, written last on every run -- the bat raises a
# "produced no verdict" row when it is absent.
#
# Usage:
#   powershell -File tools\file_walk_check.ps1 -Check <TempAds|TempHtml|OutlookMsg> [-MarkerDir <dir>] [-Elevated 0|1] [-BudgetSeconds <n>]
#   powershell -File tools\file_walk_check.ps1 -SelfTest   (walks nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('TempAds', 'TempHtml', 'OutlookMsg')]
    [string]$Check,
    [string]$MarkerDir = $env:TEMP,
    [int]$Elevated = -1,
    # Only CI changes these: a scratch root, so every state runs through the
    # real walker, and a budget of 0 to drive the out-of-time path.
    [string]$Root,
    # -1 = this check's own default (see $script:Checks).
    [int]$BudgetSeconds = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
$script:MaxListed = 25
$script:HtmlBytes = 200000
$script:MsgDays = 90

function Write-Marker {
    param([string]$Name, [string]$Sev)
    # An empty value is no verdict, never a marker.
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintablePath {
    # A file name goes into the report as text: no control characters (a
    # name can hold a line break), and capped.
    param([string]$s)
    # ...and no direction overrides: a right-to-left override in a name makes
    # 'gpj.exe' print as 'exe.jpg'.
    $t = (([string]$s) -replace '[\x00-\x1F\x7F\u202A-\u202E\u2066-\u2069]', '?')
    if ($t.StartsWith('\\?\')) { $t = $t.Substring(4) }
    # Too long: keep the START and the END. Cutting the tail dropped the file
    # name from a finding under a deep path, the one part the reader needs.
    if ($t.Length -gt 260) { $t = $t.Substring(0, 110) + ' ... ' + $t.Substring($t.Length - 140) }
    return $t
}

$script:Checks = @{
    TempAds    = @{ What = 'Alternate-data-stream check'; Where = 'TEMP'; Tech = 'T1564.004'; Budget = 180; Miss = 'content hidden in a stream there would go unseen'; Ok = '[OK] No suspicious ADS in Temp.' }
    TempHtml   = @{ What = 'Oversized HTML/HTA check'; Where = 'TEMP'; Tech = 'T1027.006'; Budget = 60; Miss = 'an HTML-smuggling payload staged there would go unseen'; Ok = '[OK] No oversized HTML/HTA files in user TEMP.' }
    OutlookMsg = @{ What = 'Outlook .msg/.oft check'; Where = 'the Outlook data folder'; Tech = 'T1566.001'; Budget = 60; Miss = 'a recent message file there would go unseen'; Ok = '[OK] No recent Outlook .msg/.oft artefacts.' }
}

# PURE. $Scan: @{ RootState = ok|missing|unreadable; RootDenied; RootError;
# RootPath; Hits = @(strings, already formatted for the list); Examined;
# Unreadable = @( @{ Path; Denied } ); Vanished; OutOfTime; Seconds; Budget }.
# Returns @{ Lines; Hit; Gap; Deferred }.
function Get-WalkVerdict {
    param([string]$Check, $Scan, [bool]$IsElevated = $true)
    $c = $script:Checks[$Check]
    $out = New-Object System.Collections.ArrayList
    $root = ConvertTo-PrintablePath ([string]$Scan.RootPath)
    if ([string]$Scan.RootState -eq 'missing') {
        if ($Check -eq 'OutlookMsg') {
            [void]$out.Add(('[OK] No Outlook data folder for this user (' + $root + ' does not exist), so there are no .msg/.oft files to check.'))
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0 }
        }
        [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed -- the folder ' + $root + ' was not found, so ' + $c.Miss + ' (' + $c.Tech + ').'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0 }
    }
    if ([string]$Scan.RootState -ne 'ok') {
        $why = ConvertTo-PrintablePath ([string]$Scan.RootError)
        [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed -- the folder ' + $root + ' could not be read (' + $why + '), so ' + $c.Miss + ' (' + $c.Tech + ').'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0 }
    }
    $hits = @($Scan.Hits | Where-Object { [string]$_ })
    $unread = @($Scan.Unreadable)
    $names = (@($unread | Select-Object -First 3 | ForEach-Object { ConvertTo-PrintablePath ([string]$_.Path) }) -join '; ') + $(if ($unread.Count -gt 3) { ('; and ' + ($unread.Count - 3) + ' more') } else { '' })
    $partial = New-Object System.Collections.ArrayList
    if ($unread.Count -gt 0) { [void]$partial.Add(([string]$unread.Count + ' folder(s) or file(s) could not be read (' + $names + ')')) }
    if ($Scan.OutOfTime) { [void]$partial.Add(('the ' + [string]$Scan.Budget + 's time budget ran out after ' + [string]$Scan.Examined + ' file(s)')) }
    $links = @($Scan.Links | Where-Object { [string]$_ })
    $linkLine = ''
    if ($links.Count -gt 0) { $linkLine = ('[INFO] ' + [string]$links.Count + ' link(s) to another folder (junction or symbolic link) were NOT followed, so what they point at was not checked here: ' + (@($links | Select-Object -First 3 | ForEach-Object { ConvertTo-PrintablePath ([string]$_) }) -join '; ') + $(if ($links.Count -gt 3) { ('; and ' + ($links.Count - 3) + ' more') } else { '' }) + '.') }
    $scope = ([string]$Scan.Examined + ' file(s) examined under ' + $root + ' in ' + [string]$Scan.Seconds + ' s' + $(if ([int]$Scan.Vanished -gt 0) { ('; ' + [string]$Scan.Vanished + ' vanished while being read (ordinary churn)') } else { '' }))
    if ($hits.Count -gt 0) {
        if ($Check -eq 'TempAds') {
            foreach ($h in @($hits | Select-Object -First $script:MaxListed)) { [void]$out.Add(('[WARNING] Alternate data stream (T1564.004): ' + (ConvertTo-PrintablePath $h))) }
        } else {
            [void]$out.Add($(if ($Check -eq 'TempHtml') { '[WARNING] Large HTML/HTA files in Temp:' } else { '[WARNING] Recent Outlook .msg/.oft artefacts (review for CVE-2023-23397 NTLM relay):' }))
            foreach ($h in @($hits | Select-Object -First $script:MaxListed)) { [void]$out.Add(('    ' + (ConvertTo-PrintablePath $h))) }
        }
        if ($hits.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO] ' + ($hits.Count - $script:MaxListed) + ' more not listed (' + $hits.Count + ' in all).')) }
        # A hit does not make the walk complete: the incompleteness is its own
        # raised line and row, or one benign hit would hide that most of the
        # tree was never examined.
        if ($partial.Count -gt 0) { [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed in full -- ' + ($partial.ToArray() -join '; ') + ', so there may be more than is listed (' + $c.Tech + ').')) }
        [void]$out.Add(('[INFO] ' + $scope + '.'))
        if ($linkLine) { [void]$out.Add($linkLine) }
        return @{ Lines = @($out.ToArray()); Hit = $true; Gap = ($partial.Count -gt 0); Deferred = 0 }
    }
    if ($partial.Count -gt 0) {
        [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed in full -- ' + ($partial.ToArray() -join '; ') + ', so ' + $c.Miss + ' (' + $c.Tech + ').'))
        [void]$out.Add(('[INFO] Nothing was found in what could be read: ' + $scope + '.'))
        if ($linkLine) { [void]$out.Add($linkLine) }
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0 }
    }
    [void]$out.Add($c.Ok)
    [void]$out.Add(('[INFO] ' + $scope + '.'))
    if ($linkLine) { [void]$out.Add($linkLine) }
    return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0 }
}

function Test-Denied {
    # Access denied anywhere in the exception chain.
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.UnauthorizedAccessException]) { return $true }
        if ($x -is [System.Security.SecurityException]) { return $true }
        if ($x.HResult -eq -2147024891) { return $true }
        # Get-Item -Stream reports a file it may not open as a bare
        # Win32Exception: the Win32 code is the only place 'denied' is said.
        if ($x -is [System.ComponentModel.Win32Exception] -and $x.NativeErrorCode -eq 5) { return $true }
        $x = $x.InnerException
    }
    return $false
}
function Test-StillListed {
    # A name the parent folder still lists did not vanish: Windows refused to
    # open it by that name (a trailing dot or space made through the \\?\
    # form is the classic way to hide a folder). Unknown counts as listed.
    param([string]$Path)
    try {
        $parent = [IO.Path]::GetDirectoryName($Path); $leaf = [IO.Path]::GetFileName($Path)
        if (-not $parent -or -not $leaf) { return $true }
        foreach ($n in [IO.Directory]::GetFileSystemEntries($parent)) { if ([IO.Path]::GetFileName($n) -eq $leaf -or $n -eq $Path) { return $true } }
        return $false
    } catch { return $true }
}
function Test-TooLong {
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.IO.PathTooLongException]) { return $true }
        $x = $x.InnerException
    }
    return $false
}
function Test-Vanished {
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.Management.Automation.ItemNotFoundException] -or $x -is [System.IO.FileNotFoundException] -or $x -is [System.IO.DirectoryNotFoundException]) { return $true }
        # 2 = file not found, 3 = path not found.
        if ($x -is [System.ComponentModel.Win32Exception] -and ($x.NativeErrorCode -eq 2 -or $x.NativeErrorCode -eq 3)) { return $true }
        $x = $x.InnerException
    }
    return $false
}

# Live. Walks $RootPath one folder at a time so each failure is caught and
# named, never silenced; $Select decides, per file, whether it is a hit and
# returns the text to list (or $null). Returns the $Scan shape above.
function Invoke-Walk {
    param([string]$RootPath, [scriptblock]$Select, [int]$Budget)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $scan = @{ RootState = 'ok'; RootDenied = $false; RootError = ''; RootPath = $RootPath; Hits = (New-Object System.Collections.ArrayList); Examined = 0; Unreadable = (New-Object System.Collections.ArrayList); Vanished = 0; OutOfTime = $false; Seconds = 0; Budget = $Budget; Links = (New-Object System.Collections.ArrayList) }
    # No path at all is not 'the folder is absent': nothing was looked at.
    if (-not $RootPath) { $scan.RootState = 'unreadable'; $scan.RootError = 'Windows did not say where this folder is'; return $scan }
    try { $rootItem = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop }
    catch {
        if (Test-Vanished $_) { $scan.RootState = 'missing' } else { $scan.RootState = 'unreadable'; $scan.RootDenied = (Test-Denied $_); $scan.RootError = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
        return $scan
    }
    $stack = New-Object System.Collections.Stack
    $stack.Push($rootItem.FullName)
    $first = $true
    while ($stack.Count -gt 0) {
        if ($clock.Elapsed.TotalSeconds -ge $Budget) { $scan.OutOfTime = $true; break }
        $dir = [string]$stack.Pop()
        $items = $null
        $err = $null
        try { $items = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) } catch { $err = $_ }
        if ($err -and (Test-TooLong $err) -and -not $dir.StartsWith('\\')) {
            # A deep tree (installers and package caches make them in TEMP) is
            # not unreadable, only long: ask again in the form Windows takes
            # at any length.
            $err = $null
            try { $items = @(Get-ChildItem -LiteralPath ('\\?\' + $dir) -Force -ErrorAction Stop) } catch { $err = $_ }
        }
        if ($err) {
            if ($first) { $scan.RootState = 'unreadable'; $scan.RootDenied = (Test-Denied $err); $scan.RootError = ($err.Exception.GetType().Name + ': ' + $err.Exception.Message); break }
            if ((Test-Vanished $err) -and -not (Test-StillListed $dir)) { $scan.Vanished++ } else { [void]$scan.Unreadable.Add(@{ Path = $dir; Denied = (Test-Denied $err) }) }
            continue
        }
        $first = $false
        foreach ($it in $items) {
            if ($it.PSIsContainer) {
                # Not through links: a junction can loop, or lead out of the
                # folder to a whole drive. Counted and named, never silent.
                # Only LINKS: a cloud-synced folder is a reparse point too.
                $lt = ''; try { $lt = [string]$it.LinkType } catch {}
                if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') { [void]$scan.Links.Add($it.FullName) } else { $stack.Push($it.FullName) }
                continue
            }
            if ($clock.Elapsed.TotalSeconds -ge $Budget) { $scan.OutOfTime = $true; break }
            $scan.Examined++
            try {
                $h = & $Select $it
                if ($h) { [void]$scan.Hits.Add([string]$h) }
            } catch {
                if ((Test-Vanished $_) -and -not (Test-StillListed $it.FullName)) { $scan.Vanished++ } else { [void]$scan.Unreadable.Add(@{ Path = $it.FullName; Denied = (Test-Denied $_) }) }
            }
        }
        if ($scan.OutOfTime) { break }
    }
    $scan.Seconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)
    return $scan
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function S { param([hashtable]$Over = @{})
        $b = @{ RootState = 'ok'; RootDenied = $false; RootError = ''; RootPath = 'C:\Users\alice\AppData\Local\Temp'; Hits = @(); Examined = 120; Unreadable = @(); Vanished = 0; OutOfTime = $false; Seconds = 0.4; Budget = 60; Links = @() }
        foreach ($k in $Over.Keys) { $b[$k] = $Over[$k] }
        return $b
    }
    $w5 = New-Object System.Management.Automation.ErrorRecord((New-Object System.ComponentModel.Win32Exception(5)), 'x', 'NotSpecified', $null)
    $w2 = New-Object System.Management.Automation.ErrorRecord((New-Object System.ComponentModel.Win32Exception(2)), 'x', 'NotSpecified', $null)
    $w32 = New-Object System.Management.Automation.ErrorRecord((New-Object System.ComponentModel.Win32Exception(32)), 'x', 'NotSpecified', $null)
    T 'a stream read refused with Win32 error 5 is access denied (Get-Item -Stream says it no other way)' ((Test-Denied $w5) -and -not (Test-Vanished $w5)) ''
    T 'a file gone between the listing and the stream read (Win32 error 2) is churn, never an unreadable file' ((Test-Vanished $w2) -and -not (Test-Denied $w2)) ''
    T 'a sharing violation (Win32 error 32) is neither: it stays an unreadable file, and a gap' ((-not (Test-Denied $w32)) -and -not (Test-Vanished $w32)) ''
    $v = Get-WalkVerdict -Check 'TempHtml' -Scan (S @{ Links = @('C:\Users\alice\AppData\Local\Temp\x') }); $t = $v.Lines -join "`n"
    T 'a junction that was not followed is said and named beside the [OK], never silent' ($t -match '(?m)^\[INFO\] 1 link\(s\) to another folder .* NOT followed.*Temp\\x' -and -not $v.Gap) $t
    $v = Get-WalkVerdict -Check 'OutlookMsg' -Scan (Invoke-Walk -RootPath '' -Select { $null } -Budget 5); $t = $v.Lines -join "`n"
    T 'no path for the Outlook folder at all is a gap, never "No Outlook data folder"' ($v.Gap -and $t -notmatch '\[OK\]') $t
    T 'a right-to-left override in a file name cannot disguise it in the report' ((ConvertTo-PrintablePath ('a' + [char]0x202E + 'gpj.exe')) -eq 'a?gpj.exe') ''
    $long = 'C:\Users\alice\AppData\Local\Temp\' + (('d' * 40 + '\') * 7) + 'deep.html'; $p = ConvertTo-PrintablePath $long
    T 'a path too long to print whole keeps its drive AND its file name' ($long.Length -gt 300 -and $p.Length -le 260 -and $p.StartsWith('C:\Users\alice') -and $p.EndsWith('deep.html')) $p
    T 'a name its parent still lists did not vanish (unknown counts as listed, never as churn)' ((Test-StillListed $PSCommandPath) -and (Test-StillListed 'Z:\dz_no_such_parent\x') -and -not (Test-StillListed (Join-Path $PSScriptRoot 'dz_no_such_file_here.tmp'))) ''
    $den = @{ Path = 'C:\Users\alice\AppData\Local\Temp\locked'; Denied = $true }
    $io = @{ Path = 'C:\Users\alice\AppData\Local\Temp\broken'; Denied = $false }

    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S); $t = $v.Lines -join "`n"
    T 'ADS, a clean walk: the [OK] wording the bats always printed, plus how much was examined' ((-not ($v.Hit -or $v.Gap)) -and $v.Deferred -eq 0 -and $t -match '(?m)^\[OK\] No suspicious ADS in Temp\.$' -and $t -match '\[INFO\] 120 file\(s\) examined under C:\\Users\\alice\\AppData\\Local\\Temp in 0\.4 s\.') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Hits = @('C:\T\a.txt :: payload') }); $t = $v.Lines -join "`n"
    T 'ADS, one hit: the WARNING wording the bats always printed' ($v.Hit -and (-not $v.Gap) -and $t -match '(?m)^\[WARNING\] Alternate data stream \(T1564\.004\): C:\\T\\a\.txt :: payload$') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Unreadable = @($den, $io) }) -IsElevated $true; $t = $v.Lines -join "`n"
    T 'ADS, folders that could not be read and no hit: a raised gap that names them, never "[OK] No suspicious ADS"' ($v.Gap -and (-not $v.Hit) -and $t -match '(?m)^\[WARNING\] Alternate-data-stream check NOT performed in full -- 2 folder\(s\) or file\(s\) could not be read \(C:\\Users\\alice\\AppData\\Local\\Temp\\locked; ' -and $t -notmatch 'No suspicious ADS' -and $t -match 'Nothing was found in what could be read') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Unreadable = @($den) }) -IsElevated $false; $t = $v.Lines -join "`n"
    T 'ADS, standard-user token, every failure access denied: a RAISED gap -- this is the user''s own folder, the token does not explain a denial there' ($v.Gap -and $t -match '(?m)^\[WARNING\] Alternate-data-stream check NOT performed in full' -and $t -notmatch '\[OK\]' -and $t -notmatch 'DEFERRED') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Unreadable = @($den, $io) }) -IsElevated $false
    T 'ADS, standard-user token, one failure NOT access denied: a raised gap, the token does not explain it' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Unreadable = @($den) }) -IsElevated $true
    T 'ADS, administrator token, access denied: a raised gap, not a deferral' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Hits = @('C:\T\a.txt :: x'); Unreadable = @($den) }); $t = $v.Lines -join "`n"
    T 'ADS, a hit AND an unreadable folder: BOTH the finding and the gap -- one hit cannot hide an incomplete walk' ($v.Hit -and $v.Gap -and $t -match '(?m)^\[WARNING\] Alternate-data-stream check NOT performed in full -- 1 folder\(s\) or file\(s\) could not be read') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ OutOfTime = $true; Examined = 9000; Budget = 60 }) -IsElevated $false; $t = $v.Lines -join "`n"
    T 'the time budget ran out: a raised gap on any token (time is not the token), never [OK]' ($v.Gap -and $v.Deferred -eq 0 -and $t -match 'the 60s time budget ran out after 9000 file\(s\)' -and $t -notmatch '\[OK\]') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ RootState = 'missing' }); $t = $v.Lines -join "`n"
    T 'TEMP itself not found: a raised gap, not the old unraised [SKIPPED]' ($v.Gap -and $t -match '(?m)^\[WARNING\] Alternate-data-stream check NOT performed -- the folder .* was not found' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ RootState = 'unreadable'; RootDenied = $true; RootError = 'UnauthorizedAccessException: denied' }) -IsElevated $false
    T 'TEMP unreadable on a standard-user token (denied): a raised gap, never a deferral' ($v.Gap -and ($v.Lines -join ' ') -notmatch 'DEFERRED') ($v.Lines -join ' | ')
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ RootState = 'unreadable'; RootDenied = $false; RootError = 'IOException: device not ready' }) -IsElevated $false
    T 'TEMP unreadable for a reason that is not access denied: a raised gap' ($v.Gap -and ($v.Lines -join "`n") -match 'device not ready') ($v.Lines -join ' | ')
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Vanished = 3 })
    T 'files that vanished mid-walk are churn: still [OK], counted in the INFO line' ((-not $v.Gap) -and ($v.Lines -join "`n") -match '3 vanished while being read \(ordinary churn\)') ($v.Lines -join ' | ')
    $many = @(1..30 | ForEach-Object { "C:\T\f$_.txt :: s" })
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Hits = $many }); $t = $v.Lines -join "`n"
    T 'thirty hits: twenty-five listed, the rest counted' (@($v.Lines | Where-Object { $_ -match '^\[WARNING\] Alternate data stream' }).Count -eq 25 -and $t -match '\[INFO\] 5 more not listed \(30 in all\)') $t
    $v = Get-WalkVerdict -Check 'TempAds' -Scan (S @{ Hits = @(('C:\T\a' + [char]10 + '[OK] No suspicious ADS in Temp.txt :: s')) })
    T 'a line break in a file name cannot forge an [OK] line' (@($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')

    $v = Get-WalkVerdict -Check 'TempHtml' -Scan (S); $t = $v.Lines -join "`n"
    T 'HTML, a clean walk: the [OK] wording the bats always printed' ($t -match '(?m)^\[OK\] No oversized HTML/HTA files in user TEMP\.$') $t
    $v = Get-WalkVerdict -Check 'TempHtml' -Scan (S @{ Hits = @('C:\T\big.html  312.5 KB  2026-11-01 10:00') }); $t = $v.Lines -join "`n"
    T 'HTML, one hit: the WARNING header the bats always printed, the file listed beneath it untagged' ($v.Hit -and $t -match '(?m)^\[WARNING\] Large HTML/HTA files in Temp:$' -and $t -match '(?m)^    C:\\T\\big\.html  312\.5 KB' -and @($v.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1) $t
    $v = Get-WalkVerdict -Check 'TempHtml' -Scan (S @{ Unreadable = @($io) })
    T 'HTML, an unreadable folder and no hit: a raised gap, never "[OK] No oversized"' ($v.Gap -and ($v.Lines -join "`n") -notmatch 'No oversized' -and ($v.Lines -join "`n") -match 'Oversized HTML/HTA check NOT performed in full') ($v.Lines -join ' | ')

    $v = Get-WalkVerdict -Check 'OutlookMsg' -Scan (S @{ RootState = 'missing'; RootPath = 'C:\Users\alice\AppData\Local\Microsoft\Outlook' }); $t = $v.Lines -join "`n"
    T 'Outlook, no data folder: [OK] that SAYS the folder does not exist -- an answer, not a guess' ((-not $v.Gap) -and $v.Deferred -eq 0 -and $t -match '(?m)^\[OK\] No Outlook data folder for this user \(C:\\Users\\alice\\AppData\\Local\\Microsoft\\Outlook does not exist\)') $t
    $v = Get-WalkVerdict -Check 'OutlookMsg' -Scan (S); $t = $v.Lines -join "`n"
    T 'Outlook, a clean walk: [OK], and no "may be absent" hedge -- it looked' ($t -match '(?m)^\[OK\] No recent Outlook \.msg/\.oft artefacts\.$' -and $t -notmatch 'may be absent') $t
    $v = Get-WalkVerdict -Check 'OutlookMsg' -Scan (S @{ Hits = @('C:\O\x.msg  2026-11-09 08:00') }); $t = $v.Lines -join "`n"
    T 'Outlook, one hit: the WARNING header the bats always printed' ($v.Hit -and $t -match '(?m)^\[WARNING\] Recent Outlook \.msg/\.oft artefacts \(review for CVE-2023-23397 NTLM relay\):$') $t
    $v = Get-WalkVerdict -Check 'OutlookMsg' -Scan (S @{ RootState = 'unreadable'; RootError = 'IOException: x' })
    T 'Outlook, the folder exists but could not be read: a raised gap, never the old [OK]' ($v.Gap -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails file_walk_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] file_walk_check self-test: a hit keeps its wording; folders or files that could not be read, or a walk that ran out of time, are a raised gap (on either token: these are the user''s own folders); a missing Outlook folder is said; and a clean walk says how much it examined.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if (-not $Check) { 'file_walk_check: -Check is required (TempAds, TempHtml or OutlookMsg).'; exit 1 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$rootPath = $Root
if (-not $rootPath) {
    if ($Check -eq 'OutlookMsg') {
        $lad = [Environment]::GetFolderPath('LocalApplicationData')
        if ($lad) { $rootPath = Join-Path $lad 'Microsoft\Outlook' }
    } else { $rootPath = $env:TEMP }
}
$select = $null
if ($Check -eq 'TempAds') {
    $select = {
        param($f)
        $s = @(Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' })
        if ($s.Count -gt 0) { return ($f.FullName + ' :: ' + (@($s | ForEach-Object { [string]$_.Stream }) -join ', ')) }
        return $null
    }
} elseif ($Check -eq 'TempHtml') {
    $select = {
        param($f)
        if (@('.html', '.htm', '.hta') -contains ([string]$f.Extension).ToLowerInvariant() -and $f.Length -gt $script:HtmlBytes) {
            return ($f.FullName + '  ' + [math]::Round($f.Length / 1024, 1).ToString([Globalization.CultureInfo]::InvariantCulture) + ' KB  ' + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture))
        }
        return $null
    }
} else {
    $cut = (Get-Date).AddDays(-$script:MsgDays)
    $select = {
        param($f)
        if (@('.msg', '.oft') -contains ([string]$f.Extension).ToLowerInvariant() -and $f.LastWriteTime -gt $cut) {
            return ($f.FullName + '  ' + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture))
        }
        return $null
    }
}
if ($BudgetSeconds -lt 0) { $BudgetSeconds = [int]$script:Checks[$Check].Budget }
$v = $null
try { $v = Get-WalkVerdict -Check $Check -Scan (Invoke-Walk -RootPath $rootPath -Select $select -Budget $BudgetSeconds) -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or @($v.Lines).Count -eq 0) {
    # No verdict is never a verdict: say so and raise it as this check's gap.
    ('[WARNING] ' + $script:Checks[$Check].What + ' NOT performed -- the walk failed before it produced a verdict (' + $script:Checks[$Check].Tech + ').')
    $v = @{ Lines = @(); Hit = $false; Gap = $true; Deferred = 0 }
}
foreach ($l in $v.Lines) { $l }
# The bat raises a row when this is absent: a helper that never got this far
# printed no verdict, and no marker must not read as nothing found.
Write-Marker -Name (@{ TempAds = 'ads'; TempHtml = 'htmltemp'; OutlookMsg = 'outlookmsg' }[$Check] + '_done') -Sev 'done'
# Marker names are written out, not built: lint_unraised_findings reads them.
if ($Check -eq 'TempAds') {
    if ($v.Hit) { Write-Marker -Name 'ads_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'ads_gap' -Sev 'WARNING' }
} elseif ($Check -eq 'TempHtml') {
    if ($v.Hit) { Write-Marker -Name 'htmltemp_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'htmltemp_gap' -Sev 'WARNING' }
} else {
    if ($v.Hit) { Write-Marker -Name 'outlookmsg_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'outlookmsg_gap' -Sev 'WARNING' }
}
exit 0
