# bits_history.ps1 -- what BITS RECORDED about transfers that are already over
# (T1197, and T1048 when a record resolves an upload). Section 5.
#
# WHY. Section 5's live check reads Get-BitsTransfer, which lists jobs that are
# still queued. A job that has completed or been cancelled is gone from it, so
# an exfiltration that finished is invisible there: the audit could see an
# attempt in progress and nothing whatever about one that succeeded. Windows
# keeps records in Microsoft-Windows-Bits-Client/Operational, and nothing in
# this audit read that channel before now.
#
# THE SCHEMA COMES FROM THE MACHINE, NOT FROM A WRITE-UP. Every third-party
# source disagrees about these events: Event 59 is described as the job being
# created, started and resumed; the requesting process is said to appear in
# Event 3 rather than 59; whether the URL is carried at all is contested. There
# is no Microsoft schema page for them. So this check hard-codes no claim about
# any event's meaning. It reads each record's own data items by NAME out of the
# record XML, falls back to the provider's own manifest template for that event
# id (ProviderMetadata.Events, which .NET documents and 5.1 therefore exposes),
# and decides what each value IS from its SHAPE: a value starting http:// or
# https:// is the remote, a drive-rooted or UNC value is a local path, and
# upload / uploadreply / download is the direction. The field name the machine
# gave each value is printed beside it, so the reader -- and the next change to
# this file -- sees the schema this machine actually has rather than one someone
# wrote down.
#
# WHAT IS GRADED is only what resolved, and only where a judgement is honest:
#   - a transfer whose remote host is a bare IP address with no name behind it
#     (WARNING; a private LAN address is context, as in the live check -- the
#     rule is the SHARED Get-RemoteHostClass below, pinned identical to the
#     copy in persistence_extra.ps1 so the live and historical checks cannot
#     disagree about the same URL);
#   - a local path written into an autostart folder (CRITICAL: nothing
#     legitimate streams a file straight into Startup);
#   - a job created by a program running from a staging folder (WARNING).
#     \Temp\ counts HERE, though it deliberately does not for a download's
#     destination: writing into the temp folder is what a downloader does, but
#     a program RUNNING from there and driving BITS is a different claim;
#   - a recorded UPLOAD, which gets its own T1048 row -- a file that already
#     left. Whether this channel records the direction at all is measured by
#     CI rather than assumed; when it does not, that is said, not implied.
#
# NOTHING RECORDED IS NOT AN ALL-CLEAR. If the channel is disabled or absent,
# nothing is being written and an empty log means nothing: [SKIPPED], raising
# nothing. If records were read but none of their fields could be named, the
# transfers were NOT graded and that is a declared gap, never a clean pass.
# The all-clear names the span it covers, because BITS logs roll over and an
# absence older than the oldest record proves nothing.
#
# MARKERS: dz_bitshist.txt (highest severity of the recorded-transfer findings),
# dz_bitshist_up.txt (a recorded upload: its own T1048 row),
# dz_bitshist_gap.txt (the channel or the schema could not be read by an
# administrator; its own ledger row), dz_bitshist_deferred.txt (a count a
# standard-user token could not perform, added to DEFERRED_COUNT, never a
# ledger row).
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    [string]$Channel = 'Microsoft-Windows-Bits-Client/Operational',
    [string]$Provider = 'Microsoft-Windows-Bits-Client',
    [int]$MaxRecords = 5000,
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

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Format-When {
    param($t)
    if ($null -eq $t) { return 'an unknown time' }
    return (([datetime]$t).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
}

# WHO IS AT THE OTHER END, as one judgement in one shape. This has more
# subtlety than it looks -- IPv4 and IPv6 literals, the private ranges, and the
# boundary at 172.31 where the private block ends -- and a second reader of the
# same channel's history now needs the identical answer. It is therefore copied
# byte-identical into tools\bits_history.ps1 and pinned by
# tools\lint_shared_copies.ps1, so the live check and the history check cannot
# drift into disagreeing about the same URL.
function Get-RemoteHostClass {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return 'unknown' }
    $u = ([string]$Url).Trim()
    if ($u -notmatch '^\s*https?://((\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:.]+\])([:/]|$)') { return 'name' }
    if ($u -match '^\s*https?://(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[(::1\]|[fF][eE]80:|[fF][cCdD][0-9A-Fa-f]{2}:))') { return 'private-ip' }
    return 'public-ip'
}

# PURE: what each of a record's values IS, decided by shape rather than by a
# field name this file was told to expect.
#
# The names come from the machine (the record's own <Data Name=...>, or the
# provider manifest's template for that event id), so they are reported, not
# trusted: a provider is free to call its URL field anything, and a localized
# or future build may. A value's shape, on the other hand, is not a matter of
# opinion -- http:// is a remote, C:\ or \\server\ is a local path, and
# upload / download is a direction. Returns the roles plus the field NAME the
# machine used for each, which is the fact a later change to this file needs.
function Get-BitsFieldRoles {
    param($Fields)
    $r = @{ Url = ''; UrlField = ''; LocalPath = ''; LocalField = ''; Direction = ''
            DirectionField = ''; ProcessPath = ''; ProcessField = ''; JobTitle = ''
            JobField = ''; Resolved = 0 }
    if ($null -eq $Fields) { return $r }
    foreach ($k in @($Fields.Keys)) {
        $name = [string]$k
        $val  = ([string]$Fields[$k]).Trim()
        if (-not $val) { continue }
        if (-not $r.Url -and $val -match '^\s*https?://\S') {
            $r.Url = $val; $r.UrlField = $name; $r.Resolved++
            continue
        }
        if ($val -match '^(?i)(upload|uploadreply|upload-reply|download)$') {
            if (-not $r.Direction) { $r.Direction = $val.ToLower(); $r.DirectionField = $name; $r.Resolved++ }
            continue
        }
        if ($val -match '^([A-Za-z]:\\|\\\\[^\\]|\\\\\?\\)') {
            # A path. Which path it is depends on what the machine called it:
            # a field whose name speaks of the process is the program that
            # drove the transfer, anything else is the file being moved. The
            # name is only a tiebreaker between two paths -- never what decides
            # that a value is a path at all.
            if ($name -match '(?i)process|image|client' -and -not $r.ProcessPath) {
                $r.ProcessPath = $val; $r.ProcessField = $name; $r.Resolved++
            } elseif (-not $r.LocalPath) {
                $r.LocalPath = $val; $r.LocalField = $name; $r.Resolved++
            }
            continue
        }
        if ($name -match '(?i)job|title|name' -and -not $r.JobTitle -and $val.Length -le 160) {
            $r.JobTitle = $val; $r.JobField = $name; $r.Resolved++
        }
    }
    return $r
}

# PURE: is this the program that drove the transfer, running from somewhere a
# program has no business running from? \Users\Public\ is spelled with its
# parent on purpose: a bare \\Public\\ once matched any directory named public
# and reported Adobe's node addon as a staging path on a clean machine.
function Get-StagingProcessReason {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = ([string]$Path).Trim()
    if ($p -match '(?i)\\Temp\\')          { return 'it runs from a temporary folder' }
    if ($p -match '(?i)\\Downloads\\')     { return 'it runs from the downloads folder' }
    if ($p -match '(?i)\\Users\\Public\\') { return 'it runs from the shared Public folder' }
    if ($p -match '(?i)\$Recycle')         { return 'it runs from the recycle bin' }
    if ($p -match '(?i)\\AppData\\Local\\Temp\\') { return 'it runs from a temporary folder' }
    return ''
}

# PURE: the records, graded.
#   Records        @( @{ Time; Id; Fields = @{ <machine's field name> = value } } )
#   Total          how many records were read in all
#   Oldest/Newest  the span the log covers, or $null
#   ReadError      the channel could not be read ('' when it was)
#   SchemaError    the provider manifest could not be read ('' when it was)
#   ChannelState   enabled | disabled | absent | unknown
#   Unreadable     records that could not be parsed at all
#   Truncated      the read stopped at the cap
function Get-BitsHistoryReport {
    param(
        $Records,
        [long]$Total = 0,
        $Oldest = $null,
        $Newest = $null,
        [string]$ReadError = '',
        [string]$SchemaError = '',
        [string]$ChannelState = 'enabled',
        [bool]$IsElevated = $true,
        [long]$Unreadable = 0,
        [bool]$Truncated = $false
    )
    $out = New-Object System.Collections.ArrayList
    $sev = 'OK'; $upSev = 'OK'; $gapSev = 'OK'; $deferred = 0; $hits = 0

    # Nothing is being recorded, so nothing recorded means nothing. Raising
    # from this would be inventing a finding; clearing from it would be the
    # all-clear-by-omission this repo keeps paying for.
    if ($ChannelState -eq 'disabled' -or $ChannelState -eq 'absent') {
        $why = 'the Bits-Client operational log is turned off on this machine'
        if ($ChannelState -eq 'absent') { $why = 'this machine has no Bits-Client operational log' }
        [void]$out.Add('[SKIPPED] What BITS recorded about finished transfers was NOT checked -- ' + $why + ', so nothing is written there and an empty log means nothing. Section 5 still grades the jobs that are queued now.')
        return @{ Lines = @($out.ToArray()); Sev = 'OK'; UpSev = 'OK'; GapSev = 'OK'; Deferred = 0; Hits = 0 }
    }

    # A read that failed part-way still grades what it read: returning here
    # would throw away the records already in hand, which is the defect the
    # companion check was fixed for.
    if ($ReadError) {
        if ($IsElevated) {
            [void]$out.Add('[WARNING] What BITS recorded about finished transfers was NOT checked, or only partly -- its operational log could not be read (' + (ConvertTo-PrintableText $ReadError) + '). Anything found before it stopped is below.')
            $gapSev = 'WARNING'
        } else {
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] What BITS recorded about finished transfers: its operational log is not readable from a standard-user token (' + (ConvertTo-PrintableText $ReadError) + ') -- re-run as administrator.')
            $deferred = 1
        }
    }

    $recs = @($Records)
    # Field resolution, counted. A record whose values could not be named at
    # all was NOT graded, and saying so is the difference between "nothing was
    # found" and "nothing was looked at".
    $roles = @()
    $noFields = 0
    foreach ($rec in $recs) {
        $rr = Get-BitsFieldRoles -Fields $rec.Fields
        if ($rr.Resolved -eq 0) { $noFields++; continue }
        $rr['Time'] = $rec.Time
        $rr['Id'] = $rec.Id
        $roles += $rr
    }
    if ($noFields -gt 0 -and @($roles).Count -eq 0 -and $recs.Count -gt 0) {
        if ($IsElevated) {
            [void]$out.Add('[WARNING] ' + $noFields + ' BITS record(s) were read but none of their fields could be named, so what those transfers did was NOT graded -- not cleared. The provider schema was ' + $(if ($SchemaError) { 'unreadable (' + (ConvertTo-PrintableText $SchemaError) + ')' } else { 'readable, but named none of these values' }) + '.')
            $gapSev = 'WARNING'
        } else {
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] ' + $noFields + ' BITS record(s) were read but their fields could not be named from this token -- re-run as administrator.')
            $deferred = 1
        }
    } elseif ($noFields -gt 0) {
        [void]$out.Add('[WARNING] ' + $noFields + ' of ' + $recs.Count + ' BITS record(s) carried no value this check could identify and were NOT graded -- not cleared.')
        $gapSev = 'WARNING'
    }

    # ---- the judgements, each on a value the machine itself named ----------
    # Grouped by what was seen rather than per record: one updater can write
    # hundreds of records, and a finding per record would bury the report.
    $byHost = @{}
    $autostart = @{}
    $byProc = @{}
    $uploads = @{}
    foreach ($rr in $roles) {
        if ($rr.Url) {
            $cls = Get-RemoteHostClass -Url $rr.Url
            if ($cls -eq 'public-ip') {
                $k = ([string]$rr.Url)
                if (-not $byHost.ContainsKey($k)) { $byHost[$k] = @{ Hits = 0; Newest = $null; Field = $rr.UrlField } }
                $byHost[$k]['Hits']++
                if ($null -eq $byHost[$k]['Newest'] -or ($null -ne $rr.Time -and [datetime]$rr.Time -gt [datetime]$byHost[$k]['Newest'])) { $byHost[$k]['Newest'] = $rr.Time }
            }
        }
        if ($rr.LocalPath -and $rr.LocalPath -match '(?i)\\Start Menu\\Programs\\Startup\\') {
            $k = ([string]$rr.LocalPath)
            if (-not $autostart.ContainsKey($k)) { $autostart[$k] = @{ Hits = 0; Newest = $null; Url = $rr.Url } }
            $autostart[$k]['Hits']++
            if ($null -eq $autostart[$k]['Newest'] -or ($null -ne $rr.Time -and [datetime]$rr.Time -gt [datetime]$autostart[$k]['Newest'])) { $autostart[$k]['Newest'] = $rr.Time }
        }
        if ($rr.ProcessPath) {
            $rsn = Get-StagingProcessReason -Path $rr.ProcessPath
            if ($rsn) {
                $k = ([string]$rr.ProcessPath) + [string][char]0 + $rsn
                if (-not $byProc.ContainsKey($k)) { $byProc[$k] = @{ Hits = 0; Newest = $null; Path = $rr.ProcessPath; Reason = $rsn } }
                $byProc[$k]['Hits']++
                if ($null -eq $byProc[$k]['Newest'] -or ($null -ne $rr.Time -and [datetime]$rr.Time -gt [datetime]$byProc[$k]['Newest'])) { $byProc[$k]['Newest'] = $rr.Time }
            }
        }
        if ($rr.Direction -match '^(?i)(upload|uploadreply|upload-reply)$') {
            # A file that has ALREADY left, which is what the live check cannot
            # see. Keyed on the pair, with NUL as the separator: no field can
            # contain it, where a bar can.
            $k = ([string]$rr.LocalPath) + [string][char]0 + ([string]$rr.Url)
            if (-not $uploads.ContainsKey($k)) { $uploads[$k] = @{ Hits = 0; Newest = $null; Local = $rr.LocalPath; Url = $rr.Url } }
            $uploads[$k]['Hits']++
            if ($null -eq $uploads[$k]['Newest'] -or ($null -ne $rr.Time -and [datetime]$rr.Time -gt [datetime]$uploads[$k]['Newest'])) { $uploads[$k]['Newest'] = $rr.Time }
        }
    }

    # Sort-Object has no -Stable on 5.1, so every ordering carries an explicit
    # tiebreaker and every list is capped.
    $cap = 10
    $shown = 0
    foreach ($k in @($uploads.Keys | Sort-Object @{ Expression = { -($uploads[$_]['Hits']) } }, @{ Expression = { $_ } })) {
        if ($shown -ge $cap) { break }
        $u = $uploads[$k]
        $what = 'a file'
        if ($u['Local']) { $what = (ConvertTo-PrintableText $u['Local']) }
        $where = 'a collector this record does not name'
        if ($u['Url']) { $where = (ConvertTo-PrintableText $u['Url']) }
        $s = 'WARNING'
        if ((Get-RemoteHostClass -Url $u['Url']) -eq 'public-ip') { $s = 'CRITICAL' }
        [void]$out.Add('[' + $s + '] BITS recorded an UPLOAD that has already happened: ' + $what + ' was sent to ' + $where + ' (' + $u['Hits'] + ' record(s), most recently ' + (Format-When $u['Newest']) + ') (T1048). This transfer is over -- the job is gone from the queue Section 5 reads, so this record is the only trace.')
        if ($s -eq 'CRITICAL') { $upSev = 'CRITICAL' } elseif ($upSev -ne 'CRITICAL') { $upSev = 'WARNING' }
        $hits++
        $shown++
    }
    if (@($uploads.Keys).Count -gt $shown) {
        [void]$out.Add('    ...and ' + (@($uploads.Keys).Count - $shown) + ' more recorded upload(s) of the same shape.')
    }

    $shown = 0
    foreach ($k in @($autostart.Keys | Sort-Object @{ Expression = { -($autostart[$_]['Hits']) } }, @{ Expression = { $_ } })) {
        if ($shown -ge $cap) { break }
        $a = $autostart[$k]
        $from = ''
        if ($a['Url']) { $from = ' from ' + (ConvertTo-PrintableText $a['Url']) }
        [void]$out.Add('[CRITICAL] BITS wrote a file straight into an autostart folder: ' + (ConvertTo-PrintableText $k) + $from + ' (' + $a['Hits'] + ' record(s), most recently ' + (Format-When $a['Newest']) + ') (T1197). Nothing legitimate streams a file into Startup; whatever was written runs at the next sign-in.')
        $sev = 'CRITICAL'
        $hits++
        $shown++
    }
    if (@($autostart.Keys).Count -gt $shown) {
        [void]$out.Add('    ...and ' + (@($autostart.Keys).Count - $shown) + ' more autostart write(s) of the same shape.')
    }

    $shown = 0
    foreach ($k in @($byHost.Keys | Sort-Object @{ Expression = { -($byHost[$_]['Hits']) } }, @{ Expression = { $_ } })) {
        if ($shown -ge $cap) { break }
        $b = $byHost[$k]
        [void]$out.Add('[WARNING] BITS transferred to or from a bare IP address with no name behind it: ' + (ConvertTo-PrintableText $k) + ' (' + $b['Hits'] + ' record(s), most recently ' + (Format-When $b['Newest']) + ') (T1197). Windows Update, the browsers'' updaters and an on-premises cache all use names; an address with none has no routine cause.')
        if ($sev -ne 'CRITICAL') { $sev = 'WARNING' }
        $hits++
        $shown++
    }
    if (@($byHost.Keys).Count -gt $shown) {
        [void]$out.Add('    ...and ' + (@($byHost.Keys).Count - $shown) + ' more bare-address transfer(s) of the same shape.')
    }

    $shown = 0
    foreach ($k in @($byProc.Keys | Sort-Object @{ Expression = { -($byProc[$_]['Hits']) } }, @{ Expression = { $_ } })) {
        if ($shown -ge $cap) { break }
        $pr = $byProc[$k]
        [void]$out.Add('[WARNING] A BITS transfer was driven by a program running from a staging folder: ' + (ConvertTo-PrintableText $pr['Path']) + ' -- ' + $pr['Reason'] + ' (' + $pr['Hits'] + ' record(s), most recently ' + (Format-When $pr['Newest']) + ') (T1197). An updater runs from Program Files; a program in one of these folders using a Windows service to move files is the T1197 shape.')
        if ($sev -ne 'CRITICAL') { $sev = 'WARNING' }
        $hits++
        $shown++
    }
    if (@($byProc.Keys).Count -gt $shown) {
        [void]$out.Add('    ...and ' + (@($byProc.Keys).Count - $shown) + ' more staging-folder transfer(s) of the same shape.')
    }

    # Context the reader needs to judge an absence, each separate from the
    # all-clear so none of them can be mistaken for one.
    if ($Truncated) {
        [void]$out.Add('[INFO] Only the newest ' + $Total + ' BITS record(s) were read; older ones were not.')
    }
    if ($Unreadable -gt 0) {
        [void]$out.Add('[WARNING] ' + $Unreadable + ' BITS record(s) could not be read and were skipped -- NOT graded, not cleared.')
        $gapSev = 'WARNING'
    }
    if ($SchemaError -and @($roles).Count -gt 0) {
        [void]$out.Add('[INFO] The Bits-Client provider schema could not be read (' + (ConvertTo-PrintableText $SchemaError) + '), so field names came from the records themselves.')
    }

    # The all-clear, withheld on any uncertainty, and naming its own coverage:
    # these logs roll over, so an absence older than the oldest record proves
    # nothing and the line must not imply otherwise.
    if ($sev -eq 'OK' -and $upSev -eq 'OK' -and $gapSev -eq 'OK' -and $deferred -eq 0 -and -not $Truncated) {
        $span = 'the records read'
        if ($null -ne $Oldest -and $null -ne $Newest) { $span = 'from ' + (Format-When $Oldest) + ' to ' + (Format-When $Newest) }
        elseif ($null -ne $Oldest) { $span = 'back to ' + (Format-When $Oldest) }
        if ($Total -le 0) {
            [void]$out.Add('[OK] The Bits-Client log is enabled and holds no transfer records, so no finished transfer is recorded on this machine. An empty log covers nothing older than itself.')
        } else {
            $named = ''
            if (@($roles).Count -gt 0) {
                $f = @($roles)[0]
                $bits = @()
                if ($f.UrlField)       { $bits += ("remote='" + (ConvertTo-PrintableText $f.UrlField) + "'") }
                if ($f.LocalField)     { $bits += ("file='" + (ConvertTo-PrintableText $f.LocalField) + "'") }
                if ($f.DirectionField) { $bits += ("direction='" + (ConvertTo-PrintableText $f.DirectionField) + "'") }
                if ($f.ProcessField)   { $bits += ("program='" + (ConvertTo-PrintableText $f.ProcessField) + "'") }
                if (@($bits).Count -gt 0) { $named = ' This machine names those fields ' + ([string]::Join(', ', $bits)) + '.' }
            }
            [void]$out.Add('[OK] ' + $Total + ' BITS transfer record(s) read, ' + $span + ': none went to a bare address, none wrote into an autostart folder, and none was driven by a program running from a staging folder.' + $named)
            # NAME THE NEWEST ONE. A count and a span prove a number was
            # produced; they do not show the reader that their own machine's
            # records were read and understood. The newest resolved transfer
            # does, it is the line that makes an all-clear checkable by hand,
            # and it is what lets CI prove a REAL record was parsed rather than
            # only a synthetic one. [INFO], because it is context beside a
            # verdict and not a second finding.
            if (@($roles).Count -gt 0) {
                $nw = @($roles)[0]
                $what = @()
                if ($nw.Url)       { $what += (ConvertTo-PrintableText $nw.Url) }
                if ($nw.LocalPath) { $what += ('to ' + (ConvertTo-PrintableText $nw.LocalPath)) }
                if ($nw.Direction) { $what += ('(' + (ConvertTo-PrintableText $nw.Direction) + ')') }
                if (@($what).Count -gt 0) {
                    [void]$out.Add('[INFO] The newest transfer recorded is ' + ([string]::Join(' ', $what)) + ', at ' + (Format-When $nw.Time) + '.')
                }
            }
        }
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; UpSev = $upSev; GapSev = $gapSev
              Deferred = $deferred; Hits = $hits }
}

if ($SelfTest) {
    $script:fails = 0
    function T {
        param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $t0 = New-Object DateTime 2026, 10, 14, 11, 30, 0, ([DateTimeKind]::Utc)
    # A record as the live path builds one: the machine's own field names, with
    # whatever values it recorded. Nothing here touches an event log, so the
    # whole rule runs on Linux pwsh.
    function NewHistRec {
        param($fields, $t = $t0, [int]$id = 59)
        @{ Time = $t; Id = $id; Fields = $fields }
    }
    $j = { param($r) ($r.Lines -join ' | ') }

    # ---- the field roles are decided by SHAPE, so a provider that renames or
    # localizes its fields is still read correctly.
    $roles = Get-BitsFieldRoles -Fields @{ jobTitle = 'Edge Update'; url = 'http://dl.example.com/x.cab'; fileName = 'C:\Windows\Temp\x.cab' }
    T 'a URL is found by its scheme, whatever the field is called' `
      ($roles.Url -eq 'http://dl.example.com/x.cab' -and $roles.UrlField -eq 'url') "$($roles.Url) / $($roles.UrlField)"
    T 'a drive-rooted value is the local file' ($roles.LocalPath -eq 'C:\Windows\Temp\x.cab') $roles.LocalPath
    T 'and the job title comes along for the line' ($roles.JobTitle -eq 'Edge Update') $roles.JobTitle
    $roles = Get-BitsFieldRoles -Fields @{ 'Auftragsname' = 'Edge Update'; 'Adresse' = 'https://dl.example.com/y.cab' }
    T 'a localized field name still yields the remote, because the shape decides' `
      ($roles.Url -eq 'https://dl.example.com/y.cab' -and $roles.UrlField -eq 'Adresse') $roles.UrlField
    $roles = Get-BitsFieldRoles -Fields @{ processPath = 'C:\Windows\System32\svchost.exe'; fileName = 'C:\x\y.bin' }
    T 'two paths are told apart by the name the machine gave them' `
      ($roles.ProcessPath -eq 'C:\Windows\System32\svchost.exe' -and $roles.LocalPath -eq 'C:\x\y.bin') "$($roles.ProcessPath) / $($roles.LocalPath)"
    $roles = Get-BitsFieldRoles -Fields @{ transferType = 'Upload' }
    T 'a direction is recognised case-insensitively' ($roles.Direction -eq 'upload') $roles.Direction
    $roles = Get-BitsFieldRoles -Fields @{ bytesTotal = '512'; status = '0x80072ee2' }
    T 'a record with nothing identifiable resolves nothing, rather than guessing' ($roles.Resolved -eq 0) "Resolved=$($roles.Resolved)"
    $roles = Get-BitsFieldRoles -Fields $null
    T 'a null field set is handled' ($roles.Resolved -eq 0) ''
    $roles = Get-BitsFieldRoles -Fields @{ fileName = '\\?\C:\x\y.bin' }
    T 'an NT-prefixed path is still a path' ($roles.LocalPath -eq '\\?\C:\x\y.bin') $roles.LocalPath
    $roles = Get-BitsFieldRoles -Fields @{ fileName = '\\server\share\y.bin' }
    T 'a UNC path is still a path' ($roles.LocalPath -eq '\\server\share\y.bin') $roles.LocalPath

    # ---- the shared host rule, the same judgement the live check makes.
    T 'a bare public IPv4 host is public' ((Get-RemoteHostClass -Url 'http://93.184.216.34/x') -eq 'public-ip') ''
    T 'a bare IPv6 host is public too' ((Get-RemoteHostClass -Url 'http://[2001:db8::7]/x') -eq 'public-ip') ''
    T 'a LAN address is private' ((Get-RemoteHostClass -Url 'http://192.168.5.5/x') -eq 'private-ip') ''
    T 'a link-local IPv6 address is private' ((Get-RemoteHostClass -Url 'http://[fe80::1]/x') -eq 'private-ip') ''
    T 'a hostname is a name' ((Get-RemoteHostClass -Url 'http://dl.example.com/x') -eq 'name') ''
    T 'a host that merely begins with digits is a name' ((Get-RemoteHostClass -Url 'http://10.cdn.example.com/x') -eq 'name') ''

    # ---- the findings.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'http://93.184.216.34/payload.bin'; fileName = 'C:\Windows\Temp\p.bin' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a transfer to a bare public address is a WARNING naming it' `
      ($r.Sev -eq 'WARNING' -and (& $j $r) -match 'bare IP address with no name behind it: http://93\.184\.216\.34/payload\.bin') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'http://192.168.5.5/wsus.cab'; fileName = 'C:\Windows\Temp\p.bin' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a LAN address is not a finding -- an on-premises cache is the ordinary cause' `
      ($r.Sev -eq 'OK' -and (& $j $r) -match '^\[OK\]') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'https://dl.example.com/x.cab'; fileName = 'C:\Users\k\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a file written into Startup is CRITICAL' `
      ($r.Sev -eq 'CRITICAL' -and (& $j $r) -match 'straight into an autostart folder') (& $j $r)
    foreach ($p in @('C:\Users\k\AppData\Local\Temp\x.exe', 'C:\Users\k\Downloads\x.exe',
                     'C:\Users\Public\x.exe', 'C:\$Recycle.Bin\S-1-5-21\x.exe')) {
        $r = Get-BitsHistoryReport -Records @((NewHistRec @{ processPath = $p; url = 'https://dl.example.com/x.cab' })) -Total 1 -Oldest $t0 -Newest $t0
        T "a transfer driven from a staging folder is a WARNING: $p" `
          ($r.Sev -eq 'WARNING' -and (& $j $r) -match 'running from a staging folder') (& $j $r)
    }
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ processPath = 'C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'; url = 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/abc' })) -Total 1 -Oldest $t0 -Newest $t0
    T "the real Edge updater's own transfer, over plain HTTP by Microsoft's design, is not a finding" `
      ($r.Sev -eq 'OK' -and $r.UpSev -eq 'OK' -and (& $j $r) -match '^\[OK\]') (& $j $r)
    # A directory NAMED public is not C:\Users\Public: the burn this repo has
    # already paid for once, pinned here before it can happen again.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ processPath = 'C:\Program Files\Acme\node_modules\thing\public\binaries\helper.exe'; url = 'https://dl.example.com/x.cab' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a directory merely named public is not the shared Public folder' ($r.Sev -eq 'OK') (& $j $r)

    # ---- a recorded upload: the thing the live check cannot see.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ transferType = 'Upload'; fileName = 'C:\Users\k\Documents\tax.pdf'; url = 'https://collector.example.com/u' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a recorded upload raises its own T1048 row, saying the transfer is over' `
      ($r.UpSev -eq 'WARNING' -and $r.Sev -eq 'OK' -and (& $j $r) -match 'recorded an UPLOAD that has already happened' -and
       (& $j $r) -match 'T1048' -and (& $j $r) -match 'the only trace') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ transferType = 'upload'; fileName = 'C:\x\y.7z'; url = 'http://198.51.100.7/u' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a recorded upload to a bare public address is CRITICAL' ($r.UpSev -eq 'CRITICAL') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ transferType = 'Download'; fileName = 'C:\x\y.cab'; url = 'https://dl.example.com/y.cab' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a recorded download raises no upload row' ($r.UpSev -eq 'OK' -and $r.Sev -eq 'OK') (& $j $r)

    # ---- grouping, caps and ordering.
    $many = @()
    foreach ($i in 1..14) { $many += (NewHistRec @{ url = ('http://93.184.216.' + $i + '/x.bin') }) }
    $r = Get-BitsHistoryReport -Records $many -Total 14 -Oldest $t0 -Newest $t0
    T 'fourteen bare-address hosts are capped at ten with the remainder counted' `
      ((@($r.Lines) | Where-Object { $_ -match 'bare IP address' }).Count -eq 10 -and (& $j $r) -match '\.\.\.and 4 more bare-address transfer') (& $j $r)
    $same = @((NewHistRec @{ url = 'http://93.184.216.34/x' }), (NewHistRec @{ url = 'http://93.184.216.34/x' }))
    $r = Get-BitsHistoryReport -Records $same -Total 2 -Oldest $t0 -Newest $t0
    T 'the same host twice is one line with a count of two' `
      ((@($r.Lines) | Where-Object { $_ -match 'bare IP address' }).Count -eq 1 -and (& $j $r) -match '\(2 record\(s\)') (& $j $r)

    # ---- nothing recorded is not an all-clear.
    foreach ($st in @('disabled', 'absent')) {
        $r = Get-BitsHistoryReport -Records @() -ChannelState $st -Total 0
        T "a $st channel is SKIPPED, raising nothing" `
          ($r.Sev -eq 'OK' -and $r.GapSev -eq 'OK' -and (& $j $r) -match '^\[SKIPPED\]' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)
    }
    $r = Get-BitsHistoryReport -Records @() -Total 0 -ChannelState 'enabled'
    T 'an enabled but empty log says so, and says it covers nothing older than itself' `
      ($r.Sev -eq 'OK' -and (& $j $r) -match 'holds no transfer records' -and (& $j $r) -match 'covers nothing older') (& $j $r)

    # ---- the three-way unreadable contract.
    $r = Get-BitsHistoryReport -Records @() -Total 0 -ReadError 'Attempted to perform an unauthorized operation.' -IsElevated $true
    T 'an administrator who cannot read the log gets a raised gap' `
      ($r.GapSev -eq 'WARNING' -and $r.Sev -eq 'OK' -and (& $j $r) -match 'NOT checked, or only partly') (& $j $r)
    T 'and no all-clear beside it' ((& $j $r) -notmatch '\[OK\]') (& $j $r)
    $r = Get-BitsHistoryReport -Records @() -Total 0 -ReadError 'Attempted to perform an unauthorized operation.' -IsElevated $false
    T 'a standard-user token gets a declared DEFERRAL, never a row' `
      ($r.Deferred -eq 1 -and $r.GapSev -eq 'OK' -and $r.Sev -eq 'OK' -and (& $j $r) -match '^\[DEFERRED - ADMIN REQUIRED\]') (& $j $r)
    # A read that failed part-way still grades what it read.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'http://93.184.216.34/x' })) -Total 1 -ReadError 'The handle is invalid.' -IsElevated $true
    T 'a part-way read still reports the records it had' `
      ($r.GapSev -eq 'WARNING' -and $r.Sev -eq 'WARNING' -and (& $j $r) -match 'bare IP address') (& $j $r)

    # ---- records read but not nameable: NOT graded, not cleared.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ bytesTotal = '512' }), (NewHistRec @{ status = '0x1' })) -Total 2 -Oldest $t0 -Newest $t0 -SchemaError 'The specified provider was not found.'
    T 'records whose fields cannot be named are a declared gap, not an all-clear' `
      ($r.GapSev -eq 'WARNING' -and (& $j $r) -match 'none of their fields could be named' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'https://dl.example.com/x' }), (NewHistRec @{ status = '0x1' })) -Total 2 -Oldest $t0 -Newest $t0
    T 'a mix states how many were not graded, and withholds the all-clear' `
      ($r.GapSev -eq 'WARNING' -and (& $j $r) -match '1 of 2 BITS record\(s\) carried no value' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)

    # ---- truncation and unreadable records each withhold the all-clear.
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'https://dl.example.com/x' })) -Total 5000 -Truncated $true -Oldest $t0 -Newest $t0
    T 'a truncated read says so and prints no all-clear' `
      ((& $j $r) -match 'Only the newest 5000' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'https://dl.example.com/x' })) -Total 3 -Unreadable 2 -Oldest $t0 -Newest $t0
    T 'skipped records are a gap, and no all-clear' `
      ($r.GapSev -eq 'WARNING' -and (& $j $r) -match '2 BITS record\(s\) could not be read' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)

    # ---- the all-clear names the span and the schema it read.
    $t1 = $t0.AddDays(-9)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = 'https://dl.example.com/x.cab'; fileName = 'C:\Windows\Temp\x.cab'; transferType = 'Download'; processPath = 'C:\Program Files\X\u.exe' })) -Total 42 -Oldest $t1 -Newest $t0
    T 'the all-clear names its coverage span' `
      ((& $j $r) -match '42 BITS transfer record\(s\) read, from 2026-10-05 11:30:00Z to 2026-10-14 11:30:00Z') (& $j $r)
    T 'and names the fields this machine used, which is the schema a later change needs' `
      ((& $j $r) -match "remote='url'" -and (& $j $r) -match "file='fileName'" -and (& $j $r) -match "direction='transferType'" -and (& $j $r) -match "program='processPath'") (& $j $r)
    T 'and names the newest transfer, so an all-clear can be checked by hand' `
      ((& $j $r) -match '\[INFO\] The newest transfer recorded is https://dl\.example\.com/x\.cab to C:\\Windows\\Temp\\x\.cab \(download\), at 2026-10-14 11:30:00Z\.') (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ bytesTotal = '7' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'with nothing resolved there is no newest-transfer line to print' `
      ((& $j $r) -notmatch 'The newest transfer recorded is') (& $j $r)

    # ---- a value a job's creator chose cannot forge a line. The lesson from
    # the review of the live check, applied here from the start.
    $phys = {
        param($res)
        @((($res.Lines -join "`n") -split "`r?`n") | Where-Object { $_ -match '^\[(OK|INFO|WARNING|CRITICAL|SKIPPED|DEFERRED)' }).Count
    }
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ url = "http://93.184.216.34/x`r`n[OK] nothing to see here" })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a crafted URL cannot forge a line of its own' ((& $phys $r) -eq 1) (& $j $r)
    $r = Get-BitsHistoryReport -Records @((NewHistRec @{ transferType = 'Upload'; fileName = "C:\x\y`r`n[OK] fine.bin"; url = 'https://c.example.com/u' })) -Total 1 -Oldest $t0 -Newest $t0
    T 'a crafted file name cannot either' ((& $phys $r) -eq 1) (& $j $r)

    if ($script:fails) {
        Write-Output "[FAIL] $($script:fails) bits_history self-test expectation(s) unmet"
        exit 1
    }
    Write-Output '[OK] bits_history self-test: the schema comes from the machine and the roles from the values'' shapes, a bare address and an autostart write and a staging-folder program each raise, a recorded upload is its own T1048 row, and a channel that records nothing is SKIPPED rather than cleared.'
    exit 0
}

if (-not $MarkerDir) { $MarkerDir = $env:TEMP }
'--- [T1197/T1048] What BITS recorded about transfers that are already over (' + $Channel + ') ---'

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

# Is anything being recorded at all? A disabled or absent channel means an
# empty log proves nothing, and that has to be said rather than read as calm.
$channelState = 'unknown'
try {
    $log = Get-WinEvent -ListLog $Channel -EA Stop
    if ($log.IsEnabled) { $channelState = 'enabled' } else { $channelState = 'disabled' }
} catch {
    if ($_.Exception.Message -match 'There is not an event log|could not be found|does not exist') { $channelState = 'absent' }
}

# THE PROVIDER'S OWN DEFINITION OF ITS EVENTS, read from the machine being
# audited. ProviderMetadata.Events gives each event's template, which names its
# data items in order -- so when a record's XML carries no names (an
# uninstalled or partly registered manifest), the names still come from the
# provider rather than from a guess in this file.
$tmpl = @{}
$schemaError = ''
try {
    $pm = Get-WinEvent -ListProvider $Provider -EA Stop
    foreach ($em in @($pm.Events)) {
        try {
            if (-not $em.Template) { continue }
            $names = @()
            foreach ($d in @(([xml]$em.Template).template.data)) {
                if ($null -ne $d -and $d.name) { $names += [string]$d.name }
            }
            if (@($names).Count -gt 0 -and -not $tmpl.ContainsKey([int]$em.Id)) { $tmpl[[int]$em.Id] = $names }
        } catch { }
    }
} catch {
    $schemaError = $_.Exception.Message
}

$records = New-Object System.Collections.ArrayList
$total = 0L; $oldest = $null; $newest = $null; $unreadable = 0L; $truncated = $false
$readError = ''
if ($channelState -eq 'enabled' -or $channelState -eq 'unknown') {
    try {
        # Every record in the channel, newest first, with no message rendered:
        # the grading keys on the FIELDS each record resolves, not on an event
        # id whose meaning the sources disagree about, so nothing is filtered
        # out here on an assumption about which ids matter.
        $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
        $q.ReverseDirection = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
        try {
            while ($true) {
                $e = $reader.ReadEvent()
                if ($null -eq $e) { break }
                try {
                    $total++
                    $oldest = $e.TimeCreated
                    if ($null -eq $newest) { $newest = $e.TimeCreated }
                    $h = @{}
                    $idx = 0
                    foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) {
                        if ($null -eq $d) { $idx++; continue }
                        $val = ''
                        if ($d -is [string]) { $val = [string]$d } else { $val = [string]$d.'#text' }
                        $nm = ''
                        if ($d -isnot [string] -and $d.Name) { $nm = [string]$d.Name }
                        if (-not $nm) {
                            # Unnamed in the record: take the name the provider
                            # itself gives that position.
                            $t = $tmpl[[int]$e.Id]
                            if ($null -ne $t -and $idx -lt @($t).Count) { $nm = [string](@($t)[$idx]) }
                        }
                        if ($nm) { $h[$nm] = $val }
                        $idx++
                    }
                    [void]$records.Add(@{ Time = $e.TimeCreated; Id = $e.Id; Fields = $h })
                } catch {
                    # One unreadable record is skipped, never the whole read --
                    # and counted, so a record this cannot parse does not read
                    # as a log with nothing in it.
                    $unreadable++
                } finally { $e.Dispose() }
                if ($total -ge $MaxRecords) { $truncated = $true; break }
            }
        } finally { $reader.Dispose() }
    } catch {
        $readError = $_.Exception.Message
    }
}

$report = Get-BitsHistoryReport -Records @($records.ToArray()) -Total $total -Oldest $oldest -Newest $newest `
    -ReadError $readError -SchemaError $schemaError -ChannelState $channelState `
    -IsElevated ($Elevated -eq 1) -Unreadable $unreadable -Truncated $truncated
foreach ($l in $report.Lines) { $l }
Write-Marker -Name 'bitshist' -Sev $report.Sev
if ($report.UpSev -ne 'OK') { Write-Marker -Name 'bitshist_up' -Sev $report.UpSev }
if ($report.GapSev -ne 'OK') { Write-Marker -Name 'bitshist_gap' -Sev $report.GapSev }
if ($report.Deferred -gt 0) { Write-Marker -Name 'bitshist_deferred' -Sev ([string]$report.Deferred) }
