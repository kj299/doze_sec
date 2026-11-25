# system_listing.ps1 -- three listings the bats built from English Windows
# output, read here from objects and SIDs instead (group I2, 2026-11-25).
#
#   -Mode TcpEstablished / TcpListening   Section 3. Was `netstat -ano |
#       findstr "ESTABLISHED"` / "LISTENING": netstat prints its state words in
#       the system language (HERGESTELLT, ABHOEREN on German Windows), so both
#       views were EMPTY on a non-English PC -- a live C2 session or a rogue
#       listener vanished from them. Now Get-NetTCPConnection, the state read
#       by property; netstat only as a fallback, parsed by column.
#   -Mode Group -Sid S-1-5-32-544|S-1-5-32-555   Section 2. Was `net localgroup
#       administrators` / "Remote Desktop Users": English names, so on a German
#       PC ("Administratoren") the report held only an error. Now
#       Get-LocalGroupMember -SID, with `net localgroup <the SID's own name>`
#       parsed by position as the fallback.
#   -Mode OsSummary   Section 1. Was `systeminfo | findstr "OS Name" ...`,
#       empty on a non-English PC. Now CIM. Context only: a failure is [INFO].
#
# A listing that could not be read is a raised gap (dz_listing_gap.txt);
# dz_listing_done.txt is written on every path that reached a verdict. An
# empty Administrators group is impossible (the built-in Administrator is
# always a member), so reading none is a gap, never "no administrators".
# Listing only: nothing here is graded.
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.
#
# Usage:
#   powershell -File tools\system_listing.ps1 -Mode TcpEstablished|TcpListening|OsSummary
#   powershell -File tools\system_listing.ps1 -Mode Group -Sid S-1-5-32-544
#   powershell -File tools\system_listing.ps1 -SelfTest

[CmdletBinding()]
param(
    [ValidateSet('TcpEstablished', 'TcpListening', 'Group', 'OsSummary', '')]
    [string]$Mode = '',
    [string]$Sid = '',
    [string]$MarkerDir = $env:TEMP,
    [int]$Max = 200,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-Field {
    param($Value)
    $t = (([string]$Value) -replace '[\x00-\x1F\x7F]', ' ').Trim()
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t
}

function Get-InnerMessage {
    param($Err)
    $x = $Err.Exception
    while ($x.InnerException) { $x = $x.InnerException }
    return (([string]$x.Message) -replace '\s+', ' ').Trim()
}

# PURE. Lines for TCP connections. $Conns: objects with LocalAddress,
# LocalPort, RemoteAddress, RemotePort, OwningProcess, State; $Names: pid ->
# process name.
function Get-TcpLines {
    param($Conns, [string]$View, $Names, [int]$Max = 200)
    $want = if ($View -eq 'TcpListening') { 'Listen' } else { 'Established' }
    $sel = @($Conns | Where-Object { [string]$_.State -eq $want } | Sort-Object { [int]$_.LocalPort }, { [string]$_.RemoteAddress })
    $out = New-Object System.Collections.ArrayList
    foreach ($c in @($sel | Select-Object -First $Max)) {
        $pn = ''; if ($Names -and $Names.ContainsKey([int]$c.OwningProcess)) { $pn = ' ' + (ConvertTo-Field $Names[[int]$c.OwningProcess]) }
        if ($want -eq 'Listen') {
            [void]$out.Add(('  ' + (ConvertTo-Field $c.LocalAddress) + ':' + [string]$c.LocalPort + '  pid=' + [string]$c.OwningProcess + $pn))
        } else {
            [void]$out.Add(('  ' + (ConvertTo-Field $c.LocalAddress) + ':' + [string]$c.LocalPort + ' -> ' + (ConvertTo-Field $c.RemoteAddress) + ':' + [string]$c.RemotePort + '  pid=' + [string]$c.OwningProcess + $pn))
        }
    }
    $what = if ($want -eq 'Listen') { 'listening TCP port(s)' } else { 'established TCP connection(s)' }
    if ($sel.Count -eq 0) { [void]$out.Add(('[INFO] No ' + $what + '.')) }
    else { [void]$out.Add(('[INFO] ' + $sel.Count + ' ' + $what + $(if ($sel.Count -gt $Max) { (', the first ' + $Max + ' listed') } else { '' }) + ', read by state in any Windows language. Review against what you expect this PC to run.')) }
    return @($out.ToArray())
}

# PURE. netstat -ano lines, picked by COLUMN (Proto, Local, Foreign, State,
# PID): the state word is localized, so a listener is told by its
# unspecified foreign address and an established view takes every TCP row
# with a remote peer, whatever its state is called. Returns @{ Lines; TcpRows }.
function Get-NetstatViewLines {
    param([string[]]$Lines, [string]$View)
    $out = @(); $tcp = 0
    foreach ($line in $Lines) {
        $t = @(([string]$line).Trim() -split '\s+')
        if ($t.Count -lt 5 -or $t[0] -ne 'TCP' -or $t[-1] -notmatch '^\d+$') { continue }
        $tcp++
        $listen = ($t[2] -eq '0.0.0.0:0' -or $t[2] -eq '[::]:0')
        if (($View -eq 'TcpListening') -eq $listen) { $out += ('  ' + (ConvertTo-Field ($t -join '  '))) }
    }
    return @{ Lines = $out; TcpRows = $tcp }
}

function Get-NetLocalGroupMembers {
    param([string[]]$Lines)
    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) { if ([string]$Lines[$i] -match '^-{3,}\s*$') { $start = $i; break } }
    if ($start -lt 0) { return $null }
    $body = @($Lines[($start + 1)..($Lines.Count - 1)] | Where-Object { ([string]$_).Trim() })
    if ($start + 1 -gt $Lines.Count - 1) { $body = @() }
    if ($body.Count -le 1) { return ,@() }
    return ,@($body[0..($body.Count - 2)] | ForEach-Object { ([string]$_).Trim() })
}

# PURE. The verdict lines for a group listing. $Members: names, or $null when
# no source answered. Administrators can never be empty.
function Get-GroupLines {
    param($Members, [string]$Sid, [string]$Label, [string]$Source, [string]$Why = '')
    if ($null -eq $Members -or ($Sid -eq 'S-1-5-32-544' -and @($Members).Count -eq 0)) {
        $r = if ($null -eq $Members) { 'it could not be read' + $(if ($Why) { ' (' + $Why + ')' } else { '' }) } else { 'it was read as empty, which it never is (the built-in Administrator is always a member)' }
        return @{ Lines = @(('[WARNING] ' + $Label + ' membership listing NOT performed -- ' + $r + ', so an account added to it would go unseen (T1078.001).')); Gap = $true }
    }
    $out = @()
    foreach ($m in @($Members)) { $out += ('  ' + (ConvertTo-Field $m)) }
    if (@($Members).Count -eq 0) { $out += ('[INFO] ' + $Label + ' has no members.') }
    else { $out += ('[INFO] ' + @($Members).Count + ' member(s) of ' + $Label + ' (' + $Sid + '), read ' + $Source + '. Every account here can do what the group allows; confirm each is expected.') }
    return @{ Lines = $out; Gap = $false }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $conns = @(
        [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 135; RemoteAddress = '0.0.0.0'; RemotePort = 0; OwningProcess = 1044; State = 'Listen' },
        [pscustomobject]@{ LocalAddress = '10.0.0.5'; LocalPort = 50123; RemoteAddress = '52.96.1.10'; RemotePort = 443; OwningProcess = 4120; State = 'Established' },
        [pscustomobject]@{ LocalAddress = '10.0.0.5'; LocalPort = 50124; RemoteAddress = '52.96.1.11'; RemotePort = 443; OwningProcess = 4120; State = 'TimeWait' })
    $l = (Get-TcpLines -Conns $conns -View 'TcpEstablished' -Names @{ 4120 = 'chrome' }) -join "`n"
    T 'established: read by the State property, with the owning process' ($l -match '(?m)^  10\.0\.0\.5:50123 -> 52\.96\.1\.10:443  pid=4120 chrome$' -and $l -notmatch '50124' -and $l -match '1 established TCP connection') $l
    $l = (Get-TcpLines -Conns $conns -View 'TcpListening' -Names @{}) -join "`n"
    T 'listening: read by the State property' ($l -match '(?m)^  0\.0\.0\.0:135  pid=1044$' -and $l -match '1 listening TCP port') $l
    $l = (Get-TcpLines -Conns @() -View 'TcpListening' -Names @{}) -join "`n"
    T 'no rows is said, never silence' ($l -match '^\[INFO\] No listening TCP port') $l
    $de = @('  Proto  Lokale Adresse  Remoteadresse  Status  PID', '  TCP    0.0.0.0:135     0.0.0.0:0      ABHOEREN   1044', '  TCP    10.0.0.5:50123  52.96.1.10:443 HERGESTELLT 4120')
    $v = Get-NetstatViewLines -Lines $de -View 'TcpEstablished'
    T 'netstat fallback by column: a German established row is listed (the findstr on ESTABLISHED listed none)' ($v.TcpRows -eq 2 -and @($v.Lines).Count -eq 1 -and $v.Lines[0] -match 'HERGESTELLT') ($v.Lines -join ' | ')
    $v = Get-NetstatViewLines -Lines $de -View 'TcpListening'
    T 'netstat fallback by column: a German listener (ABHOEREN) is listed' (@($v.Lines).Count -eq 1 -and $v.Lines[0] -match 'ABHOEREN') ($v.Lines -join ' | ')
    T 'netstat output with no TCP row reads zero rows (a gap for the caller)' ((Get-NetstatViewLines -Lines @('error') -View 'TcpListening').TcpRows -eq 0) ''
    $mem = Get-NetLocalGroupMembers @('Aliasname     Administratoren', '', 'Mitglieder', '', '-------------------------------------------------------------------------------', 'Administrator', 'dzuser', 'Der Befehl wurde erfolgreich ausgefuehrt.', '')
    T 'net localgroup by position: German members are read' ((@($mem) -join ',') -ceq 'Administrator,dzuser') (@($mem) -join ',')
    $g = Get-GroupLines -Members @('PC\Administrator', 'PC\alice') -Sid 'S-1-5-32-544' -Label 'Administrators' -Source 'by SID'
    T 'Administrators members are listed with a count' ((-not $g.Gap) -and ($g.Lines -join "`n") -match '2 member\(s\) of Administrators \(S-1-5-32-544\)') ($g.Lines -join ' | ')
    $g = Get-GroupLines -Members @() -Sid 'S-1-5-32-544' -Label 'Administrators' -Source 'by SID'
    T 'Administrators read as empty is a gap (it never is), never "no members"' ($g.Gap -and $g.Lines[0] -match 'NOT performed -- it was read as empty') ($g.Lines -join ' | ')
    $g = Get-GroupLines -Members @() -Sid 'S-1-5-32-555' -Label 'Remote Desktop Users' -Source 'by SID'
    T 'Remote Desktop Users empty is said, not a gap' ((-not $g.Gap) -and $g.Lines[0] -match 'has no members') ($g.Lines -join ' | ')
    $g = Get-GroupLines -Members $null -Sid 'S-1-5-32-555' -Label 'Remote Desktop Users' -Source '' -Why 'x'
    T 'a group that could not be read is a raised gap' ($g.Gap -and $g.Lines[0] -match '^\[WARNING\] Remote Desktop Users membership listing NOT performed -- it could not be read \(x\)') ($g.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails system_listing self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] system_listing self-test: TCP views read by state and groups by SID in any language; a German netstat or net localgroup is read by column; nothing read is a gap, never an empty listing.'
    exit 0
}

foreach ($n in 'listing_gap', 'listing_done') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
if (-not $Mode) { '[WARNING] System listing NOT performed -- -Mode is required.'; Write-Marker -Name 'listing_gap' -Sev 'WARNING'; Write-Marker -Name 'listing_done' -Sev 'done'; exit 0 }

if ($Mode -eq 'OsSummary') {
    # Context only: a failure is said, never a row.
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        ('  OS: ' + (ConvertTo-Field $os.Caption) + '  version ' + [string]$os.Version + '  build ' + [string]$os.BuildNumber)
        ('  Last boot: ' + $(try { ([datetime]$os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm') } catch { '?' }))
    } catch { '[INFO] Operating-system summary not read (' + (Get-InnerMessage $_) + ').' }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        ('  Domain/workgroup: ' + (ConvertTo-Field $cs.Domain) + $(if ($cs.PartOfDomain) { ' (domain-joined)' } else { ' (not domain-joined)' }))
        ('  Physical memory: ' + [math]::Round(([double]$cs.TotalPhysicalMemory) / 1GB, 1) + ' GB')
    } catch { '[INFO] Computer-system summary not read (' + (Get-InnerMessage $_) + ').' }
    try {
        $hf = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | Sort-Object { try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue } } -Descending)
        ('  Updates recorded: ' + $hf.Count + $(if ($hf.Count) { '; newest: ' + ((@($hf | Select-Object -First 5 | ForEach-Object { [string]$_.HotFixID + $(try { ' (' + ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') + ')' } catch { '' }) })) -join ', ') } else { '' }))
    } catch { '[INFO] Installed-update list not read (' + (Get-InnerMessage $_) + ').' }
    Write-Marker -Name 'listing_done' -Sev 'done'
    exit 0
}

if ($Mode -eq 'TcpEstablished' -or $Mode -eq 'TcpListening') {
    $conns = $null; $why = ''
    try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { $why = Get-InnerMessage $_ }
    if ($null -ne $conns) {
        $names = @{}
        try { foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = [string]$p.ProcessName } } catch {}
        Get-TcpLines -Conns $conns -View $Mode -Names $names -Max $Max
    } else {
        $ns = Get-NetstatViewLines -Lines @(& netstat -ano 2>$null) -View $Mode
        if ($ns.TcpRows -eq 0) {
            '[WARNING] TCP ' + $(if ($Mode -eq 'TcpListening') { 'listening-port' } else { 'connection' }) + ' listing NOT performed -- Get-NetTCPConnection failed (' + $why + ') and netstat returned no TCP row, so a rogue listener or a live command-and-control session would go unseen (T1071).'
            Write-Marker -Name 'listing_gap' -Sev 'WARNING'
        } else {
            '[INFO] Get-NetTCPConnection did not answer (' + $why + '); listed from netstat, by column.'
            $ns.Lines | Select-Object -First $Max
            '[INFO] ' + @($ns.Lines).Count + ' row(s) from netstat.'
        }
    }
    Write-Marker -Name 'listing_done' -Sev 'done'
    exit 0
}

# Group
$label = switch ($Sid) { 'S-1-5-32-544' { 'Administrators' } 'S-1-5-32-555' { 'Remote Desktop Users' } default { $Sid } }
if ($Sid -notmatch '^S-1-5-32-\d+$') { '[WARNING] Group membership listing NOT performed -- -Sid must be a built-in group SID.'; Write-Marker -Name 'listing_gap' -Sev 'WARNING'; Write-Marker -Name 'listing_done' -Sev 'done'; exit 0 }
$members = $null; $source = ''; $why = ''
try { $members = @(Get-LocalGroupMember -SID $Sid -ErrorAction Stop | ForEach-Object { [string]$_.Name + ' (' + [string]$_.ObjectClass + ', ' + [string]$_.PrincipalSource + ')' }); $source = 'by SID' }
catch {
    $why = Get-InnerMessage $_
    # Get-LocalGroupMember fails on a group holding an orphaned SID; net
    # localgroup does not. Asked by the group's own name, from its SID.
    try {
        $gname = ((New-Object System.Security.Principal.SecurityIdentifier $Sid).Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
        $m2 = Get-NetLocalGroupMembers @(& net localgroup $gname 2>$null)
        if ($null -ne $m2) { $members = @($m2); $source = 'with net localgroup ' + $gname + ', by position (Get-LocalGroupMember: ' + $why + ')' }
    } catch { $why = $why + '; ' + (Get-InnerMessage $_) }
}
$g = Get-GroupLines -Members $members -Sid $Sid -Label $label -Source $source -Why $why
$g.Lines
if ($g.Gap) { Write-Marker -Name 'listing_gap' -Sev 'WARNING' }
Write-Marker -Name 'listing_done' -Sev 'done'
exit 0
