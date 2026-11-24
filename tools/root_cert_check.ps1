# root_cert_check.ps1 -- Section 17: root certificates added recently.
#
# The check it replaces was
#   Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(-90) }
# NotBefore is the date the certificate's VALIDITY starts, chosen by whoever
# made it -- not the date it was installed. A fake root minted with a
# NotBefore two years ago and planted yesterday (the Ruby Sleet / DPRK shape)
# read "[OK] No new root certificates installed in last 90 days." And the
# store read had no -ErrorAction Stop, so a store that could not be read read
# the same.
#
# THE FACT: each root certificate is a registry key named after its
# thumbprint, and the key's last-write time is set by Windows when the
# certificate is written (Get-RegKeyLastWrite, the pinned shared copy). The
# stores read: the machine Root store, its Group Policy and Enterprise
# physical stores, and the current user's Root store.
#
# THE RULE (pure, in Get-RootCertVerdict, pinned by -SelfTest):
#   * a key written in the last -Days days is a recent root;
#   * recent roots written TOGETHER -- -BatchSize or more inside the same
#     -BatchMinutes window -- are the shape of a Windows update, a feature
#     update or an image build rewriting its roots: [INFO], listed, not raised;
#   * any other recent root is the finding, [WARNING], listed with its
#     subject, issuer, thumbprint, store, write time and NotBefore;
#   * a store or key that could not be read (a listing that failed, a
#     last-write time Windows would not give) is a raised gap, named.
# THE LIMIT, said in the report: an attacker with administrator rights can
# rewrite a key's last-write time; this catches the root that is planted, not
# one planted and then aged by hand.
#
# Markers (in -MarkerDir): dz_rootcert_hit.txt, dz_rootcert_gap.txt, and
# dz_rootcert_done.txt written last.
#
# Usage:
#   powershell -File tools\root_cert_check.ps1 [-MarkerDir <dir>] [-Days 90]
#   powershell -File tools\root_cert_check.ps1 -SelfTest   (reads nothing)
#   -StoreRoot <key> (repeatable; CI only) replaces the real stores.
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$Days = 90,
    [int]$BatchSize = 5,
    [int]$BatchMinutes = 2,
    [string[]]$StoreRoot = @(),
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

function ConvertTo-LineText {
    param([string]$s, [int]$Max = 200)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

# Live. When Windows last wrote a registry key; $null when it would not say.
function Get-RegKeyLastWrite {
    param([string]$KeyPath)
    if (-not $KeyPath) { return $null }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DozeSec.RegTime').Type) {
            Add-Type -ErrorAction Stop -Namespace DozeSec -Name RegTime -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int RegQueryInfoKey(IntPtr hKey, System.Text.StringBuilder lpClass,
    IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
    IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
    IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
        }
    } catch { return $null }
    $key = $null
    try {
        # Accept both provider paths (HKLM:\...) and PSPath forms.
        $p = $KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $p = $p -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' -replace '^HKEY_CURRENT_USER\\', 'HKCU:\'
        $key = Get-Item -LiteralPath $p -EA Stop
        $ft = [long]0
        $rc = [DozeSec.RegTime]::RegQueryInfoKey($key.Handle.DangerousGetHandle(),
            $null, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [ref]$ft)
        if ($rc -ne 0 -or $ft -le 0) { return $null }
        return [datetime]::FromFileTime($ft)
    } catch { return $null }
}


# PURE. $Entries: @( @{ Store; Thumb; Written (datetime or $null); Subject;
# Issuer; NotBefore } ). $Unread: @( 'store or key: why' ). Returns
# @{ Lines; Hit; Gap }.
function Get-RootCertVerdict {
    param($Entries = @(), [string[]]$Unread = @(), [datetime]$Now, [int]$Days = 90, [int]$BatchSize = 5, [int]$BatchMinutes = 2)
    $out = New-Object System.Collections.ArrayList
    $cut = $Now.AddDays(-$Days)
    $all = @($Entries | Where-Object { $_ })
    $noTime = @($all | Where-Object { $null -eq $_.Written })
    $recent = @($all | Where-Object { $null -ne $_.Written -and $_.Written -gt $cut } | Sort-Object { $_.Written })
    # Batches: a run of recent keys each within BatchMinutes of the next.
    $batched = New-Object System.Collections.ArrayList
    $single = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $recent.Count) {
        $j = $i
        while (($j + 1) -lt $recent.Count -and ($recent[$j + 1].Written - $recent[$j].Written).TotalMinutes -le $BatchMinutes) { $j++ }
        $run = @($recent[$i..$j])
        if ($run.Count -ge $BatchSize) { [void]$batched.Add($run) } else { foreach ($e in $run) { [void]$single.Add($e) } }
        $i = $j + 1
    }
    $fmt = { param($e) ('  ' + $e.Store + '  ' + $e.Thumb + '  ' + (ConvertTo-LineText ([string]$e.Subject) 120) + '  issuer: ' + (ConvertTo-LineText ([string]$e.Issuer) 120) + '  written ' + $e.Written.ToString('yyyy-MM-dd HH:mm') + $(if ($e.NotBefore) { '  (NotBefore ' + ([datetime]$e.NotBefore).ToString('yyyy-MM-dd') + ')' } else { '' })) }
    $hit = $false
    if ($single.Count) {
        [void]$out.Add(('[WARNING] ' + $single.Count + ' root certificate(s) installed in the last ' + $Days + ' days, by when Windows wrote them (Ruby Sleet drops fake roots):'))
        foreach ($e in @($single | Select-Object -First 20)) { [void]$out.Add((& $fmt $e)) }
        if ($single.Count -gt 20) { [void]$out.Add(('[INFO] ' + ($single.Count - 20) + ' more not listed.')) }
        $hit = $true
    }
    foreach ($b in $batched) {
        [void]$out.Add(('[INFO] ' + $b.Count + ' root certificate(s) were written together at ' + $b[0].Written.ToString('yyyy-MM-dd HH:mm') + ' -- the shape of a Windows update or image build rewriting its roots, so they are listed, not raised:'))
        foreach ($e in @($b | Select-Object -First 5)) { [void]$out.Add((& $fmt $e)) }
        if ($b.Count -gt 5) { [void]$out.Add(('  ... and ' + ($b.Count - 5) + ' more in the same batch.')) }
    }
    $un = @($Unread | Where-Object { $_ }) + @($noTime | ForEach-Object { $_.Store + '\' + $_.Thumb + ': Windows gave no last-write time' })
    if ($un.Count) {
        [void]$out.Add(('[WARNING] Root certificate check NOT performed in full -- ' + $un.Count + ' store(s) or certificate(s) could not be read: ' + ((@($un | Select-Object -First 5 | ForEach-Object { ConvertTo-LineText $_ })) -join '; ') + $(if ($un.Count -gt 5) { '; and ' + ($un.Count - 5) + ' more' } else { '' }) + ', so a root planted there would go unseen (T1553.004).'))
    }
    if (-not $hit -and -not $un.Count) {
        [void]$out.Add(('[OK] No root certificate installed in the last ' + $Days + ' days (' + $all.Count + ' read, judged by when Windows wrote them, not by their NotBefore date).'))
    } elseif (-not $hit) {
        [void]$out.Add(('[OK] No root certificate installed in the last ' + $Days + ' days among the ' + ($all.Count - $noTime.Count) + ' that could be read.'))
    }
    [void]$out.Add('[INFO] An attacker with administrator rights can rewrite a key''s last-write time; this finds a root that is planted, not one planted and then aged by hand.')
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = ($un.Count -gt 0) }
}

# Live. Reads one registry store of certificates (each subkey a thumbprint).
function Read-CertStore {
    param([string]$Key, [string]$Label, [string]$CertDrive)
    $r = @{ Entries = @(); Unread = @() }
    $subs = $null
    try { $subs = @(Get-ChildItem -LiteralPath $Key -ErrorAction Stop) }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return $r }
        $r.Unread += ($Label + ': ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $r
    }
    foreach ($s in $subs) {
        $thumb = Split-Path -Leaf $s.Name
        $w = Get-RegKeyLastWrite $s.PSPath
        $subj = ''; $iss = ''; $nb = $null
        if ($CertDrive) {
            try { $c = Get-Item -LiteralPath (Join-Path $CertDrive $thumb) -ErrorAction Stop; $subj = $c.Subject; $iss = $c.Issuer; $nb = $c.NotBefore } catch {}
        }
        $r.Entries += @{ Store = $Label; Thumb = $thumb; Written = $w; Subject = $subj; Issuer = $iss; NotBefore = $nb }
    }
    return $r
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $now = [datetime]'2026-11-24T12:00:00'
    function E { param([string]$Th, $W, $Nb = $null) @{ Store = 'LocalMachine\Root'; Thumb = $Th; Written = $W; Subject = 'CN=' + $Th; Issuer = 'CN=' + $Th; NotBefore = $Nb } }
    $old = $now.AddDays(-400)
    $v = Get-RootCertVerdict -Entries @((E 'A' $old), (E 'B' $old)) -Now $now
    T 'roots written long ago: the [OK], saying what it judged by' ((-not ($v.Hit -or $v.Gap)) -and ($v.Lines -join ' ') -match '^\[OK\] No root certificate installed in the last 90 days \(2 read, judged by when Windows wrote them') ($v.Lines -join ' | ')
    $v = Get-RootCertVerdict -Entries @((E 'A' $old), (E 'EVIL' $now.AddDays(-1) $now.AddYears(-2))) -Now $now
    T 'a root written yesterday with a NotBefore two years ago is the finding (the defect: NotBefore read as install time)' ($v.Hit -and ($v.Lines -join ' ') -match '1 root certificate\(s\) installed in the last 90 days' -and ($v.Lines -join ' ') -match 'EVIL .*NotBefore 2024-11-24') ($v.Lines -join ' | ')
    $batch = @(1..8 | ForEach-Object { E ('W' + $_) $now.AddDays(-10).AddSeconds($_ * 5) })
    $v = Get-RootCertVerdict -Entries $batch -Now $now
    T 'eight roots rewritten together (a Windows update or image build): [INFO], not raised' ((-not $v.Hit) -and ($v.Lines -join ' ') -match '^\[INFO\] 8 root certificate\(s\) were written together') ($v.Lines -join ' | ')
    $v = Get-RootCertVerdict -Entries (@($batch) + @(E 'EVIL' $now.AddDays(-3))) -Now $now
    T 'a single root beside an update batch is still the finding' ($v.Hit -and ($v.Lines -join ' ') -match 'EVIL') ($v.Lines -join ' | ')
    $v = Get-RootCertVerdict -Entries @((E 'A' $old)) -Unread @('LocalMachine\Root (Group Policy): SecurityException: denied') -Now $now
    T 'a store that could not be read is a raised gap, and the [OK] says what it covers' ($v.Gap -and -not $v.Hit -and ($v.Lines -join ' ') -match 'Root certificate check NOT performed in full -- 1 store' -and ($v.Lines -join ' ') -match 'among the 1 that could be read') ($v.Lines -join ' | ')
    $v = Get-RootCertVerdict -Entries @((E 'A' $null)) -Now $now
    T 'a certificate whose last-write time Windows would not give is a gap, never "not recent"' ($v.Gap -and ($v.Lines -join ' ') -match 'A: Windows gave no last-write time') ($v.Lines -join ' | ')
    $v = Get-RootCertVerdict -Entries @() -Now $now
    T 'the limit is always said' (($v.Lines -join ' ') -match 'can rewrite a key''s last-write time') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails root_cert_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] root_cert_check self-test: a root is judged by when Windows wrote it, not its NotBefore; one planted recently is the finding, a batch rewritten together is [INFO], and a store that could not be read is a raised gap.'
    exit 0
}

foreach ($n in 'hit', 'gap', 'done') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_rootcert_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
$stores = if ($StoreRoot.Count) { @($StoreRoot | ForEach-Object { @{ Key = $_; Label = $_; Drive = '' } }) } else { @(
    @{ Key = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates'; Label = 'LocalMachine\Root'; Drive = 'Cert:\LocalMachine\Root' },
    @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'; Label = 'LocalMachine\Root (Group Policy)'; Drive = 'Cert:\LocalMachine\Root' },
    @{ Key = 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates'; Label = 'LocalMachine\Root (Enterprise)'; Drive = 'Cert:\LocalMachine\Root' },
    @{ Key = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label = 'CurrentUser\Root'; Drive = 'Cert:\CurrentUser\Root' }) }
$entries = @(); $unread = @()
foreach ($st in $stores) {
    $r = Read-CertStore -Key $st.Key -Label $st.Label -CertDrive $st.Drive
    $entries += $r.Entries; $unread += $r.Unread
}
$v = Get-RootCertVerdict -Entries $entries -Unread $unread -Now (Get-Date) -Days $Days -BatchSize $BatchSize -BatchMinutes $BatchMinutes
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'rootcert_hit' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'rootcert_gap' -Sev 'WARNING' }
Write-Marker -Name 'rootcert_done' -Sev 'done'
exit 0
