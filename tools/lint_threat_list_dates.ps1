# lint_threat_list_dates.ps1 -- a shipped threat list whose entries change
# must carry a new "# Last verified by doze_sec:" date.
#
# WHY: ThreatLists\ttp_manifest.txt changed content in three commits
# (1a9969d, f6cc722, f2453c5) while its header stayed at 2026-06-06. The
# elevated field run of 2026-09-25 12:51 then replaced the runtime copy
# "same date, content differs", which was right only because the seed's tie
# rule favours the shipped file. A content change to a shipped list is a new
# verification, and the date is the only thing a runtime copy is reconciled
# by (tools\threat_list_seed.ps1), so a stale date is a reconciliation that
# happens by luck of a rule's direction.
#
# RULE: the header line is
#   # Last verified by doze_sec: <yyyy-MM-dd> <HH:mm:ss> sha256:<16 hex>
# where the digest is SHA-256 over the NORMALISED entries -- every line
# trimmed, blank lines and `#` comment lines dropped, joined by LF, UTF-8 --
# the exact Get-NormalizedHash rule in tools\threat_list_sync.ps1 (which
# writes the same header on every -updateTTP refresh), first 16 hex digits.
# A list fails when the header is missing, the date does not parse or lies in
# the future, the digest is missing, or the digest does not match the
# entries. Git history is not available on a user's machine or a shallow
# checkout, so the check is self-contained: the header carries what the
# entries looked like when the date was written.
#
# -Stamp rewrites a failing header with today's date and the current digest.
# That is a statement that the entries were re-verified; it is deliberate,
# never automatic. -Stamp -KeepDate adds or refreshes the digest without
# moving the date (adoption of the digest on lists whose entries did not
# change; nothing else). -File limits -Stamp to one list.
#
# -SelfTest: fixtures for every defect class, a changed-entry mutation on a
# temp copy that must fail and must pass after -Stamp, the shipped tree
# clean, and the digest rule cross-checked against the sync tool's own
# Get-NormalizedHash (extracted by AST, so two copies of the rule cannot
# drift apart unnoticed).
#
# Windows PowerShell 5.1 and pwsh 7 (Linux CI) -- no dependencies.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$Stamp,
    [switch]$KeepDate,
    [string]$File = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$script:HeaderRx = '^\s*#\s*Last verified by doze_sec:\s*(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?(?:\s+sha256:([0-9A-Fa-f]{16}))?\s*$'

# The same normalisation as threat_list_sync.ps1's Get-NormalizedHash: trim,
# drop blanks, drop # comment lines (the header is one), join with LF, UTF-8.
function Get-ListDigest {
    param([string[]]$Lines)
    $norm = (@($Lines) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' }) -join "`n"
    if ($norm -eq '') { return '' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')).Substring(0, 16) }
    finally { $sha.Dispose() }
}

# PURE: the header's parts, or $null fields when absent.
function Get-HeaderInfo {
    param([string[]]$Lines)
    for ($i = 0; $i -lt @($Lines).Count; $i++) {
        $l = [string]$Lines[$i]
        if ($l -notmatch '^\s*#\s*Last verified by doze_sec\b') { continue }
        $m = [regex]::Match($l, $script:HeaderRx)
        if (-not $m.Success) { return @{ Index = $i; Date = $null; Digest = $null; Malformed = $true } }
        $txt = $m.Groups[1].Value + $(if ($m.Groups[2].Success) { ' ' + $m.Groups[2].Value } else { ' 00:00:00' })
        $d = $null
        try { $d = [datetime]::ParseExact($txt, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch { $d = $null }
        return @{ Index = $i; Date = $d; Digest = $(if ($m.Groups[3].Success) { $m.Groups[3].Value.ToUpperInvariant() } else { $null }); Malformed = ($null -eq $d) }
    }
    return @{ Index = -1; Date = $null; Digest = $null; Malformed = $false }
}

# PURE: defects for one list.
function Get-ListDefects {
    param([string[]]$Lines, [string]$Name, [datetime]$Today = (Get-Date))
    $bad = @()
    $h = Get-HeaderInfo -Lines $Lines
    if ($h.Index -lt 0) { return @(("{0}: no '# Last verified by doze_sec:' header -- the seed step cannot reconcile a runtime copy without one; run -Stamp" -f $Name)) }
    if ($h.Malformed) { return @(("{0}: the verified date does not parse (expected yyyy-MM-dd HH:mm:ss); run -Stamp" -f $Name)) }
    if ($h.Date -gt $Today.AddDays(1)) { $bad += ("{0}: the verified date {1} lies in the future" -f $Name, $h.Date.ToString('yyyy-MM-dd')) }
    $want = Get-ListDigest -Lines $Lines
    if ($null -eq $h.Digest) {
        $bad += ("{0}: not stamped -- the header carries no sha256 digest of its entries, so a content change cannot be told from a re-verification; run -Stamp (or -Stamp -KeepDate to adopt the digest without moving the date)" -f $Name)
    } elseif ($h.Digest -ne $want) {
        $bad += ("{0}: entries changed since they were verified on {1} (header digest {2}, entries now {3}) -- a content change is a new verification; re-verify and run -Stamp" -f $Name, $h.Date.ToString('yyyy-MM-dd'), $h.Digest, $want)
    }
    return @($bad)
}

# Rewrite the header in place; returns the new lines.
function Set-ListHeader {
    param([string[]]$Lines, [bool]$KeepExistingDate, [datetime]$Now = (Get-Date))
    $h = Get-HeaderInfo -Lines $Lines
    $date = $(if ($KeepExistingDate -and $null -ne $h.Date) { $h.Date.ToString('yyyy-MM-dd HH:mm:ss') } else { $Now.ToString('yyyy-MM-dd HH:mm:ss') })
    $header = '# Last verified by doze_sec: ' + $date + ' sha256:' + (Get-ListDigest -Lines $Lines)
    $out = New-Object System.Collections.Generic.List[string]
    if ($h.Index -lt 0) { $out.Add($header); foreach ($l in @($Lines)) { $out.Add([string]$l) } }
    else { for ($i = 0; $i -lt @($Lines).Count; $i++) { if ($i -eq $h.Index) { $out.Add($header) } else { $out.Add([string]$Lines[$i]) } } }
    return $out.ToArray()
}

$dir = Join-Path $Root 'ThreatLists'
if (-not (Test-Path -LiteralPath $dir)) { Write-Host ("[FAIL] no ThreatLists directory under {0} -- this lint is broken, not the lists" -f $Root); exit 1 }
$lists = @(Get-ChildItem -LiteralPath $dir -File -Filter *.txt | Sort-Object Name)
if ($lists.Count -lt 5) { Write-Host ("[FAIL] only {0} list(s) under ThreatLists -- this lint is broken, not the lists" -f $lists.Count); exit 1 }

if ($SelfTest) {
    $fails = @()
    $today = Get-Date '2026-10-03'
    # (Build header strings OUTSIDE the array literal: inside @( ) the comma
    # binds tighter than +, and 'x' + (f), 'y' becomes one joined string.)
    $goodHdr = '# Last verified by doze_sec: 2026-06-06 10:20:38 sha256:' + (Get-ListDigest -Lines @('a|b', 'c|d'))
    $good = @($goodHdr, '# Format: X|Y', '', 'a|b', 'c|d')
    if (@(Get-ListDefects -Lines $good -Name 'good.txt' -Today $today).Count -ne 0) { $fails += 'a stamped list with matching entries was reported' }
    $d = @(Get-ListDefects -Lines @('# Format: X|Y', 'a|b') -Name 'nohdr.txt' -Today $today)
    if ($d.Count -ne 1 -or $d[0] -notmatch 'no .* header') { $fails += ("missing header not reported: " + ($d -join ' | ')) }
    $d = @(Get-ListDefects -Lines @('# Last verified by doze_sec: 2026-06-06 10:20:38', 'a|b') -Name 'unstamped.txt' -Today $today)
    if ($d.Count -ne 1 -or $d[0] -notmatch 'not stamped') { $fails += ("unstamped header not reported: " + ($d -join ' | ')) }
    $changed = @($good[0], '# Format: X|Y', 'a|b', 'c|d', 'e|f')
    $d = @(Get-ListDefects -Lines $changed -Name 'changed.txt' -Today $today)
    if ($d.Count -ne 1 -or $d[0] -notmatch 'entries changed since they were verified on 2026-06-06') { $fails += ("changed entries not reported: " + ($d -join ' | ')) }
    $d = @(Get-ListDefects -Lines @('# Last verified by doze_sec: yesterday sha256:0123456789ABCDEF', 'a|b') -Name 'baddate.txt' -Today $today)
    if ($d.Count -ne 1 -or $d[0] -notmatch 'does not parse') { $fails += ("malformed date not reported: " + ($d -join ' | ')) }
    $futureHdr = '# Last verified by doze_sec: 2027-01-01 00:00:00 sha256:' + (Get-ListDigest -Lines @('a|b'))
    $future = @($futureHdr, 'a|b')
    $d = @(Get-ListDefects -Lines $future -Name 'future.txt' -Today $today)
    if ($d.Count -ne 1 -or $d[0] -notmatch 'in the future') { $fails += ("future date not reported: " + ($d -join ' | ')) }
    # Comments and whitespace are not entries: editing them does not change the digest.
    $cosmetic = @($good[0], '# Format: changed comment', '  a|b  ', '', 'c|d')
    if (@(Get-ListDefects -Lines $cosmetic -Name 'cosmetic.txt' -Today $today).Count -ne 0) { $fails += 'a comment/whitespace-only edit was reported as a content change' }
    # Stamping: a changed list passes after -Stamp (date moves) and after -Stamp -KeepDate (date kept).
    $st = Set-ListHeader -Lines $changed -KeepExistingDate $false -Now $today
    if (@(Get-ListDefects -Lines $st -Name 'stamped.txt' -Today $today).Count -ne 0 -or $st[0] -notmatch '^# Last verified by doze_sec: 2026-10-03 00:00:00 sha256:[0-9A-F]{16}$') { $fails += ("-Stamp did not produce a passing header: " + $st[0]) }
    $kd = Set-ListHeader -Lines $changed -KeepExistingDate $true -Now $today
    if (@(Get-ListDefects -Lines $kd -Name 'kept.txt' -Today $today).Count -ne 0 -or $kd[0] -notmatch '^# Last verified by doze_sec: 2026-06-06 10:20:38 sha256:') { $fails += ("-Stamp -KeepDate did not keep the date: " + $kd[0]) }
    $nh = Set-ListHeader -Lines @('# Format: X', 'a|b') -KeepExistingDate $true -Now $today
    if ($nh[0] -notmatch '^# Last verified by doze_sec: 2026-10-03' -or $nh.Count -ne 3) { $fails += ("-Stamp on a list with no header did not prepend one: " + ($nh -join ' / ')) }
    # The digest rule must be THE SAME rule the sync tool writes with. Extract
    # Get-NormalizedHash from threat_list_sync.ps1 by AST and compare on a
    # fixture; two hand copies of a rule drift apart unnoticed otherwise.
    $syncPath = Join-Path (Join-Path $Root 'tools') 'threat_list_sync.ps1'
    if (-not (Test-Path -LiteralPath $syncPath)) { $fails += 'tools/threat_list_sync.ps1 not found for the digest cross-check' }
    else {
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($syncPath, [ref]$tok, [ref]$err)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-NormalizedHash' }, $true)
        if (-not $fn) { $fails += 'Get-NormalizedHash not found in threat_list_sync.ps1 -- the cross-check cannot run' }
        else {
            $sb = [scriptblock]::Create($fn.Extent.Text + "`nGet-NormalizedHash -Content `$args[0]")
            $fixture = "# Last verified by doze_sec: 2026-01-01 00:00:00`r`n# comment`r`n  a|b  `r`n`r`nc|d`r`n"
            $theirs = [string](& $sb $fixture)
            $mine = Get-ListDigest -Lines ($fixture -split "`r?`n")
            if (-not $theirs -or $theirs.Substring(0, 16) -ne $mine) { $fails += ("digest rule drifted from threat_list_sync.ps1: sync {0} vs lint {1}" -f $theirs, $mine) }
        }
    }
    # The shipped tree must be clean, and a mutated copy must fail then pass.
    foreach ($f in $lists) {
        $d = @(Get-ListDefects -Lines ([IO.File]::ReadAllLines($f.FullName)) -Name $f.Name)
        if ($d.Count) { $fails += ("shipped {0}: {1}" -f $f.Name, $d[0]) }
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_ltd_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        $src = $lists | Where-Object { $_.Name -eq 'ttp_manifest.txt' } | Select-Object -First 1
        if (-not $src) { $fails += 'ttp_manifest.txt not found for the mutation case' }
        else {
            $m = [System.Collections.Generic.List[string]]([IO.File]::ReadAllLines($src.FullName))
            $m.Add('T9999.999|Mutation|lint self-test entry')
            $d = @(Get-ListDefects -Lines $m.ToArray() -Name 'mutated ttp_manifest.txt')
            if ($d.Count -ne 1 -or $d[0] -notmatch 'entries changed') { $fails += ("an added entry on a shipped list was not reported: " + ($d -join ' | ')) }
            $re = Set-ListHeader -Lines $m.ToArray() -KeepExistingDate $false
            if (@(Get-ListDefects -Lines $re -Name 'restamped').Count -ne 0) { $fails += 'the mutated list did not pass after -Stamp' }
        }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    if ($fails.Count) { Write-Host ("[FAIL] lint_threat_list_dates self-test: {0} problem(s):" -f $fails.Count); $fails | ForEach-Object { Write-Host ("  - " + $_) }; exit 1 }
    Write-Host ("[OK] lint_threat_list_dates self-test: every defect class is caught, cosmetic edits are not, -Stamp and -Stamp -KeepDate produce passing headers, the digest rule matches threat_list_sync.ps1, and the {0} shipped lists are clean." -f $lists.Count)
    exit 0
}

if ($Stamp) {
    $n = 0
    foreach ($f in $lists) {
        if ($File -and $f.Name -ne $File) { continue }
        $lines = [IO.File]::ReadAllLines($f.FullName)
        if (@(Get-ListDefects -Lines $lines -Name $f.Name).Count -eq 0) { continue }
        $new = Set-ListHeader -Lines $lines -KeepExistingDate ([bool]$KeepDate)
        [IO.File]::WriteAllLines($f.FullName, [string[]]$new, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ("stamped {0}: {1}" -f $f.Name, $new[0])
        $n++
    }
    Write-Host ("[OK] {0} list(s) stamped." -f $n)
    exit 0
}

$bad = @()
foreach ($f in $lists) { $bad += @(Get-ListDefects -Lines ([IO.File]::ReadAllLines($f.FullName)) -Name $f.Name) }
if ($bad.Count) {
    Write-Host ("[FAIL] {0} shipped threat list defect(s) ({1} list(s) scanned):" -f $bad.Count, $lists.Count)
    $bad | ForEach-Object { Write-Host ("  - " + $_) }
    Write-Host '       A content change to a shipped list is a new verification: re-verify the entries and run tools/lint_threat_list_dates.ps1 -Stamp.'
    exit 1
}
Write-Host ("[OK] lint_threat_list_dates: {0} shipped list(s) carry a verified date and a digest that matches their entries." -f $lists.Count)
exit 0
