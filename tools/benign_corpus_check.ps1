# benign_corpus_check.ps1 -- the benign look-alike corpus, checked two ways.
#
#   -Mode Lint    (any platform) every entry in tests/benign_corpus.txt is
#                 complete, its regex compiles, and its proof resolves to a
#                 real test: a harness Invert case, a windows-smoke.yml step,
#                 or a stated field-only reason. The reverse holds too: every
#                 Invert case in the harness is catalogued. Stale = FAIL.
#   -Mode Report  (against a real SecurityReport_*.txt) every QUIET entry seen
#                 in the report stayed at or below its maxsev; every ADVISE
#                 entry seen prints its verification note. Refuses a TEST RUN
#                 report unless -AllowTestRun (the harness passes it).
#   -SelfTest     mutates copies and asserts each mutation FAILS.
#
# Windows PowerShell 5.1 compatible; no external dependencies.

[CmdletBinding()]
param(
    [ValidateSet('Lint', 'Report')][string]$Mode = 'Lint',
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$Corpus,
    [string]$Report,
    [switch]$AllowTestRun,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
if (-not $Corpus) { $Corpus = Join-Path $Root 'tests/benign_corpus.txt' }
$harnessPath = Join-Path $Root 'tests/detection_selftest.ps1'
$smokePath   = Join-Path $Root '.github/workflows/windows-smoke.yml'
$sevRank = @{ 'OK' = 0; 'INFO' = 1; 'SKIPPED' = 0; 'WARNING' = 2; 'CRITICAL' = 3 }

function Read-Corpus {
    param([string]$Path)
    $entries = @(); $cur = $null
    foreach ($raw in [IO.File]::ReadAllLines($Path)) {
        $ln = $raw.Trim()
        if (-not $ln -or $ln.StartsWith('#')) { continue }
        if ($ln -match '^\[([A-Za-z0-9][A-Za-z0-9_.-]*)\]$') {
            $cur = @{ Id = $matches[1]; Line = 0; Proofs = @() }
            $entries += $cur
            continue
        }
        if ($ln -match '^([a-z]+)\s*=\s*(.*)$') {
            if ($null -eq $cur) { throw ("benign_corpus.txt: key outside any [entry]: {0}" -f $ln) }
            $k = $matches[1]; $v = $matches[2].Trim()
            if ($k -eq 'proof') { $cur.Proofs += @([regex]::Split($v, ';\s*(?=(?:harness|ci|field):)') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            else { $cur[$k] = $v }
            continue
        }
        throw ("benign_corpus.txt: unparseable line: {0}" -f $ln)
    }
    return $entries
}

function Get-InvertCaseNames {
    param([string]$Path)
    $tok = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$errs)
    if ($errs -and $errs.Count) { throw ("detection_selftest.ps1 does not parse: {0}" -f $errs[0].Message) }
    $names = @()
    foreach ($ht in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
        $kv = @{}
        foreach ($pair in $ht.KeyValuePairs) { $kv[$pair.Item1.Extent.Text.Trim("'`"")] = $pair.Item2 }
        if (-not $kv.ContainsKey('Invert') -or -not $kv.ContainsKey('Name')) { continue }
        if ($kv['Invert'].Extent.Text -notmatch '\$true') { continue }
        $nl = $kv['Name'].Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
        if ($nl) { $names += $nl.Value }
    }
    return $names
}

function Invoke-Lint {
    param([string]$CorpusPath, [string]$HarnessPath, [string]$SmokePath)
    $fail = @()
    foreach ($f in @($CorpusPath, $HarnessPath, $SmokePath)) { if (-not (Test-Path -LiteralPath $f)) { return @(("missing: {0}" -f $f)) } }
    $entries = Read-Corpus $CorpusPath
    $invert = @(Get-InvertCaseNames $HarnessPath)
    $steps = @([regex]::Matches([IO.File]::ReadAllText($SmokePath), '(?m)^\s*-\s*name:\s*"?([^"\r\n]+?)"?\s*$') | ForEach-Object { $_.Groups[1].Value })
    if ($invert.Count -lt 4) { $fail += ("only {0} Invert case(s) parsed from the harness -- this check is broken, not the code" -f $invert.Count) }
    if ($steps.Count -lt 20) { $fail += ("only {0} step name(s) parsed from windows-smoke.yml -- this check is broken, not the code" -f $steps.Count) }
    $ids = @{}; $harnessRefs = @{}; $q = 0; $a = 0; $h = 0; $c = 0; $fo = 0
    foreach ($e in $entries) {
        $id = $e.Id
        if ($ids.ContainsKey($id)) { $fail += ("duplicate entry id: {0}" -f $id) }
        $ids[$id] = $true
        foreach ($k in @('class', 'signature', 'note')) { if (-not $e.ContainsKey($k) -or -not $e[$k]) { $fail += ("{0}: missing {1}" -f $id, $k) } }
        if ($e.Proofs.Count -eq 0) { $fail += ("{0}: no proof -- every benign twin must name the test that proves the tool handles it" -f $id) }
        if ($e['class'] -notin @('QUIET', 'ADVISE')) { $fail += ("{0}: class must be QUIET or ADVISE" -f $id) }
        if ($e['class'] -eq 'QUIET') {
            $q++
            if (-not $e.ContainsKey('maxsev') -or $e['maxsev'] -notin @('OK', 'INFO', 'WARNING')) { $fail += ("{0}: QUIET entries need maxsev = OK|INFO|WARNING" -f $id) }
        } elseif ($e['class'] -eq 'ADVISE') { $a++ }
        if ($e['signature']) {
            try { [void][regex]::new($e['signature']) } catch { $fail += ("{0}: signature is not a valid regex: {1}" -f $id, $_.Exception.Message) }
        }
        if ($e['note'] -and $e['note'].Length -lt 40) { $fail += ("{0}: note is too short to help a person verify it" -f $id) }
        foreach ($p in $e.Proofs) {
            if ($p -match '^harness:(.+)$') {
                $needle = $matches[1].Trim()
                $hit = @($invert | Where-Object { $_.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
                if ($hit.Count -eq 0) { $fail += ("{0}: proof '{1}' matches no Invert case in the harness" -f $id, $p) }
                else { $h++; foreach ($n in $hit) { $harnessRefs[$n] = $true } }
            } elseif ($p -match '^ci:(.+)$') {
                $needle = $matches[1].Trim()
                if (-not @($steps | Where-Object { $_.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count) { $fail += ("{0}: proof '{1}' matches no step name in windows-smoke.yml" -f $id, $p) }
                else { $c++ }
            } elseif ($p -match '^field:(.+)$') {
                if ($matches[1].Trim().Length -lt 20) { $fail += ("{0}: field-only proof needs a real reason" -f $id) } else { $fo++ }
            } else { $fail += ("{0}: proof '{1}' must start with harness:, ci: or field:" -f $id, $p) }
        }
    }
    foreach ($n in $invert) {
        if (-not $harnessRefs.ContainsKey($n)) { $fail += ("harness Invert case is not catalogued in the corpus: {0}" -f $n) }
    }
    if ($entries.Count -lt 10) { $fail += ("only {0} corpus entries -- vacuous" -f $entries.Count) }
    if ($h -lt 4) { $fail += ("only {0} harness proofs -- every Invert case should be referenced" -f $h) }
    return @{ Fail = $fail; Entries = $entries.Count; Quiet = $q; Advise = $a; Harness = $h; Ci = $c; Field = $fo; Invert = $invert.Count }
}

function Invoke-Report {
    param([string]$CorpusPath, [string]$ReportPath, [bool]$AllowTest)
    $out = @(); $fail = @(); $observed = 0
    if (-not (Test-Path -LiteralPath $ReportPath)) { return @{ Lines = @(("[FAIL] report not found: {0}" -f $ReportPath)); Fail = 1; Observed = 0; Total = 0 } }
    $lines = [IO.File]::ReadAllLines($ReportPath)
    if (-not $AllowTest -and (($lines -join "`n") -match 'TEST RUN -- every finding below was planted')) {
        return @{ Lines = @('[FAIL] this is a test-run report (every finding in it was planted); the benign corpus is checked against REAL reports. Pass -AllowTestRun only from the harness.'); Fail = 1; Observed = 0; Total = 0 }
    }
    $entries = Read-Corpus $CorpusPath
    if ($entries.Count -lt 10) { return @{ Lines = @(("[FAIL] only {0} corpus entries parsed -- vacuous" -f $entries.Count)); Fail = 1; Observed = 0; Total = 0 } }
    foreach ($e in $entries) {
        $rx = [regex]::new($e['signature'])
        $hits = @($lines | Where-Object { $rx.IsMatch($_) })
        if ($hits.Count -eq 0) { continue }
        $observed++
        if ($e['class'] -eq 'QUIET') {
            $maxAllowed = $sevRank[$e['maxsev']]; $worst = 'untagged'; $worstRank = -1; $badLine = $null
            foreach ($hl in $hits) {
                if ($hl -match '^\s*\[(OK|INFO|SKIPPED|WARNING|CRITICAL)\]') {
                    $r = $sevRank[$matches[1]]
                    if ($r -gt $worstRank) { $worstRank = $r; $worst = $matches[1]; if ($r -gt $maxAllowed) { $badLine = $hl.Trim() } }
                }
            }
            if ($worstRank -gt $maxAllowed) {
                $fail += $e.Id
                $out += ("  [FAIL   ] {0}: known benign look-alike reported at [{1}] (max allowed [{2}]):" -f $e.Id, $worst, $e['maxsev'])
                $out += ("            " + $badLine)
                $out += ("            " + $e['note'])
            } else {
                $out += ("  [OK     ] {0}: {1} line(s), highest tag [{2}]" -f $e.Id, $hits.Count, $worst)
            }
        } else {
            $out += ("  [ADVISE ] {0}: {1} matching line(s) -- known benign cause exists. {2}" -f $e.Id, $hits.Count, $e['note'])
            foreach ($hl in ($hits | Select-Object -First 3)) { $out += ("            " + $hl.Trim()) }
        }
    }
    $out += ("  observed {0} of {1} corpus entries in this report ({2} not present on this machine -- normal)" -f $observed, $entries.Count, ($entries.Count - $observed))
    return @{ Lines = $out; Fail = $fail.Count; Observed = $observed; Total = $entries.Count }
}

# ---- self-test ------------------------------------------------------------
if ($SelfTest) {
    $bad = @(); $ran = 0
    $tmpBase = Join-Path ([IO.Path]::GetTempPath()) ("dz_bc_selftest_{0}" -f [guid]::NewGuid().ToString('N'))
    try {
        $mutations = @(
            @{ Name = 'entry with its proof removed';           Find = '(?m)^proof\s*=\s*ci:Network provider[^\r\n]*\r?\n'; Repl = ''; Expect = 'no proof' },
            @{ Name = 'harness proof pointing at no case';      Find = 'harness:Benign signed shortcut in Startup'; Repl = 'harness:NO SUCH CASE'; Expect = 'matches no Invert case' },
            @{ Name = 'an Invert case left uncatalogued';       Find = '(?s)\[sbl-amsi-self\].*?\r?\n\r?\n'; Repl = ''; Expect = 'not catalogued' },
            @{ Name = 'an invalid regex signature';             Find = '(?m)^signature\s*=\s*Sysmon is not installed'; Repl = 'signature = Sysmon [is not installed'; Expect = 'not a valid regex' },
            @{ Name = 'a QUIET entry without maxsev';           Find = '(?m)^maxsev\s*=\s*INFO\r?\n(?=proof\s*=\s*ci:edr_presence.ps1\r?\nsignature\s*=\s*never been onboarded)'; Repl = ''; Expect = 'need maxsev' }
        )
        foreach ($m in $mutations) {
            $dir = Join-Path $tmpBase ("m{0}" -f $ran)
            New-Item -ItemType Directory -Path (Join-Path $dir 'tests') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $dir '.github/workflows') -Force | Out-Null
            Copy-Item -LiteralPath $harnessPath -Destination (Join-Path $dir 'tests') -Force
            Copy-Item -LiteralPath $smokePath -Destination (Join-Path $dir '.github/workflows') -Force
            $src = [IO.File]::ReadAllText($Corpus)
            $mut = [regex]::Replace($src, $m.Find, $m.Repl, 1)
            if ($mut -eq $src) { $bad += ("{0}: the mutation did not apply -- the self-test is broken, not the code" -f $m.Name); $ran++; continue }
            [IO.File]::WriteAllText((Join-Path $dir 'tests/benign_corpus.txt'), $mut)
            $r = Invoke-Lint -CorpusPath (Join-Path $dir 'tests/benign_corpus.txt') -HarnessPath (Join-Path $dir 'tests/detection_selftest.ps1') -SmokePath (Join-Path $dir '.github/workflows/windows-smoke.yml')
            $msg = ($r.Fail -join "`n")
            if ($r.Fail.Count -eq 0) { $bad += ("{0}: the lint PASSED on the mutated corpus" -f $m.Name) }
            elseif ($msg -notmatch [regex]::Escape($m.Expect)) { $bad += ("{0}: failed, but not for the expected reason ('{1}' absent):`n{2}" -f $m.Name, $m.Expect, $msg) }
            else { Write-Host ("  [OK] lint fails as it must: {0}" -f $m.Name) }
            $ran++
        }
        # Report-mode behavior on synthetic reports.
        $rep = Join-Path $tmpBase 'synthetic.txt'
        $cases = @(
            @{ Name = 'QUIET twin reported at WARNING';  Text = "[WARNING] Non-default network provider 'P9NP' -> C:\Windows\System32\p9np.dll -- Microsoft-signed system DLL`n"; Allow = $false; ExpectFail = $true;  Expect = 'reported at \[WARNING\]' },
            @{ Name = 'QUIET twin reported at INFO';     Text = "[INFO] Non-default network provider 'P9NP' -> C:\Windows\System32\p9np.dll -- Microsoft-signed system DLL`n"; Allow = $false; ExpectFail = $false; Expect = '\[OK     \] netprov-p9np' },
            @{ Name = 'ADVISE twin prints its note';      Text = "[WARNING] System event log was cleared at 1/1/2026`n"; Allow = $false; ExpectFail = $false; Expect = '\[ADVISE \] ev104-smartcard' },
            @{ Name = 'a test-run report is refused';     Text = "*** TEST RUN -- every finding below was planted by the test harness ***`n[INFO] Sysmon is not installed`n"; Allow = $false; ExpectFail = $true;  Expect = 'test-run report' },
            @{ Name = 'a test-run report is accepted with -AllowTestRun'; Text = "*** TEST RUN -- every finding below was planted by the test harness ***`n[INFO] Sysmon is not installed`n"; Allow = $true; ExpectFail = $false; Expect = 'observed 1 of' }
        )
        foreach ($cse in $cases) {
            [IO.File]::WriteAllText($rep, $cse.Text)
            $r = Invoke-Report -CorpusPath $Corpus -ReportPath $rep -AllowTest $cse.Allow
            $txt = ($r.Lines -join "`n")
            $failed = ($r.Fail -gt 0)
            if ($failed -ne $cse.ExpectFail) { $bad += ("report: {0}: expected fail={1}, got fail={2}:`n{3}" -f $cse.Name, $cse.ExpectFail, $failed, $txt) }
            elseif ($txt -notmatch $cse.Expect) { $bad += ("report: {0}: output lacks '{1}':`n{2}" -f $cse.Name, $cse.Expect, $txt) }
            else { Write-Host ("  [OK] report behaves: {0}" -f $cse.Name) }
            $ran++
        }
    } finally { Remove-Item -LiteralPath $tmpBase -Recurse -Force -EA SilentlyContinue }
    if ($ran -lt 10) { $bad += ("only {0} self-test cases ran" -f $ran) }
    if ($bad.Count) { Write-Host ("[FAIL] benign_corpus_check self-test: {0} problem(s):" -f $bad.Count); $bad | ForEach-Object { Write-Host ("  - " + $_) }; exit 1 }
    Write-Host ("[OK] benign_corpus_check self-test: {0} cases -- every mutation fails the lint and report mode grades correctly." -f $ran)
    exit 0
}

# ---- modes ----------------------------------------------------------------
if ($Mode -eq 'Lint') {
    $r = Invoke-Lint -CorpusPath $Corpus -HarnessPath $harnessPath -SmokePath $smokePath
    if ($r.Fail.Count) {
        Write-Host ("[FAIL] benign corpus: {0} problem(s) -- a known false positive is undocumented or untested:" -f $r.Fail.Count)
        $r.Fail | ForEach-Object { Write-Host ("  - " + $_) }
        exit 1
    }
    Write-Host ("[OK] benign corpus: {0} entries ({1} QUIET, {2} ADVISE); proofs: {3} harness, {4} CI, {5} field-only; all {6} harness Invert cases catalogued." -f $r.Entries, $r.Quiet, $r.Advise, $r.Harness, $r.Ci, $r.Field, $r.Invert)
    exit 0
}
if (-not $Report) { Write-Host '[FAIL] -Mode Report needs -Report <SecurityReport_*.txt>'; exit 1 }
$r = Invoke-Report -CorpusPath $Corpus -ReportPath $Report -AllowTest ([bool]$AllowTestRun)
Write-Host "== Benign look-alike corpus vs this report =="
$r.Lines | ForEach-Object { Write-Host $_ }
if ($r.Fail -gt 0) { Write-Host ("[FAIL] {0} known benign look-alike(s) reported above their allowed severity -- a false positive has returned." -f $r.Fail); exit 1 }
Write-Host ("[OK] no known benign look-alike is reported above its allowed severity ({0} of {1} observed)." -f $r.Observed, $r.Total)
exit 0
