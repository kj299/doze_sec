# lint_readonly.ps1 -- the tripwire behind the -readonly switch.
#
# WHY: -readonly promises a person "this audit changes nothing on your
# machine outside the output folder and the temp folder, and makes no
# network connections." That promise is only as good as the gates in front
# of every mutation and egress site in the two batch scripts. A future edit
# that adds a `reg add`, a `bcdedit /set` or an `Invoke-WebRequest` without a
# gate would silently make the promise false on a user's machine. This lint
# fails on any such site.
#
# RULES (both doze_sec.bat and doze_sec_noAdmin.bat):
#   1. Every EXECUTABLE line (not echo/rem/::) matching a known
#      mutation/egress pattern must have a gate token within the preceding
#      window: READONLY_MODE, or a switch variable that -readonly forces or
#      refuses (SKIP_SRP, SKIP_THREAT_UPDATE, VT_SELF_SKIP, NETWORK_AVAIL,
#      VT_CHECK, DNS_PROBE, UPDATE_TTP).
#   2. The RunOnce `reg add` and the `bcdedit /set|/timeout` sites must be
#      gated by READONLY_MODE specifically (they have no switch of their own).
#   3. :args_done must force SKIP_SRP / SKIP_THREAT_UPDATE / VT_SELF_SKIP and
#      route -vt / -dnsprobe / -updateTTP to :readonly_conflict.
#   4. Vacuity: fewer than 8 sites found in a script = the scanner is broken.
#
# -SelfTest mutates copies (an ungated reg add; the INIT-8 gate removed) and
# asserts each FAILS. Runs on any platform.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest,
    [int]$Window = 60
)

$ErrorActionPreference = 'Stop'
$bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat')
foreach ($b in $bats) { if (-not (Test-Path -LiteralPath (Join-Path $Root $b))) { Write-Host ("[FAIL] missing: {0}" -f $b); exit 1 } }

if ($SelfTest) {
    $mutations = @(
        @{ Name = 'an ungated reg add far from any gate'
           Find = '(?m)^echo  \[3/18\] NETWORK CONFIGURATION AND LIVE CONNECTIONS>> "%REPORT%"\r?\n'
           Repl = '$0' + 'reg add "HKCU\Software\dz_lint_probe" /v x /t REG_SZ /d y /f >nul 2>&1' + "`r`n"
           Expect = 'reg add' },
        @{ Name = 'the INIT-8 read-only gate removed'
           Find = '(?m)^if "%READONLY_MODE%"=="1" \(\r?\n\s*echo  \[SKIP\] read-only mode: RunOnce[^\r\n]*\r?\n[^\r\n]*\r?\n\s*goto :runonce_done\r?\n\)\r?\n'
           Repl = ''
           Expect = 'must be gated by READONLY_MODE' },
        @{ Name = ':args_done no longer forces SKIP_SRP'
           Find = '(?m)^if "%READONLY_MODE%"=="1" set "SKIP_SRP=1"\r?\n'
           Repl = ''
           Expect = 'does not force' }
    )
    $tmpBase = Join-Path ([IO.Path]::GetTempPath()) ("dz_ro_selftest_{0}" -f [guid]::NewGuid().ToString('N'))
    $bad = @(); $ran = 0
    try {
        foreach ($m in $mutations) {
            $dir = Join-Path $tmpBase ("m{0}" -f $ran); New-Item -ItemType Directory -Path $dir -Force | Out-Null
            foreach ($b in $bats) { Copy-Item -LiteralPath (Join-Path $Root $b) -Destination $dir -Force }
            $target = Join-Path $dir 'doze_sec.bat'
            $src = [IO.File]::ReadAllText($target)
            $mut = [regex]::Replace($src, $m.Find, $m.Repl, 1)
            if ($mut -eq $src) { $bad += ("{0}: the mutation did not apply -- the self-test is broken, not the code" -f $m.Name); $ran++; continue }
            [IO.File]::WriteAllText($target, $mut)
            $out = & $PSCommandPath -Root $dir *>&1 | Out-String
            if ($LASTEXITCODE -eq 0) { $bad += ("{0}: the lint PASSED on the mutated script" -f $m.Name) }
            elseif ($out -notmatch [regex]::Escape($m.Expect)) { $bad += ("{0}: failed, but not for the expected reason ('{1}' absent):`n{2}" -f $m.Name, $m.Expect, $out) }
            else { Write-Host ("  [OK] fails as it must: {0}" -f $m.Name) }
            $ran++
        }
    } finally { Remove-Item -LiteralPath $tmpBase -Recurse -Force -EA SilentlyContinue }
    if ($ran -lt $mutations.Count) { $bad += 'not every mutation ran' }
    if ($bad.Count) { Write-Host ("[FAIL] lint_readonly self-test: {0} problem(s):" -f $bad.Count); $bad | ForEach-Object { Write-Host ("  - " + $_) }; exit 1 }
    Write-Host ("[OK] lint_readonly self-test: all {0} mutations fail the lint, each for the right reason." -f $ran)
    exit 0
}

$siteRx = '\breg add\b|\breg delete\b|bcdedit /set|bcdedit /timeout|bcdedit /deletevalue|srp_check\.ps1|Checkpoint-Computer|\bping -n\b|self_update_check\.ps1|threat_list_sync\.ps1|vt_self_check\.ps1|vt_check\.ps1|vt_ip_check\.ps1|dns_probe\.ps1|claude -p|Invoke-WebRequest'
# skip_ttp_update: the -updateTTP block is one region gated at its top by
# UPDATE_TTP; its internal error exits name the label and mark the region.
$gateRx = 'READONLY_MODE|SKIP_SRP|SKIP_THREAT_UPDATE|VT_SELF_SKIP|NETWORK_AVAIL|VT_CHECK|DNS_PROBE|UPDATE_TTP|skip_ttp_update'
$strictRx = '\breg add\b.*RunOnce|bcdedit /set|bcdedit /timeout'
$fail = @(); $total = 0
foreach ($b in $bats) {
    $path = Join-Path $Root $b
    $lines = [IO.File]::ReadAllLines($path)
    $sites = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = $lines[$i].TrimStart()
        if (-not $t) { continue }
        # Text, not code: echoed commands, comments, and lines written into the
        # report/undo script. An `addfix` payload also lands here -- it is a
        # command the USER may later run, never one the audit runs, so it is not
        # a read-only violation. Those payloads are not unchecked: they are the
        # subject of tools/lint_remediation.ps1, and the assertion below proves
        # the audit never executes the file it generates.
        if ($t -match '^(\(?echo\b|rem\b|::)') { continue }
        # Event-log searches pass attacker command strings as needles; they are data.
        if ($t -match 'select_lines\.ps1') { continue }
        if ($t -notmatch $siteRx) { continue }
        # The exit-time removal of our own RunOnce value is cleanup, not a mutation.
        if ($t -match '\breg delete\b' -and $t -match '_resume"') { continue }
        $sites++
        $from = [Math]::Max(0, $i - $Window)
        $ctx = ($lines[$from..$i] -join "`n")
        if ($t -match $strictRx) {
            if ($ctx -notmatch 'READONLY_MODE') { $fail += ("{0}:{1}: {2} -- must be gated by READONLY_MODE (no switch of its own)" -f $b, ($i + 1), $t) }
        } elseif ($ctx -notmatch $gateRx) {
            $fail += ("{0}:{1}: {2} -- no read-only gate within the preceding {3} lines" -f $b, ($i + 1), $t, $Window)
        }
    }
    if ($sites -lt 8) { $fail += ("{0}: only {1} mutation/egress site(s) found -- this lint is broken, not the code" -f $b, $sites) }
    $total += $sites
    $src = $lines -join "`n"
    foreach ($force in @('SKIP_SRP', 'SKIP_THREAT_UPDATE', 'VT_SELF_SKIP')) {
        if ($src -notmatch ('if "%READONLY_MODE%"=="1" set "' + $force + '=1"')) { $fail += ("{0}: :args_done does not force {1}=1 under -readonly" -f $b, $force) }
    }
    foreach ($refuse in @('VT_CHECK', 'DNS_PROBE', 'UPDATE_TTP')) {
        if ($src -notmatch ('if "%READONLY_MODE%"=="1" if "%' + $refuse + '%"=="1" goto :readonly_conflict')) { $fail += ("{0}: -readonly does not refuse {1}" -f $b, $refuse) }
    }
    if ($src -notmatch '(?m)^:readonly_conflict') { $fail += ("{0}: :readonly_conflict label missing" -f $b) }
    if ($src -notmatch 'READ-ONLY RUN -- this audit makes no changes') { $fail += ("{0}: the read-only banner is missing from the report header" -f $b) }
    # The audit GENERATES a remediation script full of machine-changing commands.
    # It must never RUN it -- that would break the read-only promise in the most
    # direct way possible. Any invocation of %REMEDIATION% outside an echo is a fail.
    foreach ($ln in $lines) {
        $tt = $ln.TrimStart()
        if ($tt -match '^(\(?echo\b|rem\b|::)') { continue }
        if ($tt -match '%REMEDIATION%' -and $tt -notmatch '^set\s' -and $tt -notmatch '>>?\s*"%REMEDIATION%"' -and $tt -notmatch 'if exist' -and $tt -notmatch '-RemediationPath') {
            $fail += ("{0}: the audit appears to EXECUTE the remediation script it generated: {1}" -f $b, $tt)
        }
    }
}
if ($fail.Count) {
    Write-Host ("[FAIL] {0} read-only invariant(s) broken -- -readonly could change a user's machine or reach the network:" -f $fail.Count)
    $fail | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] read-only tripwire holds: {0} mutation/egress sites across both scripts are gated; -readonly forces the skips and refuses the network switches." -f $total)
exit 0
