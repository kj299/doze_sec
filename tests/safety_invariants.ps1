# safety_invariants.ps1 -- prove the test harness cannot lock a person out of
# their own machine, and that every plant declares its blast radius.
#
# WHY THIS EXISTS: a real user ran tests\manual_ci.ps1, was told by the runbook
# to start it and walk away for ~20 minutes, and came back locked out. The
# screen locked on the idle timer while detection_selftest.ps1 had a fake
# credential provider registered ({deadbeef-...} -> a DLL that does not exist).
# LogonUI loads credential providers to draw the lock and Ctrl+Alt+Del screens;
# with a broken one registered it could not render a usable unlock UI, and
# Ctrl+Alt+Del appeared dead. Recovery took a hard power-off.
#
# The first fix tagged THREE plants as lock-screen-risky. An audit of all the
# plants found NINE on the logon/authentication path, including LSA packages
# that lsass loads AT BOOT. The first version of this file then checked those
# nine by name -- an allowlist, so a tenth would have been invisible to it.
#
# This version inverts the burden. Every case in the harness must carry a
# blast-radius manifest (Touches = what it changes on the host, Affects =
# which of logon / boot / network / defense it can hit), and the axes are also
# INFERRED from what the Plant body touches: a plant that writes to a known
# logon-path location without declaring 'logon' fails here, whatever its name.
# "I audited three, the answer was nine" is now structurally impossible.
#
# It is static analysis over the PowerShell AST -- it reads the harness rather
# than running it -- so it works on any platform, including the Linux CI
# runner and a dev box.
#
#   -Root <dir>   check a different checkout (used by -SelfTest)
#   -SelfTest     mutate copies of the harness and assert each mutation FAILS;
#                 a check that cannot fail is not a check.
#
# Exit 0 = the safety invariants hold. Non-zero = a person could be locked out,
# or a plant is undeclared.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$fail = @()

$harness = Join-Path $Root 'tests/detection_selftest.ps1'
$manual   = Join-Path $Root 'tests/manual_ci.ps1'
$cleanup  = Join-Path $Root 'tests/cleanup_selftest.ps1'
$smoke    = Join-Path $Root 'tests/noadmin_smoke.ps1'
foreach ($f in @($harness, $manual, $cleanup, $smoke)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host ("[FAIL] missing: {0}" -f $f); exit 1 }
}

# ---- Self-test: the check must fail when the claim is false ----------------
if ($SelfTest) {
    $mutations = @(
        @{ Name = 'undeclared plant (Touches line removed)'
           File = 'detection_selftest'
           Find = "(?m)^\s*Touches= @\('registry:HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest[^\r\n]*\r?\n"
           Repl = ''
           Expect = 'no Touches declaration' },
        @{ Name = 'logon-path plant without a LockScreenRisk reason'
           File = 'detection_selftest'
           Find = "(?m)^\s*LockScreenRisk = 'registers a credential provider[^\r\n]*\r?\n"
           Repl = ''
           Expect = 'no LockScreenRisk' },
        @{ Name = 'logon-path plant that denies the logon axis (inference must catch it)'
           File = 'detection_selftest'
           Find = "(Credential Providers\\\{deadbeef[^\r\n]*\r?\n[^\r\n]*\r?\n\s*Affects= )@\('logon'\)"
           Repl = '$1@()'
           Expect = 'touches a logon-path location' },
        @{ Name = 'cold recovery no longer covers a declared target'
           File = 'cleanup_selftest'
           Find = "(?m)^Remove-RegKey \(`"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify[^\r\n]*\r?\n"
           Repl = ''
           Expect = 'cleanup_selftest.ps1 does not cover' },
        @{ Name = 'smoke test plants an account without declaring it'
           File = 'noadmin_smoke'
           Find = "(?m)^\s*'account:[^\r\n]*\r?\n"
           Repl = ''
           Expect = 'noadmin_smoke.ps1' }
    )
    # Mutation 3 also trips the LockScreenRisk<->logon rule; the assertion is
    # that the INFERENCE message is among the failures, which is the rule that
    # makes an undeclared logon-path plant impossible regardless of its name.
    $tmpBase = Join-Path ([IO.Path]::GetTempPath()) ("dz_sv_selftest_{0}" -f [guid]::NewGuid().ToString('N'))
    $ran = 0; $bad = @()
    try {
        foreach ($m in $mutations) {
            $dir = Join-Path $tmpBase ("m{0}" -f $ran)
            New-Item -ItemType Directory -Path (Join-Path $dir 'tests') -Force | Out-Null
            foreach ($f in @($harness, $manual, $cleanup, $smoke)) { Copy-Item -LiteralPath $f -Destination (Join-Path $dir 'tests') -Force }
            $target = Join-Path $dir ("tests/{0}.ps1" -f $m.File)
            $src = Get-Content -LiteralPath $target -Raw
            $mut = [regex]::Replace($src, $m.Find, $m.Repl, 1)
            if ($mut -eq $src) { $bad += ("{0}: the mutation did not apply -- the self-test is broken, not the code" -f $m.Name); $ran++; continue }
            [IO.File]::WriteAllText($target, $mut)
            $out = & $PSCommandPath -Root $dir *>&1 | Out-String
            $code = $LASTEXITCODE
            if ($code -eq 0) { $bad += ("{0}: the check PASSED on the mutated harness" -f $m.Name) }
            elseif ($out -notmatch [regex]::Escape($m.Expect)) { $bad += ("{0}: failed, but not for the expected reason ('{1}' absent). Output:`n{2}" -f $m.Name, $m.Expect, $out) }
            else { Write-Host ("  [OK] fails as it must: {0}" -f $m.Name) }
            $ran++
        }
    } finally {
        Remove-Item -LiteralPath $tmpBase -Recurse -Force -EA SilentlyContinue
    }
    if ($ran -lt $mutations.Count) { $bad += 'not every mutation ran' }
    if ($bad.Count) {
        Write-Host ("[FAIL] safety_invariants self-test: {0} problem(s):" -f $bad.Count)
        $bad | ForEach-Object { Write-Host ("  - " + $_) }
        exit 1
    }
    Write-Host ("[OK] safety_invariants self-test: all {0} mutations fail the check, each for the right reason." -f $ran)
    exit 0
}

# ---- Parse the harness --------------------------------------------------
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($harness, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count) { Write-Host ("[FAIL] detection_selftest.ps1 does not parse: {0}" -f $errs[0].Message); exit 1 }
$sSrc = Get-Content -LiteralPath $harness -Raw
$mSrc = Get-Content -LiteralPath $manual   -Raw
$cSrc = Get-Content -LiteralPath $cleanup  -Raw

$casesAssign = $ast.Find({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$cases' }, $false)
if (-not $casesAssign) { Write-Host '[FAIL] $cases assignment not found in detection_selftest.ps1 -- this check is broken, not the code'; exit 1 }
$allHts = $casesAssign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
# Direct children only: a nested hashtable inside a case is not a case.
$caseAsts = @()
foreach ($ht in $allHts) {
    $p = $ht.Parent; $direct = $true
    while ($p -and ($p -ne $casesAssign)) {
        if ($p -is [System.Management.Automation.Language.HashtableAst]) { $direct = $false; break }
        $p = $p.Parent
    }
    if ($direct) { $caseAsts += $ht }
}
if ($caseAsts.Count -lt 30) { Write-Host ("[FAIL] only {0} case(s) parsed from the harness -- this check is broken, not the code" -f $caseAsts.Count); exit 1 }

# Top-level variable assignments: the plant targets live in these, not in the
# case bodies, so axis inference must see through one or two levels of them.
$varRhs = @{}
foreach ($as in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $false)) {
    $lhs = $as.Left.Extent.Text -replace '^\$(script:)?', ''
    if (-not $varRhs.ContainsKey($lhs)) { $varRhs[$lhs] = $as.Right.Extent.Text }
}

function Get-Literals($valueAst) {
    # Every string constant under the value; also flag anything that is not a
    # literal, because the manifest must be greppable without evaluation.
    $lits = @($valueAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
    $nonLit = @($valueAst.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
        $n -is [System.Management.Automation.Language.VariableExpressionAst] -or
        $n -is [System.Management.Automation.Language.BinaryExpressionAst] -or
        $n -is [System.Management.Automation.Language.CommandAst] }, $true))
    $isArray = [bool]($valueAst.Find({ param($n) $n -is [System.Management.Automation.Language.ArrayExpressionAst] }, $true))
    return @{ Lits = $lits; NonLiteral = ($nonLit.Count -gt 0); IsArray = $isArray }
}

$kinds = @('registry', 'file', 'service', 'account', 'network', 'firewall', 'defender', 'hosts')
$axes  = @('logon', 'boot', 'network', 'defense')
# Axis inference: if the plant (or a variable it uses) mentions one of these,
# the axis MUST be declared. Extend this list when a new plant location is
# added; the cleanup-coverage check below is the reminder.
$axisKeywords = @{
    logon   = @('Credential Providers', 'Winlogon\Notify', 'SCRNSAVE', 'Notification Packages', 'Authentication Packages',
                'NetworkProvider', 'UserInitMprLogonScript', 'AppInit_DLLs', 'AppCertDlls')
    boot    = @('Authentication Packages', 'Notification Packages', 'BootExecute', "'start=' 'auto'")
    network = @('portproxy', 'NetFirewallProfile', 'NetworkProvider', 'drivers\etc\hosts')
    defense = @('WDigest', 'MpPreference', 'NetFirewallProfile', '/active:yes')
}

# ---- 1. Every case carries a complete, literal, consistent manifest --------
$caseCount = 0; $plantCount = 0; $logonCount = 0; $touchCount = 0; $names = @{}
foreach ($ht in $caseAsts) {
    $caseCount++
    $kv = @{}
    foreach ($pair in $ht.KeyValuePairs) {
        $k = $pair.Item1.Extent.Text.Trim("'`"")
        $kv[$k] = $pair.Item2
    }
    $name = '(unnamed case at line {0})' -f $ht.Extent.StartLineNumber
    if ($kv.ContainsKey('Name')) {
        $nl = $kv['Name'].Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
        if ($nl) { $name = $nl.Value }
    }
    if ($names.ContainsKey($name)) { $fail += ("duplicate case name: {0}" -f $name) }
    $names[$name] = $true

    # Plant body (empty = a piggyback case that plants nothing).
    $plantEmpty = $true; $plantText = ''
    if ($kv.ContainsKey('Plant')) {
        $sb = $kv['Plant'].Find({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)
        if ($sb) {
            $plantText = $sb.Extent.Text
            if ($sb.ScriptBlock.EndBlock -and $sb.ScriptBlock.EndBlock.Statements.Count -gt 0) { $plantEmpty = $false }
        }
    } else { $fail += ("{0}: no Plant block" -f $name) }
    if (-not $plantEmpty) { $plantCount++ }

    if (-not $kv.ContainsKey('Touches')) { $fail += ("{0}: no Touches declaration -- every plant must declare what it changes on the host" -f $name); continue }
    if (-not $kv.ContainsKey('Affects')) { $fail += ("{0}: no Affects declaration -- every plant must declare which of logon/boot/network/defense it can hit" -f $name); continue }
    $t = Get-Literals $kv['Touches']
    $a = Get-Literals $kv['Affects']
    if (-not $t.IsArray -or $t.NonLiteral) { $fail += ("{0}: Touches must be an array of literal strings" -f $name) }
    if (-not $a.IsArray -or $a.NonLiteral) { $fail += ("{0}: Affects must be an array of literal strings" -f $name) }
    $touches = @($t.Lits); $affects = @($a.Lits)
    $touchCount += $touches.Count

    if ($plantEmpty -and $touches.Count)        { $fail += ("{0}: declares Touches but its Plant is empty" -f $name) }
    if (-not $plantEmpty -and -not $touches.Count) { $fail += ("{0}: PLANTS SOMETHING BUT DECLARES NOTHING (Touches is empty)" -f $name) }
    foreach ($e in $touches) {
        $kind = ($e -split ':', 2)[0]
        if (($kinds -notcontains $kind) -or ($e -notmatch '^[a-z]+:\S')) { $fail += ("{0}: malformed Touches entry '{1}' (kind:target[|coldkey])" -f $name, $e); continue }
        # Standalone cold recovery must cover every declared target.
        $body = ($e -split ':', 2)[1]
        $parts = $body -split '\|', 2
        $coldkey = if ($parts.Count -eq 2) { $parts[1] } else { ($parts[0] -split '\\')[-1] }
        if (-not $coldkey.Trim()) { $fail += ("{0}: Touches entry '{1}' has an empty cold-recovery key" -f $name, $e); continue }
        if ($cSrc.IndexOf($coldkey, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            $fail += ("{0}: cleanup_selftest.ps1 does not cover '{1}' (looked for '{2}') -- an interrupted run could leave it behind" -f $name, $e, $coldkey)
        }
    }
    foreach ($x in $affects) { if ($axes -notcontains $x) { $fail += ("{0}: unknown Affects axis '{1}'" -f $name, $x) } }

    # logon <-> LockScreenRisk, both directions: the runtime skip keys on the
    # axis, the skip message on the reason. Neither may exist without the other.
    $hasLogon = ($affects -contains 'logon')
    $hasReason = $kv.ContainsKey('LockScreenRisk')
    if ($hasLogon) { $logonCount++ }
    if ($hasLogon -and -not $hasReason) { $fail += ("{0}: Affects logon but has no LockScreenRisk reason (the skip message would be empty)" -f $name) }
    if ($hasReason -and -not $hasLogon) { $fail += ("{0}: has LockScreenRisk but does not declare Affects logon -- -NoLockScreenRisk would NOT skip it; a user could be locked out" -f $name) }

    # Axis inference from the plant body, seen through the variables it uses.
    if (-not $plantEmpty) {
        $text = $plantText
        $seen = @{}
        $queue = @([regex]::Matches($plantText, '\$(?:script:)?([A-Za-z_][A-Za-z0-9_]*)') | ForEach-Object { $_.Groups[1].Value })
        for ($depth = 0; $depth -lt 2; $depth++) {
            $next = @()
            foreach ($v in $queue) {
                if ($seen.ContainsKey($v) -or -not $varRhs.ContainsKey($v)) { continue }
                $seen[$v] = $true
                $text += "`n" + $varRhs[$v]
                $next += @([regex]::Matches($varRhs[$v], '\$(?:script:)?([A-Za-z_][A-Za-z0-9_]*)') | ForEach-Object { $_.Groups[1].Value })
            }
            $queue = $next
        }
        foreach ($axis in $axes) {
            foreach ($kw in $axisKeywords[$axis]) {
                if ($text.IndexOf($kw, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and ($affects -notcontains $axis)) {
                    $fail += ("{0}: plant touches a {1}-path location ('{2}') but does not declare Affects '{1}'" -f $name, $axis, $kw)
                }
            }
        }
    }
}
if ($caseCount -lt 30)  { $fail += ("only {0} cases examined -- vacuous" -f $caseCount) }
if ($logonCount -lt 9)  { $fail += ("only {0} logon-path plants declared; nine are known to exist -- one has lost its declaration" -f $logonCount) }
if ($touchCount -lt 25) { $fail += ("only {0} Touches entries examined -- vacuous" -f $touchCount) }

# ---- 2. The switch exists and short-circuits BEFORE anything is planted ---
if ($sSrc -notmatch '\[switch\]\$NoLockScreenRisk') { $fail += '-NoLockScreenRisk switch is not declared' }
$skipIdx  = $sSrc.IndexOf("if (`$NoLockScreenRisk -and (@(`$c.Affects) -contains 'logon'))")
$trackIdx = $sSrc.IndexOf('$planted += $c')
$plantIdx = $sSrc.IndexOf('& $c.Plant')
if ($skipIdx -lt 0)  { $fail += 'the skip branch is missing from the planting loop, or no longer keys on Affects logon' }
elseif (-not ($skipIdx -lt $trackIdx -and $trackIdx -lt $plantIdx)) {
    $fail += 'the skip branch does not precede planting -- a skipped case would still touch the machine'
}
# The runtime manifest check must run before the planting loop, too.
$rtIdx = $sSrc.IndexOf('blast-radius manifest is incomplete')
if ($rtIdx -lt 0 -or ($plantIdx -ge 0 -and $rtIdx -gt $plantIdx)) { $fail += 'the harness does not validate the manifest at runtime before planting' }

# ---- 3. A skip must be DECLARED, never silent ----------------------------
$skipBlock = ''
if ($skipIdx -ge 0) { $skipBlock = $sSrc.Substring($skipIdx, [Math]::Min(600, $sSrc.Length - $skipIdx)) }
if ($skipBlock -notmatch '\$c\.MaySkip\s*=') { $fail += 'the skip branch does not set MaySkip -- the skip would not be declared in the scoreboard' }

# ---- 4. manual_ci must be SAFE BY DEFAULT --------------------------------
if ($mSrc -notmatch '\[switch\]\$AllowLockScreenRisk') { $fail += 'manual_ci has no -AllowLockScreenRisk opt-in' }
if ($mSrc -notmatch 'if \(-not \$AllowLockScreenRisk\)') { $fail += 'manual_ci is not safe by default' }
if ($mSrc -notmatch 'NoLockScreenRisk') { $fail += 'manual_ci never passes -NoLockScreenRisk to the harness' }
if ($mSrc -notmatch 'locked\s*out') { $fail += 'the -AllowLockScreenRisk warning does not say the user could be locked out' }

# ---- 5. The non-admin smoke test declares its plants too -------------------
$sTok = $null; $sErr = $null
$sAst = [System.Management.Automation.Language.Parser]::ParseFile($smoke, [ref]$sTok, [ref]$sErr)
if ($sErr -and $sErr.Count) { $fail += ("noadmin_smoke.ps1 does not parse: {0}" -f $sErr[0].Message) }
else {
    $smokeSrc = Get-Content -LiteralPath $smoke -Raw
    $decl = @{}
    foreach ($as in $sAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $false)) {
        $l = $as.Left.Extent.Text
        if ($l -eq '$Touches' -or $l -eq '$Affects') { $decl[$l] = Get-Literals $as.Right }
    }
    if (-not $decl.ContainsKey('$Touches')) { $fail += 'noadmin_smoke.ps1 has no $Touches blast-radius declaration' }
    if (-not $decl.ContainsKey('$Affects')) { $fail += 'noadmin_smoke.ps1 has no $Affects blast-radius declaration' }
    if ($decl.ContainsKey('$Touches')) {
        $st = @($decl['$Touches'].Lits)
        $verbs = @{ 'New-LocalUser' = 'account:'; 'icacls' = 'file:'; 'Set-Service' = 'service:'; 'WDigest' = 'registry:' }
        foreach ($verb in $verbs.Keys) {
            if ($smokeSrc.IndexOf($verb, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                if (-not @($st | Where-Object { $_ -like ($verbs[$verb] + '*') }).Count) {
                    $fail += ("noadmin_smoke.ps1 uses {0} but declares no '{1}' entry in `$Touches" -f $verb, $verbs[$verb])
                }
            }
        }
        foreach ($e in $st) { if (($kinds -notcontains (($e -split ':', 2)[0]))) { $fail += ("noadmin_smoke.ps1: malformed Touches entry '{0}'" -f $e) } }
    }
    if ($decl.ContainsKey('$Affects')) {
        $sa = @($decl['$Affects'].Lits)
        foreach ($x in $sa) { if ($axes -notcontains $x) { $fail += ("noadmin_smoke.ps1: unknown Affects axis '{0}'" -f $x) } }
        if ($smokeSrc -match 'WDigest' -and ($sa -notcontains 'defense')) { $fail += 'noadmin_smoke.ps1 plants WDigest but does not declare Affects defense' }
    }
}

# ---- verdict --------------------------------------------------------------
if ($fail.Count) {
    Write-Host ''
    Write-Host ("[FAIL] {0} safety invariant(s) broken -- a person could be locked out of their machine, or a plant is undeclared:" -f $fail.Count)
    $fail | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] Safety invariants hold: {0} cases, {1} plants, {2} declared host mutations, {3} logon-path plants;" -f $caseCount, $plantCount, $touchCount, $logonCount)
Write-Host '     every plant declares its blast radius and the inferred axes agree, every logon-path'
Write-Host '     plant is skipped before planting and the skip declared, standalone cold recovery'
Write-Host '     covers every declared target, and manual_ci is safe by default with a warning'
Write-Host '     that names the consequence.'
exit 0
