# safety_invariants.ps1 -- prove the test harness cannot lock a person out of
# their own machine.
#
# WHY THIS EXISTS: a real user ran tests\manual_ci.ps1, was told by the runbook
# to start it and walk away for ~20 minutes, and came back locked out. The
# screen locked on the idle timer while detection_selftest.ps1 had a fake
# credential provider registered ({deadbeef-...} -> a DLL that does not exist).
# LogonUI loads credential providers to draw the lock and Ctrl+Alt+Del screens;
# with a broken one registered it could not render a usable unlock UI, and
# Ctrl+Alt+Del appeared dead. Recovery took a hard power-off.
#
# On an ephemeral CI runner this was invisible forever -- nothing ever locks it.
# The first fix tagged three plants as lock-screen-risky. An audit of ALL the
# plants found NINE on the logon/authentication path, including LSA packages
# that lsass loads AT BOOT, which are worse than the one that caused the
# incident. This test exists so that gap cannot silently reopen.
#
# It is static analysis -- it reads the harness rather than running it -- so it
# works on any platform, including the Linux CI runner and a dev box.
#
# Exit 0 = the safety invariants hold. Non-zero = a person could be locked out.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$fail  = @()

$selftest = Join-Path $root 'tests\detection_selftest.ps1'
$manual   = Join-Path $root 'tests\manual_ci.ps1'
$cleanup  = Join-Path $root 'tests\cleanup_selftest.ps1'
foreach ($f in @($selftest, $manual, $cleanup)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host ("[FAIL] missing: {0}" -f $f); exit 1 }
}
$sSrc = Get-Content -LiteralPath $selftest -Raw
$mSrc = Get-Content -LiteralPath $manual   -Raw
$cSrc = Get-Content -LiteralPath $cleanup  -Raw

# ---- 1. Every plant on the logon/auth path is tagged ----------------------
# Named explicitly: a new plant on this path must be added here deliberately,
# which is the point -- silence is what caused the incident.
$mustBeTagged = @(
    'Rogue Credential Provider DLL',
    'Winlogon Notify package',
    'Malicious screensaver',
    'Rogue LSA Authentication package',
    'Rogue LSA Notification package',
    'Rogue Network Provider',
    'UserInitMprLogonScript',
    'AppInit_DLLs set',
    'AppCert DLL registered'
)
# Split the file into case blocks and check each named case carries the tag.
$blocks = $sSrc -split '\r?\n    @\{'
if ($blocks.Count -lt 25) { $fail += ("case table did not parse -- only {0} block(s); this test is broken, not the code" -f $blocks.Count) }
$taggedCount = 0
foreach ($needle in $mustBeTagged) {
    $blk = @($blocks | Where-Object { $_ -like ("*Name   = '" + $needle + "*") })
    if ($blk.Count -eq 0) {
        $fail += ("case not found in harness: {0}" -f $needle)
    } elseif ($blk[0] -notmatch 'LockScreenRisk\s*=') {
        $fail += ("PLANT ON THE LOGON PATH IS NOT TAGGED LockScreenRisk: {0} -- a user could be locked out" -f $needle)
    } else { $taggedCount++ }
}
if ($taggedCount -lt $mustBeTagged.Count) { $fail += 'not every logon-path plant is tagged' }

# ---- 2. The switch exists and short-circuits BEFORE anything is planted ---
if ($sSrc -notmatch '\[switch\]\$NoLockScreenRisk') { $fail += '-NoLockScreenRisk switch is not declared' }
$skipIdx  = $sSrc.IndexOf('if ($NoLockScreenRisk -and $c.LockScreenRisk)')
$trackIdx = $sSrc.IndexOf('$planted += $c')
$plantIdx = $sSrc.IndexOf('& $c.Plant')
if ($skipIdx -lt 0)  { $fail += 'the skip branch is missing from the planting loop' }
elseif (-not ($skipIdx -lt $trackIdx -and $trackIdx -lt $plantIdx)) {
    $fail += 'the skip branch does not precede planting -- a skipped case would still touch the machine'
}

# ---- 3. A skip must be DECLARED, never silent ----------------------------
# The scoreboard reports SKIP only when MaySkip is set; the skip branch must
# set it, or the case would be counted as a REGRESS or vanish.
$skipBlock = ''
if ($skipIdx -ge 0) { $skipBlock = $sSrc.Substring($skipIdx, [Math]::Min(600, $sSrc.Length - $skipIdx)) }
if ($skipBlock -notmatch '\$c\.MaySkip\s*=') { $fail += 'the skip branch does not set MaySkip -- the skip would not be declared in the scoreboard' }

# ---- 4. manual_ci must be SAFE BY DEFAULT --------------------------------
if ($mSrc -notmatch '\[switch\]\$AllowLockScreenRisk') { $fail += 'manual_ci has no -AllowLockScreenRisk opt-in' }
if ($mSrc -notmatch 'if \(-not \$AllowLockScreenRisk\)') { $fail += 'manual_ci is not safe by default' }
if ($mSrc -notmatch 'NoLockScreenRisk') { $fail += 'manual_ci never passes -NoLockScreenRisk to the harness' }
# The opt-in must name the actual consequence, not a vague caution.
if ($mSrc -notmatch 'locked\s*out') { $fail += 'the -AllowLockScreenRisk warning does not say the user could be locked out' }

# ---- 5. Standalone cold recovery must cover every risky artifact ---------
$mustClean = @(
    'Credential Providers', 'Winlogon\Notify', 'SCRNSAVE',
    'Notification Packages', 'Authentication Packages', 'ProviderOrder',
    'dz_selftest_np', 'UserInitMprLogonScript', 'AppInit_DLLs', 'AppCertDlls'
)
foreach ($m in $mustClean) {
    if ($cSrc -notmatch [regex]::Escape($m)) {
        $fail += ("cleanup_selftest.ps1 does not remove: {0} -- an interrupted run could leave it behind" -f $m)
    }
}

# ---- verdict --------------------------------------------------------------
if ($fail.Count) {
    Write-Host ''
    Write-Host ("[FAIL] {0} safety invariant(s) broken -- a person could be locked out of their machine:" -f $fail.Count)
    $fail | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] Safety invariants hold: {0} logon-path plants tagged and skipped before planting," -f $taggedCount)
Write-Host '     every skip declared, manual_ci safe by default with a warning that names the'
Write-Host '     consequence, and standalone cold recovery covers all of them.'
exit 0
