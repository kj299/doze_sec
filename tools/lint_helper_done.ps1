# lint_helper_done.ps1 -- run by lint.yml (Linux pwsh). Read-only.
# Usage: pwsh -NoProfile -File tools/lint_helper_done.ps1 [-Root <checkout>]
#
# Helpers whose death used to read as a CLEAN section (nine at first, then com_clsid_check): their markers were read, but nothing checked the helper finished,
# and a missing helper printed "[INFO] ... skipped". For each, in BOTH bats:
# the done marker is deleted before the call, a missing helper raises a row,
# and a "produced no verdict" backstop raises one when the marker is absent;
# and the helper's own source writes that marker. Then the same check is run
# on a copy with one backstop removed, and must fail.
param([string]$Root = '')
$ErrorActionPreference = 'Stop'
# Derived here, not in the param default: Windows PowerShell 5.1 leaves the
# script's own path empty while a param block is evaluated (CLAUDE.md).
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
$specs = @(
  @{ Tool = 'persistence_eval';        Done = 'dz_persist_done.txt';       Src = "# Written last: the caller raises `"produced no verdict`" when it is absent.`nif (`$DoneFile) { Write-MarkerFile -Path `$DoneFile -Value 'done' }"; Arg = $true; NotPart = '-Part OtherAccounts' },
  @{ Tool = 'startup_eval';            Done = 'dz_startup_done.txt';       Src = "'startup_done'" },
  @{ Tool = 'persistence_extra';       Done = 'dz_persist_extra_done.txt'; Src = "'persist_extra_done'" },
  @{ Tool = 'logon_persistence';       Done = 'dz_logon_done.txt';         Src = "Write-Marker 'done' 'done'" },
  @{ Tool = 'module_inspect';          Done = 'dz_module_done.txt';        Src = "'module_done'" },
  @{ Tool = 'service_signature_check'; Done = 'dz_svcgate_done.txt';       Src = "if (`$DoneFile) { Set-Content -LiteralPath `$DoneFile -Value 'done' -Encoding ASCII }"; Arg = $true },
  @{ Tool = 'edr_presence';            Done = 'dz_edr_done.txt';           Src = "'edr_done'" },
  @{ Tool = 'hosts_check';             Done = 'dz_hosts_done.txt';         Src = "'hosts_done'" },
  @{ Tool = 'bits_history';            Done = 'dz_bitshist_done.txt';      Src = "'bitshist_done'" },
  @{ Tool = 'com_clsid_check';         Done = 'dz_com_done.txt';           Src = "Write-Marker -Name 'com_done' -Sev 'done'" },
  @{ Tool = 'browser_extensions';      Done = 'dz_browserext_done.txt';    Src = "Set-Content -LiteralPath `$doneMarker -Value 'done' -Encoding ASCII" },
  @{ Tool = 'boot_activesetup_check';  Done = 'dz_bootas_done.txt';        Src = "Write-Marker -Name 'bootas_done' -Sev 'done'" })
function Get-Defects([hashtable]$Texts, [hashtable]$Sources) {
  $bad = @()
  foreach ($bat in $Texts.Keys) {
    $l = @($Texts[$bat] -split "\r?\n")
    foreach ($sp in $specs) {
      $t = $sp.Tool; $d = [regex]::Escape($sp.Done); $tag = "${bat} ${t}"
      # The call site whose call line is THIS check's (persistence_eval is called
      # twice; the default part is the one without -Part OtherAccounts), found
      # by content, never by which comes first.
      $ci = -1
      for ($q = 0; $q -lt $l.Count - 1; $q++) {
        if ($l[$q] -ne ('if exist "%SCRIPT_DIR%tools\' + $t + '.ps1" (')) { continue }
        if ($sp.NotPart -and $l[$q + 1].Contains($sp.NotPart)) { continue }
        $ci = $q; break
      }
      if ($ci -lt 0) { $bad += "${tag}: no call site found"; continue }
      if ($sp.Arg -and -not $l[$ci + 1].Contains('-DoneFile "%TEMP%\' + $sp.Done + '"')) { $bad += "${tag}: the call does not pass -DoneFile `"%TEMP%\$($sp.Done)`"" }
      if ($l[$ci - 1] -notmatch ('^del "%TEMP%\\' + $d + '" 2>nul$')) { $bad += "${tag}: the done marker is not deleted just before the call" }
      $ei = $ci + 2
      if ($l[$ei] -ne ') else (') { $bad += "${tag}: the call is not a single line followed by ') else ('"; continue }
      $close = [array]::FindIndex([string[]]$l, $ei + 1, [Predicate[string]]{ param($x) $x -eq ')' })
      $missing = $l[($ei + 1)..($close - 1)] -join "`n"
      if ($missing -notmatch 'call :dz_finding WARNING ') { $bad += "${tag}: a missing helper raises no row" }
      $want = 'if not exist "%TEMP%\' + $sp.Done + '" if exist "%SCRIPT_DIR%tools\' + $t + '.ps1" ('
      if ($l[$close + 1] -ne $want) { $bad += "${tag}: no 'produced no verdict' backstop right after the call"; continue }
      if ($l[$close + 2] -notmatch '^    echo \[WARNING\] .* produced no verdict -- NOT performed' -or $l[$close + 3] -notmatch '^    call :dz_finding WARNING ') { $bad += "${tag}: the backstop does not print and raise" }
    }
  }
  foreach ($sp in $specs) { if (-not $Sources[$sp.Tool].Contains($sp.Src)) { $bad += "tools\$($sp.Tool).ps1 writes no done marker ($($sp.Src))" } }
  return $bad
}
$texts = @{}; foreach ($b in 'doze_sec.bat', 'doze_sec_noAdmin.bat') { $texts[$b] = [IO.File]::ReadAllText((Join-Path $Root $b)) }
$srcs = @{}; foreach ($sp in $specs) { $srcs[$sp.Tool] = ([IO.File]::ReadAllText((Join-Path $Root ("tools/" + $sp.Tool + ".ps1")))) -replace "`r`n", "`n" }
$bad = @(Get-Defects $texts $srcs)
if ($bad.Count) { $bad | ForEach-Object { "[FAIL] $_" }; exit 1 }
"[OK] all $($specs.Count) helpers: done marker cleared, a missing helper raised, a 'produced no verdict' backstop, in both bats ($($specs.Count * 2) call sites)"
# The check must be able to fail: drop one backstop, and one tool's marker.
$m = $texts.Clone(); $m['doze_sec_noAdmin.bat'] = $m['doze_sec_noAdmin.bat'] -replace '(?m)^if not exist "%TEMP%\\dz_hosts_done\.txt" if exist', 'if exist'
$ms = $srcs.Clone(); $ms['bits_history'] = $ms['bits_history'].Replace("'bitshist_done'", "'bitshist_x'")
$m['doze_sec.bat'] = $m['doze_sec.bat'].Replace(' -DoneFile "%TEMP%\dz_svcgate_done.txt"', '')
$ms['persistence_eval'] = $ms['persistence_eval'].Replace("if (`$DoneFile) { Write-MarkerFile -Path `$DoneFile -Value 'done' }`n", '')
$mb = @(Get-Defects $m $ms)
if (-not ($mb -match 'doze_sec_noAdmin\.bat hosts_check: no .produced no verdict. backstop') -or -not ($mb -match 'bits_history\.ps1 writes no done marker') -or -not ($mb -match 'doze_sec\.bat service_signature_check: the call does not pass -DoneFile') -or -not ($mb -match 'persistence_eval\.ps1 writes no done marker')) { "[FAIL] the check did not fail on a removed backstop and a removed marker: $($mb -join ' | ')"; exit 1 }
'[OK] the check fails on a removed backstop, a call that no longer passes -DoneFile, and a tool that writes no done marker (including persistence_eval, whose OtherAccounts branch writes one of its own)'

# A MISSING TOOL IS A RAISED ROW, NOT AN [INFO] (group I1, 2026-11-25). Six
# checks still printed "[INFO] tools\X.ps1 not found -- ... skipped" and
# raised nothing, so cross_api_check (the rootkit check), log_gap_check and
# four more read as a CLEAN section when their tool was absent. Fail on any
# [INFO] or [SKIPPED] "tools\X.ps1 not found/missing" line in either bat,
# outside the allowlist below, which needs a reason.
$missAllow = @{
  # The optional threat-list updater: the audit still runs on the shipped
  # lists, so no check is lost when it is absent.
  'threat_list_sync' = 'optional updater; the shipped lists still apply'
}
function Get-UnraisedMissing([hashtable]$Texts) {
  $out = @()
  foreach ($bat in $Texts.Keys) {
    foreach ($m in [regex]::Matches($Texts[$bat], '(?m)^.*\[(INFO|SKIPPED)\][^\r\n]*tools\\([a-z0-9_]+)\.ps1 (not found|missing)')) {
      if (-not $missAllow.ContainsKey($m.Groups[2].Value)) { $out += ("{0}: a missing tools\{1}.ps1 prints {2} and raises nothing" -f $bat, $m.Groups[2].Value, $m.Groups[1].Value) }
    }
  }
  return $out
}
$um = @(Get-UnraisedMissing $texts)
if ($um.Count) { $um | ForEach-Object { "[FAIL] $_" }; '  A missing tool prints [WARNING] <check> NOT performed -- tools\X.ps1 not found, and calls :dz_finding.'; exit 1 }
"[OK] no missing tool prints an unraised [INFO] or [SKIPPED] in either bat ($($missAllow.Count) allowlisted with a reason)"
$m2 = $texts.Clone(); $m2['doze_sec.bat'] += "`r`n    echo  [INFO] tools\cross_api_check.ps1 not found -- cross-API consistency check skipped.>> `"%REPORT%`"`r`n"
if (-not (@(Get-UnraisedMissing $m2) -match 'cross_api_check')) { '[FAIL] the missing-tool check did not fail on the old [INFO] line'; exit 1 }
'[OK] the missing-tool check fails on the old cross_api_check [INFO] line'
exit 0
