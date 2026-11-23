# lint_helper_done.ps1 -- run by lint.yml (Linux pwsh). Read-only.
# Usage: pwsh -NoProfile -File tools/lint_helper_done.ps1 [-Root <checkout>]
#
# Nine helpers' death used to read as a CLEAN section: their markers were read, but nothing checked the helper finished,
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
  @{ Tool = 'persistence_eval';        Done = 'dz_persist_done.txt';       Src = 'Write-MarkerFile -Path $DoneFile' },
  @{ Tool = 'startup_eval';            Done = 'dz_startup_done.txt';       Src = "'startup_done'" },
  @{ Tool = 'persistence_extra';       Done = 'dz_persist_extra_done.txt'; Src = "'persist_extra_done'" },
  @{ Tool = 'logon_persistence';       Done = 'dz_logon_done.txt';         Src = "Write-Marker 'done' 'done'" },
  @{ Tool = 'module_inspect';          Done = 'dz_module_done.txt';        Src = "'module_done'" },
  @{ Tool = 'service_signature_check'; Done = 'dz_svcgate_done.txt';       Src = '$DoneFile' },
  @{ Tool = 'edr_presence';            Done = 'dz_edr_done.txt';           Src = "'edr_done'" },
  @{ Tool = 'hosts_check';             Done = 'dz_hosts_done.txt';         Src = "'hosts_done'" },
  @{ Tool = 'bits_history';            Done = 'dz_bitshist_done.txt';      Src = "'bitshist_done'" })
function Get-Defects([hashtable]$Texts, [hashtable]$Sources) {
  $bad = @()
  foreach ($bat in $Texts.Keys) {
    $l = @($Texts[$bat] -split "\r?\n")
    foreach ($sp in $specs) {
      $t = $sp.Tool; $d = [regex]::Escape($sp.Done); $tag = "${bat} ${t}"
      $ci = [array]::FindIndex([string[]]$l, [Predicate[string]]{ param($x) $x -eq ('if exist "%SCRIPT_DIR%tools\' + $t + '.ps1" (') })
      if ($ci -lt 0) { $bad += "${tag}: no call site found"; continue }
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
$srcs = @{}; foreach ($sp in $specs) { $srcs[$sp.Tool] = [IO.File]::ReadAllText((Join-Path $Root ("tools/" + $sp.Tool + ".ps1"))) }
$bad = @(Get-Defects $texts $srcs)
if ($bad.Count) { $bad | ForEach-Object { "[FAIL] $_" }; exit 1 }
"[OK] all nine helpers: done marker cleared, a missing helper raised, a 'produced no verdict' backstop, in both bats ($($specs.Count * 2) call sites)"
# The check must be able to fail: drop one backstop, and one tool's marker.
$m = $texts.Clone(); $m['doze_sec_noAdmin.bat'] = $m['doze_sec_noAdmin.bat'] -replace '(?m)^if not exist "%TEMP%\\dz_hosts_done\.txt" if exist', 'if exist'
$ms = $srcs.Clone(); $ms['bits_history'] = $ms['bits_history'].Replace("'bitshist_done'", "'bitshist_x'")
$mb = @(Get-Defects $m $ms)
if (-not ($mb -match 'doze_sec_noAdmin\.bat hosts_check: no .produced no verdict. backstop') -or -not ($mb -match 'bits_history\.ps1 writes no done marker')) { "[FAIL] the check did not fail on a removed backstop and a removed marker: $($mb -join ' | ')"; exit 1 }
'[OK] the check fails on a removed backstop and on a tool that writes no done marker'
exit 0
