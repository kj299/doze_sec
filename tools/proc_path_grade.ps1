# proc_path_grade.ps1 -- grade processes running from user-profile paths.
#
# WHY: Section 4 matched a path list and raised WARNING "Investigate now" for
# every hit, while the summary dashboard graded the SAME processes on their
# signature and reported "[INFO] Processes from user-profile paths, all validly
# signed". One field report carried both verdicts about the same six brave.exe
# processes. A reader cannot act on a tool that contradicts itself, and the
# alarming half was the wrong one: Brave, Chrome, Edge, Slack, Teams and VS Code
# all install per-user under \AppData\ by design, so \AppData\ alone is not a
# signal -- treating it as one is how a tool trains its reader to ignore it.
#
# THE RULE (the dashboard's, now shared so the two cannot drift apart):
#   * \Temp\, \Downloads\, \Users\Public\, \$Recycle -- suspicious whatever the
#     signature says. Nothing legitimate runs its main binary from there.
#   * \AppData\ -- only suspicious when the binary is NOT validly signed.
#
# An unreadable or unsignable file is reported as unsigned: for this decision
# "I could not verify it" belongs with the risky half, not the safe half.
#
# Read-only. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    # NOT Mandatory: a mandatory parameter makes -SelfTest sit at an
    # interactive prompt instead of running, which in CI is a hang rather than
    # an error. Validated below, where it is actually needed.
    [string]$Path,
    [string]$MarkerFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and NO -EA SilentlyContinue -- a swallowed failure here is
    # exactly how a field test lost its finding. Kept as a LOCAL function in
    # each tool, like Write-Marker: a shared file would add a missing-file
    # mode that breaks every tool at once, and the test is the propagation
    # mechanism.
    param([string]$Path, [string]$Value = 'hit')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# IN SCOPE: the user-profile locations this check is about. Everything else --
# Program Files, System32, WindowsApps -- is NOT graded at all.
#
# This filter is the fix for a regression I shipped in #198. The caller passes
# the FULL Win32_Process dump (doze_sec.bat:1916); select_lines.ps1 filters it
# for display, and I pointed this grader at the unfiltered dump. It therefore
# graded all 110 running processes and reported seven Microsoft Store binaries
# under C:\Program Files\WindowsApps as suspicious on a clean machine -- they
# are MSIX/catalog-signed, so Get-AuthenticodeSignature on the inner .exe does
# not return Valid. Worse than the contradiction it replaced.
#
# The tool now decides its own scope rather than trusting the caller to have
# filtered: one implementation of the whole rule, filter and grade together.
$script:InScope = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Recycle|\\Users\\Public\\'

# Within scope, paths where a running binary is suspicious regardless of signer.
$script:HighRisk = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\$Recycle'

function Get-PathsFromDump {
    param([string]$File)
    $out = @()
    foreach ($line in (Get-Content -LiteralPath $File -EA SilentlyContinue)) {
        # A path may contain spaces, so take everything from the drive letter on
        # rather than splitting on whitespace.
        $m = [regex]::Match($line, '[A-Za-z]:\\.*$')
        if ($m.Success) { $out += $m.Value.Trim() }
    }
    return ($out | Sort-Object -Unique)
}

function Get-Verdict {
    param([string[]]$Paths, [scriptblock]$SigCheck)
    $bad = @()
    foreach ($p in $Paths) {
        if ($p -notmatch $script:InScope) { continue }
        if ($p -match $script:HighRisk) { $bad += $p; continue }
        $status = & $SigCheck $p
        if ($status -ne 'Valid') { $bad += $p }
    }
    $inScope = @($Paths | Where-Object { $_ -match $script:InScope })
    return @{ Bad = @($bad); Total = $inScope.Count; Seen = @($Paths).Count }
}

$script:RealSigCheck = {
    param([string]$File)
    try {
        if (-not (Test-Path -LiteralPath $File)) { return 'Missing' }
        return [string](Get-AuthenticodeSignature -LiteralPath $File -EA Stop).Status
    } catch { return 'Unverifiable' }
}

if ($SelfTest) {
    $fails = 0
    $sig = { param($f) if ($f -like '*signed*') { 'Valid' } else { 'NotSigned' } }
    $cases = @(
        @{ Name = 'AppData + validly signed is NOT a finding'
           Paths = @('C:\Users\u\AppData\Local\BraveSoftware\signed-brave.exe'); ExpectBad = 0 },
        @{ Name = 'AppData + unsigned IS a finding'
           Paths = @('C:\Users\u\AppData\Local\Evil\dropper.exe');               ExpectBad = 1 },
        @{ Name = 'Temp is a finding even when validly signed'
           Paths = @('C:\Users\u\AppData\Local\Temp\signed-thing.exe');          ExpectBad = 1 },
        @{ Name = 'Downloads is a finding even when validly signed'
           Paths = @('C:\Users\u\Downloads\signed-thing.exe');                   ExpectBad = 1 },
        @{ Name = 'Users\Public is a finding even when validly signed'
           Paths = @('C:\Users\Public\signed-thing.exe');                        ExpectBad = 1 },
        # The #198 regression, pinned by its real-world instances. These are
        # NOT user-profile paths, so they must never be graded at all -- and
        # both are catalog-signed, so a signature check on them returns
        # NotSigned and would flag them if scope were not enforced first.
        @{ Name = 'Program Files is out of scope, unsigned or not'
           Paths = @('C:\Program Files\WiFiman Desktop\wifiman-desktopd.exe');   ExpectBad = 0 },
        @{ Name = 'WindowsApps (MSIX, catalog-signed) is out of scope'
           Paths = @('C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_22607.1401.4.0_x64__8wekyb3d8bbwe\StoreExperienceHost.exe'); ExpectBad = 0 },
        @{ Name = 'System32 is out of scope'
           Paths = @('C:\Windows\System32\svchost.exe');                         ExpectBad = 0 },
        # And scope must not swallow a real finding sitting beside them.
        @{ Name = 'a mixed dump grades only the user-profile paths'
           Paths = @('C:\Windows\System32\svchost.exe',
                     'C:\Program Files\WindowsApps\Whatever\app.exe',
                     'C:\Users\u\AppData\Local\Temp\dropper.exe');            ExpectBad = 1 }
    )
    foreach ($c in $cases) {
        $r = Get-Verdict -Paths $c.Paths -SigCheck $sig
        if ($r.Bad.Count -eq $c.ExpectBad) { Write-Output "[OK]   $($c.Name)" }
        else { Write-Output "[FAIL] $($c.Name): got $($r.Bad.Count) finding(s), expected $($c.ExpectBad)"; $fails++ }
    }
    # An unverifiable file must land with the risky half, never the safe half.
    $r = Get-Verdict -Paths @('C:\Users\u\AppData\Local\App\gone.exe') -SigCheck { param($f) 'Unverifiable' }
    if ($r.Bad.Count -eq 1) { Write-Output '[OK]   a signature that cannot be verified counts as unsigned' }
    else { Write-Output '[FAIL] an unverifiable signature was treated as clean'; $fails++ }
    # The dump parser must survive a path containing spaces.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_ppg_' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.txt')
    Set-Content -LiteralPath $tmp -Value 'winword.exe  777  C:\Program Files\Microsoft Office\winword.exe'
    $got = @(Get-PathsFromDump -File $tmp)
    Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
    if ($got.Count -eq 1 -and $got[0] -eq 'C:\Program Files\Microsoft Office\winword.exe') {
        Write-Output '[OK]   a path containing spaces is parsed whole'
    } else { Write-Output "[FAIL] path with spaces parsed as: $($got -join ' | ')"; $fails++ }

    if ($fails) { Write-Output "[FAIL] $fails proc_path_grade self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] proc_path_grade self-test: AppData alone is context, Temp/Downloads/Public are findings, unverifiable counts as unsigned.'
    exit 0
}

if (-not $Path) { Write-Output '[SKIPPED] proc_path_grade: -Path <process dump> is required (or -SelfTest); the suspicious-path check was NOT graded.'; exit 1 }
if (-not (Test-Path -LiteralPath $Path)) { Write-Output "[SKIPPED] proc_path_grade: dump not found at $Path; the suspicious-path check was NOT graded."; exit 1 }
$paths = @(Get-PathsFromDump -File $Path)
$v = Get-Verdict -Paths $paths -SigCheck $script:RealSigCheck
if ($v.Total -eq 0) {
    Write-Output ("[OK] No processes running from user-profile locations ({0} process path(s) examined; Program Files, System32 and WindowsApps are out of scope for this check)." -f $v.Seen)
    exit 0
}
if ($v.Bad.Count -eq 0) {
    Write-Output ("[INFO] {0} of {1} process path(s) are under user-profile locations, all validly signed -- per-user installs (Brave, Chrome, Edge, Slack, Teams, VS Code) live there by design. Context, not a finding." -f $v.Total, $v.Seen)
    exit 0
}
Write-Output ("[WARNING] {0} of {1} user-profile process path(s) are suspicious -- running from \Temp\, \Downloads\, \Users\Public\ or \`$Recycle, or not validly signed:" -f $v.Bad.Count, $v.Total)
$v.Bad | ForEach-Object { Write-Output ('  ' + $_) }
Write-MarkerFile -Path $MarkerFile
exit 0
