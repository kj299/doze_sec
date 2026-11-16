# system_dll_sig_check.ps1 -- is a DLL that programs load by NAME sitting in a
# system folder without Microsoft's signature (T1574.001, DLL search-order
# hijacking)? version.dll, winhttp.dll, dbghelp.dll and the rest are loaded by
# name; a copy dropped where a program looks first runs inside that program.
#
# The check was an inline block:
#   $sig = Get-AuthenticodeSignature $f -EA SilentlyContinue
#   if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { hit }
# so a signature that could not be READ ($sig empty, or Status UnknownError)
# was reported as an unsigned DLL -- a finding the tool never observed -- and
# any valid signer whose subject merely contained the word "Microsoft" passed.
#
# THE RULE (pure, in Get-DllVerdict, pinned by -SelfTest):
#   * Valid, signed by O=Microsoft Corporation -> fine;
#   * Valid by anyone else, NotSigned, HashMismatch, NotTrusted -> the WARNING
#     the bats always printed, each file listed with status, signer, size and
#     times;
#   * UnknownError, a file Windows cannot evaluate, or an exception -> NOT
#     checked: a raised gap, never counted as unsigned;
#   * a folder that could not be listed -> a gap; a folder that does not exist
#     (SysWOW64 on 32-bit Windows) is said, not graded;
#   * a hit and a gap are both raised; [OK] says how many files were checked.
# Markers: dz_sysdll_hit / dz_sysdll_gap / dz_sysdll_done (written last).
#
# Usage:
#   powershell -File tools\system_dll_sig_check.ps1 [-MarkerDir <dir>]
#   powershell -File tools\system_dll_sig_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    # Only CI changes this: scratch folders holding planted look-alikes.
    [string[]]$Dirs,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
$script:Names = @('version.dll', 'winhttp.dll', 'dbghelp.dll', 'dbgcore.dll', 'wer.dll', 'ualapi.dll', 'WTSAPI32.dll', 'msasn1.dll', 'npmproxy.dll')
$script:MsSigner = '(^|,\s*)O=Microsoft Corporation(\s*,|$)'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -ErrorAction Stop | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -ErrorAction Stop
}

function ConvertTo-PrintableText {
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 260) { $t = $t.Substring(0, 260) + '...' }
    return $t
}

# PURE. One file: @{ Status; Signer; Error } -> 'ok' | 'hit' | 'unchecked'.
function Get-DllGrade {
    param($F)
    if ([string]$F.Error) { return 'unchecked' }
    switch ([string]$F.Status) {
        'Valid' { if ([string]$F.Signer -match $script:MsSigner) { return 'ok' } else { return 'hit' } }
        'NotSigned' { return 'hit' }
        'HashMismatch' { return 'hit' }
        'NotTrusted' { return 'hit' }
        default { return 'unchecked' }
    }
}

# PURE. $Dirs: @( @{ Dir; State = ok|missing|unreadable; Error; Files = @( @{
# Path; Status; Signer; Error; Facts } ) } ). Returns @{ Lines; Hit; Gap }.
function Get-DllVerdict {
    param($Dirs)
    $out = New-Object System.Collections.ArrayList
    $hits = New-Object System.Collections.ArrayList
    $unchecked = New-Object System.Collections.ArrayList
    $missing = New-Object System.Collections.ArrayList
    $checked = 0
    foreach ($d in @($Dirs)) {
        $dir = ConvertTo-PrintableText ([string]$d.Dir)
        if ([string]$d.State -eq 'missing') { [void]$missing.Add($dir); continue }
        if ([string]$d.State -ne 'ok') { [void]$unchecked.Add(($dir + ' (the folder could not be listed: ' + (ConvertTo-PrintableText ([string]$d.Error)) + ')')); continue }
        foreach ($f in @($d.Files)) {
            $p = ConvertTo-PrintableText ([string]$f.Path)
            switch (Get-DllGrade $f) {
                'ok' { $checked++ }
                'hit' { $checked++; [void]$hits.Add(('  ' + $p + ' [SIG: ' + (ConvertTo-PrintableText ([string]$f.Status)) + '] ' + $(if ([string]$f.Signer) { 'signer ' + (ConvertTo-PrintableText ([string]$f.Signer)) } else { 'no signer' }) + $(if ([string]$f.Facts) { '; ' + (ConvertTo-PrintableText ([string]$f.Facts)) } else { '' }))) }
                default { [void]$unchecked.Add(($p + ' (' + $(if ([string]$f.Error) { ConvertTo-PrintableText ([string]$f.Error) } else { 'signature status ' + (ConvertTo-PrintableText ([string]$f.Status)) }) + ')')) }
            }
        }
    }
    if ($hits.Count) {
        [void]$out.Add('[WARNING][T1574.001] Unsigned/suspicious DLLs in system paths:')
        foreach ($h in $hits) { [void]$out.Add($h) }
        [void]$out.Add('[INFO] Each of these names is loaded by name, so a copy here runs inside whatever program loads it. A file Microsoft did not sign under one of these names in a system folder is the hijack shape; check where it came from before deleting it.')
    }
    if ($unchecked.Count) {
        $lead = $(if ($hits.Count -or $checked) { '[WARNING] System-path DLL signature check NOT performed in full -- ' } else { '[WARNING] System-path DLL signature check NOT performed -- ' })
        [void]$out.Add(($lead + $unchecked.Count + ' could not be checked: ' + ($unchecked -join '; ') + '. They were NOT counted as unsigned; a hijacking DLL there would go unseen (T1574.001).'))
    }
    if (-not ($hits.Count -or $unchecked.Count)) {
        [void]$out.Add(('[OK] No suspicious unsigned DLLs found in system paths (' + $checked + ' file(s) checked, each signed by Microsoft).'))
    }
    if ($missing.Count) { [void]$out.Add(('[INFO] Not present on this PC, so not checked: ' + ($missing -join ', ') + '.')) }
    return @{ Lines = @($out.ToArray()); Hit = ($hits.Count -gt 0); Gap = ($unchecked.Count -gt 0) }
}

# Live. One folder: which of the names are in it, and their signatures.
function Read-DllDir {
    param([string]$Dir)
    $d = @{ Dir = $Dir; State = 'ok'; Error = ''; Files = @() }
    if (-not $Dir) { $d.State = 'missing'; return $d }
    try { $null = Get-Item -LiteralPath $Dir -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { $d.State = 'missing'; return $d }
    catch { $d.State = 'unreadable'; $d.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $d }
    $files = New-Object System.Collections.ArrayList
    foreach ($n in $script:Names) {
        $found = @()
        try { $found = @(Get-ChildItem -LiteralPath $Dir -Filter $n -File -Force -ErrorAction Stop) }
        catch { $d.State = 'unreadable'; $d.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $d }
        foreach ($it in $found) {
            if ([string]$it.Name -ine $n) { continue }
            $f = @{ Path = $it.FullName; Status = ''; Signer = ''; Error = ''; Facts = ('{0} bytes, modified {1:yyyy-MM-dd HH:mm} UTC' -f $it.Length, $it.LastWriteTimeUtc) }
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $it.FullName -ErrorAction Stop
                $f.Status = [string]$s.Status
                if ($s.SignerCertificate) { $f.Signer = [string]$s.SignerCertificate.Subject }
            } catch { $f.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
            [void]$files.Add($f)
        }
    }
    $d.Files = @($files.ToArray())
    return $d
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $ms = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    function F { param([string]$Name = 'version.dll', [string]$Status = 'Valid', [string]$Signer = $ms, [string]$Err = '') @{ Path = ('C:\Windows\System32\' + $Name); Status = $Status; Signer = $Signer; Error = $Err; Facts = '1024 bytes' } }
    function D { param($Files = @(), [string]$State = 'ok', [string]$Err = '') @{ Dir = 'C:\Windows\System32'; State = $State; Error = $Err; Files = @($Files) } }
    $v = Get-DllVerdict @((D @((F), (F 'winhttp.dll')))); $t = $v.Lines -join "`n"
    T 'Microsoft-signed DLLs: [OK] naming how many were checked' ((-not ($v.Hit -or $v.Gap)) -and $t -match '(?m)^\[OK\] No suspicious unsigned DLLs found in system paths \(2 file\(s\) checked') $t
    $v = Get-DllVerdict @((D @((F 'version.dll' 'NotSigned' '')))); $t = $v.Lines -join "`n"
    T 'an unsigned version.dll: the WARNING the bats always printed, the file listed with its status' ($v.Hit -and $t -match '(?m)^\[WARNING\]\[T1574\.001\] Unsigned/suspicious DLLs in system paths:$' -and $t -match 'version\.dll \[SIG: NotSigned\] no signer') $t
    $v = Get-DllVerdict @((D @((F 'winhttp.dll' 'Valid' 'CN=Acme Microsoft Tools, O=Acme Ltd')))); $t = $v.Lines -join "`n"
    T 'a valid signer whose name merely contains "Microsoft": the WARNING, not a pass' ($v.Hit -and $t -match 'Acme') $t
    foreach ($s in 'HashMismatch', 'NotTrusted') {
        $v = Get-DllVerdict @((D @((F 'wer.dll' $s))))
        T ('status ' + $s + ': the WARNING') ($v.Hit) ($v.Lines -join ' | ')
    }
    $v = Get-DllVerdict @((D @((F 'dbghelp.dll' 'UnknownError' '')))); $t = $v.Lines -join "`n"
    T 'UnknownError (the signature could not be read): a raised gap, NEVER counted as unsigned' ($v.Gap -and -not $v.Hit -and $t -match '(?m)^\[WARNING\] System-path DLL signature check NOT performed -- 1 could not be checked: .*dbghelp\.dll \(signature status UnknownError\)' -and $t -match 'NOT counted as unsigned') $t
    $v = Get-DllVerdict @((D @((F 'wer.dll' '' '' 'IOException: in use'))))
    T 'an exception reading the signature: a gap, not a hit' ($v.Gap -and -not $v.Hit) ($v.Lines -join ' | ')
    $v = Get-DllVerdict @((D @((F 'wer.dll' 'NotSupportedFileFormat' ''))))
    T 'a file Windows cannot evaluate: a gap, not a hit' ($v.Gap -and -not $v.Hit) ($v.Lines -join ' | ')
    $v = Get-DllVerdict @((D -State 'unreadable' -Err 'UnauthorizedAccessException: denied'))
    T 'a folder that could not be listed: a gap, never [OK]' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-DllVerdict @((D @((F 'version.dll' 'NotSigned' ''), (F 'wer.dll' 'UnknownError' ''))))
    T 'a hit AND an unchecked file: both raised, the gap says "in full"' ($v.Hit -and $v.Gap -and ($v.Lines -join ' ') -match 'NOT performed in full') ($v.Lines -join ' | ')
    $v = Get-DllVerdict @((D @((F))), @{ Dir = 'C:\Windows\SysWOW64'; State = 'missing'; Error = ''; Files = @() })
    T 'a folder that does not exist (32-bit Windows): said, not graded' ((-not $v.Gap) -and ($v.Lines -join ' ') -match 'Not present on this PC, so not checked: C:\\Windows\\SysWOW64') ($v.Lines -join ' | ')
    $v = Get-DllVerdict @((D @((F ('version.dll' + [char]10 + '[OK] No suspicious') 'NotSigned' ''))))
    T 'a line break in a path cannot forge an [OK] line' ($v.Hit -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails system_dll_sig_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] system_dll_sig_check self-test: a DLL Microsoft did not sign is the WARNING, a signature that could not be read is a raised gap and never "unsigned", and a folder that could not be listed is a gap.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if (-not $Dirs) { $Dirs = @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'), $env:ProgramFiles, ${env:ProgramFiles(x86)}) }
$v = $null
try { $v = Get-DllVerdict @($Dirs | ForEach-Object { Read-DllDir ([string]$_) }) } catch { $v = $null }
if ($null -eq $v -or @($v.Lines).Count -eq 0) {
    '[WARNING] System-path DLL signature check NOT performed -- the check failed before it produced a verdict (T1574.001).'
    $v = @{ Lines = @(); Hit = $false; Gap = $true }
}
foreach ($l in $v.Lines) { $l }
try {
    if ($v.Hit) { Write-Marker -Name 'sysdll_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'sysdll_gap' -Sev 'WARNING' }
    Write-Marker -Name 'sysdll_done' -Sev 'done'
} catch { ('system_dll_sig_check: the verdict above could not be saved for the bat (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
