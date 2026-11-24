# account_files_check.ps1 -- two checks of THIS account's own files, which a
# failed read used to report as absent.
#
#   -Check PsHistory   Section 11: the PowerShell (PSReadLine) command history.
#   -Check CloudCreds  Section 18: Azure / AWS / GCP / kubectl CLI credential
#                      files -- tokens an attacker on this account can replay
#                      (T1528).
#
# WHY A TOOL (2026-11-24). Both were inline blocks that decided by existence:
# `if not exist <ConsoleHost_history.txt>` printed "[INFO] No PS history file
# found.", and the cloud block's `Test-Path` printed "[OK] No cloud CLI
# credential files found (no cloud attack surface from local tokens)." A
# path this account cannot read is NOT reported missing by either -- cmd's
# `if exist` and Test-Path both return false for a denied path, never an
# error -- so a history or a token file behind a deny ACE read as "not
# there", and the history block also read only ConsoleHost_history.txt,
# while VS Code's and the ISE's histories sit beside it.
#
# THE RULE. A file is absent only when its folder ANSWERS without it, or the
# folder itself does not exist (Test-AbsentForSure, the file_walk_check
# rule; a folder that refuses to list is not an answer). A path that is
# present but could not be read, or a folder that could not be listed, is
# "[WARNING] ... NOT performed" with dz_<name>_gap.txt, raised by both bats
# as its own row. Each check states its scope: this account only.
#
# OUTPUT. PsHistory prints the last -Last lines of each history file,
# indented behind "    > " so a command that happens to begin with a
# severity tag can never be read as one. CloudCreds prints [INFO] for each
# file present (context: the files are normal on a developer's machine;
# the report asks the reader to confirm they are expected).
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.
#
# Usage:
#   powershell -File tools\account_files_check.ps1 -Check PsHistory|CloudCreds [-MarkerDir <dir>]
#   powershell -File tools\account_files_check.ps1 -SelfTest

[CmdletBinding()]
param(
    [ValidateSet('PsHistory', 'CloudCreds', '')]
    [string]$Check = '',
    [string]$MarkerDir = $env:TEMP,
    [int]$Last = 50,
    # CI hooks: the folder PsHistory reads, and the root CloudCreds' relative
    # paths resolve against (both default to this account's real folders).
    [string]$HistoryDir = '',
    [string]$CredRoot = '',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK' -or -not $MarkerDir) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function Test-AbsentForSure {
    # A path is absent only when its parent ANSWERS without it, or the parent
    # itself does not exist (a browser that is not installed). A parent that
    # refuses to list is not an answer.
    param([string]$Path)
    $parent = [IO.Path]::GetDirectoryName($Path); $leaf = [IO.Path]::GetFileName($Path)
    if (-not $parent -or -not $leaf) { return $false }
    try { $names = @([IO.Directory]::GetFileSystemEntries($parent)) }
    catch [System.IO.DirectoryNotFoundException] { return $true }
    catch { return $false }
    foreach ($n in $names) { if ([IO.Path]::GetFileName($n) -eq $leaf) { return $false } }
    return $true
}

function Get-InnerMessage {
    param($Err)
    $x = $Err.Exception
    while ($x.InnerException) { $x = $x.InnerException }
    return (([string]$x.Message) -replace '\s+', ' ').Trim()
}

# PURE. The closing verdict from what was read. $Unread: names (with reason)
# of paths that are there and could not be read. Returns @{ Lines; Gap }.
function Get-FilesVerdict {
    param([string]$What, [int]$Found, [string[]]$Unread, [string]$NoneLine)
    $out = @()
    $u = @($Unread | Where-Object { $_ })
    if ($u.Count -gt 0) {
        $out += ('[WARNING] ' + $What + ' check NOT performed in full -- ' + $u.Count + ' path(s) are there but could not be read: ' + (($u | Select-Object -First 5) -join '; ') + $(if ($u.Count -gt 5) { '; ...' } else { '' }))
    }
    if ($Found -eq 0 -and $u.Count -eq 0) { $out += $NoneLine }
    return @{ Lines = $out; Gap = ($u.Count -gt 0) }
}

# PURE. A history line made safe to print: control characters out, length
# capped, indented behind a marker no severity parser reads as a tag.
function Format-HistoryLine {
    param([string]$Line)
    $l = ([string]$Line) -replace '[\x00-\x08\x0B-\x1F\x7F]', '?'
    if ($l.Length -gt 300) { $l = $l.Substring(0, 300) + ' ...[truncated]' }
    return ('    > ' + $l)
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $v = Get-FilesVerdict -What 'Cloud CLI credential' -Found 0 -Unread @('AWS CLI: access denied') -NoneLine '[OK] none'
    T 'a file that is there and unreadable is a raised gap, never the [OK] "none found" (the defect)' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]' -and $v.Lines[0] -match '^\[WARNING\] Cloud CLI credential check NOT performed in full -- 1 path') ($v.Lines -join ' | ')
    $v = Get-FilesVerdict -What 'x' -Found 0 -Unread @() -NoneLine '[OK] none'
    T 'nothing there and nothing unread: the none line' ((-not $v.Gap) -and $v.Lines[0] -eq '[OK] none') ($v.Lines -join ' | ')
    $v = Get-FilesVerdict -What 'x' -Found 2 -Unread @('a', 'b') -NoneLine '[OK] none'
    T 'files found and files unread: the gap, and no none line' ($v.Gap -and $v.Lines.Count -eq 1) ($v.Lines -join ' | ')
    $h = Format-HistoryLine '[CRITICAL] this is a typed command'
    T 'a history line that begins with a tag is indented behind a marker, so no grader reads it as a finding' ($h -ceq '    > [CRITICAL] this is a typed command') $h
    $h = Format-HistoryLine ('a' + [char]27 + '[31mb')
    T 'control characters in a history line are replaced' ($h -ceq '    > a?[31mb') $h
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_afc_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $tmp 'present.txt') -Value 'x'
        T 'a file whose folder lists it is not absent' (-not (Test-AbsentForSure (Join-Path $tmp 'present.txt'))) ''
        T 'a file whose folder answers without it is absent' (Test-AbsentForSure (Join-Path $tmp 'missing.txt')) ''
        T 'a file whose folder does not exist is absent' (Test-AbsentForSure (Join-Path $tmp 'nodir\missing.txt')) ''
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    if ($fails) { Write-Output "[FAIL] $fails account_files_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] account_files_check self-test: a path that is there and unreadable is a raised gap, never "not found"; history lines cannot pose as findings.'
    exit 0
}

if (-not $Check) { '[WARNING] account_files_check: -Check is required -- NOT performed.'; exit 2 }

if ($Check -eq 'PsHistory') {
    Remove-Item -LiteralPath (Join-Path $MarkerDir 'dz_pshist_gap.txt') -Force -EA SilentlyContinue
    if (-not $HistoryDir) {
        if (-not $env:APPDATA) {
            '[WARNING] PowerShell history check NOT performed -- APPDATA is not set, so this account''s history folder is unknown.'
            Write-Marker -Name 'pshist_gap' -Sev 'WARNING'
            exit 0
        }
        $HistoryDir = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine'
    }
    '[INFO] Scope: this account''s PSReadLine history folder (' + $HistoryDir + '), every *_history.txt in it -- the console, VS Code and the ISE each keep one. Other accounts'' history, and a HistorySavePath a profile moves elsewhere, are not read.'
    $files = $null
    $unread = @()
    try { $files = @(Get-ChildItem -LiteralPath $HistoryDir -Filter '*_history.txt' -File -Force -ErrorAction Stop) }
    catch {
        if (Test-AbsentForSure $HistoryDir) { $files = @() }
        else { $unread += ($HistoryDir + ': ' + (Get-InnerMessage $_)) }
    }
    $found = 0
    foreach ($f in @($files)) {
        $lines = $null
        try { $lines = @(Get-Content -LiteralPath $f.FullName -Tail $Last -ErrorAction Stop) }
        catch { $unread += ($f.Name + ': ' + (Get-InnerMessage $_)); continue }
        $found++
        ('[INFO] PowerShell history: ' + $f.FullName + ' (last written ' + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + '). Last ' + $lines.Count + ' command(s):')
        foreach ($l in $lines) { Format-HistoryLine $l }
    }
    $v = Get-FilesVerdict -What 'PowerShell history' -Found $found -Unread $unread -NoneLine '[INFO] No PowerShell history saved for this account.'
    $v.Lines
    if ($v.Gap) { Write-Marker -Name 'pshist_gap' -Sev 'WARNING' }
    exit 0
}

# CloudCreds
Remove-Item -LiteralPath (Join-Path $MarkerDir 'dz_cloudcred_gap.txt') -Force -EA SilentlyContinue
$prof = if ($CredRoot) { $CredRoot } else { $env:USERPROFILE }
$appd = if ($CredRoot) { Join-Path $CredRoot 'AppData\Roaming' } else { $env:APPDATA }
if (-not $prof -or -not $appd) {
    '[WARNING] Cloud CLI credential check NOT performed -- USERPROFILE or APPDATA is not set, so this account''s folders are unknown.'
    Write-Marker -Name 'cloudcred_gap' -Sev 'WARNING'
    exit 0
}
$creds = @(
    @{ Name = 'Azure CLI';      Path = (Join-Path $prof '.azure\accessTokens.json') },
    @{ Name = 'Azure CLI MSAL'; Path = (Join-Path $prof '.azure\msal_token_cache.json') },
    @{ Name = 'AWS CLI';        Path = (Join-Path $prof '.aws\credentials') },
    @{ Name = 'GCP';            Path = (Join-Path $appd 'gcloud\credentials.db') },
    @{ Name = 'GCP ADC';        Path = (Join-Path $appd 'gcloud\application_default_credentials.json') },
    @{ Name = 'kubectl';        Path = (Join-Path $prof '.kube\config') }
)
'[INFO] Scope: this account''s profile only (' + $prof + '). Other accounts'' CLI credentials are not read.'
$found = @()
$unread = @()
foreach ($c in $creds) {
    try {
        $item = Get-Item -LiteralPath $c.Path -Force -ErrorAction Stop
        $found += ($c.Name + ': ' + $c.Path + ' (modified: ' + $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')')
    } catch {
        if (Test-AbsentForSure $c.Path) { continue }
        $unread += ($c.Name + ' (' + $c.Path + '): ' + (Get-InnerMessage $_))
    }
}
if ($found.Count -gt 0) {
    '[INFO] Cloud CLI credential files present -- verify each is expected; a token here can be replayed by anything running as this account (T1528):'
    foreach ($f in $found) { '  ' + $f }
}
$v = Get-FilesVerdict -What 'Cloud CLI credential' -Found $found.Count -Unread $unread -NoneLine '[OK] No cloud CLI credential files in this account''s profile.'
$v.Lines
if ($v.Gap) { Write-Marker -Name 'cloudcred_gap' -Sev 'WARNING' }
exit 0
