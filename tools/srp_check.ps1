# srp_check.ps1 -- create a System Restore Point and record whether it actually
# took effect, so the audit's per-run change log lists "[CREATED]" only when a
# new restore point really appeared.
#
# Why this exists as a .ps1 helper instead of inline-in-bat PowerShell:
#   - Windows throttles restore points to ONE per 24h. The previous inline code
#     logged [CREATED] every run regardless of whether Checkpoint-Computer
#     actually created one, which broke the change-log's trust contract.
#   - The fix needs a before/after sequence-number comparison around the
#     Checkpoint-Computer call. The cmd-escaped multi-line "echo if (...)"
#     pattern this requires is a parser minefield (regression in v7.2 was
#     caused by exactly that). Extracting to a real .ps1 removes the escaping
#     burden entirely and lets the 5.1 parser CI step validate the syntax.
#
# Windows PowerShell 5.1 compatible.
#
# Exit code is intentionally NOT used as the "did it create" signal because
# Tee/redirection inside the calling bat would mask it. Instead, the script
# writes -MarkerFile only when SequenceNumber.Max(after) > SequenceNumber.Max(before).
# The bat then checks `if exist <MarkerFile>` to decide whether to log [CREATED].
#
# Usage (from doze_sec.bat):
#   "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\srp_check.ps1" `
#       -Description "<text>" -MarkerFile "%TEMP%\dz_srp_created.txt"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$Description,
    [Parameter(Mandatory=$true)] [string]$MarkerFile
)

$ErrorActionPreference = 'Continue'

function Get-MaxSequenceNumber {
    try {
        $points = @(Get-ComputerRestorePoint -EA Stop)
        if ($points) {
            return ($points | Measure-Object -Property SequenceNumber -Maximum).Maximum
        }
    } catch {}
    return 0
}

$beforeMax = Get-MaxSequenceNumber

try {
    Enable-ComputerRestore -Drive "$env:SystemDrive\" -EA SilentlyContinue
    Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -EA Stop
} catch {
    Write-Output ('  [WARN] SRP failed: ' + $_.Exception.Message)
    Write-Output '       To fix: Control Panel > System > System Protection > Configure > Enable'
}

$afterMax = Get-MaxSequenceNumber

if ($afterMax -gt $beforeMax) {
    Write-Output '  [OK] System Restore Point created successfully.'
    New-Item -LiteralPath $MarkerFile -Force | Out-Null
} else {
    Write-Output '  [INFO] No new restore point created -- Windows allows only one per 24h, or System Protection is off. Existing restore points are unaffected.'
}
