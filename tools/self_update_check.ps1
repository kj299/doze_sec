# self_update_check.ps1 -- INIT 10/14 self-update version check.
#
# Extracted from doze_sec.bat's inline PowerShell so the try/catch/elseif
# chain is no longer assembled through fragile cmd.exe echo escaping (the
# crash class behind the INIT 12 / HTML report regressions). The caller runs
# this twice -- once teed to the report, once to the console.
#
# Prints a human-readable status to stdout. NEVER throws: every network/HTTP
# failure degrades to an [INFO] line so the audit always continues.
# Windows PowerShell 5.1 compatible.

param(
    [Parameter(Mandatory=$true)] [string]$LocalVer,
    [Parameter(Mandatory=$true)] [string]$RemoteUrl,
    [Parameter(Mandatory=$false)][string]$DownloadUrl = ''
)

$ErrorActionPreference = 'Continue'

# GitHub PAT for private-repo access: env var first, then a token file.
$token = $env:DOZESEC_TOKEN
if (-not $token) {
    $tf = Join-Path $env:USERPROFILE '.dozesec_token'
    if (Test-Path -LiteralPath $tf) { $token = (Get-Content -LiteralPath $tf -Raw -EA SilentlyContinue).Trim() }
}
$headers = @{ 'User-Agent' = 'doze_sec' }
if ($token) { $headers['Authorization'] = "Bearer $token" }

try {
    $remoteVer = (Invoke-WebRequest $RemoteUrl -UseBasicParsing -TimeoutSec 10 -Headers $headers -EA Stop).Content.Trim()
    Write-Output ('  Remote version : ' + $remoteVer)
    Write-Output ('  Local version  : ' + $LocalVer)
    $rv = ($remoteVer -replace '[^0-9.]', '').Trim('.')
    $lv = ($LocalVer  -replace '[^0-9.]', '').Trim('.')
    if ([version]$rv -gt [version]$lv) {
        Write-Output '[UPDATE AVAILABLE] A newer version exists. Download from:'
        if ($DownloadUrl) { Write-Output ('  ' + $DownloadUrl) }
        Write-Output 'Verify SHA256 hash after downloading before running.'
    } else {
        Write-Output '[OK] Script is current (no update required).'
    }
} catch {
    $sc = $null
    try { $sc = [int]$_.Exception.Response.StatusCode } catch {}
    if ($sc -eq 401) {
        Write-Output '  [INFO] Update check: authentication failed (HTTP 401). GitHub PAT is invalid, expired, or lacks Contents:Read on this repo.'
    } elseif ($sc -eq 403) {
        Write-Output '  [INFO] Update check: forbidden (HTTP 403). Token may be rate-limited or scope-restricted.'
    } elseif ($sc -eq 404 -and $token) {
        Write-Output '  [INFO] Update check: 404 even with token. PAT does not grant access to this repo; verify it is scoped to kj299/doze_sec.'
    } elseif ($sc -eq 404) {
        Write-Output '  [INFO] Update check: 404 (repo is private and no GitHub PAT found). Set $env:DOZESEC_TOKEN or write the PAT to %USERPROFILE%\.dozesec_token. Self-update disabled; this is not a scan failure.'
    } elseif ($sc) {
        Write-Output ('  [INFO] Update check failed (HTTP ' + $sc + '): ' + $_.Exception.Message)
    } else {
        Write-Output ('  [INFO] Update check failed: ' + $_.Exception.Message)
    }
}
