# threat_list_sync.ps1 -- INIT 10/14 threat-list incremental sync with
# upstream-freshness reporting.
#
# The original inline heredoc in doze_sec.bat did a line-additive merge and
# printed "already up to date" when every remote line was present locally.
# That signal only meant "matches what is currently committed to the repo" --
# it did NOT tell the user whether the upstream CTI itself was stale, nor
# whether the upstream file had been rewritten/reordered in ways the line-
# additive merge couldn't catch.
#
# This helper preserves the safe-by-default additive merge (so manual
# -updateTTP additions and per-row provenance comments are never blown
# away) AND surfaces two new signals:
#
#   1. Upstream freshness -- queries the GitHub commits API for the date
#      of the last commit that touched each file
#      (`/repos/<owner>/<repo>/commits?path=...&per_page=1`). We chose the
#      commits API over `Last-Modified` on raw.githubusercontent.com
#      because Fastly strips Last-Modified at the CDN edge, so the raw URL
#      only ever returns Date/ETag/Cache-Control and no commit time. We
#      parse the API response and report '(upstream YYYY-MM-DD, Nd ago)'
#      per file. If any TTP/IOC file's upstream is older than -StaleDays
#      (default 60), emit a [WARNING].
#
#   2. Upstream-vs-local divergence -- after the additive merge, compute
#      SHA256 of normalized content (trim, drop blanks, drop # comments)
#      for both sides. If they differ, append '(divergent: K local-only
#      lines vs upstream)' so the user can spot rewrites/deletions that
#      the line-additive merge cannot fix automatically.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File threat_list_sync.ps1 `
#       -BaseUrl "https://raw.githubusercontent.com/<owner>/<repo>/<ref>/ThreatLists" `
#       -LocalDir "C:\path\to\ThreatLists" `
#       [-StaleDays 60]
#
# The owner/repo/ref are parsed out of -BaseUrl so the helper only needs
# the one URL the bat already has.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] [string]$BaseUrl = '',
    [Parameter(Mandatory=$false)] [string]$LocalDir = '',
    [Parameter(Mandatory=$false)] [int]$StaleDays = 60
)

$ErrorActionPreference = 'Continue'

if ($BaseUrl -eq '' -or $LocalDir -eq '') {
    Write-Error "threat_list_sync.ps1: -BaseUrl and -LocalDir are required."
    exit 2
}

if (-not (Test-Path -LiteralPath $LocalDir)) {
    try { New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null } catch {}
}

# Load GitHub PAT for private-repo access. Priority: env var -> token file.
$token = $env:DOZESEC_TOKEN
if (-not $token) {
    $tf = Join-Path $env:USERPROFILE '.dozesec_token'
    if (Test-Path -LiteralPath $tf) {
        $token = (Get-Content -LiteralPath $tf -Raw -EA SilentlyContinue).Trim()
    }
}
$headers = @{ 'User-Agent' = 'doze_sec' }
if ($token) { $headers['Authorization'] = "Bearer $token" }

$files = @(
    'ioc_processes.txt','ioc_named_pipes.txt','ioc_services.txt',
    'ioc_registry.txt','ioc_file_paths.txt','ioc_scheduled_tasks.txt',
    'ioc_domains.txt','ioc_hashes.txt','ioc_lolbins.txt','ttp_manifest.txt'
)

# Parse the GitHub commits-API endpoint out of -BaseUrl. Expects a URL of
# the form https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>.
# If anything looks off, $apiBase stays null and the freshness check is
# silently skipped (the additive merge still runs).
$apiBase = $null
$apiPathPrefix = $null
$m = [regex]::Match($BaseUrl, '^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/(.+)$')
if ($m.Success) {
    $owner = $m.Groups[1].Value
    $repo  = $m.Groups[2].Value
    $apiPathPrefix = $m.Groups[3].Value.TrimEnd('/')
    $apiBase = "https://api.github.com/repos/$owner/$repo/commits"
}

# One-shot lookup of "when was this path last committed?" via the GitHub
# commits API. Returns $null if the API call fails for any reason -- the
# caller should treat $null as "no signal available, fall back to silent".
function Get-UpstreamCommitDate {
    param([string]$RelPath)
    if (-not $apiBase) { return $null }
    $u = $apiBase + '?path=' + [System.Uri]::EscapeDataString("$apiPathPrefix/$RelPath") + '&per_page=1'
    try {
        $resp = Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 10 -Headers $headers -EA Stop
        $arr = ConvertFrom-Json $resp.Content
        if ($arr -and $arr.Count -gt 0) {
            return [DateTime]::Parse($arr[0].commit.committer.date)
        }
    } catch {}
    return $null
}

# SHA256 of content after normalization: trim each line, drop blanks, drop
# `#` comment lines, rejoin. Identical normalized content => identical hash.
function Get-NormalizedHash {
    param([string]$Content)
    if ($null -eq $Content -or $Content -eq '') { return '' }
    $norm = (($Content -split "`r?`n") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notmatch '^\s*#' }) -join "`n"
    if ($norm -eq '') { return '' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')
    } finally {
        $sha.Dispose()
    }
}

# Same normalization but returns the array of distinct lines, so we can
# count local-only entries when the hashes differ.
function Get-NormalizedLines {
    param([string]$Content)
    if ($null -eq $Content -or $Content -eq '') { return @() }
    return @(($Content -split "`r?`n") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notmatch '^\s*#' })
}

$updated = 0
$skipped = 0
$staleHits = @()

foreach ($f in $files) {
    $url  = "$BaseUrl/$f"
    $dest = Join-Path $LocalDir $f
    try {
        $remote = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 10 -Headers $headers -EA Stop

        # Upstream freshness via the GitHub commits API. $null means we
        # couldn't determine the date (API unavailable, URL not parseable
        # as raw.githubusercontent.com, etc.) -- in that case we just
        # silently omit the freshness suffix from this file's status line.
        $lm = Get-UpstreamCommitDate $f
        $ageStr = ''
        $ageDays = $null
        if ($lm) {
            $ageDays = [int]((Get-Date).ToUniversalTime() - $lm.ToUniversalTime()).TotalDays
            $ageStr = ' (upstream ' + $lm.ToString('yyyy-MM-dd') + ', ' + $ageDays + 'd ago)'
        }

        $remoteContent = $remote.Content
        $remoteLines   = Get-NormalizedLines $remoteContent
        $remoteHash    = Get-NormalizedHash $remoteContent

        if (Test-Path $dest) {
            $existingContent = Get-Content $dest -Raw
            $existing = Get-NormalizedLines $existingContent
            $added = 0
            foreach ($line in $remoteLines) {
                if ($existing -notcontains $line) {
                    Add-Content $dest ("# Added by self-update on " + (Get-Date -Format 'yyyy-MM-dd'))
                    Add-Content $dest $line
                    $added++
                }
            }

            # Compare normalized content of post-merge local vs remote.
            $postMergeContent = Get-Content $dest -Raw
            $localHash        = Get-NormalizedHash $postMergeContent
            $localOnly        = @(Get-NormalizedLines $postMergeContent | Where-Object { $remoteLines -notcontains $_ })

            $divergentStr = ''
            if ($remoteHash -ne $localHash -and $localOnly.Count -gt 0) {
                $divergentStr = ' (divergent: ' + $localOnly.Count + ' local-only line(s) vs upstream)'
            }

            if ($added -gt 0) {
                Write-Output ('  [OK] ' + $f + ': ' + $added + ' new entries merged' + $ageStr + $divergentStr)
                $updated++
            } else {
                Write-Output ('  [OK] ' + $f + ': already up to date' + $ageStr + $divergentStr)
                $skipped++
            }
        } else {
            [System.IO.File]::WriteAllText($dest, $remoteContent, (New-Object System.Text.UTF8Encoding $false))
            Write-Output ('  [OK] ' + $f + ': downloaded (new file)' + $ageStr)
            $updated++
        }

        # Track files whose upstream is older than the staleness threshold.
        if ($null -ne $ageDays -and $ageDays -gt $StaleDays) {
            $staleHits += [PSCustomObject]@{ File = $f; Days = $ageDays; UpstreamDate = $lm }
        }
    } catch {
        Write-Output ('  [INFO] ' + $f + ': not available at remote URL')
        $skipped++
    }
}

Write-Output ("  Summary: " + $updated + " files updated, " + $skipped + " unchanged/unavailable")

if ($staleHits.Count -gt 0) {
    Write-Output ''
    Write-Output ("[WARNING] " + $staleHits.Count + " threat-list file(s) have upstream older than " + $StaleDays + " days:")
    foreach ($h in $staleHits) {
        Write-Output ('    - ' + $h.File + ': last upstream commit ' + $h.UpstreamDate.ToString('yyyy-MM-dd') + ' (' + $h.Days + 'd ago)')
    }
    Write-Output "[WARNING] CTI signal may be stale. Re-run with -updateTTP and push the regenerated files."
}
