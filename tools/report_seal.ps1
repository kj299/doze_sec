# report_seal.ps1 -- seal the finished report so later tampering is detectable.
#
# WHY: the report is written to disk ON THE MACHINE UNDER SUSPICION. If that
# machine is compromised, whoever compromised it can edit the report -- delete
# the finding that names their implant, change a verdict, alter a timestamp --
# and nothing about the file would show it. For someone who may need the report
# later as evidence (a protective order, a police report, an HR process, a
# handover to a security helpline) that is a real gap, and closing it costs one
# hash.
#
# WHAT IT DOES
#   1. SHA256 of the text report and of the HTML report.
#   2. Writes a sidecar <report>.sha256 recording both digests, the file names,
#      their sizes, and the seal time.
#   3. Prints both digests to the console.
#
# WHY THE CONSOLE MATTERS: the sidecar sits on the same disk as the report, so
# an attacker with write access can rewrite both. The console output is harder
# to reach after the fact -- it is on screen in front of the person running the
# audit, it goes into AuditConsole_<TS>.log, and it can be photographed or
# copied into a message immediately. Reading the digest out loud to someone, or
# sending it to yourself, is a perfectly good way to anchor it off-device.
#
# THE HONEST LIMIT, WHICH THE REPORT ALSO STATES: a digest computed ON a
# compromised machine proves only that the file has not changed SINCE the audit
# ran. It is not proof the audit itself ran unmolested -- an implant with kernel
# access could have fed the audit false answers, and this hash would faithfully
# seal those false answers. It is tamper-EVIDENCE for the report, not
# attestation of the machine. Saying otherwise would be exactly the kind of
# false assurance the rest of this tool is built to avoid.
#
# This is a reporting utility. It evaluates no security condition and raises no
# finding: a failure to seal degrades to [WARNING] text and never fabricates a
# result.
#
# Windows PowerShell 5.1 compatible. Read-only with respect to the audited
# system (it writes only its own sidecar). Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Report,
    [string]$HtmlReport = '',
    [string]$SealPath   = ''
)

$ErrorActionPreference = 'Continue'

if (-not $SealPath) { $SealPath = "$Report.sha256" }

function Get-Digest {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $h = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -EA Stop
        $len = (Get-Item -LiteralPath $Path -EA Stop).Length
        return [pscustomobject]@{ Name = (Split-Path -Leaf $Path); Hash = $h.Hash.ToUpper(); Size = $len }
    } catch { return $null }
}

$txt  = Get-Digest $Report
$html = Get-Digest $HtmlReport

if (-not $txt) {
    "[WARNING] Report could not be read for sealing -- no integrity digest was produced for $Report. The report is still usable, but its integrity cannot be verified later."
    exit 0
}

$sealedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$lines = @(
    '# doze_sec report integrity seal'
    "# Sealed: $sealedAt"
    '#'
    '# Verify at any time with:'
    "#   Get-FileHash '<file>' -Algorithm SHA256"
    '# and compare the value below. A mismatch means the file changed after the'
    '# audit finished.'
    '#'
    '# LIMIT: this proves the FILE has not changed since the audit ran. It does'
    '# not prove the audit itself was not interfered with on a compromised'
    '# machine. Keep a copy of the digest somewhere off this device.'
    ''
    ("SHA256  {0}  {1}  ({2} bytes)" -f $txt.Hash, $txt.Name, $txt.Size)
)
if ($html) { $lines += ("SHA256  {0}  {1}  ({2} bytes)" -f $html.Hash, $html.Name, $html.Size) }

$wrote = $false
try {
    Set-Content -LiteralPath $SealPath -Value $lines -Encoding UTF8 -EA Stop
    $wrote = $true
} catch {}

"[INFO] Report integrity seal ($sealedAt):"
"[INFO]   $($txt.Name)"
"[INFO]     SHA256 $($txt.Hash)"
if ($html) {
    "[INFO]   $($html.Name)"
    "[INFO]     SHA256 $($html.Hash)"
}
if ($wrote) {
    "[INFO]   Digest file: $SealPath"
} else {
    "[WARNING] Could not write the digest file to $SealPath -- the digests above are still valid; record them off this device now."
}
"[INFO]   Record these digests somewhere OFF this device. Verify later with: Get-FileHash '<file>' -Algorithm SHA256"

exit 0
