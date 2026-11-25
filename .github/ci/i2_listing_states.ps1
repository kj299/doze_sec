# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# Read-only apart from marker files in a scratch folder under TEMP. It lives
# in .github/ so it never reaches a USB stick.
#
# Group I2 through the real readers on Windows PowerShell 5.1: the listings
# that used to pipe English Windows output through findstr now read objects,
# event XML field names and SIDs.
#   event_scan_check -Check SecurityList: the Security log read elevated (no
#     gap); a log that does not exist is a raised gap.
#   firewall_rules_list: the runner's enabled inbound ALLOW rules are listed
#     (there are always some), no gap; outbound BLOCK answers too.
#   system_listing: listening ports are listed, established answers,
#     Administrators holds the runner account (read by SID), Remote Desktop
#     Users answers, the OS summary names the OS. No gap anywhere.
$ErrorActionPreference = 'Stop'
foreach ($t in 'event_scan_check', 'firewall_rules_list', 'system_listing') {
  $o = (& ".\tools\$t.ps1" -SelfTest) -join "`n"
  if ($LASTEXITCODE -ne 0) { Write-Host $o; throw "$t -SelfTest failed" }
}
$md = Join-Path $env:TEMP ("dz_ci_i2_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
function Clear-M { Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force }
function Has([string]$n) { Test-Path (Join-Path $md "dz_$n.txt") }
try {
  # ---- SecurityList ----
  Clear-M
  $o = (& .\tools\event_scan_check.ps1 -Check SecurityList -Ids '4672,4624' -Fields 'SubjectUserName,TargetUserName,LogonType' -Label 'Sign-ins - Events 4672 and 4624' -Tech T1078 -MarkerDir $md -Elevated 1) -join "`n"
  Write-Host $o
  if ((Has 'seclist_gap') -or -not (Has 'seclist_done')) { throw 'the Security log listing raised a gap on an elevated runner, or wrote no done marker' }
  if ($o -notmatch 'event\(s\) read from the Security log' -and $o -notmatch 'No Sign-ins - Events 4672 and 4624 events') { throw 'the Security log listing printed neither records nor its empty line' }
  Write-Host ("[MEASURED] Security log listing: {0} record(s) shown" -f ([regex]::Matches($o, '(?m)^TimeCreated: ')).Count)
  Clear-M
  $o = (& .\tools\event_scan_check.ps1 -Check SecurityList -Ids '4672' -Fields 'SubjectUserName' -Label 'Planted' -Tech T1078 -MarkerDir $md -Elevated 1 -LogName 'dz-ci-no-such-log') -join "`n"
  Write-Host $o
  if (-not (Has 'seclist_gap') -or $o -notmatch '\[WARNING\] Planted listing NOT performed -- the dz-ci-no-such-log log could not be read') { throw 'a log that does not exist was not a raised gap' }

  # The reader change must not stop the OTHER checks reading messages: a
  # field list of @($null) once read as one field, so no message was
  # rendered and AMSI, service-install and spray checks read clean.
  Clear-M
  $o = (& .\tools\event_scan_check.ps1 -Check ScriptBlockList -MarkerDir $md -Elevated 1) -join "`n"
  $shown = ([regex]::Matches($o, '(?m)^TimeCreated: ')).Count
  Write-Host ("[MEASURED] ScriptBlockList: {0} block(s) listed" -f $shown)
  if ($shown -gt 0 -and $o -notmatch '(?m)^  ScriptBlock ID:') { Write-Host $o; throw 'Script Block records were listed with no rendered message (ScriptBlock ID) -- the reader stopped rendering messages' }
  if ($o -match 'had no text Windows could render') { Write-Host $o; throw 'the reader reported Script Block events with no text on a runner' }

  # ---- firewall_rules_list ----
  Clear-M
  $o = (& .\tools\firewall_rules_list.ps1 -View InboundAllow -MarkerDir $md) -join "`n"
  Write-Host (($o -split "`n" | Select-Object -Last 3) -join "`n")
  if ((Has 'fwrules_gap') -or -not (Has 'fwrules_done')) { throw 'the inbound ALLOW rule listing raised a gap on a runner' }
  if ($o -notmatch '(?m)^\[INFO\] [1-9]\d* enabled inbound ALLOW rule\(s\)') { throw 'no enabled inbound ALLOW rule was listed; every Windows has some' }
  if ($o -notmatch '(?m)^  .+ \| program=.+ \| protocol=.+ \| localport=.+ \| remote=') { throw 'a rule line lacks its program, port or address' }
  Clear-M
  $o = (& .\tools\firewall_rules_list.ps1 -View OutboundBlock -MarkerDir $md) -join "`n"
  if ((Has 'fwrules_gap') -or -not (Has 'fwrules_done')) { throw 'the outbound BLOCK rule listing raised a gap on a runner' }

  # ---- system_listing ----
  Clear-M
  $o = (& .\tools\system_listing.ps1 -Mode TcpListening -MarkerDir $md) -join "`n"
  if ((Has 'listing_gap') -or -not (Has 'listing_done') -or $o -notmatch '(?m)^\[INFO\] [1-9]\d* listening TCP port\(s\)') { Write-Host $o; throw 'listening ports were not listed (a runner always has some), or a gap was raised' }
  Clear-M
  $o = (& .\tools\system_listing.ps1 -Mode TcpEstablished -MarkerDir $md) -join "`n"
  if ((Has 'listing_gap') -or -not (Has 'listing_done') -or $o -notmatch 'established TCP connection') { Write-Host $o; throw 'the established-connection view did not answer' }
  Clear-M
  $o = (& .\tools\system_listing.ps1 -Mode Group -Sid S-1-5-32-544 -MarkerDir $md) -join "`n"
  Write-Host $o
  if ((Has 'listing_gap') -or -not (Has 'listing_done')) { throw 'the Administrators listing raised a gap on a runner' }
  if ($o -notmatch [regex]::Escape($env:USERNAME)) { throw "the Administrators listing does not hold the runner account $($env:USERNAME)" }
  Clear-M
  $o = (& .\tools\system_listing.ps1 -Mode Group -Sid S-1-5-32-555 -MarkerDir $md) -join "`n"
  if ((Has 'listing_gap') -or -not (Has 'listing_done')) { Write-Host $o; throw 'the Remote Desktop Users listing raised a gap on a runner' }
  Clear-M
  $o = (& .\tools\system_listing.ps1 -Mode OsSummary -MarkerDir $md) -join "`n"
  Write-Host $o
  if ($o -notmatch '(?m)^  OS: .*Windows' -or -not (Has 'listing_done')) { throw 'the OS summary did not name the OS' }
  Write-Host '[OK] I2: Security-log listings, firewall rules, TCP views and group members are read from objects, field names and SIDs; nothing read is a raised gap; the runner raised none.'
} finally {
  Remove-Item -LiteralPath $md -Recurse -Force -EA SilentlyContinue
}
