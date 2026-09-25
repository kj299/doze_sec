# report_safety.ps1 -- truthful-reporting layer (Tier 0). Two modes, both
# called from doze_sec.bat / doze_sec_noAdmin.bat.
#
# WHY THIS EXISTS: the most dangerous line this tool can print is "CLEAN -- no
# issues detected." A user-mode configuration audit that comes back clean rules
# out a lot of commodity malware and misconfiguration -- but it does NOT prove a
# device is safe from a targeted or state-level actor, whose kernel-level implant
# can lie to every API this script calls. For the people this project is meant to
# protect -- journalists, activists, abuse survivors -- a false sense of safety
# can be worse than no audit at all: they may keep using a compromised device, or
# remediate in a way that destroys evidence or alerts the person watching them.
#
# This module never evaluates a security condition. It frames the results
# honestly:
#   -Mode Preamble   emits the "read this first" block: what a clean result does
#                    and does not mean, the at-risk-user safety warnings, and
#                    where to get expert help. Static text -- no host data.
#   -Mode Coverage   reads the finished report and emits a COVERAGE & CONFIDENCE
#                    block: how many findings, how many checks were SKIPPED
#                    (could not run), and -- if the audit-policy check flagged it
#                    -- a plain warning that a clean event-log result may just
#                    mean nothing was being recorded.
#
# The referrals are stable, well-known, free at-risk-user resources. They are
# informational; this tool contacts nothing.
#
# Windows PowerShell 5.1 compatible. Read-only. helpers-ps51 CI executes both
# modes and asserts the key phrases are present.

[CmdletBinding()]
param(
    [ValidateSet('Preamble', 'Coverage')][string]$Mode = 'Preamble',
    [string]$Report = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE: what the report's own audit-policy lines allow this block to claim.
# OK only when at least one 'auditing is ON' line was seen and no OFF line;
# REDUCED on any OFF; otherwise NOT VERIFIED. The old rule was 'no OFF line
# seen' -- an OK default -- and the first standard-user field run, where the
# audit-policy check never executed (auditpol needs admin), read
# 'Audit visibility : OK' for a check that did not run.
function Get-AuditVisibility {
    param([string[]]$Lines)
    $on = $false; $off = $false; $deferred = $false
    foreach ($l in @($Lines)) {
        if ($l -match 'auditing is OFF' -or $l -match 'command-line logging is DISABLED') { $off = $true }
        elseif ($l -match 'auditing is ON' -or $l -match 'command-line logging is ENABLED') { $on = $true }
        elseif ($l -match 'DEFERRED - ADMIN REQUIRED\] auditpol') { $deferred = $true }
    }
    if ($off) { return 'REDUCED' }
    if ($on) { return 'OK' }
    if ($deferred) { return 'DEFERRED' }
    return 'UNKNOWN'
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    T 'four ON lines and the cmdline ENABLED line: OK' ((Get-AuditVisibility -Lines @('[OK] Process Creation (4688) auditing is ON -- feeds x.', '[OK] Logon (4624/4625) auditing is ON -- feeds y.', '[OK] Process-creation command-line logging is ENABLED (4688 events include the command line).')) -eq 'OK') ''
    T 'one OFF among ON lines: REDUCED' ((Get-AuditVisibility -Lines @('[OK] Logon (4624/4625) auditing is ON -- feeds y.', '[WARNING] Process Creation (4688) auditing is OFF [No Auditing] -- ...')) -eq 'REDUCED') ''
    T 'cmdline DISABLED alone: REDUCED' ((Get-AuditVisibility -Lines @('[OK] Logon (4624/4625) auditing is ON -- feeds y.', '[WARNING] Process-creation command-line logging is DISABLED -- ...')) -eq 'REDUCED') ''
    T 'the standard-user report: auditpol deferred, no ON line -> DEFERRED, never OK' ((Get-AuditVisibility -Lines @('[DEFERRED - ADMIN REQUIRED] auditpol (audit-policy visibility) requires admin -- ...')) -eq 'DEFERRED') ''
    T 'a report with no audit-policy lines at all -> UNKNOWN, never OK' ((Get-AuditVisibility -Lines @('[OK] something else')) -eq 'UNKNOWN') ''
    T 'an empty report -> UNKNOWN' ((Get-AuditVisibility -Lines @()) -eq 'UNKNOWN') ''
    T 'a SKIPPED localized row beside ON rows is still OK (the ON rows are evidence)' ((Get-AuditVisibility -Lines @('[OK] Logon (4624/4625) auditing is ON', '[SKIPPED] User Account Management (4720/4732) auditing state could not be read')) -eq 'OK') ''
    T 'auditpol itself SKIPPED (needs admin) with nothing else -> UNKNOWN, never OK' ((Get-AuditVisibility -Lines @('[SKIPPED] auditpol could not be queried -- audit-policy visibility NOT verified (needs admin).')) -eq 'UNKNOWN') ''
    if ($fails) { Write-Output "[FAIL] $fails report_safety self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] report_safety self-test: audit visibility is OK only on evidence of auditing ON, REDUCED on any OFF, and never OK by default.'
    exit 0
}

if ($Mode -eq 'Preamble') {
    @'
====================================================================
  READ THIS FIRST -- WHAT THIS AUDIT CAN AND CANNOT TELL YOU
====================================================================
  This tool inspects Windows configuration, persistence points, and
  event logs from inside the running system. That catches a great deal
  of commodity malware, misconfiguration, and many hands-on-keyboard
  intrusions.

  A "CLEAN" result does NOT prove your device is safe. It means the
  checks that RAN found nothing -- not that nothing is there:
    * A targeted or nation-state actor with a kernel-level implant can
      hide from every check a tool like this performs. On-host, user-mode
      auditing cannot be authoritative against that class of adversary.
    * Some checks may have been SKIPPED (see COVERAGE & CONFIDENCE at the
      end) or blind because auditing was turned off (see Section 16).
    * This is a point-in-time snapshot. Clean now is not clean tomorrow.

  IF YOU ARE AT ELEVATED RISK -- a journalist, activist, human-rights
  defender, or someone worried about an abusive partner or acquaintance:
    * Running this audit, and especially REMEDIATING what it finds, can
      ALERT a person who has remote access to this device. Consider
      whether that is safe for you before acting.
    * If you may need it later (a protective order, a police report),
      PRESERVE EVIDENCE first: do not delete files or change settings
      until someone qualified has reviewed the device. Remediation
      destroys the proof.
    * You do not have to do this alone. Free, confidential expert help:
        - Access Now Digital Security Helpline ...... accessnow.org/help
          (24/7, multilingual, for civil-society and at-risk users)
        - Coalition Against Stalkerware ............. stopstalkerware.org
          (if you fear an abusive partner or acquaintance)
        - Citizen Lab (targeted-threat research) .... citizenlab.ca
    * If you are in immediate danger, contact local emergency services.
====================================================================
'@
    return
}

# ---- Coverage mode -------------------------------------------------------
$crit = 0; $warn = 0; $skip = 0
$auditVis = 'UNKNOWN'
if ($Report -and (Test-Path -LiteralPath $Report)) {
    try {
        $lines = Get-Content -LiteralPath $Report -EA Stop
        $auditVis = Get-AuditVisibility -Lines $lines
        foreach ($l in $lines) {
            $t = $l.TrimStart()
            # Anchor to the line's OWN leading tag, the same rule block_sev.ps1
            # applies. Unanchored matching counted every line that merely
            # MENTIONED the token -- including the TOP FINDINGS block that
            # top_findings.ps1 prepends, which quotes each finding, so every
            # finding was counted twice in the block that is supposed to tell
            # the reader how much to trust the run.
            if ($t -match '^\[CRITICAL\]') { $crit++ }
            elseif ($t -match '^\[WARNING\]') { $warn++ }
            elseif ($t -match '^\[SKIPPED\]') { $skip++ }
            # A helper that is missing is a check that DID NOT RUN. doze_sec.bat
            # reports those as "[INFO] tools\X.ps1 not found -- ... skipped",
            # which the [SKIPPED] test above never matched. So deleting a helper
            # -- say stalkerware_check.ps1, the one check that models an abusive
            # partner -- left this block asserting "every attempted check
            # produced a result" while that check had silently vanished. An
            # honesty block that certifies coverage it does not have is worse
            # than no honesty block at all.
            elseif ($t -match '^\[INFO\]' -and $t -match 'not found' -and $t -match 'skip') { $skip++ }
        }
    } catch {}
}

'===================================================================='
'  COVERAGE & CONFIDENCE'
'  ------------------------------------------------------------------'
"  Findings this run : $crit critical, $warn warning line(s)."
if ($skip -gt 0) {
    "  Checks SKIPPED    : $skip -- these could NOT run (permissions, a"
    '                      disabled service, missing data, or a helper script'
    '                      that was not found). A clean overall result does'
    '                      not cover what was skipped.'
} else {
    '  Checks SKIPPED    : 0 -- every attempted check produced a result.'
}
switch ($auditVis) {
    'REDUCED' {
        '  Audit visibility  : REDUCED -- Windows security auditing is partly'
        '                      OFF (Section 16). A clean event-log result may'
        '                      only mean the events were never recorded. Enable'
        '                      auditing and re-run before trusting a clean pass.'
    }
    'OK' { '  Audit visibility  : OK -- the event-based checks had auditing enabled.' }
    'DEFERRED' {
        '  Audit visibility  : NOT VERIFIED -- the audit-policy check needs'
        '                      administrator rights and did not run. Whether the'
        '                      event-based checks could see anything is unknown;'
        '                      re-run as administrator.'
    }
    default {
        '  Audit visibility  : NOT VERIFIED -- no audit-policy result was found'
        '                      in this report. Treat every event-based clean'
        '                      result as unconfirmed.'
    }
}
'  ------------------------------------------------------------------'
'  A clean result lowers the odds of commodity compromise. It cannot'
'  rule out a sophisticated, targeted actor. If you have specific reason'
'  to believe you are targeted, treat this as one input and seek expert'
'  review (see READ THIS FIRST at the top of this report).'
'===================================================================='
