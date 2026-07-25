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
    [string]$Report = ''
)

$ErrorActionPreference = 'Continue'

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
$auditBlind = $false
if ($Report -and (Test-Path -LiteralPath $Report)) {
    try {
        $lines = Get-Content -LiteralPath $Report -EA Stop
        foreach ($l in $lines) {
            if ($l -match '\[CRITICAL\]') { $crit++ }
            elseif ($l -match '\[WARNING\]') { $warn++ }
            elseif ($l -match '\[SKIPPED\]') { $skip++ }
            if ($l -match 'auditing is OFF' -or $l -match 'command-line logging is DISABLED') { $auditBlind = $true }
        }
    } catch {}
}

'===================================================================='
'  COVERAGE & CONFIDENCE'
'  ------------------------------------------------------------------'
"  Findings this run : $crit critical, $warn warning line(s)."
if ($skip -gt 0) {
    "  Checks SKIPPED    : $skip -- these could NOT run (permissions, a"
    '                      disabled service, or missing data). A clean'
    '                      overall result does not cover what was skipped.'
} else {
    '  Checks SKIPPED    : 0 -- every attempted check produced a result.'
}
if ($auditBlind) {
    '  Audit visibility  : REDUCED -- Windows security auditing is partly'
    '                      OFF (Section 16). A clean event-log result may'
    '                      only mean the events were never recorded. Enable'
    '                      auditing and re-run before trusting a clean pass.'
} else {
    '  Audit visibility  : OK -- the event-based checks had auditing enabled.'
}
'  ------------------------------------------------------------------'
'  A clean result lowers the odds of commodity compromise. It cannot'
'  rule out a sophisticated, targeted actor. If you have specific reason'
'  to believe you are targeted, treat this as one input and seek expert'
'  review (see READ THIS FIRST at the top of this report).'
'===================================================================='
