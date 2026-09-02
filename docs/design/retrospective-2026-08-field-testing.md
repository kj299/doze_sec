# Retrospective: 2026-08-22 → 2026-09-01 — retrospective fixes, backlog, field testing, and a lockout

Scope: sixteen merged PRs and two direct merges. The period began as a
retrospective-driven fix cycle and ended with the tool being run, for the first
time, against the owner's real machine — which produced five detection bugs,
one systemic marker-loss bug across twelve tools, and an incident in which the
test harness locked the owner out of that machine.

The purpose of this project is to protect people who cannot defend
themselves. That framing is the standard everything below is measured against.

## 1. Timeline

| Phase | Refs | What |
|---|---|---|
| Retrospective, passes 1–3 | #173–#179 | 55 findings adjudicated: 39 fixed, 7 deferred with reasons, 9 folded in |
| Backlog | #180–#183 | timestamps on persistence findings; tamper-evident reports; event-log gap detection; confidence-calibrated section verdicts; EDR/Sysmon presence |
| CI outage begins | 2026-08-27 | Actions quota exhausted; every run reports zero billable compute |
| Field testing | 08-29 → 08-31 | the owner's Windows 11 laptop becomes the verification bench |
| Field fixes | #184, #185 | five detection bugs; the manual-CI runbook; standalone teardown; trigger diet |
| **Lockout incident** | **08-30** | **the detection harness locked the owner out of their own machine** |
| Safety fix | #186 | nine logon-path plants gated; `safety_invariants.ps1` |

Verification gates on `main` at the end of the period: three lints,
`marker_selftest`, `safety_invariants`, `detection_selftest` (32 must-fire
cases, roughly a dozen must-not-fire guards), `noadmin_smoke`,
`cleanup_selftest`, and `manual_ci` as the one-command runbook.

## 2. What went well — with the evidence

**The merge discipline was vindicated, not merely principled.** Refusing to
merge #183 on a green tick it had never earned looked like stubbornness for
three days of CI outage. When its assertions finally executed on a real
machine, the "unverified" branch was broken three ways — one of them a WARNING
that never reached the findings ledger. A green tick would have shipped all
three.

**The gates built in the earlier retrospective worked as designed.**
`lint_docs_drift` caught the author's own push. The section-sync rule in
`detection_selftest` and the `-Strict` no-empty-parse gates held throughout.

**Checks cross-examining each other is a real strength.** The event-log gap
check from #181 is what disproved the "System log was cleared" false positive
in the owner's own report: 47,098 consistently numbered records could not
coexist with a clear thirty minutes earlier. The tool caught its own lie,
from its own output, without touching the machine again.

**Field testing was the most productive verification in the project's
history.** One real machine, one weekend: five detection bugs, a marker-loss
bug across twelve tools, and the lockout. CI had been green over all of them
for months.

**Every fix shipped with a test proven in both directions** — failing on the
old code and passing on the new: `marker_selftest` (12/12 fail → 12/12 pass),
`safety_invariants` (fails when a tag is removed), and the ev104 and
network-provider CI pins that test the shipped fragment rather than a copy.

**The owner's machine ended more secure than it started**: firewall enabled on
all profiles, command-line process auditing on, ASR rules enabled, and a clean
bill of health from an independent marker scan.

## 3. What went wrong — six incidents, root-caused

### 3.1 Twelve tools could print a finding and never raise it

`Write-Marker` used `Set-Content -EA SilentlyContinue` into a directory it
never created. A real `[WARNING]` printed into the report while the ledger —
and so the section verdict, `FINDINGS COUNTED`, and the exit code — never
heard about it. The function was copy-pasted into twelve tools, including
`cross_api_check` (the rootkit detector), `boot_chain_check`, and
`driver_audit`.

*Root cause.* The lint guarding "printing is not raising" is static: it proves
a check *routes* through a marker, not that the write *lands*. And the CI
workflow pre-created the marker directories before invoking the tools, hiding
the fragility. No runtime test of the marker contract existed.

### 3.2 Two false ACTIVE COMPROMISE indicators

"System event log was cleared" fired on a smart-card reader's Event 104. Event
IDs are unique only per provider; the query matched the bare ID, and
`WudfUsbccidDriver` logs 104 for "the Smartcard reader reported the following
class descriptor". Separately, "Non-default network provider" flagged WSL's
own `P9NP` as cleartext credential capture, because the branch upgraded a
Microsoft-signed verdict to WARNING to keep a pre-WSL three-name allowlist
authoritative — against the file's own documented tiering.

*Root cause.* Both detections had a benign twin that was never tested. The
harness carries 32 must-fire cases and roughly a dozen must-not-fire guards.
For this audience, a false "you are compromised" is the most harmful output
the tool can produce: it causes panic, wrong action, and — worse — teaches the
reader to skip the section that would catch the real thing.

### 3.3 The `Sense` false positive and its self-contradicting summary

Windows ships the Defender for Endpoint sensor service inert on every machine
never onboarded to MDE. The check warned on it unconditionally, then the
summary announced "No third-party EDR agent was detected" three lines after
warning about a stopped one.

*Root cause.* As 3.2 — no benign-twin test. Additionally, CI runners (Server
2022) carry no `Sense` service, so the case was untestable there by
construction.

### 3.4 The lockout

`detection_selftest.ps1` registers a credential provider, a screensaver, a
Winlogon Notify handler, LSA Notification and Authentication packages, a
network provider, a logon script, and AppInit/AppCert DLLs — nine plants on
the logon and authentication path, every one pointing at a file that
deliberately does not exist. The runbook told the owner to start the run and
walk away for twenty minutes. The idle timer locked the screen. LogonUI, which
loads credential providers to draw the lock and Ctrl+Alt+Del screens, could
not render a usable unlock UI. Ctrl+Alt+Del did nothing. Recovery took a hard
power-off.

*Root causes.* (a) The harness was reviewed for what it detects, never for
what it does to the host. (b) It was designed for an ephemeral runner that
never locks and nobody sits at, then pointed at a laptop without
re-evaluating blast radius. (c) The instruction to walk away was precisely the
trigger. (d) **The first fix tagged three plants.** It was shipped from a
hypothesis about the mechanism rather than an audit of every plant; the audit,
done afterwards, found nine, and the six missed include LSA packages that
`lsass` loads at boot — a worse failure than the one that caused the incident.

### 3.5 Test-run reports are indistinguishable from real ones

The harness writes its planted-findings report to
`C:\SecurityAudit\SecurityReport_*.txt` — the same directory and name pattern
as a real audit. The owner opened one and asked how to fix their computer: ten
CRITICALs, every one planted by the test.

*Root cause.* No separation between test artifacts and real output.

### 3.6 Vacuous passes kept recurring — including in the author's own work

The harness's first field assertion printed PASS when the script under test
had not executed at all. The author's verification of the safety fix printed
OK against zero cases. A PowerShell double-quote interpolation made another
assertion compare against an empty string and report success.

*Root cause.* The project has a rule against vacuous passes and enforces it in
several named places (`-Strict` gates, `marker_selftest`'s minimum count), but
not as a general property that every test must satisfy.

### Also

The CI quota exhaustion was foreseeable: a private repository bills minutes,
`windows-smoke` runs five `windows-latest` jobs at 2× with 20–35-minute
timeouts, and it ran on every PR push. Neither workflow had
`workflow_dispatch`, so nothing could be re-run without pushing a commit. The
firewall plant flaked on a machine that re-arms its own profile. Every
session-bound watch died with a session restart.

## 4. The systemic pattern underneath all of it

**The verification strategy tested the tool on an environment that is not
its deployment target.** CI runs on Windows Server 2022: ephemeral, no user
session, no lock screen, no consumer software, no WSL, no smart-card readers,
no Defender for Endpoint, nobody sitting at it. The tool's target is a
person's Windows 10 or 11 laptop — the machine of someone who cannot defend
themselves. Every real bug this period, and the incident, lived in that gap.
Months of green CI were green *about the runner*, not about the target.

Two corollaries:

- **Harm asymmetry was inverted in the tests.** For this audience, false
  positives and host damage are worse than misses — yet the suite was weighted
  toward "does it fire", and no host-safety review existed at all.
- **Real-machine testing is simultaneously the most valuable activity and the
  most dangerous one**, and the project had no safe way to do it. That is the
  core thing to fix.

## 5. Recommendations — prioritized

### P0 — safety and trust

1. **Quarantine test output.** Harness runs write to
   `C:\SecurityAudit\selftest\` and stamp `*** TEST RUN — every finding below
   was planted by the test harness ***` on the report's first lines and in the
   HTML header. A test report must never be mistakable for a real one.
2. **A read-only field-test mode and a benign-baseline corpus.** Split
   real-machine work into two activities. *False-positive hunting*: run the
   audit read-only on real machines — safe anywhere, no plants. *Detection
   proving*: the plant harness, on a VM or CI only. Catalog known-benign
   look-alikes (`P9NP`, never-onboarded `Sense`, `WudfUsbccidDriver` Event 104,
   Codex sandbox accounts, …) in `tests/benign_corpus.txt` and regression-test
   them.
3. **A blast-radius manifest for the harness.** Every plant declares what it
   touches (registry, file, service, account) and whether it can affect logon,
   boot, or the network. `safety_invariants` fails on any plant without a
   declaration. This turns "the first audit found three, the answer was nine"
   into a structural impossibility.

### P1 — detection quality

4. **False-positive parity.** Every must-fire case names its benign twin; the
   emulation-corpus lint, which already enforces "every core detection has a
   plant", also enforces "every plant has a must-not-fire twin".
5. **Provider-qualified event queries as a lint.** Any `Get-WinEvent` or
   `wevtutil` query by bare event ID fails lint. The Event 104 lesson
   generalizes to every event-based check.
6. **Apply "Microsoft-signed under System32 is context" consistently.** Audit
   every DLL-path verdict for the allowlist-overrides-signature pattern that
   produced the `P9NP` false positive.

### P2 — engineering hygiene

7. **Non-vacuity as a lint over `tests/*.ps1`.** Every test must assert a
   minimum count of things examined — the pattern `marker_selftest` and
   `safety_invariants` already use, made mandatory.
8. **`docs/recovery.md`.** The lockout recovery ladder, durable in the repo
   rather than in a chat transcript. (Shipped alongside this document.)
9. **CI economics.** Keep the trigger diet from #185; decide between a public
   repository (unlimited minutes), a self-hosted Windows runner, or accepting
   manual gating on PRs. Note the trap that made the outage worse than it
   looked: six months of green over a bug is not evidence — it is the absence
   of a test.
10. **A working rule for agents, in `CLAUDE.md`.** Audit the full space before
    shipping a fix — "three of nine" happened because a hypothesis was shipped
    as an answer — and never say "verified" without a test that fails when the
    claim is false.

### Explicitly not recommended

- **Collapsing the twelve `Write-Marker` copies into a shared file.** The lint
  is the propagation mechanism. A shared helper adds a missing-file failure
  mode that would break every tool at once, which is worse than the
  duplication.
- **The two remaining older backlog items** (a coverage denominator; explicit
  `attack_matrix` "detected" semantics). They still cost more in structural
  risk than they return.
- **Any further plant-harness runs on the owner's daily-driver machine.** VM
  or CI only, until recommendation 2 exists.

## 6. On the tool's epistemics — a question the owner asked

"Does the code validate whether there is a compromise or not?" The honest
answer is no, and the report should never let a reader believe otherwise. The
tool queries the operating system through ordinary APIs; a kernel-level
implant sits beneath those APIs and can answer every one of them falsely, and
the tool would faithfully report clean. `report_seal.ps1` already states this
limit. A clean result means "none of the specific traps I know how to set
were sprung, as far as the OS would tell me" — meaningful, not a clean bill of
health. A finding means "investigate", not "compromised", as this period's
false positives demonstrated. The report's refusal to print "System appears
clean" is a strength and is tested; recommendation 2 extends the same honesty
to the false-positive side.
