# Retrospective: 2026-09-01 → 2026-09-23 — seams, field runs, and the machine the tool has never seen

Scope: twenty-eight pull requests, #188 through #215, and ten or more field
runs, every one of them on the owner's Windows 11 laptop. The period began by
shipping the 2026-08 retrospective's safety recommendations and ended with the
first field run in the project's history that found nothing new.

The purpose of this project is to protect people who cannot defend themselves.
That framing is the standard everything below is measured against.

## 1. Timeline

| Phase | Refs | What |
|---|---|---|
| 2026-08 recommendations shipped | #188–#191 | quarantined test output; blast-radius manifest; read-only field mode; the benign look-alike corpus |
| Report and remediation truth | #192–#196 | commands that could never run; lines that never reached the report; findings that never reached the ledger; the command probe |
| Field runs 09-05 → 09-07 | #198, #203–#206 | fourteen "injected" Office modules; a null-roots crash on every machine without Office; `:dz_ps_scan` had never raised a finding; MSIX catalog signatures; bthmodem.sys was CORRUPT and Windows agreed |
| Overstated claims | 09-08 → 09-14 | CBS.log read for corrupted system binaries (T1554); three claims the tool could not back; Memory Integrity stated beside an unsigned-driver finding |
| Field run 09-19 | #211, #212 | the BITS rule flagged the same benign Edge job through a third rule; the dashboard measured the process list twice; a severity tag on a gloss |
| The seam sweep | #213, #215 | every severity-emitting tool gets a pure verdict function and a self-test; seven tools seamed, each with a rule a real machine would have tripped |
| Field run 09-20 12:57 | #214 | CRITICAL on a clean machine; exit code 0 on the default path for every run ever; a permanent false all-clear in Section 16 |
| **Field run 09-20 18:50** | — | **seven predictions, seven correct, no new defect: the first clean confirmation run** |

Verification gates on `main` at the end of the period: nine lints, the marker
and safety self-tests, the printed-findings assertion, the benign-corpus lint
and report grader, twenty-one tool self-tests, and six Windows jobs. Forty-six
benign look-alikes are catalogued, thirty-five of them proven by a CI step.

## 2. What went well — with the evidence

**Field runs kept finding what CI could not, and the yield fell to zero.** The
09-05 to 09-07 runs produced eleven defects. The 09-19 run produced three. The
09-20 12:57 run produced six, two of them in mechanisms that had never worked
on any machine. The 09-20 18:50 run produced none. That curve is the evidence
that the tool has become trustworthy on the one machine it has been run on.

**Predictions written before a run made the scoring honest.** Each field run
was preceded by falsifiable predictions written into the plan. The 09-20 12:57
run scored "tag count equals finding count" as 10 = 10, and only the
prediction made it visible that the equality held by cancellation: one extra
aggregate line and one counted row printed with no severity tag. That
cancellation became defect number six of the run.

**Mutation testing caught three tests that could not fail.** The first gloss
lint reported `[OK]` on a mutated tree because every fix had left a comment
between the two lines it required to be adjacent. A stalkerware case was
labelled "hard cast" under an error preference that never unwinds. A
com_clsid fixture passed only because of the bare `\Public\` regex it should
have been guarding against. None of the three would have been found by
reading; each was found by mutating the code and requiring the test to fail.

**Surveys by structure found what surveys by wording missed.** "One gloss and
no other" was eight. "log_gap has zero benign cases" was four. The adjacency
lint could not fail. In every case the lexical survey undercounted and the
structural one did not, which is now a rule in `CLAUDE.md`.

**The seam sweep found a real false positive in every tool it touched.**
Extracting the grading into pure functions was framed as test hygiene. It
found: an empty registry string reported as a hidden account; an offline
laptop reported as nine DNS blackholes; Process Explorer's documented
Replace-Task-Manager option reported as an IFEO hijack; every Patch Tuesday
driver replacement and every reboot's RPC port reshuffle reported as a change
worth a WARNING. Each was pinned verbatim as a must-not-raise case with the
first-party source beside it.

**The tool found true things on a real machine.** bthmodem.sys was corrupt,
and `CBS.log` said so in Microsoft's own words. Two accounts hidden from the
sign-in screen, an unsigned service binary, a BYOVD-abusable driver, and five
hardening gaps were all real. The "driver catalog gap" that would have
suppressed the bthmodem finding was measured before it was built, found not
to exist, and never shipped.

## 3. What went wrong — root-caused

### 3.1 Three mechanisms had never worked, on any machine, ever

- **`:dz_ps_scan` had never raised a finding** (#205). A `for /f` backtick
  command beginning with a quote is mangled by `cmd /c`, the loop body never
  ran, and the grade kept its `OK` default. Eighteen call sites, both bats,
  every machine, since the mechanism was written.
- **The exit code was 0 on the default path for every run** (#214). The
  console-log re-exec handed the code back through `echo %EXIT_CODE%>file`,
  and cmd reads a digit before `>` as a handle. The #96 fix never worked; the
  harness passes `-noConsoleLog`, so CI only ever tested the other path.
- **Section 16's service-install filter could never match** (#214). Its
  findstr tokens were XML element names run against `wevtutil /f:text`
  output. It printed `[OK] No recent service install events` on every
  machine while Section 18 listed twenty-six in the same report.

*Root cause, common to all three.* Each had a test that asserted the
mechanism fired, and none had a test that compared the tool to itself. The
assertions that found them are of a different kind: report against ledger,
dashboard tile against section verdict, process exit code against the
report's own `EXIT CODE:` line. A backstop that fires on the failure makes
the failure invisible, and a default of `OK` makes a broken grader look like a
clean block. Both are now rules, and both are enforced.

### 3.2 A CRITICAL on a clean machine, from a regex nine tools shared

`\Public\` was written to mean `C:\Users\Public\` and matched any directory
named public. Adobe's Node native addon under `node_modules\...\public\` in
Program Files was reported as loaded from a staging path: CRITICAL, exit code
8, "treat as incident response". Nine tools carried the same regex.

*Root cause.* A directory-name regex with no parent, and no must-not-raise
case containing the bare word. The fix anchored all nine and pinned the Adobe
path verbatim; restoring the bare regex fails three self-test cases.

### 3.3 Our own residue reported as an intrusion for three weeks

Six Event 7045 records with image path `cmd.exe /c rem dz_probe`, left by a
manual run of the EDR verification block on 08-30, were listed as suspicious
service installations on every audit until 09-20. The exclusion knew
`dz_selftest` and `dzsmoke`, not the marker the block used before #200. The
corpus entry said the residue was handled. It was not.

*Root cause.* The catalogue described the plants as they are, not the records
as they were. A corpus entry is a claim, and this one had no test.

### 3.4 The author's surveys undercounted, three times

"This one instance and no other" (#212) was eight instances. "log_gap_check
has zero benign cases" was four. "Verified" was said of the adjacency lint
before its mutation had been run. Each undercount was corrected in the same
period, and each correction is recorded beside the claim it corrects.

*Root cause.* A survey keyed on how the thing is usually written finds the
instances written that way. The sweep that finds the rest counts structure:
severity tags per emitted block, benign cases per verdict function.

### Also

- A CI step shipped red on its first run because it queried the event log
  300 ms after `sc create`; the Service Control Manager writes 7045
  asynchronously. Fixed the same hour; the step now waits and fails on
  absence with its own message.
- Squash merges on a reused branch made every push after a merge a
  force-with-lease over already-merged history. Harmless, verified each time
  by an empty tree diff, but a step that could go wrong.
- `pwsh` disappeared from the development container mid-period, so the last
  docs-only change could not run `lint_docs_drift` locally before CI.

## 4. The systemic pattern underneath all of it

**The gap moved, and it did not close.** The 2026-08 retrospective found that
CI tested a runner rather than the target. This period closed that gap for one
machine: every field run, ten or more, was on the owner's Windows 11 laptop,
elevated, in read-only mode. The tool has never run on the machine of the
person it exists for, never by anyone but its author, and never as a standard
user. `doze_sec_noAdmin.bat` has CI coverage only.

**The corpus is one laptop's software.** Forty-six benign look-alikes,
catalogued from Brave, Signal, Proton Drive, Docker, Adobe, Logitech, Ollama,
Codex, Process Explorer and WiFiman. A second machine carries a different set,
and the next false positives live there. The clean confirmation run on 09-20
is evidence about one machine, not about the next.

**The tool's two strongest answers to a capable actor have never run in the
field.** THREAT_MODEL calls baseline diff the strongest signal against an
implant no signature knows. Diff mode has run only on CI runners; no baseline
has ever been captured on a real machine. The DNS integrity probe has never
run outside CI either. Both are refused by the read-only field mode, which is
the only mode a field run has ever used.

**The manifest over-claims by less than it looks.** Twenty-two of 107
techniques have no detection by id. About half are not host-observable by a
point-in-time audit (spearphishing links, exfiltration, archiving collected
data, lateral tool transfer). Several are labelling drift: the RMM and LOLBin
process checks exist and carry no T1219 or T1218 id. One is a real gap: T1036
masquerading, a system-process name running outside its canonical directory,
is the most common evasion on a client machine and has no check.

## 5. Recommendations — prioritized

### P0 — reach the target

1. **A second real machine, read-only.** `tests\field_test.ps1` on another
   person's Windows laptop: nothing to install, nothing to undo. Predictions
   written in advance; every finding adjudicated against the corpus. This is
   the only step that moves the tool toward its audience, and it costs no
   code.
2. **The same laptop as a standard user.** One `doze_sec_noAdmin.bat` field
   run. The person the tool exists for is often not an administrator of the
   machine that matters.

### P1 — exercise the strongest detections

3. **Capture a baseline and run the DNS probe once on the owner's machine.**
   One elevated run with `-baseline save` and `-dnsprobe`: one snapshot file
   under `C:\SecurityAudit`, nine resolutions of Microsoft's own names. From
   then on every field run diffs against the baseline, and the October Patch
   Tuesday becomes the real test of the churn rule #215 pinned in a
   self-test.
4. **Close T1036 and relabel T1219/T1218.** A finding for `svchost`,
   `lsass`, `csrss`, `services`, `winlogon`, `smss`, `wininit`, `explorer`
   running outside their canonical directory, with a self-test and corpus
   entries; the ids on the checks that already exist.

### P2 — hygiene

5. **Stop layering gates.** The seam sweep is complete and the last
   confirmation run was clean. Add a gate when a field run demands one.
6. **Keep the prediction-before-run discipline** for every field run, with
   the score reported misses first.
7. **The 2026-08 items still open**: provider-qualified event queries as a
   lint (5), the signed-under-System32-is-context audit (6), non-vacuity as a
   lint over `tests/*.ps1` (7), and CI economics (9). None was the cause of a
   defect this period; none should pre-empt P0.

### Explicitly not recommended

- **A second retrospective-driven fix cycle.** Every defect of this period
  came from a field run or from the seam sweep, not from re-reading the code.
- **Any plant-harness run on a machine a person depends on.** The VM-or-CI
  rule from 2026-08 stands; the 08-30 residue is still in the owner's System
  log.
- **Building the twenty-two manifest ids into detections.** Most are not
  host-observable; the honest move is the relabel in recommendation 4 and a
  manifest note for the rest.

## 6. On the tool's epistemics — updated

The 2026-08 answer stands: a clean result means "none of the specific traps
I know how to set were sprung, as far as the OS would tell me". This period
adds a second limit. A clean confirmation run is evidence about the machine it
ran on. The corpus, the pinned benign instances and the seven-of-seven score
all describe one laptop. Until the tool has run on a second machine, its
false-positive rate on the machines it exists for is unmeasured, and the
report should not be read as if it were.
