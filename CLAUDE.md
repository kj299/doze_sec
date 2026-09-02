# doze_sec — repo guidance

Windows 10/11 security audit tool. Scope, coverage matrices, non-goals, and
known detection gaps are defined in THREAT_MODEL.md — keep it (and the
README coverage counts) in sync when adding or removing detections. Main deliverables are two large cmd.exe
batch scripts (`doze_sec.bat`, `doze_sec_noAdmin.bat`) plus PowerShell helpers
in `tools/`. Target platform: every Windows 10 and Windows 11 build — assume
only built-in Windows PowerShell 5.1 and cmd.exe. Do not use `pwsh`-only
(PowerShell 7) syntax in `tools/*.ps1`, and do not assume `wmic` exists
(removed in Windows 11 24H2+; always provide a fallback).

## Batch comment rule (REQUIRED — recurring bug class)

**Never use `::` comments inside parenthesized blocks** (`if (...)`,
`for ... do (...)`, `else (...)`). cmd.exe parses `::` as a label, not a
comment, inside `( )` scopes:

- a `)` in the comment text closes the block prematurely — both if/else
  branches fire and "The system cannot find the drive specified." errors
  appear (issue #108);
- two adjacent `::` lines execute the second one as a command;
- a `::` as the last line of a block is a syntax error.

Use `rem` for every comment inside a parenthesized block. `::` is fine at
top level (column-0 section banners etc.). Note that `rem` text still
undergoes `%var%` expansion at parse time — write `date`/`time`, not
`%date%`/`%time%`, in comment text, and never end a `rem` line with `^`.

History: this bug class recurred in issues #35, #36, #39, PR #93 review,
and #108. It is now enforced by lint.

## Never leave the user's machine unusable (REQUIRED)

A command or test handed to a person to run on their own machine must not be
able to leave that machine unusable. This is not hypothetical: the detection
harness registers a credential provider, a screensaver and a Winlogon Notify
handler that all point at DLLs which deliberately do not exist. On an ephemeral
CI runner that is invisible -- nothing ever locks it. On a real laptop, the
screen locked mid-run, LogonUI could not draw an unlock UI, Ctrl+Alt+Del did
nothing, and the owner was locked out of their own machine. The runbook had
told them to start it and walk away.

So, for anything a user runs locally:

- **Default to the safe path.** Destructive or lock-out-capable behavior is
  opt-in via an explicit switch, never the default. `manual_ci.ps1` passes
  `-NoLockScreenRisk` unless `-AllowLockScreenRisk` is given.
- **Warn in the imperative, up front, and say what the bad outcome is** --
  "you would be locked out and need a hard power-off", not "may affect logon".
  A warning that does not name the consequence is not a warning.
- **A skipped dangerous check is declared, never silent** (`[ SKIP ]` with a
  reason), so a green run can never imply coverage it did not have.
- **Ask what happens if this is interrupted**, and ship the recovery: cleanup
  must be runnable standalone and cold (`tests\cleanup_selftest.ps1`), not only
  as an in-process `finally`.
- **Test artifacts are quarantined and stamped.** A harness run passes
  `-selftest`: output goes under `…\SecurityAudit\selftest\` and the report
  opens with `*** TEST RUN -- every finding below was planted ***`. A report of
  planted findings must never be mistakable for, or auto-diffed against, a real
  audit -- the owner opened one and asked how to fix their computer.
- **Every plant declares its blast radius.** Each case in
  `tests/detection_selftest.ps1` carries `Touches` (every host mutation, as
  `kind:target`) and `Affects` (which of logon / boot / network / defense it
  can hit). `tests/safety_invariants.ps1` reads the harness AST and fails on
  any plant without a declaration, infers the axes from what the plant body
  touches so a declaration cannot be quietly omitted, and requires the cold
  cleanup to cover every declared target. Its `-SelfTest` proves it fails on
  a mutated harness. The harness prints the blast radius before it plants.
- **Two activities, two scripts.** On the machine a person is sitting at:
  `tests\field_test.ps1` -- runs the audit with `-readonly` (no change outside
  the output folder and the temp folder, no network connections), proves that
  claim before/after, and hands every finding over for adjudication against
  `tests\benign_corpus.txt`. The plant harness (`manual_ci.ps1`,
  `detection_selftest.ps1`) is for a throwaway VM or CI only. `-readonly` is
  kept honest by `tools\lint_readonly.ps1`: every `reg add` / `bcdedit /set` /
  restore-point / download site in the bats must stay behind a gate.
- **Every known false positive is catalogued.** `tests\benign_corpus.txt`
  names each benign look-alike, the tool's line for it, its allowed severity,
  and the test that proves it (`harness:` Invert case, `ci:` step, or a
  `field:` reason). `tools\benign_corpus_check.ps1 -Mode Lint` fails on an
  unresolvable proof or an uncatalogued Invert case; `-Mode Report` grades a
  real report and is run by `field_test.ps1` and the harness.
- CI keeps full coverage where the risk does not apply -- a runner has no lock
  screen to break -- so safety on the user's machine costs no test coverage.

## Lint (run before committing batch changes)

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1
```

Scans all `.bat`/`.cmd` files with a cmd-accurate parenthesis-depth tracker
and fails on any `::` comment inside a block. CI runs the same script on
every push/PR (`.github/workflows/lint.yml`). It needs only built-in
PowerShell (5.1+ on Windows, `pwsh` on CI) — no external dependencies.

## Printing a finding is not raising it (REQUIRED — enforced by lint)

Every verdict the tool produces — the per-section `CLEAN`/`ISSUES FOUND` line,
`FINDINGS COUNTED`, and the process exit code — derives from the findings
ledger. Writing `[CRITICAL] ...` into `%REPORT%` reaches none of them: the
line sits in the report while the section says "CLEAN -- no issues detected".
A retrospective found ~25 checks in exactly that state (Cobalt Strike named
pipes, WMI subscription persistence, IFEO accessibility hijacks, ransomware
extensions, AMSI-bypass traces, unsigned system-path DLLs, recent root certs).

So a check that can print a severity **must** reach the ledger by one of:

- **staged PowerShell block** → run it with
  `call :dz_ps_scan <section> <technique> "<message>"` instead of redirecting
  into `%REPORT%`. It appends the output, grades it with `tools\block_sev.ps1`
  (leading-tag parsing — `[OK]`/`[INFO]`/`[SKIPPED]` never inflate a block),
  and raises once at the highest severity the block printed;
- **marker file** → the tool writes a severity word to `%TEMP%\dz_<name>.txt`
  and the bat reads it with `set /p` and calls `:dz_finding`;
- **direct `echo`** → a `call :dz_finding` beside it.

Anything that prints a tag but is genuinely not a finding (audit
self-degradation, a per-item line whose aggregate raise is elsewhere) goes in
`tests/unraised_allowlist.txt` **with a reason**; the lint prints the used
exemptions and warns about stale ones.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_unraised_findings.ps1
```

Fails on any staged block that emits a severity without `:dz_ps_scan` or a
marker, and on any direct `echo [CRITICAL]/[WARNING] ... >> "%REPORT%"` with no
raise nearby. CI runs it on Linux (`lint.yml`) and again on Windows PowerShell
5.1 (`windows-smoke.yml`), where the Windows job also asserts the lint actually
scanned the blocks — a parser regression must not turn into a vacuous pass.
`tests/detection_selftest.ps1` closes the loop at runtime: any section whose
body prints a finding must declare `ISSUES FOUND`.

## Real-Windows CI (`.github/workflows/windows-smoke.yml`)

The lint above is Linux/pwsh and cannot exercise cmd.exe, Windows
PowerShell 5.1 runtime behavior, real WMI/CIM, `findstr`, or detect a
runtime hang. `windows-smoke.yml` runs on a real `windows-latest` runner on
pushes to `main`, on manual dispatch, and **on any PR that touches functional
code** (the bats, `tools/`, `tests/`, `ThreatLists/`, the workflows). Docs-only
PRs skip it. The repo is private (metered minutes) and these five Windows
jobs bill at 2x, which exhausted a month's quota mid-cycle in 2026-08; the
first response removed the suite from PRs entirely, which was wrong -- a diet
must never cost coverage of a bug fix or feature. The `paths` filter and the
concurrency-cancel rule are the cost controls. `tests\manual_ci.ps1` (run
elevated on a real Windows machine) remains available as a second bench; during
the outage that manual route caught five real bugs CI had never seen. The jobs:

- **helpers-ps51**: parses every `tools/*.ps1` with the 5.1 parser and
  executes the read-only ones (scheduled tasks, browser extensions,
  `select_lines.ps1` incl. a 20,000-char line, `top_findings`,
  `report_format`, `report_html` (asserts the Findings Index + section
  links), `ioc_hash_check`, `srp_check`, and the INIT-path extractions
  `self_update_check` / `disk_info` / `smart_health`) against real
  WMI/CIM/Authenticode.

## INIT-path PowerShell: prefer tools/*.ps1 over inline echo-built PSRUN

Building PowerShell by echoing lines into `%PSRUN%` and running it is a
recurring crash source: any mis-escaped `(` `)` `{` `}` `|` `<` `>` `&`
makes cmd.exe abort the whole audit (": was unexpected at this time"). This
bit INIT 12 (SRP) and the HTML report. When a block has nesting (try/catch,
calculated properties `@{N=..;E={..}}`, if/elseif chains), put it in a
`tools/*.ps1` with a `-Mode`/param contract and call it — the script has NO
cmd escaping and is parsed+executed by the helpers-ps51 CI job. Already
extracted: `report_html`, `srp_check`, `self_update_check`, `disk_info`,
`smart_health`, `dns_probe`. Simple single-value one-liners (e.g.
`(Get-CimInstance ...).Prop`) can stay inline.
- **readonly-field-test**: runs `tests\field_test.ps1` (the script a person
  runs on their own machine) and asserts the `-readonly` proof lines executed:
  RunOnce absent, boot configuration unchanged, READ-ONLY banner, corpus clean.
- **full-run**: runs `doze_sec.bat -dev -sdu -nosrp` end-to-end under a
  20-minute timeout. A hang (e.g. findstr on multi-KB lines) blows the
  timeout and fails the job; output is uploaded as an artifact.

This is the authoritative end-to-end check — prefer it over reasoning about
runtime behavior from a non-Windows dev box. When a `.ps1` or section is
added, extend the helpers-ps51 job to execute it.

## Other cmd.exe traps already documented in-code

- Inside blocks use delayed expansion (`!var!`); `%var%` expands at
  block-parse time (see comments near the `errorlevel` checks).
- `endlocal` and `exit /b %EXIT_CODE%` must stay on one line so the value
  is captured before `endlocal` clears it (closes #96).
- Parens in `echo` text written into generated scripts must be escaped
  (`^)`, `^|`) when the echo can run inside a block.
