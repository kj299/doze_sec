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
- **The remediation script is the one artifact a person runs elevated.** It is
  generated by `addfix 'tag' "command"` lines echoed into `%PSRUN%`, so the
  command is a *double-quoted PowerShell string* and every `$var` in it expands
  while the file is being WRITTEN, not when the user runs it. Two commands
  shipped broken this way (`\$false` became `\False`; a `$_`/`$ms` block became
  a parse error that voided the entire file). Use single quotes for command
  payloads, and remember cmd eats `^` **outside** double quotes and leaves it
  **inside** them. `tools/lint_remediation.ps1` reproduces the whole expansion
  and parses what would really land on disk; its `-SelfTest` proves it fails on
  each bug class. The generated script asserts elevation, states that it has no
  undo, and its guard text must stay legible with no colour.
- **Remediation is staged, and every fix states its reversal.** `addfix` and
  `addenforce` take an UNDO argument; a fix with no safe reversal passes `''`
  and the generated line says so. Stage 1 (`Remediation_<ts>.ps1`) holds the
  safe, reversible changes; `_enforce.ps1` holds the ones worth observing in
  audit mode first (ASR block); `_undo.ps1` collects the reversals. Fixes can
  be triggered from the findings LEDGER, not just the dashboard prose --
  `if(led 'WARNING' '9' 'T1562.001' '<message substring>')`. The ledger is
  complete by the time the summary block runs. SECTION+CODE is not unique, so
  a trigger also matches part of the message. The fix counter keys on the
  `# FIX: ` marker, never a list of command verbs -- a verb list silently
  dropped fixes it did not recognise while still writing them into the file
  the user runs.
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

**A REAL run now closes that loop too.** The harness asserted the invariant for
a long time while an actual audit never checked itself, so the one machine that
mattered was the only place the check did not run: a field report printed three
`[WARNING] Key ASR rule not in Block mode` lines into Section 9 and then
declared `CLEAN`, and the finding never reached the ledger, `FINDINGS COUNTED`,
the exit code or the remediation script. `tools/verdict_audit.ps1` runs after
Section 18, reuses `tests/unraised_allowlist.txt` so curated exemptions are not
duplicated, appends its result to the report, and raises `AUDITGAP` when a
section printed a finding it never raised.

**A grader that cannot read its input says so.** `tools/block_sev.ps1` returns
`UNREADABLE`, never `OK`, when the block output cannot be read, and retries
briefly first because the caller writes that file with one process and reads it
with the next. `:dz_ps_scan` turns `UNREADABLE` into a declared `AUDITGAP`
finding. Returning `OK` there was the original defect: not inventing a finding
is right, but claiming cleanliness is indistinguishable from having checked.
Checks whose miss would be silent also drop a marker as a backstop (the ASR
block does, alongside its grade), raised only when the grade came back `OK`, so
a correct grade never double-counts.

## The report is the product (REQUIRED — enforced by lint)

A line the report *prints* must actually reach the report, and a command it
tells the reader to run must actually run. One field run exposed three classes
at once, none of which any findings-oriented gate could see:

- **Odd quote count on an `echo ... >> "%REPORT%"` line.** cmd honours double
  quotes when it looks for a redirection operator, so an unbalanced `"` puts
  the `>>` *inside* a quote. Text, operator and report path are all printed to
  the CONSOLE and the line never reaches the report. Two narrative lines shipped
  this way; the sentence that survived broke mid-clause.
- **A caret inside double quotes.** Outside quotes cmd CONSUMES `^`; inside
  them it leaves it alone. 90 display lines carried `^(`, `^)` or `^|` inside
  quotes, so the report printed stray carets — and pasting
  `wevtutil ... /q:"*[System[^(EventID=4720^)]]"` hands those carets to
  wevtutil, which rejects the XPath.
- **A truncated `Command:` line.** 22 per bat had lost an opening paren
  (`"Get-MpPreference).ExclusionPath"`, `"Test-Path $f) {"`) or stopped
  mid-hashtable (`@{LogName='Security'`). They printed, they looked
  authoritative, and none would run.

So: inside cmd double quotes, escape nothing — `(`, `)`, `|`, `<`, `>`, `&`
are already literal there. Every `Command:` line must be something a reader can
paste and run, and must describe what the check actually does.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_report_echo.ps1
```

Fails on an odd quote count, on a caret inside quotes, on unbalanced
`()`/`[]`/`{}` in a `Command:` line, and on a printed `powershell -Command`
payload that does not parse under the 5.1-level AST parser. `-SelfTest` proves
it fails on each class; it reports 210 defects against the code that shipped
them. CI runs it in `lint.yml`, and `manual_ci.ps1` runs it in step 1.

### Parsing is not running (REQUIRED — enforced by probe)

`lint_report_echo` proves a printed `Command:` line parses. That is a weaker
claim than the line makes: the report says "here is how to check this
yourself". This project has already paid for the difference once — two
remediation commands parsed cleanly and could never execute.

`tools/report_command_probe.ps1 -Report <report>` runs them, against the report
a `-readonly` audit just produced, so it tests the exact text a reader would
paste with `%VAR%` already expanded.

- It executes **nothing it cannot prove read-only**, by allowlist — a deny-list
  misses what it has not seen, and this is the one part that touches a machine.
  Six printed lines are genuinely not read-only (the RunOnce `reg add`, the
  `ping`, the self-update `Invoke-WebRequest`); they honestly document the
  audit's own INIT actions, and are skipped **by name with a reason**.
- A line it cannot classify at all is a **failure**, not a skip. Adding a check
  whose `Command:` line uses something new will fail until the allowlist is
  taught what it is — that friction is the point.
- It grades **well-formedness, not findings**. Finding nothing is success; a
  missing path, service, log or optional module is machine state. Do not read a
  green run as more than "the printed line is well-formed and invocable".
- `-ClassifyOnly` runs the gate without executing anything; `-SelfTest` proves
  a malformed command fails, a mutating one is refused, and an unclassifiable
  one fails.
- A trailing `   [note]` on a printed line is documentation, and is stripped
  before execution. It was not, and `reg` received `[also the HKLM twin]` as
  arguments and answered *ERROR: Invalid syntax*.
- **A per-command timeout is not enough.** Two runs of the same tree went from
  3 slow commands to 29, taking the probe from 2.5 to 8.7 minutes; the worst
  case blows the job's own timeout and reads as a hang. `-BudgetSeconds` caps
  total wall clock and DECLARES the remainder as un-probed; the `-MinProbed`
  floor is what keeps that from passing as coverage. A slow command still
  counts as executed, because argument-binding and syntax errors surface in the
  first moments — one still working at the timeout has already shown it is
  well-formed.

**Never use `continue` inside a PowerShell `switch` to skip a loop iteration.**
It leaves the switch, not the loop. An early version of the probe fell through
after deciding to *skip* the RunOnce `reg add` and tried to execute it; on
Linux it died for want of `cmd.exe`, on Windows it would have written the key.
Use `if`/`continue`, and give any executor a guard that refuses a kind it was
never meant to run.

### Parsing on 5.1 is not meaning the same thing on 5.1 (REQUIRED — enforced by lint)

The 5.1 parser check above catches syntax pwsh accepts and 5.1 REJECTS. The
worse class is the opposite: source both engines accept and **read
differently**. There is no parse error to find, so every existing gate is blind
to it, and it stays invisible until a case that depends on it runs on real 5.1.

`tools/hosts_check.ps1` shipped two instances at once. Its UTF-8 BOM strip was:

```
$l = $raw -replace "^\xEF\xBB\xBF", ''      # the mojibake form -- ASCII source, fine
$l = $l   -replace "^<raw BOM bytes>", ''   # meant to be U+FEFF
```

The second held the three raw UTF-8 BOM bytes typed into a **BOM-less** `.ps1`.
Windows PowerShell 5.1 decodes a BOM-less script as ANSI, so those bytes became
`U+00EF U+00BB U+00BF` and the line compiled to an exact **duplicate** of the one
above it. On the only engine this tool ships to, a real `U+FEFF` was never
stripped, the first HOSTS entry then failed the address test, and it was dropped
with no error. `Trim()` does not save it either — .NET does not classify
`U+FEFF` as whitespace. A blackholed `windowsupdate.microsoft.com` on line 1 of
a UTF-8 HOSTS file would have been **invisible**: a false negative, in the check
written specifically to close a false negative.

The test that should have caught it was written `` `u{FEFF} ``, which is
PowerShell 6+ only. 5.1 has no such escape — it drops the backtick and hands you
the literal text — so the case asserted against the string `"u{FEFF}127.0.0.1"`
and **could not fail for its own reason**. It passed on pwsh 7 across four
merges. Real-Windows CI is what finally caught it.

So, in every `.ps1`:

- **Pure ASCII source, everywhere, including comments.** Build the character
  from its code point (`[char]0xFEFF`), or in a regex use the .NET escape
  `﻿` — `\` is not a PowerShell string escape, so that stays ASCII in the
  source and means the same on both engines. Comments are covered too: not
  because mojibake in a comment breaks anything, but because a lint that has to
  tell a comment from a regex is a lint with an exception list to rot. (The
  repo's one other instance was a comment quoting a Japanese `auditpol` header
  — which rendered as mojibake to exactly the reader it was written for.)
- **No `` `u{...} `` and no `` `e ``** inside a double-quoted string.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_ps51_portability.ps1
```

Rule 2 is scoped **by AST**, to double-quoted and here-strings only. A backtick
escapes nothing in a comment, and this repo's comments quote identifiers
markdown-style (`` `else` ``, `` `echo` ``, `` `event ID` ``) — a naive file-wide
regex reported six defects across four files on its first run. A lint people
learn to work around is worse than no lint. `-SelfTest` proves it fails on each
class **and stays quiet on the prose**. CI runs it in `lint.yml`.

### "Unavailable" is not an answer (REQUIRED)

A check that cannot determine its own subject must say so *loudly and
itemised*, and its inability must be visible as a gap rather than absorbed as
calm. The PSv2 engine check — the AMSI downgrade path, T1059.001 — printed
`[SKIPPED] PSv2 state unavailable.` on **five real audits across two dates**,
elevated, and nobody noticed because a single skip reads like housekeeping.

Two failures stacked:

- `try{ Get-WindowsOptionalFeature -Online ... }catch{ ... }` had no
  `-ErrorAction Stop`. The failure was **non-terminating**, so the catch never
  ran and the block emitted *nothing at all* — not the data, not the fallback.
  A `try/catch` around a cmdlet without `-EA Stop` is not error handling.
- The CIM fallback returned nothing, so the `else` printed `[SKIPPED]`.

`tools/psv2_check.ps1` replaces both: five methods, most authoritative first,
and the verdict **names the method that answered**. `[SKIPPED]` only when all
five are inconclusive, and it then lists what was tried.

**Positive and negative evidence are not symmetric.** "v2 launched" proves the
downgrade path exists and outranks every declarative source. "v2 did not
launch" proves much less — absent .NET 3.5, a policy, any startup error looks
identical — so it is consulted **last** and the verdict says it was inferred.
For the same reason the registry method returns *inconclusive* when there is no
`HKLM:` drive at all, rather than reading a missing registry as a missing
engine. **False reassurance is the worse error in a security tool**, so every
method must be able to say "I don't know" separately from "it's fine".

CI treats a `[SKIPPED]` from this tool on a runner as a **failure** — a
runner's PSv2 state is knowable — and asserts the verdict and the ledger marker
agree, since a `[WARNING]` with no marker is a finding that never reaches the
ledger.

### A section and the dashboard must not contradict each other (REQUIRED)

One field report said both things about the same six `brave.exe` processes:
Section 4 raised `[WARNING] Suspicious process paths found above. Investigate
now.` while the summary reported `[INFO] Processes from user-profile paths, all
validly signed`. A reader cannot act on a tool that disagrees with itself, and
the alarming half was the wrong one — Brave, Chrome, Edge, Slack, Teams and VS
Code all install per-user under `\AppData\`, so a path match alone is not a
signal. Treating it as one is how a tool teaches its reader to ignore it.

`tools/proc_path_grade.ps1` now holds the rule for both: `\Temp\`,
`\Downloads\`, `\Users\Public\` and `$Recycle` are suspicious whatever the
signature says; `\AppData\` only when the binary is not validly signed. A
signature that cannot be verified counts as unsigned — for that decision "I
could not check" belongs with the risky half.

**Key existence is not evidence either.** Section 18's registry IOC check
flagged `HKLM\...\PortProxy\v4tov4\tcp [EXISTS]` while Section 3 of the same
report said `[OK] No netsh portproxy rules.` Windows leaves that key behind,
empty, once the rules are gone. A key-existence IOC now requires the key to
hold at least one value or subkey, and the finding says how many.

**"Not on disk" is not "unbacked".** The first field run with Word open
produced fourteen `[WARNING] ... reflective or unbacked load ... (T1055)` lines
for ordinary Office and VBA DLLs — the tool telling its owner that Microsoft
Word was running fourteen in-memory-injected modules on a clean machine. Office
Click-to-Run runs in a virtual application environment with private copies of
its files under `<install>\root\VFS\ProgramFilesCommonX64\`, so WINWORD reports
a `C:\Program Files\Common Files\...` path that exists only inside the process;
a bare `Test-Path` from outside says "not on disk". `module_inspect` now
resolves through the VFS before declaring a module absent — discovering the
package root from the loading process's own image path (the first ancestor with
a `VFS` subdirectory), not from a hard-coded product path, so a machine whose
Click-to-Run key is missing does not get its Office DLLs reported as injected.
When it still does not resolve, the wording states the two indistinguishable
causes instead of asserting injection. The downgrade is asymmetric: a staging
path keeps CRITICAL and a non-system path keeps the full T1055 finding — only
"plausible system path, not visible from outside" is downgraded, and to STATED
UNCERTAINTY, never to silence.

**Excluding our own plants means excluding the MARKER, never the NAME.** The
harness's EDR verification plants a service under a REAL product name
(`SentinelAgent`) because `edr_presence` matches by service name and a
test-scoped name would exercise nothing. Six Event 7045 records for it outlived
a manual run on a real machine and were reported as suspicious service installs
on every later audit — correctly, since a service with a `cmd.exe` image path is
exactly an attacker's shape. Excluding the *name* would let an attacker hide a
service by calling it `SentinelAgent`; the plants therefore carry `dz_selftest`
in the IMAGE PATH, which the check already excludes and declares as a count.

**Do not report our own test harness as an intrusion.** The plant harness
installs `dz_selftest_flag_svc`; cleanup removes the service but cannot remove
the Event 7045 record of installing it, so every later audit on that machine
reported five "suspicious service installations". Harness names are excluded
and the exclusion is declared with a count — never silently.

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
