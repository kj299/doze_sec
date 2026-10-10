# Changelog

All notable changes to doze_sec are recorded here. This is the project release
history; the per-run `ChangeLog_<timestamp>.txt` files under `C:\SecurityAudit`
are a separate, machine-specific record of changes each audit made.

## Unreleased

### The script-policy probe reads every helper's Mark of the Web, and a hidden question can no longer hang the audit
`tools\exec_probe.ps1` proved that PowerShell runs one script here: itself.
On a PC whose IT sets a Group Policy RemoteSigned or Unrestricted policy, an
unmarked script runs. A copy unzipped from a download carries the Mark of the
Web (a Zone.Identifier stream) on every file, and some of its files may have
been replaced since. RemoteSigned refused each marked helper; a refused helper
writes no marker, so its check read OK. Unrestricted stopped to ask about each
marked script, and every helper's output goes into the report, so the question
waited where nobody could see it and the audit hung. Microsoft documents both
(about_Execution_Policies). The probe now reads each helper's mark against the
Group Policy:

- RemoteSigned or Unrestricted with marked helpers prints
  `AUDIT NOT PERFORMED`, names each marked script with its zone, says what to
  do (carry the tool on a stick made by `make_usb_stick.ps1`, which never
  carries the mark) and exits 1. A missing verdict is never read as ok.
- No Group Policy with marked helpers prints an `[INFO]` line: the marks are
  harmless here and would not be on a managed PC.
- When PowerShell refuses even the probe, cmd counts the zone-3 and zone-4
  marks itself. The report names the mark as the cause only under a policy
  that checks it, and notes a network path, which Windows can place in the
  Internet zone.

A new printed `Command:` line shows the reader how to list the marks
themselves.

**What I had wrong.** CLAUDE.md said the probe "runs once before the first
helper". It never did: `threat_list_seed.ps1` runs before it on every run, and
`ttp_merge.ps1` does on `-updateTTP`. A fully marked copy under Unrestricted
would have hung there before the probe could say anything. A read-only review
of the plan found this before any code was written. The probe and every helper
before it now run `-NonInteractive`, so a question fails at once. The
documented field_test commands do the same, because under `Tee-Object` a
marked field_test's own question might not show.

**Measured, not argued.** The readonly job plants each Group Policy on a copy
of the checkout and asks Windows itself which marks it treats as downloaded:
zones 0 to 5, a stream with no header and an empty stream, under both
policies. The probe's rule is pinned to that answer: the job fails if Windows
refuses a script the probe reads as local. Both bats must then stop and name
two zone-3 helpers and not a zone-2 one. With the probe marked too, cmd must
count 3 and not 4. The hang itself is measured: a marked probe in its own
console, without and then with `-NonInteractive`. A fully marked copy run the
way a person runs it, in its own console with the console log on, must stop
within three minutes. A Linux guard keeps the bats' wiring.

### Sections 18c, 18d and 18h are proven to fire, each beside a look-alike that must not
18a and 18f had been proven by harness plants, and 18b and 18e by planted
pipes and tasks in the helpers job. 18c (services), 18d (staging files) and
18h (registry) had never matched anything in a test. The plant harness now
plants one indicator each that the lists name, and one look-alike each that
only resembles one:
- **18c** matches a service's name or display name as a substring. A
  never-started service named `dz_selftest_ioc_PSEXESVC` (PsExec's service
  name) must be matched. Its twin carries the real Windows name
  `SecurityHealthService`, and the list's look-alike entry
  `securityhealthservice2` must not match it. Both run `notepad.exe`, a validly
  signed Microsoft binary, so Section 7 grades them clean and cannot satisfy
  the Section 7 case for its own plant. The names avoid the harness's
  `dz_selftest_evil` marker for the same reason.
- **18d** tests an exact path. A harmless text file at the listed
  `%TEMP%\beacon.bin` must be matched. The same name in a folder the list does
  not name must not be.
- **18h** looks a value up by exact name. A per-user Run value named
  `ChromeUpdate` must be matched; it points at a file that does not exist, so
  nothing can run at logon. A value whose name only contains it
  (`ChromeUpdateHelper_dz_selftest`) must not be.

Each match must reach the ledger under its own section and technique
(`WARNING|18|T1543`, `CRITICAL|18|T1074`, `WARNING|18|T1112`). Each twin is
graded only when its sibling matched, and is catalogued in
`tests\benign_corpus.txt`. The cold cleanup removes each plant only by its
marker: a `beacon.bin` or `ChromeUpdate` value that is not the harness's is a
real indicator, and evidence, so it is kept and named. T1074 and T1112 are now
CORE in `tests\emulation_corpus.txt`. T1112 used to be UNTESTABLE ("no single
safe artifact to plant"); the Run value is that artifact.

The list's other registry entries are not planted on purpose. Defender
policy, UAC, LSA, the COM hijacks and the proxy setting would each change how
the machine behaves. 18h's bad-value judgement is pinned instead on real
machine state: the full-run job asserts 18h does not list `EnableLUA` on a
runner with UAC on. That was the 2026-09-24 field bug, where a runtime list
missing its bad-value column turned UAC ON into an IOC. `top_findings` gained
analyst notes for the service, named-pipe and scheduled-task hit lines.

### A user named O'Brien gets a dashboard, remediation fixes and a Section 11 history; the [CRITICAL] census counts again
The batch files build PowerShell as text, and wherever they pasted a path
between single quotes, an apostrophe in it ended the string early. That
covers `C:\Users\O'Brien`, `Mary O'Brien`, and `O’Brien` typed with a
typographic apostrophe, which PowerShell also reads as a quote. The whole
script was then a parse error that printed and raised nothing. Section 18's
five blocks were fixed in #242. A sweep of both scripts found the rest:
- **The dashboard script** pasted `SUMCODE` and `SUMCOUNT`, which live in
  `%TEMP%` under the user's profile even on an elevated run, plus the three
  remediation paths and the ledger path. For such a user there was no
  dashboard, from either script. The remediation script still appeared,
  because cmd writes its safety header before the dashboard runs, but it held
  only that header: no fixes and no closing lines.
- **Section 11's PowerShell-history block** pasted `%APPDATA%`, so the
  history was never shown.
- **The end-of-run `[CRITICAL]`-line census** pasted the report path, which
  sits under the profile for a standard user. It also never worked for
  anyone. It was a `for /f` backtick command that began with `"%PWSH%"`, the
  shape CLAUDE.md records as running nothing: `cmd /c` strips the outer
  quotes and the command is mangled. So `CRIT_COUNT` kept its 0, and the
  alarm it feeds could never fire. That alarm is the one that notices a
  section printing `[CRITICAL]` but raising something lower. The census now
  reads its count through a file and `set /p`. When it cannot read a count,
  the alarm says it checked nothing, instead of passing silently.
- **The elevated script's console-log capture and its `-updateTTP` /
  `-importTTP` sanitizer** pasted their paths too. On the elevated script
  those paths sit under `C:\SecurityAudit`, so no user name reaches them;
  changing them is hardening, not a fix anyone could have hit. The noAdmin
  script's capture already read its path from the environment.

Every code site now reads its path from the environment (`$env:REPORT`,
`Join-Path $env:APPDATA ...`); cmd's variables are the child's environment.
No quoting is involved, so apostrophes, typographic apostrophes, spaces and
`$` are all safe. The six printed `Command:` lines per script that a reader
pastes (five `IOCDIR`, one `APPDATA`) write `'%IOCDIR:'=''%...'`. cmd doubles
the apostrophe, and a doubled apostrophe is a literal one inside a
single-quoted PowerShell string. A typographic apostrophe is not doubled
there, so for that one case the printed line is still not pasteable.

How it is proven:
- **`tools\lint_quoted_paths.ps1`** works out which variables hold a path
  from the scripts' own `set` lines, followed to a fixpoint, so a path
  variable added later is covered. It fails on any of them pasted into
  PowerShell code in any quoting. Between single quotes an apostrophe ends
  the string; in double quotes a `$` or a backtick is expanded; unquoted, a
  space splits the argument. It covers every line shape the scripts use or
  CLAUDE.md prescribes (`if ... echo`, redirection first, `(echo ...)`),
  `%~dp0` and `for`-variable paths. It also fails on a printed `Command:`
  line that does not double the apostrophe. On `main` it reported the 32
  sites above. Its `-SelfTest` reverts one fixed site of each kind (the
  dashboard, the census, the history block, a printed line, the delayed
  form), and plants each line shape and quoting with a path in it. It checks
  that a state value, a comment and a newly added path variable are each
  handled correctly. It does not revert every one of the 32 sites.
  `lint_report_echo` now renders cmd's `%X:'=''%` on a path holding an
  apostrophe before it parses a printed command.
- **The standard-user CI job's test account is named `dz o'smoke`**, with an
  apostrophe and a space, so that user's report, ledger, remediation scripts,
  `%TEMP%` and `APPDATA` all sit under `C:\Users\dz o'smoke`. Run 1, through
  `field_test.ps1`, must print the dashboard, and the dashboard must fill in
  the stage-1 remediation script: the file must parse and hold the closing
  line only the dashboard writes. The census must run. A PowerShell history
  planted in the
  profile before run 2 must show in Section 11.
  An earlier draft checked only that the remediation file existed and parsed.
  The review showed that passes on the old code, since cmd writes the header
  either way.
- **The full-run job** runs the audit with `TEMP` and `TMP` under
  `C:\dz_ci_o'brien`, and `APPDATA` under `C:\dz ci o'brien`, with a planted
  history. The same three things must hold.
- **The helpers job** takes the census lines from the bat and runs them in
  cmd against a report under an apostrophe-and-space folder holding two
  `[CRITICAL]` lines. They must count 2. The old `for /f` form, run the same
  way on a plain path, must count nothing: measured, not argued. The printed
  18e command, echoed by cmd with an apostrophe in `IOCDIR`, must parse and
  run, and the undoubled form must not parse.

### Section 18: every IOC match that cannot run says so and raises it; 18e reads tasks in any language
Misses first, both mine:
- **PR #241 broke the Section 18 summary.** Rewriting it into gotos left the
  hits branch behind an `IOC_HITS==0` test, which is never true there, so
  with any IOC match the summary printed nothing. No test read the summary.
  It now prints its tally, and says when checks above could not run. The
  plant harness asserts the tally line.
- **The backlog note behind this change was incomplete.** It named 18b and
  18e. The same unraised gap was in 18c, 18d, 18h and 18k, and in the
  "could not list" branches of 18a, 18b, 18c, 18e and 18g. It also said the
  summary counted these lines as gaps. That was false for 18e and 18k: their
  `[INFO] ... skipped` lines match none of the words the summary counts.

What changed:
- **A matcher that cannot run raises a gap.** When its list is missing or
  holds no entries, or Windows will not list processes, pipes, services,
  tasks or command lines, each check prints `[WARNING] <check> IOC match NOT
  performed -- <reason>`. It raises a gap-worded ledger row under its own
  section and technique. It never reads `[OK]`, and a gap does not count as
  an IOC match. The staged blocks write `dz_iochit_18X_gap.txt`, which both
  bats read. `ioc_hash_check.ps1` does the same for a missing list, or one
  with no valid SHA256 row.
- **18e uses `Get-ScheduledTask` instead of schtasks' CSV.** It matched on
  `TaskName` and `Task To Run`. schtasks takes its column names from its
  language files, so on a non-English Windows those columns did not exist,
  nothing was compared, and 18e printed `[OK]`. That is a permanent
  all-clear for anyone not on English Windows. The CSV also cuts the command
  line at about 261 characters, so a match later in a long command was never
  seen. 18e now matches the task's full path and every action's complete
  command line. Its `Command:` line is runnable PowerShell, and
  `Get-ScheduledTask` joined the command probe's read-only allowlist.
- **An 18k hash match is raised CRITICAL.** `ioc_hash_check` prints
  `[CRITICAL] ... QUARANTINE IMMEDIATELY` for a file with a known-bad
  SHA256, and both bats raised it as WARNING. A hash match alone ended the
  run at exit 2 beside a printed `[CRITICAL]` line, and the bat's own
  ledger-divergence alarm fired.
- The noAdmin bat's 18e marker is renamed to match the elevated bat's, so
  Section 18 is the same in both, apart from the noAdmin driver note.

How it is proven:
- The gap branches only run when something is missing, which no healthy
  machine shows. `tests\section18_gaps.ps1` renders each staged block the
  way cmd writes it and runs it. With no list, and with a comments-only
  list, it must print the NOT-performed line and write its gap marker, with
  no `[OK]` line and no hit. It also checks that both bats carry the same
  blocks and that each bat deletes, reads and raises each gap under the right
  technique. Its `-SelfTest` proves twelve named defects each fail for their
  own reason, among them the summary guard restored. The `[SKIPPED]` revert
  is caught both by reading the bat and by running the block.
- lint.yml runs it on Linux, where the Windows listings do not exist, so
  18b, 18c and 18e also prove their "could not be listed" branch.
- The Windows helpers job runs it under 5.1. The shipped lists must give no
  gap. A planted named pipe must be matched. Planted scheduled tasks must be
  matched by name and by an action argument 300 characters in, and a twin
  task holding no list entry must not be. A missing hash list and a
  comment-only one must each print NOT performed and write the gap marker.
- A healthy runner raises no Section 18 gap. The plant harness, the
  full-run job and the standard-user smoke test all assert it. On the
  standard-user path a false gap would not change the run's MAXSEV, so
  nothing else would notice it.
- `assert_printed_findings_raised` gained contracts for the 18b, 18c, 18d,
  18e, 18h and 18k findings and their gap lines. `lint_shared_copies` pins
  `Expand-CmdEscapes`, which the test copies from `lint_remediation`.

**A read-only review of the change, before the first push, found three more
ways Section 18 could read clean having checked nothing:**
- **No ThreatLists folder at all.** The bat printed `[SKIP]`, jumped past
  every match, raised nothing and left the gap count at 0, so the dashboard
  tile read PASS: "no threat indicator matches across all categories". That
  happens when someone copies the bat and `tools\` without `ThreatLists\`.
  It is now `[WARNING] IOC sweep NOT performed`, with an `IOCSWEEP` ledger
  row, and the tile reads "not an all-clear".
- **An apostrophe in the folder path.** The five staged blocks pasted the
  list folder between single quotes. The standard-user script keeps it under
  the profile folder, so for a user named `O'Brien` each block was a
  PowerShell parse error. It printed no verdict and raised nothing, and the
  summary read `[OK]`. The blocks now read the folder from the environment
  (`$env:IOCDIR`). Each block also writes a done marker as its last act, and
  a block that stops before its verdict, for this reason or any other, is a
  raised `NOT performed` line. The same flaw is in 7 more lines per script,
  outside Section 18. It is recorded in the backlog as the next change.
- **18f when `ipconfig /displaydns` printed nothing at all** was still an
  unraised `[SKIPPED]`. It is now a raised gap. An empty cache while the DNS
  Client is running stays `[SKIPPED]`: there the input is absent, not the
  listing.

The review also found that the new test's `-SelfTest` would break on a
Windows (CRLF) checkout. It now runs on Windows too. It also found that "a
gap never counts as a match" was claimed but not asserted. It is asserted
now, with a mutation that adds `IOC_HITS+=1` to a gap read.

CI's first Windows run then failed on the new test itself, before it checked
anything. Its repo root came from `$PSCommandPath` in a `param()` default,
which Windows PowerShell 5.1 leaves empty when a script is run with
`powershell -File`. pwsh 7 fills it in, so every Linux run had passed. The
root is now derived in the script body from `$PSScriptRoot`. CLAUDE.md
records the rule.

### Sections 18a, 18f and 18g: one matcher that cannot read clean on failure, and plants that prove 18a and 18f fire
No test had ever planted a positive 18a match (a running process named on
`ioc_processes.txt`) or 18f match (a C2 domain from `ioc_domains.txt` in the
DNS cache). Reading the two sections showed they could also print
`[OK] No ... IOC matches.` having matched nothing:
- **The exit code checked was the wrong one.** They ran
  `findstr /i /g:<list> <file> | findstr /v /c:"#"`, and in a cmd pipe
  `%errorlevel%` is the LAST stage's. When the first findstr failed (list
  unreadable -- 18f never checked that its list existed -- a line too long,
  out of memory), its error went only to the console. The second findstr got
  no input and exited 1, and the report said `[OK]`.
- **The list's own header picked the match mode.** findstr treats every
  search string as literal or every one as a pattern, depending on the first
  line, which is `# Last verified by doze_sec: <date> <time>`. The time
  separator comes from the culture. Where it is `.`, the header holds a
  pattern character and the whole list silently became patterns.
- **Comment lines were search strings,** although the header said findstr
  ignored them. The bare `#` lines (9 in `ioc_processes.txt`, 6 in
  `ioc_domains.txt`) matched any line containing `#`, which the second
  findstr then removed, so a real hit on such a line vanished.

All three sections now match with `tools\select_lines.ps1 -PatternFile`,
already used by 18g. It skips comments and blank lines and matches as a
literal, case-insensitive substring. Its exit code is 0 for a match, 1 for
none, and 2 for nothing to match with. Exit 2 now prints
`[WARNING] <check> NOT performed -- <list> could not be read or holds no
entries` and raises a gap-worded row under the same section and technique. It
used to print `[OK]` in 18g too. `select_lines` gains a `-SelfTest` that runs
the script as a child process, so the exit codes it checks are the ones
cmd.exe sees. It has 12 cases: comments never searched, a literal `.`, a hit
on a line holding `#` kept, a comment-only or missing list is 2, and others.
The list headers that said "matched via findstr" now say how each list is
really matched. That reaches a machine's runtime copy only when the copy is
replaced. The seed keeps a copy whose verified date is newer than the
release's, and every online sync re-stamps that date, so a synced machine
keeps the old comments until `-resetTTP`. On a machine whose copies are still
dated 2026-06-06, the first run prints five `runtime copy replaced by the
release baseline` lines: the dates tie and the content differs, so the
release wins. The change is in comments only, not entries.

The plant harness gains four cases:
- A copy of ping.exe named `dz_selftest_evil_chisel.exe`, running from
  `C:\dz_selftest_ioc\`, must be matched in 18a.
- Its twin, named after an RMM agent the list deliberately dropped, must not.
- A HOSTS line `127.0.0.1 dz-selftest-evil.ngrok.io` must be matched in 18f.
  Windows preloads HOSTS into the cache `ipconfig /displaydns` lists, so
  nothing is sent to the network. If the DNS client did not load the line,
  the case is declared void, not passed.
- Its twin, `dz-selftest-benign.ngrok.com`, the vendor's own site, must not.

Each match must reach the ledger under its own section and technique
(Section 3 also raises T1071.004). Every expectation is anchored inside its
subsection, because Section 3 copies the whole DNS cache into the report and
a bare name match would pass whether or not 18f fired. Cold cleanup stops the
processes by path, and the HOSTS lines carry the existing marker. The two
twins have ADVISE corpus entries. Contracts were added to
`assert_printed_findings_raised`, and `top_findings` gained analyst notes for
the three findings and the gap lines. lint.yml checks that each section in
both bats branches three ways on the exit code, and that the old two-way
branch fails that check.

**An adversarial review of this change (four lenses, a skeptic per finding)
found 13 defects, all fixed before the first push:**
- The new `select_lines -SelfTest` would have failed on every Windows
  PowerShell 5.1 run. Under the CI step's `Stop` preference, 5.1 turns a
  child's redirected stderr into a terminating error, and that hits exactly
  the exit-2 cases the test exists to prove. Three reviewers found it
  independently. The self-test now sets `Continue` first.
- The Section 18 summary still said "[OK] No threat indicator matches found
  across all IOC categories" when a category above it had printed NOT
  performed, and the dashboard showed a PASS tile with the same words.
  `tools\count_gaps.ps1` now counts the section's NOT-performed, `[SKIPPED]`
  and `[DEFERRED` lines from the byte offset where the sweep began. With
  any, the summary reads "not an all-clear" and the tile reads INFO. An
  unreadable count is -1, never 0.
- 18f read `[OK]` when the DNS Client service was stopped. `ipconfig` prints
  its banner even when it cannot show the cache, so a non-empty file proved
  nothing. 18f now requires a record's dashed underline, which appears in
  every language. With none, a stopped service is a raised NOT-performed
  line, and a running service with an empty cache is a declared `[SKIPPED]`.
- The harness's ledger check ignored a voided 18f plant, so the job would
  have failed when the DNS client did not load HOSTS. It now checks a row
  only when the match was printed. Each benign twin was also graded `[OK]`
  when its matcher never matched anything. A new `TestableIf` precondition
  grades the twin only when its sibling plant matched, and reports SKIP
  otherwise.
- The new CI check accepted five ways of breaking the branch it guards. It
  now reads the block line by line, from the call through the five lines
  after it, with exactly one way into `[OK]`. It runs all six named
  mutations and requires each to fail.
- The printed `Command:` lines (`... | select_lines.ps1 -PatternFile ...`)
  could not be run. They are now PowerShell a reader can paste: the list's
  entries, then the same literal, case-insensitive match over
  `Get-CimInstance Win32_Process` or `Get-DnsClientCache`. The command probe
  runs them; `Get-DnsClientCache` was added to its read-only allowlist.
- The older HOSTS plant got the same trailing-newline guard as the new ones.
- The CHANGELOG had two inaccuracies: the bare `#` line count, and the
  header fix reaching runtime copies.

**CI's first run found one more, and reading it found two beside it.** One
of the three HOSTS cleanups failed with `Stream was not readable`. It healed
in the same run, because each cleanup drops every marker line and the next
two succeeded, but a cleanup that fails on someone's VM leaves a DNS-hijack
line in their HOSTS file. Reading the code showed two more defects:
- The cleanup rewrote HOSTS through `Get-Content` / `Set-Content -Encoding
  UTF8`. On Windows PowerShell 5.1 that writes a BOM and re-encodes every
  line, so the owner's own HOSTS file came back changed.
- `cleanup_selftest.ps1` caught any HOSTS failure and reported it as
  `ABSENT`. The recovery script said a plant was gone when it could not
  remove it.

All three HOSTS cases and the cold cleanup now call one helper,
`Remove-HostsMarkerLines`. It drops only the marker lines and leaves every
other byte as it was: encoding, BOM and line endings. It writes only when it
removed something. A failed read or write is retried up to five times, 400 ms
apart. When it takes more than one attempt it prints how many and the first
error. When it still fails, it throws with the error of the call that failed.
In the cold cleanup a missing HOSTS file is `ABSENT`, and a failure is an
error that sets exit code 1. The cold cleanup carries its own copy, because it
must run standalone. `lint_shared_copies` now scans `tests\` as well as
`tools\` and keeps the two copies identical. Two copies have no majority
text, so when they differ the lint names both.

Not changed, noted: 18b and 18e read their lists in PowerShell, and a missing
list there prints `[SKIPPED]` / `[INFO]` without raising. The summary now
counts those lines as gaps.

### The USB stick: an adversarial review of this PR, every finding fixed before merge
Five lenses, each finding re-checked by a skeptic. All 24 findings held, some
at lower severity; none deleted anything this laptop had not written or
touched another disk. The ones that mattered for trust:
- **A rollback read `[OK]`.** A visited machine could put back an OLDER copy
  this laptop once wrote: the files and that copy's manifest, saved on an
  earlier visit. If the stick came home under a new volume ID, the content
  fallback found the old manifest and printed "exactly what this laptop put
  there". `-Refresh` would then delete the evidence. `-Refresh` now retires
  the manifest of the copy it replaces (`<file>.superseded`; the store lists
  `*.sha256` only), so an old copy never matches again. The self-test plays
  the attack through: v1 made, refreshed to v2, the saved v1 put back. It
  reads UNVERIFIED under a new ID and shows differences under the old one.
- **The root record was chosen by how little it reported.** Among exact
  matches, the fallback preferred the manifest whose stick-root record hid
  the most, so another stick's record could hide a planted `EFI\BOOT` file.
  Matching on the stick's own manifest copy removes the choice: one stick,
  one manifest, its own root record.
- **The stick's own manifest copy was never checked.** -Verify ignored it and
  -Refresh deleted it whatever it held. It is now compared byte for byte with
  the laptop's: rewritten is `[CHANGED]`, missing is `[REMOVED]`, and -Refresh
  refuses either way.
- **A link or a file in place of `doze_sec`, under a new ID,** got "There are
  no manifests" and exit 2, even when the store held manifests. It now
  always reads `[LINK]` or `[CHANGED]` plus the evidence warning, exit 1.
  Remove-StickCopy checks for a link before anything else.
- **`-Manifest` accepted a file on the stick itself.** That is now refused.
  With an empty store, the message says "this laptop cannot vouch for this
  copy: do not run it".

Smaller fixes:
- PowerShell turns an exception thrown by a property getter into `$null`, so
  `FileInfo.Attributes` on a BitLocker-locked or unrecognised volume read 0, an
  ordinary file. The picker therefore offered an unreadable stick for checking.
  `Get-EntryState` now calls `[IO.File]::GetAttributes` and returns
  `unreadable`, and the picker refuses such a drive with that reason.
- `-Refresh` with no exact match now lists the candidates and deletes
  nothing. It used to say "this laptop holds no manifest".
- The picker offers `-Refresh` only for sticks that hold a copy.
- A failed drive listing in a window that is not elevated says so and names
  `-Drive E:`.
- The printed `-Verify` command carries the resolved folder (and
  `-ManifestStore`), so it really works from any folder.
- The content-match note says why the stick was matched by its files: a new
  port, an unreadable volume, or a moved folder.
- The stick is read once per check, and files are hashed by stream. Matching
  against many manifests no longer re-reads the stick for each, and a planted
  huge file cannot exhaust memory.

Docs: the ZIP folder is `doze_sec-` plus the branch name with `/` turned into
`-` (`doze_sec-claude-code-review-3qcjyn`). The no-argument `-Verify` needs an
administrator window; `-Drive E: -Verify` works in a normal one. Three
mutations of the new safeguards each fail the self-test: a retired manifest
still listed, the manifest copy not compared when matching by content, and the
link checked after the missing-manifest case.

### The USB stick script asks which drive
Run `tools\make_usb_stick.ps1` with no drive letter and it lists the drives.
Only the USB sticks it would accept get a number. Every other drive is listed
with the reason it is not offered: the Windows disk, a disk not on the USB bus,
a stick that already holds the tool (`-Refresh` replaces that copy, `-Verify`
checks it). The person types a number, then that drive's letter to confirm.
Nothing is written before that, and a wrong answer, an empty one or `Q` writes
nothing. With `-Verify` it offers the sticks that hold `doze_sec`, including a
write-protected one, since reading back needs no write. In a window that cannot
ask (`powershell -NonInteractive`) it stops at once and names the `-Drive`
form. It never waits. `-Drive E:` still skips the questions. Self-tested with
injected answers (18 cases, 20 with the review fixes above). Three mutations each fail the self-test:
numbering refused drives, skipping the confirmation, and offering a stick with
no copy to verify. On the Windows runner, CI checks that `-ListCandidates`
refuses the system drive. It also checks that the picker run non-interactively
exits 1 within two minutes without copying.

### The USB stick from a download is the stick CI tests; a re-identified stick still verifies
The owner tried to make the stick before the PR adding the script was merged,
so the script was not in their checkout. Making it from GitHub's Download ZIP
instead was then checked by reading the code (two tracers, seven skeptics and
a completeness critic, reading only). The route works, and the check turned up
four things, all fixed here. None of them deleted anything or vouched for a
changed stick:
- **Line endings.** Only `.bat`/`.cmd` were written with CRLF. From a ZIP,
  which carries the repo's LF endings, every `.ps1` and `.txt` reached the stick
  LF-only. A Windows checkout, the only thing CI ever built a stick from, is
  CRLF throughout. findstr's `$` anchor needs a CR, so Section 18i printed a
  stray blank line, and `findstr /g:` had never been run against an LF-only
  list. Every text file (an extension allowlist; a file holding a NUL byte is
  left alone) is now written with CRLF. The conversion is byte-exact through
  Latin-1, safe for UTF-8, and much faster than the old per-byte loop.
- **A stick with a new volume ID.** `-Verify` found the laptop manifest only by
  volume ID. Windows can give a stick with no serial number a new ID in another
  USB port, and the stick then read `[UNVERIFIED] ... make the stick again`. A
  failed volume lookup was swallowed with the same result. `-Verify` and
  `-Refresh` now fall back to the newest laptop manifest the copy matches
  exactly, and say so. "Exactly" counts every file AND the stick's own copy of
  that manifest, byte for byte. That copy is what makes a stick's manifest its
  own: two sticks made from the same checkout hold the same files, but each
  holds a different manifest. No exact match gives `[UNVERIFIED]` (exit 2),
  never a TAMPERED verdict against a manifest that may belong to another
  stick. The message lists every laptop manifest with its difference count
  (or why it was not compared) and points to `-Manifest`. A manifest that
  cannot be read is now listed with its reason; it used to be skipped in
  silence.
- **Which guide, where the results go.** The make run's last lines name the
  guide on the stick (`E:\doze_sec\docs\second-machine.md`); an older checkout
  can hold an older guide that has no warning about the results folder. They
  also say to bring results back outside `E:\doze_sec`, since anything added
  there reads as tampering.
- **The ZIP route is documented**, including the trap that sends a first run
  to the same "does not exist" error: the ZIP holds its own top folder, and
  Extract All's default destination adds another.

CI: the read-only job now builds its stick from a `git archive` with
autocrlf off. It asserts the source really is LF-only, so the step cannot pass
on a source that tests nothing. It plants Mark of the Web on every file, puts
the tree in a nested folder, and runs the script with `-ExecutionPolicy Bypass
-File` as a person does. It asserts that no bare LF and no mark reached the
stick. field_test then runs from that stick with every existing assertion. A
copy in a new place must verify by content, and a copy that was also changed
must read UNVERIFIED (exit 2). The self-test grows to 84 cases on Windows (82
on Linux, where the 3 stream cases skip and the case-collision case runs);
113 on Windows with the drive picker and the review fixes below.
Five mutations each fail it: normalisation limited to batch files again, no
content fallback, a match that ignores differences, the NUL guard removed, and
no root ranking.

Found while reading, not fixed here: no test has ever planted a process name
from `ioc_processes.txt` (Section 18a) or a domain from `ioc_domains.txt` in
the DNS cache (Section 18f). Both detections have never fired in a test.

### Carry the tool on a USB stick; two defects found on the way
README, readMe.txt and docs/second-machine.md now explain how to put doze_sec
on a USB stick with tools built into Windows, and how to run it from there.
`tools\make_usb_stick.ps1` makes the stick. It never formats anything. It
accepts only a USB-bus disk that is not the boot or system disk. It leaves off
`.git` and the plant harness, and names each file it skips. It copies file
contents only, so Mark of the Web does not travel, and writes the batch files
with CRLF line endings. It reads every file back and keeps a SHA-256 manifest
on the laptop. `-Verify` checks a returned stick against that laptop copy,
never the one on the stick. It lists files changed, added or removed, new data
streams and links, and root files that can run or boot and were not there when
the stick was made. It never follows a link: a junction planted in place of
`E:\doze_sec` is reported, and nothing behind it is read. The checker itself
stays off the stick, so the one that vouches for a stick has never travelled.
It also refuses to run from the target. `-Refresh` deletes only files the
laptop manifest lists, and only when the copy is still exactly what the
laptop wrote: saved results or evidence of tampering make it refuse and list
what it found. An adversarial review (five lenses, each finding re-checked by
a skeptic) found 13 real defects before the first push, and all are fixed:
- Stream enumeration threw on FAT32/exFAT under Windows PowerShell 5.1.
- An unreadable stick (BitLocker-locked, Mac-formatted) was called
  "unformatted", with format advice.
- `-Refresh` could delete saved results.
- A junction in place of the tool folder was followed.
- The checker shipped on the stick, and the documented back-home command was
  relative.
- Root files already on the stick were flagged as tampering.
- Results could travel on to the next PC.
- Way B used Documents, which OneDrive may sync.

The stick is not bootable, and the docs say why. The audit checks the running
Windows, so a booted stick would audit itself. Windows' own bootable stick has
no PowerShell. And boot changes can send a BitLocker PC into recovery. For a
check from outside Windows, the docs point to Microsoft Defender Offline. The
read-only CI job now runs field_test from a copy the script made, then
verifies that copy is unchanged. That proves the reduced file set is enough
and the audit writes nothing into its own folder, so a write-protected stick
works.

Defects found along the way, all fixed:
- The VirusTotal self-check abort (exit 7) jumped past the RunOnce cleanup
  after INIT 8 had created the resume entry, so the next logon would have
  relaunched the audit. A lint.yml step now requires the delete before every
  early exit after INIT 8, and it fails on the pre-fix scripts.
- A `-noAdmin` run wrote its console log to `C:\SecurityAudit` while
  promising to write only the user's own folder. The log now goes to the run's
  output folder, and the standard-user CI job asserts it. The path now reaches
  Tee-Object through the environment (`-LiteralPath $env:...`), so no
  apostrophe in a profile name -- straight or typographic -- can break it.
- Found by the same review, and older than this change: the noAdmin RunOnce
  resume entry left out `-noAdmin`, so a resumed standard-user run would have
  stopped FATAL at the admin check. It now carries the switch, and field_test
  accepts the longer command line.

### Copied helpers cannot drift
The tools are self-contained by design, so `Get-RegKeyLastWrite` lives in five
tools and `Get-WhenLine` / `Write-WhenCaveat` in four. `tools/lint_shared_copies.ps1`
fails CI when any copy differs from the others (line endings aside), naming the
file and the first differing line; its self-test drifts a temp copy each way.
It found one drift on its first run -- `pending_reboot_check`'s copy had lost a
comment line -- restored here. No behaviour change.

### A managed machine can no longer make the audit read CLEAN while blind; a second-machine runbook
Every helper and every staged block runs as `powershell -ExecutionPolicy Bypass
-File`. An execution policy set by Group Policy (MachinePolicy or UserPolicy,
e.g. AllSigned) overrides `-ExecutionPolicy Bypass`, and AppLocker or WDAC run
PowerShell in ConstrainedLanguage, where the .NET calls the checks use throw.
A refused helper writes no marker, no marker reads OK, so on such a machine the
sections would have said CLEAN for checks that never ran -- and on Windows 11
24H2 (no wmic) INIT 3 would have read the build as 0 and field_test's `-dev`
would have carried the run on. Found by reading, while writing the runbook for
a machine that may be managed; no field run showed it.

Both bats now run `tools\exec_probe.ps1` once, right after the report header
and before the first helper. If PowerShell refuses the script, or runs it in a
language mode other than FullLanguage, the report opens with
`*** AUDIT NOT PERFORMED -- PowerShell will not run this audit's helper scripts
on this machine ***`, prints `Get-ExecutionPolicy -List` and the language mode
(read through `-Command`, which no execution policy blocks), and the run ends
with exit 1 and `STATUS: Nothing was audited`. A copy missing `tools\` says
so the same way. On an ordinary machine the report gains one
`[OK] PowerShell runs this audit's helper scripts (FullLanguage ...)` line,
which field_test now requires. field_test itself names a ConstrainedLanguage
session before anything in it fails, and names an AUDIT NOT PERFORMED report
in one line instead of a cascade of integrity failures. The read-only CI job
plants both conditions -- a MachinePolicy AllSigned value and the machine
`__PSLockdownPolicy=4` variable -- runs both bats under each, and asserts
exit 1, the banner, the evidence and no section verdict; each plant is
confirmed to have taken first and declares a `[ SKIP ]` if it did not, and a
`cmd` step removes it if the PowerShell step could not.

`docs\second-machine.md` is the runbook for backlog P0 #1: carry the folder
on a USB stick (no git, no GitHub login, nothing installed), paste a
preflight that says GO / NO-GO, read the warnings first (a work PC's security
software may alert IT, who may cut the machine off the network; someone
else's report holds their user names and software -- keep it private; never
the plant harness, never the remediation scripts), run field_test elevated
and not, bring the two output folders back, delete three folders.

### A driver finding carries its triage facts; BitLocker is declared once; per-user services stop churning the baseline
Three things the 2026-10-03 field runs showed, none a missed detection, each
the report being unhelpful or wrong about the machine.

**Driver findings.** The standard-user report printed
`Driver ...\PROCEXP152.SYS [ff9b3fc49bb3cd9a...] -- known BYOVD-abusable
driver ...` and nothing else. The owner then needed three commands and a
second opinion to learn what `driver_audit` already held: the driver had no
service and was not loaded, and the hash -- cut to 16 characters -- could
not be looked up anywhere. The finding line now ends with `:` and carries,
indented beneath it, the full SHA-256, the signer and Authenticode status,
the file's created/modified times, whether a driver service points at it
and is running (`LOADED`, `registered, not running`, or `on disk only`),
the matching Event 7045 install record or how far back the System log
reaches, and the commands to verify each. Severity rules are unchanged. The
helpers job asserts the block under its signed `gdrv.sys` plant (full hash
equal to `Get-FileHash`, `on disk only`).

**BitLocker, standard user.** Section 13 declared BitLocker
`[DEFERRED - ADMIN REQUIRED]` and then, four lines later, ran
`Get-BitLockerVolume` unelevated anyway and printed
`[SKIPPED] BitLocker status unavailable` -- so the coverage block read
`Checks SKIPPED : 1` and TOP FINDINGS added a coverage note for a check
already counted as deferred. The evaluated block now runs only with admin
rights. And the dashboard's BitLocker tile, in both bats, queried BitLocker
a second time -- the sixth tile that re-measured instead of stating the
section's verdict. Section 13 now writes `on` / `off` / `unavailable` (or
`deferred`) and the tile reads it; the full-run job asserts they agree and
the standard-user job asserts one declaration and a deferred tile.

**Baseline churn.** The elevated report's baseline block was ~95 lines, 48
of them one class: per-user service instances, which Windows names
`<template>_<suffix>` per logon session, so a new logon renamed all 24. The
diff now compares an instance under its template, but only when a real
user-service template exists and the instance runs its image -- a
look-alike name, or an instance repointed at another binary, is still
reported. Two values that repeated on every read-only run are excluded from
the OLD snapshot too: the Winlogon logon/logoff counters (excluded at
capture since #232, but an older snapshot still held them) and doze_sec's
own RunOnce resume entry -- by marker, not name: the data must point at one
of our bats. The helpers job re-suffixes the runner's instances in an old
snapshot and plants the resume name with a foreign binary as the twin that
must still be reported.

### Pending-reboot entries carry markers; every finding carries a note
The first field run of `pending_reboot_check` (2026-10-03 19:16) listed the
seven queued operations and read every one as `(source missing)`: the real
entries are prefixed, before the NT `\??\` prefix, by `*1` / `*2` on the
source and `*1!` on a rename destination. `!` is Microsoft's documented
MOVEFILE_REPLACE_EXISTING marker; `*N` is not on Microsoft Learn and is
written by Windows' own updaters (OneDrive, Edge, GamingServices). The strip
anchored on `\??\`, so the marker survived into the printed path and into
the existence probe. `Split-PendingEntry` now strips both markers and the
prefix, the probe receives the clean path, and the markers are shown beside
the operation (`[marker *1]`, `[markers *1, !replace]`); six cases pinned
verbatim, and both CI plants add a `*1`-prefixed entry. The same report's
TOP FINDINGS block still read "No specific analyst note mapped" for five
findings (Script Block Logging, hidden accounts, three ASR rules);
`top_findings` has notes for them, and the full-run job now fails on ANY
unmapped finding so the gap cannot reopen.

### The report is plain text again
The 2026-10-03 field report carried 100 NUL bytes, so `grep` called it a
binary file: `wevtutil qe ... /f:text` prints some message fields with their
NUL terminator attached (`Service Account:  LocalSystem\0` in every Event
7045 record, `Level: Information\0` in the Defender 1116/1117 block) and both
bats append that text as-is. `tools/report_format.ps1`, which already
rewrites the report before `top_findings` and `report_html` run, now strips
every NUL and writes the count to `-NulCountFile`; the summary declares it
(`REPORT HYGIENE: N NUL bytes removed from event-log text`), so the
sanitiser is auditable rather than silent. `tests/field_test.ps1` asserts
the report a person's machine produced holds no NUL byte; the full-run job
asserts the same on the runner's report and that a printed hygiene count is
never 0; the helpers job feeds `report_format` a sample with three NULs and
asserts they are gone, counted, and the surrounding text intact.

### Section 1 names what is pending
Every run on the owner's laptop exits 4 with "Reboot the system then re-run
the audit", and the 2026-10-03 report proved (WinInit Event 12) a boot on
2026-10-02 after which `PendingFileRenameOperations` was still set. The
check tested only that the value existed, printed nothing of what it held
or when it was written, and its `catch{}` turned an unreadable key into
`[OK] No pending reboot detected`. `tools/pending_reboot_check.ps1` replaces
the inline block in both bats: it reads the Windows Update and Component
Based Servicing flags and `PendingFileRenameOperations` (+ `...2`), parses
the REG_MULTI_SZ into `delete:` / `rename: a -> b` operations (Microsoft's
MoveFileEx contract; a missing source is said), prints them indented
beneath ONE `[WARNING] Reboot pending: ...` line that ends with a colon so
`top_findings` carries them, and reads each flag key's RegQueryInfoKey
last-write time against `LastBootUpTime`: written AFTER the boot is fresh (a
Restart will apply it); written BEFORE is stale (it survived a restart --
re-created by a component, or never processed because Fast Startup's "Shut
down" hibernates the kernel and does not run the queue; the report names
`HiberbootEnabled` and says Restart, not Shut down). The bats read the age
from a state file: a stale queue changes the `[EXIT 4]` lines and the
summary STATUS from "reboot and re-run" to "restarting again is unlikely to
clear it; review the queued operations". A flag that cannot be read is a
declared gap (`dz_reboot_gap.txt`, its own ledger row), never an all-clear.
The REBOOT row text and exit code are unchanged. `top_findings` keyed its
Windows Update note on `WindowsUpdate requires a reboot`, which the bat
never printed; fixed, and the PendingFileRenameOperations note now explains
the listing. Self-test 26 cases; the helpers job appends a rename to the
runner's queue and asserts it is listed by path and reads fresh (restored
in finally); the full-run plant appends instead of skipping so the
post-run step can assert the listing; a printed-findings contract for
Section 1 / REBOOT; corpus entry `[pending-reboot-flags]`.

### The baseline diff knows what changes by design
The 2026-10-03 elevated field run's one unpredicted ledger row was
`WARNING|17|BASELINE`, built from ten `[WARNING]` lines that were all
updates and installs: three `OneDrive Startup Task-<SID>` CHANGED where only
the version directory moved (the action is an UNQUOTED path with spaces, so
`Get-BinPath` took `C:\Program` as the binary, found nothing, and the
signature check never ran -- the sibling service with a quoted path read
INFO); `GoogleChromeElevationService` and the Codex MSIX service CHANGED by a
version segment (validly signed, but the rule forgave Microsoft alone); NEW
`ZoomVDIMGMTTaskUser` (a Zoom-signed install); two NEW `\SoftLanding\` tasks
with an empty action (Windows' own COM-handler tasks, no executable to grade);
NEW `tcp/49670` for `jhi_service` bound to `[::1]` only; and
`Winlogon\LastLogOffEndTimePerfCounter`, a counter Windows rewrites at every
logoff, snapshotted as a persistence value. Every raise was right by the
rules and wrong about the machine. `tools/baseline_diff.ps1` now: walks an
unquoted action's space-separated prefixes to the first file that exists (as
CreateProcess does) before sign-checking; grades CHANGED records by the
CURRENT binary's signer, so a validly signed non-Microsoft binary whose
record differs only in a version-shaped path segment is `[INFO] ... validly
signed by <CN> -- version bump` (a changed start mode, directory, argument or
hash is not a bump and stays WARNING naming the signer; unsigned stays
WARNING; RUN values are never downgraded); reads a NEW task/service/driver/
autorun validly signed by a non-Microsoft publisher, clean arguments, no
staging path, as `[INFO] ... a new install, not an update; confirm it is one
you made`; reads a NEW task with no executable action as a COM-handler task,
INFO under `\Microsoft\Windows\` and `\SoftLanding\`, WARNING anywhere else;
records each listener's bind address (`<owner> bind=<address>`), reads a
loopback-only listener as INFO whatever the owner or range, compares PORT
records by owner so a baseline saved before the field existed causes no
CHANGED storm, and raises a listener that moves from loopback to a
network-reachable address; and excludes the two Winlogon logon/logoff perf
counters from the snapshot by exact name, declared once when the snapshot is
saved. WARNING lines now carry the reason in parentheses like INFO lines do,
and `top_findings` has analyst notes for every baseline line (they read "No
specific analyst note mapped" before). Self-test 27 -> 72 cases, the ten
field lines pinned verbatim in both directions; the helpers job opens a
loopback listener and an all-interfaces listener during the diff and asserts
INFO and WARNING respectively, and asserts the snapshot's PORT records carry
a bind and hold no Winlogon counter; four corpus entries.

### The ledger row of a raised gap names the gap
The second half of the 2026-10-03 vocabulary decision. A tool that could
not run raised WARNING through its one severity marker, and the bat's
`:dz_finding` call site has one fixed message per marker, so the ledger row
named the finding the check WOULD have made: `log_gap` that cannot read a
log elevated filed "Event-log records missing with no clear event";
`cross_api` that cannot enumerate the Task Scheduler filed "Cross-API
disagreement or hidden task - rootkit indicator"; `hosts_check` on a missing
HOSTS file filed "Non-standard entries found in HOSTS"; the LSA tool's
UNKNOWN filed "LSASS PPL not enabled". The printed line named the gap since
#226, but the adjudication worksheet, the HTML findings index and the
remediation `led` triggers read the row. Eleven tools now keep two
severities -- what they observed (`dz_<name>.txt`) and what they could not
(`dz_<name>_gap.txt`) -- and both bats raise the gap marker as its own row
with gap wording under the same section and technique (16 markers, 32 call
sites), so verdicts, counts and contracts are unchanged and no `led`
trigger can fire on a gap. A gap-only run no longer prints the all-clear
line (driver, startup folder, module inspection). `lint_unraised_findings`
now requires the gap marker wherever a gap line is printed and its read in
both bats (10 tools on the tree before this change; the eleventh, `baseline_diff`, escaped the rule because its gap line carried no NOT-performed phrase, and now carries one); the
helpers job plants three gaps (missing HOSTS file, empty CBS directory, a
log that does not exist) and asserts the gap marker, no finding marker and
no all-clear line; the full-run job asserts every finding-worded row has a
non-gap finding line in its section.

### A shipped threat list's content change carries a new verified date
`ThreatLists/ttp_manifest.txt` changed content in three commits while its
`# Last verified by doze_sec:` header stayed at 2026-06-06; the 12:51 field
run then replaced the runtime copy "same date, content differs", right only
because the seed's tie rule favours the shipped file. The header now also
carries `sha256:<16 hex>` of the normalised entries (the sync tool's own
`Get-NormalizedHash` rule, written on every `-updateTTP` refresh), and
`tools/lint_threat_list_dates.ps1` fails when the entries drift from it,
when the header is missing, or when the date does not parse or lies in the
future. `-Stamp` re-verifies deliberately; `-Stamp -KeepDate` adopted the
digest on the nine IOC lists whose entries have not changed since
2026-06-06, and `ttp_manifest.txt` moved to 2026-10-03. The self-test
cross-checks the digest rule against the sync tool by AST so two copies
cannot drift. Expect ten `runtime copy replaced by the release baseline`
provenance lines on the first run after this release (the header line
differs, dates tie, the release wins), once.

### LSA Protection: the boot event is the fact, the registry value is the intent
Section 12 and `module_inspect` both decided whether LSASS runs protected
from `HKLM\...\Lsa\RunAsPPL` alone. Microsoft Learn ("Configure added LSA
protection"): a clean-installed, enterprise-joined, HVCI-capable Windows 11
22H2+ client runs LSASS protected BY DEFAULT with no `RunAsPPL` value, so a
registry-only rule reported exactly that machine as unprotected -- a
T1003.001 row, a WARN tile, and elevated a T1055 row for the lsass denial
the protection itself causes. The signal Microsoft names for verification
is WinInit Event 12 in the System log ("LSASS.exe was started as a protected
process with level: 4"), readable from a standard-user token.
`tools/lsa_protection_check.ps1` now decides on that event first and the
registry second, with the psv2 asymmetry: the event since this boot is
proof; the event absent is evidence only when the System log still reaches
back to the boot; the registry value is intent, which reads PENDING when it
is set but LSASS did not start protected (reboot pending, or value 2 on a
build before Windows 11 22H2); unknown is a raised gap, never an all-clear.
Measured ONCE in Section 4 (`-Mode Measure`, before module_inspect), printed
and raised in Section 12 (`-Mode Report`), read by module_inspect and by the
tile from the same state file. Fifteen self-test cases; the helpers job runs
it live and runs a declared experiment (can a synthetic WinInit Event 12 be
written on the runner?); a printed-finding contract pins the Section 12
WARNING to its row; corpus entry `[lsa-protection-on-without-registry-value]`.

### The LSASS PPL tile states Section 12's verdict; the intermittent standard-user alarm explained
The quoting added to `noadmin_smoke` in #225 named the alarm that had fired
on some standard-user CI runs and not others: `Dashboard verdict is CRIT but
ledger max severity is WARNING`, from the tile `[!! CRITICAL !!] LSASS PPL
DISABLED (RunAsPPL=0)`. Section 12 grades an explicit `RunAsPPL=0` and an
absent value both as WARNING; the tile re-read the registry and graded the
explicit 0 as CRIT, so the alarm fired on runner images that carry an
explicit 0 and stayed quiet where the value is absent. Section 12 now writes
its reading (`1`, `2`, `absent`, the sanitised value, or `unreadable`) to a
state file and the tile prints that, naming Section 12, with NOT graded when
no verdict was recorded. The standard-user job asserts the tile never reads
CRIT and names its source.

### lsass denied on a standard-user token is a deferral, not a finding
`module_inspect` printed `[WARNING] lsass module enumeration denied while LSA
Protection is OFF -- lsass injection NOT checked` and raised a T1055 row
whenever lsass refused enumeration and `RunAsPPL` was not set -- on a
standard-user token too, which can never open lsass whatever the machine's
state. The token, not the machine: the class CLAUDE.md names, found by
reading which raised-gap lines the standard-user path could print after the
`[SKIPPED]` retagging, not by a field run (the owner's laptop has
`RunAsPPL=1` and takes the `[OK]` branch). The verdict is now a pure
`Get-LsassDenialVerdict` graded by token: unelevated with protection off it
prints `[DEFERRED - ADMIN REQUIRED]` and counts through
`dz_module_deferred.txt` into `DEFERRED_COUNT` (both bats); elevated it stays
the raised WARNING; `RunAsPPL=2` (enabled without the UEFI lock, Windows 11
22H2+) now counts as ON instead of being graded as OFF. Self-test cases both
ways; the standard-user CI job asserts the WARNING never prints there and one
of the two declared branches does; corpus entry
`[lsass-unreadable-from-standard-user]`. **And the denial itself was never
detected on the standard-user runner**: the `.Modules` getter did not throw
for other users' processes there, it returned an empty list, so the
`catch`-only rule counted zero refusals and Section 4 read "179 unique
module(s) across 148 process(es)" from the user's own processes alone, with
no refused count printed. A refusal is now decided on evidence (a live
process with no readable module), the refused count names the token as a
cause, and the lsass branch runs where it never had.

### Defender exclusion tiles read Section 9's state line
The three Section 9 exclusion blocks (paths, processes, extensions) lived
inline in both bats, and the dashboard tile then called `Get-MpPreference`
AGAIN -- a second measurement of the kind the Defender real-time, tamper and
signature tiles had just been cured of. The tile also printed nothing at all
when `Get-MpPreference` returned nothing (an all-clear by omission), and
extension exclusions never reached the dashboard. The blocks are now
`tools/defender_exclusions_check.ps1` (pure judgement + self-test, marker
`dz_defexcl.txt`, the same "Defender exclusions configured" ledger row), it
writes `graded|paths|processes|extensions`, and three tiles state what the
section found, naming Section 9, with NOT graded when it could not query.
Each excluded item prints on its own `path:` / `process:` / `extension:` line
so an item cannot start a report line with a severity tag. The helpers job
runs the tool before and after planting a real path exclusion and asserts the
WARNING, the item by name, the marker and the state count; the full-run job
asserts Section 9 and the dashboard agree on every kind; a printed-finding
contract pins the exclusion WARNING to its ledger row.

### A raised gap prints [WARNING]; [SKIPPED] is never raised
Vocabulary decision (owner, 2026-10-03). 27 sites in ten tools printed
`[SKIPPED] ... NOT performed` and raised WARNING in the next line -- a blind
spot raised on purpose, because a view an administrator cannot open is itself
an anomaly. The section verdict then read "ISSUES FOUND -- review [WARNING]
entries above" with no WARNING line to find, and the summary's warning-line
count ran below the findings counted. Those lines now print `[WARNING]` with
the same NOT-performed wording; `[SKIPPED]` is reserved for gaps that raise
nothing and `[DEFERRED - ADMIN REQUIRED]` for a standard-user token's gaps.
The coverage block counts raised gaps by their phrase as "Gaps RAISED" so
they stay visible as coverage gaps; `lint_unraised_findings` fails on a
raised `[SKIPPED]` (27 defects against the code that shipped, three of them missed by the hand survey that preceded the rule). The bats'
"helper not found" gap for the Defender core check follows the same rule.
Deferred to the backlog: the ledger row of a raised gap still names the
finding the check would have made rather than the gap it hit.

### Defender dashboard: no tile re-measures
The tamper-protection and signature-age tiles still called
`Get-MpComputerStatus` themselves after the real-time tile moved onto Section
9's state line, and the signature tile graded on its own thresholds (CRIT at
7 days, WARN at 3) while the section raises one WARNING past 7 days -- two
rules for one fact. The state line now carries five fields
(`mode|realtime|graded|tamper|sigage`), every tile states what Section 9
graded, a section that could not query Defender reads NOT graded on every
Defender tile, and the signature and tamper remediation fixes trigger off
that state instead of the tile text. The experiment step prints the prior
`ForceDefenderPassiveMode` value, not only its presence: the first run showed
the runner image already carried one.

### Defender core check extracted; passive mode self-tested; the dashboard stops re-measuring it
The Section 9 Defender core block (real-time, antivirus, tamper protection,
signature age, the `Get-MpPreference` disable flags, and the passive-mode
judgement that suppresses the real-time and antivirus CRITICALs when
`AMRunningMode` says another product is in control) was staged inline in both
bats. It is now `tools/defender_core_check.ps1`: the same lines, the marker
idiom, a pure `Get-DefenderCoreReport` and a 16-case `-SelfTest` covering
Passive Mode, EDR Block Mode and SxS Passive Mode (INFO, nothing raised for
the flags they explain), an EMPTY mode (not passive: CRITICAL, fail closed),
an explicit `DisableRealtimeMonitoring` under passive mode (still CRITICAL),
tamper protection and signature age under passive mode (still WARNING), and
both query failures (`[SKIPPED]`, nothing invented). `[defender-passive-mode]`
was the last corpus entry with no test; it now has one. The
`ForceDefenderPassiveMode` experiment the owner asked for runs as a declared
CI step: Microsoft documents that passive mode requires Defender for Endpoint
onboarding, so the expected outcome on a runner is no flip, printed as a
`[ SKIP ]` with the reason; a flip would be asserted and promote the entry.
Two dashboard defects found on the way are fixed: the real-time tile called
`Get-MpComputerStatus` a second time with no passive handling, so a
passive-mode machine read `[ CRIT ] Real-time protection DISABLED` on the
dashboard while Section 9 printed `[INFO]`; and the remediation script keyed
off that tile text, so it would have re-enabled Defender real-time protection
on a machine where another antivirus owns protection. The tile now states the
verdict Section 9 reached through a state file (`mode|realtime|graded`, the
`PROCPATH_STATE` idiom; a missing verdict reads NOT graded), and the fix
triggers off that state. `tests/assert_printed_findings_raised.ps1` gains the
Section 9 real-time contract, which the runner (real-time off since the image
was built) exercises on every full run.

### Field-only corpus proofs: seven benign twins get a test
`tests/benign_corpus.txt` had eight entries whose only proof was a `field:`
reason -- a promise that the tool handles the benign state, exercised by
nothing. Seven now have a real proof. Planted on the runner, each with its
malign twin where the rule has one: the Windows default screensaver state
(`ScreenSaverIsSecure=0` with a real System32 screensaver, INFO); a validly
signed per-user updater under `%AppData%` beside the same file with bytes
appended (INFO / CRITICAL); the ADFS and Azure AD Connect registry footprints
in the full-run job (INFO, graded by `benign_corpus_check -Mode Report` on the
real report, which the full run never ran before); an unsigned DLL loaded
from an ordinary path into an ordinary process beside the existing staging
plant (counted, never raised). Isolated into pure functions with self-tests
where timing or a token made a plant impossible: the process-race verdict in
`cross_api_check` (`Get-ProcessRaceVerdict` / `Get-ProcessRaceReport`, four
cases) and the VirusTotal credibility tiers in `vt_ip_check`
(`Get-VtCredibility`, nine cases, `-SelfTest` runs without a token or the
network -- the tool had never run in CI at all). The eighth,
`[defender-passive-mode]`, stays field-only: its only input is
`AMRunningMode`, which needs a second registered antivirus; the backlog
records the `ForceDefenderPassiveMode` experiment that might change that.

### Baseline run 2026-09-26 14:22: the resume entry pointed at a file that does not exist
The first non-read-only field run (`-baseline -dnsprobe`) scored four of six
predictions and found three defects in one mechanism, the RunOnce resume
entry. (1) Section 5 printed the value the audit had just written:
`*WIN11_SecurityAudit_resume = "C:\...\doze_sec\-noVtSelf" -resume`. The
bat expanded `%~f0` AFTER its switch-parsing loop, and cmd's `shift` moves
`%0` along with the other arguments, so `%0` was the last switch typed and
`%~f0` resolved it against the current directory. No interrupted run given a
switch could ever have resumed; `SCRIPT_DIR=%~dp0`, set after the same loop,
was the current directory, so `tools\` was found only when the bat was run
from its own checkout -- which is the only way anyone, including CI, has
ever run it. Both bats now capture `SCRIPT_PATH` / `SCRIPT_DIR` /
`SCRIPT_FILE` before the loop; `tools/lint_arg0.ps1` fails on any `%~...0`
after the first `shift` (46 sites in the code that shipped). (2) The exit
handler deleted the entry only on exit 0/2/8 (noAdmin 0/2/6/8), so a run
that COMPLETED with a reboot pending (exit 4 -- every run on the owner's
laptop) left it behind; harmless only because of (1), and dangerous the
moment (1) was fixed alone. It is now deleted on every exit that reaches the
handler; the entry outlives only a run that never got there, which is what
it is for. The console summary no longer says "No system changes were made"
without naming the temporary entry it created and removed. (3) The proof
`RunOnce resume key: absent after the run` in `tests\field_test.ps1`, and
the CI job's "independent" check, looked for `*doze_sec_resume` -- a value
named after the bat FILE; the audit names it after `SCRIPT_NAME`. The proof
had passed on every machine and every runner without ever looking at the
real value. `field_test` now reads the name from the bat, refuses to run
without it, and cross-checks both the name and the path against the INIT 8
`Command:` line the report prints, so a wrong name or a `<cwd>\<switch>` path
is a FAIL on every machine. The full-run CI job now plants
`PendingFileRenameOperations` so the runner takes the exit-4 path the owner's
laptop takes, and asserts the entry named the bat during the run and is gone
after it. Also from the run: the DNS probe resolved all nine names to public
addresses, the baseline saved 1258 records, and the update check reported
`404 even with token` (a PAT without Contents:read on this repository).

### Standard-user confirmation run 2026-09-25 08:46: the field test itself had never run as a standard user
Six of seven predictions held: exit code 6 (reboot pending), six ledger rows
with six printed finding lines, Sections 16 and 17 PARTIAL with the Security
log and TaskCache declared deferred, Section 5 graded and naming the one IFEO
subkey the token cannot read (`DefenderAgentScan.exe`), the zthelper and
audit-visibility lines unchanged. The miss was the field test's own verdict:
`FAIL: 1 read-only / integrity / corpus check(s) failed` -- it demanded the
read-only skip line `no restore point created`, but a standard user cannot
create a restore point, so `doze_sec_noAdmin.bat` defers that step (needs
admin) before read-only mode has anything to skip. Every standard-user field
run had ended in that FAIL; CI had only ever run `tests\field_test.ps1`
elevated. A second bug in the same branch: an explicit `-BatPath
doze_sec_noAdmin.bat` while unelevated dropped `-noAdmin`, so the bat would
abort FATAL. Both fixed: the expected declaration is token-aware ("restore
point deferred (needs admin) -- the token cannot create one"), and the
standard-user CI job now runs `field_test.ps1` AS the standard user for its
unplanted run -- exit 0, no `[FAIL]`, the proof lines executed -- and holds
the report it produced to the deferral contract.

### Standard-user confirmation run 2026-09-24 21:03: what the token cannot see is a deferral, not a finding
The confirmation run after #218/#219 scored four of eight predictions, one
partial, three wrong. Three defects, all of one class -- a check the TOKEN
could not perform was raised as a finding or lost outright:

- **Section 16 raised "Event-log records missing with no clear event" for the
  Security log a standard user cannot list**, and Section 17 raised
  "Cross-API disagreement or hidden task - rootkit indicator" for the
  TaskCache a standard user cannot read. Both tools printed `[SKIPPED] ...
  (needs admin)` and then wrote a WARNING marker: two ledger rows, two
  ISSUES FOUND verdicts, and nothing printed to review -- eight rows counted
  against six `[WARNING]` lines. On a standard-user token a needs-admin gap
  is the token, not the machine: both are now `[DEFERRED - ADMIN REQUIRED]`,
  added to `DEFERRED_COUNT` through a second marker (`dz_<name>_deferred.txt`
  holds the count), never a ledger row. Elevated, a view an administrator
  cannot open is still a raised gap. Pure `Get-UnlistableLogVerdict` and
  `Get-TaskViewVerdict` with self-test cases both ways.
- **One unreadable IFEO subkey lost the whole Debugger-hijack check.**
  `persistence_eval` enumerated with `-EA Stop`, so the first subkey the
  token could not open terminated the enumeration and Section 5 printed
  `[SKIPPED] IFEO enumeration failed` on both standard-user runs -- a
  `sethc.exe` hijack in a readable subkey would have gone unaudited. The
  readable subkeys are now graded and the unreadable ones named
  (`Get-IfeoReadReport`): `[INFO]`, not graded, not cleared, as a standard
  user; a WARNING that names them when an administrator cannot read them.
- **The smoke test's exit-code rule omitted reboot precedence.** The bat sets
  4 for a pending reboot, a WARNING raise only lifts a code still below 2,
  and non-admin turns 4 into 6; the laptop had a reboot pending and read 6
  with MAXSEV WARNING, correctly. The rule now mirrors the whole bat.
- **Gates.** `tests/noadmin_smoke.ps1` asserts the inverse of "printed but
  not raised": every ledger row has a printed `[CRITICAL]`/`[WARNING]` line
  in its section (the assertion that caught the two rows), plants an IFEO
  subkey with a deny-Users ACL and requires the check to run and name it,
  and requires the two DEFERRED lines and the absence of the two rows.
  `tools/verdict_audit.ps1` gains the weak inverse rule for real runs -- a
  ledger record whose section printed neither a finding line nor a
  `[SKIPPED]` line is an AUDITGAP -- and a `-SelfTest` (it had none). Three
  corpus entries; a structural survey found 25 skip-then-raise sites in ten
  tools, which stay as the documented elevated-token design.

### Standard-user field run 2026-09-24: a Microsoft service called a rootkit, and UAC ON called an IOC
The first field run of `doze_sec_noAdmin.bat` scored three of eight predictions
and exited 8. Four defects, all specific to the path a person who is not an
administrator takes:

- **`cross_api_check` reported `zthelper` as a hidden service, CRITICAL.**
  ZTHelper is Windows 11's Zero Trust DNS helper (KB5058411); its service DACL
  denies enumeration to standard users, so it is in the registry and absent
  from `Get-Service` and `Win32_Service` for that token. The check now asks
  the SCM for each such service BY NAME: error 5 is the DACL and is reported
  as not enumerable from this token (counted, named, never a finding, never
  cleared; a WARNING when an administrator is refused); error 1060, the SCM
  has never heard of it, stays CRITICAL. Pure verdicts, a 20-case self-test,
  and the standard-user smoke job now plants a DACL-restricted service.
  **That job failed on the first push, on exactly the field defect, and
  again on the second.** The probe asked .NET's `ServiceController` for the
  service by name. Push one read the Win32 code one exception layer down
  (PowerShell wraps a property getter's exception, so the code is three
  links deep), found nothing, and kept a default of 1060. Push two walked
  the chain and still got 1060: `ServiceController` resolves the name
  through `GetServiceDisplayName` and throws a hard-coded
  `ERROR_SERVICE_DOES_NOT_EXIST` when that fails for any reason
  (dotnet/runtime, `ServiceController.GenerateNames`), so it cannot tell a
  service the token may not query from one that does not exist. The probe
  is now `sc.exe query <name>`, whose exit code is the SCM's own answer to
  `OpenService(SERVICE_QUERY_STATUS)`: 5, 1060 or 0. No default grade
  remains: no readable code is an `unprobed` WARNING, never CRITICAL, never
  cleared, and the hidden-service line now states the by-name error it was
  established from. The elevated helpers job plants a service whose DACL
  denies Administrators `SERVICE_QUERY_STATUS` so the probe meets a real SCM
  answer on 5.1 under both tokens.
  **And the defect had been in CI on every main run.** The standard-user
  smoke job's run 1 (nothing planted) read `LEDGER MAXSEV (CRITICAL)` and
  `exit code 8 with an organic CRITICAL` on a clean runner, on main, before
  this PR: the runner carries a DACL-restricted Windows service of its own,
  and the test's CRITICAL branch accepted the false positive as organic.
  With the probe fixed the same runner reads WARNING, and the never-run
  branch turned out to expect 6 where the bat deliberately keeps 2. The test
  now pins "no plant means no CRITICAL" and mirrors the bat's rule
  (CRITICAL 8, WARNING 2, nothing raised 6).
- **A stale per-user copy of `ioc_registry.txt` flagged `EnableLUA = 1` and
  `RunAsPPL = 1`**, the secure values. The runtime ThreatLists were seeded by
  copy-if-missing and never reconciled, and the per-user copy predated the
  `|BadValue` column. `tools/threat_list_seed.ps1` replaces a runtime list
  older than or forked from the release, keeps one `-updateTTP` refreshed
  after the release, and prints what it did into the report.
- **Section 16 skipped `log_gap_check` and `audit_policy_check` silently on
  the standard-user path, and the coverage block certified
  `Audit visibility : OK`** for a check that never ran. The gap check now runs
  unelevated (the Security log declared unreadable), the audit-policy check
  is declared DEFERRED, and `report_safety` says `NOT VERIFIED` unless it has
  seen evidence of auditing ON.
- **The Section 18 tally line** `[WARNING] N IOC category matches found` is
  a tally, retagged `[INFO]`; its allowlist exemption is gone.

Also wrong in the predictions: Section 9 (ASR) is deferred wholesale without
elevation, so the ASR row does not survive a standard-user run.

### Added: a system-process name running outside its directory is a finding (T1036)
`tools/masquerade_check.ps1`, Section 4. Naming an implant svchost.exe,
lsass.exe or explorer.exe and running it from AppData, ProgramData, Temp or a
vendor folder is the most common evasion on a client machine; Task Manager
shows a familiar name and most readers stop there. The check grades the SAME
process snapshot Section 4 already takes (one measurement), against the
canonical directory of each Windows name on THIS machine's Windows directory:
System32 for most, SysWOW64 too for the names that have a 32-bit twin, the
Windows root for explorer, System32\wbem for WmiPrvSE, the versioned Defender
platform directory for MsMpEng. Case-insensitive (the owner's machine spells
it `C:\WINDOWS\system32\` and `Explorer.EXE`), anchored on directory AND name
(`System32x\` and `System32\drivers\` are not System32). A name with no
readable path is stated as NOT GRADED, never cleared and never a finding.
WARNING, not CRITICAL: the path says the file is not the Windows binary, not
what it is. A harness plant runs a copy of ping.exe named svchost.exe from
Users\Public and requires the WARNING and its ledger row; five benign twins
are catalogued and pinned in the self-test.

The Section 4 LOLBin and RMM inventories now carry the ids the manifest
already assigned them (T1218.005, T1218.010, T1219). They list matching
processes without a severity, as before; the id marks where the technique is
observed, so `attack_matrix` stops reporting them as documented-but-not-
detected. Technique count 84 -> 88.

### Retrospective 2026-09
`docs/design/retrospective-2026-09-seams-and-field-runs.md`: twenty-eight
PRs, ten or more field runs on one machine, three mechanisms that had never
worked, the first clean confirmation run, and why the next step is a second
machine rather than more code.

### The last four tools get a seam, and each had a judgement a real machine would trip
`dns_probe`, `audit_policy_check`, `persistence_eval` and `baseline_diff` were the
remaining severity-emitting tools with no pure verdict function and no
`-SelfTest`. Extracting the grading found, in each, a rule that the ordinary
state of a real machine would have tripped:

- **`dns_probe`: all-fail is not nine blackholes.** A laptop with no network,
  a VPN not yet up or a resolver that is down fails every probe domain, and the
  rule printed nine `[WARNING]` blackhole lines, wrote the marker and put a
  DNS/HOSTS blackhole finding in the ledger. Nothing resolving is now
  `[SKIPPED]` with marker value `unverified`; the bats read the marker VALUE
  with `set /p` and the dashboard tile reads NOT VERIFIED, never PASS. Some
  resolving and some not, or an answer of `0.0.0.0`/loopback/private, is the
  hijack shape and stays WARNING. `0/8`, broadcast and multicast answers are now
  non-public too. The runner's real answers are pinned verbatim, including
  `wdcp.microsoft.com -> 172.178.160.22`, a 172.x address outside 172.16/12.
- **`persistence_eval`: Process Explorer's "Replace Task Manager" is an IFEO
  Debugger on `taskmgr.exe`** (Sysinternals documents it). It is `[INFO]` only
  when the debugger file is named procexp and is validly Microsoft-signed; an
  unsigned or third-party-signed file with that name, or signed procexp on any
  other target, is still the hijack. The owner's fifteen real autoruns are
  pinned verbatim as must-not-raise.
- **`baseline_diff`: a change detector must know what changes by design.**
  CHANGED was WARNING unconditionally, so the first run after a Patch Tuesday
  would have raised a finding per replaced Microsoft driver; a NEW listener
  was WARNING unconditionally, so every reboot's RPC dynamic-port reshuffle
  raised findings. A CHANGED record whose current binary is validly
  Microsoft-signed, not in a staging path, with clean arguments is `[INFO]`;
  a NEW dynamic-range (49152+) listener owned by a system process is `[INFO]`.
  Replaced unsigned binaries, anything in Temp/Downloads/Users\Public even
  when signed, new admins, new root CAs, RUN changes and suspicious arguments
  stay WARNING; the CI LOLBin case keeps passing.
- **`audit_policy_check`**: the positional GUID parse and the
  Success / No Auditing / localized classification are now pure and pinned
  against a real English `auditpol /r` answer and a German header; `Erfolg`
  is stated as unread, never reported as OFF.

Every new judgement has a mutation that fails its own self-test; the
`benign-twin-grade` lint job and the four Windows smoke steps run them, and
the persistence_eval step now plants an IFEO Debugger on the real registry and
requires the WARNING and the marker.

### Field run 2026-09-20: a CRITICAL on a clean machine, and an exit code that was always 0
The first field run after #213 scored four of five predictions correct (the
fifth matched by cancellation), and then declared `RESULT: CRITICAL findings.
Treat as incident response.` on a clean machine. Reading the report and the
console log found six defects no gate could see:

- **`\Public\` matched any directory named public.** `module_inspect` reported
  Adobe Creative Cloud's Node native addon under
  `node_modules\@growthsdk\growthsdk\public\binaries\` in Program Files as
  "loaded from a staging path": CRITICAL, exit code 8. Nine tools carried the
  same regex; all now anchor to `\Users\Public\`, the form the Section 18
  7045 rule already used. The Adobe path is pinned verbatim as a must-not-raise
  case in `module_inspect -SelfTest`, with `Users\Public`, Temp and Downloads
  as must-raise cases, and catalogued as `[node-native-addon-public-dir]`.
- **The exit code was 0 on the path a person runs.** Without `-noConsoleLog`
  the bat re-runs itself under Tee-Object and hands its exit code back through
  a file written as `echo %EXIT_CODE%>"file"`. cmd reads a digit before `>` as
  a redirection HANDLE, so `echo 8>file` printed `ECHO is off.` (the last line
  of every console log) and wrote nothing; the parent kept its default and
  exited 0. Every exit code is one digit, so the #96 fix never worked, and the
  harness passes `-noConsoleLog`, so CI only ever tested the other path. The
  redirection now comes first. `lint_report_echo` fails on the pattern, and
  the full-run job compares the process exit code with the report's own
  `EXIT CODE:` line.
- **Section 16 printed a false all-clear on Event 7045** on every machine: its
  findstr tokens were XML element names (`ServiceName`, `ImagePath`) and
  `wevtutil /f:text` prints `Service Name:`, `Service File Name:`. Nothing could
  match. The same report's Section 18 listed 26 such events. CI now lifts the
  findstr line from the bat and runs it against a record planted on the runner,
  and proves the old tokens print nothing.
- **Two report paragraphs lost their first two lines to the console**: only the
  last line of each carried `>> "%REPORT%"`. A new `lint_report_echo` rule
  fails on report prose left unredirected inside a redirected paragraph.
- **Six of our own `rem dz_probe` service records were reported as suspicious
  installs on every audit for three weeks.** The exclusion knew `dz_selftest`
  and `dzsmoke`, not the marker the EDR probe used before #200. The corpus
  entry said the residue was handled; it was not. The full-run job now plants a
  `dz_probe` record and asserts Section 18 counts it and does not list it.
- **`[REBOOT PENDING]` was a counted WARNING printed with no severity tag**,
  which is why the tag count matched the finding count only by cancellation.
  It now prints `[WARNING] Reboot pending: ...`.
- 17 lines of `WARNING: Chain status: CERT_TRUST_IS_NOT_TIME_VALID` from
  `Test-Certificate`'s warning stream, for services that passed, no longer
  land in Section 7.

Adjudicated as correct and left alone: the unsigned WiFiman service binary,
PROCEXP152.SYS, BitLocker, Script Block Logging, Sticky Keys, the ASR rules and
the CodexSandbox hidden accounts.

### A severity tag marks a finding, and eight lines were marking a gloss
#212 fixed one such line and claimed a survey had found "this one instance and
no other". **That claim was wrong.** The survey keyed on advice-shaped
*wording*, so it saw only glosses phrased as advice, and missed ones phrased as
a consequence (*"Anyone who can reach this PC remotely could watch what you
do"*), a remedy (*"Add a TECHNIQUE|TACTIC|NAME line"*) or a mechanism
(*"Deleting the SD value hides a task... Used by HAFNIUM"*).

Eight instances in five tools, all retagged `[INFO]`. No severity changed: in
every case the finding above still drives `$sev`, the marker and the ledger row.

`lint_unraised_findings.ps1` now enforces the rule **structurally**: within one
emitted block, at most one line may carry a severity tag. Getting there took
three formulations, and the first two are the point.

1. **Adjacency.** Reported `[OK]` and **could not fail** — fixing each instance
   left an explanatory comment between the finding and its gloss, so mutating a
   tag back was invisible to it. A lint a comment defeats is not a lint.
2. **Adjacency skipping comments and blanks.** Caught 3 of 8.
3. **A per-region count.** Catches all 8 — and only this one found the two
   `cross_api_check.ps1` instances no sweep had reported.

### Three checks that judged without a test that could say they were wrong
A sweep asked of every rule: *could its test fail if the rule were WRONG, as
opposed to merely broken?* The gap tracked the absence of a pure verdict
function almost exactly — every tool that had one carried benign
must-not-raise cases, and every tool that did not carried none.

- **`stalkerware_check.ps1`** had **no `-SelfTest` at all**, in the one check
  written for someone who may be in danger. Now pure, 28 cases. It immediately
  found a real bug: PowerShell converts an empty string to `0`, so
  `'' -as [int]` is `0` and an **empty `REG_SZ` under `SpecialAccounts\UserList`
  was reported as an account hidden from the sign-in screen** — a false
  accusation on that path. The rule now requires a genuinely numeric value.
- **`boot_chain_check.ps1`** — a legacy BIOS, a VM without UEFI variables and
  VBS/HVCI switched off are the *ordinary* state of consumer hardware, and
  nothing executed against any of them. Now pinned, including the #210 rule
  that a null DeviceGuard reading says "could not be determined" and never
  "not running".
- **`log_gap_check.ps1`** — correcting my own survey, which reported zero
  benign cases: `Get-RecordGap` already had four. The untested rules were the
  retention floor and the heuristic that tells a reader *"records were lost"*.
  Both now pure, twelve new cases, behaviour unchanged.

### Plain HTTP is not a signal, and the BITS rule stops saying it is
For the **third** time, and through a **third** rule, the 2026-09-19 field run
raised Microsoft Edge's own updater:

```
[WARNING] BITS job 'Edge Component Updater' (owner ...) created 2026-08-09,
41 days old, and it fetches over plain HTTP, not HTTPS
(http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/...)
```

Microsoft documents `*.dl.delivery.mp.microsoft.com` as **HTTP on port 80** for
Edge content delivery, and states: *"Be sure not to use HTTPS for those
endpoints that specify HTTP, and vice versa. The connection will fail."* Plain
HTTP there is **required** — the payloads are signed and hash-verified
separately — so the rule flagged the most common BITS job class on Windows. The
branch is deleted.

It was added in the same change that fixed the age arm for the same job. **A
false positive removed from one rule came back through a new one**, which is
the pattern this file already records for the notify-command arm.

**The test is the real story.** The CI case used `http://localhost` and asserted
the rule *fired*. It passed, every run. It never asked whether firing was
*correct* — the mechanism was tested and the judgement was not. That case now
asserts the opposite, and a second case pins the real `msedge.b.tlu.dl...`
remote verbatim as something that must never raise.

What still raises: a bare **public** IP address, a write directly into an
autostart folder, an unreadable file list, or a notify command line. A bare
**private** address (10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x) is now
context with its cause named — an on-premises WSUS server, an SCCM distribution
point and a Microsoft Connected Cache node are all routinely reached by bare LAN
address, and BITS is the transport all three use. `172.15.x` and `172.32.x` sit
outside that block and still raise; the self-test pins both boundaries.

`persistence_extra.ps1` had **no `-SelfTest` at all**, so this rule could only
ever be exercised by CI against a real `bitsadmin` job on a Windows runner —
which is why the mistake had to be caught by hand on the owner's machine. The
grading is now a pure `Get-BitsVerdict` taking plain values, with 25 cases that
run on any platform, and `lint.yml` gains a `persistence-bits-grade` job.

### The summary dashboard no longer measures the process list a second time
The same report said both of these about the same machine:

| | |
|---|---|
| Section 4 | `[WARNING] 2 of 3 user-profile process path(s) are suspicious` |
| Dashboard | `[INFO] Processes from user-profile paths, all validly signed: 1` |

Neither was wrong. Section 4 grades a process dump taken early in the run; the
dashboard tile called `Get-CimInstance Win32_Process` again about eight minutes
later, with its own inline copy of the rule. An Ollama install finished in
between, so the installer processes existed for one measurement and not the
other.

`proc_path_grade.ps1` was introduced to stop exactly this contradiction, and its
header claimed the rule was *"now shared so the two cannot drift apart."* It was
not shared — the tile's copy had also quietly dropped `$Recycle` from both its
regexes and graded `CRIT` where the section graded `WARNING`. But **sharing the
rule would not have been enough. Identical rules still contradict when they are
two measurements.**

So the tile no longer measures. `proc_path_grade.ps1` writes its verdict to a
`-StateFile`; the bats read it into `PROCPATH_STATE` and the dashboard prints
that — the same idiom `DNSPROBE_STATE` already used. Every tile now names the
scope it covers ("in the Section 4 process snapshot"), and a missing verdict
prints *"were NOT graded"* rather than an all-clear.

The names cross into cmd.exe, where `&`, `|`, `>`, `^`, `%` and `!` in a
filename would be shell syntax, so the state line is sanitised to a strict
allowlist and capped. It also never has an empty trailing field: cmd's `for /f`
does not define a token that is not there and leaves the text `%%e` in the
command, so an empty name list would have set `PROCPATH_NAMES` to the literal
string `%e`.

### An installer running from %TEMP% is catalogued
The same run flagged `OllamaSetup.exe` under `\Temp\WinGet\` and
`OllamaSetup.tmp` under `\Temp\is-0X2Z2LGMY8.tmp\` (Inno Setup's extraction
folder). **Both are true positives and stay findings** — `\Temp\` is suspicious
whatever the signature says, because an attacker running from there looks
identical. What was missing is the prompt to ask the right question, so
`tests/benign_corpus.txt` gains an ADVISE entry that puts it plainly: *were you
installing something when this audit ran?* If not, this is exactly the shape the
check exists to catch.

### An unsigned-driver finding now says whether Memory Integrity is running
On 2026-09-07 the audit correctly reported an unsigned kernel driver, and
exposure was nil the whole time: that machine ran HVCI / Memory Integrity, so
kernel code integrity was hypervisor-enforced. **The audit knew that** —
`boot_chain_check.ps1` printed it in Section 13 — and the driver finding in
Section 18 never mentioned it. Two sections holding halves of one picture, and
the reader left to join them.

`tools/driver_audit.ps1` now prints one `[INFO]` line beside a signature
finding, stating the measured Memory Integrity state and pointing at Section 13
for the rest of the boot chain.

**It never changes the grade.** An unsigned kernel driver is a WARNING whether
or not HVCI is running: the file is still wrong — `bthmodem.sys` was genuinely
corrupt — and the mitigation can be switched off while the finding outlives it.
Downgrading a real finding because a mitigating control is present is the false
reassurance this project treats as its worst failure, so a self-test case
asserts the HVCI-on wording still says the finding stands, and CI asserts the
marker severity is unchanged.

The wording claims only what was measured. Not "this driver cannot load" — a
guarantee about a specific binary — but the state and the established meaning
of the mechanism, mirroring `boot_chain_check`'s own phrasing.

**All three states produce a line**, including *unknown*: `driver_audit.ps1` is
not admin-gated in `doze_sec_noAdmin.bat` (`boot_chain_check.ps1` is), so
unelevated runs where the query cannot answer are real, and going silent there
is the failure this was designed against.

`Get-HvciNote` is a pure function taking a state, and the probe is never called
during `-SelfTest` — that suite runs on Linux, where the DeviceGuard namespace
does not exist. Nine new cases; three mutations proven to fail, including one
that guards the no-downgrade decision.

**Also fixed in `boot_chain_check.ps1`:** a `$null` `SecurityServicesRunning` or
`VirtualizationBasedSecurityStatus` was reported as *not running* rather than
*could not be determined* — stating hardening as absent when it merely could
not be read. Copying that logic into the driver audit would have duplicated the
bug. Its CI step asserted nothing at all about those lines before; it now
requires exactly one answer to each question.

Catalogued as `[hvci-off-driver-context]` in `tests/benign_corpus.txt`: most
consumer hardware has HVCI off, and that must never read as a finding.

### Fixed: three claims that overstated what the tool knew
All three surfaced in one field run on 2026-09-13, and all three are the same
mistake: reporting more certainty than the evidence carried.

**BITS jobs are no longer flagged for their age alone.** The rule raised a
WARNING on any job older than 30 days. On the owner's machine it fired for
`Edge Component Updater` -- Microsoft Edge's own updater, created 2026-08-09,
with no notify command line. It had been 29 days old during the previous run
and 35 during this one: **the finding reported a birthday, not a behaviour**,
and nothing on the machine had changed. It was also the same benign job the
notify-command arm had already been fixed for, so the false positive returned
through the other rule -- which is what an unconditioned rule will always
allow.

T1197 persistence executes through the *notify command line*, handled
separately. A long-parked job without one can still move bytes, so the
discriminator is now the **destination**: a bare IP address, plain HTTP, or a
write directly into an autostart folder raises; an unreadable file list raises with the
uncertainty stated; an ordinary destination is reported as `[INFO]` context
with the destination shown. Deliberately not a list of known-good job names --
this repo already records that excluding by name lets an attacker pick the
name. The destination signals deliberately do **not** use `$badPathRx`, though every
other arm in that file does: it contains `\Temp\`, and a BITS job writing into
the temp folder is what a downloader *does* — Edge's updater included. Raising
on that would have replaced one false positive with a broader one. Caught before
it shipped, and the CI case now downloads to `$env:TEMP` specifically to keep it
caught.

Catalogued as `[bits-long-lived-updater]` in `tests/benign_corpus.txt`,
and CI now drives both directions against a real `bitsadmin` job.

**The CBS check now states the window it covers.** It reported
`[OK] 2 CBS log file(s) read -- Windows servicing has recorded no corrupt
system files`, which reads as absolute. It is not: CBS logs rotate, and on that
machine the corrupt-file records from 2026-09-07 had **completely aged out six
days later** -- confirmed by counting `Corrupt file` lines in the retained logs,
which came back zero. Every run now names the oldest timestamp it could see and
says plainly that older corruption is invisible to the check.

**And a counter that was wrong exactly when coverage shrank.** If the read
budget expired part-way through a log, the file was counted as *both* read and
unread. Files are now counted as fully read, cut short, never opened, denied,
or failed -- separately, because they mean different things to a reader.

Two bugs in that reader were found by a fixture round-trip, not by the
self-test, which only covers the pure grading functions: `[datetime]::TryParse`
with an untyped `[ref]` threw and sent every file read into the catch, so a
readable log reported `[SKIPPED]`; and `StreamReader.Peek()` returns `-1` rather
than `$null` at end of stream, so every complete file counted as partial. CI
accepted `[SKIPPED]` as a valid outcome and would have shipped both. It now
fails on `[SKIPPED]` from an elevated runner -- the same rule `psv2_check`
already carries -- asserts the coverage line, and drives the real reader over a
fixture.

### Added: the audit reads Windows' own record of corrupted system binaries
The Windows servicing stack writes to `%WINDIR%\Logs\CBS\CBS.log` every time
it finds a protected system binary whose bytes do not match the component
store. That is a first-party integrity oracle, and the tool did not read it.

The cost of not reading it, measured: on 2026-09-07 the driver audit flagged
`bthmodem.sys` as unsigned and establishing *why* took five rounds of
hand-written diagnostics against the owner's machine. The answer was already in
CBS.log — `DEPLOY [Pnp] Corrupt file:` six times, then `Repaired file:`.

`tools/cbs_integrity_check.ps1` (Section 13, **T1554** Compromise Host Software
Binary) reads it. Two design constraints shaped it:

- **The log is history, so the present is verified.** CBS entries persist
  indefinitely. An unrepaired entry is a *lead*, not a verdict: the file's
  signature is checked now, and only a file that was logged corrupt *and* still
  fails verification becomes a finding. Reporting long-repaired corruption as
  current would be the same defect as reporting an empty `PortProxy` key as an
  IOC.
- **Microsoft KB 954402's benign class is excluded by design.**
  `[SR] Cannot repair member file ... hash mismatch` appears routinely and
  benignly for static files Windows Resource Protection does not protect —
  Microsoft's own example is a wallpaper `.jpg`. A naive grep reports wallpaper
  as compromise. Executable payloads are the discriminator.

Everything else is reported as counted context rather than silence: files
repaired by Windows, paths no longer on disk, and the KB 954402 class. An
unreadable log is `[SKIPPED]`, never `[OK]`, and budget exhaustion is declared
as missing coverage rather than passed off as clean.

Eleven self-test cases run over fixed inputs — including the real `bthmodem.sys`
lines verbatim and KB 954402's own example — and are proven to fail on three
mutations: dropping the repair pairing, dropping the KB 954402 discriminator,
and dropping the live verification. Deliberately corrupting a protected binary
to test end-to-end would risk an unbootable machine, so it is declared
`UNTESTABLE` in `tests/emulation_corpus.txt` with that reason rather than left
as a silent gap.

Non-admin runs defer it and say so (`[DEFERRED - ADMIN REQUIRED]`), since
reading the CBS directory needs elevation on most builds.

### Confirmed: the driver audit caught real corruption of a system binary
The `bthmodem.sys` warning that three documents called a false positive was
true, and Windows says so in its own words. `sfc /VERIFYFILE` returned
*Windows Resource Protection found integrity violations*, and `CBS.log` logged
`DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\bthmodem.sys` six
times across roughly an hour before `DEPLOY [Pnp] Repaired file` for the same
path. After the repair the file reports `Status=Valid`,
`SignatureType=Catalog`, `IsOSBinary=True`.

The size was 114,688 bytes before and after, with a different SHA256 —
equal length, different content, which is in-place corruption of an extent
rather than one file substituted for another. The machine carries an Intel
RAID 0 volume, which has no parity to rebuild a bad block from.

Exposure was nil throughout: HVCI / Memory Integrity was running with Secure
Boot in user mode, so an unsigned kernel driver could not load, and the
BTHMODEM service was `STOPPED` with exit code 1077 — never started.

**The audit detected genuine corruption of a kernel binary hours before
anything else on the machine acted on it**, and the fix that had been designed
for this "false positive" would have silenced exactly that warning.

### Confirmed on a real machine: the Sticky Keys ledger raise works, debt retired
The Sticky Keys finding now reaches the findings ledger on the owner's own
Windows 11 machine, not merely on a CI runner:
`WARNING|13|T1546.008|Sticky Keys shortcut enabled - Shift x5 triggers
sethc.exe at the logon screen`. Its remediation and the matching undo are both
present in the generated scripts.

Its `addfix` had been triggered by `($joined -match 'Sticky Keys shortcut
enabled') -or (led 'WARNING' '13' 'T1546.008' 'Sticky Keys')`. The first half
was deliberate temporary debt: matching the DASHBOARD PROSE is exactly what
queued an elevated command for a finding the tool did not count, and it was
kept only until the ledger half could be shown to fire on real hardware. It
has, so the prose half is gone and the trigger is the ledger alone.

The same report confirms the rest of the chain end to end: the header reads
`0 CRITICAL / 9 WARNING -- 30 DASHBOARD CHECKS PASSED`, `FINDINGS COUNTED: 9`,
and the ledger holds exactly 9 rows. Header, count and ledger agree, with no
`AUDITGAP` anywhere in the report.

### Fixed: the driver signature grade could not be tested at all
`tools/driver_audit.ps1` decided whether a kernel driver is unsigned with a
bare `Get-AuthenticodeSignature` inline in its scan loop, with no injection
point — unlike `service_signature_check.ps1`, `module_inspect.ps1` and
`proc_path_grade.ps1`, which all grade behind an injectable probe. The rule
most likely to be wrong was the only one no test could exercise.

It is now a pure `Get-DriverVerdict` behind `$script:SigProbe` /
`$script:HashProbe`, with a `-SelfTest` covering eight cases in both
directions. No behaviour change. One case asserts the emitted message still
matches the regex `tests/benign_corpus.txt` keys on, so rewording it can no
longer silently decouple that entry.

Two latent platform dependencies surfaced and were removed:
`[IO.Path]::GetFileName` treats `\` as a separator only on Windows, so off
Windows it returned the entire path and every known-bad *name* rule stopped
matching; and `Join-Path` resolves the drive and throws when it does not
exist, which a pure grading function must not depend on.

### Corrected: the driver-catalog gap does not exist, and bthmodem is a TRUE finding
Three documents — `README.md`, `docs/design/backlog.md` and
`tests/benign_corpus.txt` — asserted that `Get-AuthenticodeSignature` cannot
read driver-store catalog signatures, and that `bthmodem.sys` reporting
`NotSigned` on the owner's machine was therefore a false positive needing a
`WinVerifyTrust` catalog-member lookup. All three were wrong, and none of the
claim had ever been measured.

Measured on the owner's own machine (Windows 11 26200, elevated, CryptSvc
running, 5,493 catalogs present and readable):

```
Total .sys: 467
   Valid/Catalog      = 464
   Valid/Authenticode = 2
   NotSigned/None     = 1     <- bthmodem.sys, alone
```

and direct queries of BOTH catalog databases, by SHA256 and by SHA1, all
returned *no catalog covers this file*, with `SignatureType=None` and no
signer. Catalogs are keyed by file hash and they accumulate, so a
legitimately-shipped-but-superseded Microsoft driver would very likely still
match one of the 5,493. Matching none means those bytes are not a version
Microsoft shipped to that machine.

**The tool's warning is correct.** The planned fix would have suppressed it.

The `[driver-catalog-signed-inbox]` corpus entry is removed rather than
reworded — it claimed a benign cause that does not exist, for a finding that
appears to be true, and an entry like that teaches a reader to dismiss a real
one. A tombstone comment records the measurement so it is not re-added on the
dead theory. README and the backlog are corrected in place.

*Why* that one file has no catalog — corruption, a third-party or OEM package,
an odd servicing outcome, or tampering, which all produce the same answer — is
open and tracked in the backlog.

### Measured: PowerShell 5.1 already reads driver catalog signatures
The backlog, the README and `tests/benign_corpus.txt` all held that
`Get-AuthenticodeSignature` cannot read driver-store catalog signatures, and
that `bthmodem.sys` reporting `NotSigned` was therefore a false positive
needing `WinVerifyTrust` with a catalog-member lookup.

Measured on a real runner (Windows Server 2025 26100, PowerShell 5.1.26100):
all 457 drivers in `System32\drivers` reported `Status=Valid`, and every one
sampled reported `SignatureType=Catalog`. **5.1 already resolves driver
catalogs.** The planned P/Invoke would have solved a problem that does not
exist, and would have suppressed a warning that may be correct.

The false positive does not reproduce on a clean machine at all. On the
owner's machine `bthmodem.sys` is the *only* driver reporting `NotSigned` —
one file, not many — which rules out a broken catalog subsystem and points at
that single driver being genuinely uncovered. Diagnosis continues against the
machine where it actually happens; no fix is shipped on a theory again.

### Fixed: no `:dz_ps_scan` block had ever raised a finding
`:dz_ps_scan` read its severity back through a `for /f` backtick whose command
began with a quoted absolute path. cmd runs such a command through `cmd /c`,
which strips the leading and trailing quote when the line begins with one, so
the invocation was mangled, produced no output, and `DZ_BLKSEV` kept its `OK`
default. All eighteen call sites in both bats were affected — Office macro
policy, Secure Boot, AMSI-bypass traces in PowerShell logs, RDP shadowing and
the nation-state TTP blocks all printed findings into the report that reached
neither the findings ledger, `FINDINGS COUNTED`, the section verdict nor the
exit code.

Only checks carrying a marker backstop survived, and the backstop masked the
failure rather than exposing it: the ASR block raises its message from the
marker precisely *when the grade came back `OK`*, so its ledger row looked like
proof the grader worked.

The grade is now read through a file and `set /p`. `DZ_BLKSEV` starts at
`DZ_NOGRADE` rather than `OK`, so a grade that is never read is declared an
`AUDITGAP` instead of passing as clean.

**Reports will show more findings than before.** Nothing new is being detected;
these are checks that were already printing into the report while the verdict
ignored them.

### Fixed: the HTML dashboard rendered 0/0/0 on machines with real findings
`report_html` builds its dashboard by matching the text report's verdict line.
When that header gained ledger-derived counts its separator changed from `/` to
` -- `, the regex stopped matching, and the cards rendered zero while the text
report showed the true numbers. The CI fixture still used the old format, so a
test existed and proved nothing. All shapes are now matched, the fixture is the
current one, and all three counts are asserted.

### Fixed: the summary header contradicted `FINDINGS COUNTED`
The header counted dashboard tiles, so a report could read
`0 CRITICAL / 3 WARNING / 30 PASSED` and end `FINDINGS COUNTED: 7`. The
CRITICAL and WARNING halves now derive from the same ledger; the third number
stays a tile count and says so.

### Fixed: Sticky Keys printed a finding that was never counted
Section 13 printed `[WARN] Sticky Keys shortcut ENABLED` — a spelling none of
the three gates recognised. `[CRITICAL]` and `[WARNING]` are now the report's
entire severity vocabulary, enforced on the `%REPORT%` and `%PSRUN%` paths.

### Fixed: MSIX package binaries reported as unsigned
MSIX signs the package, not each inner file, so `Get-AuthenticodeSignature` on
the inner `.exe` correctly returns `NotSigned`. `SignatureKind` is now the
oracle: `Store`/`System` are inventory, `Developer`/`Enterprise` and `None`
stay findings, and an unresolvable package fails closed.

### Fixed: false positives on HOSTS, COM CLSIDs, BITS and browser extensions
A machine's own hostname mapped to its own private address is no longer a DNS
hijack; a dangling vendor COM registration is context; an empty BITS notify
command line is not a finding; and a store-installed extension is graded on
provenance rather than permissions alone.

### New gates
`tests/assert_printed_findings_raised.ps1`, `tests/assert_header_matches_ledger.ps1`,
`tools/lint_ps51_portability.ps1`, and artifact parity in `tools/lint_docs_drift.ps1`.

## 7.3

### New: `-dnsprobe` active DNS integrity probe (opt-in)
Adds an opt-in active DNS check (Section 3, `tools/dns_probe.ps1`). When
`-dnsprobe` is passed, the audit resolves a fixed list of **legitimate**
Windows / Defender / connectivity domains and flags any that fail to resolve
or resolve to a non-public IP (0.0.0.0 / loopback / private / link-local) — the
signature of malware blackholing update/AV traffic via a DNS or HOSTS hijack
(T1562.001). It also inventories the configured DNS resolvers.

**Safe by design:** it never resolves attacker / `ioc_domains.txt` C2 entries,
so it sends no outbound queries to malicious infrastructure. That
higher-fidelity but OPSEC-risky variant remains deferred (see THREAT_MODEL.md).
Off by default; gated like `-vt`. A blackhole signature raises the exit code to
WARNING and is surfaced as a finding in the live summary + HTML Findings Index
(under ACTIVE COMPROMISE INDICATORS), not just buried in the Section 3 body. The
new script is parsed and executed by the helpers-ps51 CI job.

## 7.2

Accuracy and trust release. Every change below makes the tool report reality
more faithfully — no false alarms, and a change log / undo script that lists
only changes actually made.

### CTI / IOC false-positive fixes
- **Registry IOC sweep (18h):** value-based entries now fire only when the
  value equals the *malicious* value (`HIVE\KEY|Value|BadValue`). Hardened
  settings such as `EnableLUA=1` and `RunAsPPL=1` are no longer flagged as
  compromise indicators.
- **Baseline cleanup:** stripped non-discriminating `# CTI-AUTO` entries that a
  prior `-updateTTP` mirror had committed into the shipped IOC lists
  (`ioc_processes.txt`, `ioc_registry.txt`, `ioc_file_paths.txt`,
  `ttp_manifest.txt`), e.g. `msbuild`, ubiquitous registry keys like `RunMRU`,
  and overly-broad path globs. The shipped baseline is now purely hand-curated.
- **Browser extensions:** expanded the first-party component allowlist so Edge /
  Chrome / Brave built-ins are not flagged as sideloaded.

### `-updateTTP` no longer pollutes the repo
- Merges are written only to the runtime `C:\SecurityAudit\ThreatLists`, never
  back into the git checkout — so `git pull` is never blocked and the baseline
  cannot drift.
- **New `-resetTTP` flag:** restores the runtime ThreatLists to the pristine
  shipped baseline (clears runtime `ioc_*.txt` / `ttp_manifest.txt`). Combine
  with `-updateTTP` for "clean slate, then fresh pull."

### Reporting accuracy
- **System event log cleared (event 104)** is now `WARNING`, not `CRITICAL`
  (Windows updates / driver installs / disk cleanup routinely clear it). The
  Security log (1102) clearing — the real attacker cover-up signal — stays
  `CRITICAL`.
- **HTML report Findings Index:** a panel at the top lists every CRITICAL and
  WARNING finding, each linking to its section. Dashboard counts now come from
  the report's own verdict line (previously inflated by incidental matches).
  The HTML generator moved to a CI-tested `tools/report_html.ps1`.
- **Change log / undo now record only real changes:**
  - INIT 11 (F8 boot menu) logs `displaybootmenu` / `timeout` changes only when
    the value actually differs from the target — no more phantom
    `was "5" -- set to "5"` entries.
  - INIT 12 (System Restore Point) logs `[CREATED]` only when a restore point
    was actually created (Windows throttles these to one per 24h).

### Counts synced
`ioc_processes` 77→54, `ioc_registry` 37→25, `ttp_manifest` / techniques 77→48,
total indicators 320→283 (README / THREAT_MODEL / readMe).

### Hardening — extract risky inline PowerShell from the INIT path
The crash class behind the INIT 12 and HTML regressions is PowerShell built by
echoing lines into a temp file: a single mis-escaped cmd metacharacter aborts
the whole audit. Extracted the remaining nested INIT-path blocks into
CI-tested `tools/*.ps1` (no cmd escaping):
`self_update_check.ps1` (INIT 10 self-update), `disk_info.ps1` (INIT 13 VM /
SSD / disk-detail / free-space), `smart_health.ps1` (INIT 14 WMI health
fallback), alongside the earlier `report_html.ps1` and `srp_check.ps1`. The
helpers-ps51 CI job now parses and executes all of them. Behavior is
unchanged; this only removes the escaping hazard.

## 7.1 and earlier

See the git history. 7.1 introduced the SENTINEL-X CTI integration, the HTML
report, the `-updateTTP` / `-importTTP` pipeline, and the real-Windows
smoke-test CI.
