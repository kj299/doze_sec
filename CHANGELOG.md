# Changelog

All notable changes to doze_sec are recorded here. This is the project release
history; the per-run `ChangeLog_<timestamp>.txt` files under `C:\SecurityAudit`
are a separate, machine-specific record of changes each audit made.

## Unreleased

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
  has never heard of it, stays CRITICAL. Pure verdicts, a 12-case self-test,
  and the standard-user smoke job now plants a DACL-restricted service.
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
