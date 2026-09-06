# doze_sec backlog

Ideas evaluated and deferred, kept here so they are not lost. Nothing here is a
commitment; each entry records enough context to pick it up later.

## Firmware / boot-chain coverage  -- SHIPPED (Sec 13 `boot_chain_check.ps1`)

**Status:** the config-audit slice below is implemented. What remains genuinely out of reach (firmware image scanning, SPI flash) stays out of scope by the stated ceiling.


**Idea.** Extend the audit below the OS: DBX (UEFI revocation list) freshness,
UEFI variable inspection, Secure Boot depth beyond the current on/off check, and
known bootkit indicators (BlackLotus, CosmicStrand and similar abuse the boot
chain to persist below Windows).

**Why it is worth doing.** State-level actors and the most capable ransomware
crews increasingly persist in firmware and the boot chain precisely because a
user-mode audit -- and most EDR -- cannot see there. It is the last major
coverage frontier for this tool.

**The honest ceiling, which must be stated in the report if this ships.** A
user-mode tool sits *above* the layer where bootkits live. This can audit the
*configuration and known-bad indicators* the OS exposes (Secure Boot state, DBX
contents via `Get-SecureBootUEFI`, the boot-order variables, moklist), but it
cannot scan the firmware image itself or trust that firmware is telling it the
truth. Framing it as "boot-chain configuration audit" rather than "firmware
scan" is essential -- overclaiming here would be the same
false-sense-of-safety failure Tier 0 exists to prevent.

**Concrete first checks.** `Get-SecureBootUEFI db`/`dbx` present and DBX not
suspiciously old (a stale DBX means known-bad bootloaders are not revoked);
`Confirm-SecureBootUEFI`; boot order and any non-Microsoft boot entries; MOK
enrollment on machines that use shim. All read-only, all PowerShell 5.1
capable, all with a clear "this cannot see a firmware implant" caveat.

## Adversary-emulation corpus

Being built now (see `tools/emulation_coverage.ps1`, `tests/emulation_corpus.txt`).

## Deferred by the retrospective (recorded, not silently dropped)

The three-pass retrospective flagged seven items as "not delivered". On review
they are unbuilt *capability*, not broken code — but leaving them undocumented
is how a gap becomes an implicit claim. Each is recorded here with what it would
take, so the difference between "decided against" and "forgotten" stays visible.

### Confidence-calibrated section verdicts in the admin script

`doze_sec_noAdmin.bat` prints a `PARTIAL` verdict when a section deferred checks
it could not run without elevation. `doze_sec.bat` has no equivalent: every
section prints the literal `CLEAN -- no issues detected` regardless of how many
of its checks were skipped (`grep -c PARTIAL doze_sec.bat` returns 0).

**Why it matters.** A section whose three checks all `[SKIPPED]` reads exactly
like a section whose three checks all passed. The Tier 0 COVERAGE & CONFIDENCE
block reports skips in aggregate, but the per-section line — the thing a reader
actually scans — does not.

**What it needs.** A per-section skip tally alongside the existing ledger query
in `:dz_section_clean`, and a third verdict state between CLEAN and ISSUES
FOUND. The ledger already carries the raises; the skips would need their own
counter.

### Per-section PARTIAL in the admin script — measured, and not worth building yet

Recorded with evidence rather than built. Across five real reports from the
owner's machine (three 09-05, two 08-30), every admin run contained exactly
**one** section-level `[SKIPPED]`, always the PSv2 check, and two of the five
did print `CLEAN` for Section 11 despite it. So the gap was real but its whole
population was one check — and the dashboard already declared it
(`[ INFO ] PSv2 state unavailable -- see Section 11`).

Fixing the PSv2 check itself (`tools/psv2_check.ps1`) removes that one skip.
Building a 40-site skip counter plus a lint for a population of zero is
disproportionate. Revisit if a real run ever shows several section-level skips
— the noAdmin `DEFERRED_COUNT` / `SEC<N>_PREV_DEF` pattern is the model.

### Catalog-signed binaries read as unsigned (two confirmed instances)

`Get-AuthenticodeSignature` returns `NotSigned` for files whose signature lives
in a security catalog rather than embedded in the file. Two confirmed on the
owner's machine:

- `C:\WINDOWS\system32\drivers\bthmodem.sys` — a Microsoft inbox driver,
  reported by the Section 18 driver audit as "unsigned or invalid Authenticode
  signature (NotSigned) on a kernel driver".
- MSIX/Store packages under `C:\Program Files\WindowsApps\...` — surfaced
  when `proc_path_grade` briefly graded out-of-scope paths (#198, fixed).
  `proc_path_grade` no longer looks at them, but the driver audit still does
  the same kind of check on files that can be catalog-signed.

- Modules loaded from an application-virtualization package
  (Office Click-to-Run, MSIX) that `module_inspect` resolves through the VFS.
  The signature is now verified at the REAL path, so the resolved case is
  correct; but a package whose layout the VFS mapping does not cover would
  fall through to the "not visible on disk" wording rather than to a signature
  verdict. A catalog-aware check would not fix that on its own — the file has
  to be located first — but the two land on the same set of files.

**What it needs.** A signature check that consults the catalog store, not only
the embedded signature — `Get-AuthenticodeSignature` alone cannot answer this.
The usual route is the WinVerifyTrust API with a catalog lookup, which means
P/Invoke from PowerShell 5.1, or shelling to `signtool verify /pa /kp` where
available. Neither is free, and getting it wrong in the *other* direction
(treating a genuinely unsigned driver as fine) is far worse than the current
false positive, so this needs a test that proves both directions before it
ships.

### A coverage percentage with a denominator

`report_safety.ps1 -Mode Coverage` reports a raw count of skipped checks. There
is no denominator anywhere, so "3 skipped" cannot be read as 3-of-12 or 3-of-200.

**What it needs.** A total-checks-attempted counter. There is currently no
central register of how many checks a run *tried*, so this is a real piece of
plumbing rather than a formatting change.

### Timestamps on persistence findings

No persistence detector surfaces the registry key's last-write time or the
backing file's timestamps. For someone reconstructing *when* a device was
compromised — the question that matters in an abuse or legal context — that is
the single most useful field the tool could add and does not.

**What it needs.** `(Get-Item $key).LastWriteTime` on the registry side is easy;
file timestamps are already available where a path is resolved. Mostly a matter
of threading them through the finding strings in `persistence_eval.ps1`,
`startup_eval.ps1`, `logon_persistence.ps1` and `persistence_extra.ps1`.

### Log-gap detection

Section 16 detects explicit clear events (Security 1102, System 104). It never
inspects retention settings, configured vs actual log size, record counts, or
the age of the oldest surviving record.

**Why it matters.** Selective deletion leaves no 1102. An attacker who trims
individual records, or who lets a deliberately undersized log roll over, defeats
every event-based check in the tool while this section reports clean.

**What it needs.** Compare `MaximumSizeInBytes` and `RecordCount` against the
oldest record's timestamp per log; a Security log whose oldest record is two
hours old on a machine that has been up for weeks is the signal.

### Sysmon / EDR presence and configuration quality

The string "Sysmon" does not appear anywhere in this repository. The tool checks
whether Defender is healthy but never asks whether any richer telemetry exists,
or whether an installed EDR agent is actually running and reporting.

**What it needs.** Service and driver presence checks for the common agents, and
for Sysmon specifically a config-quality read (is it installed with a
schema-versioned config, or the bare default that logs almost nothing).

### Tamper-evident reports

The report is written and finalized with no integrity digest and no off-host
copy guidance.

**Why it matters.** If the machine is compromised, the report on it can be
edited by whoever compromised it — and for an at-risk user the report may
eventually need to be evidence.

**What it needs.** Emit a SHA256 of the finished report (and print it to the
console, where it is harder to alter after the fact), plus explicit guidance to
copy the report off the device before remediating. Small change, meaningful for
the at-risk-user case the tool already speaks to.

### `attack_matrix` defines "detected" as "the id appears in the source"

`attack_matrix.ps1` and `emulation_coverage.ps1` both derive their technique set
by regex-scanning `.bat`/`.ps1` for `T1234` strings. That over-claims for ids
that appear only in prose or a comment, and under-claims for real detections
whose technique id is never written down in the code.

**Why it is deferred rather than fixed.** The alternative — an explicit
technique registry each check declares itself into — is more accurate but adds a
second source of truth that can itself drift, which is exactly the failure the
live scan was built to avoid. The current approximation is honest as long as it
is documented, which is what this entry does. Revisit if the drift becomes real
rather than theoretical.

---

## Status of the entries above (2026-09-02)

Shipped since this file was written: **Sysmon / EDR presence** (#183, with
the config-quality read deliberately left out — grading it would mean
executing the vendor binary on a machine under suspicion), **tamper-evident
reports** (#180), **event-log gaps** (#181). The `attack_matrix` "detected"
semantics entry stands as a documented non-decision. The coverage-denominator
item remains deferred.

## Recommendations from the 2026-08 field-testing retrospective

Source and reasoning: `docs/design/retrospective-2026-08-field-testing.md`.
The systemic finding is that the verification strategy tested the tool on an
environment (ephemeral Server 2022 runners) that is not its deployment target
(a person's Windows 10/11 laptop). Every real bug of the period, and the
lockout incident, lived in that gap. Priorities reflect harm to the tool's
audience, not effort.

### P0 — safety and trust

1. **Quarantine test output** (done, #189). Harness runs write to
   `C:\SecurityAudit\selftest\` and stamp a `*** TEST RUN ***` banner on the
   report's first lines and the HTML header. A test report must never be
   mistakable for a real one — the owner opened one and asked how to fix
   their computer.
2. **Read-only field-test mode + benign-baseline corpus** (done: `-readonly`,
   `tests/field_test.ps1`, `tests/benign_corpus.txt`, `lint_readonly`). False-positive
   hunting (read-only, safe on any real machine) separated from detection
   proving (the plant harness, VM/CI only). `tests/benign_corpus.txt`
   catalogs known-benign look-alikes (`P9NP`, never-onboarded `Sense`,
   `WudfUsbccidDriver` Event 104, Codex sandbox accounts, …) and they are
   regression-tested.
3. **Blast-radius manifest for the harness** (done). Every plant declares
   what it touches and whether it can affect logon, boot, network, or
   defense; `safety_invariants` fails on any plant without a declaration,
   infers the axes from the plant body, and self-tests against mutations.

### P1 — detection quality

4. **False-positive parity** — every must-fire case names its benign twin;
   the emulation-corpus lint enforces it (32 must-fire vs ~12 must-not-fire
   today).
5. **Provider-qualified event queries as a lint** — any `Get-WinEvent` /
   `wevtutil` query by bare event ID fails.
6. **Apply "Microsoft-signed under System32 is context" consistently** —
   audit every DLL-path verdict for the allowlist-overrides-signature
   pattern.

### P2 — engineering hygiene

7. **Non-vacuity as a lint over `tests/*.ps1`** — every test asserts a
   minimum examined count.
8. **`docs/recovery.md`** — shipped with the retrospective.
9. **CI economics** — keep the trigger diet; decide between a public repo, a
   self-hosted Windows runner, or manual PR gating.
10. **Agent working rule in `CLAUDE.md`** — audit the full space before
    shipping a fix; never say "verified" without a test that fails when the
    claim is false.

### Explicitly not recommended

- Collapsing the twelve `Write-Marker` copies into a shared file (a
  missing-file failure mode that breaks every tool at once; the lint is the
  propagation mechanism).
- The two older deferred items above.
- Any further plant-harness runs on a daily-driver machine until item 2
  exists.
