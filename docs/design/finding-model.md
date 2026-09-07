# Design memo — unifying the finding model (review finding #4)

Status: **draft for decision** · Scope: `doze_sec.bat`, `doze_sec_noAdmin.bat`,
`tests/detection_selftest.ps1` · Owner: TBD

## 1. Problem

A single audit run produces three severity signals that are computed from
three *different* populations of checks and can contradict each other:

| Channel | Computed by | Drives | Population |
|---|---|---|---|
| `FINDINGS` counter | 24 cmd-side `set /a FINDINGS+=1` sites | per-section verdict (`[SECTION n/18 RESULT: …]`), `FINDINGS COUNTED: N` | sections that were wired |
| Summary dashboard | `ck` in a PSRUN block (`$cr/$wa/$pa/$inf`), re-deriving state | dashboard counts + `SUM_RESULT` token → exit code | a curated high-value subset, re-checked independently |
| CRITICAL scrape | `Select-String '\A[CRITICAL]'` over the report | exit code → 8 | any report line starting `[CRITICAL]` |

All three feed one **saturating** `EXIT_CODE` global (`if … LSS n set n`).

### Concrete divergences observed

- **Firewall-disabled-only host:** the dashboard's `ck 'CRIT'` drives the exit
  code to 8, but nothing increments `FINDINGS`, so the report prints
  `FINDINGS COUNTED: 0` next to a code-8 verdict, and Section 8's own verdict
  reads `[SECTION 8/18 RESULT: CLEAN]`. Three artifacts of one run disagree.
- **Section 9 Defender exclusions:** emit `[WARNING] Exclusion paths found:`
  but do not touch `FINDINGS`; the dashboard re-derives exclusions via a `ck`,
  so the exit code rises while Section 9's verdict says CLEAN and
  `FINDINGS COUNTED` omits it.
- **Fully-silent class (now partly closed):** a section `[WARNING]` that the
  dashboard does *not* re-derive and that isn't wired to `FINDINGS` produced
  no machine-readable signal at all. Section 7 service-gating was exactly this
  until #144; other sections may still be.

## 2. Root cause / history

The tool grew section by section. The dashboard was added later as a *second
pass* that re-derives a hand-picked subset. `FINDINGS` was added (Step 3, #141)
to fix per-section verdict masking, but it only instrumented the cmd-side raise
sites — not the PSRUN-emitted `[WARNING]`/`[CRITICAL]` lines and not the
dashboard. So no single record is authoritative; each signal sees a different
slice of reality.

## 3. Goal — invariants a fix must establish

- **I1 (single source):** every severity signal — section verdict,
  `FINDINGS COUNTED`, dashboard counts, exit code — derives from one record.
- **I2 (no divergence):** a finding counted in one place is counted in all.
- **I3 (non-lossy severity):** severity is a monotonic max (8 > 4 > 2 > 0),
  not a value that saturates at 2 and hides higher findings.
- **I4 (pure exit code):** exit code is a pure function of the record — 8 iff
  ≥1 CRITICAL, 2 iff ≥1 WARNING (and the fatal/abort codes 1/3/5/7 still
  short-circuit before it).

## 4. Options

### Option A — Reconcile in place (keep the three channels, wire the gaps)
Make every `[WARNING]`/`[CRITICAL]` site also bump `FINDINGS` + the exit code,
and have the dashboard read the same counters instead of re-deriving.

- **Pros:** incremental, low blast radius, no rewrite; each gap is a small PR
  with a harness plant — the exact pattern used for #1/#5/#6.
- **Cons:** the duplication remains; the dashboard still re-runs checks; drift
  can recur every time a section is added; the count is still per-check-block,
  not per-finding.
- **Effort:** ongoing, ~1 PR per section-class.

### Option B — One findings ledger (recommended)
Each detection (section *or* dashboard) appends a structured line to a run-scoped
ledger file, e.g. `SEVERITY|SECTION|CODE|MESSAGE`. A single end-of-run PS pass
reads the ledger and computes **everything**: section verdicts, `FINDINGS
COUNTED` (true per-finding), dashboard counts, and the exit code (max severity).
cmd only orchestrates; the ledger is the truth. The CRITICAL scrape and the
`SUM_RESULT` token are deleted.

- **Pros:** satisfies I1–I4; per-finding counting; section verdict and dashboard
  cannot diverge; new detections just append; removes two of the three fragile
  channels.
- **Cons:** every detection site converts to "append to ledger" (~50 sites
  across both bats); section-verdict *timing* changes (computed from the ledger
  rather than inline per section). Medium rewrite — but the harness already
  asserts the observable outputs, so it guards the migration.
- **Effort:** one larger PR, or 2–3 staged (see §6).

### Option C — Move the finding model into PowerShell
The deepest fix (strangler-fig from the original review): a PS module owns the
finding model; cmd just invokes sections.

- **Pros:** eliminates the whole class of cmd escaping/expansion/channel bugs;
  unit-testable in isolation.
- **Cons:** large, multi-release, and out of proportion to #4 alone — the
  repo's identity is "two cmd.exe batch scripts." Not warranted just for this.
- **Effort:** a program, not a PR.

## 5. Recommendation

**A hybrid, sequenced:**

1. **Now — Option A for the known live divergences** (Section 9 Defender
   exclusions; any dashboard `ck` check that raises the exit code without a
   matching `FINDINGS` bump). Small, safe, each with a plant. This removes the
   user-visible contradictions immediately, and doing it *also produces the
   full inventory of finding sites* that Option B needs.
2. **Next — evaluate Option B** as one dedicated, harness-guarded effort, using
   that inventory. Option C stays out of scope unless a broader PS migration is
   independently decided.

## 6. Migration plan (if Option B is chosen)

Each step ships green; the detection harness is the safety net.

1. Define the ledger format + a `dz_finding` append helper (tiny `tools/*.ps1`
   or a cmd `:label`). One PR, no behavior change, add helper + unit test.
2. Convert section `[WARNING]`/`[CRITICAL]` sites to append (keep the report
   echo). Section verdict reads the ledger filtered by section — guarded by the
   existing verdict-unmasking harness cases.
3. Convert the dashboard to read the ledger; delete the `ck` checks that merely
   re-derive sections (keep `ck` only for genuine dashboard-only rollups).
4. Replace the CRITICAL scrape + `SUM_RESULT` token with
   `exit = maxSeverity(ledger)` — guarded by the exit-8 harness case.
5. `FINDINGS COUNTED` = ledger line count (true per-finding). Update the harness
   assertion accordingly.

## 7. Open questions to settle first

- **Count semantics:** should `FINDINGS COUNTED` mean *distinct findings*
  (ledger lines) or *checks that found something*? Option B naturally gives the
  former; confirm that's intended.
- **Verdict timing:** compute section verdicts at end (simplest, matches the
  ledger model) vs. streaming inline as today. End-of-run changes *when* the
  `[SECTION n RESULT]` line is emitted and may need a second pass or a
  placeholder — decide before step 2.
- **noAdmin parity:** every change lands in both bats, but the harness only runs
  the admin bat (noAdmin is covered by lint/parse + the sync CI guard). Option
  B's larger surface strengthens the case for a noAdmin harness run.

## 8. Status — migration complete (2026-07-25)

> **Superseded in part — see §9.** Two of the invariants this section declares
> achieved were not, and stayed unachieved until 2026-09-07.

Implemented across PRs #148–#160 and the exit-code flip PR:

- `tools/ledger.ps1` + `:dz_finding` landed; every raise site (sections, INIT,
  dashboard retrofits) writes through them.
- Section verdicts derive from the ledger (`:dz_section_clean`, findstr-based,
  in both bats). Verdict timing resolved by evaluating in-section, so the
  streaming `[SECTION n RESULT]` lines kept their position.
- `FINDINGS COUNTED` = ledger line count (distinct findings — the Option B
  natural semantics from §7).
- Exit code = `maxSeverity(ledger)`, made explicit at end-of-run with the
  `:dz_finding` per-call raise kept as the incremental/abort-path form.
- The `[CRITICAL]` report scrape and the dashboard `SUM_RESULT` token no
  longer touch the exit code or the count; both survive only as
  ledger-divergence alarms ([INFO] report lines the harness fails on).
- The dashboard's `ck` display is intentionally retained as a presentation
  layer; its tally acts as the Div-2 floor/alarm, not a source of truth.
- The §7 noAdmin-parity concern is addressed: CI now runs the plant/assert
  harness against `doze_sec_noAdmin.bat` elevated (adaptive full path) and
  runs it as a real standard user (`tests/noadmin_smoke.ps1`) asserting the
  deferral contract -- Admin : 0, PARTIAL verdicts, HKLM-read detection
  without admin, exit-code 6/8 semantics, and the ledger consistency net.

## 9. Correction — I1/I2 were not achieved by the 2026-07-25 migration

§8 above declares the migration complete. It was not, and the gap ran for the
whole life of the mechanism. Recorded here rather than edited away, because the
interesting part is *why nothing noticed*.

**`:dz_ps_scan` never reached the ledger.** It read its severity back with

```
for /f "usebackq delims=" %%s in (`"%PWSH%" ... -Path "%DZ_BLK%" 2^>nul`) do set "DZ_BLKSEV=%%s"
```

cmd runs a `for /f` backtick command through `cmd /c`, and `cmd /c` strips the
leading and trailing quote when the line begins with one. This one began with
`"%PWSH%"`, so the invocation was mangled, produced no output, the loop body
never ran, and `DZ_BLKSEV` kept its `OK` default. Every one of the eighteen
`:dz_ps_scan` call sites — Office macro policy, Secure Boot, AMSI-bypass traces,
RDP shadowing, the nation-state TTP blocks — printed findings that reached
neither the ledger, `FINDINGS COUNTED`, the section verdict nor the exit code.
So **I1 held only for the raise sites that used `:dz_finding` or a marker**, and
`:dz_ps_scan` was neither.

**The backstop is what hid it.** §8 records the marker retrofits approvingly.
But the ASR block raises its message *from the marker precisely when the grade
came back `OK`* — so on every affected run its ledger row existed and looked
like proof the grader worked. That row was used, twice, to argue `:dz_ps_scan`
was fine. It never supported the claim: it is equally consistent with the grader
raising nothing. **Treat a backstop's row as evidence the primary path FAILED,
never that it worked.**

**I2 was violated again in the presentation layer.** §8 calls the dashboard's
`ck` tally "a presentation layer … not a source of truth", which is right — but
the summary *header* was built from it, so a report read
`0 CRITICAL / 3 WARNING / 30 PASSED` while ending `FINDINGS COUNTED: 7`. Fixing
that changed the header's shape, which silently broke `report_html`'s verdict
regex, and the HTML dashboard rendered **0/0/0 on a machine with real CRITICAL
findings** — a divergence that reads as reassurance.

### What enforces the invariants now

| Invariant | Enforced by |
|---|---|
| A printed finding reaches the ledger under its own section AND technique | `tests/assert_printed_findings_raised.ps1` (in `full-run`) |
| The summary header equals `FINDINGS COUNTED` | `tests/assert_header_matches_ledger.ps1` (in `full-run`) |
| The HTML dashboard equals the text report's verdict line | the `report_html` step in `helpers-ps51`, asserting all three counts |
| A grade that is never read is declared, not assumed clean | `DZ_BLKSEV` starts at `DZ_NOGRADE`, raised as `AUDITGAP` |

The lesson §8 should have carried: **an invariant with no test is a wish.** Each
of the three above was stated in prose — in this memo, in `CLAUDE.md`, in
`report_html`'s own header comment — and none was asserted anywhere.
