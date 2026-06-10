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

## Lint (run before committing batch changes)

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1
```

Scans all `.bat`/`.cmd` files with a cmd-accurate parenthesis-depth tracker
and fails on any `::` comment inside a block. CI runs the same script on
every push/PR (`.github/workflows/lint.yml`). It needs only built-in
PowerShell (5.1+ on Windows, `pwsh` on CI) — no external dependencies.

## Other cmd.exe traps already documented in-code

- Inside blocks use delayed expansion (`!var!`); `%var%` expands at
  block-parse time (see comments near the `errorlevel` checks).
- `endlocal` and `exit /b %EXIT_CODE%` must stay on one line so the value
  is captured before `endlocal` clears it (closes #96).
- Parens in `echo` text written into generated scripts must be escaped
  (`^)`, `^|`) when the echo can run inside a block.
