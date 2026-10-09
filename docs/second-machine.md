# Running doze_sec on a second machine

This page is for running the audit on a computer that is not the one you
develop on: a family member's PC, a friend's laptop, or a work machine. The
point is to find out what the tool gets wrong on a machine it has never seen.
Every finding gets checked by hand afterwards.

**What it does to that machine:** nothing you have to undo. The audit runs
read-only. It writes only its own output folder and the temp folder, makes no
network connections, and installs nothing (it uses the Windows PowerShell 5.1
built into Windows 10 and 11). `tests\field_test.ps1` checks that claim before
and after the run and prints the result. When you are finished you delete
the output folders (and the tool, if you copied it onto the PC).

---

## Before you start: read these warnings

**On a WORK or school machine, get written permission from IT first.** The
audit reads the LSASS protection state, the Security event log, every service,
scheduled task and driver, and the DLLs loaded inside running processes.
Corporate security software (Defender for Endpoint, CrowdStrike, SentinelOne
and others) can treat that as suspicious. **IT may get an alert, contact you,
or cut the machine off the network until they have looked.** Do not run it
there without their OK.

**On SOMEONE ELSE'S PC, ask them first and keep the report private.** The
report contains their user names, computer name, installed software, network
configuration and recent event-log entries. Do not post it anywhere public.

**Never run the test harness there** (`tests\manual_ci.ps1`,
`tests\detection_selftest.ps1`). It plants fake malware on purpose, and on a
real PC it once **locked the owner out of their own machine** until a hard
power-off (see `docs\recovery.md`). Only `tests\field_test.ps1` is safe.

**Never run the generated `Remediation_*.ps1` scripts there.** They change
security settings. Bring them back unrun so they can be reviewed.

---

## Step 1: put the tool on a USB stick (on your own laptop)

The repository is private, and the other machine needs neither git nor a
GitHub login. Open PowerShell **as administrator** on your laptop, go to your
`doze_sec` folder, and run (use your stick's letter):

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\make_usb_stick.ps1 -ListCandidates
powershell -NoProfile -ExecutionPolicy Bypass -File tools\make_usb_stick.ps1 -Drive E:
```

It accepts only a drive on the USB bus that is not your Windows disk, and it
**never formats anything**. It copies the tool to `E:\doze_sec`, leaves off
`.git` and the test harness (named as it goes -- the harness must never reach
someone else's PC), and keeps a SHA-256 manifest of the stick on your laptop.
Then eject the stick, plug it back in, and run the same command with `-Verify`
once before you leave.

If the stick is unformatted: File Explorer, right-click the drive, Format,
exFAT. **Formatting erases every file on that drive -- check the letter is the
stick.** Without the script, `robocopy C:\path\to\doze_sec E:\doze_sec /E /XD .git`
also works, but it carries the harness, and there is no manifest to check the
stick against afterwards.

## Step 2: decide how to run it on the second machine

- **A. Straight from the stick (the default).** Nothing of the tool is copied
  onto that PC. Leave the stick in until field_test prints `OK` or `FAIL`.
  The commands below use `E:`; use whatever letter the stick gets there.
- **B. Copied onto the PC,** if the stick cannot stay plugged in: copy
  `E:\doze_sec` to `Documents\doze_sec`, i.e.
  `C:\Users\<name>\Documents\doze_sec`. **Do not put it in a Temp folder:** the
  audit refuses to run from Temp (exit code 5).

## Step 3: preflight. Paste this in before running anything

Open a **normal** PowerShell window (Start menu, type `powershell`, Enter) and
paste this whole block. Commands typed at the prompt are not subject to the
script policy, so this works even where scripts are blocked. It changes
nothing.

```
"--- execution policy (who decides whether scripts may run) ---"
Get-ExecutionPolicy -List
"--- language mode ---"
$ExecutionContext.SessionState.LanguageMode
"--- versions ---"
"PowerShell " + $PSVersionTable.PSVersion
"Windows " + [Environment]::OSVersion.Version
"--- managed by an organisation? ---"
dsregcmd /status | findstr /i "DomainJoined AzureAdJoined EnterpriseJoined"
"--- antivirus products ---"
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName
"--- is this window elevated? (a line with S-1-16-12288 means yes) ---"
whoami /groups | findstr S-1-16-12288
```

Read the answers:

| What you see | Meaning | What to do |
|---|---|---|
| `MachinePolicy` or `UserPolicy` is `AllSigned` or `Restricted` | IT has set a script policy that overrides the audit's `-ExecutionPolicy Bypass`. The audit's checks cannot run. | **Stop.** Send the preflight output; it is useful data on its own. (If you run anyway, the audit now says `AUDIT NOT PERFORMED` and exits 1. It no longer reports CLEAN for checks that never ran.) |
| Language mode is not `FullLanguage` | AppLocker or WDAC has locked PowerShell down. | **Stop**, same as above. |
| `DomainJoined : YES`, `AzureAdJoined : YES` or `EnterpriseJoined : YES` | A managed machine. | The IT warning above applies. Go ahead only with their permission. |
| An antivirus other than Microsoft Defender is listed | A third-party security product is installed. | Expect Defender to read "passive mode" in the report. That is normal, not a finding. On a work machine, see the IT warning. |
| `PowerShell 5.1...` | Normal for Windows 10 and 11. | Go on. |
| A line with `S-1-16-12288` | This window is elevated. | Fine either way; see Step 4. |

If the policy lines read `Undefined`, `RemoteSigned`, `Unrestricted` or
`Bypass`, and the language mode is `FullLanguage`: **go.**

## Step 4: run the audit (about 3 to 6 minutes each)

**If you have admin rights on that machine,** run it twice. First as
administrator: Start menu, type `powershell`, right-click, **Run as
administrator**, then (way A, from the stick):

```
New-Item -ItemType Directory -Force C:\SecurityAudit | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File E:\doze_sec\tests\field_test.ps1 | Tee-Object -FilePath C:\SecurityAudit\field_test_console.txt
```

Then in a **normal** PowerShell window:

```
New-Item -ItemType Directory -Force $env:USERPROFILE\SecurityAudit | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File E:\doze_sec\tests\field_test.ps1 | Tee-Object -FilePath $env:USERPROFILE\SecurityAudit\field_test_console.txt
```

For way B, replace `E:\doze_sec` with `$env:USERPROFILE\Documents\doze_sec`.

**If you do not have admin rights,** the normal run alone is still worth
doing. Checks that need admin are marked `[DEFERRED - ADMIN REQUIRED]`.

`New-Item` creates the audit's own output folder (the audit would create it
anyway), and `Tee-Object` saves what field_test prints there, so everything
ends up in one place. The `-ExecutionPolicy Bypass` affects only
that one PowerShell process; it changes no setting on the machine. You can keep
using the machine while it runs. A write-protected stick is fine: the audit
never writes into its own folder.

field_test ends with one of:

- `OK: read-only run verified...`: everything worked.
- `FAIL: ... AUDIT NOT PERFORMED`: PowerShell would not run the audit's
  helper scripts on this machine, so nothing was audited. **Stop there and do
  not try to work around it** (for example by copying the tool somewhere else
  to dodge a policy on removable drives): it is the PC owner's or IT's control.
  Send the console output; the reason is in it.
- Any other `FAIL`: send everything; that is a bug in the tool.

## Step 5: bring the results back

Copy these folders onto the USB stick, for example into `E:\results\<PC name>\`:

- `C:\SecurityAudit` (from the administrator run)
- `C:\Users\<name>\SecurityAudit` (from the normal run)

They hold the reports (`.txt` and `.html`), the `.ledger` files, the `.sha256`
digests, the console logs, the `Remediation_*.ps1` scripts (**unrun**) and
`field_test_console.txt`.

## Step 6: clean up the second machine

Delete whichever of these exist:

- `C:\SecurityAudit`
- `C:\Users\<name>\SecurityAudit`
- `C:\Users\<name>\Documents\doze_sec` (way B only)

Nothing else changed. field_test's `== Read-only proof ==` lines say so for
the RunOnce key, the boot configuration and the restore points.

## Step 7: back home

- Before anything else, check the stick on your laptop:

  ```
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\make_usb_stick.ps1 -Drive E: -Verify
  ```

  It compares `E:\doze_sec` with the manifest kept on your laptop -- never the
  copy on the stick, which the visited PC could have rewritten -- and lists any
  file changed, added or removed, plus anything new at the stick's root that
  could run (`autorun.inf`, shortcuts, programs). **A changed tool file means
  the PC you visited changed it: report it, do not run that copy again, and
  keep that stick exactly as it is -- it is evidence.** Use a new stick for the
  next PC. If nothing changed, `-Drive E: -Refresh` makes a fresh copy.
- Read the `.txt` report first. The `.html` was written by the PC you were
  checking; if you suspect that PC, do not open its `.html` in your browser.
- **Never run anything from the stick on your own laptop** -- the remediation
  scripts are for the audited PC, and only after review.

## Why the stick is not bootable

Booting the PC from the stick would start a different Windows, and the audit
checks the Windows that is running, so it would describe the stick, not the PC.
Windows' own bootable stick (a recovery drive) does not include PowerShell, so
the audit could not start there anyway. **Do not boot the PC from the stick or
change its boot settings:** on a PC with BitLocker or device encryption that
can make it ask for the 48-digit recovery key at the next start, and without
the key you cannot get to any file on that PC again.

---

## What happens next

Before the results are opened, predictions for that machine are written down.
Then every finding is adjudicated in one of two ways:

- **real:** the remediation section of the report says what to do;
- **a benign look-alike the tool got wrong:** recorded in
  `tests\benign_corpus.txt` with a test, so it cannot come back.

Misses are reported first.
