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
three folders.

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

## Step 1: copy the tool onto a USB stick (on your own laptop)

The repository is private, and the other machine needs neither git nor a
GitHub login. Copy the folder, leaving out `.git`:

```
robocopy C:\path\to\doze_sec E:\doze_sec /E /XD .git
```

Replace `E:` with your USB stick's drive letter. You can also copy the folder
in File Explorer; `.git` is hidden and not needed. **The whole folder is
needed:** the audit stops with `tools\exec_probe.ps1 is missing` if `tools\`,
`tests\` or `ThreatLists\` did not come across.

## Step 2: copy it onto the second machine

Copy `E:\doze_sec` to `Documents\doze_sec`, i.e.
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
administrator**, then:

```
cd $env:USERPROFILE\Documents\doze_sec
New-Item -ItemType Directory -Force C:\SecurityAudit | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File tests\field_test.ps1 | Tee-Object -FilePath C:\SecurityAudit\field_test_console.txt
```

Then in a **normal** PowerShell window:

```
cd $env:USERPROFILE\Documents\doze_sec
New-Item -ItemType Directory -Force $env:USERPROFILE\SecurityAudit | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File tests\field_test.ps1 | Tee-Object -FilePath $env:USERPROFILE\SecurityAudit\field_test_console.txt
```

**If you do not have admin rights,** the normal run alone is still worth
doing. Checks that need admin are marked `[DEFERRED - ADMIN REQUIRED]`.

`New-Item` creates the audit's own output folder (the audit would create it
anyway), and `Tee-Object` saves what field_test prints there, so everything
ends up in one place. The `-ExecutionPolicy Bypass` affects only
that one PowerShell process; it changes no setting on the machine. You can keep
using the machine while it runs.

field_test ends with one of:

- `OK: read-only run verified...`: everything worked.
- `FAIL: ... AUDIT NOT PERFORMED`: PowerShell would not run the audit's
  helper scripts on this machine, so nothing was audited. Send the console
  output; the reason is in it.
- Any other `FAIL`: send everything; that is a bug in the tool.

## Step 5: bring the results back

Copy these folders onto the USB stick:

- `C:\SecurityAudit` (from the administrator run)
- `C:\Users\<name>\SecurityAudit` (from the normal run)

They hold the reports (`.txt` and `.html`), the `.ledger` files, the `.sha256`
digests, the `Remediation_*.ps1` scripts (**unrun**) and
`field_test_console.txt`.

## Step 6: clean up the second machine

Delete:

- `C:\Users\<name>\Documents\doze_sec`
- `C:\SecurityAudit`
- `C:\Users\<name>\SecurityAudit`

Nothing else changed. field_test's `== Read-only proof ==` lines say so for
the RunOnce key, the boot configuration and the restore points.

---

## What happens next

Before the results are opened, predictions for that machine are written down.
Then every finding is adjudicated in one of two ways:

- **real:** the remediation section of the report says what to do;
- **a benign look-alike the tool got wrong:** recorded in
  `tests\benign_corpus.txt` with a test, so it cannot come back.

Misses are reported first.
