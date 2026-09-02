# Recovery: if the machine will not unlock or log in after a harness run

`tests\detection_selftest.ps1` plants nine artifacts on the logon and
authentication path (credential provider, screensaver, Winlogon Notify
handler, LSA packages, network provider, logon script, AppInit/AppCert DLLs),
each pointing at a file that does not exist. Since #186 the runbook
(`tests\manual_ci.ps1`) skips all nine by default. This page exists because,
before that fix, a run locked the owner out of their own machine.

**If the screen is locked and Ctrl+Alt+Del does nothing, work down this list.
Stop as soon as you can log in.**

## 1. Force restart

Hold the power button for about ten seconds until the machine fully powers
off. Wait five seconds. Power on.

> Unclean shutdown: anything unsaved in open apps is lost. Nothing else is at
> risk — NTFS journals through it.

This is usually enough. The harness cleans up after itself, so the registry is
normally already clean and only the wedged LogonUI process needs clearing.

## 2. Safe Mode

Power on, then hold the power button the moment the manufacturer logo appears.
Do this three times in a row; on the third boot Windows enters recovery
("Preparing Automatic Repair").

**Troubleshoot → Advanced options → Startup Settings → Restart → press 4.**

Safe Mode loads a minimal set of components and generally bypasses
third-party credential providers, so the built-in password box comes back. If
you can log in here, skip to "Once you are back in".

## 3. Remove the planted keys offline

Same three-interrupted-boots route, then
**Troubleshoot → Advanced options → Command Prompt**.

If BitLocker is on, you will need the recovery key from your Microsoft
account or wherever it was backed up. Find the Windows drive first — in
recovery it is often `D:`, not `C:`:

```
dir C:\Windows
dir D:\Windows
```

Using whichever letter shows a real Windows folder (written as `D:` below):

```
reg load HKLM\OFFSW D:\Windows\System32\config\SOFTWARE
reg delete "HKLM\OFFSW\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{deadbeef-0000-0000-0000-00000000d123}" /f
reg delete "HKLM\OFFSW\Classes\CLSID\{deadbeef-0000-0000-0000-00000000d123}" /f
reg delete "HKLM\OFFSW\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\dz_selftest_evil" /f
reg add "HKLM\OFFSW\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "" /f
reg unload HKLM\OFFSW
exit
```

> "The system was unable to find the specified registry key" on a `reg delete`
> line is expected and fine — it means that key was already cleaned up. Only
> `reg load` failing is a real problem.
>
> Type these exactly. Deleting other keys in that hive can make Windows
> unbootable. Do not improvise here.

The LSA packages live in the SYSTEM hive and are removed by name from a
multi-string value, which is awkward from a recovery prompt; if steps 1–3 have
not worked, step 4 is the safer route.

## 4. System Restore

Same recovery menu → **Troubleshoot → Advanced options → System Restore**,
choose a point from before the harness run.

> Rolls back system settings and recently installed programs, including any
> security hardening applied since that point. Documents are untouched.

## Once you are back in

Run the standalone teardown in an elevated PowerShell. It removes only
marker-tagged test artifacts, is safe to run any number of times, and reports
every item as REMOVED or ABSENT:

```powershell
cd <repo>
.\tests\cleanup_selftest.ps1
```

Then confirm nothing remains on the logon path:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' | Select-Object PSChildName
Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -EA SilentlyContinue
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -EA SilentlyContinue
```

No `{deadbeef-…}` in the first, and nothing pointing at `C:\Users\Public\` in
the other two, means the machine is clean.

## Do not run the plant harness on a machine you cannot afford to hard-reset

`manual_ci.ps1` is safe by default, but it still briefly enables the guest
account, turns on WDigest, opens a portproxy, and plants IFEO hijacks. None of
those can lock you out, but the machine is briefly less hardened. Prefer a
throwaway VM or CI. Never pass `-AllowLockScreenRisk` on a machine you are
sitting at.


For the machine you are sitting at, use `tests\field_test.ps1` instead: it
runs the audit with `-readonly` (no change outside the output folder and the
temp folder, no network connections), proves that before and after, and hands
you every finding to adjudicate. It plants nothing and cannot lock you out.