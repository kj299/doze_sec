update to include these types of things. 

optional Create System Restore point: Create a pre-run system restore point. Vista and up only, client OS's only. Not supported on Server OS's, and on Windows 10 does not work if the system is in any form of Safe Mode. This is a known bug, and I spent hours trying to find a workaround but was not able to find a solution, so if you absolutely require a system restore point, recommend running in normal mode

Detect TEMP execution: Detect if we're running from the TEMP directory and prevent doze_sec from executing if so. TEMP is one of the first places to get wiped when doze_sec starts so we cannot run from there

Make log directories: Create the master log directory and sub-directories if they don't exist. By default this is %SystemDrive%\Logs\doze_sec.log

Detect Windows & IE versions: Determines quite a few things in the script, such as which versions of various commands get executed

Unsupported OS blocker: Throw an alert message if running on an unsupported OS, then exit. Use the -dev switch to override this behavior and allow running on unsupported Windows versions. Currently only triggers on Windows Server 2016.

Disk configuration check: Check if the system drive is an SSD, Virtual Disk, or throws an unspecified error (couldn't be read by smartctl.exe) and set the SKIP_DEFRAG variable to yes_ssd, yes_vm, or yes_error respectively. If any of these conditions are triggered, doze_sec skips Stage 5 defrag automatically

Detect free space: Detect and save available hard drive space to compare against later. Simply used to show how much space was reclaimed; does not affect any script functions

Detect resume: Detect whether or not we're resuming after an interrupted run (e.g. from a reboot)

Enable F8 Safe Mode selection: Re-enable the ability to use the F8 key on bootup (Windows 8 and up only; enabled by default on Server 2012/2012 R2)

Check for network connection: Check for an active network connection, and skip the update checks if one isn't found

Check for update: Compare the local copy of doze_sec to the version on the official repo (does this by reading latest version number from sha256sums.txt). If the local copy is out of date, doze_sec will ask to automatically download the latest copy (always recommended). If permitted, it will download a copy to the desktop, verify the SHA256 hash, then self-destruct (delete) the old version

Update debloat lists: Connect to Github and download the latest version of the Stage 2 debloat lists at initial launch. Use the -sdu (SKIP_DEBLOAT_UPDATE) switch to prevent this behavior. I recommend letting doze_sec update the lists unless you have a good, specific reason not to

Detect Administrator rights: Detect whether or not we're running as Administrator and alert the user if we're not

Create RunOnce entry: Create the following registry key to support resuming if there is an interruption: HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v "*doze_sec_resume" /t REG_SZ /d "%~dp0doze_sec.bat %-resume". The * prefix on the key name forces Windows to execute it in Safe Mode.

SMART check: Dump the SMART status of all hard disks in the system, then display an alert if any drive reports one of the following status codes: Error,Degraded,Unknown,PredFail,Service,Stressed,NonRecover

add error codes
When doze_sec exits, it will pass an exit code indicating the final status (success/warning/error/failure/etc).

CODE	MEANING
0	Success
1	Error (usually fatal)
2	Warning (non-fatal)
3	Unsupported OS (run with -dev to override)
4	Exit pending reboot
5	User is an idiot (aka you tried running from the temp directory in spite of the instructions clearly saying not to)