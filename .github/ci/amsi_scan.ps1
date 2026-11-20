# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# Asks Windows' own AMSI scanner (the one that blocked tools\event_scan_check.ps1
# as a Trojan on a real PC) to scan every PowerShell file this repository
# ships. It may switch Defender's real-time protection ON for the scan and
# puts it back as it found it in finally. It lives in .github/ so it never
# reaches a USB stick.
#
# A scanner that is off detects nothing, so a clean result means something
# only when the scanner is shown to work first: Microsoft's documented AMSI
# test sample must come back detected. If it does not, the step is a declared
# [ SKIP ] with the measured result, never a pass. The AMSI names below are
# assembled for the reason tools\lint_amsi_text.ps1 gives.
$ErrorActionPreference = 'Stop'
$w = 'Am' + 'si'
$src = @"
using System;
using System.Runtime.InteropServices;
public static class DzAmsiScan {
    [DllImport("$($w.ToLower()).dll", EntryPoint = "$($w)Initialize", CharSet = CharSet.Unicode)]
    public static extern int Init(string appName, out IntPtr context);
    [DllImport("$($w.ToLower()).dll", EntryPoint = "$($w)Scan" + "String", CharSet = CharSet.Unicode)]
    public static extern int Scan(IntPtr context, string text, string contentName, IntPtr session, out int result);
    [DllImport("$($w.ToLower()).dll", EntryPoint = "$($w)Uninitialize")]
    public static extern void Uninit(IntPtr context);
}
"@
Add-Type -TypeDefinition $src

$rtBefore = $null
$rtChanged = $false
try {
    try { $rtBefore = [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { Write-Host ("MEASURED: Get-MpComputerStatus did not answer: {0}" -f $_.Exception.Message) }
    Write-Host ("MEASURED: Defender real-time protection before the scan: {0}" -f $rtBefore)
    if ($rtBefore -eq $false) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            $rtChanged = $true
            Start-Sleep -Seconds 5
            Write-Host ("MEASURED: real-time protection after asking for it: {0}" -f [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled)
        } catch { Write-Host ("MEASURED: real-time protection could not be switched on here: {0}" -f $_.Exception.Message) }
    }

    $ctx = [IntPtr]::Zero
    $hr = [DzAmsiScan]::Init('doze_sec_ci', [ref]$ctx)
    if ($hr -ne 0) { Write-Host ("[ SKIP ] the AMSI scanner could not be opened on this runner (HRESULT 0x{0:X8}); the text rule in lint.yml still holds" -f $hr); exit 0 }
    try {
        # Microsoft's documented AMSI test sample (the AMSI equivalent of EICAR).
        $sample = 'AMSI Test ' + 'Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
        $r = 0
        $hr = [DzAmsiScan]::Scan($ctx, $sample, 'dz_test_sample', [IntPtr]::Zero, [ref]$r)
        Write-Host ("MEASURED: the AMSI test sample scanned with HRESULT 0x{0:X8}, result {1} (32768 or more is detected)" -f $hr, $r)
        if ($hr -ne 0 -or $r -lt 32768) {
            Write-Host '[ SKIP ] the AMSI provider on this runner does not detect even its own test sample, so a clean scan here would prove nothing; the text rule in lint.yml still holds'
            exit 0
        }
        $files = @(Get-ChildItem tools\*.ps1, tests\*.ps1, .github\ci\*.ps1 -File)
        if ($files.Count -lt 50) { throw ("only {0} PowerShell file(s) found to scan" -f $files.Count) }
        $hits = @()
        foreach ($f in $files) {
            $text = [IO.File]::ReadAllText($f.FullName)
            $r = 0
            $hr = [DzAmsiScan]::Scan($ctx, $text, $f.FullName, [IntPtr]::Zero, [ref]$r)
            if ($hr -ne 0) { throw ("the AMSI scan of {0} failed with HRESULT 0x{1:X8}" -f $f.Name, $hr) }
            if ($r -ge 32768) { $hits += ("{0} (result {1})" -f $f.FullName, $r) }
        }
        if ($hits.Count) {
            $hits | ForEach-Object { Write-Host ("::error::Defender's AMSI scanner reads this file as malicious, so PowerShell will refuse to run it on every PC with real-time protection on: {0}" -f $_) }
            throw ("{0} file(s) read as malicious by AMSI" -f $hits.Count)
        }
        Write-Host ("AMSI: the scanner detected its own test sample, and none of the {0} PowerShell files this repository ships" -f $files.Count)
    } finally { [DzAmsiScan]::Uninit($ctx) }
} finally {
    if ($rtChanged) {
        try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; Write-Host 'Defender real-time protection put back to off, as the runner had it' }
        catch { Write-Host ("::warning::could not put real-time protection back to off: {0}" -f $_.Exception.Message) }
    }
}
exit 0
