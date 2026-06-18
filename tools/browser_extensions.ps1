# ============================================================================
# browser_extensions.ps1 -- inventory installed browser extensions (MITRE
# T1176, Browser Extensions) for the CURRENT user across Chromium-family
# browsers (Chrome, Edge, Brave, Vivaldi) and Firefox.
#
# WHY: a malicious or over-privileged browser extension is a quiet
# credential-theft / session-hijack / traffic-interception foothold that
# survives reboots and rides inside a trusted process. doze_sec audited the
# browser credential STORE access time (Section 18) but never enumerated the
# extensions themselves.
#
# WHAT IT FLAGS ([WARNING]) -- tuned to avoid alarming on normal extensions:
#   - sideloaded / developer-mode / non-store extensions (Chromium
#     from_webstore=false or a non-store Location code; Firefox sourceURI
#     missing on a user-profile add-on) -- the classic malware path
#   - malware-favored permissions: nativeMessaging, debugger, proxy,
#     desktopCapture, tabCapture, pageCapture
#   - broad host access (<all_urls> / *://*/*) COMBINED with an interception
#     permission (webRequest(+Blocking), declarativeNetRequest, cookies,
#     management, clipboardRead) -- broad host access ALONE is common and
#     legitimate (ad blockers, password managers) so it is only [INFO]
#   - policy force-installed entries (ExtensionInstallForcelist) under HKLM/HKCU
# Store extensions with notable-but-common perms or broad host alone are listed
# at [OK] with the perms noted in brackets. A profile whose data cannot be read
# (locked DB, corrupt JSON, access denied) is reported [SKIPPED] -- never a
# silent clean.
#
# COMPATIBILITY: Windows PowerShell 5.1 (built into Win10/11). Read-only.
# No pwsh-only syntax, no external tools, no admin required (own profile).
#
# OUTPUT: human-readable lines to stdout. Creates a marker file
# %TEMP%\dz_browserext_hit.txt when at least one [WARNING] is emitted, so the
# caller (doze_sec.bat / doze_sec_noAdmin.bat) can fold it into the section
# verdict the same way the Section 18 IOC sub-checks do.
# ============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

$marker = Join-Path $env:TEMP 'dz_browserext_hit.txt'
if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force -EA SilentlyContinue }

$script:warnCount = 0
$script:okCount = 0
$script:skipCount = 0

# Permissions a credential-stealer / interceptor specifically wants, and which
# legitimate extensions rarely need -> always worth a human look.
$highRiskPerms = @('nativeMessaging','debugger','proxy','desktopCapture','tabCapture','pageCapture')
# Powerful but common in legitimate extensions -> only a [WARNING] when paired
# with broad host access (the traffic/credential interception pattern).
$notablePerms  = @('webRequest','webRequestBlocking','declarativeNetRequest',
                   'declarativeNetRequestWithHostAccess','cookies','management','clipboardRead','privacy')
$broadHosts = @('<all_urls>','*://*/*','http://*/*','https://*/*','*://*')

# Vendor built-in component extensions (shipped inside Microsoft Edge / Google
# Chrome). They are "not from the web store" BY DESIGN, so the non-store signal
# alone flags every one of them and floods the report. These fixed, documented
# IDs are trusted built-ins -> never flagged.
$builtinIds = @(
    'mhjfbmdgcfjbbpaeojofohoefgiehjai',  # Edge/Chrome built-in PDF Viewer
    'nkeimhogjdpnpccoofpliimaahmaaome',  # Microsoft Edge built-in component
    'ncbjelpjchkpbikbpkcchkhkblodoama',  # Edge WebRTC internals component
    'ndcpkimcihhghdcddljkfmmjccdmcmof',  # Edge Copilot Bridge
    'ihmafllikibpmigkcoadcmckbfhibefp',  # Edge Feedback
    'iglcjdemknebjbklcgkfaebgojjphkec',  # Microsoft Store (Edge)
    'jmjflgjpcpepeafmmgdpfkogkghcpiha',  # Edge built-in component
    'nmmhkkegccagdldgiimedpiccmgmieda',  # Google Chrome built-in (payments)
    'mfehgcgbbipciilhngfkfduckiieefnc'   # Edge built-in component
)

function Test-BroadHost {
    param($hosts)
    foreach ($h in @($hosts)) {
        foreach ($b in $broadHosts) { if ($h -eq $b) { return $true } }
    }
    return $false
}

function Emit-Extension {
    param($tag, $name, $ver, $id, $nonStoreReason, $perms, $hosts)
    # Trusted vendor built-in (Edge/Chrome component) -> never flag.
    if ($builtinIds -contains $id) {
        $script:okCount++
        Write-Output ("[OK] $tag  $name v$ver ($id)  [vendor built-in component]")
        return
    }
    $high    = @($perms | Where-Object { $highRiskPerms -contains $_ })
    $notable = @($perms | Where-Object { $notablePerms  -contains $_ })
    $broad   = Test-BroadHost $hosts

    # A non-store / sideloaded origin alone is noteworthy but NOT alarming --
    # browsers ship many non-store built-ins, so flagging on that signal alone
    # floods the report. Escalate to [WARNING] only when the extension also
    # wields a malware-favored capability, or broad host access paired with an
    # interception permission. A lone non-store origin is surfaced at [INFO].
    $warnReasons = @()
    if ($high.Count -gt 0) { $warnReasons += ('malware-favored perms: ' + ($high -join ',')) }
    if ($broad -and $notable.Count -gt 0) { $warnReasons += ('broad host access + ' + ($notable -join ',')) }

    if ($warnReasons.Count -gt 0) {
        if ($nonStoreReason) { $warnReasons = @($nonStoreReason) + $warnReasons }
        $script:warnCount++
        Write-Output ("[WARNING] $tag  $name v$ver ($id)")
        Write-Output ('            -> ' + ($warnReasons -join '; '))
    } elseif ($nonStoreReason) {
        $script:okCount++
        Write-Output ("[INFO] $tag  $name v$ver ($id)  -> $nonStoreReason (no risky capability)")
    } else {
        $script:okCount++
        $ctx = @()
        if ($broad) { $ctx += 'all-URLs' }
        if ($notable.Count -gt 0) { $ctx += ($notable -join ',') }
        if ($ctx.Count -gt 0) { Write-Output ("[OK] $tag  $name v$ver ($id)  [" + ($ctx -join '; ') + ']') }
        else { Write-Output ("[OK] $tag  $name v$ver ($id)") }
    }
}

# -------------------------------------------------------------------------
# Chromium family
# -------------------------------------------------------------------------
$chromiumBrowsers = @(
    @{ Name = 'Chrome';  Base = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
    @{ Name = 'Edge';    Base = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
    @{ Name = 'Brave';   Base = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') },
    @{ Name = 'Vivaldi'; Base = (Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data') }
)

# Chromium Manifest::Location integer codes that mean "not from the Web Store"
# (external pref / external registry / unpacked / command-line). from_webstore
# is the primary signal; this is a backstop for tampered/older profiles.
$nonStoreLocations = @(2,3,4,8,10)

foreach ($b in $chromiumBrowsers) {
    if (-not (Test-Path -LiteralPath $b.Base)) { continue }
    $profiles = @(Get-ChildItem -LiteralPath $b.Base -Directory -EA SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
    foreach ($prof in $profiles) {
        $tag = "$($b.Name)/$($prof.Name)"
        $prefFile = $null
        foreach ($cand in 'Secure Preferences','Preferences') {
            $p = Join-Path $prof.FullName $cand
            if (Test-Path -LiteralPath $p) { $prefFile = $p; break }
        }
        if (-not $prefFile) { continue }
        try {
            $json = Get-Content -LiteralPath $prefFile -Raw -EA Stop | ConvertFrom-Json -EA Stop
        } catch {
            Write-Output "[SKIPPED] $tag -- could not parse preferences (locked or corrupt); extension inventory NOT performed."
            $script:skipCount++
            continue
        }
        $settings = $null
        if ($json.extensions -and $json.extensions.settings) { $settings = $json.extensions.settings }
        if (-not $settings) { Write-Output "[INFO] $tag -- no extensions registered."; continue }
        foreach ($prop in $settings.PSObject.Properties) {
            $id = $prop.Name
            $ext = $prop.Value
            $man = $ext.manifest
            if (-not $man) { continue }   # built-in component/theme with no manifest
            $name = if ($man.name) { [string]$man.name } else { '(unnamed)' }
            $ver = [string]$man.version
            $perms = @()
            if ($man.permissions) { $perms += @($man.permissions) }
            if ($man.optional_permissions) { $perms += @($man.optional_permissions) }
            $hostPerms = @()
            if ($man.host_permissions) { $hostPerms += @($man.host_permissions) }
            # MV2 mixes host match patterns into "permissions"; split for clarity.
            $permWords = @($perms | Where-Object { $_ -is [string] -and $_ -notmatch '://' -and $_ -ne '<all_urls>' })
            $permHosts = @($perms | Where-Object { $_ -is [string] -and ($_ -match '://' -or $_ -eq '<all_urls>') })
            $allHosts = @($hostPerms + $permHosts)

            $fromStore = $true
            if ($null -ne $ext.from_webstore) { $fromStore = [bool]$ext.from_webstore }
            $loc = $ext.location
            $isNonStoreLoc = ($null -ne $loc) -and ($nonStoreLocations -contains [int]$loc)

            $nonStoreReason = $null
            if (-not $fromStore)     { $nonStoreReason = 'NOT from web store (sideloaded/dev/external)' }
            elseif ($isNonStoreLoc)  { $nonStoreReason = "install location code $loc (non-store)" }

            Emit-Extension $tag $name $ver $id $nonStoreReason $permWords $allHosts
        }
    }
}

# -------------------------------------------------------------------------
# Firefox
# -------------------------------------------------------------------------
$ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if (Test-Path -LiteralPath $ffRoot) {
    foreach ($prof in @(Get-ChildItem -LiteralPath $ffRoot -Directory -EA SilentlyContinue)) {
        $tag = "Firefox/$($prof.Name)"
        $extJson = Join-Path $prof.FullName 'extensions.json'
        if (-not (Test-Path -LiteralPath $extJson)) { continue }
        try {
            $json = Get-Content -LiteralPath $extJson -Raw -EA Stop | ConvertFrom-Json -EA Stop
        } catch {
            Write-Output "[SKIPPED] $tag -- could not parse extensions.json (locked or corrupt); extension inventory NOT performed."
            $script:skipCount++
            continue
        }
        if (-not $json.addons) { Write-Output "[INFO] $tag -- no add-ons registered."; continue }
        foreach ($a in @($json.addons)) {
            if ($a.type -and $a.type -ne 'extension') { continue }
            $name = if ($a.defaultLocale -and $a.defaultLocale.name) { [string]$a.defaultLocale.name } else { [string]$a.id }
            $ver = [string]$a.version
            $id = [string]$a.id
            $loc = [string]$a.location
            $src = [string]$a.sourceURI
            $perms = @()
            if ($a.userPermissions -and $a.userPermissions.permissions) { $perms += @($a.userPermissions.permissions) }
            $origins = @()
            if ($a.userPermissions -and $a.userPermissions.origins) { $origins += @($a.userPermissions.origins) }

            # A user-profile add-on with no addons.mozilla.org source URI was not
            # installed from the official gallery -> sideloaded / manually dropped.
            $sideloaded = ($loc -eq 'app-profile') -and ([string]::IsNullOrEmpty($src) -or ($src -notmatch 'mozilla\.org'))
            $nonStoreReason = $null
            if ($sideloaded) { $nonStoreReason = 'no AMO source (sideloaded/manual)' }

            Emit-Extension $tag $name $ver $id $nonStoreReason $perms $origins
        }
    }
}

# -------------------------------------------------------------------------
# Policy force-installed extensions (HKLM/HKCU ExtensionInstallForcelist)
# -------------------------------------------------------------------------
$forceKeys = @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist',
    'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
)
foreach ($k in $forceKeys) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    $vals = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
    if (-not $vals) { continue }
    foreach ($p in $vals.PSObject.Properties) {
        if ($p.Name -match '^PS') { continue }
        $script:warnCount++
        Write-Output ("[WARNING] Policy force-install ($k): " + [string]$p.Value)
    }
}

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
if (($script:warnCount + $script:okCount + $script:skipCount) -eq 0) {
    Write-Output '[INFO] No browser profiles with extensions found for the current user.'
} else {
    Write-Output ("[INFO] Browser extension inventory: $($script:okCount) OK, $($script:warnCount) flagged, $($script:skipCount) skipped.")
}
if ($script:warnCount -gt 0) {
    New-Item -Path $marker -ItemType File -Force | Out-Null
    Write-Output '[INFO] Review [WARNING] extensions: remove anything sideloaded or unrecognised via the browser Extensions page.'
}
