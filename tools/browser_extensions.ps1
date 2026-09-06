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
param([switch]$SelfTest)

$ErrorActionPreference = 'SilentlyContinue'

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$psNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

$marker = Join-Path $env:TEMP 'dz_browserext_hit.txt'
if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force -EA SilentlyContinue }

$script:warnCount = 0
$script:okCount = 0
$script:skipCount = 0

# PROVENANCE IS PART OF THE GRADE, not just a reason string. A field report
# (2026-09-06) flagged four extensions on a clean machine: Adobe Acrobat and
# Keeper Password Manager, in Chrome, Edge and Brave. A password manager needs
# broad host access and native messaging -- that is how it fills forms and
# reaches its desktop app. A PDF tool needs native messaging for the same
# reason. Those permissions are the product, not a signal.
#
# The check already computed $nonStoreReason and then did not grade on it: a
# sideloaded extension and a Web Store extension with identical permissions
# produced the IDENTICAL [WARNING], differing only by one extra reason token.
#
# Worse, provenance itself was wrong. `from_webstore` is a CHROME Web Store
# field; an Edge Add-ons install carries Microsoft's CRX endpoint instead, so
# the owner's Edge copy of Keeper was reported "NOT from web store
# (sideloaded/dev/external)" while being a perfectly ordinary store install.
# update_url -- the field that actually answers this -- was never read, though
# it sits in the already-parsed manifest.
$storeUpdateUrlRx = 'clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase'

# Chromium Manifest::Location integer codes that mean "not from the Web Store"
# (external pref / external registry / unpacked / command-line). Declared HERE,
# beside the other constants and above the functions that read it -- it used to
# sit below them, so Get-ChromiumProvenance saw $null for it when called from
# anywhere but the main loop, and every external-pref install graded 'unknown'.
$nonStoreLocations = @(2,3,4,8,10)

# Permissions that stay a WARNING even for a Web Store extension. These are rare
# in legitimate extensions, and a malicious extension CAN be published to a
# store -- this is the case the provenance downgrade must not go quiet on.
$alwaysHighPerms = @('debugger','proxy','desktopCapture','tabCapture','pageCapture')
# Permissions a credential-stealer / interceptor specifically wants, and which
# legitimate extensions rarely need -> always worth a human look.
# nativeMessaging is in this list but NOT in $alwaysHighPerms: it is ubiquitous
# in legitimate store extensions that pair with a desktop application.
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
    'mfehgcgbbipciilhngfkfduckiieefnc',  # Edge built-in component
    'ahfgeienlihckogmohjhadlkjgocpleb',  # Chrome/Edge/Brave Web Store (component)
    'fignfifoniblkonapihmkfakmlgkbkcf',  # Google Network Speech
    'neajdppkdcdipfabeoofebfddakdcjhd',  # Google Network Speech (Edge variant)
    'dgiklkfkllikcanfonkcabmbdfmgleag',  # Edge Clipboard component
    'epdpgaljfdjmcemiaplofbiholoaepem',  # Edge Suppress Consent Prompt component
    'fikbjbembnmfhppjfnmfkahdhfohhjmg',  # Edge Media Internals Services component
    'jdiccldimpdaibmpdkjnbmckianbfold',  # Microsoft Voices (Edge)
    'mnojpmjdmbbfmejpflffifhffcmidifd'   # Brave built-in component
)

function Test-BroadHost {
    param($hosts)
    foreach ($h in @($hosts)) {
        foreach ($b in $broadHosts) { if ($h -eq $b) { return $true } }
    }
    return $false
}

function Get-ChromiumProvenance {
    # 'component' | 'store' | 'unpacked' | 'non-store' | 'unknown'.
    # Takes the already-deserialized settings + manifest objects, so a self-test
    # can drive it from a ConvertFrom-Json fixture with no filesystem at all.
    param($Ext, $Manifest, [bool]$DeveloperMode = $false)
    $loc = $null
    if ($null -ne $Ext -and $null -ne $Ext.location) { $loc = [int]$Ext.location }
    if ($loc -eq 5) { return 'component' }          # Manifest::COMPONENT
    if ($loc -eq 4) { return 'unpacked' }           # loaded unpacked (dev mode)

    # update_url is the definitive discriminator, and covers BOTH official
    # stores -- Google's CRX endpoint and Microsoft's Edge Add-ons endpoint.
    $uu = ''
    if ($null -ne $Manifest -and $null -ne $Manifest.update_url) { $uu = [string]$Manifest.update_url }
    if ($uu -match $storeUpdateUrlRx) { return 'store' }

    if ($null -ne $Ext -and $null -ne $Ext.from_webstore -and [bool]$Ext.from_webstore) { return 'store' }
    # 1 INTERNAL, 6 EXTERNAL_PREF_DOWNLOAD, 7/9 EXTERNAL_POLICY* are all
    # store-downloaded installs.
    if ($loc -eq 1 -or $loc -eq 6 -or $loc -eq 7 -or $loc -eq 9) { return 'store' }
    if ($null -ne $loc -and ($nonStoreLocations -contains $loc)) { return 'non-store' }
    if ($DeveloperMode -and $null -eq $uu) { return 'unknown' }
    # NOT 'store'. The old code defaulted from_webstore to $true when the field
    # was absent, so unknown provenance read as a store install -- it failed
    # OPEN. Unknown is graded with the risky half, the same rule as "a signature
    # that cannot be verified counts as unsigned" in proc_path_grade.ps1.
    return 'unknown'
}

function Get-FirefoxProvenance {
    # Firefox is the better-instrumented half: signedState is a direct AMO
    # signature oracle (2 = signed by AMO, 0 = missing, -1 = broken) and
    # sourceURI records where it came from. Neither signedState nor
    # installTelemetryInfo was read before.
    param($Addon)
    if ($null -eq $Addon) { return 'unknown' }
    $loc = [string]$Addon.location
    if ($loc -eq 'app-builtin' -or $loc -eq 'app-system-defaults' -or [bool]$Addon.isSystem) { return 'component' }
    if ($null -ne $Addon.signedState -and [int]$Addon.signedState -ge 2) { return 'store' }
    $src = [string]$Addon.sourceURI
    if ($src -match 'mozilla\.org') { return 'store' }
    $tel = ''
    if ($Addon.installTelemetryInfo -and $Addon.installTelemetryInfo.source) { $tel = [string]$Addon.installTelemetryInfo.source }
    if ($tel -eq 'amo' -or $tel -eq 'about:addons') { return 'store' }
    if ($tel -eq 'sideload' -or [bool]$Addon.foreignInstall) { return 'non-store' }
    if ($loc -eq 'app-profile' -and [string]::IsNullOrEmpty($src)) { return 'non-store' }
    return 'unknown'
}

function Get-ExtensionVerdict {
    # Pure: returns @{ Tag = 'OK'|'INFO'|'WARNING'; Provenance; Reasons = @() }.
    # Shaped like Get-ClsidVerdict (com_clsid_check.ps1) and Get-ServiceVerdict
    # (service_signature_check.ps1) so a self-test can assert on it -- the old
    # Emit-Extension wrote strings and mutated a counter, so nothing could.
    param($Id, $Provenance, $Perms, $Hosts)
    if ($builtinIds -contains $Id -or $Provenance -eq 'component') {
        return @{ Tag = 'OK'; Provenance = 'component'; Reasons = @('vendor built-in component') }
    }
    $high      = @($Perms | Where-Object { $highRiskPerms   -contains $_ })
    $alwaysHi  = @($Perms | Where-Object { $alwaysHighPerms -contains $_ })
    $notable   = @($Perms | Where-Object { $notablePerms    -contains $_ })
    $broad     = Test-BroadHost $Hosts

    $reasons = @()
    if ($high.Count -gt 0) { $reasons += ('malware-favored perms: ' + ($high -join ',')) }
    if ($broad -and $notable.Count -gt 0) { $reasons += ('broad host access + ' + ($notable -join ',')) }

    $fromStore = ($Provenance -eq 'store')
    if (-not $fromStore -and $Provenance -ne 'unknown') {
        $reasons = @("origin: $Provenance") + $reasons
    } elseif ($Provenance -eq 'unknown') {
        $reasons = @('origin: could not be determined') + $reasons
    }

    if ($reasons.Count -eq 0) { return @{ Tag = 'OK'; Provenance = $Provenance; Reasons = @() } }

    # A store install with only the ordinary power-user permissions is
    # INVENTORY. The permissions are still named so a reader can adjudicate.
    if ($fromStore -and $alwaysHi.Count -eq 0) {
        return @{ Tag = 'INFO'; Provenance = $Provenance; Reasons = $reasons }
    }
    # Everything else keeps the WARNING: a store extension holding debugger /
    # proxy / a capture permission, and anything not provably from a store.
    if ($alwaysHi.Count -gt 0) { $reasons = @('high-risk perms: ' + ($alwaysHi -join ',')) + $reasons }
    if ($high.Count -eq 0 -and -not ($broad -and $notable.Count -gt 0)) {
        # Non-store origin with no risky capability at all -> context, as before.
        return @{ Tag = 'INFO'; Provenance = $Provenance; Reasons = @($reasons[0] + ' (no risky capability)') }
    }
    return @{ Tag = 'WARNING'; Provenance = $Provenance; Reasons = $reasons }
}

function Emit-Extension {
    param($tag, $name, $ver, $id, $provenance, $perms, $hosts)
    $v = Get-ExtensionVerdict -Id $id -Provenance $provenance -Perms $perms -Hosts $hosts
    switch ($v.Tag) {
        'WARNING' {
            $script:warnCount++
            Write-Output ("[WARNING] $tag  $name v$ver ($id)")
            Write-Output ('            -> ' + ($v.Reasons -join '; '))
        }
        'INFO' {
            $script:okCount++
            Write-Output ("[INFO] $tag  $name v$ver ($id)")
            Write-Output ('            -> ' + ($v.Reasons -join '; ') + ' -- installed from an official store, so these are the extension doing its job. Context, not a finding.')
        }
        default {
            $script:okCount++
            if ($v.Reasons.Count -gt 0 -and $v.Reasons[0] -eq 'vendor built-in component') {
                Write-Output ("[OK] $tag  $name v$ver ($id)  [vendor built-in component]")
            } else {
                $ctx = @()
                if (Test-BroadHost $hosts) { $ctx += 'all-URLs' }
                $n = @($perms | Where-Object { $notablePerms -contains $_ })
                if ($n.Count -gt 0) { $ctx += ($n -join ',') }
                if ($ctx.Count -gt 0) { Write-Output ("[OK] $tag  $name v$ver ($id)  [" + ($ctx -join '; ') + ']') }
                else { Write-Output ("[OK] $tag  $name v$ver ($id)") }
            }
        }
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function J { param([string]$Text) return ($Text | ConvertFrom-Json) }
    $storeUrl = 'https://clients2.google.com/service/update2/crx'
    $edgeUrl  = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx'

    # ---- provenance, from real Preferences shapes -------------------------
    $e = J '{"location":1,"from_webstore":true}'
    $m = J ('{"update_url":"' + $storeUrl + '"}')
    T 'a Chrome Web Store install is store provenance' `
      ((Get-ChromiumProvenance -Ext $e -Manifest $m) -eq 'store') (Get-ChromiumProvenance -Ext $e -Manifest $m)

    # THE OWNER'S EDGE KEEPER: Edge Add-ons install, from_webstore false because
    # that field means the CHROME store. Was reported "sideloaded/dev/external".
    $e = J '{"location":1,"from_webstore":false}'
    $m = J ('{"update_url":"' + $edgeUrl + '"}')
    T 'an Edge Add-ons install is store provenance, not sideloaded' `
      ((Get-ChromiumProvenance -Ext $e -Manifest $m) -eq 'store') (Get-ChromiumProvenance -Ext $e -Manifest $m)

    # Pin the update_url read itself: no location, no from_webstore, nothing to
    # fall back on. Without reading update_url this is 'unknown' and the
    # extension is graded with the risky half.
    T 'a store update_url alone establishes store provenance (Google)' `
      ((Get-ChromiumProvenance -Ext (J '{}') -Manifest (J ('{"update_url":"' + $storeUrl + '"}'))) -eq 'store') `
      (Get-ChromiumProvenance -Ext (J '{}') -Manifest (J ('{"update_url":"' + $storeUrl + '"}')))
    T 'a store update_url alone establishes store provenance (Edge Add-ons)' `
      ((Get-ChromiumProvenance -Ext (J '{}') -Manifest (J ('{"update_url":"' + $edgeUrl + '"}'))) -eq 'store') `
      (Get-ChromiumProvenance -Ext (J '{}') -Manifest (J ('{"update_url":"' + $edgeUrl + '"}')))
    # ...and a NON-official update_url must not.
    T 'a third-party update_url does NOT establish store provenance' `
      ((Get-ChromiumProvenance -Ext (J '{}') -Manifest (J '{"update_url":"https://evil.example/crx"}')) -eq 'unknown') `
      (Get-ChromiumProvenance -Ext (J '{}') -Manifest (J '{"update_url":"https://evil.example/crx"}'))

    $e = J '{"location":4}'
    T 'location 4 is an unpacked (dev-mode) load' `
      ((Get-ChromiumProvenance -Ext $e -Manifest (J '{}')) -eq 'unpacked') (Get-ChromiumProvenance -Ext $e -Manifest (J '{}'))
    $e = J '{"location":5}'
    T 'location 5 is a vendor component, without needing the hardcoded ID list' `
      ((Get-ChromiumProvenance -Ext $e -Manifest (J '{}')) -eq 'component') (Get-ChromiumProvenance -Ext $e -Manifest (J '{}'))
    $e = J '{"location":2}'
    T 'an external-pref install is non-store' `
      ((Get-ChromiumProvenance -Ext $e -Manifest (J '{}')) -eq 'non-store') (Get-ChromiumProvenance -Ext $e -Manifest (J '{}'))
    # The old code defaulted this to store -- it failed OPEN.
    T 'absent provenance fields are UNKNOWN, not store' `
      ((Get-ChromiumProvenance -Ext (J '{}') -Manifest (J '{}')) -eq 'unknown') (Get-ChromiumProvenance -Ext (J '{}') -Manifest (J '{}'))

    # ---- the owner's four flagged extensions ------------------------------
    $acrobat = @('nativeMessaging','webRequest','cookies','declarativeNetRequest')
    $keeper  = @('declarativeNetRequestWithHostAccess','webRequest','privacy')
    $all     = @('<all_urls>')

    $v = Get-ExtensionVerdict -Id 'efaidnbmnnnibpcajpcglclefindmkaj' -Provenance 'store' -Perms $acrobat -Hosts $all
    T 'Adobe Acrobat from the store is context, not a finding' `
      ($v.Tag -eq 'INFO') "$($v.Tag): $($v.Reasons -join '; ')"
    $v = Get-ExtensionVerdict -Id 'bfogiafebfohielmmehodmfbbebbbpei' -Provenance 'store' -Perms $keeper -Hosts $all
    T 'Keeper from the store is context, not a finding' `
      ($v.Tag -eq 'INFO') "$($v.Tag): $($v.Reasons -join '; ')"

    # ---- ...and none of that may swallow a real one -----------------------
    $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'non-store' -Perms $acrobat -Hosts $all
    T 'the SAME permissions sideloaded are still a WARNING' `
      ($v.Tag -eq 'WARNING') "$($v.Tag): $($v.Reasons -join '; ')"
    $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'unpacked' -Perms $keeper -Hosts $all
    T 'an unpacked dev-mode load with those permissions is a WARNING' `
      ($v.Tag -eq 'WARNING') "$($v.Tag): $($v.Reasons -join '; ')"
    $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'unknown' -Perms $keeper -Hosts $all
    T 'UNKNOWN provenance is graded with the risky half' `
      ($v.Tag -eq 'WARNING') "$($v.Tag): $($v.Reasons -join '; ')"

    # A store extension CAN be malicious, so the sharpest permissions keep
    # their WARNING even from a store.
    foreach ($p in @('debugger','proxy','desktopCapture','tabCapture','pageCapture')) {
        $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'store' -Perms @($p) -Hosts @()
        T "a store extension holding '$p' is still a WARNING" ($v.Tag -eq 'WARNING') "$($v.Tag)"
    }

    $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'store' -Perms @('storage') -Hosts @()
    T 'an ordinary store extension with no risky permission is OK' ($v.Tag -eq 'OK') "$($v.Tag)"
    $v = Get-ExtensionVerdict -Id 'zz' -Provenance 'non-store' -Perms @('storage') -Hosts @()
    T 'a sideloaded extension with no risky permission stays INFO' ($v.Tag -eq 'INFO') "$($v.Tag)"
    $v = Get-ExtensionVerdict -Id 'mhjfbmdgcfjbbpaeojofohoefgiehjai' -Provenance 'unknown' -Perms $acrobat -Hosts $all
    T 'a known vendor built-in ID is OK whatever it holds' ($v.Tag -eq 'OK') "$($v.Tag)"

    # ---- Firefox ----------------------------------------------------------
    T 'an AMO-signed add-on is store provenance' `
      ((Get-FirefoxProvenance -Addon (J '{"location":"app-profile","signedState":2}')) -eq 'store') ''
    T 'a profile add-on with no source is non-store' `
      ((Get-FirefoxProvenance -Addon (J '{"location":"app-profile","sourceURI":null}')) -eq 'non-store') ''
    T 'a Firefox system add-on is a component' `
      ((Get-FirefoxProvenance -Addon (J '{"location":"app-system-defaults"}')) -eq 'component') ''

    if ($fails) { Write-Output "[FAIL] $fails browser_extensions self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] browser_extensions self-test: store installs are graded on provenance, sideloaded and unknown are not downgraded, and debugger/proxy/capture stay findings anywhere.'
    exit 0
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
        # Profile-wide developer mode: an unpacked load is far likelier here.
        # Sits in the same already-parsed document and was never read.
        $devMode = $false
        if ($json.extensions -and $json.extensions.ui -and $null -ne $json.extensions.ui.developer_mode) {
            $devMode = [bool]$json.extensions.ui.developer_mode
        }
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

            $prov = Get-ChromiumProvenance -Ext $ext -Manifest $man -DeveloperMode $devMode
            Emit-Extension $tag $name $ver $id $prov $permWords $allHosts
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

            $prov = Get-FirefoxProvenance -Addon $a
            Emit-Extension $tag $name $ver $id $prov $perms $origins
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
        # Exact-name skip, not a '^PS' prefix match (see persistence_eval.ps1).
        if ($psNoteProps -contains $p.Name) { continue }
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
