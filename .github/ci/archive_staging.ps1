# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   archive_staging.ps1 -SelfTest + the runner's real staging folders and planted archives (7-Zip when the image carries it)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$stSw = [Diagnostics.Stopwatch]::StartNew()
$out = (.\tools\archive_staging.ps1 -SelfTest) -join "`n"
Write-Host $out
if ($LASTEXITCODE -ne 0) { throw 'archive_staging self-test failed' }
# The LZMA cases run the header decoder on 5.1, the engine this ships
# to; its speed there is measured, not assumed.
Write-Host ('measured: archive_staging -SelfTest took {0:N1} s on Windows PowerShell 5.1' -f $stSw.Elapsed.TotalSeconds)
$n = @($out -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 180) { throw "archive_staging self-test ran only $n case(s)" }
if ($out -notmatch 'LZMA: a stream another encoder made decodes byte for byte') { throw 'the LZMA decoder case did not run on 5.1' }
if ($out -match '\[SKIP\]') { throw 'the real Compress-Archive case was skipped on Windows, where it must run' }

# THE RUNNER'S REAL STAGING FOLDERS, the benign twin at scale: its
# Temp and Downloads hold tool archives, installer caches and
# Office/MSIX packages. None may raise, nothing may be deferred on
# an elevated token, and the check must say what it covered.
$md = Join-Path $env:TEMP ("dz_as_live_{0}" -f $PID)
$live = (.\tools\archive_staging.ps1 -MarkerDir $md) -join "`n"
Write-Host $live
if ($live -match 'Exception|ParserError|is not recognized') { throw "archive_staging errored on the runner's folders: $live" }
foreach ($m in @('dz_archstage.txt', 'dz_archstage_gap.txt', 'dz_archstage_deferred.txt')) {
  if (Test-Path (Join-Path $md $m)) { throw ("{0} written on a clean runner: {1}" -f $m, (Get-Content (Join-Path $md $m))) }
}
# An all-clear, or -- only when a cap or the time budget is the stated
# reason -- the same sentence scoped to what was read. Never silence.
if ($live -notmatch '\[OK\] (\d+ archive\(s\) examined across|No archives in the) \d+ staging folder\(s\)|\[INFO\] (\d+ archive\(s\) examined across|No archives in the) \d+ staging folder\(s\)[^\r\n]*before [^\r\n]* stopped it') { throw "archive_staging printed no coverage verdict on the runner: $live" }
# One folder is one folder: the runner's %TEMP% is an 8.3 short path
# (RUNNER~1), and the first run of this step listed its Temp twice.
if ($live -match '~\d\\AppData\\Local\\Temp' -and $live -match 'runneradmin\\AppData\\Local\\Temp') { throw 'the same Temp folder was listed under its 8.3 short name AND its long name -- one folder read as two' }
Write-Host ('measured on this image: ' + (($live -split "`n" | Where-Object { $_ -match 'examined across|No archives in|plain archive\(s\)|package\(s\) that are ZIP|Mark of the Web|could not be determined|named like an archive|cabinet\(s\)|volume\(s\) of split|cloud-only|held open|holds more than|time budget|Not present' }) -join ' | '))
Remove-Item $md -Recurse -Force -EA SilentlyContinue

# PLANTS in the shared Public folder, each beside the twin that must
# stay quiet. The hand-built ones come from the published layouts
# and always run; the REAL ones are made by the image's own 7-Zip
# when it is there, and a declared [ SKIP ] when it is not. A plant
# is inert bytes: no archiver can open the RAR, the zips hold a line
# of text, nothing executes. Removed in finally; a leftover is
# correctly a finding on the next run, so the leak check throws.
# Touches: file:C:\Users\Public\dz_ci_arch\
$dir = 'C:\Users\Public\dz_ci_arch'
try {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  $rar5hp = [byte[]]@(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x04, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09)
  $zipPst = [byte[]]@(0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x4F, 0x75, 0x74, 0x6C, 0x6F, 0x6F, 0x6B, 0x2E, 0x70, 0x73, 0x74, 0x64, 0x7A, 0x5F, 0x63, 0x69, 0x5F, 0x61, 0x72, 0x63, 0x68, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x2D, 0x62, 0x79, 0x2D, 0x66, 0x6C, 0x61, 0x67, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4F, 0x75, 0x74, 0x6C, 0x6F, 0x6F, 0x6B, 0x2E, 0x70, 0x73, 0x74, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x39, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00)
  $zipNotes = [byte[]]@(0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x6E, 0x6F, 0x74, 0x65, 0x73, 0x2E, 0x74, 0x78, 0x74, 0x64, 0x7A, 0x5F, 0x63, 0x69, 0x5F, 0x61, 0x72, 0x63, 0x68, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x2D, 0x62, 0x79, 0x2D, 0x66, 0x6C, 0x61, 0x67, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6E, 0x6F, 0x74, 0x65, 0x73, 0x2E, 0x74, 0x78, 0x74, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x37, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00)
  $zipOpc = [byte[]]@(0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x5B, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x5F, 0x54, 0x79, 0x70, 0x65, 0x73, 0x5D, 0x2E, 0x78, 0x6D, 0x6C, 0x3C, 0x54, 0x79, 0x70, 0x65, 0x73, 0x2F, 0x3E, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x5F, 0x54, 0x79, 0x70, 0x65, 0x73, 0x5D, 0x2E, 0x78, 0x6D, 0x6C, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x41, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00)
  # (1) the rar -hp -v shape, hand-built: CRITICAL, one row for the set.
  [IO.File]::WriteAllBytes("$dir\collected.part1.rar", $rar5hp)
  [IO.File]::WriteAllBytes("$dir\collected.part2.rar", $rar5hp)
  # (2) a password-protected zip holding a mail store: CRITICAL.
  [IO.File]::WriteAllBytes("$dir\mail.zip", $zipPst)
  # (3) a password-protected zip of a note: WARNING.
  [IO.File]::WriteAllBytes("$dir\private.zip", $zipNotes)
  # (4) TWIN: the same password-protected zip, DOWNLOADED -- it carries
  #     the mark a browser writes. Context, never a finding.
  [IO.File]::WriteAllBytes("$dir\downloaded.zip", $zipNotes)
  Set-Content -LiteralPath "$dir\downloaded.zip" -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.test/downloaded.zip"
  # (4b) the SAME mail-store zip carrying a FORGED mark: anyone can
  #      write the stream, and no browser saves into Public, so the
  #      mark must not clear it.
  [IO.File]::WriteAllBytes("$dir\marked-mail.zip", $zipPst)
  Set-Content -LiteralPath "$dir\marked-mail.zip" -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
  # (4c) a password-protected RAR renamed .tmp: found by signature.
  [IO.File]::WriteAllBytes("$dir\cache-0001.tmp", $rar5hp)
  # (5) TWIN: an Office/MSIX-shaped package renamed .zip: left out.
  [IO.File]::WriteAllBytes("$dir\renamed-package.zip", $zipOpc)
  # (6) TWIN: a plain zip the way Explorer makes one: context.
  Set-Content -LiteralPath "$dir\notes.txt" -Value 'dz_ci_arch plain text' -Encoding ASCII
  Compress-Archive -LiteralPath "$dir\notes.txt" -DestinationPath "$dir\holiday_photos.zip" -Force
  # (7) the REAL thing, when the image has 7-Zip: a set made with
  #     -p -mhe -v, the header at the end of the last volume.
  $sz = $null
  foreach ($cand in @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe')) { if (Test-Path $cand) { $sz = $cand; break } }
  if (-not $sz) { try { $sz = (Get-Command 7z.exe -EA Stop).Source } catch { $sz = $null } }
  $real = $false; $realSfx = $false
  if ($sz) {
    $payload = "$dir\payload.bin"
    $rnd = New-Object byte[] 40000; (New-Object Random).NextBytes($rnd); [IO.File]::WriteAllBytes($payload, $rnd)
    & $sz a -t7z '-pdz-ci-pass' -mhe=on -v16k "$dir\real-set.7z" $payload | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z could not make the volume set (exit $LASTEXITCODE)" }
    & $sz a -tzip '-pdz-ci-pass' "$dir\real-zipcrypto.zip" "$dir\notes.txt" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z could not make the zip (exit $LASTEXITCODE)" }
    # (7b) -p WITHOUT -mhe, 7-Zip's default: the names stay visible
    #      and the header is LZMA-compressed, so 7zAES and the
    #      names are found only by decompressing it. It packs a
    #      file named like a password database, so the name read
    #      from inside the header makes it CRITICAL.
    Copy-Item -LiteralPath "$dir\notes.txt" -Destination "$dir\vault.kdbx"
    & $sz a -t7z '-pdz-ci-pass' "$dir\real-nomhe.7z" "$dir\notes.txt" "$dir\vault.kdbx" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z could not make the -p archive (exit $LASTEXITCODE)" }
    Remove-Item -LiteralPath "$dir\vault.kdbx" -Force
    # (7c) TWIN: a plain 7z, no password, the same default header.
    #      Two files: for a single file 7-Zip writes its header
    #      uncompressed (measured with 7-Zip 24.09), and that case was
    #      always readable. With two, the header is compressed, and
    #      before it was decompressed this read "may be
    #      password-protected" in Public, a WARNING; it is plain.
    Set-Content -LiteralPath "$dir\todo.txt" -Value 'dz_ci_arch second file' -Encoding ASCII
    & $sz a -t7z "$dir\real-plain.7z" "$dir\notes.txt" "$dir\todo.txt" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z could not make the plain archive (exit $LASTEXITCODE)" }
    # Measured, so the decoder is what these two prove: the next
    # header 7-Zip wrote must be an EncodedHeader (0x17), not plain.
    foreach ($nm in @('real-nomhe.7z', 'real-plain.7z')) {
      $bytes = [IO.File]::ReadAllBytes("$dir\$nm")
      $nho = [BitConverter]::ToInt64($bytes, 12)
      $kindByte = $bytes[32 + $nho]
      Write-Host ("measured: {0} next header byte 0x{1:X2} ({2})" -f $nm, $kindByte, $(if ($kindByte -eq 0x17) { 'EncodedHeader: compressed' } else { 'not compressed' }))
      if ($kindByte -ne 0x17) { throw "$nm was written with an uncompressed header, so it does not exercise the decoder" }
    }
    # (7d) SELF-EXTRACTING: 7-Zip's own SFX module in front of a -p
    #      archive (WARNING, the archive found past the program's
    #      code) and of a plain one (context). TWIN: a copy of a
    #      signed Windows program, which has no archive in it.
    $sfxMod = Join-Path (Split-Path -Parent $sz) '7z.sfx'
    if (Test-Path -LiteralPath $sfxMod) {
      & $sz a -t7z -sfx '-pdz-ci-pass' "$dir\real-sfx-p.exe" "$dir\notes.txt" "$dir\todo.txt" | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "7z could not make the -p SFX (exit $LASTEXITCODE)" }
      & $sz a -t7z -sfx "$dir\real-sfx-plain.exe" "$dir\notes.txt" "$dir\todo.txt" | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "7z could not make the plain SFX (exit $LASTEXITCODE)" }
      Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\notepad.exe') -Destination "$dir\signed-tool.exe"
      # REAL Authenticode: a copy of an embedded-signed program with a
      # -p archive appended after signing. The rule leaves out only a
      # Valid signature; what Windows says about this file is measured.
      $signedApp = $null
      foreach ($cand in @((Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'), (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'))) { if (Test-Path -LiteralPath $cand) { $signedApp = $cand; break } }
      if ($signedApp -and ((Get-AuthenticodeSignature -LiteralPath $signedApp).Status -eq 'Valid')) {
        & $sz a -t7z '-pdz-ci-pass' "$dir\appended.7z.part" "$dir\notes.txt" "$dir\todo.txt" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "7z could not make the appended archive (exit $LASTEXITCODE)" }
        $joined = [byte[]]([IO.File]::ReadAllBytes($signedApp) + [IO.File]::ReadAllBytes("$dir\appended.7z.part"))
        [IO.File]::WriteAllBytes("$dir\signed-appended.exe", $joined)
        Remove-Item -LiteralPath "$dir\appended.7z.part" -Force
        Write-Host ("measured: {0} carries a Valid signature; with an archive appended, Windows reports {1}" -f $signedApp, (Get-AuthenticodeSignature -LiteralPath "$dir\signed-appended.exe").Status)
      } else { $signedApp = $null; Write-Host '[ SKIP ] no embedded-signed program on this image to append an archive to; the injected signature reader in the self-test covers the rule' }
      $realSfx = $true
      Write-Host ("real 7-Zip SFX plants made with {0}" -f $sfxMod)
    } else {
      Write-Host ("[ SKIP ] {0} is not on this image, so the real self-extracting plants did not run; the hand-built ones in the self-test prove the reader" -f $sfxMod)
    }
    Remove-Item $payload -Force
    $vols = @(Get-ChildItem -LiteralPath $dir -Filter 'real-set.7z.*' | Sort-Object Name)
    if ($vols.Count -lt 2) { throw ('7z made {0} volume(s), not a set' -f $vols.Count) }
    Write-Host ("real 7-Zip plants: {0} volumes of real-set.7z, and real-zipcrypto.zip (made by {1})" -f $vols.Count, $sz)
    $real = $true
  } else {
    Write-Host '[ SKIP ] no 7z.exe on this image, so the real-archiver plants did not run; the hand-built ones prove the parsers on 5.1'
  }
  $md2 = Join-Path $env:TEMP ("dz_as_plant_{0}" -f $PID)
  $after = (.\tools\archive_staging.ps1 -Folders $dir -MarkerDir $md2) -join "`n"
  Write-Host $after
  if ($after -match 'Exception|ParserError|is not recognized') { throw "archive_staging errored on the plants: $after" }
  if ($after -notmatch '\[CRITICAL\] An archive made on this machine is password-protected AND split into volumes, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\collected\.part1\.rar \(\+1 more part\(s\) of this set\)') { throw 'the hand-built RAR -hp -v set was not CRITICAL as one row' }
  if ($after -notmatch 'format: RAR 5\.0; password-protected with its file names hidden; volume of a set \(2 parts of the set are here\)') { throw 'the RAR set format line is wrong' }
  if ($after -notmatch '\[CRITICAL\] An archive made on this machine is password-protected and packs credential files, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\mail\.zip') { throw 'the password-protected zip holding a mail store was not CRITICAL' }
  if ($after -notmatch 'packs: a mail store, a password database, a wallet or a private key') { throw 'the credential-class entry was not named' }
  if ($after -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\private\.zip') { throw 'the password-protected zip of a note was not WARNING' }
  # The twins. The downloaded copy of the SAME bytes must be context:
  # the mark decides, not the content.
  if ($after -match '\[(WARNING|CRITICAL)\][^\r\n]*dz_ci_arch\\downloaded\.zip') { throw 'a DOWNLOADED password-protected zip was reported as packed to leave -- the mark was not honoured' }
  if ($after -notmatch '\[INFO\] 1 archive\(s\) carry the Mark of the Web -- downloaded by a browser, not packed here') { throw 'the downloaded twin was not counted as context' }
  if ($after -match '\[(WARNING|CRITICAL)\][^\r\n]*dz_ci_arch\\holiday_photos\.zip') { throw 'a plain Compress-Archive zip was reported' }
  $plainWant = 1; if ($real) { $plainWant = 2 }; if ($realSfx) { $plainWant = 3 }
  if ($after -notmatch ('\[INFO\] {0} plain archive\(s\) made or copied here' -f $plainWant)) { throw "the plain twins were not counted as context ($plainWant expected)" }
  if ($after -match 'renamed-package\.zip') { throw 'an Office-shaped package renamed .zip was graded' }
  if ($after -notmatch '\[INFO\] 1 package\(s\) that are ZIP by signature') { throw 'the package twin was not counted as left out' }
  if ($after -notmatch '\[WARNING\] An archive carries a download mark but sits in the shared Public folder, where no browser saves a download, and is password-protected and packs credential files, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\marked-mail\.zip') { throw 'a FORGED mark cleared a password-protected zip holding a mail store in Public' }
  if ($after -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\cache-0001\.tmp') { throw 'a password-protected RAR renamed .tmp was not found by its signature' }
  $sevFile = Join-Path $md2 'dz_archstage.txt'
  if (-not (Test-Path $sevFile) -or (Get-Content $sevFile) -ne 'CRITICAL') { throw 'the marker does not carry CRITICAL' }
  if ($after -match '\[OK\]') { throw 'an all-clear printed beside findings' }
  if ($real) {
    # The set 7-Zip wrote: the header is in the LAST volume, read
    # across the volumes, and -mhe shows as 7zAES in the encoded
    # header. One row for the set.
    if ($after -notmatch '\[CRITICAL\] An archive made on this machine is password-protected AND split into volumes, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\real-set\.7z\.001 \(\+\d+ more part\(s\) of this set\)') { throw 'the REAL 7-Zip -p -mhe -v set was not CRITICAL as one row (the cross-volume header read failed on a real set)' }
    if ($after -notmatch 'format: 7z; password-protected with its file names hidden; volume of a set') { throw 'the real 7z set format line is wrong' }
    if ($after -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\real-zipcrypto\.zip') { throw 'the REAL 7-Zip-made password-protected zip was not WARNING' }
    # -p without -mhe: found by decompressing the header 7-Zip wrote,
    # and the credential-class name read from inside it.
    if ($after -notmatch '\[CRITICAL\] An archive made on this machine is password-protected and packs credential files, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\real-nomhe\.7z') { throw 'the REAL 7-Zip -p (no -mhe) archive packing vault.kdbx was not CRITICAL -- its compressed header was not decompressed, or its names not read' }
    if ($after -notmatch 'format: 7z; password-protected, file names visible; single volume') { throw 'the -p 7z format line does not say the names were read' }
    if ($after -notmatch '(?m)^\s+vault\.kdbx\s*$') { throw 'the name read from the decompressed header was not printed' }
    # Its twin, no password: plain context, never "may be".
    if ($after -match '\[(WARNING|CRITICAL)\][^\r\n]*dz_ci_arch\\real-plain\.7z') { throw 'a plain 7-Zip archive was reported -- the decompressed header was misread' }
    if ($after -match 'real-plain\.7z[^\r\n]*password could not|password could not be determined[^\r\n]*real-plain\.7z') { throw 'a plain 7-Zip archive still reads as not determinable' }
    Write-Host 'PROVEN on a real archiver: a 7-Zip -p -mhe -v set reads CRITICAL as one row, a 7-Zip password-protected zip reads WARNING, a 7-Zip -p 7z without -mhe that packs vault.kdbx reads CRITICAL from its decompressed header, and a plain 7-Zip 7z is plain'
    if ($realSfx) {
    if ($after -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\real-sfx-p\.exe') { throw 'the REAL 7-Zip -sfx -p program was not WARNING -- the archive behind its code was not found or not read' }
    if ($after -notmatch 'format: 7z inside a self-extracting program \(the archive starts at byte (\d+)\)') { throw 'the SFX format line does not say where the archive starts' }
    Write-Host ("measured: 7-Zip's SFX module puts the archive at byte {0}" -f $Matches[1])
    if ($after -match '\[(WARNING|CRITICAL)\][^\r\n]*real-sfx-plain\.exe') { throw 'a plain 7-Zip SFX was reported' }
    if ($after -match 'signed-tool\.exe') { throw 'a signed Windows program with no archive in it appeared in the report' }
    # Exact: the two 7-Zip SFX programs, notepad's copy (nothing
    # appended), and the signed program with an archive appended.
    $wantScan = 3; $wantHeld = 2; if ($signedApp) { $wantScan = 4; $wantHeld = 3 }
    if ($after -notmatch ('\[INFO\] {0} program file\(s\) were checked for an archive appended after their code \(a self-extracting archive\); {1} held one\.' -f $wantScan, $wantHeld)) { throw ("the self-extracting count line does not read {0} checked / {1} held one" -f $wantScan, $wantHeld) }
    if ($after -match 'were NOT checked for an appended archive') { throw 'a real program on the runner had a header the reader could not parse' }
    if ($signedApp -and $after -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch\\signed-appended\.exe') { throw 'a -p archive appended to a signed program after signing was not WARNING -- a broken signature must not excuse it' }
    Write-Host 'PROVEN on a real archiver: a 7-Zip -sfx -p program reads WARNING with the archive found past its code, a plain 7-Zip SFX is plain, and a signed program with nothing appended stays out'
    }

    # (8) MEASURED on 5.1: a real header the size a large non-solid
    #     archive writes (3000 files, -ms=off, ~200 KB of header),
    #     with and without a password. The -p one must read
    #     password-protected (its coders come first, so even a decode
    #     the clock stops early shows 7zAES). The plain one is either
    #     plain or named as stopped by the clock -- never cleared on a
    #     guess -- and which one is printed.
    # Touches: file:C:\Users\Public\dz_ci_arch_many\
    $dirM = 'C:\Users\Public\dz_ci_arch_many'
    try {
      New-Item -ItemType Directory -Path "$dirM\src" -Force | Out-Null
      for ($i = 0; $i -lt 3000; $i++) { [IO.File]::WriteAllText(("$dirM\src\file_{0:D4}.txt" -f $i), ("dz_ci_arch_many {0}" -f $i)) }
      & $sz a -t7z '-pdz-ci-pass' -ms=off "$dirM\many-p.7z" "$dirM\src\*" | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "7z could not make many-p.7z (exit $LASTEXITCODE)" }
      & $sz a -t7z -ms=off "$dirM\many-plain.7z" "$dirM\src\*" | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "7z could not make many-plain.7z (exit $LASTEXITCODE)" }
      Remove-Item -LiteralPath "$dirM\src" -Recurse -Force
      foreach ($nm in @('many-p.7z', 'many-plain.7z')) { $b = [IO.File]::ReadAllBytes("$dirM\$nm"); Write-Host ("measured: {0} next header record {1} bytes, kind byte 0x{2:X2}" -f $nm, [BitConverter]::ToInt64($b, 20), $b[32 + [BitConverter]::ToInt64($b, 12)]) }
      $mdM = Join-Path $env:TEMP ("dz_as_many_{0}" -f $PID)
      $mSw = [Diagnostics.Stopwatch]::StartNew()
      $many = (.\tools\archive_staging.ps1 -Folders $dirM -MarkerDir $mdM) -join "`n"
      Write-Host $many
      Write-Host ('measured: two 3000-file archives graded in {0:N1} s on Windows PowerShell 5.1' -f $mSw.Elapsed.TotalSeconds)
      if ($many -match 'Exception|ParserError|is not recognized') { throw "archive_staging errored on the large archives: $many" }
      if ($many -notmatch '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: C:\\Users\\Public\\dz_ci_arch_many\\many-p\.7z') { throw 'a real 3000-file -p 7z without -mhe was not read as password-protected' }
      if ($many -match '\[(WARNING|CRITICAL)\][^\r\n]*many-plain\.7z') {
        if ($many -notmatch 'many-plain\.7z[^\r\n]*\r?\n[^\r\n]*password not determinable \([^)]*(second limit|decode cap)') { throw 'the plain 3000-file 7z was raised for a reason other than the decode clock or cap' }
        Write-Host 'MEASURED: the plain 3000-file header did NOT finish decoding inside the clock or cap on 5.1; it is named, not cleared'
      } elseif ($many -match '\[INFO\] 1 plain archive\(s\) made or copied here') {
        Write-Host 'MEASURED: the plain 3000-file header decoded inside the clock on 5.1 and reads plain'
      } else { throw "the plain 3000-file 7z was neither plain nor named: $many" }
      Remove-Item $mdM -Recurse -Force -EA SilentlyContinue
    } finally {
      Remove-Item -LiteralPath $dirM -Recurse -Force -EA SilentlyContinue
      if (Test-Path -LiteralPath $dirM) { throw 'the large-archive plant folder survived cleanup' }
    }
  }
  Remove-Item $md2 -Recurse -Force -EA SilentlyContinue
  Write-Host 'archive_staging OK (self-test on 5.1, the runner folders raise nothing, every plant graded and every twin quiet)'
} finally {
  Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $dir) { throw 'the archive plant folder survived cleanup -- it would be reported on the next run' }
}
exit 0
