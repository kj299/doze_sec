# archive_staging.ps1 -- an archive MADE ON THIS MACHINE that is password-
# protected, split into volumes, or packs credential files, sitting in a
# staging folder (T1560 Archive Collected Data; Collection). Section 14.
#
# WHY. Before data leaves a machine it is packed. Microsoft's own incident
# reporting names the shape every time: Volt Typhoon "staging collected data in
# password-protected archives" (Microsoft Security Blog, 2023-05-24); HAFNIUM
# "using 7-Zip to compress stolen data into ZIP files for exfiltration", with
# the advice to check for ".zip, .rar, and .7z files in C:\ProgramData\"
# (2021-03-02); NICKEL "used either a renamed rar.exe or 7z.exe to archive the
# files" (2021-12-06); and ATT&CK's menuPass entry, "multi-part archives, often
# saved in the Recycle Bin". ATT&CK's own analytic for T1560 keys on "file
# write operations to temporary or staging directories" of "large compressed or
# encrypted files". Nothing in this audit looked at an archive before now, and
# the manifest's claim that Section 18's process list covered it was false: no
# archiver was on that list.
#
# THE JUDGEMENT IS THE WHOLE CHECK. Downloads is full of archives, and %TEMP%
# is where pip, npm, VS Code, installers and browsers unpack theirs. Two facts
# make the rule honest:
#   1. A file a browser downloaded carries the Mark of the Web (the
#      Zone.Identifier stream, [ZoneTransfer] ZoneId=3, or 1/2 for an intranet
#      or trusted site): Microsoft documents that Edge, Chrome and the
#      Attachment Execution Service write it, that an NTFS copy preserves it,
#      and that a file the OneDrive sync client fetched does NOT carry it. An
#      archive rar.exe or 7z.exe wrote on this machine never has one. So "no
#      mark" means made or copied HERE. A marked archive came IN and is
#      context -- with one exception, because anyone can write that stream: a
#      marked archive of the strongest shape (password AND volumes, or a
#      password or volumes AND credential files) sitting somewhere no browser
#      saves a download (the Public folder, a system temp folder, ProgramData,
#      the recycle bin) is still raised, and every marked archive of that
#      shape is named with the origin its mark records.
#   2. A password and volume splitting are what an attacker needs and an
#      ordinary local archive (Explorer's "Compress", a tool's cache) never
#      has. Both are readable from the file's own header bytes, by the format
#      owners' published layouts (PKWARE's APPNOTE for ZIP; RARLAB's UnRAR
#      source for RAR 4.x and 5.0; 7-Zip's 7zFormat.txt), with no third-party
#      tool. The one thing decompressed is a 7z's own header, which 7-Zip
#      LZMA-compresses by default (below); file contents never are.
# So: no mark AND a password is WARNING; no mark AND volumes is WARNING outside
# Downloads (a split set in Downloads is how torrent and file-sharing clients
# deliver large files, and many of them write no mark, so there it is named
# context); both together is CRITICAL -- the exact shape in the reports above;
# a visible entry name of the credential class (a mail store, a password
# database, a wallet, a private key, a registry-hive copy, a browser's
# saved-password store) escalates. A plain single-volume local archive is
# context, counted and named, never a row. A CAB set is context: a cabinet
# cannot carry a password, and installers write spanned sets.
#
# WHAT THIS CANNOT TELL, SAID RATHER THAN IMPLIED: a 7z made with a password
# but WITHOUT header encryption looks like a plain 7z until its compressed
# header is decompressed. The header is LZMA by default, and this tool decodes
# it (capped at 256 KiB of header, 10 seconds each and 30 seconds per run,
# smallest first, after every other archive has been graded; CRC-checked)
# and reads its coders and names; a header coded with anything else, one
# larger than the cap, one that fails its CRC, does not decode or is not
# reached in that time is reported as "not determinable" and named (raised only in the Public folder, where nothing
# unpacks); entry names are read from ZIP, RAR and 7z, contents never;
# a self-extracting program is read when its archive sits in the first 64 KiB
# past its code (the PE overlay), and left out when it is validly signed by its
# publisher (an installer); files are examined to a stated
# depth with stated caps; a cloud-only placeholder is not read (reading it
# would download it); and a file the OneDrive client synced carries no mark,
# so a downloaded archive it fetched reads as made here (the corpus names that
# twin).
#
# NOTHING EXAMINED IS NOT AN ALL-CLEAR. A folder or file an administrator
# could not read is a declared gap with its own ledger row; one a standard-user
# token cannot open (another profile, the system temp folders, another user's
# recycle bin) is a counted DEFERRAL, never a row; a cap or the time budget
# turns the all-clear into an [INFO] line scoped to what was read. The
# coverage line names the folders and the depth, so a reader can see what it
# does not cover.
#
# EVERY LOOP BOUND COMES FROM THE BUFFER, NOT THE FILE. A crafted header can
# claim 2^60 entries; each count read from a file is checked against the bytes
# that remain, and every walk must advance, so a hostile file in Downloads
# cannot hang the audit.
#
# MARKERS: dz_archstage.txt (highest severity of the archive findings),
# dz_archstage_gap.txt (a folder or file an administrator could not read; its
# own ledger row), dz_archstage_deferred.txt (a count a standard-user token
# could not perform, added to DEFERRED_COUNT, never a ledger row).
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    [string[]]$Folders = @(),
    [int]$MaxFilesPerFolder = 20000,
    [int]$MaxProbes = 5000,
    [int]$BudgetSeconds = 120,
    [int]$Depth = 2,
    [int]$Elevated = -1,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write turns a
    # finding into a CLEAN section. Create the directory, and let a genuine
    # write failure print instead of vanishing.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Format-When {
    param($t)
    if ($null -eq $t) { return 'an unknown time' }
    return (([datetime]$t).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
}

function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

# ---------------------------------------------------------------------------
# Byte helpers. Every parser below works on a byte[] it was handed, so the
# self-test can feed it synthetic archives without touching a real one.
# ---------------------------------------------------------------------------

function Read-FileBytes {
    # Up to $Count bytes from $Offset (negative = from the end). Read() may
    # return fewer bytes than asked, so it loops; a short file yields a short
    # array. Opened with FileShare.ReadWrite so a file another program is
    # writing can still be read.
    param([string]$Path, [long]$Offset, [int]$Count)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $len = $fs.Length
        $start = $Offset
        if ($start -lt 0) { $start = $len + $Offset; if ($start -lt 0) { $start = 0 } }
        if ($start -ge $len -or $Count -le 0) { return (New-Object byte[] 0) }
        $want = [int][math]::Min([long]$Count, $len - $start)
        $null = $fs.Seek($start, [System.IO.SeekOrigin]::Begin)
        $buf = New-Object byte[] $want
        $got = 0
        while ($got -lt $want) {
            $n = $fs.Read($buf, $got, $want - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        if ($got -lt $want) { $short = New-Object byte[] $got; [Array]::Copy($buf, $short, $got); return $short }
        return $buf
    } finally { $fs.Dispose() }
}

function Read-SpanBytes {
    # $Count bytes starting at $Offset of the stream formed by concatenating
    # $Paths (with the given $Sizes), the way 7-Zip reads a raw volume set.
    # Returns fewer bytes when the stream ends first.
    param([string[]]$Paths, [long[]]$Sizes, [long]$Offset, [int]$Count)
    $l = New-Object System.Collections.Generic.List[byte]
    $base = [long]0
    if ($Offset -lt 0) { $Offset = 0 }
    for ($i = 0; $i -lt $Paths.Count -and $l.Count -lt $Count; $i++) {
        $sz = [long]$Sizes[$i]
        $from = $Offset + $l.Count
        if ($from -lt $base + $sz) {
            $part = Read-FileBytes -Path $Paths[$i] -Offset ($from - $base) -Count ($Count - $l.Count)
            foreach ($b in @($part)) { if ($null -ne $b) { $l.Add([byte]$b) } }
        }
        $base += $sz
    }
    return $l.ToArray()
}

function Test-BytesAt {
    param([byte[]]$Buf, [long]$Pos, [int[]]$Want)
    if ($null -eq $Buf -or $Pos -lt 0 -or ($Pos + $Want.Count) -gt $Buf.Count) { return $false }
    for ($i = 0; $i -lt $Want.Count; $i++) { if ($Buf[$Pos + $i] -ne $Want[$i]) { return $false } }
    return $true
}

function Get-U16 { param([byte[]]$Buf, [long]$Pos) if ($Pos -lt 0 -or ($Pos + 2) -gt $Buf.Count) { return -1 }; return [int][BitConverter]::ToUInt16($Buf, [int]$Pos) }
function Get-U32 { param([byte[]]$Buf, [long]$Pos) if ($Pos -lt 0 -or ($Pos + 4) -gt $Buf.Count) { return -1 }; return [long][BitConverter]::ToUInt32($Buf, [int]$Pos) }
# Signed on purpose: a value at or above 2^63 reads negative and every caller
# rejects a negative size or offset, instead of an overflow exception.
function Get-U64 { param([byte[]]$Buf, [long]$Pos) if ($Pos -lt 0 -or ($Pos + 8) -gt $Buf.Count) { return -1 }; return [BitConverter]::ToInt64($Buf, [int]$Pos) }

function Read-Vint {
    # RAR 5.0 variable-length integer: 7 bits per byte, low group first, the
    # high bit meaning "another byte follows" (RARLAB technote; UnRAR GetV).
    # Ok is false on a run past the buffer or past ten bytes; a value that
    # reaches the sign bit is returned negative and rejected by the callers.
    param([byte[]]$Buf, [long]$Pos)
    $v = [long]0; $shift = 0; $p = $Pos
    while ($p -ge 0 -and $p -lt $Buf.Count -and $shift -le 63) {
        $b = [int]$Buf[$p]; $p++
        $v = $v -bor ([long]($b -band 0x7F) -shl $shift)
        if (($b -band 0x80) -eq 0) { return @{ Value = $v; Next = $p; Ok = $true } }
        $shift += 7
    }
    return @{ Value = -1; Next = $p; Ok = $false }
}

function Read-SevenZipNumber {
    # 7z's UINT64 encoding (7zFormat.txt): the count of leading one bits in
    # the first byte is the number of extra bytes, little-endian; the rest of
    # the first byte holds the high part. Ok is false past the buffer; a value
    # reaching the sign bit is negative and rejected by the callers.
    param([byte[]]$Buf, [long]$Pos)
    if ($Pos -lt 0 -or $Pos -ge $Buf.Count) { return @{ Value = -1; Next = $Pos; Ok = $false } }
    $first = [int]$Buf[$Pos]
    $mask = 0x80; $extra = 0
    while ($extra -lt 8 -and ($first -band $mask) -ne 0) { $extra++; $mask = $mask -shr 1 }
    if (($Pos + 1 + $extra) -gt $Buf.Count) { return @{ Value = -1; Next = $Buf.Count; Ok = $false } }
    $v = [long]0
    for ($i = 0; $i -lt $extra; $i++) { $v = $v -bor ([long]$Buf[$Pos + 1 + $i] -shl (8 * $i)) }
    if ($extra -lt 8) { $high = [long]($first -band ($mask - 1)); $v = $v -bor ($high -shl (8 * $extra)) }
    return @{ Value = $v; Next = ($Pos + 1 + $extra); Ok = $true }
}

# ---------------------------------------------------------------------------
# WHAT A FILE IS, by its own first bytes -- a renamed archive is still one.
# ---------------------------------------------------------------------------

function Get-ArchiveKind {
    # 'zip', 'zip-span' (the first segment of a split set, APPNOTE 0x08074b50),
    # 'rar4', 'rar5', '7z', 'cab', 'gzip', 'bzip2', 'xz', 'tar', or 'none'.
    # $Head is the first 512 bytes (tar's magic sits at 257).
    param([byte[]]$Head)
    if ($null -eq $Head -or $Head.Count -lt 4) { return 'none' }
    if (Test-BytesAt $Head 0 @(0x50, 0x4B, 0x03, 0x04)) { return 'zip' }
    if (Test-BytesAt $Head 0 @(0x50, 0x4B, 0x07, 0x08)) { return 'zip-span' }
    if (Test-BytesAt $Head 0 @(0x50, 0x4B, 0x30, 0x30)) { return 'zip' }
    if (Test-BytesAt $Head 0 @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07)) {
        if ($Head.Count -ge 8 -and $Head[6] -eq 0x01 -and $Head[7] -eq 0x00) { return 'rar5' }
        if ($Head.Count -ge 7 -and $Head[6] -eq 0x00) { return 'rar4' }
        return 'none'
    }
    if (Test-BytesAt $Head 0 @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)) { return '7z' }
    if (Test-BytesAt $Head 0 @(0x4D, 0x53, 0x43, 0x46)) { return 'cab' }
    if (Test-BytesAt $Head 0 @(0x1F, 0x8B)) { return 'gzip' }
    if ((Test-BytesAt $Head 0 @(0x42, 0x5A, 0x68)) -and $Head[3] -ge 0x31 -and $Head[3] -le 0x39) { return 'bzip2' }
    if (Test-BytesAt $Head 0 @(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00)) { return 'xz' }
    if (Test-BytesAt $Head 257 @(0x75, 0x73, 0x74, 0x61, 0x72)) { return 'tar' }
    # An empty ZIP is only its end record.
    if (Test-BytesAt $Head 0 @(0x50, 0x4B, 0x05, 0x06)) { return 'zip' }
    return 'none'
}

function Get-KindLabel {
    param([string]$Kind)
    switch ($Kind) {
        'zip'      { return 'ZIP' }
        'zip-span' { return 'ZIP (first segment of a split set)' }
        'rar4'     { return 'RAR 4.x' }
        'rar5'     { return 'RAR 5.0' }
        '7z'       { return '7z' }
        'cab'      { return 'CAB' }
        'gzip'     { return 'gzip' }
        'bzip2'    { return 'bzip2' }
        'xz'       { return 'xz' }
        'tar'      { return 'tar' }
        default    { return $Kind }
    }
}

# ---------------------------------------------------------------------------
# ZIP (PKWARE APPNOTE): the end-of-central-directory record is within the last
# 22 + 65535 bytes; "number of this disk" non-zero means a split or spanned
# set (0xFFFF is the zip64 sentinel, resolved from the zip64 record); each
# central entry's general-purpose bit 0 means encrypted (bit 6 is strong
# encryption, bit 13 a masked central directory), and compression method 99 is
# WinZip AES. The file name follows the 46-byte fixed part. The LOCAL headers
# carry the same flags at +6 and the method at +8, and are walked too: a zip
# whose end record is damaged or whose central flags were cleared is still
# read from the front.
# ---------------------------------------------------------------------------

function Get-ZipFactsFromBytes {
    # $Tail = the last bytes of the file (up to 65557). Finds the end record,
    # resolves zip64, and says where the central directory is.
    param([byte[]]$Tail, [long]$FileLength)
    $r = @{ Parsed = $false; Split = $false; Encrypted = $null; Entries = @(); Opc = $false; Why = ''; CdOffset = -1; CdSize = 0; EntryCount = 0 }
    if ($null -eq $Tail -or $Tail.Count -lt 22) { $r.Why = 'too short for an end-of-central-directory record'; return $r }
    $tailStart = $FileLength - $Tail.Count
    $eocd = -1; $loose = -1
    for ($i = $Tail.Count - 22; $i -ge 0; $i--) {
        if (Test-BytesAt $Tail $i @(0x50, 0x4B, 0x05, 0x06)) {
            $clen = Get-U16 $Tail ($i + 20)
            if (($i + 22 + $clen) -eq $Tail.Count) { $eocd = $i; break }
            # A record followed by trailing bytes (an appended byte, a
            # concatenation) is still the record when its central directory
            # ends where the record begins; archivers open such files.
            if ($loose -lt 0 -and ($i + 22 + $clen) -le $Tail.Count) {
                $cs = Get-U32 $Tail ($i + 12); $co = Get-U32 $Tail ($i + 16)
                if ($cs -ge 0 -and $co -ge 0 -and ($co + $cs) -le ($tailStart + $i)) { $loose = $i }
            }
        }
    }
    if ($eocd -lt 0) { $eocd = $loose }
    if ($eocd -lt 0) { $r.Why = 'no end-of-central-directory record'; return $r }
    $thisDisk = Get-U16 $Tail ($eocd + 4)
    $cdDisk = Get-U16 $Tail ($eocd + 6)
    $total = [long](Get-U16 $Tail ($eocd + 10))
    $cdSize = Get-U32 $Tail ($eocd + 12)
    $cdOff = Get-U32 $Tail ($eocd + 16)
    $z64 = ($thisDisk -eq 0xFFFF -or $cdDisk -eq 0xFFFF -or $cdOff -eq 0xFFFFFFFF -or $cdSize -eq 0xFFFFFFFF -or $total -eq 0xFFFF)
    if (-not $z64) {
        if ($thisDisk -ne 0 -or $cdDisk -ne 0) { $r.Split = $true }
    } else {
        # Zip64: the locator sits immediately before the end record and names
        # the total disk count and the zip64 end record's offset; that record
        # holds the real disk numbers (+16, +20), entry count (+32), central
        # directory size (+40) and offset (+48).
        $loc = $eocd - 20
        if ($loc -ge 0 -and (Test-BytesAt $Tail $loc @(0x50, 0x4B, 0x06, 0x07))) {
            $disks = Get-U32 $Tail ($loc + 16)
            if ($disks -gt 1) { $r.Split = $true }
            $z64off = Get-U64 $Tail ($loc + 8)
            $zp = $z64off - $tailStart
            if ($z64off -ge 0 -and $zp -ge 0 -and ($zp + 56) -le $Tail.Count -and (Test-BytesAt $Tail $zp @(0x50, 0x4B, 0x06, 0x06))) {
                if ((Get-U32 $Tail ($zp + 16)) -ne 0 -or (Get-U32 $Tail ($zp + 20)) -ne 0) { $r.Split = $true }
                $total = Get-U64 $Tail ($zp + 32)
                $cdSize = Get-U64 $Tail ($zp + 40)
                $cdOff = Get-U64 $Tail ($zp + 48)
            } else { $r.Why = 'zip64 end record outside the tail window'; return $r }
        } else { $r.Why = 'zip64 fields with no locator'; return $r }
    }
    if ($cdOff -lt 0 -or $cdSize -lt 0 -or $total -lt 0) { $r.Why = 'a negative central-directory size or offset'; return $r }
    $r.Parsed = $true; $r.CdOffset = $cdOff; $r.CdSize = $cdSize; $r.EntryCount = $total
    $r.EocdPos = $tailStart + $eocd; $r.Zip64 = $z64
    if ($total -eq 0) { $r.Encrypted = $false }
    return $r
}

function Test-PackageEntryName {
    param([string]$Name)
    $leaf = ($Name -replace '^.*/', '')
    return ($leaf -ieq '[Content_Types].xml' -or $leaf -ieq 'AppxManifest.xml' -or $Name -match '^(?i)META-INF/MANIFEST\.MF$')
}

function Get-ZipEntriesFromBytes {
    # Walk the central directory bytes. Returns Encrypted ($true when any
    # entry is), Entries (names, capped), Opc (an Office/MSIX/JAR package
    # rather than an archive), and Count. Every step advances at least 46.
    param([byte[]]$Cd, [int]$Cap = 500)
    $r = @{ Encrypted = $false; Entries = @(); Opc = $false; Count = 0; Masked = $false }
    if ($null -eq $Cd) { return $r }
    $p = 0
    $names = New-Object System.Collections.ArrayList
    while (($p + 46) -le $Cd.Count -and (Test-BytesAt $Cd $p @(0x50, 0x4B, 0x01, 0x02)) -and $r.Count -lt 100000) {
        $flags = Get-U16 $Cd ($p + 8)
        $method = Get-U16 $Cd ($p + 10)
        $nlen = Get-U16 $Cd ($p + 28)
        $xlen = Get-U16 $Cd ($p + 30)
        $clen = Get-U16 $Cd ($p + 32)
        if (($flags -band 0x0001) -ne 0 -or ($flags -band 0x0040) -ne 0 -or $method -eq 99) { $r.Encrypted = $true }
        if (($flags -band 0x2000) -ne 0) { $r.Masked = $true; $r.Encrypted = $true }
        $r.Count++
        if (($p + 46 + $nlen) -le $Cd.Count -and $nlen -gt 0) {
            $name = [System.Text.Encoding]::UTF8.GetString($Cd, $p + 46, $nlen)
            if ($names.Count -lt $Cap) { [void]$names.Add($name) }
            if (Test-PackageEntryName $name) { $r.Opc = $true }
        }
        $p += 46 + $nlen + $xlen + $clen
    }
    $r.Entries = @($names.ToArray())
    return $r
}

function Get-ZipLocalFromBytes {
    # Walk the LOCAL headers from the front: signature 50 4B 03 04, flags at
    # +6, method at +8, compressed size at +18, name length at +26, extra
    # length at +28, name at +30. A data-descriptor entry (flag bit 3) with
    # no size cannot be skipped, so the walk stops there having read it.
    param([byte[]]$Head, [int]$Cap = 500)
    $r = @{ Encrypted = $false; Entries = @(); Opc = $false; Count = 0 }
    if ($null -eq $Head) { return $r }
    $p = 0
    if ((Test-BytesAt $Head 0 @(0x50, 0x4B, 0x07, 0x08)) -or (Test-BytesAt $Head 0 @(0x50, 0x4B, 0x30, 0x30))) { $p = 4 }
    $names = New-Object System.Collections.ArrayList
    while (($p + 30) -le $Head.Count -and (Test-BytesAt $Head $p @(0x50, 0x4B, 0x03, 0x04)) -and $r.Count -lt $Cap) {
        $flags = Get-U16 $Head ($p + 6)
        $method = Get-U16 $Head ($p + 8)
        $csize = Get-U32 $Head ($p + 18)
        $nlen = Get-U16 $Head ($p + 26)
        $xlen = Get-U16 $Head ($p + 28)
        if (($flags -band 0x0001) -ne 0 -or ($flags -band 0x0040) -ne 0 -or $method -eq 99) { $r.Encrypted = $true }
        $r.Count++
        if ($nlen -gt 0 -and ($p + 30 + $nlen) -le $Head.Count) {
            $name = [System.Text.Encoding]::UTF8.GetString($Head, $p + 30, $nlen)
            [void]$names.Add($name)
            if (Test-PackageEntryName $name) { $r.Opc = $true }
        }
        if (($flags -band 0x0008) -ne 0 -and $csize -eq 0) { break }
        if ($csize -lt 0 -or $csize -eq 0xFFFFFFFF) { break }
        $p += 30 + $nlen + $xlen + $csize
    }
    $r.Entries = @($names.ToArray())
    return $r
}

function Get-ZipFacts {
    # $SpanPaths / $SpanSizes: this file first, then the later raw volumes of
    # its set (7-Zip's name.zip.001, .002 ...), read as one stream.
    # $Base: where the archive starts (past a self-extracting program's code).
    param([string]$Path, [long]$Length, [string[]]$SpanPaths = @(), [long[]]$SpanSizes = @(), [long]$Base = 0)
    $span = ($SpanPaths.Count -gt 1)
    $total = $Length
    if ($span) { $total = 0; foreach ($s in $SpanSizes) { $total += [long]$s } }
    $tailLen = [int][math]::Min([long]65557, $total)
    if ($span) { $tail = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset ($total - $tailLen) -Count $tailLen }
    else { $tail = Read-FileBytes -Path $Path -Offset (-65557) -Count 65557 }
    $f = Get-ZipFactsFromBytes -Tail $tail -FileLength $total
    $cdRead = $false
    if ($f.Parsed -and $f.CdOffset -ge 0 -and $f.CdSize -gt 0 -and -not ($f.Split -and -not $span)) {
        $want = [int][math]::Min([long]$f.CdSize, 2097152)
        if ($span) { $cd = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset $f.CdOffset -Count $want }
        else { $cd = Read-FileBytes -Path $Path -Offset $f.CdOffset -Count $want }
        $e = Get-ZipEntriesFromBytes -Cd $cd
        if ($e.Count -eq 0 -and -not $span -and -not $f.Zip64 -and ($f.EocdPos - $f.CdSize) -ge 0 -and ($f.EocdPos - $f.CdSize) -ne $f.CdOffset) {
            # Data before the archive (a self-extracting program, or bytes
            # prepended) leaves the stated offsets relative to the archive's
            # own start; the central directory then ends where the end record
            # begins, which is where archivers look next.
            $cd = Read-FileBytes -Path $Path -Offset ($f.EocdPos - $f.CdSize) -Count $want
            $e = Get-ZipEntriesFromBytes -Cd $cd
        }
        if ($e.Count -gt 0) {
            $cdRead = $true
            $f.Encrypted = $e.Encrypted; $f.Entries = $e.Entries; $f.Opc = $e.Opc
            if ($e.Masked) { $f.Why = 'central directory masked (encrypted)' }
        } elseif ($f.EntryCount -gt 0) {
            $f.Why = 'central directory not at the offset the end record names'
        }
    }
    # The local headers, read from the front, settle what the central
    # directory could not -- and catch central flags that were cleared.
    if ($span) { $head = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset 0 -Count 1048576 }
    else { $head = Read-FileBytes -Path $Path -Offset $Base -Count 1048576 }
    $lo = Get-ZipLocalFromBytes -Head $head
    if ($lo.Encrypted) { $f.Encrypted = $true }
    if ($lo.Opc) { $f.Opc = $true }
    if (-not $cdRead) {
        if (@($f.Entries).Count -eq 0) { $f.Entries = $lo.Entries }
        if (-not $lo.Encrypted -and $f.EntryCount -ne 0) { $f.Encrypted = $null }
        if (-not $f.Parsed -and -not $lo.Encrypted) { $f.Encrypted = $null }
        if ($null -eq $f.Encrypted -and -not $f.Why) { $f.Why = 'end record unreadable' }
    }
    return $f
}

# ---------------------------------------------------------------------------
# RAR. RARLAB's UnRAR source (archive.cpp, arcread.cpp, headers.hpp,
# headers5.hpp) gives both layouts:
#   4.x: signature 52 61 72 21 1A 07 00; blocks of HEAD_CRC(2) HEAD_TYPE(1)
#        HEAD_FLAGS(2) HEAD_SIZE(2). Main header type 0x73 with MHD_VOLUME
#        0x0001, MHD_PASSWORD 0x0080 (headers encrypted, so nothing after it
#        is readable), MHD_FIRSTVOLUME 0x0100. File header type 0x74 with
#        LHD_PASSWORD 0x0004 (data encrypted, names visible), PACK_SIZE at +7,
#        NAME_SIZE at +26, the name at +32 (+40 when LHD_LARGE 0x0100 adds the
#        high size fields). Any block with flag 0x8000 carries ADD_SIZE at +7.
#   5.0: signature 52 61 72 21 1A 07 01 00; blocks of CRC32(4) vint size, then
#        vint type, vint flags, [vint extra size if flags&1], [vint data size
#        if flags&2]. Type 4 is the archive-encryption header (made by -hp:
#        everything after it is ciphertext); type 1 the main header whose
#        archive flags carry 0x0001 = volume and 0x0002 = volume number
#        present; type 2 a file header (flags, unpacked size, attributes,
#        [mtime], [crc], compression, host OS, name size, name) whose extra
#        area holds type-1 encryption records (-p: data encrypted, names
#        visible); type 5 the end header whose flag 0x0001 means a next volume
#        exists.
# ---------------------------------------------------------------------------

function Get-RarFactsFromBytes {
    param([byte[]]$Buf, [int]$Cap = 500)
    $r = @{ Parsed = $false; Encrypted = $false; HeadersEncrypted = $false; MultiVolume = $false; FirstVolume = $null; Entries = @(); Why = ''; Count = 0 }
    if ($null -eq $Buf -or $Buf.Count -lt 8) { $r.Why = 'too short'; return $r }
    $names = New-Object System.Collections.ArrayList
    if ($Buf[6] -eq 0x00) {
        # ---- RAR 4.x
        $p = [long]7; $blocks = 0
        while (($p + 7) -le $Buf.Count -and $blocks -lt $Cap) {
            $type = [int]$Buf[$p + 2]
            $flags = Get-U16 $Buf ($p + 3)
            $size = Get-U16 $Buf ($p + 5)
            if ($size -lt 7) { break }
            $blocks++
            if ($type -eq 0x73) {
                $r.Parsed = $true
                if (($flags -band 0x0001) -ne 0) { $r.MultiVolume = $true }
                if (($flags -band 0x0100) -ne 0) { $r.FirstVolume = $true } elseif (($flags -band 0x0001) -ne 0) { $r.FirstVolume = $false }
                if (($flags -band 0x0080) -ne 0) { $r.Encrypted = $true; $r.HeadersEncrypted = $true; break }
                $p += $size
                continue
            }
            if ($type -eq 0x74) {
                $pack = Get-U32 $Buf ($p + 7)
                $nlen = Get-U16 $Buf ($p + 26)
                $nameAt = $p + 32
                if (($flags -band 0x0100) -ne 0) { $hi = Get-U32 $Buf ($p + 32); if ($hi -gt 0) { $pack = $pack + ($hi * 4294967296) }; $nameAt = $p + 40 }
                if (($flags -band 0x0004) -ne 0) { $r.Encrypted = $true }
                $r.Count++
                if ($nlen -gt 0 -and ($nameAt + $nlen) -le $Buf.Count) {
                    $raw = New-Object byte[] $nlen; [Array]::Copy($Buf, $nameAt, $raw, 0, $nlen)
                    $z = [Array]::IndexOf($raw, [byte]0)
                    if ($z -ge 0) { if ($z -eq 0) { $raw = New-Object byte[] 0 } else { $cut = New-Object byte[] $z; [Array]::Copy($raw, $cut, $z); $raw = $cut } }
                    if ($names.Count -lt $Cap -and $raw.Count -gt 0) { [void]$names.Add([System.Text.Encoding]::UTF8.GetString([byte[]]$raw)) }
                }
                if ($pack -lt 0) { break }
                $p += $size + $pack
                continue
            }
            if ($type -eq 0x7B) { if (($flags -band 0x0001) -ne 0) { $r.MultiVolume = $true }; break }
            $add = 0
            if (($flags -band 0x8000) -ne 0) { $add = Get-U32 $Buf ($p + 7); if ($add -lt 0) { $add = 0 } }
            $p += $size + $add
        }
        if (-not $r.Parsed) { $r.Why = 'no main header' }
    } else {
        # ---- RAR 5.0
        $p = [long]8; $blocks = 0
        while (($p + 7) -le $Buf.Count -and $blocks -lt $Cap) {
            $hs = Read-Vint $Buf ($p + 4)
            if (-not $hs.Ok -or $hs.Value -le 0) { break }
            $hstart = $hs.Next
            $hend = $hstart + $hs.Value
            if ($hend -gt $Buf.Count) { break }
            $t = Read-Vint $Buf $hstart; $f = Read-Vint $Buf $t.Next
            if (-not $t.Ok -or -not $f.Ok) { break }
            $q = $f.Next
            $extra = 0; $data = 0
            if (($f.Value -band 1) -ne 0) { $x = Read-Vint $Buf $q; if (-not $x.Ok -or $x.Value -lt 0) { break }; $extra = $x.Value; $q = $x.Next }
            if (($f.Value -band 2) -ne 0) { $d = Read-Vint $Buf $q; if (-not $d.Ok -or $d.Value -lt 0) { break }; $data = $d.Value; $q = $d.Next }
            $blocks++
            if ($t.Value -eq 4) { $r.Parsed = $true; $r.Encrypted = $true; $r.HeadersEncrypted = $true; break }
            if ($t.Value -eq 1) {
                $r.Parsed = $true
                $af = Read-Vint $Buf $q
                if ($af.Ok -and ($af.Value -band 0x0001) -ne 0) { $r.MultiVolume = $true; if (($af.Value -band 0x0002) -ne 0) { $r.FirstVolume = $false } else { $r.FirstVolume = $true } }
            } elseif ($t.Value -eq 2 -or $t.Value -eq 3) {
                $ff = Read-Vint $Buf $q
                $u = Read-Vint $Buf $ff.Next   # unpacked size
                $a = Read-Vint $Buf $u.Next    # attributes
                $q2 = $a.Next
                if (($ff.Value -band 0x0002) -ne 0) { $q2 += 4 }
                if (($ff.Value -band 0x0004) -ne 0) { $q2 += 4 }
                $ci = Read-Vint $Buf $q2; $ho = Read-Vint $Buf $ci.Next; $nl = Read-Vint $Buf $ho.Next
                $nameAt = $nl.Next
                if ($t.Value -eq 2) {
                    $r.Count++
                    if ($nl.Ok -and $nl.Value -gt 0 -and ($nameAt + $nl.Value) -le $hend -and $names.Count -lt $Cap) {
                        [void]$names.Add([System.Text.Encoding]::UTF8.GetString($Buf, [int]$nameAt, [int]$nl.Value))
                    }
                }
                if ($extra -gt 0 -and $extra -le $hs.Value) {
                    $xp = $hend - $extra
                    $recs = 0
                    while ($xp -lt $hend -and $recs -lt 64) {
                        $recs++
                        $rs = Read-Vint $Buf $xp
                        if (-not $rs.Ok -or $rs.Value -le 0) { break }
                        $rt = Read-Vint $Buf $rs.Next
                        if ($rt.Ok -and $rt.Value -eq 1 -and $t.Value -eq 2) { $r.Encrypted = $true }
                        $xp = $rs.Next + $rs.Value
                    }
                }
            } elseif ($t.Value -eq 5) {
                $ef = Read-Vint $Buf $q
                if ($ef.Ok -and ($ef.Value -band 0x0001) -ne 0) { $r.MultiVolume = $true }
                break
            }
            $p = $hend + $data
        }
        if (-not $r.Parsed) { $r.Why = 'no main or encryption header' }
    }
    $r.Entries = @($names.ToArray())
    return $r
}

function Get-RarFacts {
    # $Base: where the archive starts in the file (0, or past a
    # self-extracting program's code).
    param([string]$Path, [long]$Length, [long]$Base = 0)
    # Headers up to the first data area are what is needed; 1 MB covers any
    # real main header plus the first file headers, and the walker skips packed
    # data by its declared size without reading it.
    $buf = Read-FileBytes -Path $Path -Offset $Base -Count 1048576
    return (Get-RarFactsFromBytes -Buf $buf)
}

# ---------------------------------------------------------------------------
# 7z (7zFormat.txt, 7zHeader.h): a 32-byte signature header (6-byte
# signature, version, StartHeaderCRC, NextHeaderOffset at +12, NextHeaderSize
# at +20, NextHeaderCRC at +28); the next header sits at 32 + NextHeaderOffset
# and begins with 0x01 (a plain Header) or 0x17 (an EncodedHeader whose
# StreamsInfo is plaintext by design). A coder id of 06 F1 07 01 is 7zAES. So:
# an EncodedHeader coded with 7zAES is -mhe, headers encrypted -- certain; a
# plain Header whose MainStreamsInfo carries 7zAES is -p, data encrypted and
# names visible -- certain; an EncodedHeader WITHOUT 7zAES is the default
# (an LZMA-compressed header), and whether the files inside are encrypted is
# inside it: the header is decoded (Invoke-LzmaDecode, below) and read as a
# plain Header. A header that cannot be decoded stays not determinable --
# said, not guessed. Every count read here is checked against the bytes left
# before any loop runs on it.
# ---------------------------------------------------------------------------

function Read-SevenZipDigests {
    # A Digests record (AllAreDefined byte, an optional bit vector, then four
    # bytes per defined digest) for $Count items. Returns the defined flags.
    param([byte[]]$Buf, [long]$Pos, [long]$Count)
    if ($Count -lt 0 -or $Count -gt ($Buf.Count - $Pos) * 8) { return @{ Ok = $false; Next = $Pos; Defined = @() } }
    if ($Pos -ge $Buf.Count) { return @{ Ok = $false; Next = $Pos; Defined = @() } }
    $all = [int]$Buf[$Pos]; $p = $Pos + 1
    $def = New-Object bool[] ([int]$Count)
    $n = 0
    if ($all -ne 0) { for ($i = 0; $i -lt $Count; $i++) { $def[$i] = $true }; $n = $Count }
    else {
        $nb = [long][math]::Ceiling($Count / 8.0)
        if (($p + $nb) -gt $Buf.Count) { return @{ Ok = $false; Next = $p; Defined = @() } }
        for ($i = 0; $i -lt $Count; $i++) { $b = [int]$Buf[$p + [math]::Floor($i / 8)]; if (($b -band (0x80 -shr ($i % 8))) -ne 0) { $def[$i] = $true; $n++ } }
        $p += $nb
    }
    if (($p + 4 * $n) -gt $Buf.Count) { return @{ Ok = $false; Next = $p; Defined = @() } }
    # The CRC of each item, -1 where none is defined.
    $vals = New-Object long[] ([int]$Count)
    $q = $p
    for ($i = 0; $i -lt $Count; $i++) { if ($def[$i]) { $vals[$i] = Get-U32 $Buf $q; $q += 4 } else { $vals[$i] = -1 } }
    return @{ Ok = $true; Next = ($p + 4 * $n); Defined = $def; Values = $vals }
}

function ConvertTo-SevenZipMethodId {
    # A coder id as 7-Zip reads it: a big-endian NUMBER (id = id << 8 | b),
    # so leading zero bytes do not change it -- 00 06 F1 07 01 is still
    # 7zAES. Hex of the value without leading zeros; Copy (0) is '00'.
    param([byte[]]$Buf, [long]$Pos, [int]$Size)
    $start = $Pos; $end = $Pos + $Size
    while ($start -lt ($end - 1) -and $Buf[$start] -eq 0) { $start++ }
    $hex = ''
    for ($i = $start; $i -lt $end; $i++) { $hex += ('{0:X2}' -f [int]$Buf[$i]) }
    return $hex
}

function Get-SevenZipCoderClass {
    # 'crypto' for 7-Zip's crypto range (06 F1 ..., 7zAES is 06 F1 07 01);
    # 'known' for the compression and filter methods 7-Zip's Methods.txt
    # lists (and the 04 F7 range of external codecs, zstd and the like);
    # 'unknown' otherwise -- a coder this audit cannot place is never read
    # as "no password".
    param([string]$Id)
    if ($Id -like '06F1*') { return 'crypto' }
    if ($Id.Length -eq 2 -and @('00', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '21') -contains $Id) { return 'known' }
    foreach ($pre in @('0301', '0303', '0304', '0401', '0402', '04F7')) { if ($Id.StartsWith($pre)) { return 'known' } }
    return 'unknown'
}

function Read-SevenZipStreamsInfo {
    # Parses PackInfo (0x06), CodersInfo (0x07) and SubStreamsInfo (0x08) from
    # $Pos up to and including the 0x00 that ends the StreamsInfo; returns the
    # coder ids seen (hex, as numbers -- see ConvertTo-SevenZipMethodId). Ok
    # is false on anything it does not understand, any count the remaining
    # bytes cannot hold, and a record list that reaches the end of the buffer
    # without its 0x00: 7-Zip reads such lists with no limit, so neither does
    # this, and every record consumes at least one byte, so the walk is
    # bounded by the buffer. Also returns what an EncodedHeader needs to be
    # decoded: PackPos, the first pack sizes, and (for the first 64 folders)
    # each folder's coders (Id, Props), unpack sizes and CRC (-1 if none);
    # FolderCount is the real count.
    param([byte[]]$Buf, [long]$Pos)
    $idSet = @{}
    $ids = New-Object System.Collections.ArrayList
    $packPos = -1
    $packSizes = New-Object System.Collections.ArrayList
    $folders = New-Object System.Collections.ArrayList
    $folderCount = 0
    $bad = { param($p) return @{ Ids = @($ids.ToArray()); Next = $p; Ok = $false; PackPos = $packPos; PackSizes = @($packSizes.ToArray()); Folders = @($folders.ToArray()); FolderCount = $folderCount } }
    $p = $Pos
    $numPack = 0
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x06) {
        $p++
        $pp = Read-SevenZipNumber $Buf $p; if (-not $pp.Ok -or $pp.Value -lt 0) { return (& $bad $p) }; $p = $pp.Next
        $packPos = $pp.Value
        $np = Read-SevenZipNumber $Buf $p; if (-not $np.Ok -or $np.Value -lt 0 -or $np.Value -gt ($Buf.Count - $np.Next)) { return (& $bad $p) }
        $p = $np.Next; $numPack = $np.Value
        $ended = $false
        while ($p -lt $Buf.Count) {
            $id = [int]$Buf[$p]; $p++
            if ($id -eq 0x00) { $ended = $true; break }
            if ($id -eq 0x09) {
                for ($i = 0; $i -lt $numPack; $i++) { $s = Read-SevenZipNumber $Buf $p; if (-not $s.Ok -or $s.Value -lt 0) { return (& $bad $p) }; if ($packSizes.Count -lt 64) { [void]$packSizes.Add([long]$s.Value) }; $p = $s.Next }
                continue
            }
            if ($id -eq 0x0A) { $dg = Read-SevenZipDigests -Buf $Buf -Pos $p -Count $numPack; if (-not $dg.Ok) { return (& $bad $p) }; $p = $dg.Next; continue }
            return (& $bad $p)
        }
        if (-not $ended) { return (& $bad $p) }
    }
    $folderOut = New-Object System.Collections.Generic.List[int]
    $folderCrc = @()
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x07) {
        $p++
        if ($p -ge $Buf.Count -or $Buf[$p] -ne 0x0B) { return (& $bad $p) }
        $p++
        $nf = Read-SevenZipNumber $Buf $p
        if (-not $nf.Ok -or $nf.Value -lt 0 -or $nf.Value -gt ($Buf.Count - $nf.Next)) { return (& $bad $p) }
        $p = $nf.Next
        $folderCount = [int]$nf.Value
        if ($p -ge $Buf.Count) { return (& $bad $p) }
        $ext = [int]$Buf[$p]; $p++
        if ($ext -ne 0) { return (& $bad $p) }
        for ($fi = 0; $fi -lt $nf.Value; $fi++) {
            $nc = Read-SevenZipNumber $Buf $p
            if (-not $nc.Ok -or $nc.Value -le 0 -or $nc.Value -gt 16) { return (& $bad $p) }
            $p = $nc.Next
            $inTotal = 0; $outTotal = 0
            $coders = @()
            for ($ci = 0; $ci -lt $nc.Value; $ci++) {
                if ($p -ge $Buf.Count) { return (& $bad $p) }
                $flag = [int]$Buf[$p]; $p++
                $idSize = $flag -band 0x0F
                if ($idSize -lt 1 -or ($p + $idSize) -gt $Buf.Count) { return (& $bad $p) }
                $hex = ConvertTo-SevenZipMethodId -Buf $Buf -Pos $p -Size $idSize
                if (-not $idSet.ContainsKey($hex)) { $idSet[$hex] = $true; [void]$ids.Add($hex) }
                $p += $idSize
                if (($flag -band 0x10) -ne 0) {
                    $ni = Read-SevenZipNumber $Buf $p; $no = Read-SevenZipNumber $Buf $ni.Next
                    if (-not $ni.Ok -or -not $no.Ok -or $ni.Value -lt 1 -or $ni.Value -gt 32 -or $no.Value -lt 1 -or $no.Value -gt 32) { return (& $bad $p) }
                    $p = $no.Next; $inTotal += $ni.Value; $outTotal += $no.Value
                } else { $inTotal += 1; $outTotal += 1 }
                $props = New-Object byte[] 0
                if (($flag -band 0x20) -ne 0) {
                    $ps = Read-SevenZipNumber $Buf $p
                    if (-not $ps.Ok -or $ps.Value -lt 0 -or $ps.Value -gt ($Buf.Count - $ps.Next)) { return (& $bad $p) }
                    if ($fi -lt 64 -and $ps.Value -gt 0 -and $ps.Value -le 64) { $props = New-Object byte[] ([int]$ps.Value); [Array]::Copy($Buf, [int]$ps.Next, $props, 0, [int]$ps.Value) }
                    $p = $ps.Next + $ps.Value
                }
                if ($fi -lt 64) { $coders += ,@{ Id = $hex; Props = $props } }
            }
            $bind = $outTotal - 1
            for ($i = 0; $i -lt $bind; $i++) { $x = Read-SevenZipNumber $Buf $p; $y = Read-SevenZipNumber $Buf $x.Next; if (-not $x.Ok -or -not $y.Ok) { return (& $bad $p) }; $p = $y.Next }
            $packed = $inTotal - $bind
            if ($packed -gt 1) { for ($i = 0; $i -lt $packed; $i++) { $x = Read-SevenZipNumber $Buf $p; if (-not $x.Ok) { return (& $bad $p) }; $p = $x.Next } }
            $folderOut.Add([int]$outTotal)
            if ($fi -lt 64) { [void]$folders.Add(@{ Coders = $coders; UnpackSizes = @(); Crc = [long]-1 }) }
        }
        # CodersUnpackSize (0x0C): one number per output stream of each folder;
        # then optional digests; then the 0x00 that ends CodersInfo.
        if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x0C) {
            $p++
            for ($fx = 0; $fx -lt $folderOut.Count; $fx++) {
                $sizes = @()
                for ($i = 0; $i -lt $folderOut[$fx]; $i++) { $x = Read-SevenZipNumber $Buf $p; if (-not $x.Ok) { return (& $bad $p) }; if ($fx -lt 64) { $sizes += [long]$x.Value }; $p = $x.Next }
                if ($fx -lt 64) { $folders[$fx].UnpackSizes = $sizes }
            }
        } else { return (& $bad $p) }
        $folderCrc = New-Object bool[] ([int]$nf.Value)
        if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x0A) {
            $p++
            $dg = Read-SevenZipDigests -Buf $Buf -Pos $p -Count $nf.Value
            if (-not $dg.Ok) { return (& $bad $p) }
            $folderCrc = $dg.Defined; $p = $dg.Next
            for ($i = 0; $i -lt $folders.Count; $i++) { $folders[$i].Crc = [long]$dg.Values[$i] }
        }
        if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x00) { $p++ } else { return (& $bad $p) }
    }
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x08) {
        # SubStreamsInfo: [0x0D streams per folder] [0x09 sizes] [0x0A
        # digests] 0x00 -- walked so the FilesInfo (the names) is reached.
        $p++
        $nfo = $folderOut.Count
        $streams = New-Object long[] $nfo
        for ($i = 0; $i -lt $nfo; $i++) { $streams[$i] = 1 }
        $ended = $false
        while ($p -lt $Buf.Count) {
            $id = [int]$Buf[$p]; $p++
            if ($id -eq 0x00) { $ended = $true; break }
            if ($id -eq 0x0D) {
                for ($i = 0; $i -lt $nfo; $i++) { $x = Read-SevenZipNumber $Buf $p; if (-not $x.Ok -or $x.Value -lt 0 -or $x.Value -gt 1000000) { return (& $bad $p) }; $streams[$i] = $x.Value; $p = $x.Next }
                continue
            }
            if ($id -eq 0x09) {
                $need = [long]0; foreach ($s in $streams) { if ($s -gt 1) { $need += $s - 1 } }
                if ($need -gt ($Buf.Count - $p)) { return (& $bad $p) }
                for ($i = 0; $i -lt $need; $i++) { $x = Read-SevenZipNumber $Buf $p; if (-not $x.Ok) { return (& $bad $p) }; $p = $x.Next }
                continue
            }
            if ($id -eq 0x0A) {
                $cnt = [long]0
                for ($i = 0; $i -lt $nfo; $i++) { $crcKnown = ($i -lt @($folderCrc).Count -and $folderCrc[$i]); if (-not ($streams[$i] -eq 1 -and $crcKnown)) { $cnt += $streams[$i] } }
                $dg = Read-SevenZipDigests -Buf $Buf -Pos $p -Count $cnt
                if (-not $dg.Ok) { return (& $bad $p) }
                $p = $dg.Next
                continue
            }
            return (& $bad $p)
        }
        if (-not $ended) { return (& $bad $p) }
    }
    # The 0x00 that ends this StreamsInfo is required: a buffer that stops
    # first is a header not read through.
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x00) { $p++ } else { return (& $bad $p) }
    return @{ Ids = @($ids.ToArray()); Next = $p; Ok = $true; PackPos = $packPos; PackSizes = @($packSizes.ToArray()); Folders = @($folders.ToArray()); FolderCount = $folderCount }
}

# ---------------------------------------------------------------------------
# LZMA, for the one thing 7-Zip compresses by default: its own header. The
# steps are those of LzmaSpec.cpp, the reference decoder Igor Pavlov placed in
# the public domain beside lzma-specification.txt in the LZMA SDK. Only what a
# 7z EncodedHeader needs: a raw stream, its five property bytes, a declared
# unpacked size.
#
# WRITTEN FOR A HOSTILE FILE. The output is capped ($MaxOut) and allocated
# once; every pass of the loop writes at least one byte or stops, so the loop
# runs at most $MaxOut times; input that runs out, a distance reaching before
# the start of the output and a malformed property byte are refusals, never a
# guess; and a stopwatch bounds the wall clock. A refusal leaves the archive
# "not determinable", which it was before this decoder existed.
#
# A class, not functions: the range decoder is called once per coded bit, and
# a class method costs a fraction of a PowerShell function call. Both engines
# (Windows PowerShell 5.0+ and pwsh) run it. Every value is held in an Int64
# and masked to 32 bits, because PowerShell reads 0xFFFFFFFF as Int32 -1 and
# widens an Int32 overflow to Double.
# ---------------------------------------------------------------------------

class DzLzmaRangeDecoder {
    [byte[]]$In
    [int]$InPos
    [int]$InEnd
    [long]$Range
    [long]$Code
    [int[]]$P
    [bool]$Starved

    [void]Normalize() {
        if ($this.Range -lt 16777216) {
            $this.Range = ($this.Range -shl 8) -band 4294967295
            $nb = 0
            if ($this.InPos -lt $this.InEnd) { $nb = [int]$this.In[$this.InPos]; $this.InPos++ } else { $this.Starved = $true }
            $this.Code = (($this.Code -shl 8) -bor $nb) -band 4294967295
        }
    }
    [int]Bit([int]$i) {
        $pr = $this.P[$i]
        $bound = ($this.Range -shr 11) * $pr
        $b = 0
        if ($this.Code -lt $bound) { $this.Range = $bound; $this.P[$i] = $pr + ((2048 - $pr) -shr 5) }
        else { $this.Range -= $bound; $this.Code -= $bound; $this.P[$i] = $pr - ($pr -shr 5); $b = 1 }
        $this.Normalize()
        return $b
    }
    [int]Tree([int]$base, [int]$bits) {
        $m = 1
        for ($i = 0; $i -lt $bits; $i++) { $m = ($m -shl 1) + $this.Bit($base + $m) }
        return ($m - (1 -shl $bits))
    }
    [int]ReverseTree([int]$base, [int]$bits) {
        $m = 1; $s = 0
        for ($i = 0; $i -lt $bits; $i++) { $b = $this.Bit($base + $m); $m = ($m -shl 1) + $b; $s = $s -bor ($b -shl $i) }
        return $s
    }
    [long]Direct([int]$bits) {
        $res = [long]0
        for ($i = 0; $i -lt $bits; $i++) {
            $this.Range = $this.Range -shr 1
            $b = 0
            if ($this.Code -ge $this.Range) { $this.Code -= $this.Range; $b = 1 }
            $this.Normalize()
            $res = ($res -shl 1) -bor $b
        }
        return $res
    }
    [int]Length([int]$base, [int]$posState) {
        if ($this.Bit($base) -eq 0) { return $this.Tree($base + 2 + ($posState -shl 3), 3) }
        if ($this.Bit($base + 1) -eq 0) { return (8 + $this.Tree($base + 130 + ($posState -shl 3), 3)) }
        return (16 + $this.Tree($base + 258, 8))
    }
}

function Invoke-LzmaDecode {
    # Returns @{ Ok; Bytes; Complete; Why }. Ok with Complete false means the
    # output stopped early (the cap, the clock, or an end marker before the
    # declared size) and Why says which; the bytes so far are returned.
    param([byte[]]$Data, [byte[]]$Props, [long]$UnpackSize, [int]$MaxOut = 262144, [double]$Seconds = 10)
    $r = @{ Ok = $false; Bytes = (New-Object byte[] 0); Complete = $false; Why = '' }
    if ($null -eq $Props -or $Props.Count -ne 5) { $r.Why = 'its LZMA properties are not five bytes'; return $r }
    $d = [int]$Props[0]
    if ($d -ge 225) { $r.Why = 'its LZMA property byte is out of range'; return $r }
    $lc = $d % 9; $d = [int][math]::Floor($d / 9); $lp = $d % 5; $pb = [int][math]::Floor($d / 5)
    # 7-Zip writes its headers with lc=3 lp=0; a larger literal context only
    # makes the probability table (0x300 << (lc+lp) entries) slow to set up.
    if (($lc + $lp) -gt 4) { $r.Why = 'its LZMA literal settings (lc+lp above 4) are not what 7-Zip writes for a header'; return $r }
    if ($UnpackSize -lt 0) { $r.Why = 'its declared size is negative'; return $r }
    if ($null -eq $Data -or $Data.Count -lt 5) { $r.Why = 'its packed stream is shorter than the range coder start'; return $r }
    if ($Data[0] -ne 0) { $r.Why = 'its range coder does not start with a zero byte'; return $r }
    $want = [int][math]::Min($UnpackSize, [long]$MaxOut)
    $z = [DzLzmaRangeDecoder]::new()
    $z.In = $Data; $z.InPos = 5; $z.InEnd = $Data.Count; $z.Starved = $false
    $code = [long]0
    for ($i = 1; $i -le 4; $i++) { $code = ($code -shl 8) -bor [long]$Data[$i] }
    $z.Code = $code; $z.Range = 4294967295
    if ($z.Code -eq $z.Range) { $r.Why = 'its range coder is corrupt'; return $r }
    # The probability model, laid out as in LzmaSpec.cpp: the state bits,
    # the distance slots and their trees, the two length coders, then the
    # literal coders (0x300 per literal context).
    $kIsRep = 192; $kIsRepG0 = 204; $kIsRepG1 = 216; $kIsRepG2 = 228; $kIsRep0Long = 240
    $kPosSlot = 432; $kPosDec = 688; $kAlign = 803; $kLen = 819; $kRepLen = 1333; $kLit = 1847
    $n = $kLit + (0x300 -shl ($lc + $lp))
    $z.P = New-Object int[] $n
    for ($i = 0; $i -lt $n; $i++) { $z.P[$i] = 1024 }
    $out = New-Object byte[] $want
    $pbMask = (1 -shl $pb) - 1; $lpMask = (1 -shl $lp) - 1
    $state = 0; $rep0 = [long]0; $rep1 = [long]0; $rep2 = [long]0; $rep3 = [long]0
    $o = 0; $marker = $false; $timedOut = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tick = 0
    while ($o -lt $want) {
        if ($z.Starved) { $r.Why = 'its packed stream ends before the header does'; return $r }
        $tick++
        if (($tick -band 1023) -eq 1 -and $sw.Elapsed.TotalSeconds -gt $Seconds) { $timedOut = $true; break }
        $posState = $o -band $pbMask
        if ($z.Bit(($state -shl 4) + $posState) -eq 0) {
            $prev = 0; if ($o -gt 0) { $prev = [int]$out[$o - 1] }
            $base = $kLit + 0x300 * ((($o -band $lpMask) -shl $lc) + ($prev -shr (8 - $lc)))
            $sym = 1
            if ($state -ge 7) {
                $mb = [int]$out[$o - $rep0 - 1]
                while ($sym -lt 0x100) {
                    $mbit = ($mb -shr 7) -band 1; $mb = $mb -shl 1
                    $bit = $z.Bit($base + ((1 + $mbit) -shl 8) + $sym)
                    $sym = ($sym -shl 1) -bor $bit
                    if ($mbit -ne $bit) { break }
                }
            }
            while ($sym -lt 0x100) { $sym = ($sym -shl 1) -bor $z.Bit($base + $sym) }
            $out[$o] = [byte]($sym - 0x100); $o++
            if ($state -lt 4) { $state = 0 } elseif ($state -lt 10) { $state -= 3 } else { $state -= 6 }
            continue
        }
        $len = 0
        if ($z.Bit($kIsRep + $state) -ne 0) {
            if ($o -eq 0) { $r.Why = 'its stream repeats a match before any output'; return $r }
            if ($z.Bit($kIsRepG0 + $state) -eq 0) {
                if ($z.Bit($kIsRep0Long + ($state -shl 4) + $posState) -eq 0) {
                    if ($state -lt 7) { $state = 9 } else { $state = 11 }
                    $out[$o] = $out[$o - $rep0 - 1]; $o++
                    continue
                }
            } else {
                if ($z.Bit($kIsRepG1 + $state) -eq 0) { $dist = $rep1 }
                else {
                    if ($z.Bit($kIsRepG2 + $state) -eq 0) { $dist = $rep2 } else { $dist = $rep3; $rep3 = $rep2 }
                    $rep2 = $rep1
                }
                $rep1 = $rep0; $rep0 = $dist
            }
            $len = $z.Length($kRepLen, $posState)
            if ($state -lt 7) { $state = 8 } else { $state = 11 }
        } else {
            $rep3 = $rep2; $rep2 = $rep1; $rep1 = $rep0
            $len = $z.Length($kLen, $posState)
            if ($state -lt 7) { $state = 7 } else { $state = 10 }
            $ls = $len; if ($ls -gt 3) { $ls = 3 }
            $slot = $z.Tree($kPosSlot + ($ls -shl 6), 6)
            if ($slot -lt 4) { $rep0 = [long]$slot }
            else {
                $nd = ($slot -shr 1) - 1
                # Int64 before the shift: slot 63 shifts by 30, past Int32.
                $dist = ([long](2 -bor ($slot -band 1))) -shl $nd
                if ($slot -lt 14) { $dist += $z.ReverseTree([int]($kPosDec + $dist - $slot), $nd) }
                else { $dist += ($z.Direct($nd - 4) -shl 4); $dist += $z.ReverseTree($kAlign, 4) }
                $rep0 = $dist
            }
            if ($rep0 -eq 4294967295) { $marker = $true; break }
        }
        if ($rep0 -ge $o) { $r.Why = 'its stream refers to data before the start of the header'; return $r }
        $len += 2
        $src = $o - [int]$rep0 - 1
        for ($k = 0; $k -lt $len -and $o -lt $want; $k++) { $out[$o] = $out[$src + $k]; $o++ }
    }
    if ($z.Starved) { $r.Why = 'its packed stream ends before the header does'; return $r }
    $r.Ok = $true
    $r.Complete = ([long]$o -eq $UnpackSize)
    if ($o -lt $want) { $short = New-Object byte[] $o; [Array]::Copy($out, $short, $o); $out = $short }
    $r.Bytes = $out
    if (-not $r.Complete) {
        if ($timedOut) { $r.Why = ('decoding stopped at the ' + [string]$Seconds + '-second limit') }
        elseif ($marker) { $r.Why = 'its stream ends before the size it declares' }
        else { $r.Why = ('the header is larger than the ' + [string]$MaxOut + '-byte decode cap') }
    }
    return $r
}

function Get-Crc32 {
    # CRC-32 (IEEE 802.3, reflected 0xEDB88320), the digest 7z stores.
    param([byte[]]$Buf)
    if ($null -eq $script:Crc32Table) {
        $t = New-Object long[] 256
        for ($n = 0; $n -lt 256; $n++) {
            $c = [long]$n
            for ($k = 0; $k -lt 8; $k++) { if (($c -band 1) -ne 0) { $c = 3988292384 -bxor ($c -shr 1) } else { $c = $c -shr 1 } }
            $t[$n] = $c
        }
        $script:Crc32Table = $t
    }
    $t = $script:Crc32Table
    $c = [long]4294967295
    foreach ($b in $Buf) { $c = $t[[int](($c -bxor $b) -band 0xFF)] -bxor ($c -shr 8) }
    return ($c -bxor 4294967295)
}

function Read-SevenZipHeader {
    # A plain Header, from the byte after its 0x01: ArchiveProperties, the
    # additional and main StreamsInfo (whose coders say whether the data is
    # encrypted), then FilesInfo with the names. Returns @{ Encrypted;
    # Entries; Why }; Encrypted is $null whenever the walk stopped before
    # it could rule a 7zAES coder out.
    param([byte[]]$Buf, [long]$Pos)
    $r = @{ Encrypted = $null; Entries = @(); Why = ''; NameCount = 0 }
    $p = $Pos
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x02) {
        # ArchiveProperties: {type, size, data} until type 0. Each step
        # moves forward and stays inside the buffer; there is no count
        # limit (7-Zip has none), and running out of buffer first is a
        # header not read through.
        $p++
        $ended = $false
        while ($p -lt $Buf.Count) {
            $pt = [int]$Buf[$p]; $p++
            if ($pt -eq 0x00) { $ended = $true; break }
            $s = Read-SevenZipNumber $Buf $p
            if (-not $s.Ok -or $s.Value -lt 0 -or $s.Value -gt ($Buf.Count - $s.Next)) { $r.Why = 'archive properties unreadable'; return $r }
            $p = $s.Next + $s.Value
        }
        if (-not $ended) { $r.Why = 'archive properties unreadable'; return $r }
    }
    $enc = $false; $walked = $true; $unknown = @()
    foreach ($sect in @(0x03, 0x04)) {
        if ($p -lt $Buf.Count -and $Buf[$p] -eq $sect) {
            $p++
            $si = Read-SevenZipStreamsInfo -Buf $Buf -Pos $p
            foreach ($id in @($si.Ids)) { $cls = Get-SevenZipCoderClass $id; if ($cls -eq 'crypto') { $enc = $true } elseif ($cls -eq 'unknown') { $unknown += $id } }
            if (-not $si.Ok) { $walked = $false; break }
            $p = $si.Next
        }
    }
    # After the streams come the FilesInfo (0x05) or the end of the Header
    # (0x00); anything else, or the end of the buffer, is a header not read
    # through.
    if ($walked -and -not ($p -lt $Buf.Count -and ($Buf[$p] -eq 0x05 -or $Buf[$p] -eq 0x00))) { $walked = $false }
    if (-not $walked) {
        if ($enc) { $r.Encrypted = $true } else { $r.Encrypted = $null }
        $r.Why = 'streams info not fully walked'
        return $r
    }
    if ($enc) { $r.Encrypted = $true }
    elseif ($unknown.Count) { $r.Encrypted = $null; $r.Why = 'coded with a method this audit does not know (' + ((@($unknown | Select-Object -First 3) | ForEach-Object { ConvertTo-PrintableText $_ }) -join ', ') + ')' }
    else { $r.Encrypted = $false }
    if ($p -lt $Buf.Count -and $Buf[$p] -eq 0x05) {
        $p++
        $nfi = Read-SevenZipNumber $Buf $p
        if (-not $nfi.Ok -or $nfi.Value -lt 0) { $r.Why = 'files info unreadable'; if (-not $enc) { $r.Encrypted = $null }; return $r }
        $p = $nfi.Next
        $names = New-Object System.Collections.ArrayList
        $ended = $false
        while ($p -lt $Buf.Count) {
            $pt = [int]$Buf[$p]; $p++
            if ($pt -eq 0x00) { $ended = $true; break }
            $ps = Read-SevenZipNumber $Buf $p
            if (-not $ps.Ok -or $ps.Value -lt 0 -or $ps.Value -gt ($Buf.Count - $ps.Next)) {
                # A files record that cannot be walked: the header was not
                # read through, so "no password" is not established.
                $r.Why = 'files info unreadable'
                if (-not $enc) { $r.Encrypted = $null }
                break
            }
            $p = $ps.Next
            if ($pt -eq 0x11 -and $ps.Value -gt 1 -and $Buf[$p] -eq 0) {
                $txt = [System.Text.Encoding]::Unicode.GetString($Buf, [int]($p + 1), [int]($ps.Value - 1))
                foreach ($nm in ($txt -split "`0")) { if ($nm) { $r.NameCount++; if ($names.Count -lt 500) { [void]$names.Add($nm) } } }
            }
            $p += $ps.Value
        }
        if (-not $ended -and -not $r.Why) {
            # The property list ran off the buffer: the names were not all
            # read, so "no credential file inside" is not established.
            $r.Why = 'files info unreadable'
            if (-not $enc) { $r.Encrypted = $null }
        }
        $r.Entries = @($names.ToArray())
    }
    return $r
}

function Get-SevenZipDecodePlan {
    # What an EncodedHeader without 7zAES needs to be read: one pack stream,
    # one folder, one coder -- LZMA (03 01 01, what 7-Zip writes by default)
    # or Copy (00). Anything else is named and left not determinable.
    param($Info)
    $bad = { param($w) return @{ Ok = $false; Why = $w } }
    if (-not $Info.Ok) { return (& $bad 'whose streams info could not be walked') }
    if (@($Info.Folders).Count -ne 1 -or @($Info.PackSizes).Count -ne 1 -or $Info.PackPos -lt 0) { return (& $bad 'with an unexpected stream layout') }
    $f = $Info.Folders[0]
    $codeIds = (@($f.Coders) | ForEach-Object { [string]$_.Id }) -join '+'
    if (@($f.Coders).Count -ne 1 -or @($f.UnpackSizes).Count -ne 1) { return (& $bad ('coded with ' + $codeIds + ', which this audit does not decode')) }
    $c = $f.Coders[0]
    if ($c.Id -ne '030101' -and $c.Id -ne '00') { return (& $bad ('coded with ' + $codeIds + ', which this audit does not decode')) }
    if ($c.Id -eq '030101' -and @($c.Props).Count -ne 5) { return (& $bad 'whose LZMA properties are malformed') }
    # An offset past 2^62 would widen to Double when 32 is added.
    if ($Info.PackPos -gt 4611686018427387904 -or [long]$Info.PackSizes[0] -le 0 -or [long]$f.UnpackSizes[0] -lt 0) { return (& $bad 'whose packed stream position or size is impossible') }
    return @{ Ok = $true; Why = ''; Coder = [string]$c.Id; Props = [byte[]]$c.Props; PackOffset = (32 + [long]$Info.PackPos); PackSize = [long]$Info.PackSizes[0]; UnpackSize = [long]$f.UnpackSizes[0]; Crc = [long]$f.Crc }
}

function Resolve-SevenZipEncodedHeader {
    # Decodes the packed header $Plan names and reads it as a plain Header.
    # Returns @{ Encrypted; Entries; Why; Decoded; Complete }. A header read
    # only in part is trusted only for what it shows: the coders come before
    # the names, so a 7zAES coder seen in the part is certain, while its
    # absence is not -- that stays not determinable.
    param($Plan, [byte[]]$Packed, [int]$MaxOut = 262144, [double]$Seconds = 10)
    $r = @{ Encrypted = $null; Entries = @(); Why = ''; Decoded = $false; Complete = $false; NameCount = 0 }
    if ($null -eq $Packed -or [long]$Packed.Count -lt $Plan.PackSize) { $r.Why = 'compressed header: its packed bytes could not be read in full, so a password is not determinable'; return $r }
    if ($Plan.Coder -eq '00') {
        $n = [int][math]::Min([math]::Min($Plan.UnpackSize, [long]$Packed.Count), [long]$MaxOut)
        $bytes = New-Object byte[] $n; [Array]::Copy($Packed, $bytes, $n)
        $d = @{ Ok = $true; Bytes = $bytes; Complete = ([long]$n -eq $Plan.UnpackSize); Why = 'its stored header is larger than the read cap' }
    } else {
        $d = Invoke-LzmaDecode -Data $Packed -Props $Plan.Props -UnpackSize $Plan.UnpackSize -MaxOut $MaxOut -Seconds $Seconds
        if (-not $d.Ok) { $r.Why = 'compressed header could not be decompressed (' + $d.Why + '), so a password is not determinable'; return $r }
    }
    $bytes = [byte[]]$d.Bytes
    $r.Complete = [bool]$d.Complete
    if ($r.Complete -and $Plan.Crc -ge 0 -and (Get-Crc32 $bytes) -ne $Plan.Crc) { $r.Why = 'compressed header failed its CRC check once decompressed, so a password is not determinable'; return $r }
    if ($bytes.Count -lt 1 -or $bytes[0] -ne 0x01) { $r.Why = 'compressed header did not decompress to a 7z header, so a password is not determinable'; return $r }
    $h = Read-SevenZipHeader -Buf $bytes -Pos 1
    $r.Decoded = $true
    $r.Entries = @($h.Entries); $r.NameCount = [int]$h.NameCount
    if ($r.Complete) { $r.Encrypted = $h.Encrypted; $r.Why = [string]$h.Why; return $r }
    if ($h.Encrypted -eq $true) { $r.Encrypted = $true; return $r }
    $r.Why = 'compressed header decompressed only in part (' + [string]$d.Why + '), so a password is not determinable'
    return $r
}

function Get-SevenZipFactsFromBytes {
    param([byte[]]$Sig, [long]$FileLength, [byte[]]$NextHeader, [switch]$SignatureOnly)
    $r = @{ Parsed = $false; Encrypted = $null; HeadersEncrypted = $false; MultiVolume = $false; Beyond = $false; Entries = @(); Why = ''; NextOffset = -1; NextSize = 0; Decode = $null; HeaderDecoded = $false; NameCount = 0 }
    if ($null -eq $Sig -or $Sig.Count -lt 32) { $r.Why = 'too short for a signature header'; return $r }
    $off = Get-U64 $Sig 12; $size = Get-U64 $Sig 20
    $r.NextOffset = $off; $r.NextSize = $size
    if ($off -lt 0 -or $size -lt 0) { $r.Why = 'a negative header offset or size'; return $r }
    if ((32 + $off + $size) -gt $FileLength) {
        # 7-Zip writes the header at the END of the last volume, so a file
        # that does not reach it is either the first of several volumes or
        # a truncated archive. Which one is the caller's call, from the name
        # and the siblings beside it.
        $r.Parsed = $true; $r.Beyond = $true; $r.Why = 'the header lies beyond this file'
        return $r
    }
    if ($size -eq 0) { $r.Parsed = $true; $r.Encrypted = $false; $r.Why = 'empty archive'; return $r }
    if ($SignatureOnly) { $r.Parsed = $true; $r.Why = 'next header not read yet'; return $r }
    if ($null -eq $NextHeader -or $NextHeader.Count -lt 1) { $r.Why = 'next header unreadable'; return $r }
    $r.Parsed = $true
    if ($NextHeader[0] -eq 0x17) {
        $si = Read-SevenZipStreamsInfo -Buf $NextHeader -Pos 1
        if (@(@($si.Ids) | Where-Object { (Get-SevenZipCoderClass $_) -eq 'crypto' }).Count) { $r.Encrypted = $true; $r.HeadersEncrypted = $true; return $r }
        # The default: the header itself is LZMA-compressed. Whether the
        # files are encrypted is inside it, so the caller decodes it from the
        # plan; until then it is not determinable, and stays so if the
        # decode is refused.
        $plan = Get-SevenZipDecodePlan -Info $si
        if ($plan.Ok) { $r.Decode = $plan; $r.Why = 'compressed header: not decompressed yet, so a password is not determinable' }
        else { $r.Why = 'compressed header ' + $plan.Why + ', so a password is not determinable' }
        return $r
    }
    if ($NextHeader[0] -eq 0x01) {
        $h = Read-SevenZipHeader -Buf $NextHeader -Pos 1
        $r.Encrypted = $h.Encrypted; $r.Entries = @($h.Entries); $r.NameCount = [int]$h.NameCount; if ($h.Why) { $r.Why = $h.Why }
        return $r
    }
    $r.Why = 'next header of an unknown kind'
    return $r
}

function Get-SevenZipFacts {
    # $SpanPaths / $SpanSizes: this file first, then the later volumes of its
    # set in order, so a header that lies beyond the first volume (where
    # 7-Zip always puts it) is read from the volume that holds it.
    # $DecodeSeconds bounds the decompression of a compressed header;
    # -NoDecode leaves a compressed header for the caller to decode later
    # (Invoke-SevenZipHeaderDecode), with the plan in .Decode.
    # $Base: where the archive starts (past a self-extracting program's
    # code); every 7z offset is relative to it, and the length is what
    # follows it.
    param([string]$Path, [long]$Length, [string[]]$SpanPaths = @(), [long[]]$SpanSizes = @(), [double]$DecodeSeconds = 10, [switch]$NoDecode, [long]$Base = 0)
    $span = ($SpanPaths.Count -gt 1)
    $total = $Length
    if ($span) {
        $total = 0; foreach ($s in $SpanSizes) { $total += [long]$s }
        $sig = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset 0 -Count 32
    } else { $total = $Length - $Base; $sig = Read-FileBytes -Path $Path -Offset $Base -Count 32 }
    $pre = Get-SevenZipFactsFromBytes -Sig $sig -FileLength $total -NextHeader $null -SignatureOnly
    if (-not $pre.Parsed -or $pre.Beyond -or $pre.NextSize -le 0) {
        if ($pre.Beyond -and $span) { $pre.Why = 'the header lies beyond the volumes present here' }
        return $pre
    }
    $want = [int][math]::Min([long]$pre.NextSize, 1048576)
    if ($span) { $nh = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset (32 + $pre.NextOffset) -Count $want }
    else { $nh = Read-FileBytes -Path $Path -Offset ($Base + 32 + $pre.NextOffset) -Count $want }
    $f = Get-SevenZipFactsFromBytes -Sig $sig -FileLength $total -NextHeader $nh
    $f.Base = $Base
    if ($null -eq $f.Decode) {
        if ([long]$pre.NextSize -gt [long]$want -and $f.Encrypted -ne $true) {
            # A plain header larger than the read: only a 7zAES coder seen in
            # the part read is certain.
            $f.Encrypted = $null; $f.Why = 'its header is larger than the 1 MiB read, and the part read does not settle it'
        }
        return $f
    }
    if ($NoDecode) { return $f }
    return (Invoke-SevenZipHeaderDecode -Facts $f -Path $Path -Total $total -SpanPaths $SpanPaths -SpanSizes $SpanSizes -Seconds $DecodeSeconds -Base $Base)
}

function Invoke-SevenZipHeaderDecode {
    # Reads the packed header the plan in $Facts.Decode names, decodes it and
    # updates $Facts; returns it.
    param($Facts, [string]$Path, [long]$Total, [string[]]$SpanPaths = @(), [long[]]$SpanSizes = @(), [double]$Seconds = 10, [long]$Base = 0)
    $f = $Facts
    $pl = $f.Decode
    if ($pl.PackSize -gt 1048576 -or ($pl.PackOffset + $pl.PackSize) -gt $Total) {
        $f.Why = 'compressed header: its packed stream lies outside the file or is larger than 1 MiB, so a password is not determinable'
        return $f
    }
    if ($SpanPaths.Count -gt 1) { $packed = Read-SpanBytes -Paths $SpanPaths -Sizes $SpanSizes -Offset $pl.PackOffset -Count ([int]$pl.PackSize) }
    else { $packed = Read-FileBytes -Path $Path -Offset ($Base + $pl.PackOffset) -Count ([int]$pl.PackSize) }
    $res = Resolve-SevenZipEncodedHeader -Plan $pl -Packed $packed -Seconds $Seconds
    $f.HeaderDecoded = [bool]$res.Decoded
    $f.Encrypted = $res.Encrypted
    $f.Entries = @($res.Entries); $f.NameCount = [int]$res.NameCount
    $f.Why = [string]$res.Why
    return $f
}

# ---------------------------------------------------------------------------
# SELF-EXTRACTING ARCHIVES. An SFX is a Windows program with the archive
# appended after its last section -- the PE "overlay": WinRAR SFX, 7-Zip
# -sfx, ZIP SFX. Any archiver opens it, and a double-click unpacks it, so a
# password-protected SFX made here is the same shape as a password-protected
# .rar. The layout is Microsoft's PE format specification: e_lfanew at 0x3C
# names the "PE\0\0" header; the COFF header holds the section count and the
# optional-header size; the optional header's data directory 4 is the
# certificate table, whose address is a FILE offset; each 40-byte section
# entry gives SizeOfRawData (+16) and PointerToRawData (+20). The overlay is
# what lies past the furthest section, less the certificate table. Every
# offset is checked against the bytes read, so a crafted header cannot send
# a read anywhere else.
# ---------------------------------------------------------------------------

function Get-PeOverlayInfo {
    # $Head: the first 4096 bytes. Returns @{ IsPe; Parsed; Regions; Why };
    # Regions are @{ Start; End } file ranges of overlay data (before and
    # after a certificate table).
    param([byte[]]$Head, [long]$FileLength)
    $r = @{ IsPe = $false; Parsed = $false; Regions = @(); Why = '' }
    if ($null -eq $Head -or $Head.Count -lt 64 -or $Head[0] -ne 0x4D -or $Head[1] -ne 0x5A) { $r.Why = 'not a program'; return $r }
    $r.IsPe = $true
    $pe = Get-U32 $Head 0x3C
    if ($pe -lt 64 -or ($pe + 24) -gt $Head.Count -or -not (Test-BytesAt $Head $pe @(0x50, 0x45, 0x00, 0x00))) { $r.Why = 'no PE header within the first 4 KiB'; return $r }
    $nsec = Get-U16 $Head ($pe + 6)
    $optSize = Get-U16 $Head ($pe + 20)
    if ($nsec -lt 1 -or $nsec -gt 96) { $r.Why = 'a section count out of range'; return $r }
    $opt = $pe + 24
    if ($optSize -lt 2 -or ($opt + $optSize) -gt $Head.Count) { $r.Why = 'an optional header past the first 4 KiB'; return $r }
    $magic = Get-U16 $Head $opt
    if ($magic -eq 0x10B) { $dd = 96 } elseif ($magic -eq 0x20B) { $dd = 112 } else { $r.Why = 'an optional header of an unknown kind'; return $r }
    $certStart = -1; $certSize = 0
    if (($dd + 40) -le $optSize -and (Get-U32 $Head ($opt + $dd - 4)) -gt 4) {
        $certStart = Get-U32 $Head ($opt + $dd + 32); $certSize = Get-U32 $Head ($opt + $dd + 36)
    }
    $sec = $opt + $optSize
    if (($sec + 40 * $nsec) -gt $Head.Count) { $r.Why = 'a section table past the first 4 KiB'; return $r }
    $end = [long]0
    for ($i = 0; $i -lt $nsec; $i++) {
        $s = $sec + 40 * $i
        $size = Get-U32 $Head ($s + 16); $ptr = Get-U32 $Head ($s + 20)
        if ($size -gt 0 -and ($ptr + $size) -gt $end) { $end = $ptr + $size }
    }
    if ($end -le 0 -or $end -gt $FileLength) { $r.Why = 'sections that reach past the end of the file'; return $r }
    $r.Parsed = $true
    $r.CertStart = -1; $r.CertSize = 0
    $regions = @()
    if ($certSize -gt 0 -and $certStart -ge $end -and ($certStart + $certSize) -le $FileLength) {
        $r.CertStart = [long]$certStart; $r.CertSize = [long]$certSize
        if ($certStart -gt $end) { $regions += ,@{ Start = $end; End = [long]$certStart } }
        if (($certStart + $certSize) -lt $FileLength) { $regions += ,@{ Start = [long]($certStart + $certSize); End = $FileLength } }
    } elseif ($end -lt $FileLength) { $regions += ,@{ Start = $end; End = $FileLength } }
    $r.Regions = $regions
    return $r
}

function Test-SfxCandidate {
    # A signature inside a program's overlay is only a candidate: the bytes
    # behind it must be that format's own header, checked the way the
    # format checks itself -- 7z's StartHeaderCRC over bytes 12..31
    # (7zFormat.txt), RAR 5.0's CRC32 over its first block (UnRAR
    # headers5.hpp), RAR 4.x's HEAD_CRC over the main header, a cabinet's
    # size, file-table offset and version 1.3 (Microsoft Cabinet Format).
    # A ZIP is checked by parsing it (its end record must resolve). The
    # caller uses the 7z and RAR checks to RANK, not to drop: an archiver may
    # still open an archive whose header CRC is wrong, so a broken CRC must
    # not hide one; a cabinet that fails is dropped (it cannot carry a
    # password, and a four-byte magic collides in ordinary data).
    param([string]$Kind, [byte[]]$B, [long]$Remaining)
    if ($null -eq $B) { return $false }
    switch ($Kind) {
        '7z' {
            if ($B.Count -lt 32) { return $false }
            $part = New-Object byte[] 20; [Array]::Copy($B, 12, $part, 0, 20)
            return ((Get-Crc32 $part) -eq (Get-U32 $B 8))
        }
        'rar5' {
            if ($B.Count -lt 16) { return $false }
            $v = Read-Vint $B 12
            if (-not $v.Ok -or $v.Value -lt 1 -or ($v.Next + $v.Value) -gt $B.Count) { return $false }
            $n = [int]($v.Next + $v.Value - 12)
            $part = New-Object byte[] $n; [Array]::Copy($B, 12, $part, 0, $n)
            return ((Get-Crc32 $part) -eq (Get-U32 $B 8))
        }
        'rar4' {
            if ($B.Count -lt 20) { return $false }
            $size = Get-U16 $B 12
            if ($size -lt 7 -or (7 + $size) -gt $B.Count) { return $false }
            $n = $size - 2
            $part = New-Object byte[] $n; [Array]::Copy($B, 9, $part, 0, $n)
            return (((Get-Crc32 $part) -band 0xFFFF) -eq (Get-U16 $B 7))
        }
        'cab' {
            if ($B.Count -lt 26) { return $false }
            $cb = Get-U32 $B 8; $cf = Get-U32 $B 16
            return ($cb -ge 0x24 -and $cb -le $Remaining -and $cf -lt $cb -and $B[24] -eq 3 -and $B[25] -eq 1)
        }
        'zip' { return $true }
    }
    return $false
}

function Find-SfxArchive {
    # Every archive signature in $Window that starts before $Limit and passes
    # Test-SfxCandidate, in order. 7-Zip's installer SFX puts a configuration
    # block before the archive, and an attacker can put a decoy there; the
    # caller grades every candidate and keeps the most severe. At most 64
    # signature look-alikes are examined: past that the window is called
    # crowded, not clean.
    param([byte[]]$Window, [long]$Limit = 65536, [long]$Remaining = [long]::MaxValue)
    $r = @{ Candidates = @(); TooMany = $false }
    if ($null -eq $Window -or $Window.Count -lt 8) { return $r }
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString($Window)
    $hits = New-Object System.Collections.ArrayList
    $looked = 0
    foreach ($sig in @(('Rar!' + [char]0x1A + [char]0x07), ('7z' + [char]0xBC + [char]0xAF + [char]0x27 + [char]0x1C), ('PK' + [char]0x03 + [char]0x04), 'MSCF')) {
        $from = 0
        while ($from -lt $text.Length) {
            $i = $text.IndexOf($sig, $from, [System.StringComparison]::Ordinal)
            if ($i -lt 0 -or $i -ge $Limit) { break }
            $looked++
            if ($looked -gt 64) { $r.TooMany = $true; break }
            $n = [int][math]::Min(512, $Window.Count - $i)
            $slice = New-Object byte[] $n; [Array]::Copy($Window, $i, $slice, 0, $n)
            $k = Get-ArchiveKind -Head $slice
            if (@('zip', 'rar4', 'rar5', '7z', 'cab') -contains $k) {
                $ok = Test-SfxCandidate -Kind $k -B $slice -Remaining ($Remaining - $i)
                if ($ok -or $k -ne 'cab') { [void]$hits.Add(@{ Offset = [long]$i; Kind = $k; Checked = [bool]$ok }) }
            }
            $from = $i + 1
        }
        if ($r.TooMany) { break }
    }
    $r.Candidates = @($hits.ToArray() | Sort-Object @{ Expression = { [long]$_.Offset } })
    return $r
}

function Get-CertPaddingRegions {
    # The certificate table is not hashed by Authenticode, so bytes padded
    # into it keep a signature Valid (Microsoft, CVE-2013-3900). A
    # WIN_CERTIFICATE is dwLength(4), wRevision 0x0200, wCertificateType 2
    # (PKCS#7), then a DER SEQUENCE; whatever lies past that SEQUENCE inside
    # the table is padding, and is scanned. A table that is not a
    # WIN_CERTIFICATE at all is scanned whole. Regions are marked InCert:
    # an archive found there is graded whatever the signature says.
    param([long]$CertStart, [long]$CertSize, [byte[]]$CertHead)
    $whole = @(@{ Start = $CertStart; End = ($CertStart + $CertSize); InCert = $true })
    if ($null -eq $CertHead -or $CertHead.Count -lt 12) { return $whole }
    $len = Get-U32 $CertHead 0
    if ((Get-U16 $CertHead 4) -ne 0x0200 -or (Get-U16 $CertHead 6) -ne 0x0002 -or $len -lt 12 -or $len -gt $CertSize -or $CertHead[8] -ne 0x30) { return $whole }
    $l1 = [int]$CertHead[9]
    if ($l1 -lt 0x80) { $der = 2 + $l1 }
    elseif ($l1 -eq 0x81) { $der = 3 + [int]$CertHead[10] }
    elseif ($l1 -eq 0x82) { $der = 4 + ([int]$CertHead[10] -shl 8) + [int]$CertHead[11] }
    elseif ($l1 -eq 0x83 -and $CertHead.Count -ge 13) { $der = 5 + ([int]$CertHead[10] -shl 16) + ([int]$CertHead[11] -shl 8) + [int]$CertHead[12] }
    else { return $whole }
    $blobEnd = $CertStart + 8 + [long]$der
    if ($blobEnd -gt ($CertStart + $CertSize)) { return $whole }
    if ($blobEnd -lt ($CertStart + $CertSize)) { return @(@{ Start = $blobEnd; End = ($CertStart + $CertSize); InCert = $true }) }
    return @()
}

function Find-SfxInFile {
    # The I/O half: reads the program's head, the certificate table's head,
    # and one window per overlay region. Returns @{ Parsed; HasCert;
    # Candidates (Base, Kind, InCert); Why }. Parsed is false when the header
    # could not be read -- that program was NOT checked, and the caller says so.
    param([string]$Path, [long]$Length)
    $r = @{ Parsed = $false; HasCert = $false; Candidates = @(); Why = '' }
    $pe = Get-PeOverlayInfo -Head (Read-FileBytes -Path $Path -Offset 0 -Count 4096) -FileLength $Length
    if (-not $pe.Parsed) { $r.Why = $pe.Why; return $r }
    $r.Parsed = $true
    $regions = @()
    foreach ($reg in @($pe.Regions)) { $regions += ,@{ Start = $reg.Start; End = $reg.End; InCert = $false } }
    if ([long]$pe.CertSize -gt 0) {
        $r.HasCert = $true
        $regions += @(Get-CertPaddingRegions -CertStart $pe.CertStart -CertSize $pe.CertSize -CertHead (Read-FileBytes -Path $Path -Offset $pe.CertStart -Count 16))
    }
    $cands = @(); $crowded = $false
    foreach ($reg in $regions) {
        $len = [long]$reg.End - [long]$reg.Start
        if ($len -lt 32) { continue }
        $w = Read-FileBytes -Path $Path -Offset $reg.Start -Count ([int][math]::Min($len, [long](65536 + 512)))
        $f = Find-SfxArchive -Window $w -Limit 65536 -Remaining $len
        if ($f.TooMany) { $crowded = $true }
        foreach ($c in @($f.Candidates)) { $cands += ,@{ Base = ([long]$reg.Start + [long]$c.Offset); Kind = [string]$c.Kind; InCert = [bool]$reg.InCert; Checked = [bool]$c.Checked } }
    }
    $r.Candidates = $cands
    if ($crowded -and $cands.Count -eq 0) { $r.Parsed = $false; $r.Why = 'more archive-signature look-alikes past its code than are checked' }
    if ($cands.Count -eq 0 -and -not $r.Why) { $r.Why = 'no archive in the first 64 KiB past its code' }
    return $r
}

# CAB (Microsoft Cabinet Format): flags at 0x1E carry cfhdrPREV_CABINET 0x0001
# and cfhdrNEXT_CABINET 0x0002. CAB has no encryption.
function Get-CabFactsFromBytes {
    param([byte[]]$Head)
    $r = @{ Parsed = $false; Encrypted = $false; MultiVolume = $false; Entries = @(); Why = '' }
    if ($null -eq $Head -or $Head.Count -lt 0x24) { $r.Why = 'too short'; return $r }
    $r.Parsed = $true
    $flags = Get-U16 $Head 0x1E
    if (($flags -band 0x0003) -ne 0) { $r.MultiVolume = $true }
    return $r
}

# ---------------------------------------------------------------------------
# NAMES. A volume set is told by its file names too, because the first volume
# of a split RAR or 7z may be the only part still here, and the remaining
# parts of a set may be what already left. 7-Zip's later raw volumes (.002 on)
# carry no signature at all, so a set's members are counted by name.
# ---------------------------------------------------------------------------

function Get-VolumeSetKey {
    # @{ Set = <the set's base name, lower-cased>; Index; Alone = $true when the
    # name shape alone says "a volume of a set" } or $null for a name that is
    # not a volume shape.
    param([string]$Name)
    if (-not $Name) { return $null }
    $n = $Name.ToLowerInvariant()
    if ($n -match '^(.+)\.part(\d+)\.rar$') { return @{ Set = $Matches[1] + '.rar'; Index = [int]$Matches[2]; Alone = $true } }
    if ($n -match '^(.+)\.r(\d\d)$') { return @{ Set = $Matches[1] + '.rar'; Index = ([int]$Matches[2] + 1); Alone = $true } }
    if ($n -match '^(.+)\.z(\d\d)$') { return @{ Set = $Matches[1] + '.zip'; Index = [int]$Matches[2]; Alone = $true } }
    if ($n -match '^(.+\.(7z|zip|rar|tar|tgz|tar\.gz|cab|bin|dat))\.(\d{3})$') { return @{ Set = $Matches[1]; Index = [int]$Matches[3]; Alone = $true } }
    if ($n -match '^(.+)\.(\d{3})$') { return @{ Set = $Matches[1]; Index = [int]$Matches[2]; Alone = $false } }
    if ($n -match '^(.+)\.(rar|zip)$') { return @{ Set = $n; Index = 0; Alone = $false } }
    return $null
}

$script:ArchiveExt = @('.zip', '.rar', '.7z', '.cab', '.gz', '.tgz', '.tar', '.bz2', '.xz', '.z01', '.001')
# ZIP by signature, never an archive for this purpose.
$script:PackageExt = @('.docx', '.docm', '.dotx', '.xlsx', '.xlsm', '.xltx', '.pptx', '.pptm', '.potx', '.vsdx', '.odt', '.ods', '.odp',
                       '.msix', '.appx', '.msixbundle', '.appxbundle', '.vsix', '.nupkg', '.jar', '.war', '.aar', '.whl', '.egg', '.xpi', '.crx', '.apk', '.ipa', '.appv', '.epub', '.xap', '.oxt', '.sketch', '.fig', '.kmz', '.snupkg')
# A cloud-only placeholder: FILE_ATTRIBUTE_OFFLINE, RECALL_ON_OPEN,
# RECALL_ON_DATA_ACCESS. Reading one would download it.
$script:CloudMask = 0x1000 -bor 0x40000 -bor 0x400000

function Get-ArchiveEntryReason {
    # The credential class, for a RELATIVE entry name (the archive's own
    # names, forward or back slashes). The sibling rule for absolute local
    # paths is persistence_extra.ps1's Get-UploadSourceReason; entry names have
    # no drive and no profile root, so the classes that survive are the ones a
    # bare name can carry. A bare .key is NOT here: a Keynote presentation is
    # name.key; only a .key inside a folder that holds keys counts.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    $n = ([string]$Name).Trim() -replace '/', '\'
    $out = @()
    if ($n -match '(?i)\.(pst|ost|kdbx|kdb|ppk|pfx|p12|keychain|wallet)$' -or $n -match '(?i)(^|\\)wallet\.dat$' -or
        $n -match '(?i)(^|\\)id_(rsa|dsa|ecdsa|ed25519)$' -or $n -match '(?i)(^|\\)(\.ssh|ssl|private|keys|certs|pki)\\[^\\]+\.key$') {
        $out += 'a mail store, a password database, a wallet or a private key'
    }
    if ($n -match '(?i)(^|\\)(ntds\.dit|SAM|SYSTEM|SECURITY)(\.(sav|bak|old|hive))?$') {
        $out += 'a copy of a registry hive or of the directory database, which holds credentials'
    }
    if ($n -match '(?i)(^|\\)(Login Data|Cookies|Web Data|key4\.db|key3\.db|logins\.json|cookies\.sqlite|Local State)$') {
        $out += "a browser's saved-password, cookie or session store"
    }
    return $out
}

function Get-RoleLabel {
    param([string]$Role)
    switch ($Role) {
        'downloads'   { return 'a Downloads folder' }
        'temp'        { return 'a temporary folder' }
        'systemp'     { return 'a system temporary folder' }
        'public'      { return 'the shared Public folder' }
        'recycle'     { return 'the recycle bin' }
        'programdata' { return 'ProgramData' }
        default       { return 'a staging folder' }
    }
}

function Get-ArchiveVerdict {
    # The table. $Zone: -1 no mark, 0 a local-machine mark, 1..4 a mark a
    # download writes (intranet, trusted, Internet, restricted), -2 a mark
    # that exists but could not be read. $Encrypted: $true, $false or $null
    # (not determinable). $Role: where the file sits. Returns @{ Sev; Class;
    # Clause }.
    param([int]$Zone, $Encrypted, [bool]$MultiVolume, [string[]]$EntryReasons, [string]$Role = 'other', [string]$Kind = 'zip')
    $downloaded = ($Zone -ge 1 -and $Zone -le 4)
    $reasons = @($EntryReasons | Where-Object { $_ })
    $enc = ($Encrypted -eq $true)
    $und = ($null -eq $Encrypted)
    $creds = ($reasons.Count -gt 0)
    $strong = (($enc -and $MultiVolume) -or ($creds -and ($enc -or $MultiVolume)))
    if ($downloaded) {
        # Anyone can write that stream. The strongest shape, marked, sitting
        # where no browser saves a download, is not cleared by the mark.
        if ($strong -and $Role -ne 'downloads' -and $Role -ne 'other') {
            $c = 'carries a download mark but sits in ' + (Get-RoleLabel $Role) + ', where no browser saves a download, and is '
            if ($enc -and $MultiVolume) { $c += 'password-protected AND split into volumes' }
            elseif ($enc) { $c += 'password-protected and packs credential files' }
            else { $c += 'split into volumes and packs credential files' }
            return @{ Sev = 'WARNING'; Class = 'marked-misplaced'; Clause = $c }
        }
        if ($strong) { return @{ Sev = 'OK'; Class = 'marked-strong'; Clause = '' } }
        return @{ Sev = 'OK'; Class = 'downloaded'; Clause = '' }
    }
    if ($enc -and $MultiVolume) {
        $c = 'is password-protected AND split into volumes'
        if ($creds) { $c += ', and packs credential files' }
        return @{ Sev = 'CRITICAL'; Class = 'packed'; Clause = $c }
    }
    if ($enc) {
        if ($creds) { return @{ Sev = 'CRITICAL'; Class = 'packed'; Clause = 'is password-protected and packs credential files' } }
        return @{ Sev = 'WARNING'; Class = 'packed'; Clause = 'is password-protected' }
    }
    if ($MultiVolume) {
        if ($creds) { return @{ Sev = 'CRITICAL'; Class = 'packed'; Clause = 'is split into volumes and packs credential files' } }
        # A cabinet cannot carry a password and installers write spanned
        # sets; a split set in Downloads is how torrent and file-sharing
        # clients deliver large files. Both are named context.
        if ($Kind -eq 'cab') { return @{ Sev = 'OK'; Class = 'cabset'; Clause = '' } }
        if ($Role -eq 'downloads') { return @{ Sev = 'OK'; Class = 'volumeset-download'; Clause = '' } }
        $c = 'is split into volumes'
        if ($und) { $c += ' (whether it is also password-protected is not determinable from its header)' }
        return @{ Sev = 'WARNING'; Class = 'packed'; Clause = $c }
    }
    if ($creds) {
        # Plain and single-volume, but it holds the credential class: packed,
        # not hidden. A person's own backup is the twin, so this is WARNING,
        # and the line names what it saw so the owner can decide.
        return @{ Sev = 'WARNING'; Class = 'packed'; Clause = 'packs credential files' }
    }
    if ($und) {
        # Nothing unpacks into the Public folder; an archive there whose
        # password cannot be determined is not routine.
        if ($Role -eq 'public') { return @{ Sev = 'WARNING'; Class = 'packed'; Clause = 'may be password-protected (whether it is could not be read from its header), and sits in the shared Public folder, where nothing unpacks' } }
        return @{ Sev = 'OK'; Class = 'undetermined'; Clause = '' }
    }
    return @{ Sev = 'OK'; Class = 'plain'; Clause = '' }
}

# ---------------------------------------------------------------------------
# THE REPORT, pure.
#   $Archives: @{ Path; Name; Folder; Role; Length; Modified; Kind; Zone;
#                 HostUrl; Encrypted; HeadersEncrypted; MultiVolume;
#                 MultiVolumeWhy; Entries; EntryCount; ParseError; SetKey;
#                 SetIndex; SetMembers }
#   $Folders:  @{ Path; Role; Depth; State = searched|absent|unlistable|
#                 deferred|budget; Error; Files; Skipped; Capped; Denied;
#                 Locked; LockedNames }
#   $Probes:   @{ Files; Probed; ProbeCap; BudgetHit; NotArchive; Packages;
#                 Cloud }
# ---------------------------------------------------------------------------

function Get-NewestArchiveLine {
    param($items)
    $n = @($items | Sort-Object @{ Expression = { $_.Modified }; Descending = $true }, @{ Expression = { [string]$_.Path } } | Select-Object -First 1)
    if ($n.Count) { return (' (newest: ' + (ConvertTo-PrintableText $n[0].Path) + ', written ' + (Format-When $n[0].Modified) + ')') }
    return ''
}

function Get-ArchiveStagingReport {
    param($Archives, $Folders, $Probes, [bool]$IsElevated = $true, [int]$Depth = 2)
    $out = New-Object System.Collections.ArrayList
    $sev = 'OK'; $gapSev = 'OK'; $deferred = 0; $hits = 0
    $archives = @($Archives | Where-Object { $null -ne $_ })
    $folders = @($Folders | Where-Object { $null -ne $_ })
    if ($null -eq $Probes) { $Probes = @{} }
    $scopeReasons = New-Object System.Collections.ArrayList

    # ---- what could not be read, before anything graded: a gap beside what
    # was read, never instead of it.
    $searched = @($folders | Where-Object { $_.State -eq 'searched' })
    $absent = @($folders | Where-Object { $_.State -eq 'absent' })
    foreach ($f in @($folders | Where-Object { $_.State -eq 'unlistable' } | Sort-Object { [string]$_.Path })) {
        if ($IsElevated) {
            [void]$out.Add(('[WARNING] Staging folder ' + (ConvertTo-PrintableText $f.Path) + ' could not be listed by an administrator -- archives there were NOT checked (' + (ConvertTo-PrintableText $f.Error) + ').'))
            $gapSev = 'WARNING'
        } else {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Staging folder ' + (ConvertTo-PrintableText $f.Path) + ' is not readable from a standard-user token -- archives there were NOT checked; re-run as administrator.'))
            $deferred++
        }
    }
    foreach ($f in @($folders | Where-Object { $_.State -eq 'deferred' } | Sort-Object { [string]$_.Path })) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + (ConvertTo-PrintableText $f.Path) + ' -- archives there were NOT checked from a standard-user token; re-run as administrator.'))
        $deferred++
    }
    foreach ($f in @($searched | Where-Object { [int]$_.Denied -gt 0 } | Sort-Object { [string]$_.Path })) {
        if ($IsElevated) {
            [void]$out.Add(('[WARNING] ' + [string]$f.Denied + ' file(s) in staging folder ' + (ConvertTo-PrintableText $f.Path) + ' could not be read by an administrator -- they were NOT checked. A file an administrator cannot open is itself unusual: check it with icacls.'))
            $gapSev = 'WARNING'
        } else {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + [string]$f.Denied + ' file(s) in ' + (ConvertTo-PrintableText $f.Path) + ' are not readable from a standard-user token -- they were NOT checked; re-run as administrator.'))
            $deferred++
        }
    }

    # ---- grade.
    $graded = New-Object System.Collections.ArrayList
    foreach ($a in $archives) {
        $reasons = @()
        foreach ($e in @($a.Entries)) { foreach ($rr in @(Get-ArchiveEntryReason -Name ([string]$e))) { if ($reasons -notcontains $rr) { $reasons += $rr } } }
        $role = [string]$a.Role; if (-not $role) { $role = 'other' }
        $v = Get-ArchiveVerdict -Zone ([int]$a.Zone) -Encrypted $a.Encrypted -MultiVolume ([bool]$a.MultiVolume) -EntryReasons $reasons -Role $role -Kind ([string]$a.Kind)
        [void]$graded.Add(@{ A = $a; V = $v; Reasons = $reasons })
    }
    # The volumes of ONE set are one finding: the lowest-numbered part present
    # speaks for the set and says how many more parts are here -- by name,
    # because 7-Zip's later volumes carry no signature of their own.
    $rank = @{ 'CRITICAL' = 0; 'WARNING' = 1; 'OK' = 2 }
    $groups = @{}
    $order = New-Object System.Collections.ArrayList
    foreach ($g in @($graded | Where-Object { $_.V.Sev -ne 'OK' })) {
        $sk = [string]$g.A.SetKey
        if ($sk -and $g.A.MultiVolume) { $gk = $sk + '|' + [string]$g.V.Sev } else { $gk = '#' + [string]$g.A.Path }
        if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.ArrayList; [void]$order.Add($gk) }
        [void]$groups[$gk].Add($g)
    }
    $findings = New-Object System.Collections.ArrayList
    foreach ($gk in $order) {
        $members = @($groups[$gk] | Sort-Object @{ Expression = { [int]$_.A.SetIndex } }, @{ Expression = { [string]$_.A.Path } })
        $lead = $members[0]
        $more = [math]::Max($members.Count - 1, [int]$lead.A.SetMembers - 1)
        [void]$findings.Add(@{ G = $lead; More = $more })
    }
    $findings = @($findings | Sort-Object @{ Expression = { $rank[[string]$_.G.V.Sev] } }, @{ Expression = { [string]$_.G.A.Path } })
    $shown = 0
    foreach ($fd in $findings) {
        $g = $fd.G; $a = $g.A; $v = $g.V
        $sev = Get-MaxSev $sev $v.Sev
        $hits++
        if ($shown -ge 10) { continue }
        $shown++
        $mb = [math]::Round(([double]$a.Length) / 1MB, 1)
        $moreText = ''
        if ([int]$fd.More -gt 0) { $moreText = ' (+' + [string]$fd.More + ' more part(s) of this set)' }
        $who = 'An archive made on this machine'
        if ($v.Class -eq 'marked-misplaced') { $who = 'An archive' }
        [void]$out.Add(('[' + $v.Sev + '] ' + $who + ' ' + $v.Clause + ', in a staging folder: ' + (ConvertTo-PrintableText $a.Path) + $moreText + ' (' + $mb + ' MB, written ' + (Format-When $a.Modified) + ') (T1560)'))
        $fmt = Get-KindLabel ([string]$a.Kind)
        if ($a.Sfx) { $fmt += ' inside a self-extracting program (the archive starts at byte ' + [string]$a.SfxBase + ')' }
        $bits = @()
        if ($a.Encrypted -eq $true) { if ($a.HeadersEncrypted) { $bits += 'password-protected with its file names hidden' } else { $bits += 'password-protected, file names visible' } }
        elseif ($null -eq $a.Encrypted) { $bits += 'password not determinable' + $(if ($a.ParseError) { ' (' + (ConvertTo-PrintableText $a.ParseError) + ')' } else { '' }) }
        else { $bits += 'no password' }
        if ($a.MultiVolume) { $bits += ('volume of a set' + $(if ($a.MultiVolumeWhy) { ' (' + (ConvertTo-PrintableText $a.MultiVolumeWhy) + ')' } else { '' })) } else { $bits += 'single volume' }
        [void]$out.Add(('    format: ' + $fmt + '; ' + ($bits -join '; ')))
        $z = [int]$a.Zone
        if ($z -ge 1 -and $z -le 4) {
            $origin = 'no origin recorded in the mark'
            if ($a.HostUrl) { $origin = 'origin ' + (ConvertTo-PrintableText $a.HostUrl) }
            $zoneLine = 'ZoneId=' + [string]$z + ', ' + $origin + ' -- anyone can write this stream, so it does not clear an archive of this shape in this folder'
        } elseif ($z -eq 0) { $zoneLine = 'ZoneId=0, the local-machine zone -- not a download' }
        elseif ($z -eq -2) { $zoneLine = 'a Zone.Identifier stream exists but could not be read' }
        else { $zoneLine = 'none -- no browser downloaded this file; it was made or copied here (a file the OneDrive client synced also carries none)' }
        [void]$out.Add('    download mark: ' + $zoneLine)
        if ($g.Reasons.Count) {
            [void]$out.Add('    packs: ' + ($g.Reasons -join '; '))
            $named = @($a.Entries | Where-Object { @(Get-ArchiveEntryReason -Name ([string]$_)).Count -gt 0 } | Select-Object -First 5)
            foreach ($nm in $named) { [void]$out.Add('      ' + (ConvertTo-PrintableText ([string]$nm))) }
        } elseif (@($a.Entries).Count -gt 0) {
            $first = @($a.Entries | Select-Object -First 3 | ForEach-Object { ConvertTo-PrintableText ([string]$_) })
            $ec = [int]$a.EntryCount; if ($ec -lt @($a.Entries).Count) { $ec = @($a.Entries).Count }
            [void]$out.Add('    holds ' + [string]$ec + ' entr' + $(if ($ec -eq 1) { 'y' } else { 'ies' }) + ', e.g. ' + ($first -join ', '))
        }
        $q = ([string]$a.Path) -replace "'", "''"
        [void]$out.Add("    verify: Get-Content -LiteralPath '" + $q + "' -Stream Zone.Identifier -ErrorAction SilentlyContinue; then open the archive with your archiver and read what it holds. If you did not make it, treat it as collected data packed to leave this machine.")
    }
    if ($hits -gt $shown) { [void]$out.Add('    ...and ' + [string]($hits - $shown) + ' more archive(s) graded the same way') }

    # ---- context, each class counted and named.
    $ms = @($graded | Where-Object { $_.V.Class -eq 'marked-strong' } | ForEach-Object { $_.A } | Sort-Object { [string]$_.Path })
    foreach ($a in @($ms | Select-Object -First 5)) {
        $o = 'no origin recorded in the mark'; if ($a.HostUrl) { $o = 'downloaded from ' + (ConvertTo-PrintableText $a.HostUrl) }
        [void]$out.Add('[INFO] A downloaded archive of the packed-to-leave shape (password-protected and split, or carrying credential files) is in Downloads: ' + (ConvertTo-PrintableText $a.Path) + ' -- ' + $o + '. Anyone can write a download mark; if you did not download it, read it as made here.')
    }
    if ($ms.Count -gt 5) { [void]$out.Add('[INFO] ...and ' + [string]($ms.Count - 5) + ' more downloaded archive(s) of that shape') }
    $dl = @($graded | Where-Object { $_.V.Class -eq 'downloaded' } | ForEach-Object { $_.A })
    if ($dl.Count) { [void]$out.Add('[INFO] ' + [string]$dl.Count + ' archive(s) carry the Mark of the Web -- downloaded by a browser, not packed here; context, not graded as staging' + (Get-NewestArchiveLine $dl)) }
    $plain = @($graded | Where-Object { $_.V.Class -eq 'plain' } | ForEach-Object { $_.A })
    if ($plain.Count) { [void]$out.Add('[INFO] ' + [string]$plain.Count + ' plain archive(s) made or copied here (single volume, no password) -- the shape Explorer''s Compress and every tool cache make; context only' + (Get-NewestArchiveLine $plain)) }
    $vsd = @($graded | Where-Object { $_.V.Class -eq 'volumeset-download' } | ForEach-Object { $_.A })
    if ($vsd.Count) { [void]$out.Add('[INFO] ' + [string]$vsd.Count + ' volume(s) of split archive sets with no password and no download mark sit in Downloads -- how torrent and file-sharing clients deliver large files; context only' + (Get-NewestArchiveLine $vsd)) }
    $cab = @($graded | Where-Object { $_.V.Class -eq 'cabset' } | ForEach-Object { $_.A })
    if ($cab.Count) { [void]$out.Add('[INFO] ' + [string]$cab.Count + ' cabinet(s) belonging to a spanned CAB set -- installers write these, and a cabinet cannot carry a password; context only' + (Get-NewestArchiveLine $cab)) }
    $und = @($graded | Where-Object { $_.V.Class -eq 'undetermined' } | ForEach-Object { $_.A } | Sort-Object { [string]$_.Path })
    if ($und.Count) {
        $nm = @($und | Select-Object -First 5 | ForEach-Object { ConvertTo-PrintableText $_.Path })
        [void]$out.Add('[INFO] ' + [string]$und.Count + ' archive(s) whose password could not be determined -- a 7z header coded with a method this audit does not decode, larger than its 256 KiB cap, failing its CRC, or not decoded within its time (10 s each, 30 s per run, smallest first), and a damaged or truncated archive, cannot be read through; graded by their volume shape only: ' + ($nm -join '; ') + $(if ($und.Count -gt 5) { '; ...and ' + [string]($und.Count - 5) + ' more' } else { '' }))
    }
    if ([int]$Probes.SfxScanned -gt 0) {
        $sfxLine = '[INFO] ' + [string]$Probes.SfxScanned + ' program file(s) were checked for an archive appended after their code (a self-extracting archive); ' + [string]$Probes.SfxFound + ' held one'
        if ([int]$Probes.SfxSigned -gt 0) { $sfxLine += ', ' + [string]$Probes.SfxSigned + ' of them validly signed by their publisher and left out: an installer is not an archive packed here' }
        [void]$out.Add($sfxLine + '.')
    }
    if ([int]$Probes.SfxUnparsed -gt 0) {
        [void]$out.Add('[INFO] ' + [string]$Probes.SfxUnparsed + ' program file(s) were NOT checked for an appended archive -- their header could not be read: ' + ((@($Probes.SfxUnparsedNames) | ForEach-Object { ConvertTo-PrintableText $_ }) -join '; ') + $(if ([int]$Probes.SfxUnparsed -gt 3) { '; ...and ' + [string]([int]$Probes.SfxUnparsed - 3) + ' more' } else { '' }))
    }
    if ([int]$Probes.Packages -gt 0) { [void]$out.Add('[INFO] ' + [string]$Probes.Packages + ' package(s) that are ZIP by signature (Office documents, MSIX/APPX, VSIX, JAR and the like) were left out: a document is not an archive for this purpose') }
    if ([int]$Probes.NotArchive -gt 0) { [void]$out.Add('[INFO] ' + [string]$Probes.NotArchive + ' file(s) named like an archive are not one by signature') }
    if ([int]$Probes.Cloud -gt 0) { [void]$out.Add('[INFO] ' + [string]$Probes.Cloud + ' cloud-only placeholder(s) were not opened: reading one would download it from the cloud. They are not covered.') }
    $locked = @($searched | Where-Object { [int]$_.Locked -gt 0 })
    if ($locked.Count) {
        $tot = 0; $nms = @(); foreach ($l in $locked) { $tot += [int]$l.Locked; $nms += @($l.LockedNames) }
        [void]$out.Add('[INFO] ' + [string]$tot + ' file(s) were held open by another program and could not be read, so they were not graded: ' + ((@($nms | Select-Object -First 3) | ForEach-Object { ConvertTo-PrintableText $_ }) -join '; '))
    }
    $sub = @($searched | Where-Object { [int]$_.Skipped -gt 0 })
    if ($sub.Count) {
        $tot = 0; foreach ($s in $sub) { $tot += [int]$s.Skipped }
        [void]$out.Add('[INFO] ' + [string]$tot + ' subfolder(s) inside the staging folders could not be listed and were skipped')
    }
    foreach ($f in @($searched | Where-Object { $_.Capped } | Sort-Object { [string]$_.Path })) {
        [void]$out.Add('[INFO] ' + (ConvertTo-PrintableText $f.Path) + ' holds more than ' + [string]$f.Files + ' files; only the first ' + [string]$f.Files + ' were examined -- it is NOT fully covered')
        [void]$scopeReasons.Add('a folder too large to examine in full')
    }
    if ([bool]$Probes.ProbeCap) {
        [void]$out.Add('[INFO] Only ' + [string]$Probes.Probed + ' file(s) without an archive extension had their signature read (cap), largest first; a renamed archive among the rest would not be seen')
        [void]$scopeReasons.Add('the signature-probe cap')
    }
    $bud = @($folders | Where-Object { $_.State -eq 'budget' } | Sort-Object { [string]$_.Path })
    if ($bud.Count -or [bool]$Probes.BudgetHit) {
        $w = ''; if ($bud.Count) { $w = ': ' + ((@($bud) | ForEach-Object { ConvertTo-PrintableText $_.Path }) -join '; ') + ' NOT reached' }
        [void]$out.Add('[INFO] The time budget ran out before every staging folder and file was examined' + $w + ' -- what follows covers only what was read')
        [void]$scopeReasons.Add('the time budget')
    }
    [void]$out.Add('[INFO] Not examined by design: archives inside other archives, a self-extracting program whose archive starts more than 64 KiB past its code or sits inside its resources (as IExpress packages do), other users'' redirected Downloads folders, and folders deeper than ' + [string]$Depth + ' level(s) below each staging folder.')

    # ---- the coverage sentence. An all-clear only when nothing was raised,
    # nothing could not be read, nothing was deferred and no cap or budget
    # was hit; otherwise the SAME sentence as [INFO], scoped to what was
    # read, so a partial run still says what it covered rather than going
    # quiet. Both name the folders and the newest archive.
    $where = @($searched | Sort-Object { [string]$_.Path } | ForEach-Object { ConvertTo-PrintableText $_.Path })
    if ($sev -ne 'OK') {
        [void]$out.Add('[INFO] ' + [string]$archives.Count + ' archive(s) examined across ' + [string]$searched.Count + ' staging folder(s); ' + [string]$hits + ' graded as made here and packed to leave.')
    } else {
        $tag = '[OK]'; $scope = ''
        if ($gapSev -ne 'OK' -or $deferred -gt 0) { $tag = '[INFO]'; $scope = ' -- for the folders this run could read; the folders declared above are NOT covered' }
        elseif ($scopeReasons.Count) { $tag = '[INFO]'; $scope = ' -- for what this run could read before ' + ((@($scopeReasons) | Select-Object -Unique) -join ' and ') + ' stopped it' }
        $span = ' to a depth of ' + [string]$Depth
        if ($archives.Count -eq 0) {
            [void]$out.Add($tag + ' No archives in the ' + [string]$searched.Count + ' staging folder(s) examined' + $span + ' (' + ($where -join '; ') + ')' + $scope + '.')
        } else {
            [void]$out.Add($tag + ' ' + [string]$archives.Count + ' archive(s) examined across ' + [string]$searched.Count + ' staging folder(s)' + $span + ' (' + ($where -join '; ') + '): none password-protected or split into volumes was made on this machine, and none packs a credential file' + $scope + '.')
            $newest = @($archives | Sort-Object @{ Expression = { $_.Modified }; Descending = $true }, @{ Expression = { [string]$_.Path } } | Select-Object -First 1)
            if ($newest.Count) { [void]$out.Add('[INFO] The newest archive examined is ' + (ConvertTo-PrintableText $newest[0].Path) + ' (' + (Get-KindLabel ([string]$newest[0].Kind)) + ', written ' + (Format-When $newest[0].Modified) + ').') }
        }
        if ($absent.Count) { [void]$out.Add('[INFO] Not present on this machine: ' + (@($absent | Sort-Object { [string]$_.Path } | ForEach-Object { ConvertTo-PrintableText $_.Path }) -join '; ')) }
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev; Deferred = $deferred; Hits = $hits }
}

# ---------------------------------------------------------------------------
# THE LIVE CLASSIFIER, as a function so the self-test drives it end to end
# over files it wrote. $Candidates: @{ Item (FullName, Name, DirectoryName,
# Extension, Length, LastWriteTimeUtc, Attributes); Folder; Role }.
# $ZoneReader: param($path) -> @{ Zone; HostUrl }. $HeadReader: param($path)
# -> the first 512 bytes (injectable so a refusal can be tested).
# ---------------------------------------------------------------------------

function Get-ZoneOfFile {
    param([string]$Path)
    $zone = -1; $hostUrl = ''
    try {
        $zt = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -Raw -EA Stop
        $inSection = $false
        foreach ($raw in (([string]$zt) -split "`r?`n")) {
            $l = $raw.Trim()
            if ($l -match '^\[([^\]]*)\]') { $inSection = ($Matches[1].Trim() -eq 'ZoneTransfer'); continue }
            if (-not $inSection) { continue }
            if ($zone -eq -1 -and $l -match '^ZoneId\s*=\s*(.*)$') { $v = $Matches[1].Trim(); if ($v -match '^\d{1,9}$') { $zone = [int]$v } else { $zone = -2 } }
            elseif (-not $hostUrl -and $l -match '^HostUrl\s*=\s*(.+)$') { $hostUrl = $Matches[1].Trim() }
        }
    } catch {
        $exists = $false
        try { $null = Get-Item -LiteralPath $Path -Stream 'Zone.Identifier' -Force -EA Stop; $exists = $true } catch { $exists = $false }
        if ($exists) { $zone = -2 }
    }
    return @{ Zone = $zone; HostUrl = $hostUrl }
}

function Read-ArchiveFacts {
    # One archive of a known kind, read at $Base: what the per-kind readers
    # established, normalised. Used for each archive and for each candidate
    # inside a self-extracting program.
    param([string]$Kind, [string]$Path, [long]$Length, [long]$Base = 0, [string[]]$SpanP = @(), [long[]]$SpanS = @(), [byte[]]$Head = $null)
    $kind = $Kind
    $x = $null; $enc = $null; $multi = $false; $multiWhy = ''; $entries = @(); $hdrEnc = $false; $opc = $false; $count = 0; $parseError = ''
    try {
        switch ($kind) {
            'zip'      { $x = Get-ZipFacts -Path $Path -Length $Length -SpanPaths $SpanP -SpanSizes $SpanS -Base $Base; $enc = $x.Encrypted; $multi = [bool]$x.Split; if ($multi) { $multiWhy = 'the end record names more than one disk' }; $entries = @($x.Entries); $opc = [bool]$x.Opc; $count = [int]$x.EntryCount; if ($null -eq $enc -and $x.Why) { $parseError = $x.Why } }
            'zip-span' { $x = Get-ZipLocalFromBytes -Head (Read-FileBytes -Path $Path -Offset $Base -Count 1048576); if ($x.Encrypted) { $enc = $true } else { $enc = $null; $parseError = 'a first segment holds no end record' }; $multi = $true; $multiWhy = 'the first segment of a split set'; $entries = @($x.Entries); $opc = [bool]$x.Opc }
            'rar4'     { $x = Get-RarFacts -Path $Path -Length $Length -Base $Base; $enc = $x.Encrypted; $hdrEnc = [bool]$x.HeadersEncrypted; $multi = [bool]$x.MultiVolume; if ($multi) { $multiWhy = 'the archive header carries the volume flag' }; $entries = @($x.Entries); $count = [int]$x.Count; if (-not $x.Parsed) { $parseError = $x.Why; if (-not $enc) { $enc = $null } } }
            'rar5'     { $x = Get-RarFacts -Path $Path -Length $Length -Base $Base; $enc = $x.Encrypted; $hdrEnc = [bool]$x.HeadersEncrypted; $multi = [bool]$x.MultiVolume; if ($multi) { $multiWhy = 'the archive header carries the volume flag' }; $entries = @($x.Entries); $count = [int]$x.Count; if (-not $x.Parsed) { $parseError = $x.Why; if (-not $enc) { $enc = $null } } }
            '7z'       {
                # A compressed header is decoded after the loop (below).
                $x = Get-SevenZipFacts -Path $Path -Length $Length -SpanPaths $SpanP -SpanSizes $SpanS -NoDecode -Base $Base
                $enc = $x.Encrypted; $hdrEnc = [bool]$x.HeadersEncrypted; $entries = @($x.Entries); $count = [math]::Max([int]$x.NameCount, $entries.Count)
                if ($SpanP.Count -gt 1) { $multi = $true; $multiWhy = [string]$SpanP.Count + ' volumes read as one stream' }
                if ($x.Beyond) { $parseError = $x.Why }
                elseif (-not $x.Parsed) { $parseError = $x.Why }
                elseif ($null -eq $enc) { if ($x.Why) { $parseError = $x.Why } else { $parseError = 'compressed header' } }
            }
            'cab'      { $cabHead = $Head; if ($Base -gt 0 -or $null -eq $cabHead) { $cabHead = Read-FileBytes -Path $Path -Offset $Base -Count 512 }; $x = Get-CabFactsFromBytes -Head $cabHead; $enc = $false; $multi = [bool]$x.MultiVolume; if ($multi) { $multiWhy = 'the cabinet header names a previous or next cabinet' } }
            default    { $enc = $false }
        }
    } catch { $parseError = $_.Exception.Message; if ($enc -ne $true) { $enc = $null } }
    $zipParsed = $false
    if ($kind -eq 'zip' -and $null -ne $x -and $x.Parsed) { $zipParsed = $true }
    return @{ X = $x; Enc = $enc; Multi = $multi; MultiWhy = $multiWhy; Entries = @($entries); HdrEnc = $hdrEnc; Opc = $opc; Count = $count; ParseError = $parseError; ZipParsed = $zipParsed; Kind = $kind; Base = $Base }
}

function Invoke-ArchiveClassification {
    # $DecodeAllowanceSeconds: the wall clock all compressed 7z headers of
    # this run may spend decoding, together. They are decoded AFTER every
    # archive has been graded on its header bytes, smallest packed header
    # first, so a folder of slow decoys cannot use up the run's budget before
    # the other archives are examined, and a real header (a few KB) is
    # decoded before them.
    param($Candidates, [int]$MaxProbes = 5000, [double]$BudgetSeconds = 120, $Stopwatch = $null, $FolderStats = $null, [double]$DecodeAllowanceSeconds = 30,
          [scriptblock]$ZoneReader = { param($p) Get-ZoneOfFile -Path $p },
          [scriptblock]$HeadReader = { param($p) Read-FileBytes -Path $p -Offset 0 -Count 512 },
          [scriptblock]$SignatureReader = { param($p) [string](Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop).Status })
    if ($null -eq $Stopwatch) { $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew() }
    if ($null -eq $FolderStats) { $FolderStats = @{} }
    $probes = @{ Files = @($Candidates).Count; Probed = 0; ProbeCap = $false; BudgetHit = $false; NotArchive = 0; Packages = 0; Cloud = 0; SfxScanned = 0; SfxFound = 0; SfxSigned = 0; SfxUnparsed = 0; SfxUnparsedNames = @() }
    $cands = @($Candidates | Where-Object { $null -ne $_ })
    # Members of every volume-shaped name, per directory, counted over ALL
    # candidates -- including 7-Zip's signature-less later volumes.
    $setCount = @{}
    $byDirName = @{}
    foreach ($c in $cands) {
        $it = $c.Item
        $byDirName[([string]$it.DirectoryName).ToLowerInvariant() + '|' + ([string]$it.Name).ToLowerInvariant()] = $c
        $vk = Get-VolumeSetKey -Name ([string]$it.Name)
        if ($null -ne $vk) { $k = ([string]$it.DirectoryName).ToLowerInvariant() + '|' + $vk.Set; if (-not $setCount.ContainsKey($k)) { $setCount[$k] = 0 }; $setCount[$k]++ }
    }
    $byExt = New-Object System.Collections.ArrayList
    $others = New-Object System.Collections.ArrayList
    foreach ($c in $cands) {
        $it = $c.Item
        $ext = ([string]$it.Extension).ToLowerInvariant()
        $nm = ([string]$it.Name).ToLowerInvariant()
        if ($c.Role -eq 'recycle' -and $nm -match '^\$i') { continue }   # the bin's own metadata, not data
        if ($script:PackageExt -contains $ext) { $probes.Packages++; continue }
        if (([int64]$it.Attributes -band $script:CloudMask) -ne 0) { $probes.Cloud++; continue }
        $vol = Get-VolumeSetKey -Name $nm
        if ($script:ArchiveExt -contains $ext -or $nm -match '\.(r\d\d|z\d\d|part\d+\.rar|tar\.gz|\d{3})$' -or ($null -ne $vol -and $vol.Alone)) { [void]$byExt.Add($c) }
        elseif ([long]$it.Length -ge 32) { [void]$others.Add($c) }
    }
    $order = New-Object System.Collections.ArrayList
    foreach ($c in @($byExt.ToArray() | Sort-Object @{ Expression = { [string]$_.Item.FullName } })) { [void]$order.Add($c) }
    $probedOthers = 0
    foreach ($c in @($others.ToArray() | Sort-Object @{ Expression = { [long]$_.Item.Length }; Descending = $true }, @{ Expression = { [string]$_.Item.FullName } })) {
        if ($probedOthers -ge $MaxProbes) { $probes.ProbeCap = $true; break }
        $probedOthers++
        [void]$order.Add($c)
    }
    $probes.Probed = $probedOthers

    $archives = New-Object System.Collections.ArrayList
    $pending = New-Object System.Collections.ArrayList
    foreach ($c in @($order.ToArray())) {
        if ($Stopwatch.Elapsed.TotalSeconds -gt $BudgetSeconds) { $probes.BudgetHit = $true; break }
        $it = $c.Item
        $path = [string]$it.FullName
        $len = [long]$it.Length
        $fk = [string]$c.Folder
        if (-not $FolderStats.ContainsKey($fk)) { $FolderStats[$fk] = @{ Denied = 0; Locked = 0; LockedNames = @() } }
        $head = $null
        try { $head = & $HeadReader $path }
        catch [System.UnauthorizedAccessException] { $FolderStats[$fk].Denied++; continue }
        catch {
            # Held open without read sharing, or gone between the listing and
            # the read: named, not graded.
            $FolderStats[$fk].Locked++
            if (@($FolderStats[$fk].LockedNames).Count -lt 3) { $FolderStats[$fk].LockedNames += $path }
            continue
        }
        $kind = Get-ArchiveKind -Head $head
        $ext = ([string]$it.Extension).ToLowerInvariant()
        $sfx = $false; $sfxBase = [long]0; $fx = $null
        if ($kind -eq 'none' -and $null -ne $head -and $head.Count -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) {
            # A program: is an archive appended after its code?
            $sf = $null
            try { $sf = Find-SfxInFile -Path $path -Length $len } catch { $sf = @{ Parsed = $false; Why = [string]$_.Exception.Message } }
            if (-not $sf.Parsed) {
                # NOT checked, and said so: a header that cannot be read is not
                # a program with nothing appended.
                $probes.SfxUnparsed++
                if (@($probes.SfxUnparsedNames).Count -lt 3) { $probes.SfxUnparsedNames += ($path + ' (' + [string]$sf.Why + ')') }
            } else {
                $probes.SfxScanned++
                $cands = @($sf.Candidates)
                if ($cands.Count -gt 0 -and $sf.HasCert -and @($cands | Where-Object { -not $_.InCert }).Count -gt 0) {
                    # A publisher signs the whole file, archive included, and
                    # appending an archive afterwards breaks the signature, so
                    # a VALID one means an installer, not an archive packed
                    # here. A signature that cannot be checked counts as
                    # unsigned. A program with no certificate table is not
                    # asked at all (hashing a large unsigned file costs the
                    # run's time for nothing). An archive found INSIDE the
                    # certificate table (padding Authenticode does not hash)
                    # is graded whatever the signature says.
                    if ($Stopwatch.Elapsed.TotalSeconds -gt $BudgetSeconds) { $probes.BudgetHit = $true; break }
                    $st = ''
                    try { $st = [string](& $SignatureReader $path) } catch { $st = 'Unknown' }
                    if ($st -eq 'Valid') {
                        $cands = @($cands | Where-Object { $_.InCert })
                        if ($cands.Count -eq 0) { $probes.SfxFound++; $probes.SfxSigned++; continue }
                    }
                }
                # Every candidate is graded and the most severe kept: a
                # password beats "not determinable" beats "no password", so a
                # decoy archive in front of the real one cannot clear it; at
                # equal severity one whose own CRC checked out wins. A ZIP
                # candidate counts only when its end record resolves (or its
                # own headers show a password); a package inside sorts last.
                $best = $null; $bestRank = -1
                foreach ($cd in @($cands | Sort-Object @{ Expression = { -not $_.Checked } }, @{ Expression = { [long]$_.Base } } | Select-Object -First 8)) {
                    $f = Read-ArchiveFacts -Kind $cd.Kind -Path $path -Length $len -Base ([long]$cd.Base)
                    if ($cd.Kind -eq 'zip' -and -not $f.ZipParsed -and $f.Enc -ne $true) { continue }
                    $rank = 1
                    if ($f.Enc -eq $true) { $rank = 3 } elseif ($null -eq $f.Enc) { $rank = 2 }
                    if ($f.Opc) { $rank = 0 }
                    if ($rank -gt $bestRank) { $best = $f; $bestRank = $rank }
                }
                if ($null -ne $best) { $probes.SfxFound++; $kind = [string]$best.Kind; $sfx = $true; $sfxBase = [long]$best.Base; $fx = $best }
            }
        }
        if ($kind -eq 'none') {
            # A later raw volume of a set (name.7z.002) is not an archive by
            # itself; it is counted as a member of its set, not here.
            $vk0 = Get-VolumeSetKey -Name ([string]$it.Name)
            if ($script:ArchiveExt -contains $ext -and -not ($null -ne $vk0 -and $vk0.Index -gt 1)) { $probes.NotArchive++ }
            continue
        }
        $vol = Get-VolumeSetKey -Name ([string]$it.Name)
        $setKey = ''; $members = 1; $index = 0
        if ($null -ne $vol) {
            $setKey = ([string]$it.DirectoryName).ToLowerInvariant() + '|' + $vol.Set
            $members = [int]$setCount[$setKey]; $index = [int]$vol.Index
        }
        # A raw volume set (name.7z.001 / name.zip.001) is read as ONE stream,
        # because its header sits at the end of the last volume.
        $spanP = @(); $spanS = @()
        if (([string]$it.Name) -match '^(?i)(.+\.(7z|zip))\.001$') {
            $base = $Matches[1]
            for ($n = 1; $n -le 9999; $n++) {
                $sib = $byDirName[([string]$it.DirectoryName).ToLowerInvariant() + '|' + ($base + '.' + $n.ToString('000')).ToLowerInvariant()]
                if ($null -eq $sib) { break }
                $spanP += [string]$sib.Item.FullName; $spanS += [long]$sib.Item.Length
            }
        }
        if ($null -eq $fx) { $fx = Read-ArchiveFacts -Kind $kind -Path $path -Length $len -SpanP $spanP -SpanS $spanS -Head $head }
        $x = $fx.X; $enc = $fx.Enc; $multi = [bool]$fx.Multi; $multiWhy = [string]$fx.MultiWhy; $entries = @($fx.Entries); $hdrEnc = [bool]$fx.HdrEnc; $opc = [bool]$fx.Opc; $count = [int]$fx.Count; $parseError = [string]$fx.ParseError
        if ($opc) { $probes.Packages++; continue }
        if (-not $multi -and $null -ne $vol -and ($vol.Alone -or $members -ge 2)) {
            $multi = $true
            if ($members -ge 2) { $multiWhy = [string]$members + ' parts of the set are here' } else { $multiWhy = 'named as a volume of a set whose other parts are not here' }
        }
        if (-not $multi) { $setKey = '' }
        $zr = & $ZoneReader $path
        $rec = @{ Path = $path; Name = [string]$it.Name; Folder = $c.Folder; Role = [string]$c.Role; Length = $len; Modified = $it.LastWriteTimeUtc; Kind = $kind
                  Zone = [int]$zr.Zone; HostUrl = [string]$zr.HostUrl; Encrypted = $enc; HeadersEncrypted = $hdrEnc; MultiVolume = $multi; MultiVolumeWhy = $multiWhy
                  Entries = $entries; EntryCount = $count; ParseError = $parseError; SetKey = $setKey; SetIndex = $index; SetMembers = $members; Sfx = $sfx; SfxBase = $sfxBase }
        [void]$archives.Add($rec)
        if ($kind -eq '7z' -and $null -ne $x -and $null -ne $x.Decode -and $null -eq $enc) {
            $tot = $len - $sfxBase; if ($spanP.Count -gt 1) { $tot = 0; foreach ($q in $spanS) { $tot += [long]$q } }
            [void]$pending.Add(@{ Rec = $rec; Facts = $x; Path = $path; Total = $tot; SpanP = $spanP; SpanS = $spanS; Size = [long]$x.Decode.PackSize; Base = $sfxBase })
        }
    }
    # The compressed 7z headers, smallest first, within the run's decode
    # allowance and its overall budget; whatever is left is named, never
    # cleared.
    $spent = 0.0; $decoded = 0
    foreach ($pd in @($pending.ToArray() | Sort-Object @{ Expression = { [long]$_.Size } }, @{ Expression = { [string]$_.Path } })) {
        $left = [math]::Min([math]::Min(10.0, $DecodeAllowanceSeconds - $spent), $BudgetSeconds - $Stopwatch.Elapsed.TotalSeconds)
        if ($left -lt 0.5) {
            $pd.Rec.ParseError = 'compressed header not decompressed: the run''s ' + [string]$DecodeAllowanceSeconds + '-second decode allowance was spent on ' + [string]$decoded + ' smaller header(s) first'
            continue
        }
        $dsw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $y = Invoke-SevenZipHeaderDecode -Facts $pd.Facts -Path $pd.Path -Total $pd.Total -SpanPaths $pd.SpanP -SpanSizes $pd.SpanS -Seconds $left -Base $pd.Base
            $pd.Rec.Encrypted = $y.Encrypted
            $pd.Rec.Entries = @($y.Entries); $pd.Rec.EntryCount = [math]::Max([int]$y.NameCount, @($y.Entries).Count)
            if ($null -eq $y.Encrypted) { $pd.Rec.ParseError = [string]$y.Why } else { $pd.Rec.ParseError = '' }
        } catch { $pd.Rec.ParseError = 'compressed header not decompressed: ' + $_.Exception.Message }
        $spent += $dsw.Elapsed.TotalSeconds; $decoded++
    }
    # A set is ONE archive: a password one volume's header established holds
    # for every part, so the parts cannot grade apart. Only a password
    # crosses between parts: "no password" read from one part does not clear
    # a part whose own header could not be read, because a decoy named as a
    # volume of the set would otherwise speak for it.
    $bySet = @{}
    foreach ($a in @($archives.ToArray())) { if ($a.SetKey) { if (-not $bySet.ContainsKey($a.SetKey)) { $bySet[$a.SetKey] = @() }; $bySet[$a.SetKey] += ,$a } }
    foreach ($k in @($bySet.Keys)) {
        $known = @($bySet[$k] | Where-Object { $null -ne $_.Encrypted } | Sort-Object @{ Expression = { -not ($_.Encrypted -eq $true) } }, @{ Expression = { [string]$_.Path } })
        if ($known.Count -eq 0) { continue }
        $lead = $known[0]
        if ($lead.Encrypted -ne $true) { continue }
        foreach ($a in @($bySet[$k])) {
            if ($null -eq $a.Encrypted -or ($lead.Encrypted -eq $true -and $a.Encrypted -ne $true)) {
                $a.Encrypted = $lead.Encrypted; $a.HeadersEncrypted = $lead.HeadersEncrypted
                if (@($a.Entries).Count -eq 0) { $a.Entries = $lead.Entries; $a.EntryCount = $lead.EntryCount }
                if ($a.Encrypted -ne $null) { $a.ParseError = '' }
            }
        }
    }
    return @{ Archives = @($archives.ToArray()); Probes = $probes }
}

# ---------------------------------------------------------------------------
# ENUMERATION, per folder: a cap per folder (a huge temp folder cannot starve
# the folders after it), a time budget checked between folders, and a state
# for every folder so the report can say exactly what it covered.
# ---------------------------------------------------------------------------

function Get-StagingCandidates {
    param($Specs, [int]$MaxFilesPerFolder = 20000, [int]$Depth = 2, [double]$BudgetSeconds = 120, $Stopwatch = $null)
    if ($null -eq $Stopwatch) { $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew() }
    $folders = New-Object System.Collections.ArrayList
    $cands = New-Object System.Collections.ArrayList
    foreach ($spec in @($Specs)) {
        if ($spec.State -ne 'try') { [void]$folders.Add($spec); continue }
        $f = [string]$spec.Path
        $d = $Depth; if ($null -ne $spec.Depth) { $d = [int]$spec.Depth }
        if ($Stopwatch.Elapsed.TotalSeconds -gt $BudgetSeconds) { [void]$folders.Add(@{ Path = $f; Role = $spec.Role; State = 'budget' }); continue }
        try {
            if (-not (Test-Path -LiteralPath $f -EA Stop)) {
                # Absent, or not listable by this token -- Test-Path answers
                # $false for both; enumerating says which.
                [void][System.IO.Directory]::GetFileSystemEntries($f)
                [void]$folders.Add(@{ Path = $f; Role = $spec.Role; State = 'absent' })
                continue
            }
            [void][System.IO.Directory]::GetFileSystemEntries($f)
            $errs = @()
            $items = @(Get-ChildItem -LiteralPath $f -File -Force -Recurse -Depth $d -EA SilentlyContinue -ErrorVariable errs | Select-Object -First ($MaxFilesPerFolder + 1))
            $capped = ($items.Count -gt $MaxFilesPerFolder)
            if ($capped) { $items = @($items | Select-Object -First $MaxFilesPerFolder) }
            foreach ($it in $items) { [void]$cands.Add(@{ Item = $it; Folder = $f; Role = $spec.Role }) }
            [void]$folders.Add(@{ Path = $f; Role = $spec.Role; Depth = $d; State = 'searched'; Files = $items.Count; Skipped = @($errs).Count; Capped = $capped; Denied = 0; Locked = 0; LockedNames = @() })
        } catch [System.IO.DirectoryNotFoundException] {
            [void]$folders.Add(@{ Path = $f; Role = $spec.Role; State = 'absent' })
        } catch {
            [void]$folders.Add(@{ Path = $f; Role = $spec.Role; State = 'unlistable'; Error = $_.Exception.Message })
        }
    }
    return @{ Candidates = @($cands.ToArray()); Folders = @($folders.ToArray()) }
}

function Get-RoleOfPath {
    param([string]$Path)
    if ($Path -match '(?i)\$Recycle\.Bin') { return 'recycle' }
    if ($Path -match '(?i)\\Users\\Public(\\|$)') { return 'public' }
    if ($Path -match '(?i)\\Downloads$') { return 'downloads' }
    if ($Path -match '(?i)\\Windows\\(Temp|ServiceProfiles\\|System32\\config\\systemprofile\\)') { return 'systemp' }
    if ($Path -match '(?i)\\Temp$') { return 'temp' }
    if ($Path -match '(?i)\\ProgramData$') { return 'programdata' }
    return 'other'
}

function Resolve-LongPath {
    # ONE FOLDER IS ONE FOLDER, WHATEVER ITS SPELLING. Windows hands %TEMP% to
    # a process in 8.3 form when the profile name does not fit 8.3
    # (C:\Users\RUNNER~1\AppData\Local\Temp on the CI runner; any user name
    # longer than eight characters or holding a space), so the profile's own
    # Temp and %TEMP% are the same directory under two names. Measured on
    # windows-latest: one Temp listed twice, so the coverage line counted 11
    # folders for 10 and an archive there would print twice. Each segment that
    # holds a '~' is resolved through Directory.GetDirectories(parent,
    # segment), which matches the short name and returns the long one.
    # $Lister is injectable so the self-test can pin it without 8.3 names.
    param([string]$Path, [scriptblock]$Lister = { param($parent, $seg) [System.IO.Directory]::GetDirectories($parent, $seg) })
    if (-not $Path -or $Path -notmatch '~') { return $Path }
    try {
        $parts = $Path.TrimEnd('\') -split '\\'
        if ($parts.Count -lt 2) { return $Path }
        $cur = $parts[0] + '\'
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $seg = $parts[$i]
            if (-not $seg) { continue }
            $next = $cur.TrimEnd('\') + '\' + $seg
            if ($seg -match '~') {
                $m = @(& $Lister $cur $seg)
                if ($m.Count -eq 1 -and $m[0]) { $next = [string]$m[0] }
            }
            $cur = $next
        }
        return $cur
    } catch { return $Path }
}

function Add-StagingFolder {
    param($list, $seen, [string]$p, [string]$Role, [string]$state = 'try', $FolderDepth = $null, [scriptblock]$Lister = $null)
    if (-not $p) { return }
    if ($Lister) { $long = Resolve-LongPath -Path $p -Lister $Lister } else { $long = Resolve-LongPath -Path $p }
    $k = $long.TrimEnd('\').ToLowerInvariant()
    if ($seen.ContainsKey($k)) { return }
    $seen[$k] = 1
    $h = @{ Path = $long.TrimEnd('\'); Role = $Role; State = $state }
    if ($null -ne $FolderDepth) { $h.Depth = [int]$FolderDepth }
    [void]$list.Add($h)
}

# ---------------------------------------------------------------------------
# SELF-TEST: synthetic archives built byte by byte from the published layouts,
# so every parser branch and every verdict row runs on Linux pwsh and on 5.1
# with no archiver installed -- and the live classifier is driven end to end
# over files this test writes.
# ---------------------------------------------------------------------------

if ($SelfTest) {
    $script:fails = 0
    function T {
        param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $t0 = New-Object DateTime 2026, 10, 15, 12, 0, 0, ([DateTimeKind]::Utc)
    $tdir = Join-Path ([System.IO.Path]::GetTempPath()) ("dz_archstage_selftest_{0}" -f $PID)
    New-Item -ItemType Directory -Path $tdir -Force | Out-Null
    function B { param([int[]]$v) return [byte[]]($v | ForEach-Object { [byte]$_ }) }
    function U16 { param([int]$v) return [byte[]]@(($v -band 0xFF), (($v -shr 8) -band 0xFF)) }
    function U32 { param([long]$v) return [byte[]]@(($v -band 0xFF), (($v -shr 8) -band 0xFF), (($v -shr 16) -band 0xFF), (($v -shr 24) -band 0xFF)) }
    function U64 { param([long]$v) return [byte[]]((U32 ($v -band 0xFFFFFFFF)) + (U32 (($v -shr 32) -band 0xFFFFFFFF))) }
    # Joins byte arrays. A function that returns a 0-element array returns
    # $null to its caller, so an empty part is skipped rather than becoming a
    # zero byte.
    function Join-Bytes { param([object[]]$parts) $l = New-Object System.Collections.Generic.List[byte]; foreach ($p in $parts) { if ($null -eq $p) { continue }; foreach ($b in @($p)) { if ($null -ne $b) { $l.Add([byte]$b) } } }; return $l.ToArray() }
    function Vint { param([long]$v) $o = @(); do { $b = [int]($v -band 0x7F); $v = $v -shr 7; if ($v -gt 0) { $b = $b -bor 0x80 }; $o += [byte]$b } while ($v -gt 0); return [byte[]]$o }
    function Asc { param([string]$s) return [System.Text.Encoding]::ASCII.GetBytes($s) }

    # ---- ZIP builder (stored entries; CRCs are not what the parser reads).
    function New-ZipBytes {
        param([object[]]$Entries, [int]$DiskNo = 0, [string]$Comment = '', [byte[]]$Prefix = $null, [switch]$ClearCentralFlags)
        $locals = New-Object System.Collections.Generic.List[byte]
        $cds = New-Object System.Collections.Generic.List[byte]
        $off = 0; if ($Prefix) { foreach ($b in $Prefix) { $locals.Add($b) }; $off = $Prefix.Count }
        foreach ($e in $Entries) {
            $name = Asc $e.Name; $data = Asc ([string]$e.Data); $flags = [int]$e.Flags; $method = [int]$e.Method
            $cflags = $flags; $cmethod = $method; if ($ClearCentralFlags) { $cflags = 0; $cmethod = 8 }
            $lh = Join-Bytes @((B @(0x50, 0x4B, 0x03, 0x04)), (U16 20), (U16 $flags), (U16 $method), (U16 0), (U16 0), (U32 0), (U32 $data.Count), (U32 $data.Count), (U16 $name.Count), (U16 0), $name, $data)
            $cd = Join-Bytes @((B @(0x50, 0x4B, 0x01, 0x02)), (U16 20), (U16 20), (U16 $cflags), (U16 $cmethod), (U16 0), (U16 0), (U32 0), (U32 $data.Count), (U32 $data.Count), (U16 $name.Count), (U16 0), (U16 0), (U16 0), (U16 0), (U32 0), (U32 $off), $name)
            foreach ($b in $lh) { $locals.Add($b) }
            foreach ($b in $cd) { $cds.Add($b) }
            $off += $lh.Count
        }
        $cmt = Asc $Comment
        $eocd = Join-Bytes @((B @(0x50, 0x4B, 0x05, 0x06)), (U16 $DiskNo), (U16 $DiskNo), (U16 $Entries.Count), (U16 $Entries.Count), (U32 $cds.Count), (U32 $off), (U16 $cmt.Count), $cmt)
        return (Join-Bytes @($locals.ToArray(), $cds.ToArray(), $eocd))
    }
    # ---- a single-disk ZIP64 whose end record holds the 0xFFFF sentinels.
    function New-Zip64Bytes {
        $name = Asc 'big.bin'; $data = Asc 'x'
        $lh = Join-Bytes @((B @(0x50, 0x4B, 0x03, 0x04)), (U16 45), (U16 0), (U16 0), (U16 0), (U16 0), (U32 0), (U32 1), (U32 1), (U16 $name.Count), (U16 0), $name, $data)
        $cd = Join-Bytes @((B @(0x50, 0x4B, 0x01, 0x02)), (U16 45), (U16 45), (U16 0), (U16 0), (U16 0), (U16 0), (U32 0), (U32 1), (U32 1), (U16 $name.Count), (U16 0), (U16 0), (U16 0), (U16 0), (U32 0), (U32 0), $name)
        $cdOff = $lh.Count; $z64Off = $cdOff + $cd.Count
        $z64 = Join-Bytes @((B @(0x50, 0x4B, 0x06, 0x06)), (U64 44), (U16 45), (U16 45), (U32 0), (U32 0), (U64 1), (U64 1), (U64 $cd.Count), (U64 $cdOff))
        $loc = Join-Bytes @((B @(0x50, 0x4B, 0x06, 0x07)), (U32 0), (U64 $z64Off), (U32 1))
        $eocd = Join-Bytes @((B @(0x50, 0x4B, 0x05, 0x06)), (U16 0xFFFF), (U16 0xFFFF), (U16 0xFFFF), (U16 0xFFFF), (U32 0xFFFFFFFF), (U32 0xFFFFFFFF), (U16 0))
        return (Join-Bytes @($lh, $cd, $z64, $loc, $eocd))
    }
    # ---- RAR 4.x builder.
    function New-Rar4Bytes {
        param([int]$MainFlags = 0, [object[]]$Files = @())
        $sig = B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00)
        $mainBody = Join-Bytes @((B @(0x73)), (U16 $MainFlags), (U16 13), (U16 0), (U32 0))
        $main = Join-Bytes @((U16 ((Get-Crc32 $mainBody) -band 0xFFFF)), $mainBody)
        $parts = @($sig, $main)
        if (($MainFlags -band 0x0080) -ne 0) { $parts += (B @(1, 2, 3, 4, 5, 6, 7, 8)); return (Join-Bytes $parts) }
        foreach ($f in $Files) {
            $name = Asc $f.Name; $data = Asc ([string]$f.Data)
            $size = 32 + $name.Count
            $fh = Join-Bytes @((U16 0), (B @(0x74)), (U16 ([int]$f.Flags)), (U16 $size), (U32 $data.Count), (U32 $data.Count), (B @(2)), (U32 0), (U32 0), (B @(29)), (B @(0x30)), (U16 $name.Count), (U32 0x20), $name, $data)
            $parts += $fh
        }
        $parts += (Join-Bytes @((U16 0), (B @(0x7B)), (U16 ([int]$(if ($MainFlags -band 0x0001) { 1 } else { 0 }))), (U16 7)))
        return (Join-Bytes $parts)
    }
    # ---- RAR 5.0 builder.
    function New-Rar5Block {
        param([int]$Type, [int]$Flags, [byte[]]$Body, [byte[]]$Extra = $null, [byte[]]$Data = $null)
        $hdr = Join-Bytes @((Vint $Type), (Vint $Flags))
        if ($Extra) { $hdr = Join-Bytes @($hdr, (Vint $Extra.Count)) }
        if ($Data) { $hdr = Join-Bytes @($hdr, (Vint $Data.Count)) }
        $hdr = Join-Bytes @($hdr, $Body)
        if ($Extra) { $hdr = Join-Bytes @($hdr, $Extra) }
        # The block CRC is real (CRC32 over the size field and the header), as
        # every archiver writes it: the self-extracting reader checks it.
        $sized = Join-Bytes @((Vint $hdr.Count), $hdr)
        $blk = Join-Bytes @((U32 (Get-Crc32 $sized)), $sized)
        if ($Data) { $blk = Join-Bytes @($blk, $Data) }
        return $blk
    }
    function New-Rar5Bytes {
        param([bool]$Crypt = $false, [int]$ArchFlags = 0, [object[]]$Files = @(), [bool]$NextVolume = $false)
        $sig = B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)
        $parts = @($sig)
        if ($Crypt) { $parts += (New-Rar5Block -Type 4 -Flags 0 -Body (Join-Bytes @((Vint 0), (Vint 0), (B @(15)), (New-Object byte[] 16)))); $parts += (B @(9, 9, 9, 9, 9, 9, 9, 9)); return (Join-Bytes $parts) }
        $mainBody = Vint $ArchFlags
        if (($ArchFlags -band 0x0002) -ne 0) { $mainBody = Join-Bytes @($mainBody, (Vint 2)) }
        $parts += (New-Rar5Block -Type 1 -Flags 0 -Body $mainBody)
        foreach ($f in $Files) {
            $name = [System.Text.Encoding]::UTF8.GetBytes([string]$f.Name); $data = Asc ([string]$f.Data)
            $body = Join-Bytes @((Vint 0), (Vint $data.Count), (Vint 0x20), (Vint 0), (Vint 2), (Vint $name.Count), $name)
            $extra = $null
            if ($f.Encrypted) { $rec = Join-Bytes @((Vint 1), (Vint 0), (B @(15)), (New-Object byte[] 32)); $extra = Join-Bytes @((Vint $rec.Count), $rec) }
            $flags = 2; if ($extra) { $flags = 3 }
            $parts += (New-Rar5Block -Type 2 -Flags $flags -Body $body -Extra $extra -Data $data)
        }
        $parts += (New-Rar5Block -Type 5 -Flags 0 -Body (Vint $(if ($NextVolume) { 1 } else { 0 })))
        return (Join-Bytes $parts)
    }
    # ---- 7z builder: a signature header and a next header of the chosen kind.
    function New-SevenZipBytes {
        param([string]$HeaderKind, [bool]$Truncate = $false, [string[]]$Names = @(), [byte[]]$RawHeader = $null)
        $pack = B @(1, 2, 3, 4, 5, 6, 7, 8)
        $coderLzma = B @(0x23, 0x03, 0x01, 0x01, 0x05, 0x5D, 0x00, 0x00, 0x01, 0x00)   # flag 0x23 (id size 3, attrs), id 030101, props 5
        $coderAes = Join-Bytes @((B @(0x24, 0x06, 0xF1, 0x07, 0x01)), (B @(0x02, 0x3F, 0x00)))      # flag 0x24: id size 4, attrs; props 2
        $nh = $RawHeader
        switch ($HeaderKind) {
            'encoded-aes'  { $folder = Join-Bytes @((Vint 2), $coderAes, $coderLzma, (B @(0x00, 0x01)))   # 2 coders, bind pair (0,1)
                             $nh = Join-Bytes @((B @(0x17, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (Vint $pack.Count), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), $folder, (B @(0x0C)), (Vint 64), (Vint 64), (B @(0x00, 0x00))) }
            'encoded-lzma' { $folder = Join-Bytes @((Vint 1), $coderLzma)
                             $nh = Join-Bytes @((B @(0x17, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (Vint $pack.Count), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), $folder, (B @(0x0C)), (Vint 64), (B @(0x00, 0x00))) }
            'plain-aes'    { $folder = Join-Bytes @((Vint 2), $coderAes, $coderLzma, (B @(0x00, 0x01)))
                             $nh = Join-Bytes @((B @(0x01, 0x04, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (Vint $pack.Count), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), $folder, (B @(0x0C)), (Vint 64), (Vint 64), (B @(0x00, 0x00))) }
            'plain-aes-sub' {
                             # As 7-Zip writes it: SubStreamsInfo (two files in
                             # one folder, one size, both CRCs) before the
                             # FilesInfo holding the names.
                             $folder = Join-Bytes @((Vint 2), $coderAes, $coderLzma, (B @(0x00, 0x01)))
                             $nh = Join-Bytes @((B @(0x01, 0x04, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (Vint $pack.Count), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), $folder, (B @(0x0C)), (Vint 64), (Vint 64), (B @(0x00)),
                                                (B @(0x08, 0x0D)), (Vint 2), (B @(0x09)), (Vint 30), (B @(0x0A, 0x01)), (U32 0x11111111), (U32 0x22222222), (B @(0x00)), (B @(0x00))) }
            'plain'        { $folder = Join-Bytes @((Vint 1), $coderLzma)
                             $nh = Join-Bytes @((B @(0x01, 0x04, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (Vint $pack.Count), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), $folder, (B @(0x0C)), (Vint 64), (B @(0x00, 0x00))) }
        }
        if ($Names.Count -and $HeaderKind -like 'plain*') {
            $txt = [System.Text.Encoding]::Unicode.GetBytes(($Names -join "`0") + "`0")
            $nh = Join-Bytes @($nh, (B @(0x05)), (Vint $Names.Count), (B @(0x11)), (Vint ($txt.Count + 1)), (B @(0x00)), $txt, (B @(0x00, 0x00)))
        }
        $size = $nh.Count; if ($Truncate) { $size = $nh.Count + 4096 }
        $tail20 = Join-Bytes @((U64 $pack.Count), (U64 $size), (U32 0))
        $sig = Join-Bytes @((B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04)), (U32 (Get-Crc32 $tail20)), $tail20)
        return (Join-Bytes @($sig, $pack, $nh))
    }
    # ---- a 7z whose next header is an EncodedHeader over real packed bytes,
    # as 7-Zip writes one by default (-mhc=on): the packed header sits right
    # after the signature header (PackPos 0) and the EncodedHeader names its
    # coder, its unpacked size and, when $Crc is given, the CRC of the header
    # it unpacks to.
    # 7z's own number encoding (7zFormat.txt; Read-SevenZipNumber reads it):
    # n leading one bits in the first byte, n little-endian bytes after it.
    # Vint above is RAR's encoding, the same only below 128.
    function N7 {
        param([long]$v)
        $n = 0
        while ($n -lt 8 -and $v -ge ([long]1 -shl (7 * ($n + 1)))) { $n++ }
        $first = ((0xFF -shl (8 - $n)) -band 0xFF) -bor [int](($v -shr (8 * $n)) -band 0xFF)
        if ($n -eq 8) { $first = 0xFF }
        $o = @([byte]$first)
        for ($i = 0; $i -lt $n; $i++) { $o += [byte](($v -shr (8 * $i)) -band 0xFF) }
        return [byte[]]$o
    }
    function New-SevenZipEncodedBytes {
        param([byte[]]$Packed, [long]$UnpackSize, [long]$Crc = -1, [string]$Coder = 'lzma', [long]$PackSize = -1, [byte[]]$Props = $null)
        if ($null -eq $Props) { $Props = B @(0x5D, 0x00, 0x00, 0x10, 0x00) }
        if ($PackSize -lt 0) { $PackSize = $Packed.Count }
        switch ($Coder) {
            'lzma'  { $cd = Join-Bytes @((B @(0x23, 0x03, 0x01, 0x01, 0x05)), $Props) }
            'lzma2' { $cd = B @(0x21, 0x21, 0x01, 0x18) }
            'copy'  { $cd = B @(0x01, 0x00) }
        }
        $crcPart = $null
        if ($Crc -ge 0) { $crcPart = Join-Bytes @((B @(0x0A, 0x01)), (U32 $Crc)) }
        $nh = Join-Bytes @((B @(0x17, 0x06)), (Vint 0), (Vint 1), (B @(0x09)), (N7 $PackSize), (B @(0x00, 0x07, 0x0B)), (Vint 1), (B @(0x00)), (Vint 1), $cd, (B @(0x0C)), (N7 $UnpackSize), $crcPart, (B @(0x00, 0x00)))
        $tail20 = Join-Bytes @((U64 $Packed.Count), (U64 $nh.Count), (U32 0))
        $sig = Join-Bytes @((B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04)), (U32 (Get-Crc32 $tail20)), $tail20)
        return (Join-Bytes @($sig, $Packed, $nh))
    }
    function New-CabBytes { param([int]$Flags) $h = New-Object byte[] 0x24; $h[0] = 0x4D; $h[1] = 0x53; $h[2] = 0x43; $h[3] = 0x46; $h[0x1E] = [byte]($Flags -band 0xFF); return $h }
    function Put { param([string]$Name, [byte[]]$Bytes, [string]$Dir = $tdir) $p = Join-Path $Dir $Name; [System.IO.File]::WriteAllBytes($p, $Bytes); return $p }
    function Facts {
        # The live classifier over ONE file this test wrote, graded as found
        # in a folder of role 'other'.
        param([string]$Path)
        $it = Get-Item -LiteralPath $Path
        $res = Invoke-ArchiveClassification -Candidates @(@{ Item = $it; Folder = (Split-Path -Parent $Path); Role = 'other' }) -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } }
        if (@($res.Archives).Count -eq 0) { return @{ Kind = 'none'; Encrypted = $null; MultiVolume = $false; Entries = @(); Parsed = $false; Why = ''; Opc = ($res.Probes.Packages -gt 0) } }
        $a = $res.Archives[0]
        return @{ Kind = $a.Kind; Encrypted = $a.Encrypted; HeadersEncrypted = $a.HeadersEncrypted; MultiVolume = $a.MultiVolume; Entries = $a.Entries; Parsed = (-not $a.ParseError); Why = $a.ParseError; Opc = $false }
    }
    function NewArc {
        param([string]$Path, [string]$Kind = 'zip', [int]$Zone = -1, $Encrypted = $false, [bool]$Multi = $false, [string[]]$Entries = @(), [bool]$HeadersEncrypted = $false, [string]$MultiWhy = '', $t = $t0, [long]$Length = 2048, [string]$ParseError = '', [string]$SetKey = '', [string]$Role = 'public', [string]$HostUrl = '', [int]$SetIndex = 0, [int]$SetMembers = 1)
        return @{ Path = $Path; Name = (Split-Path -Leaf $Path); Folder = (Split-Path -Parent $Path); Role = $Role; Length = $Length; Modified = $t; Kind = $Kind; Zone = $Zone; HostUrl = $HostUrl; Encrypted = $Encrypted; HeadersEncrypted = $HeadersEncrypted; MultiVolume = $Multi; MultiVolumeWhy = $MultiWhy; Entries = $Entries; EntryCount = $Entries.Count; ParseError = $ParseError; SetKey = $SetKey; SetIndex = $SetIndex; SetMembers = $SetMembers }
    }
    function Classify {
        # The live classifier over a whole directory this test wrote.
        param([string]$Dir, [string]$Role = 'other', [hashtable]$Zones = @{}, [hashtable]$Attr = @{}, [scriptblock]$HeadReader = $null)
        $cands = @()
        foreach ($it in @(Get-ChildItem -LiteralPath $Dir -File -Force -Recurse)) {
            $o = $it
            if ($Attr.ContainsKey($it.Name)) { $o = [pscustomobject]@{ FullName = $it.FullName; Name = $it.Name; DirectoryName = $it.DirectoryName; Extension = $it.Extension; Length = $it.Length; LastWriteTimeUtc = $it.LastWriteTimeUtc; Attributes = $Attr[$it.Name] } }
            $cands += @{ Item = $o; Folder = $Dir; Role = $Role }
        }
        # A plain scriptblock reading a script-scoped map: .GetNewClosure() is
        # not used anywhere in this repo (5.1 resolves functions differently
        # inside the dynamic module it builds).
        $script:TestZones = $Zones
        $zr = { param($p) $n = Split-Path -Leaf $p; if ($script:TestZones.ContainsKey($n)) { $script:TestZones[$n] } else { @{ Zone = -1; HostUrl = '' } } }
        $st = @{}
        if ($HeadReader) { $res = Invoke-ArchiveClassification -Candidates $cands -ZoneReader $zr -HeadReader $HeadReader -FolderStats $st }
        else { $res = Invoke-ArchiveClassification -Candidates $cands -ZoneReader $zr -FolderStats $st }
        $fs = @{ Path = $Dir; Role = $Role; State = 'searched'; Files = $cands.Count; Skipped = 0; Capped = $false; Denied = 0; Locked = 0; LockedNames = @() }
        if ($st.ContainsKey($Dir)) { $fs.Denied = $st[$Dir].Denied; $fs.Locked = $st[$Dir].Locked; $fs.LockedNames = $st[$Dir].LockedNames }
        $rep = Get-ArchiveStagingReport -Archives $res.Archives -Folders @($fs) -Probes $res.Probes
        return @{ Res = $res; Rep = $rep; Text = ($rep.Lines -join ' | ') }
    }
    function NewDir { param([string]$n) $d = Join-Path $tdir $n; New-Item -ItemType Directory -Path $d -Force | Out-Null; return $d }
    function Timed { param([scriptblock]$sb) $sw = [System.Diagnostics.Stopwatch]::StartNew(); $null = & $sb; return $sw.Elapsed.TotalSeconds }
    $fo = @(@{ Path = 'C:\Users\k\Downloads'; Role = 'downloads'; State = 'searched'; Files = 10; Skipped = 0 }, @{ Path = 'C:\Users\Public'; Role = 'public'; State = 'searched'; Files = 3; Skipped = 0 })
    $j = { param($r) ($r.Lines -join ' | ') }

    try {
        # ---- signatures.
        T 'a ZIP is known by its local-header signature' ((Get-ArchiveKind -Head (B @(0x50, 0x4B, 0x03, 0x04, 0, 0))) -eq 'zip') ''
        T 'the first segment of a split ZIP is known by its spanning signature' ((Get-ArchiveKind -Head (B @(0x50, 0x4B, 0x07, 0x08, 0x50, 0x4B))) -eq 'zip-span') ''
        T 'RAR 4.x and RAR 5.0 are told apart by the seventh byte' (((Get-ArchiveKind -Head (B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0))) -eq 'rar4') -and ((Get-ArchiveKind -Head (B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00))) -eq 'rar5')) ''
        T 'a 7z, a CAB and a gzip are known by signature' (((Get-ArchiveKind -Head (B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))) -eq '7z') -and ((Get-ArchiveKind -Head (B @(0x4D, 0x53, 0x43, 0x46))) -eq 'cab') -and ((Get-ArchiveKind -Head (B @(0x1F, 0x8B, 0x08, 0))) -eq 'gzip')) ''
        T 'a bzip2 and an xz are known by signature, so a .tar.xz is not called "not an archive"' (((Get-ArchiveKind -Head (B @(0x42, 0x5A, 0x68, 0x39, 0x31))) -eq 'bzip2') -and ((Get-ArchiveKind -Head (B @(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00))) -eq 'xz')) ''
        $tarHead = New-Object byte[] 512; foreach ($i in 0..4) { $tarHead[257 + $i] = [byte]('ustar'[$i]) }
        T 'a tar is known by its magic at offset 257' ((Get-ArchiveKind -Head $tarHead) -eq 'tar') ''
        T 'a text file is not an archive' ((Get-ArchiveKind -Head (Asc 'hello world, this is not an archive at all')) -eq 'none') ''
        T 'a RAR signature with an unknown version byte is not graded as RAR' ((Get-ArchiveKind -Head (B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x02, 0x00))) -eq 'none') ''

        # ---- ZIP.
        $p = Put 'plain.zip' (New-ZipBytes -Entries @(@{ Name = 'docs/a.txt'; Flags = 0; Method = 0; Data = 'aaa' }, @{ Name = 'docs/b.txt'; Flags = 0; Method = 0; Data = 'bbb' }))
        $f = Facts $p
        T 'a plain ZIP parses: two entries, no password, one volume' ($f.Parsed -and $f.Encrypted -eq $false -and -not $f.MultiVolume -and @($f.Entries).Count -eq 2 -and $f.Entries[0] -eq 'docs/a.txt') "$($f.Encrypted)/$($f.MultiVolume)/$(@($f.Entries).Count)/$($f.Why)"
        $p = Put 'crypt.zip' (New-ZipBytes -Entries @(@{ Name = 'report.docx'; Flags = 1; Method = 8; Data = 'xx' }))
        $f = Facts $p
        T 'a ZipCrypto entry (general-purpose bit 0) is password-protected, names still visible' ($f.Encrypted -eq $true -and $f.Entries[0] -eq 'report.docx') "$($f.Encrypted)"
        $p = Put 'aes.zip' (New-ZipBytes -Entries @(@{ Name = 'x.bin'; Flags = 1; Method = 99; Data = 'xx' }))
        $f = Facts $p
        T 'a WinZip AES entry (method 99) is password-protected' ($f.Encrypted -eq $true) "$($f.Encrypted)"
        $p = Put 'masked.zip' (New-ZipBytes -Entries @(@{ Name = 'x.bin'; Flags = 0x2001; Method = 8; Data = 'xx' }))
        $f = Facts $p
        T 'a masked central directory (bit 13) is password-protected' ($f.Encrypted -eq $true) "$($f.Encrypted)"
        $p = Put 'split.zip' (New-ZipBytes -Entries @(@{ Name = 'x.bin'; Flags = 0; Method = 0; Data = 'xx' }) -DiskNo 2)
        $f = Facts $p
        T 'an end record on disk 2 means a split set' ($f.MultiVolume) "$($f.MultiVolume)"
        $p = Put 'comment.zip' (New-ZipBytes -Entries @(@{ Name = 'x.bin'; Flags = 0; Method = 0; Data = 'xx' }) -Comment ('PK' + [char]5 + [char]6 + 'a comment holding a fake end signature'))
        $f = Facts $p
        T 'a fake end signature inside the comment does not fool the tail scan' ($f.Parsed -and $f.Encrypted -eq $false -and @($f.Entries).Count -eq 1) "$($f.Why)/$(@($f.Entries).Count)"
        $p = Put 'office.zip' (New-ZipBytes -Entries @(@{ Name = '[Content_Types].xml'; Flags = 0; Method = 8; Data = '<x/>' }, @{ Name = 'word/document.xml'; Flags = 0; Method = 8; Data = '<w/>' }))
        $f = Facts $p
        T 'an Office/MSIX package is recognised by its [Content_Types].xml entry' ($f.Kind -eq 'none' -and $f.Opc) "$($f.Kind)/$($f.Opc)"
        $p = Put 'jar.zip' (New-ZipBytes -Entries @(@{ Name = 'META-INF/MANIFEST.MF'; Flags = 0; Method = 8; Data = 'm' }))
        $f = Facts $p
        T 'a JAR is recognised by its manifest entry' ($f.Kind -eq 'none' -and $f.Opc) "$($f.Kind)/$($f.Opc)"
        $p = Put 'empty.zip' (New-ZipBytes -Entries @())
        $f = Facts $p
        T 'an empty ZIP (end record only) is a plain archive, not an error' ($f.Parsed -and $f.Encrypted -eq $false) "$($f.Parsed)/$($f.Why)"
        $p = Put 'trunc.zip' (B @(0x50, 0x4B, 0x03, 0x04, 1, 2, 3, 4, 5, 6, 7, 8))
        $f = Facts $p
        T 'a ZIP with no end record is declared not determinable, never clean' ($null -eq $f.Encrypted -and -not $f.Parsed) "$($f.Encrypted)/$($f.Why)"
        $p = Put 'trailing.zip' (Join-Bytes @((New-ZipBytes -Entries @(@{ Name = 'Outlook.pst'; Flags = 1; Method = 8; Data = 'x' })), (B @(0x0A))))
        $f = Facts $p
        T 'a password-protected ZIP with one byte appended is still password-protected (copy /b loot.zip+x)' ($f.Encrypted -eq $true -and $f.Entries[0] -eq 'Outlook.pst') "$($f.Encrypted)/$($f.Entries -join ',')/$($f.Why)"
        $p = Put 'cleared.zip' (New-ZipBytes -Entries @(@{ Name = 'a.bin'; Flags = 1; Method = 8; Data = 'x' }) -ClearCentralFlags)
        $f = Facts $p
        T 'central-directory flags cleared while the local headers say encrypted: still password-protected' ($f.Encrypted -eq $true) "$($f.Encrypted)"
        $p = Put 'big64.zip' (New-Zip64Bytes)
        $f = Facts $p
        T 'a single-disk ZIP64 with 0xFFFF sentinels in its end record is NOT a split set' ($f.Parsed -and -not $f.MultiVolume -and $f.Encrypted -eq $false) "$($f.MultiVolume)/$($f.Encrypted)/$($f.Why)"

        # ---- RAR 4.x.
        $p = Put 'plain4.rar' (New-Rar4Bytes -MainFlags 0 -Files @(@{ Name = 'notes.txt'; Flags = 0x8000; Data = 'n' }))
        $f = Facts $p
        T 'a RAR 4.x with one plain file: no password, one volume, the name read' ($f.Parsed -and $f.Encrypted -eq $false -and -not $f.MultiVolume -and $f.Entries[0] -eq 'notes.txt') "$($f.Encrypted)/$($f.MultiVolume)/$($f.Entries -join ',')"
        $p = Put 'hp4.rar' (New-Rar4Bytes -MainFlags 0x0081)
        $f = Facts $p
        T 'RAR 4.x MHD_PASSWORD (headers encrypted, -hp) is password-protected with names hidden, and MHD_VOLUME a volume' ($f.Encrypted -eq $true -and $f.HeadersEncrypted -and $f.MultiVolume -and @($f.Entries).Count -eq 0) "$($f.Encrypted)/$($f.HeadersEncrypted)/$($f.MultiVolume)"
        $p = Put 'p4.rar' (New-Rar4Bytes -MainFlags 0 -Files @(@{ Name = 'Outlook.pst'; Flags = 0x8004; Data = 'd' }))
        $f = Facts $p
        T 'RAR 4.x LHD_PASSWORD (-p) is password-protected with the names visible' ($f.Encrypted -eq $true -and -not $f.HeadersEncrypted -and $f.Entries[0] -eq 'Outlook.pst') "$($f.Encrypted)/$($f.Entries -join ',')"
        $p = Put 'vol4.rar' (New-Rar4Bytes -MainFlags 0x0101 -Files @(@{ Name = 'a.txt'; Flags = 0x8000; Data = 'a' }))
        $f = Facts $p
        T 'RAR 4.x MHD_VOLUME without a password is a volume, not password-protected' ($f.MultiVolume -and $f.Encrypted -eq $false) "$($f.MultiVolume)/$($f.Encrypted)"
        $nul = New-Rar4Bytes -MainFlags 0 -Files @(@{ Name = 'Xa.txt'; Flags = 0x8000; Data = 'a' })
        $nul[7 + 13 + 32] = 0   # the name's first byte -> NUL
        $f = Get-RarFactsFromBytes -Buf $nul
        T 'a RAR 4.x name that starts with NUL yields no name, not two stray bytes' (@($f.Entries).Count -eq 0) "$($f.Entries -join ',')"

        # ---- RAR 5.0.
        $p = Put 'plain5.rar' (New-Rar5Bytes -Files @(@{ Name = 'photo.jpg'; Data = 'p' }))
        $f = Facts $p
        T 'a RAR 5.0 with one plain file: no password, one volume, the name read' ($f.Parsed -and $f.Encrypted -eq $false -and -not $f.MultiVolume -and $f.Entries[0] -eq 'photo.jpg') "$($f.Encrypted)/$($f.MultiVolume)/$($f.Entries -join ',')"
        $p = Put 'hp5.rar' (New-Rar5Bytes -Crypt $true)
        $f = Facts $p
        T 'a RAR 5.0 archive-encryption header (type 4, -hp) is password-protected with names hidden' ($f.Encrypted -eq $true -and $f.HeadersEncrypted) "$($f.Encrypted)/$($f.HeadersEncrypted)"
        $p = Put 'p5.rar' (New-Rar5Bytes -Files @(@{ Name = 'Login Data'; Data = 'l'; Encrypted = $true }))
        $f = Facts $p
        T 'a RAR 5.0 file header with an encryption extra record (-p) is password-protected, names visible' ($f.Encrypted -eq $true -and -not $f.HeadersEncrypted -and $f.Entries[0] -eq 'Login Data') "$($f.Encrypted)/$($f.Entries -join ',')"
        $p = Put 'vol5.rar' (New-Rar5Bytes -ArchFlags 0x0001 -Files @(@{ Name = 'a.txt'; Data = 'a' }) -NextVolume $true)
        $f = Facts $p
        T 'a RAR 5.0 main header with the volume flag is a volume of a set' ($f.MultiVolume -and $f.Encrypted -eq $false) "$($f.MultiVolume)/$($f.Encrypted)"
        $p = Put 'last5.rar' (New-Rar5Bytes -ArchFlags 0x0003 -Files @(@{ Name = 'a.txt'; Data = 'a' }))
        $f = Facts $p
        T 'a later RAR 5.0 volume (volume-number field present) is still a volume' ($f.MultiVolume) "$($f.MultiVolume)"
        $p = Put 'bad5.rar' (B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80))
        $f = Facts $p
        T 'a RAR 5.0 whose header sizes are garbage is declared not determinable, never clean' (-not $f.Parsed -and $null -eq $f.Encrypted) "$($f.Parsed)/$($f.Encrypted)/$($f.Why)"

        # ---- 7z.
        $p = Put 'mhe.7z' (New-SevenZipBytes -HeaderKind 'encoded-aes')
        $f = Facts $p
        T 'a 7z EncodedHeader coded with 7zAES (-mhe) is password-protected with names hidden' ($f.Parsed -and $f.Encrypted -eq $true -and $f.HeadersEncrypted) "$($f.Parsed)/$($f.Encrypted)/$($f.Why)"
        $p = Put 'default.7z' (New-SevenZipBytes -HeaderKind 'encoded-lzma')
        $f = Facts $p
        T 'a 7z compressed header that will not decompress is NOT DETERMINABLE, neither clean nor password-protected' ($null -eq $f.Encrypted -and $f.Why -match 'compressed header') "$($f.Encrypted)/$($f.Why)"
        $p = Put 'p.7z' (New-SevenZipBytes -HeaderKind 'plain-aes' -Names @('secrets\id_rsa', 'notes.txt'))
        $f = Facts $p
        T 'a plain 7z Header whose streams carry 7zAES (-p -mhc=off) is password-protected with the names read' ($f.Encrypted -eq $true -and -not $f.HeadersEncrypted -and $f.Entries[0] -eq 'secrets\id_rsa') "$($f.Encrypted)/$($f.Entries -join ',')"
        $p = Put 'psub.7z' (New-SevenZipBytes -HeaderKind 'plain-aes-sub' -Names @('Outlook.pst', 'notes.txt'))
        $f = Facts $p
        T 'a plain 7z Header with SubStreamsInfo, as 7-Zip writes it, still yields its names' ($f.Encrypted -eq $true -and $f.Entries[0] -eq 'Outlook.pst' -and @($f.Entries).Count -eq 2) "$($f.Encrypted)/$($f.Entries -join ',')/$($f.Why)"
        $p = Put 'plain.7z' (New-SevenZipBytes -HeaderKind 'plain' -Names @('a.txt'))
        $f = Facts $p
        T 'a plain 7z Header without 7zAES is not password-protected' ($f.Encrypted -eq $false -and $f.Entries[0] -eq 'a.txt') "$($f.Encrypted)"
        $p = Put 'cut.7z' (New-SevenZipBytes -HeaderKind 'plain' -Truncate $true)
        $f = Facts $p
        T 'a plain-named 7z whose header lies beyond the file is TRUNCATED (or a renamed first volume): not determinable, not a volume set' ($null -eq $f.Encrypted -and -not $f.MultiVolume -and $f.Why -match 'beyond') "$($f.Encrypted)/$($f.MultiVolume)/$($f.Why)"
        $p = Put 'short.7z' (B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4))
        $f = Facts $p
        T 'a 7z shorter than its signature header is declared not determinable' (-not $f.Parsed -and $null -eq $f.Encrypted) "$($f.Parsed)"
        # A volume set as 7-Zip writes one: the whole archive cut into pieces,
        # the header at the end of the LAST piece. Read as one stream, the
        # first volume yields the header.
        $whole = New-SevenZipBytes -HeaderKind 'encoded-aes'
        $cut = 20
        $v1 = Join-Path $tdir 'set.7z.001'; $v2 = Join-Path $tdir 'set.7z.002'; $v3 = Join-Path $tdir 'set.7z.003'
        [System.IO.File]::WriteAllBytes($v1, [byte[]]$whole[0..($cut - 1)])
        [System.IO.File]::WriteAllBytes($v2, [byte[]]$whole[$cut..(2 * $cut - 1)])
        [System.IO.File]::WriteAllBytes($v3, [byte[]]$whole[(2 * $cut)..($whole.Count - 1)])
        $f = Get-SevenZipFacts -Path $v1 -Length $cut -SpanPaths @($v1, $v2, $v3) -SpanSizes @([long]$cut, [long]$cut, [long]($whole.Count - 2 * $cut))
        T 'a 7z volume set read across its volumes yields the header from the last one: -mhe seen' ($f.Parsed -and $f.Encrypted -eq $true -and $f.HeadersEncrypted) "$($f.Parsed)/$($f.Encrypted)/$($f.Why)"
        $f = Get-SevenZipFacts -Path $v1 -Length $cut -SpanPaths @($v1, $v2) -SpanSizes @([long]$cut, [long]$cut)
        T 'with the last volume missing the header is beyond what is here, and that is said' ($f.Beyond -and $null -eq $f.Encrypted -and $f.Why -match 'beyond the volumes present') "$($f.Encrypted)/$($f.Why)"
        Remove-Item -LiteralPath $v1, $v2, $v3 -Force

        # ---- the compressed header, decompressed. Vectors made by Python's
        # lzma module (liblzma, raw LZMA1) from the plain headers the
        # builder above writes, so the decoder is checked against an encoder
        # it shares no code with; the CRCs are zlib's.
        $hdrAes = [byte[]](New-SevenZipBytes -HeaderKind 'plain-aes' -Names @('secrets\id_rsa', 'notes.txt'))[40..134]
        $hdrPlain = [byte[]](New-SevenZipBytes -HeaderKind 'plain' -Names @('a.txt', 'b.txt'))[40..97]
        $lzAes = [Convert]::FromBase64String('AACBMweuD84/w+eIBwj+5VlOfAWwIfYuIP5Wb/ulvdgyF90jPU7O0qqCcLpU8U71etcJvDy0YKsY7wgFth8Wrq/7vO+P+kTU+nYE3D8Fkux7//+iG4AA')
        $lzPlain = [Convert]::FromBase64String('AACBMweuD84/w+eIKjEfPNUXRzZ03OjtEA5rhSjfVbNlWU/tnuianWmUHucWtdC19///RH3AAA==')
        $lzProps = B @(0x5D, 0x00, 0x00, 0x10, 0x00)
        $d = Invoke-LzmaDecode -Data $lzAes -Props $lzProps -UnpackSize $hdrAes.Count
        T 'LZMA: a stream another encoder made decodes byte for byte to the 7z header it was made from' ($d.Ok -and $d.Complete -and [Convert]::ToBase64String($d.Bytes) -eq [Convert]::ToBase64String($hdrAes)) "$($d.Ok)/$($d.Complete)/$($d.Why)/$(@($d.Bytes).Count)"
        T 'CRC-32 of a decoded header equals the one zlib computed for it' ((Get-Crc32 $hdrAes) -eq 3774331717 -and (Get-Crc32 $hdrPlain) -eq 698215715) ('{0:X8}/{1:X8}' -f (Get-Crc32 $hdrAes), (Get-Crc32 $hdrPlain))
        $txt = Join-Bytes @((Asc ('The quick brown fox jumps over the lazy dog. ' * 40)), [byte[]](0..255), (Asc ('abcabcabcabd' * 30)))
        $lzTxt = [Convert]::FromBase64String('ACoa2dR0RO8pRtClfuS4ZIEJWYn+mQ7JesAuCfaxbTbbuzZJTMyB+hhgJYdoGgAdVAatZTQVjBXyJRpZ7SvvGQ0dyqTU8BkxWTBHBp4+a+Zf91D2u6IdL5Ph60O6GXWnsyQCT0jqqp1OTReQwybPu7R5d3h+ZU+gA7+vzj6uwvQILWGLb+sGftdAtHFm64qcFe/HYfmir0JscWwsaCatbUpNzwubqbBfvwz58KEJnu3dFw3LvGhVbZi6oA6mkdK5wiEv8n7HQ6qeedmiJZOzcthpznLMxsazE8F7JicMojmDp6OUaOVtWCJfXsoIE6s/+vJ0IzH9rx9E+Yc5J6r+EL1ml351XeN3PtKjxK/U5QcxB2WsxKh95jTCyO+WcEAyVQyHcajVzWDC6BjzC39A2rY3m9SrXXRWg5mQ6eYvGwIJEyGCJTVo//SZXQA=')
        $d = Invoke-LzmaDecode -Data $lzTxt -Props (B @(0x12, 0x00, 0x00, 0x01, 0x00)) -UnpackSize $txt.Count
        T 'LZMA: other literal and position settings (lc=0 lp=2 pb=0), long matches and every byte value decode exactly' ($d.Ok -and $d.Complete -and (Get-Crc32 $d.Bytes) -eq 0x5E79038D) "$($d.Ok)/$($d.Complete)/$($d.Why)"
        $d = Invoke-LzmaDecode -Data $lzTxt -Props (B @(0x12, 0x00, 0x00, 0x01, 0x00)) -UnpackSize ($txt.Count + 10)
        T 'LZMA: an end marker before the declared size stops the decode and says so, never complete' ($d.Ok -and -not $d.Complete -and @($d.Bytes).Count -eq $txt.Count -and $d.Why -match 'ends before the size') "$($d.Ok)/$($d.Complete)/$($d.Why)"
        $d = Invoke-LzmaDecode -Data ([byte[]]$lzTxt[0..150]) -Props (B @(0x12, 0x00, 0x00, 0x01, 0x00)) -UnpackSize $txt.Count
        T 'LZMA: a stream cut short is refused, not padded out' (-not $d.Ok -and $d.Why -match 'ends before the header') "$($d.Ok)/$($d.Why)"
        $bad1 = Invoke-LzmaDecode -Data (Join-Bytes @((B @(1)), [byte[]]$lzAes[1..($lzAes.Count - 1)])) -Props $lzProps -UnpackSize 95
        $bad2 = Invoke-LzmaDecode -Data $lzAes -Props (B @(225, 0, 0, 16, 0)) -UnpackSize 95
        $bad3 = Invoke-LzmaDecode -Data $lzAes -Props (B @(0x5D, 0, 0, 16)) -UnpackSize 95
        T 'LZMA: a non-zero first byte, a property byte past 224 and short properties are each refused' (-not $bad1.Ok -and -not $bad2.Ok -and -not $bad3.Ok) "$($bad1.Why)/$($bad2.Why)/$($bad3.Why)"
        $d = Invoke-LzmaDecode -Data $lzTxt -Props (B @(0x12, 0x00, 0x00, 0x01, 0x00)) -UnpackSize 1099511627776 -MaxOut 100
        T 'LZMA: a declared size of 2^40 is capped -- 100 bytes allocated and decoded, the cap named' ($d.Ok -and -not $d.Complete -and @($d.Bytes).Count -eq 100 -and $d.Why -match 'decode cap') "$($d.Ok)/$(@($d.Bytes).Count)/$($d.Why)"
        $d = Invoke-LzmaDecode -Data $lzTxt -Props (B @(0x12, 0x00, 0x00, 0x01, 0x00)) -UnpackSize $txt.Count -Seconds -1
        T 'LZMA: the clock is checked from the first symbol, and a decode it stops is named, not complete' ($d.Ok -and -not $d.Complete -and $d.Why -match 'second limit') "$($d.Ok)/$($d.Why)"
        # Random bytes behind a valid start: every one must end at once,
        # refused or capped, and never throw.
        $rng = New-Object System.Random 7
        $threw = 0; $over = 0
        $secs = Timed {
            for ($i = 0; $i -lt 40; $i++) {
                $junk = New-Object byte[] (64 + $rng.Next(448)); $rng.NextBytes($junk); $junk[0] = 0
                try { $x = Invoke-LzmaDecode -Data $junk -Props $lzProps -UnpackSize 4096; if (@($x.Bytes).Count -gt 4096) { $over++ } } catch { $threw++ }
            }
        }
        T 'LZMA: forty streams of random bytes each end at once -- refused or bounded, none throws' ($threw -eq 0 -and $over -eq 0 -and $secs -lt 30) "threw=$threw over=$over secs=$secs"

        $p = Put 'p-nomhe.7z' (New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count -Crc 3774331717)
        $f = Facts $p
        T 'a 7z made with -p but WITHOUT -mhe: its compressed header is decompressed, 7zAES is found, the names are read' ($f.Encrypted -eq $true -and -not $f.HeadersEncrypted -and $f.Entries[0] -eq 'secrets\id_rsa' -and -not $f.Why) "$($f.Encrypted)/$($f.HeadersEncrypted)/$($f.Entries -join ',')/$($f.Why)"
        $p = Put 'plain-default.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Crc 698215715)
        $f = Facts $p
        T 'a plain 7z as 7-Zip makes it by default (compressed header, no password) is now read as NOT password-protected' ($f.Encrypted -eq $false -and $f.Entries[1] -eq 'b.txt') "$($f.Encrypted)/$($f.Entries -join ',')/$($f.Why)"
        $p = Put 'crc.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Crc 698215716)
        $f = Facts $p
        T 'a compressed header that fails its CRC once decompressed is not determinable, never clean' ($null -eq $f.Encrypted -and $f.Why -match 'CRC') "$($f.Encrypted)/$($f.Why)"
        $p = Put 'lzma2hdr.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Coder 'lzma2')
        $f = Facts $p
        T 'a header coded with something other than LZMA (here LZMA2) is named and left not determinable' ($null -eq $f.Encrypted -and $f.Why -match 'coded with 21') "$($f.Encrypted)/$($f.Why)"
        $p = Put 'farpack.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -PackSize 99999)
        $f = Facts $p
        T 'a packed header said to reach past the end of the file is not read, and not determinable' ($null -eq $f.Encrypted -and $f.Why -match 'outside the file') "$($f.Encrypted)/$($f.Why)"
        $p = Put 'bomb.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize 2147483648)
        $f = Facts $p
        T 'a header claiming 2 GiB unpacked is never allocated at that size, and what is not decoded is not determinable' ($null -eq $f.Encrypted -and $f.Why -match 'only in part') "$($f.Encrypted)/$($f.Why)"
        $p = Put 'stored.7z' (New-SevenZipEncodedBytes -Packed $hdrAes -UnpackSize $hdrAes.Count -Crc 3774331717 -Coder 'copy')
        $f = Facts $p
        T 'a header stored with the Copy coder is read as it stands' ($f.Encrypted -eq $true -and $f.Entries[0] -eq 'secrets\id_rsa') "$($f.Encrypted)/$($f.Why)"
        $pre = Get-SevenZipFactsFromBytes -Sig ([byte[]](New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count)[0..31]) -FileLength 1000 -NextHeader ([byte[]](New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count)[(32 + $lzAes.Count)..(31 + $lzAes.Count + 40)])
        $part = Resolve-SevenZipEncodedHeader -Plan $pre.Decode -Packed $lzAes -MaxOut 40
        $partP = Resolve-SevenZipEncodedHeader -Plan @{ Coder = '030101'; Props = $lzProps; PackSize = $lzPlain.Count; UnpackSize = $hdrPlain.Count; Crc = -1 } -Packed $lzPlain -MaxOut 40
        T 'a header decoded only in part is trusted for what it shows: a 7zAES coder in the part is certain, its absence is not' ($part.Encrypted -eq $true -and -not $part.Complete -and $null -eq $partP.Encrypted -and $partP.Why -match 'only in part') "$($part.Encrypted)/$($partP.Encrypted)/$($partP.Why)"
        # The real -p -v shape without -mhe: the packed header and the
        # EncodedHeader both at the end of the LAST volume, read across all.
        $whole = New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count -Crc 3774331717
        $cut = 50
        $v1 = Join-Path $tdir 'nomhe.7z.001'; $v2 = Join-Path $tdir 'nomhe.7z.002'; $v3 = Join-Path $tdir 'nomhe.7z.003'
        [System.IO.File]::WriteAllBytes($v1, [byte[]]$whole[0..($cut - 1)])
        [System.IO.File]::WriteAllBytes($v2, [byte[]]$whole[$cut..(2 * $cut - 1)])
        [System.IO.File]::WriteAllBytes($v3, [byte[]]$whole[(2 * $cut)..($whole.Count - 1)])
        $f = Get-SevenZipFacts -Path $v1 -Length $cut -SpanPaths @($v1, $v2, $v3) -SpanSizes @([long]$cut, [long]$cut, [long]($whole.Count - 2 * $cut))
        T 'a -p volume set without -mhe: the compressed header is read across the volumes and decompressed' ($f.Encrypted -eq $true -and -not $f.HeadersEncrypted -and $f.HeaderDecoded) "$($f.Encrypted)/$($f.HeaderDecoded)/$($f.Why)"
        Remove-Item -LiteralPath $v1, $v2, $v3 -Force

        # ---- what the review found: a record list that ends at a fixed
        # count, an id written with a leading zero byte, a header that stops
        # early, names after many properties, more than 64 folders. Each one
        # 7-Zip opens as password-protected; each read as plain before.
        $cAes = Join-Bytes @((B @(0x24, 0x06, 0xF1, 0x07, 0x01)), (B @(0x02, 0x3F, 0x00)))
        $cLz = B @(0x23, 0x03, 0x01, 0x01, 0x05, 0x5D, 0x00, 0x00, 0x01, 0x00)
        $fAes = Join-Bytes @((Vint 2), $cAes, $cLz, (B @(0x00, 0x01)))
        $codersAes = Join-Bytes @((B @(0x07, 0x0B, 0x01, 0x00)), $fAes, (B @(0x0C, 0x40, 0x40, 0x00)))
        $packOne = B @(0x06, 0x00, 0x01, 0x09, 0x08)
        $crcRec = Join-Bytes @((B @(0x0A, 0x01)), (U32 1))
        $many = @(); for ($i = 0; $i -lt 20; $i++) { $many += ,$crcRec }
        $nh = Join-Bytes @((B @(0x01, 0x04)), $packOne, (Join-Bytes $many), (B @(0x00)), $codersAes, (B @(0x00, 0x00)))
        $f = Facts (Put 'many-crc.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nh))
        T 'twenty CRC records in a PackInfo are walked to their end: the 7zAES coder after them is found' ($f.Encrypted -eq $true) "$($f.Encrypted)/$($f.Why)"
        $props = @(); for ($i = 0; $i -lt 65; $i++) { $props += ,(B @(0x01, 0x01, 0x00)) }
        $nh = Join-Bytes @((B @(0x01, 0x02)), (Join-Bytes $props), (B @(0x00, 0x04)), $packOne, (B @(0x00)), $codersAes, (B @(0x00, 0x00)))
        $f = Facts (Put 'many-props.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nh))
        T 'sixty-five archive properties are walked to their end: the 7zAES coder after them is found' ($f.Encrypted -eq $true) "$($f.Encrypted)/$($f.Why)"
        $h = Read-SevenZipHeader -Buf (B @(0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x10)) -Pos 1
        T 'a header that stops inside its PackInfo is NOT "no password"' ($null -eq $h.Encrypted) "$($h.Encrypted)/$($h.Why)"
        $h = Read-SevenZipHeader -Buf (Join-Bytes @((B @(0x01, 0x04)), $packOne, (B @(0x00, 0x00)))) -Pos 1
        T 'a header that stops after its streams, with neither names nor its end byte, is NOT "no password"' ($null -eq $h.Encrypted) "$($h.Encrypted)/$($h.Why)"
        $cAes5 = Join-Bytes @((B @(0x25, 0x00, 0x06, 0xF1, 0x07, 0x01)), (B @(0x02, 0x3F, 0x00)))
        $nh = Join-Bytes @((B @(0x01, 0x04)), $packOne, (B @(0x00, 0x07, 0x0B, 0x01, 0x00)), (Vint 2), $cAes5, $cLz, (B @(0x00, 0x01, 0x0C, 0x40, 0x40, 0x00, 0x00, 0x00)))
        $f = Facts (Put 'aes5.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nh))
        T 'a 7zAES id written with a leading zero byte (00 06 F1 07 01) is still 7zAES, as 7-Zip reads ids as numbers' ($f.Encrypted -eq $true) "$($f.Encrypted)/$($f.Why)"
        $cOdd = B @(0x04, 0xDE, 0xAD, 0xBE, 0xEF)
        $nh = Join-Bytes @((B @(0x01, 0x04)), $packOne, (B @(0x00, 0x07, 0x0B, 0x01, 0x00, 0x01)), $cOdd, (B @(0x0C, 0x40, 0x00, 0x00, 0x00)))
        $f = Facts (Put 'odd-coder.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nh))
        T 'a coder id this audit cannot place is named and NOT read as "no password"' ($null -eq $f.Encrypted -and $f.Why -match 'DEADBEEF') "$($f.Encrypted)/$($f.Why)"
        $name = [System.Text.Encoding]::Unicode.GetBytes("vault.kdbx`0")
        $dummies = @(); for ($i = 0; $i -lt 70; $i++) { $dummies += ,(B @(0x19, 0x00)) }
        $nh = Join-Bytes @((B @(0x01, 0x04)), $packOne, (B @(0x00, 0x07, 0x0B, 0x01, 0x00, 0x01)), $cLz, (B @(0x0C, 0x40, 0x00, 0x00)), (B @(0x05, 0x01)), (Join-Bytes $dummies), (B @(0x11)), (Vint ($name.Count + 1)), (B @(0x00)), $name, (B @(0x00, 0x00)))
        $f = Facts (Put 'late-name.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nh))
        T 'a file name after seventy other file properties is still read, so a credential file cannot be hidden behind them' ($f.Encrypted -eq $false -and $f.Entries -contains 'vault.kdbx') "$($f.Encrypted)/$($f.Entries -join ',')/$($f.Why)"
        $fLz = Join-Bytes @((Vint 1), $cLz)
        $pk = @(); $fs = @(); $us = @(); for ($i = 0; $i -lt 100; $i++) { $pk += ,(B @(0x08)); $fs += ,$fLz; $us += ,(B @(0x40)) }
        $nhPlain = Join-Bytes @((B @(0x01, 0x04, 0x06, 0x00)), (Vint 100), (B @(0x09)), (Join-Bytes $pk), (B @(0x00, 0x07, 0x0B)), (Vint 100), (B @(0x00)), (Join-Bytes $fs), (B @(0x0C)), (Join-Bytes $us), (B @(0x00, 0x00, 0x00)))
        $nhAes = Join-Bytes @((B @(0x01, 0x04, 0x06, 0x00)), (Vint 101), (B @(0x09)), (Join-Bytes $pk), (B @(0x08, 0x00, 0x07, 0x0B)), (Vint 101), (B @(0x00)), (Join-Bytes $fs), $fAes, (B @(0x0C)), (Join-Bytes $us), (B @(0x40, 0x40, 0x00, 0x00, 0x00)))
        $fa = Facts (Put 'folders-aes.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nhAes))
        $fp = Facts (Put 'folders-plain.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader $nhPlain))
        T 'more than 64 folders (a non-solid 7z): the 7zAES coder in folder 101 is found, and 100 plain folders read plain' ($fa.Encrypted -eq $true -and $fp.Encrypted -eq $false) "$($fa.Encrypted)/$($fa.Why)/$($fp.Encrypted)/$($fp.Why)"
        # A plain header that ends, but whose declared size runs past the
        # 1 MiB this tool reads: the part read does not settle it.
        $nhBig = Join-Bytes @((B @(0x01, 0x04)), $packOne, (B @(0x00, 0x07, 0x0B, 0x01, 0x00, 0x01)), $cLz, (B @(0x0C, 0x40, 0x00, 0x00, 0x00)))
        $pad = New-Object byte[] (1100000 - $nhBig.Count)
        $f = Facts (Put 'big-header.7z' (New-SevenZipBytes -HeaderKind 'raw' -RawHeader (Join-Bytes @($nhBig, $pad))))
        T 'a plain header larger than the 1 MiB read is NOT "no password" from its first part' ($null -eq $f.Encrypted -and $f.Why -match '1 MiB') "$($f.Encrypted)/$($f.Why)"
        $l1 = Invoke-LzmaDecode -Data $lzAes -Props (B @(44, 0, 0, 16, 0)) -UnpackSize 95
        $l2 = Invoke-LzmaDecode -Data $lzAes -Props (B @(224, 0, 0, 16, 0)) -UnpackSize 95
        T 'LZMA: literal settings 7-Zip never writes for a header (lc+lp above 4) are refused before the table is built' (-not $l1.Ok -and -not $l2.Ok -and $l1.Why -match 'lc\+lp') "$($l1.Why)/$($l2.Why)"
        # The run-wide decode allowance: once it is spent, a compressed header
        # is named as not decompressed, never cleared.
        $dd = NewDir 'allowance'
        Put 'one.7z' (New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count -Crc 3774331717) $dd | Out-Null
        Put 'two.7z' (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Crc 698215715) $dd | Out-Null
        $cands = @(); foreach ($it in @(Get-ChildItem -LiteralPath $dd -File)) { $cands += @{ Item = $it; Folder = $dd; Role = 'public' } }
        $res = Invoke-ArchiveClassification -Candidates $cands -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -DecodeAllowanceSeconds 0
        $named = @($res.Archives | Where-Object { $null -eq $_.Encrypted -and $_.ParseError -match 'decode allowance was spent' })
        T 'with the decode allowance spent, each compressed header is named as not decompressed and left not determinable' ($named.Count -eq 2) (($res.Archives | ForEach-Object { "$($_.Name)=$($_.Encrypted):$($_.ParseError)" }) -join ' | ')
        $res = Invoke-ArchiveClassification -Candidates $cands -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } }
        $one = @($res.Archives | Where-Object { $_.Name -eq 'one.7z' })[0]; $two = @($res.Archives | Where-Object { $_.Name -eq 'two.7z' })[0]
        T 'the classifier decodes compressed headers after grading the rest: one -p archive, one plain' ($one.Encrypted -eq $true -and $two.Encrypted -eq $false -and -not $one.ParseError) "$($one.Encrypted)/$($two.Encrypted)/$($one.ParseError)"
        # A part of a set whose own header cannot be read is not cleared by
        # a sibling's "no password".
        $ds = NewDir 'setprop'
        Put 'x.part1.rar' (New-Rar5Bytes -ArchFlags 1 -Files @(@{ Name = 'a.txt'; Data = 'a' })) $ds | Out-Null
        Put 'x.part2.rar' (Join-Bytes @((B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)), (B @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)))) $ds | Out-Null
        $cl = Classify -Dir $ds
        $p2 = @($cl.Res.Archives | Where-Object { $_.Name -eq 'x.part2.rar' })[0]
        T 'a set part whose header cannot be read is NOT cleared by a sibling that reads "no password"' ($null -ne $p2 -and $null -eq $p2.Encrypted) "$(if ($p2) { "$($p2.Encrypted)/$($p2.ParseError)" } else { 'part2 not graded' })"

        # ---- self-extracting programs. A minimal PE (Microsoft's PE format
        # specification): a DOS header whose e_lfanew points at "PE\0\0", a
        # COFF header with one section, an optional header (PE32 or PE32+)
        # whose data directory 4 is the certificate table, and one section
        # of 0x200 bytes at 0x200, so the program's code ends at 0x400.
        function New-PeStub {
            param([switch]$Plus, [long]$CertAt = 0, [long]$CertSize = 0, [int]$Sections = 1, [int]$Lfanew = 0x40)
            $optSize = 224; $magic = 0x10B; $dd = 96
            if ($Plus) { $optSize = 240; $magic = 0x20B; $dd = 112 }
            $b = New-Object byte[] 0x400
            $b[0] = 0x4D; $b[1] = 0x5A
            [Array]::Copy([BitConverter]::GetBytes([int]$Lfanew), 0, $b, 0x3C, 4)
            if (($Lfanew + 4) -le $b.Count) { $b[$Lfanew] = 0x50; $b[$Lfanew + 1] = 0x45 }
            $coff = $Lfanew + 4
            if (($coff + 20) -le $b.Count) {
                [Array]::Copy([BitConverter]::GetBytes([uint16]$Sections), 0, $b, $coff + 2, 2)
                [Array]::Copy([BitConverter]::GetBytes([uint16]$optSize), 0, $b, $coff + 16, 2)
            }
            $opt = $Lfanew + 24
            if (($opt + $optSize) -le $b.Count) {
                [Array]::Copy([BitConverter]::GetBytes([uint16]$magic), 0, $b, $opt, 2)
                [Array]::Copy([BitConverter]::GetBytes([int]16), 0, $b, $opt + $dd - 4, 4)
                [Array]::Copy([BitConverter]::GetBytes([int]$CertAt), 0, $b, $opt + $dd + 32, 4)
                [Array]::Copy([BitConverter]::GetBytes([int]$CertSize), 0, $b, $opt + $dd + 36, 4)
                $sec = $opt + $optSize
                if (($sec + 40) -le $b.Count) {
                    [Array]::Copy([BitConverter]::GetBytes([int]0x200), 0, $b, $sec + 16, 4)
                    [Array]::Copy([BitConverter]::GetBytes([int]0x200), 0, $b, $sec + 20, 4)
                }
            }
            return $b
        }
        $stub = New-PeStub
        $pi = Get-PeOverlayInfo -Head ([byte[]](Join-Bytes @($stub, (New-Object byte[] 100)))[0..1023]) -FileLength 1124
        T 'PE overlay: a PE32 program''s code ends after its last section, and what follows is the overlay' ($pi.Parsed -and @($pi.Regions).Count -eq 1 -and $pi.Regions[0].Start -eq 0x400 -and $pi.Regions[0].End -eq 1124) "$($pi.Parsed)/$($pi.Why)/$(@($pi.Regions).Count)"
        $pi = Get-PeOverlayInfo -Head (New-PeStub -Plus) -FileLength 2048
        T 'PE overlay: the PE32+ (64-bit) layout is read the same way' ($pi.Parsed -and $pi.Regions[0].Start -eq 0x400) "$($pi.Parsed)/$($pi.Why)"
        $pi = Get-PeOverlayInfo -Head (New-PeStub -CertAt 0x400 -CertSize 0x100) -FileLength 0x500
        T 'PE overlay: a signed program whose only extra bytes are its certificate has no overlay' ($pi.Parsed -and @($pi.Regions).Count -eq 0) "$($pi.Parsed)/$(@($pi.Regions).Count)"
        $pi = Get-PeOverlayInfo -Head (New-PeStub -CertAt 0x500 -CertSize 0x100) -FileLength 0x700
        T 'PE overlay: bytes before the certificate and after it are both overlay' (@($pi.Regions).Count -eq 2 -and $pi.Regions[0].End -eq 0x500 -and $pi.Regions[1].Start -eq 0x600) "$(@($pi.Regions).Count)"
        $bad1 = Get-PeOverlayInfo -Head (New-PeStub -Lfanew 5000) -FileLength 4096
        $bad2 = Get-PeOverlayInfo -Head (New-PeStub -Sections 1000) -FileLength 4096
        $bad3 = Get-PeOverlayInfo -Head (Asc 'MZ this is not really a program at all, just two letters') -FileLength 60
        T 'PE overlay: an e_lfanew past the head, 1000 sections, or no PE header at all is NOT parsed, and nothing throws' (-not $bad1.Parsed -and -not $bad2.Parsed -and -not $bad3.Parsed) "$($bad1.Why)/$($bad2.Why)/$($bad3.Why)"
        $sfxDir = NewDir 'sfx'
        $rar5hp = New-Rar5Bytes -Crypt $true
        Put 'collected.exe' (Join-Bytes @($stub, $rar5hp)) $sfxDir | Out-Null
        Put 'notes-p.exe' (Join-Bytes @($stub, (Asc ';!@Install@!UTF-8!' + "`r`nTitle=`"x`"`r`n;!@InstallEnd@!"), (New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count -Crc 3774331717))) $sfxDir | Out-Null
        Put 'plain7z.exe' (Join-Bytes @($stub, (New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Crc 698215715))) $sfxDir | Out-Null
        $zipRel = New-ZipBytes -Entries @(@{ Name = 'Outlook.pst'; Flags = 1; Data = 'x' })
        Put 'zip-archive-relative.exe' (Join-Bytes @($stub, $zipRel)) $sfxDir | Out-Null
        Put 'zip-file-relative.exe' (New-ZipBytes -Entries @(@{ Name = 'keys.kdbx'; Flags = 1; Data = 'x' }) -Prefix $stub) $sfxDir | Out-Null
        Put 'zip-plain.exe' (Join-Bytes @($stub, (New-ZipBytes -Entries @(@{ Name = 'readme.txt'; Data = 'x' })))) $sfxDir | Out-Null
        Put 'nooverlay.exe' $stub $sfxDir | Out-Null
        $far = New-Object byte[] 70000
        Put 'far.exe' (Join-Bytes @($stub, $far, $rar5hp)) $sfxDir | Out-Null
        $cands = @(); foreach ($it in @(Get-ChildItem -LiteralPath $sfxDir -File)) { $cands += @{ Item = $it; Folder = $sfxDir; Role = 'public' } }
        $res = Invoke-ArchiveClassification -Candidates $cands -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'NotSigned' }
        $by = @{}; foreach ($a in @($res.Archives)) { $by[$a.Name] = $a }
        T 'SFX: a RAR 5.0 -hp archive behind a program is found, read at its own offset, and password-protected' ($by.ContainsKey('collected.exe') -and $by['collected.exe'].Kind -eq 'rar5' -and $by['collected.exe'].Sfx -and $by['collected.exe'].SfxBase -eq 0x400 -and $by['collected.exe'].Encrypted -eq $true) "$(($by.Keys | Sort-Object) -join ',')"
        T 'SFX: a 7z behind 7-Zip''s installer configuration block is found, its compressed header decoded at the right base, names read' ($by.ContainsKey('notes-p.exe') -and $by['notes-p.exe'].Encrypted -eq $true -and @($by['notes-p.exe'].Entries) -contains 'secrets\id_rsa') "$(if ($by['notes-p.exe']) { "$($by['notes-p.exe'].Encrypted)/$($by['notes-p.exe'].ParseError)" })"
        T 'SFX: a plain 7z behind a program is plain' ($by.ContainsKey('plain7z.exe') -and $by['plain7z.exe'].Encrypted -eq $false) "$(if ($by['plain7z.exe']) { "$($by['plain7z.exe'].Encrypted)/$($by['plain7z.exe'].ParseError)" })"
        T 'SFX: a ZIP behind a program is read whether its offsets count from its own start or from the file''s, its credential names seen' ($by.ContainsKey('zip-archive-relative.exe') -and $by['zip-archive-relative.exe'].Encrypted -eq $true -and @($by['zip-archive-relative.exe'].Entries) -contains 'Outlook.pst' -and $by.ContainsKey('zip-file-relative.exe') -and @($by['zip-file-relative.exe'].Entries) -contains 'keys.kdbx' -and $by.ContainsKey('zip-plain.exe') -and $by['zip-plain.exe'].Encrypted -eq $false -and -not $by['zip-plain.exe'].ParseError) "$(if ($by['zip-archive-relative.exe']) { "$($by['zip-archive-relative.exe'].Encrypted)/$($by['zip-archive-relative.exe'].ParseError)/$(@($by['zip-archive-relative.exe'].Entries) -join ',')" })"
        T 'SFX: a program with nothing appended, and one whose archive starts past 64 KiB, are not graded (the second is the declared limit)' (-not $by.ContainsKey('nooverlay.exe') -and -not $by.ContainsKey('far.exe') -and $res.Probes.SfxScanned -eq 8 -and $res.Probes.SfxFound -eq 6) "scanned=$($res.Probes.SfxScanned) found=$($res.Probes.SfxFound) $(($by.Keys | Sort-Object) -join ',')"
        $script:SigCalls = 0
        $resS = Invoke-ArchiveClassification -Candidates $cands -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) $script:SigCalls++; 'Valid' }
        T 'SFX: a program with no certificate table is never asked for its signature (no hashing for nothing) and is graded' ($script:SigCalls -eq 0 -and @($resS.Archives | Where-Object { $_.Sfx }).Count -eq 6 -and $resS.Probes.SfxSigned -eq 0) "calls=$($script:SigCalls) graded=$(@($resS.Archives | Where-Object { $_.Sfx }).Count)"
        $resE = Invoke-ArchiveClassification -Candidates $cands -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) throw 'no Authenticode here' }
        T 'SFX: a signature that cannot be checked counts as unsigned -- graded, never left out' (@($resE.Archives | Where-Object { $_.Sfx }).Count -eq 6 -and $resE.Probes.SfxSigned -eq 0) "graded=$(@($resE.Archives | Where-Object { $_.Sfx }).Count)"
        # A signed installer: the archive sits before the certificate table,
        # which is a well-formed WIN_CERTIFICATE (dwLength, revision 0x0200,
        # type 2, a DER SEQUENCE).
        function New-WinCert {
            param([int]$Der = 64, [byte[]]$Pad = $null)
            $seq = Join-Bytes @((B @(0x30, 0x82, (($Der -shr 8) -band 0xFF), ($Der -band 0xFF))), (New-Object byte[] $Der))
            $body = Join-Bytes @($seq, $Pad)
            return (Join-Bytes @((U32 (8 + $body.Count)), (U16 0x0200), (U16 0x0002), $body))
        }
        $sigDir = NewDir 'sfxsigned'
        $arc = New-SevenZipEncodedBytes -Packed $lzAes -UnpackSize $hdrAes.Count -Crc 3774331717
        $cert = New-WinCert
        Put 'vendor-installer.exe' (Join-Bytes @((New-PeStub -CertAt (0x400 + $arc.Count) -CertSize $cert.Count), $arc, $cert)) $sigDir | Out-Null
        $sigC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $sigDir -File)) { $sigC += @{ Item = $it; Folder = $sigDir; Role = 'public' } }
        $script:SigCalls = 0
        $rs = Invoke-ArchiveClassification -Candidates $sigC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) $script:SigCalls++; 'Valid' }
        T 'SFX: a program validly signed by its publisher is left out and counted -- an installer, not an archive packed here' ($script:SigCalls -eq 1 -and @($rs.Archives).Count -eq 0 -and $rs.Probes.SfxSigned -eq 1 -and $rs.Probes.SfxFound -eq 1) "calls=$($script:SigCalls) signed=$($rs.Probes.SfxSigned) graded=$(@($rs.Archives).Count)"
        $rm = Invoke-ArchiveClassification -Candidates $sigC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'HashMismatch' }
        T 'SFX: a signature that no longer matches the file (an archive appended after signing) is graded, never left out' (@($rm.Archives).Count -eq 1 -and $rm.Archives[0].Encrypted -eq $true -and $rm.Probes.SfxSigned -eq 0) "graded=$(@($rm.Archives).Count)"
        Remove-Item -LiteralPath $sigDir -Recurse -Force
        # The certificate table is not hashed by Authenticode, so an archive
        # PADDED INTO it keeps the signature Valid (CVE-2013-3900). Found
        # there, it is graded whatever the signature says -- and so is one in
        # a table that is not a WIN_CERTIFICATE at all.
        $padDir = NewDir 'sfxpad'
        $padded = New-WinCert -Pad $arc
        Put 'padded-cert.exe' (Join-Bytes @((New-PeStub -CertAt 0x400 -CertSize $padded.Count), $padded)) $padDir | Out-Null
        Put 'fake-cert.exe' (Join-Bytes @((New-PeStub -CertAt 0x400 -CertSize $arc.Count), $arc)) $padDir | Out-Null
        # A real installer's plain archive before its certificate, and a
        # password-protected one padded into that certificate: the signature
        # IS asked (there is a candidate outside the table), comes back Valid,
        # and still only the outside candidate is excused.
        $plainArc = New-SevenZipEncodedBytes -Packed $lzPlain -UnpackSize $hdrPlain.Count -Crc 698215715
        Put 'signed-plus-padding.exe' (Join-Bytes @((New-PeStub -CertAt (0x400 + $plainArc.Count) -CertSize $padded.Count), $plainArc, $padded)) $padDir | Out-Null
        $padC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $padDir -File)) { $padC += @{ Item = $it; Folder = $padDir; Role = 'public' } }
        $rp = Invoke-ArchiveClassification -Candidates $padC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'Valid' }
        $pby = @{}; foreach ($a in @($rp.Archives)) { $pby[$a.Name] = $a }
        T 'SFX: an archive padded into a valid certificate table, or in a table that is no certificate, is found and graded even with a Valid signature' ($pby.ContainsKey('padded-cert.exe') -and $pby['padded-cert.exe'].Encrypted -eq $true -and $pby.ContainsKey('fake-cert.exe') -and $pby['fake-cert.exe'].Encrypted -eq $true -and $pby.ContainsKey('signed-plus-padding.exe') -and $pby['signed-plus-padding.exe'].Encrypted -eq $true) "$(($pby.Keys | Sort-Object) -join ',') signed=$($rp.Probes.SfxSigned)"
        Remove-Item -LiteralPath $padDir -Recurse -Force
        # DECOYS: a signature with nothing valid behind it, or a real plain
        # archive, in front of the real password-protected one. Every
        # candidate is graded and the most severe kept.
        $decDir = NewDir 'sfxdecoy'
        $encRar = New-Rar5Bytes -Crypt $true
        $plainZip = New-ZipBytes -Entries @(@{ Name = 'readme.txt'; Data = 'x' })
        Put 'cab-decoy.exe' (Join-Bytes @($stub, (Asc 'MSCF'), (New-Object byte[] 60), $encRar)) $decDir | Out-Null
        Put '7z-decoy.exe' (Join-Bytes @($stub, (B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04)), (New-Object byte[] 24), $encRar)) $decDir | Out-Null
        Put 'pk-decoy.exe' (Join-Bytes @($stub, (B @(0x50, 0x4B, 0x03, 0x04)), (New-Object byte[] 40), $encRar)) $decDir | Out-Null
        Put 'zip-decoy.exe' (Join-Bytes @($stub, $plainZip, $encRar)) $decDir | Out-Null
        $zeroCrc = [byte[]]$encRar.Clone(); for ($i = 8; $i -lt 12; $i++) { $zeroCrc[$i] = 0 }
        Put 'rar-zero-crc.exe' (Join-Bytes @($stub, (Asc 'MSCF'), (New-Object byte[] 60), $zeroCrc)) $decDir | Out-Null
        $decC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $decDir -File)) { $decC += @{ Item = $it; Folder = $decDir; Role = 'public' } }
        $rd = Invoke-ArchiveClassification -Candidates $decC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'NotSigned' }
        $dby = @{}; foreach ($a in @($rd.Archives)) { $dby[$a.Name] = $a }
        $allEnc = (@('cab-decoy.exe', '7z-decoy.exe', 'pk-decoy.exe', 'zip-decoy.exe', 'rar-zero-crc.exe') | Where-Object { $dby.ContainsKey($_) -and $dby[$_].Encrypted -eq $true }).Count
        T 'SFX: a decoy signature, or a real plain archive, in front of a password-protected RAR cannot clear it -- the most severe candidate is kept, and a zeroed header CRC does not hide the RAR' ($allEnc -eq 5) "$(($dby.Keys | Sort-Object | ForEach-Object { $_ + '=' + $dby[$_].Kind + '/' + $dby[$_].Encrypted }) -join ' ')"
        Remove-Item -LiteralPath $decDir -Recurse -Force
        # An installer that keeps a stored ZIP fragment early in its overlay
        # (no end record) is not graded "may be password-protected".
        $nsDir = NewDir 'sfxnsis'
        $lh = Join-Bytes @((B @(0x50, 0x4B, 0x03, 0x04)), (U16 20), (U16 0), (U16 0), (U16 0), (U16 0), (U32 0), (U32 5), (U32 5), (U16 8), (U16 0), (Asc 'data.bin'), (Asc 'hello'))
        Put 'setup.exe' (Join-Bytes @($stub, (Asc 'NullsoftInst'), (New-Object byte[] 200), $lh, (New-Object byte[] 300))) $nsDir | Out-Null
        $nsC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $nsDir -File)) { $nsC += @{ Item = $it; Folder = $nsDir; Role = 'public' } }
        $rn = Invoke-ArchiveClassification -Candidates $nsC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'NotSigned' }
        T 'SFX: an installer with a ZIP fragment and no end record in its overlay is not graded at all -- no "may be password-protected" in Public' (@($rn.Archives).Count -eq 0) "$(@($rn.Archives).Count) $(if (@($rn.Archives).Count) { $rn.Archives[0].Kind + '/' + $rn.Archives[0].Encrypted })"
        Remove-Item -LiteralPath $nsDir -Recurse -Force
        # A header that cannot be read is NOT a program with nothing appended:
        # it is counted, named, and said.
        $unDir = NewDir 'sfxunparsed'
        $badStub = New-PeStub; [Array]::Copy([BitConverter]::GetBytes([int]0x7FFFFF00), 0, $badStub, 0x40 + 24 + 224 + 20, 4)
        Put 'broken.exe' (Join-Bytes @($badStub, $arc)) $unDir | Out-Null
        $unC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $unDir -File)) { $unC += @{ Item = $it; Folder = $unDir; Role = 'public' } }
        $ru = Invoke-ArchiveClassification -Candidates $unC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'NotSigned' }
        $ruRep = (Get-ArchiveStagingReport -Archives $ru.Archives -Folders @(@{ Path = $unDir; Role = 'public'; State = 'searched'; Files = 1; Skipped = 0; Capped = $false; Denied = 0; Locked = 0; LockedNames = @() }) -Probes $ru.Probes).Lines -join "`n"
        T 'SFX: a program whose header cannot be read is counted as NOT checked and named, never as checked' ($ru.Probes.SfxUnparsed -eq 1 -and $ru.Probes.SfxScanned -eq 0 -and $ruRep -match '\[INFO\] 1 program file\(s\) were NOT checked for an appended archive -- their header could not be read: .*broken\.exe') $ruRep
        Remove-Item -LiteralPath $unDir -Recurse -Force
        # A window crowded with signature look-alikes is examined to a fixed
        # count and declared crowded, never scanned for seconds, never clean.
        $crowd = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt 9000; $i++) { foreach ($b in @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x05)) { $crowd.Add([byte]$b) } }
        $cw = $null
        $secs = Timed { $script:cw = Find-SfxArchive -Window $crowd.ToArray() }
        T 'SFX: an overlay crowded with nine thousand signature look-alikes is declared crowded within seconds, not searched to the end' ($script:cw.TooMany -and @($script:cw.Candidates).Count -eq 0 -and $secs -lt 5) "tooMany=$($script:cw.TooMany) secs=$secs"
        # The 64 KiB window, both sides of its edge, and the readers that
        # must use the base: a ZIP whose central flags were cleared (only its
        # local headers, read at the base, show the password) and a CAB set.
        $wDir = NewDir 'sfxwindow'
        Put 'at30k.exe' (Join-Bytes @($stub, (New-Object byte[] 30000), $encRar)) $wDir | Out-Null
        Put 'at65530.exe' (Join-Bytes @($stub, (New-Object byte[] 65530), $encRar)) $wDir | Out-Null
        Put 'at65537.exe' (Join-Bytes @($stub, (New-Object byte[] 65537), $encRar)) $wDir | Out-Null
        Put 'zip-cleared.exe' (Join-Bytes @($stub, (New-ZipBytes -Entries @(@{ Name = 'a.txt'; Flags = 1; Data = 'x' }) -ClearCentralFlags))) $wDir | Out-Null
        $cab = New-Object byte[] 0x40; $cab[0] = 0x4D; $cab[1] = 0x53; $cab[2] = 0x43; $cab[3] = 0x46
        [Array]::Copy([BitConverter]::GetBytes([int]0x40), 0, $cab, 8, 4); [Array]::Copy([BitConverter]::GetBytes([int]0x2C), 0, $cab, 16, 4); $cab[24] = 3; $cab[25] = 1; $cab[0x1E] = 0x02
        Put 'cabset.exe' (Join-Bytes @($stub, $cab)) $wDir | Out-Null
        $wC = @(); foreach ($it in @(Get-ChildItem -LiteralPath $wDir -File)) { $wC += @{ Item = $it; Folder = $wDir; Role = 'public' } }
        $rw = Invoke-ArchiveClassification -Candidates $wC -ZoneReader { param($p) @{ Zone = -1; HostUrl = '' } } -SignatureReader { param($p) 'NotSigned' }
        $wby = @{}; foreach ($a in @($rw.Archives)) { $wby[$a.Name] = $a }
        T 'SFX: an archive 30 KB and 65530 bytes past the code is found; one 65537 bytes past is the declared limit' ($wby.ContainsKey('at30k.exe') -and $wby.ContainsKey('at65530.exe') -and -not $wby.ContainsKey('at65537.exe')) "$(($wby.Keys | Sort-Object) -join ',')"
        T 'SFX: a ZIP whose central flags were cleared shows its password through its local headers, read at the base' ($wby.ContainsKey('zip-cleared.exe') -and $wby['zip-cleared.exe'].Encrypted -eq $true) "$(if ($wby['zip-cleared.exe']) { [string]$wby['zip-cleared.exe'].Encrypted })"
        T 'SFX: a cabinet behind a program is read at its base -- its next-cabinet flag makes it a volume of a set' ($wby.ContainsKey('cabset.exe') -and $wby['cabset.exe'].MultiVolume) "$(if ($wby['cabset.exe']) { [string]$wby['cabset.exe'].MultiVolume })"
        Remove-Item -LiteralPath $wDir -Recurse -Force
        $rep = Get-ArchiveStagingReport -Archives $res.Archives -Folders @(@{ Path = $sfxDir; Role = 'public'; State = 'searched'; Files = 8; Skipped = 0; Capped = $false; Denied = 0; Locked = 0; LockedNames = @() }) -Probes $res.Probes
        $rt = $rep.Lines -join "`n"
        T 'SFX report: the finding says where the archive starts, and the program count is stated' ($rt -match '\[WARNING\] An archive made on this machine is password-protected, in a staging folder: .*collected\.exe' -and $rt -match 'format: RAR 5\.0 inside a self-extracting program \(the archive starts at byte 1024\)' -and $rt -match '\[INFO\] 8 program file\(s\) were checked for an archive appended after their code \(a self-extracting archive\); 6 held one\.') $rt
        $pr = Put 'renamed.exe' (New-Rar5Bytes -Crypt $true)
        $f = Facts $pr
        T 'a RAR at byte 0 named .exe is graded as a RAR, as before -- not as a program' ($f.Kind -eq 'rar5' -and $f.Encrypted -eq $true) "$($f.Kind)/$($f.Encrypted)"
        Remove-Item -LiteralPath $sfxDir -Recurse -Force

        # ---- hostile headers: every one must finish at once and never be
        # read as clean. Each was a hang before the bounds came from the
        # buffer.
        function SevenRaw { param([byte[]]$nh) $sig = Join-Bytes @((B @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04)), (U32 0), (U64 0), (U64 $nh.Count), (U32 0)); return (Join-Bytes @($sig, $nh)) }
        $hostile = @(
            @{ N = 'a pack count of 2^32 with nothing behind it'; H = (B @(0x17, 0x06, 0x00, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0x09)) },
            @{ N = 'a complex coder claiming 2^31 output streams'; H = (B @(0x17, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x11, 0x01, 0x01, 0xF0, 0xFF, 0xFF, 0xFF, 0x7F)) },
            @{ N = 'an archive-property size that points backwards'; H = (Join-Bytes @((B @(0x01, 0x02, 0x19, 0xFF)), (B @(0xF6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)))) },
            @{ N = 'a files-info property size that points backwards'; H = (Join-Bytes @((B @(0x01, 0x05, 0x01, 0x11, 0xFF)), (B @(0xF6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)))) }
        )
        foreach ($h in $hostile) {
            $p = Put 'hostile.7z' (SevenRaw $h.H)
            $f = $null
            $secs = Timed { $script:hf = Facts $p }
            $f = $script:hf
            T ('a hostile 7z header (' + $h.N + ') finishes at once and is not read as clean') ($secs -lt 3 -and $f.Encrypted -ne $false) ("{0:N1}s enc={1}" -f $secs, $f.Encrypted)
        }
        $p = Put 'hostile5.rar' (Join-Bytes @((B @(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)), (U32 0), (Vint 12), (Vint 2), (Vint 3), (B @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01)), (Vint 5)))
        $secs = Timed { $script:hf = Facts $p }
        T 'a hostile RAR 5.0 header (a ten-byte negative size) finishes at once' ($secs -lt 3) ("{0:N1}s" -f $secs)

        # ---- CAB.
        $f = Get-CabFactsFromBytes -Head (New-CabBytes -Flags 0x0002)
        T 'a CAB with cfhdrNEXT_CABINET is a volume of a set' ($f.MultiVolume) ''
        $f = Get-CabFactsFromBytes -Head (New-CabBytes -Flags 0)
        T 'a single CAB is neither split nor password-protected' (-not $f.MultiVolume -and $f.Encrypted -eq $false) ''

        # ---- names.
        $k = Get-VolumeSetKey -Name 'Backup.part03.rar'
        T 'name.partN.rar is a volume of a set by name alone' ($k.Alone -and $k.Set -eq 'backup.rar' -and $k.Index -eq 3) "$($k.Set)/$($k.Index)"
        $k = Get-VolumeSetKey -Name 'data.r00'
        T 'old-style name.rNN belongs to the same set as name.rar' ($k.Alone -and $k.Set -eq 'data.rar') "$($k.Set)"
        $k = Get-VolumeSetKey -Name 'x.z01'
        T 'name.z01 is a split ZIP segment' ($k.Alone -and $k.Set -eq 'x.zip') "$($k.Set)"
        $k = Get-VolumeSetKey -Name 'dump.7z.002'
        T 'name.7z.NNN is a 7-Zip volume' ($k.Alone -and $k.Set -eq 'dump.7z' -and $k.Index -eq 2) "$($k.Set)"
        $k = Get-VolumeSetKey -Name 'readme.zip'
        T 'a plain name.zip is a set member only when a sibling says so' ($null -ne $k -and -not $k.Alone) ''
        $k = Get-VolumeSetKey -Name 'report.docx'
        T 'a document name is no volume shape' ($null -eq $k) ''
        $k = Get-VolumeSetKey -Name 'frame.001'
        T 'a bare .001 is a set member only when its signature says it is an archive' ($null -ne $k -and -not $k.Alone) ''

        # ---- entry names: the credential class.
        T 'a mail store inside the archive is the credential class' ((Get-ArchiveEntryReason -Name 'Users/k/Documents/Outlook Files/Outlook.pst').Count -eq 1) ''
        T 'a password database and a private key are the credential class' (((Get-ArchiveEntryReason -Name 'vault.kdbx').Count -eq 1) -and ((Get-ArchiveEntryReason -Name '.ssh/id_ed25519').Count -eq 1)) ''
        T 'a Bitcoin wallet.dat and a .key inside a keys folder are the credential class' (((Get-ArchiveEntryReason -Name 'Bitcoin/wallet.dat').Count -eq 1) -and ((Get-ArchiveEntryReason -Name 'etc/ssl/private/server.key').Count -eq 1)) ''
        T 'a Keynote presentation (talk.key) and a project''s nginx/server.key are NOT the credential class' (((Get-ArchiveEntryReason -Name 'WWDC/talk.key').Count -eq 0) -and ((Get-ArchiveEntryReason -Name 'mysite/nginx/server.key').Count -eq 0)) ''
        T 'a registry-hive copy and ntds.dit are the credential class' (((Get-ArchiveEntryReason -Name 'hives\SAM').Count -eq 1) -and ((Get-ArchiveEntryReason -Name 'ntds.dit').Count -eq 1)) ''
        T "a browser's Login Data store is the credential class" ((Get-ArchiveEntryReason -Name 'Chrome/Default/Login Data').Count -eq 1) ''
        T 'a document, a photo and a system.json are NOT the credential class' (((Get-ArchiveEntryReason -Name 'report.docx').Count -eq 0) -and ((Get-ArchiveEntryReason -Name 'IMG_0001.jpg').Count -eq 0) -and ((Get-ArchiveEntryReason -Name 'config/system.json').Count -eq 0)) ''
        T 'a file merely named like a hive with an extension (SYSTEM.txt) is not a hive copy' ((Get-ArchiveEntryReason -Name 'SYSTEM.txt').Count -eq 0) ''

        # ---- the verdict table.
        $v = Get-ArchiveVerdict -Zone 3 -Encrypted $false -MultiVolume $true -EntryReasons @() -Role 'public'
        T 'a DOWNLOADED archive is context whatever it holds -- it came in, it was not packed here' ($v.Sev -eq 'OK' -and $v.Class -eq 'downloaded') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone 3 -Encrypted $true -MultiVolume $true -EntryReasons @() -Role 'downloads'
        T 'a downloaded archive of the strongest shape in Downloads is named context, not a row' ($v.Sev -eq 'OK' -and $v.Class -eq 'marked-strong') "$($v.Sev)/$($v.Class)"
        $v = Get-ArchiveVerdict -Zone 3 -Encrypted $true -MultiVolume $true -EntryReasons @() -Role 'public'
        T 'a FORGED mark does not clear the strongest shape where no browser saves (Public): WARNING' ($v.Sev -eq 'WARNING' -and $v.Class -eq 'marked-misplaced' -and $v.Clause -match 'no browser saves a download') "$($v.Sev)/$($v.Class)"
        $v = Get-ArchiveVerdict -Zone 1 -Encrypted $false -MultiVolume $false -EntryReasons @() -Role 'downloads'
        T 'an intranet-zone mark (ZoneId=1) is a download too' ($v.Sev -eq 'OK' -and $v.Class -eq 'downloaded') "$($v.Class)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $false -MultiVolume $false -EntryReasons @()
        T 'a plain single-volume local archive is context, never a row' ($v.Sev -eq 'OK' -and $v.Class -eq 'plain') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $true -MultiVolume $false -EntryReasons @()
        T 'a password-protected local archive is WARNING' ($v.Sev -eq 'WARNING' -and $v.Clause -eq 'is password-protected') "$($v.Sev)/$($v.Clause)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $false -MultiVolume $true -EntryReasons @() -Role 'public'
        T 'a local archive split into volumes outside Downloads is WARNING' ($v.Sev -eq 'WARNING' -and $v.Clause -eq 'is split into volumes') "$($v.Sev)/$($v.Clause)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $false -MultiVolume $true -EntryReasons @() -Role 'downloads'
        T 'a split set with no password in Downloads is named context (torrent and file-sharing clients write no mark)' ($v.Sev -eq 'OK' -and $v.Class -eq 'volumeset-download') "$($v.Sev)/$($v.Class)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $false -MultiVolume $true -EntryReasons @() -Role 'systemp' -Kind 'cab'
        T 'a spanned CAB set is context: a cabinet cannot carry a password' ($v.Sev -eq 'OK' -and $v.Class -eq 'cabset') "$($v.Sev)/$($v.Class)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $true -MultiVolume $true -EntryReasons @() -Role 'downloads'
        T 'password-protected AND split, made here, is CRITICAL -- the shape every cited intrusion used' ($v.Sev -eq 'CRITICAL') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $true -MultiVolume $false -EntryReasons @('a mail store')
        T 'a password-protected local archive that packs credential files is CRITICAL' ($v.Sev -eq 'CRITICAL' -and $v.Clause -match 'credential') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $false -MultiVolume $false -EntryReasons @('a mail store')
        T 'a PLAIN local archive that packs credential files is WARNING, not CRITICAL -- a person''s own backup is the twin' ($v.Sev -eq 'WARNING' -and $v.Clause -eq 'packs credential files') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $null -MultiVolume $false -EntryReasons @() -Role 'temp'
        T 'a 7z whose password is not determinable is context, not clean and not a finding' ($v.Sev -eq 'OK' -and $v.Class -eq 'undetermined') "$($v.Sev)/$($v.Class)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $null -MultiVolume $false -EntryReasons @() -Role 'public'
        T 'an archive whose password is not determinable, in the Public folder where nothing unpacks, is WARNING' ($v.Sev -eq 'WARNING' -and $v.Clause -match 'Public folder') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -1 -Encrypted $null -MultiVolume $true -EntryReasons @() -Role 'temp'
        T 'a split archive whose password is not determinable is WARNING, and says what it could not tell' ($v.Sev -eq 'WARNING' -and $v.Clause -match 'not determinable') "$($v.Sev)/$($v.Clause)"
        $v = Get-ArchiveVerdict -Zone 0 -Encrypted $true -MultiVolume $false -EntryReasons @()
        T 'a local-machine mark (ZoneId=0) is not a download: graded as made here' ($v.Sev -eq 'WARNING') "$($v.Sev)"
        $v = Get-ArchiveVerdict -Zone -2 -Encrypted $true -MultiVolume $false -EntryReasons @()
        T 'a mark that exists but cannot be read does not clear the archive' ($v.Sev -eq 'WARNING') "$($v.Sev)"

        # ---- the report.
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\Public\1.rar' -Kind 'rar5' -Encrypted $true -HeadersEncrypted $true -Multi $true -MultiWhy '3 parts present')) -Folders $fo -Probes @{}
        T 'the CRITICAL line names the archive, its folder and the technique, and the format line says what was read' `
          ($r.Sev -eq 'CRITICAL' -and $r.Hits -eq 1 -and (& $j $r) -match '\[CRITICAL\] An archive made on this machine is password-protected AND split into volumes, in a staging folder: C:\\Users\\Public\\1\.rar \(0 MB, written 2026-10-15 12:00:00Z\) \(T1560\)' -and (& $j $r) -match 'format: RAR 5\.0; password-protected with its file names hidden; volume of a set \(3 parts present\)') (& $j $r)
        T 'and no all-clear is printed beside a finding' ((& $j $r) -notmatch '\[OK\]') (& $j $r)
        T 'and the verify line is a pasteable command' ((& $j $r) -match "verify: Get-Content -LiteralPath 'C:\\Users\\Public\\1\.rar' -Stream Zone\.Identifier") (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc "C:\Users\k\Downloads\o'brien.zip" -Kind 'zip' -Encrypted $true -Role 'downloads')) -Folders $fo -Probes @{}
        T 'an apostrophe in the path is doubled in the verify line' ((& $j $r) -match "-LiteralPath 'C:\\Users\\k\\Downloads\\o''brien\.zip'") (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\k\Downloads\sample.zip' -Kind 'zip' -Zone 3 -Encrypted $false -Multi $false -Role 'downloads')) -Folders $fo -Probes @{}
        T 'a downloaded archive is INFO context and the all-clear still prints' `
          ($r.Sev -eq 'OK' -and (& $j $r) -match '\[INFO\] 1 archive\(s\) carry the Mark of the Web -- downloaded by a browser, not packed here' -and (& $j $r) -match '\[OK\] 1 archive\(s\) examined across 2 staging folder\(s\)') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\k\Downloads\tool.7z.001' -Kind '7z' -Zone 3 -Encrypted $true -Multi $true -Role 'downloads' -HostUrl 'https://example.test/tool.7z.001')) -Folders $fo -Probes @{}
        T 'a downloaded archive of the strongest shape is NAMED with the origin its mark records' ($r.Sev -eq 'OK' -and (& $j $r) -match '\[INFO\] A downloaded archive of the packed-to-leave shape [^|]*tool\.7z\.001 -- downloaded from https://example\.test/tool\.7z\.001') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\Public\x.part1.rar' -Kind 'rar5' -Zone 3 -Encrypted $true -Multi $true -Role 'public')) -Folders $fo -Probes @{}
        T 'and the same shape marked but in Public is a WARNING whose mark line says it does not clear it' ($r.Sev -eq 'WARNING' -and (& $j $r) -match '\[WARNING\] An archive carries a download mark but sits in the shared Public folder' -and (& $j $r) -match 'download mark: ZoneId=3, no origin recorded in the mark -- anyone can write this stream') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\k\AppData\Local\Temp\pip-unpack-1\x.zip' -Kind 'zip' -Encrypted $false -Role 'temp')) -Folders $fo -Probes @{}
        T 'a plain local archive is counted as context, named, and the all-clear names its coverage, depth and the newest archive' `
          ($r.Sev -eq 'OK' -and (& $j $r) -match '\[INFO\] 1 plain archive\(s\) made or copied here' -and (& $j $r) -match '\[OK\] 1 archive\(s\) examined across 2 staging folder\(s\) to a depth of 2 \(C:\\Users\\k\\Downloads; C:\\Users\\Public\): none password-protected or split into volumes was made on this machine, and none packs a credential file\.' -and (& $j $r) -match '\[INFO\] The newest archive examined is C:\\Users\\k\\AppData\\Local\\Temp\\pip-unpack-1\\x\.zip \(ZIP, written') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @() -Folders $fo -Probes @{}
        T 'no archives at all is an all-clear that names the folders it read' ((& $j $r) -match '\[OK\] No archives in the 2 staging folder\(s\) examined to a depth of 2 \(C:\\Users\\k\\Downloads; C:\\Users\\Public\)\.') (& $j $r)
        T 'and it says what is not examined by design' ((& $j $r) -match '\[INFO\] Not examined by design: archives inside other archives, a self-extracting program whose archive starts more than 64 KiB past its code') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\k\Downloads\backup.zip' -Kind 'zip' -Encrypted $false -Entries @('Outlook Files/archive.pst', 'notes.txt') -Role 'downloads')) -Folders $fo -Probes @{}
        T 'a plain local archive packing a mail store is WARNING and names the entry' `
          ($r.Sev -eq 'WARNING' -and (& $j $r) -match '\[WARNING\] An archive made on this machine packs credential files, in a staging folder' -and (& $j $r) -match 'packs: a mail store, a password database, a wallet or a private key \| +Outlook Files/archive\.pst') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\k\AppData\Local\Temp\x.7z' -Kind '7z' -Encrypted $null -Role 'temp')) -Folders $fo -Probes @{}
        T 'an archive whose password is not determinable is NAMED in context, and the all-clear is still printed beside it' `
          ($r.Sev -eq 'OK' -and (& $j $r) -match '\[INFO\] 1 archive\(s\) whose password could not be determined [^|]*: C:\\Users\\k\\AppData\\Local\\Temp\\x\.7z' -and (& $j $r) -match '\[OK\] 1 archive\(s\) examined') (& $j $r)
        $gapF = @(@{ Path = 'C:\Users\k\Downloads'; Role = 'downloads'; State = 'searched'; Files = 1; Skipped = 0 }, @{ Path = 'C:\Windows\Temp'; Role = 'systemp'; State = 'unlistable'; Error = 'Access to the path is denied' })
        $r = Get-ArchiveStagingReport -Archives @() -Folders $gapF -Probes @{} -IsElevated $true
        T 'a folder an administrator cannot list is a raised gap, and the all-clear is withheld' `
          ($r.GapSev -eq 'WARNING' -and $r.Sev -eq 'OK' -and (& $j $r) -match '\[WARNING\] Staging folder C:\\Windows\\Temp could not be listed by an administrator -- archives there were NOT checked' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)
        T 'and what WAS read is still stated, scoped, so a partial run never goes quiet' ((& $j $r) -match '\[INFO\] No archives in the 1 staging folder\(s\) examined to a depth of 2 \(C:\\Users\\k\\Downloads\) -- for the folders this run could read; the folders declared above are NOT covered\.') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @() -Folders $gapF -Probes @{} -IsElevated $false
        T 'the same folder on a standard-user token is a counted DEFERRAL, never a row, and no all-clear' `
          ($r.GapSev -eq 'OK' -and $r.Deferred -eq 1 -and (& $j $r) -match '\[DEFERRED - ADMIN REQUIRED\] Staging folder C:\\Windows\\Temp is not readable from a standard-user token' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -match '\[INFO\] No archives in the 1 staging folder\(s\) examined') (& $j $r)
        $defF = @(@{ Path = 'C:\Users\k\Downloads'; Role = 'downloads'; State = 'searched'; Files = 1; Skipped = 0 }, @{ Path = "other users' profiles and recycle bins"; State = 'deferred' })
        $r = Get-ArchiveStagingReport -Archives @() -Folders $defF -Probes @{} -IsElevated $false
        T 'folders the token never tried are declared deferred with a count' ($r.Deferred -eq 1 -and (& $j $r) -match "\[DEFERRED - ADMIN REQUIRED\] other users' profiles and recycle bins -- archives there were NOT checked") (& $j $r)
        $denF = @(@{ Path = 'C:\Users\Public'; Role = 'public'; State = 'searched'; Files = 4; Skipped = 0; Denied = 1; Locked = 0 })
        $r = Get-ArchiveStagingReport -Archives @() -Folders $denF -Probes @{} -IsElevated $true
        T 'a FILE an administrator could not read is a raised gap, not a silent drop' ($r.GapSev -eq 'WARNING' -and (& $j $r) -match '\[WARNING\] 1 file\(s\) in staging folder C:\\Users\\Public could not be read by an administrator -- they were NOT checked' -and (& $j $r) -notmatch '\[OK\]') (& $j $r)
        $budF = @(@{ Path = 'C:\Users\k\Downloads'; Role = 'downloads'; State = 'searched'; Files = 1; Skipped = 0 }, @{ Path = 'C:\$Recycle.Bin'; Role = 'recycle'; State = 'budget' })
        $r = Get-ArchiveStagingReport -Archives @() -Folders $budF -Probes @{} -IsElevated $true
        T 'a folder the time budget never reached is declared as that -- not as a permissions failure, no gap row -- and there is no all-clear' `
          ($r.GapSev -eq 'OK' -and $r.Deferred -eq 0 -and (& $j $r) -match 'The time budget ran out before every staging folder and file was examined: C:\\\$Recycle\.Bin NOT reached' -and (& $j $r) -notmatch 'could not be listed' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -match '\[INFO\] No archives in the 1 staging folder\(s\) examined[^|]*before the time budget stopped it') (& $j $r)
        $capF = @(@{ Path = 'C:\Users\k\AppData\Local\Temp'; Role = 'temp'; State = 'searched'; Files = 20000; Skipped = 0; Capped = $true })
        $r = Get-ArchiveStagingReport -Archives @() -Folders $capF -Probes @{} -IsElevated $true
        T 'a capped folder says it is NOT fully covered, and the coverage line is scoped, never an all-clear' ((& $j $r) -match 'holds more than 20000 files; only the first 20000 were examined -- it is NOT fully covered' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -match 'before a folder too large to examine in full stopped it') (& $j $r)
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\Public\a.rar' -Kind 'rar5' -Encrypted $true), (NewArc 'C:\Windows\Temp\b.rar' -Kind 'rar5' -Encrypted $true -Role 'systemp')) -Folders $gapF -Probes @{} -IsElevated $true
        T 'a gap beside findings: both the finding rows and the gap are raised, nothing is dropped' ($r.Sev -eq 'WARNING' -and $r.GapSev -eq 'WARNING' -and $r.Hits -eq 2) "$($r.Sev)/$($r.GapSev)/$($r.Hits)"
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\Public\a.zip' -Kind 'zip' -Encrypted $false)) -Folders $fo -Probes @{ Files = 30000; Probed = 5000; ProbeCap = $true; Packages = 4; NotArchive = 2; Cloud = 3 }
        T 'caps and exclusions are printed as context, and the coverage line is then scoped, never an all-clear' `
          ((& $j $r) -match '\[INFO\] Only 5000 file\(s\) without an archive extension had their signature read \(cap\)' -and (& $j $r) -match '4 package\(s\) that are ZIP by signature' -and (& $j $r) -match '2 file\(s\) named like an archive are not one by signature' -and (& $j $r) -match '3 cloud-only placeholder\(s\) were not opened' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -match '\[INFO\] 1 archive\(s\) examined across 2 staging folder\(s\)[^|]*before the signature-probe cap stopped it') (& $j $r)
        $many = @(); for ($i = 1; $i -le 13; $i++) { $many += (NewArc ('C:\Users\Public\v' + $i + '.rar') -Kind 'rar5' -Encrypted $true) }
        $r = Get-ArchiveStagingReport -Archives $many -Folders $fo -Probes @{}
        $phys = @($r.Lines | Where-Object { $_ -match '^\[WARNING\] An archive made on this machine' }).Count
        T 'findings are capped at 10 lines with the rest counted' ($phys -eq 10 -and $r.Hits -eq 13 -and (& $j $r) -match '\.\.\.and 3 more archive\(s\) graded the same way') "$phys/$($r.Hits)"
        $r = Get-ArchiveStagingReport -Archives @((NewArc "C:\Users\Public\evil`r`n[OK] forged line.rar" -Kind 'rar5' -Encrypted $true -Entries @("x`r`n[CRITICAL] forged.pst"))) -Folders $fo -Probes @{}
        $okPhys = @($r.Lines | Where-Object { $_ -match '^\[OK\]' }).Count
        $critPhys = @($r.Lines | Where-Object { $_ -match '^\[CRITICAL\]' }).Count
        T 'a crafted file or entry name cannot forge a line of its own' ($okPhys -eq 0 -and $critPhys -eq 1 -and $r.Sev -eq 'CRITICAL' -and (& $j $r) -match 'evil\?\?\[OK\] forged line\.rar') "ok=$okPhys crit=$critPhys"
        $a1 = NewArc 'C:\Users\Public\b.rar' -Kind 'rar5' -Encrypted $true
        $a2 = NewArc 'C:\Users\Public\a.rar' -Kind 'rar5' -Encrypted $true -Multi $true
        $r1 = Get-ArchiveStagingReport -Archives @($a1, $a2) -Folders $fo -Probes @{}
        $r2 = Get-ArchiveStagingReport -Archives @($a2, $a1) -Folders $fo -Probes @{}
        T 'the same archives in a different order produce the same report, CRITICAL first' (((& $j $r1) -eq (& $j $r2)) -and ($r1.Lines[0] -match '^\[CRITICAL\]')) ''
        $r = Get-ArchiveStagingReport -Archives @((NewArc 'C:\Users\Public\x.rar' -Kind 'rar5' -Encrypted $true -ParseError 'header sizes garbage')) -Folders $fo -Probes @{}
        T 'an archive the parser could not finish is still graded by what it read' ($r.Sev -eq 'WARNING') (& $j $r)
        $parts = @(); for ($i = 1; $i -le 4; $i++) { $parts += (NewArc ('C:\Users\Public\b.part' + $i + '.rar') -Kind 'rar5' -Encrypted $true -HeadersEncrypted $true -Multi $true -MultiWhy '4 parts of the set are here' -SetKey 'c:\users\public|b.rar' -SetIndex $i -SetMembers 4) }
        $r = Get-ArchiveStagingReport -Archives $parts -Folders $fo -Probes @{}
        $physC = @($r.Lines | Where-Object { $_ -match '^\[CRITICAL\]' }).Count
        T 'the volumes of one set are ONE finding, the first part speaking for the rest' ($physC -eq 1 -and $r.Hits -eq 1 -and (& $j $r) -match 'b\.part1\.rar \(\+3 more part\(s\) of this set\)') "lines=$physC hits=$($r.Hits)"
        $two = @((NewArc 'C:\Users\Public\c.part1.rar' -Kind 'rar5' -Encrypted $true -Multi $true -SetKey 'c:\users\public|c.rar' -SetIndex 1), (NewArc 'C:\Users\Public\d.part1.rar' -Kind 'rar5' -Encrypted $true -Multi $true -SetKey 'c:\users\public|d.rar' -SetIndex 1))
        $r = Get-ArchiveStagingReport -Archives $two -Folders $fo -Probes @{}
        T 'two different sets stay two findings' ($r.Hits -eq 2) "hits=$($r.Hits)"

        # ---- THE LIVE CLASSIFIER, end to end over files written here.
        $d = NewDir 'oldrar'
        $null = Put 'movie.rar' (New-Rar4Bytes -MainFlags 0x0101 -Files @(@{ Name = 'a.mkv'; Flags = 0x8000; Data = 'a' })) $d
        $null = Put 'movie.r00' (New-Rar4Bytes -MainFlags 0x0001 -Files @(@{ Name = 'a.mkv'; Flags = 0x8000; Data = 'a' })) $d
        $c = Classify -Dir $d -Role 'public'
        T 'live: an old-style set (name.rar + name.r00) is one set, led by name.rar, WARNING outside Downloads' ($c.Rep.Sev -eq 'WARNING' -and $c.Rep.Hits -eq 1 -and $c.Text -match 'movie\.rar \(\+1 more part\(s\) of this set\)') $c.Text
        $c = Classify -Dir $d -Role 'downloads'
        T 'live: the same set in Downloads is named context, not a row' ($c.Rep.Sev -eq 'OK' -and $c.Text -match '\[INFO\] 2 volume\(s\) of split archive sets with no password and no download mark sit in Downloads') $c.Text
        $d = NewDir 'zipsplit'
        $null = Put 'x.z01' (Join-Bytes @((B @(0x50, 0x4B, 0x07, 0x08)), (New-ZipBytes -Entries @(@{ Name = 'Outlook.pst'; Flags = 1; Method = 8; Data = 'x' })))) $d
        $null = Put 'x.zip' (New-ZipBytes -Entries @(@{ Name = 'Outlook.pst'; Flags = 1; Method = 8; Data = 'x' }) -DiskNo 1) $d
        $c = Classify -Dir $d -Role 'temp'
        T 'live: a split ZIP (x.z01 + x.zip) holding a mail store under a password is CRITICAL as one set' ($c.Rep.Sev -eq 'CRITICAL' -and $c.Rep.Hits -eq 1 -and $c.Text -match '\(\+1 more part\(s\) of this set\)') $c.Text
        $d = NewDir 'sevenset'
        $whole = New-SevenZipBytes -HeaderKind 'encoded-aes'
        $null = Put 'loot.7z.001' ([byte[]]$whole[0..19]) $d
        $null = Put 'loot.7z.002' ([byte[]]$whole[20..39]) $d
        $null = Put 'loot.7z.003' ([byte[]]$whole[40..($whole.Count - 1)]) $d
        $c = Classify -Dir $d -Role 'temp'
        T 'live: a real-shaped 7-Zip set (.001 signed, .002/.003 raw) is read across its volumes: CRITICAL, +2 more, and the raw parts are not "not an archive"' ($c.Rep.Sev -eq 'CRITICAL' -and $c.Rep.Hits -eq 1 -and $c.Text -match 'loot\.7z\.001 \(\+2 more part\(s\) of this set\)' -and $c.Text -match 'format: 7z; password-protected with its file names hidden; volume of a set \(3 volumes read as one stream\)' -and $c.Text -notmatch 'named like an archive are not one') $c.Text
        $d = NewDir 'bare001'
        $null = Put 'photos.001' (New-ZipBytes -Entries @(@{ Name = 'a.jpg'; Flags = 0; Method = 0; Data = 'a' })) $d
        $c = Classify -Dir $d -Role 'public'
        T 'live: a lone .001 that is a plain ZIP is a plain archive, not a volume set' ($c.Rep.Sev -eq 'OK' -and $c.Text -match '1 plain archive\(s\)') $c.Text
        $null = Put 'photos.002' (B @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33)) $d
        $c = Classify -Dir $d -Role 'public'
        T 'live: with a .002 beside it, the .001 is a volume of a set (WARNING outside Downloads)' ($c.Rep.Sev -eq 'WARNING' -and $c.Text -match 'photos\.001 \(\+1 more part\(s\) of this set\)') $c.Text
        $d = NewDir 'renamed'
        $null = Put 'loot.tmp' (New-Rar5Bytes -Crypt $true) $d
        $null = Put 'backup.partial' (New-Rar5Bytes -Crypt $true) $d
        $null = Put 'x.crdownload' (New-Rar5Bytes -Crypt $true) $d
        $c = Classify -Dir $d -Role 'temp'
        T 'live: an archive renamed .tmp, .partial or .crdownload is found by its signature, not waved through as a download in progress' ($c.Rep.Sev -eq 'WARNING' -and $c.Rep.Hits -eq 3 -and $c.Text -match 'loot\.tmp') $c.Text
        $d = NewDir 'pkg'
        $null = Put 'report.docx' (New-ZipBytes -Entries @(@{ Name = '[Content_Types].xml'; Flags = 1; Method = 8; Data = 'x' })) $d
        $null = Put 'renamed.zip' (New-ZipBytes -Entries @(@{ Name = 'AppxManifest.xml'; Flags = 0; Method = 0; Data = 'x' })) $d
        $c = Classify -Dir $d -Role 'public'
        T 'live: an Office document and a renamed MSIX package are left out and counted' ($c.Rep.Sev -eq 'OK' -and $c.Text -match '2 package\(s\) that are ZIP by signature') $c.Text
        $d = NewDir 'zones'
        $null = Put 'dl.zip' (New-ZipBytes -Entries @(@{ Name = 'a.txt'; Flags = 1; Method = 8; Data = 'x' })) $d
        $null = Put 'forged.part1.rar' (New-Rar5Bytes -Crypt $true) $d
        $null = Put 'forged.part2.rar' (New-Rar5Bytes -Crypt $true) $d
        $c = Classify -Dir $d -Role 'public' -Zones @{ 'dl.zip' = @{ Zone = 3; HostUrl = 'https://example.test/dl.zip' }; 'forged.part1.rar' = @{ Zone = 3; HostUrl = '' }; 'forged.part2.rar' = @{ Zone = 3; HostUrl = '' } }
        T 'live: the mark is read per file -- a marked password zip is context, a marked -hp -v set in Public is still a WARNING' ($c.Rep.Sev -eq 'WARNING' -and $c.Rep.Hits -eq 1 -and $c.Text -match 'carry the Mark of the Web' -and $c.Text -match 'forged\.part1\.rar \(\+1 more part\(s\) of this set\)') $c.Text
        $d = NewDir 'cloud'
        $null = Put 'online.zip' (New-ZipBytes -Entries @(@{ Name = 'a.txt'; Flags = 1; Method = 8; Data = 'x' })) $d
        $c = Classify -Dir $d -Role 'downloads' -Attr @{ 'online.zip' = [int64]0x400000 }
        T 'live: a cloud-only placeholder is not opened (it would download), and that is counted' ($c.Rep.Sev -eq 'OK' -and $c.Text -match '1 cloud-only placeholder\(s\) were not opened') $c.Text
        $d = NewDir 'denied'
        $null = Put 'locked.rar' (New-Rar5Bytes -Crypt $true) $d
        $c = Classify -Dir $d -Role 'public' -HeadReader { param($p) throw (New-Object System.UnauthorizedAccessException 'Access to the path is denied.') }
        T 'live: a file an administrator cannot open is counted into the gap, not silently dropped' ($c.Rep.GapSev -eq 'WARNING' -and $c.Text -match '1 file\(s\) in staging folder [^|]* could not be read by an administrator') $c.Text
        $c = Classify -Dir $d -Role 'public' -HeadReader { param($p) throw (New-Object System.IO.IOException 'The process cannot access the file because it is being used by another process.') }
        T 'live: a file held open by another program is named, not graded, and not a gap' ($c.Rep.GapSev -eq 'OK' -and $c.Text -match '1 file\(s\) were held open by another program and could not be read, so they were not graded: [^|]*locked\.rar') $c.Text
        $d = NewDir 'unparsed'
        $null = Put 'loot.zip' (Join-Bytes @((New-ZipBytes -Entries @(@{ Name = 'a.bin'; Flags = 0; Method = 8; Data = 'x' })), (New-Object byte[] 70000))) $d
        $c = Classify -Dir $d -Role 'temp'
        T 'live: a ZIP whose end record cannot be found is NOT graded "no password" -- it is named as not determinable' ($c.Text -match 'whose password could not be determined[^|]*loot\.zip' -and $c.Text -notmatch 'plain archive') $c.Text

        # ---- enumeration: per-folder cap, budget, absent.
        $e1 = NewDir 'enumA'; $e2 = NewDir 'enumB'
        for ($i = 1; $i -le 5; $i++) { Set-Content -LiteralPath (Join-Path $e1 ('junk' + $i + '.txt')) -Value 'x' }
        $null = Put 'loot.rar' (New-Rar5Bytes -Crypt $true) $e2
        $en = Get-StagingCandidates -Specs @(@{ Path = $e1; Role = 'temp'; State = 'try' }, @{ Path = $e2; Role = 'public'; State = 'try' }, @{ Path = (Join-Path $tdir 'nope'); Role = 'temp'; State = 'try' }) -MaxFilesPerFolder 3
        $fa = @($en.Folders | Where-Object { $_.Path -eq $e1 })[0]; $fb = @($en.Folders | Where-Object { $_.Path -eq $e2 })[0]; $fn = @($en.Folders | Where-Object { $_.Path -like '*nope' })[0]
        T 'enumeration: the file cap is PER FOLDER, so a full folder cannot starve the next one' ($fa.Capped -and $fa.Files -eq 3 -and -not $fb.Capped -and @($en.Candidates | Where-Object { $_.Item.Name -eq 'loot.rar' }).Count -eq 1) "A capped=$($fa.Capped) files=$($fa.Files); B files=$($fb.Files)"
        T 'enumeration: a folder that does not exist is absent, not a gap' ($fn.State -eq 'absent') "$($fn.State)"
        $sw0 = [System.Diagnostics.Stopwatch]::StartNew()
        $en = Get-StagingCandidates -Specs @(@{ Path = $e1; Role = 'temp'; State = 'try' }) -BudgetSeconds -1 -Stopwatch $sw0
        T 'enumeration: a folder the budget never reached has the state "budget", not "unlistable"' ($en.Folders[0].State -eq 'budget') "$($en.Folders[0].State)"
        $lister = { param($parent, $seg) if ($seg -eq 'RUNNER~1') { @('C:\Users\runneradmin') } elseif ($seg -eq 'AMBIG~1') { @('C:\x\a', 'C:\x\b') } else { @() } }
        T 'a short 8.3 path resolves to its long name, segment by segment' ((Resolve-LongPath -Path 'C:\Users\RUNNER~1\AppData\Local\Temp' -Lister $lister) -eq 'C:\Users\runneradmin\AppData\Local\Temp') (Resolve-LongPath -Path 'C:\Users\RUNNER~1\AppData\Local\Temp' -Lister $lister)
        T 'a path without a short segment is returned unchanged, and an ambiguous one is left as given' (((Resolve-LongPath -Path 'C:\Users\k\Downloads' -Lister $lister) -eq 'C:\Users\k\Downloads') -and ((Resolve-LongPath -Path 'C:\x\AMBIG~1' -Lister $lister) -eq 'C:\x\AMBIG~1')) ''
        $l8 = New-Object System.Collections.ArrayList; $s8 = @{}
        Add-StagingFolder $l8 $s8 'C:\Users\runneradmin\AppData\Local\Temp' 'temp' -Lister $lister
        Add-StagingFolder $l8 $s8 'C:\Users\RUNNER~1\AppData\Local\Temp\' 'temp' -Lister $lister
        Add-StagingFolder $l8 $s8 'C:\Users\Public' 'public' -Lister $lister
        T 'one folder is one folder: %TEMP% in 8.3 form beside the profile''s own Temp is listed ONCE, under its long name' ($l8.Count -eq 2 -and $l8[0].Path -eq 'C:\Users\runneradmin\AppData\Local\Temp') ("{0}: {1}" -f $l8.Count, (($l8 | ForEach-Object { $_.Path }) -join '; '))
        T 'roles: Public, Downloads, a system temp folder and the recycle bin are told apart by path' (((Get-RoleOfPath 'C:\Users\Public\x') -eq 'public') -and ((Get-RoleOfPath 'C:\Users\k\Downloads') -eq 'downloads') -and ((Get-RoleOfPath 'C:\Windows\Temp') -eq 'systemp') -and ((Get-RoleOfPath 'D:\$Recycle.Bin') -eq 'recycle') -and ((Get-RoleOfPath 'C:\Users\k\AppData\Local\Temp') -eq 'temp')) ''

        # ---- a real archive from the engine's own Compress-Archive, the plain
        # shape Explorer makes, through the live classifier end to end.
        $src = Join-Path $tdir 'src.txt'; Set-Content -LiteralPath $src -Value 'hello' -Encoding ASCII
        $real = Join-Path $tdir 'real.zip'
        $cz = $null
        try { Compress-Archive -LiteralPath $src -DestinationPath $real -Force -EA Stop } catch { $cz = $_.Exception.Message }
        if ($cz) { Write-Output ('[SKIP] Compress-Archive not usable here (' + $cz + '); the real-ZIP case is covered by CI on Windows') }
        else {
            $f = Facts $real
            T 'a ZIP written by Compress-Archive parses as plain, single volume, with its entry named' ($f.Parsed -and $f.Encrypted -eq $false -and -not $f.MultiVolume -and $f.Entries[0] -eq 'src.txt') "$($f.Parsed)/$($f.Encrypted)/$($f.Entries -join ',')/$($f.Why)"
        }
        # ---- a renamed archive through the live classifier: the NICKEL shape.
        $p = Put 'invoice.dat' (New-Rar5Bytes -Crypt $true)
        $f = Facts $p
        T 'a RAR renamed .dat is still a RAR by signature, headers encrypted' ($f.Kind -eq 'rar5' -and $f.Encrypted -eq $true) "$($f.Kind)/$($f.Encrypted)"
    } finally {
        Remove-Item -LiteralPath $tdir -Recurse -Force -EA SilentlyContinue
    }

    if ($script:fails) {
        Write-Output "[FAIL] $($script:fails) archive_staging self-test expectation(s) unmet"
        exit 1
    }
    Write-Output '[OK] archive_staging self-test: ZIP, RAR 4.x/5.0, 7z and CAB headers parse from the published layouts with every loop bound by the buffer, a downloaded archive is context unless a forged-looking mark sits where no browser saves, a plain local one is context, a password or a volume set made here raises, both together is CRITICAL, credential-class entries escalate, a password that cannot be determined is said and named, and every gap, cap and budget is declared.'
    exit 0
}

# ===========================================================================
# LIVE PATH
# ===========================================================================

if (-not $MarkerDir) { $MarkerDir = $env:TEMP }
'--- [T1560] Archives made on this machine, in its staging folders ---'

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

function Get-DownloadsFolder {
    # The current user's Downloads may be redirected (OneDrive's "Known Folder
    # Move" does this): read the shell folder value and expand it; fall back
    # to the profile's Downloads.
    param([string]$ProfileDir)
    $d = ''
    try {
        $v = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -EA Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($v) { $d = [Environment]::ExpandEnvironmentVariables([string]$v) }
    } catch { }
    if (-not $d) { $d = Join-Path $ProfileDir 'Downloads' }
    return $d
}

function Get-StagingFolders {
    # The folders this token should look at. Elevated: every profile's
    # Downloads and temp folder, the Public folder, the system temp folders
    # (Windows\Temp, SYSTEM's, the network and local service profiles'),
    # ProgramData (one level: HAFNIUM staged there), PerfLogs, and the
    # recycle bin of every fixed drive. Standard user: its own Downloads and
    # temp folders, Public, ProgramData and its own recycle bins; the rest is
    # declared deferred, never silently skipped.
    param([bool]$IsElevated)
    $list = New-Object System.Collections.ArrayList
    $seen = @{}
    $sysDrive = $env:SystemDrive; if (-not $sysDrive) { $sysDrive = 'C:' }
    $me = $env:USERPROFILE
    if ($me) {
        Add-StagingFolder $list $seen (Get-DownloadsFolder -ProfileDir $me) 'downloads'
        # The profile's own Temp first: with the dedupe below, the long
        # spelling is the one the report names.
        Add-StagingFolder $list $seen (Join-Path $me 'AppData\Local\Temp') 'temp'
        Add-StagingFolder $list $seen $env:TEMP 'temp'
    }
    $pub = $env:PUBLIC; if (-not $pub) { $pub = Join-Path $sysDrive 'Users\Public' }
    Add-StagingFolder $list $seen $pub 'public'
    $pd = $env:ProgramData; if (-not $pd) { $pd = Join-Path $sysDrive 'ProgramData' }
    Add-StagingFolder $list $seen $pd 'programdata' 'try' 1
    $sid = ''
    try { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }
    $bins = @()
    try { foreach ($dv in [System.IO.DriveInfo]::GetDrives()) { if ($dv.DriveType -eq 'Fixed' -and $dv.IsReady) { $bins += (Join-Path $dv.RootDirectory.FullName '$Recycle.Bin') } } } catch { }
    if ($bins.Count -eq 0) { $bins = @(Join-Path ($sysDrive + '\') '$Recycle.Bin') }
    if ($IsElevated) {
        if ($env:windir) {
            Add-StagingFolder $list $seen (Join-Path $env:windir 'Temp') 'systemp'
            Add-StagingFolder $list $seen (Join-Path $env:windir 'System32\config\systemprofile\AppData\Local\Temp') 'systemp'
            Add-StagingFolder $list $seen (Join-Path $env:windir 'ServiceProfiles\NetworkService\AppData\Local\Temp') 'systemp'
            Add-StagingFolder $list $seen (Join-Path $env:windir 'ServiceProfiles\LocalService\AppData\Local\Temp') 'systemp'
        }
        Add-StagingFolder $list $seen (Join-Path ($sysDrive + '\') 'PerfLogs') 'systemp'
        $profiles = @()
        try {
            foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -EA Stop)) {
                try {
                    $pp = [string](Get-ItemProperty -LiteralPath $k.PSPath -EA Stop).ProfileImagePath
                    if ($pp) { $pp = [Environment]::ExpandEnvironmentVariables($pp); if ($pp -match '(?i)\\Users\\[^\\]+$') { $profiles += $pp } }
                } catch { }
            }
        } catch {
            # The profile list unreadable by an administrator: say so, as a
            # folder that could not be read, rather than silently covering
            # one profile.
            [void]$list.Add(@{ Path = 'the profile list (HKLM ProfileList)'; Role = 'other'; State = 'unlistable'; Error = $_.Exception.Message })
        }
        foreach ($pp in ($profiles | Sort-Object)) {
            Add-StagingFolder $list $seen (Join-Path $pp 'Downloads') 'downloads'
            Add-StagingFolder $list $seen (Join-Path $pp 'AppData\Local\Temp') 'temp'
        }
        foreach ($b in $bins) { Add-StagingFolder $list $seen $b 'recycle' }
    } else {
        if ($sid) { foreach ($b in $bins) { Add-StagingFolder $list $seen (Join-Path $b $sid) 'recycle' } }
        if ($env:windir) { Add-StagingFolder $list $seen (Join-Path $env:windir 'Temp') 'systemp' 'deferred' }
        Add-StagingFolder $list $seen "other users' Downloads, temp folders and recycle bins, the service profiles' temp folders and PerfLogs" 'other' 'deferred'
    }
    return @($list.ToArray())
}

$folderSpecs = @()
if ($Folders.Count) {
    # powershell -File hands a list as ONE string, so the separator is ';'
    # (a path may hold a comma, never a semicolon).
    foreach ($f in $Folders) { foreach ($piece in ($f -split ';')) { if ($piece.Trim()) { $pt = $piece.Trim().TrimEnd('\'); $folderSpecs += @{ Path = $pt; Role = (Get-RoleOfPath $pt); State = 'try' } } } }
}
else { $folderSpecs = @(Get-StagingFolders -IsElevated ($Elevated -eq 1)) }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$en = Get-StagingCandidates -Specs $folderSpecs -MaxFilesPerFolder $MaxFilesPerFolder -Depth $Depth -BudgetSeconds $BudgetSeconds -Stopwatch $sw
$stats = @{}
$cl = Invoke-ArchiveClassification -Candidates $en.Candidates -MaxProbes $MaxProbes -BudgetSeconds $BudgetSeconds -Stopwatch $sw -FolderStats $stats
foreach ($fr in $en.Folders) {
    if ($fr.State -eq 'searched' -and $stats.ContainsKey([string]$fr.Path)) {
        $fr.Denied = $stats[[string]$fr.Path].Denied; $fr.Locked = $stats[[string]$fr.Path].Locked; $fr.LockedNames = $stats[[string]$fr.Path].LockedNames
    }
}
$report = Get-ArchiveStagingReport -Archives $cl.Archives -Folders $en.Folders -Probes $cl.Probes -IsElevated ($Elevated -eq 1) -Depth $Depth
foreach ($l in $report.Lines) { $l }
Write-Marker -Name 'archstage' -Sev $report.Sev
if ($report.GapSev -ne 'OK') { Write-Marker -Name 'archstage_gap' -Sev $report.GapSev }
if ($report.Deferred -gt 0) { Write-Marker -Name 'archstage_deferred' -Sev ([string]$report.Deferred) }
