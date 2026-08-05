# doze_sec backlog

Ideas evaluated and deferred, kept here so they are not lost. Nothing here is a
commitment; each entry records enough context to pick it up later.

## Firmware / boot-chain coverage

**Idea.** Extend the audit below the OS: DBX (UEFI revocation list) freshness,
UEFI variable inspection, Secure Boot depth beyond the current on/off check, and
known bootkit indicators (BlackLotus, CosmicStrand and similar abuse the boot
chain to persist below Windows).

**Why it is worth doing.** State-level actors and the most capable ransomware
crews increasingly persist in firmware and the boot chain precisely because a
user-mode audit -- and most EDR -- cannot see there. It is the last major
coverage frontier for this tool.

**The honest ceiling, which must be stated in the report if this ships.** A
user-mode tool sits *above* the layer where bootkits live. This can audit the
*configuration and known-bad indicators* the OS exposes (Secure Boot state, DBX
contents via `Get-SecureBootUEFI`, the boot-order variables, moklist), but it
cannot scan the firmware image itself or trust that firmware is telling it the
truth. Framing it as "boot-chain configuration audit" rather than "firmware
scan" is essential -- overclaiming here would be the same
false-sense-of-safety failure Tier 0 exists to prevent.

**Concrete first checks.** `Get-SecureBootUEFI db`/`dbx` present and DBX not
suspiciously old (a stale DBX means known-bad bootloaders are not revoked);
`Confirm-SecureBootUEFI`; boot order and any non-Microsoft boot entries; MOK
enrollment on machines that use shim. All read-only, all PowerShell 5.1
capable, all with a clear "this cannot see a firmware implant" caveat.

## Adversary-emulation corpus

Being built now (see `tools/emulation_coverage.ps1`, `tests/emulation_corpus.txt`).
