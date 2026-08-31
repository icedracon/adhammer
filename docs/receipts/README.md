# Live-validation receipts

This directory holds sanitized outputs of `scripts/live_validation.sh`
runs against authorized DCs. Every receipt is committable — the scrubber
(`scripts/scrub_receipt.py`) redacts every lab identifier (DC IP, realm,
admin credentials, real domain SIDs, NT hashes, ccache blobs, long hex
blobs) to placeholders before writing.

## Naming

`<adhammer_version>__<windows_label>.{md,json}`

Examples:

- `1.4.9__2019.md`
- `1.4.9__2022.md`
- `1.4.9__2025.md`

## How to add a receipt

1. Boot the DC VM (`2019server` / `2022server` / `2025server1`).
2. Get the DC's IP + realm + an admin credential.
3. Run:

   ```bash
   cd adhammer
   cargo build --release --bin adhammer
   export ADH_PW_VALUE='the-actual-password-never-in-any-committed-file'
   ADH_DC=<dc-ip> \
   ADH_REALM=<REALM> \
   ADH_ADMIN='<REALM>\Administrator' \
   ADH_PW='env:ADH_PW_VALUE' \
   WINDOWS_LABEL=2019 \
     ./scripts/live_validation.sh
   ```

4. Review the generated receipt with `git diff docs/receipts/`.
   - Confirm no lab identifier survived redaction.
   - Confirm all verbs behaved as expected.
5. `git add docs/receipts/ && git commit -m "validation: adhammer 1.4.9 receipt vs <label>"`
6. Update `docs/VALIDATION.md` to promote any row from `validation owed`
   or `offline-only` to `supported` for the tested Windows version.

## Ledger promotion policy

A `supported` row in `docs/VALIDATION.md` requires:

- At least one live-validation receipt in this directory
  targeting a Windows-version in the current release-cycle matrix.
- The receipt must include the verb's `pass` line.
- The receipt's binary sha256 must match the release artifact.

Receipts that predate the current release cycle count as historical
context, not as fresh validation. Every cycle regenerates its own
receipts.

## What the scrubber does NOT scrub

- Timestamps — chronology is what a receipt is for.
- Protocol names, opnums, error codes — these are the evidence.
- Placeholder IPs shaped like `10.X.X.X` / `192.168.X.X`.
- Windows version identifiers (Server 2019 etc.) — they're the release-
  matrix labels.

## What the scrubber DOES scrub

- The literal DC IP passed via `--dc`.
- The realm passed via `--realm`.
- The admin identity passed via `--admin`.
- The password passed via `--pw` + its URL-encoded form.
- Real domain SIDs (RID preserved for meaning: 500, 512, 519 etc.).
- 32-hex-char sequences (NT hash shape).
- 64-hex-char sequences (AES256 key shape).
- 128+-hex-char sequences (ccache / TGT / hive-blob shape).
- Any IPv4 the caller didn't explicitly declare via `--dc`.

## Hard refuse list

The scrubber will REFUSE to emit output if it detects any of the
strings in `HARD_BLOCK_SUBSTRINGS` (matches the pre-commit hook list).
Fix upstream (rotate the credential; scrub input by hand) before
rerunning.
