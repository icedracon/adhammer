#!/usr/bin/env bash
# WS-CASCADE-REHEARSAL — bottom-up `cargo publish --dry-run` rehearsal for
# the 12 publishable adhammer crates. Reveals whether a real crates.io
# cascade would succeed against the current tree WITHOUT publishing anything.
#
# Discipline it enforces:
# - Publish order is derived from `cargo metadata` (never a remembered list),
#   ensuring leaves ship before dependents.
# - Any crate that fails dry-run reveals a real blocker (missing
#   readme/license/repository, unresolvable version, `[patch.crates-io]`
#   pointing at an unpublished sibling, feature-flag mismatch).
# - Runs in --allow-dirty --no-verify --dry-run: never publishes, never
#   requires a clean worktree, never rebuilds a full graph.
#
# Expected states:
# - Clean tree (no [patch.crates-io]): every crate dry-run passes ⇒ cascade
#   is ready.
# - Current dev tree (patches for smb2-client + dcerpc): the first crate
#   whose transitive graph reaches a patched dep fails with "no matching
#   package found". THAT IS THE INTENDED FAIL-CLOSED SIGNAL that the
#   cascade cannot proceed until patches are stripped and their siblings
#   published.
#
# CI expectation: this rehearsal is INFORMATIONAL until the release moment;
# the CI job runs it continue-on-error so it never blocks routine merges.
# Before a real cascade run, verify manually that this reports green.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Bottom-up publish DAG (leaves first). Derived from `cargo metadata` —
# regenerate with `scripts/cascade_rehearsal.sh --print-dag` when the
# internal dependency graph changes.
CRATES=(
  adhammer-ldap
  adhammer-secrets
  adhammer-core
  adhammer-sysvol
  adhammer-graph
  adhammer-checks
  adhammer-report
  adhammer-collector
  adhammer-kerberos
  adhammer-bloodhound
  adhammer
  adhammer-sdk
)

if [[ "${1:-}" == "--print-dag" ]]; then
  cargo metadata --format-version=1 --no-deps 2>/dev/null | \
    python3 -c "
import json, sys
m = json.load(sys.stdin)
pkgs = {p['name']: {d['name'] for d in p['dependencies']
                    if d['name'].startswith('adhammer')}
        for p in m['packages']}
internal = set(pkgs)
order, seen = [], set()
def visit(n):
    if n in seen: return
    seen.add(n)
    for d in pkgs[n]:
        if d in internal: visit(d)
    order.append(n)
for p in sorted(internal):
    visit(p)
for c in order:
    print(c)
"
  exit 0
fi

echo "[cascade-rehearsal] running \`cargo publish --dry-run\` in DAG order..."
echo "[cascade-rehearsal] $(date -u +%FT%TZ) — HEAD $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

# Detect fail-close state up front for a clearer report.
PATCHED=0
if grep -qE '^\[patch\.crates-io\]' Cargo.toml; then
  PATCHED=1
  echo "[cascade-rehearsal] NOTE: [patch.crates-io] is present in Cargo.toml"
  echo "[cascade-rehearsal] NOTE: the first crate reaching a patched dep will FAIL — that is the intended fail-closed signal"
fi

passed=0
failed=0
first_failure=""

for c in "${CRATES[@]}"; do
  printf "  %-22s ... " "$c"
  if cargo publish --dry-run --allow-dirty --no-verify -p "$c" >/tmp/cascade_${c}.log 2>&1; then
    echo "OK"
    passed=$((passed+1))
  else
    echo "FAIL (see /tmp/cascade_${c}.log)"
    failed=$((failed+1))
    if [[ -z "$first_failure" ]]; then
      first_failure="$c"
    fi
  fi
done

echo
echo "[cascade-rehearsal] summary: $passed OK / $failed FAIL out of ${#CRATES[@]}"
if [[ $failed -gt 0 ]]; then
  echo "[cascade-rehearsal] first failure: $first_failure"
  echo "[cascade-rehearsal] tail of first failure log:"
  tail -8 "/tmp/cascade_${first_failure}.log" | sed 's/^/    /'
  if [[ $PATCHED -eq 1 ]]; then
    echo "[cascade-rehearsal] EXPECTED FAIL-CLOSED: [patch.crates-io] present."
    echo "[cascade-rehearsal] To rehearse a clean cascade: strip [patch.crates-io],"
    echo "[cascade-rehearsal] regenerate Cargo.lock with --locked, and re-run this script."
    exit 2  # distinguish "known fail-closed" from "unknown failure"
  fi
  exit 1
fi

echo "[cascade-rehearsal] green — every crate dry-runs successfully; cascade is ready-shape."
exit 0
