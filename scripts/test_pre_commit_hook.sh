#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git -C "$WORK" init -q
git -C "$WORK" config user.email test@example.invalid
git -C "$WORK" config user.name "Hook Test"
mkdir -p "$WORK/.githooks"
cp "$ROOT/.githooks/pre-commit" "$WORK/.githooks/pre-commit"
cp "$ROOT/.githooks/leak-terms.txt" "$WORK/.githooks/leak-terms.txt"
printf 'clean\n' > "$WORK/probe.txt"
git -C "$WORK" add .
git -C "$WORK" commit -q --no-verify -m baseline

printf 'Zikurat%s\n' 7 > "$WORK/probe.txt"
git -C "$WORK" add probe.txt
if git -C "$WORK" -c core.hooksPath=/dev/null --exec-path >/dev/null 2>&1 && \
    (cd "$WORK" && .githooks/pre-commit >/dev/null 2>&1); then
    echo "hook accepted a staged deny-pattern match" >&2
    exit 1
fi

git -C "$WORK" reset -q --hard HEAD
printf '[\n' > "$WORK/.githooks/leak-terms.txt"
printf 'changed\n' > "$WORK/probe.txt"
git -C "$WORK" add .githooks/leak-terms.txt probe.txt
if (cd "$WORK" && .githooks/pre-commit >/dev/null 2>&1); then
    echo "hook failed open on malformed canonical regex" >&2
    exit 1
fi

echo "pre-commit hook fail-closed tests passed"
