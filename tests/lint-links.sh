#!/bin/bash
# The repo is github.com/briankmatheson/...; a common typo drops the "k".
# Fails if any file (other than build output and the lock file) still has
# the bad form. Email addresses (@brianmatheson.com) are not links and are
# left alone.
#   tests/lint-links.sh
set -uo pipefail
cd "$(dirname "$0")/.."
pattern='github\.com/brianmatheson/'
if command -v rg >/dev/null 2>&1; then
    hits=$(rg -n "$pattern" --glob '!target' --glob '!Cargo.lock' --glob '!.git' . || true)
else
    hits=$(grep -rnE "$pattern" --exclude-dir=target --exclude-dir=.git --exclude=Cargo.lock . || true)
fi
if [ -n "$hits" ]; then
    echo "bad repo links (brianmatheson -> briankmatheson):" >&2
    echo "$hits" >&2
    exit 1
fi
echo "  ok  no bad repo links"
