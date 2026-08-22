#!/usr/bin/env bash
# check-review-verdicts.sh — for every extension manifest, require a committed
# secrets & security review verdict whose filename is the CURRENT content hash
# and whose verdict line is PASS.
#
# This is what CI enforces. It does not run a review; it proves one exists for
# exactly the bytes about to ship. Change any published byte and the hash
# moves, the old verdict stops matching, and this fails until a fresh review
# is filed under the new hash.
#
# Usage: scripts/check-review-verdicts.sh [manifest.yaml ...]
#        (no args = every extensions/manifests/*/manifest.yaml)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"
# deno: on PATH, or the copy swamp ships with
if ! command -v deno >/dev/null 2>&1; then
  if [ -x "$HOME/.swamp/deno/deno" ]; then PATH="$HOME/.swamp/deno:$PATH"; export PATH
  else echo "deno not found (install deno or swamp)" >&2; exit 1; fi
fi

manifests=("$@")
if [ ${#manifests[@]} -eq 0 ]; then
  while IFS= read -r m; do manifests+=("$m"); done < <(ls extensions/manifests/*/manifest.yaml 2>/dev/null || true)
fi
if [ ${#manifests[@]} -eq 0 ]; then
  echo "check-review-verdicts: no manifests yet"; exit 0
fi

fail=0
for m in "${manifests[@]}"; do
  name="$(basename "$(dirname "$m")")"
  hash="$(deno run --allow-read scripts/content-hash.ts "$m")"
  verdict="reviews/$name/$hash.md"
  if [ ! -f "$verdict" ]; then
    echo "MISSING  $name  no review for content hash ${hash:0:12}… (expected $verdict)"
    fail=1; continue
  fi
  if grep -q -E '^verdict:[[:space:]]*PASS[[:space:]]*$' "$verdict"; then
    echo "PASS     $name  ${hash:0:12}…"
  else
    echo "NOT-PASS $name  ${hash:0:12}…  ($(grep -m1 -E '^verdict:' "$verdict" || echo 'no verdict line'))"
    fail=1
  fi
done
exit "$fail"
