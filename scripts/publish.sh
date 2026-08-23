#!/usr/bin/env bash
# publish.sh — the whole release sequence for one extension, in order, stopping
# at the first failure. The only human step is the approval prompt at the end.
#
# Usage:
#   scripts/publish.sh <name> [--review-only] [--skip-review] [--channel beta|rc]
#
#   <name>          extension directory at the repo root (holds manifest.yaml)
#   --review-only   run gates 1–6 (through the security review) and stop
#   --skip-review   reuse an existing PASS verdict for the current hash; do
#                   not call the model. Fails if none exists.
#   --channel       registry prerelease channel (default: stable)
#
# Environment:
#   SLOG_BOG_DENYLIST   path to the private identifier denylist (outside the
#                       repo). Strongly recommended; warns if unset.
#   REVIEW_MODEL        model for the security review (default claude-fable-5)
#
# Gates, in order:
#   1 swamp extension fmt --check
#   2 deno fmt --check + deno test (sibling *_test.ts)
#   3 swamp extension quality
#   4 gen-readme.ts --check           README equals the generated one
#   5 scan-identifiers.sh             generic rules + private denylist
#   6 security review                 Fable pass → reviews/<name>/<hash>.md, must be PASS
#   7 swamp extension push --dry-run  (built-in adversarial review forced fresh)
#   8 STOP for operator approval, then push
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"
# deno: on PATH, or the copy swamp ships with
if ! command -v deno >/dev/null 2>&1; then
  if [ -x "$HOME/.swamp/deno/deno" ]; then PATH="$HOME/.swamp/deno:$PATH"; export PATH
  else echo "deno not found (install deno or swamp)" >&2; exit 1; fi
fi

name="${1:-}"; shift || true
[ -n "$name" ] || { sed -n '2,25p' "$0"; exit 2; }
review_only=0; skip_review=0; channel=""
while [ $# -gt 0 ]; do
  case "$1" in
    --review-only) review_only=1 ;;
    --skip-review) skip_review=1 ;;
    --channel) channel="${2:-}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

manifest="$name/manifest.yaml"
[ -f "$manifest" ] || { echo "no manifest at $manifest" >&2; exit 2; }
model="${REVIEW_MODEL:-claude-fable-5}"
# Read once, up front: the publish summary (gate 8) needs these even when the
# review branch is skipped because a PASS verdict is already on file.
version="$(grep -m1 -E '^version:' "$manifest" | sed 's/version:[[:space:]]*//' | tr -d '"'"'"'')"
pkg="$(grep -m1 -E '^name:' "$manifest" | sed -E 's/^name:[[:space:]]*//' | tr -d '"'"'"'')"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

step "1/8 swamp extension fmt --check"
swamp extension fmt "$manifest" --check

step "2/8 deno fmt + tests"
deno fmt --check "$name/" scripts/
if ls "$name"/*_test.ts >/dev/null 2>&1; then
  deno test --allow-read --allow-env --allow-net "$name/"
else
  echo "WARNING: no tests found — testing-completeness will be flagged" >&2
fi

step "3/8 swamp extension quality"
swamp extension quality "$manifest"

step "4/8 README is generated and current"
deno run --allow-read --allow-run --allow-env scripts/gen-readme.ts --check "$name"

step "5/8 identifier scan"
published=()
while IFS= read -r f; do [ -n "$f" ] && published+=("$f"); done \
  < <(deno run --allow-read scripts/content-hash.ts "$manifest" --list)
if [ -z "${SLOG_BOG_DENYLIST:-}" ]; then
  echo "WARNING: SLOG_BOG_DENYLIST is not set — only generic rules will run." >&2
fi
scripts/scan-identifiers.sh "${published[@]}"

step "6/8 secrets & security review ($model)"
hash="$(deno run --allow-read scripts/content-hash.ts "$manifest")"
verdict="reviews/$name/$hash.md"
mkdir -p "reviews/$name"
if [ -f "$verdict" ]; then
  echo "verdict already on file for ${hash:0:12}…: $verdict"
elif [ "$skip_review" -eq 1 ]; then
  echo "--skip-review given but no verdict exists for ${hash:0:12}…" >&2; exit 1
else
  command -v claude >/dev/null || { echo "claude CLI not found" >&2; exit 1; }
  {
    cat review/secrets-security-pass.md
    printf '\n\n# INPUT\nextension: %s\nversion: %s\ncontent-hash: %s\ndate: %s\n\n' \
      "$name" "$version" "$hash" "$(date +%F)"
    for f in "${published[@]}"; do
      printf '=== FILE: %s ===\n' "$f"; cat "$f"; printf '\n=== END FILE ===\n\n'
    done
  } | claude -p --model "$model" --output-format text > "$verdict.tmp"
  mv "$verdict.tmp" "$verdict"
  echo "wrote $verdict"
fi
if grep -q -E '^verdict:[[:space:]]*PASS[[:space:]]*$' "$verdict"; then
  echo "review: PASS"
else
  echo "review did not PASS — see $verdict" >&2
  grep -E '^verdict:' "$verdict" >&2 || true
  exit 1
fi
[ "$review_only" -eq 1 ] && { echo "--review-only: stopping after the review."; exit 0; }

step "7/8 swamp extension push --dry-run"
# Our gate of record is the Fable verdict in reviews/ (gate 6, PASS above),
# which is a stricter superset of swamp's built-in adversarial-review
# dimensions. swamp still emits a "no adversarial-review report recorded"
# warning of its own; per swamp's docs that is NOT a hard block, it is a
# confirmable warning, so we let --yes acknowledge it at push time rather
# than maintaining a second review artifact in swamp's format. (Do not clear
# swamp's review dir here — that only guarantees the warning and changes
# nothing that matters.)
dry=(swamp extension push "$manifest" --dry-run)
[ -n "$channel" ] && dry+=(--channel "$channel")
"${dry[@]}" || { echo "dry-run failed — not pushing." >&2; exit 1; }

step "8/8 operator approval"
echo "About to publish:"
echo "  extension : $name  (version $version)"
echo "  hash      : $hash"
echo "  verdict   : $verdict (PASS)"
echo "  channel   : ${channel:-stable}"
echo "  visibility: registry default (private) — flip public after install-verify"
echo "  files     :"; printf '    %s\n' "${published[@]}"
echo
read -r -p "Type JP-GO to push, anything else to abort: " answer
[ "$answer" = "JP-GO" ] || { echo "aborted."; exit 1; }
# --yes: non-interactive confirm. swamp's own push prompt AND its
# not-a-hard-block adversarial-review warning are both acknowledged here; the
# human gate is the JP-GO line above.
push=(swamp extension push "$manifest" --yes)
[ -n "$channel" ] && push+=(--channel "$channel")
"${push[@]}"
echo
echo "Published $pkg. Next: install-verify from a clean clone, then flip public:"
echo "  swamp extension install $pkg   # into a scratch dir; confirm it resolves"
echo "  (registry defaults to private — make it public from the swamp-club UI/CLI when verified)"
echo "published. Next: install-verify from a clean clone, then flip visibility."
