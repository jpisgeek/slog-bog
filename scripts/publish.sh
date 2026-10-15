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
#   --allow-untested  publish an extension that has no *_test.ts (discouraged)
#
# Environment:
#   SLOG_BOG_DENYLIST   path to the private identifier denylist (outside the
#                       repo). Strongly recommended; warns if unset.
#   REVIEW_MODEL        model for the security review
#                       (default gpt-daybreak-blue-latest, via `codex exec`)
#
# Gates, in order:
#   1 swamp extension fmt --check
#   2 deno fmt --check + deno test (sibling *_test.ts)
#   3 swamp extension quality
#   4 gen-readme.ts --check           README equals the generated one
#   5 scan-identifiers.sh             generic rules + private denylist
#   6 security review                 codex pass → reviews/<name>/<hash>.md, must be PASS
#   7 swamp extension push --dry-run  (built-in adversarial review forced fresh)
#   8 STOP for operator approval, then push
set -euo pipefail

# ---------------------------------------------------------------------------
# PUBLISHING: REOPENED 2026-09-10 (supersedes the 2026-09-01 retirement).
#
# Why it was retired (2026-09-01): most of what had been published was
# agent-driven exploration nobody actually ran, wrapped in gates heavier than
# the work they guarded, so the repo was frozen to reference-only.
#
# Why it is open again (2026-09-10, Jason's decision): the repo now grows
# extensions built against real backends — caddy manages live systemd Caddy
# routes with drift checks and rollback; others wrap real fleet services.
# Freezing the whole repo to stop the exploration junk was too blunt. The
# retirement's real lesson — do not ship things nobody verified — is carried
# not by a blanket wall but by the per-extension gates below, and by gate 6 in
# particular: NOTHING publishes without a FRESH security verdict bound to its
# exact current bytes (reviews/<name>/<contenthash>.md, verdict: PASS). Stale
# verdicts (the reviewer or the bytes changed) and self-authored verdicts do
# not admit a push. Validity is enforced per extension, at publish time, on the
# real bytes — which is stricter than an all-or-nothing freeze ever was.
#
# The kill-switch is retained, inverted: publishing is open by default; set
# SLOG_BOG_PUBLISH_STOPPED=1 to re-close the repo instantly if that is ever
# the right call again.
# ---------------------------------------------------------------------------
if [ "${SLOG_BOG_PUBLISH_STOPPED:-}" = "1" ]; then
  echo "publish.sh: publishing is manually re-closed (SLOG_BOG_PUBLISH_STOPPED=1). Unset it to reopen." >&2
  exit 1
fi
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
review_only=0; skip_review=0; channel=""; allow_untested=0
while [ $# -gt 0 ]; do
  case "$1" in
    --review-only) review_only=1 ;;
    --skip-review) skip_review=1 ;;
    --allow-untested) allow_untested=1 ;;
    --channel) channel="${2:-}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

manifest="$name/manifest.yaml"
[ -f "$manifest" ] || { echo "no manifest at $manifest" >&2; exit 2; }
model="${REVIEW_MODEL:-gpt-daybreak-blue-latest}"
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
  # --allow-run is needed by the vault tests (they drive a fake pass-cli);
  # --allow-write by the dashboard tests (they render to a temp file).
  deno test --allow-read --allow-write --allow-env --allow-net --allow-run "$name/"
else
  echo "REFUSING: $name has no *_test.ts. Publishing untested code under your" >&2
  echo "name is the one gap the security review cannot cover. Write tests, or" >&2
  echo "pass --allow-untested to override deliberately." >&2
  [ "${allow_untested:-0}" -eq 1 ] || exit 1
fi

step "3/8 swamp extension quality"
swamp extension quality "$manifest"

step "4/8 README is generated and current"
deno run --allow-read --allow-run --allow-env scripts/gen-readme.ts --check "$name"

step "5/8 identifier scan"
published=()
published_list="$(deno run --allow-read --allow-run scripts/content-hash.ts "$manifest" --list)"
while IFS= read -r f; do [ -n "$f" ] && published+=("$f"); done \
  <<< "$published_list"
if [ -z "${SLOG_BOG_DENYLIST:-}" ]; then
  echo "WARNING: SLOG_BOG_DENYLIST is not set — only generic rules will run." >&2
fi
scripts/scan-identifiers.sh "${published[@]}"

step "6/8 secrets & security review ($model)"
hash="$(deno run --allow-read --allow-run scripts/content-hash.ts "$manifest")"
verdict="reviews/$name/$hash.md"
mkdir -p "reviews/$name"
# A verdict is keyed on the content hash, so an unchanged extension keeps the
# verdict it already has. That is deliberate policy, not merely a saved API
# call. The security reviewer changed from claude-fable-5 to
# gpt-daybreak-blue-latest on 2026-08-28, and the ruling was that existing
# verdicts stand for the versions they were bound to: those exact bytes were
# reviewed by what was the gate of record at the time, and re-reviewing
# already-published code changes nothing about what is already public.
#
# Any NEW content hash gets the new reviewer. Change one byte of a published
# extension and it is reviewed afresh -- that is the property that matters,
# and it is why the cache is keyed on content rather than on version.
if [ -f "$verdict" ]; then
  echo "verdict already on file for ${hash:0:12}…: $verdict"
elif [ "$skip_review" -eq 1 ]; then
  echo "--skip-review given but no verdict exists for ${hash:0:12}…" >&2; exit 1
else
  command -v codex >/dev/null || { echo "codex CLI not found" >&2; exit 1; }
  prompt="$(mktemp)"
  {
    cat review/secrets-security-pass.md
    printf '\n\n# INPUT\nextension: %s\nversion: %s\ncontent-hash: %s\ndate: %s\n\n' \
      "$name" "$version" "$hash" "$(date +%F)"
    for f in "${published[@]}"; do
      printf '=== FILE: %s ===\n' "$f"; cat "$f"; printf '\n=== END FILE ===\n\n'
    done
  } > "$prompt"
  # -o writes ONLY the model's final message. Without it the whole transcript
  # -- hook lines, token counts, ANSI -- lands in the committed verdict, and
  # the PASS grep below would be matching against decoration rather than a
  # verdict. --cd is required because codex exec refuses to run outside a
  # trusted git directory.
  codex exec --model "$model" --cd "$root" -o "$verdict.tmp" - < "$prompt" >/dev/null
  rm -f "$prompt"
  [ -s "$verdict.tmp" ] || { echo "review produced no output" >&2; rm -f "$verdict.tmp"; exit 1; }
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
# The independent security verdict and Swamp's dimensional review are
# separate evidence. Do not use --yes to waive a missing, stale, incomplete,
# or issue-bearing dimensional report just because the security review passed.
dry=(swamp extension push "$manifest" --dry-run --json)
[ -n "$channel" ] && dry+=(--channel "$channel")
dry_result="$("${dry[@]}")" || { echo "dry-run failed — not pushing." >&2; exit 1; }
printf '%s\n' "$dry_result"
if ! printf '%s\n' "$dry_result" | python3 -c '
import json, sys
result = json.load(sys.stdin)
warnings = result.get("warnings", {})
checks = result.get("registryChecks", [])
if (result.get("status") != "dry_run" or not checks
    or any(check.get("status") != "passed" for check in checks)
    or warnings.get("review") or warnings.get("safety")
    or any(w.get("cause") == "not-audited" for w in warnings.get("dependencyTrust", []))
    or result.get("unresolvedWarnings") or result.get("acceptedWarnings")):
    sys.exit(1)
'; then
  echo "REFUSING: resolve the review, safety, dependency audit, or registry checks shown above, then rerun." >&2
  exit 1
fi

step "8/8 operator approval"
echo "About to publish:"
echo "  extension : $name  (version $version)"
echo "  hash      : $hash"
echo "  verdict   : $verdict (PASS)"
echo "  channel   : ${channel:-stable}"
echo "  files     :"; printf '    %s\n' "${published[@]}"
echo
# New packages inherit collective visibility; existing packages preserve their
# visibility. A private release is not a staging gate for a public release.
echo "  visibility: registry default; confirm the applied visibility after push."
echo "  reversal  : yank/deprecate only (the artifact was still public)."
[ -n "$channel" ] || echo "  tip       : --channel beta publishes as a prerelease instead of stable."
echo
read -r -p "Type JP-GO to push, anything else to abort: " answer
[ "$answer" = "JP-GO" ] || { echo "aborted."; exit 1; }
# --json never prompts and does not waive newly appearing warnings with --yes.
# The operator gate remains the JP-GO line above.
push=(swamp extension push "$manifest" --json)
[ -n "$channel" ] && push+=(--channel "$channel")
"${push[@]}"
echo
echo "Published $pkg (public). Verify the registry copy resolves for a consumer:"
echo "  cd \$(mktemp -d) && swamp repo init --tool none"
echo "  swamp extension pull $pkg && swamp model type search jpisgeek"
echo "If it is wrong: swamp extension yank $pkg <version>   (reversible: unyank)"
