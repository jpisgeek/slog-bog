#!/usr/bin/env bash
# scan-identifiers.sh — mechanical pre-filter for private/identifying content
# on the published surface of a swamp extension.
#
# This is NOT the gate of record (that is the Fable secrets & security pass in
# review/secrets-security-pass.md). It exists to fail fast and cheaply on the
# things a regex can catch, so a review is never spent on an obvious leak.
#
# Usage:
#   scripts/scan-identifiers.sh [--denylist FILE] [--quiet] PATH...
#
#   PATH        files or directories to scan (directories are walked)
#   --denylist  a private file of fixed strings, one per line (# comments ok),
#               matched case-insensitively. Keep it OUTSIDE this repo — it is
#               the list of real hostnames, domains, vault item paths, IDs that
#               must never appear here, which makes the list itself sensitive.
#               Also read from $SLOG_BOG_DENYLIST if the flag is absent.
#   --quiet     print only the summary line
#
# Exit codes: 0 clean · 1 hits found · 2 usage error
#
# Generic rules (always on):
#   ip-private      RFC 1918, loopback, link-local, CGNAT, IPv6 ULA/link-local
#   host-local      localhost, *.local, *.lan, *.internal, *.home.arpa
#   path-local      /Users/, /home/, /Volumes/, /private/, C:\Users\, file://
#   secret-shape    AWS access keys, GitHub/OpenAI-style tokens, PEM blocks,
#                   Slack tokens, "Bearer <long>", password=/secret= literals
#   mac-address     aa:bb:cc:dd:ee:ff
#   email           user@domain (except @example.*, @localhost)
#   userinfo-url    scheme://user:pass@host
#   control-byte    NUL or other C0 control bytes in a text file
#
# grep runs with -a so a stray control byte cannot hide a file as "binary".

set -euo pipefail

denylist="${SLOG_BOG_DENYLIST:-}"
quiet=0
paths=()

while [ $# -gt 0 ]; do
  case "$1" in
    --denylist) denylist="${2:-}"; shift 2 ;;
    --denylist=*) denylist="${1#--denylist=}"; shift ;;
    --quiet) quiet=1; shift ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    --) shift; paths+=("$@"); break ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) paths+=("$1"); shift ;;
  esac
done

if [ ${#paths[@]} -eq 0 ]; then
  echo "usage: $0 [--denylist FILE] [--quiet] PATH..." >&2
  exit 2
fi

# Collect regular files. Skip VCS metadata and the scanner's own test fixtures
# (which intentionally contain dirty content) — unless the caller pointed
# directly inside the fixtures, which is how the self-test exercises them.
files=()
for p in "${paths[@]}"; do
  if [ -d "$p" ]; then
    case "$p" in
      *tests/fixtures*) prune=() ;;
      *) prune=(! -path '*/tests/fixtures/*') ;;
    esac
    while IFS= read -r -d '' f; do files+=("$f"); done < <(
      find "$p" -type f \
        ! -path '*/.git/*' \
        ! -path '*/node_modules/*' \
        ${prune[@]+"${prune[@]}"} \
        -print0
    )
  elif [ -f "$p" ]; then
    files+=("$p")
  else
    echo "not found: $p" >&2; exit 2
  fi
done

if [ ${#files[@]} -eq 0 ]; then
  echo "scan-identifiers: no files to scan"; exit 0
fi

hits=0
report() { # rule file:line:match
  hits=$((hits + 1))
  [ "$quiet" -eq 1 ] || printf '%s\t%s\n' "$1" "$2"
}

# Each generic rule: name + extended regex. Keep patterns narrow enough that
# vendor API domains and documentation placeholders do not trip them.
rule_names=(
  ip-private
  host-local
  path-local
  secret-shape
  mac-address
  email
  userinfo-url
)
rule_regex=(
  # ip-private: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, fc00::/7, fe80::/10
  '(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|169\.254\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)|(^|[^0-9a-fA-F:])(f[cd][0-9a-fA-F]{2}:|fe80:)'
  # host-local
  '(^|[^A-Za-z0-9.-])localhost([^A-Za-z0-9-]|$)|[A-Za-z0-9-]+\.(local|lan|internal|home\.arpa)([^A-Za-z0-9.-]|$)'
  # path-local
  '(^|[^A-Za-z0-9])(/Users/|/home/[A-Za-z]|/Volumes/|/private/(tmp|var|etc)|[A-Za-z]:\\Users\\)|file://'
  # secret-shape
  '(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._~+/=-]{24,}|(password|passwd|secret|api[_-]?key|token)[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"']{8,}["'"'"'])'
  # mac-address
  '(^|[^0-9A-Fa-f:])([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}([^0-9A-Fa-f:]|$)'
  # email — placeholder domains (example.*, *.example.*, localhost) are filtered
  # out after the match because BSD grep has no -P for lookaheads.
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  # userinfo-url
  '[a-z][a-z0-9+.-]*://[^/@[:space:]]+:[^/@[:space:]]+@'
)

for i in "${!rule_names[@]}"; do
  name="${rule_names[$i]}"; re="${rule_regex[$i]}"
  for f in "${files[@]}"; do
    while IFS= read -r line; do
      [ -n "$line" ] && report "$name" "$f:$line"
    done < <(
      grep -a -n -E -o -- "$re" "$f" 2>/dev/null | {
        if [ "$name" = "email" ]; then
          grep -a -v -E -i '@([a-z0-9-]+\.)*example\.[a-z]+$|@localhost$' || true
        else
          cat
        fi
      } | head -50 || true
    )
  done
done

# control-byte: NUL or C0 controls other than \t \n \r. Report once per file
# with a count; a single one is enough to hide a file from plain grep.
for f in "${files[@]}"; do
  n=$(LC_ALL=C tr -cd '\000-\010\013\014\016-\037' < "$f" | wc -c | tr -d ' ')
  if [ "$n" -gt 0 ]; then report "control-byte" "$f: $n control byte(s)"; fi
done

# Private denylist: fixed strings, case-insensitive, whole-line match on the hit.
if [ -n "$denylist" ]; then
  if [ ! -r "$denylist" ]; then echo "denylist not readable: $denylist" >&2; exit 2; fi
  # Strip comments/blank lines into a temp pattern file.
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  grep -v -E '^[[:space:]]*(#|$)' "$denylist" > "$tmp" || true
  if [ -s "$tmp" ]; then
    for f in "${files[@]}"; do
      while IFS= read -r line; do
        [ -n "$line" ] && report "denylist" "$f:$line"
      done < <(grep -a -n -i -F -f "$tmp" -- "$f" 2>/dev/null | cut -c1-200 || true)
    done
  fi
else
  [ "$quiet" -eq 1 ] || echo "scan-identifiers: no denylist supplied (set --denylist or \$SLOG_BOG_DENYLIST) — generic rules only" >&2
fi

echo "scan-identifiers: ${#files[@]} file(s) scanned, $hits hit(s)"
[ "$hits" -eq 0 ]
