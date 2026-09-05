#!/usr/bin/env bash
# test-scan.sh — proves scan-identifiers.sh catches what it claims and stays
# quiet on clean input. Run from anywhere; exits non-zero on any failure.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
scan="$here/scan-identifiers.sh"
fx="$root/tests/fixtures"
fail=0

expect_rule() { # rule file  — the named rule must fire on that fixture file
  local rule="$1" file="$2"
  # The scanner exits 1 on hits by design; don't let pipefail hide grep's answer.
  if { "$scan" "$fx/dirty/$file" 2>/dev/null || true; } | grep -q "^${rule}"$'\t'; then
    echo "ok    $rule  ($file)"
  else
    echo "FAIL  $rule did not fire on $file"; fail=1
  fi
}

echo "== dirty fixtures: every rule must fire =="
expect_rule ip-private    ip.ts
expect_rule ip-private    loopback-address.ts
expect_rule ip-private    loopback-prefix.ts
expect_rule host-local    loopback-name.ts
expect_rule host-local    hosts.yaml
expect_rule path-local    paths.ts
expect_rule secret-shape  secrets.ts
expect_rule mac-address   ids.yaml
expect_rule email         ids.yaml
expect_rule userinfo-url  ids.yaml
expect_rule control-byte  nul.ts

echo "== denylist: fires only when supplied =="
if { "$scan" --denylist "$fx/denylist.sample.txt" "$fx/dirty/denylisted.md" 2>/dev/null || true; } | grep -q "^denylist"$'\t'; then
  echo "ok    denylist fires with --denylist"
else
  echo "FAIL  denylist did not fire"; fail=1
fi
if { "$scan" "$fx/dirty/denylisted.md" 2>/dev/null || true; } | grep -q "^denylist"$'\t'; then
  echo "FAIL  denylist fired without a denylist"; fail=1
else
  echo "ok    denylist silent without --denylist"
fi

echo "== exit codes =="
if "$scan" --quiet "$fx/dirty" >/dev/null 2>&1; then
  echo "FAIL  dirty dir exited 0"; fail=1
else
  echo "ok    dirty dir exits non-zero"
fi
if "$scan" --quiet --denylist "$fx/denylist.sample.txt" "$fx/clean" >/dev/null 2>&1; then
  echo "ok    clean dir exits 0"
else
  echo "FAIL  clean dir produced hits:"; "$scan" --denylist "$fx/denylist.sample.txt" "$fx/clean" || true; fail=1
fi

echo "== scanner skips its own fixtures when scanning the repo =="
if "$scan" --quiet "$root/tests" >/dev/null 2>&1; then
  echo "ok    tests/ dir (fixtures excluded) is clean"
else
  echo "FAIL  fixtures were not excluded"; fail=1
fi

[ "$fail" -eq 0 ] && echo "all scan tests passed" || { echo "scan tests FAILED"; exit 1; }
