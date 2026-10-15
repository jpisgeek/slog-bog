#!/usr/bin/env bash
# CI/release evidence check, not controller-owned dispatch admission.
# Usage: scripts/check-review-verdicts.sh [manifest.yaml ...]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/.."
exec python3 "$here/check-committed-reviews.py" "$@"
