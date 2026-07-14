#!/usr/bin/env bash
# botsign verify as a local policy gate: block a push (or a release) when
# any commit in the outgoing range fails attestation. Wire it up as
# .git/hooks/pre-push or call it from any local automation. Usage:
#
#   bash examples/verify-gate.sh <repo> [range]
#
# Exit code is botsign's: 0 = every commit attested or unmanaged,
# 1 = at least one failing commit, with the report on stdout.
set -euo pipefail

REPO="${1:?usage: verify-gate.sh <repo> [range]}"
RANGE="${2:-HEAD}"
BOTSIGN="${BOTSIGN:-botsign}"

if "$BOTSIGN" verify --range "$RANGE" "$REPO"; then
  echo "gate: signatures attested — proceeding"
else
  echo "gate: attestation failed — refusing to proceed" >&2
  exit 1
fi
