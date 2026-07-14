#!/usr/bin/env bash
# End-to-end smoke test for botsign: builds the binary, mints a session in
# a throwaway keystore, lets real git sign commits through botsign, then
# audits the history — including impersonation, teammate import, and
# revocation. No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/botsign"
REPO="$WORKDIR/repo"
export BOTSIGN_KEYSTORE="$WORKDIR/keystore"

# Isolate git completely from the host user's configuration.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

commit_on() {
  # commit_on <seq> <message>: stage everything, commit with pinned date
  # using whatever identity/signing config the repo carries.
  local seq="$1"; shift
  local date
  date="$(printf '2026-03-%02dT10:00:00+00:00' "$seq")"
  git -C "$REPO" add -A
  GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
    git -C "$REPO" commit -q -m "$*"
}

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/botsign) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "botsign 0.1.0" || fail "--version mismatch"

echo "3. mint a session and attach a fresh repository"
git init -q -b main "$REPO"
NEW_OUT="$("$BIN" new --agent claude-code --repo "$REPO")"
echo "$NEW_OUT" | grep -q "^session   claude-code-" || fail "no session id in new output"
echo "$NEW_OUT" | grep -q "commit signing on" || fail "attach confirmation missing"
SID="$(echo "$NEW_OUT" | awk '/^session/ {print $2}')"
git -C "$REPO" config --local botsign.session | grep -qx "$SID" || fail "repo not wired to $SID"

echo "4. a plain git commit comes out signed"
printf 'package main\n' > "$REPO/main.go"
commit_on 1 "Add rate limiter"
git -C "$REPO" cat-file commit HEAD | grep -q "BEGIN SSH SIGNATURE" \
  || fail "commit has no SSH signature"

echo "5. stock git verifies through botsign (gpg.ssh.program)"
GITOUT="$(git -C "$REPO" verify-commit HEAD 2>&1)" \
  || fail "git verify-commit rejected the signature"
echo "$GITOUT" | grep -q "Good \"git\" signature" \
  || fail "git verify-commit output unexpected: $GITOUT"

echo "6. botsign verify attests the history"
OUT="$("$BIN" verify "$REPO")"
echo "$OUT" | grep -q "verified" || fail "verified status missing"
echo "$OUT" | grep -q "$SID" || fail "session attribution missing"
echo "$OUT" | grep -q "verify: PASS" || fail "verdict should be PASS"

echo "7. JSON report is machine-readable"
JSON="$("$BIN" verify --format json "$REPO")"
echo "$JSON" | grep -q '"tool": "botsign"' || fail "json envelope missing"
echo "$JSON" | grep -q '"ok": true' || fail "json verdict wrong"
echo "$JSON" | grep -q '"verified": 1' || fail "json summary wrong"

echo "8. a teammate imports the public card and verifies too"
"$BIN" export > "$WORKDIR/card.txt"
BOTSIGN_KEYSTORE="$WORKDIR/keystore2" "$BIN" import "$WORKDIR/card.txt" >/dev/null
OUT="$(BOTSIGN_KEYSTORE="$WORKDIR/keystore2" "$BIN" verify "$REPO")" \
  || fail "verification via imported public keys failed"
echo "$OUT" | grep -q "verify: PASS" || fail "imported-keystore verdict wrong"

echo "9. impersonation is caught"
EMAIL="$(echo "$NEW_OUT" | awk '/^email/ {print $2}')"
printf 'sneaky\n' > "$REPO/sneak.txt"
git -C "$REPO" add -A
GIT_AUTHOR_DATE=2026-03-02T10:00:00+00:00 GIT_COMMITTER_DATE=2026-03-02T10:00:00+00:00 \
  git -C "$REPO" -c user.name=claude-code -c "user.email=$EMAIL" -c commit.gpgsign=false \
  commit -q -m "Sneaky unsigned change"
set +e
OUT="$("$BIN" verify "$REPO")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "verify should exit 1 on impersonation (got $CODE)"
echo "$OUT" | grep -q "unsigned" || fail "unsigned status missing"

echo "10. status and detach"
OUT="$("$BIN" status "$REPO")" || fail "status should exit 0 on a healthy repo"
echo "$OUT" | grep -q "signing   on" || fail "status should report signing on"
"$BIN" detach "$REPO" >/dev/null
git -C "$REPO" config --local --get botsign.session >/dev/null 2>&1 \
  && fail "detach left botsign config behind"

echo "11. revocation invalidates history"
"$BIN" revoke "$SID" >/dev/null
set +e
OUT="$("$BIN" verify --range HEAD~1 --keystore "$BOTSIGN_KEYSTORE" "$REPO")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "verify should exit 1 after revocation (got $CODE)"
echo "$OUT" | grep -q "revoked" || fail "revoked status missing"

echo "12. usage errors exit 2"
set +e
"$BIN" verify --format yaml "$REPO" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
set -e

echo "SMOKE OK"
