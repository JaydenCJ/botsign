#!/usr/bin/env bash
# Builds a small demo repository with a session-signed agent history plus
# the two things an audit must catch: an ordinary human commit and an
# impersonation attempt (botsign identity claimed, no signature). Usage:
#
#   go build -o botsign ./cmd/botsign     # or have botsign on PATH
#   bash examples/make-demo-repo.sh /tmp/botsign-demo
#   ./botsign verify /tmp/botsign-demo
#
# The keystore lands in <target-dir>.keystore (override: BOTSIGN_KEYSTORE).
set -euo pipefail

DEST="${1:?usage: make-demo-repo.sh <target-dir>}"
[ -e "$DEST" ] && { echo "refusing to overwrite $DEST" >&2; exit 1; }

BOTSIGN="${BOTSIGN:-botsign}"
command -v "$BOTSIGN" >/dev/null || { echo "botsign not found; build it or set BOTSIGN=" >&2; exit 1; }
export BOTSIGN_KEYSTORE="${BOTSIGN_KEYSTORE:-$DEST.keystore}"

export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

commit_on() {
  # commit_on <seq> <message> [git -c overrides...]: pinned-date commit.
  local seq="$1" msg="$2"; shift 2
  local date
  date="$(printf '2026-03-%02dT09:00:00+00:00' "$seq")"
  git -C "$DEST" add -A
  GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
    git -C "$DEST" "$@" commit -q -m "$msg"
}

git init -q -b main "$DEST"
mkdir -p "$DEST/src" "$DEST/docs"

# 1 — mint a session for the agent and wire the repo to it.
"$BOTSIGN" new --agent claude-code --repo "$DEST"
SESSION_EMAIL="$(git -C "$DEST" config --local user.email)"

# 2+3 — the agent works normally; every commit comes out signed.
cat > "$DEST/src/limiter.go" <<'EOF'
package src

// Allow reports whether another request fits the window.
func Allow(used, limit int) bool {
	return used < limit
}
EOF
commit_on 1 "Add rate limiter"

cat > "$DEST/src/limiter_test.go" <<'EOF'
package src

import "testing"

func TestAllow(t *testing.T) {
	if !Allow(1, 2) || Allow(2, 2) {
		t.Fatal("window math wrong")
	}
}
EOF
commit_on 2 "Cover the limiter window"

# 4 — an ordinary human commit: unmanaged, passes by default.
printf '# Ops guide\nRestart with care.\n' > "$DEST/docs/ops.md"
commit_on 3 "Document restarts" \
  -c user.name="Dev Human" -c user.email="dev@example.test" -c commit.gpgsign=false

# 5 — impersonation: the session identity without the session key.
printf 'sneaky change\n' > "$DEST/src/sneak.txt"
commit_on 4 "Tune the limiter defaults" \
  -c user.name="claude-code" -c "user.email=$SESSION_EMAIL" -c commit.gpgsign=false

echo
echo "demo repo ready — now run:"
echo "  $BOTSIGN verify $DEST"
