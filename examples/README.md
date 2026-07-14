# botsign examples

Two runnable scripts, both offline and self-contained.

## make-demo-repo.sh

Fabricates a small git repository the way a real agent session would:
mints a `claude-code` session, wires the repo to it, makes two signed
commits, then adds the two cases every audit must classify correctly — an
ordinary human commit and an impersonation attempt (the session's email
on an unsigned commit).

```bash
go build -o botsign ./cmd/botsign
bash examples/make-demo-repo.sh /tmp/botsign-demo
./botsign verify /tmp/botsign-demo          # exits 1: impersonation caught
BOTSIGN_KEYSTORE=/tmp/botsign-demo.keystore ./botsign sessions   # the minted session
```

(`verify` finds the keystore by itself — attach recorded it in the repo's
config; `sessions` has no repo to ask, so point it at the demo keystore.)

## verify-gate.sh

Shows `botsign verify` as a policy gate: it exits non-zero the moment any
commit in the range fails attestation, so it can back a `pre-push` hook,
a release checklist, or any local automation.

```bash
bash examples/verify-gate.sh /tmp/botsign-demo; echo "exit: $?"
bash examples/verify-gate.sh /tmp/botsign-demo 'HEAD~2'   # older, clean range
```

Both scripts pin commit dates and isolate git configuration, so every run
produces the same report shape; the session ID, key, and commit hashes are
fresh each time, because the ID derives from the newly minted key.
