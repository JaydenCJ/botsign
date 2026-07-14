# Contributing to botsign

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22 and git ≥2.34 (for SSH-signature support); nothing else.

```bash
git clone https://github.com/JaydenCJ/botsign && cd botsign
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, mints a session in a throwaway
keystore, lets real git sign commits through botsign, and audits the
result — impersonation, teammate import, and revocation included; it must
finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (91 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (crypto, parsing, and classification never shell out — only
   `gitio.Git` does).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in
  the PR.
- No network calls, ever — botsign's only external interface is the
  local `git` binary. No telemetry.
- Cryptography stays boring: Ed25519 via the standard library, exact
  SSHSIG wire compatibility with OpenSSH. New formats or algorithms need
  an interop story before code.
- Verification statuses are a closed, documented set: a new status needs
  a README row, a unit test reproducing the commit shape, and a decision
  on whether it fails the audit.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical reports,
  including all orderings.

## Reporting bugs

Include the output of `botsign version`, the full command you ran, the
report or error output, and — for verification disputes — the raw commit
(`git cat-file commit <sha>`, redact the message if needed) plus the
session record from `botsign show <id> --json`, since those two artifacts
are exactly what the verifier sees.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
