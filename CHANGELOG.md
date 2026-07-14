# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Per-agent-session Ed25519 signing identities: `botsign new` mints a
  keypair, derives a key-bound session ID and `@botsign.invalid` email,
  and stores everything in a local keystore (JSON record + OpenSSH
  keypair + regenerated allowed_signers).
- Standard-library implementations of the OpenSSH formats involved:
  SSHSIG signing/verification (sha512/sha256), unencrypted
  `openssh-key-v1` private keys, authorized_keys public lines, and the
  ALLOWED SIGNERS file format.
- One-command repo wiring: `new --repo` / `attach` set repo-local
  identity and SSH-signing config with botsign itself as
  `gpg.ssh.program`; `detach` removes every managed key; `status` audits
  the wiring with exit codes.
- ssh-keygen `-Y` compatibility interface (`sign`, `verify`,
  `find-principals`, `check-novalidate`), so plain `git commit`,
  `git verify-commit`, and `git log --show-signature` work with no
  OpenSSH toolchain installed.
- `botsign verify`: walks any revision range, reconstructs each commit's
  signed payload byte-exactly, and classifies every commit into a closed
  status set (verified, unmanaged, unsigned, bad-signature, unknown-key,
  mismatch, revoked, expired) with quotable detail, text/JSON output,
  `--require-signed`, and exit code 1 on failure.
- Session lifecycle: `--ttl` expiry checked against commit timestamps,
  `revoke` (shreds the private key, fails all of the session's commits),
  `sessions`/`show` listings, and `export`/`import` of public-only
  session cards whose IDs are cryptographically bound to their keys.
- Runnable examples (`examples/make-demo-repo.sh`,
  `examples/verify-gate.sh`) and a signing-format reference
  (`docs/signature-format.md`).
- 91 deterministic offline tests (unit + in-process CLI integration with
  real git signing through the test binary) and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/botsign/releases/tag/v0.1.0
