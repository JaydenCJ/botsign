# How botsign signs and verifies

botsign contains a complete, standard-library implementation of the
OpenSSH signature stack, so neither signing nor verification ever shells
out to `ssh-keygen`. This document pins down exactly what is signed, in
which formats, and how git is wired into it.

## What exactly is signed

When git signs a commit, the payload is **the raw commit object with the
`gpgsig` header removed** — tree, parents, author, committer, any other
headers, and the full message, byte for byte. botsign reconstructs that
payload from `git cat-file commit <sha>` by excising the `gpgsig` block
(the header line plus its space-prefixed continuation lines) and nothing
else. One byte of drift and the signature reads as tampered, which is the
point: subject lines, authorship, and timestamps are all covered.

## The SSHSIG envelope

Signatures use OpenSSH's SSHSIG format (`PROTOCOL.sshsig`), armored as a
`-----BEGIN SSH SIGNATURE-----` block. The binary layout:

| Field | Value in botsign |
|---|---|
| magic | `SSHSIG` (6 raw bytes) |
| version | `1` |
| public key | wire blob, `ssh-ed25519` only |
| namespace | `git` (commits/tags); never valid across namespaces |
| reserved | empty |
| hash algorithm | `sha512` when signing; `sha256` also accepted on verify |
| signature | inner blob: `ssh-ed25519` + 64 raw bytes |

The Ed25519 signature covers `SSHSIG ‖ namespace ‖ reserved ‖ hash-name ‖
H(payload)` — the payload is hashed exactly once, so signing a large
commit costs one digest pass.

## Key formats

- **Private keys**: unencrypted `openssh-key-v1` containers, mode `0600`,
  one per session at `<keystore>/keys/<session-id>`. The checkint pair is
  derived from the seed instead of random, making key files byte-stable.
- **Public keys**: single-line authorized_keys format with a
  `botsign:<session-id>` comment.
- **Fingerprints**: OpenSSH `SHA256:<base64>` of the public key blob. The
  8-hex-char session ID suffix is a prefix of that same digest, so a
  session ID is cryptographically bound to its key — imports re-derive
  and reject records where the two disagree.

## How git is wired in

`botsign new --repo` / `botsign attach` set only repo-local config:

| Key | Value |
|---|---|
| `user.name` / `user.email` | the session identity |
| `user.signingKey` | path to the session's private key |
| `gpg.format` | `ssh` |
| `gpg.ssh.program` | the botsign binary itself |
| `gpg.ssh.allowedSignersFile` | `<keystore>/allowed_signers` |
| `commit.gpgsign` | `true` |
| `botsign.session` / `botsign.keystore` | breadcrumbs for `status`/`verify` |

git then invokes botsign through the `ssh-keygen -Y` interface: `-Y sign`
at commit time, `-Y find-principals` / `-Y verify` / `-Y check-novalidate`
for `git verify-commit` and `git log --show-signature`. botsign implements
all four operations, so no OpenSSH toolchain is required — but because the
output is standard SSHSIG, a stock `ssh-keygen -Y verify` with the
exported allowed_signers file validates the same commits independently:

```bash
botsign export > signers
# payload = the commit object minus its gpgsig header …
git cat-file commit HEAD | perl -0pe 's/^gpgsig .*?\n(?! )//sm' > payload
# … and the signature is that header, unfolded (drop "gpgsig " and the continuation spaces)
git cat-file commit HEAD | awk '/^gpgsig /{s=1; print substr($0,8); next} s && /^ /{print substr($0,2); next} {s=0}' > commit.sig
ssh-keygen -Y verify -f signers -I "$(git log -1 --format=%ce)" -n git -s commit.sig < payload
```

## allowed_signers

`<keystore>/allowed_signers` is regenerated on every keystore mutation and
holds one line per non-revoked session, scoped to the git namespace:

```
<email> namespaces="git" ssh-ed25519 <base64-key>
```

The same line is what `botsign export` prints and `botsign import`
consumes — a session's public half travels as one line of text.
