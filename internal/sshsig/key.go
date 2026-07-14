package sshsig

// key.go encodes and decodes Ed25519 keys in the two on-disk formats the
// OpenSSH toolchain uses: single-line authorized_keys entries for public
// keys, and the openssh-key-v1 container for private keys. botsign writes
// only unencrypted keys (sessions are short-lived and file permissions are
// the boundary), but the parser rejects encrypted input with a clear error
// instead of garbage.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// KeyType is the only SSH key algorithm botsign mints or accepts.
const KeyType = "ssh-ed25519"

const (
	privateKeyLabel = "OPENSSH PRIVATE KEY"
	privateMagic    = "openssh-key-v1\x00"
	// cipher "none" still pads the private section to its block size of 8.
	privatePadBlock = 8
)

// GenerateKey mints a fresh Ed25519 keypair from the given entropy source
// (crypto/rand.Reader in production, a fixed stream in tests).
func GenerateKey(rand io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %v", err)
	}
	return pub, priv, nil
}

// EncodePublicBlob renders the SSH wire blob for a public key: the same
// bytes that follow the base64 in an authorized_keys line.
func EncodePublicBlob(pub ed25519.PublicKey) []byte {
	var w buffer
	w.str([]byte(KeyType))
	w.str(pub)
	return w.b
}

// ParsePublicBlob decodes an SSH public key wire blob, accepting only
// ssh-ed25519.
func ParsePublicBlob(blob []byte) (ed25519.PublicKey, error) {
	r := reader{b: blob}
	keyType := r.str()
	key := r.bytes()
	if r.err != nil {
		return nil, fmt.Errorf("bad public key blob: %v", r.err)
	}
	if keyType != KeyType {
		return nil, fmt.Errorf("unsupported key type %q (want %s)", keyType, KeyType)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad ed25519 public key length %d", len(key))
	}
	if len(r.rest()) != 0 {
		return nil, errors.New("trailing bytes after public key")
	}
	return ed25519.PublicKey(key), nil
}

// MarshalAuthorized renders a single authorized_keys-style line (no
// trailing newline): `ssh-ed25519 <base64> <comment>`.
func MarshalAuthorized(pub ed25519.PublicKey, comment string) string {
	line := KeyType + " " + base64.StdEncoding.EncodeToString(EncodePublicBlob(pub))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// ParseAuthorized parses an authorized_keys-style line into the public key
// and its optional comment.
func ParseAuthorized(line string) (ed25519.PublicKey, string, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return nil, "", errors.New("public key line needs `ssh-ed25519 <base64>`")
	}
	if fields[0] != KeyType {
		return nil, "", fmt.Errorf("unsupported key type %q (want %s)", fields[0], KeyType)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, "", fmt.Errorf("bad public key base64: %v", err)
	}
	pub, err := ParsePublicBlob(blob)
	if err != nil {
		return nil, "", err
	}
	return pub, strings.Join(fields[2:], " "), nil
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of a public key:
// `SHA256:` plus unpadded base64 of the blob digest.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(EncodePublicBlob(pub))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// MarshalPrivate renders an unencrypted openssh-key-v1 private key block.
// The checkint pair is normally random; botsign derives it from the key so
// that marshalling is deterministic — it only exists to detect a wrong
// decryption passphrase, which cannot happen with cipher "none".
func MarshalPrivate(priv ed25519.PrivateKey, comment string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	seedSum := sha256.Sum256(priv.Seed())
	check := binary.BigEndian.Uint32(seedSum[:4])

	var sec buffer
	sec.uint32(check)
	sec.uint32(check)
	sec.str([]byte(KeyType))
	sec.str(pub)
	sec.str(priv) // 64 bytes: seed || public
	sec.str([]byte(comment))
	for i := byte(1); len(sec.b)%privatePadBlock != 0; i++ {
		sec.raw([]byte{i})
	}

	var w buffer
	w.raw([]byte(privateMagic))
	w.str([]byte("none")) // ciphername
	w.str([]byte("none")) // kdfname
	w.str(nil)            // kdfoptions
	w.uint32(1)           // number of keys
	w.str(EncodePublicBlob(pub))
	w.str(sec.b)
	return armor(privateKeyLabel, 70, w.b)
}

// ParsePrivate decodes an unencrypted openssh-key-v1 Ed25519 private key
// and returns the key plus its comment. Encrypted keys and non-ed25519
// keys are rejected with descriptive errors.
func ParsePrivate(data []byte) (ed25519.PrivateKey, string, error) {
	bin, err := dearmor(privateKeyLabel, data)
	if err != nil {
		return nil, "", err
	}
	r := reader{b: bin}
	r.literal([]byte(privateMagic), "openssh-key-v1 magic")
	cipher := r.str()
	kdf := r.str()
	r.bytes() // kdfoptions
	numKeys := r.uint32()
	pubBlob := r.bytes()
	secBytes := r.bytes()
	if r.err != nil {
		return nil, "", fmt.Errorf("bad private key: %v", r.err)
	}
	if cipher != "none" || kdf != "none" {
		return nil, "", fmt.Errorf("private key is encrypted (cipher %q); botsign only reads unencrypted session keys", cipher)
	}
	if numKeys != 1 {
		return nil, "", fmt.Errorf("private key file holds %d keys (want 1)", numKeys)
	}
	pub, err := ParsePublicBlob(pubBlob)
	if err != nil {
		return nil, "", err
	}

	s := reader{b: secBytes}
	check1 := s.uint32()
	check2 := s.uint32()
	keyType := s.str()
	pubAgain := s.bytes()
	privBytes := s.bytes()
	comment := s.str()
	if s.err != nil {
		return nil, "", fmt.Errorf("bad private key section: %v", s.err)
	}
	if check1 != check2 {
		return nil, "", errors.New("private key checkint mismatch")
	}
	if keyType != KeyType {
		return nil, "", fmt.Errorf("unsupported key type %q (want %s)", keyType, KeyType)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("bad ed25519 private key length %d", len(privBytes))
	}
	priv := ed25519.PrivateKey(privBytes)
	derived := priv.Public().(ed25519.PublicKey)
	if !derived.Equal(pub) || !derived.Equal(ed25519.PublicKey(pubAgain)) {
		return nil, "", errors.New("private key does not match its embedded public key")
	}
	for i, pad := range s.rest() {
		if pad != byte(i+1) {
			return nil, "", errors.New("bad private key padding")
		}
	}
	return priv, comment, nil
}
