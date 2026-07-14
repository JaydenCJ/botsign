package sshsig

// sshsig.go implements the SSHSIG detached-signature format that
// `ssh-keygen -Y sign` produces and git embeds in commit `gpgsig` headers
// when gpg.format=ssh. The format is specified in OpenSSH's
// PROTOCOL.sshsig: the signature covers a fixed preamble, the namespace,
// the hash algorithm, and a digest of the message — never the raw message
// — so large payloads are hashed exactly once.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

const (
	signatureLabel = "SSH SIGNATURE"
	sigMagic       = "SSHSIG"
	sigVersion     = 1

	// NamespaceGit is the namespace git uses for commit and tag signatures.
	NamespaceGit = "git"

	// defaultHash matches ssh-keygen's default, so botsign signatures stay
	// verifiable with a stock `ssh-keygen -Y verify`.
	defaultHash = "sha512"
)

// Signature is a decoded SSHSIG envelope.
type Signature struct {
	PublicKey ed25519.PublicKey
	Namespace string
	HashAlg   string
	Sig       []byte // raw 64-byte ed25519 signature
}

// hashMessage applies the envelope's hash algorithm to the message.
func hashMessage(alg string, message []byte) ([]byte, error) {
	switch alg {
	case "sha256":
		sum := sha256.Sum256(message)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(message)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q (want sha256 or sha512)", alg)
	}
}

// signedData renders the blob that is actually signed, per PROTOCOL.sshsig.
func signedData(namespace, hashAlg string, digest []byte) []byte {
	var w buffer
	w.raw([]byte(sigMagic))
	w.str([]byte(namespace))
	w.str(nil) // reserved
	w.str([]byte(hashAlg))
	w.str(digest)
	return w.b
}

// Sign produces an armored SSHSIG signature over message in the given
// namespace, using ssh-keygen's default sha512 pre-hash.
func Sign(priv ed25519.PrivateKey, namespace string, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, errors.New("signature namespace must not be empty")
	}
	digest, err := hashMessage(defaultHash, message)
	if err != nil {
		return nil, err
	}
	rawSig := ed25519.Sign(priv, signedData(namespace, defaultHash, digest))

	var sigBlob buffer
	sigBlob.str([]byte(KeyType))
	sigBlob.str(rawSig)

	var w buffer
	w.raw([]byte(sigMagic))
	w.uint32(sigVersion)
	w.str(EncodePublicBlob(priv.Public().(ed25519.PublicKey)))
	w.str([]byte(namespace))
	w.str(nil) // reserved
	w.str([]byte(defaultHash))
	w.str(sigBlob.b)
	return armor(signatureLabel, 76, w.b), nil
}

// Decode parses an armored SSHSIG envelope without checking the signature.
// Use it to discover which key claims to have signed before deciding
// whether that key is trusted; Verify does the cryptographic check.
func Decode(armored []byte) (*Signature, error) {
	bin, err := dearmor(signatureLabel, armored)
	if err != nil {
		return nil, err
	}
	r := reader{b: bin}
	r.literal([]byte(sigMagic), "SSHSIG magic")
	version := r.uint32()
	pubBlob := r.bytes()
	namespace := r.str()
	r.bytes() // reserved
	hashAlg := r.str()
	sigBlob := r.bytes()
	if r.err != nil {
		return nil, fmt.Errorf("bad SSHSIG envelope: %v", r.err)
	}
	if version != sigVersion {
		return nil, fmt.Errorf("unsupported SSHSIG version %d (want %d)", version, sigVersion)
	}
	pub, err := ParsePublicBlob(pubBlob)
	if err != nil {
		return nil, err
	}

	s := reader{b: sigBlob}
	sigType := s.str()
	rawSig := s.bytes()
	if s.err != nil {
		return nil, fmt.Errorf("bad SSHSIG signature blob: %v", s.err)
	}
	if sigType != KeyType {
		return nil, fmt.Errorf("unsupported signature algorithm %q (want %s)", sigType, KeyType)
	}
	if len(rawSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("bad ed25519 signature length %d", len(rawSig))
	}
	return &Signature{
		PublicKey: pub,
		Namespace: namespace,
		HashAlg:   hashAlg,
		Sig:       rawSig,
	}, nil
}

// Verify checks an armored SSHSIG signature over message in the given
// namespace and returns the signing public key on success. The namespace
// must match exactly: a signature minted for "file" must never validate a
// git commit.
func Verify(armored []byte, namespace string, message []byte) (ed25519.PublicKey, error) {
	sig, err := Decode(armored)
	if err != nil {
		return nil, err
	}
	if sig.Namespace != namespace {
		return nil, fmt.Errorf("signature namespace is %q, want %q", sig.Namespace, namespace)
	}
	digest, err := hashMessage(sig.HashAlg, message)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(sig.PublicKey, signedData(sig.Namespace, sig.HashAlg, digest), sig.Sig) {
		return nil, errors.New("signature does not verify against its embedded public key")
	}
	return sig.PublicKey, nil
}
