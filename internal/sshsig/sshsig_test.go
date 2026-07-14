// SSHSIG envelope tests. The layout is pinned field by field against
// OpenSSH's PROTOCOL.sshsig so signatures stay verifiable with a stock
// `ssh-keygen -Y verify`, and every rejection path (wrong namespace,
// tampered payload, tampered signature, spliced key) is exercised.
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"strings"
	"testing"
)

const testMessage = "tree 0000000000000000000000000000000000000000\n\ncommit body\n"

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(armored, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("Verify returned a different public key than the signer")
	}
}

func TestSignRejectsEmptyNamespace(t *testing.T) {
	_, priv := testKey(t, 1)
	if _, err := Sign(priv, "", []byte("x")); err == nil {
		t.Fatal("empty namespace must be rejected — ssh-keygen requires one too")
	}
}

func TestVerifyRejectsWrongNamespace(t *testing.T) {
	// A signature minted for the "file" namespace must never validate a
	// git commit; namespace separation is the whole point of SSHSIG.
	_, priv := testKey(t, 1)
	armored, err := Sign(priv, "file", []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(armored, NamespaceGit, []byte(testMessage)); err == nil {
		t.Fatal("cross-namespace signature must be rejected")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	_, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(testMessage, "commit body", "commit b0dy", 1)
	if _, err := Verify(armored, NamespaceGit, []byte(tampered)); err == nil {
		t.Fatal("tampered message must not verify")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	_, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := dearmor(signatureLabel, armored)
	if err != nil {
		t.Fatal(err)
	}
	bin[len(bin)-1] ^= 0x01 // flip a bit in the raw ed25519 signature
	if _, err := Verify(armor(signatureLabel, 76, bin), NamespaceGit, []byte(testMessage)); err == nil {
		t.Fatal("bit-flipped signature must not verify")
	}
}

func TestVerifyRejectsSplicedPublicKey(t *testing.T) {
	// Replace the embedded public key with another session's key: the
	// signature must stop verifying, otherwise identity could be reassigned.
	pubA, privA := testKey(t, 1)
	pubB, _ := testKey(t, 2)
	armored, err := Sign(privA, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := dearmor(signatureLabel, armored)
	if err != nil {
		t.Fatal(err)
	}
	spliced := bytes.Replace(bin, []byte(pubA), []byte(pubB), 1)
	if _, err := Verify(armor(signatureLabel, 76, spliced), NamespaceGit, []byte(testMessage)); err == nil {
		t.Fatal("spliced public key must not verify")
	}
}

func TestDecodeExposesEnvelopeFields(t *testing.T) {
	pub, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Decode(armored)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !sig.PublicKey.Equal(pub) || sig.Namespace != "git" || sig.HashAlg != "sha512" || len(sig.Sig) != 64 {
		t.Fatalf("bad envelope: ns=%q hash=%q siglen=%d", sig.Namespace, sig.HashAlg, len(sig.Sig))
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	_, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := dearmor(signatureLabel, armored)
	if err != nil {
		t.Fatal(err)
	}
	bin[len(sigMagic)+3] = 9 // version field follows the 6-byte magic
	if _, err := Decode(armor(signatureLabel, 76, bin)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("want a version error, got %v", err)
	}
}

func TestVerifyRejectsUnknownHashAlgorithm(t *testing.T) {
	// Hand-build an envelope claiming an "md5" pre-hash. Decode accepts
	// the container (the field is opaque there); Verify must refuse it.
	pub, _ := testKey(t, 1)
	var sigBlob buffer
	sigBlob.str([]byte(KeyType))
	sigBlob.str(bytes.Repeat([]byte{0}, 64))
	var w buffer
	w.raw([]byte(sigMagic))
	w.uint32(sigVersion)
	w.str(EncodePublicBlob(pub))
	w.str([]byte(NamespaceGit))
	w.str(nil)
	w.str([]byte("md5"))
	w.str(sigBlob.b)
	_, err := Verify(armor(signatureLabel, 76, w.b), NamespaceGit, []byte(testMessage))
	if err == nil || !strings.Contains(err.Error(), "md5") {
		t.Fatalf("want an unsupported-hash error naming md5, got %v", err)
	}
}

func TestVerifyAcceptsSha256Envelope(t *testing.T) {
	// ssh-keygen can be told to pre-hash with sha256 (-Ohashalg=sha256);
	// botsign always signs sha512 but must verify both. Hand-assemble the
	// envelope a foreign ssh-keygen would produce.
	pub, priv := testKey(t, 1)
	digest, err := hashMessage("sha256", []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	rawSig := ed25519.Sign(priv, signedData(NamespaceGit, "sha256", digest))
	var sigBlob buffer
	sigBlob.str([]byte(KeyType))
	sigBlob.str(rawSig)
	var w buffer
	w.raw([]byte(sigMagic))
	w.uint32(sigVersion)
	w.str(EncodePublicBlob(pub))
	w.str([]byte(NamespaceGit))
	w.str(nil)
	w.str([]byte("sha256"))
	w.str(sigBlob.b)

	got, err := Verify(armor(signatureLabel, 76, w.b), NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatalf("sha256 envelope: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("wrong key returned")
	}
}

func TestSignedDataLayoutIsPinned(t *testing.T) {
	// The blob that is actually signed, per PROTOCOL.sshsig: magic,
	// namespace, reserved, hash name, digest — each length-prefixed
	// except the magic. Pinning the exact bytes guards interop.
	digest := sha512.Sum512([]byte("m"))
	got := signedData("git", "sha512", digest[:])
	want := append([]byte("SSHSIG"),
		0, 0, 0, 3, 'g', 'i', 't',
		0, 0, 0, 0,
		0, 0, 0, 6, 's', 'h', 'a', '5', '1', '2',
		0, 0, 0, 64)
	want = append(want, digest[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed-data layout drifted:\n got %x\nwant %x", got, want)
	}
}

func TestArmoredSignatureShape(t *testing.T) {
	_, priv := testKey(t, 1)
	armored, err := Sign(priv, NamespaceGit, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	text := string(armored)
	if !strings.HasPrefix(text, "-----BEGIN SSH SIGNATURE-----\n") ||
		!strings.HasSuffix(text, "-----END SSH SIGNATURE-----\n") {
		t.Fatalf("bad armor frame:\n%s", text)
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if len(line) > 76 {
			t.Fatalf("armor line exceeds 76 chars: %q", line)
		}
	}
}
