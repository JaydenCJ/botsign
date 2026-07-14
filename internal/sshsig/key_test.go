// Key-format tests: authorized_keys public lines and the openssh-key-v1
// private container. Keys are generated from fixed entropy so every
// expected value below is stable across runs and machines.
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

// testKey mints a deterministic keypair; tag varies the seed.
func testKey(t *testing.T, tag byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{tag}, ed25519.SeedSize)
	pub, priv, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestPublicBlobRoundTrip(t *testing.T) {
	pub, _ := testKey(t, 1)
	back, err := ParsePublicBlob(EncodePublicBlob(pub))
	if err != nil {
		t.Fatalf("ParsePublicBlob: %v", err)
	}
	if !back.Equal(pub) {
		t.Fatal("round trip changed the key")
	}
}

func TestParsePublicBlobRejectsMalformed(t *testing.T) {
	var rsa buffer
	rsa.str([]byte("ssh-rsa"))
	rsa.str(bytes.Repeat([]byte{1}, 32))
	if _, err := ParsePublicBlob(rsa.b); err == nil || !strings.Contains(err.Error(), "ssh-rsa") {
		t.Fatalf("want an unsupported-type error naming ssh-rsa, got %v", err)
	}
	pub, _ := testKey(t, 1)
	if _, err := ParsePublicBlob(append(EncodePublicBlob(pub), 0x00)); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
	if _, err := ParsePublicBlob([]byte{0, 0}); err == nil {
		t.Fatal("truncated blob must be rejected")
	}
}

func TestAuthorizedLineRoundTrip(t *testing.T) {
	pub, _ := testKey(t, 3)
	line := MarshalAuthorized(pub, "botsign:demo-12345678")
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "ssh-ed25519" || fields[2] != "botsign:demo-12345678" {
		t.Fatalf("bad authorized_keys line shape: %q", line)
	}
	back, comment, err := ParseAuthorized(line)
	if err != nil {
		t.Fatalf("ParseAuthorized: %v", err)
	}
	if !back.Equal(pub) || comment != "botsign:demo-12345678" {
		t.Fatalf("round trip lost data: comment=%q", comment)
	}
}

func TestParseAuthorizedRejectsGarbage(t *testing.T) {
	for _, line := range []string{
		"",
		"ssh-ed25519",
		"ssh-rsa AAAAB3NzaC1yc2E=",
		"ssh-ed25519 !!!not-base64!!!",
	} {
		if _, _, err := ParseAuthorized(line); err == nil {
			t.Fatalf("line %q must be rejected", line)
		}
	}
}

func TestFingerprintIsStableAndWellFormed(t *testing.T) {
	pub, _ := testKey(t, 1)
	fp := Fingerprint(pub)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint %q lacks the SHA256: prefix", fp)
	}
	// 32 digest bytes → 43 chars of unpadded base64.
	if got := len(strings.TrimPrefix(fp, "SHA256:")); got != 43 {
		t.Fatalf("fingerprint body is %d chars, want 43", got)
	}
	if fp != Fingerprint(pub) {
		t.Fatal("fingerprint must be deterministic")
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	_, priv := testKey(t, 4)
	pem := MarshalPrivate(priv, "botsign:test-comment")
	back, comment, err := ParsePrivate(pem)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	if !back.Equal(priv) {
		t.Fatal("round trip changed the private key")
	}
	if comment != "botsign:test-comment" {
		t.Fatalf("comment = %q", comment)
	}
}

func TestPrivateKeyMarshalIsDeterministic(t *testing.T) {
	// The checkint is derived from the seed rather than random, so two
	// marshals of one key are byte-identical — keystore writes are
	// reproducible and diffable.
	_, priv := testKey(t, 4)
	if !bytes.Equal(MarshalPrivate(priv, "c"), MarshalPrivate(priv, "c")) {
		t.Fatal("marshalling must be deterministic")
	}
}

func TestParsePrivateRejectsEncryptedKeys(t *testing.T) {
	_, priv := testKey(t, 5)
	pem := MarshalPrivate(priv, "")
	bin, err := dearmor(privateKeyLabel, pem)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite ciphername "none" → "aes1" in place (same length keeps all
	// downstream offsets valid).
	tampered := bytes.Replace(bin, []byte("\x00\x00\x00\x04none"), []byte("\x00\x00\x00\x04aes1"), 1)
	_, _, err = ParsePrivate(armor(privateKeyLabel, 70, tampered))
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("want an encrypted-key error, got %v", err)
	}
}

func TestParsePrivateRejectsBadMagic(t *testing.T) {
	bad := armor(privateKeyLabel, 70, []byte("not-openssh-key-v1 data"))
	if _, _, err := ParsePrivate(bad); err == nil {
		t.Fatal("bad magic must be rejected")
	}
}

func TestParsePrivateRejectsCheckintMismatch(t *testing.T) {
	_, priv := testKey(t, 6)
	pub := priv.Public().(ed25519.PublicKey)

	var sec buffer
	sec.uint32(1)
	sec.uint32(2) // deliberately different
	sec.str([]byte(KeyType))
	sec.str(pub)
	sec.str(priv)
	sec.str(nil)
	for i := byte(1); len(sec.b)%privatePadBlock != 0; i++ {
		sec.raw([]byte{i})
	}
	var w buffer
	w.raw([]byte(privateMagic))
	w.str([]byte("none"))
	w.str([]byte("none"))
	w.str(nil)
	w.uint32(1)
	w.str(EncodePublicBlob(pub))
	w.str(sec.b)

	_, _, err := ParsePrivate(armor(privateKeyLabel, 70, w.b))
	if err == nil || !strings.Contains(err.Error(), "checkint") {
		t.Fatalf("want a checkint error, got %v", err)
	}
}

func TestParsePrivateRejectsForeignPublicKey(t *testing.T) {
	// A container whose outer public key does not match the embedded
	// private key is corrupt or spliced; it must not parse.
	_, privA := testKey(t, 7)
	pubB, _ := testKey(t, 8)
	pem := MarshalPrivate(privA, "")
	bin, err := dearmor(privateKeyLabel, pem)
	if err != nil {
		t.Fatal(err)
	}
	pubA := privA.Public().(ed25519.PublicKey)
	tampered := bytes.Replace(bin, []byte(pubA), []byte(pubB), 1)
	if _, _, err := ParsePrivate(armor(privateKeyLabel, 70, tampered)); err == nil {
		t.Fatal("spliced public key must be rejected")
	}
}
