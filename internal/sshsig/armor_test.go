// Armor tests: OpenSSH-style ASCII armor with the tolerant decoding the
// real world needs — git strips trailing newlines when folding signatures
// into headers, and forges re-wrap and CRLF-convert text in transit.
package sshsig

import (
	"bytes"
	"strings"
	"testing"
)

func TestArmorDearmorRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0xab, 0xcd, 0xef}, 100)
	armored := armor("SSH SIGNATURE", 76, data)
	back, err := dearmor("SSH SIGNATURE", armored)
	if err != nil {
		t.Fatalf("dearmor: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Fatal("round trip changed the payload")
	}
}

func TestDearmorAcceptsCRLFAndAnyWrap(t *testing.T) {
	data := []byte("payload bytes here")
	armored := string(armor("SSH SIGNATURE", 4, data)) // absurdly narrow wrap
	crlf := strings.ReplaceAll(armored, "\n", "\r\n")
	back, err := dearmor("SSH SIGNATURE", []byte(crlf))
	if err != nil {
		t.Fatalf("dearmor CRLF: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Fatal("CRLF round trip changed the payload")
	}
}

func TestDearmorToleratesMissingTrailingNewline(t *testing.T) {
	// git strips the value's final newline when folding a signature into
	// the gpgsig header; the decoder must not care.
	armored := bytes.TrimSuffix(armor("SSH SIGNATURE", 76, []byte("x")), []byte("\n"))
	if _, err := dearmor("SSH SIGNATURE", armored); err != nil {
		t.Fatalf("dearmor without trailing newline: %v", err)
	}
}

func TestDearmorRejectsWrongLabel(t *testing.T) {
	armored := armor("OPENSSH PRIVATE KEY", 70, []byte("x"))
	if _, err := dearmor("SSH SIGNATURE", armored); err == nil {
		t.Fatal("a private key block must not decode as a signature")
	}
}

func TestDearmorRejectsMalformedBlocks(t *testing.T) {
	whole := string(armor("SSH SIGNATURE", 76, []byte("x")))
	for name, input := range map[string]string{
		"missing header": strings.SplitN(whole, "\n", 2)[1],
		"missing footer": strings.SplitN(whole, "-----END", 2)[0],
		"bad base64":     "-----BEGIN SSH SIGNATURE-----\nnot*base64*at*all\n-----END SSH SIGNATURE-----\n",
	} {
		if _, err := dearmor("SSH SIGNATURE", []byte(input)); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}
