// allowed_signers parser tests — the format botsign both writes and
// consumes, and that a stock ssh-keygen must also accept.
package store

import (
	"strings"
	"testing"
)

const goodKeyB64 = "AAAAC3NzaC1lZDI1NTE5AAAAIDAUxdcTG95+7qDtcUcUKHgqP3xAqG0Hr7kyUgZXX6sa"

func TestParseAllowedSignerBasic(t *testing.T) {
	entry, err := ParseAllowedSigner("a@botsign.invalid,b@botsign.invalid ssh-ed25519 " + goodKeyB64)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entry.Principals) != 2 || entry.Principals[1] != "b@botsign.invalid" {
		t.Fatalf("principals = %v", entry.Principals)
	}
	if entry.KeyType != "ssh-ed25519" || len(entry.KeyBlob) == 0 {
		t.Fatalf("key not parsed: type=%q", entry.KeyType)
	}
	// No namespaces option means every namespace is permitted.
	if !entry.PermitsNamespace("git") || !entry.PermitsNamespace("file") {
		t.Fatal("entry without namespaces must permit any namespace")
	}
}

func TestParseAllowedSignerNamespaceOption(t *testing.T) {
	entry, err := ParseAllowedSigner(`a@botsign.invalid namespaces="git,tag" ssh-ed25519 ` + goodKeyB64)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !entry.PermitsNamespace("git") || !entry.PermitsNamespace("tag") || entry.PermitsNamespace("file") {
		t.Fatalf("namespaces = %v", entry.Namespaces)
	}
}

func TestParseAllowedSignerToleratesUnknownOptions(t *testing.T) {
	// valid-after etc. are legal ssh-keygen options; 0.1.0 tolerates them
	// so hand-maintained files keep working.
	entry, err := ParseAllowedSigner(`a@botsign.invalid valid-after="20260101" namespaces="git" ssh-ed25519 ` + goodKeyB64)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !entry.PermitsNamespace("git") {
		t.Fatal("namespaces option lost among unknown options")
	}
}

func TestParseAllowedSignerRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"just-a-principal",
		"a@botsign.invalid ssh-ed25519",
		"a@botsign.invalid ssh-ed25519 %%%not-base64%%%",
	} {
		if _, err := ParseAllowedSigner(line); err == nil {
			t.Fatalf("line %q must be rejected", line)
		}
	}
}

func TestParseAllowedSignersReportsLineNumbers(t *testing.T) {
	data := "# fine\na@botsign.invalid ssh-ed25519 " + goodKeyB64 + "\nbroken-line\n"
	_, err := ParseAllowedSigners([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want an error naming line 3, got %v", err)
	}
}
