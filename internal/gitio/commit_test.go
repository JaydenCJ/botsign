// Commit-object parser tests. The fixtures below are byte-exact copies of
// what `git cat-file commit` emits; the payload-reconstruction tests are
// the load-bearing ones, because a single byte of drift from what git
// signed makes every signature verify as tampered.
package gitio

import (
	"bytes"
	"strings"
	"testing"
)

const unsignedCommit = "tree 2e81171448eb9f2ee3821e3d447aa6b2fe3ddba1\n" +
	"parent 4a7d1ed414474e4033ac29ccb8653d9b18a0f2c1\n" +
	"author claude-code <claude-code+48cecea4@botsign.invalid> 1772359200 +0000\n" +
	"committer claude-code <claude-code+48cecea4@botsign.invalid> 1772359200 +0900\n" +
	"\n" +
	"Add rate limiter\n\nBody paragraph.\n"

// signedCommit is unsignedCommit with a gpgsig header folded in exactly
// the way git does it: continuation lines carry one leading space.
const signedCommit = "tree 2e81171448eb9f2ee3821e3d447aa6b2fe3ddba1\n" +
	"parent 4a7d1ed414474e4033ac29ccb8653d9b18a0f2c1\n" +
	"author claude-code <claude-code+48cecea4@botsign.invalid> 1772359200 +0000\n" +
	"committer claude-code <claude-code+48cecea4@botsign.invalid> 1772359200 +0900\n" +
	"gpgsig -----BEGIN SSH SIGNATURE-----\n" +
	" U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTk=\n" +
	" -----END SSH SIGNATURE-----\n" +
	"\n" +
	"Add rate limiter\n\nBody paragraph.\n"

func TestParseCommitBasicFields(t *testing.T) {
	c, err := ParseCommit("abc1234def", []byte(unsignedCommit))
	if err != nil {
		t.Fatalf("ParseCommit: %v", err)
	}
	if c.Author.Email != "claude-code+48cecea4@botsign.invalid" || c.Author.Name != "claude-code" {
		t.Fatalf("author = %+v", c.Author)
	}
	if c.Subject != "Add rate limiter" {
		t.Fatalf("subject = %q", c.Subject)
	}
	if c.ShortSHA() != "abc1234" {
		t.Fatalf("short sha = %q", c.ShortSHA())
	}
	if c.GPGSig != nil {
		t.Fatal("unsigned commit must have no signature")
	}
}

func TestParseCommitTimestampsAndZones(t *testing.T) {
	c, err := ParseCommit("x", []byte(unsignedCommit))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Author.When.Unix(); got != 1772359200 {
		t.Fatalf("author epoch = %d", got)
	}
	// Committer is +0900: same instant, different zone.
	if !c.Committer.When.Equal(c.Author.When) {
		t.Fatal("zones must not shift the instant")
	}
	if _, offset := c.Committer.When.Zone(); offset != 9*3600 {
		t.Fatalf("committer offset = %d, want +9h", offset)
	}
}

func TestParseCommitUnsignedPayloadIsRaw(t *testing.T) {
	c, err := ParseCommit("x", []byte(unsignedCommit))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Payload, []byte(unsignedCommit)) {
		t.Fatal("payload of an unsigned commit must be the raw object")
	}
}

func TestParseCommitExcisesGpgsigExactly(t *testing.T) {
	// The signed payload must be byte-identical to the object before git
	// inserted the gpgsig header — this equality is what makes botsign's
	// native verification agree with git's.
	c, err := ParseCommit("x", []byte(signedCommit))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Payload, []byte(unsignedCommit)) {
		t.Fatalf("payload drifted:\n%q\nwant\n%q", c.Payload, unsignedCommit)
	}
}

func TestParseCommitUnfoldsSignature(t *testing.T) {
	c, err := ParseCommit("x", []byte(signedCommit))
	if err != nil {
		t.Fatal(err)
	}
	want := "-----BEGIN SSH SIGNATURE-----\n" +
		"U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTk=\n" +
		"-----END SSH SIGNATURE-----"
	if string(c.GPGSig) != want {
		t.Fatalf("unfolded signature = %q", c.GPGSig)
	}
}

func TestParseCommitPreservesOtherMultilineHeaders(t *testing.T) {
	// A merge commit can carry a folded mergetag header; only gpgsig may
	// be excised from the payload.
	raw := strings.Replace(signedCommit,
		"gpgsig -----BEGIN SSH SIGNATURE-----\n U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTk=\n -----END SSH SIGNATURE-----\n",
		"mergetag object 4a7d1ed414474e4033ac29ccb8653d9b18a0f2c1\n type commit\n tag v1\n", 1)
	c, err := ParseCommit("x", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Payload, []byte(raw)) {
		t.Fatal("mergetag header must stay in the payload")
	}
	if c.GPGSig != nil {
		t.Fatal("no gpgsig header in this commit")
	}
}

func TestParseCommitRejectsMalformedObjects(t *testing.T) {
	if _, err := ParseCommit("x", []byte("tree abc\nauthor a <a@example.test> 1 +0000")); err == nil {
		t.Fatal("an object without a header/body separator must be rejected")
	}
	raw := "tree abc\nauthor a <a@example.test> 1772359200 +0000\n\nmsg\n"
	if _, err := ParseCommit("x", []byte(raw)); err == nil || !strings.Contains(err.Error(), "committer") {
		t.Fatalf("want a missing-committer error, got %v", err)
	}
}

func TestParseIdentityEdgeCases(t *testing.T) {
	// Names may contain parens, dots, and extra spaces; the email is
	// always the last <…> pair.
	id, err := parseIdentity("Dev Human (via tool) <dev@example.test> 1772359200 -0430")
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "Dev Human (via tool)" || id.Email != "dev@example.test" {
		t.Fatalf("identity = %+v", id)
	}
	if _, offset := id.When.Zone(); offset != -(4*3600 + 30*60) {
		t.Fatalf("offset = %d, want -4h30m", offset)
	}
	for _, bad := range []string{
		"No Email 1772359200 +0000",
		"A <a@example.test> notanumber +0000",
		"A <a@example.test> 1772359200 0900",
		"A <a@example.test> 1772359200",
	} {
		if _, err := parseIdentity(bad); err == nil {
			t.Fatalf("identity %q must be rejected", bad)
		}
	}
}
