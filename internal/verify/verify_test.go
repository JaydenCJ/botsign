// Audit-engine tests. Commits are assembled synthetically (payload bytes,
// real Ed25519 signature, git-style header folding) against a keystore
// with frozen time and fixed entropy, so every one of the eight statuses
// has a deterministic, offline reproduction.
package verify

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/botsign/internal/gitio"
	"github.com/JaydenCJ/botsign/internal/sshsig"
	"github.com/JaydenCJ/botsign/internal/store"
)

var frozenNow = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

type seqRand struct{ n byte }

func (s *seqRand) Read(p []byte) (int, error) {
	s.n++
	for i := range p {
		p[i] = s.n
	}
	return len(p), nil
}

// storeSeq spaces the entropy streams of separate stores apart, so a
// "foreign keystore" in a test really holds different keys. Outcomes do
// not depend on which exact keys are minted, only on their distinctness.
var storeSeq byte

func testStore(t *testing.T) *store.Store {
	t.Helper()
	storeSeq += 50
	return &store.Store{
		Root: t.TempDir(),
		Rand: &seqRand{n: storeSeq},
		Now:  func() time.Time { return frozenNow },
	}
}

// commitSpec describes a synthetic commit.
type commitSpec struct {
	name, email string
	when        time.Time
	signWith    string // session ID whose key signs; "" = unsigned
	tamper      bool   // corrupt the payload after signing
	rawSig      string // literal gpgsig value overriding signWith (e.g. a PGP block)
}

// buildCommit assembles raw commit bytes exactly as git would store them.
func buildCommit(t *testing.T, st *store.Store, spec commitSpec) *gitio.Commit {
	t.Helper()
	when := spec.when
	if when.IsZero() {
		when = frozenNow
	}
	identity := fmt.Sprintf("%s <%s> %d +0000", spec.name, spec.email, when.Unix())
	payload := "tree 2e81171448eb9f2ee3821e3d447aa6b2fe3ddba1\n" +
		"author " + identity + "\n" +
		"committer " + identity + "\n" +
		"\n" +
		"Synthetic change\n"

	sigText := spec.rawSig
	if spec.signWith != "" {
		priv, err := st.LoadPrivate(spec.signWith)
		if err != nil {
			t.Fatalf("load key %s: %v", spec.signWith, err)
		}
		armored, err := sshsig.Sign(priv, sshsig.NamespaceGit, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		sigText = strings.TrimSuffix(string(armored), "\n")
	}
	raw := payload
	if sigText != "" {
		// Fold the armor into a gpgsig header the way git does: value on
		// the header line, every following line prefixed with one space,
		// inserted after the last header (before the blank line).
		folded := "gpgsig " + strings.ReplaceAll(sigText, "\n", "\n ") + "\n"
		idx := strings.Index(raw, "\n\n")
		raw = raw[:idx+1] + folded + raw[idx+1:]
	}
	if spec.tamper {
		raw = strings.Replace(raw, "Synthetic change", "Synthetic chANge", 1)
	}
	c, err := gitio.ParseCommit("d34db33fd34db33fd34db33fd34db33fd34db33f", []byte(raw))
	if err != nil {
		t.Fatalf("ParseCommit: %v", err)
	}
	return c
}

func mustCheck(t *testing.T, st *store.Store, spec commitSpec) Result {
	t.Helper()
	res, err := Check(buildCommit(t, st, spec), st)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return res
}

func mint(t *testing.T, st *store.Store, agent string, opts store.CreateOptions) *store.Session {
	t.Helper()
	sess, err := st.Create(agent, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return sess
}

func TestCheckVerified(t *testing.T) {
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	c := buildCommit(t, st, commitSpec{name: sess.Name, email: sess.Email, signWith: sess.ID})
	res, err := Check(c, st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("status = %s (%s), want verified", res.Status, res.Detail)
	}
	if res.Session != sess.ID || res.Agent != "claude-code" {
		t.Fatalf("attribution = %s/%s", res.Session, res.Agent)
	}
	// Fixture self-check: the reconstructed payload must exclude the
	// signature header and verify against it, exactly like git's payload.
	if bytes.Contains(c.Payload, []byte("gpgsig")) {
		t.Fatal("payload still contains the signature header")
	}
	if _, err := sshsig.Verify(c.GPGSig, sshsig.NamespaceGit, c.Payload); err != nil {
		t.Fatalf("reconstructed payload does not verify: %v", err)
	}
}

func TestCheckUnmanagedHuman(t *testing.T) {
	st := testStore(t)
	mint(t, st, "claude-code", store.CreateOptions{})
	res := mustCheck(t, st, commitSpec{name: "Dev Human", email: "dev@example.test"})
	if res.Status != StatusUnmanaged || res.Session != "" {
		t.Fatalf("status = %s session=%q", res.Status, res.Session)
	}
}

func TestCheckUnsignedImpersonation(t *testing.T) {
	// Anyone can set user.email to a session identity; without the key
	// the commit must fail as unsigned.
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	res := mustCheck(t, st, commitSpec{name: sess.Name, email: sess.Email})
	if res.Status != StatusUnsigned {
		t.Fatalf("status = %s, want unsigned", res.Status)
	}
	if res.Session != sess.ID {
		t.Fatal("the claimed session must still be attributed for the audit trail")
	}
	// A botsign-domain email that matches no session record is still a
	// claim — and still fails.
	ghost := mustCheck(t, st, commitSpec{name: "ghost", email: "ghost+00000000@botsign.invalid"})
	if ghost.Status != StatusUnsigned {
		t.Fatalf("ghost status = %s, want unsigned", ghost.Status)
	}
}

func TestCheckBadSignatureOnTamperedPayload(t *testing.T) {
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	res := mustCheck(t, st, commitSpec{name: sess.Name, email: sess.Email, signWith: sess.ID, tamper: true})
	if res.Status != StatusBadSignature {
		t.Fatalf("status = %s, want bad-signature", res.Status)
	}
}

func TestCheckUnknownKeyWhenClaimed(t *testing.T) {
	// Signed by a key from another keystore while claiming an identity
	// here: cannot be attested, must fail.
	other := testStore(t)
	foreign := mint(t, other, "claude-code", store.CreateOptions{})
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	// Sign with the foreign key but keep the local identity claim.
	c := buildCommit(t, other, commitSpec{name: sess.Name, email: sess.Email, signWith: foreign.ID})
	res, err := Check(c, st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUnknownKey {
		t.Fatalf("status = %s, want unknown-key", res.Status)
	}
	if !strings.Contains(res.Detail, "SHA256:") {
		t.Fatalf("detail must name the unknown key: %q", res.Detail)
	}
}

func TestCheckUnknownKeyUnclaimedIsUnmanaged(t *testing.T) {
	// A human signing with their own personal SSH key is not botsign's
	// business unless they claim a session identity.
	other := testStore(t)
	foreign := mint(t, other, "personal", store.CreateOptions{})
	st := testStore(t)
	c := buildCommit(t, other, commitSpec{name: "Dev Human", email: "dev@example.test", signWith: foreign.ID})
	res, err := Check(c, st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUnmanaged {
		t.Fatalf("status = %s, want unmanaged", res.Status)
	}
}

func TestCheckMismatchAcrossSessions(t *testing.T) {
	// Session B's key signing under session A's identity is key reuse —
	// exactly what per-session keys exist to catch.
	st := testStore(t)
	a := mint(t, st, "agent-a", store.CreateOptions{})
	b := mint(t, st, "agent-b", store.CreateOptions{})
	res := mustCheck(t, st, commitSpec{name: a.Name, email: a.Email, signWith: b.ID})
	if res.Status != StatusMismatch {
		t.Fatalf("status = %s, want mismatch", res.Status)
	}
	if !strings.Contains(res.Detail, b.ID) {
		t.Fatalf("detail must name the actual signer: %q", res.Detail)
	}
}

func TestCheckMismatchSessionKeyUnderHumanIdentity(t *testing.T) {
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	res := mustCheck(t, st, commitSpec{name: "Dev Human", email: "dev@example.test", signWith: sess.ID})
	if res.Status != StatusMismatch {
		t.Fatalf("status = %s, want mismatch", res.Status)
	}
}

func TestCheckRevoked(t *testing.T) {
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	// Sign first, then revoke: the historical commit turns untrusted.
	c := buildCommit(t, st, commitSpec{name: sess.Name, email: sess.Email, signWith: sess.ID})
	if _, err := st.Revoke(sess.ID); err != nil {
		t.Fatal(err)
	}
	res, err := Check(c, st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusRevoked {
		t.Fatalf("status = %s, want revoked", res.Status)
	}
}

func TestCheckExpired(t *testing.T) {
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{TTL: time.Hour})
	res := mustCheck(t, st, commitSpec{
		name: sess.Name, email: sess.Email, signWith: sess.ID,
		when: frozenNow.Add(3 * time.Hour),
	})
	if res.Status != StatusExpired {
		t.Fatalf("status = %s, want expired", res.Status)
	}
	// Inside the window the same session verifies.
	res = mustCheck(t, st, commitSpec{
		name: sess.Name, email: sess.Email, signWith: sess.ID,
		when: frozenNow.Add(30 * time.Minute),
	})
	if res.Status != StatusVerified {
		t.Fatalf("in-window status = %s, want verified", res.Status)
	}
}

func TestCheckForeignSignatureFormats(t *testing.T) {
	// A PGP signature on a human commit is unmanaged; the same block on
	// a claimed identity is a bad signature.
	pgp := "-----BEGIN PGP SIGNATURE-----\nnotarealsig\n-----END PGP SIGNATURE-----"
	st := testStore(t)
	sess := mint(t, st, "claude-code", store.CreateOptions{})
	human := mustCheck(t, st, commitSpec{name: "Dev", email: "dev@example.test", rawSig: pgp})
	if human.Status != StatusUnmanaged {
		t.Fatalf("human PGP commit = %s, want unmanaged", human.Status)
	}
	claimed := mustCheck(t, st, commitSpec{name: sess.Name, email: sess.Email, rawSig: pgp})
	if claimed.Status != StatusBadSignature {
		t.Fatalf("claimed PGP commit = %s, want bad-signature", claimed.Status)
	}
}

func TestStatusFailingMatrix(t *testing.T) {
	failing := []Status{StatusUnsigned, StatusBadSignature, StatusUnknownKey, StatusMismatch, StatusRevoked, StatusExpired}
	for _, s := range failing {
		if !s.Failing(false) {
			t.Fatalf("%s must fail", s)
		}
	}
	if StatusVerified.Failing(true) {
		t.Fatal("verified never fails")
	}
	if StatusUnmanaged.Failing(false) {
		t.Fatal("unmanaged passes by default")
	}
	if !StatusUnmanaged.Failing(true) {
		t.Fatal("unmanaged fails under --require-signed")
	}
}
