// Keystore tests. Every store gets a temp root, a frozen clock, and a
// fixed entropy stream, so session IDs, fingerprints, and file contents
// are identical on every run.
package store

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/botsign/internal/sshsig"
)

// countingRand hands out a distinct deterministic 32-byte seed per key.
type countingRand struct{ n byte }

func (c *countingRand) Read(p []byte) (int, error) {
	c.n++
	for i := range p {
		p[i] = c.n
	}
	return len(p), nil
}

// newStore builds a deterministic store: clock frozen at epoch+1000h,
// advancing one minute per Create so List ordering is well-defined.
func newStore(t *testing.T) *Store {
	t.Helper()
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	tick := 0
	return &Store{
		Root: t.TempDir(),
		Rand: &countingRand{},
		Now: func() time.Time {
			tick++
			return base.Add(time.Duration(tick) * time.Minute)
		},
	}
}

func TestCreateDerivesIDFromKey(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("claude-code", CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(sess.ID, "claude-code-") {
		t.Fatalf("bad session ID %q", sess.ID)
	}
	suffix := strings.TrimPrefix(sess.ID, "claude-code-")
	if len(suffix) != 8 {
		t.Fatalf("ID suffix %q is not 8 hex chars", suffix)
	}
	// The suffix is bound to the key: re-derive it from the public key.
	pub, _, err := sshsig.ParseAuthorized(sess.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := shortID(sshsig.EncodePublicBlob(pub)); suffix != want {
		t.Fatalf("ID suffix %s does not derive from the key (%s)", suffix, want)
	}
	// Default identity follows from the ID.
	if sess.Name != "claude-code" {
		t.Fatalf("name = %q", sess.Name)
	}
	if want := "claude-code+" + suffix + "@botsign.invalid"; sess.Email != want {
		t.Fatalf("email = %q, want %q", sess.Email, want)
	}
	if sess.Expires != nil || sess.Revoked != nil || sess.Imported {
		t.Fatal("a plain session must be live, unexpiring, and local")
	}
}

func TestCreateHonorsOverridesAndTTL(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("Helper Bot", CreateOptions{
		Name:  "helper-bot (session)",
		Email: "bots@example.test",
		TTL:   8 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Agent != "helper-bot" {
		t.Fatalf("agent = %q, want normalized helper-bot", sess.Agent)
	}
	if sess.Name != "helper-bot (session)" || sess.Email != "bots@example.test" {
		t.Fatalf("overrides lost: %q %q", sess.Name, sess.Email)
	}
	if sess.Expires == nil || !sess.Expires.Equal(sess.Created.Add(8*time.Hour)) {
		t.Fatalf("expires = %v, want created+8h", sess.Expires)
	}
}

func TestCreateRejectsInvalidAgents(t *testing.T) {
	st := newStore(t)
	for _, agent := range []string{"", "-lead", "über-agent", strings.Repeat("a", 40)} {
		if _, err := st.Create(agent, CreateOptions{}); err == nil {
			t.Fatalf("agent %q must be rejected", agent)
		}
	}
}

func TestNormalizeAgentMapsSeparators(t *testing.T) {
	got, err := NormalizeAgent("Claude Code_v2.local")
	if err != nil {
		t.Fatal(err)
	}
	if got != "claude-code-v2-local" {
		t.Fatalf("normalized to %q", got)
	}
}

func TestPrivateKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(st.KeyPath(sess.ID))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key mode = %o, want 600", perm)
	}
	// And the key file lives exactly where attach points git at.
	if want := filepath.Join(st.Root, "keys", sess.ID); st.KeyPath(sess.ID) != want {
		t.Fatalf("KeyPath = %q, want %q", st.KeyPath(sess.ID), want)
	}
}

func TestGetUnknownSessionFails(t *testing.T) {
	st := newStore(t)
	if _, err := st.Get("nobody-00000000"); err == nil || !strings.Contains(err.Error(), "unknown session") {
		t.Fatalf("want an unknown-session error, got %v", err)
	}
}

func TestListSortsByCreationThenID(t *testing.T) {
	st := newStore(t)
	// Created in this order; the frozen clock advances a minute per mint.
	for _, agent := range []string{"zeta", "alpha", "mid"} {
		if _, err := st.Create(agent, CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	var agents []string
	for _, s := range sessions {
		agents = append(agents, s.Agent)
	}
	if strings.Join(agents, ",") != "zeta,alpha,mid" {
		t.Fatalf("order = %v, want creation order", agents)
	}
}

func TestRevokeShredsKeyAndAllowedSigners(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Revoke(sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := os.Stat(st.KeyPath(sess.ID)); !os.IsNotExist(err) {
		t.Fatal("private key must be deleted on revoke")
	}
	signers, err := os.ReadFile(st.AllowedSignersPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(signers, []byte(sess.Email)) {
		t.Fatal("revoked session must leave allowed_signers")
	}
	if _, err := st.LoadPrivate(sess.ID); err == nil {
		t.Fatal("LoadPrivate after revoke must fail")
	}
	if _, err := st.Revoke(sess.ID); err == nil || !strings.Contains(err.Error(), "already revoked") {
		t.Fatalf("double revoke: %v", err)
	}
}

func TestSessionStatusLifecycle(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if got := sess.Status(sess.Created.Add(time.Minute)); got != "active" {
		t.Fatalf("fresh session status = %q", got)
	}
	if got := sess.Status(sess.Created.Add(2 * time.Hour)); got != "expired" {
		t.Fatalf("aged session status = %q", got)
	}
	revoked, err := st.Revoke(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Revocation dominates expiry.
	if got := revoked.Status(sess.Created.Add(2 * time.Hour)); got != "revoked" {
		t.Fatalf("revoked session status = %q", got)
	}
}

func TestExportLineIsValidAllowedSigner(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	line := ExportLine(sess)
	entry, err := ParseAllowedSigner(line)
	if err != nil {
		t.Fatalf("export line does not re-parse: %v", err)
	}
	if len(entry.Principals) != 1 || entry.Principals[0] != sess.Email {
		t.Fatalf("principals = %v", entry.Principals)
	}
	if !entry.PermitsNamespace("git") || entry.PermitsNamespace("file") {
		t.Fatal("export line must be scoped to the git namespace")
	}
}

func TestImportRoundTrip(t *testing.T) {
	src := newStore(t)
	sess, err := src.Create("claude-code", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dst := newStore(t)
	imported, err := dst.Import([]byte("# a comment\n\n" + ExportLine(sess) + "\n"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(imported) != 1 || imported[0].ID != sess.ID || !imported[0].Imported {
		t.Fatalf("imported = %+v", imported)
	}
	// The imported record resolves lookups exactly like a local one.
	pub, _, err := sshsig.ParseAuthorized(sess.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	found, err := dst.FindByPublicKey(sshsig.EncodePublicBlob(pub))
	if err != nil || found == nil || found.ID != sess.ID {
		t.Fatalf("FindByPublicKey after import: %v %v", found, err)
	}
	if _, err := dst.LoadPrivate(sess.ID); err == nil {
		t.Fatal("imported sessions must have no private key")
	}
}

func TestImportRejectsTamperedPrincipal(t *testing.T) {
	// Renaming the principal's ID suffix breaks the key↔ID binding; the
	// import must refuse, or one agent could claim another's session.
	src := newStore(t)
	sess, err := src.Create("claude-code", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.TrimPrefix(sess.ID, "claude-code-")
	forged := strings.Replace(ExportLine(sess), suffix, "deadbeef", 1)
	dst := newStore(t)
	if _, err := dst.Import([]byte(forged)); err == nil || !strings.Contains(err.Error(), "does not match its key") {
		t.Fatalf("want a binding error, got %v", err)
	}
}

func TestImportRejectsForeignAndDuplicate(t *testing.T) {
	src := newStore(t)
	sess, err := src.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dst := newStore(t)
	if _, err := dst.Import([]byte("dev@example.test namespaces=\"git\" ssh-ed25519 " + sess.KeyB64())); err == nil {
		t.Fatal("non-botsign principals must be rejected")
	}
	if _, err := dst.Import([]byte(ExportLine(sess))); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Import([]byte(ExportLine(sess))); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate import: %v", err)
	}
	if _, err := dst.Import([]byte("# only comments\n")); err == nil {
		t.Fatal("an input with no signer lines must be an error")
	}
}

func TestFindByEmailIsCaseInsensitive(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found, err := st.FindByEmail(strings.ToUpper(sess.Email))
	if err != nil || found == nil || found.ID != sess.ID {
		t.Fatalf("FindByEmail: %v %v", found, err)
	}
	miss, err := st.FindByEmail("nobody@example.test")
	if err != nil || miss != nil {
		t.Fatalf("miss = %v %v", miss, err)
	}
}

func TestAllowedSignersListsEveryLiveSession(t *testing.T) {
	st := newStore(t)
	a, err := st.Create("agent-a", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Create("agent-b", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(st.AllowedSignersPath())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseAllowedSigners(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("allowed_signers has %d entries, want 2", len(entries))
	}
	if entries[0].Principals[0] != a.Email || entries[1].Principals[0] != b.Email {
		t.Fatalf("allowed_signers order/content wrong: %v %v", entries[0].Principals, entries[1].Principals)
	}
}

func TestIsManagedEmail(t *testing.T) {
	if !IsManagedEmail("claude-code+12ab34cd@botsign.invalid") {
		t.Fatal("minted identity must be managed")
	}
	if !IsManagedEmail("X+Y@BOTSIGN.INVALID") {
		t.Fatal("domain matching must be case-insensitive")
	}
	if IsManagedEmail("dev@example.test") || IsManagedEmail("a@botsign.invalid.example.test") {
		t.Fatal("foreign domains must not be managed")
	}
}

func TestLoadPrivateMatchesPublic(t *testing.T) {
	st := newStore(t)
	sess, err := st.Create("agent", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	priv, err := st.LoadPrivate(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshsig.ParseAuthorized(sess.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("stored private key does not match the session public key")
	}
}
