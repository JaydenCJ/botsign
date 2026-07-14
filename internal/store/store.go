// Package store is botsign's on-disk keystore: one JSON record plus an
// OpenSSH keypair per agent session, and a regenerated allowed_signers
// file that both `git verify-commit` and teammates' ssh-keygen can consume.
// The layout under Root is:
//
//	sessions/<id>.json   session metadata (agent, identity, timestamps)
//	keys/<id>            unencrypted OpenSSH private key, mode 0600
//	keys/<id>.pub        authorized_keys-style public key line
//	allowed_signers      one line per non-revoked session
package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/botsign/internal/sshsig"
)

// EmailDomain is the reserved domain botsign session identities live
// under. RFC 2606 guarantees `.invalid` never resolves, so a session email
// can never receive mail or collide with a real account.
const EmailDomain = "botsign.invalid"

// Session is one minted (or imported) agent signing identity.
type Session struct {
	ID          string     `json:"id"`
	Agent       string     `json:"agent"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	PublicKey   string     `json:"public_key"` // authorized_keys line incl. comment
	Fingerprint string     `json:"fingerprint"`
	Created     time.Time  `json:"created"`
	Expires     *time.Time `json:"expires,omitempty"`
	Revoked     *time.Time `json:"revoked,omitempty"`
	Imported    bool       `json:"imported,omitempty"`
}

// Status summarizes a session's lifecycle for listings: active, expired,
// or revoked (revocation wins over expiry).
func (s *Session) Status(now time.Time) string {
	switch {
	case s.Revoked != nil:
		return "revoked"
	case s.Expires != nil && now.After(*s.Expires):
		return "expired"
	default:
		return "active"
	}
}

// KeyB64 returns the bare base64 key material from the stored public key
// line (field two of the authorized_keys format).
func (s *Session) KeyB64() string {
	fields := strings.Fields(s.PublicKey)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// Store reads and writes a keystore rooted at Root. Now and Rand are
// injectable for deterministic tests; the zero values fall back to
// time.Now and crypto/rand.
type Store struct {
	Root string
	Now  func() time.Time
	Rand io.Reader
}

func (st *Store) now() time.Time {
	if st.Now != nil {
		return st.Now().UTC()
	}
	return time.Now().UTC()
}

func (st *Store) rand() io.Reader {
	if st.Rand != nil {
		return st.Rand
	}
	return rand.Reader
}

func (st *Store) sessionPath(id string) string {
	return filepath.Join(st.Root, "sessions", id+".json")
}

// KeyPath returns the private key location for a session; this exact path
// is written into `user.signingKey` when a repo is attached.
func (st *Store) KeyPath(id string) string {
	return filepath.Join(st.Root, "keys", id)
}

// AllowedSignersPath returns the aggregated principals file consumed by
// `git verify-commit` via gpg.ssh.allowedSignersFile.
func (st *Store) AllowedSignersPath() string {
	return filepath.Join(st.Root, "allowed_signers")
}

// agentPattern is the shape an agent name must normalize into: DNS-label
// style, so it embeds cleanly in emails, file names, and git config.
var agentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// NormalizeAgent lowercases an agent name and maps spaces, dots, and
// underscores to hyphens, then validates the result.
func NormalizeAgent(agent string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(agent))
	norm = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '.', '_', '/':
			return '-'
		}
		return r
	}, norm)
	if !agentPattern.MatchString(norm) {
		return "", fmt.Errorf("invalid agent name %q: need 1-32 chars of [a-z0-9-] after normalization, starting alphanumeric", agent)
	}
	return norm, nil
}

// shortID derives the 8-hex-char session suffix from a public key blob.
// It is a prefix of the same SHA256 digest the fingerprint shows, so a
// session ID is cryptographically bound to its key: imports re-derive it
// and refuse records whose ID and key disagree.
func shortID(pubBlob []byte) string {
	sum := sha256.Sum256(pubBlob)
	return hex.EncodeToString(sum[:4])
}

// IsManagedEmail reports whether an email claims a botsign identity.
func IsManagedEmail(email string) bool {
	return strings.HasSuffix(strings.ToLower(email), "@"+EmailDomain)
}

// CreateOptions tune Create; the zero value mints a plain session.
type CreateOptions struct {
	Name  string        // git user.name override; defaults to the agent
	Email string        // git user.email override; defaults to <agent>+<id8>@botsign.invalid
	TTL   time.Duration // >0 sets an expiry relative to creation
}

// Create mints a new session: keypair, identity, on-disk records, and a
// refreshed allowed_signers file.
func (st *Store) Create(agent string, opts CreateOptions) (*Session, error) {
	norm, err := NormalizeAgent(agent)
	if err != nil {
		return nil, err
	}
	pub, priv, err := sshsig.GenerateKey(st.rand())
	if err != nil {
		return nil, err
	}
	id8 := shortID(sshsig.EncodePublicBlob(pub))
	id := norm + "-" + id8

	now := st.now().Truncate(time.Second)
	sess := &Session{
		ID:          id,
		Agent:       norm,
		Name:        opts.Name,
		Email:       opts.Email,
		PublicKey:   sshsig.MarshalAuthorized(pub, "botsign:"+id),
		Fingerprint: sshsig.Fingerprint(pub),
		Created:     now,
	}
	if sess.Name == "" {
		sess.Name = norm
	}
	if sess.Email == "" {
		sess.Email = fmt.Sprintf("%s+%s@%s", norm, id8, EmailDomain)
	}
	if opts.TTL > 0 {
		exp := now.Add(opts.TTL)
		sess.Expires = &exp
	}

	if _, err := os.Stat(st.sessionPath(id)); err == nil {
		return nil, fmt.Errorf("session %s already exists", id)
	}
	if err := os.MkdirAll(filepath.Join(st.Root, "keys"), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(st.KeyPath(id), sshsig.MarshalPrivate(priv, "botsign:"+id), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(st.KeyPath(id)+".pub", []byte(sess.PublicKey+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := st.save(sess); err != nil {
		return nil, err
	}
	return sess, st.WriteAllowedSigners()
}

func (st *Store) save(sess *Session) error {
	if err := os.MkdirAll(filepath.Join(st.Root, "sessions"), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(st.sessionPath(sess.ID), append(data, '\n'), 0o644)
}

// Get loads one session by ID.
func (st *Store) Get(id string) (*Session, error) {
	data, err := os.ReadFile(st.sessionPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("unknown session %q (see `botsign sessions`)", id)
	}
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("corrupt session record %s: %v", st.sessionPath(id), err)
	}
	return &sess, nil
}

// List returns every session, sorted by creation time then ID so output
// is stable across runs.
func (st *Store) List() ([]*Session, error) {
	entries, err := os.ReadDir(filepath.Join(st.Root, "sessions"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sessions []*Session
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		sess, err := st.Get(name)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].Created.Equal(sessions[j].Created) {
			return sessions[i].Created.Before(sessions[j].Created)
		}
		return sessions[i].ID < sessions[j].ID
	})
	return sessions, nil
}

// Revoke marks a session revoked, shreds its private key, and drops it
// from allowed_signers. Verification of commits it signed fails from now
// on — revocation is a statement that the session is no longer trusted.
func (st *Store) Revoke(id string) (*Session, error) {
	sess, err := st.Get(id)
	if err != nil {
		return nil, err
	}
	if sess.Revoked != nil {
		return nil, fmt.Errorf("session %s was already revoked at %s", id, sess.Revoked.Format(time.RFC3339))
	}
	now := st.now().Truncate(time.Second)
	sess.Revoked = &now
	if err := os.Remove(st.KeyPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := st.save(sess); err != nil {
		return nil, err
	}
	return sess, st.WriteAllowedSigners()
}

// LoadPrivate reads and decodes a session's private key.
func (st *Store) LoadPrivate(id string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(st.KeyPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no private key for session %q (revoked or imported?)", id)
	}
	if err != nil {
		return nil, err
	}
	priv, _, err := sshsig.ParsePrivate(data)
	return priv, err
}

// FindByPublicKey resolves a raw public key blob to the session that owns
// it, or nil if no session matches.
func (st *Store) FindByPublicKey(blob []byte) (*Session, error) {
	want := base64.StdEncoding.EncodeToString(blob)
	sessions, err := st.List()
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		if sess.KeyB64() == want {
			return sess, nil
		}
	}
	return nil, nil
}

// FindByEmail resolves a committer email to its session, or nil.
func (st *Store) FindByEmail(email string) (*Session, error) {
	sessions, err := st.List()
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		if strings.EqualFold(sess.Email, email) {
			return sess, nil
		}
	}
	return nil, nil
}

// ExportLine renders one session as an ssh-keygen allowed_signers line:
// `<principal> namespaces="git" ssh-ed25519 <base64>`. The same line is
// what `botsign import` consumes, so exporting on one machine and
// importing on another needs no extra format.
func ExportLine(sess *Session) string {
	return fmt.Sprintf("%s namespaces=\"git\" %s %s", sess.Email, sshsig.KeyType, sess.KeyB64())
}

// WriteAllowedSigners regenerates allowed_signers from every non-revoked
// session. Revoked sessions are excluded so `git verify-commit` fails for
// them too, not just `botsign verify`.
func (st *Store) WriteAllowedSigners() error {
	sessions, err := st.List()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, sess := range sessions {
		if sess.Revoked != nil {
			continue
		}
		b.WriteString(ExportLine(sess))
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(st.Root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(st.AllowedSignersPath(), []byte(b.String()), 0o644)
}

// Import ingests allowed_signers lines produced by ExportLine on another
// machine, creating public-key-only session records. The session ID is
// re-derived from the key, and the principal must carry the matching
// 8-hex suffix — a record whose ID and key disagree is rejected, so an
// import cannot claim someone else's session name.
func (st *Store) Import(data []byte) ([]*Session, error) {
	var imported []*Session
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sess, err := st.importLine(line)
		if err != nil {
			return imported, fmt.Errorf("line %d: %v", lineNo+1, err)
		}
		imported = append(imported, sess)
	}
	if len(imported) == 0 {
		return nil, errors.New("no allowed_signers lines found in input")
	}
	return imported, st.WriteAllowedSigners()
}

func (st *Store) importLine(line string) (*Session, error) {
	signer, err := ParseAllowedSigner(line)
	if err != nil {
		return nil, err
	}
	if len(signer.Principals) != 1 {
		return nil, fmt.Errorf("want exactly one principal, got %d", len(signer.Principals))
	}
	principal := signer.Principals[0]
	if !IsManagedEmail(principal) {
		return nil, fmt.Errorf("principal %q is not a botsign identity (@%s)", principal, EmailDomain)
	}
	local, _, _ := strings.Cut(principal, "@")
	agent, id8, ok := strings.Cut(local, "+")
	if !ok {
		return nil, fmt.Errorf("principal %q lacks the <agent>+<id> local part", principal)
	}
	norm, err := NormalizeAgent(agent)
	if err != nil {
		return nil, err
	}
	if want := shortID(signer.KeyBlob); id8 != want {
		return nil, fmt.Errorf("principal %q does not match its key (id says %s, key derives %s)", principal, id8, want)
	}
	id := norm + "-" + id8
	if _, err := os.Stat(st.sessionPath(id)); err == nil {
		return nil, fmt.Errorf("session %s already exists in this keystore", id)
	}
	pub, err := sshsig.ParsePublicBlob(signer.KeyBlob)
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:          id,
		Agent:       norm,
		Name:        norm,
		Email:       principal,
		PublicKey:   sshsig.MarshalAuthorized(pub, "botsign:"+id),
		Fingerprint: sshsig.Fingerprint(pub),
		Created:     st.now().Truncate(time.Second),
		Imported:    true,
	}
	return sess, st.save(sess)
}
