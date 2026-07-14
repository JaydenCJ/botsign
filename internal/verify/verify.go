// Package verify is the audit engine: it classifies every commit in a
// range against the keystore and answers, cryptographically, "which agent
// session did what?". Classification is a pure function over (commit,
// keyring) so every status has a deterministic unit test; only the range
// walk touches git.
package verify

import (
	"time"

	"github.com/JaydenCJ/botsign/internal/gitio"
	"github.com/JaydenCJ/botsign/internal/sshsig"
	"github.com/JaydenCJ/botsign/internal/store"
)

// Status classifies one commit. The set is closed and documented in the
// README; anything that is not verified or unmanaged fails verification.
type Status string

const (
	// StatusVerified: valid signature by a known, live session whose
	// identity matches the committer.
	StatusVerified Status = "verified"
	// StatusUnmanaged: no botsign identity and no known-session signature
	// — a human commit. Passes unless --require-signed.
	StatusUnmanaged Status = "unmanaged"
	// StatusUnsigned: the committer claims a botsign identity but the
	// commit carries no signature. This is how impersonation looks.
	StatusUnsigned Status = "unsigned"
	// StatusBadSignature: a signature is present but cryptographically
	// invalid, malformed, or in the wrong namespace.
	StatusBadSignature Status = "bad-signature"
	// StatusUnknownKey: a botsign identity is claimed but the signing key
	// (or the claimed session) is not in this keystore.
	StatusUnknownKey Status = "unknown-key"
	// StatusMismatch: a valid signature by session X under the identity
	// of session Y or of a human — key reuse across identities.
	StatusMismatch Status = "mismatch"
	// StatusRevoked: a valid signature by a session that has since been
	// revoked; revocation withdraws trust retroactively.
	StatusRevoked Status = "revoked"
	// StatusExpired: a valid signature, but the commit is timestamped
	// after the session's expiry.
	StatusExpired Status = "expired"
)

// Failing reports whether a status fails the audit. requireSigned turns
// unmanaged commits into failures too, for repos where every commit must
// come from an attested session.
func (s Status) Failing(requireSigned bool) bool {
	switch s {
	case StatusVerified:
		return false
	case StatusUnmanaged:
		return requireSigned
	default:
		return true
	}
}

// Result is the verdict for one commit.
type Result struct {
	SHA       string    `json:"sha"`
	ShortSHA  string    `json:"short_sha"`
	Subject   string    `json:"subject"`
	Committer string    `json:"committer"`
	When      time.Time `json:"when"`
	Status    Status    `json:"status"`
	Session   string    `json:"session,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// Keyring is the slice of the keystore Check needs; *store.Store
// satisfies it, and tests can substitute fixed maps.
type Keyring interface {
	FindByPublicKey(blob []byte) (*store.Session, error)
	FindByEmail(email string) (*store.Session, error)
}

// Check classifies one parsed commit against the keyring.
func Check(c *gitio.Commit, ring Keyring) (Result, error) {
	res := Result{
		SHA:       c.SHA,
		ShortSHA:  c.ShortSHA(),
		Subject:   c.Subject,
		Committer: c.Committer.Email,
		When:      c.Committer.When,
	}
	claimed, err := ring.FindByEmail(c.Committer.Email)
	if err != nil {
		return res, err
	}
	managedClaim := claimed != nil || store.IsManagedEmail(c.Committer.Email)
	if claimed != nil {
		res.Session, res.Agent = claimed.ID, claimed.Agent
	}

	// No signature at all.
	if c.GPGSig == nil {
		if managedClaim {
			res.Status = StatusUnsigned
			res.Detail = "committer claims a botsign identity but the commit is unsigned"
			return res, nil
		}
		res.Status = StatusUnmanaged
		return res, nil
	}

	// A signature exists — decode it to learn which key claims it.
	sig, decodeErr := sshsig.Decode(c.GPGSig)
	if decodeErr != nil {
		if managedClaim {
			res.Status = StatusBadSignature
			res.Detail = "signature is not a valid SSHSIG envelope: " + decodeErr.Error()
			return res, nil
		}
		// A human's PGP/other signature is none of our business.
		res.Status = StatusUnmanaged
		return res, nil
	}
	signer, err := ring.FindByPublicKey(sshsig.EncodePublicBlob(sig.PublicKey))
	if err != nil {
		return res, err
	}
	if signer == nil {
		if managedClaim {
			res.Status = StatusUnknownKey
			res.Detail = "signing key " + sshsig.Fingerprint(sig.PublicKey) + " is not in this keystore"
			return res, nil
		}
		res.Status = StatusUnmanaged
		return res, nil
	}
	res.Session, res.Agent = signer.ID, signer.Agent

	// The key is one of ours: the cryptography must hold.
	if _, err := sshsig.Verify(c.GPGSig, sshsig.NamespaceGit, c.Payload); err != nil {
		res.Status = StatusBadSignature
		res.Detail = err.Error()
		return res, nil
	}
	if signer.Revoked != nil {
		res.Status = StatusRevoked
		res.Detail = "session revoked at " + signer.Revoked.UTC().Format(time.RFC3339)
		return res, nil
	}
	if signer.Expires != nil && c.Committer.When.After(*signer.Expires) {
		res.Status = StatusExpired
		res.Detail = "committed after session expiry " + signer.Expires.UTC().Format(time.RFC3339)
		return res, nil
	}
	if claimed == nil || claimed.ID != signer.ID {
		res.Status = StatusMismatch
		res.Detail = "signed by " + signer.ID + " but committed as " + c.Committer.Email
		return res, nil
	}
	res.Status = StatusVerified
	return res, nil
}

// Report is the audit outcome for a commit range.
type Report struct {
	Repo          string
	Head          string
	Branch        string
	Range         string
	RequireSigned bool
	Results       []Result
	Counts        map[Status]int
	Failing       int
}

// OK reports whether the audit passed.
func (r *Report) OK() bool { return r.Failing == 0 }

// Run walks a revision range (newest first, as git rev-list emits it) and
// classifies every commit.
func Run(repoPath, rangeSpec string, ring Keyring, requireSigned bool) (*Report, error) {
	g := gitio.Git{Dir: repoPath}
	top, err := g.RepoTop()
	if err != nil {
		return nil, err
	}
	head, branch, err := g.Head()
	if err != nil {
		return nil, err
	}
	shas, err := g.RevList(rangeSpec)
	if err != nil {
		return nil, err
	}
	report := &Report{
		Repo:          top,
		Head:          head,
		Branch:        branch,
		Range:         rangeSpec,
		RequireSigned: requireSigned,
		Counts:        map[Status]int{},
	}
	for _, sha := range shas {
		raw, err := g.CatCommit(sha)
		if err != nil {
			return nil, err
		}
		commit, err := gitio.ParseCommit(sha, raw)
		if err != nil {
			return nil, err
		}
		res, err := Check(commit, ring)
		if err != nil {
			return nil, err
		}
		report.Results = append(report.Results, res)
		report.Counts[res.Status]++
		if res.Status.Failing(requireSigned) {
			report.Failing++
		}
	}
	return report, nil
}
