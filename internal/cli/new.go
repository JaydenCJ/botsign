package cli

// new.go implements the session lifecycle against a repository: minting
// (new), wiring a repo to a session (attach), unwiring (detach), and
// inspecting the wiring (status).

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JaydenCJ/botsign/internal/gitio"
	"github.com/JaydenCJ/botsign/internal/store"
)

// managedKeys are the repo-local config keys attach owns and detach
// removes. botsign never touches global or system config.
var managedKeys = []string{
	"user.name",
	"user.email",
	"user.signingKey",
	"gpg.format",
	"gpg.ssh.program",
	"gpg.ssh.allowedSignersFile",
	"commit.gpgsign",
	"botsign.session",
	"botsign.keystore",
}

func runNew(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "", "agent this session belongs to (required)")
	repo := fs.String("repo", "", "also attach the given repository")
	name := fs.String("name", "", "git user.name override")
	email := fs.String("email", "", "git user.email override")
	ttl := fs.Duration("ttl", 0, "session expiry, e.g. 8h")
	asJSON := fs.Bool("json", false, "machine-readable output")
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(stderr, "botsign new: unexpected argument %q\n", fs.Args()[0])
		return ExitUsage
	}
	if *agent == "" {
		fmt.Fprintln(stderr, "botsign new: --agent is required")
		return ExitUsage
	}
	if *ttl < 0 {
		fmt.Fprintln(stderr, "botsign new: --ttl must be a positive duration (e.g. 8h)")
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, *repo)
	if err != nil {
		return fail(stderr, err)
	}
	// Validate the repo before minting, so a bad --repo path cannot leave
	// an orphaned session behind in the keystore.
	if *repo != "" {
		if _, err := (gitio.Git{Dir: *repo}).RepoTop(); err != nil {
			return fail(stderr, err)
		}
	}
	sess, err := st.Create(*agent, store.CreateOptions{Name: *name, Email: *email, TTL: *ttl})
	if err != nil {
		return fail(stderr, err)
	}
	attachedTo := ""
	if *repo != "" {
		top, err := attach(st, sess, *repo)
		if err != nil {
			return fail(stderr, err)
		}
		attachedTo = top
	}
	if *asJSON {
		return printSessionJSON(stdout, stderr, sess, attachedTo)
	}
	printSession(stdout, sess)
	if attachedTo != "" {
		fmt.Fprintf(stdout, "attached  %s (commit signing on)\n", attachedTo)
	}
	return ExitOK
}

// printSession renders the key-value block shared by new and show.
func printSession(w io.Writer, sess *store.Session) {
	fmt.Fprintf(w, "session   %s\n", sess.ID)
	fmt.Fprintf(w, "agent     %s\n", sess.Agent)
	fmt.Fprintf(w, "key       %s\n", sess.Fingerprint)
	fmt.Fprintf(w, "email     %s\n", sess.Email)
	fmt.Fprintf(w, "created   %s\n", sess.Created.UTC().Format(time.RFC3339))
	if sess.Expires != nil {
		fmt.Fprintf(w, "expires   %s\n", sess.Expires.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(w, "expires   never\n")
	}
	if sess.Revoked != nil {
		fmt.Fprintf(w, "revoked   %s\n", sess.Revoked.UTC().Format(time.RFC3339))
	}
	if sess.Imported {
		fmt.Fprintf(w, "imported  yes (public key only)\n")
	}
}

func printSessionJSON(stdout, stderr io.Writer, sess *store.Session, attachedTo string) int {
	payload := struct {
		*store.Session
		Attached string `json:"attached,omitempty"`
	}{sess, attachedTo}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fail(stderr, err)
	}
	return ExitOK
}

// attach wires a repository to a session: identity, SSH signing via
// botsign itself, and the keystore breadcrumbs status/verify read back.
// It returns the repo top-level path.
func attach(st *store.Store, sess *store.Session, repoPath string) (string, error) {
	if sess.Revoked != nil {
		return "", fmt.Errorf("session %s is revoked and cannot sign", sess.ID)
	}
	if sess.Imported {
		return "", fmt.Errorf("session %s is imported (public key only) and cannot sign here", sess.ID)
	}
	if _, err := os.Stat(st.KeyPath(sess.ID)); err != nil {
		return "", fmt.Errorf("session %s has no private key at %s", sess.ID, st.KeyPath(sess.ID))
	}
	program, err := programPath()
	if err != nil {
		return "", err
	}
	g := gitio.Git{Dir: repoPath}
	top, err := g.RepoTop()
	if err != nil {
		return "", err
	}
	settings := []struct{ key, value string }{
		{"user.name", sess.Name},
		{"user.email", sess.Email},
		{"user.signingKey", st.KeyPath(sess.ID)},
		{"gpg.format", "ssh"},
		{"gpg.ssh.program", program},
		{"gpg.ssh.allowedSignersFile", st.AllowedSignersPath()},
		{"commit.gpgsign", "true"},
		{"botsign.session", sess.ID},
		{"botsign.keystore", st.Root},
	}
	for _, s := range settings {
		if err := g.ConfigSet(s.key, s.value); err != nil {
			return "", err
		}
	}
	return top, nil
}

func runAttach(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) < 1 || len(rest) > 2 {
		fmt.Fprintln(stderr, "botsign attach: usage: botsign attach SESSION [path]")
		return ExitUsage
	}
	repoPath := "."
	if len(rest) == 2 {
		repoPath = rest[1]
	}
	st, err := resolveStore(*ksFlag, "")
	if err != nil {
		return fail(stderr, err)
	}
	sess, err := st.Get(rest[0])
	if err != nil {
		return fail(stderr, err)
	}
	top, err := attach(st, sess, repoPath)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "attached  %s → %s (commit signing on)\n", top, sess.ID)
	return ExitOK
}

func runDetach(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("detach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoPath, code := parseWithPath(fs, args, stderr)
	if code != ExitOK {
		return code
	}
	g := gitio.Git{Dir: repoPath}
	top, err := g.RepoTop()
	if err != nil {
		return fail(stderr, err)
	}
	sid, err := g.ConfigGet("botsign.session")
	if err != nil {
		return fail(stderr, err)
	}
	if sid == "" {
		return fail(stderr, fmt.Errorf("%s is not attached to a botsign session", top))
	}
	for _, key := range managedKeys {
		if err := g.ConfigUnset(key); err != nil {
			return fail(stderr, err)
		}
	}
	fmt.Fprintf(stdout, "detached  %s (was %s; signing config removed)\n", top, sid)
	return ExitOK
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksFlag := keystoreFlag(fs)
	repoPath, code := parseWithPath(fs, args, stderr)
	if code != ExitOK {
		return code
	}
	g := gitio.Git{Dir: repoPath}
	top, err := g.RepoTop()
	if err != nil {
		return fail(stderr, err)
	}
	sid, err := g.ConfigGet("botsign.session")
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "repo      %s\n", top)
	if sid == "" {
		fmt.Fprintln(stdout, "session   none (not attached)")
		return ExitFail
	}
	st, err := resolveStore(*ksFlag, repoPath)
	if err != nil {
		return fail(stderr, err)
	}
	healthy := true
	sess, err := st.Get(sid)
	if err != nil {
		fmt.Fprintf(stdout, "session   %s (missing from keystore %s)\n", sid, st.Root)
		return ExitFail
	}
	state := sess.Status(time.Now().UTC())
	if state != "active" {
		healthy = false
	}
	fmt.Fprintf(stdout, "session   %s (%s)\n", sid, state)
	fmt.Fprintf(stdout, "agent     %s\n", sess.Agent)

	signing, _ := g.ConfigGet("commit.gpgsign")
	format, _ := g.ConfigGet("gpg.format")
	if signing == "true" && format == "ssh" {
		fmt.Fprintln(stdout, "signing   on (gpg.format=ssh)")
	} else {
		fmt.Fprintf(stdout, "signing   OFF (commit.gpgsign=%q, gpg.format=%q)\n", signing, format)
		healthy = false
	}
	keyPath, _ := g.ConfigGet("user.signingKey")
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Fprintf(stdout, "key       %s (present)\n", keyPath)
	} else {
		fmt.Fprintf(stdout, "key       %s (MISSING)\n", keyPath)
		healthy = false
	}
	program, _ := g.ConfigGet("gpg.ssh.program")
	if _, err := os.Stat(program); err == nil {
		fmt.Fprintf(stdout, "program   %s (present)\n", program)
	} else {
		fmt.Fprintf(stdout, "program   %s (MISSING)\n", program)
		healthy = false
	}
	if !healthy {
		return ExitFail
	}
	return ExitOK
}
