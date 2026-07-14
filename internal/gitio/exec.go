// Package gitio talks to the local git binary and parses raw commit
// objects. The parsers are pure functions over bytes so they can be tested
// against fixtures; only the thin Git runner shells out.
package gitio

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Git runs git commands inside Dir. The zero value runs in the current
// working directory.
type Git struct {
	Dir string
}

// run executes git with hardened flags so user configuration (signature
// display, pagers) cannot change the output shape.
func (g Git) run(args ...string) ([]byte, error) {
	full := append([]string{
		"-c", "log.showSignature=false",
		"-c", "core.pager=cat",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = g.Dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", args[0], firstLine(msg))
	}
	return out.Bytes(), nil
}

// RepoTop returns the absolute path of the repository working-tree root.
func (g Git) RepoTop() (string, error) {
	out, err := g.run("rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Head returns the current commit hash and branch name ("HEAD" if detached).
func (g Git) Head() (hash, branch string, err error) {
	out, err := g.run("rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	hash = strings.TrimSpace(string(out))
	out, err = g.run("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", "", err
	}
	return hash, strings.TrimSpace(string(out)), nil
}

// RevList enumerates the commits reachable from a revision range spec
// (e.g. "HEAD" or "main..HEAD"), newest first.
func (g Git) RevList(rangeSpec string) ([]string, error) {
	out, err := g.run("rev-list", rangeSpec)
	if err != nil {
		return nil, err
	}
	var shas []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			shas = append(shas, line)
		}
	}
	return shas, nil
}

// CatCommit returns the raw bytes of one commit object, exactly as git
// stores it — including any embedded gpgsig header.
func (g Git) CatCommit(sha string) ([]byte, error) {
	return g.run("cat-file", "commit", sha)
}

// ConfigSet writes a repo-local config key.
func (g Git) ConfigSet(key, value string) error {
	_, err := g.run("config", "--local", key, value)
	return err
}

// ConfigGet reads a repo-local config key; missing keys return "" and no
// error, because "not set" is an expected state for botsign.
func (g Git) ConfigGet(key string) (string, error) {
	out, err := g.run("config", "--local", "--get", key)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 1") {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ConfigUnset removes a repo-local config key, tolerating its absence.
func (g Git) ConfigUnset(key string) error {
	_, err := g.run("config", "--local", "--unset-all", key)
	if err != nil && strings.Contains(err.Error(), "exit status 5") {
		return nil // exit 5 = key did not exist
	}
	return err
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}
