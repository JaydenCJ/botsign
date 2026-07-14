// End-to-end CLI tests: real (temporary, offline) git repositories, real
// signing, in-process command dispatch. When an attached repo commits,
// git invokes gpg.ssh.program — which attach resolved to THIS test binary
// — so TestMain doubles as the signing backend, exercising the exact
// plumbing production uses. Everything is deterministic: pinned commit
// dates, isolated git config, per-test keystores.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// git calls its ssh program as `<program> -Y <op> …`; a normal test
	// invocation never starts with -Y.
	if len(os.Args) > 1 && os.Args[1] == "-Y" {
		os.Exit(Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// runCLI dispatches botsign in-process.
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// setupEnv isolates git and the keystore for one test and returns the
// keystore root.
func setupEnv(t *testing.T) string {
	t.Helper()
	ks := filepath.Join(t.TempDir(), "keystore")
	t.Setenv("BOTSIGN_KEYSTORE", ks)
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	return ks
}

func initRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	git(t, ".", nil, "init", "-q", "-b", "main", repo)
	return repo
}

// git runs a git command with pinned dates layered over the test env.
func git(t *testing.T, dir string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, errBuf.String())
	}
	return out.String()
}

// agentCommit writes a file and commits through the attached identity —
// signing included, exactly like an agent running `git commit`.
func agentCommit(t *testing.T, repo string, seq int, msg string) {
	t.Helper()
	writeFile(t, repo, fmt.Sprintf("file-%d.txt", seq), fmt.Sprintf("content %d\n", seq))
	date := fmt.Sprintf("2026-03-%02dT10:00:00+00:00", seq)
	git(t, repo, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, "add", "-A")
	git(t, repo, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, "commit", "-q", "-m", msg)
}

// humanCommit commits with an explicit identity and no signature.
func humanCommit(t *testing.T, repo string, seq int, name, email, msg string) {
	t.Helper()
	writeFile(t, repo, fmt.Sprintf("file-%d.txt", seq), fmt.Sprintf("content %d\n", seq))
	date := fmt.Sprintf("2026-03-%02dT10:00:00+00:00", seq)
	env := []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}
	git(t, repo, env, "add", "-A")
	git(t, repo, env,
		"-c", "user.name="+name, "-c", "user.email="+email, "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", msg)
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mintAttached mints a session attached to the repo and returns its
// parsed JSON record.
func mintAttached(t *testing.T, repo string, extra ...string) map[string]any {
	t.Helper()
	args := append([]string{"new", "--agent", "claude-code", "--repo", repo, "--json"}, extra...)
	code, out, errOut := runCLI(t, "", args...)
	if code != 0 {
		t.Fatalf("new failed (%d): %s", code, errOut)
	}
	var sess map[string]any
	if err := json.Unmarshal([]byte(out), &sess); err != nil {
		t.Fatalf("new --json output: %v\n%s", err, out)
	}
	return sess
}

func TestVersionAndHelp(t *testing.T) {
	code, out, _ := runCLI(t, "", "version")
	if code != 0 || out != "botsign 0.1.0\n" {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	code, out, _ = runCLI(t, "", "help")
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}
	for _, cmd := range []string{"new", "attach", "verify", "sessions", "export", "import", "revoke", "status"} {
		if !strings.Contains(out, "botsign "+cmd) {
			t.Fatalf("help does not mention %q:\n%s", cmd, out)
		}
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	setupEnv(t)
	for name, args := range map[string][]string{
		"unknown command": {"frobnicate"},
		"new sans agent":  {"new"},
		"bad format":      {"verify", "--format", "yaml", "."},
		"attach sans id":  {"attach"},
		"negative ttl":    {"new", "--agent", "a", "--ttl", "-1h"},
	} {
		if code, _, _ := runCLI(t, "", args...); code != ExitUsage {
			t.Fatalf("%s: exit %d, want %d", name, code, ExitUsage)
		}
	}
}

func TestNewAttachConfiguresRepo(t *testing.T) {
	ks := setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	id := sess["id"].(string)
	if !strings.HasPrefix(id, "claude-code-") {
		t.Fatalf("session id = %q", id)
	}
	for key, want := range map[string]string{
		"gpg.format":      "ssh",
		"commit.gpgsign":  "true",
		"botsign.session": id,
		"user.email":      sess["email"].(string),
		"user.signingkey": filepath.Join(ks, "keys", id),
	} {
		if got := strings.TrimSpace(git(t, repo, nil, "config", "--local", key)); got != want {
			t.Fatalf("config %s = %q, want %q", key, got, want)
		}
	}
	// The allowed_signers file exists and names the session identity.
	signers, err := os.ReadFile(filepath.Join(ks, "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signers), sess["email"].(string)) {
		t.Fatal("allowed_signers missing the new identity")
	}
}

func TestNewWithBadRepoMintsNothing(t *testing.T) {
	// A bad --repo path must fail before the keypair is minted; otherwise
	// every typo would leave an orphaned session in the keystore.
	ks := setupEnv(t)
	code, _, errOut := runCLI(t, "", "new", "--agent", "claude-code", "--repo", filepath.Join(t.TempDir(), "missing"))
	if code != ExitRuntime {
		t.Fatalf("new with bad repo: exit %d, want %d\n%s", code, ExitRuntime, errOut)
	}
	if _, err := os.Stat(filepath.Join(ks, "sessions")); !os.IsNotExist(err) {
		t.Fatal("bad --repo left a session behind in the keystore")
	}
}

func TestSignedCommitVerifiesEndToEnd(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	agentCommit(t, repo, 1, "Add rate limiter")

	// The commit object carries a real SSHSIG signature.
	raw := git(t, repo, nil, "cat-file", "commit", "HEAD")
	if !strings.Contains(raw, "BEGIN SSH SIGNATURE") {
		t.Fatalf("commit is not signed:\n%s", raw)
	}
	code, out, _ := runCLI(t, "", "verify", repo)
	if code != 0 {
		t.Fatalf("verify exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "verified") || !strings.Contains(out, sess["id"].(string)) || !strings.Contains(out, "verify: PASS") {
		t.Fatalf("verify output:\n%s", out)
	}
}

func TestVerifyDetectsImpersonation(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	agentCommit(t, repo, 1, "Legit signed work")
	// A different actor claims the session identity without the key.
	humanCommit(t, repo, 2, "claude-code", sess["email"].(string), "Sneaky unsigned change")

	code, out, _ := runCLI(t, "", "verify", repo)
	if code != ExitFail {
		t.Fatalf("verify exited %d, want %d\n%s", code, ExitFail, out)
	}
	if !strings.Contains(out, "unsigned") || !strings.Contains(out, "claims a botsign identity") {
		t.Fatalf("impersonation not called out:\n%s", out)
	}
	if !strings.Contains(out, "verify: FAIL (1 failing commit)") {
		t.Fatalf("verdict missing:\n%s", out)
	}
}

func TestVerifyRequireSigned(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	mintAttached(t, repo)
	agentCommit(t, repo, 1, "Signed work")
	humanCommit(t, repo, 2, "Dev Human", "dev@example.test", "Human tweak")

	if code, out, _ := runCLI(t, "", "verify", repo); code != 0 {
		t.Fatalf("human commits pass by default, got %d:\n%s", code, out)
	}
	code, out, _ := runCLI(t, "", "verify", "--require-signed", repo)
	if code != ExitFail || !strings.Contains(out, "unmanaged") {
		t.Fatalf("--require-signed: code=%d\n%s", code, out)
	}
}

func TestVerifyJSONEnvelope(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	agentCommit(t, repo, 1, "Signed work")

	code, out, _ := runCLI(t, "", "verify", "--format", "json", repo)
	if code != 0 {
		t.Fatalf("verify exited %d", code)
	}
	var env struct {
		Tool    string         `json:"tool"`
		Schema  int            `json:"schema_version"`
		OK      bool           `json:"ok"`
		Summary map[string]int `json:"summary"`
		Commits []struct {
			Status  string `json:"status"`
			Session string `json:"session"`
			Agent   string `json:"agent"`
		} `json:"commits"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if env.Tool != "botsign" || env.Schema != 1 || !env.OK || env.Summary["verified"] != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	if len(env.Commits) != 1 || env.Commits[0].Session != sess["id"].(string) || env.Commits[0].Agent != "claude-code" {
		t.Fatalf("commits = %+v", env.Commits)
	}
}

func TestVerifyRangeScopesAudit(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	agentCommit(t, repo, 1, "Signed work")
	humanCommit(t, repo, 2, "claude-code", sess["email"].(string), "Impersonation")

	// Only the newest commit: fails.
	if code, _, _ := runCLI(t, "", "verify", "--range", "HEAD~1..HEAD", repo); code != ExitFail {
		t.Fatalf("scoped audit of the bad commit must fail, got %d", code)
	}
	// Only the oldest commit: passes.
	if code, out, _ := runCLI(t, "", "verify", "--range", "HEAD~1", repo); code != 0 {
		t.Fatalf("scoped audit of the good commit must pass, got %d:\n%s", code, out)
	}
	// Verifying outside any repo is a runtime error.
	if code, _, _ := runCLI(t, "", "verify", t.TempDir()); code != ExitRuntime {
		t.Fatal("verify outside a repo must exit 3")
	}
}

func TestStatusAndDetachLifecycle(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)

	code, out, _ := runCLI(t, "", "status", repo)
	if code != 0 || !strings.Contains(out, sess["id"].(string)+" (active)") || !strings.Contains(out, "signing   on") {
		t.Fatalf("healthy status: code=%d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "", "detach", repo)
	if code != 0 || !strings.Contains(out, "detached") {
		t.Fatalf("detach: code=%d\n%s", code, out)
	}
	if got := git(t, repo, nil, "config", "--local", "--list"); strings.Contains(got, "botsign") || strings.Contains(got, "gpg.format") {
		t.Fatalf("managed config survived detach:\n%s", got)
	}
	if code, out, _ = runCLI(t, "", "status", repo); code != ExitFail || !strings.Contains(out, "not attached") {
		t.Fatalf("post-detach status: code=%d\n%s", code, out)
	}
	if code, _, _ = runCLI(t, "", "detach", repo); code != ExitRuntime {
		t.Fatal("double detach must be a runtime error")
	}
}

func TestSessionsShowExportImport(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	id := sess["id"].(string)
	agentCommit(t, repo, 1, "Signed work")

	code, out, _ := runCLI(t, "", "sessions")
	if code != 0 || !strings.Contains(out, id) || !strings.Contains(out, "active") {
		t.Fatalf("sessions: code=%d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "", "show", id)
	if code != 0 || !strings.Contains(out, "pubkey    ssh-ed25519 ") {
		t.Fatalf("show: code=%d\n%s", code, out)
	}
	code, card, _ := runCLI(t, "", "export")
	if code != 0 || !strings.Contains(card, sess["email"].(string)) {
		t.Fatalf("export: code=%d\n%s", code, card)
	}

	// A teammate imports the card into a fresh keystore via stdin and can
	// verify the same history without ever holding the private key.
	ks2 := filepath.Join(t.TempDir(), "keystore2")
	code, out, errOut := runCLI(t, card, "import", "--keystore", ks2, "-")
	if code != 0 || !strings.Contains(out, "imported  "+id) {
		t.Fatalf("import: code=%d\n%s%s", code, out, errOut)
	}
	code, out, _ = runCLI(t, "", "verify", "--keystore", ks2, repo)
	if code != 0 || !strings.Contains(out, "verify: PASS") {
		t.Fatalf("verify with imported keystore: code=%d\n%s", code, out)
	}
}

func TestRevokeInvalidatesHistoryAndBlocksAttach(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	sess := mintAttached(t, repo)
	id := sess["id"].(string)
	agentCommit(t, repo, 1, "Signed work")

	if code, out, _ := runCLI(t, "", "verify", repo); code != 0 {
		t.Fatalf("pre-revoke verify failed:\n%s", out)
	}
	if code, out, _ := runCLI(t, "", "revoke", id); code != 0 || !strings.Contains(out, "revoked   "+id) {
		t.Fatalf("revoke: code=%d\n%s", code, out)
	}
	code, out, _ := runCLI(t, "", "verify", repo)
	if code != ExitFail || !strings.Contains(out, "revoked") {
		t.Fatalf("post-revoke verify: code=%d\n%s", code, out)
	}
	// The dead session can no longer be wired to a repo.
	if code, _, errOut := runCLI(t, "", "attach", id, repo); code != ExitRuntime || !strings.Contains(errOut, "revoked") {
		t.Fatalf("attach after revoke: code=%d %s", code, errOut)
	}
}

func TestExpiredSessionFailsVerify(t *testing.T) {
	setupEnv(t)
	repo := initRepo(t)
	mintAttached(t, repo, "--ttl", "1h")

	// Commit timestamped two hours from now — beyond created+1h, no
	// matter when this test runs.
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	writeFile(t, repo, "late.txt", "late\n")
	git(t, repo, []string{"GIT_AUTHOR_DATE=" + future, "GIT_COMMITTER_DATE=" + future}, "add", "-A")
	git(t, repo, []string{"GIT_AUTHOR_DATE=" + future, "GIT_COMMITTER_DATE=" + future}, "commit", "-q", "-m", "Past the deadline")

	code, out, _ := runCLI(t, "", "verify", repo)
	if code != ExitFail || !strings.Contains(out, "expired") {
		t.Fatalf("expired session: code=%d\n%s", code, out)
	}
}

func TestCompatModeDirect(t *testing.T) {
	// Drive the ssh-keygen interface exactly as git does, without git:
	// sign a payload file, then find-principals / verify / check-novalidate.
	ks := setupEnv(t)
	code, out, errOut := runCLI(t, "", "new", "--agent", "claude-code", "--json")
	if code != 0 {
		t.Fatalf("new: %s", errOut)
	}
	var sess map[string]any
	if err := json.Unmarshal([]byte(out), &sess); err != nil {
		t.Fatal(err)
	}
	id, email := sess["id"].(string), sess["email"].(string)
	keyPath := filepath.Join(ks, "keys", id)
	allowed := filepath.Join(ks, "allowed_signers")

	payload := filepath.Join(t.TempDir(), "buffer")
	content := "tree deadbeef\n\npayload to sign\n"
	if err := os.WriteFile(payload, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sign — including a glued -O option, which git 2.43+ passes.
	code, _, errOut = runCLI(t, "", "-Y", "sign", "-n", "git", "-Overify-time=20260301100000", "-f", keyPath, payload)
	if code != 0 {
		t.Fatalf("-Y sign: %s", errOut)
	}
	sig, err := os.ReadFile(payload + ".sig")
	if err != nil || !bytes.Contains(sig, []byte("BEGIN SSH SIGNATURE")) {
		t.Fatalf("no signature written: %v", err)
	}

	code, out, _ = runCLI(t, "", "-Y", "find-principals", "-f", allowed, "-s", payload+".sig")
	if code != 0 || strings.TrimSpace(out) != email {
		t.Fatalf("find-principals: code=%d out=%q", code, out)
	}

	code, out, _ = runCLI(t, content, "-Y", "verify", "-f", allowed, "-I", email, "-n", "git", "-s", payload+".sig")
	if code != 0 || !strings.Contains(out, `Good "git" signature for `+email) {
		t.Fatalf("-Y verify: code=%d out=%q", code, out)
	}
	// The wrong principal, a tampered payload, and the wrong namespace
	// must all fail.
	if code, _, _ = runCLI(t, content, "-Y", "verify", "-f", allowed, "-I", "other@example.test", "-n", "git", "-s", payload+".sig"); code == 0 {
		t.Fatal("wrong principal must fail")
	}
	if code, _, _ = runCLI(t, content+"x", "-Y", "verify", "-f", allowed, "-I", email, "-n", "git", "-s", payload+".sig"); code == 0 {
		t.Fatal("tampered payload must fail")
	}
	if code, _, _ = runCLI(t, content, "-Y", "check-novalidate", "-n", "file", "-s", payload+".sig"); code == 0 {
		t.Fatal("wrong namespace must fail")
	}
	code, out, _ = runCLI(t, content, "-Y", "check-novalidate", "-n", "git", "-s", payload+".sig")
	if code != 0 || !strings.Contains(out, `Good "git" signature with`) {
		t.Fatalf("check-novalidate: code=%d out=%q", code, out)
	}
}
