// Package cli implements the botsign command-line interface. Run takes
// argv and three streams and returns an exit code, so the whole surface is
// testable in-process without building a binary. It also implements the
// ssh-keygen `-Y` interface, because git invokes botsign itself (via
// gpg.ssh.program) to sign and verify.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/JaydenCJ/botsign/internal/gitio"
	"github.com/JaydenCJ/botsign/internal/store"
	"github.com/JaydenCJ/botsign/internal/version"
)

// Exit codes. Documented in the README; `verify` and `status` use
// ExitFail as their machine-readable verdict.
const (
	ExitOK      = 0
	ExitFail    = 1
	ExitUsage   = 2
	ExitRuntime = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return ExitOK
	}
	switch args[0] {
	case "-Y":
		// git invoked us as its ssh-keygen: gpg.ssh.program interface.
		return runCompat(args, stdin, stdout, stderr)
	case "new":
		return runNew(args[1:], stdout, stderr)
	case "attach":
		return runAttach(args[1:], stdout, stderr)
	case "detach":
		return runDetach(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "sessions":
		return runSessions(args[1:], stdout, stderr)
	case "show":
		return runShow(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "import":
		return runImport(args[1:], stdin, stdout, stderr)
	case "revoke":
		return runRevoke(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "botsign %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "botsign: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

// keystoreFlag registers the shared --keystore flag.
func keystoreFlag(fs *flag.FlagSet) *string {
	return fs.String("keystore", "", "keystore directory (default: $BOTSIGN_KEYSTORE, the repo's botsign.keystore config, then the user config dir)")
}

// resolveStore picks the keystore root: explicit flag, then the
// BOTSIGN_KEYSTORE environment variable, then the repo's botsign.keystore
// config (when a repo is in play), then <user-config-dir>/botsign. The
// result is always absolute, because the path gets written into git
// config and read back from other working directories.
func resolveStore(flagValue, repoPath string) (*store.Store, error) {
	root := flagValue
	if root == "" {
		root = os.Getenv("BOTSIGN_KEYSTORE")
	}
	if root == "" && repoPath != "" {
		if v, err := (gitio.Git{Dir: repoPath}).ConfigGet("botsign.keystore"); err == nil {
			root = v
		}
	}
	if root == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("cannot locate a keystore: %v (set --keystore or BOTSIGN_KEYSTORE)", err)
		}
		root = filepath.Join(dir, "botsign")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &store.Store{Root: abs}, nil
}

// programPath resolves the binary git should invoke for signing:
// BOTSIGN_PROGRAM if set (useful for tests and relocated installs),
// otherwise the running executable.
func programPath() (string, error) {
	if p := os.Getenv("BOTSIGN_PROGRAM"); p != "" {
		return filepath.Abs(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot resolve the botsign binary path: %v", err)
	}
	return filepath.EvalSymlinks(exe)
}

// onePath extracts the optional single positional path argument.
func onePath(rest []string, stderr io.Writer) (string, int) {
	switch len(rest) {
	case 0:
		return ".", ExitOK
	case 1:
		return rest[0], ExitOK
	default:
		fmt.Fprintf(stderr, "botsign: expected at most one path argument, got %d\n", len(rest))
		return "", ExitUsage
	}
}

// fail prints a runtime error in the standard shape.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "botsign: %v\n", err)
	return ExitRuntime
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `botsign %s — per-agent git identities, signature-backed

Usage:
  botsign new --agent NAME [flags]     mint a session signing key (+ optional --repo attach)
  botsign attach SESSION [path]        wire a repo to an existing session
  botsign detach [path]                remove botsign-managed config from a repo
  botsign status [path]                show which session a repo commits as
  botsign verify [flags] [path]        verify who did what (exit 1 on failure)
  botsign sessions [--json]            list sessions in the keystore
  botsign show SESSION [--json]        print one session's details
  botsign export [SESSION...]          print allowed_signers lines for teammates
  botsign import FILE|-                ingest exported lines (public keys only)
  botsign revoke SESSION               withdraw trust and shred the private key
  botsign version                      print the version

New flags:
  --agent NAME           agent this session belongs to (required)
  --repo PATH            also attach the given repository
  --name NAME            git user.name override (default: the agent)
  --email ADDR           git user.email override (default: minted identity)
  --ttl DURATION         session expiry, e.g. 8h or 30m (default: none)
  --json                 machine-readable output

Verify flags:
  --range SPEC           revision range, e.g. main..HEAD (default: HEAD)
  --format FORMAT        text (default) or json
  --require-signed       unmanaged (human) commits fail too

Every command accepts --keystore PATH (or BOTSIGN_KEYSTORE).
Exit codes: 0 ok · 1 verification/status failure · 2 usage error · 3 runtime error
`, version.Version)
}

// parseWithPath parses a FlagSet and extracts the optional single
// positional path. flag.FlagSet stops at the first non-flag argument, so
// `verify path --format json` would silently ignore the flags; this
// rejects that shape with a pointed error instead.
func parseWithPath(fs *flag.FlagSet, args []string, stderr io.Writer) (string, int) {
	if err := fs.Parse(args); err != nil {
		return "", ExitUsage
	}
	rest := fs.Args()
	if len(rest) > 1 && strings.HasPrefix(rest[1], "-") {
		fmt.Fprintf(stderr, "botsign: flags must come before the path argument (saw %q after %q)\n", rest[1], rest[0])
		return "", ExitUsage
	}
	return onePath(rest, stderr)
}
