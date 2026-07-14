package cli

// sessions.go implements the keystore-facing commands: listing, showing,
// exporting, importing, and revoking sessions.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JaydenCJ/botsign/internal/store"
)

func runSessions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, ".")
	if err != nil {
		return fail(stderr, err)
	}
	sessions, err := st.List()
	if err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		if sessions == nil {
			sessions = []*store.Session{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sessions); err != nil {
			return fail(stderr, err)
		}
		return ExitOK
	}
	if len(sessions) == 0 {
		fmt.Fprintf(stdout, "no sessions in %s (mint one with `botsign new --agent NAME`)\n", st.Root)
		return ExitOK
	}
	now := time.Now().UTC()
	fmt.Fprintf(stdout, "%-28s %-16s %-9s %-20s %s\n", "session", "agent", "status", "created", "key")
	for _, sess := range sessions {
		status := sess.Status(now)
		if sess.Imported && status == "active" {
			status = "imported"
		}
		fmt.Fprintf(stdout, "%-28s %-16s %-9s %-20s %s\n",
			sess.ID, sess.Agent, status,
			sess.Created.UTC().Format("2006-01-02 15:04:05"), sess.Fingerprint)
	}
	return ExitOK
}

func runShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(stderr, "botsign show: usage: botsign show SESSION")
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, ".")
	if err != nil {
		return fail(stderr, err)
	}
	sess, err := st.Get(fs.Args()[0])
	if err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		return printSessionJSON(stdout, stderr, sess, "")
	}
	printSession(stdout, sess)
	fmt.Fprintf(stdout, "pubkey    %s\n", sess.PublicKey)
	return ExitOK
}

func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, ".")
	if err != nil {
		return fail(stderr, err)
	}
	var sessions []*store.Session
	if ids := fs.Args(); len(ids) > 0 {
		for _, id := range ids {
			sess, err := st.Get(id)
			if err != nil {
				return fail(stderr, err)
			}
			if sess.Revoked != nil {
				return fail(stderr, fmt.Errorf("session %s is revoked; refusing to export it as trusted", id))
			}
			sessions = append(sessions, sess)
		}
	} else {
		all, err := st.List()
		if err != nil {
			return fail(stderr, err)
		}
		for _, sess := range all {
			if sess.Revoked == nil {
				sessions = append(sessions, sess)
			}
		}
	}
	if len(sessions) == 0 {
		return fail(stderr, fmt.Errorf("nothing to export from %s", st.Root))
	}
	for _, sess := range sessions {
		fmt.Fprintln(stdout, store.ExportLine(sess))
	}
	return ExitOK
}

func runImport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(stderr, "botsign import: usage: botsign import FILE (or - for stdin)")
		return ExitUsage
	}
	var data []byte
	var err error
	if src := fs.Args()[0]; src == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return fail(stderr, err)
	}
	st, err := resolveStore(*ksFlag, ".")
	if err != nil {
		return fail(stderr, err)
	}
	imported, err := st.Import(data)
	if err != nil {
		return fail(stderr, err)
	}
	for _, sess := range imported {
		fmt.Fprintf(stdout, "imported  %s (%s, %s)\n", sess.ID, sess.Agent, sess.Fingerprint)
	}
	return ExitOK
}

func runRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksFlag := keystoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(stderr, "botsign revoke: usage: botsign revoke SESSION")
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, ".")
	if err != nil {
		return fail(stderr, err)
	}
	sess, err := st.Revoke(fs.Args()[0])
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "revoked   %s at %s (private key deleted, dropped from allowed_signers)\n",
		sess.ID, sess.Revoked.UTC().Format(time.RFC3339))
	return ExitOK
}
