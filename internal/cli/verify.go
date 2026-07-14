package cli

// verify.go implements `botsign verify`: the audit command that walks a
// revision range and classifies every commit against the keystore.

import (
	"flag"
	"fmt"
	"io"

	"github.com/JaydenCJ/botsign/internal/render"
	"github.com/JaydenCJ/botsign/internal/verify"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rangeSpec := fs.String("range", "HEAD", "revision range to audit, e.g. main..HEAD")
	format := fs.String("format", "text", "output format: text or json")
	requireSigned := fs.Bool("require-signed", false, "unmanaged (human) commits fail too")
	ksFlag := keystoreFlag(fs)
	repoPath, code := parseWithPath(fs, args, stderr)
	if code != ExitOK {
		return code
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "botsign: unknown --format %q (want text or json)\n", *format)
		return ExitUsage
	}
	st, err := resolveStore(*ksFlag, repoPath)
	if err != nil {
		return fail(stderr, err)
	}
	report, err := verify.Run(repoPath, *rangeSpec, st, *requireSigned)
	if err != nil {
		return fail(stderr, err)
	}
	if *format == "json" {
		if err := render.JSON(stdout, report); err != nil {
			return fail(stderr, err)
		}
	} else {
		render.Text(stdout, report)
	}
	if report.OK() {
		return ExitOK
	}
	return ExitFail
}
