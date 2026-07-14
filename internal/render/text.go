// Package render turns verification reports into terminal text and stable
// JSON. Both renderers are pure writers over the report struct, so output
// is byte-identical for identical input.
package render

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/JaydenCJ/botsign/internal/verify"
)

// statusOrder fixes the summary ordering: good news first, then each
// failure class, so diffs of report output stay meaningful.
var statusOrder = []verify.Status{
	verify.StatusVerified,
	verify.StatusUnmanaged,
	verify.StatusUnsigned,
	verify.StatusBadSignature,
	verify.StatusUnknownKey,
	verify.StatusMismatch,
	verify.StatusRevoked,
	verify.StatusExpired,
}

// Text renders the human-facing report: header, one line per commit
// (newest first), detail lines for anything failing, then a summary and
// verdict.
func Text(w io.Writer, r *verify.Report) {
	fmt.Fprintf(w, "botsign verify — %s @ %.7s (%s)\n", filepath.Base(r.Repo), r.Head, r.Branch)
	noun := "commits"
	if len(r.Results) == 1 {
		noun = "commit"
	}
	fmt.Fprintf(w, "range: %s · %d %s\n\n", r.Range, len(r.Results), noun)

	for _, res := range r.Results {
		agent := res.Session
		if agent == "" {
			agent = "—"
		}
		fmt.Fprintf(w, "  %s  %-13s  %-24s %s\n", res.ShortSHA, res.Status, agent, res.Subject)
		if res.Detail != "" && res.Status.Failing(r.RequireSigned) {
			fmt.Fprintf(w, "           └─ %s\n", res.Detail)
		}
	}
	if len(r.Results) > 0 {
		fmt.Fprintln(w)
	}

	fmt.Fprint(w, "summary:")
	printed := false
	for _, s := range statusOrder {
		if n := r.Counts[s]; n > 0 {
			if printed {
				fmt.Fprint(w, " ·")
			}
			fmt.Fprintf(w, " %d %s", n, s)
			printed = true
		}
	}
	if !printed {
		fmt.Fprint(w, " no commits in range")
	}
	fmt.Fprintln(w)

	if r.OK() {
		fmt.Fprintln(w, "verify: PASS")
		return
	}
	noun = "commits"
	if r.Failing == 1 {
		noun = "commit"
	}
	fmt.Fprintf(w, "verify: FAIL (%d failing %s)\n", r.Failing, noun)
}
