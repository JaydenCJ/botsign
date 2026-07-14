// Command botsign mints per-agent-session git signing identities and
// verifies, commit by commit, which session did what.
package main

import (
	"os"

	"github.com/JaydenCJ/botsign/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
