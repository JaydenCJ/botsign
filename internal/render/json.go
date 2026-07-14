package render

import (
	"encoding/json"
	"io"

	"github.com/JaydenCJ/botsign/internal/verify"
)

// jsonEnvelope is the machine-readable report. schema_version is bumped
// on any breaking change to this shape.
type jsonEnvelope struct {
	Tool          string          `json:"tool"`
	SchemaVersion int             `json:"schema_version"`
	Repo          string          `json:"repo"`
	Head          string          `json:"head"`
	Branch        string          `json:"branch"`
	Range         string          `json:"range"`
	RequireSigned bool            `json:"require_signed"`
	Commits       []verify.Result `json:"commits"`
	Summary       map[string]int  `json:"summary"`
	Failing       int             `json:"failing"`
	OK            bool            `json:"ok"`
}

// JSON renders the report as indented JSON with a trailing newline.
func JSON(w io.Writer, r *verify.Report) error {
	env := jsonEnvelope{
		Tool:          "botsign",
		SchemaVersion: 1,
		Repo:          r.Repo,
		Head:          r.Head,
		Branch:        r.Branch,
		Range:         r.Range,
		RequireSigned: r.RequireSigned,
		Commits:       r.Results,
		Summary:       map[string]int{},
		Failing:       r.Failing,
		OK:            r.OK(),
	}
	if env.Commits == nil {
		env.Commits = []verify.Result{}
	}
	for status, n := range r.Counts {
		env.Summary[string(status)] = n
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}
