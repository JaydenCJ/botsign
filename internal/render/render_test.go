// Renderer tests over hand-built reports: identical input must produce
// byte-identical text and JSON, in a fixed status order.
package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/botsign/internal/verify"
)

func sampleReport() *verify.Report {
	when := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return &verify.Report{
		Repo:   "/work/api",
		Head:   "0196db2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Branch: "main",
		Range:  "HEAD",
		Results: []verify.Result{
			{SHA: "a", ShortSHA: "a000001", Subject: "Sneaky change", Committer: "x+1@botsign.invalid",
				When: when, Status: verify.StatusUnsigned, Session: "claude-code-12ab34cd",
				Detail: "committer claims a botsign identity but the commit is unsigned"},
			{SHA: "b", ShortSHA: "b000002", Subject: "Add limiter", Committer: "x+1@botsign.invalid",
				When: when, Status: verify.StatusVerified, Session: "claude-code-12ab34cd", Agent: "claude-code"},
			{SHA: "c", ShortSHA: "c000003", Subject: "Human tweak", Committer: "dev@example.test",
				When: when, Status: verify.StatusUnmanaged},
		},
		Counts: map[verify.Status]int{
			verify.StatusUnsigned:  1,
			verify.StatusVerified:  1,
			verify.StatusUnmanaged: 1,
		},
		Failing: 1,
	}
}

func TestTextReportFailingRun(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport())
	out := buf.String()
	for _, want := range []string{
		"botsign verify — api @ 0196db2 (main)",
		"range: HEAD · 3 commits",
		"a000001  unsigned",
		"└─ committer claims a botsign identity",
		"b000002  verified       claude-code-12ab34cd",
		"summary: 1 verified · 1 unmanaged · 1 unsigned",
		"verify: FAIL (1 failing commit)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportPassingRunHidesDetails(t *testing.T) {
	r := sampleReport()
	r.Results = r.Results[1:] // drop the unsigned commit
	r.Counts = map[verify.Status]int{verify.StatusVerified: 1, verify.StatusUnmanaged: 1}
	r.Failing = 0
	var buf bytes.Buffer
	Text(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "verify: PASS") {
		t.Fatalf("missing PASS verdict:\n%s", out)
	}
	if strings.Contains(out, "└─") {
		t.Fatal("passing commits must not print detail lines")
	}
}

func TestTextSummaryOrderIsStable(t *testing.T) {
	var a, b bytes.Buffer
	Text(&a, sampleReport())
	Text(&b, sampleReport())
	if a.String() != b.String() {
		t.Fatal("identical reports rendered differently")
	}
	// verified must always precede failure classes in the summary.
	out := a.String()
	if strings.Index(out, "1 verified") > strings.Index(out, "1 unsigned") {
		t.Fatal("summary order drifted")
	}
}

func TestTextEmptyRange(t *testing.T) {
	r := &verify.Report{Repo: "/r", Head: "abc1234", Branch: "main", Range: "HEAD..HEAD", Counts: map[verify.Status]int{}}
	var buf bytes.Buffer
	Text(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "no commits in range") || !strings.Contains(out, "verify: PASS") {
		t.Fatalf("empty range rendering:\n%s", out)
	}
}

func TestJSONEnvelope(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Tool          string         `json:"tool"`
		SchemaVersion int            `json:"schema_version"`
		OK            bool           `json:"ok"`
		Failing       int            `json:"failing"`
		Summary       map[string]int `json:"summary"`
		Commits       []struct {
			Status  string `json:"status"`
			Session string `json:"session"`
		} `json:"commits"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env.Tool != "botsign" || env.SchemaVersion != 1 || env.OK || env.Failing != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	if env.Summary["verified"] != 1 || env.Summary["unsigned"] != 1 {
		t.Fatalf("summary = %v", env.Summary)
	}
	if len(env.Commits) != 3 || env.Commits[1].Session != "claude-code-12ab34cd" {
		t.Fatalf("commits = %+v", env.Commits)
	}

	// An empty report must serialize commits as [], not null.
	var empty bytes.Buffer
	if err := JSON(&empty, &verify.Report{Counts: map[verify.Status]int{}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(empty.String(), `"commits": []`) {
		t.Fatalf("commits must be [] for consumers, got:\n%s", empty.String())
	}
}
