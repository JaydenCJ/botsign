package gitio

// commit.go parses raw commit objects (the exact bytes of
// `git cat-file commit <sha>`). The one subtlety botsign lives and dies
// by: when git signs a commit, the signed payload is the commit object
// with the entire multi-line `gpgsig` header removed and everything else
// byte-identical. Payload reconstruction therefore works on raw bytes and
// never re-serializes headers.

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Identity is a parsed author/committer line.
type Identity struct {
	Name  string
	Email string
	When  time.Time
}

// Commit is a parsed commit object.
type Commit struct {
	SHA       string
	Author    Identity
	Committer Identity
	GPGSig    []byte // armored signature from the gpgsig header, or nil
	Payload   []byte // raw object minus the gpgsig header: what was signed
	Subject   string // first line of the commit message
}

// ShortSHA returns the 7-character abbreviation used in reports.
func (c *Commit) ShortSHA() string {
	if len(c.SHA) < 7 {
		return c.SHA
	}
	return c.SHA[:7]
}

// ParseCommit parses raw commit bytes. It extracts the author, committer,
// and optional gpgsig header, and reconstructs the signed payload by
// removing the gpgsig block (header line plus its space-prefixed
// continuation lines) from the raw bytes.
func ParseCommit(sha string, raw []byte) (*Commit, error) {
	headerEnd := bytes.Index(raw, []byte("\n\n"))
	if headerEnd < 0 {
		return nil, fmt.Errorf("commit %s: no header/body separator", sha)
	}
	c := &Commit{SHA: sha}

	// Walk header lines, tracking the byte range of each logical header
	// (first line plus continuations) so gpgsig can be excised exactly.
	lineStart := 0
	var sigStart, sigEnd = -1, -1
	var haveAuthor, haveCommitter bool
	for lineStart < headerEnd {
		nl := bytes.IndexByte(raw[lineStart:headerEnd+1], '\n')
		if nl < 0 {
			nl = headerEnd - lineStart
		}
		lineEnd := lineStart + nl + 1 // past the newline

		// Continuation lines belong to the previous header.
		blockEnd := lineEnd
		for blockEnd <= headerEnd && raw[blockEnd] == ' ' {
			cnl := bytes.IndexByte(raw[blockEnd:headerEnd+1], '\n')
			if cnl < 0 {
				break
			}
			blockEnd += cnl + 1
		}

		line := raw[lineStart : lineEnd-1]
		key, value, _ := bytes.Cut(line, []byte(" "))
		switch string(key) {
		case "author":
			id, err := parseIdentity(string(value))
			if err != nil {
				return nil, fmt.Errorf("commit %s: %v", sha, err)
			}
			c.Author, haveAuthor = id, true
		case "committer":
			id, err := parseIdentity(string(value))
			if err != nil {
				return nil, fmt.Errorf("commit %s: %v", sha, err)
			}
			c.Committer, haveCommitter = id, true
		case "gpgsig":
			sigStart, sigEnd = lineStart, blockEnd
			c.GPGSig = unfoldHeader(raw[lineStart:blockEnd])
		}
		lineStart = blockEnd
	}
	if !haveAuthor || !haveCommitter {
		return nil, fmt.Errorf("commit %s: missing author or committer header", sha)
	}

	if sigStart >= 0 {
		c.Payload = append(append([]byte{}, raw[:sigStart]...), raw[sigEnd:]...)
	} else {
		c.Payload = raw
	}

	body := raw[headerEnd+2:]
	if nl := bytes.IndexByte(body, '\n'); nl >= 0 {
		c.Subject = string(body[:nl])
	} else {
		c.Subject = string(body)
	}
	return c, nil
}

// unfoldHeader reverses git's header folding: drop the "gpgsig " prefix
// and the single leading space of every continuation line. Git strips the
// value's trailing newline when folding, so the armor parser downstream
// tolerates its absence.
func unfoldHeader(block []byte) []byte {
	lines := bytes.Split(bytes.TrimSuffix(block, []byte("\n")), []byte("\n"))
	var out [][]byte
	for i, line := range lines {
		if i == 0 {
			_, value, _ := bytes.Cut(line, []byte(" "))
			out = append(out, value)
			continue
		}
		out = append(out, bytes.TrimPrefix(line, []byte(" ")))
	}
	return bytes.Join(out, []byte("\n"))
}

// parseIdentity parses `Name <email> epoch tz` from the right, because
// names may contain anything except '<'.
func parseIdentity(s string) (Identity, error) {
	open := strings.LastIndex(s, "<")
	shut := strings.LastIndex(s, ">")
	if open < 0 || shut < open {
		return Identity{}, fmt.Errorf("bad identity %q: missing <email>", s)
	}
	id := Identity{
		Name:  strings.TrimSpace(s[:open]),
		Email: s[open+1 : shut],
	}
	fields := strings.Fields(s[shut+1:])
	if len(fields) != 2 {
		return Identity{}, fmt.Errorf("bad identity %q: want epoch and timezone after email", s)
	}
	epoch, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("bad identity timestamp %q", fields[0])
	}
	loc, err := parseTZ(fields[1])
	if err != nil {
		return Identity{}, err
	}
	id.When = time.Unix(epoch, 0).In(loc)
	return id, nil
}

// parseTZ converts a git offset like +0900 or -0430 into a fixed zone.
func parseTZ(tz string) (*time.Location, error) {
	if len(tz) != 5 || (tz[0] != '+' && tz[0] != '-') {
		return nil, errors.New("bad timezone " + strconv.Quote(tz))
	}
	hours, err1 := strconv.Atoi(tz[1:3])
	mins, err2 := strconv.Atoi(tz[3:5])
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad timezone " + strconv.Quote(tz))
	}
	offset := (hours*60 + mins) * 60
	if tz[0] == '-' {
		offset = -offset
	}
	return time.FixedZone(tz, offset), nil
}
