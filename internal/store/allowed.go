package store

// allowed.go parses the ssh-keygen ALLOWED SIGNERS format (see
// ssh-keygen(1)): `principals [options] keytype base64-key`. botsign both
// writes this format (WriteAllowedSigners, ExportLine) and reads it (the
// import path, and the `-Y verify` / `-Y find-principals` compatibility
// modes that git invokes).

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// AllowedSigner is one parsed allowed_signers line.
type AllowedSigner struct {
	Principals []string // comma-separated first field, split
	Namespaces []string // from a namespaces="a,b" option; empty = any
	KeyType    string
	KeyBlob    []byte // decoded key material
}

// PermitsNamespace reports whether the entry is valid for a signature
// namespace, honoring the ssh-keygen rule that no namespaces option means
// "any namespace".
func (a *AllowedSigner) PermitsNamespace(ns string) bool {
	if len(a.Namespaces) == 0 {
		return true
	}
	for _, allowed := range a.Namespaces {
		if allowed == ns {
			return true
		}
	}
	return false
}

// ParseAllowedSigner parses a single non-comment allowed_signers line.
func ParseAllowedSigner(line string) (*AllowedSigner, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return nil, fmt.Errorf("allowed_signers line needs `principals [options] keytype base64`, got %d fields", len(fields))
	}
	entry := &AllowedSigner{Principals: strings.Split(fields[0], ",")}

	// Everything between the principals and the key type is options.
	rest := fields[1:]
	for len(rest) > 0 && strings.Contains(rest[0], "=") && !strings.HasPrefix(rest[0], "ssh-") {
		opt := rest[0]
		rest = rest[1:]
		key, value, _ := strings.Cut(opt, "=")
		if strings.EqualFold(key, "namespaces") {
			entry.Namespaces = strings.Split(strings.Trim(value, `"`), ",")
		}
		// Other options (valid-after, cert-authority, …) are tolerated
		// but not enforced in 0.1.0.
	}
	if len(rest) < 2 {
		return nil, fmt.Errorf("allowed_signers line %q is missing the key", line)
	}
	entry.KeyType = rest[0]
	blob, err := base64.StdEncoding.DecodeString(rest[1])
	if err != nil {
		return nil, fmt.Errorf("bad key base64 in allowed_signers line: %v", err)
	}
	entry.KeyBlob = blob
	return entry, nil
}

// ParseAllowedSigners parses a whole file, skipping blanks and comments.
func ParseAllowedSigners(data []byte) ([]*AllowedSigner, error) {
	var entries []*AllowedSigner
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := ParseAllowedSigner(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo+1, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
