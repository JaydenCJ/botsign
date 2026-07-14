package sshsig

// armor.go handles the PEM-like ASCII armor OpenSSH wraps its binary
// containers in. OpenSSH is not strict PEM: private keys wrap base64 at 70
// columns, SSHSIG signatures at 76, and there are no headers between the
// BEGIN line and the payload. The decoder is deliberately tolerant (CRLF,
// stray blank lines, any wrap width) because git and forges re-wrap
// signatures in transit.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// armor encodes data as an OpenSSH ASCII-armored block with the given
// label ("OPENSSH PRIVATE KEY", "SSH SIGNATURE") and base64 line width.
func armor(label string, width int, data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var out bytes.Buffer
	fmt.Fprintf(&out, "-----BEGIN %s-----\n", label)
	for len(enc) > width {
		out.WriteString(enc[:width])
		out.WriteByte('\n')
		enc = enc[width:]
	}
	out.WriteString(enc)
	out.WriteByte('\n')
	fmt.Fprintf(&out, "-----END %s-----\n", label)
	return out.Bytes()
}

// dearmor decodes an armored block, requiring the given label. It accepts
// CRLF line endings, surrounding whitespace, and any base64 wrap width.
func dearmor(label string, in []byte) ([]byte, error) {
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
	text := strings.ReplaceAll(string(in), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	var b64 strings.Builder
	state := 0 // 0 = before BEGIN, 1 = inside, 2 = after END
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch state {
		case 0:
			if line == begin {
				state = 1
			}
		case 1:
			if line == end {
				state = 2
				continue
			}
			b64.WriteString(line)
		}
	}
	if state == 0 {
		return nil, fmt.Errorf("missing %q header", begin)
	}
	if state == 1 {
		return nil, fmt.Errorf("missing %q footer", end)
	}
	data, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("bad base64 in %s block: %v", label, err)
	}
	return data, nil
}
