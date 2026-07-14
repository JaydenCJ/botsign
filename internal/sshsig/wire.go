// Package sshsig implements the pieces of the OpenSSH ecosystem that
// botsign needs to mint and verify Ed25519 signing keys without shelling
// out to ssh-keygen: the SSH wire encoding (RFC 4251 §5), the
// openssh-key-v1 private key container, authorized_keys public key lines,
// and the SSHSIG detached-signature format (OpenSSH PROTOCOL.sshsig).
// Everything is pure standard library.
package sshsig

import (
	"encoding/binary"
	"errors"
)

// errTruncated is returned whenever a wire structure ends mid-field.
var errTruncated = errors.New("truncated ssh wire data")

// buffer builds SSH wire structures. All writes are infallible.
type buffer struct {
	b []byte
}

// uint32 appends a big-endian 32-bit length or counter.
func (w *buffer) uint32(v uint32) {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
}

// str appends an RFC 4251 `string`: a uint32 length prefix plus the bytes.
func (w *buffer) str(p []byte) {
	w.uint32(uint32(len(p)))
	w.b = append(w.b, p...)
}

// raw appends bytes verbatim, with no length prefix.
func (w *buffer) raw(p []byte) {
	w.b = append(w.b, p...)
}

// reader consumes SSH wire structures. The first decoding error sticks and
// turns every subsequent read into a no-op, so callers can decode a whole
// struct and check err once at the end.
type reader struct {
	b   []byte
	err error
}

func (r *reader) uint32() uint32 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 4 {
		r.err = errTruncated
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) bytes() []byte {
	n := r.uint32()
	if r.err != nil {
		return nil
	}
	if uint64(len(r.b)) < uint64(n) {
		r.err = errTruncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) str() string {
	return string(r.bytes())
}

// literal consumes exactly the given bytes and records an error otherwise.
func (r *reader) literal(want []byte, what string) {
	if r.err != nil {
		return
	}
	if len(r.b) < len(want) || string(r.b[:len(want)]) != string(want) {
		r.err = errors.New("bad " + what)
		return
	}
	r.b = r.b[len(want):]
}

// rest returns everything not yet consumed.
func (r *reader) rest() []byte {
	if r.err != nil {
		return nil
	}
	return r.b
}
