// Wire-encoding tests: the RFC 4251 primitives everything else in the
// package is built from. A silent off-by-one here would corrupt every key
// and signature, so round-trips and truncation are pinned exactly.
package sshsig

import (
	"bytes"
	"testing"
)

func TestBufferStringRoundTrip(t *testing.T) {
	var w buffer
	w.uint32(7)
	w.str([]byte("hello"))
	w.str(nil)
	w.raw([]byte{0xff})

	r := reader{b: w.b}
	if got := r.uint32(); got != 7 {
		t.Fatalf("uint32 = %d, want 7", got)
	}
	if got := r.str(); got != "hello" {
		t.Fatalf("str = %q, want hello", got)
	}
	if got := r.bytes(); len(got) != 0 {
		t.Fatalf("empty string decoded to %d bytes", len(got))
	}
	if rest := r.rest(); !bytes.Equal(rest, []byte{0xff}) {
		t.Fatalf("rest = %v, want [0xff]", rest)
	}
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
}

func TestReaderErrorsStickAndCoverAllShapes(t *testing.T) {
	// A string header claiming 100 bytes with only 2 available must fail,
	// and every later read must be an inert no-op — that is what lets
	// decoders check err once at the end.
	var w buffer
	w.uint32(100)
	w.raw([]byte{1, 2})
	r := reader{b: w.b}
	if got := r.bytes(); got != nil {
		t.Fatalf("truncated read returned %v", got)
	}
	if r.err == nil {
		t.Fatal("expected a truncation error")
	}
	if got := r.uint32(); got != 0 {
		t.Fatalf("read after error returned %d, want 0", got)
	}
	if got := r.rest(); got != nil {
		t.Fatalf("rest after error returned %v, want nil", got)
	}

	// Three bytes cannot hold a uint32.
	short := reader{b: []byte{0, 0, 1}}
	short.uint32()
	if short.err == nil {
		t.Fatal("short uint32 must error")
	}

	// A literal mismatch (wrong magic) must error too.
	lit := reader{b: []byte("SSHSIG....")}
	lit.literal([]byte("OPENSSH"), "magic")
	if lit.err == nil {
		t.Fatal("literal mismatch must set an error")
	}
}
