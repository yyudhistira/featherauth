package secure

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// Covers: SEC-10 (part)
func TestBoxSealFailsWhenSourceFails(t *testing.T) {
	b, err := newBox([][]byte{testKey(1)}, failReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Seal([]byte("x")); err == nil {
		t.Error("Seal succeeded without randomness")
	}
}

// Covers: SEC-10 (part)
func TestBoxFixedSourceGivesDeterministicNonce(t *testing.T) {
	mk := func() *Box {
		b, err := newBox([][]byte{testKey(1)}, bytes.NewReader(bytes.Repeat([]byte{7}, 12)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, err1 := mk().Seal([]byte("x"))
	c, err2 := mk().Seal([]byte("x"))
	if err1 != nil || err2 != nil || a != c {
		t.Fatalf("seals differ: %q %q (%v, %v)", a, c, err1, err2)
	}
	if !strings.Contains(a, ".BwcHBwcHBwcHBwcH") { // base64url of twelve 0x07 bytes
		t.Errorf("sealed %q does not start with the fixed nonce", a)
	}
}

// Covers: SEC-10 (part)
func TestBoxDuplicateKeysCollapse(t *testing.T) {
	b, err := NewBox([][]byte{testKey(1), testKey(2), testKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.aeads) != 2 {
		t.Errorf("box holds %d keys, want 2 distinct", len(b.aeads))
	}
	sealed, _ := b.Seal([]byte("x"))
	if got, err := b.Open(sealed); err != nil || string(got) != "x" {
		t.Errorf("Open = %q, %v", got, err)
	}
}
