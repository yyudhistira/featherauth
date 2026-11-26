package secure_test

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/secure"
)

var base64url = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Covers: SEC-08 (part)
func TestTokenLengths(t *testing.T) {
	// 16 bytes is the 128 bits SEC-08 requires for state and nonce; 32 bytes
	// is used for refresh tokens and codes.
	for nBytes, wantLen := range map[int]int{16: 22, 32: 43} {
		tok, err := secure.Token(secure.Default, nBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != wantLen {
			t.Errorf("Token(%d) has %d characters, want %d", nBytes, len(tok), wantLen)
		}
		if !base64url.MatchString(tok) {
			t.Errorf("Token(%d) = %q is not unpadded base64url", nBytes, tok)
		}
	}
}

func TestTokenIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok, err := secure.Token(secure.Default, 16)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestTokenUsesTheSource(t *testing.T) {
	src := bytes.NewReader(bytes.Repeat([]byte{0xff}, 16))
	tok, err := secure.Token(src, 16)
	if err != nil {
		t.Fatal(err)
	}
	if want := "_____________________w"; tok != want {
		t.Fatalf("Token = %q, want %q", tok, want)
	}
}

var errBroken = errors.New("broken source")

type brokenSource struct{}

func (brokenSource) Read([]byte) (int, error) { return 0, errBroken }

func TestTokenErrors(t *testing.T) {
	if _, err := secure.Token(brokenSource{}, 16); !errors.Is(err, errBroken) {
		t.Errorf("broken source: err = %v, want %v", err, errBroken)
	}
	if _, err := secure.Token(bytes.NewReader([]byte{1, 2, 3}), 16); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short source: err = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	for _, n := range []int{0, -1} {
		if _, err := secure.Token(secure.Default, n); err == nil {
			t.Errorf("Token(%d) gave no error", n)
		}
	}
}

func TestNewIDVectors(t *testing.T) {
	cases := []struct {
		name   string
		at     time.Time
		random byte
		want   string
	}{
		{"smallest", time.UnixMilli(0), 0x00, "00000000000000000000000000"},
		{"largest", time.UnixMilli(1<<48 - 1), 0xff, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := bytes.NewReader(bytes.Repeat([]byte{c.random}, 10))
			id, err := secure.NewID(src, clock.NewFake(c.at))
			if err != nil {
				t.Fatal(err)
			}
			if id != c.want {
				t.Fatalf("NewID = %q, want %q", id, c.want)
			}
		})
	}
}

func TestNewIDSortsByCreationTime(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	var ids []string
	for i := 0; i < 100; i++ {
		id, err := secure.NewID(secure.Default, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 26 {
			t.Fatalf("id %q has %d characters, want 26", id, len(id))
		}
		ids = append(ids, id)
		c.Advance(time.Millisecond)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("ids created a millisecond apart do not sort by creation time")
	}
}

func TestNewIDErrors(t *testing.T) {
	now := clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	if _, err := secure.NewID(brokenSource{}, now); !errors.Is(err, errBroken) {
		t.Errorf("broken source: err = %v, want %v", err, errBroken)
	}
	for name, at := range map[string]time.Time{
		"before 1970":       time.UnixMilli(-1),
		"after 48-bit time": time.UnixMilli(1 << 48),
	} {
		if _, err := secure.NewID(secure.Default, clock.NewFake(at)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestHashOf(t *testing.T) {
	// SHA-256 test vector from FIPS 180-2.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := secure.HashOf("abc"); got != secure.Hash(want) {
		t.Fatalf("HashOf(abc) = %s, want %s", got, want)
	}
}

func TestEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"secret", "secret", true},
		{"secret", "secreT", false},
		{"secret", "secret1", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := secure.Equal(c.a, c.b); got != c.want {
			t.Errorf("Equal(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Covers: FR-22 (part)
func TestNewUUID(t *testing.T) {
	tests := []struct {
		name string
		fill byte
		want string
	}{
		{"all ones keep their bits except version and variant", 0xff, "ffffffff-ffff-4fff-bfff-ffffffffffff"},
		{"all zeros get the version and the variant", 0x00, "00000000-0000-4000-8000-000000000000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := secure.NewUUID(bytes.NewReader(bytes.Repeat([]byte{tc.fill}, 16)))
			if err != nil || got != tc.want {
				t.Fatalf("NewUUID = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		got, err := secure.NewUUID(secure.Default)
		if err != nil {
			t.Fatal(err)
		}
		if !uuidV4.MatchString(got) {
			t.Fatalf("NewUUID = %q, not a lowercase version 4 UUID", got)
		}
		if seen[got] {
			t.Fatalf("NewUUID repeated %q", got)
		}
		seen[got] = true
	}
}

// Covers: FR-22 (part)
func TestNewUUIDErrors(t *testing.T) {
	if _, err := secure.NewUUID(brokenSource{}); !errors.Is(err, errBroken) {
		t.Errorf("broken source: err = %v, want %v", err, errBroken)
	}
	if _, err := secure.NewUUID(bytes.NewReader(make([]byte, 8))); err == nil {
		t.Error("short source: want an error")
	}
}

var alnum = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// Covers: FR-40
func TestAlphanumeric(t *testing.T) {
	got, err := secure.Alphanumeric(secure.Default, 22)
	if err != nil || len(got) != 22 || !alnum.MatchString(got) {
		t.Fatalf("Alphanumeric = %q, %v, want 22 letters and digits", got, err)
	}
	// The mapping, and the bytes that would favour a character (248 and
	// above) are skipped: 0 A, 25 Z, 26 a, 51 z, 52 0, 61 9, 62 A again, 247 9.
	src := bytes.NewReader([]byte{0, 25, 26, 51, 52, 61, 62, 248, 255, 247})
	if got, err := secure.Alphanumeric(src, 8); err != nil || got != "AZaz09A9" {
		t.Errorf("Alphanumeric from fixed bytes = %q, %v, want AZaz09A9", got, err)
	}
	seen := map[string]bool{}
	for range 1000 {
		s, err := secure.Alphanumeric(secure.Default, 22)
		if err != nil || seen[s] {
			t.Fatalf("repeated or failed: %q %v", s, err)
		}
		seen[s] = true
	}
}

// Covers: FR-40
func TestAlphanumericErrors(t *testing.T) {
	if _, err := secure.Alphanumeric(secure.Default, 0); err == nil {
		t.Error("a length of 0 was accepted")
	}
	if _, err := secure.Alphanumeric(bytes.NewReader([]byte{1, 2}), 5); err == nil {
		t.Error("a short source was accepted")
	}
	if _, err := secure.Alphanumeric(errReader{}, 5); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("err = %v, want the source's error", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
