package secure_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
)

func boxKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newBox(t *testing.T, keys ...[]byte) *secure.Box {
	t.Helper()
	b, err := secure.NewBox(keys)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SEC-10 (part)
func TestBoxRoundTrip(t *testing.T) {
	b := newBox(t, boxKey(1))
	sealed, err := b.Seal([]byte("apple-refresh-token"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "apple-refresh-token") {
		t.Fatal("sealed value holds the plaintext")
	}
	got, err := b.Open(sealed)
	if err != nil || string(got) != "apple-refresh-token" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	again, _ := b.Seal([]byte("apple-refresh-token"))
	if again == sealed {
		t.Error("two seals of one value are equal; the nonce is not fresh")
	}
	empty, err := b.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Open(empty); err != nil || len(got) != 0 {
		t.Errorf("empty round trip = %q, %v", got, err)
	}
}

// Covers: SEC-10 (part)
func TestBoxSealedCarriesKeyID(t *testing.T) {
	k := boxKey(1)
	id := string(secure.HashOf(string(k)))[:8]
	sealed, err := newBox(t, k).Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, id+".") {
		t.Errorf("sealed %q does not start with key id %q", sealed, id)
	}
}

// Covers: SEC-10 (part)
// Acceptance: Encryption key rotation (part)
func TestBoxRotation(t *testing.T) {
	oldKey, newKey := boxKey(1), boxKey(2)
	sealedOld, err := newBox(t, oldKey).Seal([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}

	both := newBox(t, newKey, oldKey)
	if got, err := both.Open(sealedOld); err != nil || string(got) != "token" {
		t.Fatalf("old value with both keys: %q, %v", got, err)
	}
	sealedNew, _ := both.Seal([]byte("token2"))
	if _, err := newBox(t, newKey).Open(sealedNew); err != nil {
		t.Errorf("new value is not sealed with the first key: %v", err)
	}
	if _, err := newBox(t, oldKey).Open(sealedNew); !errors.Is(err, secure.ErrUnknownKey) {
		t.Errorf("new value with only the old key: %v, want ErrUnknownKey", err)
	}

	if _, err := newBox(t, newKey).Open(sealedOld); !errors.Is(err, secure.ErrUnknownKey) {
		t.Errorf("old value with the old key removed: %v, want ErrUnknownKey", err)
	}
}

// Covers: SEC-10 (part)
func TestBoxRejectsChangedOrMalformedValues(t *testing.T) {
	b := newBox(t, boxKey(1))
	sealed, _ := b.Seal([]byte("token"))
	dot := strings.IndexByte(sealed, '.')
	flip := func(i int) string {
		c := []byte(sealed)
		if c[i] == 'A' {
			c[i] = 'B'
		} else {
			c[i] = 'A'
		}
		return string(c)
	}
	cases := []struct {
		name   string
		in     string
		unknwn bool
	}{
		{"changed first body byte", flip(dot + 1), false},
		{"changed last byte", flip(len(sealed) - 1), false},
		{"truncated", sealed[:len(sealed)-4], false},
		{"nonce only", sealed[:dot+1] + "AAAA", false},
		{"empty", "", false},
		{"no separator", "abcdef12", false},
		{"empty body", sealed[:dot+1], false},
		{"not base64", sealed[:dot+1] + "!!!", false},
		{"unknown key id", "00000000" + sealed[dot:], true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := b.Open(c.in)
			if err == nil {
				t.Fatalf("Open succeeded with %q", got)
			}
			if errors.Is(err, secure.ErrUnknownKey) != c.unknwn {
				t.Errorf("ErrUnknownKey = %v for %v", !c.unknwn, err)
			}
		})
	}
	// a value moved under another key id does not open either
	other := newBox(t, boxKey(2), boxKey(1))
	s2, _ := other.Seal([]byte("t"))
	forged := string(secure.HashOf(string(boxKey(1))))[:8] + s2[dot:]
	if _, err := other.Open(forged); err == nil {
		t.Error("value under the wrong key id opened")
	}
}

// Covers: SEC-10 (part)
func TestNewBoxValidatesKeys(t *testing.T) {
	cases := []struct {
		name string
		keys [][]byte
	}{
		{"none", nil},
		{"short", [][]byte{make([]byte, 16)}},
		{"long", [][]byte{make([]byte, 33)}},
		{"second bad", [][]byte{boxKey(1), make([]byte, 5)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := secure.NewBox(c.keys); err == nil {
				t.Error("NewBox accepted the keys")
			}
		})
	}
}

// Covers: SEC-10 (part)
func TestNewBoxCopiesKeys(t *testing.T) {
	k := boxKey(1)
	b := newBox(t, k)
	sealed, _ := b.Seal([]byte("x"))
	for i := range k {
		k[i] = 0
	}
	if _, err := b.Open(sealed); err != nil {
		t.Errorf("box depends on the caller's slice: %v", err)
	}
}

// Covers: SEC-13 (part)
func TestBoxLogsNoKeyMaterial(t *testing.T) {
	k1, k2 := boxKey(0x41), boxKey(0x42)
	b := newBox(t, k1, k2)
	sealed, _ := b.Seal([]byte("secret-plain"))
	forbidden := []string{string(k1), string(k2), "QUFBQUFB", "QkJCQkJC", sealed,
		string(secure.HashOf(string(k1)))[:8], string(secure.HashOf(string(k2)))[:8]}
	cases := map[string]func(l *slog.Logger){
		"direct":     func(l *slog.Logger) { l.Info("m", "box", b) },
		"nested map": func(l *slog.Logger) { l.Info("m", "details", map[string]any{"box": b, "in": map[string]any{"x": b}}) },
		"group":      func(l *slog.Logger) { l.Info("m", slog.Group("g", slog.Any("box", b))) },
	}
	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log(logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0))))
			out := buf.String()
			if !strings.Contains(out, `"key_count":2`) {
				t.Errorf("log lacks key_count: %s", out)
			}
			for _, f := range forbidden {
				if strings.Contains(out, f) {
					t.Errorf("log holds %q", f)
				}
			}
		})
	}
	var _ slog.LogValuer = b
}

// The id of a key, the id of the first key and the id format the key commands
// accept (SEC-43, SEC-47).
//
// Covers: SEC-43 (part), SEC-47 (part)
func TestKeyIDsAndTheirFormat(t *testing.T) {
	k1, k2 := boxKey(1), boxKey(2)
	id1, id2 := secure.KeyID(k1), secure.KeyID(k2)
	if id1 != string(secure.HashOf(string(k1)))[:8] || id1 == id2 || !secure.ValidKeyID(id1) {
		t.Fatalf("ids %q %q", id1, id2)
	}
	b := newBox(t, k2, k1)
	if b.FirstKeyID() != id2 || !b.HasKey(id1) || !b.HasKey(id2) || b.HasKey("00000000") {
		t.Fatalf("first %q, has %v %v", b.FirstKeyID(), b.HasKey(id1), b.HasKey(id2))
	}
	for id, want := range map[string]bool{
		"0123abcd": true, "ABCDEF12": false, "0123abc": false, "0123abcde": false,
		"0123abcg": false, "": false, "0123abc ": false, "0123abc\n": false, "0123abcé": false,
	} {
		if got := secure.ValidKeyID(id); got != want {
			t.Errorf("ValidKeyID(%q) = %v, want %v", id, got, want)
		}
	}
}

// A sealed value has exactly one valid spelling: the base64url of the body must
// be canonical, so a last character with non-zero unused bits is refused even
// though the loose decoding would give the same bytes.
//
// Covers: SEC-10 (part)
func TestBoxRefusesANonCanonicalSpelling(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := newBox(t, boxKey(1))
	// Six bytes of plaintext make a 34-byte body: the last character carries
	// four unused bits, which Seal leaves at zero.
	sealed, err := b.Seal([]byte("tokens"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Open(sealed); err != nil || string(got) != "tokens" {
		t.Fatalf("the canonical value does not open: %q, %v", got, err)
	}
	last := strings.IndexByte(alphabet, sealed[len(sealed)-1])
	if last < 0 || last&0x0f != 0 {
		t.Fatalf("the last character %q has unused bits set", sealed[len(sealed)-1])
	}
	for bit := 1; bit < 16; bit++ {
		spelled := sealed[:len(sealed)-1] + string(alphabet[last|bit])
		if got, err := b.Open(spelled); err == nil {
			t.Fatalf("Open accepted a non-canonical spelling (low bits %#x): %q", bit, got)
		}
	}
}
