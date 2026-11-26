package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ErrUnknownKey means a sealed value carries the id of a key the Box does not
// hold, for example after the key that sealed it was removed.
var ErrUnknownKey = errors.New("secure: sealed value uses an unknown key")

const (
	boxKeySize = 32
	keyIDSize  = 8
)

// Box encrypts small secrets (provider refresh tokens) with AES-GCM. It seals
// with the first key and opens with any. A sealed value is the key id, a ".",
// and the unpadded base64url of a 12-byte nonce followed by the ciphertext.
// A Box logs only how many keys it holds (it implements slog.LogValuer).
type Box struct {
	src   Source
	first string
	aeads map[string]cipher.AEAD
}

var _ slog.LogValuer = (*Box)(nil)

// NewBox returns a Box for keys of 32 bytes; the first key seals. The keys are
// copied.
func NewBox(keys [][]byte) (*Box, error) { return newBox(keys, Default) }

// newBox is NewBox with the source of nonces given, for tests.
func newBox(keys [][]byte, src Source) (*Box, error) {
	if len(keys) == 0 {
		return nil, errors.New("secure: a box needs at least one key")
	}
	b := &Box{src: src, aeads: make(map[string]cipher.AEAD, len(keys))}
	for i, k := range keys {
		if len(k) != boxKeySize {
			return nil, fmt.Errorf("secure: encryption key %d has %d bytes, want %d", i+1, len(k), boxKeySize)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("secure: encryption key %d: %w", i+1, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secure: encryption key %d: %w", i+1, err)
		}
		id := KeyID(k)
		if i == 0 {
			b.first = id
		}
		b.aeads[id] = aead
	}
	return b, nil
}

// KeyID returns the id of a key: the first 8 hex characters of the SHA-256 of
// its raw bytes.
func KeyID(key []byte) string { return string(HashOf(string(key)))[:keyIDSize] }

// ValidKeyID reports whether s is a key id: exactly 8 lowercase hex characters.
func ValidKeyID(s string) bool {
	if len(s) != keyIDSize {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FirstKeyID returns the id of the key that seals.
func (b *Box) FirstKeyID() string { return b.first }

// HasKey reports whether the box holds the key with this id.
func (b *Box) HasKey(id string) bool { _, ok := b.aeads[id]; return ok }

// LogValue logs the number of keys and nothing else.
func (b *Box) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("key_count", len(b.aeads)))
}

// Seal encrypts plain with the first key. The key id is bound to the
// ciphertext as additional data.
func (b *Box) Seal(plain []byte) (string, error) {
	aead := b.aeads[b.first]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := io.ReadFull(b.src, nonce); err != nil {
		return "", fmt.Errorf("secure: reading random bytes: %w", err)
	}
	body := aead.Seal(nonce, nonce, plain, []byte(b.first))
	return b.first + "." + base64.RawURLEncoding.EncodeToString(body), nil
}

// Open decrypts a value made by Seal with any of the box's keys. It returns
// ErrUnknownKey when no key has the value's key id.
func (b *Box) Open(sealed string) ([]byte, error) {
	id, enc, ok := strings.Cut(sealed, ".")
	if !ok {
		return nil, errors.New("secure: sealed value has no key id")
	}
	aead, ok := b.aeads[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil {
		return nil, errors.New("secure: sealed value is not base64url")
	}
	n := aead.NonceSize()
	if len(body) < n+aead.Overhead() {
		return nil, errors.New("secure: sealed value is too short")
	}
	plain, err := aead.Open(nil, body[:n], body[n:], []byte(id))
	if err != nil {
		return nil, errors.New("secure: sealed value does not authenticate")
	}
	return plain, nil
}
