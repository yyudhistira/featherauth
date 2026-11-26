// Package secure holds the random sources, identifiers, hashing and
// constant-time comparison that the rest of the service uses. It is the only
// package besides clock allowed to read a random source directly.
package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// Source is a random source. Default is the operating system's.
type Source = io.Reader

// Default is crypto/rand. Tests pass a fixed reader instead.
var Default Source = rand.Reader

// Token returns nBytes random bytes as unpadded base64url: 16 bytes give 22
// characters (the 128 bits SEC-08 asks for state and nonce), 32 bytes give 43.
func Token(src Source, nBytes int) (string, error) {
	if nBytes <= 0 {
		return "", fmt.Errorf("secure: token size %d must be positive", nBytes)
	}
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(src, b); err != nil {
		return "", fmt.Errorf("secure: reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// crockford is the base32 alphabet of ULIDs.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID: 48 bits of milliseconds since 1970 followed by 80
// random bits, as 26 characters. IDs from later milliseconds sort after
// earlier ones.
func NewID(src Source, c clock.Clock) (string, error) {
	ms := c.Now().UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return "", fmt.Errorf("secure: time %v is outside the ULID range", c.Now())
	}
	var b [16]byte
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	if _, err := io.ReadFull(src, b[6:]); err != nil {
		return "", fmt.Errorf("secure: reading random bytes: %w", err)
	}

	// Encode 128 bits as 26 groups of 5 bits (the top 2 of 130 are zero).
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	var out [26]byte
	for i := range out {
		shift := uint(125 - 5*i) // bit offset of this group from the least significant bit
		var v uint64
		switch {
		case shift >= 64:
			v = hi >> (shift - 64)
		case shift+5 <= 64:
			v = lo >> shift
		default:
			v = lo>>shift | hi<<(64-shift)
		}
		out[i] = crockford[v&31]
	}
	return string(out[:]), nil
}

// NewUUID returns a random version 4 UUID in lowercase hyphenated form
// (8-4-4-4-12), the format of a user id when a realm's user_data.id_format is
// uuid.
func NewUUID(src Source) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(src, b[:]); err != nil {
		return "", fmt.Errorf("secure: reading random bytes: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant 10
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:], b[10:])
	return string(out[:]), nil
}

// Hash is a hex-encoded SHA-256 digest. Codes, refresh tokens and handoff ids
// are stored and looked up only by their Hash.
type Hash string

// HashOf returns the SHA-256 digest of s.
func HashOf(s string) Hash {
	sum := sha256.Sum256([]byte(s))
	return Hash(hex.EncodeToString(sum[:]))
}

// Equal compares two secrets in constant time (for equal lengths).
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Alphanumeric returns n random ASCII letters and digits. Every character is
// equally likely: a random byte of 248 or more (the last partial run of the
// 62-character alphabet) is skipped.
func Alphanumeric(src Source, n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("secure: length %d must be positive", n)
	}
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		b := buf[:n-len(out)]
		if _, err := io.ReadFull(src, b); err != nil {
			return "", fmt.Errorf("secure: reading random bytes: %w", err)
		}
		for _, c := range b {
			if c < 248 {
				out = append(out, alphanumeric[int(c)%len(alphanumeric)])
			}
		}
	}
	return string(out), nil
}
