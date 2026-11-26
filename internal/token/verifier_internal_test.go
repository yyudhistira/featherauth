package token

import (
	"errors"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

func verifierFor(t *testing.T, kid string, ks signers) (*Verifier, *config.Realm) {
	t.Helper()
	r := &config.Realm{Name: "main", Keys: []config.Key{{Kid: kid, State: "active"}}}
	return NewVerifier(clock.NewFake(time.Unix(1_700_000_000, 0)), fakeSecrets{keys: ks}), r
}

// Covers: SEC-16 (part)
func TestKeySetCacheIsPerRealmPointer(t *testing.T) {
	k1, k2 := rsaKey(t), rsaKey(t)
	v, r1 := verifierFor(t, "a", signers{"a": k1, "b": k2})
	r2 := &config.Realm{Name: "other", Keys: []config.Key{{Kid: "b", State: "active"}}}
	s1, err := v.keySet(r1)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := v.keySet(r1)
	if s1 != again {
		t.Error("the key set of the same realm pointer is rebuilt")
	}
	s2, err := v.keySet(r2)
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Error("another realm pointer shares a key set")
	}
	if _, _, ok := s2.Lookup("a"); ok {
		t.Error("the second key set holds a key of the first realm")
	}
}

// Covers: SEC-16 (part)
func TestKeySetCacheHoldsOneEntryPerRealmName(t *testing.T) {
	k1, k2 := rsaKey(t), rsaKey(t)
	v, r1 := verifierFor(t, "a", signers{"a": k1, "b": k2})
	s1, err := v.keySet(r1)
	if err != nil {
		t.Fatal(err)
	}
	// A reload: the same realm name with a new pointer replaces the entry.
	r2 := &config.Realm{Name: r1.Name, Keys: []config.Key{{Kid: "b", State: "active"}}}
	s2, err := v.keySet(r2)
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Error("a new realm pointer reused the old key set")
	}
	if _, _, ok := s2.Lookup("b"); !ok {
		t.Error("the new key set lacks the new key")
	}
	if len(v.sets) != 1 {
		t.Errorf("cache holds %d entries for one realm", len(v.sets))
	}
	if again, _ := v.keySet(r2); again != s2 {
		t.Error("the new snapshot is rebuilt on every call")
	}
	r3 := &config.Realm{Name: "second", Keys: r1.Keys}
	if _, err := v.keySet(r3); err != nil {
		t.Fatal(err)
	}
	if len(v.sets) != 2 {
		t.Errorf("cache holds %d entries for two realms", len(v.sets))
	}
}

func TestVerifierReportsKeySetErrors(t *testing.T) {
	v, r := verifierFor(t, "missing", signers{})
	if _, err := v.keySet(r); err == nil {
		t.Fatal("a realm with an unloaded key built a key set")
	}
	if _, err := v.Access(r, "a.b.c"); err == nil || errors.Is(err, ErrExpired) {
		t.Fatalf("Access: err = %v", err)
	}
	if _, err := v.IDTokenHint(nil, "a.b.c"); err == nil {
		t.Fatal("nil realm accepted")
	}
}
