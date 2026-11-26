package oidc

import (
	"context"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-10 (part)
func TestJWKSDocumentIsCachedPerSnapshot(t *testing.T) {
	l, _ := testutil.NewConfigDir(t, "public_url: https://auth.example.com\n", map[string]string{"main": testutil.MinimalRealm("main")})
	j := NewJWKS()
	snap1 := l.Current()
	realm, _ := snap1.Realm("main")

	a, err := j.document(snap1, realm)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := j.document(snap1, realm); &a[0] != &b[0] {
		t.Error("the key set was rebuilt for the same snapshot")
	}
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	snap2 := l.Current()
	realm2, _ := snap2.Realm("main")
	c, _ := j.document(snap2, realm2)
	if &c[0] == &a[0] {
		t.Error("the cache survived a new snapshot")
	}
}

// Covers: FR-10 (part)
func TestJWKSDocumentWithoutSecretsFails(t *testing.T) {
	l, _ := testutil.NewConfigDir(t, "public_url: https://auth.example.com\n", map[string]string{"main": testutil.MinimalRealm("main")})
	realm, _ := l.Current().Realm("main")
	bare := config.NewSnapshot(&config.ServerFile{}, nil, nil, nil)
	j := NewJWKS()
	if _, err := j.document(bare, realm); err == nil {
		t.Fatal("no error without secrets")
	}
	if len(j.cache.docs) != 0 {
		t.Error("a failure was cached")
	}
}
