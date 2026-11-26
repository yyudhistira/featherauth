package oidc

import (
	"context"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-01 (part)
func TestDiscoveryDocumentIsCachedPerSnapshot(t *testing.T) {
	l, _ := testutil.NewConfigDir(t, "public_url: https://auth.example.com\n", map[string]string{"main": testutil.MinimalRealm("main")})
	d := NewDiscovery()
	snap1 := l.Current()
	realm, _ := snap1.Realm("main")

	a, b := d.document(snap1, realm), d.document(snap1, realm)
	if &a[0] != &b[0] {
		t.Error("the document was rebuilt for the same snapshot")
	}

	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	snap2 := l.Current()
	if snap2 == snap1 {
		t.Fatal("reload kept the snapshot")
	}
	realm2, _ := snap2.Realm("main")
	c := d.document(snap2, realm2)
	if &c[0] == &a[0] {
		t.Error("the cache survived a new snapshot")
	}
	if e := d.document(snap2, realm2); &e[0] != &c[0] {
		t.Error("the new snapshot's document was not cached")
	}
}
