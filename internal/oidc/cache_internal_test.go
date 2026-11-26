package oidc

import (
	"errors"
	"sync"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
)

func cacheRealm(name string) *config.Realm { return &config.Realm{Name: config.RealmName(name)} }

// Covers: FR-01 (part)
func TestRealmCacheSlowBuildDoesNotBlockOtherRealms(t *testing.T) {
	var c realmCache
	snap := &config.Snapshot{}
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.get(snap, cacheRealm("a"), func() ([]byte, error) {
			close(started)
			<-release
			return []byte("a"), nil
		})
	}()
	<-started
	b, err := c.get(snap, cacheRealm("b"), func() ([]byte, error) { return []byte("b"), nil })
	if err != nil || string(b) != "b" {
		t.Errorf("realm b: %q, %v", b, err)
	}
	close(release)
	<-done
}

// Covers: FR-01 (part)
func TestRealmCacheConcurrentGetsReturnOneDocument(t *testing.T) {
	var c realmCache
	snap := &config.Snapshot{}
	realm := cacheRealm("a")
	const n = 32
	results := make([][]byte, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = c.get(snap, realm, func() ([]byte, error) { return []byte{byte(i)}, nil })
		}()
	}
	wg.Wait()
	for i, r := range results {
		if len(r) != 1 || &r[0] != &results[0][0] {
			t.Fatalf("caller %d got a different document", i)
		}
	}
}

// Covers: FR-01 (part)
func TestRealmCacheFailedBuildIsNotCached(t *testing.T) {
	var c realmCache
	snap, realm := &config.Snapshot{}, cacheRealm("a")
	boom := errors.New("boom")
	if _, err := c.get(snap, realm, func() ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("error: %v", err)
	}
	b, err := c.get(snap, realm, func() ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(b) != "ok" {
		t.Errorf("retry: %q, %v", b, err)
	}
}

// Covers: FR-01 (part)
func TestRealmCacheStaleBuildIsNotStoredInNewSnapshot(t *testing.T) {
	var c realmCache
	old, cur := &config.Snapshot{}, &config.Snapshot{}
	realm := cacheRealm("a")
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	releaseOld := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { releaseOld(); <-done })
	go func() {
		defer close(done)
		_, _ = c.get(old, realm, func() ([]byte, error) {
			close(started)
			<-release
			return []byte("old"), nil
		})
	}()
	<-started
	// Make cur the current snapshot while its cache stays empty: the failed
	// build is not stored.
	boom := errors.New("boom")
	if _, err := c.get(cur, realm, func() ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("error: %v", err)
	}
	releaseOld()
	<-done
	built := false
	b, _ := c.get(cur, realm, func() ([]byte, error) { built = true; return []byte("rebuilt"), nil })
	if !built || string(b) != "rebuilt" {
		t.Errorf("the new snapshot's cache holds %q (built %v)", b, built)
	}
}
