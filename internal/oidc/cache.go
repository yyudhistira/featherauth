package oidc

import (
	"net/http"
	"sync"

	"github.com/yyudhistira/featherauth/internal/config"
)

// realmCache keeps one document (bytes) per realm for one configuration
// snapshot. When a different snapshot is asked for, the cache starts empty.
// A failed build is not cached.
type realmCache struct {
	mu   sync.Mutex
	snap *config.Snapshot
	docs map[config.RealmName][]byte
}

// get returns the cached document of the realm of snap, building it with build
// on a miss. The build runs outside the lock, so a slow realm does not block
// the others. Concurrent first requests may both build; the first stored
// result wins and every caller of the same snapshot and realm gets it. A
// build for a snapshot that is no longer current is returned to its caller but
// never stored.
func (c *realmCache) get(snap *config.Snapshot, r *config.Realm, build func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	c.reset(snap)
	if b, ok := c.docs[r.Name]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()

	b, err := build()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap != snap {
		return b, nil
	}
	if first, ok := c.docs[r.Name]; ok {
		return first, nil
	}
	c.docs[r.Name] = b
	return b, nil
}

// reset starts an empty cache when snap differs from the cached snapshot. The
// caller holds c.mu.
func (c *realmCache) reset(snap *config.Snapshot) {
	if c.snap != snap {
		c.snap, c.docs = snap, map[config.RealmName][]byte{}
	}
}

// serveCached writes a public JSON document with the cache headers shared by
// the discovery and JWKS endpoints.
func serveCached(w http.ResponseWriter, b []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}
