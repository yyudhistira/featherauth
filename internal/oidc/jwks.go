package oidc

import (
	"net/http"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// JWKS serves the public keys of a realm. The key set document comes from
// token.KeySet and is built once per configuration snapshot and realm.
type JWKS struct{ cache realmCache }

// NewJWKS returns the JWKS handler.
func NewJWKS() *JWKS { return &JWKS{} }

// document returns the cached JWKS of the realm of snap.
func (j *JWKS) document(snap *config.Snapshot, r *config.Realm) ([]byte, error) {
	return j.cache.get(snap, r, func() ([]byte, error) {
		ks, err := token.NewKeySet(r, snap.Secrets())
		if err != nil {
			return nil, err
		}
		return ks.JWKS(), nil
	})
}

// ServeHTTP answers with the realm's key set; the realm and the snapshot come
// from the request context (server.FromContext).
func (j *JWKS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	b, err := j.document(info.Snapshot, info.Realm)
	if err != nil {
		serverError(w, r, info)
		return
	}
	serveCached(w, b)
}

var _ http.Handler = (*JWKS)(nil)
