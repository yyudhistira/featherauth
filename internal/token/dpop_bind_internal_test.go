package token

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const bindURL = "https://auth.example.com/main/token"

var bindNow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// bindProof returns a proof of key for the token endpoint, with its jti.
func bindProof(t *testing.T, key any, jti string) []string {
	t.Helper()
	return []string{testutil.DPoPProof(t, key, nil, map[string]any{
		"htm": "POST", "htu": bindURL, "iat": bindNow.Unix(), "jti": jti,
	})}
}

// dpopThumbprintOf is the thumbprint of the key of a proof, as VerifyDPoP reads it.
func dpopThumbprintOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	p, err := VerifyDPoP(bindProof(t, k, "thumb-probe"), "POST", bindURL, "", bindNow)
	if err != nil {
		t.Fatal(err)
	}
	return p.Thumbprint
}

// wantCode checks that err is a grant refusal with the code.
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != code {
		t.Fatalf("err = %v, want grant error %s", err, code)
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// bindNew: off binds nothing, required refuses a request without a proof, a
// proof that fails or was used before is refused, and a passing proof binds a
// public client's session and only the access token of a confidential one.
func TestBindNewRules(t *testing.T) {
	k, _ := testutil.ECKey(t)
	thumb := dpopThumbprintOf(t, k)
	st := testutil.NewStore(t)
	ctx := context.Background()
	req := func(h []string) DPoPRequest { return DPoPRequest{Header: h, Method: "POST", URL: bindURL} }
	run := func(cl *config.Client, r DPoPRequest) (binding, error) {
		var b binding
		err := st.Write(ctx, func(tx store.Tx) (err error) {
			b, err = bindNew(ctx, tx, cl, r, bindNow)
			return err
		})
		return b, err
	}
	pub := func(m config.DPoPMode) *config.Client { return &config.Client{Type: config.Public, DPoP: m} }
	conf := func(m config.DPoPMode) *config.Client { return &config.Client{Type: config.Confidential, DPoP: m} }

	if b, err := run(pub(config.DPoPOff), req(bindProof(t, k, "off-1"))); err != nil || b != (binding{}) {
		t.Fatalf("off: %+v, %v", b, err)
	}
	if b, err := run(pub(config.DPoPAllowed), req(nil)); err != nil || b != (binding{}) {
		t.Fatalf("allowed without a proof: %+v, %v", b, err)
	}
	_, err := run(pub(config.DPoPRequired), req(nil))
	wantCode(t, err, CodeInvalidRequest)
	_, err = run(pub(config.DPoPAllowed), req([]string{"not-a-proof"}))
	wantCode(t, err, CodeInvalidDPoPProof)
	b, err := run(pub(config.DPoPAllowed), req(bindProof(t, k, "pub-1")))
	if err != nil || b != (binding{access: thumb, refresh: thumb}) {
		t.Fatalf("public: %+v, %v", b, err)
	}
	_, err = run(pub(config.DPoPAllowed), req(bindProof(t, k, "pub-1")))
	wantCode(t, err, CodeInvalidDPoPProof)
	b, err = run(conf(config.DPoPAllowed), req(bindProof(t, k, "conf-1")))
	if err != nil || b != (binding{access: thumb}) {
		t.Fatalf("confidential: %+v, %v", b, err)
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// bindRefresh: a bound token needs its key, and the key must match; an unbound
// token answers Bearer for a public client, and bound for a confidential one.
func TestBindRefreshRules(t *testing.T) {
	k, _ := testutil.ECKey(t)
	other, _ := testutil.ECKey(t)
	thumb := dpopThumbprintOf(t, k)
	ctx := context.Background()
	st := testutil.NewStore(t)
	run := func(cl *config.Client, rt store.RefreshToken, h []string) (binding, error) {
		var b binding
		err := st.Write(ctx, func(tx store.Tx) (err error) {
			b, err = bindRefresh(ctx, tx, cl, rt, DPoPRequest{Header: h, Method: "POST", URL: bindURL}, bindNow)
			return err
		})
		return b, err
	}
	bound := store.RefreshToken{DPoPJKT: thumb}
	unbound := store.RefreshToken{}
	pub := func(m config.DPoPMode) *config.Client { return &config.Client{Type: config.Public, DPoP: m} }
	conf := func(m config.DPoPMode) *config.Client { return &config.Client{Type: config.Confidential, DPoP: m} }

	if b, err := run(pub(config.DPoPOff), unbound, nil); err != nil || b != (binding{}) {
		t.Fatalf("off, unbound: %+v, %v", b, err)
	}
	_, err := run(pub(config.DPoPAllowed), bound, nil)
	wantCode(t, err, CodeInvalidRequest)
	_, err = run(pub(config.DPoPOff), bound, nil)
	wantCode(t, err, CodeInvalidRequest)
	_, err = run(pub(config.DPoPRequired), unbound, nil)
	wantCode(t, err, CodeInvalidRequest)
	if b, err := run(pub(config.DPoPAllowed), unbound, nil); err != nil || b != (binding{}) {
		t.Fatalf("allowed, unbound, no proof: %+v, %v", b, err)
	}
	_, err = run(pub(config.DPoPAllowed), bound, []string{"not-a-proof"})
	wantCode(t, err, CodeInvalidDPoPProof)
	_, err = run(pub(config.DPoPAllowed), bound, bindProof(t, other, "wrong-key"))
	wantCode(t, err, CodeInvalidGrant)
	b, err := run(pub(config.DPoPAllowed), bound, bindProof(t, k, "same-key"))
	if err != nil || b != (binding{access: thumb, refresh: thumb}) {
		t.Fatalf("bound, same key: %+v, %v", b, err)
	}
	_, err = run(pub(config.DPoPAllowed), bound, bindProof(t, k, "same-key"))
	wantCode(t, err, CodeInvalidDPoPProof)
	b, err = run(pub(config.DPoPAllowed), unbound, bindProof(t, k, "unbound-public"))
	if err != nil || b != (binding{}) {
		t.Fatalf("unbound public with a proof: %+v, %v", b, err)
	}
	b, err = run(conf(config.DPoPAllowed), unbound, bindProof(t, k, "unbound-conf"))
	if err != nil || b != (binding{access: thumb}) {
		t.Fatalf("unbound confidential with a proof: %+v, %v", b, err)
	}
	// A dpop off client ignores a proof sent with an unbound token: the answer
	// is Bearer, whatever the client type, and the proof's jti is not remembered.
	for _, cl := range []*config.Client{pub(config.DPoPOff), conf(config.DPoPOff)} {
		if b, err := run(cl, unbound, bindProof(t, k, "off-unbound")); err != nil || b != (binding{}) {
			t.Fatalf("off, unbound, with a proof: %+v, %v", b, err)
		}
	}
	b, err = run(pub(config.DPoPAllowed), unbound, bindProof(t, k, "off-unbound"))
	if err != nil || b != (binding{}) {
		t.Fatalf("the jti of an ignored proof was remembered: %+v, %v", b, err)
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding (part)
// A malformed endpoint URL is a configuration error: the binding returns it as
// it is, not as a refusal of the proof, for a code and for a refresh token.
func TestBindingMalformedEndpointIsAConfigurationError(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	cl := &config.Client{Type: config.Public, DPoP: config.DPoPAllowed}
	req := DPoPRequest{Header: []string{"x.y.z"}, Method: "POST", URL: "https://[::1/t"}
	err := st.Write(ctx, func(tx store.Tx) error {
		if _, err := bindNew(ctx, tx, cl, req, bindNow); err == nil || errors.Is(err, ErrDPoPProof) {
			t.Errorf("bindNew err = %v, want a configuration error", err)
		}
		_, err := bindRefresh(ctx, tx, cl, store.RefreshToken{DPoPJKT: "thumb"}, req, bindNow)
		if err == nil || errors.Is(err, ErrDPoPProof) {
			t.Errorf("bindRefresh err = %v, want a configuration error", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
