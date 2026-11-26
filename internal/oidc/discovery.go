package oidc

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
)

// tokenClaims are the claims every token carries, listed after the claims
// selected by user_data.claims in claims_supported.
var tokenClaims = []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "sid", "nonce", "at_hash"}

// discoveryDoc is the discovery document. The field order is the order of the
// design's table.
type discoveryDoc struct {
	Issuer                       string   `json:"issuer"`
	AuthorizationEndpoint        string   `json:"authorization_endpoint"`
	TokenEndpoint                string   `json:"token_endpoint"`
	UserinfoEndpoint             string   `json:"userinfo_endpoint"`
	JWKSURI                      string   `json:"jwks_uri"`
	EndSessionEndpoint           string   `json:"end_session_endpoint"`
	RevocationEndpoint           string   `json:"revocation_endpoint"`
	TokenEndpointAuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
	RevocationAuthMethods        []string `json:"revocation_endpoint_auth_methods_supported"`
	ResponseTypes                []string `json:"response_types_supported"`
	SubjectTypes                 []string `json:"subject_types_supported"`
	IDTokenSigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes                       []string `json:"scopes_supported"`
	Claims                       []string `json:"claims_supported"`
	ResponseModes                []string `json:"response_modes_supported"`
	GrantTypes                   []string `json:"grant_types_supported"`
	CodeChallengeMethods         []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIss     bool     `json:"authorization_response_iss_parameter_supported"`
	RequestParameterSupported    bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported bool     `json:"request_uri_parameter_supported"`
	ClaimsParameterSupported     bool     `json:"claims_parameter_supported"`
	BackchannelLogoutSupported   bool     `json:"backchannel_logout_supported"`
	BackchannelSessionSupported  bool     `json:"backchannel_logout_session_supported"`
	// DPoPSigningAlgs lists the algorithms of DPoP proofs when a client of the
	// realm has dpop other than off (FR-44); omitted otherwise.
	DPoPSigningAlgs []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

func buildDiscovery(r *config.Realm) []byte {
	doc := discoveryDoc{
		Issuer:                      r.Issuer(),
		AuthorizationEndpoint:       r.EndpointURL(config.EndpointAuthorize, ""),
		TokenEndpoint:               r.EndpointURL(config.EndpointToken, ""),
		UserinfoEndpoint:            r.EndpointURL(config.EndpointUserinfo, ""),
		JWKSURI:                     r.EndpointURL(config.EndpointJWKS, ""),
		EndSessionEndpoint:          r.EndpointURL(config.EndpointLogout, ""),
		RevocationEndpoint:          r.EndpointURL(config.EndpointRevoke, ""),
		TokenEndpointAuthMethods:    []string{"client_secret_basic", "client_secret_post", "none"},
		RevocationAuthMethods:       []string{"client_secret_basic", "client_secret_post", "none"},
		ResponseTypes:               []string{"code"},
		SubjectTypes:                []string{"public"},
		IDTokenSigningAlgs:          []string{"RS256"},
		Scopes:                      []string{"openid"},
		Claims:                      append(slices.Clone(r.UserData.Claims), tokenClaims...),
		ResponseModes:               []string{"query", "fragment", "form_post"},
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		CodeChallengeMethods:        []string{"S256"},
		AuthorizationResponseIss:    true,
		BackchannelLogoutSupported:  true,
		BackchannelSessionSupported: true,
	}
	if realmHasDPoP(r) {
		doc.DPoPSigningAlgs = []string{"ES256", "RS256"}
	}
	b, _ := json.Marshal(doc) // a plain struct: Marshal cannot fail
	return b
}

// Discovery serves the discovery document of a realm. The document is built
// once per configuration snapshot and realm and kept until the snapshot
// changes.
type Discovery struct{ cache realmCache }

// NewDiscovery returns the discovery handler.
func NewDiscovery() *Discovery { return &Discovery{} }

// document returns the cached document of the realm of snap.
func (d *Discovery) document(snap *config.Snapshot, r *config.Realm) []byte {
	b, _ := d.cache.get(snap, r, func() ([]byte, error) { return buildDiscovery(r), nil })
	return b
}

// ServeHTTP answers with the realm's discovery document; the realm and the
// snapshot come from the request context (server.FromContext).
func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	serveCached(w, d.document(info.Snapshot, info.Realm))
}

var _ http.Handler = (*Discovery)(nil)

// realmHasDPoP reports whether a client of the realm has the dpop option other
// than off.
func realmHasDPoP(r *config.Realm) bool {
	for _, cl := range r.Clients {
		if cl.DPoP != config.DPoPOff {
			return true
		}
	}
	return false
}
