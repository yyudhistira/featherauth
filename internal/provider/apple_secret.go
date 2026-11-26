package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// AppleAudience is the aud of Apple's client secret.
const AppleAudience = "https://appleid.apple.com"

// AppleSecretOptions are the settings of the client secret.
type AppleSecretOptions struct {
	TeamID        string // iss
	KeyID         string // kid
	ServicesID    string // sub, the provider's client_id
	PrivateKeyPEM []byte // the .p8 file, PKCS 8 PEM of an EC P-256 key
	Lifetime      time.Duration
	Clock         clock.Clock
}

// AppleSecret makes Apple's client secret: an ES256 JWT signed with the .p8
// key, generated each time it is asked for.
type AppleSecret struct {
	teamID, keyID, servicesID string
	key                       *ecdsa.PrivateKey
	lifetime                  time.Duration
	clk                       clock.Clock
}

// NewAppleSecret checks the options and parses the key.
func NewAppleSecret(o AppleSecretOptions) (*AppleSecret, error) {
	switch {
	case o.TeamID == "" || o.KeyID == "" || o.ServicesID == "":
		return nil, errors.New("provider: apple: the team id, key id and services id are required")
	case o.Lifetime <= 0 || o.Lifetime > config.MaxAppleSecretLifetime:
		return nil, errors.New("provider: apple: the client secret lifetime must be above zero and at most six months")
	case o.Clock == nil:
		return nil, errors.New("provider: apple: no clock")
	}
	block, _ := pem.Decode(o.PrivateKeyPEM)
	if block == nil {
		return nil, errors.New("provider: apple: the private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("provider: apple: the private key is not a PKCS 8 key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("provider: apple: the private key must be an EC P-256 key")
	}
	return &AppleSecret{
		teamID: o.TeamID, keyID: o.KeyID, servicesID: o.ServicesID, key: key, lifetime: o.Lifetime, clk: o.Clock,
	}, nil
}

// Secret returns a new client secret: header kid = Key ID; claims iss = Team
// ID, sub = Services ID, aud = AppleAudience, iat now and exp = iat plus the
// lifetime.
func (a *AppleSecret) Secret() (string, error) {
	now := a.clk.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": a.teamID, "sub": a.servicesID, "aud": AppleAudience,
		"iat": now.Unix(), "exp": now.Add(a.lifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	h := jws.NewHeaders()
	if err := h.Set(jws.KeyIDKey, a.keyID); err != nil {
		return "", err
	}
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), a.key, jws.WithProtectedHeaders(h)))
	if err != nil {
		return "", fmt.Errorf("provider: apple: signing the client secret: %w", err)
	}
	return string(out), nil
}

// LogValue implements slog.LogValuer. The private key is never logged.
func (a AppleSecret) LogValue() slog.Value {
	return slog.GroupValue(slog.String("team_id", a.teamID), slog.String("key_id", a.keyID))
}

var _ slog.LogValuer = AppleSecret{}
