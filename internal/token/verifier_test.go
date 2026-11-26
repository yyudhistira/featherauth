package token_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

func (e *env) verifier() *token.Verifier { return token.NewVerifier(e.clock, e.secrets) }

func mustID(t *testing.T, e *env, access string) string {
	t.Helper()
	raw, err := e.issuer.ID(e.realm, e.client("web"), testSubject(), testSession(), access)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRefresh(t *testing.T, e *env) string {
	t.Helper()
	raw, err := e.issuer.RefreshJWT(e.realm, e.client("web"), testSubject(), testSession(), issueTime.Add(time.Hour), "j1")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// forge signs claims with a header chosen by the test, using the realm's key
// for kid (or the private key of signKid when it differs).
func forge(t testing.TB, e *env, alg, typ, kid, signKid, claims string) string {
	t.Helper()
	h := jws.NewHeaders()
	if typ != "" {
		_ = h.Set(jws.TypeKey, typ)
	}
	if kid != "" {
		_ = h.Set(jws.KeyIDKey, kid)
	}
	var opt jws.SignOption
	if alg == "none" {
		opt = jws.WithInsecureNoSignature(jws.WithProtectedHeaders(h))
	} else {
		opt = jws.WithKey(mustAlg(t, alg), e.secrets.Signing(signKid), jws.WithProtectedHeaders(h))
	}
	out, err := jws.Sign([]byte(claims), opt)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func accessClaimsJSON(e *env, iss string, exp time.Time) string {
	return `{"iss":"` + iss + `","sub":"u1","aud":"web","exp":` + itoa(exp.Unix()) + `,"iat":1}`
}

func itoa(n int64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// Covers: SEC-20 (part), SEC-14 (part)
func TestAccessRoundTripForEachAlgorithm(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			e := newEnv(t, alg, "")
			raw, exp := mustAccess(t, e, "plain", testSubject(), testSession())
			got, err := e.verifier().Access(e.realm, raw)
			if err != nil {
				t.Fatalf("Access: %v", err)
			}
			want := token.AccessClaims{
				Sub: "u1", Aud: "https://api.example.com", ClientID: "plain", Azp: "plain",
				Sid: "s1", Scope: "openid", Exp: exp, Iat: issueTime, Jti: jtiOf,
				AuthTime: issueTime.Add(-time.Minute),
			}
			if got != want {
				t.Fatalf("claims = %+v, want %+v", got, want)
			}
		})
	}
}

// Covers: SEC-20 (part), SEC-14 (part)
func TestIDTokenHintRoundTrip(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			e := newEnv(t, alg, "")
			raw := mustID(t, e, "at")
			got, err := e.verifier().IDTokenHint(e.realm, raw)
			if err != nil {
				t.Fatalf("IDTokenHint: %v", err)
			}
			want := token.HintClaims{Sub: "u1", Sid: "s1", Aud: "web", Exp: issueTime.Add(15 * time.Minute)}
			if got != want {
				t.Fatalf("claims = %+v, want %+v", got, want)
			}
		})
	}
}

// Covers: SEC-20 (part), SEC-14 (part)
// Acceptance: Token swap (part)
func TestSwapMatrix(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		e := newEnv(t, alg, "")
		v := e.verifier()
		access, _ := mustAccess(t, e, "web", testSubject(), testSession())
		id := mustID(t, e, access)
		refresh := mustRefresh(t, e)
		rows := []struct {
			name string
			raw  string
			hint bool
		}{
			{"ID token as access token", id, false},
			{"refresh JWT as access token", refresh, false},
			{"access token as hint", access, true},
			{"refresh JWT as hint", refresh, true},
		}
		for _, row := range rows {
			t.Run(alg+" "+row.name, func(t *testing.T) {
				var err error
				if row.hint {
					_, err = v.IDTokenHint(e.realm, row.raw)
				} else {
					_, err = v.Access(e.realm, row.raw)
				}
				if !errors.Is(err, token.ErrWrongType) {
					t.Fatalf("err = %v, want ErrWrongType", err)
				}
			})
		}
	}
}

// Covers: SEC-20 (part), SEC-14 (part)
func TestMissingTypIsWrongType(t *testing.T) {
	e := newEnv(t, "RS256", "")
	raw := forge(t, e, "RS256", "", "rsa-new", "rsa-new", accessClaimsJSON(e, e.realm.Issuer(), issueTime.Add(time.Hour)))
	if _, err := e.verifier().Access(e.realm, raw); !errors.Is(err, token.ErrWrongType) {
		t.Fatalf("err = %v, want ErrWrongType", err)
	}
}

// twoRealms loads realms main and other with distinct kids, and returns the
// environment of main plus a token issuer for other.
func twoRealms(t *testing.T) (main, other *config.Realm, secrets config.Secrets, fc *clock.Fake) {
	t.Helper()
	realm := func(name, kid string) string {
		return "name: " + name + "\nkeys:\n  - { kid: " + kid + "-new, file: secrets/" + kid + "-new.pem, state: active }\n" +
			"  - { kid: " + kid + "-old, file: secrets/" + kid + "-old.pem, state: verify_only }\n" +
			"providers:\n  google:\n    enabled: true\n    client_id: 1234.apps.googleusercontent.com\n    client_secret_file: secrets/google_secret\n" +
			"clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n"
	}
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", realm("main", "m"))
	d.Realm(t, "other", realm("other", "o"))
	for _, f := range []string{"m-new", "m-old", "o-new", "o-old"} {
		// Distinct keys: the shared fixture key would make every kid verify.
		pem, err := token.GenerateRSA(token.DefaultRSABits)
		if err != nil {
			t.Fatal(err)
		}
		d.Write(t, "secrets/"+f+".pem", string(pem))
	}
	d.Secret(t, "secrets/google_secret")
	fc = clock.NewFake(issueTime)
	l, err := config.NewLoader(d.Root, fc, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	main, _ = snap.Realm("main")
	other, _ = snap.Realm("other")
	if main == nil || other == nil {
		t.Fatal("realms missing")
	}
	return main, other, snap.Secrets(), fc
}

// Covers: SEC-16 (part)
// Acceptance: Realm isolation (part)
func TestTokensOfAnotherRealmAreRejected(t *testing.T) {
	main, other, secrets, fc := twoRealms(t)
	iss := token.NewIssuer(fc, fixedSource(), secrets)
	v := token.NewVerifier(fc, secrets)
	acc, _, err := iss.Access(other, other.Clients["web"], testSubject(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	id, err := iss.ID(other, other.Clients["web"], testSubject(), testSession(), acc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Access(main, acc); !errors.Is(err, token.ErrWrongRealm) {
		t.Fatalf("access: err = %v, want ErrWrongRealm", err)
	}
	if _, err := v.IDTokenHint(main, id); !errors.Is(err, token.ErrWrongRealm) {
		t.Fatalf("hint: err = %v, want ErrWrongRealm", err)
	}
	// The token verifies in its own realm.
	if _, err := v.Access(other, acc); err != nil {
		t.Fatalf("own realm: %v", err)
	}
	if _, err := v.IDTokenHint(other, id); err != nil {
		t.Fatalf("own realm hint: %v", err)
	}
}

// Covers: SEC-16 (part)
// Acceptance: Realm isolation (part)
func TestMatchingIssuerSignedByAnotherRealmKeyIsASignatureError(t *testing.T) {
	main, other, secrets, fc := twoRealms(t)
	_ = other
	e := &env{realm: main, secrets: secrets, clock: fc}
	claims := accessClaimsJSON(e, main.Issuer(), issueTime.Add(time.Hour))
	raw := forge(t, e, "RS256", "at+jwt", "o-new", "o-new", claims)
	if _, err := token.NewVerifier(fc, secrets).Access(main, raw); !errors.Is(err, token.ErrSignature) {
		t.Fatalf("other realm kid: err = %v, want ErrSignature", err)
	}
	// Main's kid in the header, other realm's private key.
	raw = forge(t, e, "RS256", "at+jwt", "m-new", "o-new", claims)
	if _, err := token.NewVerifier(fc, secrets).Access(main, raw); !errors.Is(err, token.ErrSignature) {
		t.Fatalf("wrong key: err = %v, want ErrSignature", err)
	}
}

// Covers: SEC-07 (part)
func TestVerifyOnlyKeyIsAccepted(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			e := newEnv(t, alg, "")
			v := e.verifier()
			claims := accessClaimsJSON(e, e.realm.Issuer(), issueTime.Add(time.Hour))
			// rsa-old is verify-only; it signs RS256 tokens only.
			if alg == "RS256" {
				raw := forge(t, e, "RS256", "at+jwt", "rsa-old", "rsa-old", claims)
				if _, err := v.Access(e.realm, raw); err != nil {
					t.Fatalf("Access with verify-only key: %v", err)
				}
			}
			idClaims := `{"iss":"` + e.realm.Issuer() + `","sub":"u1","aud":"web","sid":"s1","exp":1}`
			hint := forge(t, e, "RS256", "JWT", "rsa-old", "rsa-old", idClaims)
			if _, err := v.IDTokenHint(e.realm, hint); err != nil {
				t.Fatalf("hint with verify-only key: %v", err)
			}
		})
	}
}

// Covers: SEC-20 (part)
func TestAccessSignatureRules(t *testing.T) {
	e := newEnv(t, "ES256", "")
	v := e.verifier()
	good, _ := mustAccess(t, e, "web", testSubject(), testSession())
	parts := strings.Split(good, ".")
	tamperedSig := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"
	claims := accessClaimsJSON(e, e.realm.Issuer(), issueTime.Add(time.Hour))
	forgedClaims := accessClaimsJSON(e, e.realm.Issuer(), issueTime.Add(48*time.Hour))
	tamperedPayload := parts[0] + "." + strings.Split(forge(t, e, "ES256", "at+jwt", "ec-new", "ec-new", forgedClaims), ".")[1] + "." + parts[2]
	rows := []struct{ name, raw string }{
		{"tampered signature", tamperedSig},
		{"tampered payload", tamperedPayload},
		{"alg none", forge(t, e, "none", "at+jwt", "ec-new", "", claims)},
		{"alg RS256 in an ES256 realm", forge(t, e, "RS256", "at+jwt", "rsa-new", "rsa-new", claims)},
		{"alg ES256 with an RSA kid", forge(t, e, "ES256", "at+jwt", "rsa-new", "ec-new", claims)},
		{"missing kid", forge(t, e, "ES256", "at+jwt", "", "ec-new", claims)},
		{"unknown kid", forge(t, e, "ES256", "at+jwt", "nope", "ec-new", claims)},
		{"not a JWT", "garbage"},
		{"empty", ""},
		{"payload not JSON", forge(t, e, "ES256", "at+jwt", "ec-new", "ec-new", "not json")},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := v.Access(e.realm, row.raw); !errors.Is(err, token.ErrSignature) {
				t.Fatalf("err = %v, want ErrSignature", err)
			}
		})
	}
}

// Covers: SEC-20 (part)
func TestHintSignatureRules(t *testing.T) {
	e := newEnv(t, "ES256", "")
	v := e.verifier()
	claims := `{"iss":"` + e.realm.Issuer() + `","sub":"u1","aud":"web","sid":"s1","exp":1}`
	rows := []struct{ name, raw string }{
		{"ES256 hint", forge(t, e, "ES256", "JWT", "ec-new", "ec-new", claims)},
		{"alg none", forge(t, e, "none", "JWT", "rsa-new", "", claims)},
		{"missing kid", forge(t, e, "RS256", "JWT", "", "rsa-new", claims)},
		{"not a JWT", "a.b"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := v.IDTokenHint(e.realm, row.raw); !errors.Is(err, token.ErrSignature) {
				t.Fatalf("err = %v, want ErrSignature", err)
			}
		})
	}
}

// Covers: SEC-14 (part)
func TestNoClockLeewayForAccessTokens(t *testing.T) {
	e := newEnv(t, "RS256", "")
	v := e.verifier()
	raw, exp := mustAccess(t, e, "web", testSubject(), testSession())
	e.clock.Set(exp.Add(-time.Second))
	if _, err := v.Access(e.realm, raw); err != nil {
		t.Fatalf("one second before exp: %v", err)
	}
	e.clock.Set(exp)
	if _, err := v.Access(e.realm, raw); !errors.Is(err, token.ErrExpired) {
		t.Fatalf("at exp: err = %v, want ErrExpired", err)
	}
	e.clock.Set(exp.Add(time.Second))
	if _, err := v.Access(e.realm, raw); !errors.Is(err, token.ErrExpired) {
		t.Fatalf("one second after exp: err = %v, want ErrExpired", err)
	}
}

// Covers: SEC-14 (part)
func TestExpiredHintIsAccepted(t *testing.T) {
	e := newEnv(t, "RS256", "")
	raw := mustID(t, e, "at")
	e.clock.Advance(1000 * time.Hour)
	got, err := e.verifier().IDTokenHint(e.realm, raw)
	if err != nil {
		t.Fatalf("expired hint: %v", err)
	}
	if got.Sid != "s1" || got.Aud != "web" {
		t.Fatalf("claims = %+v", got)
	}
}

// Covers: SEC-14 (part)
func TestAccessWithoutExpIsExpired(t *testing.T) {
	e := newEnv(t, "RS256", "")
	raw := forge(t, e, "RS256", "at+jwt", "rsa-new", "rsa-new", `{"iss":"`+e.realm.Issuer()+`","sub":"u1"}`)
	if _, err := e.verifier().Access(e.realm, raw); !errors.Is(err, token.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// A tampered token is a signature error even when it has also expired.
func TestSignatureIsCheckedBeforeExpiry(t *testing.T) {
	e := newEnv(t, "RS256", "")
	raw, exp := mustAccess(t, e, "web", testSubject(), testSession())
	e.clock.Set(exp.Add(time.Hour))
	parts := strings.Split(raw, ".")
	raw = parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"
	if _, err := e.verifier().Access(e.realm, raw); !errors.Is(err, token.ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestAccessIgnoresTheAudience(t *testing.T) {
	e := newEnv(t, "RS256", "")
	raw := forge(t, e, "RS256", "at+jwt", "rsa-new", "rsa-new",
		`{"iss":"`+e.realm.Issuer()+`","sub":"u1","aud":"anything","exp":`+itoa(issueTime.Add(time.Hour).Unix())+`}`)
	if _, err := e.verifier().Access(e.realm, raw); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifierIsSafeForConcurrentUse(t *testing.T) {
	e := newEnv(t, "RS256", "")
	v := e.verifier()
	raw, _ := mustAccess(t, e, "web", testSubject(), testSession())
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := v.Access(e.realm, raw); err != nil {
					t.Errorf("Access: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRealmPointersGetTheirOwnKeys(t *testing.T) {
	main, other, secrets, fc := twoRealms(t)
	iss := token.NewIssuer(fc, fixedSource(), secrets)
	v := token.NewVerifier(fc, secrets)
	a1, _, _ := iss.Access(main, main.Clients["web"], testSubject(), testSession())
	a2, _, _ := iss.Access(other, other.Clients["web"], testSubject(), testSession())
	for i := 0; i < 2; i++ { // second round uses the cache
		if _, err := v.Access(main, a1); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Access(other, a2); err != nil {
			t.Fatal(err)
		}
	}
}

// Covers: SEC-07 (part)
func TestVerifyOnlyKeyOfTheRealmVerifiesAndOtherKeysDoNot(t *testing.T) {
	main, _, secrets, fc := twoRealms(t)
	e := &env{realm: main, secrets: secrets, clock: fc}
	v := token.NewVerifier(fc, secrets)
	claims := accessClaimsJSON(e, main.Issuer(), issueTime.Add(time.Hour))
	hintClaims := `{"iss":"` + main.Issuer() + `","sub":"u1","aud":"web","sid":"s1","exp":1}`
	if _, err := v.Access(main, forge(t, e, "RS256", "at+jwt", "m-old", "m-old", claims)); err != nil {
		t.Errorf("verify-only key, access: %v", err)
	}
	if _, err := v.IDTokenHint(main, forge(t, e, "RS256", "JWT", "m-old", "m-old", hintClaims)); err != nil {
		t.Errorf("verify-only key, hint: %v", err)
	}
	if _, err := v.IDTokenHint(main, forge(t, e, "RS256", "JWT", "m-old", "m-new", hintClaims)); !errors.Is(err, token.ErrSignature) {
		t.Errorf("hint signed by another key: err = %v, want ErrSignature", err)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Covers: SEC-20 (part)
func TestGarbageTokensAreSignatureErrors(t *testing.T) {
	e := newEnv(t, "RS256", "")
	good, _ := mustAccess(t, e, "web", testSubject(), testSession())
	parts := strings.Split(good, ".")
	rows := []struct{ name, raw string }{
		{"two segments", parts[0] + "." + parts[1]},
		{"four segments", good + ".AAAA"},
		{"one segment", parts[0]},
		{"very large", strings.Repeat("a", 4<<20)},
		{"very large with dots", strings.Repeat("a", 1<<20) + "." + strings.Repeat("b", 1<<20) + "." + strings.Repeat("c", 1<<20)},
		{"non-base64 header", "!!!." + parts[1] + "." + parts[2]},
		{"non-base64 payload", parts[0] + ".!!!." + parts[2]},
		{"non-base64 signature", parts[0] + "." + parts[1] + ".!!!"},
		{"non-JSON header", b64("not json") + "." + parts[1] + "." + parts[2]},
		{"JSON array header", b64("[]") + "." + parts[1] + "." + parts[2]},
		{"empty segments", ".."},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := e.verifier().Access(e.realm, row.raw); !errors.Is(err, token.ErrSignature) {
				t.Fatalf("Access: err = %v, want ErrSignature", err)
			}
			if _, err := e.verifier().IDTokenHint(e.realm, row.raw); !errors.Is(err, token.ErrSignature) {
				t.Fatalf("IDTokenHint: err = %v, want ErrSignature", err)
			}
		})
	}
}

// Covers: SEC-20 (part)
func TestSignedTokensWithOddClaimTypes(t *testing.T) {
	e := newEnv(t, "RS256", "")
	v := e.verifier()
	iss := `"` + e.realm.Issuer() + `"`
	future := strconv.FormatInt(issueTime.Add(time.Hour).Unix(), 10)
	rows := []struct {
		name, claims string
		want         error
	}{
		{"exp as a string", `{"iss":` + iss + `,"exp":"` + future + `"}`, token.ErrExpired},
		{"exp missing", `{"iss":` + iss + `}`, token.ErrExpired},
		{"exp null", `{"iss":` + iss + `,"exp":null}`, token.ErrExpired},
		{"exp an array", `{"iss":` + iss + `,"exp":[1]}`, token.ErrExpired},
		{"exp negative", `{"iss":` + iss + `,"exp":-5}`, token.ErrExpired},
		{"exp a float in the future", `{"iss":` + iss + `,"exp":` + future + `.5}`, nil},
		{"exp a float in the past", `{"iss":` + iss + `,"exp":1.5}`, token.ErrExpired},
		{"exp huge", `{"iss":` + iss + `,"exp":1e30}`, nil},
		{"exp hugely negative", `{"iss":` + iss + `,"exp":-1e30}`, token.ErrExpired},
		{"iss a number", `{"iss":5,"exp":` + future + `}`, token.ErrWrongRealm},
		{"iss missing", `{"exp":` + future + `}`, token.ErrWrongRealm},
		{"iss an array", `{"iss":[` + iss + `],"exp":` + future + `}`, token.ErrWrongRealm},
		{"payload a JSON array", `[]`, token.ErrSignature},
		{"payload null", `null`, token.ErrWrongRealm},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			raw := forge(t, e, "RS256", "at+jwt", "rsa-new", "rsa-new", row.claims)
			_, err := v.Access(e.realm, raw)
			if row.want == nil && err != nil || row.want != nil && !errors.Is(err, row.want) {
				t.Fatalf("err = %v, want %v", err, row.want)
			}
		})
	}
}

// Covers: SEC-14 (part)
func TestHintIgnoresExp(t *testing.T) {
	e := newEnv(t, "RS256", "")
	iss := `"` + e.realm.Issuer() + `"`
	for _, exp := range []string{``, `,"exp":"soon"`, `,"exp":null`, `,"exp":[1]`, `,"exp":1e30`, `,"exp":-1`} {
		raw := forge(t, e, "RS256", "JWT", "rsa-new", "rsa-new", `{"iss":`+iss+`,"sub":"u1","aud":"web","sid":"s1"`+exp+`}`)
		got, err := e.verifier().IDTokenHint(e.realm, raw)
		if err != nil {
			t.Errorf("exp %q: %v", exp, err)
		} else if got.Sid != "s1" || got.Aud != "web" {
			t.Errorf("exp %q: claims %+v", exp, got)
		}
	}
	// aud is read as a string only.
	raw := forge(t, e, "RS256", "JWT", "rsa-new", "rsa-new", `{"iss":`+iss+`,"sid":"s1","aud":["web"]}`)
	if got, err := e.verifier().IDTokenHint(e.realm, raw); err != nil || got.Aud != "" {
		t.Errorf("array aud: %+v, %v", got, err)
	}
}

// Covers: SEC-20 (part)
func TestHMACTokenKeyedWithThePublicKeyIsRejected(t *testing.T) {
	e := newEnv(t, "RS256", "")
	pub, _, _ := e.keys.Lookup("rsa-new")
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	claims := accessClaimsJSON(e, e.realm.Issuer(), issueTime.Add(time.Hour))
	for name, secret := range map[string][]byte{"PEM": pemKey, "DER": der} {
		for _, typ := range []string{"at+jwt", "JWT"} {
			h := jws.NewHeaders()
			_ = h.Set(jws.TypeKey, typ)
			_ = h.Set(jws.KeyIDKey, "rsa-new")
			out, err := jws.Sign([]byte(claims), jws.WithKey(jwa.HS256(), secret, jws.WithProtectedHeaders(h)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.verifier().Access(e.realm, string(out)); typ == "at+jwt" && !errors.Is(err, token.ErrSignature) {
				t.Errorf("%s: Access err = %v, want ErrSignature", name, err)
			}
			if _, err := e.verifier().IDTokenHint(e.realm, string(out)); typ == "JWT" && !errors.Is(err, token.ErrSignature) {
				t.Errorf("%s: IDTokenHint err = %v, want ErrSignature", name, err)
			}
		}
	}
}

func FuzzVerify(f *testing.F) {
	e := newEnv(f, "RS256", "")
	v := e.verifier()
	valid, _, err := e.issuer.Access(e.realm, e.client("web"), testSubject(), testSession())
	if err != nil {
		f.Fatal(err)
	}
	id, err := e.issuer.ID(e.realm, e.client("web"), testSubject(), testSession(), valid)
	if err != nil {
		f.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	for _, seed := range []string{
		valid, id, "", ".", "..", "a.b.c", parts[0] + "." + parts[1], valid + ".x",
		b64("{}") + "." + b64("{}") + ".", strings.Repeat("a", 100000),
		forge(f, e, "none", "at+jwt", "rsa-new", "", `{}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, accessErr := v.Access(e.realm, raw)
		if raw != valid && accessErr == nil {
			t.Fatalf("Access accepted %q", raw)
		}
		if raw == valid && accessErr != nil {
			t.Fatalf("Access rejected the valid token: %v", accessErr)
		}
		if _, err := v.IDTokenHint(e.realm, raw); raw != id && err == nil {
			t.Fatalf("IDTokenHint accepted %q", raw)
		}
	})
}
