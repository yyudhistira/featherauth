package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

// sealedCLI is an admin environment with two encryption keys on disk and four
// Apple-like tokens in realm main: u1 and u2 sealed by k1, u2 again by k2 under
// another provider key, and the realm "other" (database id r2) with one
// sealed by k1.
type sealedCLI struct {
	*adminEnv
	k1, k2     []byte
	id1, id2   string
	plain      map[string]string // provider/subject -> token
	storedAt   map[string]string // provider/subject -> value at the start
	secretText []string
}

func newSealedCLI(t *testing.T, d dbDriver) *sealedCLI {
	t.Helper()
	s := &sealedCLI{adminEnv: newAdminEnv(t, d), plain: map[string]string{}, storedAt: map[string]string{}}
	s.k1 = newKeyFile(t, s.dir, "secrets/key1")
	s.k2 = newKeyFile(t, s.dir, "secrets/key2")
	s.id1, s.id2 = secure.KeyID(s.k1), secure.KeyID(s.k2)
	s.keys(t, "secrets/key2", "secrets/key1") // k2 first, k1 second
	box1, err := secure.NewBox([][]byte{s.k1})
	if err != nil {
		t.Fatal(err)
	}
	box2, err := secure.NewBox([][]byte{s.k2})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = s.svc.Write(ctx, func(tx store.Tx) error {
		for _, r := range []struct {
			realm       store.RealmID
			user        string
			provider    config.ProviderKey
			sub         string
			box         *secure.Box
			ident       string
			withoutSeal bool
		}{
			{"r1", "u2", "apple", "sub-2", box1, "i2", false},
			{"r1", "u1", "apple", "sub-1", box1, "i1", false},
			{"r1", "u2", "appleb", "sub-3", box2, "i3", false},
			{"r1", "u1", "github", "sub-4", nil, "i4", true},
		} {
			ident := store.Identity{ID: store.IdentityID(r.ident), RealmID: r.realm, UserID: store.UserID(r.user), Provider: r.provider, ProviderSub: r.sub, CreatedAt: t0}
			if r.box != nil {
				token := "the-refresh-token-" + r.ident
				v, err := r.box.Seal([]byte(token))
				if err != nil {
					return err
				}
				ident.ProviderRefreshTokenEnc = v
				s.plain[string(r.provider)+"/"+r.sub] = token
				s.storedAt[string(r.provider)+"/"+r.sub] = v
				s.secretText = append(s.secretText, token, strings.SplitN(v, ".", 2)[1])
			}
			if err := tx.Identities().Create(ctx, ident); err != nil {
				return err
			}
		}
		if _, err := tx.Realms().Ensure(ctx, "other", "r2", t0); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, store.User{ID: "o1", RealmID: "r2", CreatedAt: t0, UpdatedAt: t0}); err != nil {
			return err
		}
		v, err := box1.Seal([]byte("the-other-realm-token"))
		if err != nil {
			return err
		}
		s.secretText = append(s.secretText, "the-other-realm-token", strings.SplitN(v, ".", 2)[1])
		return tx.Identities().Create(ctx, store.Identity{ID: "io", RealmID: "r2", UserID: "o1", Provider: "apple", ProviderSub: "so", ProviderRefreshTokenEnc: v, CreatedAt: t0})
	})
	if err != nil {
		t.Fatal(err)
	}
	s.secretText = append(s.secretText, string(s.k1), string(s.k2))
	return s
}

// keys writes the encryption_key_files of server.yaml; none writes no list.
func (s *sealedCLI) keys(t *testing.T, files ...string) {
	t.Helper()
	y := "public_url: https://auth.example.com\n"
	if len(files) > 0 {
		y += "secrets:\n  encryption_key_files: [" + strings.Join(files, ", ") + "]\n"
	}
	writeConfig(t, s.dir, "server.yaml", y)
}

func (s *sealedCLI) value(t *testing.T, realm store.RealmID, provider, sub string) string {
	t.Helper()
	var v string
	err := s.svc.Read(context.Background(), func(tx store.Tx) error {
		i, err := tx.Identities().Find(context.Background(), realm, config.ProviderKey(provider), sub)
		v = i.ProviderRefreshTokenEnc
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (s *sealedCLI) auditRows(t *testing.T, action string) []store.AuditEvent {
	t.Helper()
	var out []store.AuditEvent
	for _, ev := range s.audit(t) {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].UserID < out[j].UserID
	})
	return out
}

// noSecrets fails the test when the output, the audit lines or the audit rows
// hold a token, a key or a part of a stored value.
func (s *sealedCLI) noSecrets(t *testing.T, rs ...result) {
	t.Helper()
	hay := ""
	for _, r := range rs {
		hay += r.stdout + r.stderr
	}
	for _, ev := range s.audit(t) {
		hay += fmt.Sprint(ev.Details)
	}
	for _, v := range s.secretText {
		if strings.Contains(hay, v) {
			t.Fatalf("an output, log line or audit row holds %q", v)
		}
	}
}

type sealedView struct {
	UserID   string `json:"user_id"`
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

func decodeList(t *testing.T, r result) []sealedView {
	t.Helper()
	var out []sealedView
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("%v: %q", err, r.stdout)
	}
	return out
}

func decodeReport(t *testing.T, r result, into any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%v: %q", err, r.stdout)
	}
}

// runWith runs a command with a store wrapper installed.
func (s *sealedCLI) runWith(t *testing.T, wrap func(store.Store) store.Store, rv user.RevokerFor, args ...string) result {
	t.Helper()
	s.clock.Advance(time.Second)
	return execApp(t, s.clock, s.env, func(a *app) {
		a.wrapStore = wrap
		if rv != nil {
			a.revokerFactory = func(config.Source, clock.Clock, *slog.Logger) user.RevokerFor { return rv }
		}
	}, args...)
}

// Covers: SEC-43
// Acceptance: Sealed tokens by key id
func TestKeysSealedListsTheIdentitiesOfAKey(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		r := s.run(t, "keys", "sealed", "main", "--key-id", s.id1)
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		got := decodeList(t, r)
		want := []sealedView{{"u1", "apple", "sub-1"}, {"u2", "apple", "sub-2"}}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("list %v, want %v", got, want)
		}
		// The keys of each object are those of the design, in its order.
		if !strings.Contains(r.stdout, `"user_id": "u1",`) || strings.Index(r.stdout, `"user_id"`) > strings.Index(r.stdout, `"provider"`) ||
			strings.Index(r.stdout, `"provider"`) > strings.Index(r.stdout, `"subject"`) {
			t.Fatalf("keys out of order: %s", r.stdout)
		}
		// The key that sealed another token; an id that none sealed; the other realm.
		if r2 := s.run(t, "keys", "sealed", "main", "--key-id", s.id2); r2.code != 0 || fmt.Sprint(decodeList(t, r2)) != fmt.Sprint([]sealedView{{"u2", "appleb", "sub-3"}}) {
			t.Fatalf("k2: %+v", r2)
		}
		r3 := s.run(t, "keys", "sealed", "main", "--key-id", "00000000")
		if r3.code != 0 || strings.TrimSpace(r3.stdout) != "[]" {
			t.Fatalf("no identity: %+v", r3)
		}
		if r4 := s.run(t, "keys", "sealed", "other", "--key-id", s.id1); r4.code != 0 || len(decodeList(t, r4)) != 1 {
			t.Fatalf("other realm: %+v", r4)
		}
		// The flag may come first as well as after the realm.
		if r5 := s.run(t, "keys", "sealed", "main", "--key-id="+s.id1); r5.code != 0 || len(decodeList(t, r5)) != 2 {
			t.Fatalf("--key-id=: %+v", r5)
		}

		// One row for each listing of the realm, empty ones too, with its line on stderr.
		rows := s.auditRows(t, "keys.sealed_listed")
		if len(rows) != 4 { // main: k1, k2, 00000000, k1 again (other realm is r2)
			t.Fatalf("%d rows", len(rows))
		}
		for i, n := range []string{"2", "1", "0", "2"} {
			ev := rows[i]
			if ev.Actor != "admin" || ev.UserID != "" || len(ev.Details) != 2 || fmt.Sprint(ev.Details["identities"]) != n {
				t.Fatalf("row %d = %+v", i, ev)
			}
		}
		if rows[2].Details["key_id"] != "00000000" || rows[0].Details["key_id"] != s.id1 {
			t.Fatalf("key ids %v %v", rows[0].Details, rows[2].Details)
		}
		if !strings.Contains(r.stderr, `"audit":true`) || !strings.Contains(r.stderr, "keys.sealed_listed") || !strings.Contains(r3.stderr, "keys.sealed_listed") {
			t.Fatalf("stderr %q", r.stderr)
		}
		s.noSecrets(t, r, r3)
	})
}

// It reads no encryption key and no configuration: a directory with only
// database.yaml works.
//
// Covers: SEC-43 (part)
// Acceptance: Sealed tokens by key id (part)
func TestKeysSealedNeedsNoKeyAndNoConfiguration(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		s.keys(t)                                     // no encryption keys at all
		writeConfig(t, s.dir, "server.yaml", "bogus") // and a server.yaml that does not load
		if r := s.run(t, "keys", "sealed", "main", "--key-id", s.id1); r.code != 0 || len(decodeList(t, r)) != 2 {
			t.Fatalf("%+v", r)
		}
	})
}

// Covers: SEC-43 (part)
// Acceptance: Sealed tokens by key id (part)
func TestKeysCommandsUsageAndNotFoundExitCodes(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		id := s.id1
		for _, cmd := range []string{"sealed", "reseal", "clear-sealed"} {
			for _, tc := range []struct {
				name string
				args []string
				code int
			}{
				{"upper-case id", []string{"main", "--key-id", "ABCDEF12"}, 2},
				{"7 characters", []string{"main", "--key-id", id[:7]}, 2},
				{"9 characters", []string{"main", "--key-id", id + "a"}, 2},
				{"not hex", []string{"main", "--key-id", "0123abcg"}, 2},
				{"empty id", []string{"main", "--key-id", ""}, 2},
				{"no id", []string{"main"}, 2},
				{"id without a value", []string{"main", "--key-id"}, 2},
				{"id twice", []string{"main", "--key-id", id, "--key-id", id}, 2},
				{"no realm", []string{"--key-id", id}, 2},
				{"empty realm", []string{"", "--key-id", id}, 2},
				{"nothing", nil, 2},
				{"unknown flag", []string{"main", "--key-id", id, "--bogus"}, 2},
				{"extra argument", []string{"main", "extra", "--key-id", id}, 2},
				{"argument after the flags", []string{"main", "--key-id", id, "extra"}, 2},
				{"unknown realm", []string{"nope", "--key-id", id}, 1},
			} {
				r := s.run(t, append([]string{"keys", cmd}, tc.args...)...)
				if r.code != tc.code {
					t.Errorf("keys %s, %s: exit %d, want %d: %+v", cmd, tc.name, r.code, tc.code, r)
				}
			}
		}
		if r := s.run(t, "keys"); r.code != 2 {
			t.Errorf("keys alone: %+v", r)
		}
		if r := s.run(t, "keys", "bogus"); r.code != 2 {
			t.Errorf("keys bogus: %+v", r)
		}
		// Nothing was written by any of them.
		if n := len(s.audit(t)); n != 0 {
			t.Fatalf("%d audit rows", n)
		}
		for k, v := range s.storedAt {
			p := strings.SplitN(k, "/", 2)
			if s.value(t, "r1", p[0], p[1]) != v {
				t.Fatalf("value of %s changed", k)
			}
		}
	})
}

// Covers: SEC-47
// Acceptance: Reseal and clear sealed tokens
func TestKeysResealMovesTokensToTheFirstKey(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		r := s.run(t, "keys", "reseal", "main", "--key-id", s.id1)
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		var rep struct {
			Resealed int          `json:"resealed"`
			Skipped  int          `json:"skipped"`
			Failed   []sealedView `json:"failed"`
		}
		decodeReport(t, r, &rep)
		if rep.Resealed != 2 || rep.Skipped != 0 || rep.Failed == nil || len(rep.Failed) != 0 || !strings.Contains(r.stdout, `"failed": []`) {
			t.Fatalf("report %+v: %s", rep, r.stdout)
		}
		box, err := secure.NewBox([][]byte{s.k2, s.k1})
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"apple/sub-1", "apple/sub-2"} {
			p := strings.SplitN(k, "/", 2)
			v := s.value(t, "r1", p[0], p[1])
			plain, err := box.Open(v)
			if !strings.HasPrefix(v, s.id2+".") || err != nil || string(plain) != s.plain[k] {
				t.Fatalf("value of %s: %q, %q, %v", k, v, plain, err)
			}
		}
		if v := s.value(t, "r1", "appleb", "sub-3"); v != s.storedAt["appleb/sub-3"] {
			t.Fatal("a value of the first key changed")
		}
		if v := s.value(t, "r2", "apple", "so"); !strings.HasPrefix(v, s.id1+".") {
			t.Fatal("the other realm's value changed")
		}
		rows := s.auditRows(t, "identity.token_resealed")
		if len(rows) != 2 || rows[0].UserID != "u1" || rows[1].UserID != "u2" {
			t.Fatalf("rows %+v", rows)
		}
		for _, ev := range rows {
			if ev.Actor != "admin" || len(ev.Details) != 3 || ev.Details["provider"] != "apple" || ev.Details["from_key"] != s.id1 || ev.Details["to_key"] != s.id2 {
				t.Fatalf("row %+v", ev)
			}
		}
		if strings.Count(r.stderr, "identity.token_resealed") != 2 {
			t.Fatalf("stderr %q", r.stderr)
		}
		// keys sealed lists nothing for k1 now; a second run changes and audits nothing.
		l := s.run(t, "keys", "sealed", "main", "--key-id", s.id1)
		if l.code != 0 || strings.TrimSpace(l.stdout) != "[]" {
			t.Fatalf("sealed after: %+v", l)
		}
		again := s.run(t, "keys", "reseal", "main", "--key-id", s.id1)
		decodeReport(t, again, &rep)
		if again.code != 0 || rep.Resealed != 0 || again.stderr != "" || len(s.auditRows(t, "identity.token_resealed")) != 2 {
			t.Fatalf("second run: %+v", again)
		}
		s.noSecrets(t, r, l, again)

		// A deleted user whose token was resealed is revoked with the new key:
		// the first key alone opens it.
		s.keys(t, "secrets/key2")
		rv := &recordingRevoker{}
		del := s.runWith(t, nil, func(realm, key string) provider.Revoker {
			if realm == "main" && key == "apple" {
				return rv
			}
			return nil
		}, "user", "delete", "main", "u1")
		if del.code != 0 || len(rv.tokens) != 1 || rv.tokens[0] != s.plain["apple/sub-1"] {
			t.Fatalf("delete %+v, revoked %v", del, rv.tokens)
		}
	})
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestKeysResealRefusesWhatItCannotDo(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		for _, tc := range []struct {
			name  string
			files []string
			setup func()
			key   string
			say   string
		}{
			{"the key is first", []string{"secrets/key1", "secrets/key2"}, nil, s.id1, "key " + s.id1 + " is the first key; add a new first key before resealing"},
			{"the key is the only one", []string{"secrets/key1"}, nil, s.id1, "is the first key"},
			{"the key is not configured", []string{"secrets/key2"}, nil, s.id1, "key " + s.id1 + " is not in secrets.encryption_key_files"},
			{"an id no key has", []string{"secrets/key2", "secrets/key1"}, nil, "00000000", "key 00000000 is not in secrets.encryption_key_files"},
			{"no key at all", nil, nil, s.id1, "is not in secrets.encryption_key_files"},
			{"the configuration does not load", []string{"secrets/key2", "secrets/key1"}, func() { writeConfig(t, s.dir, "realms/main.yaml", "bogus: [") }, s.id1, "main.yaml"},
		} {
			s.keys(t, tc.files...)
			if tc.setup != nil {
				tc.setup()
			}
			r := s.run(t, "keys", "reseal", "main", "--key-id", tc.key)
			if r.code != 1 || !strings.Contains(r.stderr, tc.say) || r.stdout != "" {
				t.Errorf("%s: %+v, want exit 1 and %q", tc.name, r, tc.say)
			}
		}
		for k, v := range s.storedAt {
			p := strings.SplitN(k, "/", 2)
			if s.value(t, "r1", p[0], p[1]) != v {
				t.Fatalf("value of %s changed", k)
			}
		}
		if n := len(s.audit(t)); n != 0 {
			t.Fatalf("%d audit rows", n)
		}
	})
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestKeysResealReportsAValueThatDoesNotDecrypt(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		good := s.storedAt["apple/sub-1"]
		altered := good[:len(good)-1] + map[bool]string{true: "B", false: "A"}[good[len(good)-1] == 'A']
		if err := s.svc.Write(context.Background(), func(tx store.Tx) error {
			ok, err := tx.Identities().ReplaceProviderToken(context.Background(), "r1", "i1", good, altered)
			if err == nil && !ok {
				err = errors.New("not altered")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		r := s.run(t, "keys", "reseal", "main", "--key-id", s.id1)
		var rep struct {
			Resealed int          `json:"resealed"`
			Skipped  int          `json:"skipped"`
			Failed   []sealedView `json:"failed"`
		}
		decodeReport(t, r, &rep)
		if r.code != 1 || rep.Resealed != 1 || len(rep.Failed) != 1 || rep.Failed[0] != (sealedView{"u1", "apple", "sub-1"}) {
			t.Fatalf("%+v", r)
		}
		if s.value(t, "r1", "apple", "sub-1") != altered {
			t.Fatal("the value that failed changed")
		}
		if rows := s.auditRows(t, "identity.token_resealed"); len(rows) != 1 || rows[0].UserID != "u2" {
			t.Fatalf("rows %+v", rows)
		}
		s.noSecrets(t, r)
	})
}

// A token the service replaced or dropped between the command's read and its
// write is left alone and counted as skipped.
//
// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestKeysChangeCommandsSkipATokenChangedMeanwhile(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		for _, cmd := range []string{"reseal", "clear-sealed"} {
			for _, drop := range []bool{false, true} {
				name := fmt.Sprintf("%s drop=%v", cmd, drop)
				t.Run(name, func(t *testing.T) {
					s := newSealedCLI(t, d)
					box, err := secure.NewBox([][]byte{s.k2, s.k1})
					if err != nil {
						t.Fatal(err)
					}
					next := ""
					if !drop {
						if next, err = box.Seal([]byte("the-new-apple-login")); err != nil {
							t.Fatal(err)
						}
					}
					wrap := func(st store.Store) store.Store {
						f := testutil.NewFaultStore(st)
						f.BeforeWrite(1, func() { // the first write is the one of u1
							err := s.svc.Write(context.Background(), func(tx store.Tx) error {
								ok, err := tx.Identities().ReplaceProviderToken(context.Background(), "r1", "i1", s.storedAt["apple/sub-1"], next)
								if err == nil && !ok {
									err = errors.New("the service's change did not apply")
								}
								return err
							})
							if err != nil {
								t.Error(err)
							}
						})
						return f
					}
					r := s.runWith(t, wrap, nil, "keys", cmd, "main", "--key-id", s.id1)
					if r.code != 0 {
						t.Fatalf("%s: %+v", name, r)
					}
					if s.value(t, "r1", "apple", "sub-1") != next {
						t.Fatalf("%s: the service's value was overwritten", name)
					}
					action, count := "identity.token_resealed", "resealed"
					if cmd == "clear-sealed" {
						action, count = "identity.token_cleared", "cleared"
					}
					var rep map[string]any
					decodeReport(t, r, &rep)
					if fmt.Sprint(rep[count]) != "1" || fmt.Sprint(rep["skipped"]) != "1" {
						t.Fatalf("%s: report %v", name, rep)
					}
					if rows := s.auditRows(t, action); len(rows) != 1 || rows[0].UserID != "u2" {
						t.Fatalf("%s: rows %+v", name, rows)
					}
					s.noSecrets(t, r)
				})
			}
		}
	})
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestKeysClearSealedSetsTheValuesToNone(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		s := newSealedCLI(t, d)
		// It reads no key: the key may be gone from the configuration, and it
		// revokes nothing at the provider.
		s.keys(t, "secrets/key2")
		rv := &recordingRevoker{}
		r := s.runWith(t, nil, func(realm, key string) provider.Revoker { return rv }, "keys", "clear-sealed", "main", "--key-id", s.id1)
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		var rep struct {
			Cleared int `json:"cleared"`
			Skipped int `json:"skipped"`
		}
		decodeReport(t, r, &rep)
		if rep.Cleared != 2 || rep.Skipped != 0 || len(rv.tokens) != 0 {
			t.Fatalf("report %+v, revoked %v", rep, rv.tokens)
		}
		if s.value(t, "r1", "apple", "sub-1") != "" || s.value(t, "r1", "apple", "sub-2") != "" {
			t.Fatal("values not cleared")
		}
		if s.value(t, "r1", "appleb", "sub-3") != s.storedAt["appleb/sub-3"] || !strings.HasPrefix(s.value(t, "r2", "apple", "so"), s.id1+".") {
			t.Fatal("another value changed")
		}
		rows := s.auditRows(t, "identity.token_cleared")
		if len(rows) != 2 || rows[0].UserID != "u1" || rows[1].UserID != "u2" {
			t.Fatalf("rows %+v", rows)
		}
		for _, ev := range rows {
			if ev.Actor != "admin" || len(ev.Details) != 2 || ev.Details["provider"] != "apple" || ev.Details["key_id"] != s.id1 {
				t.Fatalf("row %+v", ev)
			}
		}
		if strings.Count(r.stderr, "identity.token_cleared") != 2 {
			t.Fatalf("stderr %q", r.stderr)
		}
		// The second run changes and audits nothing; sealed lists nothing.
		again := s.run(t, "keys", "clear-sealed", "main", "--key-id", s.id1)
		decodeReport(t, again, &rep)
		if again.code != 0 || rep.Cleared != 0 || again.stderr != "" || len(s.auditRows(t, "identity.token_cleared")) != 2 {
			t.Fatalf("second run %+v", again)
		}
		if l := s.run(t, "keys", "sealed", "main", "--key-id", s.id1); strings.TrimSpace(l.stdout) != "[]" {
			t.Fatalf("sealed after: %+v", l)
		}
		s.noSecrets(t, r, again)
	})
}

// A store failure exits 1 and changes nothing for the identity in progress.
//
// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestKeysChangeCommandsExitOneOnAStoreFailure(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		for _, cmd := range []string{"reseal", "clear-sealed"} {
			t.Run(cmd, func(t *testing.T) {
				s := newSealedCLI(t, d)
				wrap := func(st store.Store) store.Store {
					f := testutil.NewFaultStore(st)
					f.Fail("Identities.ReplaceProviderToken", errors.New("the store failed"))
					return f
				}
				r := s.runWith(t, wrap, nil, "keys", cmd, "main", "--key-id", s.id1)
				if r.code != 1 || !strings.Contains(r.stderr, "the store failed") {
					t.Fatalf("%s: %+v", cmd, r)
				}
				for k, v := range s.storedAt {
					p := strings.SplitN(k, "/", 2)
					if s.value(t, "r1", p[0], p[1]) != v {
						t.Fatalf("%s: value of %s changed", cmd, k)
					}
				}
				if n := len(s.audit(t)); n != 0 {
					t.Fatalf("%s: %d audit rows", cmd, n)
				}
				s.noSecrets(t, r)
			})
		}
	})
}

// The usage text lists the three commands.
//
// Covers: SEC-43 (part), SEC-47 (part)
func TestKeysSealedCommandsAreInTheUsage(t *testing.T) {
	r := exec(t, nil)
	for _, want := range []string{"keys sealed <realm> --key-id <id>", "keys reseal <realm> --key-id <id>", "keys clear-sealed <realm> --key-id <id>"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}
