package admin_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// sealedEnv is an admin environment whose realm has three users with Apple
// tokens, two sealed by key k1 and one by k2, and one user without a token. k1
// and k2 are the keys of the boxes below.
type sealedEnv struct {
	*env
	fault       *testutil.FaultStore
	k1, k2      []byte
	id1, id2    string
	box1, box12 *secure.Box // box12 seals with k2 and opens k1 too
	box21       *secure.Box // box21 seals with k1
	plain       map[string]string
	sealedBy    map[string]string // identity id -> value as stored at the start
}

func newSealedEnv(t *testing.T) *sealedEnv {
	t.Helper()
	fault := testutil.NewFaultStore(testutil.NewStore(t))
	s := &sealedEnv{env: wire(t, fault), fault: fault, plain: map[string]string{}, sealedBy: map[string]string{}}
	s.k1, s.k2 = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	s.id1, s.id2 = secure.KeyID(s.k1), secure.KeyID(s.k2)
	var err error
	if s.box1, err = secure.NewBox([][]byte{s.k1}); err != nil {
		t.Fatal(err)
	}
	if s.box12, err = secure.NewBox([][]byte{s.k2, s.k1}); err != nil {
		t.Fatal(err)
	}
	if s.box21, err = secure.NewBox([][]byte{s.k1, s.k2}); err != nil {
		t.Fatal(err)
	}
	box2, _ := secure.NewBox([][]byte{s.k2})
	for _, u := range []struct {
		user, ident, provider, sub string
		box                        *secure.Box
	}{
		{"u2", "i2", "apple", "sub-2", s.box1},
		{"u1", "i1", "apple", "sub-1", s.box1},
		{"u3", "i3", "apple", "sub-3", box2},
		{"u4", "i4", "google", "sub-4", nil},
	} {
		s.addUser(t, u.user, u.user+"@example.org", false)
		ident := store.Identity{ID: store.IdentityID(u.ident), RealmID: s.realm, UserID: store.UserID(u.user), Provider: config.ProviderKey(u.provider), ProviderSub: u.sub, CreatedAt: start}
		if u.box != nil {
			s.plain[u.ident] = "refresh-token-of-" + u.ident
			if ident.ProviderRefreshTokenEnc, err = u.box.Seal([]byte(s.plain[u.ident])); err != nil {
				t.Fatal(err)
			}
			s.sealedBy[u.ident] = ident.ProviderRefreshTokenEnc
		}
		s.must(t, func(ctx context.Context, tx store.Tx) error { return tx.Identities().Create(ctx, ident) })
	}
	// A realm of another name with a token of k1: the commands leave it alone.
	err = s.st.Write(context.Background(), func(tx store.Tx) error {
		if _, err := tx.Realms().Ensure(context.Background(), "other", "r2", start); err != nil {
			return err
		}
		if err := tx.Users().Create(context.Background(), store.User{ID: "o1", RealmID: "r2", CreatedAt: start, UpdatedAt: start}); err != nil {
			return err
		}
		v, err := s.box1.Seal([]byte("other-realm-token"))
		if err != nil {
			return err
		}
		return tx.Identities().Create(context.Background(), store.Identity{ID: "io1", RealmID: "r2", UserID: "o1", Provider: "apple", ProviderSub: "so1", ProviderRefreshTokenEnc: v, CreatedAt: start})
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *sealedEnv) must(t *testing.T, fn func(context.Context, store.Tx) error) {
	t.Helper()
	ctx := context.Background()
	if err := s.st.Write(ctx, func(tx store.Tx) error { return fn(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
}

// value returns the stored token of the identity of the user, in realm r1.
func (s *sealedEnv) value(t *testing.T, user, ident string) string {
	t.Helper()
	var v string
	err := s.st.Read(context.Background(), func(tx store.Tx) error {
		list, err := tx.Identities().ListByUser(context.Background(), s.realm, store.UserID(user))
		for _, i := range list {
			if string(i.ID) == ident {
				v = i.ProviderRefreshTokenEnc
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (s *sealedEnv) setValue(t *testing.T, ident, from, to string) {
	t.Helper()
	s.must(t, func(ctx context.Context, tx store.Tx) error {
		ok, err := tx.Identities().ReplaceProviderToken(ctx, s.realm, store.IdentityID(ident), from, to)
		if err == nil && !ok {
			err = errors.New("setValue: not replaced")
		}
		return err
	})
}

func (s *sealedEnv) actions(t *testing.T, action string) []store.AuditEvent {
	t.Helper()
	var out []store.AuditEvent
	for _, ev := range s.events(t) {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	// Rows of one instant have no order of their own: sort by user.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].UserID < out[j].UserID)
	})
	return out
}

// noSecrets fails the test when the log or an audit row holds a token or a key.
func (s *sealedEnv) noSecrets(t *testing.T) {
	t.Helper()
	bad := []string{string(s.k1), string(s.k2), "refresh-token-of-", "other-realm-token"}
	for _, v := range s.sealedBy {
		bad = append(bad, v, strings.SplitN(v, ".", 2)[1])
	}
	hay := s.log.String()
	for _, ev := range s.events(t) {
		hay += fmt.Sprint(ev.Details)
	}
	for _, b := range bad {
		if strings.Contains(hay, b) {
			t.Fatalf("a log line or audit row holds %q", b)
		}
	}
}

// Covers: SEC-43
// Acceptance: Sealed tokens by key id
func TestSealedByListsTheIdentitiesOfTheKeyInOrder(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	got, err := s.ops.SealedBy(ctx, "main", s.id1)
	if err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(time.Second) // the rows sort by time
	// u1 sorts before u2; the other realm's identity and k2's are not listed.
	want := []admin.SealedRef{{UserID: "u1", Provider: "apple", Subject: "sub-1"}, {UserID: "u2", Provider: "apple", Subject: "sub-2"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("SealedBy = %v, want %v", got, want)
	}
	if got, err := s.ops.SealedBy(ctx, "main", s.id2); err != nil || len(got) != 1 || got[0].UserID != "u3" {
		t.Fatalf("SealedBy k2 = %v, %v", got, err)
	}
	s.clock.Advance(time.Second)
	// A key that no configuration lists works the same; an id with none is empty.
	if got, err := s.ops.SealedBy(ctx, "main", "00000000"); err != nil || len(got) != 0 {
		t.Fatalf("SealedBy unknown id = %v, %v", got, err)
	}
	evs := s.actions(t, "keys.sealed_listed")
	if len(evs) != 3 {
		t.Fatalf("%d keys.sealed_listed rows, want one per listing", len(evs))
	}
	for i, n := range []string{"2", "1", "0"} {
		ev := evs[i]
		if ev.Actor != "admin" || ev.UserID != "" || len(ev.Details) != 2 || fmt.Sprint(ev.Details["identities"]) != n {
			t.Fatalf("row %d = %+v", i, ev)
		}
	}
	if evs[0].Details["key_id"] != s.id1 || evs[2].Details["key_id"] != "00000000" {
		t.Fatalf("details %v %v", evs[0].Details, evs[2].Details)
	}
	if !strings.Contains(s.log.String(), "keys.sealed_listed") {
		t.Fatal("no audit line")
	}
	s.noSecrets(t)
}

// Covers: SEC-43 (part)
// Acceptance: Sealed tokens by key id (part)
func TestSealedByRefusesWhatItCannotListAndAuditsNothing(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	for _, id := range []string{"", "ABCDEF12", "0123abc", "0123abcde", "0123abcg"} {
		if _, err := s.ops.SealedBy(ctx, "main", id); !errors.Is(err, admin.ErrInvalid) {
			t.Errorf("SealedBy(%q) = %v, want ErrInvalid", id, err)
		}
	}
	if _, err := s.ops.SealedBy(ctx, "nope", s.id1); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("unknown realm: %v", err)
	}
	s.fault.FailWrite = errors.New("store down")
	if _, err := s.ops.SealedBy(ctx, "main", s.id1); err == nil {
		t.Error("a store failure was not reported")
	}
	s.fault.FailWrite = nil
	if n := len(s.actions(t, "keys.sealed_listed")); n != 0 {
		t.Fatalf("%d audit rows", n)
	}
}

// Covers: SEC-47
// Acceptance: Reseal and clear sealed tokens
func TestResealMovesTheTokensToTheFirstKey(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	rep, err := s.ops.Reseal(ctx, "main", s.id1, s.box12)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Resealed != 2 || rep.Skipped != 0 || len(rep.Failed) != 0 {
		t.Fatalf("report %+v", rep)
	}
	for _, c := range []struct{ user, ident string }{{"u1", "i1"}, {"u2", "i2"}} {
		v := s.value(t, c.user, c.ident)
		if !strings.HasPrefix(v, s.id2+".") || v == s.sealedBy[c.ident] {
			t.Fatalf("value of %s = %q", c.ident, v)
		}
		if plain, err := s.box12.Open(v); err != nil || string(plain) != s.plain[c.ident] {
			t.Fatalf("value of %s opens to %q, %v", c.ident, plain, err)
		}
	}
	if v := s.value(t, "u3", "i3"); v != s.sealedBy["i3"] {
		t.Fatal("a value of another key changed")
	}
	rows := s.actions(t, "identity.token_resealed")
	if len(rows) != 2 || rows[0].UserID != "u1" || rows[1].UserID != "u2" {
		t.Fatalf("rows %+v", rows)
	}
	for _, ev := range rows {
		d := ev.Details
		if ev.Actor != "admin" || len(d) != 3 || d["provider"] != "apple" || d["from_key"] != s.id1 || d["to_key"] != s.id2 {
			t.Fatalf("row %+v", ev)
		}
	}
	if left, err := s.ops.SealedBy(ctx, "main", s.id1); err != nil || len(left) != 0 {
		t.Fatalf("SealedBy after the reseal = %v, %v", left, err)
	}
	// Run again: nothing changes and nothing is audited.
	before := len(s.events(t))
	rep, err = s.ops.Reseal(ctx, "main", s.id1, s.box12)
	if err != nil || rep.Resealed != 0 || rep.Skipped != 0 || len(rep.Failed) != 0 || len(s.events(t)) != before {
		t.Fatalf("second run: %+v, %v, %d rows", rep, err, len(s.events(t))-before)
	}
	// The other realm's token is still k1's.
	var other []store.SealedIdentity
	_ = s.st.Read(ctx, func(tx store.Tx) (err error) {
		other, err = tx.Identities().SealedBy(ctx, "r2", s.id1)
		return err
	})
	if len(other) != 1 {
		t.Fatal("the other realm's token was changed")
	}
	s.noSecrets(t)
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestResealNeedsTheKeyAndAnotherFirstKey(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	if _, err := s.ops.Reseal(ctx, "main", s.id1, s.box21); !errors.Is(err, admin.ErrKeyIsFirst) {
		t.Fatalf("first key: %v", err)
	}
	if _, err := s.ops.Reseal(ctx, "main", s.id1, s.box1); !errors.Is(err, admin.ErrKeyIsFirst) {
		t.Fatalf("only key: %v", err)
	}
	if _, err := s.ops.Reseal(ctx, "main", "00000000", s.box12); !errors.Is(err, admin.ErrKeyNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
	if _, err := s.ops.Reseal(ctx, "main", s.id1, nil); !errors.Is(err, admin.ErrKeyNotConfigured) {
		t.Fatalf("no key at all: %v", err)
	}
	if _, err := s.ops.Reseal(ctx, "main", "ABCDEF12", s.box12); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := s.ops.Reseal(ctx, "nope", s.id1, s.box12); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
	for _, m := range []struct {
		key  string
		box  *secure.Box
		text string
	}{
		{"00000000", s.box12, "key 00000000 is not in secrets.encryption_key_files"},
		{s.id1, s.box21, "key " + s.id1 + " is the first key; add a new first key before resealing"},
	} {
		_, err := s.ops.Reseal(ctx, "main", m.key, m.box)
		if err == nil || err.Error() != m.text {
			t.Errorf("error %v, want %q", err, m.text)
		}
	}
	for ident, v := range s.sealedBy {
		user := map[string]string{"i1": "u1", "i2": "u2", "i3": "u3"}[ident]
		if s.value(t, user, ident) != v {
			t.Fatalf("value of %s changed", ident)
		}
	}
	if n := len(s.events(t)); n != 0 {
		t.Fatalf("%d audit rows", n)
	}
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestResealCountsAValueThatDoesNotDecryptAsFailed(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	// Alter the first character after the key id of u1's value: it no longer
	// authenticates. The last character is not safe to alter: the unpadded
	// base64url decoder ignores the unused low bits of the final character, so
	// "A" and "B" there can decode to the same bytes and the value would still
	// open (which made this test flaky).
	good := s.sealedBy["i1"]
	at := strings.Index(good, ".") + 1
	altered := good[:at] + map[bool]string{true: "B", false: "A"}[good[at] == 'A'] + good[at+1:]
	s.setValue(t, "i1", good, altered)
	rep, err := s.ops.Reseal(ctx, "main", s.id1, s.box12)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Resealed != 1 || len(rep.Failed) != 1 || rep.Failed[0] != (admin.SealedRef{UserID: "u1", Provider: "apple", Subject: "sub-1"}) {
		t.Fatalf("report %+v", rep)
	}
	if s.value(t, "u1", "i1") != altered {
		t.Fatal("the failed value changed")
	}
	if !strings.HasPrefix(s.value(t, "u2", "i2"), s.id2+".") {
		t.Fatal("the other value was not resealed")
	}
	rows := s.actions(t, "identity.token_resealed")
	if len(rows) != 1 || rows[0].UserID != "u2" {
		t.Fatalf("rows %+v", rows)
	}
	// It is still listed, so the key stays in the way.
	if left, _ := s.ops.SealedBy(ctx, "main", s.id1); len(left) != 1 || left[0].UserID != "u1" {
		t.Fatalf("still sealed: %v", left)
	}
	s.noSecrets(t)
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestResealLeavesATokenTheServiceChangedInTheMeantime(t *testing.T) {
	for _, name := range []string{"replaced by a new login", "dropped"} {
		t.Run(name, func(t *testing.T) {
			s := newSealedEnv(t)
			ctx := context.Background()
			next := ""
			if name != "dropped" {
				var err error
				if next, err = s.box12.Seal([]byte("the-new-login-token")); err != nil {
					t.Fatal(err)
				}
			}
			// The first write is the one of u1: the service changes its token first.
			s.fault.BeforeWrite(1, func() { s.setValue(t, "i1", s.sealedBy["i1"], next) })
			rep, err := s.ops.Reseal(ctx, "main", s.id1, s.box12)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Resealed != 1 || rep.Skipped != 1 || len(rep.Failed) != 0 {
				t.Fatalf("report %+v", rep)
			}
			if s.value(t, "u1", "i1") != next {
				t.Fatalf("the service's value was overwritten: %q", s.value(t, "u1", "i1"))
			}
			rows := s.actions(t, "identity.token_resealed")
			if len(rows) != 1 || rows[0].UserID != "u2" {
				t.Fatalf("rows %+v", rows)
			}
		})
	}
}

// A failure of the store stops the run with nothing changed for the identity
// in progress; the ones done stay done, and a second run does the rest.
//
// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestResealStoreFailureChangesNothingForTheIdentityInProgress(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	boom := errors.New("store failed")
	s.fault.FailOnce("Audit.Insert", boom) // the first audit row fails
	if _, err := s.ops.Reseal(ctx, "main", s.id1, s.box12); !errors.Is(err, boom) {
		t.Fatalf("Reseal = %v, want the store error", err)
	}
	if s.value(t, "u1", "i1") != s.sealedBy["i1"] || len(s.actions(t, "identity.token_resealed")) != 0 {
		t.Fatal("the failed identity changed or was audited")
	}
	rep, err := s.ops.Reseal(ctx, "main", s.id1, s.box12)
	if err != nil || rep.Resealed != 2 {
		t.Fatalf("second run %+v, %v", rep, err)
	}
	if _, err := s.ops.Reseal(ctx, "main", s.id1, s.box12); err != nil {
		t.Fatal(err)
	}
	s.fault.Fail("Identities.SealedBy", boom)
	if _, err := s.ops.Reseal(ctx, "main", s.id1, s.box12); !errors.Is(err, boom) {
		t.Fatalf("a failed read: %v", err)
	}
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestClearSealedSetsTheValuesToNone(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	rep, err := s.ops.ClearSealed(ctx, "main", s.id1)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cleared != 2 || rep.Skipped != 0 {
		t.Fatalf("report %+v", rep)
	}
	if s.value(t, "u1", "i1") != "" || s.value(t, "u2", "i2") != "" || s.value(t, "u3", "i3") != s.sealedBy["i3"] {
		t.Fatal("wrong values after the clear")
	}
	rows := s.actions(t, "identity.token_cleared")
	if len(rows) != 2 || rows[0].UserID != "u1" || rows[1].UserID != "u2" {
		t.Fatalf("rows %+v", rows)
	}
	for _, ev := range rows {
		if ev.Actor != "admin" || len(ev.Details) != 2 || ev.Details["provider"] != "apple" || ev.Details["key_id"] != s.id1 {
			t.Fatalf("row %+v", ev)
		}
	}
	before := len(s.events(t))
	rep, err = s.ops.ClearSealed(ctx, "main", s.id1)
	if err != nil || rep.Cleared != 0 || rep.Skipped != 0 || len(s.events(t)) != before {
		t.Fatalf("second run: %+v, %v", rep, err)
	}
	if _, err := s.ops.ClearSealed(ctx, "main", "ABCDEF12"); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := s.ops.ClearSealed(ctx, "nope", s.id1); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
	s.noSecrets(t)
}

// Covers: SEC-47 (part)
// Acceptance: Reseal and clear sealed tokens (part)
func TestClearSealedLeavesATokenTheServiceChangedInTheMeantime(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	next, err := s.box12.Seal([]byte("the-new-login-token"))
	if err != nil {
		t.Fatal(err)
	}
	s.fault.BeforeWrite(1, func() { s.setValue(t, "i1", s.sealedBy["i1"], next) })
	rep, err := s.ops.ClearSealed(ctx, "main", s.id1)
	if err != nil || rep.Cleared != 1 || rep.Skipped != 1 {
		t.Fatalf("report %+v, %v", rep, err)
	}
	if s.value(t, "u1", "i1") != next || s.value(t, "u2", "i2") != "" {
		t.Fatal("the service's value was overwritten, or the other was not cleared")
	}
	if rows := s.actions(t, "identity.token_cleared"); len(rows) != 1 || rows[0].UserID != "u2" {
		t.Fatalf("rows %+v", rows)
	}
	boom := errors.New("store failed")
	s.fault.Fail("Identities.ReplaceProviderToken", boom)
	if _, err := s.ops.ClearSealed(ctx, "main", s.id2); !errors.Is(err, boom) {
		t.Fatalf("a store failure: %v", err)
	}
	if s.value(t, "u3", "i3") != s.sealedBy["i3"] {
		t.Fatal("the identity in progress changed")
	}
}

// The types that list identities log no token and no subject.
//
// Covers: SEC-43 (part), SEC-47 (part)
func TestSealedTypesLogNoValues(t *testing.T) {
	ref := admin.SealedRef{UserID: "u1", Provider: "apple", Subject: "subject-xyz"}
	rep := admin.ResealReport{Resealed: 1, Failed: []admin.SealedRef{ref}}
	si := store.SealedIdentity{ID: "i1", UserID: "u1", Provider: "apple", Subject: "subject-xyz", Value: "aaaaaaaa.secret-value"}
	var buf bytes.Buffer
	l := logx.New(&buf, 0, clock.NewFake(start))
	l.Info("direct", "ref", ref, "report", rep, "ident", si)
	l.Info("nested", "details", map[string]any{"ref": ref, "report": rep, "ident": si})
	out := buf.String()
	for _, bad := range []string{"subject-xyz", "secret-value", "aaaaaaaa."} {
		if strings.Contains(out, bad) {
			t.Fatalf("log holds %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, "u1") {
		t.Fatalf("log lacks the user id: %s", out)
	}
}
