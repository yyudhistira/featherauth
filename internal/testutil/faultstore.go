package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// FaultStore wraps a real store and injects failures. FailWrite makes every
// Write fail at once; Fail makes one repository operation, named like
// "Refresh.Insert", fail in the middle of a transaction. Operations:
// Realms.Ensure, Realms.Find, Users.Get, Users.Create, Users.Update,
// Users.FindVerifiedByEmailKey, Identities.Find, Identities.Create,
// Identities.Update, Identities.Delete, Identities.ListByUser, Identities.SetProviderToken,
// Identities.SealedBy, Identities.ReplaceProviderToken, Users.Delete,
// Refresh.RevokeUser, Refresh.DeleteUser, Audit.Insert, AuthCodes.Create, AuthCodes.Consume,
// Refresh.Insert, Refresh.FindByHash, Refresh.FindByID, Refresh.MarkReplaced, Refresh.Extend,
// Refresh.RevokeSession, Refresh.RevokeOthers, Refresh.SessionLive, AuthRequests.Delete,
// SSOSessions.Create, SSOSessions.Find, SSOSessions.Touch, SSOSessions.Delete,
// SSOSessions.DeleteByUser, SSOSessions.DeleteByIdentity and SSOSessions.DeleteByRealm.
// FailOnce makes the named operation fail with err on its next call only.
// AbortRuns makes the first runs runs of every Write fail with err after its
// function has run, as a Postgres deadlock or serialization failure does: the
// store rolls the run back, so the test sees what a second run sees.
// With nothing set it only delegates. Writes counts the write transactions
// started, including the ones that FailWrite makes fail.
type FaultStore struct {
	store.Store
	FailWrite error
	// FailRead makes every Read fail at once.
	FailRead error

	mu        sync.Mutex
	ops       map[string]error
	once      map[string]error
	abortRuns int
	abortErr  error
	writes    int
	// swapUser is the user that the swapAt-th Identities.Find after SwapFind
	// returns as the identity's user; empty when no swap is set.
	swapUser store.UserID
	swapAt   int
	findRuns int
	// beforeWrite is run before the beforeAt-th Write after BeforeWrite.
	beforeWrite func()
	beforeAt    int
}

// NewFaultStore wraps s.
func NewFaultStore(s store.Store) *FaultStore { return &FaultStore{Store: s} }

var _ store.Store = (*FaultStore)(nil)

// Fail makes the named operation return err from now on.
func (f *FaultStore) Fail(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ops == nil {
		f.ops = map[string]error{}
	}
	f.ops[op] = err
}

// FailOnce makes the named operation return err on its next call only.
func (f *FaultStore) FailOnce(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.once == nil {
		f.once = map[string]error{}
	}
	f.once[op] = err
}

// SwapFind makes the nth Identities.Find from now on (1 is the next one) return
// the identity with the user id user instead of its own, so a test can check
// that a login refuses an identity of another user.
func (f *FaultStore) SwapFind(nth int, user store.UserID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swapUser, f.swapAt, f.findRuns = user, nth, 0
}

// swappedUser counts one Identities.Find and returns the user to swap in, if
// this is the call SwapFind names.
func (f *FaultStore) swappedUser() (store.UserID, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.swapUser == "" {
		return "", false
	}
	f.findRuns++
	if f.findRuns == f.swapAt {
		return f.swapUser, true
	}
	return "", false
}

// BeforeWrite runs fn before the nth Write from now on (1 is the next one),
// before its transaction starts, so a test can change the data as another
// process (the service) does between a command's read and its write. fn runs
// once and may use the wrapped store.
func (f *FaultStore) BeforeWrite(nth int, fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeWrite, f.beforeAt = fn, nth
}

// AbortRuns makes the first n runs of every later Write fail with err after
// their function has run.
func (f *FaultStore) AbortRuns(n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.abortRuns, f.abortErr = n, err
}

func (f *FaultStore) failure(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.once[op]; ok {
		delete(f.once, op)
		return err
	}
	return f.ops[op]
}

// Read implements store.Store.
func (f *FaultStore) Read(ctx context.Context, fn func(store.Tx) error) error {
	if f.FailRead != nil {
		return f.FailRead
	}
	return f.Store.Read(ctx, func(tx store.Tx) error { return fn(faultTx{tx, f}) })
}

// Writes returns how many write transactions were started.
func (f *FaultStore) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// Write implements store.Store.
func (f *FaultStore) Write(ctx context.Context, fn func(store.Tx) error) error {
	f.mu.Lock()
	f.writes++
	n, abort := f.abortRuns, f.abortErr
	var hook func()
	if f.beforeWrite != nil {
		if f.beforeAt--; f.beforeAt == 0 {
			hook, f.beforeWrite = f.beforeWrite, nil
		}
	}
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if f.FailWrite != nil {
		return f.FailWrite
	}
	if n == 0 {
		return f.Store.Write(ctx, func(tx store.Tx) error { return fn(faultTx{tx, f}) })
	}
	runs := 0
	return f.Store.Write(ctx, func(tx store.Tx) error {
		runs++
		err := fn(faultTx{tx, f})
		if runs <= n {
			return abort
		}
		return err
	})
}

type faultTx struct {
	store.Tx
	f *FaultStore
}

func (t faultTx) Realms() store.Realms { return faultRealms{t.Tx.Realms(), t.f} }
func (t faultTx) Users() store.Users   { return faultUsers{t.Tx.Users(), t.f} }
func (t faultTx) Identities() store.Identities {
	return faultIdentities{t.Tx.Identities(), t.f}
}
func (t faultTx) Audit() store.Audit { return faultAudit{t.Tx.Audit(), t.f} }
func (t faultTx) AuthCodes() store.AuthCodes {
	return faultCodes{t.Tx.AuthCodes(), t.f}
}
func (t faultTx) RefreshTokens() store.RefreshTokens {
	return faultRefresh{t.Tx.RefreshTokens(), t.f}
}

// SSOSessions wraps the browser sessions so that SSOSessions.Create can fail.
func (t faultTx) SSOSessions() store.SSOSessions {
	return faultSSO{t.Tx.SSOSessions(), t.f}
}

type faultSSO struct {
	store.SSOSessions
	f *FaultStore
}

// Create fails with the injected error, if one is set for SSOSessions.Create,
// and otherwise stores the row.
func (s faultSSO) Create(ctx context.Context, ss store.SSOSession) error {
	if err := s.f.failure("SSOSessions.Create"); err != nil {
		return err
	}
	return s.SSOSessions.Create(ctx, ss)
}

// Delete fails with the injected error, if one is set for SSOSessions.Delete,
// and otherwise deletes the row.
func (s faultSSO) Delete(ctx context.Context, realm store.RealmID, h secure.Hash) error {
	if err := s.f.failure("SSOSessions.Delete"); err != nil {
		return err
	}
	return s.SSOSessions.Delete(ctx, realm, h)
}

// Find fails with the injected error, if one is set for SSOSessions.Find.
func (s faultSSO) Find(ctx context.Context, realm store.RealmID, h secure.Hash) (store.SSOSession, error) {
	if err := s.f.failure("SSOSessions.Find"); err != nil {
		return store.SSOSession{}, err
	}
	return s.SSOSessions.Find(ctx, realm, h)
}

// Touch fails with the injected error, if one is set for SSOSessions.Touch.
func (s faultSSO) Touch(ctx context.Context, realm store.RealmID, h secure.Hash, used, expires time.Time) error {
	if err := s.f.failure("SSOSessions.Touch"); err != nil {
		return err
	}
	return s.SSOSessions.Touch(ctx, realm, h, used, expires)
}

// DeleteByUser fails with the injected error, if one is set for
// SSOSessions.DeleteByUser.
func (s faultSSO) DeleteByUser(ctx context.Context, realm store.RealmID, u store.UserID) error {
	if err := s.f.failure("SSOSessions.DeleteByUser"); err != nil {
		return err
	}
	return s.SSOSessions.DeleteByUser(ctx, realm, u)
}

// DeleteByIdentity fails with the injected error, if one is set for
// SSOSessions.DeleteByIdentity.
func (s faultSSO) DeleteByIdentity(ctx context.Context, realm store.RealmID, i store.IdentityID) error {
	if err := s.f.failure("SSOSessions.DeleteByIdentity"); err != nil {
		return err
	}
	return s.SSOSessions.DeleteByIdentity(ctx, realm, i)
}

// DeleteByRealm fails with the injected error, if one is set for
// SSOSessions.DeleteByRealm.
func (s faultSSO) DeleteByRealm(ctx context.Context, realm store.RealmID) error {
	if err := s.f.failure("SSOSessions.DeleteByRealm"); err != nil {
		return err
	}
	return s.SSOSessions.DeleteByRealm(ctx, realm)
}

// AuthRequests wraps the logins in progress so that AuthRequests.Delete can fail.
func (t faultTx) AuthRequests() store.AuthRequests {
	return faultAuthRequests{t.Tx.AuthRequests(), t.f}
}

type faultRealms struct {
	store.Realms
	f *FaultStore
}

func (r faultRealms) Ensure(ctx context.Context, n config.RealmName, id store.RealmID, at time.Time) (store.RealmID, error) {
	if err := r.f.failure("Realms.Ensure"); err != nil {
		return "", err
	}
	return r.Realms.Ensure(ctx, n, id, at)
}

func (r faultRealms) Find(ctx context.Context, n config.RealmName) (store.RealmID, error) {
	if err := r.f.failure("Realms.Find"); err != nil {
		return "", err
	}
	return r.Realms.Find(ctx, n)
}

type faultUsers struct {
	store.Users
	f *FaultStore
}

func (u faultUsers) Get(ctx context.Context, realm store.RealmID, id store.UserID) (store.User, error) {
	if err := u.f.failure("Users.Get"); err != nil {
		return store.User{}, err
	}
	return u.Users.Get(ctx, realm, id)
}

// faultAuthRequests is the AuthRequests of a faultTx.
type faultAuthRequests struct {
	store.AuthRequests
	f *FaultStore
}

// Delete fails with the injected error, if one is set for AuthRequests.Delete,
// and otherwise deletes the row.
func (a faultAuthRequests) Delete(ctx context.Context, id store.AuthRequestID) error {
	if err := a.f.failure("AuthRequests.Delete"); err != nil {
		return err
	}
	return a.AuthRequests.Delete(ctx, id)
}

type faultCodes struct {
	store.AuthCodes
	f *FaultStore
}

func (c faultCodes) Create(ctx context.Context, ac store.AuthCode) error {
	if err := c.f.failure("AuthCodes.Create"); err != nil {
		return err
	}
	return c.AuthCodes.Create(ctx, ac)
}

func (c faultCodes) Consume(ctx context.Context, h secure.Hash, now time.Time) (store.AuthCode, error) {
	if err := c.f.failure("AuthCodes.Consume"); err != nil {
		return store.AuthCode{}, err
	}
	return c.AuthCodes.Consume(ctx, h, now)
}

type faultRefresh struct {
	store.RefreshTokens
	f *FaultStore
}

func (r faultRefresh) Insert(ctx context.Context, rt store.RefreshToken) error {
	if err := r.f.failure("Refresh.Insert"); err != nil {
		return err
	}
	return r.RefreshTokens.Insert(ctx, rt)
}

func (r faultRefresh) FindByHash(ctx context.Context, realm store.RealmID, h secure.Hash) (store.RefreshToken, error) {
	if err := r.f.failure("Refresh.FindByHash"); err != nil {
		return store.RefreshToken{}, err
	}
	return r.RefreshTokens.FindByHash(ctx, realm, h)
}

func (r faultRefresh) FindByID(ctx context.Context, realm store.RealmID, id store.RefreshTokenID) (store.RefreshToken, error) {
	if err := r.f.failure("Refresh.FindByID"); err != nil {
		return store.RefreshToken{}, err
	}
	return r.RefreshTokens.FindByID(ctx, realm, id)
}

// UserLiveSessions fails with the injected error, if one is set for
// Refresh.UserLiveSessions.
func (r faultRefresh) UserLiveSessions(ctx context.Context, realm store.RealmID, id store.UserID, now time.Time) ([]store.LiveSession, error) {
	if err := r.f.failure("Refresh.UserLiveSessions"); err != nil {
		return nil, err
	}
	return r.RefreshTokens.UserLiveSessions(ctx, realm, id, now)
}

func (r faultRefresh) MarkReplaced(ctx context.Context, id, succ store.RefreshTokenID) error {
	if err := r.f.failure("Refresh.MarkReplaced"); err != nil {
		return err
	}
	return r.RefreshTokens.MarkReplaced(ctx, id, succ)
}

func (r faultRefresh) Extend(ctx context.Context, realm store.RealmID, id store.RefreshTokenID, at time.Time) error {
	if err := r.f.failure("Refresh.Extend"); err != nil {
		return err
	}
	return r.RefreshTokens.Extend(ctx, realm, id, at)
}

func (r faultRefresh) RevokeSession(ctx context.Context, realm store.RealmID, s store.SessionID, now time.Time) (store.Ended, error) {
	if err := r.f.failure("Refresh.RevokeSession"); err != nil {
		return store.Ended{}, err
	}
	return r.RefreshTokens.RevokeSession(ctx, realm, s, now)
}

func (r faultRefresh) SessionLive(ctx context.Context, realm store.RealmID, s store.SessionID) (bool, error) {
	if err := r.f.failure("Refresh.SessionLive"); err != nil {
		return false, err
	}
	return r.RefreshTokens.SessionLive(ctx, realm, s)
}

func (r faultRefresh) RevokeOthers(ctx context.Context, realm store.RealmID, s store.SessionID, keep store.RefreshTokenID, now time.Time) error {
	if err := r.f.failure("Refresh.RevokeOthers"); err != nil {
		return err
	}
	return r.RefreshTokens.RevokeOthers(ctx, realm, s, keep, now)
}

func (u faultUsers) Create(ctx context.Context, usr store.User) error {
	if err := u.f.failure("Users.Create"); err != nil {
		return err
	}
	return u.Users.Create(ctx, usr)
}

func (u faultUsers) Update(ctx context.Context, usr store.User) error {
	if err := u.f.failure("Users.Update"); err != nil {
		return err
	}
	return u.Users.Update(ctx, usr)
}

func (u faultUsers) FindVerifiedByEmailKey(ctx context.Context, realm store.RealmID, key string) (store.User, error) {
	if err := u.f.failure("Users.FindVerifiedByEmailKey"); err != nil {
		return store.User{}, err
	}
	return u.Users.FindVerifiedByEmailKey(ctx, realm, key)
}

type faultIdentities struct {
	store.Identities
	f *FaultStore
}

func (i faultIdentities) Find(ctx context.Context, realm store.RealmID, p config.ProviderKey, sub string) (store.Identity, error) {
	if err := i.f.failure("Identities.Find"); err != nil {
		return store.Identity{}, err
	}
	ident, err := i.Identities.Find(ctx, realm, p, sub)
	// Every call counts, found or not, so that SwapFind names a call by its order.
	if u, ok := i.f.swappedUser(); ok && err == nil {
		ident.UserID = u
	}
	return ident, err
}

func (i faultIdentities) Create(ctx context.Context, id store.Identity) error {
	if err := i.f.failure("Identities.Create"); err != nil {
		return err
	}
	return i.Identities.Create(ctx, id)
}

func (i faultIdentities) Update(ctx context.Context, id store.Identity) error {
	if err := i.f.failure("Identities.Update"); err != nil {
		return err
	}
	return i.Identities.Update(ctx, id)
}

type faultAudit struct {
	store.Audit
	f *FaultStore
}

func (a faultAudit) Insert(ctx context.Context, e store.AuditEvent) error {
	if err := a.f.failure("Audit.Insert"); err != nil {
		return err
	}
	return a.Audit.Insert(ctx, e)
}

func (u faultUsers) Delete(ctx context.Context, realm store.RealmID, id store.UserID) error {
	if err := u.f.failure("Users.Delete"); err != nil {
		return err
	}
	return u.Users.Delete(ctx, realm, id)
}

func (i faultIdentities) Delete(ctx context.Context, realm store.RealmID, id store.IdentityID) error {
	if err := i.f.failure("Identities.Delete"); err != nil {
		return err
	}
	return i.Identities.Delete(ctx, realm, id)
}

func (i faultIdentities) ListByUser(ctx context.Context, realm store.RealmID, u store.UserID) ([]store.Identity, error) {
	if err := i.f.failure("Identities.ListByUser"); err != nil {
		return nil, err
	}
	return i.Identities.ListByUser(ctx, realm, u)
}

func (i faultIdentities) SetProviderToken(ctx context.Context, realm store.RealmID, id store.IdentityID, sealed string) error {
	if err := i.f.failure("Identities.SetProviderToken"); err != nil {
		return err
	}
	return i.Identities.SetProviderToken(ctx, realm, id, sealed)
}

func (i faultIdentities) SealedBy(ctx context.Context, realm store.RealmID, keyID string) ([]store.SealedIdentity, error) {
	if err := i.f.failure("Identities.SealedBy"); err != nil {
		return nil, err
	}
	return i.Identities.SealedBy(ctx, realm, keyID)
}

func (i faultIdentities) ReplaceProviderToken(ctx context.Context, realm store.RealmID, id store.IdentityID, old, next string) (bool, error) {
	if err := i.f.failure("Identities.ReplaceProviderToken"); err != nil {
		return false, err
	}
	return i.Identities.ReplaceProviderToken(ctx, realm, id, old, next)
}

func (r faultRefresh) RevokeUser(ctx context.Context, realm store.RealmID, u store.UserID, now time.Time) (store.Ended, error) {
	if err := r.f.failure("Refresh.RevokeUser"); err != nil {
		return store.Ended{}, err
	}
	return r.RefreshTokens.RevokeUser(ctx, realm, u, now)
}

func (r faultRefresh) DeleteUser(ctx context.Context, realm store.RealmID, u store.UserID) (store.Ended, error) {
	if err := r.f.failure("Refresh.DeleteUser"); err != nil {
		return store.Ended{}, err
	}
	return r.RefreshTokens.DeleteUser(ctx, realm, u)
}

// LogoutNotifications wraps the logout notifications of a faultTx: Logout.Enqueue,
// Logout.Claim, Logout.Done and Logout.Drop can fail.
func (t faultTx) LogoutNotifications() store.LogoutNotifications {
	return faultLogout{t.Tx.LogoutNotifications(), t.f}
}

type faultLogout struct {
	store.LogoutNotifications
	f *FaultStore
}

func (l faultLogout) Enqueue(ctx context.Context, n store.LogoutNotification) error {
	if err := l.f.failure("Logout.Enqueue"); err != nil {
		return err
	}
	return l.LogoutNotifications.Enqueue(ctx, n)
}

func (l faultLogout) Claim(ctx context.Context, now time.Time, limit int) ([]store.LogoutNotification, error) {
	if err := l.f.failure("Logout.Claim"); err != nil {
		return nil, err
	}
	return l.LogoutNotifications.Claim(ctx, now, limit)
}

func (l faultLogout) Done(ctx context.Context, id store.LogoutNotificationID) error {
	if err := l.f.failure("Logout.Done"); err != nil {
		return err
	}
	return l.LogoutNotifications.Done(ctx, id)
}

func (l faultLogout) Drop(ctx context.Context, id store.LogoutNotificationID) error {
	if err := l.f.failure("Logout.Drop"); err != nil {
		return err
	}
	return l.LogoutNotifications.Drop(ctx, id)
}
