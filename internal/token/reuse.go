package token

import (
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

// ReuseKind says which kind of token was reused.
type ReuseKind string

// The kinds of reuse: a refresh token presented after its grace window, or
// after one of its successors was used, and a login code used a second time.
const (
	ReuseRefreshToken ReuseKind = "refresh_token"
	ReuseCode         ReuseKind = "code"
)

// Reuse describes a reused refresh token or login code that revoked a session.
// The token endpoint records it (SEC-25): a warning, and an audit row when
// Ended is true.
type Reuse struct {
	// Realm is the store id of the realm of the session.
	Realm store.RealmID
	// User is the user the session belongs to.
	User UserID
	// Client is the client the session belongs to.
	Client config.ClientID
	// Session is the session that was revoked.
	Session SessionID
	// Kind is the kind of token that was reused.
	Kind ReuseKind
	// Ended is true when the revocation ended at least one refresh token of
	// the session that was not revoked before (an expired one counts).
	Ended bool
}
