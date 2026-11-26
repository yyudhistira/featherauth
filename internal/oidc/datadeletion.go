package oidc

import (
	"net/http"
	"regexp"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/web"
)

// DataDeletion is the data-deletion instructions page, GET /{realm}/data-deletion
// (FR-34). It tells the user to delete the account in the app or to write to
// the realm's login_page.contact. Opened with the confirmation code Meta was
// given (FR-40), it adds one sentence saying that deletions are carried out at
// once, and shows the code.
type DataDeletion struct{}

var _ http.Handler = DataDeletion{}

// NewDataDeletion returns the data-deletion page handler.
func NewDataDeletion() DataDeletion { return DataDeletion{} }

// ServeHTTP renders the page of the realm in the request context.
func (DataDeletion) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet) {
		return
	}
	page := web.Page{Kind: web.PageDataDeletion}
	// A confirmation code (Meta's callback) adds one sentence; a code that is
	// repeated or not 22 ASCII letters and digits is ignored.
	if codes := r.URL.Query()["code"]; len(codes) == 1 && confirmationCode.MatchString(codes[0]) {
		page.Code = codes[0]
	}
	pages.Page(w, r, info.Realm, page)
}

// confirmationCode is the form of the codes the events endpoint gives Meta.
var confirmationCode = regexp.MustCompile(`^[A-Za-z0-9]{22}$`)
