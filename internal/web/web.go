// Package web renders the browser pages: the provider chooser, the error,
// signed-out and data-deletion pages and the form_post answer page. It also
// serves the stylesheet and provider logos, sets the security headers of
// browser pages, and picks the page language.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
)

//go:embed templates
var templateFS embed.FS

// PageKind says which page to render.
type PageKind int

// The pages.
const (
	PageChooser PageKind = iota + 1
	PageError
	PageSignedOut
	PageDataDeletion
	// PageFormPost is the page that posts an authorization result to the
	// client by a self-submitting form (response_mode=form_post).
	PageFormPost
)

// Provider is one button of the chooser.
type Provider struct {
	Key config.ProviderKey
	// Name is the text of the button.
	Name string
	// Brand is "google", "apple", "github" or "facebook" for the built-in
	// providers, which draw their own logo and colours; empty for any other.
	Brand string
	// Href is the link of the button: the authorize request with the provider
	// hint added.
	Href string
}

// Field is one parameter of a form_post page.
type Field struct{ Name, Value string }

// Page is what to render.
type Page struct {
	Kind PageKind
	// Status is the HTTP status; 0 means 200.
	Status int
	// Providers are the chooser's buttons, in order.
	Providers []Provider
	// MessageID is the id of the explanation on an error page; an unknown id
	// shows error.server.
	MessageID string
	// Action and Fields are the target and the parameters of a form_post
	// page. Action must be an absolute URL.
	Action string
	Fields []Field
	// Code is the confirmation code a data-deletion page shows with one
	// extra sentence; empty shows the instructions only. The caller checks its
	// form; the template escapes it.
	Code string
}

// Renderer renders a page for a realm in the language of the request.
type Renderer interface {
	Page(w http.ResponseWriter, r *http.Request, realm *config.Realm, p Page)
}

// Pages renders the built-in templates.
type Pages struct {
	tmpl map[PageKind]*template.Template
}

var _ Renderer = (*Pages)(nil)

var pageFiles = map[PageKind]string{
	PageChooser:      "chooser.html",
	PageError:        "error.html",
	PageSignedOut:    "signed_out.html",
	PageDataDeletion: "data_deletion.html",
}

// NewPages parses the templates. They are built into the binary, so a parse
// error is a bug and panics.
func NewPages() *Pages {
	p := &Pages{tmpl: map[PageKind]*template.Template{}}
	for kind, file := range pageFiles {
		p.tmpl[kind] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+file))
	}
	p.tmpl[PageFormPost] = template.Must(template.ParseFS(templateFS, "templates/form_post.html"))
	return p
}

// formPostScript is the one script of the form_post page; its hash is in the
// page's Content-Security-Policy.
const formPostScript = "document.forms[0].submit();"

// scriptHash is the CSP source of formPostScript.
func scriptHash() string {
	sum := sha256.Sum256([]byte(formPostScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// contact is the realm's contact as a link.
type contact struct {
	Text string
	Href template.URL
}

func realmContact(realm *config.Realm) *contact {
	c := realm.LoginPage.Contact
	switch {
	case c == "":
		return nil
	case strings.HasPrefix(c, "https://"):
		return &contact{Text: c, Href: template.URL(c)}
	default:
		return &contact{Text: c, Href: template.URL("mailto:" + c)}
	}
}

// view is the data of every template.
type view struct {
	Lang       string
	Title      string
	RealmName  string
	AssetsPath string
	LogoURL    string
	Contact    *contact
	Providers  []providerView
	Message    string
	Action     template.URL
	Fields     []Field
	Script     template.HTML
	Code       string

	messages map[string]string // translation, may be nil
}

type providerView struct {
	Name, Href, Class, Logo string
}

// LogoFile is the file name of the provider's logo under logos/: PNG for
// Google (its SVGs need foreignObject) and Facebook (its kit has no SVG), SVG
// for the others.
func (p providerView) LogoFile() string {
	if p.Logo == "google" || p.Logo == "facebook" {
		return p.Logo + ".png"
	}
	return p.Logo + ".svg"
}

// T is the text of a message id, looked up in order: the realm's translation
// file for the page's language, the built-in translation of that language, and
// English (FR-50).
func (v *view) T(id string) string {
	if s, ok := v.messages[id]; ok {
		return s
	}
	if m, ok := builtin[v.Lang]; ok {
		if s, ok := m[id]; ok {
			return s
		}
	}
	return English[id]
}

// SignInWith is the text of a provider's button.
func (v *view) SignInWith(name string) string {
	return strings.ReplaceAll(v.T("chooser.sign_in_with"), "{name}", name)
}

// LogInWith is the text of the Facebook button: Meta's login wording is
// "Log in with Facebook" or "Continue with Facebook", not "Sign in with".
func (v *view) LogInWith(name string) string {
	return strings.ReplaceAll(v.T("chooser.log_in_with"), "{name}", name)
}

var builtinBrands = map[string]bool{"google": true, "apple": true, "github": true, "facebook": true}

// Page implements Renderer.
func (pg *Pages) Page(w http.ResponseWriter, r *http.Request, realm *config.Realm, p Page) {
	lang := Negotiate(r.Header.Get("Accept-Language"), realm.LoginPage.SupportedLocales, realm.LoginPage.DefaultLocale)
	v := &view{
		Lang:       lang,
		RealmName:  realmTitle(realm),
		AssetsPath: realm.EndpointPath(config.EndpointAssets, ""),
		messages:   realm.Messages(lang),
	}
	status := p.Status
	if status == 0 {
		status = http.StatusOK
	}
	tmpl, ok := pg.tmpl[p.Kind]
	if !ok {
		fail(w, realm)
		return
	}
	name := "layout"
	switch p.Kind {
	case PageChooser:
		v.Title = v.T("chooser.title")
		v.LogoURL = realm.LoginPage.LogoURL
		for _, pr := range p.Providers {
			pv := providerView{Name: pr.Name, Href: pr.Href, Class: "brand-generic"}
			if builtinBrands[pr.Brand] {
				pv.Class, pv.Logo = "brand-"+pr.Brand, pr.Brand
			}
			v.Providers = append(v.Providers, pv)
		}
	case PageError:
		v.Title = v.T("error.title")
		id := p.MessageID
		if _, known := English[id]; !known {
			id = "error.server"
		}
		v.Message = v.T(id)
		v.Contact = realmContact(realm)
	case PageSignedOut:
		v.Title = v.T("signed_out.title")
	case PageDataDeletion:
		v.Title = v.T("data_deletion.title")
		v.Code = p.Code
		v.Contact = realmContact(realm)
	case PageFormPost:
		u, err := url.Parse(p.Action)
		if err != nil || !safeAction(u) {
			fail(w, realm)
			return
		}
		v.Action, v.Fields = template.URL(p.Action), p.Fields
		v.Script = template.HTML("<script>" + formPostScript + "</script>")
		name = "form_post"
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, name, v); err != nil {
		fail(w, realm)
		return
	}
	h := w.Header()
	SecurityHeaders(realm, h)
	if p.Kind == PageFormPost {
		h.Set("Content-Security-Policy", formPostCSP(p.Action))
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, buf.String())
}

func realmTitle(realm *config.Realm) string {
	if realm.DisplayName != "" {
		return realm.DisplayName
	}
	return string(realm.Name)
}

// safeAction accepts an absolute URL whose scheme cannot run script. Redirect
// URIs are validated at load (FR-32); this is the last guard.
func safeAction(u *url.URL) bool {
	switch strings.ToLower(u.Scheme) {
	case "", "javascript", "data", "file", "vbscript":
		return false
	}
	return true
}

// formPostCSP is the policy of the form_post page: it replaces the realm's
// (FR-33) and allows only the page's script, by hash, and the target origin as
// form-action.
func formPostCSP(action string) string {
	u, _ := url.Parse(action)
	target := u.Scheme + ":"
	if u.Host != "" {
		target = u.Scheme + "://" + u.Host
	}
	return "default-src 'none'; script-src " + scriptHash() + "; form-action " + target + "; frame-ancestors 'none'"
}

// fail answers a page that cannot be rendered.
func fail(w http.ResponseWriter, realm *config.Realm) {
	h := w.Header()
	SecurityHeaders(realm, h)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintln(w, "internal error")
}
