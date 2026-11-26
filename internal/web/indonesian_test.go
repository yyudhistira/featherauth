package web_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/web"
)

// idRealmExtra is a realm that lists id in supported_locales, with no
// translation file: the built-in Indonesian is served.
const idRealmExtra = "display_name: Example Realm\n" +
	"login_page:\n" +
	"  logo_url: https://example.com/logo.png\n" +
	"  accent_color: \"#ff6600\"\n" +
	"  contact: help@example.com\n" +
	"  supported_locales: [en, id]\n" +
	testutil.DefaultClients

// idPages are the pages a visitor sees, each with the message id of its title
// and of its text, which must be in Indonesian.
var idPages = []struct {
	name string
	page web.Page
	ids  []string
}{
	{"chooser", chooser, []string{"chooser.title", "chooser.prompt"}},
	{"error", web.Page{Kind: web.PageError, Status: 400, MessageID: "error.invalid_request"}, []string{"error.title", "error.invalid_request", "error.contact"}},
	{"error server", web.Page{Kind: web.PageError, Status: 500, MessageID: "error.server"}, []string{"error.title", "error.server"}},
	{"signed out", web.Page{Kind: web.PageSignedOut}, []string{"signed_out.title", "signed_out.body"}},
	{"data deletion", web.Page{Kind: web.PageDataDeletion, Code: "AB12CD34EF56GH78IJ90KL"}, []string{"data_deletion.title", "data_deletion.in_app", "data_deletion.confirmed"}},
	{"form post", web.Page{Kind: web.PageFormPost, Action: "https://app.example.com/cb", Fields: []web.Field{{Name: "code", Value: "x"}}}, []string{"form_post.title", "form_post.body", "form_post.button"}},
}

// Covers: FR-50, FR-57 (part)
// Acceptance: Built-in languages
func TestIndonesianPagesHaveNoEnglishLeft(t *testing.T) {
	realm := newRealmIn(t, serverDefaultYAML, idRealmExtra)
	id, ok := web.BuiltinTranslation("id")
	if !ok {
		t.Fatal("no built-in Indonesian translation")
	}
	for _, p := range idPages {
		t.Run(p.name, func(t *testing.T) {
			body := render(t, realm, "id", p.page).Body.String()
			if !strings.Contains(body, `lang="id"`) {
				t.Errorf("the page is not marked id:\n%s", body)
			}
			for _, mid := range p.ids {
				if !strings.Contains(body, id[mid]) {
					t.Errorf("the page lacks the Indonesian text of %s: %q", mid, id[mid])
				}
			}
			if p.name == "chooser" && !strings.Contains(body, "<span>Masuk dengan Google</span>") {
				t.Errorf("the provider buttons are not in Indonesian:\n%s", body)
			}
			for mid, english := range web.English {
				if strings.Contains(body, english) {
					t.Errorf("the page still holds the English text of %s: %q", mid, english)
				}
			}
		})
	}
}

// Covers: FR-50
// Acceptance: Built-in languages (part)
func TestIndonesianNeedsTheListing(t *testing.T) {
	realm := newRealm(t, realmExtra) // supported_locales is the default [en]
	body := render(t, realm, "id", chooser).Body.String()
	if !strings.Contains(body, `lang="en"`) || !strings.Contains(body, web.English["chooser.prompt"]) {
		t.Errorf("without id in supported_locales the default locale is not used:\n%s", body)
	}
}

// Covers: FR-50
// Acceptance: Built-in languages (part)
func TestConfigFileReplacesOneIndonesianMessage(t *testing.T) {
	src, dir := testutil.NewConfigDir(t, serverDefaultYAML, map[string]string{"main": testutil.MinimalRealm("main")})
	dir.Write(t, "locales/id.yaml", "chooser.title: Masuk ke akun Anda\n")
	testutil.WriteRealm(t, dir, "main", testutil.RealmYAML("main", "login_page:\n  supported_locales: [en, id]\n"+testutil.DefaultClients))
	if res := src.Reload(t.Context()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	realm, _ := src.Current().Realm("main")
	body := render(t, realm, "id", chooser).Body.String()
	id, _ := web.BuiltinTranslation("id")
	for _, want := range []string{"<h1>Masuk ke akun Anda</h1>", id["chooser.prompt"], "<span>Masuk dengan Google</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q, the replaced message or a built-in one:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<h1>Masuk</h1>") {
		t.Error("the built-in title shows although the file replaces it")
	}
}

// Covers: FR-50
// Acceptance: Built-in languages (part)
func TestChooserInIndonesianMatchesGolden(t *testing.T) {
	realm := newRealmIn(t, serverDefaultYAML, idRealmExtra)
	golden(t, "chooser_id.golden.html", render(t, realm, "id", chooser).Body.Bytes())
}

// Covers: FR-50
// Acceptance: Built-in languages (part)
// A test fails when the built-in id translation lacks a message id, or holds
// one that no message has, or moves a {name} placeholder.
func TestBuiltinIndonesianHasEveryMessageID(t *testing.T) {
	id, ok := web.BuiltinTranslation("id")
	if !ok {
		t.Fatal("no built-in Indonesian translation")
	}
	for mid, english := range web.English {
		text, has := id[mid]
		if !has || text == "" {
			t.Errorf("the Indonesian translation lacks %q", mid)
			continue
		}
		if strings.Contains(english, "{name}") != strings.Contains(text, "{name}") {
			t.Errorf("%q: the {name} placeholder differs between English and Indonesian", mid)
		}
	}
	for mid := range id {
		if _, ok := web.English[mid]; !ok {
			t.Errorf("the Indonesian translation has %q, which no message has", mid)
		}
	}
}

// Covers: FR-50 (part)
// Acceptance: Built-in languages (part)
// The languages the binary translates are the built-in locales of the config,
// with English.
func TestBuiltinLocalesAreTheTranslatedLanguages(t *testing.T) {
	want := append([]string{"en"}, web.BuiltinLanguages()...)
	got := config.BuiltinLocales()
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("config builtin locales %v, web translations %v", got, want)
	}
	for _, code := range web.BuiltinLanguages() {
		if _, ok := web.BuiltinTranslation(code); !ok {
			t.Errorf("%s is listed but has no translation", code)
		}
	}
}
