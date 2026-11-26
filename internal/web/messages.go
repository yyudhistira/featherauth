package web

import (
	"slices"
	"strings"
)

// English is the built-in text of every message id. A realm's translation
// file (locales/<code>.yaml) maps ids to other text; an id it lacks shows in
// English. {name} in a text stands for the provider's name.
var English = map[string]string{
	"chooser.title":           "Sign in",
	"chooser.prompt":          "Choose how you want to sign in.",
	"chooser.log_in_with":     "Log in with {name}",
	"chooser.sign_in_with":    "Sign in with {name}",
	"chooser.no_providers":    "No sign-in method is available right now.",
	"data_deletion.title":     "Delete your data",
	"data_deletion.in_app":    "To delete your account and the data stored about you, use the delete-account option in the app.",
	"data_deletion.contact":   "If you cannot do that, write to",
	"data_deletion.confirmed": "Deletion requests are carried out at once. Your confirmation code is",
	"error.title":             "Something went wrong",
	"error.contact":           "If this keeps happening, contact",
	"error.invalid_request":   "The request is not valid, so you cannot be sent back to the app. Go back to the app and try again.",
	"error.request_expired":   "This sign-in request is unknown or has expired. Go back to the app and try again.",
	"error.realm_disabled":    "Sign-in is not available right now.",
	"error.logout_refused":    "The sign-out request could not be verified.",
	"error.server":            "Something went wrong on our side. Try again later.",
	"form_post.title":         "Continue",
	"form_post.body":          "You are being sent back to the app.",
	"form_post.button":        "Continue",
	"signed_out.title":        "Signed out",
	"signed_out.body":         "You are signed out. You can close this window.",
}

// ExampleLocale is the content of locales/en.yaml.example: every message id
// with its English text, one per line, sorted by id.
func ExampleLocale() []byte {
	var b strings.Builder
	b.WriteString("# Translation file example: every message id with its English text.\n")
	b.WriteString("# Copy it to locales/<code>.yaml, translate the values, and list <code> in\n")
	b.WriteString("# login_page.supported_locales. An id that is missing shows in English.\n")
	b.WriteString("# {name} stands for the provider's name.\n")
	ids := make([]string, 0, len(English))
	for id := range English {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		b.WriteString(id + ": " + yamlQuote(English[id]) + "\n")
	}
	return []byte(b.String())
}

// yamlQuote writes s as a double-quoted YAML scalar.
func yamlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
