package config

import (
	"slices"
	"testing"
)

// Covers: FR-50
// Acceptance: Built-in languages (part)
// Listing a built-in language needs no translation file; another language still does.
func TestBuiltinLocaleNeedsNoFile(t *testing.T) {
	dir := keyDir(t)
	ok := realmRow("id listed without a file", "login_page:\n  supported_locales: [en, id]\n  default_locale: id\n", 0, "", "")
	if ds := validateText(t, dir, ok.kind, ok.fileName(), ok.text(), ok.noEnc); len(ds) != 0 {
		t.Fatalf("id is built in, but the config reports %v", ds)
	}
	other := realmRow("nl listed without a file", "login_page:\n  supported_locales: [en, nl]\n", 0, "", "")
	if ds := validateText(t, dir, other.kind, other.fileName(), other.text(), other.noEnc); len(ds) == 0 {
		t.Fatal("nl is not built in and has no file, but the config accepts it")
	}
}

// Covers: FR-50 (part)
// Acceptance: Built-in languages (part)
func TestBuiltinLocales(t *testing.T) {
	got := BuiltinLocales()
	slices.Sort(got)
	if want := []string{"en", "id"}; !slices.Equal(got, want) {
		t.Errorf("BuiltinLocales = %v, want %v", got, want)
	}
	if !BuiltinLocale("id") || !BuiltinLocale("en") || BuiltinLocale("nl") {
		t.Error("BuiltinLocale does not match BuiltinLocales")
	}
}
