package config

import "slices"

// builtinLocales are the languages the binary ships a translation of, with
// English (FR-50): listing one in login_page.supported_locales needs no file.
var builtinLocales = []string{"en", "id"}

// BuiltinLocales returns the languages the binary translates, English included.
func BuiltinLocales() []string { return slices.Clone(builtinLocales) }

// BuiltinLocale reports whether code is a built-in language.
func BuiltinLocale(code string) bool { return slices.Contains(builtinLocales, code) }
