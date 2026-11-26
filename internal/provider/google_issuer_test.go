package provider

import (
	"strings"
	"testing"
)

// The issuer rule of Google's security events (FR-48): two issuers match when
// each, minus one trailing "/", gives the same text that is not empty and does
// not end in "/"; nothing else is normalised.
// Covers: FR-48
// Acceptance: Google issuer with a trailing slash (part)
func TestSameIssuer(t *testing.T) {
	const g = "https://accounts.google.com"
	rows := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", g, g, true},
		{"the first with one slash", g + "/", g, true},
		{"the second with one slash", g, g + "/", true},
		{"both with a slash", g + "/", g + "/", true},
		{"both with two slashes", g + "//", g + "//", false},
		{"two slashes", g + "//", g, false},
		{"two slashes against one", g + "//", g + "/", false},
		{"three slashes against two", g + "///", g + "//", false},
		{"three slashes against one", g + "///", g + "/", false},
		{"three slashes", g + "///", g, false},
		{"upper-case scheme", "HTTPS://accounts.google.com", g, false},
		{"upper-case host", "https://Accounts.google.com", g, false},
		{"upper-case host with the slash", "https://Accounts.google.com/", g, false},
		{"http", "http://accounts.google.com", g, false},
		{"no scheme", "accounts.google.com", g, false},
		{"a path", g + "/x", g, false},
		{"a leading space", " " + g, g, false},
		{"a trailing space", g + " ", g, false},
		{"an empty token issuer", "", g, false},
		{"an empty document issuer", g, "", false},
		{"both empty", "", "", false},
		{"a lone slash against empty", "/", "", false},
		{"empty against a lone slash", "", "/", false},
		{"a lone slash against a lone slash", "/", "/", false},
		{"two slashes against empty", "//", "", false},
		{"a lone slash against an issuer", "/", g, false},
		{"another issuer", "https://other.example", g, false},
		{"another issuer with a slash", "https://other.example/", g, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := sameIssuer(r.a, r.b); got != r.want {
				t.Errorf("sameIssuer(%q, %q) = %v, want %v", r.a, r.b, got, r.want)
			}
			if got := sameIssuer(r.b, r.a); got != r.want {
				t.Errorf("sameIssuer(%q, %q) = %v, want %v (not symmetric)", r.b, r.a, got, r.want)
			}
		})
	}
}

// Covers: FR-48
func FuzzSameIssuer(f *testing.F) {
	for _, s := range [][2]string{
		{"", ""}, {"/", ""}, {"//", ""}, {"/", "/"}, {"https://accounts.google.com", "https://accounts.google.com/"},
		{"https://accounts.google.com//", "https://accounts.google.com"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ta, tb := strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/")
		want := ta == tb && ta != "" && !strings.HasSuffix(ta, "/")
		if got := sameIssuer(a, b); got != want {
			t.Fatalf("sameIssuer(%q, %q) = %v, want %v", a, b, got, want)
		}
		if sameIssuer(a, b) != sameIssuer(b, a) {
			t.Fatalf("sameIssuer is not symmetric for %q, %q", a, b)
		}
	})
}
