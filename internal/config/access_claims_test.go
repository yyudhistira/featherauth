package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Covers: FR-41 (part)
// Acceptance: Access token claims (part)
func TestAccessTokenClaimsAbsentEmptyAndNull(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		set  bool
		want []string
	}{
		{name: "absent", yaml: "", set: false},
		{name: "one claim", yaml: "user_data:\n  access_token_claims: [preferred_username]\n", set: true, want: []string{"preferred_username"}},
		{name: "empty list is set", yaml: "user_data:\n  access_token_claims: []\n", set: true, want: []string{}},
		{name: "empty value is not set", yaml: "user_data:\n  access_token_claims:\n", set: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ds := DecodeRealm("main.yaml", []byte(tc.yaml))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			got := r.UserData.AccessTokenClaims
			if (got != nil) != tc.set {
				t.Fatalf("set = %v, want %v", got != nil, tc.set)
			}
			if tc.set && !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("claims %v, want %v", *got, tc.want)
			}
		})
	}
}

// Covers: FR-41 (part)
// Acceptance: Access token claims (part)
func TestAccessClaimsIsTheOptionOrTheClaims(t *testing.T) {
	claims := []string{"name", "email"}
	cases := []struct {
		name string
		u    UserData
		want []string
	}{
		{name: "not set: the claims", u: UserData{Claims: claims}, want: []string{"name", "email"}},
		{name: "set", u: UserData{Claims: claims, AccessTokenClaims: &[]string{"email"}}, want: []string{"email"}},
		{name: "set and empty", u: UserData{Claims: claims, AccessTokenClaims: &[]string{}}, want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.u.AccessClaims()
			if !slices.Equal(got, tc.want) {
				t.Fatalf("AccessClaims() = %v, want %v", got, tc.want)
			}
			if len(got) > 0 {
				got[0] = "changed"
				if tc.u.Claims[0] != "name" || (tc.u.AccessTokenClaims != nil && (*tc.u.AccessTokenClaims)[0] != "email") {
					t.Fatal("AccessClaims returned a slice that shares the realm's lists")
				}
			}
		})
	}
}

// Covers: FR-41
// Acceptance: Access token claims
func TestAccessTokenClaimsOutsideUserDataClaimsIsAConfigError(t *testing.T) {
	dir := keyDir(t)
	cases := []struct {
		name  string
		extra string
		line  int
		field string
	}{
		{name: "name not in the default claims", extra: "user_data:\n  access_token_claims: [nickname]\n", line: 3, field: "user_data.access_token_claims[0]"},
		{name: "name outside a narrowed claims list", extra: "user_data:\n  claims: [name]\n  access_token_claims: [name, email]\n", line: 4, field: "user_data.access_token_claims[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := validateText(t, dir, "realm", "realms/main.yaml", realmHead+tc.extra+realmKeys, false)
			if len(ds) != 1 {
				t.Fatalf("want exactly one diagnostic, got %v", ds)
			}
			d := ds[0]
			if d.Field != tc.field || d.Line != tc.line || d.Severity != Error || !strings.Contains(d.Message, "not in user_data.claims") {
				t.Fatalf("diagnostic %+v, want field %s at line %d with the reason \"not in user_data.claims\"", d, tc.field, tc.line)
			}
		})
	}
}

// Covers: FR-41
// Acceptance: Access token claims
func TestAccessTokenClaimsWithinUserDataClaimsAreValid(t *testing.T) {
	dir := keyDir(t)
	cases := []struct {
		name  string
		extra string
	}{
		{name: "a subset", extra: "user_data:\n  claims: [name, email]\n  access_token_claims: [email]\n"},
		{name: "the same list", extra: "user_data:\n  claims: [name]\n  access_token_claims: [name]\n"},
		{name: "empty list", extra: "user_data:\n  claims: [name]\n  access_token_claims: []\n"},
		{name: "not set", extra: "user_data:\n  claims: [name]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, d := range validateText(t, dir, "realm", "realms/main.yaml", realmHead+tc.extra+realmKeys, false) {
				if strings.HasPrefix(d.Field, "user_data.access_token_claims") {
					t.Fatalf("unexpected diagnostic %+v", d)
				}
			}
		})
	}
}
