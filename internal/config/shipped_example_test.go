package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
)

const shippedDir = "../../deploy/config.example"

func shippedFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(shippedDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shippedDirWithSecrets copies the shipped examples into a temporary config
// directory with the key and secret files they name.
func shippedDirWithSecrets(t *testing.T) *configdir.Dir {
	t.Helper()
	d := configdir.New(t)
	d.Write(t, "server.yaml", string(shippedFile(t, "server.yaml")))
	d.Write(t, "database.yaml", string(shippedFile(t, "database.yaml")))
	d.Realm(t, "example", string(shippedFile(t, "realms/example.yaml")))
	d.EncryptionKey(t, "secrets/encryption_key")
	d.RSAKey(t, "secrets/example/signing-2026-10.pem")
	d.Secret(t, "secrets/example/client_secret")
	d.Secret(t, "secrets/postgres_password")
	d.AppleKey(t, "secrets/example/apple_key.p8")
	return d
}

// Covers: FR-19 (part)
// Acceptance: Config remarks (part)
func TestShippedExamplesLoadClean(t *testing.T) {
	_, ds := loadDir(t, shippedDirWithSecrets(t))
	if len(ds) != 0 {
		t.Fatalf("diagnostics: %v", ds)
	}
}

// occurrence is one key of an example file.
type occurrence struct {
	path      string
	line      int
	commented bool
}

// occurrences returns every key of a YAML document with its option path and
// whether it has a comment on the lines above it. A path names a list item as
// "[]" and a provider or client by "*", so it compares with the paths of the
// types; the line tells the occurrences of one path apart.
func occurrences(t *testing.T, file string, raw []byte) []occurrence {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	var out []occurrence
	var walk func(n *yaml.Node, prefix, lead string)
	walk = func(n *yaml.Node, prefix, lead string) {
		switch n.Kind {
		case yaml.DocumentNode:
			walk(n.Content[0], prefix, "")
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				c := k.HeadComment
				if i == 0 && c == "" {
					c = lead // a comment above "- key:" belongs to the first key
				}
				path := prefix + k.Value
				if prefix == "providers." || prefix == "clients." {
					path = prefix + "*"
				}
				out = append(out, occurrence{path, k.Line, strings.TrimSpace(c) != ""})
				switch v.Kind {
				case yaml.MappingNode:
					walk(v, path+".", "")
				case yaml.SequenceNode:
					for _, item := range v.Content {
						if item.Kind == yaml.MappingNode {
							walk(item, path+"[].", item.HeadComment)
						}
					}
				}
			}
		}
	}
	walk(&doc, "", "")
	return out
}

// uncommented lists the keys that have no comment above them, one entry for
// each occurrence.
func uncommented(occ []occurrence) []string {
	var out []string
	for _, o := range occ {
		if !o.commented {
			out = append(out, fmt.Sprintf("%s (line %d)", o.path, o.line))
		}
	}
	return out
}

// optionPaths lists the option paths of a type, with "*" for the key of a map.
func optionPaths(typ reflect.Type) []string {
	var out []string
	for _, p := range leaves(typ, "") {
		p = normalizeMapKey(p)
		out = append(out, p)
		// The sections that hold options need a comment too.
		for i, c := range p {
			if c == '.' {
				if sec := p[:i]; sec != "providers" && sec != "clients" && !strings.HasSuffix(sec, "[]") && !slices.Contains(out, sec) {
					out = append(out, sec)
				}
			}
		}
	}
	return out
}

func normalizeMapKey(p string) string {
	for _, m := range []string{"providers.", "clients."} {
		if strings.HasPrefix(p, m) {
			return m + "*." + strings.TrimPrefix(p, m)
		}
	}
	return p
}

// Covers: FR-19
// Acceptance: Config remarks
func TestEveryOptionIsInTheShippedExamplesWithAComment(t *testing.T) {
	files := []struct {
		file string
		typ  reflect.Type
	}{
		{"server.yaml", reflect.TypeOf(ServerFile{})},
		{"server.tls.yaml.example", reflect.TypeOf(ServerFile{})},
		{"database.yaml", reflect.TypeOf(DatabaseFile{})},
		{"realms/example.yaml", reflect.TypeOf(RealmFile{})},
	}
	n := 0
	for _, f := range files {
		occ := occurrences(t, f.file, shippedFile(t, f.file))
		var all []string
		for _, o := range occ {
			all = append(all, o.path)
		}
		for _, p := range optionPaths(f.typ) {
			if p == "providers.*" || p == "clients.*" {
				p = strings.TrimSuffix(p, ".*")
			}
			n++
			if !slices.Contains(all, p) {
				t.Errorf("%s: option %q is not in the example", f.file, p)
			}
		}
		for _, u := range uncommented(occ) {
			t.Errorf("%s: %s has no comment above it", f.file, u)
		}
		// Every key in the example is an option of the types (the loader
		// rejects unknown fields; this also catches a bad "*" path).
		known := optionPaths(f.typ)
		for _, p := range all {
			if !slices.Contains(known, p) && !slices.Contains(known, strings.TrimSuffix(p, ".*")) &&
				p != "providers.*" && p != "clients.*" {
				t.Errorf("%s: %q is not an option", f.file, p)
			}
		}
	}
	if n < 100 {
		t.Errorf("only %d options checked", n)
	}
}

// Covers: FR-19 (part)
// Acceptance: Config remarks (part)
func TestCommentCheckCountsEveryOccurrence(t *testing.T) {
	occ := occurrences(t, "x.yaml", []byte("# a\nlisten: x\nlog_level: info\n"))
	if got := uncommented(occ); !slices.Equal(got, []string{"log_level (line 3)"}) {
		t.Fatalf("uncommented %v", got)
	}
	// Two provider blocks share the path providers.*.enabled: the one
	// without a comment must be reported although the other has one.
	occ = occurrences(t, "r.yaml", []byte(`# all
providers:
  # first
  google:
    # on
    enabled: true
  # second
  github:
    enabled: true
`))
	if got := uncommented(occ); !slices.Equal(got, []string{"providers.*.enabled (line 9)"}) {
		t.Fatalf("uncommented %v", got)
	}
}

// Covers: FR-19 (part)
// Acceptance: Config remarks (part)
func TestOnlyOptionsAppearOnlyUnderTheirOwnProvider(t *testing.T) {
	common := map[string]bool{}
	own := map[string][]string{}
	pt := reflect.TypeOf(Provider{})
	for i := 0; i < pt.NumField(); i++ {
		name, ok := yamlName(pt.Field(i))
		if !ok {
			continue
		}
		if only := pt.Field(i).Tag.Get("only"); only != "" {
			own[only] = append(own[only], name)
		} else {
			common[name] = true
		}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(shippedFile(t, "realms/example.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	var providers *yaml.Node
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "providers" {
			providers = top.Content[i+1]
		}
	}
	if providers == nil || len(providers.Content) < 10 {
		t.Fatal("no providers in the example")
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(providers.Content); i += 2 {
		key, block := providers.Content[i].Value, providers.Content[i+1]
		keys := map[string]bool{}
		typ := key
		for j := 0; j+1 < len(block.Content); j += 2 {
			keys[block.Content[j].Value] = true
			if block.Content[j].Value == "type" {
				typ = block.Content[j+1].Value
			}
		}
		seen[typ] = true
		for k := range keys {
			if !common[k] && !slices.Contains(own[typ], k) {
				t.Errorf("provider %s (type %s) sets %q, which belongs to another type", key, typ, k)
			}
		}
		for _, k := range own[typ] {
			if !keys[k] {
				t.Errorf("provider %s (type %s) lacks its own option %q", key, typ, k)
			}
		}
	}
	for typ := range providerTypes {
		if !seen[typ] {
			t.Errorf("the example has no %s provider", typ)
		}
	}
}

const exampleWebClientFile = "../../examples/web-app/example-web-client.yaml"

// Covers: FR-61 (part)
// Acceptance: Example web app client entry
// The entry of the example web app is a copyable file: added under `clients:` of
// the shipped realm example it passes validation without a diagnostic, and the
// shipped realm example holds no such client itself.
func TestExampleWebClientEntryLoadsInTheShippedRealm(t *testing.T) {
	raw, err := os.ReadFile(exampleWebClientFile)
	if err != nil {
		t.Fatal(err)
	}
	_, entry, ok := strings.Cut(string(raw), "\nclients:\n")
	if !ok || !strings.HasPrefix(entry, "  example-web:") {
		t.Fatalf("%s: the entry does not follow a clients: line", exampleWebClientFile)
	}
	realm := string(shippedFile(t, "realms/example.yaml"))
	if strings.Contains(realm, "example-web") {
		t.Fatal("the shipped realm example holds an example-web client")
	}
	const marker = "\nclients:\n"
	if strings.Count(realm, marker) != 1 {
		t.Fatalf("the shipped realm example has %d clients: lines, want 1", strings.Count(realm, marker))
	}
	d := shippedDirWithSecrets(t)
	d.Realm(t, "example", strings.Replace(realm, marker, marker+entry+"\n", 1))
	l, ds := loadDir(t, d)
	if len(ds) != 0 {
		t.Fatalf("diagnostics: %v", ds)
	}
	snap := l.Current()
	r, ok := snap.Realm("example")
	if !ok {
		t.Fatal("no realm example")
	}
	c, ok := r.Clients["example-web"]
	if !ok {
		t.Fatal("the realm has no client example-web")
	}
	if c.Type != "public" || !slices.Equal(c.RedirectURIs, []string{"http://127.0.0.1:5173/callback"}) ||
		!slices.Equal(c.PostLogoutRedirectURIs, []string{"http://127.0.0.1:5173/"}) ||
		!slices.Equal(c.WebOrigins, []string{"http://127.0.0.1:5173"}) {
		t.Fatalf("client %+v", c)
	}
}
