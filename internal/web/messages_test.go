package web_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/yyudhistira/featherauth/internal/web"
)

// exampleFile is the translation example the design says config init writes
// (config init copies it into the config directory).
var exampleFile = filepath.Join("..", "..", "deploy", "config.example", "locales", "en.yaml.example")

func TestExampleLocaleListsEveryID(t *testing.T) {
	if *update {
		if err := os.MkdirAll(filepath.Dir(exampleFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(exampleFile, web.ExampleLocale(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(web.ExampleLocale()) {
		t.Fatalf("%s is out of date; write web.ExampleLocale() to it", exampleFile)
	}
	var got map[string]string
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(web.English) {
		t.Errorf("the example has %d ids, the built-in English %d", len(got), len(web.English))
	}
	for id, text := range web.English {
		if got[id] != text {
			t.Errorf("%s: example %q, built-in %q", id, got[id], text)
		}
	}
}

func TestEveryIDTheTemplatesUseIsInEnglish(t *testing.T) {
	ids, err := web.TemplateIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("no message ids found in the templates")
	}
	for _, id := range ids {
		if _, ok := web.English[id]; !ok {
			t.Errorf("the templates use %q, which has no English text", id)
		}
	}
	// And the other way: an id nothing uses is dead text, except the
	// explanations an error page picks by id.
	used := map[string]bool{}
	for _, id := range ids {
		used[id] = true
	}
	for id := range web.English {
		if !used[id] && !hasPrefix(id, "error.") {
			t.Errorf("%q is in the English messages but no template uses it", id)
		}
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
