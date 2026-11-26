package config

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// designRow is one row of an option table in docs/DESIGN.md.
type designRow struct {
	provider string // per-provider table only: the type the row belongs to
	options  []string
	def      string // default cell without backticks; empty when the table has none
	hasDef   bool
	possible string // "Possible values" cell as written
}

// designTables returns the option tables of the Configuration reference by
// section heading.
func designTables(t *testing.T) map[string][]designRow {
	t.Helper()
	raw, err := os.ReadFile("../../docs/DESIGN.md")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	out := map[string][]designRow{}
	section := ""
	inRef := false
	var header []string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "### Configuration reference"):
			inRef = true
			continue
		case strings.HasPrefix(l, "## ") && inRef:
			inRef = false
		}
		if !inRef {
			continue
		}
		if strings.HasPrefix(l, "#### ") {
			section = strings.TrimPrefix(l, "#### ")
			header = nil
			continue
		}
		if strings.HasPrefix(l, "Per-provider options and defaults") {
			section = "per-provider"
			continue
		}
		if strings.HasPrefix(l, "Common options for every provider") {
			section = "common"
			continue
		}
		if !strings.HasPrefix(l, "|") {
			if l == "" {
				continue
			}
			continue
		}
		cells := strings.Split(strings.Trim(l, "|"), " | ")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if cells[0] == "Option" || cells[0] == "Provider" {
			header = cells
			continue
		}
		if strings.HasPrefix(cells[0], "---") || header == nil {
			continue
		}
		row := designRow{}
		optCell := cells[0]
		if header[0] == "Provider" {
			row.provider = strings.ToLower(strings.Trim(cells[0], "`"))
			optCell = cells[1]
			row.def, row.hasDef = cells[2], true
			row.possible = cells[4]
		} else {
			row.def, row.hasDef = cells[1], true
			row.possible = cells[3]
		}
		row.options = expandOptions(optCell)
		key := section
		switch {
		case strings.HasPrefix(section, "`server.yaml`"):
			key = "server"
		case strings.HasPrefix(section, "`database.yaml`"):
			key = "database"
		case strings.HasPrefix(section, "Realm file"):
			key = "realm"
		case strings.HasPrefix(section, "Providers"):
			key = "common"
			if header[0] == "Provider" {
				key = "per-provider"
			}
		case strings.HasPrefix(section, "Clients"):
			key = "client"
		case section == "common" || section == "per-provider":
		default:
			continue
		}
		out[key] = append(out[key], row)
	}
	return out
}

// expandOptions turns "`endpoints.authorize`, `.token`" into full paths.
func expandOptions(cell string) []string {
	var out []string
	prefix := ""
	for _, part := range strings.Split(cell, ",") {
		p := strings.Trim(strings.TrimSpace(part), "`")
		if strings.HasPrefix(p, ".") {
			p = prefix + p
		} else if i := strings.LastIndex(p, "."); i >= 0 {
			prefix = p[:i]
		}
		out = append(out, p)
	}
	return out
}

func yamlName(f reflect.StructField) (string, bool) {
	tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
	if tag == "-" || tag == "" {
		return "", false
	}
	return tag, true
}

// field resolves a dotted option path in a struct type; "[]" steps into list items.
func field(t reflect.Type, path string) (reflect.StructField, []int, bool) {
	var index []int
	var sf reflect.StructField
	for _, step := range strings.Split(path, ".") {
		t = deref(t)
		step = strings.TrimSuffix(step, "[]")
		if t.Kind() == reflect.Slice {
			t = deref(t.Elem())
		}
		if t.Kind() != reflect.Struct {
			return sf, nil, false
		}
		found := false
		for i := 0; i < t.NumField(); i++ {
			if n, ok := yamlName(t.Field(i)); ok && n == step {
				sf, found = t.Field(i), true
				index = append(index, i)
				t = sf.Type
				break
			}
		}
		if !found {
			return sf, nil, false
		}
	}
	return sf, index, true
}

// leaves lists the option paths of every field that is not a struct holding other options.
func leaves(t reflect.Type, prefix string) []string {
	var out []string
	t = deref(t)
	for i := 0; i < t.NumField(); i++ {
		n, ok := yamlName(t.Field(i))
		if !ok {
			continue
		}
		ft := deref(t.Field(i).Type)
		path := prefix + n
		switch {
		case ft.Kind() == reflect.Struct && ft != reflect.TypeOf(Duration(0)):
			out = append(out, leaves(ft, path+".")...)
		case ft.Kind() == reflect.Slice && deref(ft.Elem()).Kind() == reflect.Struct:
			out = append(out, path)
			out = append(out, leaves(ft.Elem(), path+"[].")...)
		case ft.Kind() == reflect.Map:
			out = append(out, path)
			out = append(out, leaves(ft.Elem(), path+".")...)
		default:
			out = append(out, path)
		}
	}
	return out
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	}
	return v.IsZero()
}

func sameValue(got, want reflect.Value) bool {
	if got.Kind() == reflect.Slice && want.Kind() == reflect.Slice && got.Len() == 0 && want.Len() == 0 {
		return true
	}
	return reflect.DeepEqual(got.Interface(), want.Interface())
}

// parseDefault reads a documented default as a value of the field's type.
func parseDefault(t *testing.T, typ reflect.Type, cell string) reflect.Value {
	t.Helper()
	text := strings.ReplaceAll(cell, "`", "")
	v := reflect.New(typ)
	if typ.Kind() == reflect.String {
		if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
			text = text[1 : len(text)-1]
		}
		v.Elem().SetString(text)
		return v.Elem()
	}
	if err := yaml.Unmarshal([]byte(text), v.Interface()); err != nil {
		t.Fatalf("default %q does not parse as %s: %v", cell, typ, err)
	}
	return v.Elem()
}

// descriptiveDefault says how a prose default of the design is checked: the
// expected value of the option after decoding a probe, or skip.
type probe struct {
	skip  bool
	zero  bool   // expect the zero value (required options, "the realm value", "the provider's own URLs")
	want  string // expected string value for names derived from the key
	brand bool   // the vendor's name for a built-in adapter, else the key
}

func classify(def string) probe {
	d := strings.ReplaceAll(def, "`", "")
	switch {
	case strings.HasPrefix(d, "required"), d == "the realm value", d == "the provider's own URLs", d == "not set",
		d == "Google's RISC configuration URL": // empty: the adapter's own default
		return probe{zero: true}
	case d == "the name", d == "the client id", d == "the key name":
		return probe{want: "key"}
	case d == "Google, Apple, GitHub or Facebook for the built-in adapters (by type); the key for type: oidc":
		return probe{brand: true}
	case d == "per provider (below)":
		return probe{skip: true}
	}
	return probe{}
}

const probeRealm = "name: probe\nproviders:\n  google: {}\n  google-work: {type: google}\n  apple: {}\n  github: {}\n  facebook: {}\n  oidc: {}\nclients:\n  probe: {}\n"

func decodeProbe(t *testing.T) *RealmFile {
	t.Helper()
	r, ds := DecodeRealm("realms/probe.yaml", []byte(probeRealm))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	return r
}

// checkRow asserts that every option of the row exists on the struct reachable
// from root and has the documented default.
func checkRow(t *testing.T, root reflect.Value, row designRow, keyName string) {
	t.Helper()
	for _, opt := range row.options {
		sf, idx, ok := field(root.Type(), opt)
		if !ok {
			t.Errorf("option %q is documented but missing in %s", opt, root.Type())
			continue
		}
		if strings.Contains(opt, "[]") {
			continue // list items: existence only
		}
		got := root.FieldByIndex(idx)
		if len(idx) > 1 {
			// walk through pointers on the way
			got = root
			for _, i := range idx {
				got = reflect.Indirect(got).Field(i)
			}
		}
		p := classify(row.def)
		switch {
		case p.skip:
		case p.zero:
			if !isZero(got) {
				t.Errorf("%s: documented %q, got non-zero %v", opt, row.def, got.Interface())
			}
		case p.brand:
			// The expected name follows the provider's type, not its key.
			want, typ := keyName, keyName
			if root.Type() == reflect.TypeOf(Provider{}) {
				typ = root.FieldByName("Type").String()
			}
			if n, ok := brandNames[typ]; ok {
				want = n
			}
			if got.String() != want {
				t.Errorf("%s: documented %q, got %q want %q", opt, row.def, got.String(), want)
			}
		case p.want != "":
			if opt == "type" && keyName == "google-work" {
				break // the probe sets this type explicitly, so the key is not the default
			}
			if got.String() != keyName {
				t.Errorf("%s: documented %q, got %q want %q", opt, row.def, got.String(), keyName)
			}
		default:
			if strings.HasSuffix(opt, "display_name") {
				t.Fatalf("%s: the documented default %q is not a form the test knows; update classify", opt, row.def)
			}
			want := parseDefault(t, sf.Type, row.def)
			if !sameValue(got, want) {
				t.Errorf("%s: documented default %q, got %v want %v", opt, row.def, got.Interface(), want.Interface())
			}
		}
	}
}

func onlyTypes(sf reflect.StructField) []string {
	if tag := sf.Tag.Get("only"); tag != "" {
		return strings.Split(tag, ",")
	}
	return nil
}

// Covers: FR-19 (part)
func TestConfigReferenceMatchesDesign(t *testing.T) {
	tables := designTables(t)
	for _, k := range []string{"server", "database", "realm", "common", "per-provider", "client"} {
		if len(tables[k]) == 0 {
			t.Fatalf("no rows parsed for %s", k)
		}
	}
	documented := map[string]map[string]bool{}
	note := func(section string, opts []string) {
		if documented[section] == nil {
			documented[section] = map[string]bool{}
		}
		for _, o := range opts {
			documented[section][o] = true
		}
	}

	s, _ := DecodeServer("server.yaml", nil)
	for _, row := range tables["server"] {
		note("server", row.options)
		checkRow(t, reflect.ValueOf(s).Elem(), row, "")
	}
	d, _ := DecodeDatabase("database.yaml", nil)
	for _, row := range tables["database"] {
		note("database", row.options)
		checkRow(t, reflect.ValueOf(d).Elem(), row, "")
	}
	r := decodeProbe(t)
	for _, row := range tables["realm"] {
		note("realm", row.options)
		root := r
		if classify(row.def).zero {
			root, _ = DecodeRealm("realms/empty.yaml", nil) // the probe sets a name
		}
		checkRow(t, reflect.ValueOf(root).Elem(), row, "probe")
	}
	for _, row := range tables["client"] {
		note("client", row.options)
		checkRow(t, reflect.ValueOf(r.Clients["probe"]).Elem(), row, "probe")
	}
	// Common provider options hold for every adapter type.
	for key, p := range r.Providers {
		for _, row := range tables["common"] {
			if key == "google" {
				note("provider", row.options)
			}
			checkRow(t, reflect.ValueOf(p).Elem(), row, key)
		}
	}
	// Per-provider options exist for the type that documents them, with its default.
	for _, row := range tables["per-provider"] {
		p, ok := r.Providers[row.provider]
		if !ok {
			t.Errorf("unknown provider %q in the design", row.provider)
			continue
		}
		note("provider", row.options)
		checkRow(t, reflect.ValueOf(p).Elem(), row, row.provider)
		for _, opt := range row.options {
			sf, _, ok := field(reflect.TypeOf(*p), opt)
			if !ok {
				continue
			}
			if only := onlyTypes(sf); len(only) > 0 {
				found := false
				for _, o := range only {
					found = found || o == row.provider
				}
				if !found {
					t.Errorf("%s is documented for %s but restricted to %v", opt, row.provider, only)
				}
			}
		}
	}
	// Every option in the types is documented.
	for section, typ := range map[string]reflect.Type{
		"server": reflect.TypeOf(ServerFile{}), "database": reflect.TypeOf(DatabaseFile{}),
		"realm": reflect.TypeOf(RealmFile{}), "client": reflect.TypeOf(Client{}), "provider": reflect.TypeOf(Provider{}),
	} {
		for _, path := range leaves(typ, "") {
			if section == "realm" && (strings.HasPrefix(path, "providers") || strings.HasPrefix(path, "clients")) {
				continue
			}
			if !documented[section][path] && !documented[section][strings.TrimSuffix(path, "[]")] {
				t.Errorf("%s option %q exists in the types but not in the design", section, path)
			}
		}
	}
}
