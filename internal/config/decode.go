package config

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DecodeServer decodes server.yaml. Unknown options are errors. The result is
// nil only when the file is not valid YAML.
func DecodeServer(file string, b []byte) (*ServerFile, []Diagnostic) {
	v := defaultServer()
	ds, lines, ok := decode(file, b, &v)
	if !ok {
		return nil, ds
	}
	v.lines = lines
	return &v, ds
}

// DecodeDatabase decodes database.yaml. Database settings are read only from
// this file (FR-25).
func DecodeDatabase(file string, b []byte) (*DatabaseFile, []Diagnostic) {
	v := defaultDatabase()
	ds, lines, ok := decode(file, b, &v)
	if !ok {
		return nil, ds
	}
	v.lines = lines
	return &v, ds
}

// DecodeRealm decodes a realm file. Unknown options are errors. The result is
// nil only when the file is not valid YAML.
func DecodeRealm(file string, b []byte) (*RealmFile, []Diagnostic) {
	v := defaultRealm()
	ds, lines, ok := decode(file, b, &v)
	if !ok {
		return nil, ds
	}
	if v.DisplayName == "" {
		v.DisplayName = v.Name
	}
	for k, p := range v.Providers {
		if p == nil {
			d := defaultProvider(providerTypeOf(k, nil), k)
			v.Providers[k] = &d
		}
	}
	for k, c := range v.Clients {
		if c == nil {
			d := defaultClient(k)
			c = &d
			v.Clients[k] = c
		}
		if c.Name == "" {
			c.Name = k
		}
		if c.Audience == "" {
			c.Audience = k
		}
	}
	v.lines = lines
	return &v, ds
}

var (
	lineRe     = regexp.MustCompile(`^line (\d+): (.*)$`)
	anyLineRe  = regexp.MustCompile(`line (\d+)`)
	maxWalkLvl = 64
)

// decode parses b into out. It reports unknown options with their path, then
// the type errors of the decoding. ok is false when b is not valid YAML.
func decode(file string, b []byte, out any) (ds []Diagnostic, lines map[string]int, ok bool) {
	var doc yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	err := dec.Decode(&doc)
	if errors.Is(err, io.EOF) {
		return nil, map[string]int{}, true
	}
	if err != nil {
		return []Diagnostic{diagFromYAMLError(file, err)}, nil, false
	}
	w := &walker{file: file, lines: map[string]int{}, at: map[int][]scalarAt{}}
	if len(doc.Content) == 1 {
		w.walk(doc.Content[0], reflect.TypeOf(out).Elem(), "", "", 0)
	}
	ds = w.diags
	var second yaml.Node
	if err := dec.Decode(&second); err == nil {
		line := second.Line
		if len(second.Content) == 1 {
			line = second.Content[0].Line
		}
		ds = append(ds, Diagnostic{File: file, Line: line, Severity: Error, Message: "more than one YAML document in the file"})
	} else if !errors.Is(err, io.EOF) {
		ds = append(ds, diagFromYAMLError(file, err))
	}

	if err := doc.Decode(out); err != nil {
		var te *yaml.TypeError
		if !errors.As(err, &te) {
			return append(ds, Diagnostic{File: file, Severity: Error, Message: err.Error()}), w.lines, true
		}
		for _, e := range te.Errors {
			ds = append(ds, w.typeError(e))
		}
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].Line < ds[j].Line })
	return ds, w.lines, true
}

func diagFromYAMLError(file string, err error) Diagnostic {
	line := 0
	if m := anyLineRe.FindStringSubmatch(err.Error()); m != nil {
		line, _ = strconv.Atoi(m[1])
	}
	return Diagnostic{File: file, Line: line, Severity: Error, Message: strings.TrimPrefix(err.Error(), "yaml: ")}
}

type scalarAt struct{ path, value string }

type walker struct {
	file  string
	diags []Diagnostic
	lines map[string]int
	at    map[int][]scalarAt // line -> scalars starting there, for type errors
}

func (w *walker) typeError(e string) Diagnostic {
	d := Diagnostic{File: w.file, Severity: Error, Message: e}
	m := lineRe.FindStringSubmatch(e)
	if m == nil {
		return d
	}
	d.Line, _ = strconv.Atoi(m[1])
	d.Message = m[2]
	cands := w.at[d.Line]
	for _, c := range cands {
		if strings.Contains(e, "`"+c.value+"`") || strings.Contains(e, strconv.Quote(c.value)) {
			d.Field = c.path
			return d
		}
	}
	if len(cands) > 0 {
		d.Field = cands[len(cands)-1].path // the deepest node starting on that line
	}
	return d
}

func resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < maxWalkLvl; i++ {
		n = n.Alias
	}
	return n
}

// pairs returns the key/value nodes of a mapping, expanding merge keys.
func pairs(n *yaml.Node, depth int) [][2]*yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > maxWalkLvl {
		return nil
	}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			v = resolve(v)
			switch {
			case v == nil:
			case v.Kind == yaml.MappingNode:
				out = append(out, pairs(v, depth+1)...)
			case v.Kind == yaml.SequenceNode:
				for _, item := range v.Content {
					out = append(out, pairs(item, depth+1)...)
				}
			}
			continue
		}
		out = append(out, [2]*yaml.Node{k, v})
	}
	return out
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// providerTypeOf is the adapter type of a provider: its `type`, else its key.
func providerTypeOf(key string, n *yaml.Node) string {
	for _, p := range pairs(n, 0) {
		if p[0].Value == "type" {
			if v := resolve(p[1]); v != nil && v.Kind == yaml.ScalarNode && v.Value != "" {
				return v.Value
			}
		}
	}
	return key
}

var providerStruct = reflect.TypeOf(Provider{})

// walk checks the option names under n against type t and records lines.
// ptype is the adapter type while walking a provider, else "".
func (w *walker) walk(n *yaml.Node, t reflect.Type, path, ptype string, depth int) {
	n = resolve(n)
	if n == nil || depth > maxWalkLvl {
		return
	}
	w.at[n.Line] = append(w.at[n.Line], scalarAt{path, n.Value})
	if n.Kind == yaml.ScalarNode {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			if name := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]; name != "" && name != "-" {
				fields[name] = t.Field(i)
			}
		}
		for _, p := range pairs(n, 0) {
			k, v := p[0], p[1]
			child := join(path, k.Value)
			f, known := fields[k.Value]
			if known && !allowedFor(f, ptype) {
				known = false
			}
			if !known {
				w.diags = append(w.diags, Diagnostic{File: w.file, Line: k.Line, Field: child, Severity: Error, Message: "unknown field"})
				continue
			}
			if _, seen := w.lines[child]; !seen {
				w.lines[child] = k.Line
			}
			w.walk(v, f.Type, child, ptype, depth+1)
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return
		}
		for _, p := range pairs(n, 0) {
			k, v := p[0], p[1]
			child := join(path, k.Value)
			if _, seen := w.lines[child]; !seen {
				w.lines[child] = k.Line
			}
			pt := ""
			if deref(t.Elem()) == providerStruct {
				pt = providerTypeOf(k.Value, v)
			}
			w.walk(v, t.Elem(), child, pt, depth+1)
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range n.Content {
			child := path + "[" + strconv.Itoa(i) + "]"
			if _, seen := w.lines[child]; !seen {
				w.lines[child] = item.Line
			}
			w.walk(item, t.Elem(), child, ptype, depth+1)
		}
	}
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// allowedFor reports whether field f may appear in a provider of type ptype.
// Outside providers (ptype empty) and for types the design does not know,
// every field is allowed.
func allowedFor(f reflect.StructField, ptype string) bool {
	only := f.Tag.Get("only")
	if only == "" || ptype == "" || !providerTypes[ptype] {
		return true
	}
	for _, o := range strings.Split(only, ",") {
		if o == ptype {
			return true
		}
	}
	return false
}

// UnmarshalYAML applies the defaults of each provider's type.
func (m *Providers) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: cannot unmarshal %s into providers", n.Line, n.ShortTag())}}
	}
	out := Providers{}
	var errs []string
	for _, p := range pairs(n, 0) {
		var key string
		if err := p[0].Decode(&key); err != nil {
			return err
		}
		if _, dup := out[key]; dup {
			errs = append(errs, fmt.Sprintf("line %d: mapping key %q already defined", p[0].Line, key))
			continue
		}
		prov := defaultProvider(providerTypeOf(key, p[1]), key)
		if err := p[1].Decode(&prov); err != nil {
			var te *yaml.TypeError
			if !errors.As(err, &te) {
				return err
			}
			errs = append(errs, te.Errors...)
		}
		out[key] = &prov
	}
	*m = out
	if len(errs) > 0 {
		return &yaml.TypeError{Errors: errs}
	}
	return nil
}

// UnmarshalYAML applies the client defaults, which do not depend on the id
// except for name and audience; DecodeRealm fills those from the map key.
func (c *Client) UnmarshalYAML(n *yaml.Node) error {
	*c = defaultClient("")
	type plain Client
	return n.Decode((*plain)(c))
}
