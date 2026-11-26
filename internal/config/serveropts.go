package config

import (
	"reflect"
	"slices"
	"strings"
)

// serverOptionLive says, for every option of server.yaml, whether a change
// applies on reload (true) or needs a restart (false). It mirrors the "Takes
// effect" column of the Configuration reference; a test compares the two.
var serverOptionLive = map[string]bool{
	"public_url":                     false,
	"listen":                         false,
	"tls.mode":                       false,
	"tls.listen":                     false,
	"tls.http_listen":                false,
	"tls.cert_file":                  false,
	"tls.key_file":                   false,
	"secrets.encryption_key_files":   false,
	"require_https":                  false,
	"strict_permissions":             false,
	"log_level":                      true,
	"trusted_proxies":                true,
	"rate_limit.per_ip_per_minute":   true,
	"rate_limit.store":               false,
	"urls.path_prefix":               false,
	"urls.issuer":                    false,
	"urls.endpoints.authorize":       false,
	"urls.endpoints.token":           false,
	"urls.endpoints.userinfo":        false,
	"urls.endpoints.jwks":            false,
	"urls.endpoints.logout":          false,
	"urls.endpoints.revoke":          false,
	"urls.endpoints.sessions":        false,
	"urls.endpoints.callback":        false,
	"urls.endpoints.account_delete":  false,
	"urls.endpoints.assets":          false,
	"urls.endpoints.provider_events": false,
	"urls.endpoints.data_deletion":   false,
	"login.provider_hint_params":     true,
	"logout.redirect_params":         true,
}

// optionLeaves calls fn for every option of the struct v, with its yaml path. Lists
// and scalars are options; structs are walked. Unexported fields are not
// options.
func optionLeaves(v reflect.Value, prefix string, fn func(path string, f reflect.Value)) {
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		name := strings.Split(sf.Tag.Get("yaml"), ",")[0]
		if !sf.IsExported() || name == "" || name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if f := v.Field(i); f.Kind() == reflect.Struct {
			optionLeaves(f, path, fn)
		} else {
			fn(path, f)
		}
	}
}

func optionMap(v reflect.Value) map[string]reflect.Value {
	m := map[string]reflect.Value{}
	optionLeaves(v, "", func(p string, f reflect.Value) { m[p] = f })
	return m
}

// changedOptions returns the sorted paths of the options whose value differs
// between a and b, which are structs of the same type.
func changedOptions(a, b reflect.Value) []string {
	nb := optionMap(b)
	var out []string
	optionLeaves(a, "", func(p string, f reflect.Value) {
		if !reflect.DeepEqual(f.Interface(), nb[p].Interface()) {
			out = append(out, p)
		}
	})
	slices.Sort(out)
	return out
}

// withLiveOptions returns a copy of running in which every live option has
// the value it has in next; the restart options keep their running values.
func withLiveOptions(running, next *ServerFile) *ServerFile {
	eff := cloneServer(running)
	nl := optionMap(reflect.ValueOf(next).Elem())
	optionLeaves(reflect.ValueOf(&eff).Elem(), "", func(p string, f reflect.Value) {
		if !serverOptionLive[p] {
			return // restart, or an option the table does not know: keep
		}
		v := nl[p]
		if v.Kind() == reflect.Slice {
			v = reflect.ValueOf(slices.Clone(v.Interface().([]string)))
		}
		f.Set(v)
	})
	return &eff
}

// restartOptions lists the changed options that need a restart: those of
// server.yaml that are not live, and every changed option of database.yaml.
func restartOptions(runSrv, newSrv *ServerFile, runDB, newDB *DatabaseFile) []string {
	var out []string
	for _, p := range changedOptions(reflect.ValueOf(runSrv).Elem(), reflect.ValueOf(newSrv).Elem()) {
		if !serverOptionLive[p] {
			out = append(out, "server.yaml:"+p)
		}
	}
	for _, p := range changedOptions(reflect.ValueOf(runDB).Elem(), reflect.ValueOf(newDB).Elem()) {
		out = append(out, "database.yaml:"+p)
	}
	return out
}
