package config

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// File names inside the configuration directory, as used in diagnostics.
const (
	serverFileName   = "server.yaml"
	databaseFileName = "database.yaml"
	realmsDirName    = "realms"
	localesDirName   = "locales"
)

// LoadError is returned by NewLoader when the configuration cannot start:
// server.yaml or database.yaml is invalid, or no realm file is valid.
type LoadError struct{ Diagnostics []Diagnostic }

func (e *LoadError) Error() string {
	var b strings.Builder
	b.WriteString("configuration is not valid")
	for _, d := range e.Diagnostics {
		if d.Severity == Error {
			b.WriteString("\n  " + d.String())
		}
	}
	return b.String()
}

// ReloadResult is the outcome of one reload.
type ReloadResult struct {
	// Applied is true when a new configuration replaced the running one. It
	// can be true while Diagnostics hold errors: a broken realm keeps its last
	// good version and an invalid server.yaml is ignored while the other
	// realms still reload. Callers decide success, such as an exit code, from
	// Diagnostics, not from Applied.
	Applied bool
	// RestartRequired lists, sorted, the options whose new value needs a
	// restart, such as "server.yaml:public_url". The running values stay.
	RestartRequired []string
	// Diagnostics holds every error and warning, ordered by file: server.yaml,
	// database.yaml, the realm files by name, then the checks across realms.
	Diagnostics []Diagnostic
}

func (r ReloadResult) clone() ReloadResult {
	r.RestartRequired = slices.Clone(r.RestartRequired)
	r.Diagnostics = slices.Clone(r.Diagnostics)
	return r
}

// Status describes the running configuration. It holds no secret.
type Status struct {
	// LoadedAt is when the running snapshot was built.
	LoadedAt time.Time
	// LastReload is when the last reload ran, applied or not.
	LastReload time.Time
	// Last is the result of the last reload.
	Last ReloadResult
	// Stale lists the realms that serve their last good version because
	// their file is invalid, sorted.
	Stale []RealmName
}

// goodRealm is a realm file that passed every check, with what it needs.
type goodRealm struct {
	file  string
	rf    *RealmFile
	sec   *FileSecrets
	fresh bool // read in the current reload, not kept from an earlier one
}

// Loader reads the configuration directory, validates it, and swaps the
// result in atomically. A broken realm file keeps the last good version of
// that realm and never affects another.
type Loader struct {
	dir   string
	clock clock.Clock
	log   *slog.Logger

	cur atomic.Pointer[Snapshot]

	// reloadMu serialises reloads and guards what the next reload starts from.
	reloadMu   sync.Mutex
	server     *ServerFile // running values: restart options from startup
	db         *DatabaseFile
	srvSecrets *FileSecrets
	good       map[string]*goodRealm // by file name

	statusMu sync.RWMutex
	status   Status

	hooks []func(context.Context, *Snapshot) // guarded by reloadMu

	newWatcher func() (watcher, error)
	trace      func(string) // tests only: called at "watching", "armed", "ignored", "error", "reloaded"
}

var _ Source = (*Loader)(nil)

// NewLoader loads the configuration in dir. It returns a *LoadError when
// server.yaml or database.yaml is invalid or no realm file is valid. l may be
// nil. The clock times the debounce of Watch.
func NewLoader(dir string, c clock.Clock, l *slog.Logger) (*Loader, error) {
	if l == nil {
		l = logx.New(io.Discard, slog.LevelError, c)
	}
	ld := &Loader{dir: dir, clock: c, log: l, newWatcher: newFSWatcher}
	res := ld.Reload(context.Background())
	if !res.Applied {
		return nil, &LoadError{Diagnostics: res.Diagnostics}
	}
	return ld, nil
}

// OnApply registers fn to run after every reload that is applied, with the
// new snapshot, before the reload is reported and before the next one can
// start. It does not run for the load of NewLoader.
func (l *Loader) OnApply(fn func(context.Context, *Snapshot)) {
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()
	l.hooks = append(l.hooks, fn)
}

// Current implements Source. It is never nil after NewLoader succeeded.
func (l *Loader) Current() *Snapshot { return l.cur.Load() }

// Status returns the state of the running configuration.
func (l *Loader) Status() Status {
	l.statusMu.RLock()
	defer l.statusMu.RUnlock()
	s := l.status
	s.Last = s.Last.clone()
	s.Stale = slices.Clone(s.Stale)
	return s
}

func (l *Loader) tr(stage string) {
	if l.trace != nil {
		l.trace(stage)
	}
}

// diagList collects diagnostics in order, without exact repeats.
type diagList struct {
	list []Diagnostic
	seen map[Diagnostic]bool
}

func (d *diagList) add(ds ...Diagnostic) {
	for _, x := range ds {
		if d.seen == nil {
			d.seen = map[Diagnostic]bool{}
		}
		if !d.seen[x] {
			d.seen[x] = true
			d.list = append(d.list, x)
		}
	}
}

func hasError(ds []Diagnostic) bool {
	return slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Severity == Error })
}

func (l *Loader) path(rel string) string { return filepath.Join(l.dir, filepath.FromSlash(rel)) }

// Reload reads the whole directory again and, when it holds a usable
// configuration, swaps it in. It is safe to call from several goroutines.
//
// An invalid server.yaml or database.yaml is reported and ignored. A realm
// file that is invalid keeps the realm's last good version, and a removed
// file removes its realm. Nothing is applied when no realm would be left.
// Server secrets are read at startup only.
func (l *Loader) Reload(ctx context.Context) ReloadResult {
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()

	now := l.clock.Now()
	res, snap, stale := l.build(ctx)
	if snap != nil {
		l.cur.Store(snap)
		res.Applied = true
	}
	l.statusMu.Lock()
	l.status.LastReload = now
	l.status.Last = res.clone()
	if snap != nil {
		l.status.LoadedAt = now
		l.status.Stale = stale
	}
	l.statusMu.Unlock()
	if snap != nil {
		for _, fn := range l.hooks {
			fn(ctx, snap)
		}
	}
	l.report(res, snap, stale)
	return res
}

func (l *Loader) report(res ReloadResult, snap *Snapshot, stale []RealmName) {
	for _, d := range res.Diagnostics {
		level := slog.LevelError
		msg := "configuration error"
		if d.Severity == Warning {
			level, msg = slog.LevelWarn, "configuration warning"
		}
		l.log.Log(context.Background(), level, msg, "file", d.File, "line", d.Line, "field", d.Field, "reason", d.Message)
	}
	if len(res.RestartRequired) > 0 {
		l.log.Warn("restart required", "options", res.RestartRequired)
	}
	for _, n := range stale {
		l.log.Warn("realm serves its last good configuration", "realm", string(n))
	}
	if snap != nil {
		l.log.Info("configuration loaded", "realm_count", len(snap.realms))
	} else {
		l.log.Error("configuration not applied; the last good configuration keeps serving")
	}
}

// build does the work of a reload without changing the loader. It returns a
// snapshot only when one is to be applied, and then updates the state the
// next reload starts from.
func (l *Loader) build(ctx context.Context) (res ReloadResult, snap *Snapshot, stale []RealmName) {
	var ds diagList
	defer func() { res.Diagnostics = ds.list }()
	if err := ctx.Err(); err != nil {
		ds.add(Diagnostic{Severity: Error, Message: "reload cancelled: " + err.Error()})
		return
	}
	startup := l.server == nil

	srvNew, srvOK := l.readServer(&ds)
	dbNew, dbOK := l.readDatabase(&ds)
	// The shared rate limit lives in the database, which only Postgres serves to
	// several instances (FR-53): a server.yaml that asks for it with SQLite is
	// invalid, as its own options are.
	if srvOK && dbOK && srvNew.RateLimit.Store == "database" && dbNew.Driver != "postgres" {
		ds.add(Diagnostic{File: serverFileName, Line: srvNew.Line("rate_limit.store"), Field: "rate_limit.store", Severity: Error,
			Message: `"database" needs driver: postgres in database.yaml`})
		srvOK = false
	}
	if startup && !(srvOK && dbOK) {
		return
	}

	eff, effDB := l.server, l.db
	if startup {
		eff, effDB = srvNew, dbNew
	} else {
		if srvOK {
			eff = withLiveOptions(l.server, srvNew)
		}
		cmpSrv, cmpDB := srvNew, dbNew
		if !srvOK {
			cmpSrv = l.server
		}
		if !dbOK {
			cmpDB = l.db
		}
		res.RestartRequired = restartOptions(l.server, cmpSrv, l.db, cmpDB)
	}

	// Server secrets (encryption keys, the database password file) are read at
	// startup only. A later reload checks the files and reports a failure like
	// an invalid server.yaml, but the secrets loaded at startup stay in use and
	// the realms still reload.
	srvSecrets, sd := LoadSecrets(l.dir, SecretSources{ServerFile: serverFileName, Server: eff, DatabaseFile: databaseFileName, Database: effDB, SkipTLSPair: !startup})
	ds.add(sd...)
	realmSrv, checkSrv := eff, eff
	if startup {
		if srvSecrets == nil {
			if !hasError(sd) {
				ds.add(Diagnostic{File: serverFileName, Severity: Error, Message: "secrets could not be loaded"})
			}
			return
		}
	} else {
		srvSecrets = l.srvSecrets
		// An encryption key file that fails now must not fail a realm that
		// stores refresh tokens; the startup keys are used, so the realms are
		// validated against the startup key list (a change to it needs a restart).
		// The realms' secret loading does not read those files again.
		c := cloneServer(eff)
		c.Secrets.EncryptionKeyFiles = nil
		realmSrv = &c
		v := cloneServer(eff)
		v.Secrets.EncryptionKeyFiles = slices.Clone(l.server.Secrets.EncryptionKeyFiles)
		checkSrv = &v
	}

	final, stale, ok := l.collectRealms(ctx, realmSrv, checkSrv, &ds)
	if !ok {
		return
	}
	if len(final) == 0 {
		ds.add(Diagnostic{File: realmsDirName, Severity: Error, Message: "no valid realm file in " + realmsDirName + "/"})
		return
	}

	files := slices.Sorted(maps.Keys(final))
	rfs := make([]*RealmFile, len(files))
	merged := &FileSecrets{signing: map[string]crypto.Signer{}, apple: map[string]*ecdsa.PrivateKey{}, secrets: map[string]string{}, enc: srvSecrets.enc}
	for i, f := range files {
		g := final[f]
		rfs[i] = g.rf
		maps.Copy(merged.signing, g.sec.signing)
		maps.Copy(merged.apple, g.sec.apple)
		maps.Copy(merged.secrets, g.sec.secrets)
	}
	snap = NewSnapshot(eff, effDB, rfs, merged)

	l.server, l.db, l.srvSecrets, l.good = eff, effDB, srvSecrets, final
	return res, snap, stale
}

// readServer reads and validates server.yaml. ok is false when the file is
// missing or invalid.
func (l *Loader) readServer(ds *diagList) (*ServerFile, bool) {
	b, err := os.ReadFile(l.path(serverFileName))
	if err != nil {
		ds.add(Diagnostic{File: serverFileName, Severity: Error, Message: "cannot read " + serverFileName})
		return nil, false
	}
	sf, d := DecodeServer(serverFileName, b)
	ds.add(d...)
	if sf == nil || hasError(d) {
		return nil, false
	}
	vd := ValidateServer(serverFileName, sf)
	ds.add(vd...)
	return sf, !hasError(vd)
}

// readDatabase reads and validates database.yaml. A missing file means the
// defaults, as in the compact example of the design.
func (l *Loader) readDatabase(ds *diagList) (*DatabaseFile, bool) {
	b, err := os.ReadFile(l.path(databaseFileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		ds.add(Diagnostic{File: databaseFileName, Severity: Error, Message: "cannot read " + databaseFileName})
		return nil, false
	}
	df, d := DecodeDatabase(databaseFileName, b)
	ds.add(d...)
	if df == nil || hasError(d) {
		return nil, false
	}
	vd := ValidateDatabase(databaseFileName, df)
	ds.add(vd...)
	return df, !hasError(vd)
}

// collectRealms reads every realm file and returns the realms to serve by
// file name: the new version of a valid file, else the last good version,
// and none for a file that never was valid. stale names the realms served
// from an older version. ok is false when the directory cannot be read.
func (l *Loader) collectRealms(ctx context.Context, eff, check *ServerFile, ds *diagList) (final map[string]*goodRealm, stale []RealmName, ok bool) {
	entries, err := os.ReadDir(l.path(realmsDirName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		ds.add(Diagnostic{File: realmsDirName, Severity: Error, Message: "cannot read directory " + realmsDirName})
		return nil, nil, false
	}
	final = map[string]*goodRealm{}
	staleFiles := map[string]bool{}
	fallback := func(f string) bool {
		prev := l.good[f]
		if prev == nil {
			return false
		}
		final[f] = &goodRealm{file: f, rf: prev.rf, sec: prev.sec}
		staleFiles[f] = true
		return true
	}
	for _, e := range entries {
		// A dot file is an editor's lock or temporary file, never a realm.
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		if ctx.Err() != nil {
			ds.add(Diagnostic{Severity: Error, Message: "reload cancelled: " + ctx.Err().Error()})
			return nil, nil, false
		}
		file := realmsDirName + "/" + e.Name()
		g, rd := l.loadRealm(file, eff, check)
		ds.add(rd...)
		if g != nil {
			final[file] = g
		} else {
			fallback(file)
		}
	}

	// Checks across realms. A realm that fails one goes back to its last good
	// version, or out; the loop ends because every round changes the set.
	for {
		files := slices.Sorted(maps.Keys(final))
		srcs := make([]RealmSource, len(files))
		for i, f := range files {
			srcs[i] = RealmSource{File: f, Realm: final[f].rf}
		}
		cross := append(ValidateKeyIDs(srcs), checkDuplicateRealms(srcs)...)
		bad := map[string]bool{}
		for _, d := range cross {
			if d.Severity == Error {
				bad[d.File] = true
			}
		}
		if len(bad) == 0 {
			break
		}
		ds.add(cross...)
		for _, f := range slices.Sorted(maps.Keys(bad)) {
			g := final[f]
			delete(final, f)
			delete(staleFiles, f)
			if g.fresh {
				fallback(f)
			}
		}
	}

	for f := range staleFiles {
		stale = append(stale, RealmName(final[f].rf.Name))
	}
	slices.Sort(stale)
	return final, stale, true
}

// loadRealm reads and checks one realm file. The result is nil when the
// file is invalid.
func (l *Loader) loadRealm(file string, eff, check *ServerFile) (*goodRealm, []Diagnostic) {
	b, err := os.ReadFile(l.path(file))
	if err != nil {
		return nil, []Diagnostic{{File: file, Severity: Error, Message: "cannot read " + file}}
	}
	rf, ds := DecodeRealm(file, b)
	if rf == nil || hasError(ds) {
		return nil, ds
	}
	// The TLS pair is checked by the server's own call, at startup only, not once
	// per realm file.
	sec, sd := LoadSecrets(l.dir, SecretSources{ServerFile: serverFileName, Server: eff, Realms: []RealmSource{{File: file, Realm: rf}}, SkipTLSPair: true})
	ds = append(ds, sd...)
	// The key rules of ValidateRealm are skipped without secrets, so a realm
	// whose secrets did not load must be invalid on its own account.
	var secrets Secrets
	if sec != nil {
		secrets = sec
	} else if !hasError(sd) {
		ds = append(ds, Diagnostic{File: file, Severity: Error, Message: "secrets could not be loaded"})
	}
	locales, ld := l.loadLocales(rf)
	ds = append(ds, ld...)
	rf.locales = locales
	ds = append(ds, ValidateRealm(file, rf, RealmCheck{Server: check, Secrets: secrets, Locales: l.localeExists})...)
	if hasError(ds) {
		return nil, ds
	}
	return &goodRealm{file: file, rf: rf, sec: sec, fresh: true}, ds
}

// localeCode says whether code can name a file in the locales directory.
func localeCode(code string) bool {
	if code == "" {
		return false
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (l *Loader) localeFile(code string) string { return localesDirName + "/" + code + ".yaml" }

// localeExists reports whether locales/<code>.yaml is a file.
func (l *Loader) localeExists(code string) bool {
	if !localeCode(code) {
		return false
	}
	fi, err := os.Stat(l.path(l.localeFile(code)))
	return err == nil && fi.Mode().IsRegular()
}

// loadLocales reads the translation file of every supported locale of the
// realm except the built-in "en". A file maps message ids to text.
func (l *Loader) loadLocales(rf *RealmFile) (map[string]map[string]string, []Diagnostic) {
	var out map[string]map[string]string
	var ds []Diagnostic
	for _, code := range rf.LoginPage.SupportedLocales {
		if code == "en" || !l.localeExists(code) {
			continue // a missing file is reported by ValidateRealm
		}
		if _, done := out[code]; done {
			continue
		}
		file := l.localeFile(code)
		b, err := os.ReadFile(l.path(file))
		if err != nil {
			ds = append(ds, Diagnostic{File: file, Severity: Error, Message: "cannot read " + file})
			continue
		}
		m := map[string]string{}
		if err := yaml.Unmarshal(b, &m); err != nil {
			d := diagFromYAMLError(file, err)
			d.Message = "must map message ids to text: " + d.Message
			ds = append(ds, d)
			continue
		}
		if out == nil {
			out = map[string]map[string]string{}
		}
		out[code] = m
	}
	return out, ds
}

// checkDuplicateRealms reports a realm name used by more than one file; the
// later file is at fault. ValidateRealm already requires the name to equal
// the file name, which makes this impossible for files it accepted.
func checkDuplicateRealms(realms []RealmSource) []Diagnostic {
	var ds []Diagnostic
	first := map[string]string{}
	for _, rs := range realms {
		if at, dup := first[rs.Realm.Name]; dup {
			line := rs.Realm.Line("name")
			ds = append(ds, Diagnostic{File: rs.File, Line: line, Field: "name", Severity: Error,
				Message: fmt.Sprintf("realm name %q is already used by %s", rs.Realm.Name, at)})
			continue
		}
		first[rs.Realm.Name] = rs.File
	}
	return ds
}
