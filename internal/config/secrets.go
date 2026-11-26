package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// minRSABits is the smallest RSA signing key the design accepts.
const minRSABits = 2048

// encryptionKeyLen is the length of an encryption key in bytes.
const encryptionKeyLen = 32

// minClientSecretChars is the length, in characters, below which the loader
// warns about the secret of a confidential client (SEC-30).
const minClientSecretChars = 32

// SecretKind tells whether a client secret belongs to a provider or to a
// client of a realm.
type SecretKind int

const (
	// ProviderSecret is the client secret of a provider.
	ProviderSecret SecretKind = iota + 1
	// ClientSecretOf is the secret of a confidential client.
	ClientSecretOf
)

// Secrets gives access to the key material and secrets read from files. A
// Secrets value logs only counts (it implements slog.LogValuer).
type Secrets interface {
	slog.LogValuer
	// Signing returns the signing key with the given kid, or nil.
	Signing(kid string) crypto.Signer
	// AppleKey returns the .p8 key of an Apple provider, or nil.
	AppleKey(realm, provider string) *ecdsa.PrivateKey
	// ClientSecret returns the secret of a provider or client, or "".
	ClientSecret(realm string, kind SecretKind, id string) string
	// EncryptionKeys returns copies of the encryption keys; the first
	// encrypts and all decrypt.
	EncryptionKeys() [][]byte
}

// RealmSource is a decoded realm file and the name used in diagnostics.
type RealmSource struct {
	File  string
	Realm *RealmFile
}

// SecretSources names everything LoadSecrets reads. Server and Database may
// be nil.
type SecretSources struct {
	ServerFile   string
	Server       *ServerFile
	DatabaseFile string
	Database     *DatabaseFile
	Realms       []RealmSource
	// SkipTLSPair leaves the built-in TLS pair out of the check. A reload sets
	// it: the pair is reloaded by the certificate reloader of the server, which
	// keeps the previous pair when a new one is broken, so a reload never fails
	// on it. Startup and config check read the pair.
	SkipTLSPair bool
}

// FileSecrets is the Secrets read from files.
type FileSecrets struct {
	signing map[string]crypto.Signer
	apple   map[string]*ecdsa.PrivateKey // realm + "\x00" + provider
	secrets map[string]string            // realm + "\x00" + kind + "\x00" + id
	enc     [][]byte
}

var _ Secrets = (*FileSecrets)(nil)

// LogValue logs how many of each kind were loaded and nothing else.
func (s *FileSecrets) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("signing_count", len(s.signing)),
		slog.Int("apple_count", len(s.apple)),
		slog.Int("secret_count", len(s.secrets)),
		slog.Int("encryption_count", len(s.enc)),
	)
}

// Signing implements Secrets.
func (s *FileSecrets) Signing(kid string) crypto.Signer { return s.signing[kid] }

// AppleKey implements Secrets.
func (s *FileSecrets) AppleKey(realm, provider string) *ecdsa.PrivateKey {
	return s.apple[realm+"\x00"+provider]
}

// ClientSecret implements Secrets.
func (s *FileSecrets) ClientSecret(realm string, kind SecretKind, id string) string {
	return s.secrets[secretKey(realm, kind, id)]
}

// EncryptionKeys implements Secrets.
func (s *FileSecrets) EncryptionKeys() [][]byte {
	out := make([][]byte, len(s.enc))
	for i, k := range s.enc {
		out[i] = bytes.Clone(k)
	}
	return out
}

func secretKey(realm string, kind SecretKind, id string) string {
	return fmt.Sprintf("%s\x00%d\x00%s", realm, kind, id)
}

// loader reads secret files relative to dir and collects diagnostics.
type loader struct {
	dir    string
	strict bool
	ds     []Diagnostic
	failed bool
}

// LoadSecrets reads every secret file named in src, relative to dir. It
// checks each file's permissions (a warning, or an error with
// strict_permissions) and parses its content. The result is nil when any
// diagnostic is an error. Diagnostics never contain bytes of a secret.
func LoadSecrets(dir string, src SecretSources) (*FileSecrets, []Diagnostic) {
	l := &loader{dir: dir}
	if src.Server != nil {
		l.strict = src.Server.StrictPermissions
	}
	s := &FileSecrets{
		signing: map[string]crypto.Signer{},
		apple:   map[string]*ecdsa.PrivateKey{},
		secrets: map[string]string{},
	}

	storesTokens := false
	for _, rs := range src.Realms {
		for _, p := range rs.Realm.Providers {
			if p != nil && p.Enabled && p.StoreRefreshToken {
				storesTokens = true
			}
		}
	}

	if src.Server != nil {
		for i, f := range src.Server.Secrets.EncryptionKeyFiles {
			field := fmt.Sprintf("secrets.encryption_key_files[%d]", i)
			at := where{src.ServerFile, src.Server.Line(field), field}
			b, ok := l.read(f, at, !storesTokens)
			if !ok {
				continue
			}
			k, err := parseEncryptionKey(b)
			if err != nil {
				l.errorf(at, "%s: %v", f, err)
				continue
			}
			s.enc = append(s.enc, k)
		}
	}

	// The database secrets are checked here so that a load reports them. The
	// values are read again at startup (ReadDatabaseSecrets), not by a reload.
	if src.Database != nil {
		l.database(src.DatabaseFile, src.Database)
	}

	// The built-in TLS pair (tls.mode files) is checked the same way.
	if src.Server != nil && src.Server.TLS.Mode == "files" && !src.SkipTLSPair {
		_, tds := LoadTLSPair(dir, src.Server)
		l.ds = append(l.ds, tds...)
		if hasError(tds) {
			l.failed = true
		}
	}

	for _, rs := range src.Realms {
		l.realm(s, rs)
	}

	if l.failed {
		return nil, l.ds
	}
	return s, l.ds
}

func (l *loader) realm(s *FileSecrets, rs RealmSource) {
	r := rs.Realm
	for i, k := range r.Keys {
		if k.File == "" {
			continue
		}
		field := fmt.Sprintf("keys[%d].file", i)
		at := where{rs.File, r.Line(field), field}
		b, ok := l.read(k.File, at, false)
		if !ok {
			continue
		}
		key, err := parseSigningKey(b)
		if err != nil {
			l.errorf(at, "%s: %v", k.File, err)
			continue
		}
		s.signing[k.Kid] = key
	}

	for _, name := range sortedKeys(r.Providers) {
		p := r.Providers[name]
		if p == nil || !p.Enabled {
			continue // a disabled provider's files are not read
		}
		if p.ClientSecretFile != "" {
			field := "providers." + name + ".client_secret_file"
			at := where{rs.File, r.Line(field), field}
			if b, ok := l.readSecretText(p.ClientSecretFile, at); ok {
				s.secrets[secretKey(r.Name, ProviderSecret, name)] = b
			}
		}
		if p.Type == "apple" && p.PrivateKeyFile != "" {
			field := "providers." + name + ".private_key_file"
			at := where{rs.File, r.Line(field), field}
			b, ok := l.read(p.PrivateKeyFile, at, false)
			if !ok {
				continue
			}
			key, err := parseSigningKey(b)
			if err != nil {
				l.errorf(at, "%s: %v", p.PrivateKeyFile, err)
				continue
			}
			ec, isEC := key.(*ecdsa.PrivateKey)
			if !isEC {
				l.errorf(at, "%s: the Apple key must be an EC P-256 private key", p.PrivateKeyFile)
				continue
			}
			s.apple[r.Name+"\x00"+name] = ec
		}
	}

	for _, id := range sortedKeys(r.Clients) {
		c := r.Clients[id]
		if c == nil || c.ClientSecretFile == "" {
			continue
		}
		field := "clients." + id + ".client_secret_file"
		at := where{rs.File, r.Line(field), field}
		if b, ok := l.readSecretText(c.ClientSecretFile, at); ok {
			if c.Type == Confidential && shortClientSecret(b) {
				l.add(at, Warning, fmt.Sprintf("secret file %s is shorter than %d characters; use a client secret of at least %d characters",
					c.ClientSecretFile, minClientSecretChars, minClientSecretChars))
			}
			s.secrets[secretKey(r.Name, ClientSecretOf, id)] = b
		}
	}
}

// shortClientSecret tells whether a client secret has fewer than
// minClientSecretChars characters. A character is a Unicode code point.
func shortClientSecret(secret string) bool {
	return utf8.RuneCountInString(secret) < minClientSecretChars
}

// where locates an option in a configuration file.
type where struct {
	file  string
	line  int
	field string
}

func (l *loader) add(at where, sev Severity, msg string) {
	if sev == Error {
		l.failed = true
	}
	l.ds = append(l.ds, Diagnostic{File: at.file, Line: at.line, Field: at.field, Severity: sev, Message: msg})
}

func (l *loader) errorf(at where, format string, args ...any) {
	l.add(at, Error, fmt.Sprintf(format, args...))
}

// read checks the permissions of the file named by option value name and
// returns its content. A missing file is skipped without a diagnostic when
// optional is true.
func (l *loader) read(name string, at where, optional bool) ([]byte, bool) {
	path := l.path(name)
	info, err := os.Stat(path)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		l.errorf(at, "cannot read secret file %s", name)
		return nil, false
	}
	if info.Mode().Perm()&0o077 != 0 {
		sev := Warning
		if l.strict {
			sev = Error
		}
		l.add(at, sev, fmt.Sprintf("secret file %s has mode %04o; it must not be accessible by group or others (use 0600)", name, info.Mode().Perm()))
		if sev == Error {
			return nil, false
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		l.errorf(at, "cannot read secret file %s", name)
		return nil, false
	}
	return b, true
}

// path returns the path of a file named in the configuration: relative names
// are relative to the configuration directory.
func (l *loader) path(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(l.dir, name)
}

// readSecretText reads a client secret file and returns its text. A file that
// is empty, or holds only whitespace, is an error: there would be no secret.
func (l *loader) readSecretText(name string, at where) (string, bool) {
	b, ok := l.read(name, at, false)
	if !ok {
		return "", false
	}
	text := secretText(b)
	if strings.TrimSpace(text) == "" {
		l.errorf(at, "secret file %s is empty", name)
		return "", false
	}
	return text, true
}

// secretText returns the file content with one trailing newline removed.
func secretText(b []byte) string {
	return strings.TrimSuffix(string(b), "\n")
}

func parseEncryptionKey(b []byte) ([]byte, error) {
	errBad := errors.New("an encryption key file must hold 32 bytes as base64 (44 characters)")
	text := secretText(b)
	if len(text) != base64.StdEncoding.EncodedLen(encryptionKeyLen) {
		return nil, errBad
	}
	k, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(k) != encryptionKeyLen {
		return nil, errBad
	}
	return k, nil
}

// parseSigningKey parses a PEM private key: RSA with at least 2048 bits, or
// EC on P-256. Errors never include the key content.
func parseSigningKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, errors.New("the PEM block is not a private key")
	}
	if err != nil {
		return nil, errors.New("the PEM block is not a valid private key")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("an RSA key must have at least %d bits, got %d", minRSABits, k.N.BitLen())
		}
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("an EC key must use curve P-256")
		}
		return k, nil
	}
	return nil, errors.New("the private key must be RSA or EC P-256")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LiveSecrets is the Secrets of the current snapshot of a Source, so that a
// reload brings new signing keys and client secrets to services built once.
// Encryption keys are read at startup only (see Loader), so they do not change.
type LiveSecrets struct{ Source Source }

var _ Secrets = LiveSecrets{}

func (l LiveSecrets) cur() Secrets { return l.Source.Current().Secrets() }

// Signing implements Secrets.
func (l LiveSecrets) Signing(kid string) crypto.Signer { return l.cur().Signing(kid) }

// AppleKey implements Secrets.
func (l LiveSecrets) AppleKey(realm, provider string) *ecdsa.PrivateKey {
	return l.cur().AppleKey(realm, provider)
}

// ClientSecret implements Secrets.
func (l LiveSecrets) ClientSecret(realm string, kind SecretKind, id string) string {
	return l.cur().ClientSecret(realm, kind, id)
}

// EncryptionKeys implements Secrets.
func (l LiveSecrets) EncryptionKeys() [][]byte { return l.cur().EncryptionKeys() }

// LogValue implements slog.LogValuer.
func (l LiveSecrets) LogValue() slog.Value { return l.cur().LogValue() }
