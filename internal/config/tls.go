package config

import (
	"crypto/tls"
	"os"
)

// LoadTLSPair reads the certificate chain and the key that tls.cert_file and
// tls.key_file name (built-in TLS, tls.mode files). Both paths are relative to
// dir unless absolute. The key is a secret file: its permissions are checked as
// those of the other secret files, a warning, or an error with
// strict_permissions. The pair must match. The result is nil when any diagnostic
// is an error. Diagnostics never contain bytes of the files.
func LoadTLSPair(dir string, s *ServerFile) (*tls.Certificate, []Diagnostic) {
	l := &loader{dir: dir, strict: s.StrictPermissions}
	certAt := where{serverFileName, s.Line("tls.cert_file"), "tls.cert_file"}
	keyAt := where{serverFileName, s.Line("tls.key_file"), "tls.key_file"}
	certPEM, certOK := l.readCertificate(s.TLS.CertFile, certAt)
	keyPEM, keyOK := l.read(s.TLS.KeyFile, keyAt, false)
	if !certOK || !keyOK {
		return nil, l.ds
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		l.errorf(keyAt, "%s and %s do not hold a certificate and its key: %v", s.TLS.CertFile, s.TLS.KeyFile, err)
		return nil, l.ds
	}
	return &pair, l.ds
}

// LoopbackListen reports whether v is host:port with an IP address host in the
// loopback range (127.0.0.0/8 or ::1). A host name is not loopback here.
func LoopbackListen(v string) bool { return loopbackListen(v) }

// TLSFiles returns the paths of the certificate and of the key of s, resolved
// as LoadTLSPair resolves them. The watcher of built-in TLS watches them.
func TLSFiles(dir string, s *ServerFile) []string {
	l := &loader{dir: dir}
	return []string{l.path(s.TLS.CertFile), l.path(s.TLS.KeyFile)}
}

// readCertificate returns the content of a certificate file. A certificate is
// public, so its permissions are not checked.
func (l *loader) readCertificate(name string, at where) ([]byte, bool) {
	b, err := os.ReadFile(l.path(name))
	if err != nil {
		l.errorf(at, "cannot read certificate file %s", name)
		return nil, false
	}
	return b, true
}
