package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
	isrv "github.com/yyudhistira/featherauth/internal/server"
)

// tlsCertificate returns the certificate of built-in TLS: the pair that
// tls.cert_file and tls.key_file name in the configuration directory. Reload
// loads the pair again; a pair that cannot be loaded is an error here.
func (a *app) tlsCertificate(srv *config.ServerFile, log *slog.Logger) (*isrv.Certificate, error) {
	dir := a.configDir()
	return isrv.NewCertificate(func() (*tls.Certificate, error) {
		pair, ds := config.LoadTLSPair(dir, srv)
		if pair == nil {
			return nil, diagnosticsError(ds)
		}
		return pair, nil
	}, log)
}

// tlsListeners opens the listeners of built-in TLS: the HTTPS listener on
// tls.listen, which serves h with the certificate of certs at TLS 1.2 or newer,
// and, when tls.http_listen is set, the plain listener that redirects to
// public_url. It returns the listeners and their servers in that order. On an
// error it closes the listeners it opened.
func tlsListeners(ctx context.Context, listen func(context.Context, string, string) (net.Listener, error),
	srv *config.ServerFile, certs *isrv.Certificate, h http.Handler, log *slog.Logger) ([]net.Listener, []*http.Server, error) {
	var lis []net.Listener
	var servers []*http.Server
	closeAll := func() {
		for _, l := range lis {
			_ = l.Close()
		}
	}
	tl, err := listen(ctx, "tcp", srv.TLS.Listen)
	if err != nil {
		return nil, nil, err
	}
	lis = append(lis, tls.NewListener(tl, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}))
	servers = append(servers, isrv.NewHTTPServer(srv.TLS.Listen, h))
	log.InfoContext(ctx, "listening", "addr", tl.Addr().String(), "role", "https")

	if srv.TLS.HTTPListen != "" {
		rl, err := listen(ctx, "tcp", srv.TLS.HTTPListen)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		lis = append(lis, rl)
		servers = append(servers, isrv.NewHTTPServer(srv.TLS.HTTPListen, isrv.Redirect(srv.PublicURL)))
		log.InfoContext(ctx, "listening", "addr", rl.Addr().String(), "role", "redirect")
	}
	return lis, servers, nil
}

// diagnosticsError joins the error diagnostics of ds into one error. The text
// names the file, the line and the reason, never the bytes of a file.
func diagnosticsError(ds []config.Diagnostic) error {
	var msgs []string
	for _, d := range ds {
		if d.Severity == config.Error {
			msgs = append(msgs, d.String())
		}
	}
	if len(msgs) == 0 {
		return errors.New("the certificate pair cannot be loaded")
	}
	return errors.New(strings.Join(msgs, "; "))
}
