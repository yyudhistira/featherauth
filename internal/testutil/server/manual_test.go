//go:build manual

package server_test

import (
	"crypto/tls"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// TestManualServer is the helper of the browser matrix check M3 in docs/RELEASING.md: the service
// of the browser tests on port 443 with the certificate in $MANUAL_CERTS, for
// checking Firefox and Safari by hand. It runs only with -tags manual and
// until interrupted.
func TestManualServer(t *testing.T) {
	dir := os.Getenv("MANUAL_CERTS")
	if dir == "" {
		t.Fatal("set MANUAL_CERTS to the directory with site.pem and site.key (see RELEASING.md, One-time setup)")
	}
	cert, err := tls.LoadX509KeyPair(dir+"/site.pem", dir+"/site.key")
	if err != nil {
		t.Fatal(err)
	}
	env := server.New(t, server.WithLoginSetting(`accent_color: "#aa3300"`))
	for key, m := range env.Mocks {
		m.SetUser(mockidp.User{Sub: "sub-" + key, Name: "Ann Example", Email: "ann@example.com", EmailVerified: true})
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.example.com" {
			env.Router.ServeHTTP(w, r)
			return
		}
		_ = r.ParseForm()
		fmt.Fprintf(os.Stderr, "CLIENT %s %s%s cookie=%v form=%v\n", r.Method, r.Host, r.URL.RequestURI(), r.Header.Get("Cookie") != "", r.PostForm)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var b strings.Builder
		fmt.Fprintf(&b, "<!DOCTYPE html><title>client</title><h1>client application %s</h1><p>%s %s", html.EscapeString(r.Host), r.Method, html.EscapeString(r.URL.RequestURI()))
		b.WriteString("<h2>posted form</h2><pre>")
		for k, v := range r.PostForm {
			fmt.Fprintf(&b, "%s = %s\n", html.EscapeString(k), html.EscapeString(strings.Join(v, ",")))
		}
		b.WriteString("</pre>")
		_, _ = w.Write([]byte(b.String()))
	})
	srv := &http.Server{
		Addr: ":443", Handler: h,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go func() { _ = srv.ListenAndServeTLS("", "") }()
	enter := func(app server.App, p string) string {
		return env.Realm.EndpointURL(config.EndpointAuthorize, "") + "?" + server.Authorize(app, p).Encode()
	}
	fmt.Fprintln(os.Stderr, "\n==== READY ====")
	fmt.Fprintln(os.Stderr, "Chooser (query client):    ", enter(server.ClientQuery, ""))
	fmt.Fprintln(os.Stderr, "Chooser (form_post client):", enter(server.ClientFormPost, ""))
	fmt.Fprintln(os.Stderr, "Apple direct (query):      ", enter(server.ClientQuery, "apple"))
	fmt.Fprintln(os.Stderr, "Google direct (form_post): ", enter(server.ClientFormPost, "google"))
	fmt.Fprintln(os.Stderr, "Ctrl-C to stop")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	_ = srv.Close()
}
