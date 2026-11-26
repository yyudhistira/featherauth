package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/yyudhistira/featherauth/internal/config"
)

const (
	defaultConfigDir = "/etc/featherauth"
	envConfigDir     = "FEATHERAUTH_CONFIG_DIR"
	envListen        = "FEATHERAUTH_LISTEN"
)

// listenAddress returns the address the service listens on: FEATHERAUTH_LISTEN,
// else `listen` of server.yaml in FEATHERAUTH_CONFIG_DIR (FR-17).
func (a *app) listenAddress() (string, error) {
	if v := a.getenv(envListen); v != "" {
		return v, nil
	}
	dir := a.getenv(envConfigDir)
	if dir == "" {
		dir = defaultConfigDir
	}
	b, err := os.ReadFile(filepath.Join(dir, "server.yaml"))
	if err != nil {
		return "", err
	}
	s, ds := config.DecodeServer("server.yaml", b)
	for _, d := range ds {
		if d.Severity == config.Error {
			return "", fmt.Errorf("%s", d)
		}
	}
	return s.Listen, nil
}

// healthcheck calls GET /readyz of the running service on its listen address,
// through the loopback interface when the address names no host, and succeeds
// on 200. The whole call is bounded by the health timeout.
func (a *app) healthcheck(ctx context.Context) int {
	listen, err := a.listenAddress()
	if err != nil {
		return a.fail(err)
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return a.fail(fmt.Errorf("listen address %q: %w", listen, err))
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/readyz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return a.fail(err)
	}
	client := &http.Client{Timeout: a.healthTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return a.fail(fmt.Errorf("readyz: %w", err))
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return a.fail(fmt.Errorf("readyz answered %d", resp.StatusCode))
	}
	fmt.Fprintln(a.stdout, "ready")
	return 0
}
