package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	isrv "github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
	"github.com/yyudhistira/featherauth/internal/web"
)

// shutdownTimeout is how long a shutdown waits for the requests in flight.
const shutdownTimeout = 30 * time.Second

// cleanupInterval is the period of the job that removes expired rows.
const cleanupInterval = time.Hour

// backupOf is the snapshot schedule of database.yaml. With driver postgres there
// is none: the backup options are not used, and a Postgres database is backed up
// with pg_dump.
func backupOf(db *config.DatabaseFile) config.BackupConfig {
	if db.Driver == "postgres" {
		return config.BackupConfig{}
	}
	return db.Backup
}

// serveCmd runs the service until SIGTERM or SIGINT; SIGHUP reloads the
// configuration.
func (a *app) serveCmd(ctx context.Context, args []string) int {
	if len(args) != 0 {
		return a.usageError("serve takes no arguments")
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	return a.serve(ctx, hup)
}

// serve is the service: it opens the database and applies the migrations,
// loads the configuration, then opens the listener. It returns when ctx is
// done, after a graceful shutdown, with the exit code. A value on hup reloads
// the configuration.
func (a *app) serve(ctx context.Context, hup <-chan os.Signal) int {
	level := new(slog.LevelVar)
	log := logx.NewLeveled(a.stdout, level, a.clock)

	st, db, err := a.openDatabase(ctx)
	if err != nil {
		return a.fail(err)
	}
	defer st.Close()
	loader, err := config.NewLoader(a.configDir(), a.clock, log)
	if err != nil {
		return a.fail(err)
	}
	snap := loader.Current()
	level.Set(parseLevel(snap.Server().LogLevel))
	if err := ensureRealms(ctx, st, snap, a.clock); err != nil {
		return a.fail(fmt.Errorf("create the realm rows: %w", err))
	}
	loader.OnApply(func(ctx context.Context, snap *config.Snapshot) {
		level.Set(parseLevel(snap.Server().LogLevel))
		if err := ensureRealms(ctx, st, snap, a.clock); err != nil {
			log.ErrorContext(ctx, "cannot create the rows of the new realms", "error", err)
		}
	})
	// The encryption keys are read at startup only; a reload checks the key
	// files but the startup keys stay in use, and a change to the list needs a
	// restart (see the loader and "Encryption key rotation" in the design), so
	// the box is built once.
	box, err := openBox(snap.Secrets().EncryptionKeys())
	if err != nil {
		return a.fail(err)
	}

	rt, err := a.router(loader, st, box, log)
	if err != nil {
		return a.fail(err)
	}
	var h http.Handler = rt
	if a.wrap != nil {
		h = a.wrap(h)
	}
	addr := a.getenv(envListen)
	if addr == "" {
		addr = snap.Server().Listen
	}
	listen := a.listen
	if listen == nil {
		listen = func(ctx context.Context, network, addr string) (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(ctx, network, addr)
		}
	}
	backups, err := store.StartBackups(st, backupOf(db), a.clock, log)
	if err != nil {
		return a.fail(err)
	}
	defer backups.Stop()
	cleanup := startCleanup(st, a.clock, log)
	defer cleanup.stop()
	// Built-in TLS (tls.mode files): the pair is loaded before any listener opens,
	// and the loopback listener serves the health endpoints only.
	srvFile := snap.Server()
	loopback := h
	var certs *isrv.Certificate
	if srvFile.TLS.Mode == "files" {
		// FEATHERAUTH_LISTEN overrides listen, so the loopback rule is checked on the
		// address that is used.
		if !config.LoopbackListen(addr) {
			return a.fail(fmt.Errorf("the listen address %q (FEATHERAUTH_LISTEN overrides listen) must be a loopback address with tls.mode files", addr))
		}
		if certs, err = a.tlsCertificate(&srvFile, log); err != nil {
			return a.fail(err)
		}
		loopback = rt.HealthHandler()
		if a.wrap != nil {
			loopback = a.wrap(loopback)
		}
	}
	l, err := listen(ctx, "tcp", addr)
	if err != nil {
		return a.fail(err)
	}
	lis := []net.Listener{l}
	servers := []*http.Server{isrv.NewHTTPServer(addr, loopback)}
	if certs != nil {
		tlsLis, tlsServers, err := tlsListeners(ctx, listen, &srvFile, certs, h, log)
		if err != nil {
			_ = l.Close()
			return a.fail(err)
		}
		lis = append(lis, tlsLis...)
		servers = append(servers, tlsServers...)
	}
	// The worker that posts back-channel logout tokens (FR-43): it runs until the
	// shutdown below stops it.
	deliverer := oidc.NewDeliverer(oidc.DeliverConfig{
		Store: st, Source: loader, Clock: a.clock, Rand: secure.Default, Log: log,
	})
	deliverer.Start()

	bg, cancelBG := context.WithCancel(context.WithoutCancel(ctx))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := loader.Watch(bg); err != nil {
			log.ErrorContext(bg, "cannot watch the configuration directory; reload with SIGHUP", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-hup:
				log.InfoContext(bg, "reload requested")
				loader.Reload(bg)
				if certs != nil {
					_ = certs.Reload(bg)
				}
			case <-bg.Done():
				return
			}
		}
	}()
	if certs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			files := config.TLSFiles(a.configDir(), &srvFile)
			if err := config.WatchFiles(bg, a.clock, log, files, func() { _ = certs.Reload(bg) }); err != nil {
				log.ErrorContext(bg, "cannot watch the certificate files; reload with SIGHUP", "error", err)
			}
		}()
	}

	serveErr := make(chan error, len(servers))
	for i, hs := range servers {
		go func() { serveErr <- hs.Serve(lis[i]) }()
	}
	log.InfoContext(ctx, "listening", "addr", l.Addr().String())

	code := 0
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		log.ErrorContext(ctx, "the server stopped", "error", err)
		code = 1
	}

	rt.BeginShutdown() // /readyz answers 503 from here on
	log.InfoContext(ctx, "shutting down")
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	// The worker drains within the same deadline as the requests: its calls in
	// flight finish, or are cut off at the deadline and counted as tries.
	stopping := make(chan error, 1)
	go func() { stopping <- deliverer.Stop(sctx) }()
	for _, hs := range servers {
		if err := hs.Shutdown(sctx); err != nil {
			log.ErrorContext(ctx, "shutdown did not finish", "error", err)
			_ = hs.Close()
			code = 1
		}
	}
	if err := <-stopping; err != nil {
		log.WarnContext(ctx, "back-channel logout calls were cut off at the shutdown; they are tried again", "error", err)
	}
	cancelBG()
	wg.Wait()
	log.InfoContext(ctx, "stopped")
	return code
}

// router wires the endpoints of the service.
func (a *app) router(src config.Source, st store.Store, box *secure.Box, log *slog.Logger) (*isrv.Router, error) {
	clk := a.clock
	secrets := config.LiveSecrets{Source: src}
	pool := provider.NewPool(src, clk, log)
	issuer := token.NewIssuer(clk, secure.Default, secrets)
	codes := token.NewCodes(st, issuer, clk, secure.Default)
	refresher := token.NewRefresher(st, token.NewIssuer(clk, secure.Default, secrets), clk, secure.Default)
	verifier := token.NewVerifier(clk, secrets)
	auditor := audit.NewWriter(st, log, clk, secure.Default)
	users := user.NewService(st, auditor, log, clk, secure.Default)
	manager := user.NewManager(st, auditor, box, func(realm, key string) provider.Revoker {
		p, ok := pool.Get(config.RealmName(realm), config.ProviderKey(key))
		if !ok {
			return nil
		}
		rv, _ := p.(provider.Revoker)
		return rv
	}, log, clk, secure.Default, sourceRealms(src))
	bearer := oidc.NewBearerAuth(verifier, st, a.clock)
	ops := admin.NewOps(st, manager, clk, log)
	h := handlers{
		discovery: oidc.NewDiscovery(),
		jwks:      oidc.NewJWKS(),
		userinfo:  oidc.NewUserinfo(oidc.UserinfoConfig{Bearer: bearer, Log: log}),
		logout:    oidc.NewLogout(oidc.LogoutConfig{Verifier: verifier, Bearer: bearer, Store: st, Users: manager, Clock: clk, Rand: secure.Default, Log: log}),
		revoke:    oidc.NewRevoke(oidc.RevokeConfig{Verifier: verifier, Store: st, Clock: clk, Rand: secure.Default, Log: log}),
		sessions:  oidc.NewSessions(oidc.SessionsConfig{Bearer: bearer, Lister: ops, Log: log}),
		account:   oidc.NewAccount(oidc.AccountConfig{Bearer: bearer, Users: manager, Clock: clk, Log: log}),
		token:     oidc.NewToken(oidc.TokenConfig{Codes: codes, Refresher: refresher, Audit: auditor, Log: log}),
		authorize: oidc.NewAuthorize(oidc.AuthorizeConfig{Registry: pool, Store: st, Clock: clk, Log: log, Verifier: verifier, Codes: codes}),
		deletion:  oidc.NewDataDeletion(),
		events:    oidc.NewEvents(oidc.EventsConfig{Registry: pool, Users: manager, Rand: secure.Default, Log: log}),
		callback:  oidc.NewCallback(oidc.CallbackConfig{Registry: pool, Store: st, Clock: clk, Log: log, Users: users, Codes: codes, Box: box}),
	}
	return isrv.NewHandler(src, h, isrv.Middleware{
		Logger: log, Clock: clk, Ready: st,
		Limit: isrv.LimitWith(rateLimiter(src, st, clk, log)),
		CORS:  isrv.CORS(),
	}), nil
}

// rateLimiter is the limiter of the requests: the instance's own counts, or with
// rate_limit.store database the counts shared through the database (FR-53).
func rateLimiter(src config.Source, st store.Store, clk clock.Clock, log *slog.Logger) isrv.Allower {
	if src.Current().Server().RateLimit.Store == "database" {
		return isrv.NewSharedLimiter(src, clk, log, isrv.StoreCounter(st))
	}
	return isrv.NewLimiter(src, clk, log)
}

// sourceRealms returns the configuration of the realms the running service
// serves: the one the source holds now. A source without a configuration is
// not available; a configuration without the realm names no client for it.
func sourceRealms(src config.Source) user.RealmOf {
	return func(name config.RealmName) (*config.Realm, bool) {
		snap := src.Current()
		if snap == nil {
			return nil, false
		}
		r, _ := snap.Realm(name)
		return r, true
	}
}

// handlers connects the router to the endpoints.
type handlers struct {
	discovery *oidc.Discovery
	authorize *oidc.Authorize
	callback  *oidc.Callback
	token     *oidc.Token
	jwks      *oidc.JWKS
	userinfo  *oidc.Userinfo
	logout    *oidc.Logout
	revoke    *oidc.Revoke
	sessions  *oidc.Sessions
	account   *oidc.Account
	events    *oidc.Events
	deletion  oidc.DataDeletion
}

var _ isrv.Handlers = handlers{}

func (h handlers) Discovery(w http.ResponseWriter, r *http.Request) { h.discovery.ServeHTTP(w, r) }
func (h handlers) Authorize(w http.ResponseWriter, r *http.Request) { h.authorize.ServeHTTP(w, r) }
func (h handlers) Callback(w http.ResponseWriter, r *http.Request)  { h.callback.ServeCallback(w, r) }
func (h handlers) CallbackContinue(w http.ResponseWriter, r *http.Request) {
	h.callback.ServeContinue(w, r)
}
func (h handlers) Token(w http.ResponseWriter, r *http.Request)          { h.token.ServeHTTP(w, r) }
func (h handlers) Userinfo(w http.ResponseWriter, r *http.Request)       { h.userinfo.ServeHTTP(w, r) }
func (h handlers) JWKS(w http.ResponseWriter, r *http.Request)           { h.jwks.ServeHTTP(w, r) }
func (h handlers) Logout(w http.ResponseWriter, r *http.Request)         { h.logout.ServeHTTP(w, r) }
func (h handlers) Revoke(w http.ResponseWriter, r *http.Request)         { h.revoke.ServeHTTP(w, r) }
func (h handlers) Sessions(w http.ResponseWriter, r *http.Request)       { h.sessions.ServeHTTP(w, r) }
func (h handlers) AccountDelete(w http.ResponseWriter, r *http.Request)  { h.account.ServeHTTP(w, r) }
func (h handlers) ProviderEvents(w http.ResponseWriter, r *http.Request) { h.events.ServeHTTP(w, r) }
func (h handlers) DataDeletion(w http.ResponseWriter, r *http.Request)   { h.deletion.ServeHTTP(w, r) }
func (handlers) Assets(w http.ResponseWriter, r *http.Request) {
	info, ok := isrv.FromContext(r.Context())
	if !ok || info.Realm == nil {
		http.NotFound(w, r)
		return
	}
	if !isrv.AllowMethods(w, r, http.MethodGet) {
		return
	}
	web.Assets(w, r, info.Realm)
}

// parseLevel maps log_level to a slog level; the configuration is validated,
// so an unknown value cannot occur and means info.
func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

// ensureRealms creates the row of every realm of snap that has none.
func ensureRealms(ctx context.Context, st store.Store, snap *config.Snapshot, clk clock.Clock) error {
	return st.Write(ctx, func(tx store.Tx) error {
		for _, r := range snap.Realms() {
			id, err := secure.NewID(secure.Default, clk)
			if err != nil {
				return err
			}
			if _, err := tx.Realms().Ensure(ctx, r.Name, store.RealmID(id), clk.Now()); err != nil {
				return err
			}
		}
		return nil
	})
}

// cleanupJob removes the expired rows every hour; its timer is the clock's.
type cleanupJob struct {
	st    store.Store
	clock clock.Clock
	log   *slog.Logger

	mu      sync.Mutex
	timer   clock.Timer
	stopped bool
	running sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func startCleanup(st store.Store, c clock.Clock, log *slog.Logger) *cleanupJob {
	ctx, cancel := context.WithCancel(context.Background())
	j := &cleanupJob{st: st, clock: c, log: log, ctx: ctx, cancel: cancel}
	j.mu.Lock()
	j.timer = c.AfterFunc(cleanupInterval, j.fire)
	j.mu.Unlock()
	return j
}

func (j *cleanupJob) fire() {
	j.mu.Lock()
	if j.stopped {
		j.mu.Unlock()
		return
	}
	j.running.Add(1)
	j.mu.Unlock()
	defer j.running.Done()

	n, err := store.Cleanup(j.ctx, j.st, j.clock.Now())
	switch {
	case errors.Is(err, context.Canceled):
	case err != nil:
		j.log.ErrorContext(j.ctx, "cleanup failed", "error", err)
	default:
		j.log.InfoContext(j.ctx, "cleanup done", "auth_requests", n.AuthRequests, "auth_codes", n.AuthCodes,
			"handoffs", n.Handoffs, "provider_events", n.ProviderEvents, "refresh_tokens", n.RefreshTokens,
			"rate_limits", n.RateLimits)
	}

	j.mu.Lock()
	if !j.stopped {
		j.timer = j.clock.AfterFunc(cleanupInterval, j.fire)
	}
	j.mu.Unlock()
}

// stop ends the job and waits for a run in progress.
func (j *cleanupJob) stop() {
	j.mu.Lock()
	j.stopped = true
	if j.timer != nil {
		j.timer.Stop()
	}
	j.mu.Unlock()
	j.cancel()
	j.running.Wait()
}
