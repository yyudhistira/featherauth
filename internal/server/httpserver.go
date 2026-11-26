package server

import (
	"context"
	"net"
	"net/http"
	"time"
)

// The fixed timeouts of the service (see HTTP endpoints in the design).
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

// NewHTTPServer returns an http.Server with the design's fixed timeouts.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// Server runs a Router on a listener and shuts it down gracefully.
type Server struct {
	http *http.Server
	rt   *Router
}

// New returns a Server for rt that listens on addr once Serve gets a listener.
func New(addr string, rt *Router) *Server {
	return &Server{http: NewHTTPServer(addr, rt), rt: rt}
}

// Serve serves on l until Shutdown; it returns http.ErrServerClosed then.
func (s *Server) Serve(l net.Listener) error { return s.http.Serve(l) }

// Shutdown makes /readyz answer 503, stops accepting connections and waits
// for the requests in flight, until ctx is done.
func (s *Server) Shutdown(ctx context.Context) error {
	s.rt.BeginShutdown()
	return s.http.Shutdown(ctx)
}
