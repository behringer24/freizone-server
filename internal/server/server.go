// Package server assembles the HTTP/HTTPS listeners for the Freizone API,
// handling the three supported TLS modes (off, manual, autocert) and
// graceful shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/behringer24/freizone-server/internal/config"
)

// Options configures how the server terminates connections and serves
// Handler.
type Options struct {
	Domain           string
	HTTPAddr         string
	HTTPSAddr        string
	TLSMode          config.TLSMode
	TLSCertFile      string
	TLSKeyFile       string
	AutocertCacheDir string
	Handler          http.Handler
	Logger           *slog.Logger
	// MaxRequestBodyBytes caps every request body -- see withMaxBody.
	MaxRequestBodyBytes int64
}

// Server wraps one or two http.Server instances, depending on TLS mode.
type Server struct {
	opts    Options
	servers []*http.Server
}

// New builds a Server for opts. It does not start listening.
func New(opts Options) (*Server, error) {
	wrapped := withLogging(withRecover(withMaxBody(opts.Handler, opts.MaxRequestBodyBytes), opts.Logger), opts.Logger)

	switch opts.TLSMode {
	case config.TLSModeOff:
		return &Server{opts: opts, servers: []*http.Server{
			{Addr: opts.HTTPAddr, Handler: wrapped},
		}}, nil

	case config.TLSModeManual:
		return &Server{opts: opts, servers: []*http.Server{
			{Addr: opts.HTTPSAddr, Handler: wrapped},
		}}, nil

	case config.TLSModeAutocert:
		if opts.Domain == "" {
			return nil, errors.New("server: autocert mode requires a domain")
		}
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(opts.Domain),
			Cache:      autocert.DirCache(opts.AutocertCacheDir),
		}
		httpsServer := &http.Server{
			Addr:      opts.HTTPSAddr,
			Handler:   wrapped,
			TLSConfig: mgr.TLSConfig(),
		}
		httpServer := &http.Server{
			Addr:    opts.HTTPAddr,
			Handler: mgr.HTTPHandler(nil), // serves ACME HTTP-01 challenges, redirects everything else to https
		}
		return &Server{opts: opts, servers: []*http.Server{httpServer, httpsServer}}, nil

	default:
		return nil, fmt.Errorf("server: unknown TLS mode %q", opts.TLSMode)
	}
}

// ListenAndServe starts all configured listeners and blocks until they have
// all stopped -- either because Shutdown was called (returns nil) or
// because one of them failed to start/run (returns that error, after best-
// effort shutting down the others).
func (s *Server) ListenAndServe() error {
	errCh := make(chan error, len(s.servers))
	for _, srv := range s.servers {
		srv := srv
		go func() {
			var err error
			switch {
			case srv.TLSConfig != nil:
				err = srv.ListenAndServeTLS("", "") // cert/key come from TLSConfig.GetCertificate (autocert)
			case s.opts.TLSMode == config.TLSModeManual:
				err = srv.ListenAndServeTLS(s.opts.TLSCertFile, s.opts.TLSKeyFile)
			default:
				err = srv.ListenAndServe()
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}

	var firstErr error
	shutdownTriggered := false
	for range s.servers {
		if err := <-errCh; err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if !shutdownTriggered {
				shutdownTriggered = true
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				s.Shutdown(ctx) //nolint:errcheck // best-effort; firstErr is what we report
				cancel()
			}
		}
	}
	return firstErr
}

// Shutdown gracefully stops all configured listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, srv := range s.servers {
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
