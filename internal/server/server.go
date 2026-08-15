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
	// BodyLimitOverrides raises that cap for specific route prefixes (the
	// blob transport), since the cap is applied outside the handler and so
	// cannot be widened from within one.
	BodyLimitOverrides []BodyLimitOverride
}

// Server wraps one or two http.Server instances, depending on TLS mode.
type Server struct {
	opts    Options
	servers []*http.Server
}

// Connection timeouts (SRV-28). Two of net/http's four are set here; the
// other two deliberately are not, and which is which is the whole point.
//
// ReadHeaderTimeout and IdleTimeout are safe because neither can fire during
// a request this server actually serves: one covers the header, the other an
// idle keep-alive connection between requests.
//
// ReadTimeout and WriteTimeout are not set, and must not be. Both cover a
// whole request/response, and both of this server's long operations exceed
// any value that would be a useful bound elsewhere: a blob upload over a slow
// mobile link can legitimately take minutes to read, and an SSE stream stays
// open for hours by design. WriteTimeout is the dangerous one -- it is reset
// only when a new request header is read, which a stream never does, so it
// would cut every stream at the timeout no matter how healthy, while the
// handler's writes went on reporting success. The bound that was actually
// wanted there is per write, and lives in the stream handler
// (internal/api/messages.go's sseWriteTimeout).
const (
	// readHeaderTimeout is the Slowloris bound: a client that opens a
	// connection and dribbles its headers holds nothing for longer than this.
	readHeaderTimeout = 15 * time.Second

	// idleTimeout closes a kept-alive connection with no request in flight.
	// Comfortably above any client's own reuse interval, so it costs a
	// reconnect only for connections genuinely finished with.
	idleTimeout = 150 * time.Second
)

// withTimeouts applies the two timeouts that are safe for every route this
// server has -- see the block above for the two that are not.
func withTimeouts(srv *http.Server) *http.Server {
	srv.ReadHeaderTimeout = readHeaderTimeout
	srv.IdleTimeout = idleTimeout
	return srv
}

// New builds a Server for opts. It does not start listening.
func New(opts Options) (*Server, error) {
	wrapped := withLogging(withRecover(withMaxBody(opts.Handler, opts.MaxRequestBodyBytes, opts.BodyLimitOverrides), opts.Logger), opts.Logger)

	switch opts.TLSMode {
	case config.TLSModeOff:
		return &Server{opts: opts, servers: []*http.Server{
			withTimeouts(&http.Server{Addr: opts.HTTPAddr, Handler: wrapped}),
		}}, nil

	case config.TLSModeManual:
		return &Server{opts: opts, servers: []*http.Server{
			withTimeouts(&http.Server{Addr: opts.HTTPSAddr, Handler: wrapped}),
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
		httpsServer := withTimeouts(&http.Server{
			Addr:      opts.HTTPSAddr,
			Handler:   wrapped,
			TLSConfig: mgr.TLSConfig(),
		})
		httpServer := withTimeouts(&http.Server{
			Addr:    opts.HTTPAddr,
			Handler: mgr.HTTPHandler(nil), // serves ACME HTTP-01 challenges, redirects everything else to https
		})
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
