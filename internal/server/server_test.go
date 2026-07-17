package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
)

func TestNewRejectsUnknownTLSMode(t *testing.T) {
	_, err := New(Options{TLSMode: "bogus", Handler: http.NewServeMux()})
	if err == nil {
		t.Fatal("expected error for unknown TLS mode")
	}
}

func TestNewAutocertRequiresDomain(t *testing.T) {
	_, err := New(Options{TLSMode: config.TLSModeAutocert, Handler: http.NewServeMux()})
	if err == nil {
		t.Fatal("expected error for autocert mode without a domain")
	}
}

func TestNewAutocertProducesTwoServers(t *testing.T) {
	srv, err := New(Options{
		TLSMode:          config.TLSModeAutocert,
		Domain:           "example.org",
		HTTPAddr:         ":80",
		HTTPSAddr:        ":443",
		AutocertCacheDir: t.TempDir(),
		Handler:          http.NewServeMux(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(srv.servers) != 2 {
		t.Errorf("len(servers) = %d, want 2 for autocert mode", len(srv.servers))
	}
}

func TestNewOffProducesOneServer(t *testing.T) {
	srv, err := New(Options{TLSMode: config.TLSModeOff, HTTPAddr: ":8080", Handler: http.NewServeMux()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(srv.servers) != 1 {
		t.Errorf("len(servers) = %d, want 1 for off mode", len(srv.servers))
	}
}

func TestShutdownWithoutListenIsSafe(t *testing.T) {
	srv, err := New(Options{TLSMode: config.TLSModeOff, HTTPAddr: ":8080", Handler: http.NewServeMux()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() error = %v, want nil for a server that never started listening", err)
	}
}

func TestListenAndServeRoundTrip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	srv, err := New(Options{TLSMode: config.TLSModeOff, HTTPAddr: "127.0.0.1:18743", Handler: mux})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()

	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://127.0.0.1:18743/ping")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /ping error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ListenAndServe() returned error = %v, want nil after graceful shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ListenAndServe() did not return after Shutdown()")
	}
}

func TestListenAndServeReportsBindError(t *testing.T) {
	// Bind the port first so the server under test fails to start.
	blocker, err := net.Listen("tcp", "127.0.0.1:18744")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer blocker.Close()

	srv, err := New(Options{TLSMode: config.TLSModeOff, HTTPAddr: "127.0.0.1:18744", Handler: http.NewServeMux()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := srv.ListenAndServe(); err == nil {
		t.Error("expected ListenAndServe() to report an error when the port is already in use")
	}
}
