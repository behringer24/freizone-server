package api

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestIsBlockedPushIP is the table guard for the SSRF denylist (audit M1):
// every internal range a device-registered endpoint must not reach is blocked,
// and ordinary public addresses are allowed.
func TestIsBlockedPushIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.0.0.53", "::1", // loopback
		"169.254.169.254", "fe80::1", // link-local (incl. cloud metadata)
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1", "fd12::1", // private / ULA
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.10", "2606:4700:4700::1111"}

	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", s)
		}
		if !isBlockedPushIP(ip) {
			t.Errorf("isBlockedPushIP(%s) = false, want true (internal address must be blocked)", s)
		}
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", s)
		}
		if isBlockedPushIP(ip) {
			t.Errorf("isBlockedPushIP(%s) = true, want false (public address must be allowed)", s)
		}
	}
}

// TestUnifiedPushClientRefusesInternalAddress verifies the hardened client's
// dialer refuses a connection to a loopback address -- the concrete SSRF the
// https-only check could not stop.
func TestUnifiedPushClientRefusesInternalAddress(t *testing.T) {
	client := newUnifiedPushClient()
	_, err := client.Get("https://127.0.0.1:1/wake")
	if !errors.Is(err, errBlockedPushTarget) {
		t.Fatalf("Get(loopback) error = %v, want it to wrap errBlockedPushTarget", err)
	}
}

// TestPushClientsDoNotFollowRedirects verifies the shared no-redirect policy:
// a 3xx is returned as-is rather than followed onto another host/scheme. The
// gateway client (no denylist) is used so a loopback test server can exercise
// the shared CheckRedirect hook.
func TestPushClientsDoNotFollowRedirects(t *testing.T) {
	var reachedFinal bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			reachedFinal = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	resp, err := newGatewayClient().Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect must not be followed)", resp.StatusCode)
	}
	if reachedFinal {
		t.Error("client followed the redirect to /final; it must not")
	}
}

// TestGatewayClientReusesConnectionsAcrossAFanout is the behavioural guard
// for gatewayMaxIdleConnsPerHost. wakeDevice starts one goroutine per
// recipient device, so a group message puts a burst of concurrent requests
// to the same host in flight. With net/http's default of 2 idle connections
// per host, only two of them survive the burst and every later request
// re-dials -- each new connection then sitting in TIME_WAIT, which is the
// binding ceiling on this path.
//
// Two bursts are used rather than one: the first necessarily opens fresh
// connections, and what matters is whether the second can reuse them.
func TestGatewayClientReusesConnectionsAcrossAFanout(t *testing.T) {
	const burst = 20

	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns[c] = true
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()

	client := newGatewayClient()
	fire := func() {
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(srv.URL + "/v1/push/send")
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining is what enables reuse
				resp.Body.Close()
			}()
		}
		wg.Wait()
	}

	fire()
	mu.Lock()
	afterFirst := len(conns)
	mu.Unlock()

	fire()
	mu.Lock()
	afterSecond := len(conns)
	mu.Unlock()

	// The second burst should be served almost entirely from the pool. A
	// couple of extra dials are tolerated: how many of the first burst's
	// connections are idle and drained by the time the second starts is a
	// scheduling detail. Anything approaching a second full burst means
	// the pool is capped near the default and the fix is not in effect.
	if newDials := afterSecond - afterFirst; newDials > burst/4 {
		t.Errorf("second burst opened %d new connections (first opened %d); "+
			"with a per-host pool of %d it should reuse nearly all of them",
			newDials, afterFirst, gatewayMaxIdleConnsPerHost)
	}
}
