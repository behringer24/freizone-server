package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// diagnoseBudget caps the whole probe. Generous enough for three layers on a
// slow link, short enough that a failing host does not have the retry delayed by
// more than the connect attempt itself cost.
const diagnoseBudget = 8 * time.Second

// diagnoseReach probes a server one layer at a time and reports, in one line,
// how far it got.
//
// This exists because a connect that times out says nothing useful on its own:
// cancelling the attempt replaces whatever the stack was about to report, and
// even without that, "i/o timeout" does not say whether the name resolved, the
// port answered, or TLS failed. Each layer is tried separately here so the
// answer names the one that broke.
//
// Bounded as a whole, not per step. Each layer having its own timeout is not
// enough: against a host where every layer hangs they add up, and this probe
// runs on top of a connect that has already spent its deadline, delaying the
// retry by more than the attempt itself cost. One budget over everything caps
// that no matter which layer stalls.
func diagnoseReach(ctx context.Context, server string) string {
	ctx, cancelAll := context.WithTimeout(ctx, diagnoseBudget)
	defer cancelAll()

	parsed, err := url.Parse(server)
	if err != nil || parsed.Host == "" {
		return fmt.Sprintf("server address %q is not a URL this client can use", server)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}

	var steps []string

	// 1. Name resolution -- the layer most likely to behave differently from the
	// rest of the app. On Android everything else resolves through the platform,
	// while this runtime may do its own lookup, and there is no
	// /etc/resolv.conf for it to read. Go's own error text names the nameserver
	// it tried, which is the tell: a failure against 127.0.0.1:53 means the
	// pure-Go resolver ran with no configuration rather than the platform's.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, host)
	cancel()
	switch {
	case err != nil:
		return fmt.Sprintf("name %q did not resolve: %v", host, err)
	case len(addrs) == 0:
		return fmt.Sprintf("name %q resolved to nothing", host)
	default:
		steps = append(steps, fmt.Sprintf("%s resolves to %s", host, strings.Join(addrs, ", ")))
	}

	// 2. A plain TCP connection, which separates "the network cannot reach it"
	// from "TLS or HTTP went wrong".
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		return strings.Join(append(steps, fmt.Sprintf("but tcp/%s did not connect: %v", port, err)), "; ")
	}
	conn.Close()
	steps = append(steps, fmt.Sprintf("tcp/%s connects", port))

	// 3. A plain unauthenticated GET, which exercises TLS and the server itself
	// without involving signing, the stream, or anything this client added.
	// Failing only here points at TLS trust or the server, not at reachability.
	getCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(getCtx, http.MethodGet, server+"/v1/server-status", nil)
	if err != nil {
		return strings.Join(append(steps, fmt.Sprintf("but the status URL is unusable: %v", err)), "; ")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return strings.Join(append(steps, fmt.Sprintf("but GET /v1/server-status failed: %v", err)), "; ")
	}
	resp.Body.Close()

	// The protocol version is worth naming. Go negotiates HTTP/2 over TLS by
	// default; the app's Dart client speaks 1.1 only. A short request behaving
	// while a long-lived streaming one stalls is exactly what a proxy
	// mishandling h2 streams looks like, and this is the cheap way to find out
	// whether h2 is even in play rather than assuming it.
	steps = append(steps, fmt.Sprintf("GET /v1/server-status answered %d over %s",
		resp.StatusCode, resp.Proto))

	return strings.Join(steps, "; ")
}

// diagnoseStream reproduces the failing request itself, signed and on a short
// fuse, and reports what came back.
//
// The three layers above can all pass while this still fails -- that is exactly
// the case reported from the device. Testing the real path is the only thing
// that separates "the network is fine" from "the network is fine and something
// about *this* request is not".
func (c *Client) diagnoseStream(ctx context.Context, id Identity) string {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	req, err := c.streamRequest(ctx, id)
	if err != nil {
		return fmt.Sprintf("could not build a stream request: %v", err)
	}

	started := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Sprintf("the stream request itself got no response headers in %s: %v",
			time.Since(started).Round(time.Millisecond), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Sprintf("the stream request answered %d over %s: %s",
			resp.StatusCode, resp.Proto, strings.TrimSpace(string(body)))
	}
	return fmt.Sprintf("the stream request answered 200 over %s in %s, so the endpoint works and the earlier attempt was something else",
		resp.Proto, time.Since(started).Round(time.Millisecond))
}
