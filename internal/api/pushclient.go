package api

import (
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"
)

// errBlockedPushTarget is returned by the UnifiedPush client's dialer when a
// device-registered endpoint resolves to a non-public address. It surfaces
// (wrapped) from the HTTP call, so callers/tests can match it with errors.Is.
var errBlockedPushTarget = errors.New("push: refusing to connect to a non-public address")

// noRedirect makes an http.Client return a 3xx response as-is instead of
// following it. Both push clients use it: a wake request must never be
// redirected onto a different scheme or host than the one that was validated
// and registered.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newUnifiedPushClient builds the HTTP client used for device-registered
// UnifiedPush endpoints (see push.go's notifyPush). Those endpoints are chosen
// by an untrusted device, so this client is deliberately locked down against
// SSRF (security audit M1):
//
//   - no redirects: an https endpoint (all handleSetPushEndpoint accepts) must
//     not be able to 302 the request onto http:// or an internal host, which
//     is exactly how the earlier https-only check was bypassable;
//   - a hard client timeout, independent of the per-call context, so a slow
//     or black-holed endpoint cannot tie up a goroutine longer than intended;
//   - a dialer that refuses any connection whose *resolved* IP is loopback,
//     link-local (incl. 169.254.169.254 cloud metadata), private/ULA,
//     unspecified or multicast. The check runs in the dialer's Control hook,
//     i.e. against every address actually dialed after DNS resolution, so a
//     hostname that resolves to an internal IP (or several) cannot slip past.
func newUnifiedPushClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   pushNotifyTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isBlockedPushIP(ip) {
				return errBlockedPushTarget
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:       pushNotifyTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: true,
			// Spread over many distributor hosts, so the total matters
			// more than the per-host figure -- but the per-host one must
			// still be set, because it otherwise defaults to 2 and a
			// distributor that many of this server's devices share would
			// re-dial for all but two of them.
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   pushNotifyTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// gatewayMaxIdleConnsPerHost is how many idle connections to keep to the
// gateway. Unusually high for a per-host figure because every gateway
// request in the process goes to that one host, so this is effectively a
// total, and it has to cover a fan-out rather than a single request:
// wakeDevice starts a goroutine per recipient device, so one group message
// can put dozens of requests in flight at once.
//
// net/http's default is 2. Everything above that number in a burst gets a
// fresh TCP connection that is closed again on completion and then sits in
// TIME_WAIT -- which, over plain http:// to a sibling container, is the
// lowest ceiling this path has: it is bounded by ephemeral ports rather
// than by any amount of CPU.
const gatewayMaxIdleConnsPerHost = 100

// newGatewayClient builds the HTTP client for the operator-configured
// freizone-gateway (see push.go's notifyPushViaGateway). The gateway URL comes
// from this server's own config, not from an untrusted device, and a gateway
// legitimately runs on an internal address (a sibling container, localhost),
// so this client keeps the redirect and timeout hardening but NOT the
// internal-address denylist -- which would otherwise block the operator's own
// gateway.
//
// It does carry its own Transport, which the SSRF-hardened client above got
// for free and this one previously did without: leaving Transport nil means
// http.DefaultTransport, whose MaxIdleConnsPerHost is 2. Since every gateway
// request in the process goes to the same single host, that default made a
// fan-out re-dial for all but two of its devices -- see
// gatewayMaxIdleConnsPerHost. Proxy is carried over explicitly, because
// dropping DefaultTransport also drops its ProxyFromEnvironment.
func newGatewayClient() *http.Client {
	return &http.Client{
		Timeout:       pushNotifyTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          gatewayMaxIdleConnsPerHost,
			MaxIdleConnsPerHost:   gatewayMaxIdleConnsPerHost,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   pushNotifyTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// isBlockedPushIP reports whether ip is one an untrusted push endpoint must not
// be allowed to reach: the ranges that only ever name this host or its internal
// network. net.IP.IsPrivate covers both IPv4 RFC1918 and IPv6 fc00::/7 ULA;
// IsLinkLocalUnicast covers 169.254.0.0/16 (cloud metadata) and fe80::/10.
func isBlockedPushIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified()
}
