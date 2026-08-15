package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"time"
)

//go:embed web/index.html
var landingHTML []byte

// Identifies this build's copy of the page. Computed once at start-up
// because the bytes are compiled in and cannot change while the process
// runs, which is also what makes it safe to revalidate against rather than
// having to guess an expiry.
var landingETag = func() string {
	sum := sha256.Sum256(landingHTML)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}()

// handleLanding serves a small human-facing page at the site root. A
// browser hitting the bare domain would otherwise get net/http's plain
// "404 page not found"; this instead explains that the host is a Freizone
// server and that Freizone is used through the app, not a browser.
//
// Safety: the page is a single compile-time-embedded file, so there is no
// filesystem access and thus no path-traversal surface. It is registered
// only at the exact root path ("GET /{$}"), so it never shadows the /v1/
// API or its JSON error contract -- unknown paths still fall through to the
// mux's default 404. It reflects no request input; the only dynamic data is
// a same-origin fetch of the already-public /v1/server-status the page runs
// client-side. None of this exposes anything /v1/server-status doesn't.
func (a *API) handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Locked down to match what the page actually needs: no external
	// resources at all, and same-origin XHR only (for the server-status
	// fetch). Inline style/script are permitted because the page ships them
	// inline and takes no user input to reflect.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src data:; "+
			"script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// The page carries its own background artwork inline, so it is no longer
	// small enough to be worth re-sending to every repeat visitor.
	// "no-cache" is revalidate-every-time rather than don't-store: an
	// operator who upgrades sees the new page at once, and an unchanged one
	// costs a header exchange instead of the whole file. ServeContent does
	// the If-None-Match comparison against the ETag set here, and leaves the
	// Content-Type above alone rather than sniffing its own.
	w.Header().Set("ETag", landingETag)
	w.Header().Set("Cache-Control", "no-cache")
	// Zero modtime: there is no meaningful file time for an embedded asset,
	// and it suppresses Last-Modified so the ETag is the only validator.
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(landingHTML))
}
