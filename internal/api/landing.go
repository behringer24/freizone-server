package api

import (
	_ "embed"
	"net/http"
)

//go:embed web/index.html
var landingHTML []byte

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
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(landingHTML)
}
