package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/behringer24/freizone-server/internal/config"
)

func TestHandleLandingServesHTML(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Freizone") {
		t.Error("body does not mention Freizone")
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy header")
	}
}

// The attestation row (SRV-19) must ship hidden: most servers will never
// carry one, and that is the ordinary case, never a warning state -- so the
// markup has to start absent from the rendered page, only ever revealed by
// script once a currently-valid attestation is actually found.
func TestHandleLandingAttestationRowStartsHidden(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/", nil)
	body := rec.Body.String()
	if !strings.Contains(body, `id="attestation-label" hidden`) {
		t.Error("attestation label is not present and hidden by default")
	}
	if !strings.Contains(body, `id="attestation-value" hidden`) {
		t.Error("attestation value is not present and hidden by default")
	}
}

// The page is one request or it is nothing: its CSP grants no 'self' for
// scripts, styles or images, so any subresource added later would not merely
// cost a round trip, it would be blocked outright and the page would come up
// broken. Cheaper to fail here than to work that out from a blank background.
// Outbound <a href> links are a different thing entirely and stay allowed --
// the footer has one.
func TestHandleLandingPullsInNothing(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	body := doRequest(t, a.Router(), http.MethodGet, "/", nil).Body.String()
	for _, subresource := range []string{
		"<script src", "<link ", "@import", "url(http", "url('http", `url("http`,
		`src="http`, "src='http", `src="/`, "src='/",
	} {
		if strings.Contains(body, subresource) {
			t.Errorf("page references an external subresource (%q); it must stay a single request", subresource)
		}
	}
}

// Guards the page's weight, not its prose. It carries its background artwork
// and its logo inline, which is the right call at a few KB apiece and the
// wrong one the moment somebody pastes in a full-size bitmap -- the app's own
// chat-background PNG would be over a megabyte base64-encoded. The ceiling is
// deliberately far above the current size: it exists to catch a binary asset,
// not to police comments.
func TestHandleLandingStaysSmall(t *testing.T) {
	const ceiling = 64 << 10

	a, _ := newTestAPI(t, config.PolicyOpen)

	size := doRequest(t, a.Router(), http.MethodGet, "/", nil).Body.Len()
	if size > ceiling {
		t.Errorf("landing page is %d bytes, over the %d ceiling -- embedding a large asset?", size, ceiling)
	}
}

// The page now depends on the exact permissions this CSP grants: an inline
// style block and script, and data: URLs for the logo and the background
// mask. Tightening any of these silently turns the page blank or unstyled
// rather than erroring, so they are pinned here.
func TestHandleLandingCSPAllowsWhatThePageUses(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	csp := doRequest(t, a.Router(), http.MethodGet, "/", nil).Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"img-src data:",              // inline logo and the background mask tile
		"style-src 'unsafe-inline'",  // the one <style> block
		"script-src 'unsafe-inline'", // the one <script> block
		"connect-src 'self'",         // the /v1/server-status read
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP is missing %q, which the page relies on; CSP = %q", directive, csp)
		}
	}
}

// A repeat visitor should get a 304 rather than the whole page again. Worth
// having now that the page carries its artwork inline: it is several times
// the size it was when it was text and a logo.
func TestHandleLandingRevalidates(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	first := doRequest(t, a.Router(), http.MethodGet, "/", nil)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the first response")
	}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	a.Router().ServeHTTP(second, req)

	if second.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 carried %d bytes of body", second.Body.Len())
	}
}

// The landing route must match only the exact root path -- an unknown path
// has to keep falling through to the mux's default 404, never get served
// the HTML page. That contract is what lets a client treat "the response
// isn't JSON" as "this host isn't a Freizone server" without the landing
// page turning every typo into a false positive.
func TestHandleLandingDoesNotShadowOtherPaths(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/not-a-real-path", nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("GET /not-a-real-path returned 200; the root handler is acting as a catch-all")
	}
	if strings.Contains(rec.Body.String(), "<html") {
		t.Error("unknown path was served the landing HTML")
	}
}

// A real /v1/ endpoint must be unaffected by the root route.
func TestLandingRouteLeavesAPIIntact(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyInvite)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
}

// SRV-21: with LandingPageEnabled off, the route must not exist at all --
// net/http's plain 404, not a JSON "disabled" response like BlobsEnabled's,
// since the whole point is giving a privately-run server no sign that
// anything Freizone-shaped is listening at the root.
func TestHandleLandingDisabledGivesPlainNotFound(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.LandingPageEnabled = false

	rec := doRequest(t, a.Router(), http.MethodGet, "/", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<html") {
		t.Error("landing HTML was served despite LandingPageEnabled = false")
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q; net/http's default 404 is plain text, not JSON", ct)
	}
}
