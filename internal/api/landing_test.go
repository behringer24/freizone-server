package api

import (
	"net/http"
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
