package api

import (
	"net/http"
	"testing"

	"github.com/behringer24/freizone-server/internal/config"
)

func TestHandleHealth(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}
