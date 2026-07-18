package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func TestHandleGetServerStatusUnclaimed(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyInvite)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp serverStatusResponse
	decodeJSON(t, rec, &resp)
	if resp.Claimed {
		t.Error("Claimed = true, want false before any bootstrap claim")
	}
	if resp.RegistrationPolicy != "invite" {
		t.Errorf("RegistrationPolicy = %q, want %q", resp.RegistrationPolicy, "invite")
	}
}

func TestHandleGetServerStatusClaimed(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	token, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	k := newIdentityKeys(t)
	claimRec := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", bootstrapBody(token, k, k.certSignature(t)))
	if claimRec.Code != http.StatusCreated {
		t.Fatalf("bootstrap claim status = %d, want 201, body = %s", claimRec.Code, claimRec.Body.String())
	}

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp serverStatusResponse
	decodeJSON(t, rec, &resp)
	if !resp.Claimed {
		t.Error("Claimed = false, want true after a bootstrap claim")
	}
	if resp.RegistrationPolicy != "open" {
		t.Errorf("RegistrationPolicy = %q, want %q", resp.RegistrationPolicy, "open")
	}
}
