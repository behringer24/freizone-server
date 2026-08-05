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

func TestHandleGetServerStatusAttestation(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyInvite)

	// Unset by default: most servers carry no attestation (SRV-19), and the
	// field is omitted rather than sent as an empty string.
	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	var resp serverStatusResponse
	decodeJSON(t, rec, &resp)
	if resp.Attestation != "" {
		t.Errorf("Attestation = %q, want empty when unset", resp.Attestation)
	}

	// Served back verbatim once configured -- this handler neither decodes
	// nor evaluates it, only hands it back exactly as given.
	const token = "opaque-attestation-token"
	a.Config.Attestation = token
	rec = doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	decodeJSON(t, rec, &resp)
	if resp.Attestation != token {
		t.Errorf("Attestation = %q, want %q", resp.Attestation, token)
	}
}
