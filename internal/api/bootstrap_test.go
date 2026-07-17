package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func bootstrapBody(token string, k identityKeys, sig []byte) []byte {
	req := bootstrapClaimRequest{
		SetupToken:          token,
		RootPubKey:          b64(k.rootPub),
		DeviceID:            k.deviceID,
		DevicePubKey:        b64(k.devicePub),
		DeviceCertIssuedAt:  k.issuedAt.UTC().Format(time.RFC3339),
		DeviceCertSignature: b64(sig),
	}
	body, _ := json.Marshal(req)
	return body
}

func TestHandleBootstrapClaimSuccess(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyClosed)
	token, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	k := newIdentityKeys(t)
	body := bootstrapBody(token, k, k.certSignature(t))

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp accountResponse
	decodeJSON(t, rec, &resp)
	if resp.ID != k.accountID {
		t.Errorf("account id = %q, want %q", resp.ID, k.accountID)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].DeviceID != k.deviceID {
		t.Errorf("devices = %+v, want one device %q", resp.Devices, k.deviceID)
	}

	acc, err := store.GetAccount(db, k.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if !acc.IsAdmin {
		t.Error("bootstrapped account is not marked as admin")
	}
}

func TestHandleBootstrapClaimWrongToken(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyClosed)
	if _, _, err := store.InitSetupToken(db, time.Now()); err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	k := newIdentityKeys(t)
	body := bootstrapBody("wrong-token", k, k.certSignature(t))

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBootstrapClaimAdminAlreadyExists(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyClosed)
	token, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	k1 := newIdentityKeys(t)
	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", bootstrapBody(token, k1, k1.certSignature(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first claim status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	if err := store.ResetSetupToken(db); err != nil {
		t.Fatalf("ResetSetupToken() error = %v", err)
	}
	token2, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	k2 := newIdentityKeys(t)
	rec2 := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", bootstrapBody(token2, k2, k2.certSignature(t)))
	if rec2.Code != http.StatusConflict {
		t.Errorf("second claim status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestHandleBootstrapClaimInvalidCertificate(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyClosed)
	token, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	k := newIdentityKeys(t)
	badSig := k.certSignature(t)
	badSig[0] ^= 0xFF

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/bootstrap/claim", bootstrapBody(token, k, badSig))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
