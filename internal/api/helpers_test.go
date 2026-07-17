package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// identityKeys is a full set of keys for one simulated account+device, plus
// the derived account id, for use across handler tests.
type identityKeys struct {
	accountID  string
	rootPub    ed25519.PublicKey
	rootPriv   ed25519.PrivateKey
	deviceID   string
	devicePub  ed25519.PublicKey
	devicePriv ed25519.PrivateKey
	issuedAt   time.Time
}

func newIdentityKeys(t *testing.T) identityKeys {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}

	return identityKeys{
		accountID:  accountID,
		rootPub:    rootPub,
		rootPriv:   rootPriv,
		deviceID:   deviceID,
		devicePub:  devicePub,
		devicePriv: devicePriv,
		issuedAt:   time.Now().Truncate(time.Second),
	}
}

func (k identityKeys) certSignature(t *testing.T) []byte {
	t.Helper()
	cert, err := devicecert.SignDeviceCertificate(k.accountID, k.deviceID, k.devicePub, k.issuedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}
	return cert.Signature
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// doSignedRequest signs the request with signerDeviceID/signerPriv (an
// existing active device on the account making the call).
func doSignedRequest(t *testing.T, handler http.Handler, method, path string, body []byte, signerDeviceID string, signerPriv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = []byte{}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ts := time.Now()
	nonce := "nonce-" + signerDeviceID + "-" + path + "-" + ts.String()
	sig := httpsig.Sign(method, req.URL.Path, req.URL.RawQuery, body, signerDeviceID, ts, nonce, signerPriv)

	req.Header.Set(httpsig.HeaderKeyID, signerDeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// newSignedHTTPRequest builds a real *http.Request (for use with an
// http.Client against an httptest.Server) signed with signerDeviceID/priv.
func newSignedHTTPRequest(t *testing.T, method, targetURL string, body []byte, signerDeviceID string, priv ed25519.PrivateKey) *http.Request {
	t.Helper()
	if body == nil {
		body = []byte{}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", targetURL, err)
	}

	req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ts := time.Now()
	nonce := "nonce-" + signerDeviceID + "-" + parsed.Path + "-" + ts.String()
	sig := httpsig.Sign(method, parsed.Path, parsed.RawQuery, body, signerDeviceID, ts, nonce, priv)

	req.Header.Set(httpsig.HeaderKeyID, signerDeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	return req
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
}
