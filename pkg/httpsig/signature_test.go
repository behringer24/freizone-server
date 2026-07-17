package httpsig

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return pub, priv
}

func TestSignAndVerifyValid(t *testing.T) {
	pub, priv := mustKeyPair(t)
	body := []byte(`{"hello":"world"}`)
	ts := time.Unix(1700000000, 0)

	sig := Sign(http.MethodPost, "/v1/devices", "", body, "device1", ts, "nonce-abc", priv)
	canonical := CanonicalString(http.MethodPost, "/v1/devices", "", FormatTimestamp(ts), "nonce-abc", "device1", body)

	if err := Verify(canonical, sig, pub); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub, priv := mustKeyPair(t)
	body := []byte(`{"hello":"world"}`)
	ts := time.Unix(1700000000, 0)
	sig := Sign(http.MethodPost, "/v1/devices", "", body, "device1", ts, "nonce-abc", priv)

	tests := []struct {
		name      string
		canonical string
	}{
		{"method", CanonicalString(http.MethodGet, "/v1/devices", "", FormatTimestamp(ts), "nonce-abc", "device1", body)},
		{"path", CanonicalString(http.MethodPost, "/v1/other", "", FormatTimestamp(ts), "nonce-abc", "device1", body)},
		{"query", CanonicalString(http.MethodPost, "/v1/devices", "x=1", FormatTimestamp(ts), "nonce-abc", "device1", body)},
		{"timestamp", CanonicalString(http.MethodPost, "/v1/devices", "", FormatTimestamp(ts.Add(time.Second)), "nonce-abc", "device1", body)},
		{"nonce", CanonicalString(http.MethodPost, "/v1/devices", "", FormatTimestamp(ts), "different-nonce", "device1", body)},
		{"keyID", CanonicalString(http.MethodPost, "/v1/devices", "", FormatTimestamp(ts), "nonce-abc", "device2", body)},
		{"body", CanonicalString(http.MethodPost, "/v1/devices", "", FormatTimestamp(ts), "nonce-abc", "device1", []byte(`{"hello":"tampered"}`))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Verify(tt.canonical, sig, pub); err == nil {
				t.Errorf("expected Verify() to fail after tampering with %s", tt.name)
			}
		})
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := mustKeyPair(t)
	otherPub, _ := mustKeyPair(t)
	body := []byte("body")
	ts := time.Unix(1700000000, 0)

	sig := Sign(http.MethodGet, "/v1/x", "", body, "device1", ts, "nonce", priv)
	canonical := CanonicalString(http.MethodGet, "/v1/x", "", FormatTimestamp(ts), "nonce", "device1", body)

	if err := Verify(canonical, sig, otherPub); err == nil {
		t.Error("expected Verify() to fail against the wrong public key")
	}
}

func TestVerifyRejectsMalformedSignature(t *testing.T) {
	pub, _ := mustKeyPair(t)
	if err := Verify("canonical", "not-valid-base64!!", pub); err == nil {
		t.Error("expected Verify() to reject malformed base64")
	}
	if err := Verify("canonical", "AAAA", pub); err == nil {
		t.Error("expected Verify() to reject a too-short signature")
	}
}

func TestParseRequestHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader("body"))
	req.Header.Set(HeaderKeyID, "device1")
	req.Header.Set(HeaderTimestamp, "1700000000")
	req.Header.Set(HeaderNonce, "nonce-abc")
	req.Header.Set(HeaderSignature, "c2ln")

	h, err := ParseRequestHeaders(req)
	if err != nil {
		t.Fatalf("ParseRequestHeaders() error = %v", err)
	}
	if h.KeyID != "device1" || h.Timestamp != "1700000000" || h.Nonce != "nonce-abc" || h.Signature != "c2ln" {
		t.Errorf("ParseRequestHeaders() = %+v", h)
	}
}

func TestParseRequestHeadersMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/devices", nil)
	req.Header.Set(HeaderKeyID, "device1")
	// Timestamp, Nonce, Signature intentionally omitted.

	if _, err := ParseRequestHeaders(req); err == nil {
		t.Error("expected ParseRequestHeaders() to fail with missing headers")
	}
}

func TestCanonicalStringFromRequestMatchesDirectBuild(t *testing.T) {
	body := []byte("payload")
	req := httptest.NewRequest(http.MethodPost, "/v1/devices?x=1", nil)
	req.Header.Set(HeaderKeyID, "device1")
	req.Header.Set(HeaderTimestamp, "1700000000")
	req.Header.Set(HeaderNonce, "nonce-abc")
	req.Header.Set(HeaderSignature, "sig")

	h, err := ParseRequestHeaders(req)
	if err != nil {
		t.Fatalf("ParseRequestHeaders() error = %v", err)
	}

	got := CanonicalStringFromRequest(req, h, body)
	want := CanonicalString(http.MethodPost, "/v1/devices", "x=1", "1700000000", "nonce-abc", "device1", body)
	if got != want {
		t.Errorf("CanonicalStringFromRequest() = %q, want %q", got, want)
	}
}

func TestParseTimestamp(t *testing.T) {
	ts, err := ParseTimestamp("1700000000")
	if err != nil {
		t.Fatalf("ParseTimestamp() error = %v", err)
	}
	if ts.Unix() != 1700000000 {
		t.Errorf("ts.Unix() = %d, want 1700000000", ts.Unix())
	}

	if _, err := ParseTimestamp("not-a-number"); err == nil {
		t.Error("expected ParseTimestamp() to fail on non-numeric input")
	}
}

func TestWithinSkew(t *testing.T) {
	now := time.Unix(1700000000, 0)

	tests := []struct {
		name string
		ts   time.Time
		want bool
	}{
		{"exact", now, true},
		{"just under, future", now.Add(4*time.Minute + 59*time.Second), true},
		{"just under, past", now.Add(-4*time.Minute - 59*time.Second), true},
		{"over, future", now.Add(6 * time.Minute), false},
		{"over, past", now.Add(-6 * time.Minute), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithinSkew(tt.ts, now, 5*time.Minute); got != tt.want {
				t.Errorf("WithinSkew(%v, %v, 5m) = %v, want %v", tt.ts, now, got, tt.want)
			}
		})
	}
}
