package main

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/pkg/attest"
)

// withTestIssuer temporarily replaces attest.TrustedIssuers for the duration
// of a test, restoring the real (compiled-in production) set afterward.
// checkAttestation is the one piece of this repo that consults that package
// var directly, so tests need to control it rather than depend on whichever
// real keys happen to be embedded.
func withTestIssuer(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	original := attest.TrustedIssuers
	attest.TrustedIssuers = []ed25519.PublicKey{pub}
	t.Cleanup(func() { attest.TrustedIssuers = original })
}

func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func TestCheckAttestationEmptyLogsNothing(t *testing.T) {
	logger, buf := newTestLogger()
	checkAttestation(&config.Config{}, logger)
	if buf.Len() != 0 {
		t.Errorf("expected no log output for an unconfigured attestation, got %q", buf.String())
	}
}

func TestCheckAttestationMalformedWarns(t *testing.T) {
	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: "not-a-valid-token"}, logger)
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("expected a WARN log for a malformed attestation, got %q", buf.String())
	}
}

func TestCheckAttestationNoTrustedIssuersWarns(t *testing.T) {
	_, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now, now.Add(24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	original := attest.TrustedIssuers
	attest.TrustedIssuers = nil
	t.Cleanup(func() { attest.TrustedIssuers = original })

	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: token, Domain: "chat.example.org"}, logger)
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "no trusted issuer") {
		t.Errorf("expected a WARN log about missing trusted issuers, got %q", buf.String())
	}
}

func TestCheckAttestationUntrustedSignerWarns(t *testing.T) {
	_, signerPriv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	otherPub, _, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, otherPub) // trusts a *different* key than the one signing below

	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now, now.Add(24*time.Hour), signerPriv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: token, Domain: "chat.example.org"}, logger)
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "verification") {
		t.Errorf("expected a WARN log about failed verification, got %q", buf.String())
	}
}

// TestCheckAttestationUnsetDomainDoesNotWarn is the regression this test
// file exists for: a server behind an external reverse proxy that
// terminates TLS itself (nginx-proxy + acme-companion, Caddy, Traefik, ...)
// legitimately never sets FREIZONE_DOMAIN -- see config.go's Domain field
// and freizone-server's own production deployment. A genuinely signed and
// verified attestation must not log a warning merely because this server
// was never told its own public domain.
func TestCheckAttestationUnsetDomainDoesNotWarn(t *testing.T) {
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now, now.Add(24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	logger, buf := newTestLogger()
	// Domain deliberately left empty, matching FREIZONE_DOMAIN being unset.
	checkAttestation(&config.Config{Attestation: token, Domain: ""}, logger)

	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("expected no WARN log when FREIZONE_DOMAIN is unset for an otherwise genuine attestation, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "level=INFO") {
		t.Errorf("expected an INFO log noting the domain could not be checked, got %q", buf.String())
	}
}

func TestCheckAttestationValidLogsInfo(t *testing.T) {
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now, now.Add(24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: token, Domain: "chat.example.org"}, logger)

	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("expected no WARN log for a fully valid attestation, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "attestation verified") {
		t.Errorf("expected the success log line, got %q", buf.String())
	}
}

func TestCheckAttestationWrongDomainWarns(t *testing.T) {
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now, now.Add(24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: token, Domain: "someone-else.example.org"}, logger)
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "not currently valid") {
		t.Errorf("expected a WARN log for a domain mismatch, got %q", buf.String())
	}
}

func TestCheckAttestationExpiredWarns(t *testing.T) {
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	now := time.Now()
	a, err := attest.Sign("chat.example.org", attest.TierCommunity, "Example", 0, now.Add(-48*time.Hour), now.Add(-24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	logger, buf := newTestLogger()
	checkAttestation(&config.Config{Attestation: token, Domain: "chat.example.org"}, logger)
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "not currently valid") {
		t.Errorf("expected a WARN log for an expired attestation, got %q", buf.String())
	}
}
