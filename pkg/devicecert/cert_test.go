package devicecert

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func mustRootKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func TestNewDeviceIDFormat(t *testing.T) {
	id, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	if len(id) != 16 {
		t.Errorf("len(id) = %d, want 16", len(id))
	}
	id2, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	if id == id2 {
		t.Error("expected two calls to NewDeviceID to produce different ids")
	}
}

func TestSignAndVerifyDeviceCertificate(t *testing.T) {
	rootPub, rootPriv := mustRootKey(t, 1)
	devicePub, _, _ := ed25519.GenerateKey(nil)
	deviceID, _ := NewDeviceID()

	cert, err := SignDeviceCertificate("account123", deviceID, devicePub, time.Now(), rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	if err := cert.Verify(rootPub); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyRejectsWrongRootKey(t *testing.T) {
	_, rootPriv := mustRootKey(t, 1)
	otherPub, _ := mustRootKey(t, 2)
	devicePub, _, _ := ed25519.GenerateKey(nil)
	deviceID, _ := NewDeviceID()

	cert, err := SignDeviceCertificate("account123", deviceID, devicePub, time.Now(), rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	if err := cert.Verify(otherPub); err == nil {
		t.Error("expected Verify() to fail against the wrong root key")
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	rootPub, rootPriv := mustRootKey(t, 1)
	devicePub, _, _ := ed25519.GenerateKey(nil)
	deviceID, _ := NewDeviceID()

	cert, err := SignDeviceCertificate("account123", deviceID, devicePub, time.Now(), rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DeviceCertificate)
	}{
		{"account id", func(c *DeviceCertificate) { c.AccountID = "someone-else" }},
		{"device id", func(c *DeviceCertificate) { id, _ := NewDeviceID(); c.DeviceID = id }},
		{"issued at", func(c *DeviceCertificate) { c.IssuedAt = c.IssuedAt.Add(time.Hour) }},
		{"device pubkey", func(c *DeviceCertificate) { p, _, _ := ed25519.GenerateKey(nil); c.DevicePubKey = p }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *cert
			tampered.Signature = append([]byte{}, cert.Signature...)
			tt.mutate(&tampered)
			if err := tampered.Verify(rootPub); err == nil {
				t.Errorf("expected Verify() to fail after tampering with %s", tt.name)
			}
		})
	}
}

func TestVerifyRejectsMalformedDeviceID(t *testing.T) {
	rootPub, rootPriv := mustRootKey(t, 1)
	devicePub, _, _ := ed25519.GenerateKey(nil)

	cert, err := SignDeviceCertificate("account123", "not-hex!!", devicePub, time.Now(), rootPriv)
	if err == nil {
		t.Fatal("expected SignDeviceCertificate to reject a malformed device id")
	}
	_ = cert
	_ = rootPub
}

func TestVerifyRejectsWrongPubKeySize(t *testing.T) {
	_, rootPriv := mustRootKey(t, 1)
	deviceID, _ := NewDeviceID()

	if _, err := SignDeviceCertificate("account123", deviceID, ed25519.PublicKey([]byte{1, 2, 3}), time.Now(), rootPriv); err == nil {
		t.Fatal("expected SignDeviceCertificate to reject an undersized device public key")
	}
}

func TestSignAndVerifyDeviceRevocation(t *testing.T) {
	rootPub, rootPriv := mustRootKey(t, 5)
	deviceID, _ := NewDeviceID()

	rev, err := SignDeviceRevocation("account123", deviceID, time.Now(), rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceRevocation() error = %v", err)
	}

	if err := rev.Verify(rootPub); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyRevocationRejectsTamperedFields(t *testing.T) {
	rootPub, rootPriv := mustRootKey(t, 5)
	deviceID, _ := NewDeviceID()

	rev, err := SignDeviceRevocation("account123", deviceID, time.Now(), rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceRevocation() error = %v", err)
	}

	tampered := *rev
	tampered.Signature = append([]byte{}, rev.Signature...)
	tampered.RevokedAt = tampered.RevokedAt.Add(time.Hour)

	if err := tampered.Verify(rootPub); err == nil {
		t.Error("expected Verify() to fail after tampering with revoked_at")
	}
}
