package store

import "testing"

func TestFederationEnabledSetting(t *testing.T) {
	db := newTestDB(t)
	// The single server_settings row (id=1) is created by InitRegistrationPolicy.
	if err := InitRegistrationPolicy(db, "closed"); err != nil {
		t.Fatalf("InitRegistrationPolicy() error = %v", err)
	}

	// An unseeded (NULL) column reads as enabled -- federation open by default.
	enabled, err := GetFederationEnabled(db)
	if err != nil {
		t.Fatalf("GetFederationEnabled() error = %v", err)
	}
	if !enabled {
		t.Error("default GetFederationEnabled = false, want true")
	}

	// Init seeds from the given default only while unseeded.
	if err := InitFederationEnabled(db, false); err != nil {
		t.Fatalf("InitFederationEnabled() error = %v", err)
	}
	if enabled, _ = GetFederationEnabled(db); enabled {
		t.Error("after InitFederationEnabled(false): enabled = true, want false")
	}

	// A second Init must NOT overwrite the already-seeded value.
	if err := InitFederationEnabled(db, true); err != nil {
		t.Fatalf("second InitFederationEnabled() error = %v", err)
	}
	if enabled, _ = GetFederationEnabled(db); enabled {
		t.Error("second Init overwrote the seeded value; want it left at false")
	}

	// Set flips it at runtime.
	if err := SetFederationEnabled(db, true); err != nil {
		t.Fatalf("SetFederationEnabled() error = %v", err)
	}
	if enabled, _ = GetFederationEnabled(db); !enabled {
		t.Error("after SetFederationEnabled(true): enabled = false, want true")
	}
}
