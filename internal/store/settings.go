package store

import "fmt"

// InitRegistrationPolicy seeds the server_settings row with defaultPolicy
// (the FREIZONE_REGISTRATION_POLICY env var's value) if no row exists yet.
// After the first boot, the env var is only ever a seed -- the DB value is
// authoritative and mutable at runtime via SetRegistrationPolicy.
func InitRegistrationPolicy(db DBTX, defaultPolicy string) error {
	var existing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM server_settings WHERE id = 1`).Scan(&existing); err != nil {
		return fmt.Errorf("store: checking for existing server settings: %w", err)
	}
	if existing > 0 {
		return nil
	}
	if _, err := db.Exec(
		`INSERT INTO server_settings (id, registration_policy) VALUES (1, ?)`,
		defaultPolicy,
	); err != nil {
		return fmt.Errorf("store: seeding registration policy: %w", err)
	}
	return nil
}

// GetRegistrationPolicy returns the current registration policy.
func GetRegistrationPolicy(db DBTX) (string, error) {
	var policy string
	if err := db.QueryRow(`SELECT registration_policy FROM server_settings WHERE id = 1`).Scan(&policy); err != nil {
		return "", fmt.Errorf("store: reading registration policy: %w", err)
	}
	return policy, nil
}

// SetRegistrationPolicy updates the registration policy. Callers are
// responsible for validating policy against the known values first (see
// config.PolicyOpen/PolicyInvite/PolicyClosed).
func SetRegistrationPolicy(db DBTX, policy string) error {
	if _, err := db.Exec(`UPDATE server_settings SET registration_policy = ? WHERE id = 1`, policy); err != nil {
		return fmt.Errorf("store: setting registration policy: %w", err)
	}
	return nil
}
