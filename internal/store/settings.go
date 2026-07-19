package store

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"

	webpush "github.com/SherClockHolmes/webpush-go"
)

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

// InitVAPIDKeys generates and persists a server-wide VAPID keypair (RFC
// 8292) the first time it's called, if server_settings doesn't have one
// yet -- requires InitRegistrationPolicy to have already created the
// server_settings row. All outgoing push wake notifications (see
// internal/api/push.go) are signed with this one keypair, not a
// per-device or per-push one.
func InitVAPIDKeys(db DBTX) error {
	var existing sql.NullString
	if err := db.QueryRow(`SELECT vapid_public_key FROM server_settings WHERE id = 1`).Scan(&existing); err != nil {
		return fmt.Errorf("store: checking for existing vapid keys: %w", err)
	}
	if existing.Valid {
		return nil
	}

	privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return fmt.Errorf("store: generating vapid keys: %w", err)
	}
	if _, err := db.Exec(
		`UPDATE server_settings SET vapid_public_key = ?, vapid_private_key = ? WHERE id = 1`,
		publicKey, privateKey,
	); err != nil {
		return fmt.Errorf("store: persisting vapid keys: %w", err)
	}
	return nil
}

// GetVAPIDKeys returns the server's VAPID keypair.
func GetVAPIDKeys(db DBTX) (publicKey, privateKey string, err error) {
	if err := db.QueryRow(`SELECT vapid_public_key, vapid_private_key FROM server_settings WHERE id = 1`).Scan(&publicKey, &privateKey); err != nil {
		return "", "", fmt.Errorf("store: reading vapid keys: %w", err)
	}
	return publicKey, privateKey, nil
}

// InitRelayIdentity generates and persists this server's Ed25519 signing
// identity the first time it's called, if server_settings doesn't have
// one yet -- requires InitRegistrationPolicy to have already created the
// server_settings row. This identity signs every outgoing request to a
// freizone-gateway (see internal/api/push.go's notifyPushViaGateway),
// with the public key itself serving as the gateway's lookup-free
// Signature-Key-Id -- there is no separate registration step with any
// gateway, by design (see freizone-gateway's README for the security
// model this enables).
func InitRelayIdentity(db DBTX) error {
	var existing sql.NullString
	if err := db.QueryRow(`SELECT relay_pubkey FROM server_settings WHERE id = 1`).Scan(&existing); err != nil {
		return fmt.Errorf("store: checking for existing relay identity: %w", err)
	}
	if existing.Valid {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("store: generating relay identity: %w", err)
	}
	if _, err := db.Exec(
		`UPDATE server_settings SET relay_pubkey = ?, relay_privkey = ? WHERE id = 1`,
		base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv),
	); err != nil {
		return fmt.Errorf("store: persisting relay identity: %w", err)
	}
	return nil
}

// GetRelayIdentity returns the server's relay signing identity, base64-
// decoded and ready to use with pkg/httpsig.
func GetRelayIdentity(db DBTX) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	var pubB64, privB64 string
	if err := db.QueryRow(`SELECT relay_pubkey, relay_privkey FROM server_settings WHERE id = 1`).Scan(&pubB64, &privB64); err != nil {
		return nil, nil, fmt.Errorf("store: reading relay identity: %w", err)
	}
	pub, err = base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("store: decoding relay public key: %w", err)
	}
	priv, err = base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, nil, fmt.Errorf("store: decoding relay private key: %w", err)
	}
	return pub, priv, nil
}
