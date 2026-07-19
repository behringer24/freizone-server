package store

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
)

// Recognized PushTarget.Platform values.
const (
	PushPlatformFCM  = "fcm"
	PushPlatformAPNS = "apns"
)

// Device is a device certified under an account's root key.
type Device struct {
	DeviceID      string
	AccountID     string
	DevicePubKey  ed25519.PublicKey
	CertIssuedAt  time.Time
	CertSignature []byte
	Status        string
	RevokedAt     *time.Time
	CreatedAt     time.Time

	// DH identity key for X3DH/Double Ratchet key agreement -- nil until
	// the device has uploaded prekeys at least once (see prekeys.go).
	DHIdentityPubKey    []byte
	DHIdentityIssuedAt  *time.Time
	DHIdentitySignature []byte

	// Push is this device's registered push-wake subscription (see
	// SetDevicePushSubscription), nil until it has registered one.
	Push *PushSubscription

	// PushTarget is this device's registered FCM/APNs push target (see
	// SetDevicePushTarget), nil until it has registered one. Mutually
	// exclusive with Push -- a device uses exactly one wake mechanism
	// at a time.
	PushTarget *PushTarget
}

// PushSubscription is a UnifiedPush/Web Push subscription: an endpoint
// URL to POST wake notifications to, plus the recipient's ECDH public
// key and auth secret used to RFC 8291-encrypt the payload for it.
type PushSubscription struct {
	Endpoint string
	P256dh   string
	Auth     string
}

// PushTarget identifies a device for delivery through a freizone-gateway
// (see internal/api/push.go's notifyPushViaGateway): which platform, and
// that platform's own addressing token (an FCM registration token, or --
// once implemented -- an APNs device token).
type PushTarget struct {
	Platform string
	Token    string
}

// CreateDevice inserts a new device. It returns ErrConflict if the device id
// is already taken.
func CreateDevice(db DBTX, d Device) error {
	_, err := db.Exec(
		`INSERT INTO devices (device_id, account_id, device_pubkey, cert_issued_at, cert_signature, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.AccountID, []byte(d.DevicePubKey), formatTime(d.CertIssuedAt), d.CertSignature, d.Status, formatTime(d.CreatedAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: device %s", ErrConflict, d.DeviceID)
		}
		return fmt.Errorf("store: creating device: %w", err)
	}
	return nil
}

// GetDevice looks up a device by id. It returns ErrNotFound if no such
// device exists.
func GetDevice(db DBTX, deviceID string) (*Device, error) {
	row := db.QueryRow(
		`SELECT device_id, account_id, device_pubkey, cert_issued_at, cert_signature, status, revoked_at, created_at,
		        dh_identity_pubkey, dh_identity_issued_at, dh_identity_signature, push_endpoint, push_p256dh, push_auth,
		        push_platform, push_target
		 FROM devices WHERE device_id = ?`,
		deviceID,
	)
	return scanDevice(row)
}

// ListDevicesByAccount returns all devices (active and revoked) certified
// under the given account, ordered by creation time.
func ListDevicesByAccount(db DBTX, accountID string) ([]Device, error) {
	rows, err := db.Query(
		`SELECT device_id, account_id, device_pubkey, cert_issued_at, cert_signature, status, revoked_at, created_at,
		        dh_identity_pubkey, dh_identity_issued_at, dh_identity_signature, push_endpoint, push_p256dh, push_auth,
		        push_platform, push_target
		 FROM devices WHERE account_id = ? ORDER BY created_at ASC`,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		d, err := scanDeviceRows(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// RevokeDevice marks an active device as revoked. It returns ErrNotFound if
// the device doesn't exist or is already revoked.
func RevokeDevice(db DBTX, deviceID string, revokedAt time.Time) error {
	res, err := db.Exec(
		`UPDATE devices SET status = ?, revoked_at = ? WHERE device_id = ? AND status = ?`,
		DeviceStatusRevoked, formatTime(revokedAt), deviceID, DeviceStatusActive,
	)
	if err != nil {
		return fmt.Errorf("store: revoking device: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for device revocation: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanDevice(row *sql.Row) (*Device, error) {
	d, err := scanDeviceFields(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func scanDeviceRows(rows *sql.Rows) (*Device, error) {
	return scanDeviceFields(rows)
}

func scanDeviceFields(s scannable) (*Device, error) {
	var d Device
	var pubkey []byte
	var issuedAt, createdAt string
	var revokedAt sql.NullString
	var dhPubKey, dhSignature []byte
	var dhIssuedAt sql.NullString
	var pushEndpoint, pushP256dh, pushAuth sql.NullString
	var pushPlatform, pushToken sql.NullString

	if err := s.Scan(
		&d.DeviceID, &d.AccountID, &pubkey, &issuedAt, &d.CertSignature, &d.Status, &revokedAt, &createdAt,
		&dhPubKey, &dhIssuedAt, &dhSignature, &pushEndpoint, &pushP256dh, &pushAuth,
		&pushPlatform, &pushToken,
	); err != nil {
		return nil, fmt.Errorf("store: scanning device: %w", err)
	}

	d.DevicePubKey = ed25519.PublicKey(pubkey)

	t, err := parseTime(issuedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing device cert_issued_at: %w", err)
	}
	d.CertIssuedAt = t

	t, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing device created_at: %w", err)
	}
	d.CreatedAt = t

	if revokedAt.Valid {
		t, err := parseTime(revokedAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parsing device revoked_at: %w", err)
		}
		d.RevokedAt = &t
	}

	if len(dhPubKey) > 0 {
		d.DHIdentityPubKey = dhPubKey
		d.DHIdentitySignature = dhSignature
		if dhIssuedAt.Valid {
			t, err := parseTime(dhIssuedAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parsing device dh_identity_issued_at: %w", err)
			}
			d.DHIdentityIssuedAt = &t
		}
	}

	if pushEndpoint.Valid {
		d.Push = &PushSubscription{Endpoint: pushEndpoint.String, P256dh: pushP256dh.String, Auth: pushAuth.String}
	}

	if pushPlatform.Valid {
		d.PushTarget = &PushTarget{Platform: pushPlatform.String, Token: pushToken.String}
	}

	return &d, nil
}

// UpsertDHIdentity sets or replaces a device's X3DH DH identity key. It
// returns ErrNotFound if the device doesn't exist.
func UpsertDHIdentity(db DBTX, deviceID string, pubKey, signature []byte, issuedAt time.Time) error {
	res, err := db.Exec(
		`UPDATE devices SET dh_identity_pubkey = ?, dh_identity_issued_at = ?, dh_identity_signature = ? WHERE device_id = ?`,
		pubKey, formatTime(issuedAt), signature, deviceID,
	)
	if err != nil {
		return fmt.Errorf("store: upserting dh identity key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for dh identity upsert: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDevicePushSubscription sets or clears (sub == nil) a device's
// registered push subscription. Setting a non-nil subscription also
// clears any registered push target (see SetDevicePushTarget) -- a
// device uses exactly one wake mechanism at a time. It returns
// ErrNotFound if the device doesn't exist.
func SetDevicePushSubscription(db DBTX, deviceID string, sub *PushSubscription) error {
	var endpoint, p256dh, auth *string
	if sub != nil {
		endpoint, p256dh, auth = &sub.Endpoint, &sub.P256dh, &sub.Auth
	}
	query := `UPDATE devices SET push_endpoint = ?, push_p256dh = ?, push_auth = ? WHERE device_id = ?`
	args := []any{endpoint, p256dh, auth, deviceID}
	if sub != nil {
		query = `UPDATE devices SET push_endpoint = ?, push_p256dh = ?, push_auth = ?, push_platform = NULL, push_target = NULL WHERE device_id = ?`
	}
	res, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("store: setting device push subscription: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for push subscription update: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDevicePushTarget sets or clears (target == nil) a device's
// registered FCM/APNs push target. Setting a non-nil target also clears
// any registered push subscription (see SetDevicePushSubscription) -- a
// device uses exactly one wake mechanism at a time. It returns
// ErrNotFound if the device doesn't exist.
func SetDevicePushTarget(db DBTX, deviceID string, target *PushTarget) error {
	var platform, token *string
	if target != nil {
		platform, token = &target.Platform, &target.Token
	}
	query := `UPDATE devices SET push_platform = ?, push_target = ? WHERE device_id = ?`
	args := []any{platform, token, deviceID}
	if target != nil {
		query = `UPDATE devices SET push_platform = ?, push_target = ?, push_endpoint = NULL, push_p256dh = NULL, push_auth = NULL WHERE device_id = ?`
	}
	res, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("store: setting device push target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for push target update: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
