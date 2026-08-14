package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/internal/store"
)

type bootstrapClaimRequest struct {
	SetupToken          string `json:"setup_token"`
	RootPubKey          string `json:"root_pubkey"`
	DeviceID            string `json:"device_id"`
	DevicePubKey        string `json:"device_pubkey"`
	DeviceCertIssuedAt  string `json:"device_cert_issued_at"`
	DeviceCertSignature string `json:"device_cert_signature"`
}

type registerAccountRequest struct {
	RootPubKey          string  `json:"root_pubkey"`
	DeviceID            string  `json:"device_id"`
	DevicePubKey        string  `json:"device_pubkey"`
	DeviceCertIssuedAt  string  `json:"device_cert_issued_at"`
	DeviceCertSignature string  `json:"device_cert_signature"`
	InviteCode          *string `json:"invite_code,omitempty"`
}

type addDeviceRequest struct {
	AccountID    string `json:"account_id"`
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
}

// recoverAccountRequest is the body of POST /v1/accounts/{id}/recover: a new
// device certificate (signed by the account's root key) to attach to an
// existing account after total device loss. The account is identified by the
// path id; the request as a whole is authenticated by a root-key signature
// (see handleRecoverAccount). Mirrors registerAccountRequest's device fields.
type recoverAccountRequest struct {
	DeviceID            string `json:"device_id"`
	DevicePubKey        string `json:"device_pubkey"`
	DeviceCertIssuedAt  string `json:"device_cert_issued_at"`
	DeviceCertSignature string `json:"device_cert_signature"`
}

type revokeDeviceRequest struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	RevokedAt string `json:"revoked_at"`
	Signature string `json:"signature"`
}

// setPushEndpointRequest registers or clears (all fields nil/omitted) a
// device's push subscription. Endpoint, P256dh, and Auth must be given
// together or not at all -- see handleSetPushEndpoint.
type setPushEndpointRequest struct {
	Endpoint *string `json:"endpoint"`
	P256dh   *string `json:"p256dh"`
	Auth     *string `json:"auth"`
}

// setPushTargetRequest registers or clears (both fields nil/omitted) a
// device's FCM/APNs push target. Platform and Token must be given
// together or not at all -- see handleSetPushTarget.
type setPushTargetRequest struct {
	Platform *string `json:"platform"`
	Token    *string `json:"token"`
}

type createInviteRequest struct {
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type createInviteResponse struct {
	Code      string  `json:"code"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type adminAccountResponse struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`

	// Activity signals (SRV-09), so the list can distinguish an account in
	// use from an abandoned one. Always present, zero when there is nothing
	// queued or stored -- an absent field would be indistinguishable from an
	// older server that doesn't send these at all, and "0 pending" is a
	// meaningful answer where "unknown" is not.
	PendingMessages int `json:"pending_messages"`
	// OldestPendingAt is omitted rather than zero-valued when the queue is
	// empty: there is no such timestamp, and a client rendering an age from
	// it would otherwise print something absurd.
	OldestPendingAt *string `json:"oldest_pending_at,omitempty"`
	BlobCount       int     `json:"blob_count"`
	BlobBytes       int64   `json:"blob_bytes"`
	// BlobBytesLimit is what BlobBytes is measured against: the per-device
	// quota times the account's device count, since that is where the limit
	// is actually enforced. Computed here rather than left to the client,
	// which has no business knowing the server's config. Zero for an account
	// with no devices, which a client must read as "no meaningful limit"
	// rather than "limit of nothing".
	BlobBytesLimit int64 `json:"blob_bytes_limit"`
	DeviceCount    int   `json:"device_count"`

	// InvitedBy is the account that issued the invite this one joined with
	// (SRV-14). Sent to admins only, and omitted rather than empty whenever
	// there is nothing to say: open registration, or an inviter who has since
	// been deleted (the invite row cascades with them). A caller therefore
	// cannot read its absence as "registered openly" -- only as "not known
	// here".
	InvitedBy *string `json:"invited_by,omitempty"`
}

func adminAccountResponseFrom(acc store.Account, activity store.AccountActivity, maxBlobBytesPerDevice int64, invitedBy string) adminAccountResponse {
	resp := adminAccountResponse{
		ID:              acc.ID,
		Role:            string(acc.Role),
		Status:          acc.Status,
		CreatedAt:       acc.CreatedAt.UTC().Format(time.RFC3339),
		PendingMessages: activity.PendingMessages,
		BlobCount:       activity.BlobCount,
		BlobBytes:       activity.BlobBytes,
		BlobBytesLimit:  maxBlobBytesPerDevice * int64(activity.DeviceCount),
		DeviceCount:     activity.DeviceCount,
	}
	if !activity.OldestPendingAt.IsZero() {
		oldest := activity.OldestPendingAt.UTC().Format(time.RFC3339)
		resp.OldestPendingAt = &oldest
	}
	if invitedBy != "" {
		resp.InvitedBy = &invitedBy
	}
	return resp
}

type setAccountRoleRequest struct {
	Role string `json:"role"`
}

// blockFederationSenderRequest blocks a remote account id from delivering
// federated messages here -- see docs/PROTOCOL.md's federation section on
// why this is per-account, not per-origin-server.
type blockFederationSenderRequest struct {
	AccountID string  `json:"account_id"`
	Reason    *string `json:"reason,omitempty"`
}

type federationBlockEntryResponse struct {
	AccountID string  `json:"account_id"`
	BlockedAt string  `json:"blocked_at"`
	BlockedBy string  `json:"blocked_by"`
	Reason    *string `json:"reason,omitempty"`
}

func federationBlockEntryResponseFrom(e store.FederationBlockEntry) federationBlockEntryResponse {
	return federationBlockEntryResponse{
		AccountID: e.AccountID,
		BlockedAt: e.BlockedAt.UTC().Format(time.RFC3339),
		BlockedBy: e.BlockedBy,
		Reason:    e.Reason,
	}
}

type statusResponse struct {
	Status string `json:"status"`
}

type registrationPolicyResponse struct {
	Policy string `json:"policy"`
}

type setRegistrationPolicyRequest struct {
	Policy string `json:"policy"`
}

// serverStatusResponse is the public GET /v1/server-status payload -- see
// internal/api/server_status.go.
type serverStatusResponse struct {
	Claimed            bool   `json:"claimed"`
	RegistrationPolicy string `json:"registration_policy"`
	FederationEnabled  bool   `json:"federation_enabled"`
	// Blob transport capability (SRV-07), so a sender can size an
	// attachment to the *recipient* server's limit before uploading.
	BlobsEnabled bool  `json:"blobs_enabled"`
	MaxBlobBytes int64 `json:"max_blob_bytes"`
	// Multi-recipient upload capability (SRV-18). Its absence means **1**,
	// not "unlimited": an older server ignores the extra recipients, stores
	// the blob for the first one and still answers 201, so a sender that
	// assumed otherwise would silently deliver a picture to one member of a
	// group. Discovered per server, like the batch fields below.
	MaxBlobRecipients int `json:"max_blob_recipients"`
	// Batch delivery capability (SRV-01). Absent means an older server, and
	// the documented fallback is to post each message on its own -- which is
	// why groups work against every server already in the field. Discovered
	// per server, since a federated group's members are spread across
	// several and they will not upgrade together.
	BatchMessages    bool `json:"batch_messages"`
	MaxBatchMessages int  `json:"max_batch_messages"`
	// Attestation (SRV-19) is an opaque pkg/attest token, served exactly as
	// configured -- this server never decodes or evaluates it, only hands
	// it back. Omitted (not an empty string) when unset, so a client can
	// tell "no attestation configured" apart from "configured but empty"
	// without special-casing the latter. Not sensitive: its safety comes
	// from the domain binding a client checks after verifying it, not from
	// being hidden.
	Attestation string `json:"attestation,omitempty"`
}

type federationEnabledResponse struct {
	Enabled bool `json:"enabled"`
}

type setFederationEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type accountResponse struct {
	ID         string           `json:"id"`
	RootPubKey string           `json:"root_pubkey"`
	Devices    []deviceResponse `json:"devices"`
}

type deviceResponse struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	IssuedAt     string `json:"issued_at"`
	// Signature is the device certificate's signature (by the account's
	// root key) -- required so a client can verify the full self-certifying
	// chain (root_pubkey -> this signature -> device_pubkey) itself,
	// without trusting the server's word for it.
	Signature string  `json:"signature"`
	Status    string  `json:"status"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

type dhIdentityCertDTO struct {
	DHPubKey  string `json:"dh_pubkey"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type signedPrekeyDTO struct {
	KeyID            uint32 `json:"key_id"`
	DHIdentityPubKey string `json:"dh_identity_pubkey"`
	PubKey           string `json:"pubkey"`
	IssuedAt         string `json:"issued_at"`
	Signature        string `json:"signature"`
}

type oneTimePrekeyDTO struct {
	KeyID  uint32 `json:"key_id"`
	PubKey string `json:"pubkey"`
}

type uploadPrekeysRequest struct {
	DHIdentityCert *dhIdentityCertDTO `json:"dh_identity_cert,omitempty"`
	SignedPrekey   signedPrekeyDTO    `json:"signed_prekey"`
	OneTimePrekeys []oneTimePrekeyDTO `json:"one_time_prekeys,omitempty"`

	// ReplaceOneTimePrekeys discards every unclaimed one-time prekey this
	// device has previously published before adding OneTimePrekeys, instead
	// of appending to them. False (append, the default) for an ordinary
	// top-up; true for a client that has reason to believe its published
	// pool contains ids it holds no private half for, and wants to publish
	// only ones it actually does. Absent/false is a no-op change from every
	// existing caller's point of view.
	ReplaceOneTimePrekeys bool `json:"replace_one_time_prekeys,omitempty"`
}

type prekeyBundleResponse struct {
	DeviceID         string            `json:"device_id"`
	DHIdentityPubKey string            `json:"dh_identity_pubkey"`
	DHIdentityCert   dhIdentityCertDTO `json:"dh_identity_cert"`
	SignedPrekey     signedPrekeyDTO   `json:"signed_prekey"`
	OneTimePrekey    *oneTimePrekeyDTO `json:"one_time_prekey,omitempty"`

	// OneTimePrekeyOmitted says why OneTimePrekey is absent, and is itself
	// absent when one was handed out (SRV-04). Purely diagnostic -- the two
	// reasons are otherwise indistinguishable, and "you weren't authenticated"
	// is something a client should notice rather than mistake for a drained
	// pool. Older clients ignore the field, which is what makes gating the key
	// a non-breaking change.
	OneTimePrekeyOmitted string `json:"one_time_prekey_omitted,omitempty"`
}

const (
	oneTimePrekeyOmittedPoolEmpty      = "pool_empty"
	oneTimePrekeyOmittedUnauthenticated = "unauthenticated"
)

// claimPrekeyBundleRequest is the OPTIONAL body of a prekey-bundle claim: the
// self-certifying identity of a claimant whose account lives on another server,
// in the same shape federated message delivery uses (§9). A claimant registered
// on this server sends no body at all and signs the request the ordinary way
// (§3); an unauthenticated claimant sends neither and gets no one-time prekey.
type claimPrekeyBundleRequest struct {
	SenderAccountID  string                  `json:"sender_account_id"`
	SenderRootPubKey string                  `json:"sender_root_pub_key"`
	SenderDeviceCert federationDeviceCertDTO `json:"sender_device_cert"`
}

// prekeyStatusResponse is the GET /v1/devices/{id}/prekey-status payload --
// lets a device check its own one-time-prekey pool without consuming one
// (unlike POST .../prekey-bundle, which claims and removes a key).
type prekeyStatusResponse struct {
	OneTimePrekeysRemaining int `json:"one_time_prekeys_remaining"`
}

type sendMessageRequest struct {
	MessageID          string          `json:"message_id"`
	RecipientAccountID string          `json:"recipient_account_id"`
	RecipientDeviceID  string          `json:"recipient_device_id"`
	Payload            json.RawMessage `json:"payload"`
}

// sendMessageBatchRequest delivers several messages in one request (SRV-01).
// It exists for group fan-out, where the same author sends N separately
// encrypted copies: batching collapses that to one request per distinct
// recipient *server* instead of one per recipient device. Every item is from
// the one signing device, so authentication is unchanged.
type sendMessageBatchRequest struct {
	Messages []batchMessageItem `json:"messages"`
}

type batchMessageItem struct {
	MessageID          string          `json:"message_id"`
	RecipientAccountID string          `json:"recipient_account_id"`
	RecipientDeviceID  string          `json:"recipient_device_id"`
	Payload            json.RawMessage `json:"payload"`
}

// batchResponse reports one outcome per submitted item, in the submitted
// order. Failures are per item and never fail the batch: one recipient at
// their queue cap must not cost the other group members their copy.
type batchResponse struct {
	Results []batchResultItem `json:"results"`
}

type batchResultItem struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

type messageResponse struct {
	MessageID       string          `json:"message_id"`
	SenderAccountID string          `json:"sender_account_id"`
	SenderDeviceID  string          `json:"sender_device_id"`
	SentAt          string          `json:"sent_at"`
	Payload         json.RawMessage `json:"payload"`
}

func messageResponseFrom(m store.Message) messageResponse {
	return messageResponse{
		MessageID:       m.MessageID,
		SenderAccountID: m.SenderAccountID,
		SenderDeviceID:  m.SenderDeviceID,
		SentAt:          m.SentAt.UTC().Format(time.RFC3339),
		Payload:         json.RawMessage(m.Payload),
	}
}

// federationDeviceCertDTO is the sending device's own certificate,
// carried inline since the recipient server has no local row to look one
// up from (see handleReceiveFederatedMessage).
type federationDeviceCertDTO struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pub_key"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
}

// federationMessageRequest is a cross-server message delivery: unlike
// sendMessageRequest (which relies on the caller already being a known,
// registered local device), this carries everything needed to verify the
// sender purely cryptographically -- no prior registration with this
// server required. See docs/PROTOCOL.md's federation section.
type federationMessageRequest struct {
	SenderAccountID    string                  `json:"sender_account_id"`
	SenderRootPubKey   string                  `json:"sender_root_pub_key"`
	SenderDeviceCert   federationDeviceCertDTO `json:"sender_device_cert"`
	RecipientAccountID string                  `json:"recipient_account_id"`
	RecipientDeviceID  string                  `json:"recipient_device_id"`
	MessageID          string                  `json:"message_id"`
	Payload            json.RawMessage         `json:"payload"`
}

// federationMessageBatchRequest is the federated twin of
// sendMessageBatchRequest. The sender's identity block appears once, at the
// top level, rather than per message -- which is the larger saving here: the
// certificate chain is verified once for the whole batch instead of N times.
type federationMessageBatchRequest struct {
	SenderAccountID  string                  `json:"sender_account_id"`
	SenderRootPubKey string                  `json:"sender_root_pub_key"`
	SenderDeviceCert federationDeviceCertDTO `json:"sender_device_cert"`
	Messages         []batchMessageItem      `json:"messages"`
}

func decodeBase64Key(s string, expectedLen int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectedLen, len(raw))
	}
	return raw, nil
}

func deviceResponseFrom(d store.Device) deviceResponse {
	resp := deviceResponse{
		DeviceID:     d.DeviceID,
		DevicePubKey: base64.StdEncoding.EncodeToString(d.DevicePubKey),
		IssuedAt:     d.CertIssuedAt.UTC().Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(d.CertSignature),
		Status:       d.Status,
	}
	if d.RevokedAt != nil {
		s := d.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}

func accountResponseFrom(acc *store.Account, devices []store.Device) accountResponse {
	resp := accountResponse{
		ID:         acc.ID,
		RootPubKey: base64.StdEncoding.EncodeToString(acc.RootPubKey),
		Devices:    make([]deviceResponse, 0, len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, deviceResponseFrom(d))
	}
	return resp
}

// blobUploadResponse is returned once an encrypted attachment has been
// stored (see blobs.go). The sender puts BlobID into the end-to-end
// encrypted message so the recipient can fetch it; ExpiresAt lets a client
// warn about (or re-upload) an attachment whose retention window is nearly
// up.
//
// Recipients reports one outcome per named device (SRV-18), the same shape
// batchResponse uses and for the same reason: one member at their quota must
// not cost the other group members their copy. BlobID and ExpiresAt are
// omitted when no recipient could be served, because then nothing was stored.
type blobUploadResponse struct {
	BlobID     string                `json:"blob_id,omitempty"`
	Size       int64                 `json:"size"`
	ExpiresAt  string                `json:"expires_at,omitempty"`
	Recipients []blobRecipientResult `json:"recipients"`
}

type blobRecipientResult struct {
	RecipientDeviceID string `json:"recipient_device_id"`
	Status            string `json:"status"`
}

// serverStatsResponse is the GET /v1/admin/stats payload: the server's
// current size and load. Deliberately never reachable from GET
// /v1/server-status or the landing page, for the same reason
// licenseStatusResponse isn't -- see stats.go's handler doc comment.
type serverStatsResponse struct {
	CapturedAt string `json:"captured_at"`

	AccountCount       int `json:"account_count"`
	ActiveAccountCount int `json:"active_account_count"`
	DeviceCount        int `json:"device_count"`

	BlobCount int   `json:"blob_count"`
	BlobBytes int64 `json:"blob_bytes"`
	DBBytes   int64 `json:"db_bytes"`

	PendingMessageCount int `json:"pending_message_count"`

	// DiskFreeBytes/DiskTotalBytes are both 0 when the host platform has no
	// way to report them wired up (internal/diskstat) -- a client should
	// read "0 and 0" as "unknown", not "completely full".
	DiskFreeBytes  int64 `json:"disk_free_bytes"`
	DiskTotalBytes int64 `json:"disk_total_bytes"`

	FederationEnabled         bool `json:"federation_enabled"`
	FederationBlocklistCount int  `json:"federation_blocklist_count"`
}

func serverStatsResponseFrom(s store.StatsSnapshot) serverStatsResponse {
	return serverStatsResponse{
		CapturedAt:               s.CapturedAt.UTC().Format(time.RFC3339),
		AccountCount:             s.AccountCount,
		ActiveAccountCount:       s.ActiveAccountCount,
		DeviceCount:              s.DeviceCount,
		BlobCount:                s.BlobCount,
		BlobBytes:                s.BlobBytes,
		DBBytes:                  s.DBBytes,
		PendingMessageCount:      s.PendingMessageCount,
		DiskFreeBytes:            s.DiskFreeBytes,
		DiskTotalBytes:           s.DiskTotalBytes,
		FederationEnabled:        s.FederationEnabled,
		FederationBlocklistCount: s.FederationBlocklistCount,
	}
}

// serverStatsPointResponse is one entry of GET /v1/admin/stats/history --
// the same fields as serverStatsResponse, kept as a separate type (rather
// than reusing it) so the two endpoints can diverge later without one's
// shape constraining the other.
type serverStatsPointResponse struct {
	CapturedAt string `json:"captured_at"`

	AccountCount       int `json:"account_count"`
	ActiveAccountCount int `json:"active_account_count"`
	DeviceCount        int `json:"device_count"`

	BlobCount int   `json:"blob_count"`
	BlobBytes int64 `json:"blob_bytes"`
	DBBytes   int64 `json:"db_bytes"`

	PendingMessageCount int `json:"pending_message_count"`

	DiskFreeBytes  int64 `json:"disk_free_bytes"`
	DiskTotalBytes int64 `json:"disk_total_bytes"`

	FederationEnabled         bool `json:"federation_enabled"`
	FederationBlocklistCount int  `json:"federation_blocklist_count"`
}

func serverStatsPointResponseFrom(s store.StatsSnapshot) serverStatsPointResponse {
	return serverStatsPointResponse{
		CapturedAt:               s.CapturedAt.UTC().Format(time.RFC3339),
		AccountCount:             s.AccountCount,
		ActiveAccountCount:       s.ActiveAccountCount,
		DeviceCount:              s.DeviceCount,
		BlobCount:                s.BlobCount,
		BlobBytes:                s.BlobBytes,
		DBBytes:                  s.DBBytes,
		PendingMessageCount:      s.PendingMessageCount,
		DiskFreeBytes:            s.DiskFreeBytes,
		DiskTotalBytes:           s.DiskTotalBytes,
		FederationEnabled:        s.FederationEnabled,
		FederationBlocklistCount: s.FederationBlocklistCount,
	}
}
