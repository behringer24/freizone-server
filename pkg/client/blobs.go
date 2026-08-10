package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// Attachments: the one part of a message the server stores, and the only part
// that outlives it.
//
// A blob is encrypted under its own key, generated per attachment and
// deliberately *not* derived from the ratchet. The key travels inside the
// message; the bytes travel separately and stay on the server until they
// expire. Deriving the key from the session instead would tie a picture to the
// session that announced it -- so resetting a secure session, or recovering
// from a desync, would make every picture already received undownloadable. A
// recovery mechanism that destroys history is not one.
//
// Everything here fails softly on the reading side. A missing blob costs its
// own picture and never the message around it: the sender may have deleted it,
// it may have expired, or the account it belonged to may have been removed
// outright -- and a caption that vanishes with its picture reads as delivery
// loss.

// ErrBlobUnavailable reports a blob the server will not serve: expired,
// deleted, or belonging to an account that no longer exists. Distinguished
// from a transport failure because it is permanent -- retrying is pointless,
// and the caller should show a placeholder rather than a spinner.
type ErrBlobUnavailable struct {
	BlobID string
	Err    error
}

func (e *ErrBlobUnavailable) Error() string {
	return fmt.Sprintf("client: attachment %s is no longer available: %v", e.BlobID, e.Err)
}

func (e *ErrBlobUnavailable) Unwrap() error { return e.Err }

// OutgoingMedia is a file on its way out, before it has a blob id.
type OutgoingMedia struct {
	Bytes    []byte
	MimeType string

	// Width and Height let a bubble reserve the right shape before the
	// download finishes, so a transcript does not jump as pictures land.
	Width, Height int

	// Thumb is a tiny preview carried *inside* the message rather than as a
	// blob, so something is visible the moment it arrives -- before, and even
	// without, the download. A kilobyte or so; anything larger belongs in the
	// blob.
	Thumb []byte

	// Kind is "image" today. Left open because an unknown kind must render as
	// a placeholder rather than break the message around it.
	Kind string
}

// UploadAttachment encrypts media and uploads it for the given recipient
// devices, returning what a message needs to carry to describe it.
//
// The recipient set is part of the upload rather than of the message: the
// server grants access per device, so a blob nobody was named for cannot be
// fetched by anybody. That is also why a group picture is uploaded once with
// every member's device listed instead of once per member.
func (c *Client) UploadAttachment(ctx context.Context, recipients []PeerEndpoint, media OutgoingMedia) (Attachment, error) {
	if len(recipients) == 0 {
		return Attachment{}, fmt.Errorf("client: an attachment needs at least one recipient device")
	}
	// Every recipient in one upload has to live on one server: the blob is
	// stored there, and the id it comes back with means nothing anywhere else.
	server := recipients[0].Server
	deviceIDs := make([]string, 0, len(recipients))
	for _, r := range recipients {
		if r.Server != server {
			return Attachment{}, fmt.Errorf("client: recipients for one attachment must share a server, %s and %s do not", recipients[0].AccountID, r.AccountID)
		}
		deviceIDs = append(deviceIDs, r.DeviceID)
	}

	key, ciphertext, digest, err := sealAttachment(media.Bytes)
	if err != nil {
		return Attachment{}, err
	}

	blobID, err := c.uploadBlob(ctx, server, deviceIDs, ciphertext, digest)
	if err != nil {
		return Attachment{}, err
	}

	kind := media.Kind
	if kind == "" {
		kind = "image"
	}
	return Attachment{
		Kind:      kind,
		Algorithm: blobAlgorithm,
		BlobID:    blobID,
		Key:       key,
		MimeType:  media.MimeType,
		ByteSize:  len(media.Bytes),
		Width:     media.Width,
		Height:    media.Height,
		Thumb:     media.Thumb,
	}, nil
}

// DownloadAttachment fetches and decrypts one attachment.
//
// server names a server other than this account's own only for the one
// legitimate case: an attachment on a group whose blob was uploaded
// (federated) to a *different* member's server rather than this account's.
// For an ordinary one-to-one attachment it is always empty -- a blob is
// uploaded to the *recipient's* own server (see UploadAttachment), precisely
// so the recipient never has to reach the sender's server to read something
// the sender sent. Passing the sender's server here for a one-to-one
// attachment sends the fetch, federated, to a server that was never handed
// the blob at all.
func (c *Client) DownloadAttachment(ctx context.Context, server string, att Attachment) ([]byte, error) {
	if att.Algorithm != "" && att.Algorithm != blobAlgorithm {
		// Named rather than assumed, so changing ciphers stays a data question
		// -- and so a build that meets a newer one says which it cannot read.
		return nil, fmt.Errorf("client: attachment %s uses %q, which this build cannot read", att.BlobID, att.Algorithm)
	}
	ciphertext, err := c.downloadBlob(ctx, server, att.BlobID)
	if err != nil {
		return nil, err
	}
	plaintext, err := openAttachment(att.Key, ciphertext)
	if err != nil {
		// The bytes arrived and will not open. Permanent for this copy, so it
		// is reported like an unavailable blob rather than as something a
		// retry might fix.
		return nil, &ErrBlobUnavailable{BlobID: att.BlobID, Err: err}
	}
	return plaintext, nil
}

// DeleteBlob removes an attachment we uploaded. Best effort by nature: the
// server expires blobs on its own, so failing to delete one costs storage
// somebody else is already accounting for.
func (c *Client) DeleteBlob(ctx context.Context, blobID string) error {
	return c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/v1/blobs/" + blobID,
		auth:   authDevice,
	}, nil)
}

const blobAlgorithm = "aes-256-gcm"

// sealAttachment encrypts plaintext under a fresh key, returning the key, the
// ciphertext and its digest.
//
// The digest is computed here because the upload signs over it rather than
// over the body (PROTOCOL.md §3's streamed variant), which is what lets a
// server authenticate a large upload before reading it -- and what makes
// hashing a multi-megabyte buffer twice unnecessary.
func sealAttachment(plaintext []byte) (key, ciphertext []byte, digest string, err error) {
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, "", fmt.Errorf("client: generating attachment key: %w", err)
	}
	gcm, err := blobAEAD(key)
	if err != nil {
		return nil, nil, "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, "", fmt.Errorf("client: generating attachment nonce: %w", err)
	}
	// Nonce prefixed to the ciphertext: it is not secret, and carrying it
	// inline keeps a blob a single self-contained byte string that needs
	// nothing but its key.
	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	sum := sha256.Sum256(ciphertext)
	return key, ciphertext, hex.EncodeToString(sum[:]), nil
}

// openAttachment reverses sealAttachment. A wrong key, a truncated blob or any
// tampering surfaces as an authentication failure rather than as garbage bytes.
func openAttachment(key, ciphertext []byte) ([]byte, error) {
	gcm, err := blobAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("client: attachment is shorter than its nonce")
	}
	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("client: attachment did not decrypt: %w", err)
	}
	return plaintext, nil
}

func blobAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("client: an attachment key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("client: creating attachment cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// uploadBlob posts raw ciphertext, signed over its digest.
//
// Deliberately not routed through [Client.do]: that path marshals a JSON body
// and signs over the bytes, and neither is right here. The body is opaque
// ciphertext, and signing it would mean holding and hashing the whole upload a
// second time.
func (c *Client) uploadBlob(ctx context.Context, server string, recipientDeviceIDs []string, ciphertext []byte, digest string) (string, error) {
	id, err := c.Identity()
	if err != nil {
		return "", err
	}

	target := id.Server
	path := "/v1/blobs"
	keyID := id.DeviceID
	federated := server != "" && server != id.Server
	if federated {
		// A federated sender has no device row on the target server, so it
		// identifies itself inline and names its key by the public key itself.
		target = server
		path = "/v1/federation/blobs"
		keyID = base64.StdEncoding.EncodeToString(id.DevicePub)
	}

	// Built by hand rather than with url.Values, so the order is ours and the
	// signed string is exactly what goes on the wire: the signature covers the
	// raw query, and the recipient set is part of it.
	params := make([]string, 0, len(recipientDeviceIDs))
	for _, deviceID := range recipientDeviceIDs {
		params = append(params, "recipient_device_id="+url.QueryEscape(deviceID))
	}
	rawQuery := strings.Join(params, "&")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+path+"?"+rawQuery, bytes.NewReader(ciphertext))
	if err != nil {
		return "", fmt.Errorf("client: building attachment upload: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+digest)
	if federated {
		if err := setFederatedSenderHeaders(req, id); err != nil {
			return "", err
		}
	}
	if err := signBodyDigest(req, http.MethodPost, path, rawQuery, keyID, digest, id); err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("client: uploading attachment: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("client: reading attachment upload response: %w", err)
	}
	// 201 for a single recipient, 200 for several: nothing is created at one
	// location when the outcomes differ per recipient.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", apiErrorFrom(resp.StatusCode, body)
	}

	var parsed struct {
		BlobID     string `json:"blob_id"`
		Recipients []struct {
			RecipientDeviceID string `json:"recipient_device_id"`
			Status            string `json:"status"`
		} `json:"recipients"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("client: decoding attachment upload response: %w", err)
	}
	if parsed.BlobID == "" {
		return "", fmt.Errorf("client: the server accepted the attachment without naming it")
	}
	return parsed.BlobID, nil
}

// downloadBlob fetches ciphertext by id.
func (c *Client) downloadBlob(ctx context.Context, server, blobID string) ([]byte, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}

	target := id.Server
	keyID := id.DeviceID
	federated := server != "" && server != id.Server
	if federated {
		target = server
		keyID = base64.StdEncoding.EncodeToString(id.DevicePub)
	}
	path := "/v1/blobs/" + blobID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+path, nil)
	if err != nil {
		return nil, fmt.Errorf("client: building attachment download: %w", err)
	}
	if federated {
		if err := setFederatedSenderHeaders(req, id); err != nil {
			return nil, err
		}
	}
	// A GET has no body, so the ordinary signature applies.
	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("client: generating request nonce: %w", err)
	}
	ts := time.Now()
	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature,
		httpsig.Sign(http.MethodGet, path, "", nil, keyID, ts, nonce, ed25519.PrivateKey(id.DevicePriv)))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: downloading attachment %s: %w", blobID, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: reading attachment %s: %w", blobID, err)
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	// Gone for good rather than temporarily unreachable, so the caller shows a
	// placeholder instead of retrying something that can never succeed.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil, &ErrBlobUnavailable{BlobID: blobID, Err: apiErrorFrom(resp.StatusCode, body)}
	}
	return nil, apiErrorFrom(resp.StatusCode, body)
}

// setFederatedSenderHeaders puts the self-certifying identity a foreign server
// needs into the headers, because a raw-ciphertext body has no room for it.
func setFederatedSenderHeaders(req *http.Request, id Identity) error {
	issuedAt := time.Now().UTC()
	sig, err := signDeviceCertificate(id, issuedAt)
	if err != nil {
		return err
	}
	req.Header.Set("Freizone-Sender-Account-Id", id.AccountID)
	req.Header.Set("Freizone-Sender-Root-Pub-Key", base64.StdEncoding.EncodeToString(id.RootPub))
	req.Header.Set("Freizone-Sender-Device-Id", id.DeviceID)
	req.Header.Set("Freizone-Sender-Device-Pub-Key", base64.StdEncoding.EncodeToString(id.DevicePub))
	req.Header.Set("Freizone-Sender-Cert-Issued-At", issuedAt.Format(time.RFC3339))
	req.Header.Set("Freizone-Sender-Cert-Signature", base64.StdEncoding.EncodeToString(sig))
	return nil
}

// signBodyDigest signs over the body's digest rather than the body, so the
// server can authenticate an upload before reading it.
func signBodyDigest(req *http.Request, method, path, rawQuery, keyID, digest string, id Identity) error {
	nonce, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("client: generating request nonce: %w", err)
	}
	ts := time.Now()
	canonical := httpsig.CanonicalStringWithBodyDigest(
		method, path, rawQuery, httpsig.FormatTimestamp(ts), nonce, keyID, digest)
	sig := base64.StdEncoding.EncodeToString(
		ed25519.Sign(ed25519.PrivateKey(id.DevicePriv), []byte(canonical)))

	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)
	return nil
}
