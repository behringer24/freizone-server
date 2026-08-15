package client

import "context"

// ServerStatus is what a server says about itself on `GET /v1/server-status`.
//
// This is where the project's standing compatibility rule lives in practice:
// availability is *discovered, never assumed*, because any combination of app
// and server version is in the field permanently. Every field here therefore
// has a documented meaning when the server did not send it -- and several of
// those defaults are not Go's zero value, which is the trap this type exists to
// close. Decoding straight into a plain struct would answer "does this server
// federate?" with false for every server old enough not to say.
type ServerStatus struct {
	// Claimed reports whether the server has an owner yet; a fresh one is
	// waiting to be bootstrapped.
	Claimed bool

	// RegistrationPolicy is "open", "invite" or "closed". A fourth value,
	// "community" (SRV-15), is planned but not shipped yet.
	RegistrationPolicy string

	// FederationEnabled defaults to TRUE when absent -- a server predating the
	// switch federates, and treating silence as "off" would strand every
	// conversation with one.
	FederationEnabled bool

	// BlobsEnabled and MaxBlobBytes describe attachment transport, so a sender
	// can size a picture to the *recipient* server's limit before uploading.
	// Absent means an older server without blob support.
	BlobsEnabled bool
	MaxBlobBytes int64

	// MaxBlobRecipients defaults to 1 when absent, NOT to unlimited. An older
	// server ignores the extra recipients, stores the blob for the first one
	// and still answers 201 -- so a sender assuming otherwise would silently
	// deliver a picture to exactly one member of a group and believe it had
	// reached everyone.
	MaxBlobRecipients int

	// BatchMessages and MaxBatchMessages describe batch delivery. Absent means
	// an older server and the documented fallback is posting each message on
	// its own, which is why groups already work against servers in the field.
	BatchMessages    bool
	MaxBatchMessages int

	// Attestation is an opaque pkg/attest token, served exactly as configured.
	// Empty means none. Verifying it is the caller's job and must be done
	// against the host actually being talked to, never the domain the token
	// names.
	Attestation string
}

// serverStatusWire mirrors the endpoint. Pointers wherever "absent" and the
// zero value mean different things, so the defaults above can be applied
// rather than guessed at.
type serverStatusWire struct {
	Claimed            bool   `json:"claimed"`
	RegistrationPolicy string `json:"registration_policy"`
	FederationEnabled  *bool  `json:"federation_enabled"`
	BlobsEnabled       bool   `json:"blobs_enabled"`
	MaxBlobBytes       int64  `json:"max_blob_bytes"`
	MaxBlobRecipients  *int   `json:"max_blob_recipients"`
	BatchMessages      bool   `json:"batch_messages"`
	MaxBatchMessages   int    `json:"max_batch_messages"`
	Attestation        string `json:"attestation"`
}

// ServerStatus fetches a server's capabilities. Pass an empty server for this
// account's own; pass another origin to discover a peer's before sending
// something it may not support.
//
// Unauthenticated on purpose: a sender has to be able to size an attachment
// for a server it has no account on.
func (c *Client) ServerStatus(ctx context.Context, server string) (ServerStatus, error) {
	var wire serverStatusWire
	if err := c.do(ctx, request{
		method: "GET",
		path:   "/v1/server-status",
		server: server,
		auth:   authNone,
	}, &wire); err != nil {
		return ServerStatus{}, err
	}
	return wire.resolve(), nil
}

// resolve applies each field's documented meaning-when-absent.
func (w serverStatusWire) resolve() ServerStatus {
	status := ServerStatus{
		Claimed:            w.Claimed,
		RegistrationPolicy: w.RegistrationPolicy,
		FederationEnabled:  true,
		BlobsEnabled:       w.BlobsEnabled,
		MaxBlobBytes:       w.MaxBlobBytes,
		MaxBlobRecipients:  1,
		BatchMessages:      w.BatchMessages,
		MaxBatchMessages:   w.MaxBatchMessages,
		Attestation:        w.Attestation,
	}
	if w.FederationEnabled != nil {
		status.FederationEnabled = *w.FederationEnabled
	}
	if w.MaxBlobRecipients != nil {
		status.MaxBlobRecipients = *w.MaxBlobRecipients
	}
	return status
}
