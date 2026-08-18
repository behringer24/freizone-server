package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// Bringing an account into existence.
//
// This lived in three places before it lived here: cmd/devclient's own
// identity.go, this package's live-server test helper -- which did a raw
// http.Post with the comment "the core offers nothing" -- and freizone-app.
// Three copies of the one operation that decides an account's permanent
// identity is exactly the shape SRV-23 exists to end.
//
// # Why the keys are written before the request
//
// Registration is not idempotent, and the failure is nasty in a way that only
// shows up in production. The server creates the account when it answers 201;
// the caller learns the account exists when it *reads* that answer. A crash,
// a dropped connection or a killed container in between leaves an account on
// the server that the caller has no record of -- and a naive retry generates
// fresh keys, registers a *second* account, consumes a second invite code, and
// comes back with a different address from the one anybody was told about.
//
// So the keys are generated and persisted first, with a marker saying a
// registration is in flight. A later attempt finds the marker, derives the
// account id from the stored root key -- which is what an account id *is*, a
// derivation of that key -- and asks the server whether it exists. Present
// means the registration did land and only the acknowledgement was lost;
// absent means retry, with the same keys, so the address never moves.

// ErrAlreadyRegistered reports an attempt to register into an account
// directory that already holds a finished identity. Registering again would
// abandon the account it already has, which is never what a caller meant.
var ErrAlreadyRegistered = errors.New("client: this account directory already holds an identity")

// RegisterOptions carry whatever the server's registration policy requires.
// The zero value is a registration on a server whose policy is `open`.
type RegisterOptions struct {
	// InviteCode is required when the policy is `invite`, and ignored when it
	// is `open`. A caller that does not know the policy can read it from
	// [Client.ServerStatus] rather than discovering it as a refusal.
	InviteCode string
}

// Register creates this account on server and stores the identity it produced.
//
// Safe to call again after a failure: an interrupted attempt is resumed rather
// than restarted, so a crash between the request and its answer cannot leave a
// second, orphaned account behind. Reports [ErrAlreadyRegistered] once there is
// a finished identity here, since that is a caller mistake rather than a state
// to recover from.
//
// Registering does not publish prekeys. That is [Client.RotatePrekeys] and
// [Client.TopUpOneTimePrekeys], kept separate because they are also what a
// long-lived account does periodically, and folding them in here would make
// the first run silently different from every run after it.
func (c *Client) Register(ctx context.Context, server string, opts RegisterOptions) (Identity, error) {
	return c.claim(ctx, server, "/v1/accounts", func(id Identity, cert *devicecert.DeviceCertificate) any {
		body := registerBody{
			RootPubKey:          base64.StdEncoding.EncodeToString(id.RootPub),
			DeviceID:            id.DeviceID,
			DevicePubKey:        base64.StdEncoding.EncodeToString(id.DevicePub),
			DeviceCertIssuedAt:  cert.IssuedAt.Format(time.RFC3339),
			DeviceCertSignature: base64.StdEncoding.EncodeToString(cert.Signature),
		}
		if opts.InviteCode != "" {
			code := opts.InviteCode
			body.InviteCode = &code
		}
		return body
	})
}

// ClaimServer registers this account *and* makes it the server's first
// administrator, using the setup token an unclaimed server prints at startup.
//
// Deliberately its own call rather than an option on [Client.Register]: the two
// differ in what they do to the *server*, not in how they are configured, and
// a caller should not be able to claim a server by filling in one more field.
// Whether a server is still unclaimed is on [Client.ServerStatus].
func (c *Client) ClaimServer(ctx context.Context, server, setupToken string) (Identity, error) {
	if setupToken == "" {
		return Identity{}, fmt.Errorf("client: claiming a server needs its setup token")
	}
	return c.claim(ctx, server, "/v1/bootstrap/claim", func(id Identity, cert *devicecert.DeviceCertificate) any {
		return bootstrapBody{
			SetupToken:          setupToken,
			RootPubKey:          base64.StdEncoding.EncodeToString(id.RootPub),
			DeviceID:            id.DeviceID,
			DevicePubKey:        base64.StdEncoding.EncodeToString(id.DevicePub),
			DeviceCertIssuedAt:  cert.IssuedAt.Format(time.RFC3339),
			DeviceCertSignature: base64.StdEncoding.EncodeToString(cert.Signature),
		}
	})
}

// claim is the shared body of both: settle what identity to use, make sure it
// is on disk, post, and take the marker down.
func (c *Client) claim(ctx context.Context, server, path string, bodyFor func(Identity, *devicecert.DeviceCertificate) any) (Identity, error) {
	if server == "" {
		return Identity{}, fmt.Errorf("client: registering needs a server address")
	}

	id, pending, err := c.identityToRegister(server)
	if err != nil {
		return Identity{}, err
	}

	// A resumed attempt asks the one question that settles it before spending
	// another invite code: does this account already exist over there?
	if pending {
		switch exists, err := c.accountExists(ctx, server, id.AccountID); {
		case err != nil:
			return Identity{}, err
		case exists:
			// The account landed; only the answer was lost. Nothing to send.
			return id, c.finishRegistration()
		}
	}

	cert, err := devicecert.SignDeviceCertificate(
		id.AccountID, id.DeviceID, id.DevicePub,
		time.Now().UTC().Truncate(time.Second), id.RootPriv,
	)
	if err != nil {
		return Identity{}, fmt.Errorf("client: signing the device certificate: %w", err)
	}

	// authNone: registration is the one call that cannot be authenticated,
	// since the credentials it would use are what it exists to create.
	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   path,
		server: server,
		body:   bodyFor(id, cert),
		auth:   authNone,
	}, nil); err != nil {
		return Identity{}, err
	}
	return id, c.finishRegistration()
}

// identityToRegister returns the identity to register with, generating one on
// the first attempt and reusing the stored one on a resumed attempt. The bool
// reports whether a previous attempt was already in flight.
func (c *Client) identityToRegister(server string) (Identity, bool, error) {
	switch existing, err := c.Identity(); {
	case err == nil:
		// A finished identity, or an interrupted attempt's. The marker is what
		// tells them apart.
		pending, perr := c.registrationPending()
		if perr != nil {
			return Identity{}, false, perr
		}
		if !pending {
			return Identity{}, false, ErrAlreadyRegistered
		}
		if existing.Server != server {
			return Identity{}, false, fmt.Errorf(
				"client: a registration on %s was interrupted here; finish or clear it before registering on %s",
				existing.Server, server)
		}
		return existing, true, nil
	case !errors.Is(err, ErrNoIdentity):
		return Identity{}, false, err
	}

	id, err := NewIdentity(server)
	if err != nil {
		return Identity{}, false, err
	}
	// Marker first, then the identity: a crash between the two must look like
	// an interrupted registration, never like a finished one.
	if err := c.markRegistrationPending(); err != nil {
		return Identity{}, false, err
	}
	if err := c.SetIdentity(id); err != nil {
		return Identity{}, false, err
	}
	return id, false, nil
}

// NewIdentity generates the keys and ids one account is, without registering
// anything: a root key, a device key, a device id, and the account id derived
// from the root public key.
//
// Exported because an account id is a derivation rather than an assignment,
// so a caller can know its own address before any server has heard of it.
func NewIdentity(server string) (Identity, error) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("client: generating the root key: %w", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("client: generating the device key: %w", err)
	}
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		return Identity{}, fmt.Errorf("client: generating the device id: %w", err)
	}
	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		return Identity{}, fmt.Errorf("client: deriving the account id: %w", err)
	}
	return Identity{
		AccountID:  accountID,
		Server:     server,
		RootPub:    rootPub,
		RootPriv:   rootPriv,
		DeviceID:   deviceID,
		DevicePub:  devicePub,
		DevicePriv: devicePriv,
	}, nil
}

// accountExists asks the public account directory whether an account is there.
// Unauthenticated, like every other read of that directory.
func (c *Client) accountExists(ctx context.Context, server, accountID string) (bool, error) {
	err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/v1/accounts/" + accountID,
		server: server,
		auth:   authNone,
	}, nil)
	if err == nil {
		return true, nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	// Anything else -- unreachable, refused, not a Freizone server -- says
	// nothing about the account, and guessing here is what would spend a
	// second invite code.
	return false, err
}

func (c *Client) registrationPending() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.pendingPath()
	if err != nil {
		return false, err
	}
	switch _, err := os.Stat(path); {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("client: reading the registration marker: %w", err)
	}
}

func (c *Client) markRegistrationPending() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.pendingPath()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, []byte("registration in flight\n"))
}

func (c *Client) finishRegistration() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.pendingPath()
	if err != nil {
		return err
	}
	return removeFile(path)
}

// The wire bodies. Named here rather than shared with internal/api on purpose:
// this package is what a third-party client would read to implement the
// protocol, and it must not depend on the server's own internals.
type registerBody struct {
	RootPubKey          string  `json:"root_pubkey"`
	DeviceID            string  `json:"device_id"`
	DevicePubKey        string  `json:"device_pubkey"`
	DeviceCertIssuedAt  string  `json:"device_cert_issued_at"`
	DeviceCertSignature string  `json:"device_cert_signature"`
	InviteCode          *string `json:"invite_code,omitempty"`
}

type bootstrapBody struct {
	SetupToken          string `json:"setup_token"`
	RootPubKey          string `json:"root_pubkey"`
	DeviceID            string `json:"device_id"`
	DevicePubKey        string `json:"device_pubkey"`
	DeviceCertIssuedAt  string `json:"device_cert_issued_at"`
	DeviceCertSignature string `json:"device_cert_signature"`
}
