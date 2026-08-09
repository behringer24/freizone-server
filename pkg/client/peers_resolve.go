package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// Turning an address someone typed into a device that can actually be
// encrypted to.
//
// Everything here is verified against the peer's own root key rather than
// trusted from the server that served it. That matters most for a federated
// peer, where the answer comes from a server nobody here has any reason to
// trust -- but it is done identically for a local one, because a rule applied
// only to strangers is a rule nobody exercises.

// PeerEndpoint is one device to deliver to, with everything needed to verify
// what it sends back.
type PeerEndpoint struct {
	AccountID string

	// Server is the peer's home server, empty when it is our own. That
	// emptiness is load-bearing rather than a convenience: it selects
	// federated delivery and federated authentication throughout the send
	// path, so a peer on our own server never takes the federation route.
	Server string

	DeviceID string

	// DevicePub is the Ed25519 key every certificate from this device is
	// checked against -- the prekey bundle's, and by extension the identity
	// behind every message it sends.
	DevicePub []byte
}

// Federated reports whether reaching this peer leaves our own server.
func (p PeerEndpoint) Federated() bool { return p.Server != "" }

type accountWire struct {
	ID         string       `json:"id"`
	RootPubKey string       `json:"root_pubkey"`
	Devices    []deviceWire `json:"devices"`
}

type deviceWire struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
	Status       string `json:"status"`
}

// ResolvePeer looks an account up and picks a device to talk to.
//
// addressOrPrefix is whatever the user typed: a full address, or the prefix a
// server will complete. server names where to ask, empty for our own.
//
// Two checks, and neither is optional. The account id must be derivable from
// the root key it came with, or the server handed us somebody else's account
// under the name we asked for. Each device's certificate must verify against
// that root key, or the server added a device the account holder never signed
// -- which is exactly how a server would read its users' messages if it could.
func (c *Client) ResolvePeer(ctx context.Context, addressOrPrefix, server string) (PeerEndpoint, error) {
	normalised, err := address.Normalize(addressOrPrefix)
	if err != nil {
		// Not an address at all -- but a prefix is legitimate here, so this is
		// passed on for the server to complete rather than rejected.
		normalised = addressOrPrefix
	}

	var acc accountWire
	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/v1/accounts/" + normalised,
		server: server,
		auth:   authNone,
	}, &acc); err != nil {
		return PeerEndpoint{}, err
	}

	rootPub, err := base64.StdEncoding.DecodeString(acc.RootPubKey)
	if err != nil {
		return PeerEndpoint{}, fmt.Errorf("client: decoding %s's root key: %w", acc.ID, err)
	}
	ok, err := address.Verify(acc.ID, rootPub)
	if err != nil {
		return PeerEndpoint{}, fmt.Errorf("client: checking %s against its root key: %w", acc.ID, err)
	}
	if !ok {
		return PeerEndpoint{}, fmt.Errorf("client: %s does not match the root key it was served with", acc.ID)
	}

	for _, d := range acc.Devices {
		if d.Status != "active" {
			continue
		}
		devicePub, err := base64.StdEncoding.DecodeString(d.DevicePubKey)
		if err != nil {
			continue // a device we cannot read is a device we cannot verify
		}
		issuedAt, err := time.Parse(time.RFC3339, d.IssuedAt)
		if err != nil {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(d.Signature)
		if err != nil {
			continue
		}
		cert := &devicecert.DeviceCertificate{
			AccountID:    acc.ID,
			DeviceID:     d.DeviceID,
			DevicePubKey: devicePub,
			IssuedAt:     issuedAt,
			Signature:    sig,
		}
		if cert.Verify(ed25519.PublicKey(rootPub)) != nil {
			continue
		}
		return PeerEndpoint{AccountID: acc.ID, Server: server, DeviceID: d.DeviceID, DevicePub: devicePub}, nil
	}
	return PeerEndpoint{}, fmt.Errorf("client: %s has no active device with a certificate that verifies", acc.ID)
}

// Endpoint returns where to reach peer, using what the conversation already
// remembers and resolving only when it has to.
//
// The device id is cached because resolving costs a round trip on every single
// message otherwise. Nothing invalidates that cache on its own -- no server
// propagates a device revocation or an account being re-created (PROTOCOL.md
// §9) -- so the send path heals it instead: the send that trips over a dead id
// is the one that forgets it. See [Client.ForgetPeerDevice].
func (c *Client) Endpoint(ctx context.Context, peer string) (PeerEndpoint, error) {
	var server string
	convo, err := c.Conversation(peer)
	if err != nil {
		return PeerEndpoint{}, err
	}
	if convo != nil {
		server = convo.PeerServer
	}
	return c.endpointOn(ctx, peer, server)
}

// endpointOn is [Client.Endpoint] with the home server supplied rather than
// looked up -- what a group member is addressed by, since the fact set records
// where each of them lives and there may be no conversation at all.
func (c *Client) endpointOn(ctx context.Context, peer, server string) (PeerEndpoint, error) {
	cached, err := c.peerDevice(peer)
	if err != nil {
		return PeerEndpoint{}, err
	}
	if cached != nil && cached.DeviceID != "" && len(cached.DevicePub) > 0 {
		if server == "" {
			server = cached.Server
		}
		return PeerEndpoint{AccountID: peer, Server: server, DeviceID: cached.DeviceID, DevicePub: cached.DevicePub}, nil
	}

	endpoint, err := c.ResolvePeer(ctx, peer, server)
	if err != nil {
		return PeerEndpoint{}, err
	}
	return endpoint, c.putPeerDevice(endpoint)
}

// peerDeviceFile is the cached answer to "which device of theirs do we talk
// to", and the key their certificates are checked against.
type peerDeviceFile struct {
	Server    string `json:"server,omitempty"`
	DeviceID  string `json:"device_id"`
	DevicePub []byte `json:"device_pub_key"`
}

func (c *Client) peerDevice(peer string) (*peerDeviceFile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.peerPath(peer, fileDevice)
	if err != nil {
		return nil, err
	}
	var stored peerDeviceFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}
	return &stored, nil
}

func (c *Client) putPeerDevice(endpoint PeerEndpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.peerPath(endpoint.AccountID, fileDevice)
	if err != nil {
		return err
	}
	return writeJSON(path, peerDeviceFile{
		Server: endpoint.Server, DeviceID: endpoint.DeviceID, DevicePub: endpoint.DevicePub,
	})
}

// StartConversation resolves an address the user has entered and creates the
// local conversation for it.
//
// The peer is marked known by this, which is what separates a conversation the
// user opened from one that opened itself: a stranger's first message creates a
// conversation awaiting approval, and reaching out to somebody is that approval
// already given. Without it, answering a message you initiated would arrive as
// a request from a stranger.
//
// Nothing is sent. Establishing the session happens on the first message,
// because that is when there is something to put a prekey block on -- and a
// conversation opened and then abandoned should not have claimed one of the
// peer's one-time prekeys.
func (c *Client) StartConversation(ctx context.Context, addressOrPrefix, server string) (Conversation, error) {
	endpoint, err := c.ResolvePeer(ctx, addressOrPrefix, server)
	if err != nil {
		return Conversation{}, err
	}

	// An existing conversation is refreshed rather than replaced: it may hold
	// a transcript, a block, or receipt watermarks, and "start a conversation"
	// with someone already in the list means open it, not reset it.
	existing, err := c.Conversation(endpoint.AccountID)
	if err != nil {
		return Conversation{}, err
	}
	convo := Conversation{PeerAccountID: endpoint.AccountID}
	if existing != nil {
		convo = *existing
	}
	convo.PeerServer = endpoint.Server
	convo.PendingApproval = false

	if err := c.putPeerDevice(endpoint); err != nil {
		return Conversation{}, err
	}
	if err := c.MarkPeerKnown(endpoint.AccountID); err != nil {
		return Conversation{}, err
	}
	if err := c.PutConversation(convo); err != nil {
		return Conversation{}, err
	}
	return convo, nil
}

// ForgetPeerDevice drops the cached device for peer, along with the session
// bound to it.
//
// Both, and that is the point: a session is keyed to the device that
// established it, so keeping one for a device that no longer exists means the
// next send re-resolves and then encrypts to a stranger's ratchet. The pair is
// discarded together or not at all.
func (c *Client) ForgetPeerDevice(peer string) error {
	c.mu.Lock()
	path, err := c.store.peerPath(peer, fileDevice)
	if err == nil {
		err = removeFile(path)
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.DeleteSession(peer, Sending); err != nil {
		return err
	}
	return c.DeleteSession(peer, Inbound)
}
