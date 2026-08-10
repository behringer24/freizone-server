package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// The one-time prekey lifecycle: keeping a pool on the server so somebody can
// start a conversation with this device while it is switched off, and claiming
// one from a peer to start theirs.
//
// The pool is what gives a first message forward secrecy. An empty pool does
// not fail -- the server serves a bundle without one and the session starts on
// the signed prekey alone -- it silently starts weaker. That silence is why
// topping up runs on a schedule rather than on demand.

const (
	// OneTimePrekeyBatch is how many keys a top-up brings the pool back to.
	OneTimePrekeyBatch = 10

	// OneTimePrekeyLowWaterMark is how low the pool is allowed to get first.
	// Comfortably above the server's own threshold, which exists only as a
	// fallback wake for a device that is not checking on its own: a device in
	// regular use should top up before the server ever has to ask.
	OneTimePrekeyLowWaterMark = 3
)

type dhIdentityCertWire struct {
	DHPubKey  string `json:"dh_pubkey"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type signedPrekeyWire struct {
	KeyID            uint32 `json:"key_id"`
	DHIdentityPubKey string `json:"dh_identity_pubkey"`
	PubKey           string `json:"pubkey"`
	IssuedAt         string `json:"issued_at"`
	Signature        string `json:"signature"`
}

type oneTimePrekeyWire struct {
	KeyID  uint32 `json:"key_id"`
	PubKey string `json:"pubkey"`
}

type uploadPrekeysBody struct {
	DHIdentityCert *dhIdentityCertWire `json:"dh_identity_cert,omitempty"`
	SignedPrekey   signedPrekeyWire    `json:"signed_prekey"`
	OneTimePrekeys []oneTimePrekeyWire `json:"one_time_prekeys,omitempty"`

	// ReplaceOneTimePrekeys asks the server to discard every unclaimed
	// one-time prekey it currently holds for this device before adding
	// OneTimePrekeys, instead of appending to them -- see
	// [Client.PurgeAndReplaceOneTimePrekeys].
	ReplaceOneTimePrekeys bool `json:"replace_one_time_prekeys,omitempty"`
}

type prekeyBundleWire struct {
	DeviceID         string             `json:"device_id"`
	DHIdentityPubKey string             `json:"dh_identity_pubkey"`
	DHIdentityCert   dhIdentityCertWire `json:"dh_identity_cert"`
	SignedPrekey     signedPrekeyWire   `json:"signed_prekey"`
	OneTimePrekey    *oneTimePrekeyWire `json:"one_time_prekey,omitempty"`

	// OneTimePrekeyOmitted says why there is no one-time prekey, when there is
	// none. "unauthenticated" is the one worth acting on -- see
	// [Bundle.ClaimedUnauthenticated].
	OneTimePrekeyOmitted string `json:"one_time_prekey_omitted,omitempty"`
}

// Bundle is verified X3DH material for one peer device.
type Bundle struct {
	ratchet.RemoteBundle

	// ClaimedUnauthenticated: the server refused our credentials and answered
	// anyway, withholding the one-time prekey.
	//
	// Never expected, because every claim this package makes is signed. So it
	// means our own credentials were rejected -- a clock far out of skew, a
	// revoked device, a stale certificate -- and the session about to be built
	// is quietly starting weaker than it should. Reported rather than refused:
	// a working conversation is worth more than one message's forward secrecy,
	// but a permanent silent downgrade is worth neither.
	ClaimedUnauthenticated bool
}

// RotatePrekeys mints a new signed prekey and a full batch of one-time
// prekeys, and publishes them.
//
// This is the deliberate rotation: registration, restoring an account onto a
// new device, or a user asking for fresh key material. It is *not* what runs
// periodically -- see [Client.TopUpOneTimePrekeys], which re-asserts the
// existing signed prekey instead. Rotating on every top-up would replace the
// key peers are mid-establishment against, several times a day, for nothing.
//
// A DH identity key is minted only if this account has none, and never
// replaced: it is the long-term half of X3DH, and every session ever
// established with this device is bound to it.
func (c *Client) RotatePrekeys(ctx context.Context) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	curve := ecdh.X25519()

	var dhCert *dhIdentityCertWire
	if len(id.DHIdentityPriv) == 0 {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("client: generating dh identity key: %w", err)
		}
		cert, err := devicecert.SignDHIdentityCertificate(
			id.AccountID, id.DeviceID, priv.PublicKey().Bytes(), now, ed25519.PrivateKey(id.DevicePriv))
		if err != nil {
			return fmt.Errorf("client: signing dh identity certificate: %w", err)
		}
		id.DHIdentityPub = priv.PublicKey().Bytes()
		id.DHIdentityPriv = priv.Bytes()
		dhCert = &dhIdentityCertWire{
			DHPubKey:  base64.StdEncoding.EncodeToString(cert.DHPubKey),
			IssuedAt:  cert.IssuedAt.Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(cert.Signature),
		}
	}

	spkPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("client: generating signed prekey: %w", err)
	}
	keyID := id.NextSignedPrekeyID
	id.NextSignedPrekeyID++
	id.SignedPrekeyID = keyID
	id.SignedPrekeyPub = spkPriv.PublicKey().Bytes()
	id.SignedPrekeyPriv = spkPriv.Bytes()

	spk, err := c.signedPrekeyWireFor(id, now)
	if err != nil {
		return err
	}
	fresh, err := c.mintOneTimePrekeys(&id, OneTimePrekeyBatch)
	if err != nil {
		return err
	}

	// Written before the upload, not after. A key the server has and this
	// device has forgotten is unusable for good -- a peer claims it, builds a
	// session, and nothing here can open the result. The reverse costs
	// nothing: a key this device holds and the server never published is
	// simply never claimed.
	if err := c.SetIdentity(id); err != nil {
		return err
	}
	return c.uploadPrekeys(ctx, id, uploadPrekeysBody{
		DHIdentityCert: dhCert,
		SignedPrekey:   spk,
		OneTimePrekeys: fresh,
	})
}

// TopUpOneTimePrekeys refills the pool if the server says it has run low.
//
// Deliberately asks the server rather than counting locally: the server is the
// one handing keys out, and a local count only knows about the ones this
// device has consumed by receiving. A device that is claimed from while
// offline learns nothing until it asks.
//
// The signed prekey is re-signed with the *same* key material every time. The
// endpoint requires one and replaces whatever is on file, so leaving it out is
// not an option -- but re-asserting is not rotating, and the difference is the
// whole reason this is a separate call.
func (c *Client) TopUpOneTimePrekeys(ctx context.Context) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	if len(id.SignedPrekeyPub) == 0 {
		// Nothing published yet -- rotating is the right call, not topping up.
		return nil
	}
	now := time.Now().UTC()

	remaining, err := c.RemainingOneTimePrekeys(ctx)
	if err != nil {
		return err
	}

	var fresh []oneTimePrekeyWire
	if remaining < OneTimePrekeyLowWaterMark {
		if fresh, err = c.mintOneTimePrekeys(&id, OneTimePrekeyBatch-remaining); err != nil {
			return err
		}
		if err := c.SetIdentity(id); err != nil {
			return err
		}
	}

	dhCert, err := devicecert.SignDHIdentityCertificate(
		id.AccountID, id.DeviceID, id.DHIdentityPub, now, ed25519.PrivateKey(id.DevicePriv))
	if err != nil {
		return fmt.Errorf("client: re-signing dh identity certificate: %w", err)
	}
	spk, err := c.signedPrekeyWireFor(id, now)
	if err != nil {
		return err
	}
	return c.uploadPrekeys(ctx, id, uploadPrekeysBody{
		DHIdentityCert: &dhIdentityCertWire{
			DHPubKey:  base64.StdEncoding.EncodeToString(dhCert.DHPubKey),
			IssuedAt:  dhCert.IssuedAt.Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(dhCert.Signature),
		},
		SignedPrekey:   spk,
		OneTimePrekeys: fresh,
	})
}

// PurgeAndReplaceOneTimePrekeys discards this device's entire published
// one-time-prekey pool and republishes a fresh batch, replacing rather than
// adding to it.
//
// For the one situation [Client.TopUpOneTimePrekeys] cannot fix on its own:
// the published pool already contains an id this device's store has no
// private half for (SRV-23's Dart-side and core-side minting once running
// side by side left exactly this on every account that talked to anyone
// before the cut finished). Topping up only ever adds more on top -- the
// server hands out the *oldest* unclaimed key first (see
// store.ClaimOneTimePrekey), so a poisoned entry would still be claimed
// before any fresh addition ever is, no matter how many more get added.
// Only an actual replace fixes it.
//
// Safe to call at any time, whether or not the pool is actually poisoned:
// every id being discarded is, by definition, unclaimed (a claim deletes
// atomically the moment it happens), so nothing has ever been built against
// any of them.
func (c *Client) PurgeAndReplaceOneTimePrekeys(ctx context.Context) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	if len(id.SignedPrekeyPub) == 0 {
		// Nothing published yet -- rotating is the right call, not this.
		return nil
	}
	now := time.Now().UTC()

	fresh, err := c.mintOneTimePrekeys(&id, OneTimePrekeyBatch)
	if err != nil {
		return err
	}
	// Written before the upload, not after -- same reasoning as
	// RotatePrekeys: a key the server ends up with that this device has
	// forgotten is unusable for good.
	if err := c.SetIdentity(id); err != nil {
		return err
	}

	dhCert, err := devicecert.SignDHIdentityCertificate(
		id.AccountID, id.DeviceID, id.DHIdentityPub, now, ed25519.PrivateKey(id.DevicePriv))
	if err != nil {
		return fmt.Errorf("client: re-signing dh identity certificate: %w", err)
	}
	spk, err := c.signedPrekeyWireFor(id, now)
	if err != nil {
		return err
	}
	return c.uploadPrekeys(ctx, id, uploadPrekeysBody{
		DHIdentityCert: &dhIdentityCertWire{
			DHPubKey:  base64.StdEncoding.EncodeToString(dhCert.DHPubKey),
			IssuedAt:  dhCert.IssuedAt.Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(dhCert.Signature),
		},
		SignedPrekey:          spk,
		OneTimePrekeys:        fresh,
		ReplaceOneTimePrekeys: true,
	})
}

// RemainingOneTimePrekeys is how many keys the server still holds for this
// device. Reading it consumes nothing, unlike claiming a bundle.
func (c *Client) RemainingOneTimePrekeys(ctx context.Context) (int, error) {
	id, err := c.Identity()
	if err != nil {
		return 0, err
	}
	var status struct {
		Remaining int `json:"one_time_prekeys_remaining"`
	}
	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/v1/devices/" + id.DeviceID + "/prekey-status",
		auth:   authDevice,
	}, &status); err != nil {
		return 0, err
	}
	return status.Remaining, nil
}

// mintOneTimePrekeys generates count keys, stores them, and returns the public
// halves to publish. Mutates id's allocation counter; the caller persists it.
func (c *Client) mintOneTimePrekeys(id *Identity, count int) ([]oneTimePrekeyWire, error) {
	if count <= 0 {
		return nil, nil
	}
	curve := ecdh.X25519()
	keys := make([]OneTimePrekey, 0, count)
	wires := make([]oneTimePrekeyWire, 0, count)
	for i := 0; i < count; i++ {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("client: generating one-time prekey: %w", err)
		}
		keyID := id.NextOneTimePrekeyID
		id.NextOneTimePrekeyID++
		keys = append(keys, OneTimePrekey{KeyID: keyID, Pub: priv.PublicKey().Bytes(), Priv: priv.Bytes()})
		wires = append(wires, oneTimePrekeyWire{KeyID: keyID, PubKey: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())})
	}
	if err := c.PutOneTimePrekeys(keys); err != nil {
		return nil, err
	}
	return wires, nil
}

func (c *Client) signedPrekeyWireFor(id Identity, now time.Time) (signedPrekeyWire, error) {
	cert, err := devicecert.SignSignedPrekeyCertificate(
		id.AccountID, id.DeviceID, id.SignedPrekeyID, id.DHIdentityPub, id.SignedPrekeyPub, now, ed25519.PrivateKey(id.DevicePriv))
	if err != nil {
		return signedPrekeyWire{}, fmt.Errorf("client: signing signed prekey certificate: %w", err)
	}
	return signedPrekeyWire{
		KeyID:            cert.KeyID,
		DHIdentityPubKey: base64.StdEncoding.EncodeToString(cert.DHIdentityPubKey),
		PubKey:           base64.StdEncoding.EncodeToString(cert.PrekeyPubKey),
		IssuedAt:         cert.IssuedAt.Format(time.RFC3339),
		Signature:        base64.StdEncoding.EncodeToString(cert.Signature),
	}, nil
}

func (c *Client) uploadPrekeys(ctx context.Context, id Identity, body uploadPrekeysBody) error {
	return c.do(ctx, request{
		method: http.MethodPost,
		path:   "/v1/devices/" + id.DeviceID + "/prekeys",
		auth:   authDevice,
		body:   body,
	}, nil)
}

// ClaimBundle fetches the X3DH material needed to start a session with peer,
// verified against that device's own signing key.
//
// Always authenticated, in whichever of the two forms applies: an ordinary
// signed request for a peer on our own server, and a self-certifying claim for
// a foreign one, which has no local row to look a device id up in. Without
// either the server still answers -- but withholds the one-time prekey,
// silently costing this session forward secrecy on its first message. Which is
// exactly why an unauthenticated answer is reported rather than accepted
// quietly; see [Bundle.ClaimedUnauthenticated].
func (c *Client) ClaimBundle(ctx context.Context, peer PeerEndpoint) (Bundle, error) {
	id, err := c.Identity()
	if err != nil {
		return Bundle{}, err
	}

	req := request{
		method: http.MethodPost,
		path:   "/v1/devices/" + peer.DeviceID + "/prekey-bundle",
		auth:   authDevice,
	}
	if peer.Federated() {
		// Shares signDeviceCert with postEnvelope/sendGroupControl rather than
		// building this shape a second time: this exact duplication is why the
		// "device_pub_key" field name (PROTOCOL.md §9, deliberately not the
		// "device_pubkey" every other identity block uses) drifted to
		// "device_pubkey" here and went unnoticed -- a claim is a request, not
		// a send, so a wrong response here read as "no one-time prekey
		// offered" rather than a visible failure.
		cert, err := signDeviceCert(id, time.Now().UTC())
		if err != nil {
			return Bundle{}, err
		}
		req.server = peer.Server
		req.auth = authFederated
		req.body = map[string]any{
			"sender_account_id":   id.AccountID,
			"sender_root_pub_key": base64.StdEncoding.EncodeToString(id.RootPub),
			"sender_device_cert":  cert,
		}
	}

	var bundle prekeyBundleWire
	if err := c.do(ctx, req, &bundle); err != nil {
		return Bundle{}, err
	}
	remote, err := verifyBundle(bundle, peer)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		RemoteBundle:           remote,
		ClaimedUnauthenticated: bundle.OneTimePrekeyOmitted == "unauthenticated",
	}, nil
}

// verifyBundle checks both certificates against the peer device's signing key
// and converts what is left into X3DH material.
//
// The certificates are the whole point of the exercise. A prekey bundle comes
// from a server -- often somebody else's -- and without verifying it, that
// server chooses the keys a session is built on, which is a working
// man-in-the-middle rather than a theoretical one.
func verifyBundle(b prekeyBundleWire, peer PeerEndpoint) (ratchet.RemoteBundle, error) {
	curve := ecdh.X25519()
	devicePub := ed25519.PublicKey(peer.DevicePub)

	dhPub, err := base64.StdEncoding.DecodeString(b.DHIdentityPubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding %s's dh identity key: %w", peer.AccountID, err)
	}
	dhIssuedAt, err := time.Parse(time.RFC3339, b.DHIdentityCert.IssuedAt)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: parsing dh identity certificate date: %w", err)
	}
	dhSig, err := base64.StdEncoding.DecodeString(b.DHIdentityCert.Signature)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding dh identity signature: %w", err)
	}
	dhCert := &devicecert.DHIdentityCertificate{
		AccountID: peer.AccountID, DeviceID: peer.DeviceID,
		DHPubKey: dhPub, IssuedAt: dhIssuedAt, Signature: dhSig,
	}
	if err := dhCert.Verify(devicePub); err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: %s's dh identity certificate is invalid: %w", peer.AccountID, err)
	}

	spkPub, err := base64.StdEncoding.DecodeString(b.SignedPrekey.PubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding %s's signed prekey: %w", peer.AccountID, err)
	}
	spkDHPub, err := base64.StdEncoding.DecodeString(b.SignedPrekey.DHIdentityPubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding signed prekey's dh identity key: %w", err)
	}
	spkIssuedAt, err := time.Parse(time.RFC3339, b.SignedPrekey.IssuedAt)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: parsing signed prekey certificate date: %w", err)
	}
	spkSig, err := base64.StdEncoding.DecodeString(b.SignedPrekey.Signature)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding signed prekey signature: %w", err)
	}
	spkCert := &devicecert.SignedPrekeyCertificate{
		AccountID: peer.AccountID, DeviceID: peer.DeviceID, KeyID: b.SignedPrekey.KeyID,
		DHIdentityPubKey: spkDHPub, PrekeyPubKey: spkPub, IssuedAt: spkIssuedAt, Signature: spkSig,
	}
	if err := spkCert.Verify(devicePub); err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: %s's signed prekey certificate is invalid: %w", peer.AccountID, err)
	}
	// The two certificates must name the same DH identity, or a server could
	// pair a genuine signed prekey with a different identity key and watch the
	// X3DH derive against a half it controls. Both signatures verify
	// individually in that case; only comparing them catches it.
	if !bytes.Equal(spkDHPub, dhPub) {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: %s's certificates disagree about its dh identity key", peer.AccountID)
	}

	dhKey, err := curve.NewPublicKey(dhPub)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: reading %s's dh identity key: %w", peer.AccountID, err)
	}
	spkKey, err := curve.NewPublicKey(spkPub)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("client: reading %s's signed prekey: %w", peer.AccountID, err)
	}
	remote := ratchet.RemoteBundle{
		DHIdentityPubKey: dhKey,
		SignedPrekeyID:   b.SignedPrekey.KeyID,
		SignedPrekeyPub:  spkKey,
	}

	// A missing one-time prekey is not an error: the pool ran dry, or the
	// claim went unauthenticated. The session is weaker on its first message
	// and works exactly as well otherwise.
	if b.OneTimePrekey != nil {
		otpkPub, err := base64.StdEncoding.DecodeString(b.OneTimePrekey.PubKey)
		if err != nil {
			return ratchet.RemoteBundle{}, fmt.Errorf("client: decoding %s's one-time prekey: %w", peer.AccountID, err)
		}
		// Deliberately unsigned, and safe to use unverified: it only ever adds
		// a fourth DH to the derivation. A forged one produces a shared secret
		// the peer cannot reproduce, so the first message simply fails to
		// decrypt -- a denial of service the server could achieve by dropping
		// the message anyway, and never a readable session.
		key, err := curve.NewPublicKey(otpkPub)
		if err != nil {
			return ratchet.RemoteBundle{}, fmt.Errorf("client: reading %s's one-time prekey: %w", peer.AccountID, err)
		}
		keyID := b.OneTimePrekey.KeyID
		remote.OneTimePrekeyID = &keyID
		remote.OneTimePrekeyPub = key
	}
	return remote, nil
}
