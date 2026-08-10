package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// Enough of a Freizone server for two real clients to hold a conversation
// through.
//
// Worth the weight, because the alternative is testing the send path against
// asserted request bodies -- which proves the client sends what this test
// expects and nothing about whether the other end can read it. Here A's send
// travels as an actual envelope through an actual queue and is opened by B's
// actual receive path, so the two halves are checked against each other rather
// than against a restatement of the format.
//
// It is a stub, not a server: no persistence, no rate limits, no revocation,
// and authentication is read but not verified (transport_test.go is where
// signatures are checked against the server's own code).
type fakeServer struct {
	t   *testing.T
	url string

	mu       sync.Mutex
	accounts map[string]*fakeAccount // by account id
	devices  map[string]*fakeDevice  // by device id

	// deviceIDs maps a readable label to the hex device id the certificates
	// demand, so tests can say "bob" instead of 32 hex characters.
	deviceIDs map[string]string
	queues    map[string][]queuedEnvelope

	// federationEnabled is what /v1/server-status reports.
	federationEnabled bool

	// sendStatus, when set, is the status every message POST is answered with
	// instead of accepting it -- how a test makes delivery fail on demand.
	sendStatus int

	// failAccounts refuses a message POST addressed to one of these account
	// ids specifically, while every other recipient still succeeds -- for a
	// group fan-out test that needs one member's copy to fail without the
	// others', which sendStatus (all-or-nothing) cannot express.
	failAccounts map[string]bool

	// bundleClaims counts prekey-bundle claims, which is how the tests tell a
	// session that was established once from one established again.
	bundleClaims int

	// unauthenticatedClaim makes the bundle endpoint answer without a one-time
	// prekey, as it does when it refuses a claim.s credentials.
	unauthenticatedClaim bool

	// blobs holds uploaded ciphertext by id, with the device set each was
	// granted to. Kept so a test can check that what reached the server is not
	// what the user chose -- the one property nobody can see from outside.
	blobs          map[string][]byte
	blobRecipients map[string][]string
	blobSeq        int

	// blobStatus, when set, is the status every blob upload is answered with,
	// so a test can make the picture fail while the message would not.
	blobStatus int
}

type fakeAccount struct {
	id      string
	rootPub ed25519.PublicKey
	devices []deviceWire
}

type fakeDevice struct {
	accountID      string
	dhIdentityCert *dhIdentityCertWire
	dhIdentityPub  string
	signedPrekey   signedPrekeyWire
	oneTimePrekeys []oneTimePrekeyWire
}

// fakeFederationDeviceCert mirrors internal/api/dto.go's
// federationDeviceCertDTO -- deliberately a second, independent definition of
// the wire shape rather than an import, since the point is to catch a client
// that drifted from the server's own field names, and importing the server's
// struct would make that drift invisible to this test binary too.
type fakeFederationDeviceCert struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pub_key"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
}

func (c *fakeFederationDeviceCert) validate() error {
	raw, err := base64.StdEncoding.DecodeString(c.DevicePubKey)
	if err != nil {
		return fmt.Errorf("invalid sender_device_cert.device_pub_key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid sender_device_cert.device_pub_key: expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return nil
}

type queuedEnvelope struct {
	MessageID       string          `json:"message_id"`
	SenderAccountID string          `json:"sender_account_id"`
	SenderDeviceID  string          `json:"sender_device_id"`
	SentAt          string          `json:"sent_at"`
	Payload         json.RawMessage `json:"payload"`
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	s := &fakeServer{
		t:                 t,
		accounts:          map[string]*fakeAccount{},
		devices:           map[string]*fakeDevice{},
		deviceIDs:         map[string]string{},
		queues:            map[string][]queuedEnvelope{},
		blobs:             map[string][]byte{},
		blobRecipients:    map[string][]string{},
		federationEnabled: true,
	}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// account creates an account with a real key hierarchy, registers it, and
// returns a Client pointed at this server with its prekeys published.
func (s *fakeServer) account(t *testing.T, label string) *Client {
	t.Helper()

	// A device id is hex by contract -- the certificates decode it -- so a
	// readable name is kept alongside rather than instead of one.
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("generating device id: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating device key: %v", err)
	}
	// The id has to derive from the root key, because ResolvePeer checks
	// exactly that before trusting anything else in the answer.
	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		t.Fatalf("deriving account id: %v", err)
	}

	issuedAt := time.Now().UTC().Truncate(time.Second)
	cert, err := devicecert.SignDeviceCertificate(accountID, deviceID, devicePub, issuedAt, rootPriv)
	if err != nil {
		t.Fatalf("signing device certificate: %v", err)
	}

	c, err := Open(filepath.Join(t.TempDir(), "account"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetIdentity(Identity{
		AccountID:  accountID,
		Server:     s.url,
		RootPub:    rootPub,
		RootPriv:   rootPriv,
		DeviceID:   deviceID,
		DevicePub:  devicePub,
		DevicePriv: devicePriv,
	}); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	s.mu.Lock()
	s.accounts[accountID] = &fakeAccount{
		id:      accountID,
		rootPub: rootPub,
		devices: []deviceWire{{
			DeviceID:     deviceID,
			DevicePubKey: base64.StdEncoding.EncodeToString(devicePub),
			IssuedAt:     issuedAt.Format(time.RFC3339),
			Signature:    base64.StdEncoding.EncodeToString(cert.Signature),
			Status:       "active",
		}},
	}
	s.devices[deviceID] = &fakeDevice{accountID: accountID}
	s.deviceIDs[label] = deviceID
	s.mu.Unlock()

	if err := c.RotatePrekeys(t.Context()); err != nil {
		t.Fatalf("RotatePrekeys: %v", err)
	}
	return c
}

// deliverTo runs one client's receive loop: drains its queue through the real
// receive path and returns what came of each envelope.
func deliverTo(t *testing.T, c *Client) []ReceiveResult {
	t.Helper()
	msgs, err := c.FetchMessages(t.Context())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	results := make([]ReceiveResult, 0, len(msgs))
	for _, msg := range msgs {
		res, err := c.HandleIncoming(msg, ReceiveOptions{})
		if err != nil {
			t.Fatalf("HandleIncoming %s: %v", msg.MessageID, err)
		}
		if err := c.AckMessage(t.Context(), msg.MessageID); err != nil {
			t.Fatalf("AckMessage: %v", err)
		}
		results = append(results, res)
	}
	return results
}

func (s *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/v1/server-status":
		s.writeJSON(w, map[string]any{
			"registration_open":  true,
			"federation_enabled": s.federationEnabled,
		})

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/accounts/"):
		id := strings.TrimPrefix(path, "/v1/accounts/")
		acc := s.lookupAccount(id)
		if acc == nil {
			s.writeError(w, http.StatusNotFound, "unknown_account")
			return
		}
		s.writeJSON(w, accountWire{
			ID:         acc.id,
			RootPubKey: base64.StdEncoding.EncodeToString(acc.rootPub),
			Devices:    acc.devices,
		})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/prekeys"):
		deviceID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/devices/"), "/prekeys")
		dev := s.devices[deviceID]
		if dev == nil {
			s.writeError(w, http.StatusNotFound, "unknown_device")
			return
		}
		var body uploadPrekeysBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if body.DHIdentityCert != nil {
			dev.dhIdentityCert = body.DHIdentityCert
			dev.dhIdentityPub = body.DHIdentityCert.DHPubKey
		}
		dev.signedPrekey = body.SignedPrekey
		if body.ReplaceOneTimePrekeys {
			// Mirrors internal/store.DeleteOneTimePrekeys: discard the whole
			// pool rather than append to it. See
			// Client.PurgeAndReplaceOneTimePrekeys.
			dev.oneTimePrekeys = nil
		}
		dev.oneTimePrekeys = append(dev.oneTimePrekeys, body.OneTimePrekeys...)
		s.writeJSON(w, map[string]any{"ok": true})

	case r.Method == http.MethodGet && strings.HasSuffix(path, "/prekey-status"):
		deviceID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/devices/"), "/prekey-status")
		dev := s.devices[deviceID]
		if dev == nil {
			s.writeError(w, http.StatusNotFound, "unknown_device")
			return
		}
		s.writeJSON(w, map[string]any{"one_time_prekeys_remaining": len(dev.oneTimePrekeys)})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/prekey-bundle"):
		deviceID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/devices/"), "/prekey-bundle")
		dev := s.devices[deviceID]
		if dev == nil || dev.dhIdentityCert == nil {
			s.writeError(w, http.StatusNotFound, "unknown_device")
			return
		}
		// See the /v1/messages case above: decoded only to catch a federated
		// claimant whose sender_device_cert has drifted from the server's
		// field names, not to authenticate it (this stub never does).
		var body struct {
			SenderDeviceCert *fakeFederationDeviceCert `json:"sender_device_cert"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				s.writeError(w, http.StatusBadRequest, "bad_request")
				return
			}
		}
		if body.SenderDeviceCert != nil {
			if err := body.SenderDeviceCert.validate(); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_request")
				return
			}
		}
		s.bundleClaims++
		bundle := prekeyBundleWire{
			DeviceID:         deviceID,
			DHIdentityPubKey: dev.dhIdentityPub,
			DHIdentityCert:   *dev.dhIdentityCert,
			SignedPrekey:     dev.signedPrekey,
		}
		switch {
		case s.unauthenticatedClaim:
			// What the server does when it will not accept the claim's
			// credentials: it answers, but without a one-time prekey.
			bundle.OneTimePrekeyOmitted = "unauthenticated"
		case len(dev.oneTimePrekeys) > 0:
			otpk := dev.oneTimePrekeys[0]
			dev.oneTimePrekeys = dev.oneTimePrekeys[1:]
			bundle.OneTimePrekey = &otpk
		default:
			bundle.OneTimePrekeyOmitted = "exhausted"
		}
		s.writeJSON(w, bundle)

	case r.Method == http.MethodPost && (path == "/v1/messages" || path == "/v1/federation/messages"):
		if s.sendStatus != 0 {
			s.writeError(w, s.sendStatus, "unknown_recipient_device")
			return
		}
		var body struct {
			MessageID          string                    `json:"message_id"`
			RecipientAccountID string                    `json:"recipient_account_id"`
			RecipientDeviceID  string                    `json:"recipient_device_id"`
			SenderAccountID    string                    `json:"sender_account_id"`
			SenderDeviceCert   *fakeFederationDeviceCert `json:"sender_device_cert"`
			Payload            json.RawMessage           `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		// Present on a federated send only, but when it is present it is what
		// the real server actually decodes -- see internal/api/dto.go's
		// federationDeviceCertDTO. A client that got the wire shape wrong (the
		// live "device_pubkey" vs "device_pub_key" bug this guards against)
		// must fail here exactly like the real server, not pass silently
		// because this stub never looked.
		if body.SenderDeviceCert != nil {
			if err := body.SenderDeviceCert.validate(); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_request")
				return
			}
		}
		if s.failAccounts[body.RecipientAccountID] {
			s.writeError(w, http.StatusServiceUnavailable, "unknown_recipient_device")
			return
		}
		sender := body.SenderAccountID
		if sender == "" {
			sender = s.accountForDevice(r.Header.Get(httpsig.HeaderKeyID))
		}
		if s.devices[body.RecipientDeviceID] == nil {
			s.writeError(w, http.StatusNotFound, "unknown_recipient_device")
			return
		}
		// De-duplication by message id, which is what makes a retry safe on
		// the wire as well as in the ratchet.
		for _, q := range s.queues[body.RecipientDeviceID] {
			if q.MessageID == body.MessageID {
				s.writeError(w, http.StatusConflict, "duplicate_message")
				return
			}
		}
		s.queues[body.RecipientDeviceID] = append(s.queues[body.RecipientDeviceID], queuedEnvelope{
			MessageID:       body.MessageID,
			SenderAccountID: sender,
			SenderDeviceID:  "sender-device",
			SentAt:          time.Now().UTC().Format(time.RFC3339),
			Payload:         body.Payload,
		})
		s.writeJSON(w, map[string]any{"ok": true})

	case r.Method == http.MethodPost && (path == "/v1/blobs" || path == "/v1/federation/blobs"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		// The digest header is what the signature covers, so a stub that
		// ignored it would let a client sign one thing and upload another
		// without any test noticing.
		if s.blobStatus != 0 {
			s.writeError(w, s.blobStatus, "upload_failed")
			return
		}
		sum := sha256.Sum256(body)
		if want := "sha256=" + hex.EncodeToString(sum[:]); r.Header.Get(httpsig.HeaderBodyDigest) != want {
			s.writeError(w, http.StatusBadRequest, "digest_mismatch")
			return
		}
		recipients := r.URL.Query()["recipient_device_id"]
		if len(recipients) == 0 {
			s.writeError(w, http.StatusBadRequest, "no_recipients")
			return
		}
		s.blobSeq++
		blobID := fmt.Sprintf("blob-%d", s.blobSeq)
		s.blobs[blobID] = append([]byte(nil), body...)
		s.blobRecipients[blobID] = recipients
		status := http.StatusCreated
		if len(recipients) > 1 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]any{"blob_id": blobID, "size": len(body)}); err != nil {
			s.t.Errorf("encoding blob response: %v", err)
		}

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/blobs/"):
		blobID := strings.TrimPrefix(path, "/v1/blobs/")
		data, ok := s.blobs[blobID]
		if !ok {
			s.writeError(w, http.StatusNotFound, "unknown_blob")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(data); err != nil {
			s.t.Errorf("writing blob: %v", err)
		}

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v1/blobs/"):
		delete(s.blobs, strings.TrimPrefix(path, "/v1/blobs/"))
		s.writeJSON(w, map[string]any{"status": "deleted"})

	case r.Method == http.MethodGet && path == "/v1/messages":
		deviceID := r.Header.Get(httpsig.HeaderKeyID)
		queue := s.queues[deviceID]
		if queue == nil {
			queue = []queuedEnvelope{}
		}
		s.writeJSON(w, queue)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v1/messages/"):
		id := strings.TrimPrefix(path, "/v1/messages/")
		deviceID := r.Header.Get(httpsig.HeaderKeyID)
		kept := s.queues[deviceID][:0]
		for _, q := range s.queues[deviceID] {
			if q.MessageID != id {
				kept = append(kept, q)
			}
		}
		s.queues[deviceID] = kept
		// 200 with a body, as the real handler answers -- a 204 here would have
		// been the stub testing the client against a server that does not exist.
		s.writeJSON(w, map[string]any{"status": "deleted"})

	default:
		s.writeError(w, http.StatusNotFound, "not_found")
	}
}

// lookupAccount resolves a full id or the prefix a user typed, which is what
// the real server offers and what makes ResolvePeer's normalisation matter.
func (s *fakeServer) lookupAccount(idOrPrefix string) *fakeAccount {
	if acc, ok := s.accounts[idOrPrefix]; ok {
		return acc
	}
	for id, acc := range s.accounts {
		if strings.HasPrefix(id, idOrPrefix) {
			return acc
		}
	}
	return nil
}

func (s *fakeServer) accountForDevice(deviceID string) string {
	if dev := s.devices[deviceID]; dev != nil {
		return dev.accountID
	}
	return ""
}

func (s *fakeServer) queueLen(label string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queues[s.deviceIDs[label]])
}

func (s *fakeServer) remainingPrekeys(label string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.devices[s.deviceIDs[label]].oneTimePrekeys)
}

func (s *fakeServer) publishedSignedPrekey(label string) signedPrekeyWire {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[s.deviceIDs[label]].signedPrekey
}

// device is the hex id behind a label, for the handful of places a test has to
// name one directly.
func (s *fakeServer) device(label string) *fakeDevice {
	return s.devices[s.deviceIDs[label]]
}

func (s *fakeServer) blobBytes(blobID string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blobs[blobID]
}

func (s *fakeServer) blobRecipientsFor(blobID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blobRecipients[blobID]
}

func (s *fakeServer) blobCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.blobs)
}

func (s *fakeServer) set(mutate func(*fakeServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutate(s)
}

func (s *fakeServer) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.t.Errorf("encoding response: %v", err)
	}
}

func (s *fakeServer) writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{"error": code, "message": code}); err != nil {
		s.t.Errorf("encoding error response: %v", err)
	}
}
