package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// newDeviceKey generates a real device keypair. Separate from newServedClient
// so a handler closure can verify against the public key -- it has to exist
// before the handler that uses it is written.
func newDeviceKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating device key: %v", err)
	}
	return pub, priv
}

// newServedClient wires a Client to a test server using the given device key,
// so signatures can be verified rather than merely inspected.
func newServedClient(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c := openTestClient(t)
	if err := c.SetIdentity(Identity{
		AccountID:  "fz1account",
		Server:     srv.URL,
		RootPub:    []byte{1},
		RootPriv:   []byte{2},
		DeviceID:   "device-1",
		DevicePub:  pub,
		DevicePriv: priv,
	}); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	return c
}

// servedClient is the shorthand for the tests that never look at a signature.
func servedClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	pub, priv := newDeviceKey(t)
	return newServedClient(t, pub, priv, handler)
}

// The signature is checked with the server's own verification path, not with a
// restatement of it here: if the two sides ever disagree about what the
// canonical string covers, this is where it shows up rather than in the field.
func TestSignedRequestVerifiesWithTheServersOwnCode(t *testing.T) {
	type result struct {
		err     error
		keyID   string
		checked bool
	}
	var got result

	pub, priv := newDeviceKey(t)
	c := newServedClient(t, pub, priv, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		headers, err := httpsig.ParseRequestHeaders(r)
		if err != nil {
			got = result{err: err}
			w.WriteHeader(500)
			return
		}
		canonical := httpsig.CanonicalStringFromRequest(r, headers, body)
		got = result{
			err:     httpsig.Verify(canonical, headers.Signature, pub),
			keyID:   headers.KeyID,
			checked: true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	err := c.do(context.Background(), request{
		method: "POST",
		path:   "/v1/messages",
		query:  "a=1&b=2",
		body:   map[string]string{"hello": "world"},
		auth:   authDevice,
	}, nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if !got.checked {
		t.Fatal("handler never verified anything")
	}
	if got.err != nil {
		t.Errorf("server could not verify our signature: %v", got.err)
	}
	if got.keyID != "device-1" {
		t.Errorf("key id: want the device id, got %q", got.keyID)
	}
}

// A foreign server has no row to look a device id up in, so the key id has to
// be the public key itself (PROTOCOL.md §9).
func TestFederatedRequestNamesTheKeyByPublicKey(t *testing.T) {
	var keyID string
	var verifyErr error

	pub, priv := newDeviceKey(t)
	c := newServedClient(t, pub, priv, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		headers, err := httpsig.ParseRequestHeaders(r)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		keyID = headers.KeyID
		verifyErr = httpsig.Verify(httpsig.CanonicalStringFromRequest(r, headers, body), headers.Signature, pub)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	})

	// A federated call to the same test host, which is all this needs: the
	// signature covers method, path and query, never the target host.
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if err := c.do(context.Background(), request{
		method: "POST", path: "/v1/federation/messages",
		server: id.Server, auth: authFederated,
	}, nil); err != nil {
		t.Fatalf("do: %v", err)
	}

	if want := base64.StdEncoding.EncodeToString(pub); keyID != want {
		t.Errorf("federated key id: want the base64 public key %q, got %q", want, keyID)
	}
	if verifyErr != nil {
		t.Errorf("federated signature did not verify: %v", verifyErr)
	}
}

func TestUnauthenticatedRequestIsNotSigned(t *testing.T) {
	var hadSignature bool
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		hadSignature = r.Header.Get(httpsig.HeaderSignature) != ""
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	})

	if err := c.do(context.Background(), request{
		method: "GET", path: "/v1/server-status", auth: authNone,
	}, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if hadSignature {
		t.Error("a public endpoint was sent a signature it never asked for")
	}
}

func TestServerErrorBecomesAPIError(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		w.Write([]byte(`{"error":{"code":"unknown_device","message":"no such device"}}`))
	})

	err := c.do(context.Background(), request{method: "GET", path: "/v1/x", auth: authDevice}, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want an APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 404 || apiErr.Code != "unknown_device" || apiErr.Message != "no such device" {
		t.Errorf("error not carried through: %+v", apiErr)
	}
	if !IsStaleDevice(err) {
		t.Error("a 404 unknown_device should read as a stale device")
	}
}

// A JSON object that simply is not shaped like an error still came from
// something speaking JSON, so it stays an APIError -- undiagnosed, not
// mistaken for a wrong address.
func TestUnshapedErrorBodyStaysAnAPIError(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(`{"something":"else"}`))
	})

	err := c.do(context.Background(), request{method: "GET", path: "/v1/x", auth: authDevice}, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want an APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "" {
		t.Errorf("code should be empty (undiagnosed), got %q", apiErr.Code)
	}
}

// "You typed the wrong address" and "the server said no" need different words
// in front of a user, so they are different errors.
func TestNonJSONAnswerIsNotAFreizoneServer(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"an HTML 404 from a plain web server", "<html><body>Not Found</body></html>", 404},
		{"a parked page answering 200", "<!doctype html><title>For sale</title>", 200},
		{"a bare JSON value rather than an object", `"nope"`, 200},
		{"nothing at all", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			err := c.do(context.Background(), request{method: "GET", path: "/v1/x", auth: authNone}, nil)

			var wrongServer *NotFreizoneServerError
			if !errors.As(err, &wrongServer) {
				t.Fatalf("want NotFreizoneServerError, got %T: %v", err, err)
			}
			if wrongServer.Host == "" {
				t.Error("no host recorded -- the user cannot be told which address to check")
			}
		})
	}
}

func TestIsStaleDeviceClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"404 with a distinct code", &APIError{StatusCode: 404, Code: "unknown_device"}, true},
		{"404 on a bundle claim", &APIError{StatusCode: 404, Code: "no_prekey_bundle"}, true},
		{"404 from an older server's catch-all", &APIError{StatusCode: 404, Code: "not_found"}, true},
		{"404 with no code at all", &APIError{StatusCode: 404}, true},
		// About the server, never about the device: counting it would cost a
		// good cached device and its session for nothing.
		{"federation switched off", &APIError{StatusCode: 404, Code: "federation_disabled"}, false},
		{"a server error", &APIError{StatusCode: 500, Code: "internal_error"}, false},
		{"not an API error at all", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsStaleDevice(tc.err); got != tc.want {
				t.Errorf("IsStaleDevice: want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestIsStaleRecipientStatus(t *testing.T) {
	if !IsStaleRecipientStatus("unknown_recipient") {
		t.Error("unknown_recipient should mean the device is gone")
	}
	// These describe conditions a retry against the same device can outlive.
	for _, status := range []string{"queue_full", "invalid", "internal_error", "delivered", ""} {
		if IsStaleRecipientStatus(status) {
			t.Errorf("%q should not be read as a dead device", status)
		}
	}
}

// The compatibility trap this type exists to close: an older server says
// nothing about capabilities it predates, and two of those silences mean the
// opposite of Go's zero value.
func TestServerStatusAppliesDefaultsForAnOlderServer(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"claimed":true,"registration_policy":"invite"}`))
	})

	status, err := c.ServerStatus(context.Background(), "")
	if err != nil {
		t.Fatalf("ServerStatus: %v", err)
	}
	if !status.FederationEnabled {
		t.Error("a server too old to mention federation must be treated as federating, " +
			"or every conversation with one is stranded")
	}
	if status.MaxBlobRecipients != 1 {
		t.Errorf("max blob recipients: want 1 for an older server, got %d -- "+
			"assuming more delivers a group picture to exactly one member and reports success",
			status.MaxBlobRecipients)
	}
	if status.BatchMessages {
		t.Error("batch delivery must not be assumed; the fallback is one post per message")
	}
	if status.RegistrationPolicy != "invite" || !status.Claimed {
		t.Errorf("plain fields lost: %+v", status)
	}
}

func TestServerStatusHonoursExplicitValues(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"claimed":true,"registration_policy":"open",
			"federation_enabled":false,
			"blobs_enabled":true,"max_blob_bytes":1048576,
			"max_blob_recipients":32,
			"batch_messages":true,"max_batch_messages":50,
			"attestation":"tok"
		}`))
	})

	status, err := c.ServerStatus(context.Background(), "")
	if err != nil {
		t.Fatalf("ServerStatus: %v", err)
	}
	// An explicit false must survive: this is an operator switching federation
	// off, not an old server staying quiet.
	if status.FederationEnabled {
		t.Error("explicit federation_enabled:false was overridden by the default")
	}
	if status.MaxBlobRecipients != 32 || status.MaxBlobBytes != 1048576 || !status.BlobsEnabled {
		t.Errorf("blob capabilities: %+v", status)
	}
	if !status.BatchMessages || status.MaxBatchMessages != 50 || status.Attestation != "tok" {
		t.Errorf("batch/attestation: %+v", status)
	}
}

func TestContextCancellationStopsARequest(t *testing.T) {
	release := make(chan struct{})
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte(`{}`))
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.do(ctx, request{method: "GET", path: "/v1/slow", auth: authNone}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want a deadline error, got %v", err)
	}
}

func TestRequestWithoutAnIdentityFails(t *testing.T) {
	c := openTestClient(t)
	err := c.do(context.Background(), request{method: "GET", path: "/v1/x", auth: authDevice}, nil)
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("want ErrNoIdentity before setup, got %v", err)
	}
}
