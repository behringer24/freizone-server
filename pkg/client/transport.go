package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// authMode is how a request proves who is sending it.
type authMode int

const (
	// authNone is a public endpoint: bootstrap, register, account lookup,
	// prekey-bundle claim.
	authNone authMode = iota

	// authDevice signs with this device's key and names it by device id --
	// the ordinary case against our own server, which has a row for us.
	authDevice

	// authFederated signs with the same key but names it by the base64 device
	// *public key* itself. A foreign server has no local row to look a device
	// id up in, so the key id has to be self-describing (PROTOCOL.md §9).
	authFederated
)

// request is one call to a Freizone server.
type request struct {
	method string
	path   string
	query  string

	// body is marshalled to JSON when non-nil. Kept as a value rather than
	// bytes so callers cannot accidentally sign one encoding and send another.
	body any

	// server overrides the account's own server, for a federated call. The
	// signature covers only method, path and query, so the target host is not
	// part of what is signed -- which is exactly why authFederated has to name
	// the key differently instead.
	server string

	auth authMode
}

// httpClient has no timeout on purpose: the message stream is a long-lived
// response, and every call carries a context that is the real deadline.
var httpClient = &http.Client{}

// do performs one request and decodes a successful JSON body into out, which
// may be nil for calls whose body is not interesting.
//
// Failure is classified, not just reported. A Freizone server refusing
// something answers JSON and becomes an [APIError] carrying the server's own
// code; a host answering anything else becomes a [NotFreizoneServerError],
// because "you typed the wrong address" and "the server said no" need
// different words in front of a user.
func (c *Client) do(ctx context.Context, r request, out any) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}

	server := r.server
	if server == "" {
		server = id.Server
	}

	var body []byte
	if r.body != nil {
		if body, err = json.Marshal(r.body); err != nil {
			return fmt.Errorf("client: encoding request body for %s: %w", r.path, err)
		}
	}

	target := server + r.path
	if r.query != "" {
		target += "?" + r.query
	}
	req, err := http.NewRequestWithContext(ctx, r.method, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: building request for %s: %w", r.path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := signRequest(req, r, body, id); err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", r.method, r.path, err)
	}
	defer resp.Body.Close()

	return decodeResponse(resp, out)
}

func signRequest(req *http.Request, r request, body []byte, id Identity) error {
	if r.auth == authNone {
		return nil
	}

	keyID := id.DeviceID
	if r.auth == authFederated {
		keyID = base64.StdEncoding.EncodeToString(id.DevicePub)
	}

	nonce, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("client: generating request nonce: %w", err)
	}
	ts := time.Now()
	sig := httpsig.Sign(r.method, r.path, r.query, body, keyID, ts, nonce, ed25519.PrivateKey(id.DevicePriv))

	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)
	return nil
}

func decodeResponse(resp *http.Response, out any) error {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("client: reading response body: %w", err)
	}

	// A Freizone server always answers with a JSON object. Anything else --
	// HTML, an empty page, a bare JSON value -- is the reliable tell that the
	// far end is not one, whatever the status code says.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return &NotFreizoneServerError{StatusCode: resp.StatusCode, Host: hostOf(resp)}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiErrorFrom(resp.StatusCode, probe)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("client: decoding response: %w", err)
	}
	return nil
}

func apiErrorFrom(status int, body map[string]json.RawMessage) error {
	apiErr := &APIError{StatusCode: status, Message: http.StatusText(status)}

	detail, ok := body["error"]
	if !ok {
		return apiErr
	}
	var parsed struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	// A JSON object without the expected error shape still came from something
	// speaking JSON, so it stays an APIError -- just an undiagnosed one.
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return apiErr
	}
	apiErr.Code = parsed.Code
	if parsed.Message != "" {
		apiErr.Message = parsed.Message
	}
	return apiErr
}

func hostOf(resp *http.Response) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.Host
	}
	return ""
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// encodeQuery builds a query string from ordered pairs rather than a map, so
// the order is ours and matches, byte for byte, what the signature covers.
func encodeQuery(pairs ...[2]string) string {
	values := make([]string, 0, len(pairs))
	for _, p := range pairs {
		values = append(values, url.QueryEscape(p[0])+"="+url.QueryEscape(p[1]))
	}
	out := ""
	for i, v := range values {
		if i > 0 {
			out += "&"
		}
		out += v
	}
	return out
}
