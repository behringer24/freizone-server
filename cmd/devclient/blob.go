package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// runBlob exercises the encrypted blob transport (SRV-07) end to end
// without the app: upload a file, download it back, compare. It sends the
// file as-is -- a real client uploads *ciphertext*, but the server treats
// the body as opaque either way, so this is enough to prove the transport,
// the streamed-body signature, quotas and expiry all work.
func runBlob(args []string) error {
	fs := flag.NewFlagSet("blob", flag.ExitOnError)
	dataDir := fs.String("datadir", "", "directory holding this client's state (required)")
	upload := fs.String("upload", "", "path of a file to upload")
	download := fs.String("download", "", "blob id to download")
	out := fs.String("out", "", "where to write a downloaded blob (default: stdout)")
	del := fs.String("delete", "", "blob id to delete")
	var to repeatedFlag
	fs.Var(&to, "to", "recipient device id for an upload (repeat for several, as a group fan-out does; default: this client's own device)")
	toServer := fs.String("to-server", "", "recipients' home server, if different from this account's own -- federated upload (PROTOCOL §10), posted directly to that server's /v1/federation/blobs")
	fs.BoolVar(&verbose, "verbose", false, "log all server requests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return fmt.Errorf("-datadir is required")
	}
	state, err := LoadState(statePath(*dataDir))
	if err != nil {
		return err
	}

	switch {
	case *upload != "":
		recipients := []string(to)
		if len(recipients) == 0 {
			// Uploading to yourself is the simplest round-trip check.
			recipients = []string{state.DeviceID}
		}
		return uploadBlob(state, *upload, recipients, *toServer)
	case *download != "":
		return downloadBlob(state, *download, *out)
	case *del != "":
		return deleteBlob(state, *del)
	default:
		return fmt.Errorf("one of -upload, -download or -delete is required")
	}
}

// repeatedFlag collects a flag given more than once, so -to can name every
// recipient of a single upload the way a group fan-out does (SRV-18).
type repeatedFlag []string

func (f *repeatedFlag) String() string     { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(v string) error { *f = append(*f, v); return nil }

// uploadBlob pushes one encrypted attachment to the recipients' server. With
// several recipient ids it is the group case (SRV-18): one upload for every
// member whose home server this is. targetServer selects the federated route
// when the recipients live somewhere other than this client's own server.
func uploadBlob(state *State, path string, recipientDeviceIDs []string, targetServer string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	server := state.Server
	urlPath := "/v1/blobs"
	// A federated sender has no device row on the target server, so it
	// identifies itself inline: headers carrying the certificate chain, and
	// the device public key itself as the signature key id (PROTOCOL §9).
	keyID := state.DeviceID
	federated := targetServer != ""
	if federated {
		server = targetServer
		urlPath = "/v1/federation/blobs"
		keyID = base64.StdEncoding.EncodeToString(state.DevicePub)
	}

	// Built by hand rather than via url.Values so the order is ours and the
	// signed string is exactly what goes on the wire -- the signature covers
	// the raw query, and the recipient set is part of it.
	params := make([]string, 0, len(recipientDeviceIDs))
	for _, id := range recipientDeviceIDs {
		params = append(params, "recipient_device_id="+url.QueryEscape(id))
	}
	rawQuery := strings.Join(params, "&")
	req, err := http.NewRequest(http.MethodPost, server+urlPath+"?"+rawQuery, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+digest)

	if federated {
		issuedAt := time.Now().UTC()
		cert, cerr := devicecert.SignDeviceCertificate(
			state.AccountID, state.DeviceID, ed25519.PublicKey(state.DevicePub), issuedAt, ed25519.PrivateKey(state.RootPriv))
		if cerr != nil {
			return fmt.Errorf("signing device certificate: %w", cerr)
		}
		// The body is raw ciphertext, so the sender's identity travels in
		// headers rather than JSON fields.
		req.Header.Set("Freizone-Sender-Account-Id", state.AccountID)
		req.Header.Set("Freizone-Sender-Root-Pub-Key", base64.StdEncoding.EncodeToString(state.RootPub))
		req.Header.Set("Freizone-Sender-Device-Id", state.DeviceID)
		req.Header.Set("Freizone-Sender-Device-Pub-Key", base64.StdEncoding.EncodeToString(state.DevicePub))
		req.Header.Set("Freizone-Sender-Cert-Issued-At", issuedAt.Format(time.RFC3339))
		req.Header.Set("Freizone-Sender-Cert-Signature", base64.StdEncoding.EncodeToString(cert.Signature))
	}

	// Signed over the digest rather than the body -- the variant that lets
	// the server authenticate a large upload before reading it (PROTOCOL §3).
	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	canonical := httpsig.CanonicalStringWithBodyDigest(
		http.MethodPost, urlPath, rawQuery, httpsig.FormatTimestamp(ts), nonce, keyID, digest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(state.DevicePriv), []byte(canonical)))

	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("uploading blob: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	// 201 for a single recipient, 200 for several -- nothing is created at
	// one location when the outcomes differ per recipient.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %s: %s", resp.Status, respBody)
	}

	var parsed struct {
		BlobID     string `json:"blob_id"`
		Size       int64  `json:"size"`
		ExpiresAt  string `json:"expires_at"`
		Recipients []struct {
			RecipientDeviceID string `json:"recipient_device_id"`
			Status            string `json:"status"`
		} `json:"recipients"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	fmt.Printf("uploaded %d bytes\n  blob_id:    %s\n  expires_at: %s\n", parsed.Size, parsed.BlobID, parsed.ExpiresAt)
	for _, rcpt := range parsed.Recipients {
		fmt.Printf("  %-24s %s\n", rcpt.RecipientDeviceID, rcpt.Status)
	}
	return nil
}

func downloadBlob(state *State, blobID, outPath string) error {
	resp, err := signedRequest(state, http.MethodGet, "/v1/blobs/"+blobID, nil)
	if err != nil {
		return fmt.Errorf("downloading blob: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: %s: %s", resp.Status, body)
	}

	if outPath == "" {
		n, err := io.Copy(os.Stdout, resp.Body)
		if err != nil {
			return fmt.Errorf("writing blob: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\ndownloaded %d bytes\n", n)
		return nil
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	fmt.Printf("downloaded %d bytes to %s\n", n, outPath)
	return nil
}

func deleteBlob(state *State, blobID string) error {
	resp, err := signedRequest(state, http.MethodDelete, "/v1/blobs/"+blobID, nil)
	if err != nil {
		return fmt.Errorf("deleting blob: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed: %s: %s", resp.Status, body)
	}
	fmt.Println("deleted", blobID)
	return nil
}
