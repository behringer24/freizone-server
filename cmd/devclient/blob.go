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
	"os"
	"time"

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
	to := fs.String("to", "", "recipient device id for an upload (default: this client's own device)")
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
		recipient := *to
		if recipient == "" {
			// Uploading to yourself is the simplest round-trip check.
			recipient = state.DeviceID
		}
		return uploadBlob(state, *upload, recipient)
	case *download != "":
		return downloadBlob(state, *download, *out)
	case *del != "":
		return deleteBlob(state, *del)
	default:
		return fmt.Errorf("one of -upload, -download or -delete is required")
	}
}

func uploadBlob(state *State, path, recipientDeviceID string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	urlPath := "/v1/blobs"
	rawQuery := "recipient_device_id=" + recipientDeviceID
	req, err := http.NewRequest(http.MethodPost, state.Server+urlPath+"?"+rawQuery, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+digest)

	// Signed over the digest rather than the body -- the variant that lets
	// the server authenticate a large upload before reading it (PROTOCOL §3).
	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	canonical := httpsig.CanonicalStringWithBodyDigest(
		http.MethodPost, urlPath, rawQuery, httpsig.FormatTimestamp(ts), nonce, state.DeviceID, digest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(state.DevicePriv), []byte(canonical)))

	req.Header.Set(httpsig.HeaderKeyID, state.DeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("uploading blob: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("upload failed: %s: %s", resp.Status, respBody)
	}

	var parsed struct {
		BlobID    string `json:"blob_id"`
		Size      int64  `json:"size"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	fmt.Printf("uploaded %d bytes\n  blob_id:    %s\n  expires_at: %s\n", parsed.Size, parsed.BlobID, parsed.ExpiresAt)
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
