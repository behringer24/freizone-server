package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/group"
)

// preparedCopy is one recipient's own ciphertext. A group message is encrypted
// once per member against that member's own ratchet -- there is no group key,
// which is what makes removing someone take effect immediately and need no
// re-key anywhere.
type preparedCopy struct {
	member    group.Member
	device    resolvedDevice
	messageID string
	payload   json.RawMessage
}

// fanOut encrypts plaintext separately for every recipient and delivers the
// copies, batching per server where the server says it can (SRV-01 phase 2)
// and posting individually where it cannot.
//
// Failures are reported per recipient and never abort the fan-out: in a group,
// one member being unreachable is not the others' problem.
func (g *groupCtx) fanOut(plaintext []byte, label string, recipients []group.Member) error {
	if len(recipients) == 0 {
		fmt.Printf("[%s] no recipients\n", label)
		return nil
	}

	// Encrypt first, save second, send third. Encrypting advances each
	// recipient's ratchet, so the advanced state has to reach disk even if the
	// network half then fails -- otherwise a retry would re-use a message
	// number and desync the peer.
	copies := make([]preparedCopy, 0, len(recipients))
	for _, m := range recipients {
		dev, err := g.resolveMember(m.AccountID, memberServer(m, g.state.Server))
		if err != nil {
			fmt.Printf("   %s  resolve failed: %v\n", shortID(m.AccountID), err)
			continue
		}
		payload, msgID, err := g.encryptFor(dev, plaintext)
		if err != nil {
			fmt.Printf("   %s  encrypt failed: %v\n", shortID(m.AccountID), err)
			continue
		}
		copies = append(copies, preparedCopy{member: m, device: dev, messageID: msgID, payload: payload})
	}
	if err := g.state.Save(g.path); err != nil {
		return err
	}

	fmt.Printf("[%s → %d recipient(s)] group %s\n", label, len(copies), shortID(g.id))

	// Group by target server: that is the unit a batch can cover, since a
	// batch goes to one server.
	byServer := map[string][]preparedCopy{}
	for _, c := range copies {
		byServer[c.device.server] = append(byServer[c.device.server], c)
	}
	servers := make([]string, 0, len(byServer))
	for s := range byServer {
		servers = append(servers, s)
	}
	sort.Strings(servers)

	for _, server := range servers {
		g.deliverToServer(server, byServer[server])
	}
	return nil
}

// memberServer resolves a member's recorded home server, defaulting to our own
// for a member recorded before servers were carried (there is none today, but
// an empty string must not silently become an unreachable target).
func memberServer(m group.Member, own string) string {
	if m.Server == "" {
		return own
	}
	return m.Server
}

// encryptFor produces one recipient's copy: their own ratchet ciphertext
// wrapped in the standard envelope, plus a fresh message id.
func (g *groupCtx) encryptFor(dev resolvedDevice, plaintext []byte) (json.RawMessage, string, error) {
	session, initial, err := getOrCreateSession(g.state, dev.accountID, dev.server, dev.deviceID, dev.devicePub)
	if err != nil {
		return nil, "", err
	}
	header, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting: %w", err)
	}
	payload, err := newSendEnvelope(initial, header, ciphertext)
	if err != nil {
		return nil, "", err
	}
	msgID, err := randomMessageID()
	if err != nil {
		return nil, "", err
	}
	return payload, msgID, nil
}

// deliverToServer sends every copy destined for one server, in one batch where
// that server advertises the capability.
func (g *groupCtx) deliverToServer(server string, copies []preparedCopy) {
	target := server
	if target == "" {
		target = g.state.Server
	}
	cap := g.batchCapability(target)

	if len(copies) > 1 && cap.supported {
		for start := 0; start < len(copies); start += cap.max {
			end := min(start+cap.max, len(copies))
			g.sendBatch(server, copies[start:end])
		}
		return
	}
	for _, c := range copies {
		g.sendSingle(server, c)
	}
}

// batchCapability asks a server once per run whether it takes batches. An
// older server simply has no such field, and the documented fallback is one
// post per message -- which is why groups work against every server already
// deployed. Discovered per server, since a federated group's members sit on
// servers that will not upgrade together.
func (g *groupCtx) batchCapability(server string) *batchCapability {
	if cached, ok := g.batch[server]; ok {
		return cached
	}
	capability := &batchCapability{}
	g.batch[server] = capability

	resp, err := jsonRequest(server, http.MethodGet, "/v1/server-status", nil)
	if err != nil {
		return capability
	}
	defer resp.Body.Close()

	var status struct {
		BatchMessages    bool `json:"batch_messages"`
		MaxBatchMessages int  `json:"max_batch_messages"`
	}
	if json.NewDecoder(resp.Body).Decode(&status) != nil || !status.BatchMessages {
		return capability
	}
	capability.supported = true
	capability.max = status.MaxBatchMessages
	if capability.max <= 0 {
		capability.max = 1
	}
	return capability
}

func (g *groupCtx) sendBatch(server string, copies []preparedCopy) {
	items := make([]batchMessageItem, 0, len(copies))
	for _, c := range copies {
		items = append(items, batchMessageItem{
			MessageID:         c.messageID,
			RecipientDeviceID: c.device.deviceID,
			Payload:           c.payload,
		})
	}

	var (
		path string
		body []byte
		err  error
		do   func() (*http.Response, error)
	)
	if server == "" {
		path = "/v1/messages/batch"
		body, err = json.Marshal(sendMessageBatchRequest{Messages: items})
		do = func() (*http.Response, error) { return signedRequest(g.state, http.MethodPost, path, body) }
	} else {
		path = "/v1/federation/messages/batch"
		var cert *federationDeviceCertDTO
		cert, err = g.federationCert()
		if err == nil {
			body, err = json.Marshal(federationMessageBatchRequest{
				SenderAccountID:  g.state.AccountID,
				SenderRootPubKey: base64.StdEncoding.EncodeToString(g.state.RootPub),
				SenderDeviceCert: *cert,
				Messages:         items,
			})
		}
		do = func() (*http.Response, error) {
			return federatedSignedRequest(g.state, server, http.MethodPost, path, body)
		}
	}
	if err != nil {
		fmt.Printf("   batch build failed: %v\n", err)
		return
	}

	start := time.Now()
	resp, err := do()
	if err != nil {
		fmt.Printf("   batch POST %s failed: %v\n", path, err)
		return
	}
	defer resp.Body.Close()
	dur := time.Since(start).Round(time.Millisecond)

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		fmt.Printf("   batch POST %s → %s: %s\n", path, resp.Status, data)
		return
	}
	var parsed batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		fmt.Printf("   batch response unreadable: %v\n", err)
		return
	}

	byID := map[string]string{}
	for _, r := range parsed.Results {
		byID[r.MessageID] = r.Status
	}
	fmt.Printf("   batch POST %s → %d item(s) in one request (%s)\n", path, len(items), dur)
	for _, c := range copies {
		fmt.Printf("      %s  %s\n", shortID(c.member.AccountID), orPlaceholder(byID[c.messageID], "no result"))
	}
}

func (g *groupCtx) sendSingle(server string, c preparedCopy) {
	var (
		path string
		body []byte
		err  error
		do   func() (*http.Response, error)
	)
	if server == "" {
		path = "/v1/messages"
		body, err = json.Marshal(sendMessageRequest{
			MessageID:         c.messageID,
			RecipientDeviceID: c.device.deviceID,
			Payload:           c.payload,
		})
		do = func() (*http.Response, error) { return signedRequest(g.state, http.MethodPost, path, body) }
	} else {
		path = "/v1/federation/messages"
		var cert *federationDeviceCertDTO
		cert, err = g.federationCert()
		if err == nil {
			body, err = json.Marshal(federationMessageRequest{
				SenderAccountID:   g.state.AccountID,
				SenderRootPubKey:  base64.StdEncoding.EncodeToString(g.state.RootPub),
				SenderDeviceCert:  *cert,
				RecipientDeviceID: c.device.deviceID,
				MessageID:         c.messageID,
				Payload:           c.payload,
			})
		}
		do = func() (*http.Response, error) {
			return federatedSignedRequest(g.state, server, http.MethodPost, path, body)
		}
	}
	if err != nil {
		fmt.Printf("      %s  build failed: %v\n", shortID(c.member.AccountID), err)
		return
	}

	resp, err := do()
	if err != nil {
		fmt.Printf("      %s  send failed: %v\n", shortID(c.member.AccountID), err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp.Body)
		fmt.Printf("      %s  %s: %s\n", shortID(c.member.AccountID), resp.Status, data)
		return
	}
	fmt.Printf("      %s  queued\n", shortID(c.member.AccountID))
}

// federationCert builds the inline device certificate a cross-server send
// carries -- the same one handleReceiveFederatedMessage verifies against this
// account's root key.
func (g *groupCtx) federationCert() (*federationDeviceCertDTO, error) {
	issuedAt := time.Now().UTC()
	cert, err := devicecert.SignDeviceCertificate(g.state.AccountID, g.state.DeviceID,
		ed25519.PublicKey(g.state.DevicePub), issuedAt, ed25519.PrivateKey(g.state.RootPriv))
	if err != nil {
		return nil, fmt.Errorf("signing device certificate: %w", err)
	}
	return &federationDeviceCertDTO{
		DeviceID:     g.state.DeviceID,
		DevicePubKey: base64.StdEncoding.EncodeToString(g.state.DevicePub),
		IssuedAt:     issuedAt.Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(cert.Signature),
	}, nil
}
