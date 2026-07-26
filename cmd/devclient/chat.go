package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// pendingSend records one text message this client sent, so an incoming
// receipt (a cumulative up_to_sent_at high-water mark) can be resolved back to
// a per-message roundtrip time measured on this client's own clock.
type pendingSend struct {
	sentAt        time.Time // the sent_at we stamped into the envelope (our clock)
	mono          time.Time // send instant, for time.Since (Go monotonic clock)
	text          string
	deliveredDone bool
	readDone      bool
}

// chatSession bundles everything one interactive chat needs: the persisted
// identity/ratchet state, the resolved peer, and the shared lock. The lock
// serializes all ratchet Encrypt/Decrypt (which mutate session state and are
// not concurrency-safe) across the interactive send goroutine and the receive
// goroutine.
type chatSession struct {
	state         *State
	path          string
	mu            sync.Mutex
	peerAccountID string
	peerServer    string // "" for same-server; a base URL for a federated peer
	peerDeviceID  string
	peerDevicePub ed25519.PublicKey
	receiptsMode  string // "both" | "delivered" | "off"
	autoReply     bool
	pending       []*pendingSend
}

func runChat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	to := fs.String("to", "", "peer account id to chat with")
	toServer := fs.String("to-server", "", "peer's home server, if different from this account's own -- federated delivery (see docs/PROTOCOL.md §9), posted directly to that server's /v1/federation/messages")
	autoReply := fs.Bool("auto-reply", false, "automatically answer every incoming text with a random short lorem-ipsum reply, so this instance can be tested without a human typing into it")
	receipts := fs.String("receipts", "both", "which receipts to send for received texts: both|delivered|off")
	verboseFlag := fs.Bool("verbose", false, "log every request to the server (not just chat messages)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return fmt.Errorf("chat: -to is required")
	}
	switch *receipts {
	case "both", "delivered", "off":
	default:
		return fmt.Errorf("chat: -receipts must be both|delivered|off, got %q", *receipts)
	}
	verbose = *verboseFlag

	path := statePath(*dataDir)
	state, err := LoadState(path)
	if err != nil {
		return err
	}

	if len(state.SignedPrekeyPriv) == 0 {
		fmt.Println("No prekeys uploaded yet -- uploading now...")
		if err := uploadPrekeys(state, defaultOneTimePrekeyBatch); err != nil {
			return err
		}
		if err := state.Save(path); err != nil {
			return err
		}
	}

	resolveServer := state.Server
	if *toServer != "" {
		resolveServer = *toServer
	}
	// peerAccountID is the server's fully-resolved id, NOT necessarily *to
	// verbatim -- the account lookup accepts a short prefix, but every
	// certificate is signed over the FULL id (see resolvePeerDevice).
	peerAccountID, peerDeviceID, peerDevicePubKey, err := resolvePeerDevice(resolveServer, *to)
	if err != nil {
		return fmt.Errorf("resolving peer: %w", err)
	}

	cs := &chatSession{
		state:         state,
		path:          path,
		peerAccountID: peerAccountID,
		peerServer:    *toServer,
		peerDeviceID:  peerDeviceID,
		peerDevicePub: peerDevicePubKey,
		receiptsMode:  *receipts,
		autoReply:     *autoReply,
	}

	mode := "receipts " + *receipts
	if *autoReply {
		mode += ", auto-reply on"
	}
	if *toServer != "" {
		fmt.Printf("Chatting as %s with %s*%s (federated; %s). Type a message and press enter; Ctrl+C to quit.\n", state.AccountID, peerAccountID, *toServer, mode)
	} else {
		fmt.Printf("Chatting as %s with %s (%s). Type a message and press enter; Ctrl+C to quit.\n", state.AccountID, peerAccountID, mode)
	}

	stop := make(chan struct{})
	go cs.receiveLoop(stop)

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			fmt.Print("> ")
			continue
		}
		cs.mu.Lock()
		err := cs.sendText(text)
		if err == nil {
			err = cs.state.Save(cs.path)
		}
		cs.mu.Unlock()
		if err != nil {
			fmt.Fprintln(os.Stderr, "send error:", err)
		}
		fmt.Print("> ")
	}
	close(stop)
	return scanner.Err()
}

// sendText wraps text in a v1 envelope, sends it, and records it for roundtrip
// timing. Caller must hold cs.mu.
func (cs *chatSession) sendText(text string) error {
	plaintext, sentAtStr, err := encodeText(text)
	if err != nil {
		return err
	}
	start := time.Now()
	if err := cs.send(plaintext, "text"); err != nil {
		return err
	}
	sentAt, perr := time.Parse(time.RFC3339Nano, sentAtStr)
	if perr != nil {
		sentAt = start.UTC()
	}
	cs.pending = append(cs.pending, &pendingSend{sentAt: sentAt, mono: start, text: text})
	return nil
}

// sendReceipt sends a delivered/read receipt for a received text, honoring the
// -receipts mode. Caller must hold cs.mu.
func (cs *chatSession) sendReceipt(status, upToSentAt string) {
	if cs.receiptsMode == "off" {
		return
	}
	if status == "read" && cs.receiptsMode == "delivered" {
		return
	}
	plaintext, err := encodeReceipt(status, upToSentAt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "receipt encode error:", err)
		return
	}
	if err := cs.send(plaintext, "receipt:"+status); err != nil {
		fmt.Fprintln(os.Stderr, "receipt send error:", err)
	}
}

// send is the single chokepoint every outbound message goes through: encrypt,
// wrap in a wire.Envelope, build the (same-server or federated) request, print
// the cleartext + the actually-sent package, POST it, and print the HTTP
// result. Caller must hold cs.mu (Encrypt mutates ratchet state).
func (cs *chatSession) send(plaintext []byte, label string) error {
	session, initial, err := getOrCreateSession(cs.state, cs.peerAccountID, cs.peerServer, cs.peerDeviceID, cs.peerDevicePub)
	if err != nil {
		return err
	}
	header, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encrypting message: %w", err)
	}
	payload, err := wire.NewEnvelope(initial, header, ciphertext).MarshalPayload()
	if err != nil {
		return err
	}
	msgID, err := randomMessageID()
	if err != nil {
		return err
	}

	var body []byte
	var path string
	var doSend func() (*http.Response, error)
	if cs.peerServer == "" {
		body, err = json.Marshal(sendMessageRequest{MessageID: msgID, RecipientDeviceID: cs.peerDeviceID, Payload: payload})
		path = "/v1/messages"
		doSend = func() (*http.Response, error) { return signedRequest(cs.state, http.MethodPost, path, body) }
	} else {
		issuedAt := time.Now().UTC()
		cert, cerr := devicecert.SignDeviceCertificate(cs.state.AccountID, cs.state.DeviceID, ed25519.PublicKey(cs.state.DevicePub), issuedAt, ed25519.PrivateKey(cs.state.RootPriv))
		if cerr != nil {
			return fmt.Errorf("signing device certificate: %w", cerr)
		}
		body, err = json.Marshal(federationMessageRequest{
			SenderAccountID:  cs.state.AccountID,
			SenderRootPubKey: base64.StdEncoding.EncodeToString(cs.state.RootPub),
			SenderDeviceCert: federationDeviceCertDTO{
				DeviceID:     cs.state.DeviceID,
				DevicePubKey: base64.StdEncoding.EncodeToString(cs.state.DevicePub),
				IssuedAt:     issuedAt.Format(time.RFC3339),
				Signature:    base64.StdEncoding.EncodeToString(cert.Signature),
			},
			RecipientDeviceID: cs.peerDeviceID,
			MessageID:         msgID,
			Payload:           payload,
		})
		path = "/v1/federation/messages"
		doSend = func() (*http.Response, error) {
			return federatedSignedRequest(cs.state, cs.peerServer, http.MethodPost, path, body)
		}
	}
	if err != nil {
		return fmt.Errorf("building send request: %w", err)
	}

	// Show the generated cleartext and the actually-sent package.
	fmt.Printf("\r[sent →%s] (%s)\n", shortID(cs.peerAccountID), label)
	fmt.Printf("   cleartext: %s\n", string(plaintext))
	fmt.Printf("   package:   %s\n", string(payload))

	start := time.Now()
	resp, err := doSend()
	if err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()
	dur := time.Since(start).Round(time.Millisecond)
	if resp.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp.Body)
		fmt.Printf("   http:      POST %s → %s\n", path, resp.Status)
		return fmt.Errorf("send failed: %s: %s", resp.Status, data)
	}
	fmt.Printf("   http:      POST %s → %d (%s)\n", path, resp.StatusCode, dur)
	return nil
}

// resolveRTT matches an incoming receipt (a cumulative up_to_sent_at mark)
// against still-pending sends and prints the per-message roundtrip. Caller
// must hold cs.mu.
func (cs *chatSession) resolveRTT(status, upToSentAtStr string) {
	upTo, err := time.Parse(time.RFC3339Nano, upToSentAtStr)
	if err != nil {
		return
	}
	for _, p := range cs.pending {
		if p.sentAt.After(upTo) {
			continue
		}
		switch status {
		case "delivered":
			if !p.deliveredDone {
				p.deliveredDone = true
				fmt.Printf("\r   [rtt] delivered in %s (%q)\n", time.Since(p.mono).Round(time.Millisecond), p.text)
			}
		case "read":
			if !p.readDone {
				p.readDone = true
				fmt.Printf("\r   [rtt] read in %s (%q)\n", time.Since(p.mono).Round(time.Millisecond), p.text)
			}
		}
	}
}

// receiveLoop holds an SSE connection open, reconnecting on failure.
func (cs *chatSession) receiveLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := cs.streamMessages(stop); err != nil {
			fmt.Fprintln(os.Stderr, "\nstream error, retrying in 3s:", err)
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (cs *chatSession) streamMessages(stop <-chan struct{}) error {
	req, err := newSignedStreamRequest(cs.state, "/v1/messages/stream")
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("opening stream failed: %s: %s", resp.Status, data)
	}

	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-stop:
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(strings.TrimSpace(line), "data: ")

		var msg messageResponse
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			fmt.Fprintln(os.Stderr, "\ndecode error:", err)
			continue
		}

		cs.handleMessage(msg)
	}
}

// handleMessage decrypts one incoming message and dispatches on its type.
// Receipts are consumed (roundtrip resolved) and NEVER answered -- this is the
// loop-prevention rule. Text is displayed, acknowledged with delivered/read
// receipts, and (if -auto-reply) answered with a lorem-ipsum text.
func (cs *chatSession) handleMessage(msg messageResponse) {
	cs.mu.Lock()
	defer func() {
		if err := cs.state.Save(cs.path); err != nil {
			fmt.Fprintln(os.Stderr, "save error:", err)
		}
		cs.mu.Unlock()
		fmt.Print("> ")
	}()

	decoded, err := cs.decrypt(msg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\ndecrypt error:", err)
		return
	}

	// Always drain the message from the server queue, whatever its type.
	go ackMessage(cs.state, msg.MessageID)

	if verbose {
		fmt.Printf("\r   package:   %s\n", string(msg.Payload))
	}

	switch decoded.kind {
	case decodedReceipt:
		fmt.Printf("\r[receipt ←%s] %s up_to %s\n", shortID(msg.SenderAccountID), decoded.status, decoded.upToSentAt)
		cs.resolveRTT(decoded.status, decoded.upToSentAt)
		// Loop-prevention: a receipt is never itself acknowledged.
		return

	case decodedText:
		fmt.Printf("\r[recv ←%s] %s\n", shortID(msg.SenderAccountID), decoded.text)

		if msg.SenderAccountID == cs.peerAccountID {
			upTo := decoded.sentAt
			if upTo == "" {
				upTo = time.Now().UTC().Format(receiptTimeLayout)
			}
			cs.sendReceipt("delivered", upTo)
			cs.sendReceipt("read", upTo)

			if cs.autoReply {
				if err := cs.sendText(randomLoremReply(decoded.text)); err != nil {
					fmt.Fprintln(os.Stderr, "auto-reply send error:", err)
				}
			}
		}
	}
}

// decrypt parses and decrypts msg, establishing a responder session first if
// needed. Caller must hold cs.mu.
func (cs *chatSession) decrypt(msg messageResponse) (decodedPlaintext, error) {
	env, err := wire.ParseEnvelope(msg.Payload)
	if err != nil {
		return decodedPlaintext{}, err
	}
	header, err := env.Header.ToHeader()
	if err != nil {
		return decodedPlaintext{}, err
	}
	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return decodedPlaintext{}, err
	}

	session, ok := cs.state.Sessions[msg.SenderAccountID]
	if !ok {
		if env.Prekey == nil {
			return decodedPlaintext{}, fmt.Errorf("no session with %s and message carries no x3dh fields", msg.SenderAccountID)
		}
		session, err = respondToNewSession(cs.state, env.Prekey)
		if err != nil {
			return decodedPlaintext{}, err
		}
		if cs.state.Sessions == nil {
			cs.state.Sessions = make(map[string]*ratchet.Session)
		}
		cs.state.Sessions[msg.SenderAccountID] = session
	}

	plaintext, err := session.Decrypt(header, ciphertext)
	if err != nil {
		return decodedPlaintext{}, fmt.Errorf("decrypting message: %w", err)
	}
	return decodePlaintext(plaintext), nil
}

// getOrCreateSession returns the existing session with peerAccountID, or
// establishes a new one as X3DH initiator by claiming the peer's prekey
// bundle. Callers must hold the state's lock.
func getOrCreateSession(state *State, peerAccountID, peerServer, peerDeviceID string, peerDevicePubKey ed25519.PublicKey) (*ratchet.Session, *ratchet.InitialMessage, error) {
	if s, ok := state.Sessions[peerAccountID]; ok {
		return s, nil, nil
	}

	bundleServer := peerServer
	if bundleServer == "" {
		bundleServer = state.Server
	}
	bundle, err := claimPrekeyBundle(bundleServer, peerDeviceID)
	if err != nil {
		return nil, nil, err
	}
	remote, err := bundleToRemoteBundle(bundle, peerAccountID, peerDeviceID, peerDevicePubKey)
	if err != nil {
		return nil, nil, err
	}

	dhPriv, err := ecdh.X25519().NewPrivateKey(state.DHIdentityPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("loading local dh identity key: %w", err)
	}

	session, initial, err := ratchet.InitiateSession(dhPriv, remote)
	if err != nil {
		return nil, nil, fmt.Errorf("initiating x3dh session: %w", err)
	}

	if state.Sessions == nil {
		state.Sessions = make(map[string]*ratchet.Session)
	}
	state.Sessions[peerAccountID] = session
	return session, initial, nil
}

func respondToNewSession(state *State, prekeyFields *wire.PrekeyFields) (*ratchet.Session, error) {
	initial, err := prekeyFields.ToInitialMessage()
	if err != nil {
		return nil, err
	}

	curve := ecdh.X25519()
	dhPriv, err := curve.NewPrivateKey(state.DHIdentityPriv)
	if err != nil {
		return nil, fmt.Errorf("loading local dh identity key: %w", err)
	}
	spkPriv, err := curve.NewPrivateKey(state.SignedPrekeyPriv)
	if err != nil {
		return nil, fmt.Errorf("loading local signed prekey: %w", err)
	}

	var otpkPriv *ecdh.PrivateKey
	if initial.OneTimePrekeyID != nil {
		if stored, ok := state.OneTimePrekeys[*initial.OneTimePrekeyID]; ok {
			otpkPriv, err = curve.NewPrivateKey(stored.Priv)
			if err != nil {
				return nil, fmt.Errorf("loading one-time prekey: %w", err)
			}
			delete(state.OneTimePrekeys, *initial.OneTimePrekeyID)
		}
	}

	return ratchet.RespondToSession(dhPriv, spkPriv, otpkPriv, initial)
}

// ackMessage best-effort deletes a message from the server queue once it's been
// decrypted; failure just means redelivery on reconnect, which is harmless.
func ackMessage(state *State, messageID string) {
	resp, err := signedRequest(state, http.MethodDelete, "/v1/messages/"+messageID, nil)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// shortID trims an account id to its short display prefix.
func shortID(id string) string {
	if len(id) > 5 {
		return id[:5]
	}
	return id
}

// loremWords is a small classic lorem-ipsum word bank -- randomLoremReply
// picks a handful of these so two devclient instances can hold a
// plausible-looking conversation unattended while testing.
var loremWords = []string{
	"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
	"sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
	"magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
	"exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
	"consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
	"velit", "esse", "cillum", "eu", "fugiat", "nulla", "pariatur",
}

// randomLoremReply builds a short (3-8 word) random lorem-ipsum sentence with
// received appended in parentheses, so the reply is both obviously
// auto-generated and traceable back to what triggered it.
func randomLoremReply(received string) string {
	n := 3 + rand.Intn(6)
	words := make([]string, n)
	for i := range words {
		words[i] = loremWords[rand.Intn(len(loremWords))]
	}
	sentence := strings.Join(words, " ")
	sentence = strings.ToUpper(sentence[:1]) + sentence[1:] + "."
	return fmt.Sprintf("%s (%s)", sentence, received)
}
