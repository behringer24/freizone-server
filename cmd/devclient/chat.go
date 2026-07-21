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

func runChat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	to := fs.String("to", "", "peer account id to chat with")
	toServer := fs.String("to-server", "", "peer's home server, if different from this account's own -- federated delivery (see docs/PROTOCOL.md §9), posted directly to that server's /v1/federation/messages")
	autoReply := fs.Bool("auto-reply", false, "automatically answer every incoming message with a random short lorem-ipsum reply, so this instance can be tested without a human typing into it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return fmt.Errorf("chat: -to is required")
	}

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

	peerServer := *toServer
	resolveServer := state.Server
	if peerServer != "" {
		resolveServer = peerServer
	}
	// peerAccountID is the server's fully-resolved id, NOT necessarily
	// *to verbatim -- the account lookup accepts a short prefix (e.g.
	// "qsvfg" for "qsvfgwuwvtdsr7hej0yag"), but every certificate this
	// account is party to (the DeviceCertificate resolvePeerDevice itself
	// verifies, and every X3DH cert bundleToRemoteBundle verifies when a
	// session actually gets established below) is signed over the FULL
	// id. Using the unresolved prefix for those would silently fail
	// signature verification even for a perfectly valid certificate --
	// see resolvePeerDevice's doc comment.
	peerAccountID, peerDeviceID, peerDevicePubKey, err := resolvePeerDevice(resolveServer, *to)
	if err != nil {
		return fmt.Errorf("resolving peer: %w", err)
	}

	var mu sync.Mutex
	save := func() error {
		mu.Lock()
		defer mu.Unlock()
		return state.Save(path)
	}

	if peerServer != "" {
		fmt.Printf("Chatting as %s with %s*%s (federated). Type a message and press enter; Ctrl+C to quit.\n", state.AccountID, peerAccountID, peerServer)
	} else if *autoReply {
		fmt.Printf("Chatting as %s with %s (auto-reply on). Type a message and press enter; Ctrl+C to quit.\n", state.AccountID, peerAccountID)
	} else {
		fmt.Printf("Chatting as %s with %s. Type a message and press enter; Ctrl+C to quit.\n", state.AccountID, peerAccountID)
	}

	stop := make(chan struct{})
	go receiveLoop(state, &mu, save, stop, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey, *autoReply)

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			fmt.Print("> ")
			continue
		}

		mu.Lock()
		err := sendToPeer(state, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey, text)
		mu.Unlock()
		if err != nil {
			fmt.Fprintln(os.Stderr, "send error:", err)
		} else if err := save(); err != nil {
			fmt.Fprintln(os.Stderr, "save error:", err)
		}
		fmt.Print("> ")
	}
	close(stop)
	return scanner.Err()
}

// sendToPeer sends text to peerAccountID via the ordinary same-server
// path, or federated delivery if peerServer names a different server
// than this account's own -- see docs/PROTOCOL.md §9. Callers must hold
// mu.
func sendToPeer(state *State, peerAccountID, peerServer, peerDeviceID string, peerDevicePubKey ed25519.PublicKey, text string) error {
	if peerServer == "" {
		return sendChatMessage(state, peerAccountID, peerDeviceID, peerDevicePubKey, text)
	}
	return sendFederatedChatMessage(state, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey, text)
}

// sendChatMessage encrypts and sends one chat message to peerAccountID.
// Callers must hold mu.
func sendChatMessage(state *State, peerAccountID, peerDeviceID string, peerDevicePubKey ed25519.PublicKey, text string) error {
	session, initial, err := getOrCreateSession(state, peerAccountID, "", peerDeviceID, peerDevicePubKey)
	if err != nil {
		return err
	}

	header, ciphertext, err := session.Encrypt([]byte(text))
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

	body, err := json.Marshal(sendMessageRequest{MessageID: msgID, RecipientDeviceID: peerDeviceID, Payload: payload})
	if err != nil {
		return fmt.Errorf("building send request: %w", err)
	}

	resp, err := signedRequest(state, http.MethodPost, "/v1/messages", body)
	if err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send failed: %s: %s", resp.Status, data)
	}
	return nil
}

// sendFederatedChatMessage encrypts and sends text directly to
// peerServer's POST /v1/federation/messages -- see docs/PROTOCOL.md §9.
// Unlike sendChatMessage, the request carries this device's own
// certificate inline, freshly re-signed (nothing requires re-using the
// one cached at registration time), since peerServer has no local row to
// look this device up in. Callers must hold mu.
func sendFederatedChatMessage(state *State, peerAccountID, peerServer, peerDeviceID string, peerDevicePubKey ed25519.PublicKey, text string) error {
	session, initial, err := getOrCreateSession(state, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey)
	if err != nil {
		return err
	}

	header, ciphertext, err := session.Encrypt([]byte(text))
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

	issuedAt := time.Now().UTC()
	cert, err := devicecert.SignDeviceCertificate(state.AccountID, state.DeviceID, ed25519.PublicKey(state.DevicePub), issuedAt, ed25519.PrivateKey(state.RootPriv))
	if err != nil {
		return fmt.Errorf("signing device certificate: %w", err)
	}

	body, err := json.Marshal(federationMessageRequest{
		SenderAccountID:  state.AccountID,
		SenderRootPubKey: base64.StdEncoding.EncodeToString(state.RootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     state.DeviceID,
			DevicePubKey: base64.StdEncoding.EncodeToString(state.DevicePub),
			IssuedAt:     issuedAt.Format(time.RFC3339),
			Signature:    base64.StdEncoding.EncodeToString(cert.Signature),
		},
		RecipientDeviceID: peerDeviceID,
		MessageID:         msgID,
		Payload:           payload,
	})
	if err != nil {
		return fmt.Errorf("building federated send request: %w", err)
	}

	resp, err := federatedSignedRequest(state, peerServer, http.MethodPost, "/v1/federation/messages", body)
	if err != nil {
		return fmt.Errorf("sending federated message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("federated send failed: %s: %s", resp.Status, data)
	}
	return nil
}

// getOrCreateSession returns the existing session with peerAccountID, or
// establishes a new one as X3DH initiator by claiming the peer's prekey
// bundle -- from peerServer if given (a federated peer), or this
// account's own server otherwise. Callers must hold the state's lock.
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

// receiveLoop holds an SSE connection open, reconnecting on failure, and
// prints/decrypts incoming messages as they arrive. If autoReply is set,
// every message received from peerAccountID is answered automatically
// with a random short lorem-ipsum reply -- see sendAutoReply.
func receiveLoop(
	state *State,
	mu *sync.Mutex,
	save func() error,
	stop <-chan struct{},
	peerAccountID, peerServer, peerDeviceID string,
	peerDevicePubKey ed25519.PublicKey,
	autoReply bool,
) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := streamMessages(state, mu, save, stop, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey, autoReply); err != nil {
			fmt.Fprintln(os.Stderr, "\nstream error, retrying in 3s:", err)
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func streamMessages(
	state *State,
	mu *sync.Mutex,
	save func() error,
	stop <-chan struct{},
	peerAccountID, peerServer, peerDeviceID string,
	peerDevicePubKey ed25519.PublicKey,
	autoReply bool,
) error {
	req, err := newSignedStreamRequest(state, "/v1/messages/stream")
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
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

		mu.Lock()
		plaintext, err := handleIncomingMessage(state, msg)
		mu.Unlock()
		if err != nil {
			fmt.Fprintln(os.Stderr, "\ndecrypt error:", err)
			continue
		}

		fmt.Printf("\r%s\n> ", fmt.Sprintf("[%s] %s", msg.SenderAccountID, plaintext))

		go ackMessage(state, msg.MessageID)

		if err := save(); err != nil {
			fmt.Fprintln(os.Stderr, "save error:", err)
		}

		if autoReply && msg.SenderAccountID == peerAccountID {
			reply := randomLoremReply(plaintext)
			mu.Lock()
			err := sendToPeer(state, peerAccountID, peerServer, peerDeviceID, peerDevicePubKey, reply)
			mu.Unlock()
			if err != nil {
				fmt.Fprintln(os.Stderr, "\nauto-reply send error:", err)
			} else {
				fmt.Printf("\r[auto-reply] %s\n> ", reply)
				if err := save(); err != nil {
					fmt.Fprintln(os.Stderr, "save error:", err)
				}
			}
		}
	}
}

// loremWords is a small classic lorem-ipsum word bank -- randomLoremReply
// picks a handful of these to stand in for an actual reply, purely so
// two devclient instances can hold a plausible-looking conversation
// unattended while testing.
var loremWords = []string{
	"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
	"sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
	"magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
	"exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
	"consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
	"velit", "esse", "cillum", "eu", "fugiat", "nulla", "pariatur",
}

// randomLoremReply builds a short (3-8 word) random lorem-ipsum sentence
// with received appended in parentheses, so the reply is both
// obviously auto-generated and traceable back to what triggered it.
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

// handleIncomingMessage decrypts msg, establishing a new session as X3DH
// responder first if needed. Callers must hold the state's lock.
func handleIncomingMessage(state *State, msg messageResponse) (string, error) {
	env, err := wire.ParseEnvelope(msg.Payload)
	if err != nil {
		return "", err
	}
	header, err := env.Header.ToHeader()
	if err != nil {
		return "", err
	}
	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return "", err
	}

	session, ok := state.Sessions[msg.SenderAccountID]
	if !ok {
		if env.Prekey == nil {
			return "", fmt.Errorf("no session with %s and message carries no x3dh fields", msg.SenderAccountID)
		}
		session, err = respondToNewSession(state, env.Prekey)
		if err != nil {
			return "", err
		}
		if state.Sessions == nil {
			state.Sessions = make(map[string]*ratchet.Session)
		}
		state.Sessions[msg.SenderAccountID] = session
	}

	plaintext, err := session.Decrypt(header, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting message: %w", err)
	}
	return string(plaintext), nil
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

// ackMessage best-effort deletes a message from the server queue once it's
// been decrypted; failure just means it'll be redelivered on next poll or
// reconnect, which is harmless (idempotent from the client's perspective).
func ackMessage(state *State, messageID string) {
	resp, err := signedRequest(state, http.MethodDelete, "/v1/messages/"+messageID, nil)
	if err != nil {
		return
	}
	resp.Body.Close()
}
