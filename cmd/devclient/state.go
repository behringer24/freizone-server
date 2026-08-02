package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/behringer24/freizone-server/pkg/group"
	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// OTPKState is one uploaded one-time prekey's key pair, kept locally until
// it's actually consumed by a peer (the server never tells the uploader
// which one gets claimed).
type OTPKState struct {
	Pub  []byte `json:"pub"`
	Priv []byte `json:"priv"`
}

// State is devclient's entire local identity and conversation state,
// persisted as JSON under -datadir.
type State struct {
	Server    string `json:"server"`
	AccountID string `json:"account_id"`

	RootPub  []byte `json:"root_pub"`
	RootPriv []byte `json:"root_priv"`

	DeviceID   string `json:"device_id"`
	DevicePub  []byte `json:"device_pub"`
	DevicePriv []byte `json:"device_priv"`

	DHIdentityPub  []byte `json:"dh_identity_pub,omitempty"`
	DHIdentityPriv []byte `json:"dh_identity_priv,omitempty"`

	SignedPrekeyID   uint32 `json:"signed_prekey_id"`
	SignedPrekeyPub  []byte `json:"signed_prekey_pub,omitempty"`
	SignedPrekeyPriv []byte `json:"signed_prekey_priv,omitempty"`

	NextSignedPrekeyID uint32               `json:"next_signed_prekey_id"`
	NextOTPKKeyID      uint32               `json:"next_otpk_key_id"`
	OneTimePrekeys     map[uint32]OTPKState `json:"one_time_prekeys,omitempty"`

	// Sessions is keyed by peer account id. This dev tool assumes a single
	// active device per peer, which is enough for a local two-person demo.
	Sessions map[string]*ratchet.Session `json:"sessions,omitempty"`

	// InboundSessions holds sessions kept only for READING, keyed by peer.
	//
	// Two people who establish a session with each other at the same moment
	// each end up holding their own initiator session, and neither can read
	// the other's. That is rare in a one-to-one chat, where somebody speaks
	// first, and routine in a group, where a new member and every existing
	// member reach for each other simultaneously. A deterministic tie-break
	// decides which session both sides will *send* on (see group_watch.go);
	// the losing one is kept here rather than discarded, so the messages
	// already in flight on it can still be read instead of being stranded.
	InboundSessions map[string]*ratchet.Session `json:"inbound_sessions,omitempty"`

	// Groups is keyed by group id (SRV-01). The value is the signed fact set;
	// membership, roles and the state hash are derived from it on every read
	// rather than stored, so there is no second representation that could
	// disagree with the events. Unmarshalling re-verifies every event, so a
	// hand-edited state file fails to load rather than loading a lie.
	Groups map[string]*group.State `json:"groups,omitempty"`
}

func statePath(dataDir string) string {
	return filepath.Join(dataDir, "state.json")
}

// LoadState reads state from path.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading state file %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing state file %s: %w", path, err)
	}
	if s.OneTimePrekeys == nil {
		s.OneTimePrekeys = make(map[uint32]OTPKState)
	}
	if s.Sessions == nil {
		s.Sessions = make(map[string]*ratchet.Session)
	}
	if s.InboundSessions == nil {
		s.InboundSessions = make(map[string]*ratchet.Session)
	}
	if s.Groups == nil {
		s.Groups = make(map[string]*group.State)
	}
	return &s, nil
}

// Save writes state to path, creating its parent directory if needed.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing state file %s: %w", path, err)
	}
	return nil
}
