package conformance

import (
	"testing"

	"github.com/behringer24/freizone-server/pkg/wire"
)

// TestVectorsAreWellFormed checks the committed testdata itself, so a broken
// vector fails here rather than showing up as a mysterious failure in every
// implementation that consumes it.
func TestVectorsAreWellFormed(t *testing.T) {
	vectors, err := Load("testdata")
	if err != nil {
		t.Fatalf("loading vectors: %v", err)
	}

	names := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if names[v.Name] {
			t.Errorf("duplicate vector name %q", v.Name)
		}
		names[v.Name] = true

		t.Run(v.Name, func(t *testing.T) {
			if v.Description == "" {
				t.Error("no description -- a vector nobody can argue from is not a vector")
			}
			if _, err := v.Receiver.DHIdentityKey(); err != nil {
				t.Errorf("receiver dh identity key: %v", err)
			}
			if _, err := v.Receiver.SignedPrekey(); err != nil {
				t.Errorf("receiver signed prekey: %v", err)
			}
			for id := range v.Receiver.OneTimePrekeys {
				if _, err := v.Receiver.OneTimePrekey(id); err != nil {
					t.Errorf("one-time prekey %d: %v", id, err)
				}
			}
			for peer := range v.Receiver.Sessions {
				s, err := v.Receiver.Session(peer)
				if err != nil {
					t.Errorf("session with %s: %v", peer, err)
				} else if s == nil {
					t.Errorf("session with %s is empty", peer)
				}
			}
			for peer := range v.Receiver.InboundSessions {
				if _, err := v.Receiver.InboundSession(peer); err != nil {
					t.Errorf("inbound session with %s: %v", peer, err)
				}
			}
			for i, step := range v.Steps {
				env, err := wire.ParseEnvelope(step.Payload)
				if err != nil {
					t.Errorf("step %d (%s): payload is not a wire envelope: %v", i+1, step.Label, err)
					continue
				}
				if _, err := env.Header.ToHeader(); err != nil {
					t.Errorf("step %d (%s): bad header: %v", i+1, step.Label, err)
				}
				if _, err := env.DecodeCiphertext(); err != nil {
					t.Errorf("step %d (%s): bad ciphertext: %v", i+1, step.Label, err)
				}
				if step.Expect.Outcome == OutcomeDecrypted && step.Expect.SessionEffect == "" {
					t.Errorf("step %d (%s): a decrypted step should pin a session effect", i+1, step.Label)
				}
			}
		})
	}
}

// TestVectorsCoverTheDivergences is a coverage guard, not a behaviour test: the
// vectors exist because these specific decisions are implemented twice today
// (SRV-23). If one is dropped, the suite silently stops watching it.
func TestVectorsCoverTheDivergences(t *testing.T) {
	vectors, err := Load("testdata")
	if err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
	have := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		have[v.Name] = true
	}
	for _, want := range []string{
		"first-contact-establishes-session",
		"redelivered-initial-must-not-reset-session",
		"failed-responder-attempt-must-not-burn-prekey",
		"duplicate-ordinary-message-is-not-desync-evidence",
		"authentication-failure-is-desync-evidence",
		"race-lower-peer-account-id-wins",
		"race-higher-peer-account-id-loses-but-stays-readable",
		"deliberate-rekey-wins-against-tie-break",
		"legacy-rekey-inferred-from-plaintext",
	} {
		if !have[want] {
			t.Errorf("vector %q is missing", want)
		}
	}
}
