package main

import (
	"crypto/ecdh"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/behringer24/freizone-server/pkg/conformance"
	"github.com/behringer24/freizone-server/pkg/group"
	"github.com/behringer24/freizone-server/pkg/ratchet"
)

const conformanceVectorDir = "../../pkg/conformance/testdata"

// knownDivergences records, per "<vector>/<step>", where this client knowingly
// departs from the shared receive-path vectors (SRV-23). Entries keep the suite
// green without hiding anything: a listed step that starts conforming fails the
// test with "remove it from the list", so the list cannot rot into a set of
// stale excuses, and a listed step that no vector produces fails too.
//
// These are real defects, not stylistic differences -- see
// docs/design/23-shared-client-core.md. They exist because the orchestration
// around pkg/ratchet is implemented twice, which is what SRV-23 removes: the
// list should empty out as pkg/client takes over, not be worked around here.
var knownDivergences = map[string]string{
	"redelivered-initial-must-not-reset-session/the initial is redelivered": "" +
		"no processed-message-id tracking exists here, so a redelivered first envelope is " +
		"processed a second time: the responder step runs again, the rewound session replaces " +
		"the advanced one, and the message is reported as newly decrypted rather than as a " +
		"duplicate. freizone-app guards this with AppState.processedMessageIds",

	"duplicate-ordinary-message-is-not-desync-evidence/same message redelivered": "" +
		"the ratchet does reject the duplicate, but decryptIncoming discards that error and " +
		"returns a generic \"no session decrypts this message\", so a harmless redelivery is " +
		"indistinguishable from a real desync",

	"authentication-failure-is-desync-evidence/corrupted ciphertext": "" +
		"pkg/ratchet classifies this as FailureAuthentication and SuggestsDesync reports true, " +
		"but decryptIncoming wraps the error with fmt.Errorf and no %w, so the classification " +
		"is lost. There is also no desync accounting to feed it into (SRV-03 is app-only)",

	"failed-responder-attempt-must-not-burn-prekey/damaged first contact": "" +
		"respondToNewSession deletes the one-time prekey from state before RespondToSession is " +
		"even called, so any initial that fails to decrypt still costs a prekey. freizone-app " +
		"looks the key up and consumes it only once a session built from it has decrypted",

	"legacy-rekey-inferred-from-plaintext/peer's own initial arrives": "" +
		"a prekey block without the SRV-17 rekey field is always treated as the racing case. " +
		"freizone-app falls back to inferring the re-key from the decrypted content being a " +
		"v:3 re-key signal -- a plaintext version this client does not model at all, so it " +
		"renders the control envelope as legacy raw text as well",
}

func TestReceivePathConformance(t *testing.T) {
	vectors, err := conformance.Load(conformanceVectorDir)
	if err != nil {
		t.Fatalf("loading conformance vectors: %v", err)
	}

	matched := make(map[string]bool, len(knownDivergences))
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			st := stateFromReceiver(t, v.Receiver)
			for i, step := range v.Steps {
				key := v.Name + "/" + step.Label
				problems := runConformanceStep(st, step)
				reason, known := knownDivergences[key]
				switch {
				case known:
					matched[key] = true
					if len(problems) == 0 {
						t.Errorf("step %d (%s): listed as a known divergence (%s) but now conforms -- remove it from knownDivergences", i+1, step.Label, reason)
						continue
					}
					t.Logf("known divergence, step %d (%s) -- %s:\n    %s", i+1, step.Label, reason, strings.Join(problems, "\n    "))
				case len(problems) > 0:
					t.Errorf("step %d (%s):\n    %s", i+1, step.Label, strings.Join(problems, "\n    "))
				}
			}
		})
	}

	var stale []string
	for key := range knownDivergences {
		if !matched[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("knownDivergences lists %q, but no vector has a step by that name", key)
	}
}

// stateFromReceiver primes a devclient State from a vector's protocol-level
// receiver description.
func stateFromReceiver(t *testing.T, r conformance.Receiver) *State {
	t.Helper()

	st := &State{
		AccountID:        r.AccountID,
		DHIdentityPriv:   r.DHIdentityPriv,
		SignedPrekeyPriv: r.SignedPrekeyPriv,
		SignedPrekeyID:   1,
		OneTimePrekeys:   make(map[uint32]OTPKState),
		Sessions:         make(map[string]*ratchet.Session),
		InboundSessions:  make(map[string]*ratchet.Session),
		Groups:           make(map[string]*group.State),
	}

	curve := ecdh.X25519()
	for id, priv := range r.OneTimePrekeys {
		k, err := curve.NewPrivateKey(priv)
		if err != nil {
			t.Fatalf("one-time prekey %d: %v", id, err)
		}
		st.OneTimePrekeys[id] = OTPKState{Pub: k.PublicKey().Bytes(), Priv: priv}
	}
	for peer := range r.Sessions {
		s, err := r.Session(peer)
		if err != nil {
			t.Fatalf("session with %s: %v", peer, err)
		}
		st.Sessions[peer] = s
	}
	for peer := range r.InboundSessions {
		s, err := r.InboundSession(peer)
		if err != nil {
			t.Fatalf("inbound session with %s: %v", peer, err)
		}
		st.InboundSessions[peer] = s
	}
	// ProcessedMessageIDs is deliberately dropped: this client has no such
	// concept, which is itself one of the things the vectors surface.
	return st
}

// runConformanceStep feeds one envelope through decryptIncoming and returns a
// description of every way the result missed the vector's expectation. Empty
// means conforming.
func runConformanceStep(st *State, step conformance.Step) []string {
	peer := step.SenderAccountID
	roleBefore := sessionRole(st.Sessions[peer])

	decoded, err := decryptIncoming(st, messageResponse{
		MessageID:       step.MessageID,
		SenderAccountID: peer,
		Payload:         step.Payload,
	})

	roleAfter := sessionRole(st.Sessions[peer])
	want := step.Expect
	var problems []string

	gotOutcome := conformance.OutcomeDecrypted
	gotCode := ""
	if err != nil {
		gotCode = ratchet.FailureCode(err)
		if gotCode == ratchet.FailureDuplicateMessage {
			gotOutcome = conformance.OutcomeDuplicate
		} else {
			gotOutcome = conformance.OutcomeUndecryptable
		}
	}
	if gotOutcome != want.Outcome {
		detail := ""
		if err != nil {
			detail = fmt.Sprintf(" (error: %v)", err)
		}
		problems = append(problems, fmt.Sprintf("outcome: want %q, got %q%s", want.Outcome, gotOutcome, detail))
	}

	if want.Text != "" && decoded.text != want.Text {
		problems = append(problems, fmt.Sprintf("text: want %q, got %q", want.Text, decoded.text))
	}

	if want.FailureCode != "" && gotCode != want.FailureCode {
		problems = append(problems, fmt.Sprintf("failure code: want %q, got %q -- the ratchet's classification is discarded rather than propagated", want.FailureCode, gotCode))
	}

	if want.SessionEffect != "" {
		if got := sessionEffect(roleBefore, roleAfter); got != want.SessionEffect {
			problems = append(problems, fmt.Sprintf("session effect: want %q, got %q (role %q -> %q)", want.SessionEffect, got, roleBefore, roleAfter))
		}
	}

	if want.InboundSessionKept != nil {
		got := st.InboundSessions[peer] != nil
		if got != *want.InboundSessionKept {
			problems = append(problems, fmt.Sprintf("inbound session kept: want %v, got %v", *want.InboundSessionKept, got))
		}
	}

	if want.OneTimePrekeysRemaining != nil {
		if got := len(st.OneTimePrekeys); got != *want.OneTimePrekeysRemaining {
			problems = append(problems, fmt.Sprintf("one-time prekeys remaining: want %d, got %d", *want.OneTimePrekeysRemaining, got))
		}
	}

	if want.CountsAsDesyncEvidence != nil {
		problems = append(problems, fmt.Sprintf("desync evidence: want %v, but this client has no desync accounting at all (SRV-03 is unimplemented here), so it can neither count nor discount a failure", *want.CountsAsDesyncEvidence))
	}

	return problems
}

func sessionRole(s *ratchet.Session) ratchet.Role {
	if s == nil {
		return ""
	}
	return s.Role
}

// sessionEffect derives what happened to the sending session from its X3DH
// role -- see conformance.SessionEffect for why that is the observable, and
// where it stops working.
func sessionEffect(before, after ratchet.Role) conformance.SessionEffect {
	switch {
	case before == "" && after != "":
		return conformance.SessionEstablished
	case before != after:
		return conformance.SessionAdoptedPeer
	default:
		return conformance.SessionUnchanged
	}
}
