package client

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/behringer24/freizone-server/pkg/conformance"
	"github.com/behringer24/freizone-server/pkg/ratchet"
)

const conformanceVectorDir = "../conformance/testdata"

// The shared receive-path vectors, run against pkg/client (SRV-23).
//
// This is the test the package exists for. The vectors were authored from
// docs/PROTOCOL.md rather than recorded from either existing implementation, so
// passing them is a claim about the protocol and not about agreeing with
// whichever client was asked first -- freizone-app's Dart layer passes all of
// them, cmd/devclient four, and the gap between those two numbers is the reason
// the orchestration is being moved here.
//
// There is deliberately no knownDivergences map alongside this one, unlike
// cmd/devclient's runner. That list exists there to record a defect without
// hiding it; here a failure has nowhere to go but a fix, because this
// implementation has no history to be compatible with.
func TestReceivePathConformance(t *testing.T) {
	vectors, err := conformance.Load(conformanceVectorDir)
	if err != nil {
		t.Fatalf("loading conformance vectors: %v", err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			c := clientFromReceiver(t, v.Receiver)
			for i, step := range v.Steps {
				if problems := runConformanceStep(t, c, step); len(problems) > 0 {
					t.Errorf("step %d (%s):\n    %s", i+1, step.Label, strings.Join(problems, "\n    "))
				}
			}
		})
	}
}

// clientFromReceiver opens a scratch account primed with a vector's
// protocol-level starting state.
func clientFromReceiver(t *testing.T, r conformance.Receiver) *Client {
	t.Helper()

	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("opening client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.SetIdentity(Identity{
		AccountID:        r.AccountID,
		Server:           "https://vectors.test",
		DHIdentityPriv:   r.DHIdentityPriv,
		SignedPrekeyID:   1,
		SignedPrekeyPriv: r.SignedPrekeyPriv,
	}); err != nil {
		t.Fatalf("priming identity: %v", err)
	}

	var prekeys []OneTimePrekey
	for id, priv := range r.OneTimePrekeys {
		prekeys = append(prekeys, OneTimePrekey{KeyID: id, Priv: priv})
	}
	if len(prekeys) > 0 {
		if err := c.PutOneTimePrekeys(prekeys); err != nil {
			t.Fatalf("priming one-time prekeys: %v", err)
		}
	}

	for peer := range r.Sessions {
		s, err := r.Session(peer)
		if err != nil {
			t.Fatalf("session with %s: %v", peer, err)
		}
		if err := c.SetSession(peer, Sending, s); err != nil {
			t.Fatalf("priming session with %s: %v", peer, err)
		}
	}
	for peer := range r.InboundSessions {
		s, err := r.InboundSession(peer)
		if err != nil {
			t.Fatalf("inbound session with %s: %v", peer, err)
		}
		if err := c.SetSession(peer, Inbound, s); err != nil {
			t.Fatalf("priming inbound session with %s: %v", peer, err)
		}
	}
	for _, id := range r.ProcessedMessageIDs {
		if err := c.MarkMessageProcessed(id); err != nil {
			t.Fatalf("priming processed id %s: %v", id, err)
		}
	}
	return c
}

// runConformanceStep feeds one envelope through HandleIncoming and returns
// every way the outcome missed the vector's expectation. Empty means
// conforming.
func runConformanceStep(t *testing.T, c *Client, step conformance.Step) []string {
	t.Helper()
	peer := step.SenderAccountID
	roleBefore := sessionRole(t, c, peer)

	res, err := c.HandleIncoming(IncomingMessage{
		MessageID:       step.MessageID,
		SenderAccountID: peer,
		Payload:         step.Payload,
	}, ReceiveOptions{})

	roleAfter := sessionRole(t, c, peer)
	want := step.Expect
	var problems []string

	gotOutcome := conformance.OutcomeDecrypted
	gotCode := ""
	switch {
	case err != nil:
		gotOutcome = conformance.OutcomeUndecryptable
		gotCode = ratchet.FailureCode(err)
	case res.Duplicate:
		gotOutcome = conformance.OutcomeDuplicate
	}
	if gotOutcome != want.Outcome {
		detail := ""
		if err != nil {
			detail = fmt.Sprintf(" (error: %v)", err)
		}
		problems = append(problems, fmt.Sprintf("outcome: want %q, got %q%s", want.Outcome, gotOutcome, detail))
	}

	if want.Text != "" && res.Content.Text != want.Text {
		problems = append(problems, fmt.Sprintf("text: want %q, got %q", want.Text, res.Content.Text))
	}

	if want.FailureCode != "" && gotCode != want.FailureCode {
		problems = append(problems, fmt.Sprintf("failure code: want %q, got %q -- the ratchet's classification must survive being wrapped", want.FailureCode, gotCode))
	}

	if want.CountsAsDesyncEvidence != nil {
		// The classification, not whether it happened to be recorded this time:
		// evidence is only written once an envelope is given up on, and a
		// vector is asking whether this step should push the receiver towards
		// re-establishing the session at all.
		got := false
		var fail *DecryptError
		if errors.As(err, &fail) {
			got = fail.DesyncEvidence
		}
		if got != *want.CountsAsDesyncEvidence {
			problems = append(problems, fmt.Sprintf("desync evidence: want %v, got %v", *want.CountsAsDesyncEvidence, got))
		}
	}

	if want.SessionEffect != "" {
		if got := effectFromRoles(roleBefore, roleAfter); got != want.SessionEffect {
			problems = append(problems, fmt.Sprintf("session effect: want %q, got %q (role %q -> %q)", want.SessionEffect, got, roleBefore, roleAfter))
		}
	}

	if want.InboundSessionKept != nil {
		inbound, err := c.Session(peer, Inbound)
		if err != nil {
			t.Fatalf("reading inbound session: %v", err)
		}
		if got := inbound != nil; got != *want.InboundSessionKept {
			problems = append(problems, fmt.Sprintf("inbound session kept: want %v, got %v", *want.InboundSessionKept, got))
		}
	}

	if want.OneTimePrekeysRemaining != nil {
		got, err := c.CountOneTimePrekeys()
		if err != nil {
			t.Fatalf("counting one-time prekeys: %v", err)
		}
		if got != *want.OneTimePrekeysRemaining {
			problems = append(problems, fmt.Sprintf("one-time prekeys remaining: want %d, got %d", *want.OneTimePrekeysRemaining, got))
		}
	}

	return problems
}

func sessionRole(t *testing.T, c *Client, peer string) ratchet.Role {
	t.Helper()
	s, err := c.Session(peer, Sending)
	if err != nil {
		t.Fatalf("reading session with %s: %v", peer, err)
	}
	if s == nil {
		return ""
	}
	return s.Role
}

// sessionEffect derives what happened to the sending session from its X3DH
// role -- see conformance.SessionEffect for why that is the observable, and
// where it stops working.
func effectFromRoles(before, after ratchet.Role) conformance.SessionEffect {
	switch {
	case before == "" && after != "":
		return conformance.SessionEstablished
	case before != after:
		return conformance.SessionAdoptedPeer
	default:
		return conformance.SessionUnchanged
	}
}
