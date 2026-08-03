package wire

import (
	"bytes"
	"testing"

	"github.com/behringer24/freizone-server/pkg/ratchet"
)

func TestHeaderDTORoundTrip(t *testing.T) {
	h := ratchet.Header{DHPub: []byte{1, 2, 3, 4}, PN: 5, N: 9}
	dto := HeaderToDTO(h)
	got, err := dto.ToHeader()
	if err != nil {
		t.Fatalf("ToHeader() error = %v", err)
	}
	if string(got.DHPub) != string(h.DHPub) || got.PN != h.PN || got.N != h.N {
		t.Errorf("got %+v, want %+v", got, h)
	}
}

func TestInitialMessageRoundTrip(t *testing.T) {
	otpkID := uint32(7)
	im := &ratchet.InitialMessage{
		SenderDHIdentityPub: []byte{9, 9, 9},
		SenderEphemeralPub:  []byte{8, 8, 8},
		SignedPrekeyID:      3,
		OneTimePrekeyID:     &otpkID,
	}
	fields := InitialMessageToPrekeyFields(im)
	got, err := fields.ToInitialMessage()
	if err != nil {
		t.Fatalf("ToInitialMessage() error = %v", err)
	}
	if string(got.SenderDHIdentityPub) != string(im.SenderDHIdentityPub) ||
		string(got.SenderEphemeralPub) != string(im.SenderEphemeralPub) ||
		got.SignedPrekeyID != im.SignedPrekeyID ||
		got.OneTimePrekeyID == nil || *got.OneTimePrekeyID != *im.OneTimePrekeyID {
		t.Errorf("got %+v, want %+v", got, im)
	}
}

func TestEnvelopeMarshalParseRoundTrip(t *testing.T) {
	header := ratchet.Header{DHPub: []byte{1, 2, 3}, PN: 0, N: 1}
	ciphertext := []byte("ciphertext-bytes")
	im := &ratchet.InitialMessage{SenderDHIdentityPub: []byte{4, 5, 6}, SenderEphemeralPub: []byte{7, 8, 9}, SignedPrekeyID: 1}

	env := NewEnvelope(im, header, ciphertext)
	payload, err := env.MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}

	parsed, err := ParseEnvelope(payload)
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	if parsed.Prekey == nil {
		t.Fatal("expected parsed envelope to carry prekey fields")
	}
	gotCiphertext, err := parsed.DecodeCiphertext()
	if err != nil {
		t.Fatalf("DecodeCiphertext() error = %v", err)
	}
	if string(gotCiphertext) != string(ciphertext) {
		t.Errorf("ciphertext = %q, want %q", gotCiphertext, ciphertext)
	}
}

// SRV-17: the three states of the prekey block's `rekey` field have to survive
// the wire distinctly -- "no" and "said nothing" are different facts, and the
// receiver handles them differently (see PrekeyFields.Rekey).
func TestPrekeyRekeyFlagIsATriState(t *testing.T) {
	header := ratchet.Header{DHPub: []byte{1, 2, 3}, PN: 0, N: 1}
	im := &ratchet.InitialMessage{SenderDHIdentityPub: []byte{4, 5, 6}, SenderEphemeralPub: []byte{7, 8, 9}, SignedPrekeyID: 1}
	yes, no := true, false

	for name, want := range map[string]*bool{
		"deliberate re-key":      &yes,
		"ordinary establishment": &no,
		"says nothing":           nil,
	} {
		payload, err := NewEnvelopeRekey(im, header, []byte("ct"), want).MarshalPayload()
		if err != nil {
			t.Fatalf("%s: MarshalPayload() error = %v", name, err)
		}
		parsed, err := ParseEnvelope(payload)
		if err != nil {
			t.Fatalf("%s: ParseEnvelope() error = %v", name, err)
		}
		got := parsed.Prekey.Rekey
		switch {
		case want == nil && got != nil:
			t.Errorf("%s: rekey = %v, want it absent", name, *got)
		case want != nil && got == nil:
			t.Errorf("%s: rekey absent, want %v", name, *want)
		case want != nil && *got != *want:
			t.Errorf("%s: rekey = %v, want %v", name, *got, *want)
		}
	}

	// Absent means absent on the wire too, so an envelope from a client that
	// does not know the field is byte-identical to what it always was.
	payload, err := NewEnvelope(im, header, []byte("ct")).MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	if bytes.Contains(payload, []byte(`"rekey"`)) {
		t.Errorf("an unstated rekey flag must not appear on the wire: %s", payload)
	}
}

func TestEnvelopeWithoutPrekeyFields(t *testing.T) {
	header := ratchet.Header{DHPub: []byte{1, 2, 3}, PN: 1, N: 2}
	env := NewEnvelope(nil, header, []byte("ct"))
	if env.Prekey != nil {
		t.Error("expected no prekey fields when initial is nil")
	}

	payload, err := env.MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	parsed, err := ParseEnvelope(payload)
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	if parsed.Prekey != nil {
		t.Error("expected parsed envelope to have no prekey fields")
	}
}
