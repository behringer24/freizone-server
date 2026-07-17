package wire

import (
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
