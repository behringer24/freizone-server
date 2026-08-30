package client

import (
	"encoding/json"
	"time"

	"github.com/behringer24/freizone-server/pkg/group"
	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// Plaintext content -- what is inside the ciphertext of a wire.Envelope, and
// therefore the one part of the protocol a server never sees.
//
// The version number is the discriminator, and each version owns its meaning
// for good. That is deliberate and costs a number per feature: a receipt is
// not a v1 with a "kind" field, and a group message is not a v1 with a group
// id, because a client that predates either would file it into a one-to-one
// transcript as chat text. Reserving a version instead means an older build
// meets something it can recognise as "newer" and can say so.
//
//	v1  chat text                (ContentText)
//	v2  read/delivery receipt    (ContentReceipt)
//	v3  session re-key signal    (ContentRekey)
//	v4  group chat text          (ContentGroupText)
//	v5  group control            (ContentGroupControl)
//
// Anything that is not JSON, or JSON without a version this build knows, is
// legacy raw text: the oldest clients sent the message body as bare bytes.
// That fallback stays because those envelopes may still be sitting in a queue,
// and reading one as text is exactly right.
//
// The one thing that is *not* a version of its own is the profile claim
// (SRV-32): it is an optional field on v1, v2 and v4, because the rule above
// cuts the other way for something meant to be invisible. Reserving v6 for it
// would make every older peer render a placeholder whenever somebody renames
// themselves, while an unknown field costs nothing anywhere.

// ContentKind is what a decrypted payload turned out to be.
type ContentKind string

const (
	ContentText         ContentKind = "text"
	ContentReceipt      ContentKind = "receipt"
	ContentRekey        ContentKind = "rekey"
	ContentGroupText    ContentKind = "group_text"
	ContentGroupControl ContentKind = "group_control"
)

const (
	versionText         = 1
	versionReceipt      = 2
	versionRekey        = 3
	versionGroupText    = 4
	versionGroupControl = 5
)

// unsupportedContentText is shown in place of a message from a build newer
// than this one. A version this code has never heard of cannot be rendered,
// and showing nothing at all reads as a message that was lost.
const unsupportedContentText = "This message uses a newer app feature and can't be shown here yet."

// ReceiptStatus is how far a peer has got with our messages.
type ReceiptStatus string

const (
	ReceiptDelivered ReceiptStatus = "delivered"
	ReceiptRead      ReceiptStatus = "read"
)

// RekeyReason is why a peer threw their session away. Carried for the
// transcript marker and for diagnostics only -- never used to decide anything
// security relevant, so an unknown value is simply RekeyUnspecified rather
// than a reason to reject the signal.
type RekeyReason string

const (
	RekeyDecryptFailures RekeyReason = "decrypt_failures"
	RekeyUserRequested   RekeyReason = "user_requested"
	RekeyUnspecified     RekeyReason = "unspecified"
)

// Content is one decrypted payload, interpreted. Which fields carry anything
// depends on Kind; the rest are zero.
type Content struct {
	Kind ContentKind

	// ID is the sender's own id for the message, which is what a reply and a
	// delete refer to. Empty for a legacy envelope, which had none -- the
	// receive path mints one so a line always has an id locally.
	ID string

	Text string

	// SentAt is the sender's clock, absent for legacy envelopes. Receipts are
	// anchored to it rather than to arrival time, so the two sides can agree
	// on what "up to here" means without agreeing on the time.
	SentAt *time.Time

	// SenderServer travels with every message rather than only the first, so a
	// peer stays reachable even if local state about them is lost.
	SenderServer string

	Attachments []Attachment

	ReplyToID            string
	ReplyPreviewText     string
	ReplyPreviewMine     *bool
	ReplyPreviewAuthorID string

	// Receipt fields.
	ReceiptStatus  ReceiptStatus
	ReceiptUpTo    time.Time
	ReceiptGroupID string

	// RekeyReason is set for ContentRekey.
	RekeyReason RekeyReason

	// Group fields. StateHash is the sender.s view of the group.s fact set,
	// which is what tells the receiver whether they are behind.
	GroupID   string
	StateHash string

	// ControlKind and Events are the payload of a group control envelope: what
	// the sender is doing, and the facts they are passing on.
	ControlKind GroupControlKind
	Events      []*group.Event

	// Profile is the name the sender asserts about itself, if this envelope
	// carried one (SRV-32). Present here exactly as it arrived and **not yet
	// verified**: checking it needs the sender's device certificate, which
	// decoding has no access to. [Client.applyProfileClaim] is what turns one
	// into something worth showing.
	Profile *profileclaim.Claim

	// Raw is the undecoded plaintext, kept so a caller that owns a part of the
	// protocol this package does not yet handle -- group control, today -- can
	// act on it without decoding twice.
	Raw []byte
}

// attachmentWire is the on-the-wire shape of an attachment, which is not the
// stored shape: the field names here are short because they are paid for per
// message and per recipient, while [Attachment]'s are spelled out because they
// are read by a person debugging a transcript.
type attachmentWire struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"alg,omitempty"`
	BlobID    string `json:"blob_id"`
	Key       []byte `json:"key"`
	MimeType  string `json:"mime,omitempty"`
	ByteSize  int    `json:"size,omitempty"`
	Width     int    `json:"w,omitempty"`
	Height    int    `json:"h,omitempty"`
	Thumb     []byte `json:"thumb,omitempty"`
}

type replyPreviewWire struct {
	Text   string  `json:"text"`
	Mine   *bool   `json:"mine,omitempty"`
	Author *string `json:"author,omitempty"`
}

// contentWire is every field any version uses, in one struct. Decoding once
// and switching on the version afterwards keeps the version rules in a single
// place -- the alternative, a probe followed by a second unmarshal per branch,
// is where the two existing implementations drifted apart.
type contentWire struct {
	V    int    `json:"v"`
	Kind string `json:"kind"`

	ID           string            `json:"id"`
	Text         string            `json:"text"`
	Attachments  []json.RawMessage `json:"attachments"`
	ReplyTo      string            `json:"reply_to"`
	ReplyPreview *replyPreviewWire `json:"reply_preview"`
	SenderServer string            `json:"sender_server"`
	SentAt       string            `json:"sent_at"`

	Status     string `json:"status"`
	UpToSentAt string `json:"up_to_sent_at"`

	Reason string `json:"reason"`

	GroupID   string         `json:"group_id"`
	StateHash string         `json:"state_hash"`
	Events    []*group.Event `json:"events"`

	// Profile rides on v1, v2 and v4 rather than owning a version of its own
	// (SRV-32). An unknown *version* renders as the "newer feature"
	// placeholder, so a control envelope for a name would paint a ghost
	// message into every older peer's transcript on every rename; an unknown
	// *field* is ignored, which is what this struct's "every field any version
	// uses" shape has always relied on and what §10's attachments established.
	Profile *profileclaim.Claim `json:"profile"`
}

// DecodeContent interprets decrypted plaintext.
//
// It never fails. Every unrecognised shape has a defined reading -- legacy raw
// text, or the "newer feature" placeholder -- because the alternative is
// dropping an envelope whose ratchet step has already been taken, and a
// message that cannot be shown is still better evidence of itself than
// silence. A caller wanting to know whether the content was understood should
// look at [Content.Kind] and, for text, whether the version was known.
func DecodeContent(plaintext []byte) Content {
	legacy := Content{Kind: ContentText, Text: string(plaintext), Raw: plaintext}

	var w contentWire
	if err := json.Unmarshal(plaintext, &w); err != nil || w.V == 0 {
		return legacy
	}

	c := Content{Raw: plaintext, ID: w.ID}
	switch {
	case w.V == versionReceipt && w.Kind == "receipt":
		upTo, err := time.Parse(time.RFC3339, w.UpToSentAt)
		if err != nil || (w.Status != string(ReceiptDelivered) && w.Status != string(ReceiptRead)) {
			// A receipt missing the only two things it consists of is not a
			// receipt. Falling back to text rather than dropping it keeps the
			// damage visible instead of turning it into a message that
			// silently never arrived.
			return legacy
		}
		c.Kind = ContentReceipt
		c.ReceiptStatus = ReceiptStatus(w.Status)
		c.ReceiptUpTo = upTo.UTC()
		c.ReceiptGroupID = w.GroupID
		c.Profile = w.Profile
		return c

	case w.V == versionRekey && w.Kind == "rekey":
		c.Kind = ContentRekey
		switch RekeyReason(w.Reason) {
		case RekeyDecryptFailures, RekeyUserRequested:
			c.RekeyReason = RekeyReason(w.Reason)
		default:
			c.RekeyReason = RekeyUnspecified
		}
		return c

	case w.V == versionGroupControl && w.GroupID != "":
		c.Kind = ContentGroupControl
		c.GroupID = w.GroupID
		c.StateHash = w.StateHash
		c.Events = w.Events
		switch GroupControlKind(w.Kind) {
		case GroupSnapshot, GroupEvents, GroupSyncRequest:
			c.ControlKind = GroupControlKind(w.Kind)
		default:
			// A kind this build does not know still carries facts, and facts
			// are the point. Treated as plain events rather than dropped:
			// folding is order-independent and idempotent, so the worst case
			// is applying something twice.
			c.ControlKind = GroupEvents
		}
		return c

	case w.V == versionGroupText && w.GroupID != "":
		c.Kind = ContentGroupText
		c.GroupID = w.GroupID
		c.StateHash = w.StateHash

	case w.V == versionText:
		c.Kind = ContentText

	case w.V > versionGroupControl:
		// Newer than anything here: say so rather than render its fields,
		// which mean something this build cannot know.
		return Content{Kind: ContentText, ID: w.ID, Text: unsupportedContentText, Raw: plaintext}

	default:
		return legacy
	}

	// Shared by the two text-carrying versions.
	c.Text = w.Text
	c.Profile = w.Profile
	c.SenderServer = w.SenderServer
	c.ReplyToID = w.ReplyTo
	if w.ReplyPreview != nil {
		c.ReplyPreviewText = w.ReplyPreview.Text
		c.ReplyPreviewMine = w.ReplyPreview.Mine
		if w.ReplyPreview.Author != nil {
			c.ReplyPreviewAuthorID = *w.ReplyPreview.Author
		}
	}
	if w.SentAt != "" {
		if t, err := time.Parse(time.RFC3339, w.SentAt); err == nil {
			utc := t.UTC()
			c.SentAt = &utc
		}
	}
	c.Attachments = decodeAttachments(w.Attachments)
	return c
}

// decodeAttachments drops entries it cannot read rather than failing the
// message around them: a damaged attachment costs its own picture, never the
// text it arrived with.
func decodeAttachments(raw []json.RawMessage) []Attachment {
	var out []Attachment
	for _, entry := range raw {
		var a attachmentWire
		if json.Unmarshal(entry, &a) != nil {
			continue
		}
		if a.BlobID == "" || len(a.Key) == 0 {
			continue // nothing to fetch, or nothing to open it with
		}
		out = append(out, Attachment{
			Kind:      a.Kind,
			Algorithm: a.Algorithm,
			BlobID:    a.BlobID,
			Key:       a.Key,
			MimeType:  a.MimeType,
			ByteSize:  a.ByteSize,
			Width:     a.Width,
			Height:    a.Height,
			Thumb:     a.Thumb,
		})
	}
	return out
}
