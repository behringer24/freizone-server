package group

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// EventType names one kind of statement about a group.
type EventType string

const (
	// EventGenesis creates the group and names its founder. Signed by the
	// group root key, and the only event carrying that key, so every other
	// signature in the group is checkable once this one is held.
	EventGenesis EventType = "genesis"
	// EventRoleGrant raises an account to moderator or admin.
	EventRoleGrant EventType = "role_grant"
	// EventRoleRevoke takes that role away again.
	EventRoleRevoke EventType = "role_revoke"
	// EventMemberAdd invites an account. It is a proposal until the invitee
	// accepts -- being added discloses your address to every member, so that
	// disclosure is not someone else's decision to make.
	EventMemberAdd EventType = "member_add"
	// EventMemberRemove removes an account from the group.
	EventMemberRemove EventType = "member_remove"
	// EventJoinAccept is an invitee accepting their own invitation.
	EventJoinAccept EventType = "join_accept"
	// EventLeave is a member removing themselves.
	EventLeave EventType = "leave"
	// EventMeta sets the group's name and topic as one record.
	EventMeta EventType = "meta"
	// EventDissolve ends the group. Signed by the group root key: the founder
	// cannot leave a group, only dissolve it, since leaving would leave an
	// authority behind that is not in the member list.
	EventDissolve EventType = "dissolve"
)

// domainTags gives every event type its own prefix in the signing bytes, so a
// signature over one shape can never be reinterpreted as another. The device
// certificates in pkg/devicecert get away without this because their two
// shapes differ in length; with nine similar records that would stop being a
// safe argument.
var domainTags = map[EventType]string{
	EventGenesis:      "frz-group-genesis-v1",
	EventRoleGrant:    "frz-group-role-grant-v1",
	EventRoleRevoke:   "frz-group-role-revoke-v1",
	EventMemberAdd:    "frz-group-member-add-v1",
	EventMemberRemove: "frz-group-member-remove-v1",
	EventJoinAccept:   "frz-group-join-accept-v1",
	EventLeave:        "frz-group-leave-v1",
	EventMeta:         "frz-group-meta-v1",
	EventDissolve:     "frz-group-dissolve-v1",
}

// signingRule says which key may sign an event type.
type signingRule uint8

const (
	// signedByDevice: an ordinary act, signed by a member's device key and
	// carrying the chain that proves which account it was.
	signedByDevice signingRule = iota
	// signedByRoot: reserved to the group root key, i.e. to the founder.
	signedByRoot
	// signedByEither: a role grant or revocation. Which key is *sufficient*
	// is not a property of the event type but of the role being granted --
	// raising someone to admin needs a rank above admin, which only the
	// founder has, while moderator needs only an admin. That comparison lives
	// in the fold (Resolve), so admission accepts both forms here and lets a
	// root signature simply count as the founder acting. It also means the
	// founder need not reach for the group root key to appoint a moderator,
	// which their own device rank already permits.
	signedByEither
)

func ruleFor(t EventType) signingRule {
	switch t {
	case EventGenesis, EventDissolve:
		return signedByRoot
	case EventRoleGrant, EventRoleRevoke:
		return signedByEither
	default:
		return signedByDevice
	}
}

// MaxNameLen and MaxTopicLen bound the two free-text fields. A group's state
// is gossiped in full to every member on any state_hash mismatch, so an
// unbounded string here is an amplification vector against every other
// member's storage, not just the sender's.
const (
	MaxNameLen  = 128
	MaxTopicLen = 512
)

// Signer identifies the device that signed an event, and carries everything
// needed to check that it was entitled to -- the same self-describing identity
// block federated message delivery already uses (docs/PROTOCOL.md section 9).
// Nil on a root-signed event, where the group root key in the genesis record
// is the whole story.
type Signer struct {
	AccountID  string                       `json:"account_id"`
	RootPubKey ed25519.PublicKey            `json:"root_pub_key"`
	DeviceCert devicecert.DeviceCertificate `json:"device_cert"`
}

// verify checks the signer block is internally consistent: the account id is
// the self-certifying hash of the root key, and the device certificate is
// validly signed by that root key for that same account.
//
// It deliberately does NOT require the device to still be active. A revoked
// device's past acts stay valid -- and cross-server device revocation is not
// observable anyway (docs/PROTOCOL.md section 9's known gap), so requiring it
// would be a check no implementation could actually perform.
func (s *Signer) verify() error {
	if s == nil {
		return errors.New("group: missing signer")
	}
	ok, err := address.Verify(s.AccountID, s.RootPubKey)
	if err != nil {
		return fmt.Errorf("group: signer account id: %w", err)
	}
	if !ok {
		return errors.New("group: signer account id does not match its root key")
	}
	if s.DeviceCert.AccountID != s.AccountID {
		return errors.New("group: signer device certificate belongs to another account")
	}
	if err := s.DeviceCert.Verify(s.RootPubKey); err != nil {
		return fmt.Errorf("group: signer device certificate: %w", err)
	}
	return nil
}

// Event is one signed statement about a group.
//
// The fields are a union across event types: each type signs exactly the ones
// it uses, and Validate rejects an event that carries any other field set.
// Without that rule a field outside a type's signing bytes would be attacker-
// controlled data riding inside a signed object.
type Event struct {
	Type     EventType `json:"type"`
	GroupID  string    `json:"group_id"`
	IssuedAt time.Time `json:"issued_at"`

	// RootPubKey and Nonce appear on the genesis event only. The public key is
	// what makes the group id checkable; the nonce is what makes the private
	// key re-derivable from the founder's recovery seed.
	RootPubKey ed25519.PublicKey `json:"root_pub_key,omitempty"`
	Nonce      []byte            `json:"nonce,omitempty"`

	// Subject is the account this event is about: the founder on genesis, the
	// granted/removed/joining account elsewhere.
	Subject string `json:"subject,omitempty"`

	// Server is the subject's home server -- the address half every other
	// member needs in order to deliver to them. On member_add, and on genesis
	// for the founder, who has no member_add of their own and would otherwise
	// be the one member nobody could address until they spoke first.
	Server string `json:"server,omitempty"`

	// Role is the role being granted or revoked.
	Role Role `json:"role,omitempty"`

	// Name and Topic are set together, as one last-writer-wins record: two
	// independently merged fields would produce a conflict case that buys
	// nothing.
	Name  string `json:"name,omitempty"`
	Topic string `json:"topic,omitempty"`

	Signer    *Signer `json:"signer,omitempty"`
	Signature []byte  `json:"signature"`
}

// ID is the event's identity: the hash over exactly what was signed plus the
// signature. Two members therefore compute the same id for the same event
// without having to agree on a JSON encoding, and no field outside the signing
// bytes can influence it.
func (e *Event) ID() (string, error) {
	buf, err := e.signingBytes()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(buf)
	h.Write(e.Signature)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Validate checks an event's shape: a known type, a plausible group id, the
// fields that type requires, and -- just as important -- that it carries no
// field its type does not sign.
func (e *Event) Validate() error {
	if _, ok := domainTags[e.Type]; !ok {
		return fmt.Errorf("group: unknown event type %q", e.Type)
	}
	if _, err := address.Normalize(e.GroupID); err != nil {
		return fmt.Errorf("group: event group id: %w", err)
	}
	if e.IssuedAt.IsZero() {
		return errors.New("group: event has no timestamp")
	}
	// The signing bytes carry RFC 3339 at second granularity, so anything
	// finer would be unsigned data that still influenced ordering -- and two
	// members could then fold the same facts into different states.
	if e.IssuedAt.Truncate(time.Second) != e.IssuedAt {
		return errors.New("group: event timestamp must not carry sub-second precision")
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("group: signature must be %d bytes, got %d", ed25519.SignatureSize, len(e.Signature))
	}

	switch ruleFor(e.Type) {
	case signedByRoot:
		if e.Signer != nil {
			return fmt.Errorf("group: %s is signed by the group root key and must carry no signer", e.Type)
		}
	case signedByDevice:
		if e.Signer == nil {
			return fmt.Errorf("group: %s must carry a signer", e.Type)
		}
	}

	// Which fields this type is allowed to set. Anything else must be zero:
	// it would not be covered by the signature.
	var wantGenesis, wantSubject, wantServer, wantRole, wantMeta bool
	switch e.Type {
	case EventGenesis:
		wantGenesis, wantSubject, wantServer = true, true, true
	case EventRoleGrant, EventRoleRevoke:
		wantSubject, wantRole = true, true
	case EventMemberAdd:
		wantSubject, wantServer = true, true
	case EventMemberRemove, EventJoinAccept, EventLeave:
		wantSubject = true
	case EventMeta:
		wantMeta = true
	case EventDissolve:
		// Carries nothing beyond the group id and its timestamp.
	}

	if wantGenesis {
		if len(e.RootPubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("group: genesis root public key must be %d bytes, got %d", ed25519.PublicKeySize, len(e.RootPubKey))
		}
		if len(e.Nonce) != NonceSize {
			return fmt.Errorf("group: genesis nonce must be %d bytes, got %d", NonceSize, len(e.Nonce))
		}
		ok, err := VerifyID(e.GroupID, e.RootPubKey)
		if err != nil {
			return fmt.Errorf("group: genesis group id: %w", err)
		}
		if !ok {
			return errors.New("group: genesis group id does not match its root key")
		}
	} else if len(e.RootPubKey) != 0 || len(e.Nonce) != 0 {
		return fmt.Errorf("group: %s must not carry group root key material", e.Type)
	}

	if wantSubject {
		if _, err := address.Normalize(e.Subject); err != nil {
			return fmt.Errorf("group: event subject: %w", err)
		}
	} else if e.Subject != "" {
		return fmt.Errorf("group: %s must not name a subject", e.Type)
	}

	if wantServer {
		if e.Server == "" {
			return fmt.Errorf("group: %s must carry the subject's home server", e.Type)
		}
	} else if e.Server != "" {
		return fmt.Errorf("group: %s must not name a server", e.Type)
	}

	if wantRole {
		if !e.Role.grantable() {
			return fmt.Errorf("group: role %s cannot be granted or revoked", e.Role)
		}
	} else if e.Role != RoleNone {
		return fmt.Errorf("group: %s must not name a role", e.Type)
	}

	if wantMeta {
		if len(e.Name) > MaxNameLen {
			return fmt.Errorf("group: name must be at most %d bytes, got %d", MaxNameLen, len(e.Name))
		}
		if len(e.Topic) > MaxTopicLen {
			return fmt.Errorf("group: topic must be at most %d bytes, got %d", MaxTopicLen, len(e.Topic))
		}
	} else if e.Name != "" || e.Topic != "" {
		return fmt.Errorf("group: %s must not carry name or topic", e.Type)
	}

	// A self-signed act can only be about the signer themselves. Anything else
	// would be an unauthorized act dressed up as a personal one.
	if e.Type == EventJoinAccept || e.Type == EventLeave {
		if e.Signer == nil || e.Signer.AccountID != e.Subject {
			return fmt.Errorf("group: %s must be signed by its own subject", e.Type)
		}
	}
	return nil
}

// Verify checks the event's shape, its signer chain, and its signature.
//
// It deliberately says nothing about authority: whether the signer was allowed
// to do this depends on every other fact in the group and on when they arrive,
// so it is decided by the fold in Resolve, not here. Admission has to be
// context-free, or an event that merely overtook the grant authorizing it
// would be rejected forever.
func (e *Event) Verify(groupRootPubKey ed25519.PublicKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	buf, err := e.signingBytes()
	if err != nil {
		return err
	}

	// An absent signer block means the group root key signed this -- the only
	// other key the protocol knows about.
	if e.Signer == nil {
		if !ed25519.Verify(groupRootPubKey, buf, e.Signature) {
			return fmt.Errorf("group: %s signature verification failed", e.Type)
		}
		return nil
	}

	if err := e.Signer.verify(); err != nil {
		return err
	}
	if !ed25519.Verify(e.Signer.DeviceCert.DevicePubKey, buf, e.Signature) {
		return fmt.Errorf("group: %s signature verification failed", e.Type)
	}
	return nil
}

// SignRoot signs an event with the group root key -- the founder acting.
func SignRoot(e *Event, groupRootPriv ed25519.PrivateKey) error {
	if ruleFor(e.Type) == signedByDevice {
		return fmt.Errorf("group: %s is not signed by the group root key", e.Type)
	}
	return sign(e, groupRootPriv, nil)
}

// SignDevice signs an event with a member's device key, attaching the signer
// block that lets any recipient chain it back to an account id.
func SignDevice(e *Event, signer *Signer, devicePriv ed25519.PrivateKey) error {
	if ruleFor(e.Type) == signedByRoot {
		return fmt.Errorf("group: %s must be signed by the group root key", e.Type)
	}
	return sign(e, devicePriv, signer)
}

func sign(e *Event, priv ed25519.PrivateKey, signer *Signer) error {
	e.Signer = signer
	// A placeholder signature keeps Validate's length check meaningful while
	// the real one is still being computed.
	e.Signature = make([]byte, ed25519.SignatureSize)
	if err := e.Validate(); err != nil {
		return err
	}
	buf, err := e.signingBytes()
	if err != nil {
		return err
	}
	e.Signature = ed25519.Sign(priv, buf)
	return nil
}

// signingBytes is the deterministic, length-prefixed binary encoding an event
// is signed over -- the same pattern as the device and prekey certificates,
// and for the same reason: JSON key ordering and whitespace are not a safe
// cross-implementation contract.
//
// Layout: the type's domain tag, the group id, the type's own fields, and the
// timestamp last.
func (e *Event) signingBytes() ([]byte, error) {
	tag, ok := domainTags[e.Type]
	if !ok {
		return nil, fmt.Errorf("group: unknown event type %q", e.Type)
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(tag))
	writeLengthPrefixed(&buf, []byte(e.GroupID))

	switch e.Type {
	case EventGenesis:
		buf.Write(e.RootPubKey)
		buf.Write(e.Nonce)
		writeLengthPrefixed(&buf, []byte(e.Subject))
		writeLengthPrefixed(&buf, []byte(e.Server))
	case EventRoleGrant, EventRoleRevoke:
		buf.WriteByte(byte(e.Role))
		writeLengthPrefixed(&buf, []byte(e.Subject))
	case EventMemberAdd:
		writeLengthPrefixed(&buf, []byte(e.Subject))
		writeLengthPrefixed(&buf, []byte(e.Server))
	case EventMemberRemove, EventJoinAccept, EventLeave:
		writeLengthPrefixed(&buf, []byte(e.Subject))
	case EventMeta:
		writeLengthPrefixed(&buf, []byte(e.Name))
		writeLengthPrefixed(&buf, []byte(e.Topic))
	case EventDissolve:
		// Nothing type-specific.
	}

	writeLengthPrefixed(&buf, []byte(e.IssuedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}

func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}
