// Package group implements Freizone groups (SRV-01): a group's
// self-certifying identity, the signed events that describe who belongs to it
// and who may do what, and the order-independent fold from those events to the
// current membership.
//
// A group is deliberately not a server object. It has no home server, no row
// anywhere, and no authority outside its own key hierarchy: a group root key
// signs the genesis record and admin grants, admins grant moderator, and
// moderators add and remove members -- each act carrying the certificate chain
// that authorizes it. State is a grow-only set of such facts, so members
// converge on the same membership regardless of the order events reach them
// and with no sequencer anywhere.
//
// The signing byte layouts here are a cross-repo wire-format contract shared
// with the mobile client -- see docs/PROTOCOL.md and docs/design/01-groups.md.
package group

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/behringer24/freizone-server/pkg/address"
)

// NonceSize is the length of a group's nonce: the per-group salt that makes
// the group root key derivable from the founder's account root key. It is
// carried in the genesis event, i.e. it is public group state -- its job is
// domain separation between several groups founded by the same account, not
// secrecy.
const NonceSize = 16

// groupRootKeyInfo is the HKDF info string for deriving a group root key. Any
// change to it mints different keys for every existing group, so it is
// versioned rather than adjusted.
const groupRootKeyInfo = "Freizone-Group-Root-v1"

// Role is a member's authority within a group.
//
// The constants are ordered so that a plain > comparison IS the authority
// rule: an account may only act against strictly lower ranks. That collapses
// the whole permission table into two checks -- granting or revoking role R
// requires a rank above R (so only the founder touches admin, only an admin
// touches moderator), and removing a member requires at least moderator plus a
// rank above the target's.
//
// Only RoleModerator and RoleAdmin are ever granted by an event. RoleMember is
// the consequence of being added, and RoleFounder is key possession -- neither
// is assignable, and neither may appear in a grant.
type Role uint8

const (
	// RoleNone is not a member of this group.
	RoleNone Role = 0
	// RoleMember may read and write, nothing more.
	RoleMember Role = 1
	// RoleModerator may invite, remove lower ranks, and set name/topic.
	RoleModerator Role = 2
	// RoleAdmin may additionally grant and revoke moderator.
	RoleAdmin Role = 3
	// RoleFounder holds the group root key: the only rank that may grant and
	// revoke admin, and the only one that cannot be removed or leave.
	RoleFounder Role = 4
)

// String renders a role for diagnostics and for the client-facing JSON view.
func (r Role) String() string {
	switch r {
	case RoleMember:
		return "member"
	case RoleModerator:
		return "moderator"
	case RoleAdmin:
		return "admin"
	case RoleFounder:
		return "founder"
	default:
		return "none"
	}
}

// grantable reports whether a role may appear in a role grant or revocation.
// Membership and foundership are not granted, so naming them in a grant is
// malformed rather than merely unauthorized.
func (r Role) grantable() bool {
	return r == RoleModerator || r == RoleAdmin
}

// NewNonce generates a group nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("group: generating nonce: %w", err)
	}
	return nonce, nil
}

// DeriveRootKey derives a group's root key from the founder's account root key
// and the group nonce.
//
// Deriving rather than generating is what makes a group survive total device
// loss on the founder's side: the nonce lives in the genesis event, so a
// founder who restores the account root key from the recovery seed phrase and
// receives the group's state from any member can re-derive this exact key --
// with no group-specific backup material to have lost in the first place.
//
// accountRootSeed is the Ed25519 seed (ed25519.PrivateKey.Seed()), not the
// expanded private key, so the derivation depends on the account's actual
// secret rather than a representation of it.
func DeriveRootKey(accountRootSeed, nonce []byte) (ed25519.PrivateKey, error) {
	if len(accountRootSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("group: account root seed must be %d bytes, got %d", ed25519.SeedSize, len(accountRootSeed))
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("group: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}

	info := append([]byte(groupRootKeyInfo), nonce...)
	r := hkdf.New(sha256.New, accountRootSeed, nil, info)

	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("group: deriving group root key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// DeriveID computes a group's self-certifying id from its root public key --
// the account-address derivation with the group version marker, so the two
// share every line of encoding and checksum logic while remaining impossible
// to confuse.
func DeriveID(rootPubKey ed25519.PublicKey) (string, error) {
	return address.DeriveIDVersion(address.VersionGroup, rootPubKey)
}

// VerifyID reports whether id is the correct, self-certifying group id for
// rootPubKey. This is what makes a group's identity independent of any server:
// anyone holding the genesis event can recompute it.
func VerifyID(id string, rootPubKey ed25519.PublicKey) (bool, error) {
	return address.VerifyVersion(address.VersionGroup, id, rootPubKey)
}
