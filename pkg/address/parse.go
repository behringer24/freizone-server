package address

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The portable address form: `id*server`.
//
// # Why this lives here
//
// An address is written `q2xjx-e3gtq-utyft-ankjc-v*chat.example.org`, and that
// is the form a person copies out of the app and pastes anywhere else. Until
// SRV-31 nothing in Go parsed it: this package owned the id half and knew
// nothing about a server, so the only reader of the composite form was
// freizone-app's Dart side. The format existed in the protocol, in one client,
// and nowhere else.
//
// That was not untidiness. freizone-bot's peer route passed an empty server
// through to delivery -- which means "mine" -- so a recipient on any other
// server was quietly unreachable, in a product whose premise is that servers
// federate. When the bot then grew a parser of its own, written from this
// format's description rather than from the existing implementation, the two
// disagreed in four places within a day, one of which misrouted an address the
// format explicitly documents.
//
// So: one home. Callers add policy on top; nobody re-derives the syntax.
//
// # Two entry points, split by strictness
//
// The strictness genuinely differs, and a single answer would be wrong for
// somebody. Parse accepts a PrefixLength prefix, because `q2xjx*chat.example.org`
// is part of the documented format and is what powers interactive completion.
// ParseFull requires the whole checksummed id, which is what configuration and
// anything unattended needs: a truncated id in an environment file resolving to
// whoever happens to match is how a message reaches a stranger.
//
// Two names rather than one function with a flag, so that every call site says
// which it meant.

// Address is a parsed `id*server`.
type Address struct {
	// ID is normalized -- separators stripped, lowercased -- and is a full id
	// after ParseFull, possibly a prefix after Parse.
	ID string

	// Server is empty for "whatever server this is being resolved against",
	// which is what a bare id, `*local` and a bare trailing `*` all mean. That
	// emptiness is load-bearing rather than a convenience: it is what selects
	// local versus federated delivery further down, so filling in a hostname
	// here to look tidy would change what happens.
	//
	// When set it is a base URL with a scheme, as NormalizeServer produces.
	Server string
}

// ErrEmptyAddress is returned for input with no id in it at all.
var ErrEmptyAddress = errors.New("address: empty")

// localServer is the format's explicit spelling of "this server". Treating it
// as equivalent to no server part at all is what lets a parser always split on
// the first star instead of special-casing the absence of one.
const localServer = "local"

// Parse reads an address, validating the syntax of the id but not its length or
// checksum -- so a PrefixLength prefix, or a partially typed id, is accepted.
// Use ParseFull anywhere a complete address is required.
func Parse(raw string) (Address, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Address{}, ErrEmptyAddress
	}

	idPart, serverPart, _ := strings.Cut(raw, "*")

	id := StripSeparators(idPart)
	if id == "" {
		return Address{}, ErrEmptyAddress
	}
	// Charset is checked even though length and checksum are not: a prefix
	// carries no checksum of its own, so this is the only thing standing between
	// a pasted fragment of something else and a lookup that treats it as an id.
	if !ValidCharset(id) {
		return Address{}, fmt.Errorf("address: %q is not an id", idPart)
	}

	server := NormalizeServer(serverPart)
	if server != "" {
		// A scheme with nothing behind it, and anything else that leaves no
		// host, is refused here rather than passed on: further down it becomes
		// a failed request against a nonsense URL, which reads as a server
		// being unreachable rather than as an address nobody could have meant.
		if u, err := url.Parse(server); err != nil || u.Host == "" {
			return Address{}, fmt.Errorf("address: %q names no server", strings.TrimSpace(serverPart))
		}
	}

	return Address{ID: id, Server: server}, nil
}

// ParseFull reads an address whose id must be complete: full length, valid
// charset, valid checksum.
func ParseFull(raw string) (Address, error) {
	a, err := Parse(raw)
	if err != nil {
		return Address{}, err
	}
	id, err := Normalize(a.ID)
	if err != nil {
		return Address{}, err
	}
	a.ID = id
	return a, nil
}

// NormalizeServer turns the server half of an address, or a server address
// somebody typed, into a base URL. Empty input, and the format's `local`, both
// give "" -- meaning "whatever server this is resolved against".
//
// A bare host is given https, since that is how a normally deployed server is
// reachable (TLS on 443, see PROTOCOL.md) and requiring the scheme in every
// configuration file would be a papercut with no upside. A scheme that is
// spelled out is respected as it stands, so a test server without TLS can be
// named http:// deliberately.
//
// The strictness there is deliberate and settled: no scheme means https, and
// https that fails is a failure. Do not add a fallback that retries over http --
// that is a silent downgrade of a connection the caller believed was encrypted
// -- and do not let an error message suggest http as the remedy. Whoever runs a
// server without TLS can type the scheme in full.
func NormalizeServer(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, localServer) {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

// String is the canonical form: no cosmetic separators, and the default scheme
// left off. It round-trips through Parse.
//
// Canonical means comparable and storable, which is why the separators go: they
// are for reading, and two spellings of one address must not compare unequal.
// The default scheme goes for the same reason a display form drops it -- a
// non-default scheme is the one part worth seeing, so keeping `https://` in
// every rendering makes the interesting case harder to spot, not easier.
func (a Address) String() string {
	if a.Server == "" {
		return a.ID
	}
	return a.ID + "*" + TrimDefaultScheme(a.Server)
}

// Display is String with the id hyphenated for a human to read aloud or check
// against another screen. Never use it for comparison or storage.
func (a Address) Display() string {
	if a.Server == "" {
		return FormatForDisplay(a.ID)
	}
	return FormatForDisplay(a.ID) + "*" + TrimDefaultScheme(a.Server)
}

// TrimDefaultScheme removes a leading "https://", leaving any other scheme
// visible. Anything else is exactly what somebody needs to notice.
func TrimDefaultScheme(server string) string {
	return strings.TrimPrefix(server, "https://")
}

// SameServer reports whether two server spellings name one server.
//
// The scheme is ignored when neither side names an explicit port, because the
// scheme is how a particular client happens to be reaching a server rather than
// part of the server's identity -- the same reason a canonical rendering drops
// the default one. An explicit port on either side is compared exactly, since
// that usually does point somewhere genuinely different. Hosts compare
// case-insensitively, since domain names do.
//
// Both sides go through NormalizeServer first, so "" and "local" are one server
// -- our own -- and neither is the same server as any named host.
func SameServer(a, b string) bool {
	na, nb := NormalizeServer(a), NormalizeServer(b)
	if na == "" || nb == "" {
		return na == nb
	}

	ua, erra := url.Parse(na)
	ub, errb := url.Parse(nb)
	if erra != nil || errb != nil {
		// Not silently "different": two spellings we cannot parse might well be
		// the same typo, and reporting them equal is the answer that does not
		// invent a distinction out of our own failure to read them.
		return strings.EqualFold(na, nb)
	}
	if !strings.EqualFold(ua.Hostname(), ub.Hostname()) {
		return false
	}
	return ua.Port() == ub.Port()
}
