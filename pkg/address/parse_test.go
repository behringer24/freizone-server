package address

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// Derived rather than typed, so a change to the derivation cannot leave these
// tests passing against ids the rest of the system would reject.
func testIDs(t *testing.T) (account, group string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	account, err := DeriveID(pub)
	if err != nil {
		t.Fatalf("DeriveID: %v", err)
	}
	group, err = DeriveIDVersion(VersionGroup, pub)
	if err != nil {
		t.Fatalf("DeriveIDVersion: %v", err)
	}
	return account, group
}

func TestABareIDHasNoServer(t *testing.T) {
	id, _ := testIDs(t)
	got, err := ParseFull(id)
	if err != nil {
		t.Fatalf("ParseFull: %v", err)
	}
	if got.ID != id {
		t.Errorf("id: got %q", got.ID)
	}
	// Empty, not our hostname filled in helpfully: emptiness is what selects
	// local delivery further down, so inventing a value changes behaviour.
	if got.Server != "" {
		t.Errorf("server should be empty, got %q", got.Server)
	}
}

func TestTheDisplayFormParsesBack(t *testing.T) {
	id, _ := testIDs(t)
	for _, raw := range []string{
		FormatForDisplay(id),
		"  " + FormatForDisplay(id) + "  ",
		strings.ToUpper(id),
	} {
		got, err := ParseFull(raw)
		if err != nil {
			t.Errorf("ParseFull(%q): %v", raw, err)
			continue
		}
		if got.ID != id {
			t.Errorf("ParseFull(%q).ID = %q", raw, got.ID)
		}
	}
}

func TestTheServerHalf(t *testing.T) {
	id, _ := testIDs(t)
	for _, tc := range []struct {
		raw  string
		want string
	}{
		// A bare host gets https: that is how a normally deployed server is
		// reachable, and requiring the scheme everywhere buys nothing.
		{"chat.example.org", "https://chat.example.org"},
		{"https://chat.example.org", "https://chat.example.org"},
		// A scheme that was spelled out is respected. This is the case where
		// guessing would be actively wrong rather than merely verbose, and the
		// only reason a test server without TLS can be named at all.
		{"http://box.lan:18081", "http://box.lan:18081"},
		{"https://chat.example.org/", "https://chat.example.org"},
		{" chat.example.org ", "https://chat.example.org"},
		// The format's two spellings of "our own server", both equivalent to
		// leaving the star off. Read literally, "local" is a hostname, and an
		// address the format documents would route nowhere.
		{"local", ""},
		{"LOCAL", ""},
		{"", ""},
		{"   ", ""},
	} {
		got, err := Parse(id + "*" + tc.raw)
		if err != nil {
			t.Errorf("Parse(id*%q): %v", tc.raw, err)
			continue
		}
		if got.Server != tc.want {
			t.Errorf("Parse(id*%q).Server = %q, want %q", tc.raw, got.Server, tc.want)
		}
	}
}

// A prefix is part of the documented format and is what interactive completion
// runs on, so the tolerant entry point has to accept it -- while the strict one
// must not, which is the whole reason there are two.
func TestPrefixesAreForParseNotParseFull(t *testing.T) {
	id, _ := testIDs(t)
	prefix := id[:PrefixLength]

	got, err := Parse(prefix + "*chat.example.org")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.ID != prefix || got.Server != "https://chat.example.org" {
		t.Errorf("got %+v", got)
	}

	if _, err := ParseFull(prefix + "*chat.example.org"); err == nil {
		t.Error("ParseFull must not accept a prefix")
	}
	// The in-between case matters more than the prefix: half an id is what a
	// truncated environment variable looks like, and completing it would send
	// something to whoever happens to match.
	if _, err := ParseFull(id[:12]); err == nil {
		t.Error("ParseFull must not accept a partial id")
	}
}

func TestWhatIsRefused(t *testing.T) {
	id, _ := testIDs(t)
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{"*chat.example.org", "empty"},
		{"---", "empty"},
		// Not an id at all. A prefix carries no checksum, so the charset check
		// is the only thing between a pasted fragment of something else and a
		// lookup that treats it as an address.
		{"hello*chat.example.org", "is not an id"},
		{"q2xjx!", "is not an id"},
		// A scheme with nothing behind it. Passed on, this becomes a request
		// against a nonsense URL and reads as an unreachable server.
		{id + "*https://", "names no server"},
		{id + "*://", "names no server"},
	} {
		if _, err := Parse(tc.raw); err == nil {
			t.Errorf("Parse(%q) should have failed", tc.raw)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %q, want it to mention %q", tc.raw, err, tc.want)
		}
	}
	if _, err := Parse(""); !errors.Is(err, ErrEmptyAddress) {
		t.Errorf("an empty address should be recognisable, got %v", err)
	}
}

// ParseFull leaves the version alone deliberately: whether an address must be
// an account or a group is the caller's rule, and this package has no way to
// know which one asked.
func TestParseFullAcceptsBothVersions(t *testing.T) {
	account, group := testIDs(t)
	for _, id := range []string{account, group} {
		got, err := ParseFull(id + "*chat.example.org")
		if err != nil {
			t.Fatalf("ParseFull(%q): %v", id, err)
		}
		version, err := VersionOf(got.ID)
		if err != nil {
			t.Fatalf("VersionOf: %v", err)
		}
		if id == group && version != VersionGroup {
			t.Errorf("a group id should still read as one, got version %d", version)
		}
	}
}

// String is what goes into storage, comparisons and log lines, so a round trip
// has to be exact -- if it lost the server, a federated address would come back
// local, which is the failure that started SRV-31.
func TestStringIsCanonicalAndRoundTrips(t *testing.T) {
	id, _ := testIDs(t)
	for _, tc := range []struct{ raw, want string }{
		{id, id},
		{FormatForDisplay(id), id},
		// The default scheme comes off: a non-default one is the part worth
		// noticing, and keeping https:// everywhere makes it harder to spot.
		{id + "*https://chat.example.org", id + "*chat.example.org"},
		{id + "*chat.example.org", id + "*chat.example.org"},
		{id + "*http://box.lan:18081", id + "*http://box.lan:18081"},
		{id + "*local", id},
	} {
		first, err := ParseFull(tc.raw)
		if err != nil {
			t.Fatalf("ParseFull(%q): %v", tc.raw, err)
		}
		if first.String() != tc.want {
			t.Errorf("ParseFull(%q).String() = %q, want %q", tc.raw, first, tc.want)
		}
		second, err := ParseFull(first.String())
		if err != nil {
			t.Fatalf("ParseFull(%q): %v", first, err)
		}
		if first != second {
			t.Errorf("%q: %+v became %+v", tc.raw, first, second)
		}
	}
}

func TestDisplayHyphenatesTheIDOnly(t *testing.T) {
	id, _ := testIDs(t)
	a, err := ParseFull(id + "*chat.example.org")
	if err != nil {
		t.Fatalf("ParseFull: %v", err)
	}
	want := FormatForDisplay(id) + "*chat.example.org"
	if a.Display() != want {
		t.Errorf("Display() = %q, want %q", a.Display(), want)
	}
	// And the two forms are not interchangeable: Display is for reading, String
	// is for comparing, and mixing them up is how one address compares unequal
	// to itself.
	if a.Display() == a.String() {
		t.Error("Display and String should differ once an id is long enough to hyphenate")
	}
}

func TestSameServer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"chat.example.org", "https://chat.example.org", true},
		{"chat.example.org", "https://chat.example.org/", true},
		{"CHAT.example.org", "chat.EXAMPLE.org", true},
		// The scheme is how this client happens to be reaching a server, not
		// part of the server's identity -- the same reason the canonical form
		// drops the default one. This case is why a duplicate check that
		// compares strings reports one recipient as two.
		{"http://chat.example.org", "https://chat.example.org", true},
		// An explicit port usually does point somewhere genuinely different,
		// so it is compared exactly rather than inferred from the scheme.
		{"chat.example.org", "chat.example.org:8443", false},
		{"http://box.lan:18080", "http://box.lan:18081", false},
		{"box.lan", "other.lan", false},
		// "Our own server" is one server, and is not any named host.
		{"", "local", true},
		{"local", "LOCAL", true},
		{"", "chat.example.org", false},
	} {
		if got := SameServer(tc.a, tc.b); got != tc.want {
			t.Errorf("SameServer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := SameServer(tc.b, tc.a); got != tc.want {
			t.Errorf("SameServer(%q, %q) = %v, want %v (not symmetric)", tc.b, tc.a, got, tc.want)
		}
	}
}
