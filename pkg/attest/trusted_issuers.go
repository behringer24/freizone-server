// SPDX-License-Identifier: MIT
package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
)

// TrustedIssuers holds the issuer public keys this build trusts, compiled
// in at build time.
//
// Several keys ship together rather than one: which key actually signs new
// attestations should be able to change without a release reaching every
// server and client, and only *adding* a new trusted key needs that.
// Provisioning spares up front is what avoids it -- only one of the keys
// below is in active use at any time; the rest are cold spares generated
// alongside it. See docs/design/19-attested-servers.md for the trade-off
// this implies for a compromised key: it stays usable until the
// attestations it signed expire, since there is no revocation beyond that.
var TrustedIssuers = []ed25519.PublicKey{
	mustDecodeIssuerKey("3DtD9hnvC14H1eelBgr4jITrN8HqPHZzGQxJfpEVUOc="),
	mustDecodeIssuerKey("QnjvdpMp7420B1xN9+G/Ej2wpZ7zH+t4bVOHk+Vg96s="),
	mustDecodeIssuerKey("i6d2Umn7X8uQIynzdspuMW2M8++E7vkU4A+tWqsY+zU="),
	mustDecodeIssuerKey("wKhG/0jcNmFoHLld0nTTeO7Nm+y3GqW0ofC6TTF6j2E="),
	mustDecodeIssuerKey("GR7iWl1naQcxxzGgvYHehxOFX8JM1FbFURdl9WKg3Zw="),
}

// mustDecodeIssuerKey decodes a base64-encoded Ed25519 public key, panicking
// on failure. Only ever called on the fixed literals above, at package
// initialization -- a panic here means this file itself was edited
// incorrectly (a typo'd or truncated key), not something reachable at
// runtime from any input a caller controls.
func mustDecodeIssuerKey(b64 string) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("attest: invalid trusted issuer key: " + err.Error())
	}
	if len(raw) != ed25519.PublicKeySize {
		panic("attest: trusted issuer key must be 32 bytes, got " + strconv.Itoa(len(raw)))
	}
	return ed25519.PublicKey(raw)
}
