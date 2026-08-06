// Admin-only visibility into this server's own attested seat ceiling
// (pkg/attest's Seats, LIC-08) against its actual active-account count.
package api

import (
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/attest"
)

// licenseStatusResponse is the GET /v1/admin/license payload. Deliberately
// never reachable from GET /v1/server-status or the landing page
// (internal/api/landing.go) -- how many accounts a server has is exactly the
// kind of fact that turns "a server exists" into "a server worth attacking",
// and it says nothing a visitor needs to decide whether to trust the
// operator, unlike the attestation token itself.
type licenseStatusResponse struct {
	// Attested is false whenever there is nothing usable to report: no
	// attestation configured, or one that fails to decode, verify, or falls
	// outside its validity window. Every field below is only meaningful when
	// this is true. Mirrors the same "decorative credential, never an
	// error" posture cmd/server's checkAttestation takes at startup, just
	// surfaced to an admin instead of a log line.
	Attested bool   `json:"attested"`
	Tier     string `json:"tier,omitempty"`
	// Seats is the attestation's advisory ceiling, 0 for "unspecified or
	// unlimited" (pkg/attest's Seats doc). Omitted rather than sent as a
	// literal 0 alongside a separate "unlimited" flag -- a client checking
	// for the field's absence and one checking it against 0 both reach the
	// same "nothing to compare against" conclusion.
	Seats     int    `json:"seats,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// ActiveAccounts and OverLimit are meaningful even when Attested is
	// false -- an admin screen can still show the account count on its own.
	ActiveAccounts int  `json:"active_accounts"`
	OverLimit      bool `json:"over_limit"`
}

// handleGetLicenseStatus reports whether this server's active-account count
// exceeds its own attested Seats ceiling. Admin only.
func (a *API) handleGetLicenseStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}

	activeAccounts, err := store.CountActiveAccounts(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := licenseStatusResponse{ActiveAccounts: activeAccounts}

	if att, ok := currentAttestation(a.Config); ok {
		resp.Attested = true
		resp.Tier = att.Tier
		resp.Seats = int(att.Seats)
		resp.ExpiresAt = att.ExpiresAt.UTC().Format(time.RFC3339)
		resp.OverLimit = att.Seats > 0 && uint32(activeAccounts) > att.Seats
	}

	writeJSON(w, http.StatusOK, resp)
}

// currentAttestation decodes, verifies, and validates cfg.Attestation,
// reporting ok only when it is genuinely signed and currently within its
// window. Deliberately mirrors cmd/server's checkAttestation start-up check
// field for field -- including its one quirk: an unset FREIZONE_DOMAIN
// (legitimate behind a reverse-proxy deployment, see config.go's Domain
// field) skips the domain *and* expiry check entirely rather than checking
// expiry alone, because a real client already re-derives both from the
// domain it actually connected to (pkg/attest.Valid) and this server cannot
// itself confirm which domain it is for in that shape. The two checks live
// in different packages (cmd/server is not importable here) and are kept in
// sync by inspection rather than by sharing code; if one changes, check the
// other.
func currentAttestation(cfg *config.Config) (*attest.Attestation, bool) {
	if cfg.Attestation == "" {
		return nil, false
	}
	a, err := attest.Decode(cfg.Attestation)
	if err != nil {
		return nil, false
	}
	if len(attest.TrustedIssuers) == 0 {
		return nil, false
	}
	if err := a.Verify(attest.TrustedIssuers); err != nil {
		return nil, false
	}
	if cfg.Domain == "" {
		return a, true
	}
	if err := a.Valid(cfg.Domain, time.Now()); err != nil {
		return nil, false
	}
	return a, true
}
