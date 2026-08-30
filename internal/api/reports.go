// Reports: a member telling this server's operator that an account is a
// problem (SRV-33). See docs/design/33-abuse-reports.md for why they are named
// rather than anonymous, and why the counter is a reason to talk to somebody
// rather than a finding.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// maxOpenReportsPerReporter bounds how many open reports one account can have
// outstanding. The unique constraint already stops repeat-reporting the same
// account; this stops one account papering the whole server. Policy, not a
// property of the data, which is why it lives here and not in the schema.
const maxOpenReportsPerReporter = 20

// maxEvidenceClaims bounds the profile-claim history a report may carry.
// Matches the client's own cap (pkg/client's maxProfileClaims).
const maxEvidenceClaims = 10

type reportRequest struct {
	Reported string               `json:"reported"`
	Category string               `json:"category"`
	Evidence []profileclaim.Claim `json:"evidence"`
}

// federatedReportRequest is reportRequest plus the inline identity a sender on
// another server authenticates with -- the same three fields, verified the
// same way, as a federated message (PROTOCOL §9).
//
// SenderServer has no counterpart there, where the home server travels inside
// the encrypted payload instead. A report has no such channel and needs the
// address anyway: the whole point of naming a reporter is that the operator
// can go and ask them what happened, which takes a reachable address rather
// than an id. It is **not** verifiable, and does not need to be -- the id is
// proven cryptographically, and a reporter who names the wrong server only
// makes themselves unreachable.
type federatedReportRequest struct {
	reportRequest
	SenderAccountID  string                  `json:"sender_account_id"`
	SenderServer     string                  `json:"sender_server"`
	SenderRootPubKey string                  `json:"sender_root_pub_key"`
	SenderDeviceCert federationDeviceCertDTO `json:"sender_device_cert"`
}

// federatedReporter validates the claimed home server and returns it.
//
// Empty is refused rather than defaulted, because an empty server *means*
// "on this server" everywhere else in the reports table -- accepting one here
// would file a stranger's report as a local member's.
func (a *API) federatedReporter(w http.ResponseWriter, claimed string) (string, bool) {
	server := address.NormalizeServer(claimed)
	if server == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"sender_server is required: the operator has to be able to reach you about this")
		return "", false
	}
	if u, err := url.Parse(server); err != nil || u.Host == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "sender_server names no server")
		return "", false
	}
	return server, true
}

type reportResponse struct {
	ID       int64  `json:"id"`
	Reported string `json:"reported"`
	Reporter string `json:"reporter"`
	Category string `json:"category"`
	State    string `json:"state"`

	// Evidence is passed back as it was stored, with EvidenceVerified saying
	// whether this server could check the signatures. The admin client checks
	// them again itself -- a client does not have to take the server's word
	// for a signature.
	Evidence         json.RawMessage `json:"evidence,omitempty"`
	EvidenceVerified bool            `json:"evidence_verified"`

	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
	ResolvedBy *string `json:"resolved_by,omitempty"`
	ResolvedAt *string `json:"resolved_at,omitempty"`
}

// handleCreateReport records a report from an account on this server, about
// any address -- local or federated.
//
// Filing with one's own server always happens, and this is that endpoint. It
// deliberately does **not** forward anything: §9 has no server-to-server
// relay, so a reporter who also wants the target's operator to know posts to
// that server's POST /v1/federation/reports itself, exactly as it delivers a
// federated message itself. That is also the honest shape for the choice --
// handing your identity to an operator you do not know is not always right,
// and it should be a decision rather than a side effect.
func (a *API) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) {
		return
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req reportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	a.saveReport(w, req, identity.AccountID, "")
}

// handleCreateFederatedReport is the same thing from a reporter on another
// server, about a local account. Public, because it does its own
// authentication -- the inline certificate chain a federated message uses.
func (a *API) handleCreateFederatedReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) {
		return
	}
	if !a.federationEnabled(w) {
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req federatedReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.SenderAccountID == "" || req.SenderRootPubKey == "" || req.SenderDeviceCert.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"sender_account_id, sender_root_pub_key and sender_device_cert are required")
		return
	}

	sender, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
		AccountID:   req.SenderAccountID,
		RootPubKey:  req.SenderRootPubKey,
		DeviceCert:  req.SenderDeviceCert,
		RequestBody: body,
	})
	if !ok {
		return
	}

	// A federated reporter may only report *here*, about an account that lives
	// here. Anything else would make this server a notice board for disputes
	// between two other servers.
	reported, err := address.ParseFull(req.Reported)
	if err != nil || reported.Server != "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"reported must be an account on this server")
		return
	}
	server, ok := a.federatedReporter(w, req.SenderServer)
	if !ok {
		return
	}
	a.saveReport(w, req.reportRequest, sender.AccountID, server)
}

// saveReport is the shared half: validate, verify what can be verified, store.
func (a *API) saveReport(w http.ResponseWriter, req reportRequest, reporterID, reporterServer string) {
	// A reporter this server knows is filed as local whatever the request
	// claimed. Otherwise a local account could come in through the federated
	// route with a made-up sender_server and land a *second* row against the
	// same target -- the unique constraint is per (reporter, reported), so the
	// counter would double for the price of one lie this server can disprove
	// by looking.
	if reporterServer != "" {
		if _, err := store.GetAccount(a.DB, reporterID); err == nil {
			reporterServer = ""
		} else if !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	if !store.ValidReportCategory(req.Category) {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"category must be one of spam, harassment, fraud, other")
		return
	}
	reported, err := address.ParseFull(req.Reported)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "reported is not a valid address")
		return
	}
	if reported.ID == reporterID && reported.Server == reporterServer {
		writeError(w, http.StatusForbidden, "forbidden", "an account cannot report itself")
		return
	}
	if len(req.Evidence) > maxEvidenceClaims {
		writeError(w, http.StatusBadRequest, "invalid_request", "too many evidence entries")
		return
	}

	// A local target must exist. A federated one is taken on trust: this server
	// has no way to ask, and refusing would make reporting a stranger depend on
	// their server being reachable at the moment somebody complains.
	if reported.Server == "" {
		if _, err := store.GetAccount(a.DB, reported.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "no such account")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	open, err := store.CountOpenReportsBy(a.DB, reporterID, reporterServer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if open >= maxOpenReportsPerReporter {
		writeError(w, http.StatusConflict, "report_limit",
			"too many reports are already open from this account")
		return
	}

	evidence, verified, err := a.checkEvidence(reported, req.Evidence)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	report := store.Report{
		ReportedID: reported.ID, ReportedServer: reported.Server,
		ReporterID: reporterID, ReporterServer: reporterServer,
		Category: req.Category, Evidence: evidence, EvidenceVerified: verified,
	}
	if err := store.SaveReport(a.DB, report, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

// checkEvidence verifies the profile claims a report carries, when it can.
//
// It can only do so for a local target, whose root key and device
// certificates this server holds. For a federated one the claims are stored
// unverified rather than fetching a stranger's key material on the say-so of
// whoever is complaining about them. Either way the admin client verifies
// again itself.
//
// A claim that does not verify is dropped, not refused: a report is worth
// having without its evidence, and rejecting the whole thing over one bad
// entry would let a broken client silence a real complaint.
func (a *API) checkEvidence(reported address.Address, claims []profileclaim.Claim) (*string, bool, error) {
	if len(claims) == 0 {
		return nil, false, nil
	}

	kept := claims
	verified := false
	if reported.Server == "" {
		devices, err := store.ListDevicesByAccount(a.DB, reported.ID)
		if err != nil {
			return nil, false, err
		}
		keys := make(map[string][]byte, len(devices))
		for _, d := range devices {
			keys[d.DeviceID] = d.DevicePubKey
		}

		kept = kept[:0]
		for _, c := range claims {
			key, known := keys[c.DeviceID]
			if !known {
				continue
			}
			if err := c.Verify(reported.ID, key); err != nil {
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			return nil, false, nil
		}
		verified = true
	}

	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, false, err
	}
	s := string(encoded)
	return &s, verified, nil
}

// handleWithdrawReport takes back a report. Somebody who bears responsibility
// for an accusation has to be able to change their mind.
//
// A withdrawal deletes rather than resolves: keeping it as a resolved case
// would leave the accusation on the record, which is exactly what withdrawing
// is meant to undo.
func (a *API) handleWithdrawReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) {
		return
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	a.withdrawReport(w, r.PathValue("reported"), identity.AccountID, "")
}

// handleWithdrawFederatedReport is the same, authenticated the federated way.
func (a *API) handleWithdrawFederatedReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) || !a.federationEnabled(w) {
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req federatedReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	sender, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
		AccountID:   req.SenderAccountID,
		RootPubKey:  req.SenderRootPubKey,
		DeviceCert:  req.SenderDeviceCert,
		RequestBody: body,
	})
	if !ok {
		return
	}
	server, ok := a.federatedReporter(w, req.SenderServer)
	if !ok {
		return
	}
	a.withdrawReport(w, r.PathValue("reported"), sender.AccountID, server)
}

func (a *API) withdrawReport(w http.ResponseWriter, reportedRaw, reporterID, reporterServer string) {
	reported, err := address.ParseFull(reportedRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "reported is not a valid address")
		return
	}
	err = store.WithdrawReport(a.DB, reporterID, reporterServer, reported.ID, reported.Server)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no report from this account about that address")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListReports is the moderation queue.
//
// A moderator sees reports whose target is a regular member; ones targeting a
// moderator or an admin are admin-only, and the query does not ask for them
// rather than filtering them out afterwards (SRV-14's precedent). A moderator
// investigating a colleague is not a moderation case any more, it is the
// operator's -- and showing an accusation to somebody forbidden to act on it
// produces exactly the corridor gossip that avoids.
func (a *API) handleListReports(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) {
		return
	}
	identity, ok := requireAdminOrModerator(w, r)
	if !ok {
		return
	}

	openOnly := r.URL.Query().Get("state") == store.ReportOpen
	reports, err := store.ListReports(a.DB, openOnly, identity.Role == store.RoleAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := make([]reportResponse, 0, len(reports))
	for _, rep := range reports {
		resp = append(resp, reportResponseFrom(rep))
	}
	writeJSON(w, http.StatusOK, resp)
}

type resolveReportRequest struct {
	Outcome string `json:"outcome"`
}

// handleResolveReport records what was done about a report.
//
// Resolving is not deleting and there is no counter reset: the value of an old
// report is that the next moderator can see there was one and how it went.
// "abusive" counts against the *reporter*, which is the counterweight to named
// reporting -- without it, responsibility costs nothing.
func (a *API) handleResolveReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsEnabled(w) {
		return
	}
	identity, ok := requireAdminOrModerator(w, r)
	if !ok {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "id must be a number")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req resolveReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if !store.ValidReportOutcome(req.Outcome) {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"outcome must be one of actioned, dismissed, abusive")
		return
	}

	report, err := store.GetReport(a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such report")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if ok := a.mayActOnReport(w, identity, *report, req.Outcome); !ok {
		return
	}

	if err := store.ResolveReport(a.DB, id, req.Outcome, identity.AccountID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// mayActOnReport applies the two role rules a moderator is bound by, in both
// directions: they may not resolve a report *about* staff, and they may not
// mark a report *by* staff abusive. Both mirror SRV-08 -- a moderator's reach
// stops at regular members, whichever end of the case they are at.
func (a *API) mayActOnReport(w http.ResponseWriter, identity auth.Identity, report store.Report, outcome string) bool {
	if identity.Role == store.RoleAdmin {
		return true
	}
	if staff, err := a.isLocalStaff(report.ReportedID, report.ReportedServer); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return false
	} else if staff {
		writeError(w, http.StatusForbidden, "forbidden",
			"reports about a moderator or an admin are for admins to resolve")
		return false
	}
	if outcome == store.ReportAbusive {
		if staff, err := a.isLocalStaff(report.ReporterID, report.ReporterServer); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return false
		} else if staff {
			writeError(w, http.StatusForbidden, "forbidden",
				"only an admin may mark a report by a moderator or an admin abusive")
			return false
		}
	}
	return true
}

func (a *API) isLocalStaff(id, server string) (bool, error) {
	if server != "" {
		return false, nil
	}
	account, err := store.GetAccount(a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return account.Role == store.RoleAdmin || account.Role == store.RoleModerator, nil
}

// reportsEnabled is the operator kill switch, in the shape of
// FederationEnabled/BlobsEnabled: a route that answers 404 with a body saying
// what is missing, so a client can tell "switched off here" from "too old to
// know about this".
func (a *API) reportsEnabled(w http.ResponseWriter) bool {
	if !a.Config.ReportsEnabled {
		writeError(w, http.StatusNotFound, "reports_disabled", "reporting is disabled on this server")
		return false
	}
	return true
}

// federationEnabled gates the two routes a stranger can reach. DB-authoritative
// like every other federation check (admin-settable at runtime via PUT
// /v1/admin/federation); the config value is only the first-boot seed.
func (a *API) federationEnabled(w http.ResponseWriter) bool {
	enabled, err := store.GetFederationEnabled(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return false
	}
	if !enabled {
		writeError(w, http.StatusNotFound, "federation_disabled", "federation is disabled on this server")
		return false
	}
	return true
}

func reportResponseFrom(r store.Report) reportResponse {
	resp := reportResponse{
		ID:               r.ID,
		Reported:         address.Address{ID: r.ReportedID, Server: r.ReportedServer}.String(),
		Reporter:         address.Address{ID: r.ReporterID, Server: r.ReporterServer}.String(),
		Category:         r.Category,
		State:            r.State,
		EvidenceVerified: r.EvidenceVerified,
		CreatedAt:        r.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:        r.UpdatedAt.UTC().Format(time.RFC3339),
		ResolvedBy:       r.ResolvedBy,
	}
	if r.Evidence != nil {
		resp.Evidence = json.RawMessage(*r.Evidence)
	}
	if r.ResolvedAt != nil {
		at := r.ResolvedAt.UTC().Format(time.RFC3339)
		resp.ResolvedAt = &at
	}
	return resp
}
