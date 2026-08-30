package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

func reportBody(t *testing.T, reported, category string, evidence []profileclaim.Claim) []byte {
	t.Helper()
	body, err := json.Marshal(reportRequest{Reported: reported, Category: category, Evidence: evidence})
	if err != nil {
		t.Fatalf("marshalling report: %v", err)
	}
	return body
}

// fileReport posts a report from k about reported, asserting it was accepted.
func fileReport(t *testing.T, a *API, k identityKeys, reported string) {
	t.Helper()
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, reported, store.ReportSpam, nil), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("report status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
}

// adminList reads the account list as k and returns the row for accountID.
func adminList(t *testing.T, a *API, k identityKeys, accountID string) adminAccountResponse {
	t.Helper()
	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("account list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var accounts []adminAccountResponse
	decodeJSON(t, rec, &accounts)
	for _, acc := range accounts {
		if acc.ID == accountID {
			return acc
		}
	}
	t.Fatalf("account %s not in the list", accountID)
	return adminAccountResponse{}
}

func listReports(t *testing.T, a *API, k identityKeys) []reportResponse {
	t.Helper()
	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/reports", nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("report list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var reports []reportResponse
	decodeJSON(t, rec, &reports)
	return reports
}

func TestReportRaisesTheCounterAndShowsTheCase(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)

	fileReport(t, a, reporter, target.accountID)

	row := adminList(t, a, admin, target.accountID)
	if row.ReportsLocal != 1 || row.ReportsFederated != 0 {
		t.Errorf("counters: got local=%d federated=%d, want 1 and 0",
			row.ReportsLocal, row.ReportsFederated)
	}
	if filed := adminList(t, a, admin, reporter.accountID).ReportsFiled; filed != 1 {
		t.Errorf("the reporter's own filed count is %d, want 1 -- the mirror is what makes brigading visible", filed)
	}

	reports := listReports(t, a, admin)
	if len(reports) != 1 {
		t.Fatalf("report list has %d entries, want 1", len(reports))
	}
	if reports[0].Reporter != reporter.accountID {
		t.Errorf("reporter: got %q, want %q -- reporting is named, that is the point",
			reports[0].Reporter, reporter.accountID)
	}
}

// One reporter counts once, however often they press the button.
func TestReportingTwiceIsStillOneReport(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)

	fileReport(t, a, reporter, target.accountID)
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, target.accountID, store.ReportFraud, nil), reporter.deviceID, reporter.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second report status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if got := adminList(t, a, admin, target.accountID).ReportsLocal; got != 1 {
		t.Errorf("counter is %d after reporting twice, want 1", got)
	}
	reports := listReports(t, a, admin)
	if len(reports) != 1 {
		t.Fatalf("report list has %d entries, want 1", len(reports))
	}
	if reports[0].Category != store.ReportFraud {
		t.Errorf("category: got %q, want the updated %q", reports[0].Category, store.ReportFraud)
	}
}

func TestWithdrawingAReportDropsTheCounter(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)

	fileReport(t, a, reporter, target.accountID)
	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/reports/"+target.accountID,
		nil, reporter.deviceID, reporter.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("withdraw status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if got := adminList(t, a, admin, target.accountID).ReportsLocal; got != 0 {
		t.Errorf("counter is %d after withdrawal, want 0 -- responsibility has to be revocable", got)
	}
}

func TestReportingYourselfIsRefused(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, k.accountID, store.ReportSpam, nil), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// Andreas' rule, and the one this whole role section turns on: a moderator can
// *report* an admin. They just cannot act on it afterwards.
func TestAModeratorMayReportAnAdmin(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	moderator := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	if err := store.SetAccountRole(db, moderator.accountID, store.RoleModerator); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, admin.accountID, store.ReportHarassment, nil), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a moderator could not report an admin: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// ...but it is not theirs to see or to resolve.
	if reports := listReports(t, a, moderator); len(reports) != 0 {
		t.Errorf("a moderator sees %d reports about staff, want 0", len(reports))
	}
	reports := listReports(t, a, admin)
	if len(reports) != 1 {
		t.Fatalf("the admin sees %d reports, want 1", len(reports))
	}

	body, _ := json.Marshal(resolveReportRequest{Outcome: store.ReportDismissed})
	rec = doSignedRequest(t, a.Router(), http.MethodPost,
		"/v1/admin/reports/"+itoa(reports[0].ID)+"/resolve", body, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a moderator resolving a report about an admin: status = %d, want 403", rec.Code)
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPost,
		"/v1/admin/reports/"+itoa(reports[0].ID)+"/resolve", body, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Errorf("the admin resolving it: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// A moderator sees and resolves ordinary members' cases -- SRV-08's whole
// point was that moderating does not require being an admin.
func TestAModeratorResolvesAnOrdinaryCase(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	moderator := registerAccount(t, a)
	if err := store.SetAccountRole(db, moderator.accountID, store.RoleModerator); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)
	fileReport(t, a, reporter, target.accountID)

	reports := listReports(t, a, moderator)
	if len(reports) != 1 {
		t.Fatalf("a moderator sees %d reports about a member, want 1", len(reports))
	}
	body, _ := json.Marshal(resolveReportRequest{Outcome: store.ReportActioned})
	rec := doSignedRequest(t, a.Router(), http.MethodPost,
		"/v1/admin/reports/"+itoa(reports[0].ID)+"/resolve", body, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Resolved, not deleted: the case stays readable, which is the whole
	// reason there is no counter reset.
	after := listReports(t, a, moderator)
	if len(after) != 1 || after[0].State != store.ReportActioned {
		t.Errorf("after resolving: %d entries, state %q -- want it kept and marked", len(after), after[0].State)
	}
}

// A moderator may not mark a report *by* staff abusive: the same limit in the
// mirror direction.
func TestAModeratorMayNotMarkAStaffReportAbusive(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	moderator := registerAccount(t, a)
	staffReporter := registerAccount(t, a)
	if err := store.SetAccountRole(db, moderator.accountID, store.RoleModerator); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	if err := store.SetAccountRole(db, staffReporter.accountID, store.RoleModerator); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	target := registerAccount(t, a)
	fileReport(t, a, staffReporter, target.accountID)

	reports := listReports(t, a, moderator)
	if len(reports) != 1 {
		t.Fatalf("report list has %d entries, want 1", len(reports))
	}
	body, _ := json.Marshal(resolveReportRequest{Outcome: store.ReportAbusive})
	rec := doSignedRequest(t, a.Router(), http.MethodPost,
		"/v1/admin/reports/"+itoa(reports[0].ID)+"/resolve", body, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestReportEvidenceIsVerifiedAndForgeryDropped(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)

	genuine, err := profileclaim.Sign(target.accountID, target.deviceID, "Bank Support",
		time.Now(), target.devicePriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Signed by the reporter's key, claiming to be the target's device: the
	// forgery a reporter would attempt if the evidence were taken on trust.
	forged, err := profileclaim.Sign(target.accountID, target.deviceID, "Something Worse",
		time.Now(), reporter.devicePriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, target.accountID, store.ReportFraud, []profileclaim.Claim{*genuine, *forged}),
		reporter.deviceID, reporter.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("report status = %d, body = %s", rec.Code, rec.Body.String())
	}

	reports := listReports(t, a, admin)
	if len(reports) != 1 {
		t.Fatalf("report list has %d entries, want 1", len(reports))
	}
	if !reports[0].EvidenceVerified {
		t.Error("evidence about a local account was not verified, though this server holds its keys")
	}
	var kept []profileclaim.Claim
	if err := json.Unmarshal(reports[0].Evidence, &kept); err != nil {
		t.Fatalf("decoding evidence: %v", err)
	}
	if len(kept) != 1 || kept[0].Name != "Bank Support" {
		t.Fatalf("evidence kept %d claims (%v), want only the genuine one", len(kept), kept)
	}
}

func TestReportsGoWithTheAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)
	fileReport(t, a, reporter, target.accountID)

	if err := store.DeleteAccount(db, target.accountID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if n := countReports(t, db); n != 0 {
		t.Errorf("%d reports survived the account they were about", n)
	}

	// And the same in the other direction: an accusation nobody can be asked
	// about goes too.
	other := registerAccount(t, a)
	fileReport(t, a, reporter, other.accountID)
	if err := store.DeleteAccount(db, reporter.accountID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if n := countReports(t, db); n != 0 {
		t.Errorf("%d reports survived the account that made them", n)
	}
}

func TestReportsRespectTheOperatorSwitch(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.ReportsEnabled = false
	k := registerAccount(t, a)
	target := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, target.accountID, store.ReportSpam, nil), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when reporting is switched off", rec.Code)
	}

	// Discoverable rather than guessable: a client checks this before it
	// offers the button at all.
	rec = doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	var status serverStatusResponse
	decodeJSON(t, rec, &status)
	if status.ReportsEnabled {
		t.Error("server-status still advertises reports as enabled")
	}
}

func TestReportLimitStopsOneAccountPaperingTheServer(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	reporter := registerAccount(t, a)

	for i := 0; i < maxOpenReportsPerReporter; i++ {
		fileReport(t, a, reporter, registerAccount(t, a).accountID)
	}
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, registerAccount(t, a).accountID, store.ReportSpam, nil),
		reporter.deviceID, reporter.devicePriv)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 past the open-report cap", rec.Code)
	}
}

func TestReportRejectsAnUnknownCategory(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	target := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/reports",
		reportBody(t, target.accountID, "whatever-they-typed", nil), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 -- categories are a fixed set, and there is no free text", rec.Code)
	}
}

func countReports(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM reports`).Scan(&n); err != nil {
		t.Fatalf("counting reports: %v", err)
	}
	return n
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

func federatedReportBody(t *testing.T, sender identityKeys, senderServer, reported, category string) []byte {
	t.Helper()
	body, err := json.Marshal(federatedReportRequest{
		reportRequest:    reportRequest{Reported: reported, Category: category},
		SenderAccountID:  sender.accountID,
		SenderServer:     senderServer,
		SenderRootPubKey: b64(sender.rootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     sender.deviceID,
			DevicePubKey: b64(sender.devicePub),
			IssuedAt:     sender.issuedAt.UTC().Format(time.RFC3339),
			Signature:    b64(sender.certSignature(t)),
		},
	})
	if err != nil {
		t.Fatalf("marshalling federated report: %v", err)
	}
	return body
}

func TestFederatedReportCountsSeparately(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	target := registerAccount(t, a)
	// A stranger: keys that were never registered here.
	stranger := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/reports",
		federatedReportBody(t, stranger, "https://elsewhere.test", target.accountID, store.ReportFraud),
		stranger)
	if rec.Code != http.StatusCreated {
		t.Fatalf("federated report status = %d, body = %s", rec.Code, rec.Body.String())
	}

	row := adminList(t, a, admin, target.accountID)
	if row.ReportsFederated != 1 || row.ReportsLocal != 0 {
		t.Errorf("counters: got local=%d federated=%d, want 0 and 1 -- they are never summed, because "+
			"anybody on any server can raise the second", row.ReportsLocal, row.ReportsFederated)
	}
	reports := listReports(t, a, admin)
	if len(reports) != 1 {
		t.Fatalf("report list has %d entries, want 1", len(reports))
	}
	// Canonical form, as PROTOCOL §1 spells an address -- no scheme.
	if reports[0].Reporter != stranger.accountID+"*elsewhere.test" {
		t.Errorf("reporter address is %q -- the operator has to be able to reach them", reports[0].Reporter)
	}
}

// Without a home server the operator cannot come back to the reporter, and an
// empty one would file a stranger as a local member.
func TestFederatedReportNeedsAHomeServer(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	target := registerAccount(t, a)
	stranger := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/reports",
		federatedReportBody(t, stranger, "", target.accountID, store.ReportSpam), stranger)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 without sender_server", rec.Code)
	}
}

// A local account coming in through the federated door with an invented home
// server must not land a second row against the same target.
func TestALocalReporterCannotDoubleUpViaFederation(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(db, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	reporter := registerAccount(t, a)
	target := registerAccount(t, a)

	fileReport(t, a, reporter, target.accountID)
	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/reports",
		federatedReportBody(t, reporter, "https://not-really.test", target.accountID, store.ReportSpam),
		reporter)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	row := adminList(t, a, admin, target.accountID)
	if row.ReportsLocal != 1 || row.ReportsFederated != 0 {
		t.Errorf("counters: got local=%d federated=%d, want 1 and 0 -- a reporter this server knows is "+
			"filed as local whatever the request claimed", row.ReportsLocal, row.ReportsFederated)
	}
	if n := countReports(t, db); n != 1 {
		t.Errorf("%d rows, want 1 -- the counter must not double for the price of one lie", n)
	}
}

func TestFederatedReportRefusesAForeignTarget(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	stranger := newIdentityKeys(t)
	other := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/reports",
		federatedReportBody(t, stranger, "https://elsewhere.test",
			other.accountID+"*https://third-party.test", store.ReportSpam), stranger)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 -- this server is not a notice board for other servers' disputes", rec.Code)
	}
}
