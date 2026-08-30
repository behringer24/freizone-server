package client

import (
	"errors"
	"testing"
)

// reportPair is two accounts on one server where the reporter has already
// received a signed name claim from the other -- the state a real report is
// filed from.
func reportPair(t *testing.T) (srv *fakeServer, reporter, reported *Client, reportedID string) {
	t.Helper()
	srv = newFakeServer(t)
	reporter = srv.account(t, "alice")
	reported = srv.account(t, "bob")
	reportedID = identityOf(t, reported).AccountID

	if err := reported.SetProfileName("Bank Support"); err != nil {
		t.Fatalf("SetProfileName: %v", err)
	}
	if _, err := reported.SendText(t.Context(), identityOf(t, reporter).AccountID, "hello", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if _, err := reporter.Drain(t.Context(), ReceiveOptions{}); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if got := profileNameOf(t, reporter, reportedID); got != "Bank Support" {
		t.Fatalf("the claim did not arrive: stored name is %q", got)
	}
	return srv, reporter, reported, reportedID
}

func profileNameOf(t *testing.T, c *Client, peer string) string {
	t.Helper()
	profile, err := c.PeerProfile(peer)
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	return profile.Name()
}

func TestReportSendsTheAssertedNameAsEvidence(t *testing.T) {
	srv, reporter, _, reportedID := reportPair(t)

	if err := reporter.Report(t.Context(), reportedID, ReportFraud, ReportOptions{}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	reports := srv.recordedReports()
	if len(reports) != 1 {
		t.Fatalf("%d reports reached the server, want 1", len(reports))
	}
	if reports[0].path != "/v1/reports" {
		t.Errorf("posted to %q, want the account's own server", reports[0].path)
	}
	if reports[0].category != string(ReportFraud) {
		t.Errorf("category = %q", reports[0].category)
	}
	if len(reports[0].evidence) != 1 || reports[0].evidence[0].Name != "Bank Support" {
		t.Fatalf("evidence = %v, want the name they asserted about themselves", reports[0].evidence)
	}
	// Forwarded verbatim, signature included -- that is what makes the name
	// evidence a moderator can check rather than one more claim by the reporter.
	if len(reports[0].evidence[0].Signature) == 0 {
		t.Error("the claim arrived without its signature")
	}
}

// A peer that has never asserted a name sends no evidence -- and no
// substitute. The name this user gave them lives in another store entirely,
// and nothing here may reach for it.
func TestReportWithoutAClaimSendsNoEvidence(t *testing.T) {
	srv := newFakeServer(t)
	reporter := srv.account(t, "alice")
	reported := srv.account(t, "bob")
	reportedID := identityOf(t, reported).AccountID
	if _, err := reporter.StartConversation(t.Context(), reportedID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	if err := reporter.Report(t.Context(), reportedID, ReportSpam, ReportOptions{}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	reports := srv.recordedReports()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want 1", len(reports))
	}
	if len(reports[0].evidence) != 0 {
		t.Errorf("evidence = %v, want none", reports[0].evidence)
	}
}

func TestReportRefusesAnUnknownCategory(t *testing.T) {
	_, reporter, _, reportedID := reportPair(t)

	if err := reporter.Report(t.Context(), reportedID, ReportCategory("something-else"), ReportOptions{}); err == nil {
		t.Error("an unknown category was accepted")
	}
}

func TestReportRefusesReportingYourself(t *testing.T) {
	srv := newFakeServer(t)
	me := srv.account(t, "alice")

	if err := me.Report(t.Context(), identityOf(t, me).AccountID, ReportSpam, ReportOptions{}); err == nil {
		t.Error("an account reported itself")
	}
}

func TestReportSurfacesAServerWithReportingOff(t *testing.T) {
	srv, reporter, _, reportedID := reportPair(t)
	srv.setReportsEnabled(false)

	err := reporter.Report(t.Context(), reportedID, ReportSpam, ReportOptions{})
	if !errors.Is(err, ErrReportsUnavailable) {
		t.Errorf("err = %v, want ErrReportsUnavailable", err)
	}

	// And discoverable in advance, which is how a caller avoids offering the
	// action at all rather than failing after the fact.
	status, err := reporter.ServerStatus(t.Context(), "")
	if err != nil {
		t.Fatalf("ServerStatus: %v", err)
	}
	if status.ReportsEnabled {
		t.Error("server-status still advertises reporting")
	}
}

func TestWithdrawTreatsNoSuchReportAsDone(t *testing.T) {
	_, reporter, _, reportedID := reportPair(t)

	// Never reported in the first place: what the user asked for is already
	// true, so this is not an error to put in front of them.
	if err := reporter.WithdrawReport(t.Context(), reportedID); err != nil {
		t.Errorf("WithdrawReport with nothing to withdraw: %v", err)
	}
}

// "reports_disabled" is also a 404, and must not be swallowed as "there was no
// report" -- that would look like a withdrawal that worked.
func TestWithdrawStillSurfacesReportingOff(t *testing.T) {
	srv, reporter, _, reportedID := reportPair(t)
	srv.setReportsEnabled(false)

	err := reporter.WithdrawReport(t.Context(), reportedID)
	if !errors.Is(err, ErrReportsUnavailable) {
		t.Errorf("err = %v, want ErrReportsUnavailable", err)
	}
}

func TestReportAndWithdrawRoundTrip(t *testing.T) {
	srv, reporter, _, reportedID := reportPair(t)

	if err := reporter.Report(t.Context(), reportedID, ReportHarassment, ReportOptions{}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if err := reporter.WithdrawReport(t.Context(), reportedID); err != nil {
		t.Fatalf("WithdrawReport: %v", err)
	}
	if reports := srv.recordedReports(); len(reports) != 0 {
		t.Errorf("%d reports left standing after a withdrawal", len(reports))
	}
}

// The evidence is the current name *and* the history behind it: an account
// that renamed itself after doing something is exactly the case where the
// sequence is the point.
func TestReportCarriesTheNameHistory(t *testing.T) {
	srv, reporter, reported, reportedID := reportPair(t)

	if err := reported.SetProfileName("Peter"); err != nil {
		t.Fatalf("SetProfileName: %v", err)
	}
	if _, err := reported.SendText(t.Context(), identityOf(t, reporter).AccountID, "and again", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if _, err := reporter.Drain(t.Context(), ReceiveOptions{}); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if err := reporter.Report(t.Context(), reportedID, ReportFraud, ReportOptions{}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	reports := srv.recordedReports()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want 1", len(reports))
	}
	names := make([]string, 0, len(reports[0].evidence))
	for _, claim := range reports[0].evidence {
		names = append(names, claim.Name)
	}
	if len(names) != 2 || names[0] != "Peter" || names[1] != "Bank Support" {
		t.Errorf("evidence names = %v, want the newest first and the one it replaced behind it", names)
	}
}
