package store

import (
	"testing"
	"time"
)

func seedReport(t *testing.T, db DBTX, reporter, reported string, now time.Time) {
	t.Helper()
	if err := SaveReport(db, Report{
		ReportedID: reported, ReporterID: reporter, Category: ReportSpam,
	}, now); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
}

// Re-reporting an account whose case was already dealt with reopens that case
// rather than adding a second: the reporter is saying it happened again, which
// is exactly what a moderator needs to see.
func TestReportingAgainReopensAResolvedCase(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()

	seedReport(t, db, "reporter", "target", now)
	reports, err := ListReports(db, false, true)
	if err != nil || len(reports) != 1 {
		t.Fatalf("ListReports = %v, %v", reports, err)
	}
	if err := ResolveReport(db, reports[0].ID, ReportDismissed, "mod", now); err != nil {
		t.Fatalf("ResolveReport: %v", err)
	}

	seedReport(t, db, "reporter", "target", now.Add(time.Hour))

	reports, err = ListReports(db, false, true)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("%d reports, want 1 -- re-reporting must never add a row", len(reports))
	}
	if reports[0].State != ReportOpen {
		t.Errorf("state is %q, want it reopened", reports[0].State)
	}
	if reports[0].ResolvedBy != nil || reports[0].ResolvedAt != nil {
		t.Error("a reopened case still names who resolved it")
	}
}

func TestOpenOnlyHidesResolvedCases(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()

	seedReport(t, db, "reporter", "target", now)
	seedReport(t, db, "reporter", "other", now)
	all, err := ListReports(db, false, true)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListReports = %d entries, %v", len(all), err)
	}
	if err := ResolveReport(db, all[0].ID, ReportActioned, "mod", now); err != nil {
		t.Fatalf("ResolveReport: %v", err)
	}

	open, err := ListReports(db, true, true)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(open) != 1 {
		t.Errorf("%d open reports, want 1", len(open))
	}
	// ...but the resolved one is still there to be read: no counter reset.
	if all, _ = ListReports(db, false, true); len(all) != 2 {
		t.Errorf("%d reports in total, want both kept", len(all))
	}
}

// Retention takes resolved and open alike: an open report nobody acted on in
// three months is not going to be acted on now, and a counter that never falls
// becomes a record for something never proven.
func TestPurgeReportsBeforeTakesBothStates(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -100)

	seedReport(t, db, "reporter", "old-open", old)
	seedReport(t, db, "reporter", "old-resolved", old)
	seedReport(t, db, "reporter", "recent", now)

	reports, err := ListReports(db, false, true)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	for _, r := range reports {
		if r.ReportedID == "old-resolved" {
			if err := ResolveReport(db, r.ID, ReportActioned, "mod", old); err != nil {
				t.Fatalf("ResolveReport: %v", err)
			}
		}
	}

	n, err := PurgeReportsBefore(db, now.AddDate(0, 0, -90))
	if err != nil {
		t.Fatalf("PurgeReportsBefore: %v", err)
	}
	if n != 2 {
		t.Errorf("purged %d, want both old ones whatever their state", n)
	}
	left, err := ListReports(db, false, true)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(left) != 1 || left[0].ReportedID != "recent" {
		t.Errorf("after the purge: %v, want only the recent one", left)
	}
}

func TestCountOpenReportsByIgnoresResolvedOnes(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()

	seedReport(t, db, "reporter", "one", now)
	seedReport(t, db, "reporter", "two", now)
	reports, err := ListReports(db, false, true)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if err := ResolveReport(db, reports[0].ID, ReportDismissed, "mod", now); err != nil {
		t.Fatalf("ResolveReport: %v", err)
	}

	n, err := CountOpenReportsBy(db, "reporter", "")
	if err != nil {
		t.Fatalf("CountOpenReportsBy: %v", err)
	}
	if n != 1 {
		t.Errorf("open reports by that account = %d, want 1 -- the cap is on outstanding ones", n)
	}
}
