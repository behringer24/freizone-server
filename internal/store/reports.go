package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Report states. Resolving is not deleting -- see the migration for why.
const (
	ReportOpen      = "open"
	ReportActioned  = "actioned"
	ReportDismissed = "dismissed"
	ReportAbusive   = "abusive"
)

// Report categories. A fixed set, and no free text: a free-text field on the
// server is a store of personal allegations, and incidentally a channel for
// writing at the operator that nothing moderates.
const (
	ReportSpam       = "spam"
	ReportHarassment = "harassment"
	ReportFraud      = "fraud"
	ReportOther      = "other"
)

// ValidReportCategory reports whether c is one this server accepts.
func ValidReportCategory(c string) bool {
	switch c {
	case ReportSpam, ReportHarassment, ReportFraud, ReportOther:
		return true
	}
	return false
}

// ValidReportOutcome reports whether o is a state a report can be resolved to.
// Deliberately not ReportOpen: reopening is what a fresh report does.
func ValidReportOutcome(o string) bool {
	switch o {
	case ReportActioned, ReportDismissed, ReportAbusive:
		return true
	}
	return false
}

// Report is one case: somebody told this server's operator about an account.
//
// Server is empty for an address on this server, which is what lets the local
// case join against accounts(id). Both sides may be federated -- a local user
// reporting a stranger, or a stranger reporting a local user.
type Report struct {
	ID int64

	ReportedID     string
	ReportedServer string
	ReporterID     string
	ReporterServer string

	Category string

	// Evidence is the SRV-32 profile claims the reporter held, as JSON and as
	// received. EvidenceVerified says whether this server could check their
	// signatures, which it can only do when the reported account is local.
	Evidence         *string
	EvidenceVerified bool

	State     string
	CreatedAt time.Time
	UpdatedAt time.Time

	ResolvedBy *string
	ResolvedAt *time.Time
}

// ReportCounts is what the admin account list shows per account.
//
// Local and Federated are never summed: a mixed figure is trivially inflated
// from outside -- anybody on any server can add to the second -- and a number
// that can be inflated by strangers is a number an operator cannot act on.
type ReportCounts struct {
	// About this account, open only.
	Local     int
	Federated int

	// Filed by this account and still open, and how often one of its reports
	// was resolved as abusive. The mirror that makes brigading visible.
	Filed   int
	Abusive int
}

// SaveReport records a report, or updates the one this reporter already has
// against this account.
//
// Re-reporting refreshes the category and evidence and reopens a resolved
// case; it never adds a row, which is the whole of "one reporter counts once".
// Reopening rather than leaving it resolved is deliberate: the reporter is
// saying it happened again, and that is exactly what a moderator needs to see.
func SaveReport(db DBTX, r Report, now time.Time) error {
	_, err := db.Exec(
		`INSERT INTO reports (reported_id, reported_server, reporter_id, reporter_server,
		                      category, evidence, evidence_verified, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(reporter_id, reporter_server, reported_id, reported_server) DO UPDATE SET
		   category = excluded.category,
		   evidence = excluded.evidence,
		   evidence_verified = excluded.evidence_verified,
		   state = ?,
		   updated_at = excluded.updated_at,
		   resolved_by = NULL,
		   resolved_at = NULL`,
		r.ReportedID, r.ReportedServer, r.ReporterID, r.ReporterServer,
		r.Category, r.Evidence, r.EvidenceVerified, ReportOpen,
		formatTime(now), formatTime(now), ReportOpen,
	)
	if err != nil {
		return fmt.Errorf("store: saving report: %w", err)
	}
	return nil
}

// WithdrawReport removes one reporter's report against one account. Returns
// ErrNotFound when there is nothing to withdraw.
//
// A withdrawal deletes rather than resolves: the reporter is saying the
// accusation should not stand, and keeping it as a resolved case would leave
// the accusation on the record anyway.
func WithdrawReport(db DBTX, reporterID, reporterServer, reportedID, reportedServer string) error {
	res, err := db.Exec(
		`DELETE FROM reports
		 WHERE reporter_id = ? AND reporter_server = ? AND reported_id = ? AND reported_server = ?`,
		reporterID, reporterServer, reportedID, reportedServer,
	)
	if err != nil {
		return fmt.Errorf("store: withdrawing report: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for report withdrawal: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountOpenReportsBy is how many open reports one account has filed, for the
// per-reporter cap. Counted rather than capped by a constraint because the
// limit is policy, not a property of the data.
func CountOpenReportsBy(db DBTX, reporterID, reporterServer string) (int, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(1) FROM reports WHERE reporter_id = ? AND reporter_server = ? AND state = ?`,
		reporterID, reporterServer, ReportOpen,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting open reports by account: %w", err)
	}
	return n, nil
}

// ResolveReport records an outcome. Returns ErrNotFound for an unknown id.
func ResolveReport(db DBTX, id int64, outcome, resolvedBy string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE reports SET state = ?, resolved_by = ?, resolved_at = ?, updated_at = ? WHERE id = ?`,
		outcome, resolvedBy, formatTime(now), formatTime(now), id,
	)
	if err != nil {
		return fmt.Errorf("store: resolving report: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for report resolution: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetReport reads one report. Returns ErrNotFound for an unknown id.
func GetReport(db DBTX, id int64) (*Report, error) {
	rows, err := db.Query(reportColumns+` FROM reports WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("store: reading report: %w", err)
	}
	defer rows.Close()

	reports, err := scanReports(rows)
	if err != nil {
		return nil, err
	}
	if len(reports) == 0 {
		return nil, ErrNotFound
	}
	return &reports[0], nil
}

// ListReports returns reports about local accounts, newest first.
//
// staffVisible false excludes reports whose target is a moderator or an admin,
// for a moderator caller: a moderator investigating a colleague is not a
// moderation case any more, it is the operator's. The exclusion is in the
// query rather than in the serialization, on SRV-14's precedent -- the rule
// should live in what is asked for, not only in what is handed back.
func ListReports(db DBTX, openOnly, staffVisible bool) ([]Report, error) {
	q := reportColumns + ` FROM reports r WHERE 1 = 1`
	var args []any
	if openOnly {
		q += ` AND r.state = ?`
		args = append(args, ReportOpen)
	}
	if !staffVisible {
		q += ` AND NOT EXISTS (
		         SELECT 1 FROM accounts a
		          WHERE a.id = r.reported_id AND r.reported_server = ''
		            AND a.role IN ('moderator', 'admin'))`
	}
	q += ` ORDER BY r.created_at DESC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing reports: %w", err)
	}
	defer rows.Close()
	return scanReports(rows)
}

// ReportCountsByAccount is the per-account figures for the whole admin list,
// keyed by account id -- one query for the server rather than one per row, the
// shape SRV-09's activity signals already established.
//
// Only local accounts appear: these are the counters drawn next to this
// server's own users.
func ReportCountsByAccount(db DBTX) (map[string]ReportCounts, error) {
	counts := map[string]ReportCounts{}

	// About each local account, split by where the reporter lives.
	rows, err := db.Query(
		`SELECT reported_id, reporter_server = '' AS local, COUNT(1)
		   FROM reports
		  WHERE reported_server = '' AND state = ?
		  GROUP BY reported_id, local`, ReportOpen)
	if err != nil {
		return nil, fmt.Errorf("store: counting reports about accounts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var local bool
		var n int
		if err := rows.Scan(&id, &local, &n); err != nil {
			return nil, fmt.Errorf("store: scanning report counts: %w", err)
		}
		c := counts[id]
		if local {
			c.Local = n
		} else {
			c.Federated = n
		}
		counts[id] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Filed by each local account: open ones, and ones judged abusive.
	filed, err := db.Query(
		`SELECT reporter_id, state, COUNT(1)
		   FROM reports
		  WHERE reporter_server = '' AND state IN (?, ?)
		  GROUP BY reporter_id, state`, ReportOpen, ReportAbusive)
	if err != nil {
		return nil, fmt.Errorf("store: counting reports by accounts: %w", err)
	}
	defer filed.Close()
	for filed.Next() {
		var id, state string
		var n int
		if err := filed.Scan(&id, &state, &n); err != nil {
			return nil, fmt.Errorf("store: scanning filed report counts: %w", err)
		}
		c := counts[id]
		if state == ReportOpen {
			c.Filed = n
		} else {
			c.Abusive = n
		}
		counts[id] = c
	}
	return counts, filed.Err()
}

// DeleteReportsForAccount clears every report naming this local account on
// either side. Called in the account-deletion transaction, not from a sweeper:
// a report about somebody who no longer exists is a claim nobody can answer,
// and one *by* them is an accusation nobody can be asked about.
func DeleteReportsForAccount(db DBTX, accountID string) error {
	_, err := db.Exec(
		`DELETE FROM reports
		  WHERE (reported_id = ? AND reported_server = '')
		     OR (reporter_id = ? AND reporter_server = '')`,
		accountID, accountID,
	)
	if err != nil {
		return fmt.Errorf("store: deleting reports for account: %w", err)
	}
	return nil
}

// PurgeReportsBefore drops reports older than cutoff, resolved and open alike,
// and returns how many went.
//
// A counter that never falls becomes a criminal record for something that was
// never proven, and the evidence goes with the row, which keeps this server's
// holdings minimal by construction rather than by anybody remembering to tidy.
func PurgeReportsBefore(db DBTX, cutoff time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM reports WHERE created_at < ?`, formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purging reports: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: checking rows affected for report purge: %w", err)
	}
	return n, nil
}

const reportColumns = `SELECT id, reported_id, reported_server, reporter_id, reporter_server,
	category, evidence, evidence_verified, state, created_at, updated_at, resolved_by, resolved_at`

func scanReports(rows *sql.Rows) ([]Report, error) {
	var out []Report
	for rows.Next() {
		var r Report
		var evidence, resolvedBy, resolvedAt sql.NullString
		var createdAt, updatedAt string
		if err := rows.Scan(
			&r.ID, &r.ReportedID, &r.ReportedServer, &r.ReporterID, &r.ReporterServer,
			&r.Category, &evidence, &r.EvidenceVerified, &r.State,
			&createdAt, &updatedAt, &resolvedBy, &resolvedAt,
		); err != nil {
			return nil, fmt.Errorf("store: scanning report: %w", err)
		}
		var err error
		if r.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("store: parsing report created_at: %w", err)
		}
		if r.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("store: parsing report updated_at: %w", err)
		}
		if evidence.Valid {
			r.Evidence = &evidence.String
		}
		if resolvedBy.Valid {
			r.ResolvedBy = &resolvedBy.String
		}
		if resolvedAt.Valid {
			t, err := parseTime(resolvedAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parsing report resolved_at: %w", err)
			}
			r.ResolvedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
