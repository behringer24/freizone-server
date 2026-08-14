// Admin-only server statistics: how large the server is (accounts, devices,
// stored attachments, messages queued, disk usage) right now, plus a
// history of the same figures for trend charts (is storage growing, are
// registrations climbing). See internal/store/stats.go and cmd/server/
// main.go's snapshot ticker for where the history comes from.
package api

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/behringer24/freizone-server/internal/diskstat"
	"github.com/behringer24/freizone-server/internal/store"
)

// maxStatsHistoryDays caps the "days" query parameter at the snapshot
// ticker's own retention window (cmd/server/main.go's
// statsSnapshotRetention, currently 2 years) -- asking for more than that
// would just return the same rows a smaller value already would.
const maxStatsHistoryDays = 2 * 365

// defaultStatsHistoryDays is used when "days" is absent, comfortably enough
// to show a season of growth without an admin having to specify anything.
const defaultStatsHistoryDays = 90

// handleGetServerStats reports the server's current size and load. Admin
// only -- like GET /v1/admin/license, how many accounts/how much storage a
// server has is exactly the kind of fact that is never exposed on GET
// /v1/server-status or the landing page.
func (a *API) handleGetServerStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}

	snapshot, err := a.CurrentStatsSnapshot()
	if err != nil {
		a.Logger.Error("computing server stats", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// In the same response as the figures above, deliberately: the forecast
	// starts at what is stored *now*, so a separate request would let an upload
	// land in between and leave the chart's measured line and its projection
	// starting at two different values -- a visible kink at the one point where
	// the reader is being asked to trust the join.
	forecast, err := a.storageForecast(snapshot)
	if err != nil {
		a.Logger.Error("computing storage forecast", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := serverStatsResponseFrom(snapshot)
	resp.Forecast = forecast
	writeJSON(w, http.StatusOK, resp)
}

// storageForecast works out how the attachment storage in snapshot will drain,
// and where it settles if uploads keep arriving at the rate they have been.
//
// The drain half is arithmetic on facts, not a prediction: every blob carries
// its own expires_at, fixed at upload and never extended, and nothing else
// removes one except a recipient releasing its claim (which only makes the real
// curve fall faster). The inflow half is the one assumption, and it is a bounded
// one -- with a fixed retention window the stored total cannot grow without
// limit, it converges on inflow-per-day times the window.
func (a *API) storageForecast(snapshot store.StatsSnapshot) (*storageForecastResponse, error) {
	retentionDays := a.Config.BlobRetentionDays
	if retentionDays <= 0 {
		// Config validation rules this out; not worth dividing by it anyway.
		return nil, nil
	}

	buckets, err := store.BlobExpiryBuckets(a.DB)
	if err != nil {
		return nil, err
	}

	// Half the retention window, capped at a week: long enough to average out a
	// quiet day, and short enough that nothing inside it can have expired yet,
	// which is what makes the measured figure exact rather than an undercount.
	inflowWindowDays := retentionDays / 2
	if inflowWindowDays > 7 {
		inflowWindowDays = 7
	}
	if inflowWindowDays < 1 {
		inflowWindowDays = 1
	}
	now := snapshot.CapturedAt
	inflowBytes, err := store.BlobBytesCreatedSince(a.DB, now.AddDate(0, 0, -inflowWindowDays))
	if err != nil {
		return nil, err
	}
	inflowPerDay := inflowBytes / int64(inflowWindowDays)

	// One point per day, one day past the window so the drain reaches zero and
	// the projection lands on the level it converges to rather than stopping
	// just short of it.
	horizon := retentionDays + 1
	drain := make([]storageForecastPoint, 0, horizon+1)
	withInflow := make([]storageForecastPoint, 0, horizon+1)
	for day := 0; day <= horizon; day++ {
		at := now.AddDate(0, 0, day)
		remaining := snapshot.BlobBytes
		if day > 0 {
			remaining = bytesStillStoredOn(buckets, at)
		}
		// New uploads live the same window, so after t days the ones still here
		// are the last min(t, retention) days' worth.
		newDays := int64(day)
		if newDays > int64(retentionDays) {
			newDays = int64(retentionDays)
		}
		drain = append(drain, storageForecastPoint{
			At:    at.UTC().Format(time.RFC3339),
			Bytes: remaining,
		})
		withInflow = append(withInflow, storageForecastPoint{
			At:    at.UTC().Format(time.RFC3339),
			Bytes: remaining + inflowPerDay*newDays,
		})
	}

	return &storageForecastResponse{
		RetentionDays:     retentionDays,
		InflowWindowDays:  inflowWindowDays,
		InflowBytesPerDay: inflowPerDay,
		EquilibriumBytes:  inflowPerDay * int64(retentionDays),
		Drain:             drain,
		WithInflow:        withInflow,
	}, nil
}

// bytesStillStoredOn sums the buckets that have not expired by at. Day zero is
// deliberately not computed this way -- it reports everything stored, expired
// -but-unswept bytes included, so the curve starts exactly on the figure the
// rest of the response gives and the first step down is the sweep doing its
// work rather than an unexplained gap.
func bytesStillStoredOn(buckets []store.BlobExpiryBucket, at time.Time) int64 {
	day := at.UTC().Format("2006-01-02")
	var remaining int64
	for _, b := range buckets {
		if b.Day >= day {
			remaining += b.Bytes
		}
	}
	return remaining
}

// handleGetServerStatsHistory reports every recorded stats snapshot from
// the last "days" days (default defaultStatsHistoryDays, capped at
// maxStatsHistoryDays), oldest first. Admin only, same reasoning as
// handleGetServerStats.
func (a *API) handleGetServerStatsHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}

	days := defaultStatsHistoryDays
	if v := r.URL.Query().Get("days"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "days must be a positive whole number")
			return
		}
		days = parsed
	}
	if days > maxStatsHistoryDays {
		days = maxStatsHistoryDays
	}

	since := a.Now().AddDate(0, 0, -days)
	history, err := store.StatsHistory(a.DB, since)
	if err != nil {
		a.Logger.Error("listing server stats history", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	points := make([]serverStatsPointResponse, len(history))
	for i, s := range history {
		points[i] = serverStatsPointResponseFrom(s)
	}
	writeJSON(w, http.StatusOK, points)
}

// CurrentStatsSnapshot combines the live database aggregates
// (store.ComputeCurrentStats) with the filesystem-derived figures a live
// request can afford to compute synchronously -- the DB file's size and the
// data directory's disk usage. Shared with the snapshot ticker
// (cmd/server/main.go) so both paths measure identically.
func (a *API) CurrentStatsSnapshot() (store.StatsSnapshot, error) {
	snapshot, err := store.ComputeCurrentStats(a.DB)
	if err != nil {
		return store.StatsSnapshot{}, err
	}

	if info, err := os.Stat(a.Config.DBPath); err == nil {
		snapshot.DBBytes = info.Size()
	}
	// A stat failure here (e.g. an unusual deployment where DBPath isn't a
	// plain file) just leaves DBBytes at 0 -- not worth failing the whole
	// stats request over one cosmetic figure.

	if free, total, err := diskstat.Free(a.Config.DataDir); err == nil {
		snapshot.DiskFreeBytes = int64(free)
		snapshot.DiskTotalBytes = int64(total)
	}

	snapshot.CapturedAt = a.Now()
	return snapshot, nil
}
