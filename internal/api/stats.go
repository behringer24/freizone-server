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

	writeJSON(w, http.StatusOK, serverStatsResponseFrom(snapshot))
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
