package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func TestHandleGetServerStatsRequiresAdmin(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	user := newAccountWithRole(t, db, store.RoleUser)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	for _, k := range []identityKeys{user, moderator} {
		rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats", nil, k.deviceID, k.devicePriv)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %s: status = %d, want 403, body = %s", k.accountID, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleGetServerStatsHistoryRequiresAdmin(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats/history", nil, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetServerStatsReportsCurrentCounts(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	newAccountWithRole(t, db, store.RoleUser)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp serverStatsResponse
	decodeJSON(t, rec, &resp)
	if resp.AccountCount != 2 {
		t.Errorf("AccountCount = %d, want 2 (the admin plus the one member created)", resp.AccountCount)
	}
	if resp.ActiveAccountCount != 2 {
		t.Errorf("ActiveAccountCount = %d, want 2", resp.ActiveAccountCount)
	}
	if resp.DeviceCount != 2 {
		t.Errorf("DeviceCount = %d, want 2 (one device each)", resp.DeviceCount)
	}
	if resp.CapturedAt == "" {
		t.Error("CapturedAt is empty, want an RFC3339 timestamp")
	}
	// Not seeded via store.InitFederationEnabled in this test setup -- an
	// unseeded setting defaults to true.
	if !resp.FederationEnabled {
		t.Error("FederationEnabled = false, want true (unseeded default)")
	}
}

// The forecast is arithmetic on facts, and these are the properties that make
// it readable: it starts where the measured figures end, the drain reaches zero
// a day past the retention window, and adding the measured inflow lands on the
// level a fixed window makes storage converge to.
func TestHandleGetServerStatsForecast(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	now := time.Now().UTC()
	a.Now = func() time.Time { return now }
	// Uploaded today, so it expires a full window from now, and it is the only
	// thing in the inflow window: 600 bytes over a 7-day window.
	if err := store.CreateBlob(db, store.Blob{
		BlobID: "blob1", SizeBytes: 600, CreatedAt: now,
		ExpiresAt: now.AddDate(0, 0, a.Config.BlobRetentionDays),
	}, []string{admin.deviceID}); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp serverStatsResponse
	decodeJSON(t, rec, &resp)

	f := resp.Forecast
	if f == nil {
		t.Fatal("no forecast in the response")
	}
	if f.RetentionDays != a.Config.BlobRetentionDays {
		t.Errorf("RetentionDays = %d, want %d", f.RetentionDays, a.Config.BlobRetentionDays)
	}
	// One point per day plus the day past the window, at both ends inclusive.
	if want := a.Config.BlobRetentionDays + 2; len(f.Drain) != want || len(f.WithInflow) != want {
		t.Fatalf("series lengths = (%d, %d), want %d each", len(f.Drain), len(f.WithInflow), want)
	}

	// Starts on the figure the rest of the response reports -- the join a chart
	// draws its measured line up to.
	if f.Drain[0].Bytes != resp.BlobBytes || f.WithInflow[0].Bytes != resp.BlobBytes {
		t.Errorf("both series start at (%d, %d), want the stored total %d",
			f.Drain[0].Bytes, f.WithInflow[0].Bytes, resp.BlobBytes)
	}
	// And ends at nothing: everything stored now has expired by then.
	if last := f.Drain[len(f.Drain)-1].Bytes; last != 0 {
		t.Errorf("the drain must reach zero a day past the window, got %d", last)
	}

	// Inflow is measured over half the window capped at a week, so 600 bytes
	// over 7 days here, and equilibrium is that rate held for a full window.
	if f.InflowWindowDays != 7 {
		t.Errorf("InflowWindowDays = %d, want 7", f.InflowWindowDays)
	}
	if want := int64(600 / 7); f.InflowBytesPerDay != want {
		t.Errorf("InflowBytesPerDay = %d, want %d", f.InflowBytesPerDay, want)
	}
	if want := f.InflowBytesPerDay * int64(f.RetentionDays); f.EquilibriumBytes != want {
		t.Errorf("EquilibriumBytes = %d, want inflow x window = %d", f.EquilibriumBytes, want)
	}
	// With the old stock gone and new uploads having replaced it, the projection
	// is sitting on that level rather than climbing past it.
	if last := f.WithInflow[len(f.WithInflow)-1].Bytes; last != f.EquilibriumBytes {
		t.Errorf("the projection ends at %d, want the equilibrium %d", last, f.EquilibriumBytes)
	}
}

// A server with no attachments at all still answers, with a forecast that says
// "nothing, going nowhere" rather than being absent or dividing by zero.
func TestHandleGetServerStatsForecastOnAnEmptyServer(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats", nil, admin.deviceID, admin.devicePriv)
	var resp serverStatsResponse
	decodeJSON(t, rec, &resp)
	if resp.Forecast == nil {
		t.Fatal("no forecast in the response")
	}
	if resp.Forecast.InflowBytesPerDay != 0 || resp.Forecast.EquilibriumBytes != 0 {
		t.Errorf("nothing stored, so nothing to project: %+v", resp.Forecast)
	}
	for _, p := range resp.Forecast.Drain {
		if p.Bytes != 0 {
			t.Errorf("drain point %s = %d, want 0", p.At, p.Bytes)
		}
	}
}

func TestHandleGetServerStatsHistoryReturnsRecordedSnapshots(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	now := time.Now().UTC().Truncate(time.Second)
	old := store.StatsSnapshot{CapturedAt: now.Add(-30 * 24 * time.Hour), AccountCount: 1}
	recent := store.StatsSnapshot{CapturedAt: now.Add(-1 * time.Hour), AccountCount: 5}
	for _, s := range []store.StatsSnapshot{old, recent} {
		if err := store.InsertStatsSnapshot(db, s); err != nil {
			t.Fatalf("InsertStatsSnapshot() error = %v", err)
		}
	}

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats/history?days=7", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var points []serverStatsPointResponse
	decodeJSON(t, rec, &points)
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1 (days=7 excludes the 30-day-old snapshot)", len(points))
	}
	if points[0].AccountCount != 5 {
		t.Errorf("AccountCount = %d, want 5", points[0].AccountCount)
	}
}

func TestHandleGetServerStatsHistoryRejectsInvalidDays(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/stats/history?days=not-a-number", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
