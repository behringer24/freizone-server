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
