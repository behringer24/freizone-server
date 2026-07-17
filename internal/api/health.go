package api

import "net/http"

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	var probe int
	if err := a.DB.QueryRow(`SELECT 1`).Scan(&probe); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
