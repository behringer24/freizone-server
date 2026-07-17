package server

import (
	"log/slog"
	"net/http"
	"time"
)

// withLogging logs method, path, status code, and duration for each request.
func withLogging(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if logger != nil {
			logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration", time.Since(start))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// withRecover recovers from panics in next, logging them and returning a
// generic 500 instead of crashing the process.
func withRecover(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if logger != nil {
					logger.Error("panic recovered", "error", rec, "path", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":{"code":"internal","message":"internal server error"}}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
