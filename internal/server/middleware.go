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

// Flush implements http.Flusher by delegating to the underlying
// ResponseWriter, if it supports it. Without this, wrapping
// http.ResponseWriter in statusWriter would silently break a
// `w.(http.Flusher)` type assertion in handlers -- e.g. the SSE message
// stream -- even when the real underlying writer supports flushing.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withMaxBody caps every request body at maxBytes, rejecting anything
// larger (the handler's own body-read -- json.Decode or io.ReadAll --
// gets a *http.MaxBytesError instead of the full oversized body) rather
// than reading an arbitrarily large request into memory. A maxBytes <= 0
// disables the cap (kept out of validated Config -- see
// internal/config -- so this is just defense against a caller
// misconfiguring it directly).
func withMaxBody(next http.Handler, maxBytes int64) http.Handler {
	if maxBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
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
