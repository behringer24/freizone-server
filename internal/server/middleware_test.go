package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithLoggingCapturesStatus(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handler := withLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), logger)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
	logged := buf.String()
	if !strings.Contains(logged, "status=418") {
		t.Errorf("expected log to contain status=418, got: %s", logged)
	}
	if !strings.Contains(logged, "path=/foo") {
		t.Errorf("expected log to contain path=/foo, got: %s", logged)
	}
}

func TestWithLoggingDefaultsStatusOK(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handler := withLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no explicit WriteHeader call"))
	}), logger)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("expected default status 200, got: %s", buf.String())
	}
}

func TestWithLoggingPreservesFlusher(t *testing.T) {
	// statusWriter wraps http.ResponseWriter in a struct; without an
	// explicit Flush() method, a `w.(http.Flusher)` assertion inside a
	// handler would silently fail even though the real underlying writer
	// (e.g. from the actual net/http server) supports flushing -- exactly
	// the bug that broke the SSE message stream end to end.
	var sawFlusher bool
	handler := withLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		sawFlusher = ok
		if ok {
			f.Flush()
		}
		w.WriteHeader(http.StatusOK)
	}), nil)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !sawFlusher {
		t.Error("handler could not type-assert http.Flusher through withLogging's wrapper")
	}
	if !rec.Flushed {
		t.Error("expected the underlying ResponseRecorder to have been flushed")
	}
}

func TestWithRecoverCatchesPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handler := withRecover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	}), logger)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()

	// Must not panic out of ServeHTTP.
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "panic recovered") {
		t.Errorf("expected panic to be logged, got: %s", buf.String())
	}
}

func TestWithRecoverPassesThroughNormalResponses(t *testing.T) {
	handler := withRecover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}), nil)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

func TestWithMaxBodyAllowsBodyAtOrUnderLimit(t *testing.T) {
	var readErr error
	handler := withMaxBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}), 10)

	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader("0123456789")) // exactly 10 bytes
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if readErr != nil {
		t.Errorf("unexpected read error at the exact limit: %v", readErr)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestWithMaxBodyRejectsOversizedBody(t *testing.T) {
	var readErr error
	handler := withMaxBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}), 10)

	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader("this body is longer than ten bytes"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if readErr == nil {
		t.Fatal("expected a read error for a body over the limit, got none")
	}
	var maxBytesErr *http.MaxBytesError
	if !errors.As(readErr, &maxBytesErr) {
		t.Errorf("error = %v, want *http.MaxBytesError", readErr)
	}
}

func TestWithMaxBodyZeroDisablesTheLimit(t *testing.T) {
	var readErr error
	var bodyLen int
	handler := withMaxBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		readErr = err
		bodyLen = len(body)
		w.WriteHeader(http.StatusOK)
	}), 0)

	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader("an arbitrarily long body, unbounded when maxBytes <= 0"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if readErr != nil {
		t.Errorf("unexpected read error with the limit disabled: %v", readErr)
	}
	if bodyLen == 0 {
		t.Error("expected the full body to be readable with the limit disabled")
	}
}
