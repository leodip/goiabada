package handlers

import (
	"log/slog"
	"net/http"
)

// HandleHealthCheckGet answers 200 healthy and takes no writer. The status is committed before the
// body, so a failed write has nothing left to answer: a 500 page there could only log a superfluous
// WriteHeader. The failure is recorded at Debug, because a probe that hung up is per-request
// tracing and not something an operator has to act on (#435).
func HandleHealthCheckGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("healthy")); err != nil {
			slog.DebugContext(r.Context(), "unable to write the health check response", "error", err)
		}
	}
}
