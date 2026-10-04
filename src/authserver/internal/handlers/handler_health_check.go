package handlers

import (
	"log/slog"
	"net/http"
)

// HandleHealthCheckGet answers 200 healthy whenever the process is up and listening, and reads
// nothing: the route table registers it beside the static files, ahead of the settings read and
// the session load, so it answers with the database down.
//
// The static answer is deliberate (#390). The liveness, readiness and startup probes all point
// here, and a probe that reads the database fails on every pod at once in a database outage:
// liveness then restarts all of them together, and readiness turns the application's own errors
// into the gateway's "no healthy upstream" and delays recovery by a probe period. A
// dependency-aware readiness check pays only when one pod loses the database while its siblings
// keep it, which today means one node losing its route to it; a pod that never reached the
// database never answers here at all, since the database is opened and migrated before any
// listener exists. Revisit once #394 caps the connection pool and #396 spreads pods across nodes,
// which is what would make failures that one pod has and its siblings do not.
//
// It takes no writer. The status is committed before the body, so a failed write has nothing left
// to answer: a 500 page there could only log a superfluous WriteHeader. The failure is recorded at
// Debug, because a probe that hung up is per-request tracing and not something an operator has to
// act on (#435).
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
