package handlers

import (
	"log/slog"
	"net/http"
)

// HandleHealthCheckGet answers 200 healthy whenever the process is up and listening, and calls
// nothing: the route table registers it beside the static files, ahead of the settings cache and
// the session load, so it answers with the auth server down.
//
// The static answer is deliberate (#390). The liveness, readiness and startup probes all point
// here, and every admin console pod shares the one auth server, so a probe that called it would
// fail on every pod at once in an auth server outage: liveness then restarts all of them together,
// and failing readiness routes around nothing, since no sibling can reach an auth server this pod
// cannot. Revisit once #394 caps the connection pool and #396 spreads pods across nodes, which is
// what would make failures that one pod has and its siblings do not.
//
// It takes no writer. The status is committed before the body, so a failed write has nothing left
// to answer, and there are no settings on the context to render an error page with. The failure is
// recorded at Debug, because a probe that hung up is per-request tracing and not something an
// operator has to act on, as on the auth server (#435).
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
