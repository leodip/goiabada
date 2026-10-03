package httpmw

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/core/logging"
)

// RequestLogger writes one log record per request when enabled, with the
// query string redacted by logging.RequestTargetForLog.
//
// It replaces chi's middleware.Logger, which writes scheme://Host + r.RequestURI
// through the standard library log package to stdout: the raw request target,
// query string and all, so an id_token_hint JWT was written to the log in full
// (#159). Going through slog also gives the process one log stream in one format
// instead of two.
//
// The flag arrives as a parameter rather than being read here, following
// RealIP, and enabled == false returns next untouched so both servers
// can mount this unconditionally.
func RequestLogger(enabled bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Health checks, static assets and the favicon are never logged.
			if r.URL.Path == "/health" ||
				strings.HasPrefix(r.URL.Path, "/static/") ||
				r.URL.Path == "/favicon.ico" {
				next.ServeHTTP(w, r)
				return
			}

			// Rendered before the handler runs, because middleware downstream of
			// this one rewrites r.URL: chi's StripSlashes, registered right after,
			// edits r.URL.Path in place. The target logged is therefore the one
			// that arrived.
			target := logging.RequestTargetForLog(r.URL)

			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			started := time.Now()

			// Deferred, so a request whose handler panics still produces a line,
			// which is what chi's logger did.
			defer func() {
				// No request_id here any more. The handler both servers install reads it off
				// the context and appends it, through the same FieldForLog bound this used to
				// apply, so the record still carries it and this is now the same record every
				// other site on the request path writes (#320 decision 2).
				attributes := make([]any, 0, 12)
				attributes = append(attributes,
					"method", logging.FieldForLog(r.Method),
					"target", target,
					// Already resolved to a bare client IP by RealIP.
					"ip", logging.FieldForLog(r.RemoteAddr),
					// Written raw. A panicking request reports 500, because this
					// middleware is mounted above Recoverer in both servers, so the
					// status Recoverer writes goes through the wrapped writer here
					// (#203). It is still 0 for a handler that returns without
					// writing anything, which is what chi logged too; normalising
					// that to 200 would make the line say 200 for a request that
					// never answered.
					"status", wrapped.Status(),
					"bytes", wrapped.BytesWritten(),
					"duration", time.Since(started),
				)
				slog.InfoContext(r.Context(), "http request", attributes...)
			}()

			next.ServeHTTP(wrapped, r)
		})
	}
}
