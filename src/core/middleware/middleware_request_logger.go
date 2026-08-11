package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const (
	// redactedValue stands in for the value of every query parameter whose name is
	// not on loggableQueryParams.
	redactedValue = "[redacted]"

	// maxLoggedTarget bounds the whole rendered request target. A real authorize
	// request renders to a couple of hundred bytes, while a client can put about a
	// megabyte in the request line (Go's default 1 MB MaxHeaderBytes, which this
	// repo never overrides), and redaction barely shortens that because the
	// parameter names survive. Without this bound an unauthenticated caller writes
	// a megabyte to the log per request (#159).
	maxLoggedTarget = 4096

	// maxLoggedQueryComponent bounds each rendered parameter name and each retained
	// value on its own, before they are assembled.
	//
	// Why it exists: the allowlist below bounds which parameters keep a value, and
	// nothing at all about the bytes inside those values or inside a parameter
	// name. Nothing validates either before they are logged, so a relying party
	// that misbuilds its authorize URL and puts a real ID token where client_id
	// goes writes a live credential to the log in full. Delete this and that
	// happens again.
	//
	// Why 512 and not 256: eleven of the twelve names below are comfortable at
	// either bound, and scope is the outlier, since a client granted twenty or so
	// resource:permission pairs passes 256 legitimately, and scope is the value an
	// operator reads when diagnosing consent and scope filtering. A JWT loses its
	// signature well before either bound, so a clipped token cannot be replayed.
	//
	// This is a bound and not an absence guarantee: a secret shorter than it is
	// still written whole (#159).
	maxLoggedQueryComponent = 512

	// maxLoggedField bounds each client-chosen scalar attribute: the method, the
	// request id and the IP. All three can be enormous, measured rather than
	// assumed: a 900000-byte method and a 900000-byte X-Request-Id both reach the
	// handler, and MiddlewareRealIP writes a 900000-byte X-Forwarded-For entry
	// straight into r.RemoteAddr.
	//
	// 128 is set from what legitimate values measure: chi's own generated request
	// id is 27 bytes, a proxy's correlation UUID is 36, the longest method in
	// ordinary use is 7, and the longest textual IPv6 address with a zone is under
	// 64. With it the worst case for one line is about 4.6 KB; without it one
	// header makes one log line of 900 KB (#159).
	maxLoggedField = 128
)

// loggableQueryParams is the set of query parameter names whose value is written
// to the log. Everything else is replaced by redactedValue.
//
// This is an allowlist rather than a denylist because a denylist fails open: a
// parameter nobody has assessed yet is logged in full on the day it lands. Every
// name here is drawn from a fixed vocabulary or is a number, and together they are
// what a support question turns on, which client, which flow, which ACR, which
// page.
//
// Matching is deliberately case-sensitive, which is the fail-closed direction for
// an allowlist: the server's own reads are case-sensitive, so Client_ID is not a
// parameter it acts on, and treating it as one would print an attacker-chosen
// value under a name that only looks familiar (#159).
var loggableQueryParams = map[string]struct{}{
	"client_id": {}, "response_type": {}, "response_mode": {}, "scope": {},
	"prompt": {}, "max_age": {}, "acr_values": {}, "code_challenge_method": {},
	"ui_locales": {}, "error": {}, "page": {}, "size": {},
}

// RequestTargetForLog renders what a log line may say about a request target.
//
// The property that makes it safe: every value that reaches the output has passed
// one of exactly two gates, an exact case-sensitive match against
// loggableQueryParams, or being empty. There is no third path, no fallback that
// writes the raw query, and no branch where a parse failure degrades to printing
// what arrived. Deleting loggableQueryParams makes this redact everything rather
// than log everything.
//
// It is exported because the API debug middleware in the auth server logs a
// request target too and must not do it differently (#159).
func RequestTargetForLog(u *url.URL) string {
	// EscapedPath and never Path: Path is decoded, so a request for
	// /auth/%0d%0aFAKE reaches a handler carrying a real CRLF. slog's handlers
	// escape that today, but slog.SetDefault is process-global and a log line that
	// is safe only because of the handler currently installed is safe by accident.
	path := u.EscapedPath()
	if u.RawQuery == "" {
		return truncate(path, maxLoggedTarget)
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		// Fail closed. ParseQuery returns a PARTIAL map beside its error, and using
		// it would log whatever happened to parse out of a query the server itself
		// will not accept: ?client_id=c;id_token_hint=<JWT> is refused here and by
		// r.FormValue alike, and a renderer that split the raw query instead would
		// log that whole token as one value under the safe name client_id.
		return truncate(fmt.Sprintf("%s?[unparsable query, %d bytes]", path, len(u.RawQuery)), maxLoggedTarget)
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(path)
	b.WriteString("?")
	first := true
	for _, name := range names {
		_, loggable := loggableQueryParams[name]
		for _, value := range values[name] {
			if !first {
				b.WriteString("&")
			}
			first = false
			// Escape first, clip second, so the bytes counted are the bytes the log
			// receives. A cut can land inside a %XX escape and leave a trailing %E;
			// the marker immediately after states the true byte count, so nothing
			// reads as a value it is not.
			b.WriteString(truncate(url.QueryEscape(name), maxLoggedQueryComponent))
			b.WriteString("=")
			switch {
			case value == "":
				// Nothing to withhold, and "name=" is what arrived.
			case loggable:
				b.WriteString(truncate(url.QueryEscape(value), maxLoggedQueryComponent))
			default:
				// No clip needed: this is eleven bytes whatever arrived.
				b.WriteString(redactedValue)
			}
		}
	}
	// The whole-target cap runs last, after redaction, so no cut can expose part of
	// a value redaction removed.
	return truncate(b.String(), maxLoggedTarget)
}

// truncate returns s unchanged when it fits, and otherwise the retained prefix
// followed by a marker giving the limit and the true byte count.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return fmt.Sprintf("%s[truncated, %d of %d bytes]", s[:limit], limit, len(s))
}

// safeLogValue keeps the printable ASCII bytes of s and percent-escapes every
// other byte, so that no client-chosen value can put a control character, a line
// separator or invalid UTF-8 into the record.
//
// The request target is already safe by construction, being built from
// EscapedPath and QueryEscape. The scalar attributes are not: a header value may
// carry a tab, U+2028, U+0085 or a lone continuation byte and still be accepted by
// net/http. Remove this and what reaches the log depends on which slog handler
// happens to be installed, which is exactly the accident RequestTargetForLog
// avoids (#159).
func safeLogValue(s string) string {
	escapeNeeded := false
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			escapeNeeded = true
			break
		}
	}
	if !escapeNeeded {
		// The common case allocates nothing.
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// fieldForLog escapes then clips a client-chosen scalar attribute, in that order,
// so the bytes the limit counts are the bytes the log receives. Remove it and one
// oversized header becomes one oversized log line (#159).
func fieldForLog(s string) string {
	return truncate(safeLogValue(s), maxLoggedField)
}

// MiddlewareRequestLogger writes one log record per request when enabled, with the
// query string redacted by RequestTargetForLog.
//
// It replaces chi's middleware.Logger, which writes scheme://Host + r.RequestURI
// through the standard library log package to stdout: the raw request target,
// query string and all, so an id_token_hint JWT was written to the log in full
// (#159). Going through slog also gives the process one log stream in one format
// instead of two.
//
// The flag arrives as a parameter rather than being read here, following
// MiddlewareRealIP, and enabled == false returns next untouched so both servers
// can mount this unconditionally.
func MiddlewareRequestLogger(enabled bool) func(next http.Handler) http.Handler {
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
			target := RequestTargetForLog(r.URL)

			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			started := time.Now()

			// Deferred, so a request whose handler panics still produces a line,
			// which is what chi's logger did.
			defer func() {
				attributes := make([]any, 0, 14)
				if requestId := middleware.GetReqID(r.Context()); requestId != "" {
					attributes = append(attributes, "request_id", fieldForLog(requestId))
				}
				attributes = append(attributes,
					"method", fieldForLog(r.Method),
					"target", target,
					// Already resolved to a bare client IP by MiddlewareRealIP.
					"ip", fieldForLog(r.RemoteAddr),
					// Written raw. This is 0 both for a panicking request and for a
					// handler that returns without writing, which is what chi logged
					// too. Normalising it to 200 would make the line say 200 for a
					// request that failed; the panic half is #203.
					"status", wrapped.Status(),
					"bytes", wrapped.BytesWritten(),
					"duration", time.Since(started),
				)
				slog.Info("http request", attributes...)
			}()

			next.ServeHTTP(wrapped, r)
		})
	}
}
