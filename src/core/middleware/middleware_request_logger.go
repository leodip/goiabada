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
		target := clipped{limit: maxLoggedTarget}
		target.writeString(path)
		target.writeString(fmt.Sprintf("?[unparsable query, %d bytes]", len(u.RawQuery)))
		return target.string()
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	target := clipped{limit: maxLoggedTarget}
	target.writeString(path)
	target.writeString("?")
	first := true
	for _, name := range names {
		_, loggable := loggableQueryParams[name]
		for _, value := range values[name] {
			if !first {
				target.writeString("&")
			}
			first = false
			// Escape first, clip second, so the bytes counted are the bytes the log
			// receives. A cut can land inside a %XX escape and leave a trailing %E;
			// the marker immediately after states the true byte count, so nothing
			// reads as a value it is not.
			target.writeQueryComponent(name)
			target.writeString("=")
			switch {
			case value == "":
				// Nothing to withhold, and "name=" is what arrived.
			case loggable:
				target.writeQueryComponent(value)
			default:
				// No clip needed: this is eleven bytes whatever arrived.
				target.writeString(redactedValue)
			}
		}
	}
	// The whole-target cap runs last, after redaction, so no cut can expose part of
	// a value redaction removed.
	return target.string()
}

// clipped accumulates a rendered string while keeping only its first limit
// bytes, counting every byte it is offered so that the truncation marker can
// still report the true length.
//
// It exists because every cap here used to run on a fully assembled string, so
// an unauthenticated client could make the server do work far out of proportion
// to the ~4 KB that reaches the log: 9000 query parameters assembled to about
// 900 KB before 4096 bytes of it were kept. The output is unchanged; only the
// discarded suffix is now counted rather than built (#159).
type clipped struct {
	b     strings.Builder
	limit int
	n     int
}

func (c *clipped) writeString(s string) {
	c.n += len(s)
	if room := c.limit - c.b.Len(); room > 0 {
		if len(s) > room {
			s = s[:room]
		}
		c.b.WriteString(s)
	}
}

// writeQueryComponent writes one rendered parameter name or retained value.
//
// Once the target's own bound is reached it stops escaping altogether and only
// counts: no further byte can reach the output, and all the marker needs is the
// length. That is what keeps a query of 9000 parameters costing what parsing it
// cost rather than a multiple of it (#159).
func (c *clipped) writeQueryComponent(s string) {
	if c.b.Len() >= c.limit {
		c.n += queryComponentLen(s)
		return
	}
	c.writeString(queryComponentForLog(s))
}

func (c *clipped) string() string {
	return truncateCounted(c.b.String(), c.limit, c.n)
}

// truncate returns s unchanged when it fits, and otherwise the retained prefix
// followed by a marker giving the limit and the true byte count.
func truncate(s string, limit int) string {
	return truncateCounted(s, limit, len(s))
}

// truncateCounted is truncate for a caller that holds the retained prefix and
// the true length separately, having deliberately never built the rest. s must
// be at least limit bytes long whenever total exceeds limit.
func truncateCounted(s string, limit, total int) string {
	if total <= limit {
		return s
	}
	return s[:limit] + truncationMarker(limit, total)
}

// truncationMarker is the only place the marker's text is written, so that
// queryComponentLen can measure a component it has deliberately not rendered
// and still agree with queryComponentForLog to the byte.
func truncationMarker(limit, total int) string {
	return fmt.Sprintf("[truncated, %d of %d bytes]", limit, total)
}

// queryComponentForLog renders one parameter name or one retained value: escaped
// with url.QueryEscape, then clipped at maxLoggedQueryComponent.
//
// url.QueryEscape maps each byte independently, so the escaped form of a prefix
// is a prefix of the escaped form, and escaping maxLoggedQueryComponent input
// bytes always yields at least that many output bytes. Escaping just that much
// therefore gives the exact bytes the clip retains, and queryEscapedLen counts
// the rest without building it. A 900000-byte value costs one scan instead of a
// 2.7 MB string that is then thrown away (#159).
func queryComponentForLog(s string) string {
	head := s
	if len(head) > maxLoggedQueryComponent {
		head = head[:maxLoggedQueryComponent]
	}
	return truncateCounted(url.QueryEscape(head), maxLoggedQueryComponent, queryEscapedLen(s))
}

// queryComponentLen returns the length queryComponentForLog(s) would have,
// without rendering it. TestQueryComponentLen_MatchesQueryComponentForLog pins
// the two together.
func queryComponentLen(s string) int {
	full := queryEscapedLen(s)
	if full <= maxLoggedQueryComponent {
		return full
	}
	return maxLoggedQueryComponent + len(truncationMarker(maxLoggedQueryComponent, full))
}

// queryEscapedLen returns the length url.QueryEscape(s) would have, without
// building it.
//
// url.QueryEscape keeps the RFC 3986 section 2.3 unreserved characters as they
// are, writes a space as "+", and writes every other byte as a three-byte %XX
// escape. That table is duplicated here rather than called, so
// TestQueryEscapedLen_MatchesTheStandardLibrary pins it against url.QueryEscape
// for all 256 byte values: a toolchain that ever changed the rule fails that
// test rather than silently mis-reporting a length in a truncation marker.
func queryEscapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			n++
			continue
		}
		n += 3
	}
	return n
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
	b.Grow(safeLogValueLen(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
			continue
		}
		// Written by hand rather than through fmt: this runs once per escaped
		// byte, and fmt.Fprintf here cost 31 ms on a 900000-byte header (#159).
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

const hexDigits = "0123456789ABCDEF"

// safeLogValueLen returns the length safeLogValue(s) would have, without
// building it.
func safeLogValueLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x20 && s[i] <= 0x7e {
			n++
			continue
		}
		n += 3
	}
	return n
}

// fieldForLog escapes then clips a client-chosen scalar attribute, in that order,
// so the bytes the limit counts are the bytes the log receives. Remove it and one
// oversized header becomes one oversized log line (#159).
//
// Like queryComponentForLog it escapes only as far as the clip reaches.
// safeLogValue also maps each byte independently, so escaping the first
// maxLoggedField bytes yields at least that many output bytes and they are
// exactly the ones kept. This matters more here than anywhere else in the file:
// chi's RequestID middleware, mounted ahead of this one in both servers, adopts
// an inbound X-Request-Id header verbatim, so before this bound an unauthenticated
// request carrying 900000 non-printable bytes in that header cost 31 ms of CPU
// and 10 MB of allocation to render 128 bytes of log (#159).
func fieldForLog(s string) string {
	if len(s) <= maxLoggedField && safeLogValueLen(s) == len(s) {
		// The common case, and the only one that runs per ordinary request: an
		// unremarkable request id, method or IP, with nothing to escape and
		// nothing to clip. It allocates nothing.
		return s
	}
	head := s
	if len(head) > maxLoggedField {
		head = head[:maxLoggedField]
	}
	return truncateCounted(safeLogValue(head), maxLoggedField, safeLogValueLen(s))
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
