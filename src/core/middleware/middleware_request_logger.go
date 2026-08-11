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
	// The escaped path and never u.Path: Path is decoded, so a request for
	// /auth/%0d%0aFAKE reaches a handler carrying a real CRLF. slog's handlers
	// escape that today, but slog.SetDefault is process-global and a log line that
	// is safe only because of the handler currently installed is safe by accident.
	pathHead, pathLen := escapedPathForLog(u, maxLoggedTarget)
	if u.RawQuery == "" {
		return truncateCounted(pathHead, maxLoggedTarget, pathLen)
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		// Fail closed. ParseQuery returns a PARTIAL map beside its error, and using
		// it would log whatever happened to parse out of a query the server itself
		// will not accept: ?client_id=c;id_token_hint=<JWT> is refused here and by
		// r.FormValue alike, and a renderer that split the raw query instead would
		// log that whole token as one value under the safe name client_id.
		target := clipped{limit: maxLoggedTarget}
		target.writeCounted(pathHead, pathLen)
		target.writeString(fmt.Sprintf("?[unparsable query, %d bytes]", len(u.RawQuery)))
		return target.string()
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	target := clipped{limit: maxLoggedTarget}
	target.writeCounted(pathHead, pathLen)
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
	c.writeCounted(s, len(s))
}

// writeCounted writes a fragment the caller has already clipped itself, counting
// the total it stands for rather than the bytes handed over. It is how a
// component deliberately never rendered in full still reaches the target's
// truncation marker with its true length.
func (c *clipped) writeCounted(head string, total int) {
	c.n += total
	if room := c.limit - c.b.Len(); room > 0 {
		c.b.WriteString(clip(head, room))
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

// clip returns the first limit bytes of s, and s itself when it is shorter.
func clip(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
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

// escapedPathForLog renders u's path exactly as u.EscapedPath() would, but keeps
// only the first limit bytes of it and returns the true rendered length
// alongside, so the caller's truncation marker can still report it.
//
// It exists because EscapedPath renders the whole path however long that is: a
// 900000-byte path of bytes needing escaping cost 5,416,840 B of allocation to
// produce the 4096 that reach the log. net/http allocates a comparable amount
// parsing that same request before any of this runs, which is what bounds the
// input, but that is a reason to keep this proportionate rather than a licence to
// pay it a second time: with logging on, the process paid it twice (#159).
//
// The semantics have to match EscapedPath byte for byte, so net/url's two
// branches are reproduced rather than approximated, and
// TestEscapedPathForLog_MatchesEscapedPath pins the whole function against the
// standard library over both of them.
func escapedPathForLog(u *url.URL, limit int) (head string, total int) {
	// Branch one: the request carried an encoding of its own and it is a valid
	// one, so EscapedPath hands it straight back and nothing needs rendering. This
	// is the branch every request through net/http takes whose path holds a byte
	// the default escaping would write differently.
	if u.RawPath != "" && rawPathEncodes(u.RawPath, u.Path) {
		return clip(u.RawPath, limit), len(u.RawPath)
	}
	if u.Path == "*" {
		// The asterisk-form request target, which net/url leaves alone.
		return "*", 1
	}

	// Branch two: escape u.Path, but only as far as the clip reaches. Each byte
	// escapes independently to one or three bytes, so the first limit input bytes
	// always yield at least limit output bytes, and they are exactly the ones kept.
	return clip(escapePathForLog(clip(u.Path, limit)), limit), pathEscapedLen(u.Path)
}

// rawPathEncodes reports what url.URL.EscapedPath's first branch decides: that
// rawPath is a valid path encoding and that unescaping it yields exactly path,
// in which case EscapedPath returns rawPath untouched.
//
// net/url reaches that answer as validEncoded followed by unescape, which builds
// the decoded string only to compare it and throw it away. This walks the two
// strings together and allocates nothing.
func rawPathEncodes(rawPath, path string) bool {
	decoded := 0
	for i := 0; i < len(rawPath); {
		var b byte
		switch c := rawPath[i]; {
		case c == '%':
			if i+2 >= len(rawPath) || !isHexDigit(rawPath[i+1]) || !isHexDigit(rawPath[i+2]) {
				return false
			}
			b = unhexDigit(rawPath[i+1])<<4 | unhexDigit(rawPath[i+2])
			i += 3
		case rawPathByteIsLiteral(c):
			b = c
			i++
		default:
			return false
		}
		if decoded >= len(path) || path[decoded] != b {
			return false
		}
		decoded++
	}
	return decoded == len(path)
}

// escapePathForLog is net/url's whole-path escaper, which the package does not
// export: url.PathEscape uses the path-SEGMENT rule and escapes "/" as well, so
// it renders a different string.
func escapePathForLog(s string) string {
	n := pathEscapedLen(s)
	if n == len(s) {
		// The common case, an ordinary request path: allocates nothing.
		return s
	}

	var b strings.Builder
	b.Grow(n)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if pathSafeBytes[c] {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

// pathEscapedLen returns the length escapePathForLog(s) would have, without
// building it.
func pathEscapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if pathSafeBytes[s[i]] {
			n++
			continue
		}
		n += 3
	}
	return n
}

// pathSafeBytes is pathByteIsSafe as a lookup, derived from it rather than
// written out again, so the rule is still stated in exactly one place.
//
// It exists because this scan is the one part of rendering that stays
// proportional to the whole path however little of it is kept: the truncation
// marker reports the true escaped length, so every byte has to be looked at even
// when 4096 of them survive. Measured on 900000 bytes needing escaping, the
// thirteen-case switch took 505 microseconds and the lookup 317 (#159).
var pathSafeBytes = func() (safe [256]bool) {
	for c := 0; c < 256; c++ {
		safe[c] = pathByteIsSafe(byte(c))
	}
	return
}()

// pathByteIsSafe reports whether net/url leaves c as it is when escaping a whole
// path: the RFC 3986 section 2.3 unreserved characters, plus the reserved
// characters it allows in a path, which is every one of "$&+,/:;=@" and not "?".
//
// That table is duplicated here rather than called, so
// TestPathEscapedLen_MatchesTheStandardLibrary pins it against EscapedPath for
// all 256 byte values: a toolchain that ever changed the rule fails that test
// rather than silently mis-reporting a length in a truncation marker.
func pathByteIsSafe(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~', '$', '&', '+', ',', '/', ':', ';', '=', '@':
		return true
	}
	return false
}

// rawPathByteIsLiteral reports whether net/url's validEncoded accepts c in a
// path without escaping. It is pathByteIsSafe plus the RFC 3986 sub-delims and
// the brackets that validEncoded lists explicitly.
func rawPathByteIsLiteral(c byte) bool {
	switch c {
	case '!', '\'', '(', ')', '*', '[', ']':
		return true
	}
	return pathByteIsSafe(c)
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhexDigit(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
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
