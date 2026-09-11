package logging

import (
	"fmt"
	"strings"
)

// MaxLoggedField bounds each client-chosen scalar attribute: the method, the
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
const MaxLoggedField = 128

// TruncateCounted returns s unchanged when it fits, and otherwise the retained
// prefix followed by a marker giving the limit and the true byte count. It is
// for a caller that holds the retained prefix and the true length separately,
// having deliberately never built the rest. s must be at least limit bytes long
// whenever total exceeds limit.
func TruncateCounted(s string, limit, total int) string {
	if total <= limit {
		return s
	}
	return s[:limit] + TruncationMarker(limit, total)
}

// TruncationMarker is the only place the marker's text is written, so that a
// caller measuring a component it has deliberately not rendered still agrees
// with the renderer to the byte.
func TruncationMarker(limit, total int) string {
	return fmt.Sprintf("[truncated, %d of %d bytes]", limit, total)
}

// SafeLogValue keeps the printable ASCII bytes of s and percent-escapes every
// other byte, so that no client-chosen value can put a control character, a line
// separator or invalid UTF-8 into the record.
//
// The request target is already safe by construction, being built from
// EscapedPath and QueryEscape. The scalar attributes are not: a header value may
// carry a tab, U+2028, U+0085 or a lone continuation byte and still be accepted by
// net/http. Remove this and what reaches the log depends on which slog handler
// happens to be installed, which is exactly the accident RequestTargetForLog
// avoids (#159).
func SafeLogValue(s string) string {
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
	b.Grow(SafeLogValueLen(s))
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

// SafeLogValueLen returns the length SafeLogValue(s) would have, without
// building it.
func SafeLogValueLen(s string) int {
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

// FieldForLog escapes then clips a client-chosen scalar attribute, in that order,
// so the bytes the limit counts are the bytes the log receives. Remove it and one
// oversized header becomes one oversized log line (#159).
//
// Like the request logger's query-component renderer it escapes only as far as
// the clip reaches. SafeLogValue maps each byte independently, so escaping the
// first MaxLoggedField bytes yields at least that many output bytes and they are
// exactly the ones kept. This matters more here than anywhere else: chi's
// RequestID middleware, mounted ahead of the request logger in both servers,
// adopts an inbound X-Request-Id header verbatim, so before this bound an
// unauthenticated request carrying 900000 non-printable bytes in that header
// cost 31 ms of CPU and 10 MB of allocation to render 128 bytes of log (#159).
func FieldForLog(s string) string {
	if len(s) <= MaxLoggedField && SafeLogValueLen(s) == len(s) {
		// The common case, and the only one that runs per ordinary request: an
		// unremarkable request id, method or IP, with nothing to escape and
		// nothing to clip. It allocates nothing.
		return s
	}
	head := s
	if len(head) > MaxLoggedField {
		head = head[:MaxLoggedField]
	}
	return TruncateCounted(SafeLogValue(head), MaxLoggedField, SafeLogValueLen(s))
}
