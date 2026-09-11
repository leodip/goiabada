package logging

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// jwtLike is the three-segment shape an id_token_hint arrives in, short enough to
// keep the table readable.
const jwtLike = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlBST0JFIn0." +
	"eyJzdWIiOiJVU0VSLVNVQiIsInNpZCI6IlNFU1NJT04tSUQifQ.U0lHTkFUVVJF"

// fieldCorpus straddles every boundary FieldForLog has: either side of the clip,
// bytes that escape to three, and a multi-byte rune whose escape can be cut
// mid-sequence.
func fieldCorpus() []string {
	return []string{
		"",
		"a",
		"GET",
		"127.0.0.1",
		"2001:db8::1%eth0",
		"openid profile email",
		"a b+c%20d",
		"\x80",
		"a\x80b",
		"  ",
		jwtLike,
		strings.Repeat("a", MaxLoggedField-1),
		strings.Repeat("a", MaxLoggedField),
		strings.Repeat("a", MaxLoggedField+1),
		strings.Repeat("\x80", MaxLoggedField/3),
		strings.Repeat("\x80", MaxLoggedField),
		strings.Repeat("\u00e9", MaxLoggedField),
		strings.Repeat("a", 4096),
	}
}

// truncate is escape-then-clip's reference form, for a caller holding the whole
// string rather than a deliberately unbuilt prefix.
func truncate(s string, limit int) string {
	return TruncateCounted(s, limit, len(s))
}

// -----------------------------------------------------------------------------
// SafeLogValue
//
// The bytes here are the ones net/http actually lets through: a NUL, a vertical
// tab, a unit separator and a DEL are all refused with 400 before any handler
// runs, so they are not in the table. A tab, a quote, U+2028, U+2029, U+0085 and a
// lone continuation byte all reach the handler.
// -----------------------------------------------------------------------------

func TestSafeLogValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		note string
	}{
		{name: "tab", in: "a\tb", want: "a%09b"},
		{name: "a literal double quote", in: `a"b`, want: `a"b`, note: "printable, so it stays; slog quotes it"},
		{name: "an equals sign", in: "a=b", want: "a=b", note: "printable, so it stays"},
		{name: "U+2028 line separator", in: "a\u2028b", want: "a%E2%80%A8b"},
		{name: "U+2029 paragraph separator", in: "a\u2029b", want: "a%E2%80%A9b"},
		{
			name: "U+0085 next line",
			in:   "a\u0085b",
			want: "a%C2%85b",
			note: "slog's JSON handler drops this one silently, which is why it is escaped here",
		},
		{
			name: "a lone 0x80 continuation byte",
			in:   "a\x80b",
			want: "a%80b",
			note: "invalid UTF-8; slog's JSON handler renders it as U+FFFD",
		},
		{name: "an already-safe IPv6 address", in: "2001:db8::1%eth0", want: "2001:db8::1%eth0", note: "unchanged, and no allocation"},
		{name: "an already-safe method", in: "GET", want: "GET"},
		{name: "the empty string", in: "", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, SafeLogValue(test.in))
		})
	}
}

func TestSafeLogValueLen_MatchesSafeLogValue(t *testing.T) {
	for b := 0; b < 256; b++ {
		s := string([]byte{byte(b)})
		assert.Equal(t, len(SafeLogValue(s)), SafeLogValueLen(s), "byte 0x%02X", b)
	}

	for _, s := range fieldCorpus() {
		assert.Equal(t, len(SafeLogValue(s)), SafeLogValueLen(s), "input of %d bytes", len(s))
	}
}

func TestFieldForLog_MatchesEscapeThenClip(t *testing.T) {
	for _, s := range fieldCorpus() {
		// The right-hand side is verbatim what the request logger did before the
		// rendering was bounded. The bound is a cost property and must not become
		// an output one.
		assert.Equal(t, truncate(SafeLogValue(s), MaxLoggedField), FieldForLog(s),
			"input of %d bytes", len(s))
	}
}

// allocatedBytesPerCall reports what f allocates on average. The bound is
// measured rather than asserted structurally because the defect it closes was
// invisible in the output: the equivalence test above passes on the unbounded
// code too.
func allocatedBytesPerCall(t *testing.T, iterations int, f func()) uint64 {
	t.Helper()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < iterations; i++ {
		f()
	}
	runtime.ReadMemStats(&after)

	return (after.TotalAlloc - before.TotalAlloc) / uint64(iterations)
}

// renderSink defeats dead-store elimination, so the work under measurement
// actually happens.
var renderSink string

func TestFieldForLog_CountsWhatItDiscardsRatherThanBuildingIt(t *testing.T) {
	// The reachable shape: chi's RequestID middleware is mounted ahead of the
	// request logger in both servers and adopts an inbound X-Request-Id verbatim,
	// and net/http admits bytes above 0x7e in a header value. Each costs three
	// bytes to escape, so before the bound this allocated 10.3 MB and burned 31 ms
	// of CPU to keep 128 bytes, for any unauthenticated request.
	huge := strings.Repeat("\x80", 900000)

	allocated := allocatedBytesPerCall(t, 20, func() { renderSink = FieldForLog(huge) })

	assert.Less(t, allocated, uint64(8192),
		"escaping must stop at the clip, but %d bytes were allocated", allocated)
	// And the output is unchanged, marker and all.
	assert.Equal(t, strings.Repeat("%80", MaxLoggedField/3)+"%8[truncated, 128 of 2700000 bytes]",
		FieldForLog(huge))
}
