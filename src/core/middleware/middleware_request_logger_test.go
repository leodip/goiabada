package middleware

import (
	"bytes"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
)

// jwtLike is the three-segment shape an id_token_hint arrives in, short enough to
// keep the table readable. It is the sentinel every leak assertion looks for.
const jwtLike = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlBST0JFIn0." +
	"eyJzdWIiOiJVU0VSLVNVQiIsInNpZCI6IlNFU1NJT04tSUQifQ.U0lHTkFUVVJF"

// -----------------------------------------------------------------------------
// Seam 1: RequestTargetForLog
//
// Every negative row names the gate that rejects it, because the two gates are
// the whole safety argument: an allowlist miss, or a ParseQuery error. A row with
// no gate is one where nothing had to be withheld.
// -----------------------------------------------------------------------------

func TestRequestTargetForLog(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
		secret string // must not appear in the output; "" means nothing to check
		gate   string
		note   string
	}{
		{
			name: "authorize, the reported defect",
			target: "/auth/authorize?client_id=admin-console&response_type=code&redirect_uri=" +
				url.QueryEscape("https://app.example/cb") +
				"&scope=openid+profile&state=af0ifjsldkj&nonce=n-0S6&id_token_hint=" + jwtLike,
			want:   "/auth/authorize?client_id=admin-console&id_token_hint=[redacted]&nonce=[redacted]&redirect_uri=[redacted]&response_type=code&scope=openid+profile&state=[redacted]",
			secret: jwtLike,
			gate:   "allowlist miss",
			note:   "the safe twelve survive, everything else goes",
		},
		{
			name: "logout",
			target: "/auth/logout?id_token_hint=" + jwtLike + "&post_logout_redirect_uri=" +
				url.QueryEscape("https://app.example/done") + "&client_id=admin-console",
			want:   "/auth/logout?client_id=admin-console&id_token_hint=[redacted]&post_logout_redirect_uri=[redacted]",
			secret: jwtLike,
			gate:   "allowlist miss",
		},
		{
			name:   "activation link",
			target: "/account/activate?email=" + url.QueryEscape("user@example.com") + "&code=ACTIVATION-CODE",
			want:   "/account/activate?code=[redacted]&email=[redacted]",
			secret: "ACTIVATION-CODE",
			gate:   "allowlist miss",
			note:   "the code and the address both go",
		},
		{
			name:   "password reset link",
			target: "/reset-password?email=" + url.QueryEscape("user@example.com") + "&code=RESET-CODE",
			want:   "/reset-password?code=[redacted]&email=[redacted]",
			secret: "RESET-CODE",
			gate:   "allowlist miss",
		},
		{
			name:   "a credential in the query of a form POST",
			target: "/auth/pwd?password=QUERY-SECRET&otp=123456",
			want:   "/auth/pwd?otp=[redacted]&password=[redacted]",
			secret: "QUERY-SECRET",
			gate:   "allowlist miss",
			note:   "r.FormValue merges the query in behind the body, so the handler reads these",
		},
		{
			name:   "no query string",
			target: "/auth/pwd",
			want:   "/auth/pwd",
			note:   "no trailing ?",
		},
		{
			name:   "bare ? with nothing after it",
			target: "/auth/authorize?",
			want:   "/auth/authorize",
			note:   "chi logged the bare ? today",
		},
		{
			name:   "parameter with no = at all",
			target: "/auth/authorize?id_token_hint",
			want:   "/auth/authorize?id_token_hint=",
			note:   "nothing to withhold, so nothing is claimed to have been",
		},
		{
			name:   "empty value",
			target: "/auth/authorize?id_token_hint=&client_id=",
			want:   "/auth/authorize?client_id=&id_token_hint=",
		},
		{
			name:   "orphan =",
			target: "/auth/authorize?=orphan",
			want:   "/auth/authorize?=[redacted]",
			secret: "orphan",
			gate:   "allowlist miss",
			note:   "the empty key is not on the list either",
		},
		{
			name:   "duplicated parameter, one benign and one not",
			target: "/auth/authorize?id_token_hint=FIRST&client_id=c&id_token_hint=SECOND",
			want:   "/auth/authorize?client_id=c&id_token_hint=[redacted]&id_token_hint=[redacted]",
			secret: "SECOND",
			gate:   "allowlist miss",
			note:   "both copies go, and the count survives",
		},
		{
			name:   "semicolon separator, the bypass",
			target: "/auth/authorize?client_id=c;id_token_hint=" + jwtLike,
			want:   "/auth/authorize?[unparsable query, 129 bytes]",
			secret: jwtLike,
			gate:   "ParseQuery error",
			// Keep this. A marker rather than a redacted query looks wrong until you
			// try the alternative: a renderer that splits the raw query on & and =
			// sees no separator here, so the whole thing is one value under the safe
			// name client_id and the complete token is logged. Failing closed is the
			// point.
		},
		{
			name:   "invalid percent escape",
			target: "/auth/authorize?id_token_hint=" + jwtLike + "&%zz=1",
			want:   "/auth/authorize?[unparsable query, 123 bytes]",
			secret: jwtLike,
			gate:   "ParseQuery error",
			// Keep this. ParseQuery returns a PARTIAL map beside this error, and that
			// map holds id_token_hint. Using it would log the token in full.
		},
		{
			name:   "a safe name in the wrong case",
			target: "/auth/authorize?CLIENT_ID=not-a-client-id-at-all",
			want:   "/auth/authorize?CLIENT_ID=[redacted]",
			secret: "not-a-client-id-at-all",
			gate:   "allowlist miss",
			// Keep this. client_id is on the list and this is redacted anyway, because
			// matching is case-sensitive: the server reads client_id case-sensitively
			// too, so CLIENT_ID is not a parameter it acts on, and printing its value
			// would print an attacker-chosen string under a familiar-looking name.
		},
		{
			name:   "a redacted name in the wrong case",
			target: "/auth/authorize?ID_TOKEN_HINT=" + jwtLike,
			want:   "/auth/authorize?ID_TOKEN_HINT=[redacted]",
			secret: jwtLike,
			gate:   "allowlist miss",
		},
		{
			name:   "ANSI escape inside a safe value",
			target: "/auth/authorize?client_id=%1b%5b31mRED",
			want:   "/auth/authorize?client_id=%1B%5B31mRED",
			note:   "decoded by ParseQuery, re-escaped by QueryEscape, so it stays inert",
		},
		{
			name:   "CRLF in the path",
			target: "/auth/%0d%0aFAKE-LOG-LINE?client_id=c",
			want:   "/auth/%0d%0aFAKE-LOG-LINE?client_id=c",
			note:   "EscapedPath keeps it encoded; r.URL.Path would carry a real CRLF",
		},
		{
			name:   "scope with spaces",
			target: "/auth/authorize?scope=openid+profile+email&client_id=c",
			want:   "/auth/authorize?client_id=c&scope=openid+profile+email",
		},
		{
			name:   "scope with %20 instead of +",
			target: "/auth/authorize?scope=openid%20profile&client_id=c",
			want:   "/auth/authorize?client_id=c&scope=openid+profile",
			// Keep this. %20 comes back as +, which looks like a bug and is not: the
			// query is parsed and re-encoded, so escaping is canonicalised. Names,
			// values and duplicate counts all survive; the exact bytes do not.
		},
	}

	// Collected so the whole-table invariant below runs over every rendered output
	// rather than over a chosen few.
	rendered := make([]string, 0, len(tests))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.ParseRequestURI(test.target)
			assert.NoError(t, err, "the test's own input must be a valid request target")

			got := RequestTargetForLog(u)

			assert.Equal(t, test.want, got)
			if test.secret != "" {
				assert.NotContains(t, got, test.secret,
					"withheld by the gate: %s", test.gate)
			}
			rendered = append(rendered, got)
		})
	}

	t.Run("every rendered target is printable ASCII", func(t *testing.T) {
		// This is what lets the middleware log the target without passing it through
		// safeLogValue: EscapedPath and QueryEscape between them leave nothing that
		// needs escaping. If a future change renders a raw byte, this fails here
		// rather than in a log file.
		for _, output := range rendered {
			assert.Equal(t, output, safeLogValue(output),
				"the rendered target must already be safe to log verbatim")
		}
	})
}

func TestRequestTargetForLog_WholeTargetCap(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantLen int
		wantEnd string
		note    string
	}{
		{
			name:   "one 200000-byte value",
			target: "/auth/authorize?x=" + strings.Repeat("A", 200000),
			// 15 path + "?x=" + 10 for [redacted]: the value is redacted before
			// anything is measured, so the cap never comes into it.
			wantLen: 28,
			wantEnd: "/auth/authorize?x=[redacted]",
			note:    "redaction alone handles a single huge value",
		},
		{
			name: "4000 distinct parameters",
			target: "/auth/authorize?" + func() string {
				parts := make([]string, 0, 4000)
				for i := 0; i < 4000; i++ {
					parts = append(parts, fmt.Sprintf("p%d=%s", i, strings.Repeat("v", 40)))
				}
				return strings.Join(parts, "&")
			}(),
			// 4096 retained + 32 for "[truncated, 4096 of 66905 bytes]". This is the
			// row that shows the cap is not redundant with the redaction: every value
			// here is redacted and the NAMES alone still come to 66905 bytes.
			wantLen: 4128,
			wantEnd: "[truncated, 4096 of 66905 bytes]",
		},
		{
			name:   "a 20000-byte path, no query at all",
			target: "/auth/" + strings.Repeat("p", 20000),
			// 4096 retained + 32 for "[truncated, 4096 of 20006 bytes]".
			wantLen: 4128,
			wantEnd: "[truncated, 4096 of 20006 bytes]",
		},
		// The path is rendered under its own bound and handed to the assembly as a
		// clipped prefix plus a length, so these three rows are what stop that length
		// going astray: the marker's total is the only place a path longer than the
		// cap is still reported, and each row reaches it down a different branch of
		// the escaping.
		{
			name:   "a 20000-byte path with a query after it",
			target: "/auth/" + strings.Repeat("p", 20000) + "?client_id=c",
			// 20006 path + 12 for "?client_id=c", then 4096 retained + a 32-byte marker.
			wantLen: 4128,
			wantEnd: "[truncated, 4096 of 20018 bytes]",
			note:    "the query is counted past the cap even though the path filled it",
		},
		{
			name:   "a path that triples when escaped, with a query after it",
			target: "/auth/" + strings.Repeat("\x80", 2000) + "?client_id=c",
			// The bytes escape to %80 each, so 6 + 6000 rendered path + 12 of query.
			wantLen: 4127,
			wantEnd: "[truncated, 4096 of 6018 bytes]",
			note:    "the length counted is the RENDERED one, three bytes per raw byte",
		},
		{
			name:   "a path already encoded on the wire, with a query after it",
			target: "/auth/" + strings.Repeat("%8a", 2000) + "?client_id=c",
			// Lowercase hex is not what net/url would write, so RawPath is kept and
			// returned verbatim: 6006 bytes of path, unchanged, plus 12 of query.
			wantLen: 4127,
			wantEnd: "[truncated, 4096 of 6018 bytes]",
			note:    "EscapedPath's other branch, where the client's own encoding survives",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.ParseRequestURI(test.target)
			assert.NoError(t, err)

			got := RequestTargetForLog(u)

			assert.Equal(t, test.wantLen, len(got))
			assert.True(t, strings.HasSuffix(got, test.wantEnd),
				"expected the output to end with %q, got the tail %q",
				test.wantEnd, got[max(0, len(got)-64):])
		})
	}
}

// The component cap is decision 9's, and it is the one part of the redactor with
// no probe row behind it, so these expectations are computed from the rule and
// carry their byte counts.
func TestRequestTargetForLog_QueryComponentCap(t *testing.T) {
	t.Run("a parameter name over the bound is clipped", func(t *testing.T) {
		// 900 bytes of "n", every one of them unreserved, so QueryEscape is the
		// identity here and 900 rendered bytes is 900 arriving bytes.
		name := strings.Repeat("n", 900)

		u, err := url.ParseRequestURI("/auth/authorize?" + name + "=x")
		assert.NoError(t, err)

		got := RequestTargetForLog(u)

		// 512 retained + "[truncated, 512 of 900 bytes]" (29 bytes), then "=" and the
		// redacted value: 15 + 1 + 512 + 29 + 1 + 10 = 568.
		assert.Equal(t, "/auth/authorize?"+name[:512]+"[truncated, 512 of 900 bytes]=[redacted]", got)
		assert.Equal(t, 568, len(got))
	})

	t.Run("an allowlisted value over the bound is clipped, the misbuilt-RP shape", func(t *testing.T) {
		// The case decision 9 was answered for: a relying party that puts a real
		// token where client_id goes. Nothing validates the value before it is
		// logged, so the bound is the only thing between that token and the log.
		//
		// 21 + 500 + 28 = 549 bytes, so the signature starts at byte 521 and a
		// 512-byte prefix cannot reach it.
		token := "eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("P", 500) + ".SIGNATURE-SENTINEL-abcdefgh"
		assert.Equal(t, 549, len(token), "the row's arithmetic depends on this length")

		u, err := url.ParseRequestURI("/auth/authorize?client_id=" + token)
		assert.NoError(t, err)

		got := RequestTargetForLog(u)

		assert.Equal(t, "/auth/authorize?client_id="+token[:512]+"[truncated, 512 of 549 bytes]", got)
		// Both halves. The prefix survives, which is what keeps the log useful, and
		// the token as a whole does not, which is what makes it unusable.
		assert.Contains(t, got, token[:512])
		assert.NotContains(t, got, token)
		assert.NotContains(t, got, "SIGNATURE-SENTINEL", "the signature must be cut")
	})

	t.Run("both caps compose on one target", func(t *testing.T) {
		// Ten parameters, each with a 900-byte name and a redacted value: each
		// renders to 512 + 29 + 1 + 10 = 552 bytes, so the assembled target passes
		// 4096 and is clipped a second time.
		parts := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			parts = append(parts, fmt.Sprintf("n%d%s=x", i, strings.Repeat("y", 898)))
		}

		u, err := url.ParseRequestURI("/auth/authorize?" + strings.Join(parts, "&"))
		assert.NoError(t, err)

		got := RequestTargetForLog(u)

		assert.Contains(t, got, "[truncated, 512 of 900 bytes]", "the component cap fired")
		assert.Contains(t, got, "[truncated, 4096 of ", "and so did the whole-target cap")
		assert.Equal(t, 4096, strings.Index(got, "[truncated, 4096 of "),
			"the whole-target marker sits at the bound, after the retained prefix")
	})

	t.Run("a redacted value is never clipped, however long the input", func(t *testing.T) {
		// [redacted] is eleven bytes whatever arrived, so it cannot reach either cap.
		// This row fails if someone later clips before checking the allowlist rather
		// than after, which would put a truncation marker on a value that was never
		// written.
		u, err := url.ParseRequestURI("/auth/authorize?id_token_hint=" + strings.Repeat("Z", 900))
		assert.NoError(t, err)

		got := RequestTargetForLog(u)

		assert.Equal(t, "/auth/authorize?id_token_hint=[redacted]", got)
		assert.NotContains(t, got, "[truncated")
	})
}

func TestRequestTargetForLog_ParseQueryParameterLimit(t *testing.T) {
	// A limit inside the standard library rather than in this code: measured at
	// go1.26.5, url.ParseQuery parses 10000 parameters and refuses 10001 with
	// "number of URL query parameters exceeded limit", returning an empty map. So a
	// query of 20000 parameters takes the fail-closed path and renders as a marker,
	// not as 4128 bytes of names. If a future toolchain moves that limit this row
	// changes, and it should read as the toolchain moving rather than as the
	// redactor breaking.
	parts := make([]string, 0, 20000)
	for i := 0; i < 20000; i++ {
		parts = append(parts, fmt.Sprintf("p%d=v", i))
	}
	query := strings.Join(parts, "&")

	u, err := url.ParseRequestURI("/auth/authorize?" + query)
	assert.NoError(t, err)

	got := RequestTargetForLog(u)

	assert.Equal(t, fmt.Sprintf("/auth/authorize?[unparsable query, %d bytes]", len(query)), got)
}

// -----------------------------------------------------------------------------
// safeLogValue
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
			assert.Equal(t, test.want, safeLogValue(test.in))
		})
	}
}

// -----------------------------------------------------------------------------
// Seam 2: MiddlewareRequestLogger
// -----------------------------------------------------------------------------

// captureSlog redirects the default logger into a buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// okHandler answers 200 with no body and records that it ran.
func okHandler(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
}

// records counts the log records in the captured output.
func records(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), `msg="http request"`)
}

func TestMiddlewareRequestLogger_DisabledWritesNothingAndStillServes(t *testing.T) {
	buf := captureSlog(t)
	ran := false

	handler := MiddlewareRequestLogger(false)(okHandler(&ran))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))

	assert.Equal(t, 0, records(buf), "nothing is logged when the flag is off")
	// The other half: a pass-through that dropped the request would also log
	// nothing.
	assert.True(t, ran, "the handler must still run")
}

func TestMiddlewareRequestLogger_SkipList(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantLines int
	}{
		{name: "/health is skipped", path: "/health", wantLines: 0},
		{name: "/healthz is not, one character away", path: "/healthz", wantLines: 1},
		{name: "/static/ is skipped", path: "/static/app.css", wantLines: 0},
		{name: "/static with no trailing slash is not", path: "/static", wantLines: 1},
		{name: "/favicon.ico is skipped", path: "/favicon.ico", wantLines: 0},
		{name: "/favicon.ico.map is not", path: "/favicon.ico.map", wantLines: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := captureSlog(t)
			ran := false

			handler := MiddlewareRequestLogger(true)(okHandler(&ran))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, test.path, nil))

			assert.Equal(t, test.wantLines, records(buf))
			// A skip list tested only by its members passes when it skips everything,
			// and a skipped path must still be served.
			assert.True(t, ran, "the handler must run either way")
		})
	}
}

func TestMiddlewareRequestLogger_LogsExactlyOneRecord(t *testing.T) {
	buf := captureSlog(t)
	ran := false

	handler := MiddlewareRequestLogger(true)(okHandler(&ran))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))

	assert.Equal(t, 1, records(buf))
	// Quoted by slog's text handler, which is a property of the handler rather than
	// of the target: the value itself is printable ASCII by construction.
	assert.Contains(t, buf.String(), `target="/auth/authorize?client_id=c"`)
}

// The goal sentence of the change: the reported defect, at both endpoints.
func TestMiddlewareRequestLogger_DoesNotLogTheIdTokenHint(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{
			name: "authorize",
			target: "/auth/authorize?client_id=admin-console&response_type=code&scope=openid+profile" +
				"&redirect_uri=" + url.QueryEscape("https://app.example/cb") +
				"&id_token_hint=" + jwtLike,
		},
		{
			name: "logout",
			target: "/auth/logout?id_token_hint=" + jwtLike +
				"&post_logout_redirect_uri=" + url.QueryEscape("https://app.example/done"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := captureSlog(t)
			ran := false

			handler := MiddlewareRequestLogger(true)(okHandler(&ran))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, test.target, nil))

			assert.Equal(t, 1, records(buf))
			assert.NotContains(t, buf.String(), jwtLike, "the hint must not reach the log")
			assert.Contains(t, buf.String(), "id_token_hint=[redacted]")
		})
	}
}

func TestMiddlewareRequestLogger_RecordsStatusAndBytes(t *testing.T) {
	buf := captureSlog(t)

	handler := MiddlewareRequestLogger(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope!"))
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

	assert.Contains(t, buf.String(), "status=403")
	assert.Contains(t, buf.String(), "bytes=5")
}

func TestMiddlewareRequestLogger_RequestId(t *testing.T) {
	t.Run("present when chi's RequestID ran ahead of the logger", func(t *testing.T) {
		buf := captureSlog(t)
		ran := false

		handler := chimiddleware.RequestID(MiddlewareRequestLogger(true)(okHandler(&ran)))
		request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
		request.Header.Set(chimiddleware.RequestIDHeader, "REQUEST-ID-SENTINEL")
		handler.ServeHTTP(httptest.NewRecorder(), request)

		assert.Contains(t, buf.String(), "request_id=REQUEST-ID-SENTINEL")
	})

	t.Run("the attribute is absent altogether when it did not", func(t *testing.T) {
		buf := captureSlog(t)
		ran := false

		handler := MiddlewareRequestLogger(true)(okHandler(&ran))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

		assert.Equal(t, 1, records(buf))
		assert.NotContains(t, buf.String(), "request_id",
			"an empty request id is omitted rather than logged as empty")
	})
}

// The three client-chosen scalar attributes. Each can arrive at 900000 bytes: the
// method and X-Request-Id straight from the request, and r.RemoteAddr because
// MiddlewareRealIP copies an X-Forwarded-For entry into it.
func TestMiddlewareRequestLogger_ClipsTheClientChosenFields(t *testing.T) {
	const huge = 900000

	tests := []struct {
		name       string
		setup      func(r *http.Request)
		wantMarker string
	}{
		{
			name:       "a 900000-byte method",
			setup:      func(r *http.Request) { r.Method = strings.Repeat("M", huge) },
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
		{
			name: "a 900000-byte X-Request-Id",
			setup: func(r *http.Request) {
				r.Header.Set(chimiddleware.RequestIDHeader, strings.Repeat("R", huge))
			},
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
		{
			name:       "a 900000-byte r.RemoteAddr",
			setup:      func(r *http.Request) { r.RemoteAddr = strings.Repeat("I", huge) },
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := captureSlog(t)
			ran := false

			handler := chimiddleware.RequestID(MiddlewareRequestLogger(true)(okHandler(&ran)))
			request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			test.setup(request)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			assert.Equal(t, 1, records(buf))
			assert.Contains(t, buf.String(), test.wantMarker)
			assert.Less(t, buf.Len(), 5*1024,
				"one oversized header must not become one oversized log line")
		})
	}
}

func TestMiddlewareRequestLogger_TheClipIsLossy(t *testing.T) {
	// Pinned rather than left to be discovered: two request ids of equal length
	// that differ only after byte 128 log identically, truncation marker included.
	// This is the accepted cost of the 128-byte bound. Nothing reads as a complete
	// identifier that is not, because every clipped value carries its own marker
	// giving the true length, so the failure is an operator seeing two records they
	// cannot tell apart rather than one they wrongly believe they can.
	//
	// The bound itself is a deferred decision in the run's closing record, section
	// 8: preserve long correlation ids in full, keep the clip, or append a digest.
	// If that answer changes, this row changes with it.
	first := strings.Repeat("p", 128) + "AAAAAAAA"
	second := strings.Repeat("p", 128) + "BBBBBBBB"
	assert.Equal(t, len(first), len(second), "the two must be the same length to collide")

	logged := make([]string, 0, 2)
	for _, requestId := range []string{first, second} {
		buf := captureSlog(t)
		ran := false

		handler := chimiddleware.RequestID(MiddlewareRequestLogger(true)(okHandler(&ran)))
		request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
		request.Header.Set(chimiddleware.RequestIDHeader, requestId)
		handler.ServeHTTP(httptest.NewRecorder(), request)

		line := buf.String()
		start := strings.Index(line, "request_id=")
		assert.NotEqual(t, -1, start)
		logged = append(logged, line[start:strings.Index(line[start:], " method=")+start])
	}

	assert.Equal(t, logged[0], logged[1], "the two distinct ids render to one logged value")
	assert.Contains(t, logged[0], "[truncated, 128 of 136 bytes]",
		"and the marker says so, so neither record claims to be complete")
}

func TestMiddlewareRequestLogger_EscapesTheClientChosenFields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(r *http.Request)
		wantIn   string
		wantOut  string
		rawIsBad string
	}{
		{
			name: "U+2028 in the request id",
			setup: func(r *http.Request) {
				r.Header.Set(chimiddleware.RequestIDHeader, "before\u2028after")
			},
			wantIn:   "before%E2%80%A8after",
			rawIsBad: "\u2028",
		},
		{
			name:     "U+0085 in the IP",
			setup:    func(r *http.Request) { r.RemoteAddr = "192.0.2.1\u0085injected" },
			wantIn:   "192.0.2.1%C2%85injected",
			rawIsBad: "\u0085",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := captureSlog(t)
			ran := false

			handler := chimiddleware.RequestID(MiddlewareRequestLogger(true)(okHandler(&ran)))
			request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			test.setup(request)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			// Both halves. Asserting only that the escape is present would pass with
			// the raw rune sitting in the record beside it.
			assert.Contains(t, buf.String(), test.wantIn)
			assert.NotContains(t, buf.String(), test.rawIsBad, "the raw rune must be gone")
		})
	}
}

func TestMiddlewareRequestLogger_RendersTheTargetBeforeDownstreamRewritesIt(t *testing.T) {
	// The one attribute whose value depends on WHEN it is read. Both servers
	// register chi's StripSlashes immediately after this middleware, and it edits
	// r.URL.Path in place, so a logger that rendered the target on the way out
	// would record a path the client never sent. Every other assertion in this file
	// passes either way, which is what makes this case worth its own test rather
	// than a comment.
	buf := captureSlog(t)

	var seenByHandler string
	chain := MiddlewareRequestLogger(true)(
		chimiddleware.StripSlashes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenByHandler = r.URL.Path
			w.WriteHeader(http.StatusOK)
		})))

	chain.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth/authorize/?client_id=c", nil))

	assert.Equal(t, "/auth/authorize", seenByHandler, "StripSlashes really does rewrite the path")
	// Quoted because slog's text handler quotes any value holding an "="".
	assert.Contains(t, buf.String(), `target="/auth/authorize/?client_id=c"`,
		"the log must carry the target that arrived, trailing slash and all")
}

func TestMiddlewareRequestLogger_LogsARequestThatPanics(t *testing.T) {
	// This is what pins the deferred write, which is otherwise invisible: chi's
	// logger produced a line for a panicking request and so must this one.
	buf := captureSlog(t)

	handler := MiddlewareRequestLogger(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("handler exploded")
	}))

	assert.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))
	})

	assert.Equal(t, 1, records(buf), "the line must survive the panic")
	// status=0 because Recoverer, which is registered outside this middleware, has
	// not written anything yet when the deferred record runs. That is what chi
	// logged too, and it is #203 rather than this change.
	assert.Contains(t, buf.String(), "status=0")
}

// -----------------------------------------------------------------------------
// The caps run during rendering, not after it
//
// Every cap in this file used to be applied to a fully built string, which let an
// unauthenticated client buy work far out of proportion to the ~4 KB that reaches
// the log: 900000 non-printable bytes in an X-Request-Id header cost 31 ms of CPU
// and 10.3 MB of allocation to render 128 bytes (#159). The rendering is now
// bounded, and the output has to be exactly what the unbounded version produced,
// so these tests come in pairs: one pinning the output against the straightforward
// "render it all, then clip" expression, one pinning the bound itself.
// -----------------------------------------------------------------------------

// renderingCorpus exercises both sides of every bound and both branches of every
// escaper: nothing to escape, everything to escape, a multi-byte rune, a space
// (the one byte QueryEscape maps to a single different byte), and inputs landing
// exactly on, just under and just over each limit.
func renderingCorpus() []string {
	return []string{
		"",
		"a",
		"client_id",
		"openid profile email",
		"a b+c%20d",
		"\x80",
		"a\x80b",
		"  ",
		"scope=openid&x=1",
		jwtLike,
		strings.Repeat("a", maxLoggedField-1),
		strings.Repeat("a", maxLoggedField),
		strings.Repeat("a", maxLoggedField+1),
		strings.Repeat("\x80", maxLoggedField/3),
		strings.Repeat("\x80", maxLoggedField),
		strings.Repeat("a", maxLoggedQueryComponent-1),
		strings.Repeat("a", maxLoggedQueryComponent),
		strings.Repeat("a", maxLoggedQueryComponent+1),
		strings.Repeat(" ", maxLoggedQueryComponent+1),
		strings.Repeat("\x80", maxLoggedQueryComponent/3),
		strings.Repeat("\x80", maxLoggedQueryComponent),
		strings.Repeat("é", maxLoggedQueryComponent),
	}
}

// The two length functions replace a call to the thing they measure, so they
// carry the whole risk of the bounded rendering: a length one byte out puts a
// wrong number in a truncation marker, which is the one part of the output a
// reader is asked to trust. Both are pinned over every byte value rather than a
// sample, so a toolchain that ever changed url.QueryEscape's table fails here
// rather than silently mis-reporting a length.

func TestQueryEscapedLen_MatchesTheStandardLibrary(t *testing.T) {
	for b := 0; b < 256; b++ {
		s := string([]byte{byte(b)})
		assert.Equal(t, len(url.QueryEscape(s)), queryEscapedLen(s),
			"byte 0x%02X: url.QueryEscape renders it as %q", b, url.QueryEscape(s))
	}

	for _, s := range renderingCorpus() {
		assert.Equal(t, len(url.QueryEscape(s)), queryEscapedLen(s), "input of %d bytes", len(s))
	}
}

// The path escaper is the one piece of net/url this file reproduces rather than
// calls, because the package exports no whole-path escaper: url.PathEscape uses
// the path-segment rule and escapes "/" too. So it is pinned twice, once per
// byte against EscapedPath and once over both of EscapedPath's branches, and the
// second is what covers the RawPath half that no length table can reach.

func TestPathEscapedLen_MatchesTheStandardLibrary(t *testing.T) {
	// "a"+c rather than c alone, because EscapedPath answers "*" for a path of
	// exactly "*" without escaping it, which would make one byte look safe when
	// the escaper renders it as %2A. escapedPathForLog carries that special case
	// separately and TestEscapedPathForLog_MatchesEscapedPath covers it.
	for b := 0; b < 256; b++ {
		s := "a" + string([]byte{byte(b)})
		escaped := (&url.URL{Path: s}).EscapedPath()

		assert.Equal(t, len(escaped), pathEscapedLen(s), "byte 0x%02X escapes to %q", b, escaped)
		assert.Equal(t, escaped, escapePathForLog(s), "byte 0x%02X", b)
	}

	for _, s := range renderingCorpus() {
		assert.Equal(t, len((&url.URL{Path: s}).EscapedPath()), pathEscapedLen(s),
			"input of %d bytes", len(s))
	}
}

// pathCorpus covers both of EscapedPath's branches and the ways the RawPath one
// is rejected, since a wrongly ACCEPTED RawPath would log bytes the standard
// library would have escaped. The rejections are the interesting rows: a
// truncated escape, a non-hex digit, a byte validEncoded refuses, and a RawPath
// that is a valid encoding of something other than Path.
func pathCorpus() []*url.URL {
	long := strings.Repeat("\x80", 3000)

	return []*url.URL{
		{Path: ""},
		{Path: "/"},
		{Path: "*"},
		{Path: "/auth/authorize"},
		{Path: "/auth/a b"},
		{Path: "/auth/\r\nFAKE"},
		{Path: "/auth/é"},
		{Path: "/$&+,/:;=@-_.~"},
		{Path: "/a?b"},
		{Path: "/" + long},
		{Path: "/" + strings.Repeat("a", 5000)},
		// RawPath accepted: a valid encoding that decodes to Path.
		{Path: "/auth/\r\nFAKE", RawPath: "/auth/%0d%0aFAKE"},
		{Path: "/auth/a b", RawPath: "/auth/a%20b"},
		{Path: "/auth/!'()*[]", RawPath: "/auth/!'()*[]"},
		{Path: "/auth/A", RawPath: "/auth/%41"},
		{Path: "/" + long, RawPath: "/" + strings.Repeat("%80", 3000)},
		// RawPath rejected: truncated escape, non-hex digit, a byte validEncoded
		// refuses, and a valid encoding of the wrong string.
		{Path: "/auth/x", RawPath: "/auth/%4"},
		{Path: "/auth/x", RawPath: "/auth/%zz"},
		{Path: "/auth/x", RawPath: "/auth/x?y"},
		{Path: "/auth/x", RawPath: "/auth/y"},
		{Path: "/auth/x", RawPath: "/auth/xy"},
		{Path: "/auth/xy", RawPath: "/auth/x"},
	}
}

func TestEscapedPathForLog_MatchesEscapedPath(t *testing.T) {
	for _, u := range pathCorpus() {
		// The right-hand side is verbatim what this file did before the path
		// rendering was bounded. The bound is a cost property and must not become
		// an output one.
		want := u.EscapedPath()
		head, total := escapedPathForLog(u, maxLoggedTarget)

		assert.Equal(t, len(want), total, "Path=%q RawPath=%q", u.Path, u.RawPath)
		assert.Equal(t, truncate(want, maxLoggedTarget), truncateCounted(head, maxLoggedTarget, total),
			"Path=%q RawPath=%q", u.Path, u.RawPath)
	}
}

// The hand-written corpus above covers the shapes worth naming. This covers the
// ones nobody thought of, which is what the RawPath branch needs: whether a
// given RawPath is a valid encoding of a given Path is a property of two strings
// at once, and the accepting and rejecting cases are one byte apart.
func TestEscapedPathForLog_MatchesEscapedPathOnRandomInput(t *testing.T) {
	// A fixed seed, so a failure is reproducible and the suite cannot go flaky.
	random := rand.New(rand.NewSource(159))
	// Bytes chosen to land on every decision in the two escapers: escaped and
	// unescaped, the sub-delims validEncoded admits but the escaper does not, the
	// percent that starts an escape, and the hex digits that finish one.
	alphabet := []byte("aZ0-_.~$&+,/:;=@?!'()*[]% \x00\x80\xff\r\nA9fFzZ")

	for i := 0; i < 5000; i++ {
		raw := make([]byte, random.Intn(24))
		for j := range raw {
			raw[j] = alphabet[random.Intn(len(alphabet))]
		}

		// Both halves independently: a RawPath net/url itself produced, and one
		// paired with an unrelated Path, which is the case EscapedPath rejects.
		u := &url.URL{Path: string(raw)}
		if random.Intn(2) == 0 {
			decoded, err := url.PathUnescape(string(raw))
			if err != nil {
				decoded = string(raw)
			}
			u = &url.URL{Path: decoded, RawPath: string(raw)}
		}

		want := u.EscapedPath()
		head, total := escapedPathForLog(u, maxLoggedTarget)

		assert.Equal(t, len(want), total, "case %d: Path=%q RawPath=%q", i, u.Path, u.RawPath)
		assert.Equal(t, truncate(want, maxLoggedTarget), truncateCounted(head, maxLoggedTarget, total),
			"case %d: Path=%q RawPath=%q", i, u.Path, u.RawPath)
	}
}

func TestSafeLogValueLen_MatchesSafeLogValue(t *testing.T) {
	for b := 0; b < 256; b++ {
		s := string([]byte{byte(b)})
		assert.Equal(t, len(safeLogValue(s)), safeLogValueLen(s), "byte 0x%02X", b)
	}

	for _, s := range renderingCorpus() {
		assert.Equal(t, len(safeLogValue(s)), safeLogValueLen(s), "input of %d bytes", len(s))
	}
}

func TestQueryComponentForLog_MatchesEscapeThenClip(t *testing.T) {
	for _, s := range renderingCorpus() {
		// The right-hand side is verbatim what this file did before the rendering
		// was bounded. The bound is a cost property and must not become an output
		// one.
		assert.Equal(t, truncate(url.QueryEscape(s), maxLoggedQueryComponent), queryComponentForLog(s),
			"input of %d bytes", len(s))
	}
}

func TestQueryComponentLen_MatchesQueryComponentForLog(t *testing.T) {
	// Once the target is full the renderer stops escaping and measures instead, so
	// these two must agree exactly: a component counted one byte short of what it
	// would have rendered puts a wrong total in the target's truncation marker.
	for _, s := range renderingCorpus() {
		assert.Equal(t, len(queryComponentForLog(s)), queryComponentLen(s), "input of %d bytes", len(s))
	}
}

func TestFieldForLog_MatchesEscapeThenClip(t *testing.T) {
	for _, s := range renderingCorpus() {
		assert.Equal(t, truncate(safeLogValue(s), maxLoggedField), fieldForLog(s),
			"input of %d bytes", len(s))
	}
}

func TestClipped_MatchesConcatenateThenClip(t *testing.T) {
	// clipped assembles the whole target, so what it must guarantee is that a
	// sequence of writes renders exactly as concatenating them and truncating
	// would. These straddle the boundary: a write landing short of the limit, one
	// crossing it, and writes after it that reach no output but must still be
	// counted, since the target's marker reports their bytes.
	writeSets := [][]string{
		{},
		{""},
		{"/auth/authorize"},
		{strings.Repeat("a", maxLoggedTarget)},
		{strings.Repeat("a", maxLoggedTarget), "b"},
		{strings.Repeat("a", maxLoggedTarget-1), "bc", "def"},
		{strings.Repeat("a", maxLoggedTarget+1), "b"},
		{"/p", "?", strings.Repeat("x", maxLoggedTarget), "&", strings.Repeat("y", 100)},
	}

	for _, writes := range writeSets {
		c := clipped{limit: maxLoggedTarget}
		for _, w := range writes {
			c.writeString(w)
		}

		assert.Equal(t, truncate(strings.Join(writes, ""), maxLoggedTarget), c.string(),
			"%d writes totalling %d bytes", len(writes), len(strings.Join(writes, "")))
	}
}

// allocatedBytesPerCall reports what f allocates on average. The bound is
// measured rather than asserted structurally because the defect it closes was
// invisible in the output: every equivalence test above passes on the unbounded
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
	// logger in both servers and adopts an inbound X-Request-Id verbatim, and
	// net/http admits bytes above 0x7e in a header value. Each costs three bytes to
	// escape, so before the bound this allocated 10.3 MB and burned 31 ms of CPU to
	// keep 128 bytes, for any unauthenticated request.
	huge := strings.Repeat("\x80", 900000)

	allocated := allocatedBytesPerCall(t, 20, func() { renderSink = fieldForLog(huge) })

	assert.Less(t, allocated, uint64(8192),
		"escaping must stop at the clip, but %d bytes were allocated", allocated)
	// And the output is unchanged, marker and all.
	assert.Equal(t, strings.Repeat("%80", maxLoggedField/3)+"%8[truncated, 128 of 2700000 bytes]",
		fieldForLog(huge))
}

func TestRequestTargetForLog_CountsWhatItDiscardsRatherThanBuildingIt(t *testing.T) {
	t.Run("one enormous allowlisted value", func(t *testing.T) {
		// The misbuilt-RP shape at scale. url.ParseQuery has to unescape the whole
		// value before this code sees it, so what is bounded is what the RENDERING
		// adds on top: escaping 300000 bytes into 900000 in order to keep 512.
		raw := "client_id=" + url.QueryEscape(strings.Repeat("\x80", 300000))
		u := &url.URL{Path: "/auth/authorize", RawQuery: raw}

		rendering := allocatedBytesPerCall(t, 20, func() { renderSink = RequestTargetForLog(u) })
		parsing := allocatedBytesPerCall(t, 20, func() {
			values, _ := url.ParseQuery(raw)
			renderSink = values.Get("client_id")
		})

		assert.Less(t, rendering, parsing+uint64(64*1024),
			"rendering allocated %d bytes over ParseQuery's own %d", rendering-parsing, parsing)
	})

	// The path is the one component no query parsing has to touch first, so nothing
	// else pays for it and the whole cost is the logger's own. Before the bound,
	// u.EscapedPath() rendered all 900000 bytes into %XX and threw away everything
	// past 4096, at 5,416,840 B a request. Both of EscapedPath's branches are
	// guarded, because they allocate for different reasons: one escapes, one only
	// has to avoid decoding what it validates.
	t.Run("an enormous path, escaped", func(t *testing.T) {
		u := &url.URL{Path: "/" + strings.Repeat("\x80", 900000)}

		allocated := allocatedBytesPerCall(t, 20, func() { renderSink = RequestTargetForLog(u) })

		assert.Less(t, allocated, uint64(64*1024),
			"escaping must stop at the target cap, but %d bytes were allocated", allocated)
	})

	t.Run("an enormous path, already encoded on the wire", func(t *testing.T) {
		// What net/http itself builds: a request target whose escaping differs from
		// net/url's own arrives with RawPath set and valid, so EscapedPath returns it
		// verbatim. Validating it must not decode it, which is what net/url does
		// before comparing. Lowercase hex is the everyday way to reach this branch,
		// net/url writing %8A where a client wrote %8a.
		r := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("%8a", 300000), nil)
		assert.NotEmpty(t, r.URL.RawPath, "the test needs the branch where RawPath is used")

		allocated := allocatedBytesPerCall(t, 20, func() { renderSink = RequestTargetForLog(r.URL) })

		assert.Less(t, allocated, uint64(64*1024),
			"validating must not decode, but %d bytes were allocated", allocated)
	})

	t.Run("many parameters, assembled past the whole-target cap", func(t *testing.T) {
		// 9000 names, each expanding threefold when escaped, assemble to about
		// 900 KB before 4096 bytes of it are kept. Once the target is full the
		// renderer measures the rest instead of escaping it, so what is left is
		// url.ParseQuery's own cost and almost nothing on top.
		parts := make([]string, 0, 9000)
		for i := 0; i < 9000; i++ {
			parts = append(parts, fmt.Sprintf("%s%d=1", strings.Repeat("\x80", 30), i))
		}
		raw := strings.Join(parts, "&")
		u := &url.URL{Path: "/auth/authorize", RawQuery: raw}

		rendering := allocatedBytesPerCall(t, 20, func() { renderSink = RequestTargetForLog(u) })
		parsing := allocatedBytesPerCall(t, 20, func() {
			values, _ := url.ParseQuery(raw)
			renderSink = values.Get("x")
		})

		assert.Less(t, rendering, parsing+uint64(256*1024),
			"rendering allocated %d bytes over ParseQuery's own %d, for a %d-byte query",
			rendering-parsing, parsing, len(raw))
	})
}
