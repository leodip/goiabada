package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// The debug middleware only runs when GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS is
// on, which is why it had no coverage. It is worth testing anyway: it wraps the
// response writer on every API request when enabled, and it is the one place that
// deliberately logs request and response bodies, so it must not log credentials.

// withDebugAPIRequests sets the flag for the duration of the test and restores it.
func withDebugAPIRequests(t *testing.T, enabled bool) {
	t.Helper()
	previous := config.GetAuthServer().DebugAPIRequests
	config.GetAuthServer().DebugAPIRequests = enabled
	t.Cleanup(func() {
		config.GetAuthServer().DebugAPIRequests = previous
	})
}

// -----------------------------------------------------------------------------
// The responseWriter wrapper
// -----------------------------------------------------------------------------

func TestDebugResponseWriter_WriteHeaderRecordsAndForwards(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: recorder, statusCode: http.StatusOK, body: &bytes.Buffer{}}

	rw.WriteHeader(http.StatusTeapot)

	assert.Equal(t, http.StatusTeapot, rw.statusCode, "the status must be recorded for logging")
	assert.Equal(t, http.StatusTeapot, recorder.Code, "and forwarded to the real writer")
}

func TestDebugResponseWriter_WriteTeesToBufferAndForwards(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: recorder, statusCode: http.StatusOK, body: &bytes.Buffer{}}

	n, err := rw.Write([]byte(`{"hello":"world"}`))

	assert.NoError(t, err)
	assert.Equal(t, len(`{"hello":"world"}`), n, "the byte count must come from the real writer")
	assert.Equal(t, `{"hello":"world"}`, rw.body.String(), "the body must be captured for logging")
	assert.Equal(t, `{"hello":"world"}`, recorder.Body.String(), "and still reach the client")
}

func TestDebugResponseWriter_MultipleWritesAccumulate(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: recorder, statusCode: http.StatusOK, body: &bytes.Buffer{}}

	_, err := rw.Write([]byte("first "))
	assert.NoError(t, err)
	_, err = rw.Write([]byte("second"))
	assert.NoError(t, err)

	assert.Equal(t, "first second", rw.body.String())
	assert.Equal(t, "first second", recorder.Body.String())
}

// -----------------------------------------------------------------------------
// The middleware
// -----------------------------------------------------------------------------

func TestAPIDebugMiddleware_DisabledPassesStraightThrough(t *testing.T) {
	withDebugAPIRequests(t, false)

	called := false
	handler := APIDebugMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// When disabled the handler must receive the original writer, not the wrapper.
		_, wrapped := w.(*responseWriter)
		assert.False(t, wrapped, "the response writer must not be wrapped when debugging is off")
		w.WriteHeader(http.StatusCreated)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/admin/users", nil))

	assert.True(t, called)
	assert.Equal(t, http.StatusCreated, recorder.Code)
}

func TestAPIDebugMiddleware_EnabledWrapsAndPreservesTheResponse(t *testing.T) {
	withDebugAPIRequests(t, true)

	handler := APIDebugMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, wrapped := w.(*responseWriter)
		assert.True(t, wrapped, "the response writer must be wrapped when debugging is on")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/admin/users", nil))

	assert.Equal(t, http.StatusAccepted, recorder.Code, "wrapping must not change the status")
	assert.Equal(t, `{"result":"ok"}`, recorder.Body.String(), "wrapping must not change the body")
}

// The middleware drains the request body to log it, so it has to put it back or
// the handler downstream would read nothing.
func TestAPIDebugMiddleware_RequestBodyIsStillReadableDownstream(t *testing.T) {
	withDebugAPIRequests(t, true)

	var seen string
	handler := APIDebugMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		assert.NoError(t, err)
		seen = buf.String()
	}))

	body := `{"email":"user@example.com"}`
	req := httptest.NewRequest("PUT", "/api/v1/account/email", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, body, seen, "the request body must be restored after being read for logging")
}

func TestAPIDebugMiddleware_EnabledWithNoRequestBody(t *testing.T) {
	withDebugAPIRequests(t, true)

	handler := APIDebugMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/admin/users", nil))

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

// -----------------------------------------------------------------------------
// debugLog
//
// This is the function that writes bodies to the log, so the case that matters is
// the Authorization header: it must be reduced to a placeholder and never logged
// verbatim.
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

func TestDebugLog_DoesNotLogTheAuthorizationHeaderVerbatim(t *testing.T) {
	testCases := []struct {
		name       string
		authHeader string
		secret     string
		wantInLog  string
	}{
		{
			name:       "bearer token is reduced to a placeholder",
			authHeader: "Bearer eyJhbGciOiJSUzI1NiJ9.SENTINEL-token-value.signature",
			secret:     "SENTINEL-token-value",
			wantInLog:  "Bearer [redacted]",
		},
		{
			name:       "basic credentials are reduced to a placeholder",
			authHeader: "Basic U0VOVElORUwtY2xpZW50OnNlY3JldA==",
			secret:     "U0VOVElORUwtY2xpZW50OnNlY3JldA==",
			wantInLog:  "[redacted] (unknown type)",
		},
		{
			name:       "an unknown scheme is reduced to a placeholder",
			authHeader: "Mystery SENTINEL-opaque-credential",
			secret:     "SENTINEL-opaque-credential",
			wantInLog:  "[redacted] (unknown type)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureSlog(t)

			req := httptest.NewRequest("POST", "/api/v1/admin/users", nil)
			req.Header.Set("Authorization", tc.authHeader)

			debugLog("POST", "/api/v1/admin/users", []byte(`{"a":1}`),
				http.StatusOK, []byte(`{"b":2}`), 5*time.Millisecond, req)

			assert.NotContains(t, logged.String(), tc.secret,
				"the credential must never be written to the log")
			assert.Contains(t, logged.String(), tc.wantInLog)
		})
	}
}

// With no Authorization header the placeholder is "None", so an absent credential
// is distinguishable from a redacted one.
func TestDebugLog_ReportsAnAbsentAuthorizationHeader(t *testing.T) {
	logged := captureSlog(t)

	req := httptest.NewRequest("GET", "/api/v1/admin/users", nil)
	debugLog("GET", "/api/v1/admin/users", nil, http.StatusOK, nil, time.Millisecond, req)

	assert.Contains(t, logged.String(), "Authorization: None")
}

// The bodies are logged deliberately, which is the point of the debug mode, so
// this pins that they do reach the log when present. It is also the regression
// guard against redaction becoming over-eager: an ordinary field must survive.
func TestDebugLog_LogsRequestAndResponseBodies(t *testing.T) {
	logged := captureSlog(t)

	req := httptest.NewRequest("POST", "/api/v1/admin/users", nil)
	debugLog("POST", "/api/v1/admin/users", []byte(`{"givenName":"Jane"}`),
		http.StatusCreated, []byte(`{"id":42}`), time.Millisecond, req)

	output := logged.String()
	assert.Contains(t, output, "givenName")
	assert.Contains(t, output, "Jane")
	assert.Contains(t, output, "201")
}

func TestDebugLog_HandlesEveryBodyShape(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/admin/users", nil)

	testCases := []struct {
		name     string
		reqBody  []byte
		respBody []byte
	}{
		{"both empty", nil, nil},
		{"valid json both ways", []byte(`{"a":1}`), []byte(`{"b":2}`)},
		{"request body is not json", []byte(`not json at all`), []byte(`{"b":2}`)},
		{"response body is not json", []byte(`{"a":1}`), []byte(`not json at all`)},
		{"neither is json", []byte(`nope`), []byte(`also nope`)},
		{"empty request, json response", nil, []byte(`{"b":2}`)},
		{"json request, empty response", []byte(`{"a":1}`), nil},
		{"nested json is indented", []byte(`{"a":{"b":[1,2,3]}}`), []byte(`{"c":{"d":true}}`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				debugLog("POST", "/api/v1/admin/users", tc.reqBody,
					http.StatusOK, tc.respBody, time.Millisecond, req)
			})
		})
	}
}

func TestDebugLog_HandlesUnknownStatusCode(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/admin/users", nil)

	// http.StatusText returns "" for an unrecognized code, which must not break
	// the log line.
	assert.NotPanics(t, func() {
		debugLog("GET", "/api/v1/admin/users", nil, 799, nil, time.Millisecond, req)
	})
}

// -----------------------------------------------------------------------------
// Redaction
//
// Everything below observes the redactor through debugLog and the captured slog
// output, which is the behaviour an operator sees. slog's text handler quotes the
// whole message, so a JSON body arrives with its newlines as the two characters
// \n and its quotes as \", which is why these assertions are written against
// unquoted fragments and sentinels rather than against quoted JSON.
// -----------------------------------------------------------------------------

// logRequestBody runs debugLog over one request body and returns what was logged.
func logRequestBody(t *testing.T, body string) string {
	t.Helper()
	logged := captureSlog(t)
	req := httptest.NewRequest("POST", "/api/v1/admin/users", nil)
	debugLog("POST", "/api/v1/admin/users", []byte(body),
		http.StatusOK, nil, time.Millisecond, req)
	return logged.String()
}

// nestedBody builds a body of `depth` nested objects with leaf at the bottom, so
// the deepest container sits at exactly `depth`.
func nestedBody(depth int, leaf string) string {
	return strings.Repeat(`{"a":`, depth) + `"` + leaf + `"` + strings.Repeat(`}`, depth)
}

// sizedBody builds a valid JSON body of exactly `size` bytes carrying the sentinel.
func sizedBody(size int, sentinel string) string {
	const prefix, suffix = `{"note":"`, `"}`
	padding := size - len(prefix) - len(suffix) - len(sentinel)
	if padding < 0 {
		panic("sizedBody: size too small for the sentinel")
	}
	return prefix + sentinel + strings.Repeat("x", padding) + suffix
}

// Every key in the vocabulary, one body per key. The redacted rows assert three
// things rather than one: the value is gone, the key is still there, and the
// placeholder is the agreed spelling. A table asserting absence only would pass
// with the entry deleted outright, or with a different placeholder, and both are
// things this change deliberately does not do.
//
// The hasSmtpPassword, otpEnabled, includeInIdToken and similar rows expect
// [redacted] although their real values are harmless booleans and integers. That
// is the accepted cost of the substring net catching credential fields nobody
// remembered to name, not a bug: none of those values is one anyone debugs with,
// and every one is visible in the admin UI.
func TestDebugLog_RedactsSensitiveKeysInBodies(t *testing.T) {
	testCases := []struct {
		key          string
		wantRedacted bool
	}{
		// The named set: every key that carries a credential on this surface.
		{"password", true},
		{"currentPassword", true},
		{"newPassword", true},
		{"otpCode", true},
		{"secretKey", true},
		{"base64Image", true},
		{"smtpPassword", true},
		{"clientSecret", true},
		{"client_secret", true},
		{"verificationCode", true},
		{"logoutUrl", true},

		// Caught by the substring net, and harmless: the accepted over-redaction.
		{"passwordPolicy", true},
		{"setPasswordType", true},
		{"hasSmtpPassword", true},
		{"otpEnabled", true},
		{"resourceOwnerPasswordCredentialsEnabled", true},
		{"includeInIdToken", true},
		{"includeInAccessToken", true},
		{"includeOpenIDConnectClaimsInIdToken", true},
		{"includeOpenIDConnectClaimsInAccessToken", true},
		{"tokenExpirationInSeconds", true},
		{"refreshTokenOfflineIdleTimeoutInSeconds", true},
		{"refreshTokenOfflineMaxLifetimeInSeconds", true},
		{"token_endpoint_auth_method", true},
		{"client_secret_expires_at", true},

		// Ordinary fields, which are the reason the log exists at all.
		{"email", false},
		{"givenName", false},
		{"id", false},
		{"enabled", false},
	}

	for _, tc := range testCases {
		t.Run(tc.key, func(t *testing.T) {
			output := logRequestBody(t, `{"`+tc.key+`":"SENTINEL"}`)

			if tc.wantRedacted {
				assert.NotContains(t, output, "SENTINEL",
					"the value of %q must never reach the log", tc.key)
				assert.Contains(t, output, tc.key,
					"the key must stay, so the log still shows what the request carried")
				assert.Contains(t, output, "[redacted]",
					"the value must be replaced by the agreed placeholder")
			} else {
				assert.Contains(t, output, "SENTINEL",
					"%q carries no credential and must still be logged", tc.key)
			}
		})
	}
}

// encoding/json matches struct tags with EqualFold semantics, so a handler accepts
// {"PASSWORD": ...} and even {"paſſword": ...} into its Password field. A matcher
// that missed either spelling would be a bypass: the handler would honour the
// request and the log would carry the credential in the clear.
func TestDebugLog_RedactsSensitiveKeysInAnyCase(t *testing.T) {
	spellings := []string{
		"PASSWORD", "PassWord", "SECRETKEY", "otpcode",
		"paſſword", "ſecretKey",
	}

	for _, spelling := range spellings {
		t.Run(spelling, func(t *testing.T) {
			output := logRequestBody(t, `{"`+spelling+`":"SENTINEL"}`)

			assert.NotContains(t, output, "SENTINEL",
				"%q is a spelling the handler accepts, so it must be redacted", spelling)
			assert.Contains(t, output, "[redacted]")
		})
	}
}

// foldKey has to agree with the standard library's notion of case equality exactly,
// because that is what decides which spellings the handler accepts. Lowercasing does
// not: it disagrees on the long-s rows below.
func TestFoldKey_MatchesEqualFold(t *testing.T) {
	spellings := []string{
		"password", "PASSWORD", "PassWord", "Password",
		"paſſword", "pasſword",
		"passwords", "passwordPolicy", "secretKey", "", "PASSWORd",
	}

	for _, spelling := range spellings {
		t.Run(spelling, func(t *testing.T) {
			assert.Equal(t,
				strings.EqualFold(spelling, "password"),
				foldKey(spelling) == foldKey("password"),
				"foldKey must classify %q the way encoding/json does", spelling)
		})
	}
}

// Credentials are not always at the top level: clientSecret arrives nested under
// client, and a body can be a bare array. Each case carries its own sentinel so a
// branch cannot be implemented wrongly and stay green on another case's evidence.
func TestDebugLog_RedactsThroughNestedStructures(t *testing.T) {
	t.Run("nested object", func(t *testing.T) {
		output := logRequestBody(t, `{"client":{"clientSecret":"NESTED-SENTINEL"}}`)

		assert.NotContains(t, output, "NESTED-SENTINEL")
		assert.Contains(t, output, "clientSecret")
		assert.Contains(t, output, "[redacted]")
	})

	t.Run("top level array", func(t *testing.T) {
		output := logRequestBody(t, `[{"password":"ARRAY-SENTINEL"}]`)

		assert.NotContains(t, output, "ARRAY-SENTINEL")
		assert.Contains(t, output, "password")
		assert.Contains(t, output, "[redacted]")
	})

	t.Run("array mixing sensitive and safe keys", func(t *testing.T) {
		output := logRequestBody(t,
			`[{"password":"MIXED-SECRET"},{"email":"MIXED-SAFE"}]`)

		assert.NotContains(t, output, "MIXED-SECRET")
		assert.Contains(t, output, "MIXED-SAFE", "the safe element must survive")
		assert.Contains(t, output, "[redacted]")
	})

	// A sensitive key whose value is an object is replaced whole rather than walked
	// into, so nothing it contained survives either.
	t.Run("object valued secret is replaced whole", func(t *testing.T) {
		output := logRequestBody(t, `{"password":{"safe":"OBJECT-SENTINEL"}}`)

		assert.NotContains(t, output, "OBJECT-SENTINEL")
		assert.NotContains(t, output, "safe",
			"the whole value goes, including keys nested inside it")
		assert.Contains(t, output, "password")
		assert.Contains(t, output, "[redacted]")
	})

	t.Run("bare scalar body", func(t *testing.T) {
		output := logRequestBody(t, `"SCALAR-SENTINEL"`)

		assert.Contains(t, output, "SCALAR-SENTINEL",
			"a scalar carries no key to judge, so it passes through")
	})
}

// POST /api/v1/account/logout-request returns a URL carrying a signed id_token_hint
// that /auth/logout accepts. Nothing about the name logoutUrl says so, which is why
// it is in the named set rather than caught by the substring net: remove that entry
// and this case is the one that fails.
func TestDebugLog_RedactsTheLogoutUrlCarryingAnIdTokenHint(t *testing.T) {
	output := logRequestBody(t, `{"logoutUrl":"https://localhost:8080/auth/logout`+
		`?id_token_hint=JWT-SENTINEL&post_logout_redirect_uri=https%3A%2F%2Fc.test%2Fout"}`)

	assert.NotContains(t, output, "JWT-SENTINEL",
		"the signed token in the URL is a credential and must not be logged")
	assert.Contains(t, output, "logoutUrl")
	assert.Contains(t, output, "[redacted]")
}

// A body that cannot be parsed, is too large, or is nested too deeply is replaced by
// a placeholder. There is no path that writes the bytes out anyway: the placeholder
// says how many there were and why they are not shown, and nothing else.
func TestDebugLog_RefusesBodiesItCannotSafelyLog(t *testing.T) {
	testCases := []struct {
		name       string
		body       string
		sentinel   string
		wantReason string
	}{
		{
			name:       "not json",
			body:       `garbage NOT-JSON-SENTINEL`,
			sentinel:   "NOT-JSON-SENTINEL",
			wantReason: "invalid character",
		},
		{
			name:       "trailing content after a valid value",
			body:       `{"a":1} TRAILING-SENTINEL`,
			sentinel:   "TRAILING-SENTINEL",
			wantReason: "trailing content",
		},
		{
			name:       "concatenated objects",
			body:       `{"a":1}{"b":"CONCAT-SENTINEL"}`,
			sentinel:   "CONCAT-SENTINEL",
			wantReason: "trailing content",
		},
		// An unmatched closing delimiter is the trailing content that does not look
		// like trailing content. json.Decoder.More answers "is there another element
		// in the container I am inside", so at the top level it reports no-more-input
		// for a stray ] or }, and a body ending in one was logged as valid JSON.
		{
			name:       "unmatched closing bracket",
			body:       `{"a":"BRACKET-SENTINEL"}]`,
			sentinel:   "BRACKET-SENTINEL",
			wantReason: "trailing content",
		},
		{
			name:       "unmatched closing brace",
			body:       `{"a":"BRACE-SENTINEL"}}`,
			sentinel:   "BRACE-SENTINEL",
			wantReason: "trailing content",
		},
		{
			name:       "whitespace before an unmatched closing bracket",
			body:       `{"a":"SPACED-BRACKET-SENTINEL"} ]`,
			sentinel:   "SPACED-BRACKET-SENTINEL",
			wantReason: "trailing content",
		},
		{
			name:       "newline before an unmatched closing brace",
			body:       "{\"a\":\"NEWLINE-BRACE-SENTINEL\"}\n}",
			sentinel:   "NEWLINE-BRACE-SENTINEL",
			wantReason: "trailing content",
		},
		{
			name:       "one byte over the size limit",
			body:       sizedBody(maxLoggedBody+1, "SIZE-SENTINEL"),
			sentinel:   "SIZE-SENTINEL",
			wantReason: "larger than",
		},
		{
			name:       "one level deeper than the depth limit",
			body:       nestedBody(maxLoggedDepth+1, "DEPTH-SENTINEL"),
			sentinel:   "DEPTH-SENTINEL",
			wantReason: "nested deeper than",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := logRequestBody(t, tc.body)

			assert.NotContains(t, output, tc.sentinel,
				"no fragment of a refused body may be logged")
			assert.Contains(t, output, fmt.Sprintf("%d bytes", len(tc.body)),
				"the operator needs to know a body was there and how big it was")
			assert.Contains(t, output, tc.wantReason,
				"and why it was not logged, or the placeholder says nothing useful")
		})
	}
}

// The other side of the refusals, which have the opposite oracle and so are separate
// cases: a body sitting exactly on a bound is logged, and an absent body produces no
// body line at all rather than a placeholder.
func TestDebugLog_LogsBodiesOnTheAcceptedSideOfEveryBound(t *testing.T) {
	t.Run("empty body logs no body line", func(t *testing.T) {
		output := logRequestBody(t, "")

		assert.NotContains(t, output, "Request Body:",
			"a bodyless request must stay distinguishable from a refused body")
	})

	t.Run("exactly the size limit", func(t *testing.T) {
		output := logRequestBody(t, sizedBody(maxLoggedBody, "AT-SIZE-SENTINEL"))

		assert.Contains(t, output, "AT-SIZE-SENTINEL",
			"the bound is exclusive, so a body of exactly this size is logged")
	})

	t.Run("exactly the depth limit", func(t *testing.T) {
		output := logRequestBody(t, nestedBody(maxLoggedDepth, "AT-DEPTH-SENTINEL"))

		assert.Contains(t, output, "AT-DEPTH-SENTINEL",
			"the deepest container may sit at exactly the limit")
	})

	// Depth is only counted through what actually gets logged. A sensitive value is
	// replaced whole and never traversed, so however deep it is, it costs the encoder
	// nothing and the body is still worth logging. Refusing here would throw away a
	// readable body over a subtree that was going to be one word.
	t.Run("a sensitive value may nest deeper than the depth limit", func(t *testing.T) {
		body := `{"password":` + nestedBody(maxLoggedDepth+8, "DEEP-SECRET-SENTINEL") + `}`

		output := logRequestBody(t, body)

		assert.NotContains(t, output, "DEEP-SECRET-SENTINEL",
			"the secret is still redacted, whatever it is wrapped in")
		assert.NotContains(t, output, "nested deeper than",
			"an untraversed subtree cannot make the body too expensive to log")
		assert.Contains(t, output, redactedValue)
		assert.Contains(t, output, "password")
	})

	// The other side of the unmatched-delimiter refusals. Requiring the second decode
	// to end in io.EOF must not start refusing the trailing whitespace that every
	// json.Encoder writes, or every body a Go client sends stops being logged.
	t.Run("trailing whitespace after a complete value", func(t *testing.T) {
		output := logRequestBody(t, "{\"a\":\"TRAILING-WS-SENTINEL\"}\n  ")

		assert.Contains(t, output, "TRAILING-WS-SENTINEL",
			"whitespace after the value is not trailing content")
	})
}

// Three ways the encoder can quietly corrupt a body that is otherwise redacted
// correctly. All three pass silently with the wrong encoder settings, so they are
// cases rather than assumptions.
func TestDebugLog_LogsBodiesFaithfully(t *testing.T) {
	t.Run("large integers keep their value", func(t *testing.T) {
		output := logRequestBody(t, `{"maxLifetime":9223372036854775807}`)

		assert.Contains(t, output, "9223372036854775807",
			"a float64 round trip would log 9223372036854776000, which is not the value sent")
	})

	t.Run("ampersands are not HTML escaped", func(t *testing.T) {
		output := logRequestBody(t, `{"websiteUrl":"https://c.test/a?x=1&y=2"}`)

		assert.Contains(t, output, "&")
		assert.NotContains(t, output, "u0026",
			"HTML escaping would make the logged URL differ from the one sent")
	})

	t.Run("nested objects are indented", func(t *testing.T) {
		output := logRequestBody(t, `{"outer":{"inner":1}}`)

		// slog quotes the message, so a newline arrives as the two characters \n
		// and the second indentation level as the four spaces after it.
		assert.Contains(t, output, `\n    \"inner\"`,
			"the body is pretty printed, which is the point of logging it")
	})
}

// -----------------------------------------------------------------------------
// The middleware, end to end
//
// Everything above drives debugLog directly, which cannot show that the middleware
// hands it the bytes it buffered and teed: the call site could pass the raw bodies
// to anything and every case above would still pass. The two cases below run real
// src/core/api payloads, built from a real TOTP seed, through the middleware mounted
// the way routes.go mounts it, and assert on what an operator would find in the log.
//
// The handlers here are the tests' own. The production handler cannot be called from
// this package because handlers/apihandlers imports this one, and reaching it would
// need a mock database, a settings context value and a validated token. What is real
// is what carries the credential: the response and request types, the seed and QR
// from otp.OTPSecretGenerator, a live TOTP code, and the same
// json.NewEncoder(w).Encode(resp) the endpoint writes its body with.
// -----------------------------------------------------------------------------

// debugAPIRouter mounts handler behind APIDebugMiddleware on a chi router, with the
// middleware as the first r.Use under /api/v1/account, which is how routes.go builds
// the account API. Debug logging is turned on for the duration of the test.
func debugAPIRouter(t *testing.T, method, pattern string, handler http.HandlerFunc) *chi.Mux {
	t.Helper()
	withDebugAPIRequests(t, true)

	router := chi.NewRouter()
	router.Route("/api/v1/account", func(r chi.Router) {
		r.Use(APIDebugMiddleware())
		r.Method(method, pattern, handler)
	})
	return router
}

// GET /api/v1/account/otp/enrollment returns the TOTP seed twice: once as secretKey
// and once inside base64Image, which is a QR of the otpauth:// URL the seed is in.
// Both must be gone from the log, and the client must still receive exactly what the
// handler wrote.
func TestAPIDebugMiddleware_DoesNotLogARealOTPEnrollmentResponse(t *testing.T) {
	logged := captureSlog(t)

	generator := otp.OTPSecretGenerator{}
	base64Image, secretKey, err := generator.GenerateOTPSecret("seam2@example.com", "Goiabada")
	assert.NoError(t, err)

	// What the handler wrote, captured as it writes it, so the comparison below is
	// against the real bytes rather than against a second encode of the same struct.
	var written bytes.Buffer
	router := debugAPIRouter(t, http.MethodGet, "/otp/enrollment", func(w http.ResponseWriter, r *http.Request) {
		resp := api.AccountOTPEnrollmentResponse{Base64Image: base64Image, SecretKey: secretKey}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(io.MultiWriter(w, &written)).Encode(resp)
		assert.NoError(t, err)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/account/otp/enrollment", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, written.Bytes(),
		"the handler must have run, or the comparison below holds between two empty slices")
	assert.Equal(t, written.Bytes(), recorder.Body.Bytes(),
		"buffering the response for the log must not change a byte of what the client receives")

	output := logged.String()
	assert.NotContains(t, output, secretKey,
		"the TOTP seed must not reach the log")
	// Asserted on a prefix rather than the whole string: a bug that logged only the
	// first part of the image would pass a whole-string check and still publish the
	// seed to anyone who reassembled it.
	assert.NotContains(t, output, base64Image[:64],
		"nor the QR code, which is the same seed in another form")

	// Absence alone would also hold with the whole response body dropped, which is not
	// what this change does: the shape of the body stays readable.
	assert.Contains(t, output, "secretKey")
	assert.Contains(t, output, "base64Image")
	assert.Contains(t, output, redactedValue)
}

// PUT /api/v1/account/otp carries three credentials up: the account password, a live
// TOTP code and the seed it was generated from. None may reach the log, and all three
// must still reach the handler, which is the half that makes the middleware safe to
// mount in front of a real endpoint rather than merely quiet.
func TestAPIDebugMiddleware_DoesNotLogARealOTPUpdateRequest(t *testing.T) {
	logged := captureSlog(t)

	generator := otp.OTPSecretGenerator{}
	_, secretKey, err := generator.GenerateOTPSecret("seam2@example.com", "Goiabada")
	assert.NoError(t, err)

	otpCode, err := totp.GenerateCode(secretKey, time.Now())
	assert.NoError(t, err)

	sent := api.UpdateAccountOTPRequest{
		Enabled:   true,
		Password:  "SENTINEL-account-password",
		OtpCode:   otpCode,
		SecretKey: secretKey,
	}
	body, err := json.Marshal(sent)
	assert.NoError(t, err)

	router := debugAPIRouter(t, http.MethodPut, "/otp", func(w http.ResponseWriter, r *http.Request) {
		var received api.UpdateAccountOTPRequest
		err := json.NewDecoder(r.Body).Decode(&received)
		assert.NoError(t, err)
		assert.Equal(t, sent, received,
			"the handler must receive the credentials intact after the middleware read the body to log it")

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(`{"otpEnabled":true}`))
		assert.NoError(t, err)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/account/otp", bytes.NewReader(body)))

	assert.Equal(t, http.StatusOK, recorder.Code)

	output := logged.String()
	assert.NotContains(t, output, "SENTINEL-account-password",
		"the account password must not reach the log")
	assert.NotContains(t, output, otpCode,
		"nor a live OTP code, which is usable until its step expires")
	assert.NotContains(t, output, secretKey,
		"nor the seed, which is usable indefinitely")

	// The request body's one harmless field, asserted with its value and its opening
	// quote. A bare "enabled" would also match the response's otpEnabled key, which
	// the substring net redacts, so the case would pass with the request body dropped.
	assert.Contains(t, output, `\"enabled\": true`,
		"an ordinary field must survive, or the entry is worth nothing to debug with")
	assert.Contains(t, output, "password")
	assert.Contains(t, output, "otpCode")
	assert.Contains(t, output, "secretKey")
	assert.Contains(t, output, redactedValue)
}
