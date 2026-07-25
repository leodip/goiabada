package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
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
			wantInLog:  "Bearer ***",
		},
		{
			name:       "basic credentials are reduced to a placeholder",
			authHeader: "Basic U0VOVElORUwtY2xpZW50OnNlY3JldA==",
			secret:     "U0VOVElORUwtY2xpZW50OnNlY3JldA==",
			wantInLog:  "*** (unknown type)",
		},
		{
			name:       "an unknown scheme is reduced to a placeholder",
			authHeader: "Mystery SENTINEL-opaque-credential",
			secret:     "SENTINEL-opaque-credential",
			wantInLog:  "*** (unknown type)",
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
// this pins that they do reach the log when present.
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
