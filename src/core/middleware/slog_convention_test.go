package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/testutil"
)

// This file pins the level and the shape of the records core's middleware writes, per #320
// decision 5.
//
// Level is the one rule in that decision the lint cannot hold: it is not decidable from the text
// of a call, so nothing stops somebody raising a handled refusal to Error or lowering a server
// fault to Warn one site at a time until the level means nothing. What holds it is a case per
// site, here, at the sites the decision names: a rate limiter doing its job, a CSRF refusal, a
// settings read that failed, a CORS configuration that could not be read. Three are pinned where
// they already were and one moved (the invalid-issuer clear, pinned at Warn beside its own case
// in middleware_jwt_test.go).
//
// Each case also asserts request_id, which is decision 2 measured end to end rather than by
// reading the call site: the attribute is on the record because chi's RequestID ran ahead of the
// middleware and the installed handler took the id off the context, and no call here names it.

// requestIdOf reads the injected attribute, failing the test when it is absent.
func requestIdOf(t *testing.T, record testutil.CapturedRecord) string {
	t.Helper()
	requestId, isString := record.Attrs["request_id"].(string)
	require.True(t, isString,
		"the record must carry request_id, injected by the handler from chi's request id")
	require.NotEmpty(t, requestId)
	return requestId
}

// theOneRecord returns the single record captured, failing when there is not exactly one.
func theOneRecord(t *testing.T, logged *testutil.SlogCapture) testutil.CapturedRecord {
	t.Helper()
	records := logged.Records()
	require.Len(t, records, 1)
	return records[0]
}

// A limiter doing its job is an expected event. Error here and an auth server under any kind of
// scripted traffic has an error log made entirely of successful defences.
func TestSlogConvention_RateLimitTripIsWarnAndJoinsTheRequest(t *testing.T) {
	const ipBudget = 30
	const ip = "198.51.100.9:5000"

	m := newTestMiddleware(nil, true)

	run := func(email string) *httptest.ResponseRecorder {
		form := url.Values{"email": {email}}
		req := limiterRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		// Through chi's RequestID, as the real chain mounts it, so the id the trip record
		// carries is one this test did not put there.
		chimiddleware.RequestID(m.LimitPwd(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTeapot)
			}))).ServeHTTP(rr, req)
		return rr
	}

	// Spend the budget before capturing, so the capture holds the trip and nothing else.
	for i := 0; i < ipBudget; i++ {
		require.Equal(t, http.StatusTeapot, run("user@example.com").Code)
	}

	logged := testutil.CaptureSlog(t)
	require.Equal(t, http.StatusTooManyRequests, run("last@example.com").Code)

	record := theOneRecord(t, logged)
	assert.Equal(t, slog.LevelWarn, record.Level)
	assert.Equal(t, "rate limit reached", record.Message)
	assert.Equal(t, "pwd_ip", record.Attrs["limiter"])
	assert.Equal(t, "198.51.100.9", record.Attrs["ip"])
	requestIdOf(t, record)
}

// The refusal's message is a literal now, and the sentence explainCsrfFailure builds is an
// attribute. Warn rather than Error because the control working is not a fault, and the record is
// pinned whole: a collector counting refusals matches on the message, and a message that went back
// to being the explanation would give it four different strings to know about (#320 decision 4).
func TestSlogConvention_CsrfRefusalIsWarnWithALiteralMessage(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/pwd", nil)
	req.Host = "auth.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	rr := httptest.NewRecorder()
	chimiddleware.RequestID(MiddlewareCsrf()(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("the handler must not be reached on a refused request")
		}))).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)

	record := theOneRecord(t, logged)
	assert.Equal(t, slog.LevelWarn, record.Level)
	assert.Equal(t, "cross-origin request refused", record.Message)
	assert.Contains(t, record.Attrs["explanation"], "reported as cross-site",
		"the sentence that used to be the message is now an attribute")
	assert.NotEmpty(t, record.Attrs["remedy"])
	assert.Equal(t, http.MethodPost, record.Attrs["method"])
	assert.Equal(t, "/auth/pwd", record.Attrs["path"])
	assert.Equal(t, "auth.example.com", record.Attrs["request_host"])
	assert.Equal(t, "https://evil.example.com", record.Attrs["origin_header"])
	assert.Equal(t, "cross-site", record.Attrs["sec_fetch_site"])
	requestIdOf(t, record)
}

// An unreadable settings row is a server fault: every page's layout reads those settings, so the
// deployment is answering 500 to everything until somebody acts. Error, and pinned.
func TestSlogConvention_SettingsReadFailureIsError(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(nil, errors.New("database error"))

	rr := httptest.NewRecorder()
	chimiddleware.RequestID(MiddlewareSettings(mockDB)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("the handler must not be reached when the settings cannot be read")
		}))).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusInternalServerError, rr.Code)

	record := theOneRecord(t, logged)
	assert.Equal(t, slog.LevelError, record.Level)
	assert.Equal(t, "unable to load the settings", record.Message)
	requestId := requestIdOf(t, record)

	// The id on the record is the one the reader is shown, which is the whole point of
	// correlating them: an operator handed this number by a user greps the log for it.
	assert.Contains(t, rr.Body.String(), requestId)

	// Exactly once. The call site used to name request_id itself and now does not, so a
	// restored attribute would write it twice and a collector keying on it would see a
	// duplicate field rather than an error.
	assert.Equal(t, 1, strings.Count(logged.Text(), "request_id="),
		"request_id comes from the handler alone, never also from the call site")
}

// Fail-closed, and loud: an unreadable web origins list is not an empty one, and the middleware
// answers false rather than letting script on any origin read a token response. Somebody has to
// act, so Error.
func TestSlogConvention_CorsConfigurationFailureIsError(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("WebOriginExists", mock.Anything, "https://app.example.com").
		Return(false, errors.New("the database is unreachable"))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Origin", "https://app.example.com")

	rr := httptest.NewRecorder()
	reached := false
	chimiddleware.RequestID(MiddlewareCors(mockDB)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))).ServeHTTP(rr, req)

	// The request still runs; what is withheld is the header that would let script read it.
	assert.True(t, reached)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"),
		"an unreadable origin list must not approve the origin")

	record := theOneRecord(t, logged)
	assert.Equal(t, slog.LevelError, record.Level)
	assert.Equal(t, "unable to load the cors configuration", record.Message)
	err, isError := record.Attrs["error"].(error)
	require.True(t, isError, "the error attribute must be an error value, not a string")
	assert.Contains(t, err.Error(), "the database is unreachable")
	requestIdOf(t, record)
}

// The request logger is the record everything else correlates to, and it was the other site that
// named request_id itself. The whole textual rule is stage 7's lint; this is the behavioural half
// for the one record that would be useless without the attribute.
func TestSlogConvention_RequestLogCarriesTheInjectedRequestIdOnce(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	rr := httptest.NewRecorder()
	chimiddleware.RequestID(MiddlewareRequestLogger(true)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

	record := theOneRecord(t, logged)
	assert.Equal(t, slog.LevelInfo, record.Level)
	assert.Equal(t, "http request", record.Message)
	requestIdOf(t, record)
	assert.Equal(t, 1, strings.Count(logged.Text(), "request_id="),
		"the request logger no longer writes request_id itself")
}
