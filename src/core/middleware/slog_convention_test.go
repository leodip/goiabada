package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/testutil"
)

// This file pins the level and the shape of the records core's middleware writes, per #320
// decision 5.
//
// Level is the one rule in that decision the lint cannot hold: it is not decidable from the text
// of a call, so nothing stops somebody raising a handled refusal to Error or lowering a server
// fault to Warn one site at a time until the level means nothing. What holds it is a case per
// site: a CSRF refusal and the request log. The authserver middleware records live with their
// middleware; the invalid-issuer clear is pinned at Warn beside its own case in
// middleware_jwt_test.go.
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
	// Under the request logger's key for the same value since #425, which bounded it.
	assert.Equal(t, "/auth/pwd", record.Attrs["target"])
	assert.NotContains(t, record.Attrs, "path")
	assert.Equal(t, "auth.example.com", record.Attrs["request_host"])
	assert.Equal(t, "https://evil.example.com", record.Attrs["origin_header"])
	assert.Equal(t, "cross-site", record.Attrs["sec_fetch_site"])
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
