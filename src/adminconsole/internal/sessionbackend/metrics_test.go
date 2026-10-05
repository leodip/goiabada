package sessionbackend

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/metrics"
)

// The backend's calls, read as a scrape reports them (#400 decision 6): each attempt is a call of
// its own under the sessions target, so the 401 that drives a refresh and the retry after it are
// two, and an endpoint nothing answers is an error twice, the one transport retry included.

func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

func TestHTTPBackend_RecordsEachAttemptUnderTheSessionsTarget(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, attempt int) {
		if attempt == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		alwaysOK(api.SessionLoadResponse{Data: "ciphertext"})(w, attempt)
	})
	reg := metrics.NewRegistry()
	backend := New(stub.server.URL, newStubTokens(), upstreammetrics.Register(reg))

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)

	exposition := scrape(t, reg)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="sessions",status="401"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="sessions",status="200"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="sessions"} 2`+"\n")
}

func TestHTTPBackend_AnEndpointNothingAnswersIsAnErrorPerAttempt(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	baseURL := "http://" + closed.Addr().String()
	require.NoError(t, closed.Close())

	reg := metrics.NewRegistry()
	backend := New(baseURL, newStubTokens(), upstreammetrics.Register(reg))

	_, err = backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)

	assert.Contains(t, scrape(t, reg), `goiabada_upstream_requests_total{target="sessions",status="error"} 2`+"\n")
}
