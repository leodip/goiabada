package upstreammetrics_test

// Seam: what a scrape reports after a call goes through a recorded client (#400 decision 6). The
// calls are real HTTP to a peer this test serves, and the counts are read from the exposition a
// scraper would read.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// scrape reads reg's exposition through its handler.
func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

// get sends one GET through client and closes the answer.
func get(t *testing.T, client *http.Client, url string) error {
	t.Helper()

	resp, err := client.Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

// Each call is counted under the client's target and the exact status the peer answered with, and
// timed under the target.
func TestRecorder_CountsEachCallByTargetAndStatus(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unavailable" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer peer.Close()

	reg := metrics.NewRegistry()
	recorder := upstreammetrics.Register(reg)
	settings := recorder.Client(upstreammetrics.Settings, &http.Client{Timeout: time.Second})
	jwks := recorder.Client(upstreammetrics.JWKS, &http.Client{Timeout: time.Second})

	require.NoError(t, get(t, settings, peer.URL+"/ok"))
	require.NoError(t, get(t, settings, peer.URL+"/ok"))
	require.NoError(t, get(t, settings, peer.URL+"/unavailable"))
	require.NoError(t, get(t, jwks, peer.URL+"/ok"))

	exposition := scrape(t, reg)
	for _, line := range []string{
		`goiabada_upstream_requests_total{target="settings",status="200"} 2`,
		`goiabada_upstream_requests_total{target="settings",status="503"} 1`,
		`goiabada_upstream_requests_total{target="jwks",status="200"} 1`,
		`goiabada_upstream_request_duration_seconds_count{target="settings"} 3`,
		`goiabada_upstream_request_duration_seconds_count{target="jwks"} 1`,
		`goiabada_upstream_request_duration_seconds_bucket{target="settings",le="60"} 3`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.Equal(t, 3, strings.Count(exposition, "goiabada_upstream_requests_total{"),
		"three series: the path the call took is no label")
}

// A call that received no response, here a connection nothing accepts, is counted as error rather
// than under any status code, and still timed.
func TestRecorder_ACallThatGetsNoResponseIsAnError(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	url := "http://" + closed.Addr().String() + "/certs"
	require.NoError(t, closed.Close())

	reg := metrics.NewRegistry()
	token := upstreammetrics.Register(reg).Client(upstreammetrics.Token, &http.Client{Timeout: time.Second})

	require.Error(t, get(t, token, url))

	exposition := scrape(t, reg)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="token",status="error"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="token"} 1`+"\n")
}

// A peer that answers after the client's timeout is an error too: the timeout is the client's,
// and the recorded copy keeps it.
func TestRecorder_TheClientsTimeoutStillHoldsAndIsAnError(t *testing.T) {
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer peer.Close()
	defer close(release)

	reg := metrics.NewRegistry()
	sessions := upstreammetrics.Register(reg).Client(upstreammetrics.Sessions, &http.Client{Timeout: 50 * time.Millisecond})

	require.Error(t, get(t, sessions, peer.URL+"/api/v1/session/load"))

	assert.Contains(t, scrape(t, reg), `goiabada_upstream_requests_total{target="sessions",status="error"} 1`+"\n")
}

// The recorded client is a copy: the one it was made from records nothing and keeps its transport,
// so wrapping a client two consumers share does not label the other's calls.
func TestRecorder_LeavesTheClientItWasGivenAsItWas(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer peer.Close()

	reg := metrics.NewRegistry()
	shared := &http.Client{Timeout: time.Second}
	recorded := upstreammetrics.Register(reg).Client(upstreammetrics.AdminAPI, shared)

	assert.NotSame(t, shared, recorded)
	assert.Nil(t, shared.Transport)
	assert.Equal(t, shared.Timeout, recorded.Timeout)

	require.NoError(t, get(t, shared, peer.URL))
	assert.NotContains(t, scrape(t, reg), "goiabada_upstream_requests_total{")

	require.NoError(t, get(t, recorded, peer.URL))
	assert.Contains(t, scrape(t, reg), `goiabada_upstream_requests_total{target="admin_api",status="200"} 1`+"\n")
}

// A nil recorder hands the client back as it is.
func TestRecorder_ANilRecorderRecordsNothing(t *testing.T) {
	client := &http.Client{}
	var recorder *upstreammetrics.Recorder

	assert.Same(t, client, recorder.Client(upstreammetrics.Token, client))
}

// The two families' labels and their sets, as the catalog states them.
func TestRegister_DeclaresTheTargetsAndStatuses(t *testing.T) {
	reg := metrics.NewRegistry()
	upstreammetrics.Register(reg)

	families := map[string]metrics.Family{}
	for _, f := range reg.Families() {
		families[f.Name] = f
	}
	requests := families["goiabada_upstream_requests_total"]
	require.Len(t, requests.Labels, 2)
	assert.Equal(t, []string{"admin_api", "settings", "token", "jwks", "sessions"}, requests.Labels[0].Values())
	statuses := requests.Labels[1].Values()
	assert.Len(t, statuses, 501)
	assert.Equal(t, "100", statuses[0])
	assert.Equal(t, "599", statuses[499])
	assert.Equal(t, "error", statuses[500])

	duration := families["goiabada_upstream_request_duration_seconds"]
	assert.Equal(t, "histogram", duration.Type)
	require.Len(t, duration.Labels, 1)
	assert.Equal(t, "target", duration.Labels[0].Name())
}
