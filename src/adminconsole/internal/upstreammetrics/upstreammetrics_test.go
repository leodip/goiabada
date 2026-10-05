package upstreammetrics_test

// Seam: what a scrape reports after a call goes through a recorded client (#400 decision 6). The
// calls are real HTTP to a peer this test serves, and the counts are read from the exposition a
// scraper would read.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// sampleValue returns the value of the one sample whose name and labels are series.
func sampleValue(t *testing.T, exposition, series string) float64 {
	t.Helper()

	var found []string
	for _, line := range strings.Split(exposition, "\n") {
		if strings.HasPrefix(line, series+" ") {
			found = append(found, strings.TrimPrefix(line, series+" "))
		}
	}
	require.Len(t, found, 1, "one %s sample", series)
	v, err := strconv.ParseFloat(found[0], 64)
	require.NoError(t, err)
	return v
}

// peerDelay is how long the slow peers below take to answer. Long enough that no fast-path bucket
// can hold the call, short enough that a loaded test machine still finishes it inside one second.
const peerDelay = 100 * time.Millisecond

// assertTimedInSeconds checks that target's one call was observed as taking at least atLeast, in
// seconds: above the 0.05 bucket, inside the one-second one, and with a sum no smaller than atLeast.
// An observation of zero, or one in milliseconds, fails it.
func assertTimedInSeconds(t *testing.T, exposition, target string, atLeast time.Duration) {
	t.Helper()

	const series = "goiabada_upstream_request_duration_seconds"
	labels := `{target="` + target + `"`
	sum := sampleValue(t, exposition, series+"_sum"+labels+"}")
	assert.GreaterOrEqual(t, sum, atLeast.Seconds())
	assert.Less(t, sum, 1.0, "a call of about %s observed in seconds, with a generous margin for the scheduler", atLeast)
	assert.Contains(t, exposition, series+"_bucket"+labels+`,le="0.05"} 0`+"\n")
	assert.Contains(t, exposition, series+"_bucket"+labels+`,le="1"} 1`+"\n")
	assert.Contains(t, exposition, series+"_count"+labels+"} 1\n")
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
	sessions := upstreammetrics.Register(reg).Client(upstreammetrics.Sessions, &http.Client{Timeout: 2 * peerDelay})

	require.Error(t, get(t, sessions, peer.URL+"/api/v1/session/load"))

	exposition := scrape(t, reg)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="sessions",status="error"} 1`+"\n")
	// Timed to the moment the client gave up, its timeout. The deadline is set before the round trip
	// starts, so the call is held to the smaller peerDelay rather than to the whole timeout.
	assertTimedInSeconds(t, exposition, "sessions", peerDelay)
}

// A call's duration is the time to the peer's response headers, in seconds: a peer that waits
// 100 ms before answering is observed as at least that.
func TestRecorder_TimesTheCallInSeconds(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(peerDelay)
	}))
	defer peer.Close()

	reg := metrics.NewRegistry()
	jwks := upstreammetrics.Register(reg).Client(upstreammetrics.JWKS, &http.Client{Timeout: 5 * time.Second})

	require.NoError(t, get(t, jwks, peer.URL+"/certs"))

	exposition := scrape(t, reg)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="jwks",status="200"} 1`+"\n")
	assertTimedInSeconds(t, exposition, "jwks", peerDelay)
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
