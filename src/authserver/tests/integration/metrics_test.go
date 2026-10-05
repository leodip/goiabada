package integration

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/hostport"
)

// The running server's metrics listener (#400), which the test script and CI start it with: the
// one place main's wiring of the listener and the real router are exercised together. The server
// answers other tests' requests while this one runs, so a count is read as how much it grew.

// scrapeMetrics reads the exposition from the metrics listener the server under test was started
// with.
func scrapeMetrics(t *testing.T) string {
	t.Helper()
	require.True(t, appConfig.AuthServer.MetricsEnabled,
		"the integration server runs with GOIABADA_AUTHSERVER_METRICS_ENABLED=true, set by run-tests.sh")

	url := "http://" + hostport.Join("localhost", appConfig.AuthServer.ListenPortMetrics) + "/metrics"
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", resp.Header.Get("Content-Type"))
	return string(body)
}

// sampleValue answers the value of the sample whose name and labels are series, 0 when the
// exposition has none yet.
func sampleValue(t *testing.T, exposition, series string) float64 {
	t.Helper()
	for _, line := range strings.Split(exposition, "\n") {
		if value, found := strings.CutPrefix(line, series+" "); found {
			v, err := strconv.ParseFloat(value, 64)
			require.NoError(t, err, line)
			return v
		}
	}
	return 0
}

func TestMetrics_TheListenerCountsTheRequestsTheServerAnswers(t *testing.T) {
	t.Parallel()

	const discovery = `goiabada_http_requests_total{route="/.well-known/openid-configuration",method="GET",status="200"}`
	const unmatched = `goiabada_http_requests_total{route="unmatched",method="GET",status="404"}`

	before := scrapeMetrics(t)

	resp, err := http.Get(appConfig.AuthServer.BaseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// A path no route answers, carrying a value no label may hold: a raw path never reaches one.
	marker := "metrics" + fake.LetterN(16)
	resp, err = http.Get(appConfig.AuthServer.BaseURL + "/no-such-route/" + marker)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	after := scrapeMetrics(t)

	assert.GreaterOrEqual(t, sampleValue(t, after, discovery)-sampleValue(t, before, discovery), float64(1))
	assert.GreaterOrEqual(t, sampleValue(t, after, unmatched)-sampleValue(t, before, unmatched), float64(1))
	assert.NotContains(t, after, marker, "a request's path never reaches a label")
	assert.Contains(t, after, "# TYPE goiabada_build_info gauge\n")
	assert.Contains(t, after, "# TYPE go_goroutines gauge\n")
	// The real pool behind the server, read at the scrape (#400 decision 5).
	assert.Contains(t, after, "# TYPE goiabada_db_connections gauge\n")
	assert.Contains(t, after, "# TYPE goiabada_db_wait_count_total counter\n")
	assert.Positive(t, sampleValue(t, after, "goiabada_db_max_open_connections"), "the pool's cap is the one it runs on")
	assert.NotContains(t, after, `route="/metrics"`, "a scrape is not counted")
}

// A client credentials grant is counted as a token issued, and a request naming no client as a
// token request refused, under the grant it asked for and the RFC 6749 section 5.2 code it was
// answered with (#400 decision 5).
func TestMetrics_TheTokenEndpointCountsWhatItIssuesAndRefuses(t *testing.T) {
	t.Parallel()

	const issued = `goiabada_tokens_issued_total{grant_type="client_credentials"}`
	const refused = `goiabada_token_requests_refused_total{grant_type="client_credentials",error="invalid_request"}`

	before := scrapeMetrics(t)

	accessToken, _ := createAdminClientWithToken(t)
	require.NotEmpty(t, accessToken)

	got := postTokenRequest(t, url.Values{"grant_type": {"client_credentials"}}, false, "", "")
	require.Equal(t, "invalid_request", got.body["error"])

	after := scrapeMetrics(t)

	assert.GreaterOrEqual(t, sampleValue(t, after, issued)-sampleValue(t, before, issued), float64(1))
	assert.GreaterOrEqual(t, sampleValue(t, after, refused)-sampleValue(t, before, refused), float64(1))
	for _, family := range []string{
		"goiabada_rate_limit_refusals_total",
		"goiabada_cleanup_runs_total",
		"goiabada_cleanup_last_run_duration_seconds",
		"goiabada_cleanup_last_success_timestamp_seconds",
		"goiabada_after_response_jobs_in_flight",
		"goiabada_after_response_jobs_dropped_total",
	} {
		assert.Contains(t, after, "# TYPE "+family+" ", "the running server registers %s", family)
	}
}

// The main listener serves no metrics, and the metrics listener nothing but them.
func TestMetrics_EachListenerServesOnlyItsOwn(t *testing.T) {
	t.Parallel()

	resp, err := http.Get(appConfig.AuthServer.BaseURL + "/metrics")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.NotContains(t, string(body), "goiabada_build_info")

	metricsBase := "http://" + hostport.Join("localhost", appConfig.AuthServer.ListenPortMetrics)
	for _, path := range []string{"/debug/pprof/", "/debug/vars", "/health"} {
		resp, err := http.Get(metricsBase + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s on the metrics listener", path)
	}
}
