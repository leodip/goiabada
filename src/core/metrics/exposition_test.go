package metrics_test

// Seam: the exposition a registry serves, read through its handler as a scraper reads it. The
// expected text is written out by hand from the examples in Prometheus's exposition_formats.md
// (text format 0.0.4), with two differences the format allows: no timestamps, which Goiabada
// never writes, and Go's shortest float spelling, so the specification's 1.458255915e9 is
// written 1.458255915e+09, which the format's ParseFloat reading accepts as the same number.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

// scrape GETs the registry's handler and returns the body, having checked the two things every
// scrape owes: a 200 and the Content-Type Prometheus 3 refuses a scrape without.
func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	res := rec.Result()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, "text/plain; version=0.0.4; charset=utf-8", res.Header.Get("Content-Type"))
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return string(body)
}

// The specification's first example: a counter with two labels, two series.
func TestExposition_ACounterWithLabels(t *testing.T) {
	reg := metrics.NewRegistry()
	requests := reg.Counter("http_requests_total", "The total number of HTTP requests.",
		metrics.Enum("method", "post", "get"),
		metrics.Enum("code", "200", "400"))

	requests.Add(1027, "post", "200")
	requests.Add(3, "post", "400")

	assert.Equal(t, ""+
		"# HELP http_requests_total The total number of HTTP requests.\n"+
		"# TYPE http_requests_total counter\n"+
		"http_requests_total{method=\"post\",code=\"200\"} 1027\n"+
		"http_requests_total{method=\"post\",code=\"400\"} 3\n",
		scrape(t, reg))
}

// The specification's escaping example. A label value escapes the backslash, the double quote and
// the line feed; HELP escapes the backslash and the line feed and leaves a quote alone.
func TestExposition_Escaping(t *testing.T) {
	reg := metrics.NewRegistry()
	const path = `C:\DIR\FILE.TXT`
	const message = "Cannot find file:\n\"FILE.TXT\""
	access := reg.Gauge("msdos_file_access_time_seconds", "A \"quoted\" help with a \\ backslash\nand a line feed.",
		metrics.Enum("path", path),
		metrics.Enum("error", message))

	access.Set(1.458255915e9, path, message)

	assert.Equal(t, ""+
		"# HELP msdos_file_access_time_seconds A \"quoted\" help with a \\\\ backslash\\nand a line feed.\n"+
		"# TYPE msdos_file_access_time_seconds gauge\n"+
		`msdos_file_access_time_seconds{path="C:\\DIR\\FILE.TXT",error="Cannot find file:\n\"FILE.TXT\""} 1.458255915e+09`+"\n",
		scrape(t, reg))
}

// The specification's histogram: cumulative buckets in ascending order, each counting the
// observations at or below its bound, ending in +Inf, then _sum and _count. 0.5 and 1 are
// observed exactly on a bound, which belongs to that bucket and not the next.
func TestExposition_AHistogram(t *testing.T) {
	reg := metrics.NewRegistry()
	duration := reg.Histogram("http_request_duration_seconds", "A histogram of the request duration.",
		[]float64{0.05, 0.1, 0.2, 0.5, 1})

	for _, v := range []float64{0.03125, 0.0625, 0.25, 0.5, 1, 3} {
		duration.Observe(v)
	}

	assert.Equal(t, ""+
		"# HELP http_request_duration_seconds A histogram of the request duration.\n"+
		"# TYPE http_request_duration_seconds histogram\n"+
		"http_request_duration_seconds_bucket{le=\"0.05\"} 1\n"+
		"http_request_duration_seconds_bucket{le=\"0.1\"} 2\n"+
		"http_request_duration_seconds_bucket{le=\"0.2\"} 2\n"+
		"http_request_duration_seconds_bucket{le=\"0.5\"} 4\n"+
		"http_request_duration_seconds_bucket{le=\"1\"} 5\n"+
		"http_request_duration_seconds_bucket{le=\"+Inf\"} 6\n"+
		"http_request_duration_seconds_sum 4.84375\n"+
		"http_request_duration_seconds_count 6\n",
		scrape(t, reg))
}

// A labeled histogram writes le after its own labels, and each series carries its own buckets,
// sum and count.
func TestExposition_AHistogramWithLabels(t *testing.T) {
	reg := metrics.NewRegistry()
	duration := reg.Histogram("job_seconds", "How long a job took.", []float64{1, 2.5},
		metrics.Enum("job", "mail", "cleanup"))

	duration.Observe(0.5, "mail")
	duration.Observe(2, "cleanup")
	duration.Observe(7, "cleanup")

	assert.Equal(t, ""+
		"# HELP job_seconds How long a job took.\n"+
		"# TYPE job_seconds histogram\n"+
		"job_seconds_bucket{job=\"cleanup\",le=\"1\"} 0\n"+
		"job_seconds_bucket{job=\"cleanup\",le=\"2.5\"} 1\n"+
		"job_seconds_bucket{job=\"cleanup\",le=\"+Inf\"} 2\n"+
		"job_seconds_sum{job=\"cleanup\"} 9\n"+
		"job_seconds_count{job=\"cleanup\"} 2\n"+
		"job_seconds_bucket{job=\"mail\",le=\"1\"} 1\n"+
		"job_seconds_bucket{job=\"mail\",le=\"2.5\"} 1\n"+
		"job_seconds_bucket{job=\"mail\",le=\"+Inf\"} 1\n"+
		"job_seconds_sum{job=\"mail\"} 0.5\n"+
		"job_seconds_count{job=\"mail\"} 1\n",
		scrape(t, reg))
}

// Families are written in name order whatever order they were registered in. An unlabeled
// counter, gauge or histogram is a series from the start and reads zero; a labeled family nobody
// has recorded in has no series yet, and still says what it is.
func TestExposition_FamiliesInNameOrderAndUnrecordedFamilies(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.Histogram("c_seconds", "C.", []float64{1})
	reg.Counter("b_total", "B.", metrics.Enum("kind", "x"))
	reg.Gauge("a_value", "A.")
	reg.Counter("a_total", "A total.")

	assert.Equal(t, ""+
		"# HELP a_total A total.\n"+
		"# TYPE a_total counter\n"+
		"a_total 0\n"+
		"# HELP a_value A.\n"+
		"# TYPE a_value gauge\n"+
		"a_value 0\n"+
		"# HELP b_total B.\n"+
		"# TYPE b_total counter\n"+
		"# HELP c_seconds C.\n"+
		"# TYPE c_seconds histogram\n"+
		"c_seconds_bucket{le=\"1\"} 0\n"+
		"c_seconds_bucket{le=\"+Inf\"} 0\n"+
		"c_seconds_sum 0\n"+
		"c_seconds_count 0\n",
		scrape(t, reg))
}

// A gauge goes down as well as up, and Set replaces what Add accumulated.
func TestExposition_GaugeAddAndSet(t *testing.T) {
	reg := metrics.NewRegistry()
	inFlight := reg.Gauge("jobs_in_flight", "Jobs running.", metrics.Enum("class", "mail", "notice"))
	last := reg.Gauge("last_run_seconds", "The last run's duration.")

	inFlight.Add(1, "mail")
	inFlight.Add(1, "mail")
	inFlight.Add(-1, "mail")
	inFlight.Add(-1, "notice")
	last.Add(5)
	last.Set(0.25)

	assert.Equal(t, ""+
		"# HELP jobs_in_flight Jobs running.\n"+
		"# TYPE jobs_in_flight gauge\n"+
		"jobs_in_flight{class=\"mail\"} 1\n"+
		"jobs_in_flight{class=\"notice\"} -1\n"+
		"# HELP last_run_seconds The last run's duration.\n"+
		"# TYPE last_run_seconds gauge\n"+
		"last_run_seconds 0.25\n",
		scrape(t, reg))
}

// A gauge read at scrape time reports what its function returns then, not when it was
// registered.
func TestExposition_AGaugeReadAtScrapeTime(t *testing.T) {
	reg := metrics.NewRegistry()
	value := 1.0
	reg.GaugeFunc("pool_size", "The pool's size.", func() float64 { return value })

	value = 42

	assert.Equal(t, ""+
		"# HELP pool_size The pool's size.\n"+
		"# TYPE pool_size gauge\n"+
		"pool_size 42\n",
		scrape(t, reg))
}

// A counter read at scrape time reports the count something else keeps, as the connection pool
// keeps its waits, and says it is a counter.
func TestExposition_ACounterReadAtScrapeTime(t *testing.T) {
	reg := metrics.NewRegistry()
	waits := int64(0)
	reg.CounterFunc("pool_waits_total", "Waits for a connection.", func() float64 { return float64(waits) })

	waits = 7

	assert.Equal(t, ""+
		"# HELP pool_waits_total Waits for a connection.\n"+
		"# TYPE pool_waits_total counter\n"+
		"pool_waits_total 7\n",
		scrape(t, reg))
}

// A labeled family read at scrape time writes the samples its function reports then, in the order
// of their label values whatever order they were reported in. Its labels hold to their declared
// sets as a recorded family's do: a value outside the set is written as other, and two samples
// that land on one series are added, so a read can no more grow a family past its sets than a
// request can.
func TestExposition_LabeledFamiliesReadAtScrapeTime(t *testing.T) {
	reg := metrics.NewRegistry()
	inUse, idle := 1.0, 1.0
	reg.GaugeVecFunc("pool_connections", "Connections by state.", func() []metrics.Sample {
		return []metrics.Sample{
			{Value: idle, LabelValues: []string{"idle"}},
			{Value: inUse, LabelValues: []string{"in_use"}},
		}
	}, metrics.Enum("state", "in_use", "idle"))
	reg.CounterVecFunc("pool_closed_total", "Connections closed by reason.", func() []metrics.Sample {
		return []metrics.Sample{
			{Value: 3, LabelValues: []string{"max_lifetime"}},
			{Value: 2, LabelValues: []string{"max_idle"}},
			{Value: 4, LabelValues: []string{"a reason nobody declared"}},
			{Value: 5, LabelValues: []string{"another"}},
		}
	}, metrics.Enum("reason", "max_idle", "max_lifetime"))

	inUse, idle = 4, 0

	assert.Equal(t, ""+
		"# HELP pool_closed_total Connections closed by reason.\n"+
		"# TYPE pool_closed_total counter\n"+
		"pool_closed_total{reason=\"max_idle\"} 2\n"+
		"pool_closed_total{reason=\"max_lifetime\"} 3\n"+
		"pool_closed_total{reason=\"other\"} 9\n"+
		"# HELP pool_connections Connections by state.\n"+
		"# TYPE pool_connections gauge\n"+
		"pool_connections{state=\"idle\"} 0\n"+
		"pool_connections{state=\"in_use\"} 4\n",
		scrape(t, reg))
}

func TestExposition_SpecialValues(t *testing.T) {
	reg := metrics.NewRegistry()
	g := reg.Gauge("special", "Special values.", metrics.Enum("which", "inf", "neg", "small"))

	g.Set(posInf(), "inf")
	g.Set(-posInf(), "neg")
	g.Set(0.000001, "small")

	body := scrape(t, reg)

	assert.Contains(t, body, "special{which=\"inf\"} +Inf\n")
	assert.Contains(t, body, "special{which=\"neg\"} -Inf\n")
	assert.Contains(t, body, "special{which=\"small\"} 1e-06\n")
}

func posInf() float64 {
	zero := 0.0
	return 1 / zero
}

// The handler writes the same exposition whatever the request asked for beyond reaching it;
// routing, and refusing every other path, is the metrics listener's mux.
func TestHandler_HEADCarriesTheContentType(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.Counter("a_total", "A.")

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/metrics", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", rec.Header().Get("Content-Type"))
}

// lines returns the exposition lines starting with prefix, which is how a test reads one family
// out of a scrape holding several.
func lines(body, prefix string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}
