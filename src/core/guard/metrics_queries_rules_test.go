package guard

// Seam: the queries a Monitoring page shows, read through assertMetricsQueries against a fixture
// page written into a temp tree, the same function the real page is checked with. The catalog the
// fixture holds is the one each server tier holds to its registry, so a query this accepts selects
// series a server writes (#400 decision 9).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real Monitoring page: every metric it names is in its catalog, and every alert and query it
// suggests selects, compares and groups only by what the families carry, so none of them is an
// alert that cannot fire.
func TestMonitoringPage_QueriesNameOnlyWhatTheCatalogDeclares(t *testing.T) {
	assertMetricsQueries(t, filepath.Dir(SourceRoot(t)), "site/src/content/docs/production-deployment/monitoring.mdx")
}

var queriesCatalogLines = []string{
	"| metric | type | labels | server | meaning |",
	"|---|---|---|---|---|",
	"| `goiabada_http_requests_total` | counter | `route`: the route table, `unmatched`; `method`: `GET`, `POST`; `status`: the response's status code | both | Requests. |",
	"| `goiabada_http_request_duration_seconds` | histogram | `route`: the route table, `unmatched` | both | Latency. |",
	"| `goiabada_cleanup_runs_total` | counter | `outcome`: `completed`, `failed`, `interrupted` | auth server | Runs. |",
	"| `goiabada_db_wait_count_total` | counter | none | auth server | Waits. |",
	"",
}

func queriesPage(body ...string) string {
	return "# Monitoring\n\n" + strings.Join(queriesCatalogLines, "\n") + "\n" + strings.Join(body, "\n") + "\n"
}

func runQueries(t *testing.T, page string) Report {
	t.Helper()
	return Run(func(r Reporter) {
		assertMetricsQueries(r, writeCatalogFixture(t, page), fakeMonitoringPage)
	})
}

// A page whose every query selects what the families carry: a described label with any value, a
// listed one with its own, a pattern left alone, a histogram's buckets by `le`, the labels a scrape
// adds, and a grouping that spans the block.
func TestMetricsQueries_APageThatSelectsWhatTheFamiliesCarryPasses(t *testing.T) {
	report := runQueries(t, queriesPage(
		"Watch `goiabada_db_wait_count_total` and `goiabada_http_request_duration_seconds_sum`, and",
		"`sum by (outcome) (goiabada_cleanup_runs_total{outcome=\"failed\"})` in prose.",
		"",
		"```promql",
		`sum by (route) (rate(goiabada_http_requests_total{route="/auth/token", method="POST", status=~"5.."}[5m]))`,
		`histogram_quantile(0.99, sum by (le, pod) (rate(goiabada_http_request_duration_seconds_bucket{route!="unmatched", le="1"}[5m])))`,
		"```",
		"",
		"```yaml",
		"- alert: GoiabadaCleanup",
		"  expr: |",
		`    increase(goiabada_cleanup_runs_total{outcome=~"failed|interrupted", job="goiabada"}[1d]) > 0`,
		`    or on (instance) goiabada_cleanup_runs_total{outcome="completed"} == 0`,
		"  annotations:",
		"    summary: '{{ $labels.pod }} has not cleaned up'",
		"```",
		"",
		"```bash",
		"curl localhost:9190/metrics | grep goiabada_db_wait_count_total",
		"```",
	))

	assert.False(t, report.Failed(), "a page that only selects what the families carry failed:\n%s", report.Text())
}

func TestMetricsQueries_AQueryThatCannotMatchFails(t *testing.T) {
	report := runQueries(t, queriesPage(
		"Watch `goiabada_db_waits_total`.",
		"",
		"```promql",
		`rate(goiabada_cleanup_runs_total{outcome="complete"}[1d])`,
		`rate(goiabada_cleanup_runs_total{outcome=~"failed|stopped"}[1d])`,
		`rate(goiabada_http_requests_total{path="/auth/token"}[5m])`,
		`rate(goiabada_http_requests_total{method="FOO"}[5m])`,
		`rate(goiabada_http_requests_total{le="1"}[5m])`,
		`sum by (rout) (rate(goiabada_http_requests_total[5m]))`,
		`sum by (le) (rate(goiabada_http_requests_total[5m]))`,
		`rate(goiabada_http_request_duration_seconds_buckets[5m])`,
		`rate(goiabada_db_wait_count_total{route=~".+"}[5m])`,
		"```",
		"",
		"In prose, `sum by (outcom) (goiabada_cleanup_runs_total{outcome=\"done\"})` is read as a query too.",
	))

	require.False(t, report.Stopped, "the check stopped rather than reporting: %s", report.Fatal)
	text := report.Text()
	for _, want := range []string{
		"site/monitoring.mdx:10 names `goiabada_db_waits_total`, which the catalog does not list",
		`site/monitoring.mdx:13 compares ` + "`outcome`" + ` of ` + "`goiabada_cleanup_runs_total`" + ` with "complete"`,
		`site/monitoring.mdx:14 compares ` + "`outcome`" + ` of ` + "`goiabada_cleanup_runs_total`" + ` with "stopped"`,
		"site/monitoring.mdx:15 selects `goiabada_http_requests_total` by `path`",
		`site/monitoring.mdx:16 compares ` + "`method`" + ` of ` + "`goiabada_http_requests_total`" + ` with "FOO"`,
		"site/monitoring.mdx:17 selects `goiabada_http_requests_total` by `le`",
		"site/monitoring.mdx:18 groups by `rout`",
		"site/monitoring.mdx:19 groups by `le`",
		"site/monitoring.mdx:20 names `goiabada_http_request_duration_seconds_buckets`",
		"site/monitoring.mdx:21 selects `goiabada_db_wait_count_total` by `route`",
		`site/monitoring.mdx:24 compares ` + "`outcome`" + ` of ` + "`goiabada_cleanup_runs_total`" + ` with "done"`,
		"site/monitoring.mdx:24 groups by `outcom`",
	} {
		assert.Contains(t, text, want)
	}
	assert.Len(t, report.Errors, 12, "%s", text)
}

// A page with no query, and one with no catalog, stop the check: with nothing to compare, every
// query would pass, or none would be read at all.
func TestMetricsQueries_APageWithNothingToCompareStops(t *testing.T) {
	cases := []struct{ name, page, want string }{
		{"no query block", queriesPage("Watch `goiabada_db_wait_count_total`.", "", "```bash", "curl localhost:9190/metrics", "```"), "no promql or yaml block"},
		{"no catalog", "# Monitoring\n\n```promql\nrate(goiabada_db_wait_count_total[5m])\n```\n", "no catalog table"},
		{"no page", "", "monitoring.mdx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := runQueries(t, tc.page)

			assert.True(t, report.Stopped, "the check did not stop: %s", report.Text())
			assert.Contains(t, report.Fatal, tc.want)
		})
	}
}
