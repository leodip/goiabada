package guard

// Seam: the rule table checkMetricsCatalog enforces, over a real metrics.Registry and a fixture
// Monitoring page written into a temp tree, read through the same functions the server tiers use.
// The page that holds the real catalog is written by the server slices; here the committed fixture
// under testdata is the pair that must pass through the exported wrapper, so the case the tiers
// will run is exercised end to end before either server registers a family (#400 decision 4).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

const fakeMonitoringPage = "site/monitoring.mdx"

var fakeCatalogLines = []string{
	"---",
	"title: Monitoring",
	"---",
	"",
	"Every metric either server exposes.",
	"",
	"| metric | type | labels | server | meaning |",
	"|---|---|---|---|---|",
	"| `goiabada_http_requests_total` | counter | `route`: the route table, `unmatched`; `method`: `GET`, `POST` | both | Requests answered. |",
	"| `goiabada_tokens_issued_total` | counter | `grant_type`: `authorization_code`, `refresh_token` | auth server | Tokens issued. |",
	"| `goiabada_settings_cache_requests_total` | counter | `result`: `hit`, `miss` | admin console | Cache lookups. |",
	"| `go_goroutines` | gauge | none | both | Goroutines. |",
	"",
	"A table that is not the catalog is not read:",
	"",
	"| alert | expression |",
	"|---|---|",
	"| `goiabada_not_a_metric` | rate(x[5m]) |",
}

func fakeCatalog() string { return strings.Join(fakeCatalogLines, "\n") + "\n" }

// fakeAuthServerFamilies registers what the fixture page says the auth server exposes.
func fakeAuthServerFamilies() []metrics.Family {
	reg := metrics.NewRegistry()
	reg.Counter("goiabada_http_requests_total", "Requests.",
		metrics.Described("route", "the route table, `unmatched`", "/health", "unmatched"),
		metrics.Enum("method", "GET", "POST"))
	reg.Counter("goiabada_tokens_issued_total", "Tokens.",
		metrics.Enum("grant_type", "authorization_code", "refresh_token"))
	reg.GaugeFunc("go_goroutines", "Goroutines.", func() float64 { return 1 })
	return reg.Families()
}

// writeCatalogFixture writes page at fakeMonitoringPage under a fresh root and returns the root.
// An empty page leaves the file absent.
func writeCatalogFixture(t *testing.T, page string) string {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "site"), 0o755))
	if page != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, fakeMonitoringPage), []byte(page), 0o600))
	}
	return root
}

// replaceCatalogLine returns the fixture page with the one line holding substr replaced.
func replaceCatalogLine(t *testing.T, substr, with string) string {
	t.Helper()

	out := make([]string, 0, len(fakeCatalogLines))
	replaced := 0
	for _, line := range fakeCatalogLines {
		if strings.Contains(line, substr) {
			replaced++
			if with == "" {
				continue
			}
			line = with
		}
		out = append(out, line)
	}
	require.Equal(t, 1, replaced, "the fixture must hold exactly one line containing %q", substr)
	return strings.Join(out, "\n") + "\n"
}

func checkFake(t *testing.T, page string, families []metrics.Family) []metricsCatalogFinding {
	t.Helper()

	findings, err := checkMetricsCatalog(writeCatalogFixture(t, page), fakeMonitoringPage, "auth server", families)
	require.NoError(t, err)
	return findings
}

// A pair the guard must accept. The console's row is not the auth server's to register, and the
// table of alerts below the catalog is not read.
func TestCheckMetricsCatalog_AcceptsAPageThatMatchesTheRegistry(t *testing.T) {
	assert.Empty(t, checkFake(t, fakeCatalog(), fakeAuthServerFamilies()))
}

// The direction the rule is mostly about: a new family fails until the docs describe it, and the
// finding carries the row to add.
func TestCheckMetricsCatalog_AFamilyWithNoRow(t *testing.T) {
	findings := checkFake(t, replaceCatalogLine(t, "goiabada_tokens_issued_total", ""), fakeAuthServerFamilies())

	require.Len(t, findings, 1)
	assert.Equal(t, "goiabada_tokens_issued_total", findings[0].Metric)
	assert.Contains(t, findings[0].Reason, "no row")
	assert.Contains(t, findings[0].Reason,
		"| `goiabada_tokens_issued_total` | counter | `grant_type`: `authorization_code`, `refresh_token` | auth server |")
}

// A family the code stopped registering, or one documented and never written.
func TestCheckMetricsCatalog_ARowWithNoFamily(t *testing.T) {
	var families []metrics.Family
	for _, family := range fakeAuthServerFamilies() {
		if family.Name != "goiabada_http_requests_total" {
			families = append(families, family)
		}
	}

	findings := checkFake(t, fakeCatalog(), families)

	require.Len(t, findings, 1)
	assert.Equal(t, "goiabada_http_requests_total", findings[0].Metric)
	assert.Contains(t, findings[0].Reason, "does not register")
}

func TestCheckMetricsCatalog_LabelDrift(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		{"a type the code does not declare",
			"| `go_goroutines` | counter | none | both | Goroutines. |",
			"counter"},
		{"a label the docs leave out",
			"| `goiabada_http_requests_total` | counter | `route`: the route table, `unmatched` | both | Requests answered. |",
			"`method`"},
		{"a label the code does not declare",
			"| `go_goroutines` | gauge | `pod`: the pod's name | both | Goroutines. |",
			"`pod`"},
		{"a value the docs leave out",
			"| `goiabada_tokens_issued_total` | counter | `grant_type`: `authorization_code` | auth server | Tokens issued. |",
			"refresh_token"},
		{"a value the code does not declare",
			"| `goiabada_tokens_issued_total` | counter | `grant_type`: `authorization_code`, `refresh_token`, `password` | auth server | Tokens issued. |",
			"password"},
		{"a described set the docs describe otherwise",
			"| `goiabada_http_requests_total` | counter | `route`: the request path; `method`: `GET`, `POST` | both | Requests answered. |",
			"the request path"},
		{"a described set the docs list instead",
			"| `goiabada_http_requests_total` | counter | `route`: `/health`, `unmatched`; `method`: `GET`, `POST` | both | Requests answered. |",
			"the route table"},
		{"a listed set the docs describe instead",
			"| `goiabada_tokens_issued_total` | counter | `grant_type`: the grant types | auth server | Tokens issued. |",
			"the grant types"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metric := strings.Trim(strings.Fields(tc.line)[1], "`")
			findings := checkFake(t, replaceCatalogLine(t, "| `"+metric+"` |", tc.line), fakeAuthServerFamilies())

			require.Len(t, findings, 1, "%v", findings)
			assert.Equal(t, metric, findings[0].Metric)
			assert.Contains(t, findings[0].Reason, tc.want)
		})
	}
}

// One metric, one row per server: a `both` row and an `auth server` row for the same name would
// leave a reader not knowing which one the auth server is held to.
func TestCheckMetricsCatalog_TwoRowsForOneMetric(t *testing.T) {
	page := replaceCatalogLine(t, "| `go_goroutines` |",
		"| `go_goroutines` | gauge | none | both | Goroutines. |\n| `go_goroutines` | gauge | none | auth server | Again. |")

	findings := checkFake(t, page, fakeAuthServerFamilies())

	require.Len(t, findings, 1)
	assert.Equal(t, "go_goroutines", findings[0].Metric)
	assert.Contains(t, findings[0].Reason, "2 rows")
}

// The ways the comparison can be meaningless, each an error rather than a finding, because every
// per-family check would otherwise pass vacuously or read the wrong thing.
func TestCheckMetricsCatalog_MeaninglessComparisonsAreErrors(t *testing.T) {
	cases := []struct {
		name     string
		page     string
		server   string
		families []metrics.Family
		want     string
	}{
		{"the page is absent", "", "auth server", fakeAuthServerFamilies(), "monitoring.mdx"},
		{"the page has no catalog table", "# Monitoring\n\n| alert | expression |\n|---|---|\n", "auth server",
			fakeAuthServerFamilies(), "no catalog table"},
		{"the page has two", fakeCatalog() + "\n" + fakeCatalog(), "auth server", fakeAuthServerFamilies(),
			"2 catalog tables"},
		{"the registry is empty", fakeCatalog(), "auth server", nil, "no families"},
		{"a server nobody runs", fakeCatalog(), "worker", fakeAuthServerFamilies(), `"worker"`},
		{"a row with a cell missing",
			replaceCatalogLine(t, "| `go_goroutines` |", "| `go_goroutines` | gauge | none | Goroutines. |"),
			"auth server", fakeAuthServerFamilies(), "4 cells"},
		{"a row naming a type Prometheus has not",
			replaceCatalogLine(t, "| `go_goroutines` |", "| `go_goroutines` | meter | none | both | Goroutines. |"),
			"auth server", fakeAuthServerFamilies(), `"meter"`},
		{"a row naming a server nobody runs",
			replaceCatalogLine(t, "| `go_goroutines` |", "| `go_goroutines` | gauge | none | everyone | Goroutines. |"),
			"auth server", fakeAuthServerFamilies(), `"everyone"`},
		{"a label cell that cannot be read",
			replaceCatalogLine(t, "| `go_goroutines` |", "| `go_goroutines` | gauge | pod | both | Goroutines. |"),
			"auth server", fakeAuthServerFamilies(), `"pod"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := checkMetricsCatalog(writeCatalogFixture(t, tc.page), fakeMonitoringPage, tc.server, tc.families)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("a table with no row for this server", func(t *testing.T) {
		page := strings.Join([]string{
			"| metric | type | labels | server | meaning |",
			"|---|---|---|---|---|",
			"| `goiabada_settings_cache_requests_total` | counter | `result`: `hit`, `miss` | admin console | Cache lookups. |",
		}, "\n") + "\n"

		_, err := checkMetricsCatalog(writeCatalogFixture(t, page), fakeMonitoringPage, "auth server", fakeAuthServerFamilies())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no row for the auth server")
	})
}

// The reporting half, driven the way the real caller drives it.
func TestAssertMetricsCatalog_ReportingHalf(t *testing.T) {
	t.Run("findings reach Errorf", func(t *testing.T) {
		root := writeCatalogFixture(t, replaceCatalogLine(t, "goiabada_tokens_issued_total", ""))

		report := Run(func(r Reporter) {
			assertMetricsCatalog(r, root, fakeMonitoringPage, "auth server", fakeAuthServerFamilies())
		})

		assert.True(t, report.Failed())
		assert.False(t, report.Stopped, "a family with no row is a finding, not a reason to stop")
		assert.Len(t, report.Errors, 1)
		assert.Contains(t, report.Text(), "goiabada_tokens_issued_total")
	})

	t.Run("a comparison that cannot be made is fatal", func(t *testing.T) {
		root := writeCatalogFixture(t, "")

		report := Run(func(r Reporter) {
			assertMetricsCatalog(r, root, fakeMonitoringPage, "auth server", fakeAuthServerFamilies())
		})

		assert.True(t, report.Stopped, "an absent page must stop the test, not pass it")
		assert.Contains(t, report.Fatal, "monitoring.mdx")
	})

	t.Run("a matching pair says nothing", func(t *testing.T) {
		root := writeCatalogFixture(t, fakeCatalog())

		report := Run(func(r Reporter) {
			assertMetricsCatalog(r, root, fakeMonitoringPage, "auth server", fakeAuthServerFamilies())
		})

		assert.False(t, report.Failed())
	})
}

// The exported wrapper, as a server's tier will call it, over the committed fixture page, which
// it resolves from the repository root.
func TestAssertMetricsCatalog_TheCommittedFixturePasses(t *testing.T) {
	AssertMetricsCatalog(t, "src/core/guard/testdata/metrics_catalog.mdx", "auth server", fakeAuthServerFamilies())
}

func TestMetricsCatalogFixture_IsTheRuleTestsPage(t *testing.T) {
	committed, err := os.ReadFile("testdata/metrics_catalog.mdx")
	require.NoError(t, err)

	assert.Equal(t, fakeCatalog(), string(committed),
		"testdata/metrics_catalog.mdx is the page the rule tests build; regenerate it from fakeCatalogLines")
}
