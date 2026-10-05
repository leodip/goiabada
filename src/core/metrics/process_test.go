package metrics_test

// Seam: the build-info and runtime gauges as a scrape reports them.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/metrics"
)

// The stamp is the one the release build writes with -ldflags -X, so the test writes it the same
// way, by assigning the variables, and puts them back.
func TestRegisterBuildInfo_ReportsThisBinarysStamp(t *testing.T) {
	version, commit := buildinfo.Version, buildinfo.GitCommit
	t.Cleanup(func() { buildinfo.Version, buildinfo.GitCommit = version, commit })
	buildinfo.Version, buildinfo.GitCommit = "1.4.0", "353810a8"

	reg := metrics.NewRegistry()
	metrics.RegisterBuildInfo(reg)

	assert.Equal(t, ""+
		"# HELP goiabada_build_info The version and commit this binary was built from, always 1.\n"+
		"# TYPE goiabada_build_info gauge\n"+
		"goiabada_build_info{version=\"1.4.0\",commit=\"353810a8\"} 1\n",
		scrape(t, reg))

	families := reg.Families()
	require.Len(t, families, 1)
	require.Len(t, families[0].Labels, 2)
	assert.Equal(t, "this binary's version", families[0].Labels[0].Description())
	assert.Equal(t, []string{"1.4.0"}, families[0].Labels[0].Values())
	assert.Equal(t, "this binary's commit", families[0].Labels[1].Description())
	assert.Equal(t, []string{"353810a8"}, families[0].Labels[1].Values())
}

// A docker build without its build arguments stamps the empty string, which the registry refuses
// with a panic, so an empty stamp reads unknown rather than stopping the server at start.
func TestRegisterBuildInfo_AnEmptyStampReadsUnknown(t *testing.T) {
	version, commit := buildinfo.Version, buildinfo.GitCommit
	t.Cleanup(func() { buildinfo.Version, buildinfo.GitCommit = version, commit })

	for name, stamp := range map[string]struct{ version, commit, want string }{
		"commit":  {"1.4.0", "", `goiabada_build_info{version="1.4.0",commit="unknown"} 1`},
		"version": {"", "353810a8", `goiabada_build_info{version="unknown",commit="353810a8"} 1`},
		"both":    {"", "", `goiabada_build_info{version="unknown",commit="unknown"} 1`},
	} {
		t.Run(name, func(t *testing.T) {
			buildinfo.Version, buildinfo.GitCommit = stamp.version, stamp.commit
			reg := metrics.NewRegistry()
			require.NotPanics(t, func() { metrics.RegisterBuildInfo(reg) })
			assert.Contains(t, scrape(t, reg), stamp.want+"\n")
		})
	}
}

// The two runtime gauges carry the names Go dashboards already read, and are read at scrape time.
func TestRegisterRuntime_ReportsGoroutinesAndHeapInUse(t *testing.T) {
	reg := metrics.NewRegistry()
	metrics.RegisterRuntime(reg)

	body := scrape(t, reg)

	assert.Contains(t, body, "# TYPE go_goroutines gauge\n")
	assert.Contains(t, body, "# TYPE go_memstats_heap_inuse_bytes gauge\n")
	assert.Positive(t, sampleValue(t, body, "go_goroutines"))
	assert.Positive(t, sampleValue(t, body, "go_memstats_heap_inuse_bytes"))

	for _, family := range reg.Families() {
		assert.Equal(t, "gauge", family.Type, family.Name)
		assert.Empty(t, family.Labels, family.Name)
	}
}

// sampleValue returns the value of the one unlabeled sample named name.
func sampleValue(t *testing.T, body, name string) float64 {
	t.Helper()

	found := lines(body, name+" ")
	require.Len(t, found, 1, "one %s sample", name)
	v, err := strconv.ParseFloat(strings.TrimPrefix(found[0], name+" "), 64)
	require.NoError(t, err)
	return v
}
