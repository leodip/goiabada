package metrics_test

// Seam: what a registry declares and what a scrape of it reports. The label rule is the point of
// the package (#400 decision 4): every label takes values from a set declared when its metric is
// registered, and a value outside the set is recorded as other, so no input can grow a family past
// the product of its sets.

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

func TestLabels_AValueOutsideTheDeclaredSetIsRecordedAsOther(t *testing.T) {
	reg := metrics.NewRegistry()
	refused := reg.Counter("refusals_total", "Refusals.",
		metrics.Enum("grant_type", "authorization_code", "refresh_token"),
		metrics.Enum("error", "invalid_grant", "invalid_client"))

	refused.Inc("authorization_code", "invalid_grant")
	refused.Inc("urn:ietf:params:oauth:grant-type:device_code", "invalid_grant")
	refused.Inc("authorization_code", "a description someone typed")
	refused.Inc("Authorization_Code", "invalid_grant")

	assert.Equal(t, []string{
		`refusals_total{grant_type="authorization_code",error="invalid_grant"} 1`,
		`refusals_total{grant_type="authorization_code",error="other"} 1`,
		`refusals_total{grant_type="other",error="invalid_grant"} 2`,
	}, lines(scrape(t, reg), "refusals_total{"))
}

// The bound the rule exists for: a thousand distinct inputs, as an attacker minting client
// identifiers would send, produce one series, not a thousand.
func TestLabels_DistinctInputsOutsideTheSetShareOneSeries(t *testing.T) {
	reg := metrics.NewRegistry()
	c := reg.Counter("seen_total", "Seen.", metrics.Enum("kind", "known"))

	for i := 0; i < 1000; i++ {
		c.Inc(fmt.Sprintf("client-%d", i))
	}

	assert.Equal(t, []string{`seen_total{kind="other"} 1000`}, lines(scrape(t, reg), "seen_total{"))
}

// "other" declared in the set is an ordinary member, and a value outside the set joins it.
func TestLabels_OtherMayBeDeclared(t *testing.T) {
	reg := metrics.NewRegistry()
	c := reg.Counter("x_total", "X.", metrics.Enum("kind", "a", "other"))

	c.Inc("other")
	c.Inc("zzz")
	c.Inc("a")

	assert.Equal(t, []string{`x_total{kind="a"} 1`, `x_total{kind="other"} 2`}, lines(scrape(t, reg), "x_total{"))
}

// Families is what the catalog check reads: each family's name, type and help, and each label's
// name, its value set and, for a set the catalog describes rather than lists, the description.
func TestRegistry_FamiliesDescribesWhatWasDeclared(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.Histogram("b_seconds", "B.", []float64{1}, metrics.Described("status", "the response's status code", "200", "404"))
	reg.Counter("a_total", "A.", metrics.Enum("kind", "x", "y"))
	reg.GaugeFunc("c_value", "C.", func() float64 { return 0 })
	reg.CounterFunc("d_total", "D.", func() float64 { return 0 })
	reg.GaugeVecFunc("e_value", "E.", func() []metrics.Sample { return nil }, metrics.Enum("state", "in_use", "idle"))
	reg.CounterVecFunc("f_total", "F.", func() []metrics.Sample { return nil }, metrics.Enum("reason", "max_idle"))

	families := reg.Families()

	require.Len(t, families, 6)
	assert.Equal(t, "a_total", families[0].Name)
	assert.Equal(t, "counter", families[0].Type)
	assert.Equal(t, "A.", families[0].Help)
	require.Len(t, families[0].Labels, 1)
	assert.Equal(t, "kind", families[0].Labels[0].Name())
	assert.Empty(t, families[0].Labels[0].Description())
	assert.Equal(t, []string{"x", "y"}, families[0].Labels[0].Values())

	assert.Equal(t, "b_seconds", families[1].Name)
	assert.Equal(t, "histogram", families[1].Type)
	require.Len(t, families[1].Labels, 1)
	assert.Equal(t, "status", families[1].Labels[0].Name())
	assert.Equal(t, "the response's status code", families[1].Labels[0].Description())
	assert.Equal(t, []string{"200", "404"}, families[1].Labels[0].Values())

	assert.Equal(t, "c_value", families[2].Name)
	assert.Equal(t, "gauge", families[2].Type)
	assert.Empty(t, families[2].Labels)

	assert.Equal(t, "d_total", families[3].Name)
	assert.Equal(t, "counter", families[3].Type)
	assert.Empty(t, families[3].Labels)

	assert.Equal(t, "e_value", families[4].Name)
	assert.Equal(t, "gauge", families[4].Type)
	require.Len(t, families[4].Labels, 1)
	assert.Equal(t, "state", families[4].Labels[0].Name())
	assert.Equal(t, []string{"in_use", "idle"}, families[4].Labels[0].Values())

	assert.Equal(t, "f_total", families[5].Name)
	assert.Equal(t, "counter", families[5].Type)
	require.Len(t, families[5].Labels, 1)
	assert.Equal(t, []string{"max_idle"}, families[5].Labels[0].Values())
}

// Each refusal is a programming error at a composition root, made once at startup, so it panics
// there rather than reaching a scrape as a family Prometheus cannot read.
func TestRegistry_RefusesWhatCannotBeExposed(t *testing.T) {
	cases := []struct {
		name     string
		register func(reg *metrics.Registry)
	}{
		{"a name registered twice", func(reg *metrics.Registry) {
			reg.Counter("dup_total", "A.")
			reg.Gauge("dup_total", "B.")
		}},
		{"a metric name Prometheus cannot read", func(reg *metrics.Registry) { reg.Counter("http-requests", "A.") }},
		{"a metric name starting with a digit", func(reg *metrics.Registry) { reg.Counter("1_total", "A.") }},
		{"a label name Prometheus cannot read", func(reg *metrics.Registry) {
			reg.Counter("a_total", "A.", metrics.Enum("grant-type", "x"))
		}},
		{"a label name Prometheus reserves", func(reg *metrics.Registry) {
			reg.Counter("a_total", "A.", metrics.Enum("__name__", "x"))
		}},
		{"a label declared twice", func(reg *metrics.Registry) {
			reg.Counter("a_total", "A.", metrics.Enum("kind", "x"), metrics.Enum("kind", "y"))
		}},
		{"a label with no values", func(reg *metrics.Registry) { reg.Counter("a_total", "A.", metrics.Enum("kind")) }},
		{"a value declared twice", func(reg *metrics.Registry) {
			reg.Counter("a_total", "A.", metrics.Enum("kind", "x", "x"))
		}},
		{"an empty value", func(reg *metrics.Registry) { reg.Counter("a_total", "A.", metrics.Enum("kind", "")) }},
		{"a described label with no description", func(reg *metrics.Registry) {
			reg.Counter("a_total", "A.", metrics.Described("kind", "", "x"))
		}},
		{"le on a histogram", func(reg *metrics.Registry) {
			reg.Histogram("a_seconds", "A.", []float64{1}, metrics.Enum("le", "x"))
		}},
		{"a histogram with no buckets", func(reg *metrics.Registry) { reg.Histogram("a_seconds", "A.", nil) }},
		{"buckets out of order", func(reg *metrics.Registry) { reg.Histogram("a_seconds", "A.", []float64{1, 0.5}) }},
		{"a bucket repeated", func(reg *metrics.Registry) { reg.Histogram("a_seconds", "A.", []float64{1, 1}) }},
		{"an empty help", func(reg *metrics.Registry) { reg.Counter("a_total", "") }},
		{"a gauge read at scrape time with nothing to read", func(reg *metrics.Registry) { reg.GaugeFunc("a_value", "A.", nil) }},
		{"a counter read at scrape time with nothing to read", func(reg *metrics.Registry) { reg.CounterFunc("a_total", "A.", nil) }},
		{"a labeled gauge read at scrape time with nothing to read", func(reg *metrics.Registry) {
			reg.GaugeVecFunc("a_value", "A.", nil, metrics.Enum("kind", "x"))
		}},
		{"a labeled counter read at scrape time with nothing to read", func(reg *metrics.Registry) {
			reg.CounterVecFunc("a_total", "A.", nil, metrics.Enum("kind", "x"))
		}},
		{"a labeled family read at scrape time with a label with no values", func(reg *metrics.Registry) {
			reg.CounterVecFunc("a_total", "A.", func() []metrics.Sample { return nil }, metrics.Enum("kind"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, func() { tc.register(metrics.NewRegistry()) })
		})
	}
}

func TestRegistry_RefusesARecordThatCannotBeRight(t *testing.T) {
	reg := metrics.NewRegistry()
	c := reg.Counter("a_total", "A.", metrics.Enum("kind", "x"), metrics.Enum("other_kind", "y"))
	plain := reg.Counter("plain_total", "Plain.")

	assert.Panics(t, func() { c.Inc("x") }, "one value for two labels")
	assert.Panics(t, func() { c.Inc("x", "y", "z") }, "three values for two labels")
	assert.Panics(t, func() { plain.Inc("x") }, "a value for an unlabeled counter")
	assert.Panics(t, func() { plain.Add(-1) }, "a counter only goes up")
}

// A read reporting a sample whose label values do not match the labels declared is the same
// programming error as a record that does, and is refused the same way.
func TestRegistry_RefusesASampleThatCannotBeRight(t *testing.T) {
	for _, values := range [][]string{nil, {"x", "y"}} {
		reg := metrics.NewRegistry()
		reg.GaugeVecFunc("a_value", "A.", func() []metrics.Sample {
			return []metrics.Sample{{Value: 1, LabelValues: values}}
		}, metrics.Enum("kind", "x"))

		assert.Panics(t, func() { scrape(t, reg) }, "%d values for one label", len(values))
	}
}

// Concurrent recording is a locking argument, which the race tier is where it is checked; here it
// is also counted, so a lost update shows as a wrong total under the plain tier too.
func TestRegistry_ConcurrentRecording(t *testing.T) {
	reg := metrics.NewRegistry()
	c := reg.Counter("hits_total", "Hits.", metrics.Enum("kind", "a", "b"))
	g := reg.Gauge("level", "Level.")
	h := reg.Histogram("wait_seconds", "Wait.", []float64{1}, metrics.Enum("kind", "a", "b"))

	const workers, each = 16, 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			kind := []string{"a", "b"}[w%2]
			for i := 0; i < each; i++ {
				c.Inc(kind)
				g.Add(0.5)
				h.Observe(0.5, kind)
				if i%100 == 0 {
					_ = reg.Families()
				}
			}
		}(w)
	}
	// A scrape racing the writers is part of what the race tier checks.
	_ = scrape(t, reg)
	wg.Wait()

	body := scrape(t, reg)
	assert.Contains(t, body, "hits_total{kind=\"a\"} 4000\n")
	assert.Contains(t, body, "hits_total{kind=\"b\"} 4000\n")
	assert.Contains(t, body, "level 4000\n")
	assert.Contains(t, body, "wait_seconds_count{kind=\"a\"} 4000\n")
	assert.Contains(t, body, "wait_seconds_bucket{kind=\"b\",le=\"+Inf\"} 4000\n")
	assert.Equal(t, 1, strings.Count(body, "# TYPE hits_total counter"))
}
