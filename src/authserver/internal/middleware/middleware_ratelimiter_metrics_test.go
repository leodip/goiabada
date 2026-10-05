package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

// The rate limiter's refusals on the metrics listener (#400 decision 5): every 429 a tier answers
// is counted under that tier's name, read the way a scraper reads it.

// refusalSamples answers the sample lines of goiabada_rate_limit_refusals_total in reg's exposition.
func refusalSamples(t *testing.T, reg *metrics.Registry) []string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_rate_limit_refusals_total") {
			samples = append(samples, line)
		}
	}
	return samples
}

func TestRateLimiter_CountsEveryRefusalUnderItsLimiter(t *testing.T) {
	// Every refusal is counted, not once per key per window as the audit event is: two refused
	// requests are two.
	t.Run("a tier every request spends", func(t *testing.T) {
		m, _, reg := newMeteredTestMiddleware(nil, true)
		for i := 0; i < 32; i++ {
			runPwd(m, fmt.Sprintf("user%d@example.com", i), "198.51.100.7:5000", false)
		}

		assert.Equal(t, []string{`goiabada_rate_limit_refusals_total{limiter="pwd_ip"} 2`}, refusalSamples(t, reg))
	})

	// The failures-only tier refuses from its own gate, without a request limiter: ten failed
	// passwords against one account from one network, then the eleventh attempt is refused.
	t.Run("a tier only failures spend", func(t *testing.T) {
		m, _, reg := newMeteredTestMiddleware(nil, true)
		for i := 0; i < 10; i++ {
			runPwd(m, "victim@example.com", "198.51.100.7:5000", true)
		}
		require.Empty(t, refusalSamples(t, reg), "ten failures spend the budget and are refused nothing")

		code, reached, _ := runPwd(m, "victim@example.com", "198.51.100.7:5000", false)
		require.Equal(t, http.StatusTooManyRequests, code)
		require.False(t, reached)

		assert.Equal(t, []string{`goiabada_rate_limit_refusals_total{limiter="pwd_account_net"} 1`}, refusalSamples(t, reg))
	})

	t.Run("a request within budget is no refusal", func(t *testing.T) {
		m, _, reg := newMeteredTestMiddleware(nil, true)
		runPwd(m, "user@example.com", "198.51.100.7:5000", false)

		assert.Empty(t, refusalSamples(t, reg))
	})

	t.Run("a disabled limiter refuses nothing", func(t *testing.T) {
		m, _, reg := newMeteredTestMiddleware(nil, false)
		for i := 0; i < 40; i++ {
			runPwd(m, "x@example.com", "203.0.113.1:5000", true)
		}

		assert.Empty(t, refusalSamples(t, reg))
	})
}

// The limiter label's declared set is every tier the constructor builds, found by the walk
// TestRateLimiter_EveryTierLogsUnderAConventionalKey uses, so a new tier cannot be counted as other.
func TestRateLimiter_TheLimiterLabelIsEveryTierName(t *testing.T) {
	m, _, reg := newMeteredTestMiddleware(nil, true)

	var tiers []foundTier
	collectTierKeyFields(reflect.ValueOf(m), "middleware", &tiers, map[visitedValue]bool{})
	require.Len(t, tiers, 15, "the walk reaches every tier the constructor builds")

	var names []string
	for _, found := range tiers {
		names = append(names, found.name)
	}
	slices.Sort(names)

	var declared []string
	for _, family := range reg.Families() {
		if family.Name != "goiabada_rate_limit_refusals_total" {
			continue
		}
		require.Equal(t, "counter", family.Type)
		require.Len(t, family.Labels, 1)
		require.Equal(t, "limiter", family.Labels[0].Name())
		declared = family.Labels[0].Values()
	}
	slices.Sort(declared)

	assert.Equal(t, names, declared)
}
