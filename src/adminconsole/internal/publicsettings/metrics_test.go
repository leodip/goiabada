package publicsettings

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// The settings cache's lookups and the settings client's calls, read as a scraper reads them, from
// the registry's exposition (#400 decision 6).

// scrape reads reg's exposition through its handler.
func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

// assertLookups holds the exposition to hits and misses. A series nothing was recorded in is not
// written, so a count of zero is its absence.
func assertLookups(t *testing.T, reg *metrics.Registry, hits, misses int) {
	t.Helper()

	exposition := scrape(t, reg)
	for result, want := range map[string]int{"hit": hits, "miss": misses} {
		series := `goiabada_settings_cache_requests_total{result="` + result + `"} `
		if want == 0 {
			assert.NotContains(t, exposition, series)
			continue
		}
		assert.Contains(t, exposition, series+strconv.Itoa(want)+"\n")
	}
}

// A lookup a fresh value answers is a hit; one that found none, the first, one after the TTL, one
// after an invalidation and one after a failure, is a miss.
func TestCache_CountsEachLookupAsAHitOrAMiss(t *testing.T) {
	refused := errors.New("the auth server is down")
	fetcher := newFakeFetcher(
		fetchAnswer{appName: "first"},
		fetchAnswer{err: refused},
		fetchAnswer{appName: "back"},
	)
	reg := metrics.NewRegistry()
	cache := NewCache(fetcher, time.Hour, reg)

	appNameOf(t, cache) // miss: nothing cached
	appNameOf(t, cache) // hit
	appNameOf(t, cache) // hit
	cache.Invalidate()
	_, err := cache.Get(context.Background()) // miss: invalidated, and the fetch fails
	require.ErrorIs(t, err, refused)
	appNameOf(t, cache) // miss: a failure is not cached
	appNameOf(t, cache) // hit

	assertLookups(t, reg, 3, 3)
}

// An expired value is a miss, though one was cached.
func TestCache_AnExpiredValueIsAMiss(t *testing.T) {
	fetcher := newFakeFetcher(fetchAnswer{appName: "first"}, fetchAnswer{appName: "second"})
	reg := metrics.NewRegistry()
	cache := NewCache(fetcher, time.Millisecond, reg)

	appNameOf(t, cache)
	time.Sleep(10 * time.Millisecond)
	appNameOf(t, cache)

	assertLookups(t, reg, 0, 2)
}

// A request that joins the fetch in flight found no fresh value either, so it is a miss though it
// started no fetch: nine misses for one fetch.
func TestCache_ALookupJoiningAFetchInFlightIsAMiss(t *testing.T) {
	release := make(chan struct{})
	fetcher := newFakeFetcher(fetchAnswer{appName: "shared", release: release})
	reg := metrics.NewRegistry()
	cache := NewCache(fetcher, time.Hour, reg)

	first := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)
	var others []<-chan getResult
	for range 8 {
		others = append(others, getAsync(cache, context.Background()))
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	for _, results := range append(others, first) {
		require.NoError(t, await(t, results, "a waiter").err)
	}
	require.Equal(t, 1, fetcher.fetches())

	assertLookups(t, reg, 0, 9)
}

// The client's calls are recorded under the settings target and the status the auth server
// answered, a refusal included.
func TestClient_RecordsItsCallsUnderTheSettingsTarget(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"appName":"Goiabada"}`))
	}))
	defer server.Close()

	reg := metrics.NewRegistry()
	client := NewClient(server.URL, upstreammetrics.Register(reg))

	_, err := client.GetPublicSettings(context.Background())
	require.NoError(t, err)
	status = http.StatusBadGateway
	_, err = client.GetPublicSettings(context.Background())
	require.Error(t, err)

	exposition := scrape(t, reg)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="settings",status="200"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="settings",status="502"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="settings"} 2`+"\n")
}
