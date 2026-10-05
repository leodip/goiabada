package publicsettings

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cache over a fake fetcher, its seam since #441: it had no test before, and every page the
// console serves reads the settings through it. The fetcher is the one thing faked, because it is
// the call that crosses to the auth server; what is asserted is what a caller of Get sees, and how
// many times the auth server would have been asked.

// patience bounds every wait in this file. A case that waits this long has failed: the behavior it
// waits for takes microseconds, and the bound only turns a hang into a failure that names itself.
const patience = 2 * time.Second

// fetchAnswer is what one fetch answers. A non-nil release holds the fetch until it is closed,
// which is how a case puts a fetch in flight and keeps it there.
type fetchAnswer struct {
	appName string
	err     error
	release chan struct{}
}

// fakeFetcher answers the n-th fetch with answers[n], and the last answer for every fetch past the
// end of the script. Each fetch announces itself on started as it begins.
type fakeFetcher struct {
	answers []fetchAnswer
	started chan int

	mu    sync.Mutex
	calls int
	ctxs  []context.Context
}

func newFakeFetcher(answers ...fetchAnswer) *fakeFetcher {
	return &fakeFetcher{answers: answers, started: make(chan int, 64)}
}

func (f *fakeFetcher) GetPublicSettings(ctx context.Context) (*api.PublicSettingsResponse, error) {
	f.mu.Lock()
	call := f.calls
	f.calls++
	f.ctxs = append(f.ctxs, ctx)
	answer := f.answers[min(call, len(f.answers)-1)]
	f.mu.Unlock()

	f.started <- call

	if answer.release != nil {
		<-answer.release
	}
	if answer.err != nil {
		return nil, answer.err
	}
	return &api.PublicSettingsResponse{AppName: answer.appName, Issuer: "https://auth.example.com"}, nil
}

func (f *fakeFetcher) fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeFetcher) fetchContext(call int) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctxs[call]
}

// awaitFetchStart waits for the next fetch to begin.
func (f *fakeFetcher) awaitFetchStart(t *testing.T) {
	t.Helper()

	select {
	case <-f.started:
	case <-time.After(patience):
		t.Fatal("no fetch began")
	}
}

type getResult struct {
	settings *api.PublicSettingsResponse
	err      error
}

// getAsync runs Get on its own goroutine, as a request would.
func getAsync(c *Cache, ctx context.Context) <-chan getResult {
	out := make(chan getResult, 1)
	go func() {
		settings, err := c.Get(ctx)
		out <- getResult{settings: settings, err: err}
	}()
	return out
}

func await(t *testing.T, results <-chan getResult, what string) getResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(patience):
		t.Fatalf("%s did not return", what)
		return getResult{}
	}
}

func appNameOf(t *testing.T, c *Cache) string {
	t.Helper()

	settings, err := c.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, settings)
	return settings.AppName
}

func TestCache_AHitWithinTheTTLDoesNotFetchAgain(t *testing.T) {
	fetcher := newFakeFetcher(fetchAnswer{appName: "first"}, fetchAnswer{appName: "second"})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	assert.Equal(t, "first", appNameOf(t, cache))
	assert.Equal(t, "first", appNameOf(t, cache), "the cached value, not a second fetch's")
	assert.Equal(t, 1, fetcher.fetches())
}

// An expired value is not served: the next Get asks the auth server again and answers with what it
// says now.
func TestCache_AnExpiredValueIsFetchedAgain(t *testing.T) {
	fetcher := newFakeFetcher(fetchAnswer{appName: "first"}, fetchAnswer{appName: "second"})
	cache := NewCache(fetcher, time.Millisecond, metrics.NewRegistry())

	assert.Equal(t, "first", appNameOf(t, cache))
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, "second", appNameOf(t, cache))
	assert.Equal(t, 2, fetcher.fetches())
}

func TestCache_InvalidateForcesAFetchOnTheNextGet(t *testing.T) {
	fetcher := newFakeFetcher(fetchAnswer{appName: "before the save"}, fetchAnswer{appName: "after the save"})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	assert.Equal(t, "before the save", appNameOf(t, cache))
	cache.Invalidate()
	assert.Equal(t, "after the save", appNameOf(t, cache))
	assert.Equal(t, 2, fetcher.fetches())
}

// A failure is answered to the caller and not kept: the request after it asks again, so an auth
// server that comes back serves the next page.
func TestCache_AFailureIsNotCached(t *testing.T) {
	refused := errors.New("the auth server is down")
	fetcher := newFakeFetcher(fetchAnswer{err: refused}, fetchAnswer{appName: "back"})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	settings, err := cache.Get(context.Background())
	assert.ErrorIs(t, err, refused)
	assert.Nil(t, settings)

	assert.Equal(t, "back", appNameOf(t, cache))
	assert.Equal(t, 2, fetcher.fetches())
}

// Decision 4: every request arriving during a fetch waits on that one fetch, so against a hung auth
// server concurrent page loads fail together at the client's timeout instead of queueing behind
// each other's.
func TestCache_ConcurrentMissesShareOneFetch(t *testing.T) {
	release := make(chan struct{})
	fetcher := newFakeFetcher(fetchAnswer{appName: "shared", release: release})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	first := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)

	var others []<-chan getResult
	for range 8 {
		others = append(others, getAsync(cache, context.Background()))
	}
	// Long enough for the eight to reach the cache. One that arrives late finds the value cached
	// and fetches nothing either, so the wait can only make this case pass for the right reason.
	time.Sleep(50 * time.Millisecond)
	close(release)

	for i, results := range append(others, first) {
		result := await(t, results, "a waiter")
		require.NoError(t, result.err, "waiter %d", i)
		assert.Equal(t, "shared", result.settings.AppName, "waiter %d", i)
	}
	assert.Equal(t, 1, fetcher.fetches(), "one fetch for every miss that arrived during it")
}

// The shared fetch's failure reaches every waiter on it, and is still not cached.
func TestCache_ConcurrentMissesShareOneFailure(t *testing.T) {
	release := make(chan struct{})
	refused := errors.New("the auth server is down")
	fetcher := newFakeFetcher(fetchAnswer{err: refused, release: release}, fetchAnswer{appName: "back"})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	first := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)
	second := getAsync(cache, context.Background())
	time.Sleep(50 * time.Millisecond)
	close(release)

	assert.ErrorIs(t, await(t, first, "the first waiter").err, refused)
	assert.ErrorIs(t, await(t, second, "the second waiter").err, refused)
	assert.Equal(t, 1, fetcher.fetches())

	assert.Equal(t, "back", appNameOf(t, cache))
}

// Decision 4: each waiter stops waiting when its own request ends, and the fetch, which is no one
// caller's, carries on for the others. The cancelled caller here is the one that started the
// fetch, which is the case a fetch on the caller's own context would get wrong: cancelling it
// would fail every request waiting behind it.
func TestCache_AWaiterWhoseRequestEndsStopsWaitingWhileTheFetchServesTheOthers(t *testing.T) {
	release := make(chan struct{})
	fetcher := newFakeFetcher(fetchAnswer{appName: "served", release: release})
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	leaving := getAsync(cache, ctx)
	fetcher.awaitFetchStart(t)
	staying := getAsync(cache, context.Background())

	cancel()
	left := await(t, leaving, "the waiter whose request ended")
	assert.ErrorIs(t, left.err, context.Canceled)
	assert.Nil(t, left.settings)

	assert.NoError(t, fetcher.fetchContext(0).Err(),
		"the fetch must not end with the request that started it")

	select {
	case <-staying:
		t.Fatal("the other waiter returned before the fetch did")
	default:
	}

	close(release)
	stayed := await(t, staying, "the waiter whose request goes on")
	require.NoError(t, stayed.err)
	assert.Equal(t, "served", stayed.settings.AppName)

	assert.Equal(t, "served", appNameOf(t, cache), "what the fetch read is cached for the next request")
	assert.Equal(t, 1, fetcher.fetches())
}

// Decision 4: a fetch that started before an Invalidate cannot store what it read. Invalidate is
// what a settings save calls once the auth server has accepted it, so the fetch in flight read the
// settings from before the save, and storing them would serve the old values for a whole TTL.
func TestCache_AnInvalidateDuringAFetchIsNotUndoneByIt(t *testing.T) {
	release := make(chan struct{})
	fetcher := newFakeFetcher(
		fetchAnswer{appName: "before the save", release: release},
		fetchAnswer{appName: "after the save"},
	)
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	inFlight := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)

	invalidated := make(chan struct{})
	go func() {
		cache.Invalidate()
		close(invalidated)
	}()
	select {
	case <-invalidated:
	case <-time.After(patience):
		t.Fatal("Invalidate waited on the fetch in flight; no lock is held across the call")
	}

	close(release)
	result := await(t, inFlight, "the waiter on the earlier fetch")
	require.NoError(t, result.err)
	assert.Equal(t, "before the save", result.settings.AppName,
		"a request that arrived before the save is answered with what its fetch read")

	assert.Equal(t, "after the save", appNameOf(t, cache), "the cache was left empty, so this read fetched")
	assert.Equal(t, 2, fetcher.fetches())
}

// A request arriving after an Invalidate does not join the fetch that started before it: that
// fetch read the settings from before the save, and the redirect after a save is exactly the
// request that must see the saved values.
func TestCache_AGetAfterAnInvalidateDoesNotJoinTheEarlierFetch(t *testing.T) {
	release := make(chan struct{})
	fetcher := newFakeFetcher(
		fetchAnswer{appName: "before the save", release: release},
		fetchAnswer{appName: "after the save"},
	)
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	inFlight := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)

	invalidated := make(chan struct{})
	go func() {
		cache.Invalidate()
		close(invalidated)
	}()
	select {
	case <-invalidated:
	case <-time.After(patience):
		t.Fatal("Invalidate waited on the fetch in flight; no lock is held across the call")
	}

	after := await(t, getAsync(cache, context.Background()), "the request after the save")
	require.NoError(t, after.err)
	assert.Equal(t, "after the save", after.settings.AppName)

	close(release)
	await(t, inFlight, "the waiter on the earlier fetch")
	assert.Equal(t, "after the save", appNameOf(t, cache),
		"the earlier fetch, ending last, did not overwrite the later one's value")
	assert.Equal(t, 2, fetcher.fetches())
}

// The earlier fetch, ending while the later one is still in flight, leaves the later one where it
// is: a request arriving then joins the fetch that started after the save rather than starting a
// third, which against a slow auth server is the queue decision 4 exists to end.
func TestCache_AnEarlierFetchEndingLeavesTheLaterOneShared(t *testing.T) {
	releaseEarlier := make(chan struct{})
	releaseLater := make(chan struct{})
	fetcher := newFakeFetcher(
		fetchAnswer{appName: "before the save", release: releaseEarlier},
		fetchAnswer{appName: "after the save", release: releaseLater},
		fetchAnswer{appName: "a third fetch"},
	)
	cache := NewCache(fetcher, time.Hour, metrics.NewRegistry())

	earlier := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)
	cache.Invalidate()
	later := getAsync(cache, context.Background())
	fetcher.awaitFetchStart(t)

	close(releaseEarlier)
	await(t, earlier, "the waiter on the earlier fetch")

	joining := getAsync(cache, context.Background())
	time.Sleep(50 * time.Millisecond)
	close(releaseLater)

	for _, results := range []<-chan getResult{later, joining} {
		result := await(t, results, "a waiter on the later fetch")
		require.NoError(t, result.err)
		assert.Equal(t, "after the save", result.settings.AppName)
	}
	assert.Equal(t, 2, fetcher.fetches())
}
