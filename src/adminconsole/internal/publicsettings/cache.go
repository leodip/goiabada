// Package publicsettings is how the admin console learns the auth server's public settings: the
// application name, the UI theme, whether SMTP is configured, and the issuer the console checks its
// own tokens' iss claim against. Client reads them from the auth server's unauthenticated
// /api/public/settings, and Cache keeps them for a TTL so that every page, which needs them before
// it renders, does not ask the auth server again. Every request arriving while a fetch is in flight
// shares that one fetch, no lock is held across it, and an Invalidate, which a settings save calls,
// is never undone by a fetch that started before it. It was internal/cache, and the client was
// apiclient.SettingsClient, until #441.
package publicsettings

import (
	"context"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/metrics"
)

// DefaultTTL is how long a fetched value is served before the next request asks again. A settings
// save through this console invalidates the cache at once, so the TTL bounds only how long a change
// made elsewhere, through the auth server's admin API, takes to reach the console's pages.
const DefaultTTL = 30 * time.Second

// fetcher is what the cache needs of the auth server: the settings, read once. Client is the
// production one.
type fetcher interface {
	GetPublicSettings(ctx context.Context) (*api.PublicSettingsResponse, error)
}

// flight is one fetch in progress, and its result once done is closed.
type flight struct {
	done     chan struct{}
	settings *api.PublicSettingsResponse
	err      error
}

// Cache serves the public settings for a TTL. A failure is not cached and an expired value is not
// served.
//
// The mutex guards the fields below it and is only ever held to read or update them, never across
// the fetch: until #441 it was held across the HTTP call, so while the auth server hung every page
// load queued behind the one ahead of it, each for up to the client's timeout (decision 4).
type Cache struct {
	fetch fetcher
	ttl   time.Duration
	// requests counts every Get by whether it found a fresh value (#400 decision 6).
	requests *metrics.Counter

	mu        sync.Mutex
	settings  *api.PublicSettingsResponse
	fetchedAt time.Time
	// generation counts invalidations. A fetch stores what it read only when the generation it
	// started under is still current, so a fetch already in flight when a save invalidates the
	// cache cannot put the settings from before the save back.
	generation uint64
	// inFlight is the fetch requests arriving now wait on, or nil when none is. Invalidate clears
	// it as well, so the request after a save starts a fetch of its own.
	inFlight *flight
}

// The result label's two values: a request answered from a fresh value, and one that found none.
const (
	resultHit  = "hit"
	resultMiss = "miss"
)

// NewCache builds a cache over fetch, serving each value it reads for ttl, and registers
// goiabada_settings_cache_requests_total on reg, which counts its lookups by result.
func NewCache(fetch fetcher, ttl time.Duration, reg *metrics.Registry) *Cache {
	return &Cache{
		fetch: fetch,
		ttl:   ttl,
		requests: reg.Counter("goiabada_settings_cache_requests_total",
			"Lookups of the auth server's public settings, by whether a fresh cached value answered them.",
			metrics.Enum("result", resultHit, resultMiss)),
	}
}

// Get returns the cached settings, or waits on a fetch when they are expired or absent: the one in
// flight if there is one, else one it starts. The fetch is detached from ctx's cancellation,
// keeping its values, because it is shared by every request that arrives while it runs and is no
// one caller's to abandon; the client's own timeout bounds it. What ctx's end does is end this
// caller's wait, with ctx's error.
//
// Every call is counted once: a hit when a fresh value answers it, and a miss otherwise, whether it
// starts the fetch or joins the one in flight (#400 decision 6).
func (c *Cache) Get(ctx context.Context) (*api.PublicSettingsResponse, error) {
	c.mu.Lock()
	if c.settings != nil && time.Since(c.fetchedAt) < c.ttl {
		settings := c.settings
		c.mu.Unlock()
		c.requests.Inc(resultHit)
		return settings, nil
	}
	c.requests.Inc(resultMiss)
	f := c.inFlight
	if f == nil {
		f = &flight{done: make(chan struct{})}
		c.inFlight = f
		go c.run(context.WithoutCancel(ctx), f, c.generation)
	}
	c.mu.Unlock()

	select {
	case <-f.done:
		return f.settings, f.err
	case <-ctx.Done():
		return nil, errs.Wrap(ctx.Err(), "the request ended while waiting for the public settings")
	}
}

// run makes one fetch for f and publishes its result to every waiter. It stores the settings only
// when the fetch succeeded and no Invalidate landed since it started.
func (c *Cache) run(ctx context.Context, f *flight, generation uint64) {
	settings, err := c.fetch.GetPublicSettings(ctx)

	c.mu.Lock()
	if err == nil && c.generation == generation {
		c.settings = settings
		c.fetchedAt = time.Now()
	}
	if c.inFlight == f {
		c.inFlight = nil
	}
	f.settings, f.err = settings, err
	c.mu.Unlock()

	close(f.done)
}

// Invalidate empties the cache, so the next Get fetches. A fetch in flight still answers the
// requests already waiting on it, but stores nothing and is joined by no request after this.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.settings = nil
	c.fetchedAt = time.Time{}
	c.generation++
	c.inFlight = nil
}
