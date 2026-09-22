package cache

import (
	"context"
	"sync"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
)

const (
	cacheTTL = 30 * time.Second
)

type SettingsCache struct {
	client     *apiclient.SettingsClient
	mu         sync.RWMutex
	cachedData *api.PublicSettingsResponse
	cachedAt   time.Time
}

func NewSettingsCache(authServerBaseURL string) *SettingsCache {
	return &SettingsCache{
		client: apiclient.NewSettingsClient(authServerBaseURL),
	}
}

// Get returns the cached settings or fetches them if the cache is expired or empty.
// The context is the originating request's and reaches the auth server call a cache miss makes.
func (c *SettingsCache) Get(ctx context.Context) (*api.PublicSettingsResponse, error) {
	c.mu.RLock()
	// Check if cache is valid
	if c.cachedData != nil && time.Since(c.cachedAt) < cacheTTL {
		data := c.cachedData
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Cache is expired or empty, fetch new data
	return c.fetchAndCache(ctx)
}

// Invalidate clears the cache, forcing a fresh fetch on the next Get()
func (c *SettingsCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cachedData = nil
	c.cachedAt = time.Time{}
}

// fetchAndCache fetches settings from the authserver and caches them
func (c *SettingsCache) fetchAndCache(ctx context.Context) (*api.PublicSettingsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine might have fetched while we were waiting for the lock
	if c.cachedData != nil && time.Since(c.cachedAt) < cacheTTL {
		return c.cachedData, nil
	}

	// Fetch from authserver
	settings, err := c.client.GetPublicSettings(ctx)
	if err != nil {
		return nil, err
	}

	// Update cache
	c.cachedData = settings
	c.cachedAt = time.Now()

	return settings, nil
}
