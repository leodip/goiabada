package cache

import (
	"sync"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/dtos"
)

const (
	cacheTTL = 30 * time.Second
)

type SettingsCache struct {
	client       *apiclient.SettingsClient
	mu           sync.RWMutex
	cachedData   *dtos.PublicSettingsResponse
	cachedAt     time.Time
	lastFetchErr error
}

func NewSettingsCache(authServerBaseURL string) *SettingsCache {
	return &SettingsCache{
		client: apiclient.NewSettingsClient(authServerBaseURL),
	}
}

// Get returns the cached settings or fetches them if the cache is expired or empty
func (c *SettingsCache) Get() (*dtos.PublicSettingsResponse, error) {
	c.mu.RLock()
	// Check if cache is valid
	if c.cachedData != nil && time.Since(c.cachedAt) < cacheTTL {
		data := c.cachedData
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Cache is expired or empty, fetch new data
	return c.fetchAndCache()
}

// Invalidate clears the cache, forcing a fresh fetch on the next Get()
func (c *SettingsCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cachedData = nil
	c.cachedAt = time.Time{}
	c.lastFetchErr = nil
}

// fetchAndCache fetches settings from the authserver and caches them
func (c *SettingsCache) fetchAndCache() (*dtos.PublicSettingsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine might have fetched while we were waiting for the lock
	if c.cachedData != nil && time.Since(c.cachedAt) < cacheTTL {
		return c.cachedData, nil
	}

	// Fetch from authserver
	settings, err := c.client.GetPublicSettings()
	if err != nil {
		c.lastFetchErr = err
		return nil, err
	}

	// Update cache
	c.cachedData = settings
	c.cachedAt = time.Now()
	c.lastFetchErr = nil

	return settings, nil
}
