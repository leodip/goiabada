package adminuserhandlers

import (
	"sync"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
)

// phoneCountriesCache holds cached phone countries data with TTL
var phoneCountriesCache struct {
	data      []api.PhoneCountryResponse
	timestamp time.Time
	mutex     sync.RWMutex
}

const phoneCountriesCacheTTL = 24 * time.Hour

// getPhoneCountriesWithCache retrieves phone countries from cache or API
func getPhoneCountriesWithCache(apiClient apiclient.ApiClient, accessToken string) ([]api.PhoneCountryResponse, error) {
	// Try to read from cache first
	phoneCountriesCache.mutex.RLock()
	if time.Since(phoneCountriesCache.timestamp) < phoneCountriesCacheTTL && phoneCountriesCache.data != nil {
		defer phoneCountriesCache.mutex.RUnlock()
		return phoneCountriesCache.data, nil
	}
	phoneCountriesCache.mutex.RUnlock()

	// Cache miss or expired - fetch from API
	data, err := apiClient.GetPhoneCountries(accessToken)
	if err != nil {
		return nil, err
	}

	// Update cache
	phoneCountriesCache.mutex.Lock()
	phoneCountriesCache.data = data
	phoneCountriesCache.timestamp = time.Now()
	phoneCountriesCache.mutex.Unlock()

	return data, nil
}
