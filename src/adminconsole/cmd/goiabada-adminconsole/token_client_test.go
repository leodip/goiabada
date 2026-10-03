package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	coreconstants "github.com/leodip/goiabada/core/constants"
)

// The one token client main builds, and hands to both the session token source and the server,
// reaches the token endpoint at its canonical path under the effective (internal) base URL with
// or without a trailing slash, as the admin console's client with the configured secret (#441).
func TestNewTokenClient_ReachesTheTokenEndpointUnderTheEffectiveBaseURL(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		t.Run("suffix "+suffix, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			var clientID, clientSecret string
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				paths = append(paths, r.URL.Path)
				clientID, clientSecret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"at","expires_in":3600}`))
			}))
			t.Cleanup(peer.Close)

			cfg := &config.Config{
				AdminConsole: config.AdminConsoleConfig{OAuthClientSecret: "the-secret"},
				AuthServer: config.AuthServerConfig{
					BaseURL:         "https://auth.example.test",
					InternalBaseURL: peer.URL + suffix,
				},
			}
			_, err := newTokenClient(cfg, nil).ClientCredentials(context.Background(), "a-scope")
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, []string{"/auth/token"}, paths)
			assert.Equal(t, coreconstants.AdminConsoleClientIdentifier, clientID)
			assert.Equal(t, "the-secret", clientSecret)
		})
	}
}
