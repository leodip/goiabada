package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/core/builtin"
)

// The one token client main builds, and hands to both the session token source and the server,
// reaches the token endpoint at its canonical path under the effective (internal) base URL with
// or without a trailing slash, as the admin console's client with the configured secret, which
// every grant now authenticates as Basic rather than in the body (#474).
func TestNewTokenClient_ReachesTheTokenEndpointUnderTheEffectiveBaseURL(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		t.Run("suffix "+suffix, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			var authorization string
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				paths = append(paths, r.URL.Path)
				authorization = r.Header.Get("Authorization")
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
			_, err := newTokenClient(cfg, nil, nil).ClientCredentials(context.Background(), "a-scope")
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, []string{"/auth/token"}, paths)
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
			require.NoError(t, err, "a Basic header, the credentials base64'd")
			id, secret, ok := strings.Cut(string(decoded), ":")
			require.True(t, ok, "the identifier and the secret, joined by one colon")
			assert.Equal(t, builtin.AdminConsoleClientIdentifier, id)
			assert.Equal(t, "the-secret", secret)
		})
	}
}
