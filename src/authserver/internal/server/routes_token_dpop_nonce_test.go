package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/dpop"
)

// Every answer to a DPoP request at the token endpoint carries exactly one fresh DPoP-Nonce and is
// no-store, the answers written ahead of the handler included (RFC 9449 sections 8 and 8.2, #42
// decision 7): the ROPC limiter's 400 for a form that does not parse, with the limiter on or off,
// and its 429. Driven through the real routes and middleware.

// assertRoutedFreshNonce checks rr carries exactly one DPoP-Nonce the routes test server's nonces
// accept now, and is not stored by a cache.
func assertRoutedFreshNonce(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	values := rr.Header().Values("DPoP-Nonce")
	require.Len(t, values, 1, "exactly one DPoP-Nonce header")
	assert.True(t, dpop.NewNonces([]byte("a session authentication key for the tests")).Accepts(values[0], time.Now()))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
}

func TestInitRoutes_ADPoPTokenRequestRefusedBeforeTheHandlerCarriesANonce(t *testing.T) {
	for limiter, enabled := range map[string]bool{"on": true, "off": false} {
		t.Run("a form that does not parse, the limiter "+limiter, func(t *testing.T) {
			server := newRoutesTestServerWith(t, func(cfg *config.Config) { cfg.AuthServer.RateLimiterEnabled = enabled })
			r := browserForm(http.MethodPost, "/auth/token", "grant_type=client_credentials&broken=%zz")
			r.Header.Set("DPoP", "a-proof-not-read-because-the-form-does-not-parse")

			rr := serve(server, r)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "invalid_request", body["error"])
			assertRoutedFreshNonce(t, rr)
		})
	}

	t.Run("the limiter's 429", func(t *testing.T) {
		server := newRoutesTestServer(t)
		noPassword := func(attempt int) *http.Request {
			r := browserForm(http.MethodPost, "/auth/token", "grant_type=password&client_id="+routesTestROPCClientId+
				"&username=user"+strconv.Itoa(attempt)+"%40example.com")
			if attempt == pwdIpCeiling {
				r.Header.Set("DPoP", "a-proof-not-read-because-the-limiter-refuses")
			}
			return r
		}

		rr := exhaust(t, server, pwdIpCeiling, noPassword)

		assertRefused(t, rr, pwdIpWindow, shapeOAuth)
		assertRoutedFreshNonce(t, rr)
	})

	t.Run("a request without a DPoP header carries no nonce", func(t *testing.T) {
		server := newRoutesTestServer(t)
		rr := serve(server, browserForm(http.MethodPost, "/auth/token", "grant_type=client_credentials&broken=%zz"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Empty(t, rr.Header().Values("DPoP-Nonce"))
	})
}
