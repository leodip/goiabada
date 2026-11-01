package oauthclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
)

// The token grants and the JWKS fetch refuse a redirect from the auth server (#715 decision 13):
// a 307 or 308 used to be followed with the grant's body and its Authorization, and a 301 turned
// the grant into a GET. Each fails instead, naming the target's origin and the internal URL
// setting, and sends nothing to the target.

var followedRedirects = []int{301, 302, 303, 307, 308}

// redirectingAuthServer answers every request to path with status and a Location on another host,
// and counts every request to any other path, which a followed redirect would be.
func redirectingAuthServer(t *testing.T, path string, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			followed.Add(1)
			return
		}
		w.Header().Set("Location", "https://auth.example.com:8443/path-marker?query-marker=1")
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, &followed
}

func assertRefusedRedirect(t *testing.T, err error, status int) {
	t.Helper()
	require.Error(t, err)
	var refused *noredirect.Error
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, status, refused.StatusCode)
	assert.Equal(t, "https://auth.example.com:8443", refused.Origin)
	assert.Contains(t, err.Error(), "https://auth.example.com:8443")
	assert.Contains(t, err.Error(), "GOIABADA_AUTHSERVER_INTERNALBASEURL")
	assert.NotContains(t, err.Error(), "path-marker")
	assert.NotContains(t, err.Error(), "query-marker")
	var endpointErr *TokenEndpointError
	assert.NotErrorAs(t, err, &endpointErr, "a redirect is not the token endpoint's own answer")
}

func TestTokenClient_RefusesARedirect(t *testing.T) {
	for _, status := range followedRedirects {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, followed := redirectingAuthServer(t, "/auth/token", status)
			client := NewTokenClient(TokenEndpointURL(server.URL), "ci", "cs", NewAuthServerHTTPClient(nil), nil)

			_, err := client.ClientCredentials(context.Background(), "authserver:manage")
			assertRefusedRedirect(t, err, status)
			_, err = client.ExchangeCode(context.Background(), "the-code", "https://console.example.com/auth/callback", "the-verifier")
			assertRefusedRedirect(t, err, status)
			_, err = client.Refresh(context.Background(), "the-refresh-token")
			assertRefusedRedirect(t, err, status)

			assert.Zero(t, followed.Load(), "nothing is sent to the redirect's target")
		})
	}
}

// A token client built with no HTTP client of its own refuses as well.
func TestTokenClient_WithItsOwnHTTPClientRefusesARedirect(t *testing.T) {
	server, followed := redirectingAuthServer(t, "/auth/token", http.StatusPermanentRedirect)

	_, err := NewTokenClient(TokenEndpointURL(server.URL), "ci", "cs", nil, nil).
		ClientCredentials(context.Background(), "authserver:manage")

	assertRefusedRedirect(t, err, http.StatusPermanentRedirect)
	assert.Zero(t, followed.Load())
}

func TestJWKSTokenParser_RefusesARedirect(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	token := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	for _, status := range followedRedirects {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, followed := redirectingAuthServer(t, "/certs", status)
			// Whatever client it is handed, the default one included, and nil.
			for name, httpClient := range map[string]*http.Client{
				"the shared client": NewAuthServerHTTPClient(nil),
				"a default client":  &http.Client{},
				"none":              nil,
			} {
				t.Run(name, func(t *testing.T) {
					parser := NewJWKSTokenParser(server.URL, httpClient, nil, oauthclienttest.ClientID,
						oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

					result, err := parser.DecodeAndValidateStoredIDToken(context.Background(), token)

					assert.Nil(t, result)
					assertRefusedRedirect(t, err, status)
				})
			}
			assert.Zero(t, followed.Load(), "nothing is sent to the redirect's target")
		})
	}
}
