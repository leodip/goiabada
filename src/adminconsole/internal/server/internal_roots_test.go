package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The route table builds the admin API client from the root pool NewServer was handed, and the
// JWKS fetch goes through the HTTP client NewServer was handed, so both verify the auth server's
// certificate against the internal roots main read (#525). The auth server is served under a
// certificate the system roots do not hold, which only the pool trusts: a signed-in
// administrator's request to a page that calls the admin API must pass the JWT middleware, which
// verifies the ID token against the JWKS it fetches, and then reach the admin API. A route table
// building the admin API client with nil, or a server dropping the pool it was handed, sends that
// call under the system roots alone, and the auth server never sees it.
func TestInitRoutes_TheJWKSFetchAndTheAdminAPIVerifyAgainstTheInternalRoots(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	s, cookies := newSignedInConsoleOverTLS(t, "openid authserver:manage-account", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/account/sessions", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	s.router.ServeHTTP(rec, req)

	exposition := scrape(t, s)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="jwks",status="200"} 1`+"\n",
		"the JWKS fetch verified the auth server's certificate against the internal roots")
	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, asked, "/api/v1/account/sessions",
		"the admin API client reached the auth server under the internal roots; the page answered %d", rec.Code)
	assert.Equal(t, http.StatusOK, rec.Code, "the page renders from the admin API's answer")
}
