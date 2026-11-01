package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The five admin list pages have shared one handler name since #443, so in initRoutes only the
// package qualifier tells their registrations apart. Until #483 no test in this package reached a
// list page as a signed-in administrator, so two registrations swapped would have rendered the
// wrong page unnoticed: each handler's tests call the function directly. Each page is requested
// here through the real route table, past the whole adminAuth chain, against an auth server that
// records which admin API path it is asked for. Swapping any two registrations fails: a page that
// reaches another area's endpoint, or none, does not pass.
func TestInitRoutes_EachAdminListPageReachesItsOwnAreasEndpoint(t *testing.T) {
	var peerMu sync.Mutex
	var peerPaths []string
	s, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, r *http.Request) {
		peerMu.Lock()
		peerPaths = append(peerPaths, r.URL.Path)
		peerMu.Unlock()
		_, _ = w.Write([]byte("{}"))
	})

	adminPages := []struct {
		path     string
		endpoint string
	}{
		{"/admin/clients", "/api/v1/admin/clients"},
		{"/admin/resources", "/api/v1/admin/resources"},
		{"/admin/groups", "/api/v1/admin/groups"},
		{"/admin/users", "/api/v1/admin/users/search"},
		{"/admin/legal-documents", "/api/v1/admin/legal-documents"},
	}

	for _, page := range adminPages {
		peerMu.Lock()
		peerPaths = nil
		peerMu.Unlock()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, page.path, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		s.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "GET %s as a signed-in administrator", page.path)

		peerMu.Lock()
		asked := append([]string(nil), peerPaths...)
		peerMu.Unlock()
		require.Contains(t, asked, page.endpoint, "GET %s asks the admin API for", page.path)
		for _, other := range adminPages {
			if other.endpoint == page.endpoint {
				continue
			}
			assert.NotContains(t, asked, other.endpoint, "GET %s asks the admin API for", page.path)
		}
	}
}
