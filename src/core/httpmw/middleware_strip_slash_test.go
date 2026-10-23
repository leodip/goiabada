package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// One trailing slash is stripped before routing, so a route answers its path with one slash after
// it as it answers its path. The handler reads the stripped path off the request it is handed,
// where chi's StripSlashes wrote it only to its routing context (#462).
func TestStripTrailingSlash(t *testing.T) {
	for _, test := range []struct {
		target, path, rawPath, escaped string
	}{
		{"/health/", "/health", "", "/health"},
		{"/health", "/health", "", "/health"},
		{"/", "/", "", "/"},
		{"/health//", "/health/", "", "/health/"},
		{"/auth/authorize/?client_id=c", "/auth/authorize", "", "/auth/authorize"},
		// A path holding an escape keeps its raw form, stripped as the decoded one is.
		{"/api/v1/admin/users/a%2Fb/", "/api/v1/admin/users/a/b", "/api/v1/admin/users/a%2Fb", "/api/v1/admin/users/a%2Fb"},
	} {
		t.Run(test.target, func(t *testing.T) {
			var seen *http.Request
			handler := StripTrailingSlash(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = r
			}))
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			assert.Equal(t, test.path, seen.URL.Path)
			assert.Equal(t, test.rawPath, seen.URL.RawPath)
			assert.Equal(t, test.escaped, seen.URL.EscapedPath())
			assert.Equal(t, test.target, seen.RequestURI, "the target as it arrived is kept")
		})
	}
}

// The query survives the strip.
func TestStripTrailingSlash_KeepsTheQuery(t *testing.T) {
	var seen *http.Request
	StripTrailingSlash(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize/?client_id=c&state=s", nil))

	assert.Equal(t, "client_id=c&state=s", seen.URL.RawQuery)
}
