package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9110 section 9.1 has a general-purpose server support GET and HEAD, and section 9.3.2 has a
// HEAD answered as the GET would be, with the same header fields and no content. The static files,
// the favicon and /health answered HEAD with 405 until #542's live check. It runs over a real
// listener, because net/http's server is what drops a HEAD's content, which a recorder does not.
func TestRegisterRoutes_TheReadOnlyResourcesAnswerHeadAsGetDoes(t *testing.T) {
	s := newStaticBranchTestServer(newFailingSettingsServer(t).URL, newTestSessionStore())
	s.templateFS = web.TemplateFS()
	s.registerRoutes()
	listener := httptest.NewServer(s.router)
	defer listener.Close()

	do := func(method, path string) (*http.Response, []byte) {
		req, err := http.NewRequestWithContext(context.Background(), method, listener.URL+path, nil)
		require.NoError(t, err)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp, body
	}

	for _, path := range []string{"/static/main.css", "/static", "/favicon.ico", "/health"} {
		t.Run(path, func(t *testing.T) {
			get, _ := do(http.MethodGet, path)
			head, body := do(http.MethodHead, path)

			assert.Equal(t, get.StatusCode, head.StatusCode, "a HEAD gets the GET's status")
			for _, name := range []string{"Content-Type", "Cache-Control", "Last-Modified", "Location", "Vary"} {
				assert.Equalf(t, get.Header.Get(name), head.Header.Get(name), "the HEAD's %s is the GET's", name)
			}
			// RFC 9110 section 8.6: a HEAD MAY carry Content-Length, and MUST NOT unless it is the
			// length the GET's content would have had.
			if length := head.Header.Get("Content-Length"); length != "" {
				assert.Equal(t, get.Header.Get("Content-Length"), length)
			}
			assert.Empty(t, body, "a HEAD has no content")
		})
	}

	// A page stays GET-only: 405, with an Allow that doesn't name HEAD (RFC 9110 section 15.5.6).
	head, _ := do(http.MethodHead, "/unauthorized")
	assert.Equal(t, http.StatusMethodNotAllowed, head.StatusCode)
	assert.NotContains(t, strings.Split(strings.ReplaceAll(head.Header.Get("Allow"), " ", ""), ","), http.MethodHead)
}
