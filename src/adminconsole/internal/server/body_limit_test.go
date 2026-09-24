package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin console's request-body table (bodyLimitPolicy in server.go) against the routes this
// binary really registers. core's own tests own the lookup; what is claimed here is this table and
// where it is mounted (#426).

// TestBodyLimitPolicy_NamesOnlyRegisteredRoutes: an entry naming a route that does not exist
// matches nothing, and the route it was written for silently falls to the default. Walking the
// real registrations is what catches a pattern renamed in routes.go and not here.
func TestBodyLimitPolicy_NamesOnlyRegisteredRoutes(t *testing.T) {
	s := newStaticBranchTestServer("http://127.0.0.1:1", &countingStore{})
	s.initRoutes(s.initMiddleware())

	var registered []string
	err := chi.Walk(s.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered = append(registered, method+" "+route)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, registered, "the walk must have reached the routes")

	policy := bodyLimitPolicy()
	for key := range policy.Routes {
		assert.Contains(t, registered, key, "a Routes key must be a registered method and pattern")
	}
	for prefix := range policy.Prefixes {
		covered := false
		for _, route := range registered {
			_, pattern, _ := strings.Cut(route, " ")
			covered = covered || strings.HasPrefix(pattern, prefix)
		}
		assert.True(t, covered, "the prefix %s must cover at least one registered route", prefix)
	}
}

// TestBodyLimitPolicy_EachRowAtItsBoundary sends each row's limit and one byte more through the
// real root chain, to a stub at a pattern that row governs.
func TestBodyLimitPolicy_EachRowAtItsBoundary(t *testing.T) {
	const upload = 3*1024*1024 + 64*1024

	tests := []struct {
		name    string
		pattern string
		target  string
		limit   int64
	}{
		{"the default, at the OAuth callback", "/auth/callback", "/auth/callback", 64 * 1024},
		{"an admin page", "/admin/users/{userId}/profile", "/admin/users/1/profile", 1 << 20},
		{"an account page", "/account/profile", "/account/profile", 1 << 20},
		{"the account picture upload", "/account/picture", "/account/picture", upload},
		{"the client logo upload", "/admin/clients/{clientId}/logo", "/admin/clients/1/logo", upload},
		{"the admin user picture upload", "/admin/users/{userId}/picture", "/admin/users/1/picture", upload},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStaticBranchTestServer("http://127.0.0.1:1", &countingStore{})
			s.initMiddleware()
			s.router.Post(test.pattern, readWholeBody)

			assert.Equal(t, fmt.Sprintf("read %d", test.limit), sendBody(s.router, test.target, test.limit),
				"a body of exactly the limit reads whole")
			assert.Equal(t, fmt.Sprintf("refused at %d", test.limit), sendBody(s.router, test.target, test.limit+1),
				"one byte more is refused")
		})
	}
}

// TestBodyLimitPolicy_TheUploadRowFollowsTheUploadPage: the upload row is sized from the console's
// own upload page, which refuses a source file over maxSize before anything is sent. The two live
// in different languages, so this is what notices one changing without the other.
func TestBodyLimitPolicy_TheUploadRowFollowsTheUploadPage(t *testing.T) {
	script, err := fs.ReadFile(web.StaticFS(), "image-upload.js")
	require.NoError(t, err)
	require.Contains(t, string(script), "const maxSize = 3 * 1024 * 1024;",
		"the upload page's size check moved or changed; resize uploadBodyLimit to match")

	assert.Equal(t, int64(3*1024*1024+64*1024), int64(uploadBodyLimit))
}

// TestInitMiddleware_TheBodyLimitSitsAfterStripSlashes pins the mount's place in the root chain:
// after StripSlashes, whose normalized path the lookup routes by, and ahead of everything else
// that could read a body.
func TestInitMiddleware_TheBodyLimitSitsAfterStripSlashes(t *testing.T) {
	s := newStaticBranchTestServer("http://127.0.0.1:1", &countingStore{})
	s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))

	var root []string
	err := chi.Walk(s.router, func(_ string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if route == "/static/*" {
			for _, mounted := range middlewares {
				root = append(root, runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name())
			}
		}
		return nil
	})
	require.NoError(t, err)

	strip := slices.Index(root, "github.com/go-chi/chi/v5/middleware.StripSlashes")
	require.GreaterOrEqual(t, strip, 0, "StripSlashes must be on the root chain: %v", root)
	require.Less(t, strip+2, len(root), "the root chain ends too early: %v", root)
	assert.Equal(t, "github.com/leodip/goiabada/core/middleware.MiddlewareBodyLimit.func1", root[strip+1])
	assert.Equal(t, "github.com/leodip/goiabada/core/middleware.MiddlewareSkipCsrf.func1", root[strip+2])
}

// readWholeBody answers how much of the body it read, or the limit that refused it.
func readWholeBody(w http.ResponseWriter, r *http.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		_, _ = fmt.Fprintf(w, "refused at %d", tooLarge.Limit)
	case err != nil:
		_, _ = fmt.Fprintf(w, "error %v", err)
	default:
		_, _ = fmt.Fprintf(w, "read %d", n)
	}
}

func sendBody(router http.Handler, target string, size int64) string {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, target, strings.NewReader(strings.Repeat("x", int(size)))))
	return recorder.Body.String()
}
