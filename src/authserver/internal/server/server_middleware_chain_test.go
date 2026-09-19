package server

import (
	"net/http"
	"reflect"
	"runtime"
	"testing"

	"github.com/go-chi/chi/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitMiddleware_TheWholeChainInOrder pins the runtime chain rather than the
// text that builds it, so every root and application middleware must be reordered
// deliberately. Once trailing-slash handling is consistent, six of the root
// chain's eight adjacencies have no other observable watching them (#335).
func TestInitMiddleware_TheWholeChainInOrder(t *testing.T) {
	s := newStaticBranchTestServer(mocks_data.NewDatabase(t))
	app := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))
	app.Get("/auth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	chains := make(map[string][]string)
	err := chi.Walk(s.router, func(_ string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		for _, mounted := range middlewares {
			name := runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name()
			chains[route] = append(chains[route], name)
		}
		return nil
	})
	require.NoError(t, err)

	wantRoot := []string{
		"github.com/go-chi/cors.(*Cors).Handler-fm",
		"github.com/go-chi/chi/v5/middleware.RequestID",
		"github.com/leodip/goiabada/core/middleware.MiddlewareSecurityHeaders.func1",
		"github.com/leodip/goiabada/core/middleware.MiddlewareRealIP.func1",
		"github.com/leodip/goiabada/core/middleware.MiddlewareRequestLogger.func1",
		"github.com/go-chi/chi/v5/middleware.Recoverer",
		"github.com/go-chi/chi/v5/middleware.StripSlashes",
		"github.com/leodip/goiabada/core/middleware.MiddlewareSkipCsrf.func1",
		"github.com/leodip/goiabada/core/middleware.MiddlewareCsrf.func1",
	}
	wantApp := append(append([]string{}, wantRoot...),
		"github.com/leodip/goiabada/authserver/internal/middleware.MiddlewareSettings.func1",
		"github.com/leodip/goiabada/core/middleware.MiddlewareCookieReset.func1",
		"github.com/leodip/goiabada/authserver/internal/middleware.MiddlewareSessionIdentifier.func1",
		"github.com/leodip/goiabada/core/i18n.MiddlewareLocale.func1",
	)

	require.Contains(t, chains, "/static/*", "the static route must have been walked")
	require.Contains(t, chains, "/auth/authorize", "the application route must have been walked")
	assert.Equal(t, wantRoot, chains["/static/*"])
	assert.Equal(t, wantApp, chains["/auth/authorize"])
}
