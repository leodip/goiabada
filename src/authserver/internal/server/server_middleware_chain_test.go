package server

import (
	"net/http"
	"reflect"
	"runtime"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitMiddleware_TheWholeChainInOrder pins the runtime chain rather than the
// text that builds it, so every root and application middleware must be reordered
// deliberately. Once trailing-slash handling is consistent, six of the root
// chain's eight adjacencies have no other observable watching them (#335).
func TestInitMiddleware_TheWholeChainInOrder(t *testing.T) {
	s := newStaticBranchTestServer(datamocks.NewDatabase(t))
	branches := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))
	probe := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	branches.pages.Get("/auth/authorize", probe)
	branches.protocol.Post("/auth/token", probe)
	branches.api.Get("/api/public/settings", probe)

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
		"github.com/leodip/goiabada/core/httpmw.SecurityHeaders.func1",
		"github.com/leodip/goiabada/core/httpmw.RealIP.func1",
		"github.com/leodip/goiabada/core/httpmw.RequestLogger.func1",
		// Above Recoverer, as the logger is, so a panic is counted as the 500 its client got (#400).
		"github.com/leodip/goiabada/core/metrics.HTTPRequests.func3",
		"github.com/go-chi/chi/v5/middleware.Recoverer",
		"github.com/go-chi/chi/v5/middleware.StripSlashes",
		// After StripSlashes, whose path it routes by, and before the /auth/logout exemption
		// predicate, which parses the form body (#426).
		"github.com/leodip/goiabada/core/httpmw.BodyLimit.func1",
		"github.com/leodip/goiabada/core/httpmw.SkipCSRF.func1",
		"github.com/leodip/goiabada/core/httpmw.CSRF.func1",
	}
	// The same chain on all three branches, which differ only in how its faults are answered.
	wantApp := append(append([]string{}, wantRoot...),
		"github.com/leodip/goiabada/authserver/internal/middleware.ServerFaults.Recoverer-fm",
		"github.com/leodip/goiabada/authserver/internal/middleware.Settings.func1",
		"github.com/leodip/goiabada/core/httpmw.CookieReset.func1",
		"github.com/leodip/goiabada/authserver/internal/middleware.SessionIdentifier.func1",
		"github.com/leodip/goiabada/core/i18n.Locale.func1",
	)

	require.Contains(t, chains, "/static/*", "the static route must have been walked")
	assert.Equal(t, wantRoot, chains["/static/*"])
	for _, route := range []string{"/auth/authorize", "/auth/token", "/api/public/settings"} {
		require.Contains(t, chains, route, "the application route must have been walked")
		assert.Equal(t, wantApp, chains[route], route)
	}
}
