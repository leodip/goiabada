package server

import (
	"net/http"
	"reflect"
	"runtime"
	"slices"
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
	s.serveStaticFiles()
	probe := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	branches.pages.Get("/auth/authorize", probe)
	branches.protocol.Get("/certs", probe)
	branches.token.Post("/auth/token", probe)
	branches.api.Get("/api/public/settings", probe)

	// A route registered for more than one method, such as GET and HEAD, is walked once per
	// method. Its chain is recorded once, and every other method of it must have the same one.
	chains := make(map[string][]string)
	var differing []string
	err := chi.Walk(s.router, func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		var chain []string
		for _, mounted := range middlewares {
			chain = append(chain, runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name())
		}
		if seen, ok := chains[route]; ok {
			if !slices.Equal(seen, chain) {
				differing = append(differing, method+" "+route)
			}
			return nil
		}
		chains[route] = chain
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, differing, "every method of a route passes through the same chain")

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
	// The same chain on all four branches, which differ only in how its faults are answered.
	wantApp := append(append([]string{}, wantRoot...),
		"github.com/leodip/goiabada/authserver/internal/middleware.ServerFaults.Recoverer-fm",
		"github.com/leodip/goiabada/authserver/internal/middleware.Settings.func1",
		"github.com/leodip/goiabada/core/httpmw.CookieReset.func1",
		"github.com/leodip/goiabada/authserver/internal/middleware.SessionIdentifier.func1",
		"github.com/leodip/goiabada/core/i18n.Locale.func1",
	)

	require.Contains(t, chains, "/static/*", "the static route must have been walked")
	assert.Equal(t, wantRoot, chains["/static/*"])
	for _, route := range []string{"/auth/authorize", "/certs", "/auth/token", "/api/public/settings"} {
		require.Contains(t, chains, route, "the application route must have been walked")
		assert.Equal(t, wantApp, chains[route], route)
	}
}
