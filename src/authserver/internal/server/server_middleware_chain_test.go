package server

import (
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"testing"

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
	branches.files.Get("/openapi.yaml", probe)
	branches.protocol.Get("/certs", probe)
	branches.token.Post("/auth/token", probe)
	branches.api.Get("/api/public/settings", probe)

	// A route registered for more than one method, such as GET and HEAD, is walked once per
	// method. Its chain is recorded once, and every other method of it must have the same one.
	chains := make(map[string][]string)
	var differing []string
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
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
		"github.com/leodip/goiabada/core/requestid.Middleware",
		"github.com/leodip/goiabada/core/httpmw.SecurityHeaders.func1",
		"github.com/leodip/goiabada/core/httpmw.RealIP.func1",
		"github.com/leodip/goiabada/core/httpmw.RequestLogger.func1",
		// Above Recoverer, as the logger is, so a panic is counted as the 500 its client got (#400).
		"github.com/leodip/goiabada/core/metrics.httpRequests.func2",
		"github.com/leodip/goiabada/core/httpmw.Recoverer",
		// Beneath everything above, so a preflight it answers carries the security headers, its
		// request id, a request-log record and a metrics sample, and a panic in its origin lookup is
		// answered 500; above the slash strip, since it normalizes the trailing slash itself (#715
		// decision 6).
		"github.com/leodip/goiabada/authserver/internal/middleware.CORS.func1",
		"github.com/leodip/goiabada/core/httpmw.StripTrailingSlash",
		// After StripTrailingSlash, whose path it routes by, and before the /auth/logout exemption
		// predicate, which parses the form body (#426).
		"github.com/leodip/goiabada/core/httpmw.BodyLimit.func1",
		"github.com/leodip/goiabada/core/httpmw.SkipCSRF.func1",
		"github.com/leodip/goiabada/core/httpmw.CSRF.func1",
	}
	// The same chain on all the branches, which differ only in how its faults are answered.
	wantApp := append(append([]string{}, wantRoot...),
		"github.com/leodip/goiabada/authserver/internal/middleware.ServerFaults.Recoverer-fm",
		"github.com/leodip/goiabada/authserver/internal/middleware.Settings.func1",
		"github.com/leodip/goiabada/core/httpmw.CookieReset.func1",
		"github.com/leodip/goiabada/authserver/internal/middleware.SessionIdentifier.func1",
		"github.com/leodip/goiabada/core/i18n.Locale.func1",
	)

	// The page branch alone then applies a known user's page language, over what the locale
	// middleware resolved; the protocol endpoints and the APIs answer in the language asked for
	// (#631 decision 5). The files branch answers faults as the page branch does, and draws no page.
	wantPages := append(append([]string{}, wantApp...),
		"github.com/leodip/goiabada/authserver/internal/middleware.PageLanguage.func1",
	)

	require.Contains(t, chains, "/static/*", "the static route must have been walked")
	assert.Equal(t, wantRoot, chains["/static/*"])
	require.Contains(t, chains, "/auth/authorize", "the page route must have been walked")
	assert.Equal(t, wantPages, chains["/auth/authorize"])
	for _, route := range []string{"/openapi.yaml", "/certs", "/auth/token", "/api/public/settings"} {
		require.Contains(t, chains, route, "the application route must have been walked")
		assert.Equal(t, wantApp, chains[route], route)
	}
}

// fileRoutes are the page-format routes that draw no page: the images and the OpenAPI document.
var fileRoutes = []string{
	"GET /openapi.yaml",
	"GET /userinfo/picture/{subject}",
	"HEAD /userinfo/picture/{subject}",
	"GET /client/logo/{clientIdentifier}",
	"HEAD /client/logo/{clientIdentifier}",
}

// Every page route of the real registrations runs the page-language middleware, and the routes that
// draw no page do not, so an image costs no read of its user (#631). The protocol and API routes
// are TestInitMiddleware_TheWholeChainInOrder's.
func TestInitRoutes_ThePageLanguageRunsOnPagesOnly(t *testing.T) {
	s := newFaultsTestServer(datamocks.NewDatabase(t))
	const pageLanguage = "github.com/leodip/goiabada/authserver/internal/middleware.PageLanguage.func1"

	seen := 0
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if routeFormat(key) != "page" {
			return nil
		}
		hasPageLanguage := false
		for _, mounted := range middlewares {
			if runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name() == pageLanguage {
				hasPageLanguage = true
			}
		}
		isFile := slices.Contains(fileRoutes, key)
		if isFile {
			seen++
		}
		assert.Equal(t, !isFile, hasPageLanguage, "%s runs the page-language middleware", key)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, len(fileRoutes), seen, "every file route is registered")
}
