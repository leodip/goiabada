package server

import (
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
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
		// The operator's safe mode switch, ahead of everything that can draw a page, so every page
		// this server draws, a fault's included, is drawn in safe mode while it is on (#816).
		"github.com/leodip/goiabada/authserver/internal/middleware.BrandSafeMode.func1",
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

	// The page branch alone carries the client a page is drawn for, which starts as none (#812). It
	// alone refreshes the browser session, ahead of the first read of it, so the
	// touch can send the session cookie again (#743 decisions 8 and 9), behind NoStore, so every
	// answer that can carry that cookie is no-store, the router's 405 included. It then applies a
	// known user's page language, over what the locale middleware resolved; the protocol endpoints
	// and the APIs answer in the language asked for (#631 decision 5). The files branch answers
	// faults as the page branch does, and draws no page.
	wantPages := append(append(append([]string{}, wantRoot...),
		"github.com/leodip/goiabada/authserver/internal/middleware.NoStore.func1",
		"github.com/leodip/goiabada/authserver/internal/middleware.PageClient.func1",
		"github.com/leodip/goiabada/core/sessionstore.Refreshing"),
		wantApp[len(wantRoot):]...)
	wantPages = append(wantPages,
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

// fileRoutes are the page-format routes that draw no page: the images, the brands' stylesheets and
// assets, and the OpenAPI document.
var fileRoutes = []string{
	"GET /openapi.yaml",
	"GET /userinfo/picture/{subject}",
	"HEAD /userinfo/picture/{subject}",
	"GET /client/logo/{clientIdentifier}",
	"HEAD /client/logo/{clientIdentifier}",
	"GET /brand/{id}/stylesheet.css",
	"HEAD /brand/{id}/stylesheet.css",
	"GET /brand/{id}/colors.css",
	"HEAD /brand/{id}/colors.css",
	"GET /brand/{id}/safe-stylesheet.css",
	"HEAD /brand/{id}/safe-stylesheet.css",
	"GET /brand/{id}/safe-colors.css",
	"HEAD /brand/{id}/safe-colors.css",
	"GET /brand-assets/{id}",
	"HEAD /brand-assets/{id}",
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

// Only the page routes of the real registrations refresh the browser session; the files, the
// protocol endpoints and the APIs read it without moving its idle deadline. The client logos, the
// profile pictures and the OpenAPI document are answered cacheable, and discovery and JWKS carry no
// directive at all, so a session cookie sent again there could be stored by a shared cache and
// replayed to other visitors; every page is no-store (#743 decision 9).
func TestInitRoutes_OnlyPagesRefreshTheBrowserSession(t *testing.T) {
	s := newFaultsTestServer(datamocks.NewDatabase(t))
	const refreshing = "github.com/leodip/goiabada/core/sessionstore.Refreshing"

	pages, others := 0, 0
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if route == "/static/*" {
			return nil
		}
		refreshes := false
		for _, mounted := range middlewares {
			if runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name() == refreshing {
				refreshes = true
			}
		}
		isPage := routeFormat(key) == "page" && !slices.Contains(fileRoutes, key)
		if isPage {
			pages++
		} else {
			others++
		}
		assert.Equal(t, isPage, refreshes, "%s refreshes the browser session", key)
		return nil
	})
	require.NoError(t, err)
	assert.Positive(t, pages, "page routes are registered")
	assert.Positive(t, others, "other routes are registered")
}

// The sign-in's step routes name the client of the sign-in a request names ahead of every guard and
// limiter they carry, so the refusals those write, the rate limiter's above all, are drawn in that
// client's brand. The authorization and sign-out routes do not: /auth/authorize names its client
// once the request reaches the client check, and a sign-out names no sign-in (#812).
func TestInitRoutes_TheSignInStepsNameTheirClientAheadOfTheirGuards(t *testing.T) {
	s := newFaultsTestServer(datamocks.NewDatabase(t))
	// By prefix: the compiler may name the closure SignInPageClient.func1 or, inlined, .1.
	const namer = "github.com/leodip/goiabada/authserver/internal/middleware.SignInPageClient."
	steps := []string{
		"GET /auth/level1", "GET /auth/level1completed", "GET /auth/level2", "GET /auth/completed",
		"GET /auth/issue", "GET /auth/pwd", "POST /auth/pwd", "GET /auth/otp", "POST /auth/otp",
		"GET /auth/recovery-codes", "POST /auth/recovery-codes", "GET /auth/legal-acceptance",
		"POST /auth/legal-acceptance", "GET /auth/consent", "POST /auth/consent",
	}

	seen := map[string]bool{}
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if !strings.HasPrefix(route, "/auth/") {
			return nil
		}
		names := make([]string, len(middlewares))
		for i, mounted := range middlewares {
			names[i] = runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name()
		}
		at := slices.IndexFunc(names, func(name string) bool { return strings.HasPrefix(name, namer) })
		if !slices.Contains(steps, key) {
			assert.Equal(t, -1, at, "%s names no sign-in's client", key)
			return nil
		}
		seen[key] = true
		if assert.NotEqual(t, -1, at, "%s names the client of its sign-in: %v", key, names) {
			assert.Equal(t, 1, strings.Count(strings.Join(names, " "), namer), key)
			for _, guard := range names[:at] {
				assert.NotContains(t, guard, "RateLimiter", "%s limits ahead of naming its client", key)
				assert.NotContains(t, guard, "Challenge", "%s challenges ahead of naming its client", key)
			}
		}
		return nil
	})
	require.NoError(t, err)
	for _, step := range steps {
		assert.True(t, seen[step], "the route table has %s", step)
	}
}

// The pages a sign-in links to, forgot password, registration, activation and password reset, name the
// client of the sign-in their URL names ahead of every guard and limiter they carry, so the refusals
// those write are drawn in that client's brand; no other page route names one that way (#812
// decisions 4 and 9).
func TestInitRoutes_ThePagesASignInLinksToNameItsClientAheadOfTheirGuards(t *testing.T) {
	s := newFaultsTestServer(datamocks.NewDatabase(t))
	// By prefix: the compiler may name the closure LinkedSignInPageClient.func1 or, inlined, .1.
	const namer = "github.com/leodip/goiabada/authserver/internal/middleware.LinkedSignInPageClient."
	linked := []string{
		"GET /forgot-password", "POST /forgot-password", "GET /account/register", "POST /account/register",
		"GET /account/activate", "POST /account/activate", "GET /reset-password", "POST /reset-password",
	}

	seen := map[string]bool{}
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		names := make([]string, len(middlewares))
		for i, mounted := range middlewares {
			names[i] = runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name()
		}
		at := slices.IndexFunc(names, func(name string) bool { return strings.HasPrefix(name, namer) })
		if !slices.Contains(linked, key) {
			assert.Equal(t, -1, at, "%s names no linked sign-in's client", key)
			return nil
		}
		seen[key] = true
		if assert.NotEqual(t, -1, at, "%s names the client of the sign-in its URL names: %v", key, names) {
			assert.Equal(t, 1, strings.Count(strings.Join(names, " "), namer), key)
			for _, guard := range names[:at] {
				assert.NotContains(t, guard, "accounthandlers", "%s guards ahead of naming its client", key)
				assert.NotContains(t, guard, "RateLimiter", "%s limits ahead of naming its client", key)
				assert.NotContains(t, guard, "Challenge", "%s challenges ahead of naming its client", key)
			}
		}
		return nil
	})
	require.NoError(t, err)
	for _, page := range linked {
		assert.True(t, seen[page], "the route table has %s", page)
	}
}
