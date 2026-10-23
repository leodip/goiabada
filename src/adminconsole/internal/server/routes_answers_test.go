package server

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// What the admin console answers as a router, pinned through the handler Start serves before the
// router under it is replaced (#462): unmatched paths and the guards that answer them first, 405s,
// HEAD, the trailing slash, non-canonical paths, the static files, request ids, a panic, and the
// metrics' route labels. Every answer here is one the switch keeps. The answers #462 changes on
// purpose, the plain-text 404 under /auth, /admin and /account, the methods a 405's Allow names,
// and a directory under /static, are asserted only as far as they stay: the status.

// notFoundPage is the 404 page's heading, as the English catalog reads, which is what tells the
// console's own page apart from a plain-text 404.
const notFoundPage = `<h1 class="auth-title">Page not found</h1>`

// newRoutingTestServer is the server main builds, through NewServer, with every route registered as
// Start registers them, over an auth server that answers the public settings and nothing else. The
// request logger is on, so each request leaves its "http request" record. It answers the auth
// server's address too, where an anonymous visitor is sent to sign in.
func newRoutingTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/settings" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"https://auth.example.test","uiTheme":"light","smtpEnabled":false}`))
	}))
	t.Cleanup(authServer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test", LogHttpRequests: true},
		AuthServer:   config.AuthServerConfig{BaseURL: authServer.URL},
	}
	registry := metrics.NewRegistry()
	upstream := upstreammetrics.Register(registry)
	cache := publicsettings.NewCache(publicsettings.NewClient(authServer.URL, nil, upstream), publicsettings.DefaultTTL, registry)

	s := NewServer(chi.NewRouter(), newTestSessionStore(), cache, nil, cfg, nil, nil, nil, registry, upstream)
	s.registerRoutes()
	return s, authServer.URL
}

// serveRouting sends one request through the server's handler, with header's fields and cookies
// set on it.
func serveRouting(s *Server, method, target string, header http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		req.Header[name] = values
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	return rr
}

// routingListener serves the server's handler on a loopback listener, for what only the real
// server does: dropping a HEAD's content, and sending a path no URL parser would build.
func routingListener(t *testing.T, s *Server) string {
	t.Helper()
	listener := httptest.NewServer(s.router)
	t.Cleanup(listener.Close)
	return listener.URL
}

// sendRouting sends one request to url over a real connection, following no redirect, and answers
// the response and its whole body.
func sendRouting(t *testing.T, method, url string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	require.NoError(t, err)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

// httpRequestRecords are the request logger's records, one per request it saw.
func httpRequestRecords(logged *logtest.SlogCapture) []logtest.CapturedRecord {
	var records []logtest.CapturedRecord
	for _, captured := range logged.Records() {
		if captured.Message == "http request" {
			records = append(records, captured)
		}
	}
	return records
}

// A path no route matches, outside every group, is the console's 404 page whatever the method, and
// a HEAD of one is the same 404 with no content.
func TestRegisterRoutes_AnUnmatchedPathAtTheRootIsThe404Page(t *testing.T) {
	s, _ := newRoutingTestServer(t)

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/no/such/page"},
		{http.MethodPost, "/no/such/page"},
		{http.MethodGet, "/HEALTH"},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			rr := serveRouting(s, request.method, request.target, nil)

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "text/html; charset=UTF-8", rr.Header().Get("Content-Type"))
			assert.Contains(t, rr.Body.String(), notFoundPage)
		})
	}

	head, body := sendRouting(t, http.MethodHead, routingListener(t, s)+"/no/such/page")
	assert.Equal(t, http.StatusNotFound, head.StatusCode)
	assert.Empty(t, body, "a HEAD has no content")
}

// The application chain runs before any 404, at the root and under each group, so public settings
// that cannot be read answer their 500 rather than the 404 or the sign-in redirect.
func TestRegisterRoutes_AnUnmatchedPathMeetsTheApplicationChainFirst(t *testing.T) {
	s := newStaticBranchTestServer(newFailingSettingsServer(t).URL, newTestSessionStore())
	s.templateFS = web.TemplateFS()
	s.staticFS = web.StaticFS()
	s.registerRoutes()

	for _, target := range []string{"/no/such/page", "/auth/no/such/page", "/admin/no/such/page", "/account/no/such/page"} {
		t.Run(target, func(t *testing.T) {
			assert.Equal(t, http.StatusInternalServerError, serveRouting(s, http.MethodGet, target, nil).Code)
		})
	}
}

// Under /admin and /account an anonymous visitor is sent to sign in whatever the path, a made-up
// one included, and whatever the method, so nobody signed out can tell a real route from a made-up
// one. A signed-in administrator's made-up path, and anyone's under /auth, is a 404, whose body is
// not pinned: #462 decision 2 changes it from chi's plain text to the 404 page.
func TestRegisterRoutes_AnUnmatchedPathUnderAGroupMeetsItsGuardsFirst(t *testing.T) {
	s, authServerURL := newRoutingTestServer(t)

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/admin/no/such/page"},
		{http.MethodGet, "/admin"},
		{http.MethodGet, "/admin/"},
		{http.MethodGet, "/account/no/such/page"},
		{http.MethodGet, "/account"},
		{http.MethodGet, "/account/"},
		// A real path by a method it does not take, ahead of any 405.
		{http.MethodPost, "/admin/clients"},
		{http.MethodDelete, "/account/profile"},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			rr := serveRouting(s, request.method, request.target, nil)

			assert.Equal(t, http.StatusFound, rr.Code)
			assert.True(t, strings.HasPrefix(rr.Header().Get("Location"), authServerURL+"/auth/authorize?"), rr.Header().Get("Location"))
		})
	}

	assert.Equal(t, http.StatusNotFound, serveRouting(s, http.MethodGet, "/auth/no/such/page", nil).Code)

	signedIn, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	assert.Equal(t, http.StatusNotFound, serveRouting(signedIn, http.MethodGet, "/admin/no/such/page", nil, cookies...).Code)
}

// A path that exists, by a method it does not take, is 405 with no content and no Content-Type.
// Allow is pinned only where the path takes one method, the one case chi names correctly and #462
// decision 3 keeps.
func TestRegisterRoutes_AKnownPathByAnotherMethodIs405WithNoContent(t *testing.T) {
	s, _ := newRoutingTestServer(t)

	for _, request := range []struct {
		method, target string
		allow          string
	}{
		{http.MethodPut, "/unauthorized", "GET"},
		{http.MethodPost, "/", "GET"},
		{http.MethodDelete, "/health", ""},
		{http.MethodOptions, "/health", ""},
		{"FOO", "/health", ""},
		{http.MethodPut, "/static/main.css", ""},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			rr := serveRouting(s, request.method, request.target, nil)

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Empty(t, rr.Body.String())
			assert.Empty(t, rr.Header().Get("Content-Type"))
			if request.allow != "" {
				assert.Equal(t, request.allow, rr.Header().Get("Allow"))
			}
		})
	}
}

// A page stays GET-only: a HEAD of one is 405, with no content and an Allow that does not name
// HEAD. The read-only resources answering HEAD as GET are routes_head_test.go's.
func TestRegisterRoutes_APageRefusesHead(t *testing.T) {
	s, _ := newRoutingTestServer(t)
	base := routingListener(t, s)

	for _, target := range []string{"/", "/unauthorized"} {
		t.Run(target, func(t *testing.T) {
			head, body := sendRouting(t, http.MethodHead, base+target)

			assert.Equal(t, http.StatusMethodNotAllowed, head.StatusCode)
			assert.NotEmpty(t, head.Header.Get("Allow"))
			assert.NotContains(t, strings.Split(strings.ReplaceAll(head.Header.Get("Allow"), " ", ""), ","), http.MethodHead)
			assert.Empty(t, body)
		})
	}
}

// One trailing slash is stripped before routing, so a route answers its path with one slash after
// it as it answers its path; a second slash is not stripped, and that path matches nothing.
func TestRegisterRoutes_OneTrailingSlashIsStripped(t *testing.T) {
	s, _ := newRoutingTestServer(t)

	health := serveRouting(s, http.MethodGet, "/health/", nil)
	assert.Equal(t, http.StatusOK, health.Code)
	assert.Equal(t, "healthy", health.Body.String())

	page := serveRouting(s, http.MethodGet, "/unauthorized", nil)
	slashed := serveRouting(s, http.MethodGet, "/unauthorized/", nil)
	require.Equal(t, http.StatusForbidden, page.Code)
	assert.Equal(t, page.Code, slashed.Code)
	assert.Equal(t, page.Header().Get("Content-Type"), slashed.Header().Get("Content-Type"))

	twice := serveRouting(s, http.MethodGet, "/health//", nil)
	assert.Equal(t, http.StatusNotFound, twice.Code)
	assert.Contains(t, twice.Body.String(), notFoundPage)
}

// A path with an empty, "." or ".." segment matches no route and is answered 404, never cleaned and
// redirected to the clean form; under a guarded group the guard answers first. Sent over a real
// connection, because no URL parser builds these targets from a string.
func TestRegisterRoutes_ANonCanonicalPathIs404(t *testing.T) {
	s, authServerURL := newRoutingTestServer(t)
	base := routingListener(t, s)

	for _, target := range []string{"//health", "/./health", "/health/."} {
		t.Run(target, func(t *testing.T) {
			resp, body := sendRouting(t, http.MethodGet, base+target)

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"), "not redirected to the clean path")
			assert.Contains(t, body, notFoundPage)
		})
	}

	// Under /static: a 404, its body changed by #462 decision 7.
	resp, _ := sendRouting(t, http.MethodGet, base+"/static/../health")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "not redirected to the clean path")

	// Under /admin: the guard sends an anonymous visitor to sign in, as on any other path under it.
	resp, _ = sendRouting(t, http.MethodGet, base+"/admin//clients")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), authServerURL+"/auth/authorize?"), resp.Header.Get("Location"))
}

// A file under /static/ is served with its content and the cache headers every static file
// carries; a file that is not there is 404. /favicon.ico redirects to the icon, and /health answers.
func TestRegisterRoutes_TheStaticFilesTheFaviconAndHealth(t *testing.T) {
	s, _ := newRoutingTestServer(t)

	for _, file := range []struct{ name, contentType string }{
		{"main.css", "text/css; charset=utf-8"},
		{"favicon/favicon.ico", "image/vnd.microsoft.icon"},
	} {
		t.Run(file.name, func(t *testing.T) {
			want, err := fs.ReadFile(web.StaticFS(), file.name)
			require.NoError(t, err)

			before := time.Now().Truncate(time.Second)
			rr := serveRouting(s, http.MethodGet, "/static/"+file.name, nil)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, file.contentType, rr.Header().Get("Content-Type"))
			assert.Equal(t, want, rr.Body.Bytes())
			assert.Equal(t, "public, max-age=300", rr.Header().Get("Cache-Control"))
			assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))
			expires, err := http.ParseTime(rr.Header().Get("Expires"))
			require.NoError(t, err, "Expires is an HTTP date")
			assert.WithinRange(t, expires, before.Add(5*time.Minute), time.Now().Add(5*time.Minute+time.Second))
		})
	}

	assert.Equal(t, http.StatusNotFound, serveRouting(s, http.MethodGet, "/static/no-such-file.css", nil).Code)

	favicon := serveRouting(s, http.MethodGet, "/favicon.ico", nil)
	assert.Equal(t, http.StatusMovedPermanently, favicon.Code)
	assert.Equal(t, "/static/favicon/favicon.ico", favicon.Header().Get("Location"))

	health := serveRouting(s, http.MethodGet, "/health", nil)
	assert.Equal(t, http.StatusOK, health.Code)
	assert.Equal(t, "healthy", health.Body.String())
}

// mintedRequestId is the request id chi's RequestID mints when a request carries none, the shape
// #462 decision 6 keeps: the host name, ten base62 characters, and a counter of at least six
// digits. A host whose name cannot be read is localhost.
func mintedRequestId(t *testing.T) *regexp.Regexp {
	t.Helper()
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}
	return regexp.MustCompile(`^` + regexp.QuoteMeta(hostname) + `/([A-Za-z0-9]{10})-([0-9]{6,})$`)
}

// An incoming X-Request-Id is the request's id verbatim, on its records; without one an id is
// minted, the same prefix for every request and a counter that grows. No response carries it.
func TestRegisterRoutes_RequestIdsAreAdoptedOrMinted(t *testing.T) {
	s, _ := newRoutingTestServer(t)
	logged := logtest.CaptureSlog(t)

	adopted := serveRouting(s, http.MethodGet, "/unauthorized", http.Header{"X-Request-Id": {"the-proxys-id 42"}})
	require.Equal(t, http.StatusForbidden, adopted.Code)
	assert.Empty(t, adopted.Header().Get("X-Request-Id"), "no response header carries the id")

	records := httpRequestRecords(logged)
	require.Len(t, records, 1)
	assert.Equal(t, "the-proxys-id 42", records[0].Attrs["request_id"])

	first := serveRouting(s, http.MethodGet, "/unauthorized", nil)
	second := serveRouting(s, http.MethodGet, "/no/such/page", nil)
	assert.Empty(t, first.Header().Get("X-Request-Id"))
	assert.Empty(t, second.Header().Get("X-Request-Id"))

	records = httpRequestRecords(logged)
	require.Len(t, records, 3)
	shape := mintedRequestId(t)
	firstId := shape.FindStringSubmatch(records[1].Attrs["request_id"].(string))
	secondId := shape.FindStringSubmatch(records[2].Attrs["request_id"].(string))
	require.NotNil(t, firstId, "minted id %q", records[1].Attrs["request_id"])
	require.NotNil(t, secondId, "minted id %q", records[2].Attrs["request_id"])
	assert.Equal(t, firstId[1], secondId[1], "one prefix for the process")
	firstCount, err := strconv.Atoi(firstId[2])
	require.NoError(t, err)
	secondCount, err := strconv.Atoi(secondId[2])
	require.NoError(t, err)
	assert.Greater(t, secondCount, firstCount, "the counter grows")
}

// A panic is answered with an empty 500, which the request logger and the metrics record as the
// 500 the client received; http.ErrAbortHandler is not answered, and leaves the server's handler
// as it was raised, for net/http to abort the connection.
func TestRegisterRoutes_APanicIsAnEmpty500(t *testing.T) {
	s, _ := newRoutingTestServer(t)
	s.router.Get("/probe/panic", func(http.ResponseWriter, *http.Request) { panic("a handler panicked") })
	s.router.Get("/probe/abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	logged := logtest.CaptureSlog(t)

	rr := serveRouting(s, http.MethodGet, "/probe/panic", http.Header{"X-Request-Id": {"the-panic"}})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Empty(t, rr.Body.String())
	assert.Empty(t, rr.Header().Get("Content-Type"))
	records := httpRequestRecords(logged)
	require.Len(t, records, 1)
	assert.Equal(t, "the-panic", records[0].Attrs["request_id"])
	assert.EqualValues(t, http.StatusInternalServerError, records[0].Attrs["status"])
	assert.Contains(t, scrape(t, s), `goiabada_http_requests_total{route="/probe/panic",method="GET",status="500"} 1`+"\n")

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		serveRouting(s, http.MethodGet, "/probe/abort", nil)
	})
}

// The metrics' route label is the route as registered, the group's prefix joined on and its
// parameters as {name}; the static files are /static/*; a request no route answered, a 404 or a
// 405, is unmatched; and a path answered through the trailing-slash strip is its route's. The admin
// API behind the pages answers 503, so each admin page answers its 500, under its own route.
func TestRegisterRoutes_TheMetricsNameEachRoute(t *testing.T) {
	s, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	for _, request := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/admin/clients/7/settings", http.StatusInternalServerError},
		{http.MethodGet, "/admin/clients", http.StatusInternalServerError},
		{http.MethodGet, "/static/main.css", http.StatusOK},
		{http.MethodGet, "/static/favicon/favicon.ico", http.StatusOK},
		{http.MethodGet, "/no/such/page", http.StatusNotFound},
		{http.MethodPut, "/unauthorized", http.StatusMethodNotAllowed},
		{http.MethodGet, "/health/", http.StatusOK},
	} {
		rr := serveRouting(s, request.method, request.target, nil, cookies...)
		require.Equal(t, request.status, rr.Code, "%s %s", request.method, request.target)
	}

	exposition := scrape(t, s)
	for _, line := range []string{
		`goiabada_http_requests_total{route="/admin/clients/{clientId}/settings",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="/admin/clients",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="/static/*",method="GET",status="200"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="GET",status="404"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="PUT",status="405"} 1`,
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 1`,
		`goiabada_http_request_duration_seconds_count{route="/admin/clients/{clientId}/settings",method="GET"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.Equal(t, 6, strings.Count(exposition, "goiabada_http_requests_total{"), exposition)
}
