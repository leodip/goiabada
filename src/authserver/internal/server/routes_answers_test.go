package server

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// What the auth server answers as a router, pinned through the handler Start serves before the
// router under it is replaced (#462): unmatched paths and the guards that answer them first, 405s,
// HEAD, the trailing slash, non-canonical paths, the static files, request ids, a panic, and the
// metrics' route labels. Every answer here is one the switch keeps. The answers #462 changes on
// purpose, the plain-text 404 under /auth and /account, the methods a 405's Allow names, and a
// directory under /static, are asserted only as far as they stay: the status.

// notFoundPage is the 404 page's heading, as the English catalog reads, which is what tells the
// server's own page apart from a plain-text 404.
const notFoundPage = `<h1 class="auth-title">Page not found</h1>`

// newRoutingTestServer is the server main builds, through NewServer, with every route registered as
// Start registers them, over database. The request logger is on, so each request leaves its
// "http request" record.
func newRoutingTestServer(t *testing.T, database *datamocks.Database) *Server {
	t.Helper()

	database.On("PoolStats").Return(testPoolStats).Maybe()

	cfg := &config.Config{}
	cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes
	cfg.AuthServer.LogHttpRequests = true

	s := NewServer(chi.NewRouter(), database, newTestSessionStore(), nil, nil, cfg)
	s.registerRoutes()
	return s
}

// newRoutingDatabase answers the settings read the application branches make, and nothing else.
func newRoutingDatabase(t *testing.T) *datamocks.Database {
	t.Helper()

	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Maybe()
	return database
}

// serveRouting sends one request through the server's handler, with header's fields set on it.
func serveRouting(s *Server, method, target string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		req.Header[name] = values
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

// sendRouting sends one request to base+target over a real connection, following no redirect, and
// answers the response and its whole body.
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

// A path no route matches, at the root or under no group, is the server's 404 page whatever the
// method, and a HEAD of one is the same 404 with no content.
func TestRegisterRoutes_AnUnmatchedPathAtTheRootIsThe404Page(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/no/such/page"},
		{http.MethodPost, "/no/such/page"},
		{http.MethodOptions, "/no/such/page"},
		{http.MethodGet, "/api/no/such/page"},
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

// The page branch's chain runs before the 404 page, at the root and under each page group, so a
// settings read that fails answers its 500 rather than the 404.
func TestRegisterRoutes_AnUnmatchedPageMeetsThePageChainFirst(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(nil, errors.New("the database is down"))
	s := newRoutingTestServer(t, database)

	for _, target := range []string{"/no/such/page", "/auth/no/such/page", "/account/no/such/page"} {
		t.Run(target, func(t *testing.T) {
			rr := serveRouting(s, http.MethodGet, target, nil)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.True(t, strings.HasPrefix(rr.Body.String(), "fatal failure in GetSettings() middleware."), rr.Body.String())
		})
	}
}

// Under each page group an unmatched path is a 404. Its body is not pinned: #462 decision 2 changes
// it from chi's plain text to the 404 page.
func TestRegisterRoutes_AnUnmatchedPathUnderAPageGroupIs404(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, target := range []string{"/auth/no/such/page", "/account/no/such/page"} {
		t.Run(target, func(t *testing.T) {
			assert.Equal(t, http.StatusNotFound, serveRouting(s, http.MethodGet, target, nil).Code)
		})
	}
}

// Under each API group the group's guards answer first: the account and session APIs refuse a
// caller with no token 401 whatever the path, a made-up one included, so an anonymous caller cannot
// tell a real route from a made-up one. The admin API's group guards let a caller with no token pass
// to its routes, whose own scope check refuses it, so a made-up path there is the group's plain-text
// 404.
func TestRegisterRoutes_AnUnmatchedPathUnderAnAPIGroupMeetsItsGuardsFirst(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/account/no/such/route"},
		{http.MethodGet, "/api/v1/sessions/no/such/route"},
		// A real path by a method it does not take is refused the same way, ahead of any 405.
		{http.MethodDelete, "/api/v1/account/profile"},
		{http.MethodGet, "/api/v1/sessions/load"},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			rr := serveRouting(s, request.method, request.target, nil)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
			assert.Equal(t, "ACCESS_TOKEN_REQUIRED", body["error_code"])
			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"), "the group's first middleware ran")
		})
	}

	rr := serveRouting(s, http.MethodGet, "/api/v1/admin/no/such/route", nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, "404 page not found\n", rr.Body.String())
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"), "the group's first middleware ran")
}

// A path that exists, by a method it does not take, is 405 with no content and no Content-Type, on
// every branch and outside them. Allow is pinned only where the path takes one method, the one
// case chi names correctly and #462 decision 3 keeps.
func TestRegisterRoutes_AKnownPathByAnotherMethodIs405WithNoContent(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, request := range []struct {
		method, target string
		allow          string
	}{
		{http.MethodPut, "/auth/token", "POST"},
		{http.MethodGet, "/auth/token", "POST"},
		{http.MethodPost, "/api/public/settings", "GET"},
		{http.MethodDelete, "/openapi.yaml", "GET"},
		{http.MethodPut, "/auth/authorize", ""},
		{http.MethodDelete, "/certs", ""},
		{http.MethodPost, "/health", ""},
		{http.MethodOptions, "/health", ""},
		{http.MethodConnect, "/health", ""},
		{"FOO", "/health", ""},
		{http.MethodPut, "/static/main.css", ""},
		{http.MethodPatch, "/api/v1/admin/users/1", ""},
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

// A resource registered for GET and HEAD answers HEAD as its GET, with the same status and header
// fields and no content; every other GET route refuses HEAD with 405, whose Allow does not name
// HEAD. Over a real listener, because net/http's server is what drops a HEAD's content.
func TestRegisterRoutes_HeadIsAnsweredAsGetOnlyWhereItIsRegistered(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))
	base := routingListener(t, s)

	for _, target := range []string{"/health", "/favicon.ico", "/static/main.css", "/static/favicon/favicon.ico",
		"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		t.Run("HEAD "+target, func(t *testing.T) {
			get, getBody := sendRouting(t, http.MethodGet, base+target)
			head, headBody := sendRouting(t, http.MethodHead, base+target)

			require.NotEqual(t, http.StatusMethodNotAllowed, get.StatusCode)
			require.NotEmpty(t, getBody, "the GET has content, which the HEAD must not")
			assert.Equal(t, get.StatusCode, head.StatusCode)
			for _, name := range []string{"Content-Type", "Cache-Control", "Location", "Vary"} {
				assert.Equalf(t, get.Header.Get(name), head.Header.Get(name), "the HEAD's %s is the GET's", name)
			}
			assert.Empty(t, headBody, "a HEAD has no content")
		})
	}

	for _, target := range []string{"/auth/authorize", "/auth/pwd", "/auth/logout", "/userinfo", "/openapi.yaml"} {
		t.Run("HEAD "+target, func(t *testing.T) {
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
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, request := range []struct{ target, contentType, body string }{
		{"/health/", "", "healthy"},
		{"/openapi.yaml/", "application/yaml", "openapi: "},
		{"/api/public/settings/", "application/json", `{"appName":"Goiabada"`},
	} {
		t.Run(request.target, func(t *testing.T) {
			rr := serveRouting(s, http.MethodGet, request.target, nil)

			assert.Equal(t, http.StatusOK, rr.Code)
			if request.contentType != "" {
				assert.Equal(t, request.contentType, rr.Header().Get("Content-Type"))
			}
			assert.True(t, strings.HasPrefix(rr.Body.String(), request.body), rr.Body.String())
		})
	}

	rr := serveRouting(s, http.MethodGet, "/health//", nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), notFoundPage)
}

// A path with an empty, "." or ".." segment matches no route and is answered 404, never cleaned and
// redirected to the clean form; under a guarded group the guard answers first. Sent over a real
// connection, because no URL parser builds these targets from a string.
func TestRegisterRoutes_ANonCanonicalPathIs404(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))
	base := routingListener(t, s)

	// Outside every group: the 404 page.
	for _, target := range []string{"//health", "/./health", "/health/."} {
		t.Run(target, func(t *testing.T) {
			resp, body := sendRouting(t, http.MethodGet, base+target)

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"), "not redirected to the clean path")
			assert.Contains(t, body, notFoundPage)
		})
	}

	// Under a page group, or under /static: a 404, its body changed by #462 decisions 2 and 7.
	for _, target := range []string{"/auth//pwd", "/auth/./pwd", "/static/../health"} {
		t.Run(target, func(t *testing.T) {
			resp, _ := sendRouting(t, http.MethodGet, base+target)

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"), "not redirected to the clean path")
		})
	}

	// Under the account API: its guard answers first, as on any other path under it.
	resp, _ := sendRouting(t, http.MethodGet, base+"/api/v1/account//profile")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Under the admin API: the group's plain-text 404.
	resp, body := sendRouting(t, http.MethodGet, base+"/api/v1/admin//users/1")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "404 page not found\n", body)
}

// A file under /static/ is served with its content and the cache headers every static file
// carries, and reads no settings; a file that is not there is 404. /favicon.ico redirects to the
// icon, and /health answers whatever the database says.
func TestRegisterRoutes_TheStaticFilesTheFaviconAndHealth(t *testing.T) {
	// No settings read is expected, so a static request that reached the application chain would
	// fail the test on the unexpected call.
	s := newRoutingTestServer(t, datamocks.NewDatabase(t))

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

// mintedRequestId is the request id requestid.Middleware mints when a request carries none, the shape
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
	s := newRoutingTestServer(t, newRoutingDatabase(t))
	logged := logtest.CaptureSlog(t)

	adopted := serveRouting(s, http.MethodGet, "/auth/logout/declined", http.Header{"X-Request-Id": {"the-proxys-id 42"}})
	require.Equal(t, http.StatusOK, adopted.Code)
	assert.Empty(t, adopted.Header().Get("X-Request-Id"), "no response header carries the id")

	records := httpRequestRecords(logged)
	require.Len(t, records, 1)
	assert.Equal(t, "the-proxys-id 42", records[0].Attrs["request_id"])

	first := serveRouting(s, http.MethodGet, "/auth/logout/declined", nil)
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

// newPanickingServer is the routing test server over a database whose settings read panics with
// value, which every application route reaches before its handler.
func newPanickingServer(t *testing.T, value any) *Server {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Run(func(mock.Arguments) { panic(value) }).Return(nil, nil)
	return newRoutingTestServer(t, database)
}

// A panic is answered 500: an empty one on the page branch, at the root's recovery, and the
// branch's JSON 500 on the protocol, token and API branches, whose error_description ends with the
// request id. The request logger and the metrics record the 500 the client received.
func TestRegisterRoutes_APanicIsAnswered500OnEachBranch(t *testing.T) {
	s := newPanickingServer(t, "the settings read panicked")
	logged := logtest.CaptureSlog(t)

	for _, request := range []struct {
		method, target, format string
	}{
		{http.MethodGet, "/openapi.yaml", "page"},
		{http.MethodGet, "/no/such/page", "page"},
		{http.MethodGet, "/.well-known/openid-configuration", "protocol"},
		{http.MethodPost, "/auth/token", "protocol"},
		{http.MethodGet, "/api/public/settings", "api"},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			requestId := "panic" + strings.ReplaceAll(request.target, "/", "-")
			rr := serveRouting(s, request.method, request.target, http.Header{"X-Request-Id": {requestId}})

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			if request.format == "page" {
				assert.Empty(t, rr.Body.String())
				assert.Empty(t, rr.Header().Get("Content-Type"))
			} else {
				assertFaultFormat(t, request.format, "", rr)
				var body map[string]string
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
				assert.True(t, strings.HasSuffix(body["error_description"], "Request Id: "+requestId), body["error_description"])
			}

			records := httpRequestRecords(logged)
			require.NotEmpty(t, records)
			last := records[len(records)-1]
			assert.Equal(t, requestId, last.Attrs["request_id"])
			assert.EqualValues(t, http.StatusInternalServerError, last.Attrs["status"])
		})
	}
	assert.Len(t, httpRequestRecords(logged), 5, "one record per request")

	exposition := scrape(t, s)
	for _, line := range []string{
		`goiabada_http_requests_total{route="/openapi.yaml",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="/.well-known/openid-configuration",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="/auth/token",method="POST",status="500"} 1`,
		`goiabada_http_requests_total{route="/api/public/settings",method="GET",status="500"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
}

// A panic is one ERROR record on every branch, carrying the request id and the stack the panic was
// raised on, through the process's one handler: on the page branch the root's recovery writes it,
// where chi's wrote a coloured trace to standard error outside the log stream (#462), and on a JSON
// branch the branch's 500 does.
func TestRegisterRoutes_APanicIsOneErrorRecordOnEachBranch(t *testing.T) {
	s := newPanickingServer(t, "the settings read panicked")
	logged := logtest.CaptureSlog(t)

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/openapi.yaml"},
		{http.MethodGet, "/no/such/page"},
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodPost, "/auth/token"},
		{http.MethodGet, "/api/public/settings"},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			requestId := "panic-record" + strings.ReplaceAll(request.target, "/", "-")
			serveRouting(s, request.method, request.target, http.Header{"X-Request-Id": {requestId}})

			var lines []string
			for _, line := range strings.Split(logged.Text(), "\n") {
				if strings.Contains(line, "level=ERROR") && strings.Contains(line, "request_id="+requestId) {
					lines = append(lines, line)
				}
			}
			require.Len(t, lines, 1, "one ERROR record for the panic:\n%s", logged.Text())
			assert.Contains(t, lines[0], "the settings read panicked")
			assert.Contains(t, lines[0], "routes_answers_test.go", "the record carries the stack the panic was raised on")
		})
	}
}

// http.ErrAbortHandler, which a handler raises to abort its response on purpose, is not answered:
// it leaves the server's handler as it was raised, on the page branch and on a JSON one, for
// net/http to abort the connection.
func TestRegisterRoutes_AnAbortedHandlerIsNotAnswered(t *testing.T) {
	s := newPanickingServer(t, http.ErrAbortHandler)

	for _, target := range []string{"/openapi.yaml", "/.well-known/openid-configuration", "/api/public/settings"} {
		t.Run(target, func(t *testing.T) {
			assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
				serveRouting(s, http.MethodGet, target, nil)
			})
		})
	}
}

// The metrics' route label is the route as registered, the group's prefix joined on and its
// parameters as {name}; the static files are /static/*; a request no route answered, a 404 or a
// 405, is unmatched; and a path answered through the trailing-slash strip is its route's.
func TestRegisterRoutes_TheMetricsNameEachRoute(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	for _, request := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/api/v1/admin/users/42", http.StatusUnauthorized},
		{http.MethodGet, "/auth/logout/declined", http.StatusOK},
		{http.MethodGet, "/static/main.css", http.StatusOK},
		{http.MethodGet, "/static/favicon/favicon.ico", http.StatusOK},
		{http.MethodGet, "/no/such/page", http.StatusNotFound},
		{http.MethodPut, "/auth/token", http.StatusMethodNotAllowed},
		{http.MethodGet, "/health/", http.StatusOK},
	} {
		require.Equal(t, request.status, serveRouting(s, request.method, request.target, nil).Code, "%s %s", request.method, request.target)
	}

	exposition := scrape(t, s)
	for _, line := range []string{
		`goiabada_http_requests_total{route="/api/v1/admin/users/{id}",method="GET",status="401"} 1`,
		`goiabada_http_requests_total{route="/auth/logout/declined",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/static/*",method="GET",status="200"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="GET",status="404"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="PUT",status="405"} 1`,
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 1`,
		`goiabada_http_request_duration_seconds_count{route="/api/v1/admin/users/{id}",method="GET"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.Equal(t, 6, strings.Count(exposition, "goiabada_http_requests_total{"), exposition)
}
