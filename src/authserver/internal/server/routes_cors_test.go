package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/routing"
)

// Where the CORS answers sit in the server, pinned through the handler Start serves (#462 decision
// 8, #280): a preflight is answered beneath the root's request id, security headers, real IP,
// request log, metrics and panic recovery, and before routing and any branch's settings read or
// group guard, on every path (#715 decision 6); every other request is routed as it would be with
// no Origin, and varies on Origin unless its handler sets Vary itself, as the static files do. The
// answers themselves are middleware.CORS's own tests.

// preflightHeader is a preflight from a registered origin asking to POST, with the request id a
// proxy in front gave it.
func preflightHeader() http.Header {
	return http.Header{
		"Origin":                        {"https://registered.example"},
		"Access-Control-Request-Method": {"POST"},
		"X-Request-Id":                  {"the-proxys-id 7"},
	}
}

// newHTTPSRoutingTestServer is newRoutingTestServer with an https base URL, so its answers carry
// Strict-Transport-Security as a deployment's HTTPS listener's do.
func newHTTPSRoutingTestServer(t *testing.T, database *datamocks.Database) *Server {
	t.Helper()

	database.On("PoolStats").Return(testPoolStats).Maybe()

	cfg := &config.Config{}
	cfg.AuthServer.BaseURL = "https://auth.test"
	cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes
	cfg.AuthServer.LogHttpRequests = true

	s := NewServer(routing.New(), database, newTestSessionStore(), nil, nil, cfg)
	s.registerRoutes()
	return s
}

// A preflight carries the baseline security headers every answer carries, and over an https base
// URL Strict-Transport-Security too (RFC 6797 section 7.1), whether it is granted or refused.
func TestRegisterRoutes_APreflightCarriesTheSecurityHeaders(t *testing.T) {
	for _, tt := range []struct {
		path      string
		wantAllow bool
	}{
		{path: "/auth/token", wantAllow: true},
		{path: "/auth/authorize"},
		{path: "/no-such-path"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("WebOriginExists", mock.Anything, mock.Anything, "https://registered.example").Return(true, nil).Maybe()
			s := newHTTPSRoutingTestServer(t, database)

			rr := serveRouting(s, http.MethodOptions, tt.path, preflightHeader())

			require.Equal(t, http.StatusOK, rr.Code)
			header := rr.Result().Header
			assert.Equal(t, []string{"max-age=31536000; includeSubDomains"}, header.Values("Strict-Transport-Security"))
			assert.Equal(t, []string{"DENY"}, header.Values("X-Frame-Options"))
			assert.Equal(t, []string{"script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"},
				header.Values("Content-Security-Policy"))
			assert.Equal(t, []string{"nosniff"}, header.Values("X-Content-Type-Options"))
			assert.Equal(t, []string{"same-origin"}, header.Values("Referrer-Policy"))
			if tt.wantAllow {
				assert.Equal(t, []string{"https://registered.example"}, header.Values("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, header.Values("Access-Control-Allow-Origin"))
			}
		})
	}
}

// A preflight leaves the request log's record, under the request id it arrived with, and so does
// the record of an origin lookup that failed (#715 decision 8). No answer carries the id.
func TestRegisterRoutes_APreflightIsLoggedUnderItsRequestId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("WebOriginExists", mock.Anything, mock.Anything, "https://registered.example").
		Return(false, errors.New("the database is down")).Once()
	s := newHTTPSRoutingTestServer(t, database)
	logged := logtest.CaptureSlog(t)

	rr := serveRouting(s, http.MethodOptions, "/auth/token", preflightHeader())

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Result().Header.Values("Access-Control-Allow-Origin"), "an unreadable origin list grants nothing")
	assert.Empty(t, rr.Header().Get("X-Request-Id"))

	records := httpRequestRecords(logged)
	require.Len(t, records, 1)
	assert.Equal(t, "the-proxys-id 7", records[0].Attrs["request_id"])
	assert.Equal(t, "OPTIONS", records[0].Attrs["method"])
	assert.Equal(t, "/auth/token", records[0].Attrs["target"])
	assert.EqualValues(t, http.StatusOK, records[0].Attrs["status"])

	var lookups []logtest.CapturedRecord
	for _, captured := range logged.Records() {
		if captured.Message == "unable to load the cors configuration" {
			lookups = append(lookups, captured)
		}
	}
	require.Len(t, lookups, 1)
	assert.Equal(t, "the-proxys-id 7", lookups[0].Attrs["request_id"])
}

// Every preflight is counted and timed under the route value preflight, granted or refused, on a
// route or on a path no route matches; an OPTIONS that is not a preflight is routed and counted as
// it was (#715 decision 10).
func TestRegisterRoutes_APreflightIsCountedUnderPreflight(t *testing.T) {
	database := newRoutingDatabase(t)
	database.On("WebOriginExists", mock.Anything, mock.Anything, "https://registered.example").Return(true, nil).Maybe()
	s := newHTTPSRoutingTestServer(t, database)

	require.Equal(t, http.StatusOK, serveRouting(s, http.MethodOptions, "/auth/token", preflightHeader()).Code)
	require.Equal(t, http.StatusOK, serveRouting(s, http.MethodOptions, "/no-such-path", preflightHeader()).Code)
	require.Equal(t, http.StatusMethodNotAllowed, serveRouting(s, http.MethodOptions, "/auth/token", nil).Code)

	exposition := scrape(t, s)
	for _, line := range []string{
		`goiabada_http_requests_total{route="preflight",method="OPTIONS",status="200"} 2`,
		`goiabada_http_request_duration_seconds_count{route="preflight",method="OPTIONS"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="OPTIONS",status="405"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.Equal(t, 2, strings.Count(exposition, "goiabada_http_requests_total{"), exposition)
}

// A panic in a preflight's origin lookup is answered 500 by the root's recovery, with the security
// headers, and is logged and counted as the 500 its client received, under preflight.
func TestRegisterRoutes_APanickingPreflightIsAnswered500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("WebOriginExists", mock.Anything, mock.Anything, "https://registered.example").
		Run(func(mock.Arguments) { panic("the origin lookup panicked") }).Return(false, nil)
	s := newHTTPSRoutingTestServer(t, database)
	logged := logtest.CaptureSlog(t)

	rr := serveRouting(s, http.MethodOptions, "/auth/token", preflightHeader())

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, []string{"max-age=31536000; includeSubDomains"}, rr.Result().Header.Values("Strict-Transport-Security"))
	assert.Equal(t, []string{"nosniff"}, rr.Result().Header.Values("X-Content-Type-Options"))

	records := httpRequestRecords(logged)
	require.Len(t, records, 1)
	assert.Equal(t, "the-proxys-id 7", records[0].Attrs["request_id"])
	assert.EqualValues(t, http.StatusInternalServerError, records[0].Attrs["status"])

	assert.Contains(t, scrape(t, s), `goiabada_http_requests_total{route="preflight",method="OPTIONS",status="500"} 1`+"\n")
}

// A preflight is 200 with no content on any path, a route, a path no route matches, a path under a
// guarded API group and a static file alike, and reads no settings: the database is strict and
// stubs only the origin lookup the token endpoint makes.
func TestRegisterRoutes_APreflightIsAnsweredBeforeRouting(t *testing.T) {
	for _, tt := range []struct {
		path      string
		wantAllow bool
	}{
		{path: "/auth/token", wantAllow: true},
		{path: "/auth/revoke", wantAllow: true},
		// No CORS: a public client, the only kind a browser holds, never introspects (#676 decision 13).
		{path: "/auth/introspect"},
		{path: "/certs", wantAllow: true},
		{path: "/auth/authorize"},
		{path: "/no-such-path"},
		{path: "/api/v1/account/profile"},
		{path: "/api/v1/admin/users"},
		{path: "/static/main.css"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("WebOriginExists", mock.Anything, mock.Anything, "https://registered.example").Return(true, nil).Maybe()
			s := newRoutingTestServer(t, database)

			rr := serveRouting(s, http.MethodOptions, tt.path, http.Header{
				"Origin":                        {"https://registered.example"},
				"Access-Control-Request-Method": {"POST"},
			})

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Empty(t, rr.Body.String())
			assert.Equal(t, []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"},
				rr.Result().Header.Values("Vary"))
			if tt.wantAllow {
				assert.Equal(t, []string{"https://registered.example"}, rr.Result().Header.Values("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rr.Result().Header.Values("Access-Control-Allow-Origin"))
			}
		})
	}
}

// An ordinary request carrying Origin is answered as its route answers it, varying on Origin: a
// guarded group's refusal, a 404 and a 405 included. A static file's own Vary replaces it, since no
// origin is allowed there.
func TestRegisterRoutes_AnOrdinaryRequestVariesOnOrigin(t *testing.T) {
	for _, tt := range []struct {
		method     string
		path       string
		wantStatus int
		wantVary   []string
	}{
		{method: http.MethodGet, path: "/health", wantStatus: http.StatusOK, wantVary: []string{"Origin"}},
		{method: http.MethodGet, path: "/no-such-path", wantStatus: http.StatusNotFound, wantVary: []string{"Origin"}},
		{method: http.MethodGet, path: "/connect/register", wantStatus: http.StatusMethodNotAllowed, wantVary: []string{"Origin"}},
		{method: http.MethodGet, path: "/api/v1/account/profile", wantStatus: http.StatusUnauthorized, wantVary: []string{"Origin"}},
		{method: http.MethodGet, path: "/static/main.css", wantStatus: http.StatusOK, wantVary: []string{"Accept-Encoding"}},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			s := newRoutingTestServer(t, newRoutingDatabase(t))

			rr := serveRouting(s, tt.method, tt.path, http.Header{"Origin": {"https://anywhere.example"}})

			assert.Equal(t, tt.wantStatus, rr.Code)
			assert.Equal(t, tt.wantVary, rr.Result().Header.Values("Vary"))
			assert.Empty(t, rr.Result().Header.Values("Access-Control-Allow-Origin"))
		})
	}
}
