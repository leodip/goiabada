package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Which branch each route is registered on, shown through the real initMiddleware and initRoutes:
// a fault that stops a request before its handler is answered in the format that route's handler
// answers every other fault in. The formats themselves, and every fault site, are the middleware
// package's ServerFaults table; this owns the assignment of routes to branches (#435).

// protocolRoutes are the routes whose handlers answer RFC 6749 section 5.2's {error,
// error_description}: token, userinfo, JWKS, discovery, and dynamic client registration, whose RFC
// 7591 section 3.2.2 error body is the same two members.
var protocolRoutes = []string{
	"POST /auth/token",
	"GET /userinfo",
	"POST /userinfo",
	"GET /certs",
	"GET /.well-known/openid-configuration",
	"POST /connect/register",
}

// routeFormat is the format a registered route must answer a fault in: the protocol routes above,
// the API routes by their prefix, and a page's text/plain for everything else.
func routeFormat(route string) string {
	if slices.Contains(protocolRoutes, route) {
		return "protocol"
	}
	_, pattern, _ := strings.Cut(route, " ")
	if strings.HasPrefix(pattern, "/api/") {
		return "api"
	}
	return "page"
}

// registeredRoutes walks the real registrations as "METHOD /pattern".
func registeredRoutes(t *testing.T, s *Server) []string {
	t.Helper()
	var routes []string
	err := chi.Walk(s.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	})
	require.NoError(t, err)
	return routes
}

// newFaultsTestServer runs the real initMiddleware and initRoutes over database.
func newFaultsTestServer(database *datamocks.Database) *Server {
	s := newStaticBranchTestServer(database)
	s.templateFS = web.TemplateFS()
	s.initRoutes(s.initMiddleware())
	return s
}

// assertFaultFormat checks a 500 answered in format; pageSentence is the text/plain body's opening
// on a page route.
func assertFaultFormat(t *testing.T, format string, pageSentence string, rr *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	switch format {
	case "page":
		assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
		assert.True(t, strings.HasPrefix(rr.Body.String(), pageSentence), rr.Body.String())
	case "protocol":
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
		assert.Equal(t, "server_error", body["error"])
		assert.Contains(t, body["error_description"], "An unexpected server error has occurred.")
		assert.Len(t, body, 2, "RFC 6749 section 5.2's two members: %s", rr.Body.String())
	case "api":
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
		assert.Equal(t, "INTERNAL_SERVER_ERROR", body["error_code"])
		assert.Contains(t, body["error_description"], "An unexpected server error has occurred.")
		assert.Len(t, body, 2, "the API envelope's two members: %s", rr.Body.String())
	default:
		t.Fatalf("unknown format %q", format)
	}
}

// requireEveryFormatReached fails a walk that classified nothing into a format, and a protocol entry
// naming no registered route, either of which would leave the sweep asserting less than it reads.
func requireEveryFormatReached(t *testing.T, routes []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, route := range routes {
		seen[routeFormat(route)] = true
	}
	for _, format := range []string{"page", "protocol", "api"} {
		require.True(t, seen[format], "no registered route answers in the %s format", format)
	}
	for _, protocol := range protocolRoutes {
		require.Contains(t, routes, protocol, "a protocol route this test names is not registered")
	}
}

// TestInitRoutes_ASettingsFaultIsAnsweredInEachRoutesFormat: with the settings row unreadable, every
// application route answers 500 before its handler, and in its handler's format. Before #435 every
// one of them answered text/plain, so a client parsing the token endpoint, userinfo, JWKS, discovery,
// registration or the APIs as JSON could not parse the one fault that reaches them all at once.
func TestInitRoutes_ASettingsFaultIsAnsweredInEachRoutesFormat(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, errors.New("the database is down"))
	s := newFaultsTestServer(database)

	routes := registeredRoutes(t, s)
	requireEveryFormatReached(t, routes)

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			method, pattern, _ := strings.Cut(route, " ")
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, httptest.NewRequest(method, routeTestTarget(pattern), nil))
			assertFaultFormat(t, routeFormat(route), "fatal failure in GetSettings() middleware.", rr)
		})
	}
}

// TestInitRoutes_ASessionFaultIsAnsweredInEachRoutesFormat: with a session cookie naming a row that
// cannot be read, every application route answers 500 before its handler, in its handler's format.
// The cookie is what reaches the session middleware's database read, so the fault needs a browser
// that has signed in, which a client calling the token endpoint from the same origin can be.
func TestInitRoutes_ASessionFaultIsAnsweredInEachRoutesFormat(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").Return(nil, errors.New("the database is down"))
	s := newFaultsTestServer(database)

	// A real session cookie naming sid-1, minted by the store the server runs.
	mint := httptest.NewRequest(http.MethodGet, "/", nil)
	minted := httptest.NewRecorder()
	session, err := s.sessionStore.Get(mint, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.SessionIdentifier] = "sid-1"
	require.NoError(t, s.sessionStore.Save(mint, minted, session))
	cookies := minted.Result().Cookies()
	require.NotEmpty(t, cookies, "the store must have set the session cookie")

	routes := registeredRoutes(t, s)
	requireEveryFormatReached(t, routes)

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			method, pattern, _ := strings.Cut(route, " ")
			req := httptest.NewRequest(method, routeTestTarget(pattern), nil)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, req)
			assertFaultFormat(t, routeFormat(route), "fatal failure in session middleware.", rr)
		})
	}
}

// The token endpoint left the /auth group, which is mounted on the page branch whole, for the
// protocol branch. A GET, which it does not serve, falls through to the group's catch-all, and chi
// carries the method it found refused there, so the group answers the 405 it answered when the
// route was its own rather than its 404 page.
func TestInitRoutes_TheTokenEndpointStillRefusesGETWith405(t *testing.T) {
	database := datamocks.NewDatabase(t)
	// The group's chain runs ahead of its 405, as it did when the route was the group's.
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil)
	s := newFaultsTestServer(database)

	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/token", nil))

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, rr.Body.String())
	assert.Equal(t, "POST", rr.Header().Get("Allow"))
}

// /api/public/settings is registered for GET only, so the router answers every other method, as
// it does on every API route: 405, Allow naming GET, and no body. The handler's own JSON 405 was
// unreachable behind it and is gone (#522 decision 5); RFC 9110 section 15.5.6 asks a 405 for the
// Allow header and nothing more.
func TestInitRoutes_PublicSettingsRefusesOtherMethodsWith405(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil).Maybe()
			s := newFaultsTestServer(database)

			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, httptest.NewRequest(method, "/api/public/settings", nil))

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, rr.Body.String())
			assert.Equal(t, "GET", rr.Header().Get("Allow"))
			assert.Empty(t, rr.Body.String())
		})
	}
}
