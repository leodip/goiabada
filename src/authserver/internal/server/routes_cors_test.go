package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// Where the CORS answers sit in the server, pinned through the handler Start serves (#462 decision
// 8, #280): a preflight is answered at the top of the chain, before routing and before any
// branch's settings read or group guard, on every path; every other request is routed as it would
// be with no Origin, and varies on Origin unless its handler sets Vary itself, as the static files
// do. The answers themselves are middleware.CORS's own tests.

// A preflight is 200 with no content on any path, a route, a path no route matches, a path under a
// guarded API group and a static file alike, and reads no settings: the database is strict and
// stubs only the origin lookup the token endpoint makes.
func TestRegisterRoutes_APreflightIsAnsweredBeforeRouting(t *testing.T) {
	for _, tt := range []struct {
		path      string
		wantAllow bool
	}{
		{path: "/auth/token", wantAllow: true},
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
