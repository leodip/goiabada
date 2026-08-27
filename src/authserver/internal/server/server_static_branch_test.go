package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The static file branch carries neither the settings read nor the session load (#266
// decision 17).
//
// This cannot be asserted anywhere but here. MiddlewareSettings and MiddlewareCookieReset
// both have their own tests and both pass whatever router they are mounted on; what decides
// the cost of a page view is which branch serveStaticFiles registers against, and that is a
// property of this file alone.
//
// The cost it removes is not marginal. An auth page references seven same-origin assets and
// an admin console page nine to eleven, MiddlewareSettings reads settings from the database
// uncached on every request, and after #266 a session load is a database read too. Mounted
// on the root, one page view would cost seven settings reads and seven session reads for
// files that can use neither.
//
// mocks_data.NewDatabase(t) fails the test on any call nobody expected, so the absence of a
// GetSettingsById expectation in the static case IS the assertion.

func TestInitMiddleware_StaticFilesSkipTheSettingsAndSessionChain(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	s := newStaticBranchTestServer(database)
	app := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))
	app.Get("/auth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/probe.css", nil))

	result := recorder.Result()
	defer func() { _ = result.Body.Close() }()

	require.Equal(t, http.StatusOK, result.StatusCode, "the file must still be served")
	database.AssertNotCalled(t, "GetSettingsById", nilTx, int64(1))
}

// TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain is the other half, and
// without it the case above is satisfied by a chain that was never mounted at all.
func TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(&models.Settings{Id: 1}, nil).Once()

	s := newStaticBranchTestServer(database)
	app := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))

	reached := false
	app.Get("/auth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

	assert.True(t, reached, "the request must reach the handler")
	database.AssertExpectations(t)
	database.AssertNumberOfCalls(t, "GetSettingsById", 1)
}

// nilTx is the transaction MiddlewareSettings passes, spelled out so AssertNotCalled names
// the exact call it is denying rather than any call at all.
var nilTx = (*sql.Tx)(nil)

func newStaticBranchTestServer(database *mocks_data.Database) *Server {
	return &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: sessions.NewCookieStore(securecookie.GenerateRandomKey(64)),
		staticFS:     fstest.MapFS{"probe.css": &fstest.MapFile{Data: []byte("body{}")}},
	}
}
