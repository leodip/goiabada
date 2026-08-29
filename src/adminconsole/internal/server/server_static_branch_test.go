package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The static file branch carries neither the settings fetch nor the session load (#266
// decision 17).
//
// The auth server has the same case, and this module's version of it matters more. Its
// settings come from an HTTP call to the auth server and, since #266, so does its session:
// an admin console page references nine to eleven same-origin assets, so mounted on the root
// a single page view would cost ten calls across the wire and a database read at the far end
// of each, on the module that was kept database-free precisely to stay light.
//
// It cannot be asserted anywhere but here. MiddlewareSettingsCache and MiddlewareCookieReset
// both have their own tests and both pass whatever router they are mounted on; what decides
// the cost of a page view is which branch serveStaticFiles registers against, and that is a
// property of this file alone.

func TestInitMiddleware_StaticFilesSkipTheSettingsAndSessionChain(t *testing.T) {
	settings := newCountingSettingsServer(t)
	store := &countingStore{}

	s := newStaticBranchTestServer(settings.URL, store)
	app := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))
	app.Get("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/probe.css", nil))

	result := recorder.Result()
	defer func() { _ = result.Body.Close() }()

	require.Equal(t, http.StatusOK, result.StatusCode, "the file must still be served")
	assert.Zero(t, settings.fetches.Load(), "a stylesheet must not cost a settings fetch")
	assert.Zero(t, store.gets.Load(), "nor a session load, which is now a call to the auth server")
}

// TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain is the other half, and
// without it the case above is satisfied by a chain that was never mounted at all.
func TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain(t *testing.T) {
	settings := newCountingSettingsServer(t)
	store := &countingStore{}

	s := newStaticBranchTestServer(settings.URL, store)
	app := s.initMiddleware()
	s.serveStaticFiles("/static", http.FS(s.staticFS))

	reached := false
	app.Get("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/clients", nil))

	assert.True(t, reached, "the request must reach the handler")
	assert.Equal(t, int64(1), settings.fetches.Load())
	assert.Equal(t, int64(1), store.gets.Load())
}

func newStaticBranchTestServer(authServerBaseURL string, store sessions.Store) *Server {
	return &Server{
		router:        chi.NewRouter(),
		sessionStore:  store,
		settingsCache: cache.NewSettingsCache(authServerBaseURL),
		staticFS:      fstest.MapFS{"probe.css": &fstest.MapFile{Data: []byte("body{}")}},
	}
}

// countingSettingsServer answers the public settings endpoint and counts how often it was
// asked. The count, not the body, is the assertion.
type countingSettingsServer struct {
	*httptest.Server
	fetches atomic.Int64
}

func newCountingSettingsServer(t *testing.T) *countingSettingsServer {
	t.Helper()

	counter := &countingSettingsServer{}
	counter.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		counter.fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada","uiTheme":"light","smtpEnabled":false,"issuer":"https://issuer.example"}`))
	}))
	t.Cleanup(counter.Close)

	return counter
}

// countingStore is a sessions.Store that records Get. It never has to return anything usable:
// MiddlewareCookieReset asks for the session and passes a non-decode error straight through,
// so a store that answers an empty session is enough to observe whether it was asked at all.
type countingStore struct {
	gets atomic.Int64
}

func (s *countingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s.gets.Add(1)
	return sessions.NewSession(s, name), nil
}

func (s *countingStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(s, name), nil
}

func (s *countingStore) Save(*http.Request, http.ResponseWriter, *sessions.Session) error {
	return nil
}
