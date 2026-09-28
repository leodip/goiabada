package server

import (
	"database/sql"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
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
	database.AssertNotCalled(t, "GetSettingsById", mock.Anything, nilTx, int64(1))
}

// TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain is the other half, and
// without it the case above is satisfied by a chain that was never mounted at all.
func TestInitMiddleware_ApplicationRoutesKeepTheSettingsAndSessionChain(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&models.Settings{Id: 1}, nil).Once()

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

// testProfilePictureMaxSizeBytes is the configured image size newStaticBranchTestServer hands the
// chain. It is not the default, so a body-limit row that read the default instead of the
// configured value would admit the row's bound plus one byte and fail
// TestBodyLimitPolicy_EachRowAtItsBoundary (#434).
const testProfilePictureMaxSizeBytes = 100 << 10

func newStaticBranchTestServer(database *mocks_data.Database) *Server {
	cfg := &config.Config{}
	cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes

	return &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: newTestSessionStore(),
		staticFS:     fstest.MapFS{"probe.css": &fstest.MapFile{Data: []byte("body{}")}},
		cfg:          cfg,
	}
}

// newTestSessionStore is the real store over an in-memory backend, which is what these
// tests drive now that the browser session is a row rather than a cookie (#266). It
// replaces a cookie store built from a random key: nothing here asserts on the cookie's
// contents, so what the double owed was a working Get and Save, and the real store over
// sessiontest.NewMemoryBackend gives both without a second implementation of either.
//
// The keys are literals rather than freshly generated ones, matching the pattern the
// store's other test callers already use. They never vary and nothing reads them, so
// generating them would only add an error to check in a helper that cannot fail.
func newTestSessionStore() *sessionstore.ServerSideStore {
	store, err := sessionstore.NewServerSideStore(
		sessiontest.NewMemoryBackend(),
		sessionkeys.SessionKeySessionIdentifier,
		false,
		sessionstore.PersistentCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	if err != nil {
		// The keys are literals above and the derivation cannot fail on them, so this is
		// unreachable. Panicking rather than dropping it keeps it that way.
		panic(err)
	}
	return store
}
