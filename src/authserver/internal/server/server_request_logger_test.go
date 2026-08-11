package server

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestInitMiddleware_RequestLoggerIsRegistered makes the claim the unit table in
// src/core/middleware cannot: that MiddlewareRequestLogger is actually mounted on the auth server's
// router, and that it is wired to the configuration flag rather than mounted with a constant. That
// table passes perfectly against a middleware nobody wired up, and deleting the Use() line here
// still compiles, because the package references custom_middleware on six other lines.
//
// It is deliberately thin. The middleware's behaviour belongs to its own tests in
// src/core/middleware, and the redaction table belongs to RequestTargetForLog. This owns one claim:
// a real request through this server's real chain of eleven middlewares produces a log line, and
// that line does not carry the id_token_hint (#159).
//
// initMiddleware is an ordinary method and httptest drives it with no harness, which is what
// server_csrf_test.go in the admin console established.

// jwtLike is the three-segment shape an id_token_hint arrives in. It is the sentinel every
// assertion below looks for.
const jwtLike = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlBST0JFIn0." +
	"eyJzdWIiOiJVU0VSLVNVQiIsInNpZCI6IlNFU1NJT04tSUQifQ.U0lHTkFUVVJF"

// withLogHttpRequests sets the flag for the duration of the test and restores it. It has to run
// before initMiddleware, which is when the value is read.
func withLogHttpRequests(t *testing.T, enabled bool) {
	t.Helper()
	previous := config.GetAuthServer().LogHttpRequests
	config.GetAuthServer().LogHttpRequests = enabled
	t.Cleanup(func() {
		config.GetAuthServer().LogHttpRequests = previous
	})
}

// captureSlog redirects the default logger into a buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// newLoggerTestServer builds a Server by hand, runs the real initMiddleware, and registers one
// handler that answers 200 and records that it ran.
//
// The database is a mock with GetSettingsById stubbed, which MiddlewareSettings calls on every
// request. MiddlewareCors also holds the database but needs no stub: go-chi/cors only calls
// AllowOriginFunc for a request carrying an Origin header, and these send none. That is enforced
// rather than assumed, since mocks_data.NewDatabase(t) fails the test on any call nobody expected.
func newLoggerTestServer(t *testing.T, logHttpRequests bool, handlerRan *bool) *Server {
	t.Helper()
	withLogHttpRequests(t, logHttpRequests)

	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(&models.Settings{Id: 1}, nil)

	s := &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: sessions.NewCookieStore(securecookie.GenerateRandomKey(64)),
	}
	s.initMiddleware()
	s.router.Get("/auth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		*handlerRan = true
		w.WriteHeader(http.StatusOK)
	})
	return s
}

// The target carries one allowlisted parameter and one that is not, so the assertions below can
// tell "the token was redacted" apart from "nothing was logged at all".
const loggerTestTarget = "/auth/authorize?client_id=admin-console&response_type=code&id_token_hint=" + jwtLike

func TestInitMiddleware_RequestLoggerIsRegistered(t *testing.T) {
	handlerRan := false
	server := newLoggerTestServer(t, true, &handlerRan)
	logged := captureSlog(t)

	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, loggerTestTarget, nil))

	// The handler at the far end of the chain answered, so the logger did not swallow the request
	// on its way through. Without this the assertions below are satisfied by a chain that broke.
	assert.True(t, handlerRan, "the request must still reach the handler")
	assert.Equal(t, http.StatusOK, recorder.Code)

	output := logged.String()
	assert.Equal(t, 1, strings.Count(output, `msg="http request"`),
		"the request logger must be mounted on the auth server, and write exactly one record")

	// The allowlisted values survived, which is what attributes the absence below to redaction
	// rather than to an empty log.
	assert.Contains(t, output, "client_id=admin-console")
	assert.Contains(t, output, "response_type=code")
	assert.Contains(t, output, "id_token_hint=[redacted]")

	assert.NotContains(t, output, jwtLike,
		"the id_token_hint must never reach the log, which is the whole of #159")
}

// Without this the test above passes against a Use() line that mounts the middleware with a
// constant true, which is the one way to get this wiring wrong that still redacts correctly.
func TestInitMiddleware_RequestLoggerHonoursTheFlag(t *testing.T) {
	handlerRan := false
	server := newLoggerTestServer(t, false, &handlerRan)
	logged := captureSlog(t)

	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, loggerTestTarget, nil))

	assert.Equal(t, 0, strings.Count(logged.String(), `msg="http request"`),
		"nothing is logged when GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS is off")
	// The other half: a middleware that dropped the request would also log nothing.
	assert.True(t, handlerRan, "the request must still reach the handler with the flag off")
	assert.Equal(t, http.StatusOK, recorder.Code)
}
