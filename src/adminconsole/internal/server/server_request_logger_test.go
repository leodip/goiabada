package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/config"
)

// TestInitMiddleware_RequestLoggerIsRegistered makes the claim the unit table in
// src/core/middleware cannot: that MiddlewareRequestLogger is actually mounted on the admin
// console's router, and that it is wired to the configuration flag rather than mounted with a
// constant. That table passes perfectly against a middleware nobody wired up, and deleting the
// Use() line here still compiles, because the package references custom_middleware on five other
// lines. The admin console also has no integration suite of its own, so there is no running-server
// test to catch it either.
//
// It is deliberately thin, for the same reason its auth server twin is: the middleware's behaviour
// belongs to its own tests in src/core/middleware, and the redaction table belongs to
// RequestTargetForLog. This owns one claim, that a real request through this server's real chain
// produces a log line and that the line carries no token (#159).

// jwtLike is the three-segment shape a token arrives in. Nothing on the admin console issues one,
// which is the point: an unassessed parameter is redacted by construction, whatever it holds.
const jwtLike = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlBST0JFIn0." +
	"eyJzdWIiOiJVU0VSLVNVQiIsInNpZCI6IlNFU1NJT04tSUQifQ.U0lHTkFUVVJF"

// The target carries two allowlisted parameters and one that is not, so the assertions below can
// tell "the token was redacted" apart from "nothing was logged at all".
const loggerTestTarget = "/admin/clients?page=2&size=10&id_token_hint=" + jwtLike

// withLogHttpRequests sets the flag for the duration of the test and restores it. It has to run
// before initMiddleware, which is when the value is read.
func withLogHttpRequests(t *testing.T, enabled bool) {
	t.Helper()
	previous := config.GetAdminConsole().LogHttpRequests
	config.GetAdminConsole().LogHttpRequests = enabled
	t.Cleanup(func() {
		config.GetAdminConsole().LogHttpRequests = previous
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
// Unlike server_csrf_test.go, which points the settings cache at an address nothing listens on,
// this one serves /api/public/settings from a local httptest server. MiddlewareSettingsCache
// answers 500 and returns on a fetch failure, so an unreachable auth server would stop the request
// before the handler, and "the request still reached the handler" is exactly the half of this test
// that says the logger did not swallow it.
func newLoggerTestServer(t *testing.T, logHttpRequests bool, handlerRan *bool) *Server {
	t.Helper()
	withLogHttpRequests(t, logHttpRequests)

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada Test","uiTheme":"light","smtpEnabled":false}`))
	}))
	t.Cleanup(authServer.Close)

	s := &Server{
		router:        chi.NewRouter(),
		sessionStore:  sessions.NewCookieStore(securecookie.GenerateRandomKey(64)),
		settingsCache: cache.NewSettingsCache(authServer.URL),
	}
	s.initMiddleware()
	s.router.Get("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
		*handlerRan = true
		w.WriteHeader(http.StatusOK)
	})
	return s
}

func TestInitMiddleware_RequestLoggerIsRegistered(t *testing.T) {
	handlerRan := false
	server := newLoggerTestServer(t, true, &handlerRan)
	logged := captureSlog(t)

	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, loggerTestTarget, nil))

	// The handler at the far end of the chain answered, so the logger did not swallow the request
	// on its way through. Without this the assertions below are satisfied by a chain that broke.
	if !handlerRan || recorder.Code != http.StatusOK {
		t.Fatalf("handlerRan = %v, status = %d, want true and %d: the request must still be served",
			handlerRan, recorder.Code, http.StatusOK)
	}

	output := logged.String()
	if got := strings.Count(output, `msg="http request"`); got != 1 {
		t.Fatalf("got %d request log records, want 1: MiddlewareRequestLogger must be mounted on "+
			"the admin console", got)
	}

	// The allowlisted values survived, which is what attributes the absence below to redaction
	// rather than to an empty log.
	for _, want := range []string{"page=2", "size=10", "id_token_hint=[redacted]"} {
		if !strings.Contains(output, want) {
			t.Errorf("the log record does not contain %q:\n%s", want, output)
		}
	}

	if strings.Contains(output, jwtLike) {
		t.Errorf("the token was written to the log, which is the whole of #159:\n%s", output)
	}
}

// Without this the test above passes against a Use() line that mounts the middleware with a
// constant true, which is the one way to get this wiring wrong that still redacts correctly.
func TestInitMiddleware_RequestLoggerHonoursTheFlag(t *testing.T) {
	handlerRan := false
	server := newLoggerTestServer(t, false, &handlerRan)
	logged := captureSlog(t)

	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, loggerTestTarget, nil))

	if got := strings.Count(logged.String(), `msg="http request"`); got != 0 {
		t.Errorf("got %d request log records, want 0: nothing is logged when "+
			"GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS is off", got)
	}
	// The other half: a middleware that dropped the request would also log nothing.
	if !handlerRan || recorder.Code != http.StatusOK {
		t.Errorf("handlerRan = %v, status = %d: the request must still be served with the flag off",
			handlerRan, recorder.Code)
	}
}
