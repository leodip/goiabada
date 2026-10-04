package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
)

// /health answers 200 healthy with the auth server down, through every route Start registers
// (#390 decision 1). The liveness, readiness and startup probes all point at it, so an auth server
// outage must not fail it: on the application branch it went through the settings cache, which
// fetches from the auth server once its entry expires and answers 500 when that fails, and
// liveness then restarted every admin console pod at once. The handler's own test cannot see
// this, because which middleware the endpoint passes through is a property of where it is
// registered.
//
// A session cookie is sent too, so the session load behind the settings cache would be counted if
// /health ever reached it.
func TestRegisterRoutes_HealthAnswersWithTheAuthServerDown(t *testing.T) {
	authServer := newFailingSettingsServer(t)
	backend := &countingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store := newTestSessionStoreOver(backend)
	cookie := seedSession(t, store)

	s := newStaticBranchTestServer(authServer.URL, store)
	s.templateFS = web.TemplateFS()
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "healthy", rr.Body.String())
	assert.Zero(t, authServer.fetches.Load(), "a health check must not fetch the settings")
	assert.Zero(t, backend.loads.Load(), "nor load the session, which is a call to the auth server")
}

// The other half: the same server's application routes still fetch the settings and fail, so the
// case above is not satisfied by an auth server the router never calls.
func TestRegisterRoutes_ApplicationRoutesStillFailWithTheAuthServerDown(t *testing.T) {
	authServer := newFailingSettingsServer(t)

	s := newStaticBranchTestServer(authServer.URL, newTestSessionStore())
	s.templateFS = web.TemplateFS()
	s.registerRoutes()

	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/unauthorized", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, int64(1), authServer.fetches.Load())
}

// failingSettingsServer is an auth server whose public settings endpoint answers 500, counting how
// often it was asked.
type failingSettingsServer struct {
	*httptest.Server
	fetches atomic.Int64
}

func newFailingSettingsServer(t *testing.T) *failingSettingsServer {
	t.Helper()

	failing := &failingSettingsServer{}
	failing.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failing.fetches.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)

	return failing
}
