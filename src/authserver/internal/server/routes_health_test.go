package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// /health answers 200 healthy with the database down, through every route Start registers (#390
// decision 1). The liveness, readiness and startup probes all point at it, so a short database
// outage must not fail it: on the application branch it read the settings row first and answered
// 500, and liveness then restarted every pod at once. The handler's own test cannot see this,
// because which middleware the endpoint passes through is a property of where it is registered.
//
// The database fails every settings read and every session read, and a session cookie is sent,
// so either middleware reached would answer 500; the settings read is then denied outright.
func TestRegisterRoutes_HealthAnswersWithTheDatabaseDown(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(nil, errors.New("the database is down")).Maybe()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, errors.New("the database is down")).Maybe()

	s := newStaticBranchTestServer(database)
	s.templateFS = web.TemplateFS()
	s.registerRoutes()

	mint := httptest.NewRequest(http.MethodGet, "/", nil)
	minted := httptest.NewRecorder()
	session, err := s.sessionStore.Get(mint, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.SessionIdentifier] = "sid-1"
	require.NoError(t, s.sessionStore.Save(mint, minted, session))
	cookies := minted.Result().Cookies()
	require.NotEmpty(t, cookies, "the store must have set the session cookie")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "healthy", rr.Body.String())
	database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, int64(1))
	database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
}

// The other half: the same server's application routes still read the settings, so the case
// above is not satisfied by a database the router never reaches.
func TestRegisterRoutes_ApplicationRoutesStillFailWithTheDatabaseDown(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(nil, errors.New("the database is down")).Once()

	s := newStaticBranchTestServer(database)
	s.templateFS = web.TemplateFS()
	s.registerRoutes()

	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
}
