package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// The two restart routes send a ceremony back to requires_level_1 through AuthContext.Restart,
// which keeps the request and discards the attempt (#140, #436). ceremony's own tests own the
// field-by-field table; these pin that each route really calls it, by asserting on the context it
// saves against a literal written out here rather than against Restart applied to a copy, which
// would pass whatever Restart did.

// abandonedAttempt is a ceremony that has authenticated somebody, with every attempt field the
// route can meet carrying a value: methods from a session that has since ended, a Scope narrowed
// below RequestedScope, and the first person's consent.
func abandonedAttempt(state ceremony.AuthState) *ceremony.AuthContext {
	authenticatedAt := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	otpConfigGeneration := int64(4)
	return &ceremony.AuthContext{
		CeremonyId:          testCeremonyId,
		ClientId:            "test-client",
		RedirectURI:         "https://example.com/callback",
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "challenge",
		ResponseMode:        "query",
		State:               "some-state",
		Nonce:               "some-nonce",
		UserAgent:           "probe/1.0",
		IpAddress:           "203.0.113.7",
		UILocales:           []string{"pt-BR"},
		Prompt:              "login",
		TargetAcrLevel:      record.AcrLevel1.String(),
		RequestedScope:      "openid profile email",

		AuthState:           state,
		Scope:               "openid profile",
		ConsentedScope:      "openid",
		UserId:              1,
		AcrLevel:            record.AcrLevel2Optional,
		AuthMethods:         "pwd otp",
		AuthenticatedAt:     &authenticatedAt,
		Level1AuthCompleted: false,
		AuthStateGeneration: 7,
		OtpConfigGeneration: &otpConfigGeneration,
	}
}

// restartedRequest is abandonedAttempt after a restart: the request as it was, Scope put back to
// RequestedScope, the state requires_level_1 and nothing else.
func restartedRequest() ceremony.AuthContext {
	return ceremony.AuthContext{
		CeremonyId:          testCeremonyId,
		ClientId:            "test-client",
		RedirectURI:         "https://example.com/callback",
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "challenge",
		ResponseMode:        "query",
		State:               "some-state",
		Nonce:               "some-nonce",
		UserAgent:           "probe/1.0",
		IpAddress:           "203.0.113.7",
		UILocales:           []string{"pt-BR"},
		Prompt:              "login",
		TargetAcrLevel:      record.AcrLevel1.String(),
		RequestedScope:      "openid profile email",

		AuthState: ceremony.AuthStateRequiresLevel1,
		Scope:     "openid profile email",
	}
}

func TestRestartRoute1_SavesTheRequestWithTheAttemptDiscarded(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	permissionChecker := handlersmocks.NewPermissionChecker(t)

	handler := HandleAuthCompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, fstest.MapFS{},
		auditLogger, permissionChecker, testBaseURL, testAdminConsoleBaseURL)

	sessionIdentifier := "terminated-session"
	req, _ := http.NewRequest("GET", "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
	rr := httptest.NewRecorder()

	// An SSO ceremony whose session ended before /auth/completed: its methods came off that
	// session and no password was entered, so Level1AuthCompleted is false and this is route 1.
	ceremonyStore.On("GetAuthContext", mock.Anything).
		Return(abandonedAttempt(ceremony.AuthStateAuthenticationCompleted), nil)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(nil, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}, nil)
	userSessionManager.On("HasValidUserSession", (*record.UserSession)(nil), testIdleTimeoutInSeconds,
		testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(false)

	var saved *ceremony.AuthContext
	ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Run(func(args mock.Arguments) {
		saved = args.Get(2).(*ceremony.AuthContext)
	}).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, testCeremonyId, assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1"),
		"the restart goes on naming the ceremony it kept")
	require.NotNil(t, saved)
	assert.Equal(t, restartedRequest(), *saved)
}

func TestRestartRoute2_SavesTheRequestWithTheAttemptDiscarded(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	codeIssuer := handlersmocks.NewCodeIssuer(t)
	implicitTokenIssuer := handlersmocks.NewImplicitTokenIssuer(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	permissionChecker := handlersmocks.NewPermissionChecker(t)

	handler := HandleIssueGet(pageRenderer, ceremonyStore, fstest.MapFS{}, codeIssuer, implicitTokenIssuer,
		database, auditLogger, userSessionManager, permissionChecker, testTokenMetrics(), testBaseURL, testAdminConsoleBaseURL)

	// The session this ceremony bound to at /auth/completed is gone by /auth/issue, and the
	// request is interactive, so this is route 2.
	req := requestWithSessionIdentifier(t, liveSessionIdentifier)
	rr := httptest.NewRecorder()

	attempt := abandonedAttempt(ceremony.AuthStateReadyToIssueCode)
	attempt.Level1AuthCompleted = true
	ceremonyStore.On("GetAuthContext", req).Return(attempt, nil)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), liveSessionIdentifier).Return(nil, nil)
	armIssueGate(database, userSessionManager, permissionChecker, attempt.RedirectURI)

	var saved *ceremony.AuthContext
	ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Run(func(args mock.Arguments) {
		saved = args.Get(2).(*ceremony.AuthContext)
	}).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, testCeremonyId, assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1"),
		"the restart goes on naming the ceremony it kept")
	require.NotNil(t, saved)
	assert.Equal(t, restartedRequest(), *saved)
}

// TestAuthCompleted_ALegacyRestartedContextIsDeniedAnEmptyScope is where a context written before
// RequestedScope existed goes after a restart: Restart put Scope back to "", the password was
// entered, and /auth/completed filters an empty scope. The real permission checker is used over the
// strict mock database, so the case also shows an empty scope reaches no permission query. The
// answer is the existing access_denied refusal with the context cleared first; nothing is saved and
// nothing is issued. That is decision 2's no-fallback rule met at the hop that enforces it (#436).
func TestAuthCompleted_ALegacyRestartedContextIsDeniedAnEmptyScope(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	database := datamocks.NewDatabase(t)
	stubRegisteredRedirectURI(database, "https://example.com/callback")
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleAuthCompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, fstest.MapFS{},
		auditLogger, permissions.NewChecker(database), testBaseURL, testAdminConsoleBaseURL)

	sessionIdentifier := "new-test-session"
	req, _ := http.NewRequest("GET", "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
	rr := httptest.NewRecorder()

	pwdAuthTime := time.Now().UTC().Add(-time.Minute)
	authContext := &ceremony.AuthContext{
		CeremonyId:          testCeremonyId,
		AuthState:           ceremony.AuthStateAuthenticationCompleted,
		ClientId:            "test-client",
		RedirectURI:         "https://example.com/callback",
		ResponseMode:        "query",
		State:               "some-state",
		UserId:              1,
		AuthMethods:         "pwd",
		AuthenticatedAt:     &pwdAuthTime,
		Level1AuthCompleted: true,
	}
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(nil, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1,
			AuthorizationCodeEnabled: true}, nil)
	userSessionManager.On("HasValidUserSession", (*record.UserSession)(nil), testIdleTimeoutInSeconds,
		testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(false)
	userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", record.AcrLevel1, int64(0),
		(*int64)(nil), &pwdAuthTime, "", (*record.UserSession)(nil)).
		Return(&record.UserSession{Id: 1, UserId: 1, AcrLevel: record.AcrLevel1, AuthTime: pwdAuthTime}, nil, nil)
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1, Enabled: true}, nil)

	const clearedContextCookie = "cleared-auth-context"
	ceremonyStore.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
		args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
	}).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location, err := rr.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/callback", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, "access_denied", location.Query().Get("error"))
	assert.Equal(t, "some-state", location.Query().Get("state"))
	assert.Empty(t, location.Query().Get("code"))
	assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"))
	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
}
