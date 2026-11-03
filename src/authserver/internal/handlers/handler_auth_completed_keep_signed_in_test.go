package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// /auth/completed records the answer the password page's Keep me signed in box was given in the
// browser session when the ceremony entered the password, on either arm, so the session's cookie
// follows it from then on; a password entered with no box records no answer, and a single sign-on
// that entered no password leaves the answer the session holds (#743 decisions 2 and 5).

// keepSignedInAnswers is the box ticked, left unticked, and not shown.
func keepSignedInAnswers() map[string]*bool {
	ticked, unticked := true, false
	return map[string]*bool{"ticked": &ticked, "unticked": &unticked, "no box": nil}
}

// reuseArmCompletion arms a ceremony completing over the browser's own valid level 1 session, at a
// level 1 client asking no consent, up to the bind and the audit record. With passwordEntered the
// ceremony verified the password (prompt=login), so the bind replaces the session's authentication;
// without it, it is a single sign-on. The bind raises nothing, so nothing is rotated.
func reuseArmCompletion(t *testing.T, passwordEntered bool, answer *bool) (http.Handler, *handlersmocks.CeremonyStore,
	*handlersmocks.PageRenderer, *httptest.ResponseRecorder, *http.Request) {

	t.Helper()
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	permissionChecker := handlersmocks.NewPermissionChecker(t)

	handler := buildAuthCompletedGet(authCompletedGetDeps{
		pageRenderer:       pageRenderer,
		ceremonyStore:      ceremonyStore,
		userSessionManager: userSessionManager,
		database:           database,
		templateFS:         fstest.MapFS{},
		auditLogger:        auditLogger,
		permissionChecker:  permissionChecker,
	})

	req, _ := http.NewRequest("GET", "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	sessionIdentifier := "test-session"
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
	rr := httptest.NewRecorder()

	sessionAuthTime := time.Now().UTC().Add(-time.Hour)
	authContext := &ceremony.AuthContext{
		CeremonyId:   testCeremonyId,
		AuthState:    ceremony.AuthStateAuthenticationCompleted,
		ClientId:     "test-client",
		UserId:       1,
		Scope:        "openid",
		AuthMethods:  "pwd",
		KeepSignedIn: answer,
	}
	if passwordEntered {
		pwdAuthTime := time.Now().UTC().Add(-time.Minute)
		authContext.AuthenticatedAt = &pwdAuthTime
		authContext.PasswordVerifiedAt = &pwdAuthTime
		authContext.Level1AuthCompleted = true
	}
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

	userSession := &record.UserSession{Id: 1, UserId: 1, AcrLevel: record.AcrLevel1, AuthMethods: "pwd",
		AuthTime: sessionAuthTime}
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
	client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1,
		AuthorizationCodeEnabled: true}
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
	userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds,
		mock.AnythingOfType("*int64")).Return(true)
	userSessionManager.On("BindUserSession", mock.Anything, sessionIdentifier, int64(1), mock.Anything,
		passwordEntered, "").Return(userSession, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, mock.Anything).Return()
	user := &record.User{Id: 1, Enabled: true}
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)
	permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", user).
		Return("openid", nil).Maybe()

	return handler, ceremonyStore, pageRenderer, rr, req
}

// A ceremony that entered the password over the browser's own session (prompt=login) records its
// answer once the bind has landed and before the ceremony moves on, so the save that sends it on
// writes the cookie the answer asks for. No box removes an answer an earlier sign-in recorded.
func TestHandleAuthCompletedGet_TheReuseArmRecordsTheAnswerOfAPasswordEntered(t *testing.T) {
	for name, answer := range keepSignedInAnswers() {
		t.Run(name, func(t *testing.T) {
			handler, ceremonyStore, _, rr, req := reuseArmCompletion(t, true, answer)

			var steps []string
			ceremonyStore.On("RecordKeepSignedIn", rr, req, testCeremonyId, answer).Return(nil).Once().
				Run(func(mock.Arguments) { steps = append(steps, "record") })
			ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				return ac.AuthState == ceremony.AuthStateReadyToIssueCode
			})).Return(nil).Once().Run(func(mock.Arguments) { steps = append(steps, "save") })

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, testBaseURL+"/auth/issue?ceremony="+testCeremonyId, rr.Header().Get("Location"))
			assert.Equal(t, []string{"record", "save"}, steps, "the answer is recorded before the ceremony moves on")
			ceremonyStore.AssertExpectations(t)
		})
	}
}

// A single sign-on entered no password, so the browser session keeps the answer it holds.
func TestHandleAuthCompletedGet_ASingleSignOnRecordsNoAnswer(t *testing.T) {
	for name, answer := range keepSignedInAnswers() {
		t.Run(name, func(t *testing.T) {
			handler, ceremonyStore, _, rr, req := reuseArmCompletion(t, false, answer)
			ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			ceremonyStore.AssertNotCalled(t, "RecordKeepSignedIn", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertExpectations(t)
		})
	}
}

// The record lands only while the browser session still holds the ceremony; one it no longer holds
// is answered as every step of a replaced ceremony is, and the ceremony is not moved on.
func TestHandleAuthCompletedGet_ARecordFindingTheCeremonyReplacedAnswersNoLongerActive(t *testing.T) {
	ticked := true
	handler, ceremonyStore, pageRenderer, rr, req := reuseArmCompletion(t, true, &ticked)
	ceremonyStore.On("RecordKeepSignedIn", rr, req, testCeremonyId, &ticked).Return(ceremony.ErrCeremonyReplaced).Once()
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	pageRenderer.AssertExpectations(t)
}

// The create arm records the answer in the rotation that binds the new session, so the sign-in's
// one cookie already follows it.
func TestHandleAuthCompletedGet_TheCreateArmRecordsTheAnswerAsItBinds(t *testing.T) {
	for name, answer := range keepSignedInAnswers() {
		t.Run(name, func(t *testing.T) {
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)

			handler := buildAuthCompletedGet(authCompletedGetDeps{
				pageRenderer:       handlersmocks.NewPageRenderer(t),
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				templateFS:         fstest.MapFS{},
				auditLogger:        auditLogger,
				permissionChecker:  permissionChecker,
			})

			req, _ := http.NewRequest("GET", "/auth/completed?ceremony="+testCeremonyId, nil)
			req = withSessionSettings(req)
			sessionIdentifier := "pre-sign-in-session"
			req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
			rr := httptest.NewRecorder()

			pwdAuthTime := time.Now().UTC().Add(-time.Minute)
			authContext := &ceremony.AuthContext{
				CeremonyId:          testCeremonyId,
				AuthState:           ceremony.AuthStateAuthenticationCompleted,
				ClientId:            "test-client",
				UserId:              1,
				Scope:               "openid",
				AuthMethods:         "pwd",
				AuthenticatedAt:     &pwdAuthTime,
				PasswordVerifiedAt:  &pwdAuthTime,
				Level1AuthCompleted: true,
				KeepSignedIn:        answer,
			}
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(nil, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil)
			client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1,
				AuthorizationCodeEnabled: true}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
			userSessionManager.On("HasValidUserSession", (*record.UserSession)(nil), testIdleTimeoutInSeconds,
				testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(false)
			newSession := &record.UserSession{Id: 2, SessionIdentifier: "new-session-of-user-1", UserId: 1,
				AcrLevel: record.AcrLevel1, AuthTime: pwdAuthTime}
			userSessionManager.On("StartNewUserSession", mock.Anything, int64(1), mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, "", (*record.UserSession)(nil), testSessionLimits).Return(newSession, nil, nil)
			expectCeremonyConfirmed(ceremonyStore, rr, req)
			ceremonyStore.On("RegenerateSessionAndBind", rr, req, testCeremonyId, int64(1), "new-session-of-user-1",
				answer).Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventStartedNewUserSession, mock.Anything).Return()
			user := &record.User{Id: 1, Enabled: true}
			database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)
			permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", user).Return("openid", nil)
			ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, testBaseURL+"/auth/issue?ceremony="+testCeremonyId, rr.Header().Get("Location"))
			ceremonyStore.AssertNotCalled(t, "RecordKeepSignedIn", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertExpectations(t)
		})
	}
}
