package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
)

// completedFixture is /auth/completed built from strict doubles, with a request carrying the session
// settings and the browser's session identifier, completedSessionIdentifier.
type completedFixture struct {
	pageRenderer       *handlersmocks.PageRenderer
	ceremonyStore      *handlersmocks.CeremonyStore
	userSessionManager *handlersmocks.UserSessionManager
	database           *datamocks.Database
	auditLogger        *handlersmocks.AuditLogger
	permissionChecker  *handlersmocks.PermissionChecker
	rr                 *httptest.ResponseRecorder
	req                *http.Request
	handler            http.HandlerFunc
}

const completedSessionIdentifier = "test-session"

// consentManageAccountScope is authserver:manage-account as a request spells it. The consent docs
// guard that owned the spelling moved to authflow with the decision it holds (#584), so this file
// names the scope itself.
const consentManageAccountScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

func newCompletedFixture(t *testing.T, authContext *ceremony.AuthContext) *completedFixture {
	f := &completedFixture{
		pageRenderer:       handlersmocks.NewPageRenderer(t),
		ceremonyStore:      handlersmocks.NewCeremonyStore(t),
		userSessionManager: handlersmocks.NewUserSessionManager(t),
		database:           datamocks.NewDatabase(t),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
		rr:                 httptest.NewRecorder(),
	}
	f.handler = buildAuthCompletedGet(authCompletedGetDeps{
		pageRenderer:       f.pageRenderer,
		ceremonyStore:      f.ceremonyStore,
		userSessionManager: f.userSessionManager,
		database:           f.database,
		templateFS:         fstest.MapFS{},
		auditLogger:        f.auditLogger,
		permissionChecker:  f.permissionChecker,
	})
	req, _ := http.NewRequest("GET", "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	f.req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), completedSessionIdentifier))
	f.ceremonyStore.On("GetAuthContext", f.req).Return(authContext, nil).Once()
	return f
}

// ssoCeremony is a ceremony that adopted the browser's session at /auth/authorize: it entered no
// credential, and its user is user 1.
func ssoCeremony(scope string) *ceremony.AuthContext {
	return &ceremony.AuthContext{
		CeremonyId: testCeremonyId,
		AuthState:  ceremony.AuthStateAuthenticationCompleted,
		ClientId:   "test-client",
		UserId:     1,
		Scope:      scope,
	}
}

// expectReusableSession arms the reads of an SSO pass up to the decision: user 1's level 1 session,
// valid, and a level 1 client. It answers the session.
func (f *completedFixture) expectReusableSession(clientIdentifier string) *record.UserSession {
	userSession := &record.UserSession{Id: 9, UserId: 1, AcrLevel: record.AcrLevel1,
		AuthTime: time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)}
	f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, completedSessionIdentifier).
		Return(userSession, nil).Once()
	f.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil).Once()
	f.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: clientIdentifier, DefaultAcrLevel: record.AcrLevel1}, nil).Once()
	f.userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds,
		mock.AnythingOfType("*int64")).Return(true).Once()
	return userSession
}

// expectBoundSSO arms the rest of the reuse arm for an SSO pass of an enabled user 1: the user read
// and the bind, which answers bound, and the audit record of the bump.
func (f *completedFixture) expectBoundSSO(bound *record.UserSession) *record.User {
	user := &record.User{Id: 1, Enabled: true}
	f.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
	f.userSessionManager.On("BindUserSession", mock.Anything, completedSessionIdentifier, int64(1),
		boundWith("", record.AcrLevel1), false, mock.Anything).Return(bound, nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, mock.Anything).Return().Once()
	return user
}

func (f *completedFixture) expect500(err interface{}) {
	f.pageRenderer.On("InternalServerError", f.rr, f.req, err).Return().Once()
}

func (f *completedFixture) assertNothingSaved(t *testing.T) {
	f.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	f.ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything, mock.Anything)
}

// /auth/completed reads its settings at the route boundary before anything else, so a request
// reaching it without them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing, not
// even its ceremony (#580 decision 5).
func TestMissingSettings_AuthCompletedAnswersBeforeReadingItsCeremony(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/completed?ceremony="+testCeremonyId, nil)
	rr := httptest.NewRecorder()
	pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	buildAuthCompletedGet(authCompletedGetDeps{
		pageRenderer:       pageRenderer,
		ceremonyStore:      ceremonyStore,
		userSessionManager: userSessionManager,
		database:           database,
		auditLogger:        handlersmocks.NewAuditLogger(t),
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
	}).ServeHTTP(rr, req)

	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	userSessionManager.AssertNotCalled(t, "HasValidUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Each load /auth/completed makes before it decides answers the 500 page when it fails, and reads
// nothing after it: the next load, the session validity check and the user are never reached, and
// nothing is bound or saved.
func TestHandleAuthCompletedGet_ALoadFailingBeforeTheDecisionAnswers500(t *testing.T) {
	failure := errors.New("read failed")

	t.Run("the browser's session", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, completedSessionIdentifier).
			Return(nil, failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.database.AssertNotCalled(t, "UserSessionLoadUser", mock.Anything, mock.Anything, mock.Anything)
		f.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("the session's user", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		userSession := &record.UserSession{Id: 9, UserId: 1}
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, completedSessionIdentifier).
			Return(userSession, nil).Once()
		f.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("the client", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		userSession := &record.UserSession{Id: 9, UserId: 1}
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, completedSessionIdentifier).
			Return(userSession, nil).Once()
		f.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil).Once()
		f.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.userSessionManager.AssertNotCalled(t, "HasValidUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("the ceremony's user", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		f.expectReusableSession("test-client")
		f.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.userSessionManager.AssertNotCalled(t, "BindUserSession", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything)
		f.ceremonyStore.AssertNotCalled(t, "RegenerateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		f.assertNothingSaved(t)
	})
}

// A load or a check after the bind that fails answers the 500 page and saves nothing, so the
// ceremony goes neither to the consent screen nor to issuance.
func TestHandleAuthCompletedGet_AFailureAfterTheBindAnswers500(t *testing.T) {
	failure := errors.New("read failed")

	t.Run("the bound session's level does not parse", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		userSession := f.expectReusableSession("test-client")
		bound := *userSession
		bound.AcrLevel = "urn:goiabada:no-such-level"
		f.expectBoundSSO(&bound)
		f.expect500(mock.MatchedBy(func(err error) bool { return err != nil }))

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.permissionChecker.AssertNotCalled(t, "FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, mock.Anything,
			mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("the scope filter", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		userSession := f.expectReusableSession("test-client")
		user := f.expectBoundSSO(userSession)
		f.permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", user).
			Return("", failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.database.AssertNotCalled(t, "GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("the stored consent", func(t *testing.T) {
		scope := "openid " + consentManageAccountScope
		f := newCompletedFixture(t, ssoCeremony(scope))
		userSession := f.expectReusableSession("test-client")
		user := f.expectBoundSSO(userSession)
		f.permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, scope, user).
			Return(scope, nil).Once()
		f.database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).
			Return(nil, failure).Once()
		f.expect500(failure)

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.assertNothingSaved(t)
	})
}

// authserver:manage-account is owed a consent whatever the client says, so /auth/completed reads the
// user's stored consent for it, and only for it: covered, the ceremony goes on to issuance, and not
// covered, to the consent screen (#509). The admin console's own client is exempt and reads nothing.
func TestHandleAuthCompletedGet_TheStoredConsentDecidesAManageAccountScope(t *testing.T) {
	scope := "openid " + consentManageAccountScope

	for _, tc := range []struct {
		name      string
		consent   *record.UserConsent
		wantState ceremony.AuthState
		wantStep  string
	}{
		{"a stored consent covering it goes on to issuance", &record.UserConsent{Scope: scope},
			ceremony.AuthStateReadyToIssueCode, "/auth/issue"},
		{"a stored consent not covering it goes to the consent screen", &record.UserConsent{Scope: "openid"},
			ceremony.AuthStateRequiresConsent, "/auth/consent"},
		{"no stored consent goes to the consent screen", nil,
			ceremony.AuthStateRequiresConsent, "/auth/consent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCompletedFixture(t, ssoCeremony(scope))
			userSession := f.expectReusableSession("test-client")
			user := f.expectBoundSSO(userSession)
			f.permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, scope, user).
				Return(scope, nil).Once()
			f.database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).
				Return(tc.consent, nil).Once()
			f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				return ac.AuthState == tc.wantState
			})).Return(nil).Once()

			f.handler.ServeHTTP(f.rr, f.req)

			assert.Equal(t, http.StatusFound, f.rr.Code)
			assert.Equal(t, testBaseURL+tc.wantStep+"?ceremony="+testCeremonyId, f.rr.Header().Get("Location"))
			f.ceremonyStore.AssertExpectations(t)
			f.database.AssertExpectations(t)
		})
	}

	t.Run("the admin console's client reads no consent", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony(scope))
		userSession := f.expectReusableSession(builtin.AdminConsoleClientIdentifier)
		user := f.expectBoundSSO(userSession)
		f.permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, scope, user).
			Return(scope, nil).Once()
		f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateReadyToIssueCode
		})).Return(nil).Once()

		f.handler.ServeHTTP(f.rr, f.req)

		assert.Equal(t, testBaseURL+"/auth/issue?ceremony="+testCeremonyId, f.rr.Header().Get("Location"))
		f.database.AssertNotCalled(t, "GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything)
	})
}

// hasNoAuthTime matches the refusal of a bound session that carries no auth time.
func hasNoAuthTime(err error) bool {
	return err != nil && strings.Contains(err.Error(), "has no auth time")
}

// The session a ceremony binds to is where its auth_time comes from, and one with a zero AuthTime
// has none to give. That cannot be stored: StartNewUserSession refuses a zero instant and migration
// 000062 ended every older session. If it ever is, /auth/completed answers 500 and the ceremony goes
// no further, so nothing is issued with a zero auth_time or one invented from the session's start
// (#580 decision 5, as #252 decision 8 refuses a missing credential instant).
func TestHandleAuthCompletedGet_ABoundSessionWithNoAuthTimeIsRefused(t *testing.T) {
	t.Run("reuse arm", func(t *testing.T) {
		f := newCompletedFixture(t, ssoCeremony("openid"))
		userSession := f.expectReusableSession("test-client")
		bound := *userSession
		bound.AuthTime = time.Time{}
		bound.Started = time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
		f.expectBoundSSO(&bound)
		f.expect500(mock.MatchedBy(hasNoAuthTime))

		f.handler.ServeHTTP(f.rr, f.req)

		f.pageRenderer.AssertExpectations(t)
		f.permissionChecker.AssertNotCalled(t, "FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, mock.Anything,
			mock.Anything)
		f.assertNothingSaved(t)
	})

	t.Run("create arm", func(t *testing.T) {
		passwordAt := time.Date(2026, 10, 14, 8, 30, 0, 0, time.UTC)
		authContext := &ceremony.AuthContext{
			CeremonyId:          testCeremonyId,
			AuthState:           ceremony.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid",
			AuthMethods:         "pwd",
			AuthenticatedAt:     &passwordAt,
			PasswordVerifiedAt:  &passwordAt,
			Level1AuthCompleted: true,
		}
		f := newCompletedFixture(t, authContext)
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, completedSessionIdentifier).
			Return(nil, nil).Once()
		f.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil).Once()
		f.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
			Return(&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}, nil).Once()
		f.userSessionManager.On("HasValidUserSession", (*record.UserSession)(nil), testIdleTimeoutInSeconds,
			testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(false).Once()
		f.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
			Return(&record.User{Id: 1, Enabled: true}, nil).Once()
		expectCeremonyConfirmed(f.ceremonyStore, f.rr, f.req)
		started := &record.UserSession{Id: 12, SessionIdentifier: "new-session-of-user-1", UserId: 1, AcrLevel: record.AcrLevel1,
			Started: time.Date(2026, 10, 14, 8, 31, 0, 0, time.UTC)}
		var minted string
		f.userSessionManager.On("StartNewUserSession", theContextOf(f.req), int64(1),
			signedInAs(int64(1), "pwd", record.AcrLevel1, &passwordAt), int64(0), (*int64)(nil), aNewDeviceOf(f.req, &minted), "",
			(*record.UserSession)(nil), testSessionLimits).Return(started, nil, nil).Once()
		expectNewSessionBound(f.ceremonyStore, f.rr, f.req, 1, "new-session-of-user-1")
		f.auditLogger.On("Log", mock.Anything, audit.EventStartedNewUserSession, mock.Anything).Return().Once()
		f.expect500(mock.MatchedBy(hasNoAuthTime))

		f.handler.ServeHTTP(f.rr, f.req)

		assert.Equal(t, minted, deviceCookieOf(t, f.rr).Value, "the session was bound before its auth time was read")
		f.pageRenderer.AssertExpectations(t)
		f.userSessionManager.AssertExpectations(t)
		f.permissionChecker.AssertNotCalled(t, "FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, mock.Anything,
			mock.Anything)
		f.assertNothingSaved(t)
	})
}
