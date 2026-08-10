package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
)

func TestHandleAuthCompletedGet(t *testing.T) {
	t.Run("Successful flow, existing session (SSO reuse), consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil (not set by password handler)
		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateAuthenticationCompleted,
			ClientId:  "test-client",
			UserId:    1,
			Scope:     "openid profile",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// =====================================================================================
	// A ceremony binds only to a session belonging to the user it authenticated (#133).
	//
	// The three subtests below are one condition seen from its three sides: a foreign session
	// that is still valid, a foreign session that is not, and a same-user session that is not.
	// The first two must be terminated and replaced, the third must be replaced and NOT
	// terminated, and it is the third that stops termination from widening into "any session
	// the create arm found", which would revoke a user's own offline grants on an ordinary
	// expired-session login.
	//
	// Every one of them gives the ambient session a HIGHER ACR than the target, which is what
	// makes the acr assertion mean something: with the ambient session fed to SetAcrLevel the
	// context would leave carrying level2_mandatory, and with the bound session it leaves
	// carrying level1, the only level anyone proved in this ceremony.
	// =====================================================================================

	// crossUserTerminateTx is an opaque non-nil transaction. Letting BeginTransaction return nil
	// would exercise a shape production never runs.
	crossUserTerminateTx := &sql.Tx{}

	// stubCrossUserTermination registers the six calls TerminateUserSessionTx and
	// revokeRefreshTokens make for one session. Thin on purpose: revocation_test.go owns the
	// exhaustive termination table, and restating it here would mean two places to update.
	// RollbackTransaction is included because the deferred rollback runs on the success path too,
	// where it is a no-op against a committed transaction; a test omitting it fails on the strict
	// mock.
	//
	// record, when non-nil, is called with "commit" at the moment CommitTransaction returns, so a
	// subtest can pin the audit events against the transaction boundary they are documented to
	// follow. Nothing else observes ordering: the strict mock records that a call happened, not
	// when.
	stubCrossUserTermination := func(database *mocks_data.Database, userSession *models.UserSession,
		revokedCodeCount int64, tokens []*models.RefreshToken, record func(string)) {

		database.On("BeginTransaction").Return(crossUserTerminateTx, nil).Once()
		database.On("RevokeCodesBySessionIdentifier", crossUserTerminateTx, userSession.SessionIdentifier).
			Return(revokedCodeCount, nil).Once()
		database.On("GetRefreshTokensBySessionIdentifier", crossUserTerminateTx, userSession.SessionIdentifier).
			Return(tokens, nil).Once()
		for i := range tokens {
			jti := tokens[i].RefreshTokenJti
			database.On("UpdateRefreshToken", crossUserTerminateTx, mock.MatchedBy(func(rt *models.RefreshToken) bool {
				return rt.RefreshTokenJti == jti
			})).Return(nil).Once()
		}
		database.On("DeleteUserSession", crossUserTerminateTx, userSession.Id).Return(nil).Once()
		database.On("CommitTransaction", crossUserTerminateTx).Return(nil).
			Run(func(mock.Arguments) {
				if record != nil {
					record("commit")
				}
			}).Once()
		database.On("RollbackTransaction", crossUserTerminateTx).Return(nil).Once()
	}

	t.Run("Valid session belonging to another user is terminated and replaced", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// User 2 authenticated in this ceremony, on a browser still cookied to user 1's
		// session: prompt=login and an id_token_hint naming someone else both arrive here
		// in exactly this shape.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              2,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 3,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "session-of-user-1"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		foreignSession := &models.UserSession{
			Id:                7,
			UserId:            1,
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          enums.AcrLevel2Mandatory.String(),
			AuthMethods:       "pwd otp",
			AuthTime:          time.Now().UTC().Add(-10 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(foreignSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, foreignSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// True, so ownership is the only thing keeping this ceremony off the reuse arm. No
		// BumpUserSession expectation is registered anywhere in this subtest, and the mock is
		// strict, so reusing the other user's session fails the case.
		userSessionManager.On("HasValidUserSession", mock.Anything, foreignSession, mock.AnythingOfType("*int")).Return(true)

		// The order in which the handover is written down, which the strict mock does not
		// observe on its own: every audit event has to follow the commit, or an event attests
		// to a termination that could still have rolled back.
		var sequence []string

		stubCrossUserTermination(database, foreignSession, 2, []*models.RefreshToken{
			{Id: 11, RefreshTokenJti: "rt-of-user-1"},
		}, func(step string) { sequence = append(sequence, step) })

		recordEvent := func(args mock.Arguments) { sequence = append(sequence, args.Get(0).(string)) }

		var replacedPayload map[string]interface{}
		auditLogger.On("Log", constants.AuditCrossUserSessionReplaced, mock.Anything).
			Run(func(args mock.Arguments) {
				recordEvent(args)
				replacedPayload = args.Get(1).(map[string]interface{})
			}).Return().Once()
		var deletedPayload map[string]interface{}
		auditLogger.On("Log", constants.AuditDeletedUserSession, mock.Anything).
			Run(func(args mock.Arguments) {
				recordEvent(args)
				deletedPayload = args.Get(1).(map[string]interface{})
			}).Return().Once()
		var terminatedPayload map[string]interface{}
		auditLogger.On("Log", constants.AuditTerminatedUserSession, mock.Anything).
			Run(func(args mock.Arguments) {
				recordEvent(args)
				terminatedPayload = args.Get(1).(map[string]interface{})
			}).Return().Once()
		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).
			Run(recordEvent).Return().Once()

		newAuthTime := time.Now().UTC()
		newSession := &models.UserSession{
			Id:       8,
			UserId:   2,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: newAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(2), int64(1), "pwd",
			enums.AcrLevel1.String(), int64(3)).
			Run(func(mock.Arguments) { sequence = append(sequence, "session-created") }).
			Return(newSession, nil)

		user := &models.User{Id: 2, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(2)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		// level1, the target, rather than the maximum taken with the other user's
		// level2_mandatory. This is the assertion the higher ambient ACR above exists for.
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AcrLevel == enums.AcrLevel1.String() &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(newAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		// The event exists to name both parties: without previousUserId an operator cannot tell
		// a browser changing hands from an administrator ending a session.
		assert.Equal(t, int64(2), replacedPayload["userId"])
		assert.Equal(t, int64(1), replacedPayload["previousUserId"])
		assert.Equal(t, sessionIdentifier, replacedPayload["previousSessionIdentifier"])
		assert.Equal(t, int64(1), replacedPayload["clientId"])

		// The terminated event reports the session that was ended, and its loggedInUser is
		// deliberately empty: the cookie still named user 1 at that instant, so recording it
		// would name the party being terminated as the actor.
		assert.Equal(t, int64(1), terminatedPayload["userId"])
		assert.Equal(t, int64(7), terminatedPayload["userSessionId"])
		assert.Equal(t, sessionIdentifier, terminatedPayload["sessionIdentifier"])
		assert.Equal(t, "", terminatedPayload["loggedInUser"])
		assert.Equal(t, int64(2), terminatedPayload["revokedCodeCount"])
		assert.Equal(t, []string{"rt-of-user-1"}, terminatedPayload["revokedRefreshTokenJtis"])

		// deleted_user_session beside it, the lifecycle record every other caller of
		// TerminateUserSessionTx writes. Without it a handover is the one termination a consumer
		// watching that stream never sees. Its loggedInUser is empty for the same reason.
		assert.Equal(t, int64(7), deletedPayload["userSessionId"])
		assert.Equal(t, "", deletedPayload["loggedInUser"])

		// No audit event before the commit, and the reason before the replacement. An event
		// written before the transaction commits would attest to a termination that could still
		// roll back; started_new_user_session is the only event that says a replacement exists,
		// so it has to follow the session that was actually created.
		assert.Equal(t, []string{
			"commit",
			constants.AuditCrossUserSessionReplaced,
			constants.AuditDeletedUserSession,
			constants.AuditTerminatedUserSession,
			"session-created",
			constants.AuditStartedNewUserSesson,
		}, sequence)

		// The other user's row is not written to, only deleted. A bump would leave it alive
		// carrying this ceremony's auth methods.
		assertNotAttempted(t, database, "UpdateUserSession")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The entry path section 1 of the agreement did not name. MiddlewareSessionIdentifier
	// publishes the ambient identifier whenever the row exists, applying no idle, max lifetime
	// or max_age test, so a session that has stopped being valid still reaches this handler with
	// its cookie intact. Termination must not be nested under validity: a row nobody can resume
	// still has offline refresh tokens that work, and the browser it belongs to has changed
	// hands either way.
	t.Run("Session belonging to another user is terminated even when it is no longer valid", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              2,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 3,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "expired-session-of-user-1"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		foreignSession := &models.UserSession{
			Id:                7,
			UserId:            1,
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          enums.AcrLevel2Mandatory.String(),
			AuthMethods:       "pwd otp",
			AuthTime:          time.Now().UTC().Add(-10 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(foreignSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, foreignSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// Both false this time, which is the whole point of the row.
		userSessionManager.On("HasValidUserSession", mock.Anything, foreignSession, mock.AnythingOfType("*int")).Return(false)

		// No refresh tokens, so the sweep finds nothing and the event still attests that the
		// action happened.
		stubCrossUserTermination(database, foreignSession, 0, nil, nil)

		auditLogger.On("Log", constants.AuditCrossUserSessionReplaced, mock.Anything).Return().Once()
		auditLogger.On("Log", constants.AuditDeletedUserSession, mock.Anything).Return().Once()
		auditLogger.On("Log", constants.AuditTerminatedUserSession, mock.Anything).Return().Once()
		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return().Once()

		newAuthTime := time.Now().UTC()
		newSession := &models.UserSession{
			Id:       8,
			UserId:   2,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: newAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(2), int64(1), "pwd",
			enums.AcrLevel1.String(), int64(3)).Return(newSession, nil)

		user := &models.User{Id: 2, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(2)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AcrLevel == enums.AcrLevel1.String() &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(newAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The control that bounds the termination above. An ordinary sign-in on a session that has
	// idled out arrives here with a non-nil ambient session too, and that one belongs to the
	// person signing in. Terminating it would revoke their own offline refresh tokens and any
	// authorization code they had not yet redeemed, on nothing more than an expired session.
	t.Run("Own session that is no longer valid is replaced but not terminated", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 3,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "expired-session-of-user-1"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		ownSession := &models.UserSession{
			Id:                7,
			UserId:            1,
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          enums.AcrLevel2Mandatory.String(),
			AuthMethods:       "pwd otp",
			AuthTime:          time.Now().UTC().Add(-10 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(ownSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, ownSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, ownSession, mock.AnythingOfType("*int")).Return(false)

		// No termination expectations at all. The mock is strict, so any of the six calls
		// TerminateUserSessionTx makes fails this case, and no cross_user_session_replaced or
		// terminated_user_session event is permitted either.
		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return().Once()

		newAuthTime := time.Now().UTC()
		newSession := &models.UserSession{
			Id:       8,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: newAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd",
			enums.AcrLevel1.String(), int64(3)).Return(newSession, nil)

		user := &models.User{Id: 1, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		// The same-user half of decision 3: the expired row's level2_mandatory does not raise
		// the acr of a token bound to the level1 session this ceremony just created.
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AcrLevel == enums.AcrLevel1.String() &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(newAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		assertNotAttempted(t, database, "BeginTransaction", "RevokeCodesBySessionIdentifier",
			"GetRefreshTokensBySessionIdentifier", "DeleteUserSession")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The failure side of the same condition. A termination that did not commit must stop the
	// ceremony dead: the previous user's grants are still live, so minting a replacement session
	// and an authorization code on top of them would hand the browser to the new user while
	// leaving the old user's refresh tokens working. Both other callers of TerminateUserSessionTx
	// pin exactly this, in TestHandleAPIUserSessionDelete_TerminationFailureIsA500 and
	// TestHandleAPIAccountSessionDelete_TerminationFailureIsA500, and it is the audit suppression
	// that matters as much as the 500: an event written on a rolled-back termination is a false
	// security record.
	t.Run("Termination failure is a 500 with nothing audited and no replacement", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              2,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 3,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "session-of-user-1"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		foreignSession := &models.UserSession{
			Id:                7,
			UserId:            1,
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          enums.AcrLevel2Mandatory.String(),
			AuthMethods:       "pwd otp",
			AuthTime:          time.Now().UTC().Add(-10 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(foreignSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, foreignSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, foreignSession, mock.AnythingOfType("*int")).Return(true)

		// The code sweep fails, which is the first write inside the transaction, so the deferred
		// rollback runs and nothing was committed. Same failure point the two API callers use.
		sweepError := errors.New("the code sweep failed")
		database.On("BeginTransaction").Return(crossUserTerminateTx, nil).Once()
		database.On("RevokeCodesBySessionIdentifier", crossUserTerminateTx, sessionIdentifier).
			Return(int64(0), sweepError).Once()
		database.On("RollbackTransaction", crossUserTerminateTx).Return(nil).Once()

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == sweepError.Error()
		})).Return().Once()

		handler.ServeHTTP(rr, req)

		// No redirect to /auth/issue, so no code can be minted from this ceremony.
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "", rr.Header().Get("Location"))

		// Nothing committed, nothing deleted, and no replacement session. The browser is left
		// cookied to the session that is still there, which is the fail-closed direction.
		assertNotAttempted(t, database, "CommitTransaction", "DeleteUserSession",
			"GetRefreshTokensBySessionIdentifier", "UpdateRefreshToken", "UpdateUserSession")
		userSessionManager.AssertNotCalled(t, "StartNewUserSession", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything)
		authHelper.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)

		// Not one audit event. cross_user_session_replaced or terminated_user_session written
		// here would attest to a revocation that rolled back.
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The other failure side, and the one the audit placement above rests on. Here the
	// termination has already committed and its three events are already written when
	// StartNewUserSession fails, so the handover is on the record and no replacement exists.
	// That asymmetry is deliberate: cross_user_session_replaced attests the ending and its
	// reason, started_new_user_session attests the replacement, and the absence of the second
	// after the first is how an operator sees a handover that did not complete. The ceremony
	// still has to stop dead, because it now has no session at all to bind a code to.
	t.Run("Replacement failure after a committed termination is a 500 with the handover recorded", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              2,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 3,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "session-of-user-1"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		foreignSession := &models.UserSession{
			Id:                7,
			UserId:            1,
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          enums.AcrLevel2Mandatory.String(),
			AuthMethods:       "pwd otp",
			AuthTime:          time.Now().UTC().Add(-10 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(foreignSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, foreignSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, foreignSession, mock.AnythingOfType("*int")).Return(true)

		var sequence []string
		stubCrossUserTermination(database, foreignSession, 2, []*models.RefreshToken{
			{Id: 11, RefreshTokenJti: "rt-of-user-1"},
		}, func(step string) { sequence = append(sequence, step) })

		recordEvent := func(args mock.Arguments) { sequence = append(sequence, args.Get(0).(string)) }

		// Once each: the termination committed, so all three are owed exactly one time even
		// though the ceremony is about to fail.
		auditLogger.On("Log", constants.AuditCrossUserSessionReplaced, mock.Anything).Run(recordEvent).Return().Once()
		auditLogger.On("Log", constants.AuditDeletedUserSession, mock.Anything).Run(recordEvent).Return().Once()
		auditLogger.On("Log", constants.AuditTerminatedUserSession, mock.Anything).Run(recordEvent).Return().Once()

		startError := errors.New("the replacement session could not be created")
		userSessionManager.On("StartNewUserSession", rr, req, int64(2), int64(1), "pwd",
			enums.AcrLevel1.String(), int64(3)).Return(nil, startError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == startError.Error()
		})).Return().Once()

		handler.ServeHTTP(rr, req)

		// No redirect, so nothing is issued on a ceremony left with no session.
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "", rr.Header().Get("Location"))

		// The handover is recorded and the replacement is not, which is the whole shape of this
		// outcome. started_new_user_session claims a session exists, and none does.
		assert.Equal(t, []string{
			"commit",
			constants.AuditCrossUserSessionReplaced,
			constants.AuditDeletedUserSession,
			constants.AuditTerminatedUserSession,
		}, sequence)
		auditLogger.AssertNotCalled(t, "Log", constants.AuditStartedNewUserSesson, mock.Anything)

		// The ceremony stops at the failure: no ACR is saved and no user is loaded, so nothing
		// downstream can act as though a session were bound.
		authHelper.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		assertNotAttempted(t, database, "GetUserById", "UpdateUserSession")
		userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, existing session with re-auth, consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Re-auth case (e.g. prompt=login): AuthenticatedAt set by password handler
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:       oauth.AuthStateAuthenticationCompleted,
			ClientId:        "test-client",
			UserId:          1,
			Scope:           "openid profile",
			AuthenticatedAt: &pwdAuthTime,
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		oldAuthTime := time.Now().UTC().Add(-1 * time.Hour)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: oldAuthTime,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// Re-auth: AuthTime is refreshed and session is updated
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			return s.Id == userSession.Id && !s.AuthTime.IsZero() && s.AuthTime.After(oldAuthTime)
		})).Return(nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				ac.AuthenticatedAt.After(oldAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The only row that distinguishes the two spellings of userReallyAuthenticated. The SSO
	// subtest above carries nil, which short-circuits before !IsZero() is reached, and the
	// re-auth subtest carries a nonzero timestamp, which passes either way; so with the
	// !IsZero() term deleted a zero AuthenticatedAt would count as authentication and the
	// session's AuthTime would be overwritten with now. That term is pre-existing and the
	// #129 gate does not read it, but nothing else in the file covers it (found by round 2
	// of the stage 5 review).
	t.Run("Successful flow, existing session, zero AuthenticatedAt does not refresh AuthTime", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Non-nil but zero, which is what an AuthContext round-tripped through the cookie
		// yields for an absent RFC 3339 timestamp.
		var zeroAuthenticatedAt time.Time
		authContext := &oauth.AuthContext{
			AuthState:       oauth.AuthStateAuthenticationCompleted,
			ClientId:        "test-client",
			UserId:          1,
			Scope:           "openid profile",
			AuthenticatedAt: &zeroAuthenticatedAt,
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// No UpdateUserSession expectation: a zero timestamp is not authentication, so
		// AuthTime must not be refreshed. Reaching it fails the case on the strict mock.

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		// The session's existing AuthTime is carried forward rather than replaced.
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// This ceremony did level 1: handler_auth_pwd sets both of these. Without
		// Level1AuthCompleted the #129 gate restarts level 1 rather than starting a
		// session, so this subtest is also the positive control for that gate.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
			// Nonzero so the StartNewUserSession expectation below pins that the handler
			// forwards THIS value. With 0 the assertion would also pass against a
			// hard-coded zero (#106 decision 11).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		// Simulating no existing session
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// Expect HasValidUserSession to return false for a new session
		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		// Expect StartNewUserSession to be called instead of BumpUserSession
		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Error in GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		profileUrl := "http://example.com/account/profile"
		config.GetAdminConsole().BaseURL = profileUrl

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == expectedError.Error()
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Invalid AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "authContext.AuthState is not authentication_completed")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client is nil", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateAuthenticationCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "client test-client not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User is not enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil
		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		// The clear has to reach the browser, so it must happen before the response is
		// committed. rr.Header() is the live map the handler and this stub share, so it shows
		// the sentinel under either ordering; rr.Result() reads the snapshot taken when the
		// status line was written, which is the only unit-tier view that tells them apart.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		// Check redirection URL
		location, _ := rr.Result().Location()
		assert.Equal(t, "https://example.com/callback", location.Scheme+"://"+location.Host+location.Path)

		// Check query parameters
		query := location.Query()
		assert.Equal(t, "access_denied", query.Get("error"))
		assert.Contains(t, query.Get("error_description"), "The user account is disabled")
		assert.Equal(t, "some-state", query.Get("state"))

		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("User is not enabled, failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		// A failed clear writes no cookie, so the browser keeps the auth context whatever the
		// handler does next. The client is still owed its error response, and server_error is
		// the code RFC 6749 4.1.2.1 mints for a fault that cannot travel as a 500.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("User is not enabled, failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails and
		// redirToClientWithError returns "unable to parse template" instead of committing.
		// form_post is the only response mode whose arm can fail after the redirect URI has
		// been validated, so it is how this branch is reached at all.
		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		// The clear failed and the server_error response the client is owed cannot be built
		// either, so there is nowhere left to send it and the 500 is the last resort. Without
		// this expectation the handler would answer nothing at all.
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		// Nothing reached the client: the form_post arm fails before it writes, and the 500 is
		// the mock's, so no redirect is committed.
		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("User is not enabled, unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		// The other half of the same family: here the clear succeeds and it is the ordinary
		// refusal that cannot be committed. This is the site's second and pre-existing 500,
		// pinned separately so a future edit cannot delete either copy unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("authContext.Scope is filtered and becomes empty", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil
		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		// Simulate the scope being filtered to an empty string
		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("", nil)

		// Same sentinel as the disabled-user case, for the second refusal in this handler.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		// Check redirection URL
		location, _ := rr.Result().Location()
		assert.Equal(t, "https://example.com/callback", location.Scheme+"://"+location.Host+location.Path)

		// Check query parameters
		query := location.Query()
		assert.Equal(t, "access_denied", query.Get("error"))
		assert.Contains(t, query.Get("error_description"), "The user is not authorized to access any of the requested scopes")
		assert.Equal(t, "some-state", query.Get("state"))

		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Scope filtered to empty with a failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("", nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Scope filtered to empty with a failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("", nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Scope filtered to empty with an unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: time.Now().UTC().Add(-5 * time.Minute),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("", nil)

		// The clear succeeds and it is the ordinary refusal that cannot be committed. Before
		// this change the handler carried on into the clear after answering the 500, which is
		// the missing return decision 5 adds; the 500 is asserted Once() so a second one would
		// fail the mock.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, consent required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Positive control for the #129 gate, as in the subtest above.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
			// Nonzero so the StartNewUserSession expectation below pins that the handler
			// forwards THIS value. With 0 the assertion would also pass against a
			// hard-coded zero (#106 decision 11).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          true,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/consent", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, offline_access scope requires consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Positive control for the #129 gate, as in the two subtests above.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile offline_access",
			AuthMethods: "pwd",
			// Nonzero for the same reason as the other cases: it pins that the handler
			// forwards this value rather than a hard-coded zero (#106).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false, // Note: This is false, but consent should still be required due to offline_access
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile offline_access", user).Return("openid profile offline_access", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/consent", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// #129 decisions 6 and 15. The two subtests below are the gate on the else branch; the
	// three "new session" subtests above are its positive control, since they now differ
	// from these only in carrying Level1AuthCompleted. That pairing is what pins the
	// predicate as "this ceremony did level 1" rather than "no valid session", which is the
	// shape TestSessionDeletedDuringAuthFlow_LoginSucceeds (#46) legitimately has.
	//
	// The second subtest is decision 15's: it carries a non-nil AuthenticatedAt written by
	// the OTP handler, so it is the row that fails against a gate reading
	// userReallyAuthenticated. That discriminator is still read on the valid-session branch,
	// and the zero-AuthenticatedAt subtest above is what covers its !IsZero() term.
	//
	// StartNewUserSession is deliberately not stubbed on the strict mock, so reaching it
	// fails the case on its own rather than through an assertion that could be deleted.
	t.Run("No valid session and this ceremony did not authenticate, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// An SSO ceremony: handler_authorize copied the session's user, methods and
		// generation onto the context and never reached the password handler, so both
		// AuthenticatedAt and Level1AuthCompleted are unset. The session was then ended
		// mid-flight.
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 7,
			Level1AuthCompleted: false,
		}

		sessionIdentifier := "terminated-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		// The session is gone, which is what "ended mid-flight" looks like from here.
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("No valid session and only OTP authenticated this ceremony, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Decision 15's ceremony. An SSO reuse stepped up to level 2, so AuthMethods came
		// off the reused session and handler_auth_otp set AuthenticatedAt on a successful
		// code, but no password was ever entered, so Level1AuthCompleted stays false. A gate
		// reading userReallyAuthenticated recreates the session here; this gate must not.
		otpAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid profile",
			AuthMethods:         "pwd otp",
			AuthStateGeneration: 7,
			AuthenticatedAt:     &otpAuthTime,
			Level1AuthCompleted: false,
		}

		sessionIdentifier := "terminated-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})
}
