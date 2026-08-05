package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The self-service half of #129 stage 4. This file did not exist either, for the reason recorded at
// the top of handler_api_users_sessions_test.go, and it shares that file's stubTermination and
// apiTerminateTx.
//
// What is unique to this site is the ownership check: it must answer 403 BEFORE anything is
// terminated, and the pre-existing integration case asserts only the status code, which a handler
// terminating first would still satisfy.

// accountSessionDeleteRequest builds the DELETE with the chi URL parameter and the validated token
// the handler reads.
func accountSessionDeleteRequest(sessionId string, subject string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/account/sessions/"+sessionId, nil)
	req = setChiURLParam(req, "id", sessionId)
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// TestHandleAPIAccountSessionDelete_TerminatesAndAuditsBothEvents is the wiring test for the
// self-service half of decision 5. The payload is asserted here too rather than left to the admin
// site: LogTerminatedUserSession is shared, but which session row each handler hands it is not, and
// this is the site that resolves the row through an ownership check first.
func TestHandleAPIAccountSessionDelete_TerminatesAndAuditsBothEvents(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	const subject = "the-user"
	user := &models.User{Id: 42, Enabled: true}
	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-own", UserId: 42}

	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	stubTermination(database, userSession, 1, []*models.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-live"},
	})

	authHelper.On("GetLoggedInSubject", mock.Anything).Return(subject)
	var deletedPayload map[string]interface{}
	auditLogger.On("Log", constants.AuditDeletedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			deletedPayload = args.Get(1).(map[string]interface{})
		}).Return().Once()
	var terminatedPayload map[string]interface{}
	auditLogger.On("Log", constants.AuditTerminatedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			terminatedPayload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, accountSessionDeleteRequest("100", subject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	require.NotNil(t, deletedPayload)
	assert.Equal(t, int64(100), deletedPayload["userSessionId"])
	assert.Equal(t, subject, deletedPayload["loggedInUser"])
	assert.Len(t, deletedPayload, 2)

	require.NotNil(t, terminatedPayload)
	assert.Equal(t, int64(42), terminatedPayload["userId"])
	assert.Equal(t, int64(100), terminatedPayload["userSessionId"])
	assert.Equal(t, "sid-own", terminatedPayload["sessionIdentifier"])
	assert.Equal(t, subject, terminatedPayload["loggedInUser"])
	assert.Equal(t, int64(1), terminatedPayload["revokedCodeCount"])
	assert.Equal(t, []string{"rt-live"}, terminatedPayload["revokedRefreshTokenJtis"])
	assert.Len(t, terminatedPayload, 6)
}

// TestHandleAPIAccountSessionDelete_ForbiddenDoesNotTerminate is the row that carries this file.
// KEEP IT. Ownership has to answer before termination, and the pre-existing integration case
// (TestAPIAccountSessionDelete_ForbiddenOnOtherUsersSession) asserts only the 403, so a handler that
// terminated somebody else's session and THEN refused would leave it green. The strict mock is the
// mechanism: no termination expectation is registered, so any call fails the test.
func TestHandleAPIAccountSessionDelete_ForbiddenDoesNotTerminate(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	const subject = "the-user"
	// The session belongs to user 7; the caller is user 42.
	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(100)).
		Return(&models.UserSession{Id: 100, SessionIdentifier: "sid-someone-else", UserId: 7}, nil).Once()
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).
		Return(&models.User{Id: 42, Enabled: true}, nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, accountSessionDeleteRequest("100", subject))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "BeginTransaction")
	database.AssertNotCalled(t, "RevokeCodesBySessionIdentifier", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleAPIAccountSessionDelete_TerminationFailureIsA500 repeats the suppression contract at the
// second site deliberately. The two audit emitters are adjacent in both handlers, so leaving the
// first one outside the error check is a one-line mistake that the other site's test cannot see.
func TestHandleAPIAccountSessionDelete_TerminationFailureIsA500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	const subject = "the-user"
	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(100)).
		Return(&models.UserSession{Id: 100, SessionIdentifier: "sid-own", UserId: 42}, nil).Once()
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).
		Return(&models.User{Id: 42, Enabled: true}, nil).Once()
	database.On("BeginTransaction").Return(apiTerminateTx, nil).Once()
	database.On("RevokeCodesBySessionIdentifier", apiTerminateTx, "sid-own").
		Return(int64(0), errors.New("the code sweep failed")).Once()
	database.On("RollbackTransaction", apiTerminateTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, accountSessionDeleteRequest("100", subject))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}
