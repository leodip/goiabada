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

// This file did not exist before #129 stage 4, and section 1 of the agreement recorded its absence
// as a finding rather than an oversight: neither session-delete endpoint had any unit coverage.
//
// What it owns is decision 9's audit contract, and that contract has no other home. The integration
// tier can read audit rows back through GetAuditLogsPaginated, so it can observe the success half,
// but it cannot force the termination transaction to fail, so nothing there can prove BOTH events
// are suppressed when it does. The termination table itself lives in revocation_test.go and is not
// restated here.

// apiTerminateTx is an opaque non-nil transaction, the counterpart of apiRevokeTx. Letting
// BeginTransaction return nil would exercise a shape production never runs.
var apiTerminateTx = &sql.Tx{}

// stubTermination registers the calls TerminateUserSessionTx makes for one session. Thin on
// purpose, following stubSweep: revocation_test.go owns the exhaustive termination table over the
// happy path, both entry guards and all six failure points, and restating it here would mean two
// places to update.
func stubTermination(database *mocks_data.Database, userSession *models.UserSession,
	revokedCodeCount int64, tokens []*models.RefreshToken) {

	database.On("BeginTransaction").Return(apiTerminateTx, nil).Once()
	database.On("RevokeCodesBySessionIdentifier", apiTerminateTx, userSession.SessionIdentifier).
		Return(revokedCodeCount, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", apiTerminateTx, userSession.SessionIdentifier).
		Return(tokens, nil).Once()
	for i := range tokens {
		if tokens[i].Revoked {
			continue
		}
		jti := tokens[i].RefreshTokenJti
		database.On("UpdateRefreshToken", apiTerminateTx, mock.MatchedBy(func(rt *models.RefreshToken) bool {
			return rt.RefreshTokenJti == jti
		})).Return(nil).Once()
	}
	database.On("DeleteUserSession", apiTerminateTx, userSession.Id).Return(nil).Once()
	database.On("CommitTransaction", apiTerminateTx).Return(nil).Once()
	database.On("RollbackTransaction", apiTerminateTx).Return(nil).Once()
}

// adminSessionDeleteRequest builds the DELETE with the chi URL parameter the handler reads.
func adminSessionDeleteRequest(sessionId string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/user-sessions/"+sessionId, nil)
	return setChiURLParam(req, "id", sessionId)
}

// TestHandleAPIUserSessionDelete_TerminatesAndAuditsBothEvents is the wiring test for the
// administrative half of decision 5, and it doubles as the field-by-field assertion on decision 9's
// payload, because this is where the new event is emitted from.
func TestHandleAPIUserSessionDelete_TerminatesAndAuditsBothEvents(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	const subject = "the-admin"
	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-terminated", UserId: 42}

	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// One live token and one already revoked, so the JTI list below proves the payload reports what
	// this call TRANSITIONED rather than what the session held.
	stubTermination(database, userSession, 3, []*models.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-live"},
		{Id: 2, RefreshTokenJti: "rt-already-gone", Revoked: true},
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
	handler := HandleAPIUserSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100"))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	// The older event's payload, unchanged. Decision 9 chose two events over one extended event on
	// compatibility grounds, so an external consumer parsing this one strictly must keep working:
	// exactly two keys, and neither renamed.
	require.NotNil(t, deletedPayload)
	assert.Equal(t, int64(100), deletedPayload["userSessionId"])
	assert.Equal(t, subject, deletedPayload["loggedInUser"])
	assert.Len(t, deletedPayload, 2)

	// The new event's payload, field by field. Asserted here rather than trusted because it is the
	// only durable record of what a termination revoked, and a missing or renamed field is invisible
	// to every other test.
	require.NotNil(t, terminatedPayload)
	assert.Equal(t, int64(42), terminatedPayload["userId"])
	assert.Equal(t, int64(100), terminatedPayload["userSessionId"])
	assert.Equal(t, "sid-terminated", terminatedPayload["sessionIdentifier"])
	assert.Equal(t, subject, terminatedPayload["loggedInUser"])
	assert.Equal(t, int64(3), terminatedPayload["revokedCodeCount"])
	assert.Equal(t, []string{"rt-live"}, terminatedPayload["revokedRefreshTokenJtis"])
	// Exactly these six keys. A seventh would go unnoticed, and more importantly this pins that none
	// of the six was dropped, which an assertion on a nil map value cannot do.
	assert.Len(t, terminatedPayload, 6)
}

// TestHandleAPIUserSessionDelete_TerminationFailureIsA500 is the case that decided this file had to
// exist. KEEP IT. The integration tier can read audit rows but cannot make the termination
// transaction fail, so this is the only seam that can show neither event is emitted when it does.
func TestHandleAPIUserSessionDelete_TerminationFailureIsA500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-terminated", UserId: 42}

	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	database.On("BeginTransaction").Return(apiTerminateTx, nil).Once()
	database.On("RevokeCodesBySessionIdentifier", apiTerminateTx, "sid-terminated").
		Return(int64(0), errors.New("the code sweep failed")).Once()
	database.On("RollbackTransaction", apiTerminateTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100"))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	// NEITHER event. deleted_user_session would otherwise claim a deletion that rolled back, and
	// the two emitters are adjacent in the handler, so it is easy to leave the first one outside the
	// error check.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleAPIUserSessionDelete_NotFoundDoesNotTerminate pins that the pre-existing 404 still
// answers first. Without it, a handler that terminated before looking the session up would pass
// every other case here.
func TestHandleAPIUserSessionDelete_NotFoundDoesNotTerminate(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	database.On("GetUserSessionById", (*sql.Tx)(nil), int64(999)).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, authHelper, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("999"))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
	// No transaction is opened for a session that does not exist.
	database.AssertNotCalled(t, "BeginTransaction")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}
