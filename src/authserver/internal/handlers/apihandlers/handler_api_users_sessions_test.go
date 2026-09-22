package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
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

// stubTermination registers the calls revocation.TerminateUserSessionTx makes for one session. Thin on
// purpose, following stubSweep: revocation_test.go owns the exhaustive termination table over the
// happy path, both entry guards and all six failure points, and restating it here would mean two
// places to update.
func stubTermination(database *mocks_data.Database, userSession *models.UserSession,
	revokedCodeCount int64, tokens []*models.RefreshToken) {

	mocks_data.ExpectRunInTransaction(database, apiTerminateTx)
	database.On("RevokeCodesBySessionIdentifier", mock.Anything, apiTerminateTx, userSession.SessionIdentifier).
		Return(revokedCodeCount, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, apiTerminateTx, userSession.SessionIdentifier).
		Return(tokens, nil).Once()
	for i := range tokens {
		if tokens[i].Revoked {
			continue
		}
		jti := tokens[i].RefreshTokenJti
		database.On("UpdateRefreshToken", mock.Anything, apiTerminateTx, mock.MatchedBy(func(rt *models.RefreshToken) bool {
			return rt.RefreshTokenJti == jti
		})).Return(nil).Once()
	}
	database.On("DeleteUserSession", mock.Anything, apiTerminateTx, userSession.Id).Return(nil).Once()
}

// adminSessionDeleteRequest builds the DELETE with the chi URL parameter the handler reads and
// the validated bearer token the chain puts on the context.
//
// The token is what the audit payload's "loggedInUser" now comes from. It used to come from a
// mocked AuthHelper.GetLoggedInSubject, which is why nothing here noticed that the real accessor
// read a session key no auth server middleware writes and returned "" at every one of these sites
// (#385). A caller with no token is a separate case, covered below.
func adminSessionDeleteRequest(sessionId string, subject string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/user-sessions/"+sessionId, nil)
	req = setChiURLParam(req, "id", sessionId)
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// TestHandleAPIUserSessionDelete_TerminatesAndAuditsBothEvents is the wiring test for the
// administrative half of decision 5, and it doubles as the field-by-field assertion on decision 9's
// payload, because this is where the new event is emitted from.
func TestHandleAPIUserSessionDelete_TerminatesAndAuditsBothEvents(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-terminated", UserId: 42}

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// One live token and one already revoked, so the JTI list below proves the payload reports what
	// this call TRANSITIONED rather than what the session held.
	stubTermination(database, userSession, 3, []*models.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-live"},
		{Id: 2, RefreshTokenJti: "rt-already-gone", Revoked: true},
	})

	var deletedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.AuditDeletedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			deletedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()
	var terminatedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.AuditTerminatedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			terminatedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100", adminSubject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	// The older event's payload, unchanged. Decision 9 chose two events over one extended event on
	// compatibility grounds, so an external consumer parsing this one strictly must keep working:
	// exactly two keys, and neither renamed.
	require.NotNil(t, deletedPayload)
	assert.Equal(t, int64(100), deletedPayload["userSessionId"])
	assert.Equal(t, adminSubject, deletedPayload["loggedInUser"])
	assert.Len(t, deletedPayload, 2)

	// The new event's payload, field by field. Asserted here rather than trusted because it is the
	// only durable record of what a termination revoked, and a missing or renamed field is invisible
	// to every other test.
	require.NotNil(t, terminatedPayload)
	assert.Equal(t, int64(42), terminatedPayload["userId"])
	assert.Equal(t, int64(100), terminatedPayload["userSessionId"])
	assert.Equal(t, "sid-terminated", terminatedPayload["sessionIdentifier"])
	assert.Equal(t, adminSubject, terminatedPayload["loggedInUser"])
	assert.Equal(t, int64(3), terminatedPayload["revokedCodeCount"])
	assert.Equal(t, []string{"rt-live"}, terminatedPayload["revokedRefreshTokenJtis"])
	// Exactly these six keys. A seventh would go unnoticed, and more importantly this pins that none
	// of the six was dropped, which an assertion on a nil map value cannot do.
	assert.Len(t, terminatedPayload, 6)
}

// TestHandleAPIUserSessionDelete_NoTokenAuditsAnEmptySubject is the other half of callerSubject.
// A request that reached the handler with no validated token on its context records the actor as
// the empty string, present rather than absent.
//
// Production cannot reach this: routes.go mounts authHeaderToContext and a scope middleware ahead
// of every route in this package, so a request without a token is refused before the handler runs.
// It is pinned anyway because it is the fallback arm of callerSubject, and an arm no test enters is
// one a later edit can turn into a panic or a dropped key without anything going red. Present
// matters as much as empty: AuditLogResponse.Details is the marshalled map returned verbatim by
// GET /api/v1/admin/audit-logs, so an absent key is a change a consumer can see (#385).
func TestHandleAPIUserSessionDelete_NoTokenAuditsAnEmptySubject(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-terminated", UserId: 42}

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	stubTermination(database, userSession, 0, []*models.RefreshToken{})

	var payloads []map[string]interface{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			payloads = append(payloads, args.Get(2).(map[string]interface{}))
		}).Return().Twice()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/user-sessions/100", nil)
	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, setChiURLParam(req, "id", "100"))

	assert.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, payloads, 2)
	for i := range payloads {
		actor, ok := payloads[i]["loggedInUser"]
		assert.True(t, ok, "the key is present even with no caller to name")
		assert.Equal(t, "", actor)
	}
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPIUserSessionDelete_TerminationFailureIsA500 is the case that decided this file had to
// exist. KEEP IT. The integration tier can read audit rows but cannot make the termination
// transaction fail, so this is the only seam that can show neither event is emitted when it does.
func TestHandleAPIUserSessionDelete_TerminationFailureIsA500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	userSession := &models.UserSession{Id: 100, SessionIdentifier: "sid-terminated", UserId: 42}

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// The deletion, which since #139 is the first write inside the termination transaction.
	stub := mocks_data.ExpectRunInTransaction(database, apiTerminateTx)
	database.On("DeleteUserSession", mock.Anything, apiTerminateTx, userSession.Id).
		Return(errors.New("the session delete failed")).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100", adminSubject))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	assert.EqualError(t, stub.BodyErr, "the session delete failed", "the body hands its error to the helper, which rolls back")
	// NEITHER event. deleted_user_session would otherwise claim a deletion that rolled back, and
	// the two emitters are adjacent in the handler, so it is easy to leave the first one outside the
	// error check.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleAPIUserSessionDelete_NotFoundDoesNotTerminate pins that the pre-existing 404 still
// answers first. Without it, a handler that terminated before looking the session up would pass
// every other case here.
func TestHandleAPIUserSessionDelete_NotFoundDoesNotTerminate(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(999)).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("999", adminSubject))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
	// No transaction is opened for a session that does not exist.
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
