package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #129 stage 4, and #129 recorded its absence
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
func stubTermination(database *datamocks.Database, userSession *record.UserSession,
	revokedCodeCount int64, tokens []*record.RefreshToken) {

	datamocks.ExpectRunInTransaction(database, apiTerminateTx)
	database.On("RevokeCodesBySessionIdentifier", mock.Anything, apiTerminateTx, userSession.SessionIdentifier).
		Return(revokedCodeCount, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, apiTerminateTx, userSession.SessionIdentifier).
		Return(tokens, nil).Once()
	for i := range tokens {
		if tokens[i].Revoked {
			continue
		}
		jti := tokens[i].RefreshTokenJti
		database.On("UpdateRefreshToken", mock.Anything, apiTerminateTx, mock.MatchedBy(func(rt *record.RefreshToken) bool {
			return rt.RefreshTokenJti == jti
		})).Return(nil).Once()
	}
	database.On("DeleteUserSession", mock.Anything, apiTerminateTx, userSession.Id).Return(nil).Once()
}

// adminSessionDeleteRequest builds the DELETE with the path value the handler reads, the settings
// its liveness rule reads, and the validated bearer token the chain puts on the context.
//
// The token is what the audit payload's "logged_in_user" now comes from. It used to come from a
// mocked AuthHelper.GetLoggedInSubject, which is why nothing here noticed that the real accessor
// read a session key no auth server middleware writes and returned "" at every one of these sites
// (#385). A caller with no token is a separate case, covered below.
func adminSessionDeleteRequest(sessionId string, subject string) *http.Request {
	return adminSessionDeleteRequestWithScope(sessionId, subject, "authserver:manage")
}

// adminSessionDeleteRequestWithScope is adminSessionDeleteRequest with the token's scope named.
func adminSessionDeleteRequestWithScope(sessionId string, subject string, scope string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/user-sessions/"+sessionId, nil)
	req.SetPathValue("id", sessionId)
	req = req.WithContext(reqctx.WithSettings(req.Context(), sessionSettings))
	return setTokenContextWithClaims(req, map[string]interface{}{"scope": scope, "sub": subject})
}

// liveSessionOf is liveSession for the user given: a session the DELETEs end, not one they answer
// 404 as already gone (#651 decision 5).
func liveSessionOf(id int64, identifier string, userId int64) *record.UserSession {
	session := liveSession(id, identifier)
	session.UserId = userId
	return &session
}

// deadSessions are a session of the user given past the idle timeout and one past the maximum
// lifetime under sessionSettings, each by a minute: stored rows the background worker has not swept
// yet, which every session endpoint treats as gone (#651 decisions 4 and 5).
func deadSessions(id int64, userId int64) map[string]*record.UserSession {
	now := time.Now().UTC()

	idle := liveSessionOf(id, "sid-idle", userId)
	idle.LastAccessed = now.Add(-time.Duration(sessionSettings.UserSessionIdleTimeoutInSeconds+60) * time.Second)

	old := liveSessionOf(id, "sid-old", userId)
	old.Started = now.Add(-time.Duration(sessionSettings.UserSessionMaxLifetimeInSeconds+60) * time.Second)

	return map[string]*record.UserSession{"past the idle timeout": idle, "past the maximum lifetime": old}
}

// TestHandleUserSessionDelete_TerminatesAndAuditsBothEvents is the wiring test for the
// administrative half of decision 5, and it doubles as the field-by-field assertion on decision 9's
// payload, because this is where the new event is emitted from.
func TestHandleUserSessionDelete_TerminatesAndAuditsBothEvents(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	userSession := liveSessionOf(100, "sid-terminated", 42)

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// One live token and one already revoked, so the JTI list below proves the payload reports what
	// this call TRANSITIONED rather than what the session held.
	stubTermination(database, userSession, 3, []*record.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-live"},
		{Id: 2, RefreshTokenJti: "rt-already-gone", Revoked: true},
	})

	var deletedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDeletedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			deletedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()
	var terminatedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventTerminatedUserSession, mock.Anything).
		Run(func(args mock.Arguments) {
			terminatedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100", adminSubject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	// The older event's payload, unchanged. Decision 9 chose two events over one extended event on
	// compatibility grounds, so an external consumer parsing this one strictly must keep working:
	// exactly two keys, and neither renamed.
	require.NotNil(t, deletedPayload)
	assert.Equal(t, int64(100), deletedPayload["user_session_id"])
	assert.Equal(t, adminSubject, deletedPayload["logged_in_user"])
	assert.Equal(t, "ended_by_administrator", deletedPayload["reason"])
	assert.Len(t, deletedPayload, 3)

	// The new event's payload, field by field. Asserted here rather than trusted because it is the
	// only durable record of what a termination revoked, and a missing or renamed field is invisible
	// to every other test.
	require.NotNil(t, terminatedPayload)
	assert.Equal(t, int64(42), terminatedPayload["user_id"])
	assert.Equal(t, int64(100), terminatedPayload["user_session_id"])
	assert.Equal(t, "sid-terminated", terminatedPayload["session_identifier"])
	assert.Equal(t, adminSubject, terminatedPayload["logged_in_user"])
	assert.Equal(t, int64(3), terminatedPayload["revoked_code_count"])
	assert.Equal(t, []string{"rt-live"}, terminatedPayload["revoked_refresh_token_jtis"])
	// Exactly these six keys. A seventh would go unnoticed, and more importantly this pins that none
	// of the six was dropped, which an assertion on a nil map value cannot do.
	assert.Len(t, terminatedPayload, 6)
}

// TestHandleUserSessionDelete_NoTokenAuditsAnEmptySubject is the other half of callerSubject.
// A request that reached the handler with no validated token on its context records the actor as
// the empty string, present rather than absent.
//
// Production cannot reach this: routes.go mounts authHeaderToContext and a scope middleware ahead
// of every route in this package, so a request without a token is refused before the handler runs.
// It is pinned anyway because it is the fallback arm of callerSubject, and an arm no test enters is
// one a later edit can turn into a panic or a dropped key without anything going red. Present
// matters as much as empty: AuditLogResponse.Details is the marshalled map returned verbatim by
// GET /api/v1/admin/audit-logs, so an absent key is a change a consumer can see (#385).
func TestHandleUserSessionDelete_NoTokenAuditsAnEmptySubject(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	userSession := liveSessionOf(100, "sid-terminated", 42)

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// No token holds no authority, so the target ceiling reads what the user holds; an ordinary
	// user's session is terminated as before.
	expectHoldsNothing(database, 42)
	stubTermination(database, userSession, 0, []*record.RefreshToken{})

	var payloads []map[string]interface{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			payloads = append(payloads, args.Get(2).(map[string]interface{}))
		}).Return().Twice()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/user-sessions/100", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), sessionSettings))
	rr := httptest.NewRecorder()
	handler := HandleUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, withPathValue(req, "id", "100"))

	assert.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, payloads, 2)
	for i := range payloads {
		actor, ok := payloads[i]["logged_in_user"]
		assert.True(t, ok, "the key is present even with no caller to name")
		assert.Empty(t, actor)
	}
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleUserSessionDelete_TerminationFailureIsA500 is the case that decided this file had to
// exist. KEEP IT. The integration tier can read audit rows but cannot make the termination
// transaction fail, so this is the only seam that can show neither event is emitted when it does.
func TestHandleUserSessionDelete_TerminationFailureIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	userSession := liveSessionOf(100, "sid-terminated", 42)

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(userSession, nil).Once()
	// The deletion, which since #139 is the first write inside the termination transaction.
	stub := datamocks.ExpectRunInTransaction(database, apiTerminateTx)
	database.On("DeleteUserSession", mock.Anything, apiTerminateTx, userSession.Id).
		Return(errors.New("the session delete failed")).Once()

	rr := httptest.NewRecorder()
	handler := HandleUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("100", adminSubject))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	require.EqualError(t, stub.BodyErr, "the session delete failed", "the body hands its error to the helper, which rolls back")
	// NEITHER event. deleted_user_session would otherwise claim a deletion that rolled back, and
	// the two emitters are adjacent in the handler, so it is easy to leave the first one outside the
	// error check.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleUserSessionDelete_NotFoundDoesNotTerminate pins that the pre-existing 404 still
// answers first. Without it, a handler that terminated before looking the session up would pass
// every other case here.
func TestHandleUserSessionDelete_NotFoundDoesNotTerminate(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(999)).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleUserSessionDelete(database, auditLogger)
	handler.ServeHTTP(rr, adminSessionDeleteRequest("999", adminSubject))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
	// No transaction is opened for a session that does not exist.
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleUserSessionDelete_ASessionNoLongerLiveIsNotFound pins #651 decision 5's administrative
// half: a session past the idle timeout or the maximum lifetime, stored until the worker sweeps it,
// is the same 404 as an id naming no session, and nothing is ended, revoked or audited.
//
// The session is an administrator's and the token granular, so the target ceiling, had it judged,
// would read what the user holds and refuse with an administrator_change_refused record. The
// liveness 404 answers before it: the strict mock has none of the ceiling's reads registered and
// the audit logger no record, so either one reached fails the test.
func TestHandleUserSessionDelete_ASessionNoLongerLiveIsNotFound(t *testing.T) {
	for name, session := range deadSessions(100, targetUserId) {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(session, nil).Once()

			rr := httptest.NewRecorder()
			HandleUserSessionDelete(database, auditLogger).
				ServeHTTP(rr, adminSessionDeleteRequestWithScope("100", grantCaller, granularScopeOfTarget))

			require.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "NOT_FOUND", decodeAPIError(t, rr))
			database.AssertExpectations(t)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetUserPermissionsByUserId", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The dead session's 404 is the one an id naming no session gets, body and all, so a caller cannot
// tell a swept row from one waiting for the sweep.
func TestHandleUserSessionDelete_ADeadSessionAnswersAsAMissingOne(t *testing.T) {
	serve := func(session *record.UserSession) *httptest.ResponseRecorder {
		database := datamocks.NewDatabase(t)
		database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(session, nil).Once()
		rr := httptest.NewRecorder()
		HandleUserSessionDelete(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, adminSessionDeleteRequest("100", adminSubject))
		return rr
	}

	missing := serve(nil)
	require.Equal(t, http.StatusNotFound, missing.Code)
	for name, session := range deadSessions(100, 42) {
		dead := serve(session)
		assert.Equal(t, missing.Code, dead.Code, name)
		assert.JSONEq(t, missing.Body.String(), dead.Body.String(), name)
	}
}
