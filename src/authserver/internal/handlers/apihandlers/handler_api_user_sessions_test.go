package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The single session GET addresses a session by its numeric id and answers with the row the
// session lists carry, built by buildSessionDetails (#651 decisions 1 and 6). What these pin is
// what that builder cannot: the handler reads the caller's sid and hands it over, and a session the
// builder leaves out, one no longer live, is the same 404 as an id naming nothing (decision 4).

// userSessionGetRequest builds the GET with the path value the handler reads, the settings the
// liveness rule reads, and a validated token naming sid when sid is non-empty.
func userSessionGetRequest(id string, sid string) *http.Request {
	req := sessionListRequest("/api/v1/admin/user-sessions/"+id, sid, nil)
	req.SetPathValue("id", id)
	return req
}

// decodeAPIError reads an error body's error_code.
func decodeAPIError(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()

	var body api.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body.ErrorCode
}

func TestHandleUserSessionGet_AnswersTheListRowWithTheCallersSid(t *testing.T) {
	database := datamocks.NewDatabase(t)

	session := liveSession(100, "sid-mine", 5)
	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(&session, nil).Once()
	database.On("UserSessionsLoadClients", mock.Anything, (*sql.Tx)(nil), []record.UserSession{session}).Return(nil).Once()
	database.On("GetClientsByIds", mock.Anything, (*sql.Tx)(nil), []int64{5}).
		Return([]record.Client{{Id: 5, ClientIdentifier: "portal"}}, nil).Once()

	rr := httptest.NewRecorder()
	HandleUserSessionGet(database).ServeHTTP(rr, userSessionGetRequest("100", "sid-mine"))

	require.Equal(t, http.StatusOK, rr.Code)
	var out api.GetUserSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	assert.Equal(t, int64(100), out.Session.Id)
	assert.Equal(t, "sid-mine", out.Session.SessionIdentifier)
	assert.Equal(t, int64(42), out.Session.UserId)
	assert.True(t, out.Session.IsCurrent, "the token's sid names this session")
	assert.Equal(t, []string{"portal"}, out.Session.ClientIdentifiers)
	require.Len(t, out.Session.Clients, 1)
	assert.Equal(t, "portal", out.Session.Clients[0].ClientIdentifier)
	database.AssertExpectations(t)
}

// A token minted through client_credentials carries no sid, and that is false, not a match of the
// empty string against anything.
func TestHandleUserSessionGet_NoSidOnTheTokenIsNotCurrent(t *testing.T) {
	database := datamocks.NewDatabase(t)

	session := liveSession(100, "sid-someone")
	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(&session, nil).Once()
	database.On("UserSessionsLoadClients", mock.Anything, (*sql.Tx)(nil), []record.UserSession{session}).Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleUserSessionGet(database).ServeHTTP(rr, userSessionGetRequest("100", ""))

	require.Equal(t, http.StatusOK, rr.Code)
	var out api.GetUserSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	assert.False(t, out.Session.IsCurrent)
	assert.Equal(t, []string{}, out.Session.ClientIdentifiers, "an array, never null")
}

// Decision 4: a session past the idle timeout or the maximum lifetime is gone, with the same answer
// as an id naming no session, and its clients are never read.
func TestHandleUserSessionGet_ASessionNoLongerLiveIsNotFound(t *testing.T) {
	idle := liveSession(100, "sid-idle", 5)
	idle.LastAccessed = time.Now().UTC().Add(-time.Duration(sessionSettings.UserSessionIdleTimeoutInSeconds+60) * time.Second)

	old := liveSession(100, "sid-old", 5)
	old.Started = time.Now().UTC().Add(-time.Duration(sessionSettings.UserSessionMaxLifetimeInSeconds+60) * time.Second)

	for name, session := range map[string]record.UserSession{"past the idle timeout": idle, "past the maximum lifetime": old} {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(100)).Return(&session, nil).Once()
			database.On("UserSessionsLoadClients", mock.Anything, (*sql.Tx)(nil), []record.UserSession{session}).Return(nil).Once()

			rr := httptest.NewRecorder()
			HandleUserSessionGet(database).ServeHTTP(rr, userSessionGetRequest("100", "sid-idle"))

			require.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "NOT_FOUND", decodeAPIError(t, rr))
			// No GetClientsByIds expectation is registered, so the strict mock fails the test if
			// the clients of a dead session are read.
			database.AssertExpectations(t)
		})
	}
}

func TestHandleUserSessionGet_AnIdNamingNoSessionIsNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), int64(99999)).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleUserSessionGet(database).ServeHTTP(rr, userSessionGetRequest("99999", ""))

	require.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "NOT_FOUND", decodeAPIError(t, rr))
}

// The session identifier this path used to take is refused as any other non-integer is, and
// nothing is read.
func TestHandleUserSessionGet_ANonIntegerIsAValidationError(t *testing.T) {
	for _, id := range []string{"6f1c1c0e-3c0b-4c1e-9a43-1d1b2f2f5c11", "abc", "1.5", ""} {
		t.Run(id, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			rr := httptest.NewRecorder()
			HandleUserSessionGet(database).ServeHTTP(rr, userSessionGetRequest(id, ""))

			require.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "VALIDATION_ERROR", decodeAPIError(t, rr))
		})
	}
}
