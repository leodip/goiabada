package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/core/api"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// One case per list endpoint that it consults buildSessionDetails, and in particular that it
// reads the caller's sid off the validated token and hands it over. session_details_test.go owns
// the helper's own table; restating it three times is what the agreement's seam section rejected.
//
// The sid read is what makes these worth writing rather than leaving to the integration tier: it
// is new for the two admin handlers, and a handler that fetched its sessions and passed "" would
// return a perfectly well-formed body with isCurrent false on every row.

// sessionListRequest builds a GET carrying the settings the filtering reads and, when sid is
// non-empty, a validated token naming that session.
func sessionListRequest(target string, sid string, claims map[string]interface{}) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, sessionSettings))
	if claims == nil {
		claims = map[string]interface{}{}
	}
	if sid != "" {
		claims["sid"] = sid
	}
	return setTokenContextWithClaims(req, claims)
}

// decodeSessionList reads the endpoint's body, which is the same envelope on all three.
func decodeSessionList(t *testing.T, rr *httptest.ResponseRecorder) []api.UserSessionDetailResponse {
	t.Helper()

	var out api.GetUserSessionsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out.Sessions
}

// expectSessionOwnerRead registers the one extra read the client endpoint makes: the owners of
// the sessions it kept, in a single GetUsersByIds. Only that endpoint has it, because only that
// one lists sessions across users.
func expectSessionOwnerRead(database *mocks_data.Database, users ...models.User) {
	byId := make(map[int64]models.User, len(users))
	for _, user := range users {
		byId[user.Id] = user
	}
	database.On("GetUsersByIds", (*sql.Tx)(nil), mock.Anything).Return(byId, nil).Once()
}

// expectSessionListReads registers the reads every list handler makes once it has its sessions:
// the per-session client rows are already on the fixtures, so UserSessionsLoadClients is a no-op
// here and GetClientsByIds is the one query buildSessionDetails runs.
func expectSessionListReads(database *mocks_data.Database, sessions []models.UserSession) {
	database.On("UserSessionsLoadClients", (*sql.Tx)(nil), sessions).Return(nil).Once()
	database.On("GetClientsByIds", (*sql.Tx)(nil), mock.Anything).
		Return([]models.Client{{Id: 5, ClientIdentifier: "portal"}}, nil).Once()
}

func TestHandleAPIUserSessionsGet_ReadsTheCallersSidAndFilters(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	now := liveSession(1, "sid-other", 5)
	mine := liveSession(2, "sid-mine", 5)
	stale := liveSession(3, "sid-stale", 5)
	stale.LastAccessed = stale.LastAccessed.Add(-48 * time.Hour)
	sessions := []models.UserSession{now, mine, stale}

	database.On("GetUserById", (*sql.Tx)(nil), int64(42)).Return(&models.User{Id: 42}, nil).Once()
	database.On("GetUserSessionsByUserId", (*sql.Tx)(nil), int64(42)).Return(sessions, nil).Once()
	expectSessionListReads(database, sessions)

	req := sessionListRequest("/api/v1/admin/users/42/sessions", "sid-mine", nil)
	req = setChiURLParam(req, "id", "42")

	rr := httptest.NewRecorder()
	HandleAPIUserSessionsGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	got := decodeSessionList(t, rr)
	require.Len(t, got, 2)
	assert.False(t, got[0].IsCurrent)
	assert.True(t, got[1].IsCurrent, "the admin's own session must be marked on this endpoint too")
	assert.Equal(t, []string{"portal"}, got[0].ClientIdentifiers)
	database.AssertExpectations(t)
}

// An admin token minted through client_credentials carries no sid, and the handler must read that
// as "none of these is mine" rather than matching the empty string against an empty identifier.
func TestHandleAPIUserSessionsGet_NoSidOnTheTokenMarksNothingCurrent(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	sessions := []models.UserSession{liveSession(1, "sid-one", 5), liveSession(2, "", 5)}

	database.On("GetUserById", (*sql.Tx)(nil), int64(42)).Return(&models.User{Id: 42}, nil).Once()
	database.On("GetUserSessionsByUserId", (*sql.Tx)(nil), int64(42)).Return(sessions, nil).Once()
	expectSessionListReads(database, sessions)

	req := sessionListRequest("/api/v1/admin/users/42/sessions", "", nil)
	req = setChiURLParam(req, "id", "42")

	rr := httptest.NewRecorder()
	HandleAPIUserSessionsGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	for _, session := range decodeSessionList(t, rr) {
		assert.False(t, session.IsCurrent)
	}
}

func TestHandleAPIClientSessionsGet_ReadsTheCallersSidAndFilters(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	mine := liveSession(2, "sid-mine", 5)
	stale := liveSession(3, "sid-stale", 5)
	stale.LastAccessed = stale.LastAccessed.Add(-48 * time.Hour)
	sessions := []models.UserSession{liveSession(1, "sid-other", 5), mine, stale}

	database.On("GetClientById", (*sql.Tx)(nil), int64(7)).Return(&models.Client{Id: 7}, nil).Once()
	database.On("GetUserSessionsByClientIdPaginated", (*sql.Tx)(nil), int64(7), 1, 50).
		Return(sessions, len(sessions), nil).Once()
	expectSessionListReads(database, sessions)
	expectSessionOwnerRead(database, models.User{Id: 42, Email: "someone@example.com"})

	req := sessionListRequest("/api/v1/admin/clients/7/sessions", "sid-mine", nil)
	req = setChiURLParam(req, "id", "7")

	rr := httptest.NewRecorder()
	HandleAPIClientSessionsGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	got := decodeSessionList(t, rr)
	require.Len(t, got, 2)
	assert.False(t, got[0].IsCurrent)
	assert.True(t, got[1].IsCurrent, "the admin's own session must be marked on this endpoint too")
	database.AssertExpectations(t)
}

func TestHandleAPIAccountSessionsGet_ReadsTheCallersSidAndFilters(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	mine := liveSession(2, "sid-mine", 5)
	stale := liveSession(3, "sid-stale", 5)
	stale.LastAccessed = stale.LastAccessed.Add(-48 * time.Hour)
	sessions := []models.UserSession{liveSession(1, "sid-other", 5), mine, stale}

	database.On("GetUserBySubject", (*sql.Tx)(nil), "the-user").Return(&models.User{Id: 42}, nil).Once()
	database.On("GetUserSessionsByUserId", (*sql.Tx)(nil), int64(42)).Return(sessions, nil).Once()
	expectSessionListReads(database, sessions)

	req := sessionListRequest("/api/v1/account/sessions", "sid-mine",
		map[string]interface{}{"sub": "the-user"})

	rr := httptest.NewRecorder()
	HandleAPIAccountSessionsGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	got := decodeSessionList(t, rr)
	require.Len(t, got, 2)
	assert.False(t, got[0].IsCurrent)
	assert.True(t, got[1].IsCurrent)
	database.AssertExpectations(t)
}
