package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// sessionOwners is the client endpoint's half of decision 9 of #373: the console rendered this
// page by reading a user back per row, up to 50 HTTP round trips, and the owners now ride along
// with the sessions. The claims are that the array is normalized, that its order is something a
// wire-bytes case can write down, and that it is one query however many rows there are -- so
// they are asserted here, on the helper, rather than restated at the handler.

func ownerSession(id int64, userId int64) api.UserSessionDetailResponse {
	return api.UserSessionDetailResponse{
		UserSessionResponse: api.UserSessionResponse{Id: id, UserId: userId},
	}
}

// Decision 10's normalization, at the source: three rows, two people, and the query asks for two
// ids. A helper collecting one id per session would ask for three and answer three records, so
// the page would print one person twice.
func TestSessionOwners_AreNormalizedAndFetchedInOneQuery(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	var asked []int64
	database.On("GetUsersByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { asked = args.Get(2).([]int64) }).
		Return(map[int64]models.User{
			7: {Id: 7, Email: "jane@example.com", GivenName: "Jane"},
			9: {Id: 9, Email: "sam@example.com", GivenName: "Sam"},
		}, nil).
		Once()

	owners, err := sessionOwners(context.Background(), database, []api.UserSessionDetailResponse{
		ownerSession(1, 7), ownerSession(2, 9), ownerSession(3, 7),
	})
	require.NoError(t, err)

	assert.Equal(t, []int64{7, 9}, asked, "one id per person, not one per session")
	require.Len(t, owners, 2)
	database.AssertExpectations(t)
}

// The order is the order the sessions first name each id, and not the order GetUsersByIds
// answers in: that method returns a map, whose iteration order Go randomizes per run, so a
// helper walking it would produce a different array on every request and nothing could pin the
// bytes.
func TestSessionOwners_FollowTheOrderTheSessionsFirstNameThem(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetUsersByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(map[int64]models.User{
			7:  {Id: 7, GivenName: "Jane"},
			9:  {Id: 9, GivenName: "Sam"},
			11: {Id: 11, GivenName: "Alex"},
		}, nil).
		Once()

	owners, err := sessionOwners(context.Background(), database, []api.UserSessionDetailResponse{
		ownerSession(1, 11), ownerSession(2, 7), ownerSession(3, 11), ownerSession(4, 9),
	})
	require.NoError(t, err)

	require.Len(t, owners, 3)
	assert.Equal(t, []int64{11, 7, 9}, []int64{owners[0].Id, owners[1].Id, owners[2].Id})
}

// An empty page asks nothing and answers an empty array rather than a nil one, which is what
// keeps "users":[] out of being "users":null against a schema that declares a required,
// non-nullable array.
func TestSessionOwners_AnEmptyPageAsksNothingAndIsNeverNil(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	owners, err := sessionOwners(context.Background(), database, []api.UserSessionDetailResponse{})
	require.NoError(t, err)
	require.NotNil(t, owners)
	assert.Len(t, owners, 0)

	marshalled, err := json.Marshal(owners)
	require.NoError(t, err)
	assert.Equal(t, "[]", string(marshalled))

	database.AssertNotCalled(t, "GetUsersByIds", mock.Anything, mock.Anything, mock.Anything)
}

// A session naming a user with no row is a broken row: user_sessions.user_id is a non-null
// foreign key. Answering 200 with that owner silently missing would render a blank name and
// email beside a live session and hide it, so the request fails instead -- the same choice
// loadSessionClients makes for a client id with no row.
func TestSessionOwners_AUserWithNoRowIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetUsersByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(map[int64]models.User{7: {Id: 7}}, nil).Once()

	owners, err := sessionOwners(context.Background(), database, []api.UserSessionDetailResponse{
		ownerSession(1, 7), ownerSession(2, 9),
	})
	require.Error(t, err)
	assert.Nil(t, owners)
	assert.Contains(t, err.Error(), "user with id 9 not found")
}

func TestSessionOwners_ADatabaseFailureIsAnError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetUsersByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(map[int64]models.User(nil), errs.New("the database is down")).Once()

	owners, err := sessionOwners(context.Background(), database, []api.UserSessionDetailResponse{ownerSession(1, 7)})
	require.Error(t, err)
	assert.Nil(t, owners, "an error must not be answered with an empty list the caller would publish")
}

// The whole envelope, off the handler, which is the one place the two arrays are seen together.
// The page reads a session's owner out of users by userId, so the pairing is the contract and
// not the arrays' lengths.
func TestHandleAPIClientSessionsGet_AnswersTheSessionsWithTheirOwners(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	sessions := []models.UserSession{liveSession(1, "sid-one", 5), liveSession(2, "sid-two", 5)}

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&models.Client{Id: 7}, nil).Once()
	database.On("GetUserSessionsByClientIdPaginated", mock.Anything, (*sql.Tx)(nil), int64(7), 1, 50).
		Return(sessions, len(sessions), nil).Once()
	expectSessionListReads(database, sessions)
	expectSessionOwnerRead(database, models.User{
		Id: 42, Email: "jane@example.com", GivenName: "Jane", FamilyName: "Doe",
	})

	req := sessionListRequest("/api/v1/admin/clients/7/sessions", "", nil)
	req = setChiURLParam(req, "id", "7")

	rr := httptest.NewRecorder()
	HandleAPIClientSessionsGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var out api.GetClientSessionsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))

	require.Len(t, out.Sessions, 2)
	require.Len(t, out.Users, 1, "both sessions belong to one person, who appears once")
	assert.Equal(t, api.SessionOwnerResponse{
		Id: 42, Email: "jane@example.com", GivenName: "Jane", FamilyName: "Doe",
	}, out.Users[0])
	for _, session := range out.Sessions {
		assert.Equal(t, out.Users[0].Id, session.UserId)
	}
	database.AssertExpectations(t)
}
