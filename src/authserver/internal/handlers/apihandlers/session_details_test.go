package apihandlers

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// buildSessionDetails is the loop all three session list endpoints run, and until #373 it was
// three copies of itself inside three handlers with no unit coverage at all: this package's other
// session tests cover only the DELETE handlers, and the integration tier cannot see how many
// queries a page costs. So this file owns the filtering, the single hydrating query and the error
// paths, and each handler owes only a case that it consults the helper.

// sessionSettings are permissive enough that a session's validity is decided by its own
// timestamps rather than by the numbers here: one day idle, one week alive.
var sessionSettings = &models.Settings{
	UserSessionIdleTimeoutInSeconds: 86400,
	UserSessionMaxLifetimeInSeconds: 604800,
}

func liveSession(id int64, identifier string, clientIds ...int64) models.UserSession {
	now := time.Now().UTC()
	session := models.UserSession{
		Id:                id,
		SessionIdentifier: identifier,
		Started:           now.Add(-time.Hour),
		LastAccessed:      now.Add(-time.Minute),
		UserId:            42,
	}
	for _, clientId := range clientIds {
		session.Clients = append(session.Clients, models.UserSessionClient{
			UserSessionId: id,
			ClientId:      clientId,
			Started:       now.Add(-time.Hour),
			LastAccessed:  now.Add(-time.Minute),
		})
	}
	return session
}

// TestBuildSessionDetails_LoadsEveryClientInOneQuery is decision 9's database half stated as the
// claim it actually is: a count. The three loops it replaces called UserSessionClientsLoadClients
// once per session, so a page of fifty sessions cost fifty queries to name the handful of clients
// a deployment has. Nothing above this tier can see that, because the response is identical
// either way, which is why the strict mock's Once is the assertion.
func TestBuildSessionDetails_LoadsEveryClientInOneQuery(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	sessions := []models.UserSession{
		liveSession(1, "sid-1", 5, 6),
		liveSession(2, "sid-2", 5),
		liveSession(3, "sid-3", 6),
	}

	var gotClientIds []int64
	database.On("GetClientsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { gotClientIds = args.Get(2).([]int64) }).
		Return([]models.Client{
			{Id: 5, ClientIdentifier: "portal"},
			{Id: 6, ClientIdentifier: "backoffice"},
		}, nil).Once()

	details, err := buildSessionDetails(context.Background(), database, sessions, sessionSettings, "")

	require.NoError(t, err)
	require.Len(t, details, 3)
	database.AssertExpectations(t)

	// The union, deduplicated: client 5 is on two sessions and client 6 on two, and asking for
	// four ids would still answer correctly while costing part of the query it was meant to save.
	assert.ElementsMatch(t, []int64{5, 6}, gotClientIds)
	assert.Len(t, gotClientIds, 2)

	assert.Equal(t, []string{"portal", "backoffice"}, details[0].ClientIdentifiers)
	assert.Equal(t, []string{"portal"}, details[1].ClientIdentifiers)
	assert.Equal(t, []string{"backoffice"}, details[2].ClientIdentifiers)
}

// A session with no clients must not make the helper ask for an empty id list.
func TestBuildSessionDetails_NoClientsRunsNoQuery(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	details, err := buildSessionDetails(context.Background(), database, []models.UserSession{liveSession(1, "sid-1")}, sessionSettings, "")

	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.Equal(t, []string{}, details[0].ClientIdentifiers)
	// No GetClientsByIds expectation is registered, so the strict mock fails the test if one is
	// made.
	database.AssertExpectations(t)
}

// Decision 2: the endpoints list what is live. An expired session is omitted rather than reported
// with a flag, and it must not reach the hydrating query either.
func TestBuildSessionDetails_DropsSessionsThatAreNoLongerValid(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	now := time.Now().UTC()
	idle := liveSession(2, "sid-idle", 9)
	idle.LastAccessed = now.Add(-48 * time.Hour)
	expired := liveSession(3, "sid-expired", 9)
	expired.Started = now.Add(-30 * 24 * time.Hour)

	sessions := []models.UserSession{liveSession(1, "sid-live", 5), idle, expired}

	var gotClientIds []int64
	database.On("GetClientsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { gotClientIds = args.Get(2).([]int64) }).
		Return([]models.Client{{Id: 5, ClientIdentifier: "portal"}}, nil).Once()

	details, err := buildSessionDetails(context.Background(), database, sessions, sessionSettings, "")

	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.Equal(t, int64(1), details[0].Id)

	// Client 9 belongs only to the dropped sessions, so filtering before hydrating is what keeps
	// it out of the query. Asking for it would be harmless and wasteful, and this is the only
	// place that could say so.
	assert.Equal(t, []int64{5}, gotClientIds)
}

// currentSid reaches the mapper. The mapper owns the comparison; this owns the wiring, which is
// the half that was wrong before: two of the three producers never passed a sid at all.
func TestBuildSessionDetails_PassesTheCallersSidThrough(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	details, err := buildSessionDetails(context.Background(), database,
		[]models.UserSession{liveSession(1, "sid-1"), liveSession(2, "sid-2")},
		sessionSettings, "sid-2")

	require.NoError(t, err)
	require.Len(t, details, 2)
	assert.False(t, details[0].IsCurrent)
	assert.True(t, details[1].IsCurrent)
}

// The error is returned rather than swallowed into a short list: a page silently missing the
// sessions whose clients failed to load is worse than a 500, because nobody can tell.
func TestBuildSessionDetails_SurfacesTheClientQueryError(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetClientsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(nil, errors.New("connection reset")).Once()

	details, err := buildSessionDetails(context.Background(), database,
		[]models.UserSession{liveSession(1, "sid-1", 5)}, sessionSettings, "")

	require.Error(t, err)
	assert.Nil(t, details)
	assert.Contains(t, err.Error(), "connection reset")
}

// A session naming a client with no row is a broken row, and UserSessionClientsLoadClients
// refused it before this helper replaced that call. Keeping the refusal is deliberate: answering
// 200 with the client quietly absent from clientIdentifiers would hide it for good.
func TestBuildSessionDetails_RefusesAClientIdWithNoRow(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetClientsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return([]models.Client{{Id: 5, ClientIdentifier: "portal"}}, nil).Once()

	details, err := buildSessionDetails(context.Background(), database,
		[]models.UserSession{liveSession(1, "sid-1", 5, 99)}, sessionSettings, "")

	require.Error(t, err)
	assert.Nil(t, details)
	assert.Contains(t, err.Error(), "client with id 99 not found")
}

// An empty list is an empty slice and never nil, because the response wraps it in a required
// array: GetUserSessionsResponse{Sessions: nil} marshals to "sessions":null.
func TestBuildSessionDetails_EmptyListIsAnEmptySlice(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	details, err := buildSessionDetails(context.Background(), database, nil, sessionSettings, "")

	require.NoError(t, err)
	require.NotNil(t, details)
	assert.Empty(t, details)
}

// TestBuildSessionDetails_LoadsClientsUnderTheCallersContext is the second half of the same
// claim, and seam 4's arm for the one read this file makes. The union query is the most
// expensive thing these three endpoints do, so it is also the one most worth abandoning when the
// caller is gone; a builder that manufactured its own context would issue it regardless.
func TestBuildSessionDetails_LoadsClientsUnderTheCallersContext(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "the caller's own")

	database := mocks_data.NewDatabase(t)
	database.On("GetClientsByIds", mock.MatchedBy(func(got context.Context) bool {
		return got.Value(marker{}) == "the caller's own"
	}), (*sql.Tx)(nil), mock.Anything).
		Return([]models.Client{{Id: 5, ClientIdentifier: "portal"}}, nil).Once()

	_, err := buildSessionDetails(ctx, database, []models.UserSession{liveSession(1, "sid-1", 5)}, sessionSettings, "")

	require.NoError(t, err)
	database.AssertExpectations(t)
}
