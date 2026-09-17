package adminclienthandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

// clientSessionsApiClient answers the two reads this page performs: the client, and its
// sessions with their owners. GetUserById is answered too, and counted rather than served, so
// the per-session user read this page used to make is absent by assertion and not merely by
// nobody having written a stub for it.
type clientSessionsApiClient struct {
	apiclient.ApiClient
	client   *api.ClientResponse
	sessions []api.UserSessionDetailResponse
	users    []api.SessionOwnerResponse

	userReads int
}

func (c *clientSessionsApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return c.client, nil
}

func (c *clientSessionsApiClient) GetClientSessionsByClientId(accessToken string, clientId int64,
	page, size int) (*api.GetClientSessionsResponse, error) {
	return &api.GetClientSessionsResponse{Sessions: c.sessions, Users: c.users}, nil
}

func (c *clientSessionsApiClient) GetUserById(accessToken string, userId int64) (*api.UserResponse, error) {
	c.userReads++
	return nil, nil
}

// The third of the three session pages, and the third hand-written SessionInfo literal, so the
// copy is pinned here for the same reason it is pinned on the other two (#281 decision 6).
func TestHandleAdminClientUserSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `goiabada-d2-second-device`

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper,
		"/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
		users:  []api.SessionOwnerResponse{{Id: 7, Email: "someone@example.com"}},
		sessions: []api.UserSessionDetailResponse{
			{Id: 1, UserId: 7, DeviceName: "goiabada-d2-second-device", DeviceType: "unknown", UserAgent: header},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)

	sessions, ok := bind["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	assert.Equal(t, header, sessions[0].UserAgent)
}

// The third of the three session pages, and the third hand-built SessionInfo literal, so the two
// instants the page formats are pinned here for the reason they are pinned on the other two (#373).
func TestHandleAdminClientUserSessionsGet_BindsTheSessionInstants(t *testing.T) {
	started := time.Date(2026, 9, 14, 21, 3, 0, 0, time.UTC)
	lastAccessed := time.Date(2026, 9, 17, 8, 45, 0, 0, time.UTC)

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper,
		"/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
		users:  []api.SessionOwnerResponse{{Id: 7, Email: "someone@example.com"}},
		sessions: []api.UserSessionDetailResponse{
			{Id: 1, UserId: 7, Started: &started, LastAccessed: &lastAccessed},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	require.NotNil(t, sessions[0].Started)
	require.NotNil(t, sessions[0].LastAccessed)
	assert.Equal(t, started, *sessions[0].Started)
	assert.Equal(t, lastAccessed, *sessions[0].LastAccessed)
}

// The client page's twin of the admin user page's case, and written separately for the reason
// every case in this trio is: this is the second of the two recomputations #373 deleted, and one
// of them left behind would be invisible to the other's test.
func TestHandleAdminClientUserSessionsGet_BindsIsCurrentFromTheResponse(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3},
		users:  []api.SessionOwnerResponse{{Id: 7}},
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, SessionIdentifier: "sid-one"}},
			{UserSessionResponse: api.UserSessionResponse{Id: 2, SessionIdentifier: "sid-two"}, IsCurrent: true},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)

	assert.Equal(t, int64(2), sessions[0].UserSessionId)
	assert.True(t, sessions[0].IsCurrent)
	assert.False(t, sessions[1].IsCurrent)
}

// The owner columns come from the envelope's users array, and no user is read back one at a
// time. This page fetched a user per session before #373 decision 9, up to 50 HTTP round trips
// to fill the two columns below, so the read count is asserted rather than the columns alone:
// filling them correctly while still making the calls would be the same page it was.
func TestHandleAdminClientUserSessionsGet_FillsTheOwnerColumnsFromTheEnvelope(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3},
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, UserId: 7}},
			{UserSessionResponse: api.UserSessionResponse{Id: 2, UserId: 9}},
		},
		users: []api.SessionOwnerResponse{
			{Id: 7, Email: "jane@example.com", GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe"},
			{Id: 9, Email: "sam@example.com", GivenName: "Sam", FamilyName: "Reed"},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)

	// Sorted by session id, descending, so session 2 is first.
	assert.Equal(t, int64(9), sessions[0].UserId)
	assert.Equal(t, "sam@example.com", sessions[0].UserEmail)
	assert.Equal(t, "Sam Reed", sessions[0].UserFullName)
	assert.Equal(t, int64(7), sessions[1].UserId)
	assert.Equal(t, "jane@example.com", sessions[1].UserEmail)
	assert.Equal(t, "Jane Q Doe", sessions[1].UserFullName)

	assert.Zero(t, apiClient.userReads,
		"the page read a user back one at a time, which is the round trip the users array replaced")
}

// Two sessions of the same person, which is what the normalized array looks like from this end:
// one record answers both rows. A page indexing users by position rather than by id would put
// the wrong name on the second row, or none.
func TestHandleAdminClientUserSessionsGet_OneOwnerAnswersEveryRowOfTheirs(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3},
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, UserId: 7}},
			{UserSessionResponse: api.UserSessionResponse{Id: 2, UserId: 7}},
		},
		users: []api.SessionOwnerResponse{{Id: 7, Email: "jane@example.com", GivenName: "Jane"}},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)
	for _, session := range sessions {
		assert.Equal(t, "jane@example.com", session.UserEmail)
		assert.Equal(t, "Jane", session.UserFullName)
	}
}

// A session whose owner is not in the array leaves the two cells empty and renders the rest of
// the row. The auth server refuses to build such a response, so this is the console being told
// something it did not expect rather than a case the endpoint produces; the page showing the
// device and the timestamps with a blank name beats the page not showing at all.
func TestHandleAdminClientUserSessionsGet_AnAbsentOwnerLeavesTheColumnsEmpty(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_usersessions.html").Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3},
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, UserId: 7, DeviceName: "Firefox"}},
		},
		users: []api.SessionOwnerResponse{},
	}

	req := handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
	)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	assert.Equal(t, "", sessions[0].UserEmail)
	assert.Equal(t, "", sessions[0].UserFullName)
	assert.Equal(t, "Firefox", sessions[0].DeviceName)
}
