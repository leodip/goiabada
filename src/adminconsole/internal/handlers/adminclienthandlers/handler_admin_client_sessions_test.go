package adminclienthandlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// clientSessionsApiClient answers the two reads this page performs: the client, and its
// sessions with their owners. GetUserById is answered too, and counted rather than served, so
// the per-session user read this page used to make is absent by assertion and not merely by
// nobody having written a stub for it.
type clientSessionsApiClient struct {
	apiclient.ApiClient
	client      *api.ClientResponse
	sessions    []api.UserSessionDetailResponse
	sessionsErr error
	users       []api.SessionOwnerResponse

	userReads int
	// deleted records the sessions the row buttons deleted, so a case can say which one went and
	// a case expecting none can say so by asserting the slice is empty.
	deleted []int64
}

func (c *clientSessionsApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return c.client, nil
}

func (c *clientSessionsApiClient) GetClientSessionsByClientId(accessToken string, clientId int64,
	page, size int) (*api.GetClientSessionsResponse, error) {
	if c.sessionsErr != nil {
		return nil, c.sessionsErr
	}
	return &api.GetClientSessionsResponse{Sessions: c.sessions, Users: c.users}, nil
}

func (c *clientSessionsApiClient) DeleteUserSessionById(accessToken string, sessionId int64) error {
	c.deleted = append(c.deleted, sessionId)
	return nil
}

func (c *clientSessionsApiClient) GetUserById(accessToken string, userId int64) (*api.UserResponse, error) {
	c.userReads++
	return nil, nil
}

// The third of the three session pages, and the third hand-written SessionInfo literal, so the
// copy is pinned here for the same reason it is pinned on the other two (#281 decision 6).
func TestHandleAdminClientUserSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `goiabada-d2-second-device`

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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

// The third of the three delete handlers, and the third hand-written comparison, so the trio is
// symmetric here for the reason it is symmetric on the page cases above. This one lists other
// people's sessions, and the administrator's own is among them whenever they hold a session on
// the client they are looking at (#373).
func TestHandleAdminClientUserSessionsPost_TheAnswerFollowsIsCurrentOnTheRow(t *testing.T) {
	const deleting = 5

	testCases := []struct {
		name string
		// sid, when set, is the claim on the console's own parsed access token. Without it the
		// request carries the bearer alone and no parsed token at all.
		sid         string
		sessions    []api.UserSessionDetailResponse
		wantCurrent bool
	}{
		{
			name: "the row being deleted is the caller's own",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}, IsCurrent: true},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}},
			},
			wantCurrent: true,
		},
		{
			name: "another row is the caller's own",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}, IsCurrent: true},
			},
		},
		{
			name: "no row is the caller's own, which is what a client credentials token produces",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}},
			},
		},
		{
			name: "the row's identifier matches the console's own claim and the field says no",
			sid:  "sid-one",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting, SessionIdentifier: "sid-one"}},
			},
		},
		{
			name: "the field says yes and the console's own claim names another session",
			sid:  "sid-elsewhere",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting, SessionIdentifier: "sid-one"},
					IsCurrent: true},
			},
			wantCurrent: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.ExpectEncodeJson(httpHelper).Once()

			apiClient := &clientSessionsApiClient{
				client:   &api.ClientResponse{Id: 3},
				sessions: testCase.sessions,
			}

			opts := []handlertest.Option{
				handlertest.WithRouteParam("clientId", "3"),
				handlertest.WithBody(strings.NewReader(`{"userSessionId": 5}`)),
			}
			if testCase.sid == "" {
				opts = append(opts, handlertest.WithAccessToken())
			} else {
				opts = append(opts, handlertest.WithJwtInfo(oauth.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					AccessToken:   &oauth.JwtToken{Claims: jwt.MapClaims{"sid": testCase.sid}},
				}))
			}

			req := handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions", opts...)

			HandleAdminClientUserSessionsPost(httpHelper, apiClient).
				ServeHTTP(httptest.NewRecorder(), req)

			answer := handlertest.Encoded(t, httpHelper)
			assert.Equal(t, true, answer["Success"])

			if testCase.wantCurrent {
				assert.Equal(t, true, answer["IsCurrentSession"],
					"the browser has to be sent through the logout flow")
				assert.Empty(t, apiClient.deleted,
					"the logout flow ends the session; deleting it here would end it twice")
				return
			}
			assert.NotContains(t, answer, "IsCurrentSession",
				"a row that is not the caller's own is deleted in place")
			assert.Equal(t, []int64{deleting}, apiClient.deleted)
		})
	}
}

// The list read is what the answer above turns on, so a list this handler cannot read is answered
// rather than swallowed. It swallowed the failure until #373, because the read was made only to
// compare against a claim rather than to decide the answer.
func TestHandleAdminClientUserSessionsPost_AListTheApiCannotReadStopsTheDelete(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3},
		sessionsErr: &apiclient.APIError{
			Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire",
			StatusCode: http.StatusInternalServerError,
		},
	}

	req := handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("clientId", "3"),
		handlertest.WithBody(strings.NewReader(`{"userSessionId": 5}`)),
	)

	HandleAdminClientUserSessionsPost(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	require.NotNil(t, captured, "the handler answered nothing")
	assert.Empty(t, apiClient.deleted, "nothing may be deleted on an answer the handler cannot make")
}
