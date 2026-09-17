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

// clientSessionsApiClient answers the three reads this page performs: the client, its sessions,
// and the per-session user lookup behind the email column.
type clientSessionsApiClient struct {
	apiclient.ApiClient
	client   *api.ClientResponse
	sessions []api.UserSessionDetailResponse
	user     *api.UserResponse
}

func (c *clientSessionsApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return c.client, nil
}

func (c *clientSessionsApiClient) GetClientSessionsByClientId(accessToken string, clientId int64,
	page, size int) ([]api.UserSessionDetailResponse, error) {
	return c.sessions, nil
}

func (c *clientSessionsApiClient) GetUserById(accessToken string, userId int64) (*api.UserResponse, error) {
	return c.user, nil
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
		user:   &api.UserResponse{Id: 7, Email: "someone@example.com"},
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
		user:   &api.UserResponse{Id: 7, Email: "someone@example.com"},
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
		user:   &api.UserResponse{Id: 7},
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
