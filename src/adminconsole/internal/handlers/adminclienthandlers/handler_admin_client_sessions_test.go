package adminclienthandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	sessions []api.EnhancedUserSessionResponse
	user     *api.UserResponse
}

func (c *clientSessionsApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return c.client, nil
}

func (c *clientSessionsApiClient) GetClientSessionsByClientId(accessToken string, clientId int64,
	page, size int) ([]api.EnhancedUserSessionResponse, error) {
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
		sessions: []api.EnhancedUserSessionResponse{
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
