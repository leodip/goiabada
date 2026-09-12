package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// clientSessionsApiClient answers the three reads this page performs: the client, its sessions,
// and the per-session user lookup behind the email column.
type clientSessionsApiClient struct {
	apiclient.ApiClient
	client   *api.ClientResponse
	sessions []api.EnhancedUserSessionResponse
	user     *models.User
}

func (c *clientSessionsApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return c.client, nil
}

func (c *clientSessionsApiClient) GetClientSessionsByClientId(accessToken string, clientId int64,
	page, size int) ([]api.EnhancedUserSessionResponse, error) {
	return c.sessions, nil
}

func (c *clientSessionsApiClient) GetUserById(accessToken string, userId int64) (*models.User, error) {
	return c.user, nil
}

// The third of the three session pages, and the third hand-written SessionInfo literal, so the
// copy is pinned here for the same reason it is pinned on the other two (#281 decision 6).
func TestHandleAdminClientUserSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `goiabada-d2-second-device`

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_clients_usersessions.html", mock.Anything).
		Return(nil).Maybe()

	apiClient := &clientSessionsApiClient{
		client: &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
		user:   &models.User{Id: 7, Email: "someone@example.com"},
		sessions: []api.EnhancedUserSessionResponse{
			{Id: 1, UserId: 7, DeviceName: "goiabada-d2-second-device", DeviceType: "unknown", UserAgent: header},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/clients/3/user-sessions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "3")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
	req = req.WithContext(ctx)

	HandleAdminClientUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing")

	sessions, ok := bind["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	assert.Equal(t, header, sessions[0].UserAgent)
}
