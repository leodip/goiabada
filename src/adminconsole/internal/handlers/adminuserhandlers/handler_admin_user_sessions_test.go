package adminuserhandlers

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

// userSessionsApiClient answers the two reads this page performs and nothing else.
type userSessionsApiClient struct {
	apiclient.ApiClient
	user     *api.UserResponse
	sessions []api.EnhancedUserSessionResponse
}

func (c *userSessionsApiClient) GetUserById(accessToken string, userId int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *userSessionsApiClient) GetUserSessionsByUserId(accessToken string,
	userId int64) ([]api.EnhancedUserSessionResponse, error) {
	return c.sessions, nil
}

// The admin-side twin of the account page's case: this handler also rebuilds SessionInfo by hand,
// so the copy has to be pinned here too. A guard added at one of three call sites and absent from
// its siblings is exactly the shape a change like this ships with (#281 decision 6).
func TestHandleAdminUserSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15`

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_sessions.html").Maybe()

	apiClient := &userSessionsApiClient{
		user: &api.UserResponse{Id: 7},
		sessions: []api.EnhancedUserSessionResponse{
			{Id: 1, DeviceName: "Safari 17", DeviceType: "Desktop", DeviceOS: "macOS", UserAgent: header},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
	)

	HandleAdminUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)

	sessions, ok := bind["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	assert.Equal(t, header, sessions[0].UserAgent)
}
