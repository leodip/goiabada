package adminuserhandlers

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

// userSessionsApiClient answers the two reads this page performs and nothing else.
type userSessionsApiClient struct {
	apiclient.ApiClient
	user     *models.User
	sessions []api.EnhancedUserSessionResponse
}

func (c *userSessionsApiClient) GetUserById(accessToken string, userId int64) (*models.User, error) {
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
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_users_sessions.html", mock.Anything).
		Return(nil).Maybe()

	apiClient := &userSessionsApiClient{
		user: &models.User{Id: 7},
		sessions: []api.EnhancedUserSessionResponse{
			{Id: 1, DeviceName: "Safari 17", DeviceType: "Desktop", DeviceOS: "macOS", UserAgent: header},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/users/7/sessions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("userId", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
	req = req.WithContext(ctx)

	HandleAdminUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

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
