package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// authenticationApiClient answers the user authentication page for a user with two-factor
// authentication on, recording the writes in the order they reach it, and refusing the password
// when refusePassword is set.
type authenticationApiClient struct {
	refusePassword bool
	writes         []string
}

func (*authenticationApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Email: "someone@example.com", OTPEnabled: true,
		OTPAuthenticatorDisabled: true}, nil
}

func (c *authenticationApiClient) UpdateUserPassword(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserPasswordRequest) (*api.UserResponse, error) {
	c.writes = append(c.writes, "password")
	if c.refusePassword {
		return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "The password is too short.",
			StatusCode: http.StatusBadRequest}
	}
	return &api.UserResponse{Id: userId}, nil
}

func (c *authenticationApiClient) UpdateUserOTP(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserOTPRequest) (*api.UserResponse, error) {
	c.writes = append(c.writes, "otp")
	return &api.UserResponse{Id: userId}, nil
}

// postAuthentication submits the authentication form with a new password and the two-factor switch
// cleared, which is the way back the console gives for a disabled authenticator (#489).
func postAuthentication(httpHelper *handlersmocks.HttpHelper, apiClient *authenticationApiClient) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	HandleAuthenticationPost(httpHelper, newFlashTestStore(), apiClient, consoleBaseURL).ServeHTTP(recorder,
		handlertest.Request(http.MethodPost, "/admin/users/42/authentication",
			handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "42"),
			handlertest.WithForm(url.Values{"newPassword": {"a-new-password-for-them"}})))
	return recorder
}

// One save sets the new password before it turns two-factor authentication off, so whoever sent
// the codes that disabled the authenticator never holds a password that signs in alone.
func TestHandleAuthenticationPost_SetsThePasswordBeforeTurningTwoFactorOff(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := &authenticationApiClient{}

	recorder := postAuthentication(httpHelper, apiClient)

	assert.Equal(t, []string{"password", "otp"}, apiClient.writes)
	assert.Equal(t, http.StatusFound, recorder.Code)
}

// A refused password leaves two-factor authentication on: the form is drawn again under the
// refusal, and the switch is not written.
func TestHandleAuthenticationPost_ARefusedPasswordLeavesTwoFactorOn(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_authentication.html").Once()
	apiClient := &authenticationApiClient{refusePassword: true}

	postAuthentication(httpHelper, apiClient)

	assert.Equal(t, []string{"password"}, apiClient.writes)
	assert.Equal(t, "The password is too short.", handlertest.Bind(t, httpHelper)["error"])
}
