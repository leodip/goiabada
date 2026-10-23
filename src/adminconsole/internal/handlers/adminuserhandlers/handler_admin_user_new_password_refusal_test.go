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

// refusingUserNewAPI is the auth server refusing the new user with code.
type refusingUserNewAPI struct {
	code string
}

func (a refusingUserNewAPI) CreateUserAdmin(context.Context, string, *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	return nil, &apiclient.APIError{Code: a.code, Message: "refused", StatusCode: http.StatusBadRequest}
}

// The nist policy's two refusals are about the password, so the page marks that field, as it marks
// it for the policy's other refusals (#550 decision 10).
func TestHandleNewPost_TheNistRefusalsMarkThePassword(t *testing.T) {
	for _, code := range []string{"validator.password.too_common", "validator.password.too_close_to_account"} {
		t.Run(code, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_new.html").Once()

			req := handlertest.Request(http.MethodPost, "/admin/users/new",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Goiabada"}),
				handlertest.WithForm(url.Values{"email": {"jane.doe@example.com"}, "password": {"PasswordPassword"}}))

			HandleNewPost(httpHelper, nil, refusingUserNewAPI{code: code}, "https://console.example").
				ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, "password", handlertest.Bind(t, httpHelper)["errorField"])
		})
	}
}
