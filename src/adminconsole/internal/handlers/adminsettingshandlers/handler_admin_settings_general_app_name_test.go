package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// refusingGeneralAPI answers the stored general settings and refuses the save with updateErr.
type refusingGeneralAPI struct {
	updateErr error
}

func (a *refusingGeneralAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{AppName: "Goiabada", Issuer: "https://auth.example.test", PasswordPolicy: "low"}, nil
}

func (a *refusingGeneralAPI) UpdateSettingsGeneral(context.Context, string, *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	return nil, a.updateErr
}

// Each of the auth server's three App name refusals marks the App name field: a blank name, which
// the save refuses since #646 decision 7, beside the name past the bound and the angle brackets.
func TestHandleGeneralPost_AnAppNameRefusalMarksTheAppNameField(t *testing.T) {
	refusals := map[string]string{
		"handler.settings_general.app_name_required": "App name is required.",
		"handler.settings_general.app_name_too_long": "App name is too long. The maximum length is 30 characters.",
		"validator.settings.app_name_angle_brackets": "The app name cannot contain the characters < or >.",
	}
	for code, message := range refusals {
		t.Run(code, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_general.html").Once()
			apiClient := &refusingGeneralAPI{updateErr: &apiclient.APIError{Code: code, Message: message, StatusCode: http.StatusBadRequest}}

			req := handlertest.Request(http.MethodPost, "/admin/settings/general",
				handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"appName": {" "}, "issuer": {"https://auth.example.test"}, "passwordPolicy": {"low"}}))
			HandleGeneralPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).
				ServeHTTP(httptest.NewRecorder(), req)

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, message, bind["error"])
			assert.Equal(t, "appName", bind["errorField"])
		})
	}
}
