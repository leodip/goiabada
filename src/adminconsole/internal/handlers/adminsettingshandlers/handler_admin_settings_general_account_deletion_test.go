package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// accountDeletionAPI answers the general settings with accountDeletionEnabled as stored, records
// the save it is sent, and answers it, or refuses it with updateErr.
type accountDeletionAPI struct {
	stored    bool
	sent      *api.UpdateSettingsGeneralRequest
	updateErr error
}

func (a *accountDeletionAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{AppName: "Goiabada", Issuer: "https://auth.example.test",
		PasswordPolicy: "low", AccountDeletionEnabled: a.stored}, nil
}

func (a *accountDeletionAPI) UpdateSettingsGeneral(_ context.Context, _ string, req *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	a.sent = req
	if a.updateErr != nil {
		return nil, a.updateErr
	}
	return &api.SettingsGeneralResponse{Issuer: req.Issuer, PasswordPolicy: req.PasswordPolicy}, nil
}

// The General page shows "Let users delete their own account" as the auth server holds it (#783
// decision 5).
func TestHandleGeneralGet_ShowsAccountDeletionAsStored(t *testing.T) {
	for _, stored := range []bool{true, false} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_general.html").Once()

		req := handlertest.Request(http.MethodGet, "/admin/settings/general", handlertest.WithAccessToken())
		HandleGeneralGet(httpHelper, newSettingsTestStore(), &accountDeletionAPI{stored: stored}).
			ServeHTTP(httptest.NewRecorder(), req)

		settings, ok := handlertest.Bind(t, httpHelper)["settings"].(SettingsGeneral)
		require.True(t, ok)
		assert.Equal(t, stored, settings.AccountDeletionEnabled, "stored %v", stored)
	}
}

// The save always sends accountDeletionEnabled, which the admin API requires: true when the box is
// ticked and false, not left out, when it is cleared, whatever was stored.
func TestHandleGeneralPost_AlwaysSendsAccountDeletionEnabled(t *testing.T) {
	for name, tc := range map[string]struct {
		form   url.Values
		stored bool
		want   bool
	}{
		"ticked":  {url.Values{"accountDeletionEnabled": {"on"}}, false, true},
		"cleared": {url.Values{}, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			tc.form.Set("appName", "Goiabada")
			tc.form.Set("issuer", "https://auth.example.test")
			tc.form.Set("passwordPolicy", "low")
			req := handlertest.Request(http.MethodPost, "/admin/settings/general",
				handlertest.WithAccessToken(), handlertest.WithForm(tc.form))

			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &accountDeletionAPI{stored: tc.stored}
			w := httptest.NewRecorder()
			HandleGeneralPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(w, req)

			require.Equal(t, http.StatusFound, w.Code)
			require.NotNil(t, apiClient.sent)
			require.NotNil(t, apiClient.sent.AccountDeletionEnabled, "the field is always sent")
			assert.Equal(t, tc.want, *apiClient.sent.AccountDeletionEnabled)
		})
	}
}

// The auth server's refusal of a missing value marks the checkbox, and the form is drawn again
// with the box as it was submitted.
func TestHandleGeneralPost_AnAccountDeletionRefusalMarksItsCheckbox(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_general.html").Once()
	const message = "Choose whether to let users delete their own account."
	apiClient := &accountDeletionAPI{updateErr: &apiclient.APIError{
		Code: "handler.settings_general.account_deletion_enabled_required", Message: message, StatusCode: http.StatusBadRequest}}

	req := handlertest.Request(http.MethodPost, "/admin/settings/general", handlertest.WithAccessToken(),
		handlertest.WithForm(url.Values{"appName": {"Goiabada"}, "issuer": {"https://auth.example.test"},
			"passwordPolicy": {"low"}, "accountDeletionEnabled": {"on"}}))
	HandleGeneralPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, message, bind["error"])
	assert.Equal(t, "accountDeletionEnabled", bind["errorField"])
	settings, ok := bind["settings"].(SettingsGeneral)
	require.True(t, ok)
	assert.True(t, settings.AccountDeletionEnabled, "the box is drawn as submitted")
}
