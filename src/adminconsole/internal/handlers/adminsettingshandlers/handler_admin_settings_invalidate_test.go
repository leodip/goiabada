package adminsettingshandlers

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

// invalidationRecorder counts what the settings saves ask of the public settings cache.
type invalidationRecorder struct {
	invalidations int
}

func (c *invalidationRecorder) Invalidate() {
	c.invalidations++
}

// settingsSaveAPI accepts every save, or refuses each with saveErr. The general page reads the
// issuer before it saves, and answers the same one after, so an accepted save takes the ordinary
// redirect rather than the sign-out an issuer change is.
type settingsSaveAPI struct {
	saveErr error
}

func (a settingsSaveAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: "https://issuer.example"}, nil
}

func (a settingsSaveAPI) UpdateSettingsGeneral(context.Context, string, *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	if a.saveErr != nil {
		return nil, a.saveErr
	}
	return &api.SettingsGeneralResponse{Issuer: "https://issuer.example"}, nil
}

func (a settingsSaveAPI) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	if a.saveErr != nil {
		return nil, a.saveErr
	}
	return &api.SettingsEmailResponse{}, nil
}

func (a settingsSaveAPI) GetSettingsUITheme(context.Context, string) (*api.SettingsUIThemeResponse, error) {
	return &api.SettingsUIThemeResponse{UITheme: "light", AvailableThemes: []string{"light", "dark"}}, nil
}

func (a settingsSaveAPI) UpdateSettingsUITheme(context.Context, string, *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error) {
	if a.saveErr != nil {
		return nil, a.saveErr
	}
	return &api.SettingsUIThemeResponse{}, nil
}

// The rest of the ports settingsSaveAPI is passed to, which no test here reaches.

func (settingsSaveAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to GetSettingsEmail")
}

func (settingsSaveAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	panic("unexpected call to SendTestEmail")
}

// The three saves whose values the console itself renders from (the app name, the theme, whether
// SMTP is on) drop the cached public settings once the auth server has accepted the save, so the
// next page shows what was saved. A refused save changed nothing and keeps the cache (#440
// decision 5).
func TestAdminSettingsSaves_InvalidateTheCacheOnlyWhenTheSaveIsAccepted(t *testing.T) {
	handlerCases := []struct {
		name     string
		template string
		form     url.Values
		build    func(h *handlersmocks.HttpHelper, c settingsSaveAPI, cache SettingsInvalidator) http.HandlerFunc
	}{
		{
			name:     "HandleGeneralPost",
			template: "/admin_settings_general.html",
			form:     url.Values{"appName": {"Goiabada"}, "issuer": {"https://issuer.example"}},
			build: func(h *handlersmocks.HttpHelper, c settingsSaveAPI, cache SettingsInvalidator) http.HandlerFunc {
				return HandleGeneralPost(h, newSettingsTestStore(), c, cache, consoleBaseURL)
			},
		},
		{
			name:     "HandleEmailPost",
			template: "/admin_settings_email.html",
			form:     url.Values{"hostOrIP": {"smtp.example.com"}, "port": {"587"}},
			build: func(h *handlersmocks.HttpHelper, c settingsSaveAPI, cache SettingsInvalidator) http.HandlerFunc {
				return HandleEmailPost(h, newSettingsTestStore(), c, cache, consoleBaseURL)
			},
		},
		{
			name:     "HandleUIThemePost",
			template: "/admin_settings_ui_theme.html",
			form:     url.Values{"themeSelection": {"dark"}},
			build: func(h *handlersmocks.HttpHelper, c settingsSaveAPI, cache SettingsInvalidator) http.HandlerFunc {
				return HandleUIThemePost(h, newSettingsTestStore(), c, cache, consoleBaseURL)
			},
		},
	}

	for _, hc := range handlerCases {
		t.Run(hc.name+", accepted", func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			cache := &invalidationRecorder{}
			w := httptest.NewRecorder()

			hc.build(httpHelper, settingsSaveAPI{}, cache).ServeHTTP(w,
				handlertest.Request(http.MethodPost, "/admin/settings", handlertest.WithAccessToken(),
					handlertest.WithForm(hc.form)))

			assert.Equal(t, http.StatusFound, w.Code, "an accepted save redirects")
			assert.Equal(t, 1, cache.invalidations)
		})

		t.Run(hc.name+", refused", func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", hc.template).Once()
			cache := &invalidationRecorder{}

			hc.build(httpHelper, settingsSaveAPI{
				saveErr: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Not that.", StatusCode: http.StatusBadRequest},
			}, cache).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings", handlertest.WithAccessToken(),
					handlertest.WithForm(hc.form)))

			assert.Equal(t, "Not that.", handlertest.Bind(t, httpHelper)["error"], "the refused form is redrawn")
			assert.Equal(t, 0, cache.invalidations)
		})
	}
}
