package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// uiThemeAPI refuses the save with updateErr and answers the theme list the refused form is
// redrawn with, or listErr.
type uiThemeAPI struct {
	updateErr error
	listErr   error
	listReads int
}

func (a *uiThemeAPI) GetSettingsUITheme(context.Context, string) (*api.SettingsUIThemeResponse, error) {
	a.listReads++
	if a.listErr != nil {
		return nil, a.listErr
	}
	return &api.SettingsUIThemeResponse{UITheme: "light", AvailableThemes: []string{"light", "dark"}}, nil
}

func (a *uiThemeAPI) UpdateSettingsUITheme(context.Context, string, *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error) {
	return nil, a.updateErr
}

func apiStatus(status int, message string) error {
	return &apiclient.APIError{Code: "a-code", Message: message, StatusCode: status}
}

// A refused save redraws the form with the theme list read again beside it, and the list is the
// part the form can do without. A 401 is the one failure of that read the form is not redrawn past:
// the session ended between the save and the read, and a resubmission would meet the same refusal.
// It goes to the session-ended route, as a 401 from the save does (#427 decision 17, final review
// round 2). Any other failure redraws the form without the list, as it did before.
func TestHandleAdminSettingsUIThemePost_OnlyASessionEndedListReadStopsTheRedraw(t *testing.T) {
	testCases := []struct {
		name      string
		updateErr error
		listErr   error
		ended     bool
		listReads int
		themes    []string
	}{
		{
			name:      "a 400 save, then a 401 on the list",
			updateErr: apiStatus(http.StatusBadRequest, "That theme does not exist."),
			listErr:   apiStatus(http.StatusUnauthorized, "Session has been terminated"),
			ended:     true,
			listReads: 1,
		},
		{
			name:      "a 409 save, then a 401 on the list",
			updateErr: apiStatus(http.StatusConflict, "Someone else saved first."),
			listErr:   apiStatus(http.StatusUnauthorized, "Session has expired"),
			ended:     true,
			listReads: 1,
		},
		{
			name:      "a 401 on the save itself, with no list read after it",
			updateErr: apiStatus(http.StatusUnauthorized, "Session has been terminated"),
			ended:     true,
		},
		{
			name:      "a 400 save, then a 500 on the list, redraws without the list",
			updateErr: apiStatus(http.StatusBadRequest, "That theme does not exist."),
			listErr:   apiStatus(http.StatusInternalServerError, "Internal error"),
			listReads: 1,
			themes:    []string{},
		},
		{
			name:      "a 400 save, then a 403 on the list, redraws without the list",
			updateErr: apiStatus(http.StatusBadRequest, "That theme does not exist."),
			listErr:   apiStatus(http.StatusForbidden, "Forbidden"),
			listReads: 1,
			themes:    []string{},
		},
		{
			name:      "a 400 save, then the list, redraws with it",
			updateErr: apiStatus(http.StatusBadRequest, "That theme does not exist."),
			listReads: 1,
			themes:    []string{"light", "dark"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			var bind map[string]interface{}
			if !tc.ended {
				httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html",
					"/admin_settings_ui_theme.html", mock.Anything).
					Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).
					Return(nil).Once()
			}

			apiClient := &uiThemeAPI{updateErr: tc.updateErr, listErr: tc.listErr}
			req := handlertest.Request(http.MethodPost, "/admin/settings/ui-theme",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"themeSelection": {"purple"}}))
			w := httptest.NewRecorder()
			HandleAdminSettingsUIThemePost(httpHelper, newSettingsTestStore(), apiClient,
				cache.NewSettingsCache("http://auth.example.invalid")).ServeHTTP(w, req)

			assert.Equal(t, tc.listReads, apiClient.listReads)
			if tc.ended {
				assert.Equal(t, http.StatusFound, w.Code)
				assert.Equal(t, "/auth/session-ended", w.Header().Get("Location"),
					"no form is redrawn for a session that has ended")
				return
			}

			require.NotNil(t, bind, "the refused form is redrawn")
			assert.Equal(t, tc.updateErr.(*apiclient.APIError).Message, bind["error"])
			assert.Equal(t, tc.themes, bind["uiThemes"])
			assert.Equal(t, SettingsUITheme{UITheme: "purple"}, bind["settings"], "with what was typed")
		})
	}
}
