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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// sessionsAPI answers the stored session settings and records the save the page sends.
type sessionsAPI struct {
	sent      *api.UpdateSettingsSessionsRequest
	updateErr error
}

func (a *sessionsAPI) GetSettingsSessions(context.Context, string) (*api.SettingsSessionsResponse, error) {
	return &api.SettingsSessionsResponse{
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
		MaxUserSessionsPerUser:          20,
	}, nil
}

func (a *sessionsAPI) UpdateSettingsSessions(_ context.Context, _ string, request *api.UpdateSettingsSessionsRequest) (*api.SettingsSessionsResponse, error) {
	a.sent = request
	if a.updateErr != nil {
		return nil, a.updateErr
	}
	return &api.SettingsSessionsResponse{}, nil
}

// The page shows the per-user session cap beside the two lifetimes (#564 decision 6).
func TestHandleSessionsGet_ShowsTheCapBesideTheLifetimes(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	var bind map[string]interface{}
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html",
		"/admin_settings_sessions.html", mock.Anything).
		Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).
		Return(nil).Once()

	req := handlertest.Request(http.MethodGet, "/admin/settings/sessions", handlertest.WithAccessToken())
	HandleSessionsGet(httpHelper, newSettingsTestStore(), &sessionsAPI{}).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, bind)
	assert.Equal(t, SettingsSessionGet{
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
		MaxUserSessionsPerUser:          20,
	}, bind["settings"])
}

// The save always sends the cap, as entered. 0 is a cap, no limit, so it is sent as 0; a value that
// is not a number is never sent as 0, which would turn the cap off, but as one the auth server
// refuses, so the page shows its refusal.
func TestHandleSessionsPost_AlwaysSendsTheCap(t *testing.T) {
	testCases := []struct {
		name    string
		entered string
		check   func(t *testing.T, sent *int)
	}{
		{"a number", "5", func(t *testing.T, sent *int) { assert.Equal(t, 5, *sent) }},
		{"0, no limit", "0", func(t *testing.T, sent *int) { assert.Equal(t, 0, *sent) }},
		{"not a number", "abc", func(t *testing.T, sent *int) {
			assert.True(t, *sent < 0 || *sent > 1000, "sent as a cap the auth server refuses, not %v", *sent)
		}},
		{"empty", "", func(t *testing.T, sent *int) {
			assert.True(t, *sent < 0 || *sent > 1000, "sent as a cap the auth server refuses, not %v", *sent)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &sessionsAPI{}

			req := handlertest.Request(http.MethodPost, "/admin/settings/sessions",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"userSessionIdleTimeoutInSeconds": {"3600"},
					"userSessionMaxLifetimeInSeconds": {"43200"},
					"maxUserSessionsPerUser":          {tc.entered},
				}))
			w := httptest.NewRecorder()
			HandleSessionsPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			require.NotNil(t, apiClient.sent)
			assert.Equal(t, 3600, apiClient.sent.UserSessionIdleTimeoutInSeconds)
			assert.Equal(t, 43200, apiClient.sent.UserSessionMaxLifetimeInSeconds)
			require.NotNil(t, apiClient.sent.MaxUserSessionsPerUser, "the cap is always sent")
			tc.check(t, apiClient.sent.MaxUserSessionsPerUser)
		})
	}
}

// A refused save redraws the form with the cap as it was entered, beside the auth server's refusal.
func TestHandleSessionsPost_ARefusedSaveRedrawsTheCapAsEntered(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	var bind map[string]interface{}
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html",
		"/admin_settings_sessions.html", mock.Anything).
		Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).
		Return(nil).Once()
	refusal := "The maximum sessions per user must be between 0 and 1000."
	apiClient := &sessionsAPI{updateErr: apiStatus(http.StatusBadRequest, refusal)}

	req := handlertest.Request(http.MethodPost, "/admin/settings/sessions",
		handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
			"userSessionIdleTimeoutInSeconds": {"3600"},
			"userSessionMaxLifetimeInSeconds": {"43200"},
			"maxUserSessionsPerUser":          {"1001"},
		}))
	HandleSessionsPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, bind)
	assert.Equal(t, refusal, bind["error"])
	assert.Equal(t, SettingsSessionPost{
		UserSessionIdleTimeoutInSeconds: "3600",
		UserSessionMaxLifetimeInSeconds: "43200",
		MaxUserSessionsPerUser:          "1001",
	}, bind["settings"])
}
