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

// The save always sends the cap, as entered. 0 is a cap, no limit, so it is sent as 0.
func TestHandleSessionsPost_AlwaysSendsTheCap(t *testing.T) {
	for _, entered := range []struct {
		value string
		sent  int
	}{{"5", 5}, {"0", 0}, {" 12 ", 12}} {
		t.Run(entered.value, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &sessionsAPI{}

			req := handlertest.Request(http.MethodPost, "/admin/settings/sessions",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"userSessionIdleTimeoutInSeconds": {"3600"},
					"userSessionMaxLifetimeInSeconds": {"43200"},
					"maxUserSessionsPerUser":          {entered.value},
				}))
			w := httptest.NewRecorder()
			HandleSessionsPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			require.NotNil(t, apiClient.sent)
			assert.Equal(t, 3600, apiClient.sent.UserSessionIdleTimeoutInSeconds)
			assert.Equal(t, 43200, apiClient.sent.UserSessionMaxLifetimeInSeconds)
			require.NotNil(t, apiClient.sent.MaxUserSessionsPerUser, "the cap is always sent")
			assert.Equal(t, entered.sent, *apiClient.sent.MaxUserSessionsPerUser)
		})
	}
}

// A value that is not a whole number is refused in the console, at its field, and nothing is sent:
// sent as 0, a lifetime would be refused as not greater than zero, and the cap would be off.
func TestHandleSessionsPost_RefusesAValueThatIsNotAWholeNumberAtItsField(t *testing.T) {
	testCases := []struct {
		name, field, message string
	}{
		{"userSessionIdleTimeoutInSeconds", "userSessionIdleTimeoutInSeconds", "Enter the idle timeout as a whole number of seconds."},
		{"userSessionMaxLifetimeInSeconds", "userSessionMaxLifetimeInSeconds", "Enter the maximum lifetime as a whole number of seconds."},
		{"maxUserSessionsPerUser", "maxUserSessionsPerUser", "Enter the maximum sessions per user as a whole number, from 0 to 1000."},
	}
	for _, tc := range testCases {
		for _, entered := range []string{"abc", ""} {
			t.Run(tc.name+" "+entered, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, mock.Anything, "/admin_settings_sessions.html").Once()
				apiClient := &sessionsAPI{}
				form := url.Values{
					"userSessionIdleTimeoutInSeconds": {"3600"},
					"userSessionMaxLifetimeInSeconds": {"43200"},
					"maxUserSessionsPerUser":          {"20"},
				}
				form.Set(tc.field, entered)

				req := handlertest.Request(http.MethodPost, "/admin/settings/sessions",
					handlertest.WithAccessToken(), handlertest.WithForm(form))
				HandleSessionsPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), req)

				assert.Nil(t, apiClient.sent, "nothing is sent")
				bind := handlertest.Bind(t, httpHelper)
				assert.Equal(t, tc.message, bind["error"])
				assert.Equal(t, tc.field, bind["errorField"])
			})
		}
	}
}

// A refused save redraws the form with the cap as it was entered, beside the auth server's refusal,
// which marks the field its code names.
func TestHandleSessionsPost_ARefusedSaveRedrawsTheCapAsEntered(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	var bind map[string]interface{}
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html",
		"/admin_settings_sessions.html", mock.Anything).
		Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).
		Return(nil).Once()
	refusal := "The maximum sessions per user must be between 0 and 1000."
	apiClient := &sessionsAPI{updateErr: &apiclient.APIError{Code: "handler.settings_sessions.max_sessions_per_user_out_of_range",
		Message: refusal, StatusCode: http.StatusBadRequest}}

	req := handlertest.Request(http.MethodPost, "/admin/settings/sessions",
		handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
			"userSessionIdleTimeoutInSeconds": {"3600"},
			"userSessionMaxLifetimeInSeconds": {"43200"},
			"maxUserSessionsPerUser":          {"1001"},
		}))
	HandleSessionsPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, bind)
	assert.Equal(t, refusal, bind["error"])
	assert.Equal(t, "maxUserSessionsPerUser", bind["errorField"], "the refusal's code names its field")
	assert.Equal(t, SettingsSessionPost{
		UserSessionIdleTimeoutInSeconds: "3600",
		UserSessionMaxLifetimeInSeconds: "43200",
		MaxUserSessionsPerUser:          "1001",
	}, bind["settings"])
}
