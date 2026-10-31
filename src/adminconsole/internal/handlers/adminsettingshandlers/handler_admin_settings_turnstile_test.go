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
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// turnstileSettingsAPI answers the stored Turnstile settings, and records the save the page sends,
// refusing it with saveErr when one is set.
type turnstileSettingsAPI struct {
	stored  api.SettingsTurnstileResponse
	saveErr error
	sent    *api.UpdateSettingsTurnstileRequest
}

func (a *turnstileSettingsAPI) GetSettingsTurnstile(context.Context, string) (*api.SettingsTurnstileResponse, error) {
	stored := a.stored
	return &stored, nil
}

func (a *turnstileSettingsAPI) UpdateSettingsTurnstile(_ context.Context, _ string, request *api.UpdateSettingsTurnstileRequest) (*api.SettingsTurnstileResponse, error) {
	a.sent = request
	if a.saveErr != nil {
		return nil, a.saveErr
	}
	return &api.SettingsTurnstileResponse{}, nil
}

// The page is told the switch, the site key and whether a secret key is saved, never the secret key
// itself: the box is empty on every load, and the stored switch is kept for the question asked
// before the challenge is turned on (#642 decision 11).
func TestHandleTurnstileGet_ThePageIsToldWhetherASecretKeyIsSaved(t *testing.T) {
	testCases := []struct {
		name      string
		stored    api.SettingsTurnstileResponse
		wantSaved bool
	}{
		{
			name:      "the challenge on with a secret key saved",
			stored:    api.SettingsTurnstileResponse{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA", HasTurnstileSecretKey: true},
			wantSaved: true,
		},
		{
			name:      "the challenge off with no secret key saved",
			stored:    api.SettingsTurnstileResponse{TurnstileSiteKey: "1x00000000000000000000AA"},
			wantSaved: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_turnstile.html").Once()
			apiClient := &turnstileSettingsAPI{stored: tc.stored}

			HandleTurnstileGet(httpHelper, newSettingsTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/turnstile", handlertest.WithAccessToken()))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, SettingsTurnstile{
				TurnstileEnabled:      tc.stored.TurnstileEnabled,
				TurnstileSiteKey:      "1x00000000000000000000AA",
				HasTurnstileSecretKey: tc.wantSaved,
				SavedTurnstileEnabled: tc.stored.TurnstileEnabled,
			}, bind["settings"])
			assert.Equal(t, false, bind["savedSuccessfully"])
		})
	}
}

// turnstileForm is the form the page posts with the challenge on and a secret key saved, with the
// boxes and the removal checkbox as the case leaves them.
func turnstileForm(edit func(url.Values)) url.Values {
	form := url.Values{
		"turnstileEnabled":      {"on"},
		"turnstileSiteKey":      {"1x00000000000000000000AA"},
		"turnstileSecretKey":    {""},
		"hasTurnstileSecretKey": {"true"},
		"savedTurnstileEnabled": {"true"},
	}
	edit(form)
	return form
}

// An empty box keeps the stored secret key, a typed one replaces it, and the ticked checkbox
// removes it: the page sends the box as it is and the removal as clearTurnstileSecretKey, never one
// in place of the other. An unticked switch is the challenge off (#642 decision 11).
func TestHandleTurnstilePost_TheFormBecomesKeepReplaceOrRemove(t *testing.T) {
	testCases := []struct {
		name string
		edit func(url.Values)
		want api.UpdateSettingsTurnstileRequest
	}{
		{
			name: "an empty box",
			edit: func(url.Values) {},
			want: api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA"},
		},
		{
			name: "a typed secret key",
			edit: func(f url.Values) { f.Set("turnstileSecretKey", "1x0000000000000000000000000000000AA") },
			want: api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
				TurnstileSecretKey: "1x0000000000000000000000000000000AA"},
		},
		{
			name: "the challenge off and the removal ticked, which disables the box",
			edit: func(f url.Values) {
				f.Del("turnstileEnabled")
				f.Del("turnstileSecretKey")
				f.Set("clearTurnstileSecretKey", "on")
			},
			want: api.UpdateSettingsTurnstileRequest{TurnstileSiteKey: "1x00000000000000000000AA", ClearTurnstileSecretKey: true},
		},
		{
			name: "a site key pasted with space around it",
			edit: func(f url.Values) {
				f.Set("turnstileSiteKey", " 2x00000000000000000000AB\n")
				f.Set("turnstileSecretKey", "2x0000000000000000000000000000000AA")
			},
			want: api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: "2x00000000000000000000AB",
				TurnstileSecretKey: "2x0000000000000000000000000000000AA"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &turnstileSettingsAPI{}
			w := httptest.NewRecorder()

			HandleTurnstilePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).
				ServeHTTP(w, handlertest.Request(http.MethodPost, "/admin/settings/turnstile",
					handlertest.WithAccessToken(), handlertest.WithForm(turnstileForm(tc.edit))))

			require.Equal(t, http.StatusFound, w.Code, "an accepted save redirects")
			assert.Equal(t, consoleBaseURL+"/admin/settings/turnstile", w.Header().Get("Location"))
			require.NotNil(t, apiClient.sent, "the save reached the API")
			assert.Equal(t, tc.want, *apiClient.sent)
		})
	}
}

// The secret key is read from the body alone: one in the query string would sit in the browser's
// history and every proxy's access log, and is never a submission (#202).
func TestHandleTurnstilePost_TheSecretKeyIsNotReadFromTheQuery(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := &turnstileSettingsAPI{}

	HandleTurnstilePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), handlertest.Request(http.MethodPost,
			"/admin/settings/turnstile?turnstileSecretKey=from-the-query",
			handlertest.WithAccessToken(), handlertest.WithForm(turnstileForm(func(f url.Values) { f.Del("turnstileSecretKey") }))))

	require.NotNil(t, apiClient.sent)
	assert.Empty(t, apiClient.sent.TurnstileSecretKey)
}

// A refused save is redrawn as it was submitted, with the API's sentence, the field its code names,
// the typed secret key back in its box, and the badge, the removal checkbox and the stored switch as
// the page had them (#642 decision 11).
func TestHandleTurnstilePost_ARefusedSaveIsRedrawnWithTheRefusalAtItsField(t *testing.T) {
	testCases := []struct {
		name      string
		code      string
		message   string
		edit      func(url.Values)
		wantField string
		want      SettingsTurnstile
	}{
		{
			name:    "the challenge turned on without a site key",
			code:    "handler.settings_turnstile.site_key_required",
			message: "Enter the site key to turn the Turnstile challenge on.",
			edit: func(f url.Values) {
				f.Set("turnstileSiteKey", "")
				f.Set("turnstileSecretKey", "typed-secret")
				f.Set("hasTurnstileSecretKey", "")
				f.Set("savedTurnstileEnabled", "")
			},
			wantField: "turnstileSiteKey",
			want:      SettingsTurnstile{TurnstileEnabled: true, TurnstileSecretKey: "typed-secret"},
		},
		{
			name:    "a site key too long",
			code:    "handler.settings_turnstile.site_key_too_long",
			message: "The site key can't be longer than 128 characters.",
			edit:    func(url.Values) {},
			want: SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
				HasTurnstileSecretKey: true, SavedTurnstileEnabled: true},
			wantField: "turnstileSiteKey",
		},
		{
			name:    "the challenge turned on without a secret key",
			code:    "handler.settings_turnstile.secret_key_required",
			message: "Enter the secret key to turn the Turnstile challenge on.",
			edit: func(f url.Values) {
				f.Set("hasTurnstileSecretKey", "")
				f.Set("savedTurnstileEnabled", "")
			},
			wantField: "turnstileSecretKey",
			want:      SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA"},
		},
		{
			name:      "the site key changed without the secret key",
			code:      "handler.settings_turnstile.site_key_changed",
			message:   "The site key has changed: enter the secret key again, or remove it.",
			edit:      func(f url.Values) { f.Set("turnstileSiteKey", "2x00000000000000000000AB") },
			wantField: "turnstileSecretKey",
			want: SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "2x00000000000000000000AB",
				HasTurnstileSecretKey: true, SavedTurnstileEnabled: true},
		},
		{
			name:      "a secret key too long",
			code:      "handler.settings_turnstile.secret_key_too_long",
			message:   "The secret key can't be longer than 128 characters.",
			edit:      func(f url.Values) { f.Set("turnstileSecretKey", "a-long-secret") },
			wantField: "turnstileSecretKey",
			want: SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
				TurnstileSecretKey: "a-long-secret", HasTurnstileSecretKey: true, SavedTurnstileEnabled: true},
		},
		{
			name:    "the secret key removed while the challenge stays on",
			code:    "handler.settings_turnstile.secret_key_clear_while_enabled",
			message: "The secret key can't be removed while the Turnstile challenge is on.",
			edit: func(f url.Values) {
				f.Del("turnstileSecretKey")
				f.Set("clearTurnstileSecretKey", "on")
			},
			wantField: "clearTurnstileSecretKey",
			want: SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
				HasTurnstileSecretKey: true, ClearTurnstileSecretKey: true, SavedTurnstileEnabled: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_turnstile.html").Once()
			apiClient := &turnstileSettingsAPI{saveErr: &apiclient.APIError{
				Code: tc.code, Message: tc.message, StatusCode: http.StatusBadRequest,
			}}
			w := httptest.NewRecorder()

			HandleTurnstilePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).
				ServeHTTP(w, handlertest.Request(http.MethodPost, "/admin/settings/turnstile",
					handlertest.WithAccessToken(), handlertest.WithForm(turnstileForm(tc.edit))))

			assert.Empty(t, w.Header().Get("Location"), "a refused save is not redirected")
			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, tc.message, bind["error"])
			assert.Equal(t, tc.wantField, bind["errorField"])
			assert.Equal(t, tc.want, bind["settings"])
		})
	}
}
