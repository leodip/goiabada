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

// emailSettingsAPI answers the stored email settings, and records the save the page sends,
// refusing it with saveErr when one is set.
type emailSettingsAPI struct {
	stored  api.SettingsEmailResponse
	saveErr error
	sent    *api.UpdateSettingsEmailRequest
}

func (a *emailSettingsAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	stored := a.stored
	return &stored, nil
}

func (a *emailSettingsAPI) UpdateSettingsEmail(_ context.Context, _ string, request *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	a.sent = request
	if a.saveErr != nil {
		return nil, a.saveErr
	}
	return &api.SettingsEmailResponse{}, nil
}

func (*emailSettingsAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	panic("unexpected call to SendTestEmail")
}

// The page is told whether a password is stored, and the host it was stored for, so it can show
// the Saved or Not set badge, offer the removal only when there is something to remove, and warn
// when the host is edited away from that one. The password itself never comes back: the box is
// empty on every load (#410 decision 3).
func TestHandleEmailGet_ThePageIsToldWhetherAPasswordIsSavedAndForWhichHost(t *testing.T) {
	testCases := []struct {
		name      string
		hasStored bool
	}{
		{name: "a password is saved", hasStored: true},
		{name: "no password is saved", hasStored: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email.html").Once()
			apiClient := &emailSettingsAPI{stored: api.SettingsEmailResponse{
				SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPUsername: "mailer",
				SMTPEncryption: "starttls", HasSMTPPassword: tc.hasStored,
			}}

			HandleEmailGet(httpHelper, newSettingsTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/email", handlertest.WithAccessToken()))

			settings, ok := handlertest.Bind(t, httpHelper)["settings"].(SettingsEmailGet)
			require.True(t, ok, "the page renders a SettingsEmailGet")
			assert.Equal(t, tc.hasStored, settings.HasSMTPPassword)
			assert.Equal(t, "smtp.example.com", settings.SavedSMTPHost)
			assert.False(t, settings.ClearSMTPPassword, "the removal starts unticked")
			assert.Empty(t, settings.SMTPPassword, "the password box is empty on load")
		})
	}
}

// emailForm is the form the page posts for a password saved for smtp.example.com, with the
// password box and the removal checkbox as the case leaves them.
func emailForm(edit func(url.Values)) url.Values {
	form := url.Values{
		"smtpEnabled":     {"on"},
		"hostOrIP":        {"smtp.example.com"},
		"port":            {"587"},
		"username":        {"mailer"},
		"password":        {""},
		"smtpEncryption":  {"starttls"},
		"fromName":        {"Goiabada"},
		"fromEmail":       {"noreply@example.com"},
		"hasSmtpPassword": {"true"},
		"savedHostOrIP":   {"smtp.example.com"},
	}
	edit(form)
	return form
}

// An empty box keeps the stored password, a typed one replaces it, and the ticked checkbox removes
// it: the page sends the box as it is and the removal as clearSmtpPassword, never one in place of
// the other (#410 decisions 1 and 3).
func TestHandleEmailPost_TheFormBecomesKeepReplaceOrRemove(t *testing.T) {
	testCases := []struct {
		name         string
		edit         func(url.Values)
		wantPassword string
		wantClear    bool
	}{
		{
			name:         "an empty box",
			edit:         func(url.Values) {},
			wantPassword: "",
			wantClear:    false,
		},
		{
			name:         "a typed password",
			edit:         func(f url.Values) { f.Set("password", " n3w pass ") },
			wantPassword: " n3w pass ",
			wantClear:    false,
		},
		{
			name: "the removal ticked, which disables the box",
			edit: func(f url.Values) {
				f.Del("password")
				f.Set("clearSmtpPassword", "on")
			},
			wantPassword: "",
			wantClear:    true,
		},
		{
			name:         "the removal absent, as a page with no saved password posts it",
			edit:         func(f url.Values) { f.Set("hasSmtpPassword", "") },
			wantPassword: "",
			wantClear:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &emailSettingsAPI{}
			w := httptest.NewRecorder()

			HandleEmailPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).
				ServeHTTP(w, handlertest.Request(http.MethodPost, "/admin/settings/email",
					handlertest.WithAccessToken(), handlertest.WithForm(emailForm(tc.edit))))

			require.Equal(t, http.StatusFound, w.Code, "an accepted save redirects")
			require.NotNil(t, apiClient.sent, "the save reached the API")
			assert.Equal(t, tc.wantPassword, apiClient.sent.SMTPPassword)
			assert.Equal(t, tc.wantClear, apiClient.sent.ClearSMTPPassword)
			assert.Equal(t, "smtp.example.com", apiClient.sent.SMTPHost)
		})
	}
}

// A refused save is redrawn as it was submitted: the typed password back in its box, so a
// resubmission sends it rather than keeping the old one, and the badge, the removal checkbox and the
// saved host the host warning compares against as the page had them (#410 decision 3).
func TestHandleEmailPost_ARefusedSaveIsRedrawnWithThePasswordAndTheSavedState(t *testing.T) {
	testCases := []struct {
		name          string
		edit          func(url.Values)
		wantPassword  string
		wantClear     bool
		wantHasStored bool
	}{
		{
			name: "a host change with a typed password",
			edit: func(f url.Values) {
				f.Set("hostOrIP", "smtp.other.example")
				f.Set("password", "typed-secret")
			},
			wantPassword:  "typed-secret",
			wantClear:     false,
			wantHasStored: true,
		},
		{
			name: "a host change with the removal ticked",
			edit: func(f url.Values) {
				f.Set("hostOrIP", "smtp.other.example")
				f.Del("password")
				f.Set("clearSmtpPassword", "on")
			},
			wantPassword:  "",
			wantClear:     true,
			wantHasStored: true,
		},
		{
			name: "a host change with no password saved",
			edit: func(f url.Values) {
				f.Set("hostOrIP", "smtp.other.example")
				f.Set("hasSmtpPassword", "")
			},
			wantPassword:  "",
			wantClear:     false,
			wantHasStored: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email.html").Once()
			cache := &invalidationRecorder{}
			apiClient := &emailSettingsAPI{saveErr: &apiclient.APIError{
				Code: "VALIDATION_ERROR", Message: "Enter the SMTP password again.", StatusCode: http.StatusBadRequest,
			}}

			HandleEmailPost(httpHelper, newSettingsTestStore(), apiClient, cache, consoleBaseURL).
				ServeHTTP(httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/email",
					handlertest.WithAccessToken(), handlertest.WithForm(emailForm(tc.edit))))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "Enter the SMTP password again.", bind["error"])
			settings, ok := bind["settings"].(SettingsEmailPost)
			require.True(t, ok, "the redraw renders a SettingsEmailPost")
			assert.Equal(t, tc.wantPassword, settings.SMTPPassword)
			assert.Equal(t, tc.wantClear, settings.ClearSMTPPassword)
			assert.Equal(t, tc.wantHasStored, settings.HasSMTPPassword)
			assert.Equal(t, "smtp.example.com", settings.SavedSMTPHost, "the host the password was saved for")
			assert.Equal(t, "smtp.other.example", settings.SMTPHost, "the host as typed")
			assert.Equal(t, 0, cache.invalidations)
		})
	}
}
