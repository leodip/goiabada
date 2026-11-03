package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// A configuration made while email is off starts from SSL/TLS on port 465, whatever mode and port
// the stored row holds, since turning email off stores none and port 0. A configuration that is on
// shows its stored mode and port, and an empty stored mode is the one the sender reads it as,
// STARTTLS if available (#718 decisions 5 and 11).
func TestHandleEmailGet_ANewConfigurationStartsFromSSLTLSOnPort465(t *testing.T) {
	testCases := []struct {
		name           string
		stored         api.SettingsEmailResponse
		wantEncryption string
		wantPort       int
	}{
		{
			name:           "email off, as turning it off stores it",
			stored:         api.SettingsEmailResponse{SMTPEnabled: false, SMTPEncryption: "none", SMTPPort: 0},
			wantEncryption: "ssltls", wantPort: 465,
		},
		{
			name:           "email off, on a fresh install's empty mode",
			stored:         api.SettingsEmailResponse{SMTPEnabled: false, SMTPEncryption: "", SMTPPort: 0},
			wantEncryption: "ssltls", wantPort: 465,
		},
		{
			name:           "email off, whatever mode and port are stored",
			stored:         api.SettingsEmailResponse{SMTPEnabled: false, SMTPEncryption: "starttls", SMTPPort: 587},
			wantEncryption: "ssltls", wantPort: 465,
		},
		{
			name:           "email on with STARTTLS if available keeps it",
			stored:         api.SettingsEmailResponse{SMTPEnabled: true, SMTPHost: "mailpit", SMTPEncryption: "none", SMTPPort: 1025},
			wantEncryption: "none", wantPort: 1025,
		},
		{
			name:           "email on with STARTTLS keeps it",
			stored:         api.SettingsEmailResponse{SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPEncryption: "starttls", SMTPPort: 587},
			wantEncryption: "starttls", wantPort: 587,
		},
		{
			name:           "email on with an empty mode shows STARTTLS if available",
			stored:         api.SettingsEmailResponse{SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPEncryption: "", SMTPPort: 25},
			wantEncryption: "none", wantPort: 25,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email.html").Once()

			HandleEmailGet(httpHelper, newSettingsTestStore(), &emailSettingsAPI{stored: tc.stored}).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/email", handlertest.WithAccessToken()))

			settings, ok := handlertest.Bind(t, httpHelper)["settings"].(SettingsEmailGet)
			require.True(t, ok, "the page renders a SettingsEmailGet")
			assert.Equal(t, tc.wantEncryption, settings.SMTPEncryption)
			assert.Equal(t, tc.wantPort, settings.SMTPPort)
			assert.Equal(t, tc.stored.SMTPEnabled, settings.SMTPEnabled)
		})
	}
}

// sendTestAnsweringAPI sends every test email, answering whether it went encrypted, and reports
// email as on.
type sendTestAnsweringAPI struct {
	encrypted bool
}

func (*sendTestAnsweringAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	return &api.SettingsEmailResponse{SMTPEnabled: true}, nil
}

func (a *sendTestAnsweringAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) (*api.SendTestEmailResponse, error) {
	return &api.SendTestEmailResponse{Success: true, Encrypted: a.encrypted}, nil
}

func (*sendTestAnsweringAPI) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to UpdateSettingsEmail")
}

// A test email the auth server sent unencrypted is said so on the page the send redirects to; one
// sent encrypted reads as before. Each is said once: a reload says neither (#718 decision 16).
func TestHandleEmailSendTest_TheRedirectedPageSaysWhetherTheTestEmailWentUnencrypted(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "sent unencrypted", true: "sent encrypted"}[encrypted], func(t *testing.T) {
			store := newSettingsTestStore()
			apiClient := &sendTestAnsweringAPI{encrypted: encrypted}

			postHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, postHelper)
			sent := httptest.NewRecorder()
			HandleEmailSendTestPost(postHelper, store, apiClient, consoleBaseURL).ServeHTTP(sent,
				handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email", handlertest.WithAccessToken(),
					handlertest.WithForm(url.Values{"destinationEmail": {"ana@example.com"}})))
			require.Equal(t, http.StatusFound, sent.Code)
			assert.Equal(t, consoleBaseURL+"/admin/settings/email/send-test-email", sent.Header().Get("Location"))

			// The browser keeps the cookies each answer sets.
			jar := map[string]*http.Cookie{}
			keep := func(rec *httptest.ResponseRecorder) {
				for _, c := range rec.Result().Cookies() {
					jar[c.Name] = c
				}
			}
			keep(sent)

			// load draws the page as the browser next asks for it, and returns its bind.
			load := func() map[string]interface{} {
				helper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, helper)
				handlertest.ExpectRender(helper, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html").Once()
				req := handlertest.Request(http.MethodGet, "/admin/settings/email/send-test-email", handlertest.WithAccessToken())
				for _, c := range jar {
					req.AddCookie(c)
				}
				rec := httptest.NewRecorder()
				HandleEmailSendTestGet(helper, store, apiClient).ServeHTTP(rec, req)
				keep(rec)
				return handlertest.Bind(t, helper)
			}

			bind := load()
			assert.Equal(t, "ana@example.com", bind["sentTo"])
			assert.Equal(t, !encrypted, bind["sentUnencrypted"])

			reloaded := load()
			assert.Empty(t, reloaded["sentTo"], "a reload says nothing was sent")
			assert.Equal(t, false, reloaded["sentUnencrypted"], "a reload says nothing went unencrypted")
		})
	}
}

// Only the last send's answer is said: an unencrypted send whose page was never loaded does not
// make a later encrypted one read as unencrypted.
func TestHandleEmailSendTest_AnEarlierUnshownSendIsNotSaidOfALaterOne(t *testing.T) {
	store := newSettingsTestStore()
	jar := map[string]*http.Cookie{}
	send := func(encrypted bool) {
		helper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, helper)
		req := handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"destinationEmail": {"ana@example.com"}}))
		for _, c := range jar {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		HandleEmailSendTestPost(helper, store, &sendTestAnsweringAPI{encrypted: encrypted}, consoleBaseURL).ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)
		for _, c := range rec.Result().Cookies() {
			jar[c.Name] = c
		}
	}

	send(false)
	send(true)

	helper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, helper)
	handlertest.ExpectRender(helper, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html").Once()
	req := handlertest.Request(http.MethodGet, "/admin/settings/email/send-test-email", handlertest.WithAccessToken())
	for _, c := range jar {
		req.AddCookie(c)
	}
	HandleEmailSendTestGet(helper, store, &sendTestAnsweringAPI{}).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, helper)
	assert.Equal(t, "ana@example.com", bind["sentTo"])
	assert.Equal(t, false, bind["sentUnencrypted"], "the last send went encrypted")
}
