package renderintegration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refusal the person can act on is drawn on the form they submitted, with the auth server's
// sentence, or the console's own for too many attempts, never as the 500 page or a page with no
// message (#562 decision 7).

// tooManyRequests is the auth server's rate limiter's answer to an API caller, word for word.
var tooManyRequests = &apiclient.APIError{Code: "TOO_MANY_REQUESTS",
	Message: "Too many requests. Please wait and try again later.", StatusCode: http.StatusTooManyRequests}

// ---- Settings > Email > Send test email ----

// sendTestEmailAPI is the auth server as the send-test page reaches it: a send it refuses.
type sendTestEmailAPI struct {
	refusal error
}

func (a *sendTestEmailAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	return a.refusal
}

func (*sendTestEmailAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	return &api.SettingsEmailResponse{SMTPEnabled: true}, nil
}

func (*sendTestEmailAPI) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to UpdateSettingsEmail")
}

// A malformed address is refused by the auth server's email validator, a 400 under the localized
// error's own code, which is not one the page named, so it answered the 500 page. It is drawn on the
// form with the address as typed, as every other 400 of the send is.
func TestRender_AdminSettingsEmailSendTest_AMalformedAddressIsDrawnOnTheForm(t *testing.T) {
	const refusal = "Informe um endereço de e-mail válido."
	apiClient := &sendTestEmailAPI{refusal: &apiclient.APIError{
		Code: "validator.email.invalid_format", Message: refusal, StatusCode: http.StatusBadRequest}}

	out := serveRefusal(t,
		adminsettingshandlers.HandleEmailSendTestPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
		"/admin/settings/email/send-test-email", url.Values{"destinationEmail": {"someone@@example"}},
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: true}))

	assert.Contains(t, out, refusal)
	input := inputRe("destinationEmail").FindString(out)
	require.NotEmpty(t, input, "the address input is drawn")
	assert.Contains(t, input, `value="someone@@example"`, "the address as typed")
}

// ---- Account > Email verification ----

// emailVerificationAPI is the auth server as the verification page reaches it: the profile as
// stored, and a code it refuses.
type emailVerificationAPI struct {
	profile *api.UserResponse
	refusal error
}

func (a *emailVerificationAPI) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return a.profile, nil
}

func (a *emailVerificationAPI) VerifyAccountEmail(context.Context, string, *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

func (*emailVerificationAPI) SendAccountEmailVerification(context.Context, string) (*api.AccountEmailVerificationSendResponse, error) {
	panic("unexpected call to SendAccountEmailVerification")
}

// A refused code is drawn with its sentence whatever email's state. Email switched off between the
// page's draw and the submission (another administrator, or the console's settings not yet
// refreshed) is refused by the auth server with a sentence the page drew only inside the block it
// draws while email is on, so the user got a page with no message at all; too many attempts at the
// code answered the 500 page.
func TestRender_AccountEmailVerification_ARefusalIsDrawnWhateverEmailsState(t *testing.T) {
	smtpOff := &apiclient.APIError{Code: "SMTP_NOT_ENABLED", Message: "SMTP is not enabled", StatusCode: http.StatusBadRequest}

	testCases := []struct {
		name        string
		smtpEnabled bool
		verified    bool
		refusal     *apiclient.APIError
		// want is the sentence drawn, the API's own when empty.
		want         string
		wantCodeForm bool
	}{
		{name: "email off, the address not verified", smtpEnabled: false, refusal: smtpOff},
		{name: "email off, the address verified", smtpEnabled: false, verified: true, refusal: smtpOff},
		{name: "email on, too many attempts", smtpEnabled: true, refusal: tooManyRequests, wantCodeForm: true,
			// A 429 is drawn with the console's own sentence in the page's language (#559 decision 10).
			want: "Chegaram muitas solicitações deste navegador, ou para esta conta, em pouco tempo. Aguarde alguns minutos e tente novamente."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &emailVerificationAPI{
				profile: &api.UserResponse{Id: 11, Email: "someone@example.com", EmailVerified: tc.verified},
				refusal: tc.refusal,
			}

			out := serveRefusal(t,
				accounthandlers.HandleEmailVerificationPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
				"/account/email-verification", url.Values{"verificationCode": {"ABC123"}},
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: tc.smtpEnabled}))

			want := tc.want
			if want == "" {
				want = tc.refusal.Message
			}
			assert.Contains(t, out, `<p>`+want+`</p>`, "the refusal's sentence is drawn")
			assert.Contains(t, out, `value="someone@example.com"`, "the address the page is about")
			code := inputRe("verificationCode").FindString(out)
			if tc.wantCodeForm {
				assert.Contains(t, code, `value="ABC123"`, "the code as typed")
			} else {
				assert.Empty(t, code, "no code form while email is off")
			}
		})
	}
}
