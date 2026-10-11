package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// The account pages' own refusals come from the catalog in the language the page is rendered in:
// English with no language on the request and Portuguese under pt-BR (#559 decision 4). Two reuse
// keys the auth server's sign-in pages already had. The two-factor enrolment's "OTP code is
// required." is handler.otp.code_required word for word; change password's confirmation mismatch is
// handler.password.confirmation_mismatch, whose English has no "new", so that one sentence reads
// differently in English than it did.
func TestAccountPages_RefuseInThePagesLanguage(t *testing.T) {
	testCases := []struct {
		name       string
		template   string
		handler    func(httpHelper *handlersmocks.HttpHelper) http.HandlerFunc
		target     string
		form       url.Values
		english    string
		portuguese string
	}{
		{
			name:     "an email change whose confirmation differs",
			template: "/account_email.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleEmailPost(h, nil, &emailRecordingApiClient{}, consoleBaseURL)
			},
			target: "/account/email",
			form: url.Values{"email": {"new@example.com"}, "emailConfirmation": {"other@example.com"},
				"currentPassword": {accountEmailFormPassword}},
			english:    "The email and email confirmation entries must be identical.",
			portuguese: "Os campos de e-mail e de confirmação de e-mail devem ser idênticos.",
		},
		{
			name:     "a password change whose confirmation differs",
			template: "/account_change_password.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleChangePasswordPost(h, nil, &passwordRecordingApiClient{}, consoleBaseURL)
			},
			target: "/account/change-password",
			form: url.Values{"currentPassword": {accountPasswordFormCurrent},
				"newPassword": {accountPasswordFormNew}, "newPasswordConfirmation": {"something-else"}},
			english:    "The password confirmation does not match the password.",
			portuguese: "A confirmação da senha não confere com a senha.",
		},
		{
			name:     "a two-factor enrolment with no code",
			template: "/account_otp.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleOtpPost(h, newStubApiClient(false), consoleBaseURL)
			},
			target:     accountOTPPath,
			form:       url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {""}},
			english:    "OTP code is required.",
			portuguese: "O código OTP é obrigatório.",
		},
	}

	for _, testCase := range testCases {
		for _, language := range []struct{ name, tag, want string }{
			{"with no language", "", testCase.english},
			{"in pt-BR", "pt-BR", testCase.portuguese},
		} {
			t.Run(testCase.name+" "+language.name, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, mock.Anything, testCase.template).Once()

				req := handlertest.Request(http.MethodPost, testCase.target,
					handlertest.WithAccessToken(), handlertest.WithLocale(language.tag),
					handlertest.WithForm(testCase.form))
				testCase.handler(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
