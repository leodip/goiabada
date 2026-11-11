package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// The forgot password and registration pages link back to signing in under their forms. A page whose
// URL names no sign-in links the admin console's account page, which starts the console's own
// sign-in, rather than a bare /auth/pwd, which a browser holding any other sign-in answers as no
// longer active and audits as a ceremony mismatch (#812). Every render of either page, the
// handlers' own and the Turnstile challenge's refusal, is handed the console's base URL for it; a
// render without it would link a relative /account/profile the auth server does not serve.
func TestSignInLink_EveryRenderIsHandedTheConsolesURL(t *testing.T) {
	unreached := func(t *testing.T) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("a refused submission reached the handler")
		})
	}
	withSettings := func(req *http.Request, settings *record.Settings) *http.Request {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req.WithContext(reqctx.WithSettings(req.Context(), settings))
	}
	challengeOn := &record.Settings{SMTPEnabled: true, SelfRegistrationEnabled: true,
		TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA"}

	for _, tc := range []struct {
		name     string
		template string
		// serve builds the handler and its request, setting what it expects of its other ports.
		serve func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request)
	}{
		{
			name:     "the forgot password form",
			template: "/forgot_password.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				return HandleForgotPasswordGet(pageRenderer, testAdminConsoleBaseURL),
					withEmailOn(httptest.NewRequest(http.MethodGet, "/forgot-password", nil))
			},
		},
		{
			name:     "the forgot password form beside a refused address",
			template: "/forgot_password.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				auditLogger := handlersmocks.NewAuditLogger(t)
				captureRequestedPasswordReset(auditLogger)
				return HandleForgotPasswordPost(pageRenderer, datamocks.NewDatabase(t), accounthandlersmocks.NewEmailSender(t),
						auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL),
					forgotPasswordRequest("not-an-address")
			},
		},
		{
			name:     "the page saying the link was sent",
			template: "/forgot_password.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				database := datamocks.NewDatabase(t)
				database.On("GetUserByEmail", mock.Anything, mock.Anything, "nobody@example.com").Return(nil, nil).Once()
				return HandleForgotPasswordPost(pageRenderer, database, accounthandlersmocks.NewEmailSender(t),
						handlersmocks.NewAuditLogger(t), &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL),
					forgotPasswordRequest("nobody@example.com")
			},
		},
		{
			name:     "the forgot password form beside the challenge's refusal",
			template: "/forgot_password.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				return RequireForgotPasswordChallenge(pageRenderer, refusingVerifier{}, testAdminConsoleBaseURL)(unreached(t)),
					withSettings(httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader("")), challengeOn)
			},
		},
		{
			name:     "the registration form",
			template: "/account_register.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				return HandleRegisterGet(pageRenderer, heldCeremonies{}, legalDocumentsInEffect{}, testAdminConsoleBaseURL),
					registerRequest(http.MethodGet, "")
			},
		},
		{
			name:     "the registration form beside a refusal",
			template: "/account_register.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				return HandleRegisterPost(pageRenderer, heldCeremonies{}, legalDocumentsInEffect{}, datamocks.NewDatabase(t),
						accounthandlersmocks.NewUserCreator(t), accounthandlersmocks.NewEmailValidator(t),
						accounthandlersmocks.NewPasswordValidator(t), accounthandlersmocks.NewEmailSender(t),
						handlersmocks.NewAuditLogger(t), &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL),
					registerRequest(http.MethodPost, "")
			},
		},
		{
			name:     "the registration form beside the challenge's refusal",
			template: "/account_register.html",
			serve: func(t *testing.T, pageRenderer *handlersmocks.PageRenderer) (http.Handler, *http.Request) {
				return RequireRegistrationChallenge(pageRenderer, heldCeremonies{}, legalDocumentsInEffect{},
						refusingVerifier{}, testAdminConsoleBaseURL)(unreached(t)),
					withSettings(httptest.NewRequest(http.MethodPost, "/account/register", strings.NewReader("")), challengeOn)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			handler, req := tc.serve(t, pageRenderer)
			var bind map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", tc.template, mock.Anything).
				Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).Return(nil).Once()

			handler.ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, bind, "the page is drawn")
			assert.Equal(t, testAdminConsoleBaseURL, bind["adminConsoleBaseUrl"])
			assert.Empty(t, bind["ceremonyId"], "the page's URL names no sign-in")
		})
	}
}
