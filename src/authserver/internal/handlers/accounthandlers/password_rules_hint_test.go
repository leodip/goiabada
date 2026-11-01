package accounthandlers

// The three forms that set a password on the auth server, registration, activation and reset, show
// the nist policy's hint under the password field, with its passphrase guidance, before anything
// is refused (#550 decision 10).

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// nistHint is #550 decision 10's hint, word for word.
const nistHint = "At least 15 characters. A few unrelated words make a long password that's easy to " +
	"remember. Common passwords, and the account's email address or the app's name, are refused."

// withNistPolicy puts an installation on the nist policy, registration open, on req.
func withNistPolicy(req *http.Request) *http.Request {
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{
		AppName: "Goiabada", SelfRegistrationEnabled: true, PasswordPolicy: record.PasswordPolicyNist,
	}))
}

// captureRendered stubs one rendering of page and returns where its data lands.
func captureRendered(pageRenderer *handlersmocks.PageRenderer, page string) *map[string]interface{} {
	rendered := new(map[string]interface{})
	pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", page, mock.Anything).
		Run(func(args mock.Arguments) { *rendered = args.Get(4).(map[string]interface{}) }).
		Return(nil).Once()
	return rendered
}

func TestPasswordForms_ShowTheNistHint(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		rendered := captureRendered(pageRenderer, "/account_register.html")

		HandleRegisterGet(pageRenderer, heldCeremonies{}, legalDocumentsInEffect{}).ServeHTTP(httptest.NewRecorder(),
			withNistPolicy(httptest.NewRequest("GET", "/account/register", nil)))

		assert.Equal(t, nistHint, (*rendered)["passwordRules"])
	})

	t.Run("activation", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		store := newMarkerTestStore()
		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, "the-emitted-code", time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
		rendered := captureRendered(pageRenderer, "/account_activate_password.html")

		sent := withMarker(t, store, withNistPolicy(httptest.NewRequest("GET", emaillinks.AccountActivatePath, nil)),
			emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash)
		HandleActivateGet(pageRenderer, store, database, handlersmocks.NewAuditLogger(t), testDataCipher).
			ServeHTTP(httptest.NewRecorder(), sent)

		assert.Equal(t, nistHint, (*rendered)["passwordRules"])
	})

	t.Run("reset", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		store := newMarkerTestStore()
		database.On("GetUserByForgotPasswordCodeHash", mock.Anything, (*sql.Tx)(nil), "the-code-hash").
			Return(&record.User{Id: 1, Enabled: true}, nil).Once()
		rendered := captureRendered(pageRenderer, "/reset_password.html")

		sent := withMarker(t, store, withNistPolicy(resetCleanGetRequest()), emaillinks.LinkMarkerFlowResetPassword, 1, "the-code-hash")
		HandleResetPasswordGet(pageRenderer, store, database, handlersmocks.NewAuditLogger(t), testDataCipher).
			ServeHTTP(httptest.NewRecorder(), sent)

		assert.Equal(t, nistHint, (*rendered)["passwordRules"])
	})

	t.Run("in the page's language", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		rendered := captureRendered(pageRenderer, "/account_register.html")
		req := withNistPolicy(httptest.NewRequest("GET", "/account/register", nil))
		req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))

		HandleRegisterGet(pageRenderer, heldCeremonies{}, legalDocumentsInEffect{}).ServeHTTP(httptest.NewRecorder(), req)

		require.NotNil(t, *rendered)
		//nolint:misspell // the pt-BR catalog's text: "relação" is Portuguese, not a misspelling of "real"
		assert.Equal(t, "Pelo menos 15 caracteres. Algumas palavras sem relação entre si formam uma senha longa e "+
			"fácil de lembrar. Senhas comuns, o endereço de e-mail da conta e o nome do aplicativo são recusados.",
			(*rendered)["passwordRules"])
	})
}
