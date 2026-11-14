package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestItalian_SignInPageUsesQueryOrSwissHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=it", "en"},
		{"/auth/pwd", "it-CH"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(req,
				"layouts/auth_layout.html", "auth_pwd.html", map[string]interface{}{
					"error": i18n.NewLocalizedError(i18n.ErrCodeLoginAuthFailed, nil).Localize(req.Context()),
				})
			require.NoError(t, err)
			assert.Contains(t, buf.String(), `<html lang="it"`)
			assert.Contains(t, buf.String(), `>Accedi</h1>`)
			assert.Contains(t, buf.String(), `>Accedi</button>`)
			assert.Contains(t, buf.String(), "Autenticazione non riuscita.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Italian, in any
// region: the subject, the language the email is marked with, and a sentence of the body, the
// activation link's and the verification code's saying how long they last, and the recovery code
// notice's giving the codes left.
func TestItalian_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"it", "it-IT", "it-CH", "it-SM", "it-VA"}, "it", []definedEmail{
		{emailtemplate.ActivationLink, "Attiva il tuo account", "Il link scade tra 5 minuti."},
		{emailtemplate.RegistrationExistingAccount, "Hai già un account", "non ne è stato creato uno nuovo."},
		{emailtemplate.Welcome, "Benvenuto!", "Il tuo account è stato creato."},
		{emailtemplate.VerificationCode, "Verifica email - codice 482915", "Il codice scade tra 5 minuti."},
		{emailtemplate.NewUserSetup, "Acme Portal - crea una password per il tuo nuovo account", "Per creare la tua password, apri questo link:"},
		{emailtemplate.TestEmail, "Acme Portal - email di prova", "Questa è un’email di prova inviata da Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Il tuo indirizzo email è stato cambiato", "qualcun altro potrebbe conoscere la tua password."},
		{emailtemplate.PasswordChanged, "La tua password è stata cambiata", "Altrimenti, qualcun altro potrebbe usare il tuo account."},
		{emailtemplate.PasswordChangedByAdministrator, "Un amministratore ha cambiato la tua password", "Se non te lo aspettavi, contatta il tuo amministratore."},
		{emailtemplate.PasswordReset, "La tua password è stata reimpostata", "Altrimenti, qualcun altro potrebbe leggere la tua email e usare il tuo account."},
		{emailtemplate.OTPEnabled, "L'autenticazione a due fattori è stata configurata", "Insieme è stato creato un nuovo set di codici di recupero"},
		{emailtemplate.OTPDisabled, "L'autenticazione a due fattori è stata disattivata", "configura di nuovo l'autenticazione a due fattori"},
		{emailtemplate.OTPDisabledByAdministrator, "Un amministratore ha disattivato la tua autenticazione a due fattori", "Puoi configurare una nuova app di autenticazione"}, //nolint:misspell // the it catalog's text: "configurare" is Italian, not a misspelling of "configure"
		{emailtemplate.RecoveryCodeUsed, "È stato usato un codice di recupero per accedere", "Codici di recupero inutilizzati rimasti: 3."},
		{emailtemplate.RecoveryCodesReplaced, "I tuoi codici di recupero sono stati sostituiti", "I codici di recupero precedenti non funzionano più"},
		{emailtemplate.OTPLockout, "La tua app di autenticazione è stata bloccata dopo troppi codici errati", "Accedi con uno dei tuoi codici di recupero"},
		{emailtemplate.AccountDeleted, "Il tuo account è stato eliminato", "Altrimenti, qualcun altro conosceva la tua password."},                                //nolint:misspell // the it catalog's text: "eliminato" is Italian, not a misspelling of "elimination"
		{emailtemplate.AccountDeletedByAdministrator, "Un amministratore ha eliminato il tuo account", "Se non te lo aspettavi, contatta il tuo amministratore."}, //nolint:misspell // the it catalog's text: "eliminato" is Italian, not a misspelling of "elimination"
	})
}
