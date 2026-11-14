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

func TestGerman_SignInPageUsesQueryOrAustrianHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=de", "en"},
		{"/auth/pwd", "de-AT"},
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
			assert.Contains(t, buf.String(), `<html lang="de"`)
			assert.Contains(t, buf.String(), `>Anmelden</h1>`)
			assert.Contains(t, buf.String(), `>Anmelden</button>`)
			assert.Contains(t, buf.String(), "Anmeldung fehlgeschlagen.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading German, in any
// region: the subject, the language the email is marked with, and a sentence of the body, the
// activation link's and the verification code's saying how long they last, and the recovery code
// notice's giving the codes left.
func TestGerman_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"de", "de-DE", "de-AT", "de-CH", "de-LI"}, "de", []definedEmail{
		{emailtemplate.ActivationLink, "Aktivieren Sie Ihr Konto", "Der Link läuft nach 5 Minuten ab."},
		{emailtemplate.RegistrationExistingAccount, "Sie haben bereits ein Konto", "Daher wurde kein neues Konto erstellt."},
		{emailtemplate.Welcome, "Willkommen!", "Ihr Konto wurde erstellt."},
		{emailtemplate.VerificationCode, "E-Mail-Bestätigung – Code 482915", "Der Code läuft nach 5 Minuten ab."},
		{emailtemplate.NewUserSetup, "Acme Portal – Passwort für Ihr neues Konto festlegen", "Öffnen Sie diesen Link, um Ihr Passwort festzulegen:"},
		{emailtemplate.TestEmail, "Acme Portal – Test-E-Mail", "Dies ist eine Test-E-Mail von Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Ihre E-Mail-Adresse wurde geändert", "Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		{emailtemplate.PasswordChanged, "Ihr Passwort wurde geändert", "Andernfalls verwendet möglicherweise jemand anderes Ihr Konto."},
		{emailtemplate.PasswordChangedByAdministrator, "Ihr Passwort wurde von der Administration geändert", "Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration."},
		{emailtemplate.PasswordReset, "Ihr Passwort wurde zurückgesetzt", "Andernfalls kann möglicherweise jemand anderes Ihre E-Mails lesen und Ihr Konto verwenden."},
		{emailtemplate.OTPEnabled, "Die Zwei-Faktor-Authentifizierung wurde eingerichtet", "Dazu wurde ein neuer Satz Wiederherstellungscodes erstellt"},
		{emailtemplate.OTPDisabled, "Die Zwei-Faktor-Authentifizierung wurde deaktiviert", "richten Sie die Zwei-Faktor-Authentifizierung erneut ein."},
		{emailtemplate.OTPDisabledByAdministrator, "Ihre Zwei-Faktor-Authentifizierung wurde von der Administration deaktiviert", "In Ihren Kontoeinstellungen können Sie eine neue Authenticator-App einrichten."},
		{emailtemplate.RecoveryCodeUsed, "Für die Anmeldung wurde ein Wiederherstellungscode verwendet", "Verbleibende unbenutzte Wiederherstellungscodes: 3."},
		{emailtemplate.RecoveryCodesReplaced, "Ihre Wiederherstellungscodes wurden ersetzt", "Ihre bisherigen Wiederherstellungscodes funktionieren nicht mehr"},
		{emailtemplate.OTPLockout, "Ihre Authenticator-App wurde nach zu vielen falschen Codes gesperrt", "Melden Sie sich mit einem Ihrer Wiederherstellungscodes an"},
		{emailtemplate.AccountDeleted, "Ihr Konto wurde gelöscht", "Andernfalls kannte jemand anderes Ihr Passwort."},
		{emailtemplate.AccountDeletedByAdministrator, "Ihr Konto wurde von der Administration gelöscht", "Die Administration hat Ihr Konto bei"},
	})
}
