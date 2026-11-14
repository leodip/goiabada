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

func TestFrench_SignInPageUsesQueryOrCanadianHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=fr", "en"},
		{"/auth/pwd", "fr-CA"},
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
			assert.Contains(t, buf.String(), `<html lang="fr"`)
			assert.Contains(t, buf.String(), `>Connexion</h1>`)
			assert.Contains(t, buf.String(), `>Se connecter</button>`)
			assert.Contains(t, buf.String(), "Échec de l’authentification.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading French, in any
// region: the subject, the language the email is marked with, and a sentence of the body, the
// activation link's and the verification code's saying how long they last, and the recovery code
// notice's giving the codes left.
func TestFrench_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"fr", "fr-FR", "fr-CA", "fr-BE", "fr-CH"}, "fr", []definedEmail{
		{emailtemplate.ActivationLink, "Activez votre compte", "Le lien expire dans 5 minutes."},
		{emailtemplate.RegistrationExistingAccount, "Vous avez déjà un compte", "Aucun nouveau compte n’a donc été créé."},
		{emailtemplate.Welcome, "Bienvenue\u00a0!", "Votre compte a été créé."},
		{emailtemplate.VerificationCode, "Vérification de l’adresse e-mail - code 482915", "Le code expire dans 5 minutes."},
		{emailtemplate.NewUserSetup, "Acme Portal - créez un mot de passe pour votre nouveau compte", "Pour créer votre mot de passe"},
		{emailtemplate.TestEmail, "Acme Portal - e-mail de test", "Ceci est un e-mail de test envoyé par Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Votre adresse e-mail a été modifiée", "une autre personne connaît peut-être votre mot de passe."},
		{emailtemplate.PasswordChanged, "Votre mot de passe a été modifié", "Sinon, une autre personne utilise peut-être votre compte."},
		{emailtemplate.PasswordChangedByAdministrator, "Un administrateur a modifié votre mot de passe", "Si vous ne vous y attendiez pas, contactez votre administrateur."},
		{emailtemplate.PasswordReset, "Votre mot de passe a été réinitialisé", "Sinon, une autre personne lit peut-être vos e-mails et utilise votre compte."},
		{emailtemplate.OTPEnabled, "L’authentification à deux facteurs a été configurée", "Un nouveau jeu de codes de récupération a été créé avec elle."},
		{emailtemplate.OTPDisabled, "L’authentification à deux facteurs a été désactivée", "configurez à nouveau l’authentification à deux facteurs"},
		{emailtemplate.OTPDisabledByAdministrator, "Un administrateur a désactivé votre authentification à deux facteurs", "Vous pouvez configurer une nouvelle application d’authentification"},
		{emailtemplate.RecoveryCodeUsed, "Un code de récupération a été utilisé pour vous connecter", "Codes de récupération inutilisés restants : 3."},
		{emailtemplate.RecoveryCodesReplaced, "Vos codes de récupération ont été remplacés", "Vos anciens codes de récupération ne fonctionnent plus"},
		{emailtemplate.OTPLockout, "Votre application d’authentification a été bloquée après trop de codes erronés", "Connectez-vous avec l’un de vos codes de récupération"},
		{emailtemplate.AccountDeleted, "Votre compte a été supprimé", "Sinon, une autre personne connaissait votre mot de passe."},
		{emailtemplate.AccountDeletedByAdministrator, "Un administrateur a supprimé votre compte", "Si vous ne vous y attendiez pas, contactez votre administrateur."},
	})
}
