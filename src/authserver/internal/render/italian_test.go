package render

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

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

func TestItalian_EveryEmailSubjectAndBodyFollowsTheRecipient(t *testing.T) {
	for _, locale := range []string{"it", "it-IT", "it-CH", "it-SM", "it-VA"} {
		for _, tc := range []struct{ name, subject, body string }{
			{"address_changed", "Il tuo indirizzo email è stato cambiato", "qualcun altro potrebbe conoscere la tua password."},
			{"password_changed", "La tua password è stata cambiata", "Altrimenti, qualcun altro potrebbe usare il tuo account."},
			{"password_changed_by_administrator", "Un amministratore ha cambiato la tua password", "Se non te lo aspettavi, contatta il tuo amministratore."},
			{"password_reset", "La tua password è stata reimpostata", "Altrimenti, qualcun altro potrebbe leggere la tua email e usare il tuo account."},
			{"otp_enabled", "L'autenticazione a due fattori è stata configurata", "Insieme è stato creato un nuovo set di codici di recupero"},
			{"otp_disabled", "L'autenticazione a due fattori è stata disattivata", "configura di nuovo l'autenticazione a due fattori"},
			{"otp_disabled_by_administrator", "Un amministratore ha disattivato la tua autenticazione a due fattori", "Puoi configurare una nuova app di autenticazione"}, //nolint:misspell // the it catalog's text: "configurare" is Italian, not a misspelling of "configure"
			{"recovery_code_used", "È stato usato un codice di recupero per accedere", "Ti restano 3 codici di recupero inutilizzati."},
			{"recovery_codes_replaced", "I tuoi codici di recupero sono stati sostituiti", "I codici di recupero precedenti non funzionano più"},
			{"otp_lockout", "La tua app di autenticazione è stata bloccata dopo troppi codici errati", "Accedi con uno dei tuoi codici di recupero"},
			{"account_deleted", "Il tuo account è stato eliminato", "Altrimenti, qualcun altro conosceva la tua password."},                                  //nolint:misspell // the it catalog's text: "eliminato" is Italian, not a misspelling of "elimination"
			{"account_deleted_by_administrator", "Un amministratore ha eliminato il tuo account", "Se non te lo aspettavi, contatta il tuo amministratore."}, //nolint:misspell // the it catalog's text: "eliminato" is Italian, not a misspelling of "elimination"
		} {
			t.Run(locale+"/"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
				// A recipient's locale replaces the sender's explicit English preference.
				ctx := i18n.WithLocale(i18n.WithLocale(req.Context(), true, "en"), true, locale, "en")
				req = req.WithContext(ctx)
				assert.Equal(t, tc.subject, i18n.T(ctx, "email."+tc.name+".subject", map[string]any{"code": "123456", "appName": "Test"}))
				buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(req,
					"layouts/email_layout.html", "emails/email_"+tc.name+".html",
					map[string]interface{}{"name": "Andrea", "link": "https://example.com/continue", "remaining": 3})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="it">`)
				assert.Contains(t, buf.String(), tc.body)
				assert.NotContains(t, buf.String(), "<no value>")
			})
		}
	}
}

func TestItalian_ExactRegionalEmailOverrideStillWins(t *testing.T) {
	// A configured template directory replaces the embedded set. Copy that set
	// here, then add the operator's exact regional copy as a real deployment does.
	templates := fstest.MapFS{}
	require.NoError(t, fs.WalkDir(web.TemplateFS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := fs.ReadFile(web.TemplateFS(), path)
		if err == nil {
			templates[path] = &fstest.MapFile{Data: data}
		}
		return err
	}))
	templates["emails/email_password_changed.it-CH.html"] = &fstest.MapFile{Data: []byte(`{{define "title"}}Email personalizzata{{end}}{{define "head"}}{{end}}{{define "body"}}La tua email di recupero{{end}}`)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "it-CH", "en"))
	buf, err := New(templates, web.StaticFS(), nil).RenderTemplateToBuffer(req,
		"layouts/email_layout.html", "emails/email_password_changed.html", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `<html lang="it-CH">`)
	assert.Contains(t, buf.String(), "La tua email di recupero")
	assert.NotContains(t, buf.String(), "Altrimenti, qualcun altro potrebbe usare il tuo account.")
}

// The emails sent from their built-in definitions (#818) follow a recipient reading Italian, in any
// region, as the template emails do: the subject, the language the email is marked with, and a
// sentence of the body, the activation link's and the verification code's saying how long they last.
func TestItalian_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"it", "it-IT", "it-CH", "it-SM", "it-VA"}, "it", []definedEmail{
		{emailtemplate.ActivationLink, "Attiva il tuo account", "Il link scade tra 5 minuti."},
		{emailtemplate.RegistrationExistingAccount, "Hai già un account", "non ne è stato creato uno nuovo."},
		{emailtemplate.Welcome, "Benvenuto!", "Il tuo account è stato creato."},
		{emailtemplate.VerificationCode, "Verifica email - codice 482915", "Il codice scade tra 5 minuti."},
		{emailtemplate.NewUserSetup, "Acme Portal - crea una password per il tuo nuovo account", "Per creare la tua password, apri questo link:"},
		{emailtemplate.TestEmail, "Acme Portal - email di prova", "Questa è un’email di prova inviata da Acme Portal."},
	})
}
