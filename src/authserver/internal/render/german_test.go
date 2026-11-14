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

func TestGerman_EveryEmailSubjectAndBodyFollowsTheRecipient(t *testing.T) {
	for _, locale := range []string{"de", "de-DE", "de-AT", "de-CH", "de-LI"} {
		for _, tc := range []struct{ name, subject, body string }{
			{"address_changed", "Ihre E-Mail-Adresse wurde geändert", "Andernfalls kennt möglicherweise jemand Ihr Passwort."},
			{"password_changed", "Ihr Passwort wurde geändert", "Andernfalls verwendet möglicherweise jemand anderes Ihr Konto."},
			{"password_changed_by_administrator", "Ihr Passwort wurde von der Administration geändert", "Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration."},
			{"password_reset", "Ihr Passwort wurde zurückgesetzt", "Andernfalls kann möglicherweise jemand anderes Ihre E-Mails lesen und Ihr Konto verwenden."},
			{"otp_enabled", "Die Zwei-Faktor-Authentifizierung wurde eingerichtet", "Dazu wurde ein neuer Satz Wiederherstellungscodes erstellt"},
			{"otp_disabled", "Die Zwei-Faktor-Authentifizierung wurde deaktiviert", "richten Sie die Zwei-Faktor-Authentifizierung erneut ein."},
			{"otp_disabled_by_administrator", "Ihre Zwei-Faktor-Authentifizierung wurde von der Administration deaktiviert", "In Ihren Kontoeinstellungen können Sie eine neue Authenticator-App einrichten."},
			{"recovery_code_used", "Für die Anmeldung wurde ein Wiederherstellungscode verwendet", "Sie haben noch 3 unbenutzte Wiederherstellungscodes."},
			{"recovery_codes_replaced", "Ihre Wiederherstellungscodes wurden ersetzt", "Ihre bisherigen Wiederherstellungscodes funktionieren nicht mehr"},
			{"otp_lockout", "Ihre Authenticator-App wurde nach zu vielen falschen Codes gesperrt", "Melden Sie sich mit einem Ihrer Wiederherstellungscodes an"},
			{"account_deleted", "Ihr Konto wurde gelöscht", "Andernfalls kannte jemand anderes Ihr Passwort."},
			{"account_deleted_by_administrator", "Ihr Konto wurde von der Administration gelöscht", "Die Administration hat Ihr Konto bei"},
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
					map[string]interface{}{"name": "Alex", "link": "https://example.com/continue", "remaining": 3})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="de">`)
				assert.Contains(t, buf.String(), tc.body)
				assert.NotContains(t, buf.String(), "<no value>")
			})
		}
	}
}

func TestGerman_ExactRegionalEmailOverrideStillWins(t *testing.T) {
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
	templates["emails/email_password_changed.de-CH.html"] = &fstest.MapFile{Data: []byte(`{{define "title"}}Eigene E-Mail{{end}}{{define "head"}}{{end}}{{define "body"}}Ihre eigene Nachricht zur Wiederherstellung{{end}}`)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "de-CH", "en"))
	buf, err := New(templates, web.StaticFS(), nil).RenderTemplateToBuffer(req,
		"layouts/email_layout.html", "emails/email_password_changed.html", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `<html lang="de-CH">`)
	assert.Contains(t, buf.String(), "Ihre eigene Nachricht zur Wiederherstellung")
	assert.NotContains(t, buf.String(), "Andernfalls verwendet möglicherweise jemand anderes Ihr Konto.")
}

// The emails sent from their built-in definitions (#818) follow a recipient reading German, in any
// region, as the template emails do: the subject, the language the email is marked with, and a
// sentence of the body, the activation link's and the verification code's saying how long they last.
func TestGerman_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"de", "de-DE", "de-AT", "de-CH", "de-LI"}, "de", []definedEmail{
		{emailtemplate.ActivationLink, "Aktivieren Sie Ihr Konto", "Der Link läuft nach 5 Minuten ab."},
		{emailtemplate.RegistrationExistingAccount, "Sie haben bereits ein Konto", "Daher wurde kein neues Konto erstellt."},
		{emailtemplate.Welcome, "Willkommen!", "Ihr Konto wurde erstellt."},
		{emailtemplate.VerificationCode, "E-Mail-Bestätigung – Code 482915", "Der Code läuft nach 5 Minuten ab."},
		{emailtemplate.NewUserSetup, "Acme Portal – Passwort für Ihr neues Konto festlegen", "Öffnen Sie diesen Link, um Ihr Passwort festzulegen:"},
		{emailtemplate.TestEmail, "Acme Portal – Test-E-Mail", "Dies ist eine Test-E-Mail von Acme Portal."},
	})
}
