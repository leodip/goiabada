package render

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

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
			buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(req,
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

func TestGerman_AllSevenEmailSubjectsAndBodiesFollowTheRecipient(t *testing.T) {
	for _, locale := range []string{"de", "de-DE", "de-AT", "de-CH", "de-LI"} {
		for _, tc := range []struct{ name, subject, body string }{
			{"forgot_password", "Passwort zurücksetzen", "um Ihr Passwort zurückzusetzen"},
			{"register_activate", "Aktivieren Sie Ihr Konto", "Der Link läuft nach 5 Minuten ab."},
			{"register_existing_account", "Sie haben bereits ein Konto", "Daher wurde kein neues Konto erstellt."},
			{"register_confirmation", "Willkommen!", "Ihr Konto wurde erstellt."},
			{"verification", "E-Mail-Bestätigung – Code 123456", "Mit diesem Code können Sie Ihre E-Mail-Adresse bestätigen"},
			{"newuser_set_password", "Test – Passwort für Ihr neues Konto festlegen", "Der Link ist 24 Stunden gültig."},
			{"address_changed", "Ihre E-Mail-Adresse wurde geändert", "Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		} {
			t.Run(locale+"/"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
				// A recipient's locale replaces the sender's explicit English preference.
				ctx := i18n.WithLocale(i18n.WithLocale(req.Context(), true, "en"), true, locale, "en")
				req = req.WithContext(ctx)
				assert.Equal(t, tc.subject, i18n.T(ctx, "email."+tc.name+".subject", map[string]any{"code": "123456", "appName": "Test"}))
				buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(req,
					"layouts/email_layout.html", "emails/email_"+tc.name+".html",
					map[string]interface{}{"name": "Alex", "link": "https://example.com/continue", "verificationCode": "123456"})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="de">`)
				assert.Contains(t, buf.String(), tc.body)
				assert.NotContains(t, buf.String(), "<no value>")
				if tc.name == "verification" {
					assert.Contains(t, buf.String(), "123456")
				}
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
	templates["emails/email_forgot_password.de-CH.html"] = &fstest.MapFile{Data: []byte(`{{define "title"}}Eigene E-Mail{{end}}{{define "head"}}{{end}}{{define "body"}}Ihre eigene Nachricht zur Wiederherstellung{{end}}`)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "de-CH", "en"))
	buf, err := New(templates, web.StaticFS()).RenderTemplateToBuffer(req,
		"layouts/email_layout.html", "emails/email_forgot_password.html", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `<html lang="de-CH">`)
	assert.Contains(t, buf.String(), "Ihre eigene Nachricht zur Wiederherstellung")
	assert.NotContains(t, buf.String(), "um Ihr Passwort zurückzusetzen")
}
