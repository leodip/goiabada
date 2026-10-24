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
			buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(req,
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

func TestFrench_AllSevenEmailSubjectsAndBodiesFollowTheRecipient(t *testing.T) {
	for _, locale := range []string{"fr", "fr-FR", "fr-CA", "fr-BE", "fr-CH"} {
		for _, tc := range []struct{ name, subject, body string }{
			{"forgot_password", "Réinitialisation du mot de passe", "Pour réinitialiser votre mot de passe"},
			{"register_activate", "Activez votre compte", "Le lien expire dans 5 minutes."},
			{"register_existing_account", "Vous avez déjà un compte", "Aucun nouveau compte n’a donc été créé."},
			{"register_confirmation", "Bienvenue\u00a0!", "Votre compte a été créé."},
			{"verification", "Vérification de l’adresse e-mail - code 123456", "Voici votre code de vérification"},
			{"newuser_set_password", "Test - créez un mot de passe pour votre nouveau compte", "Le lien est valable 24 heures."},
			{"address_changed", "Votre adresse e-mail a été modifiée", "une autre personne connaît peut-être votre mot de passe."},
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
					map[string]interface{}{"name": "Camille", "link": "https://example.com/continue", "verificationCode": "123456"})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="fr">`)
				assert.Contains(t, buf.String(), tc.body)
				assert.NotContains(t, buf.String(), "<no value>")
				if tc.name == "verification" {
					assert.Contains(t, buf.String(), "123456")
				}
			})
		}
	}
}

func TestFrench_ExactRegionalEmailOverrideStillWins(t *testing.T) {
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
	templates["emails/email_forgot_password.fr-CA.html"] = &fstest.MapFile{Data: []byte(`{{define "title"}}Courriel personnalisé{{end}}{{define "head"}}{{end}}{{define "body"}}Votre courriel de récupération{{end}}`)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "fr-CA", "en"))
	buf, err := New(templates, web.StaticFS()).RenderTemplateToBuffer(req,
		"layouts/email_layout.html", "emails/email_forgot_password.html", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `<html lang="fr-CA">`)
	assert.Contains(t, buf.String(), "Votre courriel de récupération")
	assert.NotContains(t, buf.String(), "Pour réinitialiser votre mot de passe")
}
