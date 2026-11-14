package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// An email sent from its built-in definition (#818) is drawn in the email layout, in the brand of
// the page it was sent from, in the built-in language that matches the recipient's, with its
// subject as its title.

// definitionValues are the values the tests send an email with.
var definitionValues = emailtemplate.Values{
	Name: "Ana", Link: buttonLink, Code: "482915", Expiry: 5 * time.Minute,
}

// renderDefinition renders email for a recipient reading locale, in brand, through a renderer whose
// base URL is emailBaseURL.
func renderDefinition(t *testing.T, email *emailtemplate.Email, locale string, brand *record.Brand) emailtemplate.Message {
	t.Helper()
	ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
	ctx = i18n.WithLocale(ctx, true, locale, "en")
	req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	var brands PageBrandReader
	if brand != nil {
		brands = &defaultBrandStub{brand: brand, assets: kitAssets}
	}
	message, err := New(web.TemplateFS(), web.StaticFS(), brands).WithBaseURL(emailBaseURL).RenderEmail(req, email, definitionValues)
	require.NoError(t, err)
	return message
}

// The password reset link for a recipient reading each language, a regional variant reading its
// language's text and a language with none reading English: the subject, the title, which is the
// subject, the language the email is marked with, and its first sentence.
func TestRenderEmail_ThePasswordResetLinkFollowsTheRecipient(t *testing.T) {
	for _, tc := range []struct {
		locale, lang, subject, sentence string
	}{
		{"en", "en", "Password reset", "You can reset your password by clicking the link below:"},
		{"en-GB", "en", "Password reset", "You can reset your password by clicking the link below:"},
		{"de-AT", "de", "Passwort zurücksetzen", "Öffnen Sie diesen Link, um Ihr Passwort zurückzusetzen:"},
		{"es-MX", "es", "Restablecimiento de contraseña", "Para restablecer tu contraseña, abre este enlace:"},
		{"fr-CA", "fr", "Réinitialisation du mot de passe", "Pour réinitialiser votre mot de passe"},
		{"it-CH", "it", "Reimpostazione della password", "Per reimpostare la password, apri questo link:"},
		{"pt", "pt-BR", "Redefinição de senha", "Você pode redefinir sua senha clicando no link abaixo:"},
		{"nl", "en", "Password reset", "You can reset your password by clicking the link below:"},
		{"sv-SE", "en", "Password reset", "You can reset your password by clicking the link below:"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			message := renderDefinition(t, emailtemplate.PasswordResetLink, tc.locale, nil)

			assert.Equal(t, tc.subject, message.Subject)
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
			require.NoError(t, err)
			assert.Equal(t, tc.subject, doc.Find("title").Text(), "the title is the subject")
			lang, _ := doc.Find("html").Attr("lang")
			assert.Equal(t, tc.lang, lang)
			assert.Contains(t, doc.Find("main").Text(), tc.sentence)
			assert.Contains(t, message.HTML, "Acme Portal</p>", "signed with the app name")
			assert.NotContains(t, message.HTML, "{{")
		})
	}
}

// The values reach the body as the recipient reads them: the name, the link drawn as a link to
// itself in the brand's color, and the expiry in the email's language.
func TestRenderEmail_DrawsItsValuesInTheBrand(t *testing.T) {
	message := renderDefinition(t, emailtemplate.PasswordResetLink, "de", themedBrand(record.BrandAppearanceLight, "plum"))

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	main := doc.Find("main")
	assert.Contains(t, main.Text(), "Guten Tag Ana,")
	assert.Contains(t, main.Text(), "Der Link läuft nach 5 Minuten ab.")
	drawn := readEmailAction(t, message.HTML)
	require.Len(t, drawn.buttons, 1)
	assert.Equal(t, "Passwort zurücksetzen", drawn.buttons[0].label)
	assert.Equal(t, []string{buttonLink}, drawn.links)
	assert.Equal(t, []string{"#7a3aa8"}, drawn.linkColors)
}

// A render without the settings is refused, as a page's is.
func TestRenderEmail_RefusesARequestWithoutSettings(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	_, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderEmail(req, emailtemplate.PasswordResetLink, definitionValues)
	require.ErrorIs(t, err, reqctx.ErrNoSettings)
}
