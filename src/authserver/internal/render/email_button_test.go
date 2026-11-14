package render

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// The four emails whose point is one action draw it as a button in the brand's color, labelled in
// the email's language, above the URL, which stays visible as the copy-and-paste fallback the body
// describes; the verification code is set apart, larger and in a monospace face (#817 decision 3).

// buttonLink is the action link the email tests render each email with.
const buttonLink = "https://auth.example.com/an-action?code=abc"

// emailButtonLabels are the four buttons' labels in each built-in language.
var emailButtonLabels = map[string]map[string]string{
	"password_reset_link": {
		"en": "Reset password", "de": "Passwort zurücksetzen", "es": "Restablecer contraseña",
		"fr": "Réinitialiser le mot de passe", "it": "Reimposta la password", "pt-BR": "Redefinir senha",
	},
	"activation_link": {
		"en": "Activate account", "de": "Konto aktivieren", "es": "Activar cuenta",
		"fr": "Activer le compte", "it": "Attiva l'account", "pt-BR": "Ativar conta",
	},
	"new_user_setup": {
		"en": "Create password", "de": "Passwort festlegen", "es": "Crear contraseña",
		"fr": "Créer le mot de passe", "it": "Crea la password", "pt-BR": "Criar senha",
	},
	"welcome": {
		"en": "Sign in", "de": "Anmelden", "es": "Iniciar sesión",
		"fr": "Se connecter", "it": "Accedi", "pt-BR": "Entrar",
	},
}

var emailLanguages = []string{"en", "de", "es", "fr", "it", "pt-BR"}

// drawnButton is what an email draws of its button: the cell that paints it and the link in it.
type drawnButton struct {
	href, label            string
	cellColor, cellBgcolor string
	cellRadius             string
	linkBackground, color  string
	linkRadius             string
}

// drawnAction is what an email draws of its action: its buttons, and the links of its body that are
// not a button, in the order they are drawn, with whether each comes after the first button.
type drawnAction struct {
	buttons     []drawnButton
	links       []string
	linkColors  []string
	afterButton []bool
}

// readEmailAction reads an email's action. A button is a link in a table of the body, the cell
// around it painted in the button's color, as an email client draws a button that ignores padding
// on a link; every other link of the body is a link.
func readEmailAction(t *testing.T, html string) drawnAction {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	var drawn drawnAction
	seenButton := false
	doc.Find("main a").Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		if isEmailButton(link) {
			cell := link.Closest("td")
			bgcolor, _ := cell.Attr("bgcolor")
			drawn.buttons = append(drawn.buttons, drawnButton{
				href: href, label: strings.TrimSpace(link.Text()),
				cellColor: styleOf(cell)["background-color"], cellBgcolor: bgcolor, cellRadius: styleOf(cell)["border-radius"],
				linkBackground: styleOf(link)["background-color"], color: styleOf(link)["color"], linkRadius: styleOf(link)["border-radius"],
			})
			seenButton = true
			return
		}
		drawn.links = append(drawn.links, href)
		drawn.linkColors = append(drawn.linkColors, styleOf(link)["color"])
		drawn.afterButton = append(drawn.afterButton, seenButton)
	})
	return drawn
}

// isEmailButton answers whether link is a button: a link in a table of an email's body.
func isEmailButton(link *goquery.Selection) bool {
	return link.ParentsUntil("main").Filter("table").Length() > 0
}

// renderBodyIn renders the email body base, written in lang, for brand, through a renderer whose base
// URL is emailBaseURL.
func renderBodyIn(t *testing.T, base, lang string, brand *record.Brand) string {
	t.Helper()
	ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
	ctx = i18n.WithLocale(ctx, true, lang, "en")
	req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	brands := &defaultBrandStub{brand: brand, assets: kitAssets}
	buf, err := New(web.TemplateFS(), web.StaticFS(), brands).WithBaseURL(emailBaseURL).RenderTemplateToBuffer(req,
		"/layouts/email_layout.html", "/emails/"+base+".html", map[string]interface{}{
			"name": "Ana", "link": buttonLink, "remaining": 3,
		})
	require.NoError(t, err)
	return buf.String()
}

// renderActionEmail renders the action email name in lang for brand: from its built-in definition
// when it has one (#818), else from its template file email_<name>.html.
func renderActionEmail(t *testing.T, name, lang string, brand *record.Brand) string {
	t.Helper()
	for _, email := range emailtemplate.BuiltIns() {
		if email.ID == name {
			return renderDefinition(t, email, lang, brand).HTML
		}
	}
	return renderBodyIn(t, "email_"+name, lang, brand)
}

// Each of the four action emails, in each built-in language, draws one button labelled in that
// language, linking the action, in the brand's color with its text in the color drawn on it, and
// then the URL itself, as a link in the brand's link color.
func TestRender_AnActionEmailDrawsAButtonAboveItsURL(t *testing.T) {
	for email, labels := range emailButtonLabels {
		for _, lang := range emailLanguages {
			t.Run(email+"/"+lang, func(t *testing.T) {
				html := renderActionEmail(t, email, lang, themedBrand(record.BrandAppearanceLight, "plum"))

				drawn := readEmailAction(t, html)

				require.Len(t, drawn.buttons, 1, "the email draws one button")
				button := drawn.buttons[0]
				assert.Equal(t, buttonLink, button.href)
				assert.Equal(t, labels[lang], button.label)
				assert.Equal(t, "#7a3aa8", button.cellColor, "the button is in the brand's color")
				assert.Equal(t, "#7a3aa8", button.cellBgcolor, "and says so to a client that drops a style")
				assert.Equal(t, "#7a3aa8", button.linkBackground)
				assert.Equal(t, "#ffffff", button.color, "its label is in the color drawn on the brand's")

				assert.Equal(t, []string{buttonLink}, drawn.links, "the URL stays, as a link")
				assert.Equal(t, []bool{true}, drawn.afterButton, "under the button")
				assert.Equal(t, []string{"#7a3aa8"}, drawn.linkColors)
				assert.Contains(t, html, ">"+buttonLink+"</a>", "the URL is written out, to copy and paste")
			})
		}
	}
}

// A dark brand's button is in its dark palette's brand color, with the color drawn on that.
func TestRender_ADarkBrandsButtonIsInItsDarkPalette(t *testing.T) {
	drawn := readEmailAction(t, renderActionEmail(t, "password_reset_link", "en", themedBrand(record.BrandAppearanceDark, "plum")))

	require.Len(t, drawn.buttons, 1)
	assert.Equal(t, "#cda4f0", drawn.buttons[0].cellColor)
	assert.Equal(t, "#cda4f0", drawn.buttons[0].linkBackground)
	assert.Equal(t, "#2a0f40", drawn.buttons[0].color)
}

// The button takes the brand's corner shape as a page's button does: rounded to 8px, square, or
// fully rounded for pill corners.
func TestRender_AnEmailsButtonTakesItsBrandsCorners(t *testing.T) {
	for _, tc := range []struct {
		corners record.BrandCorners
		want    string
	}{
		{record.BrandCornersRounded, "8px"},
		{record.BrandCornersSquare, "0"},
		{record.BrandCornersPill, "9999px"},
	} {
		t.Run(string(tc.corners), func(t *testing.T) {
			brand := themedBrand(record.BrandAppearanceLight, "plum")
			brand.Corners = tc.corners

			drawn := readEmailAction(t, renderActionEmail(t, "activation_link", "en", brand))

			require.Len(t, drawn.buttons, 1)
			assert.Equal(t, tc.want, drawn.buttons[0].cellRadius)
			assert.Equal(t, tc.want, drawn.buttons[0].linkRadius)
		})
	}
}

// Every other email draws no button: its links, the verification email's and the "this address
// already has an account" notice's among them, are links in the brand's link color.
func TestRender_OnlyTheFourActionEmailsDrawAButton(t *testing.T) {
	assertNoButton := func(t *testing.T, html string) {
		t.Helper()
		drawn := readEmailAction(t, html)
		assert.Empty(t, drawn.buttons)
		for _, color := range drawn.linkColors {
			assert.Equal(t, "#7a3aa8", color)
		}
	}

	bodies, err := fs.Glob(web.TemplateFS(), "emails/*.html")
	require.NoError(t, err)
	for _, body := range bodies {
		name := strings.TrimSuffix(path.Base(body), ".html")
		base, lang, _ := strings.Cut(name, ".")
		if lang == "" {
			lang = "en"
		}
		t.Run(name, func(t *testing.T) {
			assertNoButton(t, renderBodyIn(t, base, lang, themedBrand(record.BrandAppearanceLight, "plum")))
		})
	}

	actions := 0
	for _, email := range emailtemplate.BuiltIns() {
		if _, action := emailButtonLabels[email.ID]; action {
			assert.True(t, email.HasButton(), "%s offers the button", email.ID)
			actions++
			continue
		}
		assert.False(t, email.HasButton(), "%s offers no button", email.ID)
		for _, lang := range emailLanguages {
			t.Run(email.ID+"/"+lang, func(t *testing.T) {
				assertNoButton(t, renderDefinition(t, email, lang, themedBrand(record.BrandAppearanceLight, "plum")).HTML)
			})
		}
	}
	assert.Equal(t, len(emailButtonLabels), actions, "the four action emails are sent from their definitions")
}

// drawnCode is the element that holds the verification code alone, and its style.
type drawnCode struct {
	count int
	style map[string]string
}

// readEmailCode finds the elements of the body whose whole text is code.
func readEmailCode(t *testing.T, html, code string) drawnCode {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	var drawn drawnCode
	doc.Find("main *").Each(func(_ int, element *goquery.Selection) {
		if strings.TrimSpace(element.Text()) == code && element.Children().Length() == 0 {
			drawn.count++
			drawn.style = styleOf(element)
		}
	})
	return drawn
}

// The verification code, in every language, is set apart in a box of its own, in the brand's
// subtle color within the line's border, larger than the body's 16px text, and in a monospace face,
// main.css's --font-mono written unquoted.
func TestRender_TheVerificationCodeIsSetApartLargerAndInAMonospaceFace(t *testing.T) {
	const monoFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace"
	for _, tc := range []struct {
		appearance        record.BrandAppearance
		subtle, line, ink string
	}{
		{record.BrandAppearanceLight, "#f0ecf2", "#ddd7e1", "#201a26"},
		{record.BrandAppearanceDark, "#231e29", "#352e3d", "#e9e5ec"},
	} {
		for _, lang := range emailLanguages {
			t.Run(string(tc.appearance)+"/"+lang, func(t *testing.T) {
				html := renderDefinition(t, emailtemplate.VerificationCode, lang, themedBrand(tc.appearance, "plum")).HTML

				code := readEmailCode(t, html, "482915")

				require.Equal(t, 1, code.count, "the code is an element of its own")
				assert.Equal(t, monoFamily, code.style["font-family"])
				assert.Equal(t, "28px", code.style["font-size"])
				assert.Equal(t, tc.subtle, code.style["background-color"])
				assert.Equal(t, "1px solid "+tc.line, code.style["border"])
				assert.Equal(t, tc.ink, code.style["color"])
				assert.Equal(t, "center", code.style["text-align"])
			})
		}
	}
}
