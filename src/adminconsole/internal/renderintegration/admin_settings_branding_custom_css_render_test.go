package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The brand editor's Custom CSS field (#816), drawn through the real renderer: the last section of the
// form, a textarea holding the CSS exactly as stored, labelled by its heading and described by what it
// reaches and by the sentence saying the preview does not draw it (decision 8); a refusal marked at
// it, described by the notice and focused.

// renderCustomCSSForm draws a stored brand's form holding css, in locale, refused at errorField when
// it names one, and answers the form.
func renderCustomCSSForm(t *testing.T, locale, css, errorField string) string {
	t.Helper()
	bind := map[string]interface{}{
		"isNew":       false,
		"storedBrand": api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "auto", Theme: "plum"},
		"brand": adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "auto", Theme: "plum",
			Corners: "rounded", Font: "system-ui", BackgroundFit: "cover", CustomCss: css},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
		"footerLanguages": renderFooterLanguages,
	}
	if errorField != "" {
		bind["error"] = "Line 2 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."
		bind["errorField"] = errorField
	}
	out := renderMenuPageIn(t, "/admin_settings_branding_brand.html", bind, locale, true)
	editorStart := strings.Index(out, `<div class="brand-editor"`)
	require.GreaterOrEqual(t, editorStart, 0)
	form := out[editorStart:]
	formEnd := strings.Index(form, "</form>")
	require.Positive(t, formEnd)
	return form[:formEnd]
}

// customCSSTextarea is the whole <textarea id="customCss">, from its start tag to its end tag.
func customCSSTextarea(t *testing.T, form string) string {
	t.Helper()
	textarea := regexp.MustCompile(`(?s)<textarea [^>]*id="customCss"[^>]*>.*?</textarea>`).FindString(form)
	require.NotEmpty(t, textarea, "no custom CSS field")
	return textarea
}

// The field follows the support contact, last before Cancel and Save. It holds the CSS as stored,
// escaped, after the line break a browser drops after <textarea>, so CSS starting with a blank line
// keeps it. Its heading is its label; its hint says where the CSS reaches and what it cannot hold,
// and the sentence after it that the preview does not show it, and how to try it.
func TestRender_AdminSettingsBrandingFormDrawsTheCustomCSSField(t *testing.T) {
	const css = "\n/* <b> & \"quotes\" </style> */\nbody[data-page=\"sign-in\"] > .auth-card {\n  border: 2px solid var(--color-brand);\n}\n"
	form := renderCustomCSSForm(t, "en", css, "")

	assert.Equal(t, `<textarea class="control control-mono" id="customCss" name="customCss" rows="12" spellcheck="false" autocomplete="off" aria-describedby="customCssHint customCssPreviewNote">`+
		"\n\n/* &lt;b&gt; &amp; &#34;quotes&#34; &lt;/style&gt; */\nbody[data-page=&#34;sign-in&#34;] &gt; .auth-card {\n  border: 2px solid var(--color-brand);\n}\n</textarea>",
		customCSSTextarea(t, form))

	assert.Contains(t, form, `<h2 class="panel-title"><label for="customCss">Custom CSS</label></h2>`)
	assert.Contains(t, form, `<p class="field-hint" id="customCssHint">Added after this brand&#39;s own styles on the auth server&#39;s pages and on the admin console&#39;s Account pages, never on its admin pages. Up to 64 KB, with no @import and no URL but a data: image.</p>`)
	assert.Contains(t, form, `<p class="field-hint" id="customCssPreviewNote">The preview doesn&#39;t show custom CSS. To try it, give this brand to a test client and sign in to that client. If a page becomes unusable, add goiabada_safe_mode=true to the authorization request, or to an admin console address, to draw the pages without it.</p>`)

	support := strings.Index(form, `id="supportPhone"`)
	field := strings.Index(form, `id="customCss"`)
	footer := strings.Index(form, `<div class="panel-footer">`)
	require.Positive(t, support)
	assert.Greater(t, field, support, "after the support contact")
	assert.Greater(t, footer, field, "before Cancel and Save")
	assert.NotContains(t, form, `aria-invalid="true"`)
	assert.NotContains(t, form, "autofocus", "a stored brand's form takes no focus")
}

// A brand with no CSS draws the field empty.
func TestRender_AdminSettingsBrandingFormDrawsAnEmptyCustomCSSField(t *testing.T) {
	assert.True(t, strings.HasSuffix(customCSSTextarea(t, renderCustomCSSForm(t, "en", "", "")), `aria-describedby="customCssHint customCssPreviewNote">`+"\n</textarea>"))
}

// A refusal of the CSS is marked at the field, which the notice naming the line describes first, and
// which takes the focus; nothing else is marked.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedCustomCSS(t *testing.T) {
	form := renderCustomCSSForm(t, "en", ".a {}\n@import \"x.css\";\n", "customCss")

	assert.True(t, strings.HasPrefix(customCSSTextarea(t, form),
		`<textarea class="control control-mono" id="customCss" name="customCss" rows="12" spellcheck="false" autocomplete="off" aria-describedby="brand-error customCssHint customCssPreviewNote" aria-invalid="true" autofocus>`+"\n.a {}\n@import &#34;x.css&#34;;\n</textarea>"))
	assert.Equal(t, 1, strings.Count(form, `aria-invalid="true"`))
	assert.Equal(t, 1, strings.Count(form, "autofocus"))

	// A refusal about another field leaves the CSS field as without one.
	other := renderCustomCSSForm(t, "en", ".a {}\n", "supportPhone")
	assert.Contains(t, customCSSTextarea(t, other), `aria-describedby="customCssHint customCssPreviewNote">`)
	assert.NotContains(t, customCSSTextarea(t, other), "aria-invalid")
}

// The field's heading, hint and sentence are in each built-in language.
func TestRender_AdminSettingsBrandingFormDrawsTheCustomCSSFieldInEachLanguage(t *testing.T) {
	english := renderCustomCSSForm(t, "en", "", "")
	for _, locale := range []string{"pt-BR", "es", "fr", "it", "de"} {
		t.Run(locale, func(t *testing.T) {
			form := renderCustomCSSForm(t, locale, "", "")
			for _, id := range []string{"customCssHint", "customCssPreviewNote"} {
				drawn := regexp.MustCompile(`<p class="field-hint" id="` + id + `">[^<]+</p>`).FindString(form)
				require.NotEmpty(t, drawn, id)
				assert.NotContains(t, english, drawn, "%s is translated", id)
			}
			assert.Contains(t, form, "goiabada_safe_mode=true", "the parameter is named as it is typed")
		})
	}
}
