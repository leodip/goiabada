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

// The brand editor's Footer links and Support contact sections (#814 decision 11), drawn through the
// real renderer in pt-BR: after the kit, three rows of a label and a URL, each with its six language
// labels in a closed disclosure the browser provides, and the contact's three fields; every input
// labelled and none autofilled; a refusal marked at the exact input its error_field points at, a
// disclosure drawn open around a refused language label.

var renderFooterLanguages = []adminsettingshandlers.FooterLanguage{
	{Tag: "en", Name: "English"}, {Tag: "de", Name: "German"}, {Tag: "es", Name: "Spanish"},
	{Tag: "fr", Name: "French"}, {Tag: "it", Name: "Italian"}, {Tag: "pt-BR", Name: "Portuguese (Brazil)"},
}

// renderFooterForm draws a stored brand's form holding two links and the whole contact, refused at
// errorField when it names one, and answers the form.
func renderFooterForm(t *testing.T, errorField string) string {
	t.Helper()
	bind := map[string]interface{}{
		"isNew":       false,
		"storedBrand": api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "auto", Theme: "plum"},
		"brand": adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "auto", Theme: "plum",
			Corners: "rounded", Font: "system-ui", BackgroundFit: "cover",
			FooterLinks: [3]adminsettingshandlers.BrandFooterLinkRow{
				{Label: "Privacy <b>", Url: "https://autumn.example/privacy?a=1&b=2", Labels: map[string]string{"de": "Datenschutz", "pt-BR": "Privacidade"}},
				{Label: "Status", Url: "https://status.autumn.example"},
			},
			SupportEmail: "help@autumn.example", SupportUrl: "https://help.autumn.example", SupportPhone: "+15550100199"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
		"footerLanguages": renderFooterLanguages,
	}
	if errorField != "" {
		bind["error"] = "Não."
		bind["errorField"] = errorField
	}
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", bind)
	editorStart := strings.Index(out, `<div class="brand-editor"`)
	require.GreaterOrEqual(t, editorStart, 0)
	form := out[editorStart:]
	formEnd := strings.Index(form, "</form>")
	require.Positive(t, formEnd)
	return form[:formEnd]
}

// inputTag is the whole <input> whose id is named.
func inputTag(t *testing.T, form, id string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input [^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(form)
	require.NotEmpty(t, tag, "no input %s", id)
	return tag
}

// footerRow is the fieldset of the row of the index named, from its start to its end.
func footerRow(t *testing.T, form string, index int) string {
	t.Helper()
	start := strings.Index(form, `<fieldset class="footer-link" id="footerLinks-`+string(rune('0'+index))+`">`)
	require.GreaterOrEqual(t, start, 0, "no row %d", index)
	end := strings.Index(form[start:], "</details>")
	require.Positive(t, end)
	return form[start : start+end]
}

func TestRender_AdminSettingsBrandingFormDrawsTheFooterSectionsAfterTheKit(t *testing.T) {
	form := renderFooterForm(t, "")

	// The two sections follow the kit, the background and its fit last among it, each a section of the
	// panel under its own title.
	fit := strings.Index(form, `id="backgroundFit-tile"`)
	links := strings.Index(form, `<h2 class="panel-title" id="footerLinksTitle">Links do rodapé</h2>`)
	contact := strings.Index(form, `<h2 class="panel-title" id="supportContactTitle">Contato de suporte</h2>`)
	require.Positive(t, fit)
	require.Greater(t, links, fit, "the footer links follow the kit")
	require.Greater(t, contact, links, "the contact follows the links")
	assert.Contains(t, form, `<p class="field-hint mt-1" id="footerLinksHint">Até três links, exibidos nesta ordem no rodapé de cada página nesta marca. Cada um precisa de um rótulo e de um endereço https:. Uma linha deixada vazia não é um link.</p>`)

	// Three rows, each a group named by its number, holding the stored link or nothing; every value is
	// text.
	for i, legend := range []string{"Link 1", "Link 2", "Link 3"} {
		row := footerRow(t, form, i)
		assert.Contains(t, row, `<legend class="field-label mb-2">`+legend+`</legend>`)
	}
	assert.Equal(t, 3, strings.Count(form, `<fieldset class="footer-link"`))
	assert.Equal(t, `<input class="control" id="footerLinks-0-label" type="text" name="footerLinks-0-label" value="Privacy &lt;b&gt;" autocomplete="off">`,
		inputTag(t, form, "footerLinks-0-label"))
	assert.Equal(t, `<input class="control" id="footerLinks-0-url" type="url" name="footerLinks-0-url" value="https://autumn.example/privacy?a=1&amp;b=2" autocomplete="off">`,
		inputTag(t, form, "footerLinks-0-url"))
	assert.Contains(t, form, `<label class="field-label" for="footerLinks-0-label">Rótulo</label>`)
	assert.Contains(t, form, `<label class="field-label" for="footerLinks-0-url">URL</label>`)
	assert.Contains(t, inputTag(t, form, "footerLinks-1-url"), `value="https://status.autumn.example"`)
	assert.Contains(t, inputTag(t, form, "footerLinks-2-label"), `value=""`)
	assert.Contains(t, inputTag(t, form, "footerLinks-2-url"), `value=""`)

	// Each row's six language labels are in a closed disclosure under it, each labelled with its
	// language, written in it, and holding the stored label or nothing.
	row := footerRow(t, form, 0)
	assert.Contains(t, row, `<details class="disclosure">`)
	assert.Contains(t, row, `<summary>Rótulo em cada idioma</summary>`)
	assert.Contains(t, row, `<p class="field-hint" id="footerLinks-0-labelsHint">Um idioma deixado em branco mostra o rótulo acima.</p>`)
	for _, language := range renderFooterLanguages {
		id := "footerLinks-0-labels-" + language.Tag
		tag := inputTag(t, row, id)
		assert.Contains(t, tag, `name="`+id+`"`)
		assert.Contains(t, tag, ` lang="`+language.Tag+`"`)
		assert.Contains(t, tag, ` autocomplete="off"`)
		assert.Contains(t, tag, ` aria-describedby="footerLinks-0-labelsHint"`)
		assert.Regexp(t, `<label class="field-label" for="`+regexp.QuoteMeta(id)+`">[^<]+</label>`, row)
	}
	assert.Contains(t, row, `<label class="field-label" for="footerLinks-0-labels-de">Deutsch (German)</label>`)
	assert.Contains(t, inputTag(t, row, "footerLinks-0-labels-de"), `value="Datenschutz"`)
	assert.Contains(t, inputTag(t, row, "footerLinks-0-labels-pt-BR"), `value="Privacidade"`)
	assert.Contains(t, inputTag(t, row, "footerLinks-0-labels-fr"), `value=""`)
	assert.Equal(t, 3, strings.Count(form, `<details class="disclosure">`), "every disclosure closed")
	assert.NotContains(t, form, "<details class=\"disclosure\" open>")

	// The contact's three fields, each labelled, of its kind, and not autofilled, since the values are
	// not the administrator's own.
	assert.Equal(t, `<input class="control" id="supportEmail" type="email" name="supportEmail" value="help@autumn.example" autocomplete="off">`,
		inputTag(t, form, "supportEmail"))
	assert.Equal(t, `<input class="control" id="supportUrl" type="url" name="supportUrl" value="https://help.autumn.example" autocomplete="off" aria-describedby="supportUrlHint">`,
		inputTag(t, form, "supportUrl"))
	assert.Equal(t, `<input class="control" id="supportPhone" type="tel" name="supportPhone" value="&#43;15550100199" autocomplete="off" aria-describedby="supportPhoneHint">`,
		inputTag(t, form, "supportPhone"))
	assert.Contains(t, form, `<label class="field-label" for="supportEmail">Endereço de e-mail</label>`)
	assert.Contains(t, form, `<label class="field-label" for="supportUrl">URL da página de suporte</label>`)
	assert.Contains(t, form, `<label class="field-label" for="supportPhone">Número de telefone</label>`)
	assert.Contains(t, form, `<p class="field-hint" id="supportUrlHint">Um endereço https:, exibido como &#34;Página de suporte&#34;.</p>`)
	assert.Contains(t, form, `<p class="field-hint" id="supportPhoneHint">Com o código do país, como &#43;55 11 91234 5678. Espaços, hífens, pontos e parênteses são removidos ao salvar.</p>`)
}

// A refusal about a link is marked at the exact input its error_field points at, described by the
// notice and focused; one about a language label draws that row's disclosure open; the contact's are
// marked at their fields. Nothing else is marked.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedFooterInput(t *testing.T) {
	marked := func(t *testing.T, form, id string) {
		t.Helper()
		tag := inputTag(t, form, id)
		assert.Contains(t, tag, ` aria-invalid="true"`, id)
		assert.Contains(t, tag, ` autofocus`, id)
		assert.Regexp(t, `aria-describedby="brand-error( [^"]*)?"`, tag, id)
		assert.Equal(t, 1, strings.Count(form, `aria-invalid="true"`), "only %s is marked", id)
		assert.Equal(t, 1, strings.Count(form, "autofocus"), "only %s takes the focus", id)
	}

	for _, id := range []string{"footerLinks-0-label", "footerLinks-1-url", "footerLinks-2-label", "supportEmail", "supportUrl", "supportPhone"} {
		t.Run(id, func(t *testing.T) {
			form := renderFooterForm(t, id)
			marked(t, form, id)
			assert.NotContains(t, form, `<details class="disclosure" open>`, "no disclosure opens for a refusal outside it")
		})
	}

	t.Run("a language label", func(t *testing.T) {
		form := renderFooterForm(t, "footerLinks-1-labels-pt-BR")
		marked(t, form, "footerLinks-1-labels-pt-BR")
		assert.Equal(t, `<input class="control" id="footerLinks-1-labels-pt-BR" type="text" name="footerLinks-1-labels-pt-BR" value="" lang="pt-BR" autocomplete="off" aria-describedby="brand-error footerLinks-1-labelsHint" aria-invalid="true" autofocus>`,
			inputTag(t, form, "footerLinks-1-labels-pt-BR"))
		assert.Contains(t, footerRow(t, form, 1), `<details class="disclosure" open>`, "the refused label is on view")
		assert.Contains(t, footerRow(t, form, 0), `<details class="disclosure">`)
		assert.Contains(t, footerRow(t, form, 2), `<details class="disclosure">`)
		assert.Equal(t, 1, strings.Count(form, `<details class="disclosure" open>`))
	})

	t.Run("the URL with its whole tag", func(t *testing.T) {
		form := renderFooterForm(t, "footerLinks-1-url")
		assert.Equal(t, `<input class="control" id="footerLinks-1-url" type="url" name="footerLinks-1-url" value="https://status.autumn.example" autocomplete="off" aria-describedby="brand-error" aria-invalid="true" autofocus>`,
			inputTag(t, form, "footerLinks-1-url"))
		assert.Equal(t, `<input class="control" id="supportPhone" type="tel" name="supportPhone" value="&#43;15550100199" autocomplete="off" aria-describedby="supportPhoneHint">`,
			inputTag(t, form, "supportPhone"), "another field is drawn as without a refusal")
	})

	// A refusal about no footer input leaves the focus on the name, as before.
	form := renderFooterForm(t, "")
	assert.NotContains(t, form, `aria-invalid="true"`)
	assert.NotContains(t, form, "autofocus", "a stored brand's form takes no focus")
	assert.NotContains(t, form, "brand-error")
}
