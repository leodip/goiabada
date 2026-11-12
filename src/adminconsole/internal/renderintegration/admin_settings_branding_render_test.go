package renderintegration

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/brandkit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Branding pages (#810), drawn through the real renderer in pt-BR: the list marks the default
// and offers no deletion of it, the form draws appearance and theme as option cards whose swatches
// take the colors the auth server listed, each refusal is marked on the field it is about, and the
// delete page of the default says it cannot be deleted.

// Palettes that are no theme's real colors, so a swatch drawn from anything but the bind cannot
// pass. Each value names its theme, mode and token.
func testPalette(prefix string) map[string]string {
	return map[string]string{
		"canvas": "#" + prefix + "001", "surface": "#" + prefix + "002", "line": "#" + prefix + "003",
		"ink": "#" + prefix + "004", "ink-muted": "#" + prefix + "005", "brand": "#" + prefix + "006",
	}
}

var renderThemes = []adminsettingshandlers.BrandThemeOption{
	{Key: "blueberry", Name: "Mirtilo", Light: testPalette("aa0"), Dark: testPalette("ab0")},
	{Key: "plum", Name: "Ameixa", Light: testPalette("ba0"), Dark: testPalette("bb0")},
}

func TestRender_AdminSettingsBrandingListMarksTheDefault(t *testing.T) {
	out := renderMenuPageAt(t, "/admin/settings/branding", "/admin_settings_branding.html", map[string]interface{}{
		"brands": []adminsettingshandlers.BrandRow{
			{BrandResponse: api.BrandResponse{Id: 4, Name: "<b>Autumn</b>", Appearance: "dark", Theme: "plum", ClientCount: 2},
				AppearanceName: "Escuro", ThemeName: "Ameixa"},
			{BrandResponse: api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true, ClientCount: 13},
				AppearanceName: "Automático", ThemeName: "Mirtilo"},
		},
	})

	// The lead says where a brand is used, and the Clients column how many clients each draws
	// (#812 decision 3).
	assert.Contains(t, out, `<p class="page-lead">As páginas de um cliente são exibidas na marca escolhida na aba Configurações dele, ou na marca padrão quando nenhuma é escolhida. Este console de administração é exibido na marca do seu próprio cliente.</p>`)
	assert.Regexp(t, `<th scope="col">Tema</th>\s*<th scope="col">Clientes</th>`, out) //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"
	assert.Contains(t, out, `<td data-label="Clientes">2</td>`)                        //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"
	assert.Contains(t, out, `<td data-label="Clientes">13</td>`)                       //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"

	// The sidebar's Branding entry, under Settings, is the page the administrator is on.
	assert.Contains(t, out, `<a class="nav-link" href="/admin/settings/branding" aria-current="page">`)
	assert.NotContains(t, out, "/admin/settings/ui-theme")

	assert.Contains(t, out, `href="/admin/settings/branding/new"`)
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/branding/4/edit">&lt;b&gt;Autumn&lt;/b&gt;</a>`)
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/branding/5/edit">Default</a>`)
	assert.NotContains(t, out, "<b>Autumn</b>", "a brand's name is text")
	assert.Contains(t, out, ">Escuro</td>")
	assert.Contains(t, out, ">Ameixa</td>")

	// The default is marked, once, and is the one brand with no Delete.
	assert.Equal(t, 1, strings.Count(out, `<span class="tag tag-note ml-1">Padrão</span>`))
	assert.Regexp(t, `branding/5/edit">Default</a>\s*<span class="tag tag-note ml-1">Padrão</span>`, out)
	assert.Contains(t, out, `href="/admin/settings/branding/4/delete"`)
	assert.NotContains(t, out, `href="/admin/settings/branding/5/delete"`)
}

// radioTag is the whole <input> of the radio with the id named.
func radioTag(t *testing.T, out, id string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input type="radio" id="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(out)
	require.NotEmpty(t, tag, "no radio %s", id)
	return tag
}

func TestRender_AdminSettingsBrandingFormDrawsTheSwatchesFromThePalettes(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           false,
		"storedBrand":     api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum", ClientCount: 1},
		"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
		"clientsNote":     "1 cliente usa esta marca.",
	})

	assert.Contains(t, out, `<h1 class="page-title">Autumn</h1>`)
	assert.Contains(t, out, `value="Autumn"`)

	// Appearance and theme are option cards, the stored ones checked.
	assert.Contains(t, radioTag(t, out, "appearance-dark"), " checked")
	assert.NotContains(t, radioTag(t, out, "appearance-auto"), " checked")
	assert.NotContains(t, radioTag(t, out, "appearance-light"), " checked")
	assert.Contains(t, radioTag(t, out, "theme-plum"), `name="theme" value="plum" checked`)
	assert.NotContains(t, radioTag(t, out, "theme-blueberry"), " checked")
	assert.Contains(t, out, `<span class="choice-label" id="theme-name-plum">Ameixa</span>`)
	assert.Contains(t, out, `<span class="choice-label" id="appearance-name-auto">Automático</span>`)

	// Each theme card shows its light and its dark palette, the line as the card's border; every
	// value comes from the bind.
	for _, theme := range renderThemes {
		for _, palette := range []map[string]string{theme.Light, theme.Dark} {
			for token, value := range palette {
				assert.Regexp(t, `(fill|stroke)="`+value+`"`, out, "%s's %s", theme.Key, token)
			}
		}
	}
	// The appearance cards are drawn in the form's theme: Plum's light alone on Light, its dark on
	// Dark, and both on Automatic; Blueberry's colors appear only on Blueberry's own card.
	assert.Equal(t, 1+2, strings.Count(out, `fill="#ba0001"`), "Plum's light canvas: its card, Light and Automatic")
	assert.Equal(t, 1+2, strings.Count(out, `fill="#bb0001"`), "Plum's dark canvas: its card, Dark and Automatic")
	assert.Equal(t, 1, strings.Count(out, `fill="#aa0001"`))
	assert.NotContains(t, out, "theme-swatch-light", "no swatch keeps hand-written colors")

	// A brand that is not the default can be made the default, asked first.
	assert.Contains(t, out, `action="/admin/settings/branding/4/make-default" data-confirm-dialog="makeDefault"`)
	assert.Contains(t, out, `id="makeDefault_modalDialog"`)
	assert.NotContains(t, out, "Nenhuma página é exibida")
	assert.Contains(t, out, `<p class="page-lead">Escolha-a na aba Configurações de um cliente para exibir as páginas desse cliente nela. 1 cliente usa esta marca.</p>`)
	assert.Contains(t, out, `data-confirm-always="As páginas de todo cliente sem marca própria, e as páginas que não pertencem a nenhum cliente, passarão a ser exibidas nesta marca imediatamente."`)
}

func TestRender_AdminSettingsBrandingFormOfTheDefaultOffersNoMakeDefault(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":             false,
		"storedBrand":       api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
		"brand":             adminsettingshandlers.BrandForm{Name: "Default", Appearance: "auto", Theme: "blueberry"},
		"brandThemes":       renderThemes,
		"appearanceTheme":   renderThemes[0],
		"savedSuccessfully": true,
		"clientsNote":       "13 clientes usam esta marca.", //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"
	})
	assert.Contains(t, out, `<p class="page-lead">Esta é a marca padrão. As páginas de todo cliente sem marca própria são exibidas nela, assim como as páginas que não pertencem a nenhum cliente. 13 clientes usam esta marca.</p>`) //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"

	assert.NotContains(t, out, "make-default")
	assert.NotContains(t, out, "makeDefault_modalDialog")
	assert.Contains(t, out, `<span class="tag tag-note">Padrão</span>`)
	assert.Contains(t, out, "Esta é a marca padrão")
	assert.Contains(t, out, `<div class="notice notice-positive" role="status">`)
	assert.Contains(t, out, "Marca salva.")
	assert.Contains(t, radioTag(t, out, "appearance-auto"), " checked")
}

func TestRender_AdminSettingsBrandingNewForm(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           true,
		"brand":           adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "blueberry"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[0],
	})

	assert.Contains(t, out, `<h1 class="page-title">Nova marca</h1>`)
	assert.Contains(t, out, ">Criar marca</button>")
	assert.NotContains(t, out, "make-default")
	assert.Regexp(t, `<input class="control" id="name"[^>]* autofocus>`, out, "a new brand starts at its name")
	assert.Contains(t, radioTag(t, out, "theme-blueberry"), " checked")
}

// Each refusal is marked on the field it is about: the name input for the name's four, the
// appearance cards and the theme cards for theirs, the group described by the notice and its first
// card focused.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedField(t *testing.T) {
	render := func(errorField string) string {
		return renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
			"isNew":           true,
			"brand":           adminsettingshandlers.BrandForm{Name: "Spring", Appearance: "auto", Theme: "plum"},
			"brandThemes":     renderThemes,
			"appearanceTheme": renderThemes[1],
			"error":           "Não.",
			"errorField":      errorField,
		})
	}

	out := render("name")
	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="brand-error">`)
	assert.Regexp(t, `<input class="control" id="name"[^>]* aria-describedby="brand-error nameHint" aria-invalid="true" autofocus>`, out)
	assert.NotContains(t, out, `<fieldset aria-describedby="brand-error">`)
	for _, id := range []string{"appearance-auto", "theme-plum"} {
		assert.NotContains(t, radioTag(t, out, id), "aria-invalid")
	}

	out = render("appearance")
	assert.NotRegexp(t, `id="name"[^>]*aria-invalid`, out)
	assert.Equal(t, 1, strings.Count(out, `<fieldset aria-describedby="brand-error">`))
	for _, id := range []string{"appearance-auto", "appearance-light", "appearance-dark"} {
		assert.Contains(t, radioTag(t, out, id), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, out, "appearance-auto"), "autofocus")
	assert.NotContains(t, radioTag(t, out, "theme-blueberry"), "aria-invalid")

	out = render("theme")
	assert.NotRegexp(t, `id="name"[^>]*aria-invalid`, out)
	assert.Equal(t, 1, strings.Count(out, `<fieldset aria-describedby="brand-error">`))
	for _, id := range []string{"theme-blueberry", "theme-plum"} {
		assert.Contains(t, radioTag(t, out, id), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, out, "theme-blueberry"), "autofocus", "the first theme takes the focus")
	assert.NotContains(t, radioTag(t, out, "theme-plum"), "autofocus")
	assert.NotContains(t, radioTag(t, out, "appearance-auto"), "aria-invalid")

	// A refusal about no one field marks none of the form's, and leaves the focus on the name. (The
	// preview's sample, outside the form, draws a refused password as the sign-in page does.)
	out = render("")
	formEnd := strings.Index(out, "</form>")
	require.Positive(t, formEnd)
	form := out[:formEnd]
	assert.NotContains(t, form, `aria-invalid="true"`)
	assert.Regexp(t, `<input class="control" id="name"[^>]* autofocus>`, out)
}

func TestRender_AdminSettingsBrandingDeletePage(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_delete.html", map[string]interface{}{
		"brand": adminsettingshandlers.BrandRow{
			BrandResponse:  api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
			AppearanceName: "Escuro", ThemeName: "Ameixa"},
		"clientsNote": "2 clientes a usam. Eles passarão para a marca padrão, Default.", //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"
	})
	// The lead says the brand will be deleted, how many clients use it and where they will move
	// (#812 decision 3).
	assert.Contains(t, out, `<p class="page-lead">A marca será excluída. 2 clientes a usam. Eles passarão para a marca padrão, Default.</p>`) //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"
	assert.NotContains(t, out, "Nenhuma página")
	assert.Contains(t, out, "<dd>Autumn</dd>")
	assert.Contains(t, out, "<dd>Escuro</dd>")
	assert.Contains(t, out, "<dd>Ameixa</dd>")
	assert.Contains(t, out, `<input class="control" id="name" type="text" name="name" value=""`)
	assert.Contains(t, out, `<button id="btnDelete" class="button button-danger" type="submit">Excluir marca</button>`)

	// The default cannot be deleted: its page says so, in the auth server's own words, and offers
	// no deletion.
	out = renderMenuPage(t, "/admin_settings_branding_delete.html", map[string]interface{}{
		"brand": adminsettingshandlers.BrandRow{
			BrandResponse:  api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
			AppearanceName: "Automático", ThemeName: "Mirtilo"},
	})
	assert.Contains(t, out, `<div class="notice notice-caution">`)
	assert.NotContains(t, out, "btnDelete")
	assert.NotContains(t, out, `name="name"`)
	assert.Contains(t, out, `href="/admin/settings/branding">Voltar às marcas</a>`)
}

// sampleOf is the sample of the mode named in the preview: from its opening tag to the next
// sample, or to the end of the preview.
func sampleOf(t *testing.T, preview, mode string) string {
	t.Helper()
	start := strings.Index(preview, `<div class="brand-sample" data-brand-sample="`+mode+`"`)
	require.GreaterOrEqual(t, start, 0, "no %s sample", mode)
	rest := preview[start+1:]
	end := strings.Index(rest, `<div class="brand-sample"`)
	if end < 0 {
		end = strings.Index(rest, "</section>")
	}
	require.GreaterOrEqual(t, end, 0, "the %s sample does not end", mode)
	return preview[start : start+1+end]
}

// The brand editor beside its preview (#811): the form on the left and, outside it, the preview
// with its text, the Light/Dark switch and a light and a dark sample of a refused sign-in, each an
// illustration nobody can reach or operate, hidden until the page's script has styled it, and the
// palettes the script styles them from.
func TestRender_AdminSettingsBrandingFormDrawsThePreview(t *testing.T) {
	for _, isNew := range []bool{true, false} {
		t.Run(map[bool]string{true: "new brand", false: "a brand's page"}[isNew], func(t *testing.T) {
			bind := map[string]interface{}{
				"isNew":           isNew,
				"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"},
				"brandThemes":     renderThemes,
				"appearanceTheme": renderThemes[1],
			}
			if !isNew {
				bind["storedBrand"] = api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"}
			}
			out := renderMenuPage(t, "/admin_settings_branding_brand.html", bind)

			assert.Regexp(t, `<script src="/static/pages/brand-preview\.js\?v=[0-9a-f]+" defer></script>`, out)

			// The two panes: the form, then the preview beside it, outside the form, so nothing in
			// the preview is submitted with it.
			editorStart := strings.Index(out, `<div class="brand-editor">`)
			require.GreaterOrEqual(t, editorStart, 0, "the editor's two panes")
			editor := out[editorStart:]
			formEnd := strings.Index(editor, "</form>")
			preview := strings.Index(editor, `<section class="brand-preview" aria-labelledby="brand-preview-title">`)
			require.Positive(t, formEnd)
			require.Greater(t, preview, formEnd, "the preview follows the form, outside it")
			editor = editor[preview:]

			// The page says in text what the preview shows.
			assert.Contains(t, editor, `<h2 class="brand-preview-title" id="brand-preview-title">Pré-visualização</h2>`)
			// One paragraph holds what it shows and the sentence saying which modes apply, so the
			// preview fits a 1280×800 screen beside the form in every language.
			assert.Regexp(t, `<p class="field-hint"><span>Uma amostra de uma página de entrada nesta marca, como o formulário está agora\. A marca só muda quando você salva\.</span>\s*<span data-brand-preview-note="auto" hidden>`, editor)

			// The switch, named, its two choices the appearances' names, on Light; a Dark brand
			// draws it hidden, and says it is always dark.
			assert.Regexp(t, `<fieldset class="brand-preview-switch" hidden>\s*<legend class="field-label">Visualizar em</legend>`, editor)
			assert.Regexp(t, `<input type="radio" id="brand-preview-mode-light" name="brandPreviewMode" value="light" checked>\s*<span>Claro</span>`, editor)
			assert.Regexp(t, `<input type="radio" id="brand-preview-mode-dark" name="brandPreviewMode" value="dark">\s*<span>Escuro</span>`, editor)
			assert.Regexp(t, `<span data-brand-preview-note="dark">Esta marca é sempre escura\.</span></p>`, editor)

			for _, mode := range []string{"light", "dark"} {
				sample := sampleOf(t, editor, mode)
				assert.Regexp(t, `^<div class="brand-sample" data-brand-sample="`+mode+`" hidden inert aria-hidden="true">`, sample)
				assert.NotContains(t, sample, "style=", "the script styles the sample through the CSSOM")
				for _, tag := range []string{"<input", "<button", "<a ", "<select", "<textarea", "tabindex"} {
					assert.NotContains(t, sample, tag, "nothing in the sample can be focused or operated")
				}
				// A refused sign-in, in the sign-in page's own words: the app name, the title, the
				// lead, the missing password said in a danger notice, the address filled, the
				// password marked invalid with no error line, Cancel beside Sign in, and the link.
				assert.Contains(t, sample, `<p class="auth-brand">Test</p>`)
				assert.Contains(t, sample, `<p class="auth-title">Entrar</p>`)
				assert.Contains(t, sample, `<p class="auth-lead">Digite seu e-mail e sua senha para continuar.</p>`)
				assert.Regexp(t, `(?s)<div class="notice notice-danger">\s*<svg[^>]*>.*</svg>\s*<p>A senha é obrigatória\.</p>`, sample)
				assert.Regexp(t, `<span class="field-label">E-mail</span>\s*<span class="control">alex@example\.com</span>`, sample)
				assert.Regexp(t, `<span class="field-label">Senha</span>\s*<span class="control" aria-invalid="true"></span>`, sample)
				assert.Contains(t, sample, `<span class="text-link">Esqueceu sua senha?</span>`)
				assert.NotContains(t, sample, "field-error", "a sign-in page draws no error line under a field")
				assert.Regexp(t, `<div class="auth-actions">\s*<span class="button">Cancelar</span>\s*<span class="button button-primary">Entrar</span>\s*</div>`, sample)
			}

			// The palettes the script draws the samples in: every listed theme's light and dark one.
			block := regexp.MustCompile(`<script type="application/json" id="brand-palettes">(.*?)</script>`).FindStringSubmatch(out)
			require.Len(t, block, 2, "the palettes data block")
			assert.Contains(t, block[1], `{"key":"blueberry","light":{"brand":"#aa0006",`)
			assert.Contains(t, block[1], `"dark":{"brand":"#bb0006",`)
			for _, theme := range renderThemes {
				for _, value := range []string{theme.Light["canvas"], theme.Dark["ink-muted"]} {
					assert.Contains(t, block[1], `"`+value+`"`, "%s's palettes", theme.Key)
				}
			}
		})
	}
}

// The preview is drawn for the form's appearance (#811 decision 2): the sentence saying which
// modes apply shown and the other two drawn hidden, for the script to show as the appearance
// changes, and the switch shown only under Automatic, the appearance a form holding none it knows
// is previewed as.
func TestRender_AdminSettingsBrandingFormDrawsThePreviewForTheAppearance(t *testing.T) {
	notes := map[string]string{
		"auto":  `<span data-brand-preview-note="auto">Os visitantes a veem clara ou escura, conforme o dispositivo deles.</span>`,
		"light": `<span data-brand-preview-note="light">Esta marca é sempre clara.</span>`,
		"dark":  `<span data-brand-preview-note="dark">Esta marca é sempre escura.</span>`,
	}
	for _, tc := range []struct {
		appearance   string
		shownNote    string
		switchHidden bool
	}{
		{"auto", "auto", false},
		{"light", "light", true},
		{"dark", "dark", true},
		{"sepia", "auto", false},
	} {
		t.Run(tc.appearance, func(t *testing.T) {
			out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
				"isNew":           true,
				"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: tc.appearance, Theme: "plum"},
				"brandThemes":     renderThemes,
				"appearanceTheme": renderThemes[1],
			})
			start := strings.Index(out, `<section class="brand-preview"`)
			require.Positive(t, start)
			preview := out[start:]

			for appearance, note := range notes {
				if appearance == tc.shownNote {
					assert.Contains(t, preview, note, "the sentence for %s shows", appearance)
				} else {
					assert.Contains(t, preview, strings.Replace(note, `">`, `" hidden>`, 1), "the sentence for %s is hidden", appearance)
				}
			}
			switchTag := regexp.MustCompile(`<fieldset class="brand-preview-switch"[^>]*>`).FindString(preview)
			if tc.switchHidden {
				assert.Equal(t, `<fieldset class="brand-preview-switch" hidden>`, switchTag)
			} else {
				assert.Equal(t, `<fieldset class="brand-preview-switch">`, switchTag)
			}
		})
	}
}

// The three Appearance cards' swatches are marked for the preview's script, which redraws them in
// the theme the form holds (#811 decision 4): each names the modes it shows, in order, and each
// shape names the token its color is drawn from. The theme cards' swatches are not marked.
func TestRender_AdminSettingsBrandingFormMarksTheAppearanceSwatches(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           true,
		"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "auto", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})

	swatches := regexp.MustCompile(`<span class="theme-swatch" aria-hidden="true"[^>]*>`).FindAllString(out, -1)
	require.Len(t, swatches, 3+len(renderThemes))
	assert.Equal(t, []string{
		`<span class="theme-swatch" aria-hidden="true" data-appearance-swatch="light dark">`,
		`<span class="theme-swatch" aria-hidden="true" data-appearance-swatch="light">`,
		`<span class="theme-swatch" aria-hidden="true" data-appearance-swatch="dark">`,
	}, swatches[:3], "the Automatic, Light and Dark cards, in order")
	for _, swatch := range swatches[3:] {
		assert.Equal(t, `<span class="theme-swatch" aria-hidden="true">`, swatch, "a theme card's swatch keeps its theme")
	}

	// Plum's light palette, on the Light card, each shape naming its token.
	light := regexp.MustCompile(`(?s)data-appearance-swatch="light">(.*?)</span>`).FindStringSubmatch(out)
	require.Len(t, light, 2)
	for _, shape := range []string{
		`<rect width="120" height="64" fill="#ba0001" data-fill="canvas"/>`,
		`fill="#ba0002" stroke="#ba0003" vector-effect="non-scaling-stroke" data-fill="surface" data-stroke="line"/>`,
		`fill="#ba0004" data-fill="ink"/>`,
		`fill="#ba0005" data-fill="ink-muted"/>`,
		`fill="#ba0006" data-fill="brand"/>`,
	} {
		assert.Contains(t, light[1], shape)
	}
}

// optionTag is the whole <option> of the font select with the value named.
func optionTag(t *testing.T, out, value string) string {
	t.Helper()
	tag := regexp.MustCompile(`<option value="` + regexp.QuoteMeta(value) + `"[^>]*>`).FindString(out)
	require.NotEmpty(t, tag, "no font option %s", value)
	return tag
}

// The kit's four choices in the brand form (#813): the corners and the background fit as radios, the
// font family as a select of the six system families and the uploaded font, and the switch hiding
// the app name, each holding what the form holds, in the console's language.
func TestRender_AdminSettingsBrandingFormDrawsTheKitsChoices(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":       false,
		"storedBrand": api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brand": adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum",
			Corners: "pill", Font: "serif", BackgroundFit: "tile", HideAppName: true},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})
	// The brand form, after the page's Make default form.
	editorStart := strings.Index(out, `<div class="brand-editor">`)
	require.GreaterOrEqual(t, editorStart, 0)
	form := out[editorStart:]
	formEnd := strings.Index(form, "</form>")
	require.Positive(t, formEnd)
	form = form[:formEnd]

	// Corners: square, rounded and pill, the stored one checked.
	assert.Regexp(t, `<legend class="field-label mb-2">Cantos</legend>`, form)
	for value, label := range map[string]string{"square": "Quadrados", "rounded": "Arredondados", "pill": "Em pílula"} {
		tag := radioTag(t, form, "corners-"+value)
		assert.Contains(t, tag, `name="corners" value="`+value+`"`)
		assert.Regexp(t, regexp.QuoteMeta(tag)+`<span>`+label+`</span></label>`, form)
	}
	assert.Contains(t, radioTag(t, form, "corners-pill"), " checked")
	assert.NotContains(t, radioTag(t, form, "corners-square"), " checked")
	assert.NotContains(t, radioTag(t, form, "corners-rounded"), " checked")

	// The font family, labelled and described, the stored one selected.
	assert.Contains(t, form, `<label class="field-label" for="font">Fonte</label>`)
	assert.Regexp(t, `<select class="control" id="font" name="font" aria-describedby="fontHint">`, form)
	assert.Contains(t, form, `<p class="field-hint" id="fontHint">As famílias do sistema usam fontes que o dispositivo de cada visitante já tem, então o texto muda um pouco de um dispositivo para outro.</p>`)
	families := regexp.MustCompile(`<option value="([^"]*)"[^>]*>([^<]*)</option>`).FindAllStringSubmatch(form, -1)
	got := make([][2]string, 0, len(families))
	for _, family := range families {
		got = append(got, [2]string{family[1], family[2]})
	}
	assert.Equal(t, [][2]string{
		{"system-ui", "Interface do sistema"},
		{"humanist", "Humanista"},
		{"geometric", "Geométrica"},
		{"serif", "Serifada"},
		{"neo-grotesque", "Neogrotesca"},
		{"rounded", "Arredondada"},
		{"uploaded", "Fonte enviada"},
	}, got, "the six system families, System UI first, then the uploaded font")
	assert.Equal(t, `<option value="serif" selected>`, optionTag(t, form, "serif"))
	assert.Equal(t, 1, strings.Count(form, " selected>"), "one family selected")

	// The background fit: cover, contain and tile, described, the stored one checked.
	assert.Regexp(t, `<fieldset aria-describedby="backgroundHint backgroundState backgroundFitHint">\s*<legend class="field-label mb-1" id="backgroundLabel">Imagem de fundo</legend>`, form)
	assert.Contains(t, form, `<p class="field-hint mt-3 mb-2" id="backgroundFitHint">Como uma imagem de fundo preenche a página atrás do cartão de entrada: cobrir preenche a página e pode cortar a imagem, conter mostra a imagem inteira e ladrilho a repete no tamanho original.</p>`)
	for value, label := range map[string]string{"cover": "Cobrir", "contain": "Conter", "tile": "Ladrilho"} {
		tag := radioTag(t, form, "backgroundFit-"+value)
		assert.Contains(t, tag, `name="backgroundFit" value="`+value+`"`)
		assert.Regexp(t, regexp.QuoteMeta(tag)+`<span>`+label+`</span></label>`, form)
	}
	assert.Contains(t, radioTag(t, form, "backgroundFit-tile"), " checked")
	assert.NotContains(t, radioTag(t, form, "backgroundFit-cover"), " checked")

	// The switch, on, with what it does said beside it.
	assert.Regexp(t, `<label class="check-row" for="hideAppName">\s*<input type="checkbox" id="hideAppName" name="hideAppName" aria-describedby="hideAppNameHint" checked>\s*`+
		`<span class="grid min-w-0 flex-1 gap-0\.5">\s*<span class="choice-label">Ocultar o nome do aplicativo</span>\s*`+
		`<span class="field-hint" id="hideAppNameHint">Para um logotipo que já mostra o nome\. Uma marca sem logotipo sempre mostra o nome\.</span>`, form)
}

// A new brand's form holds the choices a brand nobody has changed is drawn in: rounded, System UI,
// cover, and the app name shown.
func TestRender_AdminSettingsBrandingNewFormHoldsTodaysLook(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew": true,
		"brand": adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "blueberry",
			Corners: "rounded", Font: "system-ui", BackgroundFit: "cover"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[0],
	})
	assert.Contains(t, radioTag(t, out, "corners-rounded"), " checked")
	assert.Equal(t, `<option value="system-ui" selected>`, optionTag(t, out, "system-ui"))
	assert.Contains(t, radioTag(t, out, "backgroundFit-cover"), " checked")
	assert.Regexp(t, `<input type="checkbox" id="hideAppName" name="hideAppName" aria-describedby="hideAppNameHint">`, out)
}

// A refusal about a kit choice is marked on its field (#813 decision 10): the corners or the
// background fit radios, each group described by the notice and its first radio focused, or the font
// select, described by the notice and its hint and focused. The other fields are left unmarked.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedKitChoice(t *testing.T) {
	render := func(errorField string) string {
		out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
			"isNew": true,
			"brand": adminsettingshandlers.BrandForm{Name: "Spring", Appearance: "auto", Theme: "plum",
				Corners: "oval", Font: "uploaded", BackgroundFit: "stretch"},
			"brandThemes":     renderThemes,
			"appearanceTheme": renderThemes[1],
			"error":           "Não.",
			"errorField":      errorField,
		})
		formEnd := strings.Index(out, "</form>")
		require.Positive(t, formEnd)
		return out[:formEnd]
	}
	fontTag := func(form string) string {
		tag := regexp.MustCompile(`<select class="control" id="font"[^>]*>`).FindString(form)
		require.NotEmpty(t, tag)
		return tag
	}

	form := render("corners")
	assert.Regexp(t, `<fieldset aria-describedby="brand-error">\s*<legend class="field-label mb-2">Cantos</legend>`, form)
	for _, value := range []string{"square", "rounded", "pill"} {
		assert.Contains(t, radioTag(t, form, "corners-"+value), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, form, "corners-square"), "autofocus", "the first corner shape takes the focus")
	assert.NotContains(t, radioTag(t, form, "corners-pill"), "autofocus")
	assert.NotRegexp(t, `id="name"[^>]*autofocus`, form)
	assert.Equal(t, `<select class="control" id="font" name="font" aria-describedby="fontHint">`, fontTag(form))
	assert.NotContains(t, radioTag(t, form, "backgroundFit-cover"), "aria-invalid")

	form = render("font")
	assert.Equal(t, `<select class="control" id="font" name="font" aria-describedby="brand-error fontHint" aria-invalid="true" autofocus>`, fontTag(form))
	assert.Equal(t, `<option value="uploaded" selected>`, optionTag(t, form, "uploaded"), "with what was sent")
	assert.NotContains(t, radioTag(t, form, "corners-square"), "aria-invalid")
	assert.NotContains(t, radioTag(t, form, "backgroundFit-cover"), "aria-invalid")
	assert.NotRegexp(t, `id="name"[^>]*autofocus`, form)

	form = render("backgroundFit")
	assert.Regexp(t, `<fieldset aria-describedby="brand-error backgroundHint backgroundState backgroundFitHint">\s*<legend class="field-label mb-1" id="backgroundLabel">Imagem de fundo</legend>`, form)
	for _, value := range []string{"cover", "contain", "tile"} {
		assert.Contains(t, radioTag(t, form, "backgroundFit-"+value), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, form, "backgroundFit-cover"), "autofocus")
	assert.NotContains(t, radioTag(t, form, "corners-square"), "aria-invalid")
	assert.Equal(t, `<select class="control" id="font" name="font" aria-describedby="fontHint">`, fontTag(form))
	assert.NotRegexp(t, `id="name"[^>]*autofocus`, form)

	// A refusal about the name leaves the kit's fields unmarked.
	form = render("name")
	assert.NotContains(t, radioTag(t, form, "corners-square"), "aria-invalid")
	assert.NotContains(t, radioTag(t, form, "backgroundFit-cover"), "aria-invalid")
	assert.Equal(t, `<select class="control" id="font" name="font" aria-describedby="fontHint">`, fontTag(form))
	assert.Equal(t, 1, strings.Count(form, "autofocus"), "the name alone takes the focus")
}

// The preview's script is handed what each corner shape and family draws, beside the palettes, in a
// data block of its own.
func TestRender_AdminSettingsBrandingFormHandsThePreviewTheKitsStyles(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           true,
		"brand":           adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "plum", Corners: "rounded", Font: "system-ui", BackgroundFit: "cover"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
		"brandKitStyles": adminsettingshandlers.BrandKitStyles{
			Corners: map[string]brandkit.Radii{"pill": {Control: "9999px", Panel: "1.5rem"}},
			Fonts:   map[string]string{"serif": "Charter, 'Bitstream Charter', serif"},
		},
	})
	block := regexp.MustCompile(`<script type="application/json" id="brand-kit-styles">(.*?)</script>`).FindStringSubmatch(out)
	require.Len(t, block, 2, "the kit's styles data block")
	var styles adminsettingshandlers.BrandKitStyles
	require.NoError(t, json.Unmarshal([]byte(block[1]), &styles), block[1])
	assert.Equal(t, map[string]brandkit.Radii{"pill": {Control: "9999px", Panel: "1.5rem"}}, styles.Corners)
	assert.Equal(t, map[string]string{"serif": "Charter, 'Bitstream Charter', serif"}, styles.Fonts)
}

// renderUploads is what the editor's uploads are bound with: each kind's route, the types it takes,
// its byte limit and the sentence refusing a file over it, in values no kind has, so a field drawn from
// anything but the bind cannot pass.
var renderUploads = map[string]adminsettingshandlers.BrandAssetUpload{
	"logo":       {URL: "/admin/settings/branding/assets/logo", Accept: "image/png,image/jpeg,image/webp", MaxBytes: 1001, TooLarge: "Logo grande."},
	"favicon":    {URL: "/admin/settings/branding/assets/favicon", Accept: "image/png", MaxBytes: 1002, TooLarge: "Favicon grande."},
	"background": {URL: "/admin/settings/branding/assets/background", Accept: "image/png,image/jpeg,image/webp", MaxBytes: 1003, TooLarge: "Fundo grande."},
	"font":       {URL: "/admin/settings/branding/assets/font", Accept: ".woff2,font/woff2", MaxBytes: 1004, TooLarge: "Fonte grande."},
}

// renderKitForm draws a stored brand's form holding a logo, a favicon and a regular font file, and
// answers the form, refused at errorField when it names one.
func renderKitForm(t *testing.T, errorField string) string {
	t.Helper()
	bind := map[string]interface{}{
		"isNew":       false,
		"storedBrand": api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "auto", Theme: "plum"},
		"brand": adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "auto", Theme: "plum",
			Corners: "rounded", Font: "uploaded", BackgroundFit: "cover",
			Logo:        &api.BrandAssetResponse{Id: 11, Kind: "logo", Url: "https://login.example.test/brand-assets/11?v=a&x=<b>", ContentType: "image/png", Width: 200, Height: 60},
			Favicon:     &api.BrandAssetResponse{Id: 13, Kind: "favicon", Url: "https://login.example.test/brand-assets/13?v=c", ContentType: "image/png", Width: 64, Height: 64},
			RegularFont: &api.BrandAssetResponse{Id: 15, Kind: "font", Url: "https://login.example.test/brand-assets/15?v=e", ContentType: "font/woff2"}},
		"brandThemes":       renderThemes,
		"appearanceTheme":   renderThemes[1],
		"brandAssetUploads": renderUploads,
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

// assetField is the upload field of slot: from its fieldset's start to the end of its hidden fields.
func assetField(t *testing.T, form, slot string) string {
	t.Helper()
	start := strings.Index(form, `<legend class="field-label mb-1" id="`+slot+`Label">`)
	require.GreaterOrEqual(t, start, 0, "no legend for %s", slot)
	fieldsetStart := strings.LastIndex(form[:start], "<fieldset")
	require.GreaterOrEqual(t, fieldsetStart, 0)
	end := strings.Index(form[start:], `name="`+slot+`Url"`)
	require.Positive(t, end, "no URL input for %s", slot)
	end += strings.Index(form[start+end:], ">") + 1
	return form[fieldsetStart : start+end]
}

// Each of the kit's six slots has its upload field in the form (#813 decision 1): named and described
// in the console's language, posting to its kind's route, holding the stored asset's id and URL for
// Save to send and the preview to draw, an image's thumbnail beside it, and Remove while it holds one.
func TestRender_AdminSettingsBrandingFormDrawsAnUploadFieldPerSlot(t *testing.T) {
	form := renderKitForm(t, "")

	for _, tc := range []struct {
		slot, kind, label, hint, thumb string
		// id and url are the hidden fields' values, src the thumbnail's, escaped as an attribute
		// holding text and one holding a URL are.
		id, url, src string
	}{
		{"logo", "logo", "Logotipo", "Exibido acima do nome do aplicativo no cartão de entrada. Uma imagem estática PNG, JPEG ou WebP, de 10 a 512 pixels de lado, até 1 MB.",
			"brand-asset-thumb", "11", "https://login.example.test/brand-assets/11?v=a&amp;x=&lt;b&gt;", "https://login.example.test/brand-assets/11?v=a&amp;x=%3cb%3e"},
		{"darkLogo", "logo", "Logotipo escuro", "Exibido no modo escuro no lugar do logotipo, com as mesmas regras. Requer um logotipo.",
			"brand-asset-thumb brand-asset-thumb-dark", "", "", ""},
		{"favicon", "favicon", "Favicon", "Mostrado na aba do navegador. Uma imagem PNG quadrada e estática, de 48 a 512 pixels de lado, até 1 MB.",
			"brand-asset-thumb", "13", "https://login.example.test/brand-assets/13?v=c", "https://login.example.test/brand-assets/13?v=c"},
		{"background", "background", "Imagem de fundo", "Exibida atrás do cartão de entrada. Uma imagem estática PNG, JPEG ou WebP, de 10 a 3840 pixels de lado, até 2 MB.",
			"brand-asset-thumb", "", "", ""},
		{"regularFont", "font", "Arquivo da fonte", "Usado quando a fonte é Fonte enviada. Um arquivo WOFF2, até 2 MB. Sozinho, ele desenha todos os pesos.",
			"", "15", "https://login.example.test/brand-assets/15?v=e", ""},
		{"boldFont", "font", "Arquivo da fonte em negrito", "Para o texto em negrito, ao lado do arquivo da fonte. Um arquivo WOFF2, até 2 MB.",
			"", "", "", ""},
	} {
		t.Run(tc.slot, func(t *testing.T) {
			field := assetField(t, form, tc.slot)
			upload := renderUploads[tc.kind]
			filled := tc.id != ""

			assert.Contains(t, field, `<legend class="field-label mb-1" id="`+tc.slot+`Label">`+tc.label+`</legend>`)
			assert.Contains(t, field, `<p class="field-hint mb-2" id="`+tc.slot+`Hint">`+tc.hint+`</p>`)
			assert.Regexp(t, `<fieldset[^>]* aria-describedby="`+tc.slot+`Hint `+tc.slot+`State`, field)
			assert.Contains(t, field, `<div class="brand-asset" data-brand-asset="`+tc.slot+`" data-upload-url="`+upload.URL+
				`" data-max-bytes="`+strconv.FormatInt(upload.MaxBytes, 10)+`" data-too-large="`+upload.TooLarge+`">`)
			assert.Contains(t, field, `<input type="file" id="`+tc.slot+`File" accept="`+upload.Accept+`" aria-labelledby="`+tc.slot+`Label" hidden>`)
			assert.Contains(t, field, `<button class="button" type="button" id="`+tc.slot+`Upload" aria-labelledby="`+tc.slot+`Upload `+tc.slot+`Label" data-brand-asset-upload>Enviar</button>`)
			removeHidden := map[bool]string{true: "", false: " hidden"}[filled]
			assert.Contains(t, field, `<button class="button button-quiet" type="button" id="`+tc.slot+`Remove" aria-labelledby="`+tc.slot+`Remove `+tc.slot+`Label" data-brand-asset-remove`+removeHidden+`>Remover</button>`)
			assert.Contains(t, field, `<div class="not-empty:mt-2" id="`+tc.slot+`Status" role="status"></div>`)
			assert.Contains(t, field, `<input type="hidden" name="`+tc.slot+`" value="`+tc.id+`">`)
			assert.Contains(t, field, `<input type="hidden" name="`+tc.slot+`Url" value="`+tc.url+`">`)

			// What the slot holds, said in text: one sentence shows, the other is hidden.
			assert.Contains(t, field, `<span data-brand-asset-state="empty"`+map[bool]string{true: " hidden", false: ""}[filled]+`>Nenhum arquivo.</span>`)
			assert.Contains(t, field, `<span data-brand-asset-state="filled"`+removeHidden+`>Arquivo enviado.</span>`)

			// An image's thumbnail, decorative beside the sentence; a font has none.
			switch {
			case tc.thumb == "":
				assert.NotContains(t, field, "brand-asset-thumb")
			case filled:
				assert.Contains(t, field, `<span class="`+tc.thumb+`" aria-hidden="true"><img src="`+tc.src+`" alt=""></span>`)
			default:
				assert.Contains(t, field, `<span class="`+tc.thumb+`" aria-hidden="true" hidden></span>`)
			}
		})
	}
	assert.Contains(t, form, `data-asset-uploading="Enviando…" data-asset-uploaded="Enviado. Salve a marca para usá-lo." `+
		`data-asset-removed="Removido. Salve a marca para aplicar." data-asset-upload-failed="Não foi possível enviar o arquivo. Tente de novo."`,
		"the sentences the upload script says")
	assert.NotContains(t, form, "autofocus", "a stored brand's page focuses nothing")
}

// A refusal about a slot is marked at its field: its group described by the notice, and its Upload
// button focused. The other slots and the name are left unmarked.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedSlot(t *testing.T) {
	for _, slot := range []string{"logo", "darkLogo", "favicon", "background", "regularFont", "boldFont"} {
		t.Run(slot, func(t *testing.T) {
			form := renderKitForm(t, slot)
			assert.Regexp(t, `<fieldset[^>]* aria-describedby="brand-error `+slot+`Hint `+slot+`State`, assetField(t, form, slot))
			assert.Regexp(t, `id="`+slot+`Upload"[^>]* autofocus`, form)
			assert.Equal(t, 1, strings.Count(form, "autofocus"), "the slot's Upload alone takes the focus")
			assert.Equal(t, 1, strings.Count(form, `aria-describedby="brand-error`), "one field is described by the notice")
		})
	}
}

// The background's field and its fit are one group, "Background image": a refused fit marks its radios,
// as before, and the group is described by the file's hint and the fit's.
func TestRender_AdminSettingsBrandingFormGroupsTheBackgroundWithItsFit(t *testing.T) {
	form := renderKitForm(t, "")
	legend := strings.Index(form, `id="backgroundLabel"`)
	require.Positive(t, legend)
	group := form[strings.LastIndex(form[:legend], "<fieldset"):]
	end := strings.Index(group, "</fieldset>")
	require.Positive(t, end)
	group = group[:end]
	assert.Regexp(t, `^<fieldset aria-describedby="backgroundHint backgroundState backgroundFitHint">\s*`+
		`<legend class="field-label mb-1" id="backgroundLabel">Imagem de fundo</legend>`, group)
	assert.Contains(t, group, `data-brand-asset="background"`)
	assert.Contains(t, group, `<p class="field-hint mt-3 mb-2" id="backgroundFitHint">Como uma imagem de fundo preenche`)
	assert.Contains(t, group, `id="backgroundFit-cover"`)

	form = renderKitForm(t, "backgroundFit")
	assert.Regexp(t, `<fieldset aria-describedby="brand-error backgroundHint backgroundState backgroundFitHint">`, form)
	assert.Contains(t, radioTag(t, form, "backgroundFit-cover"), "autofocus")
	assert.NotRegexp(t, `id="backgroundUpload"[^>]* autofocus`, form)
}

// The sample draws the logo above the app name, as a sign-in card does: a box the preview script puts
// the logo of each mode in, drawn hidden and empty until it has one.
func TestRender_AdminSettingsBrandingSampleHasARoomForTheLogo(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           true,
		"brand":           adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "plum", Corners: "rounded", Font: "system-ui", BackgroundFit: "cover"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})
	for _, mode := range []string{"light", "dark"} {
		assert.Regexp(t, `<div class="panel-body">\s*<div class="auth-logo" hidden></div>\s*<p class="auth-brand">`, sampleOf(t, out, mode))
	}
}

// The sample draws a room for the brand's footer under its card (#814 decision 12), the last thing in
// it, which the preview script fills from the form's footer fields: hidden and empty until it holds a
// link or a contact value, its links' list, then the "Need help?" line with a place for the address,
// the number and the "Support page" link, in the page's language. It is not the page's footer
// landmark, which the console's admin pages never draw, and nothing in it can be operated: the links
// are drawn as text.
func TestRender_AdminSettingsBrandingSampleHasARoomForTheFooter(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew": false,
		"brand": adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "plum", Corners: "rounded", Font: "system-ui", BackgroundFit: "cover",
			FooterLinks:  [3]adminsettingshandlers.BrandFooterLinkRow{{Label: "Privacy", Url: "https://autumn.example/privacy"}},
			SupportEmail: "help@autumn.example"},
		"storedBrand":     api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "auto", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})
	assert.NotContains(t, out, "<footer", "the console's admin pages draw no footer landmark")
	for _, mode := range []string{"light", "dark"} {
		sample := sampleOf(t, out, mode)
		assert.Regexp(t, `</div>\s*</div>\s*`+
			`<div class="brand-footer" data-brand-sample-footer hidden>\s*`+
			`<ul class="brand-footer-links" hidden></ul>\s*`+
			`<p class="brand-footer-contact" hidden>\s*`+
			`<span>Precisa de ajuda\?</span>\s*`+
			`<span class="brand-footer-link" data-brand-sample-contact="email" hidden></span>\s*`+
			`<span class="brand-footer-link" data-brand-sample-contact="phone" hidden></span>\s*`+
			`<span class="brand-footer-link" data-brand-sample-contact="url" hidden>Página de suporte</span>\s*`+
			`</p>\s*</div>\s*</div>\s*$`, sample, "the %s sample's footer, under its card", mode)
		assert.NotContains(t, sample, "Privacy", "the script draws the links")
		assert.NotContains(t, sample, "help@autumn.example", "the script draws the contact")
	}
}

// A brand on a custom palette, before the editor has its Colors section (#815 slice 4): no theme
// card is checked, and the form carries the theme custom after the cards, so a save sends it back
// unless a card is picked, which the browser sends first.
func TestRender_AdminSettingsBrandingFormKeepsACustomTheme(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           false,
		"storedBrand":     api.BrandResponse{Id: 8, Name: "Custom", Appearance: "auto", Theme: "custom"},
		"brand":           adminsettingshandlers.BrandForm{Name: "Custom", Appearance: "auto", Theme: "custom"},
		"brandThemes":     renderThemes,
		"appearanceTheme": adminsettingshandlers.BrandThemeOption{},
	})

	assert.NotContains(t, radioTag(t, out, "theme-blueberry"), " checked")
	assert.NotContains(t, radioTag(t, out, "theme-plum"), " checked")
	hidden := strings.Index(out, `<input type="hidden" name="theme" value="custom">`)
	require.GreaterOrEqual(t, hidden, 0, "the form carries the theme custom")
	assert.Greater(t, hidden, strings.Index(out, `id="theme-plum"`), "after the theme cards")
}

// A brand on a built-in theme carries no custom theme.
func TestRender_AdminSettingsBrandingFormOfABuiltInThemeCarriesNoCustomTheme(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           false,
		"storedBrand":     api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})

	assert.NotContains(t, out, `value="custom"`)
}
