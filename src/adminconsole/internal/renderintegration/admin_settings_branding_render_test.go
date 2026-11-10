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
			{BrandResponse: api.BrandResponse{Id: 4, Name: "<b>Autumn</b>", Appearance: "dark", Theme: "plum"},
				AppearanceName: "Escuro", ThemeName: "Ameixa"},
			{BrandResponse: api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
				AppearanceName: "Automático", ThemeName: "Mirtilo"},
		},
	})

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
		"storedBrand":     api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
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
	assert.Contains(t, out, "Nenhuma página é exibida nesta marca.")
}

func TestRender_AdminSettingsBrandingFormOfTheDefaultOffersNoMakeDefault(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":             false,
		"storedBrand":       api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
		"brand":             adminsettingshandlers.BrandForm{Name: "Default", Appearance: "auto", Theme: "blueberry"},
		"brandThemes":       renderThemes,
		"appearanceTheme":   renderThemes[0],
		"savedSuccessfully": true,
	})

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
	})
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
			assert.Contains(t, editor, "Uma amostra de uma página de entrada nesta marca, como o formulário está agora. A marca só muda quando você salva.")

			// The switch, named, its two choices the appearances' names, on Light; a Dark brand
			// draws it hidden, and says it is always dark.
			assert.Regexp(t, `<fieldset class="brand-preview-switch" hidden>\s*<legend class="field-label">Visualizar em</legend>`, editor)
			assert.Regexp(t, `<input type="radio" id="brand-preview-mode-light" name="brandPreviewMode" value="light" checked>\s*<span>Claro</span>`, editor)
			assert.Regexp(t, `<input type="radio" id="brand-preview-mode-dark" name="brandPreviewMode" value="dark">\s*<span>Escuro</span>`, editor)
			assert.Contains(t, editor, `<p class="field-hint" data-brand-preview-note="dark">Esta marca é sempre escura.</p>`)

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
		"auto":  `<p class="field-hint" data-brand-preview-note="auto">Os visitantes a veem clara ou escura, conforme o dispositivo deles.</p>`,
		"light": `<p class="field-hint" data-brand-preview-note="light">Esta marca é sempre clara.</p>`,
		"dark":  `<p class="field-hint" data-brand-preview-note="dark">Esta marca é sempre escura.</p>`,
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
